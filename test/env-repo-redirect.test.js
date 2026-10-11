// A cloned or downloaded repository must not steer the MCP server: repository
// env files can never set the endpoint or agent identity, and can supply a key
// only from an owner-only file on a safe directory chain.
const assert = require('node:assert/strict');
const { execFileSync, spawn, spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { resolveMarrowEnv, nonDefaultBaseUrlHost } = require('../dist/env.js');
const { validateBaseUrl } = require('../dist/index.js');

const CLI = path.join(__dirname, '..', 'dist', 'cli.js');
const dummyKey = (label) => `synthetic-${label}-${crypto.randomBytes(12).toString('hex')}`;

function chainIsSafe(dir) {
  const uid = process.getuid();
  let current = fs.realpathSync(dir);
  for (;;) {
    const stat = fs.lstatSync(current);
    if ((stat.mode & 0o022) !== 0 || (stat.uid !== uid && stat.uid !== 0)) return false;
    const parent = path.dirname(current);
    if (parent === current) return true;
    current = parent;
  }
}

// A private base whose whole real directory chain is owner/root-owned and not
// group/other-writable. A shared /tmp (1777) never qualifies: run the suite with
// TMPDIR set to a private directory to exercise the accepted-file paths.
function safeBase() {
  if (typeof process.getuid !== 'function') return null;
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-env-safe-'));
  return chainIsSafe(base) ? base : null;
}
const SAFE = safeBase();
const needsSafe = SAFE ? {} : { skip: 'TMPDIR directory chain is group/other-writable (e.g. /tmp); set TMPDIR to a private directory' };

function scratch(label) {
  return fs.mkdtempSync(path.join(SAFE || os.tmpdir(), `${label}-`));
}

function write(file, lines, mode) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, `${lines.join('\n')}\n`, { mode });
  fs.chmodSync(file, mode);
}

function ownerHome(root, lines, mode = 0o600) {
  const home = path.join(root, 'home');
  fs.mkdirSync(path.join(home, '.marrow'), { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  if (lines) write(path.join(home, '.marrow', 'env'), lines, mode);
  return home;
}

function emptyHome(root) {
  const home = path.join(root, 'empty-home');
  fs.mkdirSync(home, { recursive: true, mode: 0o700 });
  return home;
}

function assertNoSecret(resolved, ...secrets) {
  const text = JSON.stringify(resolved);
  for (const secret of secrets) assert.equal(text.includes(secret), false, 'secret value leaked into resolution output');
}

function withUid(uid, fn) {
  const original = process.getuid;
  process.getuid = uid === undefined ? undefined : () => uid;
  try { return fn(); } finally { process.getuid = original; }
}

// ── planted files at every walk depth ─────────────────────────────────────

test('planted 0644 .env at depths 0-7 supplies neither key nor endpoint, and names the file', () => {
  for (let depth = 0; depth <= 7; depth += 1) {
    const root = scratch('depth');
    const parts = Array.from({ length: depth }, (_, i) => `d${i}`);
    const cwd = path.join(root, 'repo', ...parts);
    fs.mkdirSync(cwd, { recursive: true, mode: 0o700 });
    const key = dummyKey('planted');
    const planted = path.join(root, 'repo', '.env');
    write(planted, [`MARROW_API_KEY=${key}`, 'MARROW_BASE_URL=https://attacker.example', 'MARROW_FLEET_AGENT_ID=attacker-agent'], 0o644);
    const resolved = resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} });
    assert.equal(resolved.missing, true, `depth ${depth}`);
    assert.equal(resolved.apiKey, '');
    assert.equal(resolved.baseUrl, 'https://api.getmarrow.ai');
    assert.equal(resolved.agentId, undefined);
    assert.ok(resolved.exactFix.includes(`Ignored the Marrow key in ${planted}`), `depth ${depth}`);
    assert.ok(resolved.exactFix.includes(`chmod 600 ${planted}`));
    assert.equal(resolved.exactFix.split('\n').length, 2, 'exactly one extra notice line');
    assertNoSecret(resolved, key);
  }
});

test('a file eight levels up is outside the walk: not read and not named', () => {
  const root = scratch('depth8');
  const cwd = path.join(root, 'repo', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h');
  fs.mkdirSync(cwd, { recursive: true, mode: 0o700 });
  write(path.join(root, 'repo', '.env'), [`MARROW_API_KEY=${dummyKey('far')}`], 0o600);
  const resolved = resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} });
  assert.equal(resolved.missing, true);
  assert.doesNotMatch(resolved.exactFix, /Ignored/);
});

test('every repository file name is rejected at 0644: .env, .env.local, .marrow/env, .marrow/env.local', () => {
  for (const rel of ['.env', '.env.local', path.join('.marrow', 'env'), path.join('.marrow', 'env.local')]) {
    const root = scratch('names');
    const cwd = path.join(root, 'repo');
    const key = dummyKey('name');
    write(path.join(cwd, rel), [`MARROW_API_KEY=${key}`], 0o644);
    const resolved = resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} });
    assert.equal(resolved.missing, true, rel);
    assert.ok(resolved.exactFix.includes(path.join(cwd, rel)), rel);
    assertNoSecret(resolved, key);
  }
});

test('0640 repository file is rejected; 0600 is accepted for the key only', needsSafe, () => {
  const root = scratch('modes');
  const cwd = path.join(root, 'repo');
  const key = dummyKey('mode');
  const file = path.join(cwd, '.env');
  write(file, [`MARROW_API_KEY=${key}`, 'MARROW_FLEET_AGENT_ID=repo-agent', 'MARROW_AGENT_ID=repo-agent-2', 'MARROW_SESSION_ID=repo-session'], 0o640);
  const rejected = resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} });
  assert.equal(rejected.missing, true);
  assert.match(rejected.exactFix, /readable or writable by group\/other/);
  assertNoSecret(rejected, key);

  fs.chmodSync(file, 0o600);
  const accepted = resolveMarrowEnv({ cwd, home: emptyHome(root), env: { MARROW_FLEET_AGENT_ID: 'env-agent', MARROW_SESSION_ID: 'env-session' } });
  assert.equal(accepted.apiKey, key);
  assert.equal(accepted.baseUrl, 'https://api.getmarrow.ai');
  assert.equal(accepted.agentId, 'env-agent', 'agent identity comes from the process env, never the repo file');
  assert.equal(accepted.sessionId, 'env-session');
  assert.doesNotMatch(JSON.stringify(accepted), /repo-agent|repo-session/);

  const noEnvIdentity = resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} });
  assert.equal(noEnvIdentity.agentId, undefined);
  assert.equal(noEnvIdentity.sessionId, undefined);
});

test('a private repository file that names another endpoint is skipped, not redirected and not re-pointed', needsSafe, () => {
  for (const line of [
    'MARROW_BASE_URL=https://attacker.example',
    'export MARROW_BASE_URL="https://attacker.example"',
    "MARROW_BASE_URL='https://api.getmarrow.ai.attacker.example'",
    'MARROW_BASE_URL=http://api.getmarrow.ai',
  ]) {
    const root = scratch('endpoint');
    const cwd = path.join(root, 'repo');
    const key = dummyKey('endpoint');
    write(path.join(cwd, '.env'), [`MARROW_API_KEY=${key}`, line], 0o600);
    const resolved = resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} });
    assert.equal(resolved.missing, true, line);
    assert.equal(resolved.baseUrl, 'https://api.getmarrow.ai');
    assert.match(resolved.exactFix, /repository files cannot set MARROW_BASE_URL/);
    assertNoSecret(resolved, key);
  }
});

test('a private repository file that repeats the endpoint in use keeps working', needsSafe, () => {
  const root = scratch('same-endpoint');
  const cwd = path.join(root, 'repo');
  const key = dummyKey('same');
  write(path.join(cwd, '.env'), [`MARROW_API_KEY=${key}`, 'MARROW_BASE_URL=https://api.getmarrow.ai/'], 0o600);
  const resolved = resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} });
  assert.equal(resolved.apiKey, key);
  assert.equal(resolved.baseUrl, 'https://api.getmarrow.ai');
});

// ── symlinks, owners, directory chain ─────────────────────────────────────

test('a symlinked repository env file is rejected even when its target is private', needsSafe, () => {
  const root = scratch('symlink-file');
  const cwd = path.join(root, 'repo');
  fs.mkdirSync(cwd, { recursive: true, mode: 0o700 });
  const target = path.join(root, 'private-env');
  const key = dummyKey('symlink');
  write(target, [`MARROW_API_KEY=${key}`], 0o600);
  fs.symlinkSync(target, path.join(cwd, '.env'));
  const resolved = resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} });
  assert.equal(resolved.missing, true);
  assert.match(resolved.exactFix, /: file is a symlink or not a regular file\./);
  assertNoSecret(resolved, key);
});

test('a symlinked .marrow directory is judged by its real directory chain', needsSafe, () => {
  const root = scratch('symlink-dir');
  const cwd = path.join(root, 'repo');
  fs.mkdirSync(cwd, { recursive: true, mode: 0o700 });
  const realDir = path.join(root, 'elsewhere');
  const key = dummyKey('symdir');
  write(path.join(realDir, 'env'), [`MARROW_API_KEY=${key}`], 0o600);
  fs.symlinkSync(realDir, path.join(cwd, '.marrow'));
  assert.equal(resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} }).apiKey, key);

  fs.chmodSync(realDir, 0o777);
  const unsafe = resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} });
  assert.equal(unsafe.missing, true);
  assert.match(unsafe.exactFix, /group\/other-writable/);
  assert.ok(unsafe.exactFix.includes(realDir), 'names the real directory, not the link');
  assertNoSecret(unsafe, key);
});

test('a group-writable directory anywhere in the chain rejects a 0600 file', needsSafe, () => {
  for (const mode of [0o770, 0o757, 0o1777]) {
    const root = scratch('gw');
    const shared = path.join(root, 'shared');
    const cwd = path.join(shared, 'repo', 'pkg');
    fs.mkdirSync(cwd, { recursive: true, mode: 0o700 });
    const key = dummyKey('gw');
    write(path.join(cwd, '.env'), [`MARROW_API_KEY=${key}`], 0o600);
    fs.chmodSync(shared, mode);
    const resolved = resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} });
    assert.equal(resolved.missing, true, mode.toString(8));
    assert.ok(resolved.exactFix.includes(`directory ${shared} is group/other-writable`));
    assert.match(resolved.exactFix, /move the key to ~\/\.marrow\/env/);
    assertNoSecret(resolved, key);
  }
});

test('the shared temp directory itself never qualifies as a safe chain', { skip: !fs.existsSync('/tmp') || (fs.statSync('/tmp').mode & 0o002) === 0 ? 'no world-writable /tmp here' : false }, () => {
  const dir = fs.mkdtempSync(path.join('/tmp', 'marrow-env-shared-'));
  const key = dummyKey('tmp');
  write(path.join(dir, '.env'), [`MARROW_API_KEY=${key}`], 0o600);
  const resolved = resolveMarrowEnv({ cwd: dir, home: emptyHome(dir), env: {} });
  assert.equal(resolved.missing, true);
  assertNoSecret(resolved, key);
});

test('a file owned by another user is rejected (uid simulated)', needsSafe, () => {
  const root = scratch('foreign');
  const cwd = path.join(root, 'repo');
  const key = dummyKey('foreign');
  write(path.join(cwd, '.env'), [`MARROW_API_KEY=${key}`], 0o600);
  const resolved = withUid(process.getuid() + 4242, () => resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} }));
  assert.equal(resolved.missing, true);
  assert.match(resolved.exactFix, /: file is owned by another user/);
  assertNoSecret(resolved, key);
});

test('a directory in the chain owned by another (non-root) user rejects a 0600 file (stat simulated)', needsSafe, () => {
  const root = scratch('foreign-dir');
  const foreignDir = path.join(root, 'theirs');
  const cwd = path.join(foreignDir, 'repo');
  const key = dummyKey('foreign-dir');
  write(path.join(cwd, '.env'), [`MARROW_API_KEY=${key}`], 0o600);
  const realLstat = fs.lstatSync;
  const foreign = fs.realpathSync(foreignDir);
  fs.lstatSync = (target, ...rest) => {
    const stat = realLstat(target, ...rest);
    if (target === foreign) return Object.assign(Object.create(Object.getPrototypeOf(stat)), stat, { uid: process.getuid() + 4242 });
    return stat;
  };
  let resolved;
  try {
    resolved = resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} });
  } finally {
    fs.lstatSync = realLstat;
  }
  assert.equal(resolved.missing, true);
  assert.ok(resolved.exactFix.includes(`directory ${foreign} is owned by another user`));
  assertNoSecret(resolved, key);
  assert.equal(resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} }).apiKey, key, 'same tree is accepted without the foreign owner');
});

test('without a uid (Windows) a repository key is never used', needsSafe, () => {
  const root = scratch('nouid');
  const cwd = path.join(root, 'repo');
  const key = dummyKey('nouid');
  write(path.join(cwd, '.env'), [`MARROW_API_KEY=${key}`], 0o600);
  const resolved = withUid(undefined, () => resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} }));
  assert.equal(resolved.missing, true);
  assert.match(resolved.exactFix, /cannot be verified on this platform/);
  assertNoSecret(resolved, key);
});

test('a planted FIFO, directory or oversized file cannot hang or feed the resolver', () => {
  const root = scratch('special');
  const cwd = path.join(root, 'repo');
  fs.mkdirSync(path.join(cwd, '.env.local'), { recursive: true, mode: 0o700 });
  let fifo = false;
  try { execFileSync('mkfifo', [path.join(cwd, '.env')]); fifo = true; } catch { /* no mkfifo */ }
  write(path.join(cwd, '.marrow', 'env'), [`MARROW_API_KEY=${dummyKey('big')}`, 'X'.repeat(1024 * 1024 + 10)], 0o600);
  // A blocking read would freeze this process, so resolve in a child with a deadline.
  const script = `const r = require(${JSON.stringify(path.join(__dirname, '..', 'dist', 'env.js'))}).resolveMarrowEnv({ cwd: process.argv[1], home: process.argv[2], env: {} }); process.stdout.write(String(r.missing));`;
  const child = spawnSync(process.execPath, ['-e', script, cwd, emptyHome(root)], { timeout: 10000, encoding: 'utf8' });
  assert.equal(child.signal, null, 'resolver hung on a special file');
  assert.equal(child.stdout, 'true');
  if (!fifo) test.diagnostic?.('mkfifo unavailable; FIFO case not exercised');
});

test('control characters in an ignored path stay on one notice line', () => {
  const root = scratch('ctl');
  const cwd = path.join(root, 'evil\nInjected line\r');
  const key = dummyKey('ctl');
  write(path.join(cwd, '.env'), [`MARROW_API_KEY=${key}`], 0o644);
  const resolved = resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} });
  assert.equal(resolved.exactFix.split('\n').length, 2);
  assert.match(resolved.exactFix, /evil\?Injected line\?/);
  assertNoSecret(resolved, key);
});

// ── owner files and process env keep precedence ──────────────────────────

test('a planted endpoint never overrides an owner key: owner URL or default stays', () => {
  const root = scratch('owner-wins');
  const cwd = path.join(root, 'repo');
  const planted = dummyKey('planted');
  write(path.join(cwd, '.env'), [`MARROW_API_KEY=${planted}`, 'MARROW_BASE_URL=https://attacker.example'], 0o600);
  const ownerKey = dummyKey('owner');
  const home = ownerHome(root, [`MARROW_API_KEY=${ownerKey}`]);
  const resolved = resolveMarrowEnv({ cwd, home, env: {} });
  assert.equal(resolved.apiKey, ownerKey);
  assert.equal(resolved.baseUrl, 'https://api.getmarrow.ai');

  write(path.join(home, '.marrow', 'env'), [`MARROW_API_KEY=${ownerKey}`, 'MARROW_BASE_URL=https://owner.example'], 0o600);
  const ownerUrl = resolveMarrowEnv({ cwd, home, env: {} });
  assert.equal(ownerUrl.baseUrl, 'https://owner.example');
  assertNoSecret(ownerUrl, planted);
});

test('process env key and URL win over every file', () => {
  const root = scratch('env-wins');
  const cwd = path.join(root, 'repo');
  write(path.join(cwd, '.env'), [`MARROW_API_KEY=${dummyKey('planted')}`, 'MARROW_BASE_URL=https://attacker.example'], 0o600);
  const key = dummyKey('env');
  const resolved = resolveMarrowEnv({ cwd, home: emptyHome(root), env: { MARROW_API_KEY: key, MARROW_BASE_URL: 'https://env.example' } });
  assert.equal(resolved.apiKey, key);
  assert.equal(resolved.baseUrl, 'https://env.example');
});

test('planted key with a process-env base URL: the planted 0644 key is not sent to that URL', () => {
  const root = scratch('env-url');
  const cwd = path.join(root, 'repo');
  const key = dummyKey('planted');
  write(path.join(cwd, '.env'), [`MARROW_API_KEY=${key}`], 0o644);
  const resolved = resolveMarrowEnv({ cwd, home: emptyHome(root), env: { MARROW_BASE_URL: 'https://env.example' } });
  assert.equal(resolved.missing, true);
  assert.equal(resolved.apiKey, '');
  assertNoSecret(resolved, key);
});

test('a non-private owner file keeps its key but loses endpoint and identity; a foreign endpoint drops the key', () => {
  const root = scratch('owner-loose');
  const cwd = path.join(root, 'repo');
  fs.mkdirSync(cwd, { recursive: true, mode: 0o700 });
  const key = dummyKey('loose-owner');
  const home = ownerHome(root, [`MARROW_API_KEY=${key}`, 'MARROW_FLEET_AGENT_ID=loose-agent', 'MARROW_SESSION_ID=loose-session'], 0o644);
  const kept = resolveMarrowEnv({ cwd, home, env: {} });
  assert.equal(kept.apiKey, key);
  assert.equal(kept.agentId, undefined);
  assert.equal(kept.sessionId, undefined);

  write(path.join(home, '.marrow', 'env'), [`MARROW_API_KEY=${key}`, 'MARROW_BASE_URL=https://staging.example'], 0o644);
  const dropped = resolveMarrowEnv({ cwd, home, env: {} });
  assert.equal(dropped.missing, true);
  assert.equal(dropped.baseUrl, 'https://api.getmarrow.ai');
  assert.ok(dropped.exactFix.includes(`chmod 600 ${path.join(home, '.marrow', 'env')}`));
  assertNoSecret(dropped, key);
});

test('hook path (trustedOnly) still never reads repository files, even private ones', needsSafe, () => {
  const root = scratch('trusted');
  const cwd = path.join(root, 'repo');
  write(path.join(cwd, '.env'), [`MARROW_API_KEY=${dummyKey('repo')}`], 0o600);
  const resolved = resolveMarrowEnv({ cwd, home: emptyHome(root), env: {}, trustedOnly: true });
  assert.equal(resolved.missing, true);
  assert.doesNotMatch(resolved.exactFix, /Ignored/);
  assert.equal(resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} }).missing, false);
});

// ── parser edge cases and fleet mapping ──────────────────────────────────

test('CRLF, quotes and export prefixes do not smuggle an endpoint or identity out of a private repo file', needsSafe, () => {
  const root = scratch('parse');
  const cwd = path.join(root, 'repo');
  const key = dummyKey('crlf');
  fs.mkdirSync(cwd, { recursive: true, mode: 0o700 });
  const file = path.join(cwd, '.env');
  fs.writeFileSync(file, `export MARROW_API_KEY="${key}"\r\nMARROW_AGENT_ID='repo-agent'\r\nX=1\rMARROW_BASE_URL=https://attacker.example\r\n`, { mode: 0o600 });
  const resolved = resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} });
  assert.equal(resolved.apiKey, key);
  assert.equal(resolved.baseUrl, 'https://api.getmarrow.ai');
  assert.equal(resolved.agentId, undefined);
});

test('fleet key/agent mappings are never read from repository or owner files', () => {
  const root = scratch('fleet');
  const cwd = path.join(root, 'repo');
  const fleetKey = dummyKey('fleet');
  write(path.join(cwd, '.env'), [`MARROW_KEY_BOB=${fleetKey}`, 'MARROW_AGENT_ID_BOB=codex-bob'], 0o600);
  const home = ownerHome(root, [`MARROW_KEY_BOB=${fleetKey}`, 'MARROW_AGENT_ID_BOB=codex-bob'], 0o600);
  const resolved = resolveMarrowEnv({ cwd, home, env: { MARROW_FLEET_AGENT_ID: 'codex-bob' } });
  assert.equal(resolved.missing, true);
  assertNoSecret(resolved, fleetKey);
});

// ── endpoint display and validation ──────────────────────────────────────

test('base URL validation: https only, no userinfo, never echoes the raw value', () => {
  assert.throws(() => validateBaseUrl('http://api.getmarrow.ai'), /must use HTTPS/);
  for (const raw of ['https://user:hunter2@api.example', 'https://api.getmarrow.ai@attacker.example', 'https://token@attacker.example']) {
    assert.throws(() => validateBaseUrl(raw), (err) => /user name or password/.test(err.message) && !err.message.includes('hunter2') && !err.message.includes('attacker'));
  }
  assert.throws(() => validateBaseUrl('not a url secretvalue'), (err) => !err.message.includes('secretvalue'));
  assert.equal(validateBaseUrl('https://api.getmarrow.ai/'), 'https://api.getmarrow.ai');
});

test('non-default endpoint host is shown precisely, including odd forms', () => {
  assert.equal(nonDefaultBaseUrlHost('https://api.getmarrow.ai'), null);
  assert.equal(nonDefaultBaseUrlHost('https://API.GetMarrow.ai/'), null);
  assert.equal(nonDefaultBaseUrlHost('https://api.getmarrow.ai:8443'), 'api.getmarrow.ai:8443');
  assert.equal(nonDefaultBaseUrlHost('https://api.getmarrow.ai.'), 'api.getmarrow.ai.');
  assert.equal(nonDefaultBaseUrlHost('https://[::1]:8443'), '[::1]:8443');
  const idn = nonDefaultBaseUrlHost('https://\u0430pi.getmarrow.ai');
  assert.match(idn, /^xn--[a-z0-9-]+\.getmarrow\.ai$/, 'look-alike hosts are shown in punycode');
  assert.equal(nonDefaultBaseUrlHost('https://evil.example\\@api.getmarrow.ai'), 'evil.example');
  assert.equal(nonDefaultBaseUrlHost('https://u:p@x.example'), 'x.example', 'host only, never userinfo');
});

test('identical repo state with different planted endpoints resolves identically (no repo-driven variation)', needsSafe, () => {
  const outputs = ['https://a.example', 'https://b.example', ''].map((url) => {
    const root = scratch('collide');
    const cwd = path.join(root, 'repo');
    const ownerKey = 'synthetic-collide-owner';
    write(path.join(cwd, '.env'), [`MARROW_API_KEY=${dummyKey('p')}`, ...(url ? [`MARROW_BASE_URL=${url}`] : []), 'MARROW_FLEET_AGENT_ID=planted'], 0o644);
    const home = ownerHome(root, null);
    const r = resolveMarrowEnv({ cwd, home, env: { MARROW_API_KEY: ownerKey, MARROW_FLEET_AGENT_ID: 'env-agent' } });
    return JSON.stringify({ k: r.apiKey, u: r.baseUrl, a: r.agentId, s: r.sessionId });
  });
  assert.equal(new Set(outputs).size, 1);
});

// ── end to end through the CLI ───────────────────────────────────────────

function runCli(args, { cwd, env }) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd, env, stdio: ['pipe', 'pipe', 'pipe'] });
    let stderr = '';
    let stdout = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 15000);
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => {
      stderr += d;
      if (/non-default Marrow endpoint/.test(stderr)) child.kill('SIGKILL');
    });
    child.on('close', (code) => { clearTimeout(timer); resolve({ code, stderr, stdout }); });
  });
}

function cliEnv(home, extra = {}) {
  const env = { PATH: process.env.PATH, HOME: home, USERPROFILE: home, MARROW_AUTO_ENROLL: 'false', ...extra };
  return env;
}

test('MCP server refuses a planted repository key and tells the owner the exact fix', async () => {
  const root = scratch('cli');
  const cwd = path.join(root, 'repo');
  const key = dummyKey('cli');
  write(path.join(cwd, '.env'), [`MARROW_API_KEY=${key}`, 'MARROW_BASE_URL=https://attacker.example'], 0o644);
  const home = emptyHome(root);
  for (const args of [[], ['keys', 'list']]) {
    const result = await runCli(args, { cwd, env: cliEnv(home) });
    assert.equal(result.code, 1, args.join(' '));
    assert.ok(result.stderr.includes(`Ignored the Marrow key in ${path.join(cwd, '.env')}`));
    assert.ok(result.stderr.includes(`chmod 600 ${path.join(cwd, '.env')}`));
    assert.equal(`${result.stderr}${result.stdout}`.includes(key), false);
    assert.doesNotMatch(result.stderr, /attacker/);
  }
});

test('MCP server names a non-default endpoint host at startup', async () => {
  const root = scratch('cli-host');
  const home = emptyHome(root);
  const result = await runCli([], { cwd: root, env: cliEnv(home, { MARROW_API_KEY: dummyKey('host'), MARROW_BASE_URL: 'https://user:pw@marrow.invalid:8443' }) });
  assert.match(result.stderr, /user name or password/);
  assert.doesNotMatch(result.stderr, /pw@/);
  const ok = await runCli([], { cwd: root, env: cliEnv(home, { MARROW_API_KEY: dummyKey('host'), MARROW_BASE_URL: 'https://marrow.invalid:8443' }) });
  assert.match(ok.stderr, /non-default Marrow endpoint: marrow\.invalid:8443/);
});
