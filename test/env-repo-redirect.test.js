// A cloned or downloaded repository must not steer the MCP server: env files
// found by walking up from the working directory never supply a key, endpoint
// or agent identity, whatever their owner or mode. Only the process env and the
// owner files ~/.marrow/env(.local) do.
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
// group/other-writable, so a repository file there would have passed the old
// owner-only check. A shared /tmp (1777) never qualifies: run the suite with
// TMPDIR set to a private directory to exercise those rows.
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

const NOTICE = 'ignored: keys are read only from ~/.marrow/env or your environment. Fix: run npx @getmarrow/install doctor, or move the line to ~/.marrow/env, then chmod 600 ~/.marrow/env.';

function assertIgnored(resolved, file, key, label) {
  assert.equal(resolved.missing, true, label);
  assert.equal(resolved.apiKey, '', label);
  assert.equal(resolved.baseUrl, 'https://api.getmarrow.ai', label);
  assert.equal(resolved.agentId, undefined, label);
  assert.equal(resolved.sessionId, undefined, label);
  assert.ok(resolved.exactFix.includes(`\nMarrow key in ${file} ${NOTICE}`), `${label}: notice names ${file}`);
  assert.equal(resolved.exactFix.split('\n').length, 2, `${label}: exactly one notice line`);
  assertNoSecret(resolved, key);
}

const PLANTED_LINES = (key) => [
  `MARROW_API_KEY=${key}`,
  'MARROW_BASE_URL=https://attacker.example',
  'MARROW_FLEET_AGENT_ID=attacker-agent',
  'MARROW_AGENT_ID=attacker-agent-2',
  'MARROW_SESSION_ID=attacker-session',
];

const gitEnv = (home) => ({ PATH: process.env.PATH, HOME: home, GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' });

// A repository whose tracked .env carries a key, cloned under the given umask.
function cloneUnderUmask(root, umask, depth) {
  const home = emptyHome(root);
  const origin = path.join(root, 'origin');
  const key = dummyKey(`clone-${umask.toString(8)}`);
  write(path.join(origin, '.env'), PLANTED_LINES(key), 0o644);
  const parts = Array.from({ length: depth }, (_, i) => `d${i}`);
  if (depth > 0) {
    fs.mkdirSync(path.join(origin, ...parts), { recursive: true });
    fs.writeFileSync(path.join(origin, ...parts, 'keep'), '');
  }
  const git = (args, cwd) => execFileSync('git', args, { cwd, env: gitEnv(home), stdio: 'ignore' });
  git(['init', '-q'], origin);
  git(['add', '-A'], origin);
  git(['-c', 'user.name=t', '-c', 'user.email=t@t.invalid', 'commit', '-qm', 'planted'], origin);
  const clone = path.join(root, 'clone');
  execFileSync('/bin/sh', ['-c', `umask ${umask.toString(8).padStart(3, '0')} && exec git clone -q "$1" "$2"`, 'sh', origin, clone], { env: gitEnv(home), stdio: 'ignore' });
  return { home, key, file: path.join(clone, '.env'), cwd: path.join(clone, ...parts) };
}

// ── planted files at every walk depth ─────────────────────────────────────

for (const umask of [0o022, 0o077]) {
  test(`git clone under umask ${umask.toString(8).padStart(3, '0')}: a tracked .env at depths 0-7 supplies nothing and is named once`, needsSafe, () => {
    for (let depth = 0; depth <= 7; depth += 1) {
      const root = scratch(`umask${umask.toString(8)}-${depth}`);
      const { home, key, file, cwd } = cloneUnderUmask(root, umask, depth);
      const mode = fs.statSync(file).mode & 0o777;
      assert.equal(mode, umask === 0o077 ? 0o600 : 0o644, 'clone produced the mode under test');
      assertIgnored(resolveMarrowEnv({ cwd, home, env: {} }), file, key, `umask ${umask.toString(8)} depth ${depth}`);
    }
  });
}

test('a file eight levels up is outside the walk: not read and not named', () => {
  const root = scratch('depth8');
  const cwd = path.join(root, 'repo', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h');
  fs.mkdirSync(cwd, { recursive: true, mode: 0o700 });
  write(path.join(root, 'repo', '.env'), [`MARROW_API_KEY=${dummyKey('far')}`], 0o600);
  const resolved = resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} });
  assert.equal(resolved.missing, true);
  assert.doesNotMatch(resolved.exactFix, /ignored/);
});

test('an archive extracted with stored modes (tar -p) yields a 0600 .env that is still ignored', needsSafe, () => {
  const root = scratch('archive');
  const src = path.join(root, 'src', 'proj');
  const key = dummyKey('archive');
  write(path.join(src, '.env'), PLANTED_LINES(key), 0o600);
  const tarball = path.join(root, 'proj.tar');
  execFileSync('tar', ['-cf', tarball, '-C', path.dirname(src), 'proj']);
  const out = path.join(root, 'out');
  fs.mkdirSync(out, { mode: 0o700 });
  execFileSync('tar', ['-xpf', tarball, '-C', out]);
  const file = path.join(out, 'proj', '.env');
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assertIgnored(resolveMarrowEnv({ cwd: path.join(out, 'proj'), home: emptyHome(root), env: {} }), file, key, 'tar -p');
});

test('every repository file name and mode is ignored: .env, .env.local, .marrow/env, .marrow/env.local at 0644/0640/0600', needsSafe, () => {
  for (const rel of ['.env', '.env.local', path.join('.marrow', 'env'), path.join('.marrow', 'env.local')]) {
    for (const mode of [0o644, 0o640, 0o600]) {
      const root = scratch('names');
      const cwd = path.join(root, 'repo');
      const key = dummyKey('name');
      write(path.join(cwd, rel), PLANTED_LINES(key), mode);
      assertIgnored(resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} }), path.join(cwd, rel), key, `${rel} ${mode.toString(8)}`);
    }
  }
});

test('MARROW_KEY in a repository file is ignored the same way', needsSafe, () => {
  const root = scratch('marrow-key');
  const cwd = path.join(root, 'repo');
  const key = dummyKey('mk');
  write(path.join(cwd, '.env'), [`MARROW_KEY=${key}`], 0o600);
  assertIgnored(resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} }), path.join(cwd, '.env'), key, 'MARROW_KEY');
});

test('several planted files produce one notice, naming the nearest', needsSafe, () => {
  const root = scratch('many');
  const cwd = path.join(root, 'repo', 'pkg');
  const keys = [dummyKey('a'), dummyKey('b'), dummyKey('c')];
  write(path.join(cwd, '.env'), [`MARROW_API_KEY=${keys[0]}`], 0o600);
  write(path.join(cwd, '.marrow', 'env'), [`MARROW_API_KEY=${keys[1]}`], 0o600);
  write(path.join(root, 'repo', '.env.local'), [`MARROW_API_KEY=${keys[2]}`], 0o600);
  const resolved = resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} });
  assertIgnored(resolved, path.join(cwd, '.marrow', 'env'), keys[0], 'many');
  assertNoSecret(resolved, ...keys);
});

test('a repository file with only endpoint/identity settings changes nothing and adds no notice', needsSafe, () => {
  const root = scratch('no-key');
  const cwd = path.join(root, 'repo');
  write(path.join(cwd, '.env'), PLANTED_LINES('x').slice(1), 0o600);
  const resolved = resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} });
  assert.equal(resolved.baseUrl, 'https://api.getmarrow.ai');
  assert.equal(resolved.agentId, undefined);
  assert.equal(resolved.exactFix.split('\n').length, 1);
});

// ── symlinks and special files ───────────────────────────────────────────

test('a symlinked repository env file is ignored even when its target is private', needsSafe, () => {
  const root = scratch('symlink-file');
  const cwd = path.join(root, 'repo');
  fs.mkdirSync(cwd, { recursive: true, mode: 0o700 });
  const target = path.join(root, 'private-env');
  const key = dummyKey('symlink');
  write(target, PLANTED_LINES(key), 0o600);
  fs.symlinkSync(target, path.join(cwd, '.env'));
  assertIgnored(resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} }), path.join(cwd, '.env'), key, 'symlink file');
});

test('a symlinked .marrow directory pointing at a private directory is ignored', needsSafe, () => {
  const root = scratch('symlink-dir');
  const cwd = path.join(root, 'repo');
  fs.mkdirSync(cwd, { recursive: true, mode: 0o700 });
  const realDir = path.join(root, 'elsewhere');
  const key = dummyKey('symdir');
  write(path.join(realDir, 'env'), PLANTED_LINES(key), 0o600);
  fs.symlinkSync(realDir, path.join(cwd, '.marrow'));
  assertIgnored(resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} }), path.join(cwd, '.marrow', 'env'), key, 'symlink dir');
});

test('a repository .marrow symlinked to ~/.marrow changes nothing: the owner file is read by its own path', needsSafe, () => {
  const root = scratch('symlink-owner');
  const cwd = path.join(root, 'repo');
  fs.mkdirSync(cwd, { recursive: true, mode: 0o700 });
  const home = ownerHome(root, null);
  const ownerKey = dummyKey('owner');
  write(path.join(home, '.marrow', 'env.local'), [`MARROW_API_KEY=${ownerKey}`], 0o600);
  fs.symlinkSync(path.join(home, '.marrow'), path.join(cwd, '.marrow'));
  const resolved = resolveMarrowEnv({ cwd, home, env: {} });
  assert.equal(resolved.apiKey, ownerKey, 'owner file reached through its real path');
  assert.equal(resolved.source, `${path.join(home, '.marrow', 'env.local')}:MARROW_API_KEY`);
});

test('without a uid (Windows) a repository key is never used', needsSafe, () => {
  const root = scratch('nouid');
  const cwd = path.join(root, 'repo');
  const key = dummyKey('nouid');
  write(path.join(cwd, '.env'), [`MARROW_API_KEY=${key}`], 0o600);
  const resolved = withUid(undefined, () => resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} }));
  assertIgnored(resolved, path.join(cwd, '.env'), key, 'no uid');
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
  write(path.join(cwd, '.env'), PLANTED_LINES(planted), 0o600);
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

test('a non-private owner file supplies nothing, with or without its own endpoint, and names the chmod fix', () => {
  const root = scratch('owner-loose');
  const cwd = path.join(root, 'repo');
  fs.mkdirSync(cwd, { recursive: true, mode: 0o700 });
  const key = dummyKey('loose-owner');
  const home = ownerHome(root, [`MARROW_API_KEY=${key}`, 'MARROW_FLEET_AGENT_ID=loose-agent', 'MARROW_SESSION_ID=loose-session'], 0o644);
  for (const lines of [null, [`MARROW_API_KEY=${key}`, 'MARROW_BASE_URL=https://staging.example']]) {
    if (lines) write(path.join(home, '.marrow', 'env'), lines, 0o644);
    const dropped = resolveMarrowEnv({ cwd, home, env: {} });
    assert.equal(dropped.missing, true);
    assert.equal(dropped.apiKey, '');
    assert.equal(dropped.baseUrl, 'https://api.getmarrow.ai');
    assert.equal(dropped.agentId, undefined);
    assert.equal(dropped.sessionId, undefined);
    assert.ok(dropped.exactFix.includes(`chmod 600 ${path.join(home, '.marrow', 'env')}`));
    assertNoSecret(dropped, key);
  }
});

test('hook path (trustedOnly) and MCP path agree: repository files are never a key source', needsSafe, () => {
  const root = scratch('trusted');
  const cwd = path.join(root, 'repo');
  write(path.join(cwd, '.env'), [`MARROW_API_KEY=${dummyKey('repo')}`], 0o600);
  const hook = resolveMarrowEnv({ cwd, home: emptyHome(root), env: {}, trustedOnly: true });
  assert.equal(hook.missing, true);
  assert.doesNotMatch(hook.exactFix, /ignored/);
  assert.equal(resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} }).missing, true);
});

test('a private owner ~/.marrow/env and ~/.marrow/env.local still work, including from cwd = HOME', needsSafe, () => {
  for (const name of ['env', 'env.local']) {
    const root = scratch('owner-ok');
    const home = ownerHome(root, null);
    const key = dummyKey('owner');
    write(path.join(home, '.marrow', name), [`MARROW_API_KEY=${key}`, 'MARROW_FLEET_AGENT_ID=owner-agent'], 0o600);
    for (const cwd of [home, path.join(root, 'repo')]) {
      fs.mkdirSync(cwd, { recursive: true, mode: 0o700 });
      const resolved = resolveMarrowEnv({ cwd, home, env: {} });
      assert.equal(resolved.apiKey, key, `${name} from ${cwd}`);
      assert.equal(resolved.agentId, 'owner-agent');
      assert.equal(resolved.source, `${path.join(home, '.marrow', name)}:MARROW_API_KEY`);
    }
  }
});

test('a key in ~/.env (not ~/.marrow/env) is a walked file and is ignored with the notice', needsSafe, () => {
  const root = scratch('home-dotenv');
  const home = ownerHome(root, null);
  const key = dummyKey('home-dotenv');
  write(path.join(home, '.env'), [`MARROW_API_KEY=${key}`], 0o600);
  const cwd = path.join(home, 'code', 'proj');
  fs.mkdirSync(cwd, { recursive: true, mode: 0o700 });
  assertIgnored(resolveMarrowEnv({ cwd, home, env: {} }), path.join(home, '.env'), key, '~/.env');
});

// ── parser edge cases and fleet mapping ──────────────────────────────────

test('CRLF, quotes and export prefixes in a private repository file supply nothing', needsSafe, () => {
  const root = scratch('parse');
  const cwd = path.join(root, 'repo');
  const key = dummyKey('crlf');
  fs.mkdirSync(cwd, { recursive: true, mode: 0o700 });
  const file = path.join(cwd, '.env');
  fs.writeFileSync(file, `export MARROW_API_KEY="${key}"\r\nMARROW_AGENT_ID='repo-agent'\r\nX=1\rMARROW_BASE_URL=https://attacker.example\r\n`, { mode: 0o600 });
  assertIgnored(resolveMarrowEnv({ cwd, home: emptyHome(root), env: {} }), file, key, 'crlf');
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

test('identical owner state with different planted repository files resolves identically (no repo-driven variation)', needsSafe, () => {
  const outputs = ['https://a.example', 'https://b.example', ''].flatMap((url) => [0o644, 0o600].map((mode) => [url, mode])).map(([url, mode]) => {
    const root = scratch('collide');
    const cwd = path.join(root, 'repo');
    const ownerKey = 'synthetic-collide-owner';
    write(path.join(cwd, '.env'), [`MARROW_API_KEY=${dummyKey('p')}`, ...(url ? [`MARROW_BASE_URL=${url}`] : []), 'MARROW_FLEET_AGENT_ID=planted', 'MARROW_SESSION_ID=planted'], mode);
    const home = ownerHome(root, null);
    const r = resolveMarrowEnv({ cwd, home, env: { MARROW_API_KEY: ownerKey, MARROW_FLEET_AGENT_ID: 'env-agent' } });
    return JSON.stringify({ k: r.apiKey, u: r.baseUrl, a: r.agentId, s: r.sessionId });
  });
  assert.equal(new Set(outputs).size, 1);
});

// ── end to end through the CLI ───────────────────────────────────────────

function runCli(args, { cwd, env, endStdin = false, input = '' }) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd, env, stdio: ['pipe', 'pipe', 'pipe'] });
    child.stdin.on('error', () => {});
    if (input) child.stdin.write(input);
    if (endStdin) child.stdin.end();
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

test('MCP server refuses a planted repository key (0644 and 0600) and shows the notice once', async () => {
  for (const mode of [0o644, 0o600]) {
    const root = scratch('cli');
    const cwd = path.join(root, 'repo');
    const key = dummyKey('cli');
    const file = path.join(cwd, '.env');
    write(file, PLANTED_LINES(key), mode);
    const home = emptyHome(root);
    // A repository key never counts: the MCP server starts keyless (initialize answered, no tools, exit 0 when stdin ends
    // after the initialize); `keys` still exits 1.
    for (const [args, code] of [[[], 0], [['keys', 'list'], 1]]) {
      const input = args.length === 0
        ? `${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05', capabilities: {} } })}\n${JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' })}\n`
        : '';
      const result = await runCli(args, { cwd, env: cliEnv(home), endStdin: true, input });
      assert.equal(result.code, code, args.join(' '));
      if (args.length === 0) {
        const answers = result.stdout.split('\n').filter(Boolean).map((line) => JSON.parse(line));
        assert.equal(answers.length, 2, 'initialize and tools/list are answered');
        assert.match(answers[0].result.instructions, /started without a Marrow key on this machine, so it has no tools/, 'the keyless server answered, not a real one');
        assert.deepEqual(answers[1].result, { tools: [] }, 'zero tools');
        assert.match(result.stderr, /started with no tools/);
      } else {
        assert.equal(result.stdout, '', 'keys list prints no MCP answer');
        assert.match(result.stderr, /MARROW_API_KEY required/);
      }
      assert.equal(result.stderr.split(`Marrow key in ${file} ${NOTICE}`).length, 2, 'notice appears exactly once');
      assert.equal(`${result.stderr}${result.stdout}`.includes(key), false);
      assert.doesNotMatch(result.stderr, /attacker/);
    }
  }
});

test('MCP server still starts from an owner ~/.marrow/env with a planted repository key present', async () => {
  const root = scratch('cli-owner');
  const cwd = path.join(root, 'repo');
  write(path.join(cwd, '.env'), PLANTED_LINES(dummyKey('planted')), 0o600);
  const home = ownerHome(root, [`MARROW_API_KEY=${dummyKey('owner')}`, 'MARROW_BASE_URL=https://marrow.invalid:8443']);
  const result = await runCli([], { cwd, env: cliEnv(home) });
  assert.match(result.stderr, /non-default Marrow endpoint: marrow\.invalid:8443/, 'owner URL in use, not the planted one');
  assert.doesNotMatch(result.stderr, /attacker|MARROW_API_KEY required/);
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
