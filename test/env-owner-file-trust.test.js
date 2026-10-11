// Owner files (~/.marrow/env, ~/.marrow/env.local) are trusted only when the
// bytes that were read come from a private regular file the owner owns, in the
// owner's own directories. A file that fails supplies nothing, key included, and
// the MCP path and the hook (trustedOnly) path give the same answer.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { resolveMarrowEnv } = require('../dist/env.js');

const dummyKey = (label) => `synthetic-${label}-${crypto.randomBytes(12).toString('hex')}`;
const DEFAULT_URL = 'https://api.getmarrow.ai';
const hasUid = typeof process.getuid === 'function';

function scratch(label) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `marrow-owner-${label}-`));
}

function write(file, lines, mode) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, `${lines.join('\n')}\n`, { mode });
  fs.chmodSync(file, mode);
}

// home (0700) with ~/.marrow (0700) and a clean working directory.
function fixture(label) {
  const root = scratch(label);
  const home = path.join(root, 'home');
  const marrowDir = path.join(home, '.marrow');
  fs.mkdirSync(marrowDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  fs.chmodSync(marrowDir, 0o700);
  const cwd = path.join(root, 'work');
  fs.mkdirSync(cwd, { recursive: true, mode: 0o700 });
  return { root, home, marrowDir, cwd, envFile: path.join(marrowDir, 'env') };
}

const PLANTED = (key) => [
  `MARROW_API_KEY=${key}`,
  'MARROW_BASE_URL=https://attacker.example',
  'MARROW_FLEET_AGENT_ID=attacker-agent',
  'MARROW_SESSION_ID=attacker-session',
];

function both(fx, env = {}) {
  return {
    mcp: resolveMarrowEnv({ cwd: fx.cwd, home: fx.home, env }),
    hook: resolveMarrowEnv({ cwd: fx.cwd, home: fx.home, env, trustedOnly: true }),
  };
}

function assertNoSecret(resolved, ...secrets) {
  const text = JSON.stringify(resolved);
  for (const secret of secrets) assert.equal(text.includes(secret), false, 'secret value leaked into resolution output');
}

function assertRejected(resolved, file, key, label) {
  assert.equal(resolved.missing, true, `${label}: missing`);
  assert.equal(resolved.apiKey, '', `${label}: no key`);
  assert.equal(resolved.baseUrl, DEFAULT_URL, `${label}: no endpoint`);
  assert.equal(resolved.agentId, undefined, `${label}: no agent`);
  assert.equal(resolved.sessionId, undefined, `${label}: no session`);
  assert.equal(resolved.source, null, `${label}: no source`);
  assert.ok(resolved.exactFix.includes(`\nIgnored the Marrow key in ${file}: the file is not owner-only`), `${label}: notice names ${file}`);
  assert.ok(resolved.exactFix.includes(`Fix: chmod 600 ${file} && chmod 700 ${path.dirname(file)}`), `${label}: chmod fix`);
  assert.equal(resolved.exactFix.split('\n').length, 2, `${label}: exactly one notice line`);
  assertNoSecret(resolved, key);
  assert.doesNotMatch(JSON.stringify(resolved), /attacker/, `${label}: no planted setting`);
}

function assertSame(pair, label) {
  assert.deepEqual(pair.hook, pair.mcp, `${label}: hook path and MCP path agree`);
}

// Patch fs for one target path so a test can swap the file at a fixed point.
// Both dist/env.js and this file see the same fs module object.
function withSwap(target, { beforeOpen, afterRead }, fn) {
  const original = { openSync: fs.openSync, readSync: fs.readSync };
  const fds = new Set();
  let swapped = false;
  fs.openSync = function patchedOpen(file, ...rest) {
    if (path.resolve(String(file)) === target && beforeOpen && !swapped) { swapped = true; beforeOpen(); }
    const fd = original.openSync.call(fs, file, ...rest);
    if (path.resolve(String(file)) === target) fds.add(fd);
    return fd;
  };
  fs.readSync = function patchedRead(fd, ...rest) {
    const n = original.readSync.call(fs, fd, ...rest);
    if (fds.has(fd) && n === 0 && afterRead && !swapped) { swapped = true; afterRead(); }
    return n;
  };
  try {
    return fn();
  } finally {
    fs.openSync = original.openSync;
    fs.readSync = original.readSync;
    assert.equal(swapped, true, 'the swap ran');
  }
}

// ── F1: a non-private owner file supplies nothing ──────────────────────────

test('Codex F1: ~/.marrow/env symlinked to a repository .env supplies no key on either path', () => {
  const fx = fixture('symlink');
  const key = dummyKey('repo');
  const repoEnv = path.join(fx.cwd, '.env');
  write(repoEnv, [`MARROW_API_KEY=${key}`], 0o600);
  fs.symlinkSync(repoEnv, fx.envFile);
  const pair = both(fx);
  assertRejected(pair.mcp, fx.envFile, key, 'mcp');
  assertRejected(pair.hook, fx.envFile, key, 'hook');
  assertSame(pair, 'symlink');
});

test('a symlinked ~/.marrow/env.local to a private file elsewhere is rejected, and a dangling one too', () => {
  const fx = fixture('symlink-local');
  const key = dummyKey('elsewhere');
  const target = path.join(fx.root, 'private', 'env');
  write(target, PLANTED(key), 0o600);
  const local = path.join(fx.marrowDir, 'env.local');
  fs.symlinkSync(target, local);
  let pair = both(fx);
  assertRejected(pair.mcp, local, key, 'mcp');
  assertSame(pair, 'symlink env.local');
  fs.unlinkSync(target);
  pair = both(fx);
  assertRejected(pair.mcp, local, key, 'dangling');
  assertSame(pair, 'dangling');
});

for (const mode of [0o664, 0o646, 0o666, 0o644, 0o640, 0o604]) {
  const label = mode.toString(8).padStart(4, '0');
  test(`Codex F1: an owner file at ${label} supplies no key, endpoint or identity on either path`, () => {
    const fx = fixture(`mode-${label}`);
    const key = dummyKey('loose');
    write(fx.envFile, PLANTED(key), mode);
    const pair = both(fx);
    assertRejected(pair.mcp, fx.envFile, key, `mcp ${label}`);
    assertRejected(pair.hook, fx.envFile, key, `hook ${label}`);
    assertSame(pair, label);
  });
}

test('Codex F1: a foreign-owned owner file (fstat uid differs) supplies nothing on either path', { skip: !hasUid }, () => {
  const fx = fixture('foreign');
  const key = dummyKey('foreign');
  write(fx.envFile, [`MARROW_API_KEY=${key}`], 0o600);
  const original = fs.fstatSync;
  fs.fstatSync = function foreignFstat(...args) {
    const stat = original.apply(fs, args);
    const real = fs.lstatSync(fx.envFile);
    if (stat.ino === real.ino && stat.dev === real.dev) stat.uid = process.getuid() + 1;
    return stat;
  };
  try {
    const pair = both(fx);
    assertRejected(pair.mcp, fx.envFile, key, 'mcp');
    assertSame(pair, 'foreign');
  } finally {
    fs.fstatSync = original;
  }
});

test('Codex F1: a whole owner chain that belongs to another uid supplies nothing on either path', { skip: !hasUid }, () => {
  const fx = fixture('foreign-chain');
  const key = dummyKey('foreign-chain');
  write(fx.envFile, [`MARROW_API_KEY=${key}`], 0o600);
  const original = process.getuid;
  process.getuid = () => original.call(process) + 1;
  try {
    const pair = both(fx);
    assertRejected(pair.mcp, fx.envFile, key, 'mcp');
    assertSame(pair, 'foreign chain');
  } finally {
    process.getuid = original;
  }
});

for (const [label, setup] of [
  ['~/.marrow group-writable (0770)', (fx) => fs.chmodSync(fx.marrowDir, 0o770)],
  ['~/.marrow other-writable (0757)', (fx) => fs.chmodSync(fx.marrowDir, 0o757)],
  ['home group-writable (0775)', (fx) => fs.chmodSync(fx.home, 0o775)],
  ['~/.marrow a symlink to a private directory', (fx) => {
    const real = path.join(fx.root, 'real-marrow');
    fs.renameSync(fx.marrowDir, real);
    fs.symlinkSync(real, fx.marrowDir);
  }],
  ['home itself a symlink', (fx) => {
    const real = path.join(fx.root, 'real-home');
    fs.renameSync(fx.home, real);
    fs.symlinkSync(real, fx.home);
  }],
]) {
  test(`Codex F1: a bad directory chain (${label}) makes a 0600 owner file supply nothing`, () => {
    const fx = fixture('chain');
    const key = dummyKey('chain');
    write(fx.envFile, PLANTED(key), 0o600);
    setup(fx);
    const pair = both(fx);
    assertRejected(pair.mcp, fx.envFile, key, `mcp ${label}`);
    assertSame(pair, label);
  });
}

test('on Windows a rejected owner file names the environment fix, not chmod', () => {
  const fx = fixture('win32');
  const key = dummyKey('win');
  write(fx.envFile, [`MARROW_API_KEY=${key}`], 0o644);
  const original = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { value: 'win32' });
  try {
    const pair = both(fx);
    assert.equal(pair.mcp.missing, true);
    assert.ok(pair.mcp.exactFix.includes(`\nIgnored the Marrow key in ${fx.envFile}: owner-only file permissions cannot be confirmed on Windows. Fix: set MARROW_API_KEY in your environment`));
    assert.doesNotMatch(pair.mcp.exactFix, /chmod 600 .*\.marrow/);
    assertNoSecret(pair.mcp, key);
    assertSame(pair, 'win32');
  } finally {
    Object.defineProperty(process, 'platform', original);
  }
});

test('a rejected env.local does not block a private ~/.marrow/env (same on both paths)', () => {
  const fx = fixture('fallthrough');
  const loose = dummyKey('loose');
  const good = dummyKey('good');
  write(path.join(fx.marrowDir, 'env.local'), PLANTED(loose), 0o644);
  write(fx.envFile, [`MARROW_API_KEY=${good}`, 'MARROW_FLEET_AGENT_ID=owner-agent'], 0o600);
  const pair = both(fx);
  assert.equal(pair.mcp.apiKey, good);
  assert.equal(pair.mcp.agentId, 'owner-agent');
  assert.equal(pair.mcp.source, `${fx.envFile}:MARROW_API_KEY`);
  assertNoSecret(pair.mcp, loose);
  assertSame(pair, 'fallthrough');
});

// ── F2: the trust decision is about the bytes that were read ───────────────

test('Codex F2: a loose file read, then replaced by a private file before the check, is rejected on both paths', () => {
  for (const trustedOnly of [false, true]) {
    const fx = fixture('swap-after-read');
    const planted = dummyKey('planted');
    const good = dummyKey('good');
    write(fx.envFile, PLANTED(planted), 0o666);
    const replacement = path.join(fx.marrowDir, 'env.next');
    write(replacement, [`MARROW_API_KEY=${good}`], 0o600);
    const resolved = withSwap(fx.envFile, { afterRead: () => fs.renameSync(replacement, fx.envFile) },
      () => resolveMarrowEnv({ cwd: fx.cwd, home: fx.home, env: {}, trustedOnly }));
    assert.equal(resolved.missing, true, `trustedOnly=${trustedOnly}`);
    assert.equal(resolved.baseUrl, DEFAULT_URL);
    assertNoSecret(resolved, planted, good);
    assert.doesNotMatch(JSON.stringify(resolved), /attacker/);
    // Next resolution reads the private file and uses it.
    assert.equal(resolveMarrowEnv({ cwd: fx.cwd, home: fx.home, env: {}, trustedOnly }).apiKey, good);
  }
});

test('Codex F2: a private file that passes, then is replaced by a loose file before open, is rejected on both paths', () => {
  for (const trustedOnly of [false, true]) {
    const fx = fixture('swap-before-open');
    const planted = dummyKey('planted');
    const good = dummyKey('good');
    write(fx.envFile, [`MARROW_API_KEY=${good}`], 0o600);
    const replacement = path.join(fx.marrowDir, 'env.next');
    write(replacement, PLANTED(planted), 0o644);
    const resolved = withSwap(fx.envFile, { beforeOpen: () => fs.renameSync(replacement, fx.envFile) },
      () => resolveMarrowEnv({ cwd: fx.cwd, home: fx.home, env: {}, trustedOnly }));
    assert.equal(resolved.missing, true, `trustedOnly=${trustedOnly}`);
    assertNoSecret(resolved, planted, good);
    assert.doesNotMatch(JSON.stringify(resolved), /attacker/);
  }
});

test('Codex F2: two private files swapped between read and check (inode mismatch) are refused on both paths', () => {
  for (const trustedOnly of [false, true]) {
    const fx = fixture('swap-inode');
    const first = dummyKey('first');
    const second = dummyKey('second');
    write(fx.envFile, [`MARROW_API_KEY=${first}`, 'MARROW_BASE_URL=https://first.example'], 0o600);
    const replacement = path.join(fx.marrowDir, 'env.next');
    write(replacement, [`MARROW_API_KEY=${second}`], 0o600);
    const resolved = withSwap(fx.envFile, { afterRead: () => fs.renameSync(replacement, fx.envFile) },
      () => resolveMarrowEnv({ cwd: fx.cwd, home: fx.home, env: {}, trustedOnly }));
    assert.equal(resolved.missing, true, `trustedOnly=${trustedOnly}`);
    assert.equal(resolved.baseUrl, DEFAULT_URL);
    assertNoSecret(resolved, first, second);
  }
});

test('a FIFO at ~/.marrow/env cannot hang either path and supplies nothing', { skip: process.platform === 'win32' }, () => {
  const fx = fixture('fifo');
  const { spawnSync } = require('node:child_process');
  const made = spawnSync('mkfifo', ['-m', '600', fx.envFile]);
  if (made.status !== 0) return;
  const pair = both(fx);
  assert.equal(pair.mcp.missing, true);
  assertSame(pair, 'fifo');
});

// ── regressions: what keeps working ────────────────────────────────────────

for (const [fileMode, dirMode, homeMode] of [[0o600, 0o700, 0o700], [0o600, 0o755, 0o755], [0o400, 0o700, 0o750]]) {
  const label = `${fileMode.toString(8)} file, ${dirMode.toString(8)} ~/.marrow, ${homeMode.toString(8)} home`;
  test(`a private owner file (${label}) still supplies key, endpoint and identity on both paths`, () => {
    for (const name of ['env', 'env.local']) {
      const fx = fixture('private');
      const key = dummyKey('owner');
      const file = path.join(fx.marrowDir, name);
      write(file, [`MARROW_API_KEY=${key}`, 'MARROW_BASE_URL=https://owner.example', 'MARROW_FLEET_AGENT_ID=owner-agent', 'MARROW_SESSION_ID=owner-session'], fileMode);
      fs.chmodSync(fx.marrowDir, dirMode);
      fs.chmodSync(fx.home, homeMode);
      const pair = both(fx);
      assert.equal(pair.mcp.missing, false, `${name} ${label}`);
      assert.equal(pair.mcp.apiKey, key);
      assert.equal(pair.mcp.baseUrl, 'https://owner.example');
      assert.equal(pair.mcp.agentId, 'owner-agent');
      assert.equal(pair.mcp.sessionId, 'owner-session');
      assert.equal(pair.mcp.source, `${file}:MARROW_API_KEY`);
      assertSame(pair, `${name} ${label}`);
    }
  });
}

test('a process-env key still wins and no owner file is opened, even a rejected one', () => {
  const fx = fixture('process-env');
  const planted = dummyKey('planted');
  write(fx.envFile, PLANTED(planted), 0o666);
  const envKey = dummyKey('env');
  const original = fs.openSync;
  let opened = 0;
  fs.openSync = function countingOpen(...args) { opened += 1; return original.apply(fs, args); };
  try {
    const pair = both(fx, { MARROW_API_KEY: envKey, MARROW_BASE_URL: 'https://env.example' });
    assert.equal(pair.mcp.apiKey, envKey);
    assert.equal(pair.mcp.baseUrl, 'https://env.example');
    assert.equal(pair.mcp.source, 'MARROW_API_KEY');
    assertNoSecret(pair.mcp, planted);
    assertSame(pair, 'process env');
  } finally {
    fs.openSync = original;
  }
  assert.equal(opened, 0, 'no file opened when the process env has a key');
});

test('hook path and MCP path agree on every owner-file row', () => {
  const rows = [
    ['private 0600', (fx, key) => write(fx.envFile, [`MARROW_API_KEY=${key}`, 'MARROW_FLEET_AGENT_ID=a'], 0o600)],
    ['0644', (fx, key) => write(fx.envFile, [`MARROW_API_KEY=${key}`], 0o644)],
    ['0664', (fx, key) => write(fx.envFile, [`MARROW_API_KEY=${key}`], 0o664)],
    ['0644 naming another endpoint', (fx, key) => write(fx.envFile, [`MARROW_API_KEY=${key}`, 'MARROW_BASE_URL=https://staging.example'], 0o644)],
    ['symlink', (fx, key) => { const t = path.join(fx.root, 't'); write(t, [`MARROW_API_KEY=${key}`], 0o600); fs.symlinkSync(t, fx.envFile); }],
    ['~/.marrow 0777', (fx, key) => { write(fx.envFile, [`MARROW_API_KEY=${key}`], 0o600); fs.chmodSync(fx.marrowDir, 0o777); }],
    ['no key line', (fx) => write(fx.envFile, ['MARROW_BASE_URL=https://x.example'], 0o600)],
    ['absent', () => {}],
    ['directory', (fx) => fs.mkdirSync(fx.envFile)],
  ];
  for (const [label, setup] of rows) {
    const fx = fixture('parity');
    const key = dummyKey('parity');
    setup(fx, key);
    assertSame(both(fx), label);
    assertSame(both(fx, { MARROW_BASE_URL: 'https://env.example', MARROW_FLEET_AGENT_ID: 'env-agent' }), `${label} with env settings`);
  }
});

// ── round 3: every check in the shared helper has a test that fails without it ──

// Wrap one fs function for the length of fn; the wrapper may edit the result.
function patchFs(name, wrapper, fn) {
  const original = fs[name];
  fs[name] = function patched(...args) { return wrapper(original.apply(fs, args), args, original); };
  try {
    return fn();
  } finally {
    fs[name] = original;
  }
}

const sameFile = (stat, file) => {
  const real = fs.lstatSync(file);
  return stat.ino === real.ino && stat.dev === real.dev;
};

for (const [label, owned] of [
  ['home and ~/.marrow', (fx) => [fx.home, fx.marrowDir]],
  ['only ~/.marrow', (fx) => [fx.marrowDir]],
  ['only home', (fx) => [fx.home]],
]) {
  test(`X1: ${label} owned by another uid, file mine, supplies nothing on either path`, { skip: !hasUid }, () => {
    const fx = fixture('dir-owner');
    const key = dummyKey('dir-owner');
    write(fx.envFile, PLANTED(key), 0o600);
    const foreign = new Set(owned(fx));
    const pair = patchFs('lstatSync', (stat, args) => {
      if (foreign.has(path.resolve(String(args[0])))) stat.uid = process.getuid() + 1;
      return stat;
    }, () => both(fx));
    assertRejected(pair.mcp, fx.envFile, key, `mcp ${label}`);
    assertRejected(pair.hook, fx.envFile, key, `hook ${label}`);
    assertSame(pair, label);
  });
}

test('X3: a home that sits under a symlinked ancestor supplies nothing on either path', () => {
  const root = scratch('ancestor');
  const real = path.join(root, 'real');
  fs.mkdirSync(path.join(real, 'home', '.marrow'), { recursive: true, mode: 0o700 });
  fs.chmodSync(path.join(real, 'home'), 0o700);
  fs.chmodSync(path.join(real, 'home', '.marrow'), 0o700);
  const link = path.join(root, 'link');
  fs.symlinkSync(real, link);
  const fx = { home: path.join(link, 'home'), cwd: root, envFile: path.join(link, 'home', '.marrow', 'env') };
  const key = dummyKey('ancestor');
  write(fx.envFile, PLANTED(key), 0o600);
  const pair = both(fx);
  assertRejected(pair.mcp, fx.envFile, key, 'mcp');
  assertRejected(pair.hook, fx.envFile, key, 'hook');
  assertSame(pair, 'ancestor symlink');
});

for (const mode of [0o600, 0o666]) {
  test(`X2: a ${mode.toString(8)} file unlinked after the read supplies nothing on either path`, () => {
    for (const trustedOnly of [false, true]) {
      const fx = fixture('unlinked');
      const key = dummyKey('unlinked');
      write(fx.envFile, PLANTED(key), mode);
      const resolved = withSwap(fx.envFile, { afterRead: () => fs.unlinkSync(fx.envFile) },
        () => resolveMarrowEnv({ cwd: fx.cwd, home: fx.home, env: {}, trustedOnly }));
      assertRejected(resolved, fx.envFile, key, `trustedOnly=${trustedOnly}`);
    }
  });
}

test('X4: a private file that grows between fstat and read supplies nothing on either path', () => {
  for (const trustedOnly of [false, true]) {
    const fx = fixture('grows');
    const key = dummyKey('grows');
    write(fx.envFile, PLANTED(key), 0o600);
    let grown = false;
    const resolved = patchFs('fstatSync', (stat) => {
      if (!grown && stat.isFile() && sameFile(stat, fx.envFile)) {
        grown = true;
        fs.appendFileSync(fx.envFile, 'MARROW_AGENT_ID=grown-agent\n');
      }
      return stat;
    }, () => resolveMarrowEnv({ cwd: fx.cwd, home: fx.home, env: {}, trustedOnly }));
    assert.equal(grown, true, 'the file grew');
    assertRejected(resolved, fx.envFile, key, `trustedOnly=${trustedOnly}`);
    assert.doesNotMatch(JSON.stringify(resolved), /grown-agent/);
  }
});

test('X5: an fstat device that differs from the lstat device supplies nothing on either path', () => {
  const fx = fixture('dev');
  const key = dummyKey('dev');
  write(fx.envFile, PLANTED(key), 0o600);
  const pair = patchFs('fstatSync', (stat) => {
    if (stat.isFile() && sameFile(stat, fx.envFile)) stat.dev += 1;
    return stat;
  }, () => both(fx));
  assertRejected(pair.mcp, fx.envFile, key, 'mcp');
  assertRejected(pair.hook, fx.envFile, key, 'hook');
  assertSame(pair, 'dev mismatch');
});

test('T3: a private owner file over 1 MiB supplies nothing; exactly 1 MiB still works', () => {
  const MAX = 1024 * 1024;
  const fx = fixture('big');
  const key = dummyKey('big');
  const head = `MARROW_API_KEY=${key}\n`;
  fs.writeFileSync(fx.envFile, head + '#'.repeat(MAX + 1 - head.length), { mode: 0o600 });
  assert.equal(fs.statSync(fx.envFile).size, MAX + 1);
  const pair = both(fx);
  assertRejected(pair.mcp, fx.envFile, key, 'mcp');
  assertRejected(pair.hook, fx.envFile, key, 'hook');
  assertSame(pair, 'over cap');
  fs.writeFileSync(fx.envFile, head + '#'.repeat(MAX - head.length), { mode: 0o600 });
  assert.equal(fs.statSync(fx.envFile).size, MAX);
  const ok = both(fx);
  assert.equal(ok.mcp.apiKey, key);
  assertSame(ok, 'at cap');
});

// ── Codex F1 (round 3): the advised fix repairs a writable home ────────────

function applyAdvice(exactFix) {
  const steps = [...exactFix.matchAll(/chmod (600|700|go-w) (\S+)/g)];
  for (const [, mode, target] of steps) {
    if (mode === 'go-w') fs.chmodSync(target, fs.lstatSync(target).mode & ~0o022);
    else fs.chmodSync(target, parseInt(mode, 8));
  }
  return steps.map((s) => s[2]);
}

for (const homeMode of [0o775, 0o757, 0o777]) {
  test(`F1 r3: the notice names a ${homeMode.toString(8)} home and following it makes both paths resolve`, { skip: !hasUid }, () => {
    const fx = fixture('home-advice');
    const key = dummyKey('home-advice');
    write(fx.envFile, [`MARROW_API_KEY=${key}`, 'MARROW_FLEET_AGENT_ID=owner-agent'], 0o600);
    fs.chmodSync(fx.home, homeMode);
    const before = both(fx);
    assertRejected(before.mcp, fx.envFile, key, 'mcp');
    assertSame(before, 'before');
    assert.ok(before.mcp.exactFix.includes(`chmod go-w ${fx.home}`), 'notice names the home directory');
    const touched = applyAdvice(before.mcp.exactFix);
    assert.ok(touched.includes(fx.home), 'advice touched the home directory');
    const after = both(fx);
    assert.equal(after.mcp.apiKey, key);
    assert.equal(after.mcp.agentId, 'owner-agent');
    assertSame(after, 'after');
  });
}

test('F1 r3: a private home leaves the notice without a home step', () => {
  const fx = fixture('home-private');
  write(fx.envFile, [`MARROW_API_KEY=${dummyKey('p')}`], 0o644);
  const { mcp } = both(fx);
  assert.doesNotMatch(mcp.exactFix, /go-w/);
});

// ── Barvis r1 F2: the one path in the notice is bounded and plain ──────────

test('r1 F2: bidi, zero-width and control characters in the path are stripped from the notice', () => {
  const fx = fixture('bidi');
  const key = dummyKey('bidi');
  const names = ['a\u202Eb', 'c\u200Bd', 'e\u2066f', 'g\u2028h'];
  const home = path.join(fx.root, `h${names.join('')}`);
  fs.mkdirSync(path.join(home, '.marrow'), { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  write(path.join(home, '.marrow', 'env'), [`MARROW_API_KEY=${key}`], 0o644);
  const pair = both({ cwd: fx.cwd, home });
  assert.equal(pair.mcp.missing, true);
  const notice = pair.mcp.exactFix.split('\n')[1];
  assert.doesNotMatch(notice, /[\u202A-\u202E\u2066-\u2069\u200B-\u200F\u2028\u2029\u0000-\u001f\u007f-\u009f]/);
  assert.ok(notice.includes('ha?bc?de?fg?h'), 'replaced with ?');
  assert.equal(pair.mcp.exactFix.split('\n').length, 2);
  assertNoSecret(pair.mcp, key);
});

test('r1 F2: a very long path is length-capped in the notice', () => {
  const fx = fixture('long');
  const key = dummyKey('long');
  let home = fx.root;
  for (let i = 0; i < 3; i += 1) {
    home = path.join(home, 'd'.repeat(200));
    fs.mkdirSync(home, { mode: 0o700 });
  }
  fs.mkdirSync(path.join(home, '.marrow'), { mode: 0o700 });
  write(path.join(home, '.marrow', 'env'), [`MARROW_API_KEY=${key}`], 0o644);
  const { mcp } = both({ cwd: fx.cwd, home });
  const file = path.join(home, '.marrow', 'env');
  assert.ok(file.length > 600);
  const notice = mcp.exactFix.split('\n')[1];
  assert.equal(notice.includes(file), false, 'full path not printed');
  assert.ok(notice.includes('...'), 'truncation marker');
  assert.ok(notice.length < 1000, `notice bounded (${notice.length})`);
  assertNoSecret(mcp, key);
});
