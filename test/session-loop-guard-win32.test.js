'use strict';

// 3.9.106 hotfix, Phase A: the loop guard on a (fake) win32 (SPEC-WINDOWS-HOOKS A2, A4, section 5/6).
// Rows: U-LG, U-CS, U-K, U-CWD, U-COL1, U-COL5, G3/G7, AB1, AB38. The win32 branch runs against real
// Linux files with a fake private-state proof injected through withLoopGuardPlatform(); the proof
// itself is covered in win-private-state.test.js.
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const guard = require('../dist/session-loop-guard.js');
const { UnsafeLoopGuardStateError } = guard;
const { runPreActionHookCommand } = require('../dist/hook-pre-action.js');
const { runHookCommand } = require('../dist/hook.js');
const { mapperEnv } = require('../dist/seatbelt/hook.js');
const { readLocalControlState } = require('../dist/control-state.js');
const { resolveMarrowEnv } = require('../dist/env.js');

const UNSAFE_TEXT = 'Marrow local loop guard state is unsafe. Repair the private owner-only state before retrying.';
const scratch = () => fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-win32-guard-'));
const cleanup = (...dirs) => dirs.forEach((dir) => fs.rmSync(dir, { recursive: true, force: true }));

// A fake proof over real files: it creates the two directories like the real one and reports the paths.
// It records every call that happens while the state lock file exists (there must be none: RC-3).
function fakeWindows(options = {}) {
  const calls = [];
  const verifies = [];
  const lockHeld = [];
  const platform = {
    platform: options.platform || 'win32',
    calls,
    verifies,
    lockHeld,
    ensure(home) {
      calls.push(home);
      const directory = path.join(home, '.marrow', 'session-loop-guard');
      if (fs.existsSync(path.join(directory, '.state.lock'))) lockHeld.push(home);
      if (options.throws) throw new Error('boom');
      if (options.fail) return { ok: false, reason: options.fail };
      fs.mkdirSync(directory, { recursive: true });
      const target = path.join(directory, 'state.json');
      return { ok: true, marrow: path.join(home, '.marrow'), directory, target, stateProven: fs.existsSync(target), identity: 'fake-identity' };
    },
    verify(home, proof) {
      verifies.push(home);
      if (options.onVerify) options.onVerify(home, proof);
      return !options.verifyFalse && proof.identity === 'fake-identity';
    },
  };
  return platform;
}
const onWindows = (platform, run) => guard.withLoopGuardPlatform(platform, run);

function operation(overrides = {}) {
  return { sessionId: 's-win', agentId: 'a-win', harness: 'codex', toolName: 'functions.exec', toolInput: { cmd: 'npm test' }, readOnly: true, ...overrides };
}

test('U-LG1 and LG5, LG6: consult, record, a repeat denial, advance and clear all work on win32, one proof per call', () => {
  const home = scratch();
  const win = fakeWindows();
  try {
    onWindows(win, () => {
      assert.equal(guard.consultSessionLoopGuard(operation(), { home }).allow, true);
      assert.equal(win.calls.length, 1, 'one proof for the whole lock hold, not one per step');
      assert.equal(fs.existsSync(guard.sessionLoopGuardPath(home)), true);
      assert.equal(guard.consultSessionLoopGuard(operation(), { home }).allow, true);
      assert.equal(win.calls.length, 2);
      guard.recordSessionLoopOutcome(operation(), true, { ok: 1 }, { home });
      const denied = guard.consultSessionLoopGuard(operation(), { home });
      assert.equal(denied.allow, false);
      assert.match(denied.reason, /already ran this exact.*Use the earlier result.*Receipt: lgr_/i); // 3.9.107 wording (FH-2)
      guard.advanceSessionInstructionEpoch(operation(), { home });
      assert.equal(guard.consultSessionLoopGuard(operation(), { home }).allow, true);
      guard.clearSessionLoopGuard(operation(), { home });
      assert.equal(guard.consultSessionLoopGuard(operation(), { home }).allow, true);
    });
    assert.equal(fs.readdirSync(path.join(home, '.marrow', 'session-loop-guard')).sort().join(), 'state.json', 'no lock or temp file is left behind');
  } finally { cleanup(home); }
});

test('U-LG2: the self-test sequence passes on the win32 path', () => {
  const win = fakeWindows();
  const result = onWindows(win, () => guard.runSessionLoopGuardSelfTest());
  assert.deepEqual(result, { pass: true, isolated: true, live_hook_observed: false, repeat_denied: true, mutation_reset: true, owner_disabled_bypass: true });
  assert.ok(win.calls.length >= 5);
  assert.ok(win.calls.every((home) => path.basename(home).startsWith('marrow-loop-guard-self-test-')));
});

test('U-LG3: a failed or throwing proof is UnsafeLoopGuardStateError for every entry point, and leaves no state behind', () => {
  for (const options of [{ fail: 'acl' }, { fail: 'chain' }, { fail: 'owner' }, { fail: 'spawn' }, { fail: 'path' }, { throws: true }]) {
    const home = scratch();
    try {
      onWindows(fakeWindows(options), () => {
        assert.throws(() => guard.consultSessionLoopGuard(operation(), { home }), UnsafeLoopGuardStateError);
        assert.throws(() => guard.recordSessionLoopOutcome(operation(), true, {}, { home }), UnsafeLoopGuardStateError);
        assert.throws(() => guard.advanceSessionInstructionEpoch(operation(), { home }), UnsafeLoopGuardStateError);
        assert.throws(() => guard.clearSessionLoopGuard(operation(), { home }), UnsafeLoopGuardStateError);
      });
      assert.equal(fs.existsSync(path.join(home, '.marrow')), false, JSON.stringify(options));
    } finally { cleanup(home); }
  }
});

test('U-LG3: a lock-time check that fails (folder identity changed) is unsafe, leaves no lock behind and does not touch state', () => {
  const home = scratch();
  try {
    onWindows(fakeWindows(), () => guard.consultSessionLoopGuard(operation(), { home }));
    const before = fs.readFileSync(guard.sessionLoopGuardPath(home), 'utf8');
    const win = fakeWindows({ verifyFalse: true });
    onWindows(win, () => {
      assert.throws(() => guard.consultSessionLoopGuard(operation({ toolInput: { cmd: 'other' } }), { home }), UnsafeLoopGuardStateError);
      assert.throws(() => guard.advanceSessionInstructionEpoch(operation(), { home }), UnsafeLoopGuardStateError);
    });
    assert.equal(win.verifies.length, 2);
    assert.equal(fs.readFileSync(guard.sessionLoopGuardPath(home), 'utf8'), before);
    assert.equal(fs.existsSync(path.join(home, '.marrow', 'session-loop-guard', '.state.lock')), false);
  } finally { cleanup(home); }
});

test('U-LG3: the hook gives the exact unsafe deny text when the proof fails, and the normal answer when it passes', async () => {
  const home = scratch();
  const originalWrite = process.stdout.write;
  const previous = { HOME: process.env.HOME, MARROW_API_KEY: process.env.MARROW_API_KEY, MARROW_KEY: process.env.MARROW_KEY };
  let output = '';
  process.stdout.write = (chunk) => { output += String(chunk); return true; };
  process.env.HOME = home;
  delete process.env.MARROW_API_KEY;
  delete process.env.MARROW_KEY;
  try {
    const event = { session_id: 'sw', tool_name: 'functions.exec', tool_input: { cmd: 'git status' } };
    await onWindows(fakeWindows({ fail: 'acl' }), () => runPreActionHookCommand({ ...event, tool_use_id: 't1' }));
    assert.ok(output.includes(UNSAFE_TEXT), output);
    output = '';
    await onWindows(fakeWindows(), () => runPreActionHookCommand({ ...event, tool_use_id: 't2' }));
    assert.equal(output.includes(UNSAFE_TEXT), false, output);
  } finally {
    process.stdout.write = originalWrite;
    for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    cleanup(home);
  }
});

test('U-LG4: the stale lock path, a planted lock and a planted state file on win32 follow the file rule', () => {
  const home = scratch();
  const win = fakeWindows();
  try {
    onWindows(win, () => {
      guard.consultSessionLoopGuard(operation(), { home });
      const directory = path.join(home, '.marrow', 'session-loop-guard');
      const lock = path.join(directory, '.state.lock');
      fs.writeFileSync(lock, '');
      const old = new Date(Date.now() - 60_000);
      fs.utimesSync(lock, old, old);
      assert.equal(guard.consultSessionLoopGuard(operation({ toolInput: { cmd: 'x' } }), { home }).allow, true, 'a stale lock is removed');
      // a lock that is a hard link, then a symlink: refused
      fs.writeFileSync(path.join(home, 'other'), '');
      fs.linkSync(path.join(home, 'other'), lock);
      assert.throws(() => guard.consultSessionLoopGuard(operation(), { home }), UnsafeLoopGuardStateError);
      fs.unlinkSync(lock);
      fs.symlinkSync(path.join(home, 'other'), lock);
      assert.throws(() => guard.consultSessionLoopGuard(operation(), { home }), UnsafeLoopGuardStateError);
      fs.unlinkSync(lock);
      // a state file that is a hard link (nlink 2), a symlink, a directory, too small
      const state = path.join(directory, 'state.json');
      const saved = fs.readFileSync(state);
      fs.linkSync(state, path.join(home, 'state-copy'));
      assert.throws(() => guard.consultSessionLoopGuard(operation(), { home }), UnsafeLoopGuardStateError, 'nlink 2');
      fs.unlinkSync(path.join(home, 'state-copy'));
      fs.renameSync(state, path.join(home, 'moved'));
      fs.symlinkSync(path.join(home, 'moved'), state);
      assert.throws(() => guard.consultSessionLoopGuard(operation(), { home }), UnsafeLoopGuardStateError, 'symlink');
      fs.unlinkSync(state);
      fs.mkdirSync(state);
      assert.throws(() => guard.consultSessionLoopGuard(operation(), { home }), UnsafeLoopGuardStateError, 'directory');
      fs.rmdirSync(state);
      fs.writeFileSync(state, '{');
      assert.throws(() => guard.consultSessionLoopGuard(operation(), { home }), UnsafeLoopGuardStateError, 'invalid json');
      fs.writeFileSync(state, saved);
      assert.equal(guard.consultSessionLoopGuard(operation(), { home }).allow, true, 'the same bytes in a plain file are fine again');
    });
  } finally { cleanup(home); }
});

test('U-C7: a state file whose bigint identity differs between lstat and fstat is refused', () => {
  const home = scratch();
  try {
    onWindows(fakeWindows(), () => {
      guard.consultSessionLoopGuard(operation(), { home });
      const original = fs.fstatSync;
      fs.fstatSync = function patched(fd, options) {
        const stat = original.call(fs, fd, options);
        if (options && options.bigint && stat.isFile() && stat.size > 0n) return Object.create(stat, { ino: { value: stat.ino + 1n } });
        return stat;
      };
      try {
        assert.throws(() => guard.consultSessionLoopGuard(operation(), { home }), UnsafeLoopGuardStateError);
      } finally { fs.fstatSync = original; }
      assert.equal(guard.consultSessionLoopGuard(operation(), { home }).allow, true);
    });
  } finally { cleanup(home); }
});

test('RC-3d: a state file that appears between the proof and the lock is accepted when it is a plain single-link file, refused when it is not', () => {
  const secret = randomBytes(32).toString('base64url');
  const plant = (home, body, mode = 0o600) => {
    const file = path.join(home, '.marrow', 'session-loop-guard', 'state.json');
    fs.writeFileSync(file, body, { mode });
  };
  const good = scratch();
  const bad = scratch();
  try {
    const accepted = fakeWindows({ onVerify: (home) => plant(home, `${JSON.stringify({ version: 1, secret, sessions: {} })}\n`) });
    assert.equal(onWindows(accepted, () => guard.consultSessionLoopGuard(operation(), { home: good })).allow, true);
    assert.equal(accepted.calls.length, 1, 'no second proof for the late file');
    const rejected = fakeWindows({ onVerify: (home) => plant(home, '{"version":2}\n') });
    onWindows(rejected, () => assert.throws(() => guard.consultSessionLoopGuard(operation(), { home: bad }), UnsafeLoopGuardStateError));
  } finally { cleanup(good, bad); }
});

test('U-LG9 and RC-3: the ACL proof never runs while the lock is held, one proof per call, verify once per lock hold', () => {
  const home = scratch();
  const other = scratch();
  const win = fakeWindows();
  try {
    onWindows(win, () => {
      const op = operation();
      guard.consultSessionLoopGuard(op, { home });
      guard.recordSessionLoopOutcome(op, true, { ok: 1 }, { home });
      assert.equal(guard.consultSessionLoopGuard(op, { home }).allow, false);
      guard.advanceSessionInstructionEpoch(op, { home });
      guard.clearSessionLoopGuard(op, { home });
      guard.consultSessionLoopGuard(op, { home: other });
    });
    assert.equal(win.calls.length, 6);
    assert.equal(win.verifies.length, 6);
    assert.deepEqual(win.lockHeld, [], 'the proof (the PowerShell spawn) was never called with the lock file present');
    // a throwing callback releases the lock for the next caller
    fs.writeFileSync(path.join(home, '.marrow', 'session-loop-guard', 'state.json'), '{"version":2}\n');
    onWindows(win, () => {
      assert.throws(() => guard.consultSessionLoopGuard(operation(), { home }), UnsafeLoopGuardStateError);
      assert.equal(fs.existsSync(path.join(home, '.marrow', 'session-loop-guard', '.state.lock')), false, 'the lock is released');
      assert.equal(guard.consultSessionLoopGuard(operation(), { home: other }).allow, true);
    });
    assert.deepEqual(win.lockHeld, []);
  } finally { cleanup(home, other); }
});

test('RC-3 and AB59: four hook processes at once all allow; none says unsafe', async () => {
  const home = scratch();
  const script = `
    const guard = require(${JSON.stringify(path.join(__dirname, '..', 'dist', 'session-loop-guard.js'))});
    const win = {
      platform: 'win32',
      ensure(home) {
        const fs = require('node:fs'); const path = require('node:path');
        const directory = path.join(home, '.marrow', 'session-loop-guard');
        fs.mkdirSync(directory, { recursive: true });
        const hold = Date.now() + 150; while (Date.now() < hold) { /* the PowerShell spawn would take this long, and it must not hold the lock */ }
        return { ok: true, marrow: path.join(home, '.marrow'), directory, target: path.join(directory, 'state.json'), stateProven: false, identity: 'x' };
      },
      verify: () => true,
    };
    const results = guard.withLoopGuardPlatform(win, () => Array.from({ length: 6 }, (_, index) => {
      try { return guard.consultSessionLoopGuard({ sessionId: 's' + process.argv[1], harness: 'codex', toolName: 'Bash', toolInput: { n: index }, readOnly: true }, { home: process.argv[2] }).allow; }
      catch (error) { return error.name; }
    }));
    process.stdout.write(JSON.stringify(results));
  `;
  try {
    const children = [1, 2, 3, 4].map((id) => new Promise((resolve) => {
      const child = require('node:child_process').spawn(process.execPath, ['-e', script, String(id), home], { stdio: ['ignore', 'pipe', 'pipe'] });
      let out = '';
      child.stdout.on('data', (chunk) => { out += chunk; });
      child.on('close', () => resolve(out));
    }));
    const outputs = (await Promise.all(children)).map((text) => JSON.parse(text));
    for (const results of outputs) assert.deepEqual(results, [true, true, true, true, true, true]);
  } finally { cleanup(home); }
});

test('G7 and G3: without getuid a POSIX host refuses, and the win32 branch never calls owned()', () => {
  const home = scratch();
  const descriptor = Object.getOwnPropertyDescriptor(process, 'getuid');
  try {
    Object.defineProperty(process, 'getuid', { value: undefined, configurable: true, writable: true });
    assert.throws(() => guard.consultSessionLoopGuard(operation(), { home }), UnsafeLoopGuardStateError);
    onWindows(fakeWindows(), () => assert.equal(guard.consultSessionLoopGuard(operation(), { home }).allow, true));
  } finally {
    Object.defineProperty(process, 'getuid', descriptor);
    cleanup(home);
  }
});

test('U-G6 and AB1: only the real process.platform picks the branch; env and event fields do nothing', () => {
  const home = scratch();
  const previous = process.env.OS;
  process.env.OS = 'Windows_NT';
  try {
    assert.equal(guard.consultSessionLoopGuard(operation(), { home }).allow, true);
    assert.equal(fs.lstatSync(path.join(home, '.marrow', 'session-loop-guard')).mode & 0o777, 0o700);
    assert.equal(fs.lstatSync(guard.sessionLoopGuardPath(home)).mode & 0o777, 0o600);
  } finally {
    if (previous === undefined) delete process.env.OS; else process.env.OS = previous;
    cleanup(home);
  }
  const run = (extra) => {
    const dir = scratch();
    try {
      const result = spawnSync(process.execPath, [path.join(__dirname, '..', 'dist', 'cli.js'), 'cursor-pre-action-hook'], {
        cwd: dir, encoding: 'utf8', timeout: 20_000,
        env: { ...process.env, HOME: dir, USERPROFILE: dir, OS: 'Windows_NT', MARROW_API_KEY: '', MARROW_KEY: '' },
        input: JSON.stringify({ conversation_id: 'ab1', hook_event_name: 'beforeShellExecution', command: 'git status', cwd: dir, workspace_roots: [dir], ...extra }),
      });
      return { status: result.status, stdout: result.stdout, mode: fs.lstatSync(path.join(dir, '.marrow', 'session-loop-guard')).mode & 0o777 };
    } finally { cleanup(dir); }
  };
  const base = run({});
  assert.deepEqual(run({ platform: 'win32' }), base);
  assert.deepEqual(run({ os: 'Windows_NT', process: { platform: 'win32' } }), base);
  assert.equal(base.mode, 0o700, 'the POSIX branch ran');
});

test('AB38 and U-LG7: POSIX still denies a group- or world-writable ~/.marrow, a loose state dir and a loose state file', () => {
  const cases = [
    ['marrow 0777', (home) => fs.chmodSync(path.join(home, '.marrow'), 0o777)],
    ['marrow 0757', (home) => fs.chmodSync(path.join(home, '.marrow'), 0o757)],
    ['marrow 0775', (home) => fs.chmodSync(path.join(home, '.marrow'), 0o775)],
    ['guard 0750', (home) => fs.chmodSync(path.join(home, '.marrow', 'session-loop-guard'), 0o750)],
    ['guard 0777', (home) => fs.chmodSync(path.join(home, '.marrow', 'session-loop-guard'), 0o777)],
    ['state 0644', (home) => fs.chmodSync(guard.sessionLoopGuardPath(home), 0o644)],
    ['marrow symlink', (home) => { const real = path.join(home, 'real'); fs.renameSync(path.join(home, '.marrow'), real); fs.symlinkSync(real, path.join(home, '.marrow')); }],
  ];
  for (const [label, mutate] of cases) {
    const home = scratch();
    try {
      guard.consultSessionLoopGuard(operation(), { home });
      mutate(home);
      assert.throws(() => guard.consultSessionLoopGuard(operation(), { home }), UnsafeLoopGuardStateError, label);
    } finally { cleanup(home); }
  }
});

// ---- U-COL1, U-COL5 ----------------------------------------------------------------------------

test('U-COL1: the same operation and the same secret give the same fingerprint and receipt on the win32 path and the POSIX path', () => {
  const secret = randomBytes(32).toString('base64url');
  const seed = (home) => {
    const directory = path.join(home, '.marrow', 'session-loop-guard');
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    fs.chmodSync(path.join(home, '.marrow'), 0o700);
    fs.chmodSync(directory, 0o700);
    fs.writeFileSync(path.join(directory, 'state.json'), `${JSON.stringify({ version: 1, secret, sessions: {} })}\n`, { mode: 0o600 });
  };
  const posix = scratch();
  const windows = scratch();
  try {
    seed(posix);
    seed(windows);
    const a = guard.consultSessionLoopGuard(operation(), { home: posix });
    const b = onWindows(fakeWindows(), () => guard.consultSessionLoopGuard(operation(), { home: windows }));
    assert.equal(a.fingerprint, b.fingerprint);
    assert.equal(a.receipt, b.receipt);
    assert.match(b.receipt, /^lgr_[a-f0-9]{24}$/);
    const c = onWindows(fakeWindows(), () => guard.consultSessionLoopGuard(operation({ toolInput: { cmd: 'npm test ' } }), { home: windows }));
    assert.notEqual(c.fingerprint, a.fingerprint, 'a trailing space is a different operation (no folding added)');
    const distinct = new Set([a.fingerprint]);
    for (const toolInput of [{ cmd: 'type C:\\Users\\A\\x' }, { cmd: 'type C:\\Users\\a\\x' }, { cmd: 'curl https://x.example/?k=REDACTED&a=1' }, { cmd: 'curl https://x.example/?k=REDACTED&a=2' },
      { cmd: 'X=1 npm test' }, { cmd: 'X=2 npm test' }, { cmd: 'npm test', field: 1 }, { cmd: 'npm test', field: 2 }]) {
      distinct.add(onWindows(fakeWindows(), () => guard.consultSessionLoopGuard(operation({ toolInput }), { home: windows })).fingerprint);
    }
    assert.equal(distinct.size, 9, 'U-COL2 for the loop fingerprint: any difference outside the secret is a different key');
    for (const home of [posix, windows]) assert.equal(fs.readFileSync(guard.sessionLoopGuardPath(home), 'utf8').includes('npm test'), false);
  } finally { cleanup(posix, windows); }
});

test('U-COL5: a runtime dummy key is in no output, state file, deny text or fake-spawn argv and env (allow, loop deny, unsafe deny)', async () => {
  const canary = `synthetic-${randomBytes(18).toString('hex')}`;
  const home = scratch();
  const originalWrite = process.stdout.write;
  const originalFetch = globalThis.fetch;
  const previous = { HOME: process.env.HOME, MARROW_API_KEY: process.env.MARROW_API_KEY, MARROW_KEY: process.env.MARROW_KEY };
  let output = '';
  process.stdout.write = (chunk) => { output += String(chunk); return true; };
  globalThis.fetch = async () => { throw new Error('network must stay unused'); };
  process.env.HOME = home;
  process.env.MARROW_API_KEY = canary;
  try {
    const event = (id, command) => ({ session_id: 'col5', tool_use_id: id, tool_name: 'functions.exec', tool_input: { cmd: command } });
    await onWindows(fakeWindows(), () => runPreActionHookCommand(event('t1', 'git status')));
    await onWindows(fakeWindows(), () => runHookCommand({ ...event('t1', 'git status'), hook_event_name: 'PostToolUse', success: true, tool_result: { canary_in_result: canary } }));
    const firstState = fs.readFileSync(guard.sessionLoopGuardPath(home), 'utf8');
    await onWindows(fakeWindows(), () => runPreActionHookCommand(event('t2', 'git status')));
    const denied = onWindows(fakeWindows(), () => {
      const op = { sessionId: 'col5', agentId: 'a', harness: 'codex', toolName: 'functions.exec', toolInput: { cmd: 'npm test' }, readOnly: true };
      guard.consultSessionLoopGuard(op, { home });
      guard.recordSessionLoopOutcome(op, true, { canary_in_result: canary }, { home });
      return guard.consultSessionLoopGuard(op, { home });
    });
    assert.equal(denied.allow, false, 'the loop deny row ran');
    assert.equal(JSON.stringify(denied).includes(canary), false);
    await onWindows(fakeWindows({ fail: 'acl' }), () => runPreActionHookCommand(event('t3', 'ls')));
    assert.ok(output.includes(UNSAFE_TEXT), 'the unsafe deny row ran');
    assert.equal(output.includes(canary), false, 'no output contains the key');
    assert.equal(firstState.includes(canary), false);
    assert.equal(fs.readFileSync(guard.sessionLoopGuardPath(home), 'utf8').includes(canary), false);
    const state = JSON.parse(fs.readFileSync(guard.sessionLoopGuardPath(home), 'utf8'));
    assert.equal(output.includes(state.secret), false, 'the loop-state secret is never printed');
  } finally {
    process.stdout.write = originalWrite;
    globalThis.fetch = originalFetch;
    for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    cleanup(home);
  }
});

// ---- U-CWD -------------------------------------------------------------------------------------

test('U-CWD1 to CWD3: on win32 no event cwd is a workspace; on POSIX the rule is unchanged', () => {
  assert.equal(mapperEnv('C:\\Users\\x', 'C:\\x', 100, 'win32').cwd, null);
  assert.equal(mapperEnv('C:\\Users\\x', '/tmp/ws', 100, 'win32').cwd, null);
  assert.equal(mapperEnv('C:\\Users\\x', '/', 100, 'win32').cwd, null);
  assert.equal(mapperEnv('/home/x', '/tmp/ws', 100, 'linux').cwd, '/tmp/ws');
  assert.equal(mapperEnv('/home/x', '/tmp/ws', 100).cwd, process.platform === 'win32' ? null : '/tmp/ws', 'the default is the real platform');
  assert.equal(mapperEnv('/home/x', 'relative/dir', 100, 'linux').cwd, null);
  assert.equal(mapperEnv('/home/x', 42, 100, 'darwin').cwd, null);
  assert.equal(mapperEnv('C:\\Users\\x', '/tmp/ws', 100, 'win32').platform, 'win32');
  assert.equal(mapperEnv('/Users/x', '/tmp/ws', 100, 'darwin').platform, 'darwin');
});

test('AB2: a forged /tmp/ws cwd on win32 makes a recursive delete an unknown-workspace stop', () => {
  const { evaluateSeatbelt } = require('../dist/seatbelt/mapper.js');
  const decide = (platform, cwd) => evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command: 'rm -rf ./x' } }, mapperEnv('/home/x', cwd, 250, platform));
  const forged = decide('win32', '/tmp/ws');
  assert.equal(forged.decision, 'stop');
  assert.match(forged.rule, /^S5\./);
  assert.ok(forged.reasons.includes('rm_recursive_unknown_cwd') || forged.hits.some((hit) => /unknown_cwd/.test(hit.reason)), JSON.stringify(forged.reasons));
});

// ---- U-CS, U-K ---------------------------------------------------------------------------------

function asWindowsModes(run) {
  const original = fs.lstatSync;
  fs.lstatSync = function patched(file, ...rest) {
    const stat = original.call(fs, file, ...rest);
    if (rest[0] && rest[0].bigint) return stat;
    return Object.create(stat, { mode: { value: (stat.isDirectory() ? 0o040000 : 0o100000) | 0o666 } });
  };
  try { return run(); } finally { fs.lstatSync = original; }
}

test('U-CS1 and CS2: control.json on Windows-like modes is unsafe, an absent one is default_enabled (unchanged)', () => {
  const home = scratch();
  try {
    asWindowsModes(() => assert.deepEqual(readLocalControlState({ home }), { enabled: true, state: 'default_enabled', changed_at: null }));
    const directory = path.join(home, '.marrow');
    fs.mkdirSync(directory, { mode: 0o700 });
    asWindowsModes(() => assert.equal(readLocalControlState({ home }).state, 'default_enabled'));
    const file = path.join(directory, 'control.json');
    fs.writeFileSync(file, `${JSON.stringify({ version: 1, enabled: false, changed_at: new Date().toISOString(), changed_by: 'owner', change_id: `ctl_${'a'.repeat(32)}` })}\n`, { mode: 0o600 });
    asWindowsModes(() => assert.throws(() => readLocalControlState({ home }), (error) => error.name === 'UnsafeControlStateError'));
  } finally { cleanup(home); }
});

test('U-K1: the env.ts owner-file refusal on win32 is unchanged (a 0644 file supplies no key and names the environment fix)', () => {
  const root = scratch();
  const home = path.join(root, 'home');
  const key = `synthetic-${randomBytes(12).toString('hex')}`;
  fs.mkdirSync(path.join(home, '.marrow'), { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(home, '.marrow', 'env'), `MARROW_API_KEY=${key}\n`, { mode: 0o644 });
  fs.chmodSync(path.join(home, '.marrow', 'env'), 0o644);
  const original = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { value: 'win32' });
  try {
    const resolved = resolveMarrowEnv({ cwd: root, home, env: {} });
    assert.equal(resolved.missing, true);
    assert.equal(resolved.apiKey, '');
    assert.match(resolved.exactFix, /owner-only file permissions cannot be confirmed on Windows\. Fix: set MARROW_API_KEY in your environment/);
    assert.equal(JSON.stringify(resolved).includes(key), false);
  } finally {
    Object.defineProperty(process, 'platform', original);
    cleanup(root);
  }
});
