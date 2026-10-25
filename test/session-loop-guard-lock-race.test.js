const assert = require('node:assert/strict');
const fs = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');
const { randomBytes } = require('node:crypto');

const {
  consultSessionLoopGuard,
  recordSessionLoopOutcome,
  sessionLoopGuardPath,
  UnsafeLoopGuardStateError,
} = require('../dist/session-loop-guard.js');
const { runPreActionHookCommand } = require('../dist/hook-pre-action.js');

const ATTEMPTS = 40;
const RUNAWAY = 250;
// Un-patched references: helpers that touch the lock must not count as guard attempts.
const realOpen = fs.openSync;
const realUnlink = fs.unlinkSync;

function home() {
  const root = fs.mkdtempSync(join(tmpdir(), 'marrow-loop-guard-lock-'));
  const directory = join(root, '.marrow', 'session-loop-guard');
  fs.mkdirSync(join(root, '.marrow'), { mode: 0o700 });
  fs.mkdirSync(directory, { mode: 0o700 });
  return { root, directory, lock: join(directory, '.state.lock') };
}

function operation(overrides = {}) {
  return { sessionId: 'lock-session', agentId: 'lock-agent', harness: 'codex', toolName: 'functions.exec', toolInput: { cmd: 'npm test' }, readOnly: true, ...overrides };
}

function errno(code) {
  return Object.assign(new Error(`${code} injected`), { code });
}

function plantLock(lock, mode = 0o600) {
  fs.closeSync(realOpen(lock, 'wx', mode));
  fs.chmodSync(lock, mode);
}

/**
 * Patches node:fs (the compiled guard calls fs.* at call time) for the lock path only.
 * A handler runs BEFORE the real call; it may mutate the disk, throw, or return { result }.
 */
function instrument(lock, handlers = {}) {
  const real = {
    open: fs.openSync, lstat: fs.lstatSync, unlink: fs.unlinkSync, fstat: fs.fstatSync, wait: Atomics.wait,
  };
  const calls = { open: 0, lstat: 0, unlink: 0, fstat: 0, waits: [] };
  const wrap = (name, matches) => function patched(...args) {
    if (matches(args[0])) {
      calls[name] += 1;
      if (calls[name] > RUNAWAY) throw new Error(`runaway ${name} on the lock`);
      const handled = handlers[name] && handlers[name](calls[name], args);
      if (handled && 'result' in handled) return handled.result;
    }
    return real[name].apply(this, args);
  };
  const onLock = (path) => path === lock;
  fs.openSync = wrap('open', onLock);
  fs.lstatSync = wrap('lstat', handlers.lstatPath ? handlers.lstatPath : onLock);
  fs.unlinkSync = wrap('unlink', onLock);
  Atomics.wait = (array, index, value, timeout) => { calls.waits.push(timeout); return 'timed-out'; };
  return {
    calls,
    restore() {
      fs.openSync = real.open;
      fs.lstatSync = real.lstat;
      fs.unlinkSync = real.unlink;
      fs.fstatSync = real.fstat;
      Atomics.wait = real.wait;
    },
  };
}

function withHome(callback, handlers) {
  const dirs = home();
  const patch = instrument(dirs.lock, typeof handlers === 'function' ? handlers(dirs) : handlers);
  try {
    return callback(dirs, patch.calls);
  } finally {
    patch.restore();
    fs.rmSync(dirs.root, { recursive: true, force: true });
  }
}

test('the lock is released between EEXIST and lstat: the acquire is retried and succeeds', () => {
  const dirs = home();
  plantLock(dirs.lock);
  const patch = instrument(dirs.lock, { lstat: (n) => { if (n === 1) realUnlink(dirs.lock); } });
  try {
    const decision = consultSessionLoopGuard(operation(), { home: dirs.root });
    assert.equal(decision.allow, true);
    assert.equal(patch.calls.open, 2);
    assert.equal(patch.calls.lstat, 1);
    assert.equal(fs.existsSync(dirs.lock), false);
    assert.ok(fs.existsSync(sessionLoopGuardPath(dirs.root)));
    recordSessionLoopOutcome(operation(), true, { ok: true }, { home: dirs.root });
    assert.equal(consultSessionLoopGuard(operation(), { home: dirs.root }).allow, false);
  } finally {
    patch.restore();
    fs.rmSync(dirs.root, { recursive: true, force: true });
  }
});

test('repeated release races stay inside the same 40 attempt budget', () => {
  withHome((dirs, calls) => {
    assert.equal(consultSessionLoopGuard(operation(), { home: dirs.root }).allow, true);
    assert.equal(calls.open, 4);
    assert.equal(calls.lstat, 3);
  }, ({ lock }) => ({
    open: (n) => { if (n <= 3) plantLock(lock); },
    lstat: () => realUnlink(lock),
  }));
});

test('ENOENT after EEXIST on every attempt ends fail-closed after exactly 40 attempts', () => {
  withHome((dirs, calls) => {
    assert.throws(() => consultSessionLoopGuard(operation(), { home: dirs.root }), UnsafeLoopGuardStateError);
    assert.equal(calls.open, ATTEMPTS);
    assert.equal(calls.lstat, ATTEMPTS);
  }, ({ lock }) => ({
    open: () => { if (!fs.existsSync(lock)) plantLock(lock); },
    lstat: () => realUnlink(lock),
  }));
});

test('a phantom ENOENT while the lock really stays held still ends fail-closed after 40 attempts', () => {
  withHome((dirs, calls) => {
    plantLock(dirs.lock);
    assert.throws(() => consultSessionLoopGuard(operation(), { home: dirs.root }), UnsafeLoopGuardStateError);
    assert.equal(calls.open, ATTEMPTS);
    assert.equal(calls.lstat, ATTEMPTS);
    assert.equal(fs.existsSync(dirs.lock), true);
  }, { lstat: () => { throw errno('ENOENT'); } });
});

test('a permanent lock ends fail-closed after exactly 40 attempts and the same 5 ms waits', () => {
  withHome((dirs, calls) => {
    plantLock(dirs.lock);
    assert.throws(() => consultSessionLoopGuard(operation(), { home: dirs.root }), UnsafeLoopGuardStateError);
    assert.equal(calls.open, ATTEMPTS);
    assert.equal(calls.lstat, ATTEMPTS);
    assert.deepEqual(calls.waits, Array(ATTEMPTS).fill(5));
    assert.equal(fs.existsSync(dirs.lock), true);
  });
});

test('a stale lock older than 30 seconds is still broken and the acquire proceeds', () => {
  withHome((dirs, calls) => {
    plantLock(dirs.lock);
    const old = new Date(Date.now() - 31_000);
    fs.utimesSync(dirs.lock, old, old);
    assert.equal(consultSessionLoopGuard(operation(), { home: dirs.root }).allow, true);
    assert.equal(calls.open, 2);
    assert.equal(calls.unlink >= 1, true);
  });
});

test('symlink, directory, wrong-mode and wrong-owner locks fail closed on the first attempt', () => {
  for (const kind of ['symlink', 'dangling', 'directory', 'mode-0644', 'mode-0000', 'mode-0700', 'owner']) {
    const dirs = home();
    const other = join(dirs.root, 'other-file');
    fs.writeFileSync(other, 'untouched', { mode: 0o600 });
    if (kind === 'symlink') fs.symlinkSync(other, dirs.lock);
    else if (kind === 'dangling') fs.symlinkSync(join(dirs.root, 'missing'), dirs.lock);
    else if (kind === 'directory') fs.mkdirSync(dirs.lock, { mode: 0o700 });
    else if (kind === 'mode-0644') plantLock(dirs.lock, 0o644);
    else if (kind === 'mode-0000') plantLock(dirs.lock, 0o000);
    else if (kind === 'mode-0700') plantLock(dirs.lock, 0o700);
    else plantLock(dirs.lock);
    const handlers = kind === 'owner'
      ? { lstat: () => ({ result: { isFile: () => true, isSymbolicLink: () => false, uid: process.getuid() + 1, mode: 0o100600, mtimeMs: Date.now() } }) }
      : {};
    const patch = instrument(dirs.lock, handlers);
    try {
      assert.throws(() => consultSessionLoopGuard(operation(), { home: dirs.root }), UnsafeLoopGuardStateError, kind);
      assert.equal(patch.calls.open, 1, kind);
      assert.equal(patch.calls.lstat, 1, kind);
      assert.deepEqual(patch.calls.waits, [], kind);
      assert.equal(fs.readFileSync(other, 'utf8'), 'untouched', kind);
      assert.equal(fs.existsSync(sessionLoopGuardPath(dirs.root)), false, kind);
    } finally {
      patch.restore();
      fs.rmSync(dirs.root, { recursive: true, force: true });
    }
  }
});

test('every lstat error other than ENOENT escapes unchanged with no retry', () => {
  for (const code of ['EACCES', 'ELOOP', 'EIO', 'EPERM', 'ENOTDIR', 'ENAMETOOLONG', 'enoent', 'EBADF', 'UNKNOWN']) {
    withHome((dirs, calls) => {
      plantLock(dirs.lock);
      assert.throws(() => consultSessionLoopGuard(operation(), { home: dirs.root }), (error) => {
        assert.equal(error.code, code);
        assert.equal(error instanceof UnsafeLoopGuardStateError, false);
        return true;
      }, code);
      assert.equal(calls.open, 1, code);
      assert.equal(calls.lstat, 1, code);
    }, { lstat: () => { throw errno(code); } });
  }
  withHome((dirs, calls) => {
    plantLock(dirs.lock);
    assert.throws(() => consultSessionLoopGuard(operation(), { home: dirs.root }), (error) => error.code === undefined && /no code/.test(error.message));
    assert.equal(calls.open, 1);
  }, { lstat: () => { throw new Error('no code, ENOENT in the text only'); } });
});

test('ENOENT from any call other than the lock lstat stays as it was', () => {
  withHome((dirs, calls) => {
    assert.throws(() => consultSessionLoopGuard(operation(), { home: dirs.root }), UnsafeLoopGuardStateError);
    assert.equal(calls.open, 1);
    assert.equal(calls.lstat, 0);
  }, { open: () => { throw errno('ENOENT'); } });
  withHome((dirs, calls) => {
    assert.throws(() => consultSessionLoopGuard(operation(), { home: dirs.root }), UnsafeLoopGuardStateError);
    assert.equal(calls.open, 1);
  }, { open: () => { throw errno('EACCES'); } });
  withHome((dirs, calls) => {
    plantLock(dirs.lock);
    const old = new Date(Date.now() - 31_000);
    fs.utimesSync(dirs.lock, old, old);
    assert.throws(() => consultSessionLoopGuard(operation(), { home: dirs.root }), (error) => error.code === 'ENOENT' && !(error instanceof UnsafeLoopGuardStateError));
    assert.equal(calls.open, 1);
    assert.equal(calls.unlink, 1);
  }, { unlink: () => { throw errno('ENOENT'); } });
  withHome((dirs, calls) => {
    assert.throws(() => consultSessionLoopGuard(operation(), { home: dirs.root }), (error) => error.code === 'ENOENT' && !(error instanceof UnsafeLoopGuardStateError));
    assert.equal(calls.open, 0);
  }, ({ root }) => ({ lstatPath: (path) => path === join(root, '.marrow'), lstat: () => { throw errno('ENOENT'); } }));
  const dirs = home();
  const realFstat = fs.fstatSync;
  const patch = instrument(dirs.lock);
  try {
    fs.fstatSync = (fd, ...rest) => { throw errno('ENOENT'); };
    assert.throws(() => consultSessionLoopGuard(operation(), { home: dirs.root }), UnsafeLoopGuardStateError);
    assert.equal(patch.calls.open, 1);
  } finally {
    fs.fstatSync = realFstat;
    patch.restore();
    fs.rmSync(dirs.root, { recursive: true, force: true });
  }
});

test('a lock swapped for a symlink, directory or planted file around the race stays fail-closed', () => {
  for (const kind of ['symlink-at-lstat', 'directory-at-lstat', 'symlink-at-retry', 'wrong-mode-at-retry']) {
    const dirs = home();
    const other = join(dirs.root, 'other-file');
    fs.writeFileSync(other, 'untouched', { mode: 0o600 });
    plantLock(dirs.lock);
    const handlers = {
      lstat: (n) => {
        if (n !== 1) return;
        realUnlink(dirs.lock);
        if (kind === 'symlink-at-lstat') fs.symlinkSync(other, dirs.lock);
        if (kind === 'directory-at-lstat') fs.mkdirSync(dirs.lock, { mode: 0o700 });
      },
      open: (n) => {
        if (n !== 2) return;
        if (kind === 'symlink-at-retry') fs.symlinkSync(other, dirs.lock);
        if (kind === 'wrong-mode-at-retry') plantLock(dirs.lock, 0o666);
      },
    };
    const patch = instrument(dirs.lock, handlers);
    try {
      assert.throws(() => consultSessionLoopGuard(operation(), { home: dirs.root }), UnsafeLoopGuardStateError, kind);
      assert.equal(fs.readFileSync(other, 'utf8'), 'untouched', kind);
      assert.equal(fs.existsSync(sessionLoopGuardPath(dirs.root)), false, kind);
      assert.equal(patch.calls.open <= 2, true, kind);
    } finally {
      patch.restore();
      fs.rmSync(dirs.root, { recursive: true, force: true });
    }
  }
});

test('hook: the release race no longer produces the unsafe-state denial, and an unsafe lock still does', async () => {
  const keyName = ['MARROW', 'API', 'KEY'].join('_');
  const originalFetch = globalThis.fetch;
  const originalWrite = process.stdout.write;
  const previous = { HOME: process.env.HOME, [keyName]: process.env[keyName], MARROW_AUTO_HOOK: process.env.MARROW_AUTO_HOOK };
  const event = { session_id: 'race-session', tool_use_id: 'race-one', tool_name: 'functions.exec', tool_input: { cmd: 'git status' } };
  let output = '';
  globalThis.fetch = async () => { throw new Error('network must stay unused'); };
  process.stdout.write = (chunk) => { output += String(chunk); return true; };
  process.env[keyName] = randomBytes(12).toString('hex');
  process.env.MARROW_AUTO_HOOK = 'true';
  const dirs = home();
  process.env.HOME = dirs.root;
  try {
    plantLock(dirs.lock);
    let patch = instrument(dirs.lock, { lstat: (n) => { if (n === 1) realUnlink(dirs.lock); } });
    try {
      await runPreActionHookCommand(event);
      assert.deepEqual(JSON.parse(output), {});
      assert.equal(patch.calls.open, 2);
    } finally {
      patch.restore();
    }
    output = '';
    fs.symlinkSync(join(dirs.root, 'elsewhere'), dirs.lock);
    patch = instrument(dirs.lock);
    try {
      await runPreActionHookCommand({ ...event, tool_use_id: 'race-two' });
      const denial = JSON.parse(output);
      assert.equal(denial.hookSpecificOutput.permissionDecision, 'deny');
      assert.match(denial.hookSpecificOutput.permissionDecisionReason, /loop guard state is unsafe/);
    } finally {
      patch.restore();
    }
  } finally {
    globalThis.fetch = originalFetch;
    process.stdout.write = originalWrite;
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    fs.rmSync(dirs.root, { recursive: true, force: true });
  }
});
