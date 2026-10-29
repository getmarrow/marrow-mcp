'use strict';

// cursor-hold (29 Oct 2026): a Cursor `git commit` was held with "Marrow did not answer in time" on a machine the
// owner took to be keyless. That text exists only on the keyed path (src/hook-pre-action.ts, the control timeout).
// A hook with no key answers locally, with no wait on any server. These rows pin both halves with the real hook CLI
// in a temporary home and Cursor's own event shape (beforeShellExecution):
//   S1  nothing under ~/.marrow, no MARROW_* variable      S2  a key in ~/.marrow/env and the API never answers or refuses
//   S3  only a fleet key NAME (MARROW_KEY_TEST) in ~/.marrow/env
// Rows 1-4 and 6 hold at BASE (3.9.108) as they do now: the keyless seatbelt is not loosened. Row 5 is the wait:
// at BASE the answer is written at the hook budget and the process then idles on two pending TCP connects until
// their own ~10 s connect timeout; now it leaves once the answer is flushed. Counts and gaps, not absolute limits.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn, spawnSync, execFileSync } = require('node:child_process');

const { HELD_SLOW_TEXT, SEATBELT_CURSOR_ASK_USER_TEXT } = require('../dist/hook-pre-action.js');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const PRELOAD = path.join(__dirname, 'support', 'seatbelt-hook-preload.cjs');
const STOP = /MARROW SEATBELT stopped/;
const CLAIMED = /linked to an account but has no working key/;

// A fixed non-key prefix + runtime hex: never classified as a live key, never printed.
function dummyKey() {
  const value = `dummy-cursorhold-${crypto.randomBytes(16).toString('hex')}`;
  assert.ok(!/^(sk_|pk_|rk_|ghp_|xox)/i.test(value));
  return value;
}

function sandbox(state, baseUrl) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-cursor-hold-')));
  const home = path.join(root, 'home');
  const proj = path.join(root, 'proj');
  const remote = path.join(root, 'remote.git');
  fs.mkdirSync(home, { mode: 0o700 });
  fs.chmodSync(home, 0o700);
  const git = (args, cwd) => execFileSync('git', args, {
    cwd,
    env: { PATH: process.env.PATH, HOME: home, GIT_CONFIG_NOSYSTEM: '1', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.invalid' },
    stdio: 'ignore',
  });
  git(['init', '-q', '--bare', remote]);
  fs.mkdirSync(proj);
  git(['init', '-q', '-b', 'main'], proj);
  fs.writeFileSync(path.join(proj, 'a.txt'), 'a\n');
  git(['add', '.'], proj);
  git(['commit', '-q', '-m', 'init'], proj);
  git(['remote', 'add', 'origin', remote], proj);
  git(['push', '-q', 'origin', 'main'], proj);
  fs.writeFileSync(path.join(proj, 'a.txt'), 'b\n');
  git(['add', '.'], proj);
  const key = dummyKey();
  if (state !== 'S1') {
    fs.mkdirSync(path.join(home, '.marrow'), { mode: 0o700 });
    fs.chmodSync(path.join(home, '.marrow'), 0o700);
    const text = state === 'S3'
      ? `MARROW_KEY_TEST=${key}\n`
      : `MARROW_API_KEY=${key}\nMARROW_BASE_URL=${baseUrl}\nMARROW_ALLOWED_BASE_URLS=${baseUrl}\n`;
    const file = path.join(home, '.marrow', 'env');
    fs.writeFileSync(file, text, { mode: 0o600 });
    fs.chmodSync(file, 0o600);
  }
  return { root, home, proj, key, netspy: path.join(root, 'net.log'), cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}

const cursorEvent = (sb, command) => ({
  hook_event_name: 'beforeShellExecution', conversation_id: `ch-${crypto.randomBytes(5).toString('hex')}`, generation_id: 'g1', command, cwd: sb.proj,
});
const hookEnv = (sb, extra = {}) => ({ PATH: process.env.PATH, HOME: sb.home, SBT_PASSWD_HOME: sb.home, MARROW_HOOK_BACKGROUND_NUDGE: 'false', ...extra });

/** Runs the real hook CLI; reports the answer, the exit code, when stdout was first written and when the process left. */
function runHook(sb, command, extraEnv = {}) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    const child = spawn(process.execPath, ['--require', PRELOAD, CLI, 'cursor-pre-action-hook'], { cwd: sb.proj, env: hookEnv(sb, extraEnv), stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    let firstOut = null;
    let exitAt = null;
    child.stdout.on('data', (chunk) => { if (firstOut === null) firstOut = Date.now() - t0; out += chunk; });
    child.stderr.on('data', (chunk) => { err += chunk; });
    child.on('exit', () => { exitAt = Date.now() - t0; });
    const killer = setTimeout(() => child.kill('SIGKILL'), 60_000);
    child.on('close', (code) => {
      clearTimeout(killer);
      const secret = (value) => value.split(sb.key).join('<dummy>');
      resolve({ code, out: secret(out), err: secret(err), firstOut, exitAt, wallMs: Date.now() - t0 });
    });
    child.stdin.end(JSON.stringify(cursorEvent(sb, command)));
  });
}

function runHookSync(sb, command) {
  const started = Date.now();
  const r = spawnSync(process.execPath, ['--require', PRELOAD, CLI, 'cursor-pre-action-hook'], {
    cwd: sb.proj, encoding: 'utf8', timeout: 60_000, input: JSON.stringify(cursorEvent(sb, command)), env: hookEnv(sb, { SBT_NETSPY: sb.netspy }),
  });
  return { code: r.status, out: r.stdout || '', err: r.stderr || '', wallMs: Date.now() - started };
}

const answer = (r) => { try { return JSON.parse(r.out); } catch { return null; } };
const networkAttempts = (sb) => (fs.existsSync(sb.netspy) ? fs.readFileSync(sb.netspy, 'utf8').split('\n').filter(Boolean).length : 0);
const stopped = (r) => r.code === 2 || answer(r)?.permission === 'deny' ? STOP.test(`${r.out}${r.err}`) : false;

const COMMIT_ROWS = [
  'git commit -m t',
  'git commit --trailer "Co-authored-by: Cursor <cursoragent@cursor.com>" -m t',
];

test('cursor-hold row 1, S1 (no key, nothing under ~/.marrow): git commit answers ask locally, Cursor\'s own Run/Skip prompt, with no network attempt', async () => {
  const sb = sandbox('S1');
  try {
    for (const command of COMMIT_ROWS) {
      for (const call of ['cold', 'warm']) {
        const r = runHookSync(sb, command);
        const a = answer(r);
        assert.equal(r.code, 0, `${call} ${command}`);
        assert.equal(a.permission, 'ask', `${call} ${command}: ${r.out}`);
        assert.equal(a.user_message, SEATBELT_CURSOR_ASK_USER_TEXT);
        assert.ok(!r.out.includes(HELD_SLOW_TEXT));
      }
    }
    assert.equal(networkAttempts(sb), 0, 'a keyless hook never reaches for a server');
    const status = answer(runHookSync(sb, 'git status'));
    assert.equal(status.permission, 'allow');
  } finally { sb.cleanup(); }
});

test('cursor-hold row 2, S1: a force push is stopped with the seatbelt stop text, cold and warm, with no network attempt', () => {
  const sb = sandbox('S1');
  try {
    for (const call of ['cold', 'warm']) {
      const r = runHookSync(sb, 'git push --force origin main');
      assert.equal(answer(r).permission, 'deny', call);
      assert.match(answer(r).user_message, STOP, call);
    }
    assert.equal(networkAttempts(sb), 0);
  } finally { sb.cleanup(); }
});

test('cursor-hold row 3, S3 (only a fleet key name in ~/.marrow/env): git commit answers locally (the claimed-no-key hold, unchanged), never HELD_SLOW_TEXT; a force push is still stopped', () => {
  const sb = sandbox('S3');
  try {
    for (const command of COMMIT_ROWS) {
      const r = runHookSync(sb, command);
      const a = answer(r);
      assert.equal(a.permission, 'deny', command);
      assert.match(a.user_message, CLAIMED, command);
      assert.ok(!r.out.includes(HELD_SLOW_TEXT));
    }
    const push = runHookSync(sb, 'git push --force origin main');
    assert.match(answer(push).user_message, STOP);
    assert.equal(networkAttempts(sb), 0);
  } finally { sb.cleanup(); }
});

// The ABUSE table (ACTUAL at BASE e3752f3 and here): every row below is stopped by the keyless seatbelt in S1 and in S3.
const MUST_STOP = [
  'git push --force origin main',
  'git commit -m t && git push --force origin main',
  'git commit -m t; git push -f origin main',
  'bash -c "git push --force origin main"',
  '(git push --force)',
  'git push --force origin main | cat',
  'echo x | git push --force origin main',
  'git push origin +main',
  'git -c x=y push --force',
  'git push --force --force origin main',
  'git push --force-with-lease --force origin main',
  'git push --no-force --force origin main',
  'git push --force --frobnicate origin main',
  'F=--force; git push $F origin main',
  'git push origin --delete main',
];

test('cursor-hold row 4, ABUSE: every force-push spelling (chains, bash -c, subshell, pipes, +main, -c x=y, repeated flags, an unknown flag, a variable, a branch delete) stops in S1 and S3; the words in a commit message do not', () => {
  for (const state of ['S1', 'S3']) {
    const sb = sandbox(state);
    try {
      for (const command of MUST_STOP) {
        const r = runHookSync(sb, command);
        assert.ok(stopped(r), `${state}: ${command}: ${r.out}${r.err}`);
      }
      const words = runHookSync(sb, 'git commit -m "safe push --force"');
      assert.ok(!stopped(words), `${state}: misleading words in a message are not a force push: ${words.out}`);
      assert.equal(networkAttempts(sb), 0, state);
    } finally { sb.cleanup(); }
  }
});

test('cursor-hold row 5, S2 (key set, Marrow never answers): the answers are unchanged (commit and force push held with HELD_SLOW_TEXT, git status allowed offline) and the hook leaves once the answer is written instead of idling on pending connects', async () => {
  const hole = net.createServer((socket) => { socket.on('error', () => {}); });
  await new Promise((resolve) => hole.listen(0, '127.0.0.1', resolve));
  const baseUrl = `https://127.0.0.1:${hole.address().port}`;
  const sb = sandbox('S2', baseUrl);
  try {
    for (const command of ['git commit -m t', 'git push --force origin main']) {
      const r = await runHook(sb, command);
      assert.equal(r.code, 0, command);
      const a = answer(r);
      assert.equal(a.permission, 'deny', command);
      assert.equal(a.user_message, HELD_SLOW_TEXT, command);
      assert.ok(r.firstOut !== null && r.exitAt !== null);
      // BASE: the answer is out at the hook budget and the process stays about 7 s more on two pending connects.
      assert.ok(r.exitAt - r.firstOut < 2_500, `${command}: the process stayed ${r.exitAt - r.firstOut} ms after its answer`);
    }
    const status = await runHook(sb, 'git status');
    assert.equal(answer(status).permission, 'allow');
    assert.match(status.out, /Marrow is offline\. This action is allowed/);
    assert.ok(status.exitAt - status.firstOut < 2_500, `git status: the process stayed ${status.exitAt - status.firstOut} ms after its answer`);
  } finally { hole.close(); sb.cleanup(); }
});

test('cursor-hold row 6, S2 (key set, Marrow refuses the connection): the answer is the same request_failed hold, and no secret is in the output', async () => {
  const sb = sandbox('S2', 'https://127.0.0.1:1');
  try {
    const r = await runHook(sb, 'git commit -m t');
    assert.equal(answer(r).permission, 'deny');
    assert.match(answer(r).user_message, /request_failed/);
    assert.ok(!r.out.includes('dummy-cursorhold-') && !r.err.includes('dummy-cursorhold-'));
  } finally { sb.cleanup(); }
});

test('cursor-hold row 7, exit code: a hook that fails its own check still exits with the code it set (the exit helper keeps process.exitCode)', () => {
  const sb = sandbox('S1');
  try {
    // Not JSON on stdin: the hook holds the call and exits non-zero or answers deny; the helper must not turn that into 0.
    const r = spawnSync(process.execPath, ['--require', PRELOAD, CLI, 'cursor-pre-action-hook'], { cwd: sb.proj, encoding: 'utf8', timeout: 60_000, input: 'not json', env: hookEnv(sb) });
    const denied = r.status !== 0 || answer({ out: r.stdout })?.permission === 'deny';
    assert.ok(denied, `${r.status} ${r.stdout}`);
  } finally { sb.cleanup(); }
});

test('cursor-hold row 8, consumers: Windsurf denies with exit code 2 and its stderr stop text, and the exit helper keeps that code (S1 force push stopped, S1 commit passes)', () => {
  const sb = sandbox('S1');
  try {
    const run = (command) => spawnSync(process.execPath, ['--require', PRELOAD, CLI, 'windsurf-pre-action-hook'], {
      cwd: sb.proj,
      encoding: 'utf8',
      timeout: 60_000,
      input: JSON.stringify({ agent_action_name: 'pre_run_command', trajectory_id: `ch-${crypto.randomBytes(5).toString('hex')}`, execution_id: 'e', tool_info: { command_line: command, cwd: sb.proj } }),
      env: hookEnv(sb),
    });
    const push = run('git push --force origin main');
    assert.equal(push.status, 2, push.stderr);
    assert.match(push.stderr, STOP);
    const commit = run('git commit -m t');
    assert.equal(commit.status, 0, `${commit.stdout}${commit.stderr}`);
  } finally { sb.cleanup(); }
});
