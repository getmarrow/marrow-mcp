'use strict';

// Test-only (never ships): runs the real hook CLI (`<root>/dist/cli.js <host>-pre-action-hook`) in a child process with a
// fake HOME and the scripted API of cursor-budget-stub.cjs. CB_CLI_ROOT points the same rows at another build (the
// pre-change master), so one row table gives the ACTUAL answer on both. Dummy keys are drawn at runtime and never printed.
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, execFileSync } = require('node:child_process');

const HERE = __dirname;
const ROOT = process.env.CB_CLI_ROOT || path.resolve(HERE, '..', '..');
const SHAPES = {
  cursor: (c, cwd, id) => ({ hook_event_name: 'beforeShellExecution', conversation_id: id, generation_id: 'g1', command: c, cwd }),
  claude: (c, cwd, id) => ({ hook_event_name: 'PreToolUse', session_id: id, tool_use_id: 't1', tool_name: 'Bash', tool_input: { command: c }, cwd }),
  codex: (c, cwd, id) => ({ hook_event_name: 'PreToolUse', session_id: id, turn_id: 't1', tool_use_id: 't1', tool_name: 'Bash', tool_input: { command: c }, cwd }),
};

function dummyKey() {
  const value = `dummy-cursorbudget-${crypto.randomBytes(16).toString('hex')}`;
  if (/^(sk_|pk_|rk_|ghp_|xox)/i.test(value)) throw new Error('dummy key looks live');
  return value;
}

function makeHome() {
  const home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-cursor-budget-')));
  const proj = path.join(home, 'proj');
  fs.mkdirSync(proj);
  execFileSync('git', ['init', '-q', '-b', 'main'], { cwd: proj, stdio: 'ignore' });
  return { home, proj, cleanup: () => fs.rmSync(home, { recursive: true, force: true }) };
}

/** One hook process. Returns the answer, its wall time from spawn, stderr and the server calls it made (paths only). */
function runHook({ host = 'cursor', command, scenario = 'ok', delays = {}, env = {}, world = null, key = dummyKey(), agentId = 'cb-agent-1', extra = {} }) {
  const own = world || makeHome();
  const logFile = path.join(own.home, `calls-${crypto.randomBytes(4).toString('hex')}.log`);
  const stubEnv = { CB_SCENARIO: scenario, CB_LOG: logFile };
  for (const [name, ms] of Object.entries(delays)) stubEnv[`CB_DELAY_${name.toUpperCase()}`] = String(ms);
  return new Promise((resolve) => {
    const t0 = Date.now();
    const child = spawn(process.execPath, [
      '--require', path.join(HERE, 'passwd-home-fake.cjs'), '--require', path.join(HERE, 'seatbelt-hook-preload.cjs'),
      '--require', path.join(HERE, 'cursor-budget-stub.cjs'), path.join(ROOT, 'dist', 'cli.js'), `${host}-pre-action-hook`,
    ], {
      cwd: own.proj, stdio: ['pipe', 'pipe', 'pipe'],
      env: { PATH: process.env.PATH, HOME: own.home, SBT_PASSWD_HOME: own.home, MARROW_API_KEY: key, MARROW_BASE_URL: 'https://api.example.test', MARROW_HOOK_BACKGROUND_NUDGE: 'false', ...stubEnv, ...env },
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (chunk) => { out += chunk; });
    child.stderr.on('data', (chunk) => { err += chunk; });
    const killer = setTimeout(() => child.kill('SIGKILL'), 40_000);
    child.on('close', (status) => {
      clearTimeout(killer);
      let answer = null;
      try { answer = out.trim() ? JSON.parse(out) : null; } catch { answer = null; }
      const calls = fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8').trim().split('\n').filter(Boolean).map((line) => line.split(' ')[0]) : [];
      if (!world) own.cleanup();
      resolve({ status, wallMs: Date.now() - t0, out, err, answer, calls, key });
    });
    child.stdin.on('error', () => {});
    child.stdin.end(JSON.stringify({ ...SHAPES[host](command, own.proj, agentId), ...extra }));
  });
}

const denied = (r) => r.status === 2 || r.answer?.permission === 'deny' || r.answer?.hookSpecificOutput?.permissionDecision === 'deny';
/** The answer lets the action run (no deny, no ask), in any host's JSON shape. */
const allowed = (r) => r.status === 0 && !denied(r) && r.answer?.permission !== 'ask';

module.exports = { runHook, makeHome, dummyKey, allowed, denied, ROOT };
