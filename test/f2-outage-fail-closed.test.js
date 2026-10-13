'use strict';

// F2 (host matrix 10-13): a keyed high-risk action was allowed as "Marrow is offline" although the
// Worker had answered (runtime 200, then the permit service 503 with safe_to_continue:false). Every
// host shares the one control path, so all 7 hook entries are driven through the real CLI with the
// recorded production-shaped bodies (test/support/f2-fetch-scenarios.cjs). A reached answer is
// honored; a real outage holds high-risk actions (the server's failure_mode:
// fail_closed_for_high_risk) and keeps the outage allow for routine ones. Dummy key generated here.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync, execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const PASSWD = path.join(__dirname, 'support', 'passwd-home-fake.cjs');
const SCENARIOS = path.join(__dirname, 'support', 'f2-fetch-scenarios.cjs');
const { MARROW_OUTAGE_WARNING, HELD_OFFLINE_TEXT, classifyTool } = require('../dist/hook-pre-action.js');
const recorded = require('./fixtures/f2-recorded-force-push.json');

const SHAPES = {
  claude: (c, cwd) => ({ hook_event_name: 'PreToolUse', session_id: 'f2-claude', tool_use_id: 't1', tool_name: 'Bash', tool_input: { command: c }, cwd }),
  codex: (c, cwd) => ({ hook_event_name: 'PreToolUse', session_id: 'f2-codex', turn_id: 't1', tool_use_id: 't1', tool_name: 'Bash', tool_input: { command: c }, cwd }),
  cursor: (c, cwd) => ({ hook_event_name: 'beforeShellExecution', conversation_id: 'f2-cursor', generation_id: 'g1', command: c, cwd }),
  gemini: (c, cwd) => ({ session_id: 'f2-gemini', hook_event_name: 'BeforeTool', tool_name: 'run_shell_command', tool_input: { command: c }, cwd }),
  grok: (c, cwd) => ({ hookEventName: 'PreToolUse', sessionId: 'f2-grok', toolUseId: 't', toolName: 'run_terminal_command', toolInput: { command: c }, cwd }),
  cline: (c, cwd) => ({ hookName: 'PreToolUse', taskId: 'f2-cline', workspaceRoots: [cwd], preToolUse: { toolName: 'execute_command', parameters: { command: c } } }),
  windsurf: (c, cwd) => ({ agent_action_name: 'pre_run_command', trajectory_id: 'f2-windsurf', execution_id: 'e1', tool_info: { command_line: c, cwd } }),
};
const HOSTS = Object.keys(SHAPES);
const HIGH = 'git push --force origin main';
const ROUTINE = 'mkdir -p build/out';

const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-f2-')));
test.after(() => fs.rmSync(base, { recursive: true, force: true }));
let n = 0;

function hook(host, command, scenario) {
  const home = path.join(base, `h${n += 1}`);
  const proj = path.join(home, 'proj');
  fs.mkdirSync(proj, { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  execFileSync('git', ['init', '-q', '-b', 'main'], { cwd: proj, stdio: 'ignore' });
  const logFile = path.join(home, 'calls.log');
  const key = `mrw_test_${crypto.randomBytes(16).toString('hex')}`;
  const r = spawnSync(process.execPath, ['--require', PASSWD, '--require', SCENARIOS, CLI, `${host}-pre-action-hook`], {
    cwd: proj, input: JSON.stringify(SHAPES[host](command, proj)), encoding: 'utf8', timeout: 30_000,
    env: {
      PATH: process.env.PATH, HOME: home, SBT_PASSWD_HOME: home, MARROW_API_KEY: key, MARROW_BASE_URL: 'https://api.example.test',
      MARROW_HOOK_BACKGROUND_NUDGE: 'false', F2_SCENARIO: scenario, F2_LOG: logFile,
    },
  });
  assert.equal(r.error, undefined);
  const all = `${r.stdout}\n${r.stderr}`;
  assert.equal(all.includes(key), false, 'the key never appears in hook output');
  let j = null;
  try { j = r.stdout.trim() ? JSON.parse(r.stdout) : null; } catch { j = null; }
  const stop = r.status === 2 || j?.hookSpecificOutput?.permissionDecision === 'deny' || j?.permission === 'deny' || j?.decision === 'deny' || j?.cancel === true;
  const calls = fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8').trim().split('\n').filter(Boolean) : [];
  return { stop, status: r.status, out: all, json: j, calls };
}

test('F2 classification: the force push is high risk and the routine command is medium on the shared classifier', () => {
  assert.equal(classifyTool({ tool_name: 'Bash', tool_input: { command: HIGH } }).risk, 'high');
  assert.equal(classifyTool({ tool_name: 'Bash', tool_input: { command: ROUTINE } }).risk, 'medium');
  // The recorded server answer itself states the failure mode the fix follows.
  assert.equal(recorded.runtime.data.failure_mode.if_marrow_unreachable, 'fail_closed_for_high_risk');
  assert.equal(recorded.enforcement_issue.status, 503);
  assert.equal(recorded.enforcement_issue.body.details.safe_to_continue, false);
});

test('F2 (recorded bodies): runtime 200 then permit 503 denies the keyed force push on all 7 hosts, never "offline, allowed"', () => {
  for (const host of HOSTS) {
    const r = hook(host, HIGH, 'permit-503');
    assert.equal(r.stop, true, `${host}: ${r.out.slice(0, 300)}`);
    assert.equal(r.out.includes(MARROW_OUTAGE_WARNING), false, `${host} must not claim an outage`);
    assert.equal(r.out.includes(HELD_OFFLINE_TEXT), false, `${host}: Marrow answered, so it is not "cannot be reached"`);
    assert.doesNotMatch(r.out, /This action is allowed/, host);
    assert.deepEqual(r.calls.filter((c) => /runtime|enforcement/.test(c)).slice(0, 2), ['/v1/agent/runtime', '/v1/agent/enforcement#issue'], host);
  }
});

test('F2: every other failure after the gate answered (think 503/reset, permit 502, verify reset) denies on all 7 hosts', () => {
  for (const scenario of ['think-503', 'think-reset', 'permit-502', 'verify-reset']) {
    for (const host of HOSTS) {
      const r = hook(host, HIGH, scenario);
      assert.equal(r.stop, true, `${scenario} ${host}: ${r.out.slice(0, 300)}`);
      assert.equal(r.out.includes(MARROW_OUTAGE_WARNING), false, `${scenario} ${host}`);
      assert.equal(r.out.includes(HELD_OFFLINE_TEXT), false, `${scenario} ${host}`);
      assert.ok(r.calls.includes('/v1/agent/runtime'), `${scenario} ${host} reached the gate`);
    }
  }
});

test('F2: a failure after the gate answered keeps the outage policy for a routine action (Windsurf, Gemini, Grok need a permit for every mutation)', () => {
  for (const scenario of ['permit-503', 'verify-reset', 'think-503']) {
    for (const host of HOSTS) {
      const r = hook(host, ROUTINE, scenario);
      assert.equal(r.stop, false, `${scenario} ${host}: ${r.out.slice(0, 300)}`);
    }
  }
});

test('F2: a real outage (refused, DNS, runtime 503) holds the high-risk action on all 7 hosts', () => {
  for (const scenario of ['runtime-refused', 'runtime-dns', 'runtime-503']) {
    for (const host of HOSTS) {
      const r = hook(host, HIGH, scenario);
      assert.equal(r.stop, true, `${scenario} ${host}: ${r.out.slice(0, 300)}`);
      assert.doesNotMatch(r.out, /This action is allowed/, `${scenario} ${host}`);
      if (['claude', 'codex', 'cursor', 'cline'].includes(host)) assert.ok(r.out.includes(HELD_OFFLINE_TEXT), `${scenario} ${host}: ${r.out.slice(0, 300)}`);
    }
  }
});

test('F2: a real outage keeps the outage allow for routine and read-only actions', () => {
  for (const scenario of ['runtime-refused', 'runtime-503']) {
    for (const host of HOSTS) {
      const r = hook(host, ROUTINE, scenario);
      assert.equal(r.stop, false, `${scenario} ${host}: ${r.out.slice(0, 300)}`);
      if (['claude', 'codex', 'cursor', 'windsurf'].includes(host)) assert.ok(r.out.includes(MARROW_OUTAGE_WARNING), `${scenario} ${host}`);
    }
  }
  for (const host of HOSTS) assert.equal(hook(host, 'ls -la', 'runtime-refused').stop, false, `ls -la ${host}`);
});

test('F2: a server allow with a verified permit is honored on all 7 hosts (the fix only changes failures)', () => {
  for (const host of HOSTS) {
    const r = hook(host, HIGH, 'permit-ok');
    assert.equal(r.stop, false, `${host}: ${r.out.slice(0, 300)}`);
    assert.ok(r.calls.includes('/v1/agent/enforcement#verify'), host);
  }
});
