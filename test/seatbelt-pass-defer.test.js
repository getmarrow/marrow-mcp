'use strict';

// Keyless seatbelt "pass" (spec §1.3: Marrow adds no decision, the host's own permission flow runs).
// An action the 3.9.103 keyless hook held (protected, or not read-only on Windsurf, Gemini or Grok)
// never gets an explicit allow that could skip the host's own approval step:
//   Claude Code / Codex `{}`, Cline `{"cancel":false}`, Windsurf exit 0 with no output (neutral);
//   Gemini CLI `{"decision":"allow"}` (the only non-blocking answer its installed guard passes; Gemini
//   applies its own policy and confirmation after BeforeTool); Cursor beforeShellExecution and
//   beforeMCPExecution "ask" (Cursor's own prompt); Cursor preToolUse and Grok: held, as 3.9.103.
// An action 3.9.103 already passed keeps those exact bytes. Real hook CLI, no key, no network.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync, execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const PRELOAD = path.join(__dirname, 'support', 'seatbelt-hook-preload.cjs');
const hook = require(path.join(ROOT, 'dist', 'hook-pre-action.js'));

const HELD = hook.SEATBELT_HELD_TEXT;
const GROK_HELD = { decision: 'deny', reason: 'Marrow blocked this protected action.' };
const CURSOR_ASK = { permission: 'ask', user_message: hook.SEATBELT_CURSOR_ASK_USER_TEXT, agent_message: hook.SEATBELT_CURSOR_ASK_AGENT_TEXT };
const CURSOR_HELD = { permission: 'deny', user_message: HELD, agent_message: HELD };
const HARNESSES = ['claude-code', 'codex', 'cursor', 'cline', 'gemini', 'grok', 'windsurf', 'mcp-client'];

// The installed host guards (@getmarrow/install 0.1.71 lineage, src/installer.js): what each lets
// through to the host. Anything else becomes the guard's launch failure (exit 2, the action blocks).
const GEMINI_GUARD_PASSES = (out) => {
  try {
    const p = JSON.parse(out);
    if (!p || typeof p !== 'object' || Array.isArray(p) || JSON.stringify(p) !== out) return false;
    const keys = Object.keys(p);
    if (p.decision === 'allow') return keys.length === 1;
    if (p.decision !== 'deny' || typeof p.reason !== 'string' || p.reason.length < 1 || p.reason.length > 500) return false;
    return keys.length === 2 ? keys.includes('reason') : false;
  } catch { return false; }
};
const GROK_GUARD_PASSES = (out) => out === '{"decision":"allow"}' || out === JSON.stringify(GROK_HELD);
const CURSOR_GUARD_PASSES = (out) => { try { const p = JSON.parse(out); return Boolean(p) && typeof p === 'object' && !Array.isArray(p); } catch { return false; } };

test('seatbeltPassOutput: an action 3.9.103 passed keeps its exact answer on every host', () => {
  for (const harness of HARNESSES) {
    for (const event of ['PreToolUse', 'beforeShellExecution', 'beforeMCPExecution', 'BeforeTool', undefined]) {
      assert.deepEqual(hook.seatbeltPassOutput(harness, event, false), hook.localControlAllowOutput(harness), `${harness} ${event}`);
    }
  }
});

test('seatbeltPassOutput: an action 3.9.103 held never gets an explicit allow that skips the host approval', () => {
  const held = (harness, event) => hook.seatbeltPassOutput(harness, event, true);
  assert.deepEqual(held('claude-code', 'PreToolUse'), {});
  assert.deepEqual(held('codex', 'PreToolUse'), {});
  assert.deepEqual(held('mcp-client', 'PreToolUse'), {});
  assert.deepEqual(held('cline', 'PreToolUse'), { cancel: false });
  assert.equal(held('windsurf', undefined), null, 'Windsurf: exit 0, no output');
  assert.deepEqual(held('gemini', 'BeforeTool'), { decision: 'allow' });
  assert.deepEqual(held('grok', 'PreToolUse'), GROK_HELD);
  assert.deepEqual(held('cursor', 'beforeShellExecution'), CURSOR_ASK);
  assert.deepEqual(held('cursor', 'beforeMCPExecution'), CURSOR_ASK);
  // Cursor preToolUse has no neutral answer and does not enforce "ask"; any other or missing name is preToolUse.
  for (const event of ['PreToolUse', 'preToolUse', 'beforeshellexecution', 'BeforeShellExecution', 'beforeShellExecution ', 'afterShellExecution', 'beforeReadFile', '', undefined, null, 7, ['beforeShellExecution']]) {
    assert.deepEqual(held('cursor', event), CURSOR_HELD, `cursor ${JSON.stringify(event)}`);
  }
  for (const harness of HARNESSES) {
    const out = held(harness, harness === 'cursor' ? 'beforeShellExecution' : 'PreToolUse');
    if (out === null) continue;
    assert.equal(out.permission === 'allow', false, harness);
    assert.equal(out.hookSpecificOutput?.permissionDecision === 'allow', false, harness);
    if (harness !== 'gemini') assert.equal(out.decision === 'allow', false, harness);
  }
  assert.ok(HELD.startsWith('MARROW SEATBELT held this action: ') && HELD.endsWith('"marrow claim" to get one-tap approvals.') && HELD.length <= 500);
});

test('seatbeltPassOutput: every answer passes the installed host guard unchanged (none turns into a launch failure)', () => {
  for (const held of [true, false]) {
    assert.equal(GEMINI_GUARD_PASSES(JSON.stringify(hook.seatbeltPassOutput('gemini', 'BeforeTool', held))), true, `gemini ${held}`);
    assert.equal(GROK_GUARD_PASSES(JSON.stringify(hook.seatbeltPassOutput('grok', 'PreToolUse', held))), true, `grok ${held}`);
    for (const event of ['beforeShellExecution', 'beforeMCPExecution', 'PreToolUse']) {
      assert.equal(CURSOR_GUARD_PASSES(JSON.stringify(hook.seatbeltPassOutput('cursor', event, held))), true, `cursor ${event} ${held}`);
    }
  }
  // No output would be a launch failure on Gemini and Grok: that is why they do not get "no output".
  assert.equal(GEMINI_GUARD_PASSES(''), false);
  assert.equal(GROK_GUARD_PASSES(''), false);
});

function sandbox() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-pass-defer-')));
  const home = path.join(root, 'home');
  const proj = path.join(home, 'proj');
  fs.mkdirSync(proj, { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  const git = (...args) => execFileSync('git', args, { cwd: proj, env: { PATH: process.env.PATH, HOME: home, GIT_CONFIG_NOSYSTEM: '1' }, stdio: 'ignore' });
  git('init', '-q', '-b', 'feat/x');
  git('remote', 'add', 'origin', 'git@github.com:acme/proj.git');
  git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '--allow-empty', '-m', 'init');
  return { root, home, proj, netspy: path.join(root, 'net.log'), cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}

function cli(sb, harness, event) {
  const entry = `${harness === 'claude-code' ? 'claude' : harness}-pre-action-hook`;
  const r = spawnSync(process.execPath, ['--require', PRELOAD, CLI, entry], {
    cwd: sb.proj, encoding: 'utf8', timeout: 30_000, input: JSON.stringify(event),
    env: { PATH: process.env.PATH, HOME: sb.home, SBT_PASSWD_HOME: sb.home, SBT_NETSPY: sb.netspy, MARROW_HOOK_BACKGROUND_NUDGE: 'false' },
  });
  assert.equal(r.error, undefined);
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, json: r.stdout.trim() ? JSON.parse(r.stdout) : null };
}

function shell(sb, harness, command) {
  const sid = `pd-${crypto.randomBytes(6).toString('hex')}`;
  if (harness === 'cursor') return { hook_event_name: 'beforeShellExecution', conversation_id: sid, generation_id: 'g1', command, cwd: sb.proj };
  if (harness === 'gemini') return { session_id: sid, hook_event_name: 'BeforeTool', tool_name: 'run_shell_command', tool_input: { command }, cwd: sb.proj };
  if (harness === 'grok') return { hookEventName: 'PreToolUse', sessionId: sid, toolUseId: 't', toolName: 'run_terminal_command', toolInput: { command }, cwd: sb.proj };
  if (harness === 'cline') return { hookName: 'PreToolUse', taskId: sid, workspaceRoots: [sb.proj], preToolUse: { toolName: 'execute_command', parameters: { command } } };
  if (harness === 'windsurf') return { agent_action_name: 'pre_run_command', trajectory_id: sid, execution_id: 'e', tool_info: { command_line: command, cwd: sb.proj } };
  return { hook_event_name: 'PreToolUse', session_id: sid, tool_use_id: 't1', tool_name: 'Bash', tool_input: { command }, cwd: sb.proj };
}

const network = (sb) => (fs.existsSync(sb.netspy) ? fs.readFileSync(sb.netspy, 'utf8') : '');

test('keyless hook CLI: a protected action the seatbelt does not stop gets each host\'s neutral answer, Cursor "ask", or a hold', () => {
  const sb = sandbox();
  try {
    for (const command of ['git push origin main', 'docker push acme/app:1', 'git commit -m "deploy to prod"', 'wrangler deploy --env staging']) {
      for (const harness of ['claude-code', 'codex']) assert.deepEqual(cli(sb, harness, shell(sb, harness, command)).json, {}, `${harness} ${command}`);
      assert.deepEqual(cli(sb, 'cline', shell(sb, 'cline', command)).json, { cancel: false }, command);
      const ws = cli(sb, 'windsurf', shell(sb, 'windsurf', command));
      assert.equal(ws.status, 0, `windsurf ${command}: ${ws.stderr}`);
      assert.equal(ws.stdout + ws.stderr, '');
      const gemini = cli(sb, 'gemini', shell(sb, 'gemini', command));
      assert.equal(gemini.stdout.trim(), '{"decision":"allow"}', command);
      assert.equal(GEMINI_GUARD_PASSES(gemini.stdout.trim()), true);
      const grok = cli(sb, 'grok', shell(sb, 'grok', command));
      assert.deepEqual(grok.json, GROK_HELD, command);
      assert.equal(GROK_GUARD_PASSES(grok.stdout), true);
      assert.deepEqual(cli(sb, 'cursor', shell(sb, 'cursor', command)).json, CURSOR_ASK, `cursor ${command}`);
      for (const harness of HARNESSES.filter((h) => h !== 'mcp-client')) assert.equal(cli(sb, harness, shell(sb, harness, command)).status, 0);
    }
    // Cursor preToolUse (a Shell tool from an older install, an MCP tool): held; beforeMCPExecution: "ask".
    const base = { conversation_id: 'pd-c', generation_id: 'g1', cwd: sb.proj };
    assert.deepEqual(cli(sb, 'cursor', { ...base, hook_event_name: 'preToolUse', tool_use_id: 't', tool_name: 'Shell', tool_input: { command: 'git push origin main' } }).json, CURSOR_HELD);
    assert.deepEqual(cli(sb, 'cursor', { ...base, hook_event_name: 'preToolUse', tool_use_id: 't', tool_name: 'MCP:deploy_service', tool_input: { env: 'staging' } }).json, CURSOR_HELD);
    assert.deepEqual(cli(sb, 'cursor', { ...base, hook_event_name: 'beforeMCPExecution', server: 'acme', tool_name: 'deploy_service', tool_input: '{"env":"staging"}', mcp_server_name: 'acme' }).json, CURSOR_ASK);
    assert.equal(network(sb), '', 'no socket, no request');
  } finally { sb.cleanup(); }
});

test('keyless hook CLI: an action 3.9.103 already passed keeps the 3.9.103 answer; a seatbelt stop is still a stop', () => {
  const sb = sandbox();
  try {
    // Unprotected, not read-only: 3.9.103 passed it on Claude Code, Codex, Cursor and Cline, held it on Gemini, Grok, Windsurf.
    const touch = 'touch notes.txt';
    assert.deepEqual(cli(sb, 'claude-code', shell(sb, 'claude-code', touch)).json, {});
    assert.deepEqual(cli(sb, 'codex', shell(sb, 'codex', touch)).json, {});
    assert.deepEqual(cli(sb, 'cursor', shell(sb, 'cursor', touch)).json, { permission: 'allow' });
    assert.deepEqual(cli(sb, 'cline', shell(sb, 'cline', touch)).json, { cancel: false });
    assert.equal(cli(sb, 'gemini', shell(sb, 'gemini', touch)).stdout.trim(), '{"decision":"allow"}');
    assert.deepEqual(cli(sb, 'grok', shell(sb, 'grok', touch)).json, GROK_HELD);
    const ws = cli(sb, 'windsurf', shell(sb, 'windsurf', touch));
    assert.equal(ws.status, 0);
    assert.equal(ws.stdout, '');
    // Read-only on Claude Code and Gemini: the 3.9.103 read-only pass.
    assert.deepEqual(cli(sb, 'claude-code', shell(sb, 'claude-code', 'ls -la')).json, {});
    assert.equal(cli(sb, 'gemini', shell(sb, 'gemini', 'git status')).stdout.trim(), '{"decision":"allow"}');
    // A seatbelt stop keeps the deny shape on every host (it is not routed through the pass).
    for (const harness of HARNESSES.filter((h) => h !== 'mcp-client')) {
      const out = cli(sb, harness, shell(sb, harness, 'npm publish'));
      if (harness === 'windsurf') { assert.equal(out.status, 2); continue; }
      const verdict = out.json.permission || out.json.hookSpecificOutput?.permissionDecision || out.json.decision || (out.json.cancel === true ? 'deny' : null);
      assert.equal(verdict, 'deny', `${harness}: ${out.stdout}`);
    }
    assert.equal(network(sb), '');
  } finally { sb.cleanup(); }
});

test('keyless hook CLI: Windsurf and Cline events carry no top-level cwd, so a recursive delete stops there (kept, fail-closed)', () => {
  const sb = sandbox();
  try {
    for (const command of ['rm -rf build', 'rm -r dist', 'find . -name x -delete']) {
      const cline = cli(sb, 'cline', shell(sb, 'cline', command));
      assert.equal(cline.json.cancel, true, `cline ${command}: ${cline.stdout}`);
      assert.match(cline.json.errorMessage, /^MARROW SEATBELT stopped this action: /);
      const ws = cli(sb, 'windsurf', shell(sb, 'windsurf', command));
      assert.equal(ws.status, 2, `windsurf ${command}`);
      assert.match(ws.stderr, /^MARROW SEATBELT stopped this action: /);
    }
    // The same delete with a known workspace (Claude Code's top-level cwd) is ordinary work.
    assert.deepEqual(cli(sb, 'claude-code', shell(sb, 'claude-code', 'rm -rf build')).json, {});
    assert.equal(network(sb), '');
  } finally { sb.cleanup(); }
});
