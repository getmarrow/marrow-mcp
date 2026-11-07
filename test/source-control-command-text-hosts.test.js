'use strict';

// The command text of a plain push or pull request leaves the machine only for a raw Claude Code Bash call: the
// hook runs as the Claude Code pre-action entrypoint and the host's own event names the Bash tool before any adapter
// rename. Every other host (Windsurf, Gemini, Codex, a Grok-style event, Cursor, Cline), an unknown entrypoint or a
// renamed call sends the 3.9.111 body: the keyed hash and no text. Each row runs the built hook in a child process
// with a fake home and the fetch mock; the runtime body the mock captured is the proof.

const assert = require('node:assert/strict');
const test = require('node:test');
const { createHash, randomBytes } = require('node:crypto');
const { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } = require('node:fs');
const { spawnSync } = require('node:child_process');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const { normalizedHookAction } = require('../dist/normalized-action.js');
const { writeOfficialHostConfigs } = require('./support/official-host-config.cjs');
const { projectCwd } = require('./support/hermetic-project.cjs');

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const MOCK = join(__dirname, 'support', 'host-approval-fetch-mock.cjs');
const REVIEW_CLASS = 'classified Bash action: review on github';
const PUSH = 'git push origin feat/x';
const PR = "gh pr create --base feat/a --head feat/b --title 'Fix the thing'";
const P = (text) => createHash('sha256').update(`marrow-normalized-action-v3\nshell\n${text}`).digest('hex');

function heldRuntime() {
  const receipt = 'gate-held';
  return {
    ok: true,
    action: REVIEW_CLASS,
    decision_id: 'decision-review',
    runtime_authorization: { id: receipt, kind: 'durable_gate_receipt', durable: true, decision_state: 'created', decision_creation_required: false, decision_id: 'decision-review' },
    gate_receipt: { id: receipt, decision: 'review_required', required: true, owner_approval_required: true, expires_at: '2030-01-01T00:30:00.000Z' },
    proof_pack: { required: false, fields: [], complete: true },
    risk_gate: { allow: true, decision: 'review_required', enforced: true, gate_required: true, gate_receipt_id: receipt, risk_level: 'high', reasons: [{ message: 'Pushes need approval.' }] },
    gate_receipt_id: receipt,
    exact_next_action: 'Obtain explicit owner approval before this action runs.',
  };
}

// One fake home per run, so a hold from one run never answers the next.
function runHook(entrypoint, payload, env = {}) {
  return runHooks([[entrypoint, payload]], env);
}

// Several hook calls in one fake home (a pre-action call, then the result hook).
function runHooks(steps, env = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-cmdtext-hosts-'));
  try {
    const home = join(dir, 'home');
    const mockDir = join(dir, 'mock');
    mkdirSync(home, { mode: 0o700 });
    writeOfficialHostConfigs(home);
    mkdirSync(mockDir);
    writeFileSync(join(mockDir, 'config.json'), JSON.stringify({ runtime: heldRuntime() }));
    const stdio = [];
    for (const [entrypoint, payload] of steps) {
    const result = spawnSync(process.execPath, [CLI, entrypoint], {
      input: JSON.stringify(payload),
      cwd: projectCwd(),
      env: {
        PATH: process.env.PATH, HOME: home, MARROW_API_KEY: `mrw_test_${randomBytes(16).toString('hex')}`,
        MARROW_BASE_URL: 'https://api.example.test', MARROW_AGENT_ID: 'agent-one', MARROW_HOOK_BACKGROUND_NUDGE: 'false',
        MARROW_PASSIVE_TOKEN_USAGE: 'false', MARROW_TEST_MOCK_DIR: mockDir, NODE_OPTIONS: `--require=${MOCK}`, ...env,
      },
      encoding: 'utf8',
      timeout: 30_000,
    });
    assert.equal(result.error, undefined);
    stdio.push(result.stdout, result.stderr);
    }
    const log = join(mockDir, 'requests.jsonl');
    const requests = existsSync(log) ? readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line)) : [];
    const bodies = requests.filter((r) => r.path === '/v1/agent/runtime' && /^classified \S+ action: /.test(r.body?.action || '')).map((r) => r.body);
    // Every byte the hook left under the fake home (hold state, spool, receipts, logs).
    const files = [];
    const walk = (path) => {
      for (const name of readdirSync(path)) {
        const child = join(path, name);
        if (statSync(child).isDirectory()) walk(child); else files.push(readFileSync(child, 'latin1'));
      }
    };
    walk(home);
    return { bodies, requests, stdio: stdio.join('\n'), homeBytes: files.join('\n') };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// Hash only, as 3.9.111: the runtime was called, no `command` key, not the plain hash, and the whole normalized
// action (but for the device-keyed hash) equals the opt-out body, which is the 3.9.111 body byte for byte.
function assertHashOnly(entrypoint, payload, text, label) {
  const sent = runHook(entrypoint, payload);
  const off = runHook(entrypoint, payload, { MARROW_HOOK_COMMAND_TEXT: 'off' });
  assert.ok(sent.bodies.length >= 1, `${label}: the runtime was called`);
  assert.equal(off.bodies.length, sent.bodies.length, `${label}: same calls as the opt-out`);
  for (const [i, body] of sent.bodies.entries()) {
    const input = body.normalized_action.tool_input;
    assert.deepEqual(Object.keys(input), ['command_sha256'], `${label}: hash only, no command key`);
    assert.match(input.command_sha256, /^[0-9a-f]{64}$/, label);
    assert.notEqual(input.command_sha256, P(text), `${label}: the keyed hash, not the plain one`);
    const strip = (b) => JSON.stringify({ ...b, normalized_action: { ...b.normalized_action, tool_input: Object.keys(b.normalized_action.tool_input) } });
    assert.equal(strip(body), strip(off.bodies[i]), `${label}: the opt-out (3.9.111) body`);
  }
  assert.equal(JSON.stringify(sent.requests).includes(text), false, `${label}: no text in any request`);
  assert.equal(JSON.stringify(sent.requests).includes(P(text)), false, `${label}: no plain hash in any request`);
  return sent;
}

function assertTextSent(entrypoint, payload, text, label) {
  const sent = runHook(entrypoint, payload);
  assert.equal(sent.bodies.length, 1, `${label}: the runtime was called once`);
  assert.equal(sent.bodies[0].action, REVIEW_CLASS, label);
  assert.deepEqual(sent.bodies[0].normalized_action.tool_input, { command_sha256: P(text), command: text }, `${label}: text and plain hash`);
}

const SESSION = '3b1f0c2e-0000-4000-8000-00000000000b';
const claudeEvent = (command, extra = {}) => ({ session_id: SESSION, cwd: '/home/operator/project', permission_mode: 'default', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command, description: 'x' }, tool_use_id: 'toolu_01HOSTS0000000000000001', ...extra });
const windsurfEvent = (command) => ({ agent_action_name: 'pre_run_command', trajectory_id: 'traj-hosts-1', execution_id: 'exec-hosts-1', tool_info: { command_line: command, cwd: '/home/operator/project' } });
const geminiEvent = (command) => ({ session_id: SESSION, cwd: '/home/operator/project', hook_event_name: 'BeforeTool', tool_name: 'run_shell_command', tool_input: { command } });
const codexEvent = (command) => ({ session_id: SESSION, cwd: '/home/operator/project', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, tool_use_id: 'call_hosts_1', model: 'm', permission_mode: 'default' });
const grokEvent = (command) => ({ hookEventName: 'PreToolUse', sessionId: SESSION, toolUseId: 'grok-hosts-1', cwd: '/home/operator/project', toolName: 'Bash', toolInput: { command } });

// ------------------------------------------------------------------ F1 rows (ruling): every host but Claude Code is hash only

test('F1-W Windsurf pre_run_command: hash only, as 3.9.111', () => {
  assertHashOnly('windsurf-pre-action-hook', windsurfEvent(PUSH), PUSH, 'windsurf');
});

test('F1-G Gemini run_shell_command: hash only, as 3.9.111', () => {
  assertHashOnly('gemini-pre-action-hook', geminiEvent(PUSH), PUSH, 'gemini');
});

test('F1-C Codex PreToolUse Bash with a string command: hash only, as 3.9.111', () => {
  assertHashOnly('codex-pre-action-hook', codexEvent(PUSH), PUSH, 'codex');
});

test('F1-K Grok-style camelCase PreToolUse Bash: hash only, as 3.9.111', () => {
  assertHashOnly('grok-pre-action-hook', grokEvent(PUSH), PUSH, 'grok');
});

test('F1-U unknown host: the generic pre-action entrypoints with tool_name Bash are hash only', () => {
  for (const entrypoint of ['pre-action-hook', '--pre-action-hook']) {
    assertHashOnly(entrypoint, claudeEvent(PUSH), PUSH, `generic ${entrypoint}`);
  }
});

test('F1-X a Claude Code-shaped payload at every non-Claude pre-action entrypoint is hash only', () => {
  for (const entrypoint of ['windsurf-pre-action-hook', 'gemini-pre-action-hook', 'codex-pre-action-hook', 'grok-pre-action-hook', 'cursor-pre-action-hook', 'cline-pre-action-hook']) {
    assertHashOnly(entrypoint, claudeEvent(PUSH), PUSH, `claude payload at ${entrypoint}`);
  }
});

test('F1-CC genuine Claude Code Bash push and pull request through the Claude Code entrypoint: text and plain hash', () => {
  assertTextSent('claude-pre-action-hook', claudeEvent(PUSH), PUSH, 'claude push');
  // The hook classes a pull request `process on workspace`, not a review on GitHub (S2), so, as on the audited head,
  // it keeps the plain hash and sends no text.
  const pr = runHook('claude-pre-action-hook', claudeEvent('gh pr create --base feat/a --head feat/b --title "Fix the thing"'));
  assert.equal(pr.bodies.length, 1, 'claude pr: the runtime was called once');
  assert.deepEqual(pr.bodies[0].normalized_action.tool_input, { command_sha256: P(PR) }, 'claude pr: plain hash, no text');
});

// ------------------------------------------------------------------ adversarial rows on the raw-event gate

test('ADV raw tool name variants at the Claude Code entrypoint: hash only (byte-equal Bash only)', () => {
  for (const name of ['bash', 'Bash ', ' Bash', 'Bash\u0000', 'Ｂash', 'Bаsh']) {
    const sent = runHook('claude-pre-action-hook', claudeEvent(PUSH, { tool_name: name }));
    for (const body of sent.bodies) assert.equal('command' in body.normalized_action.tool_input, false, JSON.stringify(name));
    assert.equal(JSON.stringify(sent.requests).includes(PUSH), false, JSON.stringify(name));
  }
});

test('ADV host-shaped events at the Claude Code entrypoint are hash only (the adapter renamed them)', () => {
  assertHashOnly('claude-pre-action-hook', windsurfEvent(PUSH), PUSH, 'windsurf event at claude');
  assertHashOnly('claude-pre-action-hook', geminiEvent(PUSH), PUSH, 'gemini event at claude');
  assertHashOnly('claude-pre-action-hook', grokEvent(PUSH), PUSH, 'grok event at claude');
  // A Claude Code payload that also carries a Grok event name: the Grok adapter rebuilds the input, so hash only.
  assertHashOnly('claude-pre-action-hook', claudeEvent(PUSH, { hookEventName: 'PreToolUse', toolName: 'Bash', toolInput: { command: PUSH } }), PUSH, 'claude + grok fields');
  // A Claude Code payload that also carries a Windsurf action name: the Windsurf adapter rebuilds the input.
  assertHashOnly('claude-pre-action-hook', { ...claudeEvent(PUSH), agent_action_name: 'pre_run_command', tool_info: { command_line: PUSH } }, PUSH, 'claude + windsurf fields');
});

test('ADV fields or env naming a host never pick it: forged harness, agent, host, client fields and env', () => {
  const forged = { harness: 'claude-code', host: 'claude-code', agent: 'claude-code', source: 'claude-code', client_name: 'claude-code', watch: { harness: 'claude-code' } };
  assertHashOnly('codex-pre-action-hook', codexEvent(PUSH), PUSH, 'codex plain');
  assertHashOnly('codex-pre-action-hook', { ...codexEvent(PUSH), ...forged }, PUSH, 'codex claiming claude');
  for (const env of [{ MARROW_HARNESS: 'claude-code' }, { MARROW_CLIENT: 'claude-code' }, { CLAUDE_CODE_CHILD_SESSION: '1' }, { CLAUDECODE: '1' }]) {
    const sent = runHook('windsurf-pre-action-hook', windsurfEvent(PUSH), env);
    for (const body of sent.bodies) assert.equal('command' in body.normalized_action.tool_input, false, JSON.stringify(env));
    assert.equal(JSON.stringify(sent.requests).includes(PUSH), false, JSON.stringify(env));
  }
  // A genuine Claude Code event with fields naming another host keeps its answer (the fields pick nothing).
  assertTextSent('claude-pre-action-hook', claudeEvent(PUSH, { harness: 'windsurf', host: 'gemini', agent: 'codex', client_name: 'grok' }), PUSH, 'claude naming others');
});

test('ADV the opt-out keeps the Claude Code call hash only; a description alone sends no text at another host', () => {
  const off = runHook('claude-pre-action-hook', claudeEvent(PUSH), { MARROW_HOOK_COMMAND_TEXT: 'off' });
  assert.deepEqual(Object.keys(off.bodies[0].normalized_action.tool_input), ['command_sha256']);
  assert.notEqual(off.bodies[0].normalized_action.tool_input.command_sha256, P(PUSH));
  const described = runHook('codex-pre-action-hook', { ...codexEvent('   '), tool_input: { command: '   ', description: PUSH } });
  for (const body of described.bodies) assert.equal('command' in body.normalized_action.tool_input, false);
});

test('ADV unit: the caller fact false gives the opt-out (3.9.111) action for every in-scope command', () => {
  const salt = randomBytes(32);
  const prior = process.env.MARROW_HOOK_COMMAND_TEXT;
  for (const text of [PUSH, PR, 'git push -u origin feat/x']) {
    const event = { tool_name: 'Bash', tool_input: { command: text } };
    const gated = normalizedHookAction(event, { salt, sendCommandText: true, claudeCodeBash: false });
    process.env.MARROW_HOOK_COMMAND_TEXT = 'off';
    try {
      assert.deepEqual(gated, normalizedHookAction(event, { salt }), text);
    } finally {
      if (prior === undefined) delete process.env.MARROW_HOOK_COMMAND_TEXT; else process.env.MARROW_HOOK_COMMAND_TEXT = prior;
    }
    assert.deepEqual(normalizedHookAction(event, { salt, sendCommandText: true, claudeCodeBash: true }).tool_input, { command_sha256: P(text), command: text });
  }
});

// ------------------------------------------------------------------ the other call sites (lifecycle, identity, spool)

function actionsIn(value) {
  if (!value || typeof value !== 'object') return [];
  const own = value.normalized_action ? [value.normalized_action] : [];
  return [...own, ...Object.values(value).flatMap(actionsIn)];
}

test('another host\'s result hook (lifecycle, identity, spool) keeps the 3.9.111 keyed hash: no plain hash, no text', () => {
  const rows = [
    ['windsurf-hook', { agent_action_name: 'post_run_command', trajectory_id: 'traj-hosts-2', execution_id: 'exec-hosts-2', tool_info: { command_line: PUSH, cwd: '/home/operator/project' } }],
    ['codex-hook', { session_id: SESSION, cwd: '/home/operator/project', hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_input: { command: PUSH }, tool_response: 'ok', tool_use_id: 'call_hosts_2' }],
    ['gemini-hook', { session_id: SESSION, cwd: '/home/operator/project', hook_event_name: 'AfterTool', tool_name: 'run_shell_command', tool_input: { command: PUSH }, tool_response: { llmContent: 'ok' } }],
    ['grok-hook', { hookEventName: 'PostToolUse', sessionId: SESSION, toolUseId: 'grok-hosts-2', cwd: '/home/operator/project', toolName: 'Bash', toolInput: { command: PUSH }, toolResponse: 'ok' }],
  ];
  const pre = { 'windsurf-hook': ['windsurf-pre-action-hook', windsurfEvent(PUSH)], 'codex-hook': ['codex-pre-action-hook', codexEvent(PUSH)], 'gemini-hook': ['gemini-pre-action-hook', geminiEvent(PUSH)], 'grok-hook': ['grok-pre-action-hook', grokEvent(PUSH)] };
  for (const [entrypoint, payload] of rows) {
    const ran = runHooks([pre[entrypoint], [entrypoint, payload]]);
    assert.ok(actionsIn(ran.requests).length >= 1, `${entrypoint}: a normalized action was recorded`);
    const all = `${JSON.stringify(ran.requests)}\n${ran.homeBytes}\n${ran.stdio}`;
    assert.equal(all.includes(PUSH), false, `${entrypoint}: no text`);
    assert.equal(all.includes(P(PUSH)), false, `${entrypoint}: no plain hash in any request or home file`);
    for (const action of actionsIn(ran.requests)) assert.equal('command' in (action.tool_input || {}), false, entrypoint);
  }
  // The Claude Code result hook keeps the audited plain hash: source-control-command-text.test.js (CONS lifecycle).
});
