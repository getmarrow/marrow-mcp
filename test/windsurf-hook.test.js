const assert = require('node:assert/strict');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const { normalizeHookEventPayload, resolveNativeHookIdentity } = require('../dist/hook-contract.js');
const { classifyTool, windsurfPreActionDecision } = require('../dist/hook-pre-action.js');
const { runHookCommand } = require('../dist/hook.js');
const { runSessionHookCommand } = require('../dist/hook-session.js');

const FIXED_DENIAL = 'Marrow blocked this action because required governance approval or proof is unavailable.\n';

async function withWindsurfEnvironment(entrypoint, env, callback) {
  const keys = [
    'MARROW_API_KEY', 'MARROW_KEY', 'MARROW_BASE_URL', 'MARROW_AGENT_ID',
    'MARROW_FLEET_AGENT_ID', 'MARROW_SESSION_ID', 'MARROW_PASSIVE_TOKEN_USAGE',
  ];
  const previous = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  const originalArg = process.argv[2];
  process.argv[2] = entrypoint;
  for (const key of keys) delete process.env[key];
  Object.assign(process.env, env || {});
  try {
    await callback();
  } finally {
    process.argv[2] = originalArg;
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

function runPreChild(input, env = {}) {
  const home = mkdtempSync(join(tmpdir(), 'marrow-windsurf-hook-'));
  try {
    return spawnSync(process.execPath, ['dist/cli.js', 'windsurf-pre-action-hook'], {
      cwd: process.cwd(),
      encoding: 'utf8',
      input: JSON.stringify(input),
      env: {
        PATH: process.env.PATH,
        HOME: home,
        MARROW_BASE_URL: 'https://api.example.test',
        ...env,
      },
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

test('Windsurf entrypoints and envelopes normalize to bounded correlation and classifications only', () => {
  for (const entrypoint of ['windsurf-pre-action-hook', 'windsurf-hook', 'windsurf-session-hook']) {
    const identity = resolveNativeHookIdentity(entrypoint, {
      cwd: '/tmp',
      home: '/tmp',
      env: { MARROW_API_KEY: 'fixture-key', MARROW_FLEET_AGENT_ID: 'windsurf-agent' },
    });
    assert.equal(identity.harness, 'windsurf');
    assert.equal(identity.client_self_reported, true);
    assert.equal(identity.agent_id, 'windsurf-agent');
  }

  const command = normalizeHookEventPayload({
    agent_action_name: 'pre_run_command',
    trajectory_id: 'trajectory-1',
    execution_id: 'execution-1',
    tool_info: { command_line: 'npm publish --otp synthetic-private-value' },
  });
  assert.deepEqual(command, {
    hook_event_name: 'pre_run_command',
    session_id: 'trajectory-1',
    tool_use_id: 'execution-1',
    tool_name: 'Bash',
    tool_input: { command: 'npm publish --otp synthetic-private-value' },
  });
  assert.equal(classifyTool(command).protected, true);

  const write = normalizeHookEventPayload({
    agent_action_name: 'post_write_code',
    trajectory_id: 'trajectory-2',
    execution_id: 'execution-2',
    tool_info: { file_path: '/private/path', edits: [{ content: 'private edit' }] },
  });
  assert.deepEqual(write, {
    hook_event_name: 'post_write_code',
    session_id: 'trajectory-2',
    tool_use_id: 'execution-2',
    tool_name: 'Write',
    tool_input: {},
    success: true,
  });

  const externalMcp = normalizeHookEventPayload({
    agent_action_name: 'pre_mcp_tool_use',
    trajectory_id: 'trajectory-3',
    execution_id: 'execution-3',
    tool_info: {
      mcp_server_name: 'github',
      mcp_tool_name: 'create_issue',
      mcp_tool_arguments: { private: 'synthetic-private-arguments' },
    },
  });
  assert.equal(classifyTool(externalMcp).protected, true);
  assert.equal(JSON.stringify(externalMcp).includes('synthetic-private-arguments'), false);

  const marrowMcp = normalizeHookEventPayload({
    agent_action_name: 'pre_mcp_tool_use',
    tool_info: { mcp_server_name: 'marrow', mcp_tool_name: 'marrow_agent_runtime' },
  });
  assert.equal(marrowMcp.tool_name, 'mcp__marrow__marrow_agent_runtime');

  const closeout = normalizeHookEventPayload({
    agent_action_name: 'post_cascade_response',
    trajectory_id: 'trajectory-4',
    execution_id: 'execution-4',
    model_name: 'synthetic-private-model',
    prompt: 'synthetic-private-prompt',
    tool_info: { response: 'synthetic-private-response', transcript: 'synthetic-private-transcript' },
  });
  assert.deepEqual(closeout, {
    hook_event_name: 'post_cascade_response',
    session_id: 'trajectory-4',
    tool_use_id: 'execution-4',
  });
});

test('Windsurf native pre decision has exact private fail-closed output', () => {
  assert.deepEqual(windsurfPreActionDecision({
    protectedRisk: true,
    permit: { verified: true },
    runtime: {
      exact_next_action: 'synthetic-private-service-text',
      risk_gate: { allow: false, decision: 'review_required', reasons: [] },
    },
  }), { exitCode: 2, stderr: FIXED_DENIAL });
  assert.deepEqual(windsurfPreActionDecision({
    protectedRisk: true,
    permit: null,
    runtime: null,
    enforcementError: 'synthetic-private-service-secret',
  }), { exitCode: 2, stderr: FIXED_DENIAL });
  assert.deepEqual(windsurfPreActionDecision({
    protectedRisk: true,
    permit: { verified: true },
    runtime: { risk_gate: { allow: true, decision: 'allow', reasons: [] } },
  }), { exitCode: 0, stderr: '' });
});

test('Windsurf child pre hook exits exactly 0 for safe actions and 2 for unavailable or unclassifiable actions', () => {
  const privateCommand = 'npm publish --otp synthetic-private-command';
  const missingKey = runPreChild({
    agent_action_name: 'pre_run_command',
    trajectory_id: 'trajectory-child',
    execution_id: 'execution-child',
    tool_info: { command_line: privateCommand },
  });
  assert.equal(missingKey.status, 2);
  assert.equal(missingKey.stdout, '');
  assert.equal(missingKey.stderr, FIXED_DENIAL);
  assert.doesNotMatch(missingKey.stderr, /npm publish|synthetic-private-command/);

  const malformed = runPreChild({
    agent_action_name: 'unsupported_private_action',
    tool_info: { command_line: 'synthetic-private-malformed' },
  });
  assert.equal(malformed.status, 2);
  assert.equal(malformed.stdout, '');
  assert.equal(malformed.stderr, FIXED_DENIAL);
  assert.doesNotMatch(malformed.stderr, /synthetic-private-malformed/);

  const readOnly = runPreChild({
    agent_action_name: 'pre_run_command',
    tool_info: { command_line: 'git status' },
  });
  assert.equal(readOnly.status, 0);
  assert.equal(readOnly.stdout, '');
  assert.equal(readOnly.stderr, '');

  const ownMcp = runPreChild({
    agent_action_name: 'pre_mcp_tool_use',
    tool_info: { mcp_server_name: 'marrow', mcp_tool_name: 'marrow_agent_runtime' },
  });
  assert.equal(ownMcp.status, 0);
  assert.equal(ownMcp.stdout, '');
  assert.equal(ownMcp.stderr, '');
});

test('Windsurf post success hooks record compact evidence without raw tool data', async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ pathname: new URL(String(url)).pathname, body: init.body ? JSON.parse(String(init.body)) : {} });
    return Response.json({ data: { accepted: true } });
  };
  try {
    await withWindsurfEnvironment('windsurf-hook', {
      MARROW_API_KEY: 'fixture-windsurf-key',
      MARROW_BASE_URL: 'https://api.example.test',
      MARROW_FLEET_AGENT_ID: 'windsurf-agent',
      MARROW_PASSIVE_TOKEN_USAGE: 'false',
    }, async () => {
      await runHookCommand({ agent_action_name: 'post_run_command', trajectory_id: 'trajectory-post', execution_id: 'command-post', tool_info: { command_line: 'synthetic-private-command', output: 'synthetic-private-output' } });
      await runHookCommand({ agent_action_name: 'post_write_code', trajectory_id: 'trajectory-post', execution_id: 'write-post', tool_info: { file_path: '/synthetic/private/path', edits: [{ text: 'synthetic-private-edit' }] } });
      await runHookCommand({ agent_action_name: 'post_mcp_tool_use', trajectory_id: 'trajectory-post', execution_id: 'mcp-post', tool_info: { mcp_server_name: 'github', mcp_tool_name: 'create_issue', mcp_tool_arguments: { private: 'synthetic-private-args' }, mcp_result: 'synthetic-private-result' } });
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(calls.length, 3);
  assert.deepEqual(calls.map((call) => call.pathname), Array(3).fill('/v1/agent/integrations/events'));
  assert.deepEqual(calls.map((call) => call.body.harness), Array(3).fill('windsurf'));
  assert.deepEqual(calls.map((call) => call.body.source), Array(3).fill('client_self_reported'));
  assert.deepEqual(calls.map((call) => call.body.success), [true, true, true]);
  assert.doesNotMatch(JSON.stringify(calls), /synthetic-private-command|synthetic-private-output|synthetic\/private\/path|synthetic-private-edit|synthetic-private-args|synthetic-private-result|fixture-windsurf-key/);
});

test('Windsurf cascade response closes once with correlation only and no response or invented usage', async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ pathname: new URL(String(url)).pathname, body: init.body ? JSON.parse(String(init.body)) : {} });
    return Response.json({ data: { accepted: true, committed: 1 } });
  };
  try {
    await withWindsurfEnvironment('windsurf-session-hook', {
      MARROW_API_KEY: 'fixture-windsurf-key',
      MARROW_BASE_URL: 'https://api.example.test',
      MARROW_FLEET_AGENT_ID: 'windsurf-agent',
    }, async () => {
      await runSessionHookCommand({
        agent_action_name: 'post_cascade_response',
        trajectory_id: 'trajectory-closeout',
        execution_id: 'execution-closeout',
        model_name: 'synthetic-private-model',
        prompt: 'synthetic-private-prompt',
        tool_info: { response: 'synthetic-private-response', token_usage: { total_tokens: 999 } },
      });
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(calls.filter((call) => call.pathname === '/v1/agent/integrations/events').length, 1);
  assert.equal(calls.filter((call) => call.pathname === '/v1/agent/session/end').length, 1);
  assert.equal(calls.some((call) => call.pathname === '/v1/agent/model-usage'), false);
  assert.doesNotMatch(JSON.stringify(calls), /synthetic-private-response|synthetic-private-model|synthetic-private-prompt|total_tokens|fixture-windsurf-key/);
});
