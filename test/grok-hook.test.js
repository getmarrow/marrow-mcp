const assert = require('node:assert/strict');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const {
  GROK_FIXED_DENIAL,
  GROK_LAUNCH_FAILURE,
  GROK_PRE_ACTION_GUARD_COMMAND,
  GROK_PRE_ACTION_HOOK_COMMAND,
  normalizeHookEventPayload,
  resolveNativeHookIdentity,
} = require('../dist/hook-contract.js');
const { classifyTool, grokPreActionHookOutput, runPreActionHookCommand } = require('../dist/hook-pre-action.js');
const { runHookCommand } = require('../dist/hook.js');
const { runSessionHookCommand } = require('../dist/hook-session.js');

async function captureStdout(callback) {
  const original = process.stdout.write;
  let output = '';
  process.stdout.write = (chunk) => { output += String(chunk); return true; };
  try {
    await callback();
    return output;
  } finally {
    process.stdout.write = original;
  }
}

async function withGrokEnvironment(entrypoint, env, callback) {
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

function runGuard(childCommand) {
  const command = GROK_PRE_ACTION_GUARD_COMMAND.replace(GROK_PRE_ACTION_HOOK_COMMAND, childCommand);
  return spawnSync(command, { shell: true, encoding: 'utf8', input: '{"private":"synthetic-private-input"}' });
}

test('Grok entrypoints and camelCase envelopes normalize to bounded native classifications', () => {
  for (const entrypoint of ['grok-context-hook', 'grok-pre-action-hook', 'grok-hook', 'grok-session-hook']) {
    const identity = resolveNativeHookIdentity(entrypoint, {
      cwd: '/tmp',
      home: '/tmp',
      env: { MARROW_API_KEY: 'fixture-key', MARROW_FLEET_AGENT_ID: 'grok-agent' },
    });
    assert.equal(identity.harness, 'grok');
    assert.equal(identity.client_self_reported, true);
    assert.equal(identity.agent_id, 'grok-agent');
  }

  const command = normalizeHookEventPayload({
    hookEventName: 'PreToolUse',
    sessionId: 'grok-session',
    toolUseId: 'grok-tool',
    toolName: 'run_terminal_command',
    toolInput: { command: 'npm publish --otp synthetic-private-value' },
    cwd: '/synthetic/private/cwd',
    workspaceRoot: '/synthetic/private/workspace',
    permissionMode: 'synthetic-private-mode',
  });
  assert.equal(command.tool_name, 'run_terminal_command');
  assert.equal(classifyTool(command).protected, true);
  assert.doesNotMatch(JSON.stringify(command), /synthetic\/private|permissionMode/);

  const ownMcp = normalizeHookEventPayload({
    hookEventName: 'PreToolUse',
    toolName: 'use_tool',
    toolInput: { serverName: 'marrow', toolName: 'marrow_agent_runtime', private: 'synthetic-private-value' },
  });
  const externalMcp = normalizeHookEventPayload({
    hookEventName: 'PreToolUse',
    toolName: 'use_tool',
    toolInput: { serverName: 'github', toolName: 'create_issue', private: 'synthetic-private-value' },
  });
  assert.equal(ownMcp.tool_name, 'mcp__marrow__marrow_agent_runtime');
  assert.equal(classifyTool(ownMcp).protected, false);
  assert.equal(externalMcp.tool_name, 'MCP:github:create_issue');
  assert.equal(classifyTool(externalMcp).protected, true);

  const failure = normalizeHookEventPayload({
    hookEventName: 'PostToolUseFailure',
    sessionId: 'grok-session',
    toolUseId: 'grok-tool',
    toolName: 'run_terminal_command',
    toolInput: { command: 'synthetic-private-command' },
    toolResult: { error: 'synthetic-private-result', output: 'synthetic-private-output' },
    cwd: '/synthetic/private/cwd',
    durationMs: 450000,
  });
  assert.deepEqual(failure, {
    hook_event_name: 'PostToolUseFailure',
    session_id: 'grok-session',
    tool_use_id: 'grok-tool',
    tool_name: 'run_terminal_command',
    tool_input: {},
    success: false,
    duration_ms: 300000,
  });
  assert.deepEqual(normalizeHookEventPayload({
    hookEventName: 'Stop',
    sessionId: 'grok-session',
    prompt: 'synthetic-private-prompt',
    response: 'synthetic-private-response',
    transcriptPath: '/synthetic/private/transcript',
  }), { hook_event_name: 'Stop', session_id: 'grok-session' });
});

test('Grok native pre-action emits only exact fixed allow or private deny JSON', async () => {
  assert.deepEqual(grokPreActionHookOutput({
    protectedRisk: true,
    permit: { verified: true },
    runtime: {
      exact_next_action: 'synthetic-private-service-text',
      risk_gate: { allow: false, decision: 'review_required', reasons: [{ message: 'synthetic-private-reason' }] },
    },
  }), { decision: 'deny', reason: GROK_FIXED_DENIAL });
  assert.deepEqual(grokPreActionHookOutput({
    protectedRisk: true,
    permit: null,
    runtime: null,
    enforcementError: 'synthetic-private-service-error',
  }), { decision: 'deny', reason: GROK_FIXED_DENIAL });
  assert.deepEqual(grokPreActionHookOutput({
    protectedRisk: true,
    permit: { verified: true },
    runtime: { risk_gate: { allow: true, decision: 'allow', reasons: [] } },
  }), { decision: 'allow' });

  await withGrokEnvironment('grok-pre-action-hook', {}, async () => {
    const denied = await captureStdout(() => runPreActionHookCommand({
      hookEventName: 'PreToolUse',
      toolName: 'write',
      toolInput: { path: '/synthetic/private/path', content: 'synthetic-private-value' },
    }));
    assert.equal(denied, JSON.stringify({ decision: 'deny', reason: GROK_FIXED_DENIAL }));
    assert.doesNotMatch(denied, /synthetic-private/);

    const readOnly = await captureStdout(() => runPreActionHookCommand({
      hookEventName: 'PreToolUse',
      toolName: 'read_file',
      toolInput: { path: '/synthetic/private/path' },
    }));
    assert.equal(readOnly, '{"decision":"allow"}');

    const ownMcp = await captureStdout(() => runPreActionHookCommand({
      hookEventName: 'PreToolUse',
      toolName: 'use_tool',
      toolInput: { serverName: 'marrow', toolName: 'marrow_agent_runtime', private: 'synthetic-private-value' },
    }));
    assert.equal(ownMcp, '{"decision":"allow"}');
  });
});

test('Grok installed pre-action guard rejects launcher failure and stdout pollution with exit 2', () => {
  const allow = runGuard('printf "{\\"decision\\":\\"allow\\"}"');
  assert.equal(allow.status, 0);
  assert.equal(allow.stdout, '{"decision":"allow"}');
  assert.equal(allow.stderr, '');

  const polluted = runGuard('printf "{\\"decision\\":\\"allow\\"}\\n"');
  assert.equal(polluted.status, 2);
  assert.equal(polluted.stdout, '');
  assert.equal(polluted.stderr, `${GROK_LAUNCH_FAILURE}\n`);

  const failed = runGuard('/synthetic/missing-grok-adapter');
  assert.equal(failed.status, 2);
  assert.equal(failed.stdout, '');
  assert.equal(failed.stderr, `${GROK_LAUNCH_FAILURE}\n`);
  assert.match(GROK_PRE_ACTION_GUARD_COMMAND, /timeout 5s/);
});

test('Grok post hooks record compact success and failure without changing results or retaining raw values', async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ pathname: new URL(String(url)).pathname, body: init.body ? JSON.parse(String(init.body)) : {} });
    return Response.json({ data: { accepted: true } });
  };
  let output;
  try {
    await withGrokEnvironment('grok-hook', {
      MARROW_API_KEY: 'fixture-grok-key',
      MARROW_BASE_URL: 'https://api.example.test',
      MARROW_FLEET_AGENT_ID: 'grok-agent',
    }, async () => {
      output = await captureStdout(async () => {
        await runHookCommand({ hookEventName: 'PostToolUse', sessionId: 'grok-post', toolUseId: 'one', toolName: 'write', toolInput: { private: 'synthetic-private-input' }, toolResult: { output: 'synthetic-private-output' } });
        await runHookCommand({ hookEventName: 'PostToolUseFailure', sessionId: 'grok-post', toolUseId: 'two', toolName: 'run_terminal_command', toolInput: { command: 'synthetic-private-command' }, toolResult: { error: 'synthetic-private-error' } });
        await runHookCommand({ hookEventName: 'PostToolUse', sessionId: 'grok-post', toolUseId: 'three', toolName: 'use_tool', toolInput: { serverName: 'marrow', toolName: 'marrow_agent_runtime', private: 'synthetic-private-mcp' }, toolResult: { output: 'synthetic-private-output' } });
      });
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(output, '');
  assert.equal(calls.length, 2);
  assert.deepEqual(calls.map((call) => call.body.success), [true, false]);
  assert.deepEqual(calls.map((call) => call.body.harness), ['grok', 'grok']);
  assert.deepEqual(calls.map((call) => call.body.source), ['client_self_reported', 'client_self_reported']);
  assert.equal(calls.some((call) => call.pathname === '/v1/agent/model-usage'), false);
  assert.doesNotMatch(JSON.stringify(calls), /synthetic-private|fixture-grok-key/);
});

test('Grok Stop closes one turn once, emits no feedback, ignores private content, and invents no usage', async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ pathname: new URL(String(url)).pathname, body: init.body ? JSON.parse(String(init.body)) : {} });
    return Response.json({ data: { accepted: true, committed: 1 } });
  };
  let output;
  try {
    await withGrokEnvironment('grok-session-hook', {
      MARROW_API_KEY: 'fixture-grok-key',
      MARROW_BASE_URL: 'https://api.example.test',
      MARROW_FLEET_AGENT_ID: 'grok-agent',
    }, async () => {
      output = await captureStdout(async () => {
        const event = {
          hookEventName: 'Stop',
          sessionId: 'grok-closeout-unique',
          prompt: 'synthetic-private-prompt',
          response: 'synthetic-private-response',
          transcriptPath: '/synthetic/private/transcript',
          usage: { total_tokens: 999 },
        };
        await runSessionHookCommand(event);
        await runSessionHookCommand(event);
      });
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(output, '');
  assert.equal(calls.filter((call) => call.pathname === '/v1/agent/integrations/events').length, 1);
  assert.equal(calls.filter((call) => call.pathname === '/v1/agent/session/end').length, 1);
  assert.equal(calls.some((call) => call.pathname === '/v1/agent/model-usage'), false);
  assert.doesNotMatch(JSON.stringify(calls), /synthetic-private|total_tokens|fixture-grok-key/);
});
