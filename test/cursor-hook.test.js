const assert = require('node:assert/strict');
const test = require('node:test');

const {
  normalizeHookEventPayload,
  resolveNativeHookIdentity,
} = require('../dist/hook-contract.js');
const {
  cursorPreActionHookOutput,
  runPreActionHookCommand,
} = require('../dist/hook-pre-action.js');
const { deriveAction, deriveToolOutcome, runHookCommand } = require('../dist/hook.js');
const { isOfficialMarrowMcpTool } = require('../dist/hook-tool-policy.js');
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

async function withCursorEnvironment(values, callback) {
  const keys = [
    'MARROW_API_KEY', 'MARROW_KEY', 'MARROW_BASE_URL', 'MARROW_AGENT_ID',
    'MARROW_FLEET_AGENT_ID', 'MARROW_SESSION_ID', 'MARROW_PASSIVE_TOKEN_USAGE',
  ];
  const previous = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  const originalArg = process.argv[2];
  process.argv[2] = values.entrypoint || 'cursor-hook';
  for (const key of keys) delete process.env[key];
  Object.assign(process.env, values.env || {});
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

test('Cursor entrypoints and lower-camel events have bounded client-self-reported identity', () => {
  for (const entrypoint of ['cursor-pre-action-hook', 'cursor-hook', 'cursor-session-hook']) {
    const identity = resolveNativeHookIdentity(entrypoint, {
      cwd: '/tmp',
      home: '/tmp',
      env: { MARROW_API_KEY: 'fixture-key', MARROW_FLEET_AGENT_ID: 'cursor-agent' },
    });
    assert.equal(identity.harness, 'cursor');
    assert.equal(identity.client_self_reported, true);
    assert.equal(identity.agent_id, 'cursor-agent');
  }
  const normalized = normalizeHookEventPayload({
    eventName: 'postToolUseFailure',
    conversationId: 'conversation-1',
    generationId: 'generation-1',
    toolUseId: 'tool-1',
    transcriptPath: '/private/transcript',
  });
  assert.equal(normalized.hook_event_name, 'PostToolUseFailure');
  assert.equal(normalized.conversation_id, 'conversation-1');
  assert.equal(normalized.generation_id, 'generation-1');
  assert.equal(normalized.tool_use_id, 'tool-1');
  assert.equal(normalizeHookEventPayload({ conversationId: '../not-safe' }).conversation_id, undefined);
});

test('Cursor native pre-action denies review and unavailable proof, never asks', () => {
  const review = cursorPreActionHookOutput({
    protectedRisk: true,
    permit: { verified: true },
    runtime: {
      exact_next_action: 'owner approval required',
      risk_gate: { allow: false, decision: 'review_required', reasons: [] },
    },
  });
  assert.deepEqual(review, {
    permission: 'deny',
    user_message: 'owner approval required',
    agent_message: 'owner approval required',
  });
  assert.deepEqual(Object.keys(review).sort(), ['agent_message', 'permission', 'user_message']);
  assert.equal(JSON.stringify(review).includes('ask'), false);
  assert.deepEqual(cursorPreActionHookOutput({
    protectedRisk: true,
    permit: null,
    runtime: null,
    enforcementError: 'runtime unavailable',
  }), {
    permission: 'deny',
    user_message: 'runtime unavailable',
    agent_message: 'runtime unavailable',
  });
  assert.deepEqual(cursorPreActionHookOutput({
    protectedRisk: false,
    permit: null,
    runtime: { risk_gate: { allow: true, decision: 'allow', reasons: [] } },
  }), { permission: 'allow' });
});

test('Cursor missing-key protected action denies privately while Marrow MCP does not recurse', async () => {
  const privateCommand = 'npm publish --otp synthetic-private-credential';
  await withCursorEnvironment({ entrypoint: 'cursor-pre-action-hook' }, async () => {
    const deniedText = await captureStdout(() => runPreActionHookCommand({
      eventName: 'preToolUse',
      conversationId: 'conversation-2',
      generationId: 'generation-2',
      toolUseId: 'tool-2',
      toolName: 'Shell',
      toolInput: { command: privateCommand },
    }));
    const denied = JSON.parse(deniedText);
    assert.equal(denied.permission, 'deny');
    assert.match(denied.user_message, /credentials are unavailable/i);
    assert.equal(denied.agent_message, denied.user_message);
    assert.deepEqual(Object.keys(denied).sort(), ['agent_message', 'permission', 'user_message']);
    assert.doesNotMatch(deniedText, /synthetic-private-credential|npm publish/);

    const allowedText = await captureStdout(() => runPreActionHookCommand({
      eventName: 'preToolUse',
      toolName: 'MCP:marrow_agent_runtime',
      toolInput: { token: 'must-not-leak' },
    }));
    assert.deepEqual(JSON.parse(allowedText), { permission: 'allow' });
  });
  assert.equal(isOfficialMarrowMcpTool('MCP:marrow_agent_runtime'), true);
  assert.equal(isOfficialMarrowMcpTool('MCP:github:create_issue'), false);
  assert.equal(deriveAction({ tool_name: 'MCP:marrow_agent_runtime', tool_input: {} }), null);
});

test('Cursor result events recognize success and failure fields without emitting raw values', async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ pathname: new URL(String(url)).pathname, body: init.body ? JSON.parse(String(init.body)) : {} });
    return Response.json({ data: { accepted: true } });
  };
  try {
    await withCursorEnvironment({
      entrypoint: 'cursor-hook',
      env: {
        MARROW_API_KEY: 'fixture-cursor-key',
        MARROW_BASE_URL: 'https://api.example.test',
        MARROW_FLEET_AGENT_ID: 'cursor-agent',
        MARROW_PASSIVE_TOKEN_USAGE: 'false',
      },
    }, async () => {
      await runHookCommand({
        eventName: 'postToolUse',
        conversationId: 'conversation-3',
        generationId: 'generation-3',
        toolUseId: 'tool-3',
        toolName: 'Write',
        toolInput: { content: 'raw-command synthetic-input-secret' },
        toolOutput: { content: 'raw-output synthetic-output-secret' },
        durationMs: 450000,
      });
      await runHookCommand({
        eventName: 'postToolUseFailure',
        conversationId: 'conversation-3',
        generationId: 'generation-3',
        toolUseId: 'tool-4',
        toolName: 'Delete',
        errorMessage: 'synthetic-error-secret',
        failureType: 'tool_error',
        durationMs: 12,
      });
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(calls.length, 2);
  assert.deepEqual(calls.map((call) => call.body.success), [true, false]);
  assert.deepEqual(calls.map((call) => call.body.harness), ['cursor', 'cursor']);
  assert.deepEqual(calls.map((call) => call.body.source), ['client_self_reported', 'client_self_reported']);
  const emitted = JSON.stringify(calls);
  assert.doesNotMatch(emitted, /raw-command|synthetic-input-secret|raw-output|synthetic-output-secret|synthetic-error-secret|fixture-cursor-key/);
  assert.deepEqual(deriveToolOutcome({ hook_event_name: 'PostToolUse', tool_output: 'ok', duration_ms: 450000 }), { success: true, duration_ms: 300000 });
  assert.equal(deriveToolOutcome({ hook_event_name: 'PostToolUseFailure', error_message: 'private' }).success, false);
});

test('Cursor stop records one bounded closeout, ends once, and invents no usage', async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ pathname: new URL(String(url)).pathname, body: init.body ? JSON.parse(String(init.body)) : {} });
    return Response.json({ data: { accepted: true, committed: 1 } });
  };
  try {
    await withCursorEnvironment({
      entrypoint: 'cursor-session-hook',
      env: {
        MARROW_API_KEY: 'fixture-cursor-key',
        MARROW_BASE_URL: 'https://api.example.test',
        MARROW_FLEET_AGENT_ID: 'cursor-agent',
      },
    }, () => runSessionHookCommand({
      eventName: 'stop',
      conversationId: 'conversation-stop',
      generationId: 'generation-stop',
      transcriptPath: '/must/not/be/read',
      unrelated: 'synthetic-unrelated-secret',
    }));
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(calls.filter((call) => call.pathname === '/v1/agent/integrations/events').length, 1);
  assert.equal(calls.filter((call) => call.pathname === '/v1/agent/session/end').length, 1);
  assert.equal(calls.some((call) => call.pathname === '/v1/agent/model-usage'), false);
  assert.doesNotMatch(JSON.stringify(calls), /must\/not\/be\/read|synthetic-unrelated-secret|fixture-cursor-key/);
});
