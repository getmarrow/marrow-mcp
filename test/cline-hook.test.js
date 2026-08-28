const assert = require('node:assert/strict');
const test = require('node:test');

const { normalizeHookEventPayload, resolveNativeHookIdentity } = require('../dist/hook-contract.js');
const { clinePreActionHookOutput, classifyTool, runPreActionHookCommand } = require('../dist/hook-pre-action.js');
const { deriveAction, deriveToolOutcome, runHookCommand } = require('../dist/hook.js');
const { isOfficialMarrowMcpEvent } = require('../dist/hook-tool-policy.js');
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

async function withClineEnvironment(entrypoint, env, callback) {
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

test('Cline entrypoints and nested envelopes normalize to bounded client-self-reported identity', () => {
  for (const entrypoint of ['cline-pre-action-hook', 'cline-hook', 'cline-session-hook']) {
    const identity = resolveNativeHookIdentity(entrypoint, {
      cwd: '/tmp',
      home: '/tmp',
      env: { MARROW_API_KEY: 'fixture-key', MARROW_FLEET_AGENT_ID: 'cline-agent' },
    });
    assert.equal(identity.harness, 'cline');
    assert.equal(identity.client_self_reported, true);
    assert.equal(identity.agent_id, 'cline-agent');
  }
  const normalized = normalizeHookEventPayload({
    hookName: 'PostToolUse',
    taskId: 'task-1',
    postToolUse: {
      toolName: 'write_to_file',
      parameters: { path: '/private/file' },
      result: { content: 'private result' },
      success: false,
      durationMs: 450000,
    },
  });
  assert.equal(normalized.hook_event_name, 'PostToolUse');
  assert.equal(normalized.task_id, 'task-1');
  assert.equal(normalized.tool_name, 'write_to_file');
  assert.deepEqual(normalized.tool_input, { path: '/private/file' });
  assert.deepEqual(normalized.tool_result, { content: 'private result' });
  assert.equal(normalized.success, false);
  assert.equal(normalized.duration_ms, 450000);
  assert.equal(normalizeHookEventPayload({ taskId: '../unsafe' }).task_id, undefined);
});

test('Cline native pre-action schema denies review and unavailable proof and allows only with cancel false', () => {
  const review = clinePreActionHookOutput({
    protectedRisk: true,
    permit: { verified: true },
    runtime: {
      exact_next_action: 'owner approval required',
      risk_gate: { allow: false, decision: 'review_required', reasons: [] },
    },
  });
  assert.deepEqual(review, { cancel: true, errorMessage: 'Marrow requires operator review before this protected action.' });
  assert.deepEqual(Object.keys(review).sort(), ['cancel', 'errorMessage']);
  assert.equal(JSON.stringify(review).includes('ask'), false);
  assert.equal('permission' in review, false);
  assert.equal('hookSpecificOutput' in review, false);
  assert.deepEqual(clinePreActionHookOutput({
    protectedRisk: true,
    permit: null,
    runtime: null,
    enforcementError: 'runtime unavailable',
  }), { cancel: true, errorMessage: 'Marrow could not verify the required action permit. Restore trusted governance and retry.' });
  assert.deepEqual(clinePreActionHookOutput({
    protectedRisk: false,
    permit: null,
    runtime: { risk_gate: { allow: true, decision: 'allow', reasons: [] } },
  }), { cancel: false });

  const serviceSecret = 'synthetic-service-private-value';
  const privateReview = clinePreActionHookOutput({
    protectedRisk: true,
    permit: { verified: true },
    runtime: {
      exact_next_action: `send ${serviceSecret} to the operator`,
      risk_gate: {
        allow: false,
        decision: 'review_required',
        reasons: [{ message: `private service text ${serviceSecret}` }],
      },
    },
  });
  const privateUnavailable = clinePreActionHookOutput({
    protectedRisk: true,
    permit: null,
    runtime: null,
    enforcementError: `runtime failed with ${serviceSecret}`,
  });
  assert.doesNotMatch(JSON.stringify([privateReview, privateUnavailable]), /synthetic-service-private-value/);
});

test('Cline missing-key protected action denies privately while Marrow MCP does not recurse', async () => {
  const privateCommand = 'npm publish --otp synthetic-private-credential';
  await withClineEnvironment('cline-pre-action-hook', {}, async () => {
    const deniedText = await captureStdout(() => runPreActionHookCommand({
      hookName: 'PreToolUse',
      taskId: 'task-2',
      preToolUse: {
        toolName: 'execute_command',
        parameters: { command: privateCommand },
      },
    }));
    const denied = JSON.parse(deniedText);
    assert.equal(denied.cancel, true);
    assert.match(denied.errorMessage, /credentials are unavailable/i);
    assert.deepEqual(Object.keys(denied).sort(), ['cancel', 'errorMessage']);
    assert.doesNotMatch(deniedText, /synthetic-private-credential|npm publish/);

    const allowedText = await captureStdout(() => runPreActionHookCommand({
      hookName: 'PreToolUse',
      taskId: 'task-2',
      preToolUse: {
        toolName: 'use_mcp_tool',
        parameters: { serverName: 'marrow', toolName: 'marrow_agent_runtime', token: 'must-not-leak' },
      },
    }));
    assert.deepEqual(JSON.parse(allowedText), { cancel: false });
  });
  const official = {
    tool_name: 'use_mcp_tool',
    tool_input: { serverName: 'marrow', toolName: 'marrow_agent_runtime' },
  };
  assert.equal(isOfficialMarrowMcpEvent(official), true);
  assert.equal(deriveAction(official), null);
  assert.equal(classifyTool({
    tool_name: 'use_mcp_tool',
    tool_input: { serverName: 'github', toolName: 'create_issue' },
  }).protected, true);
});

test('Cline PostToolUse captures nested success and failure without retaining raw values', async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ pathname: new URL(String(url)).pathname, body: init.body ? JSON.parse(String(init.body)) : {} });
    return Response.json({ data: { accepted: true } });
  };
  try {
    await withClineEnvironment('cline-hook', {
      MARROW_API_KEY: 'fixture-cline-key',
      MARROW_BASE_URL: 'https://api.example.test',
      MARROW_FLEET_AGENT_ID: 'cline-agent',
      MARROW_PASSIVE_TOKEN_USAGE: 'false',
    }, async () => {
      await runHookCommand({
        hookName: 'PostToolUse',
        taskId: 'task-3',
        postToolUse: {
          toolName: 'write_to_file',
          parameters: { content: 'synthetic-input-secret' },
          result: { content: 'synthetic-output-secret' },
          success: true,
          durationMs: 450000,
        },
      });
      await runHookCommand({
        hookName: 'PostToolUse',
        taskId: 'task-3',
        postToolUse: {
          toolName: 'delete_file',
          parameters: { path: 'synthetic-private-path' },
          result: { error: 'synthetic-error-secret' },
          success: false,
          durationMs: 12,
        },
      });
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(calls.length, 2);
  assert.deepEqual(calls.map((call) => call.body.success), [true, false]);
  assert.deepEqual(calls.map((call) => call.body.harness), ['cline', 'cline']);
  assert.deepEqual(calls.map((call) => call.body.source), ['client_self_reported', 'client_self_reported']);
  assert.doesNotMatch(JSON.stringify(calls), /synthetic-input-secret|synthetic-output-secret|synthetic-private-path|synthetic-error-secret|fixture-cline-key/);
  assert.deepEqual(deriveToolOutcome({ success: true, tool_result: 'ok', duration_ms: 450000 }), { success: true, duration_ms: 300000 });
  assert.equal(deriveToolOutcome({ success: false, tool_result: 'private error' }).success, false);
});

test('Cline TaskCancel and TaskComplete adapters each close once without continuation or invented usage', async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ pathname: new URL(String(url)).pathname, body: init.body ? JSON.parse(String(init.body)) : {} });
    return Response.json({ data: { accepted: true, committed: 1 } });
  };
  try {
    await withClineEnvironment('cline-session-hook', {
      MARROW_API_KEY: 'fixture-cline-key',
      MARROW_BASE_URL: 'https://api.example.test',
      MARROW_FLEET_AGENT_ID: 'cline-agent',
    }, async () => {
      await runSessionHookCommand({ hookName: 'TaskCancel', taskId: 'task-cancel', workspaceRoots: ['/private/root'] });
      await runSessionHookCommand({ hookName: 'TaskComplete', taskId: 'task-complete', userId: 'private-user' });
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(calls.filter((call) => call.pathname === '/v1/agent/integrations/events').length, 2);
  assert.equal(calls.filter((call) => call.pathname === '/v1/agent/session/end').length, 2);
  assert.equal(calls.some((call) => call.pathname === '/v1/agent/model-usage'), false);
  assert.doesNotMatch(JSON.stringify(calls), /private\/root|private-user|fixture-cline-key/);
});
