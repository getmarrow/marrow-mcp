const assert = require('node:assert/strict');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const { normalizeHookEventPayload, resolveNativeHookIdentity } = require('../dist/hook-contract.js');
const { classifyTool, geminiPreActionHookOutput } = require('../dist/hook-pre-action.js');
const { runHookCommand } = require('../dist/hook.js');
const { runSessionHookCommand } = require('../dist/hook-session.js');

const FIXED_REASON = 'Marrow blocked this action because required governance approval or proof is unavailable.';

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

async function withGeminiEnvironment(entrypoint, env, callback) {
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

function runPreChild(input) {
  const home = mkdtempSync(join(tmpdir(), 'marrow-gemini-hook-'));
  try {
    return spawnSync(process.execPath, ['dist/cli.js', 'gemini-pre-action-hook'], {
      cwd: process.cwd(),
      encoding: 'utf8',
      input: JSON.stringify(input),
      env: {
        PATH: process.env.PATH,
        HOME: home,
        MARROW_BASE_URL: 'https://api.example.test',
      },
    });
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

test('Gemini entrypoints and hook envelopes normalize to bounded classifications only', () => {
  for (const entrypoint of ['gemini-pre-action-hook', 'gemini-hook', 'gemini-session-hook']) {
    const identity = resolveNativeHookIdentity(entrypoint, {
      cwd: '/tmp',
      home: '/tmp',
      env: { MARROW_API_KEY: 'fixture-key', MARROW_FLEET_AGENT_ID: 'gemini-agent' },
    });
    assert.equal(identity.harness, 'gemini');
    assert.equal(identity.client_self_reported, true);
    assert.equal(identity.agent_id, 'gemini-agent');
  }

  const shell = normalizeHookEventPayload({
    session_id: 'gemini-session',
    hook_event_name: 'BeforeTool',
    tool_name: 'run_shell_command',
    tool_input: { command: 'npm publish --otp synthetic-private-value' },
    mcp_context: { private: 'synthetic-private-context' },
    cwd: '/synthetic/private/path',
  });
  assert.equal(shell.tool_name, 'Bash');
  assert.equal(classifyTool(shell).protected, true);
  assert.equal(JSON.stringify(shell).includes('synthetic-private-context'), false);
  assert.equal(JSON.stringify(shell).includes('/synthetic/private/path'), false);

  const ownMcp = normalizeHookEventPayload({
    session_id: 'gemini-session',
    hook_event_name: 'BeforeTool',
    tool_name: 'mcp_marrow_marrow_agent_runtime',
    tool_input: { private: 'synthetic-private-arguments' },
  });
  const externalMcp = normalizeHookEventPayload({
    session_id: 'gemini-session',
    hook_event_name: 'BeforeTool',
    tool_name: 'mcp_github_create_issue',
    tool_input: { private: 'synthetic-private-arguments' },
  });
  assert.equal(classifyTool(ownMcp).protected, false);
  assert.equal(classifyTool(externalMcp).protected, true);

  const after = normalizeHookEventPayload({
    session_id: 'gemini-session',
    hook_event_name: 'AfterTool',
    tool_name: 'write_file',
    tool_input: { file_path: '/synthetic/private/file', content: 'synthetic-private-input' },
    tool_response: { error: 'synthetic-private-error', output: 'synthetic-private-output' },
    mcp_context: { private: 'synthetic-private-context' },
    transcript_path: '/synthetic/private/transcript',
    duration_ms: 450000,
  });
  assert.deepEqual(after, {
    hook_event_name: 'AfterTool',
    session_id: 'gemini-session',
    tool_name: 'Write',
    tool_input: {},
    success: false,
    duration_ms: 300000,
  });

  const closeout = normalizeHookEventPayload({
    session_id: 'gemini-session',
    hook_event_name: 'AfterAgent',
    prompt: 'synthetic-private-prompt',
    prompt_response: 'synthetic-private-response',
    transcript_path: '/synthetic/private/transcript',
    cwd: '/synthetic/private/cwd',
  });
  assert.deepEqual(closeout, { hook_event_name: 'AfterAgent', session_id: 'gemini-session' });
});

test('Gemini BeforeTool uses exact fixed allow and deny JSON without service text', () => {
  assert.deepEqual(geminiPreActionHookOutput({
    protectedRisk: true,
    permit: { verified: true },
    runtime: {
      exact_next_action: 'synthetic-private-service-text',
      risk_gate: { allow: false, decision: 'review_required', reasons: [{ message: 'synthetic-private-reason' }] },
    },
  }), { decision: 'deny', reason: FIXED_REASON });
  assert.deepEqual(geminiPreActionHookOutput({
    protectedRisk: true,
    permit: null,
    runtime: null,
    enforcementError: 'synthetic-private-service-secret',
  }), { decision: 'deny', reason: FIXED_REASON });
  assert.deepEqual(geminiPreActionHookOutput({
    protectedRisk: true,
    permit: { verified: true },
    runtime: { risk_gate: { allow: true, decision: 'allow', reasons: [] } },
  }), { decision: 'allow' });
});

test('Gemini child BeforeTool returns strict exit-zero JSON for allow, missing proof, and unclassifiable input', () => {
  const denied = runPreChild({
    session_id: 'gemini-child',
    hook_event_name: 'BeforeTool',
    tool_name: 'write_file',
    tool_input: { file_path: '/synthetic/private/path', content: 'synthetic-private-content' },
  });
  assert.equal(denied.status, 0);
  assert.equal(denied.stderr, '');
  assert.equal(denied.stdout, JSON.stringify({ decision: 'deny', reason: FIXED_REASON }));
  assert.doesNotMatch(denied.stdout, /synthetic-private/);

  const malformed = runPreChild({
    session_id: 'gemini-child',
    hook_event_name: 'BeforeTool',
    tool_input: { command: 'synthetic-private-malformed' },
  });
  assert.equal(malformed.status, 0);
  assert.equal(malformed.stderr, '');
  assert.equal(malformed.stdout, JSON.stringify({ decision: 'deny', reason: FIXED_REASON }));

  const readOnly = runPreChild({
    session_id: 'gemini-child',
    hook_event_name: 'BeforeTool',
    tool_name: 'run_shell_command',
    tool_input: { command: 'git status' },
  });
  assert.equal(readOnly.status, 0);
  assert.equal(readOnly.stderr, '');
  assert.equal(readOnly.stdout, '{"decision":"allow"}');

  const ownMcp = runPreChild({
    session_id: 'gemini-child',
    hook_event_name: 'BeforeTool',
    tool_name: 'mcp_marrow_marrow_agent_runtime',
    tool_input: { private: 'synthetic-private-mcp-arguments' },
  });
  assert.equal(ownMcp.status, 0);
  assert.equal(ownMcp.stderr, '');
  assert.equal(ownMcp.stdout, '{"decision":"allow"}');
});

test('Gemini AfterTool returns neutral JSON and records compact success/failure without raw values', async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ pathname: new URL(String(url)).pathname, body: init.body ? JSON.parse(String(init.body)) : {} });
    return Response.json({ data: { accepted: true } });
  };
  let output;
  try {
    await withGeminiEnvironment('gemini-hook', {
      MARROW_API_KEY: 'fixture-gemini-key',
      MARROW_BASE_URL: 'https://api.example.test',
      MARROW_FLEET_AGENT_ID: 'gemini-agent',
      MARROW_PASSIVE_TOKEN_USAGE: 'false',
    }, async () => {
      output = await captureStdout(async () => {
        await runHookCommand({ session_id: 'gemini-post', hook_event_name: 'AfterTool', tool_name: 'write_file', tool_input: { content: 'synthetic-private-input' }, tool_response: { output: 'synthetic-private-output' } });
        await runHookCommand({ session_id: 'gemini-post', hook_event_name: 'AfterTool', tool_name: 'mcp_github_create_issue', tool_input: { private: 'synthetic-private-args' }, tool_response: { error: 'synthetic-private-error' }, mcp_context: { private: 'synthetic-private-context' } });
      });
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(output, '{}{}');
  assert.equal(calls.length, 2);
  assert.deepEqual(calls.map((call) => call.pathname), Array(2).fill('/v1/agent/integrations/events'));
  assert.deepEqual(calls.map((call) => call.body.success), [true, false]);
  assert.deepEqual(calls.map((call) => call.body.harness), ['gemini', 'gemini']);
  assert.deepEqual(calls.map((call) => call.body.source), ['client_self_reported', 'client_self_reported']);
  assert.doesNotMatch(JSON.stringify(calls), /synthetic-private-input|synthetic-private-output|synthetic-private-args|synthetic-private-error|synthetic-private-context|fixture-gemini-key/);
});

test('Gemini AfterAgent closes once, returns neutral JSON, ignores private response fields, and invents no usage', async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ pathname: new URL(String(url)).pathname, body: init.body ? JSON.parse(String(init.body)) : {} });
    return Response.json({ data: { accepted: true, committed: 1 } });
  };
  let output;
  try {
    await withGeminiEnvironment('gemini-session-hook', {
      MARROW_API_KEY: 'fixture-gemini-key',
      MARROW_BASE_URL: 'https://api.example.test',
      MARROW_FLEET_AGENT_ID: 'gemini-agent',
    }, async () => {
      output = await captureStdout(() => runSessionHookCommand({
        session_id: 'gemini-closeout',
        hook_event_name: 'AfterAgent',
        prompt: 'synthetic-private-prompt',
        prompt_response: 'synthetic-private-response',
        transcript_path: '/synthetic/private/transcript',
        cwd: '/synthetic/private/cwd',
        usage: { total_tokens: 999 },
      }));
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(output, '{}');
  assert.equal(calls.filter((call) => call.pathname === '/v1/agent/integrations/events').length, 1);
  assert.equal(calls.filter((call) => call.pathname === '/v1/agent/session/end').length, 1);
  assert.equal(calls.some((call) => call.pathname === '/v1/agent/model-usage'), false);
  assert.doesNotMatch(JSON.stringify(calls), /synthetic-private-prompt|synthetic-private-response|synthetic\/private|total_tokens|fixture-gemini-key/);
});
