const assert = require('node:assert/strict');
const { mkdtempSync, readFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const { marrowAgentRuntime, marrowAuto, marrowStatus } = require('../dist/index.js');
const { MarrowRequestError } = require('../dist/request-reliability.js');
const { writeGuidanceCache } = require('../dist/guidance-cache.js');

function mcpInput(toolName = 'marrow_agent_runtime') {
  return [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
    { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
    {
      jsonrpc: '2.0', id: 3, method: 'tools/call',
      params: { name: toolName, arguments: toolName === 'marrow_agent_runtime' ? { action: 'deploy safely', type: 'deploy' } : {} },
    },
  ].map((row) => JSON.stringify(row)).join('\n') + '\n';
}

function runMcp(home, extraEnv = {}) {
  return spawnSync(process.execPath, [join(__dirname, '..', 'dist', 'cli.js')], {
    env: {
      ...process.env,
      HOME: home,
      MARROW_API_KEY: 'fixture-control-path-key',
      MARROW_BASE_URL: 'https://127.0.0.1:9',
      MARROW_FLEET_AGENT_ID: 'agent-control-test',
      MARROW_AUTO_ENROLL: 'false',
      MARROW_REQUEST_TIMEOUT_MS: '150',
      ...extraEnv,
    },
    input: mcpInput(),
    encoding: 'utf8',
    timeout: 3_000,
  });
}

test('status proves the authenticated agent path rather than public health', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url) => {
    calls.push(String(url));
    return Response.json({ data: { health: 'healthy' } });
  };
  try {
    await marrowStatus('fixture-key', 'https://api.example.test');
    assert.deepEqual(calls, ['https://api.example.test/v1/agent/status?fast=1']);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('transport errors are typed and never expose raw undici failure text', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    const error = new TypeError('fetch failed');
    error.cause = { code: 'ENOTFOUND' };
    throw error;
  };
  try {
    await assert.rejects(
      () => marrowAgentRuntime('fixture-key', 'https://api.example.test', { action: 'deploy safely' }),
      (error) => error instanceof MarrowRequestError
        && error.code === 'dns_unavailable'
        && !/fetch failed/i.test(error.message),
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('default MCP surface is compact and transient runtime failure returns structured stale-safe guidance', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-control-path-'));
  try {
    writeGuidanceCache({
      apiKey: 'fixture-control-path-key',
      baseUrl: 'https://127.0.0.1:9',
      agentId: 'agent-control-test',
      context: '## Marrow before-action\n- Decision: review_required; risk: high.\n- Next: verify the deploy proof.',
      home,
    });
    const child = runMcp(home);
    assert.equal(child.status, 0, child.stderr);
    const messages = child.stdout.trim().split('\n').map((line) => JSON.parse(line));
    assert.equal(messages.length, 3, child.stdout);
    assert.deepEqual(messages[1].result.tools.map((tool) => tool.name).sort(), [
      'marrow_agent_runtime', 'marrow_ask', 'marrow_auto', 'marrow_commit', 'marrow_handoff_status', 'marrow_status',
    ].sort());
    const result = JSON.parse(messages[2].result.content[0].text);
    assert.equal(messages[2].result.isError, true);
    assert.equal(result.ok, false);
    assert.equal(result.available, false);
    assert.equal(result.allow, false);
    assert.equal(result.disposition, 'review_required');
    assert.equal(result.stale_can_authorize_high_risk, false);
    assert.match(result.stale_brief, /verify the deploy proof/);
    assert.match(result.error.exact_fix, /retry|doctor|outbound/i);
    assert.match(result.client_update.update_command, /@getmarrow\/mcp@latest setup/);
    assert.doesNotMatch(messages[2].result.content[0].text, /fetch failed/i);
    assert.equal('error' in messages[2], false);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('full MCP profile remains callable for backward-compatible advanced workflows', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-control-path-full-'));
  try {
    const child = runMcp(home, { MARROW_TOOL_PROFILE: 'full' });
    assert.equal(child.status, 0, child.stderr);
    const messages = child.stdout.trim().split('\n').map((line) => JSON.parse(line));
    assert.ok(messages[1].result.tools.length > 40);
    assert.ok(messages[1].result.tools.some((tool) => tool.name === 'marrow_replay_compare'));
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('auto does not invent successful completion when success is absent', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), body: init?.body ? JSON.parse(String(init.body)) : null });
    return Response.json({ data: { decision_id: 'decision-pending' } });
  };
  try {
    const result = await marrowAuto('fixture-key', 'https://api.example.test', {
      action: 'investigate a deployment',
      outcome: 'command exited zero but business outcome is unverified',
    });
    assert.deepEqual(result, { decision_id: 'decision-pending', committed: false });
    assert.equal(calls.length, 1);
    assert.match(calls[0].url, /\/v1\/agent\/think$/);
    assert.doesNotMatch(JSON.stringify(calls), /marrow_auto completed|checks/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('published canary requires a completed child response for every route', () => {
  const source = readFileSync(join(__dirname, '..', 'scripts', 'control-path-canary.cjs'), 'utf8');
  assert.match(source, /spawnSync/);
  assert.match(source, /returned no MCP tool response/);
  assert.match(source, /child\.status !== 0/);
  assert.match(source, /tools_checked: results\.length/);
  assert.match(source, /process\.exitCode = 1/);
});
