const assert = require('node:assert/strict');
const { mkdtempSync, readFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const { marrowAgentRuntime, marrowAuto, marrowBuyerProof, marrowStatus } = require('../dist/index.js');
const { MarrowRequestError, normalizeRequestError, reliableFetch, requestErrorFromResponse, structuredRequestFailure } = require('../dist/request-reliability.js');
const { highRiskRuntimeCanClose, normalizeRuntimeResult } = require('../dist/runtime-contract.js');
const { writeGuidanceCache } = require('../dist/guidance-cache.js');

function mcpInput(toolName = 'marrow_agent_runtime', args) {
  return [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
    { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
    {
      jsonrpc: '2.0', id: 3, method: 'tools/call',
      params: { name: toolName, arguments: args || (toolName === 'marrow_agent_runtime' ? { action: 'deploy safely', type: 'deploy' } : {}) },
    },
  ].map((row) => JSON.stringify(row)).join('\n') + '\n';
}

function runMcp(home, extraEnv = {}, input = mcpInput()) {
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
    input,
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

test('malformed successful runtime responses fail closed with a typed invalid_response', async () => {
  const originalFetch = globalThis.fetch;
  try {
    for (const body of [{}, { data: {} }, { data: { risk_gate: { allow: true } } }]) {
      globalThis.fetch = async () => Response.json(body);
      await assert.rejects(
        () => marrowAgentRuntime('fixture-key', 'https://api.example.test', { action: 'deploy safely' }),
        (error) => error instanceof MarrowRequestError && error.code === 'invalid_response',
      );
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('native slim runtime responses normalize without weakening their decision', () => {
  const allowed = normalizeRuntimeResult({
    response_mode: 'slim', decision: 'proceed', risk_level: 'low', gate_required: false,
    proof_required: false, proof_complete: true, gate_receipt_id: 'gate-low',
  });
  assert.equal(allowed.risk_gate.allow, true);
  assert.equal(allowed.risk_gate.decision, 'allow');
  assert.equal(allowed.proof_pack.complete, true);

  const blocked = normalizeRuntimeResult({
    response_mode: 'slim', decision: 'block', risk_level: 'high', gate_required: true,
    proof_required: true, proof_complete: false, gate_receipt_id: 'gate-blocked',
  });
  assert.equal(blocked.risk_gate.allow, false);
  assert.equal(blocked.risk_gate.decision, 'block');
  assert.equal(blocked.proof_pack.complete, false);
  assert.equal(normalizeRuntimeResult({ response_mode: 'slim', decision: 'unknown_policy' }), null);
});

test('native slim runtime responses reject unknown risk levels', () => {
  assert.equal(normalizeRuntimeResult({
    response_mode: 'slim',
    decision: 'allow',
    risk_level: 'future_unknown',
    gate_required: false,
    proof_required: false,
    proof_complete: true,
  }), null);
});

test('API failure messages and exact fixes redact secret-shaped values', async () => {
  const originalFetch = globalThis.fetch;
  const leakedKey = ['mrw', 'sensitive', 'fixture', 'value'].join('_');
  const leakedConfig = `${['MARROW', 'API', 'KEY'].join('_')}=${['fixture', 'sensitive', 'value'].join('-')}`;
  globalThis.fetch = async () => Response.json({
    error: `backend rejected ${leakedKey}`,
    exact_fix: `retry with ${leakedConfig}`,
  }, { status: 503 });
  try {
    await assert.rejects(
      () => marrowAgentRuntime('fixture-key', 'https://api.example.test', { action: 'deploy safely' }),
      (error) => error instanceof MarrowRequestError
        && error.code === 'service_unavailable'
        && !String(error.message).includes(leakedKey)
        && !String(error.exactFix).includes(leakedConfig)
        && /REDACTED/.test(`${error.message} ${error.exactFix}`),
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('fleet-bound identity is identical in agent-scoped headers, bodies, and query defaults', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    calls.push({
      url: String(url),
      headers: new Headers(init.headers),
      body: init.body ? JSON.parse(String(init.body)) : null,
    });
    if (String(url).includes('/v1/agent/runtime')) {
      return Response.json({ data: {
        response_mode: 'slim', decision: 'allow', risk_level: 'low', gate_required: false,
        proof_required: false, proof_complete: true, gate_receipt_id: 'gate-fixture',
      } });
    }
    return Response.json({ data: {} });
  };
  try {
    const agentId = 'fleet-bound-agent';
    await marrowAgentRuntime('fixture-key', 'https://api.example.test', { action: 'inspect safely' }, 'session-one', agentId);
    await marrowBuyerProof('fixture-key', 'https://api.example.test', {}, 'session-one', agentId);

    assert.equal(calls.length, 2);
    assert.equal(calls[0].headers.get('X-Marrow-Agent-Id'), agentId);
    assert.equal(calls[0].body.agent_id, agentId);
    assert.equal(calls[1].headers.get('X-Marrow-Agent-Id'), agentId);
    assert.equal(new URL(calls[1].url).searchParams.get('agent_id'), agentId);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('scope mismatch code and backend exact repair survive a structured 403', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({
    error: 'Agent identity does not match the key binding.',
    details: {
      code: 'MARROW_AGENT_SCOPE_MISMATCH',
      exact_fix: 'Use the fleet-bound agent identity for both the request body and header.',
      fix_command: 'export MARROW_FLEET_AGENT_ID=fleet-bound-agent',
    },
  }, { status: 403 });
  try {
    await assert.rejects(
      () => marrowAgentRuntime('fixture-key', 'https://api.example.test', { action: 'inspect safely' }, 'session-one', 'fleet-bound-agent'),
      (error) => {
        assert.ok(error instanceof MarrowRequestError);
        assert.equal(error.code, 'permission_denied');
        assert.equal(error.backendCode, 'MARROW_AGENT_SCOPE_MISMATCH');
        assert.match(error.exactFix, /fleet-bound agent identity/);
        const failure = structuredRequestFailure(error);
        assert.equal(failure.error.code, 'MARROW_AGENT_SCOPE_MISMATCH');
        assert.equal(failure.error.category, 'permission_denied');
        assert.match(failure.error.exact_fix, /fleet-bound agent identity/);
        assert.equal(failure.error.fix_command, 'export MARROW_FLEET_AGENT_ID=fleet-bound-agent');
        return true;
      },
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('an unstructured Cloudflare 403 is an infrastructure failure rather than a Marrow policy denial', () => {
  const failure = requestErrorFromResponse(new Response('<html>edge denial</html>', {
    status: 403,
    headers: { 'content-type': 'text/html', 'cf-ray': 'fixture-ray' },
  }));
  assert.equal(failure.code, 'edge_access_denied');
  assert.equal(failure.status, 403);
  assert.equal(failure.retryable, false);
  assert.match(failure.exactFix, /Cloudflare Ray ID/);
});

test('a timeout returns a concrete retry delay rather than an unresolved placeholder', () => {
  const failure = normalizeRequestError(new DOMException('Timed out', 'AbortError'));
  const payload = structuredRequestFailure(failure);
  assert.equal(failure.code, 'request_timeout');
  assert.equal(payload.error.retry_after_ms, 250);
  assert.match(payload.error.exact_fix, /250 ms/);
  assert.doesNotMatch(payload.error.exact_fix, /retry_after_ms/i);
});

test('caller-supplied abort signals retain one bounded safe retry', async () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    return calls === 1 ? new Response('{}', { status: 503 }) : Response.json({ data: { health: 'healthy' } });
  };
  try {
    const controller = new AbortController();
    const response = await reliableFetch('https://api.example.test/v1/agent/status', { signal: controller.signal });
    assert.equal(response.status, 200);
    assert.equal(calls, 2);
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
    assert.equal(result.failure_kind, 'infrastructure');
    assert.equal(result.authorization_state, 'unavailable');
    assert.equal(result.gate_obtained, false);
    assert.equal('allow' in result, false);
    assert.equal('disposition' in result, false);
    assert.equal(result.stale_can_authorize_high_risk, false);
    assert.match(result.stale_brief, /verify the deploy proof/);
    assert.match(result.error.exact_fix, /retry|doctor|outbound/i);
    assert.equal(result.client_update.installed_version_verified, true);
    assert.equal(result.client_update.version_status, 'unknown');
    assert.equal(result.client_update.update_command, 'npx -y --package=@getmarrow/mcp@latest marrow-mcp setup');
    assert.equal(result.control_path.tool, 'marrow_agent_runtime');
    assert.equal(result.control_path.sample_count, 1);
    assert.equal(typeof result.lifecycle_spool.pending, 'number');
    assert.match(result.lifecycle_spool.drain_command, /marrow-mcp drain-spool$/);
    assert.doesNotMatch(messages[2].result.content[0].text, /fetch failed/i);
    assert.equal('error' in messages[2], false);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('a first-session control outage still returns an honest local safety brief', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-control-path-empty-'));
  try {
    const child = runMcp(home);
    assert.equal(child.status, 0, child.stderr);
    const messages = child.stdout.trim().split('\n').map((line) => JSON.parse(line));
    const result = JSON.parse(messages[2].result.content[0].text);
    assert.equal(result.failure_kind, 'infrastructure');
    assert.equal(result.stale_source, 'local_outage_safety');
    assert.equal(result.stale_ms, null);
    assert.match(result.stale_brief, /returned no policy decision/);
    assert.equal('allow' in result, false);
    assert.equal('disposition' in result, false);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('initialize carries the always-on control loop through the standard MCP instructions field', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-control-path-instructions-'));
  try {
    const child = runMcp(home, { MARROW_AUTO_ENROLL: 'true' });
    assert.equal(child.status, 0, child.stderr);
    const messages = child.stdout.trim().split('\n').map((line) => JSON.parse(line));
    assert.match(messages[0].result.instructions, /marrow_agent_runtime before consequential actions/);
    assert.match(messages[0].result.instructions, /Infrastructure failures are not policy denials/);
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

test('compact MCP profile rejects direct calls to hidden advanced tools', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-control-path-hidden-'));
  try {
    const child = runMcp(home, {}, mcpInput('marrow_create_key', { name: 'must-not-run' }));
    assert.equal(child.status, 0, child.stderr);
    const messages = child.stdout.trim().split('\n').map((line) => JSON.parse(line));
    assert.equal(messages[2].error.code, -32601);
    assert.match(messages[2].error.message, /active Marrow tool profile/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('high-risk closure requires an allowed fresh receipt and complete proof', () => {
  const runtime = {
    risk_gate: { allow: true, decision: 'allow' },
    proof_pack: { complete: true },
    gate_receipt: { id: 'gate-one', decision: 'allow', expires_at: '2030-01-01T00:00:00.000Z' },
  };
  assert.equal(highRiskRuntimeCanClose(runtime, { test: 'passed' }, undefined, Date.parse('2029-01-01T00:00:00.000Z')), true);
  assert.equal(highRiskRuntimeCanClose({ ...runtime, risk_gate: { allow: false, decision: 'block' } }, { test: 'passed' }, undefined), false);
  assert.equal(highRiskRuntimeCanClose({ ...runtime, proof_pack: { complete: false } }, { test: 'passed' }, undefined), false);
  assert.equal(highRiskRuntimeCanClose({ ...runtime, gate_receipt: { id: 'gate-one', decision: 'review_required' } }, { test: 'passed' }, undefined), false);
  assert.equal(highRiskRuntimeCanClose(runtime, undefined, undefined), false);
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
  assert.match(source, /class PersistentMcpClient/);
  assert.match(source, /process_count: 1/);
  assert.match(source, /per_tool_latency_excludes_initialization: true/);
  assert.match(source, /unexpected response id/);
  assert.match(source, /returned no MCP tool response/);
  assert.match(source, /empty or invalid tool payload/);
  assert.match(source, /version !== expectedVersion/);
  assert.match(source, /validatePayload\(name, payload\)/);
  assert.match(source, /\['marrow_value_report', \{ period: '7d' \}\]/);
  assert.doesNotMatch(source, /\['marrow_dashboard', \{\}\]/);
  assert.match(source, /client\.request\('tools\/call'/);
  assert.match(source, /latency_groups/);
  assert.match(source, /tools_checked: results\.length/);
  assert.match(source, /process\.exitCode = 1/);
});

test('MCP omits an unconfigured agent identity instead of generating restart drift', () => {
  const source = readFileSync(join(__dirname, '..', 'src', 'cli.ts'), 'utf8');
  assert.match(source, /const FLEET_AGENT_ID = resolvedEnv\.agentId \|\| undefined/);
  assert.doesNotMatch(source, /hostname\(\).*Date\.now/);
});
