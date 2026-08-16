const assert = require('node:assert/strict');
const { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const { marrowAgentRuntime, marrowAuto, marrowBuyerProof, marrowCommit, marrowStatus } = require('../dist/index.js');
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
  const env = {
    ...process.env,
    HOME: home,
    MARROW_API_KEY: 'fixture-control-path-key',
    MARROW_BASE_URL: 'https://127.0.0.1:9',
    MARROW_FLEET_AGENT_ID: 'agent-control-test',
    MARROW_AUTO_ENROLL: 'false',
    MARROW_REQUEST_TIMEOUT_MS: '150',
    ...extraEnv,
  };
  if (Object.hasOwn(extraEnv, 'MARROW_REQUEST_TIMEOUT_MS') && extraEnv.MARROW_REQUEST_TIMEOUT_MS == null) {
    delete env.MARROW_REQUEST_TIMEOUT_MS;
  }
  return spawnSync(process.execPath, [join(__dirname, '..', 'dist', 'cli.js')], {
    env,
    input,
    encoding: 'utf8',
    timeout: 3_000,
  });
}

function installControlFetchMock(home) {
  const mockPath = join(home, 'mock-control-fetch.cjs');
  writeFileSync(mockPath, `
const delay = Number(process.env.MARROW_TEST_FETCH_DELAY_MS || 0);
function wait(signal) {
  if (!delay) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, delay);
    const abort = () => {
      clearTimeout(timer);
      reject(signal?.reason || new DOMException('Aborted', 'AbortError'));
    };
    if (signal?.aborted) abort();
    else signal?.addEventListener('abort', abort, { once: true });
  });
}
globalThis.fetch = async (url, init = {}) => {
  await wait(init.signal);
  const target = String(url);
  if (target.includes('/v1/analytics/decision-brief')) {
    return Response.json({ data: {
      summary: 'Use current control guidance.', next_actions: ['Verify the live gate.'],
      risk: { similar_failures: [] }, failure_alerts: [], fleet_reliability: { outcome_coverage: 1 },
    } });
  }
  if (target.includes('/v1/agent/runtime')) {
    if (process.env.MARROW_TEST_RUNTIME_WITH_STATUS === '1') {
      return Response.json({ data: {
        ok: true,
        risk_gate: { allow: true, decision: 'allow', risk_level: 'low', gate_required: false },
        status: {
          ok: true,
          health: 'healthy',
          enabled: true,
          measurement_availability: {
            available: true, state: 'measured', exact: false, source: 'shared_runtime_snapshot',
          },
          memory: { has_memory: true, decision_count: 20 },
          has_memory: true,
          decision_count: 20,
          outcome_count: 7,
        },
      } });
    }
    return Response.json({ data: {
      response_mode: 'slim', decision: 'allow', risk_level: 'low', gate_required: false,
      proof_required: false, proof_complete: true, gate_receipt_id: 'gate-fixture',
    } });
  }
  if (target.includes('/v1/agent/think')) {
    return Response.json({ data: { decision_id: 'decision-auto' } });
  }
  if (target.includes('/v1/agent/commit')) {
    const body = JSON.parse(String(init.body || '{}'));
    if (process.env.MARROW_TEST_PROOF_INCOMPLETE === '1') {
      return Response.json({
        error: 'Required proof pack is incomplete',
        details: {
          code: 'MARROW_PROOF_PACK_INCOMPLETE',
          missing_fields: ['deployment_and_smoke', 'rollback_target'],
          exact_fix: 'Add the missing proof fields under proof (deployment_and_smoke, rollback_target) and retry /v1/agent/commit with the same gate_receipt_id.',
          exact_next_action: 'Retry /v1/agent/commit only after proof includes: deployment_and_smoke, rollback_target.',
          safe_to_continue: false,
        },
      }, { status: 409 });
    }
    if (body.proof?.test !== 'passed') {
      return Response.json({ error: 'fixture requires forwarded proof' }, { status: 400 });
    }
    if (process.env.MARROW_TEST_COMMIT_STATE === 'missing') {
      return Response.json({ data: { success: true } });
    }
    return Response.json({ data: {
      committed: process.env.MARROW_TEST_COMMIT_STATE !== 'false',
    } });
  }
  if (target.includes('/v1/agent/integrations/events')) {
    const body = JSON.parse(String(init.body || '{}'));
    if (process.env.MARROW_TEST_FORBID_OUTCOME_COMMITTED === '1' && body.event_type === 'outcome_committed') {
      return Response.json({ error: 'fixture forbids false closure' }, { status: 503 });
    }
    if (process.env.MARROW_TEST_LIFECYCLE_FAILURE === '1') {
      return Response.json({ error: 'fixture lifecycle outage' }, { status: 503 });
    }
    return Response.json({ data: { accepted: true } });
  }
  if (target.includes('/v1/fleet/handoffs/status') && process.env.MARROW_TEST_HANDOFF_PLAN === '1') {
    return Response.json({
      error: { code: 'FORBIDDEN', message: 'Fleet learning requires the Team plan or above.' },
      details: { current_plan: 'free', code: 'MARROW_PLAN_UPGRADE_REQUIRED', required_feature: 'fleet_learning' },
    }, { status: 403 });
  }
  return Response.json({ data: { health: 'healthy' } });
};
`, { mode: 0o600 });
  return mockPath;
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
    assert.deepEqual(calls, ['https://api.example.test/v1/agent/status?fast=1&compact=1']);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('status uses one compact contract across representative MCP host identities', async () => {
  const originalFetch = globalThis.fetch;
  const originalClient = process.env.MARROW_CLIENT;
  const seen = [];
  globalThis.fetch = async (url, init) => {
    seen.push({ url: String(url), client: init.headers['X-Marrow-Client'] });
    return Response.json({ data: { ok: true, health: 'healthy' } });
  };
  try {
    for (const client of ['grok', 'codex', 'claude-code', 'custom']) {
      process.env.MARROW_CLIENT = client;
      await marrowStatus('fixture-key', 'https://api.example.test');
    }
    assert.deepEqual(seen.map((entry) => entry.url), Array(4).fill('https://api.example.test/v1/agent/status?fast=1&compact=1'));
    assert.deepEqual(seen.map((entry) => entry.client), ['grok', 'codex', 'claude-code', 'custom']);
  } finally {
    globalThis.fetch = originalFetch;
    if (originalClient == null) delete process.env.MARROW_CLIENT;
    else process.env.MARROW_CLIENT = originalClient;
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
  assert.equal(payload.error.retry_after_ms, 1_000);
  assert.match(payload.error.exact_fix, /1000 ms/);
  assert.doesNotMatch(payload.error.exact_fix, /retry_after_ms/i);
});

test('cached guidance never reduces the live MCP control deadline to 500 ms', () => {
  const source = readFileSync(join(__dirname, '..', 'src', 'cli.ts'), 'utf8');
  assert.doesNotMatch(source, /hasCache\s*\?\s*500/);
  assert.match(source, /options\.highRisk\s*\|\|\s*runtimeBudget\s*\?\s*4_500\s*:\s*4_000/);
});

test('a cached ask does not shorten the next runtime call below the customer default deadline', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-cached-runtime-'));
  try {
    const mockPath = installControlFetchMock(home);
    const env = {
      MARROW_REQUEST_TIMEOUT_MS: null,
      MARROW_TEST_FETCH_DELAY_MS: '700',
      NODE_OPTIONS: `--require=${mockPath}`,
    };
    const asked = runMcp(home, env, mcpInput('marrow_ask', { query: 'What should run before this action?' }));
    assert.equal(asked.status, 0, asked.stderr);
    const askMessages = asked.stdout.trim().split('\n').map((line) => JSON.parse(line));
    assert.equal(askMessages[2].result.isError, undefined, asked.stdout);
    assert.match(JSON.parse(askMessages[2].result.content[0].text).answer, /current control guidance/i);

    const runtime = runMcp(home, env, mcpInput('marrow_agent_runtime', {
      action: 'Review a local documentation note',
      type: 'general',
    }));
    assert.equal(runtime.status, 0, runtime.stderr);
    const runtimeMessages = runtime.stdout.trim().split('\n').map((line) => JSON.parse(line));
    assert.equal(runtimeMessages[2].result.isError, undefined, runtime.stdout);
    const payload = JSON.parse(runtimeMessages[2].result.content[0].text);
    assert.equal(payload.risk_gate.allow, true);
    assert.equal(payload.risk_gate.decision, 'allow');
    assert.equal(payload.control_path.success_count, 1);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
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

test('standalone status immediately reuses a fresh measured runtime status without claiming a live gate', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-control-status-cache-'));
  try {
    const mockPath = installControlFetchMock(home);
    const runtime = runMcp(home, {
      NODE_OPTIONS: `--require=${mockPath}`,
      MARROW_TEST_RUNTIME_WITH_STATUS: '1',
      MARROW_CLIENT: 'codex',
    });
    assert.equal(runtime.status, 0, runtime.stderr);

    const status = runMcp(home, { MARROW_CLIENT: 'codex' }, mcpInput('marrow_status', {}));
    assert.equal(status.status, 0, status.stderr);
    const messages = status.stdout.trim().split('\n').map((line) => JSON.parse(line));
    const payload = JSON.parse(messages[2].result.content[0].text);
    assert.equal(messages[2].result.isError, undefined);
    assert.equal(payload.status_source, 'last_known_runtime_status');
    assert.equal(payload.status_freshness, 'fresh');
    assert.equal(payload.has_memory, true);
    assert.equal(payload.decision_count, 20);
    assert.equal(payload.authorization_state, 'status_only_non_authorizing');
    assert.equal(payload.fresh_runtime_gate_required_for_high_risk, true);
    assert.equal(payload.host_capability.host, 'codex');
    assert.ok(payload.control_path.current_ms < 100, `cached status handler took ${payload.control_path.current_ms}ms`);

    const cacheDirectory = join(home, '.marrow', 'cache');
    const statusFile = readdirSync(cacheDirectory).find((name) => name.startsWith('status-'));
    assert.ok(statusFile);
    const statusPath = join(cacheDirectory, statusFile);
    const cacheRecord = JSON.parse(readFileSync(statusPath, 'utf8'));
    cacheRecord.stored_at = new Date(Date.now() - 31_000).toISOString();
    writeFileSync(statusPath, JSON.stringify(cacheRecord), { mode: 0o600 });
    const staleStatus = runMcp(home, { MARROW_CLIENT: 'codex' }, mcpInput('marrow_status', {}));
    const staleMessages = staleStatus.stdout.trim().split('\n').map((line) => JSON.parse(line));
    const stalePayload = JSON.parse(staleMessages[2].result.content[0].text);
    assert.equal(stalePayload.status_freshness, 'stale');
    assert.equal(stalePayload.stale, true);
    assert.ok(stalePayload.control_path.current_ms < 100, `stale cached status handler took ${stalePayload.control_path.current_ms}ms`);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('neutral stdio MCP status reports on-demand capability without host-specific behavior', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-control-status-neutral-'));
  try {
    const mockPath = installControlFetchMock(home);
    const child = runMcp(home, {
      NODE_OPTIONS: `--require=${mockPath}`,
      MARROW_CLIENT: '',
    }, mcpInput('marrow_status', {}));
    assert.equal(child.status, 0, child.stderr);
    const messages = child.stdout.trim().split('\n').map((line) => JSON.parse(line));
    const payload = JSON.parse(messages[2].result.content[0].text);
    assert.equal(payload.host_capability.transport, 'mcp_stdio');
    assert.equal(payload.host_capability.host, 'mcp-client');
    assert.equal(payload.host_capability.tool_invocation, 'on_demand');
    assert.equal(payload.host_capability.passive_hooks.provided_by_mcp_transport, false);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('proof-pack validation remains a reachable proof requirement and never masquerades as an outage', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-proof-validation-'));
  const exactFix = 'Add the missing proof fields under proof (deployment_and_smoke, rollback_target) and retry /v1/agent/commit with the same gate_receipt_id.';
  try {
    const mockPath = installControlFetchMock(home);
    writeGuidanceCache({
      apiKey: 'fixture-control-path-key',
      baseUrl: 'https://127.0.0.1:9',
      agentId: 'agent-control-test',
      context: '## Marrow cached outage brief\n- This must not replace live proof validation.',
      home,
    });
    const child = runMcp(home, {
      NODE_OPTIONS: `--require=${mockPath}`,
      MARROW_TEST_PROOF_INCOMPLETE: '1',
      MARROW_CLIENT: 'grok',
      MARROW_REQUEST_TIMEOUT_MS: '1000',
    }, mcpInput('marrow_commit', {
      decision_id: 'decision-proof-required',
      success: true,
      outcome: 'Production deployment completed.',
      gate_receipt_id: 'gate-proof-required',
      proof: { summary: 'Deployment attempted.' },
    }));
    assert.equal(child.status, 0, child.stderr);
    const outputLines = child.stdout.trim().split('\n');
    assert.equal(outputLines.length, 3, JSON.stringify({ stdout: child.stdout, stderr: child.stderr, status: child.status, signal: child.signal }));
    const messages = outputLines.map((line) => JSON.parse(line));
    const payload = JSON.parse(messages[2].result.content[0].text);
    assert.equal(messages[2].result.isError, true);
    assert.equal(payload.ok, false);
    assert.equal(payload.available, true);
    assert.equal(payload.service_reachable, true);
    assert.equal(payload.failure_kind, 'validation');
    assert.equal(payload.validation_state, 'proof_required');
    assert.equal(payload.proof_required, true);
    assert.equal(payload.error.code, 'MARROW_PROOF_PACK_INCOMPLETE');
    assert.equal(payload.error.category, 'proof_required');
    assert.equal(payload.error.status, 409);
    assert.equal(payload.error.retryable, false);
    assert.deepEqual(payload.error.missing_fields, ['deployment_and_smoke', 'rollback_target']);
    assert.deepEqual(payload.missing_fields, ['deployment_and_smoke', 'rollback_target']);
    assert.equal(payload.error.exact_fix, exactFix);
    assert.equal(payload.exact_next_action, exactFix);
    assert.equal(payload.client_update.metadata_status, 'live_control_path_reached_version_unverified');
    assert.equal('stale_brief' in payload, false);
    assert.equal('stale_source' in payload, false);
    assert.equal('authorization_state' in payload, false);
    assert.equal('gate_obtained' in payload, false);
    assert.doesNotMatch(messages[2].result.content[0].text, /control-path outage brief|local_outage_safety|local_only_control_path_unavailable|authorization_state.*unavailable/i);
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
    assert.match(messages[0].result.instructions, /MCP tools are on demand/);
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
    risk_gate: { allow: true, decision: 'allow', enforced: true, enforcement_decision: 'allow' },
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

test('commit propagates a caller abort signal into the live request', async () => {
  const originalFetch = globalThis.fetch;
  let requestSignal;
  globalThis.fetch = async (_url, init = {}) => {
    requestSignal = init.signal;
    return new Promise((_resolve, reject) => {
      const abort = () => reject(requestSignal?.reason || new DOMException('Aborted', 'AbortError'));
      if (requestSignal?.aborted) abort();
      else requestSignal?.addEventListener('abort', abort, { once: true });
    });
  };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 25);
  try {
    await assert.rejects(
      () => marrowCommit('fixture-key', 'https://api.example.test', {
        decision_id: 'decision-signal',
        success: true,
        outcome: 'verified outcome',
        proof: { test: 'passed' },
        gate_receipt_id: 'gate-signal',
      }, 'session-signal', 'agent-signal', controller.signal),
      (error) => error instanceof MarrowRequestError && error.code === 'request_timeout',
    );
    assert.equal(requestSignal.aborted, true);
  } finally {
    clearTimeout(timer);
    globalThis.fetch = originalFetch;
  }
});

test('marrow_auto returns in-band commit confirmation only after forwarding supplied proof', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-auto-proof-'));
  try {
    const mockPath = installControlFetchMock(home);
    const child = runMcp(home, {
      NODE_OPTIONS: `--require=${mockPath}`,
      MARROW_TEST_FETCH_DELAY_MS: '0',
      // Keep the fixture deterministic under full-suite CPU load. The
      // cache-deadline regression is covered separately with no override.
      MARROW_REQUEST_TIMEOUT_MS: '1000',
    }, mcpInput('marrow_auto', {
      action: 'Update a local documentation note',
      outcome: 'Documentation check passed',
      success: true,
      proof: { test: 'passed' },
    }));
    assert.equal(child.status, 0, child.stderr);
    const messages = child.stdout.trim().split('\n').map((line) => JSON.parse(line));
    assert.equal(messages[2].result.isError, undefined, child.stdout);
    const payload = JSON.parse(messages[2].result.content[0].text);
    assert.equal(payload.decision_id, 'decision-auto', child.stdout);
    assert.equal(payload.live_delivery.accepted, true);
    assert.equal(payload.live_delivery.committed, true);
    assert.equal(payload.logging, 'governed_commit_confirmed');
    assert.equal(payload.completion_state, 'closed_with_proof');
    assert.equal(payload.receipt.accepted, true);
    assert.equal(payload.receipt.queued, false);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('marrowAuto preserves an explicit HTTP 200 committed false result', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    calls.push(String(url));
    if (String(url).endsWith('/v1/agent/think')) {
      return Response.json({ data: { decision_id: 'decision-not-closed' } });
    }
    return Response.json({ data: { committed: false } });
  };
  try {
    const result = await marrowAuto('fixture-key', 'https://api.example.test', {
      action: 'Update a local documentation note',
      outcome: 'Documentation check passed',
      success: true,
      proof: { test: 'passed' },
      gate_receipt_id: 'gate-not-closed',
    });
    assert.deepEqual(result, { decision_id: 'decision-not-closed', committed: false });
    assert.deepEqual(calls, [
      'https://api.example.test/v1/agent/think',
      'https://api.example.test/v1/agent/commit',
    ]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('marrowCommit rejects an HTTP 200 response missing committed with typed invalid_response', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({ data: { success: true } });
  try {
    await assert.rejects(
      () => marrowCommit('fixture-key', 'https://api.example.test', {
        decision_id: 'decision-missing-commit-state',
        success: true,
        outcome: 'Verification passed',
        proof: { test: 'passed' },
        gate_receipt_id: 'gate-missing-commit-state',
      }),
      (error) => error instanceof MarrowRequestError && error.code === 'invalid_response',
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('marrow_auto never closes or emits outcome_committed when HTTP 200 says committed false', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-auto-not-closed-'));
  try {
    const mockPath = installControlFetchMock(home);
    const child = runMcp(home, {
      NODE_OPTIONS: `--require=${mockPath}`,
      MARROW_TEST_COMMIT_STATE: 'false',
      MARROW_TEST_FORBID_OUTCOME_COMMITTED: '1',
      MARROW_REQUEST_TIMEOUT_MS: '1000',
    }, mcpInput('marrow_auto', {
      action: 'Update a local documentation note',
      outcome: 'Documentation check passed',
      success: true,
      proof: { test: 'passed' },
    }));
    assert.equal(child.status, 0, child.stderr);
    const messages = child.stdout.trim().split('\n').map((line) => JSON.parse(line));
    assert.equal(messages[2].result.isError, undefined, child.stdout);
    const text = messages[2].result.content[0].text;
    const payload = JSON.parse(text);
    assert.equal(payload.live_delivery.accepted, true);
    assert.equal(payload.live_delivery.committed, false);
    assert.equal(payload.logging, 'intent_confirmed');
    assert.equal(payload.completion_state, 'delivery_pending');
    assert.equal(payload.receipt.queued, false, 'fixture accepts only a non-outcome_committed lifecycle event');
    assert.doesNotMatch(text, /closed_with_proof|outcome_committed/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('marrow_auto treats an HTTP 200 missing committed as invalid and queues only the pending lifecycle receipt', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-auto-invalid-commit-'));
  try {
    const mockPath = installControlFetchMock(home);
    const child = runMcp(home, {
      NODE_OPTIONS: `--require=${mockPath}`,
      MARROW_TEST_COMMIT_STATE: 'missing',
      MARROW_TEST_LIFECYCLE_FAILURE: '1',
      MARROW_REQUEST_TIMEOUT_MS: '1000',
    }, mcpInput('marrow_auto', {
      action: 'Update a local documentation note',
      outcome: 'Documentation check passed',
      success: true,
      proof: { test: 'passed' },
    }));
    assert.equal(child.status, 0, child.stderr);
    const messages = child.stdout.trim().split('\n').map((line) => JSON.parse(line));
    assert.equal(messages[2].result.isError, undefined, child.stdout);
    const text = messages[2].result.content[0].text;
    const payload = JSON.parse(text);
    assert.equal(payload.live_delivery.accepted, false);
    assert.equal(payload.live_delivery.committed, false);
    assert.equal(payload.live_delivery.failure.error.code, 'invalid_response');
    assert.equal(payload.logging, 'durably_queued');
    assert.equal(payload.completion_state, 'delivery_pending');
    assert.equal(payload.receipt.queued, true);
    assert.doesNotMatch(text, /closed_with_proof|outcome_committed/);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('plan-gated handoff status is reported as entitlement rather than an API outage', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-handoff-plan-'));
  try {
    const mockPath = installControlFetchMock(home);
    const child = runMcp(home, {
      NODE_OPTIONS: `--require=${mockPath}`,
      MARROW_TEST_HANDOFF_PLAN: '1',
      MARROW_CLIENT: 'grok',
    }, mcpInput('marrow_handoff_status', {}));
    assert.equal(child.status, 0, child.stderr);
    const messages = child.stdout.trim().split('\n').map((line) => JSON.parse(line));
    const payload = JSON.parse(messages[2].result.content[0].text);
    assert.equal(messages[2].result.isError, undefined);
    assert.equal(payload.state, 'not_entitled');
    assert.equal(payload.failure_kind, 'entitlement');
    assert.equal(payload.authorization_state, 'plan_limited');
    assert.equal(payload.credential_valid, true);
    assert.equal(payload.current_plan, 'free');
    assert.equal(payload.required_plan, 'team');
    assert.equal(payload.required_feature, 'fleet_learning');
    assert.equal(payload.host_capability.host, 'grok');
    assert.equal(payload.host_capability.tool_invocation, 'on_demand');
    assert.equal(payload.host_capability.passive_hooks.provided_by_mcp_transport, false);
  } finally {
    rmSync(home, { recursive: true, force: true });
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
