const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { spawnSync } = require('node:child_process');
const { readFileSync } = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');
const {
  CANARY_ASYNC_TOOL_TIMEOUT_MAX_MS,
  CANARY_DEFAULT_ASYNC_TOOL_TIMEOUT_MS,
  CANARY_DEFAULT_TOOL_TIMEOUT_MS,
  CANARY_DEFAULT_TOTAL_TIMEOUT_MS,
  CANARY_TOOL_TIMEOUT_MARGIN_MS,
  MARROW_AUTO_RESPONSE_BUDGET_MAX_MS,
  runCanary,
  serializeFailure,
} = require('../scripts/control-path-canary.cjs');

const tools = [
  'marrow_status', 'marrow_runtime_status', 'marrow_orient', 'marrow_ask',
  'marrow_agent_runtime', 'marrow_auto', 'marrow_first_value', 'marrow_buyer_proof',
  'marrow_governance_control_plane', 'marrow_value_report', 'marrow_fleet_lessons',
];

function payload(name) {
  if (name === 'marrow_status' || name === 'marrow_runtime_status') return { status: 'healthy' };
  if (name === 'marrow_orient') return { warnings: [], shouldPause: false };
  if (name === 'marrow_ask') return { answer: 'Proceed with verified evidence.' };
  if (name === 'marrow_agent_runtime') return { risk_gate: { allow: true, decision: 'proceed' }, proof_pack: { complete: true } };
  if (name === 'marrow_auto') return {
    decision_id: 'canary-decision',
    completion_state: 'closed_with_proof',
    phase: 'closed',
    resumable: false,
    live_delivery: { accepted: true, committed: true },
  };
  if (name === 'marrow_first_value') return { active: true, headline: 'Marrow active' };
  if (name === 'marrow_value_report') return { period: { days: 7 }, metrics: { decisions: { total: 1 } }, fleet: { active_agents: 1 } };
  return { result: 'available' };
}

function fakeSpawn(mode = 'good', timing = {}) {
  const state = { processCount: 0, killed: false, childEnv: null, calls: [], autoCalls: 0 };
  const factory = (_command, _args, spawnOptions = {}) => {
    state.processCount++;
    state.childEnv = spawnOptions.env || null;
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.stdout.setEncoding = () => {};
    child.closed = false;
    const finish = (code, signal = null) => {
      if (child.closed) return;
      child.closed = true;
      queueMicrotask(() => child.emit('exit', code, signal));
    };
    child.kill = () => {
      state.killed = true;
      finish(null, 'SIGKILL');
    };
    child.stdin = Object.assign(new EventEmitter(), {
      writable: true,
      write(line, callback) {
        const request = JSON.parse(line);
        state.calls.push(request);
        if (timing.handle?.(request, child, callback)) return;
        let response;
        if (request.method === 'initialize') {
          response = { jsonrpc: '2.0', id: request.id, result: { serverInfo: { version: 'test-version' } } };
        } else if (request.method === 'tools/list') {
          response = { jsonrpc: '2.0', id: request.id, result: { tools: tools.map((name) => ({ name })) } };
        } else if (mode === 'timeout') {
          if (callback) callback();
          return;
        } else if (mode === 'malformed') {
          setTimeout(() => child.stdout.emit('data', 'not-json\n'), 1);
          if (callback) callback();
          return;
        } else if (mode === 'wrong_id') {
          response = { jsonrpc: '2.0', id: request.id + 99, result: {} };
        } else if (mode === 'rpc_error') {
          response = { jsonrpc: '2.0', id: request.id, error: { code: -32000 } };
        } else {
          if (request.params?.name === 'marrow_auto') state.autoCalls += 1;
          const toolPayload = mode === 'auto_resume'
            && request.params?.name === 'marrow_auto'
            && state.autoCalls === 1
            ? {
                decision_id: 'canary-decision',
                completion_state: 'delivery_pending',
                phase: 'commit_pending',
                resumable: true,
                retry_after_ms: 0,
                live_delivery: { accepted: true, committed: false },
                http_attempt_trace: { attempts: [{
                  route_phase: 'commit', duration_ms: 240, status: 202,
                  error_category: null, typed_timeout: false, pending_code: 'commit_pending',
                  replay_code: null, server_timings_ms: { auth_ms: 210 },
                  server_timing_coverage: 'partial',
                  requested_wait_ms: 0, actual_wait_ms: 0,
                }], dropped_count: 0 },
              }
            : payload(request.params.name);
          response = {
            jsonrpc: '2.0',
            id: request.id,
            result: { content: [{ type: 'text', text: JSON.stringify(toolPayload) }] },
          };
        }
        const delay = request.method === 'initialize'
          ? timing.initializeDelayMs ?? 220
          : request.method === 'tools/call' && request.params?.name === 'marrow_auto'
          ? timing.autoDelayMs ?? 10
          : request.method === 'tools/call'
          ? 10
          : 0;
        setTimeout(() => child.stdout.emit('data', `${JSON.stringify(response)}\n`), delay);
        if (callback) callback();
      },
      end() {
        this.writable = false;
        finish(0);
      },
    });
    return child;
  };
  return { factory, state };
}

function environment() {
  return {
    MARROW_API_KEY: 'test-only-key',
    MARROW_EXPECTED_MCP_VERSION: 'test-version',
    MARROW_REQUEST_TIMEOUT_MS: '250',
    MARROW_MCP_CANARY_TOOL_TIMEOUT_MS: '250',
    MARROW_MCP_CANARY_TOTAL_TIMEOUT_MS: '5000',
  };
}

test('uses one persistent process and excludes startup from per-tool timings', async () => {
  const fake = fakeSpawn();
  const result = await runCanary(environment(), { spawnProcess: fake.factory });
  assert.equal(fake.state.processCount, 1);
  assert.equal(result.process_count, 1);
  assert.equal(result.initialization_ms >= 200, true);
  assert.equal(result.per_tool_latency_excludes_initialization, true);
  assert.equal(result.results.every((row) => row.latency_ms < 100), true);
  assert.equal(result.latency_groups.hot_path.count, 6);
  assert.equal(result.latency_groups.reports.count, 5);
  const autoCall = fake.state.calls.find((call) => call.params?.name === 'marrow_auto');
  assert.match(autoCall.params.arguments.operation_id, /^canary_[0-9a-f-]{36}$/);
});

test('retries a resumable auto phase with the same operation before accepting the canary', async () => {
  const fake = fakeSpawn('auto_resume');
  const result = await runCanary(environment(), { spawnProcess: fake.factory });
  assert.equal(result.ok, true);
  assert.equal(fake.state.autoCalls, 2);
  const autoCalls = fake.state.calls.filter((call) => call.params?.name === 'marrow_auto');
  assert.equal(autoCalls[0].params.arguments.operation_id, autoCalls[1].params.arguments.operation_id);
  const auto = result.results.find((row) => row.tool === 'marrow_auto');
  assert.equal(auto.auto_attempt_records.length, 2);
  assert.equal(auto.auto_attempt_records[0].phase, 'commit_pending');
  assert.equal(auto.auto_attempt_records[0].requested_wait_ms, 0);
  assert.ok(auto.auto_attempt_records[0].actual_wait_ms >= 0);
  assert.equal(auto.auto_attempt_records[0].http_attempt_trace.attempts[0].status, 202);
  assert.equal(auto.auto_attempt_records[1].status, 'committed');
});

test('canary retains only valid auto timing metrics and measured outer attempts', async () => {
  const fake = fakeSpawn('good', { initializeDelayMs: 0, handle: (request, child) => {
    if (request.params?.name !== 'marrow_auto') return false;
    return respond(child, request, { result: { content: [{ text: JSON.stringify({
      ...payload('marrow_auto'), action: secret, proof: { secret },
      phase_timings_ms: { runtime: null, think: 5, commit: 7, total: 12, secret },
      response_timings_ms: { core: 12, durable_enqueue: 4, full_response: 17, secret },
      http_attempt_trace: { attempts: Array.from({ length: 13 }, () => ({
        route_phase: 'think', duration_ms: 6, status: 200, error_category: null,
        typed_timeout: false, pending_code: null, replay_code: null,
        server_timings_ms: { auth_ms: 4, [secret]: 999 },
        server_timing_coverage: 'partial',
        requested_wait_ms: null, actual_wait_ms: 0,
      })), dropped_count: 0 },
      attempts: secret,
    }) }] } });
  } });
  const result = await runCanary(environment(), { spawnProcess: fake.factory });
  const auto = result.results.find((row) => row.tool === 'marrow_auto');
  assert.deepEqual(auto.phase_timings_ms, { think: 5, commit: 7, total: 12 });
  assert.deepEqual(auto.response_timings_ms, { core: 12, durable_enqueue: 4, full_response: 17 });
  assert.equal(auto.attempts, 1);
  assert.equal(auto.retry_wait_ms, 0);
  assert.equal(auto.auto_attempt_records[0].http_attempt_trace.attempts.length, 12);
  assert.equal(auto.auto_attempt_records[0].http_attempt_trace.dropped_count, 1);
  assert.equal(auto.auto_attempt_records[0].http_attempt_trace.attempts[0].server_timings_ms.auth_ms, 4);
  assert.equal(auto.auto_attempt_records[0].http_attempt_trace.attempts[0].server_timing_coverage, 'partial');
  assert.equal(JSON.stringify(result).includes(secret), false);
});

test('canary omits invalid optional numbers and preserves auto measurements on later failure', async () => {
  const { failure } = await captureFailure((request, child) => {
    if (request.params?.name === 'marrow_auto') return respond(child, request, { result: { content: [{ text: JSON.stringify({
      ...payload('marrow_auto'), phase_timings_ms: { runtime: Infinity, think: NaN, commit: -1, total: 60001 },
      response_timings_ms: { core: '12', durable_enqueue: null, full_response: 25 },
    }) }] } });
    if (request.params?.name === 'marrow_first_value') return respond(child, request, { result: { content: [{ text: '{}' }] } });
    return false;
  });
  const auto = failure.results.find((row) => row.tool === 'marrow_auto');
  assert.equal(auto.phase_timings_ms, undefined);
  assert.deepEqual(auto.response_timings_ms, { full_response: 25 });
  assert.equal(auto.attempts, 1);
  assert.equal(auto.retry_wait_ms, 0);
  assert.equal(auto.auto_attempt_records.length, 1);
  assert.equal(auto.auto_attempt_records[0].status, 'committed');
  assert.equal(failure.error_class, 'contract');
});

test('canary retains the timed-out inner HTTP attempt when marrow_auto delivery fails', async () => {
  const { failure } = await captureFailure((request, child) => request.params?.name === 'marrow_auto'
    && respond(child, request, { result: { content: [{ text: JSON.stringify({
      phase: null,
      resumable: false,
      live_delivery: { accepted: false, committed: false, failure: {
        ok: false, error: { category: 'request_timeout', status: null },
      } },
      http_attempt_trace: { attempts: [{
        route_phase: 'think', duration_ms: 4000, status: 200,
        error_category: 'request_timeout', typed_timeout: true,
        pending_code: null, replay_code: null,
        server_timings_ms: { account_123_ms: 3 },
        server_timing_coverage: 'partial',
        requested_wait_ms: 1000, actual_wait_ms: 0,
      }], dropped_count: 0 },
    }) }] } }));
  assert.equal(failure.error_class, 'request_timeout');
  assert.equal(failure.auto_attempt_records.length, 1);
  assert.equal(failure.auto_attempt_records[0].error_category, 'request_timeout');
  assert.equal(failure.auto_attempt_records[0].http_attempt_trace.attempts[0].typed_timeout, true);
  assert.equal(failure.auto_attempt_records[0].http_attempt_trace.attempts[0].status, 200);
  assert.equal(failure.auto_attempt_records[0].http_attempt_trace.attempts[0].server_timing_coverage, 'unavailable');
});

test('canary keeps malformed and contradictory auto states as contract failures', async () => {
  for (const invalid of [
    { resumable: true, live_delivery: { committed: false } },
    { phase: 'owner_approval_required', completion_state: 'pending_owner_approval', resumable: false,
      live_delivery: { accepted: true, committed: true } },
  ]) {
    const { failure, state } = await captureFailure((request, child) => request.params?.name === 'marrow_auto'
      && respond(child, request, { result: { content: [{ text: JSON.stringify(invalid) }] } }));
    assert.equal(failure.error_class, 'contract');
    assert.equal(failure.auto_phase, undefined);
    assert.equal(state.calls.filter((row) => row.params?.name === 'marrow_auto').length, 1);
  }
});

test('canary classifies actual CLI delivery failures without hiding HTTP authority or transport errors', async () => {
  for (const [category, status, expected] of [
    ['request_timeout', null, 'request_timeout'], ['authentication_required', null, 'authentication'],
    ['permission_denied', null, 'authorization'], ['proof_required', 409, 'proof_required'],
    ['proof_required', 401, 'authentication'], ['proof_required', 403, 'authorization'],
    ['proof_required', 503, 'unavailable503'], ['dns_unavailable', null, 'tool_unavailable'],
    ['invalid_response', null, 'contract'], ['arbitrary', null, 'contract'], ['toString', null, 'contract'],
  ]) {
    const { failure } = await captureFailure((request, child) => request.params?.name === 'marrow_auto'
      && respond(child, request, { result: { content: [{ text: JSON.stringify({
        phase: null, live_delivery: { accepted: false, committed: false, failure: {
          ok: false, error: { category, status, message: secret, code: category },
        } },
      }) }] } }));
    assert.equal(failure.error_class, expected, `${category}/${status}`);
    assert.equal(failure.auto_phase, undefined);
  }
  const { failure } = await captureFailure((request, child) => request.params?.name === 'marrow_auto'
    && respond(child, request, { result: { content: [{ text: JSON.stringify({
      ...payload('marrow_auto'), live_delivery: { committed: true, failure: {
        ok: false, error: { category: 'proof_required', status: 409 },
      } },
    }) }] } }));
  assert.equal(failure.error_class, 'contract');
});

for (const [phase, completion, classification] of [
  ['commit_pending', 'delivery_pending', 'completion_pending'],
  ['owner_approval_required', 'pending_owner_approval', 'approval_required'],
  ['review_required', 'review_required_terminal', 'approval_required'],
  ['proof_required', 'pending_required_proof', 'proof_required'],
]) {
  test(`canary classifies valid ${phase} without success or an outage claim`, async () => {
    const { failure, state } = await captureFailure((request, child) => request.params?.name === 'marrow_auto'
      && respond(child, request, { result: { content: [{ text: JSON.stringify({
        phase, completion_state: completion, resumable: phase === 'commit_pending', retry_after_ms: 900000,
        live_delivery: { accepted: true, committed: false },
        phase_timings_ms: { runtime: -1, think: 'secret', commit: 2, total: 3 },
        response_timings_ms: { core: 3, durable_enqueue: 1, full_response: 5 },
        decision_id: secret, exact_next_action: secret,
      }) }] } }));
    assert.equal(failure.ok, false);
    assert.equal(failure.error_class, classification);
    assert.equal(failure.auto_phase, phase);
    assert.deepEqual(failure.phase_timings_ms, { commit: 2, total: 3 });
    assert.equal(failure.response_timings_ms.full_response, 5);
    assert.equal(state.calls.filter((row) => row.params?.name === 'marrow_auto').length, 1);
  });
}

test('default canary tool timeout does not override the customer MCP request deadline', async () => {
  const fake = fakeSpawn();
  const env = environment();
  delete env.MARROW_REQUEST_TIMEOUT_MS;
  env.MARROW_MCP_CANARY_TOOL_TIMEOUT_MS = '2750';
  const result = await runCanary(env, { spawnProcess: fake.factory });
  assert.equal(result.ok, true);
  assert.equal(fake.state.childEnv.MARROW_REQUEST_TIMEOUT_MS, undefined);
  assert.equal(fake.state.childEnv.MARROW_MCP_CANARY_TOOL_TIMEOUT_MS, '2750');
});

test('default canary tool ceiling contains the maximum auto budget plus response margin', () => {
  assert.equal(MARROW_AUTO_RESPONSE_BUDGET_MAX_MS, 8_000);
  assert.equal(CANARY_TOOL_TIMEOUT_MARGIN_MS, 2_000);
  assert.equal(CANARY_DEFAULT_TOOL_TIMEOUT_MS, 10_000);
  assert.ok(
    CANARY_DEFAULT_TOOL_TIMEOUT_MS
      >= MARROW_AUTO_RESPONSE_BUDGET_MAX_MS + CANARY_TOOL_TIMEOUT_MARGIN_MS,
  );
});

test('default canary accepts one 6-8s auto invocation without a timeout override', async () => {
  const fake = fakeSpawn('good', { autoDelayMs: 6_100 });
  const env = environment();
  delete env.MARROW_REQUEST_TIMEOUT_MS;
  delete env.MARROW_MCP_CANARY_TOOL_TIMEOUT_MS;
  delete env.MARROW_MCP_CANARY_TOTAL_TIMEOUT_MS;
  const result = await runCanary(env, { spawnProcess: fake.factory });
  const auto = result.results.find((row) => row.tool === 'marrow_auto');
  assert.equal(result.ok, true);
  assert.equal(fake.state.autoCalls, 1);
  assert.ok(auto.latency_ms >= 6_000 && auto.latency_ms < 8_000, `unexpected auto latency ${auto.latency_ms}ms`);
});

for (const [mode, pattern] of [
  ['wrong_id', /unexpected response id/],
  ['malformed', /malformed JSON/],
  ['rpc_error', /JSON-RPC error/],
  ['timeout', /timed out/],
]) {
  test(`${mode} response fails closed and terminates the child`, async () => {
    const fake = fakeSpawn(mode);
    await assert.rejects(runCanary(environment(), { spawnProcess: fake.factory }), pattern);
    assert.equal(fake.state.processCount, 1);
    if (mode === 'timeout' || mode === 'wrong_id' || mode === 'malformed') {
      assert.equal(fake.state.killed, true);
    }
  });
}

test('failure retains safe structured evidence', async () => {
  const fake = fakeSpawn('timeout');
  await assert.rejects(runCanary(environment(), { spawnProcess: fake.factory }), (error) => {
    assert.equal(error.failure?.ok, false);
    assert.equal(error.failure.stage, 'tool_call');
    assert.equal(error.failure.tool, 'marrow_status');
    assert.equal(error.failure.error_class, 'request_timeout');
    assert.equal(error.failure.attempt, 1);
    assert.deepEqual(error.failure.results, []);
    assert.deepEqual(JSON.parse(serializeFailure(error)), error.failure);
    return true;
  });
});

const secret = 'SECRET-private-key-customer-identity-prompt';
async function captureFailure(handle, overrides = {}, spawnProcess) {
  const fake = fakeSpawn('good', { initializeDelayMs: 0, handle });
  let failure;
  await assert.rejects(runCanary({ ...environment(), ...overrides }, {
    spawnProcess: spawnProcess || fake.factory,
  }), (error) => {
    failure = error.failure;
    assert.deepEqual(JSON.parse(serializeFailure(error)), failure);
    assert.equal(serializeFailure(error).includes(secret), false);
    assert.ok(Buffer.byteLength(serializeFailure(error)) < 4096);
    assert.ok(Number.isFinite(failure.latency_ms) && failure.latency_ms >= 0 && failure.latency_ms <= 60000);
    assert.ok(Number.isFinite(failure.total_latency_ms) && failure.total_latency_ms >= 0 && failure.total_latency_ms <= 60000);
    assert.ok(failure.results.length <= 11);
    return true;
  });
  return { failure, state: fake.state };
}

function respond(child, request, body) {
  queueMicrotask(() => child.stdout.emit('data', `${JSON.stringify({ jsonrpc: '2.0', id: request.id, ...body })}\n`));
  return true;
}

test('success retains all eleven live assertions in order', async () => {
  const fake = fakeSpawn('good', { initializeDelayMs: 0 });
  const result = await runCanary(environment(), { spawnProcess: fake.factory });
  assert.equal(result.tools_checked, 11);
  assert.deepEqual(result.results.map((row) => row.tool), tools);
  assert.ok(result.results.every((row) => row.ok && row.live));
});

test('terminal malformed output after the final response rejects with active tool evidence', async () => {
  const { failure, state } = await captureFailure((request, child, callback) => {
    if (request.params?.name !== 'marrow_fleet_lessons') return false;
    const response = { jsonrpc: '2.0', id: request.id,
      result: { content: [{ text: JSON.stringify(payload(request.params.name)) }] } };
    queueMicrotask(() => child.stdout.emit('data', `${JSON.stringify(response)}\nnot-json\n`));
    callback?.();
    return true;
  });
  assert.equal(failure.error_class, 'protocol');
  assert.equal(failure.stage, 'tool_call');
  assert.equal(failure.tool, 'marrow_fleet_lessons');
  assert.equal(failure.attempt, 1);
  assert.deepEqual(failure.results.map((row) => row.tool), tools.slice(0, 10));
  assert.equal(failure.tools_checked, 10);
  assert.equal(state.killed, true);
});

test('terminal asynchronous stdin error during shutdown rejects with completed partial rows', async () => {
  const { failure, state } = await captureFailure((request, child) => {
    if (request.method === 'initialize') {
      const end = child.stdin.end.bind(child.stdin);
      child.stdin.end = () => {
        queueMicrotask(() => child.stdin.emit('error', new Error(secret)));
        end();
      };
    }
    return false;
  });
  assert.equal(failure.error_class, 'process_write');
  assert.equal(failure.stage, 'shutdown');
  assert.equal(failure.tool, null);
  assert.equal(failure.attempt, 0);
  assert.deepEqual(failure.results.map((row) => row.tool), tools);
  assert.equal(failure.tools_checked, 11);
  assert.equal(state.killed, true);
});

test('parent-requested bounded shutdown cleanup preserves an eleven-tool success', async () => {
  const fake = fakeSpawn('good', { initializeDelayMs: 0, handle(request, child) {
    if (request.method === 'initialize') child.stdin.end = () => { child.stdin.writable = false; };
    return false;
  } });
  const result = await runCanary(environment(), { spawnProcess: fake.factory });
  assert.equal(result.ok, true);
  assert.equal(result.tools_checked, 11);
  assert.deepEqual(result.results.map((row) => row.tool), tools);
  assert.equal(fake.state.killed, true);
});

test('parent-requested cleanup does not hide an asynchronous write error', async () => {
  const { failure } = await captureFailure((request, child) => {
    if (request.method === 'initialize') {
      child.stdin.end = () => { child.stdin.writable = false; };
      const kill = child.kill.bind(child);
      child.kill = () => {
        queueMicrotask(() => child.stdin.emit('error', new Error(secret)));
        kill();
      };
    }
    return false;
  });
  assert.equal(failure.error_class, 'process_write');
  assert.equal(failure.stage, 'shutdown');
  assert.equal(failure.tools_checked, 11);
});

for (const mode of ['timeout', 'exit', 'write_callback', 'write_throw', 'stdin_error']) {
  test(`partial results preserve the active failed tool on ${mode}`, async () => {
    const { failure } = await captureFailure((request, child, callback) => {
      if (request.params?.name !== 'marrow_ask') return false;
      if (mode === 'exit') queueMicrotask(() => child.emit('exit', 17, secret));
      if (mode === 'write_callback') callback(new Error(secret));
      if (mode === 'write_throw') throw new Error(secret);
      if (mode === 'stdin_error') queueMicrotask(() => child.stdin.emit('error', new Error(secret)));
      return true;
    });
    assert.equal(failure.stage, 'tool_call');
    assert.equal(failure.tool, 'marrow_ask');
    assert.equal(failure.attempt, 1);
    assert.equal(failure.error_class, mode === 'timeout' ? 'request_timeout' : mode === 'exit' ? 'process_exit' : 'process_write');
    assert.deepEqual(failure.results.map((row) => row.tool), tools.slice(0, 3));
    assert.equal(failure.tools_checked, 3);
    assert.equal(Object.hasOwn(failure, 'http_status'), false);
  });
}

test('total timeout identifies the active request and retains partial rows', async () => {
  const { failure } = await captureFailure((request) => request.params?.name === 'marrow_auto', {
    MARROW_MCP_CANARY_TOOL_TIMEOUT_MS: '10000', MARROW_MCP_CANARY_TOTAL_TIMEOUT_MS: '2000',
  });
  assert.equal(failure.error_class, 'total_timeout');
  assert.equal(failure.tool, 'marrow_auto');
  assert.equal(failure.stage, 'tool_call');
  assert.equal(failure.results.length, 5);
});

for (const body of [null, [], 'bad', { jsonrpc: '2.0', id: 3 }, { jsonrpc: 'wrong', id: 3, result: {} }]) {
  test(`malformed RPC structure ${JSON.stringify(body)} is bounded protocol failure`, async () => {
    const { failure } = await captureFailure((request, child) => {
      if (request.method !== 'tools/call') return false;
      queueMicrotask(() => child.stdout.emit('data', `${JSON.stringify(body)}\n`));
      return true;
    });
    assert.equal(failure.error_class, 'protocol');
  });
}

for (const [label, body, expected, status] of [
  ['invalid JSON', { content: [{ text: secret }] }, 'contract'],
  ['empty JSON', { content: [{ text: '{}' }] }, 'contract'],
  ['invalid status contract', { content: [{ text: JSON.stringify({ answer: secret }) }] }, 'contract'],
  ['stale guidance', { content: [{ text: JSON.stringify({ status: 'healthy', stale: true }) }] }, 'contract'],
  ['last known guidance', { content: [{ text: JSON.stringify({ status: 'healthy', source: 'last_known' }) }] }, 'contract'],
  ...[
    ['auth', { ok: false, error: { code: 'INVALID_API_KEY', message: secret } }, 'authentication'],
    ['forbidden', { ok: false, error: { status: 403, message: secret } }, 'authorization', 403],
    ['503', { available: false, error: { status: 503, code: secret } }, 'unavailable503', 503],
    ['arbitrary error', { ok: false, error: { code: secret, message: 'HTTP 503' } }, 'tool_unavailable'],
    ['string status', { ok: false, error: { status: '503', code: secret } }, 'tool_unavailable'],
    ['invalid status', { ok: false, http_status: 999999, error_code: secret }, 'tool_unavailable'],
  ].map(([label, body, expected, status]) => [label, { content: [{ text: JSON.stringify(body) }] }, expected, status]),
]) {
  test(`tool ${label} has a safe explicit classification`, async () => {
    const { failure } = await captureFailure((request, child) => request.method === 'tools/call' && respond(child, request, { result: body }));
    assert.equal(failure.error_class, expected);
    assert.equal(failure.stage, 'tool_validate');
    assert.equal(failure.tool, 'marrow_status');
    assert.equal(failure.http_status, status);
    assert.equal(Object.hasOwn(failure, 'http_status'), status !== undefined);
  });
}

for (const [body, expected, version] of [
  [{ result: {} }, 'contract', null],
  [{ result: { serverInfo: { version: secret } } }, 'package_mismatch', null],
  [{ result: { serverInfo: { version: '3.9.81' } } }, 'package_mismatch', '3.9.81'],
  [{ error: { code: 'UNAUTHORIZED', message: secret } }, 'authentication', null],
  [{ error: { status: 503, message: secret } }, 'unavailable503', null],
]) {
  test(`initialize ${expected} does not invent a tool or expose version strings`, async () => {
    const { failure } = await captureFailure((request, child) => respond(child, request, body), {
      MARROW_EXPECTED_MCP_VERSION: '3.9.80',
    });
    assert.equal(failure.stage, 'initialize');
    assert.equal(failure.tool, null);
    assert.equal(failure.error_class, expected);
    assert.equal(failure.package_version, version);
    assert.equal(failure.expected_version, '3.9.80');
  });
}

test('missing full-profile tool is a hard contract failure without call attribution', async () => {
  const { failure } = await captureFailure((request, child) => request.method === 'tools/list'
    && respond(child, request, { result: { tools: [{ name: secret }] } }));
  assert.equal(failure.stage, 'tools_list');
  assert.equal(failure.error_class, 'contract');
  assert.equal(failure.tool, null);
});

for (const mode of ['throw', 'error']) {
  test(`spawn ${mode} produces no fabricated tool or HTTP status`, async () => {
    const { failure } = await captureFailure(null, {}, mode === 'throw' ? () => { throw new Error(secret); } : (...args) => {
      const child = fakeSpawn('good', { initializeDelayMs: 0 }).factory(...args);
      queueMicrotask(() => child.emit('error', Object.assign(new Error(secret), { code: secret })));
      return child;
    });
    assert.equal(failure.error_class, 'process_spawn');
    assert.equal(failure.tool, null);
    assert.equal(failure.http_status, undefined);
    assert.equal(failure.package_version, null);
  });
}

for (const stream of ['stdout', 'stderr']) {
  test(`${stream} flood produces bounded evidence without retaining bytes`, async () => {
    const { failure } = await captureFailure((request, child) => {
      if (request.method !== 'tools/call') return false;
      queueMicrotask(() => child[stream].emit('data', secret.repeat(10000)));
      return true;
    });
    assert.equal(failure.error_class, 'output_limit');
  });
}

test('uncommitted resumable auto remains bounded at three attempts', async () => {
  const { failure, state } = await captureFailure((request, child) => request.params?.name === 'marrow_auto'
    && respond(child, request, { result: { content: [{ text: JSON.stringify({
      phase: 'commit_pending', completion_state: 'delivery_pending', resumable: true, retry_after_ms: 0,
      live_delivery: { accepted: true, committed: false },
    }) }] } }));
  assert.equal(failure.error_class, 'completion_pending');
  assert.equal(failure.tool, 'marrow_auto');
  assert.equal(failure.attempt, 3);
  assert.equal(state.calls.filter((request) => request.params?.name === 'marrow_auto').length, 3);
});

test('serializer ignores forged error fields and arbitrary strings', () => {
  const error = Object.assign(new Error(secret), { failure: { tool: secret, error_class: secret, results: [secret] } });
  assert.equal(serializeFailure(error).includes(secret), false);
  assert.equal(JSON.parse(serializeFailure(error)).error_class, 'internal');
});

test('CLI missing authentication emits exactly one JSON record and constant stderr with exit 1', () => {
  const env = { ...process.env, MARROW_API_KEY: '', MARROW_EXPECTED_MCP_VERSION: secret };
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, ['scripts/control-path-canary.cjs'], { cwd: require('node:path').resolve(__dirname, '..'), env, encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.equal(result.stderr, 'MCP_CONTROL_PATH_CANARY=FAIL\n');
  assert.equal(result.stdout.trim().split('\n').length, 1);
  const failure = JSON.parse(result.stdout);
  assert.equal(failure.error_class, 'authentication');
  assert.equal(failure.stage, 'setup');
  assert.equal(failure.process_count, 0);
  assert.equal(failure.tool, null);
  assert.equal(failure.expected_version, null);
  assert.equal(result.stdout.includes(secret), false);
});

test('missing compiled dependency still reaches the CLI JSON handler', async () => {
  const output = { stdout: '', stderr: '' };
  const module = { exports: {} };
  const localRequire = (name) => {
    if (name === '../dist/index.js') throw new Error(secret);
    if (name === '../package.json') return { version: '3.9.80' };
    return require(name);
  };
  localRequire.main = module;
  const mockProcess = { env: {}, stdout: { write: (value) => { output.stdout += value; } }, stderr: { write: (value) => { output.stderr += value; } } };
  vm.runInNewContext(readFileSync(require.resolve('../scripts/control-path-canary.cjs'), 'utf8'), {
    require: localRequire, module, process: mockProcess, __dirname, setTimeout, clearTimeout, Buffer,
  });
  await new Promise(setImmediate);
  assert.equal(mockProcess.exitCode, 1);
  assert.equal(JSON.parse(output.stdout).error_class, 'configuration');
  assert.equal(output.stderr, 'MCP_CONTROL_PATH_CANARY=FAIL\n');
  assert.equal(output.stdout.includes(secret), false);
});

test('default async tool ceiling and total budget match the published canary contract', () => {
  assert.equal(CANARY_ASYNC_TOOL_TIMEOUT_MAX_MS, 30_000);
  assert.equal(CANARY_DEFAULT_ASYNC_TOOL_TIMEOUT_MS, 10_000);
  assert.equal(CANARY_DEFAULT_ASYNC_TOOL_TIMEOUT_MS, Math.min(
    CANARY_ASYNC_TOOL_TIMEOUT_MAX_MS,
    MARROW_AUTO_RESPONSE_BUDGET_MAX_MS + CANARY_TOOL_TIMEOUT_MARGIN_MS,
  ));
  assert.equal(CANARY_DEFAULT_TOTAL_TIMEOUT_MS, 45_000);
});

test('async ceiling lets marrow_auto outlast the minimum regular tool timeout by default', async () => {
  const fake = fakeSpawn('good', { initializeDelayMs: 0, autoDelayMs: 400 });
  const result = await runCanary(environment(), { spawnProcess: fake.factory });
  assert.equal(result.ok, true);
  const auto = result.results.find((row) => row.tool === 'marrow_auto');
  assert.ok(auto.latency_ms >= 400, `unexpected auto latency ${auto.latency_ms}ms`);
});

test('async ceiling bounds a hanging marrow_auto without retrying the timeout', async () => {
  const { failure, state } = await captureFailure((request, child, callback) => {
    if (request.params?.name !== 'marrow_auto') return false;
    if (callback) callback();
    return true;
  }, { MARROW_MCP_CANARY_ASYNC_TOOL_TIMEOUT_MS: '300' });
  assert.equal(failure.error_class, 'request_timeout');
  assert.equal(failure.tool, 'marrow_auto');
  assert.equal(failure.attempt, 1);
  assert.equal(failure.auto_attempt_records.length, 1);
  assert.equal(failure.auto_attempt_records[0].error_category, 'request_timeout');
  assert.equal(state.killed, true);
});

test('async ceiling does not extend regular tools past the tool timeout', async () => {
  const { failure } = await captureFailure((request, child) => {
    if (request.params?.name !== 'marrow_ask') return false;
    setTimeout(() => respond(child, request, {
      result: { content: [{ text: JSON.stringify(payload('marrow_ask')) }] },
    }), 400);
    return true;
  }, { MARROW_MCP_CANARY_ASYNC_TOOL_TIMEOUT_MS: '5000' });
  assert.equal(failure.error_class, 'request_timeout');
  assert.equal(failure.tool, 'marrow_ask');
  assert.equal(failure.attempt, 1);
});

test('async ceiling above the 30s maximum clamps before the default 45s total budget', { timeout: 60_000 }, async () => {
  const { failure } = await captureFailure((request, child, callback) => {
    if (request.params?.name !== 'marrow_auto') return false;
    if (callback) callback();
    return true;
  }, {
    MARROW_MCP_CANARY_ASYNC_TOOL_TIMEOUT_MS: '60000',
    MARROW_MCP_CANARY_TOTAL_TIMEOUT_MS: undefined,
  });
  assert.equal(failure.error_class, 'request_timeout');
  assert.equal(failure.tool, 'marrow_auto');
  assert.ok(failure.latency_ms >= 29_000, `async ceiling fired at ${failure.latency_ms}ms`);
  assert.ok(failure.total_latency_ms < 45_000, `total budget fired at ${failure.total_latency_ms}ms`);
});

test('one transport-class failure retries in-run and annotates recovered_on_retry', async () => {
  let statusCalls = 0;
  const fake = fakeSpawn('good', { initializeDelayMs: 0, handle: (request, child) => {
    if (request.params?.name !== 'marrow_status') return false;
    statusCalls += 1;
    if (statusCalls > 1) return false;
    return respond(child, request, { result: { content: [{ text: JSON.stringify({
      ok: false, error: { code: 'edge_reset', message: secret },
    }) }] } });
  } });
  const result = await runCanary(environment(), { spawnProcess: fake.factory });
  assert.equal(result.ok, true);
  assert.equal(statusCalls, 2);
  const row = result.results.find((entry) => entry.tool === 'marrow_status');
  assert.equal(row.recovered_on_retry, true);
  assert.deepEqual(result.results.filter((entry) => entry.recovered_on_retry).map((entry) => entry.tool), ['marrow_status']);
  assert.equal(JSON.stringify(result).includes(secret), false);
});

test('non-transport tool failure does not trigger the in-run retry', async () => {
  const { failure, state } = await captureFailure((request, child) => request.params?.name === 'marrow_status'
    && respond(child, request, { result: { content: [{ text: '{}' }] } }));
  assert.equal(failure.error_class, 'contract');
  assert.equal(failure.stage, 'tool_validate');
  assert.equal(failure.tool, 'marrow_status');
  assert.equal(failure.attempt, 1);
  assert.equal(state.calls.filter((call) => call.params?.name === 'marrow_status').length, 1);
});

test('a persistent transport failure exhausts the single retry and still fails', async () => {
  const { failure, state } = await captureFailure((request, child) => request.params?.name === 'marrow_status'
    && respond(child, request, { result: { content: [{ text: JSON.stringify({
      available: false, error: { status: 503 },
    }) }] } }));
  assert.equal(failure.error_class, 'unavailable503');
  assert.equal(failure.tool, 'marrow_status');
  assert.equal(failure.attempt, 2);
  assert.equal(failure.http_status, 503);
  assert.equal(state.calls.filter((call) => call.params?.name === 'marrow_status').length, 2);
  assert.ok(failure.total_latency_ms >= 1_000, `retry wait was ${failure.total_latency_ms}ms`);
});
