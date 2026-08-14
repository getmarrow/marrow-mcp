const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const test = require('node:test');
const { runCanary } = require('../scripts/control-path-canary.cjs');

const tools = [
  'marrow_status', 'marrow_runtime_status', 'marrow_orient', 'marrow_ask',
  'marrow_agent_runtime', 'marrow_first_value', 'marrow_buyer_proof',
  'marrow_governance_control_plane', 'marrow_value_report', 'marrow_fleet_lessons',
];

function payload(name) {
  if (name === 'marrow_status' || name === 'marrow_runtime_status') return { status: 'healthy' };
  if (name === 'marrow_orient') return { warnings: [], shouldPause: false };
  if (name === 'marrow_ask') return { answer: 'Proceed with verified evidence.' };
  if (name === 'marrow_agent_runtime') return { risk_gate: { allow: true, decision: 'proceed' }, proof_pack: { complete: true } };
  if (name === 'marrow_first_value') return { active: true, headline: 'Marrow active' };
  if (name === 'marrow_value_report') return { period: { days: 7 }, metrics: { decisions: { total: 1 } }, fleet: { active_agents: 1 } };
  return { result: 'available' };
}

function fakeSpawn(mode = 'good') {
  const state = { processCount: 0, killed: false };
  const factory = () => {
    state.processCount++;
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
    child.stdin = {
      writable: true,
      write(line, callback) {
        const request = JSON.parse(line);
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
          response = {
            jsonrpc: '2.0',
            id: request.id,
            result: { content: [{ type: 'text', text: JSON.stringify(payload(request.params.name)) }] },
          };
        }
        const delay = request.method === 'initialize' ? 220 : request.method === 'tools/call' ? 10 : 0;
        setTimeout(() => child.stdout.emit('data', `${JSON.stringify(response)}\n`), delay);
        if (callback) callback();
      },
      end() {
        this.writable = false;
        finish(0);
      },
    };
    return child;
  };
  return { factory, state };
}

function environment() {
  return {
    MARROW_API_KEY: 'test-only-key',
    MARROW_EXPECTED_MCP_VERSION: 'test-version',
    MARROW_REQUEST_TIMEOUT_MS: '250',
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
  assert.equal(result.latency_groups.hot_path.count, 5);
  assert.equal(result.latency_groups.reports.count, 5);
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
