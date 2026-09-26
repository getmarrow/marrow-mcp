const assert = require('node:assert/strict');
const test = require('node:test');
const { marrowAuto } = require('../dist/index.js');

test('mock protocol cold/concurrent/idle/restart auto converges on one decision and outcome', async (t) => {
  const originalFetch = globalThis.fetch;
  const records = new Map();
  const counts = { think_requests: 0, commit_requests: 0, decisions: 0, outcomes: 0 };
  let lostThinkAck = true;
  let lostCommitAck = true;
  globalThis.fetch = async (url, init) => {
    const path = new URL(String(url)).pathname;
    const phase = path.endsWith('/think') ? 'think' : 'commit';
    counts[`${phase}_requests`] += 1;
    const key = new Headers(init.headers).get('Idempotency-Key');
    if (records.has(key)) {
      if (records.get(key).body !== init.body) return Response.json({
        error: 'Exact idempotency binding conflict', details: { code: 'IDEMPOTENCY_CONFLICT' },
      }, { status: 409 });
    } else {
      records.set(key, { body: init.body, result: phase === 'think'
        ? { decision_id: 'mock-exact-decision' } : { committed: true } });
      counts[phase === 'think' ? 'decisions' : 'outcomes'] += 1;
    }
    if (phase === 'think' && lostThinkAck) {
      lostThinkAck = false;
      throw new DOMException('Response lost after accepted think', 'AbortError');
    }
    if (phase === 'commit' && lostCommitAck) {
      lostCommitAck = false;
      throw new DOMException('Response lost after durable commit', 'AbortError');
    }
    return Response.json({ data: records.get(key).result });
  };
  const params = { action: 'Record a local fixture check', outcome: 'Fixture passed', success: true,
    operation_id: 'protocol_same_operation', proof: { checks: ['fixture'] } };
  const invoke = (fn, input = params) => fn('protocol-fixture-key', 'https://api.example.test', input,
    'protocol-session', 'protocol-agent', 8000);
  try {
    const concurrent = await Promise.all([invoke(marrowAuto), invoke(marrowAuto)]);
    assert.ok(concurrent.every((result) => result.committed && result.decision_id === 'mock-exact-decision'));
    const idle = await invoke(marrowAuto);
    assert.equal(idle.committed, true);
    delete require.cache[require.resolve('../dist/index.js')];
    const restarted = require('../dist/index.js').marrowAuto;
    const replay = await invoke(restarted);
    assert.equal(replay.committed, true);
    assert.equal(replay.decision_id, idle.decision_id);
    assert.equal(counts.decisions, 1);
    assert.equal(counts.outcomes, 1);
    assert.equal(records.size, 2);
    assert.equal(counts.think_requests, 4);
    assert.equal(counts.commit_requests, 5);
    await assert.rejects(invoke(restarted, { ...params, outcome: 'Conflicting outcome' }), (error) => error.status === 409);
    assert.equal(counts.outcomes, 1);
    t.diagnostic(JSON.stringify(counts));
  } finally { globalThis.fetch = originalFetch; }
});


test('canonical canary numeric UUID reaches Think and Commit and closes exactly one outcome', async () => {
  const originalFetch = globalThis.fetch;
  const operationId = 'auto_12345678-1234-4234-8234-123456789012';
  const requests = [];
  const records = new Map();
  globalThis.fetch = async (url, init) => {
    const phase = new URL(String(url)).pathname.endsWith('/think') ? 'think' : 'commit';
    const key = new Headers(init.headers).get('Idempotency-Key');
    requests.push({ phase, key });
    assert.equal(key, `mcp-auto:${operationId}:${phase}`);
    if (records.has(key)) assert.equal(records.get(key).body, init.body);
    else records.set(key, { body: init.body, result: phase === 'think'
      ? { decision_id: 'numeric-canary-decision' } : { committed: true } });
    return Response.json({ data: records.get(key).result });
  };
  try {
    const params = { operation_id: operationId, action: 'Record one bounded MCP control-path canary outcome',
      outcome: 'The MCP auto canary reached one committed outcome.', success: true,
      type: 'process', proof: { checks: ['mcp_auto_committed'] } };
    const invoke = () => marrowAuto('canary-fixture-key', 'https://api.example.test', params,
      'canary-fixture-session', 'canary-fixture-agent', 8000);
    const first = await invoke();
    assert.equal(first.phase, 'closed');
    assert.equal(first.committed, true);
    assert.equal(first.decision_id, 'numeric-canary-decision');
    assert.deepEqual(requests.map(({ phase }) => phase), ['think', 'commit']);
    const replay = await invoke();
    assert.equal(replay.phase, 'closed');
    assert.equal(replay.committed, true);
    assert.equal(replay.decision_id, first.decision_id);
    assert.equal(records.size, 2, 'one durable decision key and one durable outcome key');
  } finally { globalThis.fetch = originalFetch; }
});
