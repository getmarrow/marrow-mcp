const test = require('node:test');
const assert = require('node:assert/strict');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const { MarrowRequestError, structuredRequestFailure } = require('../dist/request-reliability.js');
const { marrowThink, marrowCommit, writeReconciliationDelayMs } = require('../dist/index.js');
const { recordLifecycleEvent, lifecycleSpoolStatus } = require('../dist/lifecycle-spool.js');

const originalBudget = process.env.MARROW_WRITE_RECONCILIATION_BUDGET_MS;
test.after(() => {
  if (originalBudget === undefined) delete process.env.MARROW_WRITE_RECONCILIATION_BUDGET_MS;
  else process.env.MARROW_WRITE_RECONCILIATION_BUDGET_MS = originalBudget;
});

function pendingBody(key, extra = {}) {
  return {
    reconciliation_contract: 'agent_write_reconciliation.v1', reconciliation_operation: 'think',
    reconciliation_state: 'pending', decision_state: 'pending', committed: false, safe_to_continue: false,
    phase: 'think_pending', resumable: true, retryable: true, idempotency_key: key, ...extra,
  };
}

function record(url, init, at) {
  const headers = new Headers(init.headers);
  return { at, url: String(url), body: String(init.body), key: headers.get('Idempotency-Key') };
}

test('delay honors server retry_after_ms clamped to 250 ms..5 s', () => {
  assert.equal(writeReconciliationDelayMs(0, 0), 250);
  assert.equal(writeReconciliationDelayMs(0, 100), 250);
  assert.equal(writeReconciliationDelayMs(0, 1234), 1234);
  assert.equal(writeReconciliationDelayMs(3, 4999.2), 5000);
  assert.equal(writeReconciliationDelayMs(0, 60_000), 5000);
  assert.equal(writeReconciliationDelayMs(0, Number.MAX_VALUE), 5000);
});

test('without guidance delay is exponential with jitter inside fixed bounds', () => {
  for (let attempt = 0; attempt < 14; attempt += 1) {
    const ceiling = Math.min(5000, 250 * 2 ** Math.min(attempt, 10));
    const low = writeReconciliationDelayMs(attempt, null, () => 0);
    const high = writeReconciliationDelayMs(attempt, null, () => 0.999999);
    assert.ok(low >= 250 && low <= Math.max(250, Math.ceil(ceiling * 0.5)), `low ${attempt}: ${low}`);
    assert.ok(high <= ceiling && high >= low, `high ${attempt}: ${high}`);
    assert.ok(high <= 5000);
  }
  assert.ok(writeReconciliationDelayMs(4, null, () => 1) > writeReconciliationDelayMs(0, null, () => 1));
  assert.notEqual(writeReconciliationDelayMs(4, null, () => 0), writeReconciliationDelayMs(4, null, () => 1));
});

test('think honors a non-1000 retry_after_ms and resumes the same operation exactly once', async () => {
  process.env.MARROW_WRITE_RECONCILIATION_BUDGET_MS = '10000';
  const original = globalThis.fetch; const calls = [];
  globalThis.fetch = async (url, init) => {
    const call = record(url, init, Date.now()); calls.push(call);
    return calls.length < 3
      ? Response.json({ data: pendingBody(call.key, { retry_after_ms: 400 }) }, { status: 202 })
      : Response.json({ data: { decision_id: 'thinkdec_one', idempotency_key: call.key } });
  };
  try {
    const result = await marrowThink('fixture', 'https://fixture.test', { action: 'pending then done' });
    assert.equal(result.decision_id, 'thinkdec_one');
    assert.equal(calls.length, 3);
    assert.equal(new Set(calls.map((c) => c.key)).size, 1, 'same idempotency key');
    assert.equal(new Set(calls.map((c) => c.body)).size, 1, 'byte-identical request');
    for (let i = 1; i < calls.length; i += 1) {
      const gap = calls[i].at - calls[i - 1].at;
      assert.ok(gap >= 380, `waited for server guidance (${gap} ms)`);
      assert.ok(gap < 950, `did not fall back to the fixed 1 s delay (${gap} ms)`);
    }
  } finally { globalThis.fetch = original; }
});

test('the larger of body retry_after_ms and Retry-After header is used', async () => {
  process.env.MARROW_WRITE_RECONCILIATION_BUDGET_MS = '10000';
  const original = globalThis.fetch; const calls = [];
  globalThis.fetch = async (url, init) => {
    const call = record(url, init, Date.now()); calls.push(call);
    return calls.length === 1
      ? Response.json({ data: pendingBody(call.key, { retry_after_ms: 300 }) }, { status: 202, headers: { 'Retry-After': '1' } })
      : Response.json({ data: { decision_id: 'thinkdec_hdr', idempotency_key: call.key } });
  };
  try {
    await marrowThink('fixture', 'https://fixture.test', { action: 'header guidance' });
    assert.ok(calls[1].at - calls[0].at >= 980);
  } finally { globalThis.fetch = original; }
});

test('missing guidance uses jittered backoff, still the same key and body', async () => {
  process.env.MARROW_WRITE_RECONCILIATION_BUDGET_MS = '10000';
  const original = globalThis.fetch; const calls = [];
  globalThis.fetch = async (url, init) => {
    const call = record(url, init, Date.now()); calls.push(call);
    return calls.length < 3
      ? Response.json({ data: pendingBody(call.key) }, { status: 202 })
      : Response.json({ data: { decision_id: 'thinkdec_backoff', idempotency_key: call.key } });
  };
  try {
    const result = await marrowThink('fixture', 'https://fixture.test', { action: 'no guidance' });
    assert.equal(result.decision_id, 'thinkdec_backoff');
    assert.equal(calls.length, 3);
    assert.equal(new Set(calls.map((c) => c.key)).size, 1);
    assert.ok(calls[1].at - calls[0].at >= 240);
    assert.ok(calls[2].at - calls[1].at >= 240);
    assert.ok(calls[2].at - calls[0].at < 4000);
  } finally { globalThis.fetch = original; }
});

test('exhausted budget returns a resumable pending receipt without waiting past the budget or claiming success', async () => {
  process.env.MARROW_WRITE_RECONCILIATION_BUDGET_MS = '3000';
  const original = globalThis.fetch; const calls = [];
  let finish = false;
  globalThis.fetch = async (url, init) => {
    const call = record(url, init, Date.now()); calls.push(call);
    return finish
      ? Response.json({ data: { decision_id: 'thinkdec_resumed', idempotency_key: call.key } })
      : Response.json({ data: pendingBody(call.key, { retry_after_ms: 5000 }) }, { status: 202 });
  };
  try {
    const started = Date.now(); let receipt;
    await assert.rejects(() => marrowThink('fixture', 'https://fixture.test', { action: 'lease longer than budget' }), (error) => {
      assert.ok(error instanceof MarrowRequestError);
      assert.equal(error.backendCode, 'MCP_RECONCILIATION_EXHAUSTED');
      const shaped = structuredRequestFailure(error);
      assert.equal(shaped.ok, false);
      receipt = shaped.pending_receipt;
      assert.equal(receipt.contract, 'mcp_write_pending.v1');
      assert.equal(receipt.committed, false);
      assert.equal(receipt.safe_to_continue, false);
      assert.equal(receipt.idempotency_key, calls[0].key);
      assert.match(receipt.request_hash, /^[a-f0-9]{64}$/);
      assert.equal('decision_id' in receipt, false);
      return true;
    });
    assert.equal(calls.length, 1, 'no second operation and no wait that cannot fit');
    assert.ok(Date.now() - started < 1500);
    finish = true;
    const resumed = await marrowThink('fixture', 'https://fixture.test', { action: 'lease longer than budget' },
      undefined, undefined, undefined, { idempotencyKey: receipt.idempotency_key, requestHash: receipt.request_hash });
    assert.equal(resumed.decision_id, 'thinkdec_resumed');
    assert.equal(calls.length, 2);
    assert.equal(calls[1].key, calls[0].key);
    assert.equal(calls[1].body, calls[0].body);
  } finally { globalThis.fetch = original; }
});

test('commit also honors guidance and exhausts into a receipt rather than a new commit', async () => {
  process.env.MARROW_WRITE_RECONCILIATION_BUDGET_MS = '3000';
  const original = globalThis.fetch; const calls = [];
  globalThis.fetch = async (url, init) => {
    const call = record(url, init, Date.now()); calls.push(call);
    return Response.json({ data: {
      reconciliation_state: 'pending', retryable: true, committed: false, decision_id: 'thinkdec_c',
      idempotency_key: call.key, retry_after_ms: 5000,
    } }, { status: 202 });
  };
  try {
    await assert.rejects(() => marrowCommit('fixture', 'https://fixture.test', {
      decision_id: 'thinkdec_c', success: true, outcome: 'done',
    }), (error) => error instanceof MarrowRequestError && error.pendingReceipt?.operation === 'commit'
      && error.pendingReceipt.committed === false);
    assert.equal(calls.length, 1);
  } finally { globalThis.fetch = original; }
});

test('rejects malformed retry_after_ms and unknown pending shapes without retrying', async () => {
  process.env.MARROW_WRITE_RECONCILIATION_BUDGET_MS = '10000';
  for (const retryAfter of ['1000', -5, 'soon']) {
    const original = globalThis.fetch; let count = 0;
    globalThis.fetch = async (url, init) => {
      count += 1; const call = record(url, init, Date.now());
      return Response.json({ data: pendingBody(call.key, { retry_after_ms: retryAfter }) }, { status: 202 });
    };
    try {
      await assert.rejects(() => marrowThink('fixture', 'https://fixture.test', { action: 'bad guidance' }),
        (error) => error.backendCode === 'MCP_RECONCILIATION_INVALID');
      assert.equal(count, 1);
    } finally { globalThis.fetch = original; }
  }
});

test('passive lifecycle delivery tolerates a 1.2 s acknowledgement that the old 750 ms cap aborted', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-slow-ack-'));
  const original = globalThis.fetch; const originalPath = process.env.MARROW_EVENT_SPOOL_PATH;
  process.env.MARROW_EVENT_SPOOL_PATH = join(directory, 'spool.json');
  globalThis.fetch = async () => { await new Promise((r) => setTimeout(r, 1200)); return new Response('{}', { status: 200 }); };
  try {
    const result = await recordLifecycleEvent({
      apiKey: 'slow-ack-key', baseUrl: 'https://api.example.test',
      event: { event_id: 'slow-ack', event_type: 'tool_completed', agent_id: 'agent-one', action: 'tool execution observed', outcome_state: 'pending', success: true },
    });
    assert.equal(result.accepted, true);
    assert.equal(result.queued, false);
    assert.equal(lifecycleSpoolStatus({ apiKey: 'slow-ack-key', agentId: 'agent-one' }).pending, 0);
  } finally {
    globalThis.fetch = original;
    if (originalPath === undefined) delete process.env.MARROW_EVENT_SPOOL_PATH; else process.env.MARROW_EVENT_SPOOL_PATH = originalPath;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('a hook never waits beyond the bounded budget and the timed-out event stays spooled for retry', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-slow-hook-'));
  const original = globalThis.fetch; const originalPath = process.env.MARROW_EVENT_SPOOL_PATH;
  process.env.MARROW_EVENT_SPOOL_PATH = join(directory, 'spool.json');
  globalThis.fetch = () => new Promise(() => {});
  try {
    const started = Date.now();
    const result = await recordLifecycleEvent({
      apiKey: 'hung-key', baseUrl: 'https://api.example.test',
      event: { event_id: 'hung-ack', event_type: 'tool_completed', agent_id: 'agent-one', action: 'tool execution observed', outcome_state: 'pending', success: true },
    });
    const elapsed = Date.now() - started;
    assert.ok(elapsed >= 2100 && elapsed < 3000, `bounded at the delivery timeout (${elapsed} ms)`);
    assert.equal(result.accepted, false);
    assert.equal(result.queued, true);
    const status = lifecycleSpoolStatus({ apiKey: 'hung-key', agentId: 'agent-one' });
    assert.equal(status.pending, 1);
    assert.equal(status.failed, 0);
    assert.equal(status.retry.reasons.ack_timeout, 1);
  } finally {
    globalThis.fetch = original;
    if (originalPath === undefined) delete process.env.MARROW_EVENT_SPOOL_PATH; else process.env.MARROW_EVENT_SPOOL_PATH = originalPath;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('a hook with a tighter host deadline can lower the inline acknowledgement cap and keeps the event spooled', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-tight-hook-'));
  const original = globalThis.fetch; const originalPath = process.env.MARROW_EVENT_SPOOL_PATH;
  process.env.MARROW_EVENT_SPOOL_PATH = join(directory, 'spool.json');
  globalThis.fetch = () => new Promise(() => {});
  try {
    const started = Date.now();
    const result = await recordLifecycleEvent({
      apiKey: 'tight-key', baseUrl: 'https://api.example.test', deliveryTimeoutMs: 750,
      event: { event_id: 'tight-ack', event_type: 'session_completed', agent_id: 'agent-one', action: 'agent session ended', outcome_state: 'pending' },
    });
    const elapsed = Date.now() - started;
    assert.ok(elapsed >= 700 && elapsed < 1500, `bounded at 750 ms (${elapsed} ms)`);
    assert.equal(result.queued, true);
    assert.equal(lifecycleSpoolStatus({ apiKey: 'tight-key', agentId: 'agent-one' }).pending, 1);
  } finally {
    globalThis.fetch = original;
    if (originalPath === undefined) delete process.env.MARROW_EVENT_SPOOL_PATH; else process.env.MARROW_EVENT_SPOOL_PATH = originalPath;
    rmSync(directory, { recursive: true, force: true });
  }
});
