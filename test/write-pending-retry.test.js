const test = require('node:test');
const assert = require('node:assert/strict');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const { MarrowRequestError, structuredRequestFailure } = require('../dist/request-reliability.js');
const { marrowThink, marrowCommit, writeReconciliationDelayMs } = require('../dist/index.js');
const {
  recordLifecycleEvent, lifecycleSpoolStatus, nudgeLifecycleSpool,
  claimBackgroundNudgeLock, releaseBackgroundNudgeLock,
} = require('../dist/lifecycle-spool.js');
const { runHookCommand } = require('../dist/hook.js');

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

test('lease_remaining_ms wins over the legacy retry_after_ms of 1000', async () => {
  process.env.MARROW_WRITE_RECONCILIATION_BUDGET_MS = '10000';
  const original = globalThis.fetch; const calls = [];
  globalThis.fetch = async (url, init) => {
    const call = record(url, init, Date.now()); calls.push(call);
    return calls.length === 1
      ? Response.json({ data: pendingBody(call.key, { retry_after_ms: 1000, lease_remaining_ms: 400 }) }, { status: 202 })
      : Response.json({ data: { decision_id: 'thinkdec_lease', idempotency_key: call.key } });
  };
  try {
    await marrowThink('fixture', 'https://fixture.test', { action: 'lease field' });
    const gap = calls[1].at - calls[0].at;
    assert.ok(gap >= 380 && gap < 900, `used lease field (${gap} ms)`);
  } finally { globalThis.fetch = original; }
});

test('invalid lease_remaining_ms falls back to retry_after_ms', async () => {
  process.env.MARROW_WRITE_RECONCILIATION_BUDGET_MS = '10000';
  const original = globalThis.fetch; const calls = [];
  globalThis.fetch = async (url, init) => {
    const call = record(url, init, Date.now()); calls.push(call);
    return calls.length === 1
      ? Response.json({ data: pendingBody(call.key, { retry_after_ms: 500, lease_remaining_ms: 'soon' }) }, { status: 202 })
      : Response.json({ data: { decision_id: 'thinkdec_fb', idempotency_key: call.key } });
  };
  try {
    await marrowThink('fixture', 'https://fixture.test', { action: 'bad lease field' });
    const gap = calls[1].at - calls[0].at;
    assert.ok(gap >= 480 && gap < 950, `used retry_after_ms (${gap} ms)`);
  } finally { globalThis.fetch = original; }
});

function withSpool(fn) {
  return async () => {
    const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-bg-'));
    const original = globalThis.fetch; const env = { ...process.env };
    process.env.MARROW_EVENT_SPOOL_PATH = join(directory, 'spool.json');
    try { await fn(directory); } finally {
      globalThis.fetch = original;
      for (const k of ['MARROW_EVENT_SPOOL_PATH', 'MARROW_API_KEY', 'MARROW_BASE_URL', 'MARROW_FLEET_AGENT_ID', 'MARROW_PASSIVE_TOKEN_USAGE']) {
        if (env[k] === undefined) delete process.env[k]; else process.env[k] = env[k];
      }
      rmSync(directory, { recursive: true, force: true });
    }
  };
}

test('PostToolUse returns immediately while the server is hung; background nudge delivers the spooled event later', withSpool(async () => {
  process.env.MARROW_PASSIVE_TOKEN_USAGE = 'false'; process.env.MARROW_API_KEY = 'mrw_post_tool_test_key'; process.env.MARROW_BASE_URL = 'https://api.example.test';
  let hung = true; const posted = [];
  globalThis.fetch = (url, init) => {
    if (!String(url).endsWith('/v1/agent/integrations/events')) return new Promise(() => {});
    if (hung) return new Promise(() => {});
    posted.push(JSON.parse(String(init.body)));
    return Promise.resolve(new Response('{}', { status: 200 }));
  };
  const started = Date.now();
  await runHookCommand({
    session_id: 'post-tool-fast', hook_event_name: 'PostToolUse', tool_name: 'Write',
    tool_input: { file_path: '/tmp/out.txt', content: 'x' }, tool_response: { ok: true }, tool_use_id: 'toolu_fast',
  });
  const elapsed = Date.now() - started;
  assert.ok(elapsed < 150, `hook returned in ${elapsed} ms with a hung server`);
  const before = lifecycleSpoolStatus({ apiKey: 'mrw_post_tool_test_key' });
  assert.equal(before.pending, 1, 'event is durably spooled');
  assert.equal(posted.length, 0);
  hung = false;
  await nudgeLifecycleSpool({ apiKey: 'mrw_post_tool_test_key', baseUrl: 'https://api.example.test' });
  assert.equal(posted.length, 1, 'background path delivered it');
  assert.equal(lifecycleSpoolStatus({ apiKey: 'mrw_post_tool_test_key' }).pending, 0);
}));

test('background delivery tolerates a 1.2 s acknowledgement that the 750 ms inline cap aborts', withSpool(async () => {
  const input = { apiKey: 'slow-ack-key', baseUrl: 'https://api.example.test' };
  let delay = 1200;
  globalThis.fetch = async () => { await new Promise((r) => setTimeout(r, delay)); return new Response('{}', { status: 200 }); };
  const event = { event_id: 'slow-ack', event_type: 'tool_completed', agent_id: 'agent-one', action: 'tool execution observed', outcome_state: 'pending', success: true };
  const inline = await recordLifecycleEvent({ ...input, event });
  assert.equal(inline.queued, true, 'inline 750 ms cap leaves it spooled');
  assert.equal(lifecycleSpoolStatus({ apiKey: input.apiKey, agentId: 'agent-one' }).retry.reasons.ack_timeout, 1);
  await new Promise((r) => setTimeout(r, 1100));
  await nudgeLifecycleSpool({ ...input, agentId: 'agent-one' });
  assert.equal(lifecycleSpoolStatus({ apiKey: input.apiKey, agentId: 'agent-one' }).pending, 0);
}));

test('inline delivery stays bounded and a timed-out event stays spooled', withSpool(async () => {
  globalThis.fetch = () => new Promise(() => {});
  const started = Date.now();
  const result = await recordLifecycleEvent({
    apiKey: 'hung-key', baseUrl: 'https://api.example.test',
    event: { event_id: 'hung-ack', event_type: 'tool_completed', agent_id: 'agent-one', action: 'tool execution observed', outcome_state: 'pending', success: true },
  });
  assert.ok(Date.now() - started < 1500);
  assert.equal(result.queued, true);
  assert.equal(lifecycleSpoolStatus({ apiKey: 'hung-key', agentId: 'agent-one' }).failed, 0);
}));

test('background nudge lock admits one launcher and recovers from a stale lock', withSpool(async () => {
  const input = { apiKey: 'lock-key', agentId: 'agent-one' };
  assert.equal(claimBackgroundNudgeLock(input), true);
  assert.equal(claimBackgroundNudgeLock(input), false);
  releaseBackgroundNudgeLock(input);
  assert.equal(claimBackgroundNudgeLock(input), true);
  const lock = `${process.env.MARROW_EVENT_SPOOL_PATH}.nudge.lock`;
  const old = new Date(Date.now() - 60_000);
  require('node:fs').utimesSync(lock, old, old);
  assert.equal(claimBackgroundNudgeLock(input), true, 'stale lock is reclaimed');
  releaseBackgroundNudgeLock(input);
}));
