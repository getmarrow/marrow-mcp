const assert = require('node:assert/strict');
const test = require('node:test');

const { marrowAuto } = require('../dist/index.js');

test('marrowAuto returns bounded privacy-safe timing records for each write request', async () => {
  const originalFetch = globalThis.fetch;
  const secret = 'do-not-retain-this-action';
  globalThis.fetch = async (url) => {
    if (String(url).includes('/think')) {
      return Response.json({ data: {
        decision_id: 'decision-trace',
        timings_ms: { db_write: 4.4, secret: 999 },
      } }, { headers: { 'server-timing': 'edge;dur=2.5, secret;dur=999' } });
    }
    return Response.json({ data: {
      committed: true,
      replayed: true,
      performance_ms: { commit_write: 6.2, secret: 999 },
    } });
  };
  try {
    const result = await marrowAuto('fixture-key', 'https://api.example.test', {
      action: secret,
      outcome: 'verified',
      success: true,
      operation_id: 'trace-success-001',
    });
    assert.equal(result.http_attempt_trace.dropped_count, 0);
    assert.deepEqual(result.http_attempt_trace.attempts.map((row) => row.route_phase), ['think', 'commit']);
    assert.equal(result.http_attempt_trace.attempts[0].status, 200);
    assert.equal(result.http_attempt_trace.attempts[0].server_timings_ms['header.edge'], 3);
    assert.equal(result.http_attempt_trace.attempts[0].server_timings_ms['timings_ms.db_write'], 4);
    assert.equal(result.http_attempt_trace.attempts[1].replay_code, 'replayed');
    assert.equal(JSON.stringify(result.http_attempt_trace).includes(secret), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('marrowAuto identifies a stalled response body as the timed-out HTTP attempt', async () => {
  const originalFetch = globalThis.fetch;
  const keepEventLoopAlive = setTimeout(() => {}, 750);
  globalThis.fetch = async () => new Response(new ReadableStream({ start() {} }), {
    status: 200,
    headers: { 'content-type': 'application/json', 'server-timing': 'db;dur=8' },
  });
  try {
    const result = await marrowAuto('fixture-key', 'https://api.example.test', {
      action: 'bounded trace timeout',
      outcome: 'pending',
      success: false,
      operation_id: 'trace-timeout-001',
    }, undefined, undefined, 500);
    assert.equal(result.phase, 'think_pending');
    assert.equal(result.http_attempt_trace.attempts.length, 1);
    assert.deepEqual(result.http_attempt_trace.attempts[0], {
      route_phase: 'think',
      duration_ms: result.http_attempt_trace.attempts[0].duration_ms,
      status: 200,
      error_category: 'request_timeout',
      typed_timeout: true,
      pending_code: null,
      replay_code: null,
      server_timings_ms: { 'header.db': 8 },
      requested_wait_ms: 1_000,
      actual_wait_ms: 0,
    });
    assert.ok(result.http_attempt_trace.attempts[0].duration_ms >= 400);
  } finally {
    clearTimeout(keepEventLoopAlive);
    globalThis.fetch = originalFetch;
  }
});
