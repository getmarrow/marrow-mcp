const assert = require('node:assert/strict');
const test = require('node:test');
const { marrowAuto } = require('../dist/index.js');

for (const phase of ['think', 'commit']) {
  test(`auto honors 1000ms ${phase} continuation with stable request identity`, async () => {
    const originalFetch = globalThis.fetch;
    const calls = [];
    globalThis.fetch = async (url, init) => {
      const path = new URL(String(url)).pathname;
      const target = path.endsWith(`/v1/agent/${phase}`);
      if (target) calls.push({ at: Date.now(), body: init.body, key: new Headers(init.headers).get('Idempotency-Key') });
      if (target && calls.length === 1) return Response.json({ data: {
        phase: `${phase}_pending`, resumable: true, retry_after_ms: 1000,
      } }, { status: 202 });
      return Response.json({ data: path.endsWith('/think') ? { decision_id: `pacing-${phase}` } : { committed: true } });
    };
    try {
      const result = await marrowAuto('pacing-key', 'https://api.example.test', {
        action: `record ${phase} pacing`, outcome: 'done', success: true, operation_id: `pacing_1000_${phase}`,
      }, undefined, undefined, 8000);
      assert.equal(result.committed, true);
      assert.equal(calls.length, 2);
      assert.ok(calls[1].at - calls[0].at >= 1000, 'must not retry before server guidance');
      assert.equal(calls[0].body, calls[1].body);
      assert.equal(calls[0].key, calls[1].key);
    } finally { globalThis.fetch = originalFetch; }
  });

  for (const retryAfter of [1000, Number.MAX_VALUE]) {
    test(`auto returns ${phase} pending when ${retryAfter}ms cannot fit`, async () => {
      const originalFetch = globalThis.fetch;
      let attempts = 0;
      globalThis.fetch = async (url) => {
        if (phase === 'commit' && new URL(String(url)).pathname.endsWith('/think')) return Response.json({ data: { decision_id: 'pacing-cannot-fit' } });
        attempts += 1;
        return Response.json({ data: { phase: `${phase}_pending`, resumable: true, retry_after_ms: retryAfter } }, { status: 202 });
      };
      try {
        const operationId = `pacing_no_fit_${phase}_${retryAfter === 1000 ? 'small' : 'huge'}`;
        const started = Date.now();
        const result = await marrowAuto('pacing-key', 'https://api.example.test', {
          action: 'record bounded pending', outcome: 'pending', success: true, operation_id: operationId,
        }, undefined, undefined, 500);
        assert.equal(result.operation_id, operationId);
        assert.equal(result.phase, `${phase}_pending`);
        assert.equal(result.resumable, true);
        assert.equal(result.committed, false);
        assert.equal(result.retry_after_ms, retryAfter);
        assert.equal(attempts, 1);
        assert.ok(Date.now() - started < 350, 'cannot-fit guidance must return without a partial wait');
      } finally { globalThis.fetch = originalFetch; }
    });
  }
}

for (const [name, wireValue] of [['missing', undefined], ['null', 'null'], ['negative', '-1'], ['infinity', '1e999'], ['NaN', 'null'], ['text', '"bad"']]) {
  test(`auto safely defaults ${name} retry guidance`, async () => {
    const originalFetch = globalThis.fetch;
    const times = [];
    globalThis.fetch = async () => {
      times.push(Date.now());
      const result = times.length === 1
        ? new Response(`{"data":{"phase":"think_pending","resumable":true${wireValue === undefined ? '' : `,"retry_after_ms":${wireValue}`}}}`, { status: 202 })
        : Response.json({ data: { decision_id: `pacing-default-${name}` } });
      if (name === 'NaN' && times.length === 1) result.json = async () => ({ data: {
        phase: 'think_pending', resumable: true, retry_after_ms: NaN,
      } });
      return result;
    };
    try {
      const result = await marrowAuto('pacing-key', 'https://api.example.test', {
        action: 'record default pacing', operation_id: `pacing_default_${name}`,
      }, undefined, undefined, 500);
      assert.equal(result.phase, 'decision_created');
      assert.equal(times.length, 2);
      assert.ok(times[1] - times[0] >= 50, 'malformed guidance uses safe 50ms default');
    } finally { globalThis.fetch = originalFetch; }
  });
}

test('auto does not retry when the response budget is exactly exhausted', async () => {
  const originalFetch = globalThis.fetch;
  const originalNow = Date.now;
  let now = originalNow();
  let attempts = 0;
  Date.now = () => now;
  globalThis.fetch = async () => {
    attempts += 1;
    now += 500;
    return Response.json({ data: { phase: 'think_pending', resumable: true, retry_after_ms: 1200 } }, { status: 202 });
  };
  try {
    const result = await marrowAuto('pacing-key', 'https://api.example.test', {
      action: 'record exhausted budget', operation_id: 'pacing_exactly_exhausted',
    }, undefined, undefined, 500);
    assert.equal(result.phase, 'think_pending');
    assert.equal(result.retry_after_ms, 1200);
    assert.equal(attempts, 1);
    assert.equal(result.phase_timings_ms.total, 500);
  } finally { globalThis.fetch = originalFetch; Date.now = originalNow; }
});
