const assert = require('node:assert/strict');
const test = require('node:test');
const { marrowAuto } = require('../dist/index.js');
const { requestErrorFromResponse } = require('../dist/request-reliability.js');

for (const header of ['120', new Date(Date.now() + 120000).toUTCString()]) {
  test(`long Retry-After remains above 60 seconds: ${header}`, async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = async (url) => {
      if (String(url).includes('/think')) return Response.json({ data: { decision_id: 'long-retry-decision' } });
      calls++;
      return Response.json({ error: 'Rate limited' }, { status: 429, headers: { 'Retry-After': header } });
    };
    try {
      const result = await marrowAuto('long-retry-key', 'https://api.example.test', {
        action: 'Record retry header fixture', success: true, outcome: 'Waiting', operation_id: `long_retry_${header === '120' ? 'seconds' : 'date'}`,
      }, undefined, undefined, 500);
      assert.equal(result.committed, false);
      assert.equal(result.phase, 'commit_pending');
      assert.ok(result.retry_after_ms > 110000);
      assert.equal(calls, 1);
    } finally { globalThis.fetch = originalFetch; }
  });
}

for (const header of ['invalid', '-1', '1e999', '1e300']) {
  test(`malformed or unbounded Retry-After suspends automatic recovery: ${header}`, async () => {
    const error = requestErrorFromResponse(new Response('', { status: 429, headers: { 'Retry-After': header } }));
    assert.equal(error.retryable, false);
    assert.equal(error.retryAfterMs, null);
    assert.match(error.exactFix, /Retry-After/);
  });
}

for (const header of ['invalid', '1e999']) {
  test(`pending202 does not retry an unsafe header: ${header}`, async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = async (url) => {
      if (String(url).includes('/think')) return Response.json({ data: { decision_id: 'unsafe-header-decision' } });
      calls++;
      return Response.json({ data: { phase: 'commit_pending', resumable: true } }, { status: 202, headers: { 'Retry-After': header } });
    };
    try {
      const result = await marrowAuto('unsafe-header-key', 'https://api.example.test', {
        action: 'Record header safety fixture', success: true, outcome: 'Pending', operation_id: `unsafe_header_${header}`,
      }, undefined, undefined, 500);
      assert.equal(result.committed, false);
      assert.equal(result.resumable, false);
      assert.equal(result.retry_after_ms, null);
      assert.equal(calls, 1);
    } finally { globalThis.fetch = originalFetch; }
  });
}
