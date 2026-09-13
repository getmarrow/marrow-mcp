const assert = require('node:assert/strict');
const test = require('node:test');

const reliabilityModule = process.env.MARROW_REQUEST_RELIABILITY_MODULE || '../dist/request-reliability.js';
const { MarrowRequestError, reliableFetch } = require(reliabilityModule);

test('request deadline remains active while a response body is stalled after headers', async () => {
  const originalFetch = globalThis.fetch;
  const keepEventLoopAlive = setTimeout(() => {}, 250);
  let headersReturned = false;
  globalThis.fetch = async (_url, init = {}) => {
    headersReturned = true;
    const signal = init.signal;
    const body = new ReadableStream({
      start(controller) {
        const abort = () => controller.error(signal?.reason || new DOMException('Aborted', 'AbortError'));
        if (signal?.aborted) abort();
        else signal?.addEventListener('abort', abort, { once: true });
      },
    });
    return new Response(body, { status: 200, headers: { 'content-type': 'application/json' } });
  };
  try {
    await assert.rejects(
      () => reliableFetch('https://api.example.test/v1/agent/think', { method: 'POST' }, {
        retryOwner: 'caller',
        timeoutMs: 100,
        consumeResponse: (response) => response.json(),
      }),
      (error) => error instanceof MarrowRequestError && error.code === 'request_timeout',
    );
    assert.equal(headersReturned, true);
  } finally {
    clearTimeout(keepEventLoopAlive);
    globalThis.fetch = originalFetch;
  }
});
