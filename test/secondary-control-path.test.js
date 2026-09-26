const assert = require('node:assert/strict');
const test = require('node:test');
const api = require('../dist/index.js');

const calls = {
  orient: () => api.marrowOrient('fixture-key', 'https://api.example.test'),
  first_value: () => api.marrowFirstValue('fixture-key', 'https://api.example.test'),
  buyer_proof: () => api.marrowBuyerProof('fixture-key', 'https://api.example.test'),
  status: () => api.marrowStatus('fixture-key', 'https://api.example.test'),
  ask: () => api.marrowAsk('fixture-key', 'https://api.example.test', { query: 'Review a local note' }),
  control_plane: () => api.marrowGovernanceControlPlane('fixture-key', 'https://api.example.test'),
  workflow: () => api.marrowWorkflow('fixture-key', 'https://api.example.test', { action: 'list' }),
};

test('control calls keep stalled response bodies inside the transport deadline', async () => {
  const originalFetch = globalThis.fetch;
  const originalTimeout = process.env.MARROW_REQUEST_TIMEOUT_MS;
  process.env.MARROW_REQUEST_TIMEOUT_MS = '150';
  try {
    for (const [name, call] of Object.entries(calls)) {
      globalThis.fetch = async () => {
        return new Response(new ReadableStream({ start(controller) {
          controller.enqueue(new TextEncoder().encode('{"data":'));
        } }), { headers: { 'Content-Type': 'application/json' } });
      };
      let guard;
      const error = await Promise.race([
        call().then(() => null, (failure) => failure),
        new Promise((resolve) => { guard = setTimeout(() => resolve(null), 600); }),
      ]);
      clearTimeout(guard);
      assert.equal(error?.code, 'request_timeout', name);
    }
  } finally {
    globalThis.fetch = originalFetch;
    if (originalTimeout === undefined) delete process.env.MARROW_REQUEST_TIMEOUT_MS;
    else process.env.MARROW_REQUEST_TIMEOUT_MS = originalTimeout;
  }
});

test('secondary calls retain terminal auth and retryable backend unavailable failures', async () => {
  const originalFetch = globalThis.fetch;
  try {
    for (const call of Object.values(calls).slice(0, 3)) {
      for (const [status, category, retryable] of [[401, 'authentication_required', false], [403, 'permission_denied', false], [503, 'service_unavailable', true]]) {
        let attempts = 0;
        globalThis.fetch = async () => {
          attempts += 1;
          return Response.json({ error: 'Bounded fixture rejection', details: { code: 'MARROW_RUNTIME_CONTINUATION_UNAVAILABLE' } }, { status });
        };
        await assert.rejects(call, (error) => error.code === category && error.status === status
          && error.retryable === retryable && error.backendCode === 'MARROW_RUNTIME_CONTINUATION_UNAVAILABLE');
        if (!retryable) assert.equal(attempts, 1);
      }
    }
  } finally { globalThis.fetch = originalFetch; }
});

test('secondary calls reject malformed success envelopes', async () => {
  const originalFetch = globalThis.fetch;
  try {
    for (const call of Object.values(calls).slice(0, 3)) {
      for (const body of [{}, { data: null }, { data: [] }, { data: {} }]) {
        globalThis.fetch = async () => Response.json(body);
        await assert.rejects(call, (error) => error.code === 'invalid_response');
      }
    }
  } finally { globalThis.fetch = originalFetch; }
});

test('consuming a retryable model-usage rejection enqueues one deferred request', async () => {
  const originalFetch = globalThis.fetch;
  let requests = 0;
  globalThis.fetch = async () => {
    requests += 1;
    return requests === 1
      ? Response.json({ error: 'Temporary fixture outage' }, { status: 503 })
      : Response.json({ data: { accepted: true } });
  };
  const input = { provider: 'fixture', model: 'fixture', input_tokens: 1, output_tokens: 1 };
  try {
    await assert.rejects(() => api.marrowModelUsage('fixture-key', 'https://api.example.test', input),
      (error) => error.code === 'service_unavailable');
    await api.marrowModelUsage('fixture-key', 'https://api.example.test', input);
    assert.equal(requests, 3);
  } finally { globalThis.fetch = originalFetch; }
});
