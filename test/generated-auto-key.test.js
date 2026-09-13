const assert = require('node:assert/strict');
const test = require('node:test');

const { marrowAuto } = require('../dist/index.js');
const { privacySafeIdempotencyKey } = require('../dist/request-reliability.js');

test('generated UUID-shaped Auto keys pass the privacy validator without weakening caller keys', async () => {
  const operationId = 'auto_12345678-1234-4123-8123-123456789012';
  const expectedKey = `mcp-auto:${operationId}:think`;
  assert.equal(privacySafeIdempotencyKey(expectedKey), true);
  for (const unsafe of [
    'caller:123456789012',
    'mcp-auto:auto_12345678-1234-5123-8123-123456789012:think',
    'mcp-auto:auto_12345678-1234-4123-7123-123456789012:think',
    'mcp-auto:auto_12345678-1234-4123-8123-123456789012:unknown',
  ]) assert.equal(privacySafeIdempotencyKey(unsafe), false, unsafe);

  const originalFetch = globalThis.fetch;
  let observedKey = null;
  globalThis.fetch = async (_url, init = {}) => {
    observedKey = new Headers(init.headers).get('Idempotency-Key');
    return Response.json({ data: { decision_id: 'fixed-operation-decision' } });
  };
  try {
    const result = await marrowAuto('fixture-key', 'https://api.example.test', {
      action: 'fixed generated key proof',
      operation_id: operationId,
    });
    assert.equal(result.phase, 'decision_created');
    assert.equal(observedKey, expectedKey);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
