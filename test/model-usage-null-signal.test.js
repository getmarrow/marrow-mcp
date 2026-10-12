const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const test = require('node:test');

const { marrowModelUsage } = require('../dist/index.js');

async function withResponse(data, callback) {
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ data }), { status: 200, headers: { 'content-type': 'application/json' } });
  try { return await callback(); } finally { globalThis.fetch = original; }
}

test('MarrowModelUsageResult.token_value_signal is nullable: a null signal passes through as null, never invented, never a crash', async () => {
  const declaration = readFileSync(join(__dirname, '..', 'dist', 'types.d.ts'), 'utf8');
  assert.match(declaration, /token_value_signal: MarrowTokenValueSignal \| null;/);
  const key = `mrw_${randomBytes(12).toString('hex')}`;
  for (const signal of [null, undefined]) {
    const data = { recorded: true, usage_id: 'u1', value_proof_endpoint: '/v1/x', exact_next_action: 'none', ...(signal === null ? { token_value_signal: null } : {}) };
    const result = await withResponse(data, () => marrowModelUsage(key, 'https://api.example.test', { provider: 'openai', model: 'm', input_tokens: 1, output_tokens: 1 }, 's', 'a'));
    assert.equal(result.token_value_signal, signal === null ? null : undefined, 'no value is invented');
    // The marrow_model_usage tool serializes the result as is (cli.ts).
    const text = JSON.stringify(result, null, 2);
    assert.equal(JSON.parse(text).recorded, true);
  }
});
