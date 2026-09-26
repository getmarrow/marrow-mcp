const test = require('node:test');
const assert = require('node:assert/strict');
const { marrowModelUsage, marrowCommit } = require('../dist/index.js');
const { extractModelUsageFromUnknown, modelUsageCaptureContextFromEnv } = require('../dist/habit-loop-copy.js');
const { normalizeModelUsage } = require('../dist/model-usage.js');

// Synthetic sentinels only; failures use fixed descriptions, never payload text.
const dummySuffix = 'synthetic_fixture_123456';
const sentinels = ['label:' + 'mrw_' + dummySuffix, 'cfut_' + dummySuffix, 'label:' + 'cfut_' + dummySuffix];
const ordinary = { provider: 'openai', model: 'gpt-4.1', input_tokens: 10, output_tokens: 2 };
const response = { id: 'resp_privacyfixture', model: 'gpt-4.1', usage: { input_tokens: 10, output_tokens: 2 } };
const context = { endpoint: 'https://api.openai.com/v1/responses', pricing_dimensions: { tier: 'standard', region: 'global', modality: 'text' } };

async function rejectBeforeTransport(input) {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; throw new Error('Unexpected transport'); };
  try {
    await assert.rejects(() => marrowModelUsage('fixture-key', 'https://api.example.test', input), TypeError);
    await assert.rejects(() => marrowCommit('fixture-key', 'https://api.example.test', {
      decision_id: 'decision-fixture', success: true, outcome: 'Fixture', auto_gate: false, model_usage: input,
    }), TypeError);
    assert.equal(calls, 0, 'Invalid metadata must not reach transport');
  } finally { globalThis.fetch = originalFetch; }
}

test('credential-shaped identity labels reject before direct or Commit transport', async () => {
  for (const value of sentinels) {
    for (const key of ['provider', 'model', 'agent_id', 'session_id', 'billing_host', 'usage_event_id', 'baseline_usage_id', 'comparison_id']) {
      await rejectBeforeTransport({ ...ordinary, [key]: value });
    }
  }
});

test('dimension secrets reject before direct or Commit transport without transforming identity', async () => {
  for (const key of ['api_key', 'authorization', 'client_secret', 'access_token', 'credential', 'password', 'private_key']) {
    await rejectBeforeTransport({ ...ordinary, pricing_dimensions: { [key]: 'synthetic-value' } });
  }
  for (const value of sentinels) await rejectBeforeTransport({ ...ordinary, pricing_dimensions: { tier: value } });
  assert.deepEqual(normalizeModelUsage({ ...ordinary, usage_event_id: 'openai:resp_privacyfixture', pricing_dimensions: context.pricing_dimensions }),
    { ...ordinary, usage_event_id: 'openai:resp_privacyfixture', pricing_dimensions: context.pricing_dimensions });
});

test('native extraction rejects credential labels and dimensions instead of emitting sentinels', () => {
  for (const value of sentinels) {
    assert.equal(extractModelUsageFromUnknown({ ...response, model: value }, context), null);
    assert.equal(extractModelUsageFromUnknown(response, { ...context, pricing_dimensions: { tier: value } }), null);
  }
  assert.equal(extractModelUsageFromUnknown(response, { ...context, pricing_dimensions: { api_key: 'synthetic-value' } }), null);
});

test('environment dimension parsing discards sensitive config and preserves ordinary evidence', () => {
  const previous = process.env.MARROW_MODEL_USAGE_PRICING_DIMENSIONS;
  try {
    for (const dimensions of [{ api_key: 'synthetic-value' }, ...sentinels.map(tier => ({ tier }))]) {
      process.env.MARROW_MODEL_USAGE_PRICING_DIMENSIONS = JSON.stringify(dimensions);
      const capture = modelUsageCaptureContextFromEnv();
      assert.equal(capture.pricing_dimensions, undefined);
      assert.equal(extractModelUsageFromUnknown(response, capture).pricing_dimensions, undefined);
    }
    process.env.MARROW_MODEL_USAGE_PRICING_DIMENSIONS = JSON.stringify(context.pricing_dimensions);
    assert.deepEqual(modelUsageCaptureContextFromEnv().pricing_dimensions, context.pricing_dimensions);
  } finally {
    if (previous === undefined) delete process.env.MARROW_MODEL_USAGE_PRICING_DIMENSIONS;
    else process.env.MARROW_MODEL_USAGE_PRICING_DIMENSIONS = previous;
  }
});
