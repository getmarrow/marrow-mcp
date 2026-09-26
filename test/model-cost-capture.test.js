const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const { webcrypto } = require('node:crypto');
const { extractModelUsageFromUnknown: extract } = require('../dist/habit-loop-copy.js');
const { marrowModelUsage, marrowCommit } = require('../dist/index.js');

// Optional cross-repository acceptance uses the actual backend, never a copied
// pricing implementation or fabricated catalog. Set this explicitly in release
// verification; ordinary MCP CI can still run the transport regressions below.
const backendRoot = process.env.MARROW_COST_BACKEND_SOURCE
  || path.resolve(__dirname, '../../marrow-model-cost-20260926');
const backendFile = path.join(backendRoot, 'src/services/model-cost.service.ts');
const backendAvailable = fs.existsSync(backendFile);
function loadBackend() {
  const ts = require('typescript');
  const cache = new Map();
  function load(filename) {
    if (cache.has(filename)) return cache.get(filename).exports;
    const module = { exports: {} };
    cache.set(filename, module);
    const nativeRequire = createRequire(filename);
    const localRequire = (specifier) => {
      const candidate = path.resolve(path.dirname(filename), `${specifier}.ts`);
      return specifier.startsWith('.') && fs.existsSync(candidate) ? load(candidate) : nativeRequire(specifier);
    };
    const compiled = ts.transpileModule(fs.readFileSync(filename, 'utf8'), {
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
      fileName: filename,
    }).outputText;
    vm.runInNewContext('(function(require,module,exports){' + compiled + '\n})', {
      crypto: webcrypto, TextEncoder, TextDecoder, console,
    }, { filename })(localRequire, module, module.exports);
    return module.exports;
  }
  return load(backendFile);
}
let backend;
const realBackend = () => backend || (backend = loadBackend());
const recordedAt = '2026-09-27T00:00:00.000Z';
const openaiContext = {
  endpoint: 'https://api.openai.com/v1/chat/completions', provider: 'openai',
  // Fixture request configuration: standard service, global endpoint, text only.
  pricing_dimensions: { tier: 'standard', region: 'global', modality: 'text' },
  billing_mode: 'api', usage_kind: 'delta', occurred_at: recordedAt,
};
const chatResponse = {
  id: 'chatcmpl-cost-fixture', object: 'chat.completion', model: 'gpt-4.1',
  usage: { prompt_tokens: 1000, completion_tokens: 100, total_tokens: 1100,
    prompt_tokens_details: { cached_tokens: 400 } },
};

async function sentUsage(input, viaCommit = false) {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), body: JSON.parse(init.body) });
    return Response.json({ data: { committed: true, recorded: true, decision_id: 'decision-cost-fixture' } });
  };
  try {
    if (viaCommit) {
      await marrowCommit('fixture-key', 'https://api.example.test', {
        decision_id: 'decision-cost-fixture', success: true, outcome: 'Fixture only',
        auto_gate: false, model_usage: input,
      });
    } else {
      await marrowModelUsage('fixture-key', 'https://api.example.test', input);
    }
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, `https://api.example.test/v1/agent/${viaCommit ? 'commit' : 'model-usage'}`);
    return viaCommit ? calls[0].body.model_usage : calls[0].body;
  } finally {
    globalThis.fetch = originalFetch;
  }
}

test('Chat capture preserves cache subset, response identity and explicit request evidence through both transports', async () => {
  const captured = extract(chatResponse, openaiContext);
  assert.equal(captured.provider, 'openai');
  assert.equal(captured.model, 'gpt-4.1');
  assert.equal(captured.billing_host, 'first_party');
  assert.equal(captured.input_tokens, 1000);
  assert.equal(captured.output_tokens, 100);
  assert.equal(captured.cached_tokens, 400);
  assert.equal(captured.token_semantics, 'input_includes_cache');
  assert.equal(captured.usage_event_id, `openai:${chatResponse.id}`);
  assert.notEqual(captured.coverage_complete, true);
  assert.notEqual(captured.overhead_complete, true);
  for (const viaCommit of [false, true]) {
    const payload = await sentUsage(captured, viaCommit);
    for (const key of ['provider', 'model', 'billing_host', 'input_tokens', 'output_tokens', 'cached_tokens',
      'token_semantics', 'usage_event_id', 'pricing_dimensions', 'billing_mode', 'usage_kind', 'occurred_at']) {
      assert.deepEqual(payload[key], captured[key], `${viaCommit ? 'Commit' : 'direct'} dropped ${key}`);
    }
  }
});

test('rich caller evidence survives direct and Commit normalization', async () => {
  const input = { ...extract(chatResponse, openaiContext), cache_write_tokens: 0,
    usage_role: 'marrow_overhead', coverage_complete: false, overhead_complete: false,
    cost_usd: 0.002, cost_source: 'provider_response', baseline_usage_id: 'usage-baseline-fixture',
    comparison_id: 'comparison-fixture', task_fingerprint: 'a'.repeat(64), constraints_fingerprint: 'b'.repeat(64) };
  for (const viaCommit of [false, true]) {
    const payload = await sentUsage(input, viaCommit);
    for (const key of Object.keys(input)) assert.deepEqual(payload[key], input[key], `dropped ${key}`);
  }
});

test('null, strings, booleans and nonfinite counts never become zero-priced observations', async () => {
  for (const value of [null, '', '12', false, NaN, Infinity, -1]) {
    for (const key of ['input_tokens', 'output_tokens', 'cached_tokens', 'cache_write_tokens', 'cost_usd']) {
      for (const viaCommit of [false, true]) {
        await assert.rejects(() => sentUsage({ provider: 'openai', model: 'gpt-4.1', [key]: value }, viaCommit),
          TypeError, `${key}: ${String(value)}`);
      }
    }
  }
});

test('Responses nested response captures input_tokens_details.cached_tokens', () => {
  const captured = extract({ type: 'response.completed', response: { id: 'resp_cost_fixture',
    model: 'gpt-4.1', usage: { input_tokens: 1000, output_tokens: 100, total_tokens: 1100,
      input_tokens_details: { cached_tokens: 400 } } } }, { ...openaiContext, endpoint: 'https://api.openai.com/v1/responses' });
  assert.equal(captured.model, 'gpt-4.1');
  assert.equal(captured.usage_event_id, 'openai:resp_cost_fixture');
  assert.equal(captured.cached_tokens, 400);
  assert.equal(captured.token_semantics, 'input_includes_cache');
});

test('Responses cache-write counts survive extraction and both transports', async () => {
  const captured = extract({ type: 'response.completed', response: { id: 'resp_cache_write_fixture',
    model: 'gpt-4.1', usage: { input_tokens: 1000, output_tokens: 100,
      input_tokens_details: { cached_tokens: 400, cache_write_tokens: 200 } } } },
  { ...openaiContext, endpoint: 'https://api.openai.com/v1/responses' });
  assert.equal(captured.cache_write_tokens, 200);
  assert.equal(captured.total_tokens, 1100);
  for (const viaCommit of [false, true]) {
    const payload = await sentUsage(captured, viaCommit);
    assert.equal(payload.cache_write_tokens, 200);
    assert.equal(payload.cached_tokens, 400);
    assert.equal(payload.token_semantics, 'input_includes_cache');
  }
});

test('missing output count stays absent and total-only usage cannot invent buckets', () => {
  const missing = extract({ ...chatResponse, usage: { prompt_tokens: 1000 } }, openaiContext);
  assert.equal(missing.output_tokens, undefined);
  const totalOnly = extract({ ...chatResponse, usage: { total_tokens: 1100 } }, openaiContext);
  if (totalOnly) {
    assert.equal(totalOnly.input_tokens, undefined);
    assert.equal(totalOnly.output_tokens, undefined);
  }
});

test('first-party billing host requires exact trusted HTTPS endpoint and matching provider', () => {
  for (const endpoint of [undefined, 'https://proxy.example/v1', 'http://api.openai.com/v1',
    'https://api.openai.com.evil.example/v1', 'https://fixture:secret@api.openai.com/v1']) {
    const captured = extract(chatResponse, { ...openaiContext, endpoint });
    assert.notEqual(captured.billing_host, 'first_party', String(endpoint));
  }
  const mismatch = extract({ ...chatResponse, provider: 'anthropic' }, openaiContext);
  assert.notEqual(mismatch?.billing_host, 'first_party');
  assert.equal(mismatch?.usage_event_id, undefined);
  for (const [response, context] of [
    [{ ...chatResponse, model: 'claude-sonnet-4-20250514' }, openaiContext],
    [chatResponse, { ...openaiContext, endpoint: 'https://api.anthropic.com/v1/messages', provider: 'anthropic' }],
  ]) {
    const wrongModel = extract(response, context);
    assert.notEqual(wrongModel?.billing_host, 'first_party');
    assert.equal(wrongModel?.usage_event_id, undefined);
  }
});

test('Anthropic partial message_start stays cumulative despite stable ID and delta configuration', async () => {
  const captured = extract({ type: 'message_start', message: { id: 'msg_partial_fixture',
    model: 'claude-sonnet-4-20250514', usage: { input_tokens: 600, output_tokens: 0 } } },
  { endpoint: 'https://api.anthropic.com/v1/messages', provider: 'anthropic', usage_kind: 'delta' });
  assert.equal(captured.usage_kind, 'cumulative');
  assert.notEqual(captured.coverage_complete, true);
  for (const viaCommit of [false, true]) {
    assert.equal((await sentUsage(captured, viaCommit)).usage_kind, 'cumulative');
  }
});

test('explicit cumulative context cannot be overridden by a stable response ID', () => {
  const captured = extract(chatResponse, { ...openaiContext, usage_kind: 'cumulative' });
  assert.equal(captured.usage_event_id, `openai:${chatResponse.id}`);
  assert.equal(captured.usage_kind, 'cumulative');
});

test('capture does not invent missing pricing dimensions or infer complete coverage', () => {
  const captured = extract(chatResponse, { endpoint: openaiContext.endpoint, provider: 'openai' });
  assert.equal(captured.pricing_dimensions, undefined);
  assert.notEqual(captured.coverage_complete, true);
  assert.notEqual(captured.overhead_complete, true);
});

const integration = { skip: backendAvailable ? false : 'Set MARROW_COST_BACKEND_SOURCE to the built backend source checkout' };
test('real catalog prices direct and Commit captured Chat usage without charging cached input twice', integration, async () => {
  const { priceUsage, aggregateCostProof } = realBackend();
  for (const viaCommit of [false, true]) {
    const payload = await sentUsage(extract(chatResponse, openaiContext), viaCommit);
    const evidence = priceUsage(payload, recordedAt);
    assert.equal(evidence.reason, null);
    assert.ok(Math.abs(evidence.amount - 0.0022) < 1e-12);
    assert.equal(JSON.stringify(evidence.buckets), JSON.stringify([600, 100, 400, 0]));
    const proof = aggregateCostProof([{ id: payload.usage_event_id, evidence_json: JSON.stringify(evidence) }]);
    assert.equal(proof.calculated_cost_usd.state, 'partial');
    assert.equal(proof.baseline_cost_usd.state, 'pending');
    assert.equal(proof.net_savings_usd.state, 'pending');
  }
});

test('real catalog prices Anthropic nested message disjoint cache read and creation counts', integration, async () => {
  const context = { endpoint: 'https://api.anthropic.com/v1/messages', provider: 'anthropic',
    pricing_dimensions: { tier: 'standard', region: 'global', modality: 'text', cache_ttl: '5m' },
    billing_mode: 'api', usage_kind: 'delta', occurred_at: recordedAt };
  const captured = extract({ message: { id: 'msg_cost_fixture', type: 'message',
    model: 'claude-sonnet-4-20250514', usage: { input_tokens: 600, output_tokens: 100,
      cache_read_input_tokens: 400, cache_creation_input_tokens: 200 } } }, context);
  assert.equal(captured.token_semantics, 'disjoint');
  assert.equal(captured.cache_write_tokens, 200);
  assert.equal(captured.usage_event_id, 'anthropic:msg_cost_fixture');
  const evidence = realBackend().priceUsage(await sentUsage(captured), recordedAt);
  assert.equal(evidence.reason, null);
  assert.ok(Math.abs(evidence.amount - 0.00417) < 1e-12);
});

test('observed Anthropic cache creation TTL split overrides conflicting request TTL and mixed writes stay unpriced', integration, async () => {
  for (const [five, hour, ttl, expected] of [
    [200, 0, '5m', 0.00417], [0, 200, '1h', 0.00462], [100, 100, 'mixed_unresolved', null],
  ]) {
    const captured = extract({ message: { id: `msg_ttl_${five}_${hour}`, type: 'message',
      model: 'claude-sonnet-4-20250514', usage: { input_tokens: 600, output_tokens: 100,
        cache_read_input_tokens: 400, cache_creation_input_tokens: 200,
        cache_creation: { ephemeral_5m_input_tokens: five, ephemeral_1h_input_tokens: hour } } } },
    { endpoint: 'https://api.anthropic.com/v1/messages', provider: 'anthropic',
      pricing_dimensions: { tier: 'standard', region: 'global', modality: 'text', cache_ttl: '5m' },
      occurred_at: recordedAt });
    assert.equal(captured.pricing_dimensions.cache_ttl, ttl);
    assert.equal(captured.cache_write_tokens, 200);
    for (const viaCommit of [false, true]) {
      const payload = await sentUsage(captured, viaCommit);
      assert.equal(payload.pricing_dimensions.cache_ttl, ttl);
      const evidence = realBackend().priceUsage(payload, recordedAt);
      if (expected === null) {
        assert.equal(evidence.amount, null);
        assert.equal(evidence.reason, 'Pricing variant not established');
      } else {
        assert.equal(evidence.reason, null);
        assert.ok(Math.abs(evidence.amount - expected) < 1e-12);
      }
    }
  }
});

test('real pricing keeps missing counts, host, dimensions, and cumulative usage unpriced', integration, async () => {
  const examples = [
    [extract({ ...chatResponse, usage: { prompt_tokens: 1000 } }, openaiContext), 'Token buckets not reported'],
    [extract(chatResponse, { ...openaiContext, endpoint: 'https://proxy.example/v1' }), 'Billing host not reported'],
    [extract(chatResponse, { ...openaiContext, pricing_dimensions: undefined }), 'Pricing variant not established'],
    [extract(chatResponse, { ...openaiContext, usage_kind: 'cumulative' }), 'Cumulative usage requires a proven delta'],
  ];
  for (const [captured, reason] of examples) {
    const evidence = realBackend().priceUsage(await sentUsage(captured), recordedAt);
    assert.equal(evidence.amount, null);
    assert.equal(evidence.reason, reason);
  }
});

test('subscription capture is only an API-equivalent amount and never complete savings', integration, async () => {
  const payload = await sentUsage(extract(chatResponse, { ...openaiContext, billing_mode: 'subscription' }));
  const evidence = realBackend().priceUsage(payload, recordedAt);
  assert.equal(evidence.basis, 'api_equivalent');
  assert.ok(evidence.amount > 0);
  assert.equal(evidence.complete, false);
});

test('duplicate capture preserves backend event identity across direct and Commit delivery', integration, async () => {
  const service = new (realBackend().ModelCostService)({});
  const first = await sentUsage(extract(chatResponse, openaiContext));
  const duplicate = await sentUsage(extract(chatResponse, openaiContext), true);
  const firstId = await service.identity('account-fixture', first);
  assert.ok(firstId);
  assert.equal(await service.identity('account-fixture', duplicate), firstId);
  assert.notEqual(await service.identity('other-account-fixture', duplicate), firstId);
});

test('malformed observed cache counts do not become a zero cache charge', () => {
  assert.equal(extract({ ...chatResponse, usage: { ...chatResponse.usage, prompt_tokens_details: { cached_tokens: null } } }, openaiContext), null);
  assert.equal(extract({ ...chatResponse, usage: { ...chatResponse.usage, cache_write_tokens: null } }, openaiContext), null);
  assert.notEqual(extract({ ...chatResponse, id: 'msg_wrong_provider' }, openaiContext)?.billing_host, 'first_party');
});
