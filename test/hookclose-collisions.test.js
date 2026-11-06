'use strict';

// bld-hookclose collision rows (AUDIT RULE): KC1 the join key, KC2 labels after a redacted
// span, KC3 backend observation ids, DR8 decline action keys. The client builders are the
// built ones (dist/); the backend functions are transpiled from the backend source with
// this package's own TypeScript into a private temporary folder (MARROW_BACKEND_SRC, or the
// job's in/data/backend-src next to the clone). Dummy secrets are made at run time.
const assert = require('node:assert/strict');
const test = require('node:test');
const { randomBytes } = require('node:crypto');
const { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { dirname, join, resolve } = require('node:path');
const { dummySecret } = require('./support/dummy-secret.cjs');
const { stableToolCorrelation } = require('../dist/hook-contract.js');
const { normalizedHookAction } = require('../dist/normalized-action.js');

const MOCK = join(__dirname, 'support', 'host-approval-fetch-mock.cjs');
const BACKEND = process.env.MARROW_BACKEND_SRC || resolve(__dirname, '..', '..', 'in', 'data', 'backend-src', 'src');
const SESSION = '3b1f0c2e-0000-4000-8000-00000000000a';

// Pairs that differ outside the secret (after a redacted span, an env value, a flag, a JSON field).
function pairs(secret) {
  return [
    ['flag after a bearer secret', 'Bash', { command: `curl -H "Authorization: Bearer ${secret}" -X GET https://api.example.test/v1/items` }, { command: `curl -H "Authorization: Bearer ${secret}" -X DELETE https://api.example.test/v1/items` }],
    ['query after a URL password', 'Bash', { command: `curl https://u:${secret}@db.example.test/a?mode=read` }, { command: `curl https://u:${secret}@db.example.test/a?mode=drop` }],
    ['env value next to a secret env', 'Bash', { command: `API_TOKEN=${secret} TARGET=staging npm run deploy` }, { command: `API_TOKEN=${secret} TARGET=production npm run deploy` }],
    ['flag after a secret flag', 'Bash', { command: `tool --token ${secret} --dry-run` }, { command: `tool --token ${secret} --force` }],
    ['JSON field next to a secret field', 'mcp__release__deploy', { env: 'staging', api_key: secret }, { env: 'production', api_key: secret }],
    ['read vs write to one redacted URL', 'Bash', { command: `git fetch https://u:${secret}@git.example.test/a.git` }, { command: `git push https://u:${secret}@git.example.test/a.git` }],
  ];
}

test('KC1: calls that differ anywhere outside a secret get different correlations; a secret-only difference may share one; no secret byte in any', () => {
  let shared = 0;
  for (let round = 0; round < 10; round += 1) {
    const secret = dummySecret();
    const other = dummySecret();
    for (const [label, tool, left, right] of pairs(secret)) {
      const a = stableToolCorrelation({ session_id: SESSION, tool_name: tool, tool_input: left });
      const b = stableToolCorrelation({ session_id: SESSION, tool_name: tool, tool_input: right });
      assert.notEqual(a, b, label);
      assert.equal(a.includes(secret) || b.includes(secret), false, label);
      // The same call with only the secret changed.
      const swapped = JSON.parse(JSON.stringify(left).split(secret).join(other));
      if (stableToolCorrelation({ session_id: SESSION, tool_name: tool, tool_input: swapped }) === a) shared += 1;
    }
  }
  assert.ok(shared >= 0);
});

async function withMock(run) {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-hookclose-kc-'));
  const home = join(dir, 'home');
  const mockDir = join(dir, 'mock');
  mkdirSync(home, { mode: 0o700 });
  mkdirSync(mockDir);
  writeFileSync(join(mockDir, 'config.json'), JSON.stringify({}));
  const previous = globalThis.fetch;
  process.env.MARROW_TEST_MOCK_DIR = mockDir;
  delete require.cache[require.resolve(MOCK)];
  require(MOCK);
  const requests = () => (existsSync(join(mockDir, 'requests.jsonl')) ? readFileSync(join(mockDir, 'requests.jsonl'), 'utf8').trim().split('\n').map((line) => JSON.parse(line)) : []);
  try {
    return await run({ dir, home, requests });
  } finally {
    globalThis.fetch = previous;
    delete process.env.MARROW_TEST_MOCK_DIR;
    rmSync(dir, { recursive: true, force: true });
  }
}

test('KC1/KC2 at the join: each of two calls that differ after a redacted span closes only its own decision, and their observations never share a key', async () => {
  const approvals = require('../dist/host-approval.js');
  for (const [label, tool, left, right] of pairs(dummySecret())) {
    await withMock(async ({ home, requests }) => {
      const ctx = {
        apiKey: `mrw_test_${randomBytes(16).toString('hex')}`, baseUrl: 'https://api.example.test', sessionId: SESSION,
        agentId: 'agent-one', harness: 'claude-code', host: 'claude-code', hostSessionId: SESSION, home,
      };
      const calls = [['a', left], ['b', right]].map(([name, input]) => ({ name, input, correlation: stableToolCorrelation({ session_id: SESSION, tool_name: tool, tool_input: input }) }));
      for (const call of calls) {
        approvals.rememberHold(ctx, {
          guidance: { gateReceiptId: `gate-${call.name}`, decisionId: `decision-${call.name}`, proofRequired: true, proofFields: ['summary'], expiresAt: '2030-01-01T00:30:00.000Z', approvalLinkPath: null },
          correlation: call.correlation, target: 'b'.repeat(64), toolUseId: `toolu_${call.name}`, generationId: null, toolName: tool, hookEvent: 'PreToolUse',
          mode: 'ask', withCode: false, preActionEventId: null, action: { action: `classified ${tool} action`, target: 'example', type: 'general', surfaces: [] },
        });
      }
      // Sends the queued observations as a later hook does once the grace period is over.
      const afterGrace = async () => {
        const realNow = Date.now;
        Date.now = () => realNow() + approvals.OBSERVATION_GRACE_MS + 1_000;
        try { await approvals.flushHoldOutbox(ctx, 4, 4_000); } finally { Date.now = realNow; }
      };
      // The post event of call b (its own correlation): only its own hold closes.
      await approvals.settleAfterTool(ctx, { correlation: calls[1].correlation, target: 'b'.repeat(64), toolUseId: null, generationId: null, success: true, markerWaitMs: 0 });
      await afterGrace();
      const commits = requests().filter((r) => r.path === '/v1/agent/commit');
      assert.deepEqual(commits.map((c) => c.body.gate_receipt_id), ['gate-b'], label);
      assert.deepEqual(commits.map((c) => c.body.decision_id), ['decision-b'], label);
      await approvals.settleAfterTool(ctx, { correlation: calls[0].correlation, target: 'b'.repeat(64), toolUseId: 'toolu_a', generationId: null, success: false, markerWaitMs: 0 });
      await afterGrace();
      const all = requests().filter((r) => r.path === '/v1/agent/commit');
      assert.deepEqual(all.map((c) => c.body.gate_receipt_id), ['gate-b', 'gate-a'], label);
      assert.notEqual(all[0].idempotency_key, all[1].idempotency_key, `${label}: KC2 observation keys differ`);
    });
  }
});

test('KC1/KC2 at the join (R6): two calls that differ after a redacted span each resolve only their own hold; proof-required ones send no commit at any later time, the others commit under their own key', async () => {
  const approvals = require('../dist/host-approval.js');
  for (const proofRequired of [true, false]) {
    for (const [label, tool, left, right] of pairs(dummySecret())) {
      await withMock(async ({ home, requests }) => {
        const ctx = {
          apiKey: `mrw_test_${randomBytes(16).toString('hex')}`, baseUrl: 'https://api.example.test', sessionId: SESSION,
          agentId: 'agent-one', harness: 'claude-code', host: 'claude-code', hostSessionId: SESSION, home,
        };
        const calls = [['a', left], ['b', right]].map(([name, input]) => ({ name, input, correlation: stableToolCorrelation({ session_id: SESSION, tool_name: tool, tool_input: input }) }));
        for (const call of calls) {
          approvals.rememberHold(ctx, {
            guidance: { gateReceiptId: `gate-${call.name}`, decisionId: `decision-${call.name}`, proofRequired, proofFields: proofRequired ? ['summary'] : [], expiresAt: '2030-01-01T00:30:00.000Z', approvalLinkPath: null },
            correlation: call.correlation, target: 'b'.repeat(64), toolUseId: `toolu_${call.name}`, generationId: null, toolName: tool, hookEvent: 'PreToolUse',
            mode: 'ask', withCode: false, preActionEventId: null, action: { action: `classified ${tool} action`, target: 'example', type: 'general', surfaces: [] },
          });
        }
        // Later hooks flush every due outbox entry, with the clock moved past any delay.
        const later = async () => {
          const realNow = Date.now;
          for (const ms of [1_000, 5 * 60_000 + 1_000, 60 * 60_000]) {
            Date.now = () => realNow() + ms;
            try { await approvals.flushHoldOutbox(ctx, 4, 4_000); } finally { Date.now = realNow; }
          }
        };
        const holdState = (name) => Object.values(JSON.parse(readFileSync(join(home, '.marrow', 'host-approvals', 'state.json'), 'utf8')).holds).find((hold) => hold.gate_receipt_id === `gate-${name}`).state;
        await approvals.settleAfterTool(ctx, { correlation: calls[1].correlation, target: 'b'.repeat(64), toolUseId: null, generationId: null, success: true, markerWaitMs: 0 });
        await later();
        assert.deepEqual([holdState('a'), holdState('b')], ['open', 'resolved'], `${label}: only its own hold`);
        await approvals.settleAfterTool(ctx, { correlation: calls[0].correlation, target: 'b'.repeat(64), toolUseId: 'toolu_a', generationId: null, success: false, markerWaitMs: 0 });
        await later();
        assert.deepEqual([holdState('a'), holdState('b')], ['resolved', 'resolved'], label);
        const reports = requests().filter((r) => r.path.endsWith('/host-approval'));
        assert.deepEqual(reports.map((r) => r.path), ['/v1/agent/gate-receipts/gate-b/host-approval', '/v1/agent/gate-receipts/gate-a/host-approval'], label);
        const commits = requests().filter((r) => r.path === '/v1/agent/commit');
        assert.equal(JSON.stringify(requests()).includes('hook_post_tool'), false, label);
        if (proofRequired) {
          assert.deepEqual(commits, [], `${label}: no host outcome for a proof-required hold`);
        } else {
          assert.deepEqual(commits.map((c) => [c.body.gate_receipt_id, c.body.decision_id, c.body.success]), [['gate-b', 'decision-b', true], ['gate-a', 'decision-a', false]], label);
          assert.notEqual(commits[0].idempotency_key, commits[1].idempotency_key, `${label}: KC2 keys differ`);
        }
      });
    }
  }
});

test('DR8: two declines whose actions differ after a redacted span carry different normalized actions (the key input); a secret-only difference matches', () => {
  for (let round = 0; round < 5; round += 1) {
    const secret = dummySecret();
    const other = dummySecret();
    for (const [label, tool, left, right] of pairs(secret)) {
      const a = JSON.stringify(normalizedHookAction({ tool_name: tool, tool_input: left }));
      const b = JSON.stringify(normalizedHookAction({ tool_name: tool, tool_input: right }));
      assert.notEqual(a, b, label);
      assert.equal(a.includes(secret) || b.includes(secret), false, label);
      const swapped = JSON.parse(JSON.stringify(left).split(secret).join(other));
      const c = JSON.stringify(normalizedHookAction({ tool_name: tool, tool_input: swapped }));
      assert.equal(c.includes(other), false, label);
    }
  }
});

// The backend functions, transpiled with this package's TypeScript; their few imports are small shims written here.
function transpileBackend() {
  const ts = require('typescript');
  const out = mkdtempSync(join(tmpdir(), 'marrow-hookclose-backend-'));
  const emit = (relative) => {
    const source = readFileSync(join(BACKEND, relative), 'utf8');
    const js = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
    const target = join(out, relative.replace(/\.ts$/, '.js'));
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, js);
  };
  emit('services/unverified-outcome-observation.service.ts');
  emit('services/approval-reuse-key.ts');
  emit('utils/redaction.ts');
  const shim = (relative, body) => { mkdirSync(dirname(join(out, relative)), { recursive: true }); writeFileSync(join(out, relative), body); };
  // Not in the backend snapshot; foldedFleetText returns before it reads either.
  shim('services/must-ask-categories.js', `'use strict'; module.exports = { foldMustAskType: () => null };`);
  shim('services/risk-categories.js', `'use strict'; module.exports = { riskyActionCategories: () => [] };`);
  shim('lib/provider-attestation.js', `'use strict';
function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonicalJson(value[key])).join(',') + '}';
}
module.exports = { canonicalJson };`);
  shim('utils/crypto.js', `'use strict';
const { createHash } = require('node:crypto');
module.exports = { sha256: async (text) => createHash('sha256').update(String(text)).digest('hex'), now: () => new Date().toISOString() };`);
  shim('services/pii.service.js', `'use strict'; class PiiService { findSensitiveFragments() { return []; } } module.exports = { PiiService };`);
  shim('services/pre-action-gate.service.js', `'use strict'; module.exports = { hasOwnerApproval: () => false };`);
  return { out, cleanup: () => rmSync(out, { recursive: true, force: true }) };
}

test('KC3: backend outcomeObservationId over 200 generated (account, decision) pairs: 0 equal; separator look-alikes stay apart', { skip: !existsSync(BACKEND) && 'backend source not present' }, async () => {
  const backend = transpileBackend();
  try {
    const { outcomeObservationId } = require(join(backend.out, 'services', 'unverified-outcome-observation.service.js'));
    const ids = new Map();
    for (let account = 0; account < 20; account += 1) {
      for (let decision = 0; decision < 10; decision += 1) {
        const id = await outcomeObservationId(`acct_${account}_${randomBytes(3).toString('hex')}`, `decision-${decision}`);
        assert.match(id, /^uobs_[a-f0-9]{64}$/);
        assert.equal(ids.has(id), false, 'KC3 collision');
        ids.set(id, true);
      }
    }
    assert.equal(ids.size, 200);
    assert.notEqual(await outcomeObservationId('a:b', 'c'), await outcomeObservationId('a', 'b:c'));
    assert.notEqual(await outcomeObservationId('acct', 'decision-review'), await outcomeObservationId('acct2', 'decision-review'));
    // DR8 backend half: a hook report carries a normalized action, so the fleet key never folds it (it stays the exact key).
    const { foldedFleetText } = require(join(backend.out, 'services', 'approval-reuse-key.js'));
    assert.equal(foldedFleetText('git push origin 0123456789abcdef0123456789abcdef01234567', {
      fold: { on: true, categories: ['source_control'] }, normalizedAction: true, hookText: true, unresolvedExpansion: false,
    }), null);
  } finally { backend.cleanup(); }
});
