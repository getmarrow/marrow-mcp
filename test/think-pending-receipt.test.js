const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { marrowThink } = require('../dist/index.js');
const { MarrowRequestError, structuredRequestFailure, privacySafeIdempotencyKey } = require('../dist/request-reliability.js');

test('pending receipt resumes the exact scoped request and rejects local drift before sending', async () => {
  const original = globalThis.fetch; const calls = []; let receipt;
  const params = { action: 'Synthetic bounded operation', context: { a: 1, b: 2 } };
  globalThis.fetch = async (url, init) => {
    calls.push({ url, body: init.body, headers: Object.fromEntries(new Headers(init.headers)) });
    const key = new Headers(init.headers).get('Idempotency-Key');
    return Response.json({ data: calls.length <= 3 ? {
      reconciliation_contract: 'agent_write_reconciliation.v1', reconciliation_operation: 'think',
      reconciliation_state: 'pending', decision_state: 'pending', committed: false, safe_to_continue: false,
      phase: 'think_pending', resumable: true, retryable: true, retry_after_ms: 1000, idempotency_key: key,
    } : { decision_id: 'decision-created', runtime_continuation_persisted: true, idempotency_key: key } },
    { status: calls.length <= 3 ? 202 : 200 });
  };
  try {
    await assert.rejects(() => marrowThink('synthetic-credential', 'https://fixture.test', params, 'session-one', 'agent-one'), error => {
      const result = structuredRequestFailure(error); receipt = result.pending_receipt;
      assert.equal(result.error.code, 'MCP_RECONCILIATION_EXHAUSTED');
      assert.equal(receipt.committed, false); assert.equal(receipt.safe_to_continue, false);
      assert.match(receipt.idempotency_key, /^mcp-think:/); assert.match(receipt.request_hash, /^[a-f0-9]{64}$/);
      assert.equal('decision_id' in receipt, false);
      assert.doesNotMatch(JSON.stringify(result), /synthetic-credential|Synthetic bounded|session-one|agent-one|fixture\.test/);
      return true;
    });
    assert.equal(calls.length, 3); assert.deepEqual(calls[1], calls[0]); assert.deepEqual(calls[2], calls[0]);
    const opts = { idempotencyKey: receipt.idempotency_key, requestHash: receipt.request_hash };
    for (const [credential, input, session, agent, override] of [
      ['other-tenant', params, 'session-one', 'agent-one', opts],
      ['synthetic-credential', { ...params, action: 'changed' }, 'session-one', 'agent-one', opts],
      ['synthetic-credential', params, 'session-other', 'agent-one', opts],
      ['synthetic-credential', params, 'session-one', 'agent-other', opts],
      ['synthetic-credential', params, 'session-one', 'agent-one', { ...opts, idempotencyKey: 'another-key' }],
      ['synthetic-credential', params, 'session-one', 'agent-one', { ...opts, requestHash: '0'.repeat(64) }],
      ['synthetic-credential', params, 'session-one', 'agent-one', { requestHash: receipt.request_hash }],
    ]) await assert.rejects(() => marrowThink(credential, 'https://fixture.test', input, session, agent, undefined, override), TypeError);
    assert.equal(calls.length, 3);
    const result = await marrowThink('synthetic-credential', 'https://fixture.test', params, 'session-one', 'agent-one', undefined, opts);
    assert.equal(result.decision_id, 'decision-created'); assert.equal(calls.length, 4); assert.deepEqual(calls[3], calls[0]);
  } finally { globalThis.fetch = original; }
});

test('caller keys reject credentials and personal identifiers without sending or echoing', async () => {
  const original = globalThis.fetch; let calls = 0;
  globalThis.fetch = async () => { calls++; throw Error('unexpected transport'); };
  try {
    for (const key of [['mrw', 'syntheticcredentialvalue'].join('_'), ['ghp', 'syntheticcredentialvalue'].join('_'), 'owner@example.test', 'owner.example', '15551234567']) {
      await assert.rejects(() => marrowThink('fixture', 'https://fixture.test', { action: 'fixture' }, undefined, undefined, undefined,
        { idempotencyKey: key }), error => error instanceof TypeError && !error.message.includes(key));
    }
    assert.equal(calls, 0);
  } finally { globalThis.fetch = original; }
});

test('structured receipt copies only validated public fields', () => {
  const receipt = { contract: 'mcp_write_pending.v1', operation: 'think', committed: false, safe_to_continue: false,
    idempotency_key: 'opaque-recovery-key', request_hash: 'a'.repeat(64), prompt: 'never expose', authorization: 'private' };
  const error = input => new MarrowRequestError({ code: 'invalid_response', message: 'pending', exactFix: 'resume', pendingReceipt: input });
  const safe = structuredRequestFailure(error(receipt)).pending_receipt;
  assert.equal(privacySafeIdempotencyKey('mcp-think:12345678-1234-4234-8234-123456789012'), true);
  assert.equal(privacySafeIdempotencyKey('mcp-commit:12345678-1234-4234-8234-123456789012'), true);
  assert.equal(safe.prompt, undefined); assert.equal(safe.authorization, undefined);
  assert.equal(structuredRequestFailure(error({ ...receipt, idempotency_key: ['mrw', 'syntheticcredentialvalue'].join('_') })).pending_receipt, undefined);
});

test('think tool exposes exact resume fields and tracks a decision only after the awaited confirmed result', () => {
  const source = fs.readFileSync(require.resolve('../src/cli.ts'), 'utf8');
  const schema = source.slice(source.indexOf("name: 'marrow_think'"), source.indexOf("name: 'marrow_commit'"));
  assert.match(schema, /idempotency_key: \{ type: 'string'/); assert.match(schema, /request_hash: \{ type: 'string'/);
  const handler = source.slice(source.indexOf("if (toolName === 'marrow_think')"), source.indexOf("if (toolName === 'marrow_commit')"));
  assert.match(handler, /idempotencyKey: args\.idempotency_key/); assert.match(handler, /requestHash: args\.request_hash/);
  assert.ok(handler.indexOf('await marrowThink(') < handler.indexOf('lastDecisionId = result.decision_id'));
});

test('manual resume validates the first terminal response before accepting any decision', async () => {
  const original = globalThis.fetch; const calls = []; let receipt; let terminal = null;
  const params = { action: 'Resume the original pending operation' };
  const invoke = options => marrowThink('fixture-credential', 'https://fixture.test', params,
    'session-original', 'agent-original', undefined, options);
  globalThis.fetch = async (url, init) => {
    calls.push({ url, body: init.body, headers: Object.fromEntries(new Headers(init.headers)) });
    const key = new Headers(init.headers).get('Idempotency-Key');
    return Response.json({ data: terminal || {
      reconciliation_contract: 'agent_write_reconciliation.v1', reconciliation_operation: 'think',
      reconciliation_state: 'pending', decision_state: 'pending', committed: false, safe_to_continue: false,
      phase: 'think_pending', resumable: true, retryable: true, retry_after_ms: 1000, idempotency_key: key,
    } }, { status: terminal ? 200 : 202 });
  };
  try {
    await assert.rejects(() => invoke(), error => {
      receipt = structuredRequestFailure(error).pending_receipt;
      return error.backendCode === 'MCP_RECONCILIATION_EXHAUSTED' && !!receipt;
    });
    assert.equal(calls.length, 3);
    const options = { idempotencyKey: receipt.idempotency_key, requestHash: receipt.request_hash };
    for (const candidate of [
      { decision_id: 'decision-final', idempotency_key: 'conflicting-key' },
      { idempotency_key: receipt.idempotency_key },
      { decision_id: '', idempotency_key: receipt.idempotency_key },
      { decision_id: 'decision\ninvalid', idempotency_key: receipt.idempotency_key },
    ]) {
      terminal = candidate; const before = calls.length;
      await assert.rejects(() => invoke(options), error => error.backendCode === 'MCP_RECONCILIATION_INVALID');
      assert.equal(calls.length, before + 1, 'no additional HTTP request after a conflicting terminal response');
      assert.deepEqual(calls.at(-1), calls[0]);
    }
    terminal = { decision_id: 'decision-final', idempotency_key: receipt.idempotency_key, runtime_continuation_persisted: true };
    const before = calls.length; const result = await invoke(options);
    assert.equal(result.decision_id, 'decision-final'); assert.equal(calls.length, before + 1);
    assert.deepEqual(calls.at(-1), calls[0]);
  } finally { globalThis.fetch = original; }
});
