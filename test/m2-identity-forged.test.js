'use strict';

// T-2 (delta audit of 0368537c): the hold correlation of a truncated action trusts only a 32-hex exact_hmac.
// normalizedHookAction always sets one (or a nonce), so this cannot come from hook input; the test forges
// the normalizer's answer to pin the guard: a truncated action without a well-formed exact_hmac gets a
// fresh correlation on every call (never shared, never resumed), and a well-formed one is stable.
const test = require('node:test');
const assert = require('node:assert/strict');

const normalized = require('../dist/normalized-action.js');
const { stableToolCorrelation } = require('../dist/hook-contract.js');

function withForgedAction(action, fn) {
  const real = normalized.normalizedHookAction;
  normalized.normalizedHookAction = () => JSON.parse(JSON.stringify(action));
  try { return fn(); } finally { normalized.normalizedHookAction = real; }
}
// A fresh input object per call (the identity cache is keyed on the object).
const corr = () => stableToolCorrelation({ session_id: 's1', tool_name: 'Bash', tool_input: { command: 'npm publish' } });

test('T-2: a truncated action with no exact_hmac or a malformed one never shares a correlation', () => {
  for (const exact of [undefined, '', 'zz', 'A'.repeat(32), '0'.repeat(31), '0'.repeat(33), 42, null, { x: 1 }]) {
    const action = { tool_kind: 'shell', tool_name: 'Bash', programs: ['npm'], truncated: true, tool_input: { command_sha256: 'f'.repeat(64), ...(exact === undefined ? {} : { exact_hmac: exact }) } };
    const [a, b] = withForgedAction(action, () => [corr(), corr()]);
    assert.notEqual(a, b, `exact_hmac ${JSON.stringify(exact)}`);
  }
});

test('T-2: a truncated action with a well-formed exact_hmac, and an untruncated action, keep one stable correlation', () => {
  const ok = { tool_kind: 'shell', tool_name: 'Bash', programs: ['npm'], truncated: true, tool_input: { command_sha256: 'f'.repeat(64), exact_hmac: '0123456789abcdef0123456789abcdef' } };
  const [a, b] = withForgedAction(ok, () => [corr(), corr()]);
  assert.equal(a, b);
  const plain = { tool_kind: 'shell', tool_name: 'Bash', programs: ['npm'], tool_input: { command_sha256: 'e'.repeat(64) } };
  const [c, d] = withForgedAction(plain, () => [corr(), corr()]);
  assert.equal(c, d);
  assert.notEqual(a, c);
});
