'use strict';
// Approval key for data a command reads: actions that differ anywhere outside a
// secret get different keys, actions that differ only in the secret match, and
// no 8-character slice of the secret is in the key or the normalized form.
// Dummy secrets are generated at runtime and never printed.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const { normalizedHookAction, normalizeShellCommand } = require('../dist/normalized-action.js');
const { DATA_CASES } = require('./support/data-collision-cases.cjs');

const SECRETS = [
  () => `Dm${crypto.randomBytes(14).toString('hex')}`,
  () => crypto.randomBytes(18).toString('base64').replace(/[+/=]/g, 'x'),
];

function slices(text, secret) {
  let found = 0;
  for (let i = 0; i + 8 <= secret.length; i += 1) if (text.includes(secret.slice(i, i + 8))) found += 1;
  return found;
}

const keyOf = (event) => JSON.stringify(normalizedHookAction(event));
const hashedForm = (event) => (event.tool_name === 'Bash' ? normalizeShellCommand(event.tool_input.command).text : '');

test('data collision cases cover at least 30 action pairs', () => {
  assert.ok(DATA_CASES.length >= 30);
});

for (const testCase of DATA_CASES) {
  test(`approval key: ${testCase.path}`, () => {
    for (const secret of testCase.keyShapedOnly ? SECRETS.slice(0, 1) : SECRETS) {
      const s1 = secret();
      const s2 = secret();
      const staging = testCase.build(s1, 'staging');
      const production = testCase.build(s1, 'production');
      const otherSecret = testCase.build(s2, 'staging');
      const [a, b, c] = [staging, production, otherSecret].map(keyOf);
      if (testCase.feedsSecrets) {
        assert.equal(a, b, 'data fed to a secrets command is all secret');
      } else {
        assert.notEqual(a, b, 'actions that differ outside the secret get different keys');
      }
      assert.equal(a, c, 'actions that differ only in the secret get the same key');
      assert.equal(normalizedHookAction(staging).truncated, true, 'an action that carried a secret never binds');
      assert.equal(slices(a + b, s1), 0, 'no slice of the secret is in the key');
      assert.equal(slices(c, s2), 0, 'no slice of the secret is in the key');
      assert.equal(slices(hashedForm(staging) + hashedForm(production), s1), 0, 'no slice of the secret is in the hashed form');
    }
  });
}

test('data without a secret keeps its 3.9.102 marker', () => {
  const plain = normalizeShellCommand(`echo '{"env":"production"}' | post`).text;
  assert.match(plain, /^echo \[data:[0-9a-f]{64}\] \| post$/);
  const secret = normalizeShellCommand(`echo '{"api_key":"Dm${crypto.randomBytes(14).toString('hex')}","env":"production"}' | post`).text;
  assert.match(secret, /^echo \[secret-data:[0-9a-f]{64}\] \| post$/);
});
