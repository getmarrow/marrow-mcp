const assert = require('node:assert/strict');
const test = require('node:test');
const { randomBytes } = require('node:crypto');
const { normalizedHookAction, normalizeShellCommand } = require('../dist/normalized-action.js');
const { COLLISION_CASES } = require('./support/normalized-collision-cases.cjs');

// Dummy secrets generated at runtime; none is printed.
// Two shapes: a password-like value (found only by its place) and a key-shaped one.
const SHAPES = [
  () => `pw-${randomBytes(6).toString('hex')}`,
  () => `Zq9${randomBytes(12).toString('hex')}X`,
];

function keyOf(input) {
  return input.kind === 'mcp'
    ? normalizedHookAction({ tool_name: input.tool, tool_input: input.input })
    : normalizedHookAction({ tool_name: 'Bash', tool_input: { command: input.command } });
}

test('collision matrix: actions that differ only after a redacted span get different keys; only-the-secret variants stay equal; the secret never appears', () => {
  for (const secret of SHAPES) for (const testCase of COLLISION_CASES) {
    const first = secret();
    const second = secret();
    const a = testCase.build(first, testCase.values[0]);
    const b = testCase.build(first, testCase.values[1]);
    const sameAction = testCase.build(second, testCase.values[0]);
    const keyA = keyOf(a);
    const keyB = keyOf(b);
    const keySame = keyOf(sameAction);
    const label = `${testCase.path}: ${testCase.pair}`;
    if (testCase.secretOnly) {
      assert.deepEqual(keyA.tool_input, keyB.tool_input, `${label}: the same action`);
    } else if (testCase.afterEqual) {
      assert.ok(testCase.why, `${label}: an equal pair names its reason`);
      if (testCase.truncatedExpected) assert.equal(keyA.truncated, true, `${label}: withheld and never binds`);
    } else {
      assert.notDeepEqual(keyA.tool_input, keyB.tool_input, `${label}: differ after the secret, keys must differ`);
    }
    assert.deepEqual(keyA.tool_input, keySame.tool_input, `${label}: differ only in the secret, keys stay equal`);
    for (const [input, value] of [[a, first], [b, first], [sameAction, second]]) {
      const key = keyOf(input);
      assert.equal(JSON.stringify(key).includes(value), false, `${label}: the secret is not in the key`);
      if (input.kind !== 'mcp') assert.equal(normalizeShellCommand(input.command).text.includes(value), false, `${label}: the secret is not in the hashed form`);
    }
  }
});
