'use strict';

// Test-only (never ships). Dummy secrets for tests that compare two actions which differ only in a secret and expect
// one key. Made at run time; none is a real credential and none is ever printed or named in a message.
//
// A random base64url value reads as a key about once in 2,000 draws: `sk_` (or `rk_`, `pk_`) followed by 12 key characters,
// at the start or after a `-` / `_`. src/key-class.ts calls such an unknown-prefix token live on purpose (fail closed), the
// action gets `[secret-live]`, the sibling with another draw stays `[secret]`, and the two keys differ. The fix is here, not in
// the classifier: a fixed prefix that is not a key prefix, then lowercase hex. Hex holds no s, r, p, k, `_` or `-`, so no draw
// can hold a key-shaped token whatever sits next to it. The leading letter keeps the value from reading as a flag.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { keyClassOf } = require('../../dist/key-class.js');

const PREFIX = 'zq';
// What a test may put right before a secret inside the span a redactor replaces (UNKNOWN_TOKEN needs a non-alphanumeric
// before `sk_`). The empty string is the draw on its own.
const BEFORE = ['', '-', '_', ':', '=', '/', '@', ' '];
const hex = (bytes) => crypto.randomBytes(bytes).toString('hex');

// The classifier must be the real one: a missing or stubbed `keyClassOf` would make every check below pass for nothing.
assert.equal(typeof keyClassOf, 'function', 'dist/key-class.js must export keyClassOf (run npm run build)');
assert.equal(keyClassOf(`${['s', 'k'].join('')}_${hex(6)}`), 'live', 'the classifier calls an unknown sk_ token live');

/** Throws unless `value` carries no key class in any delimiter context (null = no class: the plain `[secret]` marker). */
function assertNotLiveKey(value) {
  for (const before of BEFORE) {
    assert.equal(keyClassOf(`${before}${value}`), null, `a dummy secret reads as a key class after ${JSON.stringify(before)}`);
  }
  return value;
}

/** A fixed non-key prefix and hex from `bytes` random bytes; every draw is checked against the classifier. */
const dummySecret = (bytes = 16) => assertNotLiveKey(`${PREFIX}${hex(bytes)}`);

module.exports = { dummySecret, assertNotLiveKey, PREFIX, BEFORE };
