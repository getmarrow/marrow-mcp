'use strict';
// K4 and K3 (MCP-111 K2b), seed 7: 20,400 pairs that differ only past one cap (each cap x position of the difference x value type
// x nesting 0-3), at the toolInput and the result position: equal on 3.9.110 (frozen copy) and OFF, all differ ON; and 20,400 true repeats equal.
const test = require('node:test');
const assert = require('node:assert/strict');
const h = require('./support/k2b-loop-guard.cjs');
const { CAPS, pastCapPair } = require('./support/k2b-k4.cjs');

const guards = h.variants();
const on = guards.on;
const secret = h.secretValue();
const arr = (v) => h.identityArray(h.op(v));

test('K4 seed 7: 20,400 past-cap pairs per position, ON all differ and keep the 3.9.110 cut; K3 20,400 true repeats equal', () => {
  const r = h.rng(7);
  let pairs = 0;
  for (let n = 0; n < 20_400; n += 1) {
    const cap = CAPS[n % CAPS.length];
    const [a, b] = pastCapPair(r, cap, Math.floor(n / CAPS.length) % 3, Math.floor(n / 18) % 3, Math.floor(n / 54) % 4);
    const legacyA = h.identity110(secret, h.op(a));
    assert.equal(legacyA, h.identity110(secret, h.op(b)), `legacy ${cap}`);
    const resultA = h.keyedHash110(secret, ['result', h.canonical110(a)]);
    assert.equal(resultA, h.keyedHash110(secret, ['result', h.canonical110(b)]), `legacy result ${cap}`);
    const fa = on.loopFingerprint(secret, arr(a)); const fb = on.loopFingerprint(secret, arr(b));
    assert.equal(fa.cut, legacyA, `ON cut is the 3.9.110 bytes ${cap}`);
    assert.equal(fb.cut, legacyA, `cut ${cap}`);
    assert.notEqual(fa.fp, fb.fp, `ON differs ${cap}`);
    assert.equal(fa.split, true);
    const ra = on.loopFingerprint(secret, ['result', a]); const rb = on.loopFingerprint(secret, ['result', b]);
    assert.equal(ra.cut, resultA);
    assert.notEqual(ra.fp, rb.fp, `ON result differs ${cap}`);
    const clone = structuredClone(a);
    assert.equal(on.loopFingerprint(secret, arr(clone)).fp, fa.fp, `repeat ${cap}`);
    assert.equal(on.loopFingerprint(secret, ['result', clone]).fp, ra.fp, `result repeat ${cap}`);
    pairs += 1;
  }
  assert.equal(pairs, 20_400);
});
test('K3 seed 7: a sample of true repeats is denied through the guard, OFF and ON', () => {
  const r = h.rng(7 + 1000);
  for (const name of ['on', 'off']) {
    const home = h.world();
    try {
      for (let n = 0; n < 300; n += 1) {
        const [a] = pastCapPair(r, CAPS[n % CAPS.length], n % 3, n % 3, n % 4);
        assert.equal(guards[name].consultSessionLoopGuard(h.op(a, { sessionId: `k3-${n}` }), { home }).allow, true);
        guards[name].recordSessionLoopOutcome(h.op(a, { sessionId: `k3-${n}` }), true, { ok: 1 }, { home });
        assert.equal(guards[name].consultSessionLoopGuard(h.op(structuredClone(a), { sessionId: `k3-${n}` }), { home }).allow, false, `${name} ${n}`);
      }
    } finally { h.rmSync(home, { recursive: true, force: true }); }
  }
});
