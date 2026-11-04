'use strict';
// D1d round 4 (the one extra test-only round, OWNER-DECISIONS-20261104 item 24 (a)): one test per SINGLE-COMMAND text and mode, through the same hook entry as test/d1d-compound.test.js.
// The round 2 tests for the count proof (I-A12), the mask (PP10), the `time` test and the loop-word test used command lists, which round 3's lone-command rule (src/seatbelt/mapper.ts:1513-1521,
// called at :1982) rejects before those clauses are read. Each text below is one simple command that rule accepts; master's answer for it is the unlowered one, so with any of the clauses
// broken the hook sends a lowered question (base_class) where master asks the original class. Expected: master a1bf437a0a13's answer (test/support/d1d-single-golden.json was recorded
// from master's built hook; this file also runs unchanged on master). No lowered question, master's call order, and master's answer bytes in both modes (allow, clear).
const assert = require('node:assert/strict');
const test = require('node:test');
const { runHook } = require('./support/d1d-hook-harness.cjs');
const { PINS, MODES, MASTER_CALLS, service, eventFor, callName, digestOf } = require('./support/d1d-single-pins.cjs');
const GOLDEN = require('./support/d1d-single-golden.json');

for (const pin of PINS) {
  for (const mode of MODES) {
    test(`PS ${pin.id} [${mode}] (${pin.plants.join(', ')}): ${JSON.stringify(pin.text)} asks master's original class and sends no lowered question`, async () => {
      const run = await runHook(service(mode), eventFor(pin.text));
      assert.equal(run.calls.some((c) => 'base_class' in c.body), false, `${pin.id}/${mode}: no base_class is sent (clause ${pin.clause})`);
      assert.deepEqual(run.calls.map(callName), MASTER_CALLS, `${pin.id}/${mode}: master's calls, in master's order`);
      assert.equal(digestOf(run), GOLDEN[`${pin.id}|${mode}`], `${pin.id}/${mode}: the stdout bytes and every call body equal master's recorded answer`);
    });
  }
}

test('PS: the pin table holds every lowering clause the lone-command rule hid, each text once, each with a recorded master answer in both modes', () => {
  const ids = PINS.map((p) => p.id);
  assert.equal(new Set(ids).size, ids.length, 'ids are unique');
  assert.equal(new Set(PINS.map((p) => p.text)).size, PINS.length, 'texts are unique');
  for (const plant of ['m02', 'm17', 'm26', 'm27', 'm28', 'm29', 'm30', 'm17+m328']) assert.ok(PINS.some((p) => p.plants.includes(plant)), `a pin for ${plant}`);
  for (const p of PINS) for (const mode of MODES) assert.match(GOLDEN[`${p.id}|${mode}`] || '', /^[0-9a-f]{64}$/, `${p.id}/${mode}: a recorded digest`);
  assert.equal(Object.keys(GOLDEN).length, PINS.length * MODES.length, 'no stale digest');
});
