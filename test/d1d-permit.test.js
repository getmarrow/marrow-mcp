'use strict';
// D1d round 2, PP3 (audit F1 / plant m25): the permit requirement of a HELD answer to the lowered question.
// When the service holds or blocks the lowered question, the hook's control path returns that answer with `protectedRisk` = the requirement of the ORIGINAL class
// (`probeVerdict ? enforcementRequired : false`). The final hook output cannot show it: a review or block verdict is denied through runtimeGateVerdict before
// protectedRisk is read, on every host. So this test reads the decision the control path builds (the object the hook turns into its answer), not stdout.
const assert = require('node:assert/strict');
const test = require('node:test');
const path = require('node:path');
const { runHook, allow, review, block, protectedPath, hashOf } = require('./support/d1d-hook-harness.cjs');

const ROOT = path.resolve(__dirname, '..');
const ev = (command) => ({ session_id: 's1', tool_use_id: 't1', tool_name: 'Bash', tool_input: { command }, cwd: ROOT });
const names = (run) => run.calls.map((c) => c.pathname.replace('/v1/agent/', '') + (c.body.operation ? `:${c.body.operation}` : ''));
const clearFor = (b) => ({ decline_check: { state: 'clear', action: hashOf(b.normalized_action) } });
// master asks this one (a `git grep` pattern with a shipping word is a protected class), and the port has a lowered candidate for it
const LOWERABLE = "git grep -c 'deploy' main";
// master asks this one too, with no lowered candidate: the requirement the original class carries on its own control path
const NOT_LOWERABLE = "git grep -c 'deploy' main; git push origin main";

// The hook awaits Promise.race([control(signal), timer]) (withTimeout): every value that settles with the shape of a control result is kept, unchanged.
async function withControlResults(fn) {
  const original = Promise.race;
  const seen = [];
  Promise.race = function race(iterable) {
    const list = Array.from(iterable);
    for (const p of list) {
      Promise.resolve(p).then((v) => { if (v && typeof v === 'object' && 'protectedRisk' in v && 'permit' in v && 'runtime' in v) seen.push(v); }, () => {});
    }
    return original.call(Promise, list);
  };
  try {
    return { run: await fn(), seen };
  } finally {
    Promise.race = original;
  }
}

test('PP3/F1: a held answer to the lowered question keeps the permit requirement of the original class; a cleared one has none', async () => {
  // the original class: block on master's own path carries the requirement
  const base = await withControlResults(() => runHook((p, b) => (p === '/v1/agent/runtime' ? block() : protectedPath(p, b)), ev(NOT_LOWERABLE)));
  assert.equal(base.seen.length, 1);
  assert.equal(base.seen[0].protectedRisk, true, 'master: a blocked protected class requires a permit');

  for (const [name, answer, decision] of [['block', block, 'block'], ['review', review, 'review_required']]) {
    const held = await withControlResults(() => runHook((p, b) => (p === '/v1/agent/runtime' ? answer() : protectedPath(p, b)), ev(LOWERABLE)));
    // the lowered question was asked (once), and no permit step ran: the answer is the hold itself
    assert.deepEqual(names(held.run), ['runtime'], name);
    assert.ok(held.run.calls[0].body.base_class, `${name}: the lowered question carried base_class`);
    assert.equal(held.seen.length, 1, name);
    const decisionBuilt = held.seen[0];
    assert.equal(decisionBuilt.runtime.risk_gate.decision, decision, name);
    assert.equal(decisionBuilt.permit, null, `${name}: no permit is issued on a held answer`);
    assert.equal(decisionBuilt.protectedRisk, true, `${name}: the held answer to the lowered question keeps the permit requirement of the original class`);
    assert.equal(decisionBuilt.protectedRisk, base.seen[0].protectedRisk, `${name}: as the original class would carry`);
    // and the hook denies, as master does
    assert.match(held.run.output, /deny/, name);
  }

  // a bound clearance is the only answer that takes the requirement away
  const cleared = await withControlResults(() => runHook((p, b) => (p === '/v1/agent/runtime' ? allow(clearFor(b)) : protectedPath(p, b)), ev(LOWERABLE)));
  assert.deepEqual(names(cleared.run), ['runtime']);
  assert.equal(cleared.seen.length, 1);
  assert.equal(cleared.seen[0].protectedRisk, false, 'a cleared lowering has no permit requirement');
  assert.equal(cleared.seen[0].permit, null);

  // an answer that is neither held nor cleared is never acted on: the original class is asked next (master's path), whose own requirement stands
  const plain = await withControlResults(() => runHook((p, b) => (p === '/v1/agent/runtime' ? allow() : protectedPath(p, b)), ev(LOWERABLE)));
  assert.deepEqual(names(plain.run), ['runtime', 'runtime', 'think', 'enforcement:issue', 'enforcement:verify']);
  assert.equal(plain.seen.length, 1);
  assert.equal(plain.seen[0].protectedRisk, true);
  assert.equal(plain.seen[0].permit.verified, true);
});
