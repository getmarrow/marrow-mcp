'use strict';
// K2b (MCP-111) owner rows: KO3/K19b (backstop at BACKSTOP_COUNT 4), KO4 (one extra run for a call that straddles the
// upgrade), KO5 (abuse rows), K14 (state growth), K5b (never stricter: lockstep sequences), AS1/AS2, K8-off, K13 kept parts.
// "3.9.110" below is the OFF copy (the switch line set false: 3.9.110 byte for byte, asserted by the K8-off row).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { join } = require('node:path');
const h = require('./support/k2b-loop-guard.cjs');

const { on, off } = h.variants();
const S = h.S16;
const pad = (i) => ({ command: `${S}${String(i).padStart(6, '0')}` });
const run = (guard, home, operation, success = true, result = { ok: 1 }) => {
  const d = guard.consultSessionLoopGuard(operation, { home });
  if (d.allow) guard.recordSessionLoopOutcome(operation, success, result, { home });
  return d;
};
const withHome = (fn) => { const home = h.world(); try { return fn(home); } finally { h.rmSync(home, { recursive: true, force: true }); } };
const entriesOf = (home) => Object.values(h.readStateFile(home).sessions).flatMap((s) => Object.values(s.entries));

const KINDS = [
  ['read', (input) => h.op(input), true, 1], ['verification', (input) => h.op(input, { toolName: 'Bash' }), true, 1],
  ['poll', (input) => h.POLL({ toolInput: input }), true, 2], ['failed mutation', (input) => h.FAILING(input), false, 2],
];
for (const [kind, make, success, masterRuns] of KINDS) {
  test(`K19b a padded ${kind} loop (same call, changing junk past a cut): ON runs exactly 4 times and the 5th is denied by the family receipt; OFF as 3.9.110`, () => {
    const count = (guard) => withHome((home) => {
      let runs = 0; let denied;
      for (let i = 0; i < 12; i += 1) {
        const operation = make(kind === 'verification' ? { command: `npm test ${S}${i}` } : kind === 'poll' ? { command: `gh run view --status ${S}${i}` } : pad(i));
        const d = run(guard, home, operation, success, { out: 'same' });
        if (!d.allow) { denied = d; break; }
        runs += 1;
      }
      assert.ok(denied, 'a padded loop is stopped');
      if (guard === on) assert.ok(entriesOf(home).some((e) => e.receipt === denied.receipt && e.fingerprint !== denied.fingerprint), 'the backstop denies with the family entry receipt');
      return runs;
    });
    assert.equal(count(on), 4);
    assert.equal(count(off), masterRuns);
  });
}
test('K19b a change inside the caps resets the family (as master); a mutation success wipes the family and split entries', () => withHome((home) => {
  for (let i = 0; i < 3; i += 1) assert.equal(run(on, home, h.op(pad(i)), true, { out: 'same' }).allow, true);
  assert.equal(run(on, home, h.op(pad(3)), true, { out: 'changed' }).allow, true); // result changed inside the cut: count resets
  for (let i = 4; i < 7; i += 1) assert.equal(run(on, home, h.op(pad(i)), true, { out: 'changed' }).allow, true);
  assert.equal(run(on, home, h.op(pad(7)), true, { out: 'changed' }).allow, false);
  run(on, home, h.FAILING({ patch: 'x' }), true, { changed: true });
  assert.equal(entriesOf(home).length, 0);
  assert.equal(run(on, home, h.op(pad(8)), true, { out: 'same' }).allow, true);
}));
test('K8-off with the switch OFF the state bytes, receipts and answers equal 3.9.110 for uncut calls; no family entry or backstop mapping is ever written', () => {
  const answers = {};
  for (const [name, guard] of [['on', on], ['off', off]]) {
    answers[name] = withHome((home) => {
      h.seedHome(home, 'C'.repeat(43));
      const out = [];
      for (let i = 0; i < 6; i += 1) { const d = run(guard, home, h.op({ command: `ls ${i % 3}` }, { invocationId: `inv${i}` }), true, { n: i % 2 }); out.push(d.allow, d.receipt); }
      return JSON.stringify([out, h.stateBytes(home).replace(/"updated_at":\d+/g, '')]);
    });
  }
  assert.equal(answers.on, answers.off, 'ON keeps the 3.9.110 bytes for uncut calls');
  withHome((home) => {
    run(off, home, h.op(pad(1)), true, { a: 1 }); run(off, home, h.op(pad(2), { invocationId: 'x' }), true, { a: 1 });
    assert.equal(entriesOf(home).length, 1);
    assert.equal(Object.keys(Object.values(h.readStateFile(home).sessions)[0].invocations).length, 0); // the denied repeat wrote nothing, so no mapping of any kind
  });
});

// ---- KO4: a call that straddles the upgrade gets exactly one extra run ----
function straddle(operationFor, firstRuns, success = true) {
  return withHome((home) => {
    h.seedHome(home, 'D'.repeat(43));
    for (let i = 0; i < firstRuns; i += 1) assert.equal(run(off, home, operationFor(), success, { out: 'same' }).allow, true);
    let extra = 0;
    for (let i = 0; i < 6; i += 1) { if (run(on, home, operationFor(), success, { out: 'same' }).allow) extra += 1; else break; }
    return { extra, master: withHome((m) => { h.seedHome(m, 'D'.repeat(43)); for (let i = 0; i < firstRuns; i += 1) run(off, m, operationFor(), success, { out: 'same' }); let r = 0; for (let i = 0; i < 6; i += 1) { if (run(off, m, operationFor(), success, { out: 'same' }).allow) r += 1; else break; } return r; }) };
  });
}
test('KO4 a lossy call recorded by 3.9.110 gets exactly one extra run (read, verification, poll count 2 and failure); within-cap calls get none', () => {
  const lossy = () => h.op({ command: `${S}A` });
  assert.deepEqual(straddle(lossy, 1), { extra: 1, master: 0 });
  assert.deepEqual(straddle(() => h.op({ command: `npm test ${S}A` }, { toolName: 'Bash' }), 1), { extra: 1, master: 0 });
  assert.deepEqual(straddle(() => h.POLL({ toolInput: { command: `gh run view --status ${S}A` } }), 2), { extra: 1, master: 0 });
  assert.deepEqual(straddle(() => h.FAILING({ patch: `${S}A` }), 2, false), { extra: 1, master: 0 });
  // count 1 poll: master still allows the 2nd run, so nothing extra; the count continues and the 3rd is denied
  assert.deepEqual(straddle(() => h.POLL({ toolInput: { command: `gh run view --status ${S}A` } }), 1), { extra: 1, master: 1 });
  // within the cap: byte-equal to master, no extra run
  assert.deepEqual(straddle(() => h.op({ command: 'ls -la' }), 1), { extra: 0, master: 0 });
  assert.deepEqual(straddle(() => h.op({ command: S }), 1), { extra: 0, master: 0 }, 'an exact-cap string is not lossy');
});
test('KO5 (a) a downgrade then a re-upgrade, a reinstall (a fresh module) and a second process grant no new extra run', () => withHome((home) => {
  h.seedHome(home, 'E'.repeat(43));
  const lossy = () => h.op({ command: `${S}A` });
  run(off, home, lossy());
  assert.equal(run(on, home, lossy()).allow, true); // the one extra run
  assert.equal(run(off, home, lossy()).allow, false); // downgrade: 3.9.110 denies the repeat
  assert.equal(run(on, home, lossy()).allow, false); // re-upgrade
  const fresh = require('node:child_process').execFileSync(process.execPath, ['-e', `const g=require(${JSON.stringify(join(h.ROOT, 'dist', 'session-loop-guard.js'))});const d=g.consultSessionLoopGuard(${JSON.stringify(lossy())},{home:${JSON.stringify(home)}});process.stdout.write(String(d.allow))`], { encoding: 'utf8' });
  assert.equal(fresh, 'false', 'a second process on the same state');
}));
test('KO5 (b) forged straddle: a forged version or field is refused as on 3.9.110; a forged valid entry gives one run per entry (the stated residual, never more than deleting the entry on 3.9.110)', () => {
  for (const guard of [on, off]) withHome((home) => {
    h.seedHome(home, 'F'.repeat(43));
    const file = join(home, '.marrow', 'session-loop-guard', 'state.json');
    for (const mutate of [(s) => { s.version = 2; }, (s) => { s.sessions = { bad: {} }; }]) {
      const state = h.readStateFile(home); mutate(state);
      fs.writeFileSync(file, `${JSON.stringify(state)}\n`, { mode: 0o600 });
      assert.throws(() => guard.consultSessionLoopGuard(h.op({ a: 1 }), { home }), /unsafe or invalid/);
    }
  });
  withHome((home) => {
    const { secret } = h.seedHome(home, 'G'.repeat(43));
    const operation = h.op({ command: `${S}A` });
    const id = h.identity110(secret, operation);
    const sessionKey = h.keyedHash110(secret, ['session', operation.sessionId, operation.agentId, operation.harness]);
    const forged = { fingerprint: id, kind: 'read', outcome: 'success', result_hash: null, unchanged_count: 9, attempts: 9, updated_at: Date.now(), receipt: `lgr_${'a'.repeat(24)}` };
    const state = h.readStateFile(home);
    state.sessions[sessionKey] = { work_epoch: 0, instruction_epoch: 0, updated_at: Date.now(), entries: { [id]: forged }, invocations: {} };
    fs.writeFileSync(join(home, '.marrow', 'session-loop-guard', 'state.json'), `${JSON.stringify(state)}\n`, { mode: 0o600 });
    assert.equal(off.consultSessionLoopGuard(operation, { home }).allow, false, '3.9.110 denies the forged entry');
    assert.equal(run(on, home, operation).allow, true, 'one run for the forged entry');
    assert.equal(run(on, home, operation).allow, false);
  });
});
test('KO5 (c) no second extra run: another session, a prune, a crash between the run and the state write; (d) a non-straddling call gets none', () => withHome((home) => {
  h.seedHome(home, 'H'.repeat(43));
  const lossy = (extra = {}) => h.op({ command: `${S}A` }, extra);
  run(off, home, lossy());
  // a crash after the run is allowed but before the state write: the consult fails, nothing is allowed, nothing is granted
  const rename = fs.renameSync; let failed = 0;
  fs.renameSync = (...args) => { failed += 1; throw new Error('crash'); };
  try { assert.throws(() => on.consultSessionLoopGuard(lossy(), { home }), /unsafe|crash/); } finally { fs.renameSync = rename; }
  assert.equal(failed, 1);
  assert.equal(run(on, home, lossy()).allow, true, 'the retry gets the one extra run');
  assert.equal(run(on, home, lossy()).allow, false);
  // another session: first seen by the new version, so it runs once (as master) and is then denied
  assert.equal(run(on, home, lossy({ sessionId: 'other' })).allow, true);
  assert.equal(run(on, home, lossy({ sessionId: 'other' })).allow, false);
  // (d) first seen by the new version: one run, no extra, equal to master
  withHome((fresh) => {
    for (const guard of [on, off]) { const m = h.world(); try { assert.equal(run(guard, m, lossy()).allow, true); assert.equal(run(guard, m, lossy()).allow, false); } finally { h.rmSync(m, { recursive: true, force: true }); } }
    assert.ok(fresh);
  });
  // a prune: 300 newer entries evict the old ones; the call is fresh on master too (same answers)
  const afterPrune = (guard) => withHome((p) => {
    h.seedHome(p, 'I'.repeat(43));
    run(off, p, lossy());
    if (guard === on) run(on, p, lossy());
    for (let i = 0; i < 300; i += 1) run(guard, p, h.op({ command: `junk ${i}` }), true, { n: i });
    return [run(guard, p, lossy()).allow, run(guard, p, lossy()).allow];
  });
  assert.deepEqual(afterPrune(on), afterPrune(off));
}));

// ---- AS1 / AS2 / K5b: never stricter than master ----
test('AS1 two polls differing only past a cut, run alternately, each with a steady result: never denied (as master)', () => {
  for (const guard of [off, on]) withHome((home) => {
    const a = () => h.POLL({ toolInput: { command: `gh run view --status ${S}A` } }); const b = () => h.POLL({ toolInput: { command: `gh run view --status ${S}B` } });
    for (let i = 0; i < 6; i += 1) { assert.equal(run(guard, home, a(), true, { v: 'A' }).allow, true, `A${i}`); assert.equal(run(guard, home, b(), true, { v: 'B' }).allow, true, `B${i}`); }
  });
});
test('AS2 uncut sibling run twice, a split sibling with the same cut result, then the uncut one: denied as master', () => {
  for (const guard of [off, on]) withHome((home) => {
    const u = () => h.POLL({ toolInput: { command: `gh run view --status ${S}`.slice(0, 16_384) } });
    const y = () => h.POLL({ toolInput: { command: `${`gh run view --status ${S}`.slice(0, 16_384)}Y` } });
    run(guard, home, u()); run(guard, home, u());
    run(guard, home, y());
    assert.equal(guard.consultSessionLoopGuard(u(), { home }).allow, false, guard === on ? 'on' : 'off');
  });
});
for (const seed of [7, 11]) {
  test(`K5b seed ${seed}: lockstep sequences of calls that differ only past a cut: no ON deny where 3.9.110 allows`, () => {
    const r = h.rng(seed);
    let checked = 0; let diverged = 0;
    for (let n = 0; n < 500; n += 1) {
      const kind = n % 4; const calls = 2 + (n % 3);
      const input = (i) => (kind === 2 ? { command: `gh run view --status ${S}${i}` } : kind === 1 ? { command: `npm test ${S}${i}` } : { command: `${S}${i}` });
      const make = (i) => (kind === 3 ? h.FAILING(input(i)) : kind === 2 ? h.POLL({ toolInput: input(i) }) : h.op(input(i), kind === 1 ? { toolName: 'Bash' } : {}));
      const homes = [h.world(), h.world()];
      try {
        h.seedHome(homes[0], 'J'.repeat(43)); h.seedHome(homes[1], 'J'.repeat(43));
        const steps = 6 + Math.floor(r() * 7);
        for (let s = 0; s < steps; s += 1) {
          const operation = make(Math.floor(r() * (calls + 1)) % (calls + 1) === calls ? 'U' : Math.floor(r() * calls));
          const ok = r() < 0.7; const result = { v: Math.floor(r() * 2) };
          const dOn = on.consultSessionLoopGuard(operation, { home: homes[0] });
          const dOff = off.consultSessionLoopGuard(operation, { home: homes[1] });
          checked += 1;
          assert.ok(!(dOn.allow === false && dOff.allow === true), `ON denied where 3.9.110 allows (seed ${seed}, sequence ${n}, step ${s})`);
          if (dOn.allow !== dOff.allow) { diverged += 1; break; } // A1: a past-cut difference is not a repeat; the worlds differ from here
          if (dOn.allow) { on.recordSessionLoopOutcome(operation, ok, result, { home: homes[0] }); off.recordSessionLoopOutcome(operation, ok, result, { home: homes[1] }); }
        }
      } finally { for (const home of homes) h.rmSync(home, { recursive: true, force: true }); }
    }
    assert.ok(checked > 2000);
    assert.ok(diverged > 0);
  });
}

// ---- K14: growth stays inside 256 entries, 256 mappings and 256 KiB ----
test('K14 a 600-call padded loop interleaved with 600 junk-split calls: entries <= 256, mappings <= 256, file <= 256 KiB, no unsafe()', () => withHome((home) => {
  for (let i = 0; i < 600; i += 1) {
    run(on, home, h.op(pad(i), { invocationId: `p${i}` }), true, { out: 'same' });
    run(on, home, h.op({ command: `${S}${i}`, junk: `${S}${i}` }, { invocationId: `j${i}` }), true, { out: `r${i}` });
  }
  const state = h.readStateFile(home);
  const session = Object.values(state.sessions)[0];
  assert.ok(Object.keys(session.entries).length <= 256);
  assert.ok(Object.keys(session.invocations).length <= 256);
  assert.ok(Buffer.byteLength(h.stateBytes(home)) <= 256 * 1024);
  assert.equal(typeof on.consultSessionLoopGuard(h.op({ command: 'after' }), { home }).allow, 'boolean'); // validateState passes
  for (const entry of Object.values(session.entries)) assert.match(entry.receipt, /^lgr_[a-f0-9]{24}$/);
}));
test('K13 kept parts: a within-cap repeat keeps count and receipt; an ON state is read by 3.9.110 (validateState passes) and 3.9.110 reads its own back', () => withHome((home) => {
  h.seedHome(home, 'K'.repeat(43));
  const same = () => h.op({ command: 'ls' });
  const first = run(off, home, same());
  assert.equal(run(on, home, same()).allow, false);
  for (let i = 0; i < 6; i += 1) run(on, home, h.op(pad(i), { invocationId: `d${i}` }), true, { out: 'same' });
  assert.equal(off.consultSessionLoopGuard(h.op({ command: 'other' }), { home }).allow, true, 'downgrade: 3.9.110 validates the ON state');
  assert.equal(on.consultSessionLoopGuard(same(), { home }).receipt, first.receipt);
}));
