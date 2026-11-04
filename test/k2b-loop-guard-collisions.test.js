'use strict';
// K2b (MCP-111): the loop guard fingerprint keeps every byte of a call. Rows are tested on the shipped dist (switch ON),
// on a mktemp copy with the one switch line set false (OFF = 3.9.110 byte for byte) and, when K2B_BASE_DIST names a
// 3.9.110 dist, on that one (the ACTUAL 3.9.110 column). Row names only: no fingerprint, receipt or secret is printed.
// kind D: the calls differ inside the caps, allowed everywhere. C: differ only past a cut, denied as a repeat on 3.9.110
// and OFF, allowed ON. E: equal by design or a true repeat, denied everywhere.
const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const h = require('./support/k2b-loop-guard.cjs');

const guards = h.variants();
const names = Object.keys(guards);
const P = 'p'.repeat(128);
const S = h.S16;
const big = (d) => BigInt(`1${'0'.repeat(299)}${d}`);
const allowedOn = (kind, name) => (name === 'on' ? kind !== 'E' : kind === 'D');
// RV rows at the result position: a stored cut hash still counts as unchanged once (the poll count continues across the upgrade), as master
const MERGED_RESULT = /^RV/;

// run a, record it, then consult b: the answer for b
function second(guard, a, b, extra = {}) {
  const home = h.world();
  try {
    assert.equal(guard.consultSessionLoopGuard(h.op(a, extra), { home }).allow, true);
    guard.recordSessionLoopOutcome(h.op(a, extra), true, { ok: true }, { home });
    return guard.consultSessionLoopGuard(h.op(b, extra), { home }).allow;
  } finally { h.rmSync(home, { recursive: true, force: true }); }
}
// poll thresholds are 2: the third consult is denied when the result did not change
function pollThird(guard, first, next) {
  const home = h.world();
  const poll = h.POLL();
  try {
    guard.consultSessionLoopGuard(poll, { home });
    guard.recordSessionLoopOutcome(poll, true, first, { home });
    guard.consultSessionLoopGuard(poll, { home });
    guard.recordSessionLoopOutcome(poll, true, next, { home });
    return guard.consultSessionLoopGuard(poll, { home }).allow;
  } finally { h.rmSync(home, { recursive: true, force: true }); }
}

const nfc = 'café';
const nfd = 'café';
const withKey = (key, value = 1) => ({ [key]: value, k000: 0 });
// [row, kind, first, second]
const PAIRS = [
  ['R1 string differs at unit 16,385', 'C', { command: `${S}A` }, { command: `${S}B` }],
  ['R2 key 129 differs', 'C', h.keysObject(129, 'a'), h.keysObject(129, 'b')],
  ['R3 item 129 differs', 'C', { list: h.itemsArray(129, 'a') }, { list: h.itemsArray(129, 'b') }],
  ['R4 key name differs past unit 128', 'C', { [`${P}A`]: 1 }, { [`${P}B`]: 1 }],
  ['R4b sibling value lost by key-name merge', 'C', { [`${P}A`]: 1, [`${P}B`]: 2 }, { [`${P}A`]: 3, [`${P}B`]: 2 }],
  ['R5 leaf at relative depth 8 differs', 'C', h.deepChain('a', 12), h.deepChain('b', 12)],
  ['R5b deep subtree, then the literal [depth]', 'C', h.deepChain('a', 7), { n: { n: { n: { n: { n: { n: { n: { leaf: '[depth]' } } } } } } } }],
  ['R6 bigint past 256 (unsupported: equal by design)', 'E', { v: big(1) }, { v: big(2) }],
  ['R6b undefined vs "undefined" (equal by design)', 'E', { v: undefined }, { v: 'undefined' }],
  ['R7 Infinity vs "Infinity"', 'C', JSON.parse('{"n":1e999}'), { n: 'Infinity' }],
  ['R7b NaN vs "NaN"', 'C', { n: Number.NaN }, { n: 'NaN' }],
  ['R8 Map with entries vs empty Map (equal by design)', 'E', { m: new Map([['a', 1]]) }, { m: new Map() }],
  ['B1a strings of 16,384 units differing at unit 16,384', 'D', { v: `${S.slice(1)}A` }, { v: `${S.slice(1)}B` }],
  ['B1b strings of 16,385 units differing at unit 16,385', 'C', { v: `${S}A` }, { v: `${S}B` }],
  ['B2a 128 items differing at item 128', 'D', { v: h.itemsArray(128, 'a') }, { v: h.itemsArray(128, 'b') }],
  ['B3a 128 keys, last sorted key differs', 'D', h.keysObject(128, 'a'), h.keysObject(128, 'b')],
  ['B4a key name of 128 units differs at its last unit', 'D', { [`${'q'.repeat(127)}A`]: 1 }, { [`${'q'.repeat(127)}B`]: 1 }],
  ['B5a leaf at relative depth 7 differs', 'D', h.deepChain('a', 6), h.deepChain('b', 6)],
  ['B5b leaf at relative depth 8 differs', 'C', h.deepChain('a', 7), h.deepChain('b', 7)],
  ['D2 NFC vs NFD within the cap', 'D', { v: nfc }, { v: nfd }],
  ['D2k NFC vs NFD key name past the 128-key cut', 'C', { ...h.keysObject(128, 0), [`z${nfc}`]: 1 }, { ...h.keysObject(128, 0), [`z${nfd}`]: 1 }],
  ['D3 NFC vs NFD past unit 16,384', 'C', { v: `${S}${nfc}` }, { v: `${S}${nfd}` }],
  ['D4 full-width vs ASCII within the cap', 'D', { v: 'ABC' }, { v: 'ＡＢＣ' }],
  ['D5 lone surrogate vs U+FFFD within the cap', 'D', { v: '\ud800' }, { v: '�' }],
  ['D5b lone surrogate vs U+FFFD past the cap', 'C', { v: `${S}\ud800` }, { v: `${S}�` }],
  ['D6 zero-width joiner within the cap', 'D', { v: 'ab' }, { v: 'a‍b' }],
  ['D6b zero-width joiner past the cap', 'C', { v: `${S}ab` }, { v: `${S}a‍b` }],
  ['D7 Latin vs Cyrillic homoglyph within the cap', 'D', { v: 'a' }, { v: 'а' }],
  ['D7b Latin vs Cyrillic homoglyph past the cap', 'C', { v: `${S}a` }, { v: `${S}а` }],
  ['D1 JSON 1 vs 1.0 vs 1e0 (one parsed number)', 'E', JSON.parse('{"n":1}'), JSON.parse('{"n":1.0e0}')],
  ['D1b JSON 2^53 vs 2^53+1 (one parsed number)', 'E', JSON.parse('{"n":9007199254740992}'), JSON.parse('{"n":9007199254740993}')],
  ['D1c 2^53 vs 2^53+1 past a cut (one parsed number)', 'E', { list: [...h.itemsArray(129, 0), JSON.parse('9007199254740992')] }, { list: [...h.itemsArray(129, 0), JSON.parse('9007199254740993')] }],
  ['G8 key order swapped', 'E', { a: 1, b: 2 }, { b: 2, a: 1 }],
  ['G9 -0 vs 0', 'E', { n: -0 }, { n: 0 }],
  ['K11-hole sparse hole vs null (equal as on 3.9.110)', 'E', { v: [1, , 3] }, { v: [1, null, 3] }], // eslint-disable-line no-sparse-arrays
  ['K20b-1 __proto__ key past the 128-key cut', 'C', JSON.parse(`{${Array.from({ length: 128 }, (_, i) => `"A${String(i).padStart(3, '0')}":0`).join(',')},"__proto__":{"a":1}}`), JSON.parse(`{${Array.from({ length: 128 }, (_, i) => `"A${String(i).padStart(3, '0')}":0`).join(',')},"__proto__":{"a":2}}`)],
  ['K20b-2 constructor key past the 128-key cut', 'C', { ...h.keysObject(128, 0, 'A'), constructor: 'a' }, { ...h.keysObject(128, 0, 'A'), constructor: 'b' }],
  ['RV1 uncut 16,384-unit string first, then 16,385 with that prefix (A1: a different call)', 'C', { v: S }, { v: `${S}A` }],
  ['RV3 "Infinity" first, then Infinity (A1: a different call)', 'C', { n: 'Infinity' }, JSON.parse('{"n":1e999}')],
  ['K4b-1 1 vs "1" past a cut (item 129)', 'C', { v: [...h.itemsArray(128, 0), 1] }, { v: [...h.itemsArray(128, 0), '1'] }],
  ['K4b-2 [1,[2]] vs [[1],2] past a cut', 'C', { v: [...h.itemsArray(128, 0), [1, [2]]] }, { v: [...h.itemsArray(128, 0), [[1], 2]] }],
  ['K4b-3 [12] vs [1,2] past a cut', 'C', { v: [...h.itemsArray(128, 0), [12]] }, { v: [...h.itemsArray(128, 0), [1, 2]] }],
  ['K4b-4 [] vs {} past a cut', 'C', { v: [...h.itemsArray(128, 0), []] }, { v: [...h.itemsArray(128, 0), {}] }],
  ['K4b-5 {"":null} vs {} past a cut', 'C', { v: [...h.itemsArray(128, 0), { '': null }] }, { v: [...h.itemsArray(128, 0), {}] }],
  ['K4b-6 one string holding "," vs the two strings it splits into, past a cut', 'C', { v: [...h.itemsArray(128, 0), ['a","b']] }, { v: [...h.itemsArray(128, 0), ['a', 'b']] }],
];
// a true repeat of the same (huge or odd) input
const REPEATS = [
  ['G1 repeat string past 16,384', { command: `${S}A` }], ['G2 repeat 129 keys', h.keysObject(129, 'a')],
  ['G3 repeat 129 items', { list: h.itemsArray(129, 'a') }], ['G4 repeat long key name', { [`${P}A`]: 1, [`${P}B`]: 2 }],
  ['G5 repeat deep object', h.deepChain('a', 12)], ['G6 repeat bigint past 256', { v: big(1) }],
  ['G7 repeat Infinity', JSON.parse('{"n":1e999}')], ['G10 repeat 1 MB string', { content: 'y'.repeat(1_048_576) }],
  ['G8m same Map object', { m: new Map([['a', 1]]) }],
];

for (const name of names) {
  for (const [row, kind, a, b] of PAIRS) {
    test(`[${name}] ${row}: toolInput pair (kind ${kind})`, () => {
      assert.equal(second(guards[name], a, b), allowedOn(kind, name), row);
    });
    test(`[${name}] ${row}: result pair (kind ${kind})`, () => {
      assert.equal(pollThird(guards[name], a, b), MERGED_RESULT.test(row) ? false : allowedOn(kind, name), row);
    });
  }
  for (const [row, input] of REPEATS) {
    test(`[${name}] ${row}: a true repeat is denied`, () => { assert.equal(second(guards[name], input, input), false, row); });
    test(`[${name}] ${row}: a poll with the same result is denied at the 3rd`, () => { assert.equal(pollThird(guards[name], input, input), false, row); });
  }
  test(`[${name}] K1-R10 a within-cap poll whose result changes resets the count (3 consults allowed)`, () => {
    const guard = guards[name];
    const home = h.world();
    const poll = h.POLL();
    try {
      const answers = [];
      for (let i = 0; i < 3; i += 1) {
        answers.push(guard.consultSessionLoopGuard(poll, { home }).allow);
        guard.recordSessionLoopOutcome(poll, true, { stdout: `run ${i}` }, { home });
      }
      assert.deepEqual(answers, [true, true, true]);
    } finally { h.rmSync(home, { recursive: true, force: true }); }
  });
  test(`[${name}] K1-G12 cyclic and very deep inputs are answered (no hang, no throw)`, () => {
    const cyclic = { v: 1 }; cyclic.self = cyclic;
    const home = h.world();
    try {
      assert.equal(typeof guards[name].consultSessionLoopGuard(h.op(cyclic), { home }).allow, 'boolean');
      assert.equal(typeof guards[name].consultSessionLoopGuard(h.op(h.deepChain(1, 10_000)), { home }).allow, 'boolean');
    } finally { h.rmSync(home, { recursive: true, force: true }); }
  });
}

// K1b: a build whose full walk always falls back (budget 0) merges R1; the shipped build splits it, and a real repeat is denied.
test('K1b self-test steps with a past-cap pair: the 2nd call is allowed and a true repeat is denied (ON); an always-fallback build fails it', () => {
  const guard = guards.on;
  assert.equal(second(guard, { command: `${S}A` }, { command: `${S}B` }), true);
  assert.equal(second(guard, { command: `${S}A` }, { command: `${S}A` }), false);
  const secret = h.secretValue();
  const arr = (v) => h.identityArray(h.op(v));
  const stats = { fallbacks: 0 };
  assert.equal(guard.loopFingerprint(secret, arr({ command: `${S}A` }), undefined, 0, stats).fp, guard.loopFingerprint(secret, arr({ command: `${S}B` }), undefined, 0, stats).fp);
  assert.equal(stats.fallbacks, 2);
  assert.notEqual(guard.loopFingerprint(secret, arr({ command: `${S}A` })).fp, guard.loopFingerprint(secret, arr({ command: `${S}B` })).fp);
  assert.equal(guard.runSessionLoopGuardSelfTest().pass, true);
});
test('K1b the OFF copy and the shipped dist both pass the installer self-test', () => {
  for (const name of ['on', 'off']) assert.equal(guards[name].runSessionLoopGuardSelfTest().repeat_denied, true, name);
});

// K8 / KO2: one switch, shipped ON, compile-time only; no path reaches it
test('K8 exactly one LOOP_GUARD_SPLIT definition, true, in src and in dist; read only in resolveLoopEntry and the result step; no process.env', () => {
  for (const file of ['src/session-loop-guard.ts', 'dist/session-loop-guard.js']) {
    const text = readFileSync(join(h.ROOT, file), 'utf8');
    assert.equal(text.split('const LOOP_GUARD_SPLIT = true;').length - 1, 1, file);
    assert.deepEqual([...text.matchAll(/LOOP_GUARD_SPLIT\s*=\s*(\w+)/g)].map((m) => m[1]), ['true'], file);
    assert.equal(/process\.env/.test(text), false, `${file} reads no env`);
    const reads = text.split('\n').filter((line) => line.includes('LOOP_GUARD_SPLIT') && !line.includes('const LOOP_GUARD_SPLIT'));
    assert.equal(reads.length, 2, `${file} reads the switch in resolveLoopEntry and the result step only`);
  }
});
test('KO2 the agent cannot flip the switch: env var, state file field, config file, tool-input field, hook payload field', () => {
  const guard = guards.on;
  const home = h.world();
  const saved = process.env.LOOP_GUARD_SPLIT;
  try {
    process.env.LOOP_GUARD_SPLIT = 'false';
    process.env.MARROW_LOOP_GUARD_SPLIT = 'false';
    h.seedHome(home, h.secretValue());
    const state = h.readStateFile(home);
    state.split = false; state.LOOP_GUARD_SPLIT = false; state.k2b = { off: true };
    require('node:fs').writeFileSync(join(home, '.marrow', 'session-loop-guard', 'state.json'), `${JSON.stringify(state)}\n`, { mode: 0o600 });
    require('node:fs').writeFileSync(join(home, '.marrow', 'config.json'), JSON.stringify({ LOOP_GUARD_SPLIT: false, loop_guard_split: false }), { mode: 0o600 });
    const forged = { command: `${S}A`, LOOP_GUARD_SPLIT: false, split: false, k2b: 'off', fingerprint: 'f'.repeat(64) };
    assert.equal(guard.consultSessionLoopGuard({ ...h.op(forged), LOOP_GUARD_SPLIT: false, split: false }, { home, LOOP_GUARD_SPLIT: false, split: false }).allow, true);
    guard.recordSessionLoopOutcome(h.op(forged), true, { ok: true }, { home });
    // the default stays ON: a differing pair past the cut is still split
    assert.equal(guard.consultSessionLoopGuard(h.op({ ...forged, command: `${S}B` }), { home }).allow, true);
  } finally {
    if (saved === undefined) delete process.env.LOOP_GUARD_SPLIT; else process.env.LOOP_GUARD_SPLIT = saved;
    delete process.env.MARROW_LOOP_GUARD_SPLIT;
    h.rmSync(home, { recursive: true, force: true });
  }
});
