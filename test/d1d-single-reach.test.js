'use strict';
// D1d round 4 (the one extra test-only round, OWNER-DECISIONS-20261104 item 24 (a)): for each single-command pin of test/d1d-single-command.test.js, the mapper and the label show that the text
// passes the lone-command rule (src/seatbelt/mapper.ts:1513-1521, called at :1982) and reaches the clause the pin covers. The hook pins are the behavioural ones; these say why each text is
// a pin and not another list that an earlier check rejects. Tip only (master has no slice record). The mapper's own decision is asserted beside the mirror of the rule, so a drift shows.
const assert = require('node:assert/strict');
const test = require('node:test');
const { classifyTool } = require('../dist/hook-pre-action.js');
const mapper = require('../dist/seatbelt/mapper.js');
const { parseShell } = require('../vendor/classifier/shell-parse.js');
const { PINS } = require('./support/d1d-single-pins.cjs');

const CWD = '/work/repo';
const decisionOf = (command) => mapper.evaluateSeatbeltShell(command, { cwd: CWD, home: '/home/u', tmpdir: '/tmp', platform: 'linux', dataSlots: true,
  fs: { readFile: () => null, realpath: () => null, readdir: () => null }, git: { toplevel: () => null, getAll: () => [], currentBranch: () => null, remoteHead: () => null } });
const ev = (command) => ({ session_id: 's1', tool_use_id: 't1', tool_name: 'Bash', tool_input: { command }, cwd: CWD });
// The lone-command rule (mapper.ts:1513-1521) read from the vendored parser's output: one command, no substitution, group, pipe or background, and its first word is the first word of the text.
const loneRule = (src) => {
  const parsed = parseShell(src);
  const c = parsed.commands.length === 1 ? parsed.commands[0] : null;
  if (!c || c.words.length === 0 || parsed.substitutions.length > 0 || c.subshell || c.pipedInput || c.pipesOutput || c.background || c.forLoop) return false;
  let i = 0;
  for (let ch = src[i]; ch === ' ' || ch === '\t' || ch === '\r' || ch === '\n' || ch === '#'; ch = src[i]) i = ch === '#' ? (src.indexOf('\n', i) < 0 ? src.length : src.indexOf('\n', i)) : i + 1;
  const next = src[i + c.words[0].text.length];
  return c.words[0].text.length > 0 && src.startsWith(c.words[0].text, i) && (next === undefined || next === ' ' || next === '\t' || next === '\n');
};
const occurrences = (text, word) => (text.match(new RegExp(`\\b${word}\\b`, 'gi')) || []).length;

for (const pin of PINS) {
  test(`PS-reach ${pin.id} (${pin.plants.join(', ')}): ${JSON.stringify(pin.text)} reaches the clause at ${pin.clause} and has no lowered candidate`, () => {
    const d = decisionOf(pin.text);
    assert.equal(d.parse, 'ok', 'the parser reads the text');
    if (pin.kind === 'time-keyword') {
      // The keyword `time` before the program: the parser drops it, so the first-word check is the layer that holds it (mapper.ts:1513-1521, the m328 layer).
      assert.equal(loneRule(pin.text), false, 'the first word of the text is not the program');
      assert.equal(d.slice.ok, false, 'a bad slice');
    } else {
      assert.equal(loneRule(pin.text), true, 'one simple command: the lone-command rule accepts the text');
      if (pin.kind === 'loop') {
        assert.equal(d.slice.ok, false, 'only the loop-word check (mapper.ts:1508-1509, :1982) makes the slice bad');
        assert.equal(d.slice.words.length, 0, 'no slot is recorded');
      } else {
        assert.equal(d.slice.ok, true, 'a slice');
        if (pin.kind === 'time') assert.ok(/\btime\b/i.test(pin.text), 'the word `time` is in the text: the hook test at hook-pre-action.ts:1205 is what holds it');
        if (pin.plants.includes('m02')) {
          assert.equal(d.slice.counts[pin.word], 1, `${pin.word} is recorded once in a slot`);
          assert.equal(occurrences(pin.text, pin.word), 2, `${pin.word} occurs twice in the text: the count proof (hook-pre-action.ts:1089) must not mask it`);
        }
        if (pin.plants.includes('m30')) {
          assert.equal(d.slice.counts[pin.word], undefined, `${pin.word} is in no recorded slot`);
          assert.ok(occurrences(pin.text, pin.word) >= 1, `${pin.word} is in the text: the mask (hook-pre-action.ts:1092) must leave it visible`);
        }
      }
    }
    const label = classifyTool(ev(pin.text), { cwd: CWD, lowering: true });
    assert.equal(label.lowered, undefined, 'no lowered candidate');
    assert.deepEqual(label, classifyTool(ev(pin.text), { cwd: CWD }), 'the label is the unchanged one');
  });
}

test('PS-reach m28: the reserved word `time` before the loop word is read as a loop word at command position (the one alternative the hook pins leave to the hook\'s own `time` test)', () => {
  const text = 'egrep -n deploy f; time while';
  assert.equal(loneRule(text), true);
  assert.equal(decisionOf(text).slice.ok, false, JSON.stringify(text));
});

test('PS-reach time layers: the keyword `time` is a bad slice at the mapper (first-word rule) and a no-candidate text at the hook, each on its own', () => {
  for (const text of ['time egrep -n deploy f', 'time -p egrep -n deploy f']) {
    assert.equal(decisionOf(text).slice.ok, false, `mapper layer: ${JSON.stringify(text)}`);
    assert.equal(classifyTool(ev(text), { cwd: CWD, lowering: true }).lowered, undefined, `hook layer: ${JSON.stringify(text)}`);
  }
});
