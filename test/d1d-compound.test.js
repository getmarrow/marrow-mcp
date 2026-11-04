'use strict';
// D1d round 3 (stricter only; main ruling 15a6eef8, A81): the hook lowers a LOWER_SHAPES row ALONE (one simple command) and nothing else. A named shape inside any compound or
// wrapper form (brace group, subshell, $( ), backticks, if/elif/else/then, while, until, for, select, case, function bodies, !, &&/||/; lists, pipelines, a background &, env/nohup/bash -c)
// has no lowered candidate: the slice is bad, the label is the unchanged one, and the hook asks the original class. Rows: PC1 (every form x every slot), PC2 (the shapes alone keep
// their lowering), PC8 (linear). The vendored parser reads `if then else elif fi do done while until ! { } time` as separators and keeps no trace of them, so the mapper reads the first
// word of the text (loneSimpleCommand); every other form is read from the parsed structure.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const { runHook, allow, protectedPath, hashOf } = require('./support/d1d-hook-harness.cjs');
const { classifyTool } = require('../dist/hook-pre-action.js');
const mapper = require('../dist/seatbelt/mapper.js');
const { SLOTS, FORMS, ALONE, PLAIN_LOWERED, build } = require('./support/d1d-compound-forms.cjs');

const ROOT = path.resolve(__dirname, '..');
const ev = (command) => ({ session_id: 's1', tool_use_id: 't1', tool_name: 'Bash', tool_input: { command }, cwd: ROOT });
const clearFor = (b) => ({ decline_check: { state: 'clear', action: hashOf(b.normalized_action) } });
// A service that clears whatever lowered question it is asked (a bound clearance), and answers master's path otherwise.
const clearing = (p, b) => (p === '/v1/agent/runtime' ? allow(b.base_class ? clearFor(b) : {}) : protectedPath(p, b));
const decisionOf = (command) => mapper.evaluateSeatbeltShell(command, { cwd: ROOT, home: '/home/u', tmpdir: '/tmp', platform: 'linux', dataSlots: true,
  fs: { readFile: () => null, realpath: () => null, readdir: () => null }, git: { toplevel: () => null, getAll: () => [], currentBranch: () => null, remoteHead: () => null } });
const lowerable = (command) => { const d = decisionOf(command); return d.slice.ok && d.parse === 'ok' && d.hits.length === 0 && d.flags.length === 0; };
const probed = (run) => run.calls.some((c) => 'base_class' in c.body);

test('PC1: every compound or wrapper form around a named shape, in each LOWER_SHAPES slot, is a bad slice with no lowered candidate and no probe through the real hook with a bound clear', async () => {
  let rows = 0;
  for (const slot of Object.keys(SLOTS)) {
    for (const form of Object.keys(FORMS)) {
      const command = build(slot, form);
      if (command === null) continue;
      const why = `${slot}/${form}: ${JSON.stringify(command)}`;
      assert.equal(lowerable(command), false, `${why}: the mapper's slice is bad`);
      const label = classifyTool(ev(command), { cwd: ROOT, lowering: true });
      assert.equal(label.lowered, undefined, `${why}: no lowered candidate`);
      assert.deepEqual(label, classifyTool(ev(command), { cwd: ROOT }), `${why}: the label is the unchanged one`);
      assert.equal(probed(await runHook(clearing, ev(command))), false, `${why}: no base_class is sent`);
      rows += 1;
    }
  }
  assert.ok(rows >= 19 * 80, `rows ${rows}`);
});

test('PC1: the forms of the ruling are all in the table (brace, subshell, $( ), backticks, if/elif/else, while, until, for, case, function, !, && || ; lists in both orders, pipelines in both orders)', () => {
  for (const form of ['brace', 'subshell', 'cmdsub', 'backtick', 'if_then', 'if_cond', 'if_else', 'elif_cond', 'elif_branch', 'while_cond', 'while_body', 'until_cond', 'until_body', 'for', 'case',
    'func_paren', 'func_kw', 'bang', 'and_first', 'and_second', 'or_first', 'or_second', 'semi_first', 'semi_second', 'pipe_first', 'pipe_second', 'bg_after', 'w_env', 'w_bash_c']) assert.ok(form in FORMS, form);
});

test('PC2: each LOWER_SHAPES row alone, and with only blanks, a comment line, a trailing newline, semicolon or /dev/null redirect, keeps its lowered candidate through the real hook with a bound clear', async () => {
  for (const slot of Object.keys(SLOTS)) {
    for (const [name, wrap] of Object.entries(ALONE)) {
      const command = wrap(SLOTS[slot]);
      if (command === null) continue;
      const why = `${slot}/${name}: ${JSON.stringify(command)}`;
      assert.equal(decisionOf(command).slice.ok, true, `${why}: one simple command is a slice`);
      if (!PLAIN_LOWERED.includes(slot)) continue;
      assert.ok(classifyTool(ev(command), { cwd: ROOT, lowering: true }).lowered, `${why}: lowered candidate`);
      const run = await runHook(clearing, ev(command));
      assert.deepEqual(run.calls.map((c) => c.pathname.replace('/v1/agent/', '')), ['runtime'], why);
      assert.ok(run.calls[0].body.base_class, `${why}: the lowered question is asked with its base class`);
    }
  }
});

test('PC1: the program must be the first word of the text: a keyword the parser drops, a leading redirect or an assignment leaves the slice bad', () => {
  for (const c of ['{ egrep -n deploy f; }', 'if egrep -n deploy f; then true; fi', '! egrep -n deploy f', 'time egrep -n deploy f', 'while egrep -n deploy f; do true; done', '>/dev/null egrep -n deploy f',
    'A=1 egrep -n deploy f', '\\\negrep -n deploy f; true', 'then egrep -n deploy f', 'do egrep -n deploy f', 'egrep -n deploy f\nthen egrep -n deploy f', '# c\n{ egrep -n deploy f; }',
    'egrep -n deploy f &', 'egrep -n deploy f | cat', '( egrep -n deploy f )', 'echo `egrep -n deploy f`', 'egrep -n $(echo deploy) f']) assert.equal(decisionOf(c).slice.ok, false, JSON.stringify(c));
  for (const c of ['egrep -n deploy f', '  egrep -n deploy f', '\n\n# a\n#b\negrep -n deploy f', 'egrep\t-n deploy f', "egrep -n 'a; { if ( b' f", 'egrep -n deploy f;']) assert.equal(decisionOf(c).slice.ok, true, JSON.stringify(c));
});

test('PC8: the first-word check is linear: a megabyte of blank and comment lines before a command, and a comment without a newline, are read at once', () => {
  const texts = [`${'#\n'.repeat(1 << 19)}egrep -n deploy f`, `${' \n'.repeat(1 << 19)}egrep -n deploy f`, `#${'x'.repeat(1 << 20)}`, `${'# a\n'.repeat(1 << 18)}{ egrep -n deploy f; }`];
  const t0 = Date.now();
  const oks = texts.map((t) => decisionOf(t)).map((d) => d.slice.ok && d.parse === 'ok');
  assert.deepEqual(oks, [false, false, false, false], 'over the size budget the text is not one simple command either');
  const small = [`${'#\n'.repeat(1 << 12)}egrep -n deploy f`, `${' \n'.repeat(1 << 12)}egrep -n deploy f`, `${'# a\n'.repeat(1 << 12)}{ egrep -n deploy f; }`];
  assert.deepEqual(small.map((t) => decisionOf(t)).map((d) => d.slice.ok && d.parse === 'ok'), [true, true, false]);
  assert.ok(Date.now() - t0 < 60000, 'four 1 MB texts in far less than a minute');
});

test('PC5: the slice decision is one function with no pattern of its own, called once, where the mapper decides the slice', () => {
  const src = fs.readFileSync(path.join(ROOT, 'src', 'seatbelt', 'mapper.ts'), 'utf8');
  const from = src.indexOf('function loneSimpleCommand(');
  assert.ok(from > 0);
  assert.equal(src.indexOf('function loneSimpleCommand(', from + 1), -1, 'defined once');
  const body = src.slice(from, src.indexOf('\n}\n', from));
  assert.equal(/new RegExp|\.test\(|\.match\(|\.replace\(|\/\^?\\|\[\^/.test(body), false, 'no pattern in the function');
  assert.equal((src.match(/loneSimpleCommand\(src, parsed\)/g) || []).length, 1, 'called once, at the slice decision');
  assert.ok(src.includes('hasLoopCommand(src) || !loneSimpleCommand(src, parsed)'), 'beside the loop and function checks');
});
