'use strict';
// D1d round 2 (stricter only): a command with a `while`, `until` or `select` loop, like a `for` loop, is never lowered; it gets the unchanged (master) answer.
// The vendored parser reads `while` and `until` as separators and keeps no trace of them, so the mapper reads them from the text (hasLoopCommand);
// `for` and `select` arrive as `forLoop` commands. Rows are named after ACCEPTANCE rows PP1 (loops are bad), PP10 (the slice mask builds no pattern from words).
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const { runHook, allow, protectedPath, hashOf } = require('./support/d1d-hook-harness.cjs');
const { classifyTool } = require('../dist/hook-pre-action.js');
const mapper = require('../dist/seatbelt/mapper.js');
const { COMMANDS } = require('./support/d1d-mask-cases.cjs');

const ROOT = path.resolve(__dirname, '..');
const W = 'deploy';
// One command per LOWER_SHAPES slot (support/lower-shapes-d1d.md), each with a shipping word in its data slot.
const SLOTS = {
  T05a: `grep -n '${W}' f`, T05b: `grep -e ${W} f`, T05c: `egrep -n '${W}' f`, T05d: `egrep -e ${W} f`, T05e: `fgrep -n '${W}' f`, T05f: `fgrep -e ${W} f`,
  T05g: `rg -n '${W}' src`, T05h: `rg -e ${W} src`, T05i: `git grep -n '${W}' HEAD`, T05j: `git grep -e ${W} -- src`,
  T06: `cat <<'EOF'\n${W} notes\nEOF`,
  P07a: `grep -rn x ${W}`, P07b: `egrep x ${W}.md`, P07c: `fgrep x ${W}.md`, P07d: `rg x ${W}`, P07e: `git grep -n x HEAD -- ${W}/x.ts`,
  P08: `sed -n '1,5p' ${W}.md`, P09: `cd ${W}`, P05: `ls ${W}`,
};
// The slots whose plain form the port lowers (the others are not asked on master either; their loop form is).
const PLAIN_LOWERED = ['T05c', 'T05d', 'T05e', 'T05f', 'T05i', 'T05j', 'T06', 'P07b', 'P07c', 'P07e', 'P08'];
// Loops around listed programs (grep, sleep, cat): the slot command in the condition, in the body, with sleep or cat as the other part.
const LOOPS = {
  while_cond: (x) => `while ${x}\ndo sleep 5; done`,
  while_cond_semi: (x) => `while ${x}; do sleep 5; done`,
  while_body: (x) => `while true; do\n${x}\ndone`,
  while_sleep_cat: (x) => `while sleep 1; do\ncat f\n${x}\ndone`,
  until_cond: (x) => `until ${x}\ndo sleep 5; done; date`,
  until_body: (x) => `until false; do\n${x}\ndone`,
  select: (x) => `select i in a b; do\n${x}\ndone`,
  for: (x) => `for i in 1 2; do\n${x}\ndone`,
};
const ev = (command) => ({ session_id: 's1', tool_use_id: 't1', tool_name: 'Bash', tool_input: { command }, cwd: ROOT });
const clearFor = (b) => ({ decline_check: { state: 'clear', action: hashOf(b.normalized_action) } });
const names = (run) => run.calls.map((c) => c.pathname.replace('/v1/agent/', '') + (c.body.operation ? `:${c.body.operation}` : ''));
const MASTER_ONLY = ['runtime', 'think', 'enforcement:issue', 'enforcement:verify'];
// A service that clears whatever lowered question it is asked (a bound clearance), and answers master's path otherwise.
const clearing = (p, b) => (p === '/v1/agent/runtime' ? allow(b.base_class ? clearFor(b) : {}) : protectedPath(p, b));
const masterLabel = (command) => classifyTool(ev(command), { cwd: ROOT });
const decisionOf = (command) => mapper.evaluateSeatbeltShell(command, { cwd: ROOT, home: '/home/u', tmpdir: '/tmp', platform: 'linux', dataSlots: true,
  fs: { readFile: () => null, realpath: () => null, readdir: () => null }, git: { toplevel: () => null, getAll: () => [], currentBranch: () => null, remoteHead: () => null } });

// Through the real hook path with a bound clear: master's answer is the original class asked, no lowered question, no base_class.
async function assertMaster(command, why) {
  const run = await runHook(clearing, ev(command));
  const label = masterLabel(command);
  // master asks the original class (think, permit issue and verify follow) when its label is protected, and only the runtime call otherwise
  assert.deepEqual(names(run), label.protected ? MASTER_ONLY : ['runtime'], `${why}: ${JSON.stringify(command)}`);
  const body = run.calls[0].body;
  assert.equal('base_class' in body, false, why);
  assert.equal(body.type, label.type, `${why}: the original class is asked`);
  assert.equal(body.action, label.action, why);
  assert.deepEqual(body.surfaces, label.surfaces, why);
  assert.equal(classifyTool(ev(command), { cwd: ROOT, lowering: true }).lowered, undefined, `${why}: no lowered candidate`);
}
async function assertLowered(command, why) {
  const run = await runHook(clearing, ev(command));
  assert.deepEqual(names(run), ['runtime'], `${why}: ${JSON.stringify(command)}`);
  assert.ok(run.calls[0].body.base_class, why);
}

test('PP1: a while, until or select loop around listed programs, in each LOWER_SHAPES slot, answers master through the real hook with a bound clear', async () => {
  let rows = 0;
  let asked = 0;
  for (const [slot, base] of Object.entries(SLOTS)) {
    for (const [form, wrap] of Object.entries(LOOPS)) {
      const command = wrap(base);
      assert.equal(decisionOf(command).slice.ok, false, `${slot}/${form}: the mapper's slice is bad`);
      await assertMaster(command, `${slot}/${form}`);
      rows += 1;
      if (masterLabel(command).protected) asked += 1;
    }
  }
  assert.equal(rows, 19 * 8);
  assert.ok(asked >= 100, 'most of the loop rows are asked on master (the others are free there)');
  // the same slots, plain, are the ones the port lowers (the loop is what changes the answer)
  for (const slot of PLAIN_LOWERED) await assertLowered(SLOTS[slot], `${slot} plain`);
});

test('PP1: the corpus shape of the audit finding (an until loop around grep and sleep, then date) answers master', async () => {
  const command = 'until grep -q ready deploy.log; do sleep 5; done; date';
  assert.equal(decisionOf(command).slice.ok, false);
  await assertMaster(command, 'until/grep/sleep/date');
  // and the loop word as a plain word of a data slot or of another command is not a loop
  await assertLowered("git grep -c deploy HEAD; echo until", 'echo until');
});

test('PP1: every spelling of the loop word at command position is bad: separators, reserved words before it, tabs, continuations, nesting', () => {
  const body = 'grep -q ready deploy.log; do sleep 5; done';
  const forms = [
    `while ${body}`, `until ${body}`, `\nwhile ${body}`, `   while ${body}`, `true && while ${body}`, `true || until ${body}`, `true; while ${body}`, `true & until ${body}`,
    `echo a | while ${body}`, `{ while ${body}; }`, `( until ${body} )`, `$(while ${body})`, `\`until ${body}\``, `! until ${body}`, `time while ${body}`,
    `if true; then while ${body}; fi`, `if true; then\nwhile ${body}\nfi`, `if false; then true; else until ${body}; fi`, `if true; then true; elif true; then while ${body}; fi`,
    `for i in 1; do while ${body}; done`, `while\tgrep -q ready deploy.log; do sleep 5; done`, `while(grep -q ready deploy.log); do sleep 5; done`,
    'wh\\\nile grep -q ready deploy.log; do sleep 5; done', 'un\\\ntil grep -q ready deploy.log; do sleep 5; done', 'while \\\n grep -q ready deploy.log; do sleep 5; done',
    'echo a \\\n&& until grep -q ready deploy.log; do sleep 5; done', 'echo a \\\\\nwhile grep -q ready deploy.log; do sleep 5; done',
    'select i in a b; do grep -q ready deploy.log; done', 'select i in a b\ndo grep -q ready deploy.log\ndone',
  ];
  for (const command of forms) {
    assert.equal(decisionOf(command).slice.ok, false, JSON.stringify(command));
    assert.equal(classifyTool(ev(command), { cwd: ROOT, lowering: true }).lowered, undefined, JSON.stringify(command));
  }
});

test('PP1: only the loop forms change: the loop word as an argument, a pattern or a file name, and the other compound forms, keep the port answer', () => {
  const lowered = ["git grep -c deploy HEAD; echo while", "git grep -c deploy HEAD; echo until", "git grep -c deploy HEAD; echo select", "git grep -E 'a|while|b' deploy",
    "git grep -n while -- deploy", "git grep -n until -- deploy", "git grep -n 'select' -- deploy", "git grep -c deploy HEAD && git grep -c until HEAD",
    // not loops, and not asked about in this round: the port lowers them and so does the patched tip
    "git grep -c deploy HEAD; if true; then git grep -c release HEAD; fi", "{ git grep -c deploy HEAD; }", "( git grep -c deploy HEAD )"];
  for (const command of lowered) {
    assert.equal(decisionOf(command).slice.ok, true, JSON.stringify(command));
    assert.ok(classifyTool(ev(command), { cwd: ROOT, lowering: true }).lowered, JSON.stringify(command));
  }
  // functions, case, coproc, tests and arithmetic never lowered on the port and still do not
  for (const command of ['f() { git grep -c deploy HEAD; }; f', 'function f { git grep -c deploy HEAD; }; f', 'case x in x) git grep -c deploy HEAD;; esac', 'coproc { git grep -c deploy HEAD; }',
    '[[ -n x ]] && git grep -c deploy HEAD', 'for i in 1 2; do git grep -c deploy HEAD; done']) {
    assert.equal(classifyTool(ev(command), { cwd: ROOT, lowering: true }).lowered, undefined, JSON.stringify(command));
  }
});

test('PP1/PP9: the loop-word check is linear: a 1 MB text of separators, blanks and reserved words is read at once', () => {
  const pad = ' '.repeat(1 << 20);
  const texts = [`${';'.repeat(1 << 19)}`, `;${pad}`, `${'; '.repeat(1 << 19)}`, `${'; do '.repeat(1 << 17)}`, `${'then '.repeat(1 << 17)}x`, `${'|'.repeat(1 << 19)}while`, `${'a\\\n'.repeat(1 << 18)}`, `${'if '.repeat(1 << 17)}`];
  const t0 = Date.now();
  for (const text of texts) {
    mapper.evaluateSeatbeltShell(`git grep -c deploy HEAD; ${text}`, { cwd: ROOT, home: '/home/u', tmpdir: '/tmp', platform: 'linux', dataSlots: true,
      fs: { readFile: () => null, realpath: () => null, readdir: () => null }, git: { toplevel: () => null, getAll: () => [], currentBranch: () => null, remoteHead: () => null } });
  }
  assert.ok(Date.now() - t0 < 60000, 'eight 1 MB texts in far less than a minute');
  const src = fs.readFileSync(path.join(ROOT, 'src', 'seatbelt', 'mapper.ts'), 'utf8');
  assert.equal((src.match(/^const LOOP_COMMAND = \//gm) || []).length, 1, 'one new pattern, a listed constant');
});

test('PP10: the slice mask builds no pattern from the words: the source has no new RegExp, and metacharacters, 10k repeated words and long texts answer as the port tip did', () => {
  const hook = fs.readFileSync(path.join(ROOT, 'src', 'hook-pre-action.ts'), 'utf8');
  const mask = hook.slice(hook.indexOf('function sliceMask('), hook.indexOf('/** The single text-only reading'));
  assert.ok(mask.length > 50 && mask.length < 600);
  assert.equal(mask.includes('new RegExp'), false, 'no pattern is built inside the function');
  assert.ok(mask.includes('SLICE_ANY_WORD'), 'the one module-level pattern of the 15 fixed words');
  // the fixed set: the pattern lists exactly the 15 LOWER_SHAPES words, so a word the mask replaces is always one of them
  const pattern = hook.match(/const SLICE_ANY_WORD = \/\\b\(\?:([^)]*)\)\\b\/gi;/);
  assert.ok(pattern);
  assert.deepEqual(pattern[1].split('|'), ['publish', 'unpublish', 'deprecate', 'deploy', 'release', 'wrangler', 'production', 'prod', 'migration', 'schema', 'database', 'd1', 'commit', 'permit', 'closure']);
  const golden = JSON.parse(fs.readFileSync(path.join(__dirname, 'support', 'd1d-mask-golden.json'), 'utf8'));
  assert.equal(golden.length, COMMANDS.length);
  COMMANDS.forEach((command, k) => {
    const r = classifyTool(ev(command), { cwd: ROOT, lowering: true });
    const got = r.lowered ? { action: r.lowered.action, target: r.lowered.target, type: r.lowered.type, surfaces: r.lowered.surfaces } : null;
    assert.deepEqual(got, golden[k], `case ${k} (${command.length} characters)`);
  });
  assert.ok(golden.filter(Boolean).length >= 15, 'the golden has lowered and unlowered cases');
  assert.ok(golden.some((g) => g === null), 'and keeps master where the port did');
});

test('PP10: the mask replaces the proven words only: a shipping word that stays outside every recorded slot keeps master (nothing is lowered)', () => {
  // `deploy` sits in the pattern slot of git grep and is proven; the other word occurs in a place no slot records, so it is never masked and the text stays asked
  for (const command of ['git grep -c deploy HEAD; echo npm publish', "git grep -c deploy HEAD; echo 'npm publish'", 'git grep -c deploy HEAD; ls -la ./production/ && echo deploy',
    "git grep -c deploy HEAD; printf 'x' > release.md"]) {
    assert.ok(masterLabel(command).protected, `master asks: ${command}`);
    assert.equal(classifyTool(ev(command), { cwd: ROOT, lowering: true }).lowered, undefined, command);
  }
  // and the proven word alone, or with words that are not shipping words, is lowered
  for (const command of ['git grep -c deploy HEAD; echo hello', 'git grep -c deploy HEAD; cat release.md']) assert.ok(classifyTool(ev(command), { cwd: ROOT, lowering: true }).lowered, command);
});
