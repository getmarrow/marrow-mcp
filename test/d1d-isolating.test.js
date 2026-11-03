'use strict';
// D1d: one isolating test per guard that no other test pins on its own (the planted-mutant list of reports/mutants.log). Each text passes every other guard.
const assert = require('node:assert/strict');
const test = require('node:test');
const path = require('node:path');
const { classifyTool } = require('../dist/hook-pre-action.js');
const mapper = require('../dist/seatbelt/mapper.js');

const ROOT = path.resolve(__dirname, '..');
const event = (command) => ({ tool_name: 'Bash', tool_input: { command }, cwd: ROOT });
const lowOf = (command) => classifyTool(event(command), { cwd: ROOT, lowering: true });
const masterOf = (command) => classifyTool(event(command), { cwd: ROOT });

test('I-A12: a word that also occurs outside the recorded slot is never masked (count proof), and the same slot alone is', () => {
  assert.ok(masterOf('git grep deploy f').protected, 'master asks the control row');
  assert.ok(lowOf('git grep deploy f').lowered, 'the slot alone is lowered');
  for (const c of ['git grep deploy f; echo deploy', 'git grep -n release f; echo release', 'git grep -e deploy -e x f; echo deploy']) {
    assert.equal(lowOf(c).lowered, undefined, c);
  }
});

test('I-A3: commit, permit and closure are masked in the pattern slot only; a pathspec or a file name keeps master (git family asks on commit)', () => {
  assert.ok(lowOf('git grep -n commit HEAD').lowered, 'pattern slot lowered');
  assert.ok(masterOf('git grep -n x -- src/commit.ts').protected, 'master asks on the pathspec word');
  for (const c of ['git grep -n x -- src/commit.ts', 'git grep -n x HEAD -- commit.md']) assert.equal(lowOf(c).lowered, undefined, c);
});

test('I-A18: a text over 8,192 characters is never lowered, whatever trims off its end', () => {
  assert.ok(lowOf('git grep deploy f').lowered);
  assert.equal(lowOf(`git grep deploy f${' '.repeat(8300)}`).lowered, undefined);
});

// Port rows (port-d1d): the guards that lived behind a second guard in the first build are pinned at the mapper's own record (`slice`), where no label rule can stand in for them.
const decisionOf = (command) => mapper.evaluateSeatbeltShell(command, { cwd: ROOT, home: '/home/u', tmpdir: '/tmp', platform: 'linux', dataSlots: true,
  fs: { readFile: () => null, realpath: () => null, readdir: () => null }, git: { toplevel: () => null, getAll: () => [], currentBranch: () => null, remoteHead: () => null } });
const t06 = (command) => decisionOf(command).slice.words.filter((w) => w.slot === 'T06').length;

test('I-F8: the mapper lists no git subcommand but grep and the four plumbing forms (a text with commit, tag, add, push or log records no slot)', () => {
  for (const c of ['git commit -m x; grep -c deploy f', 'git commit -am x && grep deploy f', 'git tag v1; grep -c deploy f', 'git add -A; grep -c deploy f', 'git push; grep -c deploy f', 'git log; grep -c deploy f']) {
    assert.equal(decisionOf(c).slice.ok, false, c);
  }
  for (const c of ['git status; grep -c deploy f', 'git rev-parse --show-toplevel && grep -c deploy f', 'git ls-files | grep -c deploy', 'git branch --list | grep -c deploy']) assert.equal(decisionOf(c).slice.ok, true, c);
});

test('I-A6a: rg flags outside the closed table give no slot (--pre, --pre-glob, --hostname-bin, -z, --search-zip, -f, --file)', () => {
  for (const f of ['--pre sh', '--pre=sh', '--pre cat', '--pre=cat', '--pre-glob=x', '--hostname-bin x', '-z', '--search-zip', '-f pats', '--file=pats']) assert.equal(decisionOf(`rg ${f} deploy src`).slice.ok, false, f);
  for (const c of ['rg -n deploy src', 'rg -g x -e deploy src', 'rg --no-heading -i deploy src']) assert.equal(decisionOf(c).slice.ok, true, c);
});

test('I-A13/F7: a heredoc body is a slot only for a bare cat (an operand, a flag-only operand list or another receiver records no T06 word)', () => {
  assert.equal(t06("cat <<'EOF'\nrelease\nEOF"), 1);
  for (const c of ["cat f <<'EOF'\nrelease\nEOF", "cat - <<'EOF'\nrelease\nEOF", "cat -n f <<'EOF'\nrelease\nEOF", "cat f g <<'EOF'\nrelease\nEOF"]) assert.equal(t06(c), 0, c);
  for (const c of ["bash <<'EOF'\nrelease\nEOF", "sh -s <<'EOF'\nrelease\nEOF", "python3 - <<'EOF'\nrelease\nEOF", "xargs <<'EOF'\nrelease\nEOF"]) assert.equal(decisionOf(c).slice.ok, false, c);
});

test('I-A6r: a read-only call never carries a lowered label, and a lowered label is never read-only', () => {
  const rows = ['grep -c deploy f', 'grep -rn release src', 'cat release.md', 'ls production', 'head -n 3 release.md', 'wc -l deploy.log', "sed -n 1p deploy.md", 'git status; grep -c deploy f'];
  let readOnly = 0;
  for (const c of rows) {
    const base = masterOf(c);
    const r = lowOf(c);
    if (base.readOnly) { readOnly += 1; assert.equal(r.lowered, undefined, c); assert.equal(r.readOnly, true, c); }
    if (r.lowered) assert.equal(r.lowered.readOnly, false, c);
  }
  assert.ok(readOnly >= 3, 'at least three of the rows are read-only on master');
});

test('I-A2r: a program word the mapper cannot read (variable, substitution, glob) gives no slot even when every other word is listed', () => {
  for (const c of ['$P deploy f', '${P} -n deploy f', '"$(echo grep)" deploy f', 'gre[p] deploy f', 'g?ep deploy f', '$P -c deploy f; ls production']) assert.equal(decisionOf(c).slice.ok, false, c);
  assert.equal(decisionOf('grep deploy f').slice.ok, true);
});
