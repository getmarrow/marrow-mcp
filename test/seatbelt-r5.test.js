'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const fsn = require('node:fs');
const os = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');

// Patch round 5 for Barvis's delta-3 audit of 964725a4 (B1, B2, A1): the three
// places where resolveMakeTargets gave a definite answer while real GNU make
// 4.3 ran something the answer does not list (B1, B2), or where an env value
// that is not a string went unseen (A1). The rule is the round-4 one: where
// the resolver cannot tell, the answer is `dynamic` / `unknown`. Rows marked
// `ran` are checked against GNU make itself when one is available
// (SEATBELT_ORACLE_MAKE, or `make` / `gmake` on PATH); the resolver
// assertions need no oracle.

const { createFakeFs } = require('./support/seatbelt-fake-fs.cjs');
const { nodeSeatbeltFs } = require('../dist/seatbelt-fs.js');
const S = require('../dist/seatbelt-scripts.js');

const nfs = nodeSeatbeltFs();
const ROOT = fsn.realpathSync(fsn.mkdtempSync(join(os.tmpdir(), 'seatbelt-r5-')));
let counter = 0;
const fresh = () => {
  const dir = join(ROOT, `d${counter++}`);
  fsn.mkdirSync(dir, { mode: 0o700 });
  return dir;
};
test.after(() => fsn.rmSync(ROOT, { recursive: true, force: true }));

const make = (text, targets = ['all'], options = {}) => S.resolveMakeTargets(createFakeFs().file('/m/Makefile', text), '/m', targets, options);
const definite = (r) => r.status === 'ok' && !r.dynamic;
const show = (r) => (r.status === 'ok' ? (r.dynamic ? 'dynamic' : `DEFINITE ${JSON.stringify(r.commands)}`) : `${r.status}/${r.reason}`);
/** The environment of a clean developer shell (what the caller of the resolver states). */
const ENV = { PATH: '/usr/bin:/bin', HOME: '/home/u' };

function findMake() {
  for (const candidate of [process.env.SEATBELT_ORACLE_MAKE, 'make', 'gmake']) {
    if (!candidate) continue;
    const probe = spawnSync(candidate, ['--version'], { encoding: 'utf8' });
    if (probe.status === 0 && /GNU Make/.test(probe.stdout)) return candidate;
  }
  return null;
}
const MAKE_BINARY = findMake();
const oracleSkip = MAKE_BINARY === null && 'GNU make not available (set SEATBELT_ORACLE_MAKE)';
// What make does with a row is written down for GNU make 4.3 (the audit's oracle); another version still gets every
// resolver assertion and the generic checks, but not the version-specific facts (4.4 reads `:::=`, for one).
const MAKE_43 = MAKE_BINARY !== null && /GNU Make 4\.3\b/.test(spawnSync(MAKE_BINARY, ['--version'], { encoding: 'utf8' }).stdout);

/**
 * Run a row through GNU make, `make -n` and a real run, in a fresh directory.
 * `@M@` in the Makefile (and in env values) is the marker file the payload
 * touches. Nothing here is more than `touch` on a path in the row's own directory.
 */
function oracle(row) {
  const dir = fresh();
  const marker = join(dir, 'MARKER');
  const sub = (text) => text.split('@M@').join(marker);
  fsn.writeFileSync(join(dir, 'Makefile'), sub(row.makefile));
  const env = { PATH: '/usr/bin:/bin', ...Object.fromEntries(Object.entries(row.env || {}).map(([k, v]) => [k, sub(v)])) };
  const targets = row.targets || ['all'];
  const args = [...Object.entries(row.overrides || {}).map(([k, v]) => `${k}=${v}`), ...targets];
  const run = (extra) => spawnSync(MAKE_BINARY, [...extra, ...args], { cwd: dir, env, encoding: 'utf8', timeout: 15000, stdio: ['ignore', 'pipe', 'pipe'] });
  const dry = run(['-n']);
  const ranDry = fsn.existsSync(marker);
  fsn.rmSync(marker, { force: true });
  const real = run([]);
  return { dir, dry, real, ranDry, ranReal: fsn.existsSync(marker), env, targets, sub };
}

/** The resolver on the same text, with the marker path filled in. */
function resolve(row) {
  const text = row.makefile.split('@M@').join('/m/MARKER');
  const env = { ...ENV, ...Object.fromEntries(Object.entries(row.env || {}).map(([k, v]) => [k, v.split('@M@').join('/m/MARKER')])) };
  return make(text, row.targets || ['all'], { env, overrides: row.overrides || {} });
}

// ---------------------------------------------------------------- B1: an assignment to a command-line-overridden name

const ALL = 'all:\n\t@echo $(X)\n';
const OVERRIDE_X = { X: 'y' };

/**
 * `ran`: what GNU make 4.3 does with the row (the marker is created by make -n
 * and by a real run alike: make reads `!=` and `:=` right sides at read time).
 * Every row must come back `dynamic` (or `unknown`): never a definite answer.
 */
const B1_ROWS = [
  // The audit's four repro rows.
  { name: 'audit: `!=` on an overridden name', makefile: `X != touch @M@\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: 'audit: `:=` with $(shell)', makefile: `X := $(shell touch @M@)\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: 'audit: `:=` with $(eval) around $(shell)', makefile: `X := $(eval Z := $(shell touch @M@))\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: 'audit: STAGE != touch; echo dev with STAGE=prod', makefile: 'STAGE != touch @M@; echo dev\ndeploy:\n\t@echo deploying $(STAGE)\n', overrides: { STAGE: 'prod' }, targets: ['deploy'], ran: true },
  // Variants of the six forms the brief names.
  { name: 'variant: define/endef (recursive) with $(shell)', makefile: `define X\n$(shell touch @M@)\nendef\n${ALL}`, overrides: OVERRIDE_X, ran: false },
  { name: 'variant: define/endef with := and $(shell)', makefile: `define X :=\n$(shell touch @M@)\nendef\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: 'variant: target-specific `X !=`', makefile: 'all: X != touch @M@\nall:\n\t@echo $(X)\n', overrides: OVERRIDE_X, ran: true },
  { name: 'variant: `override X !=`', makefile: `override X != touch @M@\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: 'variant: `export X !=`', makefile: `export X != touch @M@\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: 'variant: line continuation in `!=`', makefile: `X != touch \\\n@M@\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: 'variant: line continuation inside $(shell)', makefile: `X := $(shell touch \\\n@M@)\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: 'variant: tabs around `!=`', makefile: `X\t!=\ttouch @M@\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: 'variant: spaces around `:=`', makefile: `X   :=   $(shell touch @M@)\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: 'variant: no blanks around `:=`', makefile: `X:=$(shell touch @M@)\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: 'variant: mixed tabs and spaces around `!=`', makefile: `X \t != \t touch @M@\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: 'variant: tab after the function name', makefile: `X := $(shell\ttouch @M@)\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  // Other operators and spellings of the same call.
  { name: '`::=` with $(shell)', makefile: `X ::= $(shell touch @M@)\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: '`:::=` with $(shell) (an error in make 4.3: still never definite)', makefile: `X :::= $(shell touch @M@)\n${ALL}`, overrides: OVERRIDE_X, ran: false, errors: true },
  { name: '`=` with $(shell) (make drops it unexpanded: still dynamic, the call is not proven inert)', makefile: `X = $(shell touch @M@)\n${ALL}`, overrides: OVERRIDE_X, ran: false },
  { name: '`?=` with $(shell)', makefile: `X ?= $(shell touch @M@)\n${ALL}`, overrides: OVERRIDE_X, ran: false },
  { name: '`+=` with $(shell)', makefile: `X += $(shell touch @M@)\n${ALL}`, overrides: OVERRIDE_X, ran: false },
  { name: '`:=` with ${shell}', makefile: `X := \${shell touch @M@}\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: '`:=` with ${eval}', makefile: `X := \${eval Z := $(shell touch @M@)}\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: '`:=` with $(eval) alone', makefile: `X := $(eval $(shell touch @M@))\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: '`:=` with $(file)', makefile: `X := $(file >@M@,x)\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: '`:=` with $(call) of a variable that holds $(shell)', makefile: `F = $(shell touch @M@)\nX := $(call F)\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: '`:=` with $(foreach)', makefile: `X := $(foreach a,b,$(shell touch @M@))\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: '`:=` with a pure function around $(shell)', makefile: `X := $(subst a,b,$(shell touch @M@))\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: '`:=` with a variable that holds $(shell)', makefile: `Y = $(shell touch @M@)\nX := $(Y)\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: '`:=` with a variable two hops from $(shell)', makefile: `Z = $(shell touch @M@)\nY = $(Z)\nX := $(Y)\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: '`:=` with a variable of the environment that holds $(shell)', makefile: `X := $(Y)\n${ALL}`, overrides: OVERRIDE_X, env: { Y: '$(shell touch @M@)' }, ran: true },
  { name: '`:=` with a variable make defines itself that was appended a $(shell)', makefile: `CC += $(shell touch @M@)\nX := $(CC)\n${ALL}`, overrides: OVERRIDE_X, ran: true },
  { name: '`:=` with an unbalanced call', makefile: `X := $(shell touch @M@\n${ALL}`, overrides: OVERRIDE_X, ran: false, errors: true },
  { name: '`:=` with a trailing `$`', makefile: `X := a$\n${ALL}`, overrides: OVERRIDE_X, ran: false },
];

/** Same right sides, but the file's assignment is not dropped: what each of them means without an override. */
test('B1: an assignment to a command-line-overridden name is inspected: the answer is never definite (audit rows and variants)', () => {
  const failures = [];
  for (const row of B1_ROWS) {
    const r = resolve(row);
    if (definite(r)) failures.push(`${row.name}: ${show(r)}`);
  }
  assert.deepEqual(failures, []);
});

test('B1 oracle: GNU make reads the dropped assignment (`!=` and the simple flavours run their right side), and the resolver is never definite there', { skip: oracleSkip }, () => {
  const failures = [];
  for (const row of B1_ROWS) {
    const run = oracle(row);
    // The oracle's own answer first: the table above is what make 4.3 does.
    if (MAKE_43) {
      assert.equal(run.ranDry, row.ran, `${row.name}: make -n ran the payload`);
      assert.equal(run.ranReal, row.ran, `${row.name}: make ran the payload`);
      if (row.errors) assert.notEqual(run.real.status, 0, `${row.name}: make fails`);
    }
    const r = resolve(row);
    if (definite(r)) failures.push(`${row.name}: ${show(r)} (make ${run.ranDry || run.ranReal ? 'ran' : 'did not run'} the payload)`);
  }
  assert.deepEqual(failures, []);
});

test('B1: the verdict for an overridden name is never looser than the one for the same assignment when nothing overrides it', () => {
  const rights = ['plain', '$(shell echo a)', '${shell echo a}', '$(eval Z := a)', '$(Y)', '$(UNDEFINED)', '$(subst a,b,c)', '$(call f,a)', '$(foreach a,b,c)', '$$a', 'a $(shell b) c', '$(file >f,x)', '$(wildcard *)'];
  const operators = [':=', '::=', '!=', '=', '?=', '+='];
  const prelude = ['', 'Y = $(shell echo y)\n', 'Y := plain\n', 'CC += $(shell echo c)\n'];
  const failures = [];
  for (const before of prelude) {
    for (const op of operators) {
      for (const right of rights) {
        // X is read by another assignment (so it is a used name), and not by a recipe: a value this resolver cannot compute
        // is then no reason for `dynamic` by itself; only what make does when it reads the line is.
        const text = `${before}X ${op} ${right}\nW := $(X)\nall:\n\t@echo hi\n`;
        const loose = make(text, ['all'], { env: ENV });
        const overridden = make(text, ['all'], { env: ENV, overrides: { X: 'y' } });
        if (!definite(loose) && definite(overridden)) failures.push(`${JSON.stringify(text)}: not overridden ${show(loose)}, overridden ${show(overridden)}`);
      }
    }
  }
  assert.deepEqual(failures, []);
});

test('B1: looking at the dropped right side does not make a name used (never looser than the unused-name rule)', () => {
  // X is read only by the assignment make drops (Y is overridden): no expansion reaches X, its value only goes to the
  // environment of the recipes. The inspection must not count that read as a use.
  for (const text of ['Y := $(X)\nall:\n\t@echo $(Y)\n', 'Y = $(X)\nall:\n\t@echo $(Y)\n', 'Y ?= $(X)\nall:\n\t@echo $(Y)\n', 'Y += $(X)\nall:\n\t@echo $(Y)\n']) {
    const r = make(text, ['all'], { env: ENV, overrides: { X: 'a', Y: 'b' } });
    assert.ok(!definite(r), `${JSON.stringify(text)}: ${show(r)}`);
  }
  // The same X, used by a recipe: the value is in the command list, so it is definite (and lists both).
  const used = make('Y := $(X)\nall:\n\t@echo $(Y) $(X)\n', ['all'], { env: ENV, overrides: { X: 'a', Y: 'b' } });
  assert.equal(show(used), 'DEFINITE ["echo b a"]');
});

test('B1 abuse: hidden among other lines, misleading words, repeated assignments, a sub-make, a second overridden name', () => {
  const failures = [];
  const rows = [
    ['plain, then $(shell): the last one winning is not the question', `X := plain\nX := $(shell touch @M@)\n${ALL}`, OVERRIDE_X],
    ['$(shell), then plain', `X := $(shell touch @M@)\nX := plain\n${ALL}`, OVERRIDE_X],
    ['after the recipe line', `all:\n\t@echo $(X)\nX := $(shell touch @M@)\n`, OVERRIDE_X],
    ['lower-case name is another variable', `x := $(shell touch @M@)\n${ALL}`, OVERRIDE_X],
    ['text of an assignment inside a recipe line', "all:\n\t@echo 'X := $(shell touch @M@)'\n", OVERRIDE_X],
    ['two overridden names, the second one `!=`', 'A := 1\nSTAGE != touch @M@; echo dev\ndeploy:\n\t@echo $(A) $(STAGE)\n', { A: '2', STAGE: 'prod' }, ['deploy']],
    ['`!=` followed through a sub-make', 'X != touch @M@\nall:\n\t@$(MAKE) deploy\ndeploy:\n\t@echo $(X)\n', OVERRIDE_X],
  ];
  for (const [name, makefile, overrides, targets] of rows) {
    const r = resolve({ makefile, overrides, targets });
    if (definite(r)) failures.push(`${name}: ${show(r)}`);
  }
  assert.deepEqual(failures, []);
  // A comment, and a `$` that is only an escaped dollar, are not a call: stay definite and are what make lists.
  for (const makefile of [`# X := $(shell touch @M@)\n${ALL}`, `X := $$(shell touch @M@)\n${ALL}`]) {
    const r = resolve({ makefile, overrides: OVERRIDE_X });
    assert.ok(definite(r), show(r));
    assert.deepEqual(r.commands, ['echo y']);
  }
});

test('B1 controls: an override over a plain assignment (no call, no unknown value) stays definite and is the command make lists', () => {
  const controls = [
    { name: '`:=` plain', makefile: `X := plain\n${ALL}` },
    { name: '`=` plain', makefile: `X = a b\n${ALL}` },
    { name: '`?=` plain', makefile: `X ?= dev\n${ALL}` },
    { name: '`+=` plain', makefile: `X += more\n${ALL}` },
    { name: '`:=` with $$', makefile: `X := a$$b\n${ALL}` },
    { name: '`:=` with a known simple variable', makefile: `Y := v\nX := $(Y)\n${ALL}` },
    { name: '`:=` with a variable nothing defines', makefile: `X := $(UNDEFINED_VARIABLE)\n${ALL}` },
    { name: '`:=` with a pure function', makefile: `X := $(subst a,b,c)\n${ALL}` },
  ];
  for (const row of controls) {
    row.overrides = OVERRIDE_X;
    if (MAKE_BINARY !== null) {
      const run = oracle(row);
      assert.equal(run.ranDry || run.ranReal, false, row.name);
      assert.deepEqual(run.dry.stdout.split('\n').filter(Boolean), ['echo y'], row.name);
    }
    const r = resolve(row);
    assert.ok(definite(r), `${row.name}: ${show(r)}`);
    assert.deepEqual(r.commands, ['echo y'], row.name);
  }
});

// ---------------------------------------------------------------- B2: NUL and lone CR in the Makefile text

/**
 * GNU make 4.3 drops the rest of a line after a NUL, and the newline with it: the
 * next line is joined to this one, so a NUL at the end of a recipe line hides the
 * next rule header (and that rule's recipe becomes part of the wanted target). A CR
 * that does not end a CRLF is not a line end to make, though it is one to other
 * readers. A Makefile with either is not read: `unknown`, whole file.
 */
const B2_ROWS = [
  // The audit's repro and the other four rows of its nul.log.
  { name: 'audit: NUL ends a recipe line, the deploy header is joined to it', makefile: 'all:\n\t@echo a\0\ndeploy:\n\t@touch @M@\n' },
  { name: 'audit: NUL then a rule header joins the recipe', makefile: 'all:\n\t@echo hi;\0\nevil:\n\t@touch @M@\n' },
  { name: 'audit: NUL in a comment hides the next rule line', makefile: 'all:\n\t@echo hi\n# note\0\nall: evil\nevil:\n\t@touch @M@\n' },
  { name: 'audit: NUL then a .PHONY header', makefile: 'all:\n\t@true;\0\n.PHONY: x\n\t@touch @M@\n' },
  { name: 'audit: NUL in an assignment swallows the next line', makefile: 'X = hi\0\nall:\n\t@echo $(X)\n\t@touch @M@\n' },
  // NUL variants.
  { name: 'NUL in the middle of a recipe line', makefile: 'all:\n\t@ec\0ho a\n\t@touch @M@\n' },
  { name: 'NUL in the middle of a word, the next line stays', makefile: 'all:\n\t@echo a\0b\n\t@touch @M@\n' },
  { name: 'NUL in a comment line', makefile: '# note\0\nall:\n\t@echo a\n' },
  { name: 'NUL in a comment between recipe lines', makefile: 'all:\n# note\0\n\t@echo a\n\t@touch @M@\n' },
  { name: 'NUL in an include line', makefile: 'include nothing.mk\0\nall:\n\t@echo a\n' },
  { name: 'NUL in a -include line', makefile: '-include nothing.mk\0\nall:\n\t@echo a\n' },
  { name: 'NUL at the start of the file', makefile: '\0all:\n\t@echo a\n' },
  { name: 'NUL at the end of the file', makefile: 'all:\n\t@echo a\n\0' },
  { name: 'NUL in a target name', makefile: 'al\0l:\n\t@echo a\n' },
  { name: 'NUL right after the colon', makefile: 'all:\0\n\t@echo a\n' },
  { name: 'NUL on a line of its own', makefile: 'all:\n\0\n\t@echo a\n' },
  { name: 'NUL before a line continuation', makefile: 'X = a\0\\\nb\nall:\n\t@echo $(X)\n' },
  { name: 'NUL inside a function call', makefile: 'X := $(sub\0st a,b,c)\nall:\n\t@echo $(X)\n' },
  { name: 'NUL in a define block', makefile: 'define X\na\0b\nendef\nall:\n\t@echo a\n' },
  { name: 'NUL after a CRLF', makefile: 'all:\r\n\t@echo a\0\r\ndeploy:\r\n\t@touch @M@\r\n' },
  // Lone CR variants.
  { name: 'CR-only line endings', makefile: 'all:\r\t@echo a\r\t@touch @M@\r' },
  { name: 'a lone CR in the middle of a recipe line', makefile: 'all:\n\t@echo a\r@touch @M@\n' },
  { name: 'a lone CR in front of a rule header', makefile: 'all:\n\t@echo a\rdeploy:\n\t@touch @M@\n' },
  { name: 'a lone CR at the end of the file', makefile: 'all:\n\t@echo a\n\t@touch @M@\r' },
  { name: 'CR CR LF', makefile: 'all:\n\t@echo a\r\r\n\t@touch @M@\n' },
  { name: 'a lone CR in a comment', makefile: '# note\rall:\n\t@echo a\n' },
  { name: 'a lone CR in an include line', makefile: 'include nothing.mk\rall:\n\t@echo a\n' },
  { name: 'a lone CR in an assignment', makefile: 'X = a\rb\nall:\n\t@echo $(X)\n' },
  { name: 'CRLF everywhere and one lone CR', makefile: 'all:\r\n\t@echo a\r\n\t@echo b\r' },
];

test('B2: a NUL byte or a CR that does not end a CRLF anywhere in the Makefile text is `unknown` (audit repro and variants)', () => {
  const failures = [];
  for (const row of B2_ROWS) {
    for (const options of [{ env: ENV }, { env: ENV, makefile: 'Makefile' }, { env: ENV, overrides: { STAGE: 'prod' } }, {}]) {
      const r = make(row.makefile.split('@M@').join('/m/MARKER'), ['all'], options);
      if (!(r.status === 'unknown' && r.reason === 'control_character')) failures.push(`${row.name} [${Object.keys(options).join(',')}]: ${show(r)}`);
    }
  }
  assert.deepEqual(failures, []);
});

test('B2: the answer is `unknown` for every wanted target and for a target the file does not have', () => {
  const text = 'all:\n\t@echo a\0\ndeploy:\n\t@touch x\n';
  for (const targets of [['all'], ['deploy'], ['nothing'], ['all', 'deploy'], []]) assert.equal(show(make(text, targets, { env: ENV })), 'unknown/control_character', JSON.stringify(targets));
});

test('B2 oracle: GNU make 4.3 joins the next line after a NUL, and the resolver does not read the file', { skip: oracleSkip }, () => {
  const rows = B2_ROWS;
  const failures = [];
  for (const row of rows) {
    const run = oracle({ makefile: row.makefile, targets: ['all'] });
    const r = S.resolveMakeTargets(nfs, run.dir, ['all'], { env: ENV });
    if (r.status !== 'unknown') failures.push(`${row.name}: ${show(r)}`);
  }
  assert.deepEqual(failures, []);
  if (!MAKE_43) return;
  // The audit's repro: the NUL ends the recipe line and the newline with it, so make runs `touch` for `all`.
  const hidden = oracle({ makefile: rows[0].makefile, targets: ['all'] });
  assert.equal(hidden.ranReal, true, 'make all creates the marker');
  assert.equal(hidden.real.status, 0);
  const listing = hidden.dry.stdout.split('\n').filter(Boolean);
  assert.deepEqual(listing, ['echo adeploy:', `touch ${join(hidden.dir, 'MARKER')}`]);
});

test('B2 controls: LF and CRLF files are read as before; CR and NUL inside a string of another file kind are not this rule', () => {
  assert.deepEqual(make('all:\n\t@echo a\n', ['all'], { env: ENV }).commands, ['echo a']);
  const crlf = make('all:\r\n\t@echo a\r\n\t@echo b\r\n', ['all'], { env: ENV });
  assert.ok(definite(crlf), show(crlf));
  assert.deepEqual(crlf.commands, ['echo a', 'echo b']);
  // The rule is on the Makefile text only: a NUL in a script file is the shebang code's business (F1), not this one.
  assert.equal(S.readScriptFile(createFakeFs().file('/s/x.sh', 'echo a\0b\n'), '/s/x.sh').status, 'ok');
});

