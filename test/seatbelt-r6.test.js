'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const fsn = require('node:fs');
const os = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');

// Patch round 6 (final micro-patch) for the two classes round 5 reported and did not fix: E1 (a make built-in appended
// a function, then expanded where make reads the line) and E2 (a plain assignment after `override`). The rule is the
// round-4 one: where the resolver cannot tell, the answer is `dynamic` / `unknown`. Rows marked `ran` are checked
// against GNU make itself when one is available (SEATBELT_ORACLE_MAKE, or `make` / `gmake` on PATH); the resolver
// assertions need no oracle.

const { createFakeFs } = require('./support/seatbelt-fake-fs.cjs');
const S = require('../dist/seatbelt-scripts.js');

const ROOT = fsn.realpathSync(fsn.mkdtempSync(join(os.tmpdir(), 'seatbelt-r6-')));
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
// resolver assertion, but not the version-specific facts (4.4 reads `:::=`, for one).
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

// ---------------------------------------------------------------- E1: a built-in variable appended a call, expanded where make reads the line

const ALL = 'all:\n\t@echo hi\n';

/**
 * `ran`: what GNU make 4.3 does with the row (the marker is created by make -n and by a real run alike: make expands
 * the right side of `:=`, the prerequisites of every rule it reads, and the recipe it runs or prints, at that time).
 * Every row must come back `dynamic` (or `unknown`): never a definite answer.
 */
const E1_ROWS = [
  // The round-5 repros.
  { name: 'repro: CC += $(shell); X := $(CC)', makefile: `CC += $(shell touch @M@)\nX := $(CC)\n${ALL}`, ran: true },
  { name: 'repro: RM += $(shell); X := $(RM)', makefile: `RM += $(shell touch @M@)\nX := $(RM)\n${ALL}`, ran: true },
  { name: 'repro: unwanted rule `unused: $(CC)`', makefile: `CC += $(shell touch @M@)\nunused: $(CC)\n${ALL}`, ran: true },
  // The five variants the brief names.
  { name: 'variant: `::=` consumer', makefile: `CC += $(shell touch @M@)\nX ::= $(CC)\n${ALL}`, ran: true },
  { name: 'variant: `:::=` consumer (an error in make 4.3: still never definite)', makefile: `CC += $(shell touch @M@)\nX :::= $(CC)\n${ALL}`, ran: false, errors: true },
  { name: 'variant: the built-in used in a recipe only (make expands the recipe when it prints or runs it)', makefile: `CC += $(shell touch @M@)\nall:\n\t@echo $(CC)\n`, ran: true },
  { name: 'variant: $(CC) inside $(if)', makefile: `CC += $(shell touch @M@)\nX := $(if $(CC),a,b)\n${ALL}`, ran: true },
  { name: 'variant: a chain Y = $(CC), then X := $(Y)', makefile: `CC += $(shell touch @M@)\nY = $(CC)\nX := $(Y)\n${ALL}`, ran: true },
  { name: 'variant: ${CC} in braces', makefile: `CC += $(shell touch @M@)\nX := \${CC}\n${ALL}`, ran: true },
  // More shapes of the same read.
  { name: 'a pure function around the built-in', makefile: `CC += $(shell touch @M@)\nX := $(strip $(CC))\n${ALL}`, ran: true },
  { name: 'a pure function around the built-in, in a prerequisite', makefile: `CC += $(shell touch @M@)\nunused: $(wildcard $(CC))\n${ALL}`, ran: true },
  { name: 'braces in a prerequisite', makefile: `CC += $(shell touch @M@)\nunused: \${CC}\n${ALL}`, ran: true },
  { name: 'order-only prerequisite', makefile: `CC += $(shell touch @M@)\nunused: | $(CC)\n${ALL}`, ran: true },
  { name: '`+=` onto a simple variable', makefile: `CC += $(shell touch @M@)\nZ := a\nZ += $(CC)\n${ALL}`, ran: true },
  { name: 'another built-in: CXX', makefile: `CXX += $(shell touch @M@)\nX := $(CXX)\n${ALL}`, ran: true },
  { name: 'another built-in: AR', makefile: `AR += $(shell touch @M@)\nunused: $(AR)\n${ALL}`, ran: true },
  { name: 'a built-in family: COMPILE.c', makefile: `COMPILE.c += $(shell touch @M@)\nX := $(COMPILE.c)\n${ALL}`, ran: true },
  { name: 'the call is $(file)', makefile: `CC += $(file >@M@,x)\nX := $(CC)\n${ALL}`, ran: true },
  { name: 'the call is $(eval)', makefile: `CC += $(eval $(shell touch @M@))\nX := $(CC)\n${ALL}`, ran: true },
  { name: 'the call is $(call) of a variable that holds $(shell)', makefile: `F = $(shell touch @M@)\nCC += $(call F)\nX := $(CC)\n${ALL}`, ran: true },
  { name: 'the call is a variable that holds $(shell)', makefile: `F = $(shell touch @M@)\nCC += $(F)\nX := $(CC)\n${ALL}`, ran: true },
  { name: 'the built-in appended twice, the call first', makefile: `CC += $(shell touch @M@)\nCC += -O2\nX := $(CC)\n${ALL}`, ran: true },
  { name: 'the built-in appended twice, the call last', makefile: `CC += -O2\nCC += $(shell touch @M@)\nX := $(CC)\n${ALL}`, ran: true },
  { name: 'tabs and no blanks around the operators', makefile: `CC\t+=\t$(shell touch @M@)\nX:=$(CC)\n${ALL}`, ran: true },
  { name: 'line continuation', makefile: `CC += $(shell touch \\\n@M@)\nX := $(CC)\n${ALL}`, ran: true },
];

test('E1: an unresolved variable that holds a call is never definite where make expands it (round-5 repros and variants)', () => {
  const failures = [];
  for (const row of E1_ROWS) {
    const r = resolve(row);
    if (definite(r)) failures.push(`${row.name}: ${show(r)}`);
  }
  assert.deepEqual(failures, []);
});

test('E1 oracle: GNU make 4.3 runs the call at read time (and in a recipe), and the resolver is never definite there', { skip: oracleSkip }, () => {
  const failures = [];
  for (const row of E1_ROWS) {
    const run = oracle(row);
    // The oracle's own answer first: the table above is what make 4.3 does.
    if (MAKE_43) {
      assert.equal(run.ranDry, row.ran, `${row.name}: make -n ran the payload`);
      assert.equal(run.ranReal, row.ran, `${row.name}: make ran the payload`);
      if (row.errors) assert.notEqual(run.real.status, 0, `${row.name}: make fails`);
    }
    const r = resolve(row);
    if (definite(r) && (run.ranDry || run.ranReal)) failures.push(`${row.name}: ${show(r)} (make ran the payload)`);
    if (definite(r) && row.ran) failures.push(`${row.name}: ${show(r)}`);
  }
  assert.deepEqual(failures, []);
});

test('E1: every built-in x consumer x call is never definite', () => {
  const builtins = ['CC', 'RM', 'CXX', 'AR', 'COMPILE.c'];
  const calls = ['$(shell echo a)', '${shell echo a}', '$(eval Z := a)', '${eval Z := a}', '$(file >f,x)', '$(call f,a)', '$(foreach a,b,$(shell c))', 'a $(shell b) c', '$(subst a,b,$(shell c))', '$(Y)'];
  const consumers = [
    (n) => `X := $(${n})\n`,
    (n) => `X ::= $(${n})\n`,
    (n) => `X :::= $(${n})\n`,
    (n) => `X := \${${n}}\n`,
    (n) => `X := a $(${n}) b\n`,
    (n) => `X := $(strip $(${n}))\n`,
    (n) => `X := $(if $(${n}),a,b)\n`,
    (n) => `X := a\nX += $(${n})\n`,
    (n) => `Y = $(${n})\nX := $(Y)\n`,
    (n) => `unused: $(${n})\n`,
    (n) => `unused: a $(${n}) b\n`,
    (n) => `unused: | $(${n})\n`,
    (n) => `unused: \${${n}}\n`,
    (n) => `unused: $(wildcard $(${n}))\n`,
  ];
  const failures = [];
  for (const name of builtins) {
    for (const call of calls) {
      for (const consumer of consumers) {
        const text = `Y = $(shell echo y)\n${name} += ${call}\n${consumer(name)}${ALL}`;
        const r = make(text, ['all'], { env: ENV });
        if (definite(r)) failures.push(`${JSON.stringify(text)}: ${show(r)}`);
      }
    }
  }
  assert.deepEqual(failures, []);
});

test('E1 controls: a built-in appended plain text, a call nothing expands, or a consumer before the append stay definite', () => {
  const controls = [
    ['plain value, `:=` consumer', `CC += -O2\nX := $(CC)\n${ALL}`],
    ['plain value, prerequisite consumer', `CC += -O2\nunused: $(CC)\n${ALL}`],
    ['a variable that is not a built-in', `CCX += -O2\nX := $(CCX)\n${ALL}`],
    ['the call is appended and nothing expands it', `CC += $(shell touch @M@)\n${ALL}`],
    ['the consumer is read before the append', `X := $(CC)\nCC += $(shell touch @M@)\n${ALL}`],
    ['an assignment with `=` of a plain value', `CC = gcc\nX := $(CC)\n${ALL}`],
    ['a comment', `# CC += $(shell touch @M@)\nX := $(CC)\n${ALL}`],
    // A simple variable holds text make has already expanded: reading it runs nothing, whatever the resolver kept of it.
    ['a simple variable of an undefined reference, read later', `X := $(UNDEFINED)\nUNDEFINED = $(shell touch @M@)\nW := $(X)\n${ALL}`],
    ['a simple variable of an undefined reference, in a prerequisite', `X := $(UNDEFINED)\nUNDEFINED = $(shell touch @M@)\nunused: $(X)\n${ALL}`],
  ];
  for (const [name, makefile] of controls) {
    const r = resolve({ makefile });
    assert.ok(definite(r), `${name}: ${show(r)}`);
  }
  if (MAKE_BINARY === null) return;
  // And make agrees: none of them runs the call.
  for (const [name, makefile] of controls) {
    const run = oracle({ makefile });
    assert.equal(run.ranDry || run.ranReal, false, `${name}: make ran a payload`);
  }
});

test('E1 abuse: misleading words and a name that only looks like a built-in', () => {
  // A call in a name that is not a built-in variable is a function the resolver could always see: still dynamic.
  assert.ok(!definite(resolve({ makefile: `CCX = $(shell touch @M@)\nX := $(CCX)\n${ALL}` })));
  // The built-in spelled in another case is a plain variable: make expands the call there too, and so is the answer.
  const lower = resolve({ makefile: `cc += $(shell touch @M@)\nX := $(cc)\n${ALL}` });
  assert.ok(!definite(lower), show(lower));
  // The recipe text of another rule is not read when the rule is not wanted.
  const unwanted = resolve({ makefile: `CC += $(shell touch @M@)\nunused:\n\t@echo $(CC)\n${ALL}` });
  assert.ok(definite(unwanted), show(unwanted));
  assert.deepEqual(unwanted.commands, ['echo hi']);
});

// ---------------------------------------------------------------- E2: an assignment without `override` to a name the file assigned with `override`

const SHOW_X = 'all:\n\t@echo $(X)\n';
const STAGE_ROW = (value) => `deploy:\n\t@echo deploying $(STAGE)\n${value || ''}`;

/**
 * `ran`: what GNU make 4.3 does with the row (as above). `prints`: what the one recipe prints, which is the value make
 * keeps. `commands`: the command list the resolver must give (the kept value, not the dropped one). `dynamic`: the
 * answer must not be definite (every row of this table: a name assigned with `override` and again without it).
 */
const E2_ROWS = [
  // The round-5 repros.
  { name: 'repro: override X = a, then X = b (make prints a)', makefile: `override X = a\nX = b\n${SHOW_X}`, ran: false, prints: 'a', commands: ['echo a'] },
  { name: 'repro: override STAGE += $(file), then STAGE ::= a b (make creates the file)', makefile: 'override STAGE += $(file >@M@,x)\nSTAGE ::= a b\nall:\n\t@echo $(STAGE)\n', ran: true, prints: '' },
  // The six variants the brief names.
  { name: 'variant: override, then +=', makefile: `override X = a\nX += b\n${SHOW_X}`, ran: false, prints: 'a', commands: ['echo a'] },
  { name: 'variant: override, then ?=', makefile: `override X = a\nX ?= b\n${SHOW_X}`, ran: false, prints: 'a', commands: ['echo a'] },
  { name: 'variant: override, then != (make runs the command and drops the value)', makefile: `override X = a\nX != touch @M@\n${SHOW_X}`, ran: true, prints: 'a' },
  { name: 'variant: a plain line between two overrides (the second override applies)', makefile: `override X = a\nX = b\noverride X = c\n${SHOW_X}`, ran: false, prints: 'c', commands: ['echo c'] },
  { name: 'variant: override inside define/endef is text, the plain line after it applies', makefile: `define BODY\noverride X = a\nendef\nX = b\n${SHOW_X}`, ran: false, prints: 'b' },
  { name: 'variant: override define, then X = b', makefile: `override define X\na\nendef\nX = b\n${SHOW_X}`, ran: false, prints: 'a' },
  { name: 'variant: target-specific override, then the global X = b', makefile: `all: override X = a\nX = b\n${SHOW_X}`, ran: false, prints: 'a' },
  // Right sides that make reads before it drops the assignment (B1 shapes, for a name the file overrode).
  { name: ':= with $(shell) after override :=', makefile: `override X := a\nX := $(shell touch @M@)\n${SHOW_X}`, ran: true, prints: 'a' },
  { name: '::= with $(shell) after override', makefile: `override X = a\nX ::= $(shell touch @M@)\n${SHOW_X}`, ran: true, prints: 'a' },
  { name: '+= of a $(shell) onto an overridden simple variable (make expands it, then drops it)', makefile: `override X := a\nX += $(shell touch @M@)\n${SHOW_X}`, ran: true, prints: 'a' },
  { name: '= with $(shell) (not expanded: dropped unread)', makefile: `override X = a\nX = $(shell touch @M@)\n${SHOW_X}`, ran: false, prints: 'a', commands: ['echo a'] },
  { name: '+= with $(shell) onto an overridden recursive variable (not expanded)', makefile: `override X = a\nX += $(shell touch @M@)\n${SHOW_X}`, ran: false, prints: 'a', commands: ['echo a'] },
  { name: 'the call is in the override, a plain line follows', makefile: `override X = $(shell touch @M@)\nX = b\n${SHOW_X}`, ran: true, prints: '' },
  { name: 'override += on a built-in, then a plain assignment', makefile: 'override CC += -O2\nCC = x\nall:\n\t@echo $(CC)\n', ran: false, prints: 'cc -O2' },
  { name: 'override ?= that defines (nothing set it before), then a plain assignment', makefile: `override X ?= a\nX = c\n${SHOW_X}`, ran: false, prints: 'a', commands: ['echo a'] },
  { name: 'production mislabelled: override STAGE = prod, then STAGE = dev', makefile: `override STAGE = prod\nSTAGE = dev\ndeploy:\n\t@echo deploying $(STAGE)\n`, targets: ['deploy'], ran: false, prints: 'deploying prod', commands: ['echo deploying prod'] },
  { name: 'production mislabelled: override STAGE := dev, then STAGE != touch; echo prod', makefile: `override STAGE := dev\nSTAGE != touch @M@; echo prod\ndeploy:\n\t@echo deploying $(STAGE)\n`, targets: ['deploy'], ran: true, prints: 'deploying dev' },
  { name: 'spelling: tabs and no blanks', makefile: `override\tX=a\nX\t=\tb\n${SHOW_X}`, ran: false, prints: 'a', commands: ['echo a'] },
  { name: 'spelling: continuation in the override', makefile: `override X = \\\na\nX = b\n${SHOW_X}`, ran: false, prints: 'a' },
  { name: 'spelling: the plain line after other lines and rules', makefile: `override X = a\nY = y\nother:\n\t@echo o\nX = b\n${SHOW_X}`, ran: false, prints: 'a', commands: ['echo a'] },
];

test('E2: a plain assignment to a name the file assigned with override is never definite, and the value kept is the override\'s', () => {
  const failures = [];
  for (const row of E2_ROWS) {
    const r = resolve(row);
    if (definite(r)) failures.push(`${row.name}: ${show(r)}`);
    if (row.commands !== undefined && !(r.status === 'ok' && JSON.stringify(r.commands) === JSON.stringify(row.commands))) failures.push(`${row.name}: commands ${show(r)}, want ${JSON.stringify(row.commands)}`);
  }
  assert.deepEqual(failures, []);
});

test('E2 oracle: GNU make 4.3 keeps the override (and still reads the dropped right side), and the resolver is never definite there', { skip: oracleSkip }, () => {
  const failures = [];
  for (const row of E2_ROWS) {
    const run = oracle(row);
    if (MAKE_43) {
      assert.equal(run.ranDry, row.ran, `${row.name}: make -n ran the payload`);
      assert.equal(run.ranReal, row.ran, `${row.name}: make ran the payload`);
      assert.equal(run.real.status, 0, `${row.name}: make rc`);
      if (row.prints !== undefined) assert.equal(run.real.stdout.trim(), row.prints, `${row.name}: make prints`);
    }
    const r = resolve(row);
    if (definite(r)) failures.push(`${row.name}: ${show(r)} (make prints ${JSON.stringify(run.real.stdout.trim())}, ${run.ranDry || run.ranReal ? 'ran' : 'did not run'} the payload)`);
  }
  assert.deepEqual(failures, []);
});

test('E2: an override that is the last assignment applies: the file with no plain line after it is read as before and is definite', () => {
  const rows = [
    ['override, then a second override', `override X = a\noverride X = c\n${SHOW_X}`, 'echo c', 'c'],
    ['override := then override +=', `override X := a\noverride X += b\n${SHOW_X}`, 'echo a b', 'a b'],
    ['plain, then override', `X = a\noverride X = c\n${SHOW_X}`, 'echo c', 'c'],
    ['a plain assignment before the override only', `X = z\nX = b\noverride X = a\n${SHOW_X}`, 'echo a', 'a'],
    ['override of one name, plain assignment of another', `override X = a\nY = b\nall:\n\t@echo $(X) $(Y)\n`, 'echo a b', 'a b'],
    ['a name that only begins like the overridden one', `override X = a\nXX = b\nall:\n\t@echo $(X)$(XX)\n`, 'echo ab', 'ab'],
    ['another case is another name', `override X = a\nx = b\n${SHOW_X}`, 'echo a', 'a'],
    ['override ?= when the name was set before: nothing assigned, a plain line applies', `X = p\noverride X ?= a\nX = c\n${SHOW_X}`, 'echo c', 'c'],
    ['no override at all', `X = a\nX = b\n${SHOW_X}`, 'echo b', 'b'],
    ['a comment that says override', `# override X = a\nX = b\n${SHOW_X}`, 'echo b', 'b'],
    ['the command line has the name too (already kept, as before)', `override X = a\nX = b\n${SHOW_X}`, 'echo a', 'a', { X: 'y' }],
  ];
  for (const [name, makefile, command, prints, overrides] of rows) {
    const r = resolve({ makefile, overrides });
    assert.ok(definite(r), `${name}: ${show(r)}`);
    assert.deepEqual(r.commands, [command], name);
    if (MAKE_BINARY !== null && MAKE_43) {
      const run = oracle({ makefile, overrides });
      assert.equal(run.real.stdout.trim(), prints, `${name}: make prints`);
      assert.equal(run.ranDry || run.ranReal, false, `${name}: make ran a payload`);
    }
  }
});

test('E2: after an override, no operator and no right side makes a plain assignment definite', () => {
  const overrides = ['override X = a', 'override X := a', 'override X ::= a', 'override X += a', 'override X ?= a', 'override X != echo a', 'override X = $(shell echo a)', 'override X := $(Y)'];
  const operators = ['=', ':=', '::=', ':::=', '?=', '+=', '!='];
  const rights = ['b', 'a', '$(shell echo b)', '${shell echo b}', '$(eval Z := 1)', '$(file >f,x)', '$(call f,a)', '$(Y)', '$(UNDEFINED)', '$$x', '$(subst a,b,c)', 'a$', '$(shell echo', ''];
  const failures = [];
  for (const first of overrides) {
    for (const op of operators) {
      for (const right of rights) {
        const text = `Y = y\n${first}\nX ${op} ${right}\n${SHOW_X}`;
        const r = make(text, ['all'], { env: ENV });
        if (definite(r)) failures.push(`${JSON.stringify(text)}: ${show(r)}`);
      }
    }
  }
  assert.deepEqual(failures, []);
});

test('E2: the same holds when the plain assignment comes later, between rules, after a recipe, and for every later one', () => {
  const failures = [];
  const rows = [
    `override X = a\nall:\n\t@echo $(X)\nX = b\n`,
    `override X = a\nall: dep\n\t@echo $(X)\ndep:\n\t@echo d\nX = b\n`,
    `override X = a\nX = b\nX = c\n${SHOW_X}`,
    `override X = a\nX = b\nX := c\n${SHOW_X}`,
    `override X = a\nY = 1\nX = b\nZ = 2\n${SHOW_X}`,
    `override X = a\nX:=b\n${SHOW_X}`,
    `override X = a\nX\t?=\tb\n${SHOW_X}`,
  ];
  for (const text of rows) {
    const r = make(text, ['all'], { env: ENV });
    if (definite(r)) failures.push(`${JSON.stringify(text)}: ${show(r)}`);
  }
  assert.deepEqual(failures, []);
});

test('E2: the override of the command line is not made stricter than before (the name is kept, the answer stays definite when the right side is inert)', () => {
  const r = make(`X = b\n${SHOW_X}`, ['all'], { env: ENV, overrides: { X: 'y' } });
  assert.ok(definite(r), show(r));
  assert.deepEqual(r.commands, ['echo y']);
  const both = make(`override X = a\nX = b\n${SHOW_X}`, ['all'], { env: ENV, overrides: { X: 'y' } });
  assert.ok(definite(both), show(both));
  assert.deepEqual(both.commands, ['echo a']);
});
