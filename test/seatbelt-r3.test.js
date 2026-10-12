const assert = require('node:assert/strict');
const test = require('node:test');

// Patch round 3 for Barvis's delta audit of db578c2c (N1-N5). The audit's own
// tests are in seatbelt-audit-delta*.test.js; these add the class variants:
// every answer the resolver cannot be sure of is unknown, never definite.

const { createFakeFs } = require('./support/seatbelt-fake-fs.cjs');
const G = require('../dist/seatbelt-git.js');
const P = require('../dist/seatbelt-path.js');
const S = require('../dist/seatbelt-scripts.js');

const HOME = '/home/u';
const FEAT = { kind: 'branch', branch: 'feat' };

// ---------------------------------------------------------------- git (N1, N2)

function repoFs(extra = {}) {
  const fs = createFakeFs()
    .mkdir(HOME)
    .file('/w/.git/HEAD', 'ref: refs/heads/feat\n')
    .file('/w/.git/config', `[alias]\n\tp = status\n\tk = status\n${extra.config || ''}`)
    // A cloned repo that ships a top-level bare layout and its own config.
    .file('/w/HEAD', 'ref: refs/heads/feat\n')
    .file('/w/objects/.keep', '')
    .file('/w/refs/.keep', '')
    .file('/w/config', '[alias]\n\tp = push -f origin main\n\tk = push -f origin main\n[remote "origin"]\n\tpush = +refs/heads/*:refs/heads/*\n')
    .file('/inc/force.cfg', '[alias]\n\tk = push -f origin main\n')
    .file('/inc/push.cfg', '[remote "origin"]\n\tpush = +refs/heads/*:refs/heads/main\n')
    .file(`${HOME}/inc.cfg`, '[alias]\n\tk = push -f origin main\n')
    .file('/inc/outer.cfg', '[include]\n\tpath = /inc/force.cfg\n');
  return fs;
}

function context(fs, extra = {}) {
  const env = extra.env || {};
  const config = G.loadGitConfig(fs, { home: HOME, dirs: G.discoverGitDirs(fs, '/w', env), env, systemFiles: [] });
  return { config, env, ...(extra.withFs ? { fs, home: HOME } : {}) };
}

const kinds = (exps) => exps.map((e) => (e.kind === 'unknown' ? `unknown:${e.reason}` : e.kind));
const definiteStatus = (exps) => exps.length === 1 && exps[0].kind === 'git' && exps[0].invocation.subcommand === 'status';
const forcePush = (exps) => exps.some((e) => e.kind === 'git' && e.invocation.subcommand === 'push' && e.invocation.args.some((a) => /^(-f|--force.*|\+.*)$/.test(a)));

test('N1: --bare (GIT_DIR=$PWD) is relocated: never a definite answer from the discovered config', () => {
  const fs = repoFs();
  const ctx = context(fs);
  // The discovered config says `p = status`; git --bare reads /w/config.
  assert.ok(definiteStatus(G.expandGitAliases(['p'], ctx)), 'control: without --bare it is one definite status');
  const inv = G.parseGitInvocation(['--bare', 'p']);
  assert.deepEqual(inv.relocated, ['--bare']);
  assert.ok(inv.unknownGlobals.includes('--bare'), 'also visible to a caller that checks only unknownGlobals');
  for (const argv of [['--bare', 'p'], ['-c', 'a.b=c', '--bare', 'p'], ['--no-pager', '--bare', 'p', 'origin'], ['--bare', 'push', '-f', 'origin', 'main'], ['--bare', 'status']]) {
    const exps = G.expandGitAliases(argv, ctx);
    assert.ok(exps.some((e) => e.kind === 'unknown' && e.reason === 'relocated'), `${argv.join(' ')}: ${kinds(exps)}`);
    assert.equal(definiteStatus(exps), false, argv.join(' '));
  }
  // The flag inside an alias definition.
  const viaAlias = repoFs({ config: '\tq = --bare status\n' });
  const exps = G.expandGitAliases(['q'], context(viaAlias));
  assert.ok(exps.some((e) => e.kind === 'unknown' && e.reason === 'relocated'), kinds(exps));
});

test('N1 class: every global flag that moves repo, config, namespace or exec path is relocated (flag twins of GIT_RELOCATING_ENV)', () => {
  const ctx = context(repoFs());
  const forms = [['--exec-path=/x', 'p'], ['--exec-path', 'p'], ['--namespace', 'n', 'p'], ['--namespace=n', 'p'], ['--attr-source=HEAD', 'p'], ['--attr-source', 'HEAD', 'p'], ['--super-prefix=x/', 'p'], ['--git-dir=/evil', 'p'], ['--git-dir', '/evil', 'p'], ['--work-tree=/evil', 'p'], ['-C', '/evil', 'p'], ['--bare', '--git-dir=/evil', 'p']];
  for (const argv of forms) {
    const exps = G.expandGitAliases(argv, ctx);
    assert.ok(exps.some((e) => e.kind === 'unknown' && e.reason === 'relocated'), `${argv.join(' ')}: ${kinds(exps)}`);
  }
  // Not relocating: pager, lazy-fetch and pathspec switches keep one definite answer.
  for (const argv of [['--no-pager', 'p'], ['-p', 'p'], ['--no-optional-locks', 'p'], ['--literal-pathspecs', 'p'], ['-c', 'color.ui=false', 'p']]) {
    assert.ok(definiteStatus(G.expandGitAliases(argv, ctx)), argv.join(' '));
  }
  // The env twin of every flag is relocated too (consistency).
  for (const name of ['GIT_NAMESPACE', 'GIT_EXEC_PATH', 'GIT_DIR']) {
    const exps = G.expandGitAliases(['p'], { config: ctx.config, env: { [name]: '/x' } });
    assert.ok(exps.some((e) => e.kind === 'unknown'), name);
  }
});

test('N1 discovery: a bare layout at the cwd level is found (git reads its config), also below a .git-less level', () => {
  const fs = createFakeFs().file('/r/sub/HEAD', 'ref: refs/heads/x\n').mkdir('/r/sub/objects').mkdir('/r/sub/refs').file('/r/sub/config', '[alias]\n\tp = push -f\n').mkdir('/r/.git');
  assert.deepEqual(G.discoverGitDirs(fs, '/r/sub'), { gitDir: '/r/sub', commonDir: '/r/sub' });
  assert.deepEqual(G.discoverGitDirs(fs, '/r'), { gitDir: '/r/.git', commonDir: '/r/.git' });
});

test('N2: -c include.path / includeIf.*.path / --config-env are expanded like git, or the answer is unknown', () => {
  const fs = repoFs();
  const plain = context(fs);
  const withFs = context(fs, { withFs: true });
  const include = ['-c', 'include.path=/inc/force.cfg', 'k'];
  // No fs to read the file: unknown, never the repo's `status`.
  const blind = G.expandGitAliases(include, plain);
  assert.ok(blind.some((e) => e.kind === 'unknown' && e.reason === 'config_incomplete'), kinds(blind));
  assert.equal(definiteStatus(blind), false);
  // With fs: expanded, so the included definition is a candidate (git uses the last one).
  const expanded = G.expandGitAliases(include, withFs);
  assert.ok(forcePush(expanded), JSON.stringify(kinds(expanded)));
  // Mixed-case keys, includeIf, nested includes, `~/` paths, --config-env, and an alias carrying its own -c.
  for (const argv of [['-c', 'Include.Path=/inc/force.cfg', 'k'], ['-c', 'includeIf.gitdir:/w/.path=/inc/force.cfg', 'k'], ['-c', 'INCLUDEIF.onbranch:feat.PATH=/inc/force.cfg', 'k'], ['-c', 'include.path=/inc/outer.cfg', 'k'], ['-c', `include.path=~/inc.cfg`, 'k']]) {
    assert.ok(forcePush(G.expandGitAliases(argv, withFs)), argv.join(' '));
    assert.equal(definiteStatus(G.expandGitAliases(argv, plain)), false, `no fs: ${argv.join(' ')}`);
  }
  const viaEnv = G.expandGitAliases(['--config-env', 'include.path=INC', 'k'], { ...withFs, env: { INC: '/inc/force.cfg' } });
  assert.ok(forcePush(viaEnv), kinds(viaEnv));
  assert.ok(G.expandGitAliases(['--config-env', 'include.path=NOPE', 'k'], withFs).some((e) => e.kind === 'unknown'));
  const aliasCarrying = context(repoFs({ config: '\tc = -c include.path=/inc/force.cfg k\n' }), { withFs: true });
  assert.ok(forcePush(G.expandGitAliases(['c'], aliasCarrying)), 'alias with its own -c include.path');
  // Unreadable, relative, ~user and too-deep includes: unknown.
  for (const value of ['/inc/missing-but-absent.cfg-is-fine-but-relative', 'rel/force.cfg', '~root/x.cfg']) {
    const exps = G.expandGitAliases(['-c', `include.path=${value}`, 'k'], withFs);
    if (value.startsWith('/')) assert.ok(definiteStatus(exps), `an absent absolute include adds nothing: ${kinds(exps)}`);
    else assert.ok(exps.some((e) => e.kind === 'unknown' && e.reason === 'config_incomplete'), `${value}: ${kinds(exps)}`);
  }
  const broken = repoFs().fail('/inc/force.cfg');
  assert.ok(G.expandGitAliases(include, context(broken, { withFs: true })).some((e) => e.kind === 'unknown' && e.reason === 'config_incomplete'));
});

test('N2 env: GIT_CONFIG_COUNT / GIT_CONFIG_PARAMETERS include.path is seen even when config was loaded from another env', () => {
  const fs = repoFs();
  const base = context(fs); // loaded with an empty env
  const env = { GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'include.path', GIT_CONFIG_VALUE_0: '/inc/force.cfg' };
  const blind = G.expandGitAliases(['k'], { config: base.config, env });
  assert.ok(blind.some((e) => e.kind === 'unknown' && e.reason === 'config_incomplete'), kinds(blind));
  assert.ok(forcePush(G.expandGitAliases(['k'], { config: base.config, env, fs, home: HOME })));
  const params = { GIT_CONFIG_PARAMETERS: "'include.path=/inc/force.cfg'" };
  assert.ok(forcePush(G.expandGitAliases(['k'], { config: base.config, env: params, fs, home: HOME })));
  const malformed = { GIT_CONFIG_PARAMETERS: "'include.path" };
  assert.ok(G.expandGitAliases(['k'], { config: base.config, env: malformed, fs, home: HOME }).some((e) => e.kind === 'unknown'));
  // The same env on both sides is still one include read, and a clean env still gives one definite answer.
  assert.ok(definiteStatus(G.expandGitAliases(['k'], { config: base.config, env: {}, fs, home: HOME })));
});

test('N2 consumers: per-invocation -c pairs (and what they include) reach implicitPushTargets through withInvocationConfig', () => {
  const fs = repoFs();
  const withFs = context(fs, { withFs: true });
  const push = (argv) => {
    const git = G.expandGitAliases(argv, withFs).find((e) => e.kind === 'git');
    return G.implicitPushTargets(G.withInvocationConfig(withFs.config, git.invocation), FEAT, 'origin');
  };
  assert.equal(push(['push', 'origin']).forceFromConfig, false, 'control');
  assert.equal(push(['-c', 'remote.origin.push=+refs/heads/*:refs/heads/main', 'push', 'origin']).forceFromConfig, true);
  const included = push(['-c', 'include.path=/inc/push.cfg', 'push', 'origin']);
  assert.equal(included.forceFromConfig, true, 'a force refspec behind an included file');
  assert.equal(included.all, true, 'a pattern refspec may update any branch');
  assert.equal(push(['-c', 'remote.origin.mirror=true', 'push', 'origin']).mirror, true);
  // The base config is not mutated.
  assert.equal(G.implicitPushTargets(withFs.config, FEAT, 'origin').forceFromConfig, false);
});

test('N2 budget: a planted include chain cannot read without bound', () => {
  let fs = repoFs();
  for (let i = 0; i < 200; i += 1) fs = fs.file(`/chain/${i}.cfg`, `[include]\n\tpath = /chain/${i + 1}.cfg\n`);
  const exps = G.expandGitAliases(['-c', 'include.path=/chain/0.cfg', 'k'], context(fs, { withFs: true }));
  assert.ok(exps.some((e) => e.kind === 'unknown' && e.reason === 'config_incomplete'), kinds(exps));
});

// -------------------------------------------------------------------- path (N3)

function pathTree() {
  return createFakeFs().mkdir(`${HOME}/.ssh`).mkdir(`${HOME}/proj/.git`).mkdir(`${HOME}/proj/sub`).file(`${HOME}/proj/sub/x`, '');
}

function pathClass(raw, variables, extra = {}) {
  const fs = pathTree();
  const ws = P.resolveWorkspace(fs, { eventCwd: `${HOME}/proj`, home: HOME });
  return P.classifyDeleteTarget(fs, ws, P.resolveOperand(fs, { home: HOME, cwd: `${HOME}/proj`, variables, ...extra }, raw, 'delete'));
}

test('N3: ~+ is the shell PWD: a PWD set earlier makes it unknown, never the event cwd', () => {
  assert.equal(pathClass('~+/sub'), 'in_workspace', 'control: no earlier PWD');
  assert.equal(pathClass('~+/sub', { PWD: `${HOME}/proj` }), 'in_workspace', 'PWD equal to the cwd is the cwd');
  for (const pwd of [HOME, '/', '.', `${HOME}/proj/`, `${HOME}/proj/sub`, '', '$HOME']) {
    assert.notEqual(pathClass('~+/.ssh', { PWD: pwd }), 'in_workspace', `PWD=${pwd}`);
    assert.equal(pathClass('~+/.ssh', { PWD: pwd }), 'unknown', `PWD=${pwd}`);
    assert.equal(pathClass('$PWD/.ssh', { PWD: pwd }), 'unknown', `$PWD, PWD=${pwd}`);
    assert.equal(pathClass('${PWD}/.ssh', { PWD: pwd }), 'unknown', `\${PWD}, PWD=${pwd}`);
  }
  const expanded = P.expandPathOperand('~+', { home: HOME, cwd: `${HOME}/proj`, variables: { PWD: '/' } });
  assert.deepEqual(expanded, { kind: 'dynamic', reason: 'no_cwd' });
  assert.deepEqual(P.expandPathOperand('~+/x', { home: HOME, cwd: null }), { kind: 'dynamic', reason: 'no_cwd' });
});

test('N3 class: ~-, ~N, ~+N, ~-N, ~user and tilde-leading variable values are unknown unless certain', () => {
  for (const raw of ['~-', '~-/x', '~-/.ssh', '~1', '~0/x', '~12', '~+1', '~+1/x', '~-1', '~-2/.ssh', '~+/../x/~-']) {
    const expanded = P.expandPathOperand(raw, { home: HOME, cwd: `${HOME}/proj`, variables: { OLDPWD: HOME } });
    if (raw === '~+/../x/~-') continue;
    assert.equal(expanded.kind, 'dynamic', raw);
  }
  // `~N` is a directory-stack entry even when a passwd lookup would answer for a user named like the number.
  assert.deepEqual(P.expandPathOperand('~1/x', { home: HOME, cwd: `${HOME}/proj`, userHome: () => `${HOME}/proj` }), { kind: 'dynamic', reason: 'tilde' });
  assert.equal(pathClass('~-/.ssh', { OLDPWD: HOME }), 'unknown');
  assert.equal(pathClass('$OLDPWD/.ssh'), 'unknown', 'OLDPWD unset in variables: the shell may have one');
  assert.equal(pathClass('$OLDPWD/.ssh', { OLDPWD: HOME }), 'outside_workspace', 'set earlier: its value (a child of home)');
  assert.equal(pathClass('$OLDPWD', { OLDPWD: HOME }), 'home');
  // ~user: only through the caller's passwd lookup; never the workspace by guess.
  assert.equal(pathClass('~root/.ssh'), 'unknown');
  assert.equal(pathClass('~nobody'), 'unknown');
  assert.equal(pathClass('~alice/x', undefined, { userHome: (user) => (user === 'alice' ? '/home/alice' : null) }), 'outside_workspace');
  assert.equal(pathClass('~ghost/x', undefined, { userHome: () => null }), 'unknown');
  // A value that still starts with `~` was not tilde-expanded by the caller (bash expands it at assignment, never later).
  assert.equal(pathClass('$X/.ssh', { X: '~' }), 'unknown');
  assert.equal(pathClass('$X', { X: '~/.ssh' }), 'unknown');
  assert.equal(pathClass('$X', { X: 'sub' }), 'in_workspace');
});

test('N3 globs: bracket expressions with `!`, a leading `]` or a [:class:] are matched, not skipped', () => {
  const fs = createFakeFs().mkdir('/home/u/proj/.git').mkdir('/home/u/.ssh').symlink('/home/u/proj/a', '/home/u').symlink('/home/u/proj/]', '/home/u').symlink('/home/u/proj/Q', '/');
  const ws = P.resolveWorkspace(fs, { eventCwd: '/home/u/proj', home: HOME });
  const cls = (raw) => P.classifyDeleteTarget(fs, ws, P.resolveOperand(fs, { home: HOME, cwd: '/home/u/proj' }, raw, 'delete'));
  for (const raw of ['[[:alpha:]]/', '[!x]/', '[]x]/', '[!]x]/', '[^x]/']) assert.notEqual(cls(raw), 'in_workspace', raw);
});

// ------------------------------------------------------------------ make (N4)

const make = (text, targets = ['all'], options = {}) => S.resolveMakeTargets(createFakeFs().file('/m/Makefile', text), '/m', targets, options);
const shows = (r) => r.status === 'ok' && r.commands.some((c) => /vercel/.test(c));
const definiteNoDeploy = (r) => r.status === 'ok' && !r.dynamic && !shows(r);
const hidden = (r) => r.status === 'ok' && !r.dynamic && !shows(r);

test('N4: a multi-word variable in prerequisites is split into words and every word is followed', () => {
  const text = 'STEPS = build deploy\nall: $(STEPS)\nbuild:\n\techo build\ndeploy:\n\tvercel --prod\n';
  assert.ok(shows(make(text)));
  assert.ok(shows(make(text.replace('STEPS = build deploy\n', ''), ['all'], { overrides: { STEPS: 'build deploy' } })));
  assert.ok(shows(make(text.replace('$(STEPS)', '${STEPS}'))), '${VAR} form');
  assert.ok(shows(make('A = deploy\nB = $(A)\nall: build $(B)\nbuild:\n\techo\ndeploy:\n\tvercel --prod\n')), 'nested');
  assert.ok(shows(make('A = de\nall: $(A)ploy\ndeploy:\n\tvercel --prod\n')), 'prefix + reference');
  assert.ok(shows(make('X = deploy\nY = X\nall: $($(Y))\ndeploy:\n\tvercel --prod\n')), 'computed name');
  assert.ok(shows(make('all: build | deploy\nbuild:\n\techo\ndeploy:\n\tvercel --prod\n')), 'order-only');
  assert.ok(shows(make('STEPS = build\nSTEPS += deploy\nall: $(STEPS)\ndeploy:\n\tvercel --prod\n')), '+=');
});

test('N4: prerequisites and target names are expanded when the line is read; := when assigned; recipes at the end', () => {
  // The prerequisite list is fixed at the rule line: a later reassignment does not remove deploy.
  assert.ok(shows(make('STEPS = build deploy\nall: $(STEPS)\nSTEPS = build\ndeploy:\n\tvercel --prod\n')));
  // := captured at assignment: B stays `deploy` although A changes later.
  assert.ok(shows(make('A = deploy\nB := $(A)\nA = build\nall: $(B)\ndeploy:\n\tvercel --prod\n')));
  // = is deferred in recipes: the value at the end of the file is used.
  const late = make('X = build\nall:\n\t$(X)\nX = vercel --prod\n');
  assert.ok(shows(late));
  // A target named by a variable.
  assert.ok(shows(make('T = deploy\nall: deploy\n$(T):\n\tvercel --prod\n')));
  assert.ok(shows(make('T = de ploy\nall: de\n$(T):\n\tvercel --prod\n')), 'two words, two targets');
  // An unresolvable target name might be any target.
  assert.equal(make('all: deploy\n$(UNKNOWN):\n\tvercel --prod\n').dynamic, true);
  // The command line wins over the file, unless `override`.
  assert.ok(shows(make('S = build\nall: $(S)\ndeploy:\n\tvercel --prod\n', ['all'], { overrides: { S: 'deploy' } })));
  assert.equal(make('S = deploy\nall: $(S)\nbuild:\n\techo\ndeploy:\n\tvercel --prod\n', ['all'], { overrides: { S: 'build' } }).commands.some((c) => /vercel/.test(c)), false);
  assert.ok(shows(make('override S = deploy\nall: $(S)\ndeploy:\n\tvercel --prod\n', ['all'], { overrides: { S: 'build' } })));
  // := with a reference that is unknown stays unresolved.
  assert.equal(make('B := $(UNKNOWN)\nall: $(B)\n').dynamic, true);
});

test('N4: ?= and += need the environment: unknown unless env is given; env and the file are combined as make does', () => {
  const text = (op) => `STAGE ${op} dev\nall:\n\twrangler deploy --env $(STAGE)\n`;
  assert.equal(make(text('?=')).dynamic, true, '?= with the environment unknown');
  assert.equal(make(text('+=')).dynamic, true, '+= with the environment unknown');
  assert.deepEqual(make(text('?='), ['all'], { env: {} }).commands, ['wrangler deploy --env dev']);
  assert.deepEqual(make(text('?='), ['all'], { env: { STAGE: 'production' } }).commands, ['wrangler deploy --env production']);
  assert.deepEqual(make(text('+='), ['all'], { env: { STAGE: 'production' } }).commands, ['wrangler deploy --env production dev']);
  // A plain = assignment beats the environment.
  assert.deepEqual(make(text('='), ['all'], { env: { STAGE: 'production' } }).commands, ['wrangler deploy --env dev']);
  // ?= after a file assignment keeps it; the env is not consulted.
  assert.deepEqual(make('STAGE = a\nSTAGE ?= b\nall:\n\techo $(STAGE)\n').commands, ['echo a']);
  // Variables the file does not assign come from env when it is given, else unknown.
  assert.equal(make('all:\n\techo $(WHO)\n').dynamic, true);
  assert.deepEqual(make('all:\n\techo $(WHO)\n', ['all'], { env: { WHO: 'me' } }).commands, ['echo me']);
  // make -e / MAKEFLAGS in the environment changes precedence and files: dynamic.
  for (const name of ['MAKEFLAGS', 'GNUMAKEFLAGS', 'MAKEFILES', 'MFLAGS']) assert.equal(make('all:\n\techo\n', ['all'], { env: { [name]: 'e' } }).dynamic, true, name);
});

test('N4: functions, substitution references, automatic variables and unbalanced references are unknown, not empty', () => {
  const cases = [
    'all: $(shell echo deploy)\ndeploy:\n\tvercel --prod\n',
    'all: $(wildcard *.mk)\n',
    'X = deploy\nall: $(X:%=%)\n',
    'all: $(subst a,deploy,a)\ndeploy:\n\tvercel --prod\n',
    'all: ${shell echo deploy}\n',
    'all:\n\t$(shell echo vercel --prod)\n',
    'X = deploy\nall:\n\t$(shell echo $(X))\n',
    'all:\n\t$(call f,deploy)\n',
    'all: $@\n',
    'all: $(\n',
    'all: $\n',
    'all: *.o\n',
    'all: [ab]\n',
    'obj: a.o b.o: %.o: %.c\n',
    'all: foo.o\n%.o: %.c\n\tcc $<\n',
    'all: $(eval deploy:\n)\n',
  ];
  for (const text of cases) {
    const r = make(text);
    assert.ok(r.status !== 'ok' || r.dynamic || shows(r), `definite answer for ${JSON.stringify(text)}: ${JSON.stringify(r)}`);
  }
  // Builtin and environment names are not guessed.
  assert.equal(make('all:\n\t$(CC) deploy\n').dynamic, true);
  assert.equal(make('all:\n\t$(CURDIR)/x\n').dynamic, true);
  // $$ is a literal $ for the shell; automatic variables stay in the recipe text.
  assert.deepEqual(make('all:\n\techo $$HOME $@\n').commands, ['echo $HOME $@']);
});

test('N4: a function with effects in a read-time context runs whether or not the target is wanted', () => {
  for (const text of [
    'X := $(shell vercel --prod)\nall:\n\techo hi\n',
    'X ::= $(shell vercel --prod)\nall:\n\techo hi\n',
    'X = $(shell vercel --prod)\nY := $(X)\nall:\n\techo hi\n',
    'other: $(shell vercel --prod)\nall:\n\techo hi\n',
    '$(shell vercel --prod): x\nall:\n\techo hi\n',
    'X := a\nX += $(shell vercel --prod)\nall:\n\techo hi\n',
    'X := a\nX := $(X) $(shell vercel --prod)\nall:\n\techo hi\n',
    'all:\n\techo hi\n$(eval deploy:)\n',
    'X := $(file >x,y)\nall:\n\techo hi\n',
    'X := $(call f,a)\nall:\n\techo hi\n',
    'X := $(subst a,b,$(shell vercel --prod))\nall:\n\techo hi\n',
  ]) assert.equal(make(text).dynamic, true, text);
  // Deferred (=) and pure forms are not executed when the file is read.
  assert.equal(make('X = $(shell vercel --prod)\nall:\n\techo hi\n').dynamic, false);
  assert.equal(make('OBJS := $(patsubst %.c,%.o,$(SRCS))\nall:\n\techo hi\n').dynamic, false);
  assert.equal(make('X = $(shell echo a)\nall:\n\techo $(X)\n').dynamic, true, 'used: executed at expansion');
});

test('N4: target-specific variables, special targets and variables that change the shell are dynamic', () => {
  const cases = [
    'STAGE = dev\nall: STAGE = production\nall:\n\twrangler deploy --env $(STAGE)\n',
    'all: override STAGE += production\n',
    'all: export X = 1\n',
    '.DEFAULT:\n\tvercel --prod\nall:\n\techo\n',
    '.SUFFIXES: .x .y\n.x.y:\n\tvercel --prod\nall: foo.y\n',
    '.SECONDEXPANSION:\nall: $$(X)\n',
    '.ONESHELL:\nall:\n\techo\n',
    '.DEFAULT_GOAL := deploy\nall:\n\techo\ndeploy:\n\tvercel --prod\n',
    '.RECIPEPREFIX = >\nall:\n>vercel --prod\n',
    'SHELL = ./evil.sh\nall:\n\techo hi\n',
    'SHELL := python3\nall:\n\techo hi\n',
    'MAKE = ./evil\nall:\n\t$(MAKE) x\n',
    'MAKEFLAGS += -e\nall:\n\techo\n',
    'VPATH = /tmp/evil\nall: x\n',
    'X != echo deploy\nall: $(X)\n',
    'define STEPS\ndeploy\nendef\nall: $(STEPS)\n',
    'ifeq ($(A),1)\nall: deploy\nendif\n',
    'include more.mk\nall:\n\techo\n',
    'load ./evil.so\nall:\n\techo\n',
    'undefine STEPS\nall: $(STEPS)\n',
    'all: build \\# deploy\n',
  ];
  for (const text of cases) {
    const r = make(text);
    assert.ok(r.status !== 'ok' || r.dynamic || shows(r), `definite answer for ${JSON.stringify(text)}: ${JSON.stringify(r)}`);
  }
  // A plain system shell is understood; it is not friction.
  assert.equal(make('SHELL := /bin/bash\nall:\n\techo hi\n').dynamic, false);
  assert.equal(make('SHELL = /usr/bin/zsh\n.PHONY: all\nall:\n\techo hi\n').dynamic, false);
});

test('N4: a tab-led line outside a rule is ordinary makefile syntax (GNU make), not a dropped recipe', () => {
  assert.ok(shows(make('X = build\n\tX += deploy\nall: $(X)\ndeploy:\n\tvercel --prod\n')), 'tab-led assignment');
  assert.ok(shows(make('X = a\n\tdeploy:\n\t\tvercel --prod\nall: deploy\n')) || make('X = a\n\tdeploy:\n\t\tvercel --prod\nall: deploy\n').dynamic, 'tab-led rule');
  // A tab-led line after a rule is still its recipe.
  assert.deepEqual(make('all:\n\techo a\n\n# c\n\techo b\n').commands, ['echo a', 'echo b']);
});

test('N4: $(MAKE) <targets> is followed in the same file; other forms are dynamic', () => {
  const base = 'deploy:\n\tvercel --prod\nbuild:\n\techo b\n';
  assert.ok(shows(make(`all:\n\t$(MAKE) deploy\n${base}`)));
  assert.ok(shows(make(`all:\n\t@$(MAKE) --no-print-directory -s build deploy\n${base}`)));
  assert.ok(shows(make(`all:\n\t+${'$'}{MAKE} deploy\n${base}`)));
  assert.ok(shows(make(`all: ; $(MAKE) deploy\n${base}`)));
  assert.ok(shows(make(`all:\n\t$(MAKE) step\nstep:\n\t$(MAKE) deploy\n${base}`)), 'two levels');
  // The same through a variable, and a literal `make` at the start of a recipe.
  assert.ok(shows(make(`RUN = $(MAKE) deploy\nall:\n\t$(RUN)\n${base}`)));
  assert.ok(shows(make(`all:\n\tmake deploy\n${base}`)));
  assert.equal(make(`all:\n\tgmake deploy\n${base}`).dynamic, true);
  // The command text itself is still reported, so a caller that recurses sees it.
  assert.ok(make(`all:\n\t$(MAKE) deploy\n${base}`).commands.includes('make deploy'));
  for (const recipe of ['$(MAKE) -C sub deploy', '$(MAKE) -f other.mk deploy', '$(MAKE) STAGE=production deploy', 'cd sub && $(MAKE) deploy', '$(MAKE) deploy | tee log', '$(MAKE) $(TARGET)', '$(MAKE) -e deploy', '$(MAKE) --eval=x deploy']) {
    const r = make(`all:\n\t${recipe}\n${base}`);
    assert.equal(r.dynamic, true, recipe);
  }
  // Unbounded recursion stops at the depth limit.
  const loop = make('all:\n\t$(MAKE) all\n');
  assert.equal(loop.status, 'ok');
  // Depth: four nested sub-makes are over the limit.
  const deep = make('a:\n\t$(MAKE) b\nb:\n\t$(MAKE) c\nc:\n\t$(MAKE) d\nd:\n\t$(MAKE) e\ne:\n\tvercel --prod\n', ['a']);
  assert.ok(shows(deep) || deep.dynamic);
});

test('N4: $(MAKE) with -f is not followed into the same file (a sub-make reads the default makefile)', () => {
  const fs = createFakeFs().file('/m/ops.mk', 'all:\n\t$(MAKE) deploy\ndeploy:\n\techo staging\n').file('/m/Makefile', 'deploy:\n\tvercel --prod\n');
  const r = S.resolveMakeTargets(fs, '/m', ['all'], { makefile: 'ops.mk' });
  assert.equal(r.dynamic, true);
  assert.ok(r.commands.includes('make deploy'), 'the sub-make line is reported for the caller to resolve in the default file');
});

test('N4: variable names that are Object.prototype keys are plain unknown names', () => {
  for (const name of ['constructor', '__proto__', 'toString', 'hasOwnProperty']) {
    const r = make(`all:\n\techo $(${name})\n`);
    assert.equal(r.dynamic, true, name);
    const assigned = make(`${name} = deploy\nall: $(${name})\ndeploy:\n\tvercel --prod\n`);
    assert.ok(shows(assigned), `${name} assigned`);
  }
});

test('N4: an expansion bomb is charged to the budget, including := (immediate) values', () => {
  let text = 'V0 := xxxxxxxxxxxxxxxx\n';
  for (let i = 1; i < 40; i += 1) text += `V${i} := $(V${i - 1}) $(V${i - 1}) $(V${i - 1}) $(V${i - 1})\n`;
  const started = Date.now();
  const r = make(`${text}all:\n\techo $(V39)\n`);
  assert.ok(Date.now() - started < 1500);
  assert.equal(r.status, 'unknown');
  const lazy = make(`${text.replace(/ := /g, ' = ')}all:\n\techo $(V39)\n`);
  assert.ok(lazy.status === 'unknown' || lazy.dynamic);
});

// ------------------------------------------------------------- shebang (N5)

function shebang(line, body = 'echo body\n') {
  return S.readScriptFile(createFakeFs().file('/s/x.sh', `${line}\n${body}`), '/s/x.sh');
}

test('N5: only a system shell with plain flags is a shell; commands in the shebang are named, the rest is unknown', () => {
  const shell = [
    '#!/bin/sh', '#!/bin/bash', '#! /bin/bash -e', '#!/usr/bin/env bash', '#!/usr/bin/env -S bash -e', '#!/usr/bin/env -S bash -eu', '#!/usr/bin/env -S bash -euo pipefail',
    '#!/usr/bin/env -Sbash -e', '#!/usr/bin/env -iS bash', '#!/usr/bin/env -S -i bash -e', '#!/usr/bin/env -u X -S bash', '#!/usr/bin/env -u X bash', '#!/usr/bin/env -i bash',
    '#!/usr/bin/env --split-string=bash -e', '#!/usr/bin/env -S "bash" -e', "#!/usr/bin/env -S 'bash' -x", '#!/bin/bash -o pipefail', '#!/usr/local/bin/zsh -f',
  ];
  for (const line of shell) assert.equal(shebang(line).interpreter, 'shell', line);
  assert.equal(S.readScriptFile(createFakeFs().file('/s/x.sh', 'echo no shebang\n'), '/s/x.sh').interpreter, 'shell');
  // Another interpreter that is understood: raw text is scanned by the caller.
  for (const line of ['#!/usr/bin/env python3', '#!/usr/bin/env -S python3 -u', '#!/usr/bin/node', '#!/usr/bin/perl -w', '#!/usr/bin/env -S node --require ./x.js']) {
    const r = shebang(line);
    assert.equal(r.interpreter, 'other', line);
    assert.equal(r.shebangCommand, undefined, line);
  }
});

test('N5: a command string in the shebang is reported (the body is only $0): interpreter other, shebangCommand set', () => {
  const cases = {
    '#!/usr/bin/env -S bash -c "echo PAYLOAD"': 'echo PAYLOAD',
    "#!/usr/bin/env -S bash -c 'echo PAYLOAD'": 'echo PAYLOAD',
    '#!/usr/bin/env -S sh -ec "echo PAYLOAD"': 'echo PAYLOAD',
    '#!/usr/bin/env -S bash -xc "echo PAYLOAD"': 'echo PAYLOAD',
    '#!/usr/bin/env -S bash -e -c "echo PAYLOAD"': 'echo PAYLOAD',
    '#!/usr/bin/env -S -i bash -c "echo PAYLOAD" arg0': 'echo PAYLOAD',
    '#!/usr/bin/env -S bash -o pipefail -c "echo PAYLOAD"': 'echo PAYLOAD',
    '#!/usr/bin/env bash -c payload': 'payload',
    '#!/bin/bash -c payload': 'payload',
    '#!/usr/bin/env -S bash -c "vercel --prod"': 'vercel --prod',
  };
  for (const [line, command] of Object.entries(cases)) {
    const r = shebang(line);
    assert.equal(r.status, 'ok', line);
    assert.equal(r.interpreter, 'other', line);
    assert.equal(r.shebangCommand, command, line);
  }
});

test('N5: environment assignments, env options, relative or planted interpreters and unparsed forms are unknown', () => {
  const unknown = [
    '#!/usr/bin/env -S BASH_ENV=./evil.sh bash', '#!/usr/bin/env -S ENV=./evil.sh sh', '#!/usr/bin/env BASH_ENV=./evil.sh bash', '#!/usr/bin/env -i PATH=/bin bash', '#!/usr/bin/env -S SHELLOPTS=xtrace PS4=x bash',
    '#!/usr/bin/env -S -i FOO=1 bash', '#!/usr/bin/env -S FOO=1 python3',
    '#!/usr/bin/env -C /tmp bash', '#!/usr/bin/env --chdir=/tmp bash', '#!/usr/bin/env --argv0=x bash', '#!/usr/bin/env -a x bash', '#!/usr/bin/env -P /x bash', '#!/usr/bin/env --block-signal bash',
    '#!/usr/bin/env -S bash -i', '#!/usr/bin/env -S bash -l', '#!/usr/bin/env -S bash --login', '#!/usr/bin/env -S bash --rcfile /x', '#!/usr/bin/env -S bash --init-file=x', '#!/usr/bin/env -S bash -s',
    '#!/usr/bin/env -S bash ./other.sh', '#!/bin/bash other.sh', '#!/bin/bash -O extglob',
    '#!/usr/bin/env -S $SHELL -e', '#!/usr/bin/env -S "${SHELL}" -e', '#!/usr/bin/env -S bash \\c -c x', '#!/usr/bin/env -S bash -c "unclosed', '#!/usr/bin/env -S bash \\q',
    '#!/usr/bin/env -S env BASH_ENV=./evil.sh bash', '#!/usr/bin/env -S env -i FOO=1 sh',
    '#!./bash', '#!bash', '#!/usr/bin/env ./bash', '#!/usr/bin/env ../bin/sh', '#!/usr/bin/env -S ./bash -e', '#!/home/u/proj/bin/bash', '#!/tmp/evil/env bash', '#!/usr/bin/env -S /home/u/proj/bin/sh -e',
    '#!', '#!/usr/bin/env', '#!/usr/bin/env -S', '#!/usr/bin/env -u', '#!/usr/bin/env -S "" ', '#!/usr/bin/env --unset',
  ];
  for (const line of unknown) assert.deepEqual(shebang(line), { status: 'unknown', reason: 'shebang' }, line);
});

test('N5: the shebang must be the first line; later `#!` lines do not change the answer, a CRLF line is never a shell (F1)', () => {
  assert.equal(shebang('# comment', '#!/usr/bin/env -S bash -c "x"\n').interpreter, 'shell');
  // Round 4 (audit F1): the kernel ends the line at \n only and \r stays in it, so a CRLF line is never a definite shell.
  assert.equal(S.readScriptFile(createFakeFs().file('/s/x.sh', '#!/usr/bin/env bash\r\necho\r\n'), '/s/x.sh').interpreter, 'other');
  assert.equal(S.readScriptFile(createFakeFs().file('/s/x.sh', '#!/usr/bin/env -S bash -c "x"\r\n'), '/s/x.sh').interpreter, 'other');
});
