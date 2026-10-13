// Regression tests from Barvis's FINAL delta audit of ecd0d1a6 (seatbelt U3/U4 round 3), copied from its evidence/final.test.cjs.
// Changes: AUDIT_DIST points at this repo's dist; the tmp prefix; and the informational "MAKE contract" row now asserts L4
// (env omitted is dynamic) instead of recording the definite answer. F1, F2, F3 and L4 rows are the ones that failed at ecd0d1a6.
'use strict';
// Barvis FINAL delta audit (ecd0d1a6): class variants for N1-N5 and the $(MAKE) decision. No secrets; payloads are harmless `echo`.
const assert = require('node:assert/strict');
const test = require('node:test');
const fsn = require('node:fs');
const { join } = require('node:path');
const { execFileSync, spawnSync } = require('node:child_process');
const D = require('node:path').join(__dirname, '..', 'dist');
const { nodeSeatbeltFs } = require(`${D}/seatbelt-fs.js`);
const G = require(`${D}/seatbelt-git.js`);
const P = require(`${D}/seatbelt-path.js`);
const S = require(`${D}/seatbelt-scripts.js`);

const ROOT = fsn.realpathSync(fsn.mkdtempSync('/tmp/barvis-final-r4-'));
let n = 0;
const fresh = () => { const d = join(ROOT, `d${n++}`); fsn.mkdirSync(d, { mode: 0o700 }); return d; };
const nfs = nodeSeatbeltFs();
const gitEnv = (home) => ({ PATH: process.env.PATH, HOME: home, XDG_CONFIG_HOME: join(home, '.config'), GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' });
const show = (exps) => exps.map((e) => e.kind === 'git' ? `git ${e.invocation.subcommand} ${e.invocation.args.join(' ')}` : `${e.kind}:${e.reason || e.command || ''}`);
// A definite "only `git status`" answer is the loose one; anything else (a push candidate or unknown) is fail-closed.
const onlyStatus = (exps) => exps.length > 0 && exps.every((e) => e.kind === 'git' && e.invocation.subcommand === 'status');
const mk = (text) => { const d = fresh(); fsn.writeFileSync(join(d, 'Makefile'), text); return d; };
const brief = (r) => r.status === 'ok' ? { dynamic: r.dynamic, commands: r.commands } : r;
// Loose = definite ok whose commands do not show the risky thing.
const makeLoose = (r, risky) => r.status === 'ok' && !r.dynamic && !r.commands.some((c) => risky.test(c));

// ---------------------------------------------------------------- N1 / N2 (git)
const repoWithStatusAlias = () => {
  const home = fresh(); const r = fresh(); const env = gitEnv(home);
  execFileSync('git', ['init', '-q', '-b', 'feat', r], { env });
  execFileSync('git', ['-C', r, 'config', 'alias.k', 'status'], { env });
  const cfg = (e = {}) => G.loadGitConfig(nfs, { home, dirs: G.discoverGitDirs(nfs, r, e), env: e, systemFiles: [] });
  return { home, r, env, cfg };
};
const oracle = (cwd, env, args) => { const o = spawnSync('git', [...args, 'config', '--get', 'alias.k'], { cwd, env }); return o.stdout.toString().trim(); };

test('N2v --config-env include.path=VAR, GIT_CONFIG_PARAMETERS (new + old quoting), nested and relative includes, includeIf, ~/ and Include.Path spellings', () => {
  const { home, r, env, cfg } = repoWithStatusAlias();
  const incDir = fresh();
  const inc = join(incDir, 'inc.cfg'); fsn.writeFileSync(inc, '[alias]\n\tk = push -f origin main\n');
  const outer = join(incDir, 'outer.cfg'); fsn.writeFileSync(outer, '[include]\n\tpath = inc.cfg\n'); // nested, relative to outer
  const deep = join(incDir, 'deep.cfg'); fsn.writeFileSync(deep, '[include]\n\tpath = outer.cfg\n');
  fsn.writeFileSync(join(home, 'inc.cfg'), '[alias]\n\tk = push -f origin main\n');
  const rows = [
    { name: 'config-env', args: ['--config-env', 'include.path=INC_P'], e: { INC_P: inc } },
    { name: 'config-env=', args: ['--config-env=include.path=INC_P'], e: { INC_P: inc } },
    { name: 'GCP new', args: [], e: { GIT_CONFIG_PARAMETERS: `'include.path'='${inc}'` } },
    { name: 'GCP old', args: [], e: { GIT_CONFIG_PARAMETERS: `'include.path=${inc}'` } },
    { name: 'GCP nested deep', args: [], e: { GIT_CONFIG_PARAMETERS: `'include.path'='${deep}'` } },
    { name: '-c nested', args: ['-c', `include.path=${outer}`], e: {} },
    { name: '-c nested deep', args: ['-c', `include.path=${deep}`], e: {} },
    { name: '-c includeIf.onbranch', args: ['-c', `includeIf.onbranch:feat.path=${inc}`], e: {} },
    { name: '-c includeIf.gitdir/i', args: ['-c', `includeIf.gitdir/i:${r}/.path=${inc}`], e: {} },
    { name: '-c Include.Path', args: ['-c', `Include.Path=${inc}`], e: {} },
    { name: '-c ~/inc', args: ['-c', 'include.path=~/inc.cfg'], e: {} },
    { name: 'COUNT nested', args: [], e: { GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'include.path', GIT_CONFIG_VALUE_0: outer } },
  ];
  const lines = [];
  for (const row of rows) {
    const o = oracle(r, { ...env, ...row.e }, row.args);
    const x = G.expandGitAliases([...row.args, 'k'], { config: cfg(row.e), env: row.e, fs: nfs, home });
    lines.push(`${row.name}: oracle="${o}" resolver=${JSON.stringify(show(x))}`);
    assert.ok(!onlyStatus(x), `${row.name}: definite git status (oracle: ${o})`);
  }
  // Without fs the same include must not be definite either.
  const nofs = G.expandGitAliases(['-c', `include.path=${inc}`, 'k'], { config: cfg({}), env: {} });
  lines.push(`no-fs: ${JSON.stringify(show(nofs))}`);
  assert.ok(!onlyStatus(nofs));
  console.log(lines.map((l) => `# ${l}`).join('\n'));
});

test('N2v alias that carries its own -c include.path, and an include that redefines another alias in the chain', () => {
  const { home, r, env, cfg } = repoWithStatusAlias();
  const inc = join(fresh(), 'inc.cfg'); fsn.writeFileSync(inc, '[alias]\n\tk2 = push -f origin main\n');
  execFileSync('git', ['-C', r, 'config', 'alias.w', `-c include.path=${inc} k2`], { env });
  execFileSync('git', ['-C', r, 'config', 'alias.k2', 'status'], { env });
  const o = spawnSync('git', ['-c', `include.path=${inc}`, 'config', '--get', 'alias.k2'], { cwd: r, env }).stdout.toString().trim();
  const x = G.expandGitAliases(['w'], { config: cfg(), env: {}, fs: nfs, home });
  console.log(`# alias-own-include oracle(k2 with include)="${o}" resolver=${JSON.stringify(show(x))}`);
  assert.ok(!onlyStatus(x));
});

test('N2v consumers: included remote.origin.push force reaches implicitPushTargets via withInvocationConfig', () => {
  const { home, r, cfg } = repoWithStatusAlias();
  const inc = join(fresh(), 'push.cfg'); fsn.writeFileSync(inc, '[remote "origin"]\n\tpush = +refs/heads/*:refs/heads/main\n');
  for (const args of [['-c', `include.path=${inc}`], ['--config-env', 'include.path=P_INC']]) {
    const e = { P_INC: inc };
    const x = G.expandGitAliases([...args, 'push', 'origin'], { config: cfg(), env: e, fs: nfs, home });
    const inv = x.find((y) => y.kind === 'git').invocation;
    const t = G.implicitPushTargets(G.withInvocationConfig(cfg(), inv), { kind: 'branch', branch: 'feat' }, 'origin');
    console.log(`# consumer ${args[0]} forceFromConfig=${t.forceFromConfig}`);
    assert.equal(t.forceFromConfig, true);
  }
});

test('N1v --bare / --git-dir=. inside an alias, -C . --bare, GIT_DIR=. env, --namespace=: all relocated', () => {
  const { home, r, env, cfg } = repoWithStatusAlias();
  execFileSync('git', ['-C', r, 'config', 'alias.b', '--bare k']);
  execFileSync('git', ['-C', r, 'config', 'alias.g', '--git-dir=. k']);
  const rows = [
    { args: ['b'], e: {} }, { args: ['g'], e: {} }, { args: ['-C', '.', '--bare', 'k'], e: {} },
    { args: ['k'], e: { GIT_DIR: '.' } }, { args: ['--namespace=x', 'push', 'origin'], e: {} },
    { args: ['-c', 'x.y=1', '--bare', 'push', '-f', 'origin', 'main'], e: {} },
  ];
  for (const row of rows) {
    const x = G.expandGitAliases(row.args, { config: cfg(row.e), env: row.e, fs: nfs, home });
    console.log(`# N1v ${row.args.join(' ')} ${JSON.stringify(row.e)} -> ${JSON.stringify(show(x))}`);
    assert.ok(x.some((y) => y.kind === 'unknown' && y.reason === 'relocated'), row.args.join(' '));
  }
  void env;
});

// ---------------------------------------------------------------- N3 (paths), bash oracle
test('N3v ~- after OLDPWD=, ${PWD}, X=~+ then $X, PWD=/ then ~+, PWD unchanged control', () => {
  const home = fresh(); const r = join(home, 'proj'); fsn.mkdirSync(join(r, '.git'), { recursive: true });
  const ws = P.resolveWorkspace(nfs, { eventCwd: r, home });
  const cls = (vars, op) => P.classifyDeleteTarget(nfs, ws, P.resolveOperand(nfs, { home, cwd: r, variables: vars }, op, 'delete'));
  const bash = (script) => execFileSync('bash', ['-c', `cd "$1"; ${script}`, '_', r, home]).toString();
  const rows = [
    { name: 'OLDPWD=$HOME; ~-/.ssh', vars: { OLDPWD: home }, op: '~-/.ssh', oracle: bash('OLDPWD="$2"; printf %s ~-/.ssh') },
    { name: 'PWD=$HOME; ${PWD}/.ssh', vars: { PWD: home }, op: '${PWD}/.ssh', oracle: bash('PWD="$2"; printf %s "${PWD}/.ssh"') },
    { name: 'PWD=/; ~+', vars: { PWD: '/' }, op: '~+', oracle: bash('PWD=/; printf %s ~+') },
    { name: 'X=~ (unexpanded by caller); $X/.ssh', vars: { X: '~' }, op: '$X/.ssh', oracle: bash('X=~; printf %s "$X/.ssh"') },
    { name: 'PWD=$HOME/; ~+/.ssh (trailing slash)', vars: { PWD: `${home}/` }, op: '~+/.ssh', oracle: bash('PWD="$2/"; printf %s ~+/.ssh') },
  ];
  for (const row of rows) {
    const c = cls(row.vars, row.op);
    const o = row.oracle.replace(home, '$HOME');
    console.log(`# N3v ${row.name}: bash=${o} resolver=${c}`);
    assert.notEqual(c, 'in_workspace', row.name);
  }
  const control = cls({ PWD: r }, '~+/build');
  console.log(`# N3v control PWD=cwd ~+/build -> ${control}`);
  assert.equal(control, 'in_workspace');
});

// ---------------------------------------------------------------- N4 (Makefile); no GNU make on this host
test('N4v $(eval), define/endef, pattern rule, .SECONDEXPANSION, .DEFAULT_GOAL, .SHELLFLAGS, private: never definite-safe', () => {
  const rows = {
    eval_line: '$(eval deploy: ; vercel --prod)\nall: deploy\n',
    eval_var: 'R = deploy: ; vercel --prod\n$(eval $(R))\nall: deploy\n',
    eval_in_prereq: 'all: $(eval X=1) build\nbuild:\n\techo b\n',
    define: 'define R\ndeploy:\n\tvercel --prod\nendef\nall: deploy\n',
    pattern: '%:\n\tvercel --prod\nall: deploy\n',
    pattern_dep: 'all: deploy\n%oy:\n\tvercel --prod\n',
    secondexp: '.SECONDEXPANSION:\nSTEPS = build\nall: $$(STEPS)\nSTEPS = build deploy\nbuild:\n\techo b\ndeploy:\n\tvercel --prod\n',
    default_goal: '.DEFAULT_GOAL := deploy\nall:\n\techo all\ndeploy:\n\tvercel --prod\n',
    shellflags: '.SHELLFLAGS := -c "vercel --prod; :"\nall:\n\techo all\n',
    private_assign: 'private STEPS = build deploy\nall:\n\techo all\n',
    dollar_dollar_prereq: 'all: $$(shell vercel --prod)\n',
  };
  for (const [name, text] of Object.entries(rows)) {
    const res = S.resolveMakeTargets(nfs, mk(text), ['all']);
    console.log(`# N4v ${name}: ${JSON.stringify(brief(res))}`);
    assert.ok(!makeLoose(res, /vercel/), name);
  }
});

test('N4v command-line overrides of execution variables (make SHELL=./evil.sh / MAKEFLAGS= / .SHELLFLAGS=)', () => {
  const dir = mk('all:\n\techo hello\n');
  fsn.writeFileSync(join(dir, 'evil.sh'), '#!/bin/sh\necho PAYLOAD_RAN\n', { mode: 0o755 });
  const rows = { SHELL: './evil.sh', MAKEFLAGS: '-f evil.mk', MAKEFILES: 'evil.mk', '.SHELLFLAGS': '-c "echo PAYLOAD_RAN; :"', VPATH: '/tmp' };
  const fails = [];
  for (const [k, v] of Object.entries(rows)) {
    const res = S.resolveMakeTargets(nfs, dir, ['all'], { overrides: { [k]: v } });
    console.log(`# N4v override ${k}=...: ${JSON.stringify(brief(res))}`);
    if (makeLoose(res, /PAYLOAD|evil/)) fails.push(k);
  }
  assert.deepEqual(fails, [], `definite answers while the override changes what runs: ${fails.join(', ')}`);
});

test('N4v recipe environment: PATH / BASH_ENV changed in the Makefile reach every recipe (exported env names, .EXPORT_ALL_VARIABLES)', () => {
  const rows = {
    path_prepend_env_known: { text: 'PATH := ./tools:$(PATH)\nall:\n\tgit status\n', opts: { env: { PATH: '/usr/bin:/bin' } } },
    path_plain_env_unknown: { text: 'PATH = ./tools\nall:\n\tgit status\n', opts: {} },
    export_all_bash_env: { text: 'SHELL := /bin/bash\n.EXPORT_ALL_VARIABLES:\nBASH_ENV = ./evil.sh\nall:\n\techo hi\n', opts: {} },
    export_all_git_dir: { text: '.EXPORT_ALL_VARIABLES:\nGIT_DIR = ./evil.git\nall:\n\tgit status\n', opts: {} },
  };
  const fails = [];
  for (const [name, row] of Object.entries(rows)) {
    const res = S.resolveMakeTargets(nfs, mk(row.text), ['all'], row.opts);
    console.log(`# N4v env ${name}: ${JSON.stringify(brief(res))}`);
    if (res.status === 'ok' && !res.dynamic) fails.push(name);
  }
  assert.deepEqual(fails, [], `definite recipe list while the recipe environment is changed: ${fails.join(', ')}`);
});

// ---------------------------------------------------------------- $(MAKE) decision
test('MAKE decision: every recursive form that changes file, dir or variables is dynamic; plain form is followed', () => {
  const tail = '\ndeploy:\n\tvercel --prod\nsafe:\n\techo safe\n';
  const forms = [
    '$(MAKE) -C sub safe', '$(MAKE) -Csub safe', '$(MAKE) --directory=sub safe', '$(MAKE) --directory sub safe',
    '$(MAKE) -f other.mk safe', '$(MAKE) -fother.mk safe', '$(MAKE) --file=other.mk safe', '$(MAKE) --makefile=other.mk safe',
    '$(MAKE) STAGE=production safe', '$(MAKE) safe STAGE=production', '$(MAKE) -e safe', '$(MAKE) --environment-overrides safe',
    'MAKEFLAGS=-fother.mk $(MAKE) safe', 'MAKEFILES=other.mk $(MAKE) safe', 'env MAKEFILES=other.mk $(MAKE) safe',
    '$(MAKE) -I inc safe', '$(MAKE) --include-dir=inc safe', '$(MAKE) --eval=x safe', '$(MAKE) -E x safe',
    '$(MAKE) -o x safe', '$(MAKE) -W x safe', '$(MAKE) -n safe', '$(MAKE) -t safe', '$(MAKE) -j 4 safe', '$(MAKE) --jobs=4 safe',
    '$(MAKE) $(MFLAGS) safe', '$(MAKE) -$(MAKEFLAGS) safe', '${MAKE} -C sub safe', 'make -C sub safe', 'gmake safe',
    '$(MAKE) -- STAGE=production safe', '$(MAKE) -s -C sub safe',
  ];
  const fails = [];
  for (const f of forms) {
    const res = S.resolveMakeTargets(nfs, mk(`all:\n\t${f}${tail}`), ['all']);
    if (res.status === 'ok' && !res.dynamic) fails.push(`${f} -> ${JSON.stringify(res.commands)}`);
  }
  console.log(`# MAKE forms tested=${forms.length} definite=${fails.length}`);
  assert.deepEqual(fails, []);
  // env-supplied MAKEFLAGS / MAKEFILES with env given
  for (const k of ['MAKEFLAGS', 'MAKEFILES', 'GNUMAKEFLAGS', 'MAKEOVERRIDES']) {
    const res = S.resolveMakeTargets(nfs, mk(`all:\n\t$(MAKE) safe${tail}`), ['all'], { env: { [k]: 'x' } });
    assert.ok(res.status !== 'ok' || res.dynamic, `env ${k}`);
  }
  // MAKE itself replaced (override / env / file)
  for (const opts of [{ overrides: { MAKE: './evil' } }, { env: { MAKE: './evil' } }]) {
    const res = S.resolveMakeTargets(nfs, mk(`all:\n\t$(MAKE) safe${tail}`), ['all'], opts);
    assert.ok(res.status !== 'ok' || res.dynamic, JSON.stringify(opts));
  }
  const fileMake = S.resolveMakeTargets(nfs, mk(`MAKE = ./evil\nall:\n\t$(MAKE) safe${tail}`), ['all']);
  assert.ok(fileMake.status !== 'ok' || fileMake.dynamic);
  // plain form followed: risky recipe visible
  const plain = S.resolveMakeTargets(nfs, mk(`all:\n\t+@$(MAKE) --no-print-directory deploy${tail}`), ['all']);
  console.log(`# MAKE plain: ${JSON.stringify(brief(plain))}`);
  assert.ok(plain.status === 'ok' && plain.commands.some((c) => /vercel/.test(c)));
  // overrides on the parent reach the followed sub-make (same variables): deploy recipe uses STAGE
  const ov = S.resolveMakeTargets(nfs, mk('STAGE = dev\nall:\n\t$(MAKE) deploy\ndeploy:\n\tvercel --env $(STAGE)\n'), ['all'], { overrides: { STAGE: 'production' } });
  console.log(`# MAKE override passthrough: ${JSON.stringify(brief(ov))}`);
  assert.ok(ov.status === 'ok' && ov.commands.some((c) => /production/.test(c)));
});

test('MAKE contract (L4): env omitted means MAKEFILES/MAKEFLAGS cannot be seen, so the answer is dynamic; U2 must always pass env', () => {
  const res = S.resolveMakeTargets(nfs, mk('all:\n\t$(MAKE) safe\nsafe:\n\techo safe\n'), ['all']);
  console.log(`# MAKE env-omitted: ${JSON.stringify(brief(res))}`);
  assert.equal(res.status, 'ok');
  assert.equal(res.dynamic, true);
});

// ---------------------------------------------------------------- N5 (shebang); oracle = kernel + coreutils env
test('N5v env -vS, -S --, #! /bin/sh -c, CR/\\v/\\f separators: the payload in the shebang line is never classified shell', () => {
  const dir = fresh();
  const cases = {
    vS_bash_c: '#!/usr/bin/env -vS bash -c "echo PAYLOAD_RAN"\necho body\n',
    S_dashdash_bash_c: '#!/usr/bin/env -S -- bash -c "echo PAYLOAD_RAN"\necho body\n',
    space_sh_c: '#! /bin/sh -c\necho body\n',
    S_vt_bash_c: '#!/usr/bin/env -S bash\v-c "echo PAYLOAD_RAN"\necho body\n',
    S_ff_bash_c: '#!/usr/bin/env -S bash\f-c "echo PAYLOAD_RAN"\necho body\n',
    S_tab_bash_c: '#!/usr/bin/env\t-S bash\t-c "echo PAYLOAD_RAN"\necho body\n',
    S_quoted_prog: '#!/usr/bin/env -S \'bash\' -c \'echo PAYLOAD_RAN\'\necho body\n',
    S_CR_bash_c: '#!/usr/bin/env -S bash\r-c "echo PAYLOAD_RAN"\necho body\n',
    S_CR_bash_e_c: '#!/usr/bin/env -S bash -e\r-c "echo PAYLOAD_RAN"\necho body\n',
    S_CR_BASH_ENV: '#!/usr/bin/env -S bash\rBASH_ENV=x\necho body\n',
  };
  const loose = [];
  for (const [name, text] of Object.entries(cases)) {
    const f = join(dir, `${name}.sh`); fsn.writeFileSync(f, text, { mode: 0o755 });
    const run = spawnSync(f, [], { cwd: dir, env: { PATH: '/usr/bin:/bin' }, timeout: 5000 });
    const ran = /PAYLOAD_RAN/.test(run.stdout.toString());
    const res = S.readScriptFile(nfs, f);
    const k = res.status === 'ok' ? res.interpreter + (res.shebangCommand ? '+cmd' : '') : `${res.status}/${res.reason}`;
    console.log(`# N5v ${name}: oracle payload_ran=${ran} resolver=${k}`);
    if (ran && res.status === 'ok' && res.interpreter === 'shell') loose.push(name);
  }
  assert.deepEqual(loose, [], `classified shell while the shebang line ran a payload: ${loose.join(', ')}`);
});

test('N5v CRLF plain shebangs (control): #!/bin/bash\\r does not exec on Linux, so `shell` is not looser', () => {
  const dir = fresh();
  const f = join(dir, 'crlf.sh'); fsn.writeFileSync(f, '#!/bin/bash\r\necho PAYLOAD_RAN\r\n', { mode: 0o755 });
  const run = spawnSync(f, [], { cwd: dir, env: { PATH: '/usr/bin:/bin' }, timeout: 5000 });
  const res = S.readScriptFile(nfs, f);
  console.log(`# N5v crlf plain: exec_error=${run.error ? run.error.code : 'none'} status=${run.status} resolver=${res.status === 'ok' ? res.interpreter : res.reason}`);
  assert.ok(!/PAYLOAD_RAN/.test(run.stdout ? run.stdout.toString() : ''));
});

test.after(() => { fsn.rmSync(ROOT, { recursive: true, force: true }); });
