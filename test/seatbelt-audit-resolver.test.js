// Regression tests from Barvis's exact-SHA audit of 5069b1c6 (seatbelt U3/U4), copied from its evidence/resolver.test.cjs.
// Only change: AUDIT_DIST points at this repo's dist.
'use strict';
// Barvis U3 audit tests (own fixtures). No secrets; dummy values generated at runtime.
const assert = require('node:assert/strict');
const test = require('node:test');
const fsn = require('node:fs');
const { join } = require('node:path');
const { randomBytes } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const D = require('node:path').join(__dirname, '..', 'dist');
const { nodeSeatbeltFs } = require(`${D}/seatbelt-fs.js`);
const G = require(`${D}/seatbelt-git.js`);
const P = require(`${D}/seatbelt-path.js`);
const S = require(`${D}/seatbelt-scripts.js`);
const DEP = require(`${D}/seatbelt-deploy.js`);
const { createFakeFs } = require(`${D}/../test/support/seatbelt-fake-fs.cjs`);

const ROOT = fsn.realpathSync(fsn.mkdtempSync('/tmp/barvis-u3-'));
let n = 0;
const fresh = () => { const d = join(ROOT, `d${n++}`); fsn.mkdirSync(d); return d; };
const nfs = nodeSeatbeltFs();
const HOME = fresh();
const gitEnv = { ...process.env, HOME, XDG_CONFIG_HOME: join(HOME, '.config'), GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' };
const git = (cwd, args, env = {}) => execFileSync('git', args, { cwd, env: { ...gitEnv, ...env }, stdio: ['ignore', 'pipe', 'pipe'] }).toString();
const repo = () => { const r = fresh(); git(r, ['init', '-q', '-b', 'feat']); return r; };
const cfg = (r, env = {}, extra = {}) => G.loadGitConfig(nfs, { home: HOME, dirs: G.discoverGitDirs(nfs, r), env, systemFiles: [], ...extra });
const expand = (argv, config, env) => G.expandGitAliases(argv, { config, env });
const hasForcePush = (exps) => exps.some((e) => e.kind === 'unknown' || e.kind === 'shell' || (e.kind === 'git' && e.invocation.subcommand === 'push' && e.invocation.args.some((a) => /^(-f|--force.*|\+.*)$/.test(a))));

// ---------- git: aliases ----------
test('G1 aliases: !sh, nested, recursive, case-variant name, builtin shadow, include/includeIf(gitdir/onbranch/hasconfig)', () => {
  const r = repo();
  git(r, ['config', 'alias.a', 'b']);
  git(r, ['config', 'alias.b', 'push -f origin main']);
  git(r, ['config', 'alias.sh1', '!git push --force origin main']);
  git(r, ['config', 'alias.l1', 'l2']); git(r, ['config', 'alias.l2', 'l1']);
  git(r, ['config', 'alias.push', 'push --force']);
  for (const [i, cond] of ['include', 'includeIf "gitdir:/nowhere/"', 'includeIf "onbranch:nomatch"', 'includeIf "hasconfig:remote.*.url:https://x/**"'].entries()) {
    const f = join(r, `inc${i}.cfg`); fsn.writeFileSync(f, `[alias]\n\tinc${i} = push -f origin main\n`);
    fsn.appendFileSync(join(r, '.git/config'), `[${cond}]\n\tpath = ${f}\n`);
  }
  const c = cfg(r);
  assert.ok(hasForcePush(expand(['a', 'origin'], c)), 'nested');
  assert.ok(expand(['sh1'], c).some((e) => e.kind === 'shell'), '!sh');
  assert.ok(expand(['l1'], c).some((e) => e.kind === 'unknown'), 'loop');
  assert.ok(hasForcePush(expand(['A'], c)), 'case-variant alias name');
  const builtin = expand(['push', 'origin', 'feat'], c);
  assert.deepEqual(builtin.map((e) => e.kind), ['git'], 'builtin push is never aliased (git semantics)');
  assert.ok(hasForcePush(expand(['PUSH', 'origin', 'main'], c)), 'git PUSH -> alias.push (not a builtin name)');
  for (let i = 0; i < 4; i += 1) assert.ok(hasForcePush(expand([`inc${i}`], c)), `include ${i}`);
});

test('G2 -c / GIT_CONFIG_COUNT / GIT_CONFIG_PARAMETERS / --config-env aliases', () => {
  const r = repo();
  const c = cfg(r, { GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'alias.e1', GIT_CONFIG_VALUE_0: 'push -f origin main', GIT_CONFIG_PARAMETERS: "'alias.e2'='push --mirror'" });
  assert.ok(hasForcePush(expand(['e1'], c)));
  assert.ok(expand(['e2'], c).some((e) => e.kind === 'git' && e.invocation.args.includes('--mirror')));
  assert.ok(hasForcePush(expand(['-c', 'alias.x=push -f origin main', 'x'], cfg(r))));
  assert.ok(expand(['--config-env', 'alias.y=MISSING', 'y'], cfg(r), {}).some((e) => e.kind === 'unknown'));
});

// Same-command env that changes which config git reads. Real git is the oracle (alias runs `!echo`, nothing is pushed).
test('G3 env that relocates config: HOME / XDG_CONFIG_HOME / GIT_DIR must not give a definite benign answer', () => {
  const r = repo();
  git(r, ['config', 'alias.p', 'status']); // benign alias the resolver can see
  const evilHome = fresh();
  fsn.writeFileSync(join(evilHome, '.gitconfig'), '[alias]\n\tq = push -f origin main\n');
  const evilXdg = fresh(); fsn.mkdirSync(join(evilXdg, 'git'));
  fsn.writeFileSync(join(evilXdg, 'git/config'), '[alias]\n\tq = push -f origin main\n');
  const evilGit = fresh(); git(evilGit, ['init', '-q', '--bare']);
  fsn.appendFileSync(join(evilGit, 'config'), '[alias]\n\tp = push -f origin main\n[remote "origin"]\n\turl = /dev/null\n\tpush = +refs/heads/*:refs/heads/*\n');
  // Oracle: real git expands q via HOME / XDG, p via GIT_DIR.
  const probe = (env, name) => { try { return git(r, ['-c', `alias.zz=!echo`, 'config', '--get', `alias.${name}`], env).trim(); } catch { return ''; } };
  assert.equal(probe({ HOME: evilHome }, 'q'), 'push -f origin main');
  assert.equal(probe({ XDG_CONFIG_HOME: evilXdg }, 'q'), 'push -f origin main');
  assert.equal(probe({ GIT_DIR: evilGit }, 'p'), 'push -f origin main');
  const bad = [];
  for (const [label, env, name] of [['HOME', { HOME: evilHome }, 'q'], ['XDG_CONFIG_HOME', { XDG_CONFIG_HOME: evilXdg }, 'q'], ['GIT_DIR', { GIT_DIR: evilGit }, 'p']]) {
    const exps = expand([name, 'origin'], cfg(r, env), env);
    if (!hasForcePush(exps)) bad.push(`${label}:${JSON.stringify(exps.map((e) => e.kind === 'git' ? `git ${e.invocation.subcommand} ${e.invocation.args.join(' ')}` : `${e.kind}:${e.reason || ''}`))}`);
  }
  // GIT_DIR also hides remote.<r>.push force from implicit targets.
  const imp = G.implicitPushTargets(cfg(r, { GIT_DIR: evilGit }), { kind: 'branch', branch: 'feat' }, 'origin');
  if (!imp.forceFromConfig && !imp.unknown) bad.push('GIT_DIR: implicit push shows no config force');
  assert.deepEqual(bad, []);
});

test('G4 --git-dir to a bare repo: discoverGitDirs result', () => {
  const b = fresh(); git(b, ['init', '-q', '--bare']);
  const d = G.discoverGitDirs(nfs, b);
  assert.notEqual(d, null, 'bare repo dir is not found as a repo (caller must not treat null as "no config")');
});

// ---------- git: config syntax differential vs real git ----------
test('G5 config parse differential vs git config --file (alias.p values)', () => {
  const cases = {
    nospace: '[alias]p=push -f',
    sameLine: '[alias] p = push -f',
    upperKey: '[ALIAS]\n\tP = push -f',
    quoted: '[alias]\n\tp = "push -f"',
    cont: '[alias]\n\tp = push \\\n -f',
    crlf: '[alias]\r\n\tp = push -f\r\n',
    bom: '﻿[alias]\n\tp = push -f',
    semi: '[alias]\n\tp = push -f ; comment',
    tabHeader: '[\talias\t]\n\tp = push -f',
    subsecDot: '[alias.x]\n\tp = push -f',
    spaceInKey: '[alias]\n\tp\t=\tpush\t-f',
    twoHeaders: '[core]\n[alias]\n\tp = push -f\n[alias]\n\tp = push --mirror',
    quotedComment: '[alias]\n\tp = "push -f #notacomment"',
    emptySub: '[alias ""]\n\tp = push -f',
    hashSection: '[alias] # c\n\tp = push -f',
  };
  const diffs = [];
  for (const [name, text] of Object.entries(cases)) {
    const f = join(fresh(), 'c'); fsn.writeFileSync(f, text);
    let want = [];
    try { want = git(ROOT, ['config', '--file', f, '--get-all', 'alias.p']).split('\n').filter(Boolean); } catch (e) { want = [`<git error ${e.status}>`]; }
    const got = G.parseGitConfigText(text, f).filter((e) => e.key === 'alias.p').map((e) => e.value);
    if (JSON.stringify(want) !== JSON.stringify(got)) diffs.push(`${name}: git=${JSON.stringify(want)} head=${JSON.stringify(got)}`);
  }
  console.log(`# G5 diffs:\n# ${diffs.join('\n# ')}`);
  // A diff is only a loosening if git sees a value the resolver misses.
  const missed = diffs.filter((d) => /git=\["push/.test(d) && !/head=\[".*push/.test(d));
  assert.deepEqual(missed, []);
});

// ---------- git: push options / refspecs ----------
test('G6 long-option abbreviation and refspec forms', () => {
  const c = (a) => G.gitLongOptionCandidates(a);
  assert.ok(c('--forc').includes('force'));
  assert.ok(c('--mir').includes('mirror'));
  assert.ok(c('--del').includes('delete'));
  assert.ok(c('--force-w=x').includes('force-with-lease'));
  assert.ok(c('--FORCE').includes('force'), 'upper-case long option');
  const head = { kind: 'branch', branch: 'feat' };
  assert.equal(G.resolvePushRefspec('+feat:main', head).force, true);
  assert.equal(G.resolvePushRefspec(':main', head).delete, true);
  assert.equal(G.resolvePushRefspec('+HEAD:refs/heads/main', head).destination, 'main');
  const bad = [];
  for (const spec of ['+feat:heads/main', '+heads/main', 'feat:heads/production', '+feat:main^{}']) {
    const r = G.resolvePushRefspec(spec, head);
    if (!G.isProtectedBranch(r.destination) && !r.all) bad.push(`${spec} -> dest=${r.destination} protected=false`);
  }
  assert.deepEqual(bad, [], 'git resolves dst "heads/main" to refs/heads/main via refs/%s');
});

test('G6b oracle (no push): git DWIM resolves "heads/main" to refs/heads/main (same ref_rev_parse_rules push dst matching uses)', () => {
  const w = repo(); fsn.writeFileSync(join(w, 'f'), '1'); git(w, ['add', 'f']); git(w, ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', 'commit', '-qm', 'a']);
  git(w, ['branch', 'main']);
  assert.equal(git(w, ['rev-parse', '--symbolic-full-name', 'heads/main']).trim(), 'refs/heads/main');
});

test('G7 implicit push targets: remote.push +, mirror, push.default=matching, upstream=main', () => {
  const r = repo();
  git(r, ['config', 'remote.origin.url', '/dev/null']);
  git(r, ['config', 'remote.origin.push', '+refs/heads/feat:refs/heads/main']);
  git(r, ['config', 'remote.origin.mirror', 'true']);
  git(r, ['config', 'push.default', 'upstream']);
  git(r, ['config', 'branch.feat.merge', 'refs/heads/main']);
  const t = G.implicitPushTargets(cfg(r), G.readGitHead(nfs, G.discoverGitDirs(nfs, r)), null);
  assert.ok(t.forceFromConfig && t.mirror && t.branches.includes('main'));
  git(r, ['config', 'push.default', 'matching']);
  assert.ok(G.implicitPushTargets(cfg(r), { kind: 'branch', branch: 'feat' }, 'origin').all);
});

// ---------- git: limits ----------
test('L1 deep include chain, alias chain, fan-out, huge config: bounded and never a definite benign answer', () => {
  const r = repo();
  const d = fresh();
  for (let i = 0; i < 15; i += 1) fsn.writeFileSync(join(d, `i${i}`), i === 14 ? '[alias]\n\tdeep = push -f origin main\n' : `[include]\n\tpath = ${join(d, `i${i + 1}`)}\n`);
  fsn.appendFileSync(join(r, '.git/config'), `[include]\n\tpath = ${join(d, 'i0')}\n`);
  let c = cfg(r);
  assert.equal(c.incomplete, true);
  assert.ok(hasForcePush(expand(['deep'], c)));
  const r2 = repo();
  let lines = '[alias]\n';
  for (let i = 0; i < 40; i += 1) lines += `\ta${i} = a${i + 1}\n`;
  lines += '\ta40 = push -f origin main\n';
  for (let i = 0; i < 300; i += 1) lines += `\tfan = fan${i % 7}\n`;
  for (let i = 0; i < 7; i += 1) lines += `\tfan${i} = fan\n`;
  fsn.appendFileSync(join(r2, '.git/config'), lines);
  c = cfg(r2);
  assert.ok(hasForcePush(expand(['a0'], c)));
  const t0 = Date.now(); assert.ok(hasForcePush(expand(['fan'], c))); assert.ok(Date.now() - t0 < 2000);
  const r3 = repo();
  fsn.appendFileSync(join(r3, '.git/config'), '[alias]\n\tbig = push -f origin main\n#' + 'x'.repeat(1.1 * 1024 * 1024) + '\n');
  c = cfg(r3);
  assert.equal(c.incomplete, true, 'oversize config must make the result incomplete');
  assert.ok(hasForcePush(expand(['big'], c)) || expand(['big'], c).some((e) => e.kind === 'unknown'));
});

test('L2 ReDoS: pathological inputs to every parser finish < 1.5 s each', () => {
  const evil = [' '.repeat(200000), '['.repeat(100000), '[a "'.repeat(50000), "'".repeat(100000), '=' .repeat(200000), ':'.repeat(200000), '- name: '.repeat(30000), '$('.repeat(50000), '{'.repeat(100000) + ',', 'a\t'.repeat(100000)];
  const slow = [];
  const time = (label, fn) => { const t = Date.now(); try { fn(); } catch {} const ms = Date.now() - t; if (ms > 1500) slow.push(`${label}:${ms}ms`); };
  const fk = createFakeFs();
  evil.forEach((e, i) => {
    time(`gitcfg${i}`, () => G.parseGitConfigText(`[alias]\n${e}\n`, 'x'));
    time(`gitcfgHdr${i}`, () => G.parseGitConfigText(`[${e}]\n`, 'x'));
    time(`toml${i}`, () => DEP.parseSimpleToml(`[${e}\nk = ${e}\n`));
    time(`jsonc${i}`, () => DEP.parseJsonc(e));
    time(`path${i}`, () => P.expandPathOperand(e, { home: '/h', cwd: '/w' }));
    time(`split${i}`, () => G.splitGitCmdline(e));
    time(`params${i}`, () => G.loadGitConfig(fk, { home: '/h', env: { GIT_CONFIG_PARAMETERS: e }, systemFiles: [] }));
    fk.file(`/w/Makefile${i}`, `${e}\n${e}: ${e}\n\t${e}\nX = ${e}\n`);
    time(`make${i}`, () => S.resolveMakeTargets(fk, '/w', ['x'], { makefile: `Makefile${i}` }));
    fk.file(`/k${i}/config`, `current-context: a\ncontexts:\n${e}\n- ${e}name: a\n  context:\n    namespace: ${e}\n`);
    time(`kube${i}`, () => DEP.readKubeContexts(fk, `/k${i}`.replace('/config', '').replace(/^/, ''), undefined));
  });
  assert.deepEqual(slow, []);
});

// ---------- scripts ----------
test('SC1 npm script chain, pre/post hooks, Make include/recursive make, shell wrapper', () => {
  const p = fresh();
  fsn.writeFileSync(join(p, 'package.json'), JSON.stringify({ scripts: { ship: 'npm run deploy', predeploy: 'echo', deploy: 'vercel --prod', postship: 'changeset publish' } }));
  const ship = S.resolvePackageScript(nfs, join(p), 'ship');
  assert.deepEqual(ship.commands.map((c) => c.command), ['npm run deploy', 'changeset publish']);
  fsn.mkdirSync(join(p, 'sub/deep'), { recursive: true });
  assert.equal(S.resolvePackageScript(nfs, join(p, 'sub/deep'), 'deploy').packageDir, p, 'prefix walk up');
  fsn.writeFileSync(join(p, 'Makefile'), 'include extra.mk\nrelease:\n\t$(MAKE) -C sub ship\n');
  const mk = S.resolveMakeTargets(nfs, p, ['release']);
  assert.equal(mk.dynamic, true);
  fsn.writeFileSync(join(p, 'GNUmakefile'), 'DEPLOY = vercel --prod\nrelease: build\n\t@$(DEPLOY)\nbuild:\n\techo\n');
  const mk2 = S.resolveMakeTargets(nfs, p, ['release']);
  assert.ok(mk2.commands.includes('vercel --prod'), 'GNUmakefile wins over Makefile');
  fsn.writeFileSync(join(p, 'w.sh'), '#!/usr/bin/env -S bash -e\nvercel --prod\n');
  const sf = S.readScriptFile(nfs, join(p, 'w.sh'));
  assert.equal(sf.interpreter, 'shell', `env -S bash shebang classified as ${sf.interpreter}`);
});

test('SC2 Makefile: target-specific var, .RECIPEPREFIX, $(shell), override from cmdline', () => {
  const p = fresh();
  fsn.writeFileSync(join(p, 'Makefile'), 'ENV = staging\ndeploy: ENV = production\ndeploy:\n\twrangler deploy --env $(ENV)\n');
  const r = S.resolveMakeTargets(nfs, p, ['deploy']);
  assert.ok(r.dynamic || r.commands.some((c) => c.includes('production')), `target-specific var: ${JSON.stringify(r.commands)} dynamic=${r.dynamic}`);
  const q = fresh();
  fsn.writeFileSync(join(q, 'Makefile'), '.RECIPEPREFIX = >\nship:\n>vercel --prod\n');
  const r2 = S.resolveMakeTargets(nfs, q, ['ship']);
  assert.ok(r2.dynamic || r2.commands.includes('vercel --prod'));
});

// ---------- deploy configs ----------
test('DP1 KUBECONFIG relative path / JSON kubeconfig must not give a definite non-prod answer', () => {
  const h = fresh(); fsn.mkdirSync(join(h, '.kube'));
  fsn.writeFileSync(join(h, '.kube/config'), 'current-context: staging\ncontexts:\n- name: staging\n  context:\n    namespace: dev\n');
  const r = DEP.readKubeContexts(nfs, h, './evil.yaml');
  const bad = [];
  if (r.status === 'ok' && r.contexts.every((c) => c.name === 'staging')) bad.push('relative KUBECONFIG ignored -> staging only');
  const j = fresh(); fsn.mkdirSync(join(j, '.kube'));
  fsn.writeFileSync(join(j, '.kube/config'), JSON.stringify({ 'current-context': 'prod-eu', contexts: [{ name: 'prod-eu', context: { namespace: 'prod' } }] }));
  const rj = DEP.readKubeContexts(nfs, j);
  if (rj.status === 'ok' && rj.contexts.length === 0) bad.push('JSON kubeconfig -> ok with 0 contexts');
  assert.deepEqual(bad, []);
});

test('DP2 wrangler [env.staging] that overrides name/routes to the production worker', () => {
  const p = fresh();
  fsn.writeFileSync(join(p, 'wrangler.toml'), 'name = "api"\nroute = "api.example.invalid/*"\n[env.staging]\nname = "api"\nroute = "api.example.invalid/*"\n');
  const r = DEP.readWranglerConfig(nfs, p);
  assert.equal(r.status, 'ok');
  assert.ok(Object.keys(r).some((k) => /name|route|worker|target/.test(k)), `only ${JSON.stringify(Object.keys(r))} returned: a staging env deploying to the production worker is invisible`);
});

test('DP3 TF_DATA_DIR / CLOUDSDK_ACTIVE_CONFIG_NAME are not modelled (reader gives a definite answer)', () => {
  const p = fresh(); fsn.mkdirSync(join(p, '.terraform')); fsn.writeFileSync(join(p, '.terraform/environment'), 'staging');
  const r = DEP.readTerraformWorkspace(nfs, p);
  assert.equal(r.status, 'ok');
  assert.ok(DEP.readTerraformWorkspace.length > 2, 'no env/TF_DATA_DIR input: TF_DATA_DIR=./x terraform apply reads ./x/environment');
});

// ---------- paths ----------
const ws = (cwd, home) => P.resolveWorkspace(nfs, { eventCwd: cwd, home, tmpdir: null });
const cls = (cwd, home, raw, assignments) => P.classifyDeleteTarget(nfs, ws(cwd, home), P.resolveOperand(nfs, { home, cwd, assignments }, raw, 'delete'));

test('PA1 glob whose expansion passes through a planted symlink child (cloned repo ships vendor/x -> ../../..)', () => {
  const home = fresh(); const r = join(home, 'proj'); fsn.mkdirSync(join(r, 'vendor'), { recursive: true }); fsn.mkdirSync(join(r, '.git'));
  fsn.symlinkSync('../..', join(r, 'vendor/cache')); // -> $HOME
  fsn.symlinkSync('/', join(r, 'vendor/root'));
  const out = {};
  for (const raw of ['vendor/*/', 'vendor/*/*', 'vendor/*/.', 'vendor/cache/', 'vendor/cache/*', 'vendor/cache']) out[raw] = cls(r, home, raw);
  console.log(`# PA1 ${JSON.stringify(out)}`);
  const bad = Object.entries(out).filter(([raw, c]) => raw !== 'vendor/cache' && c === 'in_workspace');
  assert.deepEqual(bad, []);
});

test('PA2 prefix assignment semantics: `DIR=x rm -rf "$DIR/"*` expands $DIR from the shell, not from the prefix', () => {
  // bash oracle
  const out = execFileSync('bash', ['-c', 'unset DIR; DIR=x printf "%s" "$DIR/"']).toString();
  assert.equal(out, '/');
  // The documented contract (PathContext.assignments: "DIR=x rm -rf \"$DIR\"") resolves it to ./x
  const home = fresh(); const r = join(home, 'p'); fsn.mkdirSync(join(r, '.git'), { recursive: true });
  const c = cls(r, home, '$DIR/*', { DIR: 'x' });
  assert.notEqual(c, 'in_workspace', 'a prefix assignment fed as `assignments` turns rm -rf /* into in_workspace');
});

test('PA3 `..` escapes, trailing slash/dot, symlink project in $HOME, unicode look-alike, case variants (fake APFS)', () => {
  const home = fresh(); const real = fresh(); fsn.mkdirSync(join(real, '.git'));
  fsn.symlinkSync(real, join(home, 'proj'));
  const r = join(home, 'proj');
  assert.equal(cls(r, home, '../'), 'home');
  assert.notEqual(cls(r, home, './a/../../..'), 'in_workspace');
  assert.equal(cls(r, home, '.'), 'workspace_root');
  assert.equal(cls(r, home, './'), 'workspace_root');
  assert.equal(cls(r, home, 'build/.'), 'in_workspace');
  assert.equal(cls(r, home, 'xѕsh'), 'unknown');
  assert.notEqual(cls(r, home, `${home}/proj/../.ssh`), 'in_workspace');
  // case-insensitive emulation (fake fs)
  const f = createFakeFs({ caseInsensitive: true });
  f.mkdir('/Users/u/.ssh').mkdir('/work/repo/.git').mkdir('/work/repo/build');
  const w = P.resolveWorkspace(f, { eventCwd: '/work/repo', home: '/Users/u' });
  const k = (raw) => P.classifyDeleteTarget(f, w, P.resolveOperand(f, { home: '/Users/u', cwd: '/work/repo' }, raw, 'delete'));
  assert.equal(k('/USERS/U'), 'home');
  assert.equal(k('/WORK/REPO'), 'workspace_root');
  assert.equal(k('/WORK/REPO/build'), 'in_workspace');
  assert.notEqual(k('/users/u/.SSH'), 'in_workspace');
});

test('PA4 backslash in a quoted operand is converted to "/" (can move an outside target inside)', () => {
  const base = fresh(); const r = join(base, 'repo'); fsn.mkdirSync(join(r, '.git'), { recursive: true });
  fsn.mkdirSync(join(base, 'x\\..\\repo\\sub'));
  const c = cls(r, fresh(), '../x\\..\\repo\\sub');
  assert.notEqual(c, 'in_workspace', 'literal dir "x\\..\\repo\\sub" next to the repo (outside WS) classified in_workspace');
});

// ---------- secrets in outputs ----------
test('SE1 resolver outputs/errors carry no secret: reasons are codes; config values stay in-memory only', () => {
  const r = repo();
  const tok = `dummy_${randomBytes(12).toString('hex')}`;
  git(r, ['config', 'http.extraheader', `Authorization: Bearer ${tok}`]);
  const c = cfg(r);
  const exps = expand(['nosuch'], c);
  assert.ok(!JSON.stringify(exps).includes(tok));
  const t = G.implicitPushTargets(c, { kind: 'branch', branch: 'feat' }, 'origin');
  assert.ok(!JSON.stringify(t).includes(tok));
  assert.ok(JSON.stringify(c).includes(tok), 'loadGitConfig returns every value (in-memory): consumers must never log it');
});

test.after(() => { try { fsn.rmSync(ROOT, { recursive: true, force: true }); } catch {} });
