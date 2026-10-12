// Regression tests from Barvis's delta audit of db578c2c (seatbelt U3/U4 patch round), copied from its evidence/delta.test.cjs.
// Only change: AUDIT_DIST points at this repo's dist.
'use strict';
// Barvis delta audit (db578c2c): new variants per blocker B1-B6 that the builder's tests do not cover.
// No secrets: dummy key material generated at runtime, never printed. Only /tmp dirs created here are used.
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
const { resolveSeatbeltModeOnHost } = require(`${D}/seatbelt-mode.js`);

const ROOT = fsn.realpathSync(fsn.mkdtempSync('/tmp/barvis-delta-'));
let n = 0;
const fresh = () => { const d = join(ROOT, `d${n++}`); fsn.mkdirSync(d, { mode: 0o700 }); return d; };
const nfs = nodeSeatbeltFs();
const uid = process.getuid();
const dummyKey = () => `mrw_dummy_${randomBytes(12).toString('hex')}`;
const HOOK = JSON.stringify({ hooks: { PreToolUse: [{ hooks: [{ command: 'marrow-mcp pre-action-hook --claimed' }] }] } });
const mode = (passwd, env = {}, argv = ['pre-action-hook']) => resolveSeatbeltModeOnHost({ fs: nfs, passwdHome: passwd, uid, env, argv });
const claim = (h) => { fsn.mkdirSync(`${h}/.marrow`, { recursive: true, mode: 0o700 }); fsn.writeFileSync(`${h}/.marrow/claimed`, ''); };

// ---------------- B1 (U4 mode) ----------------
test('B1v evidence only in a third place the code now reads (USERPROFILE home, CODEX_HOME, CLAUDE_CONFIG_DIR, CLINE_DIR)', () => {
  const out = {};
  { const p = fresh(); const up = fresh(); claim(up); out.USERPROFILE = mode(p, { USERPROFILE: up }).mode; }
  { const p = fresh(); const up = fresh(); claim(up); out.HOME_eq_passwd_plus_USERPROFILE = mode(p, { HOME: p, USERPROFILE: up }).mode; }
  { const p = fresh(); const c = fresh(); fsn.writeFileSync(`${c}/config.toml`, `[hooks]\ncmd = "marrow-mcp codex-pre-action-hook --claimed"\n`); out.CODEX_HOME_toml = mode(p, { CODEX_HOME: c }).mode; }
  { const p = fresh(); const c = fresh(); fsn.writeFileSync(`${c}/settings.local.json`, HOOK); out.CLAUDE_CONFIG_DIR_local = mode(p, { CLAUDE_CONFIG_DIR: c }).mode; }
  { const p = fresh(); const c = fresh(); fsn.mkdirSync(`${c}/hooks`); fsn.writeFileSync(`${c}/hooks/PreToolUse`, '#!/bin/sh\nexec marrow-mcp cline-pre-action-hook --claimed\n'); out.CLINE_DIR = mode(p, { CLINE_DIR: c }).mode; }
  { const p = fresh(); out.CODEX_HOME_relative = mode(p, { CODEX_HOME: 'rel/codex' }).mode; }
  console.log(`# B1v ${JSON.stringify(out)}`);
  assert.deepEqual(Object.entries(out).filter(([, m]) => m === 'seatbelt'), []);
});

test('B1v HOME unset / empty: not looser than the passwd answer; HOME symlink to passwd home: equal (not stricter, not looser)', () => {
  const p = fresh();
  const out = { unset_clean: mode(p, {}).mode, empty_clean: mode(p, { HOME: '' }).mode };
  const link = join(ROOT, `link${n++}`); fsn.symlinkSync(p, link);
  out.symlink_clean = mode(p, { HOME: link }).mode;
  out.trailing_slash_clean = mode(p, { HOME: `${p}/` }).mode;
  claim(p);
  out.unset_claimed = mode(p, {}).mode;
  out.empty_claimed = mode(p, { HOME: '' }).mode;
  out.symlink_claimed = mode(p, { HOME: link }).mode;
  console.log(`# B1v-home ${JSON.stringify(out)}`);
  assert.equal(out.unset_clean, 'seatbelt');
  assert.equal(out.symlink_clean, 'seatbelt', 'symlink HOME to passwd home must not be stricter for no reason');
  assert.equal(out.trailing_slash_clean, 'seatbelt');
  for (const k of ['unset_claimed', 'empty_claimed', 'symlink_claimed']) assert.equal(out[k], 'claimed_no_key', k);
});

test('B1v HOME="" (3.9.102 os.homedir() returns "" so its writers use cwd-relative .marrow): informational', () => {
  // Oracle: node's os.homedir() with HOME="" is "" (libuv returns the set value), not the passwd home.
  const h = execFileSync(process.execPath, ['-e', 'process.stdout.write(JSON.stringify(require("os").homedir()))'], { env: { ...process.env, HOME: '' } }).toString();
  console.log(`# B1v-empty os.homedir()=${h}`);
  const p = fresh();
  console.log(`# B1v-empty mode with HOME="" and clean passwd: ${mode(p, { HOME: '' }).mode}`);
});

test('B1v key under an env home is never used (no account from env home); key in trusted home still selects account', () => {
  const p = fresh(); const e = fresh();
  fsn.mkdirSync(`${e}/.marrow`, { mode: 0o700 });
  fsn.writeFileSync(`${e}/.marrow/env`, `MARROW_API_KEY=${dummyKey()}\n`, { mode: 0o600 });
  const r = mode(p, { HOME: e });
  assert.equal(r.mode, 'claimed_no_key');
  assert.deepEqual(r.homes, [p]);
});

// ---------------- B2 (push destinations) ----------------
test('B2v protected destinations in every spelling stay protected; feature controls stay unprotected', () => {
  const head = { kind: 'branch', branch: 'feat' };
  const prot = (spec) => G.isProtectedBranch(G.resolvePushRefspec(spec, head).destination);
  const mustProtect = ['feat:refs/remotes/origin/main', 'HEAD:main', '@:main', 'feat:main~0', 'feat:main^0', 'feat:main@{0}', 'feat:MAIN', 'feat:Main', 'feat:Heads/main', 'feat:HEADS/MAIN', 'feat:REFS/HEADS/main', 'feat:refs/heads/Main', 'feat:refs/heads/heads/main', '+feat:main', 'main:main', 'feat:refs/tags/main', 'feat:tags/main', 'feat:remotes/origin/main', 'feat:production', 'feat:refs/heads/production', ':main', ':heads/main', 'feat:main.lock', 'feat:main/', 'feat:/main', 'feat:ma\tin', 'feat:refs/heads/', 'heads/main', 'refs/heads/main'];
  const bad = mustProtect.filter((s) => !prot(s));
  // --force-with-lease with origin main:main: the option parse must keep the force and the protected dest.
  const inv = G.parseGitPushArgs ? G.parseGitPushArgs(['--force-with-lease', 'origin', 'main:main']) : null;
  console.log(`# B2v unprotected=${JSON.stringify(bad)} lease=${inv ? JSON.stringify(inv).slice(0, 200) : 'n/a (no parseGitPushArgs export)'}`);
  assert.deepEqual(bad, []);
  for (const s of ['feat:feat', 'feat:feature/main', 'feat:mainline', 'feat:origin/main']) assert.equal(prot(s), false, s);
  // git oracle: heads/main and refs/heads/main DWIM to the same ref.
  const r = fresh();
  const env = { ...process.env, HOME: r, GIT_CONFIG_NOSYSTEM: '1' };
  execFileSync('git', ['init', '-q', '-b', 'main', r], { env });
  execFileSync('git', ['-C', r, '-c', 'user.name=x', '-c', 'user.email=x@x.invalid', 'commit', '-q', '--allow-empty', '-m', 'x'], { env });
  for (const ref of ['heads/main', 'refs/heads/main', 'main~0', 'HEAD', '@']) {
    const out = execFileSync('git', ['-C', r, 'rev-parse', '--symbolic-full-name', ref], { env }).toString().trim();
    console.log(`# B2v oracle ${ref} -> ${out || '(commit, not a symbolic ref)'}`);
  }
});

// ---------------- B3 (git relocation) ----------------
const gitEnv = (home) => ({ ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, '.config'), GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' });
const hasRisk = (exps) => exps.some((e) => e.kind === 'unknown' || e.kind === 'shell' || (e.kind === 'git' && (e.invocation.subcommand !== 'status' || e.invocation.args.some((a) => /^(-f|--force.*|\+.*)$/.test(a)))));
const show = (exps) => exps.map((e) => e.kind === 'git' ? `git ${e.invocation.subcommand} ${e.invocation.args.join(' ')}` : `${e.kind}:${e.reason || e.command || ''}`);

test('B3v `git --bare p` in a cloned repo that ships a top-level HEAD/objects/refs/config: git reads ./config', () => {
  const home = fresh(); const r = fresh();
  const env = gitEnv(home);
  execFileSync('git', ['init', '-q', '-b', 'feat', r], { env });
  execFileSync('git', ['-C', r, 'config', 'alias.p', 'status']);
  // Planted in the work tree (committable files):
  fsn.writeFileSync(join(r, 'HEAD'), 'ref: refs/heads/feat\n');
  fsn.mkdirSync(join(r, 'objects')); fsn.writeFileSync(join(r, 'objects/.keep'), '');
  fsn.mkdirSync(join(r, 'refs')); fsn.writeFileSync(join(r, 'refs/.keep'), '');
  fsn.writeFileSync(join(r, 'config'), '[alias]\n\tp = push -f origin main\n[remote "origin"]\n\turl = /dev/null\n\tpush = +refs/heads/*:refs/heads/*\n');
  const oracle = execFileSync('git', ['--bare', 'config', '--get', 'alias.p'], { cwd: r, env }).toString().trim();
  const config = G.loadGitConfig(nfs, { home, dirs: G.discoverGitDirs(nfs, r, {}), env: {}, systemFiles: [] });
  const exps = G.expandGitAliases(['--bare', 'p', 'origin'], { config, env: {} });
  const inv = G.parseGitInvocation(['--bare', 'p', 'origin']);
  console.log(`# B3v --bare oracle alias.p="${oracle}" resolver=${JSON.stringify(show(exps))} directories=${JSON.stringify(inv.directories)} unknownGlobals=${JSON.stringify(inv.unknownGlobals)}`);
  assert.equal(oracle, 'push -f origin main');
  assert.ok(hasRisk(exps), '`git --bare p` gives a definite benign answer while git runs push -f');
});

test('B3v GIT_INDEX_FILE / GIT_OBJECT_DIRECTORY / GIT_NAMESPACE env -> unknown; --namespace flag; core.worktree; gitdir: file; linked worktree config.worktree', () => {
  const home = fresh(); const r = fresh();
  const env = gitEnv(home);
  execFileSync('git', ['init', '-q', '-b', 'feat', r], { env });
  execFileSync('git', ['-C', r, 'config', 'alias.p', 'status'], { env });
  const cfg = (e) => G.loadGitConfig(nfs, { home, dirs: G.discoverGitDirs(nfs, r, e), env: e, systemFiles: [] });
  const out = {};
  for (const name of ['GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_NAMESPACE']) {
    const e = { [name]: '/tmp/x' };
    out[name] = show(G.expandGitAliases(['p', 'origin'], { config: cfg(e), env: e }));
  }
  out.namespace_flag = show(G.expandGitAliases(['--namespace=x', 'p'], { config: cfg({}), env: {} }));
  // core.worktree does not move the config: definite answer from the same config is correct.
  execFileSync('git', ['-C', r, 'config', 'core.worktree', '/tmp'], { env });
  out.core_worktree = show(G.expandGitAliases(['p'], { config: cfg({}), env: {} }));
  // .git file pointing elsewhere: the pointed-to config must be read.
  const elsewhere = fresh(); execFileSync('git', ['init', '-q', '--bare', elsewhere], { env });
  fsn.appendFileSync(join(elsewhere, 'config'), '[alias]\n\tq = push -f origin main\n');
  const w = fresh(); fsn.writeFileSync(join(w, '.git'), `gitdir: ${elsewhere}\n`);
  const oracleQ = execFileSync('git', ['config', '--get', 'alias.q'], { cwd: w, env }).toString().trim();
  out.gitdir_file = show(G.expandGitAliases(['q'], { config: G.loadGitConfig(nfs, { home, dirs: G.discoverGitDirs(nfs, w, {}), env: {}, systemFiles: [] }), env: {} }));
  // linked worktree with extensions.worktreeConfig + alias in config.worktree
  execFileSync('git', ['-C', r, '-c', 'user.name=x', '-c', 'user.email=x@x.invalid', 'commit', '-q', '--allow-empty', '-m', 'x'], { env });
  const wt = join(fresh(), 'wt');
  execFileSync('git', ['-C', r, 'worktree', 'add', '-q', '-b', 'w1', wt], { env });
  execFileSync('git', ['-C', r, 'config', 'extensions.worktreeConfig', 'true'], { env });
  execFileSync('git', ['-C', wt, 'config', '--worktree', 'alias.z', 'push -f origin main'], { env });
  const oracleZ = execFileSync('git', ['config', '--get', 'alias.z'], { cwd: wt, env }).toString().trim();
  out.worktree = show(G.expandGitAliases(['z'], { config: G.loadGitConfig(nfs, { home, dirs: G.discoverGitDirs(nfs, wt, {}), env: {}, systemFiles: [] }), env: {} }));
  console.log(`# B3v ${JSON.stringify(out)} oracleQ="${oracleQ}" oracleZ="${oracleZ}"`);
  for (const name of ['GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_NAMESPACE']) assert.ok(out[name].some((s) => s.startsWith('unknown')), name);
  assert.ok(out.gitdir_file.some((s) => /push -f/.test(s)), 'gitdir: file');
  assert.ok(out.worktree.some((s) => /push -f/.test(s)), 'config.worktree');
});

test('B3v -c include.path / GIT_CONFIG_PARAMETERS include.path pull in another file (git oracle)', () => {
  const home = fresh(); const r = fresh(); const env = gitEnv(home);
  execFileSync('git', ['init', '-q', '-b', 'feat', r], { env });
  const inc = join(fresh(), 'inc.cfg'); fsn.writeFileSync(inc, '[alias]\n\tk = push -f origin main\n');
  let oracle = '';
  try { oracle = execFileSync('git', ['-c', `include.path=${inc}`, 'config', '--get', 'alias.k'], { cwd: r, env }).toString().trim(); } catch { oracle = '(none)'; }
  const config = G.loadGitConfig(nfs, { home, dirs: G.discoverGitDirs(nfs, r, {}), env: {}, systemFiles: [] });
  const exps = G.expandGitAliases(['-c', `include.path=${inc}`, 'k'], { config, env: {} });
  console.log(`# B3v -c include oracle="${oracle}" resolver=${JSON.stringify(show(exps))}`);
  if (oracle === 'push -f origin main') assert.ok(hasRisk(exps), '-c include.path hides the alias');
});

test('B3v HOME string differs from trusted home only by symlink: config incomplete (stricter, informational)', () => {
  const home = fresh(); const link = join(ROOT, `hl${n++}`); fsn.symlinkSync(home, link);
  const r = fresh(); execFileSync('git', ['init', '-q', r], { env: gitEnv(home) });
  const c = G.loadGitConfig(nfs, { home, dirs: G.discoverGitDirs(nfs, r, { HOME: link }), env: { HOME: link }, systemFiles: [] });
  console.log(`# B3v HOME-symlink incomplete=${c.incomplete}`);
});

// ---------------- B4 (globs and links) ----------------
const ws = (cwd, home) => P.resolveWorkspace(nfs, { eventCwd: cwd, home });
const cls = (cwd, home, raw, ctx = {}) => P.classifyDeleteTarget(nfs, ws(cwd, home), P.resolveOperand(nfs, { home, cwd, ...ctx }, raw, 'delete'));
const proj = () => { const home = fresh(); const r = join(home, 'proj'); fsn.mkdirSync(join(r, 'vendor'), { recursive: true }); fsn.mkdirSync(join(r, '.git')); return { home, r }; };

test('B4v link loops, links in .. segments, mid-segment globs, unreadable dirs, >1024 entries', () => {
  const out = {};
  { const { home, r } = proj(); fsn.symlinkSync('b', join(r, 'vendor/a')); fsn.symlinkSync('a', join(r, 'vendor/b')); out.loop_glob_slash = cls(r, home, 'vendor/*/'); out.loop_glob_inner = cls(r, home, 'vendor/*/x'); out.loop_plain = cls(r, home, 'vendor/a/'); }
  { const { home, r } = proj(); fsn.mkdirSync(join(home, 'sub')); fsn.symlinkSync(join(home, 'sub'), join(r, 'vendor/cache')); out.dotdot_after_link = cls(r, home, 'vendor/cache/../victim'); out.dotdot_after_link_glob_prefix = cls(r, home, 'vendor/cache/../*'); }
  { const { home, r } = proj(); fsn.symlinkSync('/', join(r, 'vendor/cache')); out.mid_segment = cls(r, home, 'vendor/c*e/etc'); out.qmark = cls(r, home, 'vendor/cach?/'); out.bracket_neg = cls(r, home, 'vendor/[!x]ache/'); out.dotstar = cls(r, home, 'vendor/.*/'); }
  { const { home, r } = proj(); out.dotstar_repo = cls(r, home, '.*/'); }
  { const { home, r } = proj(); const d = join(r, 'vendor/locked'); fsn.mkdirSync(d); fsn.symlinkSync('/', join(d, 'x')); fsn.chmodSync(d, 0o000); out.unreadable = cls(r, home, 'vendor/*/*/'); fsn.chmodSync(d, 0o700); }
  { const { home, r } = proj(); for (let i = 0; i < 1100; i += 1) fsn.writeFileSync(join(r, 'vendor', `f${i}`), ''); out.over_budget = cls(r, home, 'vendor/*/'); }
  { const { home, r } = proj(); fsn.symlinkSync(home, join(r, 'vendor/h')); out.glob_then_dotdot = cls(r, home, 'vendor/*/../x'); }
  console.log(`# B4v ${JSON.stringify(out)}`);
  const bad = Object.entries(out).filter(([, c]) => c === 'in_workspace');
  assert.deepEqual(bad, []);
  // bash oracle for `..` after a link: the kernel resolves the link first.
  const { home, r } = proj(); fsn.mkdirSync(join(home, 'sub')); fsn.symlinkSync(join(home, 'sub'), join(r, 'vendor/cache'));
  const real = execFileSync('bash', ['-c', 'cd "$1" && cd -P vendor/cache/.. && pwd -P', '_', r]).toString().trim();
  assert.equal(real, home);
});

test('B4v hard links: a hard-linked file inside the repo is only unlinked by rm (no directory hard links on Linux)', () => {
  const { home, r } = proj();
  const outside = join(home, 'secret.txt'); fsn.writeFileSync(outside, 'x');
  fsn.linkSync(outside, join(r, 'vendor/hl'));
  assert.equal(cls(r, home, 'vendor/hl'), 'in_workspace');
  let dirLink = 'refused';
  try { fsn.linkSync(home, join(r, 'vendor/dl')); dirLink = 'allowed'; } catch { /* EPERM */ }
  console.log(`# B4v hard-link file=in_workspace dir-hardlink=${dirLink}`);
  assert.equal(dirLink, 'refused');
});

// ---------------- B5 (variables) ----------------
test('B5v variables contract: earlier statements vs prefix assignments vs ${X:-/} vs $(echo /) vs ~+ after PWD=', () => {
  const { home, r } = proj();
  const out = {
    export_then_rm: cls(r, home, '$DIR/*', { variables: { DIR: 'x' } }), // export DIR=x; rm -rf "$DIR"/*  (correct: ./x/*)
    same_shell_assign: cls(r, home, '$DIR', { variables: { DIR: 'x' } }),
    prefix_only: cls(r, home, '$DIR/', { prefixAssignments: { DIR: 'x' } }),
    default_expansion: cls(r, home, '${DIR:-/}', { variables: { DIR: 'x' } }),
    default_unset: cls(r, home, '${DIR:-/}'),
    cmd_subst: cls(r, home, '$(echo /)'),
    empty_var: cls(r, home, '$DIR/*', { variables: { DIR: '' } }),
    home_reassigned: cls(r, home, '~/*', { variables: { HOME: '/' } }),
    pwd_reassigned_dollar: cls(r, home, '$PWD/*', { variables: { PWD: '/' } }),
    pwd_reassigned_tilde_plus: cls(r, home, '~+/*', { variables: { PWD: '/' } }),
    oldpwd_tilde_minus: cls(r, home, '~-/*', { variables: { OLDPWD: '/' } }),
  };
  // bash oracles
  const tp = execFileSync('bash', ['-c', 'cd "$1"; PWD=/; printf %s ~+', '_', r]).toString();
  const pre = execFileSync('bash', ['-c', 'unset DIR; DIR=x printf %s "$DIR/"']).toString();
  const sub = execFileSync('env', ['DIR=x', 'sh', '-c', 'printf %s "$DIR/"']).toString();
  console.log(`# B5v ${JSON.stringify(out)} oracle(~+ after PWD=/)=${tp} oracle(prefix)=${pre} oracle(env DIR=x sh -c)=${sub}`);
  assert.equal(out.export_then_rm, 'in_workspace');
  assert.notEqual(out.prefix_only, 'in_workspace');
  assert.notEqual(out.default_expansion, 'in_workspace');
  assert.notEqual(out.default_unset, 'in_workspace');
  assert.notEqual(out.cmd_subst, 'in_workspace');
  assert.equal(out.empty_var, 'root');
  assert.notEqual(out.home_reassigned, 'in_workspace');
  assert.notEqual(out.pwd_reassigned_dollar, 'in_workspace');
  assert.equal(tp, '/');
  assert.notEqual(out.pwd_reassigned_tilde_plus, 'in_workspace', '`PWD=/; rm -rf ~+/*` deletes /*');
});

// ---------------- B6 (Makefile budget) ----------------
test('B6v 1 MB worst-case Makefile shapes: bounded time, never ok-without-dynamic when over budget', () => {
  const MB = 1024 * 1024;
  const shapes = {
    long_line_prereqs: () => `all: ${'p '.repeat(MB / 2 - 10)}\n\tvercel --prod\n`,
    long_recipe_line: () => `all:\n\techo ${'x'.repeat(MB - 20)}\n`,
    many_targets_one_rule: () => `${Array.from({ length: 60000 }, (_, i) => `t${i}`).join(' ')}: a\n\tvercel --prod\n`.slice(0, MB),
    many_rules: () => { let s = ''; let i = 0; while (s.length < MB - 64) s += `t${i}: t${++i}\n\techo ${i}\n`; return s; },
    many_prereqs_many_rules: () => { let s = ''; let i = 0; while (s.length < MB - 200) s += `r${i++}: ${'a b c d e f g h '.repeat(8)}\n`; return s; },
    deep_includes: () => { let s = ''; for (let i = 0; i < 20000; i += 1) s += `include f${i}.mk\n`; return `${s}all:\n\tvercel --prod\n`; },
    var_bomb: () => { let s = 'V0 = xxxxxxxxxxxxxxxx\n'; for (let i = 1; i < 40; i += 1) s += `V${i} = $(V${i - 1}) $(V${i - 1}) $(V${i - 1}) $(V${i - 1})\n`; return `${s}all:\n\techo $(V39)\n`; },
    continuation_flood: () => `all: \\\n${'a \\\n'.repeat(MB / 5)}\n\tvercel --prod\n`,
    comment_flood: () => `${'#'.repeat(MB - 30)}\nall:\n\tvercel --prod\n`,
    crlf_flood: () => `${'\r\n'.repeat(MB / 2 - 20)}all:\n\tvercel --prod\n`,
  };
  const rows = [];
  for (const [name, make] of Object.entries(shapes)) {
    const dir = fresh(); const text = make();
    fsn.writeFileSync(join(dir, 'Makefile'), text);
    const t0 = process.hrtime.bigint();
    const res = S.resolveMakeTargets(nfs, dir, []);
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    const verdict = res.status === 'ok' ? (res.dynamic ? 'ok+dynamic' : `ok(${res.commands.length} cmds)`) : `${res.status}/${res.reason || ''}`;
    rows.push({ name, bytes: text.length, ms: Math.round(ms), verdict, hidesDeploy: res.status === 'ok' && !res.dynamic && /vercel/.test(text) && !res.commands.some((c) => /vercel/.test(c)) });
  }
  for (const row of rows) console.log(`# B6v ${JSON.stringify(row)}`);
  assert.deepEqual(rows.filter((x) => x.ms > 1500), [], 'over 1.5 s');
  assert.deepEqual(rows.filter((x) => x.hidesDeploy), [], 'definite ok that hides the deploy recipe');
});

test('B6v-sem a multi-word variable used as a prerequisite hides the deploy recipe (make -n oracle)', () => {
  const dir = fresh();
  fsn.writeFileSync(join(dir, 'Makefile'), 'STEPS = build deploy\nall: $(STEPS)\nbuild:\n\techo build\ndeploy:\n\tvercel --prod\n');
  let oracle = '';
  try { oracle = execFileSync('make', ['-n', '-C', dir, 'all'], { stdio: ['ignore', 'pipe', 'ignore'] }).toString(); } catch { oracle = '(make not available)'; }
  const res = S.resolveMakeTargets(nfs, dir, ['all']);
  console.log(`# B6v-sem oracle=${JSON.stringify(oracle)} resolver=${JSON.stringify(res.status === 'ok' ? { commands: res.commands, dynamic: res.dynamic } : res)}`);
  if (/vercel/.test(oracle)) assert.ok(res.status !== 'ok' || res.dynamic || res.commands.some((c) => /vercel/.test(c)), 'definite ok without the vercel recipe');
});

test.after(() => { fsn.rmSync(ROOT, { recursive: true, force: true }); });
