const assert = require('node:assert/strict');
const test = require('node:test');

const { createFakeFs } = require('./support/seatbelt-fake-fs.cjs');
const {
  parseGitConfigText,
  loadGitConfig,
  gitConfigValues,
  discoverGitDirs,
  expandGitAliases,
  parseGitInvocation,
  splitGitCmdline,
  gitLongOptionCandidates,
  readGitHead,
  readRemoteDefaultBranch,
  isProtectedBranch,
  resolvePushRefspec,
  implicitPushTargets,
} = require('../dist/seatbelt-git.js');

const REPO_CONFIG = `[core]
\tbare = false
[alias]
\tsp = push -f
\tpush = status
\tstatus = push --force origin main
\tsave = "!git push --force origin main"
\tch = sp
\tloop1 = loop2
\tloop2 = loop1
\tquoted = push \\"--force-with-lease\\" origin main
[include]
\tpath = extra.cfg
[includeIf "gitdir:/nowhere/"]
\tpath = /r/.git/cond.cfg
[remote "origin"]
\turl = https://example.invalid/r.git
[branch "feat"]
\tremote = origin
\tmerge = refs/heads/main
`;

function repoFs(extra = {}) {
  const fs = createFakeFs()
    .mkdir('/home/u', { mode: 0o700 })
    .file('/home/u/.gitconfig', '[alias]\n\tsp = push origin feat\n\tglobalonly = push --mirror\n')
    .mkdir('/r/src')
    .file('/r/.git/config', extra.config ?? REPO_CONFIG)
    .file('/r/.git/extra.cfg', '[alias]\n\thidden = push --mirror\n')
    .file('/r/.git/cond.cfg', '[alias]\n\tcond = push --delete origin main\n')
    .file('/r/.git/HEAD', extra.head ?? 'ref: refs/heads/feat\n')
    .file('/r/.git/refs/remotes/origin/HEAD', 'ref: refs/remotes/origin/trunk-x\n');
  return fs;
}

function ctx(fs, env = {}) {
  const dirs = discoverGitDirs(fs, '/r/src');
  const config = loadGitConfig(fs, { home: '/home/u', dirs, env, systemFiles: [] });
  return { dirs, config, env };
}

function expand(argv, fs = repoFs(), env = {}) {
  const c = ctx(fs, env);
  return expandGitAliases(argv, { config: c.config, env });
}

function pushes(expansions) {
  return expansions.filter((e) => e.kind === 'git' && e.invocation.subcommand === 'push').map((e) => e.invocation.args.join(' '));
}

test('git config parse: sections, subsections, quotes, escapes, comments, bare keys', () => {
  const entries = parseGitConfigText('[Alias]\n  P = "push  -f" # c\n[remote "Up"]\n push = +refs/heads/*:refs/heads/*\n[x.Y]\nflag\nk = a\\\nb\n', 'f');
  assert.deepEqual(entries.map((e) => [e.key, e.value]), [
    ['alias.p', 'push  -f'],
    ['remote.Up.push', '+refs/heads/*:refs/heads/*'],
    ['x.y.flag', 'true'],
    ['x.y.k', 'ab'],
  ]);
});

test('S1 alias: a repo alias hides a force-push (git sp origin main)', () => {
  const found = pushes(expand(['sp', 'origin', 'main']));
  assert.ok(found.includes('-f origin main'));
});

test('S1 alias: every definition across scopes is a candidate (repo and global disagree)', () => {
  const found = pushes(expand(['sp', 'origin', 'main']));
  assert.ok(found.includes('-f origin main'));
  assert.ok(found.includes('origin feat origin main'));
  assert.ok(pushes(expand(['globalonly'])).includes('--mirror'));
});

test('S1 alias: git -c alias.p="push --force" p', () => {
  const found = expand(['-c', 'alias.p=push --force', 'p', 'origin', 'main']);
  assert.deepEqual(pushes(found), ['--force origin main']);
});

test('S1 alias: names fold case like git config keys (git SP)', () => {
  assert.ok(pushes(expand(['SP', 'origin', 'main'])).includes('-f origin main'));
});

test('S1 alias: a planted alias never overrides a built-in (git push / git status stay themselves)', () => {
  const push = expand(['push', 'origin', 'main']);
  assert.equal(push.length, 1);
  assert.equal(push[0].invocation.subcommand, 'push');
  const status = expand(['status']);
  assert.equal(status.length, 1);
  assert.equal(status[0].invocation.subcommand, 'status');
});

test('adversarial fix: an alias named like a maybe-installed command (git lfs, git switch) keeps both answers', () => {
  const fs = repoFs({ config: `${REPO_CONFIG}[alias]\n\tlfs = push -f origin main\n\tswitch = push --mirror\n\tlog = push -f origin main\n` });
  const lfs = expand(['lfs'], fs);
  assert.ok(lfs.some((e) => e.kind === 'git' && e.invocation.subcommand === 'lfs'));
  assert.deepEqual(pushes(lfs), ['-f origin main']);
  assert.deepEqual(pushes(expand(['switch'], fs)), ['--mirror']);
  // A core built-in is never overridden.
  assert.deepEqual(expand(['log'], fs).map((e) => e.invocation.subcommand), ['log']);
  // A maybe-installed command with no alias is just itself.
  assert.deepEqual(expand(['subtree']).map((e) => e.kind + ':' + e.invocation.subcommand), ['git:subtree']);
});

test('S1 alias: recursive aliases expand; loops are unknown', () => {
  assert.ok(pushes(expand(['ch', 'origin', 'main'])).includes('-f origin main'));
  assert.deepEqual(expand(['loop1']).map((e) => e.kind + ':' + (e.reason || '')), ['unknown:loop']);
});

test('S1 alias: `!sh` aliases become shell commands with the args kept', () => {
  const found = expand(['save', 'x']);
  assert.deepEqual(found, [{ kind: 'shell', command: 'git push --force origin main', args: ['x'] }]);
});

test('S1 alias: include and includeIf files are read (conditions not evaluated: more candidates only)', () => {
  assert.deepEqual(pushes(expand(['hidden'])), ['--mirror']);
  assert.deepEqual(pushes(expand(['cond'])), ['--delete origin main']);
});

test('S1 alias: quoted alias words keep their quoting (split_cmdline)', () => {
  assert.deepEqual(pushes(expand(['quoted'])), ['--force-with-lease origin main']);
  assert.deepEqual(splitGitCmdline(`push 'a b' "c\\"d" e\\ f`), ['push', 'a b', 'c"d', 'e f']);
  assert.equal(splitGitCmdline('push "open'), null);
});

test('S1 alias: an alias that starts with global options is re-parsed', () => {
  const found = expand(['-c', 'alias.x=-c push.default=matching push', 'x']);
  assert.equal(found[0].invocation.subcommand, 'push');
  assert.ok(found[0].invocation.config.some(([k, v]) => k === 'push.default' && v === 'matching'));
});

test('S1 alias: GIT_CONFIG_COUNT and GIT_CONFIG_PARAMETERS aliases (env adds candidates)', () => {
  const env = { GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'alias.e', GIT_CONFIG_VALUE_0: 'push --force' };
  assert.deepEqual(pushes(expand(['e'], repoFs(), env)), ['--force']);
  const params = { GIT_CONFIG_PARAMETERS: `'alias.q'='push --mirror'` };
  assert.deepEqual(pushes(expand(['q'], repoFs(), params)), ['--mirror']);
  const broken = ctx(repoFs(), { GIT_CONFIG_COUNT: 'x' });
  assert.equal(broken.config.incomplete, true);
});

test('S1 alias: --config-env alias with a missing variable is unknown', () => {
  assert.deepEqual(expand(['--config-env=alias.z=ZV', 'z']).map((e) => e.kind), ['unknown']);
  const found = expandGitAliases(['--config-env', 'alias.z=ZV', 'z'], { config: ctx(repoFs()).config, env: { ZV: 'push -f' } });
  assert.deepEqual(pushes(found), ['-f']);
});

test('S1 alias: unknown names are unknown, and unreadable config says so', () => {
  assert.deepEqual(expand(['nope']).map((e) => e.reason), ['not_found']);
  const fs = repoFs().fail('/r/.git/config');
  assert.deepEqual(expand(['nope'], fs).map((e) => e.reason), ['config_incomplete']);
});

test('include depth is capped (self-include) and marks config incomplete', () => {
  const fs = repoFs({ config: '[include]\n\tpath = config\n' });
  assert.equal(ctx(fs).config.incomplete, true);
});

test('include paths: ~/ uses the trusted home, relative paths the including file', () => {
  const fs = repoFs({ config: '[include]\n\tpath = ~/inc.cfg\n' }).file('/home/u/inc.cfg', '[alias]\n\th = push -f\n');
  assert.deepEqual(pushes(expand(['h'], fs)), ['-f']);
});

test('git global options: -C, --git-dir, -c, unknown globals', () => {
  const inv = parseGitInvocation(['-C', '/x', '--git-dir=/y/.git', '-c', 'a.b=c', '--no-pager', '--weird', 'push', '-f']);
  assert.deepEqual(inv.directories, ['/x', '/y/.git']);
  assert.deepEqual(inv.config, [['a.b', 'c']]);
  assert.deepEqual(inv.unknownGlobals, ['--weird']);
  assert.equal(inv.subcommand, 'push');
  assert.deepEqual(inv.args, ['-f']);
});

test('A8 long-option prefix abbreviation: --forc, --mirr, --del and negations', () => {
  assert.ok(gitLongOptionCandidates('--forc').includes('force'));
  assert.ok(gitLongOptionCandidates('--forc').includes('force-with-lease'));
  assert.deepEqual(gitLongOptionCandidates('--force'), ['force']);
  assert.deepEqual(gitLongOptionCandidates('--mirr'), ['mirror']);
  assert.deepEqual(gitLongOptionCandidates('--del'), ['delete']);
  assert.deepEqual(gitLongOptionCandidates('--force-w=main:abc'), ['force-with-lease']);
  assert.ok(gitLongOptionCandidates('--f').includes('force'));
  assert.deepEqual(gitLongOptionCandidates('--no-force'), ['no-force']);
  assert.ok(gitLongOptionCandidates('--no-forc').includes('no-force'));
  assert.deepEqual(gitLongOptionCandidates('--zzz'), []);
});

test('HEAD, worktrees and the remote default branch', () => {
  const fs = repoFs();
  const dirs = discoverGitDirs(fs, '/r/src');
  assert.deepEqual(dirs, { gitDir: '/r/.git', commonDir: '/r/.git' });
  assert.deepEqual(readGitHead(fs, dirs), { kind: 'branch', branch: 'feat' });
  assert.equal(readRemoteDefaultBranch(fs, dirs, 'origin'), 'trunk-x');
  assert.equal(readRemoteDefaultBranch(fs, dirs, 'up'), null);
  assert.equal(readRemoteDefaultBranch(fs, dirs, '../x'), 'unknown');
  const detached = repoFs({ head: 'a'.repeat(40) + '\n' });
  assert.deepEqual(readGitHead(detached, dirs), { kind: 'detached' });
  assert.deepEqual(readGitHead(repoFs({ head: 'junk' }), dirs), { kind: 'unknown' });
  const wt = repoFs().file('/w/.git', 'gitdir: /r/.git/worktrees/w\n').file('/r/.git/worktrees/w/commondir', '../..\n').file('/r/.git/worktrees/w/HEAD', 'ref: refs/heads/hotfix/1\n');
  const wtDirs = discoverGitDirs(wt, '/w');
  assert.equal(wtDirs.gitDir, '/r/.git/worktrees/w');
  assert.deepEqual(readGitHead(wt, wtDirs), { kind: 'branch', branch: 'hotfix/1' });
  const wtConfig = loadGitConfig(wt, { home: '/home/u', dirs: wtDirs, systemFiles: [] });
  assert.ok(gitConfigValues(wtConfig, 'alias.sp').includes('push -f'));
});

test('PB: baseline, remote default branch, case variants and unresolved targets', () => {
  for (const name of ['main', 'Main', 'MASTER', 'release/1.2', 'refs/heads/main', 'gh-pages', 'deploy/eu', 'release']) assert.equal(isProtectedBranch(name), true, name);
  for (const name of ['feat/x', 'releasefoo', 'mainline', 'hotfix']) assert.equal(isProtectedBranch(name), false, name);
  assert.equal(isProtectedBranch('trunk-x', ['trunk-x']), true);
  assert.equal(isProtectedBranch(null), true);
  assert.equal(isProtectedBranch(''), true);
});

test('push refspecs: +force, :delete, HEAD, patterns, dynamic', () => {
  const head = { kind: 'branch', branch: 'main' };
  assert.deepEqual(resolvePushRefspec('+HEAD:refs/heads/main', head), { force: true, delete: false, destination: 'main', all: false });
  assert.deepEqual(resolvePushRefspec(':release/1.2', head), { force: false, delete: true, destination: 'release/1.2', all: false });
  assert.equal(resolvePushRefspec('HEAD', { kind: 'detached' }).destination, null);
  assert.equal(resolvePushRefspec('$X', head).destination, null);
  assert.equal(resolvePushRefspec('refs/heads/*:refs/heads/*', head).all, true);
  assert.equal(resolvePushRefspec(':', head).all, true);
  assert.equal(resolvePushRefspec('feat', head).destination, 'feat');
});

test('implicit push targets: union of remote.<r>.push, push.default and upstream; planted +refspec and mirror', () => {
  const plain = ctx(repoFs());
  const head = readGitHead(repoFs(), plain.dirs);
  const t = implicitPushTargets(plain.config, head, null);
  assert.deepEqual(t.remotes, ['origin']);
  assert.ok(t.branches.includes('feat') && t.branches.includes('main'));
  assert.equal(t.forceFromConfig, false);

  const planted = repoFs({ config: `${REPO_CONFIG}[remote "origin"]\n\tpush = +refs/heads/*:refs/heads/*\n\tmirror = true\n[push]\n\tdefault = matching\n` });
  const p = ctx(planted);
  const pt = implicitPushTargets(p.config, readGitHead(planted, p.dirs), 'origin');
  assert.equal(pt.forceFromConfig, true);
  assert.equal(pt.mirror, true);
  assert.equal(pt.all, true);

  const detached = implicitPushTargets(plain.config, { kind: 'detached' }, null);
  assert.equal(detached.unknown, true);
});

test('cloned repo plants config to hide a force-push: every hiding form is visible to the resolver', () => {
  const planted = `[alias]
\tst = push -f origin main
\tci = "!f() { git push --force origin HEAD:main; }; f"
[include]
\tpath = ../.githooks/aliases
[remote "origin"]
\tpush = +HEAD:refs/heads/main
`;
  const fs = repoFs({ config: planted }).file('/r/.githooks/aliases', '[alias]\n\tsync = push --mirr\n');
  assert.deepEqual(pushes(expand(['st'], fs)), ['-f origin main']);
  assert.equal(expand(['ci'], fs)[0].kind, 'shell');
  assert.deepEqual(pushes(expand(['sync'], fs)), ['--mirr']);
  assert.ok(gitLongOptionCandidates('--mirr').includes('mirror'));
  const c = ctx(fs);
  const t = implicitPushTargets(c.config, readGitHead(fs, c.dirs), 'origin');
  assert.equal(t.forceFromConfig, true);
  assert.ok(t.branches.includes('main'));
});
