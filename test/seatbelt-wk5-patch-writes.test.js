'use strict';

// WK-5 (weekly scan, MEDIUM, carried two weeks): `patch`, `git apply` and `git am` write the files their patch text
// names, but the keyless seatbelt never saw those names: `patch` was an inert program, `apply` and `am` were only
// "cannot change the branch" subcommands, and no write-target case read a patch. A prompt-injected agent wrote a diff
// and ran `cd ~ && patch -p0 < x.diff` to edit a protected file (Marrow's own hook settings, .mcp.json, .bashrc).
//
// Now every patch, git apply and git am call is a write to the names in its patch file. The mapper reads a literal,
// bounded, regular patch file; everything it cannot know for certain is an unknown write (S0, a stop, never a pass).
// Rows run on the mapper with the fake host (home /home/u, workspace /home/u/proj, test/support/seatbelt-fakes.cjs) and
// once through the real keyless hook. File contents are dummies.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync, execFileSync } = require('node:child_process');

const { evaluateSeatbeltShell, evaluateSeatbelt } = require('../dist/seatbelt/mapper.js');
const tables = require('../dist/seatbelt/tables.js');
const text = require('../dist/seatbelt/patch-text.js');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');

const WS = '/home/u/proj';
// A unified diff of one file; `a` and `b` are the header names.
const uni = (a, b = a) => `--- ${a}\n+++ ${b}\n@@ -1 +1 @@\n-one\n+two\n`;
const git = (a, b = a) => `diff --git ${a} ${b}\n--- ${a}\n+++ ${b}\n@@ -1 +1 @@\n-one\n+two\n`;
const SETTINGS_P1 = uni('a/.claude/settings.json', 'b/.claude/settings.json');
const SETTINGS_P0 = uni('.claude/settings.json');
const MCP_GIT = git('a/.mcp.json', 'b/.mcp.json');
const OK_P1 = uni('a/src/index.ts', 'b/src/index.ts');
const OK_GIT = git('a/src/index.ts', 'b/src/index.ts');

const FILES = {
  '/home/u/d': SETTINGS_P0,
  '/home/u/proj/d': SETTINGS_P1,
  '/home/u/proj/d0': SETTINGS_P0,
  '/home/u/proj/mcp.diff': MCP_GIT,
  '/home/u/proj/ok.diff': OK_P1,
  '/home/u/proj/okgit.diff': OK_GIT,
  '/home/u/proj/safe-test-fixture-ok.diff': SETTINGS_P1,
  '/home/u/proj/test/safe.diff': MCP_GIT,
  '/home/u/proj/dotdot.diff': uni('a/../.bashrc', 'b/../.bashrc'),
  '/home/u/proj/bashrc.diff': uni('a/.bashrc', 'b/.bashrc'),
  '/home/u/proj/rename.diff': 'diff --git a/x.txt b/.claude/settings.json\nsimilarity index 100%\nrename from x.txt\nrename to .claude/settings.json\n',
  '/home/u/proj/copy.diff': 'diff --git a/x.txt b/.mcp.json\nsimilarity index 100%\ncopy from x.txt\ncopy to .mcp.json\n',
  '/home/u/proj/empty.diff': '',
  '/home/u/proj/prose.diff': 'hello, this is not a patch\n',
  '/home/u/proj/quoted.diff': '--- "a/.claude/settings.json"\n+++ "b/.claude/settings.json"\n@@ -1 +1 @@\n-one\n+two\n',
  '/home/u/proj/escaped.diff': '--- a/x\\.txt\n+++ b/x\\.txt\n@@ -1 +1 @@\n-one\n+two\n',
  '/home/u/proj/m.mbox': `From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\nFrom: A <a@example.invalid>\nSubject: [PATCH] x\n\n---\n ${'x'} | 2 +-\n\n${SETTINGS_P1}`,
  '/home/u/proj/ok.mbox': `From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\nFrom: A <a@example.invalid>\nSubject: [PATCH] x\n\n---\n x | 2 +-\n\n${OK_GIT}`,
  '/home/u/proj/qp.mbox': `From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\nSubject: [PATCH] x\nContent-Transfer-Encoding: quoted-printable\n\n--- a/=2Eclaude/settings.json\n+++ b/=2Eclaude/settings.json\n@@ -1 +1 @@\n-one\n+two\n`,
  '/home/u/proj/two.diff': OK_P1 + SETTINGS_P1,
  '/home/u/proj/ctx.diff': '*** a/.claude/settings.json\t2020-01-01\n--- b/.claude/settings.json\t2020-01-02\n***************\n*** 1 ****\n! one\n--- 1 ----\n! two\n',
  '/home/u/proj/sp.diff': uni('a/.claude/settings.json 2020-01-01 00:00:00', 'b/.claude/settings.json 2020-01-01 00:00:00'),
  '/home/u/proj/index.diff': 'Index: .claude/settings.json\n===================================================================\n',
  '/home/u/proj/null.diff': '--- /dev/null\n+++ b/src/new.ts\n@@ -0,0 +1 @@\n+one\n',
  '/home/u/proj/src/inside.diff': OK_P1,
};
const sh = (command, files = {}, extra = {}) => evaluateSeatbeltShell(command, makeEnv({ files: { ...FILES, ...files }, ...extra }));
// Rows are checked all at once: a failing row is recorded and the test fails at its end with the list of every failing row.
const FAILS = [];
const want = (cond, message) => { if (!cond) FAILS.push(message); };
test.afterEach(() => { const failed = FAILS.splice(0); assert.deepEqual(failed, []); });
const stopsS0 = (command, prefix, files, extra) => {
  const d = sh(command, files, extra);
  want(d.decision === 'stop' && d.category === 'S0', `${command}: expected an S0 stop, got ${d.decision}/${d.category} [${d.reasons}]`);
  if (prefix) want(d.reasons.some((r) => r.startsWith(prefix)), `${command}: expected a ${prefix}* reason, got [${d.reasons}]`);
  return d;
};
const passes = (command, files, extra) => {
  const d = sh(command, files, extra);
  want(d.decision === 'pass' && d.category === 'none', `${command}: expected pass, got ${d.decision}/${d.category} [${d.reasons}]`);
};

// ---- the audit rows: a protected target through every shell form
test('WK-5: patch with a protected target stops S0 (cd ~, -d, -i, --input, stdin file), in every shell form', () => {
  for (const command of [
    'cd ~ && patch -p0 < d',
    'patch -d ~ -p1 < d',
    'patch -d ~ -p1 -i d',
    'patch -p1 -d ~ --input=d',
    'patch --directory=~ -p1 < d',
    'patch -p1 --input d -d ~',
    'cd ~ && patch -p0 -i d',
    'cd ~ && patch -p0 --input=d',
    'cd /home/u && patch -p0 < d',
    'cd ~ && patch -p0 d d',
    'cd ~ && patch .claude/settings.json < d',
    // chained, nested and wrapped
    "bash -c 'cd ~ && patch -p0 < d'",
    "sh -c 'cd ~ && patch -p0 < d'",
    "bash -c 'cd ~; patch -p0 < d'",
    'true; cd ~ && patch -p0 < d',
    'false || cd ~ && patch -p0 < d',
    'false || (cd ~ && patch -p0 < d)',
    'echo hi && cd ~ && patch -p0 < d',
    '(cd ~ && patch -p0 < d)',
    'echo $(cd ~ && patch -p0 < d)',
    'echo "$(cd ~ && patch -p0 < d)"',
    'X=1 patch -d ~ -p1 < d',
    'env X=1 patch -d ~ -p1 < d',
    'time patch -d ~ -p1 < d',
    'nice -n 5 patch -d ~ -p1 < d',
    'sudo patch -d ~ -p1 < d',
    'xargs patch -d ~ -p1 < d',
    'fakeroot patch -d ~ -p1 < d',
    'strace -f patch -d ~ -p1 < d',
    'cross-env A=1 patch -d ~ -p1 -i d',
    'if true; then patch -d ~ -p1 < d; fi',
    'for i in 1; do patch -d ~ -p1 < d; done',
    '{ patch -d ~ -p1 < d; }',
    'patch -d ~ -p1 < d | cat',
    'echo done | { patch -d ~ -p1 -i d; }',
    'cd ~ && patch -p0 < /home/u/d',
    'P=/home/u/d; cd ~; patch -p0 -i "$P"',
  ]) stopsS0(command, 'patch_write');
});

test('WK-5: git apply with a protected target stops S0 (.mcp.json, home files, directory and repository forms)', () => {
  for (const command of [
    'git apply mcp.diff',
    'git apply test/safe.diff',
    'git apply /home/u/proj/mcp.diff',
    'git apply -p1 mcp.diff',
    'git apply -p 1 mcp.diff',
    'git apply --index mcp.diff',
    'git apply --cached mcp.diff',
    'git apply --3way mcp.diff',
    'git apply -3 mcp.diff',
    'git apply --reject mcp.diff',
    'git apply --apply mcp.diff',
    'git apply --whitespace=nowarn mcp.diff',
    'git apply -v -q mcp.diff',
    'git apply ok.diff mcp.diff',
    'git apply -C1 -p1 mcp.diff',
    'git apply --directory=. mcp.diff',
    'git apply --directory ~ d0',
    'git apply --directory=.. ok.diff',
    'git apply --directory=../x mcp.diff',
    'git apply --directory=src/.. mcp.diff',
    'git -C ~ apply /home/u/proj/d',
    'cd ~ && git apply proj/d',
    'git apply d0 --directory=~',
    'git apply --exclude=src/* --include=.mcp.json mcp.diff',
    // chained and wrapped
    "bash -c 'git apply mcp.diff'",
    "sh -c 'git apply mcp.diff'",
    'true; git apply mcp.diff',
    'false || git apply mcp.diff',
    'echo hi && git apply mcp.diff',
    '(git apply mcp.diff)',
    'echo $(git apply mcp.diff)',
    'git apply mcp.diff | cat',
    'GIT_AUTHOR_NAME=x git apply mcp.diff',
    'env X=1 git apply mcp.diff',
    'time git apply mcp.diff',
    'fakeroot git apply mcp.diff',
    'git apply - < mcp.diff && git apply mcp.diff',
    'git -c apply.whitespace=nowarn apply mcp.diff',
  ]) stopsS0(command, 'git_apply_write');
  // the same names through the dashed program and a git alias
  stopsS0('git-apply mcp.diff', 'git_apply_write');
  stopsS0('/usr/lib/git-core/git-apply mcp.diff', 'git_apply_write');
  stopsS0('git -c alias.ap=apply ap mcp.diff', 'git_apply_write');
  stopsS0("git -c 'alias.ap=!patch -p1 -i' ap d -d ~", null);
});

test('WK-5: precision: the rows with a readable protected target stop on the protected path itself, not on a generic hold', () => {
  const protectedRow = (command) => {
    const d = sh(command);
    want(d.reasons.some((r) => /^(?:patch|git_apply|git_am)_write_protected_path$/.test(r)), `${command}: [${d.reasons}]`);
  };
  for (const command of ['cd ~ && patch -p0 < d', 'patch -d ~ -p1 < d', 'patch -d ~ -p1 -i /home/u/proj/d', 'patch -p1 --input=/home/u/proj/d -d ~', 'cd ~ && patch -p0 -i d', 'patch -p1 -i d -o ~/x', "bash -c 'cd ~ && patch -p0 < d'", '(cd ~ && patch -p0 < d)',
    'echo $(cd ~ && patch -p0 < d)', 'X=1 patch -d ~ -p1 < d', 'env X=1 patch -d ~ -p1 < d', 'true; cd ~ && patch -p0 < d', 'false || cd ~ && patch -p0 < d',
    'git apply mcp.diff', 'git apply test/safe.diff', 'git apply -p1 mcp.diff', 'git apply --directory=~ d0', 'git -C ~ apply proj/d', 'cd ~ && git apply proj/d',
    'git am m.mbox', 'git am < m.mbox', 'cd ~ && git am proj/m.mbox', 'git apply rename.diff', 'git apply copy.diff', 'patch -p0 < ctx.diff', 'patch -p1 < sp.diff',
    'patch -p1 < index.diff', 'git apply two.diff', 'patch -p1 < safe-test-fixture-ok.diff', 'git-apply mcp.diff', 'git apply --check --apply mcp.diff', 'git apply --apply --check mcp.diff',
    'patch --dry-run --dry-run -p1 < mcp.diff', 'fakeroot patch -d ~ -p1 < d']) protectedRow(command);
});

test('WK-5: git am with a protected target, a missing mailbox or any session word stops S0', () => {
  for (const command of [
    'git am m.mbox',
    'git am nothing.mbox',
    'git am ok.mbox m.mbox',
    'git am --signoff m.mbox',
    'git am -3 -s -k m.mbox',
    'git am --directory=src m.mbox',
    'git am -p1 m.mbox',
    'git am < m.mbox',
    'git am qp.mbox',
    'git am',
    'git am -',
    'git am --continue',
    'git am --abort',
    'git am --skip',
    'git am -i m.mbox',
    'git am --patch-format=hg m.mbox',
    'git am src',
    "bash -c 'git am m.mbox'",
    'cd ~ && git am proj/m.mbox',
    'git-am m.mbox',
  ]) stopsS0(command, 'git_am_write');
});

test('WK-5: patch text that is not a known literal file is an unknown write (stdin, heredoc, pipe, substitution, group, variable, glob)', () => {
  for (const command of [
    'patch -p1',
    'patch',
    'patch -p1 <<EOF\n--- a/x\n+++ b/x\nEOF',
    "patch -p1 <<'EOF'\n--- a/src/index.ts\n+++ b/src/index.ts\n@@ -1 +1 @@\n-one\n+two\nEOF",
    "patch -p1 <<< '--- a/src/index.ts'",
    'cat ok.diff | patch -p1',
    'cat d | patch -p1',
    'echo x | patch -p1',
    'cat ok.diff | cat | patch -p1',
    'patch -p1 < <(cat ok.diff)',
    'patch -p1 < "$(echo ok.diff)"',
    'patch -p1 < $P',
    'patch -p1 < "$P"',
    'patch -p1 -i "$P"',
    'patch -p1 --input="$P"',
    'patch -p1 -i $(echo ok.diff)',
    'patch -p1 -i ok.*',
    'patch -p1 < ok.*',
    'patch -p1 -i -',
    'patch -p1 - < ok.diff < ok.diff',
    'patch -p1 < ok.diff < d',
    'patch -p1 0< ok.diff 3< ok.diff',
    'patch -p1 3< ok.diff',
    'patch -p1 <&3',
    'patch -p1 <> ok.diff',
    '{ patch -p1; } < ok.diff',
    '(patch -p1) < ok.diff',
    'while read l; do patch -p1; done < ok.diff',
    "bash -c 'patch -p1' < ok.diff",
    "bash -c 'patch -p1 < ok.diff' < d",
    'cat ok.diff | { patch -p1; }',
    'patch -p1 nothing.diff',
    'patch -p1 -i nothing.diff',
    'patch -p1 < nothing.diff',
    'patch -p1 < src',
    'patch -p1 < /dev/stdin',
    'patch -p1 < /dev/fd/0',
    'patch -p1 -i /proc/self/fd/0',
    'patch a b c',
    'cd $X && patch -p1 < ok.diff',
    'patch -p1 < ok.diff && cd "$X" && patch -p1 < ok.diff',
    'git apply',
    'git apply -',
    'git apply < ok.diff < d',
    'git apply <<EOF\nx\nEOF',
    'cat okgit.diff | git apply',
    'cat okgit.diff | git apply -',
    'git apply "$P"',
    'git apply $P',
    'git apply okgit.*',
    'git apply nothing.diff',
    'git apply ok.diff nothing.diff',
    'git apply src',
    'git apply --directory="$D" ok.diff',
    'git apply -p"$N" ok.diff',
  ]) {
    const d = sh(command);
    want(d.decision === 'stop' && d.category === 'S0', `${command}: expected an S0 stop, got ${d.decision}/${d.category} [${d.reasons}]`);
    want(d.reasons.some((r) => /^(?:patch|git_apply)_write_unknown_/.test(r)), `${command}: expected an unknown-write reason, got [${d.reasons}]`);
  }
});

test('WK-5: more abuse rows: absolute and odd header names, symlink patches, a patch file made on the same line, process substitution, find -exec, CRLF', () => {
  const files = {
    '/home/u/proj/abs.diff': uni('/home/u/.bashrc'),
    '/home/u/proj/abs1.diff': uni('a//home/u/.zshrc', 'b//home/u/.zshrc'),
    '/home/u/proj/tilde.diff': uni('~/.bashrc'),
    '/home/u/proj/slashes.diff': uni('a//.claude///settings.json', 'b//.claude///settings.json'),
    '/home/u/proj/dot.diff': uni('a/./.claude/./settings.json', 'b/./.claude/./settings.json'),
    '/home/u/proj/upper.diff': uni('a/.CLAUDE/Settings.JSON', 'b/.CLAUDE/Settings.JSON'),
    '/home/u/proj/crlf.diff': '--- a/.mcp.json\r\n+++ b/.mcp.json\r\n@@ -1 +1 @@\r\n-one\r\n+two\r\n',
    '/home/u/proj/sym.diff': 'diff --git a/lnk b/lnk\nnew file mode 120000\n--- /dev/null\n+++ b/lnk\n@@ -0,0 +1 @@\n+/home/u/.claude/settings.json\n\\ No newline at end of file\n',
    '/home/u/proj/sym2.diff': 'diff --git a/lnk b/lnk\nold mode 100644\nnew mode 120000\n',
    '/home/u/proj/nofile.diff': 'diff --git a/x b/x\nindex 111..222 100644\nBinary files a/x and b/x differ\n',
  };
  for (const [command, want_] of [
    ['patch -p0 < abs.diff', 'patch_write_protected_path'],
    ['patch -p1 < abs1.diff', 'patch_write_protected_path'],
    ['patch -p0 < tilde.diff', 'patch_write_protected_path'],
    ['patch -p1 < slashes.diff', 'patch_write_protected_path'],
    ['patch -p1 < dot.diff', 'patch_write_protected_path'],
    ['git apply crlf.diff', 'git_apply_write_protected_path'],
    ['patch -p1 < crlf.diff', 'patch_write_protected_path'],
    ['git apply sym.diff', 'git_apply_write_unknown_header_symlink_patch'],
    ['git apply sym2.diff', 'git_apply_write_unknown_header_symlink_patch'],
    ['patch -p1 < sym.diff', 'patch_write_unknown_header_symlink_patch'],
    ['cat > ok.diff <<EOF\n--- a/src/x.ts\n+++ b/src/x.ts\nEOF\npatch -p1 < ok.diff', 'patch_write_unknown_written_here'],
    ['printf "x" > ok.diff; git apply ok.diff', 'git_apply_write_unknown_written_here'],
    ['patch -p1 -i <(cat ok.diff)', 'patch_write_unknown_dynamic_word'],
    ['git apply <(cat ok.diff)', 'git_apply_write_unknown_dynamic_word'],
    ['git apply $(cat ok.diff)', 'git_apply_write_unknown_dynamic_word'],
    ['find . -name x -exec patch -p1 -i d -d ~ {} \\;', 'patch_write_unknown_dynamic_word'],
  ]) {
    const d = sh(command, files);
    want(d.decision === 'stop' && d.category === 'S0' && d.reasons.includes(want_), `${command}: want ${want_}, got ${d.decision}/${d.category} [${d.reasons}]`);
  }
  // names are compared as written on a case-sensitive host and folded on a case-insensitive one (the mapper's own platform rule)
  assert.equal(sh('git apply upper.diff', files).decision, 'pass');
  const mac = sh('git apply upper.diff', files, { platform: 'darwin' });
  want(mac.decision === 'stop' && mac.reasons.includes('git_apply_write_protected_path'), `darwin upper-case names: ${mac.decision} [${mac.reasons}]`);
  // a patch with no file header at all (binary only) lists its names in the git header: still read
  passes('git apply nofile.diff', files);
  // another machine: not a local file, the old answer stays
  const remote = sh("ssh host 'patch -p1 < d'", files);
  want(!remote.reasons.some((r) => /^patch_write/.test(r)), `ssh: [${remote.reasons}]`);
});

test('WK-5: a dynamic git subcommand or -C folder still stops (the existing S1 answer is kept)', () => {
  for (const command of ['git $X apply ok.diff', 'git -C "$X" apply ok.diff', 'git $(echo apply) ok.diff']) want(sh(command).decision === 'stop', command);
});

test('WK-5: stdin means one literal `< file`; a heredoc or here-string is never known-empty or known-safe, even with a benign body', () => {
  const d = sh("patch -p1 <<'EOF'\n--- a/src/index.ts\n+++ b/src/index.ts\n@@ -1 +1 @@\n-one\n+two\nEOF");
  assert.deepEqual(d.reasons, ['patch_write_unknown_stdin']);
  assert.deepEqual(sh('git apply <<EOF\nEOF').reasons, ['git_apply_write_unknown_stdin']);
  assert.deepEqual(sh('git am <<EOF\nEOF').reasons, ['git_am_write_unknown_stdin']);
  assert.deepEqual(sh('cat ok.diff | patch -p1').reasons, ['patch_write_unknown_stdin']);
  assert.deepEqual(sh('patch -p1').reasons, ['patch_write_unknown_stdin']);
});

test('WK-5: a header the reader doubts, a size over the bound, an unknown flag or a file written in this command is an unknown write', () => {
  const cases = [
    ['patch -p1 < empty.diff', 'patch_write_unknown_header_no_headers'],
    ['patch -p1 < prose.diff', 'patch_write_unknown_header_no_headers'],
    ['patch -p1 < quoted.diff', 'patch_write_unknown_header_odd_name'],
    ['patch -p1 < escaped.diff', 'patch_write_unknown_header_odd_name'],
    ['patch -p1 < dotdot.diff', 'patch_write_unknown_header_dotdot'],
    ['git apply dotdot.diff', 'git_apply_write_unknown_header_dotdot'],
    ['git apply empty.diff', 'git_apply_write_unknown_header_no_headers'],
    ['git apply null.diff null.diff empty.diff', 'git_apply_write_unknown_header_no_headers'],
    ['git am qp.mbox', 'git_am_write_unknown_header_encoded_mail_body'],
    ['patch --bogus -p1 < ok.diff', 'patch_write_unknown_unknown_option'],
    ['patch -p1 -e < ok.diff', 'patch_write_unknown_unknown_option'],
    ['patch -p1 -B bak/ < ok.diff', 'patch_write_unknown_unknown_option'],
    ['patch -p1 --suffix=.x < ok.diff', 'patch_write_unknown_unknown_option'],
    ['patch -p1 -z .x < ok.diff', 'patch_write_unknown_unknown_option'],
    ['patch -p1 --follow-symlinks < ok.diff', 'patch_write_unknown_unknown_option'],
    ['patch -p1 --dry < ok.diff', 'patch_write_unknown_unknown_option'],
    ['patch -pX < ok.diff', 'patch_write_unknown_bad_strip'],
    ['patch -p1 -p2 < ok.diff', 'patch_write_unknown_repeated_option'],
    ['patch -p1 -i ok.diff -i d', 'patch_write_unknown_repeated_option'],
    ['patch -d a -d b -p1 < ok.diff', 'patch_write_unknown_repeated_option'],
    ['patch -d src -p1 -i ok.diff', 'patch_write_unknown_dir_relative_input'],
    ['patch -d .. -p1 < ok.diff', 'patch_write_unknown_dotdot'],
    ['git apply --bogus ok.diff', 'git_apply_write_unknown_unknown_option'],
    ['git apply --stat --bogus ok.diff', 'git_apply_write_unknown_unknown_option'],
    ['git apply --chec ok.diff', 'git_apply_write_unknown_unknown_option'],
    ['git apply --verb ok.diff', 'git_apply_write_unknown_unknown_option'],
    ['git apply -vq ok.diff', 'git_apply_write_unknown_unknown_option'],
    ['git apply -p ok.diff', 'git_apply_write_unknown_bad_strip'],
    ['git apply --directory', 'git_apply_write_unknown_missing_value'],
    ['git apply -p1 -p0 ok.diff', 'git_apply_write_unknown_repeated_option'],
    ['git am --bogus m.mbox', 'git_am_write_unknown_unknown_option'],
    ['git apply --directory=src ok.diff --directory=lib', 'git_apply_write_unknown_repeated_option'],
    ['git --git-dir=x.git apply ok.diff', 'git_apply_write_unknown_git_repository'],
    ['git --work-tree=/home/u apply ok.diff', 'git_apply_write_unknown_git_repository'],
    ['GIT_WORK_TREE=~ git apply ok.diff', 'git_apply_write_unknown_git_repository'],
    ['GIT_DIR=x.git git apply ok.diff', 'git_apply_write_unknown_git_repository'],
    ['git -c core.worktree=~ apply ok.diff', 'git_apply_write_unknown_git_worktree'],
    ['cp d ok.diff && patch -p1 < ok.diff', 'patch_write_unknown_written_here'],
    ['echo x > ok.diff && git apply ok.diff', 'git_apply_write_unknown_written_here'],
    ['printf x | tee ok.diff && patch -p1 -i ok.diff', 'patch_write_unknown_written_here'],
    ['mv d ok.diff && patch -p1 -i ok.diff', 'patch_write_unknown_written_here'],
    ['curl -o ok.diff http://localhost/x && git apply ok.diff', 'git_apply_write_unknown_written_here'],
    ['sed -i s/a/b/ ok.diff && patch -p1 < ok.diff', 'patch_write_unknown_written_here'],
    ['ln -sf d ok.diff && patch -p1 < ok.diff', 'patch_write_unknown_written_here'],
    ['ln -s d lnk.diff && patch -p1 < lnk.diff', 'patch_write_unknown_written_here'],
  ];
  for (const [command, reason] of cases) {
    const d = sh(command);
    want(d.decision === 'stop' && d.category === 'S0' && d.reasons.includes(reason), `${command}: want S0 ${reason}, got ${d.decision}/${d.category} [${d.reasons}]`);
  }
});

test('WK-5: the size bound is exact: 1 MiB reads, one byte more is an unknown write', () => {
  const pad = (size) => OK_P1 + ' '.repeat(size - Buffer.byteLength(OK_P1));
  assert.equal(tables.LIMITS.maxPatchBytes, 1024 * 1024);
  passes('patch -p1 < big.diff', { '/home/u/proj/big.diff': pad(1024 * 1024) });
  passes('git apply big.diff', { '/home/u/proj/big.diff': pad(1024 * 1024) });
  const over = pad(1024 * 1024 + 1);
  assert.equal(Buffer.byteLength(over), 1024 * 1024 + 1);
  assert.deepEqual(sh('patch -p1 < big.diff', { '/home/u/proj/big.diff': over }).reasons, ['patch_write_unknown_unreadable']);
  assert.deepEqual(sh('git apply big.diff', { '/home/u/proj/big.diff': over }).reasons, ['git_apply_write_unknown_unreadable']);
  // a protected name hidden behind a long run of padding lines is still found within the bound
  const hidden = `${'x\n'.repeat(400000)}${SETTINGS_P1}`;
  assert.ok(Buffer.byteLength(hidden) < 1024 * 1024);
  stopsS0('patch -p1 < big.diff', 'patch_write_protected_path', { '/home/u/proj/big.diff': hidden });
});

// ---- misleading words, rename and copy headers, `..`, odd header forms: names are read from the patch, not guessed
test('WK-5: a patch path or message that says safe/test does not make a protected target safe; rename and copy headers count', () => {
  for (const command of [
    'patch -p1 < safe-test-fixture-ok.diff',
    'patch -p1 -i safe-test-fixture-ok.diff # harmless fixture test, dry run only',
    'git apply safe-test-fixture-ok.diff',
    'git apply test/safe.diff',
    'cd ~ && patch -p0 < proj/safe-test-fixture-ok.diff && echo "safe test only"',
    'git apply rename.diff',
    'git apply copy.diff',
    'git apply -p0 rename.diff',
    'git apply --directory=src rename.diff',
    'patch -p1 < rename.diff',
    'patch -p1 < copy.diff',
    'patch -p0 < ctx.diff',
    'patch -p0 -i ctx.diff',
    'patch -p1 < sp.diff',
    'patch -p1 < index.diff',
    'patch -p1 < two.diff',
    'git apply two.diff',
    'git apply bashrc.diff --directory=~',
    'cd ~ && git apply proj/bashrc.diff',
  ]) {
    const d = stopsS0(command, null);
    want(d.reasons.some((r) => /^(?:patch_write|git_apply_write)_(?:protected|unknown)/.test(r)), `${command}: [${d.reasons}]`);
  }
  assert.ok(sh('git apply rename.diff').reasons.includes('git_apply_write_protected_path'));
  assert.ok(sh('git apply copy.diff').reasons.includes('git_apply_write_protected_path'));
});

test('WK-5: `+++ b/..` and `../` in any header form stop; a /dev/null side alone is fine', () => {
  for (const name of ['a/../x', '../x', 'a/b/../../c', '..', 'a/..', '/a/../b']) {
    const files = { '/home/u/proj/h.diff': uni(`a/${name}`, `b/${name}`), '/home/u/proj/g.diff': git(`a/${name}`, `b/${name}`) };
    want(sh('patch -p1 < h.diff', files).reasons.includes('patch_write_unknown_header_dotdot'), `patch ${name}`);
    want(sh('git apply g.diff', files).reasons.includes('git_apply_write_unknown_header_dotdot'), `git apply ${name}`);
  }
  passes('patch -p1 < null.diff');
  passes('git apply null.diff');
  assert.ok(text.readPatchNames('--- /dev/null\n+++ b/src/new.ts\n', false).names.includes('b/src/new.ts'));
  assert.deepEqual(text.readPatchNames('--- a/src/old.ts\n+++ /dev/null\n', false).names, ['a/src/old.ts']);
});

// ---- the benign rows keep today's answer
test('WK-5: a literal patch file that edits only workspace files keeps its answer (pass)', () => {
  for (const command of [
    'git apply ok.diff',
    'git apply okgit.diff',
    'git apply -p1 okgit.diff',
    'git apply ok.diff okgit.diff',
    'git apply --check ok.diff',
    'git apply --index ok.diff',
    'git apply --cached okgit.diff',
    'git apply --reverse ok.diff',
    'git apply --directory=src okgit.diff',
    'git apply --whitespace=fix ok.diff',
    'git apply /home/u/proj/ok.diff',
    'git apply null.diff',
    'git apply -v ok.diff',
    'cd src && git apply ../ok.diff',
    'cd src && git apply inside.diff',
    'git -C src apply inside.diff',
    'git apply -- ok.diff',
    'patch -p1 < ok.diff',
    'patch -p1 -i ok.diff',
    'patch -p1 --input=ok.diff',
    'patch -p1 --input ok.diff',
    'patch -p1 -N -s -f -R < ok.diff',
    'patch -Nsp1 < ok.diff',
    'patch -p1 -b < ok.diff',
    'patch -p1 -l -t --forward --force --quiet < ok.diff',
    'patch -p1 --fuzz=3 -F 2 < ok.diff',
    'patch -p1 -d src < ok.diff',
    'patch -d src -p1 -i /home/u/proj/ok.diff',
    'patch -p1 src/index.ts < ok.diff',
    'patch -p1 src/index.ts ok.diff',
    'patch -p1 -o /tmp/out.ts < ok.diff',
    'patch -p1 -r /tmp/out.rej -i ok.diff',
    'patch -p1 < null.diff',
    'patch -p0 < okgit.diff',
    'cd src && patch -p1 < ../ok.diff',
    'patch --help',
    'patch --version',
    'git apply --help',
    'git apply -h',
    'git am --help',
    'git am ok.mbox',
    'git am -3 -s ok.mbox',
    'git am < ok.mbox',
    'git am --directory=src ok.mbox',
  ]) passes(command);
});

test('WK-5: dry runs and read-only git apply forms write nothing and keep today\'s answer, only when the flag parse is certain', () => {
  for (const command of [
    'patch --dry-run -p1 < ok.diff',
    'patch --dry-run -p1 < mcp.diff',
    'patch --dry-run -p0 -i d0 -d ~',
    'patch -p1 --dry-run -i d',
    'cd ~ && patch --dry-run -p0 < d',
    'git apply --check mcp.diff',
    'git apply --stat mcp.diff',
    'git apply --numstat mcp.diff',
    'git apply --summary mcp.diff',
    'git apply --check --stat --numstat --summary mcp.diff',
    'git apply --check -p1 --directory=src mcp.diff',
    'git apply --check -v mcp.diff',
    'git apply --check nothing.diff',
    'git apply --stat - < mcp.diff',
    'git apply --check',
    'cat mcp.diff | git apply --check',
  ]) passes(command);
  // not certain, or applying again: back to the write reading
  for (const command of [
    'git apply --check --apply mcp.diff',
    'git apply --apply --check mcp.diff',
    'git apply --stat --apply mcp.diff',
    'git apply --check --no-check mcp.diff',
    'git apply --check --no-apply mcp.diff',
    'git apply --no-check --apply mcp.diff',
    'git apply --check --reject mcp.diff',
    'git apply --check --index mcp.diff',
    'git apply --check --cached mcp.diff',
    'git apply --check --3way mcp.diff',
    'git apply --check -3 mcp.diff',
    'git apply --check --intent-to-add mcp.diff',
    'git apply --summary --build-fake-ancestor=x mcp.diff',
    'git apply --check --bogus mcp.diff',
    'git apply --chec mcp.diff',
    'git apply --stat --check --apply mcp.diff',
    'git apply --check mcp.diff && git apply mcp.diff',
    'git apply --check mcp.diff ; git apply mcp.diff',
    'git apply --check --check mcp.diff',
    'git apply --stat --stat mcp.diff',
    'git apply --check --stat --check mcp.diff',
    'patch --dry-run --dry-run -p1 < mcp.diff',
    'patch --dry-run -p1 -o ~/.bashrc < mcp.diff',
    'patch --dry-run -p1 --bogus < mcp.diff',
    'patch --dry -p1 < mcp.diff',
    'patch --dry-run=1 -p1 < mcp.diff',
    'patch --dry-run -p1 < mcp.diff && patch -p1 < mcp.diff',
    'patch --dry-run -p1 < mcp.diff; patch -p1 < mcp.diff',
  ]) {
    const d = sh(command);
    want(d.decision === 'stop' && d.category === 'S0', `${command}: expected an S0 stop, got ${d.decision}/${d.category} [${d.reasons}]`);
  }
});

test('WK-5: output, reject and fake-ancestor files are write targets too', () => {
  stopsS0('patch -p1 -o ~/.bashrc < ok.diff', 'patch_write_protected_path');
  stopsS0('patch -p1 --output=~/.bashrc -i ok.diff', 'patch_write_protected_path');
  stopsS0('patch -p1 -r ~/.claude/settings.json -i ok.diff', 'patch_write_protected_path');
  stopsS0('patch -p1 --reject-file=.mcp.json -i ok.diff', 'patch_write_protected_path');
  stopsS0('patch -p1 --global-reject-file=~/.zshrc -i ok.diff', 'patch_write_protected_path');
  stopsS0('git apply --build-fake-ancestor=.mcp.json ok.diff', 'git_apply_write_protected_path');
  stopsS0('git apply --build-fake-ancestor ~/.bashrc ok.diff', 'git_apply_write_protected_path');
});

// ---- tail-position words are data, not patch calls
test('WK-5: a bare `patch` word of a version tool is data and keeps its answer; a real wrapper call is read', () => {
  for (const command of ['poetry version patch', 'bumpversion patch', 'semver -i patch 1.2.3', 'hatch version patch', 'cargo set-version --bump patch', 'npm version patch',
    'pnpm version patch', 'yarn version --patch', 'npm run patch', 'git commit -m "patch"', 'echo patch', 'make patch', 'kubectl patch deploy x -p {}']) {
    const d = sh(command);
    want(!d.reasons.some((r) => /^patch_write/.test(r)), `${command}: [${d.reasons}]`);
  }
  for (const command of ['fakeroot patch -p0 -d ~ < d', 'fakeroot patch -p1 -i d -d ~', 'strace patch -p1 d d', 'fakeroot patch d.diff d']) {
    want(sh(command, { '/home/u/proj/d.diff': OK_P1 }).reasons.some((r) => /^patch_write/.test(r)), command);
  }
});

// ---- consumers: the label reaches the keyless stop, the account floor and the outage hold, and downstream cannot undo it
test('WK-5: the tables say what they control: patch is no inert program, git apply/am only stay in the branch-handling list', () => {
  assert.equal(tables.INERT_PROGRAMS.has('patch'), false);
  for (const name of ['patch', 'git-apply', 'git-am']) assert.ok(tables.KNOWN_COMMANDS.has(name), name);
  // HEAD_SAFE_SUBS (mapper.ts) lists the git subcommands that cannot change which branch is checked out. It is not a
  // write list: `apply` and `am` stay in it, and their writes come from patchFamilyWrites.
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'seatbelt', 'mapper.ts'), 'utf8');
  assert.match(src, /cannot change which branch is checked out/);
  assert.match(src, /if \(sub === 'apply' \|\| sub === 'am'\) patchFamilyWrites\(sub, args, gctx, run, x, overrides\)/);
  assert.match(src, /case 'patch': return patchFamilyWrites\('patch'/);
});

test('WK-5: every new reason is a receipt-safe code (lowercase words, at most 64 characters) and no row leaks a path or a name', () => {
  const reasons = new Set();
  for (const command of ['patch -p1', 'patch -p1 < empty.diff', 'patch -p1 < quoted.diff', 'patch -p1 < dotdot.diff', 'patch --bogus < ok.diff', 'patch -p1 -i ok.diff -i d',
    'patch -p1 < d', 'git apply mcp.diff', 'git apply', 'git apply --bogus ok.diff', 'git am qp.mbox', 'git am --continue', 'git --git-dir=x apply ok.diff',
    'git -c core.worktree=~ apply ok.diff', 'git apply --directory=.. ok.diff', 'cp d ok.diff && patch -p1 < ok.diff', 'patch a b c', 'patch -d src -p1 -i ok.diff']) {
    for (const r of sh(command).reasons) reasons.add(r);
  }
  assert.ok(reasons.size >= 12, [...reasons].join(','));
  for (const r of reasons) { assert.match(r, /^[a-z0-9_]{1,64}$/, r); assert.doesNotMatch(r, /settings|mcp|bashrc|claude|home|proj/); }
});

test('WK-5 consumers (mapper level): the file-edit tools and other shells read the same label; the outage reading is high, never not_high', () => {
  const { outageRisk } = require('../dist/seatbelt/hook.js');
  // Tool names that run a shell command share the mapper's shell answer.
  for (const tool of ['Bash', 'Monitor', 'PowerShell']) {
    const input = tool === 'Monitor' ? { command: 'cd ~ && patch -p0 < d', description: 'w', timeout_ms: 60000 } : { command: 'cd ~ && patch -p0 < d' };
    const d = evaluateSeatbelt({ tool_name: tool, tool_input: input }, makeEnv({ files: FILES }));
    want(d.decision === 'stop' && d.category === 'S0', `${tool}: ${d.decision}/${d.category}`);
  }
  // The outage reading (a hit that is not a budget or internal error is high). Run on the real file system of a sandbox.
  // outageRisk reads the user's real home (passwd) for `~`, so the rows name the sandbox files by relative path.
  const sb = sandbox();
  try {
    for (const command of ['git apply mcp.diff', 'git am m.mbox', 'patch -p1', 'git apply', 'cat mcp.diff | git apply', 'patch -p1 -i "$P"', 'patch -p1 < nothing.diff', 'git apply --directory=.. ok.diff']) {
      const r = outageRisk({ tool_name: 'Bash', tool_input: { command }, cwd: sb.proj, truncated: false }, Date.now() + 60_000);
      want(r.risk === 'high', `${command}: outage reading ${r.risk} (a hit is high; never not_high)`);
    }
  } finally { sb.cleanup(); }
  // A benign call is not made high by the new table entries: no hit and no risk tag, which is what outageRisk reads.
  for (const command of ['git apply ok.diff', 'patch -p1 < ok.diff', 'git apply --check mcp.diff', 'patch --dry-run -p1 < mcp.diff']) {
    const d = sh(command);
    want(d.decision === 'pass' && d.hits.length === 0 && d.risk.length === 0, `${command}: ${d.decision} hits=${d.hits.length} risk=${d.risk.length}`);
  }
});

// The real hook CLI, keyless, in a temporary home with a real git work tree (dummy file contents).
const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const PRELOAD = path.join(__dirname, 'support', 'seatbelt-hook-preload.cjs');
const HOOKS = { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'npx -y --package=@getmarrow/mcp@3.9.103 marrow-mcp claude-pre-action-hook' }] }] };

function sandbox() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-wk5-')));
  const home = path.join(root, 'home');
  const proj = path.join(home, 'proj');
  fs.mkdirSync(proj, { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  for (const d of ['.ssh', '.aws', '.marrow', '.claude']) fs.mkdirSync(path.join(home, d), { mode: 0o700 });
  execFileSync('git', ['init', '-q', '-b', 'feat/x'], { cwd: proj, env: { PATH: process.env.PATH, HOME: home, GIT_CONFIG_NOSYSTEM: '1' }, stdio: 'ignore' });
  const put = (rel, body) => { const p = path.join(home, rel); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, body); };
  put('.claude/settings.json', JSON.stringify({ hooks: HOOKS }, null, 2));
  put('.claude/plugins/installed_plugins.json', '{"version":2,"plugins":{}}');
  put('.claude/plugins/cache/getmarrow/marrow/1.2.3/scripts/marrow-launch.cjs', 'module.exports = 1;\n');
  put('.npm/_npx/abc123/node_modules/@getmarrow/mcp/dist/cli.js', 'module.exports = 1;\n');
  put('proj/src/index.ts', 'export {};\n');
  put('d', SETTINGS_P0);
  put('proj/d', SETTINGS_P1);
  put('proj/mcp.diff', MCP_GIT);
  put('proj/ok.diff', OK_P1);
  put('proj/m.mbox', FILES['/home/u/proj/m.mbox']);
  return { root, home, proj, netspy: path.join(root, 'net.log'), cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}
function hook(sb, event) {
  const r = spawnSync(process.execPath, ['--require', PRELOAD, CLI, 'claude-pre-action-hook'], {
    cwd: sb.proj, encoding: 'utf8', timeout: 60_000, input: JSON.stringify(event),
    env: { PATH: process.env.PATH, HOME: sb.home, SBT_PASSWD_HOME: sb.home, SBT_NETSPY: sb.netspy, MARROW_HOOK_BACKGROUND_NUDGE: 'false' },
  });
  if (r.error || r.signal || (r.status !== 0 && r.status !== 2)) return { v: 'hook_failed', r };
  let j = null;
  try { j = r.stdout && r.stdout.trim() ? JSON.parse(r.stdout) : null; } catch { j = null; }
  const body = JSON.stringify(j || '') + (r.stderr || '');
  const d = j ? (j.hookSpecificOutput?.permissionDecision || j.decision || null) : null;
  if ((r.status === 2 || d === 'deny' || d === 'block') && /MARROW SEATBELT stopped/.test(body)) return { v: /S0\.self_protection/.test(body) ? 'STOP_S0' : 'stop-other', body };
  if (r.status === 2 || d === 'deny' || d === 'block') return { v: 'held', body };
  if (r.status !== 0 || j === null || typeof j !== 'object' || Array.isArray(j)) return { v: 'hook_failed', r };
  return { v: 'pass' };
}
const sid = () => `wk5-${crypto.randomBytes(6).toString('hex')}`;
const event = (sb, tool, command) => ({ hook_event_name: 'PreToolUse', session_id: sid(), tool_use_id: 't1', tool_name: tool,
  tool_input: tool === 'Monitor' ? { command, description: 'watch', timeout_ms: 60000 } : { command }, cwd: sb.proj });

test('WK-5 consumers (real keyless hook, Bash and Monitor): the protected patch stops S0; the benign one passes; no network', () => {
  const sb = sandbox();
  try {
    for (const tool of ['Bash', 'Monitor']) {
      for (const command of ['cd ~ && patch -p0 < d', 'patch -d ~ -p1 < d', 'git apply mcp.diff', 'git am m.mbox', 'cat d | patch -p1', 'patch -p1 -i "$P"']) {
        const r = hook(sb, event(sb, tool, command));
        assert.equal(r.v, 'STOP_S0', `${tool}: ${command}: ${r.body || ''}`);
      }
      for (const command of ['git apply ok.diff', 'patch -p1 < ok.diff', 'git apply --check mcp.diff']) {
        assert.equal(hook(sb, event(sb, tool, command)).v, 'pass', `${tool}: ${command}`);
      }
    }
    assert.equal(fs.existsSync(sb.netspy) ? fs.readFileSync(sb.netspy, 'utf8') : '', '');
    // the stop text carries rule and reason codes only
    const r = hook(sb, event(sb, 'Bash', 'cd ~ && patch -p0 < d'));
    assert.match(r.body, /Code: S0\.self_protection\/patch_write_protected_path/);
    assert.doesNotMatch(r.body, /\.claude\/settings/);
    // the receipt of that stop: S0, the new reason code, the program, and nothing from the command, the patch or the paths
    const { readReceipts } = require('./support/seatbelt-receipts.cjs');
    const { validateReceipt } = require('../dist/seatbelt/record.js');
    const all = readReceipts(sb.home).map((x) => x.receipt);
    assert.ok(all.length > 0);
    const stops = all.filter((x) => x.decision === 'stop' && x.reasons.includes('patch_write_protected_path'));
    assert.ok(stops.length > 0);
    for (const receipt of stops) { assert.deepEqual(validateReceipt(receipt), []); assert.equal(receipt.rule, 'S0.self_protection'); assert.ok(Array.isArray(receipt.programs)); }
    const raw = readReceipts(sb.home).map((x) => x.line).join('\n');
    for (const banned of ['settings', 'mcp.diff', sb.home, sb.root, '.claude']) assert.ok(!raw.includes(banned), `${banned} is in a receipt`);
  } finally { sb.cleanup(); }
});

test('WK-5 consumers (account floor, watch): the floor records the stop for the same call and never changes the answer', () => {
  const { accountFloor, accountFloorStops, SEATBELT_ROLLOUT } = require('../dist/seatbelt/hook.js');
  const sb = sandbox();
  const keep = process.env.HOME;
  try {
    // accountFloor computes the same mapper decision; in watch it returns null (the record is the product).
    assert.equal(SEATBELT_ROLLOUT.account_floor, 'watch');
    assert.equal(accountFloor('claude', { tool_name: 'Bash', tool_input: { command: 'cd ~ && patch -p0 < d' }, cwd: sb.proj, truncated: false }, Date.now() + 60_000), null);
    // The one rule that would enforce it: a stop floor with no enforced server allow stops; an advisory allow never lifts it.
    const floor = evaluateSeatbeltShell('cd ~ && patch -p0 < d', makeEnv({ files: FILES }));
    assert.equal(floor.decision, 'stop');
    assert.equal(accountFloorStops('on', floor, 'none'), true);
    assert.equal(accountFloorStops('on', floor, 'advisory_allow'), true);
    assert.equal(accountFloorStops('on', floor, 'deny'), true);
    assert.equal(accountFloorStops('on', floor, 'enforced_allow'), false);
    assert.equal(accountFloorStops('watch', floor, 'none'), false);
  } finally { process.env.HOME = keep; sb.cleanup(); }
});

test('WK-5 consumers (approval and held-call keys): keys come from the normalized command text only; two apply calls with different patch files never share one', () => {
  const { stableToolCorrelation, exactHookTarget } = require('../dist/hook-contract.js');
  const key = (command, session = 's1') => stableToolCorrelation({ session_id: session, tool_use_id: 't', tool_name: 'Bash', tool_input: { command } });
  const target = (command) => exactHookTarget({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command } });
  // The patch file's content is never read for a key: a different file name is a different key, the same text is the same key.
  const pairs = [['git apply ok.diff', 'git apply mcp.diff'], ['patch -p1 < ok.diff', 'patch -p1 < mcp.diff'], ['git apply ok.diff', 'git apply ok.diff mcp.diff'],
    ['git apply --check mcp.diff', 'git apply mcp.diff'], ['git apply mcp.diff', 'git apply --directory=~ mcp.diff'], ['patch -p1 -i d', 'patch -p0 -i d'],
    ['cd ~ && patch -p0 < d', 'cd . && patch -p0 < d'], ['git am a.mbox', 'git am b.mbox'], ['patch -d ~ -p1 < d', 'patch -d . -p1 < d']];
  for (const [x, y] of pairs) {
    assert.notEqual(key(x), key(y), `${x} / ${y}`);
    assert.notEqual(target(x) + key(x), target(y) + key(y), `${x} / ${y}`);
  }
  assert.equal(key('git apply ok.diff'), key('git apply ok.diff'));
  // Expected result, stated: the key is a function of the text. A patch file edited between two identical calls keeps the key;
  // the mapper reads the file again at every call, so the new content is judged at the new call.
  assert.equal(key('git apply mcp.diff'), key('git apply mcp.diff'));
  // A secret in the text changes nothing about the rest: text after a redacted span still differs.
  const dummy = crypto.randomBytes(16).toString('hex');
  assert.notEqual(key(`API_KEY=${dummy} patch -p1 -i a.diff`), key(`API_KEY=${dummy} patch -p1 -i b.diff`));
});

test('WK-5 consumers (env-dump check of the hook): a mapper run with an empty file system reads the new rows as S0 unknown writes, never as S4 or an unfinished run', () => {
  const { ENV_DUMP_REASONS } = require('../dist/seatbelt/env-dump.js');
  const bare = { cwd: WS, home: '/home/u', tmpdir: '/tmp', platform: 'linux', fs: { readFile: () => null, realpath: (p) => p },
    git: { toplevel: () => null, getAll: () => [], currentBranch: () => null, remoteHead: () => null } };
  for (const command of ['patch -p1 < ok.diff', 'git apply ok.diff', 'git am m.mbox']) {
    const d = evaluateSeatbeltShell(command, bare);
    assert.equal(d.decision, 'stop', command);
    assert.ok(d.hits.every((h) => h.category === 'S0' && !ENV_DUMP_REASONS.has(h.reason) && !/^(?:mapper_error|budget_)/.test(h.reason)), `${command}: ${d.reasons}`);
  }
});

// ---- rule 6: the neighbours the brief asked about
test('WK-5 rule 6: git checkout -- <path> and git restore already check their operands; stash apply/pop are a follow-up (documented, not changed)', () => {
  for (const command of ['git checkout -- .claude/settings.json', 'git checkout HEAD -- .mcp.json', 'git restore .claude/settings.json', 'git restore --source=HEAD~1 .mcp.json',
    'git restore --worktree .mcp.json', 'git restore -W ~/.bashrc']) {
    const d = stopsS0(command, null);
    assert.ok(d.reasons.some((r) => /^git_(?:checkout|restore)_protected/.test(r)), `${command}: ${d.reasons}`);
  }
  passes('git checkout -- src/index.ts');
  passes('git restore src/index.ts');
  // FOLLOW-UP (main decides the friction): the targets of a stash sit in git objects, not in a patch file, so these
  // keep today's answer. If a later change reads stash content, update this row.
  passes('git stash apply');
  passes('git stash pop');
});

// ---- the pure reader and option parser
test('patch-text: header forms, over-collection and doubt', () => {
  const names = (t, mail = false) => text.readPatchNames(t, mail);
  assert.deepEqual(names('--- a/x\n+++ b/x\n').names, ['a/x', 'b/x']);
  assert.deepEqual(names('--- a/x\t2020-01-01\n+++ b/x\t2020-01-01\n').names, ['a/x', 'b/x']);
  assert.deepEqual(names('--- a/x 2020-01-01 00:00:00\n+++ b/x 2020-01-01\n').names.sort(), ['a/x', 'a/x 2020-01-01 00:00:00', 'b/x', 'b/x 2020-01-01'].sort());
  assert.deepEqual(names('--- a/x\r\n+++ b/x\r\n').names, ['a/x', 'b/x']);
  assert.deepEqual(names('*** a/x\n--- b/x\n').names, ['a/x', 'b/x']);
  assert.deepEqual(names('Index: x/y\n').names, ['x/y']);
  assert.deepEqual(names('diff --git a/x b/y\nrename from x\nrename to y\n').names.sort(), ['a/x', 'b/y', 'x', 'y'].sort());
  assert.deepEqual(names('diff --git a/my file b/my file\n').names.includes('b/my file'), true);
  assert.deepEqual(names('diff -ru old/x new/x\n--- old/x\n+++ new/x\n').names.sort(), ['new/x', 'old/x']);
  assert.deepEqual(names('copy from a\ncopy to b\n').names, ['a', 'b']);
  // hunk content that reads as a header is collected too
  assert.ok(names('--- a/x\n+++ b/x\n@@ -1 +1 @@\n--- note\n+++ more\n').names.includes('note'));
  const doubts = {
    'no_headers': ['', 'hello\n', '@@ -1 +1 @@\n-a\n+b\n', '--- /dev/null\n+++ /dev/null\n'],
    'odd_name': ['--- "a"\n', '--- a\\b\n', '--- a\u0001b\n', 'diff --git "a/x" "b/x"\n'],
    'dotdot': ['--- ../x\n', '+++ a/../x\n', 'rename to a/../x\n'.replace('rename', 'rename').replace(/^/, 'rename from x\n')],
    'empty_name': ['--- \n', '--- \t'],
    'perforce_header': ['==== //depot/x#1 - /x ====\n'],
    'combined_diff': ['diff --cc x\n', 'diff --combined x\n'],
    'odd_git_header': ['diff --git x\n'],
    'long_header': [`--- ${'a'.repeat(5000)}\n`, `diff --git ${'a '.repeat(3000)}\n`],
    'too_many_names': [Array.from({ length: 300 }, (_, i) => `--- a/f${i}\n`).join('')],
  };
  for (const [why, list] of Object.entries(doubts)) for (const t of list) assert.equal(names(t).doubt, why, JSON.stringify(t.slice(0, 40)));
  // mail bodies: only a plain transfer encoding is read
  assert.equal(names('Content-Transfer-Encoding: base64\n--- a/x\n', true).doubt, 'encoded_mail_body');
  assert.equal(names('content-transfer-encoding: Quoted-Printable\n--- a/x\n', true).doubt, 'encoded_mail_body');
  assert.equal(names('Content-Transfer-Encoding: 8bit\n--- a/x\n', true).doubt, null);
  assert.equal(names('Content-Transfer-Encoding: base64\n--- a/x\n', false).doubt, null);
});

test('patch-text: -p stripping and the candidate names', () => {
  assert.equal(text.stripComponents('a/b/c', 0), 'a/b/c');
  assert.equal(text.stripComponents('a/b/c', 1), 'b/c');
  assert.equal(text.stripComponents('a/b/c', 2), 'c');
  assert.equal(text.stripComponents('a/b/c', 3), null);
  assert.equal(text.stripComponents('/a/b', 1), 'a/b');
  assert.equal(text.stripComponents('a//b', 1), 'b');
  assert.equal(text.stripComponents('//a/b', 1), 'a/b');
  assert.equal(text.stripComponents('x', 1), null);
  assert.deepEqual(text.targetNames(['b/.claude/settings.json'], 'apply', null).sort(), ['.claude/settings.json', 'b/.claude/settings.json']);
  assert.deepEqual(text.targetNames(['b/.claude/settings.json'], 'patch', null).sort(), ['b/.claude/settings.json', 'settings.json']);
  assert.deepEqual(text.targetNames(['b/.claude/settings.json'], 'patch', 0), ['b/.claude/settings.json']);
  assert.deepEqual(text.targetNames(['b/x'], 'am', 2), ['b/x']);
  assert.ok(text.targetNames(['/home/u/.bashrc'], 'patch', 1).includes('/home/u/.bashrc'));
  assert.ok(text.targetNames(['/home/u/.bashrc'], 'patch', 1).includes('home/u/.bashrc'));
});

test('patch-text: option parsing is exact (no abbreviations, no repeats, no clusters for git)', () => {
  const p = (kind, ...words) => text.parsePatchCall(kind, words);
  assert.equal(p('patch', '-p1', '-i', 'd').ok, true);
  assert.deepEqual(p('patch', '-p1', '-i', 'd', '-d', 'x', '-o', 'out', 'f').inputs, ['d']);
  assert.deepEqual(p('patch', '-Np1', '-ix').inputs, ['x']);
  assert.equal(p('patch', '-Np1').strip, 1);
  assert.equal(p('patch', '--strip=2').strip, 2);
  assert.equal(p('patch', '--strip', '2').strip, 2);
  assert.equal(p('patch', '--input=d').inputs[0], 'd');
  assert.equal(p('patch', '-p1', '--', '-weird').operands[0], '-weird');
  assert.equal(p('patch', '--dry-run').readOnly, true);
  assert.equal(p('patch', '--dry-run', '--dry-run').readOnly, false);
  assert.equal(p('patch', '--dry-run', '-o', 'x').readOnly, false);
  assert.equal(p('patch', '--version').info, true);
  assert.equal(p('patch', '-v').info, true);
  assert.equal(p('patch', '--version', '-p1').info, false);
  for (const bad of [['-e'], ['-n'], ['-B', 'x'], ['-Y', 'x'], ['-z', 'x'], ['-V', 'x'], ['-C', '1'], ['--follow-symlinks'], ['--merge'], ['--dry'], ['--dry-run=x'], ['--input'], ['-p'], ['-pa']]) {
    assert.equal(p('patch', ...bad).ok, false, bad.join(' '));
  }
  assert.equal(p('apply', '--check').readOnly, true);
  assert.equal(p('apply', '--summary', '--stat', '-p1', '--directory=x', '--include', 'y').readOnly, true);
  for (const bad of [['--check', '--apply'], ['--apply', '--check'], ['--check', '--no-check'], ['--check', '--no-apply'], ['--check', '--reject'], ['--check', '--index'],
    ['--check', '--cached'], ['--check', '-3'], ['--check', '-N'], ['--stat', '--build-fake-ancestor=x'], ['--no-stat'], []]) {
    assert.equal(p('apply', ...bad).readOnly, false, bad.join(' '));
  }
  for (const bad of [['--chec'], ['-vq'], ['-pa'], ['--directory'], ['-C', 'x'], ['--no-bogus'], ['-x'], ['--output=x']]) assert.equal(p('apply', ...bad).ok, false, bad.join(' '));
  assert.equal(p('apply', '-p', '2').strip, 2);
  assert.equal(p('apply', '-p2').strip, 2);
  assert.equal(p('apply', '-C', '1', '--whitespace=fix', '--unsafe-paths', 'a', 'b').operands.length, 2);
  for (const bad of [['-i'], ['--continue'], ['--abort'], ['--skip'], ['-S'], ['--gpg-sign'], ['--patch-format=hg'], ['-r'], ['--show-current-patch']]) assert.equal(p('am', ...bad).ok, false, bad.join(' '));
  assert.equal(p('am', '-3', '-s', '--directory=x', 'm').operands[0], 'm');
  assert.equal(p('am', '--no-keep-cr', '--no-3way', 'm').ok, true);
  assert.equal(p('am', 'm').readOnly, false);
  assert.equal(p('am', '--help').info, true);
});

// ---- patch round 1 (audit r2: MEDIUM-1 header spellings, LOW-1 checkout then patch, LOW-2 the cd rows)
// GNU patch 2.7.6 skips any run of spaces, tabs and `X` before it tests a line for a header, reads `Index:` with no
// space, and git reads `rename old|new` as well as `rename from|to`. A second diff in such a spelling, after a benign
// first diff, used to pass; the rows below were checked against the real binaries in a scratch folder.
const FIRST = uni('a/src/index.ts', 'b/src/index.ts');
const NORMAL = '1c1\n< one\n---\n> two\n';
const MCP_P1 = uni('a/.mcp.json', 'b/.mcp.json');
const indent = (prefix, t) => t.split('\n').map((l) => (l === '' ? l : prefix + l)).join('\n');
const moved = (verb, a, b, to) => `diff --git a/x.txt b/${to}\nsimilarity index 100%\n${verb} ${a} x.txt\n${verb} ${b} ${to}\n`;
const PROTECTED = [['settings', '.claude/settings.json', SETTINGS_P1], ['mcp', '.mcp.json', MCP_P1]];
const LABEL = { patch: 'patch_write', apply: 'git_apply_write', am: 'git_am_write' };
const callsFor = (f) => [['patch', `patch -p1 < ${f}`], ['apply', `git apply ${f}`], ['patch', `patch -p1 -i ${f}`]];
// A row must stop on the protected path itself (not on a generic hold), under the label of its program.
const stopsProtected = (kind, command, files) => {
  const d = sh(command, files);
  want(d.decision === 'stop' && d.category === 'S0' && d.reasons.includes(`${LABEL[kind]}_protected_path`), `${command}: want ${LABEL[kind]}_protected_path, got ${d.decision}/${d.category} [${d.reasons}]`);
};
const stopsUnknown = (kind, command, why, files) => {
  const d = sh(command, files);
  want(d.decision === 'stop' && d.category === 'S0' && d.reasons.includes(`${LABEL[kind]}_unknown_${why}`), `${command}: want ${LABEL[kind]}_unknown_${why}, got ${d.decision}/${d.category} [${d.reasons}]`);
};

test('WK-5 patch 1 (MEDIUM-1 a): a header indented by spaces, a tab or X is read: a second diff after a benign one stops on the protected path', () => {
  const files = {};
  const rows = [];
  for (const [pi, prefix] of [' ', '    ', '\t', 'X', ' X\t X', 'XX', '\t\t ', ' '.repeat(1000)].entries()) {
    for (const [pn, , diff] of PROTECTED) {
      for (const [shape, text] of [['second', FIRST + indent(prefix, diff)], ['only', indent(prefix, diff)]]) {
        const f = `/home/u/proj/ind-${pi}-${pn}-${shape}.diff`;
        files[f] = text;
        for (const [kind, command] of callsFor(`ind-${pi}-${pn}-${shape}.diff`)) rows.push([kind, command]);
      }
    }
  }
  for (const [kind, command] of rows) stopsProtected(kind, command, files);
  // the other header kinds, indented: context diff, git header, perforce-free `Index:` plus unified, CRLF
  const more = {
    '/home/u/proj/i-ctx.diff': FIRST + indent('  ', '*** a/.claude/settings.json\t2020-01-01\n--- b/.claude/settings.json\t2020-01-02\n***************\n*** 1 ****\n! one\n--- 1 ----\n! two\n'),
    '/home/u/proj/i-git.diff': FIRST + indent(' ', MCP_GIT),
    '/home/u/proj/i-crlf.diff': (FIRST + indent(' ', SETTINGS_P1)).replace(/\n/g, '\r\n'),
    '/home/u/proj/i-mix.diff': FIRST + indent('X \t', SETTINGS_P1),
    '/home/u/proj/i-ren.diff': FIRST + indent(' ', 'diff --git a/x.txt b/.claude/settings.json\nrename from x.txt\nrename to .claude/settings.json\n'),
  };
  for (const f of Object.keys(more)) { const name = path.posix.basename(f); stopsProtected('patch', `patch -p1 < ${name}`, more); stopsProtected('apply', `git apply ${name}`, more); }
  // every call form of the audit still reaches the indented file
  for (const command of ["bash -c 'patch -p1 < i-mix.diff'", 'cd . && patch -p1 < i-mix.diff', '(patch -p1 < i-mix.diff)', 'true; git apply i-mix.diff', 'X=1 patch -p1 -i i-mix.diff', 'git apply -p1 --3way i-mix.diff']) {
    const d = sh(command, more);
    want(d.decision === 'stop' && d.category === 'S0' && d.reasons.some((r) => /_write_protected_path$/.test(r)), `${command}: ${d.decision}/${d.category} [${d.reasons}]`);
  }
  // git am reads the mailbox body with the same reader
  const am = { '/home/u/proj/i.mbox': `From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\nSubject: [PATCH] x\n\n---\n x | 2 +-\n\n${FIRST}${indent(' ', MCP_GIT)}` };
  stopsProtected('am', 'git am i.mbox', am);
});

test('WK-5 patch 1 (MEDIUM-1 b): `Index:` with no space, a tab or several spaces names the file, with a normal-format hunk too', () => {
  const files = {};
  const rows = [];
  for (const [id, head] of [['nospace', 'Index:'], ['tab', 'Index:\t'], ['one', 'Index: '], ['three', 'Index:   '], ['tabsp', 'Index:\t '], ['indent', '  Index:'], ['x', 'XIndex:'], ['tabindent', '\tIndex:\t']]) {
    for (const [pn, name] of PROTECTED) {
      for (const [shape, text] of [['second', `${FIRST}${head}${name}\n${NORMAL}`], ['only', `${head}${name}\n${NORMAL}`], ['uni', `${FIRST}${head}${name}\n${uni('src/other.ts')}`]]) {
        const f = `idx-${id}-${pn}-${shape}.diff`;
        files[`/home/u/proj/${f}`] = text;
        for (const [kind, command] of callsFor(f)) rows.push([kind, command]);
      }
    }
  }
  for (const [kind, command] of rows) stopsProtected(kind, command, files);
  // a timestamp after the name does not hide it
  const stamp = { '/home/u/proj/idx-ts.diff': `${FIRST}Index:.claude/settings.json\t2020-01-01\n${NORMAL}` };
  stopsProtected('patch', 'patch -p1 < idx-ts.diff', stamp);
  stopsProtected('apply', 'git apply idx-ts.diff', stamp);
});

test('WK-5 patch 1 (MEDIUM-1 c): `rename old|new` and `copy old|new` name the new file, like from|to, in every pairing', () => {
  const files = {};
  const rows = [];
  for (const verb of ['rename', 'copy']) {
    for (const [a, b] of [['old', 'new'], ['from', 'new'], ['old', 'to'], ['from', 'to'], ['new', 'old']]) {
      for (const [pn, name] of PROTECTED) {
        const f = `mv-${verb}-${a}-${b}-${pn}.diff`;
        files[`/home/u/proj/${f}`] = moved(verb, a, b, name);
        files[`/home/u/proj/after-${f}`] = FIRST + moved(verb, a, b, name);
        files[`/home/u/proj/ind-${f}`] = FIRST + indent(' ', moved(verb, a, b, name));
        for (const g of [f, `after-${f}`, `ind-${f}`]) for (const [kind, command] of callsFor(g)) rows.push([kind, command]);
      }
    }
  }
  for (const [kind, command] of rows) stopsProtected(kind, command, files);
  const am = { '/home/u/proj/mv.mbox': `From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\nSubject: [PATCH] x\n\n---\n x | 2 +-\n\n${moved('rename', 'old', 'new', '.claude/settings.json')}` };
  stopsProtected('am', 'git am mv.mbox', am);
});

test('WK-5 patch 1 (spec 1, 3): a line that opens like a move or an Index with no readable name is a doubt (an unknown write), never a pass', () => {
  const files = {};
  const lines = {
    'rename-2sp': 'rename  from x.txt', 'rename-tab': 'rename\tfrom x.txt', 'rename-bare': 'rename x.txt', 'rename-sp': 'rename ', 'rename-other': 'rename of x.txt',
    'copy-of': 'copy of x.txt', 'copy-tab': 'copy\tto x.txt', 'copy-sp': 'copy ', 'rename-ind': ' rename the thing', 'copy-ind': '\tcopy x y', 'copy-X': 'Xcopy a b',
  };
  for (const [id, line] of Object.entries(lines)) files[`/home/u/proj/odd-${id}.diff`] = `${FIRST}${line}\n`;
  for (const id of Object.keys(lines)) {
    stopsUnknown('patch', `patch -p1 < odd-${id}.diff`, 'header_odd_move_header', files);
    stopsUnknown('apply', `git apply odd-${id}.diff`, 'header_odd_move_header', files);
  }
  // `Index:` with nothing after it has no name to read
  const empty = { '/home/u/proj/e1.diff': `${FIRST}Index:\n${NORMAL}`, '/home/u/proj/e2.diff': `${FIRST}Index:\t \n${NORMAL}`, '/home/u/proj/e3.diff': `${FIRST} Index:\n` };
  for (const f of ['e1.diff', 'e2.diff', 'e3.diff']) { stopsUnknown('patch', `patch -p1 < ${f}`, 'header_empty_name', empty); stopsUnknown('apply', `git apply ${f}`, 'header_empty_name', empty); }
  // an indented header whose name cannot be read is a doubt too (quoted, backslash, control byte, dotdot, long)
  const odd = {
    '/home/u/proj/o1.diff': `${FIRST}  --- "a/x"\n`, '/home/u/proj/o2.diff': `${FIRST}\t+++ a\\b\n`, '/home/u/proj/o3.diff': `${FIRST}X--- a\u0001b\n`,
    '/home/u/proj/o4.diff': `${FIRST} Index:../x\n`, '/home/u/proj/o5.diff': `${FIRST}  --- ${'a'.repeat(5000)}\n`, '/home/u/proj/o6.diff': `${FIRST}  --- \n`,
  };
  const expect = { 'o1.diff': 'odd_name', 'o2.diff': 'odd_name', 'o3.diff': 'odd_name', 'o4.diff': 'dotdot', 'o5.diff': 'long_header', 'o6.diff': 'empty_name' };
  for (const [f, why] of Object.entries(expect)) { stopsUnknown('patch', `patch -p1 < ${f}`, `header_${why}`, odd); stopsUnknown('apply', `git apply ${f}`, `header_${why}`, odd); }
});

test('WK-5 patch 1 (controls): benign indented, Index: and rename diffs that name only ordinary files still pass; plain column-0 headers still stop', () => {
  const files = {};
  const benign = [];
  let n = 0;
  for (const prefix of [' ', '    ', '\t', 'X', ' X\t X', 'XX']) {
    files[`/home/u/proj/b${n}.diff`] = FIRST + indent(prefix, uni('a/src/other.ts', 'b/src/other.ts'));
    benign.push(`b${n}.diff`); n += 1;
  }
  files['/home/u/proj/bi1.diff'] = `${FIRST}Index:src/other.ts\n${NORMAL}`;
  files['/home/u/proj/bi2.diff'] = `${FIRST}Index:\tsrc/other.ts\n${NORMAL}`;
  files['/home/u/proj/bi3.diff'] = `${FIRST}  Index: src/other.ts\n${NORMAL}`;
  files['/home/u/proj/bm1.diff'] = moved('rename', 'old', 'new', 'src/moved.ts');
  files['/home/u/proj/bm2.diff'] = moved('rename', 'from', 'to', 'src/moved.ts');
  files['/home/u/proj/bm3.diff'] = moved('copy', 'from', 'to', 'src/copied.ts');
  files['/home/u/proj/bm4.diff'] = FIRST + indent(' ', moved('rename', 'old', 'new', 'src/moved.ts'));
  // a context line that only looks like prose is not a header: lower-case index:, a lone `---` rule, `diff --git` text, a star line
  files['/home/u/proj/bc.diff'] = FIRST.replace('@@ -1 +1 @@\n', '@@ -1,5 +1,5 @@\n index:.claude/settings.json\n ---\n *** Warning: "x"\n diff --git a/x b/y\n ---name\n');
  benign.push('bi1.diff', 'bi2.diff', 'bi3.diff', 'bm1.diff', 'bm2.diff', 'bm3.diff', 'bm4.diff', 'bc.diff');
  for (const f of benign) { passes(`patch -p1 < ${f}`, files); passes(`git apply ${f}`, files); passes(`patch -p1 -i ${f}`, files); }
  // plain column-0 headers, as before
  for (const command of ['patch -p1 < d', 'git apply mcp.diff', 'git apply rename.diff', 'git apply copy.diff', 'patch -p1 < index.diff', 'patch -p0 < ctx.diff']) stopsS0(command, null);
  // the reader itself: the benign indented diff gives only ordinary names
  assert.deepEqual(text.readPatchNames(files['/home/u/proj/b0.diff'], false).names.sort(), ['a/src/index.ts', 'a/src/other.ts', 'b/src/index.ts', 'b/src/other.ts']);
});

test('WK-5 patch 1 (LOW-2): the cd rows: only the working folder plus -p reach a bare settings.json', () => {
  const files = { '/home/u/.claude/x.diff': uni('a/b/c/settings.json'), '/home/u/proj/x.diff': uni('a/b/c/settings.json'), '/home/u/.claude/y.diff': uni('a/b/c/d/settings.json') };
  stopsProtected('apply', 'cd ~/.claude && git apply -p3 x.diff', files);
  stopsProtected('patch', 'cd ~/.claude && patch -p3 < x.diff', files);
  stopsProtected('patch', 'cd ~/.claude && patch -p3 -i x.diff', files);
  stopsProtected('apply', '(cd ~/.claude && git apply -p3 x.diff)', files);
  stopsProtected('patch', "bash -c 'cd ~/.claude && patch -p3 < x.diff'", files);
  stopsProtected('apply', 'cd /home/u/.claude && git apply -p3 x.diff', files);
  stopsProtected('patch', 'cd ~ && cd .claude && patch -p3 < x.diff', files);
  stopsProtected('apply', 'git -C ~/.claude apply -p3 x.diff', files);
  stopsProtected('patch', 'cd ~/.claude && patch -p4 < y.diff', files);
  // the same diff from the workspace, or with a different strip count, does not reach the protected file
  passes('cd ~/proj && git apply -p3 x.diff', files);
  passes('cd ~/proj && patch -p3 < x.diff', files);
});

test('WK-5 patch 1 (LOW-1): a patch file that git checkout or git restore rewrites on the same line is not the file the mapper read', () => {
  const files = { '/home/u/proj/sub/in.diff': OK_P1, '/home/u/proj/ok.mbox': FILES['/home/u/proj/ok.mbox'] };
  for (const [kind, command] of [
    ['patch', 'git checkout HEAD -- ok.diff && patch -p1 < ok.diff'],
    ['apply', 'git checkout HEAD -- ok.diff && git apply ok.diff'],
    ['apply', 'git checkout main -- ok.diff; git apply ok.diff'],
    ['patch', 'git checkout -- ok.diff && patch -p1 -i ok.diff'],
    ['apply', 'git restore --source=HEAD~1 ok.diff && git apply ok.diff'],
    ['patch', 'git restore ok.diff && patch -p1 -i ok.diff'],
    ['am', 'git checkout HEAD -- ok.mbox && git am ok.mbox'],
    ['apply', 'git checkout HEAD -- ok.diff || true; git apply ok.diff'],
    ['apply', '(git checkout HEAD -- ok.diff) && git apply ok.diff'],
    ['apply', 'git checkout HEAD -- ok.diff && git apply /home/u/proj/ok.diff'],
    ['patch', 'cd sub && git checkout HEAD -- in.diff && patch -p1 < in.diff'],
    ['apply', 'git -C sub checkout HEAD -- in.diff && git apply sub/in.diff'],
  ]) stopsUnknown(kind, command, 'written_here', files);
  // a different file is not the patch file; nothing else about checkout and restore changes
  passes('git checkout HEAD -- other.txt && git apply ok.diff', files);
  passes('git restore other.txt && patch -p1 < ok.diff', files);
  passes('git checkout feat/x && git apply ok.diff', files);
  passes('git checkout -- src/index.ts', files);
  // the script and package readers keep their answers: only the patch readers look at the checked-out names
  const keep = { '/home/u/proj/build.sh': 'echo hi\n', '/home/u/proj/package.json': '{"scripts":{"test":"echo hi"}}\n' };
  for (const [withCheckout, without] of [['git checkout HEAD -- build.sh && bash build.sh', 'true && bash build.sh'], ['git checkout -- package.json && npm test', 'true && npm test'],
    ['git restore build.sh && ./build.sh', 'true && ./build.sh']]) {
    const a = sh(withCheckout, keep);
    const b = sh(without, keep);
    want(a.decision === b.decision && a.category === b.category && a.reasons.join() === b.reasons.join(), `${withCheckout}: [${a.decision} ${a.reasons}] differs from [${b.decision} ${b.reasons}]`);
  }
});

test('WK-5 patch 1 (consumers, mapper level): the keyed floor, the outage reading and the held-call keys see the new header forms; keys come from the command text only', () => {
  const { outageRisk, accountFloor, accountFloorStops } = require('../dist/seatbelt/hook.js');
  const { stableToolCorrelation, exactHookTarget } = require('../dist/hook-contract.js');
  const sb = sandbox();
  try {
    const put = (rel, body) => fs.writeFileSync(path.join(sb.proj, rel), body);
    put('ind.diff', FIRST + indent(' ', MCP_P1));
    put('idx.diff', `${FIRST}Index:.mcp.json\n${NORMAL}`);
    put('ren.diff', moved('rename', 'old', 'new', '.mcp.json'));
    put('ok2.diff', FIRST + indent(' ', uni('a/src/other.ts', 'b/src/other.ts')));
    // the outage reading is high for the forms that used to read not_high, and still not high for the benign one
    for (const command of ['git apply ind.diff', 'patch -p1 < ind.diff', 'git apply idx.diff', 'patch -p1 < idx.diff', 'git apply ren.diff', 'patch -p1 -i ren.diff']) {
      const r = outageRisk({ tool_name: 'Bash', tool_input: { command }, cwd: sb.proj, truncated: false }, Date.now() + 60_000);
      want(r.risk === 'high', `${command}: outage reading ${r.risk}`);
    }
    const benignOutage = outageRisk({ tool_name: 'Bash', tool_input: { command: 'patch -p1 < ok2.diff' }, cwd: sb.proj, truncated: false }, Date.now() + 60_000);
    want(benignOutage.risk !== 'high', `benign indented patch: outage reading ${benignOutage.risk}`);
    // the keyed (account) floor computes the same decision: watch returns null, and an advisory allow never lifts an enforced stop
    for (const command of ['git apply ind.diff', 'git apply idx.diff', 'git apply ren.diff']) {
      assert.equal(accountFloor('claude', { tool_name: 'Bash', tool_input: { command }, cwd: sb.proj, truncated: false }, Date.now() + 60_000), null, command);
    }
    const floor = sh('git apply ind.diff', { '/home/u/proj/ind.diff': FIRST + indent(' ', MCP_P1) });
    assert.equal(floor.decision, 'stop');
    assert.equal(accountFloorStops('on', floor, 'advisory_allow'), true);
    assert.equal(accountFloorStops('on', floor, 'enforced_allow'), false);
  } finally { sb.cleanup(); }
  // Keys: the command text only. Same text, two files that differ only in one indented header line: the same key and target, two decisions.
  const key = (command) => stableToolCorrelation({ session_id: 's1', tool_use_id: 't', tool_name: 'Bash', tool_input: { command } });
  const target = (command) => exactHookTarget({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command } });
  const okFile = FIRST + indent(' ', uni('a/src/x.ts', 'b/src/x.ts'));
  const badFile = FIRST + indent(' ', uni('a/.mcp.json', 'b/.mcp.json'));
  const fa = sh('git apply d.diff', { '/home/u/proj/d.diff': okFile });
  const fb = sh('git apply d.diff', { '/home/u/proj/d.diff': badFile });
  assert.equal(fa.decision, 'pass');
  assert.equal(fb.decision, 'stop');
  assert.equal(key('git apply d.diff'), key('git apply d.diff'));
  assert.equal(target('git apply d.diff'), target('git apply d.diff'));
  // a different file name or flag is a different key (as before), and neither key holds patch text
  for (const [x, y] of [['git apply d.diff', 'git apply e.diff'], ['git apply d.diff', 'git apply -p1 d.diff'], ['patch -p1 < d.diff', 'patch -p1 < e.diff'], ['git apply d.diff', 'cd .claude && git apply d.diff']]) {
    assert.notEqual(key(x), key(y), `${x} / ${y}`);
    assert.notEqual(target(x) + key(x), target(y) + key(y), `${x} / ${y}`);
  }
  for (const k of [key('git apply d.diff'), target('git apply d.diff')]) assert.ok(!String(k).includes('mcp.json') && !String(k).includes('src/x.ts'));
  // a secret in the text: text after the redacted span still differs; no secret reaches a reason code (dummy value generated here)
  const dummy = crypto.randomBytes(16).toString('hex');
  assert.notEqual(key(`API_KEY=${dummy} git apply d.diff`), key(`API_KEY=${dummy} git apply e.diff`));
  const withSecret = sh(`API_KEY=${dummy} git apply d.diff`, { '/home/u/proj/d.diff': badFile });
  assert.equal(withSecret.decision, 'stop');
  assert.ok(!JSON.stringify(withSecret).includes(dummy));
  // every reason of the new rows is a receipt-safe code
  const reasons = new Set([...fb.reasons, ...withSecret.reasons, ...sh('git apply odd.diff', { '/home/u/proj/odd.diff': `${FIRST}rename of x\n` }).reasons,
    ...sh('git apply odd.diff', { '/home/u/proj/odd.diff': `${FIRST}Index:\n` }).reasons]);
  assert.ok(reasons.size >= 3);
  for (const r of reasons) { assert.match(r, /^[a-z0-9_]{1,64}$/, r); assert.doesNotMatch(r, /settings|mcp|bashrc|claude|home|proj/); }
});

test('WK-5 patch 1 (consumers, real keyless hook): the new header forms stop S0 through the real hook CLI, Bash and Monitor; benign indented diffs pass; no network', () => {
  const sb = sandbox();
  try {
    const put = (rel, body) => fs.writeFileSync(path.join(sb.proj, rel), body);
    put('ind.diff', FIRST + indent(' ', MCP_P1));
    put('tab.diff', FIRST + indent('\t', SETTINGS_P1));
    put('x.diff', FIRST + indent('X', MCP_P1));
    put('idx.diff', `${FIRST}Index:.mcp.json\n${NORMAL}`);
    put('idxtab.diff', `${FIRST}Index:\t.claude/settings.json\n${NORMAL}`);
    put('ren.diff', moved('rename', 'old', 'new', '.mcp.json'));
    put('rens.diff', moved('rename', 'old', 'new', '.claude/settings.json'));
    put('ok2.diff', FIRST + indent(' ', uni('a/src/other.ts', 'b/src/other.ts')));
    put('okidx.diff', `${FIRST}Index:src/other.ts\n${NORMAL}`);
    for (const tool of ['Bash', 'Monitor']) {
      for (const command of ['patch -p1 < ind.diff', 'git apply ind.diff', 'patch -p1 < tab.diff', 'git apply x.diff', 'patch -p1 < idx.diff', 'git apply idxtab.diff', 'git apply ren.diff', 'patch -p1 -i rens.diff',
        'cd ~/proj && git apply ren.diff']) {
        const r = hook(sb, event(sb, tool, command));
        assert.equal(r.v, 'STOP_S0', `${tool}: ${command}: ${r.body || ''}`);
      }
      for (const command of ['patch -p1 < ok2.diff', 'git apply ok2.diff', 'patch -p1 < okidx.diff', 'git apply okidx.diff']) assert.equal(hook(sb, event(sb, tool, command)).v, 'pass', `${tool}: ${command}`);
    }
    assert.equal(fs.existsSync(sb.netspy) ? fs.readFileSync(sb.netspy, 'utf8') : '', '');
    const r = hook(sb, event(sb, 'Bash', 'git apply ren.diff'));
    assert.match(r.body, /Code: S0\.self_protection\/git_apply_write_protected_path/);
    assert.doesNotMatch(r.body, /mcp\.json|\.claude\/settings/);
  } finally { sb.cleanup(); }
});

test('patch-text (patch 1): the indent run, Index: and rename old|new in the pure reader', () => {
  const names = (t, mail = false) => text.readPatchNames(t, mail);
  for (const prefix of [' ', '    ', '\t', 'X', ' X\t X', 'XX']) {
    assert.deepEqual(names(indent(prefix, '--- a/x\n+++ b/x\n')).names, ['a/x', 'b/x'], JSON.stringify(prefix));
    assert.deepEqual(names(indent(prefix, '*** a/x\n--- b/x\n')).names, ['a/x', 'b/x'], JSON.stringify(prefix));
    assert.deepEqual(names(`${prefix}Index: x/y\n`).names, ['x/y'], JSON.stringify(prefix));
    assert.deepEqual(names(`${prefix}diff --git a/x b/y\n`).names.sort(), ['a/x', 'b/y'], JSON.stringify(prefix));
    assert.deepEqual(names(`${prefix}rename old x\n${prefix}rename new y\n`).names, ['x', 'y'], JSON.stringify(prefix));
    assert.equal(names(`${prefix}new file mode 120000\n--- a\n`).doubt, 'symlink_patch', JSON.stringify(prefix));
    assert.equal(names(`${prefix}==== //depot/x#1 ====\n`).doubt, 'perforce_header', JSON.stringify(prefix));
  }
  for (const head of ['Index:', 'Index:\t', 'Index: ', 'Index:  \t ']) assert.deepEqual(names(`${head}x/y\n`).names, ['x/y'], JSON.stringify(head));
  assert.deepEqual(names('rename old a\nrename new b\ncopy old c\ncopy new d\n').names, ['a', 'b', 'c', 'd']);
  assert.deepEqual(names('rename from a\nrename to b\ncopy from c\ncopy to d\n').names, ['a', 'b', 'c', 'd']);
  // only a leading run of space, tab and X is skipped: other bytes before a marker keep it from being a header
  for (const t of ['+--- a/x\n', '>--- a/x\n', '\f--- a/x\n', ' --- a/x\n', '#Index: x\n', '\u0000--- a/x\n', '﻿--- a/x\n']) assert.equal(names(t).doubt, 'no_headers', JSON.stringify(t));
  // doubts
  assert.equal(names('rename  from a\n').doubt, 'odd_move_header');
  assert.equal(names('rename\tfrom a\n').doubt, 'odd_move_header');
  assert.equal(names('rename x\n').doubt, 'odd_move_header');
  assert.equal(names(' copy of x\n').doubt, 'odd_move_header');
  assert.equal(names('Index:\n').doubt, 'empty_name');
  assert.equal(names('XIndex:  \n').doubt, 'empty_name');
  assert.equal(names('rename old \n').doubt, 'empty_name');
  assert.equal(names('  --- "a"\n').doubt, 'odd_name');
  assert.equal(names('rename_file(a)\n--- a/x\n').doubt, null);
  assert.equal(names('renamed old a\n--- a/x\n').doubt, null);
  assert.equal(names('copying from a\n--- a/x\n').doubt, null);
  // an indented transfer-encoding line of a mail is not a mail header: the mail rule is unchanged
  assert.equal(names('  Content-Transfer-Encoding: base64\n--- a/x\n', true).doubt, null);
  assert.equal(names('Content-Transfer-Encoding: base64\n--- a/x\n', true).doubt, 'encoded_mail_body');
  // long indent is fine, a long header after it is not
  assert.deepEqual(names(`${' '.repeat(100000)}--- a/x\n`).names, ['a/x']);
  assert.equal(names(`${' '.repeat(100)}--- ${'a'.repeat(5000)}\n`).doubt, 'long_header');
});

// ---------------------------------------------------------------------------------------------------------------------
// Patch round 2 (WK-5): MEDIUM-1 `git am` honours `format=flowed; delsp=yes` (and two more mail transforms the reader could not
// see), LOW-1 `git checkout` / `git restore` operands that are not one plain file name, LOW-2 the other readers keep their answers.

const MAIL_HEAD = 'From 0000000000000000000000000000000000000000 Mon Sep 17 00:00:00 2001\nFrom: A <a@example.invalid>\nDate: Mon, 1 Jan 2024 00:00:00 +0000\nSubject: [PATCH] x\n';
const CT_FLOWED = 'Content-Type: text/plain; charset=UTF-8; format=flowed; delsp=yes\nContent-Transfer-Encoding: 8bit\n';
const mailStat = (n) => `---\n ${n} | 2 +-\n 1 file changed, 1 insertion(+), 1 deletion(-)\n\n`;
const HUNK = '@@ -1 +1 @@\n-one\n+two\n';
const SIGN = '-- \n2.43.0\n\n';
const mailOf = (headers, body) => `${MAIL_HEAD}${headers}\n${body}`;
const SET_NAME = '.claude/settings.json';
// Names split over two mail lines: each first line ends in a space, which git joins (and drops) when the mail is flowed with delsp.
const SPLIT_CLA = `--- a/.cla \nude/settings.json\n+++ b/.cla \nude/settings.json\n${HUNK}`;
const SPLIT_A = `--- a/ \n${SET_NAME}\n+++ b/ \n${SET_NAME}\n${HUNK}`;
const SPLIT_GIT = `diff --git a/.cla \nude/settings.json b/${SET_NAME}\n--- a/${SET_NAME}\n+++ b/${SET_NAME}\n${HUNK}`;
const MBOX = '/home/u/proj/m.mbox';
const amStops = (text, why, id) => {
  const d = sh('git am m.mbox', { [MBOX]: text });
  want(d.decision === 'stop' && d.category === 'S0' && d.reasons.includes(`git_am_write_unknown_header_${why}`), `${id}: want git_am_write_unknown_header_${why}, got ${d.decision}/${d.category} [${d.reasons}]`);
};
const amPasses = (text, id) => {
  const d = sh('git am m.mbox', { [MBOX]: text });
  want(d.decision === 'pass' && d.category === 'none', `${id}: want pass, got ${d.decision}/${d.category} [${d.reasons}]`);
};

test('WK-5 patch 2 (MEDIUM-1): a format=flowed mail is an unknown write, in every spelling real git am reads (soft-broken header names are joined by git, not by the reader)', () => {
  const body = (split) => `${mailStat(SET_NAME)}${split}${SIGN}`;
  const rows = [
    ['audit row: traditional ---/+++ split after .cla', mailOf(CT_FLOWED, body(SPLIT_CLA))],
    ['audit row: split after a/', mailOf(CT_FLOWED, body(SPLIT_A))],
    ['audit row: lower-case header, FORMAT=Flowed; DelSp=Yes', mailOf('content-type: text/plain; charset=UTF-8; FORMAT=Flowed; DelSp=Yes\ncontent-transfer-encoding: 8bit\n', body(SPLIT_CLA))],
    ['audit row: diff --git line split', mailOf(CT_FLOWED, `${mailStat(SET_NAME)}${SPLIT_GIT}${SIGN}`)],
    ['flowed without delsp', mailOf('Content-Type: text/plain; charset=UTF-8; format=flowed\n', body(SPLIT_CLA))],
    ['folded Content-Type (space)', mailOf('Content-Type: text/plain; charset=UTF-8;\n format=flowed;\n delsp=yes\n', body(SPLIT_CLA))],
    ['folded Content-Type (tab)', mailOf('Content-Type: text/plain; charset=UTF-8;\n\tformat=flowed;\tdelsp=yes\n', body(SPLIT_CLA))],
    ['quoted values', mailOf('Content-Type: text/plain; charset="UTF-8"; format="flowed"; delsp="yes"\n', body(SPLIT_CLA))],
    ['mixed case', mailOf('CONTENT-TYPE: TEXT/PLAIN; FoRmAt=FlOwEd; DeLsP=YeS\n', body(SPLIT_CLA))],
    ['MIME part header only', mailOf('MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="BB"\n', `--BB\n${CT_FLOWED}\n${body(SPLIT_CLA)}--BB--\n`)],
    ['second MIME part', mailOf('MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="BB"\n', `--BB\nContent-Type: text/plain\n\nhello\n--BB\nContent-Type: text/x-patch; format=flowed; delsp=yes\n\n${body(SPLIT_CLA)}--BB--\n`)],
    ['second message of the mbox', `${mailOf('', `${mailStat('ok.txt')}${OK_P1}${SIGN}`)}\n${mailOf(CT_FLOWED, body(SPLIT_CLA))}`],
    ['CRLF mail', mailOf(CT_FLOWED, body(SPLIT_CLA)).replace(/\n/g, '\r\n')],
    ['space-stuffed and split', mailOf(CT_FLOWED, `${mailStat(SET_NAME)} --- a/.cla \nude/settings.json\n +++ b/.cla \nude/settings.json\n${HUNK}${SIGN}`)],
    ['names not split at all (the flowed word is enough)', mailOf(CT_FLOWED, `${mailStat(SET_NAME)}${uni(`a/${SET_NAME}`, `b/${SET_NAME}`)}${SIGN}`)],
    // new friction: a flowed mail that names only ordinary files holds too (git format-patch never writes one)
    ['NEW FRICTION: flowed mail naming only an ordinary file', mailOf(CT_FLOWED, `${mailStat('src/index.ts')}${OK_P1}${SIGN}`)],
    // over-hold: the words anywhere in a mail (reason is the same)
    ['over-hold: the words in the commit message', mailOf('', `see format=flowed here\n${mailStat('src/index.ts')}${OK_P1}${SIGN}`)],
    ['over-hold: the words in a hunk line', mailOf('', `${mailStat('src/index.ts')}${OK_P1.replace('-one', '-format=flowed')}${SIGN}`)],
    ['over-hold: blanks around the equals sign', mailOf('Content-Type: text/plain; format = flowed; delsp = yes\n', `${mailStat('src/index.ts')}${OK_P1}${SIGN}`)],
  ];
  for (const [id, text] of rows) amStops(text, 'flowed_mail_body', id);
  // the plain mbox naming a protected file (control) still stops on the protected path itself
  const plain = mailOf('', `${mailStat(SET_NAME)}${uni(`a/${SET_NAME}`, `b/${SET_NAME}`)}${SIGN}`);
  const d = sh('git am m.mbox', { [MBOX]: plain });
  want(d.decision === 'stop' && d.reasons.includes('git_am_write_protected_path'), `plain mbox: ${d.decision} [${d.reasons}]`);
  // plain mail with the split names and no flowed word: git does not join them, so there is nothing hidden (names read as written)
  amPasses(mailOf('', body(SPLIT_CLA)), 'split names in a plain mail');
  // benign mails that git format-patch writes keep passing: plain, 8bit with a charset, encoded words in From / Subject (also folded)
  const benignBody = `${mailStat('src/index.ts')}${OK_P1}${SIGN}`;
  amPasses(mailOf('', benignBody), 'plain benign mail');
  amPasses(mailOf('MIME-Version: 1.0\nContent-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 8bit\n', benignBody), 'charset + 8bit');
  amPasses(mailOf('Content-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 7bit\n', benignBody), '7bit');
  amPasses(mailOf('', benignBody).replace('From: A', 'From: =?UTF-8?q?J=C3=BCrgen?='), 'encoded From');
  amPasses(mailOf('', benignBody).replace('Subject: [PATCH] x', 'Subject: =?UTF-8?q?[PATCH]_x=C3=A9?=\n =?UTF-8?q?_more=C3=A9?='), 'folded encoded Subject');
  amPasses(mailOf('Content-Type: text/plain\n', benignBody).replace('Subject: [PATCH] x', 'Subject: s\n =?UTF-8?q?x?='), 'folded encoded Subject, then a plain Content-Type');
  // the flowed rule belongs to git am only: patch and git apply do not decode mail
  const flowedFile = { '/home/u/proj/fl.mbox': mailOf(CT_FLOWED, benignBody) };
  passes('git apply fl.mbox', flowedFile);
  passes('patch -p1 < fl.mbox', flowedFile);
  // a second git am on the same line reads its own mailbox, in every shell form
  const two = { [MBOX]: mailOf(CT_FLOWED, body(SPLIT_CLA)), '/home/u/proj/okm.mbox': mailOf('', benignBody) };
  for (const command of ['git am okm.mbox && git am m.mbox', 'git am okm.mbox m.mbox', 'git am okm.mbox; git am m.mbox', '(git am okm.mbox; git am m.mbox)', "bash -c 'git am okm.mbox; git am m.mbox'", 'git am okm.mbox || git am m.mbox']) {
    const d = sh(command, two);
    want(d.decision === 'stop' && d.category === 'S0' && d.reasons.includes('git_am_write_unknown_header_flowed_mail_body'), `${command}: want the flowed doubt, got ${d.decision} [${d.reasons}]`);
  }
  passes('git am okm.mbox && git am okm.mbox', two);
});

test('WK-5 patch 2 (MEDIUM-1, found by the security pass): git am also decodes RFC 2047 encoded words in Content-Type and finds base64 or quoted-printable anywhere in a Content-Transfer-Encoding value', () => {
  const split = `${mailStat(SET_NAME)}${SPLIT_CLA}${SIGN}`;
  const real = Buffer.from(`${mailStat(SET_NAME)}${uni(`a/${SET_NAME}`, `b/${SET_NAME}`)}${SIGN}`).toString('base64').replace(/(.{76})/g, '$1\n') + '\n';
  const decoy = uni('a/ok.txt', 'b/ok.txt');
  const q = '=?utf-8?q?text/plain=3B_format=3Dflowed=3B_delsp=3Dyes?=';
  const rows = [
    ['Q encoded word is the whole Content-Type', mailOf(`Content-Type: ${q}\n`, split), 'encoded_mail_header'],
    ['B encoded word is the whole Content-Type', mailOf(`Content-Type: =?utf-8?b?${Buffer.from('text/plain; format=flowed; delsp=yes').toString('base64')}?=\n`, split), 'encoded_mail_header'],
    ['encoded word holds format=flowed only', mailOf('Content-Type: text/plain; =?utf-8?q?format=3Dflowed?=; delsp=yes\n', split), 'encoded_mail_header'],
    ['encoded word on a folded line', mailOf('Content-Type: text/plain;\n =?utf-8?q?format=3Dflowed=3B?=\n delsp=yes\n', split), 'encoded_mail_header'],
    ['value starts on the folded line', mailOf(`Content-Type:\n ${q}\n`, split), 'encoded_mail_header'],
    ['encoded word in a MIME part header', mailOf('MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="BB"\n', `--BB\nContent-Type: ${q}\n\n${split}--BB--\n`), 'encoded_mail_header'],
    ['upper-case header and encoded word', mailOf('CONTENT-TYPE: =?UTF-8?Q?text/plain=3B_FORMAT=3DFlowed=3B_DelSp=3DYes?=\n', split), 'encoded_mail_header'],
    ['Content-Transfer-Encoding: 7bit base64 (real patch in base64, plain decoy)', mailOf('Content-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 7bit base64\n', `${real}${decoy}`), 'encoded_mail_body'],
    ['Content-Transfer-Encoding: 7bit; x=base64', mailOf('Content-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 7bit; x=base64\n', `${real}${decoy}`), 'encoded_mail_body'],
    ['Content-Transfer-Encoding folded: 7bit, then base64', mailOf('Content-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 7bit\n base64\n', `${real}${decoy}`), 'encoded_mail_body'],
    ['Content-Transfer-Encoding folded: 8bit, then quoted-printable', mailOf('Content-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 8bit\n quoted-printable\n', `${mailStat(SET_NAME)}--- a/.cla=\nude/settings.json\n+++ b/.cla=\nude/settings.json\n${HUNK}${SIGN}${decoy}`), 'encoded_mail_body'],
    ['Content-Transfer-Encoding upper case', mailOf('Content-Type: text/plain; charset=UTF-8\nCONTENT-TRANSFER-ENCODING: 7BIT BaSe64\n', `${real}${decoy}`), 'encoded_mail_body'],
    ['Content-Transfer-Encoding in a MIME part', mailOf('MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="BB"\n', `--BB\nContent-Type: text/plain\nContent-Transfer-Encoding: 7bit base64\n\n${real}${decoy}--BB--\n`), 'encoded_mail_body'],
  ];
  for (const [id, text, why] of rows) amStops(text, why, id);
  // the encoded word as the transfer encoding and the old rows (first token not plain) are doubts as before
  const ew = sh('git am m.mbox', { [MBOX]: mailOf('Content-Type: text/plain\nContent-Transfer-Encoding: =?utf-8?q?base64?=\n', `${real}${decoy}`) });
  want(ew.decision === 'stop' && ew.reasons.some((r) => r.startsWith('git_am_write_unknown_header_encoded_mail_')), `encoded-word transfer encoding: ${ew.decision} [${ew.reasons}]`);
  for (const enc of ['base64', 'quoted-printable', 'BASE64', 'x-uuencode']) {
    amStops(mailOf(`Content-Type: text/plain\nContent-Transfer-Encoding: ${enc}\n`, `${real}${decoy}`), 'encoded_mail_body', enc);
  }
  // RFC 2231 style parameters and a Content-Type with no encoded word are not decoded by git: no new hold
  amPasses(mailOf('Content-Type: text/plain; charset=UTF-8; name="a.patch"\n', `${mailStat('src/index.ts')}${OK_P1}${SIGN}`), 'plain Content-Type with parameters');
});

test('patch-text (patch 2): the mail-only doubts of the pure reader', () => {
  const names = (t, mail = true) => text.readPatchNames(t, mail);
  const diff = '--- a/x\n+++ b/x\n';
  for (const header of ['Content-Type: text/plain; format=flowed', 'Content-Type: text/plain; format=flowed; delsp=yes', 'content-type: text/plain; FORMAT=Flowed; DelSp=Yes',
    'Content-Type: text/plain; format="flowed"', 'Content-Type: text/plain; format = flowed', 'Content-Type: text/plain;\n format=flowed', 'Content-Type: text/plain;\n\tformat=flowed',
    'X-Other: 1\n format=flowed', 'format=flowed', 'FORMAT=FLOWED', 'Content-Type: text/plain; format=flowedX']) {
    assert.equal(names(`${header}\n\n${diff}`).doubt, 'flowed_mail_body', JSON.stringify(header));
    assert.equal(names(`${header}\n\n${diff}`, false).doubt, null, `${JSON.stringify(header)} without mail mode`);
  }
  // CRLF, and the flowed word on a line that also looks like a header
  assert.equal(names(`Content-Type: text/plain; format=flowed\r\n\r\n${diff}`).doubt, 'flowed_mail_body');
  assert.equal(names('--- a/x format=flowed\n+++ b/x\n').doubt, 'flowed_mail_body');
  assert.equal(names(`${diff}+format=flowed\n`).doubt, 'flowed_mail_body');
  // a flowed word after real names does not drop them (the call is a doubt, so they are not used, but the reader stays total)
  assert.deepEqual(names(`${diff}Content-Type: text/plain; format=flowed\n`).names.sort(), ['a/x', 'b/x']);
  // no flowed word: unchanged
  for (const header of ['Content-Type: text/plain; charset=UTF-8', 'Content-Type: text/plain; format=fixed', 'Content-Type: text/plain; formatted=flowing', 'Content-Type: text/plain; reformat=yes; flow=ed']) {
    assert.equal(names(`${header}\n\n${diff}`).doubt, null, JSON.stringify(header));
  }
  // an encoded word in Content-Type (any line of that header), or base64 / quoted-printable anywhere in a Content-Transfer-Encoding value
  for (const header of ['Content-Type: =?utf-8?q?text/plain?=', 'content-type: text/plain; =?UTF-8?B?Zm9ybWF0PWZsb3dlZA==?=', 'Content-Type: text/plain;\n =?utf-8?q?format=3Dflowed?=',
    'Content-Type:\n =?utf-8?q?x?=\n charset=UTF-8']) {
    assert.equal(names(`${header}\n\n${diff}`).doubt, 'encoded_mail_header', JSON.stringify(header));
    assert.equal(names(`${header}\n\n${diff}`, false).doubt, null);
  }
  for (const header of ['Content-Transfer-Encoding: base64', 'Content-Transfer-Encoding: 7bit base64', 'Content-Transfer-Encoding: 7bit; x=base64', 'Content-Transfer-Encoding: 7bit\n base64',
    'CONTENT-TRANSFER-ENCODING: 8bit BASE64', 'Content-Transfer-Encoding: 8bit\n\tquoted-printable', 'Content-Transfer-Encoding: quoted-printable']) {
    assert.equal(names(`${header}\n\n${diff}`).doubt, 'encoded_mail_body', JSON.stringify(header));
    assert.equal(names(`${header}\n\n${diff}`, false).doubt, null);
  }
  assert.equal(names(`Content-Transfer-Encoding: =?utf-8?q?base64?=\n\n${diff}`).doubt, 'encoded_mail_header');
  assert.equal(names(`Content-Transfer-Encoding: x-uuencode\n\n${diff}`).doubt, 'encoded_mail_body');
  // headers git format-patch writes keep reading: encoded words in other headers (also folded), charset, 7bit / 8bit
  for (const t of ['From: =?UTF-8?q?J=C3=BCrgen?= <a@example.invalid>\nSubject: =?UTF-8?q?x?=\n =?UTF-8?q?y?=\nContent-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 8bit\n\n',
    'Subject: s\n =?UTF-8?q?x?=\nContent-Transfer-Encoding: 7bit\n\n', 'MIME-Version: 1.0\nContent-Type: text/plain; charset=UTF-8; name="a.patch"\n\n']) {
    assert.deepEqual(names(`${t}${diff}`), { names: ['a/x', 'b/x'], doubt: null }, JSON.stringify(t));
  }
  // an indented hunk line is not a mail header, even when it starts with a header word and holds an encoded-looking text
  assert.equal(names(`Subject: s\n\n${diff}@@ -1 +1 @@\n Content-Type: x =?a?b?c?=\n`).doubt, null);
});

// ---- LOW-1: a git checkout / git restore operand that is not one plain file name may rewrite the patch file after it was read
const LOW1_FILES = {
  '/home/u/proj/p.diff': OK_P1,
  '/home/u/proj/q.diff': OK_P1,
  '/home/u/proj/other.txt': 'x\n',
  '/home/u/proj/patches/p.diff': OK_P1,
  '/home/u/proj/sub/p.diff': OK_P1,
  '/home/u/proj/list': 'p.diff\n',
  '/home/u/proj/p.mbox': FILES['/home/u/proj/ok.mbox'],
  '/home/u/q.diff': OK_P1,
  '/home/u/proj/-x.diff': OK_P1,
};

test('WK-5 patch 2 (LOW-1): an operand of git checkout / git restore that is a folder, a glob, a variable, a substitution or a pathspec file makes any later patch read on the line an unknown write', () => {
  for (const [kind, command] of [
    // the six rows of the brief
    ['apply', 'git checkout main -- . && git apply p.diff'],
    ['patch', 'git checkout main -- patches && patch -p1 < patches/p.diff'],
    ['apply', 'git checkout -- *.diff && git apply p.diff'],
    ['apply', "git checkout -- '*.diff' && git apply p.diff"],
    ['apply', 'git checkout --pathspec-from-file=list && git apply p.diff'],
    ['apply', 'git checkout -- $(cat list) && git apply p.diff'],
    // folders
    ['apply', 'git restore . && git apply p.diff'],
    ['patch', 'git checkout -- patches/ && patch -p1 < patches/p.diff'],
    ['patch', 'git checkout -- ./patches && patch -p1 < ./patches/../patches/p.diff'],
    ['apply', 'cd sub && git checkout -- . && cd .. && git apply sub/p.diff'],
    ['apply', 'git -C sub checkout -- . && git apply sub/p.diff'],
    ['apply', 'git checkout -- /home/u/proj && git apply p.diff'],
    ['apply', 'git checkout -- ~/proj && git apply p.diff'],
    ['apply', 'git checkout -- .. && git apply p.diff'],
    ['apply', 'git checkout -- / && git apply p.diff'],
    // globs, quoted globs, brace and class forms, escapes, empty word, pathspec magic
    ['apply', 'git checkout -- p.di?? && git apply p.diff'],
    ['apply', 'git checkout -- p.di[f]f && git apply p.diff'],
    ['apply', "git checkout -- '{p,q}.diff' && git apply p.diff"],
    ['apply', 'git checkout -- {p,q}.diff && git apply p.diff'],
    ['apply', "git checkout -- 'p.di\\f' && git apply p.diff"],
    ['apply', "git checkout -- '' && git apply p.diff"],
    ['apply', "git checkout -- '' && git apply ../q.diff"],
    ['apply', "git checkout -- ':/' && git apply p.diff"],
    ['apply', "git checkout -- ':(glob)**/*.diff' && git apply p.diff"],
    ['apply', "git checkout -- ':!other.txt' && git apply p.diff"],
    // after a bare `--` every word is a path, even one that starts with a dash
    ['apply', 'git checkout main -- -x.diff && git apply -- -x.diff'],
    ['patch', 'git checkout main -- -x.diff && patch -p1 -i -x.diff'],
    ['apply', 'git restore -- -x.diff && git apply -- -x.diff'],
    // the operands come from a pipe, find -exec or a substitution
    ['apply', 'echo p.diff | xargs git checkout -- && git apply p.diff'],
    ['apply', "find . -name '*.diff' -exec git checkout -- {} \\; && git apply p.diff"],
    ['apply', 'git ls-files | xargs git checkout -- && git apply p.diff'],
    ['apply', 'git checkout -- $(git ls-files) && git apply p.diff'],
    ['apply', 'for f in p.diff q.diff; do git checkout -- "$f"; done; git apply p.diff'],
    // variables and substitutions
    ['apply', 'git checkout -- "$F" && git apply p.diff'],
    ['apply', 'git checkout -- ${F} && git apply p.diff'],
    ['apply', 'git checkout -- `cat list` && git apply p.diff'],
    // the pathspec file, any spelling git reads
    ['apply', 'git restore --pathspec-from-file list && git apply p.diff'],
    ['patch', 'git restore --pathspec-from-file=list && patch -p1 < p.diff'],
    ['apply', 'git restore --pathspec-from=list && git apply p.diff'],
    ['apply', 'git restore --path=list && git apply p.diff'],
    ['am', 'git checkout --pathspec-from-file list && git am p.mbox'],
    // every shell form carries the mark to the later read
    ['apply', '(git checkout -- .) && git apply p.diff'],
    ['apply', 'git checkout -- . ; git apply p.diff'],
    ['apply', 'git checkout -- . || git apply p.diff'],
    ['apply', 'git checkout -- . | cat; git apply p.diff'],
    ['apply', "bash -c 'git checkout -- . && git apply p.diff'"],
    ['apply', "git checkout -- . && bash -c 'git apply p.diff'"],
    ['apply', 'git checkout -- . && git apply p.diff q.diff'],
    ['apply', 'git checkout -- . && git apply -p1 --directory=sub p.diff'],
    ['am', 'git checkout -- . && git am p.mbox'],
  ]) stopsUnknown(kind, command, 'written_here', LOW1_FILES);
  // controls: a plain file name that is not the patch file, a ref, a branch switch, an index-only restore, a read-only apply, apply first
  for (const command of [
    'git checkout -- other.txt && git apply p.diff',
    'git checkout HEAD -- other.txt && patch -p1 < p.diff',
    'git restore other.txt && git apply p.diff',
    'git checkout feat/x && git apply p.diff',
    'git checkout main && git apply p.diff',
    'git checkout -b feat && git apply p.diff',
    'git checkout -- patches && git apply p.diff',
    'git checkout -- sub && git apply patches/p.diff',
    'git checkout -- src/index.ts',
    'git restore --staged other.txt && git apply p.diff',
    'git restore --staged --pathspec-from-file=list && git apply p.diff',
    'git restore --source=HEAD~1 other.txt && git apply p.diff',
    'git restore --source=$REF other.txt && git apply p.diff',
    'git -C sub restore . && git apply p.diff',
    'git checkout -- . && git apply --check p.diff',
    'git checkout -- . && git apply ../q.diff',
    'git apply p.diff && git checkout -- .',
    'git checkout -- other.txt && git apply sub/p.diff',
  ]) passes(command, LOW1_FILES);
});

test('WK-5 patch 2 (LOW-1, new friction): a variable or substitution among the words of git checkout / git restore holds a later apply, even a branch name', () => {
  for (const command of ['git checkout "$BRANCH" && git apply p.diff', 'git checkout -b "$BRANCH" && git apply p.diff', 'git checkout $(git rev-parse HEAD) && git apply p.diff']) {
    stopsUnknown('apply', command, 'written_here', LOW1_FILES);
  }
});

// ---- LOW-2: only the patch readers look at the checked-out names. Putting them into the shared `ctx.written` would loosen these five
const LOW2_FILES = {
  '/home/u/proj/bad.sh': 'git push --force origin main\n',
  '/home/u/proj/good.sh': 'echo hi\n',
  '/home/u/proj/package.json': JSON.stringify({ scripts: { y: 'git push --force origin main', z: 'echo hi' } }),
  '/home/u/proj/Makefile': 'bad:\n\tgit push --force origin main\ngood:\n\techo hi\n',
};

test('WK-5 patch 2 (LOW-2): checkout and restore operands never loosen the script, package.json and Makefile readers (the shared written set is not used)', () => {
  for (const command of [
    'git checkout -- bad.sh && bash bad.sh',
    'git checkout -- package.json && npm run y',
    'git restore package.json && npm run y',
    'git checkout -- Makefile && make bad',
    'git restore Makefile && make bad',
    // the whole-line mark (a folder, a glob) does not reach them either
    'git checkout -- . && bash bad.sh',
    'git checkout -- . && npm run y',
    'git checkout -- . && make bad',
    'git checkout -- *.sh && bash bad.sh',
    'git restore . && ./bad.sh',
  ]) {
    const d = sh(command, LOW2_FILES);
    want(d.decision === 'stop' && d.reasons.includes('git_push_force_protected_branch'), `${command}: want the force-push stop of the script, got ${d.decision} [${d.reasons}]`);
  }
  // the same answer with and without the checkout in front, for every reader
  for (const [withCheckout, without] of [
    ['git checkout -- bad.sh && bash bad.sh', 'true && bash bad.sh'], ['git checkout -- package.json && npm run y', 'true && npm run y'],
    ['git restore package.json && npm run y', 'true && npm run y'], ['git checkout -- Makefile && make bad', 'true && make bad'], ['git restore Makefile && make bad', 'true && make bad'],
    ['git checkout -- good.sh && bash good.sh', 'true && bash good.sh'], ['git checkout -- . && npm run z', 'true && npm run z'], ['git restore Makefile && make good', 'true && make good'],
    ['git checkout -- *.sh && bash good.sh', 'true && bash good.sh'],
  ]) {
    const a = sh(withCheckout, LOW2_FILES);
    const b = sh(without, LOW2_FILES);
    want(a.decision === b.decision && a.category === b.category && a.reasons.join() === b.reasons.join(), `${withCheckout}: [${a.decision} ${a.reasons}] differs from [${b.decision} ${b.reasons}]`);
  }
  for (const command of ['git checkout -- good.sh && bash good.sh', 'git checkout -- package.json && npm run z', 'git restore Makefile && make good', 'git checkout -- . && bash good.sh', 'git checkout -- . && make good']) passes(command, LOW2_FILES);
});

test('WK-5 patch 2 (consumers, mapper level): the outage reading is high for the new stops, benign rows stay not high, and held-call keys come from the command text only', () => {
  const { outageRisk } = require('../dist/seatbelt/hook.js');
  const { stableToolCorrelation, exactHookTarget } = require('../dist/hook-contract.js');
  const sb = sandbox();
  try {
    const put = (rel, body) => { fs.mkdirSync(path.dirname(path.join(sb.proj, rel)), { recursive: true }); fs.writeFileSync(path.join(sb.proj, rel), body); };
    put('fl.mbox', mailOf(CT_FLOWED, `${mailStat(SET_NAME)}${SPLIT_CLA}${SIGN}`));
    put('flok.mbox', mailOf(CT_FLOWED, `${mailStat('src/index.ts')}${OK_P1}${SIGN}`));
    put('enc.mbox', mailOf('Content-Type: =?utf-8?q?text/plain=3B_format=3Dflowed?=\n', `${mailStat(SET_NAME)}${SPLIT_CLA}${SIGN}`));
    put('okm.mbox', mailOf('', `${mailStat('src/index.ts')}${OK_P1}${SIGN}`));
    put('patches/ok.diff', OK_P1);
    const outage = (command) => outageRisk({ tool_name: 'Bash', tool_input: { command }, cwd: sb.proj, truncated: false }, Date.now() + 60_000).risk;
    for (const command of ['git am fl.mbox', 'git am flok.mbox', 'git am enc.mbox', 'git checkout main -- . && git apply ok.diff', 'git checkout -- *.diff && git apply ok.diff',
      'git checkout main -- patches && patch -p1 < patches/ok.diff']) {
      want(outage(command) === 'high', `${command}: outage reading ${outage(command)}`);
    }
    // (a benign git row reads high here for want of a passwd home: the git config cannot be named in this process, as on master; the benign git rows are measured in the evidence run)
    for (const command of ['patch -p1 < ok.diff', 'patch -p1 < patches/ok.diff']) want(outage(command) !== 'high', `${command}: outage reading ${outage(command)}`);
  } finally { sb.cleanup(); }
  const key = (command) => stableToolCorrelation({ session_id: 's1', tool_use_id: 't', tool_name: 'Bash', tool_input: { command } });
  const target = (command) => exactHookTarget({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command } });
  for (const [x, y] of [['git am a.mbox', 'git am b.mbox'], ['git checkout -- . && git apply p.diff', 'git checkout -- . && git apply q.diff'],
    ['git checkout -- *.diff && git apply p.diff', 'git checkout -- *.diff && git apply q.diff'], ['git checkout -- . && git apply p.diff', 'git checkout -- patches && git apply p.diff']]) {
    assert.notEqual(key(x), key(y), `${x} / ${y}`);
    assert.notEqual(target(x) + key(x), target(y) + key(y), `${x} / ${y}`);
  }
  const dummy = crypto.randomBytes(16).toString('hex');
  assert.notEqual(key(`API_KEY=${dummy} git am a.mbox`), key(`API_KEY=${dummy} git am b.mbox`));
  const withSecret = sh(`API_KEY=${dummy} git am m.mbox`, { [MBOX]: mailOf(CT_FLOWED, `${mailStat(SET_NAME)}${SPLIT_CLA}${SIGN}`) });
  assert.equal(withSecret.decision, 'stop');
  assert.ok(!JSON.stringify(withSecret).includes(dummy));
  for (const r of new Set([...withSecret.reasons, ...sh('git am m.mbox', { [MBOX]: mailOf('Content-Type: =?utf-8?q?x?=\n', `${mailStat('a')}${OK_P1}`) }).reasons])) {
    assert.match(r, /^[a-z0-9_]{1,64}$/, r);
    assert.doesNotMatch(r, /settings|mcp|bashrc|claude|home|proj/);
  }
});

test('WK-5 patch 2 (consumers, real keyless hook): a flowed mail and the checkout rows stop S0 through the real hook CLI, Bash and Monitor; benign rows pass; no network', () => {
  const sb = sandbox();
  try {
    const put = (rel, body) => fs.writeFileSync(path.join(sb.proj, rel), body);
    put('fl.mbox', mailOf(CT_FLOWED, `${mailStat(SET_NAME)}${SPLIT_CLA}${SIGN}`));
    put('flok.mbox', mailOf(CT_FLOWED, `${mailStat('src/index.ts')}${OK_P1}${SIGN}`));
    put('enc.mbox', mailOf('Content-Type: =?utf-8?q?text/plain=3B_format=3Dflowed=3B_delsp=3Dyes?=\n', `${mailStat(SET_NAME)}${SPLIT_CLA}${SIGN}`));
    put('okm.mbox', mailOf('Content-Transfer-Encoding: 8bit\nContent-Type: text/plain; charset=UTF-8\n', `${mailStat('src/index.ts')}${OK_P1}${SIGN}`));
    for (const tool of ['Bash', 'Monitor']) {
      for (const command of ['git am fl.mbox', 'git am flok.mbox', 'git am enc.mbox', 'git checkout main -- . && git apply ok.diff', 'git checkout -- *.diff && patch -p1 < ok.diff']) {
        const r = hook(sb, event(sb, tool, command));
        assert.equal(r.v, 'STOP_S0', `${tool}: ${command}: ${r.body || ''}`);
      }
      for (const command of ['git am okm.mbox', 'git checkout -- other.txt && git apply ok.diff', 'git restore --staged src/index.ts && git apply ok.diff']) assert.equal(hook(sb, event(sb, tool, command)).v, 'pass', `${tool}: ${command}`);
    }
    assert.equal(fs.existsSync(sb.netspy) ? fs.readFileSync(sb.netspy, 'utf8') : '', '');
    const r = hook(sb, event(sb, 'Bash', 'git am fl.mbox'));
    assert.match(r.body, /Code: S0\.self_protection\/git_am_write_unknown_header_flowed_mail_body/);
    assert.doesNotMatch(r.body, /\.claude\/settings/);
    const r2 = hook(sb, event(sb, 'Bash', 'git checkout main -- . && git apply ok.diff'));
    assert.match(r2.body, /Code: S0\.self_protection\/git_apply_write_unknown_written_here/);
  } finally { sb.cleanup(); }
});
