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
