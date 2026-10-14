'use strict';

// Patch round 3 (delta audit F-OPT): the seatbelt parsers read a long option only on an exact match with a fixed
// list. GNU tools (and git, curl, wget) accept a long option shortened to a unique prefix, so `cp --targ=DIR src`
// writes into DIR while a parser that only knows `--target-directory` read it as "no target". A fixed table, not a
// search: for each parser one row with the option spelled exactly (today's answer), one with it cut to its first 4
// letters, and one with a made-up `--zz-unknown`. The last two must give the strict answer for an S0 target: the
// Marrow plugins folder, ~/.claude/settings.json and the npx copy. Mapper rows run the three targets; hook rows run
// the real hook CLI keyless on the 7 host paths (plus Grok's fixed denial).
// Also in this file: the friction narrowings of the same round (tree, prettier --check, tar/zip create), the awk
// program-text writers (F-AWK) and the Codex hook file on every host (F-CODEX).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync, execFileSync } = require('node:child_process');

const { evaluateSeatbelt } = require('../dist/seatbelt/mapper.js');
const L = require('../dist/seatbelt/longopts.js');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const PRELOAD = path.join(__dirname, 'support', 'seatbelt-hook-preload.cjs');

const HOOKS = { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'npx -y --package=@getmarrow/mcp@3.9.103 marrow-mcp claude-pre-action-hook' }] }] };
const FILES = {
  '/home/u/.claude/settings.json': JSON.stringify({ hooks: HOOKS }, null, 2),
  '/home/u/.claude/plugins/installed_plugins.json': '{"version":2,"plugins":{}}',
  '/home/u/.claude/plugins/cache/getmarrow/marrow/1.2.3/scripts/marrow-launch.cjs': 'module.exports = 1;\n',
  '/home/u/.npm/_npx/abc123/node_modules/@getmarrow/mcp/dist/cli.js': 'module.exports = 1;\n',
  '/home/u/.codex/hooks.json': JSON.stringify({ hooks: HOOKS }, null, 2),
  '/home/u/.bashrc': '# rc\n',
};
const DIRS = ['/home/u/.claude', '/home/u/.claude/plugins/cache/getmarrow/marrow', '/home/u/.npm/_npx/abc123/node_modules/@getmarrow', '/home/u/.codex'];
const sh = (command) => evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command } }, makeEnv({ files: FILES, dirs: DIRS }));

// The three S0 targets: a file and a folder that holds it. {A} is the file's absolute path (for awk program text).
const TARGETS = [
  { name: 'settings', T: '~/.claude/settings.json', D: '~/.claude', A: '/home/u/.claude/settings.json' },
  { name: 'plugins', T: '~/.claude/plugins/cache/getmarrow/marrow/1.2.3/scripts/marrow-launch.cjs', D: '~/.claude/plugins/cache/getmarrow/marrow', A: '/home/u/.claude/plugins/cache/getmarrow/marrow/1.2.3/scripts/marrow-launch.cjs' },
  { name: 'npx copy', T: '~/.npm/_npx/abc123/node_modules/@getmarrow/mcp/dist/cli.js', D: '~/.npm/_npx/abc123/node_modules/@getmarrow', A: '/home/u/.npm/_npx/abc123/node_modules/@getmarrow/mcp/dist/cli.js' },
];
const fill = (cmd, t, home) => cmd.replace(/\{T\}/g, t.T).replace(/\{D\}/g, t.D).replace(/\{A\}/g, home ? t.A.replace('/home/u', home) : t.A);

// ------------------------------------------------------------------------------------------------
// The fixed table. exact: the option spelled in full (the answer it had before this round); short: the option cut to
// its first 4 letters; unk: a made-up `--zz-unknown`. Both of the last two must stop (S0).
// `reasons` names a reason code the strict row must carry (the parser under test stopped it, not another rule).
const PARSERS = [
  // cpDestination
  { parser: 'cpDestination (source read)', exact: ['cp --reflink=auto {T} /tmp/p3-dst', 'pass'], short: 'cp --refl=auto {T} /tmp/p3-dst', unk: 'cp --zz-unknown {T} /tmp/p3-dst' },
  { parser: 'cpDestination (--target-directory)', exact: ['cp --target-directory={D} /tmp/p3-x', 'stop'], short: 'cp --targ={D} /tmp/p3-x', unk: 'cp --zz-unknown {D} /tmp/p3-x' },
  { parser: 'cpDestination (link copy)', exact: ['cp --link {T} /tmp/p3-l', 'stop'], short: 'cp --li {T} /tmp/p3-l', unk: 'cp --zz-unknown {T} /tmp/p3-l' },
  { parser: 'cpDestination (value word last)', exact: ['cp {T} /tmp/p3-dst --sparse always', 'pass'], short: 'cp /tmp/p3-x {T} --spar always', unk: 'cp /tmp/p3-x {T} --zz-unknown always' },
  // modelled writers (writeTargets / targetDirFlag)
  { parser: 'writeTargets mv', exact: ['mv --target-directory={D} /tmp/p3-x', 'stop'], short: 'mv --targ={D} /tmp/p3-x', unk: 'mv --zz-unknown={D} /tmp/p3-x', reasons: 'mv_write_protected' },
  { parser: 'writeTargets install', exact: ['install --target-directory={D} /tmp/p3-x', 'stop'], short: 'install --targ={D} /tmp/p3-x', unk: 'install --zz-unknown={D} /tmp/p3-x', reasons: 'install_write_protected' },
  { parser: 'writeTargets ln', exact: ['ln --target-directory={D} /tmp/p3-x', 'stop'], short: 'ln --targ={D} /tmp/p3-x', unk: 'ln --zz-unknown={D} /tmp/p3-x', reasons: 'ln_write_protected' },
  { parser: 'writeTargets tar -C', exact: ['tar --extract --directory={D} -f /tmp/p3.tar', 'stop'], short: 'tar --extract --dire={D} -f /tmp/p3.tar', unk: 'tar --extract --zz-unknown={D} -f /tmp/p3.tar', reasons: 'tar_write_protected' },
  { parser: 'writeTargets sed -i', exact: ['sed --in-place=.bak s/a/b/ {T}', 'stop'], short: 'sed --in-p=.bak s/a/b/ {T}', unk: 'sed --zz-unknown s/a/b/ {T}', reasons: 'sed_write_protected' },
  { parser: 'writeTargets curl', exact: ['curl --output {T} https://example.test/x', 'stop'], short: 'curl --outp {T} https://example.test/x', unk: 'curl --zz-unknown {T} https://example.test/x', reasons: 'curl_write_protected' },
  { parser: 'writeTargets wget', exact: ['wget --output-document={T} https://example.test/x', 'stop'], short: 'wget --outp={T} https://example.test/x', unk: 'wget --zz-unknown={T} https://example.test/x', reasons: 'wget_write_protected' },
  { parser: 'writeTargets rsync', exact: ['rsync --archive /tmp/p3-s/ {D}/', 'stop'], short: 'rsync --arch /tmp/p3-s/ {D}/', unk: 'rsync --zz-unknown /tmp/p3-s/ {D}/', reasons: 'rsync_write_protected' },
  // reader exclusions (operandRuleApplies): a reader keeps passing; a long option it does not list makes it no reader
  { parser: 'reader cat', exact: ['cat --number {T}', 'pass'], short: 'cat --numb {T}', unk: 'cat --zz-unknown {T}' },
  { parser: 'reader grep', exact: ['grep --line-number x {T}', 'pass'], short: 'grep --line x {T}', unk: 'grep --zz-unknown x {T}' },
  { parser: 'reader rg', exact: ['rg --hidden x {T}', 'pass'], short: 'rg --hidd x {T}', unk: 'rg --zz-unknown x {T}' },
  { parser: 'reader jq', exact: ['jq --compact-output . {T}', 'pass'], short: 'jq --comp . {T}', unk: 'jq --zz-unknown . {T}' },
  { parser: 'reader yq', exact: ['yq --output-format=json . {T}', 'pass'], short: 'yq --outp=json . {T}', unk: 'yq --zz-unknown . {T}' },
  { parser: 'reader bat', exact: ['bat --paging=never {T}', 'pass'], short: 'bat --pagi=never {T}', unk: 'bat --zz-unknown {T}' },
  { parser: 'reader less', exact: ['less --quiet {T}', 'pass'], short: 'less --quie {T}', unk: 'less --zz-unknown {T}' },
  { parser: 'reader more', exact: ['more --silent {T}', 'pass'], short: 'more --sile {T}', unk: 'more --zz-unknown {T}' },
  { parser: 'reader head', exact: ['head --lines=5 {T}', 'pass'], short: 'head --line=5 {T}', unk: 'head --zz-unknown {T}' },
  { parser: 'reader tail', exact: ['tail --lines=5 {T}', 'pass'], short: 'tail --line=5 {T}', unk: 'tail --zz-unknown {T}' },
  { parser: 'reader wc', exact: ['wc --lines {T}', 'pass'], short: 'wc --line {T}', unk: 'wc --zz-unknown {T}' },
  { parser: 'reader ls', exact: ['ls --almost-all {T}', 'pass'], short: 'ls --almo {T}', unk: 'ls --zz-unknown {T}' },
  { parser: 'reader du', exact: ['du --human-readable {T}', 'pass'], short: 'du --huma {T}', unk: 'du --zz-unknown {T}' },
  { parser: 'reader stat', exact: ['stat --terse {T}', 'pass'], short: 'stat --ters {T}', unk: 'stat --zz-unknown {T}' },
  { parser: 'reader diff', exact: ['diff --brief {T} /tmp/p3-x', 'pass'], short: 'diff --brie {T} /tmp/p3-x', unk: 'diff --zz-unknown {T} /tmp/p3-x' },
  { parser: 'reader cmp', exact: ['cmp --silent {T} /tmp/p3-x', 'pass'], short: 'cmp --sile {T} /tmp/p3-x', unk: 'cmp --zz-unknown {T} /tmp/p3-x' },
  { parser: 'reader file', exact: ['file --brief {T}', 'pass'], short: 'file --brie {T}', unk: 'file --zz-unknown {T}' },
  { parser: 'reader sha256sum', exact: ['sha256sum --binary {T}', 'pass'], short: 'sha256sum --bina {T}', unk: 'sha256sum --zz-unknown {T}' },
  { parser: 'reader tree', exact: ['tree --noreport {D}', 'pass'], short: 'tree --nore {D}', unk: 'tree --zz-unknown {D}' },
  { parser: 'reader prettier', exact: ['prettier --check {T}', 'pass'], short: 'prettier --chec {T}', unk: 'prettier --zz-unknown {T}' },
  // sedReadOnly, awkReadOnly, find
  { parser: 'sedReadOnly', exact: ['sed --quiet 1p {T}', 'pass'], short: 'sed --quie 1p {T}', unk: 'sed --zz-unknown 1p {T}' },
  { parser: 'awkReadOnly', exact: ["awk --field-separator=: '{print $1}' {T}", 'pass'], short: "awk --fiel=: '{print $1}' {T}", unk: "awk --zz-unknown '{print $1}' {T}" },
  { parser: 'find (read)', exact: ['find {T} -name x', 'pass'], short: 'find {T} -nam x', unk: 'find {T} --zz-unknown' },
  { parser: 'find (-delete)', exact: ['find {D} -delete', 'stop'], short: 'find {D} -dele', unk: 'find {D} --zz-unknown' },
  // git read-only and index-only checks
  { parser: 'git read-only (diff)', exact: ['git diff --stat {T}', 'pass'], short: 'git diff --sta {T}', unk: 'git diff --zz-unknown {T}' },
  { parser: 'git read-only (log)', exact: ['git log --oneline -- {T}', 'pass'], short: 'git log --onel -- {T}', unk: 'git log --zz-unknown -- {T}' },
  { parser: 'git read-only (--output)', exact: ['git diff --output=/tmp/p3-out.patch {T}', 'pass'], short: 'git diff --outp={T}', unk: 'git diff --zz-unknown={T}' },
  { parser: 'git index-only (reset)', exact: ['git reset --mixed -- {T}', 'pass'], short: 'git reset --har -- {T}', unk: 'git reset --zz-unknown -- {T}' },
  { parser: 'git index-only (restore)', exact: ['git restore --staged {T}', 'pass'], short: 'git restore --staged --work {T}', unk: 'git restore --staged --zz-unknown {T}' },
  { parser: 'git index-only (rm)', exact: ['git rm --cached {T}', 'pass'], short: 'git rm --cach {T}', unk: 'git rm --cached --zz-unknown {T}' },
  { parser: 'git grep pager command', exact: ['git grep --open-files-in-pager="rm {T}" foo', 'stop'], short: 'git grep --open-f="rm {T}" foo', unk: 'git grep --zz-unknown="rm {T}" foo' },
  // tar option reader (commands the options run)
  { parser: 'tar --to-command', exact: ['tar -xf /tmp/p3.tar --to-command="rm {T}"', 'stop'], short: 'tar -xf /tmp/p3.tar --to-comm="rm {T}"', unk: 'tar -xf /tmp/p3.tar --zz-unknown="rm {T}"' },
  { parser: 'tar --create (inputs are reads)', exact: ['tar --create --file=/tmp/p3-out.tar {T}', 'pass'], short: 'tar --crea --file=/tmp/p3-out.tar {T}', unk: 'tar --create --zz-unknown --file=/tmp/p3-out.tar {T}' },
];

const strictAnswer = (d, row, cmd) => {
  assert.equal(d.decision, 'stop', `${row.parser}: ${cmd}: ${d.reasons}`);
  assert.ok(d.hits.some((h) => h.category === 'S0'), `${row.parser}: ${cmd}: ${d.reasons}`);
  if (row.reasons) assert.ok(d.reasons.some((r) => r.startsWith(row.reasons)), `${row.parser}: ${cmd}: the parser under test did not stop it: ${d.reasons}`);
};

test('long options: the fixed table (exact keeps its answer; shortened and unknown give the strict S0 answer) on the three S0 targets', () => {
  let rows = 0;
  for (const t of TARGETS) {
    for (const row of PARSERS) {
      const [exactCmd, want] = row.exact;
      const e = fill(exactCmd, t);
      const d = sh(e);
      assert.equal(d.decision, want, `${row.parser} exact on ${t.name}: ${e}: ${d.reasons}`);
      if (want === 'stop') assert.ok(d.hits.some((h) => h.category === 'S0'), `${row.parser} exact on ${t.name}: ${e}`);
      strictAnswer(sh(fill(row.short, t)), row, `${row.parser} short on ${t.name}: ${fill(row.short, t)}`);
      strictAnswer(sh(fill(row.unk, t)), row, `${row.parser} unknown on ${t.name}: ${fill(row.unk, t)}`);
      rows += 3;
    }
  }
  assert.equal(rows, PARSERS.length * 3 * TARGETS.length);
});

test('long options: the audit rows (F-OPT) and the abbreviations of the wrappers around them stop', () => {
  for (const t of TARGETS) {
    for (const c of [
      `cp --target=${t.D} /tmp/p3-x`, `cp --t=${t.D} /tmp/p3-x`, `cp --target-dir ${t.D} /tmp/p3-x`, `cp --li ${t.T} /tmp/p3-x`, `cp --sym ${t.T} /tmp/p3-x`,
      `cp -r --preserve=mode --targ=${t.D} /tmp/p3-x`, `cp /tmp/p3-x ${t.T} --sparse always`, `cp /tmp/p3-x ${t.T} --no-preserve mode`,
      `git reset --har -- ${t.T}`, `git restore --staged --work ${t.T}`, `git restore --staged --worktre ${t.T}`, `git diff --outp=${t.T}`,
      `git grep --open-f="rm ${t.T}" foo`, `git --exec-pat=/x diff ${t.T}`, `git --zz-unknown log -- ${t.T}`,
      `tar -xf /tmp/p3.tar --to-comm="rm ${t.T}"`, `tar -xf /tmp/p3.tar --checkpoint-act=exec="rm ${t.T}"`, `tar -cf /tmp/p3.tar --use-compress="rm ${t.T}" /tmp/p3-x`,
      `rg --pr="rm ${t.T}" foo src`, `bat --pag="rm ${t.T}" README.md`,
    ]) {
      const d = sh(c);
      assert.equal(d.decision, 'stop', `${c}: ${d.reasons}`);
      assert.ok(d.hits.some((h) => h.category === 'S0'), `${c}: ${d.reasons}`);
    }
  }
});

test('long options: benign rows on non-protected paths do not stop (friction controls)', () => {
  for (const c of [
    'cp -r --preserve=mode src dst', 'cp --backup=numbered a b', 'sort --output=out.txt in.txt', 'sed --in-place=.bak s/a/b/ notes.txt', 'git log --oneline',
    'git diff --stat', 'tar --create --file=out.tar src',
    'cp --reflink=auto a b', 'cp --update --verbose a b', 'cp --archive src/ /tmp/backup/', 'mv --verbose --no-clobber a b', 'ln --symbolic --force a b',
    'install --mode=755 --directory /tmp/p3-bin', 'rsync --archive --delete --exclude=node_modules src/ /tmp/x/', 'rsync --dry-run --verbose src/ /tmp/x/',
    'curl --silent --show-error --fail --output /tmp/p3-x https://example.test/x', 'wget --quiet --output-document=/tmp/p3-x https://example.test/x',
    'tar --extract --gzip --file=/tmp/p3.tgz --directory=/tmp/p3-x --strip-components=1', 'tar --list --verbose --file=/tmp/p3.tar',
    'grep --recursive --line-number --include=*.js foo src', 'grep --color=auto --ignore-case foo README.md', 'rg --hidden --glob "*.js" foo src', 'rg --files-with-matches foo src',
    'ls --color=auto --human-readable -l', 'du --max-depth=1 --human-readable', 'diff --unified a b', 'head --lines=5 README.md', 'jq --raw-output .a a.json', 'bat --style=plain README.md',
    'sed --quiet 1,5p README.md', "awk --assign n=3 'NR<=n' README.md", 'find . -name "*.js" -not -path "./node_modules/*" -maxdepth 3 -type f',
    'find src -type f -mtime -1 -size +1k -print0', 'git log --oneline --graph --decorate -n 5', 'git diff --stat --name-only HEAD~1', 'git status --short --branch',
    'git show --stat HEAD', 'git add --all', 'git commit --amend --no-edit', 'git blame --line-porcelain README.md', 'git grep --line-number foo', 'git ls-files --others --exclude-standard',
    'git reset --soft HEAD~1', 'git restore --staged README.md', 'git rm --cached --quiet README.md', 'prettier --check src', 'tree -L 2 src', 'zip -r /tmp/p3-out.zip src',
    'git -C /tmp/p3-repo --no-pager log --oneline',
  ]) {
    const d = sh(c);
    assert.equal(d.decision, 'pass', `${c}: ${d.reasons}`);
  }
});

test('long options: the lists read a long option on an exact match only (unit)', () => {
  const list = L.longList('plain value= maybe[=] [no-]neg any~');
  const w = (...t) => t.map((text) => ({ text }));
  assert.equal(L.unknownLong(w('--plain', '--value=1', '--maybe', '--maybe=2', '--neg', '--no-neg', '--any', '--any=3'), list), -1);
  assert.equal(L.unknownLong(w('--plai'), list), 0, 'a shortened option is unknown');
  assert.equal(L.unknownLong(w('--plain=1'), list), 0, 'a flag with a value is unknown');
  assert.equal(L.unknownLong(w('--value', '--zz'), list), -1, 'the word after a value option is its value, not an option');
  assert.equal(L.unknownLong(w('--value', 'x', '--zzz'), list), 2);
  assert.equal(L.unknownLong(w('--no-plain'), list), 0, 'no- only where [no-] is written');
  assert.equal(L.unknownLong(w('--PLAIN'), list), 0, 'case counts');
  assert.equal(L.unknownLong(w('--', '--zz-unknown'), list), -1, 'a bare -- ends the options');
  assert.equal(L.unknownLong(w('--', '--zz-unknown'), list, 2, false), 1, 'unless the parser reads past it');
  assert.equal(L.unknownLong([{ text: null }, { text: '-x' }, { text: '-' }], list), -1, 'dynamic words, short options and - are not long options');
  assert.deepEqual(L.unknownLongAll(w('--a', '--plain', '--b'), list), [0, 2]);
  const find = L.longList('name= type= delete');
  assert.equal(L.unknownLong(w('-name', '-x', '-type', 'f'), find, 1, false), -1, 'find: the word after -name is a value');
  assert.equal(L.unknownLong(w('-nam'), find, 1, false), 0);
  assert.equal(L.unknownLong(w('-name=x'), find, 1, false), 0, 'find options never carry =');
  assert.equal(L.takesNextWord('--value', list), true);
  assert.equal(L.takesNextWord('--value=1', list), false);
  assert.equal(L.takesNextWord('--maybe', list), false);
  // The real lists never hold an option that writes or runs on a reader.
  for (const [name, list2] of [['rg', L.RG_LONG], ['bat', L.BAT_LONG], ['less', L.LESS_LONG], ['yq', L.YQ_LONG], ['file', L.FILE_LONG], ['prettier', L.PRETTIER_LONG]]) {
    for (const bad of ['pre', 'pre-glob', 'hostname-bin', 'pager', 'log-file', 'LOG-FILE', 'inplace', 'in-place', 'split-exp', 'compile', 'write', 'cache-location', 'plugin', 'config', 'output']) {
      assert.equal(list2.has(bad), false, `${name} list holds ${bad}`);
    }
  }
});

test('friction (delta audit): tree, prettier --check and archiving read their inputs; their writing forms keep the stop', () => {
  for (const t of TARGETS) {
    for (const c of [
      `tree ${t.D}`, `tree -a -L 2 ${t.D}`, `tree --noreport ${t.D}`,
      `prettier --check ${t.T}`, `prettier -c ${t.T}`, `prettier --list-different ${t.T}`, `prettier -l ${t.T}`, `prettier ${t.T}`, `npx prettier --check ${t.T}`, `npx -y prettier -c ${t.T}`,
      `bunx prettier --list-different ${t.T}`, `./node_modules/.bin/prettier --check ${t.T}`,
      `tar czf /tmp/p3-out.tgz ${t.D}`, `tar -czf /tmp/p3-out.tgz ${t.D}`, `tar -cvzf /tmp/p3-out.tgz ${t.D} ${t.T}`, `tar --create --gzip --file /tmp/p3-out.tgz ${t.D}`,
      `tar -cf /tmp/p3-out.tar -C ${t.D} .`, `tar cf - ${t.D} | gzip > /tmp/p3-out.tgz`, `zip -r /tmp/p3-out.zip ${t.D}`, `zip /tmp/p3-out.zip ${t.T}`,
      `zip -rq /tmp/p3-out.zip ${t.D} -x '*.git*'`,
    ]) {
      const d = sh(c);
      assert.equal(d.decision, 'pass', `${c}: ${d.reasons}`);
    }
    for (const c of [
      `tree -o /tmp/p3-out.txt ${t.D}`, `tree -Lo /tmp/p3-out.txt ${t.D}`, `tree -o ${t.T} /tmp/p3-src`, `tree --zz-unknown ${t.D}`, `tree --noreport -o /tmp/p3-out.txt ${t.D}`,
      `prettier --write ${t.T}`, `prettier -w ${t.T}`, `prettier -cw ${t.T}`, `prettier --check --write ${t.T}`, `prettier --wri ${t.T}`, `prettier --cache --cache-location=${t.T} --check src`,
      `npx prettier --write ${t.T}`, `npx -y prettier -w ${t.T}`, `prettier --check $X ${t.T}`,
      `tar czf ${t.T} /tmp/p3-src`, `tar -czf ${t.T} /tmp/p3-src`, `tar -cf /tmp/p3-out.tar --index-file=${t.T} /tmp/p3-src`, `tar xzf /tmp/p3.tgz -C ${t.D}`, `tar -xf /tmp/p3.tar ${t.T}`,
      `tar --remove-files -czf /tmp/p3-out.tgz ${t.T}`, `tar czf /tmp/p3-out.tgz --zz-unknown ${t.T}`, `tar cf /tmp/p3-out.tar $X ${t.T}`, `tar -rf /tmp/p3.tar ${t.T}`, `tar --append -f ${t.T} /tmp/p3-src`,
      `zip ${t.T} /tmp/p3-src`, `zip -m /tmp/p3-out.zip ${t.T}`, `zip -r -O ${t.T} /tmp/p3-out.zip /tmp/p3-src`, `zip --zz-unknown /tmp/p3-out.zip ${t.T}`,
    ]) {
      const d = sh(c);
      assert.equal(d.decision, 'stop', `${c}: ${d.reasons}`);
      assert.ok(d.hits.some((h) => h.category === 'S0' || h.category === 'S4'), `${c}: ${d.reasons}`);
    }
  }
});

test('F-AWK: an awk program that writes or runs from its own text has its quoted paths checked', () => {
  for (const t of TARGETS) {
    for (const c of [
      `awk 'BEGIN{print "x" > "${t.A}"}'`, `awk 'BEGIN{print "x" >> "${t.A}"}'`, `awk '{printf "%s\\n", $0 > "${t.A}"}' /tmp/p3-in`, `awk 'BEGIN{system("rm ${t.A}")}'`,
      `awk 'BEGIN{print "x" | "tee ${t.A}"}'`, `gawk 'BEGIN{print > "${t.A}"}'`, `mawk '{print $1 > "${t.A}"}' /tmp/p3-in`,
    ]) {
      const d = sh(c);
      assert.equal(d.decision, 'stop', `${c}: ${d.reasons}`);
      assert.ok(d.hits.some((h) => h.category === 'S0'), `${c}: ${d.reasons}`);
    }
  }
  for (const c of [`awk '{print > "/tmp/p3-out.txt"}' /tmp/p3-in`, `awk 'BEGIN{print "x" > "/dev/stderr"}'`, `awk '{print $1}' ${TARGETS[0].T}`, `awk -F: '{print $1}' ${TARGETS[0].T}`,
    `awk 'BEGIN{system("echo hi")}'`, `awk '{ print "has > sign in text" }' /tmp/p3-in`]) {
    assert.equal(sh(c).decision, 'pass', c);
  }
});

// ------------------------------------------------------------------------------------------------
// Hook rows: the real hook CLI, keyless, in a temporary home (the same fixtures as the NEW-1 and NEW-2 tests).

function keylessSandbox() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-p3-')));
  const home = path.join(root, 'home');
  const proj = path.join(home, 'proj');
  fs.mkdirSync(proj, { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  for (const d of ['.ssh', '.aws', '.marrow', '.claude']) fs.mkdirSync(path.join(home, d), { mode: 0o700 });
  execFileSync('git', ['init', '-q', '-b', 'feat/x'], { cwd: proj, env: { PATH: process.env.PATH, HOME: home, GIT_CONFIG_NOSYSTEM: '1' }, stdio: 'ignore' });
  const put = (rel, text) => { const p = path.join(home, rel); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, text); };
  put('.claude/settings.json', JSON.stringify({ hooks: HOOKS }, null, 2));
  put('.claude/plugins/installed_plugins.json', '{"version":2,"plugins":{}}');
  put('.claude/plugins/cache/getmarrow/marrow/1.2.3/scripts/marrow-launch.cjs', 'module.exports = 1;\n');
  put('.npm/_npx/abc123/node_modules/@getmarrow/mcp/dist/cli.js', 'module.exports = 1;\n');
  return { root, home, proj, netspy: path.join(root, 'net.log'), cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}
const ENTRY = { claude: 'claude-pre-action-hook', codex: 'codex-pre-action-hook', cursor: 'cursor-pre-action-hook', 'cursor-pre': 'cursor-pre-action-hook',
  gemini: 'gemini-pre-action-hook', cline: 'cline-pre-action-hook', windsurf: 'windsurf-pre-action-hook', grok: 'grok-pre-action-hook' };
function hook(sb, host, event) {
  const r = spawnSync(process.execPath, ['--require', PRELOAD, CLI, ENTRY[host]], {
    cwd: sb.proj, encoding: 'utf8', timeout: 30_000, input: JSON.stringify(event),
    env: { PATH: process.env.PATH, HOME: sb.home, SBT_PASSWD_HOME: sb.home, SBT_NETSPY: sb.netspy, MARROW_HOOK_BACKGROUND_NUDGE: 'false' },
  });
  return { status: r.status, out: r.stdout || '', err: r.stderr || '' };
}
const sid = () => `p3-${crypto.randomBytes(6).toString('hex')}`;
function shellEvent(sb, host, command) {
  if (host === 'cursor') return { hook_event_name: 'beforeShellExecution', conversation_id: sid(), generation_id: 'g1', command, cwd: sb.proj };
  if (host === 'cursor-pre') return { hook_event_name: 'preToolUse', conversation_id: sid(), generation_id: 'g', tool_use_id: 't', tool_name: 'Shell', tool_input: { command }, cwd: sb.proj };
  if (host === 'gemini') return { session_id: sid(), hook_event_name: 'BeforeTool', tool_name: 'run_shell_command', tool_input: { command }, cwd: sb.proj };
  if (host === 'grok') return { hookEventName: 'PreToolUse', sessionId: sid(), toolUseId: 't', toolName: 'run_terminal_command', toolInput: { command }, cwd: sb.proj };
  if (host === 'cline') return { hookName: 'PreToolUse', taskId: sid(), workspaceRoots: [sb.proj], preToolUse: { toolName: 'execute_command', parameters: { command } } };
  if (host === 'windsurf') return { agent_action_name: 'pre_run_command', trajectory_id: sid(), execution_id: 'e', tool_info: { command_line: command, cwd: sb.proj } };
  return { hook_event_name: 'PreToolUse', session_id: sid(), tool_use_id: 't1', tool_name: 'Bash', tool_input: { command }, cwd: sb.proj };
}
function toolEvent(sb, host, tool, input) {
  if (host === 'gemini') return { session_id: sid(), hook_event_name: 'BeforeTool', tool_name: tool, tool_input: input, cwd: sb.proj };
  if (host === 'cline') return { hookName: 'PreToolUse', taskId: sid(), workspaceRoots: [sb.proj], preToolUse: { toolName: tool, parameters: input } };
  if (host === 'cursor-pre') return { hook_event_name: 'preToolUse', conversation_id: sid(), generation_id: 'g', tool_use_id: 't', tool_name: tool, tool_input: input, cwd: sb.proj };
  return { hook_event_name: 'PreToolUse', session_id: sid(), tool_use_id: 't1', tool_name: tool, tool_input: input, cwd: sb.proj };
}
/** STOP: the seatbelt's own stop; GROK: Grok's fixed denial; otherwise the host's pass. */
function verdict(r) {
  let j = null;
  try { j = r.out.trim() ? JSON.parse(r.out) : null; } catch { j = null; }
  const text = JSON.stringify(j || '') + r.err;
  if (/^\{"decision":"deny","reason":"Marrow blocked this protected action\."\}$/.test(r.out.trim())) return 'GROK';
  const d = j ? (j.permission || j.hookSpecificOutput?.permissionDecision || j.decision || (j.cancel === true ? 'deny' : null)) : null;
  if ((r.status === 2 || d === 'deny' || d === 'block') && /MARROW SEATBELT stopped/.test(text)) return 'STOP';
  if (r.status === 2 || d === 'deny' || d === 'block') return 'held';
  return 'pass';
}
const HOSTS7 = ['claude', 'codex', 'cursor', 'cursor-pre', 'gemini', 'cline', 'windsurf'];

// One representative row per parser family, cycling the three S0 targets, on the 7 host paths.
const HOOK_ROWS = [
  'cpDestination (source read)', 'cpDestination (--target-directory)', 'writeTargets tar -C', 'writeTargets sed -i', 'writeTargets curl', 'reader cat', 'reader rg', 'reader jq',
  'reader bat', 'reader tree', 'reader prettier', 'sedReadOnly', 'awkReadOnly', 'find (read)', 'find (-delete)', 'git read-only (diff)', 'git index-only (reset)',
  'git index-only (restore)', 'git grep pager command', 'tar --to-command', 'tar --create (inputs are reads)',
].map((name) => PARSERS.find((p) => p.parser === name));

test('long options (hook): the fixed table through the real hook CLI on the 7 host paths; Grok gives its fixed denial', () => {
  const sb = keylessSandbox();
  try {
    let cells = 0;
    HOOK_ROWS.forEach((row, n) => {
      const t = TARGETS[n % TARGETS.length];
      const [exactCmd, want] = row.exact;
      const variants = [['exact', fill(exactCmd, t, sb.home), want === 'pass' ? 'pass' : 'STOP'], ['short', fill(row.short, t, sb.home), 'STOP'], ['unknown', fill(row.unk, t, sb.home), 'STOP']];
      for (const [label, command, expected] of variants) {
        for (const host of HOSTS7) {
          const v = verdict(hook(sb, host, shellEvent(sb, host, command)));
          // A pass row must not be the seatbelt's stop; a host may still hold the action for its own reasons (cursor holds git reset).
          if (expected === 'pass') assert.ok(v === 'pass' || v === 'held', `${row.parser} ${label} on ${host} (${t.name}): ${command}: ${v}`);
          else assert.equal(v, expected, `${row.parser} ${label} on ${host} (${t.name}): ${command}`);
          cells += 1;
        }
        const g = verdict(hook(sb, 'grok', shellEvent(sb, 'grok', command)));
        if (expected === 'STOP') assert.equal(g, 'GROK', `${row.parser} ${label} on grok: ${command}`);
      }
    });
    assert.equal(cells, HOOK_ROWS.length * 3 * HOSTS7.length);
    assert.equal(fs.existsSync(sb.netspy) ? fs.readFileSync(sb.netspy, 'utf8') : '', '');
  } finally { sb.cleanup(); }
});

test('friction and F-AWK (hook): tree, prettier --check and archive creation pass; their writing forms and awk program writers stop on the 7 host paths', () => {
  const sb = keylessSandbox();
  try {
    const t = TARGETS[0];
    const passes = [`tree ${t.D}`, `prettier --check ${t.T}`, `npx prettier --check ${t.T}`, `tar czf /tmp/p3-out.tgz ${t.D}`, `zip -r /tmp/p3-out.zip ${t.D}`];
    const stops = [`tree -o /tmp/p3-out.txt ${t.D}`, `prettier --write ${t.T}`, `tar czf ${t.T} /tmp/p3-src`, `tar xzf /tmp/p3.tgz -C ${t.D}`, `awk 'BEGIN{print "x" > "${sb.home}/.claude/settings.json"}'`,
      `awk 'BEGIN{system("rm ${sb.home}/.claude/settings.json")}'`];
    for (const host of HOSTS7) {
      for (const c of passes) assert.equal(verdict(hook(sb, host, shellEvent(sb, host, c))), 'pass', `${host}: ${c}`);
      for (const c of stops) assert.equal(verdict(hook(sb, host, shellEvent(sb, host, c))), 'STOP', `${host}: ${c}`);
    }
    for (const c of stops) assert.equal(verdict(hook(sb, 'grok', shellEvent(sb, 'grok', c))), 'GROK', `grok: ${c}`);
  } finally { sb.cleanup(); }
});

test('F-CODEX: a write under ~/.codex stops (S0) on every host, also a native write tool that leaves the Marrow part as it was', () => {
  const sb = keylessSandbox();
  try {
    const hooks = path.join(sb.home, '.codex', 'hooks.json');
    const config = path.join(sb.home, '.codex', 'config.toml');
    // Shell writes: all 7 host paths.
    for (const c of [`echo '{}' > ~/.codex/hooks.json`, `printf '{}' > ${hooks}`, `echo x > ~/.codex/config.toml`, `tee ~/.codex/hooks.json < /tmp/p3-x`]) {
      for (const host of HOSTS7) assert.equal(verdict(hook(sb, host, shellEvent(sb, host, c))), 'STOP', `${host}: ${c}`);
      assert.equal(verdict(hook(sb, 'grok', shellEvent(sb, 'grok', c))), 'GROK');
    }
    // Native write tools (the file does not exist yet, and the content holds no hook entry at all).
    const cells = [
      ['claude', 'Write', { file_path: hooks, content: '{}' }], ['codex', 'Write', { file_path: hooks, content: '{}' }], ['gemini', 'write_file', { file_path: hooks, content: '{}' }],
      ['cline', 'write_to_file', { path: hooks, content: '{}' }], ['cursor-pre', 'Write', { file_path: hooks, content: '{}' }],
      ['claude', 'Write', { file_path: path.join(sb.proj, '.codex', 'hooks.json'), content: '{}' }], ['gemini', 'write_file', { file_path: path.join(sb.proj, '.codex', 'hooks.json'), content: '{}' }],
      ['claude', 'Write', { file_path: config, content: 'x = 1\n' }], ['gemini', 'write_file', { file_path: config, content: 'x = 1\n' }], ['gemini', 'replace', { file_path: hooks, old_string: '"hooks"', new_string: '"hooks"' }],
    ];
    for (const [host, tool, input] of cells) assert.equal(verdict(hook(sb, host, toolEvent(sb, host, tool, input))), 'STOP', `${host} ${tool} ${input.file_path || input.path}`);
    // Control: a file outside every protected folder.
    for (const [host, tool, input] of [['gemini', 'write_file', { file_path: path.join(sb.proj, 'notes.md'), content: 'x' }], ['claude', 'Write', { file_path: path.join(sb.proj, 'notes.md'), content: 'x' }]]) {
      assert.equal(verdict(hook(sb, host, toolEvent(sb, host, tool, input))), 'pass', `${host} control`);
    }
  } finally { sb.cleanup(); }
});
