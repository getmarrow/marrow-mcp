'use strict';

// Patch round 3 (delta audit F-OPT): the seatbelt parsers read a long option only on an exact match with a fixed
// list. GNU tools (and git, curl, wget) accept a long option shortened to a unique prefix, so `cp --targ=DIR src`
// writes into DIR while a parser that only knows `--target-directory` read it as "no target". A fixed table, not a
// search: for each parser one row with the option spelled exactly (today's answer), one with it cut to its first 4
// letters, and one with a made-up `--zz-unknown`. The last two must give the strict answer for an S0 target: the
// Marrow plugins folder, ~/.claude/settings.json and the npx copy. Mapper rows run the three targets; the same table runs
// through the real hook CLI in seatbelt-long-options-hook.test.js.
// Also in this file: the friction narrowings of the same round (tree, prettier --check, tar/zip create), the awk
// program-text writers (F-AWK) and the Codex hook file on every host (F-CODEX).
const test = require('node:test');
const assert = require('node:assert/strict');

const { evaluateSeatbelt } = require('../dist/seatbelt/mapper.js');
// The previous build (a8c9f809) has no such module: its run of this file still reports every mapper row.
let L = null;
try { L = require('../dist/seatbelt/longopts.js'); } catch { L = null; }
const { makeEnv } = require('./support/seatbelt-fakes.cjs');

const { FILES, DIRS, TARGETS, fill, PARSERS } = require('./support/long-options-table.cjs');
const sh = (command) => evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command } }, makeEnv({ files: FILES, dirs: DIRS }));

const strictAnswer = (d, row, cmd) => {
  assert.equal(d.decision, 'stop', `${row.parser}: ${cmd}: ${d.reasons}`);
  assert.ok(d.hits.some((h) => h.category === 'S0'), `${row.parser}: ${cmd}: ${d.reasons}`);
  for (const want of [].concat(row.reasons || [])) assert.ok(d.reasons.some((r) => r.startsWith(want)), `${row.parser}: ${cmd}: the parser under test did not stop it (no ${want}): ${d.reasons}`);
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

test('long options: everyday options on a read of a protected file keep passing (a reader list that missed one would be friction)', () => {
  const T = '~/.claude/settings.json';
  for (const c of [
    `cat --number --show-ends ${T}`, `cat --squeeze-blank ${T}`, `head --lines=20 --quiet ${T}`, `tail --lines=+5 --follow=name ${T}`, `wc --lines --words --bytes ${T}`, `stat --format=%s ${T}`,
    `ls --color=auto --human-readable --almost-all ~/.claude`, `ls --sort=time --reverse -l ~/.claude`, `du --human-readable --max-depth=1 --summarize ~/.claude`, `file --mime-type --brief ${T}`,
    `diff --unified --ignore-all-space ${T} /tmp/p3-x`, `diff --color=never --recursive ~/.claude /tmp/p3-x`, `cmp --silent ${T} /tmp/p3-x`, `sha256sum --binary ${T}`, `md5sum --tag ${T}`,
    `grep --line-number --ignore-case --color=never hooks ${T}`, `grep --recursive --include=*.json --files-with-matches hooks ~/.claude`, `grep --fixed-strings --count marrow ${T}`,
    `rg --hidden --glob '*.json' --no-heading --line-number hooks ~/.claude`, `rg --files-with-matches --type json hooks ~/.claude`, `rg --max-count 3 --color never hooks ${T}`, `rg --print0 --files ~/.claude`,
    `jq --raw-output --sort-keys .hooks ${T}`, `jq --arg k hooks --compact-output '.[$k]' ${T}`, `yq --output-format=json . ${T}`, `bat --style=plain --paging=never --color=always ${T}`,
    `less --RAW-CONTROL-CHARS --quit-if-one-screen ${T}`, `tree -a -L 2 -I node_modules ~/.claude`, `tree --noreport --dirsfirst ~/.claude`, `prettier --check --tab-width 2 --print-width 100 ${T}`,
    `find ~/.claude -maxdepth 2 -type f -name '*.json' -mtime -7 -not -path '*/cache/*' -print0`, `find ~/.claude -newer /tmp/p3-x -size +1k -user u -perm -u+r`,
    `git diff --cached --name-status --diff-filter=M ${T}`, `git diff --staged --stat --no-color ${T}`, `git log --pretty=format:%h --since=2.weeks --author=bob --grep=fix --follow -- ${T}`,
    `git log --committer=bob --after=2020-01-01 --before=2030-01-01 --oneline -- ${T}`, `git show --format=%H --no-patch HEAD:.claude/settings.json`, `git blame --line-porcelain -w ${T}`,
    `git status --porcelain=v1 --untracked-files=no`, `git add --intent-to-add --verbose ${T}`, `git ls-files --cached --others --exclude-standard -- ${T}`,
    `cp --preserve=all --reflink=auto ${T} /tmp/p3-x`, `cp --archive --update --verbose ${T} /tmp/p3-x`,
    `tar --create --gzip --verbose --file=/tmp/p3.tgz --exclude=cache ~/.claude`, `tar --list --file=/tmp/p3.tgz`, `zip -rq /tmp/p3.zip ~/.claude`,
    `sed --quiet --regexp-extended '1,5p' ${T}`, `awk --assign n=3 'NR<=n' ${T}`,
  ]) {
    const d = sh(c);
    assert.equal(d.decision, 'pass', `${c}: ${d.reasons}`);
  }
});

test('long options: chains, subshells, wrappers, repeated flags and variables around the new rules (AUDIT RULE abuse cases)', () => {
  for (const t of TARGETS) {
    for (const c of [
      // chains, subshells, shells, pipes, wrappers
      `true && cp --targ=${t.D} /tmp/p3-x`, `(cp --targ=${t.D} /tmp/p3-x)`, `bash -c 'cp --targ=${t.D} /tmp/p3-x'`, `echo ${t.D} | xargs cp --targ=${t.D}`,
      `env FOO=1 cp --targ=${t.D} /tmp/p3-x`, `sudo cp --targ=${t.D} /tmp/p3-x`, `nohup cp --targ=${t.D} /tmp/p3-x`, `false || cp --li ${t.T} /tmp/p3-x`,
      // repeated flags: the last one counts
      `cp --target-directory=/tmp --target-directory=${t.D} /tmp/p3-x`, `cp --targ=/tmp --targ=${t.D} /tmp/p3-x`,
      // misleading words before the real command
      `echo cp --targ=D; cp --refl=auto ${t.T} /tmp/p3-x`,
      // the friction rules cannot be used to carry a write
      `prettier --check ${t.T} && prettier --write ${t.T}`, `prettier --check ${t.T}; prettier -w ${t.T}`, `P=--write; prettier --check $P ${t.T}`, `O=-o; tree $O ${t.D}`,
      `tar czf /tmp/p3-out.tgz ${t.D}; tar xzf /tmp/p3-out.tgz -C ${t.D}`, `tar $A czf /tmp/p3-out.tgz ${t.D}`, `zip -r /tmp/p3-out.zip ${t.D} && zip -m /tmp/p3-out.zip ${t.T}`,
      `bash -c 'prettier --write ${t.T}'`, `git log --oneline | tee ${t.T}`, `tree ${t.D} | tee ${t.T}`, `tar czf /tmp/p3-out.tgz ${t.D} | tee ${t.T}`,
      `awk 'BEGIN{print > "${t.A}"}' && echo done`,
    ]) {
      const d = sh(c);
      assert.equal(d.decision, 'stop', `${c}: ${d.reasons}`);
      assert.ok(d.hits.some((h) => h.category === 'S0'), `${c}: ${d.reasons}`);
    }
    // Reads that stay reads inside a chain or a shell.
    for (const c of [`tree ${t.D} && prettier --check ${t.T}`, `tar czf /tmp/p3-out.tgz ${t.D} && zip -r /tmp/p3-out.zip ${t.D}`]) {
      assert.equal(sh(c).decision, 'pass', c);
    }
  }
  // A shell given the command as text keeps the generic rule (the text is one operand): the settings folder is no protected text.
  for (const c of [`sh -c 'tar czf /tmp/p3-out.tgz ~/.claude'`, `echo 'prettier --check' ~/.claude/settings.json | sh`]) assert.equal(sh(c).decision, 'pass', c);
});

test('long options: the lists read a long option on an exact match only (unit)', { skip: L === null }, () => {
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
      `prettier --check ${t.T}`, `prettier -c ${t.T}`, `prettier --list-different ${t.T}`, `prettier -l ${t.T}`, `prettier ${t.T}`, `npx prettier --check ${t.T}`, `npx -y prettier -c ${t.T}`, `npx prettier@3.3.0 --check ${t.T}`,
      `bunx prettier --list-different ${t.T}`, `./node_modules/.bin/prettier --check ${t.T}`,
      `tar czf /tmp/p3-out.tgz ${t.D}`, `tar -czf /tmp/p3-out.tgz ${t.D}`, `tar -cvzf /tmp/p3-out.tgz ${t.D} ${t.T}`, `tar --create --gzip --file /tmp/p3-out.tgz ${t.D}`,
      `tar -cf /tmp/p3-out.tar -C ${t.D} .`, `tar cf - ${t.D} | gzip > /tmp/p3-out.tgz`, `zip -r /tmp/p3-out.zip ${t.D}`, `zip /tmp/p3-out.zip ${t.T}`,
      `zip -rq /tmp/p3-out.zip ${t.D} -x '*.git*'`,
    ]) {
      const d = sh(c);
      assert.equal(d.decision, 'pass', `${c}: ${d.reasons}`);
    }
    for (const c of [
      `tree -o /tmp/p3-out.txt ${t.D}`, `tree -Lo /tmp/p3-out.txt ${t.D}`, `tree -R -L 1 ${t.D}`, `tree -aR ${t.D}`, `tree -o ${t.T} /tmp/p3-src`, `tree --zz-unknown ${t.D}`, `tree --noreport -o /tmp/p3-out.txt ${t.D}`,
      `prettier --write ${t.T}`, `prettier -w ${t.T}`, `prettier -cw ${t.T}`, `prettier --check --write ${t.T}`, `prettier --wri ${t.T}`, `prettier --cache --cache-location=${t.T} --check src`,
      `npx prettier --write ${t.T}`, `npx -y prettier -w ${t.T}`, `prettier --check $X ${t.T}`, `tree $O ${t.T}`, `tree $O ${t.D}`,
      // npx options that take a value would make the mapper read that value as the package: every word counts then.
      `npx --cache cat prettier -w ${t.T}`, `npx --registry https://example.test cat prettier -w ${t.T}`, `npx -y --node-options=--x cat prettier -w ${t.T}`,
      `npx -y cat prettier -w ${t.T}`, `bunx --bun cat prettier -w ${t.T}`, `npx -p evil-pkg prettier --check ${t.T}`, `npx -y cat ${t.T}`, `npx -y jq . ${t.T}`,
      `npx --package=evil-pkg prettier --check ${t.T}`, `npx -- prettier --check ${t.T}`, `npx prettier@3.3.0 --write ${t.T}`,
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
// Patch round 4 (exact-final audit): P3-F1 (an attached short value is a destination whatever its first character),
// P3-F2 (zip reads a documented multi-letter option by its meaning) and Residual 1 (env / sudo / doas and the working folder
// of the command they run). A fixed table (the rows of test/support/long-options-table.cjs run in the first test of this file
// and through the hook CLI) plus the rows below; no search for new spellings.

test('patch round 4: the fixed rows stop on the three S0 targets (attached short values, zip -TT / -lf, wrapper working folders)', () => {
  for (const t of TARGETS) {
    for (const c of [
      // P3-F1: the attached value of a short option, relative to a protected working folder
      `cd ${t.P} && cp -t${t.R} /tmp/p4-x`, `cd ${t.P} && cp -rt${t.R} /tmp/p4-x`, `cd ${t.P} && mv -t${t.R} /tmp/p4-x`, `cd ${t.P} && ln -s -t${t.R} /tmp/p4-x`,
      `cd ${t.P} && install -t${t.R} /tmp/p4-x`, `cd ${t.P} && cp --refl=auto -t${t.R} /tmp/p4-x`, `cd ${t.P} && cp --zz-unknown -t${t.R} /tmp/p4-x`,
      // P3-F2: -TT and --unzip-command run a command, -lf writes a log file
      `zip /tmp/p4.zip /tmp/p4-in -T -TT "rm ${t.T}"`, `zip /tmp/p4.zip /tmp/p4-in -T -TT="rm ${t.T}"`, `zip /tmp/p4.zip /tmp/p4-in -T -TT"rm ${t.T}"`, `zip /tmp/p4.zip /tmp/p4-in -rTT "rm ${t.T}"`,
      `zip /tmp/p4.zip /tmp/p4-in -T --unzip-command "rm ${t.T}"`, `zip /tmp/p4.zip /tmp/p4-in -T --unzip-command="rm ${t.T}"`, `zip /tmp/p4.zip /tmp/p4-in -T --unzip-comm="rm ${t.T}"`,
      `zip /tmp/p4.zip /tmp/p4-in -T -TT "bash -c 'rm ${t.T}'"`, `zip /tmp/p4.zip /tmp/p4-in -lf ${t.T}`, `zip /tmp/p4.zip /tmp/p4-in -lf=${t.T}`, `zip /tmp/p4.zip /tmp/p4-in -lf${t.T}`,
      `zip /tmp/p4.zip /tmp/p4-in -rlf ${t.T}`, `zip /tmp/p4.zip /tmp/p4-in -lf /tmp/p4.log -lf ${t.T}`, `zip /tmp/p4.zip /tmp/p4-in -ds 1m -TT "rm ${t.T}"`,
      // the documented flags that are read now still carry no write, and the ones that create files or change inputs stay unread (every operand counts)
      `zip -sc -m /tmp/p4.zip ${t.T}`, `zip -sC /tmp/p4.zip ${t.T}`, `zip -sc ${t.T} /tmp/p4-in`, `zip -dc -O ${t.T} /tmp/p4.zip /tmp/p4-in`, `zip -AC /tmp/p4.zip ${t.T}`, `zip -sf -b ${t.T} /tmp/p4.zip /tmp/p4-in`,
      // Residual 1: an unlisted long option or an unreadable chdir value leaves the working folder unknown
      `env --chdir=${t.PA} cp /tmp/p4-x ${t.F}`, `env --chdi=${t.PA} cp /tmp/p4-x ${t.F}`, `env --zz-unknown cp /tmp/p4-x ${t.F}`, `env -C "$D" cp /tmp/p4-x ${t.F}`,
      `env --chdir "$D" cp /tmp/p4-x ${t.F}`,
      `sudo --chdir=${t.PA} cp /tmp/p4-x ${t.F}`, `sudo --chdi=${t.PA} cp /tmp/p4-x ${t.F}`, `sudo --zz-unknown cp /tmp/p4-x ${t.F}`, `sudo -D "$D" cp /tmp/p4-x ${t.F}`,
      `sudo --chdir "$D" cp /tmp/p4-x ${t.F}`, `sudo -u root --zz-unknown mv /tmp/p4-x ${t.F}`,
      `doas --chdir=${t.PA} cp /tmp/p4-x ${t.F}`, `doas --zz-unknown cp /tmp/p4-x ${t.F}`, `doas -u root --chdi=${t.PA} install /tmp/p4-x ${t.F}`,
      // chains and wrappers around the same rows
      `true && env --zz-unknown cp /tmp/p4-x ${t.F}`, `(sudo --zz-unknown cp /tmp/p4-x ${t.F})`, `bash -c 'env --zz-unknown cp /tmp/p4-x ${t.F}'`, `env --zz-unknown sudo --user=root cp /tmp/p4-x ${t.F}`,
      `sudo --zz-unknown tee ${t.F} < /tmp/p4-x`, `sudo --zz-unknown rm -f ${t.F}`, `env --zz-unknown sh -c 'cp /tmp/p4-x ${t.F}'`,
    ]) {
      const d = sh(c);
      assert.equal(d.decision, 'stop', `${c}: ${d.reasons}`);
      assert.ok(d.hits.some((h) => h.category === 'S0'), `${c}: ${d.reasons}`);
    }
  }
});

test('patch round 4: a chdir option written with a dynamic value in one word is a dynamic command word and stops as before', () => {
  for (const c of ['env -C"$D" cp /tmp/p4-x notes.txt', 'env --chdir="$D" cp /tmp/p4-x notes.txt', 'sudo --chdir="$D" cp /tmp/p4-x notes.txt', 'sudo -D"$D" cp /tmp/p4-x notes.txt']) {
    assert.equal(sh(c).decision, 'stop', c);
  }
});

test('patch round 4 (abuse rows): repeated flags, variables and misleading words around the new rules', () => {
  for (const t of TARGETS) {
    for (const c of [
      // repeated flags: the last chdir counts, and an unlisted option after a readable one makes the folder unknown again
      `env --chdir=/tmp/p4-work --chdi=/tmp/p4-other cp /tmp/p4-x ${t.F}`, `sudo --chdir=/tmp/p4-work --zz-unknown cp /tmp/p4-x ${t.F}`, `env --chdir=/tmp/p4-work -C "$D" cp /tmp/p4-x ${t.F}`,
      `zip /tmp/p4.zip /tmp/p4-in -lf /tmp/p4.log -lf ${t.T}`, `zip /tmp/p4.zip /tmp/p4-in -TT true -TT "rm ${t.T}"`, `cd ${t.P} && cp -t/tmp -t${t.R} /tmp/p4-x`,
      // variables: the option or its value is a variable, so the word is dynamic
      `P=--zz-unknown; env $P cp /tmp/p4-x ${t.F}`, `D=${t.PA}; env -C $D cp /tmp/p4-x ${t.F}`, `L=-lf; zip /tmp/p4.zip /tmp/p4-in $L ${t.T}`,
    ]) {
      assert.equal(sh(c).decision, 'stop', c);
    }
    // misleading words: the option names are only text here
    for (const c of [`echo env --zz-unknown cp a ${t.F}`, `git commit -m "zip -lf ${t.T}"`, `echo "zip x.zip y -TT 'rm ${t.T}'"`, `printf '%s' "sudo --chd=${t.PA} cp x ${t.F}"`, `echo cd ${t.P} '&&' cp -t${t.R} x`]) {
      assert.equal(sh(c).decision, 'pass', c);
    }
    // a later readable chdir under a known absolute folder is the folder the command runs in
    assert.equal(sh('env --chdir=/tmp/p4-work --chdir=/tmp/p4-other cp a b').decision, 'pass');
  }
});

test('patch round 4: ordinary commands in the same shapes keep passing (friction controls on non-protected paths)', () => {
  for (const c of [
    'cp -tbuild a.txt', 'cp -t build a.txt', 'cp -rtbuild src', 'mv -tbuild a.txt', 'install -tbin a.sh', 'cp -Sbak a.txt b.txt', 'cp --reflink=auto -tbuild a.txt', 'cp --zz-unknown -tbuild a.txt',
    'zip -rq out.zip src', 'zip -r out.zip src', 'zip -rq out.zip src -x "*.git*"', 'zip -r9 out.zip src', 'zip -T out.zip src', 'zip -T -TT "unzip -tqq" out.zip src', 'zip -r -ds 1m out.zip src', 'zip -rdc out.zip src',
    'zip -q -lf out.log out.zip src', 'zip -rq out.zip src -tt 2030-01-01', 'zip -X- out.zip src', 'zip -sc out.zip src', 'zip -fz- out.zip big', 'zip -rq -UN=UTF8 out.zip src',
    'env --unset=FOO cp a b', 'env --unset FOO cp a b', 'env --chdir=/tmp/p4-work cp a b', 'env -C /tmp/p4-work cp a b', 'env -i FOO=1 cp /tmp/p4-a /tmp/p4-b', 'env --ignore-environment --null true',
    'env --block-signal=INT cp /tmp/p4-a /tmp/p4-b', 'env --debug --default-signal cp /tmp/p4-a /tmp/p4-b',
    'sudo --user=www cp a /var/www/x', 'sudo --user www cp /tmp/p4-a /tmp/p4-b', 'sudo --preserve-env=PATH install -m 644 a /tmp/p4-share/x', 'sudo --non-interactive --set-home cp /tmp/p4-a /tmp/p4-b',
    'sudo --role r --type t cp /tmp/p4-a /tmp/p4-b', 'sudo --chdir=/tmp/p4-work cp a b', 'sudo -D /tmp/p4-work cp a b', 'sudo --host=h --prompt=p --login ls',
    'doas -u www cp /tmp/p4-a /tmp/p4-b', 'doas cp /tmp/p4-a /tmp/p4-b',
    // absolute destinations under an unknown folder are judged as before
    'env --zz-unknown cp /tmp/p4-a /tmp/p4-b', 'sudo --zz-unknown cp /tmp/p4-a /tmp/p4-b', 'doas --zz-unknown cp /tmp/p4-a /tmp/p4-b', 'sudo -D "$D" cp /tmp/p4-a /tmp/p4-b',
    // a later readable chdir is the folder the command runs in (last one wins)
    'env --zz-unknown --chdir=/tmp/p4-work cp a b', 'sudo --zz-unknown -D /tmp/p4-work cp a b',
    // a wrapper that runs something that is no writer
    'env --zz-unknown ls', 'sudo --zz-unknown git status', 'sudo -D "$D" make install',
  ]) {
    const d = sh(c);
    assert.equal(d.decision, 'pass', `${c}: ${d.reasons}`);
  }
});

test('patch round 4: under an unknown working folder a relative write destination gets the S0 answer with the usual code; absolute ones are judged as before', () => {
  // doas has no long option: --chdir is not one of its options either, so the folder is unknown
  assert.equal(sh('doas --chdir=/tmp/p4-work cp a b').decision, 'stop');
  for (const c of ['env --zz-unknown cp a b', 'sudo --zz-unknown cp a b', 'doas --zz-unknown cp a b', 'env -C "$D" cp a b', 'sudo -D "$D" cp a b', 'env --zz-unknown touch notes.txt', 'sudo --zz-unknown rm -f notes.txt']) {
    const d = sh(c);
    assert.equal(d.decision, 'stop', `${c}: ${d.reasons}`);
    assert.deepEqual([...new Set(d.hits.map((h) => h.category))], ['S0'], `${c}: only S0`);
    assert.ok(d.reasons.every((r) => /_write_protected_path$/.test(r)), `${c}: the existing write code only: ${d.reasons}`);
  }
  // The stop text is the one every S0 stop has.
  const a = sh('env --zz-unknown cp a b');
  const b = sh(`cp /tmp/p4-x ${TARGETS[0].T}`);
  assert.equal(a.category, b.category);
  assert.equal(a.rule, b.rule);
  // An absolute protected destination stops as it always did, the folder option does not matter.
  assert.equal(sh(`env --zz-unknown cp /tmp/p4-x ${TARGETS[0].A}`).decision, 'stop');
});

test('patch round 4: the env, sudo and doas lists hold the full spellings of their documentation (unit)', { skip: L === null || !L.ENV_LONG }, () => {
  const w = (...t) => t.map((text) => ({ text }));
  assert.equal(L.unknownLong(w('--ignore-environment', '--null', '--unset=A', '--unset', 'B', '--chdir=/x', '--chdir', '/y', '--split-string=s', '--block-signal', '--block-signal=INT', '--debug', '--help', '--version'), L.ENV_LONG), -1);
  for (const bad of ['--chd=/x', '--chdi', '--unse=A', '--ignore', '--zz-unknown', '--null=1', '--argv0=x']) assert.equal(L.unknownLong(w(bad), L.ENV_LONG), 0, bad);
  assert.equal(L.unknownLong(w('--user=a', '--user', 'b', '--chdir=/x', '--preserve-env', '--preserve-env=PATH', '--login', '--shell', '--non-interactive', '--set-home', '--edit', '--host=h', '--role=r', '--type=t', '--chroot=/c', '--close-from=3', '--command-timeout=5', '--other-user=u', '--group=g', '--prompt=p', '--validate', '--list', '--version', '--help'), L.SUDO_LONG), -1);
  for (const bad of ['--chd=/x', '--chdi', '--us=a', '--preserve', '--zz-unknown', '--login=1', '--login-class=c', '--auth-type=a']) assert.equal(L.unknownLong(w(bad), L.SUDO_LONG), 0, bad);
  assert.equal(L.DOAS_LONG.size, 0, 'doas has no long option');
  assert.equal(L.unknownLong(w('--user=root'), L.DOAS_LONG), 0);
});
