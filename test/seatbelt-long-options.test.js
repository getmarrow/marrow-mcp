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
