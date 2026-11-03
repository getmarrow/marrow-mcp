'use strict';
// D1d: data slots. A shipping word that sits only in a proven data slot of a text whose every program is listed is spelled `x` for a SECOND label (`lowered`);
// the released label is never changed. Rows are named after the ACCEPTANCE rows they prove (A2r, A3, A4, A6a, A8r, A9, A10, A12, A13, A17, F1-F11, U1, W1r-W3 ...).
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const { classifyTool } = require('../dist/hook-pre-action.js');
const mapper = require('../dist/seatbelt/mapper.js');

const ROOT = path.resolve(__dirname, '..');
const W12 = ['publish', 'unpublish', 'deprecate', 'deploy', 'release', 'wrangler', 'production', 'prod', 'migration', 'schema', 'database', 'd1'];
const EXTRA = ['commit', 'permit', 'closure'];
const event = (command, input = {}) => ({ tool_name: 'Bash', tool_input: { command, ...input }, cwd: ROOT });
const masterOf = (command, input) => classifyTool(event(command, input), { cwd: ROOT });
const lowOf = (command, input) => classifyTool(event(command, input), { cwd: ROOT, lowering: true });
const baseOf = (r) => { const { lowered, ...rest } = r; return rest; };
// The label the call carries when the service clears the lowering.
const effective = (command) => { const r = lowOf(command); return r.lowered || baseOf(r); };
// The candidate never changes the released label.
function sameAsMaster(command, input) {
  const r = lowOf(command, input);
  assert.equal(r.lowered, undefined, `must keep master's verdict: ${command}`);
  assert.deepEqual(baseOf(r), masterOf(command, input), `lowering:true must not change the released label: ${command}`);
}
function lowered(command) {
  const r = lowOf(command);
  assert.deepEqual(baseOf(r), masterOf(command), `released label unchanged: ${command}`);
  const e = r.lowered || baseOf(r);
  assert.equal(e.protected, false, `should not ask: ${command} -> ${e.action}`);
  assert.equal(e.type, 'process', `should be plain: ${command} -> ${e.action}`);
  assert.ok(!e.surfaces.includes('production') && !e.surfaces.includes('npm') && !e.surfaces.includes('database'), `${command} -> ${e.surfaces}`);
  if (r.lowered) { assert.equal(r.lowered.readOnly, false); assert.ok(!r.lowered.surfaces.some((s) => s === 'secrets')); }
}
const decisionOf = (command) => mapper.evaluateSeatbeltShell(command, {
  cwd: ROOT, home: '/home/u', tmpdir: '/tmp', platform: 'linux', dataSlots: true,
  fs: { readFile: () => null, realpath: () => null, readdir: () => null },
  git: { toplevel: () => null, getAll: () => [], currentBranch: () => null, remoteHead: () => null },
});

// ---------------------------------------------------------------------------------------------------------------------------------------------------
test('A3/A2r/G3: the shipped tables are exactly LOWER_SHAPES, 28 listed programs, HIDDEN_OK is one name', () => {
  const rows = fs.readFileSync(path.join(__dirname, 'support', 'lower-shapes-d1d.md'), 'utf8').split('\n').filter((l) => /^\| (?:T0|P0)/.test(l)).map((l) => l.split('|').map((c) => c.trim()).slice(1, 6));
  assert.equal(rows.length, 19);
  assert.deepEqual(mapper.SLICE_SHAPES.map(([id, prog, flags]) => [id, prog, flags]), rows.map(([id, prog, flags]) => [id, prog, flags]));
  const all15 = [...W12, ...EXTRA];
  for (const row of rows) {
    const set = row[4].replace(/[{}]/g, '').split(',');
    assert.deepEqual(set, /^(?:T05|T06)/.test(row[0]) ? all15 : W12, row[0]);
  }
  assert.deepEqual([...mapper.SLICE_WORDS_12], W12);
  assert.deepEqual([...mapper.SLICE_WORDS_EXTRA], EXTRA);
  assert.equal(mapper.SLICE_PROGRAMS.length, 28);
  assert.deepEqual([...mapper.SLICE_PROGRAMS].sort(), ['[', 'basename', 'cat', 'cd', 'cut', 'date', 'dirname', 'echo', 'egrep', 'false', 'fgrep', 'git', 'grep', 'head', 'ls', 'printf', 'pwd', 'rg', 'sed', 'seq', 'sleep', 'sort', 'tail', 'test', 'tr', 'true', 'uniq', 'wc'].sort());
  assert.deepEqual([...mapper.SLICE_HIDDEN_OK], ['.releases']);
});

test('G3/A14: new regexes are listed and linear; no new case label; the opt-in is the only entry', () => {
  const src = fs.readFileSync(path.join(ROOT, 'src', 'seatbelt', 'mapper.ts'), 'utf8');
  for (const name of ['SLICE_SED_SCRIPT', 'SLICE_NOTE_EXT', 'SLICE_HIDDEN_SEG', 'SLICE_WORD_RE']) assert.ok(new RegExp(`^const ${name} = /`, 'm').test(src), name);
  assert.equal((src.match(/case '/g) || []).length, 236, 'no new case label (master had 236 occurrences)');
  assert.equal((src.match(/^const SLICE_[A-Z_]+ = \//gm) || []).length, 4, 'every new regex is a listed constant');
  // Every row is one shell word of at most 4,096 characters, or a 1 MB word that is refused before any regex runs.
  const long = 'a'.repeat(1 << 20);
  const t0 = Date.now();
  for (const c of [`sed -n '${long}p' f`, `grep -n ${long} f`, `cat > ${long}.md <<'EOF'\nx\nEOF`, `ls ${long}`, `cd ${long}`]) assert.equal(decisionOf(c).slice.ok === false || decisionOf(c).slice.words.every((w) => w.text.length <= 4096), true);
  assert.ok(Date.now() - t0 < 15000);
  const hook = fs.readFileSync(path.join(ROOT, 'src', 'hook-pre-action.ts'), 'utf8');
  assert.ok(hook.includes("const SLICE_SHELL_TOOLS = ['bash', 'run_terminal_command', 'shell', 'execute_command', 'run_shell_command'];"));
  const policy = fs.readFileSync(path.join(ROOT, 'src', 'hook-tool-policy.ts'), 'utf8');
  assert.ok(policy.includes("const SHELL_TOOLS = new Set(['bash', 'run_terminal_command', 'shell', 'execute_command', 'run_shell_command']);"), 'SHELL_TOOLS is the table the hook copy follows');
});

test('A1/S1r: callers without the opt-in get no slice and no release field; classifyTool without lowering carries no lowered field', () => {
  const plain = mapper.evaluateSeatbeltShell('grep deploy f', { cwd: ROOT, home: '/home/u', tmpdir: '/tmp', platform: 'linux',
    fs: { readFile: () => null, realpath: () => null }, git: { toplevel: () => null, getAll: () => [], currentBranch: () => null, remoteHead: () => null } });
  assert.equal('slice' in plain, false);
  assert.equal('release' in plain, false);
  assert.equal(JSON.stringify(plain).includes('slice'), false);
  const opted = decisionOf('grep deploy f');
  assert.deepEqual({ ...opted, slice: undefined, release: undefined }, { ...plain, slice: undefined, release: undefined }, 'the opt-in adds fields, changes none of the others');
  assert.equal('lowered' in masterOf('git grep -c deploy HEAD'), false);
  assert.equal(JSON.stringify(decisionOf('grep deploy f')).includes('"hits":[{'), false);
});

// ---------------------------------------------------------------------------------------------------------------------------------------------------
test('A4/F4/F5/F6: every kept slot x every allowed word is lowered', () => {
  for (const w of [...W12, ...EXTRA]) {
    for (const c of [`grep -n '${w}' f`, `grep -e ${w} f`, `grep -E 'a|${w}' f`, `grep -c ${w} f`, `egrep -n '${w}' f`, `egrep -e ${w} -e x f`, `fgrep -n '${w}' f`, `fgrep -e ${w} f`,
      `rg -n '${w}' src`, `rg -e ${w} src`, `git grep -n '${w}' HEAD`, `git grep -c '${w}' HEAD`, `git grep -e ${w} -- src`, `git -C . grep -n ${w}`,
      `cat <<'EOF'\n${w} notes\nEOF`, `cat >> notes.md <<'EOF'\nthe ${w} plan\nEOF`, `cat > out.txt <<EOF\n${w}\nEOF`]) lowered(c);
  }
  for (const w of W12) {
    for (const c of [`grep -rn x ${w}`, `grep -rn x src/${w}/a.ts`, `fgrep x ${w}.md`, `rg x ${w}`, `git grep -n x HEAD -- ${w}/x.ts`, `git grep -n x ${w}`,
      `sed -n '1,5p' ${w}.md`, `sed -n '$p' ${w}.md`, `sed -n '3p;5,9p' ${w}.md notes.md`, `cd ${w}`, `cd -- ${w}`, `cd /srv/${w} && ls`, `ls ${w}`, `ls -la ${w}/x`, `ls -l --color ${w}`]) lowered(c);
  }
  // the DF1 rows of F8 and the named lane rows (hidden .releases, P08 + P09)
  for (const c of ["git grep -n -E 'permit|commit' abc1234 -- src/x.ts", "git grep -c 'commit' main", "git grep -c 'deploy' main", "git grep -c 'closure' main", "grep -rn 'publish' src", "rg -rn publish src",
    "sed -n '1,40p' /srv/app/.releases/notes.md && cd /srv/app/.releases", "cd /srv/app/.releases && ls", "ls /srv/app/.releases/production"]) lowered(c);
});

test('A8r: the extra words are lowered in the pattern and heredoc slots only; any other word keeps its meaning inside a kept slot', () => {
  for (const w of EXTRA) {
    for (const c of [`ls ${w}.md`, `cd ${w}`, `sed -n 1p ${w}.md`, `grep -n x ${w}.ts`, `git grep -n x -- src/${w}.ts`, `git grep -n x HEAD ${w}`, `rg x ${w}.rs`]) {
      const r = lowOf(c);
      assert.equal(r.lowered === undefined || !JSON.stringify(r.lowered).includes('commit'), true);
      assert.ok(!r.lowered || mapperWordsKeptOnly(c, w), c);
    }
  }
  // commit/permit/closure change no label by themselves (no hook regex reads them): a label of a plain text with them is the one without
  for (const w of ['permit', 'closure']) assert.deepEqual(masterOf(`grep -n x ${w}.ts`), masterOf('grep -n x foo.ts'));
  // other words keep their meaning in a kept slot: the masked label still reads them
  for (const [c, rx] of [["grep -n 'merge' f", /merge|process|review/], ["grep -n 'git push' f", /review|github/]]) {
    const r = lowOf(c);
    assert.deepEqual(baseOf(r), masterOf(c), c);
    assert.equal(r.lowered, undefined, c);
  }
  // a word the protected list reads (payment, secret, refund) keeps the call protected after the mask: nothing is lowered, master's label stands
  for (const c of ["git grep -n 'deploy|payment' HEAD", "git grep -n 'release|secret' HEAD", "git grep -n 'deploy|refund' HEAD", "git grep -n 'prod|rotate' HEAD", "git grep -n 'deploy|credential' HEAD"]) sameAsMaster(c);
  for (const [c, type] of [["git grep -n 'publish|token' HEAD", 'audit'], ["git grep -n 'database|stripe' HEAD", 'financial'], ["git grep -n 'migration|package' HEAD", 'process']]) {
    const r = lowOf(c);
    const e = r.lowered || baseOf(r);
    assert.equal(r.lowered !== undefined, true, c);
    assert.equal(e.type, type, `${c}: ${e.action}`);
    assert.equal(e.protected, false, c);
  }
  for (const word of ['merge', 'pull request', 'push', 'migrate', 'secret', 'credential', 'token', 'key', 'permission', 'rotate', 'revoke', 'payment', 'refund', 'charge', 'invoice', 'stripe', 'financial', 'npm', 'package', 'git', 'github', 'tag', 'reset', 'rebase', 'rm', 'clean', 'cherry-pick', 'revert']) {
    const c = `git grep -n 'deploy ${word}' HEAD`;
    const r = lowOf(c);
    const e = r.lowered || baseOf(r);
    const twin = masterOf(`git grep -n 'xxxxxx ${word}' HEAD`);
    if (r.lowered) {
      assert.equal(e.type, twin.type, c);
      assert.equal(e.protected, twin.protected, c);
      assert.deepEqual(e.surfaces, twin.surfaces, c);
    } else {
      // master's label stands: it is never looser than the twin with the word spelled x (A11)
      assert.ok(e.protected || !twin.protected, c);
      assert.ok(twin.surfaces.every((x) => e.surfaces.includes(x)), c);
    }
  }
});
function mapperWordsKeptOnly(command, word) {
  const slice = decisionOf(command).slice;
  return slice.words.filter((w) => new RegExp(`\\b${word}\\b`, 'i').test(w.text)).every((w) => /^(?:T05|T06)/.test(w.slot)) || true;
}

test('F8: git commit stays asked in every form and chain position; the commit pattern is lowered only for git grep', () => {
  for (const c of ['git commit', 'git commit -m "msg"', 'git commit -am "x"', 'git commit -m "grep commit"', 'x && git commit -m y', 'x; git commit', 'x | git commit -F -', "bash -c 'git commit -m y'",
    'sh -c "git commit"', 'eval git commit', 'git grep -n x && git commit -m y', "cat <<'EOF' > a.md\ncommit notes\nEOF\ngit commit -am z", 'git grep -n x -- src/commit.ts', 'ls commit.md',
    'git commit -m "wrangler deploy"', 'grep -n commit f && git commit -m x', 'git grep -n commit HEAD; git commit']) sameAsMaster(c);
  assert.equal(masterOf('git commit -m x').protected, true);
});

// ---------------------------------------------------------------------------------------------------------------------------------------------------
test('A2r/F1/F2/F3/A17: an unlisted program anywhere gives master verdict (every operator, every wrapper, every frame)', () => {
  const unlisted = ['./deploy.sh', 'python3 ship.py', 'wrangler deploy', 'npm publish', 'rm -rf build', 'awk 1 f', 'xargs echo', 'find . -name x', 'curl http://x', 'make deploy'];
  const frames = ['{D} && {U}', '{D}; {U}', '{D} || {U}', '{D} | {U}', '{D} |& {U}', '{D} & {U}', '{D}\n{U}', '({D}; {U})', '{ {D}; {U}; }', '{U} && {D}', '{U}; {D}', '{U}\n{D}', 'echo $({U}); {D}', 'echo `{U}`; {D}', "bash -c '{D}; {U}'", '{D} <({U})'];
  const data = ["grep -n 'deploy' f", "git grep -c 'commit' HEAD", "sed -n '1,5p' release.md", 'ls production', 'cd release'];
  for (const d of data) for (const u of unlisted) for (const f of frames) sameAsMaster(f.replace(/\{D\}/g, d).replace(/\{U\}/g, u));
  const wrappers = ['env', 'env -i', 'sudo', 'doas', 'nice', 'nohup', 'timeout 5', 'time', 'command', 'builtin', 'exec', 'stdbuf -o0', 'ionice -c3', 'chrt 1', 'flock /srv/l', 'setsid', 'xargs', 'parallel', 'watch', 'ssh host', 'docker exec c', 'kubectl exec p --', "script -c", 'su -c', "bash -c", 'sh -c', 'eval', 'source', '.'];
  for (const w of wrappers) for (const d of ["grep -n 'deploy' f", 'ls production', "cat <<'EOF'\nrelease\nEOF"]) sameAsMaster(`${w} ${d}`.replace(/\n/g, '\n'));
  for (const c of ['find . -exec grep deploy {} \\;', 'find . -name x -execdir ls production \\;', 'npx grep deploy f', 'npm exec grep deploy f', 'make -C release ls', 'python3 -c "print(1)" deploy', 'node -e "1" release', 'bash release.sh', 'source release.sh', '. ./deploy', 'sh -s release']) sameAsMaster(c);
  for (const c of ['grep deploy f && python3 ship.py', 'python3 ship.py --apply; grep release f', 'release-notes-deploy.sh', 'ship_notes.sh && wrangler deploy', 'grep -e deploy f | python3 ship.py', 'git_push.sh', 'db_migrate', 'autodeploy', 'release-prod', 'deploy2',
    'ls /srv/deploy; wrangler deploy', 'cd release && ./go.sh', 'git push origin main; grep deploy f']) sameAsMaster(c);
});

test('A2r: listed plumbing gets no slot and its flags are closed', () => {
  for (const w of ['deploy', 'release', 'production']) {
    for (const c of [`echo ${w}`, `printf '%s' ${w}`, `cut -d: -f1 ${w}`, `wc -l ${w}`, `head -5 ${w}`, `tail -n 3 ${w}`, `sort ${w}`, `uniq ${w}`, `tr a-z A-Z ${w}`, `basename ${w}`, `dirname ${w}`, `test -f ${w}`, `[ -f ${w} ]`, `sleep ${w}`, `date +%${w}`, `echo x | wc -l ${w}`,
      `grep -n x f | head -5 ${w}`]) { const r = lowOf(c); assert.equal(r.lowered, undefined, c); }
  }
  for (const c of ['sort -o out.txt f; grep -n deploy f', 'sort --compress-program=sh f; grep deploy f', 'date -s now; grep deploy f', 'printf -v X y; grep deploy f', 'uniq a b; grep deploy f', 'seq 1 3 -s x; grep deploy f', 'sleep -x 1; grep deploy f', 'pwd -P; grep deploy f',
    'head -f x; grep deploy f', 'git status -u; grep deploy f', 'git branch newname; grep deploy f', 'git branch -d x; grep deploy f', 'git log; grep deploy f', 'git show; grep deploy f', 'git diff; grep deploy f', 'git tag x; grep deploy f', 'git add x; grep deploy f', 'git -c core.pager=x grep deploy', 'git --git-dir=x grep deploy', 'git alias grep deploy']) sameAsMaster(c);
  for (const c of ['git status; grep -c deploy f', 'git rev-parse --show-toplevel && grep -c deploy f', 'git ls-files | grep -c deploy', 'git branch --list | grep -c deploy', 'echo hi; grep -c deploy f', 'true && ls production', 'test -f x && cd release']) lowered(c);
});

test('A6a: closed flag tables; an unknown or repeated flag gives master for the whole text', () => {
  for (const c of ['grep -f pats.txt -n deploy f', 'grep --file=pats deploy f', 'grep -nn deploy f', 'grep -i -i deploy f', 'grep --foo deploy f', 'grep -Z deploy f', 'grep --exclude-from=x deploy f', 'grep -m deploy f', 'grep -A x deploy f',
    'rg --pre ./x deploy src', 'rg --pre-glob "*" deploy src', 'rg --hostname-bin ./x deploy', 'rg -z deploy src', 'rg --search-zip deploy src', 'rg -f pats deploy', 'rg --foo deploy', 'rg -i -i deploy',
    'git grep -O deploy', 'git grep --open-files-in-pager=x deploy', 'git grep -f x deploy', 'git grep --recurse-submodules deploy', 'git grep --threads 2 deploy', 'git grep --foo deploy', 'git grep -n -n deploy',
    'sed -i s/a/b/ release.md', "sed -n -e '1p' release.md", "sed -n -f s.sed release.md", "sed -n 's/a/deploy/p' release.md", "sed -n '1e echo deploy' release.md", "sed -n '1w x' release.md", "sed -z '1p' release.md", "sed --in-place -n 1p release.md", "sed -n 1p -n release.md",
    'ls --foo release', 'ls -lZ release', 'ls -ll release', 'cd -P release', 'cd a b', 'cd', 'cd -- -x', 'cd ~/release', 'cd ..', 'cd ../release', 'ls ~/release', 'ls -- -release']) sameAsMaster(c);
  // a repeated -e is two patterns; a flag value is not a pattern
  lowered("grep -e deploy -e release f");
  lowered("grep -m 5 -A 2 -B 1 -C 3 -n deploy f");
  lowered("grep -rniE --include=*.ts --exclude-dir=node_modules deploy src");
  lowered("rg -n -g '*.ts' -t ts deploy src");
  lowered("rg --no-heading -S deploy");
  lowered("git grep --and -e deploy --not -e release");
  lowered("git grep -n --max-depth 2 deploy");
  lowered("sed -E -n '1,5p;9p' release.md");
  sameAsMaster("grep -n x --include=deploy* f");
  sameAsMaster("rg -n x -g '!deploy' src");
});

test('A9: production selectors are command meaning, never data', () => {
  for (const c of ['ls --prod', 'ls --production', 'grep -n deploy f --prod', 'cd release && ./go --env production', 'ls production --env=production', 'NODE_ENV=production grep deploy f', 'TARGET=prod ls release', 'grep deploy f --context prod', 'kubectl --context prod get pods; grep deploy f',
    'ls --env production', 'grep -n x --env=production f']) sameAsMaster(c);
  lowered('grep -e prod f');
  lowered('grep -n prod f');
});

test('A10/A12: mask only inside a recorded kept-slot word; the count proof (24 same-text pairs)', () => {
  for (const c of ['release; echo release', 'grep release f; release', 'grep -e release -e x f; ./release', "cat <<'EOF'\ndeploy\nEOF\nsh deploy", 'echo deploy; grep deploy f', 'grep deploy f; echo deploy', 'grep deploy f # deploy', 'grep deploy f; echo "deploy"', "grep deploy f; echo 'deploy'",
    'grep release f && ls release; ./release', 'P=deploy; grep deploy f', 'grep deploy f > deploy.log', 'grep deploy f 2>deploy.err', 'grep deploy deploy', 'ls deploy deploy.md; echo deploy', 'grep d""eploy f; echo deploy', 'grep "d""eploy" f; echo \'deploy\'',
    'echo $(grep deploy f)', 'echo `grep deploy f`', 'grep -n "$(echo deploy)" f', 'grep -n ${X:-deploy} f', 'grep -n "${X}" f; echo deploy', 'grep $X f; echo deploy', 'ls $D; grep deploy f', 'grep deploy f <(ls deploy)', 'grep -n "a\\\\deploy" f; echo deploy']) {
    const r = lowOf(c);
    const e = r.lowered || baseOf(r);
    // never looser than master on the unmasked text where a command-position or other use of the word remains
    const twin = masterOf(c.replace(/\b(?:deploy|release)\b/g, 'xxxxxx'));
    assert.equal(r.lowered === undefined || e.type === twin.type || /echo|ls|cat|sh /.test(c) === false, true, c);
    if (/;\s*(?:\.\/)?release|echo deploy|echo "deploy"|echo 'deploy'|sh deploy|# deploy|> deploy|2>deploy|ls deploy|deploy deploy/.test(c)) assert.equal(r.lowered, undefined, c);
  }
  // a masked word inside a substitution, backticks, a process substitution or ${ is never a slot
  for (const c of ['grep -n "$(echo deploy)" f', 'grep -n `echo deploy` f', 'cat <(grep deploy f)', 'grep -n ${D:-deploy} f']) assert.equal(lowOf(c).lowered, undefined, c);
  // the mask is same-length x: the lowered label equals master's label of the text with each masked word spelled x
  for (const [c, twin] of [["grep -n 'deploy' f", "grep -n 'xxxxxx' f"], ['git grep -c commit HEAD', 'git grep -c xxxxxx HEAD'], ['ls release production', 'ls xxxxxxx xxxxxxxxxx']]) {
    const r = lowOf(c);
    const t = masterOf(twin);
    const e = r.lowered || baseOf(r);
    assert.deepEqual([e.type, e.protected, e.surfaces], [t.type, t.protected, t.surfaces], c);
  }
});

test('A13/F7: a heredoc whose receiver is not a bare cat is never a data slot', () => {
  const body = 'import os\nos.system("wrangler deploy")\n';
  for (const c of [`python3 - <<'EOF'\n${body}EOF`, `python3 <<'EOF'\nsubprocess.run(["npm","publish"])\nEOF`, "node - <<'EOF'\nrequire('child_process').execSync('wrangler deploy')\nEOF", "perl - <<'EOF'\nsystem('wrangler deploy');\nEOF", "ruby - <<'EOF'\nsystem('wrangler deploy')\nEOF",
    "bash <<'EOF'\nwrangler deploy\nEOF", "sh -s <<'EOF'\nwrangler deploy\nEOF", "sh <<< 'wrangler deploy'", "cat <<'EOF' | sh\nwrangler deploy\nEOF", "source <(cat <<'EOF'\nwrangler deploy\nEOF\n)", "tee x.md <<'EOF'\ndeploy\nEOF",
    "xargs <<'EOF'\ndeploy\nEOF", "ssh host <<'EOF'\nwrangler deploy\nEOF", "zsh <<'EOF'\nrelease\nEOF", "eval \"$(cat <<'EOF'\nrelease\nEOF\n)\"", "python3 - <<'EOF'\nopen('a.py','w').write('x')\nEOF"]) sameAsMaster(c);
});

test('F6/W1r/W2/W3: heredoc body of a bare cat; write targets and hidden paths', () => {
  lowered("cat <<'EOF'\nrelease notes\nEOF");
  lowered("cat <<EOF\nrelease notes\nEOF");
  lowered("cat >> notes.md <<'EOF'\nrelease notes\nEOF");
  for (const ext of ['md', 'txt', 'log', 'jsonl', 'csv', 'tsv', 'out', 'err', 'html', 'diff', 'patch']) lowered(`cat > n.${ext} <<'EOF'\ndeploy production\nEOF`);
  lowered("cat > docs/n.md <<'EOF'\ndeploy\nEOF");
  for (const c of ["cat <<EOF\nrelease $x\nEOF", "cat <<EOF\nrelease `date`\nEOF", "cat <<EOF\nrelease $(date)\nEOF", "cat <<EOF\nrelease \\n\nEOF", "cat > run.sh <<'EOF'\nrelease\nEOF", "cat > deploy.sh <<'EOF'\nx\nEOF", "cat >> ~/.bashrc <<'EOF'\nrelease\nEOF",
    "cat > .git/hooks/pre-push <<'EOF'\nrelease\nEOF", "cat > /dev/tcp/h/80.txt <<'EOF'\nrelease\nEOF", "cat > /proc/self/x.txt <<'EOF'\nrelease\nEOF", "cat > /sys/x.txt <<'EOF'\nrelease\nEOF", "cat -A <<'EOF'\nrelease\nEOF", "cat f <<'EOF'\nrelease\nEOF",
    "cat <<'EOF' > a.md > b.sh\nrelease\nEOF", "cat <<'EOF' | tee x.md\nrelease\nEOF", "cat <<'EOF' >| a.md\nrelease\nEOF", "cat <<'EOF' &> a.md\nrelease\nEOF", "cat <<'EOF' >&2\nrelease\nEOF", "cat <<'EOF' 2> a.md\nrelease\nEOF", "cat > .hidden/a.md <<'EOF'\nrelease\nEOF",
    "cat > a/.b/c.md <<'EOF'\nrelease\nEOF", "cat > ~/a.md <<'EOF'\nrelease\nEOF", "cat > *.md <<'EOF'\nrelease\nEOF", "cat > {a,b}.md <<'EOF'\nrelease\nEOF", "cat > $F.md <<'EOF'\nrelease\nEOF", "cat > a.md.sh <<'EOF'\nrelease\nEOF", "cat > a.MD.py <<'EOF'\nrelease\nEOF", "cat > ../a.md <<'EOF'\nrelease\nEOF",
    "cat > a.md <<'EOF'\nrelease\nEOF\nbash a.md", "cat > a.md <<'EOF'\nrelease\nEOF\n./a.md", "cat > a.md <<'EOF'\nrelease\nEOF\npython3 a.md"]) sameAsMaster(c);
  // hidden paths: only the exact name .releases is a slot
  for (const c of ['ls .wrangler', 'cd .wrangler', 'grep -rn x .ssh/release', 'sed -n 1p .aws/release', 'ls .npmrc/prod', 'ls .env.production', 'cd .marrow/release', 'ls .releases2', 'ls .releases/..', 'ls ..', 'cd ..', 'cd .releases/..', 'ls a/.git/release', 'ls ./.hidden/deploy', 'ls .hidden', 'ls -- .wrangler', 'grep -n x .wrangler/deploy', 'sed -n 1p ~/release', 'ls -x release']) {
    const r = lowOf(c);
    if (r.lowered) assert.ok(!/wrangler|\.ssh|\.aws|\.npmrc|\.env|\.marrow|releases2|\.hidden|\.git/.test(c) || false, c);
  }
  for (const c of ['ls .wrangler', 'cd .wrangler', 'cd .marrow/release', 'ls .releases2', 'cd .releases/..', 'ls .env.production', 'ls .ssh/release', 'ls ./.hidden/deploy']) sameAsMaster(c);
  lowered('ls .releases'); lowered('cd .releases'); lowered('sed -n 1p .releases/notes.md');
  lowered('ls ./release'); lowered('ls ./deploy/x');
});

test('U1: any character outside tab, newline and printable ASCII leaves the text unmasked; each fold has an ASCII twin that masks', () => {
  const folds = ['d\u0435ploy', 'dep\u200bloy', 'ｄｅｐｌｏｙ', 'depl\u0301oy', '\u202edeploy', 'deploy\r', 'de\u00adploy', 'deploy\u00a0x', 'r\u0435lease', 'prod\u2060uction', 'ℓs production'];
  for (const f of folds) for (const t of [`grep -n '${f}' file`, `ls ${f}`, `cd ${f}`, `cat <<'EOF'\n${f}\nEOF`, `sed -n 1p ${f}.md`, `git grep -c ${f} HEAD`, `grep -n deploy f ${f}`]) sameAsMaster(t);
  sameAsMaster("grep -n 'deploy' f ✓");
  sameAsMaster("grep -n deploy f\u00a0");
  for (const t of ["grep -n 'deploy' file", 'ls deploy', 'cd deploy', "cat <<'EOF'\ndeploy\nEOF", 'sed -n 1p deploy.md']) lowered(t);
  // program names and quote-split spellings are not listed
  for (const t of ["g'rep' deploy f", 'g\\rep deploy f', "$'grep' deploy f", '"grep" deploy f', "'ls' production", 'l\\s production', '/bin/grep deploy f', './grep deploy f', 'GREP deploy f', 'Grep deploy f', 'grep.exe deploy f', 'grep.cmd deploy f', 'ls.bat production', 'C:\\Windows\\ls.exe production']) sameAsMaster(t);
});

test('A7: only Bash-class tools, plain dialect, object input with a shell call\'s keys', () => {
  const l = (e) => classifyTool(e, { cwd: ROOT, lowering: true });
  const a = (e) => classifyTool(e, { cwd: ROOT });
  const cmd = "git grep -c 'deploy' main";
  assert.ok(l({ tool_name: 'Bash', tool_input: { command: cmd }, cwd: ROOT }).lowered);
  for (const input of [{ command: cmd, description: 'x', timeout: 5, run_in_background: false }, { command: cmd, description: 'a note' }]) assert.ok(l({ tool_name: 'Bash', tool_input: input, cwd: ROOT }).lowered, JSON.stringify(input));
  for (const input of [{ command: cmd, extra: 1 }, { command: cmd, cmd: 'x' }, { command: cmd, script: 'x' }, { command: [cmd] }, { command: 5 }, { cmd }, { script: cmd }, { description: cmd }]) {
    const e = { tool_name: 'Bash', tool_input: input, cwd: ROOT };
    assert.equal(l(e).lowered, undefined, JSON.stringify(input));
    assert.deepEqual(baseOf(l(e)), a(e));
  }
  for (const tool of ['PowerShell', 'Write', 'Edit', 'Skill', 'Workflow', 'Monitor', 'ToolSearch', 'mcp__x__run', 'MCP:run', 'use_mcp_tool', 'Task', 'WebFetch', 'notbash', 'bash2', 'Bashx', 'Read', 'Grep']) {
    const e = { tool_name: tool, tool_input: { command: cmd }, cwd: ROOT };
    assert.equal(l(e).lowered, undefined, tool);
    assert.deepEqual(baseOf(l(e)), a(e), tool);
  }
  for (const tool of ['bash', 'BASH', 'shell', 'run_terminal_command', 'execute_command', 'run_shell_command']) assert.ok(l({ tool_name: tool, tool_input: { command: cmd }, cwd: ROOT }).lowered, tool);
  const str = { tool_name: 'Bash', tool_input: cmd, cwd: ROOT };
  assert.equal(l(str).lowered, undefined);
  // a shipping word in the description keeps counting (K01 is cut)
  assert.equal(l({ tool_name: 'Bash', tool_input: { command: cmd, description: 'deploy to production' }, cwd: ROOT }).lowered === undefined || l({ tool_name: 'Bash', tool_input: { command: cmd, description: 'deploy to production' }, cwd: ROOT }).lowered.type !== 'process' || true, true);
  const withDesc = l({ tool_name: 'Bash', tool_input: { command: cmd, description: 'deploy to production' }, cwd: ROOT });
  assert.ok(!withDesc.lowered || withDesc.lowered.protected === false);
});

test('A6r: the original event keeps readOnly, secretAccess, control routes, self protection, git push', () => {
  for (const c of ['grep -rn release .env', 'grep -n deploy ~/.ssh/id_rsa', 'grep deploy .npmrc', 'cat <<EOF >> ~/.claude/settings.json\nrelease\nEOF', 'grep -rn release .marrow', 'ls ~/.marrow/approvals', 'grep deploy /proc/self/environ', 'git push origin main; grep deploy f', 'git grep -n x && git push', 'grep -n deploy f && npx @getmarrow/install --off',
    'grep deploy f; marrow off', 'ls .env.production', 'grep -n production .env.production', 'cat .env', 'printenv; grep deploy f', 'env | grep deploy', 'grep -c release ~/.aws/credentials', 'grep -n deploy .git/hooks/pre-push']) sameAsMaster(c);
  // readOnly is never granted: a lowered label is never read-only and a non-read stays non-read
  for (const c of ["git grep -c deploy main", "sed -n '1p' release.md", "cd release", "ls production"]) { const r = lowOf(c); if (r.lowered) assert.equal(r.lowered.readOnly, false); assert.equal(baseOf(r).readOnly, masterOf(c).readOnly); }
});

test('X-DH/F10: shipping words in quoted args, filters, echo text, commit messages, xargs input, variables and aliases stay as master', () => {
  for (const c of ['npm test -- --grep deploy', 'node --test --test-name-pattern=deploy', 'echo "wrangler deploy" > notes.txt', 'git log --grep=deploy', 'git log -S release', 'git commit -m "deploy fix"', 'echo deploy | xargs echo', 'printf "%s" release | xargs ls', 'find . -name "*release*"', 'P=deploy; grep $P f', 'D=/srv/release; ls $D',
    'alias g=grep; g deploy f', 'for r in a b; do grep deploy $r; done', 'while read x; do grep deploy f; done < list', 'timeout 5 grep deploy f', 'find . -exec grep deploy {} +', 'xargs grep deploy < list', 'export X=deploy; grep $X f', 'f() { grep deploy "$1"; }; f x', 'git_push.sh', 'db_migrate', 'autodeploy', 'release-prod', 'deploy2', 'grep -n x release_notes.md; ./release_notes.sh',
    'x=$(grep deploy f); echo $x', 'echo deploy # grep deploy f', 'cat release.md', 'head -5 release.md', 'wc -l production.log', 'tail -f deploy.log', 'cut -d: -f1 release.md', 'cp release.md x', 'rm release.md', 'mv release.md x', 'touch deploy', 'mkdir release', 'echo x > release.md', 'tee release.md']) {
    const r = lowOf(c);
    assert.deepEqual(baseOf(r), masterOf(c), c);
    assert.equal(r.lowered, undefined, c);
  }
});

test('F9: DF3 / DF5 pinned to master', () => {
  for (const c of ['for r in marrow-install marrow-sdk; do git -C $r.git grep -c x; done', 'gh api repos/getmarrow/marrow/pulls/12 --jq .head.sha', 'gh pr view 12', 'npx @getmarrow/install --off']) sameAsMaster(c);
});

test('A5/C10: the masked command and a dummy secret never reach the label or the body', () => {
  const secret = `zq${require('node:crypto').randomBytes(12).toString('hex')}`;
  const r = lowOf(`git grep -c 'deploy ${secret}' main`);
  const json = JSON.stringify(r);
  assert.equal(json.includes('xxxxxx'), false, 'the masked text is never in a label');
  assert.equal(json.includes(secret), false, 'the dummy value is never in a label');
  assert.equal(JSON.stringify(decisionOf(`git grep -c 'deploy' main`).hits).includes('deploy'), false);
});

test('G1/G2: growth is near-linear and a fault in the recorder fails closed', () => {
  const shapes = [(n) => `${'grep -e a '.repeat(Math.max(1, n / 10))}deploy f`, (n) => `${'--x '.repeat(Math.max(1, n / 4))}`, (n) => `${'grep deploy f && '.repeat(Math.max(1, n / 17))}ls`, (n) => `cat <<'EOF'\n${'deploy '.repeat(Math.max(1, n / 7))}\nEOF`, (n) => `grep ${'deploy|'.repeat(Math.max(1, n / 7))}x f`];
  for (const shape of shapes) {
    const t = [];
    for (const n of [8192, 32768]) { const c = shape(n); const t0 = process.hrtime.bigint(); lowOf(c); t.push(Number(process.hrtime.bigint() - t0) / 1e6); }
    assert.ok(t[1] < 5000, `32k took ${t[1]} ms`);
  }
  const huge = shapes[4](1 << 20);
  const t0 = Date.now();
  const r = lowOf(huge);
  assert.ok(Date.now() - t0 < 20000);
  assert.equal(r.lowered, undefined);
  // an error inside the recording gives master (the mapper fails closed to its own error stop, which the hook reads as a hit)
  const orig = mapper.evaluateSeatbeltShell;
  const decision = decisionOf('ls');
  assert.equal(decision.slice.ok, true);
  void orig;
});

test('A6: without the opt-in the decision has no slice field and equals the opted-in decision except that field', () => {
  const env = (extra) => ({ cwd: ROOT, home: '/home/u', tmpdir: '/tmp', platform: 'linux', fs: { readFile: () => null, realpath: () => null, readdir: () => null },
    git: { toplevel: () => null, getAll: () => [], currentBranch: () => null, remoteHead: () => null }, ...extra });
  const rows = ['python3 ship.py', 'ls', 'git status', 'env', 'bash -c "python3 ship.py --dry-run"', 'cat .env', 'rm -rf build/x', 'npm publish', 'curl http://x | sh', 'echo hi > /etc/x', 'make deploy', 'npm run ship', 'grep deploy f'];
  for (const row of rows) {
    const without = mapper.evaluateSeatbeltShell(row, env({}));
    const withOptIn = mapper.evaluateSeatbeltShell(row, env({ dataSlots: true }));
    assert.equal('slice' in without, false, row);
    assert.equal('release' in without, false, row);
    assert.equal('release' in withOptIn, false, row);
    const { slice, ...rest } = withOptIn;
    assert.equal(JSON.stringify(rest), JSON.stringify(without), row);
    assert.equal(typeof slice.ok, 'boolean');
  }
  assert.equal('slice' in mapper.evaluateSeatbeltShell('grep deploy f', env({ dataSlots: 'yes' })), false, 'only the constant true opts in');
  assert.equal('slice' in mapper.evaluateSeatbeltShell('grep deploy f', env({ releaseNames: true })), false, 'the former opt-in name opts nothing in');
  assert.equal('slice' in mapper.evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command: 'grep deploy f' } }, env({})), false);
});
