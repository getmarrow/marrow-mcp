'use strict';

// Regression tests for the r4 micro-patch of the seatbelt category mapper: the final delta audit of
// c7947a36 (Barvis, 2026-10-12, FAIL: B1 bash arrays, B2 wrangler global flags, B3 a branch change
// that runs concurrently with the trimmed command, B4 push refspec mapping). Every repro of the audit
// is a row here and fails on c7947a36. Dummy values only.
const test = require('node:test');
const assert = require('node:assert/strict');

const { evaluateSeatbelt, evaluateSeatbeltShell } = require('../dist/seatbelt/mapper.js');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');

const sh = (cmd, opts) => evaluateSeatbeltShell(cmd, makeEnv(opts || {}));
const stops = (cmd, opts) => assert.equal(sh(cmd, opts).decision, 'stop', cmd);
const passes = (cmd, opts) => assert.equal(sh(cmd, opts).decision, 'pass', `${cmd} [${sh(cmd, opts).reasons.join(',')}]`);
const F = { current: 'feat/x' };
const W = 'wrangler pages deploy dist';
const T3 = 'git push origin "$(git branch --show-current)"';
const T3f = 'git push -f origin "$(git branch --show-current)"';
const MAP_MAIN = { 'remote.origin.push': ['+refs/heads/feat/x:refs/heads/main'] };

// ---------------------------------------------------------------------------------------------
// B1: array contents are not modelled; every array syntax makes the name unresolved.

test('B1: the six review repros stop', () => {
  for (const cmd of [
    'cmd=(npm test); cmd[1]=publish; "${cmd[@]}"',
    'cmd=(git push); "${cmd[@]}" -f origin main',
    'w=(wrangler pages deploy); "${w[@]}" dist --branch main',
    'c=(ls /home/u); c[0]=rm; c[2]=-rf; "${c[@]}"',
    'cmd=(git push); ${cmd[*]} -f origin main',
    'a=(git status); a[1]=push; a[2]=-f; a[3]=origin; a[4]=main; "${a[@]}"',
  ]) stops(cmd, F);
});

test('B1: arrays in bash -c, functions, loops, += appends, unset and a nested substitution stop', () => {
  for (const cmd of [
    `bash -c 'cmd=(git push); "\${cmd[@]}" -f origin main'`,
    `sh -c 'c=(npm test); c[1]=publish; "\${c[@]}"'`,
    'f() { c=(npm test); c[1]=publish; "${c[@]}"; }; f',
    'for x in 1 2; do c=(npm test); c[1]=publish; "${c[@]}"; done',
    'while true; do c=(npm test); c[1]=publish; "${c[@]}"; break; done',
    'cmd=(npm); cmd+=(publish); "${cmd[@]}"',
    'cmd=(git); cmd+=(push -f origin main); "${cmd[@]}"',
    "a=(npm test publish); unset 'a[1]'; \"${a[@]}\"",
    'a=(rm -rf x /home/u); unset a[2]; "${a[@]}"',
    'c=(npm test); c[1]=publish; x=$( "${c[@]}" )',
    'c=(npm test); c[1]=publish; echo $( "${c[@]}" )',
    'c=(npm test); c[1]=publish; `"${c[@]}"`',
    'eval \'c=(npm test); c[1]=publish; "${c[@]}"\'',
    'c=(npm test); (c[1]=publish; "${c[@]}")',
    '{ c=(npm test); c[1]=publish; }; "${c[@]}"',
  ]) stops(cmd, F);
});

test('B1: declare -a/-A, local -a, mapfile, readarray and read -a make the name unresolved', () => {
  for (const cmd of [
    'declare -a c=(npm publish); "${c[@]}"',
    'typeset -a c; c[0]=npm; c[1]=publish; "${c[@]}"',
    'declare -A m; m[x]=npm; "${m[x]}" publish',
    'f() { local -a c=(git push -f origin main); "${c[@]}"; }; f',
    'mapfile -t c <<< "npm publish"; "${c[@]}"',
    'readarray -t c <<< "git push -f origin main"; "${c[@]}"',
    "read -ra c <<< 'rm -rf /home/u'; \"${c[@]}\"",
    'c=(npm test); n=${#c[@]}; "${c[0]}" publish',
    'c=(npm test); k=${!c[@]}; "${c[@]:0:1}" publish',
    'c=npm; "${c[0]}" publish',
    'c=npm; c[0]=git; "$c" push -f origin main',
  ]) stops(cmd, F);
});

test('B1: a literal element of an array stays a classified reading (never looser than c7947a36)', () => {
  for (const cmd of [
    'f=(/home/u/.aws/credentials); cat "${f[@]}"',
    'f=(~/.aws/credentials); cat ${f[0]}',
    'f=(a); f[1]=/home/u/.ssh/id_ed25519; cat "${f[@]}"',
    'f=(a /home/u/.aws/credentials); cat "${f[@]}"',
    'f=(~/.aws/credentials); cat "$f"',
    'p=(/home/u); rm -rf "${p[@]}"',
    'c=(/home/u/.claude/settings.json); echo x > "${c[0]}"',
    'f=(a); f+=(/home/u/.aws/credentials); cat "${f[@]}"',
    'bash -c \'f=(/home/u/.aws/credentials); cat "${f[@]}"\'',
  ]) stops(cmd, F);
  // The readings follow the name through an assignment, a loop variable, a redirect target and `cd`.
  for (const cmd of [
    'c=(/home/u/.aws/credentials); x="${c[0]}"; cat "$x"',
    'c=(a /home/u/.aws/credentials); x="${c[@]}"; cat $x',
    'c=(/home/u/.aws/credentials); for f in "${c[@]}"; do cat "$f"; done',
    'c=(a /home/u/.ssh/id_ed25519); for f in x "${c[@]}"; do cat "$f"; done',
    'c=(/home/u/.claude/settings.json); echo x > "${c[0]}"',
    'c=(/home/u/.aws); cd "${c[0]}"; cat credentials',
    'c=(/home/u/.aws); cd "$c" && cat credentials',
  ]) stops(cmd, F);
  // Elements that are not secret stay quiet.
  passes('c=(README.md); x="${c[0]}"; cat "$x"', F);
  passes('c=(a b); for f in "${c[@]}"; do cat "$f"; done', F);
  passes('c=(src); cd "${c[0]}"; cat index.ts', F);
  passes('f=(README.md package.json); cat "${f[@]}"', F);
  passes('f=(dist coverage); echo "${f[0]}"', F);
});

test('B1: the audit array rows behave as the auditor expected, except the two documented pass rows', () => {
  const rows = require('./fixtures/seatbelt/audit-r4/arrays.cjs');
  // Documented deviation (brief r4, B1): array contents are not modelled, so a command word that is an
  // array expansion is unresolved and stops, as at 452da607. The auditor had expected a pass.
  const stricter = new Set(['A:pass-test', 'A:pass-prefix-test']);
  const wrong = [];
  for (const row of rows) {
    const want = stricter.has(row.id) ? 'stop' : row.expect;
    const d = sh(row.cmd, F);
    if (d.decision !== want) wrong.push(`${row.id} want=${want} got=${d.decision}`);
  }
  assert.deepEqual(wrong, []);
  assert.equal(stricter.size, 2);
});

test('B1: ordinary scalar variables and array text that never runs stay quiet', () => {
  for (const cmd of [
    'x=npm; "$x" test',
    'files=(a b c); echo "${files[@]}"',
    'files=(a b c); for f in "${files[@]}"; do echo "$f"; done',
    'n=3; echo $n',
    'a=(1 2 3); echo ${#a[@]}',
    'declare -a names=(x y); printf "%s\\n" "${names[@]}"',
    'echo [a-z]* | head -1',
  ]) passes(cmd, F);
});

// ---------------------------------------------------------------------------------------------
// B2: wrangler global flags and environment move the Pages branch; only a short allowlist keeps T1.

test('B2: --cwd anywhere, --config/-c, --env-file, empty --branch=, unknown flags and WRANGLER_/CF_PAGES_ variables stop', () => {
  for (const cmd of [
    `${W} --cwd ../other-repo`,
    `${W} --cwd=../other-repo`,
    'wrangler pages deploy --cwd /home/u/other-repo dist',
    'npx wrangler pages deploy dist --cwd=/home/u/other-repo',
    `${W} --cwd "$D"`,
    'wrangler --cwd ../other-repo pages deploy dist',
    'wrangler --cwd=../other-repo pages deploy dist',
    'wrangler pages --cwd ../other-repo deploy dist',
    'wrangler --some-global-flag x pages deploy dist',
    'wrangler pages --some-global-flag x deploy dist',
    'wrangler --some-global-flag x pages deploy dist --branch main',
    `${W} --config ../other/wrangler.toml`,
    `${W} -c ../other/wrangler.toml`,
    `${W} --env-file ../other/.env`,
    `${W} --branch=`,
    `${W} --branch ""`,
    `${W} --unknown-flag`,
    `${W} --env production`,
    `${W} -e production`,
    `${W} --experimental-json-config`,
    `${W} --`,
    `${W} "$FLAG"`,
    'wrangler pages deploy "$DIR"',
    `WRANGLER_SEND_METRICS=false ${W}`,
    `CF_PAGES_BRANCH=main ${W}`,
    `export WRANGLER_LOG=debug; ${W}`,
    `env CF_PAGES_COMMIT_SHA=abc ${W}`,
    `WRANGLER_C3_COMMAND=x npx ${W}`,
  ]) stops(cmd, F);
});

test('B2: --cwd with an explicit branch keeps the explicit-branch rule', () => {
  stops('wrangler --cwd ../other-repo pages deploy dist --branch main', F);
  stops('wrangler pages deploy dist --branch main --cwd ../other-repo', F);
  passes('wrangler --cwd ../other-repo pages deploy dist --branch feat/x', F);
});

test('B2: the allowlisted Pages deploy flags keep T1', () => {
  for (const cmd of [
    W,
    `${W} --project-name site`,
    `${W} --project-name=site`,
    `${W} --commit-dirty=true`,
    `${W} --commit-dirty true --commit-hash abc123`,
    `${W} --commit-message "fix: x"`,
    `${W} --skip-caching`,
    `${W} --no-bundle`,
    `${W} --project-name site --skip-caching --no-bundle`,
    'npx wrangler pages deploy ./out --project-name site',
    'wrangler pages deploy --project-name site dist',
  ]) passes(cmd, F);
  stops(W, { current: 'main' });
  stops(W, { current: null });
});

// ---------------------------------------------------------------------------------------------
// B3: T1 and T3 only for the last command of a plain top-level list, with nothing concurrent.

test('B3: the review repros stop', () => {
  for (const cmd of [
    `${W} & git checkout main`,
    `${W} | git checkout main`,
    `(${W}) & git checkout main`,
    `${T3f} & git checkout main`,
    `${T3f} | git checkout main`,
    `${T3f} & echo "ref: refs/heads/main" > .git/HEAD`,
    `for i in 1; do ${W} | git branch -m main; done`,
    `(sleep 2; ${W}) & git checkout main`,
    `{ sleep 2; ${W}; } | git checkout main`,
    `(sleep 2; ${T3f}) & git checkout main`,
    `{ sleep 2; ${T3f}; } & git switch main; wait`,
  ]) stops(cmd, F);
});

test('B3: nohup, coproc, disown, setsid, ( … ) &, { …; } | cat and other shapes around the trimmed command stop', () => {
  for (const cmd of [
    `nohup ${W} & git checkout main`,
    `nohup ${W} >/dev/null 2>&1 &`,
    `${W} &`,
    `${W} & disown; git checkout main`,
    `${W} & disown`,
    `coproc ${W}; git checkout main`,
    `coproc { ${W}; }`,
    `setsid ${W}; git checkout main`,
    `setsid -f ${W} & git checkout main`,
    `git checkout main & setsid -f ${W}`,
    `(${W}) &`,
    `( ${W} ) & git checkout main`,
    `{ ${W}; } | cat`,
    `{ ${W}; } &`,
    `${W} | cat`,
    `${W} |& cat`,
    `${W} 2>&1 | tee deploy.log`,
    `${W}; git checkout main`,
    `${W} && git checkout main`,
    `${W} || git checkout main`,
    `${W}\ngit checkout main`,
    `${W}; echo done`,
    `if true; then ${W}; fi`,
    `for i in 1; do ${W}; done`,
    `while true; do ${W}; break; done`,
    `( ${W} )`,
    `{ ${W}; }`,
    `f() { ${W}; }; f`,
    `bash -c '${W}'`,
    `sh -c "${W}"`,
    `eval '${W}'`,
    `time ${W}`,
    `trap 'git checkout main' EXIT; ${W}`,
    `alias wrangler='git checkout main; command wrangler'; ${W}`,
    `PROMPT_COMMAND='git checkout main'; ${W}`,
    `BASH_ENV=/tmp/x.sh ${W}`,
    `export ENV=/tmp/x.sh; ${W}`,
    `echo dist | xargs wrangler pages deploy`,
    `sleep 1 & ${W}`,
    `true & ${T3}`,
    `echo y | ${W}`,
    `true | ${T3}`,
    `trap 'echo bye' EXIT; ${W}`,
    `trap 'echo bye' EXIT; ${T3}`,
    `alias ll='ls -l'; ${W}`,
    `PROMPT_COMMAND=true; ${W}`,
    `${T3} &`,
    `${T3} | cat`,
    `${T3}; git checkout main`,
    `${T3} && git checkout main`,
    `nohup ${T3} & git checkout main`,
    `coproc ${T3}; git checkout main`,
    `{ ${T3}; } | cat`,
    `( ${T3} ) & git checkout main`,
    `bash -c '${T3}'`,
    `trap 'git checkout main' EXIT; ${T3}`,
    `if true; then ${T3}; fi`,
    `f() { ${T3}; }; f`,
  ]) stops(cmd, F);
});

test('B3: everyday shapes still pass on an unprotected branch', () => {
  for (const cmd of [
    W,
    `npm run build && ${W}`,
    `npm run build && ${W} --project-name site`,
    `npm test; ${W}`,
    'git status && wrangler pages deploy dist',
    T3,
    T3f,
    `git add -A && git commit -m x && ${T3}`,
    `git add -A && git commit -m "feat: x" && ${T3}`,
    `git fetch origin && git merge origin/feat/x && ${T3f}`,
    `npm test 2>&1 | tail -3 && ${T3}`,
    `${T3} 2>&1`,
    `${W} > deploy.log 2>&1`,
    `git commit -m "a & b" && ${T3}`,
    `x=1\n${W}`,
    `setsid -f ${W}`,
    `nohup ${W}`,
  ]) {
    // `a & b` inside a quoted message is the one shape the guard cannot tell from a background
    // operator: it stops (fail closed). Everything else passes.
    if (cmd.includes('"a & b"')) { stops(cmd, F); continue; }
    passes(cmd, F);
  }
});

test('B3: a branch change earlier in the same line still stops (existing head check)', () => {
  for (const cmd of [`git checkout main && ${W}`, `git switch main; ${T3}`, `cd ../other-repo && ${W}`, `git -C ../other-repo checkout main && ${T3}`]) stops(cmd, F);
});

test('B3: MCP shell tool events apply the same shape rule (the last text only)', () => {
  const ev = (tool_input) => evaluateSeatbelt({ tool_name: 'Bash', tool_input }, makeEnv(F));
  assert.equal(ev({ command: W }).decision, 'pass');
  assert.equal(ev({ command: `${W} & git checkout main` }).decision, 'stop');
  assert.equal(ev({ command: `npm run build && ${T3}` }).decision, 'pass');
  assert.equal(ev({ command: `${T3} | cat` }).decision, 'stop');
});

// ---------------------------------------------------------------------------------------------
// B4: a push mapping (remote.<r>.push and friends) set in the line, or known in the repo config.

test('B4: the review repros stop', () => {
  stops('git -c remote.origin.push=refs/heads/feat/x:refs/heads/main push -f origin "$(git branch --show-current)"', F);
  stops('git config remote.origin.push +refs/heads/feat/x:refs/heads/main && git push origin "$(git branch --show-current)"', F);
  stops(T3f, { current: 'feat/x', gitConfig: MAP_MAIN });
  stops(T3, { current: 'feat/x', gitConfig: MAP_MAIN });
  stops('git push -f origin feat/x', { current: 'feat/x', gitConfig: MAP_MAIN });
});

test('B4: wildcard and HEAD mappings, push.default=upstream with an upstream of main, and unreadable config', () => {
  stops(T3f, { current: 'feat/x', gitConfig: { 'remote.origin.push': ['+refs/heads/*:refs/heads/main'] } });
  stops('git push -f origin feat/x', { current: 'feat/x', gitConfig: { 'remote.origin.push': ['+refs/heads/*:refs/heads/main'] } });
  stops(T3f, { current: 'feat/x', gitConfig: { 'remote.origin.push': ['refs/heads/*:refs/heads/*'] } });
  stops(T3f, { current: 'feat/x', gitConfig: { 'remote.origin.push': ['HEAD:main'] } });
  stops('git push -f origin feat/x', { current: 'feat/x', gitConfig: { 'remote.origin.push': ['HEAD:main'] } });
  stops('git push -f origin HEAD', { current: 'feat/x', gitConfig: { 'remote.origin.push': ['HEAD:main'] } });
  // push.default only chooses the destination when no refspec is given (git-push(1)): with an explicit
  // branch name the push goes to that name, so repo config alone does not stop T3; without a refspec
  // the existing rule applies.
  passes(T3f, { current: 'feat/x', gitConfig: { 'push.default': ['upstream'], 'branch.feat/x.merge': ['refs/heads/main'] } });
  stops('git push -f', { current: 'feat/x', gitConfig: { 'push.default': ['upstream'], 'branch.feat/x.merge': ['refs/heads/main'] } });
  stops('git -c push.default=upstream -c branch.feat/x.merge=refs/heads/main push -f', F);
  stops('git -c push.default=upstream push -f origin "$(git branch --show-current)"', F);
  // The config cannot be read: no trim for T3.
  stops(T3, { current: 'feat/x', gitThrows: true });
  stops(T3f, { current: 'feat/x', gitThrows: true });
});

test('B4: every setting in the line that can map or redirect the push stops T3 and a forced literal push', () => {
  for (const setting of [
    'git -c remote.origin.push=+refs/heads/feat/x:refs/heads/main',
    'git -c push.default=upstream',
    'git -c remote.origin.pushurl=git@example.com:o/r.git',
    'git -c remote.origin.url=git@example.com:o/r.git',
    'git -c url.git@example.com:.pushInsteadOf=https://example.com/',
    'git -c branch.feat/x.merge=refs/heads/main',
    'git --config-env=remote.origin.push=MAPVAR',
    'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=remote.origin.push GIT_CONFIG_VALUE_0=+refs/heads/feat/x:refs/heads/main git',
    "GIT_CONFIG_PARAMETERS=\"'remote.origin.push=+refs/heads/feat/x:refs/heads/main'\" git",
    'GIT_CONFIG_GLOBAL=/tmp/g.cfg git',
    'GIT_CONFIG_SYSTEM=/tmp/s.cfg git',
  ]) {
    stops(`${setting} push origin "$(git branch --show-current)"`, F);
    stops(`${setting} push -f origin "$(git branch --show-current)"`, F);
    stops(`${setting} push -f origin feat/x`, F);
    stops(`${setting} push origin feat/x`, F);
  }
  // A read-only mention counts as well (fail closed): the text is not told apart from a write.
  stops(`git config --get remote.origin.push && ${T3f}`, F);
  stops(`git config --get remote.origin.url; ${T3}`, F);
  for (const cfg of ['remote.origin.push', 'push.default', 'remote.origin.pushurl', 'remote.origin.url', 'url.x.pushInsteadOf', 'branch.feat/x.merge']) {
    stops(`git config ${cfg} refs/heads/main && ${T3}`, F);
    stops(`git config --add ${cfg} refs/heads/main && ${T3f}`, F);
    stops(`git config ${cfg} refs/heads/main; git push -f origin feat/x`, F);
  }
});

test('B4: literal branch names and everyday pushes keep 452da607 behaviour', () => {
  for (const cmd of ['git push origin feat/x', 'git push -u origin feat/x', 'git push -f origin feat/x', 'git push --force-with-lease origin feat/x', 'git push origin HEAD']) passes(cmd, F);
  // Unknown or unrelated config: no new stop.
  passes('git push -f origin feat/x', { current: 'feat/x', gitThrows: true });
  passes('git push -f origin feat/x', { current: 'feat/x', gitConfig: { 'remote.origin.push': ['refs/heads/feat/y:refs/heads/feat/y'] } });
  passes('git push -f origin feat/x', { current: 'feat/x', gitConfig: { 'remote.origin.push': ['refs/heads/main:refs/heads/main'] } });
  passes(T3, { current: 'feat/x', gitConfig: { 'remote.origin.push': ['refs/heads/main:refs/heads/main'] } });
  passes(T3f, { current: 'feat/x', gitConfig: { 'remote.origin.push': ['+refs/heads/feat/x:refs/heads/feat/x'] } });
  // A `+` in the configured mapping forces the push without -f on the command line.
  stops('git push origin feat/x', { current: 'feat/x', gitConfig: { 'remote.origin.push': ['+refs/heads/feat/x:refs/heads/main'] } });
  stops('git push origin HEAD', { current: 'feat/x', gitConfig: { 'remote.origin.push': ['+HEAD:refs/heads/main'] } });
  stops('git -c remote.origin.push=+refs/heads/feat/x:refs/heads/main push origin feat/x', F);
  stops('git -c remote.origin.push=refs/heads/feat/x:refs/heads/main push -f origin feat/x', F);
  // A mapping onto a protected ref without a `+` and without -f is the non-force push of Q1: flag only.
  passes('git push origin feat/x', { current: 'feat/x', gitConfig: { 'remote.origin.push': ['refs/heads/feat/x:refs/heads/main'] } });
  // A forced push to main stays a stop, with or without config.
  stops('git push -f origin main', F);
  stops('git push origin +feat/x:main', F);
});
