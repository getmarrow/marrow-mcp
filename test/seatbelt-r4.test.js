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

