'use strict';

// Mutation check for the seatbelt mapper (not part of `npm test`; run after `npm run build`):
//   node test/support/seatbelt-mutants.cjs
// Each mutant edits dist/seatbelt/*.js in place, runs test/seatbelt-mapper.test.js, and restores the
// file. A mutant is killed when the test run fails. Exit 1 if any mutant survives.
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..', '..');
const MAPPER = path.join(ROOT, 'dist', 'seatbelt', 'mapper.js');

const MUTANTS = [
  {
    name: 'last-wins removed (first occurrence of a repeated flag decides)',
    file: MAPPER,
    edits: [
      // Both boolFlag and valueFlag stop at the first occurrence.
      ['        if (a.text === \'--\')\n            break;\n        const t = a.text;\n        if (names.includes(t)) {',
        '        if (a.text === \'--\')\n            break;\n        if (typeof state !== \'undefined\' ? state !== \'absent\' : value !== undefined)\n            break;\n        const t = a.text;\n        if (names.includes(t)) {'],
    ],
  },
  {
    name: 'classifier "routine" treated as a pass for S categories',
    file: MAPPER,
    edits: [
      ['function evaluateSeatbeltShell(command, env) {', 'function evaluateSeatbeltShell(command, env) {\n    if (env.classifierClass === \'routine\')\n        return finish(newRun(env, \'\'));'],
      ['function evaluateSeatbelt(event, env) {', 'function evaluateSeatbelt(event, env) {\n    if (env.classifierClass === \'routine\')\n        return finish(newRun(env, \'\'));'],
    ],
  },
  {
    name: '.env template exception widened to every .env file',
    file: MAPPER,
    edits: [['tables_1.ENV_TEMPLATE_SUFFIX.test(base)', 'true']],
  },
  {
    name: 'decoded-exec (S-x) check removed',
    file: MAPPER,
    edits: [
      ['function decoderCommand(cmd, _run, info) {', 'function decoderCommand(cmd, _run, info) {\n    return false;'],
      ['hit(run, \'Sx\',', 'void (run, \'Sx\','],
    ],
  },
];

function runTests() {
  const r = spawnSync(process.execPath, ['--test', '--require', './test/support/isolated-environment.cjs', 'test/seatbelt-mapper.test.js'], { cwd: ROOT, encoding: 'utf8' });
  const fails = (r.stdout.match(/^# fail (\d+)/m) || [])[1];
  return { status: r.status, fails: Number(fails || 0) };
}

let survived = 0;
const base = runTests();
console.log(`baseline: exit ${base.status}, failing tests ${base.fails}`);
if (base.status !== 0) process.exit(2);
for (const m of MUTANTS) {
  const original = fs.readFileSync(m.file, 'utf8');
  let mutated = original;
  for (const [from, to] of m.edits) {
    const count = mutated.split(from).length - 1;
    if (count < 1) { console.log(`MUTANT NOT APPLIED (${m.name}): pattern missing`); process.exitCode = 1; }
    mutated = mutated.split(from).join(to);
  }
  try {
    fs.writeFileSync(m.file, mutated);
    const r = runTests();
    const killed = r.status !== 0;
    if (!killed) survived += 1;
    console.log(`${killed ? 'KILLED  ' : 'SURVIVED'} ${m.name}: exit ${r.status}, failing tests ${r.fails}`);
  } finally {
    fs.writeFileSync(m.file, original);
  }
}
if (survived) process.exit(1);
