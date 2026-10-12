'use strict';

// Mutation check for the seatbelt mapper (not part of `npm test`; run after `npm run build`):
//   node test/support/seatbelt-mutants.cjs
// Each mutant edits dist/seatbelt/*.js in place, runs the seatbelt mapper, patch-round and audit
// regression tests, and restores the files. A mutant is killed when the test run fails. Exit 1 if a
// mutant survives or an anchor is missing (a mutant that did not apply proves nothing).
//
// Mutants 1-9 are the first round. M-F1..M-F11, M-GH and M-TIME revert one patch-round fix each.
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..', '..');
const MAPPER = path.join(ROOT, 'dist', 'seatbelt', 'mapper.js');
const TABLES = path.join(ROOT, 'dist', 'seatbelt', 'tables.js');
const TESTS = ['test/seatbelt-mapper.test.js', 'test/seatbelt-patch-r2.test.js', 'test/seatbelt-audit-regression.test.js'];

const M = (file, from, to) => [file, from, to];

const MUTANTS = [
  {
    name: 'first round: last-wins removed (first occurrence of a repeated flag decides)',
    edits: [M(MAPPER, "        if (a.text === '--')\n            break;\n        const t = a.text;\n        if (names.includes(t)) {",
      "        if (a.text === '--')\n            break;\n        if (typeof state !== 'undefined' ? state !== 'absent' : value !== undefined)\n            break;\n        const t = a.text;\n        if (names.includes(t)) {")],
  },
  {
    name: 'first round: classifier "routine" treated as a pass for S categories',
    edits: [
      M(MAPPER, 'function evaluateSeatbeltShell(command, env) {', "function evaluateSeatbeltShell(command, env) {\n    if (env.classifierClass === 'routine')\n        return finish(newRun(env, ''));"),
      M(MAPPER, 'function evaluateSeatbelt(event, env) {', "function evaluateSeatbelt(event, env) {\n    if (env.classifierClass === 'routine')\n        return finish(newRun(env, ''));"),
    ],
  },
  { name: 'first round: .env template exception widened to every .env file', edits: [M(MAPPER, 'tables_1.ENV_TEMPLATE_SUFFIX.test(base)', 'true')] },
  {
    name: 'first round: decoded-exec (S-x) check removed',
    edits: [M(MAPPER, 'function decoderCommand(cmd, _run, info) {', 'function decoderCommand(cmd, _run, info) {\n    return false;'), M(MAPPER, "hit(run, 'Sx', 'interpreter_decoded_exec');", 'void 0;')],
  },
  {
    name: 'M-F1 unknown wrappers: the argv of an unknown program (and of deploy/publish tools) is not scanned',
    edits: [
      M(MAPPER, 'if (tables_1.INERT_PROGRAMS.has(prog) || ctx.backstop)', 'if (true)'),
      M(MAPPER, 'if (!tables_1.INERT_PROGRAMS.has(prog) && !ctx.backstop && !DATA_ARGV_TOOLS.has(prog))', 'if (false)'),
    ],
  },
  {
    name: 'M-F2 variables: no field splitting, a dynamic command word and a dynamic subcommand pass',
    edits: [
      M(MAPPER, 'const splits = !word.quoted || force;', 'const splits = false;'),
      M(MAPPER, "hit(run, 'Sx', 'dynamic_command_word');", 'void 0;'),
      M(MAPPER, "hit(run, 'S1', 'git_dynamic_subcommand');", 'void 0;'),
      M(MAPPER, "hit(run, 'S3', `${prog}_dynamic_subcommand`);", 'void 0;'),
      M(MAPPER, "        tripwire(run.topSource, run);\n        hit(run, 'Sx', reason);\n        return;", '        return;'),
    ],
  },
  {
    name: 'M-F3 padding: the 8 KB cutoff is back and over-budget input passes',
    edits: [
      M(TABLES, 'maxCommandBytes: 64 * 1024', 'maxCommandBytes: 8 * 1024'),
      M(MAPPER, "hit(run, 'Sx', 'budget_size');", 'void 0;'),
      M(MAPPER, "hit(run, 'Sx', parsed.error === 'too_many_commands' ? 'budget_segments' : 'budget_size');", 'void 0;'),
      M(MAPPER, "hit(run, 'Sx', 'budget_segments');", 'void 0;'),
      M(MAPPER, "hit(run, 'Sx', 'unparsed_dynamic');", 'void 0;'),
    ],
  },
  {
    name: 'M-F4 branch name trick: a short or ambiguous ref is no longer the protected branch',
    edits: [M(MAPPER, 'function resolveRefName(ref, current) {', "function resolveRefName(ref, current) {\n    if (ref === 'HEAD' || ref === '@')\n        return current;\n    if (ref.startsWith('refs/heads/'))\n        return ref.slice(11);\n    return ref;")],
  },
  {
    name: 'M-F5 npm abbreviations and option-first forms are not resolved',
    edits: [
      M(MAPPER, 'function npmCandidates(token) {', 'function npmCandidates(token) {\n    return [tables_1.NPM_ALIASES[token] || token];'),
      M(MAPPER, '            unknownPending = true;', '            unknownPending = false;'),
      M(MAPPER, 'const argv = sep >= 0 ? [...fwd.slice(0, sep), ...fwd.slice(sep + 1)] : fwd;', 'const argv = fwd;'),
    ],
  },
  {
    name: 'M-F6 git config from the environment and include.path are ignored',
    edits: [
      M(MAPPER, 'envGitConfig(x, ctx, run, overrides);', 'void 0;'),
      M(MAPPER, 'if (tables_1.GIT_CONFIG_INCLUDE.test(canon)) {', 'if (false) {'),
      M(MAPPER, "overrides.set(CONFIG_UNKNOWN, ['1']);", 'void 0;'),
    ],
  },
  {
    name: 'M-F7 here-strings and heredocs into a shell are not classified',
    edits: [
      M(MAPPER, "const onCommand = x.cmd.heredoc !== null || x.cmd.redirects.some((r) => r.op === '<<<');", 'const onCommand = false;'),
      M(MAPPER, "if (r.op === '<<<' && r.target)", 'if (false)'),
    ],
  },
  {
    name: 'M-F8 curl | sh allowance covers any pipeline that has a fetcher anywhere upstream',
    edits: [M(MAPPER, 'if (upstream.length === 1 && fetcherCommand(direct) && !x.info.groupSource) {', 'if (upstream.some((c) => fetcherCommand(c))) {')],
  },
  {
    name: 'M-F9 symlink globs and links made in the same command are not resolved',
    edits: [M(MAPPER, 'if (a.glob && globFollowsLinks(a.text)) {', 'if (false) {'), M(MAPPER, '    recordLinks(prog, rest, ctx, run);\n', '')],
  },
  {
    name: 'M-F10a budgets removed (work, script fan-out, wall clock), memo kept',
    edits: [
      M(MAPPER, 'if (run.work > tables_1.LIMITS.maxWork)', 'if (false)'),
      M(MAPPER, 'if (run.scriptExpansions > tables_1.LIMITS.maxScriptExpansions)', 'if (false)'),
      M(MAPPER, 'if (Date.now() >= run.deadline)', 'if (false)'),
    ],
  },
  {
    name: 'M-F10 budgets removed: no work, script fan-out, wall-clock budget or memo',
    edits: [
      M(MAPPER, 'if (run.work > tables_1.LIMITS.maxWork)', 'if (false)'),
      M(MAPPER, 'if (run.scriptExpansions > tables_1.LIMITS.maxScriptExpansions)', 'if (false)'),
      M(MAPPER, 'if (Date.now() >= run.deadline)', 'if (false)'),
      M(MAPPER, 'if (run.seen.has(key))', 'if (false)'),
    ],
  },
  {
    name: 'M-TIME only the wall-clock budget removed',
    edits: [M(MAPPER, 'if (Date.now() >= run.deadline)', 'if (false)')],
  },
  {
    name: 'M-F11 shell tools: only the old tool name list is read, command fields are ignored',
    edits: [M(MAPPER, 'const known = tables_1.SHELL_TOOL_NAMES.has(name);',
      "const known = ['bash', 'shell', 'local_shell', 'exec_command', 'container.exec', 'run_terminal_command', 'execute_command', 'run_shell_command', 'run_command', 'terminal'].includes(name);\n    if (!known)\n        return null;")],
  },
  {
    name: 'M-GH gh repo delete, release delete and API deletes removed from S1',
    edits: [
      M(MAPPER, "if (sub === 'repo' && (sub2 === 'delete' || sub2 === null)) {", 'if (false) {'),
      M(MAPPER, "if (sub === 'release' && (sub2 === 'delete' || sub2 === 'delete-asset' || sub2 === null)) {", 'if (false) {'),
      M(MAPPER, "if (m === 'DELETE' || m === 'UNKNOWN') {", 'if (false) {'),
    ],
  },
  {
    name: 'M-S4 env dumps in interpreter code are not stopped',
    edits: [M(MAPPER, "hit(run, 'S4', 'interpreter_env_dump');", 'void 0;')],
  },
  {
    name: 'M-FS a throwing file system is no longer a stop',
    edits: [M(MAPPER, "if (run.fsState.errored)\n        hit(run, 'Sx', 'fs_error');", 'void 0;')],
  },
];

// A mutant that removes a budget can also make the run unbounded (sixty references per script, six
// levels deep). A test run that does not finish within the limit counts as failing: the mutant is killed.
const RUN_LIMIT_MS = 240000;
function runTests() {
  const r = spawnSync(process.execPath, ['--test', '--require', './test/support/isolated-environment.cjs', ...TESTS], {
    cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: RUN_LIMIT_MS, killSignal: 'SIGKILL',
  });
  const fails = (String(r.stdout || '').match(/^# fail (\d+)/m) || [])[1];
  const timedOut = r.status === null;
  return { status: timedOut ? 124 : r.status, fails: Number(fails || 0), timedOut };
}

const log = (line) => { fs.writeSync(1, `${line}\n`); };
const only = process.argv[2] ? new RegExp(process.argv[2]) : null;
let survived = 0;
let broken = 0;
const base = runTests();
log(`baseline: exit ${base.status}, failing tests ${base.fails}`);
if (base.status !== 0) process.exit(2);
const files = [...new Set(MUTANTS.flatMap((m) => m.edits.map((e) => e[0])))];
const saved = Object.fromEntries(files.map((f) => [f, fs.readFileSync(f, 'utf8')]));
for (const m of MUTANTS) {
  if (only && !only.test(m.name)) continue;
  const contents = { ...saved };
  let applied = true;
  for (const [file, from, to] of m.edits) {
    const count = contents[file].split(from).length - 1;
    if (count < 1) { log(`NOT APPLIED  ${m.name}: anchor missing: ${from.slice(0, 70).replace(/\n/g, '\\n')}`); applied = false; broken += 1; break; }
    contents[file] = contents[file].split(from).join(to);
  }
  if (!applied) continue;
  try {
    for (const f of files) fs.writeFileSync(f, contents[f]);
    const r = runTests();
    const killed = r.status !== 0;
    if (!killed) survived += 1;
    log(`${killed ? 'KILLED  ' : 'SURVIVED'} ${m.name}: exit ${r.status}${r.timedOut ? ' (run exceeded the time limit)' : ''}, failing tests ${r.fails}`);
  } finally {
    for (const f of files) fs.writeFileSync(f, saved[f]);
  }
}
log(`mutants: ${MUTANTS.length}, survived ${survived}, not applied ${broken}`);
if (survived || broken) process.exit(1);
