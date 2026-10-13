'use strict';
// The delta auditor's 18 mutants A1-A18 (Barvis, 2026-10-12, my-mutants.cjs), kept as a script of this repo.
// usage: node test/support/seatbelt-audit-mutants.cjs <scratch-mcp-copy>  (edits dist/ of that copy, restores)
// Changes against the audit's copy: the r3 test file is in TESTS (it pins the glob cap, A16), and the
// anchor of A6 follows the N6 rewrite of the walk (`else if (walked.truncated)`).
const fs = require('node:fs'); const path = require('node:path'); const { spawnSync } = require('node:child_process');
const ROOT = path.resolve(process.argv[2]);
const MAP = path.join(ROOT, 'dist/seatbelt/mapper.js'); const TAB = path.join(ROOT, 'dist/seatbelt/tables.js');
const TESTS = ['test/seatbelt-mapper.test.js', 'test/seatbelt-patch-r2.test.js', 'test/seatbelt-audit-regression.test.js', 'test/seatbelt-r3.test.js'];
const MUT = [
  ['A1 GIT_CONFIG_COUNT: only index 0 read', MAP, 'for (let k = 0; k < n; k += 1) {\n                const key = envValue(x, ctx, `GIT_CONFIG_KEY_${k}`);', 'for (let k = 0; k < Math.min(n, 1); k += 1) {\n                const key = envValue(x, ctx, `GIT_CONFIG_KEY_${k}`);'],
  ['A2 dynamic command word not a stop', MAP, "    tripwire(args.map(argText).join(' '), run);\n    hit(run, 'Sx', 'dynamic_command_word');", "    tripwire(args.map(argText).join(' '), run);\n    void 0;"],
  ['A3 terraform without evidence passes', MAP, "return stop('terraform_environment_unresolved');", 'return true;'],
  ['A4 git credential fill passes', MAP, "hit(run, 'S4', 'git_credential_fill');", 'void 0;'],
  ['A5 kubectl secret -o yaml passes', MAP, "hit(run, 'S4', 'kubectl_secret_value');", 'void 0;'],
  ['A6 tool-input walk truncation passes', MAP, "    else if (walked.truncated)\n        exhaust(run, 'budget_tool_input');", '    else if (walked.truncated)\n        void 0;'],
  // N4 added a word-segment rule next to the key table (`CommandLine` is command + line), so the table
  // entry alone is redundant: the mutant drops the entry and the segment rule together.
  ['A7 F11 key commandline dropped (table entry and segment rule)', TAB, [["'cmd', 'commandline', ", "'cmd', "], ['function commandLikeKey(raw) {', 'function commandLikeKey(raw) {\n    return false;']], null],
  ['A8 refs/<other>/x resolves to its tail (short-ref rule loosened)', MAP, "    if (/^refs\\//i.test(ref))\n        return null;", "    if (/^refs\\//i.test(ref))\n        return ref.replace(/^refs\\/[^/]+\\//, '');"],
  ['A9 ambiguous heads/ tags/ prefix accepted as branch name', MAP, '    if (AMBIGUOUS_REF_PREFIX.test(ref) || /^(?:head', '    if (/^(?:head'],
  ['A10 same-command ln -s not recorded', MAP, 'function recordLinks(prog, rest, ctx, run) {', 'function recordLinks(prog, rest, ctx, run) {\n    return;'],
  ['A11 here-string text not read as stdin', MAP, "    for (const r of x.cmd.redirects)\n        if (r.op === '<<<' && r.target)", "    for (const r of x.cmd.redirects)\n        if (false)"],
  ['A12 gpg --export-secret-keys passes', MAP, "? stop('gpg_export_secret') : false", '? false : false'],
  ['A13 fs error not a stop', MAP, "hit(run, 'Sx', 'fs_error')", 'void 0'],
  ['A14 gh DELETE branch protection passes', MAP, "hit(run, 'S1', 'gh_api_delete_branch_protection');", 'void 0;'],
  ['A15 nesting depth limit 6 -> 600', TAB, 'maxDepth: 6,', 'maxDepth: 600,'],
  ['A16 glob match cap 256 -> 1e9', TAB, 'maxGlobMatches: 256,', 'maxGlobMatches: 1e9,'],
  ['A17 wrangler pages without --branch passes', MAP, "return stop('wrangler_pages_production_branch');", 'return true;'],
  ['A18 aws ssm --with-decryption passes', MAP, "hit(run, 'S4', 'aws_ssm_decrypt');", 'void 0;'],
];
let surv = 0; const res = [];
for (const [name, file, from, to] of MUT) {
  const orig = fs.readFileSync(file, 'utf8');
  const pairs = Array.isArray(from) ? from : [[from, to]];
  let n = Infinity;
  let mutated = orig;
  for (const [f, t] of pairs) {
    n = Math.min(n, mutated.split(f).length - 1);
    mutated = mutated.split(f).join(t);
  }
  if (n < 1) { res.push(`| ${name} | ANCHOR MISSING |`); surv += 1; continue; }
  fs.writeFileSync(file, mutated);
  const r = spawnSync(process.execPath, ['--test', ...TESTS], { cwd: ROOT, encoding: 'utf8', timeout: 300000 });
  fs.writeFileSync(file, orig);
  const fails = ((r.stdout || '').match(/^# fail (\d+)/m) || [])[1];
  const killed = r.status !== 0;
  if (!killed) surv += 1;
  res.push(`| ${name} | ${n} site(s) | ${killed ? `KILLED (fail ${fails ?? (r.signal || 'timeout')})` : 'SURVIVED'} |`);
}
console.log('| mutant | applied | result |\n|---|---|---|\n' + res.join('\n'));
console.log(`survivors=${surv}`);
process.exit(surv ? 1 : 0);
