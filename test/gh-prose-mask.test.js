'use strict';

// L2 (owner-decided loosening, Buu 2026-11-11T05:16Z item 2): the prose, repo slug, branch, label and people values of
// `gh pr create|edit|comment|review` and `gh issue create|comment|edit` are not action words, so they no longer make a deploy.
// Only those exact shapes change (LOWER-SHAPES-l2.md); every other form keeps master's answer, recorded here as BASE_SNAPSHOT
// (master 68fa8b320cd9). Every abuse, collision and plant row of the spec section is a test here. Dummy secrets are made at
// run time and never printed.
const assert = require('node:assert/strict');
const test = require('node:test');

const policy = require('../dist/hook-tool-policy.js');
const { classifyTool } = require('../dist/hook-pre-action.js');
const { normalizedHookAction } = require('../dist/normalized-action.js');
const { dummySecret } = require('./support/dummy-secret.cjs');

const bash = (command, tool = 'Bash') => ({ tool_name: tool, tool_input: { command } });
const shot = (c) => `${c.action}|${c.protected}|${c.risk}|${c.target}|${c.role}`;
const QUIET = 'classified Bash action: process on workspace|false|medium|workspace:process|general';

// The listed shapes with action words in the left-out values: a deploy on master; here the answer the same call has with neutral values.
const LOWER = [
  ['miss', 'gh pr create --title "Ship it" --body "Merging this will deploy to production"', 'gh pr create --title "Ship it" --body x'],
  ['repo slug', 'gh pr create -R x/release --title t', 'gh pr create -R x/x --title t'],
  ['misleading body', 'gh pr create --title t --body "deploy to production after merge"', 'gh pr create --title t --body x'],
  ['repeated title', 'gh pr create --title deploy --title release', 'gh pr create --title x --title x'],
  ['equals form', 'gh pr create --title=release --body=deploy', 'gh pr create --title=x --body=x'],
  ['short flags', 'gh pr create -t "prod hotfix" -b "wrangler release notes"', 'gh pr create -t x -b x'],
  ['base and head', 'gh pr create --base release --head deploy-fix --title t', 'gh pr create --base x --head x --title t'],
  ['label people', 'gh pr create --label deploy -l production --reviewer release-team --assignee prod-oncall --title t', 'gh pr create --label x -l x --reviewer x --assignee x --title t'],
  ['body file', 'gh pr create -F release-notes.md', 'gh pr create -F x.md'],
  ['body file equals', 'gh pr create --title release --body-file=deploy.md', 'gh pr create --title x --body-file=x.md'],
  ['pr edit', 'gh pr edit 12 --title "release prep" --body "prod"', 'gh pr edit 12 --title x --body x'],
  ['pr comment', 'gh pr comment 12 --body "ready to deploy to production"', 'gh pr comment 12 --body x'],
  ['pr review', 'gh pr review 12 --approve --body "ship the release"', 'gh pr review 12 --approve --body x'],
  ['issue create', 'gh issue create --title "prod deploy broke" --body "release blocked"', 'gh issue create --title x --body x'],
  ['issue comment', 'gh issue comment 5 --body "deployed to production"', 'gh issue comment 5 --body x'],
  ['issue edit', 'gh issue edit 5 --title "release" --label deploy -R x/prod', 'gh issue edit 5 --title x --label x -R x/x'],
  ['after a reader cd', 'cd repo && gh pr create --title "release" --body "deploy"', 'cd repo && gh pr create --title x --body x'],
  ['with a push', 'gh pr create --title deploy && git push origin feat', 'gh pr create --title x && git push origin feat'],
  ['two listed segments','gh pr create --title release && gh pr comment 1 --body deploy', 'gh pr create --title x && gh pr comment 1 --body x'],
];

// Every other form: master's answer, byte for byte (spec abuse rows, the production mislabel corpus, adversarial forms).
// STAY-BEGIN
const STAY = [
  ['abuse: create then merge', bash('gh pr create --title t && gh pr merge 1')],
  ['abuse: substitution body', bash('gh pr create --body "$(wrangler deploy)"')],
  ['abuse: cd prod rm', bash('cd /srv/prod && rm -rf data')],
  ['abuse: cd release wrangler', bash('cd release-ops && npx wrangler deploy')],
  ['abuse: merge repo slug', bash('gh pr merge -R x/release')],
  ['abuse: unknown flag', bash('gh pr create --title t --foo deploy')],
  ['fixes: cd then pr view', bash('cd release-ops && gh pr view')],
  ['chain: semicolon deploy', bash('gh pr create --title t; npx wrangler deploy')],
  ['chain: or deploy', bash('gh pr create --title t || npx wrangler deploy')],
  ['chain: pipe deploy', bash('gh pr create --title t | npx wrangler deploy')],
  ['chain: newline deploy', bash('gh pr create --title t\nnpx wrangler deploy')],
  ['chain: background deploy', bash('gh pr create --title t & npx wrangler deploy')],
  ['chain: cd then reader', bash('cd release && cat deploy.txt && gh pr create --title t')],
  ['subshell', bash('(gh pr create --title deploy)')],
  ['group', bash('{ gh pr create --title deploy; }')],
  ['bash -c', bash('bash -c "gh pr create --title deploy"')],
  ['sh -c', bash("sh -c 'gh pr create --body release'")],
  ['eval', bash('eval gh pr create --title deploy')],
  ['sudo', bash('sudo gh pr create --title deploy')],
  ['env wrapper', bash('env gh pr create --title deploy')],
  ['assignment', bash('GH_REPO=x/prod gh pr create --title deploy')],
  ['command wrapper', bash('command gh pr create --title deploy')],
  ['xargs', bash('xargs gh pr create --title deploy')],
  ['full path', bash('/usr/bin/gh pr create --title deploy')],
  ['upper program', bash('GH pr create --title deploy')],
  ['upper group', bash('gh PR create --title deploy')],
  ['upper sub', bash('gh pr Create --title deploy')],
  ['variable value', bash('gh pr create --title "deploy $TAG"')],
  ['braced variable', bash('gh pr create --title "${TAG}" --body production')],
  ['backtick value', bash('gh pr create --body "`wrangler deploy`"')],
  ['substitution title', bash('gh pr create --title "$(cat release)"')],
  ['process substitution', bash('gh pr create --body-file <(npx wrangler deploy)')],
  ['heredoc body', bash('gh pr create --body-file - <<EOF\ndeploy to production\nEOF')],
  ['end of options', bash('gh pr create -- --title deploy')],
  ['attached short', bash('gh pr create -tdeploy')],
  ['short equals', bash('gh pr create -t=deploy')],
  ['unknown long equals', bash('gh pr create --milestone=release')],
  ['output file', bash('gh pr create --title t > release.log')],
  ['stderr file', bash('gh pr create --title t 2> deploy.log')],
  ['positional words', bash('gh pr comment release --body t')],
  ['proto group', bash('gh __proto__ create --title deploy')],
  ['constructor group', bash('gh constructor create --title deploy')],
  ['unlisted pr sub', bash('gh pr checkout release')],
  ['pr close', bash('gh pr close 1 --comment deploy')],
  ['pr ready', bash('gh pr ready --repo x/release')],
  ['issue unlisted head', bash('gh issue create --head deploy --title t')],
  ['issue unlisted base', bash('gh issue create --base release --title t')],
  ['issue unlisted reviewer', bash('gh issue create --reviewer prod --title t')],
  ['issue close', bash('gh issue close 5 --repo x/prod')],
  ['issue delete', bash('gh issue delete 5 --repo x/prod')],
  ['gh release', bash('gh release create v1 --title t --notes n')],
  ['gh workflow run', bash('gh workflow run ship.yml --repo x/prod')],
  ['gh api', bash('gh api -R x/prod repos/x/y/deployments')],
  ['gh repo', bash('gh repo create x/release --title t')],
  ['glab', bash('glab mr create --title deploy --body production')],
  ['hub', bash('hub pull-request --title deploy -b production')],
  ['git commit', bash('git commit -m "deploy to production" --title release')],
  ['curl', bash('curl --title deploy -b production https://example.invalid/')],
  ['echo', bash('echo --body production --title release')],
  ['wrangler with title', bash('npx wrangler deploy --title t --body b')],
  ['nbsp unicode', bash('gh pr create --title t npx wrangler deploy')],
  ['line separator', bash('gh pr create --title t npx wrangler deploy')],
  ['fullwidth gh', bash('ｇｈ pr create --title deploy')],
  ['powershell', { tool_name: 'PowerShell', tool_input: { command: 'gh pr create --title deploy' } }],
  ['forged description', { tool_name: 'Bash', tool_input: { command: 'npx wrangler deploy', description: 'gh pr create --title t' } }],
  ['forged cmd', { tool_name: 'Bash', tool_input: { command: 'npx wrangler deploy', cmd: 'gh pr create --title t' } }],
  ['unknown tool', { tool_name: 'gh', tool_input: { command: 'gh pr create --title release' } }],
  ['mcp tool', { tool_name: 'mcp__github__create_pull_request', tool_input: { title: 'deploy', body: 'production' } }],
  ['cd unknown then cd prod', bash('cd "$W" && cd prod-release && rm -rf data')],
  ['upper flag', bash('gh pr create --TITLE deploy')],
  ['comment words', bash('gh pr create --title t # deploy')],
  ['body file secret path', bash('gh pr create --title t --body-file .env')],
  ['input string gh with deploy', { tool_name: 'Bash', tool_input: 'gh pr create --title t; npx wrangler deploy' }],
];
// STAY-END

// Recorded from master 68fa8b320cd9 (dist built there): classifyTool(row) as action|protected|risk|target|role.
const BASE_SNAPSHOT = {
  'abuse: create then merge': 'classified Bash action: review on github|true|high|github:review|review',
  'abuse: substitution body': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'abuse: cd prod rm': 'classified Bash action: process on workspace|true|high|workspace:process|general',
  'abuse: cd release wrangler': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'abuse: merge repo slug': 'classified Bash action: deploy on production, github|true|high|github:deploy|deploy',
  'abuse: unknown flag': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'fixes: cd then pr view': 'classified Bash action: process on workspace|false|low|workspace:process|general',
  'chain: semicolon deploy': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'chain: or deploy': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'chain: pipe deploy': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'chain: newline deploy': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'chain: background deploy': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'chain: cd then reader': 'classified Bash action: process on workspace|false|medium|workspace:process|general',
  'subshell': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'group': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'bash -c': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'sh -c': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'eval': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'sudo': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'env wrapper': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'assignment': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'command wrapper': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'xargs': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'full path': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'upper program': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'upper group': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'upper sub': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'variable value': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'braced variable': 'classified Bash action: process on production|true|high|production:process|general',
  'backtick value': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'substitution title': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'process substitution': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'heredoc body': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'end of options': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'attached short': 'classified Bash action: process on workspace|false|medium|workspace:process|general',
  'short equals': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'unknown long equals': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'output file': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'stderr file': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'positional words': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'proto group': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'constructor group': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'unlisted pr sub': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'pr close': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'pr ready': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'issue unlisted head': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'issue unlisted base': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'issue unlisted reviewer': 'classified Bash action: process on production|true|high|production:process|general',
  'issue close': 'classified Bash action: process on production|true|high|production:process|general',
  'issue delete': 'classified Bash action: process on production|true|high|production:process|general',
  'gh release': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'gh workflow run': 'classified Bash action: process on production|true|high|production:process|general',
  'gh api': 'classified Bash action: process on production|true|high|production:process|general',
  'gh repo': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'glab': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'hub': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'git commit': 'classified Bash action: deploy on production, github|true|high|github:deploy|deploy',
  'curl': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'echo': 'classified Bash action: process on workspace|false|low|workspace:process|general',
  'wrangler with title': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'nbsp unicode': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'line separator': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'fullwidth gh': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'powershell': 'classified PowerShell action: deploy on production|true|high|production:deploy|deploy',
  'forged description': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'forged cmd': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'unknown tool': 'classified gh action: deploy on production|true|high|production:deploy|deploy',
  'mcp tool': 'classified mcp__github__create_pull_request action: deploy on production|true|high|production:deploy|deploy',
  'cd unknown then cd prod': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'upper flag': 'classified Bash action: deploy on production|true|high|production:deploy|deploy',
  'comment words': 'classified Bash action: process on workspace|false|medium|workspace:process|general',
  'body file secret path': 'classified Bash action: audit on secrets|true|high|secrets:audit|audit',
  'input string gh with deploy': 'classified Bash action: deploy on production|true|high|production:deploy|deploy'
};

for (const [name, command, neutral] of LOWER) {
  test(`LOWER ${name}: the listed gh values make no deploy (the answer of the same call with neutral values)`, () => {
    const c = classifyTool(bash(command));
    assert.equal(shot(c), shot(classifyTool(bash(neutral))));
    assert.ok(!c.surfaces.includes('production') && c.type !== 'deploy');
  });
}

test('LOWER: a gh pr create with prose is the quiet process on workspace it is without the prose', () => {
  assert.equal(shot(classifyTool(bash(LOWER[0][1]))), QUIET);
});

for (const [name, event] of STAY) {
  test(`STAY ${name}: master's answer, unchanged`, () => {
    assert.ok(name in BASE_SNAPSHOT, 'row recorded on master');
    assert.equal(shot(classifyTool(event)), BASE_SNAPSHOT[name]);
  });
}

test('abuse rows that must hold stay protected and high', () => {
  for (const command of ['gh pr create --title t && gh pr merge 1', 'gh pr create --body "$(wrangler deploy)"', 'cd /srv/prod && rm -rf data',
    'cd release-ops && npx wrangler deploy', 'gh pr merge -R x/release', 'gh pr create --title t --foo deploy']) {
    const c = classifyTool(bash(command));
    assert.equal(c.protected, true, command);
    assert.equal(c.risk, 'high', command);
  }
  assert.equal(classifyTool(bash('gh pr create --title a --title b')).protected, false);
});

test('production mislabel: no other program loses production', () => {
  for (const [name, event] of STAY) {
    const base = BASE_SNAPSHOT[name] || '';
    if (base.includes('production')) assert.ok(classifyTool(event).surfaces.includes('production'), name);
  }
});

const hash = (command, salt) => normalizedHookAction(bash(command), { salt }).tool_input;
const SALT = Buffer.alloc(32, 7);

test('COLL: bodies that differ give different exact keys', () => {
  const a = hash('gh pr create --title t --body "deploy note A"', SALT);
  const b = hash('gh pr create --title t --body "deploy note B"', SALT);
  assert.notEqual(a.command_sha256, b.command_sha256);
  assert.notEqual(JSON.stringify(a), JSON.stringify(b));
  assert.equal(shot(classifyTool(bash('gh pr create --title t --body "deploy note A"'))), shot(classifyTool(bash('gh pr create --title t --body "deploy note B"'))));
});

test('COLL: a secret in a body stays out of keys and class text, and text after it still changes the key', () => {
  const d = dummySecret();
  const e = dummySecret();
  const rows = [`gh pr create --title t --body "https://u:${d}@h/o/r then A"`, `gh pr create --title t --body "https://u:${d}@h/o/r then B"`,
    `gh pr create --title t --body "https://u:${e}@h/o/r then A"`];
  const [a, b, c] = rows.map((row) => normalizedHookAction(bash(row), { salt: SALT }));
  for (const [i, out] of [a, b, c].entries()) {
    const text = JSON.stringify(out) + JSON.stringify(classifyTool(bash(rows[i])));
    assert.ok(!text.includes(d) && !text.includes(e), 'no secret in a key or class text');
  }
  assert.notEqual(a.tool_input.command_sha256, b.tool_input.command_sha256);
  assert.equal(a.tool_input.command_sha256, c.tool_input.command_sha256);
});

test('CONS-CLASS: a masked gh pr create never shares a class or a key with a merge, a release or a deploy', () => {
  const create = 'gh pr create --title release --body "deploy to production"';
  const quiet = classifyTool(bash(create));
  for (const other of ['gh pr merge 1', 'gh pr merge -R x/release', 'gh release create v1', 'npx wrangler deploy', 'gh workflow run deploy.yml']) {
    const c = classifyTool(bash(other));
    assert.notEqual(c.action, quiet.action, other);
    assert.notEqual(hash(other, SALT).command_sha256, hash(create, SALT).command_sha256, other);
  }
});

test('CONS-HASH: the exact hash covers the whole input, left-out values included', () => {
  const short = hash('gh pr create --title t', SALT);
  const long = hash('gh pr create --title t --body "deploy to production"', SALT);
  assert.notEqual(short.command_sha256, long.command_sha256);
  assert.notEqual(JSON.stringify(short), JSON.stringify(long));
});

// TMO: the masked view is text only; a thrown reader, a thrown verdict and an overrun of its budget give master's answer (the hold).
// A stub acts only when the masked view (ghProseScanText) calls it; every other caller gets the real reader.
function withStub(key, value, fn) {
  const real = policy[key];
  policy[key] = (...args) => (new Error().stack.includes('ghProseScanText') ? value(...args) : real(...args));
  try { return fn(); } finally { policy[key] = real; }
}
const MISS = 'gh pr create --title "Ship it" --body "Merging this will deploy to production"';
const MISS_BASE = 'classified Bash action: deploy on production|true|high|production:deploy|deploy';

test('TMO: a thrown reader error gives master\'s hold', () => {
  withStub('parseShellSegments', () => { throw new Error('reader fault'); }, () => assert.equal(shot(classifyTool(bash(MISS))), MISS_BASE));
});

test('TMO: a thrown verdict gives master\'s hold', () => {
  withStub('shellSegmentVerdict', () => { throw new Error('verdict fault'); }, () => assert.equal(shot(classifyTool(bash(MISS))), MISS_BASE));
});

test('TMO: an overrun of the time budget gives master\'s hold', () => {
  const real = policy.parseShellSegments;
  const now = Date.now;
  let skew = 0;
  Date.now = () => now() + skew;
  try {
    withStub('parseShellSegments', (...args) => { skew += 60_000; return real(...args); }, () => assert.equal(shot(classifyTool(bash(MISS))), MISS_BASE));
  } finally { Date.now = now; }
});

test('TMO: a reader that answers nothing gives master\'s hold', () => {
  withStub('parseShellSegments', () => null, () => assert.equal(shot(classifyTool(bash(MISS))), MISS_BASE));
});
