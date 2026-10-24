'use strict';

// Claude Code built-ins that only report, notify, structure output, render or hand text back are read
// as calls whose words are not actions: ordinary text full of release words adds no denial (keyless)
// and no protected classification (keyed), and the call is still reported (never read-only).
// Workflow's `script` is JavaScript, not shell text. Every unknown label keeps the keyword rule, a
// `command` on Workflow or an unknown tool is still read as shell, and the built-ins a released
// matcher already hooked keep the 3.9.103 classification and keys byte for byte.
// The real hook runs keyless with a trusted fake home (test/support/seatbelt-hook-preload.cjs).
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync, execFileSync } = require('node:child_process');

const { classifyTool } = require('../dist/hook-pre-action.js');
const { isReadOnlyToolEvent, toolPolicyReading } = require('../dist/hook-tool-policy.js');
const { normalizedHookAction } = require('../dist/normalized-action.js');
const { exactHookTarget, stableToolCorrelation } = require('../dist/hook-contract.js');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const PRELOAD = path.join(__dirname, 'support', 'seatbelt-hook-preload.cjs');
const BASE = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'base-hooked-builtins-3.9.103.json'), 'utf8'));

// Every keyword-rule word, in the ordinary text these tools carry.
const WORDS = 'deploy to production, publish the release, migrate the database, rotate and revoke the secret credential token, payment, cat .env';
const NON_ACTING = [
  ['Agent', { description: 'Release check', prompt: WORDS, subagent_type: 'general-purpose' }],
  ['Artifact', { title: 'Release notes', content: `# Release\n${WORDS}` }],
  ['ArtifactCheck', { id: 'art_1', note: WORDS }],
  ['ArtifactComments', { artifact_id: 'art_1', comment: WORDS }],
  ['ArtifactData', { artifact_id: 'art_1', data: { note: WORDS } }],
  ['AskUserQuestion', { questions: [{ question: WORDS, options: [{ label: 'yes' }, { label: 'no' }] }] }],
  ['CronCreate', { cron: '*/30 * * * *', prompt: WORDS, recurring: true }],
  ['CronDelete', { id: 'cron_1' }],
  ['CronList', {}],
  ['EnterPlanMode', {}],
  ['ExitPlanMode', { plan: WORDS }],
  ['KillShell', { shell_id: 'shell_1' }],
  ['ListAgents', {}],
  ['Monitor', { ws: { url: 'wss://events.example.com/deploy' }, description: WORDS, timeout_ms: 60000 }],
  ['PushNotification', { message: 'deploy to production done; secret credential token rotated; cat .env checked', status: 'proactive' }],
  ['ReportFindings', { findings: [{ file: 'src/deploy.ts', line: 12, summary: WORDS, failure_scenario: WORDS, category: 'secret-exposure', verdict: 'CONFIRMED' }], level: 'high' }],
  ['ScheduleWakeup', { delaySeconds: 1200, prompt: WORDS, reason: 'watch the production deploy' }],
  ['SendMessage', { to: 'reviewer', message: WORDS }],
  ['SlashCommand', { command: '/review deploy to production secret credential token cat .env' }],
  ['StructuredOutput', { result: { status: 'deployed to production', notes: WORDS } }],
  ['SubagentHandback', { result: WORDS }],
  ['WebFetch', { url: 'https://docs.example.com/release/production', prompt: WORDS }],
  ['Workflow', { script: `export const meta = { name: 'release', description: 'deploy to production' }\nawait agent('cat .env and summarize the secret credential token rotation; ${WORDS}')`, description: WORDS }],
  ['Workflow', { script: 'await agent("cat .env and summarize")' }],
  ['Workflow', { script: 'const r = await agent(`cat ~/.ssh/id_ed25519 and npm publish`)', title: 'release', args: { target: 'production' } }],
];
// Built-ins that act through a fixed shell reading or a remote service: not part of this set.
const NOT_NON_ACTING = ['Bash', 'PowerShell', 'EnterWorktree', 'ExitWorktree', 'RemoteTrigger', 'DesignSync', 'Skill', 'Task', 'WebSearch',
  'BashOutput', 'NotebookRead', 'ReadMcpResourceTool', 'TaskCreate', 'TaskGet', 'TaskList', 'TaskOutput', 'TaskStop', 'TaskUpdate', 'TodoWrite', 'ToolSearch'];

function sandbox() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-native-friction-')));
  const home = path.join(root, 'home');
  const proj = path.join(home, 'proj');
  fs.mkdirSync(proj, { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  fs.mkdirSync(path.join(home, '.ssh'), { mode: 0o700 });
  fs.writeFileSync(path.join(home, '.ssh', 'id_ed25519'), 'dummy\n', { mode: 0o600 });
  const git = (...args) => execFileSync('git', args, { cwd: proj, env: { PATH: process.env.PATH, HOME: home, GIT_CONFIG_NOSYSTEM: '1' }, stdio: 'ignore' });
  git('init', '-q', '-b', 'feat/x');
  git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '--allow-empty', '-m', 'init');
  return { root, home, proj, netspy: path.join(root, 'net.log'), cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}

function hook(sb, tool_name, tool_input) {
  const event = { hook_event_name: 'PreToolUse', session_id: `nf-${crypto.randomBytes(6).toString('hex')}`, tool_use_id: 't1', tool_name, tool_input, cwd: sb.proj };
  const result = spawnSync(process.execPath, ['--require', PRELOAD, CLI, 'claude-pre-action-hook'], {
    cwd: sb.proj, input: JSON.stringify(event), encoding: 'utf8', timeout: 60_000,
    env: { PATH: process.env.PATH, HOME: sb.home, SBT_PASSWD_HOME: sb.home, SBT_NETSPY: sb.netspy, MARROW_HOOK_BACKGROUND_NUDGE: 'false' },
  });
  assert.equal(result.error, undefined);
  let json = null;
  try { json = result.stdout.trim() ? JSON.parse(result.stdout) : null; } catch { json = { unparsed: result.stdout }; }
  const permission = json ? (json.hookSpecificOutput?.permissionDecision || json.decision || null) : null;
  const reason = json ? String(json.hookSpecificOutput?.permissionDecisionReason || json.reason || '') : '';
  return { status: result.status, permission, reason };
}

test('non-acting built-ins: ordinary text full of release words is not protected and is still reported', () => {
  for (const [tool, tool_input] of NON_ACTING) {
    const event = { tool_name: tool, tool_input };
    const c = classifyTool(event);
    assert.deepEqual(c, {
      action: `classified ${tool} action: process on workspace`, target: 'workspace:process', type: 'process', role: 'general',
      surfaces: ['workspace'], risk: 'medium', protected: false, readOnly: false,
    }, tool);
    assert.equal(isReadOnlyToolEvent(event), false, `${tool} is reported to Marrow`);
    assert.equal(toolPolicyReading(event).base, 'non_acting', tool);
  }
  for (const tool of NOT_NON_ACTING) assert.notEqual(toolPolicyReading({ tool_name: tool, tool_input: { prompt: WORDS } }).base, 'non_acting', tool);
});

test('non-acting built-ins: the real keyless hook gives no denial and no prompt, and makes no network call', () => {
  const sb = sandbox();
  try {
    for (const [tool, tool_input] of NON_ACTING) {
      const answer = hook(sb, tool, tool_input);
      assert.equal(answer.status, 0, `${tool}: ${answer.reason}`);
      assert.equal(answer.permission, null, `${tool}: ${answer.permission} ${answer.reason}`);
    }
    assert.equal(fs.existsSync(sb.netspy) ? fs.readFileSync(sb.netspy, 'utf8') : '', '');
  } finally {
    sb.cleanup();
  }
});

test('negative controls: unknown labels keep the keyword rule; a command on Workflow or an unknown tool is still shell (S1, S4)', () => {
  // Keyed: an unknown label, and any label that is not the exact host name, stays protected by its words.
  for (const tool of ['FutureTool', 'workflow', 'WORKFLOW', 'Workflow ', 'pushnotification', 'Reportfindings', 'StructuredOutput\n', 'mcp__x__ReportFindings']) {
    assert.equal(classifyTool({ tool_name: tool, tool_input: { note: WORDS } }).protected, true, JSON.stringify(tool));
  }
  const sb = sandbox();
  try {
    const words = hook(sb, 'FutureTool', { note: WORDS });
    assert.equal(words.permission, 'deny', 'FutureTool with words: no key, protected');
    for (const tool of ['Workflow', 'FutureTool', 'WORKFLOW']) {
      const push = hook(sb, tool, { command: 'git push --force origin master' });
      assert.equal(push.permission, 'deny', `${tool} command push`);
      assert.match(push.reason, /MARROW SEATBELT stopped this action: force-push/, tool);
    }
    // Only the exact Workflow label reads `script` as JavaScript: the same script on another label is shell text.
    for (const tool of ['FutureTool', 'WORKFLOW', 'workflow']) {
      const read = hook(sb, tool, { script: 'cat ~/.ssh/id_ed25519' });
      assert.equal(read.permission, 'deny', `${tool} script read`);
      assert.match(read.reason, /MARROW SEATBELT stopped this action/, tool);
    }
  } finally {
    sb.cleanup();
  }
});

test('built-ins a released matcher hooked keep the 3.9.103 classification and keys byte for byte (Task and WebSearch included)', () => {
  const salt = Buffer.alloc(32, 7);
  assert.equal(BASE.rows.length, 17);
  for (const row of BASE.rows) {
    const event = { tool_name: row.tool, tool_input: row.input };
    assert.deepEqual(classifyTool(event), row.classification, row.tool);
    assert.equal(isReadOnlyToolEvent(event), row.readOnly, row.tool);
    assert.deepEqual(normalizedHookAction(event, { salt, deadlineAt: Date.now() + 10_000 }), row.normalized, row.tool);
    assert.equal(stableToolCorrelation({ session_id: BASE.session_id, ...event }), row.correlation, row.tool);
    assert.equal(exactHookTarget(event), row.target, row.tool);
  }
  for (const tool of ['Task', 'WebSearch', 'TodoWrite', 'ToolSearch', 'BashOutput', 'TaskStop']) assert.ok(BASE.rows.some((row) => row.tool === tool), tool);
});

test('keys: each non-acting built-in is keyed by its whole input and by its own name', () => {
  const salt = crypto.randomBytes(32);
  const key = (tool, tool_input) => {
    const event = { tool_name: tool, tool_input };
    const n = normalizedHookAction(event, { salt, deadlineAt: Date.now() + 10_000 });
    return { n: JSON.stringify(n), correlation: stableToolCorrelation({ session_id: 's', ...event }), target: exactHookTarget(event) };
  };
  const differ = (a, b, label) => {
    assert.notEqual(a.n, b.n, `${label}: normalized action`);
    assert.notEqual(a.correlation, b.correlation, `${label}: correlation`);
  };
  const pairs = [
    ['PushNotification', { message: 'build done', status: 'proactive' }, { message: 'build failed', status: 'proactive' }],
    ['ReportFindings', { findings: [{ file: 'a.ts', summary: 'x' }] }, { findings: [{ file: 'a.ts', summary: 'y' }] }],
    ['ReportFindings', { findings: [{ file: 'a.ts', summary: 'x' }] }, { findings: [{ file: 'b.ts', summary: 'x' }] }],
    ['StructuredOutput', { result: { status: 'ok' } }, { result: { status: 'failed' } }],
    ['SubagentHandback', { result: 'done' }, { result: 'not done' }],
    ['Artifact', { title: 't', content: 'a' }, { title: 't', content: 'b' }],
    ['ArtifactComments', { artifact_id: 'a1', comment: 'x' }, { artifact_id: 'a2', comment: 'x' }],
    ['ArtifactData', { artifact_id: 'a1', data: { n: 1 } }, { artifact_id: 'a1', data: { n: 2 } }],
    ['ArtifactCheck', { id: 'a1' }, { id: 'a2' }],
    ['Workflow', { script: "await agent('a')" }, { script: "await agent('b')" }],
    ['Workflow', { script: "await agent('a')" }, { script: "await agent('a')", args: { env: 'production' } }],
    ['ListAgents', {}, { filter: 'x' }],
  ];
  for (const [tool, a, b] of pairs) differ(key(tool, a), key(tool, b), `${tool} ${JSON.stringify(a)} vs ${JSON.stringify(b)}`);
  const same = { message: 'deploy done', status: 'proactive' };
  const tools = ['PushNotification', 'SendMessage', 'ReportFindings', 'StructuredOutput', 'SubagentHandback', 'Artifact', 'ArtifactData', 'Workflow', 'FutureTool', 'pushnotification'];
  for (let i = 0; i < tools.length; i += 1) {
    for (let j = i + 1; j < tools.length; j += 1) differ(key(tools[i], same), key(tools[j], same), `${tools[i]} vs ${tools[j]}`);
  }
  // A repeat of the same call is the same key; text after a secret-looking span still differs; no secret text in any key.
  const secret = `mrw_live_${crypto.randomBytes(12).toString('hex')}`;
  assert.equal(key('PushNotification', same).n, key('PushNotification', { ...same }).n);
  const withSecret = (tail) => ({ message: `token=${secret} then ${tail}`, status: 'proactive' });
  differ(key('PushNotification', withSecret('ship it')), key('PushNotification', withSecret('roll back')), 'text after a secret');
  for (const k of [key('PushNotification', withSecret('ship it')), key('ReportFindings', { findings: [{ summary: `key ${secret}` }] })]) {
    assert.equal(`${k.n}${k.correlation}${k.target}`.includes(secret), false, 'no secret in a key');
  }
});
