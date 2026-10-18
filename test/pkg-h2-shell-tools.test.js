'use strict';

// PKG-H2 (security sweep 2026-10-18): the Claude Code matcher skipped shell-capable tools (Monitor,
// PowerShell) and other built-ins, so neither the keyed gate nor the keyless seatbelt saw them.
//   1. The matcher hooks every label except Marrow's exact own labels and LS / ListMcpResourcesTool,
//      and never skips a label the 3.9.103 list matcher hooked.
//   2. A Monitor or PowerShell command is classified exactly as the same Bash command, keyless and keyed.
//   3. Any other call carrying a command or script string is never classified below Bash for that text,
//      and is unchanged when its own classification is already at least as strict.
//   4. Newly hooked non-acting built-ins add no hold for ordinary input; EnterWorktree is Bash `git worktree add`.
//   5. Keys: Monitor X, Bash X and Monitor Y never share a key; secrets never reach a key.
// Dummy secrets are generated at runtime; nothing reaches a network.
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const { MARROW_OWN_TOOL_NAMES, NATIVE_HOOK_UNHOOKED_READ_ONLY_TOOLS, listNativeHookMatcher } = require('../dist/own-tool.js');
const { NATIVE_HOOK_MATCHER, LEGACY_NATIVE_HOOK_MATCHERS, exactHookTarget, stableToolCorrelation } = require('../dist/hook-contract.js');
const { classifyTool } = require('../dist/hook-pre-action.js');
const { isReadOnlyToolEvent, isSecretMaterialAccess, toolPolicyReading } = require('../dist/hook-tool-policy.js');
const { normalizedHookAction } = require('../dist/normalized-action.js');
const { evaluateSeatbelt } = require('../dist/seatbelt/mapper.js');
const { findHolds, recordHold } = require('../dist/host-approval-state.js');
const { consultSessionLoopGuard, recordSessionLoopOutcome } = require('../dist/session-loop-guard.js');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');

const OWN = [...MARROW_OWN_TOOL_NAMES].sort();
const NATIVE = ['Bash', 'BashOutput', 'KillShell', 'Monitor', 'PowerShell', 'Edit', 'MultiEdit', 'Write', 'NotebookEdit', 'Read', 'Glob',
  'Grep', 'LS', 'WebSearch', 'WebFetch', 'Task', 'Agent', 'TaskCreate', 'TaskGet', 'TaskList', 'TaskUpdate', 'TaskStop', 'TaskOutput',
  'TodoWrite', 'ToolSearch', 'Skill', 'SendMessage', 'EnterWorktree', 'ExitWorktree', 'EnterPlanMode', 'ExitPlanMode',
  'ListMcpResourcesTool', 'ReadMcpResourceTool', 'SlashCommand', 'CronCreate', 'CronDelete', 'CronList', 'ScheduleWakeup', 'AskUserQuestion'];
// The brief's step-1 table.
const LABELS = [
  ...NATIVE, 'mcp__x__y', 'mcp__github__push', 'functions.x',
  ...OWN.map((t) => `mcp__marrow__${t}`), ...OWN.map((t) => `mcp__plugin_marrow_marrow__${t}`),
  ...OWN.map((t) => `mcp__plugin_marrow_marrow__${t}X`), ...OWN.map((t) => `mcp__marrowX__${t}`),
  'Bash\n', ' LS', 'LS\u0000', 'Monitor ', '', 'FutureTool', 'Run', 'Xyz',
];
const EXEMPT = new Set([...OWN.map((t) => `mcp__marrow__${t}`), ...NATIVE_HOOK_UNHOOKED_READ_ONLY_TOOLS]);
const LIST_3_9_103 = listNativeHookMatcher();

// ------------------------------------------------------------------ 1. matcher

test('PKG-H2 matcher: every label the 3.9.103 list matcher hooked stays hooked; every other label but the exact exemptions is hooked', () => {
  assert.ok(LEGACY_NATIVE_HOOK_MATCHERS.includes(LIST_3_9_103), 'a hook still carrying the released list matcher is repaired');
  assert.deepEqual([...NATIVE_HOOK_UNHOOKED_READ_ONLY_TOOLS], ['LS', 'ListMcpResourcesTool']);
  const before = new RegExp(LIST_3_9_103);
  const search = new RegExp(NATIVE_HOOK_MATCHER);
  const full = new RegExp(`^(?:${NATIVE_HOOK_MATCHER})$`);
  const pads = ['', ' ', '\n', '\r', '\0', '\u2028', 'X', 'x'];
  let n = 0;
  for (const base of LABELS) {
    for (const label of new Set([base, ...pads.flatMap((p) => [`${base}${p}`, `${p}${base}`])])) {
      n += 1;
      if (before.test(label)) assert.equal(search.test(label), true, `was hooked, now skipped: ${JSON.stringify(label)}`);
      assert.equal(search.test(label), !EXEMPT.has(label), `search ${JSON.stringify(label)}`);
      assert.equal(full.test(label), !EXEMPT.has(label), `full ${JSON.stringify(label)}`);
    }
  }
  for (const tool of ['Monitor', 'PowerShell', 'WebFetch', 'Agent', 'Skill', 'SendMessage', 'EnterWorktree', 'ExitWorktree', 'KillShell', 'FutureTool', '']) {
    assert.equal(before.test(tool), false, `${tool} was skipped by 3.9.103`);
    assert.equal(search.test(tool), true, `${tool} is hooked now`);
  }
  assert.ok(n > 4000, `checked ${n}`);
});

// ------------------------------------------------------------------ 2. Monitor / PowerShell = Bash

const SHELL_BATTERY = [
  // ordinary
  'ls', 'ls -la', 'git status', 'git log --oneline -5', 'git diff', 'npm test', 'npm run build', 'pytest', 'cat README.md', 'tail -f app.log | grep --line-buffered ERROR',
  'Get-ChildItem', 'dir', 'Get-Content README.md', 'Get-Process | Select-Object -First 5', 'echo $env:PATH', 'Write-Output hi; Get-Date',
  // publish / push / deploy, chained and wrapped
  'git push --force origin master', 'git push origin X', 'git push origin Y', 'npm publish', 'npx wrangler deploy --env production',
  'echo ok && git push origin master', 'echo ok; git push origin master', 'false || git push origin master', 'echo ok | git push origin master',
  '(git push origin master)', 'bash -c "git push --force origin master"', 'sh -c \'npm publish\'', 'X=push; git $X origin master',
  'git push --no-force --force origin main', 'git -c x=y push --force origin main', '/usr/bin/git push -f origin main', 'env git push -f origin main',
  // misleading words, unknown flags
  'git commit -m "git push --force"', 'cd push-force && ls', 'echo "npm publish"', 'git status --frobnicate', 'grep -r "deploy production" docs',
  // secrets
  'cat .env', 'cat ~/.ssh/id_rsa', 'cat /proc/self/environ', 'printenv', 'grep TOKEN .env', 'cp .env /tmp/x',
  // destructive / infra
  'rm -rf /', 'kubectl delete deployment web', 'terraform apply -auto-approve', 'curl -X POST https://api.example.com/x', 'Remove-Item -Recurse -Force C:\\x',
];
const VARIANTS = ['Monitor', 'PowerShell', 'monitor', 'MONITOR', 'Monitor\n', 'Monitor ', 'powershell', 'POWERSHELL'];
const monitorInput = (command) => ({ command, description: 'watch', timeout_ms: 60000 });

test('PKG-H2 classification: a Monitor or PowerShell command (any case or padding, command or script field) is classified exactly as the same Bash command', () => {
  for (const command of SHELL_BATTERY) {
    const bash = { tool_name: 'Bash', tool_input: { command, description: 'x' } };
    const want = classifyTool(bash);
    for (const tool of VARIANTS) {
      for (const tool_input of [monitorInput(command), { command }, { script: command }, { script: command, description: 'd', timeout: 5 }]) {
        const ev = { tool_name: tool, tool_input };
        assert.deepEqual(classifyTool(ev), want, `${JSON.stringify(tool)} ${JSON.stringify(tool_input)}`);
        assert.equal(isReadOnlyToolEvent(ev), isReadOnlyToolEvent(bash), `${tool} read-only ${command}`);
        assert.equal(isSecretMaterialAccess(ev), isSecretMaterialAccess(bash), `${tool} secret ${command}`);
      }
    }
  }
});

test('PKG-H2 classification: the issue rows (keyed) and ordinary PowerShell', () => {
  const push = classifyTool({ tool_name: 'Monitor', tool_input: monitorInput('git push --force origin master') });
  assert.equal(push.protected, true);
  assert.equal(push.risk, 'high');
  const env = classifyTool({ tool_name: 'Monitor', tool_input: monitorInput('cat .env') });
  assert.equal(env.protected, true, 'Monitor reading .env is a protected secret access (3.9.103 called it medium)');
  assert.ok(env.surfaces.includes('secrets'));
  for (const command of ['Get-ChildItem', 'dir', 'Get-Content README.md', 'git status']) {
    const c = classifyTool({ tool_name: 'PowerShell', tool_input: { command, description: 'x' } });
    assert.equal(c.protected, false, command);
    assert.notEqual(c.risk, 'high', command);
  }
});

test('PKG-H2 seatbelt (keyless): Monitor and PowerShell get Bash\'s exact decision and category; the issue rows stop S1 and S4', () => {
  for (const command of SHELL_BATTERY) {
    const bash = evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command } }, makeEnv());
    for (const tool of VARIANTS) {
      const d = evaluateSeatbelt({ tool_name: tool, tool_input: monitorInput(command) }, makeEnv());
      assert.equal(d.decision, bash.decision, `${JSON.stringify(tool)} ${command}`);
      assert.equal(d.category, bash.category, `${JSON.stringify(tool)} ${command}`);
      assert.equal(d.shell, true, `${JSON.stringify(tool)} is read as shell`);
    }
  }
  const push = evaluateSeatbelt({ tool_name: 'Monitor', tool_input: monitorInput('git push --force origin master') }, makeEnv());
  assert.equal(push.decision, 'stop');
  assert.equal(push.category, 'S1');
  const env = evaluateSeatbelt({ tool_name: 'Monitor', tool_input: monitorInput('cat .env') }, makeEnv());
  assert.equal(env.decision, 'stop');
  assert.equal(env.category, 'S4');
  for (const command of ['Get-ChildItem', 'dir', 'Get-Content README.md', 'git status']) {
    assert.equal(evaluateSeatbelt({ tool_name: 'PowerShell', tool_input: { command } }, makeEnv()).decision, 'pass', command);
  }
});

// ------------------------------------------------------------------ 3. hooked today: never below Bash

const TYPE_ORDER = ['publish', 'deploy', 'review', 'migration', 'audit', 'financial', 'process'];
function atLeast(a, b, label) {
  if (a.readOnly) assert.equal(b.readOnly, true, `${label}: read-only only if Bash is`);
  if (b.protected) assert.equal(a.protected, true, `${label}: protected when Bash is`);
  assert.ok(['low', 'medium', 'high'].indexOf(a.risk) >= ['low', 'medium', 'high'].indexOf(b.risk), `${label}: risk ${a.risk} < ${b.risk}`);
  assert.ok(TYPE_ORDER.indexOf(a.type) <= TYPE_ORDER.indexOf(b.type), `${label}: type ${a.type} weaker than ${b.type}`);
  for (const s of b.surfaces.filter((x) => x !== 'workspace')) assert.ok(a.surfaces.includes(s), `${label}: surface ${s}`);
}

test('PKG-H2 classification: any other tool carrying a command or script string is never below Bash for that text', () => {
  const tools = ['mcp__x__exec', 'mcp__github__run_command', 'functions.mcp__x__y', 'FutureTool', 'Run', 'Task', 'TaskCreate', 'Xyz', 'BashOutput'];
  for (const command of SHELL_BATTERY) {
    const bash = classifyTool({ tool_name: 'Bash', tool_input: { command } });
    for (const tool of tools) {
      for (const tool_input of [{ command }, { script: command }, { command, path: '/tmp/x' }]) {
        atLeast(classifyTool({ tool_name: tool, tool_input }), bash, `${tool} ${JSON.stringify(tool_input)}`);
      }
    }
  }
  // Its own classification is kept, byte for byte, when it is already at least as strict (an MCP tool is protected).
  const own = classifyTool({ tool_name: 'mcp__x__exec', tool_input: { command: 'ls' } });
  assert.deepEqual(own, {
    action: 'classified mcp__x__exec action: process on workspace', target: 'workspace:process', type: 'process', role: 'general',
    surfaces: ['workspace'], risk: 'high', protected: true, readOnly: false,
  });
  // A tool hooked today without shell text keeps its classification (no reading change).
  assert.deepEqual(toolPolicyReading({ tool_name: 'Task', tool_input: { description: 'd', prompt: 'p' } }), { base: 'named', shell: [], exact: false, bashLabel: false });
});

// ------------------------------------------------------------------ 4. newly hooked built-ins

test('PKG-H2 new built-ins: ordinary input adds no hold; words in a prompt, message or URL are not actions', () => {
  const rows = [
    ['WebFetch', { url: 'https://github.com/o/r/releases', prompt: 'summarize the latest release and the production deploy notes' }],
    ['Agent', { description: 'Deploy check', prompt: 'Find where secrets are read and never touch production', subagent_type: 'general-purpose' }],
    ['SendMessage', { to: 'teammate', message: 'please publish the release to production' }],
    ['ExitPlanMode', { plan: '1. migrate the database schema 2. deploy to prod' }],
    ['CronCreate', { cron: '*/5 * * * *', prompt: 'check the deploy status' }],
    ['ScheduleWakeup', { delaySeconds: 600, prompt: 'check the release', reason: 'deploy' }],
    ['AskUserQuestion', { questions: [{ question: 'Deploy to production?' }] }],
    ['SlashCommand', { command: '/deploy production' }],
    ['KillShell', { shell_id: 'abc' }],
    ['EnterPlanMode', {}],
    ['CronList', {}],
    ['CronDelete', { id: 'x' }],
    ['Monitor', { ws: { url: 'wss://events.example.com/deploy' }, description: 'deploy events', timeout_ms: 60000 }],
  ];
  for (const [tool, tool_input] of rows) {
    const c = classifyTool({ tool_name: tool, tool_input });
    assert.deepEqual(c, {
      action: `classified ${tool} action: process on workspace`, target: 'workspace:process', type: 'process', role: 'general',
      surfaces: ['workspace'], risk: 'medium', protected: false, readOnly: false,
    }, tool);
  }
  // Skill is read as Read: read-only.
  const skill = classifyTool({ tool_name: 'Skill', tool_input: { skill: 'deploy', args: 'production' } });
  assert.equal(skill.readOnly, true);
  assert.equal(skill.protected, false);
  assert.equal(isReadOnlyToolEvent({ tool_name: 'Skill', tool_input: { skill: 'deploy' } }), true);
  // Only the exact labels: a padded or re-cased name keeps today's default (words count).
  for (const tool of ['Agent ', 'agent', 'WEBFETCH', 'Skill\n']) {
    const c = classifyTool({ tool_name: tool, tool_input: { prompt: 'deploy to production' } });
    assert.equal(c.protected, true, JSON.stringify(tool));
  }
  // An unknown tool without shell text keeps today's default for an unclassified hooked tool.
  assert.equal(classifyTool({ tool_name: 'FutureTool', tool_input: { note: 'deploy to production' } }).protected, true);
  assert.equal(classifyTool({ tool_name: 'FutureTool', tool_input: { note: 'hello' } }).protected, false);
});

test('PKG-H2 new built-ins: a non-acting tool that carries shell text is never below Bash for it', () => {
  const bash = classifyTool({ tool_name: 'Bash', tool_input: { command: 'git push --force origin master' } });
  atLeast(classifyTool({ tool_name: 'Agent', tool_input: { prompt: 'x', command: 'git push --force origin master' } }), bash, 'Agent+command');
  atLeast(classifyTool({ tool_name: 'WebFetch', tool_input: { url: 'https://x', script: 'git push --force origin master' } }), bash, 'WebFetch+script');
});

test('PKG-H2 EnterWorktree / ExitWorktree: classified as Bash `git worktree add` / `remove` (own label), keyless and outage as Bash', () => {
  for (const [tool, command] of [['EnterWorktree', 'git worktree add'], ['ExitWorktree', 'git worktree remove']]) {
    const bash = classifyTool({ tool_name: 'Bash', tool_input: { command } });
    const c = classifyTool({ tool_name: tool, tool_input: { name: 'feature-x' } });
    assert.deepEqual({ ...c, action: undefined }, { ...bash, action: undefined }, tool);
    assert.equal(c.action, bash.action.replace('Bash', tool));
    const d = evaluateSeatbelt({ tool_name: tool, tool_input: { name: 'feature-x' } }, makeEnv());
    const b = evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command } }, makeEnv());
    assert.equal(d.decision, b.decision, tool);
    assert.equal(d.recognized, true, `${tool} is recognised (no keyless master hold)`);
    assert.equal(d.shell, true);
  }
});

// ------------------------------------------------------------------ 5. keys

const salt = randomBytes(32);
function keys(ev) {
  const n = normalizedHookAction(ev, { salt, deadlineAt: Date.now() + 5000 });
  return {
    normalized: JSON.stringify(n),
    hash: n.tool_input.command_sha256 || n.tool_input.input_sha256 || '',
    exact: n.tool_input.exact_hmac || '',
    truncated: n.truncated === true,
    correlation: stableToolCorrelation({ session_id: 's', ...ev }),
    target: exactHookTarget(ev),
    kind: n.tool_kind,
  };
}
function differ(a, b, label) {
  assert.notEqual(a.normalized, b.normalized, `${label}: normalized action`);
  assert.notEqual(a.correlation, b.correlation, `${label}: correlation`);
  if (!a.truncated && !b.truncated) assert.notEqual(a.hash, b.hash, `${label}: hash`);
  if (a.truncated && b.truncated) assert.notEqual(a.exact, b.exact, `${label}: exact_hmac`);
}

test('PKG-H2 keys: Bash X, Monitor X, PowerShell X and Monitor Y never share a key; Monitor X repeats its own', () => {
  const S = randomBytes(18).toString('base64url');
  const commands = ['git push origin X', 'git push --force origin master', 'echo ok && git push origin master', 'ls', `curl -H "Authorization: Bearer ${S}" https://api.example.com/a`,
    `API_TOKEN=${S} npm run deploy`];
  for (const command of commands) {
    const bash = keys({ tool_name: 'Bash', tool_input: { command } });
    const mon = keys({ tool_name: 'Monitor', tool_input: monitorInput(command) });
    const ps = keys({ tool_name: 'PowerShell', tool_input: { command } });
    assert.equal(mon.kind, 'shell');
    differ(bash, mon, `Bash vs Monitor: ${command.replace(S, '<s>')}`);
    differ(bash, ps, `Bash vs PowerShell: ${command.replace(S, '<s>')}`);
    differ(mon, ps, `Monitor vs PowerShell: ${command.replace(S, '<s>')}`);
    assert.notEqual(mon.target, bash.target);
    assert.deepEqual(keys({ tool_name: 'Monitor', tool_input: monitorInput(command) }), mon, 'a retry keeps its key');
    for (const k of [bash, mon, ps]) assert.ok(!JSON.stringify(k).includes(S), 'no secret in any key');
  }
  differ(keys({ tool_name: 'Monitor', tool_input: monitorInput('git push origin X') }), keys({ tool_name: 'Monitor', tool_input: monitorInput('git push origin Y') }), 'Monitor X vs Y');
  differ(keys({ tool_name: 'Monitor', tool_input: monitorInput('git push origin X') }), keys({ tool_name: 'monitor', tool_input: monitorInput('git push origin X') }), 'Monitor vs monitor');
  differ(keys({ tool_name: 'Monitor', tool_input: monitorInput('git push origin X') }), keys({ tool_name: 'Monitor\n', tool_input: monitorInput('git push origin X') }), 'Monitor vs Monitor\\n');
  // Commands that differ only in a secret value may share a key; the secret never appears.
  const S1 = randomBytes(18).toString('base64url');
  const S2 = randomBytes(18).toString('base64url');
  const a = keys({ tool_name: 'Monitor', tool_input: monitorInput(`curl -H "Authorization: Bearer ${S1}" https://api.example.com/a`) });
  const b = keys({ tool_name: 'Monitor', tool_input: monitorInput(`curl -H "Authorization: Bearer ${S2}" https://api.example.com/a`) });
  for (const k of [a, b]) assert.ok(!JSON.stringify(k).includes(S1) && !JSON.stringify(k).includes(S2));
  // An irregular Monitor call (a WebSocket and a command, or both command and script) is keyed by its whole input.
  const odd1 = keys({ tool_name: 'Monitor', tool_input: { command: 'ls', ws: { url: 'wss://a.example' } } });
  const odd2 = keys({ tool_name: 'Monitor', tool_input: { command: 'ls', ws: { url: 'wss://b.example' } } });
  assert.equal(odd1.kind, 'other');
  differ(odd1, odd2, 'Monitor command+ws');
  differ(keys({ tool_name: 'PowerShell', tool_input: { command: 'ls', script: 'a' } }), keys({ tool_name: 'PowerShell', tool_input: { command: 'ls', script: 'b' } }), 'command+script');
});

test('PKG-H2 keys: newly hooked built-ins are keyed by their whole input (a prompt, message or URL difference is a different key)', () => {
  const pairs = [
    ['Agent', { description: 'Run tests', prompt: 'run npm test', subagent_type: 'x' }, { description: 'Run tests', prompt: 'run npm publish', subagent_type: 'x' }],
    ['WebFetch', { url: 'https://a.example/x', prompt: 'summarize' }, { url: 'https://a.example/x', prompt: 'list secrets' }],
    ['WebFetch', { url: 'https://a.example/x', prompt: 'p' }, { url: 'https://a.example/y', prompt: 'p' }],
    ['SendMessage', { to: 'a', message: `${'x'.repeat(5000)}1` }, { to: 'a', message: `${'x'.repeat(5000)}2` }],
    ['Monitor', { ws: { url: 'wss://a.example/1' }, description: 'events', timeout_ms: 1000 }, { ws: { url: 'wss://a.example/2' }, description: 'events', timeout_ms: 1000 }],
    ['EnterWorktree', { name: 'a' }, { name: 'b' }],
    ['Skill', { skill: 'a' }, { skill: 'b' }],
    ['CronCreate', { cron: '* * * * *', prompt: 'a' }, { cron: '* * * * *', prompt: 'b' }],
  ];
  for (const [tool, x, y] of pairs) {
    const a = keys({ tool_name: tool, tool_input: x });
    const b = keys({ tool_name: tool, tool_input: y });
    assert.equal(a.kind, 'other', tool);
    differ(a, b, tool);
  }
  // Agent and Task with the same input never share a key either.
  const input = { description: 'Run tests', prompt: 'run npm test', subagent_type: 'x' };
  differ(keys({ tool_name: 'Agent', tool_input: input }), keys({ tool_name: 'Task', tool_input: input }), 'Agent vs Task');
});

test('PKG-H2 hold store: a held Monitor push is never claimed by its Bash twin or by Monitor Y', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-h2-holds-'));
  try {
    const scope = { apiKey: `dummy-${randomBytes(8).toString('hex')}`, baseUrl: 'https://api.example.test', agentId: null };
    const held = { tool_name: 'Monitor', tool_input: monitorInput('git push --force origin master') };
    const id = (ev) => ({ correlation: stableToolCorrelation({ session_id: 's', ...ev }), target: exactHookTarget(ev) });
    const h = id(held);
    recordHold(scope, {
      host: 'claude-code', harness: 'claude-code', session_id: 's', host_session_id: 's', agent_id: null, correlation: h.correlation, target: h.target,
      tool_use_id: null, generation_id: null, tool_name: 'Monitor', hook_event: 'PreToolUse', mode: 'wait', gate_receipt_id: 'gate-h2', decision_id: null,
      asked_at: new Date().toISOString(), pre_action_event_id: null, proof_required: false, proof_fields: [], expires_at: null, withCode: false,
      action: { action: 'a', target: 't', type: 'review', surfaces: ['github'] },
    }, home);
    assert.equal(findHolds(scope, { ...h, sessionId: 's', mode: 'wait', states: ['open'] }, home).length, 1, 'the same call finds its hold');
    for (const other of [
      { tool_name: 'Bash', tool_input: { command: 'git push --force origin master' } },
      { tool_name: 'Monitor', tool_input: monitorInput('git push --force origin Y') },
      { tool_name: 'PowerShell', tool_input: { command: 'git push --force origin master' } },
      { tool_name: 'monitor', tool_input: monitorInput('git push --force origin master') },
    ]) {
      assert.equal(findHolds(scope, { ...id(other), sessionId: 's', mode: 'wait', states: ['open'] }, home).length, 0, JSON.stringify(other));
    }
  } finally { rmSync(home, { recursive: true, force: true }); }
});

// ------------------------------------------------------------------ loop guard

test('PKG-H2 loop guard: a re-armed Monitor is not refused; a repeated read-only Bash still is', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-h2-loop-'));
  try {
    const op = (toolName, toolInput, invocationId) => ({ sessionId: 's', agentId: 'a', harness: 'claude-code', toolName, toolInput, invocationId, readOnly: true });
    const input = monitorInput('tail -f app.log | grep --line-buffered ERROR');
    for (let i = 0; i < 4; i += 1) {
      const o = op('Monitor', input, `m${i}`);
      assert.equal(consultSessionLoopGuard(o, { home }).allow, true, `re-arm ${i}`);
      recordSessionLoopOutcome(o, true, { task_id: `t${i}` }, { home });
    }
    const b = op('Bash', { command: 'cat README.md' }, 'b0');
    assert.equal(consultSessionLoopGuard(b, { home }).allow, true);
    recordSessionLoopOutcome(b, true, 'same', { home });
    assert.equal(consultSessionLoopGuard(op('Bash', { command: 'cat README.md' }, 'b1'), { home }).allow, false, 'Bash unchanged');
  } finally { rmSync(home, { recursive: true, force: true }); }
});
