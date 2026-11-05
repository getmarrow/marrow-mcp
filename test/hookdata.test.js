'use strict';

// Hook data words (ACCEPTANCE bld-hookdata, FIX #1 core-loop step A): fully quoted arguments of the data programs, heredoc
// bodies and scanned inline code are data, never the command; `git merge-base` is not `git merge`; row F tells the truth.
// Every row is a hook INPUT; nothing is ever run. BASE answers come from test/fixtures/hookdata/base-classification.json
// (recorded from cb1918f261f2 by the build job), so a HOLD or as-BASE row proves the tip equals BASE byte for byte.
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { randomBytes } = require('node:crypto');
const { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const { classifyTool } = require('../dist/hook-pre-action.js');
const { toolClassificationText } = require('../dist/hook-tool-policy.js');
const { localControlEvidence } = require('../dist/control-state.js');
const { rows } = require('./support/hookdata-rows.cjs');
const BASE = require('./fixtures/hookdata/base-classification.json');

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const CAPTURE = join(__dirname, 'support', 'hookdata-capture.cjs');
const FIELDS = ['action', 'target', 'type', 'role', 'surfaces', 'risk', 'protected', 'readOnly'];
const pick = (c) => Object.fromEntries(FIELDS.map((field) => [field, c[field]]));
const bash = (row) => ({ tool_name: 'Bash', tool_input: { command: row.command, ...(row.extra || {}) } });
const NEW_ROW_F = 'The account owner runs `npx @getmarrow/install control disable` in their own terminal; it asks for a confirmation code. Agents cannot turn control off.';

test('the BASE fixture covers every row, and every HOLD row is protected on BASE', () => {
  assert.equal(BASE.base, 'cb1918f261f2dde66dcaf29bbd1f99861bbe92f5');
  assert.deepEqual(Object.keys(BASE.rows).sort(), rows.map((row) => row.id).sort());
  for (const row of rows.filter((item) => item.expect === 'HOLD')) assert.equal(BASE.rows[row.id].pre.protected, true, row.id);
  for (const row of rows.filter((item) => item.expect === 'ALLOW')) assert.ok(row.shape, `${row.id} names its LOWER_SHAPES id`);
});

for (const row of rows) {
  test(`${row.id} ${row.expect}${row.shape ? ` (${row.shape})` : ''}: classifyTool`, () => {
    const tip = pick(classifyTool(bash(row)));
    const base = BASE.rows[row.id].pre;
    if (row.expect === 'ALLOW') {
      assert.equal(tip.protected, false, `${row.id}: ${tip.action}`);
      if (row.shape !== 'base' && row.shape !== 'L12') {
        // The branch ran: the classification text keeps the program word and drops the data.
        const text = toolClassificationText(bash(row)).toLowerCase();
        assert.match(text, /^bash ; /, `${row.id}: ${text}`);
        assert.doesNotMatch(text, /deploy|release|production|publish/, `${row.id}: ${text}`);
      }
    } else {
      assert.deepEqual(tip, base, `${row.id} keeps the BASE classification`);
    }
  });
}

test('S9 pre/post parity: PostToolUse classifies every row as PreToolUse (only BASE env-print rows differ, as on BASE)', () => {
  for (const row of rows) {
    const pre = pick(classifyTool(bash(row)));
    const post = pick(classifyTool(bash(row), { postTool: true }));
    const base = BASE.rows[row.id];
    if (base.pre.action === base.post.action) assert.equal(post.action, pre.action, row.id);
    else assert.deepEqual(post, base.post, `${row.id}: a BASE pre/post difference stays the BASE one`);
    assert.equal(post.type, pre.type, row.id);
  }
});

test('S7: git merge-base, merge-tree and merge-file are not git merge; git merge keeps protection', () => {
  for (const command of ['git merge-base --is-ancestor A B', 'git merge-base A B', 'git merge-tree A B', 'git merge-file a base b', 'git -C repo merge-base A B']) {
    const result = classifyTool({ tool_name: 'Bash', tool_input: { command } });
    assert.equal(result.protected, false, command);
    assert.equal(result.type, 'review', command);
  }
  for (const command of ['git merge feature', 'git merge -', 'git merge --ff-only x', 'git -C repo merge x', 'git merge-base A B && git merge x', 'git merge-base A B; git push']) {
    assert.equal(classifyTool({ tool_name: 'Bash', tool_input: { command } }).protected, true, command);
  }
});

test('F1 row F: the control-disable text is exact, and control state is unchanged', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-hookdata-rowf-'));
  const previous = process.env.HOME;
  try {
    process.env.HOME = home;
    const evidence = localControlEvidence(false);
    assert.equal(evidence.exact_next_action, NEW_ROW_F);
    assert.equal(evidence.enabled, true);
    assert.equal(evidence.state, 'default_enabled');
    assert.doesNotMatch(JSON.stringify(evidence), /--yes/);
  } finally {
    if (previous === undefined) delete process.env.HOME; else process.env.HOME = previous;
    rmSync(home, { recursive: true, force: true });
  }
});

// The built hook in a child process, as marrow-launch.cjs runs it: one event on stdin, a dummy key generated here, every
// Marrow call answered by the capture preload with an allow gate (so only the hook's own protection can hold).
function hookHarness() {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-hookdata-'));
  const home = join(dir, 'home');
  const project = join(dir, 'project');
  mkdirSync(home, { mode: 0o700 });
  mkdirSync(project);
  const apiKey = `zq${randomBytes(16).toString('hex')}`;
  let runs = 0;
  const run = (entrypoint, event) => {
    const capture = join(dir, `capture-${runs += 1}`);
    mkdirSync(capture);
    const result = spawnSync(process.execPath, [CLI, entrypoint], {
      input: JSON.stringify(event),
      cwd: project,
      env: {
        PATH: process.env.PATH, HOME: home, TMPDIR: process.env.TMPDIR || tmpdir(), MARROW_API_KEY: apiKey, MARROW_BASE_URL: 'https://api.example.test',
        MARROW_AGENT_ID: 'agent-hookdata', MARROW_HOOK_BACKGROUND_NUDGE: 'false', MARROW_PASSIVE_TOKEN_USAGE: 'false',
        HOOKDATA_CAPTURE_DIR: capture, NODE_OPTIONS: `--require=${CAPTURE}`,
      },
      encoding: 'utf8',
      timeout: 30_000,
    });
    assert.equal(result.error, undefined);
    assert.equal(`${result.stdout}${result.stderr}`.includes(apiKey), false, 'the key never appears in hook output');
    const file = join(capture, 'requests.jsonl');
    const requests = existsSync(file) ? readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line)) : [];
    let json = null;
    try { json = result.stdout.trim() ? JSON.parse(result.stdout) : null; } catch { json = null; }
    const decision = json?.hookSpecificOutput?.permissionDecision ?? json?.permission ?? json?.decision ?? null;
    const runtime = requests.find((request) => request.path === '/v1/agent/runtime')?.body ?? null;
    const events = requests.filter((request) => request.path === '/v1/agent/integrations/events').map((request) => request.body);
    return { status: result.status, json, decision, runtime, events };
  };
  return { dir, project, run, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

const held = (decision) => decision === 'deny' || decision === 'ask' || decision === 'block';

test('the built hook in a child process (Claude Code PreToolUse and PostToolUse) asks exactly where classifyTool protects', () => {
  const h = hookHarness();
  try {
    for (const row of rows) {
      const event = { session_id: 'hookdata-session', cwd: h.project, hook_event_name: 'PreToolUse', ...bash(row), tool_use_id: `toolu_${row.id}` };
      const pre = h.run('pre-action-hook', event);
      assert.equal(pre.status, 0, row.id);
      const tip = classifyTool(bash(row), { cwd: h.project });
      assert.equal(held(pre.decision), tip.protected, `${row.id}: hook decision ${pre.decision}`);
      if (row.expect === 'ALLOW') assert.equal(held(pre.decision), false, row.id);
      if (row.expect === 'HOLD') assert.equal(held(pre.decision), true, row.id);
      if (pre.runtime) assert.equal(pre.runtime.action, tip.action, row.id);
      const checked = pre.events.find((item) => item.event_type === 'pre_action_checked');
      const post = h.run('hook', { ...event, hook_event_name: 'PostToolUse', tool_response: { stdout: '', stderr: '', interrupted: false } });
      assert.equal(post.status, 0, row.id);
      const completed = post.events.find((item) => item.event_type !== 'pre_action_checked' && item.action);
      const base = BASE.rows[row.id];
      if (checked && completed && base.pre.action === base.post.action) assert.equal(completed.action, checked.action, `${row.id}: pre/post action text`);
    }
  } finally {
    h.cleanup();
  }
});

test('platform forms: Codex and Cursor PreToolUse shapes give the same answer for A4 (ALLOW) and A1a (HOLD)', () => {
  const h = hookHarness();
  try {
    for (const id of ['A4', 'A1a', 'A30d']) {
      const row = rows.find((item) => item.id === id);
      const codex = { session_id: 'hookdata-codex', turn_id: 'turn-1', cwd: h.project, hook_event_name: 'PreToolUse', model: 'gpt-5-codex', permission_mode: 'default', tool_name: 'Bash', tool_use_id: `call_${id}`, tool_input: { command: row.command } };
      const cursor = { conversation_id: 'c0ffee00-0000-4000-8000-00000000000d', generation_id: 'gen-1', hook_event_name: 'preToolUse', tool_name: 'Shell', tool_input: { command: row.command, working_directory: h.project }, tool_use_id: `cursor-${id}`, cwd: h.project, workspace_roots: [h.project] };
      for (const [entrypoint, event] of [['codex-pre-action-hook', codex], ['cursor-pre-action-hook', cursor]]) {
        const result = h.run(entrypoint, event);
        assert.equal(result.status, 0, `${entrypoint} ${id}`);
        const tip = classifyTool(event, { cwd: h.project });
        assert.equal(tip.protected, row.expect !== 'ALLOW', `${entrypoint} ${id}: ${tip.action}`);
        if (result.runtime) assert.equal(result.runtime.action, tip.action, `${entrypoint} ${id}`);
        const asked = held(result.decision) || /deny|ask/.test(JSON.stringify(result.json || {}));
        assert.equal(asked, row.expect !== 'ALLOW', `${entrypoint} ${id}: ${JSON.stringify(result.json)}`);
      }
    }
  } finally {
    h.cleanup();
  }
});
