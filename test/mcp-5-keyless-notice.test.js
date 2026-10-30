const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

// MCP-5 (spec friction r3 §6, rows K-1..K-4): a keyless hook with control on prints ONE user-visible notice per host session, names only.

const NOTICE = 'Marrow hooks in this session have no API key, so holds and approvals are NOT recorded. Put MARROW_API_KEY in ~/.marrow/env (chmod 600) or start the host with it, then restart the session.';
const dummy = (prefix) => `${prefix}-${randomBytes(12).toString('hex')}`;
const TOKEN_SHAPES = /(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}/;

function home(directory, control) {
  const path = join(directory, 'home');
  mkdirSync(path, { recursive: true, mode: 0o700 });
  if (control !== undefined) {
    mkdirSync(join(path, '.marrow'), { mode: 0o700, recursive: true });
    writeFileSync(join(path, '.marrow', 'control.json'), `${JSON.stringify({
      version: 1, enabled: control, changed_at: '2026-09-29T00:00:00.000Z', change_id: 'ctl_0123456789abcdef0123456789abcdef', changed_by: 'owner_cli',
    })}\n`, { mode: 0o600 });
  }
  return path;
}

function run(entry, path, input, env = {}) {
  return spawnSync(process.execPath, [join(__dirname, '..', 'dist', 'cli.js'), entry], {
    cwd: path,
    env: { PATH: process.env.PATH, HOME: path, MARROW_API_KEY: '', MARROW_KEY: '', MARROW_AUTO_HOOK: 'true', MARROW_EVENT_SPOOL_PATH: join(path, 'spool.json'), ...env },
    input: JSON.stringify(input),
    encoding: 'utf8',
    timeout: 20_000,
  });
}

const pre = (session, command = 'ls') => ({ session_id: session, tool_use_id: `t-${session}-${randomBytes(3).toString('hex')}`, hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command } });
const messages = (result) => {
  const out = [];
  for (const text of [result.stdout]) {
    if (!text.trim()) continue;
    const parsed = JSON.parse(text);
    if (parsed.systemMessage) out.push(parsed.systemMessage);
  }
  return out;
};

test('MCP-5 K-1: the first keyless pre-action call of a session prints the notice, the next calls of that session print none, a new session prints one', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m5-'));
  try {
    const path = home(directory, true);
    const first = run('claude-pre-action-hook', path, pre('s-one'));
    assert.equal(first.status, 0, first.stderr);
    assert.deepEqual(messages(first), [NOTICE]);
    for (let call = 0; call < 3; call += 1) {
      const again = run('claude-pre-action-hook', path, pre('s-one', `ls /tmp/${call}`));
      assert.equal(again.status, 0, again.stderr);
      assert.deepEqual(messages(again), []);
    }
    assert.deepEqual(messages(run('claude-pre-action-hook', path, pre('s-two'))), [NOTICE]);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('MCP-5 K-1: the notice rides along with a hold and keeps the hold (deny stays a deny)', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m5-'));
  try {
    const path = home(directory);
    const result = run('claude-pre-action-hook', path, pre('s-hold', 'npm publish'));
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout);
    assert.equal(output.systemMessage, NOTICE);
    assert.equal(output.hookSpecificOutput.permissionDecision, 'deny');
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

const EVENTS = [
  ['claude-context-hook', (s) => ({ session_id: s, hook_event_name: 'UserPromptSubmit', prompt: 'hello there' })],
  ['claude-hook', (s) => ({ session_id: s, tool_use_id: `t-${s}`, hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_input: { command: 'ls' }, tool_response: { stdout: 'x' } })],
  ['claude-session-hook', (s) => ({ session_id: s, hook_event_name: 'SessionEnd' })],
];

for (const [entry, payload] of EVENTS) {
  test(`MCP-5 K-1: ${entry} is a first hook event too: one notice, then none`, () => {
    const directory = mkdtempSync(join(tmpdir(), 'marrow-m5-'));
    try {
      const path = home(directory);
      assert.deepEqual(messages(run(entry, path, payload('s-ev'))), [NOTICE], entry);
      assert.deepEqual(messages(run(entry, path, payload('s-ev'))), []);
      assert.deepEqual(messages(run('claude-pre-action-hook', path, pre('s-ev'))), [], 'one notice per session across hooks');
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });
}

test('MCP-5 K-2: a keyed session gets no notice', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m5-'));
  try {
    const path = home(directory);
    for (const [entry, payload] of [['claude-pre-action-hook', pre], ...EVENTS]) {
      const result = run(entry, path, entry === 'claude-pre-action-hook' ? pre('s-keyed') : payload('s-keyed'), { MARROW_API_KEY: dummy('mcp-test-dummy') });
      assert.deepEqual(messages(result), [], entry);
      assert.equal(result.stdout.includes('no API key'), false, entry);
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('MCP-5 K-4: control disabled by the owner, and hooks switched off, give no notice', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m5-'));
  try {
    const off = home(directory, false);
    assert.deepEqual(messages(run('claude-pre-action-hook', off, pre('s-off'))), []);
    assert.deepEqual(messages(run('claude-hook', off, EVENTS[1][1]('s-off'))), []);
    const on = join(directory, 'home2');
    mkdirSync(on, { recursive: true, mode: 0o700 });
    assert.deepEqual(messages(run('claude-pre-action-hook', on, pre('s-quiet'), { MARROW_AUTO_HOOK: 'false' })), []);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('MCP-5 K-3: no value is printed: names only, and no token shape appears in any output', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m5-'));
  try {
    const path = home(directory);
    const secret = dummy('mcp-test-dummy');
    const other = dummy('mcp-test-dummy');
    const outputs = [];
    for (const [entry, make] of [['claude-pre-action-hook', pre], ...EVENTS]) {
      const result = run(entry, path, make(`s-k3-${entry}`), { MARROW_ADMIN_TOKEN: secret, OTHER_PASSWORD: other, MARROW_API_KEY: '' });
      outputs.push(result.stdout, result.stderr);
    }
    const all = outputs.join('\n');
    assert.match(all, /MARROW_API_KEY/);
    assert.equal(all.includes(secret), false);
    assert.equal(all.includes(other), false);
    assert.doesNotMatch(all, TOKEN_SHAPES);
    assert.doesNotMatch(NOTICE, TOKEN_SHAPES);
    assert.doesNotMatch(dummy('mcp-test-dummy'), TOKEN_SHAPES, 'the dummy generator never draws a live-shaped value');
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('MCP-5: the marker is owner-only, named by a hash (never the session id), and a call with no session id sends nothing', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m5-'));
  try {
    const path = home(directory);
    run('claude-pre-action-hook', path, pre('session-id-must-not-appear'));
    const folder = join(path, '.marrow', 'session-markers');
    const names = readdirSync(folder);
    assert.equal(names.length, 1);
    assert.doesNotMatch(names[0], /session-id-must-not-appear/);
    assert.equal(statSync(folder).mode & 0o777, 0o700);
    assert.equal(statSync(join(folder, names[0])).mode & 0o777, 0o600);
    const { session_id: _omitted, ...noSession } = pre('x');
    assert.deepEqual(messages(run('claude-pre-action-hook', path, noSession)), []);
    assert.equal(readdirSync(folder).length, 1);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('MCP-5: other hosts keep their exact output (the notice is for Claude Code only)', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m5-'));
  try {
    const path = home(directory);
    for (const entry of ['codex-pre-action-hook', 'grok-pre-action-hook', 'gemini-pre-action-hook', 'cursor-pre-action-hook']) {
      const result = run(entry, path, { ...pre('s-other'), hook_event_name: entry.startsWith('cursor') ? 'preToolUse' : 'PreToolUse' });
      assert.equal(result.stdout.includes('no API key, so holds'), false, entry);
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
