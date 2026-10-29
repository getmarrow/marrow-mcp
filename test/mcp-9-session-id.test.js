const assert = require('node:assert/strict');
const { createHash, randomBytes } = require('node:crypto');
const { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

// MCP-9 (spec friction r3 §3.5, abuse rows M1-M10, collision rows K9-1..K9-7): one Marrow session id per agent, one helper for every hook.

const tagOf = (agent) => createHash('sha256').update(`marrow-session-agent\n${agent}`).digest('hex').slice(0, 16);
const dummy = () => `mcp-test-dummy-${randomBytes(12).toString('hex')}`;

test('MCP-9 helper: K9-1/K9-2/K9-3/M9/M10 and the fixed suffix shape', () => {
  const { marrowSessionId } = require('../dist/session-id.js');
  const S = 'host-session-1';
  assert.equal(marrowSessionId(S, 'cliff-agent'), `${S}.m${tagOf('cliff-agent')}`);
  assert.notEqual(marrowSessionId(S, 'A'), marrowSessionId(S, 'B'), 'K9-1');
  assert.notEqual(marrowSessionId(S, 'A'), marrowSessionId('host-session-2', 'A'), 'K9-2');
  for (const none of [undefined, null, '']) assert.equal(marrowSessionId(S, none), S, 'K9-3 / M9: no agent id is the raw base');
  assert.notEqual(marrowSessionId(S, 'Cliff-Agent'), marrowSessionId(S, 'cliff-agent'), 'M10: more separation, never less');
  assert.match(marrowSessionId(S, 'a'), /^host-session-1\.m[0-9a-f]{16}$/);
  assert.equal(marrowSessionId(S, 'a'), marrowSessionId(S, 'a'), 'deterministic');
});

test('MCP-9 helper: K9-4 injective over bases and agents, a forged suffix gets a second suffix (M3)', () => {
  const { marrowSessionId } = require('../dist/session-id.js');
  const seen = new Map();
  for (let base = 0; base < 60; base += 1) {
    for (let agent = 0; agent < 60; agent += 1) {
      const id = marrowSessionId(`s${base}`, `agent-${agent}`);
      assert.equal(seen.has(id), false, `${base}/${agent} collides with ${seen.get(id)}`);
      seen.set(id, `${base}/${agent}`);
    }
  }
  const legitB = marrowSessionId('S', 'B');
  const forged = marrowSessionId(legitB, 'A');
  assert.notEqual(forged, legitB, 'A cannot land on B by naming B\'s id as its base');
  assert.equal(forged, `${legitB}.m${tagOf('A')}`);
  assert.notEqual(forged, marrowSessionId('S', 'A'));
});

test('MCP-9 helper: K9-5 a base over 110 characters is hashed deterministically; 110 stays raw', () => {
  const { marrowSessionId } = require('../dist/session-id.js');
  const raw110 = 'x'.repeat(110);
  const long1 = `${'x'.repeat(110)}1`;
  const long2 = `${'x'.repeat(110)}2`;
  assert.equal(marrowSessionId(raw110, 'a'), `${raw110}.m${tagOf('a')}`);
  const hashed = marrowSessionId(long1, 'a');
  assert.match(hashed, /^h[0-9a-f]{32}\.m[0-9a-f]{16}$/);
  assert.equal(hashed, `h${createHash('sha256').update(long1).digest('hex').slice(0, 32)}.m${tagOf('a')}`);
  assert.notEqual(hashed, marrowSessionId(long2, 'a'));
  assert.equal(hashed, marrowSessionId(long1, 'a'));
  assert.ok(hashed.length <= 128 && marrowSessionId(raw110, 'a').length <= 128, 'always within the 128 characters the lifecycle validators keep');
  assert.match(marrowSessionId('S', 'a'), /^[A-Za-z0-9._:-]+$/, 'always within the lifecycle id charset');
});

test('MCP-9 helper: K9-7 no secret is part of the derivation', () => {
  const key = dummy();
  const saved = process.env.MARROW_API_KEY;
  process.env.MARROW_API_KEY = key;
  try {
    const { marrowSessionId } = require('../dist/session-id.js');
    assert.equal(marrowSessionId('S', 'cliff-agent').includes(key), false);
    assert.equal(marrowSessionId('S', 'cliff-agent'), `S.m${tagOf('cliff-agent')}`, 'the key does not change the id');
  } finally {
    if (saved === undefined) delete process.env.MARROW_API_KEY; else process.env.MARROW_API_KEY = saved;
  }
});

// ---- process-level: every hook sends the same per-agent id (K9-6, R-29c) ----------------------------------------------------------------

function home(directory) {
  const path = join(directory, 'home');
  mkdirSync(path, { recursive: true, mode: 0o700 });
  return path;
}

function run(entry, directory, path, input, env = {}, preload = join(__dirname, 'support', 'fetch-capture.cjs')) {
  const capture = join(directory, 'capture.ndjson');
  const result = spawnSync(process.execPath, [join(__dirname, '..', 'dist', 'cli.js'), entry], {
    cwd: path,
    env: {
      PATH: process.env.PATH, HOME: path, MARROW_API_KEY: dummy(), MARROW_KEY: '', MARROW_AUTO_HOOK: 'true',
      MARROW_EVENT_SPOOL_PATH: join(path, 'spool.json'), NODE_OPTIONS: `--require ${preload}`, CAPTURE_FILE: capture, ...env,
    },
    input: JSON.stringify(input),
    encoding: 'utf8',
    timeout: 25_000,
  });
  const lines = existsSync(capture) ? readFileSync(capture, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line)) : [];
  // The PostToolUse hook queues its lifecycle event in the local spool and delivers it later: the queued event carries the same session id.
  const spool = join(path, 'spool.json');
  if (existsSync(spool)) lines.push({ url: 'spool', body: readFileSync(spool, 'utf8') });
  return { result, lines };
}

const sessionIds = (lines) => {
  const found = new Set();
  for (const line of lines) {
    for (const match of `${line.body} ${line.url}`.matchAll(/(?:"session_id"\s*:\s*"|session_id=)([^"&\\]+)/g)) found.add(decodeURIComponent(match[1]));
  }
  return found;
};

const HOST = 'host-session-28e485ab';
const EVENTS = [
  ['claude-pre-action-hook', { session_id: HOST, tool_use_id: 't-pre', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'npm publish' } }],
  ['claude-hook', { session_id: HOST, tool_use_id: 't-post', hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_input: { command: 'touch marrow-m9-x' }, tool_response: { stdout: '' } }],
  ['claude-context-hook', { session_id: HOST, hook_event_name: 'UserPromptSubmit', prompt: 'please deploy the website' }],
  ['claude-session-hook', { session_id: HOST, hook_event_name: 'SessionEnd' }],
];

for (const [entry, payload] of EVENTS) {
  test(`MCP-9 K9-6/R-29c: ${entry} sends the per-agent Marrow session id, never the raw host id`, () => {
    const directory = mkdtempSync(join(tmpdir(), 'marrow-m9-'));
    try {
      const path = home(directory);
      const { result, lines } = run(entry, directory, path, payload, { MARROW_AGENT_ID: 'cliff-agent' });
      assert.equal(result.status, 0, result.stderr);
      const ids = sessionIds(lines);
      assert.ok(ids.size > 0, `${entry} sent no session id: ${JSON.stringify(lines.map((line) => line.url))}`);
      assert.deepEqual([...ids], [`${HOST}.m${tagOf('cliff-agent')}`], entry);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });

  test(`MCP-9 M9: ${entry} with a key but no agent id keeps the raw id (byte-identical to 3.9.108)`, () => {
    const directory = mkdtempSync(join(tmpdir(), 'marrow-m9-'));
    try {
      const path = home(directory);
      const { lines } = run(entry, directory, path, payload, { MARROW_AGENT_ID: '' });
      const ids = [...sessionIds(lines)];
      assert.ok(ids.length > 0);
      assert.deepEqual(ids, [HOST], entry);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });
}

test('MCP-9 K9-1: two agents in one host session get two Marrow sessions; the same agent keeps one', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m9-'));
  try {
    const path = home(directory);
    const a = sessionIds(run('claude-pre-action-hook', directory, path, EVENTS[0][1], { MARROW_AGENT_ID: 'agent-a' }).lines);
    rmSync(join(directory, 'capture.ndjson'), { force: true });
    const b = sessionIds(run('claude-pre-action-hook', directory, path, EVENTS[0][1], { MARROW_AGENT_ID: 'agent-b' }).lines);
    rmSync(join(directory, 'capture.ndjson'), { force: true });
    const aAgain = sessionIds(run('claude-pre-action-hook', directory, path, EVENTS[0][1], { MARROW_AGENT_ID: 'agent-a' }).lines);
    assert.deepEqual([...a], [`${HOST}.m${tagOf('agent-a')}`]);
    assert.deepEqual([...b], [`${HOST}.m${tagOf('agent-b')}`]);
    assert.deepEqual([...aAgain], [...a]);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('MCP-9 M3: MARROW_SESSION_ID naming another agent\'s per-agent id still gets this agent\'s own suffix', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m9-'));
  try {
    const path = home(directory);
    const victim = `${HOST}.m${tagOf('agent-b')}`;
    const { lines } = run('claude-pre-action-hook', directory, path, EVENTS[0][1], { MARROW_AGENT_ID: 'agent-a', MARROW_SESSION_ID: victim });
    const ids = [...sessionIds(lines)];
    assert.deepEqual(ids, [`${victim}.m${tagOf('agent-a')}`]);
    assert.equal(ids.includes(victim), false);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('MCP-9 M6/S-a: an unprotected action on a 403 session mismatch is let through silently by the hook (pinned)', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m9-'));
  try {
    const path = home(directory);
    const { result } = run('claude-pre-action-hook', directory, path,
      { session_id: HOST, tool_use_id: 't-low', hook_event_name: 'PreToolUse', tool_name: 'Write', tool_input: { file_path: join(path, 'work', 'notes.md'), content: 'x' } },
      { MARROW_AGENT_ID: 'cliff-agent', FETCH_STATUS: '403' }, join(__dirname, 'support', 'fetch-status.cjs'));
    assert.equal(result.status, 0, result.stderr);
    assert.doesNotMatch(result.stdout, /"permissionDecision":"(?:deny|ask)"/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('MCP-9 M1/M7: a protected action on a 403 session mismatch is still held (the ownership error is never an allow)', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m9-'));
  try {
    const path = home(directory);
    const { result } = run('claude-pre-action-hook', directory, path, EVENTS[0][1],
      { MARROW_AGENT_ID: 'cliff-agent', FETCH_STATUS: '403' }, join(__dirname, 'support', 'fetch-status.cjs'));
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /"permissionDecision":"deny"/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
