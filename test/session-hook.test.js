const assert = require('node:assert/strict');
const {
  mkdtempSync,
  readFileSync,
  rmSync,
} = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const { runSessionHookCommand, sessionEndAutoCommitOpen } = require('../dist/hook-session.js');

async function withHookEnvironment(callback) {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-session-hook-'));
  const previous = {
    MARROW_API_KEY: process.env.MARROW_API_KEY,
    MARROW_BASE_URL: process.env.MARROW_BASE_URL,
    MARROW_AGENT_ID: process.env.MARROW_AGENT_ID,
    MARROW_SESSION_ID: process.env.MARROW_SESSION_ID,
    MARROW_EVENT_SPOOL_PATH: process.env.MARROW_EVENT_SPOOL_PATH,
  };
  process.env.MARROW_API_KEY = 'test-session-hook-key';
  process.env.MARROW_BASE_URL = 'https://api.example.test';
  process.env.MARROW_AGENT_ID = 'agent-one';
  delete process.env.MARROW_SESSION_ID;
  process.env.MARROW_EVENT_SPOOL_PATH = join(directory, 'spool.json');
  try {
    await callback(process.env.MARROW_EVENT_SPOOL_PATH);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    rmSync(directory, { recursive: true, force: true });
  }
}

test('Stop hook retries use deterministic source correlation without an environment session ID', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response('{}', { status: 503 });
  try {
    await withHookEnvironment(async (spoolPath) => {
      const source = {
        session_id: 'claude-source-session',
        transcript_path: '/tmp/transcript.jsonl',
        cwd: '/tmp/project',
        hook_event_name: 'Stop',
      };
      await runSessionHookCommand(source);
      await runSessionHookCommand(source);
      const events = JSON.parse(readFileSync(spoolPath, 'utf8'));
      assert.equal(events.length, 1);
      assert.match(events[0].event_id, /^session-stop-[a-f0-9]{32}$/);
      assert.equal(events[0].session_id, 'claude-source-session');
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('Stop hook auto-commits open decisions and records observed usage only', async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    const href = String(url);
    const body = init.body ? JSON.parse(String(init.body)) : {};
    calls.push({ href, body });
    return new Response(JSON.stringify({ data: { committed: 1, recorded: true } }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  };
  try {
    await withHookEnvironment(async () => {
      await runSessionHookCommand({
        session_id: 'session-usage',
        hook_event_name: 'Stop',
        usage: { prompt_tokens: 12, completion_tokens: 4, total_tokens: 16 },
        model: 'test-model',
      });
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
  const sessionEnd = calls.find((call) => call.href.includes('/v1/agent/session/end'));
  const usage = calls.find((call) => call.href.includes('/v1/agent/model-usage'));
  assert.ok(sessionEnd);
  assert.equal(sessionEnd.body.auto_commit_open, true);
  assert.ok(usage);
  assert.equal(usage.body.input_tokens, 12);
  assert.equal(usage.body.total_tokens, 16);
  assert.equal(usage.body.source, 'mcp_session_end');
});

test('Stop hook does not invent model usage when the host omits counts', async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ href: String(url), body: init.body ? JSON.parse(String(init.body)) : {} });
    return new Response(JSON.stringify({ data: { committed: 1 } }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  };
  try {
    await withHookEnvironment(async () => {
      await runSessionHookCommand({
        session_id: 'session-empty',
        hook_event_name: 'Stop',
      });
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.ok(calls.some((call) => call.href.includes('/v1/agent/session/end')));
  assert.equal(calls.some((call) => call.href.includes('/v1/agent/model-usage')), false);
});

test('session-end auto-commit defaults on and can still be opted out', () => {
  assert.equal(sessionEndAutoCommitOpen(undefined), true);
  assert.equal(sessionEndAutoCommitOpen(null), true);
  assert.equal(sessionEndAutoCommitOpen(true), true);
  assert.equal(sessionEndAutoCommitOpen(false), false);
  assert.equal(sessionEndAutoCommitOpen('false'), false);
});

test('the complete Stop hook is bounded when every fetch ignores abort', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = () => new Promise(() => {});
  try {
    await withHookEnvironment(async () => {
      const started = Date.now();
      await runSessionHookCommand({ session_id: 'bounded-session', hook_event_name: 'Stop' });
      assert.ok(Date.now() - started < 2400);
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});
