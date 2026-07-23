const assert = require('node:assert/strict');
const {
  mkdtempSync,
  readFileSync,
  rmSync,
} = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const { runSessionHookCommand } = require('../dist/hook-session.js');

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
