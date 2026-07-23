const assert = require('node:assert/strict');
const { mkdtempSync, readFileSync, rmSync, statSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const { recordLifecycleEvent } = require('../dist/lifecycle-spool.js');

test('PostToolUse correlates the tool receipt and outcome closure', () => {
  const source = readFileSync(join(__dirname, '../src/hook.ts'), 'utf8');
  const correlationFields = source.match(/workflow_id: lifecycleCorrelation/g) || [];

  assert.match(source, /const lifecycleCorrelation = `mcp-hook-\$\{randomUUID\(\)\}`/);
  assert.equal(correlationFields.length, 2);
});

test('MCP lifecycle spool keeps compact redacted receipts across process attempts', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-spool-'));
  const path = join(directory, 'spool.json');
  const originalPath = process.env.MARROW_EVENT_SPOOL_PATH;
  const originalFetch = globalThis.fetch;
  process.env.MARROW_EVENT_SPOOL_PATH = path;
  let available = false;
  const delivered = [];
  globalThis.fetch = async (_url, init) => {
    delivered.push(JSON.parse(init.body));
    return available
      ? new Response(JSON.stringify({ data: { accepted: true } }), { status: 200, headers: { 'Content-Type': 'application/json' } })
      : new Response(JSON.stringify({ error: 'temporary' }), { status: 503, headers: { 'Content-Type': 'application/json' } });
  };

  try {
    const queued = await recordLifecycleEvent({
      apiKey: 'test-mcp-spool-key',
      baseUrl: 'https://api.example.com',
      event: {
        event_id: 'mcp-event-one',
        event_type: 'tool_completed',
        agent_id: 'agent-one',
        action: 'publish with --token secret-value-that-must-not-persist',
        outcome_state: 'pending',
        success: true,
      },
    });
    assert.equal(queued.queued, true);
    assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.doesNotMatch(readFileSync(path, 'utf8'), /secret-value-that-must-not-persist/);

    available = true;
    const drained = await recordLifecycleEvent({
      apiKey: 'test-mcp-spool-key',
      baseUrl: 'https://api.example.com',
      event: {
        event_id: 'mcp-event-two',
        event_type: 'outcome_committed',
        agent_id: 'agent-one',
        action: 'publish package',
        outcome_state: 'closed',
        success: true,
      },
    });
    assert.equal(drained.queued, false);
    assert.deepEqual(JSON.parse(readFileSync(path, 'utf8')), []);
    assert.deepEqual(delivered.slice(-2).map((event) => event.event_id), ['mcp-event-one', 'mcp-event-two']);
  } finally {
    globalThis.fetch = originalFetch;
    if (originalPath === undefined) delete process.env.MARROW_EVENT_SPOOL_PATH;
    else process.env.MARROW_EVENT_SPOOL_PATH = originalPath;
    rmSync(directory, { recursive: true, force: true });
  }
});
