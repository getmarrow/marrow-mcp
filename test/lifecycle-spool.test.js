const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const {
  chmodSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} = require('node:fs');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');
const test = require('node:test');

const { recordLifecycleEvent } = require('../dist/lifecycle-spool.js');

function withSpoolPath(path, callback) {
  const originalPath = process.env.MARROW_EVENT_SPOOL_PATH;
  process.env.MARROW_EVENT_SPOOL_PATH = path;
  return Promise.resolve()
    .then(callback)
    .finally(() => {
      if (originalPath === undefined) delete process.env.MARROW_EVENT_SPOOL_PATH;
      else process.env.MARROW_EVENT_SPOOL_PATH = originalPath;
    });
}

function lifecycleInput(event) {
  return {
    apiKey: 'test-mcp-spool-key',
    baseUrl: 'https://api.example.com',
    event: {
      event_id: 'mcp-event-one',
      event_type: 'tool_completed',
      agent_id: 'agent-one',
      action: 'tool execution observed; business outcome pending',
      outcome_state: 'pending',
      success: true,
      ...event,
    },
  };
}

test('passive hooks use stable source correlations and never auto-close tool exits as business success', () => {
  const hook = readFileSync(join(__dirname, '../src/hook.ts'), 'utf8');
  const context = readFileSync(join(__dirname, '../src/hook-context.ts'), 'utf8');

  assert.match(hook, /stableHookCorrelation/);
  assert.match(hook, /event_id: `posttool-\$\{lifecycleCorrelation\}`/);
  assert.match(hook, /business outcome pending/);
  assert.doesNotMatch(hook, /marrowAuto\(/);
  assert.doesNotMatch(hook, /outcome_committed/);
  assert.match(context, /classified agent request:/);
  assert.doesNotMatch(context, /const action = redactedPrompt|action: redactedPrompt/);
  assert.match(context, /event_id: `prompt-\$\{requestCorrelation\}`/);
  assert.match(context, /event_id: `preaction-\$\{requestCorrelation\}`/);
  assert.match(hook, /observed_hook: 'action_result'/);
  assert.match(context, /observed_hook: 'pre_action'/);
});

test('native MCP hook receipts carry bounded capability and configuration evidence', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-capability-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response('{}', { status: 503 });
  try {
    await withSpoolPath(path, async () => {
      await recordLifecycleEvent(lifecycleInput({
        correlation_id: 'correlation-one',
        observed_hook: 'action_result',
      }));
      const [event] = JSON.parse(readFileSync(path, 'utf8'));
      assert.equal(event.correlation_id, 'correlation-one');
      assert.equal(event.capability_level, 'native_hooks');
      assert.equal(event.adapter_version, '3.9.50');
      assert.match(event.config_fingerprint, /^[a-f0-9]{64}$/);
      assert.deepEqual(event.expected_hooks, ['pre_action', 'action_result', 'session_end']);
      assert.equal(event.observed_hook, 'action_result');
    });
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('MCP lifecycle spool keeps compact redacted receipts across process attempts', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-spool-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  let available = false;
  const delivered = [];
  globalThis.fetch = async (_url, init) => {
    delivered.push(JSON.parse(init.body));
    return available
      ? new Response(JSON.stringify({ data: { accepted: true } }), { status: 200 })
      : new Response(JSON.stringify({ error: 'temporary' }), { status: 503 });
  };

  try {
    await withSpoolPath(path, async () => {
      const queued = await recordLifecycleEvent(lifecycleInput({
        action: 'publish with --token secret-value-that-must-not-persist',
      }));
      assert.equal(queued.accepted, false);
      assert.equal(queued.queued, true);
      assert.equal(statSync(path).mode & 0o777, 0o600);
      assert.doesNotMatch(readFileSync(path, 'utf8'), /secret-value-that-must-not-persist/);

      available = true;
      const drained = await recordLifecycleEvent(lifecycleInput({
        event_id: 'mcp-event-two',
        event_type: 'outcome_committed',
        action: 'explicit outcome evidence recorded',
        outcome_state: 'closed',
      }));
      assert.equal(drained.accepted, true);
      assert.equal(drained.queued, false);
      assert.deepEqual(JSON.parse(readFileSync(path, 'utf8')), []);
      assert.deepEqual(delivered.slice(-2).map((event) => event.event_id), ['mcp-event-one', 'mcp-event-two']);
    });
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('terminal rejection and exhausted retries remain explicit durable dead letters', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-reject-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  try {
    await withSpoolPath(path, async () => {
      globalThis.fetch = async () => new Response('{}', { status: 400 });
      const rejected = await recordLifecycleEvent(lifecycleInput({ event_id: 'terminal-reject' }));
      assert.equal(rejected.accepted, false);
      assert.equal(rejected.failed, true);
      assert.match(readFileSync(path, 'utf8'), /"delivery_state":"dead_letter"/);

      globalThis.fetch = async () => new Response('{}', { status: 503 });
      let exhausted;
      for (let attempt = 0; attempt < 3; attempt += 1) {
        exhausted = await recordLifecycleEvent(lifecycleInput({ event_id: 'retry-exhausted' }));
      }
      assert.equal(exhausted.accepted, false);
      assert.equal(exhausted.failed, true);
      const row = JSON.parse(readFileSync(path, 'utf8')).find((event) => event.event_id === 'retry-exhausted');
      assert.equal(row.delivery_state, 'dead_letter');
      assert.equal(row.attempts, 3);
    });
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('runtime validation rejects unrestricted fields and keeps every record byte-bounded', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-bounds-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response('{}', { status: 503 });
  try {
    await withSpoolPath(path, async () => {
      await assert.rejects(
        recordLifecycleEvent(lifecycleInput({ event_type: 'private prompt content' })),
        /invalid lifecycle event_type/,
      );
      await assert.rejects(
        recordLifecycleEvent(lifecycleInput({ occurred_at: 'not-a-timestamp' })),
        /invalid lifecycle occurred_at/,
      );
      await assert.rejects(
        recordLifecycleEvent(lifecycleInput({ workflow_id: 'private workflow value with spaces' })),
        /invalid lifecycle workflow_id/,
      );
      await recordLifecycleEvent(lifecycleInput({
        event_id: 'bounded-record',
        action: `owner@example.com https://private.example/path /home/customer/private ${'private '.repeat(2000)}`,
      }));
      const stored = readFileSync(path, 'utf8');
      assert.ok(Buffer.byteLength(stored, 'utf8') < 4096);
      assert.doesNotMatch(stored, /owner@example\.com|private\.example|\/home\/customer/);
    });
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('corrupt spool is quarantined and custom parent permissions are preserved', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-corrupt-'));
  const parent = join(directory, 'shared-parent');
  const path = join(parent, 'spool.json');
  mkdirSync(parent, { mode: 0o755 });
  chmodSync(parent, 0o755);
  writeFileSync(path, '{not-json');
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response('{}', { status: 503 });
  try {
    await withSpoolPath(path, async () => {
      const result = await recordLifecycleEvent(lifecycleInput({ event_id: 'after-corruption' }));
      assert.equal(result.recovered_corruption, true);
      assert.equal(statSync(parent).mode & 0o777, 0o755);
      assert.ok(readdirSync(parent).some((name) => name.startsWith('spool.json.corrupt-')));
      assert.match(readFileSync(path, 'utf8'), /after-corruption/);
    });
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('bounded delivery timeout cannot stall a hook when fetch ignores abort', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-timeout-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  globalThis.fetch = () => new Promise(() => {});
  try {
    await withSpoolPath(path, async () => {
      const started = Date.now();
      const result = await recordLifecycleEvent(lifecycleInput({ event_id: 'timeout-event' }));
      assert.ok(Date.now() - started < 1500);
      assert.equal(result.queued, true);
      assert.match(readFileSync(path, 'utf8'), /timeout-event/);
    });
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('same-namespace concurrent hook processes do not lose lifecycle receipts', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-concurrent-'));
  const path = join(directory, 'spool.json');
  const modulePath = resolve(__dirname, '../dist/lifecycle-spool.js');
  const workers = Array.from({ length: 120 }, (_, index) => new Promise((resolveWorker, rejectWorker) => {
    const script = `
      global.fetch = async () => new Response('{}', { status: 503 });
      const { recordLifecycleEvent } = require(${JSON.stringify(modulePath)});
      recordLifecycleEvent({
        apiKey: 'test-concurrent-key',
        baseUrl: 'https://api.example.com',
        event: {
          event_id: 'worker-${index}',
          event_type: 'tool_completed',
          agent_id: 'agent-one',
          action: 'tool execution observed',
          outcome_state: 'pending',
          success: true
        }
      }).then(() => process.exit(0), () => process.exit(1));
    `;
    const child = spawn(process.execPath, ['-e', script], {
      env: { ...process.env, MARROW_EVENT_SPOOL_PATH: path },
      stdio: 'ignore',
    });
    child.once('error', rejectWorker);
    child.once('exit', (code) => code === 0 ? resolveWorker() : rejectWorker(new Error(`worker exited ${code}`)));
  }));

  try {
    await Promise.all(workers);
    const events = JSON.parse(readFileSync(path, 'utf8'));
    assert.equal(new Set(events.map((event) => event.event_id)).size, 120);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
