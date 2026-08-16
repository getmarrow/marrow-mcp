const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const {
  chmodSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  lstatSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} = require('node:fs');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');
const test = require('node:test');

const {
  drainLifecycleSpool,
  lifecycleSpoolStatus,
  recordLifecycleEvent,
} = require('../dist/lifecycle-spool.js');
const { lifecycleSpoolCommandOutcome } = require('../dist/spool-command.js');
const {
  nativeHookConfigurationFingerprint,
  nativeHookEvidence,
  stableSessionWorkflowId,
  stableToolCorrelation,
} = require('../dist/hook-contract.js');
const { preActionHookOutput } = require('../dist/hook-pre-action.js');

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

test('passive hooks use joinable action bindings without treating tool exits as business success', () => {
  const hook = readFileSync(join(__dirname, '../src/hook.ts'), 'utf8');
  const context = readFileSync(join(__dirname, '../src/hook-context.ts'), 'utf8');
  const preAction = readFileSync(join(__dirname, '../src/hook-pre-action.ts'), 'utf8');

  assert.match(hook, /stableToolCorrelation/);
  assert.match(preAction, /stableToolCorrelation/);
  assert.match(hook, /event_id: `posttool-\$\{lifecycleCorrelation\}`/);
  assert.match(preAction, /event_id: `pretool-\$\{correlation\}`/);
  assert.match(hook, /return classifyTool\(event\)\.action/);
  assert.match(hook, /outcome_state: 'pending'/);
  assert.doesNotMatch(hook, /marrowAuto\(/);
  assert.doesNotMatch(hook, /outcome_committed/);
  assert.match(context, /classified agent request:/);
  assert.doesNotMatch(context, /const action = redactedPrompt|action: redactedPrompt/);
  assert.match(context, /event_id: `prompt-\$\{requestCorrelation\}`/);
  assert.match(hook, /nativeHookEvidence\('action_result'\)/);
  assert.match(hook, /target: classified\.target/);
  assert.match(hook, /surfaces: classified\.surfaces/);
  assert.match(context, /nativeHookEvidence\('prompt'\)/);
});

test('generic lifecycle events cannot impersonate native hook coverage', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-capability-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response('{}', { status: 503 });
  try {
    await withSpoolPath(path, async () => {
      await recordLifecycleEvent(lifecycleInput({
        correlation_id: 'correlation-one',
        target: 'production:deploy',
        surfaces: ['production', 'github'],
        observed_hook: 'action_result',
      }));
      const [event] = JSON.parse(readFileSync(path, 'utf8'));
      assert.equal(event.correlation_id, 'correlation-one');
      assert.equal(event.target, 'production:deploy');
      assert.deepEqual(event.surfaces, ['github', 'production']);
      assert.equal('capability_level' in event, false);
      assert.equal('adapter_version' in event, false);
      assert.equal('config_fingerprint' in event, false);
      assert.equal('expected_hooks' in event, false);
      assert.equal(event.observed_hook, 'action_result');
    });
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('native MCP hook receipts carry bounded capability and actual configuration evidence', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-native-capability-'));
  const path = join(directory, 'spool.json');
  const settingsDir = join(directory, '.claude');
  mkdirSync(settingsDir, { recursive: true });
  writeFileSync(join(settingsDir, 'settings.json'), JSON.stringify({
    hooks: {
      UserPromptSubmit: [{ hooks: [{ type: 'command', command: 'npx -y @getmarrow/mcp@3.9.62 context-hook' }] }],
      PreToolUse: [{ matcher: 'Bash|Edit|Write|MultiEdit|mcp__(?!marrow__marrow_).*', hooks: [{ type: 'command', command: 'npx -y @getmarrow/mcp@3.9.62 pre-action-hook' }] }],
      PostToolUse: [{ matcher: 'Bash|Edit|Write|MultiEdit|mcp__(?!marrow__marrow_).*', hooks: [{ type: 'command', command: 'npx -y @getmarrow/mcp@3.9.62 hook' }] }],
      PostToolUseFailure: [{ matcher: 'Bash|Edit|Write|MultiEdit|mcp__(?!marrow__marrow_).*', hooks: [{ type: 'command', command: 'npx -y @getmarrow/mcp@3.9.62 hook' }] }],
      Stop: [{ hooks: [{ type: 'command', command: 'npx -y @getmarrow/mcp@3.9.62 session-hook' }] }],
    },
  }));
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response('{}', { status: 503 });
  try {
    await withSpoolPath(path, async () => {
      await recordLifecycleEvent(lifecycleInput({
        correlation_id: 'correlation-native',
        ...nativeHookEvidence('action_result', directory),
      }));
      const [event] = JSON.parse(readFileSync(path, 'utf8'));
      assert.equal(event.capability_level, 'native_hooks');
      assert.equal(event.adapter_version, '3.9.62');
      assert.match(event.config_fingerprint, /^[a-f0-9]{64}$/);
      assert.deepEqual(event.expected_hooks, ['prompt', 'pre_action', 'action_result', 'session_end']);
      assert.equal(event.observed_hook, 'action_result');

      const before = nativeHookConfigurationFingerprint(directory);
      const changed = JSON.parse(readFileSync(join(settingsDir, 'settings.json'), 'utf8'));
      changed.hooks.PreToolUse[0].hooks[0].timeout = 15;
      writeFileSync(join(settingsDir, 'settings.json'), JSON.stringify(changed));
      assert.notEqual(nativeHookConfigurationFingerprint(directory), before);
    });
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('pre-action and result hooks share tool correlation while sessions share workflow identity', () => {
  const event = {
    session_id: 'session-one',
    tool_use_id: 'tool-use-one',
    tool_name: 'Bash',
    tool_input: { command: 'deploy' },
  };
  assert.equal(stableToolCorrelation(event), stableToolCorrelation({ ...event, tool_input: { command: 'changed after execution' } }));
  assert.notEqual(stableToolCorrelation(event), stableToolCorrelation({ ...event, tool_use_id: 'tool-use-two' }));
  assert.equal(stableSessionWorkflowId('session-one'), stableSessionWorkflowId('session-one', 'other'));
});

test('pre-action policy maps block to deny, review to ask, and allow to native permission flow', () => {
  const block = preActionHookOutput({
    runtime: { risk_gate: { allow: false, decision: 'block', reasons: [{ message: 'proof missing' }] }, exact_next_action: 'collect proof' },
    permit: { verified: true, permit_id: 'permit-block' },
    protectedRisk: true,
  });
  assert.equal(block.hookSpecificOutput.permissionDecision, 'deny');
  assert.equal(block.hookSpecificOutput.permissionDecisionReason, 'collect proof');

  const review = preActionHookOutput({
    runtime: { risk_gate: { allow: false, decision: 'review_required', reasons: [] }, exact_next_action: 'ask owner' },
    permit: { verified: true, permit_id: 'permit-review' },
    protectedRisk: true,
  });
  assert.equal(review.hookSpecificOutput.permissionDecision, 'ask');

  const allow = preActionHookOutput({
    runtime: { risk_gate: { allow: true, decision: 'allow', reasons: [] }, before_you_act: 'reuse the prior lesson' },
    permit: { verified: true, permit_id: 'permit-allow' },
    protectedRisk: false,
  });
  assert.equal('permissionDecision' in allow.hookSpecificOutput, false);
  assert.match(allow.hookSpecificOutput.additionalContext, /reuse the prior lesson/);
  assert.match(allow.hookSpecificOutput.additionalContext, /permit-allow/);

  const unavailable = preActionHookOutput({ runtime: null, permit: null, protectedRisk: true });
  assert.equal(unavailable.hookSpecificOutput.permissionDecision, 'deny');
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
      assert.deepEqual(delivered.slice(-2).map((event) => event.event_id), ['mcp-event-two', 'mcp-event-one']);
    });
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('MCP lifecycle spool reports aggregate backlog health and drains without adding an event', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-spool-health-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  let available = false;
  globalThis.fetch = async () => available
    ? new Response(JSON.stringify({ data: { accepted: true } }), { status: 200 })
    : new Response('{}', { status: 503 });
  try {
    await withSpoolPath(path, async () => {
      await recordLifecycleEvent(lifecycleInput({ event_id: 'health-event-one' }));
      const pending = lifecycleSpoolStatus({ apiKey: 'test-mcp-spool-key', agentId: 'agent-one' });
      assert.equal(pending.state, 'pending');
      assert.equal(pending.pending, 1);
      assert.equal(pending.failed, 0);
      assert.match(pending.oldest_pending_at, /^\d{4}-/);
      assert.equal(pending.available, pending.capacity - 1);
      assert.doesNotMatch(JSON.stringify(pending), /tool execution observed/);

      available = true;
      const clear = await drainLifecycleSpool({
        apiKey: 'test-mcp-spool-key',
        baseUrl: 'https://api.example.com',
        agentId: 'agent-one',
      });
      assert.equal(clear.state, 'clear');
      assert.equal(clear.pending, 0);
      assert.deepEqual(JSON.parse(readFileSync(path, 'utf8')), []);
    });
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('explicit drain tolerates slow edge delivery without lengthening passive hooks', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-slow-drain-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  let slowDelivery = false;
  globalThis.fetch = async () => {
    if (!slowDelivery) return new Response('{}', { status: 503 });
    await new Promise((resolve) => setTimeout(resolve, 1_100));
    return new Response('{}', { status: 200 });
  };
  try {
    await withSpoolPath(path, async () => {
      const queued = await recordLifecycleEvent(lifecycleInput({ event_id: 'slow-drain-event' }));
      assert.equal(queued.queued, true);
      slowDelivery = true;
      const started = Date.now();
      const drained = await drainLifecycleSpool({
        apiKey: 'test-mcp-spool-key',
        baseUrl: 'https://api.example.com',
        agentId: 'agent-one',
      });
      assert.ok(Date.now() - started >= 1_000);
      assert.equal(drained.state, 'clear');
      assert.equal(drained.pending, 0);
    });
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('deferred lifecycle capture writes locally without a network call', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-deferred-'));
  const path = join(directory, 'spool.json');
  const originalFetch = global.fetch;
  let calls = 0;
  global.fetch = async () => { calls += 1; throw new Error('network should not be called'); };
  process.env.MARROW_EVENT_SPOOL_PATH = path;
  try {
    const result = await recordLifecycleEvent({ ...lifecycleInput({ event_id: 'deferred-prompt' }), deferDelivery: true });
    assert.equal(result.queued, true);
    assert.equal(calls, 0);
  } finally {
    global.fetch = originalFetch;
    delete process.env.MARROW_EVENT_SPOOL_PATH;
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
      assert.equal(row.last_status, 503);
      assert.match(
        lifecycleSpoolStatus({ apiKey: 'test-mcp-spool-key', agentId: 'agent-one' }).exact_fix,
        /timed out|unavailable/i,
      );
    });
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('explicit drain retries durable dead letters after the delivery problem is fixed', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-dead-letter-recovery-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  let available = false;
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    return new Response('{}', { status: available ? 200 : 400 });
  };
  try {
    await withSpoolPath(path, async () => {
      const rejected = await recordLifecycleEvent(lifecycleInput({ event_id: 'recover-dead-letter' }));
      assert.equal(rejected.failed, true);
      assert.equal(lifecycleSpoolStatus({ apiKey: 'test-mcp-spool-key', agentId: 'agent-one' }).failed, 1);

      available = true;
      const drained = await drainLifecycleSpool({
        apiKey: 'test-mcp-spool-key',
        baseUrl: 'https://api.example.com',
        agentId: 'agent-one',
      });
      assert.equal(drained.state, 'clear');
      assert.equal(drained.failed, 0);
      assert.equal(drained.pending, 0);
      assert.equal(calls, 2);
    });
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('mixed drain does not hide dead letters that were never retried', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-mixed-drain-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  try {
    await withSpoolPath(path, async () => {
      globalThis.fetch = async () => new Response('{}', { status: 503 });
      await recordLifecycleEvent(lifecycleInput({ event_id: 'mixed-pending' }));
      globalThis.fetch = async () => new Response('{}', { status: 400 });
      await recordLifecycleEvent(lifecycleInput({ event_id: 'mixed-dead' }));

      globalThis.fetch = async () => new Response('{}', { status: 503 });
      const status = await drainLifecycleSpool({
        apiKey: 'test-mcp-spool-key',
        baseUrl: 'https://api.example.com',
        agentId: 'agent-one',
      });
      assert.equal(status.state, 'attention_required');
      assert.equal(status.failed, 1);
      assert.equal(status.pending, 1);
    });
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('spool status exposes older credential namespaces without replaying them under the current key', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-spool-inventory-'));
  const home = join(directory, 'home');
  const originalHome = process.env.HOME;
  const originalPath = process.env.MARROW_EVENT_SPOOL_PATH;
  const originalFetch = globalThis.fetch;
  mkdirSync(home, { recursive: true, mode: 0o700 });
  process.env.HOME = home;
  delete process.env.MARROW_EVENT_SPOOL_PATH;
  try {
    await recordLifecycleEvent({
      ...lifecycleInput({ event_id: 'old-key-event', agent_id: 'agent-one' }),
      apiKey: 'old-key-for-inventory-test',
      deferDelivery: true,
    });
    await recordLifecycleEvent({
      ...lifecycleInput({ event_id: 'current-key-event', agent_id: 'agent-one' }),
      apiKey: 'current-key-for-inventory-test',
      deferDelivery: true,
    });
    const status = lifecycleSpoolStatus({ apiKey: 'current-key-for-inventory-test', agentId: 'agent-one' });
    assert.equal(status.pending, 1);
    assert.equal(status.other_namespaces.state, 'attention_required');
    assert.equal(status.other_namespaces.count, 1);
    assert.equal(status.other_namespaces.pending, 1);
    assert.match(status.other_namespaces.exact_fix, /Legacy debt never blocks/);

    let delivered = 0;
    globalThis.fetch = async () => {
      delivered += 1;
      return new Response('{}', { status: 200 });
    };
    const drained = await drainLifecycleSpool({
      apiKey: 'current-key-for-inventory-test',
      baseUrl: 'https://api.example.com',
      agentId: 'agent-one',
    });
    assert.equal(delivered, 1);
    assert.equal(drained.pending, 0);
    assert.equal(drained.other_namespaces.pending, 1);
    assert.equal(drained.other_namespaces.event_counts_exact, true);
    assert.equal(drained.other_namespaces.blocks_current_namespace, false);
    assert.match(drained.other_namespaces.safe_recovery_action, /exact original agent identity/);
    assert.match(drained.other_namespaces.safe_quarantine_action, /do not copy, merge, replay, edit, or delete/);
  } finally {
    globalThis.fetch = originalFetch;
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalPath === undefined) delete process.env.MARROW_EVENT_SPOOL_PATH;
    else process.env.MARROW_EVENT_SPOOL_PATH = originalPath;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('drain and status exit successfully for a clear active namespace while reporting isolated legacy debt', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-spool-cli-scope-'));
  const home = join(directory, 'home');
  const originalHome = process.env.HOME;
  const originalPath = process.env.MARROW_EVENT_SPOOL_PATH;
  const originalFetch = globalThis.fetch;
  mkdirSync(home, { recursive: true, mode: 0o700 });
  process.env.HOME = home;
  delete process.env.MARROW_EVENT_SPOOL_PATH;
  try {
    await recordLifecycleEvent({
      ...lifecycleInput({ event_id: 'legacy-pending', agent_id: 'agent-one' }),
      apiKey: 'legacy-cli-key',
      deferDelivery: true,
    });
    globalThis.fetch = async () => new Response('{}', { status: 400 });
    await recordLifecycleEvent({
      ...lifecycleInput({ event_id: 'legacy-failed', agent_id: 'agent-one' }),
      apiKey: 'legacy-cli-key',
    });

    const status = lifecycleSpoolStatus({ apiKey: 'current-cli-key', agentId: 'agent-one' });
    for (const drain of [false, true]) {
      const outcome = lifecycleSpoolCommandOutcome(status, drain);
      assert.equal(outcome.exitCode, 0);
      assert.equal(outcome.output.ok, true);
      assert.equal(outcome.output.scope, 'current_credential_namespace');
      assert.equal(outcome.output.legacy_namespace_debt, true);
      assert.equal(outcome.output.lifecycle_spool.state, 'clear');
      assert.equal(outcome.output.lifecycle_spool.pending, 0);
      assert.equal(outcome.output.lifecycle_spool.failed, 0);
      assert.equal(outcome.output.lifecycle_spool.other_namespaces.pending, 1);
      assert.equal(outcome.output.lifecycle_spool.other_namespaces.failed, 1);
      assert.equal(outcome.output.lifecycle_spool.other_namespaces.blocks_current_namespace, false);
    }
  } finally {
    globalThis.fetch = originalFetch;
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalPath === undefined) delete process.env.MARROW_EVENT_SPOOL_PATH;
    else process.env.MARROW_EVENT_SPOOL_PATH = originalPath;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('active namespace failures retain a nonzero exit independently of legacy inventory', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-spool-cli-active-fail-'));
  const home = join(directory, 'home');
  const originalHome = process.env.HOME;
  const originalPath = process.env.MARROW_EVENT_SPOOL_PATH;
  const originalFetch = globalThis.fetch;
  mkdirSync(home, { recursive: true, mode: 0o700 });
  process.env.HOME = home;
  delete process.env.MARROW_EVENT_SPOOL_PATH;
  try {
    globalThis.fetch = async () => new Response('{}', { status: 400 });
    await recordLifecycleEvent({
      ...lifecycleInput({ event_id: 'current-failed', agent_id: 'agent-one' }),
      apiKey: 'current-failed-key',
    });
    const status = lifecycleSpoolStatus({ apiKey: 'current-failed-key', agentId: 'agent-one' });
    const outcome = lifecycleSpoolCommandOutcome(status, false);
    assert.equal(outcome.exitCode, 2);
    assert.equal(outcome.output.ok, false);
    assert.equal(outcome.output.lifecycle_spool.state, 'attention_required');
    assert.equal(outcome.output.lifecycle_spool.failed, 1);
  } finally {
    globalThis.fetch = originalFetch;
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalPath === undefined) delete process.env.MARROW_EVENT_SPOOL_PATH;
    else process.env.MARROW_EVENT_SPOOL_PATH = originalPath;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('older namespace inventory is bounded and reports truncation', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-spool-inventory-bound-'));
  const home = join(directory, 'home');
  const originalHome = process.env.HOME;
  const originalPath = process.env.MARROW_EVENT_SPOOL_PATH;
  mkdirSync(home, { recursive: true, mode: 0o700 });
  process.env.HOME = home;
  delete process.env.MARROW_EVENT_SPOOL_PATH;
  try {
    await recordLifecycleEvent({
      ...lifecycleInput({ event_id: 'current-bound-event', agent_id: 'agent-one' }),
      apiKey: 'current-key-for-bound-test',
      deferDelivery: true,
    });
    const spoolDirectory = join(home, '.marrow', 'spool');
    for (let index = 0; index < 129; index += 1) {
      const suffix = index.toString(16).padStart(20, '0');
      writeFileSync(join(spoolDirectory, `mcp-${suffix}.json`), '[]', { mode: 0o600 });
    }
    const status = lifecycleSpoolStatus({ apiKey: 'current-key-for-bound-test', agentId: 'agent-one' });
    assert.equal(status.other_namespaces.count, 129);
    assert.equal(status.other_namespaces.count_exact, false);
    assert.equal(status.other_namespaces.event_counts_exact, false);
    assert.equal(status.other_namespaces.scanned, 128);
    assert.equal(status.other_namespaces.scan_limit, 128);
    assert.equal(status.other_namespaces.directory_entries_scanned, 130);
    assert.equal(status.other_namespaces.directory_entry_limit, 1024);
    assert.equal(status.other_namespaces.truncated, true);
    assert.equal(status.other_namespaces.state, 'attention_required');
    assert.match(status.other_namespaces.exact_fix, /bounded scan limit/i);
  } finally {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalPath === undefined) delete process.env.MARROW_EVENT_SPOOL_PATH;
    else process.env.MARROW_EVENT_SPOOL_PATH = originalPath;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('legacy inventory bounds total directory traversal even when entries do not match spool filenames', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-spool-directory-bound-'));
  const home = join(directory, 'home');
  const originalHome = process.env.HOME;
  const originalPath = process.env.MARROW_EVENT_SPOOL_PATH;
  const spoolDirectory = join(home, '.marrow', 'spool');
  mkdirSync(spoolDirectory, { recursive: true, mode: 0o700 });
  process.env.HOME = home;
  delete process.env.MARROW_EVENT_SPOOL_PATH;
  try {
    for (let index = 0; index < 1025; index += 1) {
      writeFileSync(join(spoolDirectory, `unrelated-${index}`), '', { mode: 0o600 });
    }
    const status = lifecycleSpoolStatus({ apiKey: 'current-directory-bound-key', agentId: 'agent-one' });
    assert.equal(status.state, 'clear');
    assert.equal(status.other_namespaces.state, 'attention_required');
    assert.equal(status.other_namespaces.count_exact, false);
    assert.equal(status.other_namespaces.directory_entries_scanned, 1024);
    assert.equal(status.other_namespaces.directory_entry_limit, 1024);
    assert.equal(status.other_namespaces.truncated, true);
    assert.equal(status.other_namespaces.blocks_current_namespace, false);
  } finally {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalPath === undefined) delete process.env.MARROW_EVENT_SPOOL_PATH;
    else process.env.MARROW_EVENT_SPOOL_PATH = originalPath;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('legacy inventory rejects symlinks, weak permissions, corruption, and oversize files without affecting active state', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-spool-inventory-adversarial-'));
  const home = join(directory, 'home');
  const originalHome = process.env.HOME;
  const originalPath = process.env.MARROW_EVENT_SPOOL_PATH;
  mkdirSync(join(home, '.marrow', 'spool'), { recursive: true, mode: 0o700 });
  process.env.HOME = home;
  delete process.env.MARROW_EVENT_SPOOL_PATH;
  try {
    const spoolDirectory = join(home, '.marrow', 'spool');
    const outside = join(directory, 'outside.json');
    writeFileSync(outside, '[]', { mode: 0o600 });
    symlinkSync(outside, join(spoolDirectory, 'mcp-00000000000000000001.json'));
    writeFileSync(join(spoolDirectory, 'mcp-00000000000000000002.json'), '[]', { mode: 0o644 });
    writeFileSync(join(spoolDirectory, 'mcp-00000000000000000003.json'), '{bad-json', { mode: 0o600 });
    writeFileSync(join(spoolDirectory, 'mcp-00000000000000000004.json'), 'x'.repeat(2 * 1024 * 1024 + 1), { mode: 0o600 });

    const status = lifecycleSpoolStatus({ apiKey: 'current-adversarial-key', agentId: 'agent-one' });
    assert.equal(status.state, 'clear');
    assert.equal(status.pending, 0);
    assert.equal(status.failed, 0);
    assert.equal(status.other_namespaces.state, 'attention_required');
    assert.equal(status.other_namespaces.unreadable, 4);
    assert.equal(status.other_namespaces.event_counts_exact, false);
    assert.equal(status.other_namespaces.blocks_current_namespace, false);
    assert.equal(readFileSync(outside, 'utf8'), '[]');
    assert.equal(lstatSync(join(spoolDirectory, 'mcp-00000000000000000001.json')).isSymbolicLink(), true);
  } finally {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalPath === undefined) delete process.env.MARROW_EVENT_SPOOL_PATH;
    else process.env.MARROW_EVENT_SPOOL_PATH = originalPath;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('edge spool delivery is host and model neutral for MCP and SDK-owned lifecycle adapters', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-spool-neutral-hosts-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  try {
    await withSpoolPath(path, async () => {
      for (const [index, adapter] of [
        ['grok-mcp', 'mcp'],
        ['claude-code', 'native_hooks'],
        ['codex-mcp', 'mcp'],
        ['owned-node-runtime', 'sdk_passive_runtime'],
      ].entries()) {
        await recordLifecycleEvent({
          ...lifecycleInput({
            event_id: `neutral-host-${index}`,
            harness: adapter[0],
            capability_level: adapter[1],
          }),
          deferDelivery: true,
        });
      }
      assert.equal(lifecycleSpoolStatus({ apiKey: 'test-mcp-spool-key', agentId: 'agent-one' }).pending, 4);
      let delivered = 0;
      globalThis.fetch = async () => {
        delivered += 1;
        return new Response('{}', { status: 200 });
      };
      const status = await drainLifecycleSpool({
        apiKey: 'test-mcp-spool-key',
        baseUrl: 'https://api.example.com',
        agentId: 'agent-one',
      });
      assert.equal(delivered, 4);
      assert.equal(status.state, 'clear');
      assert.equal(status.pending, 0);
      assert.equal(status.failed, 0);
    });
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('spool commands reject process-list key material without echoing it', () => {
  const source = readFileSync(resolve(__dirname, '../src/cli.ts'), 'utf8');
  assert.match(source, /if \(cliArgs\.apiKey\)[\s\S]{0,400}--key is not accepted/);
  assert.doesNotMatch(source, /--key is not accepted[^\n]*\$\{cliArgs\.apiKey\}/);
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
  chmodSync(path, 0o600);
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

test('custom spool rejects a non-sticky world-writable ancestor', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-unsafe-ancestor-'));
  const unsafeParent = join(directory, 'unsafe');
  mkdirSync(unsafeParent, { mode: 0o777 });
  chmodSync(unsafeParent, 0o777);
  const path = join(unsafeParent, 'state', 'spool.json');
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response('{}', { status: 503 });
  try {
    await withSpoolPath(path, async () => {
      await assert.rejects(
        recordLifecycleEvent(lifecycleInput({ event_id: 'reject-unsafe-ancestor' })),
        /non-sticky writable ancestor/,
      );
    });
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('default spool rejects symlinked path components without mutating the target', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-default-symlink-'));
  const home = join(directory, 'home');
  const target = join(directory, 'outside');
  const originalHome = process.env.HOME;
  const originalPath = process.env.MARROW_EVENT_SPOOL_PATH;
  mkdirSync(join(home, '.marrow'), { recursive: true, mode: 0o700 });
  mkdirSync(target, { mode: 0o755 });
  chmodSync(target, 0o755);
  symlinkSync(target, join(home, '.marrow', 'spool'), 'dir');
  process.env.HOME = home;
  delete process.env.MARROW_EVENT_SPOOL_PATH;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response('{}', { status: 503 });
  try {
    await assert.rejects(
      recordLifecycleEvent(lifecycleInput({ event_id: 'reject-default-symlink' })),
      /cannot contain symlinked components/,
    );
    assert.equal(lstatSync(join(home, '.marrow', 'spool')).isSymbolicLink(), true);
    assert.equal(statSync(target).mode & 0o777, 0o755);
    assert.deepEqual(readdirSync(target), []);
  } finally {
    globalThis.fetch = originalFetch;
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalPath === undefined) delete process.env.MARROW_EVENT_SPOOL_PATH;
    else process.env.MARROW_EVENT_SPOOL_PATH = originalPath;
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
    const errorPath = join(directory, `worker-${index}.error`);
    const script = `
      const fs = require('node:fs');
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
      }).then(
        () => { process.exitCode = 0; },
        (error) => {
          const detail = String(error?.stack || error);
          console.error(detail);
          fs.writeFileSync(${JSON.stringify(errorPath)}, detail);
          process.exitCode = 1;
        },
      );
    `;
    const child = spawn(process.execPath, ['-e', script], {
      env: { ...process.env, MARROW_EVENT_SPOOL_PATH: path },
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', (chunk) => { stderr += chunk.toString('utf8').slice(0, 1000); });
    child.once('error', rejectWorker);
    child.once('exit', (code) => code === 0
      ? resolveWorker()
      : rejectWorker(new Error(`worker exited ${code}: ${stderr.trim() || (existsSync(errorPath) ? readFileSync(errorPath, 'utf8') : 'no error detail')}`)));
  }));

  try {
    await Promise.all(workers);
    const events = JSON.parse(readFileSync(path, 'utf8'));
    assert.equal(new Set(events.map((event) => event.event_id)).size, 120);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
