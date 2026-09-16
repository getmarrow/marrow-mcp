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
  nudgeLifecycleSpool,
  quarantineLegacyNamespaces,
  recordLifecycleEvent,
} = require('../dist/lifecycle-spool.js');
const { lifecycleSpoolCommandOutcome } = require('../dist/spool-command.js');
const {
  clientReportedHookLifecycleIdentity,
  localHookConfigurationFingerprint,
  resolveNativeHookIdentity,
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

test('bounded nudge backs off transient failures, preserves wire identity, and recovers without foreground network work', async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-transient-schedule-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  const bodies = [];
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: Date.parse('2026-09-09T12:00:00.000Z') });
  try {
    await withSpoolPath(path, async () => {
      globalThis.fetch = async (_url, init) => {
        bodies.push(init.body);
        return new Response('{}', { status: bodies.length === 1 ? 503 : 200 });
      };
      const input = { ...lifecycleInput({ event_id: 'scheduled-transient' }), deferDelivery: true };
      await recordLifecycleEvent(input);
      assert.equal(bodies.length, 0, 'deferred local capture never enters fetch');
      const nudge = nudgeLifecycleSpool({ apiKey: input.apiKey, baseUrl: input.baseUrl, agentId: input.event.agent_id });
      await new Promise(setImmediate);
      assert.equal(bodies.length, 1);
      let status = lifecycleSpoolStatus({ apiKey: input.apiKey, agentId: input.event.agent_id });
      assert.equal(status.pending, 1);
      assert.equal(status.failed, 0);
      assert.equal(status.retry.scheduled, 1);
      assert.equal(status.retry.reasons.transient_http, 1);
      t.mock.timers.tick(999);
      await new Promise(setImmediate);
      assert.equal(bodies.length, 1, 'no early background retry');
      t.mock.timers.tick(1);
      await nudge;
      assert.equal(bodies.length, 2);
      assert.equal(bodies[0], bodies[1], 'local attempt metadata never changes the server request');
      assert.equal('next_attempt_at' in JSON.parse(bodies[1]), false);
      status = lifecycleSpoolStatus({ apiKey: input.apiKey, agentId: input.event.agent_id });
      assert.equal(status.state, 'clear');
    });
  } finally { globalThis.fetch = originalFetch; t.mock.timers.reset(); rmSync(directory, { recursive: true, force: true }); }
});

test('Retry-After beyond the owner budget survives restart without early retry or namespace crossover', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-retry-after-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  const originalNow = Date.now;
  let clock = Date.parse('2026-09-09T12:00:00.000Z');
  Date.now = () => clock;
  let calls = 0;
  try {
    await withSpoolPath(path, async () => {
      globalThis.fetch = async () => { calls++; return new Response('{}', { status: 429, headers: { 'Retry-After': '3600' } }); };
      const input = lifecycleInput({ event_id: 'server-retry-minimum' });
      await recordLifecycleEvent(input);
      const [row] = JSON.parse(readFileSync(path, 'utf8'));
      assert.equal(row.next_attempt_at, '2026-09-09T13:00:00.000Z');
      delete require.cache[require.resolve('../dist/lifecycle-spool.js')];
      const restarted = require('../dist/lifecycle-spool.js');
      const scope = { apiKey: input.apiKey, baseUrl: input.baseUrl, agentId: input.event.agent_id };
      await restarted.nudgeLifecycleSpool(scope);
      await restarted.recordLifecycleEvent(input);
      assert.equal(calls, 1, 'restart and duplicate capture honor the persisted minimum');
      clock = Date.parse(row.next_attempt_at);
      globalThis.fetch = async () => { calls++; return new Response('{}', { status: 200 }); };
      await restarted.nudgeLifecycleSpool(scope);
      assert.equal(calls, 2);
      assert.equal(restarted.lifecycleSpoolStatus(scope).state, 'clear');
    });
  } finally { Date.now = originalNow; globalThis.fetch = originalFetch; rmSync(directory, { recursive: true, force: true }); }
});

test('concurrent delivery failures preserve the longest retry deadline and blocked guidance in either completion order', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-concurrent-retry-'));
  const originalFetch = globalThis.fetch;
  const originalNow = Date.now;
  const origin = Date.parse('2026-09-09T12:00:00.000Z');
  let clock = origin;
  Date.now = () => clock;
  try {
    for (const blocked of [false, true]) {
      for (const reverse of [false, true]) {
        clock = origin;
        const path = join(directory, `spool-${blocked}-${reverse}.json`);
        await withSpoolPath(path, async () => {
          const input = lifecycleInput({ event_id: `concurrent-${blocked}-${reverse}` });
          await recordLifecycleEvent({ ...input, deferDelivery: true });
          const responses = [];
          const bodies = [];
          globalThis.fetch = async (_url, init) => {
            bodies.push(init.body);
            return new Promise((resolve) => responses.push(resolve));
          };
          const scope = { apiKey: input.apiKey, agentId: input.event.agent_id,
            baseUrl: input.baseUrl, maxEvents: 1, budgetMs: 1000, requestTimeoutMs: 1000, retryDeadLetters: false };
          const drains = [drainLifecycleSpool(scope), drainLifecycleSpool(scope)];
          assert.equal(responses.length, 2);
          const strict = new Response('{}', { status: 429, headers: { 'Retry-After': blocked ? 'tomorrow' : '60' } });
          const ordinary = new Response('{}', { status: 503 });
          responses[0](reverse ? ordinary : strict);
          await drains[0];
          responses[1](reverse ? strict : ordinary);
          await drains[1];
          assert.equal(bodies[0], bodies[1], 'same event wire identity survives concurrent owners');
          const [row] = JSON.parse(readFileSync(path, 'utf8'));
          assert.equal(row.attempts, 2);
          assert.equal(row.delivery_state, 'queued');
          if (blocked) {
            assert.equal(row.retry_blocked, true);
            assert.equal(row.retry_reason, 'retry_after_invalid');
          } else {
            assert.equal(row.next_attempt_at, new Date(origin + 60_000).toISOString());
          }
          let laterCalls = 0;
          globalThis.fetch = async () => { laterCalls++; return new Response('{}', { status: 200 }); };
          delete require.cache[require.resolve('../dist/lifecycle-spool.js')];
          const restarted = require('../dist/lifecycle-spool.js');
          clock = origin + 59_000;
          await restarted.drainLifecycleSpool(scope);
          assert.equal(laterCalls, 0, 'restart preserves minimum and blocked guidance');
          clock = origin + 60_000;
          await restarted.drainLifecycleSpool(scope);
          assert.equal(laterCalls, blocked ? 0 : 1);
          assert.equal(restarted.lifecycleSpoolStatus(scope).state, blocked ? 'attention_required' : 'clear');
        });
      }
    }
  } finally { Date.now = originalNow; globalThis.fetch = originalFetch; rmSync(directory, { recursive: true, force: true }); }
});

test('an offline background owner stops at its finite budget and leaves the next retry on disk', async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-offline-budget-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  const origin = Date.parse('2026-09-09T12:00:00.000Z');
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: origin });
  let calls = 0;
  try {
    await withSpoolPath(path, async () => {
      await recordLifecycleEvent({ ...lifecycleInput({ event_id: 'offline-budget' }), deferDelivery: true });
      globalThis.fetch = async () => { calls++; throw new Error('offline'); };
      const scope = { apiKey: 'test-mcp-spool-key', agentId: 'agent-one', baseUrl: 'https://api.example.com' };
      const owner = nudgeLifecycleSpool(scope);
      await new Promise(setImmediate);
      for (const delay of [1_000, 2_000, 4_000, 8_000]) {
        t.mock.timers.tick(delay);
        await new Promise(setImmediate);
      }
      await owner;
      assert.equal(calls, 5);
      const status = lifecycleSpoolStatus(scope);
      assert.equal(status.failed, 0);
      assert.equal(status.pending, 1);
      assert.equal(status.retry.reasons.network_error, 1);
      assert.equal(status.retry.next_attempt_at, new Date(origin + 31_000).toISOString());
      t.mock.timers.tick(300_000);
      await new Promise(setImmediate);
      assert.equal(calls, 5, 'no timer or retry loop survives its owner budget');
      globalThis.fetch = async () => { calls++; return new Response('{}', { status: 200 }); };
      await nudgeLifecycleSpool(scope);
      assert.equal(lifecycleSpoolStatus(scope).state, 'clear');
      assert.equal(calls, 6);
    });
  } finally { globalThis.fetch = originalFetch; t.mock.timers.reset(); rmSync(directory, { recursive: true, force: true }); }
});

test('malformed and excessive Retry-After suspend queued delivery rather than shorten the server minimum', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-invalid-retry-after-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  let calls = 0;
  try {
    await withSpoolPath(path, async () => {
      for (const [index, header] of ['tomorrow', '-1', '999999999999999999999999999'].entries()) {
        globalThis.fetch = async () => { calls++; return new Response('{}', { status: 503, headers: { 'Retry-After': header } }); };
        await recordLifecycleEvent(lifecycleInput({ event_id: `invalid-guidance-${index}` }));
      }
      const scope = { apiKey: 'test-mcp-spool-key', agentId: 'agent-one', baseUrl: 'https://api.example.com' };
      await nudgeLifecycleSpool(scope);
      const status = await drainLifecycleSpool(scope);
      assert.equal(calls, 3);
      assert.equal(status.pending, 3);
      assert.equal(status.failed, 0);
      assert.equal(status.retry.blocked, 3);
      assert.equal(status.retry.reasons.retry_after_invalid, 3);
      assert.equal(status.retry.next_attempt_at, null);
      assert.match(status.exact_fix, /will not retry early/);
      assert.doesNotMatch(JSON.stringify(status), /999999999999999999999999999|tomorrow/);
    });
  } finally { globalThis.fetch = originalFetch; rmSync(directory, { recursive: true, force: true }); }
});

test('permanent authorization rejections never enter automatic recovery while schema rejections get one bounded attempt', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-permanent-classification-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  let calls = 0;
  try {
    await withSpoolPath(path, async () => {
      for (const status of [400, 401, 403, 422]) {
        globalThis.fetch = async () => { calls++; return new Response('{}', { status }); };
        const receipt = await recordLifecycleEvent(lifecycleInput({ event_id: `permanent-${status}` }));
        assert.equal(receipt.failed, true);
      }
      const scope = { apiKey: 'test-mcp-spool-key', agentId: 'agent-one', baseUrl: 'https://api.example.com' };
      await nudgeLifecycleSpool(scope);
      assert.equal(calls, 6, 'auth dead letters are never auto-retried; recoverable ones get one bounded attempt');
      const rows = JSON.parse(readFileSync(path, 'utf8'));
      const auth = rows.filter((row) => row.event_id === 'permanent-401' || row.event_id === 'permanent-403');
      assert.equal(auth.length, 2);
      assert.ok(auth.every((row) => row.delivery_state === 'dead_letter'
        && row.recovery_attempts === undefined && row.last_recovery_at === undefined));
      const recoverable = rows.filter((row) => row.event_id === 'permanent-400' || row.event_id === 'permanent-422');
      assert.ok(recoverable.every((row) => row.delivery_state === 'dead_letter' && row.recovery_attempts === 1));
      const status = lifecycleSpoolStatus(scope);
      assert.equal(status.failed, 2);
      assert.equal(status.recoverable, 2);
      assert.equal(status.pending, 0);
      assert.equal(status.state, 'attention_required');
      assert.equal(status.retry.reasons.authentication_rejected, 2);
      assert.equal(status.retry.reasons.schema_rejected, 2);
      assert.match(status.exact_fix, /credential and agent binding/);
    });
  } finally { globalThis.fetch = originalFetch; rmSync(directory, { recursive: true, force: true }); }
});

test('legacy array records preserve attempts and permanent dead letters while transient queued events gain retry metadata', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-retry-compatibility-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  try {
    await withSpoolPath(path, async () => {
      await recordLifecycleEvent({ ...lifecycleInput({ event_id: 'legacy-queued' }), deferDelivery: true });
      const [base] = JSON.parse(readFileSync(path, 'utf8'));
      writeFileSync(path, JSON.stringify([{ ...base, attempts: 3, last_status: 0 }, { ...base, event_id: 'legacy-dead', attempts: 3, last_status: 0, delivery_state: 'dead_letter' }]), { mode: 0o600 });
      globalThis.fetch = async () => { throw new Error('offline'); };
      await drainLifecycleSpool({ apiKey: 'test-mcp-spool-key', agentId: 'agent-one', baseUrl: 'https://api.example.com', retryDeadLetters: false });
      const rows = JSON.parse(readFileSync(path, 'utf8'));
      assert.equal(rows[0].attempts, 4);
      assert.equal(rows[0].delivery_state, 'queued');
      assert.equal(rows[0].retry_reason, 'network_error');
      assert.ok(rows[0].next_attempt_at);
      assert.equal(rows[1].delivery_state, 'dead_letter');
      assert.equal(rows[1].attempts, 3);
      assert.equal(rows[1].next_attempt_at, undefined);
    });
  } finally { globalThis.fetch = originalFetch; rmSync(directory, { recursive: true, force: true }); }
});


test('near-limit legacy payload survives retry metadata without quarantine or false acceptance', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-byte-envelope-'));
  const originalFetch = globalThis.fetch;
  const originalNow = Date.now;
  let clock = originalNow();
  Date.now = () => clock;
  const id = 'a'.repeat(128);
  const base = { event_id: id, event_type: 'outcome_committed', harness: id, agent_id: id,
    action: '漢'.repeat(180), target: '語'.repeat(180),
    surfaces: Array.from({ length: 16 }, (_, index) => `${String(index).padStart(2, '0')}${'a'.repeat(78)}`),
    workflow_id: id, session_id: id, decision_id: id, correlation_id: id, source: 'client_self_reported',
    intervention_disposition: 'overridden', action_changed: true, risk_level: 'medium', outcome_state: 'closed', success: true };
  try {
    for (const [index, action] of [base.action, '\ud800'.repeat(120) + '漢'.repeat(60)].entries()) {
      const path = join(directory, `spool-${index}.json`);
      await withSpoolPath(path, async () => {
        const input = lifecycleInput({ ...base, action });
        await recordLifecycleEvent({ ...input, deferDelivery: true });
        const [legacy] = JSON.parse(readFileSync(path, 'utf8'));
        assert.equal(Buffer.byteLength(JSON.stringify(legacy)), index === 0 ? 3722 : 4082);
        assert.equal(legacy.next_attempt_at, undefined);
        const bodies = [];
        globalThis.fetch = async (_url, init) => { bodies.push(init.body); return new Response('{}', { status: 503 }); };
        const queued = await recordLifecycleEvent(input);
        assert.equal(queued.accepted, false);
        assert.equal(queued.queued, true);
        assert.equal(queued.recovered_corruption, false);
        const [retried] = JSON.parse(readFileSync(path, 'utf8'));
        if (index === 1) assert.equal(Buffer.byteLength(JSON.stringify(retried)), 4222);
        assert.equal(retried.event_id, legacy.event_id);
        assert.equal(retried.action, legacy.action);
        assert.equal(readdirSync(directory).some(name => name.includes('.corrupt-')), false);
        clock = Date.parse(retried.next_attempt_at);
        globalThis.fetch = async (_url, init) => { bodies.push(init.body); return new Response('{}', { status: 200 }); };
        const closed = await recordLifecycleEvent(input);
        assert.equal(closed.accepted, true);
        assert.equal(bodies[0], bodies[1], 'retry envelope cannot change immutable wire bytes');
        assert.deepEqual(JSON.parse(readFileSync(path, 'utf8')), []);
      });
    }
  } finally { Date.now = originalNow; globalThis.fetch = originalFetch; rmSync(directory, { recursive: true, force: true }); }
});

test('local metadata has a bounded 350-byte maximum and cannot expand the immutable payload limit', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-metadata-maximum-'));
  const path = join(directory, 'spool.json');
  const metadata = { attempts: 1000000, delivery_state: 'dead_letter', last_status: 599,
    last_attempt_at: '+275760-09-13T00:00:00.000Z', next_attempt_at: '+275760-09-13T00:00:00.000Z',
    retry_reason: 'authentication_rejected', retry_blocked: true,
    recovery_attempts: 1000000, last_recovery_at: '+275760-09-13T00:00:00.000Z',
    recovery_exhausted: true, server_owned: true };
  assert.equal(Buffer.byteLength(JSON.stringify(metadata)), 350);
  assert.ok(Buffer.byteLength(JSON.stringify(metadata)) <= 384);
  try {
    await withSpoolPath(path, async () => {
      await recordLifecycleEvent({ ...lifecycleInput({ event_id: 'metadata-maximum' }), deferDelivery: true });
      const [base] = JSON.parse(readFileSync(path, 'utf8'));
      writeFileSync(path, JSON.stringify([{ ...base, ...metadata }]), { mode: 0o600 });
      const retainedStatus = lifecycleSpoolStatus({ apiKey: 'test-mcp-spool-key', agentId: 'agent-one' });
      assert.equal(retainedStatus.failed, 0);
      assert.equal(retainedStatus.server_owned, 1);
      assert.equal(existsSync(path), true);
      const retained = readFileSync(path, 'utf8');
      const id = 'a'.repeat(128);
      await assert.rejects(recordLifecycleEvent({ ...lifecycleInput({ event_id: id, harness: id, agent_id: id,
        action: '\ud800'.repeat(180), target: '\ud800'.repeat(180), workflow_id: id, session_id: id, decision_id: id, correlation_id: id,
        surfaces: Array.from({ length: 16 }, (_, i) => `${String(i).padStart(2, '0')}${'a'.repeat(78)}`) }), deferDelivery: true }), /byte limit/);
      await assert.rejects(recordLifecycleEvent({ ...lifecycleInput({ event_type: 'invalid-type' }), deferDelivery: true }), /event_type/);
      assert.equal(readFileSync(path, 'utf8'), retained, 'invalid admission preserves already queued evidence');
      writeFileSync(path, JSON.stringify([{ ...base, last_status: 9999 }]), { mode: 0o600 });
      const invalid = lifecycleSpoolStatus({ apiKey: 'test-mcp-spool-key', agentId: 'agent-one' });
      assert.equal(invalid.recovered_corruption, true);
      assert.equal(existsSync(path), false, 'invalid metadata keeps the established quarantine behavior');
    });
  } finally { rmSync(directory, { recursive: true, force: true }); }
});


test('aggregate retry reservation blocks near-full legacy delivery before fetch and preserves admission headroom', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-total-retry-capacity-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  const metadataFields = ['attempts', 'delivery_state', 'last_status', 'last_attempt_at', 'next_attempt_at', 'retry_reason', 'retry_blocked',
    'recovery_attempts', 'last_recovery_at', 'recovery_exhausted', 'server_owned'];
  const payload = event => Object.fromEntries(Object.entries(event).filter(([key]) => !metadataFields.includes(key)));
  const reserved = events => Buffer.byteLength(JSON.stringify(events.map(payload))) + events.length * 383;
  const max = 2 * 1024 * 1024;
  const id = 'a'.repeat(128);
  const event = { event_id: id, event_type: 'outcome_committed', harness: id, agent_id: id, action: '漢'.repeat(180), target: '語'.repeat(180),
    surfaces: Array.from({ length: 16 }, (_, i) => `${String(i).padStart(2, '0')}${'a'.repeat(78)}`),
    workflow_id: id, session_id: id, decision_id: id, correlation_id: id, source: 'client_self_reported',
    intervention_disposition: 'overridden', action_changed: true, risk_level: 'medium', outcome_state: 'closed', success: true };
  let calls = 0;
  try {
    await withSpoolPath(path, async () => {
      const input = lifecycleInput(event);
      await recordLifecycleEvent({ ...input, deferDelivery: true });
      const [base] = JSON.parse(readFileSync(path, 'utf8'));
      const recordBytes = Buffer.byteLength(JSON.stringify(base));
      const count = Math.floor((max - 1) / (recordBytes + 1));
      const rows = Array.from({ length: count }, (_, i) => ({ ...base, event_id: `${String(i).padStart(6, '0')}${'a'.repeat(122)}` }));
      const legacy = JSON.stringify(rows);
      assert.ok(Buffer.byteLength(legacy) <= max && Buffer.byteLength(legacy) > max - 4096);
      assert.ok(reserved(rows) > max);
      writeFileSync(path, legacy, { mode: 0o600 });
      globalThis.fetch = async () => { calls++; return new Response('{}', { status: 429, headers: { 'Retry-After': '3600' } }); };
      const scope = { apiKey: input.apiKey, baseUrl: input.baseUrl, agentId: event.agent_id };
      const status = await drainLifecycleSpool(scope);
      assert.equal(status.state, 'attention_required');
      assert.equal(status.retry.capacity_blocked, rows.length);
      assert.match(status.exact_fix, /No delivery will start/);
      await nudgeLifecycleSpool(scope);
      const duplicate = await recordLifecycleEvent({ ...input, event: { ...event, event_id: rows[0].event_id } });
      assert.equal(duplicate.queued, true);
      assert.equal(calls, 0);
      assert.equal(readFileSync(path, 'utf8'), legacy, 'legacy queue bytes survive capacity block');
      const deadLegacy = JSON.stringify(rows.map(row => ({ ...row, delivery_state: 'dead_letter' })));
      writeFileSync(path, deadLegacy, { mode: 0o600 });
      const deadStatus = await drainLifecycleSpool(scope);
      assert.equal(deadStatus.retry.capacity_blocked, rows.length);
      assert.match(deadStatus.exact_fix, /No delivery will start/);
      assert.equal(calls, 0);
      assert.equal(readFileSync(path, 'utf8'), deadLegacy);

      // Fixture reset only: model an admission with just enough reserved space.
      while (reserved([...rows, base]) > max) rows.pop();
      writeFileSync(path, JSON.stringify(rows), { mode: 0o600 });
      const accepted = await recordLifecycleEvent({ ...input, deferDelivery: true });
      assert.equal(accepted.queued, true);
      const admitted = JSON.parse(readFileSync(path, 'utf8'));
      assert.ok(reserved(admitted) <= max);
      const beforeRejected = readFileSync(path, 'utf8');
      await assert.rejects(recordLifecycleEvent({ ...input, event: { ...event, event_id: 'next'.padEnd(128, 'a') }, deferDelivery: true }), /capacity insufficient/);
      assert.equal(readFileSync(path, 'utf8'), beforeRejected);
      const attempted = await recordLifecycleEvent(input);
      assert.equal(attempted.queued, true);
      assert.equal(calls, 1);
      const withRetry = JSON.parse(readFileSync(path, 'utf8'));
      assert.equal(withRetry.find(row => row.event_id === id).retry_reason, 'rate_limited');
      assert.ok(Buffer.byteLength(JSON.stringify(withRetry)) <= max);
      assert.equal(withRetry.length, admitted.length);
      assert.equal(readdirSync(directory).some(name => name.includes('.corrupt-')), false);
    });
  } finally { globalThis.fetch = originalFetch; rmSync(directory, { recursive: true, force: true }); }
});

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
  assert.match(hook, /clientReportedHookLifecycleIdentity\(identity\)/);
  assert.match(hook, /target: classified\.target/);
  assert.match(hook, /surfaces: classified\.surfaces/);
  assert.match(context, /clientReportedHookLifecycleIdentity\(identity\)/);
});

test('forged lifecycle capability payload loses every certified-looking field', async () => {
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
        adapter_version: 'forged-adapter',
        capability_level: 'native_hooks',
        config_fingerprint: 'forged-fingerprint',
        expected_hooks: ['prompt', 'pre_action', 'action_result', 'session_end'],
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
      assert.equal('observed_hook' in event, false);
      assert.equal(event.source, 'client_self_reported');
    });
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('wire delivery omits an absent agent identity for authoritative server derivation', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-server-agent-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  let delivered;
  globalThis.fetch = async (_url, init) => {
    delivered = JSON.parse(init.body);
    return new Response(JSON.stringify({ data: { accepted: true, agent_id: 'server-bound-agent' } }), { status: 200 });
  };
  try {
    await withSpoolPath(path, () => recordLifecycleEvent(lifecycleInput({ agent_id: undefined })));
    assert.equal(Object.hasOwn(delivered, 'agent_id'), false);
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('native hook activity stays client-self-reported and cannot emit certification evidence', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-native-capability-'));
  const path = join(directory, 'spool.json');
  const settingsDir = join(directory, '.claude');
  mkdirSync(settingsDir, { recursive: true });
  writeFileSync(join(settingsDir, 'settings.json'), JSON.stringify({
    hooks: {
      UserPromptSubmit: [{ hooks: [{ type: 'command', command: 'npx -y @getmarrow/mcp@3.9.74 context-hook' }] }],
      PreToolUse: [{ matcher: 'Bash|Edit|Write|MultiEdit|mcp__(?!marrow__marrow_).*', hooks: [{ type: 'command', command: 'npx -y @getmarrow/mcp@3.9.74 pre-action-hook' }] }],
      PostToolUse: [{ matcher: 'Bash|Edit|Write|MultiEdit|mcp__(?!marrow__marrow_).*', hooks: [{ type: 'command', command: 'npx -y @getmarrow/mcp@3.9.74 hook' }] }],
      PostToolUseFailure: [{ matcher: 'Bash|Edit|Write|MultiEdit|mcp__(?!marrow__marrow_).*', hooks: [{ type: 'command', command: 'npx -y @getmarrow/mcp@3.9.74 hook' }] }],
      Stop: [{ hooks: [{ type: 'command', command: 'npx -y @getmarrow/mcp@3.9.74 session-hook' }] }],
    },
  }));
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response('{}', { status: 503 });
  try {
    await withSpoolPath(path, async () => {
      await recordLifecycleEvent(lifecycleInput({
        correlation_id: 'correlation-native',
        ...clientReportedHookLifecycleIdentity(resolveNativeHookIdentity('claude-hook', {
          cwd: directory,
          home: directory,
          env: { MARROW_API_KEY: 'fixture-hook-key' },
        })),
      }));
      const [event] = JSON.parse(readFileSync(path, 'utf8'));
      assert.equal(event.source, 'client_self_reported');
      assert.equal(event.harness, 'claude-code');
      assert.equal(event.capability_level, undefined);
      assert.equal(event.adapter_version, undefined);
      assert.equal(event.config_fingerprint, undefined);
      assert.equal(event.expected_hooks, undefined);
      assert.equal(event.observed_hook, undefined);

      const before = localHookConfigurationFingerprint(directory);
      const changed = JSON.parse(readFileSync(join(settingsDir, 'settings.json'), 'utf8'));
      changed.hooks.PreToolUse[0].hooks[0].timeout = 15;
      writeFileSync(join(settingsDir, 'settings.json'), JSON.stringify(changed));
      assert.notEqual(localHookConfigurationFingerprint(directory), before);
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

  const codexReview = preActionHookOutput({
    runtime: { risk_gate: { allow: false, decision: 'review_required', reasons: [] }, exact_next_action: 'ask owner' },
    permit: { verified: true, permit_id: 'permit-review' },
    protectedRisk: true,
  }, 'codex');
  assert.equal(codexReview.hookSpecificOutput.permissionDecision, 'deny');
  assert.equal(codexReview.hookSpecificOutput.permissionDecisionReason, 'ask owner');

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
  const originalNow = Date.now;
  let clock = originalNow();
  Date.now = () => clock;
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
      clock += 1_000;
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
    Date.now = originalNow;
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

test('deferred receipt survives restart and lost ACK with stable ID and one nudge owner', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-deferred-replay-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  const originalNow = Date.now;
  let clock = originalNow();
  Date.now = () => clock;
  const effects = new Set();
  const attempts = [];
  try {
    await withSpoolPath(path, async () => {
      const input = { ...lifecycleInput({ event_id: 'stable-deferred-replay' }), deferDelivery: true };
      const queued = await recordLifecycleEvent(input);
      assert.equal(queued.accepted, false);
      assert.equal(queued.queued, true);
      globalThis.fetch = async (_url, init) => {
        const event = JSON.parse(init.body);
        attempts.push(event.event_id);
        effects.add(event.event_id); // Model the server's stable-event-ID dedupe.
        clock += 20_001; // Exhaust this finite owner after its first attempt.
        throw new Error('ACK lost after the server recorded the event');
      };
      const nudgeInput = { apiKey: input.apiKey, baseUrl: input.baseUrl, agentId: input.event.agent_id };
      await Promise.all([nudgeLifecycleSpool(nudgeInput), nudgeLifecycleSpool(nudgeInput)]);
      assert.equal(attempts.length, 1, 'overlapping nudges have one delivery owner');
      assert.equal(JSON.parse(readFileSync(path, 'utf8'))[0].event_id, queued.event_id);

      // Load a fresh module, as a restarted client does; only disk state survives.
      delete require.cache[require.resolve('../dist/lifecycle-spool.js')];
      const restarted = require('../dist/lifecycle-spool.js');
      const replay = await restarted.recordLifecycleEvent(input);
      assert.equal(replay.event_id, queued.event_id);
      assert.equal(JSON.parse(readFileSync(path, 'utf8')).length, 1);
      globalThis.fetch = async (_url, init) => {
        const event = JSON.parse(init.body);
        attempts.push(event.event_id);
        effects.add(event.event_id);
        return Response.json({ data: { accepted: true } });
      };
      clock = Date.parse(JSON.parse(readFileSync(path, 'utf8'))[0].next_attempt_at);
      await restarted.nudgeLifecycleSpool(nudgeInput);
      assert.deepEqual(attempts, [queued.event_id, queued.event_id]);
      assert.equal(effects.size, 1);
      assert.equal(restarted.lifecycleSpoolStatus(nudgeInput).pending, 0);
    });
  } finally { Date.now = originalNow; globalThis.fetch = originalFetch; rmSync(directory, { recursive: true, force: true }); }
});

test('deferred capture reports full and unsafe spool failures without dropping prior receipts', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-deferred-full-'));
  const path = join(directory, 'spool.json');
  try {
    await withSpoolPath(path, async () => {
      await recordLifecycleEvent({ ...lifecycleInput({ event_id: 'capacity-base' }), deferDelivery: true });
      const [base] = JSON.parse(readFileSync(path, 'utf8'));
      const full = Array.from({ length: 1000 }, (_, index) => ({ ...base, event_id: `full-${index}` }));
      writeFileSync(path, JSON.stringify(full), { mode: 0o600 });
      await assert.rejects(recordLifecycleEvent({ ...lifecycleInput({ event_id: 'must-not-claim-accepted' }), deferDelivery: true }), /capacity exceeded/);
      assert.deepEqual(JSON.parse(readFileSync(path, 'utf8')), full);
      chmodSync(path, 0o666);
      await assert.rejects(recordLifecycleEvent({ ...lifecycleInput({ event_id: 'unsafe-must-fail' }), deferDelivery: true }), /permission|private|unsafe|owner/i);
    });
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('permanent rejection dead-letters while repeated transient failures remain scheduled', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-reject-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  const originalNow = Date.now;
  let clock = originalNow();
  Date.now = () => clock;
  try {
    await withSpoolPath(path, async () => {
      globalThis.fetch = async () => new Response('{}', { status: 400 });
      const rejected = await recordLifecycleEvent(lifecycleInput({ event_id: 'terminal-reject' }));
      assert.equal(rejected.accepted, false);
      assert.equal(rejected.failed, true);
      assert.match(readFileSync(path, 'utf8'), /"delivery_state":"dead_letter"/);

      globalThis.fetch = async () => new Response('{}', { status: 503 });
      let exhausted;
      for (let attempt = 0; attempt < 4; attempt += 1) {
        exhausted = await recordLifecycleEvent(lifecycleInput({ event_id: 'retry-exhausted' }));
        const row = JSON.parse(readFileSync(path, 'utf8')).find(event => event.event_id === 'retry-exhausted');
        clock = Date.parse(row.next_attempt_at);
      }
      assert.equal(exhausted.accepted, false);
      assert.equal(exhausted.failed, false);
      const row = JSON.parse(readFileSync(path, 'utf8')).find((event) => event.event_id === 'retry-exhausted');
      assert.equal(row.delivery_state, 'queued');
      assert.equal(row.attempts, 4);
      assert.equal(row.last_status, 503);
      const finalStatus = lifecycleSpoolStatus({ apiKey: 'test-mcp-spool-key', agentId: 'agent-one' });
      assert.equal(finalStatus.failed, 0);
      assert.equal(finalStatus.recoverable, 1);
      assert.match(finalStatus.exact_fix, /Automatic recovery/);
      assert.match(finalStatus.exact_fix, /No local action is required/);
    });
  } finally {
    Date.now = originalNow;
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
      const beforeDrain = lifecycleSpoolStatus({ apiKey: 'test-mcp-spool-key', agentId: 'agent-one' });
      assert.equal(beforeDrain.failed, 0, 'a schema rejection is recoverable, not operator attention');
      assert.equal(beforeDrain.recoverable, 1);

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

test('explicit drain preserves transient backlog instead of inventing exhausted dead letters', async () => {
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
      assert.equal(status.state, 'pending');
      assert.equal(status.pending, 2);
      assert.equal(status.failed, 0);
    });
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('nudge automatically recovers a transport-class dead letter once the server is healthy', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-auto-recovery-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  let calls = 0;
  const bodies = [];
  try {
    await withSpoolPath(path, async () => {
      const input = { ...lifecycleInput({ event_id: 'auto-recover-transport' }), deferDelivery: true };
      await recordLifecycleEvent(input);
      const [base] = JSON.parse(readFileSync(path, 'utf8'));
      writeFileSync(path, JSON.stringify([{ ...base, delivery_state: 'dead_letter', last_status: 503, retry_reason: 'transient_http' }]), { mode: 0o600 });
      const before = lifecycleSpoolStatus({ apiKey: input.apiKey, agentId: input.event.agent_id });
      assert.equal(before.failed, 0);
      assert.equal(before.recoverable, 1);
      assert.notEqual(before.state, 'attention_required');
      globalThis.fetch = async (_url, init) => { calls += 1; bodies.push(init.body); return new Response('{}', { status: 200 }); };
      await nudgeLifecycleSpool({ apiKey: input.apiKey, baseUrl: input.baseUrl, agentId: input.event.agent_id });
      assert.equal(calls, 1);
      const wire = JSON.parse(bodies[0]);
      assert.equal(wire.recovery_attempts, undefined, 'local recovery metadata never reaches the wire');
      assert.equal(wire.server_owned, undefined);
      assert.deepEqual(JSON.parse(readFileSync(path, 'utf8')), [], 'recovered event is removed after delivery');
      assert.equal(lifecycleSpoolStatus({ apiKey: input.apiKey, agentId: input.event.agent_id }).state, 'clear');
    });
  } finally { globalThis.fetch = originalFetch; rmSync(directory, { recursive: true, force: true }); }
});

test('a 409 during recovery marks the dead letter server_owned without operator attention', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-recovery-conflict-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  let calls = 0;
  try {
    await withSpoolPath(path, async () => {
      const input = { ...lifecycleInput({ event_id: 'recovery-conflict' }), deferDelivery: true };
      await recordLifecycleEvent(input);
      const [base] = JSON.parse(readFileSync(path, 'utf8'));
      writeFileSync(path, JSON.stringify([{ ...base, delivery_state: 'dead_letter', last_status: 400, retry_reason: 'schema_rejected' }]), { mode: 0o600 });
      globalThis.fetch = async () => { calls += 1; return new Response('{}', { status: 409 }); };
      const scope = { apiKey: input.apiKey, baseUrl: input.baseUrl, agentId: input.event.agent_id };
      await nudgeLifecycleSpool(scope);
      assert.equal(calls, 1);
      const [row] = JSON.parse(readFileSync(path, 'utf8'));
      assert.equal(row.delivery_state, 'dead_letter');
      assert.equal(row.server_owned, true);
      assert.equal(row.recovery_attempts, 1);
      const status = lifecycleSpoolStatus(scope);
      assert.equal(status.failed, 0);
      assert.equal(status.server_owned, 1);
      assert.equal(status.recoverable, 0);
      assert.notEqual(status.state, 'attention_required');
      await nudgeLifecycleSpool(scope);
      assert.equal(calls, 1, 'server-owned evidence is never replayed');
    });
  } finally { globalThis.fetch = originalFetch; rmSync(directory, { recursive: true, force: true }); }
});

test('authentication dead letters are never auto-retried and keep drain-spool guidance', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-auth-manual-only-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  let calls = 0;
  try {
    await withSpoolPath(path, async () => {
      for (const status of [401, 403]) {
        globalThis.fetch = async () => { calls += 1; return new Response('{}', { status }); };
        const receipt = await recordLifecycleEvent(lifecycleInput({ event_id: `auth-${status}` }));
        assert.equal(receipt.failed, true);
      }
      assert.equal(calls, 2);
      globalThis.fetch = async () => { calls += 1; return new Response('{}', { status: 200 }); };
      const scope = { apiKey: 'test-mcp-spool-key', agentId: 'agent-one', baseUrl: 'https://api.example.com' };
      await nudgeLifecycleSpool(scope);
      assert.equal(calls, 2, 'the auth class is manual-only and never auto-retried');
      const rows = JSON.parse(readFileSync(path, 'utf8'));
      assert.ok(rows.every((row) => row.delivery_state === 'dead_letter'
        && row.recovery_attempts === undefined && row.last_recovery_at === undefined));
      const status = lifecycleSpoolStatus(scope);
      assert.equal(status.failed, 2);
      assert.equal(status.state, 'attention_required');
      assert.match(status.exact_fix, /credential and agent binding/);
      assert.match(status.exact_fix, /drain-spool/);
    });
  } finally { globalThis.fetch = originalFetch; rmSync(directory, { recursive: true, force: true }); }
});

test('recovery cooldown prevents re-attempts within fifteen minutes', async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-recovery-cooldown-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: Date.parse('2026-09-16T00:00:00.000Z') });
  let calls = 0;
  try {
    await withSpoolPath(path, async () => {
      const input = { ...lifecycleInput({ event_id: 'recovery-cooldown' }), deferDelivery: true };
      await recordLifecycleEvent(input);
      const [base] = JSON.parse(readFileSync(path, 'utf8'));
      writeFileSync(path, JSON.stringify([{ ...base, delivery_state: 'dead_letter', last_status: 503, retry_reason: 'transient_http' }]), { mode: 0o600 });
      globalThis.fetch = async () => { calls += 1; return new Response('{}', { status: 400 }); };
      const scope = { apiKey: input.apiKey, baseUrl: input.baseUrl, agentId: input.event.agent_id };
      await nudgeLifecycleSpool(scope);
      assert.equal(calls, 1);
      assert.equal(JSON.parse(readFileSync(path, 'utf8'))[0].recovery_attempts, 1);
      await nudgeLifecycleSpool(scope);
      assert.equal(calls, 1, 'a second nudge inside the cooldown does not re-attempt');
      t.mock.timers.tick(15 * 60_000 - 1);
      await nudgeLifecycleSpool(scope);
      assert.equal(calls, 1, 'one millisecond early is still cooling down');
      t.mock.timers.tick(1);
      await nudgeLifecycleSpool(scope);
      assert.equal(calls, 2, 'recovery resumes once the cooldown elapses');
      assert.equal(JSON.parse(readFileSync(path, 'utf8'))[0].recovery_attempts, 2);
    });
  } finally { globalThis.fetch = originalFetch; t.mock.timers.reset(); rmSync(directory, { recursive: true, force: true }); }
});

test('recovery exhausts after three failed attempts and requires no local action', async (t) => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-recovery-exhausted-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: Date.parse('2026-09-16T00:00:00.000Z') });
  let calls = 0;
  try {
    await withSpoolPath(path, async () => {
      const input = { ...lifecycleInput({ event_id: 'recovery-exhaustion' }), deferDelivery: true };
      await recordLifecycleEvent(input);
      const [base] = JSON.parse(readFileSync(path, 'utf8'));
      writeFileSync(path, JSON.stringify([{ ...base, delivery_state: 'dead_letter', last_status: 400, retry_reason: 'schema_rejected' }]), { mode: 0o600 });
      globalThis.fetch = async () => { calls += 1; return new Response('{}', { status: 400 }); };
      const scope = { apiKey: input.apiKey, baseUrl: input.baseUrl, agentId: input.event.agent_id };
      for (let attempt = 1; attempt <= 3; attempt += 1) {
        await nudgeLifecycleSpool(scope);
        assert.equal(calls, attempt);
        t.mock.timers.tick(15 * 60_000);
      }
      const [row] = JSON.parse(readFileSync(path, 'utf8'));
      assert.equal(row.delivery_state, 'dead_letter');
      assert.equal(row.recovery_attempts, 3);
      assert.equal(row.recovery_exhausted, true);
      const status = lifecycleSpoolStatus(scope);
      assert.equal(status.failed, 0);
      assert.equal(status.recoverable, 0);
      assert.equal(status.recovery_exhausted, 1);
      assert.notEqual(status.state, 'attention_required');
      assert.match(status.exact_fix, /no local action is required/i);
      await nudgeLifecycleSpool(scope);
      assert.equal(calls, 3, 'exhausted dead letters are not re-attempted');
    });
  } finally { globalThis.fetch = originalFetch; t.mock.timers.reset(); rmSync(directory, { recursive: true, force: true }); }
});

test('a legacy dead letter without last_status is recovery-eligible', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-legacy-corpse-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  let calls = 0;
  try {
    await withSpoolPath(path, async () => {
      const input = { ...lifecycleInput({ event_id: 'legacy-corpse' }), deferDelivery: true };
      await recordLifecycleEvent(input);
      const [base] = JSON.parse(readFileSync(path, 'utf8'));
      writeFileSync(path, JSON.stringify([{ ...base, delivery_state: 'dead_letter' }]), { mode: 0o600 });
      globalThis.fetch = async () => { calls += 1; return new Response('{}', { status: 200 }); };
      await nudgeLifecycleSpool({ apiKey: input.apiKey, baseUrl: input.baseUrl, agentId: input.event.agent_id });
      assert.equal(calls, 1);
      assert.deepEqual(JSON.parse(readFileSync(path, 'utf8')), []);
    });
  } finally { globalThis.fetch = originalFetch; rmSync(directory, { recursive: true, force: true }); }
});

test('a 409 on first delivery marks the event server_owned immediately', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-first-conflict-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  let calls = 0;
  try {
    await withSpoolPath(path, async () => {
      globalThis.fetch = async () => { calls += 1; return new Response('{}', { status: 409 }); };
      const receipt = await recordLifecycleEvent(lifecycleInput({ event_id: 'first-delivery-conflict' }));
      assert.equal(receipt.accepted, false);
      assert.equal(receipt.failed, true);
      const [row] = JSON.parse(readFileSync(path, 'utf8'));
      assert.equal(row.delivery_state, 'dead_letter');
      assert.equal(row.server_owned, true);
      const scope = { apiKey: 'test-mcp-spool-key', agentId: 'agent-one', baseUrl: 'https://api.example.com' };
      const status = lifecycleSpoolStatus(scope);
      assert.equal(status.failed, 0);
      assert.equal(status.server_owned, 1);
      assert.notEqual(status.state, 'attention_required');
      globalThis.fetch = async () => { calls += 1; return new Response('{}', { status: 200 }); };
      await nudgeLifecycleSpool(scope);
      assert.equal(calls, 1, 'server-owned evidence is never replayed by the nudge');
    });
  } finally { globalThis.fetch = originalFetch; rmSync(directory, { recursive: true, force: true }); }
});

test('manual drain retries auth and exhausted dead letters but skips server_owned', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-manual-drain-authority-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  const calls = [];
  try {
    await withSpoolPath(path, async () => {
      const ids = ['drain-auth', 'drain-owned', 'drain-exhausted'];
      for (const eventId of ids) {
        await recordLifecycleEvent({ ...lifecycleInput({ event_id: eventId }), deferDelivery: true });
      }
      const rows = JSON.parse(readFileSync(path, 'utf8'));
      writeFileSync(path, JSON.stringify(rows.map((row) => {
        if (row.event_id === 'drain-auth') return { ...row, delivery_state: 'dead_letter', last_status: 401, retry_reason: 'authentication_rejected' };
        if (row.event_id === 'drain-owned') return { ...row, delivery_state: 'dead_letter', last_status: 409, retry_reason: 'permanent_http', server_owned: true };
        return { ...row, delivery_state: 'dead_letter', last_status: 400, retry_reason: 'schema_rejected', recovery_attempts: 3, recovery_exhausted: true };
      })), { mode: 0o600 });
      globalThis.fetch = async (_url, init) => {
        const eventId = JSON.parse(init.body).event_id;
        calls.push(eventId);
        return new Response('{}', { status: eventId === 'drain-exhausted' ? 503 : 200 });
      };
      const scope = { apiKey: 'test-mcp-spool-key', agentId: 'agent-one', baseUrl: 'https://api.example.com' };
      const drained = await drainLifecycleSpool(scope);
      assert.deepEqual(calls.sort(), ['drain-auth', 'drain-exhausted'], 'manual drain retries auth and exhausted classes only');
      const remaining = JSON.parse(readFileSync(path, 'utf8'));
      assert.equal(remaining.some((row) => row.event_id === 'drain-auth'), false, 'delivered auth event is removed');
      const exhausted = remaining.find((row) => row.event_id === 'drain-exhausted');
      assert.equal(exhausted.delivery_state, 'queued');
      assert.equal(exhausted.recovery_exhausted, undefined, 'manual requeue clears exhaustion for a fresh budget');
      assert.equal(exhausted.recovery_attempts, undefined);
      const owned = remaining.find((row) => row.event_id === 'drain-owned');
      assert.equal(owned.delivery_state, 'dead_letter');
      assert.equal(owned.server_owned, true);
      assert.equal(owned.last_attempt_at, undefined, 'server-owned rows are never re-attempted');
      assert.equal(drained.failed, 0);
      assert.equal(drained.server_owned, 1);
      assert.equal(drained.pending, 1);
    });
  } finally { globalThis.fetch = originalFetch; rmSync(directory, { recursive: true, force: true }); }
});

test('status partitions a mixed spool into failed, recoverable, server_owned, and recovery_exhausted', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-mixed-counts-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  try {
    await withSpoolPath(path, async () => {
      const ids = ['mix-queued', 'mix-auth', 'mix-owned', 'mix-recoverable-one', 'mix-recoverable-two', 'mix-exhausted'];
      for (const eventId of ids) {
        await recordLifecycleEvent({ ...lifecycleInput({ event_id: eventId }), deferDelivery: true });
      }
      const rows = JSON.parse(readFileSync(path, 'utf8'));
      writeFileSync(path, JSON.stringify(rows.map((row) => {
        if (row.event_id === 'mix-auth') return { ...row, delivery_state: 'dead_letter', last_status: 403, retry_reason: 'authentication_rejected' };
        if (row.event_id === 'mix-owned') return { ...row, delivery_state: 'dead_letter', last_status: 409, retry_reason: 'permanent_http' };
        if (row.event_id === 'mix-recoverable-one') return { ...row, delivery_state: 'dead_letter', last_status: 400, retry_reason: 'schema_rejected' };
        if (row.event_id === 'mix-recoverable-two') return { ...row, delivery_state: 'dead_letter', last_status: 503, retry_reason: 'transient_http' };
        if (row.event_id === 'mix-exhausted') return { ...row, delivery_state: 'dead_letter', last_status: 400, retry_reason: 'schema_rejected', recovery_attempts: 3, recovery_exhausted: true };
        return row;
      })), { mode: 0o600 });
      const status = lifecycleSpoolStatus({ apiKey: 'test-mcp-spool-key', agentId: 'agent-one' });
      assert.equal(status.pending, 1);
      assert.equal(status.failed, 1);
      assert.equal(status.recoverable, 2);
      assert.equal(status.server_owned, 1, 'a legacy 409 corpse classifies as server-owned');
      assert.equal(status.recovery_exhausted, 1);
      assert.equal(status.state, 'attention_required', 'only the auth class forces operator attention');
      assert.match(status.exact_fix, /credential and agent binding/);
    });
  } finally { globalThis.fetch = originalFetch; rmSync(directory, { recursive: true, force: true }); }
});

test('a recoverable-only spool satisfies the cli nudge gate and self-heals', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-gate-recoverable-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  let calls = 0;
  try {
    await withSpoolPath(path, async () => {
      const input = { ...lifecycleInput({ event_id: 'gate-recoverable' }), deferDelivery: true };
      await recordLifecycleEvent(input);
      const [base] = JSON.parse(readFileSync(path, 'utf8'));
      writeFileSync(path, JSON.stringify([{ ...base, delivery_state: 'dead_letter', last_status: 400, retry_reason: 'schema_rejected' }]), { mode: 0o600 });
      const scope = { apiKey: input.apiKey, baseUrl: input.baseUrl, agentId: input.event.agent_id };
      const status = lifecycleSpoolStatus(scope);
      assert.equal(status.pending, 0);
      assert.equal(status.recoverable, 1);
      // The reportLifecycleSpool gate in src/cli.ts: pending > 0 || recoverable > 0.
      assert.equal(status.pending > 0 || status.recoverable > 0, true, 'dead letters alone trigger the nudge gate');
      globalThis.fetch = async () => { calls += 1; return new Response('{}', { status: 200 }); };
      if (status.pending > 0 || status.recoverable > 0) await nudgeLifecycleSpool(scope);
      assert.equal(calls, 1);
      assert.equal(lifecycleSpoolStatus(scope).state, 'clear');
    });
  } finally { globalThis.fetch = originalFetch; rmSync(directory, { recursive: true, force: true }); }
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

test('quarantine moves leftover namespace files without replaying them under the current key', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-spool-quarantine-'));
  const home = join(directory, 'home');
  const originalHome = process.env.HOME;
  const originalPath = process.env.MARROW_EVENT_SPOOL_PATH;
  const originalFetch = globalThis.fetch;
  mkdirSync(home, { recursive: true, mode: 0o700 });
  process.env.HOME = home;
  delete process.env.MARROW_EVENT_SPOOL_PATH;
  try {
    await recordLifecycleEvent({
      ...lifecycleInput({ event_id: 'legacy-quarantine-event', agent_id: 'agent-one' }),
      apiKey: 'legacy-key-for-quarantine-test',
      deferDelivery: true,
    });
    await recordLifecycleEvent({
      ...lifecycleInput({ event_id: 'current-quarantine-event', agent_id: 'agent-one' }),
      apiKey: 'current-key-for-quarantine-test',
      deferDelivery: true,
    });
    const before = lifecycleSpoolStatus({ apiKey: 'current-key-for-quarantine-test', agentId: 'agent-one' });
    assert.equal(before.pending, 1);
    assert.equal(before.other_namespaces.count, 1);

    let delivered = 0;
    globalThis.fetch = async () => {
      delivered += 1;
      return new Response('{}', { status: 200 });
    };
    const quarantined = quarantineLegacyNamespaces({
      apiKey: 'current-key-for-quarantine-test',
      agentId: 'agent-one',
    });
    assert.equal(quarantined.moved, 1);
    assert.match(String(quarantined.destination), /quarantine/);
    const after = lifecycleSpoolStatus({ apiKey: 'current-key-for-quarantine-test', agentId: 'agent-one' });
    assert.equal(after.pending, 1);
    assert.equal(after.other_namespaces.count, 0);
    assert.equal(after.other_namespaces.state, 'clear');
    assert.equal(existsSync(join(home, '.marrow', 'spool', 'quarantine')), true);
    assert.equal(delivered, 0);
    const leftover = readdirSync(join(home, '.marrow', 'spool')).filter((name) => name.endsWith('.lock'));
    assert.deepEqual(leftover, []);
    const quarantinedLocks = readdirSync(join(home, '.marrow', 'spool', 'quarantine')).filter((name) => name.endsWith('.lock'));
    assert.deepEqual(quarantinedLocks, []);
  } finally {
    globalThis.fetch = originalFetch;
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalPath === undefined) delete process.env.MARROW_EVENT_SPOOL_PATH;
    else process.env.MARROW_EVENT_SPOOL_PATH = originalPath;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('explicit drain continues after a failed current-namespace event', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-drain-continue-'));
  const path = join(directory, 'spool.json');
  const originalFetch = globalThis.fetch;
  try {
    await withSpoolPath(path, async () => {
      await recordLifecycleEvent({ ...lifecycleInput({ event_id: 'drain-fail-first' }), deferDelivery: true });
      await recordLifecycleEvent({ ...lifecycleInput({ event_id: 'drain-succeed-second' }), deferDelivery: true });
      let calls = 0;
      globalThis.fetch = async () => {
        calls += 1;
        if (calls === 1) return new Response('{}', { status: 400 });
        return new Response('{}', { status: 200 });
      };
      const drained = await drainLifecycleSpool({
        apiKey: 'test-mcp-spool-key',
        baseUrl: 'https://api.example.com',
        agentId: 'agent-one',
      });
      assert.equal(calls, 2);
      assert.equal(drained.pending, 0);
      assert.equal(drained.failed, 0, 'a 400 dead letter is recoverable, not operator attention');
      assert.equal(drained.recoverable, 1);
    });
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('quarantine unlinks leftover namespace lock files for moved json', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-spool-lock-'));
  const home = join(directory, 'home');
  const originalHome = process.env.HOME;
  const originalPath = process.env.MARROW_EVENT_SPOOL_PATH;
  mkdirSync(home, { recursive: true, mode: 0o700 });
  process.env.HOME = home;
  delete process.env.MARROW_EVENT_SPOOL_PATH;
  try {
    await recordLifecycleEvent({
      ...lifecycleInput({ event_id: 'legacy-lock-event', agent_id: 'agent-one' }),
      apiKey: 'legacy-key-for-lock-test',
      deferDelivery: true,
    });
    await recordLifecycleEvent({
      ...lifecycleInput({ event_id: 'current-lock-event', agent_id: 'agent-one' }),
      apiKey: 'current-key-for-lock-test',
      deferDelivery: true,
    });
    const spoolDir = join(home, '.marrow', 'spool');
    const first = quarantineLegacyNamespaces({
      apiKey: 'current-key-for-lock-test',
      agentId: 'agent-one',
    });
    assert.equal(first.moved, 1);
    const movedJson = readdirSync(join(spoolDir, 'quarantine')).find((name) => name.endsWith('.json'));
    assert.ok(movedJson);
    writeFileSync(join(spoolDir, `${movedJson}.lock`), '', { encoding: 'utf8', mode: 0o600 });
    quarantineLegacyNamespaces({
      apiKey: 'current-key-for-lock-test',
      agentId: 'agent-one',
    });
    assert.equal(existsSync(join(spoolDir, `${movedJson}.lock`)), false);
    assert.equal(readdirSync(join(spoolDir, 'quarantine')).some((name) => name.endsWith('.lock')), false);
  } finally {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalPath === undefined) delete process.env.MARROW_EVENT_SPOOL_PATH;
    else process.env.MARROW_EVENT_SPOOL_PATH = originalPath;
    rmSync(directory, { recursive: true, force: true });
  }
});

test('nudge drains current pending events without waiting on the caller', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-spool-nudge-'));
  const home = join(directory, 'home');
  const originalHome = process.env.HOME;
  const originalPath = process.env.MARROW_EVENT_SPOOL_PATH;
  const originalFetch = globalThis.fetch;
  mkdirSync(home, { recursive: true, mode: 0o700 });
  process.env.HOME = home;
  delete process.env.MARROW_EVENT_SPOOL_PATH;
  try {
    for (const eventId of ['nudge-one', 'nudge-two', 'nudge-three']) {
      await recordLifecycleEvent({
        ...lifecycleInput({ event_id: eventId, agent_id: 'agent-one' }),
        apiKey: 'current-key-for-nudge-test',
        deferDelivery: true,
      });
    }
    assert.equal(lifecycleSpoolStatus({ apiKey: 'current-key-for-nudge-test', agentId: 'agent-one' }).pending, 3);
    let delivered = 0;
    globalThis.fetch = async () => {
      delivered += 1;
      return new Response('{}', { status: 200 });
    };
    await nudgeLifecycleSpool({
      apiKey: 'current-key-for-nudge-test',
      baseUrl: 'https://api.example.com',
      agentId: 'agent-one',
    });
    assert.equal(delivered, 3);
    assert.equal(lifecycleSpoolStatus({ apiKey: 'current-key-for-nudge-test', agentId: 'agent-one' }).pending, 0);
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
    globalThis.fetch = async () => new Response('{}', { status: 401 });
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
    assert.match(outcome.output.lifecycle_spool.exact_fix, /credential and agent binding/);
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
    const weakPermissionsFile = join(spoolDirectory, 'mcp-00000000000000000002.json');
    writeFileSync(weakPermissionsFile, '[]', { mode: 0o644 });
    chmodSync(weakPermissionsFile, 0o644);
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
      const delivered = [];
      globalThis.fetch = async (_url, init) => {
        delivered.push(JSON.parse(init.body));
        return new Response('{}', { status: 200 });
      };
      const status = await drainLifecycleSpool({
        apiKey: 'test-mcp-spool-key',
        baseUrl: 'https://api.example.com',
        agentId: 'agent-one',
      });
      assert.equal(delivered.length, 4);
      for (const event of delivered) {
        assert.equal(event.source, 'client_self_reported');
        assert.equal('capability_level' in event, false);
        assert.equal('adapter_version' in event, false);
        assert.equal('config_fingerprint' in event, false);
        assert.equal('expected_hooks' in event, false);
        assert.equal('observed_hook' in event, false);
      }
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
      const status = lifecycleSpoolStatus({ apiKey: 'test-mcp-spool-key', agentId: 'agent-one' });
      assert.equal(status.failed, 0);
      assert.equal(status.retry.reasons.ack_timeout, 1);
      assert.equal(status.retry.scheduled, 1);
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
