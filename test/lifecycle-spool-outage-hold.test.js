// Outage hold: one delivery pass stops at the first retryable failure (5xx, network error, 429, 408, 425) and the
// whole spool waits for that failure's backoff or the server Retry-After, at most 60 s, before any event is tried
// again. The failed event keeps its own deadline rules. Fake clock, fake fetch, a private spool path, a dummy key
// generated at runtime. Every test has a hard timeout.
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const MODULE = process.env.OUTAGE_HOLD_TEST_SPOOL_MODULE || '../dist/lifecycle-spool.js';
const spool = require(MODULE);

const ORIGIN = Date.parse('2026-11-16T08:00:00.000Z');
const HOLD_CAP_MS = 60_000;

function dummyKey() {
  const key = `mrw_dummy_hold_${randomBytes(12).toString('hex')}`;
  assert.doesNotMatch(key, /^(sk|pk|rk)_|^ghp_|^xox/);
  return key;
}

async function withSpool(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-outage-hold-'));
  const path = join(dir, 'spool.json');
  const originalPath = process.env.MARROW_EVENT_SPOOL_PATH;
  const originalFetch = globalThis.fetch;
  process.env.MARROW_EVENT_SPOOL_PATH = path;
  const key = dummyKey();
  const posts = [];
  const ctx = {
    dir, path, key, posts,
    scope: { apiKey: key, agentId: 'agent-hold', baseUrl: 'https://api.example.com' },
    answer: () => ({ status: 200 }),
  };
  globalThis.fetch = async (_url, init) => {
    const body = JSON.parse(init.body);
    posts.push({ id: body.event_id, at: Date.now(), body: init.body, auth: Boolean(init.headers.Authorization) });
    const answer = ctx.answer(body, posts.length);
    if (answer.throws) throw new Error('offline');
    return new Response('{}', { status: answer.status, headers: answer.headers || {} });
  };
  try {
    await fn(ctx);
  } finally {
    globalThis.fetch = originalFetch;
    if (originalPath === undefined) delete process.env.MARROW_EVENT_SPOOL_PATH;
    else process.env.MARROW_EVENT_SPOOL_PATH = originalPath;
    try { chmodSync(dir, 0o700); } catch {}
    rmSync(dir, { recursive: true, force: true });
  }
}

function record(ctx, id, eventType = 'tool_completed') {
  return spool.recordLifecycleEvent({
    apiKey: ctx.key, baseUrl: ctx.scope.baseUrl, deferDelivery: true,
    event: { event_id: id, event_type: eventType, agent_id: 'agent-hold', action: `observed ${id}`, outcome_state: 'pending', success: true },
  });
}

const rows = (ctx) => (existsSync(ctx.path) ? JSON.parse(readFileSync(ctx.path, 'utf8')) : []);

// Run a background owner on the fake clock in 100 ms steps until it settles (bounded).
async function runOwner(t, owner, maxMs = 30_000) {
  let done = false;
  owner.then(() => { done = true; }, () => { done = true; });
  for (let waited = 0; !done && waited <= maxMs; waited += 100) {
    await new Promise(setImmediate);
    t.mock.timers.tick(100);
  }
  await new Promise(setImmediate);
  assert.equal(done, true, 'the owner ends inside its budget');
}

const drainOnce = (ctx, extra = {}) => spool.drainLifecycleSpool({
  ...ctx.scope, maxEvents: 40, budgetMs: 1, requestTimeoutMs: 1_000, retryDeadLetters: false, ...extra,
});

test('O3: a 5xx outage sends one failed POST per wait window, always the oldest event, never one per queued event', { timeout: 20_000 }, async (t) => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: ORIGIN });
  try {
    await withSpool(async (ctx) => {
      const ids = Array.from({ length: 15 }, (_, i) => `outage-${String(i).padStart(2, '0')}`);
      for (const id of ids) await record(ctx, id, 'pre_action_checked');
      ctx.answer = () => ({ status: 503 });
      await runOwner(t, spool.nudgeLifecycleSpool(ctx.scope));
      // One owner with a 20 s budget: attempts at 0, 1, 3, 7 and 15 s (the 3.9.114 backoff of one event).
      assert.equal(ctx.posts.length, 5, `failed POSTs in one owner budget: ${ctx.posts.length}`);
      assert.deepEqual([...new Set(ctx.posts.map((p) => p.id))], [ids[0]], 'only the oldest event is tried while the server fails');
      for (let i = 1; i < ctx.posts.length; i += 1) {
        assert.ok(ctx.posts[i].at - ctx.posts[i - 1].at >= 1_000, 'never two failed POSTs inside one wait window');
      }
      assert.equal(rows(ctx).filter((r) => r.delivery_state === 'queued').length, 15, 'no event lost during the outage');
      // A second owner inside the hold sends nothing.
      const before = ctx.posts.length;
      await runOwner(t, spool.nudgeLifecycleSpool(ctx.scope));
      assert.ok(ctx.posts.length - before <= 1, 'a later owner adds at most one POST per wait window');
      // Recovery: every event once, oldest first.
      ctx.answer = () => ({ status: 200 });
      t.mock.timers.tick(HOLD_CAP_MS + 1_000);
      const start = ctx.posts.length;
      await runOwner(t, spool.nudgeLifecycleSpool(ctx.scope));
      const delivered = ctx.posts.slice(start).map((p) => p.id);
      assert.deepEqual(delivered, ids, 'after recovery every event once, oldest first');
      assert.equal(rows(ctx).length, 0, 'spool empty');
    });
  } finally { t.mock.timers.reset(); }
});

test('T2: a 429 Retry-After 30 on the pre-action event holds a later PostToolUse event; then pre-action first', { timeout: 20_000 }, async (t) => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: ORIGIN });
  try {
    await withSpool(async (ctx) => {
      ctx.answer = (body) => (body.event_id === 't2-pre' && ctx.posts.filter((p) => p.id === 't2-pre').length === 1
        ? { status: 429, headers: { 'Retry-After': '30' } } : { status: 200 });
      await record(ctx, 't2-pre', 'pre_action_checked');
      await runOwner(t, spool.nudgeLifecycleSpool(ctx.scope));
      assert.equal(ctx.posts.length, 1);
      await record(ctx, 't2-post', 'tool_completed');
      await runOwner(t, spool.nudgeLifecycleSpool(ctx.scope));
      assert.equal(spool.hasDueLifecycleEvents(ctx.scope), false, 'no event is due during the spool-wide wait');
      t.mock.timers.tick(29_000 - (Date.now() - ORIGIN));
      await drainOnce(ctx);
      assert.deepEqual(ctx.posts.map((p) => p.id), ['t2-pre'], 'nothing is delivered inside the 30 s');
      t.mock.timers.tick(30_000 - (Date.now() - ORIGIN));
      await runOwner(t, spool.nudgeLifecycleSpool(ctx.scope));
      assert.deepEqual(ctx.posts.map((p) => p.id), ['t2-pre', 't2-pre', 't2-post'], 'after the wait: pre-action first, then PostToolUse');
      assert.ok(ctx.posts[1].at >= ORIGIN + 30_000);
    });
  } finally { t.mock.timers.reset(); }
});

const FAR_DATE = new Date(ORIGIN + 365 * 24 * 3600 * 1000).toUTCString();
for (const [label, header, own] of [
  ['7 days', '604800', 'deadline'],
  ['10 years', '315360000', 'blocked'],
  ['negative', '-5', 'blocked'],
  ['non-numeric', 'soon', 'blocked'],
  ['an HTTP date far ahead', FAR_DATE, 'blocked'],
]) {
  test(`RACAP AB-S4: a Retry-After of ${label} holds the other events at most 60 s; the failed event keeps its 3.9.114 rule`, { timeout: 20_000 }, async (t) => {
    t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: ORIGIN });
    try {
      await withSpool(async (ctx) => {
        ctx.answer = (body) => (body.event_id === 'cap-failed' ? { status: 429, headers: { 'Retry-After': header } } : { status: 200 });
        await record(ctx, 'cap-failed', 'pre_action_checked');
        await record(ctx, 'cap-other-1');
        await record(ctx, 'cap-other-2');
        await drainOnce(ctx);
        assert.deepEqual(ctx.posts.map((p) => p.id), ['cap-failed'], 'the pass stops at the 429');
        t.mock.timers.tick(HOLD_CAP_MS - 1);
        await drainOnce(ctx);
        assert.equal(ctx.posts.length, 1, 'the others wait for the spool-wide hold');
        t.mock.timers.tick(1);
        await drainOnce(ctx);
        assert.deepEqual(ctx.posts.map((p) => p.id), ['cap-failed', 'cap-other-1', 'cap-other-2'], 'the others go at 60 s, oldest first');
        const [failed] = rows(ctx);
        assert.equal(failed.event_id, 'cap-failed');
        assert.equal(failed.delivery_state, 'queued');
        if (own === 'deadline') {
          assert.equal(failed.next_attempt_at, new Date(ORIGIN + 604_800_000).toISOString(), 'the server minimum is kept');
        } else {
          assert.equal(failed.retry_blocked, true, 'malformed or excessive guidance suspends the event');
          assert.equal(failed.retry_reason, 'retry_after_invalid');
        }
      });
    } finally { t.mock.timers.reset(); }
  });
}

test('AB-S5: a network error, then a 5xx, then a 429: one POST per pass, oldest first, then all once in order', { timeout: 20_000 }, async (t) => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: ORIGIN });
  try {
    await withSpool(async (ctx) => {
      const script = [{ throws: true }, { status: 503 }, { status: 429, headers: { 'Retry-After': '2' } }];
      ctx.answer = (_body, n) => script[n - 1] || { status: 200 };
      for (const id of ['s5-a', 's5-b', 's5-c']) await record(ctx, id);
      for (const wait of [0, 1_000, 2_000]) {
        t.mock.timers.tick(wait);
        const before = ctx.posts.length;
        await drainOnce(ctx, { budgetMs: 1 });
        assert.equal(ctx.posts.length - before, 1, 'one POST per pass');
      }
      assert.deepEqual(ctx.posts.map((p) => p.id), ['s5-a', 's5-a', 's5-a']);
      await drainOnce(ctx);
      assert.equal(ctx.posts.length, 3, 'the Retry-After holds the spool');
      t.mock.timers.tick(4_000);
      await drainOnce(ctx);
      assert.deepEqual(ctx.posts.slice(3).map((p) => p.id), ['s5-a', 's5-b', 's5-c']);
      assert.equal(rows(ctx).length, 0);
    });
  } finally { t.mock.timers.reset(); }
});

test('AB-S3 RECOV: a crash between the failed POST and the wait write leaves every event queued; no further POST that pass', { timeout: 20_000 }, async (t) => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: ORIGIN });
  try {
    await withSpool(async (ctx) => {
      for (const id of ['s3-a', 's3-b', 's3-c']) await record(ctx, id);
      ctx.answer = () => ({ status: 503 });
      await drainOnce(ctx);
      assert.deepEqual(rows(ctx).map((r) => `${r.event_id}:${r.delivery_state}:${r.attempts}`), ['s3-a:queued:1', 's3-b:queued:0', 's3-c:queued:0'],
        'a failed POST keeps its event queued; the wait drops and reorders nothing');
      t.mock.timers.tick(1_000);
      const before = readFileSync(ctx.path, 'utf8');
      // The folder turns read-only while the POST is in flight: the wait cannot be written.
      ctx.answer = () => { chmodSync(ctx.dir, 0o500); return { status: 503 }; };
      await spool.nudgeLifecycleSpool(ctx.scope);
      chmodSync(ctx.dir, 0o700);
      assert.equal(ctx.posts.length, 2, 'no further POST after the failure whose wait could not be written');
      assert.equal(readFileSync(ctx.path, 'utf8'), before, 'the spool is unchanged: every event still queued');
      ctx.answer = () => ({ status: 200 });
      await drainOnce(ctx);
      assert.deepEqual(ctx.posts.slice(2).map((p) => p.id), ['s3-a', 's3-b', 's3-c'], 'later: each once, oldest first');
    });
  } finally { t.mock.timers.reset(); }
});

test('AB-S1: an always-5xx server keeps a full spool queued (caps as 3.9.114) and delivers oldest first after recovery', { timeout: 20_000 }, async (t) => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: ORIGIN });
  try {
    await withSpool(async (ctx) => {
      await record(ctx, 'full-0000');
      const [template] = rows(ctx);
      const full = Array.from({ length: 1000 }, (_, i) => ({ ...template, event_id: `full-${String(i).padStart(4, '0')}`, action: `observed ${i}` }));
      writeFileSync(ctx.path, JSON.stringify(full), { mode: 0o600 });
      await assert.rejects(record(ctx, 'full-overflow'), /capacity/);
      ctx.answer = () => ({ status: 503 });
      await runOwner(t, spool.nudgeLifecycleSpool(ctx.scope));
      assert.equal(ctx.posts.length, 5);
      assert.deepEqual([...new Set(ctx.posts.map((p) => p.id))], ['full-0000']);
      assert.equal(rows(ctx).length, 1000, 'nothing dropped');
      ctx.answer = () => ({ status: 200 });
      t.mock.timers.tick(HOLD_CAP_MS + 1_000);
      const start = ctx.posts.length;
      await drainOnce(ctx, { maxEvents: 10 });
      assert.deepEqual(ctx.posts.slice(start).map((p) => p.id), full.slice(0, 10).map((r) => r.event_id), 'oldest first');
      assert.equal(rows(ctx).length, 990);
    });
  } finally { t.mock.timers.reset(); }
});

test('CONS-S2: status during a spool-wide wait keeps the per-event due and scheduled counts; nothing is posted', { timeout: 20_000 }, async (t) => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: ORIGIN });
  try {
    await withSpool(async (ctx) => {
      ctx.answer = (body) => (body.event_id === 'st-a' ? { status: 503 } : { status: 200 });
      await record(ctx, 'st-a');
      await drainOnce(ctx);
      await record(ctx, 'st-b');
      const status = spool.lifecycleSpoolStatus(ctx.scope);
      assert.equal(status.pending, 2);
      assert.equal(status.retry.scheduled, 1, 'the failed event is scheduled');
      assert.equal(status.retry.due, 1, 'the new event is due by its own deadline; the spool-wide wait holds it');
      assert.equal(status.retry.next_attempt_at, new Date(ORIGIN + 1_000).toISOString());
      assert.equal(spool.shouldNudgeLifecycleSpool(status), true);
      assert.equal(spool.hasDueLifecycleEvents(ctx.scope), false);
      await drainOnce(ctx);
      assert.equal(ctx.posts.length, 1);
    });
  } finally { t.mock.timers.reset(); }
});

test('AB-S6 SC-4: the dummy key is in no spool file or body; it goes only in the Authorization header', { timeout: 20_000 }, async (t) => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: ORIGIN });
  try {
    await withSpool(async (ctx) => {
      ctx.answer = () => ({ status: 503 });
      for (const id of ['k-a', 'k-b']) await record(ctx, id);
      await drainOnce(ctx);
      t.mock.timers.tick(HOLD_CAP_MS);
      ctx.answer = () => ({ status: 200 });
      await record(ctx, 'k-c');
      const files = readdirSync(ctx.dir).map((f) => readFileSync(join(ctx.dir, f), 'utf8'));
      assert.equal(files.some((text) => text.includes(ctx.key)), false);
      await drainOnce(ctx);
      assert.equal(ctx.posts.some((p) => p.body.includes(ctx.key)), false);
      assert.equal(ctx.posts.every((p) => p.auth), true);
    });
  } finally { t.mock.timers.reset(); }
});

test('an explicit drain during the hold posts nothing: a dead letter is only requeued and waits for the hold', { timeout: 20_000 }, async (t) => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: ORIGIN });
  try {
    await withSpool(async (ctx) => {
      ctx.answer = (body) => (body.event_id === 'dl-held' ? { status: 503 } : { status: 400 });
      await record(ctx, 'dl-held');
      await record(ctx, 'dl-dead');
      await drainOnce(ctx);
      assert.deepEqual(ctx.posts.map((p) => p.id), ['dl-held'], 'the pass stops at the 503');
      writeFileSync(ctx.path, JSON.stringify(rows(ctx).map((r) => (r.event_id === 'dl-dead'
        ? { ...r, delivery_state: 'dead_letter', last_status: 400, retry_reason: 'schema_rejected' } : r))), { mode: 0o600 });
      await drainOnce(ctx, { retryDeadLetters: true });
      assert.equal(ctx.posts.length, 1, 'no POST inside the hold, dead letters included');
      assert.equal(rows(ctx).find((r) => r.event_id === 'dl-dead').delivery_state, 'queued');
      ctx.answer = () => ({ status: 200 });
      t.mock.timers.tick(1_000);
      await drainOnce(ctx, { retryDeadLetters: true });
      assert.deepEqual(ctx.posts.slice(1).map((p) => p.id), ['dl-held', 'dl-dead'], 'after the hold: oldest first, once each');
    });
  } finally { t.mock.timers.reset(); }
});
