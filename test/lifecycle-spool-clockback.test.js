// Clock moved back after a failed lifecycle POST. A retryable failure holds the whole spool only while its last
// attempt is not after now (spoolHoldUntil); a failure time ahead of the clock (the clock moved back, or a forged
// row) holds nothing, as on 3.9.114: every due event is still posted once, and the failed event keeps its own
// deadline. Fake clock moved by setTime (never wall-clock time, sleeps or load), fake fetch, a private spool path,
// a dummy key generated at runtime. Every test has a hard timeout.
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const MODULE = process.env.CLOCKBACK_TEST_SPOOL_MODULE || '../dist/lifecycle-spool.js';
const spool = require(MODULE);

const ORIGIN = Date.parse('2026-11-16T08:00:00.000Z');
const HOLD_CAP_MS = 60_000;
const DAY_MS = 24 * 3600 * 1000;
const at = (ms) => new Date(ms).toISOString();

function dummyKey() {
  const key = `mrw_dummy_clockback_${randomBytes(12).toString('hex')}`;
  assert.doesNotMatch(key, /^(sk|pk|rk)_|^ghp_|^xox/);
  return key;
}

async function withSpool(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-clockback-'));
  const path = join(dir, 'spool.json');
  const originalPath = process.env.MARROW_EVENT_SPOOL_PATH;
  const originalFetch = globalThis.fetch;
  process.env.MARROW_EVENT_SPOOL_PATH = path;
  const key = dummyKey();
  const posts = [];
  const ctx = {
    dir, path, key, posts,
    scope: { apiKey: key, agentId: 'agent-clock', baseUrl: 'https://api.example.com' },
    answer: () => ({ status: 200 }),
  };
  globalThis.fetch = async (_url, init) => {
    const body = JSON.parse(init.body);
    posts.push({ id: body.event_id, at: Date.now(), body: init.body, auth: Boolean(init.headers.Authorization) });
    const answer = ctx.answer(body, posts.length);
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
    event: { event_id: id, event_type: eventType, agent_id: 'agent-clock', action: `observed ${id}`, outcome_state: 'pending', success: true },
  });
}

const rows = (ctx) => (existsSync(ctx.path) ? JSON.parse(readFileSync(ctx.path, 'utf8')) : []);
const ids = (list) => list.map((p) => p.id);

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

// Queue the events, then one drain pass at ORIGIN: the first event's POST fails retryably and the pass stops there.
// The failure holds the spool at a time inside its wait (not at the failure instant: CB2 below owns that boundary).
async function failFirst(t, ctx, eventIds, failure = { status: 503 }) {
  for (const id of eventIds) await record(ctx, id);
  ctx.answer = (body) => (body.event_id === eventIds[0] ? failure : { status: 200 });
  await drainOnce(ctx);
  assert.deepEqual(ids(ctx.posts), [eventIds[0]], 'precondition: the pass stops at the failed POST');
  const [failed] = rows(ctx);
  assert.equal(failed.event_id, eventIds[0]);
  assert.equal(failed.delivery_state, 'queued');
  assert.equal(failed.attempts, 1);
  assert.equal(failed.last_attempt_at, at(ORIGIN), 'precondition: the failure is stamped with the fake clock');
  assert.ok(Date.parse(failed.next_attempt_at) > ORIGIN, 'precondition: the failed event has its own deadline');
  t.mock.timers.setTime(ORIGIN + 500);
  assert.equal(spool.hasDueLifecycleEvents(ctx.scope), false, 'precondition: inside its wait the failure holds the spool');
  t.mock.timers.setTime(ORIGIN);
  return failed;
}

test('CB1: the clock moves back one day after a failed POST: the next drain posts every due event once, as 3.9.114', { timeout: 20_000 }, async (t) => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: ORIGIN });
  try {
    await withSpool(async (ctx) => {
      await failFirst(t, ctx, ['cb1-a', 'cb1-b', 'cb1-c']);
      const failedRow = rows(ctx)[0];
      t.mock.timers.setTime(ORIGIN - DAY_MS);
      ctx.answer = () => ({ status: 200 });
      assert.equal(spool.hasDueLifecycleEvents(ctx.scope), true, 'a failure dated after the clock holds nothing: the other events are due');
      const start = ctx.posts.length;
      await drainOnce(ctx);
      assert.deepEqual(ids(ctx.posts.slice(start)), ['cb1-b', 'cb1-c'], 'every due event once, oldest first');
      assert.deepEqual(rows(ctx).map((r) => r.event_id), ['cb1-a'], 'the failed event stays queued');
      assert.deepEqual(rows(ctx)[0], failedRow, 'the failed event keeps its own deadline, untouched');
      // Its own deadline still binds: nothing more is posted until the clock is past it.
      await drainOnce(ctx);
      assert.equal(ctx.posts.length, start + 2, 'the failed event is not due at the moved-back time');
      t.mock.timers.setTime(ORIGIN + 1_000);
      await drainOnce(ctx);
      assert.deepEqual(ids(ctx.posts.slice(start + 2)), ['cb1-a'], 'past its own deadline it is posted once');
      assert.equal(rows(ctx).length, 0, 'spool empty');
      const files = readdirSync(ctx.dir).map((f) => readFileSync(join(ctx.dir, f), 'utf8'));
      assert.equal(files.some((text) => text.includes(ctx.key)), false, 'the dummy key is in no spool file');
      assert.equal(ctx.posts.some((p) => p.body.includes(ctx.key)), false, 'the dummy key is in no body');
    });
  } finally { t.mock.timers.reset(); }
});

test('CB1: a single failed event, then the clock moves back one day and a new event is recorded: the new event is posted once', { timeout: 20_000 }, async (t) => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: ORIGIN });
  try {
    await withSpool(async (ctx) => {
      await failFirst(t, ctx, ['cb1s-a']);
      t.mock.timers.setTime(ORIGIN - DAY_MS);
      await record(ctx, 'cb1s-b');
      ctx.answer = () => ({ status: 200 });
      assert.equal(spool.hasDueLifecycleEvents(ctx.scope), true);
      await drainOnce(ctx);
      assert.deepEqual(ids(ctx.posts), ['cb1s-a', 'cb1s-b'], 'the new event is posted once; the failed one waits for its own deadline');
      assert.deepEqual(rows(ctx).map((r) => r.event_id), ['cb1s-a']);
    });
  } finally { t.mock.timers.reset(); }
});

test('CB1: the background owner posts every due event once after the clock moves back one day', { timeout: 20_000 }, async (t) => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: ORIGIN });
  try {
    await withSpool(async (ctx) => {
      await failFirst(t, ctx, ['cb1o-a', 'cb1o-b', 'cb1o-c']);
      t.mock.timers.setTime(ORIGIN - DAY_MS);
      ctx.answer = () => ({ status: 200 });
      await runOwner(t, spool.nudgeLifecycleSpool(ctx.scope));
      assert.deepEqual(ids(ctx.posts), ['cb1o-a', 'cb1o-b', 'cb1o-c'], 'the owner posts the two due events once; the failed one is not due');
      assert.deepEqual(rows(ctx).map((r) => r.event_id), ['cb1o-a']);
    });
  } finally { t.mock.timers.reset(); }
});

for (const [label, backMs] of [['one second', 1_000], ['one minute', 60_000]]) {
  test(`CB2: the clock moves back ${label} after a failed POST: the next drain posts every due event once`, { timeout: 20_000 }, async (t) => {
    t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: ORIGIN });
    try {
      await withSpool(async (ctx) => {
        await failFirst(t, ctx, ['cb2-a', 'cb2-b', 'cb2-c']);
        t.mock.timers.setTime(ORIGIN - backMs);
        ctx.answer = () => ({ status: 200 });
        assert.equal(spool.hasDueLifecycleEvents(ctx.scope), true);
        await drainOnce(ctx);
        assert.deepEqual(ids(ctx.posts), ['cb2-a', 'cb2-b', 'cb2-c'], 'the two due events once, oldest first');
        assert.deepEqual(rows(ctx).map((r) => r.event_id), ['cb2-a'], 'the failed event keeps its own deadline');
      });
    } finally { t.mock.timers.reset(); }
  });
}

test('CB2: the clock not moved holds the spool at the failure instant and until the failed event is due, then oldest first', { timeout: 20_000 }, async (t) => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: ORIGIN });
  try {
    await withSpool(async (ctx) => {
      await failFirst(t, ctx, ['cb2e-a', 'cb2e-b']);
      await drainOnce(ctx);
      assert.equal(ctx.posts.length, 1, 'a failure at this very instant holds the other events');
      t.mock.timers.setTime(ORIGIN + 999);
      await drainOnce(ctx);
      assert.equal(ctx.posts.length, 1, 'one millisecond before its own deadline still holds them');
      t.mock.timers.setTime(ORIGIN + 1_000);
      ctx.answer = () => ({ status: 200 });
      await drainOnce(ctx);
      assert.deepEqual(ids(ctx.posts), ['cb2e-a', 'cb2e-a', 'cb2e-b'], 'at its deadline: the failed event first, then the other');
    });
  } finally { t.mock.timers.reset(); }
});

test('CB3: the clock moves forward past RETRY_MAX_MS: the hold window ends even for a server minimum of one hour', { timeout: 20_000 }, async (t) => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: ORIGIN });
  try {
    await withSpool(async (ctx) => {
      const failed = await failFirst(t, ctx, ['cb3-a', 'cb3-b', 'cb3-c'], { status: 429, headers: { 'Retry-After': '3600' } });
      assert.equal(failed.next_attempt_at, at(ORIGIN + 3_600_000), 'the server minimum is kept on the failed event');
      t.mock.timers.setTime(ORIGIN + HOLD_CAP_MS - 1);
      await drainOnce(ctx);
      assert.equal(ctx.posts.length, 1, 'one millisecond inside the window nothing is posted');
      t.mock.timers.setTime(ORIGIN + HOLD_CAP_MS);
      assert.equal(spool.hasDueLifecycleEvents(ctx.scope), true, 'RETRY_MAX_MS after the failed attempt the window has ended');
      t.mock.timers.setTime(ORIGIN + HOLD_CAP_MS + 1);
      ctx.answer = () => ({ status: 200 });
      assert.equal(spool.hasDueLifecycleEvents(ctx.scope), true, 'past RETRY_MAX_MS the window stays ended');
      await drainOnce(ctx);
      assert.deepEqual(ids(ctx.posts.slice(1)), ['cb3-b', 'cb3-c'], 'the other events once, oldest first; the failed event keeps its one-hour minimum');
      assert.deepEqual(rows(ctx).map((r) => r.event_id), ['cb3-a']);
    });
  } finally { t.mock.timers.reset(); }
});

// A forged row: queued, last attempt dated after the clock. It holds nothing; the other events are posted once.
const FORGED_PREFIX = 'ab1-';
for (const [label, forge, forgedIsDue] of [
  ['one second ahead with its own wait', { last_attempt_at: at(ORIGIN + 1_000), next_attempt_at: at(ORIGIN + 2_000) }, false],
  ['one day ahead with its own wait', { last_attempt_at: at(ORIGIN + DAY_MS), next_attempt_at: at(ORIGIN + DAY_MS + 1_000) }, false],
  ['ten years ahead with its own wait', { last_attempt_at: at(ORIGIN + 3_650 * DAY_MS), next_attempt_at: at(ORIGIN + 3_650 * DAY_MS + 1_000) }, false],
  ['one day ahead and suspended', { last_attempt_at: at(ORIGIN + DAY_MS), retry_blocked: true, retry_reason: 'retry_after_invalid' }, false],
  ['one day ahead with no wait of its own', { last_attempt_at: at(ORIGIN + DAY_MS) }, true],
]) {
  test(`AB1: a forged last_attempt_at ${label} holds nothing`, { timeout: 20_000 }, async (t) => {
    t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: ORIGIN });
    try {
      await withSpool(async (ctx) => {
        await record(ctx, `${FORGED_PREFIX}template`);
        const [template] = rows(ctx);
        const forged = { ...template, event_id: `${FORGED_PREFIX}forged`, attempts: 1, last_status: 503, ...forge };
        const due = ['due-1', 'due-2'].map((name) => ({ ...template, event_id: `${FORGED_PREFIX}${name}` }));
        writeFileSync(ctx.path, JSON.stringify([forged, ...due]), { mode: 0o600 });
        assert.equal(spool.hasDueLifecycleEvents(ctx.scope), true, 'the other events are due');
        await drainOnce(ctx);
        const expected = [...(forgedIsDue ? [forged.event_id] : []), ...due.map((row) => row.event_id)];
        assert.deepEqual(ids(ctx.posts), expected, 'every due event once, oldest first');
        if (!forgedIsDue) assert.deepEqual(rows(ctx), [forged], 'the forged row is left as it was');
      });
    } finally { t.mock.timers.reset(); }
  });
}

test('AB1 control: the same forged row dated one second in the past holds the other events', { timeout: 20_000 }, async (t) => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: ORIGIN });
  try {
    await withSpool(async (ctx) => {
      await record(ctx, `${FORGED_PREFIX}template`);
      const [template] = rows(ctx);
      const forged = { ...template, event_id: `${FORGED_PREFIX}past`, attempts: 1, last_status: 503, last_attempt_at: at(ORIGIN - 1_000), next_attempt_at: at(ORIGIN + 1_000) };
      const due = { ...template, event_id: `${FORGED_PREFIX}due-3` };
      writeFileSync(ctx.path, JSON.stringify([forged, due]), { mode: 0o600 });
      assert.equal(spool.hasDueLifecycleEvents(ctx.scope), false, 'a failure in the past holds the spool');
      await drainOnce(ctx);
      assert.equal(ctx.posts.length, 0, 'nothing is posted inside the hold');
      t.mock.timers.setTime(ORIGIN + 1_000);
      await drainOnce(ctx);
      assert.deepEqual(ids(ctx.posts), [forged.event_id, due.event_id], 'after the hold: oldest first');
    });
  } finally { t.mock.timers.reset(); }
});

// A malformed last_attempt_at never reaches the hold check: the stored row is not a canonical time, so the whole
// spool file is moved aside as corrupt (3.9.115) and nothing in it holds anything.
for (const [label, value] of [
  ['text', 'not a time'],
  ['an empty string', ''],
  ['a time without milliseconds', '2026-11-16T08:00:00Z'],
  ['an HTTP date', 'Mon, 16 Nov 2026 08:00:00 GMT'],
]) {
  test(`AB2: a malformed last_attempt_at (${label}) holds nothing: the spool is set aside and a new event is posted once`, { timeout: 20_000 }, async (t) => {
    t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: ORIGIN });
    try {
      await withSpool(async (ctx) => {
        await record(ctx, 'ab2-template');
        const [template] = rows(ctx);
        const forged = { ...template, event_id: 'ab2-forged', attempts: 1, last_status: 503, last_attempt_at: value, next_attempt_at: at(ORIGIN + DAY_MS) };
        writeFileSync(ctx.path, JSON.stringify([forged, { ...template, event_id: 'ab2-other' }]), { mode: 0o600 });
        const fresh = await record(ctx, 'ab2-fresh');
        assert.equal(fresh.recovered_corruption, true, 'the unreadable spool is set aside');
        assert.equal(readdirSync(ctx.dir).filter((f) => f.includes('.corrupt-')).length, 1);
        assert.deepEqual(rows(ctx).map((r) => r.event_id), ['ab2-fresh']);
        assert.equal(spool.hasDueLifecycleEvents(ctx.scope), true);
        await drainOnce(ctx);
        assert.deepEqual(ids(ctx.posts), ['ab2-fresh'], 'the new event is posted once');
        assert.equal(rows(ctx).length, 0);
      });
    } finally { t.mock.timers.reset(); }
  });
}

test('AB2: a queued row with no last_attempt_at (NaN) and a dead letter dated in the future hold nothing', { timeout: 20_000 }, async (t) => {
  t.mock.timers.enable({ apis: ['Date', 'setTimeout'], now: ORIGIN });
  try {
    await withSpool(async (ctx) => {
      await record(ctx, 'ab2n-template');
      const [template] = rows(ctx);
      const dead = {
        ...template, event_id: 'ab2n-dead', delivery_state: 'dead_letter', attempts: 1, last_status: 400, retry_reason: 'schema_rejected',
        last_attempt_at: at(ORIGIN + DAY_MS), next_attempt_at: at(ORIGIN + DAY_MS + 1_000),
      };
      writeFileSync(ctx.path, JSON.stringify([dead, { ...template, event_id: 'ab2n-a' }, { ...template, event_id: 'ab2n-b' }]), { mode: 0o600 });
      assert.equal(spool.hasDueLifecycleEvents(ctx.scope), true);
      await drainOnce(ctx);
      assert.deepEqual(ids(ctx.posts), ['ab2n-a', 'ab2n-b'], 'both queued events once in one pass; the dead letter is not tried');
      assert.deepEqual(rows(ctx), [dead], 'the dead letter is left as it was');
    });
  } finally { t.mock.timers.reset(); }
});
