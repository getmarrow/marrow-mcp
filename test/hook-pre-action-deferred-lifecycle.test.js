// The pre-action hook answers on the runtime result: its pre_action_checked lifecycle event is in the spool
// before the answer and a detached background nudge delivers it after the answer. MARROW_HOOK_BACKGROUND_NUDGE=false
// (and a spool write that fails) keeps the inline delivery. Real entrypoint (`cli.js claude-pre-action-hook`),
// real event JSON on stdin, fake HOME, dummy key generated at runtime, self-signed https loopback recorder.
const test = require('node:test');
const assert = require('node:assert/strict');
const https = require('node:https');
const { spawn, execFileSync } = require('node:child_process');
const { randomBytes } = require('node:crypto');
const { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');

const CLI = process.env.DEFER_LIFECYCLE_TEST_CLI || resolve(__dirname, '../dist/cli.js');
const EVENTS_PATH = '/v1/agent/integrations/events';

let opensslOk = true;
try { execFileSync('openssl', ['version'], { stdio: 'ignore' }); } catch { opensslOk = false; }
const skip = !opensslOk || process.platform === 'win32';

// A dummy key: fixed non-key prefix plus runtime hex; never a live key shape.
function dummyKey() {
  const key = `mrw_dummy_defer_${randomBytes(12).toString('hex')}`;
  assert.doesNotMatch(key, /^(sk|pk|rk)_|^ghp_|^xox/);
  return key;
}

function makeCert(dir) {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'k.pem'),
    '-out', join(dir, 'c.pem'), '-days', '1', '-subj', '/CN=127.0.0.1',
    '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
  return { key: readFileSync(join(dir, 'k.pem')), cert: readFileSync(join(dir, 'c.pem')), certPath: join(dir, 'c.pem') };
}

const ALLOW = { risk_gate: { allow: true, decision: 'allow', enforced: true, reasons: [] } };
const HELD = {
  ok: true,
  decision_id: 'decision-defer',
  runtime_authorization: { id: 'gate-defer', kind: 'durable_gate_receipt', durable: true, decision_state: 'created', decision_creation_required: false, decision_id: 'decision-defer' },
  gate_receipt: { id: 'gate-defer', decision: 'review_required', required: true, owner_approval_required: true, expires_at: '2030-01-01T00:30:00.000Z' },
  proof_pack: { required: false, fields: [], complete: true },
  completion_contract: {
    decision_id: 'decision-defer', decision_creation_required: false, decision_state: 'created',
    owner_approval_required: true, arbitration_receipt_required: false, gate_receipt_required: true,
    required_commit_fields: ['decision_id', 'success', 'outcome', 'gate_receipt_id'],
    owner_approval: {
      mode: 'ordinary_non_arbitrated', proof_path: null, proof_shape: null, dashboard_receipt_required: false,
      trusted_completion_receipt_required: true, receipt_field: 'owner_approval_receipt_id',
      approval_endpoint: '/v1/dashboard/enforcement/owner-approval', approval_authority: 'host_operator_or_dashboard_owner',
      approval_status_endpoint: '/v1/agent/gate-receipts/gate-defer/owner-approval', approval_status_poll_after_ms: 5000,
      host_approval_endpoint: '/v1/agent/gate-receipts/gate-defer/host-approval', host_approval_accepted: true,
      host_approval_trust: 'client_attested', approval_categories: ['source_control'],
      verified_approval_required: false, verified_approval_categories: [],
    },
  },
  risk_gate: { allow: true, decision: 'review_required', enforced: true, gate_required: true, gate_receipt_id: 'gate-defer', risk_level: 'high', reasons: [{ message: 'Needs approval.' }] },
  gate_receipt_id: 'gate-defer',
  exact_next_action: 'Obtain explicit owner approval before this action runs.',
};

// The loopback recorder: per-route latency, per-event lifecycle answers, replay identity by event id.
async function withRecorder(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-defer-'));
  const cert = makeCert(dir);
  const config = { runtimeMs: 0, lifecycleMs: 0, runtime: ALLOW, runtimeMode: 'ok', lifecycle: () => ({ status: 200 }) };
  const requests = [];
  const accepted = new Map();
  const seen = new Map();
  const replay = { mismatches: 0, replays: 0 };
  const server = https.createServer({ key: cert.key, cert: cert.cert }, (req, res) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      const path = new URL(req.url, 'https://127.0.0.1').pathname;
      let body = null;
      try { body = raw ? JSON.parse(raw) : null; } catch { body = raw; }
      const headers = { ...req.headers };
      delete headers.authorization;
      const row = { path, body, raw, headers, start: Date.now(), end: null, status: 0 };
      requests.push(row);
      // A POST ends when its answer is sent or the client gives up on it (the inline cap), whichever comes first.
      res.on('close', () => { if (row.end === null) row.end = Date.now(); });
      const finish = (status, payload, extraHeaders = {}) => {
        row.status = status;
        res.on('finish', () => { if (row.end === null) row.end = Date.now(); });
        res.writeHead(status, { 'content-type': 'application/json', ...extraHeaders });
        res.end(JSON.stringify(payload));
      };
      if (path === EVENTS_PATH) {
        const id = body && body.event_id;
        const count = (seen.get(id) || 0) + 1;
        seen.set(id, count);
        const answer = config.lifecycle(body, count);
        setTimeout(() => {
          if (answer.drop) { row.end = Date.now(); row.status = -1; req.socket.destroy(); return; }
          if (answer.status >= 200 && answer.status < 300) {
            // The server's replay identity: one record per event id; a resend must carry the same payload.
            if (accepted.has(id)) { replay.replays += 1; if (accepted.get(id) !== raw) replay.mismatches += 1; } else accepted.set(id, raw);
          }
          finish(answer.status, answer.status < 300 ? { data: { accepted: true } } : { error: { code: answer.code || 'x' } }, answer.headers || {});
        }, config.lifecycleMs);
        return;
      }
      if (path === '/v1/agent/runtime') {
        setTimeout(() => {
          if (config.runtimeMode === 'outage') { row.end = Date.now(); req.socket.destroy(); return; }
          finish(200, { data: config.runtime });
        }, config.runtimeMs);
        return;
      }
      finish(200, { data: {} });
    });
  });
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  const key = dummyKey();
  const home = join(dir, 'home');
  const project = join(dir, 'project');
  mkdirSync(home, { mode: 0o700 });
  mkdirSync(project, { mode: 0o700 });
  const env = {
    PATH: process.env.PATH, HOME: home, MARROW_API_KEY: key, MARROW_AGENT_ID: 'agent-defer',
    MARROW_BASE_URL: `https://127.0.0.1:${server.address().port}`, MARROW_PASSIVE_TOKEN_USAGE: 'false',
    NODE_EXTRA_CA_CERTS: cert.certPath,
    ...(process.env.DEFER_LIFECYCLE_TEST_NETGUARD ? { NODE_OPTIONS: `--require=${process.env.DEFER_LIFECYCLE_TEST_NETGUARD}`, NETGUARD_LOG: process.env.NETGUARD_LOG || '' } : {}),
  };
  try {
    await fn({ dir, home, project, env, key, config, requests, accepted, seen, replay });
  } finally {
    // Let any detached nudge finish before the folder goes.
    await until(() => locks(home).length === 0, 25_000);
    server.closeAllConnections();
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

function runHook(env, payload, extra = {}, entrypoint = 'claude-pre-action-hook') {
  return new Promise((done) => {
    const start = Date.now();
    let answerAt = null;
    let stdout = '';
    let stderr = '';
    const child = spawn(process.execPath, [CLI, entrypoint], { env: { ...env, ...extra }, stdio: ['pipe', 'pipe', 'pipe'], cwd: payload.cwd });
    child.stdout.on('data', (chunk) => { if (answerAt === null) answerAt = Date.now(); stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.stdin.end(JSON.stringify(payload));
    child.on('exit', (code) => {
      const exitAt = Date.now();
      done({ code, stdout, stderr, start, answerAt: answerAt ?? exitAt, exitAt, pid: child.pid });
    });
  });
}

const preEvent = (project, id, command = 'node build.js') => ({
  session_id: 'sess-defer', cwd: project, permission_mode: 'default', hook_event_name: 'PreToolUse',
  tool_name: 'Bash', tool_input: { command }, tool_use_id: id,
});
const postEvent = (project, id, command = 'node build.js') => ({
  session_id: 'sess-defer', cwd: project, hook_event_name: 'PostToolUse', tool_name: 'Bash',
  tool_input: { command }, tool_response: { stdout: 'ok' }, tool_use_id: id,
});

const spoolDir = (home) => join(home, '.marrow', 'spool');
const isDir = (p) => { try { return statSync(p).isDirectory(); } catch { return false; } };
const spoolFiles = (home) => isDir(spoolDir(home)) ? readdirSync(spoolDir(home)).filter((f) => /^mcp-[0-9a-f]+\.json$/.test(f)) : [];
const spoolRows = (home) => spoolFiles(home).flatMap((f) => {
  try { const parsed = JSON.parse(readFileSync(join(spoolDir(home), f), 'utf8')); return Array.isArray(parsed) ? parsed : parsed.events || []; } catch { return []; }
});
const locks = (home) => isDir(spoolDir(home)) ? readdirSync(spoolDir(home)).filter((f) => f.endsWith('.nudge.lock')) : [];
const lifecyclePosts = (requests) => requests.filter((r) => r.path === EVENTS_PATH);
const prePosts = (requests) => lifecyclePosts(requests).filter((r) => r.body && r.body.event_type === 'pre_action_checked');
const runtimePosts = (requests) => requests.filter((r) => r.path === '/v1/agent/runtime');
async function until(cond, ms = 15_000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (cond()) return true; await new Promise((r) => setTimeout(r, 50)); }
  return cond();
}
const settled = (ctx) => until(() => locks(ctx.home).length === 0 && lifecyclePosts(ctx.requests).every((r) => r.end !== null), 25_000);

// Parsed-JSON comparison after removing generated times only; the event id keeps its payload-bound base.
function normal(value) {
  if (Array.isArray(value)) return value.map(normal);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (k === 'occurred_at' || k === 'date' || k === 'x-request-start') continue;
      out[k] = k === 'event_id' && typeof v === 'string' ? v.replace(/-[0-9a-f]{12}$/, '-<digest>') : normal(v);
    }
    return out;
  }
  return value;
}
const NOISY_HEADERS = new Set(['content-length', 'connection', 'host']);
const headerView = (h) => Object.fromEntries(Object.entries(h).filter(([k]) => !NOISY_HEADERS.has(k))
  .map(([k, v]) => [k, k === 'idempotency-key' ? String(v).replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, '<uuid>') : v]).sort());


async function observe(ctx, payload, extra = {}) {
  const before = ctx.requests.length;
  const run = await runHook(ctx.env, payload, extra);
  await settled(ctx);
  const mine = ctx.requests.slice(before);
  return { run, mine, runtime: runtimePosts(mine), pre: prePosts(mine) };
}

test('M1: with lifecycle 900 ms and runtime 450 ms the answer is written before the lifecycle POST ends', { skip, timeout: 90_000 }, () => withRecorder(async (ctx) => {
  ctx.config.runtimeMs = 450;
  ctx.config.lifecycleMs = 900;
  const { run, pre, runtime } = await observe(ctx, preEvent(ctx.project, 'toolu_m1'));
  assert.equal(runtime.length, 1, 'the runtime call is made');
  assert.equal(pre.length, 1, 'the pre-action event is delivered exactly once');
  assert.ok(run.exitAt < pre[0].end, `answer and exit (${run.exitAt - run.start} ms) come before the lifecycle POST ends (${pre[0].end - run.start} ms)`);
  assert.ok(run.answerAt >= runtime[0].start, 'the answer never comes before the control call starts');
  assert.equal(spoolRows(ctx.home).length, 0, 'the spool is empty after delivery');
}));

test('SA-7 SC-1 SC-2: nudge off is the inline path; nudge on sends the same runtime body, headers and lifecycle payload', { skip, timeout: 90_000 }, () => withRecorder(async (ctx) => {
  ctx.config.runtimeMs = 50;
  ctx.config.lifecycleMs = 300;
  const off = await observe(ctx, preEvent(ctx.project, 'toolu_sc'), { MARROW_HOOK_BACKGROUND_NUDGE: 'false' });
  assert.equal(off.pre.length, 1);
  assert.ok(off.pre[0].end <= off.run.exitAt, 'nudge off: the lifecycle POST ends before the hook exits (3.9.114 order)');
  const on = await observe(ctx, preEvent(ctx.project, 'toolu_sc'));
  assert.equal(on.pre.length, 1);
  assert.equal(on.run.stdout, off.run.stdout);
  assert.equal(on.run.code, off.run.code);
  assert.deepEqual(normal(on.runtime.map((r) => r.body)), normal(off.runtime.map((r) => r.body)));
  assert.deepEqual(on.runtime.map((r) => headerView(r.headers)), off.runtime.map((r) => headerView(r.headers)));
  assert.deepEqual(normal(on.pre[0].body), normal(off.pre[0].body));
  assert.deepEqual(headerView(on.pre[0].headers), headerView(off.pre[0].headers));
  for (const post of [on.pre[0], off.pre[0]]) assert.match(post.body.event_id, /^pretool-.+-[0-9a-f]{12}$/);
  assert.equal(on.pre[0].body.event_id.replace(/-[0-9a-f]{12}$/, ''), off.pre[0].body.event_id.replace(/-[0-9a-f]{12}$/, ''));
}));

test('SA-1: the nudge never starts (lock held by another owner): the event stays spooled and the next hook delivers it once', { skip, timeout: 90_000 }, () => withRecorder(async (ctx) => {
  await runHook(ctx.env, preEvent(ctx.project, 'toolu_warm'));
  await settled(ctx);
  const lockFile = join(spoolDir(ctx.home), `${spoolFiles(ctx.home)[0] || 'none'}.nudge.lock`);
  ctx.requests.length = 0;
  writeFileSync(lockFile, `1:${randomBytes(8).toString('hex')}`, { mode: 0o600 });
  const first = await runHook(ctx.env, preEvent(ctx.project, 'toolu_sa1a'));
  assert.equal(first.code, 0);
  await new Promise((r) => setTimeout(r, 800));
  // Never lost: posted inline (nudge off) or in the spool for the next owner.
  assert.equal(prePosts(ctx.requests).length + spoolRows(ctx.home).filter((r) => r.event_type === 'pre_action_checked').length, 1);
  rmSync(lockFile, { force: true });
  await observe(ctx, preEvent(ctx.project, 'toolu_sa1b'));
  const ids = prePosts(ctx.requests).filter((r) => r.status === 200).map((r) => r.body.event_id);
  assert.equal(ids.length, 2, 'both events delivered');
  assert.equal(new Set(ids).size, 2, 'each exactly once');
  assert.equal(spoolRows(ctx.home).length, 0);
}));

test('SA-2 SC-3: a lost ACK is redelivered with the same event id and accepted once by the replay identity', { skip, timeout: 90_000 }, () => withRecorder(async (ctx) => {
  ctx.config.lifecycle = (body, count) => (count === 1 ? { drop: true } : { status: 200 });
  const { run } = await observe(ctx, preEvent(ctx.project, 'toolu_sa2'));
  assert.equal(run.code, 0);
  await new Promise((r) => setTimeout(r, 1200));
  await runHook(ctx.env, postEvent(ctx.project, 'toolu_sa2'), {}, 'claude-hook');
  await until(() => prePosts(ctx.requests).some((r) => r.status === 200), 20_000);
  await settled(ctx);
  const posts = prePosts(ctx.requests);
  assert.ok(posts.length >= 2);
  assert.equal(new Set(posts.map((p) => p.body.event_id)).size, 1, 'one event id across the redelivery');
  assert.deepEqual(posts[0].body, posts[posts.length - 1].body, 'the same payload');
  assert.equal(posts.filter((p) => p.status === 200).length, 1, 'accepted once');
  assert.equal(ctx.replay.mismatches, 0);
  assert.equal(spoolRows(ctx.home).length, 0);
}));

test('SA-3: 429 Retry-After 30 holds the deferred event; nothing early; then pre-action before PostToolUse', { skip, timeout: 90_000 }, () => withRecorder(async (ctx) => {
  let first = true;
  ctx.config.lifecycle = (body) => {
    if (first && body.event_type === 'pre_action_checked') { first = false; return { status: 429, headers: { 'retry-after': '30' } }; }
    return { status: 200 };
  };
  const t0 = Date.now();
  await observe(ctx, preEvent(ctx.project, 'toolu_sa3'));
  await new Promise((r) => setTimeout(r, 1500));
  const held = spoolRows(ctx.home).find((r) => r.event_type === 'pre_action_checked');
  assert.ok(held, 'the event stays in the spool');
  assert.ok(Date.parse(held.next_attempt_at) >= t0 + 29_000, 'next attempt not before Retry-After');
  assert.equal(prePosts(ctx.requests).length, 1, 'no second attempt before the time');
  // Time passes (the spool's own next attempt moves to now), then the PostToolUse hook of the same call runs.
  const file = join(spoolDir(ctx.home), spoolFiles(ctx.home)[0]);
  const raw = JSON.parse(readFileSync(file, 'utf8'));
  const rows = Array.isArray(raw) ? raw : raw.events;
  for (const row of rows) if (row.next_attempt_at) row.next_attempt_at = new Date(Date.now() - 1000).toISOString();
  writeFileSync(file, JSON.stringify(raw), { mode: 0o600 });
  chmodSync(file, 0o600);
  await runHook(ctx.env, postEvent(ctx.project, 'toolu_sa3'), {}, 'claude-hook');
  await until(() => lifecyclePosts(ctx.requests).filter((r) => r.status === 200).length >= 2, 15_000);
  await settled(ctx);
  const ok = lifecyclePosts(ctx.requests).filter((r) => r.status === 200).map((r) => r.body.event_type);
  assert.equal(ok[0], 'pre_action_checked', 'the pre-action event first');
  assert.equal(ok.length, 2);
}));

test('SA-4: 5xx three times then 2xx: delivered once, spool empty', { skip, timeout: 90_000 }, () => withRecorder(async (ctx) => {
  ctx.config.lifecycle = (body, count) => (count <= 3 ? { status: 503 } : { status: 200 });
  await observe(ctx, preEvent(ctx.project, 'toolu_sa4'));
  await new Promise((r) => setTimeout(r, 1200));
  await runHook(ctx.env, postEvent(ctx.project, 'toolu_sa4'), {}, 'claude-hook');
  await until(() => prePosts(ctx.requests).some((r) => r.status === 200), 20_000);
  await settled(ctx);
  assert.equal(prePosts(ctx.requests).filter((r) => r.status === 200).length, 1);
  assert.equal(new Set(prePosts(ctx.requests).map((r) => r.body.event_id)).size, 1);
  assert.equal(spoolRows(ctx.home).length, 0);
}));

for (const [status, code] of [[409, 'server_owned'], [422, 'schema_rejected']]) {
  test(`SA-5: ${status} on the pre-action event ends in the same spool state and post count as the inline path`, { skip, timeout: 90_000 }, () => withRecorder(async (ctx) => {
    const state = async (extra, id) => {
      ctx.requests.length = 0;
      ctx.config.lifecycle = (body) => (body.event_type === 'pre_action_checked' ? { status, code } : { status: 200 });
      await observe(ctx, preEvent(ctx.project, id), extra);
      await runHook(ctx.env, postEvent(ctx.project, id), extra, 'claude-hook');
      await settled(ctx);
      await new Promise((r) => setTimeout(r, 300));
      await settled(ctx);
      const row = spoolRows(ctx.home).find((r) => r.event_type === 'pre_action_checked' && r.correlation_id && r.event_id.includes(id.slice(-6)) || false)
        || spoolRows(ctx.home).filter((r) => r.event_type === 'pre_action_checked').pop();
      return { posts: prePosts(ctx.requests).length, state: row && row.delivery_state, owned: row && row.server_owned === true, reason: row && row.retry_reason };
    };
    const off = await state({ MARROW_HOOK_BACKGROUND_NUDGE: 'false' }, `toolu_sa5off${status}`);
    rmSync(spoolDir(ctx.home), { recursive: true, force: true });
    const on = await state({}, `toolu_sa5on${status}`);
    assert.equal(on.state, 'dead_letter');
    assert.equal(on.state, off.state);
    assert.equal(on.owned, off.owned);
    assert.equal(on.reason, off.reason);
  }));
}

test('SA-6: an unwritable spool keeps the answer; the hook does not wait twice on a held spool lock', { skip, timeout: 90_000 }, () => withRecorder(async (ctx) => {
  mkdirSync(join(ctx.home, '.marrow'), { mode: 0o700 });
  writeFileSync(spoolDir(ctx.home), 'not a folder', { mode: 0o600 });
  const off = await observe(ctx, preEvent(ctx.project, 'toolu_sa6'), { MARROW_HOOK_BACKGROUND_NUDGE: 'false' });
  const on = await observe(ctx, preEvent(ctx.project, 'toolu_sa6'));
  assert.equal(on.run.stdout, off.run.stdout);
  assert.equal(on.run.code, off.run.code);
  assert.equal(on.pre.length, off.pre.length, 'the same lifecycle delivery as the inline path');
  assert.deepEqual(normal(on.runtime.map((r) => r.body)), normal(off.runtime.map((r) => r.body)));
  // A spool lock held past its wait: one wait, as the inline path, never two.
  rmSync(spoolDir(ctx.home), { force: true });
  await observe(ctx, preEvent(ctx.project, 'toolu_sa6w'));
  const name = spoolFiles(ctx.home)[0];
  const lock = join(spoolDir(ctx.home), `${name}.lock`);
  const hold = setInterval(() => { try { writeFileSync(lock, 'held', { mode: 0o600 }); } catch {} }, 1000);
  writeFileSync(lock, 'held', { mode: 0o600 });
  try {
    const offLock = await runHook(ctx.env, preEvent(ctx.project, 'toolu_sa6l'), { MARROW_HOOK_BACKGROUND_NUDGE: 'false' });
    const onLock = await runHook(ctx.env, preEvent(ctx.project, 'toolu_sa6l'));
    assert.equal(onLock.stdout, offLock.stdout);
    assert.equal(onLock.code, offLock.code);
    assert.ok(onLock.answerAt - onLock.start < (offLock.answerAt - offLock.start) + 3_000, 'no second lock wait');
  } finally {
    clearInterval(hold);
    rmSync(lock, { force: true });
  }
}));

test('SA-8: two parallel hooks and a running PostToolUse nudge: one nudge owner, every event once', { skip, timeout: 90_000 }, () => withRecorder(async (ctx) => {
  ctx.config.lifecycleMs = 200;
  const runs = await Promise.all([
    runHook(ctx.env, postEvent(ctx.project, 'toolu_sa8p'), {}, 'claude-hook'),
    runHook(ctx.env, preEvent(ctx.project, 'toolu_sa8a')),
    runHook(ctx.env, preEvent(ctx.project, 'toolu_sa8b', 'make all')),
  ]);
  assert.ok(runs.every((r) => r.code === 0));
  await until(() => lifecyclePosts(ctx.requests).filter((r) => r.status === 200).length >= 3, 20_000);
  // A last hook picks up anything a finishing owner left (the documented hand-over).
  await settled(ctx);
  if (spoolRows(ctx.home).length > 0) await observe(ctx, preEvent(ctx.project, 'toolu_sa8c', 'python3 tool.py'));
  await settled(ctx);
  const ids = new Set(lifecyclePosts(ctx.requests).filter((r) => r.status === 200).map((r) => r.body.event_id));
  assert.equal(ids.size, 3, 'every event recorded once by the replay identity');
  assert.equal(ctx.replay.mismatches, 0, 'a resend never carries another payload');
  assert.equal(spoolRows(ctx.home).length, 0);
  assert.equal(locks(ctx.home).length, 0, 'the nudge lock is released');
}));

for (const mode of ['timeout', 'outage']) {
  test(`SA-9: runtime ${mode}: the answer equals the inline path and the event is still delivered`, { skip, timeout: 90_000 }, () => withRecorder(async (ctx) => {
    if (mode === 'timeout') ctx.config.runtimeMs = 9_000; else ctx.config.runtimeMode = 'outage';
    const off = await observe(ctx, preEvent(ctx.project, `toolu_sa9${mode}`), { MARROW_HOOK_BACKGROUND_NUDGE: 'false' });
    const on = await observe(ctx, preEvent(ctx.project, `toolu_sa9${mode}`));
    assert.equal(on.run.stdout, off.run.stdout);
    assert.equal(on.run.code, off.run.code);
    assert.equal(on.pre.filter((r) => r.status === 200).length, 1, 'delivered after the answer');
    assert.deepEqual(normal(on.pre[0].body), normal(off.pre[0].body));
  }));
}

test('SA-10: a held answer keeps its hold, owner link and close; the hold names the delivered event id', { skip, timeout: 90_000 }, () => withRecorder(async (ctx) => {
  ctx.config.runtime = HELD;
  const command = 'git push origin feature-defer';
  const off = await observe(ctx, preEvent(ctx.project, 'toolu_sa10', command), { MARROW_HOOK_BACKGROUND_NUDGE: 'false' });
  const on = await observe(ctx, preEvent(ctx.project, 'toolu_sa10', command));
  assert.equal(on.run.stdout, off.run.stdout);
  assert.equal(on.run.code, off.run.code);
  const others = (o) => o.mine.filter((r) => r.path !== EVENTS_PATH).map((r) => [r.path, normal(r.body)]);
  assert.deepEqual(others(on), others(off), 'the same close, link and runtime calls');
  assert.equal(on.pre.filter((r) => r.status === 200).length, 1);
  const id = on.pre[0].body.event_id;
  const named = JSON.stringify(on.mine.map((r) => r.body)).includes(id) || walk(join(ctx.home, '.marrow')).some((f) => readFileSync(f, 'utf8').includes(id));
  assert.ok(named, 'the hold record or a hold call names the event id');
}));

function walk(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    const st = statSync(full);
    return st.isDirectory() ? walk(full) : st.size < 2_000_000 ? [full] : [];
  });
}

test('SA-11: keyless: no spool, no nudge, the same answer as the inline path', { skip, timeout: 90_000 }, () => withRecorder(async (ctx) => {
  const homeOff = join(ctx.dir, 'home-off');
  mkdirSync(homeOff, { mode: 0o700 });
  const env = { ...ctx.env, MARROW_API_KEY: '' };
  const off = await runHook({ ...env, HOME: homeOff }, preEvent(ctx.project, 'toolu_sa11'), { MARROW_HOOK_BACKGROUND_NUDGE: 'false' });
  const on = await runHook(env, preEvent(ctx.project, 'toolu_sa11'));
  assert.equal(on.stdout, off.stdout);
  assert.equal(on.code, off.code);
  assert.equal(spoolFiles(ctx.home).length, 0);
  assert.equal(locks(ctx.home).length, 0);
  assert.equal(lifecyclePosts(ctx.requests).length, 0);
}));

test('SA-12 SC-3: a reused tool_use_id is a new attempt with its own event id, as the inline path', { skip, timeout: 90_000 }, () => withRecorder(async (ctx) => {
  const ids = async (extra) => {
    const a = await observe(ctx, preEvent(ctx.project, 'toolu_reused'), extra);
    await new Promise((r) => setTimeout(r, 20));
    const b = await observe(ctx, preEvent(ctx.project, 'toolu_reused'), extra);
    return [a.pre[0].body.event_id, b.pre[0].body.event_id];
  };
  const off = await ids({ MARROW_HOOK_BACKGROUND_NUDGE: 'false' });
  const on = await ids({});
  assert.notEqual(on[0], on[1]);
  assert.notEqual(off[0], off[1]);
  const base = (id) => id.replace(/-[0-9a-f]{12}$/, '');
  assert.equal(base(on[0]), base(off[0]));
  assert.equal(base(on[1]), base(on[0]));
}));

test('SA-13: nudge env set from outside gives no second owner and no skipped delivery', { skip, timeout: 90_000 }, () => withRecorder(async (ctx) => {
  const forged = { MARROW_INTERNAL_NUDGE_LOCK: randomBytes(8).toString('hex') };
  const { run, pre } = await observe(ctx, preEvent(ctx.project, 'toolu_sa13'), forged);
  assert.equal(run.code, 0);
  assert.equal(pre.filter((r) => r.status === 200).length, 1);
  assert.equal(locks(ctx.home).length, 0);
  assert.equal(spoolRows(ctx.home).length, 0);
}));

test('SC-4: the dummy key is in no spool file, body, stdout or stderr', { skip, timeout: 90_000 }, () => withRecorder(async (ctx) => {
  ctx.config.lifecycle = (body, count) => (count === 1 ? { status: 503 } : { status: 200 });
  const { run, mine } = await observe(ctx, preEvent(ctx.project, 'toolu_sc4'));
  await new Promise((r) => setTimeout(r, 300));
  const texts = [run.stdout, run.stderr, JSON.stringify(mine.map((r) => [r.body, r.headers])), ...walk(join(ctx.home, '.marrow')).map((f) => readFileSync(f, 'utf8'))];
  assert.equal(texts.filter((t) => t.includes(ctx.key)).length, 0);
}));

test('a custom spool path (not bound to this key and agent) keeps the inline delivery before the answer', { skip, timeout: 90_000 }, () => withRecorder(async (ctx) => {
  ctx.config.lifecycleMs = 200;
  const { run, pre } = await observe(ctx, preEvent(ctx.project, 'toolu_custom'), { MARROW_EVENT_SPOOL_PATH: join(ctx.dir, 'custom-spool.json') });
  assert.equal(pre.length, 1);
  assert.ok(pre[0].end <= run.exitAt, 'posted inline before the hook exits');
  assert.equal(locks(ctx.home).length, 0);
}));

test('a spool write that fails once takes the inline path: the event is posted before the answer, never lost', { skip, timeout: 90_000 }, () => withRecorder(async (ctx) => {
  // Fault double: the first spool-lock open of the pre-action process fails once (a transient spool error).
  const preload = join(ctx.dir, 'spool-fails-once.cjs');
  writeFileSync(preload, [
    "const fs = require('node:fs'); const open = fs.openSync; let failed = false;",
    "fs.openSync = function (p, ...rest) {",
    "  if (!failed && process.argv[2] === 'claude-pre-action-hook' && /mcp-[0-9a-f]+\\.json\\.lock$/.test(String(p))) { failed = true; const e = new Error('transient'); e.code = 'EIO'; throw e; }",
    '  return open.call(this, p, ...rest);',
    '};',
  ].join('\n'));
  const { run, pre } = await observe(ctx, preEvent(ctx.project, 'toolu_transient'), { NODE_OPTIONS: `${ctx.env.NODE_OPTIONS || ''} --require=${preload}`.trim() });
  assert.equal(run.code, 0);
  assert.equal(pre.filter((r) => r.status === 200).length, 1, 'delivered once');
  assert.ok(pre[0].end <= run.exitAt, 'posted inline before the hook exits');
}));

// R6-a (round 2): against a slow lifecycle server the answer comes on the runtime result, never on the lifecycle
// POST, and the pre-action event is in the spool before the answer (so it is still posted after the process exits).
test('R6-a: lifecycle 5 s and runtime 450 ms: the answer within runtime + 300 ms, and the event is still posted', { skip, timeout: 45_000 }, () => withRecorder(async (ctx) => {
  ctx.config.runtimeMs = 450;
  ctx.config.lifecycleMs = 5_000;
  ctx.config.lifecycle = () => { ctx.config.lifecycleMs = 0; return { status: 200 }; };
  const run = await runHook(ctx.env, preEvent(ctx.project, 'toolu_r6a'));
  const runtime = runtimePosts(ctx.requests);
  assert.equal(runtime.length, 1);
  assert.ok(runtime[0].end !== null && run.answerAt - runtime[0].end <= 300,
    `answer ${run.answerAt - run.start} ms, runtime answered at ${runtime[0].end - run.start} ms`);
  assert.equal(run.code, 0);
  assert.ok(await until(() => prePosts(ctx.requests).length >= 1, 8_000), 'the spooled event is posted after the answer');
  await settled(ctx);
  const ids = prePosts(ctx.requests).filter((r) => r.status === 200).map((r) => r.body.event_id);
  assert.ok(ids.length >= 1, 'delivered');
  assert.equal(new Set(ids).size, 1, 'one event id');
}));

// R6-b (round 2): the deferred pre-action payload is byte-equal to the inline (3.9.114) payload for the same event:
// the raw request bytes compared with only the generated time and its payload-bound id digest replaced.
test('R6-b: the deferred pre-action payload is byte-equal to the inline payload for the same event', { skip, timeout: 45_000 }, () => withRecorder(async (ctx) => {
  const generated = (raw) => raw.replace(/"occurred_at":"[^"]+"/g, '"occurred_at":"<t>"').replace(/("event_id":"[^"]+-)[0-9a-f]{12}"/g, '$1<d>"');
  const inline = await observe(ctx, preEvent(ctx.project, 'toolu_r6b', 'node r6b.js'), { MARROW_HOOK_BACKGROUND_NUDGE: 'false' });
  const deferred = await observe(ctx, preEvent(ctx.project, 'toolu_r6b', 'node r6b.js'));
  assert.equal(inline.pre.length, 1);
  assert.equal(deferred.pre.length, 1);
  assert.ok(inline.pre[0].end <= inline.run.exitAt, 'the inline payload was posted before the exit');
  assert.equal(generated(deferred.pre[0].raw), generated(inline.pre[0].raw));
  assert.deepEqual(headerView(deferred.pre[0].headers), headerView(inline.pre[0].headers));
}));
