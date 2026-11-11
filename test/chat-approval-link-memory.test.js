'use strict';

// F2 MCP part, round 2: the once-per-receipt memory of approval-link requests never drops a live receipt, and a
// memory full of live receipts sends no request (the hold is answered as a hold with no link request).
// Two layers: the real dist/cli.js over stdio against a loopback stand-in for the Marrow API (300 receipts, the clock moved
// by a preload, status reads), and one fresh `node` process per scenario that calls the built dist/index.js with a counting
// fetch (10,000 receipts, the state x receipt x clock matrix, races). Every key, token and secret is made at run time.
const assert = require('node:assert/strict');
const test = require('node:test');
const http = require('node:http');
const { spawn, spawnSync } = require('node:child_process');
const { randomBytes } = require('node:crypto');
const { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { writeOfficialHostConfigs } = require('./support/official-host-config.cjs');
const { dummySecret } = require('./support/dummy-secret.cjs');

const ROOT = join(__dirname, '..');
const CLI = join(ROOT, 'dist', 'cli.js');
const INDEX = join(ROOT, 'dist', 'index.js');
const hex = (bytes) => randomBytes(bytes).toString('hex');
const HOLD = 'Deploy the worker to production';
const DAY = 86_400_000;
// Relative to the run, so the expiry is never already past when a receipt is made: EARLY ends within the test clocks' reach, FAR never.
const FAR = new Date(Date.now() + 5 * 365 * DAY).toISOString();
const EARLY = new Date(Date.now() + 2 * DAY).toISOString();
const LIMIT = 256;

// ---------------------------------------------------------------- the loopback stand-in for the Marrow API

function heldRuntime(receipt, action, who, expiresAt) {
  return {
    ok: true, action, decision_id: 'decision-review', agent_id: who.agent, session_id: who.session, fresh_runtime_response: true,
    runtime_authorization: { id: receipt, kind: 'durable_gate_receipt', durable: true, decision_state: 'created', decision_creation_required: false, decision_id: 'decision-review' },
    gate_receipt: { id: receipt, decision: 'review_required', required: true, owner_approval_required: true, ...(expiresAt === undefined ? {} : { expires_at: expiresAt }) },
    proof_pack: { required: true, fields: ['summary', 'checks', 'outcome'], complete: false },
    completion_contract: {
      decision_id: 'decision-review', decision_creation_required: false, decision_state: 'created',
      owner_approval_required: true, arbitration_receipt_required: false, gate_receipt_required: true, must_commit_outcome: true,
      commit_endpoint: '/v1/agent/commit', gate_receipt_id: receipt,
      required_commit_fields: ['decision_id', 'success', 'outcome', 'gate_receipt_id'],
      owner_approval: {
        mode: 'ordinary_non_arbitrated', proof_path: null, proof_shape: null, dashboard_receipt_required: false,
        trusted_completion_receipt_required: true, receipt_field: 'owner_approval_receipt_id',
        approval_endpoint: '/v1/dashboard/enforcement/owner-approval', approval_authority: 'host_operator_or_dashboard_owner',
        approval_status_endpoint: `/v1/agent/gate-receipts/${receipt}/owner-approval`, approval_status_poll_after_ms: 1000,
        host_approval_endpoint: `/v1/agent/gate-receipts/${receipt}/host-approval`, host_approval_accepted: true,
        host_approval_trust: 'client_attested', approval_categories: ['production_deploy'],
        verified_approval_required: false, verified_approval_categories: [],
      },
    },
    risk_gate: { allow: true, decision: 'review_required', enforced: true, gate_required: true, gate_receipt_id: receipt, risk_level: 'high', reasons: [{ message: 'Production deploys need approval.' }] },
    gate_receipt_id: receipt,
    exact_next_action: 'Obtain explicit owner approval before this action runs.',
  };
}

// receiptFor(call, action): the receipt id the call gets; expiresFor(receipt): the receipt's expires_at (undefined = absent);
// statusFor(receipt): the state the status read answers; foreign: ids the link route answers 404; leak: a token and a secret
// the link reply carries in many fields.
async function startDouble(options = {}) {
  const requests = [];
  const identity = { agent: 'agent-one', session: 'mcp-session-1' };
  const leak = options.leak || {};
  let runtimeCalls = 0;
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      let body = null;
      try { body = raw ? JSON.parse(raw) : null; } catch { body = null; }
      const entry = { method: req.method, path: req.url.split('?')[0], body, session: req.headers['x-marrow-session-id'] || null, agent: req.headers['x-marrow-agent-id'] || null };
      requests.push(entry);
      const send = (status, value) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(value)); };
      if (entry.path === '/v1/agent/runtime' && req.method === 'POST') {
        runtimeCalls += 1;
        const action = typeof body?.action === 'string' ? body.action : 'unknown';
        const who = { agent: body?.agent_id || identity.agent, session: body?.session_id || identity.session };
        const receipt = options.receiptFor ? options.receiptFor(runtimeCalls, action) : `gate-m${runtimeCalls}`;
        return send(200, { data: heldRuntime(receipt, action, who, options.expiresFor ? options.expiresFor(receipt) : FAR) });
      }
      const status = entry.path.match(/^\/v1\/agent\/gate-receipts\/([^/]+)\/owner-approval$/);
      if (status && req.method === 'GET') {
        const state = options.statusFor ? options.statusFor(status[1]) : 'pending';
        return send(200, { data: { gate_receipt_id: status[1], decision_id: 'decision-review', state, gate_decision: 'owner_approval_required', owner_approval_receipt_id: null,
          decided_at: null, approval_source: null, approval_trust: null, approval_answered_by: null, expires_at: FAR, terminal: state !== 'pending', retryable: state === 'pending', poll_after_ms: 1000, exact_next_action: state } });
      }
      const link = entry.path.match(/^\/v1\/agent\/gate-receipts\/([^/]+)\/approval-link$/);
      if (link && req.method === 'POST') {
        const id = decodeURIComponent(link[1]);
        if (options.foreign?.includes(id)) return send(404, { error: 'Gate receipt not found.', details: { code: 'MARROW_GATE_RECEIPT_NOT_FOUND' } });
        const view = { id: 'link-1', gate_receipt_id: id, channel: 'email', recipient_hint: 'o***', expires_at: '2030-01-01T00:10:00.000Z', delivered_at: '2030-01-01T00:00:01.000Z' };
        if (leak.token) Object.assign(view, { token: leak.token, link_token: leak.token, url: leak.url });
        return send(200, { data: { sent: true, state: 'sent', reason: 'owner_requested_in_chat', approval_link: view,
          exact_next_action: `Marrow sent a one-tap approval link to the account owner. ${leak.url || ''} ${leak.secret || ''}`.trim(), ...(leak.token ? { token: leak.token } : {}) } });
      }
      if (entry.path === '/v1/agent/commit') return send(200, { data: { committed: true } });
      return send(200, { data: { accepted: true } });
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: server.address().port, identity, requests,
    links: () => requests.filter((entry) => /\/approval-link$/.test(entry.path)),
    linksFor: (id) => requests.filter((entry) => entry.path === `/v1/agent/gate-receipts/${id}/approval-link`),
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

// The MCP requires an https base URL: this preload sends one placeholder origin to the loopback stand-in, and moves the
// MCP's own clock by the number of milliseconds the test writes to the clock file (positive or negative).
const PRELOAD_SOURCE = `'use strict';
const fs = require('node:fs');
const port = process.env.MARROW_TEST_LOOPBACK_PORT;
const clockFile = process.env.MARROW_TEST_CLOCK_FILE;
const realFetch = globalThis.fetch;
globalThis.fetch = (url, init) => {
  const text = typeof url === 'string' ? url : url instanceof URL ? url.href : url && url.url;
  if (typeof text === 'string' && text.startsWith('https://api.example.test')) return realFetch('http://127.0.0.1:' + port + text.slice('https://api.example.test'.length), init);
  return realFetch(url, init);
};
const realNow = Date.now.bind(Date);
Date.now = () => {
  let offset = 0;
  try { offset = Number(fs.readFileSync(clockFile, 'utf8')) || 0; } catch { offset = 0; }
  return realNow() + offset;
};
`;

async function startMcp(double, options = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-chat-memory-'));
  const home = join(dir, 'home');
  mkdirSync(home, { mode: 0o700 });
  writeOfficialHostConfigs(home);
  const preload = join(dir, 'preload.cjs');
  const clockFile = join(dir, 'clock-ms');
  writeFileSync(preload, PRELOAD_SOURCE);
  const child = spawn(process.execPath, [CLI], {
    env: {
      PATH: process.env.PATH, HOME: home, MARROW_API_KEY: `mrw_test_${hex(16)}`, MARROW_BASE_URL: 'https://api.example.test',
      MARROW_AGENT_ID: double.identity.agent, MARROW_TOOL_PROFILE: 'core', MARROW_SESSION_ID: double.identity.session,
      MARROW_HOOK_BACKGROUND_NUDGE: 'false', MARROW_PASSIVE_TOKEN_USAGE: 'false', MARROW_AUTO_ENROLL: 'false',
      MARROW_TEST_LOOPBACK_PORT: String(double.port), MARROW_TEST_CLOCK_FILE: clockFile, NODE_OPTIONS: `--require=${preload}`,
      NODE_DISABLE_COMPILE_CACHE: '1', TMPDIR: tmpdir(),
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const waiting = new Map();
  const transcript = [];
  let stderr = '';
  let buffer = '';
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  child.stdout.on('data', (chunk) => {
    buffer += chunk;
    let index;
    while ((index = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, index).trim();
      buffer = buffer.slice(index + 1);
      if (!line) continue;
      transcript.push(line);
      const message = JSON.parse(line);
      if (message.method === 'elicitation/create') child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: message.id, result: { action: 'cancel' } })}\n`);
      else if (message.id !== undefined && waiting.has(message.id)) waiting.get(message.id)(message);
    }
  });
  let seq = 0;
  const rpc = (method, params) => new Promise((resolve) => { seq += 1; waiting.set(seq, resolve); child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: seq, method, params })}\n`); });
  await rpc('initialize', {
    protocolVersion: options.capability ? '2025-06-18' : '2024-11-05',
    capabilities: options.capability ? { elicitation: {} } : {},
    clientInfo: { name: 'claude-code', version: '2.1.289' },
  });
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
  return {
    setClock: (ms) => writeFileSync(clockFile, String(ms)),
    call: async (name, args) => {
      const reply = await rpc('tools/call', { name, arguments: args });
      const text = reply.result?.content?.[0]?.text ?? '';
      let json = null;
      try { json = JSON.parse(text); } catch { json = null; }
      return { reply, text, json };
    },
    output: () => `${transcript.join('\n')}\n${stderr}`,
    close: async () => {
      child.stdin.end();
      await new Promise((resolve) => { child.on('close', resolve); setTimeout(() => { child.kill(); resolve(); }, 5_000).unref(); });
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

async function scenario(options, mcpOptions, body) {
  const double = await startDouble(options);
  const mcp = await startMcp(double, mcpOptions);
  try { return await body(double, mcp); } finally { await mcp.close(); await double.close(); }
}

const runtimeCall = (mcp, extra = {}, action = HOLD) => mcp.call('marrow_agent_runtime', { action, type: 'deploy', ...extra });
const autoCall = (mcp, extra = {}, action = HOLD) => mcp.call('marrow_auto', { action, type: 'deploy', operation_id: `op_${hex(6)}`, ...extra });
const maskReceipt = (value, ...ids) => ids.reduce((text, id) => text.split(id).join('<receipt>'), typeof value === 'string' ? value : JSON.stringify(value));
// The parts of a tool reply that carry the answer; times, durations and traces differ between any two calls.
const answerOf = (json, ...ids) => maskReceipt({
  keys: Object.keys(json).sort(), next: json.exact_next_action, phase: json.phase, retry: json.retry_after_ms, committed: json.committed,
  request: json.owner_approval_request ?? null, receipt: json.gate_receipt?.decision ?? null,
}, ...ids);

// Fills the memory with 256 live receipts (gate-m1 .. gate-m256), one call at a time, as a person at the session.
async function fill(mcp, count = LIMIT) {
  for (let call = 1; call <= count; call += 1) await runtimeCall(mcp, {}, `${HOLD} ${call}`);
}

// ---------------------------------------------------------------- the built MCP over stdio: PP2 rows (1)-(6)

test('PP2 (1): 300 distinct receipts, then a repeat on receipt 1: receipt 1 was asked once and is never asked again', async () => {
  await scenario({ receiptFor: (call) => (call === 301 ? 'gate-m1' : `gate-m${call}`) }, { capability: true }, async (double, mcp) => {
    for (let call = 1; call <= 301; call += 1) await runtimeCall(mcp, {}, `${HOLD} ${call}`);
    assert.equal(double.linksFor('gate-m1').length, 1, 'first_receipt_posts');
    assert.equal(double.links().length, LIMIT, 'one request each for the first 256 receipts, none for the rest');
    for (let call = 1; call <= LIMIT; call += 1) assert.equal(double.linksFor(`gate-m${call}`).length, 1, `gate-m${call}`);
    for (let call = LIMIT + 1; call <= 300; call += 1) assert.equal(double.linksFor(`gate-m${call}`).length, 0, `gate-m${call} asked nobody`);
  });
});

test('PP2 (2), (3): a memory full of live receipts sends nothing for a new one, still held; an expiry frees exactly one slot; a clock that goes back frees none', async () => {
  const expiresFor = (receipt) => (receipt === 'gate-m5' ? EARLY : FAR);
  await scenario({ expiresFor }, { capability: true }, async (double, mcp) => {
    await fill(mcp);
    assert.equal(double.links().length, LIMIT);
    const fullRuntime = await runtimeCall(mcp, {}, `${HOLD} 257`);
    const fullAuto = await autoCall(mcp, { request_owner_link: true }, `${HOLD} 258`);
    const again = await runtimeCall(mcp, {}, `${HOLD} 259`);
    assert.equal(double.links().length, LIMIT, 'a new receipt on a full memory of live receipts sends no request');
    for (const held of [fullRuntime, again]) {
      assert.equal(held.json.gate_receipt.decision, 'review_required', 'still held');
      assert.equal(held.json.owner_approval_request, undefined, 'no claim of a send');
    }
    assert.equal(fullAuto.json.phase, 'owner_approval_required');
    assert.equal(fullAuto.json.live_delivery.committed, false);
    assert.doesNotMatch(fullAuto.json.exact_next_action, /one-tap approval/, 'the hold says nothing was sent, not that a link went out');
    // A clock that goes back never ends a receipt early.
    mcp.setClock(-3650 * DAY);
    await runtimeCall(mcp, {}, `${HOLD} 260`);
    assert.equal(double.links().length, LIMIT, 'a clock ten years back: the early receipt is still live');
    // The early receipt ends; its slot goes to the next new receipt and to nobody else.
    mcp.setClock(400 * DAY);
    const first = await runtimeCall(mcp, {}, `${HOLD} 261`);
    assert.equal(double.links().length, LIMIT + 1, 'exactly one request after an expiry');
    assert.match(first.json.owner_approval_request.message, /^Marrow sent a one-tap approval to your email\./);
    await runtimeCall(mcp, {}, `${HOLD} 262`);
    await runtimeCall(mcp, {}, `${HOLD} 263`);
    assert.equal(double.links().length, LIMIT + 1, 'one slot freed, one request');
    // The receipt that had its slot taken is still remembered: a repeat on it sends nothing.
    await runtimeCall(mcp, {}, `${HOLD} 261 again`);
    assert.equal(double.links().length, LIMIT + 1);
  });
});

test('F-FULL: the answer of a hold on a full memory is the answer of a hold with no link request, on both tools', async () => {
  const full = await scenario({}, { capability: true }, async (double, mcp) => {
    await fill(mcp);
    const runtime = await runtimeCall(mcp, {}, `${HOLD} 257`);
    const auto = await autoCall(mcp, { request_owner_link: true }, `${HOLD} 258`);
    assert.equal(double.links().length, LIMIT);
    return { runtime: answerOf(runtime.json, 'gate-m257'), auto: answerOf(auto.json, 'gate-m258') };
  });
  const none = await scenario({ receiptFor: (call) => `gate-m${256 + call}` }, {}, async (double, mcp) => {
    const runtime = await runtimeCall(mcp, {}, `${HOLD} 257`);
    const auto = await autoCall(mcp, {}, `${HOLD} 258`);
    assert.equal(double.links().length, 0, 'no person: no request');
    return { runtime: answerOf(runtime.json, 'gate-m257'), auto: answerOf(auto.json, 'gate-m258') };
  });
  assert.equal(full.runtime, none.runtime);
  assert.equal(full.auto, none.auto);
  assert.match(JSON.parse(full.auto).next, /Nobody can approve it from this tool call, so it waits quietly; nothing was sent to anyone\./);
});

test('F-LIVE: a status read that saw a receipt decided frees its slot; a pending read frees none', async () => {
  const statusFor = (receipt) => (receipt === 'gate-m7' ? 'declined' : 'pending');
  await scenario({ receiptFor: (call) => ({ 257: 'gate-m3', 258: 'gate-m500', 259: 'gate-m7', 260: 'gate-m501', 261: 'gate-m502' })[call] ?? `gate-m${call}`, statusFor }, { capability: true }, async (double, mcp) => {
    await fill(mcp);
    // A poll on a receipt that is still pending (gate-m3): nothing is freed.
    await autoCall(mcp, {}, `${HOLD} poll pending`);
    await runtimeCall(mcp, {}, `${HOLD} new one`);
    assert.equal(double.links().length, LIMIT);
    // The owner's decline of gate-m7 is read in this process: its slot is free for one new receipt.
    const declined = await autoCall(mcp, {}, `${HOLD} poll declined`);
    assert.match(declined.json.exact_next_action, /declined/i);
    await runtimeCall(mcp, {}, `${HOLD} new two`);
    assert.equal(double.links().length, LIMIT + 1, 'one request');
    await runtimeCall(mcp, {}, `${HOLD} new three`);
    assert.equal(double.links().length, LIMIT + 1);
  });
});

test('PP2 (4): the same receipt in another session or agent sends nothing; a foreign receipt is refused by the service and asked once; on a full memory it is not asked', async () => {
  await scenario({ receiptFor: (call) => (call === 2 ? 'gate-m1' : call === 3 ? 'gate-foreign' : call === 4 ? 'gate-foreign' : `gate-m${call}`), foreign: ['gate-foreign'] }, { capability: true }, async (double, mcp) => {
    await runtimeCall(mcp);
    const other = await runtimeCall(mcp, { sessionId: 'another-session', agentId: 'another-agent' });
    assert.equal(double.linksFor('gate-m1').length, 1, 'the receipt is asked once whatever session or agent names it');
    assert.match(other.json.owner_approval_request.message, /^Marrow already sent a one-tap approval/);
    const foreign = await runtimeCall(mcp);
    assert.equal(double.linksFor('gate-foreign').length, 1);
    assert.equal(foreign.json.owner_approval_request.state, 'not_sent');
    assert.match(foreign.json.owner_approval_request.message, /^Nothing was sent to the account owner, so this hold waits for them/);
    await runtimeCall(mcp);
    assert.equal(double.linksFor('gate-foreign').length, 1, 'refused once, not retried');
  });
  await scenario({ receiptFor: (call) => (call === 257 || call === 258 ? 'gate-foreign' : `gate-m${call}`), foreign: ['gate-foreign'] }, { capability: true }, async (double, mcp) => {
    await fill(mcp);
    await runtimeCall(mcp, { sessionId: 'another-session', agentId: 'another-agent' });
    await runtimeCall(mcp);
    assert.equal(double.linksFor('gate-foreign').length, 0, 'a full memory sends nothing, not even for a receipt the service would refuse');
    assert.equal(double.links().length, LIMIT);
  });
});

test('PP2 (5), (6): no token, link or secret in any text the agent reads, in the logs or in a request; receipts that differ only in a suffix are separate entries', async () => {
  const leak = { token: hex(22).slice(0, 43), url: `https://approve.example.test/a#t=${hex(22).slice(0, 43)}`, secret: dummySecret(16) };
  const secretAction = `curl -H "Authorization: Bearer ${leak.secret}" https://example.test/deploy production`;
  const ids = ['gate-aaaa0001', 'gate-aaaa0002', 'gate-aaaa0001', 'gate-aaaa000I', 'gate-aaaa0001.', 'gate-aaaa0001-x'];
  await scenario({ leak, receiptFor: (call) => ids[call - 1] ?? `gate-m${call}` }, { capability: true }, async (double, mcp) => {
    const replies = [];
    for (let index = 0; index < ids.length; index += 1) replies.push(await runtimeCall(mcp, { context: { note: leak.secret } }, index === 0 ? secretAction : `${HOLD} ${index}`));
    assert.deepEqual(double.links().map((entry) => entry.path.split('/')[4]), ['gate-aaaa0001', 'gate-aaaa0002', 'gate-aaaa000I', 'gate-aaaa0001.', 'gate-aaaa0001-x'], 'separate entries; the repeat sends nothing');
    for (let call = ids.length + 1; call <= 300; call += 1) await runtimeCall(mcp, {}, `${HOLD} ${call}`);
    assert.equal(double.links().length, LIMIT);
    const everything = `${mcp.output()}\n${replies.map((reply) => reply.text).join('\n')}\n${JSON.stringify(double.links())}`;
    for (const value of [leak.token, leak.url, leak.secret]) assert.equal(everything.includes(value), false, 'a token, link or secret reached agent-readable text, a log or a request');
  });
});

// ---------------------------------------------------------------- the built dist/index.js in a fresh process per scenario

const CHILD_SOURCE = `'use strict';
const fs = require('node:fs');
const spec = JSON.parse(fs.readFileSync(0, 'utf8'));
const posts = Object.create(null);
const states = Object.create(null);
let clock = 0;
const realNow = Date.now.bind(Date);
Date.now = () => realNow() + clock;
const json = (status, value) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
globalThis.fetch = async (url, init) => {
  const link = String(url).match(/\\/gate-receipts\\/([^/]+)\\/approval-link$/);
  const status = String(url).match(/\\/gate-receipts\\/([^/]+)\\/owner-approval$/);
  if (link) {
    const id = decodeURIComponent(link[1]);
    posts[id] = (posts[id] || 0) + 1;
    if ((spec.foreign || []).includes(id)) return json(404, { error: 'Gate receipt not found.' });
    return json(200, { data: { sent: true, state: 'sent', reason: 'owner_requested_in_chat', approval_link: { id: 'link-1', gate_receipt_id: id, channel: 'email', recipient_hint: 'o***', expires_at: '2030-01-01T00:10:00.000Z', delivered_at: '2030-01-01T00:00:01.000Z' }, exact_next_action: 'sent' } });
  }
  if (status) {
    const id = decodeURIComponent(status[1]);
    return json(200, { data: { gate_receipt_id: spec.statusReplyFor && spec.statusReplyFor[id] ? spec.statusReplyFor[id] : id, state: states[id] || 'pending', terminal: false, retryable: true, poll_after_ms: 1000, exact_next_action: 'x' } });
  }
  return json(404, {});
};
(async () => {
  const mcp = require(spec.dist);
  const base = { apiKey: 'mrw_test_' + require('node:crypto').randomBytes(8).toString('hex'), baseUrl: 'https://api.example.test', sessionId: 'session-a', agentId: 'agent-a', timeoutMs: 2000 };
  const out = { results: [], counts: { request: 0, repeat: 0, none: 0 } };
  const ask = async (id, exp, extra) => {
    const when = exp && typeof exp === 'object' && typeof exp.in === 'number' ? new Date(Date.now() + exp.in).toISOString() : exp;
    const got = await mcp.requestChatOwnerLink({ ...base, ...(extra || {}), gateReceiptId: id, receiptExpiresAt: when });
    const kind = got === null ? 'none' : got.repeat ? 'repeat' : 'request';
    out.counts[kind] += 1;
    return kind;
  };
  for (const step of spec.steps) {
    if (step.op === 'ask') out.results.push(await ask(step.id, step.exp, step.extra));
    else if (step.op === 'fill') for (let i = 1; i <= step.n; i += 1) await ask(step.prefix + i, step.exp);
    else if (step.op === 'burst') out.results.push((await Promise.all(Array.from({ length: step.n }, (_, i) => ask(step.same ? step.prefix : step.prefix + i, step.exp)))).join(','));
    else if (step.op === 'clock') clock = step.ms;
    else if (step.op === 'status') { states[step.id] = step.state; try { await mcp.marrowOwnerApprovalStatus(base.apiKey, base.baseUrl, step.id, 'session-a', 'agent-a'); out.results.push('read'); } catch { out.results.push('threw'); } }
  }
  out.posts = posts;
  out.total = Object.values(posts).reduce((sum, n) => sum + n, 0);
  process.stdout.write(JSON.stringify(out));
})().catch((error) => { process.stderr.write(String(error && error.stack || error)); process.exit(1); });
`;

function runChild(spec) {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-chat-child-'));
  try {
    const script = join(dir, 'child.cjs');
    writeFileSync(script, CHILD_SOURCE);
    const done = spawnSync(process.execPath, [script], {
      input: JSON.stringify({ dist: INDEX, ...spec }), encoding: 'utf8', maxBuffer: 32 * 1024 * 1024, timeout: 120_000,
      env: { PATH: process.env.PATH, HOME: dir, NODE_DISABLE_COMPILE_CACHE: '1', TMPDIR: tmpdir() },
    });
    assert.equal(done.status, 0, done.stderr);
    return JSON.parse(done.stdout);
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

const live = (n, exp = FAR) => ({ op: 'fill', n, prefix: 'rc-', exp });

test('F-BOUND: 10,000 distinct receipts never put more than 256 in the memory: 256 requests, then none; the first receipt is never asked twice', () => {
  const out = runChild({ steps: [live(10_000), { op: 'ask', id: 'rc-1', exp: FAR }, { op: 'ask', id: 'rc-10000', exp: FAR }, { op: 'ask', id: 'rc-256', exp: FAR }, { op: 'ask', id: 'rc-257', exp: FAR }] });
  assert.equal(out.total, LIMIT, 'requests sent');
  assert.equal(out.counts.request, LIMIT);
  assert.equal(out.counts.none, 10_000 - LIMIT + 2, 'every receipt past the bound sends nothing');
  assert.deepEqual(out.results, ['repeat', 'none', 'repeat', 'none']);
  assert.equal(out.posts['rc-1'], 1);
});

test('F-BOUND: 300 callers at once on 300 distinct receipts send 256; 5 at once on one receipt send 1', () => {
  const out = runChild({ steps: [{ op: 'burst', n: 300, prefix: 'bb-', exp: FAR }, { op: 'burst', n: 5, prefix: 'same', same: true, exp: FAR }] });
  assert.equal(out.counts.request, LIMIT);
  assert.equal(out.posts.same, undefined, 'the memory is already full of live receipts');
  const alone = runChild({ steps: [{ op: 'burst', n: 5, prefix: 'same', same: true, exp: FAR }] });
  assert.equal(alone.posts.same, 1);
  assert.equal(alone.results[0].split(',').filter((kind) => kind === 'request').length, 1);
});

// memory x receipt x clock. The memory holds 256 receipts r1..r256 (r1 is `special`); `ask` is the final call.
const MATRIX = [
  // name, steps before the final ask, final ask, expected kind, expected requests in total
  ['empty memory, new receipt', [], 'rc-n1', 'request', 1],
  ['partly full (10), new receipt', [live(10)], 'rc-n1', 'request', 11],
  ['partly full (10), repeat', [live(10)], 'rc-3', 'repeat', 10],
  ['full of live, new receipt', [live(LIMIT)], 'rc-n1', 'none', LIMIT],
  ['full of live, repeat of the oldest', [live(LIMIT)], 'rc-1', 'repeat', LIMIT],
  ['full of live, repeat of the newest', [live(LIMIT)], 'rc-256', 'repeat', LIMIT],
  ['full of live, new receipt that the service refuses', [live(LIMIT)], 'rc-n1', 'none', LIMIT, { foreign: ['rc-n1'] }],
  ['one expired (x), clock normal, new receipt', [{ op: 'ask', id: 'rc-x', exp: EARLY }, live(LIMIT - 1)], 'rc-n1', 'none', LIMIT],
  ['one expired (x), clock past its end, new receipt', [{ op: 'ask', id: 'rc-x', exp: EARLY }, live(LIMIT - 1), { op: 'clock', ms: 400 * DAY }], 'rc-n1', 'request', LIMIT + 1],
  ['one expired (x), clock past its end, repeat of a live one', [{ op: 'ask', id: 'rc-x', exp: EARLY }, live(LIMIT - 1), { op: 'clock', ms: 400 * DAY }], 'rc-1', 'repeat', LIMIT],
  ['one expired (x), clock past its end, repeat of the expired one (its slot is kept until needed)', [{ op: 'ask', id: 'rc-x', exp: EARLY }, live(LIMIT - 1), { op: 'clock', ms: 400 * DAY }], 'rc-x', 'repeat', LIMIT],
  ['one expired (x), clock ten years back, new receipt', [{ op: 'ask', id: 'rc-x', exp: EARLY }, live(LIMIT - 1), { op: 'clock', ms: -3650 * DAY }], 'rc-n1', 'none', LIMIT],
  ['every receipt expired, new receipt', [live(LIMIT, EARLY), { op: 'clock', ms: 400 * DAY }], 'rc-n1', 'request', LIMIT + 1],
  ['one decided (used), new receipt', [live(LIMIT), { op: 'status', id: 'rc-9', state: 'used' }], 'rc-n1', 'request', LIMIT + 1],
  ['one decided (approved), new receipt', [live(LIMIT), { op: 'status', id: 'rc-9', state: 'approved' }], 'rc-n1', 'request', LIMIT + 1],
  ['one decided (declined), new receipt', [live(LIMIT), { op: 'status', id: 'rc-9', state: 'declined' }], 'rc-n1', 'request', LIMIT + 1],
  ['one decided (expired), new receipt', [live(LIMIT), { op: 'status', id: 'rc-9', state: 'expired' }], 'rc-n1', 'request', LIMIT + 1],
  ['one pending read, new receipt', [live(LIMIT), { op: 'status', id: 'rc-9', state: 'pending' }], 'rc-n1', 'none', LIMIT],
  ['unavailable, not_held, arbitration_review and unknown reads end nothing', [live(LIMIT), ...['unavailable', 'not_held', 'arbitration_review', 'approved-ish', 'USED', ''].map((state) => ({ op: 'status', id: 'rc-9', state }))], 'rc-n1', 'none', LIMIT],
  ['a decided read of a receipt that was never asked ends nothing', [live(LIMIT), { op: 'status', id: 'never-asked', state: 'used' }], 'rc-n1', 'none', LIMIT],
  ['a status reply that names another receipt ends nothing', [live(LIMIT), { op: 'status', id: 'rc-9', state: 'used' }], 'rc-n1', 'none', LIMIT],
];

for (const [name, steps, id, kind, total, extra] of MATRIX) {
  test(`matrix: ${name}`, () => {
    const spec = { steps: [...steps.flat(), { op: 'ask', id, exp: FAR }], ...(extra || {}) };
    if (name.startsWith('a status reply that names another receipt')) spec.statusReplyFor = { 'rc-9': 'someone-else' };
    const out = runChild(spec);
    assert.equal(out.results[out.results.length - 1], kind, JSON.stringify(out.counts));
    assert.equal(out.total, total);
  });
}

test('F-LIVE: a missing, empty or unreadable expiry is live: a full memory of them never frees a slot, even with the clock moved a century ahead', () => {
  for (const exp of [undefined, null, '', 'not-a-time', 'NaN', '  ', '2030-13-45T99:99:99Z', 12345, {}]) {
    const out = runChild({ steps: [{ op: 'fill', n: LIMIT, prefix: 'rc-', exp }, { op: 'clock', ms: 36_500 * DAY }, { op: 'ask', id: 'rc-n1', exp: FAR }, { op: 'ask', id: 'rc-1', exp }] });
    assert.deepEqual(out.results, ['none', 'repeat'], `expiry ${JSON.stringify(exp)}`);
    assert.equal(out.total, LIMIT);
  }
});

test('F-LIVE: after the clock passes their end, 256 in-flight-then-expired receipts free one slot per new receipt', () => {
  const out = runChild({ steps: [{ op: 'burst', n: LIMIT, prefix: 'ff-', exp: EARLY }, { op: 'clock', ms: 400 * DAY }, { op: 'burst', n: 3, prefix: 'gg-', exp: FAR }] });
  assert.equal(out.posts['gg-0'], 1, 'the first new receipt takes a freed slot');
  assert.equal(out.counts.request, LIMIT + 3, 'every receipt of the second burst finds a slot: 256 of the first burst ended');
});

// ---------------------------------------------------------------- the memory's key and writers, read from the source

test('F-BOUND, key: every write to the memory is keyed by the receipt id and goes through the one function that never evicts a live entry', () => {
  const source = readFileSync(join(ROOT, 'src', 'index.ts'), 'utf8');
  const writes = source.split('\n').filter((line) => /chatLinkAsked\.set\(/.test(line));
  assert.equal(writes.length, 1, 'one writer');
  assert.match(writes[0], /chatLinkAsked\.set\(gateReceiptId, /);
  assert.equal(source.split('\n').filter((line) => /chatLinkAsked\.delete\(/.test(line)).length, 1, 'one place drops an entry');
  assert.match(source, /const CHAT_LINK_MEMORY_LIMIT = 256;/);
});

// ---------------------------------------------------------------- the adversarial pass (reports/adversarial.md names each)

const MIN = 60_000;

test('ADV time: receipts that last as long as the service makes them (30 minutes) are kept at 29 minutes and freed at 31', () => {
  const kept = runChild({ steps: [{ op: 'fill', n: LIMIT, prefix: 'rc-', exp: { in: 30 * MIN } }, { op: 'clock', ms: 29 * MIN }, { op: 'ask', id: 'rc-n1', exp: FAR }] });
  assert.deepEqual(kept.results, ['none']);
  assert.equal(kept.total, LIMIT);
  const freed = runChild({ steps: [{ op: 'fill', n: LIMIT, prefix: 'rc-', exp: { in: 30 * MIN } }, { op: 'clock', ms: 31 * MIN }, { op: 'ask', id: 'rc-n1', exp: FAR }] });
  assert.deepEqual(freed.results, ['request']);
  assert.equal(freed.total, LIMIT + 1);
});

test('ADV race at the expiry edge: 300 callers at once after 256 receipts ended get 256 requests and 44 refusals, and no receipt is asked twice', () => {
  const out = runChild({ steps: [{ op: 'burst', n: LIMIT, prefix: 'ff-', exp: { in: 30 * MIN } }, { op: 'clock', ms: 31 * MIN }, { op: 'burst', n: 300, prefix: 'gg-', exp: { in: 30 * MIN } }] });
  assert.equal(out.counts.request, LIMIT * 2);
  assert.equal(out.counts.none, 300 - LIMIT);
  assert.equal(Math.max(...Object.values(out.posts)), 1, 'no receipt asked twice');
});

test('ADV many sessions: 50 sessions and agents asking about one receipt send one request', () => {
  const steps = Array.from({ length: 50 }, (_, i) => ({ op: 'ask', id: 'rc-shared', exp: FAR, extra: { sessionId: `session-${i}`, agentId: `agent-${i}` } }));
  const out = runChild({ steps });
  assert.equal(out.posts['rc-shared'], 1);
  assert.equal(out.counts.repeat, 49);
});

test('ADV a full memory: no spelling of a new receipt, and no expiry given to the new receipt, makes it send', () => {
  const ids = ['RC-1', 'rc-1.', 'rc-1 ', ' rc-1', 'rc-1\u0000', 'rc\u20111', 'rc-01', 'rc-1:', 'rc-n1', '__proto__', 'constructor', 'toString', `rc-1${'x'.repeat(300)}`];
  const steps = [live(LIMIT), ...ids.map((id) => ({ op: 'ask', id, exp: { in: -DAY } })), { op: 'ask', id: 'rc-n2', exp: '0' }, { op: 'ask', id: 'rc-n3' }];
  const out = runChild({ steps });
  assert.deepEqual(out.results, Array(ids.length + 2).fill('none'));
  assert.equal(out.total, LIMIT);
});

test('ADV an expiry made from text: text that Date.parse reads as a past date is not an expiry; only a full ISO instant is', () => {
  for (const exp of ['0', '1', '12', '2000', '1970', 'Jan 1 2000', '2000-01-01', '2000-01-01 00:00:00', '2000-01-01T00:00:00', '  2000-01-01T00:00:00Z', '2000-01-01T00:00:00Z ', 0, [], [2000]]) {
    const out = runChild({ steps: [{ op: 'fill', n: LIMIT, prefix: 'rc-', exp }, { op: 'ask', id: 'rc-n1', exp: FAR }] });
    assert.deepEqual(out.results, ['none'], `expiry ${JSON.stringify(exp)} is not an end`);
    assert.equal(out.total, LIMIT);
  }
  for (const exp of ['2000-01-01T00:00:00Z', '2000-01-01T00:00:00.000Z', '2000-01-01T01:00:00+01:00', '2000-01-01T00:00:00.123456Z']) {
    const out = runChild({ steps: [{ op: 'fill', n: LIMIT, prefix: 'rc-', exp }, { op: 'ask', id: 'rc-n1', exp: FAR }] });
    assert.deepEqual(out.results, ['request'], `expiry ${exp} is an end`);
  }
});

test('ADV a clock that jumps forward: a receipt it ended can lose its slot and be asked again once; the receipt is asked twice at most because the process clock passed its own expires_at', () => {
  const out = runChild({ steps: [{ op: 'fill', n: LIMIT, prefix: 'rc-', exp: { in: 30 * MIN } }, { op: 'clock', ms: 31 * MIN }, { op: 'ask', id: 'rc-new', exp: { in: 30 * MIN } }, { op: 'ask', id: 'rc-1', exp: { in: 30 * MIN } }, { op: 'ask', id: 'rc-1', exp: { in: 30 * MIN } }] });
  assert.deepEqual(out.results, ['request', 'request', 'repeat']);
  assert.equal(out.posts['rc-1'], 2);
});

test('ADV key: ids that are names on Object.prototype are plain keys', () => {
  const out = runChild({ steps: ['__proto__', 'constructor', 'toString', 'hasOwnProperty', '__proto__'].map((id) => ({ op: 'ask', id, exp: FAR })) });
  assert.deepEqual(out.results, ['request', 'request', 'request', 'request', 'repeat']);
});

test('ADV an expiry made from text, through the real tool: a reply whose expires_at the runtime reader would turn into a past date ends nothing', async () => {
  for (const text of ['0', 'Jan 1 2000']) {
    await scenario({ expiresFor: () => text }, { capability: true }, async (double, mcp) => {
      await fill(mcp);
      assert.equal(double.links().length, LIMIT);
      const held = await runtimeCall(mcp, {}, `${HOLD} 257`);
      assert.equal(double.links().length, LIMIT, `expires_at ${JSON.stringify(text)}: no slot freed, no request`);
      assert.equal(held.json.gate_receipt.decision, 'review_required', 'still held');
      assert.equal(held.json.owner_approval_request, undefined);
    });
  }
});
