'use strict';

// F2 MCP part: when a person is at the session, the MCP asks Marrow once per held receipt to send the owner its
// one-tap approval link, and tells the person the channel, never a token. The MCP never records a verdict.
// The real dist/cli.js runs over stdio against a loopback stand-in for the Marrow API (below). The stand-in answers
// the approval-link route the way the service does: sent / not_sent / already_sent, approval_link {id, gate_receipt_id,
// channel, recipient_hint, expires_at, delivered_at}, no token. Every key, token and secret here is made at run time.
const assert = require('node:assert/strict');
const test = require('node:test');
const http = require('node:http');
const { spawn } = require('node:child_process');
const { randomBytes } = require('node:crypto');
const { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { writeOfficialHostConfigs } = require('./support/official-host-config.cjs');
const { dummySecret } = require('./support/dummy-secret.cjs');

const ROOT = join(__dirname, '..');
const CLI = join(ROOT, 'dist', 'cli.js');
const hex = (bytes) => randomBytes(bytes).toString('hex');
const LINK_PATH = /^\/v1\/agent\/gate-receipts\/[A-Za-z0-9._:-]{1,200}\/approval-link$/;
const SENT_TEXT = /^Marrow sent a one-tap approval to your (email|telegram|slack)\. Nothing runs until you tap it\./;
const HOLD = 'Deploy the worker to production';

// ---------------------------------------------------------------- the loopback stand-in for the Marrow API

function heldRuntime(receipt, action, who, approval = {}) {
  return {
    ok: true, action, decision_id: 'decision-review', agent_id: who.agent, session_id: who.session, fresh_runtime_response: true,
    runtime_authorization: { id: receipt, kind: 'durable_gate_receipt', durable: true, decision_state: 'created', decision_creation_required: false, decision_id: 'decision-review' },
    gate_receipt: { id: receipt, decision: 'review_required', required: true, owner_approval_required: true, expires_at: '2030-01-01T00:30:00.000Z' },
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
        ...approval,
      },
    },
    risk_gate: { allow: true, decision: 'review_required', enforced: true, gate_required: true, gate_receipt_id: receipt, risk_level: 'high', reasons: [{ message: 'Production deploys need approval.' }] },
    gate_receipt_id: receipt,
    exact_next_action: 'Obtain explicit owner approval before this action runs.',
  };
}

function allowRuntime(receipt, action, who) {
  return {
    ok: true, action, decision_id: 'decision-low', agent_id: who.agent, session_id: who.session, fresh_runtime_response: true,
    runtime_authorization: { id: receipt, kind: 'durable_gate_receipt', durable: true, decision_state: 'created', decision_creation_required: false, decision_id: 'decision-low' },
    gate_receipt: { id: receipt, decision: 'allow', required: false, owner_approval_required: false, expires_at: '2030-01-01T00:30:00.000Z' },
    proof_pack: { required: false, fields: [], complete: true },
    completion_contract: {
      decision_id: 'decision-low', decision_creation_required: false, decision_state: 'created', owner_approval_required: false,
      arbitration_receipt_required: false, gate_receipt_required: true, must_commit_outcome: true, commit_endpoint: '/v1/agent/commit',
      gate_receipt_id: receipt, required_commit_fields: ['decision_id', 'success', 'outcome', 'gate_receipt_id'],
    },
    risk_gate: { allow: true, decision: 'allow', enforced: true, gate_required: true, gate_receipt_id: receipt, risk_level: 'low', reasons: [] },
    gate_receipt_id: receipt,
    exact_next_action: 'Proceed.',
  };
}

// mode: 'f2' a person_present request sends, anything else is quiet; 'old' the live service before the fix (an unlocked
// hold is always not_sent); 'refuse-field' 400 on person_present; 'error' a 500 carrying the secret; 'sent-leaky' and
// 'not-sent-leaky' replies that carry a token, a URL and a secret. receipts: 'unique' (default) or 'same'.
async function startDouble(options = {}) {
  const mode = options.mode || 'f2';
  const requests = [];
  const perReceipt = new Map();
  const identity = { agent: 'agent-one', session: 'mcp-session-1' };
  const leak = options.leak || {};
  let runtimeCalls = 0;
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      let body = null;
      try { body = raw ? JSON.parse(raw) : null; } catch { body = null; }
      const entry = {
        method: req.method, path: req.url.split('?')[0], body,
        session: req.headers['x-marrow-session-id'] || null, agent: req.headers['x-marrow-agent-id'] || null,
        authorized: Boolean(req.headers.authorization),
      };
      requests.push(entry);
      const send = (status, value) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(value)); };
      if (entry.path === '/v1/agent/runtime' && req.method === 'POST') {
        runtimeCalls += 1;
        const action = typeof body?.action === 'string' ? body.action : 'unknown';
        const who = { agent: body?.agent_id || identity.agent, session: body?.session_id || identity.session };
        if (/LOWRISK/.test(action)) return send(200, { data: allowRuntime(`gate-low-${runtimeCalls}`, action, who) });
        const receipt = options.receiptFor ? options.receiptFor(runtimeCalls, action) : options.receipts === 'same' ? 'gate-held' : `gate-${hex(4)}-${runtimeCalls}`;
        return send(200, { data: heldRuntime(receipt, action, who, options.approval) });
      }
      const status = entry.path.match(/^\/v1\/agent\/gate-receipts\/([^/]+)\/owner-approval$/);
      if (status && req.method === 'GET') {
        return send(200, { data: { gate_receipt_id: status[1], decision_id: 'decision-review', state: 'pending', gate_decision: 'owner_approval_required', owner_approval_receipt_id: null,
          decided_at: null, approval_source: null, approval_trust: null, approval_answered_by: null, expires_at: '2030-01-01T00:30:00.000Z', terminal: false, retryable: true, poll_after_ms: 1000, exact_next_action: 'pending' } });
      }
      const link = entry.path.match(/^\/v1\/agent\/gate-receipts\/([^/]+)\/approval-link$/);
      if (link && req.method === 'POST') {
        const id = decodeURIComponent(link[1]);
        const known = Object.keys(body || {}).every((key) => ['channel', 'decision_id', 'person_present'].includes(key));
        if (mode === 'refuse-field' || !known) {
          return send(400, { error: 'Approval link request is invalid.', details: { code: 'MARROW_APPROVAL_LINK_INVALID', fields: mode === 'refuse-field' ? ['person_present'] : Object.keys(body || {}), retryable: false } });
        }
        if (mode === 'error') return send(500, { error: `link failed ${leak.secret}`, details: { code: 'MARROW_LINK_FAILED', retryable: true, message: leak.secret } });
        // A receipt of another session or agent is not found for this one.
        if (options.foreign?.includes(id) || entry.session !== identity.session || entry.agent !== identity.agent) {
          return send(404, { error: 'Gate receipt not found.', details: { code: 'MARROW_GATE_RECEIPT_NOT_FOUND' } });
        }
        const count = (perReceipt.get(id) || 0) + 1;
        perReceipt.set(id, count);
        if (count > 3) return send(429, { error: 'Too many approval link requests.', details: { code: 'MARROW_APPROVAL_LINK_LIMITED', retryable: true } });
        const quiet = mode === 'old' || (mode === 'f2' && body?.person_present !== true);
        if (quiet || mode === 'not-sent-leaky') {
          return send(200, { data: {
            sent: false, state: 'not_sent', reason: mode === 'old' ? 'owner_ping_off' : 'no_person_present', approval_link: null,
            exact_next_action: `No link was sent. ${leak.url || ''} ${leak.secret || ''}`.trim(),
            ...(mode === 'not-sent-leaky' ? { token: leak.token, link_url: leak.url } : {}),
          } });
        }
        const view = { id: 'link-1', gate_receipt_id: id, channel: options.channel || 'telegram', recipient_hint: 'o***', expires_at: '2030-01-01T00:10:00.000Z', delivered_at: '2030-01-01T00:00:01.000Z' };
        if (mode === 'sent-leaky') Object.assign(view, { token: leak.token, url: leak.url, link_token: leak.token, channel: leak.token });
        return send(200, { data: {
          sent: true, state: 'sent', reason: 'owner_requested_in_chat', approval_link: view,
          exact_next_action: `Marrow sent a one-tap approval link to the account owner. ${leak.url || ''}`.trim(),
          ...(mode === 'sent-leaky' ? { token: leak.token, error: leak.secret } : {}),
        } });
      }
      const host = entry.path.match(/^\/v1\/agent\/gate-receipts\/([^/]+)\/host-approval$/);
      if (host && req.method === 'POST') {
        // The service records the host's answer as client-attested; the receipt itself stays waiting for the owner here.
        return send(200, { data: { host_approval: {
          owner_approval_receipt_id: body?.verdict === 'approved' ? 'oar-host' : null, owner_decline_receipt_id: body?.verdict === 'declined' ? 'odr-host' : null,
          gate_receipt_id: host[1], decision_id: 'decision-review', verdict: body?.verdict, source: 'host_prompt', trust: 'client_attested',
          answered_by: 'host_operator', host: body?.host, recorded_at: new Date().toISOString(), expires_at: '2030-01-01T00:30:00.000Z',
        }, replayed: false, evidence_recorded: true, exact_next_action: 'recorded' } });
      }
      if (entry.path === '/v1/agent/commit') return send(200, { data: { committed: true } });
      return send(200, { data: { accepted: true } });
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: server.address().port, identity, requests,
    links: () => requests.filter((entry) => /\/approval-link$/.test(entry.path)),
    runtimes: () => requests.filter((entry) => entry.path === '/v1/agent/runtime'),
    hostReports: () => requests.filter((entry) => /\/host-approval$/.test(entry.path)),
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

// The MCP requires an https base URL: it is pointed at a placeholder origin that this preload sends to the loopback stand-in.
const REWRITE_SOURCE = `'use strict';
const port = process.env.MARROW_TEST_LOOPBACK_PORT;
const realFetch = globalThis.fetch;
globalThis.fetch = (url, init) => {
  const text = typeof url === 'string' ? url : url instanceof URL ? url.href : url && url.url;
  if (typeof text === 'string' && text.startsWith('https://api.example.test')) return realFetch('http://127.0.0.1:' + port + text.slice('https://api.example.test'.length), init);
  return realFetch(url, init);
};
`;

// The real MCP over stdio. capability: the host advertises elicitation. elicit: how the host's dialog is answered.
async function startMcp(double, options = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-chat-link-'));
  const home = join(dir, 'home');
  mkdirSync(home, { mode: 0o700 });
  writeOfficialHostConfigs(home);
  const preload = join(dir, 'loopback-rewrite.cjs');
  writeFileSync(preload, REWRITE_SOURCE);
  const apiKey = `mrw_test_${hex(16)}`;
  const child = spawn(process.execPath, [CLI], {
    env: {
      PATH: process.env.PATH, HOME: home, MARROW_API_KEY: apiKey, MARROW_BASE_URL: 'https://api.example.test',
      MARROW_AGENT_ID: double.identity.agent, MARROW_TOOL_PROFILE: 'core', MARROW_SESSION_ID: double.identity.session,
      MARROW_HOOK_BACKGROUND_NUDGE: 'false', MARROW_PASSIVE_TOKEN_USAGE: 'false', MARROW_AUTO_ENROLL: 'false',
      MARROW_TEST_LOOPBACK_PORT: String(double.port), NODE_OPTIONS: `--require=${preload}`,
      NODE_DISABLE_COMPILE_CACHE: '1', TMPDIR: tmpdir(),
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const elicit = options.elicit || { action: 'cancel' };
  const elicitations = [];
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
      if (message.method === 'elicitation/create') {
        elicitations.push(message);
        child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: message.id, result: elicit })}\n`);
      } else if (message.id !== undefined && waiting.has(message.id)) {
        waiting.get(message.id)(message);
      }
    }
  });
  let seq = 0;
  const rpc = (method, params) => new Promise((resolve) => { seq += 1; waiting.set(seq, resolve); child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id: seq, method, params })}\n`); });
  const init = await rpc('initialize', {
    protocolVersion: options.capability ? '2025-06-18' : '2024-11-05',
    capabilities: options.capability ? { elicitation: {} } : {},
    clientInfo: { name: 'claude-code', version: '2.1.289' },
  });
  child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
  return {
    init, elicitations, apiKey,
    call: async (name, args) => {
      const reply = await rpc('tools/call', { name, arguments: args });
      const text = reply.result?.content?.[0]?.text ?? '';
      let json = null;
      try { json = JSON.parse(text); } catch { json = null; }
      return { reply, text, json };
    },
    // Every byte the MCP wrote to the agent (stdout) and to its log (stderr).
    output: () => `${transcript.join('\n')}\n${stderr}`,
    close: async () => {
      child.stdin.end();
      await new Promise((resolve) => { child.on('close', resolve); setTimeout(() => { child.kill(); resolve(); }, 5_000).unref(); });
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

// One double and one MCP per scenario; both are always closed.
async function scenario(options, mcpOptions, body) {
  const double = await startDouble(options);
  const mcp = await startMcp(double, mcpOptions);
  try { return await body(double, mcp); } finally { await mcp.close(); await double.close(); }
}

const runtimeCall = (mcp, extra = {}, action = HOLD) => mcp.call('marrow_agent_runtime', { action, type: 'deploy', ...extra });
const autoCall = (mcp, extra = {}, action = HOLD) => mcp.call('marrow_auto', { action, type: 'deploy', operation_id: `op_${hex(6)}`, ...extra });

// ---------------------------------------------------------------- MB1: once per receipt

test('MB1: a held receipt with a person present (host elicitation) makes exactly one approval-link request {person_present: true}', async () => {
  await scenario({ receipts: 'same' }, { capability: true }, async (double, mcp) => {
    const first = await runtimeCall(mcp);
    assert.equal(first.json.gate_receipt.decision, 'review_required', 'the hold itself is unchanged');
    assert.equal(first.json.gate_receipt_id, 'gate-held');
    assert.equal(double.links().length, 1);
    assert.deepEqual(double.links()[0].body, { person_present: true });
    assert.equal(double.links()[0].path, '/v1/agent/gate-receipts/gate-held/approval-link');
    assert.match(first.json.owner_approval_request.message, SENT_TEXT);
    assert.equal(first.json.owner_approval_request.state, 'sent');
    assert.equal(first.json.owner_approval_request.channel, 'telegram');
    assert.match(first.json.owner_approval_request.message, /read it at \/v1\/agent\/gate-receipts\/gate-held\/owner-approval after about 1 s/);
    assert.match(first.json.owner_approval_request.message, /Never write or claim an approval yourself\.$/);
    assert.equal(first.json.exact_next_action, 'Obtain explicit owner approval before this action runs.');
    // A repeat call, the status polls and a retry on the same receipt send none.
    await runtimeCall(mcp);
    await mcp.call('marrow_runtime_status', {});
    await mcp.call('marrow_status', {});
    const retry = await runtimeCall(mcp, { request_owner_link: true });
    assert.equal(double.links().length, 1, 'still one request for the receipt');
    assert.match(retry.json.owner_approval_request.message, /^Marrow already sent a one-tap approval to your telegram\. Nothing runs until you tap it\./, 'a repeat answers from the first answer and claims no new send');
    assert.equal(retry.json.owner_approval_request.state, 'sent');
  });
});

test('MB1: two receipts get two requests, each for its own receipt id', async () => {
  await scenario({}, { capability: true }, async (double, mcp) => {
    const a = await runtimeCall(mcp);
    const b = await runtimeCall(mcp, {}, 'Deploy the worker to production again');
    assert.notEqual(a.json.gate_receipt_id, b.json.gate_receipt_id);
    assert.deepEqual(double.links().map((entry) => entry.path).sort(), [a.json.gate_receipt_id, b.json.gate_receipt_id].map((id) => `/v1/agent/gate-receipts/${id}/approval-link`).sort());
  });
});

test('MB1: request_owner_link: true is a person present without the elicitation capability, on both tools', async () => {
  await scenario({}, {}, async (double, mcp) => {
    const direct = await runtimeCall(mcp, { request_owner_link: true });
    assert.equal(double.links().length, 1);
    assert.match(direct.json.owner_approval_request.message, SENT_TEXT);
    const auto = await autoCall(mcp, { request_owner_link: true });
    assert.equal(double.links().length, 2, 'the auto hold is its own receipt: one more');
    assert.equal(auto.json.phase, 'owner_approval_required');
    assert.match(auto.json.exact_next_action, /Marrow sent a one-tap approval to your telegram\. Nothing runs until you tap it\./);
    assert.deepEqual(double.links()[1].body, { person_present: true });
  });
});

test('MB1: marrow_auto with a host that asks its user: a dialog the person does not answer sends one request; the retry and the poll send none', async () => {
  await scenario({ receipts: 'same' }, { capability: true, elicit: { action: 'cancel' } }, async (double, mcp) => {
    const operation_id = `op_${hex(6)}`;
    const first = await mcp.call('marrow_auto', { action: HOLD, type: 'deploy', operation_id });
    assert.equal(mcp.elicitations.length, 1, 'the host was asked first');
    assert.equal(double.links().length, 1);
    assert.deepEqual(double.links()[0].body, { person_present: true });
    assert.equal(first.json.phase, 'owner_approval_required');
    assert.equal(first.json.live_delivery.committed, false);
    assert.match(first.json.exact_next_action, /Marrow sent a one-tap approval to your telegram\. Nothing runs until you tap it\. Call marrow_auto again with this same operation_id after retry_after_ms/);
    const poll = await mcp.call('marrow_auto', { action: HOLD, type: 'deploy', operation_id });
    const again = await mcp.call('marrow_auto', { action: HOLD, type: 'deploy', operation_id: `op_${hex(6)}`, request_owner_link: true });
    assert.equal(double.links().length, 1, 'the same receipt in another call or operation sends none');
    assert.match(poll.json.exact_next_action, /^Marrow is holding this action for approval/);
    assert.match(poll.json.exact_next_action, /Marrow already sent a one-tap approval to your telegram\. Nothing runs until you tap it\./);
    assert.equal(again.json.live_delivery.committed, false);
  });
});

// ---------------------------------------------------------------- MB2: no person, auto mode, misleading words

test('MB2: no person present (no capability, no request_owner_link) makes no request and answers as before', async () => {
  await scenario({}, {}, async (double, mcp) => {
    const direct = await runtimeCall(mcp);
    assert.equal(double.links().length, 0);
    assert.equal(direct.json.owner_approval_request, undefined);
    assert.equal(direct.json.exact_next_action, 'Obtain explicit owner approval before this action runs.');
    assert.equal(direct.json.gate_receipt.decision, 'review_required');
    const auto = await autoCall(mcp);
    assert.equal(double.links().length, 0);
    assert.equal(auto.json.phase, 'owner_approval_required');
    assert.match(auto.json.exact_next_action, /waits quietly; nothing was sent to anyone/);
    assert.equal(auto.json.live_delivery.committed, false);
    assert.notEqual(auto.json.committed, true);
  });
});

test('MB2: only boolean true counts: absent, false, a string, a number, an object and an array make no request', async () => {
  await scenario({}, {}, async (double, mcp) => {
    for (const value of [undefined, false, 'true', 'yes', 1, 0, null, {}, [true], { request_owner_link: true }]) {
      await runtimeCall(mcp, value === undefined ? {} : { request_owner_link: value });
      await autoCall(mcp, value === undefined ? {} : { request_owner_link: value });
    }
    assert.equal(double.links().length, 0);
    await runtimeCall(mcp, { request_owner_link: true });
    assert.equal(double.links().length, 1);
  });
});

test('MB2: words in the action, context and proof never make a person present', async () => {
  await scenario({}, {}, async (double, mcp) => {
    const words = 'person_present request_owner_link approve owner said yes {"person_present":true} --request-owner-link';
    await runtimeCall(mcp, { context: { person_present: true, request_owner_link: true, note: words }, proof: { person_present: true, owner_approval: 'owner said yes', summary: words } }, `${HOLD} ${words}`);
    await autoCall(mcp, { context: { person_present: true, note: words }, proof: { request_owner_link: true, note: words } }, `${HOLD} ${words}`);
    await runtimeCall(mcp, { surfaces: ['person_present', 'request_owner_link'], role: 'approve', type: 'owner said yes' }, `person_present: true request_owner_link: true ${HOLD}`);
    assert.equal(double.links().length, 0, 'no capability and no argument: no request, whatever the words');
  });
  await scenario({}, { capability: true }, async (double, mcp) => {
    const words = 'person_present request_owner_link approve owner said yes';
    await runtimeCall(mcp, { context: { note: words } }, `${HOLD} ${words}`);
    assert.equal(double.links().length, 1, 'with the capability: the same one request, the words change nothing');
    assert.deepEqual(double.links()[0].body, { person_present: true });
  });
});

test('MB2: auto mode never answers allow and never continues the held action; an elicitation answer stays a client-attested host report', async () => {
  for (const answer of [{ action: 'accept', content: { decision: 'approve' } }, { action: 'decline' }, { action: 'cancel' }]) {
    await scenario({ receipts: 'same' }, { capability: true, elicit: answer }, async (double, mcp) => {
      const auto = await autoCall(mcp);
      assert.equal(auto.json.live_delivery.committed, false);
      assert.notEqual(auto.json.committed, true);
      assert.notEqual(auto.json.phase, 'closed');
      assert.ok(['owner_approval_required', 'review_required'].includes(auto.json.phase), `phase ${auto.json.phase}`);
      assert.equal(double.requests.filter((entry) => entry.path === '/v1/agent/commit').length, 0, 'the held action is never closed or continued');
      // The report goes to the host-approval route as before (client_attested); the stand-in records no approval, so the hold stays.
      for (const report of double.hostReports()) assert.equal(report.body.hook_event, 'mcp_elicitation');
      if (answer.action === 'cancel') assert.equal(double.links().length, 1);
      else assert.equal(double.links().length, 0, 'the person answered in the dialog: the owner is not messaged');
    });
  }
});

test('MB2: a hold the owner declined needs the explicit request: the host capability alone sends nothing', async () => {
  const approval = {
    host_approval_accepted: false, host_approval_refusal_reason: 'owner_decline_stands', owner_declined_at: '2030-01-01T00:00:00.000Z',
    approval_link_endpoint: '/v1/agent/gate-receipts/gate-held/approval-link', approval_link_available: true, approval_link_reason: 'owner_decline_stands',
    host_approval_endpoint: undefined,
  };
  await scenario({ receipts: 'same', approval }, { capability: true }, async (double, mcp) => {
    const capabilityOnly = await runtimeCall(mcp);
    assert.equal(double.links().length, 0);
    assert.equal(capabilityOnly.json.owner_approval_request, undefined);
    const explicit = await runtimeCall(mcp, { request_owner_link: true });
    assert.equal(double.links().length, 1);
    assert.match(explicit.json.owner_approval_request.message, SENT_TEXT);
    await runtimeCall(mcp, { request_owner_link: true });
    assert.equal(double.links().length, 1, 'once');
  });
});

test('MB2: an action that is not held makes no request even with a person present', async () => {
  await scenario({}, { capability: true }, async (double, mcp) => {
    const low = await runtimeCall(mcp, { request_owner_link: true }, 'run the unit tests LOWRISK');
    assert.equal(low.json.gate_receipt.decision, 'allow');
    assert.equal(double.links().length, 0);
    assert.equal(low.json.owner_approval_request, undefined);
  });
});

// ---------------------------------------------------------------- MB3: no verdict from the client

test('MB3: no source or build file calls the verdict or open route of an approval link; the new fetches are the approval-link route only', () => {
  const files = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, name.name);
      if (name.isDirectory()) walk(path);
      else if (/\.(ts|js)$/.test(name.name) && !/\.d\.ts$/.test(name.name)) files.push(path);
    }
  };
  walk(join(ROOT, 'src'));
  walk(join(ROOT, 'dist'));
  assert.ok(files.length > 50);
  const offenders = files.filter((path) => /\/v1\/approval-links\/(verdict|open)|approval-links\/(verdict|open)/.test(readFileSync(path, 'utf8')));
  assert.deepEqual(offenders, []);
  const source = readFileSync(join(ROOT, 'src', 'index.ts'), 'utf8');
  const chat = source.slice(source.indexOf('export async function requestChatOwnerLink'), source.indexOf('export function chatLinkSentence'));
  assert.ok(chat.length > 200);
  assert.equal((chat.match(/fetch\(/g) || []).length, 0, 'the chat request goes through marrowRequestApprovalLink only');
  assert.match(chat, /marrowRequestApprovalLink\(/);
});

test('MB3: a person present never makes the MCP call the verdict or host-approval routes from the direct runtime path', async () => {
  await scenario({}, { capability: true }, async (double, mcp) => {
    await runtimeCall(mcp);
    await runtimeCall(mcp, { request_owner_link: true });
    const paths = double.requests.map((entry) => entry.path);
    assert.ok(!paths.some((path) => /approval-links|host-approval|owner-approval-receipt/.test(path)));
    assert.equal(double.hostReports().length, 0);
  });
});

// ---------------------------------------------------------------- MB4: identity and old backends

test('MB4: the approval-link request carries the runtime call\'s own agent and session headers, also when the caller names others', async () => {
  await scenario({}, { capability: true }, async (double, mcp) => {
    await runtimeCall(mcp);
    await runtimeCall(mcp, { sessionId: 'other-session-9', agentId: 'other-agent-9' }, 'Deploy the worker to production, second');
    const runtimes = double.runtimes();
    const links = double.links();
    assert.equal(runtimes.length, 2);
    assert.equal(links.length, 2);
    for (let index = 0; index < 2; index += 1) {
      assert.equal(links[index].session, runtimes[index].session, 'X-Marrow-Session-Id equals the runtime call');
      assert.equal(links[index].agent, runtimes[index].agent, 'X-Marrow-Agent-Id equals the runtime call');
      assert.equal(links[index].session, 'mcp-session-1');
      assert.equal(links[index].agent, 'agent-one');
      assert.equal(links[index].authorized, true);
    }
    assert.equal(runtimes[1].body.session_id, 'other-session-9', 'the caller\'s name goes only where it went before');
  });
});

test('MB4: a receipt of another session answers 404: the MCP says the hold waits, one request, no loop', async () => {
  await scenario({ foreign: ['gate-foreign-1'], receiptFor: () => 'gate-foreign-1' }, { capability: true }, async (double, mcp) => {
    const result = await runtimeCall(mcp);
    assert.equal(double.links().length, 1);
    assert.equal(result.json.owner_approval_request.state, 'not_sent');
    assert.match(result.json.owner_approval_request.message, /^Nothing was sent to the account owner, so this hold waits for them: a person approves it at their next interactive session, where the host asks them\. Do not run it; carry on with low-risk work\./);
    await runtimeCall(mcp);
    await mcp.call('marrow_runtime_status', {});
    assert.equal(double.links().length, 1, 'no retry on the same receipt');
  });
});

test('MB4: a service that never heard of the new reason (not_sent) leaves the hold waiting, with one request, and the session goes on with low-risk work', async () => {
  await scenario({ mode: 'old', receipts: 'same' }, { capability: true }, async (double, mcp) => {
    const held = await runtimeCall(mcp);
    assert.equal(double.links().length, 1);
    assert.equal(held.json.owner_approval_request.state, 'not_sent');
    assert.match(held.json.owner_approval_request.message, /^Nothing was sent to the account owner, so this hold waits for them/);
    assert.equal(held.json.gate_receipt.decision, 'review_required');
    await runtimeCall(mcp);
    const low = await runtimeCall(mcp, {}, 'run the unit tests LOWRISK');
    assert.equal(low.json.gate_receipt.decision, 'allow');
    assert.equal(double.links().length, 1, 'no loop, no retry storm');
  });
});

test('MB4: a service that refuses person_present as an unknown field gets one request and no plain resend', async () => {
  await scenario({ mode: 'refuse-field' }, { capability: true }, async (double, mcp) => {
    const held = await runtimeCall(mcp);
    assert.equal(double.links().length, 1);
    assert.deepEqual(double.links()[0].body, { person_present: true });
    assert.equal(held.json.owner_approval_request.state, 'not_sent');
  });
});

// ---------------------------------------------------------------- MB5: token and secret free

test('MB5: a reply that carries a token, a link URL and a secret puts none of them in the agent\'s text, logs or errors', async () => {
  const token = randomBytes(32).toString('base64url');
  assert.equal(token.length, 43);
  const secret = dummySecret(16);
  const url = `https://links.example.test/a/${token}`;
  for (const mode of ['sent-leaky', 'not-sent-leaky', 'error']) {
    for (const via of ['runtime', 'auto']) {
      await scenario({ mode, leak: { token, url, secret } }, { capability: true, elicit: { action: 'cancel' } }, async (double, mcp) => {
        const result = via === 'runtime' ? await runtimeCall(mcp) : await autoCall(mcp);
        assert.equal(double.links().length, 1, `${mode} ${via}`);
        const everything = `${mcp.output()}\n${result.text}`;
        for (const [name, value] of [['token', token], ['url', url], ['secret', secret], ['host', 'links.example.test'], ['key', mcp.apiKey]]) {
          assert.equal(everything.includes(value), false, `${mode} ${via}: no ${name} in any text`);
        }
        assert.doesNotMatch(everything, /link_token|"token"|recipient_hint/);
        if (mode === 'sent-leaky') assert.match(via === 'runtime' ? result.json.owner_approval_request.message : result.json.exact_next_action, /Marrow sent a one-tap approval to your owner channel\. Nothing runs until you tap it\./);
        else assert.match(via === 'runtime' ? result.json.owner_approval_request.message : result.json.exact_next_action, /Nothing was sent to the account owner/);
      });
    }
  }
});

test('MB5: a channel that is not one of the owner\'s channels is shown as "owner channel", never as the value', async () => {
  const lookalike = hex(15).slice(0, 30);
  await scenario({ channel: lookalike }, { capability: true }, async (double, mcp) => {
    const result = await runtimeCall(mcp);
    assert.equal(result.json.owner_approval_request.channel, null);
    assert.match(result.json.owner_approval_request.message, /^Marrow sent a one-tap approval to your owner channel\. Nothing runs until you tap it\./);
    assert.equal(`${mcp.output()}${result.text}`.includes(lookalike), false);
  });
});

// ---------------------------------------------------------------- MB6: abuse and collisions

test('MB6: a caller that forges request_owner_link on every call gets one request per receipt and nothing approves', async () => {
  await scenario({}, {}, async (double, mcp) => {
    const ids = [];
    for (let index = 0; index < 5; index += 1) {
      const held = await runtimeCall(mcp, { request_owner_link: true }, `${HOLD} ${index}`);
      assert.equal(held.json.gate_receipt.decision, 'review_required');
      assert.equal(held.json.gate_receipt.owner_approval_required, true);
      ids.push(held.json.gate_receipt_id);
      await runtimeCall(mcp, { request_owner_link: true }, `${HOLD} ${index}`);
    }
    assert.equal(double.links().length, 10, 'two calls per action; each call is its own receipt, each receipt one request');
    assert.equal(new Set(double.links().map((entry) => entry.path)).size, 10);
    assert.equal(double.requests.filter((entry) => /approval-links|host-approval|\/commit$/.test(entry.path)).length, 0, 'nothing records an approval or closes the hold');
  });
});

test('MB6: a burst of 10 holds in one session: one request each, never two for a receipt, even in parallel', async () => {
  await scenario({}, { capability: true }, async (double, mcp) => {
    const results = await Promise.all(Array.from({ length: 10 }, (_, index) => runtimeCall(mcp, {}, `${HOLD} burst ${index}`)));
    assert.equal(new Set(results.map((entry) => entry.json.gate_receipt_id)).size, 10);
    assert.equal(double.links().length, 10);
    assert.equal(new Set(double.links().map((entry) => entry.path)).size, 10, 'no receipt twice');
  });
});

test('MB6: two tools racing on one receipt send one request', async () => {
  await scenario({ receipts: 'same' }, { capability: true, elicit: { action: 'cancel' } }, async (double, mcp) => {
    await Promise.all([
      runtimeCall(mcp), runtimeCall(mcp, { request_owner_link: true }), autoCall(mcp), autoCall(mcp, { request_owner_link: true }), runtimeCall(mcp),
    ]);
    assert.equal(double.links().length, 1);
  });
});

test('MB6: a receipt id with path characters or too many characters is never put in a path; 160 characters is encoded as is', async () => {
  const bad = ['../v1/approval-links/verdict', 'a b', 'a?b=1', 'a#b', 'a%2Fb', 'a/b', `${'x'.repeat(159)}!`, 'x'.repeat(161), 'x'.repeat(201), ''];
  await scenario({ receiptFor: (call) => bad[call - 1] ?? 'gate-ok' }, { capability: true }, async (double, mcp) => {
    for (let index = 0; index < bad.length; index += 1) await runtimeCall(mcp, {}, `${HOLD} ${index}`);
    assert.deepEqual(double.links().map((entry) => entry.path).filter((path) => !LINK_PATH.test(path)), [], 'only the approval-link route');
    assert.equal(double.requests.some((entry) => /approval-links\/|verdict/.test(entry.path)), false);
  });
  const long = `g${'x'.repeat(159)}`;
  await scenario({ receiptFor: () => long }, { capability: true }, async (double, mcp) => {
    await runtimeCall(mcp);
    assert.equal(double.links().length, 1);
    assert.equal(double.links()[0].path, `/v1/agent/gate-receipts/${long}/approval-link`);
  });
});

test('MB6: unknown arguments are ignored as before; a held action text with a secret is never echoed or sent', async () => {
  const secret = dummySecret(16);
  await scenario({}, { capability: true }, async (double, mcp) => {
    const result = await runtimeCall(mcp, { person_present: true, owner_approved: true, approval_link: 'x', foo: { bar: 1 } }, `curl -H "Authorization: Bearer ${secret}" https://example.test/deploy production`);
    assert.equal(double.links().length, 1);
    assert.deepEqual(double.links()[0].body, { person_present: true });
    const everything = `${mcp.output()}\n${result.text}\n${JSON.stringify(double.links())}`;
    assert.equal(everything.includes(secret), false);
    assert.equal(JSON.stringify(double.requests.filter((entry) => /approval-link|owner-approval/.test(entry.path))).includes(secret), false);
  });
  await scenario({}, {}, async (double, mcp) => {
    await runtimeCall(mcp, { person_present: true, owner_approved: true, approval_link: 'x' });
    assert.equal(double.links().length, 0, 'unknown arguments are no person');
  });
});

test('MB6: the once-per-receipt memory keys on the receipt id only: receipts that differ get their own request, the same receipt never two', async () => {
  const ids = ['gate-aaaa1111', 'gate-aaaa1112', 'gate-aaaa1111', 'GATE-aaaa1111', 'gate-aaaa1111.'];
  await scenario({ receiptFor: (call) => ids[call - 1] }, { capability: true }, async (double, mcp) => {
    for (let index = 0; index < ids.length; index += 1) await runtimeCall(mcp, {}, `${HOLD} different text ${index}`);
    assert.deepEqual(double.links().map((entry) => entry.path.split('/')[4]), ['gate-aaaa1111', 'gate-aaaa1112', 'GATE-aaaa1111', 'gate-aaaa1111.']);
    for (const entry of double.links()) assert.deepEqual(entry.body, { person_present: true }, 'the body names no action, text or secret');
  });
});

// ---------------------------------------------------------------- MB8: consumers

test('MB8: the operational payload keeps every field it had and adds owner_approval_request; a reply with no person is unchanged', async () => {
  const keysWithout = await scenario({ receipts: 'same' }, {}, async (double, mcp) => Object.keys((await runtimeCall(mcp)).json).sort());
  await scenario({ receipts: 'same' }, { capability: true }, async (double, mcp) => {
    const keysWith = Object.keys((await runtimeCall(mcp)).json).sort();
    assert.deepEqual(keysWith.filter((key) => key !== 'owner_approval_request'), keysWithout);
    assert.ok(keysWith.includes('host_capability') && keysWith.includes('control_path') && keysWith.includes('lifecycle_spool'));
  });
});
