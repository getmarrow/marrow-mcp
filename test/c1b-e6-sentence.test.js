'use strict';
// C1b E6 fix-up: a 403 MARROW_AGENT_SCOPE_MISMATCH refusal says where the refused agent id came from. When the request
// this tool call sent carried the tool's own agentId argument, the message says so (and drops the env sentence and the
// agent_id_source label, which would name the wrong source); otherwise the 3.9.115 env sentence and label stay. When the
// service's allowed_agent_ids passed the M-8 validation, one more sentence names those bound ids. Rows E6S-1..E6S-9 of
// SPEC-C1b-mcp-e6-sentence run through the real stdio server against a loopback fake in the backend's answer shapes
// (agentErr: {error, code, details:{code, exact_fix, allowed_agent_ids}}). Dummy keys made at run time; never printed.
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');
const { dummySecret } = require('./support/dummy-secret.cjs');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const FAKE_ORIGIN = 'https://c1b-e6-sentence.invalid';
const ENV_AGENT = 'env-agent-e6s';
const ARG_AGENT = 'arg-agent-e6s';
const ARG_SENTENCE = "The refused agent id came from this tool call's agentId argument.";
const ENV_SENTENCE = "This server took the id from MARROW_FLEET_AGENT_ID in this server's environment (set by the host or its launcher).";
const BOUND_PREFIX = 'Agent ids bound to this API key:';
const VALID_IDS = ['agent-a', 'agent.b:c_1-2'];
const EXACT_FIX = 'This API key is not bound to the agent this request names. Use one of the bound agent ids.';
const TARGETS = ['/v1/agent/governance/', '/v1/agent/audit/', '/v1/workflows', '/v1/agent/model-usage'];

// ---- loopback fake ----------------------------------------------------------------------------------------------
function startBackend() {
  const fake = { requests: [], answer: null };
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const pathname = req.url.split('?')[0];
      fake.requests.push({ method: req.method, url: req.url, pathname, headers: { ...req.headers }, body: Buffer.concat(chunks).toString('utf8') });
      const target = TARGETS.some((prefix) => pathname.startsWith(prefix));
      const { status = 200, body = JSON.stringify({ data: {} }) } = (target && fake.answer) || {};
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(body);
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    fake, base: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((done) => { server.closeAllConnections?.(); server.close(done); }),
  })));
}

const agentErr = (status, error, code, details) => ({ status, body: JSON.stringify({ error, code, details }) });
const scopeMismatch = (allowed) => agentErr(403, 'Agent-bound key cannot access another agent.', 'FORBIDDEN', {
  code: 'MARROW_AGENT_SCOPE_MISMATCH', exact_fix: EXACT_FIX, ...(allowed === undefined ? {} : { allowed_agent_ids: allowed }),
});

// ---- real stdio server ------------------------------------------------------------------------------------------
function startServer(base) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-e6s-'));
  const preload = path.join(home, 'to-loopback.cjs');
  fs.writeFileSync(preload, [
    'const real = globalThis.fetch;',
    `globalThis.fetch = (url, init) => real(String(url).replace(${JSON.stringify(FAKE_ORIGIN)}, ${JSON.stringify(base)}), init);`,
  ].join('\n'));
  const key = dummySecret();
  const child = spawn(process.execPath, ['--require', preload, CLI], {
    cwd: home,
    env: {
      PATH: process.env.PATH, HOME: home, MARROW_API_KEY: key, MARROW_BASE_URL: FAKE_ORIGIN,
      MARROW_FLEET_AGENT_ID: ENV_AGENT, MARROW_TOOL_PROFILE: 'full', MARROW_AUTO_HOOK: 'false', MARROW_REQUEST_TIMEOUT_MS: '1500',
      ...(process.env.NODE_OPTIONS ? { NODE_OPTIONS: process.env.NODE_OPTIONS } : {}),
    },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const waiting = new Map();
  let buffer = '';
  let stdoutAll = '';
  let stderrAll = '';
  child.stderr.on('data', (chunk) => { stderrAll += chunk; });
  child.stdout.on('data', (chunk) => {
    buffer += chunk;
    stdoutAll += chunk;
    let at;
    while ((at = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, at).trim();
      buffer = buffer.slice(at + 1);
      if (!line) continue;
      let message;
      try { message = JSON.parse(line); } catch { continue; }
      if (waiting.has(message.id)) { waiting.get(message.id)(message); waiting.delete(message.id); }
    }
  });
  let nextId = 1;
  const request = (method, params) => new Promise((resolve, reject) => {
    const id = nextId++;
    const timer = setTimeout(() => { waiting.delete(id); reject(new Error(`no answer to ${method}`)); }, 20_000);
    waiting.set(id, (message) => { clearTimeout(timer); resolve(message); });
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
  });
  const ready = request('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'e6s-test', version: '1' } })
    .then((message) => { child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`); return message; });
  return {
    ready, home, key,
    call: (name, args) => request('tools/call', { name, arguments: args }),
    stderr: () => stderrAll,
    stdout: () => stdoutAll,
    stop: () => new Promise((resolve) => {
      if (child.exitCode !== null) return resolve();
      child.once('exit', () => resolve());
      child.kill();
    }),
  };
}

function filesUnder(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...filesUnder(full));
    else if (entry.isFile()) out.push(fs.readFileSync(full, 'utf8'));
  }
  return out;
}

let backend;
let server;
const extraArgKeys = [];
const dump = [];
const relevant = () => backend.fake.requests.filter((r) => TARGETS.some((prefix) => r.pathname.startsWith(prefix)));
/** One tool call against `answer`; returns the parsed failure and the requests it sent to the target routes. */
async function refusal(row, tool, args, answer = scopeMismatch(VALID_IDS)) {
  backend.fake.requests.length = 0;
  backend.fake.answer = answer;
  const message = await server.call(tool, args);
  const text = message.result?.content?.[0]?.text;
  assert.equal(message.result?.isError, true, `${row}: a tool failure`);
  const failure = JSON.parse(text);
  const { control_path, lifecycle_spool, ...stable } = failure; // per-call counters, not part of the refusal text
  dump.push({ row, tool, args: row === 'E6S-6' ? '[runtime dummy args]' : args, answer, stable }); // dummy keys never reach the dump
  return { failure, requests: relevant() };
}
const message = (failure) => String(failure.error?.message || '');
const count = (haystack, needle) => haystack.split(needle).length - 1;

test.before(async () => {
  backend = await startBackend();
  server = startServer(backend.base);
  await server.ready;
});

test.after(async () => {
  await server?.stop();
  await backend?.close();
  if (process.env.E6S_DUMP) fs.writeFileSync(process.env.E6S_DUMP, `${JSON.stringify(dump, null, 1)}\n`);
});

test('E6S-1 explicit agentId argument sent: the argument sentence, no env sentence, no agent_id_source label', async () => {
  for (const [tool, args] of [
    ['marrow_governance_timeline', { agentId: ARG_AGENT }],
    ['marrow_buyer_proof', { agentId: ARG_AGENT, periodDays: 7 }],
  ]) {
    const { failure, requests } = await refusal('E6S-1', tool, args);
    const text = message(failure);
    assert.equal(count(text, ARG_SENTENCE), 1, `${tool}: ${text}`);
    assert.equal(text.includes('took the id from'), false, `${tool}: ${text}`);
    assert.equal(Object.hasOwn(failure, 'agent_id_source'), false, tool);
    // Request shape: the argument went into the agent_id query the scope check reads; the header keeps the env id.
    assert.equal(requests.length, 1, tool);
    assert.equal(new URL(requests[0].url, 'http://x').searchParams.get('agent_id'), ARG_AGENT, tool);
    assert.equal(requests[0].headers['x-marrow-agent-id'], ENV_AGENT, tool);
  }
});

test('E6S-2 no explicit argument: the 3.9.115 env sentence and agent_id_source label', async () => {
  for (const [tool, args] of [['marrow_governance_timeline', {}], ['marrow_buyer_proof', {}], ['marrow_decision_trace', { decisionId: 'dec-e6s' }]]) {
    const { failure } = await refusal('E6S-2', tool, args);
    const text = message(failure);
    assert.equal(count(text, ENV_SENTENCE), 1, `${tool}: ${text}`);
    assert.equal(text.includes(ARG_SENTENCE), false, `${tool}: ${text}`);
    assert.equal(failure.agent_id_source?.variable, 'MARROW_FLEET_AGENT_ID', tool);
    assert.equal(failure.agent_id_source?.agent_id, ENV_AGENT, tool);
  }
});

test('E6S-3 a valid allowed_agent_ids list: one bound-ids sentence with that list', async () => {
  for (const args of [{}, { agentId: ARG_AGENT }]) {
    const { failure } = await refusal('E6S-3', 'marrow_governance_timeline', args);
    const text = message(failure);
    assert.equal(count(text, `${BOUND_PREFIX} ${VALID_IDS.join(', ')}.`), 1, text);
    assert.equal(count(text, BOUND_PREFIX), 1, text);
    assert.ok(text.endsWith(`${BOUND_PREFIX} ${VALID_IDS.join(', ')}.`), text);
    assert.deepEqual(failure.error.allowed_agent_ids, VALID_IDS);
  }
});

const BAD_LISTS = [
  ['65 ids', Array.from({ length: 65 }, (_, i) => `agent-${i}`)],
  ['a non-string entry', ['agent-a', 7]],
  ['an entry with a space', ['agent a']],
  ['an entry with a newline', ['agent-a\nagent-b']],
  ['an entry of 129 chars', ['a'.repeat(129)]],
  ['a unicode entry', ['agent-é']],
  ['a string, not an array', 'agent-a, agent-b'],
  ['an empty array', []],
  ['the member missing', undefined],
];
for (const [name, list] of BAD_LISTS) {
  test(`E6S-3 allowed_agent_ids is ${name}: no bound-ids sentence`, async () => {
    for (const args of [{}, { agentId: ARG_AGENT }]) {
      const { failure } = await refusal('E6S-3', 'marrow_governance_timeline', args, scopeMismatch(list));
      const text = message(failure);
      assert.equal(text.includes(BOUND_PREFIX), false, text);
      assert.equal(Object.hasOwn(failure.error, 'allowed_agent_ids'), false);
      assert.equal(count(text, args.agentId ? ARG_SENTENCE : ENV_SENTENCE), 1, text);
      if (typeof list === 'string') assert.equal(text.includes(list), false, text);
    }
  });
}

test('E6S-4 every other credential_scope code and other statuses: no argument sentence, no bound-ids sentence', async () => {
  const others = [
    ['credential scope invalid', agentErr(403, 'Agent credential scope invalid.', 'FORBIDDEN', { code: 'ACTION_PERMIT_AGENT_CREDENTIAL_SCOPE_INVALID', exact_fix: EXACT_FIX, allowed_agent_ids: VALID_IDS }), true],
    ['permit required', agentErr(403, 'Permit required', 'FORBIDDEN', { code: 'ACTION_PERMIT_REQUIRED', allowed_agent_ids: VALID_IDS }), false],
    ['header refusal', agentErr(400, 'Invalid agent id header', 'BAD_REQUEST', { code: 'MARROW_AGENT_HEADER_INVALID', exact_fix: 'Use X-Marrow-Agent-Id with 1-128 characters.' }), false],
    ['authentication required', { status: 401, body: JSON.stringify({ error: 'Unauthorized', code: 'UNAUTHORIZED' }) }, false],
    ['scope code on 400', agentErr(400, 'Agent-bound key cannot access another agent.', 'BAD_REQUEST', { code: 'MARROW_AGENT_SCOPE_MISMATCH', exact_fix: EXACT_FIX, allowed_agent_ids: VALID_IDS }), false],
    ['scope code on 404', agentErr(404, 'Not found', 'NOT_FOUND', { code: 'MARROW_AGENT_SCOPE_MISMATCH', allowed_agent_ids: VALID_IDS }), false],
    ['scope code on 500', agentErr(500, 'Internal', 'INTERNAL', { code: 'MARROW_AGENT_SCOPE_MISMATCH', allowed_agent_ids: VALID_IDS }), false],
  ];
  for (const [name, answer, envSentence] of others) {
    const sent = [];
    for (const args of [{}, { agentId: ARG_AGENT }]) {
      const { failure, requests } = await refusal('E6S-4', 'marrow_governance_timeline', args, answer);
      const text = message(failure);
      assert.equal(text.includes(ARG_SENTENCE), false, `${name}: ${text}`);
      assert.equal(text.includes(BOUND_PREFIX), false, `${name}: ${text}`);
      assert.equal(count(text, ENV_SENTENCE), envSentence ? 1 : 0, `${name}: ${text}`);
      assert.equal(Object.hasOwn(failure, 'agent_id_source'), envSentence, name);
      sent.push(requests.length);
    }
    assert.equal(sent[1], sent[0], `${name}: the argument changes no request count`);
  }
});

test('E6S-4 a 403 whose only code is a top-level MARROW_AGENT_SCOPE_MISMATCH (no details) is that code as the client reads it', async () => {
  const answer = { status: 403, body: JSON.stringify({ error: 'Forbidden', code: 'MARROW_AGENT_SCOPE_MISMATCH' }) };
  const plain = (await refusal('E6S-4', 'marrow_governance_timeline', {}, answer)).failure;
  assert.equal(count(message(plain), ENV_SENTENCE), 1, message(plain));
  assert.equal(plain.agent_id_source?.variable, 'MARROW_FLEET_AGENT_ID');
  const withArg = (await refusal('E6S-4', 'marrow_governance_timeline', { agentId: ARG_AGENT }, answer)).failure;
  assert.equal(count(message(withArg), ARG_SENTENCE), 1, message(withArg));
  assert.equal(message(withArg).includes(BOUND_PREFIX), false, message(withArg));
});

test('E6S-5 code and exact_fix stay the service values, with or without the argument', async () => {
  const a = (await refusal('E6S-5', 'marrow_governance_timeline', {})).failure;
  const b = (await refusal('E6S-5', 'marrow_governance_timeline', { agentId: ARG_AGENT })).failure;
  assert.equal(a.error.code, 'MARROW_AGENT_SCOPE_MISMATCH');
  assert.equal(a.error.exact_fix, EXACT_FIX);
  assert.equal(b.error.code, a.error.code);
  assert.equal(b.error.exact_fix, a.error.exact_fix);
  const { message: ma, ...restA } = a.error;
  const { message: mb, ...restB } = b.error;
  assert.deepEqual(restB, restA);
});

test('E6S-6 a runtime dummy key in env and in the tool arguments is in no message, label or log', async () => {
  const argKey = dummySecret();
  extraArgKeys.push(argKey);
  const { failure } = await refusal('E6S-6', 'marrow_governance_timeline', { agentId: ARG_AGENT, limit: 5, note: argKey });
  const { failure: second } = await refusal('E6S-6', 'marrow_governance_timeline', { agentId: argKey });
  for (const value of [server.key, argKey]) {
    assert.equal(JSON.stringify(failure).includes(value), false);
    assert.equal(JSON.stringify(second).includes(value), false);
    assert.equal(server.stderr().includes(value), false);
    for (const file of filesUnder(server.home)) assert.equal(file.includes(value), false);
  }
  assert.equal(server.stdout().includes(server.key), false);
});

test('E6S-7 no automatic retry and no change of identity: exactly one request, env agent header kept', async () => {
  for (const args of [{}, { agentId: ARG_AGENT }, { agentId: ENV_AGENT }]) {
    const { requests } = await refusal('E6S-7', 'marrow_governance_timeline', args);
    assert.equal(requests.length, 1, JSON.stringify(args));
    assert.equal(requests[0].headers['x-marrow-agent-id'], ENV_AGENT);
    for (const id of VALID_IDS) assert.equal(JSON.stringify(requests[0]).includes(id), false);
  }
});

test('E6S-8 gateReceiptId branches never send the argument: the 3.9.115 env sentence and label', async () => {
  for (const tool of ['marrow_decision_trace', 'marrow_buyer_proof']) {
    const { failure, requests } = await refusal('E6S-8', tool, { gateReceiptId: 'gr-e6s-0001', agentId: ARG_AGENT });
    const text = message(failure);
    assert.equal(text.includes(ARG_SENTENCE), false, `${tool}: ${text}`);
    assert.equal(count(text, ENV_SENTENCE), 1, `${tool}: ${text}`);
    assert.equal(failure.agent_id_source?.variable, 'MARROW_FLEET_AGENT_ID', tool);
    assert.equal(requests.length, 1, tool);
    assert.equal(JSON.stringify(requests[0]).includes(ARG_AGENT), false, tool);
    assert.equal(requests[0].url.includes('?'), false, tool);
    assert.equal(requests[0].body, '', tool);
    assert.equal(requests[0].headers['x-marrow-agent-id'], ENV_AGENT, tool);
  }
});

test('E6S-8 a handler that copies the whole arguments object and drops agentId (marrow_model_usage) does not send it: env sentence', async () => {
  const { failure, requests } = await refusal('E6S-8', 'marrow_model_usage', { agentId: ARG_AGENT, model: 'm', input_tokens: 1 }, scopeMismatch());
  const text = message(failure);
  assert.equal(text.includes(ARG_SENTENCE), false, text);
  assert.equal(count(text, ENV_SENTENCE), 1, text);
  assert.equal(failure.agent_id_source?.variable, 'MARROW_FLEET_AGENT_ID');
  assert.equal(requests.length, 1);
  assert.equal(JSON.stringify(requests[0]).includes(ARG_AGENT), false);
});

test('E6S-9 empty and null agentId are not sent (env sentence); the env id itself as the argument is sent', async () => {
  for (const value of ['', null]) {
    const { failure, requests } = await refusal('E6S-9', 'marrow_governance_timeline', { agentId: value });
    const text = message(failure);
    assert.equal(text.includes(ARG_SENTENCE), false, text);
    assert.equal(count(text, ENV_SENTENCE), 1, text);
    assert.equal(failure.agent_id_source?.variable, 'MARROW_FLEET_AGENT_ID');
    assert.equal(new URL(requests[0].url, 'http://x').searchParams.get('agent_id'), ENV_AGENT);
  }
  const { failure, requests } = await refusal('E6S-9', 'marrow_governance_timeline', { agentId: ENV_AGENT });
  assert.equal(count(message(failure), ARG_SENTENCE), 1, message(failure));
  assert.equal(message(failure).includes('took the id from'), false);
  assert.equal(Object.hasOwn(failure, 'agent_id_source'), false);
  // Request shape: the argument went to the agent_id query (the same value as the env header).
  assert.equal(new URL(requests[0].url, 'http://x').searchParams.get('agent_id'), ENV_AGENT);
});

test('E6S-9 a later call without the argument is not marked by an earlier call with it', async () => {
  await refusal('E6S-9', 'marrow_governance_timeline', { agentId: ARG_AGENT });
  const { failure } = await refusal('E6S-9', 'marrow_governance_timeline', {});
  assert.equal(message(failure).includes(ARG_SENTENCE), false, message(failure));
  assert.equal(count(message(failure), ENV_SENTENCE), 1, message(failure));
});
