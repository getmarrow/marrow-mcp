'use strict';
// C1b: marrow_decision_trace reads the gate receipt chain (gateReceiptId) and marrow_buyer_proof reads the signed export
// (gateReceiptId) and hands its body back byte for byte; a 403 MARROW_AGENT_SCOPE_MISMATCH refusal shows the bound
// agent ids when they are a valid list. Rows M-1..M-12 of the C1b MCP spec run through the real stdio server against a
// loopback fake that answers in the backend's shapes (ok -> {data}, fail -> {error, code, details}, signing failure ->
// {error, code}, signed export -> a bare JSON body). Dummy key made at run time; never printed.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');
const { dummySecret } = require('./support/dummy-secret.cjs');

const ROOT = path.join(__dirname, '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const FAKE_ORIGIN = 'https://c1b-passthrough.invalid';
const SIGNED_PREFIX = '/v1/agent/audit/signed-receipts/';
const CHAIN_PREFIX = '/v1/agent/governance/chain/';
const TRACE_PREFIX = '/v1/agent/governance/trace/';
const HOW_TO_VERIFY = "Save content[0] unchanged to a file, save the JWKS, then verify offline with the installer's verify command.";
const ANSWER_MARK = 'c1b-answer-mark-7f3a';
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

// The signed export the backend serves: bare JSON, odd whitespace, escapes, raw non-ASCII and a DUPLICATE member.
const SIGNED_BODY = `{"format":"marrow.signed_records.v1" ,\n\t"signing":{"status":"signed","alg":"EdDSA","kid":"k1"},`
  + `"records":[{"note":"\\u00e9 \u00e9 \\/ \\"q\\" ${ANSWER_MARK}","n":1,"n":2}],"unsigned_notes":{}}  \n`;

// ---- loopback fake ----------------------------------------------------------------------------------------------
function startBackend() {
  const fake = { requests: [], plan: null };
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const url = req.url;
      const pathname = url.split('?')[0];
      fake.requests.push({ method: req.method, url, pathname, headers: { ...req.headers }, body: Buffer.concat(chunks).toString('utf8') });
      const answer = fake.plan ? fake.plan(pathname, req) : null;
      if (answer === 'hang') return; // never answers: the client's timeout decides
      const { status = 200, type = 'application/json', body = JSON.stringify({ data: {} }), headers = {} } = answer || {};
      res.writeHead(status, { 'content-type': type, ...headers });
      res.end(Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8'));
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    fake, base: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((done) => { server.closeAllConnections?.(); server.close(done); }),
  })));
}

// Backend answer builders (response.ts ok()/fail(), agent-route-support agentErr(), signed-records signingFailureResponse()).
const ok = (data) => ({ status: 200, body: JSON.stringify({ data }) });
const agentErr = (status, error, code, details) => ({ status, body: JSON.stringify({ error, code, details }) });
const signingFailure = (status, error, code, extra = {}) => ({ status, body: JSON.stringify({ error, code, ...extra }) });
const scopeMismatch = (allowed, extra = {}) => agentErr(403, 'Agent-bound key cannot access another agent.', 'FORBIDDEN', {
  code: 'MARROW_AGENT_SCOPE_MISMATCH',
  exact_fix: 'This API key is not bound to the agent this request names. Use one of the bound agent ids.',
  allowed_agent_ids: allowed,
  ...extra,
});

// ---- real stdio server ------------------------------------------------------------------------------------------
function startServer(base, extraEnv = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-c1b-'));
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
      MARROW_AUTO_HOOK: 'false', MARROW_REQUEST_TIMEOUT_MS: '1500',
      ...(process.env.NODE_OPTIONS ? { NODE_OPTIONS: process.env.NODE_OPTIONS } : {}),
      ...extraEnv,
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
  const ready = request('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'c1b-test', version: '1' } })
    .then((message) => {
      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
      return message;
    });
  return {
    ready, home, key, request,
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

/** Every file under `dir` (spools, state), as raw text. */
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
const relevant = () => backend.fake.requests.filter((r) => r.pathname.startsWith('/v1/agent/governance/') || r.pathname.startsWith('/v1/agent/audit/'));
const reset = (plan) => { backend.fake.requests.length = 0; backend.fake.plan = plan; };
const textOf = (message, index = 0) => message.result?.content?.[index]?.text;
const failureOf = (message) => JSON.parse(textOf(message));

test.before(async () => {
  backend = await startBackend();
  server = startServer(backend.base);
  await server.ready;
});

test.after(async () => {
  await server?.stop();
  await backend?.close();
  if (server) fs.rmSync(server.home, { recursive: true, force: true });
});

const signedPlan = (answer) => (pathname) => (pathname.startsWith(SIGNED_PREFIX) ? answer : ok({ ignored: true }));

test('M-1 signed export: content[0] is the served body byte for byte; the label hashes that body', async () => {
  reset(signedPlan({ status: 200, body: SIGNED_BODY }));
  const message = await server.call('marrow_buyer_proof', { gateReceiptId: 'gr_123.abc-x' });
  assert.equal(message.result?.isError, undefined);
  assert.equal(message.result.content.length, 2);
  const text = textOf(message);
  assert.equal(text, SIGNED_BODY);
  assert.equal(sha256(Buffer.from(text, 'utf8')), sha256(Buffer.from(SIGNED_BODY, 'utf8')));
  assert.ok(text.includes('"n":1,"n":2'), 'the duplicate member reaches the caller');
  const label = JSON.parse(textOf(message, 1));
  assert.deepEqual(Object.keys(label), ['kind', 'bytes_sha256', 'jwks_path', 'how_to_verify']);
  assert.equal(label.kind, 'marrow.signed_records.v1');
  assert.equal(label.bytes_sha256, sha256(Buffer.from(SIGNED_BODY, 'utf8')));
  assert.equal(label.jwks_path, '/.well-known/marrow-signing-keys.json');
  assert.equal(label.how_to_verify, HOW_TO_VERIFY);
  const [one] = relevant();
  assert.equal(relevant().length, 1);
  assert.equal(one.method, 'GET');
  assert.equal(one.url, `${SIGNED_PREFIX}gr_123.abc-x`);
});

test('M-1 collision rows: one changed byte in a payload value or in whitespace gives another bytes_sha256', async () => {
  const labels = [];
  for (const body of [SIGNED_BODY, SIGNED_BODY.replace('"n":2', '"n":3'), SIGNED_BODY.replace(' ,\n', '  ,\n'), `\ufeff${SIGNED_BODY}`]) {
    reset(signedPlan({ status: 200, body }));
    const message = await server.call('marrow_buyer_proof', { gateReceiptId: 'gr_1' });
    assert.equal(textOf(message), body, 'a byte-order mark or changed byte is passed through, never normalised');
    const label = JSON.parse(textOf(message, 1));
    assert.equal(label.bytes_sha256, sha256(Buffer.from(body, 'utf8')));
    labels.push(label.bytes_sha256);
  }
  assert.equal(new Set(labels).size, labels.length);
});

test('M-2 source pin: the signed path never parses or re-serialises the body', () => {
  const source = fs.readFileSync(path.join(ROOT, 'src', 'index.ts'), 'utf8');
  const start = source.indexOf('export async function marrowSignedReceiptExport(');
  assert.ok(start >= 0, 'marrowSignedReceiptExport exists');
  const end = source.indexOf('\nexport ', start + 1);
  const body = source.slice(start, end < 0 ? undefined : end);
  for (const banned of ['JSON.parse', '.json()', 'JSON.stringify', 'fetchJsonResponse', 'fetchWithRetryQueue', 'redact', '.trim(', '.text()']) {
    assert.equal(body.includes(banned), false, `the signed path must not use ${banned}`);
  }
  assert.ok(body.includes("fatal: true"), 'invalid UTF-8 is refused, never replaced');
  assert.ok(body.includes('ignoreBOM: true'), 'a byte-order mark is kept');
});

const SIGNED_FAILURES = [
  ['400', agentErr(400, 'Invalid receipt id', 'BAD_REQUEST', { code: 'BAD_REQUEST', exact_fix: 'Use the receipt id as listed.' }), 'BAD_REQUEST', 400],
  ['404', agentErr(404, 'Receipt not found', 'NOT_FOUND', { code: 'NOT_FOUND' }), 'NOT_FOUND', 404],
  ['409', signingFailure(409, 'Record is older than signing', 'MARROW_SIGNING_BEFORE_SIGNED_FROM', { signed_from: '2026-11-01T00:00:00.000Z' }), 'MARROW_SIGNING_BEFORE_SIGNED_FROM', 409],
  ['429', { ...agentErr(429, 'Rate limited', 'RATE_LIMITED', { code: 'RATE_LIMITED' }), headers: { 'retry-after': '0' } }, 'RATE_LIMITED', 429],
  ['503 not configured', signingFailure(503, 'Signed export is not configured', 'MARROW_SIGNING_NOT_CONFIGURED'), 'MARROW_SIGNING_NOT_CONFIGURED', 503],
  ['503 misconfigured', signingFailure(503, 'Signed export is misconfigured', 'MARROW_SIGNING_MISCONFIGURED'), 'MARROW_SIGNING_MISCONFIGURED', 503],
  ['503 keys invalid', signingFailure(503, 'Signing keys are invalid', 'MARROW_SIGNING_KEYS_INVALID'), 'MARROW_SIGNING_KEYS_INVALID', 503],
  ['503 unstable', signingFailure(503, 'Signed export is not stable for this record', 'MARROW_SIGNING_UNSTABLE_RECORD'), 'MARROW_SIGNING_UNSTABLE_RECORD', 503],
  ['500', agentErr(500, 'Failed to build signed export', 'INTERNAL_ERROR', { code: 'INTERNAL_ERROR' }), 'INTERNAL_ERROR', 500],
  ['502 html', { status: 502, type: 'text/html', body: `<html><body>Bad gateway ${ANSWER_MARK}</body></html>` }, 'service_unavailable', 502],
];

for (const [name, answer, code, status] of SIGNED_FAILURES) {
  test(`M-3 signed export ${name}: the 3.9.115 structured failure of an existing read, never answer text`, async () => {
    reset(signedPlan(answer));
    const signed = await server.call('marrow_buyer_proof', { gateReceiptId: 'gr_fail' });
    assert.equal(signed.result?.isError, true);
    assert.equal(signed.result.content.length, 1);
    const failure = failureOf(signed);
    assert.equal(failure.ok, false);
    assert.equal(failure.error.code, code);
    assert.equal(failure.error.status, status);
    assert.equal(textOf(signed).includes(ANSWER_MARK), false);
    // The same answer on an existing read (decision trace by decisionId) gives the same error object.
    reset((pathname) => (pathname.startsWith(TRACE_PREFIX) ? answer : ok({})));
    const existing = await server.call('marrow_decision_trace', { decisionId: 'dec-fail' });
    assert.deepEqual(failure.error, failureOf(existing).error);
  });
}

test('M-3 signed export timeout: the structured request_timeout failure', async () => {
  reset((pathname) => (pathname.startsWith(SIGNED_PREFIX) ? 'hang' : ok({})));
  const message = await server.call('marrow_buyer_proof', { gateReceiptId: 'gr_slow' });
  assert.equal(message.result?.isError, true);
  assert.equal(message.result.content.length, 1);
  assert.equal(failureOf(message).error.code, 'request_timeout');
});

const REFUSED_BODIES = [
  ['over 65536 bytes', { status: 200, body: `{"pad":"${'a'.repeat(65_536)}","m":"${ANSWER_MARK}"}` }],
  ['not UTF-8', { status: 200, body: Buffer.concat([Buffer.from(`{"m":"${ANSWER_MARK}","x":"`), Buffer.from([0xff, 0xfe, 0xc3]), Buffer.from('"}')]) }],
  ['empty 200', { status: 200, body: '' }],
  ['201 instead of 200', { status: 201, body: `{"m":"${ANSWER_MARK}"}` }],
];

for (const [name, answer] of REFUSED_BODIES) {
  test(`M-4 signed export ${name}: fixed refusal, no partial text`, async () => {
    reset(signedPlan(answer));
    const message = await server.call('marrow_buyer_proof', { gateReceiptId: 'gr_big' });
    assert.equal(message.result?.isError, true);
    assert.equal(message.result.content.length, 1);
    assert.equal(failureOf(message).error.code, 'invalid_response');
    assert.equal(textOf(message).includes(ANSWER_MARK), false);
    assert.equal(textOf(message).includes('aaaaaaaa'), false);
  });
}

test('M-4 boundary: a body of exactly 65536 bytes passes through', async () => {
  const body = `{"pad":"${'b'.repeat(65_536 - 10)}"}`;
  assert.equal(Buffer.byteLength(body), 65_536);
  reset(signedPlan({ status: 200, body }));
  const message = await server.call('marrow_buyer_proof', { gateReceiptId: 'gr_edge' });
  assert.equal(textOf(message), body);
});

const BAD_IDS = ['', '../x', '%2e%2e', 'a/b', '\u0430bc', 'abc\n', 'abc?q', 'abc#', 'a b', ' abc', 'abc\u200b', '..', 'gr:1', 123, false, ['abc'], { id: 'abc' }];
const BAD_SIGNED_IDS = [...BAD_IDS, 'x'.repeat(129)];
const BAD_CHAIN_IDS = [...BAD_IDS, 'ab', '.abc', 'x'.repeat(201)];

test('M-5 marrow_buyer_proof refuses a bad gateReceiptId before any request', async () => {
  for (const bad of BAD_SIGNED_IDS) {
    reset(() => ok({ should_not: 'be read' }));
    const message = await server.call('marrow_buyer_proof', { gateReceiptId: bad });
    assert.equal(message.error?.code, -32602, `refused: ${JSON.stringify(bad)}`);
    assert.equal(relevant().length, 0, `no request for ${JSON.stringify(bad)}`);
  }
});

test('M-5 marrow_decision_trace refuses a bad gateReceiptId before any request', async () => {
  for (const bad of BAD_CHAIN_IDS) {
    reset(() => ok({ should_not: 'be read' }));
    const message = await server.call('marrow_decision_trace', { gateReceiptId: bad });
    assert.equal(message.error?.code, -32602, `refused: ${JSON.stringify(bad)}`);
    assert.equal(relevant().length, 0, `no request for ${JSON.stringify(bad)}`);
  }
});

test('M-6 marrow_decision_trace: both ids and neither are -32602 with no request; decisionId only reads the trace', async () => {
  reset((pathname) => (pathname.startsWith(TRACE_PREFIX) ? ok({ trace: { id: 'dec-1' } }) : ok({ chain: { id: 'x' } })));
  const both = await server.call('marrow_decision_trace', { decisionId: 'dec-1', gateReceiptId: 'gr_abc' });
  assert.equal(both.error?.code, -32602);
  assert.equal(relevant().length, 0);
  const neither = await server.call('marrow_decision_trace', {});
  assert.equal(neither.error?.code, -32602);
  assert.equal(neither.error.message, 'decisionId is required');
  assert.equal(relevant().length, 0);
  const only = await server.call('marrow_decision_trace', { decisionId: 'dec-1' });
  assert.equal(textOf(only), JSON.stringify({ trace: { id: 'dec-1' } }, null, 2));
  assert.equal(relevant().length, 1);
  assert.equal(relevant()[0].url, `${TRACE_PREFIX}dec-1`);
});

test('M-6 a null gateReceiptId counts as absent (the 3.9.115 answer)', async () => {
  reset((pathname) => (pathname.startsWith(TRACE_PREFIX) ? ok({ trace: { id: 'dec-2' } }) : ok({ proof: 1 })));
  const trace = await server.call('marrow_decision_trace', { decisionId: 'dec-2', gateReceiptId: null });
  assert.equal(textOf(trace), JSON.stringify({ trace: { id: 'dec-2' } }, null, 2));
  const proof = await server.call('marrow_buyer_proof', { gateReceiptId: null });
  assert.equal(textOf(proof), JSON.stringify({ proof: 1 }, null, 2));
  assert.deepEqual(relevant().map((r) => r.pathname), [`${TRACE_PREFIX}dec-2`, '/v1/agent/governance/buyer-proof']);
});

test('M-7 chain 200: {chain} exactly as parsed from data', async () => {
  const chain = { schema_version: 'gate_receipt_chain_v1', gate_receipt_id: 'gr_abc', links: [{ approval: 'reused', at: 1 }], note: '\u00e9' };
  reset((pathname) => (pathname.startsWith(CHAIN_PREFIX) ? ok({ chain, extra: 'not passed' }) : ok({ trace: 1 })));
  const message = await server.call('marrow_decision_trace', { gateReceiptId: 'gr_abc' });
  assert.equal(textOf(message), JSON.stringify({ chain }, null, 2));
  assert.equal(relevant().length, 1);
  assert.equal(relevant()[0].url, `${CHAIN_PREFIX}gr_abc`);
  assert.equal(relevant()[0].method, 'GET');
});

test('M-7 chain 404 and 400: structured failures with the backend code', async () => {
  reset((pathname) => (pathname.startsWith(CHAIN_PREFIX)
    ? agentErr(404, 'Gate receipt not found.', 'NOT_FOUND', { code: 'MARROW_GATE_RECEIPT_NOT_FOUND', retryable: false })
    : ok({ trace: 1 })));
  const missing = await server.call('marrow_decision_trace', { gateReceiptId: 'gr_missing' });
  assert.equal(missing.result?.isError, true);
  assert.equal(failureOf(missing).error.code, 'MARROW_GATE_RECEIPT_NOT_FOUND');
  assert.equal(failureOf(missing).error.status, 404);
  const fix = 'Use the gate_receipt_id exactly as POST /v1/agent/runtime returned it.';
  reset((pathname) => (pathname.startsWith(CHAIN_PREFIX)
    ? agentErr(400, 'Invalid gate receipt id.', 'BAD_REQUEST', { code: 'MARROW_GATE_RECEIPT_ID_INVALID', retryable: false, exact_fix: fix })
    : ok({ trace: 1 })));
  const invalid = await server.call('marrow_decision_trace', { gateReceiptId: 'gr_invalid' });
  assert.equal(failureOf(invalid).error.code, 'MARROW_GATE_RECEIPT_ID_INVALID');
  assert.equal(failureOf(invalid).error.exact_fix, fix);
  reset((pathname) => (pathname.startsWith(CHAIN_PREFIX) ? ok({ not_chain: true }) : ok({ trace: 1 })));
  const shapeless = await server.call('marrow_decision_trace', { gateReceiptId: 'gr_shape' });
  assert.equal(failureOf(shapeless).error.code, 'invalid_response');
});

const VALID_IDS = ['agent-a', 'agent.b:2', 'A_c-9'];
const BAD_LISTS = [
  ['65 entries', Array.from({ length: 65 }, (_, i) => `agent-${i}`)],
  ['empty list', []],
  ['non-string entry', ['agent-a', 7]],
  ['entry with a space', ['agent a']],
  ['entry with a newline', ['agent-a\n']],
  ['129 chars', ['a'.repeat(129)]],
  ['unicode', ['\u0430gent']],
  ['string, not an array', 'agent-a'],
  ['object', { 0: 'agent-a', length: 1 }],
  ['empty string entry', ['']],
];

const tracePlan = (answer) => (pathname) => (pathname.startsWith(TRACE_PREFIX) ? answer : ok({}));

test('M-8 403 MARROW_AGENT_SCOPE_MISMATCH with a valid list: allowed_agent_ids shown, one request, no retry', async () => {
  reset(tracePlan(scopeMismatch(VALID_IDS)));
  const message = await server.call('marrow_decision_trace', { decisionId: 'dec-scope' });
  const failure = failureOf(message);
  assert.equal(failure.error.code, 'MARROW_AGENT_SCOPE_MISMATCH');
  assert.deepEqual(failure.error.allowed_agent_ids, VALID_IDS);
  assert.equal(relevant().length, 1);
  // The 64-entry edge passes.
  const sixtyFour = Array.from({ length: 64 }, (_, i) => `agent-${i}`);
  reset(tracePlan(scopeMismatch(sixtyFour)));
  assert.deepEqual(failureOf(await server.call('marrow_decision_trace', { decisionId: 'dec-scope' })).error.allowed_agent_ids, sixtyFour);
});

for (const [name, list] of BAD_LISTS) {
  test(`M-8 403 MARROW_AGENT_SCOPE_MISMATCH with ${name}: allowed_agent_ids omitted, one request`, async () => {
    reset(tracePlan(scopeMismatch(list)));
    const failure = failureOf(await server.call('marrow_decision_trace', { decisionId: 'dec-scope' }));
    assert.equal(failure.error.code, 'MARROW_AGENT_SCOPE_MISMATCH');
    assert.equal(Object.hasOwn(failure.error, 'allowed_agent_ids'), false);
    assert.equal(relevant().length, 1);
  });
}

test('M-8 the member on another code or status is omitted', async () => {
  for (const answer of [
    agentErr(403, 'Permit required', 'FORBIDDEN', { code: 'ACTION_PERMIT_REQUIRED', allowed_agent_ids: VALID_IDS }),
    agentErr(400, 'Agent-bound key cannot access another agent.', 'BAD_REQUEST', { code: 'MARROW_AGENT_SCOPE_MISMATCH', allowed_agent_ids: VALID_IDS }),
    agentErr(404, 'Agent-bound key cannot access another agent.', 'NOT_FOUND', { code: 'MARROW_AGENT_SCOPE_MISMATCH', allowed_agent_ids: VALID_IDS }),
  ]) {
    reset(tracePlan(answer));
    const failure = failureOf(await server.call('marrow_decision_trace', { decisionId: 'dec-other' }));
    assert.equal(Object.hasOwn(failure.error, 'allowed_agent_ids'), false);
    assert.equal(relevant().length, 1);
  }
});

test('M-9 buyer_proof without the new input keeps its request and output', async () => {
  const data = { failures_avoided: 3, reliability_score: 0.9 };
  reset((pathname) => (pathname === '/v1/agent/governance/buyer-proof' ? ok(data) : ok({})));
  const message = await server.call('marrow_buyer_proof', { periodDays: 7 });
  assert.equal(textOf(message), JSON.stringify(data, null, 2));
  assert.equal(relevant().length, 1);
  assert.equal(relevant()[0].method, 'GET');
  assert.equal(relevant()[0].url, '/v1/agent/governance/buyer-proof?period_days=7');
});

test('M-10 tools/list: 17 primary tools; decision_trace and buyer_proof carry the optional gateReceiptId', async () => {
  for (const profile of [undefined, 'core', 'full']) {
    const listed = profile ? startServer(backend.base, { MARROW_TOOL_PROFILE: profile }) : server;
    try {
      await listed.ready;
      const { result } = await listed.request('tools/list', {});
      const names = result.tools.map((tool) => tool.name);
      if (profile === 'core') {
        // The core profile does not list either tool, before or after this change.
        assert.equal(names.includes('marrow_decision_trace') || names.includes('marrow_buyer_proof'), false);
        continue;
      }
      if (!profile) assert.equal(names.length, 17);
      const trace = result.tools.find((tool) => tool.name === 'marrow_decision_trace');
      const proof = result.tools.find((tool) => tool.name === 'marrow_buyer_proof');
      assert.deepEqual(Object.keys(trace.inputSchema.properties), ['decisionId', 'gateReceiptId']);
      assert.deepEqual(trace.inputSchema.required, []);
      assert.deepEqual(Object.keys(proof.inputSchema.properties), ['agentId', 'periodDays', 'gateReceiptId']);
      assert.deepEqual(proof.inputSchema.required, []);
      for (const tool of [trace, proof]) {
        assert.equal(tool.inputSchema.properties.gateReceiptId.type, 'string');
        assert.equal(/certified|tamper|immutable/i.test(JSON.stringify(tool)), false);
      }
    } finally {
      if (profile) { await listed.stop(); fs.rmSync(listed.home, { recursive: true, force: true }); }
    }
  }
});

test('M-12 signed path request: the read header set of the other reads, no agent_id query, no body', async () => {
  reset((pathname) => (pathname.startsWith(SIGNED_PREFIX) ? { status: 200, body: SIGNED_BODY } : ok({ chain: { id: 1 } })));
  await server.call('marrow_buyer_proof', { gateReceiptId: 'gr_hdr', agentId: 'agent-other', periodDays: 9 });
  await server.call('marrow_decision_trace', { gateReceiptId: 'gr_hdr' });
  const [signed, chain] = relevant();
  assert.equal(signed.method, 'GET');
  assert.equal(signed.url, `${SIGNED_PREFIX}gr_hdr`);
  assert.equal(signed.body, '');
  assert.deepEqual(Object.keys(signed.headers).sort(), Object.keys(chain.headers).sort());
  assert.equal(signed.headers.authorization, chain.headers.authorization);
});

test('M-11 the dummy key and the answer text reach no stderr, log or spool file', async () => {
  reset(signedPlan({ status: 200, body: SIGNED_BODY }));
  await server.call('marrow_buyer_proof', { gateReceiptId: 'gr_log' });
  const stderr = server.stderr();
  assert.equal(stderr.includes(server.key), false);
  assert.equal(stderr.includes(ANSWER_MARK), false);
  assert.equal(server.stdout().includes(server.key), false);
  for (const text of filesUnder(server.home)) {
    assert.equal(text.includes(server.key), false);
    assert.equal(text.includes(ANSWER_MARK), false);
  }
});
