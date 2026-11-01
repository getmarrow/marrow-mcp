'use strict';
// marrow_think must hand back the backend's answer for every answer shape, also when cached orient warnings exist and the
// answer has no `intelligence` object (it used to throw "Cannot set properties of undefined (setting 'insights')" after
// the decision was already created). The real stdio server runs against a fake loopback backend; the cached warnings come
// from the real path: the 5th think call starts refreshOrientWarnings, which asks POST /v1/agent/runtime. Dummy key made
// at run time; the server only dials https, so a preload (written to the private temp dir) points that one fake origin at
// the loopback backend and nothing leaves 127.0.0.1.
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');
const { dummySecret } = require('./support/dummy-secret.cjs');

const CLI = path.join(__dirname, '..', 'dist', 'cli.js');
const FAKE_ORIGIN = 'https://think-guard.invalid';
const WARNING = 'Synthetic caution from the fake backend';
const BACKEND_INSIGHT = { type: 'pattern', summary: 'backend insight kept', action: 'read it', severity: 'info', count: 2 };

// What the backend answers to a think, by shape key (carried in the action text).
const SHAPES = {
  a: { name: 'no intelligence', answer: () => ({ decision_id: 'dec-a', ok: true }) },
  b: { name: 'intelligence null', answer: () => ({ decision_id: 'dec-b', ok: true, intelligence: null }) },
  c: { name: 'intelligence array', answer: () => ({ decision_id: 'dec-c', ok: true, intelligence: [] }) },
  d: { name: 'intelligence {} without insights', answer: () => ({ decision_id: 'dec-d', ok: true, intelligence: {} }) },
  e: { name: 'intelligence with insights', answer: () => ({ decision_id: 'dec-e', ok: true, intelligence: { score: 3, insights: [BACKEND_INSIGHT] } }) },
  f: { name: 'intelligence string', answer: () => ({ decision_id: 'dec-f', ok: true, intelligence: 'text' }) },
  g: { name: 'intelligence number', answer: () => ({ decision_id: 'dec-g', ok: true, intelligence: 7 }) },
  h: { name: 'intelligence true', answer: () => ({ decision_id: 'dec-h', ok: true, intelligence: true }) },
};
const OBJECT_SHAPES = new Set(['d', 'e']);

/** The cached-warning entry BASE builds from one orient warning (type runtime_proceed, failureRate 0). */
const injected = (message) => ({
  type: 'failure_pattern', summary: message, action: 'Review past runtime_proceed failures before proceeding', severity: 'warning', count: 0,
});

function startBackend({ warn }) {
  const seen = { runtime: 0, think: 0 };
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      const send = (status, data) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify({ data })); };
      const url = req.url.split('?')[0];
      if (req.method === 'POST' && url === '/v1/agent/runtime') {
        seen.runtime += 1;
        return send(200, {
          response_mode: 'slim', decision: 'allow', risk_level: 'low', gate_required: false, proof_required: false, proof_complete: false,
          ...(warn ? { before_you_act: WARNING } : {}),
        });
      }
      if (req.method === 'POST' && url === '/v1/agent/think') {
        seen.think += 1;
        let body = {};
        try { body = JSON.parse(raw); } catch { /* an empty body answers like a plain think */ }
        const key = /^shape:(\w)\b/.exec(String(body.action || ''))?.[1];
        return send(200, key && SHAPES[key] ? SHAPES[key].answer() : { decision_id: 'dec-warmup', ok: true, intelligence: { insights: [] } });
      }
      return send(200, {});
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({
    seen, base: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((done) => server.close(done)),
  })));
}

/** One stdio MCP server process; `call` resolves the JSON-RPC response of a tools/call. */
function startServer(base) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-think-guard-'));
  const preload = path.join(home, 'to-loopback.cjs');
  fs.writeFileSync(preload, [
    'const real = globalThis.fetch;',
    `globalThis.fetch = (url, init) => real(String(url).replace(${JSON.stringify(FAKE_ORIGIN)}, ${JSON.stringify(base)}), init);`,
  ].join('\n'));
  const child = spawn(process.execPath, ['--require', preload, CLI], {
    cwd: home,
    env: {
      PATH: process.env.PATH, HOME: home, MARROW_API_KEY: dummySecret(), MARROW_BASE_URL: FAKE_ORIGIN,
      MARROW_AUTO_HOOK: 'false', MARROW_TOOL_PROFILE: 'full',
    },
    stdio: ['pipe', 'pipe', 'ignore'],
  });
  const waiting = new Map();
  let buffer = '';
  child.stdout.on('data', (chunk) => {
    buffer += chunk;
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
  const ready = request('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'think-guard-test', version: '1' } })
    .then(() => child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`));
  return {
    ready,
    call: (args) => request('tools/call', { name: 'marrow_think', arguments: args }),
    stop: () => { child.kill(); fs.rmSync(home, { recursive: true, force: true }); },
  };
}

const waitUntil = async (test, what) => {
  const end = Date.now() + 10_000;
  while (!test()) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
};

/** Real refresh path: think calls 1-5, the 5th asks /v1/agent/runtime; the 6th call and later see the cached result. */
async function warmUp(server, backend) {
  for (let i = 1; i <= 5; i += 1) {
    const reply = await server.call({ action: `warm-up ${i}` });
    assert.ok(!reply.error && !reply.result.isError, 'warm-up think calls answer');
  }
  await waitUntil(() => backend.seen.runtime >= 1, 'the orient refresh request');
  await new Promise((resolve) => setTimeout(resolve, 300));
}

const outputOf = (reply) => ({
  failed: Boolean(reply.error) || reply.result?.isError === true,
  text: reply.result?.content?.[0]?.text ?? JSON.stringify(reply.error ?? null),
});

/** All shapes x checkLoop x context on one warmed-up server. Returns Map "shape/checkLoop/context" -> output. */
async function runMatrix({ warn }) {
  const backend = await startBackend({ warn });
  const server = startServer(backend.base);
  const out = new Map();
  try {
    await server.ready;
    await warmUp(server, backend);
    for (const key of Object.keys(SHAPES)) {
      for (const checkLoop of [true, false]) {
        for (const withContext of [true, false]) {
          const args = { action: `shape:${key} think`, checkLoop, ...(withContext ? { context: { type: 'process' } } : {}) };
          out.set(`${key}/${checkLoop}/${withContext}`, outputOf(await server.call(args)));
        }
      }
    }
    assert.ok(backend.seen.think >= 5 + out.size, 'every think reached the fake backend');
  } finally {
    server.stop();
    await backend.close();
  }
  if (process.env.THINK_GUARD_DUMP) {
    const rows = [...out].map(([k, v]) => ({ k, warn, failed: v.failed, text: v.failed ? v.text.slice(0, 160) : v.text }));
    fs.appendFileSync(process.env.THINK_GUARD_DUMP, `${JSON.stringify({ warn, rows })}\n`);
  }
  return out;
}

const backendText = (key) => JSON.stringify(SHAPES[key].answer(), null, 2);
const combos = () => Object.keys(SHAPES).flatMap((key) => [true, false].flatMap((checkLoop) => [true, false].map((ctx) => [key, `${key}/${checkLoop}/${ctx}`])));

test('cached orient warnings are really set before the shapes are tried (real refresh path)', async () => {
  const backend = await startBackend({ warn: true });
  const server = startServer(backend.base);
  try {
    await server.ready;
    await warmUp(server, backend);
    const reply = outputOf(await server.call({ action: 'shape:d probe' }));
    assert.equal(reply.failed, false);
    assert.deepEqual(JSON.parse(reply.text).intelligence.insights, [injected(WARNING)]);
  } finally {
    server.stop();
    await backend.close();
  }
});

test('with cached warnings: shapes without an intelligence object return the backend answer unchanged (C2 a-c, f-h)', async () => {
  const out = await runMatrix({ warn: true });
  for (const [key, id] of combos().filter(([key]) => !OBJECT_SHAPES.has(key))) {
    const got = out.get(id);
    assert.equal(got.failed, false, `${id} (${SHAPES[key].name}) must not be a tool error: ${got.text.slice(0, 120)}`);
    assert.equal(got.text, backendText(key), `${id} (${SHAPES[key].name}) is byte-equal to the backend answer`);
    assert.match(got.text, /"decision_id": "dec-[a-h]"/, `${id} keeps the decision id`);
    assert.equal(got.text.includes(WARNING), false, `${id} carries no injected warning and no new intelligence object`);
  }
});

test('with cached warnings: an intelligence object gets the warnings first, then the backend insights (C2 d-e)', async () => {
  const out = await runMatrix({ warn: true });
  for (const [key, id] of combos().filter(([key]) => OBJECT_SHAPES.has(key))) {
    const got = out.get(id);
    assert.equal(got.failed, false, `${id} must not be a tool error`);
    const expected = SHAPES[key].answer();
    expected.intelligence.insights = [injected(WARNING), ...(expected.intelligence.insights || [])];
    assert.equal(got.text, JSON.stringify(expected, null, 2), `${id} (${SHAPES[key].name}) is built as BASE builds it`);
  }
  const e = JSON.parse(out.get('e/true/true').text).intelligence.insights;
  assert.deepEqual(e, [injected(WARNING), BACKEND_INSIGHT], 'warnings first, backend insight kept after them');
});

test('with NO cached warnings: every shape returns byte-equal to the backend answer', async () => {
  const out = await runMatrix({ warn: false });
  for (const [key, id] of combos()) {
    const got = out.get(id);
    assert.equal(got.failed, false, `${id} must not be a tool error`);
    assert.equal(got.text, backendText(key), `${id} (${SHAPES[key].name}) is untouched`);
  }
});
