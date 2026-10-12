'use strict';
// marrow_decision_brief, marrow_workflow and marrow_retrieve_memories send
// user text redacted, like marrow_ask: on the index function path and on the
// MCP stdio path. Runtime dummies only; only booleans are compared, nothing
// is printed.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');

const { marrowDecisionBrief, marrowWorkflow } = require('../dist/index.js');

const CLI = path.join(__dirname, '..', 'dist', 'cli.js');
const PRELOAD = path.join(__dirname, 'support', 'fetch-capture.cjs');

const hex = () => crypto.randomBytes(12).toString('hex');
const b64 = () => crypto.randomBytes(18).toString('base64');

// Every shape the shared redactor covers; each keeps the text after it (" then <tail>").
const SHAPES = [
  ['--token=', hex, (s) => `deploy --token=${s}`],
  ['--api-key value', hex, (s) => `run --api-key ${s}`],
  ['Bearer', hex, (s) => `Authorization: Bearer ${s}x`],
  ['NAME=value', hex, (s) => `STRIPE_SECRET=${s}`],
  ['NAME: value', hex, (s) => `DB_PASSWORD: ${s}`],
  ['Marrow key', hex, (s) => `key mrw_${s}`],
  ['sk_ token', hex, (s) => `use sk_${s}`],
  ['URL ?token=', hex, (s) => `https://a.example/x?token=${s}&next=1`],
  ['JSON "api_key": "v"', hex, (s) => `{"api_key": "${s}", "env": "x"}`],
  ['JSON "password":"v"', hex, (s) => `{"password":"${s}","env":"x"}`],
  ['URL userinfo', hex, (s) => `postgres://admin:${s}@db.example/app`],
  ['Authorization: Basic', b64, (s) => `Authorization: Basic ${s}`],
  ['Proxy-Authorization: Basic', b64, (s) => `Proxy-Authorization: Basic ${s}`],
];

function leaks(text, secret) {
  for (let i = 0; i + 8 <= secret.length; i += 1) if (text.includes(secret.slice(i, i + 8))) return true;
  return false;
}

/** Every outgoing request of one in-process call, captured. */
async function capture(run) {
  const original = globalThis.fetch;
  const sent = [];
  globalThis.fetch = async (url, init = {}) => {
    sent.push({ url: String(url), body: typeof init.body === 'string' ? init.body : '' });
    return new Response(JSON.stringify({ data: { ok: true } }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  try { await run(); } catch { /* the response shape does not matter here */ } finally { globalThis.fetch = original; }
  return sent.map((r) => `${decodeURIComponent(r.url)}\n${r.body}`).join('\n');
}

function texts(shape, tail) {
  return (s) => `${shape(s)} then ${tail}`;
}

/** One workflow call per action, every user-text field carrying the text. */
function workflowCalls(text) {
  return [
    { action: 'register', name: text('n'), description: text('d'), steps: [{ step: 1, description: text('s') }], tags: [text('t')] },
    { action: 'update', workflowId: 'wf_1', name: text('n'), description: text('d'), tags: [text('t')] },
    { action: 'list', tags: [text('t')] },
    { action: 'start', workflowId: 'wf_1', agentId: 'agent', context: { note: text('c'), deep: { list: [text('c2')] } }, inputs: { prompt: text('i') } },
    { action: 'advance', workflowId: 'wf_1', instanceId: 'in_1', stepCompleted: 1, outcome: text('o'), contextUpdate: { note: text('u') } },
  ];
}

const KEY = () => `mrw_${hex()}${hex()}`;

for (const [name, gen, shape] of SHAPES) {
  test(`index path: ${name} never leaves marrow_decision_brief or marrow_workflow`, async () => {
    const s1 = gen();
    const s2 = gen();
    const staging = texts(shape, 'staging');
    const production = texts(shape, 'production');
    const brief = (s, f) => capture(() => marrowDecisionBrief(KEY(), 'https://api.example.invalid', { action: f(s), target: f(s) }, 'sess', 'agent'));
    const workflow = (s, f) => capture(async () => { for (const call of workflowCalls((field) => `${field}:${f(s)}`)) await marrowWorkflow(KEY(), 'https://api.example.invalid', call, 'sess', 'agent'); });
    for (const send of [brief, workflow]) {
      const a = await send(s1, staging);
      const b = await send(s1, production);
      const c = await send(s2, staging);
      assert.equal(a.length > 0, true, 'a request was sent');
      assert.equal(leaks(a, s1) || leaks(b, s1) || leaks(c, s2), false, 'no 8-character slice of the dummy leaves the process');
      assert.equal(a.includes('then staging'), true, 'the text after the secret is kept');
      assert.notEqual(a, b, 'texts that differ after the secret stay different');
      assert.equal(a, c, 'texts that differ only in the secret are sent alike');
    }
  });
}

test('workflow redaction keeps the structure: every step, tag and nested value', async () => {
  const s = hex();
  const steps = Array.from({ length: 25 }, (_, i) => ({ step: i + 1, description: `step ${i} TOKEN=${s} done` }));
  const sent = await capture(() => marrowWorkflow(KEY(), 'https://api.example.invalid', { action: 'register', name: 'w', description: 'd', steps, tags: ['a'] }, 'sess', 'agent'));
  const body = JSON.parse(sent.split('\n').slice(1).join('\n'));
  assert.equal(body.steps.length, 25);
  assert.equal(body.steps[24].description, 'step 24 TOKEN=[REDACTED] done');
  assert.equal(body.steps[24].step, 25);
});

/** One MCP stdio session: initialize, then each call in turn; returns every captured request. */
function viaCli(calls) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tool-redact-'));
  const capFile = path.join(dir, 'cap.jsonl');
  fs.writeFileSync(capFile, '');
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['--require', PRELOAD, CLI], {
      env: {
        PATH: process.env.PATH,
        HOME: dir,
        MARROW_API_KEY: KEY(),
        MARROW_BASE_URL: 'https://api.example.invalid',
        MARROW_AUTO_HOOK: 'false',
        MARROW_TOOL_PROFILE: 'full',
        CAPTURE_FILE: capFile,
      },
      stdio: ['pipe', 'pipe', 'ignore'],
    });
    let out = '';
    let next = 0;
    const lastId = 100 + calls.length - 1;
    const send = (message) => child.stdin.write(`${JSON.stringify(message)}\n`);
    const sendNext = () => {
      if (next >= calls.length) return;
      const [tool, args] = calls[next];
      send({ jsonrpc: '2.0', id: 100 + next, method: 'tools/call', params: { name: tool, arguments: args } });
      next += 1;
    };
    child.stdout.on('data', (chunk) => {
      out += chunk;
      if (out.includes('"id":1,') && next === 0) { send({ jsonrpc: '2.0', method: 'notifications/initialized' }); sendNext(); }
      for (let id = 100; id < 100 + next; id += 1) {
        if (out.includes(`"id":${id},`) && id === 100 + next - 1) sendNext();
      }
      if (out.includes(`"id":${lastId},`)) child.kill();
    });
    const timer = setTimeout(() => child.kill(), 30_000);
    child.on('exit', () => {
      clearTimeout(timer);
      const lines = fs.readFileSync(capFile, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line));
      fs.rmSync(dir, { recursive: true, force: true });
      resolve(lines);
    });
    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } } });
  });
}

test('MCP stdio path: decision brief, workflow and memory query are sent redacted, the text after kept', { timeout: 120_000 }, async () => {
  const secrets = SHAPES.map(([, gen]) => gen());
  const text = (tail) => SHAPES.map(([, , shape], i) => `${shape(secrets[i])} then ${tail}`).join(' | ');
  const calls = [
    ['marrow_decision_brief', { action: text('brief-tail') }],
    ['marrow_retrieve_memories', { query: text('memory-tail') }],
    ...workflowCalls((field) => `${field}:${text('workflow-tail')}`).map((call) => ['marrow_workflow', call]),
  ];
  const sent = await viaCli(calls);
  const urls = sent.map((r) => r.url);
  assert.equal(urls.some((u) => u.includes('/v1/analytics/decision-brief')), true, 'the brief was sent');
  assert.equal(urls.some((u) => u.includes('/v1/memories/retrieve')), true, 'the memory query was sent');
  assert.equal(urls.filter((u) => u.includes('/v1/workflows')).length >= 5, true, 'every workflow call was sent');
  const all = sent.map((r) => `${decodeURIComponent(r.url.replace(/\+/g, ' '))}\n${r.body}`).join('\n');
  for (const s of secrets) assert.equal(leaks(all, s), false, 'no 8-character slice of any dummy leaves the process');
  const brief = sent.find((r) => r.url.includes('decision-brief'));
  assert.equal(JSON.parse(brief.body).action.includes('then brief-tail'), true);
  const memory = sent.find((r) => r.url.includes('/v1/memories/retrieve'));
  assert.equal(new URL(memory.url).searchParams.get('q').includes('then memory-tail'), true);
  const register = sent.find((r) => r.url.endsWith('/v1/workflows/register'));
  assert.equal(JSON.parse(register.body).steps[0].description.includes('then workflow-tail'), true);
});
