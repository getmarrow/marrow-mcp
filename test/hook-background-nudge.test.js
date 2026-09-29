// Real detached-process path: `marrow-mcp claude-hook` + its background-nudge child,
// against a loopback HTTPS server. Offline (127.0.0.1 only).
const test = require('node:test');
const assert = require('node:assert/strict');
const https = require('node:https');
const { spawn, execFileSync } = require('node:child_process');
const { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync, existsSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');

const CLI = resolve(__dirname, '../dist/cli.js');
const KEY = 'mrw_bg_nudge_test_key_1';

let opensslOk = true;
try { execFileSync('openssl', ['version'], { stdio: 'ignore' }); } catch { opensslOk = false; }

function makeCert(dir) {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'k.pem'),
    '-out', join(dir, 'c.pem'), '-days', '1', '-subj', '/CN=127.0.0.1',
    '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
  return { key: readFileSync(join(dir, 'k.pem')), cert: readFileSync(join(dir, 'c.pem')), certPath: join(dir, 'c.pem') };
}

async function withEnv(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-mcp-bgnudge-'));
  const cert = makeCert(dir);
  const events = [];
  const server = https.createServer({ key: cert.key, cert: cert.cert }, (req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      if (req.url === '/v1/agent/integrations/events') events.push(JSON.parse(body || '{}'));
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"data":{"accepted":true}}');
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const home = join(dir, 'home');
  mkdirSync(home, { mode: 0o700 });
  const env = {
    PATH: process.env.PATH, HOME: home, MARROW_API_KEY: KEY,
    MARROW_BASE_URL: `https://127.0.0.1:${server.address().port}`,
    MARROW_PASSIVE_TOKEN_USAGE: 'false', NODE_EXTRA_CA_CERTS: cert.certPath,
  };
  try { await fn({ dir, home, env, events }); } finally {
    server.close(); rmSync(dir, { recursive: true, force: true });
  }
}

function runHook(env, payload, extra = {}) {
  return new Promise((resolveRun) => {
    const started = Date.now();
    const child = spawn(process.execPath, [CLI, 'claude-hook'], { env: { ...env, ...extra }, stdio: ['pipe', 'ignore', 'ignore'] });
    child.stdin.end(JSON.stringify(payload));
    child.on('exit', () => resolveRun(Date.now() - started));
  });
}

const spoolDir = (home) => join(home, '.marrow', 'spool');
const locks = (home) => existsSync(spoolDir(home)) ? readdirSync(spoolDir(home)).filter((f) => f.endsWith('.nudge.lock')) : [];
async function until(cond, ms = 15_000) {
  const end = Date.now() + ms;
  while (Date.now() < end) { if (cond()) return true; await new Promise((r) => setTimeout(r, 100)); }
  return cond();
}
const write = (id) => ({ session_id: 's', hook_event_name: 'PostToolUse', tool_name: 'Write',
  tool_input: { file_path: '/tmp/x', content: 'a' }, tool_response: { ok: true }, tool_use_id: id });

test('PostToolUse spools and a detached background-nudge process delivers it, then releases its lock', { skip: !opensslOk }, () => withEnv(async ({ home, env, events }) => {
  await runHook(env, write('t1'));
  assert.equal(await until(() => events.length === 1), true, 'child delivered exactly one event');
  assert.equal(await until(() => locks(home).length === 0), true, 'lock released by the owning child');
  await new Promise((r) => setTimeout(r, 500));
  assert.equal(events.length, 1);
}));

test('MARROW_AUTO_HOOK=false does not launch a nudge even with a queued event', { skip: !opensslOk }, () => withEnv(async ({ home, env, events }) => {
  const { recordLifecycleEvent } = require('../dist/lifecycle-spool.js');
  const previousHome = process.env.HOME; process.env.HOME = home;
  try {
    await recordLifecycleEvent({ apiKey: KEY, baseUrl: env.MARROW_BASE_URL, deferDelivery: true,
      event: { event_id: 'queued-1', event_type: 'tool_completed', action: 'tool execution observed', outcome_state: 'pending', success: true } });
  } finally { process.env.HOME = previousHome; }
  await runHook(env, write('t2'), { MARROW_AUTO_HOOK: 'false' });
  await new Promise((r) => setTimeout(r, 1500));
  assert.equal(events.length, 0);
  assert.deepEqual(locks(home), []);
}));

test('a read-only PostToolUse launches nothing and never reads spool namespaces', { skip: !opensslOk }, () => withEnv(async ({ dir, home, env, events }) => {
  mkdirSync(spoolDir(home), { recursive: true, mode: 0o700 });
  writeFileSync(join(spoolDir(home), 'mcp-otherotherother0000.json'), '[]', { mode: 0o600 });
  const log = join(dir, 'fs.log');
  writeFileSync(join(dir, 'trace.js'), `
    const fs = require('node:fs'); const dir = ${JSON.stringify(spoolDir(home))};
    for (const name of ['readFileSync', 'openSync', 'readdirSync', 'opendirSync', 'statSync', 'lstatSync', 'readdir']) {
      const orig = fs[name]; if (!orig) continue;
      fs[name] = function (p, ...rest) { if (typeof p === 'string' && p.startsWith(dir)) fs.appendFileSync(${JSON.stringify(log)}, name + ' ' + p + '\\n'); return orig.call(this, p, ...rest); };
    }`);
  await runHook(env, { session_id: 's', hook_event_name: 'PostToolUse', tool_name: 'Read',
    tool_input: { file_path: '/tmp/x' }, tool_response: { content: 'x' }, tool_use_id: 'ro1' },
  { NODE_OPTIONS: `--require ${join(dir, 'trace.js')}` });
  await new Promise((r) => setTimeout(r, 800));
  assert.equal(existsSync(log) ? readFileSync(log, 'utf8') : '', '', 'no spool path touched');
  assert.equal(events.length, 0);
  assert.deepEqual(locks(home), []);
}));

test('MARROW_HOOK_BACKGROUND_NUDGE=false falls back to bounded inline delivery with no child', { skip: !opensslOk }, () => withEnv(async ({ home, env, events }) => {
  await runHook(env, write('t3'), { MARROW_HOOK_BACKGROUND_NUDGE: 'false' });
  assert.equal(events.length, 1, 'delivered inline by the hook itself');
  assert.deepEqual(locks(home), []);
}));
