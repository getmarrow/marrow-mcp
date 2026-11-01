'use strict';
// MCP-1 CUT (cut-mcp1): the identity-source text and `identity --explain` read NO config file. A hard link or a symlink at a
// fixed host-config path (or a plain config file there) must never be opened, on any entry point: server start, the tool 403,
// the credential-scope hook on three hosts, `identity --explain` and `identity --explain --json`. BASE (3.9.109) opens none.
// The trace is by inode: a preload wraps every fs call that opens a path (open, read, stream, promises) and logs the call when the
// path resolves to the inode of a dummy credential store or of a listed config path, whatever name it was reached by.
// Dummy files and dummy keys only: a fixed non-key prefix + runtime hex, each draw asserted NOT live-shaped.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const test = require('node:test');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const SCOPE_FIX = 'Use the fleet-bound agent identity for both the request body and header.';
const HOOK_NAME = { claude: 'claude-pre-action-hook', codex: 'codex-pre-action-hook', cursor: 'cursor-pre-action-hook' };
// MARROW_TRACE_ENTRIES narrows the entry points (a comparison run on BASE has no `identity` command); the default is all seven.
const ENTRIES = new Set((process.env.MARROW_TRACE_ENTRIES || 'start,tool,claude,codex,cursor,explain,explain-json').split(','));

// The credential stores a client must never open, by their usual names (dummy copies only).
const STORE_NAMES = ['.claude.json', 'settings.local.json', '.npmrc', '.git-credentials', 'fleet.env', 'hosts.yml', 'auth.json', '.hermes/config.yaml'];

function dummyKey() {
  const key = `zzfixture-${crypto.randomBytes(12).toString('hex')}`;
  assert.doesNotMatch(key, /^(?:sk|pk|rk)_|^gh[pousr]_|^xox[a-z]-|^AKIA|^AIza|^eyJ/, 'dummy key must classify NOT_LIVE');
  return key;
}

function scratch(prefix) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), `marrow-mcp-cutopen-${prefix}-`)));
  fs.chmodSync(dir, 0o700);
  return dir;
}

function writeFile(file, text, mode = 0o600) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, text, { mode });
  fs.chmodSync(file, mode);
  return file;
}

const mcpJson = (block) => JSON.stringify({ mcpServers: { marrow: { command: 'npx', args: ['-y', '@getmarrow/mcp'], env: block } } });

/** The six host config paths the removed lookup used to open (the fixed list of the round-1 build). */
function listedConfigPaths(home, cwd) {
  return [
    path.join(home, '.mcp.json'),
    path.join(cwd, '.mcp.json'),
    path.join(home, '.cursor', 'mcp.json'),
    path.join(cwd, '.cursor', 'mcp.json'),
    path.join(home, '.codex', 'config.toml'),
    path.join(home, '.gemini', 'settings.json'),
  ];
}

// ---- the open tracer (preload) ----------------------------------------------------------------------------------------

const TRACE_SOURCE = `
'use strict';
const fs = require('node:fs');
const stat = fs.statSync.bind(fs);
const append = fs.appendFileSync.bind(fs);
const watch = new Set(JSON.parse(process.env.TRACE_INODES || '[]'));
let busy = false;
function note(fn, target) {
  if (busy || typeof target === 'number') return;
  busy = true;
  try {
    const s = stat(target instanceof URL ? target : Buffer.isBuffer(target) ? target.toString() : String(target));
    const id = s.dev + ':' + s.ino;
    if (watch.has(id)) append(process.env.TRACE_LOG, fn + ' ' + id + '\\n');
  } catch { /* not a path that exists: nothing was opened */ } finally { busy = false; }
}
function wrap(holder, fn) {
  const real = holder[fn];
  if (typeof real !== 'function') return;
  holder[fn] = function (target, ...rest) { note(fn, target); return real.call(this, target, ...rest); };
}
for (const fn of ['openSync', 'open', 'readFileSync', 'readFile', 'createReadStream', 'openAsBlob', 'copyFileSync', 'copyFile']) wrap(fs, fn);
for (const fn of ['open', 'readFile', 'copyFile']) wrap(fs.promises, fn);
`;

function installTracer(root) {
  const file = path.join(root, 'trace-opens.cjs');
  fs.writeFileSync(file, TRACE_SOURCE, { mode: 0o600 });
  return file;
}

const inodeOf = (file) => { const s = fs.statSync(file); return `${s.dev}:${s.ino}`; };

/** One case: dummy stores, the six listed paths linked (or written) per `kind`, and the set of inodes the tracer watches. */
function makeCase(prefix, kind, storeName) {
  const root = scratch(prefix);
  const home = path.join(root, 'home');
  const cwd = path.join(root, 'cwd');
  for (const dir of [home, cwd]) { fs.mkdirSync(dir, { mode: 0o700 }); fs.chmodSync(dir, 0o700); }
  const key = dummyKey();
  const id = `agent-${crypto.randomBytes(4).toString('hex')}`;
  const stores = STORE_NAMES.map((name) => writeFile(path.join(root, 'stores', name), mcpJson({ MARROW_FLEET_AGENT_ID: id, MARROW_API_KEY: key })));
  const listed = listedConfigPaths(home, cwd);
  const store = stores[STORE_NAMES.indexOf(storeName)];
  for (const file of listed) {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    if (kind === 'hardlink') fs.linkSync(store, file);
    else if (kind === 'symlink') fs.symlinkSync(store, file);
    else writeFile(file, file.endsWith('.toml')
      ? `[mcp_servers.marrow.env]\nMARROW_FLEET_AGENT_ID = "${id}"\n`
      : mcpJson({ MARROW_FLEET_AGENT_ID: id }));
  }
  const inodes = new Set([...stores, ...listed].map(inodeOf));
  const log = path.join(root, 'trace.log');
  fs.writeFileSync(log, '');
  return { root, home, cwd, key, id, store, listed, log, tracer: installTracer(root), inodes: JSON.stringify([...inodes]), cleanup() { fs.rmSync(root, { recursive: true, force: true }); } };
}

const traceEnv = (fx) => ({ TRACE_INODES: fx.inodes, TRACE_LOG: fx.log });
const traceLines = (fx) => fs.readFileSync(fx.log, 'utf8').split('\n').filter(Boolean);

/** Nothing the child printed or sent holds the dummy key, a prefix of it, the id source file contents or a store path. */
function assertNoLeak(fx, ...texts) {
  const blob = texts.join('\n');
  assert.ok(!blob.includes(fx.key) && !blob.includes(fx.key.slice(0, 12)), 'the dummy key (or its first 12 characters) appeared in an output');
  assert.ok(!blob.includes(fx.root), 'an absolute scratch path appeared in an output');
}

// ---- entry points ------------------------------------------------------------------------------------------------------

function baseEnv(fx, env) {
  return { PATH: process.env.PATH, HOME: fx.home, USERPROFILE: fx.home, MARROW_API_KEY: fx.key, MARROW_FLEET_AGENT_ID: fx.id, ...traceEnv(fx), ...env };
}

function runServer(fx, frames) {
  const mock = path.join(fx.root, 'scope-fetch.cjs');
  fs.writeFileSync(mock, `
globalThis.fetch = async () => Response.json({
  error: 'Agent identity does not match the key binding.',
  details: { code: 'MARROW_AGENT_SCOPE_MISMATCH', exact_fix: ${JSON.stringify(SCOPE_FIX)} },
}, { status: 403 });
`, { mode: 0o600 });
  const input = frames.map((row) => JSON.stringify(row)).join('\n') + '\n';
  return spawnSync(process.execPath, ['--require', fx.tracer, '--require', mock, CLI], {
    cwd: fx.cwd, input, encoding: 'utf8', timeout: 30_000,
    env: baseEnv(fx, { MARROW_BASE_URL: 'https://127.0.0.1:9', MARROW_AUTO_ENROLL: 'false', MARROW_TOOL_PROFILE: 'core', MARROW_REQUEST_TIMEOUT_MS: '3000' }),
  });
}

const INIT = { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} };
const CALL = { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'marrow_agent_runtime', arguments: { action: 'inspect a local note', type: 'general' } } };

function startFakeService() {
  const seen = [];
  const server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      const pathname = new URL(req.url, 'http://fake.invalid').pathname;
      seen.push({ path: pathname, body: raw });
      const body = raw ? JSON.parse(raw) : {};
      const send = (status, value) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(value)); };
      if (pathname === '/v1/agent/integrations/events') return send(200, { data: { accepted: true } });
      if (pathname === '/v1/agent/commit') return send(200, { data: { committed: true, decision_id: body.decision_id } });
      if (pathname === '/v1/agent/think') return send(200, { data: { decision_id: 'decision-think' } });
      if (pathname === '/v1/agent/runtime') {
        return send(200, { data: {
          runtime_authorization: { id: 'fast_gate_one', durable: false, decision_creation_required: true },
          completion_contract: { decision_creation_required: true },
          risk_gate: { allow: true, decision: 'allow', enforced: true, reasons: [] },
          gate_receipt_id: 'fast_gate_one', before_you_act: 'Proceed with the low-risk work.', proof_pack: { fields: [] },
        } });
      }
      if (pathname === '/v1/agent/enforcement') return send(403, { error: 'synthetic-private-service-text', code: 'MARROW_AGENT_SCOPE_MISMATCH' });
      return send(404, { error: 'unexpected' });
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ seen, port: server.address().port, close: () => new Promise((done) => server.close(done)) })));
}

function hookEvent(host, cwd) {
  return host === 'cursor'
    ? { hook_event_name: 'beforeShellExecution', conversation_id: 'c1', generation_id: 'g1', command: 'wrangler deploy production', cwd }
    : { hook_event_name: 'PreToolUse', tool_name: 'Bash', permission_mode: 'default', session_id: 'session-one', tool_input: { command: 'wrangler deploy production' }, tool_use_id: 'tool-use-one', cwd };
}

async function runHook(fx, host) {
  const service = await startFakeService();
  try {
    const redirect = path.join(fx.root, 'redirect-fetch.cjs');
    fs.writeFileSync(redirect, "const real = globalThis.fetch; globalThis.fetch = (u, i) => real(String(u).replace(/^https:\\/\\/api\\.example\\.test/, `http://127.0.0.1:${process.env.FAKE_PORT}`), i);\n");
    const child = spawn(process.execPath, ['--require', fx.tracer, '--require', redirect, CLI, HOOK_NAME[host]], {
      cwd: fx.cwd,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: baseEnv(fx, { FAKE_PORT: String(service.port), MARROW_BASE_URL: 'https://api.example.test', MARROW_SESSION_ID: 'session-one',
        MARROW_EVENT_SPOOL_PATH: path.join(fx.root, 'spool.json'), MARROW_HOOK_BACKGROUND_NUDGE: 'false' }),
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (chunk) => { out += chunk; });
    child.stderr.on('data', (chunk) => { err += chunk; });
    const killer = setTimeout(() => child.kill('SIGKILL'), 60_000);
    await new Promise((resolve) => { child.on('close', resolve); child.stdin.end(JSON.stringify(hookEvent(host, fx.cwd))); });
    clearTimeout(killer);
    const answer = out.trim() ? JSON.parse(out) : null;
    const reason = host === 'cursor' ? answer?.agent_message : answer?.hookSpecificOutput?.permissionDecisionReason;
    return { out, err, reason, seen: service.seen };
  } finally { await service.close(); }
}

async function traceAllEntries(fx) {
  const outputs = [];
  const answers = {};
  if (ENTRIES.has('start')) {
    const run = runServer(fx, [INIT]);
    assert.ok(run.stdout.includes('"id":1'), `server start did not answer initialize: ${run.stderr.slice(0, 200)}`);
    outputs.push(run.stdout, run.stderr);
  }
  if (ENTRIES.has('tool')) {
    const run = runServer(fx, [INIT, CALL]);
    const call = run.stdout.trim().split('\n').filter(Boolean).map((line) => JSON.parse(line)).find((row) => row.id === 3);
    assert.ok(call, `no tools/call answer: ${run.stderr.slice(0, 200)}`);
    assert.match(JSON.parse(call.result.content[0].text).error.message, /MARROW_AGENT_SCOPE_MISMATCH|not authorized|does not match/i);
    outputs.push(run.stdout, run.stderr);
  }
  for (const host of ['claude', 'codex', 'cursor']) {
    if (!ENTRIES.has(host)) continue;
    const run = await runHook(fx, host);
    assert.match(run.reason || '', /This Marrow API key is not authorized to obtain action permits for agent/, `${host}: the hook did not answer the credential-scope deny`);
    outputs.push(run.out, run.err, ...run.seen.map((r) => r.body));
  }
  for (const [name, args] of [['explain', ['identity', '--explain']], ['explain-json', ['identity', '--explain', '--json']]]) {
    if (!ENTRIES.has(name)) continue;
    const run = spawnSync(process.execPath, ['--require', fx.tracer, CLI, ...args], { cwd: fx.cwd, encoding: 'utf8', timeout: 20_000, env: baseEnv(fx, {}) });
    assert.equal(run.status, 0, `${name}: exit ${run.status}: ${run.stderr.slice(0, 200)}`);
    answers[name] = run.stdout;
    outputs.push(run.stdout, run.stderr);
  }
  return { outputs, answers };
}

/** The trace first (the claim of this file), then the answers that show the entry points really ran. */
function assertCase(fx, run, label) {
  assert.deepEqual(traceLines(fx), [], `an open of a listed config path or credential store was traced (${label})`);
  assertNoLeak(fx, ...run.outputs);
  if (run.answers['explain-json']) assert.deepEqual(JSON.parse(run.answers['explain-json']), { agent_id: fx.id, variable: 'MARROW_FLEET_AGENT_ID', origin: 'process_env', file: null });
}

// =====================================================================================================================
// the tracer itself: it must see an open however it is spelled (otherwise "0 opens" proves nothing)
// =====================================================================================================================
test('C1 tracer control: openSync, readFileSync, a stream and promises.readFile through a hard link AND a symlink are all logged', async () => {
  const fx = makeCase('control', 'hardlink', '.claude.json');
  try {
    const link = fx.listed[0];
    const sym = path.join(fx.root, 'sym-to-store');
    fs.symlinkSync(fx.store, sym);
    const script = `
const fs = require('node:fs');
const [link, sym] = process.argv.slice(1);
fs.closeSync(fs.openSync(link, 'r'));
fs.readFileSync(link, 'utf8');
fs.readFile(link, () => {});
fs.createReadStream(link).on('error', () => {}).destroy();
fs.promises.readFile(link).then(() => fs.promises.open(sym, 'r')).then((h) => h.close());
fs.readFileSync(sym);
`;
    const run = spawnSync(process.execPath, ['--require', fx.tracer, '-e', script, link, sym], { encoding: 'utf8', timeout: 20_000, env: { PATH: process.env.PATH, ...traceEnv(fx) } });
    assert.equal(run.status, 0, run.stderr);
    const seen = new Set(traceLines(fx).map((line) => line.split(' ')[0]));
    for (const fn of ['openSync', 'readFileSync', 'readFile', 'createReadStream']) assert.ok(seen.has(fn), `the tracer missed ${fn}`);
    assert.ok(seen.has('open'), 'the tracer missed promises.open through the symlink');
  } finally { fx.cleanup(); }
});

// =====================================================================================================================
// C1  the matrix: 8 credential stores x hard link / symlink at every listed path, plus a plain config file at every listed path
// =====================================================================================================================
for (const kind of ['hardlink', 'symlink']) {
  for (const storeName of STORE_NAMES) {
    test(`C1 ${kind} at all six listed config paths to a dummy ${storeName}: 0 opens on server start, tool 403, three hooks, identity --explain (text, JSON)`, async () => {
      const fx = makeCase(`${kind}-${storeName.replace(/\W+/g, '')}`, kind, storeName);
      try {
        assertCase(fx, await traceAllEntries(fx), `${kind}, ${storeName}`);
      } finally { fx.cleanup(); }
    });
  }
}

test('C1 a plain config file (the marrow env block holds the id) at all six listed paths: 0 opens on every entry point', async () => {
  const fx = makeCase('plain', 'plain', '.claude.json');
  try {
    assertCase(fx, await traceAllEntries(fx), 'plain config files');
  } finally { fx.cleanup(); }
});

// =====================================================================================================================
// C1  no code path left that could read one: the added modules import no file-system API and the removed names are gone
// =====================================================================================================================
test('C1 the identity-source module imports no fs and the config-file reader and fixed list are gone from src and dist', () => {
  const source = fs.readFileSync(path.join(ROOT, 'src', 'identity-explain.ts'), 'utf8');
  assert.doesNotMatch(source, /from 'fs'|from 'node:fs'|require\('fs'\)|require\('node:fs'\)/, 'identity-explain.ts imports fs');
  assert.doesNotMatch(source, /parseToml|readMarrowEnvBlock|agentIdConfigFiles|openSync|readFileSync|lstatSync/);
  const built = fs.readFileSync(path.join(ROOT, 'dist', 'identity-explain.js'), 'utf8');
  assert.doesNotMatch(built, /readMarrowEnvBlock|agentIdConfigFiles|openSync|readFileSync|lstatSync/);
  for (const file of ['env.ts', 'cli.ts', 'hook-pre-action.ts', 'index.ts']) {
    const text = fs.existsSync(path.join(ROOT, 'src', file)) ? fs.readFileSync(path.join(ROOT, 'src', file), 'utf8') : '';
    assert.doesNotMatch(text, /agentIdConfigFiles|readMarrowEnvBlock/, `${file} still names the removed lookup`);
  }
});
