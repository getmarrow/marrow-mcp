'use strict';
// MCP-1 CUT (cut-mcp1, cut2-mcp1): the identity-source sentence of the tool 403 reads NO config file and adds NO read of the owner
// key file. A hard link or a symlink at a fixed host-config path (or a plain config file there) must never be opened, on any entry
// point: server start, the tool 403, the credential-scope hook on three hosts. BASE (3.9.109) opens none.
// The owner-file rows (C1 owner file) count the opens of ~/.marrow/env itself when the key lives only there: every entry opens it
// exactly as often as BASE does (once), and each row proves its branch ran before the count is read (REACHED).
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
// MARROW_TRACE_ENTRIES narrows the entry points; the default is all five.
const ENTRIES = new Set((process.env.MARROW_TRACE_ENTRIES || 'start,tool,claude,codex,cursor').split(','));

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
const owner = process.env.TRACE_OWNER_INODE || '';
let busy = false;
function note(fn, target) {
  if (busy || typeof target === 'number') return;
  busy = true;
  try {
    const s = stat(target instanceof URL ? target : Buffer.isBuffer(target) ? target.toString() : String(target));
    const id = s.dev + ':' + s.ino;
    if (watch.has(id)) append(process.env.TRACE_LOG, fn + ' ' + id + '\\n');
    if (owner && id === owner) append(process.env.TRACE_OWNER_LOG, fn + ' ' + id + '\\n');
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
function makeCase(prefix, kind, storeName, { ownerKey = false } = {}) {
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
  // The owner key file: the key lives ONLY here (no key in the process environment); it names its own service, as the owner file does.
  const ownerLog = path.join(root, 'trace-owner.log');
  fs.writeFileSync(ownerLog, '');
  const owner = path.join(home, '.marrow', 'env');
  const strayKey = ownerKey === 'stray' ? dummyKey() : '';
  if (ownerKey) writeFile(owner, `MARROW_API_KEY=${ownerKey === 'stray' ? strayKey : key}\nMARROW_BASE_URL=https://api.example.test\nMARROW_FLEET_AGENT_ID=${id}\n`);
  return { root, home, cwd, key, strayKey, id, store, listed, log, ownerKey, owner, ownerLog, ownerInode: ownerKey ? inodeOf(owner) : '', tracer: installTracer(root), inodes: JSON.stringify([...inodes]), cleanup() { fs.rmSync(root, { recursive: true, force: true }); } };
}

const traceEnv = (fx) => ({ TRACE_INODES: fx.inodes, TRACE_LOG: fx.log, TRACE_OWNER_INODE: fx.ownerInode, TRACE_OWNER_LOG: fx.ownerLog });
const traceLines = (fx) => fs.readFileSync(fx.log, 'utf8').split('\n').filter(Boolean);
const ownerOpens = (fx) => fs.readFileSync(fx.ownerLog, 'utf8').split('\n').filter(Boolean).length;
const resetOwnerTrace = (fx) => fs.writeFileSync(fx.ownerLog, '');

/** Nothing the child printed or sent holds the dummy key, a prefix of it, the id source file contents or a store path. */
function assertNoLeak(fx, ...texts) {
  const blob = texts.join('\n');
  for (const secret of [fx.key, fx.strayKey].filter(Boolean)) {
    assert.ok(!blob.includes(secret) && !blob.includes(secret.slice(0, 12)), 'a dummy key (or its first 12 characters) appeared in an output');
  }
  assert.ok(!blob.includes(fx.root), 'an absolute scratch path appeared in an output');
}

// ---- entry points ------------------------------------------------------------------------------------------------------

function baseEnv(fx, env) {
  // Owner-key cases carry the key and the id in ~/.marrow/env only; the others put the key in the process environment.
  const identity = fx.ownerKey === 'only' ? {} : { MARROW_API_KEY: fx.key, MARROW_FLEET_AGENT_ID: fx.id };
  return { PATH: process.env.PATH, HOME: fx.home, USERPROFILE: fx.home, ...identity, ...traceEnv(fx), ...env };
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
      const entry = { path: pathname, body: raw, status: 0 };
      seen.push(entry);
      const body = raw ? JSON.parse(raw) : {};
      const send = (status, value) => { entry.status = status; res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(value)); };
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

function hookEvent(host, cwd, command = 'wrangler deploy production') {
  return host === 'cursor'
    ? { hook_event_name: 'beforeShellExecution', conversation_id: 'c1', generation_id: 'g1', command, cwd }
    : { hook_event_name: 'PreToolUse', tool_name: 'Bash', permission_mode: 'default', session_id: 'session-one', tool_input: { command }, tool_use_id: 'tool-use-one', cwd };
}

async function runHook(fx, host, command = 'wrangler deploy production', spec = undefined) {
  const service = await startFakeService();
  try {
    const redirect = path.join(fx.root, 'redirect-fetch.cjs');
    fs.writeFileSync(redirect, "const real = globalThis.fetch; globalThis.fetch = (u, i) => real(String(u).replace(/^https:\\/\\/api\\.example\\.test/, `http://127.0.0.1:${process.env.FAKE_PORT}`), i);\n");
    const child = spawn(process.execPath, ['--require', fx.tracer, '--require', redirect, CLI, spec ? spec.hook : HOOK_NAME[host]], {
      cwd: fx.cwd,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: baseEnv(fx, { FAKE_PORT: String(service.port), MARROW_BASE_URL: 'https://api.example.test', MARROW_SESSION_ID: 'session-one',
        MARROW_EVENT_SPOOL_PATH: path.join(fx.root, 'spool.json'), MARROW_HOOK_BACKGROUND_NUDGE: 'false', ...(spec?.env || {}) }),
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (chunk) => { out += chunk; });
    child.stderr.on('data', (chunk) => { err += chunk; });
    const killer = setTimeout(() => child.kill('SIGKILL'), 60_000);
    const code = await new Promise((resolve) => { child.on('close', resolve); child.stdin.end(JSON.stringify(spec ? spec.event(command, fx.cwd) : hookEvent(host, fx.cwd, command))); });
    clearTimeout(killer);
    const answer = out.trim() ? JSON.parse(out) : null;
    const reason = spec ? spec.reason(answer) : host === 'cursor' ? answer?.agent_message : answer?.hookSpecificOutput?.permissionDecisionReason;
    const denied = code === 2 || /"deny"|"cancel":\s*true|"block"/.test(JSON.stringify(answer));
    return { out, err, reason, code, denied, seen: service.seen };
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
  return { outputs, answers };
}

/** The trace first (the claim of this file), then the answers that show the entry points really ran. */
function assertCase(fx, run, label) {
  assert.deepEqual(traceLines(fx), [], `an open of a listed config path or credential store was traced (${label})`);
  assertNoLeak(fx, ...run.outputs);
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
    test(`C1 ${kind} at all six listed config paths to a dummy ${storeName}: 0 opens on server start, tool 403, three hooks`, async () => {
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
test('C1 the identity-source module imports no fs; the config-file reader, the hook text half and `identity --explain` are gone from src and dist', () => {
  const source = fs.readFileSync(path.join(ROOT, 'src', 'identity-explain.ts'), 'utf8');
  assert.doesNotMatch(source, /from 'fs'|from 'node:fs'|require\('fs'\)|require\('node:fs'\)/, 'identity-explain.ts imports fs');
  assert.doesNotMatch(source, /parseToml|readMarrowEnvBlock|agentIdConfigFiles|openSync|readFileSync|lstatSync/);
  const built = fs.readFileSync(path.join(ROOT, 'dist', 'identity-explain.js'), 'utf8');
  assert.doesNotMatch(built, /readMarrowEnvBlock|agentIdConfigFiles|openSync|readFileSync|lstatSync/);
  const removed = /agentIdConfigFiles|readMarrowEnvBlock|credentialScopeSource|credentialScopeText|baseEnforcementError|explainEnvironment|runIdentityCommand|explanationJson/;
  for (const file of ['env.ts', 'cli.ts', 'hook-pre-action.ts', 'index.ts', 'identity-explain.ts']) {
    const text = fs.existsSync(path.join(ROOT, 'src', file)) ? fs.readFileSync(path.join(ROOT, 'src', file), 'utf8') : '';
    assert.doesNotMatch(text, removed, `${file} still names a removed lookup`);
    const built = path.join(ROOT, 'dist', file.replace(/\.ts$/, '.js'));
    if (fs.existsSync(built)) assert.doesNotMatch(fs.readFileSync(built, 'utf8'), removed, `dist/${path.basename(built)} still names a removed lookup`);
  }
  // Only the tool 403 resolves the sentence's source, from the resolution made at start: no second resolve call anywhere this change touched.
  assert.doesNotMatch(fs.readFileSync(path.join(ROOT, 'src', 'identity-explain.ts'), 'utf8'), /resolveMarrowEnv\(|readOwnerEnvFile|readEnvFile/, 'identity-explain.ts resolves or reads on its own');
  assert.match(fs.readFileSync(path.join(ROOT, 'src', 'cli.ts'), 'utf8'), /explainAgentIdSource\(resolvedEnv\)/, 'the tool sentence is built from the start-time resolution');
});

// =====================================================================================================================
// C1 owner file: the key lives ONLY in ~/.marrow/env. Every entry opens that file exactly as often as BASE (3.9.109) does: once.
// A row counts the opens only after the proof that its branch ran (REACHED): the ready answer, the tool status, or the hook's
// deny text together with the fake service's 403 on the enforcement call, both in the same run. The first cut read the file a
// second time on a hook credential-scope 403 (F-R2-1, 2 opens): that row is red there.
// =====================================================================================================================
const BASE_OWNER_OPENS = 1;
const HOST_FIXTURES = path.join(ROOT, 'test', 'fixtures', 'host-approvals');
const fixtureJson = (name) => JSON.parse(fs.readFileSync(path.join(HOST_FIXTURES, name), 'utf8'));
const HOST_SPECS = {
  claude: { hook: 'claude-pre-action-hook', head: true, event: (c) => ({ ...fixtureJson('claude-pre-tool-use.json'), permission_mode: 'default', tool_input: { command: c } }), reason: (o) => o?.hookSpecificOutput?.permissionDecisionReason },
  codex: { hook: 'codex-pre-action-hook', head: true, env: { MARROW_TEST_HOST_PROCESS: '/usr/local/bin/codex exec deploy' }, event: (c) => ({ ...fixtureJson('codex-pre-tool-use.json'), tool_input: { command: c } }), reason: (o) => o?.hookSpecificOutput?.permissionDecisionReason },
  cursor: { hook: 'cursor-pre-action-hook', head: true, event: (c) => ({ ...fixtureJson('cursor-before-shell.json'), command: c }), reason: (o) => o?.agent_message },
  gemini: { hook: 'gemini-pre-action-hook', event: (c) => ({ ...fixtureJson('gemini-before-tool.json'), tool_input: { command: c } }), reason: (o) => o?.reason ?? o?.hookSpecificOutput?.permissionDecisionReason },
  grok: { hook: 'grok-pre-action-hook', event: (c) => ({ ...fixtureJson('grok-pre-tool-use.json'), toolInput: { command: c } }), reason: (o) => o?.reason ?? o?.hookSpecificOutput?.permissionDecisionReason },
  cline: { hook: 'cline-pre-action-hook', event: (c) => ({ hookName: 'PreToolUse', taskId: 'task-cut2', preToolUse: { toolName: 'execute_command', parameters: { command: c } } }), reason: (o) => o?.errorMessage },
  windsurf: { hook: 'windsurf-pre-action-hook', event: (c) => ({ agent_action_name: 'pre_run_command', trajectory_id: 'traj-cut2', execution_id: 'exec-cut2', tool_info: { command_line: c, cwd: '/home/operator/project' } }), reason: (o) => o?.reason },
};

/** REACHED for a hook credential-scope 403: the service answered the enforcement call 403 AND the hook denied, in this one run. */
function assertScope403Reached(run, spec, label) {
  assert.ok(run.seen.some((r) => r.path === '/v1/agent/enforcement' && r.status === 403), `${label}: REACHED failed: the fake service never answered the enforcement call 403`);
  if (spec.head) assert.match(run.reason || '', /This Marrow API key is not authorized to obtain action permits for agent/, `${label}: REACHED failed: no credential-scope deny text`);
  else assert.ok(run.denied, `${label}: REACHED failed: the hook did not deny`);
}

/** The five owner-file entries, each with its REACHED proof, the opens read after the proof. Returns the open counts by entry. */
async function ownerEntryCounts(fx) {
  const counts = {};
  const outputs = [];
  resetOwnerTrace(fx);
  const start = runServer(fx, [INIT]);
  assert.ok(start.stdout.includes('"id":1') && /"result"/.test(start.stdout), `server start did not answer initialize: ${start.stderr.slice(0, 200)}`);
  counts.start = ownerOpens(fx);
  outputs.push(start.stdout, start.stderr);
  resetOwnerTrace(fx);
  const tool = runServer(fx, [INIT, CALL]);
  const call = tool.stdout.trim().split('\n').filter(Boolean).map((line) => JSON.parse(line)).find((row) => row.id === 3);
  assert.ok(call, `no tools/call answer: ${tool.stderr.slice(0, 200)}`);
  const payload = JSON.parse(call.result.content[0].text);
  assert.equal(payload.error.status, 403, 'REACHED failed: the tool status is not 403');
  assert.equal(payload.error.code, 'MARROW_AGENT_SCOPE_MISMATCH', 'REACHED failed: not the credential-scope code');
  counts.tool = ownerOpens(fx);
  outputs.push(tool.stdout, tool.stderr);
  for (const [host, spec] of Object.entries(HOST_SPECS)) {
    resetOwnerTrace(fx);
    const hook = await runHook(fx, host, undefined, spec);
    assertScope403Reached(hook, spec, host);
    counts[`hook:${host}`] = ownerOpens(fx);
    outputs.push(hook.out, hook.err, ...hook.seen.map((r) => r.body));
  }
  for (const host of ['claude', 'codex', 'cursor']) {
    resetOwnerTrace(fx);
    const hook = await runHook(fx, host, 'ls -la', HOST_SPECS[host]);
    assert.equal(hook.code, 0, `${host}: REACHED failed: the read-only hook did not exit 0`);
    assert.ok(!hook.denied && hook.out.trim(), `${host}: REACHED failed: the read-only action was not allowed by the hook`);
    assert.ok(!hook.seen.some((r) => r.path === '/v1/agent/enforcement' && r.status === 403), `${host}: a read-only action reached the 403 branch`);
    counts[`readonly:${host}`] = ownerOpens(fx);
    outputs.push(hook.out, hook.err, ...hook.seen.map((r) => r.body));
  }
  return { counts, outputs };
}

test('C1 owner file: with the key only in ~/.marrow/env every entry opens that file exactly as often as BASE (once): start, tool 403, the 403 hook on 7 hosts, a read-only hook on 3', async () => {
  const fx = makeCase('owner-only', 'plain', '.claude.json', { ownerKey: 'only' });
  try {
    const { counts, outputs } = await ownerEntryCounts(fx);
    const expected = Object.fromEntries(Object.keys(counts).map((name) => [name, BASE_OWNER_OPENS]));
    assert.deepEqual(counts, expected, 'every entry opens the owner key file as many times as BASE: once');
    assert.deepEqual(traceLines(fx), [], 'no listed config path or credential store was opened');
    assertNoLeak(fx, ...outputs);
  } finally { fx.cleanup(); }
});

test('C1 owner file: the same with a hard link and with a symlink at all six listed config paths (they stay unopened; the owner file still opens once)', async () => {
  for (const kind of ['hardlink', 'symlink']) {
    const fx = makeCase(`owner-${kind}`, kind, '.npmrc', { ownerKey: 'only' });
    try {
      const { counts, outputs } = await ownerEntryCounts(fx);
      for (const [name, opens] of Object.entries(counts)) assert.equal(opens, BASE_OWNER_OPENS, `${kind}: ${name} opened the owner key file ${opens} times (BASE ${BASE_OWNER_OPENS})`);
      assert.deepEqual(traceLines(fx), [], `${kind}: a listed config path or credential store was opened`);
      assertNoLeak(fx, ...outputs);
    } finally { fx.cleanup(); }
  }
});

test('C1 owner file: with the key in the process environment no entry opens ~/.marrow/env at all, even when that file exists with another key', async () => {
  const fx = makeCase('owner-stray', 'plain', '.claude.json', { ownerKey: 'stray' });
  try {
    const { counts, outputs } = await ownerEntryCounts(fx);
    for (const [name, opens] of Object.entries(counts)) assert.equal(opens, 0, `${name} opened the owner key file ${opens} times with the key in the environment (BASE 0)`);
    assertNoLeak(fx, ...outputs);
  } finally { fx.cleanup(); }
});

test('C1 owner file: `identity --explain` is not a command of this build: it behaves as on BASE (starts the server on the closed input, prints nothing, one start-time open)', () => {
  const fx = makeCase('owner-explain', 'plain', '.claude.json', { ownerKey: 'only' });
  try {
    for (const args of [['identity', '--explain'], ['identity', '--explain', '--json'], ['identity']]) {
      resetOwnerTrace(fx);
      const run = spawnSync(process.execPath, ['--require', fx.tracer, CLI, ...args], { cwd: fx.cwd, input: '', encoding: 'utf8', timeout: 20_000, env: baseEnv(fx, { MARROW_AUTO_ENROLL: 'false', MARROW_TOOL_PROFILE: 'core' }) });
      assert.equal(run.status, 0, `${args.join(' ')}: REACHED failed: the server did not start and end on closed input: ${run.stderr.slice(0, 200)}`);
      assert.equal(run.stdout, '', `${args.join(' ')}: printed an explanation`);
      assert.doesNotMatch(run.stderr, /Agent id:|origin|Usage: marrow-mcp identity/, `${args.join(' ')}: an identity command answered`);
      assert.equal(ownerOpens(fx), BASE_OWNER_OPENS, `${args.join(' ')}: opened the owner key file ${ownerOpens(fx)} times (BASE ${BASE_OWNER_OPENS})`);
      assertNoLeak(fx, run.stdout, run.stderr);
    }
    assert.doesNotMatch(fs.readFileSync(CLI, 'utf8'), /runIdentityCommand|identity --explain/, 'dist/cli.js still names the command');
    const help = spawnSync(process.execPath, [CLI, '--help'], { cwd: fx.cwd, encoding: 'utf8', timeout: 20_000, env: { PATH: process.env.PATH, HOME: fx.home } });
    assert.equal(help.status, 0, help.stderr);
    assert.doesNotMatch(help.stdout, /identity/, '--help still lists the command');
  } finally { fx.cleanup(); }
});
