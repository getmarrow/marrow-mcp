'use strict';
// MCP-1 (U7), after the cuts (cut-mcp1, cut2-mcp1): name the SOURCE of the agent id (variable + origin) in the tool 403 only. Rows
// T1-T7, M4, M5. The hook text is BASE's (the hook half and `identity --explain` are gone). No host config file is read to find
// it and no extra read of ~/.marrow/env is made (test/identity-source-no-config-open.test.js traces the opens): `file` is null
// unless the id came from ~/.marrow/env. Only explanatory text is new: no decision, status code or identity changes.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const CLI = path.join(__dirname, '..', 'dist', 'cli.js');
const SCOPE_FIX = 'Use the fleet-bound agent identity for both the request body and header.';

// Dummy key: fixed non-key prefix + runtime hex, each draw asserted NOT live-shaped.
function dummyKey() {
  const key = `zzfixture-${crypto.randomBytes(12).toString('hex')}`;
  assert.doesNotMatch(key, /^(?:sk|pk|rk)_|^gh[pousr]_|^xox[a-z]-|^AKIA|^AIza|^eyJ/, 'dummy key must classify NOT_LIVE');
  return key;
}

function privateDir(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `marrow-mcp-idsrc-${prefix}-`));
  fs.chmodSync(dir, 0o700);
  return dir;
}

function writeFile(file, text, mode = 0o600) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, text, { mode });
  fs.chmodSync(file, mode);
  return file;
}

const mcpJson = (block, server = 'marrow') => JSON.stringify({ mcpServers: { [server]: { command: 'npx', args: ['-y', '@getmarrow/mcp'], env: block } } });

function fixture(prefix) {
  const home = privateDir(`${prefix}-home`);
  const cwd = privateDir(`${prefix}-cwd`);
  return { home, cwd, cleanup() { fs.rmSync(home, { recursive: true, force: true }); fs.rmSync(cwd, { recursive: true, force: true }); } };
}

const lazy = {
  get env() { return require('../dist/env.js'); },
  get explain() { return require('../dist/identity-explain.js'); },
  get hook() { return require('../dist/hook-pre-action.js'); },
  get req() { return require('../dist/request-reliability.js'); },
};

function resolveIn(env, fx) {
  return lazy.env.resolveMarrowEnv({ env, home: fx.home, cwd: fx.cwd, trustedOnly: true });
}

function explainIn(env, fx) {
  const resolved = resolveIn(env, fx);
  return lazy.explain.explainAgentIdSource(resolved);
}

const KEYS = ['agent_id', 'file', 'origin', 'variable'];
const jsonOf = (lookup) => ({ agent_id: lookup.agent_id, variable: lookup.variable, origin: lookup.origin, file: lookup.file });

// ---- the tool path: a spawned server answering 403 MARROW_AGENT_SCOPE_MISMATCH --------------------------------------

function installScopeMock(dir, extra = '') {
  const mock = path.join(dir, 'scope-fetch.cjs');
  fs.writeFileSync(mock, `
const fs = require('node:fs');
globalThis.fetch = async (url, init = {}) => {
  const headers = new Headers(init.headers || {});
  fs.appendFileSync(process.env.MARROW_TEST_SEEN, JSON.stringify({ path: new URL(String(url)).pathname, agent: headers.get('X-Marrow-Agent-Id') }) + '\\n');
  ${extra}
  return Response.json({
    error: 'Agent identity does not match the key binding.',
    details: { code: 'MARROW_AGENT_SCOPE_MISMATCH', exact_fix: ${JSON.stringify(SCOPE_FIX)} },
  }, { status: 403 });
};
`, { mode: 0o600 });
  return mock;
}

function mcpFrames() {
  return [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'marrow_agent_runtime', arguments: { action: 'inspect a local note', type: 'general' } } },
  ].map((row) => JSON.stringify(row)).join('\n') + '\n';
}

// Runs the real server (dist/cli.js) against the 403 mock. `env` is the whole child environment except what the
// harness adds (PATH, HOME, mock wiring); nothing is inherited from the runner.
function runToolPath(fx, env) {
  const seen = path.join(fx.cwd, 'seen.jsonl');
  const mock = installScopeMock(fx.cwd);
  const child = spawnSync(process.execPath, [CLI], {
    cwd: fx.cwd,
    input: mcpFrames(),
    encoding: 'utf8',
    timeout: 20_000,
    env: {
      PATH: process.env.PATH,
      HOME: fx.home,
      USERPROFILE: fx.home,
      MARROW_BASE_URL: 'https://127.0.0.1:9',
      MARROW_AUTO_ENROLL: 'false',
      MARROW_TOOL_PROFILE: 'core',
      MARROW_REQUEST_TIMEOUT_MS: '3000',
      MARROW_TEST_SEEN: seen,
      NODE_OPTIONS: `--require=${mock}`,
      ...env,
    },
  });
  const answers = child.stdout.trim().split('\n').filter(Boolean).map((line) => JSON.parse(line));
  const call = answers.find((row) => row.id === 3);
  assert.ok(call, `no tools/call answer: ${child.stdout.slice(0, 300)} ${child.stderr.slice(0, 300)}`);
  const payload = JSON.parse(call.result.content[0].text);
  const requests = fs.existsSync(seen) ? fs.readFileSync(seen, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [];
  return { child, payload, call, requests };
}

// ---- the hook path: the in-process pre-action hook against a 403 on the permit issue ---------------------------------

async function runHookScope(fx, env, event) {
  const { runPreActionHookCommand } = lazy.hook;
  const originalFetch = globalThis.fetch;
  const originalWrite = process.stdout.write;
  const originalArgv = process.argv[2];
  const originalCwd = process.cwd();
  const touched = new Set(Object.keys(process.env).filter((k) => /^MARROW_/.test(k)));
  for (const k of Object.keys(env)) touched.add(k);
  touched.add('HOME'); touched.add('USERPROFILE');
  const previous = Object.fromEntries([...touched].map((k) => [k, process.env[k]]));
  for (const k of touched) delete process.env[k];
  Object.assign(process.env, { HOME: fx.home, USERPROFILE: fx.home, MARROW_BASE_URL: 'https://api.example.test', MARROW_SESSION_ID: 'session-one',
    MARROW_EVENT_SPOOL_PATH: path.join(fx.home, 'spool.json'), ...env });
  process.argv[2] = 'claude-pre-action-hook';
  process.chdir(fx.cwd);
  let output = '';
  process.stdout.write = (chunk) => { output += String(chunk); return true; };
  globalThis.fetch = async (url, init = {}) => {
    const pathname = new URL(String(url)).pathname;
    const body = init.body ? JSON.parse(String(init.body)) : {};
    if (pathname === '/v1/agent/integrations/events') return Response.json({ data: { accepted: true } });
    if (pathname === '/v1/agent/commit') return Response.json({ data: { committed: true, decision_id: body.decision_id } });
    if (pathname === '/v1/agent/runtime') {
      return Response.json({ data: {
        runtime_authorization: { id: 'fast_gate_one', durable: false, decision_creation_required: true },
        completion_contract: { decision_creation_required: true },
        risk_gate: { allow: true, decision: 'allow', enforced: true, reasons: [] },
        gate_receipt_id: 'fast_gate_one', before_you_act: 'Proceed with the low-risk work.', proof_pack: { fields: [] },
      } });
    }
    if (pathname === '/v1/agent/think') return Response.json({ data: { decision_id: 'decision-think' } });
    if (pathname === '/v1/agent/enforcement' && body.operation === 'issue') {
      return new Response(JSON.stringify({ error: 'synthetic-private-service-text', code: 'MARROW_AGENT_SCOPE_MISMATCH' }), { status: 403, headers: { 'content-type': 'application/json' } });
    }
    throw new Error(`unexpected ${pathname}`);
  };
  try {
    await runPreActionHookCommand(event);
    return output;
  } finally {
    globalThis.fetch = originalFetch;
    process.stdout.write = originalWrite;
    process.argv[2] = originalArgv;
    process.chdir(originalCwd);
    for (const [k, v] of Object.entries(previous)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
}

const PROTECTED_EVENT = () => ({
  hook_event_name: 'PreToolUse', tool_name: 'Bash', permission_mode: 'default', session_id: 'session-one',
  tool_input: { command: 'wrangler deploy production' }, tool_use_id: 'tool-use-one',
});

const HEAD = (agent, code = 'MARROW_AGENT_SCOPE_MISMATCH') => `This Marrow API key is not authorized to obtain action permits for agent "${agent}" (HTTP 403 ${code}).`;
const BASE_NEXT_STEP = 'Use the API key issued to that agent, or set MARROW_FLEET_AGENT_ID (or MARROW_AGENT_ID) to the agent this key belongs to, then retry.';
const BASE_NO_ID_HEAD = "This Marrow API key is not authorized to obtain action permits for this hook's agent (no MARROW_FLEET_AGENT_ID or MARROW_AGENT_ID is set) (HTTP 403 MARROW_AGENT_SCOPE_MISMATCH).";
const sentenceEnv = (variable) => `This server took the id from ${variable} in this server's environment (set by the host or its launcher).`;

// =====================================================================================================================
// T1  id from the process env (a host config file holds the same value): variable + origin named, exactly the U7 line, no file
// =====================================================================================================================
test('T1 tool 403: the id from the process env names MARROW_FLEET_AGENT_ID and the environment, never a config file', () => {
  const fx = fixture('t1');
  try {
    const key = dummyKey();
    const file = writeFile(path.join(fx.home, '.mcp.json'), mcpJson({ MARROW_FLEET_AGENT_ID: 'agent-alpha', MARROW_API_KEY: key }));
    const { payload, requests } = runToolPath(fx, { MARROW_API_KEY: key, MARROW_FLEET_AGENT_ID: 'agent-alpha' });
    assert.equal(payload.ok, false);
    assert.equal(payload.error.status, 403);
    assert.equal(payload.error.code, 'MARROW_AGENT_SCOPE_MISMATCH');
    assert.equal(payload.error.exact_fix, SCOPE_FIX, 'the backend repair text stays byte-equal');
    assert.ok(payload.error.message.includes(sentenceEnv('MARROW_FLEET_AGENT_ID')), payload.error.message);
    assert.ok(!payload.error.message.includes(file) && !payload.error.message.includes(fx.home) && !/mcp\.json|config file/.test(payload.error.message), 'no file, label or path');
    assert.deepEqual(Object.keys(payload.agent_id_source).sort(), KEYS);
    assert.deepEqual(payload.agent_id_source, { agent_id: 'agent-alpha', variable: 'MARROW_FLEET_AGENT_ID', origin: 'process_env', file: null });
    assert.ok(requests.length >= 1 && requests.every((r) => r.agent === 'agent-alpha'), 'the identity sent is unchanged');
  } finally { fx.cleanup(); }
});

test('T1 credential-scope text (hook): the BASE text, byte for byte (no source sentence)', async () => {
  const fx = fixture('t1h');
  try {
    const key = dummyKey();
    const file = writeFile(path.join(fx.home, '.mcp.json'), mcpJson({ MARROW_FLEET_AGENT_ID: 'agent-alpha' }));
    const out = await runHookScope(fx, { MARROW_API_KEY: key, MARROW_FLEET_AGENT_ID: 'agent-alpha' }, PROTECTED_EVENT());
    const decision = JSON.parse(out).hookSpecificOutput;
    assert.equal(decision.permissionDecision, 'deny');
    assert.equal(decision.permissionDecisionReason, `${HEAD('agent-alpha')} ${BASE_NEXT_STEP}`);
    assert.ok(!decision.permissionDecisionReason.includes(file) && !/mcp\.json|config file/.test(decision.permissionDecisionReason), 'no file, label or path');
  } finally { fx.cleanup(); }
});

test('T1 resolution: origin and variable are the exact names read, the id is the exact value', () => {
  const fx = fixture('t1r');
  try {
    const key = dummyKey();
    const fleet = resolveIn({ MARROW_API_KEY: key, MARROW_FLEET_AGENT_ID: 'a-fleet', MARROW_AGENT_ID: 'a-plain' }, fx);
    assert.deepEqual({ ...fleet.agentIdSource }, { origin: 'process_env', variable: 'MARROW_FLEET_AGENT_ID' });
    assert.equal(fleet.agentId, 'a-fleet');
    const plain = resolveIn({ MARROW_API_KEY: key, MARROW_AGENT_ID: 'a-plain' }, fx);
    assert.deepEqual({ ...plain.agentIdSource }, { origin: 'process_env', variable: 'MARROW_AGENT_ID' });
    const emptyFleet = resolveIn({ MARROW_API_KEY: key, MARROW_FLEET_AGENT_ID: '', MARROW_AGENT_ID: 'a-plain' }, fx);
    assert.equal(emptyFleet.agentIdSource.variable, 'MARROW_AGENT_ID', 'an empty value is absent, the next variable is read');
  } finally { fx.cleanup(); }
});

test('T1 presence parity: "" is absent (origin none); whitespace-only, control characters and > 64 chars print as <unsafe id>', () => {
  const fx = fixture('t1p');
  try {
    const key = dummyKey();
    const none = explainIn({ MARROW_API_KEY: key, MARROW_FLEET_AGENT_ID: '', MARROW_AGENT_ID: '' }, fx);
    assert.deepEqual(jsonOf(none), { agent_id: null, variable: null, origin: 'none', file: null });
    assert.equal(lazy.explain.agentIdSourceSentence(none), '');
    for (const bad of ['   ', 'agent\u0007bell', `a${'b'.repeat(64)}`, 'agent\nsplit', 'agent‮flip']) {
      const e = explainIn({ MARROW_API_KEY: key, MARROW_FLEET_AGENT_ID: bad }, fx);
      assert.equal(e.origin, 'process_env', JSON.stringify(bad));
      assert.equal(e.agent_id, '<unsafe id>', JSON.stringify(bad));
      assert.equal(e.variable, 'MARROW_FLEET_AGENT_ID');
      const text = JSON.stringify(jsonOf(e)) + lazy.explain.agentIdSourceSentence(e);
      assert.ok(!text.includes(bad.trim() || '\u0000nope'), 'the unsafe value is never printed');
    }
    const edge = explainIn({ MARROW_API_KEY: key, MARROW_FLEET_AGENT_ID: 'b'.repeat(64) }, fx);
    assert.equal(edge.agent_id, 'b'.repeat(64), '64 chars is printable');
  } finally { fx.cleanup(); }
});

test('T1 credential-scope text (hook) for an unsafe id is the BASE text: no id named, never the value', async () => {
  const fx = fixture('t1u');
  try {
    const out = await runHookScope(fx, { MARROW_API_KEY: dummyKey(), MARROW_FLEET_AGENT_ID: 'bad\u0007id' }, PROTECTED_EVENT());
    const reason = JSON.parse(out).hookSpecificOutput.permissionDecisionReason;
    assert.equal(reason, `${BASE_NO_ID_HEAD} ${BASE_NEXT_STEP}`);
    assert.ok(!reason.includes('\u0007'));
  } finally { fx.cleanup(); }
});

// =====================================================================================================================
// T2  id only in process env: the same line whatever any config file holds
// =====================================================================================================================
test('T2 tool 403 sentence and hook text: the process env sentence names no config file (the hook text is BASE\'s), whatever the files at the listed paths hold', async () => {
  const fx = fixture('t2');
  try {
    const key = dummyKey();
    // A config file that holds a DIFFERENT id, and one with the id under another server name, are not sources.
    writeFile(path.join(fx.home, '.mcp.json'), mcpJson({ MARROW_FLEET_AGENT_ID: 'someone-else' }));
    writeFile(path.join(fx.cwd, '.mcp.json'), mcpJson({ MARROW_FLEET_AGENT_ID: 'agent-beta' }, 'other-server'));
    const { payload, requests } = runToolPath(fx, { MARROW_API_KEY: key, MARROW_AGENT_ID: 'agent-beta' });
    assert.ok(payload.error.message.includes(sentenceEnv('MARROW_AGENT_ID')), payload.error.message);
    assert.deepEqual(payload.agent_id_source, { agent_id: 'agent-beta', variable: 'MARROW_AGENT_ID', origin: 'process_env', file: null });
    assert.equal(payload.error.status, 403);
    assert.ok(requests.every((r) => r.agent === 'agent-beta'));
    const out = await runHookScope(fx, { MARROW_API_KEY: key, MARROW_AGENT_ID: 'agent-beta' }, PROTECTED_EVENT());
    assert.equal(JSON.parse(out).hookSpecificOutput.permissionDecisionReason, `${HEAD('agent-beta')} ${BASE_NEXT_STEP}`);
  } finally { fx.cleanup(); }
});

// =====================================================================================================================
// T3  owner file wins over process env
// =====================================================================================================================
test('T3 owner file id wins over process env: ~/.marrow/env is named, not the process env', async () => {
  const fx = fixture('t3');
  try {
    const key = dummyKey();
    writeFile(path.join(fx.home, '.marrow', 'env'), `MARROW_API_KEY=${key}\nMARROW_FLEET_AGENT_ID=owner-agent\n`);
    const resolved = resolveIn({ MARROW_FLEET_AGENT_ID: 'env-agent' }, fx);
    assert.equal(resolved.agentId, 'owner-agent');
    assert.equal(resolved.agentIdSource.origin, 'owner_file');
    assert.equal(resolved.agentIdSource.variable, 'MARROW_FLEET_AGENT_ID');
    const lookup = explainIn({ MARROW_FLEET_AGENT_ID: 'env-agent' }, fx);
    assert.deepEqual(jsonOf(lookup), { agent_id: 'owner-agent', variable: 'MARROW_FLEET_AGENT_ID', origin: 'owner_file', file: '~/.marrow/env' });
    assert.equal(lazy.explain.agentIdSourceSentence(lookup), 'This server took the id from MARROW_FLEET_AGENT_ID in ~/.marrow/env.');
    // The tool path, through the real server.
    const { payload, requests } = runToolPath(fx, { MARROW_FLEET_AGENT_ID: 'env-agent' });
    assert.ok(payload.error.message.includes('This server took the id from MARROW_FLEET_AGENT_ID in ~/.marrow/env.'), payload.error.message);
    assert.ok(!payload.error.message.includes("this server's environment"));
    assert.deepEqual(payload.agent_id_source, { agent_id: 'owner-agent', variable: 'MARROW_FLEET_AGENT_ID', origin: 'owner_file', file: '~/.marrow/env' });
    assert.ok(requests.every((r) => r.agent === 'owner-agent'), 'the id sent is the owner-file id, as on BASE');
    const out = await runHookScope(fx, { MARROW_FLEET_AGENT_ID: 'env-agent' }, PROTECTED_EVENT());
    assert.equal(JSON.parse(out).hookSpecificOutput.permissionDecisionReason, `${HEAD('owner-agent')} ${BASE_NEXT_STEP}`, 'the hook text is BASE\'s: it does not name the owner file');
  } finally { fx.cleanup(); }
});

test('T3 owner file without an id: the id still comes from the process env', () => {
  const fx = fixture('t3b');
  try {
    writeFile(path.join(fx.home, '.marrow', 'env'), `MARROW_API_KEY=${dummyKey()}\n`);
    const lookup = explainIn({ MARROW_AGENT_ID: 'env-only' }, fx);
    assert.deepEqual(jsonOf(lookup), { agent_id: 'env-only', variable: 'MARROW_AGENT_ID', origin: 'process_env', file: null });
    const viaAgentVar = (() => {
      writeFile(path.join(fx.home, '.marrow', 'env'), `MARROW_API_KEY=${dummyKey()}\nMARROW_AGENT_ID=owner-plain\n`);
      return explainIn({ MARROW_FLEET_AGENT_ID: 'env-fleet' }, fx);
    })();
    assert.deepEqual(jsonOf(viaAgentVar), { agent_id: 'owner-plain', variable: 'MARROW_AGENT_ID', origin: 'owner_file', file: '~/.marrow/env' });
  } finally { fx.cleanup(); }
});

test('T3 a refused owner file (group-writable) is never a source', () => {
  const fx = fixture('t3c');
  try {
    writeFile(path.join(fx.home, '.marrow', 'env'), `MARROW_API_KEY=${dummyKey()}\nMARROW_FLEET_AGENT_ID=owner-agent\n`, 0o660);
    const lookup = explainIn({ MARROW_FLEET_AGENT_ID: 'env-agent' }, fx);
    assert.equal(lookup.origin, 'process_env');
    assert.equal(lookup.agent_id, 'env-agent');
  } finally { fx.cleanup(); }
});

// =====================================================================================================================
// T4  the env block also holds MARROW_API_KEY=<dummy>: 0 dummy bytes anywhere
// =====================================================================================================================
function treeFiles(dir, out = []) {
  for (const name of fs.readdirSync(dir)) {
    const p = path.join(dir, name);
    const st = fs.lstatSync(p);
    if (st.isDirectory()) treeFiles(p, out);
    else if (st.isFile()) out.push(p);
  }
  return out;
}

test('T4 / T-SEC: no output, report or new file holds the dummy key; only the agent id value is printed (tool 403, hook text, sentence)', async () => {
  const fx = fixture('t4');
  try {
    const key = dummyKey();
    const keyLong = dummyKey();
    const file = writeFile(path.join(fx.home, '.mcp.json'), mcpJson({ MARROW_API_KEY: key, MARROW_FLEET_AGENT_ID: 'agent-alpha', MARROW_BASE_URL: 'https://api.getmarrow.ai' }));
    writeFile(path.join(fx.home, '.marrow', 'env'), `MARROW_API_KEY=${keyLong}\n`);
    const before = new Map(treeFiles(fx.home).map((p) => [p, fs.readFileSync(p)]));
    // 1. in-process lookup, sentence and JSON
    const lookup = explainIn({ MARROW_API_KEY: key, MARROW_FLEET_AGENT_ID: 'agent-alpha' }, fx);
    const inProcess = JSON.stringify(jsonOf(lookup)) + lazy.explain.agentIdSourceSentence(lookup) + JSON.stringify(lookup);
    // 2. the tool 403, whole server output
    const tool = runToolPath(fx, { MARROW_API_KEY: key, MARROW_FLEET_AGENT_ID: 'agent-alpha' });
    // 3. the hook text
    const hook = await runHookScope(fx, { MARROW_API_KEY: key, MARROW_FLEET_AGENT_ID: 'agent-alpha' }, PROTECTED_EVENT());
    const everything = [inProcess, tool.child.stdout, tool.child.stderr, hook].join('\n');
    for (const secret of [key, keyLong]) {
      assert.equal(everything.includes(secret), false, 'a dummy key reached an output');
      assert.equal(everything.includes(secret.slice(0, 18)), false, 'a dummy key prefix reached an output');
    }
    assert.ok(!tool.payload.error.message.includes('mcp.json') && !tool.payload.error.message.includes(file), 'no config file is named');
    assert.ok(!/MARROW_API_KEY|MARROW_BASE_URL|"env"|mcpServers/.test(tool.payload.error.message + hook), 'no env block or other variable text');
    // 5. every file under the fixture home: only the files the fixture wrote hold the key; no new file does
    for (const p of treeFiles(fx.home)) {
      if (before.has(p)) continue;
      const text = fs.readFileSync(p);
      assert.equal(text.includes(key), false, `new file ${path.basename(p)} holds the dummy key`);
      assert.equal(text.includes(keyLong), false, `new file ${path.basename(p)} holds the dummy key`);
      assert.doesNotMatch(path.basename(p), /\.(?:bak|orig|undo)$/);
    }
    for (const [p, bytes] of before) assert.ok(fs.readFileSync(p).equals(bytes), `${path.basename(p)} was changed`);
    // the no-id case prints no file and no key either
    const none = lazy.explain.explainAgentIdSource(resolveIn({ MARROW_API_KEY: key }, fx));
    assert.deepEqual(jsonOf(none), { agent_id: null, variable: null, origin: 'none', file: null });
    assert.equal((JSON.stringify(none) + lazy.explain.agentIdSourceSentence(none)).includes(key), false);
  } finally { fx.cleanup(); }
});

test('M4 the new line names the variable and origin only: no key, env block, or identity-changing command', async () => {
  const fx = fixture('m4');
  try {
    const key = dummyKey();
    writeFile(path.join(fx.home, '.mcp.json'), mcpJson({ MARROW_API_KEY: key, MARROW_FLEET_AGENT_ID: 'agent-alpha' }));
    const lookup = explainIn({ MARROW_API_KEY: key, MARROW_FLEET_AGENT_ID: 'agent-alpha' }, fx);
    const sentence = lazy.explain.agentIdSourceSentence(lookup);
    const hook = await runHookScope(fx, { MARROW_API_KEY: key, MARROW_FLEET_AGENT_ID: 'agent-alpha' }, PROTECTED_EVENT());
    const tool = runToolPath(fx, { MARROW_API_KEY: key, MARROW_FLEET_AGENT_ID: 'agent-alpha' });
    assert.equal(JSON.parse(hook).hookSpecificOutput.permissionDecisionReason, `${HEAD('agent-alpha')} ${BASE_NEXT_STEP}`, 'the hook text is BASE\'s');
    for (const text of [sentence, tool.payload.error.message.replace('Agent identity does not match the key binding.', '')]) {
      assert.doesNotMatch(text, /--agent-id|--fix-identity|\bupdate\b|\bunset\b|control disable|export MARROW|npx |install@/i, text);
    }
    assert.equal(tool.payload.error.exact_fix, SCOPE_FIX);
  } finally { fx.cleanup(); }
});

// =====================================================================================================================
// T6  a symlink, group-writable, > 2 MiB, invalid or non-file config at a listed path changes nothing: it is never looked at
// =====================================================================================================================
test('T6 whatever sits at ~/.mcp.json (symlink, group-writable, over 2 MiB, invalid JSON, a directory) the sentence and JSON are the same, with no "could not be read" note', async () => {
  const unsafeCases = {
    symlink(file) {
      const target = path.join(path.dirname(file), 'real-mcp.json');
      writeFile(target, mcpJson({ MARROW_FLEET_AGENT_ID: 'agent-alpha' }));
      fs.symlinkSync(target, file);
    },
    'group-writable': (file) => writeFile(file, mcpJson({ MARROW_FLEET_AGENT_ID: 'agent-alpha' }), 0o660),
    'world-writable': (file) => writeFile(file, mcpJson({ MARROW_FLEET_AGENT_ID: 'agent-alpha' }), 0o606),
    'over 2 MiB': (file) => writeFile(file, mcpJson({ MARROW_FLEET_AGENT_ID: 'agent-alpha', PAD: 'x'.repeat(2 * 1024 * 1024 + 16) })),
    'invalid JSON': (file) => writeFile(file, '{"mcpServers": {"marrow": {"env": {"MARROW_FLEET_AGENT_ID": "agent-alpha"'),
    'a directory': (file) => fs.mkdirSync(file, { mode: 0o700 }),
  };
  for (const [label, make] of Object.entries(unsafeCases)) {
    const fx = fixture('t6');
    try {
      const file = path.join(fx.home, '.mcp.json');
      make(file);
      const key = dummyKey();
      const lookup = explainIn({ MARROW_API_KEY: key, MARROW_FLEET_AGENT_ID: 'agent-alpha' }, fx);
      assert.equal(lookup.origin, 'process_env', label);
      assert.equal(lookup.file, null, `${label}: not named`);
      assert.equal(lazy.explain.agentIdSourceSentence(lookup), sentenceEnv('MARROW_FLEET_AGENT_ID'), label);
      assert.deepEqual(jsonOf(lookup), { agent_id: 'agent-alpha', variable: 'MARROW_FLEET_AGENT_ID', origin: 'process_env', file: null }, label);
      const out = await runHookScope(fx, { MARROW_API_KEY: key, MARROW_FLEET_AGENT_ID: 'agent-alpha' }, PROTECTED_EVENT());
      const reason = JSON.parse(out).hookSpecificOutput.permissionDecisionReason;
      assert.equal(reason, `${HEAD('agent-alpha')} ${BASE_NEXT_STEP}`, `${label}: the hook text is BASE's`);
      assert.ok(!reason.includes(file) && !reason.includes('real-mcp.json') && !reason.includes('read safely'), `${label}: file not named`);
    } finally { fx.cleanup(); }
  }
});

// =====================================================================================================================
// T7  fleet-key case
// =====================================================================================================================
test('T7 fleet_key_match: origin, variable and the key variable NAME (never a value)', () => {
  const fx = fixture('t7');
  try {
    const direct = dummyKey();
    const fleetKey = dummyKey();
    const env = { MARROW_API_KEY: direct, MARROW_FLEET_AGENT_ID: 'fleet-agent-a', MARROW_AGENT_ID_ALPHA: 'fleet-agent-a', MARROW_KEY_ALPHA: fleetKey };
    const resolved = resolveIn(env, fx);
    assert.equal(resolved.apiKey, fleetKey, 'the key choice is BASE behavior');
    assert.equal(resolved.agentId, 'fleet-agent-a');
    assert.deepEqual({ ...resolved.agentIdSource }, { origin: 'fleet_key_match', variable: 'MARROW_FLEET_AGENT_ID', keyVariable: 'MARROW_KEY_ALPHA' });
    const lookup = lazy.explain.explainAgentIdSource(resolved);
    assert.deepEqual(jsonOf(lookup), { agent_id: 'fleet-agent-a', variable: 'MARROW_FLEET_AGENT_ID', origin: 'fleet_key_match', file: null });
    const sentence = lazy.explain.agentIdSourceSentence(lookup);
    assert.ok(sentence.startsWith(sentenceEnv('MARROW_FLEET_AGENT_ID')), sentence);
    assert.ok(sentence.includes('MARROW_KEY_ALPHA'));
    assert.ok(!sentence.includes(fleetKey) && !sentence.includes(direct) && !JSON.stringify(lookup).includes(fleetKey));
    // MARROW_AGENT_ID as the requested variable
    const viaPlain = resolveIn({ MARROW_API_KEY: direct, MARROW_AGENT_ID: 'fleet-agent-a', MARROW_AGENT_ID_ALPHA: 'fleet-agent-a', MARROW_KEY_ALPHA: fleetKey }, fx);
    assert.deepEqual({ ...viaPlain.agentIdSource }, { origin: 'fleet_key_match', variable: 'MARROW_AGENT_ID', keyVariable: 'MARROW_KEY_ALPHA' });
    // same key as the direct one: BASE answers with the direct branch, so the origin is process_env
    const same = resolveIn({ MARROW_API_KEY: direct, MARROW_FLEET_AGENT_ID: 'fleet-agent-a', MARROW_AGENT_ID_ALPHA: 'fleet-agent-a', MARROW_KEY_ALPHA: direct }, fx);
    assert.equal(same.agentIdSource.origin, 'process_env');
  } finally { fx.cleanup(); }
});

// =====================================================================================================================
// M5  never looser: decisions, status codes and the identity sent are those of BASE; only the explanation text differs
// =====================================================================================================================
test('M5 the hook answer for a credential-scope 403 is still a deny; other 403s and outages keep their BASE text byte-equal', () => {
  const { controlRejectionMessage } = lazy.hook;
  const { MarrowRequestError } = lazy.req;
  const other = new MarrowRequestError({ code: 'permission_denied', backendCode: 'MARROW_PLAN_REQUIRED', message: 'x', status: 403, exactFix: 'fix' });
  assert.equal(controlRejectionMessage(other, 'darvis'), "Marrow did not allow this protected action (HTTP 403 MARROW_PLAN_REQUIRED). Run `npx -y @getmarrow/install@latest doctor` in this terminal to check this machine's Marrow setup, then retry.");
  const down = new MarrowRequestError({ code: 'tls_failure', message: 'x', exactFix: 'fix' });
  assert.equal(controlRejectionMessage(down), 'Marrow is unavailable, so this protected action was denied (tls_failure). Retry when Marrow is reachable.');
  const scope = new MarrowRequestError({ code: 'permission_denied', backendCode: 'MARROW_AGENT_SCOPE_MISMATCH', message: 'x', status: 403, exactFix: 'fix' });
  // No source given: the BASE sentence, byte for byte.
  assert.equal(controlRejectionMessage(scope, 'darvis'), `${HEAD('darvis')} ${BASE_NEXT_STEP}`);
  assert.equal(controlRejectionMessage(scope), `This Marrow API key is not authorized to obtain action permits for this hook's agent (no MARROW_FLEET_AGENT_ID or MARROW_AGENT_ID is set) (HTTP 403 MARROW_AGENT_SCOPE_MISMATCH). ${BASE_NEXT_STEP}`);
});

test('M5 a non-scope 403 on the tool path carries no source text and the identity sent is unchanged', () => {
  const fx = fixture('m5');
  try {
    const mock = path.join(fx.cwd, 'plan-fetch.cjs');
    fs.writeFileSync(mock, `
globalThis.fetch = async () => Response.json({ error: 'plan', details: { code: 'MARROW_PLAN_UPGRADE_REQUIRED', exact_fix: 'Upgrade.' } }, { status: 403 });
`);
    const child = spawnSync(process.execPath, [CLI], {
      cwd: fx.cwd, input: mcpFrames(), encoding: 'utf8', timeout: 20_000,
      env: { PATH: process.env.PATH, HOME: fx.home, MARROW_API_KEY: dummyKey(), MARROW_FLEET_AGENT_ID: 'agent-alpha', MARROW_BASE_URL: 'https://127.0.0.1:9', MARROW_AUTO_ENROLL: 'false', MARROW_TOOL_PROFILE: 'core', NODE_OPTIONS: `--require=${mock}` },
    });
    const call = child.stdout.trim().split('\n').map((l) => JSON.parse(l)).find((r) => r.id === 3);
    const payload = JSON.parse(call.result.content[0].text);
    assert.equal(payload.error.status, 403);
    assert.equal(payload.agent_id_source, undefined);
    assert.doesNotMatch(payload.error.message, /took the id/);
  } finally { fx.cleanup(); }
});

test('T1 an id that is a pasted API key is never echoed by the sentence or the tool 403 (the hook head keeps its BASE text)', async () => {
  const fx = fixture('t1k');
  try {
    const pasted = 'mrw_' + crypto.randomBytes(16).toString('hex');
    const lookup = explainIn({ MARROW_API_KEY: dummyKey(), MARROW_FLEET_AGENT_ID: pasted }, fx);
    assert.equal(lookup.agent_id, '<unsafe id>');
    assert.ok(!(JSON.stringify(jsonOf(lookup)) + lazy.explain.agentIdSourceSentence(lookup)).includes(pasted));
    const tool = runToolPath(fx, { MARROW_API_KEY: dummyKey(), MARROW_FLEET_AGENT_ID: pasted });
    assert.ok(!tool.child.stdout.includes(pasted), 'the tool 403 does not echo it');
    assert.equal(tool.payload.agent_id_source.agent_id, '<unsafe id>');
  } finally { fx.cleanup(); }
});
