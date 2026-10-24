'use strict';

// Keyless start (3.9.106): with no Marrow key anywhere the server reads one, the MCP server answers
// with zero tools and get-a-key instructions instead of exiting 1. Any key, key-shaped input or doubt
// keeps today's path. Keys here are dummies made at runtime; no test prints one.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

const { KEYLESS_NOTICE, keylessInstructions, keylessStart, keylessProtocolVersion } = require('../dist/keyless-server.js');
const { resolveMarrowEnv } = require('../dist/env.js');
const { cursorOfficialMarrowServer, codexOfficialMarrowServer, isOfficialMarrowServerLaunch } = require('../dist/own-server-identity.js');

const CLI = path.join(__dirname, '..', 'dist', 'cli.js');
const EFFECTS = path.join(__dirname, 'support', 'keyless-effects-recorder.cjs');
const NETWORK = path.join(__dirname, 'support', 'm2-network-recorder.cjs');
const dummyKey = (label) => `synthetic-${label}-${crypto.randomBytes(12).toString('hex')}`;
const GET_A_KEY_URL = 'https://getmarrow.ai/signup';
const ACTIVATE_COMMAND = 'npx -y @getmarrow/install@latest activate';
const KEYLESS_INSTRUCTIONS = keylessInstructions({ getKeyUrl: GET_A_KEY_URL, activateCommand: ACTIVATE_COMMAND });
// The text the 3.9.106 builder shipped, pinned whole: the parts passed in from cli.ts must rebuild exactly this.
const SHIPPED_INSTRUCTIONS = 'This Marrow server started without a Marrow key on this machine, so it has no tools. '
  + 'It does not judge, check or record any action. '
  + 'Marrow hooks, where they are set up on this machine, are separate from this server and keep their free keyless seatbelt; this server does not show whether any are set up. '
  + 'To connect a Marrow account, the owner creates a key at https://getmarrow.ai/signup and runs npx -y @getmarrow/install@latest activate in their own terminal, then restarts this agent host. '
  + 'A key can not be added from this chat.';
// The FH no-key refusal (first-hour tip), byte for byte, for the Claude Code plugin and for everything else.
const PLUGIN_REFUSAL = 'Error: MARROW_API_KEY required. Marrow plugin: put MARROW_API_KEY in ~/.marrow/env, run chmod 600 ~/.marrow/env, then /reload-plugins. The seatbelt hooks keep working without a key. Do not run marrow-mcp setup or activate for the plugin.\n'
  + 'Get a key: https://getmarrow.ai/signup. Day-one steps and commands: npx @getmarrow/mcp --help\n';
const PLAIN_REFUSAL = 'Error: MARROW_API_KEY environment variable is required\n'
  + 'Create an API key at https://getmarrow.ai, then export MARROW_API_KEY from trusted secret storage or place it in ~/.marrow/env with owner-only permissions before running npx -y --package=@getmarrow/mcp@latest marrow-mcp setup.\n'
  + 'Get a key: https://getmarrow.ai/signup. Day-one steps and commands: npx @getmarrow/mcp --help\n';
const STATUS_WORDS = /\b(allowed|active|protected|enforced|enforcement|covered|coverage|approved|verified)\b/i;

function scratch(label) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), `keyless-${label}-`)));
  const home = path.join(root, 'home');
  const cwd = path.join(root, 'project');
  fs.mkdirSync(home, { mode: 0o700 });
  fs.mkdirSync(cwd, { mode: 0o700 });
  return { root, home, cwd };
}

function ownerFile(home, name, lines, mode = 0o600) {
  fs.mkdirSync(path.join(home, '.marrow'), { recursive: true, mode: 0o700 });
  const file = path.join(home, '.marrow', name);
  fs.writeFileSync(file, `${lines.join('\n')}\n`, { mode });
  fs.chmodSync(file, mode);
  return file;
}

const frame = (id, method, params) => `${JSON.stringify({ jsonrpc: '2.0', id, method, ...(params === undefined ? {} : { params }) })}\n`;
const INIT = frame(1, 'initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'test', version: '1' } });

/** Starts dist/cli.js, writes each entry of `writes` as one write, ends stdin, and collects the result. */
function run({ home, cwd, env = {}, args = [], writes = [INIT], preload = [EFFECTS], gapMs = 0, endStdin = true }) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [...preload.flatMap((file) => ['--require', file]), CLI, ...args], {
      cwd, env: { PATH: process.env.PATH, HOME: home, USERPROFILE: home, ...env }, stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 20000);
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.stdin.on('error', () => {});
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      const lines = stdout.split('\n').filter(Boolean).map((line) => JSON.parse(line));
      resolve({ code, signal, stdout, stderr, lines, byId: new Map(lines.filter((l) => l.id !== null).map((l) => [l.id, l])) });
    });
    (async () => {
      for (const text of writes) {
        child.stdin.write(text);
        if (gapMs) await new Promise((r) => setTimeout(r, gapMs));
      }
      if (endStdin) child.stdin.end();
    })();
  });
}

function assertKeyless(result, label) {
  assert.equal(result.code, 0, `${label}: exit 0 on stdin end after an initialize`);
  const init = result.byId.get(1);
  assert.ok(init && init.result, `${label}: initialize answered`);
  assert.equal(init.result.instructions, KEYLESS_INSTRUCTIONS, `${label}: keyless instructions`);
  assert.deepEqual(init.result.capabilities, { tools: { listChanged: false } }, `${label}: only tools, none listed`);
  assert.match(result.stderr, new RegExp(KEYLESS_NOTICE.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.doesNotMatch(result.stderr, /environment variable is required|EFFECT /, `${label}: no exit-1 error, no side effect`);
}

function assertRealPath(result, label) {
  const init = result.byId.get(1);
  if (init) {
    assert.notEqual(init.result && init.result.instructions, KEYLESS_INSTRUCTIONS, `${label}: real server, not keyless`);
  } else {
    assert.equal(result.code, 1, `${label}: today's exit 1`);
  }
  assert.doesNotMatch(result.stderr, /no Marrow key on this machine, so the Marrow MCP server started with no tools/, label);
}

// ---------------------------------------------------------------- S1: zero tools, no side effects

test('keyless: initialize, tools/list empty, tools/call refused, prompts/resources empty, nothing else served', async () => {
  const { home, cwd } = scratch('s1');
  const call = (id, name) => frame(id, 'tools/call', { name, arguments: { command: 'git push --force', token: dummyKey('arg') } });
  const r = await run({ home, cwd, writes: [
    frame(0, 'tools/list'), INIT, frame(2, 'tools/list'), call(3, 'marrow_agent_runtime'), call(4, 'marrow_think'), call(5, '__proto__'),
    frame(6, 'tools/call'), frame(7, 'prompts/list'), frame(8, 'resources/list'), frame(9, 'resources/templates/list'),
    frame(10, 'prompts/get', { name: 'marrow-always-on' }), frame(11, 'sampling/createMessage', {}), frame(12, 'ping'),
    frame(13, 'resources/read', { uri: 'file:///etc/passwd' }), frame(14, 'completion/complete', {}),
  ] });
  assertKeyless(r, 's1');
  assert.equal(r.byId.get(0).error.code, -32002, 'tools/list before initialize is refused');
  assert.deepEqual(r.byId.get(2).result, { tools: [] });
  for (const id of [3, 4, 5, 6]) {
    assert.equal(r.byId.get(id).error.code, -32602, `tools/call ${id} is a JSON-RPC error`);
    assert.equal(r.byId.get(id).result, undefined);
  }
  assert.deepEqual(r.byId.get(7).result, { prompts: [] });
  assert.deepEqual(r.byId.get(8).result, { resources: [] });
  assert.deepEqual(r.byId.get(9).result, { resourceTemplates: [] });
  for (const id of [10, 11, 13, 14]) assert.equal(r.byId.get(id).error.code, -32601, `method ${id} not served`);
  assert.deepEqual(r.byId.get(12).result, {});
  assert.equal(r.lines.length, 15, 'one answer per request, no server-initiated request or notification');
  assert.ok(r.lines.every((l) => l.jsonrpc === '2.0' && !('method' in l)), 'stdout carries only responses');
  assert.doesNotMatch(r.stdout, /synthetic-arg|git push/, 'tool arguments are never echoed');
});

test('keyless: no file write, child process or network; HOME and project trees unchanged; the serving code reads no env', async () => {
  const control = spawnSync(process.execPath, ['--require', EFFECTS, '-e', 'try { require("fs").writeFileSync("x", "y") } catch {}'], { encoding: 'utf8', env: { PATH: process.env.PATH } });
  assert.match(control.stderr, /EFFECT fs writeFileSync/, 'the recorder sees writes (positive control)');
  const { root, home, cwd } = scratch('effects');
  const tree = () => {
    const out = [];
    const walk = (dir) => { for (const name of fs.readdirSync(dir).sort()) { const p = path.join(dir, name); const s = fs.lstatSync(p); out.push(`${p}:${s.mode}:${s.size}:${s.mtimeMs}`); if (s.isDirectory()) walk(p); } };
    walk(root);
    return out.join('\n');
  };
  const before = tree();
  const r = await run({ home, cwd, writes: [INIT, frame(2, 'tools/list'), frame(3, 'tools/call', { name: 'marrow_agent_runtime', arguments: {} })] });
  assertKeyless(r, 'effects');
  assert.equal(r.stderr.includes('EFFECT'), false);
  assert.equal(tree(), before, 'nothing created or changed under HOME or the project');
  const source = fs.readFileSync(path.join(__dirname, '..', 'dist', 'keyless-server.js'), 'utf8');
  const serving = source.slice(source.indexOf('function serveKeylessMcp'));
  assert.ok(serving.length > 500 && !/process\.env|require\(|spawn|fetch|writeFile|openSync/.test(serving), 'serveKeylessMcp reads no env, loads nothing, opens nothing');
});

// ---------------------------------------------------------------- S2 / abuse table: what counts as a key

test('abuse: a present key of any shape (invalid, whitespace, MARROW_KEY, duplicates) runs the real server, never keyless', async () => {
  const { root, home, cwd } = scratch('present');
  const key = dummyKey('present');
  const capture = path.join(root, 'net.jsonl');
  const cases = [
    ['invalid key', { MARROW_API_KEY: key }],
    ['whitespace-only key', { MARROW_API_KEY: '   ' }],
    ['tab/newline key', { MARROW_API_KEY: '\t\n' }],
    ['MARROW_KEY only', { MARROW_KEY: key }],
    ['empty MARROW_API_KEY + MARROW_KEY', { MARROW_API_KEY: '', MARROW_KEY: key }],
    ['key + empty MARROW_KEY', { MARROW_API_KEY: key, MARROW_KEY: '' }],
    ['key + other-host base URL', { MARROW_API_KEY: key, MARROW_BASE_URL: 'https://marrow.invalid:8443' }],
  ];
  for (const [label, env] of cases) {
    const r = await run({ home, cwd, env: { MARROW_BASE_URL: 'https://marrow.invalid', CAPTURE_FILE: capture, ...env }, preload: [NETWORK], writes: [INIT, frame(2, 'tools/list')] });
    assertRealPath(r, label);
    assert.ok(r.byId.get(2).result.tools.length > 0, `${label}: the real server's tools`);
    assert.equal(`${r.stdout}${r.stderr}`.includes(key), false, `${label}: key never printed`);
  }
  for (const line of fs.existsSync(capture) ? fs.readFileSync(capture, 'utf8').split('\n').filter(Boolean) : []) {
    assert.match(JSON.parse(line).url || 'marrow.invalid', /marrow\.invalid/, 'the real server only ever addressed its configured host (refused locally)');
  }
});

test('abuse: key-shaped inputs the resolver does not use still keep today\'s exit 1 (fleet key, --key forms, refused owner file)', async () => {
  const { home, cwd } = scratch('ambiguous');
  const key = dummyKey('amb');
  const cases = [
    ['fleet key with matching identity, no direct key', {}, { MARROW_FLEET_AGENT_ID: 'agent-a', MARROW_AGENT_ID_A: 'agent-a', MARROW_KEY_A: key }],
    ['fleet key alone', {}, { MARROW_KEY_B: key }],
    ['--key with empty value', { args: ['--key', ''] }, {}],
    ['--key=value form', { args: [`--key=${key}`] }, {}],
    ['dangling --key', { args: ['--key'] }, {}],
  ];
  for (const [label, extra, env] of cases) {
    const r = await run({ home, cwd, env, ...extra });
    assert.equal(r.code, 1, `${label}: exit 1 as today`);
    assert.match(r.stderr, /MARROW_API_KEY environment variable is required/, label);
    assert.equal(r.lines.length, 0, `${label}: no MCP answer`);
    assert.equal(r.stderr.includes(key), false, `${label}: key never printed`);
  }
  const refusedHome = scratch('refused').home;
  ownerFile(refusedHome, 'env', [`MARROW_API_KEY=${key}`], 0o644);
  const refused = await run({ home: refusedHome, cwd });
  assert.equal(refused.code, 1, 'refused ~/.marrow/env: exit 1 as today');
  assert.match(refused.stderr, /not owner-only[\s\S]*chmod 600/, 'the chmod advice stays visible');
  assert.equal(refused.stderr.includes(key), false);
  assert.equal(resolveMarrowEnv({ env: { HOME: refusedHome }, home: refusedHome, cwd }).ownerFileRefused, true);
  assert.equal(resolveMarrowEnv({ env: { HOME: home }, home, cwd }).ownerFileRefused, undefined, 'absent owner files are not "refused"');
});

test('abuse: a key in ~/.marrow/env or ~/.marrow/env.local only runs the real server', async () => {
  for (const name of ['env', 'env.local']) {
    const { root, home, cwd } = scratch(`owner-${name}`);
    const key = dummyKey('owner');
    ownerFile(home, name, [`MARROW_API_KEY=${key}`, 'MARROW_BASE_URL=https://marrow.invalid']);
    const r = await run({ home, cwd, env: { CAPTURE_FILE: path.join(root, 'net.jsonl') }, preload: [NETWORK], writes: [INIT, frame(2, 'tools/list')] });
    assertRealPath(r, name);
    assert.ok(r.byId.get(2).result.tools.length > 0, `${name}: real tools`);
    assert.equal(`${r.stdout}${r.stderr}`.includes(key), false);
  }
});

test('abuse: a key only in a project .env never counts: keyless, the ignored notice once, the key never printed', async () => {
  const { home, cwd } = scratch('repo');
  const key = dummyKey('repo');
  for (const name of ['.env', '.env.local', path.join('.marrow', 'env')]) {
    const file = path.join(cwd, name);
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    fs.writeFileSync(file, `MARROW_API_KEY=${key}\nMARROW_BASE_URL=https://attacker.invalid\n`, { mode: 0o600 });
  }
  const r = await run({ home, cwd, writes: [INIT, frame(2, 'tools/list')] });
  assertKeyless(r, 'repo key');
  assert.deepEqual(r.byId.get(2).result, { tools: [] });
  assert.equal(r.stderr.split('ignored: keys are read only from ~/.marrow/env or your environment').length, 2, 'notice exactly once');
  assert.equal(`${r.stdout}${r.stderr}`.includes(key), false);
  assert.doesNotMatch(`${r.stdout}${r.stderr}`, /attacker/);
});

test('abuse: empty MARROW_API_KEY / MARROW_KEY and a key under a name the server never reads are keyless (zero tools, nothing echoed)', async () => {
  const { home, cwd } = scratch('empty');
  const key = dummyKey('wrongname');
  for (const env of [{ MARROW_API_KEY: '' }, { MARROW_KEY: '' }, { MARROW_API_KEY: '', MARROW_KEY: '' }, { MARROW_APIKEY: key }, { MARROW_TOKEN: key }, { marrow_api_key: key }, { MARROW_KEY_B: '' }]) {
    const r = await run({ home, cwd, env, writes: [INIT, frame(2, 'tools/list')] });
    assertKeyless(r, JSON.stringify(Object.keys(env)));
    assert.deepEqual(r.byId.get(2).result, { tools: [] });
    assert.equal(`${r.stdout}${r.stderr}`.includes(key), false);
  }
});

test('abuse: hostile MARROW_BASE_URL with no key: https -> keyless with no network and no host echo; http or credentials -> today\'s refusal', async () => {
  const { home, cwd } = scratch('baseurl');
  for (const env of [
    { MARROW_BASE_URL: 'https://attacker.example' },
    { MARROW_BASE_URL: 'https://attacker.example', MARROW_ALLOWED_BASE_URLS: 'https://attacker.example' },
    { MARROW_BASE_URL: 'https://attacker.example', npm_config_registry: 'https://attacker.example', NPM_CONFIG_USERCONFIG: '/nonexistent' },
  ]) {
    const r = await run({ home, cwd, env, writes: [INIT, frame(2, 'tools/list')] });
    assertKeyless(r, JSON.stringify(Object.keys(env)));
    assert.doesNotMatch(`${r.stdout}${r.stderr}`, /attacker/, 'the hostile host is never named or contacted');
  }
  for (const [url, message] of [['http://attacker.example', /must use HTTPS/], ['https://u:p@attacker.example', /must not contain a user name or password/], ['not a url', /not a valid URL/]]) {
    const r = await run({ home, cwd, env: { MARROW_BASE_URL: url } });
    assert.notEqual(r.code, 0, `${url}: refused as today`);
    assert.match(r.stderr, message);
    assert.equal(r.lines.length, 0, `${url}: no MCP answer`);
    assert.doesNotMatch(r.stderr, /EFFECT /);
  }
});

test('keylessStart unit table: only a clear no-key result is keyless; any doubt is false', () => {
  const none = { apiKey: '', baseUrl: 'https://api.getmarrow.ai', source: null, missing: true, exactFix: '' };
  assert.equal(keylessStart(none, [], {}), true);
  assert.equal(keylessStart({ ...none, baseUrl: '' }, [], {}), true, 'empty base URL means the default, as in the server');
  const doubts = [
    [{ ...none, apiKey: ' ' }, [], {}], [{ ...none, apiKey: 'k' }, [], {}], [{ ...none, apiKey: undefined }, [], {}],
    [{ ...none, missing: false }, [], {}], [{ ...none, source: 'MARROW_API_KEY' }, [], {}], [{ ...none, ownerFileRefused: true }, [], {}],
    [{ ...none, ownerFileRefused: false }, [], {}], [{ ...none, baseUrl: 'http://x' }, [], {}], [{ ...none, baseUrl: 42 }, [], {}],
    [none, ['--key', 'k'], {}], [none, ['--key=k'], {}], [none, ['--keyfile'], {}], [none, [42], {}],
    [none, [], { MARROW_KEY_A: 'k' }], [none, [], { MARROW_KEY_: 'k' }], [null, [], {}], ['', [], {}], [[], [], {}],
  ];
  for (const [resolved, argv, env] of doubts) assert.equal(keylessStart(resolved, argv, env), false, JSON.stringify([resolved, argv, env]));
  assert.equal(keylessStart(none, [], { MARROW_KEY_A: '' }), true, 'an empty fleet slot is no key');
  const throwing = { get apiKey() { throw new Error('x'); } };
  assert.equal(keylessStart(throwing, [], {}), false);
});

// ---------------------------------------------------------------- S4: protocol version and cross-host

const PROTOCOL_CASES = [
  undefined, null, [], {}, { protocolVersion: 20250618 }, { protocolVersion: '2099-01-01' }, { protocolVersion: '' },
  { protocolVersion: '2025-06-18' }, { protocolVersion: '2025-06-18', capabilities: { elicitation: true } },
  { protocolVersion: '2025-06-18', capabilities: { elicitation: {} } }, { protocolVersion: '2025-11-25', capabilities: { elicitation: {} } },
  { protocolVersion: '2025-03-26', capabilities: { elicitation: {} } }, { protocolVersion: '2025-06-18 ', capabilities: { elicitation: {} } },
  { protocolVersion: '2025-06-18', capabilities: { elicitation: null } }, { protocolVersion: '2025-06-18', capabilities: { elicitation: [] } },
];

test('initialize with odd protocolVersion values answers exactly what the real server answers', async () => {
  const { root, home, cwd } = scratch('protocol');
  const writes = PROTOCOL_CASES.map((params, i) => frame(i + 1, 'initialize', params));
  const keyless = await run({ home, cwd, writes });
  assertKeyless(keyless, 'protocol');
  const real = await run({ home, cwd, writes, preload: [NETWORK], env: { MARROW_API_KEY: dummyKey('proto'), MARROW_BASE_URL: 'https://marrow.invalid', MARROW_AUTO_ENROLL: 'false', CAPTURE_FILE: path.join(root, 'net.jsonl') } });
  PROTOCOL_CASES.forEach((params, i) => {
    const expected = real.byId.get(i + 1).result.protocolVersion;
    assert.equal(keyless.byId.get(i + 1).result.protocolVersion, expected, JSON.stringify(params));
    assert.equal(keylessProtocolVersion(params), expected);
  });
});

test('cross-host: identical keyless answer for Claude Code, Codex, Cursor, Gemini and others; no status or coverage claim', async () => {
  const { home, cwd } = scratch('hosts');
  const answers = [];
  for (const [name, env] of [['claude-code', {}], ['codex-mcp-client', { MARROW_TOOL_PROFILE: 'full' }], ['cursor-vscode', { MARROW_AUTO_ENROLL: 'false' }], ['gemini-cli-mcp-client', {}], ['hermes', {}], ['', {}]]) {
    const r = await run({ home, cwd, env, writes: [frame(1, 'initialize', { protocolVersion: '2025-06-18', capabilities: { elicitation: {} }, clientInfo: { name, version: '9' } }), frame(2, 'tools/list')] });
    assertKeyless(r, name || 'unnamed');
    answers.push(JSON.stringify([r.byId.get(1).result, r.byId.get(2).result]));
  }
  assert.equal(new Set(answers).size, 1, 'one answer for every host');
  for (const text of [KEYLESS_INSTRUCTIONS, KEYLESS_NOTICE]) {
    assert.doesNotMatch(text, STATUS_WORDS, 'never says allowed/active/protected/enforced/covered');
    assert.doesNotMatch(text, /allow|approv|permit|grant|authori[sz]|proceed|decision|safe to/i, 'the plugin stub test\'s deny words (T2-1)');
    assert.doesNotMatch(text, /Claude|Codex|Cursor|Gemini|Hermes/, 'names no host');
  }
  assert.match(KEYLESS_INSTRUCTIONS, /no tools/);
  assert.match(KEYLESS_INSTRUCTIONS, /https:\/\/getmarrow\.ai\/signup/);
  assert.match(KEYLESS_INSTRUCTIONS, /free keyless seatbelt/);
  const help = spawnSync(process.execPath, [CLI, '--help'], { encoding: 'utf8', env: { PATH: process.env.PATH, HOME: home } }).stdout;
  for (const command of ['https://getmarrow.ai/signup', 'npx -y @getmarrow/install@latest activate']) {
    assert.ok(help.includes(command) && KEYLESS_INSTRUCTIONS.includes(command), `instructions and --help name the same ${command}`);
  }
});

// ---------------------------------------------------------------- S6: stdio framing

test('stdio: partial frame at EOF, two frames in one write, a frame split across writes, oversize line (all after an initialize)', async () => {
  const { home, cwd } = scratch('stdio');
  const partial = await run({ home, cwd, writes: [INIT.trimEnd()] });
  assert.equal(partial.code, 0);
  assert.ok(partial.byId.get(1).result, 'a final frame without newline is still answered');
  const truncated = await run({ home, cwd, writes: [INIT, '{"jsonrpc":"2.0","id":2,"method":"tools/li'] });
  assert.equal(truncated.code, 0);
  assert.equal(truncated.lines.at(-1).error.code, -32700, 'a truncated frame at EOF is a parse error, nothing more');
  const two = await run({ home, cwd, writes: [INIT + frame(2, 'tools/list') + frame(3, 'tools/call', { name: 'marrow_think' })] });
  assert.deepEqual(two.lines.map((l) => l.id), [1, 2, 3], 'frames in one write answered in order');
  assert.equal(two.byId.get(3).error.code, -32602);
  const joined = await run({ home, cwd, writes: [INIT, `${frame(2, 'tools/list').trimEnd()}${frame(3, 'tools/list')}`] });
  assert.equal(joined.lines.at(-1).error.code, -32700, 'two objects on one line are one parse error, neither runs');
  assert.equal(joined.lines.length, 2);
  const split = await run({ home, cwd, writes: [INIT.slice(0, 20), INIT.slice(20), frame(2, 'tools/list')], gapMs: 30 });
  assert.deepEqual(split.byId.get(2).result, { tools: [] }, 'a frame split across writes');
  const big = await run({ home, cwd, writes: [INIT, `{"jsonrpc":"2.0","id":2,"method":"tools/list","pad":"${'x'.repeat(1024 * 1024 + 10)}"}\n`, frame(3, 'tools/list')] });
  assert.equal(big.lines[1].error.code, -32600, 'oversize line refused');
  assert.deepEqual(big.byId.get(3).result, { tools: [] }, 'the next line is served');
  const odd = await run({ home, cwd, writes: [INIT, '[1,2]\n', 'null\n', '{"jsonrpc":"1.0","id":5,"method":"ping"}\n', '{"jsonrpc":"2.0","id":{},"method":"ping"}\n', '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'] });
  assert.deepEqual(odd.lines.slice(1).map((l) => [l.id, l.error.code]), [[null, -32600], [null, -32600], [null, -32600], [null, -32600]], 'invalid requests refused; the notification gets no reply');
});

test('stdio: a closed stdout (EPIPE) ends the keyless server with exit 0', async () => {
  const { home, cwd } = scratch('epipe');
  const result = await new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI], { cwd, env: { PATH: process.env.PATH, HOME: home }, stdio: ['pipe', 'pipe', 'ignore'] });
    const timer = setTimeout(() => child.kill('SIGKILL'), 20000);
    child.stdout.destroy();
    child.stdin.on('error', () => {});
    child.on('close', (code) => { clearTimeout(timer); resolve(code); });
    setTimeout(() => { for (let i = 0; i < 50; i++) child.stdin.write(INIT); }, 100);
  });
  assert.equal(result, 0);
});

// ---------------------------------------------------------------- F1: exit 1 unless a valid initialize arrived

// What master did with no key: the refusal on stderr, nothing on stdout, exit 1.
function assertNoKeyExit(result, label, { stdout = '' } = {}) {
  assert.equal(result.code, 1, `${label}: exit 1 as master`);
  assert.equal(result.stdout, stdout, `${label}: stdout`);
  assert.equal(result.stderr, PLAIN_REFUSAL, `${label}: master's three stderr lines, nothing else (no "started with no tools" notice)`);
}

const CURSOR_HOOK = `${JSON.stringify({ hook_event_name: 'beforeShellExecution', command: 'rm -rf /' })}\n`;
const CLAUDE_HOOK = `${JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'git push --force' }, session_id: 's' })}\n`;

test('F1: the audit repro and other non-MCP first frames exit 1 like master (nothing on stdout, master\'s stderr text)', async () => {
  const { home, cwd } = scratch('f1');
  const frames = [
    ['Cursor beforeShellExecution payload', [CURSOR_HOOK]],
    ['Claude PreToolUse payload', [CLAUDE_HOOK]],
    ['pre-initialize parse error', ['this is not json\n']],
    ['pre-initialize truncated frame at EOF', ['{"jsonrpc":"2.0","id":1,"method":"initial']],
    ['pre-initialize JSON array', ['[1,2]\n']],
    ['pre-initialize null', ['null\n']],
    ['pre-initialize string', ['"initialize"\n']],
    ['jsonrpc 1.0 initialize', ['{"jsonrpc":"1.0","id":1,"method":"initialize"}\n']],
    ['no method', ['{"jsonrpc":"2.0","id":1}\n']],
    ['non-string method', ['{"jsonrpc":"2.0","id":1,"method":7}\n']],
    ['initialize with an invalid id', ['{"jsonrpc":"2.0","id":{},"method":"initialize"}\n']],
    ['pre-initialize oversize line', [`{"jsonrpc":"2.0","id":1,"method":"initialize","pad":"${'x'.repeat(1024 * 1024 + 10)}"}\n`]],
    ['hook payload after blank lines', ['\n\n', CURSOR_HOOK]],
    ['hook payload split across writes', [CURSOR_HOOK.slice(0, 20), CURSOR_HOOK.slice(20)]],
    ['hook payload first, then a valid initialize (never reached)', [CURSOR_HOOK, INIT]],
  ];
  for (const [label, writes] of frames) {
    assertNoKeyExit(await run({ home, cwd, writes }), label);
  }
  // The audit's own repro, through a real shell pipe.
  const piped = spawnSync('sh', ['-c', `printf '%s\\n' '{"hook_event_name":"beforeShellExecution","command":"rm -rf /"}' | "$0" "$1"`, process.execPath, CLI], {
    encoding: 'utf8', cwd, env: { PATH: process.env.PATH, HOME: home },
  });
  assert.equal(piped.status, 1, 'the audit repro exits 1');
  assert.equal(piped.stdout, '');
  assert.equal(piped.stderr, PLAIN_REFUSAL);
});

test('F1: empty stdin, a notification only, or an early end of stdin before any initialize exit 1 like master', async () => {
  const { home, cwd } = scratch('f1-eof');
  assertNoKeyExit(await run({ home, cwd, writes: [] }), 'empty stdin');
  assertNoKeyExit(await run({ home, cwd, writes: ['\n'] }), 'blank line only');
  assertNoKeyExit(await run({ home, cwd, writes: ['{"jsonrpc":"2.0","method":"notifications/initialized"}\n'] }), 'notification only');
  assertNoKeyExit(await run({ home, cwd, writes: ['{"jsonrpc":"2.0","method":"initialize"}\n'] }), 'initialize with no id is a notification, not a request');
  assertNoKeyExit(await run({ home, cwd, writes: [], endStdin: true, gapMs: 0 }), 'stdin closed at once');
});

test('F1: a request before initialize is refused -32002 and does not count as an initialize: EOF is still exit 1; initialize afterwards serves', async () => {
  const { home, cwd } = scratch('f1-ping');
  const ping = await run({ home, cwd, writes: [frame(1, 'ping')] });
  assert.equal(ping.code, 1, 'ping before initialize, then EOF: exit 1');
  assert.deepEqual(ping.lines.map((l) => [l.id, l.error && l.error.code]), [[1, -32002]], 'the only stdout line is the -32002 refusal');
  assert.equal(ping.stderr, PLAIN_REFUSAL);
  const list = await run({ home, cwd, writes: [frame(1, 'tools/list'), frame(2, 'tools/call', { name: 'marrow_agent_runtime', arguments: {} })] });
  assert.equal(list.code, 1);
  assert.deepEqual(list.lines.map((l) => [l.id, l.error.code]), [[1, -32002], [2, -32002]]);
  assert.equal(list.stderr, PLAIN_REFUSAL);
  const then = await run({ home, cwd, writes: [frame(1, 'ping'), frame(2, 'initialize', { protocolVersion: '2024-11-05', capabilities: {} }), frame(3, 'tools/list')] });
  assert.equal(then.code, 0, 'a valid initialize arrived: EOF is exit 0');
  assert.equal(then.byId.get(1).error.code, -32002);
  assert.equal(then.byId.get(2).result.instructions, KEYLESS_INSTRUCTIONS);
  assert.deepEqual(then.byId.get(3).result, { tools: [] });
  assert.match(then.stderr, new RegExp(KEYLESS_NOTICE.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.doesNotMatch(then.stderr, /environment variable is required/);
});

test('F1: once initialized, bad frames are answered as before and EOF is exit 0; a garbage frame before initialize can not be undone', async () => {
  const { home, cwd } = scratch('f1-after');
  const r = await run({ home, cwd, writes: [INIT, 'not json\n', '[1]\n', CURSOR_HOOK, frame(2, 'tools/list')] });
  assert.equal(r.code, 0);
  assert.deepEqual(r.lines.map((l) => (l.error ? l.error.code : 'ok')), ['ok', -32700, -32600, -32600, 'ok']);
  assert.doesNotMatch(r.stderr, /environment variable is required/);
  assertNoKeyExit(await run({ home, cwd, writes: ['not json\n', INIT] }), 'garbage, then a valid initialize: never reached');
});

test('F1: under the Claude Code plugin the non-MCP exit 1 prints FH\'s plugin refusal, and the exit-1 text of both modes equals the server\'s own', async () => {
  const { home, cwd } = scratch('f1-plugin');
  const plugin = await run({ home, cwd, env: { CLAUDE_PLUGIN_ROOT: cwd }, writes: [CURSOR_HOOK] });
  assert.equal(plugin.code, 1);
  assert.equal(plugin.stdout, '');
  assert.equal(plugin.stderr, PLUGIN_REFUSAL);
  // The same text on the path that never reaches the keyless server: a refused owner file still exits 1 with the chmod advice.
  const refusedHome = scratch('f1-plugin-refused').home;
  ownerFile(refusedHome, 'env', [`MARROW_API_KEY=${dummyKey('plugin')}`], 0o644);
  const refused = await run({ home: refusedHome, cwd, env: { CLAUDE_PLUGIN_ROOT: cwd }, writes: [] });
  assert.equal(refused.code, 1);
  assert.equal(refused.stderr, PLUGIN_REFUSAL, 'plugin text, byte for byte, on the unchanged exit-1 path');
  const refusedPlain = await run({ home: refusedHome, cwd, writes: [] });
  assert.equal(refusedPlain.code, 1);
  assert.equal(refusedPlain.stderr.startsWith(PLAIN_REFUSAL.split('\n')[0]), true);
  assert.match(refusedPlain.stderr, /not owner-only[\s\S]*chmod 600[\s\S]*Get a key: https:\/\/getmarrow\.ai\/signup\. Day-one steps and commands: npx @getmarrow\/mcp --help\n$/);
});

test('plugin mode: the keyless answer carries the plugin key steps (one source with the exit-1 text), never the activate command', async () => {
  const { home, cwd } = scratch('plugin-keyless');
  const r = await run({ home, cwd, env: { CLAUDE_PLUGIN_ROOT: cwd }, writes: [INIT, frame(2, 'tools/list')] });
  assert.equal(r.code, 0);
  const text = r.byId.get(1).result.instructions;
  const steps = PLUGIN_REFUSAL.split('\n')[0].replace('Error: MARROW_API_KEY required. ', '');
  assert.ok(text.includes(steps), 'the plugin steps, word for word');
  assert.ok(r.stderr.includes(steps), 'and in the stderr notice');
  assert.doesNotMatch(text, /npx -y @getmarrow\/install|marrow-mcp setup$/);
  assert.match(text, /no tools/);
  assert.match(text, /A key can not be added from this chat\.$/);
  assert.doesNotMatch(text, /allow|approv|permit|grant|authori[sz]|proceed|decision|safe to/i);
  assert.doesNotMatch(text, STATUS_WORDS);
  assert.deepEqual(r.byId.get(2).result, { tools: [] });
  assert.equal(keylessInstructions({ getKeyUrl: GET_A_KEY_URL, activateCommand: ACTIVATE_COMMAND, pluginSteps: steps }), text);
  assert.equal(SHIPPED_INSTRUCTIONS, KEYLESS_INSTRUCTIONS, 'without the plugin the text is what the builder shipped');
  for (const blank of ['', '   ']) {
    const plain = await run({ home, cwd, env: { CLAUDE_PLUGIN_ROOT: blank }, writes: [INIT] });
    assert.equal(plain.byId.get(1).result.instructions, KEYLESS_INSTRUCTIONS, 'a blank CLAUDE_PLUGIN_ROOT is not the plugin');
  }
});

// ---------------------------------------------------------------- consumer: the installer doctor's seatbelt-status

test('consumer: seatbelt-status (installer doctor) with no key is read-only, prints one JSON line, exits 0 and starts no keyless server', async () => {
  const { root, home, cwd } = scratch('status');
  const before = fs.readdirSync(root).join(',');
  for (const writes of [[], [INIT]]) {
    const r = await run({ home, cwd, args: ['seatbelt-status'], writes });
    assert.equal(r.code, 0, 'seatbelt-status exits 0 with no key');
    assert.equal(r.stdout.trim().split('\n').length, 1, 'one line of JSON');
    assert.equal(r.lines.length, 1);
    assert.equal(typeof r.lines[0], 'object');
    assert.equal(r.lines[0].jsonrpc, undefined, 'a status line, not an MCP answer');
    assert.doesNotMatch(r.stderr, /EFFECT |no Marrow key on this machine|environment variable is required/);
  }
  assert.equal(fs.readdirSync(root).join(','), before);
  assert.deepEqual(fs.readdirSync(home), [], 'nothing written under HOME');
});

// ---------------------------------------------------------------- F3: packaging

test('packaging: npm pack lists dist/keyless-server.js (and its types); package.json "files" covers dist', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  assert.ok(pkg.files.includes('dist'), 'package.json files names dist');
  const { root, home } = scratch('pack');
  const packed = spawnSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts', '--offline'], {
    encoding: 'utf8', cwd: path.join(__dirname, '..'),
    env: { PATH: process.env.PATH, HOME: home, npm_config_cache: path.join(root, 'npm-cache'), npm_config_update_notifier: 'false' },
  });
  assert.equal(packed.status, 0, `npm pack --dry-run: ${packed.stderr.slice(0, 300)}`);
  const listed = new Set(JSON.parse(packed.stdout)[0].files.map((file) => file.path));
  for (const required of ['dist/cli.js', 'dist/keyless-server.js', 'dist/keyless-server.d.ts', 'dist/env.js']) {
    assert.ok(listed.has(required), `${required} is in the packed list`);
  }
  // Every module the entry requires locally is itself in the packed list, so a new module can not be left out of the package.
  const entry = fs.readFileSync(path.join(__dirname, '..', 'dist', 'cli.js'), 'utf8');
  const local = [...entry.matchAll(/require\("\.\/([^"]+)"\)/g)].map((m) => `dist/${m[1].replace(/\.js$/, '')}.js`);
  assert.ok(local.includes('dist/keyless-server.js'), 'the entry loads the keyless module');
  for (const file of new Set(local)) assert.ok(listed.has(file), `${file} (required by dist/cli.js) is in the packed list`);
});

// ---------------------------------------------------------------- consumers: identity, setup

test('consumer: own-server identity keeps today\'s verdict whatever the key state (it reads host config only)', () => {
  const files = (table) => (p) => (Object.prototype.hasOwnProperty.call(table, p) ? { state: 'ok', text: table[p] } : { state: 'missing' });
  const official = { marrow: { command: 'npx', args: ['-y', '@getmarrow/mcp'] } };
  const hostile = { marrow: { command: 'node', args: ['/tmp/marrow-lookalike.js'] } };
  const keyed = { marrow: { command: 'npx', args: ['-y', '@getmarrow/mcp'], env: { MARROW_API_KEY: 'x' } } };
  const verdicts = (processEnv) => [official, hostile, keyed].map((servers) => {
    const cursor = cursorOfficialMarrowServer({ home: '/virtual/home', cwds: [], processCwd: '/virtual/p', onlyServer: false, env: processEnv, read: files({ '/virtual/home/.cursor/mcp.json': JSON.stringify({ mcpServers: servers }) }) }).official;
    const toml = Object.entries(servers).map(([name, s]) => `[mcp_servers.${name}]\ncommand = ${JSON.stringify(s.command)}\nargs = ${JSON.stringify(s.args)}\n`).join('');
    const codex = codexOfficialMarrowServer({ env: { CODEX_HOME: '/virtual/codex', ...processEnv }, read: files({ '/virtual/codex/config.toml': toml }), processArgs: null, processCwd: '/virtual/p' }).official;
    return [cursor, codex];
  });
  const noKey = verdicts({});
  assert.deepEqual(noKey, verdicts({ MARROW_API_KEY: dummyKey('id') }), 'the verdict does not depend on a key');
  assert.equal(noKey[0][0], true, 'Cursor: the official npx launch is proven (today)');
  assert.deepEqual(noKey[1], [false, false], 'a look-alike server is never official on Cursor or Codex');
  assert.equal(isOfficialMarrowServerLaunch('node', ['/tmp/marrow-lookalike.js']), false);
  const identitySource = fs.readFileSync(path.join(__dirname, '..', 'dist', 'own-server-identity.js'), 'utf8');
  assert.doesNotMatch(identitySource, /keyless-server/, 'the identity check never consults keyless mode');
});

test('consumer: setup and hooks with no key keep today\'s behaviour (setup exit 2 and writes nothing)', async () => {
  const { home, cwd } = scratch('setup');
  const r = await run({ home, cwd, args: ['setup'], writes: [] });
  assert.equal(r.code, 2);
  assert.match(r.stderr, /needs your API key before setup can write hooks, so nothing was written/);
  assert.doesNotMatch(r.stderr, /EFFECT /);
  assert.equal(r.lines.length, 0);
});
