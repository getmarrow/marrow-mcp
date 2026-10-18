// PKG-M2: a key read from an owner file (~/.marrow/env, ~/.marrow/env.local) is sent only to the
// default endpoint, the endpoint that same file names, or an exact origin that same file lists in
// MARROW_ALLOWED_BASE_URLS. A base URL that only the process environment names never moves it.
// A key from the process environment keeps the process environment URL.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const test = require('node:test');

const { emitBaseUrlNotice, resolveMarrowEnv } = require('../dist/env.js');
const { resolveNativeHookIdentity } = require('../dist/hook-contract.js');

const VECTORS = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'm2-base-url-vectors.json'), 'utf8'));
const DEFAULT_URL = VECTORS.default;
const RECORDER = path.join(__dirname, 'support', 'm2-network-recorder.cjs');
const CLI = path.join(__dirname, '..', 'dist', 'cli.js');

const dummyKey = (label) => `synthetic-${label}-${crypto.randomBytes(12).toString('hex')}`;

function fixture(label) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `marrow-m2-${label}-`));
  const home = path.join(root, 'home');
  const marrowDir = path.join(home, '.marrow');
  fs.mkdirSync(marrowDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  fs.chmodSync(marrowDir, 0o700);
  const cwd = path.join(root, 'work');
  fs.mkdirSync(cwd, { recursive: true, mode: 0o700 });
  return { root, home, marrowDir, cwd, envFile: path.join(marrowDir, 'env'), localFile: path.join(marrowDir, 'env.local') };
}

function write(file, lines, mode = 0o600) {
  fs.writeFileSync(file, `${lines.join('\n')}\n`, { mode });
  fs.chmodSync(file, mode);
}

function ownerFile(fx, key, extra = []) {
  write(fx.envFile, [`MARROW_API_KEY=${key}`, ...extra]);
}

function resolve(fx, env = {}, options = {}) {
  return resolveMarrowEnv({ cwd: fx.cwd, home: fx.home, env, ...options });
}

function assertNoLeak(resolved, key, ...needles) {
  const notice = resolved.baseUrlNotice || '';
  assert.equal(notice.includes(key), false, 'the notice must not contain the key');
  for (const needle of needles) assert.equal(notice.includes(needle), false, `the notice must not contain ${needle}`);
  assert.equal(JSON.stringify({ ...resolved, apiKey: '' }).includes(key), false, 'the key appears only in apiKey');
}

for (const vector of VECTORS.vectors) {
  for (const trustedOnly of [false, true]) {
    test(`owner key + env URL (${trustedOnly ? 'hook' : 'server'} path): ${vector.name}`, () => {
      const fx = fixture('vec');
      const key = dummyKey('owner');
      ownerFile(fx, key, vector.allowed ? [`MARROW_ALLOWED_BASE_URLS=${vector.allowed}`] : []);
      const env = vector.envUrl == null ? {} : { MARROW_BASE_URL: vector.envUrl };
      const resolved = resolve(fx, env, { trustedOnly });
      assert.equal(resolved.apiKey, key, 'the owner-file key is the key in use');
      assert.ok(String(resolved.source).endsWith(':MARROW_API_KEY') && String(resolved.source).startsWith(fx.envFile));
      if (vector.expect === 'kept') assert.equal(resolved.baseUrl, vector.expectedUrl);
      else assert.equal(resolved.baseUrl, DEFAULT_URL);
      assert.equal(Boolean(resolved.baseUrlNotice), vector.expectNotice, `notice presence for ${vector.name}`);
      if (resolved.baseUrlNotice) {
        assert.match(resolved.baseUrlNotice, /^ignored MARROW_BASE_URL from the process environment: the key comes from ~\/\.marrow\/env; list the URL in MARROW_ALLOWED_BASE_URLS in that file to allow it$/);
        assert.equal(resolved.baseUrlNotice.split('\n').length, 1, 'one line');
      }
      const raw = String(vector.envUrl || '');
      assertNoLeak(resolved, key, ...raw.split(/[/@:\s]+/).filter((part) => part.length > 6 && !'https://api.getmarrow.ai'.includes(part)));
    });
  }
}

test('owner key + owner-file URL: kept, and the environment URL is not consulted', () => {
  const fx = fixture('file-url');
  const key = dummyKey('owner');
  ownerFile(fx, key, ['MARROW_BASE_URL=https://staging.example']);
  for (const envUrl of [undefined, 'https://attacker.example', 'https://staging.example', 'http://[::1]:8787']) {
    const resolved = resolve(fx, envUrl ? { MARROW_BASE_URL: envUrl } : {});
    assert.equal(resolved.baseUrl, 'https://staging.example');
    assert.equal(resolved.baseUrlNotice, undefined);
  }
});

test('owner key + owner-allowlisted URL: kept, with the URL the environment named', () => {
  const fx = fixture('allow');
  const key = dummyKey('owner');
  ownerFile(fx, key, ['MARROW_ALLOWED_BASE_URLS=https://one.example,https://two.example:8443']);
  assert.equal(resolve(fx, { MARROW_BASE_URL: 'https://two.example:8443' }).baseUrl, 'https://two.example:8443');
  assert.equal(resolve(fx, { MARROW_BASE_URL: 'https://three.example' }).baseUrl, DEFAULT_URL);
});

test('env key + env URL: unchanged, whatever the URL is', () => {
  const fx = fixture('env-key');
  const key = dummyKey('env');
  for (const url of ['https://attacker.example', 'http://[::1]:8787', 'http://127.0.0.1:9', 'https://user:pw@attacker.example', 'HTTPS://API.GETMARROW.AI']) {
    for (const trustedOnly of [false, true]) {
      const resolved = resolve(fx, { MARROW_API_KEY: key, MARROW_BASE_URL: url }, { trustedOnly });
      assert.equal(resolved.apiKey, key);
      assert.equal(resolved.baseUrl, url, 'an environment key keeps the environment URL (the fleet uses environment keys)');
      assert.equal(resolved.baseUrlNotice, undefined);
    }
  }
  const matched = resolve(fx, { MARROW_API_KEY: key, MARROW_FLEET_AGENT_ID: 'agent-a', MARROW_AGENT_ID_A: 'agent-a', MARROW_KEY_A: dummyKey('fleet'), MARROW_BASE_URL: 'https://fleet.example' });
  assert.equal(matched.baseUrl, 'https://fleet.example');
});

test('both an environment key and an owner-file key: the environment key wins, so its environment URL is kept', () => {
  const fx = fixture('both');
  const envKey = dummyKey('env');
  ownerFile(fx, dummyKey('owner'));
  const resolved = resolve(fx, { MARROW_API_KEY: envKey, MARROW_BASE_URL: 'https://staging.example' });
  assert.equal(resolved.apiKey, envKey);
  assert.equal(resolved.baseUrl, 'https://staging.example');
  assert.equal(resolved.baseUrlNotice, undefined);
});

test('the file that supplies the key is the file whose allowlist counts (env.local key, env allowlist)', () => {
  const fx = fixture('same-file');
  const key = dummyKey('local');
  write(fx.localFile, [`MARROW_API_KEY=${key}`]);
  write(fx.envFile, [`MARROW_API_KEY=${dummyKey('other')}`, 'MARROW_ALLOWED_BASE_URLS=https://staging.example', 'MARROW_BASE_URL=https://named.example']);
  const resolved = resolve(fx, { MARROW_BASE_URL: 'https://staging.example' });
  assert.equal(resolved.apiKey, key);
  assert.equal(resolved.baseUrl, DEFAULT_URL, 'a different owner file cannot authorise the URL');
  assert.ok(resolved.baseUrlNotice);
});

test('an allowlist in a file that is not owner-only supplies nothing: no key, nothing to send', () => {
  const fx = fixture('untrusted');
  const key = dummyKey('loose');
  write(fx.envFile, [`MARROW_API_KEY=${key}`, 'MARROW_ALLOWED_BASE_URLS=https://staging.example'], 0o644);
  const resolved = resolve(fx, { MARROW_BASE_URL: 'https://staging.example' });
  assert.equal(resolved.apiKey, '');
  assert.equal(resolved.missing, true);
  assert.equal(JSON.stringify(resolved).includes(key), false);
});

test('a symlinked owner file supplies nothing: no key, nothing to send', { skip: process.platform === 'win32' }, () => {
  const fx = fixture('symlink');
  const key = dummyKey('linked');
  const real = path.join(fx.root, 'real-env');
  write(real, [`MARROW_API_KEY=${key}`, 'MARROW_ALLOWED_BASE_URLS=https://staging.example']);
  fs.symlinkSync(real, fx.envFile);
  const resolved = resolve(fx, { MARROW_BASE_URL: 'https://staging.example' });
  assert.equal(resolved.apiKey, '');
  assert.equal(resolved.missing, true);
});

test('a project file never supplies a key or an allowlist', () => {
  const fx = fixture('project');
  write(path.join(fx.cwd, '.env'), [`MARROW_API_KEY=${dummyKey('project')}`, 'MARROW_ALLOWED_BASE_URLS=https://attacker.example', 'MARROW_BASE_URL=https://attacker.example']);
  const resolved = resolve(fx, { MARROW_BASE_URL: 'https://attacker.example' });
  assert.equal(resolved.apiKey, '');
});

test('allowlist keys are read only from files: the process environment cannot allowlist itself', () => {
  const fx = fixture('env-allow');
  ownerFile(fx, dummyKey('owner'));
  const resolved = resolve(fx, { MARROW_BASE_URL: 'https://attacker.example', MARROW_ALLOWED_BASE_URLS: 'https://attacker.example' });
  assert.equal(resolved.baseUrl, DEFAULT_URL);
  assert.ok(resolved.baseUrlNotice);
});

test('emitBaseUrlNotice writes one source-only line per process, no matter how often it is called', () => {
  const fx = fixture('emit');
  const key = dummyKey('owner');
  ownerFile(fx, key);
  const resolved = resolve(fx, { MARROW_BASE_URL: 'https://user:pw@attacker.example' });
  const writes = [];
  const original = process.stderr.write;
  process.stderr.write = (chunk) => { writes.push(String(chunk)); return true; };
  try {
    emitBaseUrlNotice(resolved);
    emitBaseUrlNotice(resolved);
    emitBaseUrlNotice({});
  } finally {
    process.stderr.write = original;
  }
  assert.equal(writes.length, 1);
  assert.equal(writes[0].includes(key), false);
  assert.equal(/attacker|pw/.test(writes[0]), false);
});

test('resolveNativeHookIdentity (every hook entrypoint) carries the notice and the default URL, one notice per process', async () => {
  const fx = fixture('identity');
  const key = dummyKey('owner');
  ownerFile(fx, key);
  const script = `
    const { resolveNativeHookIdentity } = require(${JSON.stringify(path.join(__dirname, '..', 'dist', 'hook-contract.js'))});
    const out = [];
    for (const entry of ['claude-pre-action-hook', 'cursor-pre-action-hook', 'codex-pre-action-hook', 'gemini-pre-action-hook', 'claude-hook', 'claude-context-hook']) {
      const identity = resolveNativeHookIdentity(entry, { cwd: ${JSON.stringify(fx.cwd)}, home: ${JSON.stringify(fx.home)}, env: { MARROW_BASE_URL: 'https://attacker.example' } });
      out.push([identity.environment.baseUrl, identity.environment.apiKey === process.env.M2_EXPECT_KEY]);
    }
    process.stdout.write(JSON.stringify(out));
  `;
  const result = await new Promise((resolveRun) => {
    const child = spawn(process.execPath, ['-e', script], { env: { PATH: process.env.PATH, HOME: fx.home, M2_EXPECT_KEY: key }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (status) => resolveRun({ status, stdout, stderr }));
  });
  assert.equal(result.status, 0, result.stderr);
  for (const [baseUrl, keyMatches] of JSON.parse(result.stdout)) {
    assert.equal(baseUrl, DEFAULT_URL);
    assert.equal(keyMatches, true);
  }
  assert.equal(result.stderr.split('\n').filter((line) => line.includes('ignored MARROW_BASE_URL')).length, 1, 'one notice for the process');
  assert.equal(result.stderr.includes(key) || result.stdout.includes(key), false);
});

// ---- consumers, end to end: where does the key actually go? ----

function listener() {
  const connections = [];
  const server = net.createServer((socket) => {
    connections.push(socket.remoteAddress);
    socket.destroy();
  });
  return new Promise((resolveListen) => {
    server.listen(0, '127.0.0.1', () => resolveListen({ server, port: server.address().port, connections }));
  });
}

function run(args, { env, input, cwd }) {
  return new Promise((resolveRun) => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd, env, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 20_000);
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (status) => {
      clearTimeout(timer);
      resolveRun({ status, stdout, stderr });
    });
    child.stdin.on('error', () => {});
    child.stdin.end(input || '');
  });
}

function childEnv(fx, key, extra, { record = true } = {}) {
  const capture = path.join(fx.root, 'capture.jsonl');
  fs.writeFileSync(capture, '');
  return {
    capture,
    env: {
      PATH: process.env.PATH,
      HOME: fx.home,
      CAPTURE_FILE: capture,
      M2_EXPECT_KEY: key,
      ...(record ? { NODE_OPTIONS: `--require=${RECORDER}` } : {}),
      MARROW_AUTO_HOOK: 'true',
      ...extra,
    },
  };
}

function captured(file) {
  return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line));
}

const PAYLOAD = JSON.stringify({
  hook_event_name: 'PreToolUse', session_id: 'm2-session', tool_name: 'Bash', tool_input: { command: 'npm publish' }, prompt: 'hello', cwd: '/tmp',
});

const ENTRYPOINTS = [
  ['ping', []],
  ['claude-pre-action-hook', []],
  ['cursor-pre-action-hook', []],
  ['codex-pre-action-hook', []],
  ['gemini-pre-action-hook', []],
  ['windsurf-pre-action-hook', []],
  ['claude-hook', []],
  ['claude-context-hook', []],
  ['claude-session-hook', []],
  ['spool', ['status']],
  ['keys', ['list']],
  ['(the MCP server, no argument)', null],
];

test('every entrypoint with an owner key and an attacker URL in the environment sends no request to the attacker', async () => {
  for (const attackerUrl of ['https://attacker.example', 'https://api.getmarrow.ai.attacker.example']) {
    for (const [entry, extra] of ENTRYPOINTS) {
      const fx = fixture('e2e');
      const key = dummyKey('owner');
      ownerFile(fx, key);
      const { env, capture } = childEnv(fx, key, { MARROW_BASE_URL: attackerUrl });
      const result = await run(extra === null ? [] : [entry, ...extra], { env, input: extra === null ? '' : PAYLOAD, cwd: fx.cwd });
      for (const record of captured(capture)) {
        if (record.kind === 'fetch') {
          assert.ok(record.url.startsWith(`${DEFAULT_URL}/`) || record.url === DEFAULT_URL, `${entry}: request went to ${new URL(record.url).origin}`);
        }
      }
      assert.equal(`${result.stdout}\n${result.stderr}`.includes(key), false, `${entry}: the key never appears in output`);
    }
  }
});

test('the pre-action hook, the context hook, ping and keys really reach the network layer with the owner key, so the check above is not vacuous', async () => {
  for (const [entry, extra] of [['claude-pre-action-hook', []], ['claude-context-hook', []], ['ping', []], ['keys', ['list']]]) {
    const fx = fixture('control');
    const key = dummyKey('owner');
    ownerFile(fx, key);
    const { env, capture } = childEnv(fx, key, { MARROW_BASE_URL: 'https://attacker.example' });
    await run([entry, ...extra], { env, input: PAYLOAD, cwd: fx.cwd });
    const fetches = captured(capture).filter((record) => record.kind === 'fetch');
    assert.ok(fetches.length > 0, `${entry} made no request`);
    assert.ok(fetches.every((record) => new URL(record.url).origin === DEFAULT_URL), `${entry}: all to the default endpoint`);
    assert.ok(fetches.some((record) => record.carries_key), `${entry}: the owner key went to the default endpoint`);
  }
});

test('an owner-allowlisted origin receives the key; the server entry point reports the notice once', async () => {
  const fx = fixture('allowed-e2e');
  const key = dummyKey('owner');
  ownerFile(fx, key, ['MARROW_ALLOWED_BASE_URLS=https://staging.example']);
  const allowed = childEnv(fx, key, { MARROW_BASE_URL: 'https://staging.example' });
  await run(['ping'], { env: allowed.env, input: '', cwd: fx.cwd });
  const fetches = captured(allowed.capture).filter((record) => record.kind === 'fetch');
  assert.ok(fetches.length > 0);
  assert.ok(fetches.every((record) => new URL(record.url).origin === 'https://staging.example'));
  assert.ok(fetches.some((record) => record.carries_key));

  const denied = childEnv(fx, key, { MARROW_BASE_URL: 'https://attacker.example' });
  const result = await run(['ping'], { env: denied.env, input: '', cwd: fx.cwd });
  const notices = result.stderr.split('\n').filter((line) => line.includes('ignored MARROW_BASE_URL'));
  assert.equal(notices.length, 1);
  assert.equal(/attacker/.test(result.stderr), false, 'the notice names no URL');
  assert.equal(result.stderr.includes(key), false);
});

test('a non-https URL is refused by every entrypoint before any network call: the listener sees nothing (no recorder in the way)', async () => {
  const wrong = await listener();
  try {
    const entries = [
      ['claude-pre-action-hook', []], ['cursor-pre-action-hook', []], ['codex-pre-action-hook', []], ['gemini-pre-action-hook', []],
      ['windsurf-pre-action-hook', []], ['claude-hook', []], ['claude-context-hook', []], ['claude-session-hook', []],
      ['ping', []], ['spool', ['status']], ['keys', ['list']],
    ];
    for (const [entry, extra] of entries) {
      const fx = fixture('http');
      const key = dummyKey('env');
      // 0.0.0.0 reaches the 127.0.0.1 listener if anything connects; it is not a named loopback host.
      const { env } = childEnv(fx, key, { MARROW_API_KEY: key, MARROW_BASE_URL: `http://0.0.0.0:${wrong.port}` }, { record: false });
      const result = await run([entry, ...extra], { env, input: PAYLOAD, cwd: fx.cwd });
      assert.equal(`${result.stdout}\n${result.stderr}`.includes(key), false, `${entry}: the key never appears in output`);
      assert.equal(`${result.stdout}\n${result.stderr}`.includes(`0.0.0.0:${wrong.port}`), false, `${entry}: the URL is not echoed`);
      if (!entry.endsWith('hook')) assert.notEqual(result.status, 0, `${entry}: a command exits non-zero`);
    }
    // The MCP server itself (no argument) stops at start.
    const fx = fixture('http-server');
    const key = dummyKey('env');
    const { env } = childEnv(fx, key, { MARROW_API_KEY: key, MARROW_BASE_URL: `http://0.0.0.0:${wrong.port}` }, { record: false });
    const server = await run([], { env, input: '', cwd: fx.cwd });
    assert.notEqual(server.status, 0, 'the server exits non-zero');
    assert.equal(wrong.connections.length, 0, 'the listener saw no connection');
    // Positive control: the listener is reachable at that address.
    await new Promise((resolveConnect, rejectConnect) => {
      const socket = net.connect(wrong.port, '0.0.0.0', () => { socket.destroy(); resolveConnect(); });
      socket.on('error', rejectConnect);
    });
    await new Promise((resolveWait) => setTimeout(resolveWait, 50));
    assert.equal(wrong.connections.length, 1, 'the control connection was seen, so the listener works');
  } finally {
    wrong.server.close();
  }
});
