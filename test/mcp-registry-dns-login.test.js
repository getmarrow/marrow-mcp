'use strict';

// MCPWF1 part A: the registry DNS login helper (scripts/mcp-registry-dns-login.cjs) reads the Ed25519
// signing key from its environment only. Rows AK1-AK14 run it against a loopback fake registry with a key
// pair made at runtime; rows S1-S5 read every workflow file and fail when a secret can reach a run line.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const HELPER = path.join(ROOT, 'scripts', 'mcp-registry-dns-login.cjs');
const WF_DIR = path.join(ROOT, '.github', 'workflows');
const LOGIN_RUN = 'node scripts/mcp-registry-dns-login.cjs --domain getmarrow.ai';
const OK_LINE = 'MCP_REGISTRY_LOGIN=OK method=dns domain=getmarrow.ai\n';

// Runtime dummy key pair: the 32-byte Ed25519 seed is the tail of the PKCS8 DER.
const pair = crypto.generateKeyPairSync('ed25519');
const KEY = pair.privateKey.export({ format: 'der', type: 'pkcs8' }).subarray(-32).toString('hex');
const PEM = pair.privateKey.export({ format: 'pem', type: 'pkcs8' });
const OTHER_PUB = crypto.generateKeyPairSync('ed25519').publicKey;
const ARG_KEY = crypto.randomBytes(32).toString('hex');
const TOKEN = `dummy-registry-token-${crypto.randomBytes(24).toString('hex')}`;
const CANARY = `canary-body-${crypto.randomBytes(12).toString('hex')}`;
assert.match(KEY, /^[0-9a-f]{64}$/);
for (const v of [KEY, ARG_KEY, TOKEN]) assert.doesNotMatch(v, /^(sk_|pk_|rk_|ghp_|xox)/);
const secrets = new Set([KEY, ARG_KEY, TOKEN, PEM]); // signatures join as the fake receives them
const [outputs, homes] = [[], []];

const windows = (v) => Array.from({ length: Math.max(0, v.length - 15) }, (_, i) => v.slice(i, i + 16));
const leaks = (text) => [...secrets].flatMap((s) => windows(s.toLowerCase())).filter((w) => String(text).toLowerCase().includes(w)).length;

function server(handler) {
  const s = Object.assign(http.createServer((req, res) => {
    s.count += 1;
    let body = '';
    req.setEncoding('utf8').on('data', (c) => { body += c; }).on('end', () => s.handler(req, body, res));
  }), { count: 0, handler });
  return new Promise((resolve) => s.listen(0, '127.0.0.1', () => {
    s.url = `http://127.0.0.1:${s.address().port}`;
    resolve(s);
  }));
}

let [fake, other, current] = [];
test.before(async () => { fake = await server(() => {}); other = await server((q, b, res) => res.end('{}')); });
test.after(() => {
  for (const s of [fake, other]) s.closeAllConnections(), s.close();
  for (const h of homes) fs.rmSync(h, { recursive: true, force: true });
});

const tokenFile = (home) => path.join(home, '.config', 'mcp-publisher', 'token.json');

// opts.key: null = unset; opts.env: overrides (undefined deletes); opts.fastTimeout lowers only the
// helper's exported test constant (never an argument or env); opts.pre plants an old 0644 token file.
function run(args, opts = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-dns-login-'));
  homes.push(home);
  if (opts.pre) {
    fs.mkdirSync(path.dirname(tokenFile(home)), { recursive: true, mode: 0o755 });
    fs.writeFileSync(tokenFile(home), '{"token":"old"}', { mode: 0o644 });
  }
  const env = { PATH: process.env.PATH, HOME: home, MCP_PRIVATE_KEY: 'key' in opts ? opts.key : KEY, ...opts.env };
  for (const k of Object.keys(env)) if (env[k] === undefined || env[k] === null) delete env[k];
  const argv = opts.fastTimeout
    ? ['-e', `const h = require(${JSON.stringify(HELPER)}); h.limits.timeoutMs = 400; h.main(process.argv.slice(1));`, '--', ...args]
    : [HELPER, ...args];
  return new Promise((resolve) => {
    const child = spawn(process.execPath, argv, { env, stdio: ['ignore', 'pipe', 'pipe'] });
    current = child;
    let [out, err] = ['', ''];
    child.stdout.on('data', (c) => { out += c; });
    child.stderr.on('data', (c) => { err += c; });
    child.on('close', (code) => {
      outputs.push(out, err);
      assert.equal(leaks(out + err), 0, 'no window of a key, signature or token in the output');
      resolve({ code, out, err, home });
    });
  });
}

// AK1: every readable /proc/<pid>/cmdline, the helper's own included, while the fake holds the request.
function procScan(pid) {
  if (process.platform !== 'linux') return null;
  const all = fs.readdirSync('/proc').filter((d) => /^\d+$/.test(d)).map((d) => {
    try { return fs.readFileSync(`/proc/${d}/cmdline`, 'utf8'); } catch { return null; }
  }).filter((t) => t !== null);
  return { own: fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8'), read: all.length, hits: all.reduce((n, t) => n + leaks(t), 0) };
}

function grant(seen) {
  return (req, body, res) => {
    seen.push({ method: req.method, url: req.url, ctype: req.headers['content-type'], accept: req.headers.accept, body, at: Date.now(), proc: procScan(current.pid) });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ registry_token: TOKEN, expires_at: 4102444800 }));
  };
}

const MODE = (p) => fs.statSync(p).mode & 0o777;
function refused(r, code, line) {
  assert.equal(r.code, code);
  if (line instanceof RegExp) assert.match(r.out, line); else assert.equal(r.out, line);
  assert.equal(fs.existsSync(tokenFile(r.home)), false, 'no token file');
}

test('AK1 AK2 AK10 AK11: key from env only, a real signed request, token file 0600 replacing an old 0644 one', async (t) => {
  const seen = [];
  fake.handler = grant(seen);
  const r = await run(['--domain', 'getmarrow.ai', '--registry', fake.url], { pre: true });
  assert.equal(r.code, 0);
  assert.equal(r.out, OK_LINE);
  assert.equal(r.err, '');
  assert.equal(seen.length, 1);
  const s = seen[0];
  assert.deepEqual([s.method, s.url, s.ctype, s.accept], ['POST', '/v0/auth/dns', 'application/json', 'application/json']);
  const body = JSON.parse(s.body);
  assert.deepEqual(Object.keys(body).sort(), ['domain', 'signed_timestamp', 'timestamp']);
  assert.equal(body.domain, 'getmarrow.ai');
  assert.match(body.timestamp, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
  assert.ok(Math.abs(Date.parse(body.timestamp) - s.at) <= 15000);
  assert.match(body.signed_timestamp, /^[0-9a-f]{128}$/);
  secrets.add(body.signed_timestamp);
  const sig = Buffer.from(body.signed_timestamp, 'hex');
  assert.equal(crypto.verify(null, Buffer.from(body.timestamp, 'utf8'), pair.publicKey, sig), true);
  assert.equal(crypto.verify(null, Buffer.from(body.timestamp, 'utf8'), OTHER_PUB, sig), false, 'the check is real');
  if (s.proc === null) assert.ok(!process.env.CI, 'the /proc reads never skip under CI'), t.diagnostic('AK1 /proc reads skipped: not Linux');
  else assert.deepEqual([/mcp-registry-dns-login\.cjs/.test(s.proc.own), s.proc.read > 1, s.proc.hits], [true, true, 0], 'no key window in any argv');
  const file = tokenFile(r.home);
  assert.equal(MODE(path.dirname(file)), 0o700);
  assert.equal(MODE(file), 0o600);
  const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(Object.keys(saved).sort(), ['method', 'registry', 'token']);
  assert.deepEqual([saved.token === TOKEN, saved.method, saved.registry], [true, 'dns', fake.url]);
});

test('COLL1: two logins with the same key differ only in timestamp and signature', async () => {
  const seen = [];
  fake.handler = grant(seen);
  for (let i = 0; i < 2; i += 1) assert.equal((await run(['--domain', 'getmarrow.ai', '--registry', fake.url])).code, 0);
  const [a, b] = seen.map((s) => JSON.parse(s.body));
  for (const x of [a, b]) secrets.add(x.signed_timestamp);
  assert.equal(a.domain, b.domain);
  assert.equal(a.timestamp === b.timestamp, a.signed_timestamp === b.signed_timestamp);
});

test('AK3: --private-key in any form or a bare hex argument exits 2 before the key is read', async () => {
  fake.handler = grant([]);
  const before = fake.count;
  const cases = [
    [['--domain', 'getmarrow.ai', '--registry', fake.url, '--private-key', ARG_KEY], 5],
    [['--domain', 'getmarrow.ai', '--registry', fake.url, `--private-key=${ARG_KEY}`], 5],
    [['--domain', 'getmarrow.ai', ARG_KEY, '--registry', fake.url], 3],
  ];
  for (const [args, pos] of cases) {
    const r = await run(args, { key: 'not-a-key' });
    refused(r, 2, `MCP_REGISTRY_LOGIN=FAIL bad_argument position=${pos}\n`);
  }
  assert.equal(fake.count, before);
});

test('AK4: a missing or malformed key exits 2 with its length only', async () => {
  fake.handler = grant([]);
  const before = fake.count;
  const hex = crypto.randomBytes(33).toString('hex');
  for (const key of [null, '', hex.slice(0, 63), hex.slice(0, 65), 'g'.repeat(64), `${hex.slice(0, 32)} ${hex.slice(32, 64)}`, PEM, `0x${hex.slice(0, 64)}`]) {
    const r = await run(['--domain', 'getmarrow.ai', '--registry', fake.url], { key });
    refused(r, 2, `MCP_REGISTRY_LOGIN=FAIL key_missing_or_malformed length=${(key || '').length}\n`);
  }
  assert.equal(fake.count, before);
});

test('AK5: 401, 403, 429 and 500 exit 1 without the body and without a token file', async () => {
  for (const status of [401, 403, 429, 500]) {
    fake.handler = (q, b, res) => { res.writeHead(status); res.end(`{"error":"${CANARY}","registry_token":"${TOKEN}"}`); };
    const r = await run(['--domain', 'getmarrow.ai', '--registry', fake.url], { pre: true });
    refused(r, 1, `MCP_REGISTRY_LOGIN=FAIL status=${status}\n`);
    assert.ok(!(r.out + r.err).includes(CANARY));
  }
});

test('AK6: a 200 without a usable string token exits 1 without a token file', async () => {
  for (const body of [`not json ${CANARY}`, '{}', '{"registry_token":5}', '{"registry_token":""}', '[]', 'null']) {
    fake.handler = (q, b, res) => { res.writeHead(200); res.end(body); };
    const r = await run(['--domain', 'getmarrow.ai', '--registry', fake.url]);
    refused(r, 1, /^MCP_REGISTRY_LOGIN=FAIL status=[a-z0-9_]+\n$/);
    assert.ok(!(r.out + r.err).includes(CANARY));
  }
});

test('AK7: a redirect is never followed', async () => {
  fake.handler = (q, b, res) => { res.writeHead(302, { location: `${other.url}/v0/auth/dns` }); res.end(); };
  const r = await run(['--domain', 'getmarrow.ai', '--registry', fake.url]);
  refused(r, 1, 'MCP_REGISTRY_LOGIN=FAIL status=302\n');
  assert.equal(other.count, 0);
});

test('AK8: refused registry URLs exit 2 before any request', async () => {
  fake.handler = grant([]);
  const before = fake.count;
  const port = new URL(fake.url).port;
  for (const url of ['http://example.invalid', 'file:///etc/passwd', 'ftp://h', 'https://u:p@h', 'https://h/?x=1', 'https://h/#f',
    'http://127.0.0.2:1', '', `http://localhost:${port}`, `${fake.url}/?x=1`, `${fake.url}#f`, `http://0x7f.0.0.1:${port}`, `http://127.1:${port}`]) {
    const r = await run(['--domain', 'getmarrow.ai', '--registry', url]);
    refused(r, 2, /^MCP_REGISTRY_LOGIN=FAIL [a-z_]+( position=\d)?\n$/);
  }
  assert.equal(fake.count, before);
});

test('AK9: TLS checks off, or HOME relative, missing or not a directory, exits 2 before any request', async () => {
  fake.handler = grant([]);
  const before = fake.count;
  for (const env of [{ NODE_TLS_REJECT_UNAUTHORIZED: '0' }, { HOME: 'relative/home' }, { HOME: undefined }, { HOME: '' }, { HOME: path.join(os.tmpdir(), `absent-${crypto.randomBytes(6).toString('hex')}`) }]) {
    const r = await run(['--domain', 'getmarrow.ai', '--registry', fake.url], { env });
    refused(r, 2, /^MCP_REGISTRY_LOGIN=FAIL [a-z_]+\n$/);
  }
  assert.equal(fake.count, before);
});

test('AK13: bad domain forms exit 2 before any request', async () => {
  fake.handler = grant([]);
  const before = fake.count;
  for (const args of [['--domain', 'getmarrow.ai;id'], ['--domain', ''], ['--domain', '-x'], ['--domain', 'getmarrow.ai', '--domain', 'getmarrow.ai'],
    ['--domain', 'GetMarrow.ai'], ['--domain', 'getmarrow.ai.'], [], ['--domain'], ['--domain=getmarrow.ai'], ['--domain', 'getmarrow'], ['--domain', 'getmarrow\u0430.ai']]) {
    const r = await run([...args, '--registry', fake.url]);
    refused(r, 2, /^MCP_REGISTRY_LOGIN=FAIL [a-z_]+( position=\d)?\n$/);
  }
  assert.equal(fake.count, before);
});

test('AK14: a registry slower than the timeout exits 1 without a token file', async () => {
  fake.handler = () => {}; // holds the request open
  const r = await run(['--domain', 'getmarrow.ai', '--registry', fake.url], { fastTimeout: true });
  refused(r, 1, 'MCP_REGISTRY_LOGIN=FAIL status=timeout\n');
  fake.closeAllConnections();
});

test('AK12: the helper spawns nothing, drops the key from its environment and prints two fixed lines', () => {
  const src = fs.readFileSync(HELPER, 'utf8');
  for (const word of ['child_process', 'worker_threads', 'vm', 'console.', 'process.stderr', 'eval(', 'Function(']) {
    assert.ok(!src.includes(word), word);
  }
  const mods = [...src.matchAll(/require\(([^)]*)\)/g)].map((m) => m[1]);
  assert.deepEqual(mods.filter((m) => !/^'node:(crypto|fs|path|http|https)'$/.test(m)), []);
  assert.ok(src.includes('delete process.env.MCP_PRIVATE_KEY'));
  const writes = [...src.matchAll(/process\.stdout\.write\(([^\n]*)/g)].map((m) => m[1]);
  assert.equal(writes.length, 2);
  assert.ok(writes.some((w) => w.startsWith('`MCP_REGISTRY_LOGIN=OK method=dns domain=${')));
  assert.ok(writes.some((w) => w.startsWith('`MCP_REGISTRY_LOGIN=FAIL ${')));
});

test('AK2 COLL2: no key, signature or token window in any output of this file', () => {
  assert.ok(outputs.length >= 40);
  assert.equal(outputs.reduce((n, o) => n + leaks(o), 0), 0);
});

// S1-S5: a small line reader of steps, env maps and run text. Any form it does not understand fails.
const SECRET_EXPR = /\$\{\{[^}]*\bsecrets\b/;
function readWorkflow(text) {
  const [lines, runs, envs, errors] = [text.split('\n'), [], [], []];
  let step = -1;
  const indent = (l) => l.length - l.trimStart().length;
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (/^\s*(#.*)?$/.test(line)) continue;
    const m = /^(\s*)(- )?([A-Za-z_][\w-]*):(?:\s+(.*))?$/.exec(line);
    if (m && m[2]) step = i;
    const ind = m ? m[1].length + (m[2] ? 2 : 0) : 0;
    const rest = m ? (m[4] || '').trim() : '';
    const block = () => {
      const out = [];
      while (i + 1 < lines.length && (/^\s*$/.test(lines[i + 1]) || indent(lines[i + 1]) > ind)) out.push(lines[(i += 1)]);
      return out;
    };
    if (m && m[3] === 'run') {
      if (/^[|>][-+]?(\s+#.*)?$/.test(rest)) runs.push({ step, text: block().map((l) => l.trim()).join('\n') });
      else if (rest && !/^['"{[&*!|>%@`]/.test(rest)) runs.push({ step, text: rest });
      else errors.push(`${i + 1}: run form`);
    } else if (m && m[3] === 'env') {
      if (rest && !rest.startsWith('#')) { errors.push(`${i + 1}: env form`); continue; }
      for (const l of block()) {
        if (/^\s*(#.*)?$/.test(l)) continue;
        const e = /^\s+([A-Za-z_]\w*):\s*(.*)$/.exec(l);
        if (e && !/^[|>]/.test(e[2])) envs.push({ step, name: e[1], value: e[2].trim() });
        else errors.push(`${i + 1}: env entry form`);
      }
    } else if (SECRET_EXPR.test(line)) errors.push(`${i + 1}: secret outside env`);
  }
  return { lines, runs, envs, errors };
}

const REG = 'publish-mcp-registry.yml';
function selfCheck(files) {
  const v = { errors: [], S1: [], S2: [], S3: [], S4: [] };
  const parsed = Object.fromEntries(Object.entries(files).map(([n, t]) => [n, readWorkflow(t)]));
  const bound = Object.values(parsed).flatMap((p) => p.envs.filter((e) => SECRET_EXPR.test(e.value)).map((e) => e.name));
  for (const [name, p] of Object.entries(parsed)) {
    v.errors.push(...p.errors.map((e) => `${name}:${e}`));
    for (const r of p.runs) {
      if (SECRET_EXPR.test(r.text)) v.S1.push(name);
      for (const b of bound) if (new RegExp(`\\b${b}\\b`).test(r.text)) v.S2.push(`${name}:${b}`); // $X, ${X, X=, env.X, printenv X
      if (r.text.includes('--private-key') || /mcp-publisher\s+login/.test(r.text)) v.S4.push(name);
    }
  }
  const reg = parsed[REG];
  const keyEnv = reg.envs.filter((e) => e.name === 'MCP_PRIVATE_KEY' || e.value.includes('MCP_PRIVATE_KEY'));
  const ok = keyEnv.length === 1 && keyEnv[0].name === 'MCP_PRIVATE_KEY' && keyEnv[0].value === '${{ secrets.MCP_PRIVATE_KEY }}'
    && reg.lines[keyEnv[0].step] === '      - name: Authenticate with getmarrow.ai DNS (ai.getmarrow/* namespace)'
    && reg.runs.filter((r) => r.step === keyEnv[0].step).map((r) => r.text).join('|') === LOGIN_RUN
    && bound.filter((b) => b === 'MCP_PRIVATE_KEY').length === 1;
  if (!ok) v.S3.push(REG);
  return v;
}
const WORKFLOWS = Object.fromEntries(fs.readdirSync(WF_DIR).filter((f) => /\.ya?ml$/.test(f)).map((f) => [f, fs.readFileSync(path.join(WF_DIR, f), 'utf8')]));
const REAL = selfCheck(WORKFLOWS);

test('S1: no run text in any workflow holds a secrets expression (the reader understood every line)', () => {
  assert.ok(Object.keys(WORKFLOWS).length >= 4 && REG in WORKFLOWS);
  assert.deepEqual(REAL.errors, []);
  assert.deepEqual(REAL.S1, []);
});
test('S2: no env name bound to a secret is named in any run text', () => assert.deepEqual(REAL.S2, []));
test('S3: MCP_PRIVATE_KEY is bound once, in the login step, whose run is the helper line', () => assert.deepEqual(REAL.S3, []));
test('S4: no run text holds --private-key or mcp-publisher login', () => assert.deepEqual(REAL.S4, []));

test('S5: the registry workflow keeps its triggers, permission, environment, pins and steps', () => {
  const lines = WORKFLOWS[REG].split('\n');
  const want = {
    3: 'on:', 4: '  workflow_dispatch:', 5: '  push:', 6: '    tags:', 7: "      - 'mcp-registry-v*'", 8: '', 9: 'permissions:', 10: '  contents: read',
    11: '', 12: 'concurrency:', 13: '  group: publish-mcp-registry', 14: '  cancel-in-progress: false',
    18: '    runs-on: ubuntu-latest', 19: '    environment: mcp-registry-publish', 20: '    timeout-minutes: 10',
    33: '          PUBLISHER_SHA256: ab128162b0616090b47cf245afe0a23f3ef08936fdce19074f5ba0a4469281ac',
    36: '            https://github.com/modelcontextprotocol/registry/releases/download/v1.7.9/mcp-publisher_linux_amd64.tar.gz \\',
    38: '          echo "$PUBLISHER_SHA256  /tmp/mcp-publisher.tar.gz" | sha256sum --check --strict',
    40: "          ./mcp-publisher --version 2>&1 | grep -F 'mcp-publisher 1.7.9'",
    43: '        run: ./mcp-publisher validate', 51: '        run: ./mcp-publisher publish', 54: '        run: npm run registry:verify',
  };
  for (const [n, text] of Object.entries(want)) assert.equal(lines[n - 1], text, `line ${n}`);
  assert.equal((WORKFLOWS[REG].match(/permissions:|id-token|environment:|timeout-minutes:|uses:/g) || []).join(','),
    'permissions:,environment:,timeout-minutes:,uses:');
});

test('S1-S4 in-memory plants each turn their rows red', () => {
  const plant = (n, text) => {
    const lines = WORKFLOWS[REG].split('\n');
    lines[n - 1] = text;
    return selfCheck({ ...WORKFLOWS, [REG]: lines.join('\n') });
  };
  const old = plant(48, '        run: ./mcp-publisher login dns --domain getmarrow.ai --private-key "$MCP_PRIVATE_KEY"');
  assert.ok(old.S2.length && old.S3.length && old.S4.length);
  assert.ok(plant(48, `        run: ${LOGIN_RUN} --x "\${{ secrets.MCP_PRIVATE_KEY }}"`).S1.length);
  const moved = plant(43, '        run: ./mcp-publisher validate --private-key "$MCP_PRIVATE_KEY"');
  assert.ok(moved.S2.length && moved.S4.length);
  const piped = plant(48, `        run: printf '%s' "$MCP_PRIVATE_KEY" | ./mcp-publisher login dns --domain getmarrow.ai`);
  assert.ok(piped.S2.length && piped.S3.length && piped.S4.length);
});
