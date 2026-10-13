'use strict';
// `marrow keys create`: --scopes / --agents absent means the key is left out of
// the request (the server default); a typo'd list loses its empty parts; a flag
// that is present but empty is a usage error (exit 2, nothing sent), never
// "omitted" (omitted = full scopes / unrestricted agents). The marrow_create_key
// tool forwards what the agent sends. Every request is answered by a local stub;
// the key values are runtime dummies and are never printed.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const CLI = path.join(__dirname, '..', 'dist', 'cli.js');
const STUB = path.join(__dirname, 'support', 'keys-fetch-stub.cjs');

const dummyKey = () => `mrw_${crypto.randomBytes(24).toString('hex')}`;

/** One process run against the stub; returns exit status, output, the key creations sent, and the stub's key. */
function run(argv, input) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'keys-create-scopes-'));
  const capture = path.join(dir, 'cap.jsonl');
  fs.writeFileSync(capture, '');
  const created = dummyKey();
  try {
    const child = spawnSync(process.execPath, ['--require', STUB, CLI, ...argv], {
      cwd: dir,
      env: {
        PATH: process.env.PATH,
        HOME: dir,
        MARROW_API_KEY: dummyKey(),
        MARROW_AUTO_HOOK: 'false',
        MARROW_AUTO_ENROLL: 'false',
        MARROW_TOOL_PROFILE: 'full',
        CAPTURE_FILE: capture,
        STUB_KEY: created,
      },
      input,
      encoding: 'utf8',
      timeout: 20_000,
      killSignal: 'SIGKILL',
    });
    const requests = fs.readFileSync(capture, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line));
    const posts = requests.filter((r) => r.method === 'POST' && r.url.endsWith('/v1/auth/keys')).map((r) => r.body);
    return { status: child.status, stdout: child.stdout || '', stderr: child.stderr || '', requests, posts, created };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const create = (...flags) => run(['keys', 'create', '--name', 'n', ...flags]);

function toolCall(args) {
  const rows = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } } },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'marrow_create_key', arguments: args } },
  ];
  return run([], `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`);
}

const BASE = '"name":"n","key_type":"live"';

test('keys create: no --scopes and no --agents leaves both keys out of the request', () => {
  const r = create();
  assert.equal(r.status, 0, r.stderr);
  assert.deepEqual(r.posts, [`{${BASE}}`]);
  assert.equal(r.stdout.includes(r.created), true, 'the created key is printed once, as before');
  assert.equal(r.stdout.split(r.created).length, 2);
  assert.equal(r.stderr.includes(r.created), false);
  assert.equal(r.requests.some((q) => q.url.includes(r.created) || q.body.includes(r.created)), false);
});

test('keys create: a list is sent after dropping empty parts and ASCII whitespace', () => {
  const sent = (flags) => { const r = create(...flags); assert.equal(r.status, 0, r.stderr); return r.posts; };
  assert.deepEqual(sent(['--scopes', 'a']), [`{${BASE},"scopes":["a"]}`]);
  assert.deepEqual(sent(['--scopes', 'a,']), [`{${BASE},"scopes":["a"]}`]);
  assert.deepEqual(sent(['--scopes', ',a']), [`{${BASE},"scopes":["a"]}`]);
  assert.deepEqual(sent(['--scopes', 'a,,b']), [`{${BASE},"scopes":["a","b"]}`]);
  assert.deepEqual(sent(['--scopes', ' a , b ,\t']), [`{${BASE},"scopes":["a","b"]}`]);
  assert.deepEqual(sent(['--scopes=a,b,']), [`{${BASE},"scopes":["a","b"]}`]);
  assert.deepEqual(sent(['--agents', 'x,y,']), [`{${BASE},"agent_ids":["x","y"]}`]);
  assert.deepEqual(sent(['--agents=x']), [`{${BASE},"agent_ids":["x"]}`]);
  assert.deepEqual(
    sent(['--type', 'test', '--scopes', 'a', '--agents', 'x', '--expires', '2030-01-01T00:00:00Z']),
    ['{"name":"n","key_type":"test","scopes":["a"],"agent_ids":["x"],"expires_at":"2030-01-01T00:00:00Z"}'],
  );
});

test('keys create: --scopes / --agents present but empty is a usage error, nothing is sent', () => {
  const empties = [['--scopes', ''], ['--scopes', ','], ['--scopes', ' , '], ['--scopes', ',,\t ,'], ['--scopes='], ['--scopes=,'], ['--scopes=  '], ['--scopes']];
  for (const flags of empties) {
    for (const [flag, noun] of [['--scopes', 'scope'], ['--agents', 'agent']]) {
      const swapped = flags.map((part) => part.replace('--scopes', flag));
      const r = create(...swapped);
      const label = JSON.stringify(swapped);
      assert.equal(r.status, 2, label);
      assert.deepEqual(r.requests, [], `${label}: no request`);
      assert.equal(r.stdout, '', label);
      assert.equal(r.stderr, `Error: list at least one ${noun}, or omit ${flag} for the default\n`, label);
    }
  }
});

test('keys create: a present empty flag is not rescued by the other flag or a later repeat', () => {
  const a = create('--scopes', '', '--agents', 'x');
  assert.equal(a.status, 2);
  assert.deepEqual(a.requests, []);
  const b = create('--scopes', 'a', '--agents', ' , ');
  assert.equal(b.status, 2);
  assert.deepEqual(b.requests, []);
  const c = create('--scopes', '', '--scopes', 'a');
  assert.equal(c.status, 2);
  assert.deepEqual(c.requests, []);
});

test('keys create: repeated flags keep the first one; two lists are never joined', () => {
  assert.deepEqual(create('--scopes', 'a', '--scopes', 'b').posts, [`{${BASE},"scopes":["a"]}`]);
  assert.deepEqual(create('--scopes=a', '--scopes', 'b').posts, [`{${BASE},"scopes":["a"]}`]);
  assert.deepEqual(create('--agents', 'x', '--agents', 'y').posts, [`{${BASE},"agent_ids":["x"]}`]);
  assert.deepEqual(create('--scopes', 'a', '--scopes', '').posts, [`{${BASE},"scopes":["a"]}`]);
});

test('keys create: duplicate, unknown and look-alike entries are sent as they are for the server to reject', () => {
  const lookalikes = ['a,a', 'Full', 'full ', '\u{ff46}ull', 'read ', ' ', 'a b', 'x'.repeat(300)];
  for (const value of lookalikes) {
    const r = create('--scopes', value);
    assert.equal(r.status, 0, JSON.stringify(value));
    const body = JSON.parse(r.posts[0]);
    const expected = value.split(',').map((part) => part.replace(/^[ \t\n\f\r]+|[ \t\n\f\r]+$/g, ''));
    assert.deepEqual(body.scopes, expected, JSON.stringify(value));
    assert.equal(Object.hasOwn(body, 'agent_ids'), false);
  }
  const r = create('--agents', 'a,a');
  assert.deepEqual(JSON.parse(r.posts[0]).agent_ids, ['a', 'a']);
});

test('marrow_create_key tool forwards what the agent sends: [] stays [], absent stays absent', () => {
  const sentBody = (args) => {
    const r = toolCall(args);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.posts.length, 1);
    assert.equal(r.stdout.includes(r.created), true, 'the created key is returned once, as before');
    return r.posts[0];
  };
  assert.equal(sentBody({ name: 'n' }), '{"name":"n"}');
  assert.equal(sentBody({ name: 'n', scopes: [] }), '{"name":"n","scopes":[]}');
  assert.equal(sentBody({ name: 'n', agent_ids: [] }), '{"name":"n","agent_ids":[]}');
  assert.equal(sentBody({ name: 'n', scopes: ['a', ''], agent_ids: [''] }), '{"name":"n","scopes":["a",""],"agent_ids":[""]}');
  assert.equal(sentBody({ name: 'n', scopes: ['a'] }), '{"name":"n","scopes":["a"]}');
});
