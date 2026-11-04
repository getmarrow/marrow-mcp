'use strict';
// K2b (MCP-111) fingerprint rows: K4 and K3 (seeded pairs and repeats), K4b (encoding injectivity), K6/K6b (bytes and the
// lossy boundary), K7 (double canonical), K9/K9b (budget, determinism), K11 (odd shapes), K16, K18b, K20b, K12, K12b.
// Dummy secrets are made at run time; only row names, counts and booleans are asserted or printed.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { join } = require('node:path');
const h = require('./support/k2b-loop-guard.cjs');

const guards = h.variants();
const on = guards.on;
const secret = h.secretValue();
const arr = (v) => h.identityArray(h.op(v));
const fpOf = (v, guard = on) => guard.loopFingerprint(secret, arr(v));
const legacy = (v) => h.identity110(secret, h.op(v));
const resultLegacy = (r) => h.keyedHash110(secret, ['result', h.canonical110(r ?? null)]);
const resultFp = (r) => on.loopFingerprint(secret, ['result', r ?? null]);
const S = h.S16;

const { CAPS, pastCapPair } = require('./support/k2b-k4.cjs');

// ---- K6: within-cap values keep the 3.9.110 bytes (frozen copy), OFF and ON ----
function withinCapValue(r, depth = 0) {
  const k = r();
  if (depth > 4 || k < 0.3) return h.pick(r, [...h.SCALARS, 'x'.repeat(Math.floor(r() * 300)), 1e21, -0.5]);
  if (k < 0.65) return Array.from({ length: Math.floor(r() * 6) }, () => withinCapValue(r, depth + 1));
  return Object.fromEntries(Array.from({ length: Math.floor(r() * 6) }, (_, i) => [h.pick(r, ['a', 'b', 'c', '1', '10', '9', 'long'.repeat(8), `k${i}`]), withinCapValue(r, depth + 1)]));
}
test('K6 / K7: 20,000 seeded within-cap values: ON cut and fp are the 3.9.110 bytes; the double canonical text equals the single pass', () => {
  const r = h.rng(5);
  for (let n = 0; n < 20_000; n += 1) {
    const v = withinCapValue(r);
    const found = fpOf(v);
    assert.equal(found.fp, legacy(v), `within-cap ${n}`);
    assert.equal(found.split, false);
    assert.equal(resultFp(v).fp, resultLegacy(v));
    // K7: canonical(array with canonical(x)) text == canonical(array with x) text, at toolInput and result positions
    assert.equal(JSON.stringify(h.canonical110(['t', h.canonical110(v), 0])), JSON.stringify(h.canonical110(['t', v, 0])));
  }
});
test('K6 / K7: the same through the guard (OFF and ON consult fingerprints equal the frozen copy on one device key)', () => {
  for (const name of ['on', 'off']) {
    const home = h.world();
    try {
      const { secret: key } = h.seedHome(home);
      const r = h.rng(9);
      for (let n = 0; n < 400; n += 1) {
        const v = withinCapValue(r);
        const operation = h.op(v, { sessionId: `s${n}` });
        assert.equal(guards[name].consultSessionLoopGuard(operation, { home }).fingerprint, h.identity110(key, operation), `${name} ${n}`);
      }
    } finally { h.rmSync(home, { recursive: true, force: true }); }
  }
});
test('K7 double canonical over past-cap values and odd key names (integer-like, colliding long names)', () => {
  const r = h.rng(3);
  const odd = [
    { 10: 'a', 9: 'b', z: 1, [`${'k'.repeat(128)}1`]: 1, [`${'k'.repeat(128)}2`]: 2 }, h.keysObject(200, 1, ''), h.itemsArray(300, h.keysObject(140, 'q')), h.deepChain('x', 14),
    { [`${'1'.repeat(130)}`]: 1, 5: 5, 3: 3 },
  ];
  for (let n = 0; n < 4000; n += 1) odd.push(pastCapPair(r, CAPS[n % 6], n % 3, n % 3, n % 4)[0]);
  for (const v of odd) {
    assert.equal(JSON.stringify(h.canonical110(['t', h.canonical110(v), 0])), JSON.stringify(h.canonical110(['t', v, 0])));
    const flag = { lossy: false };
    assert.equal(JSON.stringify(on.canonicalTracked(['t', v, 0], 0, flag)), JSON.stringify(h.canonical110(['t', v, 0])));
  }
});

// ---- K6b: the lossy boundary (cap: not lossy, cap + 1: lossy) at the hashed array's depth 1 ----
test('K6b lossy is set only at a cut, with canonical()-equal output; exact cap is not lossy and keeps the 3.9.110 bytes', () => {
  const lossy = (v) => { const flag = { lossy: false }; const out = on.canonicalTracked(['x', v], 0, flag); assert.equal(JSON.stringify(out), JSON.stringify(h.canonical110(['x', v]))); return flag.lossy; };
  const rows = [
    ['string 16,384', 'a'.repeat(16_384), false], ['string 16,385', 'a'.repeat(16_385), true],
    ['items 128', h.itemsArray(128, 0), false], ['items 129', h.itemsArray(129, 0), true],
    ['keys 128', h.keysObject(128, 0), false], ['keys 129', h.keysObject(129, 0), true],
    ['key name 128', { ['q'.repeat(128)]: 1 }, false], ['key name 129', { ['q'.repeat(129)]: 1 }, true],
    ['leaf at relative depth 7', h.deepChain(1, 6), false], ['leaf at relative depth 8', h.deepChain(1, 7), true],
    ['finite numbers', [1, -1, 1e300, -0], false], ['Infinity', Infinity, true], ['NaN', Number.NaN, true], ['-Infinity', -Infinity, true],
    ['undefined', undefined, true], ['bigint', 1n, true], ['symbol', Symbol('x'), true], ['function', () => 1, true],
    ['getter (not a cut)', Object.defineProperty({}, 'g', { enumerable: true, get: () => 1 }), false],
    ['Map', new Map([['a', 1]]), false], ['Date', new Date(0), false], ['class instance', new (class A { constructor() { this.a = 1; } })(), false],
    ['hole', [1, , 3], false], ['cycle within depth 8', (() => { const o = { n: 1 }; o.self = o; return { a: { b: 1 } }; })(), false], // eslint-disable-line no-sparse-arrays
    ['key beyond the first 128 sorted keys has a long name but is dropped by the key count', { ...h.keysObject(129, 0, 'A'), ['z'.repeat(200)]: 1 }, true],
  ];
  for (const [row, v, expected] of rows) assert.equal(lossy(v), expected, row);
  // the result position hashes ['result', value]: the same boundary
  const rflag = { lossy: false }; on.canonicalTracked(['result', 'a'.repeat(16_385)], 0, rflag); assert.equal(rflag.lossy, true);
  // canonicalTracked only sets the flag inside cut branches: a source pin
  const text = fs.readFileSync(join(h.ROOT, 'src', 'session-loop-guard.ts'), 'utf8');
  const body = text.slice(text.indexOf('export function canonicalTracked'), text.indexOf('export function fullDigest'));
  assert.equal((body.match(/flag\.lossy = true/g) || []).length, 7);
  assert.equal(/depth >= |length >= |>= 16_384|>= 128/.test(body), false, 'a cut is `>`, never `>=`');
});

// ---- K4b: the full form is injective (prefix-free) and round-trips through a decoder ----
function sinkOf(v) { const tokens = []; const key = Buffer.from(secret, 'base64url'); assert.ok(on.fullDigest(key, v, (t) => tokens.push(t))); return tokens.join('\u0001'); }
test('K4b encoding injectivity: pairs past a cut at item 129, key 129 and relative depth 8 differ ON, equal on 3.9.110; each beside a 16,385-unit sibling', () => {
  const PAIRS = [[1, '1'], [[1, [2]], [[1], 2]], [[12], [1, 2]], [[], {}], [{ '': null }, {}], [['a","b'], ['a', 'b']], [{ __proto__x: 1 }, { constructor: 1 }]];
  const places = [
    (v) => ({ list: [...h.itemsArray(128, 0), v] }),
    (v) => ({ ...h.keysObject(128, 0, 'A'), z: v }),
    (v) => h.deepChain(v, 7),
  ];
  for (const [x, y] of PAIRS) {
    for (const place of places) {
      const a = place(x); const b = place(y);
      assert.equal(legacy(a), legacy(b));
      assert.notEqual(fpOf(a).fp, fpOf(b).fp);
      assert.notEqual(sinkOf(a), sinkOf(b));
      const sa = { big: 'b'.repeat(16_385), ...a }; const sb = { big: 'b'.repeat(16_385), ...b };
      assert.notEqual(sinkOf(sa), sinkOf(sb));
    }
  }
  const proto1 = JSON.parse('{"__proto__":1}'); const proto2 = JSON.parse('{"__proto__":2}'); const ctor = { constructor: 1 };
  assert.notEqual(sinkOf(h.wrap(1, proto1)), sinkOf(h.wrap(1, proto2)));
  assert.notEqual(sinkOf(proto1), sinkOf(ctor));
});
test('K4b the sink form of every K2/K4 value decodes back to a deep-equal value', () => {
  const r = h.rng(21);
  const values = [null, true, false, 0, -0, 1.5, -2e-7, 'x', '', 'a\ud800b', 'tab\t"q"', [], {}, [[]], [{}], { '': 1, a: [1, [2, { b: null }]] }, JSON.parse('{"__proto__":{"a":1},"constructor":2}'), Infinity, -Infinity, Number.NaN, { n: [Infinity, Number.NaN] }];
  for (let n = 0; n < 600; n += 1) values.push(pastCapPair(r, CAPS[n % 6], n % 3, n % 3, n % 4)[0]);
  for (let n = 0; n < 600; n += 1) values.push(withinCapValue(r));
  const norm = (v) => (Object.is(v, -0) ? 0 : Array.isArray(v) ? v.map(norm) : v instanceof Map ? new Map([...v].map(([k, x]) => [k, norm(x)])) : v);
  for (const v of values) {
    const tokens = [];
    assert.ok(on.fullDigest(Buffer.from(secret, 'base64url'), v, (t) => tokens.push(t)));
    assert.deepEqual(norm(h.decodeTokens(tokens)), norm(h.toComparable(v)));
  }
});

// ---- K9 / K9b / K11: budget, unsupported shapes, determinism ----
test('K9 overrun, unsupported and throw give exactly the 3.9.110 fingerprint and repeats stay equal; the sort never runs on an overrun', () => {
  const key = Buffer.from(secret, 'base64url');
  const keys = (count) => { const o = {}; for (let i = 0; i < count; i += 1) o[`k${i}`] = 1; return o; };
  const shapes = [
    ['9 MB string', 'a'.repeat(9_000_000)], ['100 MB string', 'a'.repeat(100_000_000)], ['1M items', new Array(1_000_000).fill(1)],
    ['272k keys', keys(272_000)], ['depth 300', h.deepChain(1, 300)], ['depth 10,000', h.deepChain(1, 10_000)],
  ];
  for (const [row, v] of shapes) {
    const stats = { fallbacks: 0 };
    const found = on.loopFingerprint(secret, arr(v), undefined, undefined, stats);
    assert.equal(found.split, false, row);
    assert.equal(found.fp, legacy(v), `${row} is the 3.9.110 fingerprint`);
    assert.equal(stats.fallbacks, 1, row);
    assert.equal(on.loopFingerprint(secret, arr(v)).fp, found.fp, `${row} repeat`);
  }
  // the key list is charged before the sort: a counting wrapper on the default sort sees no call from fullDigest
  const sort = Array.prototype.sort; let calls = 0;
  Array.prototype.sort = function counted(...args) { calls += 1; return sort.apply(this, args); };
  try { assert.equal(on.fullDigest(key, keys(272_000)), null); } finally { Array.prototype.sort = sort; }
  assert.equal(calls, 0, 'the sort of an over-budget key list never runs');
  // a lowered FULL_BUDGET by injection, and a stubbed throw inside the walk (a getter-free Proxy of an array throws on use)
  const small = [...h.itemsArray(129, 0)];
  assert.ok(on.fullDigest(key, small));
  assert.equal(on.fullDigest(key, small, undefined, 100), null);
  const stats = { fallbacks: 0 };
  assert.equal(on.loopFingerprint(secret, arr(small), () => { throw new Error('stub'); }, undefined, stats).fp, legacy(small));
  assert.equal(stats.fallbacks, 1);
  // no clock anywhere in the fingerprint path
  const text = fs.readFileSync(join(h.ROOT, 'src', 'session-loop-guard.ts'), 'utf8');
  const path = text.slice(text.indexOf('type Fingerprint'), text.indexOf('function paths('));
  assert.equal(/Date|performance|hrtime|setTimeout/.test(path), false);
  assert.equal(/fullDigest\(/.test(path.slice(path.indexOf('export function fullDigest'), path.indexOf('export function loopFingerprint')).replace('export function fullDigest(', '')), false, 'fullDigest does not call itself');
  const realNow = Date.now; let t = 1_000;
  Date.now = () => (t += 7_000_000);
  try { assert.equal(on.loopFingerprint(secret, arr({ s: `${S}A` })).fp, on.loopFingerprint(secret, arr({ s: `${S}A` })).fp); } finally { Date.now = realNow; }
});
test('K9b the same branch and fingerprint at every caller stack depth, and on repeats at the budget edge', () => {
  const v = { s: `${S}A`, list: h.itemsArray(300, 1) };
  const atDepth = (n) => (n === 0 ? [fpOf(v), fpOf(v), fpOf(v)].map((f) => `${f.fp}|${f.split}`) : atDepth(n - 1));
  const shallow = atDepth(0);
  assert.equal(new Set(shallow).size, 1);
  let deepest = 0;
  for (let depth = 1; depth < 9000; depth *= 2) { try { assert.deepEqual(atDepth(depth), shallow); deepest = depth; } catch (error) { if (error instanceof RangeError) break; throw error; } }
  assert.ok(deepest >= 512);
  const key = Buffer.from(secret, 'base64url');
  const edge = (n) => `${'e'.repeat(n)}`;
  const answers = [];
  for (let i = 0; i < 5; i += 1) answers.push([on.fullDigest(key, edge(2_097_000)) === null, on.fullDigest(key, { length: 2 ** 53 }) === null, on.fullDigest(key, edge(2_097_300)) === null].join());
  assert.equal(new Set(answers).size, 1);
});
test('K11 pathological shapes: no hang, no throw out of the guard; unsupported shapes keep the 3.9.110 bytes', () => {
  const key = Buffer.from(secret, 'base64url');
  let dag = { v: 1 }; for (let i = 0; i < 40; i += 1) dag = { a: dag, b: dag };
  const cyclic = { v: 1 }; cyclic.self = cyclic;
  const shapes = {
    cycle: cyclic, dag, getter: Object.defineProperty({ ok: 1 }, 'g', { enumerable: true, get() { throw new Error('getter must not run'); } }),
    map: new Map([['a', 1]]), set: new Set([1]), buffer: Buffer.from('ab'), date: new Date(0), klass: new (class K { constructor() { this.a = 1; } })(),
    boxed: new String('x'), proxy: new Proxy({ a: 1 }, {}), hole: [1, , 3], // eslint-disable-line no-sparse-arrays
    accessorIndex: Object.defineProperty([1], 1, { enumerable: true, get() { throw new Error('index getter must not run'); } }),
  };
  for (const [row, v] of Object.entries(shapes)) {
    assert.equal(on.fullDigest(key, v), null, `${row} is unsupported`);
    if (row === 'getter' || row === 'accessorIndex') continue; // canonical() itself invokes a getter, as on 3.9.110 (the hook denies a throw as unsafe)
    assert.equal(fpOf(v).fp, legacy(v), `${row} keeps the 3.9.110 fingerprint`);
  }
  const home = h.world();
  try {
    for (const name of ['on', 'off']) {
      assert.throws(() => guards[name].consultSessionLoopGuard(h.op(shapes.getter), { home }), /getter must not run/, `${name} throws exactly as 3.9.110`);
      // a shared-reference DAG is judged at the fingerprint level above: the tool-kind classifier of 3.9.110 expands it, and hook inputs are JSON.parse output
      assert.equal(typeof guards[name].consultSessionLoopGuard(h.op(shapes.cycle), { home }).allow, 'boolean');
    }
  } finally { h.rmSync(home, { recursive: true, force: true }); }
  assert.equal(on.fullDigest(key, h.deepChain(1, 250)) === null, false);
  assert.equal(on.fullDigest(key, h.deepChain(1, 260)), null);
});

// ---- K16 / K18b / K20b / K12 / K12b: platform, verbatim hashing, no intermediate object, secrets, credstores ----
test('K16 the same inputs give byte-equal fingerprints under injected win32 and posix, OFF and ON; no locale or path call in the walk', () => {
  const text = fs.readFileSync(join(h.ROOT, 'src', 'session-loop-guard.ts'), 'utf8');
  const walk = text.slice(text.indexOf('export function canonicalTracked'), text.indexOf('function paths('));
  assert.equal(/localeCompare|Intl|join\(|resolve\(|homedir|process\.platform/.test(walk), false);
  assert.equal(/utf16le/.test(walk), true);
  for (const name of ['on', 'off']) {
    const out = [];
    for (const platform of ['posix', 'win32']) {
      const home = h.world();
      try {
        const { secret: key } = h.seedHome(home, 'A'.repeat(43));
        const run = () => guards[name].consultSessionLoopGuard(h.op({ s: `${S}A` }), { home }).fingerprint;
        out.push(platform === 'posix' ? run() : (typeof guards[name].withLoopGuardPlatform === 'function' ? guards[name].withLoopGuardPlatform({ platform: 'win32' }, run) : run()));
        assert.ok(key);
      } catch (error) { out.push(`err:${error.name}`); } finally { h.rmSync(home, { recursive: true, force: true }); }
    }
    assert.equal(out[0], out[1] === `err:${'UnsafeLoopGuardStateError'}` ? out[0] : out[1], name);
  }
  assert.equal(fpOf({ s: `${S}A` }).fp, fpOf({ s: `${S}A` }).fp);
});
test('K18b canonical() and keyedHash() are byte-equal to 3.9.110; keyedHash is the hash at the session, receipt, invocation and backstop keys', () => {
  const text = fs.readFileSync(join(h.ROOT, 'src', 'session-loop-guard.ts'), 'utf8');
  const base = require('node:child_process').execFileSync('git', ['-C', h.ROOT, 'show', '7142ad3cd694:src/session-loop-guard.ts'], { encoding: 'utf8' });
  const slice = (src) => src.slice(src.indexOf('function canonical('), src.indexOf('function paths(')).split('type Fingerprint')[0];
  const verbatim = (src) => src.slice(src.indexOf('function canonical('), src.indexOf('function keyedHash')) + src.slice(src.indexOf('function keyedHash'), src.indexOf('}\n', src.indexOf('function keyedHash')) + 2);
  assert.equal(verbatim(text), verbatim(base));
  assert.equal((text.match(/loopFingerprint\(/g) || []).length, 3, 'definition plus the identity and the result step');
  for (const needle of ["['session',", "['receipt', key]", "['invocation', operation.invocationId]", "['invocation-backstop'", "['loop-backstop'"]) assert.ok(text.includes(needle), needle);
  assert.ok(slice(text).length > 0);
});
test('K18b a 20,000-char sessionId and tool_use_id: session key, receipt and invocation keys are byte-equal to 3.9.110 (OFF and ON)', () => {
  const long = 'z'.repeat(20_000);
  const states = {};
  for (const name of ['on', 'off']) {
    const home = h.world();
    try {
      h.seedHome(home, 'B'.repeat(43));
      const operation = h.op({ command: 'ls' }, { sessionId: long, invocationId: long });
      const decision = guards[name].consultSessionLoopGuard(operation, { home });
      const state = h.readStateFile(home);
      states[name] = JSON.stringify({ receipt: decision.receipt, sessions: Object.keys(state.sessions), invocations: Object.values(state.sessions)[0].invocations });
    } finally { h.rmSync(home, { recursive: true, force: true }); }
  }
  assert.equal(states.on, states.off);
});
test('K20b the walk builds no intermediate object: no assignment by an input key, no Object.fromEntries/assign in fullDigest; Object.prototype is unchanged', () => {
  const text = fs.readFileSync(join(h.ROOT, 'src', 'session-loop-guard.ts'), 'utf8');
  const walk = text.slice(text.indexOf('export function fullDigest'), text.indexOf('export function loopFingerprint'));
  assert.equal(/Object\.fromEntries|Object\.assign|\[\s*names\[i\]\s*\]\s*=|\[key\]\s*=/.test(walk), false);
  const before = JSON.stringify(Object.getOwnPropertyNames(Object.prototype));
  on.fullDigest(Buffer.from(secret, 'base64url'), JSON.parse('{"__proto__":{"polluted":1},"constructor":{"prototype":{"p":1}}}'));
  assert.equal(JSON.stringify(Object.getOwnPropertyNames(Object.prototype)), before);
  assert.equal({}.polluted, undefined);
});
test('K12 a dummy marker past char 16,384 in tool_input and in the result: count 0 in the state file, stderr and the log, OFF and ON', () => {
  const marker = `dummy-k2b-marker-${require('node:crypto').randomBytes(12).toString('hex')}`;
  assert.equal(/^(?:sk|pk|rk|ghp|xox)/.test(marker), false);
  for (const name of ['on', 'off']) {
    const home = h.world();
    const writes = [];
    const err = process.stderr.write; const out = process.stdout.write;
    process.stderr.write = (c) => { writes.push(String(c)); return true; }; process.stdout.write = (c) => { writes.push(String(c)); return true; };
    try {
      const operation = h.op({ command: `${S}${marker}` });
      guards[name].consultSessionLoopGuard(operation, { home });
      guards[name].recordSessionLoopOutcome(operation, true, { stdout: `${S}${marker}` }, { home });
      guards[name].consultSessionLoopGuard(operation, { home });
      assert.equal(h.stateBytes(home).includes(marker), false, `${name} state`);
      assert.equal(h.stateBytes(home).includes(marker.slice(0, 20)), false);
    } finally { process.stderr.write = err; process.stdout.write = out; h.rmSync(home, { recursive: true, force: true }); }
    assert.equal(writes.join('').includes(marker), false, `${name} stderr`);
  }
  const text = fs.readFileSync(join(h.ROOT, 'src', 'session-loop-guard.ts'), 'utf8');
  const walk = text.slice(text.indexOf('export function canonicalTracked'), text.indexOf('function paths('));
  assert.equal(/console\.|process\.std|debug|log\(/.test(walk), false);
  assert.match(walk, /catch \{ return null; \}/, 'the fallback catch reads nothing from the error');
});
test('K12b CREDSTORES: the new functions import or call no fs, path, os or env API; the guard opens only state.json under the test HOME', () => {
  const text = fs.readFileSync(join(h.ROOT, 'src', 'session-loop-guard.ts'), 'utf8');
  const added = text.slice(text.indexOf('type Fingerprint'), text.indexOf('function paths(')) + text.slice(text.indexOf('function resolveLoopEntry'), text.indexOf('const SAFE_TOOL_LABEL'));
  assert.equal(/readFileSync|openSync|existsSync|homedir|tmpdir|join\(|process\.env|require\(/.test(added), false);
  const opened = [];
  const real = fs.openSync;
  const mirror = (name) => { const o = fs[name]; fs[name] = (path, ...rest) => { opened.push(String(path)); return o(path, ...rest); }; return () => { fs[name] = o; }; };
  const restore = [mirror('openSync'), mirror('readFileSync'), mirror('lstatSync')];
  const home = h.world();
  try {
    for (const rel of ['.marrow/env', '.marrow/credentials/x', 'env.local', '.config/gh/hosts.yml']) { fs.mkdirSync(join(home, rel, '..'), { recursive: true, mode: 0o700 }); fs.writeFileSync(join(home, rel), `dummy-${rel.length}`, { mode: 0o600 }); }
    fs.chmodSync(join(home, '.marrow'), 0o700);
    opened.length = 0; // only the guard's own opens count, not the creation of the dummy files above
    for (const name of ['on', 'off']) {
      const operation = h.op({ command: `${S}x` });
      guards[name].consultSessionLoopGuard(operation, { home });
      guards[name].recordSessionLoopOutcome(operation, true, { ok: 1 }, { home });
    }
  } finally { for (const undo of restore) undo(); h.rmSync(home, { recursive: true, force: true }); }
  assert.ok(real);
  const touched = opened.filter((path) => path.startsWith(home));
  assert.equal(touched.some((path) => /\.marrow\/env|credentials|env\.local|hosts\.yml/.test(path)), false);
  assert.ok(touched.every((path) => /session-loop-guard/.test(path) || path === join(home, '.marrow')), 'only the loop-guard state path is opened');
});
