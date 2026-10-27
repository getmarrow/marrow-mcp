'use strict';

// Test-only. The dummy secret of the exact-action tests never reads as a Stripe-style key, and the classifier
// (src/key-class.ts, untouched) keeps every answer the live/test split relies on: the look-alike spellings stay live,
// the documented test formats stay test, the live formats stay live, and a live key beside a test key makes the action
// live. Dummy keys are generated at run time and put together from pieces; nothing here prints one, and no assertion
// message carries a value.
const assert = require('node:assert/strict');
const test = require('node:test');
const { randomBytes } = require('node:crypto');
const { keyClassOf } = require('../dist/key-class.js');
const { normalizedHookAction, normalizeShellCommand } = require('../dist/normalized-action.js');
const { dummySecret, assertNotLiveKey, PREFIX, BEFORE } = require('./support/dummy-secret.cjs');
const { LOOKALIKES, live, test: testKey, payload, sh, pick } = require('./support/key-class-rows.cjs');

const norm = (event) => normalizedHookAction(event, { deadlineAt: Date.now() + 5_000 });
const hex = (n) => randomBytes(Math.ceil(n / 2)).toString('hex').slice(0, n);
// `sk_`, `rk_`, `pk_` as pieces, so no file holds a key-shaped literal.
const KEY_PREFIXES = ['sk', 'rk', 'pk'];
const keyOf = (prefix, klass, body) => `${prefix}_${klass}_${body}`;
const body = (length, alphabet = null) => (alphabet ? Array.from(randomBytes(length), (b) => alphabet[b % alphabet.length]).join('') : pick(length));
const AN_DASH = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';

test('dummySecret: 20,000 draws, none reads as a key class behind any delimiter, all distinct, hex after a fixed prefix', () => {
  const seen = new Set();
  for (let i = 0; i < 20_000; i += 1) {
    const value = dummySecret();
    assert.ok(/^zq[0-9a-f]{32}$/.test(value), 'shape: fixed prefix and 32 hex characters');
    seen.add(value);
  }
  assert.equal(seen.size, 20_000, 'every draw differs');
  assert.equal(PREFIX, 'zq');
  assert.ok(BEFORE.includes('') && BEFORE.includes('-') && BEFORE.includes('_'), 'the delimiters that open a key token are covered');
  for (const bytes of [1, 4, 8, 24, 48]) for (let i = 0; i < 500; i += 1) assert.ok(/^zq[0-9a-f]+$/.test(dummySecret(bytes)));
});

test('dummySecret: two draws behind the same text get the same marker and the same key (the S1 claim, 500 pairs x 6 shapes)', () => {
  const shapes = [
    (x) => sh(`vercel deploy --prod --token ${x}`),
    (x) => sh(`curl -H "Authorization: Bearer ${x}" -X DELETE https://api.example.test/v1/deploy`),
    (x) => sh(`DB_PASSWORD=${x} ./migrate.sh down`),
    (x) => sh(`git push https://deploy:${x}@git.example.test/acme/api.git main`),
    (x) => sh(`mysql -u root -p${x} prod -e "drop table x"`),
    (x) => ({ tool_name: 'mcp__ops__deploy', tool_input: { api_key: x, env: 'production' } }),
  ];
  for (const make of shapes) {
    for (let i = 0; i < 500; i += 1) {
      const a = norm(make(dummySecret())); const b = norm(make(dummySecret()));
      assert.equal(a.truncated, true);
      assert.deepEqual(a, b);
      const text = JSON.stringify(a);
      assert.ok(!text.includes('[secret-live]') && !text.includes('[secret-test]'), 'no class marker for a value with no key shape');
    }
  }
});

test('mutants: a generator that can emit a key-shaped token trips the assertion (and the message holds no value)', () => {
  const mutants = {
    'sk_ + 12 key characters': () => `${KEY_PREFIXES[0]}_${hex(12)}`,
    'rk_ + 12 key characters': () => `${KEY_PREFIXES[1]}_${hex(12)}`,
    'pk_ + 12 key characters': () => `${KEY_PREFIXES[2]}_${hex(12)}`,
    'sk_ + 24 mixed-case key characters': () => `${KEY_PREFIXES[0]}_${body(24)}`,
    'SK_ upper case + 12': () => `${KEY_PREFIXES[0].toUpperCase()}_${hex(12)}`,
    'plain prefix, dash, then sk_ + 12': () => `s${hex(6)}-${KEY_PREFIXES[0]}_${hex(12)}`,
    'plain prefix, underscore, then pk_ + 12': () => `s${hex(6)}_${KEY_PREFIXES[2]}_${hex(12)}`,
    'fixed prefix that is itself a key prefix': () => `${KEY_PREFIXES[0]}_${hex(16)}`,
    'sk_ + payload with dashes and underscores': () => `${KEY_PREFIXES[0]}_${body(24, AN_DASH)}`,
    'a TEST key (would put [secret-test] on one action and [secret] on its sibling)': () => keyOf(KEY_PREFIXES[0], 'test', payload()),
    'a live key': () => keyOf(KEY_PREFIXES[0], 'live', payload()),
  };
  for (const [name, make] of Object.entries(mutants)) {
    const value = make();
    assert.throws(() => assertNotLiveKey(value), (error) => error instanceof assert.AssertionError && !error.message.includes(value), name);
  }
});

test('mutant: the previous generator (s + random base64url) trips the assertion within a bounded number of draws', () => {
  let tripped = 0;
  let draws = 0;
  while (!tripped && draws < 500_000) {
    draws += 1;
    try { assertNotLiveKey(`s${randomBytes(24).toString('base64url')}`); } catch { tripped = draws; }
  }
  assert.ok(tripped > 0, 'the old generator is caught (about 1 draw in 2,000)');
});

test('the 31 look-alike spellings: 30 read as live, the Cyrillic-s homoglyph has no class (plain [secret], as master), none is ever test (50 payloads each)', () => {
  assert.equal(LOOKALIKES.length, 31);
  assert.equal(LOOKALIKES.filter((look) => look.expect === 'live').length, 28);
  let liveRows = 0;
  for (const look of LOOKALIKES) {
    const classes = new Set();
    for (let i = 0; i < 50; i += 1) {
      const klass = keyClassOf(look.make(payload()));
      classes.add(klass);
      if (look.expect === 'live') assert.equal(klass, 'live', look.id);
      else assert.notEqual(klass, 'test', look.id);
    }
    if (classes.size === 1 && classes.has('live')) liveRows += 1;
  }
  assert.ok(liveRows >= 30, 'at least 30 of the 31 spellings are live; only a homoglyph that no fold maps to a key letter may have no class');
});

test('documented test formats (sk_test_, pk_test_, rk_test_; 12 to 99 key characters; alone, quoted, in a flag, in a header, two in one span) classify as test', () => {
  for (const prefix of KEY_PREFIXES) {
    for (const length of [12, 13, 24, 40, 99]) {
      for (const alphabet of [null, AN_DASH]) {
        const key = keyOf(prefix, 'test', body(length, alphabet));
        const other = keyOf(prefix, 'test', body(length, alphabet));
        for (const span of [key, `"${key}"`, `--api-key=${key}`, `Authorization: Bearer ${key}`, `${key},${other}`, `K=${key} L=${other}`]) {
          assert.equal(keyClassOf(span), 'test', `${prefix} test, ${length} characters`);
        }
      }
    }
  }
  for (let i = 0; i < 200; i += 1) assert.equal(keyClassOf(testKey()), 'test');
});

test('live formats (sk_live_, rk_live_, pk_live_ and unknown classes) classify as live', () => {
  for (const prefix of KEY_PREFIXES) {
    for (const length of [1, 11, 12, 24, 99]) {
      assert.equal(keyClassOf(keyOf(prefix, 'live', body(length))), 'live', `${prefix} live, ${length} characters`);
    }
    for (const klass of ['prod', 'staging', 'dev', 'live2', 'production', 'testing']) {
      assert.equal(keyClassOf(keyOf(prefix, klass, body(24))), 'live', `${prefix} ${klass}`);
    }
  }
  for (let i = 0; i < 200; i += 1) assert.equal(keyClassOf(live()), 'live');
});

test('both keys in one action: live wins in either order, as a span and through the normalized action', () => {
  for (let i = 0; i < 50; i += 1) {
    const [t1, t2, l] = [testKey(), testKey(), live()];
    assert.equal(keyClassOf(`${t1} ${l}`), 'live');
    assert.equal(keyClassOf(`${l} ${t1}`), 'live');
    assert.equal(keyClassOf(`${t1} ${t2}`), 'test');
    const commands = {
      testLive: `stripe charges list --api-key ${t1} --api-key ${l}`,
      liveTest: `stripe charges list --api-key ${l} --api-key ${t1}`,
      testTest: `stripe charges list --api-key ${t1} --api-key ${t2}`,
      envLiveTest: `STRIPE_KEY=${l} SK=${t1} ./pay.sh`,
      envTestLive: `STRIPE_KEY=${t1} SK=${l} ./pay.sh`,
    };
    const actions = Object.fromEntries(Object.entries(commands).map(([name, command]) => [name, norm(sh(command))]));
    for (const name of ['testLive', 'liveTest', 'envLiveTest', 'envTestLive']) {
      // The text the hashes are made from carries the class markers (one per span); the action itself holds only hashes.
      const text = normalizeShellCommand(commands[name]).text;
      assert.ok(text.includes('[secret-live]'), `${name}: live marker`);
      assert.notEqual(text, normalizeShellCommand(commands.testTest).text, `${name}: not the test-only text`);
      assert.equal(actions[name].truncated, true, `${name}: never bound`);
    }
    assert.ok(normalizeShellCommand(commands.testTest).text.includes('[secret-test]'));
    assert.notDeepEqual(actions.testLive, actions.testTest, 'a live key beside a test key is not the test-only action');
    assert.notDeepEqual(actions.liveTest, actions.testTest);
  }
});
