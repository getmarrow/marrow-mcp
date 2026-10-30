'use strict';

// An approval, hold or correlation made for an action with a test key (sk_test_, rk_test_, pk_test_) never covers the same
// action with a live key. Dummy keys are generated at runtime (test/support/key-class-rows.cjs); no key is printed.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const { normalizedHookAction, normalizeShellCommand } = require('../dist/normalized-action.js');
const { keyClassOf } = require('../dist/key-class.js');
const { redactSensitiveText, redactSensitiveValue, redactSensitiveStrings } = require('../dist/redact.js');
const { stableToolCorrelation } = require('../dist/hook-contract.js');
const { POSITIONS, LOOKALIKES, live, test: testKey, payload, sh, mcp, edit } = require('./support/key-class-rows.cjs');

const SALT = randomBytes(32);
const act = (event, salt = SALT) => normalizedHookAction(JSON.parse(JSON.stringify(event)), { salt, deadlineAt: Number.POSITIVE_INFINITY });
/** What is sent to the service, without the local-only exact_hmac. */
const sent = (action) => { const { exact_hmac: _exact, ...rest } = action.tool_input; return { ...action, tool_input: rest }; };
const hashOf = (action) => action.tool_input.command_sha256 ?? action.tool_input.input_sha256;
const tail = (key) => key.slice(key.lastIndexOf('_') + 1);
const shellText = (command) => normalizeShellCommand(command).text;
const EXACT_ONLY_TAIL = new Set(['edit-path-bare']);
// A key inside a longer path token (`/p/KEY.txt`) is not replaced in the hashed input (as on master): its raw text is keyed, so even
// two different secrets of one class get different keys (stricter than the collision rule needs).
const KEPT_RAW = new Set(['edit-path-ext']);

test('classifier: closed answers, fail closed', () => {
  for (const prefix of ['sk', 'rk', 'pk']) {
    assert.equal(keyClassOf(testKey(prefix)), 'test', `${prefix} test`);
    assert.equal(keyClassOf(live(prefix)), 'live', `${prefix} live`);
  }
  assert.equal(keyClassOf(`${testKey()},${testKey('rk')}`), 'test', 'two test keys');
  assert.equal(keyClassOf(`${testKey()} ${live()}`), 'live', 'any live wins');
  assert.equal(keyClassOf(`${live()} ${testKey()}`), 'live', 'any live wins, either order');
  assert.equal(keyClassOf(`${testKey()}&note=live`), 'test', 'the word live elsewhere does not matter');
  for (const none of ['hunter2', `ghp_${payload()}`, `sk-proj-${payload()}`, `sk-ant-${payload()}`, 'task_live_ok', 'mask_test_results', '', 'sk_']) {
    assert.equal(keyClassOf(none), null, `no class: ${none.slice(0, 12)}`);
  }
  assert.equal(keyClassOf('sk_test'), 'live', 'a test prefix without the payload is not certain: live');
  assert.equal(keyClassOf(Buffer.from(`${live()}:`).toString('base64')), 'live', 'Basic-auth base64 of a live key');
  assert.equal(keyClassOf(`Basic ${Buffer.from(`${testKey()}:`).toString('base64')}`), 'test', 'Basic-auth base64 of a test key');
  for (const look of LOOKALIKES) assert.notEqual(keyClassOf(look.make(payload())), 'test', `look-alike never test: ${look.id}`);
  for (const look of LOOKALIKES.filter((entry) => entry.expect === 'live')) assert.equal(keyClassOf(look.make(payload())), 'live', `look-alike is live: ${look.id}`);
});

test('every position: test and live get different keys, neither is bound, same class stays equal, text after the key still separates', () => {
  for (const position of POSITIONS) {
    const [t1, t2, l1, l2] = [testKey(), testKey(), live(), live()];
    const [at, at2, al, al2] = [t1, t2, l1, l2].map((key) => act(position.build(key)));
    const label = position.id;
    assert.equal(at.truncated, true, `${label}: test action is never bound`);
    assert.equal(al.truncated, true, `${label}: live action is never bound`);
    assert.notEqual(hashOf(at), hashOf(al), `${label}: text hash differs`);
    assert.notEqual(at.tool_input.exact_hmac, al.tool_input.exact_hmac, `${label}: exact_hmac (the hold key) differs`);
    if (!KEPT_RAW.has(label)) {
      assert.deepEqual(sent(at), sent(at2), `${label}: test vs test (only the secret differs): equal`);
      assert.deepEqual(sent(al), sent(al2), `${label}: live vs live (only the secret differs): equal`);
    }
    for (const [key, base] of [[t1, at], [l1, al]]) {
      const other = act(position.build(key, 'b'));
      // A bare path word is withheld whole (as on master): its tail separates only the hold key, which keeps the raw text.
      if (!EXACT_ONLY_TAIL.has(label)) assert.notDeepEqual(sent(other), sent(base), `${label}: differs after the key`);
      assert.notEqual(other.tool_input.exact_hmac, base.tool_input.exact_hmac, `${label}: exact_hmac differs after the key`);
    }
    for (const [key, value] of [[t1, at], [l1, al]]) {
      assert.equal(JSON.stringify(value).includes(tail(key)), false, `${label}: the secret is not in the action`);
    }
    // The hook's hold correlation (session + tool + normalized action) follows.
    const event = (key) => ({ session_id: 's', ...position.build(key) });
    assert.notEqual(stableToolCorrelation(event(t1)), stableToolCorrelation(event(l1)), `${label}: correlation differs`);
  }
});

test('look-alike prefixes read as live never classify as test', () => {
  const canonical = testKey();
  for (const look of LOOKALIKES) {
    for (const [name, build] of [
      ['assignment', (v) => `STRIPE_API_KEY=${v} ./pay.sh`],
      ['bare word', (v) => `./pay.sh ${v}`],
      ['flag', (v) => `stripe charges list --api-key ${v}`],
      ['header', (v) => `curl -H "Authorization: Bearer ${v}" https://x.example.com`],
    ]) {
      const value = look.make(payload());
      const text = shellText(build(value));
      assert.equal(text.includes('[secret-test]'), false, `${look.id} / ${name}: never the test marker`);
      assert.notDeepEqual(sent(act(sh(build(value)))), sent(act(sh(build(canonical)))), `${look.id} / ${name}: never shares the test key`);
      if (look.expect === 'live' && name !== 'bare word') assert.equal(text.includes('[secret-live]'), true, `${look.id} / ${name}: live marker`);
    }
    const viaTool = act(mcp({ api_key: look.make(payload()), memo: 'x' }));
    assert.notDeepEqual(sent(viaTool), sent(act(mcp({ api_key: canonical, memo: 'x' }))), `${look.id}: tool input never shares the test key`);
  }
});

test('Unicode names and values: fold, zero-width, homoglyph, non-ASCII', () => {
  const [t, l] = [testKey(), live()];
  for (const name of ['STRIPE_API_KEY', 'STRIPE_API​_KEY', 'STRIPE­_API_KEY', 'ＳＴＲＩＰＥ_API_KEY', 'STRΙPE_API_KEY', 'stripe_clé', 'ключ_API_KEY', 'STRIPE_API_KEY﻿']) {
    const [a, b] = [`${name}=${t} ./pay.sh`, `${name}=${l} ./pay.sh`].map((command) => act(sh(command)));
    assert.notEqual(a.tool_input.exact_hmac, b.tool_input.exact_hmac, `${JSON.stringify(name)}: exact differs`);
    assert.notEqual(hashOf(a), hashOf(b), `${JSON.stringify(name)}: hash differs`);
    assert.equal(a.truncated, true);
    assert.equal(b.truncated, true);
  }
  // A key with non-ASCII text around it is never certain to be a test key; a non-ASCII word before a live key keeps the live marker.
  assert.equal(shellText(`STRIPE_API_KEY=${l} ./pay.sh café`).includes('[secret-live]'), true);
  assert.equal(shellText(`./pay.sh café ${t}`).includes('[secret-test]'), true);
  assert.equal(keyClassOf(`${t}é`), 'live', 'a test key with a non-ASCII tail is not certain: live');
  assert.equal(keyClassOf(`${t}​`), 'live', 'a test key with a zero-width tail is not certain: live');
});

test('both keys in one action, repeated flags, order', () => {
  const [t1, t2, l] = [testKey(), testKey(), live()];
  const sets = {
    flagsTL: `stripe charges list --api-key ${t1} --api-key ${l}`,
    flagsLT: `stripe charges list --api-key ${l} --api-key ${t1}`,
    flagsTT: `stripe charges list --api-key ${t1} --api-key ${t2}`,
    flagsEqLT: `stripe charges list --api-key=${l} --api-key=${t1}`,
    flagsEqTT: `stripe charges list --api-key=${t1} --api-key=${t2}`,
    assignTL: `PK=${t1} SK=${l} ./pay.sh`,
    assignLT: `PK=${l} SK=${t1} ./pay.sh`,
    assignTT: `PK=${t1} SK=${t2} ./pay.sh`,
  };
  const keys = Object.fromEntries(Object.entries(sets).map(([name, command]) => [name, act(sh(command))]));
  const distinct = (names) => names.forEach((a, i) => names.slice(i + 1).forEach((b) => {
    assert.notDeepEqual(sent(keys[a]), sent(keys[b]), `${a} vs ${b}`);
    assert.notEqual(keys[a].tool_input.exact_hmac, keys[b].tool_input.exact_hmac, `${a} vs ${b}: exact`);
  }));
  distinct(['flagsTL', 'flagsLT', 'flagsTT']);
  distinct(['flagsEqLT', 'flagsEqTT']);
  distinct(['assignTL', 'assignLT', 'assignTT']);
  for (const name of ['flagsTL', 'flagsLT', 'flagsEqLT']) assert.equal(shellText(sets[name]).includes('[secret-live]'), true, `${name}: a live marker stays`);
  // A non-credential name (`PK=`) is data: hashed with the marker inside it, so the class is in the hash.
  assert.match(shellText(sets.assignTL), /^PK=\[secret-data:[0-9a-f]{64}\] SK=\[secret-live\] /);
  assert.equal(shellText(sets.flagsTL), 'stripe charges list --api-key [secret-test] --api-key [secret-live]');
  assert.equal(shellText(sets.flagsLT), 'stripe charges list --api-key [secret-live] --api-key [secret-test]');
  const tool = (a, b) => act(mcp({ api_key: a, backup_key: b, memo: 'x' }));
  assert.notDeepEqual(sent(tool(t1, l)), sent(tool(t1, t2)));
  assert.notDeepEqual(sent(tool(l, t1)), sent(tool(t1, t2)));
  assert.notDeepEqual(sent(tool(l, t1)), sent(tool(t1, l)));
  assert.notEqual(tool(t1, l).tool_input.exact_hmac, tool(t1, t2).tool_input.exact_hmac);
  // One word holding both: live wins.
  assert.equal(shellText(`STRIPE_API_KEY=${t1},${l} ./pay.sh`).includes('[secret-test]'), false);
});

test('chains, wrappers, variables and misleading words never downgrade a live key', () => {
  const [t, l] = [testKey(), live()];
  const wrappers = [
    (c) => `${c}`, (c) => `cd /tmp && ${c}`, (c) => `${c} && echo done`, (c) => `echo hi; ${c}`, (c) => `false || ${c}`, (c) => `cat x | ${c}`,
    (c) => `(${c})`, (c) => `{ ${c}; }`, (c) => `echo "$(${c})"`, (c) => `bash -c '${c}'`, (c) => `sh -c "${c}"`, (c) => `sudo ${c}`, (c) => `nohup ${c} &`,
    (c) => `time ${c}`, (c) => `env FOO=1 ${c}`, (c) => `xargs -I{} ${c}`, (c) => `timeout 5 ${c}`,
  ];
  for (const [index, wrap] of wrappers.entries()) {
    const inner = (key) => `stripe charges list --api-key ${key}`;
    const a = act(sh(wrap(inner(t))));
    const b = act(sh(wrap(inner(l))));
    assert.notEqual(a.tool_input.exact_hmac, b.tool_input.exact_hmac, `wrapper ${index}: exact`);
    assert.notEqual(hashOf(a), hashOf(b), `wrapper ${index}: hash`);
    assert.equal(b.truncated, true, `wrapper ${index}`);
    assert.equal(shellText(wrap(inner(l))).includes('[secret-test]'), false, `wrapper ${index}: live never shows test`);
  }
  // A test key before a live key in a chain keeps both markers in place.
  const chain = shellText(`STRIPE_API_KEY=${t} ./a.sh && STRIPE_API_KEY=${l} ./b.sh`);
  assert.equal(chain, 'STRIPE_API_KEY=[secret-test] ./a.sh && STRIPE_API_KEY=[secret-live] ./b.sh');
  assert.notDeepEqual(sent(act(sh(`STRIPE_API_KEY=${t} ./a.sh && STRIPE_API_KEY=${l} ./b.sh`))), sent(act(sh(`STRIPE_API_KEY=${t} ./a.sh && STRIPE_API_KEY=${t} ./b.sh`))));
  // Variables: a live key assigned in the command keeps its class through the reference.
  const viaVar = (key) => act(sh(`K=${key}; curl -u $K: https://api.example.com`));
  assert.notEqual(viaVar(t).tool_input.exact_hmac, viaVar(l).tool_input.exact_hmac);
  assert.notEqual(act(sh(`export K=${t} && ./pay.sh "$K"`)).tool_input.exact_hmac, act(sh(`export K=${l} && ./pay.sh "$K"`)).tool_input.exact_hmac);
  // A variable whose value is set outside the command has no class the hook can see: the text holds the reference only (same as master).
  assert.equal(/\[secret-(?:live|test)\]/.test(shellText('curl -u $STRIPE_KEY: https://api.example.com')), false);
  // Misleading words and paths.
  const lines = [
    (k) => `echo "only a test, not live" && STRIPE_API_KEY=${k} ./deploy.sh /opt/test/sk_test_dir`,
    (k) => `STRIPE_API_KEY=${k} ./deploy.sh --env test --mode sandbox --stage staging`,
    (k) => `cd /srv/test-live-sandbox && curl -u ${k}: https://api.sandbox.test/v1/charges`,
    (k) => `git commit -m "use sk_test_ keys in tests" && stripe charges list --api-key ${k}`,
    (k) => `stripe --api-key ${k} charges list # test mode, sk_test_ only`,
    (k) => `ENV=test STRIPE_MODE=test STRIPE_API_KEY=${k} ./deploy.sh`,
  ];
  for (const [index, line] of lines.entries()) {
    const [a, b] = [act(sh(line(t))), act(sh(line(l)))];
    assert.notEqual(a.tool_input.exact_hmac, b.tool_input.exact_hmac, `misleading ${index}: exact`);
    assert.notDeepEqual(sent(a), sent(b), `misleading ${index}`);
    assert.equal(shellText(line(l)).includes('[secret-test]'), false, `misleading ${index}: live never shows test`);
  }
  // A tool input that claims test mode in its own fields.
  const claimed = (key) => act(mcp({ api_key: key, mode: 'test', environment: 'test', livemode: false, note: 'sk_test_ only' }));
  assert.notDeepEqual(sent(claimed(t)), sent(claimed(l)));
  assert.notEqual(claimed(t).tool_input.exact_hmac, claimed(l).tool_input.exact_hmac);
});

test('forged markers typed by the caller never turn a live key into a test key', () => {
  const [t, l] = [testKey(), live()];
  const withLiteral = (literal, key) => act(sh(`./pay.sh ${literal} ${key}`));
  for (const literal of ['[secret-test]', '[secret]', '[REDACTED_TEST]', '[secret-live]']) {
    assert.notDeepEqual(sent(withLiteral(literal, t)), sent(withLiteral(literal, l)), `${literal} next to a key`);
    assert.equal(withLiteral(literal, l).truncated, true);
  }
  // A literal marker is never the text of a live key's marker unless it is the live marker itself.
  assert.notDeepEqual(sent(act(sh('./pay.sh [secret-test]'))), sent(act(sh(`./pay.sh ${l}`))));
  assert.notDeepEqual(sent(act(sh('./pay.sh [secret]'))), sent(act(sh(`./pay.sh ${l}`))), 'master: a literal [secret] equalled any key');
  // The caller's own field cannot pick the marker: the class comes from the key text.
  assert.equal(shellText(`STRIPE_API_KEY=${l} ./pay.sh --class test --marker "[secret-test]"`).startsWith('STRIPE_API_KEY=[secret-live]'), true);
  assert.equal(redactSensitiveText(`STRIPE_API_KEY=${l} [REDACTED_TEST]`).includes('[REDACTED_LIVE]'), true);
});

test('branch and shortcut rows: every early return keeps the separation', () => {
  const [t, l] = [testKey(), live()];
  const pair = (build, label, exactOnly = false) => {
    const [a, b] = [act(build(t)), act(build(l))];
    // A word past the scan limit is withheld unread (master): the sent part is the same marker, the hold key keeps the raw text.
    if (!exactOnly) assert.notDeepEqual(sent(a), sent(b), `${label}: sent part`);
    assert.notEqual(a.tool_input.exact_hmac, b.tool_input.exact_hmac, `${label}: exact_hmac`);
    assert.equal(a.truncated, true, `${label}: truncated`);
  };
  pair((k) => sh(`./pay.sh ${'x'.repeat(20_000)} ${k}`), 'long word before the key');
  pair((k) => sh(`./pay.sh ${k}${'y'.repeat(20_000)}`), 'word over the scan limit holding the key', true);
  pair((k) => sh(`./pay.sh ${Array.from({ length: 5_000 }, (_, i) => `w${i}`).join(' ')} ${k}`), 'more than 4096 words (placeholder)', true);
  pair((k) => sh(`./pay.sh ${k}${'z '.repeat(140_000)}`), 'command over 256 KB (placeholder)', true);
  pair((k) => mcp({ tree: { a: { b: { c: { d: { e: { f: { g: { api_key: k } } } } } } } } }), 'tool input past depth 6');
  pair((k) => mcp({ list: Array.from({ length: 70 }, (_, i) => `v${i}`).concat(k) }), 'array past 64 entries (the key is past the cut: only the hold key sees it)', true);
  pair((k) => mcp({ api_key: k, ...Object.fromEntries(Array.from({ length: 70 }, (_, i) => [`f${i}`, i])) }), 'object past 64 entries');
  pair((k) => ({ ...sh(`./pay.sh ${k}`), input_truncated: true }), 'input cut by the host adapter');
  pair((k) => ({ tool_name: 'Bash', tool_input: { command: `./pay.sh ${k}`, description: 'x' } }), 'description field');
  pair((k) => mcp({ k }, `mcp__${'s'.repeat(130)}__tool`), 'tool name past 128 characters');
  pair((k) => sh(`./pay.sh ${k}`), 'plain shell word');
  // Short words cannot hold a key and are untouched.
  assert.equal(shellText('./pay.sh sk_test_a'), './pay.sh sk_test_a');
  // No salt: a random value matches nothing (asked again), also for the test key.
  const noSalt = (key) => normalizedHookAction(sh(`./pay.sh ${key}`), { salt: null, deadlineAt: Number.POSITIVE_INFINITY });
  assert.notEqual(noSalt(t).tool_input.exact_hmac, noSalt(t).tool_input.exact_hmac);
  // A public key (pk_) is kept raw in the exact pass, so pk_live and pk_test differ there too.
  assert.notEqual(act(sh(`./pay.sh ${live('pk')}`)).tool_input.exact_hmac, act(sh(`./pay.sh ${testKey('pk')}`)).tool_input.exact_hmac);
});

test('no key of this family: nothing moves', () => {
  const secrets = [`ghp_${payload()}`, `sk-proj-${payload()}${payload()}`, `sk-ant-${payload()}`, `xoxb-${'1'.repeat(12)}-${'2'.repeat(12)}-${payload()}`, 'hunter2hunter2'];
  for (const secret of secrets) {
    assert.equal(shellText(`STRIPE_API_KEY=${secret} ./pay.sh`), 'STRIPE_API_KEY=[secret] ./pay.sh');
    assert.equal(shellText(`curl -H "Authorization: Bearer ${secret}" https://x.example.com`).includes('[secret]'), true);
    assert.equal(/\[secret-(?:live|test)\]/.test(shellText(`./pay.sh ${secret} --api-key ${secret}`)), false);
  }
  assert.equal(shellText('git status && ls -la'), 'git status && ls -la');
  assert.equal(shellText('deploy --env production').includes('[secret'), false);
  assert.equal(act(sh('wrangler deploy --env production')).truncated, undefined, 'a plain deploy is still bound');
});

test('paths sent to the service stay class-free; the class is in the hashes', () => {
  const [t, l] = [testKey(), live()];
  for (const build of [(k) => edit(`/p/${k}.txt`), (k) => edit(`/p/.env.${k}`), (k) => edit(`/p/a.txt?token=${k}`), (k) => edit(`/p/${k}`)]) {
    const [a, b] = [act(build(t)), act(build(l))];
    assert.deepEqual(a.paths, b.paths, 'paths equal');
    assert.equal(JSON.stringify(a.paths).includes('[secret-'), false, 'no class marker in paths');
    assert.equal(a.truncated, true);
    assert.notEqual(a.tool_input.exact_hmac, b.tool_input.exact_hmac);
  }
  // On the path-span branch the key stays in the hashed input, so the text hash separates too.
  assert.notEqual(hashOf(act(edit(`/p/${t}`))), hashOf(act(edit(`/p/${l}`))));
});

test('redact.ts: the gate action text keeps the class and hides the key', () => {
  const [t, l] = [testKey(), live()];
  const shapes = [
    (k) => `curl -u ${k}: https://x.example.com`,
    (k) => `STRIPE_API_KEY=${k} run`,
    (k) => `stripe --api-key ${k} charges`,
    (k) => `stripe --api-key=${k} charges`,
    (k) => `curl -H "Authorization: Bearer ${k}" https://x.example.com`,
    (k) => `Authorization: Bearer ${k}`,
    (k) => `Authorization: Basic ${Buffer.from(`${k}:`).toString('base64')}`,
    (k) => `Basic ${Buffer.from(`${k}:`).toString('base64')}`,
    (k) => `Bearer ${k}`,
    (k) => `https://x.example.com/run?auth=${k}&target=a`,
    (k) => `https://x.example.com/run?token=${k}`,
    (k) => `https://user:${k}@x.example.com/a`,
    (k) => `{"api_key": "${k}", "env": "a"}`,
    (k) => `password: ${k}`,
    (k) => `note ${k} here`,
  ];
  for (const [index, shape] of shapes.entries()) {
    const [a, b] = [redactSensitiveText(shape(t)), redactSensitiveText(shape(l))];
    assert.notEqual(a, b, `shape ${index}: test and live text differ`);
    assert.equal(a.includes(tail(t)) || b.includes(tail(l)), false, `shape ${index}: the key is hidden`);
    assert.match(a, /_TEST\]|_test\]/, `shape ${index}: test marker`);
    assert.match(b, /_LIVE\]|_live\]/, `shape ${index}: live marker`);
    assert.equal(redactSensitiveText(a), a, `shape ${index}: redacting twice changes nothing (test)`);
    assert.equal(redactSensitiveText(b), b, `shape ${index}: redacting twice changes nothing (live)`);
    assert.equal(redactSensitiveText(shape(live())), b, `shape ${index}: live vs live (only the secret differs): equal`);
    assert.equal(redactSensitiveText(shape(testKey())), a, `shape ${index}: test vs test (only the secret differs): equal`);
  }
  assert.equal(redactSensitiveText(`run ${testKey('rk')} and ${live('rk')}`), 'run [REDACTED_TOKEN_TEST] and [REDACTED_TOKEN_LIVE]', 'rk_ keys are hidden too');
  assert.equal(redactSensitiveText(`${testKey('pk')} ${live('pk')}`), '[REDACTED_TOKEN_TEST] [REDACTED_TOKEN_LIVE]');
  assert.equal(redactSensitiveText(`${testKey()} ${live()}`), '[REDACTED_TOKEN_TEST] [REDACTED_TOKEN_LIVE]');
  assert.notEqual(redactSensitiveText(`curl -u ${testKey()}: https://x.example.com/a`), redactSensitiveText(`curl -u ${testKey()}: https://x.example.com/b`), 'text after the span differs');
  assert.equal(redactSensitiveText(`--api-key "${live()} x"`).includes('AMBIGUOUS'), true, 'an ambiguous value stays ambiguous (never binds)');
  // A credential-named query value with more fields behind it is ambiguous (never binds); it was downgraded to a plain marker on master.
  assert.equal(redactSensitiveText(`https://x.example.com/run?api_key=${live()}&target=a`), 'https://x.example.com/run?api_key=[REDACTED_AMBIGUOUS]');
  assert.equal(redactSensitiveText(`https://x.example.com/run?api_key=${testKey()}&target=a`), 'https://x.example.com/run?api_key=[REDACTED_AMBIGUOUS]');
  // Not this family: unchanged.
  assert.equal(redactSensitiveText(`ghp_${payload()}`), '[REDACTED_TOKEN]');
  assert.equal(redactSensitiveText('STRIPE_API_KEY=hunter2hunter2'), 'STRIPE_API_KEY=[REDACTED]');
  // Structured fields under a credential name.
  assert.deepEqual(redactSensitiveValue({ api_key: t, memo: 'm' }), { api_key: '[redacted_test]', memo: 'm' });
  assert.deepEqual(redactSensitiveValue({ api_key: l, memo: 'm' }), { api_key: '[redacted_live]', memo: 'm' });
  assert.deepEqual(redactSensitiveStrings({ token: l, nested: { password: t } }), { token: '[redacted_live]', nested: { password: '[redacted_test]' } });
  assert.deepEqual(redactSensitiveStrings({ token: { a: l } }), { token: '[redacted_live]' });
  assert.deepEqual(redactSensitiveStrings({ token: 'hunter2' }), { token: '[redacted]' });
  for (const look of LOOKALIKES) {
    const out = redactSensitiveText(`STRIPE_API_KEY=${look.make(payload())} run`);
    assert.equal(/_TEST\]/.test(out), false, `redact.ts look-alike never test: ${look.id}`);
  }
});

test('static guard: a new bare [secret] site must be reviewed (it would skip the class)', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'normalized-action.ts'), 'utf8').split('\n');
  const uses = source.filter((line) => /\bSECRET\b/.test(line) && !/^\s*(?:\*|\/\/|\/\*)/.test(line));
  assert.equal(uses.length, 9, `bare SECRET uses: ${uses.map((line) => line.trim().slice(0, 60)).join(' | ')}`);
  assert.equal(source.filter((line) => /includes\(SECRET\)/.test(line)).length, 1, 'the one includes(SECRET) is the path check, after the class is dropped');
  assert.equal(source.filter((line) => /hasSecretMarker\(/.test(line)).length, 3, 'the definition and the two callers');
});
