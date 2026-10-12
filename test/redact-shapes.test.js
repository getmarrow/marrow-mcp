'use strict';
// Shared redactor: quoted JSON keys, URL userinfo and auth headers. Runtime
// dummies only; assertions never print a dummy (only booleans are compared).
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const { redactSensitiveText } = require('../dist/redact.js');

const hex = () => crypto.randomBytes(12).toString('hex');
const b64 = () => crypto.randomBytes(18).toString('base64');

function leaks(text, secret) {
  for (let i = 0; i + 8 <= secret.length; i += 1) if (text.includes(secret.slice(i, i + 8))) return true;
  return false;
}

const SHAPES = [
  ['"api_key": "v"', hex, (s, t) => `{"api_key": "${s}", "env": "${t}"}`],
  ['"password":"v"', hex, (s, t) => `{"password":"${s}","env":"${t}"}`],
  ['"token"', hex, (s, t) => `{"token":"${s}","env":"${t}"}`],
  ['"secret"', hex, (s, t) => `{"secret":"${s}","env":"${t}"}`],
  ['"client_secret"', hex, (s, t) => `{"client_secret":"${s}","env":"${t}"}`],
  ['"authorization"', hex, (s, t) => `{"authorization":"Basic ${s}","env":"${t}"}`],
  ['"access_token"', hex, (s, t) => `{"access_token":"${s}","env":"${t}"}`],
  ['"DB_PASSWORD"', hex, (s, t) => `{"DB_PASSWORD" : "${s}" , "env":"${t}"}`],
  ['"passwd" unquoted value', hex, (s, t) => `{"passwd": ${s}, "env":"${t}"}`],
  ["'api_key': 'v'", hex, (s, t) => `{'api_key': '${s}', 'env': '${t}'}`],
  ['escaped quote inside the value', hex, (s, t) => `{"api_key":"${s.slice(0, 10)}\\"${s.slice(10)}","env":"${t}"}`],
  ['escaped \\"api_key\\":\\"v\\" in a shell string', hex, (s, t) => `curl -d "{\\"api_key\\":\\"${s}\\",\\"env\\":\\"${t}\\"}" https://x.example`],
  ['URL userinfo postgres', hex, (s, t) => `psql postgres://admin:${s}@db.example/app env=${t}`],
  ['URL userinfo https', hex, (s, t) => `https://user:${s}@host.example/path?env=${t}`],
  ['Authorization: Basic', b64, (s, t) => `Authorization: Basic ${s} env=${t}`],
  ['Proxy-Authorization: Basic', b64, (s, t) => `Proxy-Authorization: Basic ${s} env=${t}`],
  ['authorization: bearer (lower case)', hex, (s, t) => `authorization: bearer ${s} env=${t}`],
  ['Authorization: Digest', hex, (s, t) => `Authorization: Digest username="bob", response="${s}", env=${t}`],
  ['Authorization: Token', hex, (s, t) => `Authorization: Token ${s} env=${t}`],
  ['Authorization: <raw value>', hex, (s, t) => `Authorization: ${s} env=${t}`],
  ['Basic <base64> outside a header', b64, (s, t) => `curl with Basic ${s} env=${t}`],
];

for (const [name, gen, shape] of SHAPES) {
  test(`redactor: ${name} is replaced, the text after it is kept`, () => {
    const s1 = gen();
    const s2 = gen();
    const staging = redactSensitiveText(shape(s1, 'staging'));
    const production = redactSensitiveText(shape(s1, 'production'));
    const otherSecret = redactSensitiveText(shape(s2, 'staging'));
    assert.equal(leaks(staging, s1), false, 'no 8-character slice of the dummy is kept');
    assert.equal(leaks(production, s1), false);
    assert.equal(leaks(otherSecret, s2), false);
    assert.equal(/\[REDACTED(?:_AMBIGUOUS)?\]/.test(staging), true, 'a fixed marker replaces it');
    assert.equal(staging.includes('staging'), true, 'the text after the secret is kept');
    assert.notEqual(staging, production, 'texts that differ after the secret stay different');
    assert.equal(staging, otherSecret, 'texts that differ only in the secret match');
  });
}

test('redactor keeps the structure around a quoted JSON secret', () => {
  const s = hex();
  assert.equal(redactSensitiveText(`{"api_key":"${s}","env":"production"}`), '{"api_key":"[REDACTED]","env":"production"}');
  assert.equal(redactSensitiveText(`postgres://admin:${s}@db.example/app`), 'postgres://admin:[REDACTED]@db.example/app');
  assert.equal(redactSensitiveText(`Authorization: Basic ${b64()} then`), 'Authorization: Basic [REDACTED] then');
});

test('a hidden span that may also hide command text gets the never-binding ambiguous marker', () => {
  const s = hex();
  const cases = [
    [`{"password":"${s} ; rm -rf /tmp/x","env":"production"}`, 'production'],
    [`{"api_key":"${s}`, ''],
    [`https://u:${s}@a.example?x=1&next=evil@b.example/y`, '/y'],
    [`Authorization: Basic ${s}&&deploy-production`, ''],
    [`TOKEN="${s} && deploy production"`, ''],
    [`--token=${s}|deploy-production`, ''],
    [`--password "${s} ; deploy"`, ''],
    [`https://a.example/x?token=${s};deploy-production`, ''],
  ];
  for (const [text, tail] of cases) {
    const out = redactSensitiveText(text);
    assert.equal(leaks(out, s), false);
    assert.equal(out.includes('[REDACTED_AMBIGUOUS]'), true);
    if (tail) assert.equal(out.endsWith(tail) || out.includes(`"env":"${tail}"`), true);
  }
  // A value that ends at a separator keeps the text after it; a plain value keeps the plain marker.
  assert.equal(redactSensitiveText(`TOKEN=${s};deploy-production`), 'TOKEN=[REDACTED];deploy-production');
  assert.equal(redactSensitiveText(`TOKEN=${s} next`), 'TOKEN=[REDACTED] next');
  assert.equal(redactSensitiveText(`{\\"api_key\\":\\"${s}\\",\\"env\\":\\"production\\"}`), '{\\"api_key\\":\\"[REDACTED]\\",\\"env\\":\\"production\\"}');
});

test('redactor leaves ordinary text alone', () => {
  for (const text of [
    '{"env": "production", "name": "api"}',
    'https://host.example/path?env=production',
    'Basic setup for the staging deploy',
    'see https://docs.example/a@b',
  ]) assert.equal(redactSensitiveText(text), text);
});

test('redactor is linear on long adversarial inputs', () => {
  const N = 200_000;
  const inputs = [
    'TOKEN'.repeat(N / 5),
    `?${'token'.repeat(N / 5)}`,
    '?'.repeat(N),
    '"token":"'.repeat(N / 9),
    `"${'a'.repeat(N)}`,
    '"token":'.repeat(N / 8),
    'a://'.repeat(N / 4),
    `a://u:${'@'.repeat(N)}`,
    'Authorization: '.repeat(N / 15),
    `Authorization: Basic ${'A'.repeat(N)}`,
    `Basic ${'A'.repeat(N)}!`,
    'Digest response="'.repeat(N / 17),
    '--token="'.repeat(N / 9),
    'a='.repeat(N / 2),
    'TOKEN= '.repeat(N / 7),
    `${'x'.repeat(N)}=`,
    `'${'api_key'.repeat(N / 7)}`,
    '\\"token\\":\\"'.repeat(N / 12),
    'TOKEN="'.repeat(N / 7),
    `TOKEN="${'a'.repeat(N)}`,
  ];
  for (const input of inputs) {
    const started = process.hrtime.bigint();
    redactSensitiveText(input);
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(ms < 1500, `a 200 KB adversarial input took ${Math.round(ms)} ms`);
  }
});
