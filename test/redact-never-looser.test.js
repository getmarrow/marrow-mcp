const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const test = require('node:test');
const { redactSensitiveText } = require('../dist/redact.js');

// Shapes where a first rewrite of the redactor left a value that 3.9.102 hid (found by a differential
// fuzz against 3.9.102): hyphenated names, wide spacing, a header swallowing a NAME, a quote that opens
// the next value, text glued to an earlier marker. Runtime dummies; only 8-character slices are compared.
const dummy = () => `Dv${randomBytes(12).toString('hex')}`;
const leaks = (out, secret) => { for (let i = 0; i + 8 <= secret.length; i += 1) if (out.includes(secret.slice(i, i + 8))) return true; return false; };

test('every value 3.9.102 hid stays hidden (differential regression shapes)', () => {
  const shapes = [
    (s) => `API-KEY=${s}`,
    (s) => `echo PRIVATE-KEY=${s}@host/x`,
    (s) => `TOKEN${' '.repeat(70)}= ${s}`,
    (s) => `${'A'.repeat(5000)}_TOKEN=${s}`,
    (s) => `Authorization: api_key="${s}`,
    (s) => `Authorization: MY_SECRET : "${s}'`,
    (s) => `Authorization: PRIVATE_KEY=\t${s},"env":"prod"}`,
    (s, x) => `echo api_key="${x}#frag&set PRIVATE_KEY="${s} `,
    (s, x) => ` && password='${x}  ; ?session='${s}\n`,
    (s, x) => `--password="${x}; API-KEY="${s}\n`,
    (s, x) => `--API-KEY='${x}@host/x&?auth='${s},"env":"prod"}`,
    (s, x) => `url=https://u:sig="${x})--TOKEN='${x}"\nkey='${s} && echo hi`,
    (s, x) => `Authorization: session:${x}?code=${x}''key="${s}'`,
  ];
  for (const [i, shape] of shapes.entries()) {
    const s = dummy();
    const out = redactSensitiveText(shape(s, dummy()));
    assert.equal(leaks(out, s), false, `shape ${i}`);
  }
});

test('the name scan stays linear on adversarial input', () => {
  for (const text of ['a-'.repeat(100000), 'TOKEN-'.repeat(40000), `x${' '.repeat(200000)}`, 'a '.repeat(100000), `TOKEN${' '.repeat(200000)}`, '?'.repeat(200000), '&a'.repeat(100000), '"'.repeat(200000)]) {
    const start = process.hrtime.bigint();
    redactSensitiveText(text);
    assert.ok(Number(process.hrtime.bigint() - start) / 1e6 < 1500, `${text.slice(0, 8)}… took too long`);
  }
});
