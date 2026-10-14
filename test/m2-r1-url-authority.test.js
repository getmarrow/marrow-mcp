'use strict';

// M2-R1 (delta audit of 0368537c): a `#` or `?` in the hidden part of `scheme://user:<span>@host`. For URL
// parsers it ends the authority (`https://deploy:443#@host` goes to host `deploy`); libpq, mysql and redis
// clients take the whole span as the password. So the span is hidden in the sent form and the display either
// way, but it is not a certain credential: the action is marked truncated, the exact key (exact_hmac) keeps the
// span, and the display uses the ambiguous marker. It never shares a key with `https://deploy:<password>@host`
// and is never shown or sent. Passwords here are dummies made at run time and never printed.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const { normalizedHookAction, normalizeShellCommand } = require('../dist/normalized-action.js');
const { redactSensitiveText } = require('../dist/redact.js');
const { stableToolCorrelation } = require('../dist/hook-contract.js');

const pw = () => `p${crypto.randomBytes(9).toString('base64url')}`;
const salt = crypto.randomBytes(32);
const action = (command) => normalizedHookAction({ tool_name: 'Bash', tool_input: { command } }, { salt });
const key = (command) => JSON.stringify(action(command));
const TEMPLATES = [
  (u) => `curl https://${u}@api.example.test/v1/a`,
  (u) => `git push -f https://${u}@github.com/acme/proj.git main`,
  (u) => `psql postgres://${u}@db.internal:5432/app`,
];

test('M2-R1: a # or ? span makes a different key from a URL password; it is hidden and marked truncated', () => {
  for (const delim of ['#', '?']) {
    for (const tmpl of TEMPLATES) {
      const withPassword = tmpl(`deploy:${pw()}`);
      const withSpan = tmpl(`deploy:443${delim}`);
      assert.notEqual(key(withPassword), key(withSpan), withSpan);
      const a = action(withSpan);
      assert.equal(a.truncated, true, withSpan);
      assert.match(a.tool_input.exact_hmac, /^[0-9a-f]{32}$/);
      assert.ok(!normalizeShellCommand(withSpan).text.includes(`443${delim}`), `hidden in the sent form: ${withSpan}`);
      assert.notEqual(stableToolCorrelation({ session_id: 's', tool_name: 'Bash', tool_input: { command: withPassword } }),
        stableToolCorrelation({ session_id: 's', tool_name: 'Bash', tool_input: { command: withSpan } }));
    }
  }
});

test('M2-R1: a password that holds # or ? (libpq, mysql) is never sent or shown', () => {
  for (const delim of ['#', '?']) {
    const tail = crypto.randomBytes(9).toString('hex');
    const command = `psql "postgresql://admin:Zq7${delim}${tail}@db.example/app"`;
    const a = action(command);
    assert.ok(!JSON.stringify(a).includes(tail), 'not in the sent action');
    assert.ok(!normalizeShellCommand(command).text.includes(tail), 'not in the normalized text');
    const shown = redactSensitiveText(command);
    assert.ok(!shown.includes(tail), 'not in the display');
    assert.ok(shown.includes('[REDACTED_AMBIGUOUS]@db.example/app'), 'ambiguous marker in the display');
    // Fail closed: two such passwords are two exact actions (each asks once).
    assert.notEqual(key(command), key(`psql "postgresql://admin:Zq8${delim}${tail}@db.example/app"`));
  }
});

test('M2-R1: actions that differ only in a plain URL password still share their key; text after the authority separates them', () => {
  const a = pw();
  const b = pw();
  assert.equal(key(`curl https://deploy:${a}@api.example.test/v1/a`), key(`curl https://deploy:${b}@api.example.test/v1/a`));
  assert.equal(normalizeShellCommand(`curl https://deploy:${a}@x.test`).text, normalizeShellCommand(`curl https://deploy:${b}@x.test`).text);
  assert.ok(!key(`curl https://deploy:${a}@api.example.test/v1/a`).includes(a));
  assert.notEqual(key(`curl https://deploy:${a}@api.example.test/v1/a`), key(`curl https://deploy:${a}@api.example.test/v1/b`));
  assert.notEqual(key(`curl https://deploy:${a}@api.example.test/v1/a`), key(`curl https://deploy:${a}@api.example.test#/v1/a`));
});

test('M2-R1: the owner display marks a # or ? span as ambiguous and still hides a plain URL password', () => {
  const a = pw();
  const shown = redactSensitiveText(`curl https://deploy:${a}@api.github.com/repos`);
  assert.ok(!shown.includes(a));
  assert.equal(shown, 'curl https://deploy:[REDACTED]@api.github.com/repos');
  for (const delim of ['#', '?']) {
    assert.equal(redactSensitiveText(`curl https://deploy:443${delim}@api.github.com/repos`), 'curl https://deploy:[REDACTED_AMBIGUOUS]@api.github.com/repos');
  }
});
