'use strict';

// M2-R1 (delta audit of 0368537c): `#` and `?` end a URL's authority (RFC 3986). `https://deploy:443#@host`
// is host `deploy`, port 443 and a fragment: there is no password, so the text is neither replaced in the
// normalized action (its key) nor in the owner's display. It no longer shares the key of
// `https://deploy:<password>@host`, and the display names the host the request really goes to. A real
// URL password is still replaced. Passwords here are dummies made at run time and never printed.
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

test('M2-R1: a # or ? after the port makes a different key from a URL password; the text stays as written', () => {
  for (const delim of ['#', '?']) {
    for (const tmpl of [(u) => `curl https://${u}@api.example.test/v1/a`, (u) => `git push -f https://${u}@github.com/acme/proj.git main`, (u) => `psql postgres://${u}@db.internal:5432/app`]) {
      const secret = pw();
      const withPassword = tmpl(`deploy:${secret}`);
      const withFragment = tmpl(`deploy:443${delim}`);
      assert.notEqual(key(withPassword), key(withFragment), withFragment);
      assert.ok(!key(withPassword).includes(secret), 'the password never reaches the key');
      assert.ok(normalizeShellCommand(withFragment).text.includes(`deploy:443${delim}@`), `kept as written: ${delim}`);
      assert.ok(!normalizeShellCommand(withPassword).text.includes(secret));
      assert.notEqual(stableToolCorrelation({ session_id: 's', tool_name: 'Bash', tool_input: { command: withPassword } }),
        stableToolCorrelation({ session_id: 's', tool_name: 'Bash', tool_input: { command: withFragment } }));
    }
  }
});

test('M2-R1: actions that differ only in the URL password still share the normalized command; the password is never shown', () => {
  const a = pw();
  const b = pw();
  const na = action(`curl https://deploy:${a}@api.example.test/v1/a`);
  const nb = action(`curl https://deploy:${b}@api.example.test/v1/a`);
  assert.equal(na.tool_input.command_sha256, nb.tool_input.command_sha256);
  assert.equal(normalizeShellCommand(`curl https://deploy:${a}@x.test`).text, normalizeShellCommand(`curl https://deploy:${b}@x.test`).text);
  assert.ok(!JSON.stringify(na).includes(a) && !JSON.stringify(nb).includes(b));
  // Text after the authority still separates actions.
  assert.notEqual(key(`curl https://deploy:${a}@api.example.test/v1/a`), key(`curl https://deploy:${a}@api.example.test/v1/b`));
});

test('M2-R1: the owner display names the real host for # and ?, and still hides a real URL password', () => {
  const secret = pw();
  const shown = redactSensitiveText(`curl https://deploy:${secret}@api.github.com/repos`);
  assert.ok(!shown.includes(secret));
  assert.match(shown, /https:\/\/deploy:\S+@api\.github\.com\/repos/);
  for (const delim of ['#', '?']) {
    assert.equal(redactSensitiveText(`curl https://deploy:443${delim}@api.github.com/repos`), `curl https://deploy:443${delim}@api.github.com/repos`);
  }
});
