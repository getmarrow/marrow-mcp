'use strict';

// The U6 receipts' device salt (~/.marrow/seatbelt/salt) is an S4 secret path: an agent that reads it
// could compute the keyed receipt ids. Writes there were already S0 (~/.marrow/**). Reading the
// receipts folder listing, the receipts themselves or other ~/.marrow files is unchanged.
const test = require('node:test');
const assert = require('node:assert/strict');

const { evaluateSeatbelt, evaluateSeatbeltShell } = require('../dist/seatbelt/mapper.js');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');

const sh = (cmd) => evaluateSeatbeltShell(cmd, makeEnv({}));
const tool = (tool_name, tool_input) => evaluateSeatbelt({ tool_name, tool_input }, makeEnv({}));

test('reading the receipts salt stops as S4, by shell and by file tool', () => {
  const reads = [
    'cat ~/.marrow/seatbelt/salt', 'cat /home/u/.marrow/seatbelt/salt', 'xxd ~/.marrow/seatbelt/salt',
    'base64 ~/.marrow/seatbelt/salt', 'cp ~/.marrow/seatbelt/salt /tmp/s', 'od -An -tx1 < ~/.marrow/seatbelt/salt',
    'cd ~/.marrow/seatbelt && cat salt', 'cat ~/.marrow/seatbelt/sal*', 'S=~/.marrow/seatbelt/salt; cat "$S"',
    'npm test && cat ~/.marrow/seatbelt/salt', 'bash -c "cat ~/.marrow/seatbelt/salt"',
  ];
  for (const cmd of reads) {
    const d = sh(cmd);
    assert.equal(d.decision, 'stop', cmd);
    assert.equal(d.category, 'S4', `${cmd}: ${d.category} ${d.reasons}`);
  }
  // Text the parser cannot read still names the salt as a secret (tripwire), next to the S0 self-protection hit.
  for (const cmd of ['cat ~/.marrow/seatbelt/salt "', 'x=$(cat ~/.marrow/seatbelt/salt']) {
    const d = sh(cmd);
    assert.equal(d.decision, 'stop', cmd);
    assert.ok(d.reasons.includes('tripwire_secret_path'), `${cmd}: ${d.reasons}`);
  }
  for (const name of ['Read', 'Grep']) {
    const d = tool(name, name === 'Read' ? { file_path: '/home/u/.marrow/seatbelt/salt' } : { pattern: 'x', path: '/home/u/.marrow/seatbelt/salt' });
    assert.equal(d.decision, 'stop', name);
    assert.equal(d.category, 'S4', name);
  }
});

test('writes to the salt stay S0; listing the store and reading other names there are unchanged', () => {
  for (const cmd of ['rm ~/.marrow/seatbelt/salt', 'echo x > ~/.marrow/seatbelt/salt', 'ln -s /tmp/x ~/.marrow/seatbelt/salt']) {
    const d = sh(cmd);
    assert.equal(d.decision, 'stop', cmd);
    assert.equal(d.category, 'S0', cmd);
  }
  for (const cmd of ['ls ~/.marrow/seatbelt', 'ls -la ~/.marrow/seatbelt/receipts', 'cat ~/.marrow/seatbelt/state.json', 'cat notes/salt', 'cat salt.txt', 'echo salt']) {
    assert.equal(sh(cmd).decision, 'pass', cmd);
  }
});
