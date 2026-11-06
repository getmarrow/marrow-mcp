'use strict';

// A5 (owner A141): a data write of a held word into a file that runs a command later (.git/config, package.json,
// .github/workflows/*.yml and *.yaml, .husky/*, Makefile) keeps master's answer in every spelling; every other lowered call
// is unchanged. Rows: test/fixtures/hookdata/a5-rows.cjs (hook INPUTS only, nothing is run). Master answers:
// test/fixtures/hookdata/a5-base.json (recorded from cb1918f261f2; `tip` says how 93f8cee54933 answered).
const assert = require('node:assert/strict');
const test = require('node:test');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const { classifyTool } = require('../dist/hook-pre-action.js');
const { protectedMention, selfProtectKind } = require('../dist/self-protect.js');
const { rows, makeHome } = require('./fixtures/hookdata/a5-rows.cjs');
const BASE = require('./fixtures/hookdata/a5-base.json');

const FIELDS = ['action', 'target', 'type', 'role', 'surfaces', 'risk', 'protected', 'readOnly'];
const pick = (c) => Object.fromEntries(FIELDS.map((field) => [field, c[field]]));
const home = mkdtempSync(join(tmpdir(), 'hookdata-a5-'));
const savedHome = process.env.HOME;
makeHome(home);
process.env.HOME = home;
test.after(() => { process.env.HOME = savedHome; rmSync(home, { recursive: true, force: true }); });
const event = (row) => ({ tool_name: 'Bash', tool_input: { command: row.command }, ...(row.home ? { cwd: row.cwd ? join(home, row.cwd) : home } : {}) });

test('the A5 rows are recorded from master, one answer per row', () => {
  assert.equal(BASE.base, 'cb1918f261f2dde66dcaf29bbd1f99861bbe92f5');
  assert.equal(Object.keys(BASE.rows).length, rows.length);
  for (const type of ['gitconfig', 'packagejson', 'workflowyml', 'workflowyaml', 'husky', 'makefile']) {
    assert.ok(rows.filter((row) => row.type === type && BASE.rows[row.id].tip === 'ALLOW' && BASE.rows[row.id].pre.protected).length >= 40, type);
  }
});

for (const row of rows) {
  const recorded = BASE.rows[row.id];
  test(`${row.id} ${row.expect} (master ${recorded.pre.protected ? 'HOLD' : 'ALLOW'}, tip ${recorded.tip})`, () => {
    const pre = pick(classifyTool(event(row)));
    const post = pick(classifyTool(event(row), { postTool: true }));
    if (row.expect === 'ALLOW') {
      assert.equal(pre.protected, false, `${row.id}: ${pre.action}`);
      assert.equal(post.action, pre.action, row.id);
    } else {
      assert.deepEqual(pre, recorded.pre, `${row.id} keeps the master classification`);
      assert.deepEqual(post, recorded.post, `${row.id} keeps the master PostToolUse classification`);
    }
  });
}

test('the run-later list is not a T2 list: an ordinary edit of package.json or a Makefile is not self-protected', () => {
  for (const command of ['echo "x" >> package.json', 'cat > Makefile <<\'EOF\'\nall:\nEOF', 'echo x > .github/workflows/ci.yml', 'echo x > .husky/pre-commit']) {
    assert.equal(selfProtectKind({ tool_name: 'Bash', tool_input: { command } }), null, command);
    assert.equal(protectedMention(command), null, command);
  }
  for (const file of ['package.json', 'Makefile', '.git/config', '.github/workflows/ci.yml', '.husky/pre-commit']) {
    assert.equal(classifyTool({ tool_name: 'Write', tool_input: { file_path: file, content: 'all:' } }).protected, false, file);
  }
});
