'use strict';
// Data words, round 2 patch (FIX1-HOOKDATA-R3-PATCH): `source` / `.` run a file and the `git config` verb writes no run-later file by a
// write form, so both keep the master answer (decision, classification and key, recorded from a master build); a data sink into
// .git/config and every write form into a run-later file keep asking (owner A141). Hook INPUT strings only: nothing here is ever run.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const P = require('./support/hookdata-r3b-rows.cjs');
const R = require('./support/hookdata-r3-rows.cjs');
const { classifyTool } = require('../dist/hook-pre-action.js');
const { writesRunLaterFile } = require('../dist/self-protect.js');
const na = require('../dist/normalized-action.js');
const MASTER = require('./fixtures/hookdata-r3b-master.json');

const root = fs.realpathSync(P.fixture(fs.mkdtempSync(path.join(os.tmpdir(), 'hookdata-r3b-'))));
const savedHome = process.env.HOME;
const savedCwd = process.cwd();
process.env.HOME = path.join(root, 'home');
process.chdir(root);
test.after(() => { process.chdir(savedCwd); process.env.HOME = savedHome; fs.rmSync(root, { recursive: true, force: true }); });

const tip = P.record({ classifyTool, na }, root);
const kinds = new Map(P.rows().map((row) => [row.id, row]));
const bash = (command) => ({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, cwd: root });

for (const [id, master] of Object.entries(MASTER)) {
  const row = kinds.get(id.split('@')[0]);
  test(`run forms and the git config verb ${id}: ${row.kind === 'sink' ? 'a run-later write still asks' : 'master answer'}`, () => {
    const answer = tip[id];
    if (row.kind === 'master' || master.decision === 'ask') assert.deepEqual(answer, master, id);
    else {
      assert.equal(answer.decision, 'ask', id);
      assert.equal(answer.type, 'security', id);
      assert.match(answer.surfaces, /persistence/, `${id}: a run-later hold says persistence, never production`);
      assert.equal(answer.key, master.key, `${id}: the key is master's`);
    }
    const event = R.eventFor(row.tool ? { ...row, tool: undefined } : row, root, row.tool ? 'powershell' : 'claude');
    assert.equal(writesRunLaterFile(event, root), row.kind === 'sink', `${id}: run-later write by name`);
  });
}

test('every patch row and host shape has a recorded master answer', () => {
  assert.deepEqual(Object.keys(tip).sort(), Object.keys(MASTER).sort());
  assert.ok(Object.keys(MASTER).length > 300);
});

test('the recorded master answers equal a live master build (HOOKDATA_R3B_MASTER names a master clone)', { skip: !process.env.HOOKDATA_R3B_MASTER }, () => {
  const dir = path.resolve(process.env.HOOKDATA_R3B_MASTER);
  const live = P.record({ classifyTool: require(path.join(dir, 'dist/hook-pre-action.js')).classifyTool, na: require(path.join(dir, 'dist/normalized-action.js')) }, root);
  assert.deepEqual(live, MASTER);
});

test('A141: every write form into a run-later file with no risk word still asks, by name', () => {
  const forms = [(t) => `echo x > ${t}`, (t) => `echo x >> ${t}`, (t) => `echo x | tee ${t}`, (t) => `echo x | tee -a ${t}`, (t) => `cp notes/NOTES.md ${t}`,
    (t) => `mv notes/NOTES.md ${t}`, (t) => `ln -sf notes/NOTES.md ${t}`, (t) => `sed -i s/a/b/ ${t}`, (t) => `cat > ${t} <<'EOF'\nx\nEOF`, (t) => `truncate -s 0 ${t}`];
  const targets = ['.git/config', 'package.json', 'Makefile', '.github/workflows/ci.yml', '.husky/pre-commit', '.gitattributes', '.envrc', 'tsconfig.json',
    '.github/actions/a/action.yml', '.git/hooks/pre-push'];
  for (const target of targets) {
    for (const form of forms) {
      const command = form(target);
      const answer = R.answer({ classifyTool }, bash(command));
      assert.equal(answer.decision, 'ask', command);
      assert.equal(writesRunLaterFile(bash(command), root), true, command);
      if (answer.type === 'security') assert.match(answer.surfaces, /persistence/, command);
    }
  }
});

test('a run form or the git config verb before or after a run-later write still asks: the write decides', () => {
  for (const command of ['git config alias.e log && echo x >> .git/config', 'source env/bin/activate; echo x > package.json', '. ./x.sh || tee -a Makefile < notes/NOTES.md',
    "cat > .envrc <<'EOF'\nexport A=1\nEOF\n. ./.envrc",'git config core.editor vim\ncp notes/NOTES.md .husky/pre-commit']) {
    assert.equal(R.answer({ classifyTool }, bash(command)).decision, 'ask', command);
    assert.equal(writesRunLaterFile(bash(command), root), true, command);
  }
});
