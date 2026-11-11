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

// Audit fix round: case spellings, look-alike spellings and sibling run-later files with data words, and words only in the tool
// description, give master's decision; mixed chains, repeated redirects, variables and odd name endings stay master or stricter.
for (const row of P.cutRows()) {
  test(`run-later files judged folded ${row.cls} ${row.id.replace(/\n/g, ' ')}: master ${row.master}`, () => {
    const answer = R.answer({ classifyTool }, P.cutEvent(row, root));
    assert.equal(answer.decision, row.master, row.id);
    if (row.master === 'ask') assert.notDeepEqual([answer.type, answer.surfaces], ['process', 'workspace'], `${row.id}: never the lowered class`);
    if (!row.input) assert.equal(R.answer({ classifyTool }, P.cutEvent(row, root, 'codex')).decision, row.master, `${row.id} (codex shape)`);
  });
}

test('the run-later hold by name is unchanged: case spellings and siblings with no risk word keep master (no new raise)', () => {
  for (const name of ['Package.json', 'PACKAGE.json', 'cargo.toml', 'wrangler.toml', 'deno.json', 'vercel.json', 'tsconfig.build.json', 'fly.toml']) {
    const event = bash(`echo x >> ${name}`);
    assert.equal(writesRunLaterFile(event, root), false, name);
    assert.equal(R.answer({ classifyTool }, event).decision, 'allow', name);
  }
});

test('data words to an ordinary file still stop asking beside the fold: lower-case and ASCII names, a description with no risk word', () => {
  for (const command of [`echo "${R.W}" >> notes/NOTES.md`, `echo "${R.W}" >> notes/pkg-notes.md`, `echo "${R.W}" >> "notes/my notes.md"`,
    `cat >> notes/NOTES.md <<'EOF'\n${R.W}\nEOF`, `echo "${R.W}" >> reports/results.csv`]) {
    const answer = R.answer({ classifyTool }, { ...R.HOSTS.claude(command), cwd: root });
    assert.deepEqual([answer.decision, answer.type, answer.surfaces], ['allow', 'process', 'workspace'], command);
  }
});

// Last fix round: run-later folder names are judged folded too (NFKC, then lower case), over every folder of the resolved path; a
// look-alike, colon, trailing dot or space in a folder below the working folder and an /etc spelling keep the master answer.
const folderAnswer = (row, host) => {
  const event = P.folderEvent(row, root, host);
  process.chdir(event.cwd);
  try { return R.answer({ classifyTool }, event); } finally { process.chdir(root); }
};
for (const row of P.folderRows()) {
  test(`run-later folder names judged folded ${row.id.replace(/\n/g, ' ')}: ${row.want}`, () => {
    const answer = folderAnswer(row);
    assert.equal(answer.decision, row.want, row.id);
    if (row.want === 'ask') assert.notDeepEqual([answer.type, answer.surfaces], ['process', 'workspace'], `${row.id}: never the lowered class`);
    if (!row.inputCwd) assert.equal(folderAnswer(row, 'codex').decision, row.want, `${row.id} (codex shape)`);
  });
}

test('the folder class sweep: 5 run-later folders x 5 spellings x 4 positions x 3 sinks all ask', () => {
  const rows = P.sweepRows();
  assert.equal(rows.length, 300);
  assert.deepEqual(rows.filter((row) => folderAnswer(row).decision !== 'ask').map((row) => row.id), []);
});

test('an /etc spelling as the working folder keeps asking (stub: an upper-case /Etc exists only on a case-insensitive disk)', () => {
  const { realpathSync } = fs;
  const { cwd } = process;
  const answerIn = (folder) => {
    fs.realpathSync = (p, ...rest) => (String(p).startsWith(folder) ? String(p) : realpathSync(p, ...rest));
    process.cwd = () => folder;
    const event = { hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'echo deploy production > notes/a.md' }, cwd: folder };
    return R.answer({ classifyTool }, event).decision;
  };
  try {
    for (const folder of ['/Etc', '/ETC/work', '/ｅtc']) assert.equal(answerIn(folder), 'ask', folder);
    assert.equal(answerIn('/Etcetera'), 'allow', 'the stub reaches the data-word path');
  } finally {
    fs.realpathSync = realpathSync;
    process.cwd = cwd;
  }
});
