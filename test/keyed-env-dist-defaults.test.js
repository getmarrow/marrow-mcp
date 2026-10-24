'use strict';

// fa-keyed-env LOW-3 (owner decision, 24 Oct): `.env.dist` and `.env.defaults` are secret files in keyed mode, as the keyless seatbelt already treats them.
// `.env.example`, `.env.sample` and `.env.template` stay templates in both modes. The keyed policy builds its template names from one list
// (ENV_TEMPLATE_WORDS, src/secret-paths.ts), a list this file proves equal to the keyless table's (ENV_TEMPLATE_SUFFIX). A real temp tree is the file system for all modes; dummy values are made here.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const SUP = path.join(__dirname, 'support');
const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-envdist-')));
const home = path.join(base, 'home');
const proj = path.join(home, 'proj');
const TOK = `ghp_${crypto.randomBytes(27).toString('base64url').replace(/[-_]/g, 'q')}`;
const FILES = ['.env', '.env.local', '.env.production', '.env.staging', '.env.dist', '.env.defaults', '.env.default', '.env.example', '.env.sample', '.env.template', '.env.examples',
  '.env.example.bak', '.env.dist.bak', '.env.distx', '.env.defaultsx', 'app.env.dist', 'app.env.example', 'env.dist', 'my.env.defaults', 'sub/.env', 'sub/.env.dist', 'sub/.env.defaults',
  'sub/.env.example', 'README.md', 'src/index.ts', 'docs/notes.txt'];
for (const f of FILES) {
  fs.mkdirSync(path.dirname(path.join(proj, f)), { recursive: true });
  fs.writeFileSync(path.join(proj, f), 'DUMMY=1\n');
}
fs.symlinkSync(path.join(proj, '.env.dist'), path.join(proj, 'dist-link.txt'));
fs.symlinkSync(path.join(proj, '.env.example'), path.join(proj, 'example-link.txt'));
test.after(() => fs.rmSync(base, { recursive: true, force: true }));

const oldHome = process.env.HOME;
const oldCwd = process.cwd();
process.env.HOME = home;
process.chdir(proj);
test.after(() => { process.chdir(oldCwd); process.env.HOME = oldHome; });
const { classifyTool, outageHolds } = require('../dist/hook-pre-action.js');
const { outageRisk } = require('../dist/seatbelt/hook.js');
const { evaluateSeatbelt } = require('../dist/seatbelt/mapper.js');
const { ENV_TEMPLATE_SUFFIX } = require('../dist/seatbelt/tables.js');
const { ENV_TEMPLATE_WORDS } = require('../dist/secret-paths.js');
const { normalizedHookAction } = require('../dist/normalized-action.js');

const bash = (command) => ({ tool_name: 'Bash', tool_input: { command: command.split('{TOK}').join(TOK) } });
const tool = (name, input) => ({ tool_name: name, tool_input: input });
const realFs = { readFile: (p, max) => { try { const s = fs.statSync(p); return s.isFile() && s.size <= max ? fs.readFileSync(p, 'utf8') : null; } catch { return null; } }, realpath: (p) => { try { return fs.realpathSync(p); } catch { return null; } }, readdir: (p) => { try { return fs.readdirSync(p); } catch { return null; } } };
const keylessStops = (event) => evaluateSeatbelt(event, { cwd: proj, home, tmpdir: '/tmp', platform: 'linux', budgetMs: 30000, fs: realFs, git: { toplevel: () => null, getAll: () => [], currentBranch: () => 'main', remoteHead: () => 'main' } }).decision === 'stop';
const held = (event) => { const c = classifyTool(event); return !c.readOnly && outageHolds(c.protected || c.risk === 'high', () => outageRisk({ tool_name: event.tool_name, tool_input: event.tool_input, cwd: proj, truncated: false }, Number.POSITIVE_INFINITY)); };

// The template words the keyless table names, read from the table itself: `\.(?:example|sample|template)$`.
const TEMPLATE_WORDS = ENV_TEMPLATE_SUFFIX.source.match(/\(\?:([^)]+)\)/)[1].split('|');

test('one list: the keyed template words equal the keyless table\'s, and are the three the owner decided on', () => {
  assert.deepEqual(TEMPLATE_WORDS, ['example', 'sample', 'template']);
  assert.deepEqual([...ENV_TEMPLATE_WORDS], TEMPLATE_WORDS);
  // The keyless regular expression is exactly these words: nothing else is spelled in it.
  assert.equal(ENV_TEMPLATE_SUFFIX.source, `\\.(?:${TEMPLATE_WORDS.join('|')})$`);
});

test('one list: for every .env name, the keyed policy and the keyless seatbelt agree on secret versus template (reads, tools, wrapped reads)', () => {
  const names = ['.env', '.env.local', '.env.production', '.env.staging', '.env.dist', '.env.defaults', '.env.default', '.env.example', '.env.sample', '.env.template', '.env.examples',
    '.env.example.bak', '.env.dist.bak', '.env.distx', '.env.defaultsx', 'sub/.env', 'sub/.env.dist', 'sub/.env.defaults', 'sub/.env.example', './.env.dist', `${proj}/.env.defaults`, `${proj}/.env.example`];
  const forms = [(n) => bash(`cat ${n}`), (n) => bash(`head -n 2 ${n}`), (n) => bash(`grep -n K ${n}`), (n) => bash(`bash -c 'cat ${n}'`), (n) => bash(`true && cat ${n}`), (n) => bash(`(cat ${n})`),
    (n) => tool('Read', { file_path: n }), (n) => tool('Grep', { pattern: 'K', path: n })];
  const wrong = [];
  let rows = 0;
  for (const n of names) {
    for (const form of forms) {
      const event = form(n);
      rows += 1;
      const keyed = classifyTool(event).protected === true;
      const keyless = keylessStops(event);
      if (keyed !== keyless) wrong.push(`${JSON.stringify(event.tool_input)}: keyed ${keyed}, keyless ${keyless}`);
    }
  }
  assert.deepEqual(wrong, []);
  assert.ok(rows >= 170, `rows: ${rows}`);
  // Every template word the keyless table names is a template in keyed mode, and every other `.env.<word>` is a secret file there.
  for (const w of TEMPLATE_WORDS) assert.equal(classifyTool(bash(`cat .env.${w}`)).protected, false, `.env.${w}`);
  for (const w of ['dist', 'defaults', 'default', 'local', 'production', 'staging', 'test', 'bak', 'examples', 'tmpl', 'orig']) assert.equal(classifyTool(bash(`cat .env.${w}`)).protected, true, `.env.${w}`);
});

const SECRET_ROWS = [];
for (const f of ['.env.dist', '.env.defaults', '.env.default', 'sub/.env.dist', './.env.dist', `${proj}/.env.dist`, `${proj}/.env.defaults`, '~/proj/.env.dist', 'dist-link.txt']) {
  for (const reader of ['cat', 'head -n 2', 'tail -n 2', 'less', 'grep -n K', 'grep -rn K', 'sed -n 1p', 'awk 1', 'xxd', 'base64', 'cp {} /tmp/out', 'source', 'diff {} README.md', 'wc -l <']) {
    SECRET_ROWS.push([`${reader} ${f}`, bash(reader.includes('{}') ? reader.split('{}').join(f) : `${reader} ${f}`)]);
  }
}
for (const c of ['cd sub && cat .env.dist', 'cd sub && cat .env.defaults', "bash -c 'cd sub && cat .env.dist'", "bash -c 'cat .env.dist'", "sh -c 'cat .env.defaults'", "eval 'cat .env.dist'", "sudo -n sh -c 'cat .env.defaults'",
  'true && cat .env.dist', 'ls; cat .env.defaults', 'false || cat .env.dist', 'cat .env.dist | head -n 2', '(cat .env.dist)', '{ cat .env.defaults; }', 'cat .env.dist &', 'echo $(cat .env.defaults)',
  'echo `cat .env.dist`', 'if true; then cat .env.dist; fi', 'for i in 1; do cat .env.defaults; done', 'f() { cat .env.dist; }; f', 'V=.env.dist; cat $V', 'cat ${V:-.env.defaults}',
  "echo .env.dist | xargs cat", "ssh localhost 'cat .env.dist'", 'timeout 5 cat .env.dist', 'nice -n 5 cat .env.defaults',
  'cat .env.d*', 'cat .env.def*', 'cat .env.{dist,defaults}', 'cat .env.dis?', 'cat .env.[d]ist', "bash -c 'cat .env.d*'"]) SECRET_ROWS.push([c, bash(c)]);
for (const f of ['.env.dist', '.env.defaults', 'sub/.env.dist', `${proj}/.env.dist`, 'dist-link.txt']) {
  SECRET_ROWS.push([`Read ${f}`, tool('Read', { file_path: f })], [`Grep ${f}`, tool('Grep', { pattern: 'K', path: f })], [`Edit ${f}`, tool('Edit', { file_path: f, old_string: 'a', new_string: 'b' })],
    [`Write ${f}`, tool('Write', { file_path: f, content: 'x' })]);
}
SECRET_ROWS.push(['Monitor bash -c', tool('Monitor', { command: "bash -c 'cat .env.dist'" })]);

test('a read of .env.dist or .env.defaults is a protected keyed action and an outage hold, and keyless stops it', () => {
  const wrong = [];
  for (const [name, event] of SECRET_ROWS) {
    const c = classifyTool(event);
    // `.env.default` (singular) is no template in the keyless table either; the glob rows reach it too. Rows the keyless seatbelt itself does not stop are not listed here.
    if (!keylessStops(event)) wrong.push(`keyless does not stop: ${name}`);
    if (!(c.protected === true && c.readOnly === false)) wrong.push(`keyed not protected: ${name}`);
    if (c.risk !== 'high') wrong.push(`keyed risk ${c.risk}: ${name}`);
    if (!held(event)) wrong.push(`outage not held: ${name}`);
  }
  assert.deepEqual(wrong, []);
  assert.ok(SECRET_ROWS.length >= 140, `rows: ${SECRET_ROWS.length}`);
});

test('the brief rows: .env.dist and .env.defaults now stop keyed as keyless; the templates answer exactly as before', () => {
  for (const c of ['cat .env.dist', 'cat .env.defaults', 'cd sub && cat .env.dist', 'cp .env.dist .env']) {
    const out = classifyTool(bash(c));
    assert.equal(out.protected, true, c);
    assert.equal(out.readOnly, false, c);
    assert.equal(keylessStops(bash(c)), true, `keyless ${c}`);
  }
  for (const c of ['cat .env.example', 'cat .env.sample', 'cat .env.template', 'cd sub && cat .env.example', 'grep -n K .env.example', 'cat app.env.example', 'diff .env.example .env.sample']) {
    const out = classifyTool(bash(c));
    assert.equal(out.protected, false, c);
    // diff is no read-only program in the keyed table (before and after this change); the readers are.
    if (!c.startsWith('diff')) { assert.equal(out.readOnly, true, c); assert.equal(out.risk, 'low', c); }
    assert.equal(keylessStops(bash(c)), false, `keyless ${c}`);
    assert.equal(held(bash(c)), false, `outage ${c}`);
  }
  // Writing .env was protected before (the target is a secret file) and stays so, from a template or from .env.dist.
  for (const c of ['cp .env.example .env', 'cp .env.dist .env']) assert.equal(classifyTool(bash(c)).protected, true, c);
  for (const f of ['.env.example', '.env.sample', '.env.template', 'example-link.txt']) {
    assert.equal(classifyTool(tool('Read', { file_path: f })).protected, false, `Read ${f}`);
    assert.equal(keylessStops(tool('Read', { file_path: f })), false, `keyless Read ${f}`);
  }
});

test('friction: names that are no secret file, text that only names one, and ordinary work keep their answers', () => {
  // `my.env.defaults`, `env.dist`, `app.env.dist`, `.env.distx` and the rest are no `.env` file in either table.
  for (const c of ['cat my.env.defaults', 'cat env.dist', 'cat app.env.dist', 'cat app.env.example', 'cat README.md', 'cat src/index.ts', 'git status', 'ls -la', 'npm test', 'grep -rn foo src', 'ls .env.dist', 'ls -la .env.defaults',
    'stat .env.dist', 'echo "copy .env.example to .env"', 'cat docs/notes.txt', 'git diff', 'cat example-link.txt']) {
    const out = classifyTool(bash(c));
    assert.equal(out.protected, false, c);
    assert.equal(keylessStops(bash(c)), false, `keyless ${c}`);
  }
  for (const c of ['ls .env.dist', 'ls -la .env.defaults', 'stat .env.dist', 'cat README.md']) assert.equal(classifyTool(bash(c)).readOnly, true, c);
});

test('twins: a .env.dist or .env.defaults row gets the keyed answer of the same command on .env.staging, in every reader and wrapper', () => {
  const readers = ['cat {}', 'head -n 2 {}', 'grep -n K {}', 'cp {} /tmp/out', 'source {}', 'sed -n 1p {}', 'wc -l < {}'];
  const wrappers = [(c) => c, (c) => `bash -c '${c}'`, (c) => `sh -c "${c}"`, (c) => `eval '${c}'`, (c) => `cd sub && ${c}`, (c) => `true && ${c}`, (c) => `(${c})`, (c) => `echo $(${c})`,
    (c) => `timeout 5 ${c}`, (c) => `ssh localhost '${c}'`, (c) => `for i in 1; do ${c}; done`, (c) => `${c} | head -n 2`];
  const answer = (c) => { const o = classifyTool(bash(c)); return JSON.stringify([o.protected, o.readOnly, o.risk, o.type, o.role, o.surfaces, held(bash(c)), keylessStops(bash(c))]); };
  const diffs = [];
  let rows = 0;
  for (const wrap of wrappers) {
    for (const r of readers) {
      for (const f of ['.env.dist', '.env.defaults']) {
        const mine = wrap(r.split('{}').join(f));
        const twin = wrap(r.split('{}').join('.env.staging'));
        rows += 1;
        if (answer(mine) !== answer(twin)) diffs.push(mine);
      }
    }
  }
  assert.deepEqual(diffs, []);
  assert.ok(rows >= 160, `rows: ${rows}`);
});

test('collisions: the new stops never share a key with a template read, and text after the name stays in the key', () => {
  const salt = crypto.randomBytes(32);
  const n = (c) => normalizedHookAction(bash(c), { salt });
  const key = (a) => JSON.stringify([a.programs, a.paths, a.tool_input.command, a.tool_input.command_sha256, a.tool_input.exact_hmac, a.truncated]);
  assert.notEqual(key(n('cat .env.dist')), key(n('cat .env.example')));
  assert.notEqual(key(n('cat .env.defaults')), key(n('cat .env.sample')));
  assert.notEqual(key(n('cat .env.dist')), key(n('cat .env.defaults')));
  assert.notEqual(key(n('cat .env.dist && ls')), key(n('cat .env.dist && rm x')));
  assert.notEqual(key(n("bash -c 'cat .env.dist'")), key(n("bash -c 'cat README.md'")));
  assert.equal(key(n('cat .env.dist')), key(n('cat .env.dist')));
  // A name that holds a token-shaped part: protected, and no secret in the key, the classification or the keyless answer.
  const c = `cat .env.${TOK}.dist`;
  assert.equal(classifyTool(bash(c)).protected, true);
  const out = JSON.stringify([n(c), classifyTool(bash(c)), keylessStops(bash(c))]);
  assert.equal(out.includes(TOK), false);
  assert.equal(out.includes(TOK.slice(4, 24)), false);
});

const CLI = path.join(ROOT, 'dist', 'cli.js');
const KEY = `mrw_test_${crypto.randomBytes(16).toString('hex')}`;
function realHook(mode, command) {
  const mock = path.join(base, 'mock');
  fs.mkdirSync(mock, { recursive: true });
  fs.writeFileSync(path.join(mock, 'config.json'), JSON.stringify({ runtime: { ok: true, decision_id: 'd-allow', risk_gate: { allow: true, decision: 'allow', enforced: true, gate_required: false, risk_level: 'low' } } }));
  const req = (f) => ['--require', path.join(SUP, f)];
  const common = { PATH: process.env.PATH, HOME: home, TMPDIR: os.tmpdir(), SBT_PASSWD_HOME: home, MARROW_PASSIVE_TOKEN_USAGE: 'false', MARROW_HOOK_BACKGROUND_NUDGE: 'false', MARROW_AUTO_ENROLL: 'false', SBT_HOOK_DEADLINE: 'roomy' };
  const modes = {
    keyed: { args: [...req('passwd-home-fake.cjs'), ...req('host-approval-fetch-mock.cjs'), ...req('seatbelt-hook-preload.cjs')], env: { ...common, MARROW_API_KEY: KEY, MARROW_BASE_URL: 'https://api.example.test', MARROW_TEST_MOCK_DIR: mock } },
    outage: { args: [...req('passwd-home-fake.cjs'), ...req('seatbelt-hook-preload.cjs'), ...req('f2-fetch-scenarios.cjs')], env: { ...common, MARROW_API_KEY: KEY, MARROW_BASE_URL: 'https://api.example.test', F2_SCENARIO: 'runtime-refused' } },
    keyless: { args: [...req('passwd-home-fake.cjs'), ...req('seatbelt-hook-preload.cjs')], env: common },
  };
  const m = modes[mode];
  const r = spawnSync(process.execPath, [...m.args, CLI, 'claude-pre-action-hook'], { cwd: proj, encoding: 'utf8', timeout: 60000, env: m.env,
    input: JSON.stringify({ session_id: 's', cwd: proj, hook_event_name: 'PreToolUse', permission_mode: 'default', tool_name: 'Bash', tool_input: { command } }) });
  assert.equal(r.error, undefined);
  assert.equal(`${r.stdout}${r.stderr}`.includes(KEY), false, 'no secret in hook output');
  let j = null;
  try { j = r.stdout.trim() ? JSON.parse(r.stdout) : null; } catch { j = null; }
  return j?.hookSpecificOutput?.permissionDecision || (r.status === 2 ? 'deny' : 'none');
}

test('the real hook stops .env.dist and .env.defaults reads in keyed (service answers allow), outage and keyless mode, and leaves the templates alone', () => {
  const stops = ['cat .env.dist', 'cat .env.defaults', 'cd sub && cat .env.dist', 'cp .env.dist /tmp/out', "bash -c 'cat .env.dist'", 'cat dist-link.txt'];
  const passes = ['cat .env.example', 'cat .env.sample', 'cat .env.template', 'cd sub && cat .env.example', 'git status', 'cat README.md'];
  const wrong = [];
  for (const mode of ['keyed', 'outage', 'keyless']) {
    for (const c of stops) if (realHook(mode, c) !== 'deny') wrong.push(`${mode}: ${c}`);
    if (mode !== 'outage') for (const c of passes) if (realHook(mode, c) === 'deny') wrong.push(`friction ${mode}: ${c}`);
  }
  // `cp .env.example .env` writes a secret file: stopped in every mode, before and after.
  for (const mode of ['keyed', 'keyless']) if (realHook(mode, 'cp .env.example .env') !== 'deny') wrong.push(`${mode}: cp .env.example .env`);
  assert.deepEqual(wrong, []);
});
