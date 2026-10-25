'use strict';

// seatbelt-gaps: reading a secret env file through a docker/podman bind mount, a find primary or the stage in front of xargs stops keyless (S4), is a protected
// action keyed and is held in an outage, as `cat .env.local` is. Only the precise forms are closed: a mount or listing of a FOLDER, templates (`.env.example`),
// ordinary work and the report-only rows keep exactly the answers they had. The rows are DATA (test/support/seatbelt-gaps-rows.json: [id, kind, command, keyless,
// keyed, outage]; the three answers are the previous build's): nothing in them is ever run, they are only parsed. A real temp tree is the file system; dummy
// values are made here. The real hook is spawned for a few rows in keyed (a scripted service that ALLOWS everything), outage and keyless mode.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const SUP = path.join(__dirname, 'support');
const ROWS = JSON.parse(fs.readFileSync(path.join(SUP, 'seatbelt-gaps-rows.json'), 'utf8'));
const CASES = JSON.parse(fs.readFileSync(path.join(SUP, 'seatbelt-gaps-cases.json'), 'utf8'));
const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-sg-')));
const home = path.join(base, 'home', 'u');
const proj = path.join(home, 'proj');
const TOK = `ghp_${crypto.randomBytes(27).toString('base64url').replace(/[-_]/g, 'q')}`;
const KEY = `mrw_test_${crypto.randomBytes(16).toString('hex')}`;
const FILES = ['.env', '.env.local', '.env.production', '.env.staging', '.env.dist', '.env.defaults', '.env.myapp', '.env.test', '.env.example', '.env.sample', '.env.template', `.env.${TOK}`,
  'README.md', 'package.json', 'src/index.ts', 'src/a.ts', 'src/b.ts', 'src/app.env', 'sub/.env', 'sub/.env.local', 'sub/.env.example', 'docs/notes.txt', 'config.env', 'dev.env', 'app.env', '.dev.vars',
  'id_rsa.pub', 'foo.txt', 'a b/.env', 'deep/er/.env.local', 'cfg/.env', 'cfg/.env.staging', 'docker-compose.yml', 'compose.yaml', 'Dockerfile', 'x.txt', 'lib/util.ts'];
for (const f of FILES) { fs.mkdirSync(path.dirname(path.join(proj, f)), { recursive: true }); fs.writeFileSync(path.join(proj, f), f === 'package.json' ? '{"name":"p"}' : 'DUMMY=1\n'); }
for (const f of ['.env', '.env.local', `.env.${TOK}`, '.ssh/id_ed25519', '.aws/credentials', '.npmrc']) { fs.mkdirSync(path.dirname(path.join(home, f)), { recursive: true }); fs.writeFileSync(path.join(home, f), 'DUMMY=1\n'); }
fs.mkdirSync(path.join(base, 'other'), { recursive: true });
fs.writeFileSync(path.join(base, 'other', '.env'), 'DUMMY=1\n');
fs.symlinkSync(proj, path.join(home, 'wslink'));
fs.symlinkSync(home, path.join(proj, 'homelink'));
fs.symlinkSync(path.join(proj, '.env.local'), path.join(proj, 'link.txt'));
fs.symlinkSync(path.join(proj, '.env.local'), path.join(proj, 'innocent.log'));
fs.symlinkSync(path.join(proj, '.env.example'), path.join(proj, 'example-link.txt'));
test.after(() => fs.rmSync(base, { recursive: true, force: true }));

const oldHome = process.env.HOME;
const oldCwd = process.cwd();
process.env.HOME = home;
process.env.SBT_PASSWD_HOME = home;
process.chdir(proj);
test.after(() => { process.chdir(oldCwd); process.env.HOME = oldHome; delete process.env.SBT_PASSWD_HOME; });
const { classifyTool, outageHolds } = require('../dist/hook-pre-action.js');
const { outageRisk } = require('../dist/seatbelt/hook.js');
const { evaluateSeatbelt } = require('../dist/seatbelt/mapper.js');
const { normalizedHookAction } = require('../dist/normalized-action.js');
const names = require('../dist/seatbelt/env-names.js');

const fill = (c) => c.split('{{TOK}}').join(TOK).split('{{WS}}').join(proj).split('{{HOME}}').join(home);
const bash = (command) => ({ tool_name: 'Bash', tool_input: { command: fill(command) } });
const realFs = { readFile: (p, max) => { try { const s = fs.statSync(p); return s.isFile() && s.size <= max ? fs.readFileSync(p, 'utf8') : null; } catch { return null; } }, realpath: (p) => { try { return fs.realpathSync(p); } catch { return null; } }, readdir: (p) => { try { return fs.readdirSync(p); } catch { return null; } } };
const gitStub = { toplevel: (cwd) => (cwd === proj || cwd.startsWith(`${proj}/`) ? proj : null), getAll: () => [], currentBranch: () => 'feat/work', remoteHead: () => 'main' };
const keylessStops = (event) => evaluateSeatbelt(event, { cwd: proj, home, tmpdir: '/tmp', platform: 'linux', classifierClass: 'routine', budgetMs: 30000, fs: realFs, git: gitStub }).decision === 'stop';
const held = (event) => { const c = classifyTool(event); return !c.readOnly && outageHolds(c.protected || c.risk === 'high', () => outageRisk({ tool_name: event.tool_name, tool_input: event.tool_input, cwd: proj, truncated: false }, Number.POSITIVE_INFINITY)); };
const answers = (command) => { const ev = bash(command); return { keyless: keylessStops(ev), keyed: classifyTool(ev).protected === true, outage: held(ev) }; };

test('every closed form stops keyless, is protected keyed and is held in an outage', () => {
  const bad = [];
  let n = 0;
  for (const [id, kind, command] of ROWS) {
    if (kind !== 'stop') continue;
    n += 1;
    const a = answers(command);
    if (!(a.keyless && a.keyed && a.outage)) bad.push(`${id} ${JSON.stringify(a)}`);
  }
  assert.ok(n >= 150, `closed rows: ${n}`);
  assert.deepEqual(bad, []);
});

test('a mount value the parser cannot read, on a line that names a secret env file in any other word, stops in every mode', () => {
  assert.ok(CASES.unresolvedClosed.length >= 5);
  for (const c of CASES.unresolvedClosed) assert.deepEqual(answers(c), { keyless: true, keyed: true, outage: true }, c);
});

test('benign work, templates, folder mounts, dynamic names keep the previous answers; the link rows keep the answers named in the data', () => {
  const bad = [];
  let n = 0;
  for (const [id, kind, command, keyless, keyed, outage] of ROWS) {
    if (kind !== 'same') continue;
    n += 1;
    const a = answers(command);
    if (a.keyless !== keyless || a.keyed !== keyed || a.outage !== outage) bad.push(`${id} ${JSON.stringify(a)} was ${keyless}/${keyed}/${outage}`);
  }
  assert.ok(n >= 150, `pinned rows: ${n}`);
  assert.deepEqual(bad, []);
});

test('the friction rows named in the task stay open', () => {
  for (const c of CASES.friction) {
    const a = answers(c);
    assert.equal(a.keyless, false, c);
    assert.equal(a.outage, false, c);
  }
});

test('a folder mount that holds a secret env file is not a stop (report-only row, unchanged)', () => {
  for (const c of CASES.folder) assert.equal(answers(c).keyless, false, c);
});

test('the stop carries a reason the keyed policy keeps (the second reading), and names no secret', () => {
  for (const [c, reason] of CASES.reasons) {
    const d = evaluateSeatbelt(bash(c), { cwd: proj, home, tmpdir: '/tmp', platform: 'linux', classifierClass: 'routine', budgetMs: 30000, fs: realFs, git: gitStub });
    assert.ok(d.hits.some((h) => h.category === 'S4' && h.reason === reason && /_secret_(?:path|pattern|dir|name)$/.test(h.reason)), `${c}: ${JSON.stringify(d.hits.map((h) => h.reason))}`);
  }
  const dump = JSON.stringify([...CASES.tokenRows.map((c) => normalizedHookAction(bash(c), { salt: Buffer.alloc(32, 7) })), ...CASES.tokenRows.map((c) => classifyTool(bash(c)))]);
  assert.equal(dump.includes(TOK), false);
});

test('collisions: the key follows every word outside the file name; a stopped row and its sibling never share a key', () => {
  const salt = Buffer.alloc(32, 7);
  const key = (c) => { const a = normalizedHookAction(bash(c), { salt }); return JSON.stringify([a.programs, a.paths, a.tool_input.command, a.tool_input.command_sha256, a.tool_input.exact_hmac, a.truncated]); };
  for (const [a, b] of CASES.differ) assert.notEqual(key(a), key(b), `${a} / ${b}`);
  for (const [a] of CASES.differ) assert.equal(key(a), key(a));
});

test('env-names helpers: names, mount values and the bounded regex matcher', () => {
  assert.equal(names.secretEnvBase('.env'), 'secret');
  assert.equal(names.secretEnvBase('.ENV.Staging'), 'secret');
  assert.equal(names.secretEnvBase('.env.dist'), 'secret');
  assert.equal(names.secretEnvBase('.env.defaults'), 'secret');
  assert.equal(names.secretEnvBase('.dev.vars'), 'secret');
  assert.equal(names.secretEnvBase('app.env'), 'present');
  for (const t of ['.env.example', '.env.sample', '.env.template', '.ENV.EXAMPLE', 'env.d.ts', 'environment.md', '.envrc', 'README.md']) assert.equal(names.secretEnvBase(t), null, t);
  assert.equal(names.volumeHost('/a/.env:/x:ro'), '/a/.env');
  assert.equal(names.volumeHost('/x'), null);
  assert.equal(names.volumeHost(':/x'), null);
  assert.deepEqual(names.mountSources('type=bind,source=/a/.env,target=/x,src=/b/.env.local'), ['/a/.env', '/b/.env.local']);
  assert.deepEqual(names.mountSources('type=bind,target=/x'), []);
  const cands = ['./.env.staging', './d/.env.local', './README.md'];
  assert.equal(names.regexMatchesAny('.*/\\.env\\..*', cands), 'yes');
  assert.equal(names.regexMatchesAny('.*/\\.e[n]v\\.staging', cands), 'yes');
  assert.equal(names.regexMatchesAny('.*/\\.env\\(\\.staging\\|\\.local\\)', cands), 'yes');
  assert.equal(names.regexMatchesAny('.*/\\.env(\\.staging|\\.local)', cands), 'yes');
  assert.equal(names.regexMatchesAny('.*\\.ts', cands), 'no');
  assert.equal(names.regexMatchesAny('.*/README\\.md', ['./.env.staging']), 'no');
  assert.equal(names.regexMatchesAny('\\1', cands), 'unsure');
  // a crafted pattern ends fast (bounded work), never a hang, and never reads as a clean "no" when it ran out of steps
  const long = `${'(a*)*'.repeat(8)}b`;
  const started = Date.now();
  const r = names.regexMatchesAny(long, [`./${'a'.repeat(200)}`]);
  assert.ok(Date.now() - started < 5000);
  assert.notEqual(r, 'yes');
});

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
  const r = spawnSync(process.execPath, [...m.args, path.join(ROOT, 'dist', 'cli.js'), 'claude-pre-action-hook'], { cwd: proj, encoding: 'utf8', timeout: 60000, env: m.env,
    input: JSON.stringify({ session_id: 's', cwd: proj, hook_event_name: 'PreToolUse', permission_mode: 'default', tool_name: 'Bash', tool_input: { command: fill(command) } }) });
  assert.equal(r.error, undefined);
  const text = `${r.stdout}${r.stderr}`;
  assert.equal(text.includes(KEY), false, 'the key stays out of the output');
  assert.equal(text.includes(TOK), false, 'the token stays out of the output');
  let j = null;
  try { j = r.stdout.trim() ? JSON.parse(r.stdout) : null; } catch { j = null; }
  return j?.hookSpecificOutput?.permissionDecision || (r.status === 2 ? 'deny' : 'none');
}

test('the real hook: the closed forms are denied in keyed (service allows), outage and keyless mode; ordinary work is not', () => {
  for (const c of CASES.realClosed) for (const mode of ['keyed', 'outage', 'keyless']) assert.equal(realHook(mode, c), 'deny', `${mode}: ${c}`);
  for (const c of CASES.realOpen) assert.notEqual(realHook('keyless', c), 'deny', `keyless: ${c}`);
});
