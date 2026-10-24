'use strict';

// F-A / MED-1: in keyed mode a secret file read inside nested shell code (`bash -c`, `eval`, `sudo -n sh -c`, `xargs`, `ssh`, a chain, a variable, a glob, a
// link) is a protected action, as the keyless seatbelt stops it (S4) and an outage holds it. A real temp tree is the file system for all three; dummy values
// are made here. The friction rows (ordinary work) keep exactly the answers they had. The real hook is spawned for the key forms in keyed (a scripted
// service that ALLOWS everything), outage and keyless mode.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const SUP = path.join(__dirname, 'support');
const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-fa-')));
const home = path.join(base, 'home');
const proj = path.join(home, 'proj');
const TOK = `ghp_${crypto.randomBytes(27).toString('base64url').replace(/[-_]/g, 'q')}`;
for (const f of ['.env', '.env.local', '.env.production', `.env.${TOK}`, '.env.example', '.npmrc', '.dev.vars', 'README.md', 'src/index.ts', 'sub/.env', 'docs/notes.txt', 'src/app.env']) {
  fs.mkdirSync(path.dirname(path.join(proj, f)), { recursive: true });
  fs.writeFileSync(path.join(proj, f), 'DUMMY=1\n');
}
fs.writeFileSync(path.join(proj, 'package.json'), '{"name":"p"}');
fs.symlinkSync(path.join(proj, '.env.local'), path.join(proj, 'link.txt'));
fs.symlinkSync(path.join(proj, '.env.local'), path.join(proj, 'innocent.log'));
fs.symlinkSync(path.join(proj, 'README.md'), path.join(proj, 'docs-link.md'));
fs.mkdirSync(path.join(proj, 'node_modules', '.bin'), { recursive: true });
fs.writeFileSync(path.join(proj, 'node_modules', 'real.js'), '1');
fs.symlinkSync(path.join(proj, 'node_modules', 'real.js'), path.join(proj, 'node_modules', '.bin', 'tool'));
test.after(() => fs.rmSync(base, { recursive: true, force: true }));

const oldHome = process.env.HOME;
const oldCwd = process.cwd();
process.env.HOME = home;
process.chdir(proj);
test.after(() => { process.chdir(oldCwd); process.env.HOME = oldHome; });
const { classifyTool, outageHolds, mayReadSecret } = require('../dist/hook-pre-action.js');
const { policyReadsAllWords } = require('../dist/hook-tool-policy.js');
const { outageRisk } = require('../dist/seatbelt/hook.js');
const { evaluateSeatbelt } = require('../dist/seatbelt/mapper.js');
const { normalizedHookAction } = require('../dist/normalized-action.js');

const bash = (command) => ({ tool_name: 'Bash', tool_input: { command: command.split('{TOK}').join(TOK) } });
const tool = (name, input) => ({ tool_name: name, tool_input: input });
const realFs = { readFile: (p, max) => { try { const s = fs.statSync(p); return s.isFile() && s.size <= max ? fs.readFileSync(p, 'utf8') : null; } catch { return null; } }, realpath: (p) => { try { return fs.realpathSync(p); } catch { return null; } }, readdir: (p) => { try { return fs.readdirSync(p); } catch { return null; } } };
const keylessStops = (event) => evaluateSeatbelt(event, { cwd: proj, home, tmpdir: '/tmp', platform: 'linux', budgetMs: 30000, fs: realFs, git: { toplevel: () => null, getAll: () => [], currentBranch: () => 'main', remoteHead: () => 'main' } }).decision === 'stop';
const held = (event) => { const c = classifyTool(event); return !c.readOnly && outageHolds(c.protected || c.risk === 'high', () => outageRisk({ tool_name: event.tool_name, tool_input: event.tool_input, cwd: proj, truncated: false }, Number.POSITIVE_INFINITY)); };

const WRAPPERS = {
  'bash -c': (f) => `bash -c 'cat ${f}'`, 'sh -c': (f) => `sh -c "cat ${f}"`, eval: (f) => `eval 'cat ${f}'`, 'sudo -n sh -c': (f) => `sudo -n sh -c 'cat ${f}'`, 'env -S': (f) => `env -S 'cat ${f}'`,
  xargs: (f) => `echo ${f} | xargs cat`, 'find -exec': (f) => `find . -maxdepth 1 -name '${f}' -exec cat {} \\;`, ssh: (f) => `ssh localhost 'cat ${f}'`, 'bash -lc': (f) => `bash -lc 'cat ${f}'`,
  nested: (f) => `sh -c "bash -c 'cat ${f}'"`,
};
const SECRET_ROWS = [];
for (const [name, fn] of Object.entries(WRAPPERS)) for (const f of ['.env', '.env.local', '.env.production', '.env.{TOK}']) SECRET_ROWS.push([`${name} ${f}`, bash(fn(f))]);
for (const c of ['true && cat .env.local', 'ls; cat .env.local', 'false || cat .env.local', 'cat .env.local | head -n 2', '(cat .env.local)', '{ cat .env.local; }', 'cat .env.local &', "bash -c 'ls && cat .env.local'",
  'V=.env.local; cat $V', 'cat ${V:-.env.local}', "bash -c 'cat ${V:-.env.local}'", 'cat ${V:-.env.{TOK}}', 'cd sub && cat .env', "bash -c 'cd sub && cat .env'", 'cat link.txt', 'cat innocent.log', "bash -c 'cat link.txt'",
  "eval 'cat innocent.log'", 'cat .e*', 'cat .e?v', "eval 'cat .e*'", 'cat sub/.e*', "bash -c 'cat .env.l*'", 'cat {.env,foo.txt}', 'cat .ENV.LOCAL', "bash -c 'case x in x) cat .env.local;; esac'",
  "bash -c 'for f in .env.local; do cat $f; done'", "bash -c 'cat .npmrc'", "eval 'cat .dev.vars'", "bash -c 'cat .netrc'", "eval 'cat .git-credentials'", "bash -c 'cat ~/.ssh/id_ed25519'", "eval 'cat ~/.aws/credentials'", "bash -c 'echo $GITHUB_TOKEN'", "bash -c 'printenv'"]) SECRET_ROWS.push([c, bash(c)]);
for (const [n, t] of [['Read .env.local', tool('Read', { file_path: '.env.local' })], ['Read link', tool('Read', { file_path: 'link.txt' })], ['Read abs link', tool('Read', { file_path: path.join(proj, 'innocent.log') })],
  ['Grep link', tool('Grep', { pattern: 'K', path: 'link.txt' })], ['Edit link', tool('Edit', { file_path: 'link.txt', old_string: 'a', new_string: 'b' })], ['Monitor bash -c', tool('Monitor', { command: "bash -c 'cat .env.local'" })]]) SECRET_ROWS.push([n, t]);

test('every secret read the seatbelt stops is a protected keyed action and an outage hold', () => {
  const missed = [];
  for (const [name, event] of SECRET_ROWS) {
    const c = classifyTool(event);
    // Two rows the keyless seatbelt itself does not stop on any build (a find -name of a token-shaped name; an upper-case name no file has): keyed only.
    const keylessLimit = /^find -exec \.env\.\{TOK\}$|\.ENV\.LOCAL/.test(name);
    if (!keylessLimit && !keylessStops(event)) missed.push(`keyless does not stop: ${name}`);
    if (!(c.protected === true && c.readOnly === false)) missed.push(`keyed not protected: ${name}`);
    if (!keylessLimit && !held(event)) missed.push(`outage not held: ${name}`);
  }
  assert.deepEqual(missed, []);
  assert.ok(SECRET_ROWS.length >= 80, `rows: ${SECRET_ROWS.length}`);
});

// Ordinary work: the answers are the ones bae9fe16 gave (protected false, read-only where it was), and the mapper is not even asked.
const FRICTION = ['git status', 'npm test', 'ls', 'cat README.md', 'grep -r foo .', 'cat .env.example', 'grep -rn process.env src', 'cat src/index.ts', 'ls -la .env.example', "bash -c 'cat README.md'", "bash -c 'git status'", "sh -c 'ls -la'",
  "eval 'git status'", "sudo -n sh -c 'ls'", "bash -c 'cat .env.example'", "bash -c 'grep -r foo .'", 'echo README.md | xargs cat', "ssh localhost 'ls'", 'docker ps', 'cd sub && ls', 'cat docs/notes.txt', 'ls node_modules/.bin',
  'node_modules/.bin/tool --version', 'git commit -m "document the .env loading"', 'echo "see .env.example"', 'cat src/*.ts', 'echo $HOME', 'grep -n password README.md', 'cat docs/notes.txt | head -n 2', 'mkdir -p build/out', 'cat environment.md'];
const FRICTION_PROTECTED_BEFORE = new Set(['git commit -m "document the .env loading"']);
test('ordinary work keeps its answers: not protected, same read-only flag, nothing held in an outage', () => {
  for (const c of FRICTION) {
    const event = bash(c);
    const out = classifyTool(event);
    assert.equal(out.protected, FRICTION_PROTECTED_BEFORE.has(c), `protected: ${c}`);
    assert.equal(keylessStops(event), false, `keyless: ${c}`);
    if (!FRICTION_PROTECTED_BEFORE.has(c)) assert.equal(held(event), false, `outage: ${c}`);
  }
  for (const [name, event] of [['Read README', tool('Read', { file_path: 'README.md' })], ['Read example', tool('Read', { file_path: '.env.example' })], ['Edit src', tool('Edit', { file_path: 'src/index.ts', old_string: 'a', new_string: 'b' })],
    ['Write src', tool('Write', { file_path: 'src/new.ts', content: 'x' })], ['Grep src', tool('Grep', { pattern: 'foo', path: 'src' })], ['Read src link-free', tool('Read', { file_path: 'src/index.ts' })]]) {
    assert.equal(classifyTool(event).protected, false, name);
  }
  assert.equal(classifyTool(bash('cp .env.example .env')).protected, true, 'a write of .env was protected before and stays so');
});

test('the filter asks the mapper for secret words and spelled names, not for ordinary text', () => {
  for (const c of ["bash -c 'cat .npmrc'", 'cat .e*', "bash -c 'echo $GITHUB_TOKEN'", 'cat ~/.ssh/id_ed25519', 'cat {.env,x}']) assert.equal(mayReadSecret(c), true, c);
  // Not asked: ordinary text, `process.env`, a program that prints a credential (not a file: out of scope), and the two spellings the friction table pins as
  // not protected (a brace-spelled dot word, an ANSI-C quote).
  for (const c of ['git status', 'npm test', 'ls -la', 'cat README.md', 'cat src/*.ts', 'cat ./*.md', 'grep -r foo .', 'echo hello', 'node -p "process.env.NODE_ENV"', "eval 'gh auth token'", "eval 'aws sts get-session-token'", 'cat .en{v,x}', 'cat .{e,x}nv', "cat $'\\x2eenv'"]) assert.equal(mayReadSecret(c), false, c);
});

test('a link is read as what it points at, and an ordinary link is not a stop', () => {
  assert.equal(classifyTool(bash('cat link.txt')).protected, true);
  assert.equal(classifyTool(bash('node_modules/.bin/tool --version')).protected, false);
  assert.equal(classifyTool(tool('Read', { file_path: 'node_modules/.bin/tool' })).protected, false);
  assert.equal(classifyTool(tool('Read', { file_path: 'no-such-file.txt' })).protected, false);
});

test('collisions: a protected read and an ordinary one never share a key; text after a secret-looking name stays in the key; no secret in the normalized action', () => {
  const salt = crypto.randomBytes(32);
  const n = (c) => normalizedHookAction(bash(c), { salt });
  const key = (a) => JSON.stringify([a.programs, a.paths, a.tool_input.command, a.tool_input.command_sha256, a.tool_input.exact_hmac, a.truncated]);
  assert.notEqual(key(n("bash -c 'cat .env.local'")), key(n("bash -c 'cat README.md'")));
  assert.notEqual(key(n("bash -c 'cat .env.local'")), key(n("bash -c 'cat .env.other'")));
  assert.notEqual(key(n(`bash -c 'cat .env.${TOK} && ls'`)), key(n(`bash -c 'cat .env.${TOK} && rm x'`)));
  assert.equal(key(n("bash -c 'cat .env.local'")), key(n("bash -c 'cat .env.local'")));
  for (const c of [`bash -c 'cat .env.${TOK}'`, `eval 'cat .env.${TOK}'`]) {
    const out = JSON.stringify([n(c), classifyTool(bash(c)), keylessStops(bash(c))]);
    assert.equal(out.includes(TOK), false);
    assert.equal(out.includes(TOK.slice(4, 24)), false);
  }
});

// The filter's regular expressions are linear: a 100 KB command built to make a dot-word regular expression backtrack (`a=.b` repeated) took 10 s once. The bound is
// far above what a linear scan needs (a few ms), so machine load cannot trip it.
test('the filter reads a 100 KB command in linear time', () => {
  const started = Date.now();
  for (const unit of ['a=.b', ':.b', 'x;.y', ' .abc', '$a']) assert.equal(typeof mayReadSecret(unit.repeat(Math.ceil(100000 / unit.length))), 'boolean');
  assert.ok(Date.now() - started < 3000, `took ${Date.now() - started} ms`);
  for (const c of ['cat .e*', 'a=.e?v', 'x;.y$Z', 'cat /tmp/.e*']) assert.equal(mayReadSecret(c), true, c);
  for (const c of ['cat README.md', 'cat a.b*', 'cat x/y.z$W', 'cat .en{v,x}']) assert.equal(mayReadSecret(c), false, c);
});

// Rows the keyed policy reads itself keep their answers (the brief's friction list): the pattern or filter operand of grep and jq, `ps` with a pid or a
// command name, an ANSI-C quote and a brace-spelled dot word (test/pre-action-hook.test.js pins both as not protected and is left as it is), a link to an ordinary file.
// The mapper is not asked a second time for a command made only of recognised read-only programs (policyReadsAllWords), and never keeps `ps_environment_loose`.
test('friction: pattern operands, ps, a link to an ordinary file and the two pinned spellings stay not protected', () => {
  for (const c of ['grep .env README.md', "jq '.env' package.json", 'ps -p 1 -o etime', 'ps -C node -o pid=', 'grep .env docs-link.md', 'cat docs-link.md', 'ls -l docs-link.md', 'grep -rn process.env src',
    "bash -c 'ps -p 1 -o etime; cat .env.example'", 'cat .en{v,x}', "cat $'.en\\x76'"]) assert.equal(classifyTool(bash(c)).protected, false, c);
  for (const c of ['grep .env README.md', "jq '.env' package.json", 'cat docs-link.md']) assert.equal(classifyTool(bash(c)).readOnly, true, c);
  assert.equal(policyReadsAllWords('grep .env README.md'), true);
  assert.equal(policyReadsAllWords("jq '.env' package.json | head -n 3"), true);
  for (const c of ["bash -c 'grep .env README.md'", 'cat .e*', 'cat $V', 'cat {a,b}', 'cat $(ls)', 'true && npm install', 'cat > out.txt']) assert.equal(policyReadsAllWords(c), false, c);
});

test('a link in a command the policy reads whole is held only when it points at a secret path', () => {
  assert.equal(classifyTool(bash('cat link.txt')).protected, true);
  assert.equal(classifyTool(bash('grep x innocent.log')).protected, true);
  assert.equal(classifyTool(bash('head -n 2 link.txt | wc -l')).protected, true);
  assert.equal(classifyTool(bash('grep x docs-link.md | wc -l')).protected, false);
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
    input: JSON.stringify({ session_id: 's', cwd: proj, hook_event_name: 'PreToolUse', permission_mode: 'default', tool_name: 'Bash', tool_input: { command: command.split('{TOK}').join(TOK) } }) });
  assert.equal(r.error, undefined);
  assert.equal(`${r.stdout}${r.stderr}`.includes(KEY) || `${r.stdout}${r.stderr}`.includes(TOK), false, 'no secret in hook output');
  let j = null;
  try { j = r.stdout.trim() ? JSON.parse(r.stdout) : null; } catch { j = null; }
  return j?.hookSpecificOutput?.permissionDecision || (r.status === 2 ? 'deny' : 'none');
}
test('the real hook stops the F-A forms in keyed (service answers allow), outage and keyless mode, and leaves ordinary work alone', () => {
  const stops = ["bash -c 'cat .env.local'", "eval 'cat .env.local'", "sudo -n sh -c 'cat .env.local'", "bash -c 'cat .env.{TOK}'", 'cat ${V:-.env.local}', "bash -c 'cat link.txt'", 'cat .e*', "bash -c 'cat .npmrc'"];
  const wrong = [];
  for (const mode of ['keyed', 'outage', 'keyless']) {
    for (const c of stops) if (realHook(mode, c) !== 'deny') wrong.push(`${mode}: ${c}`);
    for (const c of ['git status', 'cat README.md', "bash -c 'cat README.md'", 'grep -rn process.env src']) if (realHook(mode, c) === 'deny' && mode !== 'outage') wrong.push(`friction ${mode}: ${c}`);
  }
  assert.deepEqual(wrong, []);
});
