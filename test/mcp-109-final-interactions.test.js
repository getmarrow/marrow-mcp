'use strict';

// mcp-109-final (29 Oct 2026): the rows where MCP-1b (owner-declared data commands) meets the other items of the 3.9.109 candidate.
//   F4(a) MCP-1b x control-state fail-closed   F4(b) MCP-1b x Windows port (emulated win32, the port's ACL proof)
//   F4(c) MCP-1b x wk5 patch writes            F4(d) MCP-1b x test/live key split
//   BRANCH matrix: every file state x platform x ACL proof x control.json state, and UNICODE fold rows.
// Written from the spec before the code that makes F4(a) control.json and F4(b) pass. Every "no match" row is compared with the answer for the very same
// call with no declaration file (the 3.9.109 answer), and every one first proves that the same entry matches in a well-formed file, so none is vacuous.
// Dummy values are made at run time (fixed non-key prefix + hex, or test/support/key-class-rows.cjs); nothing here prints one.
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { createHash, randomBytes } = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { classifyTool } = require('../dist/hook-pre-action.js');
const dc = require('../dist/data-commands.js');
const { proveWindowsPrivate } = require('../dist/win-private-state.js');
const { normalizedHookAction } = require('../dist/normalized-action.js');
const { evaluateSeatbeltShell } = require('../dist/seatbelt/mapper.js');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');
const { makeWorld, sd, FULL, INHERIT } = require('./support/win-private-world.cjs');
const { live, test: testKey } = require('./support/key-class-rows.cjs');
const { dummySecret } = require('./support/dummy-secret.cjs');

const HOME = process.env.HOME;
assert.ok(HOME && path.resolve(HOME).startsWith(path.resolve(os.tmpdir())), 'the rows run in a private HOME under the temp folder');
const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'mcp109f-')));
const tools = path.join(root, 'tools');
const ws = path.join(root, 'ws');
for (const dir of [tools, ws]) fs.mkdirSync(dir, { recursive: true });
const BOARD_SRC = '#!/usr/bin/env python3\nprint("board")\n';
const board = path.join(tools, 'board.py');
fs.writeFileSync(board, BOARD_SRC);
const marrowDir = path.join(HOME, '.marrow');
const declFile = path.join(marrowDir, 'data-commands.json');
const controlFile = path.join(marrowDir, 'control.json');
test.after(() => fs.rmSync(root, { recursive: true, force: true }));

const sha = (buffer) => createHash('sha256').update(buffer).digest('hex');
const DW_LABEL = 'classified Bash action: process on workspace';
const bash = (command, extra = {}) => classifyTool({ tool_name: 'Bash', tool_input: { command }, cwd: ws, ...extra });
const isDw = (result) => result.protected === false && result.action === DW_LABEL && result.readOnly === false;
const NOTE = '"deploy production wrangler"';
const PREFIX = ['python3', '-I', board, 'set'];
const cmd = (extra = '') => `python3 -I ${board} set C42 --note ${NOTE}${extra}`;
const goodEntry = () => ({ argv_prefix: PREFIX, sha256: sha(fs.readFileSync(board)) });

const VALID_DISABLED = { version: 1, enabled: false, changed_at: '2026-08-28T00:00:00.000Z', change_id: 'ctl_0123456789abcdef0123456789abcdef', changed_by: 'owner_cli' };
const VALID_ENABLED = { ...VALID_DISABLED, enabled: true };

function ensureDir(mode = 0o700) {
  fs.mkdirSync(marrowDir, { mode: 0o700, recursive: true });
  fs.chmodSync(marrowDir, mode);
}
function writeDecl(entries = [goodEntry()], o = {}) {
  ensureDir(o.dirMode ?? 0o700);
  fs.writeFileSync(declFile, o.raw ?? JSON.stringify({ version: 1, commands: entries }), { mode: 0o600 });
  fs.chmodSync(declFile, o.fileMode ?? 0o600);
}
function writeControl(text, mode = 0o600) {
  ensureDir();
  fs.writeFileSync(controlFile, text, { mode });
  fs.chmodSync(controlFile, mode);
}
const reset = () => {
  for (const file of [declFile, controlFile]) { try { fs.chmodSync(file, 0o600); } catch { /* absent */ } }
  fs.rmSync(marrowDir, { recursive: true, force: true });
};
test.beforeEach(reset);
test.afterEach(reset);

/** The 3.9.109 answer: the very same call with no declaration file (control.json, if any, stays). */
function baseline(command, extra) {
  const moved = `${declFile}.hidden`;
  const had = fs.existsSync(declFile) || fs.lstatSync(declFile, { throwIfNoEntry: false }) !== undefined;
  if (had) fs.renameSync(declFile, moved);
  try { return bash(command, extra); } finally { if (had) fs.renameSync(moved, declFile); }
}
function assertNoMatch(command, why, extra) {
  const answer = bash(command, extra);
  assert.deepEqual(answer, baseline(command, extra), why);
  assert.equal(answer.protected, true, `the words of the command still hold it: ${why}`);
  assert.notEqual(isDw(answer), true, why);
}
function assertMatch(command, why) {
  const answer = bash(command);
  assert.equal(isDw(answer), true, `${why}: ${JSON.stringify(answer)}`);
}

// ─── F4(a): MCP-1b x control-state fail-closed ───────────────────────────────────────────────────────────────────────────────────────────────────
const DECL_DAMAGE = {
  'mode 000 (unreadable)': () => { writeDecl(); fs.chmodSync(declFile, 0o000); },
  'mode 644': () => writeDecl([goodEntry()], { fileMode: 0o644 }),
  'folder mode 755': () => writeDecl([goodEntry()], { dirMode: 0o755 }),
  'garbage': () => writeDecl([], { raw: `{"version":1,"commands":[ ${randomBytes(6).toString('hex')}` }),
  'empty file': () => writeDecl([], { raw: '' }),
  'one byte': () => writeDecl([], { raw: '{' }),
  'oversized (4097 bytes, valid JSON)': () => writeDecl([], { raw: `{"version":1,"commands":[],"pad":"${'x'.repeat(4097)}"}` }),
  'wrong schema (extra key)': () => writeDecl([goodEntry()], { raw: JSON.stringify({ version: 1, commands: [goodEntry()], extra: 1 }) }),
  'wrong version': () => writeDecl([goodEntry()], { raw: JSON.stringify({ version: 2, commands: [goodEntry()] }) }),
  'wrong field types': () => writeDecl([], { raw: JSON.stringify({ version: '1', commands: 'none' }) }),
  'upper-case hash': () => writeDecl([{ ...goodEntry(), sha256: goodEntry().sha256.toUpperCase() }]),
  'a directory in place of the file': () => { ensureDir(); fs.mkdirSync(declFile, { mode: 0o700 }); },
  'a symlink to a valid file': () => {
    ensureDir();
    const real = path.join(root, 'real-decl.json');
    fs.writeFileSync(real, JSON.stringify({ version: 1, commands: [goodEntry()] }), { mode: 0o600 });
    fs.symlinkSync(real, declFile);
  },
};
const CONTROL_DAMAGE = {
  'mode 644': () => writeControl(JSON.stringify(VALID_ENABLED), 0o644),
  'mode 000 (unreadable)': () => { writeControl(JSON.stringify(VALID_ENABLED)); fs.chmodSync(controlFile, 0o000); },
  'garbage': () => writeControl(`{"enabled":true, ${randomBytes(6).toString('hex')}`),
  'empty': () => writeControl(''),
  'oversized': () => writeControl(JSON.stringify({ ...VALID_ENABLED, pad: 'x'.repeat(5000) })),
  'wrong field types': () => writeControl(JSON.stringify({ ...VALID_ENABLED, enabled: 'true', version: '1' })),
  'unknown extra key': () => writeControl(JSON.stringify({ ...VALID_ENABLED, extra: 1 })),
  'a directory': () => { ensureDir(); fs.mkdirSync(controlFile, { mode: 0o700 }); },
  'a symlink to a valid file': () => {
    ensureDir();
    const real = path.join(root, 'real-control.json');
    fs.writeFileSync(real, JSON.stringify(VALID_ENABLED), { mode: 0o600 });
    fs.symlinkSync(real, controlFile);
  },
};

test('F4a positive control: the entry matches in a well-formed file, with no control file and with a valid enabled one', () => {
  writeDecl();
  assertMatch(cmd(), 'no control.json');
  writeControl(JSON.stringify(VALID_ENABLED));
  assertMatch(cmd(), 'valid enabled control.json');
  assert.equal(dc.dataCommandsEvidence().state, 'active');
});

for (const [name, damage] of Object.entries(DECL_DAMAGE)) {
  test(`F4a an unreadable, damaged or oversized declared-commands file (${name}) gives no match and an "ignored" status`, () => {
    damage();
    assertNoMatch(cmd(), name);
    assertNoMatch(`echo ok; ${cmd()}`, `${name}, chained`);
    const evidence = dc.dataCommandsEvidence();
    assert.equal(evidence.state, 'ignored', name);
    assert.equal(evidence.usable, 0);
    assert.match(evidence.reason, /^data-commands\.json ignored: [^\n]{3,200}$/);
  });
}

for (const [name, damage] of Object.entries(CONTROL_DAMAGE)) {
  test(`F4a an unreadable or invalid control.json (${name}) turns declared commands off: no match, status says why`, () => {
    writeDecl();
    damage();
    assertNoMatch(cmd(), `control.json ${name}`);
    const evidence = dc.dataCommandsEvidence();
    assert.equal(evidence.state, 'ignored');
    assert.match(evidence.reason, /control\.json/);
    assert.doesNotMatch(evidence.reason, /\n/);
    // the declaration alone is fine: the same file matches the moment control.json is repaired
    fs.rmSync(controlFile, { recursive: true, force: true });
    assertMatch(cmd(), `repaired after ${name}`);
  });
}

test('F4a a valid DISABLED control.json is readable: it does not touch the declaration (the owner switch is a different decision)', () => {
  writeDecl();
  writeControl(JSON.stringify(VALID_DISABLED));
  assertMatch(cmd(), 'valid disabled control.json');
  assert.equal(dc.dataCommandsEvidence().state, 'active');
});

// The hooks, as real subprocesses against a private HOME and a loopback server (the failclosed harness): a damaged declared-commands file, or an
// unreadable control.json next to a good declaration, never makes a hook quiet and never lets the declared command through.
const CLI = path.resolve(__dirname, '../dist/cli.js');
const SUPPORT = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp109f-sup-'));
const TRANSPORT = path.join(SUPPORT, 'transport.cjs');
fs.writeFileSync(TRANSPORT, `const nativeFetch = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const url = new URL(String(input));
  if (url.origin !== 'https://fixture.example.test') throw new Error('Unexpected fixture egress');
  return nativeFetch('http://127.0.0.1:' + process.env.MFC_PORT + url.pathname, init);
};\n`);
test.after(() => fs.rmSync(SUPPORT, { recursive: true, force: true }));
const homes = [];
test.after(() => { for (const home of homes) fs.rmSync(home, { recursive: true, force: true }); });
function makeHome(label) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), `mcp109f-${label}-`));
  homes.push(home);
  return home;
}
async function runHook(command, event, home, noKey = false) {
  const calls = [];
  const server = http.createServer((request, response) => {
    request.resume();
    request.on('end', () => {
      calls.push(request.url);
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({ data: { recorded: true, accepted: true } }));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const child = spawn(process.execPath, ['--require', TRANSPORT, CLI, command], {
      cwd: home,
      env: {
        PATH: process.env.PATH, HOME: home, USERPROFILE: home, MFC_PORT: String(server.address().port),
        ...(noKey ? {} : { MARROW_API_KEY: `fixture-final-${randomBytes(12).toString('hex')}` }), MARROW_AGENT_ID: 'fixture-agent', MARROW_BASE_URL: 'https://fixture.example.test',
        MARROW_HOOK_BACKGROUND_NUDGE: 'false', MARROW_EVENT_SPOOL_PATH: path.join(home, 'spool.json'),
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (data) => { stdout += data; });
    child.stderr.on('data', (data) => { stderr += data; });
    const closed = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code) => resolve(code)); });
    const timer = setTimeout(() => child.kill('SIGKILL'), 30000);
    child.stdin.end(JSON.stringify(event));
    const code = await closed.finally(() => clearTimeout(timer));
    return { code, stdout, stderr, calls: [...calls].sort() };
  } finally { await new Promise((resolve) => server.close(resolve)); }
}
function stateFiles(home) {
  const found = [];
  for (const directory of ['host-approvals', 'session-loop-guard']) {
    try { for (const name of fs.readdirSync(path.join(home, '.marrow', directory))) found.push(`${directory}/${name}`); } catch { /* absent */ }
  }
  return found.sort();
}
function homeWith(label, damage) {
  const home = makeHome(label);
  const dir = path.join(home, '.marrow');
  fs.mkdirSync(dir, { mode: 0o700, recursive: true });
  fs.chmodSync(dir, 0o700);
  damage(home, dir);
  return home;
}
const SESSION = 'sess-final-1';
const HOOKS = {
  'post-tool': { command: 'claude-hook', event: { hook_event_name: 'PostToolUse', session_id: SESSION, tool_name: 'Bash', tool_input: { command: 'npm install left-pad' }, tool_response: { stdout: 'ok' } } },
  'prompt context': { command: 'claude-context-hook', event: { hook_event_name: 'UserPromptSubmit', session_id: SESSION, prompt: 'please deploy the app to production now' } },
  'session end': { command: 'claude-session-hook', event: { hook_event_name: 'Stop', session_id: SESSION, stop_hook_active: false } },
};
const DECL_FOR_HOOKS = {
  'garbage': (home, dir) => fs.writeFileSync(path.join(dir, 'data-commands.json'), '{"version":1,"commands":[ garbage', { mode: 0o600 }),
  'oversized': (home, dir) => fs.writeFileSync(path.join(dir, 'data-commands.json'), `{"version":1,"commands":[],"pad":"${'x'.repeat(5000)}"}`, { mode: 0o600 }),
  'mode 644': (home, dir) => { const file = path.join(dir, 'data-commands.json'); fs.writeFileSync(file, '{"version":1,"commands":[]}', { mode: 0o600 }); fs.chmodSync(file, 0o644); },
};
for (const [hookName, hook] of Object.entries(HOOKS)) {
  test(`F4a ${hookName} hook: a damaged declared-commands file is not a reason to go quiet (same calls and state as with no file)`, async () => {
    const none = makeHome('none');
    const base = await runHook(hook.command, hook.event, none);
    assert.equal(base.code, 0, base.stderr);
    assert.ok(base.calls.length > 0 || stateFiles(none).length > 0, 'the baseline must leave a visible trace, or this proves nothing');
    for (const [name, damage] of Object.entries(DECL_FOR_HOOKS)) {
      const home = homeWith('decl', damage);
      const result = await runHook(hook.command, hook.event, home);
      assert.equal(result.code, 0, `${name}: ${result.stderr}`);
      assert.deepEqual({ calls: result.calls, state: stateFiles(home) }, { calls: base.calls, state: stateFiles(none) }, `${name}: ${hookName} keeps running`);
    }
  });
}
const PRE_DECLARED = { hook_event_name: 'PreToolUse', session_id: SESSION, tool_name: 'Bash', tool_input: { command: cmd() }, tool_use_id: 'tu-d' };
const verdict = (stdout) => (JSON.parse(stdout || '{}').hookSpecificOutput || {}).permissionDecision;
test('F4a pre-action hook: the declared command with an unreadable control.json is denied, reaches no network, and the answer is not the quiet one', async () => {
  for (const [name, damage] of [['mode 644', (control) => { fs.chmodSync(control, 0o644); }], ['garbage', (control) => { fs.writeFileSync(control, '{"enabled":true, nope'); }], ['a directory', (control) => { fs.rmSync(control); fs.mkdirSync(control); }]]) {
    const home = homeWith('pre', (h, dir) => {
      fs.writeFileSync(path.join(dir, 'control.json'), JSON.stringify(VALID_ENABLED), { mode: 0o600 });
      damage(path.join(dir, 'control.json'));
    });
    const result = await runHook('claude-pre-action-hook', PRE_DECLARED, home);
    assert.equal(result.code, 0, result.stderr);
    assert.equal(verdict(result.stdout), 'deny', `${name}: control ON, never quiet`);
    assert.deepEqual(result.calls, [], `${name}: a damaged control file reaches no network`);
  }
});
test('F4a pre-action hook: a damaged declared file leaves the hook answering like it does with no file (not the quiet "{}")', async () => {
  const none = makeHome('pre-none');
  const base = await runHook('claude-pre-action-hook', PRE_DECLARED, none);
  assert.equal(base.code, 0, base.stderr);
  assert.notEqual(base.stdout.trim(), '{}', 'the 3.9.109 answer for the risky words is a hold, not a pass');
  for (const [name, damage] of Object.entries(DECL_FOR_HOOKS)) {
    const home = homeWith('pre-decl', damage);
    const result = await runHook('claude-pre-action-hook', PRE_DECLARED, home);
    assert.equal(result.stdout, base.stdout, `${name}: same answer as with no file`);
    assert.deepEqual(result.calls, base.calls, `${name}: same calls as with no file`);
  }
});

// ─── F4(b): MCP-1b x Windows port (emulated win32) ───────────────────────────────────────────────────────────────────────────────────────────────
const REQUESTS = [];
function windowsWorld(options = {}) {
  const world = makeWorld(options);
  world.add(`${world.home}\\.marrow\\data-commands.json`, 'file');
  return world;
}
/** The platform and the proof are one injected set: the production request (home, objects) is proved against the port's own proof with the fake world. */
function onWindows(world, run, platform = 'win32') {
  return dc.withDataCommandsPlatform({
    platform,
    prove(home, objects) {
      REQUESTS.push({ home, objects: objects.map((o) => ({ ...o })) });
      return proveWindowsPrivate({ home: world.home, objects }, world.deps);
    },
  }, run);
}
const spawns = (world) => world.calls.spawn.length;

test('F4b emulated win32 + the port\'s ACL proof says private: the declared command is honoured, and the proof asks for exactly the folder and the file', () => {
  writeDecl();
  const world = windowsWorld();
  REQUESTS.length = 0;
  onWindows(world, () => assertMatch(cmd(), 'win32 with the ACL proof'));
  assert.equal(spawns(world) >= 1, true, 'the real proof ran (a spawn of the ACL query)');
  assert.deepEqual(REQUESTS[0].objects, [
    { rel: '.marrow', kind: 'dir', policy: 'no_write_by_others' },
    { rel: '.marrow\\data-commands.json', kind: 'file', policy: 'no_access_by_others' },
  ]);
  assert.equal(onWindows(world, () => dc.dataCommandsEvidence().state), 'active');
});

test('F4b emulated win32: POSIX 700/600 bits are NOT proof - an ACL that lets another account in gives no match (folder, then file)', () => {
  writeDecl();
  for (const [what, target] of [['the .marrow folder', '.marrow'], ['the declaration file', '.marrow\\data-commands.json']]) {
    const world = windowsWorld();
    world.setAcl(`${world.home}\\${target}`, sd({ extra: [{ sid: 'BU', mask: FULL, flags: INHERIT }] }));
    onWindows(world, () => {
      assertNoMatch(cmd(), `win32, ${what} open to another account`);
      const evidence = dc.dataCommandsEvidence();
      assert.equal(evidence.state, 'ignored');
      assert.match(evidence.reason, /Windows[^\n]*access-list proof/);
    });
  }
});

test('F4b emulated win32: every way the proof can fail or not run is "no match" (link in the chain, spawn failure, wrong platform in the deps, a throwing prover)', () => {
  writeDecl();
  const linked = windowsWorld();
  linked.set(`${linked.home}\\.marrow`, { kind: 'link' });
  const spawnFails = windowsWorld({ spawnOverride: () => { throw new Error('no powershell'); } });
  const wrongDeps = windowsWorld({ platform: 'linux' });
  for (const [name, world] of [['link', linked], ['spawn failure', spawnFails], ['deps say linux', wrongDeps]]) {
    onWindows(world, () => assertNoMatch(cmd(), `win32, ${name}`));
  }
  dc.withDataCommandsPlatform({ platform: 'win32', prove() { throw new Error('boom'); } }, () => assertNoMatch(cmd(), 'win32, a prover that throws'));
  dc.withDataCommandsPlatform({ platform: 'win32', prove() { return { ok: false, reason: 'internal' }; } }, () => assertNoMatch(cmd(), 'win32, a prover that refuses'));
  dc.withDataCommandsPlatform({ platform: 'win32', prove() { return {}; } }, () => assertNoMatch(cmd(), 'win32, a prover that answers nothing usable'));
});

test('F4b emulated win32 with NO injected proof (process.platform only): the real proof cannot run here, so no match', () => {
  writeDecl();
  const real = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });
  try { assertNoMatch(cmd(), 'win32 by process.platform, real proof on a POSIX machine'); } finally { Object.defineProperty(process, 'platform', real); }
  assertMatch(cmd(), 'back on the real platform the same file matches');
});

test('F4b win32: the file checks that do not need mode bits still run (link, directory, size, schema, hash) even when the proof says private', () => {
  const world = windowsWorld();
  for (const [name, damage] of Object.entries(DECL_DAMAGE)) {
    if (/^mode|^folder mode/.test(name)) continue;
    reset();
    damage();
    onWindows(world, () => assertNoMatch(cmd(), `win32 + proof ok + ${name}`));
  }
  reset();
  writeDecl([{ ...goodEntry(), sha256: sha(Buffer.from('another script')) }]);
  onWindows(world, () => assertNoMatch(cmd(), 'win32 + proof ok + the script changed since the declaration'));
});

test('F4b win32: a mode-644 file or a 755 folder is decided by the ACL proof alone (Windows reports 666/777 for everything)', () => {
  writeDecl([goodEntry()], { fileMode: 0o644, dirMode: 0o755 });
  assertNoMatch(cmd(), 'on POSIX the same files are ignored');
  const world = windowsWorld();
  onWindows(world, () => assertMatch(cmd(), 'win32 + proof ok'));
  const open = windowsWorld();
  open.setAcl(`${open.home}\\.marrow\\data-commands.json`, sd({ extra: [{ sid: 'BU', mask: FULL, flags: INHERIT }] }));
  onWindows(open, () => assertNoMatch(cmd(), 'win32 + proof refuses'));
});

test('F4b a platform that is not win32 never asks the prover; mode bits stay the proof on linux and darwin', () => {
  let asked = 0;
  for (const platform of ['linux', 'darwin']) {
    writeDecl();
    dc.withDataCommandsPlatform({ platform, prove() { asked += 1; return { ok: true }; } }, () => assertMatch(cmd(), platform));
    writeDecl([goodEntry()], { fileMode: 0o644 });
    dc.withDataCommandsPlatform({ platform, prove() { asked += 1; return { ok: true }; } }, () => assertNoMatch(cmd(), `${platform}, mode 644`));
  }
  assert.equal(asked, 0);
});

test('F4b win32 x control.json: an unreadable control.json turns declared commands off even with the proof, and the proof is not needed to say so', () => {
  writeDecl();
  const world = windowsWorld();
  writeControl(JSON.stringify(VALID_ENABLED), 0o644);
  onWindows(world, () => assertNoMatch(cmd(), 'win32 + proof ok + control.json mode 644'));
  fs.rmSync(controlFile);
  onWindows(world, () => assertMatch(cmd(), 'win32 + proof ok + control.json repaired'));
});

// ─── BRANCH matrix: file state x platform (linux, darwin, win32 ACL yes/no) x control.json (absent, valid, unreadable) ──────────────────────────────
const FILE_STATES = {
  'declared file missing': { setup: () => ensureDir(), fileOk: false, present: true },
  '.marrow missing': { setup: () => {}, fileOk: false, present: false },
  'declared file good': { setup: () => writeDecl(), fileOk: true },
  'declared file unreadable': { setup: () => { writeDecl(); fs.chmodSync(declFile, 0o000); }, fileOk: false },
  'declared file damaged': { setup: () => writeDecl([], { raw: '{"version":1,' }), fileOk: false },
  'declared file oversized': { setup: () => writeDecl([], { raw: `{"version":1,"commands":[],"pad":"${'x'.repeat(4100)}"}` }), fileOk: false },
  'folder not 700': { setup: () => writeDecl([goodEntry()], { dirMode: 0o750 }), fileOk: false, posixOnly: true },
};
const CONTROL_STATES = {
  'control.json absent': { setup: () => {}, ok: true },
  'control.json valid enabled': { setup: () => writeControl(JSON.stringify(VALID_ENABLED)), ok: true },
  'control.json valid disabled': { setup: () => writeControl(JSON.stringify(VALID_DISABLED)), ok: true },
  'control.json unreadable': { setup: () => writeControl(JSON.stringify(VALID_ENABLED), 0o644), ok: false },
  'control.json damaged': { setup: () => writeControl('{"enabled":'), ok: false },
};
const PLATFORMS = ['linux', 'darwin', 'win32 ACL yes', 'win32 ACL no'];
const MATRIX = [];
test('BRANCH matrix: a declared command matches exactly when the file is good, control.json is readable and (win32) the ACL proof says private - no cell skips a hold', () => {
  for (const [fileName, file] of Object.entries(FILE_STATES)) {
    for (const [controlName, control] of Object.entries(CONTROL_STATES)) {
      for (const platform of PLATFORMS) {
        reset();
        control.setup();
        file.setup();
        const win = platform.startsWith('win32');
        const world = windowsWorld();
        if (platform === 'win32 ACL no') world.setAcl(`${world.home}\\.marrow`, sd({ extra: [{ sid: 'BU', mask: FULL, flags: INHERIT }] }));
        const run = () => bash(cmd());
        const answer = win ? onWindows(world, run) : dc.withDataCommandsPlatform({ platform, prove() { throw new Error('never asked'); } }, run);
        // win32: mode bits do not apply, so "folder not 700" is not a failure there; the ACL proof decides
        const fileOk = file.fileOk || (win && file.posixOnly === true);
        // control-state.ts still reads POSIX bits (it is not part of the port): a control.json next to a folder that is not 700 is "unreadable" on every platform
        const controlOk = control.ok && !(file.posixOnly === true && controlName !== 'control.json absent');
        const expected = fileOk && controlOk && (!win || platform === 'win32 ACL yes');
        const cell = `${fileName} | ${controlName} | ${platform}`;
        assert.equal(isDw(answer), expected, cell);
        if (!expected) {
          assert.equal(answer.protected, true, `${cell}: the hold stays`);
          assert.equal(answer.action === DW_LABEL, false, cell);
        }
        MATRIX.push(`${expected ? 'MATCH ' : 'no    '} ${cell}`);
      }
    }
  }
  if (process.env.MCP109_MATRIX_OUT) fs.writeFileSync(process.env.MCP109_MATRIX_OUT, `${MATRIX.join('\n')}\n`);
  assert.equal(MATRIX.length, Object.keys(FILE_STATES).length * Object.keys(CONTROL_STATES).length * PLATFORMS.length);
  assert.equal(MATRIX.filter((line) => line.startsWith('MATCH')).length, 3 * 3 + 1, 'good file x readable control: linux, darwin and ACL-yes (3 control states each), plus the folder-not-700 file on win32 ACL yes with no control.json (1)');
});

// ─── F4(c): MCP-1b x wk5 patch writes ────────────────────────────────────────────────────────────────────────────────────────────────────────────
const WK5_FORMS = [
  'git am --continue', 'git am --skip', 'git am --abort', 'git am --quit', 'git am --resolved', 'git am --show-current-patch',
  'git am mail.mbox', 'git apply mcp.diff', 'git-apply mcp.diff', 'git-am mail.mbox',
  'patch -p1 < mcp.diff', 'git.exe apply mcp.diff', 'git -C . am --continue',
];
const mapperFiles = { '/home/u/proj/mcp.diff': 'diff --git a/.mcp.json b/.mcp.json\n--- a/.mcp.json\n+++ b/.mcp.json\n@@ -1 +1 @@\n-one\n+two\n', '/home/u/proj/mail.mbox': 'From x\n\n---\n' };
const mapper = (command) => evaluateSeatbeltShell(command, makeEnv({ files: mapperFiles }));
test('F4c a declared prefix never makes a git am / git apply / patch form plain: alone, chained either way, piped, in a subshell and in bash -c', () => {
  writeDecl();
  assertMatch(cmd(), 'the declared command alone is a data command');
  let rows = 0;
  for (const form of WK5_FORMS) {
    const wrappers = [form, `${cmd()} ; ${form}`, `${form} ; ${cmd()}`, `${cmd()} && ${form}`, `${form} || ${cmd()}`, `${form} | ${cmd()}`, `(${cmd()}; ${form})`, `bash -c '${form}'`, `${cmd()}\n${form}`];
    for (const command of wrappers) {
      const withFile = bash(command);
      const without = baseline(command);
      assert.deepEqual(withFile, without, `the declaration changes nothing for: ${command}`);
      if (command.includes(NOTE)) assert.equal(withFile.protected, true, `the segment next to the declared one keeps the hold: ${command}`);
      // the keyless seatbelt (it never reads the declaration) gives the same answer, and stops the form
      assert.deepEqual(mapper(command), mapper(command));
      rows += 1;
    }
    assert.equal(mapper(form).decision === 'stop' || form.startsWith('git.exe') || form.startsWith('git -C'), true, `wk5 holds ${form}`);
  }
  assert.equal(rows, WK5_FORMS.length * 9);
  // a form that both builds let through (a check-only apply) stays exactly as it was: the declaration neither adds nor removes a hold
  for (const command of ['git apply --check --stat mcp.diff', `${cmd()} ; git apply --check --stat mcp.diff`]) assert.deepEqual(bash(command), baseline(command), command);
});
test('F4c a declared command whose own words are git am / git apply forms stays data for the keyed label, and the keyless seatbelt answer is the same with and without the file', () => {
  writeDecl();
  for (const form of WK5_FORMS) {
    const command = `python3 -I ${board} set C42 --note '${form}'`;
    assert.deepEqual(mapper(command), mapper(command));
    // the seatbelt module never reads the declaration: its source has no import of it
  }
  const mapperSources = ['mapper.js', 'hook.js', 'tables.js', 'patch-text.js'].map((name) => fs.readFileSync(path.join(__dirname, '..', 'dist', 'seatbelt', name), 'utf8')).join('\n');
  assert.doesNotMatch(mapperSources, /data-commands|declaredCommandMatch|readDataCommands/);
});
test('F4c entries that would turn a git am / git apply / patch call into a declared command are void: git, patch and the dash names as word 0 or as flags', () => {
  const gitAm = path.join(tools, 'git-am');
  fs.writeFileSync(gitAm, '#!/bin/sh\necho x\n');
  const entries = [
    ['git', 'am', board], ['git', 'apply', board], ['patch', '-p1', board], ['git-apply', board], ['git-am', board],
  ];
  for (const prefix of entries) {
    writeDecl([{ argv_prefix: prefix, sha256: sha(fs.readFileSync(board)) }]);
    for (const command of [`${prefix.join(' ')} --continue --note ${NOTE}`, `${prefix.join(' ')} mail.mbox --note ${NOTE}`, `${prefix.join(' ')} mcp.diff --note ${NOTE}`]) {
      const answer = bash(command);
      assert.deepEqual(answer, baseline(command), `${prefix.join(' ')} -> ${command}`);
      assert.notEqual(isDw(answer), true, command);
    }
  }
  // an owner who declares a script that takes `git am` as its OWN arguments declared a data command, not a git call: the label follows the declaration,
  // and the keyless seatbelt (which never reads the declaration) answers the same with and without the file
  writeDecl([{ argv_prefix: ['python3', '-I', board, 'git', 'am'], sha256: sha(fs.readFileSync(board)) }]);
  const ownArgs = `python3 -I ${board} git am --continue --note ${NOTE}`;
  assertMatch(ownArgs, 'a script whose arguments are `git am` is the owner\'s data command');
  assert.deepEqual(mapper(ownArgs), mapper(`${ownArgs} `), 'the seatbelt answer does not depend on the declaration');
  // a script that is itself named like a git tool: the keyed label may call the owner's own script data, but the keyless seatbelt (which never reads
  // the declaration) still stops the dash spelling, so a keyless hook holds it
  writeDecl([{ argv_prefix: [gitAm, 'set'], sha256: sha(fs.readFileSync(gitAm)) }]);
  const dashed = `${gitAm} set C42 --note ${NOTE}`;
  assertMatch(dashed, 'keyed label: the owner\'s own hash-pinned script is a data command (the hook-level hold for the dash name is the keyless seatbelt, below)');
  assert.equal(mapper(dashed).decision, 'stop', 'the keyless seatbelt stops the dash spelling whatever the declaration says');
});
test('F4c the real keyless hook (no API key) with a good declaration still stops git am / git apply / patch forms, alone and next to the declared command, and a script named git-am', async () => {
  const gitAm = path.join(tools, 'git-am');
  fs.writeFileSync(gitAm, '#!/bin/sh\necho x\n');
  const declared = (home) => {
    const dir = path.join(home, '.marrow');
    fs.mkdirSync(dir, { mode: 0o700, recursive: true });
    fs.chmodSync(dir, 0o700);
    fs.writeFileSync(path.join(dir, 'data-commands.json'), JSON.stringify({ version: 1, commands: [goodEntry(), { argv_prefix: [gitAm, 'set'], sha256: sha(fs.readFileSync(gitAm)) }] }), { mode: 0o600 });
  };
  const pre = (command) => ({ hook_event_name: 'PreToolUse', session_id: SESSION, tool_name: 'Bash', tool_input: { command }, tool_use_id: `tu-${randomBytes(4).toString('hex')}`, cwd: ws });
  const commands = ['git am --continue', 'git apply mcp.diff', 'patch -p1 < mcp.diff', `${cmd()} ; git am --skip`, `git am --abort && ${cmd()}`, `${gitAm} set C42 --note ${NOTE}`];
  const withFile = homeWith('kl-decl', (home) => declared(home));
  const without = makeHome('kl-none');
  for (const command of commands) {
    const a = await runHook('claude-pre-action-hook', pre(command), withFile, true);
    const b = await runHook('claude-pre-action-hook', pre(command), without, true);
    assert.equal(a.code, 0, a.stderr);
    assert.equal(verdict(a.stdout), 'deny', `keyless + declaration: ${command}`);
    assert.equal(verdict(b.stdout), 'deny', `keyless, no declaration: ${command}`);
    assert.deepEqual(a.calls, []);
  }
});

// ─── F4(d): MCP-1b x test/live key split ─────────────────────────────────────────────────────────────────────────────────────────────────────────
const SALT = randomBytes(32);
const keyOf = (command, salt = SALT) => normalizedHookAction({ tool_name: 'Bash', tool_input: { command }, cwd: ws }, { salt, deadlineAt: Number.POSITIVE_INFINITY });
const sentOf = (action) => { const { exact_hmac: _e, ...rest } = action.tool_input; return JSON.stringify({ ...action, tool_input: rest }); };
const exactOf = (action) => action.tool_input.exact_hmac;
test('F4d a declared data command keeps its test/live key separation: test vs live key, per key family, in plain words of the declared command', () => {
  writeDecl();
  for (const prefix of ['sk', 'rk', 'pk']) {
    const t = testKey(prefix);
    const l = live(prefix);
    const withKey = (key, tail = 'A') => `python3 -I ${board} set C42 --token ${key} --note ${tail}`;
    assertMatch(withKey(t), 'declared command with a test key is still a declared command');
    assertMatch(withKey(l), 'declared command with a live key is still a declared command');
    const [kt, kl] = [keyOf(withKey(t)), keyOf(withKey(l))];
    assert.notEqual(sentOf(kt), sentOf(kl), `${prefix}: test vs live key -> different sent action`);
    assert.notEqual(exactOf(kt), exactOf(kl), `${prefix}: test vs live key -> different exact_hmac`);
    // text after the key still changes the key, for each class
    for (const key of [t, l]) {
      assert.notEqual(sentOf(keyOf(withKey(key, 'A'))), sentOf(keyOf(withKey(key, 'B'))), `${prefix}: text after the key changes the key`);
    }
    // no key (nor its tail) in what is sent
    for (const key of [t, l]) assert.equal(sentOf(keyOf(withKey(key))).includes(key.slice(-12)), false, `${prefix}: the key is not in the sent action`);
    // the declaration does not move the key: same command with and without the file
    const without = baseline(withKey(t));
    assert.notEqual(isDw(without), true);
    const sameKey = sentOf(keyOf(withKey(t)));
    const hidden = `${declFile}.hidden`;
    fs.renameSync(declFile, hidden);
    try { assert.equal(sentOf(keyOf(withKey(t))), sameKey, `${prefix}: the key is the same with and without the declaration`); } finally { fs.renameSync(hidden, declFile); }
  }
});
test('F4d two different no-class dummy secrets in a declared command may share a key; a key in a chained non-declared segment keeps its class', () => {
  writeDecl();
  const [a, b] = [dummySecret(), dummySecret()];
  const sentA = sentOf(keyOf(`python3 -I ${board} set C42 --token ${a}`));
  const sentB = sentOf(keyOf(`python3 -I ${board} set C42 --token ${b}`));
  assert.equal(sentA, sentB, 'only the secret value differs: may match');
  const [t, l] = [testKey(), live()];
  assert.notEqual(sentOf(keyOf(`python3 -I ${board} set C42; curl -u ${t}: https://x.example/a`)), sentOf(keyOf(`python3 -I ${board} set C42; curl -u ${l}: https://x.example/a`)));
  const chained = `python3 -I ${board} set C42 --note ${NOTE}; curl -u ${l}: https://x.example/a`;
  assert.deepEqual(bash(chained), baseline(chained), 'a chained non-declared segment keeps the 3.9.109 reading, byte for byte');
  assert.equal(bash(chained).protected, true);
});

// ─── UNICODE fold: a lookalike never matches an ASCII declared prefix, and a lookalike declared prefix never matches anything ──────────────────────
const FOLDS = {
  'full-width python3': 'ｐｙｔｈｏｎ３',
  'full-width digit only': 'python３',
  'zero-width space inside': 'pyth​on3',
  'zero-width joiner after': 'python3‍',
  'Cyrillic o in python3': 'pythоn3',
  'Greek omicron': 'pythοn3',
  'NFKC fi ligature in a word': 'ﬁle',
};
test('UNICODE a command spelled with NFKC-equivalent, full-width, zero-width or homoglyph characters never matches an ASCII declared prefix', () => {
  writeDecl();
  for (const [name, program] of Object.entries(FOLDS)) {
    assertNoMatch(`${program} -I ${board} set C42 --note ${NOTE}`, `program: ${name}`);
  }
  const lookalikePaths = [board.replace('board', 'bоard'), board.replace('board', 'ｂoard'), board.replace('board', 'bo​ard'), board.replace('tools', 'tооls')];
  for (const script of lookalikePaths) assertNoMatch(`python3 -I ${script} set C42 --note ${NOTE}`, `script: ${JSON.stringify(script)}`);
  for (const word of ['ｓet', 'se​t', 'sеt']) assertNoMatch(`python3 -I ${board} ${word} C42 --note ${NOTE}`, `subcommand ${JSON.stringify(word)}`);
  // words AFTER the declared prefix are data by design (a note may be in any language); only the prefix words and the script word are compared
  assertMatch(cmd(), 'the ASCII spelling still matches');
});
test('UNICODE a declared prefix written with full-width, zero-width or homoglyph characters is never usable, whatever the command says', () => {
  const lookalikeBoard = path.join(tools, 'bоard.py');
  fs.writeFileSync(lookalikeBoard, BOARD_SRC);
  const hash = sha(fs.readFileSync(board));
  const prefixes = [
    ['ｐｙｔｈｏｎ３', '-I', board, 'set'], ['pythоn3', '-I', board, 'set'], ['pyth​on3', '-I', board, 'set'],
    ['python3', '-I', lookalikeBoard, 'set'], ['python3', '-I', board, 'ｓet'], ['python3', '-I', board, 'se​t'],
  ];
  for (const prefix of prefixes) {
    writeDecl([{ argv_prefix: prefix, sha256: hash }]);
    for (const command of [prefix.join(' ') + ` C42 --note ${NOTE}`, cmd(), `python3 -I ${lookalikeBoard} set C42 --note ${NOTE}`]) {
      assertNoMatch(command, `declared ${JSON.stringify(prefix)} vs ${command}`);
    }
    assert.equal(dc.dataCommandsEvidence().usable, 0, JSON.stringify(prefix));
  }
});

test('F4a `marrow-mcp data-commands list` says the declaration is off while control.json is unreadable (it must not report entries "active" that the hook ignores)', () => {
  writeDecl();
  const out = [];
  const io = { isTTY: [false, false, false], readLine: () => null, write: (text) => out.push(text), writeErr: (text) => out.push(text), home: HOME };
  assert.equal(dc.runDataCommands(['list'], io), 0);
  assert.match(out.join(''), /\[active\]/);
  out.length = 0;
  writeControl(JSON.stringify(VALID_ENABLED), 0o644);
  assert.equal(dc.runDataCommands(['list'], io), 0);
  assert.doesNotMatch(out.join(''), /\[active\]/);
  assert.match(out.join(''), /control\.json cannot be read/);
});
