'use strict';

// F14 (29 Oct 2026): when ~/.marrow/control.json exists but cannot be read or is invalid, Marrow's hooks must
// keep working as if control were ON. A valid file that says "disabled" and a missing file keep their behaviour.
// Every hook runs as a real subprocess against a private fake HOME and a loopback server; nothing here touches the
// machine's own ~/.marrow. The API key is a dummy generated at run time (fixed non-key prefix + hex).
const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const CLI = path.resolve(__dirname, '../dist/cli.js');
const FIX = 'npx @getmarrow/install control status';
const VALID_DISABLED = { version: 1, enabled: false, changed_at: '2026-08-28T00:00:00.000Z', change_id: 'ctl_0123456789abcdef0123456789abcdef', changed_by: 'owner_cli' };
const VALID_ENABLED = { ...VALID_DISABLED, enabled: true };
const CANARY = `CANARY-${crypto.randomBytes(8).toString('hex')}`;
const NOT_LIVE_KEY = /(?:^|[^a-z0-9])(?:sk|pk|rk|ghp|xox[a-z])[_-]/i;

const SUPPORT = fs.mkdtempSync(path.join(os.tmpdir(), 'mfc-support-'));
const TRANSPORT = path.join(SUPPORT, 'transport.cjs');
fs.writeFileSync(TRANSPORT, `const nativeFetch = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const url = new URL(String(input));
  if (url.origin !== 'https://fixture.example.test') throw new Error('Unexpected fixture egress');
  return nativeFetch('http://127.0.0.1:' + process.env.MFC_PORT + url.pathname, init);
};\n`);
test.after(() => fs.rmSync(SUPPORT, { recursive: true, force: true }));

const homes = [];
function makeHome(label = 'home') {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), `mfc-${label}-`));
  homes.push(home);
  return home;
}
test.after(() => { for (const home of homes) fs.rmSync(home, { recursive: true, force: true }); });

const controlFile = (home) => path.join(home, '.marrow', 'control.json');
function marrowDir(home) {
  const directory = path.join(home, '.marrow');
  fs.mkdirSync(directory, { mode: 0o700, recursive: true });
  fs.chmodSync(directory, 0o700);
  return directory;
}
function writeRaw(home, text, mode = 0o600) {
  marrowDir(home);
  fs.writeFileSync(controlFile(home), text, { mode });
  fs.chmodSync(controlFile(home), mode);
}
function writeValid(home, value, mode = 0o600) { writeRaw(home, `${JSON.stringify(value)}\n`, mode); }
function elsewhereDisabled(home) {
  const target = path.join(home, 'elsewhere', 'valid-disabled.json');
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  fs.writeFileSync(target, `${JSON.stringify(VALID_DISABLED)}\n`, { mode: 0o600 });
  return target;
}

// Every way the file can exist and still be unreadable or invalid (ACCEPTANCE F1).
const DAMAGE = {
  'permission-denied': (home) => { writeValid(home, VALID_DISABLED); fs.chmodSync(controlFile(home), 0o000); },
  'corrupt-json': (home) => writeRaw(home, `{"enabled":false, ${CANARY}`),
  'wrong-field-types': (home) => writeRaw(home, `${JSON.stringify({ ...VALID_DISABLED, enabled: 'false', version: '1' })}\n`),
  'unknown-extra-key': (home) => writeRaw(home, `${JSON.stringify({ ...VALID_DISABLED, extra: CANARY })}\n`),
  'empty-file': (home) => writeRaw(home, ''),
  'oversized': (home) => writeRaw(home, `${JSON.stringify({ ...VALID_DISABLED, pad: 'x'.repeat(5000) })}\n`),
  'a-directory': (home) => { marrowDir(home); fs.mkdirSync(controlFile(home), { mode: 0o700 }); },
  'symlink-to-valid-disabled-elsewhere': (home) => { marrowDir(home); fs.symlinkSync(elsewhereDisabled(home), controlFile(home)); },
  'dangling-symlink': (home) => { marrowDir(home); fs.symlinkSync(path.join(home, 'nowhere.json'), controlFile(home)); },
  'valid-disabled-but-group-readable': (home) => writeValid(home, VALID_DISABLED, 0o644),
};

function dummyKey() {
  const key = `fixture-failclosed-${crypto.randomBytes(12).toString('hex')}`;
  assert.doesNotMatch(key, NOT_LIVE_KEY);
  return key;
}

async function runHook(command, event, home, extraEnv = {}, extraArgs = []) {
  const calls = [];
  const server = http.createServer((request, response) => {
    let body = '';
    request.on('data', (chunk) => { body += chunk; });
    request.on('end', () => {
      calls.push(request.url);
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({ data: { recorded: true, accepted: true } }));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const child = spawn(process.execPath, ['--require', TRANSPORT, CLI, command, ...extraArgs], {
      cwd: home,
      env: {
        PATH: process.env.PATH, HOME: home, USERPROFILE: home, MFC_PORT: String(server.address().port),
        MARROW_API_KEY: dummyKey(), MARROW_AGENT_ID: 'fixture-agent', MARROW_BASE_URL: 'https://fixture.example.test',
        MARROW_HOOK_BACKGROUND_NUDGE: 'false', MARROW_EVENT_SPOOL_PATH: path.join(home, 'spool.json'),
        ...extraEnv,
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (data) => { stdout += data; });
    child.stderr.on('data', (data) => { stderr += data; });
    const closed = new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (code) => resolve(code)); });
    const timer = setTimeout(() => child.kill('SIGKILL'), 30000);
    child.stdin.end(typeof event === 'string' ? event : JSON.stringify(event));
    const code = await closed.finally(() => clearTimeout(timer));
    return { code, stdout, stderr, calls: [...calls].sort() };
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

// What a hook visibly did: the server calls it made and the local state files it wrote (control files excluded).
function stateFiles(home) {
  const found = [];
  for (const directory of ['host-approvals', 'session-loop-guard']) {
    const base = path.join(home, '.marrow', directory);
    try { for (const name of fs.readdirSync(base)) found.push(`${directory}/${name}`); } catch { /* absent */ }
  }
  return found.sort();
}
const signature = (result, home) => ({ calls: result.calls, state: stateFiles(home) });

const SESSION = 'sess-failclosed-1';
const HOOKS = {
  'post-tool (claude-hook)': { command: 'claude-hook', event: { hook_event_name: 'PostToolUse', session_id: SESSION, tool_name: 'Bash', tool_input: { command: 'npm install left-pad' }, tool_response: { stdout: 'ok', exit_code: 0 }, tool_use_id: 'tu-1' } },
  'prompt context (claude-context-hook)': { command: 'claude-context-hook', event: { hook_event_name: 'UserPromptSubmit', session_id: SESSION, prompt: 'please deploy the app to production now' } },
  'session end (claude-session-hook)': { command: 'claude-session-hook', event: { hook_event_name: 'Stop', session_id: SESSION, stop_hook_active: false } },
  'permission marker (claude-permission-request-hook)': { command: 'claude-permission-request-hook', event: { hook_event_name: 'PermissionRequest', session_id: SESSION, tool_name: 'Bash', tool_input: { command: 'npm install left-pad' } } },
};

async function baselineSignature(hook) {
  const home = makeHome('on');
  const result = await runHook(hook.command, hook.event, home);
  assert.equal(result.code, 0, result.stderr);
  const sig = signature(result, home);
  assert.ok(sig.calls.length > 0 || sig.state.length > 0, 'the control-ON baseline must leave a visible trace, or this test proves nothing');
  return sig;
}

// ---------------------------------------------------------------- F1: unreadable == control ON
for (const [hookName, hook] of Object.entries(HOOKS)) {
  test(`F1 ${hookName}: every unreadable or invalid control file behaves like control ON`, async () => {
    const baseline = await baselineSignature(hook);
    for (const [damageName, damage] of Object.entries(DAMAGE)) {
      const home = makeHome(`f1-${damageName.slice(0, 8)}`);
      damage(home);
      const result = await runHook(hook.command, hook.event, home);
      assert.equal(result.code, 0, `${damageName}: ${result.stderr}`);
      assert.deepEqual(signature(result, home), baseline, `${damageName}: ${hookName} must keep checking as if control were on`);
    }
  });
}

test('F1 post-tool on Gemini: an unreadable file keeps checking and the host still gets exactly one {}', async () => {
  const event = { hook_event_name: 'AfterTool', session_id: SESSION, tool_name: 'run_shell_command', tool_input: { command: 'npm install left-pad' }, tool_response: { llmContent: 'ok' } };
  const on = makeHome('gem-on');
  const baseline = await runHook('gemini-hook', event, on);
  assert.equal(baseline.stdout, '{}');
  assert.ok(baseline.calls.length > 0, 'the ON baseline must leave a trace');
  const off = makeHome('gem-off');
  writeValid(off, VALID_DISABLED);
  const disabled = await runHook('gemini-hook', event, off);
  assert.equal(disabled.stdout, '{}', 'disabled still prints one {}');
  assert.deepEqual(disabled.calls, []);
  for (const [name, damage] of Object.entries(DAMAGE)) {
    const home = makeHome('gem-bad');
    damage(home);
    const result = await runHook('gemini-hook', event, home);
    assert.equal(result.stdout, '{}', `${name}: exactly one {}`);
    assert.deepEqual(result.calls, baseline.calls, `${name}: keeps checking as if control were on`);
  }
});

// ---------------------------------------------------------------- F2: disabled file and missing file keep today's behaviour
for (const [hookName, hook] of Object.entries(HOOKS)) {
  test(`F2 ${hookName}: a valid disabled file does nothing; a missing file and a valid enabled file act like ON`, async () => {
    const baseline = await baselineSignature(hook);
    const disabled = makeHome('f2-disabled');
    writeValid(disabled, VALID_DISABLED);
    const off = await runHook(hook.command, hook.event, disabled);
    assert.equal(off.code, 0, off.stderr);
    assert.deepEqual(signature(off, disabled), { calls: [], state: [] }, 'a valid disabled file still turns the hook off');
    assert.equal(off.stdout, hook.command === 'claude-context-hook' ? '{}' : '', 'disabled output is byte for byte the old one');

    const enabled = makeHome('f2-enabled');
    writeValid(enabled, VALID_ENABLED);
    const on = await runHook(hook.command, hook.event, enabled);
    assert.deepEqual(signature(on, enabled), baseline, 'a valid enabled file acts like a missing one');
    assert.doesNotMatch(on.stdout, /control file|control status/, 'a readable file prints no notice');
  });
}

// ---------------------------------------------------------------- F1 (pre-action): already closed on BASE, pinned here
const PRE_READ = { hook_event_name: 'PreToolUse', session_id: SESSION, tool_name: 'Read', tool_input: { file_path: 'README.md' }, tool_use_id: 'tu-r' };
const PRE_PUSH = { hook_event_name: 'PreToolUse', session_id: SESSION, tool_name: 'Bash', tool_input: { command: 'git push --force origin main' }, tool_use_id: 'tu-b' };
function decision(stdout) {
  const parsed = JSON.parse(stdout);
  return parsed.hookSpecificOutput || {};
}

test('F1 pre-action: an unreadable control file denies every action, never allows (BASE behaviour pinned)', async () => {
  for (const [damageName, damage] of Object.entries(DAMAGE)) {
    for (const event of [PRE_READ, PRE_PUSH]) {
      const home = makeHome('f1pre');
      damage(home);
      const result = await runHook('claude-pre-action-hook', event, home);
      assert.equal(result.code, 0, result.stderr);
      assert.equal(decision(result.stdout).permissionDecision, 'deny', `${damageName} ${event.tool_name}`);
      assert.deepEqual(result.calls, [], `${damageName}: a damaged control file reaches no network`);
    }
  }
});

test('F2 pre-action: a valid disabled file still allows; a missing file still allows a read', async () => {
  const disabled = makeHome('f2pre-d');
  writeValid(disabled, VALID_DISABLED);
  for (const event of [PRE_READ, PRE_PUSH]) {
    const result = await runHook('claude-pre-action-hook', event, disabled);
    assert.equal(result.stdout, '{}');
  }
  const missing = makeHome('f2pre-m');
  const read = await runHook('claude-pre-action-hook', PRE_READ, missing);
  assert.equal(read.stdout, '{}');
  assert.deepEqual(read.calls, []);
  const push = await runHook('claude-pre-action-hook', PRE_PUSH, missing);
  assert.equal(decision(push.stdout).permissionDecision, 'deny', 'with control ON a force push to main is still held');
  assert.deepEqual(push.calls, ['/v1/agent/integrations/events', '/v1/agent/runtime']);
});

// ---------------------------------------------------------------- F3: one plain notice per session
function notice(stdout) {
  const parsed = JSON.parse(stdout || '{}');
  return typeof parsed.systemMessage === 'string' ? parsed.systemMessage : typeof parsed.user_message === 'string' ? parsed.user_message : '';
}
const PROMPT = (session) => ({ hook_event_name: 'UserPromptSubmit', session_id: session, prompt: 'hello there' });

test('F3 context hook: one plain notice per session names the file and the fix, and never prints its contents', async () => {
  const home = makeHome('f3');
  DAMAGE['corrupt-json'](home);
  const first = await runHook('claude-context-hook', PROMPT('sess-a'), home);
  const text = notice(first.stdout);
  assert.ok(text.includes(controlFile(home)), `notice names the file path: ${text}`);
  assert.ok(text.includes(FIX), 'notice names the fix');
  assert.ok(!/[\u0000-\u0008\u000b-\u001f\u007f]/.test(text), 'plain text');
  assert.ok(text.length <= 500, 'short');
  const second = await runHook('claude-context-hook', PROMPT('sess-a'), home);
  assert.equal(notice(second.stdout), '', 'the same session is told once');
  const other = await runHook('claude-context-hook', PROMPT('sess-b'), home);
  assert.ok(notice(other.stdout).includes(FIX), 'a new session is told again');
  for (const result of [first, second, other]) {
    assert.ok(!result.stdout.includes(CANARY) && !result.stderr.includes(CANARY), 'file contents are never printed');
  }
});

test('F3 context hook: no notice for a readable file (missing, enabled) and none for a valid disabled file', async () => {
  const missing = makeHome('f3-m');
  assert.equal(notice((await runHook('claude-context-hook', PROMPT('s'), missing)).stdout), '');
  const enabled = makeHome('f3-e');
  writeValid(enabled, VALID_ENABLED);
  assert.equal(notice((await runHook('claude-context-hook', PROMPT('s'), enabled)).stdout), '');
  const disabled = makeHome('f3-d');
  writeValid(disabled, VALID_DISABLED);
  assert.equal((await runHook('claude-context-hook', PROMPT('s'), disabled)).stdout, '{}');
});

test('F3 context hook: the Cursor and Gemini prompt hooks carry the same notice in their own fields', async () => {
  const cursorHome = makeHome('f3-cursor');
  DAMAGE['empty-file'](cursorHome);
  const cursor = await runHook('cursor-context-hook', { hook_event_name: 'beforeSubmitPrompt', conversation_id: 'conv-1', prompt: 'hello' }, cursorHome);
  const cursorOut = JSON.parse(cursor.stdout);
  assert.equal(cursorOut.continue, true);
  assert.ok(String(cursorOut.user_message).includes(FIX) && String(cursorOut.user_message).includes(controlFile(cursorHome)));
  const geminiHome = makeHome('f3-gemini');
  DAMAGE['empty-file'](geminiHome);
  const gemini = await runHook('gemini-context-hook', { hook_event_name: 'BeforeAgent', session_id: 'gem-1', prompt: 'hello' }, geminiHome);
  assert.ok(String(JSON.parse(gemini.stdout).systemMessage).includes(FIX));
});

test('F3 pre-action: the deny reason names the file and the fix and never prints contents', async () => {
  const home = makeHome('f3pre');
  DAMAGE['corrupt-json'](home);
  for (const event of [PRE_READ, PRE_PUSH]) {
    const result = await runHook('claude-pre-action-hook', event, home);
    const reason = String(decision(result.stdout).permissionDecisionReason);
    assert.match(reason, /local control state is unsafe/i, 'the old wording stays');
    assert.ok(reason.includes(controlFile(home)), reason);
    assert.ok(reason.includes(FIX), reason);
    assert.ok(!result.stdout.includes(CANARY) && !result.stderr.includes(CANARY));
  }
});

test('F3 context hook: the Codex and Grok prompt hooks carry the notice as a user-only systemMessage', async () => {
  for (const command of ['codex-context-hook', 'grok-context-hook']) {
    const home = makeHome('f3-codex-grok');
    DAMAGE['wrong-field-types'](home);
    const result = await runHook(command, PROMPT(`${command}-s`), home);
    const parsed = JSON.parse(result.stdout);
    assert.ok(String(parsed.systemMessage).includes(FIX) && String(parsed.systemMessage).includes(controlFile(home)), `${command}: ${result.stdout}`);
    assert.ok(!result.stdout.includes('"wrong'), 'no file content');
  }
});

// What every host's pre-action hook answers when the file is unreadable: the host's own deny shape, never an allow.
const HOST_PRE_ACTION = {
  'claude-pre-action-hook': { event: { hook_event_name: 'PreToolUse', session_id: 's1', tool_name: 'Bash', tool_input: { command: 'ls' }, tool_use_id: 't1' }, denied: (o) => o.hookSpecificOutput.permissionDecision === 'deny', carriesFix: true },
  'codex-pre-action-hook': { event: { hook_event_name: 'PreToolUse', session_id: 's1', tool_name: 'Bash', tool_input: { command: 'ls' }, tool_use_id: 't1' }, denied: (o) => o.hookSpecificOutput.permissionDecision === 'deny', carriesFix: true },
  'grok-pre-action-hook': { event: { hook_event_name: 'PreToolUse', session_id: 's1', tool_name: 'Bash', tool_input: { command: 'ls' }, tool_use_id: 't1' }, denied: (o) => o.decision === 'deny', carriesFix: false },
  'gemini-pre-action-hook': { event: { hook_event_name: 'BeforeTool', session_id: 's1', tool_name: 'run_shell_command', tool_input: { command: 'ls' } }, denied: (o) => o.decision === 'deny', carriesFix: false },
  'cursor-pre-action-hook': { event: { hook_event_name: 'preToolUse', conversation_id: 'c1', tool_name: 'Shell', tool_input: { command: 'ls' }, tool_use_id: 't1' }, denied: (o) => o.permission === 'deny', carriesFix: true },
  'cline-pre-action-hook': { event: { hookName: 'PreToolUse', taskId: 'k1', preToolUse: { toolName: 'execute_command', parameters: { command: 'ls' } } }, denied: (o) => o.cancel === true, carriesFix: false },
};
test('F1 pre-action on every host: an unreadable control file answers with that host\'s deny shape (hosts with fixed deny texts keep them)', async () => {
  for (const [command, spec] of Object.entries(HOST_PRE_ACTION)) {
    const home = makeHome('f1hosts');
    DAMAGE['permission-denied'](home);
    const result = await runHook(command, spec.event, home);
    assert.equal(result.code, 0, `${command}: ${result.stderr}`);
    assert.ok(spec.denied(JSON.parse(result.stdout)), `${command}: ${result.stdout}`);
    assert.equal(result.stdout.includes(FIX), spec.carriesFix, `${command}: fix text ${spec.carriesFix ? 'expected' : 'unchanged (fixed host text)'}`);
    assert.deepEqual(result.calls, [], `${command}: no network`);
  }
  const home = makeHome('f1windsurf');
  DAMAGE['permission-denied'](home);
  const windsurf = await runHook('windsurf-pre-action-hook', { agent_action_name: 'pre_run_command', trajectory_id: 'w1', tool_info: { command_line: 'ls', cwd: '/tmp' } }, home);
  assert.equal(windsurf.code, 2, 'Windsurf blocks with exit code 2');
});

// ---------------------------------------------------------------- F3 unit: the marker
test('F3 marker: claims once per session, stores no session id, uses owner-only files, stays bounded', () => {
  const { claimUnreadableControlNotice, unreadableControlNotice } = require('../dist/control-notice.js');
  const home = makeHome('marker');
  marrowDir(home);
  assert.equal(claimUnreadableControlNotice('claude-code:s1', home), true);
  assert.equal(claimUnreadableControlNotice('claude-code:s1', home), false);
  assert.equal(claimUnreadableControlNotice('claude-code:s2', home), true);
  const directory = path.join(home, '.marrow', 'control-notice');
  assert.equal(fs.statSync(directory).mode & 0o777, 0o700);
  const names = fs.readdirSync(directory);
  assert.equal(names.length, 2);
  for (const name of names) {
    assert.match(name, /^[a-f0-9]{32}$/);
    assert.equal(fs.statSync(path.join(directory, name)).mode & 0o777, 0o600);
  }
  for (let index = 0; index < 260; index += 1) claimUnreadableControlNotice(`claude-code:bulk-${index}`, home);
  assert.ok(fs.readdirSync(directory).length <= 200, 'old markers are pruned');
  // Keys that differ anywhere get different markers; the same key is one marker.
  const pairs = [['claude-code:s1', 'codex:s1'], ['claude-code:s1', 'claude-code:s1 '], ['claude-code:s1', 'claude-code:S1'], ['claude-code:a:b', 'claude-code:a'], ['claude-code:', 'claude-code:\u0000']];
  for (const [left, right] of pairs) {
    const collisionHome = makeHome('marker-collide');
    marrowDir(collisionHome);
    assert.equal(claimUnreadableControlNotice(left, collisionHome), true, left);
    assert.equal(claimUnreadableControlNotice(right, collisionHome), true, `${right} must not be mistaken for ${left}`);
    assert.equal(claimUnreadableControlNotice(left, collisionHome), false, left);
  }
  const odd = path.join(home, 'a\nb\u0007c');
  const text = unreadableControlNotice(odd);
  assert.ok(!/[\u0000-\u001f\u007f]/.test(text), 'control characters in the path are neutralised');
  assert.ok(text.includes(FIX));
});

test('F3 marker: a symlinked ~/.marrow is never written through; the notice then shows every time', () => {
  const { claimUnreadableControlNotice } = require('../dist/control-notice.js');
  const home = makeHome('marker-link');
  const outside = makeHome('marker-outside');
  fs.symlinkSync(outside, path.join(home, '.marrow'));
  assert.equal(claimUnreadableControlNotice('claude-code:s1', home), true);
  assert.equal(claimUnreadableControlNotice('claude-code:s1', home), true);
  assert.deepEqual(fs.readdirSync(outside), [], 'nothing is created through the link');
  const missingHome = makeHome('marker-missing');
  assert.equal(claimUnreadableControlNotice('claude-code:s1', missingHome), true);
  assert.equal(fs.existsSync(path.join(missingHome, '.marrow')), false, 'a notice never creates ~/.marrow');
});

// ---------------------------------------------------------------- F4: an agent that damages the file cannot turn checks off
const TARGET = '"$HOME/.marrow/control.json"';
const ACTIONS = {
  'chmod 000': `chmod 000 ${TARGET}`,
  'truncate': `: > ${TARGET}`,
  'write garbage': `printf 'garbage{' > ${TARGET}`,
  'swap for a symlink to a valid disabled file': `ln -sf "$HOME/elsewhere/valid-disabled.json" ${TARGET}`,
};
const CHAINS = {
  '&&': (action) => `true && ${action}`,
  ';': (action) => `true; ${action}`,
  '||': (action) => `false || ${action}`,
  'pipe': (action) => `echo x | { ${action}; }`,
  'subshell': (action) => `( ${action} )`,
  'bash -c': (action) => `bash -c '${action.replace(/'/g, "'\\''")}'`,
};

test('F4 abuse: chmod, truncate, garbage and symlink swap, plain or chained, never turn the post-tool hook off', async () => {
  const baseline = await baselineSignature(HOOKS['post-tool (claude-hook)']);
  const combos = [];
  for (const [actionName, action] of Object.entries(ACTIONS)) {
    combos.push([actionName, 'plain', action]);
    for (const [chainName, chain] of Object.entries(CHAINS)) combos.push([actionName, chainName, chain(action)]);
  }
  const { readLocalControlState } = require('../dist/control-state.js');
  for (let start = 0; start < combos.length; start += 7) {
    // allSettled: a failing combination must not leave its siblings running after the test has ended.
    const settled = await Promise.allSettled(combos.slice(start, start + 7).map(async ([actionName, chainName, command]) => {
      const home = makeHome('f4');
      writeValid(home, VALID_ENABLED);
      elsewhereDisabled(home);
      const shell = spawnSync('sh', ['-c', command], { env: { PATH: process.env.PATH, HOME: home }, encoding: 'utf8' });
      assert.equal(shell.status, 0, `${actionName} / ${chainName}: ${shell.stderr}`);
      assert.throws(() => readLocalControlState({ home }), /unsafe/, `${actionName} / ${chainName}: the damage must have landed`);
      const result = await runHook('claude-hook', HOOKS['post-tool (claude-hook)'].event, home);
      assert.deepEqual(signature(result, home), baseline, `${actionName} / ${chainName} must not switch checks off`);
      const pre = await runHook('claude-pre-action-hook', PRE_PUSH, home);
      assert.equal(decision(pre.stdout).permissionDecision, 'deny', `${actionName} / ${chainName}: the pre-action hook stays closed`);
    }));
    const failure = settled.find((entry) => entry.status === 'rejected');
    if (failure) throw failure.reason;
  }
});

test('F4 abuse: a damaged ~/.marrow directory (symlink, group-writable) is not a way to turn checks off', async () => {
  const baselineHome = makeHome('f4dir-on');
  const baseline = await runHook('claude-hook', HOOKS['post-tool (claude-hook)'].event, baselineHome);
  assert.ok(baseline.calls.length > 0);
  const linked = makeHome('f4dir-link');
  const outside = makeHome('f4dir-out');
  fs.mkdirSync(path.join(outside, 'real'), { mode: 0o700 });
  fs.writeFileSync(path.join(outside, 'real', 'control.json'), `${JSON.stringify(VALID_DISABLED)}\n`, { mode: 0o600 });
  fs.symlinkSync(path.join(outside, 'real'), path.join(linked, '.marrow'));
  const writable = makeHome('f4dir-open');
  writeValid(writable, VALID_DISABLED);
  fs.chmodSync(path.join(writable, '.marrow'), 0o770);
  for (const home of [linked, writable]) {
    const pre = await runHook('claude-pre-action-hook', PRE_PUSH, home);
    assert.equal(decision(pre.stdout).permissionDecision, 'deny');
    const post = await runHook('claude-hook', HOOKS['post-tool (claude-hook)'].event, home);
    assert.ok(post.calls.includes('/v1/agent/integrations/events'), 'the post-tool hook still records');
    const prompt = await runHook('claude-context-hook', PROMPT('dir-damage'), home);
    assert.ok(notice(prompt.stdout).includes(FIX), 'and the person is told once');
  }
});

test('F4 abuse: words in the path or the environment do not decide anything; unknown hook flags change nothing', async () => {
  const baseline = await baselineSignature(HOOKS['post-tool (claude-hook)']);
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'mfc-enabled-false-disabled-control-off-'));
  homes.push(home);
  DAMAGE['corrupt-json'](home);
  const plain = await runHook('claude-hook', HOOKS['post-tool (claude-hook)'].event, home);
  assert.deepEqual(signature(plain, home), baseline);
  const withVariables = await runHook('claude-hook', HOOKS['post-tool (claude-hook)'].event, home, { MARROW_CONTROL: 'disabled', MARROW_CONTROL_ENABLED: 'false', MARROW_LOCAL_CONTROL: 'off' });
  assert.deepEqual(signature(withVariables, home), baseline, 'no environment variable stands in for the file');
  const unknownFlags = await runHook('claude-hook', HOOKS['post-tool (claude-hook)'].event, home, {}, ['--control=off', '--enabled=false', '--enabled=true', '--unknown-flag']);
  assert.deepEqual(signature(unknownFlags, home), baseline, 'repeated and unknown flags change nothing');
});
