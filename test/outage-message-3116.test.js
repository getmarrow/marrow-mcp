'use strict';

// A4 (pack row 22 of MCP 3.9.116): the hook says truthfully whether Marrow is slow or unavailable, what is held and
// when to retry. Text only: every decision, exit code and output shape stays as published 3.9.115 (d3dea44c4b21).
// Every host entrypoint runs as a real process (dist/cli.js), with real event JSON on stdin, a throwaway HOME, a dummy
// key generated here and a self-signed https loopback generated here (unreachable = a closed port, 5xx, slow = no
// answer, 4xx, success). Every server body is forged and full of marker strings that must never reach any output.
// Rows: T1-T10, AB1-AB7, COL and DEF of the build SPEC (SPEC-bld-mcp3116-outage, section OUTAGE27).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const https = require('node:https');
const net = require('node:net');
const path = require('node:path');
const crypto = require('node:crypto');
const { tmpdir } = require('node:os');
const { execFileSync, spawn } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
// Test-only preload: SBT_HOOK_DEADLINE=roomy moves the short host deadlines 30 s out, so a loaded run never overruns them.
const PRELOAD = path.join(__dirname, 'support', 'seatbelt-hook-preload.cjs');
const contract = require('../dist/hook-contract.js');
const pre = require('../dist/hook-pre-action.js');
const { HELD_UNREACHABLE_TEXT } = require('../dist/host-approval.js');
const { ownerLockedRuntime, fixture } = require('./support/first-hour-harness.cjs');

// The four texts, byte-exact from the signed design (SPEC-a4-outage-message-20261118.md, change item 2).
const OUTAGE = 'Marrow is unavailable (no connection or a server error). This action runs. High-risk actions are held until Marrow answers; try them again then. The record stays queued locally and is sent when Marrow answers.';
const SLOW = 'Marrow did not answer within this hook\'s time limit. This action runs. High-risk actions are held until Marrow answers in time; try them again in a moment.';
const HELD_SLOW = 'Marrow did not answer within this hook\'s time limit, so this action is held: it needs Marrow\'s answer before it runs. Retry it in a moment.';
const HELD_OFFLINE = 'Marrow is unavailable (no connection or a server error), so this high-risk action is held: it needs Marrow\'s answer before it runs. Routine actions keep running. Retry it when Marrow answers.';
// Unchanged by this row (src/host-approval.ts).
const UNREACHABLE = 'Marrow could not confirm the owner\'s approval; this action stays held. Retry when Marrow is reachable.';
const RUNS_TEXTS = [OUTAGE, SLOW];
const HELD_TEXTS = [HELD_SLOW, HELD_OFFLINE, UNREACHABLE];
// 3.9.115 texts: none may be printed by this version.
const OLD_TEXTS = [
  'Marrow is offline. This action is allowed. The record stays queued locally and is sent when Marrow is back.',
  'Marrow did not answer in time, so this action is held. Retry it in a moment.',
  'Marrow cannot be reached right now, so this high-risk action is held; routine actions keep running. Retry it when Marrow is back.',
];

const SHAPES = {
  claude: (c, cwd) => ({ hook_event_name: 'PreToolUse', session_id: 'o-claude', tool_use_id: 't1', tool_name: 'Bash', tool_input: { command: c }, cwd }),
  codex: (c, cwd) => ({ hook_event_name: 'PreToolUse', session_id: 'o-codex', turn_id: 't1', tool_use_id: 't1', tool_name: 'Bash', tool_input: { command: c }, cwd }),
  cursor: (c, cwd) => ({ hook_event_name: 'beforeShellExecution', conversation_id: 'o-cursor', generation_id: 'g1', command: c, cwd }),
  gemini: (c, cwd) => ({ session_id: 'o-gemini', hook_event_name: 'BeforeTool', tool_name: 'run_shell_command', tool_input: { command: c }, cwd }),
  grok: (c, cwd) => ({ hookEventName: 'PreToolUse', sessionId: 'o-grok', toolUseId: 't', toolName: 'run_terminal_command', toolInput: { command: c }, cwd }),
  cline: (c, cwd) => ({ hookName: 'PreToolUse', taskId: 'o-cline', workspaceRoots: [cwd], preToolUse: { toolName: 'execute_command', parameters: { command: c } } }),
  windsurf: (c, cwd) => ({ agent_action_name: 'pre_run_command', trajectory_id: 'o-windsurf', execution_id: 'e1', tool_info: { command_line: c, cwd } }),
};
// 'grok-guard' = the Grok rows through the guard script setup writes (GROK_PRE_ACTION_GUARD_COMMAND).
const HOSTS = [...Object.keys(SHAPES), 'grok-guard'];
// Hosts whose hold answer carries the held text (Gemini and Grok deny with their own fixed texts, as 3.9.115).
const HELD_TEXT_HOSTS = ['claude', 'codex', 'cursor', 'cline', 'windsurf'];
const ROUTINE = 'mkdir -p build/out';
const HIGH = 'git push --force origin main';
const PROTECTED = 'npm publish';

// AB1: every forged body carries marker strings, a forged `slow`/`outage` field, ANSI and newline bytes.
const MARKER = 'ZQMARKER';
const forged = (status) => JSON.stringify({
  error: { code: `${MARKER} bad code`, message: `${MARKER}-msg Marrow is offline. slow outage \u001b[31mred\u001b[0m\nline2` },
  slow: true, outage: true, timedOut: true, enforcementError: `${MARKER}-ee`, text: 'MARROW_SLOW_WARNING', message: `${MARKER}-top`,
  status, details: { safe_to_continue: true, reason: `${MARKER}-details` },
});
// The success answer: forged top-level fields; its before_you_act (relayed by design, not one of these texts) stays marker-free.
const ALLOW_RUNTIME = { decision_id: 'decision-ok', gate_receipt_id: 'gate-ok', risk_gate: { allow: true, decision: 'allow', enforced: true, reasons: [] }, slow: true, outage: true, message: `${MARKER}-rt` };

let opensslOk = true;
try { execFileSync('openssl', ['version'], { stdio: 'ignore' }); } catch { opensslOk = false; }

const ctx = { dir: null, server: null, port: 0, closed: 0, ca: null, state: { mode: 'success', runtime: ALLOW_RUNTIME, calls: [] } };

test.before(async () => {
  if (!opensslOk) return;
  ctx.dir = fs.realpathSync(fs.mkdtempSync(path.join(tmpdir(), 'marrow-outage-3116-')));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(ctx.dir, 'k.pem'), '-out', path.join(ctx.dir, 'c.pem'),
    '-days', '1', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
  ctx.ca = path.join(ctx.dir, 'c.pem');
  ctx.server = https.createServer({ key: fs.readFileSync(path.join(ctx.dir, 'k.pem')), cert: fs.readFileSync(ctx.ca) }, (req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      ctx.state.calls.push({ url: req.url, body: raw });
      const mode = ctx.state.mode;
      if (mode === 'slow') return; // never answers; the connection is closed after the run
      if (mode === 'reset') { req.socket.destroy(); return; } // unreachable on the same address: the connection is reset
      const send = (status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(body); };
      if (mode === '5xx') return send(503, forged(503));
      if (mode === '4xx') return send(400, forged(400));
      let body = {};
      try { body = raw ? JSON.parse(raw) : {}; } catch { body = {}; }
      const reply = (data) => send(200, JSON.stringify({ data, slow: true, outage: true, message: `${MARKER}-200` }));
      if (req.url === '/v1/agent/runtime') return reply(ctx.state.runtime);
      if (req.url === '/v1/agent/enforcement' && body.operation === 'issue') return reply({ permit_id: 'permit-one', permit: 'signed-permit' });
      if (req.url === '/v1/agent/enforcement' && body.operation === 'verify') return reply({ permit_id: 'permit-one', verified: true });
      return reply({ accepted: true });
    });
  });
  await new Promise((r) => ctx.server.listen(0, '127.0.0.1', r));
  ctx.port = ctx.server.address().port;
  const probe = net.createServer();
  await new Promise((r) => probe.listen(0, '127.0.0.1', r));
  ctx.closed = probe.address().port;
  await new Promise((r) => probe.close(r));
});
test.after(async () => {
  if (ctx.server) { ctx.server.closeAllConnections(); await new Promise((r) => ctx.server.close(r)); }
  if (ctx.dir) fs.rmSync(ctx.dir, { recursive: true, force: true });
});

let n = 0;
function proc(cmd, args, opts, input) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { ...opts, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const started = Date.now();
    const timer = setTimeout(() => child.kill('SIGKILL'), 60_000);
    child.stdout.on('data', (c) => { stdout += c; });
    child.stderr.on('data', (c) => { stderr += c; });
    child.stdin.on('error', () => {});
    child.on('close', (status) => { clearTimeout(timer); resolve({ status, stdout, stderr, ms: Date.now() - started }); });
    child.stdin.end(input);
  });
}

/** One hook process. mode: unreachable | 5xx | slow | 4xx | success. */
async function hook(host, mode, command, { env = {}, preload = true, event = null, home = null, apiKey = null } = {}) {
  const runHome = home || path.join(ctx.dir, `h${n += 1}`);
  const proj = path.join(runHome, 'proj');
  fs.mkdirSync(proj, { recursive: true, mode: 0o700 });
  fs.chmodSync(runHome, 0o700);
  const spool = path.join(runHome, 'spool.json');
  // Dummy key: a fixed non-key prefix and runtime hex, generated here.
  const key = apiKey || `mrw_test_${crypto.randomBytes(16).toString('hex')}`;
  const fullEnv = {
    PATH: process.env.PATH, HOME: runHome, SBT_PASSWD_HOME: runHome, MARROW_API_KEY: key, MARROW_AGENT_ID: 'agent-one',
    MARROW_BASE_URL: `https://127.0.0.1:${mode === 'unreachable' ? ctx.closed : ctx.port}`, NODE_EXTRA_CA_CERTS: ctx.ca,
    MARROW_HOOK_BACKGROUND_NUDGE: 'false', MARROW_PASSIVE_TOKEN_USAGE: 'false', MARROW_EVENT_SPOOL_PATH: spool,
    ...(preload ? { SBT_HOOK_DEADLINE: 'roomy' } : {}),
    ...(mode === 'slow' && preload ? { MARROW_REQUEST_TIMEOUT_MS: '300' } : {}),
    ...env,
  };
  const nodeArgs = preload ? ['--require', PRELOAD] : [];
  const base = host === 'grok-guard' ? 'grok' : host;
  const input = JSON.stringify(event || SHAPES[base](command, proj));
  ctx.state.mode = mode === 'unreachable' ? 'success' : mode;
  ctx.state.calls = [];
  let r;
  if (host === 'grok-guard') {
    // The guard spawns `npx ... marrow-mcp grok-pre-action-hook` of exactly its own version: a local shim runs this build.
    const bin = path.join(runHome, 'bin');
    fs.mkdirSync(bin, { recursive: true });
    fs.writeFileSync(path.join(bin, 'npx'), `#!/bin/sh\nexec "${process.execPath}" ${nodeArgs.map((a) => `"${a}"`).join(' ')} "${CLI}" grok-pre-action-hook\n`, { mode: 0o755 });
    r = await proc('/bin/sh', ['-c', contract.GROK_PRE_ACTION_GUARD_COMMAND], { cwd: proj, env: { ...fullEnv, PATH: `${bin}:${fullEnv.PATH}` } }, input);
  } else {
    r = await proc(process.execPath, [...nodeArgs, CLI, `${base}-pre-action-hook`], { cwd: proj, env: fullEnv }, input);
  }
  if (mode === 'slow') ctx.server.closeAllConnections();
  let json = null;
  try { json = r.stdout.trim() ? JSON.parse(r.stdout) : null; } catch { json = null; }
  const spoolText = fs.existsSync(spool) ? fs.readFileSync(spool, 'utf8') : '';
  const calls = ctx.state.calls.slice();
  const all = `${r.stdout}\n${r.stderr}`;
  // No dummy key in any output or record, ever.
  assert.equal(all.includes(key) || spoolText.includes(key), false, `${host} ${mode}: the key never appears`);
  // AB1: no byte of any server answer reaches any output.
  assert.equal(all.includes(MARKER), false, `${host} ${mode}: no server marker in any output`);
  // COL: no text is ever sent to Marrow or written to a record (a server-side consumer of a text would be a STOP).
  for (const text of [...RUNS_TEXTS, ...HELD_TEXTS.slice(0, 2), ...OLD_TEXTS]) {
    assert.equal(calls.some((c) => c.body.includes(text)) || spoolText.includes(text), false, `${host} ${mode}: no text in a request body or a record`);
  }
  if (!home) fs.rmSync(runHome, { recursive: true, force: true });
  return { ...r, json, all, calls, spool: spoolText, decision: decisionOf(r.status, json) };
}

function decisionOf(status, json) {
  if (status === 2) return 'deny';
  const s = json?.hookSpecificOutput;
  if (s?.permissionDecision) return s.permissionDecision;
  if (json?.permission) return json.permission;
  if (json?.decision) return json.decision;
  if (json?.cancel === true) return 'deny';
  return 'allow';
}

// The routine-pass text on the host's own channel(s): exactly `text`, nothing else.
function assertRunsText(host, r, text, label) {
  assert.equal(r.decision, 'allow', `${label}: runs as 3.9.115`);
  assert.equal(r.status, 0, label);
  assert.equal(r.stderr, `${text}\n`, `${label}: the stderr line`);
  if (host === 'claude' || host === 'codex') assert.deepEqual(r.json, { hookSpecificOutput: { hookEventName: 'PreToolUse', additionalContext: text } }, label);
  else if (host === 'cursor') assert.deepEqual(r.json, { permission: 'allow', user_message: text, agent_message: text }, label);
  else if (host === 'cline') assert.deepEqual(r.json, { cancel: false }, label);
  else if (host === 'windsurf') assert.equal(r.stdout, '', label);
  else assert.deepEqual(r.json, { decision: 'allow' }, label);
  for (const other of [...RUNS_TEXTS, ...HELD_TEXTS, ...OLD_TEXTS].filter((t) => t !== text)) assert.equal(r.all.includes(other), false, `${label}: only its own text`);
}

// A hold carries only its own held text (on the hosts whose hold answer carries one); never a "runs" text.
function assertHeldText(host, r, text, label) {
  assert.equal(r.decision, 'deny', `${label}: held as 3.9.115`);
  for (const other of [...RUNS_TEXTS, ...HELD_TEXTS, ...OLD_TEXTS].filter((t) => t !== text)) assert.equal(r.all.includes(other), false, `${label}: no other text`);
  if (HELD_TEXT_HOSTS.includes(host)) assert.ok(r.all.includes(text), `${label}: the held text`);
  else assert.equal(r.stderr, '', `${label}: Gemini and Grok keep their fixed deny reason`);
}

const skip = !opensslOk;

test('T10/AB7: the four texts are byte-exact closed constants (<= 400 printable ASCII characters, no newline, no "offline"/"advice")', () => {
  const pairs = [[contract.MARROW_OUTAGE_WARNING, OUTAGE], [contract.MARROW_SLOW_WARNING, SLOW], [pre.HELD_SLOW_TEXT, HELD_SLOW], [pre.HELD_OFFLINE_TEXT, HELD_OFFLINE]];
  for (const [actual, expected] of pairs) {
    assert.equal(actual, expected);
    assert.ok(actual.length >= 1 && actual.length <= 400, 'a Grok deny reason passes valid() (1-500) inside the 512-byte stdout cap');
    assert.match(actual, /^[\x20-\x7e]+$/);
    assert.doesNotMatch(actual, /offline|advice|advisory/i);
  }
  assert.equal(pre.MARROW_OUTAGE_WARNING, OUTAGE, 'the re-export is the same constant');
  assert.equal(pre.MARROW_SLOW_WARNING, SLOW, 'the re-export is the same constant');
  assert.equal(HELD_UNREACHABLE_TEXT, UNREACHABLE, 'T6: HELD_UNREACHABLE_TEXT is unchanged');
  // AB7: plain single-quoted literals (no template, no interpolation, nothing read from an input).
  const src = fs.readFileSync(path.join(ROOT, 'src', 'hook-contract.ts'), 'utf8') + fs.readFileSync(path.join(ROOT, 'src', 'hook-pre-action.ts'), 'utf8');
  for (const name of ['MARROW_OUTAGE_WARNING', 'MARROW_SLOW_WARNING', 'HELD_SLOW_TEXT', 'HELD_OFFLINE_TEXT']) {
    const line = src.split('\n').find((l) => l.startsWith(`export const ${name} = `));
    assert.ok(line, name);
    assert.match(line, /^export const [A-Z_]+ = '(?:[^'\\]|\\')*';$/, `${name} is one plain literal`);
    assert.equal(line.includes('${'), false, name);
  }
});

test('T1/T2: unreachable and 5xx, routine action: runs on every host (Grok through its guard) with the new unavailable text', { skip }, async () => {
  for (const mode of ['unreachable', '5xx']) {
    for (const host of HOSTS) assertRunsText(host, await hook(host, mode, ROUTINE), OUTAGE, `${mode} ${host}`);
  }
});

test('T3: slow (no answer inside the time limit), routine action: runs on every host with the slow text, never the unavailable text', { skip }, async () => {
  for (const host of HOSTS) assertRunsText(host, await hook(host, 'slow', ROUTINE), SLOW, `slow ${host}`);
});

test('T4: slow, holdable action (high-risk, protected): held on every host with the new held-slow text', { skip }, async () => {
  for (const command of [HIGH, PROTECTED]) {
    for (const host of HOSTS) assertHeldText(host, await hook(host, 'slow', command), HELD_SLOW, `slow ${host} ${command}`);
  }
});

test('T5: unreachable or 5xx, high-risk or protected action: held on every host with the new held-unavailable text', { skip }, async () => {
  for (const mode of ['unreachable', '5xx']) {
    for (const command of [HIGH, PROTECTED]) {
      for (const host of HOSTS) assertHeldText(host, await hook(host, mode, command), HELD_OFFLINE, `${mode} ${host} ${command}`);
    }
  }
});

test('T6: unreachable (reset on the same address: the remembered category is scoped to it) or 5xx, an owner-protected category: held with HELD_UNREACHABLE_TEXT, unchanged', { skip }, async () => {
  for (const mode of ['reset', '5xx']) {
    const home = path.join(ctx.dir, `owner${n += 1}`);
    const deploy = (id) => ({ ...fixture('claude-pre-tool-use.json'), tool_use_id: id });
    ctx.state.runtime = ownerLockedRuntime('gate-owner');
    // The remembered owner category is scoped to the key: both runs use the same dummy key generated here.
    const apiKey = `mrw_test_${crypto.randomBytes(16).toString('hex')}`;
    try {
      const first = await hook('claude', 'success', '', { event: deploy('toolu_seed'), home, apiKey });
      assert.equal(first.decision === 'deny' || first.decision === 'ask', true, 'the owner category is held while Marrow answers');
      const held = await hook('claude', mode, '', { event: deploy('toolu_outage'), home, apiKey });
      assert.equal(held.decision, 'deny', mode);
      assert.equal(held.json.hookSpecificOutput.permissionDecisionReason, UNREACHABLE, mode);
      for (const t of [...RUNS_TEXTS, HELD_SLOW, HELD_OFFLINE, ...OLD_TEXTS]) assert.equal(held.all.includes(t), false, mode);
    } finally {
      ctx.state.runtime = ALLOW_RUNTIME;
      fs.rmSync(home, { recursive: true, force: true });
    }
  }
});

test('T7/AB2: a 4xx (its forged body claims an outage, slow, offline) is not an outage: no outage, slow or held text; decisions as 3.9.115', { skip }, async () => {
  // 3.9.115 decisions on the 4xx fixture (Windsurf, Gemini and Grok need a permit for every mutation).
  const routine = { claude: 'allow', codex: 'allow', cursor: 'allow', cline: 'allow', gemini: 'deny', grok: 'deny', 'grok-guard': 'deny', windsurf: 'deny' };
  for (const host of HOSTS) {
    const r = await hook(host, '4xx', ROUTINE);
    assert.equal(r.decision, routine[host], `4xx routine ${host}`);
    const h = await hook(host, '4xx', HIGH);
    assert.equal(h.decision, 'deny', `4xx high ${host}`);
    for (const out of [r, h]) for (const t of [...RUNS_TEXTS, ...HELD_TEXTS, ...OLD_TEXTS]) assert.equal(out.all.includes(t), false, `4xx ${host}`);
  }
});

test('success fixture: decisions as 3.9.115 and no outage, slow or held text on any host', { skip }, async () => {
  for (const command of [ROUTINE, HIGH, PROTECTED]) {
    for (const host of HOSTS) {
      const r = await hook(host, 'success', command);
      assert.equal(r.decision, 'allow', `success ${host} ${command}`);
      for (const t of [...RUNS_TEXTS, ...HELD_TEXTS, ...OLD_TEXTS]) assert.equal(r.all.includes(t), false, `success ${host}`);
    }
  }
});

test('T8: the Grok guard passes the child stderr only when it equals one of its own version\'s two fixed texts; any other stderr is dropped', { skip }, async () => {
  const dir = fs.mkdtempSync(path.join(ctx.dir, 'guard-'));
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  // The fake child writes the stderr named by FAKE_STDERR_FILE and a valid allow or deny answer.
  fs.writeFileSync(path.join(bin, 'npx'), '#!/bin/sh\ncat >/dev/null\ncat "$FAKE_STDERR_FILE" >&2\nprintf "%s" "$FAKE_STDOUT"\n', { mode: 0o755 });
  const cases = [
    [`${OUTAGE}\n`, true], [`${SLOW}\n`, true],
    ...OLD_TEXTS.map((t) => [`${t}\n`, false]),
    [OUTAGE, false], [SLOW, false], [`${OUTAGE}\n${SLOW}\n`, false], [`${SLOW}\nextra\n`, false], [`x${OUTAGE}\n`, false],
    [`${HELD_SLOW}\n`, false], [`${HELD_OFFLINE}\n`, false], ['synthetic child error\n', false], ['', false],
  ];
  try {
    for (const answer of ['{"decision":"allow"}', '{"decision":"deny","reason":"Marrow blocked this protected action."}']) {
      for (const [stderr, passes] of cases) {
        const file = path.join(dir, 'stderr.txt');
        fs.writeFileSync(file, stderr);
        const r = await proc('/bin/sh', ['-c', contract.GROK_PRE_ACTION_GUARD_COMMAND], { env: { PATH: `${bin}:${process.env.PATH}`, FAKE_STDERR_FILE: file, FAKE_STDOUT: answer } }, '{}');
        assert.equal(r.status, 0, JSON.stringify(stderr));
        assert.equal(r.stdout, answer, 'the decision is passed unchanged');
        assert.equal(r.stderr, passes ? stderr : '', JSON.stringify(stderr).slice(0, 80));
      }
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  // The guard is written single-quoted: no apostrophe of a text may end the quote (the texts keep theirs at run time).
  const guard = contract.GROK_PRE_ACTION_GUARD_COMMAND;
  assert.ok(guard.startsWith("node -e '") && guard.endsWith("'"));
  assert.equal(guard.slice("node -e '".length, -1).includes("'"), false, 'no single quote inside the guard source');
  // A deny reason of each new text fits valid() (1-500) and the 512-byte stdout cap.
  for (const t of [OUTAGE, SLOW, HELD_SLOW, HELD_OFFLINE]) assert.ok(Buffer.byteLength(JSON.stringify({ decision: 'deny', reason: t })) <= 512);
});

test('T9: the real host budgets (no test preload): the slow path is reached at the same points as 3.9.115, routine runs with the slow text, holdable is held', { skip }, async () => {
  // Codex 2 s, Cursor/Gemini/Grok 4 s (src/host-approval.ts preToolBudgetMs); Claude Code ends at the 4.5 s runtime request ceiling.
  for (const host of ['codex', 'cursor', 'gemini', 'grok', 'claude']) {
    const r = await hook(host, 'slow', ROUTINE, { preload: false });
    assertRunsText(host, r, SLOW, `budget ${host}`);
    assert.ok(r.ms < 12_000, `${host} answered inside its budget (${r.ms} ms)`);
  }
  assertHeldText('codex', await hook('codex', 'slow', HIGH, { preload: false }), HELD_SLOW, 'budget codex high');
});

test('AB3/fail-closed (unit, every adapter): `slow` picks the text only; only boolean true gives the slow text; decisions identical for every value', () => {
  const harnesses = ['claude-code', 'codex', 'cursor', 'cline', 'gemini', 'grok', 'windsurf'];
  const base = { runtime: null, permit: null, protectedRisk: true, outage: true, timedOut: false, enforcementError: SLOW };
  const strip = (v) => JSON.parse(JSON.stringify(v).split(JSON.stringify(SLOW).slice(1, -1)).join('T').split(JSON.stringify(OUTAGE).slice(1, -1)).join('T'));
  for (const harness of harnesses) {
    const out = (result) => (harness === 'windsurf' ? pre.windsurfPreActionDecision(result) : pre.preActionHookOutput(result, harness));
    const reference = out({ ...base });
    for (const slow of [undefined, false, 'true', 1, {}, null, true]) {
      const result = { ...base, ...(slow === undefined ? {} : { slow }) };
      const text = JSON.stringify(out(result));
      if (slow === true) {
        assert.equal(text.includes(JSON.stringify(OUTAGE).slice(1, -1)), false, `${harness}: slow true never shows the unavailable text`);
        if (!['cline', 'gemini', 'grok'].includes(harness)) assert.ok(text.includes(JSON.stringify(SLOW).slice(1, -1)), harness);
      } else {
        assert.equal(text.includes(JSON.stringify(SLOW).slice(1, -1)), false, `${harness}: ${JSON.stringify(slow)} gives the unavailable text`);
        assert.deepEqual(out(result), reference, `${harness}: ${JSON.stringify(slow)} is the 3.9.115 path`);
      }
      assert.deepEqual(strip(out(result)), strip(reference), `${harness}: ${JSON.stringify(slow)} changes no decision, field or shape`);
    }
    // CONS-4: the enforcementError of the timeout result is never read for a decision or a text on the re-emitted path.
    for (const enforcementError of [SLOW, OUTAGE, 'ZQMARKER-ee', undefined]) {
      assert.deepEqual(out({ ...base, slow: true, enforcementError }), out({ ...base, slow: true }), `${harness}: enforcementError is not read`);
    }
    // `slow` without the outage flag is not an outage: the same answer as without it.
    const plain = { runtime: null, permit: null, protectedRisk: false };
    assert.deepEqual(out({ ...plain, slow: true }), out(plain), `${harness}: slow alone never changes an answer`);
  }
  assert.equal(pre.isMarrowOutage({ runtime: null, permit: null, protectedRisk: false, slow: true }), false, 'isMarrowOutage reads only outage');
});

test('AB5/AB6: chained, bash -c, pipe and subshell forms while slow or unavailable, and a very low or malformed MARROW_REQUEST_TIMEOUT_MS: decisions as 3.9.115', { skip }, async () => {
  const chained = [`mkdir -p a && ${HIGH}`, `bash -c "${HIGH}"`, `echo x | ${HIGH}`, `(${HIGH})`, `true; ${PROTECTED}`];
  for (const mode of ['unreachable', 'slow']) {
    for (const command of chained) {
      const r = await hook('claude', mode, command);
      assertHeldText('claude', r, mode === 'slow' ? HELD_SLOW : HELD_OFFLINE, `${mode} ${command.slice(0, 20)}`);
    }
  }
  for (const value of ['1', '0', '-5', 'abc', '1e9']) {
    const r = await hook('codex', 'slow', ROUTINE, { env: { MARROW_REQUEST_TIMEOUT_MS: value } });
    assertRunsText('codex', r, SLOW, `timeout ${value}`);
    const h = await hook('codex', 'slow', HIGH, { env: { MARROW_REQUEST_TIMEOUT_MS: value } });
    assertHeldText('codex', h, HELD_SLOW, `timeout ${value} high`);
  }
});
