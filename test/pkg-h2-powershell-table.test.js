'use strict';

// R1 (job tue-r1-pwsh-fix, Codex review of 24f17b60): PowerShell was read as its exact Bash twin, so Bash's
// non-content allowlist applied to PowerShell text: `type ./production.env` (PowerShell `type` is Get-Content)
// was read-only/unprotected/low and the hook let it through with no runtime gate. Now a PowerShell call is:
//   (a) read as the named tool it was in 3.9.103 (exactly what that build's classifyTool returned), and
//   (b) read as Bash reads its text with no Bash allowlist applied (the PowerShell dialect of the splitter),
//       the stricter of both, and never read-only.
// Every expectation below is a PowerShell table (test/support/pwsh-table.cjs): what the PowerShell command DOES,
// never what Bash does with the same text. The 3.9.103 answers are a fixture generated from that build
// (test/fixtures/pwsh-base-868a9c18.json, test/support/gen-pwsh-base-fixture.cjs).
// Dummy secrets are generated at runtime; nothing reaches a network.
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const { classifyTool, seatbeltPassOutput, runPreActionHookCommand } = require('../dist/hook-pre-action.js');
const { SHELL_DIALECT, isReadOnlyToolEvent, isSecretMaterialAccess, isWholeInputNativeTool, parseShellSegments, shellSegmentVerdict, toolPolicyReading } = require('../dist/hook-tool-policy.js');
const { shouldSkipAutoLog, deriveAction } = require('../dist/hook.js');
const { evaluateSeatbelt } = require('../dist/seatbelt/mapper.js');
const { consultSessionLoopGuard, recordSessionLoopOutcome } = require('../dist/session-loop-guard.js');
const { ROWS, POWERSHELL_LABELS, MCP_LABELS, FORMS, tableEvents, eventKey } = require('./support/pwsh-table.cjs');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');
const base = require('./fixtures/pwsh-base-868a9c18.json');

const RISK = ['low', 'medium', 'high'];
const TYPES = ['publish', 'deploy', 'review', 'migration', 'audit', 'financial', 'process'];
const risk = (c) => RISK.indexOf(c.risk);

// ------------------------------------------------------------------ the table

test('R1 table: every PowerShell row is never read-only, protected exactly as PowerShell reads it, and never below medium', () => {
  assert.ok(ROWS.length >= 140, `rows ${ROWS.length}`);
  for (const [command, wantProtected] of ROWS) {
    for (const [form, make] of FORMS) {
      const event = { tool_name: 'PowerShell', tool_input: make(command) };
      const c = classifyTool(event);
      const label = `${form}: ${JSON.stringify(command)}`;
      assert.equal(c.readOnly, false, `${label}: readOnly`);
      assert.equal(isReadOnlyToolEvent(event), false, `${label}: isReadOnlyToolEvent`);
      assert.equal(shouldSkipAutoLog(event), false, `${label}: the post-tool auto-log is not skipped`);
      assert.equal(c.protected, wantProtected, `${label}: protected`);
      assert.ok(risk(c) >= RISK.indexOf(wantProtected ? 'high' : 'medium'), `${label}: risk ${c.risk}`);
    }
  }
});

test('R1 table: labels in any case or padding are the same tool; another server\'s PowerShell stays a named, protected MCP tool', () => {
  for (const command of ['type .env', 'type ./README.md', 'ls', 'type ./production.env', 'echo hi; type .env']) {
    const [, wantProtected] = ROWS.find((r) => r[0] === command);
    for (const tool_name of POWERSHELL_LABELS) {
      for (const [form, make] of FORMS.slice(0, 3)) {
        const c = classifyTool({ tool_name, tool_input: make(command) });
        const label = `${JSON.stringify(tool_name)} ${form} ${command}`;
        assert.equal(c.readOnly, false, label);
        assert.equal(c.protected, wantProtected, label);
        assert.ok(risk(c) >= RISK.indexOf(wantProtected ? 'high' : 'medium'), label);
      }
    }
    for (const tool_name of MCP_LABELS) {
      const c = classifyTool({ tool_name, tool_input: { command } });
      assert.equal(c.readOnly, false, tool_name);
      assert.equal(c.protected, true, `${tool_name}: another server's tool is protected`);
      assert.equal(c.risk, 'high', tool_name);
      const reading = toolPolicyReading({ tool_name, tool_input: { command } });
      assert.equal(reading.exact, false, `${tool_name}: not an exact shell reading`);
      assert.equal(reading.dialect, undefined, `${tool_name}: not PowerShell's dialect`);
    }
  }
});

test('R1 table: the issue rows (type of an env file) are protected, high and not read-only for PowerShell; Bash keeps its own answer', () => {
  for (const command of ['type ./production.env', 'type .env', 'TYPE ./production.env', 'type ~/.ssh/id_rsa', 'cat env:X', 'ls env:', 'echo $env:X']) {
    const ps = classifyTool({ tool_name: 'PowerShell', tool_input: { command } });
    assert.equal(ps.readOnly, false, command);
    assert.ok(risk(ps) >= 1, command);
  }
  for (const command of ['type ./production.env', 'type .env', 'TYPE ./production.env', 'type ~/.ssh/id_rsa']) {
    const ps = classifyTool({ tool_name: 'PowerShell', tool_input: { command } });
    assert.equal(ps.protected, true, command);
    assert.equal(ps.risk, 'high', command);
    assert.ok(ps.surfaces.includes('secrets'), command);
  }
  // Bash's `type` is a shell builtin that names a program: unchanged (S4 of the fail-closed spec).
  const bash = classifyTool({ tool_name: 'Bash', tool_input: { command: 'type .env' } });
  assert.deepEqual({ readOnly: bash.readOnly, protected: bash.protected, risk: bash.risk }, { readOnly: true, protected: false, risk: 'low' });
});

// ------------------------------------------------------------------ never looser than 3.9.103, never below Bash

test('R1 base fixture: 3.9.103 never read PowerShell as read-only; the fixture covers every event of the table', () => {
  assert.equal(base.base, '868a9c18530a75fcee5052441d0d3d2383511df4');
  const events = tableEvents();
  assert.ok(events.length > 1000, `events ${events.length}`);
  for (const { event } of events) assert.ok(base.rows[eventKey(event)], `no 3.9.103 answer for ${eventKey(event)}`);
  assert.equal(Object.values(base.rows).filter((r) => r.readOnly).length, 0);
});

test('R1 base fixture: patched >= 3.9.103 on every event (never read-only, protected never lost, risk and type never lower, surfaces never fewer)', () => {
  let stricter = 0;
  let same = 0;
  for (const { event } of tableEvents()) {
    const was = base.rows[eventKey(event)];
    const now = classifyTool(event);
    const label = eventKey(event);
    assert.equal(now.readOnly, false, `${label}: read-only`);
    if (was.protected) assert.equal(now.protected, true, `${label}: protected lost`);
    assert.ok(risk(now) >= RISK.indexOf(was.risk), `${label}: risk ${now.risk} < ${was.risk}`);
    assert.ok(TYPES.indexOf(now.type) <= TYPES.indexOf(was.type), `${label}: type ${now.type} weaker than ${was.type}`);
    for (const surface of was.surfaces.filter((x) => x !== 'workspace')) assert.ok(now.surfaces.includes(surface), `${label}: surface ${surface} lost`);
    if (now.protected !== was.protected || now.risk !== was.risk || now.type !== was.type) stricter += 1; else same += 1;
  }
  // Some rows are stricter than 3.9.103 (a secret file named without a keyword); the rest are its answer.
  assert.ok(stricter > 0 && same > 0, `stricter ${stricter} same ${same}`);
});

test('R1 base fixture: the label of a PowerShell call is kept exactly as 3.9.103 labelled it', () => {
  for (const { event } of tableEvents()) {
    const was = base.rows[eventKey(event)];
    const now = classifyTool(event);
    // The target (what the gate is sent) is never a weaker class than 3.9.103's for the same surfaces.
    assert.match(now.action, /^classified /, eventKey(event));
    assert.ok(now.action.startsWith(`classified ${String(event.tool_name).slice(0, 64)} action:`), eventKey(event));
    if (was.protected === now.protected && was.type === now.type && JSON.stringify(was.surfaces) === JSON.stringify(now.surfaces)) {
      assert.equal(now.target, was.target, `${eventKey(event)}: same classification, same target`);
    }
  }
});

test('R1 Bash twin: patched >= the Bash reading of the same text (protected and risk) on every command and script row', () => {
  for (const [command] of ROWS) {
    const bash = classifyTool({ tool_name: 'Bash', tool_input: { command } });
    for (const [form, make] of FORMS.slice(0, 4)) {
      const ps = classifyTool({ tool_name: 'PowerShell', tool_input: make(command) });
      const label = `${form}: ${JSON.stringify(command)}`;
      if (bash.protected) assert.equal(ps.protected, true, `${label}: Bash protects it`);
      assert.ok(risk(ps) >= risk(bash), `${label}: risk ${ps.risk} < Bash ${bash.risk}`);
      assert.ok(TYPES.indexOf(ps.type) <= TYPES.indexOf(bash.type), `${label}: type`);
      for (const surface of bash.surfaces.filter((s) => s !== 'workspace')) assert.ok(ps.surfaces.includes(surface), `${label}: surface ${surface}`);
    }
  }
});

test('R1 Monitor and Bash are not PowerShell: Monitor keeps its exact Bash reading, Bash and MCP tools are unchanged', () => {
  for (const [command] of ROWS) {
    const bash = classifyTool({ tool_name: 'Bash', tool_input: { command } });
    for (const input of [{ command }, { script: command }, { command, description: 'd', timeout_ms: 5000 }]) {
      assert.deepEqual(classifyTool({ tool_name: 'Monitor', tool_input: input }), bash, `Monitor ${JSON.stringify(input)}`);
    }
  }
  const monitor = toolPolicyReading({ tool_name: 'Monitor', tool_input: { command: 'ls' } });
  assert.equal(monitor.exact, true);
  assert.equal(monitor.bashLabel, true);
  assert.equal(monitor.dialect, undefined);
  const ps = toolPolicyReading({ tool_name: 'PowerShell', tool_input: { command: 'ls' } });
  assert.equal(ps.exact, false);
  assert.equal(ps.dialect, 'powershell');
  assert.ok(ps.shell.every((twin) => twin[SHELL_DIALECT] === 'powershell' && !Object.keys(twin).includes('shellDialect')));
  // A PowerShell call with no shell text keeps the plain named reading.
  assert.deepEqual(toolPolicyReading({ tool_name: 'PowerShell', tool_input: { description: 'd' } }), { base: 'named', shell: [], exact: false, bashLabel: false });
  assert.deepEqual(toolPolicyReading({ tool_name: 'PowerShell', tool_input: 'ls' }), { base: 'named', shell: [], exact: false, bashLabel: false });
});

// ------------------------------------------------------------------ the PowerShell dialect of the splitter

test('R1 dialect: Bash parsing is unchanged without the flag; PowerShell reads a backslash as a path character', () => {
  assert.deepEqual(parseShellSegments('type .\\.env')[0].words, ['type', '..env']);
  assert.deepEqual(parseShellSegments('type .\\.env', 'powershell')[0].words, ['type', '.\\.env']);
  assert.deepEqual(parseShellSegments('echo "a\\" ; type .env', undefined), null, 'Bash: the backslash escapes the quote, the string never closes');
  const ps = parseShellSegments('echo "a\\" ; type .env', 'powershell');
  assert.deepEqual(ps.map((s) => s.words), [['echo', 'a\\'], ['type', '.env']]);
});

test('R1 dialect: what PowerShell quotes differently is not modelled (typographic quotes, here-strings, comment blocks, escapes)', () => {
  for (const text of ['echo “a” ; type .env', "echo ‘a’", "Get-Content @'\n.env\n'@", 'Get-Content @"\n.env\n"@', 'type <# c #> .env', 'ty`pe .env', 'echo $(type .env)', '(type .env)', 'echo ${env:X}']) {
    assert.equal(parseShellSegments(text, 'powershell'), null, JSON.stringify(text));
  }
});

test('R1 dialect: no word is a read-only inspection and no program is exempt, whatever Bash\'s lists say', () => {
  const segment = (text) => parseShellSegments(text, 'powershell')[0];
  for (const text of ['ls', 'pwd', 'echo hello', 'type README.md', 'cat README.md', 'git status', 'find . -name x', 'env', 'which node']) {
    assert.equal(shellSegmentVerdict(segment(text), '/home/u/proj', 'powershell') === 'read', false, text);
  }
  for (const text of ['type .env', 'echo .env', 'ls .env', 'find .env', 'stat .env', 'file .env', 'which .env', 'cat .env', 'Get-Content -Path:.env', 'Foo-Bar .env']) {
    assert.equal(shellSegmentVerdict(segment(text), '/home/u/proj', 'powershell'), 'secret', text);
  }
  // The same Bash words keep Bash's verdicts.
  assert.equal(shellSegmentVerdict(parseShellSegments('type .env')[0], '/home/u/proj'), 'read');
  assert.equal(shellSegmentVerdict(parseShellSegments('ls')[0], '/home/u/proj'), 'read');
  assert.equal(shellSegmentVerdict(parseShellSegments('cat .env')[0], '/home/u/proj'), 'secret');
});

test('R1 dialect: unknown verbs, aliases and programs never fall below rw/medium; a secret path in them is protected', () => {
  for (const verb of ['Foo-Bar', 'gcm', 'xyz', 'Get-Whatever', 'tee', 'iwr', 'sudo', 'C:\\tools\\x.exe', './run.sh', '/usr/bin/type', '/bin/cat', '/usr/bin/find']) {
    const clean = classifyTool({ tool_name: 'PowerShell', tool_input: { command: `${verb} README.md` } });
    assert.equal(clean.readOnly, false, verb);
    assert.equal(clean.risk, 'medium', verb);
    const secret = classifyTool({ tool_name: 'PowerShell', tool_input: { command: `${verb} .env` } });
    assert.equal(secret.protected, true, verb);
    assert.equal(secret.risk, 'high', verb);
  }
});

test('R1 consumers: the shell text of a PowerShell call is a secret access exactly when the dialect reads a secret in it', () => {
  for (const [command, wantProtected] of ROWS.filter((r) => !/production|push|deploy|publish|prod\*/.test(r[0]))) {
    assert.equal(isSecretMaterialAccess({ tool_name: 'PowerShell', tool_input: { command } }), wantProtected, command);
  }
});

test('R1 consumers: the key of a plain PowerShell call is unchanged by the reading (whole-input forms stay whole-input)', () => {
  assert.equal(isWholeInputNativeTool({ tool_name: 'PowerShell', tool_input: { command: 'ls' } }), false);
  assert.equal(isWholeInputNativeTool({ tool_name: 'PowerShell', tool_input: { command: 'ls', description: 'd', timeout: 5 } }), false);
  assert.equal(isWholeInputNativeTool({ tool_name: 'PowerShell', tool_input: { script: 'ls' } }), false);
  assert.equal(isWholeInputNativeTool({ tool_name: 'PowerShell', tool_input: { command: 'ls', script: 'a' } }), true);
  assert.equal(isWholeInputNativeTool({ tool_name: 'PowerShell', tool_input: { command: 'ls', other: 1 } }), true);
  assert.equal(isWholeInputNativeTool({ tool_name: 'Monitor', tool_input: { command: 'ls', script: 'a' } }), true);
  assert.equal(isWholeInputNativeTool({ tool_name: 'Bash', tool_input: { command: 'ls', script: 'a' } }), false);
  assert.equal(isWholeInputNativeTool({ tool_name: 'mcp__x__PowerShell', tool_input: { command: 'ls' } }), false);
});

test('R1 forged fields: no field of a host event or a tool input can set or clear the dialect (it is a symbol); a forged one changes nothing', () => {
  for (const forged of [{ shellDialect: 'powershell' }, { shellDialect: 'bash' }, { dialect: 'powershell' }, { [String(SHELL_DIALECT)]: 'powershell' }]) {
    for (const command of ['type .env', 'type ./README.md', 'ls', 'cat .env']) {
      for (const tool_name of ['Bash', 'Monitor', 'PowerShell', 'Task']) {
        const plain = classifyTool({ tool_name, tool_input: { command } });
        const withEvent = classifyTool({ tool_name, tool_input: { command }, ...forged });
        const withInput = classifyTool({ tool_name, tool_input: { command, ...forged } });
        assert.deepEqual(withEvent, plain, `${tool_name} ${command} ${JSON.stringify(forged)}: event field`);
        assert.equal(withInput.readOnly, plain.readOnly, `${tool_name} ${command}: input field`);
        assert.equal(withInput.protected, plain.protected, `${tool_name} ${command}: input field`);
      }
    }
  }
  assert.equal(classifyTool({ tool_name: 'Bash', tool_input: { command: 'type .env' }, shellDialect: 'powershell' }).readOnly, true, 'Bash keeps Bash\'s own reading');
  assert.equal(classifyTool({ tool_name: 'PowerShell', tool_input: { command: 'type .env' }, shellDialect: 'bash' }).readOnly, false, 'PowerShell keeps its own');
});

// ------------------------------------------------------------------ keyless seatbelt (evaluateSeatbelt)

test('R1 seatbelt (keyless): base vs patched over the PowerShell table: no event is looser than 3.9.103', () => {
  const order = { pass: 0, stop: 1 };
  let looser = 0;
  let checked = 0;
  for (const { event } of tableEvents()) {
    const was = base.rows[eventKey(event)].seatbelt;
    const now = evaluateSeatbelt(event, makeEnv());
    checked += 1;
    if (order[now.decision] < order[was.decision]) looser += 1;
    if (was.decision === 'stop') assert.equal(now.decision, 'stop', `${eventKey(event)}: ${was.category} no longer stops`);
  }
  assert.equal(looser, 0);
  assert.ok(checked > 1000, `checked ${checked}`);
});

test('R1 seatbelt (keyless): a PowerShell call the 3.9.103 keyless hook held is never passed with an explicit allow', () => {
  // seatbeltPassOutput(harness, event, heldBefore): heldBefore = !readOnly && (protected || the host needs enforcement).
  for (const command of ['type ./production.env', 'type .env', 'cat env:X', 'ls']) {
    const c = classifyTool({ tool_name: 'PowerShell', tool_input: { command } });
    for (const harness of ['claude-code', 'codex', 'cursor', 'gemini', 'cline', 'windsurf', 'grok']) {
      const heldBefore = !c.readOnly && (c.protected || ['windsurf', 'gemini', 'grok'].includes(harness));
      const answer = seatbeltPassOutput(harness, 'beforeShellExecution', heldBefore);
      const text = JSON.stringify(answer);
      if (c.protected) {
        assert.ok(heldBefore, `${harness}: ${command}`);
        assert.doesNotMatch(text, /"permission":"allow"|"cancel":false.*"allow"|"permissionDecision":"allow"/, `${harness}: ${command}`);
        if (harness === 'cursor') assert.equal(answer.permission, 'ask', 'Cursor: its own prompt decides');
      }
    }
  }
});

// ------------------------------------------------------------------ consumers: the keyed hook, loop guard

function withKeyedHook(fn) {
  const originalFetch = globalThis.fetch;
  const keys = ['MARROW_API_KEY', 'MARROW_BASE_URL', 'MARROW_AGENT_ID', 'MARROW_SESSION_ID', 'MARROW_EVENT_SPOOL_PATH', 'HOME'];
  const previous = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  const directory = mkdtempSync(join(tmpdir(), 'marrow-pwsh-table-'));
  const calls = [];
  process.env.MARROW_API_KEY = `dummy-${randomBytes(12).toString('hex')}`;
  process.env.MARROW_BASE_URL = 'https://api.example.test';
  process.env.MARROW_AGENT_ID = 'agent-one';
  process.env.MARROW_SESSION_ID = 'session-one';
  process.env.MARROW_EVENT_SPOOL_PATH = join(directory, 'spool.json');
  process.env.HOME = directory;
  globalThis.fetch = async (url, init = {}) => {
    const pathname = new URL(String(url)).pathname;
    const body = init.body ? JSON.parse(String(init.body)) : {};
    if (pathname !== '/v1/agent/integrations/events') calls.push({ pathname, body });
    if (pathname === '/v1/agent/runtime') {
      return Response.json({ data: {
        decision_id: 'decision-runtime',
        runtime_authorization: { id: 'gate-one', decision_id: 'decision-runtime', decision_creation_required: false },
        completion_contract: { decision_id: 'decision-runtime', decision_creation_required: false },
        risk_gate: { allow: false, decision: 'review_required', enforced: true, reasons: [{ message: 'needs the owner' }] },
        gate_receipt_id: 'gate-one', gate_receipt: { id: 'gate-one' }, proof_pack: { fields: ['command'] },
      } });
    }
    return Response.json({ data: { accepted: true } });
  };
  return fn({ calls }).finally(() => {
    globalThis.fetch = originalFetch;
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    rmSync(directory, { recursive: true, force: true });
  });
}

async function runKeyed(tool_name, command) {
  const originalWrite = process.stdout.write;
  let out = '';
  process.stdout.write = (chunk) => { out += String(chunk); return true; };
  try {
    await runPreActionHookCommand({ session_id: 'session-one', tool_use_id: `tool-${randomBytes(4).toString('hex')}`, tool_name, tool_input: { command } });
  } finally { process.stdout.write = originalWrite; }
  return out;
}

test('R1 consumers (keyed hook): a PowerShell type of an env file reaches the runtime gate and is held; Bash keeps its fast path', async () => {
  await withKeyedHook(async ({ calls }) => {
    for (const command of ['type ./production.env', 'type .env', 'cat env:X', 'echo hello', 'ls']) {
      calls.length = 0;
      const out = await runKeyed('PowerShell', command);
      assert.ok(calls.some((c) => c.pathname === '/v1/agent/runtime'), `${command}: the runtime gate is asked (no read-only fast path)`);
      assert.doesNotMatch(out, /"permissionDecision":"allow"/, command);
    }
    calls.length = 0;
    const held = JSON.parse(await runKeyed('PowerShell', 'type .env'));
    assert.equal(held.hookSpecificOutput.permissionDecision, 'deny', 'review_required holds the protected read');
    // Bash `type .env` (a builtin naming a program) is read-only and never reaches the gate, as before.
    calls.length = 0;
    await runKeyed('Bash', 'type .env');
    assert.deepEqual(calls.map((c) => c.pathname), []);
  });
});

test('R1 consumers (post-tool): a PowerShell call is never skipped by the read-only auto-log skip; Bash read-only still is', () => {
  assert.equal(shouldSkipAutoLog({ tool_name: 'PowerShell', tool_input: { command: 'type ./production.env' } }), false);
  assert.equal(shouldSkipAutoLog({ tool_name: 'PowerShell', tool_input: { command: 'ls' } }), false);
  assert.equal(shouldSkipAutoLog({ tool_name: 'Bash', tool_input: { command: 'ls' } }), true);
  assert.match(deriveAction({ tool_name: 'PowerShell', tool_input: { command: 'type .env' } }), /^classified PowerShell action: audit on secrets$/);
});

test('R1 consumers (loop guard): a PowerShell call is a mutation to the loop guard, exactly as a non-read-only Bash call is', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-pwsh-loop-'));
  try {
    // The guard's answers over a success, a repeat, then the same failure three times.
    const trace = (toolName, command, session) => {
      const readOnly = classifyTool({ tool_name: toolName, tool_input: { command } }).readOnly;
      const op = (id) => ({ sessionId: session, agentId: 'a', harness: 'claude-code', toolName, toolInput: { command }, invocationId: id, readOnly });
      const answers = [];
      const ok = op('s1');
      answers.push(consultSessionLoopGuard(ok, { home }).allow);
      recordSessionLoopOutcome(ok, true, 'same', { home });
      answers.push(consultSessionLoopGuard(op('s2'), { home }).allow);
      for (let i = 0; i < 3; i += 1) {
        const failing = op(`f${i}`);
        answers.push(consultSessionLoopGuard(failing, { home }).allow);
        recordSessionLoopOutcome(failing, false, 'same', { home });
      }
      return { readOnly, answers };
    };
    const bash = trace('Bash', 'git add -A', 'bash-session');
    assert.equal(bash.readOnly, false);
    for (const command of ['type .env', 'ls', 'git add -A']) {
      const ps = trace('PowerShell', command, `ps-${command}`);
      assert.equal(ps.readOnly, false, command);
      assert.deepEqual(ps.answers, bash.answers, `${command}: the guard treats it as a Bash mutation`);
    }
  } finally { rmSync(home, { recursive: true, force: true }); }
});
