const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const { classifyTool } = require('../dist/hook-pre-action.js');
const { selfProtectKind } = require('../dist/self-protect.js');
const { heldLabel } = require('./support/mcp-109-n2-categories.cjs');
const { B1, B2, RES, EXEC, TRIP, CLEAR, INTERP, BASE_HELD, HELD, TRIPWIRE_HELD } = require('./support/mcp0-patch-rows.cjs');
const BASE = require('./fixtures-mcp0-patch-base.json');

// MCP-0 round 2 (audit-mcp0 B1, B2, B3). The change adds holds for control-off forms; it must never slow an ordinary command. A command that names no
// control-off word, or names one only as data, gets exactly its 3.9.109 answer (test/fixtures-mcp0-patch-base.json, recorded by running that build). A command
// that spells a control-off command in a form the change reads (a heredoc body, an inline script the mapper stops) is still held.

const SECURITY_LABEL = 'classified Bash action: security on marrow-control';
const DENY_TEXT = 'Turning Marrow control off needs the account owner. Ask them to run it in their own terminal.';
const bash = (command) => classifyTool({ tool_name: 'Bash', tool_input: { command }, cwd: tmpdir() });
const answer = (command) => {
  const c = bash(command);
  return { type: c.type, surfaces: c.surfaces, protected: c.protected, readOnly: c.readOnly, risk: c.risk, action: c.action, selfKind: selfProtectKind({ tool_name: 'Bash', tool_input: { command } }, tmpdir()) };
};

// ---- PN1 (B1), PN2 (B2): the 3.9.109 answer, whole --------------------------------------------------------------------------------------------

for (const [group, rows] of [['B1', B1], ['B2', B2], ['RES', RES], ['EXEC', EXEC], ['TRIP', TRIP], ['CLEAR', CLEAR], ['INTERP', INTERP]]) {
  for (const [id, command] of rows) {
    test(`${group} keeps its 3.9.109 answer (no new refusal): ${id}`, () => {
      assert.ok(BASE[`${group}|${id}`], 'recorded 3.9.109 answer');
      assert.deepEqual(answer(command), BASE[`${group}|${id}`], JSON.stringify(command));
      assert.notEqual(heldLabel(bash(command).action), SECURITY_LABEL, JSON.stringify(command));
    });
  }
}

for (const [id, command] of BASE_HELD) {
  test(`BASE_HELD keeps its 3.9.109 answer (a held read of Marrow's own files): ${id}`, () => {
    assert.deepEqual(answer(command), BASE[`BASE_HELD|${id}`], JSON.stringify(command));
    assert.equal(bash(command).protected, true);
  });
}

// ---- the forms the change was made for stay held ---------------------------------------------------------------------------------------------

for (const [group, rows] of [['HELD', HELD], ['TRIPWIRE_HELD', TRIPWIRE_HELD]]) {
  for (const [id, command] of rows) {
    test(`${group} a control-off word in a form the change reads is held as marrow-control: ${id}`, () => {
      const result = bash(command);
      assert.equal(heldLabel(result.action), SECURITY_LABEL, JSON.stringify(command));
      assert.equal(result.protected, true);
      assert.equal(result.readOnly, false);
    });
  }
}

// ---- the hook, as a host runs it ------------------------------------------------------------------------------------------------------------

const dummyKey = () => {
  const key = `zzfixture-${randomBytes(16).toString('hex')}`;
  assert.doesNotMatch(key, /^(?:sk|pk|rk)_|ghp_|gho_|xox[a-z]-|AKIA/, 'a dummy key is never live-shaped');
  return key;
};
const CAPTURE = join(__dirname, 'support', 'fetch-capture.cjs');

function makeHome(directory) {
  const home = join(directory, 'home');
  mkdirSync(join(home, '.marrow'), { recursive: true, mode: 0o700 });
  writeFileSync(join(home, '.marrow', 'control.json'), `${JSON.stringify({
    version: 1, enabled: true, changed_at: '2026-09-29T00:00:00.000Z', change_id: 'ctl_0123456789abcdef0123456789abcdef', changed_by: 'owner_cli',
  })}\n`, { mode: 0o600 });
  return home;
}

function hook(directory, home, command, env = {}) {
  const capture = join(directory, `capture-${randomBytes(4).toString('hex')}.ndjson`);
  const result = spawnSync(process.execPath, [join(__dirname, '..', 'dist', 'cli.js'), 'claude-pre-action-hook'], {
    cwd: home,
    env: {
      PATH: process.env.PATH, HOME: home, MARROW_API_KEY: '', MARROW_KEY: '', MARROW_AUTO_HOOK: 'true',
      MARROW_EVENT_SPOOL_PATH: join(home, 'spool.json'), NODE_OPTIONS: `--require ${CAPTURE}`, CAPTURE_FILE: capture, ...env,
    },
    input: JSON.stringify({ session_id: `s-${randomBytes(3).toString('hex')}`, tool_use_id: 't-1', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, permission_mode: 'auto' }),
    encoding: 'utf8',
    timeout: 20_000,
  });
  assert.equal(result.status, 0, result.stderr);
  const lines = existsSync(capture) ? readFileSync(capture, 'utf8').split('\n').filter(Boolean) : [];
  return { stdout: result.stdout, stderr: result.stderr, calls: lines.length };
}

test('B1/B2/RES/EXEC/TRIP in the hook, keyless auto and account auto: no owner-only refusal for the audit rows and their neighbours', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m0p-'));
  try {
    const home = makeHome(directory);
    const key = dummyKey();
    for (const [id, command] of [...B1, ...B2, ...RES, ...EXEC, ...TRIP]) {
      for (const env of [{}, { MARROW_API_KEY: key }]) {
        const { stdout, stderr } = hook(directory, home, command, env);
        assert.equal(stdout.includes(DENY_TEXT), false, id);
        assert.equal(`${stdout}${stderr}`.includes(key), false, 'the key never reaches output');
      }
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('HELD and TRIPWIRE_HELD in the hook, keyless auto and account auto: the owner-only refusal, with no network call', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-m0p-'));
  try {
    const home = makeHome(directory);
    for (const [id, command] of [...HELD, ...TRIPWIRE_HELD]) {
      for (const env of [{}, { MARROW_API_KEY: dummyKey() }]) {
        const { stdout, calls } = hook(directory, home, command, env);
        assert.equal(JSON.parse(stdout).hookSpecificOutput.permissionDecisionReason, DENY_TEXT, id);
        assert.equal(calls, 0, `${id}: no network call`);
      }
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

// ---- PN3 (B3): a mapper that errors or throws, on the shape only the mapper can read ------------------------------------------------------------

const PRELOAD = join(__dirname, 'support', 'mcp0-mapper-preload.cjs');
const MAPPER_ONLY = 'A=@getmarrow; npx $A/install control disable --yes';
const MAPPER_ONLY_TWIN = 'A=@getmarrow; ls $A/mcp';
function classifyWithMapper(mode, command) {
  const result = spawnSync(process.execPath, ['-e', `const { classifyTool } = require(${JSON.stringify(join(__dirname, '..', 'dist', 'hook-pre-action.js'))});
const c = classifyTool({ tool_name: 'Bash', tool_input: { command: ${JSON.stringify(command)} }, cwd: '/tmp' });
process.stdout.write(JSON.stringify(c));`], { env: { PATH: process.env.PATH, HOME: tmpdir(), MCP0_MAPPER_MODE: mode, NODE_OPTIONS: `--require ${PRELOAD}` }, encoding: 'utf8', timeout: 20_000 });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test('PN3 control: with the mapper working (mode off) the mapper-only shape is a hold', () => {
  assert.equal(heldLabel(classifyWithMapper('off', MAPPER_ONLY).action), SECURITY_LABEL);
});

for (const [mode, what] of [
  ['error-stub', 'a mapper that returns a mapper_error stop'],
  ['error-real', 'the real mapper failing inside, so it returns its own mapper_error stop'],
  ['throws', 'a mapper that throws out of evaluateSeatbeltShell'],
]) {
  test(`PN3: ${what}, on a call that names a control-off word, is a hold`, () => {
    const result = classifyWithMapper(mode, MAPPER_ONLY);
    assert.equal(heldLabel(result.action), SECURITY_LABEL);
    assert.equal(result.protected, true);
    assert.equal(result.readOnly, false);
  });
  test(`PN3: ${what}, on a call that names no control-off word, changes nothing`, () => {
    // (A failing mapper also makes the secret-read check fail closed in 3.9.109, so only the control-off hold is compared.)
    assert.notEqual(heldLabel(classifyWithMapper(mode, MAPPER_ONLY_TWIN).action), SECURITY_LABEL);
  });
}
