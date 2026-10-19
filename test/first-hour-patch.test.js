'use strict';

// First-hour patch round: PATCH-CURSOR, PATCH-BOUND, PATCH-E7, PATCH-C14, PATCH-R1. Text bounds and
// notices only: no decision, exit code, rule or reason code, receipt, key or hold state is asserted
// differently from the first-hour suite. Every random value is made at run time and never printed.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = path.resolve(__dirname, '..');
const pre = require(path.join(ROOT, 'dist', 'hook-pre-action.js'));
const fallback = require(path.join(ROOT, 'dist', 'seatbelt', 'fallback-copy.js'));
const seatbelt = require(path.join(ROOT, 'dist', 'seatbelt', 'hook.js'));
const { MarrowRequestError } = require(path.join(ROOT, 'dist', 'request-reliability.js'));

const FALLBACK_CODES = ['strict', 'key_rejected', 'home_unknown', 'home_unusable', 'env_home_unusable', 'home_mismatch', 'evidence_unknown', 'setup_unconfirmed'];
const token = (bytes = 12) => crypto.randomBytes(bytes).toString('hex');

// ------------------------------------------------------------------------------------------ PATCH-CURSOR

// What 3.9.104 did to every Cursor enforcement text: collapse white space and cut at 500 characters.
const baseCursorCut = (text) => String(text ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 500);
const cursor = (enforcementError, extra = {}) => pre.cursorPreActionHookOutput({ runtime: null, permit: null, protectedRisk: true, enforcementError, ...extra });

test('PATCH-CURSOR: the fixed keyless texts are not cut on Cursor, and each ends with its code', () => {
  const generated = fallback.setupUnconfirmedTexts();
  assert.deepEqual(generated, FALLBACK_CODES.map((code) => fallback.setupUnconfirmedText(code)), 'the set is the table, one text per code');
  const fixed = [pre.NO_KEY_TEXT, pre.CLAIMED_NO_KEY_TEXT, pre.SETUP_UNCONFIRMED_TEXT, ...generated];
  assert.ok(Math.max(...fixed.map((text) => text.length)) > 500, 'the test must include a text the base bound of 500 would cut');
  for (const text of fixed) {
    const out = cursor(text, { credentialsUnavailable: true });
    assert.equal(out.permission, 'deny');
    assert.equal(out.user_message, text, text.slice(-60));
    assert.equal(out.agent_message, text);
    assert.deepEqual(Object.keys(out).sort(), ['agent_message', 'permission', 'user_message']);
  }
  for (const code of FALLBACK_CODES) assert.ok(cursor(fallback.setupUnconfirmedText(code)).user_message.endsWith(` Code: ${code}.`), code);
  // The decision does not depend on the text: a keyless text with no flag is still a deny.
  assert.equal(cursor(pre.NO_KEY_TEXT).permission, 'deny');
});

test('PATCH-CURSOR: every other enforcement text keeps the base cut at 500, byte for byte', () => {
  const longCode = `ACTION_PERMIT_${token(30)}`.slice(0, 80);
  const agentId = `agent-${token(60)}`.slice(0, 128);
  const rejected = new MarrowRequestError({ code: 'http_error', backendCode: longCode, message: 'x', status: 403, exactFix: 'x' });
  const cases = [
    ['credential_scope with a 128-character agent id and a long backend code', pre.controlRejectionMessage(rejected, agentId, 'credential_scope')],
    ['rejection without an agent id', pre.controlRejectionMessage(rejected, undefined, 'credential_scope')],
    ['unavailable', pre.controlRejectionMessage(rejected, agentId, 'unavailable')],
    ['a forged text that starts with NO_KEY_TEXT', `${pre.NO_KEY_TEXT} ${token(300)}`],
    ['a forged text that starts with CLAIMED_NO_KEY_TEXT', `${pre.CLAIMED_NO_KEY_TEXT}${' x'.repeat(300)}`],
    ['a forged text that starts with a fallback hold', `${fallback.setupUnconfirmedText('home_mismatch')} ${token(300)}`],
    ['a fallback hold with one extra character', `${fallback.setupUnconfirmedText('strict')}!`],
    ['a fallback hold with one character fewer', fallback.setupUnconfirmedText('strict').slice(0, -1)],
    ['a hold text with a changed code', fallback.setupUnconfirmedText('strict').replace('Code: strict.', 'Code: other.')],
    ['an input failure', 'Marrow did not check this action because its hook input is 99999999 bytes, over the 4194304-byte pre-action limit, so it was denied. Split it into smaller tool calls and retry.'],
    ['a long text of fixed words', 'Marrow could not verify the required action permit. '.repeat(30)],
  ];
  // The longest the real rejection text gets (128-character agent id, 80-character code) is 424 characters: the bound never binds for it, and the open parts still sit under the base bound.
  assert.ok(cases[0][1].length > 400 && cases[0][1].length <= 500, String(cases[0][1].length));
  let cut = 0;
  for (const [name, text] of cases) {
    const out = cursor(text);
    assert.equal(out.user_message, baseCursorCut(text), name);
    assert.equal(out.agent_message, out.user_message, name);
    assert.ok(out.user_message.length <= 500, name);
    if (text.length > 500) cut += 1;
  }
  assert.ok(cut >= 4, `the cases must include texts over 500 characters (${cut})`);
  // The default text, and a text with control characters and runs of white space.
  assert.equal(cursor(undefined).user_message, baseCursorCut('Marrow could not verify the required action permit. Retry after governance is available.'));
  assert.equal(cursor(`a\u0000b\n\n  c\t${'z'.repeat(700)}`).user_message, baseCursorCut(`a\u0000b\n\n  c\t${'z'.repeat(700)}`));
});

// ------------------------------------------------------------------------------------------ PATCH-BOUND

const fs = require('node:fs');
const os = require('node:os');
const { spawnSync } = require('node:child_process');

const RULES = { S0: 'S0.self_protection', S1: 'S1.protected_branch_force', S2: 'S2.production_deploy', S3: 'S3.package_publish', S4: 'S4.credential_access', S5: 'S5.recursive_delete_outside_ws', Sx: 'Sx.obfuscated_exec', hook: 'U5.fail_closed' };
// A real long reason code, the longest code the CODE pattern lets through (64 characters), and the unreadable-script wrapper.
const REASONS = ['claude_plugin_marketplace_remove_marrow', 'r'.repeat(64), 'script_unreadable'];
const PERSON_ADVICE = 'If you (the person at this machine) meant it, run it yourself in your own terminal.';
const AGENT_INSTRUCTION = 'Agent: do not retry it another way and do not edit Marrow settings; tell the user it was stopped.';
const shownText = (host, out) => (host === 'claude-code' || host === 'codex' ? out.hookSpecificOutput.permissionDecisionReason : host === 'cursor' ? out.user_message : host === 'cline' ? out.errorMessage : out.reason);

test('PATCH-BOUND: the longest real fallback stop keeps the person advice and ends with its code on Claude Code, Codex and Cursor', () => {
  let longest = 0;
  for (const code of FALLBACK_CODES) for (const [category, rule] of Object.entries(RULES)) for (const reason of REASONS) {
    const text = seatbelt.seatbeltStopText(category, rule, reason, 'claimed_no_key', false, code);
    longest = Math.max(longest, text.length);
    for (const host of ['claude-code', 'codex', 'cursor']) {
      const shown = shownText(host, pre.localLoopGuardDenyOutput(host, text));
      assert.equal(shown, text, `${host} ${code} ${category} ${reason}: ${text.length}`);
      assert.ok(shown.includes(PERSON_ADVICE) && shown.includes(AGENT_INSTRUCTION));
      assert.ok(shown.endsWith(` Code: ${rule}/${reason}; mode: ${code}.`));
    }
  }
  assert.ok(longest > 700, `the cases must include the long rows (${longest})`);
  assert.ok(longest <= 880, `longest ${longest}`);
});

test('PATCH-BOUND: Cline and Gemini CLI stay at their own 500; the agent instruction and both codes stay, the text is never longer', () => {
  let cut = 0;
  for (const code of FALLBACK_CODES) for (const [category, rule] of Object.entries(RULES)) for (const reason of REASONS) {
    const text = seatbelt.seatbeltStopText(category, rule, reason, 'claimed_no_key', false, code);
    for (const host of ['cline', 'gemini']) {
      const out = pre.localLoopGuardDenyOutput(host, text);
      const shown = shownText(host, out);
      assert.ok(shown.length <= 500, `${host} ${code} ${category} ${reason}: ${shown.length}`);
      assert.ok(shown.includes(AGENT_INSTRUCTION), `${host} ${code} ${category} ${reason}`);
      assert.ok(shown.endsWith(` Code: ${rule}/${reason}; mode: ${code}.`), `${host} ${code} ${category} ${reason}`);
      assert.deepEqual(Object.keys(out).sort(), host === 'cline' ? ['cancel', 'errorMessage'] : ['decision', 'reason']);
      if (shown !== text) cut += 1;
    }
  }
  assert.ok(cut > 0);
});

test('PATCH-BOUND: the keyless hold on Cline fits the installed Cline hook (500); texts that fit are untouched and the code stays', () => {
  const held = (enforcementError) => pre.clinePreActionHookOutput({ runtime: null, permit: null, protectedRisk: true, enforcementError, credentialsUnavailable: true });
  let cut = 0;
  for (const text of [pre.NO_KEY_TEXT, pre.CLAIMED_NO_KEY_TEXT, pre.SETUP_UNCONFIRMED_TEXT, ...fallback.setupUnconfirmedTexts()]) {
    const out = held(text);
    assert.equal(out.cancel, true);
    assert.deepEqual(Object.keys(out).sort(), ['cancel', 'errorMessage']);
    assert.ok(out.errorMessage.length <= 500, String(out.errorMessage.length));
    if (text.length <= 500) assert.equal(out.errorMessage, text);
    else {
      cut += 1;
      assert.ok(out.errorMessage.startsWith('Marrow stopped this action: there is no Marrow key on this machine, and '));
      assert.ok(/ Code: [a-z_]+\.$/.test(out.errorMessage) && text.endsWith(out.errorMessage.slice(out.errorMessage.lastIndexOf(' Code: '))));
    }
  }
  assert.ok(cut >= 1, 'at least one fixed hold is over 500');
  // The other Cline texts are unchanged.
  assert.equal(pre.clinePreActionHookOutput({ runtime: null, permit: null, protectedRisk: true, failure: 'unavailable' }).errorMessage, 'Marrow is unavailable, so this protected action was denied. Retry when Marrow is reachable.');
});

// The real hooks of six hosts, keyless, in the fallback with the longest reason (a group-writable and world-writable ~/.claude), offline.
const CLI = path.join(ROOT, 'dist', 'cli.js');
const PRELOAD = path.join(__dirname, 'support', 'seatbelt-hook-preload.cjs');
function hostEvent(host, command, dir) {
  const sid = `fh-${token(6)}`;
  switch (host) {
    case 'claude-code': return ['claude-pre-action-hook', { hook_event_name: 'PreToolUse', session_id: sid, tool_use_id: 't1', tool_name: 'Bash', tool_input: { command }, cwd: dir }];
    case 'codex': return ['codex-pre-action-hook', { hook_event_name: 'PreToolUse', session_id: sid, tool_use_id: 't1', tool_name: 'Bash', tool_input: { command }, cwd: dir }];
    case 'cursor': return ['cursor-pre-action-hook', { hook_event_name: 'beforeShellExecution', conversation_id: sid, generation_id: 'g1', command, cwd: dir }];
    case 'cline': return ['cline-pre-action-hook', { hookName: 'PreToolUse', taskId: sid, workspaceRoots: [dir], preToolUse: { toolName: 'execute_command', parameters: { command } } }];
    case 'windsurf': return ['windsurf-pre-action-hook', { agent_action_name: 'pre_run_command', trajectory_id: sid, execution_id: 't1', tool_info: { command_line: command, cwd: dir } }];
    case 'gemini': return ['gemini-pre-action-hook', { session_id: sid, hook_event_name: 'BeforeTool', tool_name: 'run_shell_command', tool_input: { command }, cwd: dir }];
    default: throw new Error(host);
  }
}
function runHost(host, command, dir, code) {
  const [entrypoint, event] = hostEvent(host, command, dir);
  const net = path.join(dir, `net-${token(3)}.log`);
  const result = spawnSync(process.execPath, ['--require', PRELOAD, CLI, entrypoint], {
    cwd: dir, input: JSON.stringify(event), encoding: 'utf8', timeout: 30_000,
    env: { PATH: process.env.PATH, HOME: dir, SBT_PASSWD_HOME: dir, SBT_NETSPY: net, MARROW_HOOK_BACKGROUND_NUDGE: 'false' },
  });
  assert.equal(result.error, undefined);
  assert.equal(fs.existsSync(net), false, 'no network attempt');
  const json = result.stdout.trim() ? JSON.parse(result.stdout) : null;
  const text = host === 'windsurf' ? result.stderr.trim() : host === 'cline' || host === 'gemini' || host === 'cursor' || host === 'claude-code' || host === 'codex' ? shownText(host, json) : '';
  return { status: result.status, text };
}

test('PATCH-BOUND: the real hook of each host, fallback evidence_unknown, longest real labels: bound and content per host', () => {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-fhp-')));
  try {
    fs.chmodSync(dir, 0o700);
    fs.mkdirSync(path.join(dir, '.claude'), { mode: 0o700 });
    fs.chmodSync(path.join(dir, '.claude'), 0o777);
    const lengths = {};
    for (const host of ['claude-code', 'codex', 'cursor', 'cline', 'windsurf', 'gemini']) {
      for (const [command, label] of [['cat .env', 'reading, copying or writing secrets'], ['npm publish', 'package publish']]) {
        const { status, text } = runHost(host, command, dir);
        assert.ok(text.startsWith(`MARROW SEATBELT stopped this action: ${label}`), `${host} ${command}: ${text.slice(0, 80)}`);
        assert.equal(status, host === 'windsurf' ? 2 : 0, host);
        assert.ok(text.endsWith('; mode: evidence_unknown.'), `${host} ${command}: ${text.slice(-70)}`);
        assert.ok(text.includes(AGENT_INSTRUCTION));
        const limit = host === 'cline' || host === 'gemini' ? 500 : 880;
        assert.ok(text.length <= limit, `${host} ${command}: ${text.length}`);
        if (limit === 880) assert.ok(text.includes(PERSON_ADVICE), `${host} ${command} keeps the person advice`);
        lengths[`${host} ${command}`] = text.length;
      }
    }
    // The hosts that take 880 get the same full text; Cline and Gemini CLI are held to 500.
    assert.ok(lengths['windsurf cat .env'] === lengths['claude-code cat .env'] && lengths['cursor cat .env'] === lengths['claude-code cat .env'] && lengths['codex cat .env'] === lengths['claude-code cat .env'], JSON.stringify(lengths));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
