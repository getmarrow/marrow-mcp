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
  assert.ok(longest > 800, `the case must be one the old bound of 800 would have cut (${longest})`);
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
    // The row the old 800 bound would have cut: the hosts that take 880 get the full text and the same text as each other; Cline and Gemini CLI are held to 500.
    assert.ok(lengths['claude-code cat .env'] > 800, JSON.stringify(lengths));
    assert.ok(lengths['windsurf cat .env'] === lengths['claude-code cat .env'] && lengths['cursor cat .env'] === lengths['claude-code cat .env'] && lengths['codex cat .env'] === lengths['claude-code cat .env'], JSON.stringify(lengths));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// ------------------------------------------------------------------------------------------ PATCH-C14

const { fixture, hostRuntime, keyedHarness } = require('./support/first-hour-harness.cjs');
const approval = require(path.join(ROOT, 'dist', 'host-approval.js'));

const CLOSING = 'Do not report or claim an approval yourself.';
const deployEvent = (over = {}) => ({ ...fixture('claude-pre-tool-use.json'), ...over });
const countOf = (text, needle) => String(text).split(needle).length - 1;
const withKeyed = (runtime, fn) => {
  const h = keyedHarness();
  try {
    h.setConfig({ runtime, status: { 'gate-held': 'pending' } });
    return fn(h);
  } finally { h.cleanup(); }
};
// A held deploy whose server reason is open text: a runtime random token is placed in it.
const runtimeWithReason = (reasonText) => hostRuntime('gate-held', {}, {
  risk_gate: { allow: true, decision: 'review_required', enforced: true, gate_required: true, gate_receipt_id: 'gate-held', risk_level: 'high', reasons: [{ message: reasonText }] },
});

test('PATCH-C14: the server reason is not in the agent text or the user line of a dialogLater hold; the dialog prompt still carries it once', () => {
  const reasonToken = `rsn${token(10)}`;
  withKeyed(runtimeWithReason(`Production deploys need approval ${reasonToken}`), (h) => {
    const denied = h.run('claude-pre-action-hook', deployEvent({ permission_mode: 'plan' }));
    assert.equal(denied.json.hookSpecificOutput.permissionDecision, 'deny');
    const agentText = denied.json.hookSpecificOutput.permissionDecisionReason;
    assert.equal(countOf(agentText, reasonToken), 0, 'agent text (permissionDecisionReason)');
    assert.equal(countOf(denied.json.systemMessage, reasonToken), 0, 'systemMessage');
    assert.equal(countOf(denied.stdout, reasonToken), 0, 'the whole hook output');
    assert.equal(countOf(agentText, ' Reason: '), 0);
    assert.ok(agentText.startsWith('Marrow is holding this action for approval (gate receipt gate-held), so it did not run. Claude Code shows no approval dialog in this session ('), agentText.slice(0, 160));
    assert.ok(agentText.endsWith(CLOSING));
    // The stored later prompt (hold.ask_text) carries the reason exactly once, as it did.
    const stored = h.holds();
    assert.equal(stored.length, 1);
    assert.equal(stored[0].dialog_later, true);
    assert.equal(countOf(stored[0].ask_text, reasonToken), 1, 'hold.ask_text');
    assert.ok(stored[0].ask_text.includes(' Reason: Production deploys need approval '));
    // In default mode the same hold becomes Claude Code's own dialog, which shows that prompt.
    const asked = h.run('claude-pre-action-hook', deployEvent({ tool_use_id: 'toolu_default' }));
    assert.equal(asked.json.hookSpecificOutput.permissionDecision, 'ask');
    assert.equal(countOf(asked.json.hookSpecificOutput.permissionDecisionReason, reasonToken), 1, 'the dialog prompt (permissionDecisionReason of the ask)');
    assert.equal(asked.json.hookSpecificOutput.permissionDecisionReason, stored[0].ask_text);
  });
});

test('PATCH-C14: the longest agent text keeps the gate receipt id and ends with the closing sentence, for every kind and the longest unavailable reason', () => {
  const kinds = [['production_deploy'], ['package_publish'], ['secrets_security'], ['data_migration'], ['billing_access'], ['destructive_action'], ['source_control'], [], ['production_deploy', 'package_publish'], ['nothing_known']];
  let longest = 0;
  for (const categories of kinds) for (const idLength of [1, 60, 160]) for (const unavailable of ['u'.repeat(5), 'Claude Code permission mode '.concat('m'.repeat(32), ' cannot guarantee an owner prompt'), 'u'.repeat(400)]) {
    const id = `i${'g'.repeat(idLength - 1)}`;
    const kind = approval.heldKindLabel(categories);
    const text = approval.dialogLaterAgentText(`Marrow is holding this action for approval (gate receipt ${id}), so it did not run.`, unavailable, kind);
    longest = Math.max(longest, text.length);
    assert.ok(text.length <= approval.DIALOG_LATER_LIMIT, String(text.length));
    assert.ok(text.endsWith(CLOSING));
    assert.ok(text.includes(`(gate receipt ${id})`));
    assert.ok(text.includes(`Marrow is holding ${kind};`));
    assert.equal(countOf(text, ' Reason: '), 0);
    assert.match(text, /^[\t\n\x20-\x7e]*$/);
  }
  assert.equal(approval.DIALOG_LATER_LIMIT, 900);
  assert.ok(longest > 800 && longest < 900, `the longest real text stays under 900 without the net (${longest})`);
});

test('PATCH-C14: every other hold plan still carries " Reason: <reason>" as at 8cf99d68', () => {
  const reason = `rsn${token(8)}`;
  const guidance = (over = {}) => ({
    gateReceiptId: 'gate-held', hostApprovalAccepted: true, hostApprovalSupported: true, hostApprovalRefusal: null, verifiedApprovalRequired: false,
    verifiedApprovalCategories: [], approvalCategories: ['production_deploy'], operatorOnly: false, operatorNotice: null, ownerDeclinedAt: null,
    linkAvailable: null, linkReason: null, unattendedOwnerPing: null, approvalAuthority: 'host_operator_or_account_owner', ...over,
  });
  const held = `Marrow is holding this action for approval (gate receipt gate-held), so it did not run. Reason: ${reason}`;
  const typed = approval.planHeldAction({ guidance: guidance(), host: 'codex', hookEvent: 'PreToolUse', reason, typedReply: true });
  assert.equal(typed.kind, 'deny');
  assert.ok(typed.agentText.startsWith(`${held} The operator was asked to approve it here.`), 'typed reply');
  const legacy = approval.planHeldAction({ guidance: guidance({ hostApprovalSupported: false }), host: 'codex', hookEvent: 'PreToolUse', reason });
  assert.ok(legacy.agentText.startsWith(held), 'legacy service');
  const unattended = approval.planHeldAction({ guidance: guidance(), host: 'claude-code', hookEvent: 'PreToolUse', reason, unattended: true, claudePrompt: { available: false, unavailableReason: 'x', headless: true } });
  assert.equal(unattended.quiet, 'unattended');
  assert.ok(unattended.agentText.startsWith(held), 'unattended');
  const quiet = approval.planHeldAction({ guidance: guidance(), host: 'gemini', hookEvent: 'BeforeTool', reason });
  assert.equal(quiet.quiet, 'attended');
  assert.ok(quiet.agentText.startsWith(held), 'attended quiet');
  // The dialogLater plan keeps its laterPrompt with the reason, and its closing sentence.
  const later = approval.planHeldAction({ guidance: guidance(), host: 'claude-code', hookEvent: 'PreToolUse', reason, claudePrompt: { available: false, unavailableReason: 'x' } });
  assert.equal(later.dialogLater, true);
  assert.equal(countOf(later.agentText, reason), 0);
  assert.equal(countOf(later.userText, reason), 0);
  assert.equal(countOf(later.userNotice, reason), 0);
  assert.equal(countOf(later.laterPrompt, reason), 1);
});

// ------------------------------------------------------------------------------------------ PATCH-R1

const NOTICE_LATER = 'Marrow is holding a production deploy for your approval. Approving in chat does not count. Press Shift+Tab until Claude Code is in default mode, then tell the agent to retry; Claude Code will ask you.';
const NOTICE_QUIET = 'Marrow is holding a production deploy for your approval. Nobody can approve it in this run, and a chat reply does not count. Your next interactive Claude Code session shows it.';
const stateModule = require(path.join(ROOT, 'dist', 'host-approval-state.js'));
const indexModule = require(path.join(ROOT, 'dist', 'index.js'));

test('PATCH-R1 (d10-unreachable): while Marrow cannot be reached the retry is denied without the dialog line; when it is reachable the dialog comes', () => {
  withKeyed(hostRuntime(), (h) => {
    const first = h.run('claude-pre-action-hook', deployEvent({ permission_mode: 'plan' }));
    assert.equal(first.json.hookSpecificOutput.permissionDecision, 'deny');
    assert.equal(first.json.systemMessage, NOTICE_LATER);
    // A pending hold read while Marrow answers: the line again, as before.
    const pending = h.run('claude-pre-action-hook', deployEvent({ permission_mode: 'plan', tool_use_id: 'toolu_pending' }));
    assert.equal(pending.json.hookSpecificOutput.permissionDecision, 'deny');
    assert.equal(pending.json.systemMessage, NOTICE_LATER);
    h.setConfig({ statusUnreachable: true });
    const before = JSON.stringify(h.state());
    for (const [label, event] of [['plan', deployEvent({ permission_mode: 'plan', tool_use_id: 'toolu_u1' })], ['default', deployEvent({ tool_use_id: 'toolu_u2' })], ['default again', deployEvent({ tool_use_id: 'toolu_u3' })]]) {
      const out = h.run('claude-pre-action-hook', event);
      assert.equal(out.json.hookSpecificOutput.permissionDecision, 'deny', label);
      assert.equal(out.json.hookSpecificOutput.permissionDecisionReason, approval.HELD_UNREACHABLE_TEXT, label);
      assert.equal(out.json.systemMessage, undefined, label);
      assert.deepEqual(Object.keys(out.json), ['hookSpecificOutput'], label);
      assert.equal(out.stdout.includes('Shift+Tab'), false, label);
    }
    assert.equal(JSON.stringify(h.state()), before, 'the hold is unchanged by the unreachable retries');
    assert.equal(h.holds().length, 1);
    h.setConfig({ statusUnreachable: false });
    const back = h.run('claude-pre-action-hook', deployEvent({ tool_use_id: 'toolu_back' }));
    assert.equal(back.json.hookSpecificOutput.permissionDecision, 'ask', 'reachable again: Claude Code asks');
    assert.equal(back.json.systemMessage, undefined);
    assert.deepEqual(commitsOf(h), []);
  });
});

const commitsOf = (h) => h.requests().filter((r) => r.path === '/v1/agent/commit');

test('PATCH-R1: only a hold still waiting is flagged for the dialog line; a read that fails, an unavailable status and an approved call already running are not', async () => {
  const hold = { id: 'hold-r1', gate_receipt_id: 'gate-held', session_id: 'sess-r1', agent_id: null, mode: 'wait', state: 'open', dialog_later: true, ask_text: 'prompt', expires_at: '2030-01-01T00:30:00.000Z' };
  const ctx = { apiKey: `mrw_test_${token(16)}`, baseUrl: 'https://api.example.test', sessionId: 'sess-r1', agentId: undefined, harness: 'claude-code', host: 'claude-code', hostSessionId: 'sess-r1' };
  const call = { correlation: 'c1', target: 't1', toolUseId: 'tu1', generationId: null, dialogAvailable: false };
  const saved = { find: stateModule.findHolds, claim: stateModule.claimHold, status: indexModule.marrowOwnerApprovalStatus };
  const answer = (status) => { indexModule.marrowOwnerApprovalStatus = async () => ({ kind: 'found', status }); };
  try {
    stateModule.findHolds = () => [hold];
    stateModule.claimHold = () => null;
    // The status cannot be read.
    indexModule.marrowOwnerApprovalStatus = async () => { throw new Error('unreachable'); };
    let out = await approval.resumeWaitingHold(ctx, call);
    assert.equal(out.kind, 'deny');
    assert.equal(out.agentText, approval.HELD_UNREACHABLE_TEXT);
    assert.equal(out.waiting, undefined);
    assert.equal(approval.holdNotice(out.hold, 'a production deploy', out.waiting === true), null);
    // The status says unavailable.
    answer({ state: 'unavailable' });
    out = await approval.resumeWaitingHold(ctx, call);
    assert.equal(out.agentText, approval.HELD_UNREACHABLE_TEXT);
    assert.equal(out.waiting, undefined);
    assert.equal(approval.holdNotice(out.hold, 'a production deploy', out.waiting === true), null);
    // Approved, and the claim is lost to an identical call already running.
    answer({ state: 'approved', decision_id: 'decision-r1', approval_source: 'host_prompt', approval_answered_by: 'host_operator' });
    out = await approval.resumeWaitingHold(ctx, call);
    assert.equal(out.kind, 'deny');
    assert.match(out.agentText, /^Marrow approved this held action once \(gate receipt gate-held\), and an identical call is already running on that approval, so this repeat did not run\./);
    assert.equal(out.waiting, undefined);
    assert.equal(approval.holdNotice(out.hold, 'a production deploy', out.waiting === true), null);
    // Still waiting: pending and arbitration review keep the line.
    for (const state of ['pending', 'arbitration_review']) {
      answer({ state, expires_at: '2030-01-01T00:30:00.000Z' });
      out = await approval.resumeWaitingHold(ctx, call);
      assert.equal(out.kind, 'deny', state);
      assert.equal(out.waiting, true, state);
      assert.equal(approval.holdNotice(out.hold, 'a production deploy', out.waiting === true), NOTICE_LATER, state);
    }
    // The headless hold keeps its own line on a waiting deny, exactly as before.
    const quiet = { ...hold, dialog_later: false, quiet: 'unattended' };
    stateModule.findHolds = () => [quiet];
    answer({ state: 'pending' });
    out = await approval.resumeWaitingHold(ctx, call);
    assert.equal(approval.holdNotice(out.hold, 'a production deploy', out.waiting === true), NOTICE_QUIET);
    // A hold that is neither: no line, whatever the flag.
    assert.equal(approval.holdNotice({ dialog_later: false, quiet: undefined, arbitration_receipt_id: undefined }, 'a production deploy', true), null);
  } finally {
    stateModule.findHolds = saved.find;
    stateModule.claimHold = saved.claim;
    indexModule.marrowOwnerApprovalStatus = saved.status;
  }
});
