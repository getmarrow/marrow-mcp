'use strict';

// First-hour fixes, tier A (copy C12-C15): output only. A held action that nobody can approve in chat
// tells the user so (a user-only systemMessage on Claude Code), the agent is told the same plainly,
// and a chat reply that looks like an approval is answered with one line. No hold, code, receipt or
// decision changes; tools/fh-diff.cjs proves that against the base build.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = path.resolve(__dirname, '..');
const { fixture, hostRuntime, ownerLockedRuntime, keyedHarness } = require('./support/first-hour-harness.cjs');
const approval = require(path.join(ROOT, 'dist', 'host-approval.js'));
const { looksLikeApprovalReply } = require(path.join(ROOT, 'dist', 'approval-reply.js'));
const pre = require(path.join(ROOT, 'dist', 'hook-pre-action.js'));

const SESSION = '3b1f0c2e-0000-4000-8000-00000000000a';
const ASCII = /^[\t\n\x20-\x7e]*$/;
const NEVER = [/\brisk\b/i, /\brisky\b/i, /\bscore\b/i, /\bclassifier\b/i, /Marrow AI/];
const NOTICE_LATER = 'Marrow is holding a production deploy for your approval. Approving in chat does not count. Press Shift+Tab until Claude Code is in default mode, then tell the agent to retry; Claude Code will ask you.';
const NOTICE_QUIET = 'Marrow is holding a production deploy for your approval. Nobody can approve it in this run, and a chat reply does not count. Your next interactive Claude Code session shows it.';
const NOTICE_CHAT = 'Marrow did not record that as an approval: a chat reply cannot approve a held action. To approve it, put Claude Code in default mode (Shift+Tab), then ask the agent to retry; Claude Code will ask you.';

const deploy = (over = {}) => ({ ...fixture('claude-pre-tool-use.json'), ...over });
const prompt = (text, over = {}) => ({ ...fixture('claude-user-prompt-submit.json'), prompt: text, ...over });
const held = (h) => h.holds();
const reports = (h) => h.requests().filter((r) => r.path.endsWith('/host-approval'));
const commits = (h) => h.requests().filter((r) => r.path === '/v1/agent/commit');
const withHarness = (fn, runtime = hostRuntime()) => {
  const h = keyedHarness();
  try {
    h.setConfig({ runtime, status: { 'gate-held': 'pending', 'gate-locked': 'pending' } });
    return fn(h);
  } finally { h.cleanup(); }
};

// ------------------------------------------------------------------------------------------ A1

test('A1 C12: a hold denied for later (no dialog in this mode) shows the user one line; the decision is the same deny', () => {
  for (const mode of ['plan', 'dontAsk', 'bypassPermissions']) {
    withHarness((h) => {
      const secret = `tok_${crypto.randomBytes(10).toString('hex')}`;
      const out = h.run('claude-pre-action-hook', deploy({ permission_mode: mode, tool_input: { command: `wrangler deploy --env production --tag ${secret}`, description: 'Deploy' } }));
      assert.equal(out.status, 0);
      assert.equal(out.json.hookSpecificOutput.permissionDecision, 'deny', mode);
      assert.equal(out.json.systemMessage, NOTICE_LATER, mode);
      assert.deepEqual(Object.keys(out.json).sort(), ['hookSpecificOutput', 'systemMessage']);
      assert.deepEqual(Object.keys(out.json.hookSpecificOutput).sort(), ['hookEventName', 'permissionDecision', 'permissionDecisionReason']);
      // F3: the user line carries the kind of action only.
      for (const hold of held(h)) {
        assert.equal(hold.dialog_later, true);
        for (const value of [hold.code, hold.gate_receipt_id, hold.id].filter(Boolean)) assert.equal(out.json.systemMessage.includes(value), false);
      }
      assert.equal(out.json.systemMessage.includes('gate-held'), false);
      assert.equal(out.json.systemMessage.includes(secret), false);
      assert.match(out.json.systemMessage, ASCII);
      for (const word of NEVER) assert.doesNotMatch(out.json.systemMessage, word);
      assert.deepEqual(commits(h), []);
      assert.deepEqual(reports(h), []);
    });
  }
});

test('A1 C13: a hold nobody can approve in this run (headless) shows the user one line; the decision is the same deny', () => {
  for (const entrypoint of ['sdk-cli', 'sdk-ts']) {
    withHarness((h) => {
      const out = h.run('claude-pre-action-hook', deploy(), { CLAUDE_CODE_ENTRYPOINT: entrypoint });
      assert.equal(out.json.hookSpecificOutput.permissionDecision, 'deny');
      assert.equal(out.json.systemMessage, NOTICE_QUIET);
      assert.deepEqual(Object.keys(out.json).sort(), ['hookSpecificOutput', 'systemMessage']);
      assert.equal(held(h)[0].quiet, 'unattended');
      assert.equal(out.json.systemMessage.includes('gate-held'), false);
    });
  }
});

test('A1: the kind is a fixed label; several kinds or an unknown one read "a protected action"', () => {
  assert.equal(approval.heldKindLabel(['production_deploy']), 'a production deploy');
  assert.equal(approval.heldKindLabel(['package_publish']), 'a package publish');
  assert.equal(approval.heldKindLabel(['production_deploy', 'production_deploy']), 'a production deploy');
  for (const odd of [[], undefined, null, ['production_deploy', 'package_publish'], ['made_up'], ['__proto__'], ['constructor'], [7], 'production_deploy']) assert.equal(approval.heldKindLabel(odd), 'a protected action', JSON.stringify(odd));
  withHarness((h) => {
    const out = h.run('claude-pre-action-hook', deploy({ permission_mode: 'plan' }));
    assert.match(out.json.systemMessage, /^Marrow is holding a protected action for your approval\./);
  }, hostRuntime('gate-held', { approval_categories: ['production_deploy', 'package_publish'] }));
});

test('A1: no user line where a person can answer, or where the hold is not one of these', () => {
  // Default mode: Claude Code asks in its dialog (an "ask", no notice).
  withHarness((h) => {
    const out = h.run('claude-pre-action-hook', deploy());
    assert.equal(out.json.hookSpecificOutput.permissionDecision, 'ask');
    assert.equal(out.json.systemMessage, undefined);
  });
  // An owner-locked category: the owner's link approves it, not a dialog and not default mode.
  withHarness((h) => {
    const out = h.run('claude-pre-action-hook', deploy({ permission_mode: 'plan' }));
    assert.equal(out.json.hookSpecificOutput.permissionDecision, 'deny');
    assert.equal(out.json.systemMessage, undefined);
  }, ownerLockedRuntime());
  // Codex keeps its typed-reply systemMessage only; Cursor and the others get none of these lines.
  withHarness((h) => {
    const out = h.run('codex-pre-action-hook', fixture('codex-pre-tool-use.json'), { CODEX_HOME: path.join(h.home, '.codex') });
    assert.ok(!JSON.stringify(out.json || {}).includes('Shift+Tab'));
  });
});

test('A1: the retry of a waiting hold shows the same line again and stays denied', () => {
  withHarness((h) => {
    const first = h.run('claude-pre-action-hook', deploy({ permission_mode: 'plan' }));
    assert.equal(first.json.systemMessage, NOTICE_LATER);
    const again = h.run('claude-pre-action-hook', deploy({ permission_mode: 'plan', tool_use_id: 'toolu_retry_same_mode' }));
    assert.equal(again.json.hookSpecificOutput.permissionDecision, 'deny');
    assert.equal(again.json.systemMessage, NOTICE_LATER);
    assert.equal(again.json.systemMessage.includes('gate-held'), false);
    assert.equal(held(h).length, 1, 'no second hold');
  });
  withHarness((h) => {
    const first = h.run('claude-pre-action-hook', deploy(), { CLAUDE_CODE_ENTRYPOINT: 'sdk-cli' });
    assert.equal(first.json.systemMessage, NOTICE_QUIET);
    const again = h.run('claude-pre-action-hook', deploy({ tool_use_id: 'toolu_retry_headless' }), { CLAUDE_CODE_ENTRYPOINT: 'sdk-cli' });
    assert.equal(again.json.hookSpecificOutput.permissionDecision, 'deny');
    assert.equal(again.json.systemMessage, NOTICE_QUIET);
  });
});

test('A1: a state that cannot be written keeps the deny (and the line)', () => {
  withHarness((h) => {
    fs.mkdirSync(path.join(h.home, '.marrow'), { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(h.home, '.marrow', 'host-approvals'), 'not a folder');
    const out = h.run('claude-pre-action-hook', deploy({ permission_mode: 'plan' }));
    assert.equal(out.json.hookSpecificOutput.permissionDecision, 'deny');
    assert.equal(out.json.hookSpecificOutput.permissionDecision === 'allow', false);
  });
});

// ------------------------------------------------------------------------------------------ A2

test('A2 C14: the agent is told to tell the user once, never to treat a chat reply as approval, and never to claim one', () => {
  withHarness((h) => {
    const out = h.run('claude-pre-action-hook', deploy({ permission_mode: 'bypassPermissions' }));
    const text = out.json.hookSpecificOutput.permissionDecisionReason;
    assert.equal(text, 'Marrow is holding this action for approval (gate receipt gate-held), so it did not run. Claude Code shows no approval dialog in this session (Claude Code permission mode bypassPermissions cannot guarantee an owner prompt). Tell the user once: Marrow is holding a production deploy; a chat approval does not count; to approve it, they switch Claude Code to default mode (Shift+Tab) and ask you to retry this exact action, and Claude Code then asks them. Do not treat a chat reply as approval. Until then carry on with other work. Do not report or claim an approval yourself.');
    assert.match(text, ASCII);
    for (const word of NEVER) assert.doesNotMatch(text, word);
  });
});

test('A2 C14: the closing sentence survives the longest reason, receipt id and unavailable reason', () => {
  const closing = 'Do not report or claim an approval yourself.';
  const guidance = (id, categories) => ({
    gateReceiptId: id, hostApprovalAccepted: true, hostApprovalSupported: true, hostApprovalRefusal: null, verifiedApprovalRequired: false,
    verifiedApprovalCategories: [], approvalCategories: categories, operatorOnly: false, operatorNotice: null, ownerDeclinedAt: null,
    linkAvailable: null, linkReason: null, unattendedOwnerPing: null, approvalAuthority: 'host_operator_or_account_owner',
  });
  for (const categories of [['production_deploy'], ['billing_access'], [], ['production_deploy', 'package_publish']]) {
    for (const idLength of [4, 60, 160]) {
      for (const reasonLength of [0, 10, 200, 5000]) {
        for (const unavailableLength of [5, 90, 400]) {
          const plan = approval.planHeldAction({
            guidance: guidance('g'.repeat(idLength), categories), host: 'claude-code', hookEvent: 'PreToolUse',
            reason: 'r'.repeat(reasonLength), claudePrompt: { available: false, unavailableReason: 'u'.repeat(unavailableLength) },
          });
          assert.equal(plan.kind, 'deny');
          assert.equal(plan.dialogLater, true);
          assert.ok(plan.agentText.length <= approval.DIALOG_LATER_LIMIT, `${plan.agentText.length}`);
          assert.ok(plan.agentText.endsWith(closing), `id ${idLength} reason ${reasonLength} unavailable ${unavailableLength}`);
          assert.ok(plan.agentText.includes('Do not treat a chat reply as approval.'));
          assert.ok(plan.agentText.includes(`(gate receipt ${'g'.repeat(idLength)})`), 'the receipt id stays in the agent text');
          assert.equal(plan.userText.includes('gate receipt'), false, 'a person reads no receipt id');
          assert.match(plan.userNotice, /^Marrow is holding (a production deploy|a billing or access change|a protected action) for your approval\. Approving in chat does not count\./);
          assert.equal(plan.userNotice.includes('g'.repeat(4)), false);
        }
      }
    }
  }
});

// ------------------------------------------------------------------------------------------ A3

test('A3: the matcher answers yes or no for short approval-like replies only', () => {
  // Trimmed first: padding does not make a reply longer.
  assert.equal(looksLikeApprovalReply(`   yes${' '.repeat(80)}`), true);
  for (const yes of ['y', 'yes', 'Yes', 'YES.', ' yes ', 'yep', 'yeah!', 'ok', 'okay', 'sure', 'approve', 'approved', 'approve it', 'i approve', 'allow', 'allowed', 'allow it', 'confirm', 'confirmed', 'go', 'go ahead', 'do it', 'proceed', 'lgtm', 'ship it', 'Go Ahead!!!', 'yes ...', 'ok.  ']) {
    assert.equal(looksLikeApprovalReply(yes), true, JSON.stringify(yes));
  }
  for (const no of ['', ' ', 'no', 'yes please', 'yes, deploy it', 'yess', 'approve the deploy', 'go ahead and deploy', 'what happened?', 'yes\nrm -rf /', 'y'.repeat(65), `yes ${'.'.repeat(70)}`, 'ok?', 'okay then', null, undefined, 7, {}, ['yes']]) {
    assert.equal(looksLikeApprovalReply(no), false, JSON.stringify(no));
  }
  assert.equal(looksLikeApprovalReply(`${'a'.repeat(300)}`), false);
});

// A hold, its session, then the prompt in the same or another session. The session's first prompt comes
// first, as in a real session: Marrow's one-time "held actions are waiting" notice (which records that it
// was shown) belongs to that prompt, not to the reply.
function open(h, preEvent, env = {}) {
  const first = h.run('claude-context-hook', prompt('hello'));
  assert.equal(first.status, 0);
  const out = h.run('claude-pre-action-hook', preEvent, env);
  assert.equal(out.status, 0);
  return out;
}
const say = (h, text, over = {}, env = {}) => h.run('claude-context-hook', prompt(text, over), env);

test('A3 C15 (a)-(d): shown only for a hold that got no real dialog', () => {
  // (a) a real dialog was shown (default mode, an "ask"), the user pressed No, then typed "yes": nothing.
  withHarness((h) => {
    assert.equal(open(h, deploy()).json.hookSpecificOutput.permissionDecision, 'ask');
    assert.equal(held(h)[0].mode, 'ask');
    const before = h.stateSnapshot();
    const out = say(h, 'yes');
    assert.equal(out.json?.systemMessage, undefined);
    assert.deepEqual(h.stateSnapshot(), before, 'the state is untouched');
  });
  // (b) denied for later (plan mode), then "yes": the notice.
  withHarness((h) => {
    open(h, deploy({ permission_mode: 'plan' }));
    const before = h.stateSnapshot();
    const out = say(h, 'yes');
    assert.equal(out.status, 0);
    assert.equal(out.json.systemMessage, NOTICE_CHAT);
    assert.deepEqual(h.stateSnapshot(), before, 'A3 writes nothing');
    assert.deepEqual(reports(h), []);
    assert.deepEqual(commits(h), []);
    assert.equal(held(h)[0].state, 'open');
  });
  // (c) a quiet hold (headless), then "ok": the notice.
  withHarness((h) => {
    open(h, deploy(), { CLAUDE_CODE_ENTRYPOINT: 'sdk-cli' });
    const before = h.stateSnapshot();
    const out = say(h, 'ok');
    assert.equal(out.json.systemMessage, NOTICE_CHAT);
    assert.deepEqual(h.stateSnapshot(), before);
  });
  // (d) a hold whose kind is not recorded as one of these (an owner-locked hold): nothing.
  withHarness((h) => {
    open(h, deploy({ permission_mode: 'plan' }));
    assert.equal(held(h)[0].dialog_later, false);
    const out = say(h, 'yes');
    assert.equal(out.json?.systemMessage, undefined);
  }, ownerLockedRuntime());
  // (d') a hold with neither field written (an older record): nothing.
  withHarness((h) => {
    open(h, deploy({ permission_mode: 'plan' }));
    const state = h.state();
    for (const hold of Object.values(state.holds)) { delete hold.dialog_later; delete hold.quiet; }
    fs.writeFileSync(h.statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 });
    const before = h.stateSnapshot();
    assert.equal(say(h, 'yes').json?.systemMessage, undefined);
    assert.deepEqual(h.stateSnapshot(), before);
  });
  // No hold at all, a prompt that is not a reply, and a hold in another state: nothing.
  withHarness((h) => {
    assert.equal(say(h, 'yes').json?.systemMessage, undefined);
    open(h, deploy({ permission_mode: 'plan' }));
    for (const text of ['what happened?', 'yes please deploy it', 'go ahead and push', '']) assert.equal(say(h, text).json?.systemMessage, undefined, JSON.stringify(text));
    const state = h.state();
    for (const hold of Object.values(state.holds)) hold.state = 'allowed';
    fs.writeFileSync(h.statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 });
    assert.equal(say(h, 'yes').json?.systemMessage, undefined, 'a spent hold');
    for (const hold of Object.values(state.holds)) { hold.state = 'open'; hold.expires_at = '2000-01-01T00:00:00.000Z'; }
    fs.writeFileSync(h.statePath, `${JSON.stringify(state)}\n`, { mode: 0o600 });
    assert.equal(say(h, 'yes').json?.systemMessage, undefined, 'an expired hold');
  });
});

test('A3 (e): the prompt text is never stored or logged, debug logging on', () => {
  withHarness((h) => {
    open(h, deploy({ permission_mode: 'plan' }));
    const token = `tok_${crypto.randomBytes(12).toString('hex')}`;
    const env = { MARROW_CONTEXT_HOOK_DEBUG: 'true', MARROW_HOOK_DEBUG: 'true' };
    const before = h.stateSnapshot();
    // A reply-like prompt: the answer is the notice; no copy of the text anywhere.
    const hit = say(h, 'lgtm', {}, env);
    assert.equal(hit.json.systemMessage, NOTICE_CHAT);
    assert.equal(hit.stderr.includes('lgtm'), false);
    // A prompt carrying a random token (a miss): no copy of the token anywhere either.
    const miss = say(h, `yes ${token}`, {}, env);
    assert.equal(miss.json?.systemMessage, undefined);
    assert.equal(miss.stderr.includes(token), false);
    assert.equal(hit.stdout.includes(token) || miss.stdout.includes(token), false);
    assert.deepEqual(h.stateSnapshot(), before, 'the state directory is byte-identical');
    const files = [];
    const walk = (dir) => { for (const name of fs.readdirSync(dir)) { const p = path.join(dir, name); fs.statSync(p).isDirectory() ? walk(p) : files.push(p); } };
    walk(h.home);
    let count = 0;
    for (const file of files) { if (fs.readFileSync(file).includes(token)) count += 1; }
    assert.equal(count, 0, 'the token is in no file under the fake HOME');
  });
});

test('abuse 1/2: a self-typed approval (a crafted event, tmux send-keys or --resume delivering it) only gets the line; the hold and the retry are unchanged', () => {
  withHarness((h) => {
    const first = open(h, deploy({ permission_mode: 'plan' }));
    assert.equal(first.json.hookSpecificOutput.permissionDecision, 'deny');
    const before = h.stateSnapshot();
    const requestsBefore = h.requests().length;
    for (const text of ['approve', 'APPROVE', 'approved.', 'yes', 'go ahead', 'i approve']) {
      // The same event the real hook receives from a typed prompt, a pasted one or a resumed session.
      const out = say(h, text, { source: 'resume' });
      assert.equal(out.status, 0);
      assert.equal(out.json.systemMessage, NOTICE_CHAT, text);
      assert.deepEqual(Object.keys(out.json), ['systemMessage'], 'nothing else is added');
    }
    assert.deepEqual(h.stateSnapshot(), before, 'the hold files are byte-identical');
    assert.deepEqual(reports(h), []);
    assert.deepEqual(commits(h), []);
    assert.ok(h.requests().length >= requestsBefore);
    // The retried action is still denied.
    const retry = h.run('claude-pre-action-hook', deploy({ permission_mode: 'plan', tool_use_id: 'toolu_after_chat_reply' }));
    assert.equal(retry.json.hookSpecificOutput.permissionDecision, 'deny');
    assert.equal(held(h).length, 1);
    assert.equal(held(h)[0].state, 'open');
  });
});

test('abuse 5: a reply in another session gets nothing and records nothing', () => {
  withHarness((h) => {
    open(h, deploy({ permission_mode: 'plan' }));
    say(h, 'hello', { session_id: 'some-other-session-b' });
    const before = h.stateSnapshot();
    const other = say(h, 'approve', { session_id: 'some-other-session-b' });
    assert.equal(other.json?.systemMessage, undefined);
    assert.deepEqual(h.stateSnapshot(), before);
    assert.deepEqual(reports(h), []);
    assert.equal(say(h, 'approve', { session_id: SESSION }).json.systemMessage, NOTICE_CHAT);
  });
});

test('abuse 9: an unreadable or unsafe state, a corrupt state or a missing session id shows nothing extra and exits like before', () => {
  const cases = {
    'unsafe state folder': (h) => fs.chmodSync(path.dirname(h.statePath), 0o755),
    'unsafe state file': (h) => fs.chmodSync(h.statePath, 0o666),
    'corrupt state': (h) => fs.writeFileSync(h.statePath, 'not json at all', { mode: 0o600 }),
    'state is a directory': (h) => { fs.rmSync(h.statePath); fs.mkdirSync(h.statePath, { mode: 0o700 }); },
    'state is a link': (h) => { const target = path.join(h.dir, 'elsewhere.json'); fs.renameSync(h.statePath, target); fs.symlinkSync(target, h.statePath); },
  };
  for (const [label, damage] of Object.entries(cases)) {
    withHarness((h) => {
      open(h, deploy({ permission_mode: 'plan' }));
      damage(h);
      const withReply = say(h, 'yes');
      const plain = say(h, 'what happened?');
      assert.equal(withReply.status, plain.status, label);
      assert.equal(withReply.status, 0, label);
      assert.equal(withReply.json?.systemMessage, undefined, label);
      assert.equal(withReply.stdout, plain.stdout, `${label}: the same output as a prompt that is not a reply`);
    });
  }
  withHarness((h) => {
    open(h, deploy({ permission_mode: 'plan' }));
    const noSession = prompt('yes');
    delete noSession.session_id;
    const out = h.run('claude-context-hook', noSession);
    assert.equal(out.status, 0);
    assert.notEqual(out.json?.systemMessage, NOTICE_CHAT);
    const odd = h.run('claude-context-hook', prompt('yes', { session_id: '../../etc passwd' }));
    assert.notEqual(odd.json?.systemMessage, NOTICE_CHAT);
  });
});

test('A3: only on Claude Code, and not in a headless run', () => {
  withHarness((h) => {
    open(h, deploy({ permission_mode: 'plan' }));
    assert.notEqual(h.run('codex-context-hook', { ...fixture('codex-user-prompt-submit.json'), prompt: 'yes', session_id: SESSION }).json?.systemMessage, NOTICE_CHAT);
  });
  assert.ok(typeof pre.heldActionHookOutput === 'function');
});
