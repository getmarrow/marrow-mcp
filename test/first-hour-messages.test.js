'use strict';

// First-hour fixes: message and output changes only (copy C1-C16). The rules, reason codes and
// decisions are proved unchanged by tools/fh-diff.cjs against the base build; these tests pin the
// words, their bounds and the structured flag that replaced a string comparison.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const seatbelt = require(path.join(ROOT, 'dist', 'seatbelt', 'hook.js'));
const pre = require(path.join(ROOT, 'dist', 'hook-pre-action.js'));

const CATEGORIES = ['S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'Sx', 'hook'];
const ASCII = /^[\t\n\x20-\x7e]*$/;
const NEVER = [/\bactivate\b/, /marrow-mcp setup/, /\brisk\b/i, /\brisky\b/i, /\bscore\b/i, /\bclassifier\b/i, /Marrow AI/];

test('FH-1 C1/C2/C3: stop texts lead with the label, say what to do, and end with the code', () => {
  const lead = 'If you (the person at this machine) meant it, run it yourself in your own terminal. Agent: do not retry it another way and do not edit Marrow settings; tell the user it was stopped.';
  const keyless = seatbelt.seatbeltStopText('S2', 'S2.production_deploy', 'wrangler_production', 'seatbelt');
  assert.equal(keyless, `MARROW SEATBELT stopped this action: production deploy. ${lead} For approval prompts instead of stops, add a Marrow key: getmarrow.ai/docs#start-here (Claude Code plugin: put MARROW_API_KEY in ~/.marrow/env, chmod 600, then /reload-plugins). Code: S2.production_deploy/wrangler_production.`);
  const account = seatbelt.seatbeltStopText('S3', 'S3.package_publish', 'npm_publish', 'account');
  assert.equal(account, `MARROW SEATBELT stopped this action: package publish. ${lead} Code: S3.package_publish/npm_publish.`);
  const linked = seatbelt.seatbeltStopText('S1', 'S1.force_push', 'protected_branch', 'claimed_no_key', true);
  assert.equal(linked, `MARROW SEATBELT stopped this action: force-push or delete of a protected branch. ${lead} ${pre.CLAIMED_NO_KEY_TEXT} Code: S1.force_push/protected_branch.`);
});

test('FH-1 C9: S4 names what it protects; an unreadable script is named as unreadable, on every category', () => {
  const s4 = seatbelt.seatbeltStopText('S4', 'S4.credential_access', 'operand_secret_path', 'seatbelt');
  assert.ok(s4.startsWith('MARROW SEATBELT stopped this action: reading, copying or writing secrets (like .env files or private keys). '));
  assert.doesNotMatch(s4, /credential or secret access/);
  for (const category of CATEGORIES) {
    const text = seatbelt.seatbeltStopText(category, `${category}.x`, 'script_unreadable', 'seatbelt');
    assert.match(text, /^MARROW SEATBELT stopped this action: a script Marrow could not read \(treated as .+\)\. If you /, category);
  }
  assert.ok(seatbelt.seatbeltStopText('S2', 'S2.production_deploy', 'script_unreadable', 'seatbelt').startsWith('MARROW SEATBELT stopped this action: a script Marrow could not read (treated as production deploy). '));
  // The other labels are unchanged.
  for (const [category, label] of [['S0', 'a change to Marrow seatbelt settings or an owner-only command'], ['S1', 'force-push or delete of a protected branch'], ['S2', 'production deploy'], ['S3', 'package publish'], ['S5', 'recursive delete outside the workspace'], ['Sx', 'obfuscated execution'], ['hook', 'a safety check that could not finish']]) {
    assert.ok(seatbelt.seatbeltStopText(category, `${category}.x`, 'some_reason', 'account').startsWith(`MARROW SEATBELT stopped this action: ${label}. `), category);
  }
});

test('FH-1: no new text tells anyone to run activate or marrow-mcp setup, uses the avoided words, or leaves ASCII', () => {
  const texts = [pre.NO_KEY_TEXT, pre.SEATBELT_HELD_TEXT];
  for (const mode of ['seatbelt', 'account', 'claimed_no_key']) {
    for (const linked of [true, false]) for (const category of CATEGORIES) texts.push(seatbelt.seatbeltStopText(category, `${category}.rule`, 'script_unreadable', mode, linked));
  }
  for (const text of texts) {
    assert.match(text, ASCII);
    for (const word of NEVER) assert.doesNotMatch(text, word, text.slice(0, 60));
  }
});

test('FH-1 C7: the no-key hold keeps the substring the plugin launcher test matches', () => {
  assert.match(pre.NO_KEY_TEXT, /no API key/);
  assert.ok(pre.NO_KEY_TEXT.startsWith('Marrow has no API key on this machine, so it held this action. '));
  assert.ok(pre.NO_KEY_TEXT.endsWith('Agent: do not retry this action.'));
  assert.ok(pre.NO_KEY_TEXT.length <= 500);
});

test('FH-1 C6: the held text keeps its prefix and says what the person can do', () => {
  assert.ok(pre.SEATBELT_HELD_TEXT.startsWith('MARROW SEATBELT held this action: this host cannot show its own approval prompt here, and no Marrow account is linked to approve it. '));
  assert.ok(pre.SEATBELT_HELD_TEXT.endsWith('For approval prompts, add a Marrow key: getmarrow.ai/docs#start-here.'));
  assert.ok(pre.SEATBELT_HELD_TEXT.length <= 500);
});

test('FH-1: every stop keeps its code at the end on each host; Gemini stays within its guard limit of 500', () => {
  const reasons = ['operand_secret_path', 'script_unreadable', 'npm_publish', 'hook_error'];
  const rules = ['S4.credential_access', 'S2.production_deploy', 'S0.owner_only', 'U5.fail_closed'];
  for (const harness of ['claude-code', 'codex', 'cursor', 'cline', 'gemini']) {
    for (const mode of ['seatbelt', 'account']) {
      for (const category of CATEGORIES) {
        for (const rule of rules) {
          for (const reason of reasons) {
            const out = pre.localLoopGuardDenyOutput(harness, seatbelt.seatbeltStopText(category, rule, reason, mode));
            const shown = out.hookSpecificOutput ? out.hookSpecificOutput.permissionDecisionReason : out.permission ? out.user_message : out.errorMessage || out.reason;
            assert.ok(shown.endsWith(` Code: ${rule}/${reason}.`), `${harness} ${mode} ${category}: ${shown.slice(-90)}`);
            assert.ok(shown.length <= (harness === 'gemini' ? 500 : 800));
          }
        }
      }
    }
  }
  // The longest codes the format allows are cut at the host's limit and never throw.
  const longest = seatbelt.seatbeltStopText('S4', `S4.${'y'.repeat(61)}`, 'z'.repeat(64), 'seatbelt');
  assert.ok(pre.localLoopGuardDenyOutput('gemini', longest).reason.length <= 500);
  assert.ok(pre.localLoopGuardDenyOutput('claude-code', longest).hookSpecificOutput.permissionDecisionReason.length <= 800);
  assert.equal(pre.localLoopGuardDenyOutput('windsurf', longest), null);
  assert.deepEqual(Object.keys(pre.localLoopGuardDenyOutput('gemini', longest)).sort(), ['decision', 'reason']);
});

test('FH-1 consumer: the Cline credentials branch follows a structured flag, not a text comparison', () => {
  const result = (extra) => ({ runtime: null, permit: null, protectedRisk: true, ...extra });
  const text = 'any words at all';
  assert.deepEqual(pre.clinePreActionHookOutput(result({ enforcementError: text, credentialsUnavailable: true })), { cancel: true, errorMessage: text });
  // Without the flag the same words are not treated as a missing key, whatever they say.
  for (const words of [pre.NO_KEY_TEXT, pre.CLAIMED_NO_KEY_TEXT, pre.SETUP_UNCONFIRMED_TEXT]) {
    const out = pre.clinePreActionHookOutput(result({ enforcementError: words }));
    assert.equal(out.cancel, true);
    assert.match(out.errorMessage, /^Marrow could not confirm a permit for this protected action\./);
  }
  // The existing failures keep their words.
  assert.match(pre.clinePreActionHookOutput(result({ failure: 'unavailable' })).errorMessage, /^Marrow is unavailable/);
  assert.match(pre.clinePreActionHookOutput(result({ failure: 'credential_scope' })).errorMessage, /^This Marrow API key is not authorized/);
});
