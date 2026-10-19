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
