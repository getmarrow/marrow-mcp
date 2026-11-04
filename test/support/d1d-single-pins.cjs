'use strict';
// Test-only. D1d round 4 (the one extra test-only round, OWNER-DECISIONS-20261104 item 24 (a)): single-command texts that reach each lowering clause the round 2 tests could not.
// The round 2 pins for m02, m17, m27, m28, m29, m30 used command LISTS; round 3's lone-command rule (src/seatbelt/mapper.ts:1513-1521, called at :1982) makes every list a bad slice before
// those clauses are read, so those tests passed without testing the clause. Every text here is ONE simple command (or one command and a loop word the parser drops) that the lone-command
// rule accepts, and master's answer for it is the unlowered one: the hook asks the original class (runtime, think, issue, verify) and sends no base_class. Used by
// test/d1d-single-command.test.js (the hook, runs on master and on the tip) and test/d1d-single-reach.test.js (the mapper and the label, tip only).
const crypto = require('node:crypto');
const { allow, protectedPath, hashOf } = require('./d1d-hook-harness.cjs');

const MODES = ['allow', 'clear'];
// What master a1bf437a0a13 asks for each text below, in both modes: the original class, never a lowered question.
const MASTER_CALLS = ['runtime', 'think', 'enforcement:issue', 'enforcement:verify'];
const HOOK_LINE = { m02: 'src/hook-pre-action.ts:1089', m30: 'src/hook-pre-action.ts:1092', m17: 'src/hook-pre-action.ts:1205' };
const LOOP_LINE = { m26: 'src/seatbelt/mapper.ts:1982', m27: 'src/seatbelt/mapper.ts:1509', m28: 'src/seatbelt/mapper.ts:1508', m29: 'src/seatbelt/mapper.ts:1508' };

// kind: comment = a shipping word repeated in a comment or left outside every slot (slice.ok true, no lowered candidate through the count proof and the mask);
//       time = the word `time` in a data position (slice.ok true; the hook's `time` test holds it); loop = a complete command, then an unterminated loop word the parser drops
//       (the lone-command rule passes: one command; the loop-word check rejects: slice.ok false); time-keyword = the keyword `time` before the program (held by the first-word rule AND the hook's `time` test).
// word: for comment pins, the shipping word whose text count is above its slot count.
const pin = (id, plants, kind, clause, text, word) => ({ id, plants, kind, clause, text, word });
const PINS = [
  // m02: the count proof (I-A12): the word is in a recorded slot once and in a comment once.
  pin('m02-tail', ['m02'], 'comment', HOOK_LINE.m02, 'egrep -n deploy f # deploy', 'deploy'),
  pin('m02-head-comment', ['m02'], 'comment', HOOK_LINE.m02, '# deploy\negrep -n deploy f', 'deploy'),
  pin('m02-next-line', ['m02'], 'comment', HOOK_LINE.m02, 'egrep -n deploy f\n# deploy', 'deploy'),
  pin('m02-git-grep', ['m02'], 'comment', HOOK_LINE.m02, 'git grep -n deploy HEAD # deploy', 'deploy'),
  pin('m02-redirect', ['m02'], 'comment', HOOK_LINE.m02, 'egrep -n deploy f 2>/dev/null # deploy', 'deploy'),
  pin('m02-commit-word', ['m02'], 'comment', HOOK_LINE.m02, 'git grep -n commit HEAD # commit', 'commit'),
  pin('m02-heredoc', ['m02'], 'comment', HOOK_LINE.m02, "cat <<'EOF'\ndeploy notes\nEOF\n# deploy", 'deploy'),
  // m30: the slice mask replaces only the proven words; a shipping word in a comment is in no slot and stays visible to the classifier.
  pin('m30-tail', ['m30'], 'comment', HOOK_LINE.m30, 'git grep -c deploy HEAD # npm publish', 'publish'),
  pin('m30-next-line', ['m30'], 'comment', HOOK_LINE.m30, 'egrep -n deploy f\n# npm publish', 'publish'),
  pin('m30-head-comment', ['m30'], 'comment', HOOK_LINE.m30, '# npm publish\negrep -n deploy f', 'publish'),
  pin('m30-heredoc', ['m30'], 'comment', HOOK_LINE.m30, "cat <<'EOF'\ndeploy notes\nEOF\n# npm publish", 'publish'),
  // m17: the hook's `time` test (the second layer of the `time` form) also fires on a data-position `time`.
  pin('m17-operand', ['m17'], 'time', HOOK_LINE.m17, 'egrep -n deploy time'),
  pin('m17-quoted-pattern', ['m17'], 'time', HOOK_LINE.m17, "egrep -n 'time deploy' f"),
  pin('m17-file-name', ['m17'], 'time', HOOK_LINE.m17, 'egrep -n deploy time.md'),
  pin('m17-comment', ['m17'], 'time', HOOK_LINE.m17, 'egrep -n deploy f # time'),
  pin('m17-pathspec', ['m17'], 'time', HOOK_LINE.m17, 'git grep -n deploy HEAD -- time/x.ts'),
  // m17 + m328 (p01): the keyword `time` before the program is held by two independent layers; only the pair lowers it through the hook.
  pin('time-keyword', ['m17+m328'], 'time-keyword', 'src/hook-pre-action.ts:1205 and src/seatbelt/mapper.ts:1982', 'time egrep -n deploy f'),
  // m26 (hasLoopCommand off) and m27, m28, m29 (a branch of the loop-word test): one complete command, then a loop word with nothing after it.
  pin('loop-semi-while', ['m26'], 'loop', LOOP_LINE.m26, 'egrep -n deploy f; while'),
  pin('loop-semi-until', ['m26', 'm29'], 'loop', `${LOOP_LINE.m26} ${LOOP_LINE.m29}`, 'egrep -n deploy f; until'),
  pin('loop-newline-while', ['m26'], 'loop', LOOP_LINE.m26, 'egrep -n deploy f\nwhile'),
  pin('loop-continuation', ['m26', 'm27'], 'loop', `${LOOP_LINE.m26} ${LOOP_LINE.m27}`, 'egrep -n deploy f; wh\\\nile'),
  pin('loop-do-while', ['m26', 'm28'], 'loop', `${LOOP_LINE.m26} ${LOOP_LINE.m28}`, 'egrep -n deploy f; do while'),
  pin('loop-if-while', ['m26', 'm28'], 'loop', `${LOOP_LINE.m26} ${LOOP_LINE.m28}`, 'egrep -n deploy f; if while'),
  pin('loop-then-until', ['m26', 'm28', 'm29'], 'loop', `${LOOP_LINE.m26} ${LOOP_LINE.m28} ${LOOP_LINE.m29}`, 'egrep -n deploy f; then until'),
  pin('loop-bang-while', ['m26', 'm28'], 'loop', `${LOOP_LINE.m26} ${LOOP_LINE.m28}`, 'egrep -n deploy f; ! while'),
  pin('loop-and-while', ['m26'], 'loop', LOOP_LINE.m26, 'egrep -n deploy f && while'),
  pin('loop-or-until', ['m26', 'm29'], 'loop', `${LOOP_LINE.m26} ${LOOP_LINE.m29}`, 'egrep -n deploy f || until'),
];

// The stub service of the lowering cells: `allow` answers every runtime question with a plain allow; `clear` answers it with a bound clearance of whatever it was asked.
const service = (mode) => (pathname, body) => {
  if (pathname !== '/v1/agent/runtime') return protectedPath(pathname, body);
  return mode === 'clear' ? allow({ decline_check: { state: 'clear', action: hashOf(body.normalized_action) } }) : allow();
};
const eventFor = (command) => ({ session_id: 's1', tool_use_id: 't1', tool_name: 'Bash', tool_input: { command }, cwd: '/work/repo' });
const callName = (c) => c.pathname.replace('/v1/agent/', '') + (c.body.operation ? `:${c.body.operation}` : '');
// The answer the host and the service see: the stdout bytes and every call (path and full body), as one digest. The keyed hashes of the text (command_sha256, input_sha256, exact_hmac) are
// HMACs under a per-device salt and the correlation id is random per call: a different value in every test process, so each is replaced by a marker after its shape (hex, 32 or 64
// characters) is checked. Every other byte of every body, and the stdout, is in the digest.
const KEYED = /^(?:command_sha256|input_sha256|exact_hmac|correlation_id)$/;
const unkeyed = (value) => {
  if (Array.isArray(value)) return value.map(unkeyed);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, KEYED.test(k) ? (/^[0-9a-f]{32}(?:[0-9a-f]{32})?$/.test(String(v)) ? `<keyed ${String(v).length}>` : `<BAD ${typeof v}>`) : unkeyed(v)]));
};
const digestOf = (run) => crypto.createHash('sha256').update(JSON.stringify({ output: run.output, calls: unkeyed(run.calls) })).digest('hex');

module.exports = { PINS, MODES, MASTER_CALLS, service, eventFor, callName, digestOf };
