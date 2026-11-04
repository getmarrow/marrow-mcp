'use strict';

// Cells for the quiet-allow matrix and an oracle written from the design alone. It never loads src or dist:
// a plain allow of an unprotected call with no permit drops service text that is only the generic sentences.
const G1 = 'Do not repeat the failed path. Apply the avoid list before acting.';
const G2 = 'No identified workflow yet. Complete the checks, then commit the outcome so Marrow can reuse this path.';
const G3 = 'Proceed with the low-risk work. Marrow is using cached summaries to keep the agent hot path fast.';
const GENERIC = [G1, G2, G3];

function orderedJoins() {
  const joins = [];
  const walk = (used, text) => {
    if (used.length) joins.push(text);
    for (const g of GENERIC) if (!used.includes(g)) walk([...used, g], text ? `${text} ${g}` : g);
  };
  walk([], '');
  return joins;
}
const JOINS = orderedJoins();
const JOIN_SET = new Set(JOINS);

// Near-miss and look-alike texts that must keep the whole service text.
const KEEP_TEXTS = [
  `${G1} ${G2} Avoid: rerun without --force`,
  `Avoid: rerun without --force ${G1}`,
  `A prior committed failure for this kind of action is recorded in decision dec-1. Review it before acting. ${G1} ${G2}`,
  `${G1} ${G2} A prior committed failure for this kind of action is recorded in decision dec-1.`,
  'Arbitration is open for this action: the owner picks one proposal. ' + G1,
  'Protected baseline: this action matches a protected baseline. ' + G2,
  'Before continuing, review prior lesson les-1 for this kind of action. ' + G1,
  'Playbook pb-1 applies to this action. ' + G1 + ' ' + G2,
  `${G1} Next action: run the decision brief first.`,
  G1.replace('failed', 'failec'),
  G1.replace('Do not', 'Do nat'),
  G1.toUpperCase(),
  G1.toLowerCase(),
  `${G1} ${G1}`,
  `${G1}${G2}`,
  `${G1}. ${G2}`,
  `${G1}\n\n${G1}`,
  `\`${G1}\``,
  `"${G1}" "${G2}"`,
  `'${G1}'`,
  `${G1} ${G2}`,
  `${G1} `,
  ` ${G1}`,
  `${G1}​`,
  `${G1.slice(0, 10)}​${G1.slice(10)}`,
  `﻿${G1}`,
  `${G1} ${G2}`,
  `${G1} ${G2}`,
  `${G1}\u000b`,
  `Ｄo not repeat the failed path. Apply the avoid list before acting.`,
  G1.replace('Do', 'Dо'),
  G1.replace('Apply', 'Applу'),
  G1.replace('failed', 'failéd'),
  G1.replace('path', 'paᴛh'),
  G2.replace('Marrow', 'Marrоw'),
  G1.slice(0, -1),
  G1.slice(1),
  G1.slice(0, 30),
  `${G1} ${G2} ${G3} ${G1}`,
  `${G1} ${G2} ${G3} `.padEnd(401, ' ') + 'x',
  `${G1} ${G2}`.padEnd(401, ' '),
  `${G1} ${G2} ${G3}`.padEnd(401, '\n'),
  5,
  0,
  true,
  false,
  {},
  { text: G1 },
  [G1],
  [],
  ['x'],
  '   x   ',
  'x',
  '   ',
  '\t\r\n ',
];

// Texts that are made only of the generic sentences and so go quiet on a plain allow.
const QUIET_TEXTS = [
  ...JOINS,
  `${G1}\n${G2}`,
  `  ${G1}\t `,
  `${G1}\r\n${G2}`,
  `\n${G3}\n`,
  `${G1}   ${G2}`,
  `${G2} \t\r\n ${G1} ${G3}`,
  `${G1} ${G2}`.padEnd(400, ' '),
  `${G1} ${G2} ${G3}`.padEnd(400, '\t'),
];

const BYA_VALUES = [
  { key: 'absent', absent: true },
  { key: 'empty', value: '' },
  { key: 'null', value: null },
  ...KEEP_TEXTS.map((value, i) => ({ key: `keep${i}`, value })),
  ...QUIET_TEXTS.map((value, i) => ({ key: `generic${i}`, value })),
];

const HARNESSES = ['claude-code', 'codex', 'mcp-client', 'cursor', 'cline', 'gemini', 'grok', 'windsurf'];
// decision 'none' leaves risk_gate out of the answer.
const DECISIONS = ['allow', 'warn', 'review_required', 'owner_approval_required', 'block', '', 'none', 'allow ', 'ALLOW'];
const ALLOW_FLAGS = ['true', 'false', 'absent'];
const PLANS = ['enforced', 'advisory'];
const PROTECTED = ['true', 'false', 'absent'];
const PERMITS = ['none', 'verified', 'unverified'];
const FLAGS = ['none', 'outage', 'timedOut', 'enforcementError'];
const LEGACY = [true, false];

function buildResult(cell, outageWarning) {
  const runtime = {
    decision_id: 'decision-runtime',
    gate_receipt_id: 'gate-one',
    runtime_authorization: { id: 'gate-one', decision_id: 'decision-runtime', decision_creation_required: false },
  };
  if (cell.decision !== 'none') {
    runtime.risk_gate = {
      decision: cell.decision,
      enforced: cell.plan === 'enforced',
      reasons: [],
      ...(cell.plan === 'advisory' ? { enforcement_decision: 'advisory' } : {}),
      ...(cell.allow === 'absent' ? {} : { allow: cell.allow === 'true' }),
    };
  }
  if (!cell.bya.absent) runtime.before_you_act = cell.bya.value;
  const result = {
    runtime,
    permit: cell.permit === 'none' ? null : { permit_id: 'permit-one', verified: cell.permit === 'verified' },
  };
  if (cell.protectedRisk !== 'absent') result.protectedRisk = cell.protectedRisk === 'true';
  if (cell.flag === 'outage') result.outage = true;
  if (cell.flag === 'timedOut') result.timedOut = true;
  if (cell.flag === 'enforcementError') result.enforcementError = outageWarning || 'Marrow did not answer.';
  return result;
}

// The generic-only rule of the design: at most 400 units, ASCII space/tab/CR/LF runs are one space, exact compare.
function oracleGenericOnly(value) {
  if (typeof value !== 'string' || value.length > 400) return false;
  const collapsed = value.split(/[ \t\r\n]+/).filter((part) => part !== '').join(' ');
  return JOIN_SET.has(collapsed);
}

// The plain-allow rule of the design.
function oracleQuiet(cell) {
  if (!['claude-code', 'codex', 'mcp-client'].includes(cell.harness)) return false;
  if (cell.flag !== 'none') return false;
  if (cell.decision !== 'allow') return false;
  if (cell.allow === 'false') return false;
  if (cell.protectedRisk !== 'false') return false;
  if (cell.permit !== 'none') return false;
  return !cell.bya.absent && oracleGenericOnly(cell.bya.value);
}

// Named cells outside the generated grid. The grid never sets response_mode, so it never builds the slim advisory
// answer: response_mode slim, risk_gate_enforced false, risk_gate.allow false next to decision allow and
// enforcement_decision advisory. That answer is no plain allow (the notice is owed to the agent), so BASE's whole
// context stays: the advisory notice line, then the service text, generic sentences included. Written from the
// design and BASE's wording of the notice, never read back from src or dist.
const SLIM_ADVISORY_NOTICE = 'Marrow advisory: this plan does not enforce the pre-action gate, so the action is allowed. Gate decision: allow.';

function namedCells() {
  const text = `${G1} ${G2}`;
  return [{
    name: 'slim-advisory-allow-false',
    harnesses: ['claude-code', 'codex', 'mcp-client'],
    result: {
      runtime: {
        response_mode: 'slim',
        risk_gate_enforced: false,
        risk_gate: { allow: false, decision: 'allow', enforced: false, enforcement_decision: 'advisory', reasons: [] },
        before_you_act: text,
      },
      permit: null,
      protectedRisk: false,
    },
    expected: { hookSpecificOutput: { hookEventName: 'PreToolUse', additionalContext: `${SLIM_ADVISORY_NOTICE}\n${text}` } },
  }];
}

function* cells() {
  for (const harness of HARNESSES) for (const decision of DECISIONS) for (const allow of ALLOW_FLAGS)
    for (const plan of PLANS) for (const protectedRisk of PROTECTED) for (const permit of PERMITS)
      for (const bya of BYA_VALUES) for (const flag of FLAGS) for (const legacy of LEGACY) {
        yield { harness, decision, allow, plan, protectedRisk, permit, bya, flag, legacy };
      }
}

module.exports = { G1, G2, G3, GENERIC, JOINS, KEEP_TEXTS, QUIET_TEXTS, BYA_VALUES, cells, namedCells, buildResult, oracleGenericOnly, oracleQuiet };
