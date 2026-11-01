'use strict';

// The hold-plan table of the no-freeze rows (M2-5, M6): what `planHeldAction` answers for every host, every kind of
// hold and every Claude Code mode, built from one build's dist folder. `node test/support/hold-plan-table.cjs <dist>`
// prints it as JSON, so the BASE build and a candidate build give two tables to compare (the BASE table is committed in
// test/fixtures/no-freeze-holds/base-hold-plans.json and pinned by test/no-freeze-holds.test.js).
//
// Claude Code rows run the real `ownerApprovalPrompt` (mode, entrypoint and attended evidence decide `claudePrompt`); the
// other hosts' rows run every combination of the inputs that host's branches read, and each (host, hold kind) cell is
// kept as the sha256 of its plans, so a changed plan names the cell that changed.
const { createHash } = require('node:crypto');
const { mkdirSync, mkdtempSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const sha = (value) => createHash('sha256').update(JSON.stringify(value)).digest('hex');

function holdRuntimes(hostRuntime) {
  const link = (receipt, approval = {}) => hostRuntime(receipt, { approval_link_endpoint: `/v1/agent/gate-receipts/${receipt}/approval-link`, ...approval });
  const legacy = hostRuntime('gate-t');
  for (const field of ['host_approval_endpoint', 'host_approval_accepted', 'host_approval_trust', 'approval_categories', 'verified_approval_required', 'verified_approval_categories']) delete legacy.completion_contract.owner_approval[field];
  legacy.completion_contract.owner_approval.approval_authority = 'authenticated_dashboard_owner';
  return {
    ordinary: hostRuntime('gate-t'),
    ordinary_ping: link('gate-t', { approval_link_available: true, approval_link_reason: 'unattended_owner_ping', unattended_owner_ping: true }),
    owner_locked: link('gate-t', { host_approval_accepted: false, host_approval_refusal_reason: 'verified_approval_required', verified_approval_required: true, verified_approval_categories: ['production_deploy'], approval_authority: 'account_owner', approval_link_available: true, approval_link_reason: 'owner_locked' }),
    owner_declined: link('gate-t', { host_approval_accepted: false, host_approval_refusal_reason: 'owner_decline_stands', approval_authority: 'account_owner', verified_approval_required: null, approval_link_available: true, approval_link_reason: 'owner_decline_stands' }),
    state_unavailable: hostRuntime('gate-t', { host_approval_accepted: false, host_approval_refusal_reason: 'approval_state_unavailable', approval_authority: 'account_owner', verified_approval_required: null }),
    legacy_service: legacy,
  };
}

// Claude Code: (mode, entrypoint, evidence) -> the event and env `ownerApprovalPrompt` reads.
const CLAUDE_VARIANTS = {
  'default+attended': { mode: 'default', attended: true },
  'default+unattended': { mode: 'default', attended: false },
  'acceptEdits+attended': { mode: 'acceptEdits', attended: true },
  'acceptEdits+unattended': { mode: 'acceptEdits', attended: false },
  'auto+scratchpad': { mode: 'auto', scratchpad: true, attended: true },
  'auto+no-scratchpad': { mode: 'auto', attended: true },
  'auto+unattended': { mode: 'auto', attended: false },
  plan: { mode: 'plan', attended: true },
  dontAsk: { mode: 'dontAsk', attended: true },
  bypassPermissions: { mode: 'bypassPermissions', attended: true },
  'mode absent': { mode: undefined, attended: true },
  'mode unknown value': { mode: 'default; rm', attended: true },
  'headless (sdk-cli)': { mode: 'default', attended: true, entrypoint: 'sdk-cli' },
  'headless auto (sdk-ts)': { mode: 'auto', scratchpad: true, attended: true, entrypoint: 'sdk-ts' },
};

function buildTable(dist, helpers) {
  const approval = require(join(dist, 'host-approval.js'));
  const hook = require(join(dist, 'hook-pre-action.js'));
  const contract = require(join(dist, 'runtime-contract.js'));
  let marker = null;
  try { marker = require(join(dist, 'attended-marker.js')); } catch { marker = null; } // the BASE build has none
  const guidanceOf = Object.fromEntries(Object.entries(holdRuntimes(helpers.hostRuntime)).map(([name, runtime]) => {
    const guidance = contract.ordinaryApprovalGuidance(contract.normalizeRuntimeResult(runtime));
    if (!guidance) throw new Error(`no guidance for ${name}`);
    return [name, guidance];
  }));
  // The scratchpad folder only has to be a non-empty string (the hook never reads it); nothing is ever written under it.
  const scratchpad = join(mkdtempSync(join(tmpdir(), 'marrow-hpt-scratch-')), 'scratchpad');
  const attendedSession = 'table-session-attended';
  if (marker) marker.recordAttendedPrompt(attendedSession);
  const claude = {};
  for (const [variant, spec] of Object.entries(CLAUDE_VARIANTS)) {
    const event = { session_id: spec.attended ? attendedSession : 'table-session-nobody', permission_mode: spec.mode, ...(spec.scratchpad ? { scratchpad_dir: scratchpad } : {}) };
    const prompt = hook.ownerApprovalPrompt('claude-code', event, spec.entrypoint ? { CLAUDE_CODE_ENTRYPOINT: spec.entrypoint } : {});
    for (const [kind, guidance] of Object.entries(guidanceOf)) {
      const plan = approval.planHeldAction({
        guidance, host: 'claude-code', hookEvent: 'PreToolUse', reason: 'Production deploys need approval.', claudePrompt: prompt,
        unattended: prompt.headless === true, typedReply: false, attendedConfirmed: false, hostPromptOff: false,
      });
      claude[`claude-code|${variant}|${kind}`] = { prompt: { available: prompt.available, headless: prompt.headless === true }, plan };
    }
  }
  const others = {};
  for (const host of ['cursor', 'codex', 'gemini', 'grok', 'cline', 'windsurf']) {
    for (const [kind, guidance] of Object.entries(guidanceOf)) {
      const cells = [];
      for (const unattended of [false, true]) for (const attendedConfirmed of [false, true]) for (const typedReply of [false, true])
        for (const cursorInteractive of [null, false, true]) for (const hostPromptOff of [false, true])
          for (const hookEvent of ['PreToolUse', 'beforeShellExecution', 'UserPromptSubmit']) for (const claudePrompt of [undefined, { available: true, unavailableReason: '' }, { available: false, unavailableReason: 'x', noFreeze: true }]) {
            cells.push(approval.planHeldAction({ guidance, host, hookEvent, reason: 'r', cursorInteractive, typedReply, unattended, attendedConfirmed, hostPromptOff, claudePrompt }));
          }
      others[`${host}|${kind}`] = { cells: cells.length, sha256: sha(cells) };
    }
  }
  return { claude, others };
}

module.exports = { buildTable, CLAUDE_VARIANTS, holdRuntimes };

if (require.main === module) {
  // A scratch HOME: the attended marker of the table's own session is written there, never in the real one.
  const home = mkdtempSync(join(tmpdir(), 'marrow-hold-plan-table-'));
  mkdirSync(join(home, '.marrow'), { mode: 0o700, recursive: true });
  process.env.HOME = home;
  const dist = require('node:path').resolve(process.argv[2] || join(__dirname, '..', '..', 'dist'));
  process.stdout.write(`${JSON.stringify(buildTable(dist, require('./first-hour-harness.cjs')), null, 1)}\n`);
}
