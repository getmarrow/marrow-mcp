import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { marrowCommit, marrowHostApproval, marrowOwnerApprovalStatus, marrowThink } from './index';
import { isMcpHookTool } from './hook-tool-policy';
import { stableToolCorrelation, type NativeHookHarness } from './hook-contract';
import type { OrdinaryApprovalGuidance } from './runtime-contract';
import {
  findHolds,
  markDialogShown,
  recordHold,
  sessionMarker,
  setSessionMarker,
  updateHold,
  APPROVAL_CODE,
  type HoldCommit,
  type HoldRecord,
  type HoldReport,
  type HoldScope,
} from './host-approval-state';
import type { MarrowOwnerApprovalStatus } from './types';

/**
 * Chat and terminal approvals: the operator answers a held action in the
 * host's own permission prompt, and the host's Marrow hook records that answer
 * with the server (client-attested). Rules (backend contract, section 3):
 * - ask only where the host really shows its own prompt for this call, and only
 *   when the server says a host approval counts for this hold;
 * - report exactly what the host reported, with its marker event; never invent
 *   an answer, a marker or a time; never let the model report an approval;
 * - a decline is only a permission rejection, never an interruption;
 * - a proof-required hold is committed by the agent with its proof (a hook
 *   commit without proof would leave an unverified observation that blocks the
 *   trusted close).
 */

export type ApprovalHost = 'claude-code' | 'codex' | 'cursor' | 'cline' | 'windsurf' | 'gemini' | 'grok' | 'other';

export const HOST_LABEL: Record<ApprovalHost, string> = {
  'claude-code': 'Claude Code',
  codex: 'Codex',
  cursor: 'Cursor',
  cline: 'Cline',
  windsurf: 'Windsurf',
  gemini: 'Gemini CLI',
  grok: 'Grok',
  other: 'the host',
};

export function approvalHostFor(harness: NativeHookHarness, env: NodeJS.ProcessEnv = process.env): ApprovalHost {
  if (harness === 'claude-code' || (harness === 'mcp-client' && env.CLAUDE_CODE_CHILD_SESSION === '1')) return 'claude-code';
  if (harness === 'mcp-client') return 'other';
  return harness;
}

/** Cursor events on which a hook "ask" is enforced (never preToolUse). */
export const CURSOR_ASK_EVENTS = new Set(['beforeShellExecution', 'beforeMCPExecution']);

const HOST_SESSION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
export const HOST_APPROVAL_REQUEST_TIMEOUT_MS = 4_000;
const SETTLE_BUDGET_MS = 9_000;

export type HoldContext = {
  apiKey: string;
  baseUrl: string;
  /** The Marrow session (X-Marrow-Session-Id) the hold was issued to. */
  sessionId: string;
  agentId?: string;
  harness: NativeHookHarness;
  host: ApprovalHost;
  /** The host's own session or conversation id, as reported to the server. */
  hostSessionId: string;
  home?: string;
};

export function hostSessionIdFor(candidates: unknown[], fallback: string): string {
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && HOST_SESSION_ID.test(candidate.trim())) return candidate.trim();
  }
  return HOST_SESSION_ID.test(fallback) ? fallback : `session-${createHash('sha256').update(fallback).digest('hex').slice(0, 32)}`;
}

function scopeOf(ctx: HoldContext): HoldScope {
  return { apiKey: ctx.apiKey, baseUrl: ctx.baseUrl, agentId: ctx.agentId || null };
}

function bounded(value: string, limit: number): string {
  return value.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, limit);
}

function untilText(expiresAt: string | null): string {
  return expiresAt ? ` until ${expiresAt}` : '';
}

/** Why only the account owner (dashboard) can approve this hold. */
function dashboardOnlyReason(guidance: OrdinaryApprovalGuidance): string {
  if (guidance.hostApprovalRefusal === 'owner_decline_stands') {
    return `The account owner declined this action${guidance.ownerDeclinedAt ? ` at ${guidance.ownerDeclinedAt}` : ' earlier'}, so only the owner can approve it now.`;
  }
  if (guidance.hostApprovalRefusal === 'approval_state_unavailable') {
    return 'Marrow could not check whether a chat or terminal approval counts for this hold, so only the account owner can approve it.';
  }
  if (guidance.verifiedApprovalRequired === true) {
    return `The owner requires a verified approval for ${guidance.verifiedApprovalCategories.join(', ') || 'this kind of'} actions, so a chat or terminal approval does not count.`;
  }
  if (guidance.verifiedApprovalRequired === null) {
    return 'Marrow could not read the account approval settings, so only the account owner can approve it.';
  }
  return 'A chat or terminal approval is not available for this hold.';
}

export type HoldPlan =
  | { kind: 'ask'; promptText: string }
  | { kind: 'deny'; agentText: string; userText: string; code: boolean };

/**
 * Decides how a hook answers an ordinary held action. Model-facing text never
 * contains an approval code; a code goes only to a user-only channel.
 */
export function planHeldAction(input: {
  guidance: OrdinaryApprovalGuidance;
  host: ApprovalHost;
  hookEvent: string;
  reason: string;
  /** Claude Code: whether a hook "ask" reaches a person in this permission mode and version. */
  claudePrompt?: { available: boolean; unavailableReason: string };
  /** Cursor: true only when sessionStart reported a local, non-background session. */
  cursorInteractive?: boolean | null;
  /** Cursor: the beforeSubmitPrompt hook has run for this conversation. */
  cursorPromptHook?: boolean | null;
}): HoldPlan {
  const { guidance, host } = input;
  const reason = input.reason ? ` Reason: ${bounded(input.reason, 200)}` : '';
  const id = guidance.gateReceiptId;
  // Shown in the host's own prompt (to the operator, never to the agent).
  const notice = guidance.operatorNotice ? ` Note: ${guidance.operatorNotice}` : '';
  if (guidance.hostApprovalAccepted) {
    if (host === 'claude-code' && input.claudePrompt?.available) {
      return {
        kind: 'ask',
        promptText: bounded(`Marrow holds this action for your approval. Approve only if you authorize this exact action; Marrow records your answer (gate receipt ${id}).${notice}${reason}`, 500),
      };
    }
    if (host === 'cursor' && CURSOR_ASK_EVENTS.has(input.hookEvent) && input.cursorInteractive === true) {
      return {
        kind: 'ask',
        promptText: bounded(`Marrow holds this action for your approval. Approve only if you authorize this exact action (gate receipt ${id}).${notice}${reason}`, 500),
      };
    }
  }
  const noPrompt = !guidance.hostApprovalAccepted
    ? dashboardOnlyReason(guidance)
    : host === 'claude-code'
    ? `No approval prompt is available here (${input.claudePrompt?.unavailableReason || 'this session cannot prompt'}).`
    : host === 'cursor'
    ? 'Cursor shows a Marrow approval prompt only for shell and MCP calls in a local interactive session.'
    : `${HOST_LABEL[host]} cannot show an approval prompt for a held action.`;
  const agentText = bounded(
    `Marrow is holding this action for approval (gate receipt ${id}), so it did not run.${reason} ${noPrompt} The account owner can approve it in the Marrow dashboard${untilText(guidance.expiresAt)}. After approval, retry this exact action; Marrow checks the approval when it is retried. Do not report or claim an approval yourself.`,
    500,
  );
  const typed = host === 'cursor' && guidance.hostApprovalAccepted && input.cursorInteractive === true && input.cursorPromptHook === true;
  return { kind: 'deny', agentText, userText: agentText, code: typed };
}

/** User-only text with the typed-reply code (Cursor user_message). Never sent to the agent. */
export function typedReplyUserText(agentText: string, code: string): string {
  return bounded(`${agentText} Or approve it here: send the message "marrow approve ${code}" (or "marrow decline ${code}"), then let the agent retry.`, 600);
}

export type RecordHoldInput = {
  guidance: OrdinaryApprovalGuidance;
  correlation: string;
  toolUseId: string | null;
  generationId: string | null;
  toolName: string;
  hookEvent: string;
  mode: 'ask' | 'wait';
  withCode: boolean;
  preActionEventId: string | null;
  action: { action: string; target: string; type: string; surfaces: string[] };
};

export function rememberHold(ctx: HoldContext, input: RecordHoldInput): HoldRecord {
  return recordHold(scopeOf(ctx), {
    host: ctx.host,
    harness: ctx.harness,
    session_id: ctx.sessionId,
    host_session_id: ctx.hostSessionId,
    agent_id: ctx.agentId || null,
    correlation: input.correlation,
    tool_use_id: input.toolUseId,
    generation_id: input.generationId,
    tool_name: input.toolName.slice(0, 256),
    hook_event: input.hookEvent,
    mode: input.mode,
    gate_receipt_id: input.guidance.gateReceiptId,
    decision_id: input.guidance.decisionId,
    asked_at: new Date().toISOString(),
    pre_action_event_id: input.preActionEventId,
    proof_required: input.guidance.proofRequired,
    proof_fields: input.guidance.proofFields,
    expires_at: input.guidance.expiresAt,
    action: {
      action: input.action.action.slice(0, 512),
      target: input.action.target.slice(0, 256),
      type: input.action.type.slice(0, 64),
      surfaces: input.action.surfaces.slice(0, 16),
    },
    withCode: input.withCode,
  }, ctx.home);
}

/** PermissionRequest (pass-through): the host is about to show its own dialog for an asked call. */
export function noteDialogShown(ctx: HoldContext, correlation: string): HoldRecord | null {
  return markDialogShown(scopeOf(ctx), { correlation, sessionId: ctx.sessionId }, new Date().toISOString(), ctx.home);
}

function statusTimeout(ms = HOST_APPROVAL_REQUEST_TIMEOUT_MS): { signal: AbortSignal; cancel: () => void } {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  timer.unref?.();
  return { signal: controller.signal, cancel: () => clearTimeout(timer) };
}

async function readStatus(ctx: HoldContext, hold: HoldRecord): Promise<{ status: MarrowOwnerApprovalStatus | null; notFound: boolean; failed: boolean }> {
  const timeout = statusTimeout();
  try {
    const result = await marrowOwnerApprovalStatus(ctx.apiKey, ctx.baseUrl, hold.gate_receipt_id, hold.session_id, hold.agent_id || undefined, timeout.signal);
    return result.kind === 'not_found' ? { status: null, notFound: true, failed: false } : { status: result.status, notFound: false, failed: false };
  } catch {
    return { status: null, notFound: false, failed: true };
  } finally {
    timeout.cancel();
  }
}

function approvedByText(status: MarrowOwnerApprovalStatus): string {
  if (status.approval_source === 'host_prompt') {
    return status.approval_answered_by === 'host_allow_rule' ? 'an allow rule in the host (client-attested)' : 'the operator (client-attested)';
  }
  return 'the account owner';
}

export type WaitingResolution =
  | { kind: 'allow'; hold: HoldRecord; contextText: string }
  | { kind: 'deny'; hold: HoldRecord; agentText: string; userText: string };

/**
 * The same action, retried after a hold that waited (denied while it waited
 * for an approval). Reads the hold's status first: approved allows it once on
 * the same gate receipt; pending denies again without a new hold; declined,
 * expired or used fall back to the normal flow (null).
 */
export async function resumeWaitingHold(ctx: HoldContext, input: {
  correlation: string;
  toolUseId: string | null;
  generationId: string | null;
}): Promise<WaitingResolution | null> {
  let holds: HoldRecord[];
  try {
    holds = findHolds(scopeOf(ctx), { correlation: input.correlation, sessionId: ctx.sessionId, mode: 'wait', states: ['open'] }, ctx.home);
  } catch {
    return null;
  }
  const hold = holds[holds.length - 1];
  if (!hold) return null;
  const read = await readStatus(ctx, hold);
  // Marrow unreachable: the normal flow decides (its outage policy applies).
  if (read.failed) return null;
  const status = read.status;
  if (!status || read.notFound) {
    updateHold(scopeOf(ctx), hold.id, () => null, ctx.home);
    return null;
  }
  if (status.state === 'approved') {
    const allowed = updateHold(scopeOf(ctx), hold.id, (current) => ({
      ...current,
      state: 'allowed',
      tool_use_id: input.toolUseId,
      generation_id: input.generationId,
      decision_id: current.decision_id || status.decision_id,
    }), ctx.home);
    if (!allowed) return null;
    return {
      kind: 'allow',
      hold: allowed,
      contextText: bounded(`Marrow: ${approvedByText(status)} approved this held action (gate receipt ${hold.gate_receipt_id}). Run only this exact action; Marrow records its outcome on that receipt.`, 400),
    };
  }
  if (status.state === 'pending' || status.state === 'unavailable') {
    const text = bounded(`Marrow is still holding this action for approval (gate receipt ${hold.gate_receipt_id}), so it did not run. The account owner can approve it in the Marrow dashboard${untilText(status.expires_at || hold.expires_at)}; then retry this exact action. Do not report or claim an approval yourself.`, 500);
    return {
      kind: 'deny',
      hold,
      agentText: text,
      userText: hold.code ? typedReplyUserText(text, hold.code) : text,
    };
  }
  if (status.state === 'declined') {
    const who = status.approval_source === 'host_prompt' ? `the operator declined it in ${HOST_LABEL[ctx.host]}` : 'the account owner declined it';
    await closeAsDenial(ctx, hold, `Denied by Marrow pre-action gate: ${who} (gate receipt ${hold.gate_receipt_id}); the action did not run.`);
  }
  updateHold(scopeOf(ctx), hold.id, () => null, ctx.home);
  return null;
}

function idempotencyFor(hold: HoldRecord, kind: string): string {
  return `mcp-host-approval:${createHash('sha256').update(`${kind}\n${hold.gate_receipt_id}`).digest('hex').slice(0, 40)}`;
}

async function ensureDecision(ctx: HoldContext, hold: HoldRecord, signal: AbortSignal): Promise<string | null> {
  if (hold.decision_id) return hold.decision_id;
  try {
    const decision = await marrowThink(ctx.apiKey, ctx.baseUrl, {
      action: hold.action.action,
      target: hold.action.target,
      surfaces: hold.action.surfaces,
      type: hold.action.type,
      source_kind: 'integration',
      ...(hold.harness !== 'mcp-client' ? { source_meta: { client: hold.harness } } : {}),
    }, hold.session_id, hold.agent_id || undefined, signal);
    const decisionId = typeof decision.decision_id === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{2,199}$/.test(decision.decision_id) ? decision.decision_id : null;
    if (decisionId) updateHold(scopeOf(ctx), hold.id, (current) => ({ ...current, decision_id: decisionId }), ctx.home);
    return decisionId;
  } catch {
    return null;
  }
}

async function commitHold(ctx: HoldContext, hold: HoldRecord, commit: HoldCommit, signal: AbortSignal): Promise<'committed' | 'unverified' | 'failed'> {
  const decisionId = hold.decision_id || await ensureDecision(ctx, hold, signal);
  if (!decisionId) return 'failed';
  try {
    const result = await marrowCommit(ctx.apiKey, ctx.baseUrl, {
      decision_id: decisionId,
      success: commit.success,
      outcome: commit.outcome,
      gate_receipt_id: hold.gate_receipt_id,
      auto_gate: false,
    }, hold.session_id, hold.agent_id || undefined, signal, idempotencyFor(hold, commit.success ? 'commit' : 'denial'));
    return result.committed === true ? 'committed' : 'unverified';
  } catch {
    return 'failed';
  }
}

async function closeAsDenial(ctx: HoldContext, hold: HoldRecord, outcome: string): Promise<void> {
  const timeout = statusTimeout(3_000);
  try {
    await commitHold(ctx, hold, { success: false, outcome: bounded(outcome, 480) }, timeout.signal);
  } finally {
    timeout.cancel();
  }
}

export type DeliveryResult =
  | { kind: 'recorded'; answeredBy: 'host_operator' | 'host_allow_rule'; verdict: 'approved' | 'declined'; committed: 'committed' | 'unverified' | 'failed' | 'skipped' }
  | { kind: 'already_approved'; committed: 'committed' | 'unverified' | 'failed' | 'skipped' }
  | { kind: 'queued' }
  | { kind: 'refused'; code: string | null; committed: 'committed' | 'unverified' | 'failed' | 'skipped' }
  | { kind: 'dropped'; code: string | null };

const REFUSED_AFTER_RUN = new Set([
  'MARROW_OWNER_APPROVAL_DECLINED',
  'MARROW_OWNER_DECLINE_STANDS',
  'MARROW_VERIFIED_OWNER_APPROVAL_REQUIRED',
  'MARROW_PRE_ACTION_GATE_EXPIRED',
  'MARROW_PRE_ACTION_GATE_USED',
  'MARROW_ARBITRATION_OWNER_APPROVAL_REQUIRED',
]);

function backoffMs(attempts: number, retryAfterMs: number | null): number {
  const exponential = Math.min(60_000, 1_000 * 2 ** Math.min(attempts, 6));
  return Math.max(exponential, retryAfterMs ?? 0);
}

/**
 * Sends a hold's queued report (and the commit that follows it) once. A
 * retryable failure (network, 409 STATE_UNAVAILABLE, 429, 5xx) keeps the
 * identical body queued with backoff: the operator's answer is never dropped
 * while its gate receipt can still accept it.
 */
export async function deliverHold(ctx: HoldContext, holdId: string, deadline = Date.now() + SETTLE_BUDGET_MS): Promise<DeliveryResult | null> {
  const scope = scopeOf(ctx);
  let hold = findHolds(scope, { id: holdId }, ctx.home)[0];
  if (!hold?.outbox) return null;
  const outbox = hold.outbox;
  const remaining = () => Math.max(250, deadline - Date.now());
  const commitAfter = async (current: HoldRecord): Promise<'committed' | 'unverified' | 'failed' | 'skipped'> => {
    if (!outbox.commit) return 'skipped';
    const timeout = statusTimeout(remaining());
    try {
      return await commitHold(ctx, current, outbox.commit, timeout.signal);
    } finally {
      timeout.cancel();
    }
  };
  // A typed approval of a waiting hold keeps it waiting: the retried action reads the status and runs once.
  const settledState: HoldRecord['state'] = hold.mode === 'wait' && outbox.report?.verdict === 'approved' && !outbox.commit ? 'open' : 'resolved';
  const finish = (state: HoldRecord['state'] = settledState) => updateHold(scope, hold.id, (current) => ({ ...current, outbox: null, state }), ctx.home);
  if (!outbox.report) {
    const committed = await commitAfter(hold);
    if (committed === 'failed') {
      updateHold(scope, hold.id, (current) => ({ ...current, outbox: current.outbox && { ...current.outbox, attempts: current.outbox.attempts + 1, next_at: Date.now() + backoffMs(current.outbox.attempts, null) } }), ctx.home);
      return { kind: 'queued' };
    }
    finish();
    return { kind: 'already_approved', committed };
  }
  let report: HoldReport = outbox.report;
  if (report.verdict === 'approved' && !report.decision_id) {
    const timeout = statusTimeout(remaining());
    const decisionId = await ensureDecision(ctx, hold, timeout.signal).finally(timeout.cancel);
    if (!decisionId) {
      updateHold(scope, hold.id, (current) => ({ ...current, outbox: current.outbox && { ...current.outbox, attempts: current.outbox.attempts + 1, next_at: Date.now() + backoffMs(current.outbox.attempts, null) } }), ctx.home);
      return { kind: 'queued' };
    }
    report = { ...report, decision_id: decisionId };
    hold = updateHold(scope, hold.id, (current) => ({ ...current, decision_id: decisionId, outbox: current.outbox && { ...current.outbox, report } }), ctx.home) || hold;
  }
  const timeout = statusTimeout(Math.min(HOST_APPROVAL_REQUEST_TIMEOUT_MS, remaining()));
  let result;
  try {
    result = await marrowHostApproval(ctx.apiKey, ctx.baseUrl, hold.gate_receipt_id, report, hold.session_id, hold.agent_id || undefined, timeout.signal);
  } catch {
    result = null;
  } finally {
    timeout.cancel();
  }
  if (!result || (!result.ok && (result.retryable || result.code === 'MARROW_OWNER_APPROVAL_STATE_UNAVAILABLE'))) {
    const retryAfter = result && !result.ok ? result.retryAfterMs : null;
    updateHold(scope, hold.id, (current) => ({
      ...current,
      outbox: current.outbox && { ...current.outbox, attempts: current.outbox.attempts + 1, next_at: Date.now() + backoffMs(current.outbox.attempts, retryAfter) },
    }), ctx.home);
    return { kind: 'queued' };
  }
  if (result.ok) {
    const recorded = updateHold(scope, hold.id, (current) => ({ ...current, decision_id: current.decision_id || result.receipt.decision_id, outbox: current.outbox && { ...current.outbox, report: null } }), ctx.home) || hold;
    const committed = await commitAfter(recorded);
    if (committed === 'failed') {
      updateHold(scope, hold.id, (current) => ({ ...current, outbox: current.outbox && { ...current.outbox, attempts: current.outbox.attempts + 1, next_at: Date.now() + backoffMs(current.outbox.attempts, null) } }), ctx.home);
    } else {
      finish();
    }
    return { kind: 'recorded', answeredBy: result.receipt.answered_by, verdict: result.receipt.verdict, committed };
  }
  if (result.code === 'MARROW_OWNER_APPROVAL_ALREADY_DECIDED' && result.existingVerdict === report.verdict) {
    const committed = await commitAfter(hold);
    finish();
    return { kind: 'already_approved', committed };
  }
  if (result.code && REFUSED_AFTER_RUN.has(result.code) || result.code === 'MARROW_OWNER_APPROVAL_ALREADY_DECIDED') {
    // Nothing was recorded. When the action already ran, its real outcome is
    // still committed; it stays unverified, which is correct.
    const committed = report.verdict === 'approved' && outbox.commit ? await commitAfter(hold) : 'skipped';
    finish();
    return { kind: 'refused', code: result.code, committed };
  }
  // 400 invalid, 403/409 scope mismatch, not held, decision closed: a hook bug or a
  // receipt that is not waiting. Never retried.
  finish();
  return { kind: 'dropped', code: result.code };
}

/** Delivers due queued reports for this key (bounded); called at the start of later hooks. */
export async function flushHoldOutbox(ctx: HoldContext, limit = 2, budgetMs = 4_000): Promise<void> {
  let due: HoldRecord[];
  try {
    due = findHolds(scopeOf(ctx), {}, ctx.home).filter((hold) => hold.outbox && hold.outbox.next_at <= Date.now()).slice(0, limit);
  } catch {
    return;
  }
  const deadline = Date.now() + budgetMs;
  for (const hold of due) {
    if (Date.now() >= deadline) break;
    await deliverHold(ctx, hold.id, deadline).catch(() => null);
  }
}

/** marrow_commit: send a queued host approval for this receipt before the agent's own commit. */
export async function deliverQueuedForReceipt(ctx: HoldContext, gateReceiptId: string): Promise<void> {
  let holds: HoldRecord[];
  try {
    holds = findHolds(scopeOf(ctx), {}, ctx.home).filter((hold) => hold.gate_receipt_id === gateReceiptId && hold.outbox?.report);
  } catch {
    return;
  }
  for (const hold of holds) await deliverHold(ctx, hold.id, Date.now() + 5_000).catch(() => null);
}

function outcomeText(hold: HoldRecord, success: boolean, host: ApprovalHost): string {
  return bounded(`${hold.action.action} ${success ? 'completed' : 'failed'} in ${HOST_LABEL[host]} after it was approved (gate receipt ${hold.gate_receipt_id}).`, 480);
}

function handoffText(hold: HoldRecord, delivery: DeliveryResult | null): string | null {
  const decision = hold.decision_id ? `decision_id ${hold.decision_id}, ` : '';
  const proof = hold.proof_fields.length ? hold.proof_fields.join(', ') : 'the required fields';
  if (!delivery) return null;
  if (delivery.kind === 'queued') {
    return bounded(`Marrow is recording the approval of this held action (gate receipt ${hold.gate_receipt_id}); the report is queued and retried automatically. Close it with marrow_commit as usual: ${decision}gate_receipt_id ${hold.gate_receipt_id}, the real success and outcome${hold.proof_required ? `, and proof with ${proof}` : ''}. Marrow sends the queued approval first.`, 600);
  }
  if (delivery.kind === 'refused') {
    return bounded(`Marrow could not record an approval for this held action (${delivery.code || 'refused'}), so its outcome stays unverified. Do not retry it to get approval; the account owner can review it in the Marrow dashboard.`, 400);
  }
  if (delivery.kind === 'dropped') return null;
  const approved = delivery.kind === 'already_approved' || (delivery.kind === 'recorded' && delivery.verdict === 'approved');
  if (!approved) return null;
  if (delivery.committed === 'committed') {
    return bounded(`Marrow recorded the approval (client-attested) and closed this held action on gate receipt ${hold.gate_receipt_id}.`, 300);
  }
  if (hold.proof_required) {
    return bounded(`Marrow recorded the approval of this held action (client-attested). Close it with marrow_commit: ${decision}gate_receipt_id ${hold.gate_receipt_id}, the real success and outcome, and proof with ${proof}. Do not call marrow_agent_runtime or marrow_think again for it.`, 600);
  }
  return bounded(`Marrow recorded the approval of this held action (client-attested). Close it with marrow_commit: ${decision}gate_receipt_id ${hold.gate_receipt_id}, and the real success and outcome.`, 500);
}

/**
 * After the tool ran (PostToolUse/PostToolUseFailure, Cursor after*Execution):
 * the operator allowed an asked call, or a waited hold was approved and retried.
 * Reports the approval (asked calls only), then commits the real outcome when
 * no proof is required; otherwise tells the agent how to close it with proof.
 */
export async function settleAfterTool(ctx: HoldContext, input: {
  correlation: string;
  toolUseId: string | null;
  generationId: string | null;
  success: boolean;
}): Promise<string | null> {
  const scope = scopeOf(ctx);
  let holds: HoldRecord[];
  try {
    holds = findHolds(scope, {
      correlation: input.correlation,
      sessionId: ctx.sessionId,
      states: ['open', 'allowed'],
      ...(input.toolUseId ? { toolUseId: input.toolUseId } : {}),
      ...(input.generationId ? { generationId: input.generationId } : {}),
    }, ctx.home).filter((hold) => hold.mode === 'ask' ? hold.state === 'open' : hold.state === 'allowed');
  } catch {
    return null;
  }
  const hold = holds[0];
  if (!hold || hold.outbox) return null;
  const answeredAt = new Date().toISOString();
  const commit = hold.proof_required ? null : { success: input.success, outcome: outcomeText(hold, input.success, ctx.host) };
  const report: HoldReport | null = hold.mode === 'ask'
    ? {
      verdict: 'approved',
      host: hold.host,
      host_session_id: hold.host_session_id,
      // Claude Code's operator marker is the pass-through PermissionRequest
      // hook only. Without it the answer is reported as the event that asked
      // and the server labels it an allow rule.
      hook_event: hold.host === 'claude-code' ? (hold.dialog_at ? 'PermissionRequest' : 'PreToolUse') : hold.hook_event,
      pre_action_event_id: hold.pre_action_event_id,
      asked_at: hold.dialog_at || hold.asked_at,
      answered_at: answeredAt,
      ...(hold.decision_id ? { decision_id: hold.decision_id } : {}),
    }
    : null;
  if (!report && !commit) {
    updateHold(scope, hold.id, (current) => ({ ...current, state: 'resolved' }), ctx.home);
    return handoffText(hold, { kind: 'already_approved', committed: 'skipped' });
  }
  updateHold(scope, hold.id, (current) => ({ ...current, state: 'resolved', outbox: { report, commit, attempts: 0, next_at: 0 } }), ctx.home);
  const delivery = await deliverHold(ctx, hold.id);
  const latest = findHolds(scope, { id: hold.id }, ctx.home)[0] || hold;
  return handoffText({ ...latest, decision_id: latest.decision_id || hold.decision_id }, delivery);
}

// ---------------------------------------------------------------------------
// Claude Code declines: a permission rejection, never an interruption.
// Texts pinned from the Claude Code 2.1.289 bundle (see test/host-approvals-claude-texts).
// ---------------------------------------------------------------------------

export const CLAUDE_CODE_USER_REJECTED = "The user doesn't want to proceed with this tool use. The tool use was rejected (eg. if it was a file edit, the new_string was NOT written to the file). STOP what you are doing and wait for the user to tell you how to proceed.";
export const CLAUDE_CODE_USER_REJECTED_WITH_FEEDBACK = "The user doesn't want to proceed with this tool use. The tool use was rejected (eg. if it was a file edit, the new_string was NOT written to the file). To tell you how to proceed, the user said:\n";
/** Interruptions, cancellations and unanswered prompts: never a decline. */
export const CLAUDE_CODE_NOT_A_DECISION_PREFIXES = [
  '[Request interrupted by user',
  '[Tool call did not complete:',
  '[Tool call interrupted:',
  '[Tool call skipped:',
  '[Tool call not completed:',
  '[Tool call result not in this copy:',
  "The user doesn't want to take this action right now.",
];
/** Transcript toolDenialKind values that mean the call never got an operator answer. */
const NOT_A_DECISION_KINDS = new Set(['cancelled', 'interrupted']);

export type ClaudeCallResolution = 'declined' | 'interrupted' | 'unknown';

export function toolResultText(value: unknown): string | null {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) {
    const text = value.find((block) => block && typeof block === 'object' && (block as Record<string, unknown>).type === 'text'
      && typeof (block as Record<string, unknown>).text === 'string') as Record<string, unknown> | undefined;
    return text ? String(text.text) : null;
  }
  return null;
}

/**
 * A structured transcript denial kind wins. Free text is used only for
 * built-in tools: an MCP tool authors its own result text and could imitate a
 * rejection, so for MCP tools only the structured kind counts.
 */
export function classifyClaudeToolResult(input: {
  toolName: string;
  text: string | null;
  denialKind?: string | null;
  unanswered?: string | null;
}): ClaudeCallResolution {
  if (input.denialKind === 'user-rejected') return 'declined';
  if ((input.denialKind && NOT_A_DECISION_KINDS.has(input.denialKind)) || input.unanswered) return 'interrupted';
  if (input.denialKind) return 'unknown';
  if (isMcpHookTool(input.toolName) || input.text === null) return 'unknown';
  const text = input.text.replace(/\s+$/, '');
  if (text === CLAUDE_CODE_USER_REJECTED || input.text.startsWith(CLAUDE_CODE_USER_REJECTED_WITH_FEEDBACK)) return 'declined';
  if (CLAUDE_CODE_NOT_A_DECISION_PREFIXES.some((prefix) => text.startsWith(prefix))) return 'interrupted';
  return 'unknown';
}

const TRANSCRIPT_TAIL_BYTES = 512 * 1024;

export type TranscriptToolResult = { text: string | null; denialKind: string | null; unanswered: string | null };

/** Reads only a bounded tail of the host's own transcript, and only the tool results asked for. */
export function transcriptToolResults(path: unknown, toolUseIds: Set<string>): Map<string, TranscriptToolResult> {
  const found = new Map<string, TranscriptToolResult>();
  if (typeof path !== 'string' || path.length > 4096 || !isAbsolute(path) || !path.endsWith('.jsonl') || toolUseIds.size === 0) return found;
  let fd = -1;
  try {
    const stat = lstatSync(path);
    const uid = typeof process.getuid === 'function' ? process.getuid() : null;
    if (!stat.isFile() || stat.isSymbolicLink() || (uid !== null && stat.uid !== uid)) return found;
    fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    const opened = fstatSync(fd);
    if (opened.ino !== stat.ino) return found;
    const length = Math.min(opened.size, TRANSCRIPT_TAIL_BYTES);
    const buffer = Buffer.alloc(length);
    readSync(fd, buffer, 0, length, opened.size - length);
    const lines = buffer.toString('utf8').split('\n');
    if (opened.size > length) lines.shift();
    for (const line of lines) {
      if (!line.includes('tool_result')) continue;
      let entry: Record<string, unknown>;
      try { entry = JSON.parse(line); } catch { continue; }
      const message = entry.message && typeof entry.message === 'object' ? entry.message as Record<string, unknown> : null;
      if (entry.type !== 'user' || !Array.isArray(message?.content)) continue;
      for (const block of message.content as Array<Record<string, unknown>>) {
        if (!block || block.type !== 'tool_result' || typeof block.tool_use_id !== 'string' || !toolUseIds.has(block.tool_use_id)) continue;
        found.set(block.tool_use_id, {
          text: toolResultText(block.content),
          denialKind: typeof entry.toolDenialKind === 'string' ? entry.toolDenialKind.slice(0, 64) : null,
          unanswered: typeof entry.toolDenialUnanswered === 'string' ? entry.toolDenialUnanswered.slice(0, 64) : null,
        });
      }
    }
  } catch {
    return found;
  } finally {
    if (fd >= 0) closeSync(fd);
  }
  return found;
}

async function settleClaudeResolution(ctx: HoldContext, hold: HoldRecord, resolution: ClaudeCallResolution, hookEvent: string): Promise<void> {
  const scope = scopeOf(ctx);
  if (resolution === 'unknown') return;
  if (resolution === 'declined') {
    const report: HoldReport = {
      verdict: 'declined',
      host: hold.host,
      host_session_id: hold.host_session_id,
      hook_event: hookEvent,
      pre_action_event_id: hold.pre_action_event_id,
      asked_at: hold.dialog_at || hold.asked_at,
      answered_at: new Date().toISOString(),
      ...(hold.decision_id ? { decision_id: hold.decision_id } : {}),
    };
    const commit: HoldCommit = {
      success: false,
      outcome: `Denied by Marrow pre-action gate: the operator declined in ${HOST_LABEL[ctx.host]} (gate receipt ${hold.gate_receipt_id}).`,
    };
    updateHold(scope, hold.id, (current) => ({ ...current, state: 'resolved', outbox: { report, commit, attempts: 0, next_at: 0 } }), ctx.home);
    await deliverHold(ctx, hold.id);
    return;
  }
  // Interrupted, cancelled or left unanswered: not a decline and not an approval.
  // The observed outcome is committed without an approval and stays unverified.
  const commit: HoldCommit = {
    success: false,
    outcome: `Not completed: the call was interrupted, cancelled or left unanswered in ${HOST_LABEL[ctx.host]} before Marrow recorded an answer (gate receipt ${hold.gate_receipt_id}); no approval or decline was given.`,
  };
  updateHold(scope, hold.id, (current) => ({ ...current, state: 'resolved', outbox: { report: null, commit, attempts: 0, next_at: 0 } }), ctx.home);
  await deliverHold(ctx, hold.id);
}

/** Claude Code PostToolBatch: decide each still-open asked call of the batch per tool_use_id. */
export async function settleToolBatch(ctx: HoldContext, input: {
  toolCalls: unknown;
  transcriptPath?: unknown;
}): Promise<number> {
  if (!Array.isArray(input.toolCalls)) return 0;
  const scope = scopeOf(ctx);
  let open: HoldRecord[];
  try {
    open = findHolds(scope, { sessionId: ctx.sessionId, mode: 'ask', states: ['open'] }, ctx.home).filter((hold) => !hold.outbox);
  } catch {
    return 0;
  }
  if (open.length === 0) return 0;
  const calls = input.toolCalls.slice(0, 64).filter((call): call is Record<string, unknown> => Boolean(call) && typeof call === 'object');
  const ids = new Set(open.map((hold) => hold.tool_use_id).filter((id): id is string => Boolean(id)));
  const transcript = transcriptToolResults(input.transcriptPath, ids);
  let settled = 0;
  for (const call of calls) {
    const toolUseId = typeof call.tool_use_id === 'string' ? call.tool_use_id : null;
    const toolName = typeof call.tool_name === 'string' ? call.tool_name : '';
    const correlation = stableToolCorrelation({ session_id: ctx.sessionId, tool_name: toolName, tool_input: call.tool_input });
    const hold = open.find((candidate) => candidate.correlation === correlation && (!toolUseId || !candidate.tool_use_id || candidate.tool_use_id === toolUseId));
    if (!hold) continue;
    const fromTranscript = toolUseId ? transcript.get(toolUseId) : undefined;
    const resolution = classifyClaudeToolResult({
      toolName,
      text: toolResultText(call.tool_response),
      denialKind: fromTranscript?.denialKind,
      unanswered: fromTranscript?.unanswered,
    });
    if (resolution === 'unknown') continue;
    await settleClaudeResolution(ctx, hold, resolution, 'PostToolBatch');
    settled += 1;
  }
  return settled;
}

/** Claude Code UserPromptSubmit fallback: a rejected dialog can end the turn before PostToolBatch. */
export async function settleAtPrompt(ctx: HoldContext, transcriptPath: unknown): Promise<number> {
  const scope = scopeOf(ctx);
  let open: HoldRecord[];
  try {
    open = findHolds(scope, { sessionId: ctx.sessionId, mode: 'ask', states: ['open'] }, ctx.home)
      .filter((hold) => !hold.outbox && hold.tool_use_id);
  } catch {
    return 0;
  }
  if (open.length === 0) return 0;
  const results = transcriptToolResults(transcriptPath, new Set(open.map((hold) => hold.tool_use_id as string)));
  let settled = 0;
  for (const hold of open) {
    const found = results.get(hold.tool_use_id as string);
    if (!found) continue;
    const resolution = classifyClaudeToolResult({ toolName: hold.tool_name, text: found.text, denialKind: found.denialKind, unanswered: found.unanswered });
    if (resolution === 'unknown') continue;
    await settleClaudeResolution(ctx, hold, resolution, 'UserPromptSubmit');
    settled += 1;
  }
  return settled;
}

// ---------------------------------------------------------------------------
// Typed replies: local interactive Cursor sessions only (never Claude Code,
// cloud or background agents, codex exec or gemini -p).
// ---------------------------------------------------------------------------

const TYPED_REPLY = /^\s*marrow\s+(approve|decline|deny)\s+([A-Za-z0-9]{6})\s*$/i;

export function parseTypedReply(prompt: unknown): { verdict: 'approved' | 'declined'; code: string } | null {
  if (typeof prompt !== 'string' || prompt.length > 64) return null;
  const match = prompt.match(TYPED_REPLY);
  if (!match) return null;
  const code = match[2].toUpperCase();
  if (!APPROVAL_CODE.test(code)) return null;
  return { verdict: match[1].toLowerCase() === 'approve' ? 'approved' : 'declined', code };
}

export function noteCursorSession(ctx: HoldContext, input: { isBackgroundAgent: unknown }): void {
  setSessionMarker('interactive', scopeOf(ctx), ctx.hostSessionId, input.isBackgroundAgent === false, ctx.home);
}

export function cursorSessionEvidence(ctx: HoldContext): { interactive: boolean | null; promptHook: boolean | null } {
  try {
    return {
      interactive: sessionMarker('interactive', scopeOf(ctx), ctx.hostSessionId, ctx.home),
      promptHook: sessionMarker('prompt_hook', scopeOf(ctx), ctx.hostSessionId, ctx.home),
    };
  } catch {
    return { interactive: null, promptHook: null };
  }
}

/** Cursor beforeSubmitPrompt: records that the prompt hook runs, and handles "marrow approve CODE". */
export async function settleTypedReply(ctx: HoldContext, prompt: unknown): Promise<string | null> {
  const scope = scopeOf(ctx);
  try { setSessionMarker('prompt_hook', scope, ctx.hostSessionId, true, ctx.home); } catch { /* evidence is best effort */ }
  const typed = parseTypedReply(prompt);
  if (!typed || ctx.host !== 'cursor') return null;
  if (cursorSessionEvidence(ctx).interactive !== true) return null;
  let hold: HoldRecord | undefined;
  try {
    hold = findHolds(scope, { code: typed.code, hostSessionId: ctx.hostSessionId, mode: 'wait', states: ['open'] }, ctx.home)[0];
  } catch {
    return null;
  }
  if (!hold || hold.outbox) return null;
  const report: HoldReport = {
    verdict: typed.verdict,
    host: hold.host,
    host_session_id: hold.host_session_id,
    hook_event: 'beforeSubmitPrompt',
    pre_action_event_id: hold.pre_action_event_id,
    asked_at: hold.asked_at,
    answered_at: new Date().toISOString(),
    ...(hold.decision_id ? { decision_id: hold.decision_id } : {}),
  };
  const commit: HoldCommit | null = typed.verdict === 'declined'
    ? { success: false, outcome: `Denied by Marrow pre-action gate: the operator declined in ${HOST_LABEL[ctx.host]} (gate receipt ${hold.gate_receipt_id}).` }
    : null;
  // An approval keeps the hold waiting: the retried action reads the status and runs once.
  updateHold(scope, hold.id, (current) => ({ ...current, state: typed.verdict === 'declined' ? 'resolved' : 'open', outbox: { report, commit, attempts: 0, next_at: 0 } }), ctx.home);
  const delivery = await deliverHold(ctx, hold.id);
  if (!delivery || delivery.kind === 'queued') return 'Marrow is recording your answer; the report is queued and retried automatically.';
  if (delivery.kind === 'recorded' || delivery.kind === 'already_approved') {
    return typed.verdict === 'approved'
      ? 'Marrow recorded your approval (client-attested). Ask the agent to retry the held action.'
      : 'Marrow recorded your decline. The held action will not run.';
  }
  return `Marrow could not record your answer (${'code' in delivery && delivery.code ? delivery.code : 'refused'}). The account owner can approve it in the Marrow dashboard.`;
}
