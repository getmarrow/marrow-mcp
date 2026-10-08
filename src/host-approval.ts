import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, readSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { marrowAgentApprovalSettings, marrowCommit, marrowHeldActions, marrowHostApproval, marrowOwnerApprovalStatus, marrowRequestApprovalLink, marrowThink } from './index';
import { isMcpHookTool } from './hook-tool-policy';
import { stableToolCorrelation, type NativeHookHarness } from './hook-contract';
import { ownerLinkPolicy, type ArbitrationApprovalGuidance, type OrdinaryApprovalGuidance } from './runtime-contract';
import {
  boundSessionId,
  claimHold,
  findHolds,
  markDialogShown,
  noteProtectedCategories,
  protectedCategoriesAmong,
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
import { hookLauncherHeadStartMs, localInteractiveSession } from './host-session';
import { normalizedHookAction } from './normalized-action';

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

/** Claude Code entrypoints with no one at a dialog (claude -p, the Agent SDKs, its GitHub Action); hooks inherit it. */
export const HEADLESS_CLAUDE_ENTRYPOINTS = new Set(['sdk-cli', 'sdk-ts', 'sdk-py', 'claude-code-github-action']);

export function claudeCodeHeadless(env: NodeJS.ProcessEnv = process.env): boolean {
  return HEADLESS_CLAUDE_ENTRYPOINTS.has(String(env.CLAUDE_CODE_ENTRYPOINT || ''));
}

/** Cursor events on which a hook "ask" is enforced (never preToolUse). */
export const CURSOR_ASK_EVENTS = new Set(['beforeShellExecution', 'beforeMCPExecution']);

const HOST_SESSION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
export const HOST_APPROVAL_REQUEST_TIMEOUT_MS = 4_000;
/** The status read is one key lookup. */
const STATUS_READ_TIMEOUT_MS = 2_500;
/** Time kept back for writing the hook's answer. */
const OUTPUT_RESERVE_MS = 400;
/** Below this, a network step is not started before the answer is written. */
const MIN_STEP_MS = 600;

/**
 * One total time budget for a pre-tool hook, counted from the start of the
 * hook process and set from each host's real kill timeout as
 * @getmarrow/install configures it: Codex 5 s (it then lets the call run),
 * Cursor 5 s with failClosed, the installer's Grok guard 5 s (it then blocks),
 * Gemini CLI 5 s. The margin covers npx start-up before the process starts.
 * Cold auth can take 900 ms plus a 1.6 s grace, so the control path keeps
 * room for a slow but healthy Marrow; when the budget still runs out, an
 * action that can be held stays held (never an outage allow).
 */
export function preToolBudgetMs(host: ApprovalHost): number {
  // Codex: 5 s kill, then it runs the call. npx start-up before this process
  // takes about 0.5-1.3 s and more under load, so the answer comes within 2 s.
  if (host === 'codex') return 2_000;
  if (host === 'cursor' || host === 'grok' || host === 'gemini') return 4_000;
  return 14_000;
}

/**
 * The hook process's deadline for its pre-tool answer and any follow-up work.
 * Codex's kill clock starts when it spawns the hook command, so the time npx
 * (or a shell) took to start this process comes out of the budget: the answer
 * comes about 2.6 s after spawn, with at least 1 s for this process itself.
 */
export function preToolDeadline(host: ApprovalHost, headStartMs: () => number = hookLauncherHeadStartMs): number {
  const start = Date.now() - Math.round(process.uptime() * 1000);
  if (host !== 'codex') return start + preToolBudgetMs(host);
  let headStart = 0;
  try { headStart = headStartMs(); } catch { headStart = 0; }
  return start + Math.max(1_000, Math.min(preToolBudgetMs(host), 2_600 - headStart));
}

/** Time left before the hook must have written its answer (Infinity without a deadline). */
export function remainingMs(ctx: { deadlineAt?: number }): number {
  return ctx.deadlineAt ? ctx.deadlineAt - Date.now() : Number.POSITIVE_INFINITY;
}

/** A step's timeout inside the budget, or null when there is no time for it before the answer. */
export function stepTimeoutMs(ctx: { deadlineAt?: number }, max: number, reserve = OUTPUT_RESERVE_MS): number | null {
  const left = remainingMs(ctx) - reserve;
  if (left < MIN_STEP_MS) return null;
  return Math.min(max, left);
}
/**
 * Work a post-tool hook does for a held call. Codex and Cursor run these hooks
 * with a 5-second timeout (as @getmarrow/install configures them); a hook cut
 * short keeps its queued report, which a later hook resends.
 */
export function settleBudgetMs(host: ApprovalHost): number {
  return host === 'codex' || host === 'cursor' ? 4_000 : 9_000;
}

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
  /** Pre-tool hooks: when the answer must be written (see preToolBudgetMs). */
  deadlineAt?: number;
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

/** Why the operator's own approval does not count for this hold (the server's refusal). */
function ownerOnlyReason(guidance: OrdinaryApprovalGuidance): string {
  if (!guidance.hostApprovalSupported) return LEGACY_SERVICE_TEXT;
  if (guidance.hostApprovalRefusal === 'owner_decline_stands') {
    return `The account owner declined this action${guidance.ownerDeclinedAt ? ` at ${guidance.ownerDeclinedAt}` : ' earlier'}.`;
  }
  if (guidance.hostApprovalRefusal === 'approval_state_unavailable') {
    return 'Marrow could not check how this hold can be approved right now.';
  }
  if (guidance.verifiedApprovalRequired === true) {
    return `The account owner approves ${guidance.verifiedApprovalCategories.join(', ') || 'these'} actions personally.`;
  }
  if (guidance.verifiedApprovalRequired === null) {
    return 'Marrow could not read the account approval settings.';
  }
  return 'An operator approval is not available for this hold.';
}

/**
 * Stands in a plan's text for what happened to the owner's one-tap link; it is
 * always replaced (finalizeOwnerRequest) before anyone sees the text, so no
 * text says a request was sent when none was.
 */
export const OWNER_APPROVAL_REQUEST_TEXT = '[owner-request]';

/** An older Marrow service: no host approvals and no links; only the account owner can approve. */
export const LEGACY_SERVICE_TEXT = 'This Marrow service does not support chat or terminal approvals yet, so only the account owner can approve it.';

/** Marrow could not be read while this action waits for an approval: it stays held. */
export const HELD_UNREACHABLE_TEXT = 'Marrow could not confirm the owner\'s approval; this action stays held. Retry when Marrow is reachable.';

export type OwnerLinkOutcome =
  | { kind: 'sent'; channel: string }
  /** The owner already has a live link (this hold's, or the arbitration's own on the service). */
  | { kind: 'already_sent'; channel?: string; expiresAt?: string | null }
  | { kind: 'deferred' }
  | { kind: 'retryable' }
  | { kind: 'failed'; code: string | null }
  /** The service sent nothing on purpose (owner_ping_off): the hold waits quietly. */
  | { kind: 'not_sent' }
  | { kind: 'none' };

/** The sentence for what happened to the owner's link. Never claims a send that did not happen. */
export function ownerRequestText(outcome: OwnerLinkOutcome): string {
  switch (outcome.kind) {
    case 'sent': return ownerLinkSentText(outcome.channel);
    case 'already_sent': return outcome.channel
      ? `The account owner already has a one-tap approval link (${outcome.channel}${outcome.expiresAt ? `, until ${outcome.expiresAt}` : ''}); wait for their answer.`
      : 'An approval link was sent to the account owner.';
    case 'not_sent': return 'Nothing was sent to anyone; it waits quietly until a person approves it.';
    // Deferred: tried right after this answer is written; until a retry confirms it, it is not "sent".
    case 'deferred':
    case 'retryable': return 'Marrow could not send the account owner an approval link yet; retrying this exact action tries again.';
    case 'failed': return `Marrow could not send the account owner an approval link${outcome.code ? ` (${outcome.code})` : ''}; tell the operator this action is waiting for the account owner's approval.`;
    default: return 'Tell the operator this action is waiting for the account owner\'s approval.';
  }
}

export type HoldPlan =
  | { kind: 'ask'; promptText: string }
  /**
   * Marrow does not block: a person is here but Marrow can neither ask in this
   * host nor observe its answer, so the host's own approval step decides (owner
   * rule). The outcome is recorded as approved through the host's own prompt,
   * not observed by Marrow (an allow rule, client-attested), never as the operator's answer.
   */
  | { kind: 'pass'; contextText: string }
  | {
    kind: 'deny';
    agentText: string;
    userText: string;
    code: boolean;
    /** The owner's one-tap link: request it now, or only when the operator asks by retrying. */
    ownerLink?: 'now' | 'on_request';
    /** Denied only because Claude Code showed no dialog; a retry where it can asks. */
    dialogLater?: boolean;
    /** Not remembered as waiting: the next attempt starts over (approval state unreadable). */
    retryFresh?: boolean;
    /** The prompt to show if a retry can ask in the host's own dialog (keeps the notice and reason). */
    laterPrompt?: string;
    /** Waits quietly: nobody can be asked here (attended) or nobody is here (unattended). */
    quiet?: 'attended' | 'unattended';
  };

/** Shown when the owner's link is sent only if the operator asks for it. */
export const OWNER_LINK_ON_REQUEST_TEXT = 'To ask the account owner, retry this exact action; Marrow then sends the owner a one-tap approval link.';

/** The sentence that replaces OWNER_APPROVAL_REQUEST_TEXT once Marrow sent the owner a one-tap link. */
export function ownerLinkSentText(channel: string): string {
  return `An approval link was sent to the account owner (${channel}).`;
}

/** Puts what happened to the owner's link into the plan's text (always, before output). */
export function finalizeOwnerRequest(plan: HoldPlan, outcome: OwnerLinkOutcome): HoldPlan {
  if (plan.kind !== 'deny') return plan;
  const text = ownerRequestText(outcome);
  return { ...plan, agentText: plan.agentText.replace(OWNER_APPROVAL_REQUEST_TEXT, text), userText: plan.userText.replace(OWNER_APPROVAL_REQUEST_TEXT, text) };
}

/** Hosts whose typed reply is a person-only marker, and that marker (backend OPERATOR_MARKER_BY_HOST). */
export const TYPED_REPLY_MARKER: Readonly<Record<string, string>> = {
  codex: 'UserPromptSubmit',
  gemini: 'BeforeAgent',
  cursor: 'beforeSubmitPrompt',
};

/**
 * Decides how a hook answers an ordinary held action. The operator approves
 * where they work: the host's own dialog (Claude Code, Cursor shell and MCP
 * calls), or a typed reply in a local interactive session of a host without a
 * dialog (Codex, Gemini CLI, Cursor otherwise). The approval code and its
 * prompt go only to a user-only channel; model-facing text never contains it.
 * When no one can answer here, the action waits quietly (the owner's link only
 * for owner-locked categories, the owner's own decline when the operator asks,
 * or unattended runs with the owner's pings on).
 * No text makes a dashboard login the step to take.
 */
export function planHeldAction(input: {
  guidance: OrdinaryApprovalGuidance;
  host: ApprovalHost;
  hookEvent: string;
  reason: string;
  /** Claude Code: whether a hook "ask" reaches a person in this permission mode and version. */
  claudePrompt?: { available: boolean; unavailableReason: string; headless?: boolean };
  /** Cursor: true only when sessionStart reported a local, non-background session. */
  cursorInteractive?: boolean | null;
  /** A local interactive session whose typed-reply hook runs (see typedReplyAvailable). */
  typedReply?: boolean;
  /** No person is in this run (headless, `codex exec`, `gemini -p`, a background agent). */
  unattended?: boolean;
  /**
   * There is positive evidence that a person is at this host (a local
   * interactive Codex, Gemini CLI or Cursor session; Grok, Cline and Windsurf
   * run where their user works). Without it a hold that cannot be asked waits quietly.
   */
  attendedConfirmed?: boolean;
  /**
   * The host's own approval prompt is off in this session (Codex started with
   * its approval bypass, never-ask, automatic review, full auto or full
   * access): leaving the action to it would let it run with no one asked.
   */
  hostPromptOff?: boolean;
}): HoldPlan {
  const { guidance, host } = input;
  const unattended = input.unattended === true;
  const reason = input.reason ? ` Reason: ${bounded(input.reason, 200)}` : '';
  const id = guidance.gateReceiptId;
  // Shown in the host's own prompt (to the operator, never to the agent).
  const notice = guidance.operatorNotice ? ` Note: ${guidance.operatorNotice}` : '';
  const held = `Marrow is holding this action for approval (gate receipt ${id}), so it did not run.${reason}`;
  const tail = ' When it is approved, retry this exact action; Marrow checks the approval then. Do not report or claim an approval yourself.';
  // Text a person reads names no receipt ids; the agent's text keeps them (it closes the action with them).
  const claudePrompt = bounded(`Marrow holds this action for your approval. Approve only if you authorize this exact action; Marrow records your answer.${notice}${reason}`, 500);
  // Owner rule: the owner's link only for (a) an owner-locked category, (b) the
  // owner's standing decline once the operator asks, (c) an unattended run with pings on.
  const policy = ownerLinkPolicy(guidance, { unattended });
  if (guidance.hostApprovalAccepted) {
    if (host === 'claude-code' && input.claudePrompt?.available) {
      return { kind: 'ask', promptText: claudePrompt };
    }
    // After an operator decline only a marked answer counts; Cursor's dialog carries no marker.
    if (host === 'cursor' && CURSOR_ASK_EVENTS.has(input.hookEvent) && input.cursorInteractive === true && !guidance.operatorOnly) {
      return {
        kind: 'ask',
        promptText: bounded(`Marrow holds this action for your approval. Approve only if you authorize this exact action.${notice}${reason}`, 500),
      };
    }
    if (input.typedReply && TYPED_REPLY_MARKER[host] && !unattended) {
      return {
        kind: 'deny',
        agentText: bounded(`${held} The operator was asked to approve it here.${tail}`, 500),
        userText: bounded(`Marrow holds this action for your approval.${notice}${reason}`, 400),
        code: true,
      };
    }
  }
  if (!guidance.hostApprovalSupported) {
    // An older service: no host approvals and no links. The hold waits, and
    // the retried action reads its status, so an owner's approval still counts.
    const agentText = bounded(`${held} ${LEGACY_SERVICE_TEXT} Retry this exact action after the owner approves it; Marrow checks the approval then. Do not report or claim an approval yourself.`, 500);
    return { kind: 'deny', agentText, userText: forPerson(agentText), code: false };
  }
  if (!guidance.hostApprovalAccepted) {
    if (guidance.hostApprovalRefusal === 'approval_state_unavailable'
      || (guidance.hostApprovalRefusal === null && guidance.verifiedApprovalRequired === null)) {
      // Nothing to wait for yet: the next attempt asks Marrow again.
      const agentText = bounded(`${held} ${ownerOnlyReason(guidance)} Retry this exact action in a moment. Do not report or claim an approval yourself.`, 500);
      return { kind: 'deny', agentText, userText: forPerson(agentText), code: false, retryFresh: true };
    }
    if (guidance.hostApprovalRefusal === 'owner_decline_stands') {
      // The owner just said no: the owner is asked again only when the operator asks.
      const why = `${ownerOnlyReason(guidance)} Only the account owner can reverse that.`;
      const ask = policy === 'on_request' ? ` ${OWNER_LINK_ON_REQUEST_TEXT}` : '';
      const agentText = bounded(`${held} ${why}${ask} Retry it only if the operator asks you to; otherwise carry on with other work. Do not report or claim an approval yourself.`, 500);
      return { kind: 'deny', agentText, userText: forPerson(agentText), code: false, ...(policy === 'on_request' ? { ownerLink: 'on_request' as const } : {}) };
    }
    // An owner-locked category: the owner's one-tap link is how it is approved.
    const request = policy === 'now' ? OWNER_APPROVAL_REQUEST_TEXT : ownerRequestText({ kind: 'none' });
    const agentText = bounded(`${held} ${ownerOnlyReason(guidance)} ${request} Carry on with other work meanwhile.${tail}`, 500);
    return { kind: 'deny', agentText, userText: forPerson(agentText), code: false, ...(policy === 'now' ? { ownerLink: 'now' as const } : {}) };
  }
  if (host === 'claude-code' && !input.claudePrompt?.headless && !unattended) {
    // The operator is present but this session shows no dialog: switching to a
    // mode with the dialog approves it here (the host's own prompt, one click).
    const agentText = bounded(`${held} Claude Code shows no approval dialog in this session (${input.claudePrompt?.unavailableReason || 'it cannot prompt'}). To approve it here, switch Claude Code to its default permission mode and retry this exact action; Claude Code then asks you. Until then carry on with other work. Do not report or claim an approval yourself.`, 500);
    return { kind: 'deny', agentText, userText: forPerson(agentText), code: false, dialogLater: true, laterPrompt: claudePrompt };
  }
  if (unattended || (host === 'claude-code' && input.claudePrompt?.headless)) {
    // Unattended: the action waits quietly and the agent carries on. The person
    // sees it at their next interactive session; the owner is pinged only on opt-in.
    const pinged = policy === 'now';
    const agentText = pinged
      ? bounded(`${held} Nobody can approve it in this run. ${OWNER_APPROVAL_REQUEST_TEXT} If it is approved, retrying this exact action runs it once; meanwhile carry on with other work. Do not report or claim an approval yourself.`, 500)
      : bounded(`${held} Nobody can approve it in this run, so it waits quietly; nothing was sent to anyone. Carry on with other work and do not retry it in this run. A person sees it at their next interactive session and approves it there by retrying it where the host's prompt asks. Do not report or claim an approval yourself.`, 500);
    return { kind: 'deny', agentText, userText: forPerson(agentText), code: false, quiet: 'unattended', ...(pinged ? { ownerLink: 'now' as const } : {}) };
  }
  // A person is here, but Marrow can neither ask in this host nor observe the
  // answer: the host's own approval step decides (owner rule). Not after an
  // operator decline (only a marked answer counts then), and not without
  // positive evidence that a person is here.
  if (input.attendedConfirmed === true && input.hostPromptOff !== true && !guidance.operatorOnly && PASS_THROUGH_HOSTS.has(host)) {
    return {
      kind: 'pass',
      contextText: bounded(`Marrow did not block this held action (gate receipt ${id}). ${HOST_LABEL[host].charAt(0).toUpperCase()}${HOST_LABEL[host].slice(1)}'s own approval step decides; Marrow cannot ask here and does not observe that answer. If it runs, Marrow records it as approved through the host's own prompt (client-attested, not an operator answer). Do not report or claim an approval yourself.${reason}`, 500),
    };
  }
  // Otherwise: hold quietly.
  const label = `${HOST_LABEL[host].charAt(0).toUpperCase()}${HOST_LABEL[host].slice(1)}`;
  const why = host === 'cursor'
    ? 'Cursor asks for approval only for shell and MCP calls in a local session.'
    : input.hostPromptOff === true
    ? `${label} runs with its own approval prompt turned off in this session (approval bypass, never-ask, automatic review or full access), so nothing asks for approval here.`
    : `${label} cannot ask for approval in this session.`;
  const agentText = bounded(`${held} ${why} It stays held until the operator approves it: tell them it is held, and that they approve it by retrying it in a session with Marrow's prompt (a host permission dialog, or a typed reply). Carry on with other work. Do not report or claim an approval yourself.`, 500);
  return { kind: 'deny', agentText, userText: HELD_FOR_YOU_TEXT, code: false, quiet: 'attended' };
}

/**
 * Hosts where an ordinary hold Marrow cannot ask about is left to the host's
 * own approval step: those whose hook can answer neutrally (no decision), so
 * the host's normal permission flow runs. A hook never emits an explicit
 * allow for a held action. Gemini CLI and Grok are not here (their installed
 * guards accept only an explicit allow or a fixed denial), nor is Cursor
 * (preToolUse has no neutral answer and "ask" is not enforced there): those
 * hold quietly.
 */
export const PASS_THROUGH_HOSTS: ReadonlySet<ApprovalHost> = new Set<ApprovalHost>(['codex', 'cline', 'windsurf']);

/** The hook_event of an answer given in a host prompt Marrow did not observe (labelled an allow rule). */
export const HOST_PROMPT_NOT_OBSERVED = 'host_prompt_not_observed';

/** What the person sees when this host cannot ask them: the action waits for them. */
export const HELD_FOR_YOU_TEXT = 'This action is held until you approve it. Approve it by retrying it in a session with Marrow\'s prompt.';

/**
 * Arbitration review_required with the server's one-tap path: the owner picks
 * and approves one proposal. The hook denies, asks Marrow to send the owner a
 * link, and the retried action reads the status. Nobody is told to log in.
 */
export function planArbitrationHold(guidance: ArbitrationApprovalGuidance, options: { unattended?: boolean } = {}): HoldPlan {
  const held = `Marrow is holding this action for arbitration review (gate receipt ${guidance.gateReceiptId}), so it did not run. The account owner picks and approves one proposal.`;
  if (options.unattended === true) {
    // Nobody here can ask: the service sends the owner a link only if they turned on unattended pings.
    const agentText = bounded(`${held} ${OWNER_APPROVAL_REQUEST_TEXT} Carry on with other work and do not retry it in this run. Do not report or claim an approval yourself.`, 500);
    return { kind: 'deny', agentText, userText: forPerson(agentText), code: false, ownerLink: 'now', quiet: 'unattended' };
  }
  // A person is here: the owner is asked only when they ask for it, by retrying this action.
  const agentText = bounded(`${held} Nothing was sent to the owner yet. If the operator wants the owner asked now, retry this exact action once; Marrow then sends the owner a one-tap link. Otherwise carry on with other work. When the owner has answered, retry this exact action; Marrow checks the answer then. Do not report or claim an approval yourself.`, 500);
  return { kind: 'deny', agentText, userText: forPerson(agentText), code: false, ownerLink: 'on_request' };
}

/** User-only text with the typed-reply code (Cursor user_message, Codex and Gemini systemMessage). */
export function typedReplyUserText(userText: string, code: string): string {
  return bounded(`${userText} To approve it, type: marrow approve ${code} (or: marrow decline ${code}). Then let the agent retry it.`, 600);
}

/** What a hold record needs from the runtime's guidance (ordinary or arbitration). */
export type HoldGuidance = Pick<OrdinaryApprovalGuidance, 'gateReceiptId' | 'decisionId' | 'proofRequired' | 'proofFields' | 'expiresAt' | 'approvalLinkPath'> & {
  hostApprovalSupported?: boolean;
  arbitrationReceiptId?: string | null;
};

export function arbitrationHoldGuidance(guidance: ArbitrationApprovalGuidance): HoldGuidance {
  return {
    gateReceiptId: guidance.gateReceiptId,
    decisionId: guidance.decisionId,
    proofRequired: guidance.proofRequired,
    proofFields: guidance.proofFields,
    expiresAt: guidance.expiresAt,
    approvalLinkPath: guidance.linkPath,
    hostApprovalSupported: true,
    arbitrationReceiptId: guidance.arbitrationReceiptId,
  };
}

export type RecordHoldInput = {
  guidance: HoldGuidance;
  correlation: string;
  toolUseId: string | null;
  generationId: string | null;
  toolName: string;
  hookEvent: string;
  mode: 'ask' | 'wait';
  withCode: boolean;
  preActionEventId: string | null;
  action: { action: string; target: string; type: string; surfaces: string[] };
  /** From the plan: whether and when the owner's one-tap link is requested. */
  ownerLink?: 'now' | 'on_request';
  /** The normalized action the runtime call carried; the answer is reported with the same one. */
  normalizedAction?: Record<string, unknown> | null;
  /** Arbitration: a person is at this session (its retry asks for the owner's link). */
  personPresent?: boolean;
  dialogLater?: boolean;
  laterPrompt?: string;
  quiet?: 'attended' | 'unattended';
  /** Left to the host's own approval step, which Marrow does not observe. */
  notObserved?: boolean;
};

const HOOK_EVENT_NAME = /^[A-Za-z][A-Za-z0-9_.:-]{0,63}$/;
const BOUNDED_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export function rememberHold(ctx: HoldContext, input: RecordHoldInput): HoldRecord {
  return recordHold(scopeOf(ctx), {
    host: ctx.host,
    harness: ctx.harness,
    // The same bound buildHeaders applies to X-Marrow-Session-Id.
    session_id: boundSessionId(ctx.sessionId),
    host_session_id: ctx.hostSessionId,
    agent_id: ctx.agentId && ctx.agentId.length <= 128 ? ctx.agentId : null,
    correlation: input.correlation,
    tool_use_id: input.toolUseId && BOUNDED_ID.test(input.toolUseId) ? input.toolUseId : null,
    generation_id: input.generationId && BOUNDED_ID.test(input.generationId) ? input.generationId : null,
    tool_name: input.toolName.slice(0, 256),
    hook_event: HOOK_EVENT_NAME.test(input.hookEvent) ? input.hookEvent : 'PreToolUse',
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
    owner_link: !input.guidance.approvalLinkPath ? null
      : input.ownerLink === 'now' ? 'unsent'
      : input.ownerLink === 'on_request' ? 'on_request'
      : null,
    link_attempts: 0,
    dialog_later: input.dialogLater === true,
    ask_text: input.dialogLater && input.laterPrompt ? bounded(input.laterPrompt, 500) : null,
    legacy_service: input.guidance.hostApprovalSupported === false,
    arbitration_receipt_id: input.guidance.arbitrationReceiptId && BOUNDED_ID.test(input.guidance.arbitrationReceiptId) ? input.guidance.arbitrationReceiptId : null,
    quiet: input.quiet ?? null,
    not_observed: input.notObserved === true,
    ...(input.normalizedAction && JSON.stringify(input.normalizedAction).length <= 16_384 ? { normalized_action: input.normalizedAction } : {}),
    ...(typeof input.personPresent === 'boolean' ? { person_present: input.personPresent } : {}),
  }, ctx.home);
}

/**
 * Remembers the categories the account owner protects, from a hold's guidance,
 * so an owner-protected action stays held while Marrow cannot be reached.
 */
export function rememberProtection(ctx: HoldContext, guidance: OrdinaryApprovalGuidance): void {
  try {
    if (guidance.verifiedApprovalRequired === true) {
      noteProtectedCategories(scopeOf(ctx), guidance.verifiedApprovalCategories, [], ctx.home);
    } else if (guidance.verifiedApprovalRequired === false) {
      noteProtectedCategories(scopeOf(ctx), [], guidance.approvalCategories, ctx.home);
    }
  } catch { /* a convenience for outages; the server stays the authority */ }
}

/** Of these categories, the ones this key last saw the account owner protect. */
export function protectedAmong(ctx: HoldContext, categories: string[]): string[] {
  return protectedCategoriesAmong(scopeOf(ctx), categories, ctx.home);
}

const OWNER_LINK_TIMEOUT_MS = 2_000;
/** Text for a person: the agent's text without receipt ids (the agent keeps them to close the action). */
export function forPerson(text: string): string {
  return text.replace(/ ?\(gate receipt [^)]{1,200}\)/g, '').replace(/ on gate receipt [A-Za-z0-9_.:-]{1,128}/g, '');
}

/** An agent id worth showing a person: not an automatic seat or key-derived fallback id. */
export function personAgentName(agent: string | null | undefined): string | null {
  if (!agent) return null;
  return /^(?:free-seat|seat|api-key|key|fallback)-/i.test(agent) ? null : agent;
}

/** The server allows three links per gate receipt. */
const MAX_LINK_ATTEMPTS = 3;
/** Link refusals that another request cannot change. */
const FINAL_LINK_CODES = new Set([
  'MARROW_APPROVAL_CHANNEL_UNAVAILABLE',
  'MARROW_APPROVAL_LINK_LIMITED',
  'MARROW_APPROVAL_LINK_NOT_HELD',
  'MARROW_APPROVAL_LINK_SCOPE_MISMATCH',
  'MARROW_APPROVAL_LINK_INVALID',
  'MARROW_APPROVAL_LINK_DECISION_REQUIRED',
  'MARROW_PRE_ACTION_GATE_USED',
  'MARROW_PRE_ACTION_GATE_EXPIRED',
  'MARROW_OWNER_APPROVAL_ALREADY_DECIDED',
  'MARROW_GATE_RECEIPT_NOT_FOUND',
]);

/**
 * Asks Marrow to send the account owner a one-tap approval link for this hold.
 * A retryable failure (network, rate limit, undelivered) is tried again on a
 * later attempt, up to the server's per-receipt limit; a final refusal is not.
 * Returns what happened. The link itself never reaches this client or the agent.
 */
export async function requestOwnerLink(ctx: HoldContext, hold: HoldRecord, reserve = OUTPUT_RESERVE_MS): Promise<OwnerLinkOutcome> {
  if (hold.owner_link === 'sent') return { kind: 'already_sent' };
  if (hold.owner_link === 'failed') return { kind: 'failed', code: null };
  if (hold.owner_link !== 'unsent' && hold.owner_link !== 'on_request') return { kind: 'none' };
  if ((hold.link_attempts || 0) >= MAX_LINK_ATTEMPTS) return { kind: 'failed', code: 'MARROW_APPROVAL_LINK_LIMITED' };
  const budget = stepTimeoutMs(ctx, OWNER_LINK_TIMEOUT_MS, reserve);
  if (budget === null) return { kind: 'deferred' };
  const timeout = statusTimeout(budget);
  let outcome: OwnerLinkOutcome;
  try {
    // Arbitration links carry whether a person at this session asked (client-attested): an
    // attended hold's link is requested on the operator's retry; an unattended one never claims a person.
    const arbitration = Boolean(hold.arbitration_receipt_id);
    const result = await marrowRequestApprovalLink(ctx.apiKey, ctx.baseUrl, hold.gate_receipt_id, hold.decision_id, hold.session_id, hold.agent_id || undefined, timeout.signal,
      arbitration ? { personPresent: hold.person_present === true && hold.owner_link === 'on_request' } : {});
    outcome = result.ok && result.alreadySent ? { kind: 'already_sent', channel: result.link.channel, expiresAt: result.link.expires_at ?? null }
      : result.ok ? { kind: 'sent', channel: result.link.channel }
      : result.notSent ? { kind: 'not_sent' }
      : !result.retryable && result.code && FINAL_LINK_CODES.has(result.code) ? { kind: 'failed', code: result.code }
      : result.retryable ? { kind: 'retryable' }
      : { kind: 'failed', code: result.code };
  } catch {
    outcome = { kind: 'retryable' };
  } finally {
    timeout.cancel();
  }
  const attempts = (hold.link_attempts || 0) + 1;
  const state: HoldRecord['owner_link'] = outcome.kind === 'sent' || outcome.kind === 'already_sent' ? 'sent'
    : outcome.kind === 'not_sent' ? null
    : outcome.kind === 'failed' || attempts >= MAX_LINK_ATTEMPTS ? 'failed'
    : 'unsent';
  try {
    updateHold(scopeOf(ctx), hold.id, (current) => ({ ...current, owner_link: state, link_attempts: attempts }), ctx.home);
  } catch { /* the link state is a convenience; the hold stands */ }
  if (outcome.kind === 'retryable' && state === 'failed') return { kind: 'failed', code: null };
  return outcome;
}

/** The categories an owner can lock (risk-categories.ts on the service). */
const OWNER_LOCKABLE_CATEGORIES = ['production_deploy', 'package_publish', 'secrets_security', 'data_migration', 'billing_access', 'destructive_action', 'source_control'];

/**
 * Once per interactive host session (its first prompt): tells the person how
 * many held actions are waiting for them, with the action type and agent only,
 * and refreshes this machine's copy of the owner-locked categories (so they
 * stay held during an outage on a fresh machine). Returns user-only text, or null.
 */
export async function heldActionsNotice(ctx: HoldContext, budgetMs = 1_500): Promise<string | null> {
  const scope = scopeOf(ctx);
  const marker = `held-actions-surfaced:${ctx.hostSessionId}`;
  try {
    if (sessionMarker('prompt_hook', scope, marker, ctx.home) === true) return null;
    setSessionMarker('prompt_hook', scope, marker, true, ctx.home);
  } catch {
    return null;
  }
  const timeout = statusTimeout(budgetMs);
  let items: Array<{ type: string; agent: string | null }> | null = null;
  let total: { n: number; capped: boolean } | null = null;
  try {
    const [held, settings] = await Promise.all([
      marrowHeldActions(ctx.apiKey, ctx.baseUrl, { scope: 'agent', limit: 20 }, ctx.sessionId, ctx.agentId, timeout.signal).catch(() => undefined),
      marrowAgentApprovalSettings(ctx.apiKey, ctx.baseUrl, ctx.sessionId, ctx.agentId, timeout.signal).catch(() => undefined),
    ]);
    if (settings) {
      noteProtectedCategories(scope, settings.verified_approval_categories,
        OWNER_LOCKABLE_CATEGORIES.filter((category) => !settings.verified_approval_categories.includes(category)), ctx.home);
    }
    if (held) {
      items = held.holds.map((hold) => ({ type: hold.decision_type || 'action', agent: hold.agent_id }));
      total = { n: held.count, capped: held.countCapped };
    }
  } finally {
    timeout.cancel();
  }
  if (!items) {
    // A service without the read: this machine's own waiting holds.
    try {
      const now = Date.now();
      items = findHolds(scope, { mode: 'wait', states: ['open'] }, ctx.home)
        .filter((hold) => !hold.expires_at || Date.parse(hold.expires_at) > now)
        .map((hold) => ({ type: hold.action.type || 'action', agent: hold.agent_id }));
    } catch {
      items = [];
    }
  }
  if (!items.length) return null;
  const groups = new Map<string, number>();
  for (const item of items) {
    const agent = personAgentName(item.agent);
    const label = `${bounded(item.type, 40)}${agent ? ` by agent ${bounded(agent, 64)}` : ''}`;
    groups.set(label, (groups.get(label) || 0) + 1);
  }
  const list = [...groups.entries()].slice(0, 5).map(([label, count]) => (count > 1 ? `${label} (${count})` : label)).join('; ');
  const n = total?.n ?? items.length;
  const plus = total?.capped ? '+' : '';
  return bounded(`Marrow: ${n}${plus} held action${n === 1 && !plus ? ' is' : 's are'} waiting for you: ${list}. Nothing ran. To approve one, retry it here and answer Marrow's prompt.`, 500);
}

/** PermissionRequest (pass-through): the host is about to show its own dialog for an asked call. */
export function noteDialogShown(ctx: HoldContext, correlation: string): HoldRecord | null {
  try {
    // This machine runs the marker hook: a post-tool hook may wait for a late marker.
    setSessionMarker('prompt_hook', scopeOf(ctx), PERMISSION_HOOK_SEEN, true, ctx.home);
  } catch { /* a convenience; the marker below is what counts */ }
  return markDialogShown(scopeOf(ctx), { correlation, sessionId: ctx.sessionId }, new Date().toISOString(), ctx.home);
}

const PERMISSION_HOOK_SEEN = 'claude-permission-request-hook-seen';
const NORMALIZED_ACTION_REFUSED = 'host-route-refuses-normalized-action';

/**
 * The exact action the operator answered for, carried with the report (it is
 * kept with the queued report so a resend is byte-identical, secrets removed),
 * unless this service refused the field recently.
 */
function reportAction(ctx: HoldContext, normalizedAction: Record<string, unknown> | null | undefined): { normalized_action?: Record<string, unknown> } {
  if (!normalizedAction) return {};
  try {
    if (sessionMarker('prompt_hook', scopeOf(ctx), NORMALIZED_ACTION_REFUSED, ctx.home) === true) return {};
  } catch { return {}; }
  return { normalized_action: normalizedAction };
}

/**
 * Whether Claude Code runs Marrow's pass-through PermissionRequest hook here:
 * seen on this machine for this key, or configured in the user's or the
 * project's Claude Code settings. Without it there is no marker to wait for.
 */
export function permissionMarkerHookPresent(ctx: HoldContext, cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd()): boolean {
  try {
    if (sessionMarker('prompt_hook', scopeOf(ctx), PERMISSION_HOOK_SEEN, ctx.home) === true) return true;
  } catch { /* fall through to the settings */ }
  const home = ctx.home || process.env.HOME || homedir();
  for (const path of [join(home, '.claude', 'settings.json'), join(cwd, '.claude', 'settings.json')]) {
    try {
      const stat = lstatSync(path);
      if (!stat.isFile() || stat.size > 1_048_576) continue;
      const hooks = (JSON.parse(readFileSync(path, 'utf8')) as { hooks?: { PermissionRequest?: unknown } })?.hooks?.PermissionRequest;
      if (Array.isArray(hooks) && JSON.stringify(hooks).includes('claude-permission-request-hook')) return true;
    } catch { /* unreadable or absent: no evidence */ }
  }
  return false;
}

function statusTimeout(ms = HOST_APPROVAL_REQUEST_TIMEOUT_MS): { signal: AbortSignal; cancel: () => void } {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  timer.unref?.();
  return { signal: controller.signal, cancel: () => clearTimeout(timer) };
}

async function readStatus(ctx: HoldContext, hold: HoldRecord): Promise<{ status: MarrowOwnerApprovalStatus | null; notFound: boolean; failed: boolean }> {
  const budget = stepTimeoutMs(ctx, STATUS_READ_TIMEOUT_MS);
  if (budget === null) return { status: null, notFound: false, failed: true };
  const timeout = statusTimeout(budget);
  try {
    const result = await marrowOwnerApprovalStatus(ctx.apiKey, ctx.baseUrl, hold.gate_receipt_id, hold.session_id, hold.agent_id || undefined, timeout.signal);
    return result.kind === 'not_found' ? { status: null, notFound: true, failed: false } : { status: result.status, notFound: false, failed: false };
  } catch {
    return { status: null, notFound: false, failed: true };
  } finally {
    timeout.cancel();
  }
}

/**
 * Who approved, as the status says it. "The account owner" only for the
 * owner's verified approval; anything else is named for what it is.
 */
export function approvalSentence(status: MarrowOwnerApprovalStatus): string {
  if (status.approval_source === 'host_prompt') {
    const who = status.approval_answered_by === 'host_operator' ? 'The operator approved'
      : status.approval_answered_by === 'owner_chat_preapproval' ? 'The account owner\'s chat pre-approval approved'
      : 'An allow rule in the host approved';
    return `${who} this held action (client-attested)`;
  }
  if (status.approval_trust === 'verified'
    && (status.approval_answered_by === 'account_owner' || status.approval_source === 'dashboard' || status.approval_source === 'one_tap')) {
    return 'The account owner approved this held action';
  }
  return 'Marrow recorded an approval for this held action';
}

export type WaitingResolution =
  | { kind: 'allow'; hold: HoldRecord; contextText: string }
  | { kind: 'ask'; hold: HoldRecord; promptText: string }
  | { kind: 'deny'; hold: HoldRecord; agentText: string; userText: string; deferredLink?: boolean };

/**
 * The same action, retried after a hold that waited (denied while it waited
 * for an approval). Reads the hold's status first: approved allows it once on
 * the same gate receipt (compare-and-set: a second identical call is denied);
 * pending denies again without a new hold; a status Marrow cannot give keeps
 * it held; declined, expired or used fall back to the normal flow (null).
 */
export async function resumeWaitingHold(ctx: HoldContext, input: {
  correlation: string;
  toolUseId: string | null;
  generationId: string | null;
  /** Claude Code shows its dialog for this attempt (permission mode and version). */
  dialogAvailable?: boolean;
}): Promise<WaitingResolution | null> {
  const scope = scopeOf(ctx);
  let holds: HoldRecord[];
  try {
    holds = findHolds(scope, { correlation: input.correlation, sessionId: ctx.sessionId, mode: 'wait', states: ['open'] }, ctx.home);
  } catch {
    return null;
  }
  const hold = holds[holds.length - 1];
  if (!hold) return null;
  const read = await readStatus(ctx, hold);
  if (read.failed || read.status?.state === 'unavailable') {
    // This exact action is waiting for an approval: it stays held until Marrow answers.
    return { kind: 'deny', hold, agentText: HELD_UNREACHABLE_TEXT, userText: HELD_UNREACHABLE_TEXT };
  }
  const status = read.status;
  if (!status || read.notFound) {
    updateHold(scope, hold.id, () => null, ctx.home);
    return null;
  }
  if (status.state === 'approved') {
    const claimed = claimHold(scope, hold.id, (current) => ({
      ...current,
      state: 'allowed',
      tool_use_id: input.toolUseId,
      generation_id: input.generationId,
      decision_id: current.decision_id || status.decision_id,
    }), ctx.home);
    if (!claimed) {
      const text = bounded(`Marrow approved this held action once (gate receipt ${hold.gate_receipt_id}), and an identical call is already running on that approval, so this repeat did not run. If it is still needed, retry it after that call finishes. Do not report or claim an approval yourself.`, 500);
      return { kind: 'deny', hold, agentText: text, userText: forPerson(text) };
    }
    const decision = claimed.decision_id ? `decision_id ${claimed.decision_id}, ` : '';
    const contextText = claimed.arbitration_receipt_id
      ? `Marrow: the account owner approved one proposal for this arbitrated action (gate receipt ${hold.gate_receipt_id}). Run only the approved proposal, then close it with marrow_commit: ${decision}gate_receipt_id ${hold.gate_receipt_id}, arbitration_receipt_id ${claimed.arbitration_receipt_id}${status.owner_approval_receipt_id ? `, owner_approval_receipt_id ${status.owner_approval_receipt_id}` : ''}, the real success and outcome${claimed.proof_required ? `, and proof with ${claimed.proof_fields.join(', ') || 'the required fields'}` : ''}.`
      : `${approvalSentence(status).startsWith('Marrow ') ? '' : 'Marrow: '}${approvalSentence(status)} (gate receipt ${hold.gate_receipt_id}). Run only this exact action; Marrow records its outcome on that receipt.`;
    return { kind: 'allow', hold: claimed, contextText: bounded(contextText, 600) };
  }
  const waitingStates = new Set(['pending', 'arbitration_review']);
  if (waitingStates.has(status.state) && hold.dialog_later && input.dialogAvailable === true && ctx.host === 'claude-code') {
    // The operator switched to a mode with the dialog: ask now, on the same gate receipt.
    const asked = claimHold(scope, hold.id, (current) => ({
      ...current,
      mode: 'ask',
      dialog_later: false,
      tool_use_id: input.toolUseId,
      generation_id: input.generationId,
      asked_at: new Date().toISOString(),
      dialog_at: null,
    }), ctx.home);
    if (!asked) return null;
    return {
      kind: 'ask',
      hold: asked,
      promptText: hold.ask_text || 'Marrow holds this action for your approval. Approve only if you authorize this exact action; Marrow records your answer.',
    };
  }
  if (waitingStates.has(status.state)) {
    // A retry is how the operator asks for the owner's link (sent once per hold;
    // a retryable failure is tried again within the server's per-receipt limit).
    const link = !hold.code && hold.owner_link ? await requestOwnerLink(ctx, hold) : { kind: 'none' as const };
    const waiting = hold.code ? 'The operator was asked to approve it here.'
      : hold.legacy_service ? `${LEGACY_SERVICE_TEXT} The account owner has not approved it yet.`
      : hold.owner_link ? ownerRequestText(link)
      : hold.dialog_later ? 'Claude Code shows no approval dialog in this session; switch to its default permission mode and retry this exact action.'
      : hold.quiet === 'unattended' ? 'Nobody can approve it in this run, so it waits quietly. Carry on with other work; a person approves it at their next interactive session.'
      : hold.quiet === 'attended' ? 'It stays held until the operator approves it by retrying it in a session with Marrow\'s prompt. Carry on with other work.'
      : ownerRequestText({ kind: 'none' });
    const expires = status.expires_at || hold.expires_at;
    const what = hold.arbitration_receipt_id ? 'for arbitration review' : 'for approval';
    const text = bounded(`Marrow is still holding this action ${what} (gate receipt ${hold.gate_receipt_id}), so it did not run. ${waiting} When it is approved${expires ? ` (before ${expires})` : ''}, retry this exact action. Do not report or claim an approval yourself.`, 500);
    return {
      kind: 'deny',
      hold,
      agentText: text,
      userText: hold.code ? 'Marrow still holds this action for your approval.'
        : hold.quiet === 'attended' ? HELD_FOR_YOU_TEXT
        : forPerson(text),
      ...(link.kind === 'deferred' ? { deferredLink: true } : {}),
    };
  }
  if (status.state === 'declined') {
    const who = status.approval_source === 'host_prompt' ? `the operator declined it in ${HOST_LABEL[ctx.host]}` : 'the account owner declined it';
    // The action did not run: close it as a denial after the hook answers (queued, resent if needed).
    updateHold(scope, hold.id, (current) => ({
      ...current,
      state: 'resolved',
      outbox: { report: null, commit: { success: false, outcome: bounded(`Denied by Marrow pre-action gate: ${who} (gate receipt ${hold.gate_receipt_id}); the action did not run.`, 480) }, attempts: 0, next_at: 0 },
    }), ctx.home);
    return null;
  }
  updateHold(scope, hold.id, () => null, ctx.home);
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

export type DeliveryResult =
  | { kind: 'recorded'; answeredBy: 'host_operator' | 'host_allow_rule' | 'owner_chat_preapproval'; verdict: 'approved' | 'declined'; committed: 'committed' | 'unverified' | 'failed' | 'skipped' }
  | { kind: 'already_approved'; committed: 'committed' | 'unverified' | 'failed' | 'skipped' }
  | { kind: 'queued' }
  | { kind: 'refused'; code: string | null; committed: 'committed' | 'unverified' | 'failed' | 'skipped' }
  | { kind: 'dropped'; code: string | null };

const REFUSED_AFTER_RUN = new Set([
  'MARROW_OWNER_APPROVAL_DECLINED',
  'MARROW_OWNER_DECLINE_STANDS',
  // An allow rule or automatic approval after the operator declined this action.
  'MARROW_EARLIER_DECLINE_STANDS',
  'MARROW_VERIFIED_OWNER_APPROVAL_REQUIRED',
  // The answer was reported for a different normalized action than the held one.
  'MARROW_HOST_APPROVAL_ACTION_MISMATCH',
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
export async function deliverHold(
  ctx: HoldContext,
  holdId: string,
  deadline = Date.now() + settleBudgetMs(ctx.host),
): Promise<DeliveryResult | null> {
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
    // A service that does not take normalized_action yet rejected the report
    // before recording it: store it without the field (remembered for a day) and send that.
    if (report.normalized_action && result && !result.ok && result.status === 400 && result.fields?.includes('normalized_action')) {
      try { setSessionMarker('prompt_hook', scope, NORMALIZED_ACTION_REFUSED, true, ctx.home); } catch { /* resent below either way */ }
      const { normalized_action: _dropped, ...plain } = report;
      report = plain;
      hold = updateHold(scope, hold.id, (current) => ({ ...current, outbox: current.outbox && { ...current.outbox, report: plain } }), ctx.home) || hold;
      result = await marrowHostApproval(ctx.apiKey, ctx.baseUrl, hold.gate_receipt_id, report, hold.session_id, hold.agent_id || undefined, timeout.signal);
    }
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

/**
 * marrow_commit from the MCP server: the hooks bound this gate receipt to the
 * host session (for example Claude Code's session_id), which the MCP server
 * process does not know. The receipt stays the authority; the session only has
 * to match it.
 */
export function holdSessionForReceipt(ctx: HoldContext, gateReceiptId: string): string | null {
  try {
    const holds = findHolds(scopeOf(ctx), {}, ctx.home).filter((hold) => hold.gate_receipt_id === gateReceiptId);
    return holds.length ? holds[holds.length - 1].session_id : null;
  } catch {
    return null;
  }
}

/** The proof fields this machine's hold for a receipt asked for (empty when unknown). */
export function proofFieldsForReceipt(ctx: HoldContext, gateReceiptId: string): string[] {
  try {
    const holds = findHolds(scopeOf(ctx), {}, ctx.home).filter((hold) => hold.gate_receipt_id === gateReceiptId);
    return holds.length && holds[holds.length - 1].proof_required ? [...holds[holds.length - 1].proof_fields] : [];
  } catch {
    return [];
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
  if (delivery.kind === 'refused' && delivery.code === 'MARROW_HOST_APPROVAL_ACTION_MISMATCH') {
    return bounded(`Marrow could not record an approval for this held action: the action that ran is not the one Marrow held (${delivery.code}), so its outcome stays unverified. Do not retry it to get approval; a new attempt is held and asked again.`, 400);
  }
  if (delivery.kind === 'refused') {
    return bounded(`Marrow could not record an approval for this held action (${delivery.code || 'refused'}), so its outcome stays unverified. Do not retry it to get approval; the account owner sees it with its receipts in Marrow.`, 400);
  }
  if (delivery.kind === 'dropped') return null;
  const approved = delivery.kind === 'already_approved' || (delivery.kind === 'recorded' && delivery.verdict === 'approved');
  if (!approved) return null;
  // A waited hold was approved on the server (by the owner, or a typed reply):
  // only an answer from this host's own prompt is the hook's client-attested record.
  const recorded = hold.not_observed
    ? 'Marrow recorded this held action as approved through the host\'s own prompt, which Marrow did not observe (client-attested, not an operator answer).'
    : hold.mode === 'ask'
    ? 'Marrow recorded the approval of this held action (client-attested).'
    : `This held action was approved (gate receipt ${hold.gate_receipt_id}).`;
  if (delivery.committed === 'committed') {
    if (hold.not_observed) {
      return bounded(`Marrow recorded this held action as approved through the host's own prompt, which Marrow did not observe (client-attested), and closed it on gate receipt ${hold.gate_receipt_id}.`, 300);
    }
    return bounded(`${hold.mode === 'ask' ? 'Marrow recorded the approval (client-attested) and closed' : 'Marrow closed'} this held action on gate receipt ${hold.gate_receipt_id}.`, 300);
  }
  const arbitration = hold.arbitration_receipt_id ? `, arbitration_receipt_id ${hold.arbitration_receipt_id} and the owner_approval_receipt_id Marrow gave when it allowed the action` : '';
  if (hold.proof_required) {
    return bounded(`${recorded} Close it with marrow_commit: ${decision}gate_receipt_id ${hold.gate_receipt_id}${arbitration}, the real success and outcome, and proof with ${proof}. Do not call marrow_agent_runtime or marrow_think again for it.`, 600);
  }
  return bounded(`${recorded} Close it with marrow_commit: ${decision}gate_receipt_id ${hold.gate_receipt_id}${arbitration}, and the real success and outcome.`, 500);
}

/** How long a post-tool hook waits for Claude Code's async PermissionRequest marker. */
export const LATE_MARKER_WAIT_MS = 1_500;

/**
 * After the tool ran (PostToolUse/PostToolUseFailure, Cursor after*Execution):
 * the operator allowed an asked call, or a waited hold was approved and retried.
 * Reports the approval (asked calls only), then commits the real outcome when
 * no proof is required and the host reported it; otherwise tells the agent how
 * to close it.
 */
export async function settleAfterTool(ctx: HoldContext, input: {
  correlation: string;
  toolUseId: string | null;
  generationId: string | null;
  /** null when the host does not say whether the call succeeded (Cursor's after-execution events). */
  success: boolean | null;
  /** Test seam: how long to wait for a late dialog marker. */
  markerWaitMs?: number;
  /** The exact action from this hook event, for the report (never stored). */
  normalizedAction?: Record<string, unknown> | null;
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
  let hold = holds[0];
  if (!hold || hold.outbox) return null;
  const answeredAt = new Date().toISOString();
  let lateMarker = false;
  if (hold.mode === 'ask' && hold.host === 'claude-code' && !hold.dialog_at && permissionMarkerHookPresent(ctx)) {
    // The marker hook runs async: after a fast click it can land just after
    // this hook starts. Wait briefly so a real click is not labelled an allow rule.
    const waitUntil = Date.now() + (input.markerWaitMs ?? LATE_MARKER_WAIT_MS);
    while (Date.now() < waitUntil) {
      await new Promise((resolve) => setTimeout(resolve, 100));
      const latest = findHolds(scope, { id: hold.id }, ctx.home)[0];
      if (!latest || latest.state !== 'open' || latest.outbox) break;
      hold = latest;
      if (latest.dialog_at) { lateMarker = true; break; }
    }
  }
  // An outcome the host does not report (null) is never committed as a success or a failure.
  const commit = hold.proof_required || input.success === null ? null : { success: input.success, outcome: outcomeText(hold, input.success, ctx.host) };
  const report: HoldReport | null = hold.mode === 'ask'
    ? {
      verdict: 'approved',
      host: hold.host,
      host_session_id: hold.host_session_id,
      // Claude Code's operator marker is the pass-through PermissionRequest
      // hook only. Without it the answer is reported as the event that asked
      // and the server labels it an allow rule.
      hook_event: hold.not_observed ? HOST_PROMPT_NOT_OBSERVED
        : hold.host === 'claude-code' ? (hold.dialog_at ? 'PermissionRequest' : 'PreToolUse') : hold.hook_event,
      pre_action_event_id: hold.pre_action_event_id,
      // A marker that landed after the call ran was written late; the dialog was
      // shown before the click, so the time the hook asked is the honest bound.
      asked_at: lateMarker ? hold.asked_at : (hold.dialog_at || hold.asked_at),
      answered_at: answeredAt,
      ...(hold.decision_id ? { decision_id: hold.decision_id } : {}),
      ...reportAction(ctx, hold.normalized_action ?? input.normalizedAction),
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

async function settleClaudeResolution(ctx: HoldContext, hold: HoldRecord, resolution: ClaudeCallResolution, hookEvent: string, normalizedAction?: Record<string, unknown> | null): Promise<void> {
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
      ...reportAction(ctx, hold.normalized_action ?? normalizedAction),
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
    await settleClaudeResolution(ctx, hold, resolution, 'PostToolBatch', normalizedHookAction({ tool_name: toolName, tool_input: call.tool_input }));
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
// Typed replies: local interactive Codex, Gemini CLI and Cursor sessions only
// (never Claude Code, Cursor cloud or background agents, codex exec or gemini -p).
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

/**
 * A typed reply counts only from a person: the session must be local and
 * interactive (Cursor: sessionStart says not a background agent; Codex and
 * Gemini CLI: the host process has a terminal and no scripted subcommand or
 * prompt flag), and its prompt hook must already have run, so the reply can
 * reach Marrow at all.
 */
export function typedReplyAvailable(ctx: HoldContext, interactive: (host: string) => boolean | null = localInteractiveSession): boolean {
  if (!TYPED_REPLY_MARKER[ctx.host]) return false;
  const evidence = cursorSessionEvidence(ctx);
  if (evidence.promptHook !== true) return false;
  if (ctx.host === 'cursor') return evidence.interactive === true;
  return interactive(ctx.host) === true;
}

export type TypedReplyResult = { ok: boolean; verdict: 'approved' | 'declined'; userText: string; agentText: string | null };

/**
 * The host's prompt hook (Codex UserPromptSubmit, Gemini BeforeAgent, Cursor
 * beforeSubmitPrompt): records that the hook runs for this session, and records
 * "marrow approve CODE" / "marrow decline CODE" typed by the operator.
 */
export async function settleTypedReply(
  ctx: HoldContext,
  prompt: unknown,
  interactive: (host: string) => boolean | null = localInteractiveSession,
): Promise<TypedReplyResult | null> {
  const scope = scopeOf(ctx);
  try { setSessionMarker('prompt_hook', scope, ctx.hostSessionId, true, ctx.home); } catch { /* evidence is best effort */ }
  const typed = parseTypedReply(prompt);
  const marker = TYPED_REPLY_MARKER[ctx.host];
  if (!typed || !marker || !typedReplyAvailable(ctx, interactive)) return null;
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
    hook_event: marker,
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
  const approved = typed.verdict === 'approved';
  if (!delivery || delivery.kind === 'queued') {
    return {
      ok: true, verdict: typed.verdict,
      userText: 'Marrow is recording your answer; the report is queued and resent automatically.',
      agentText: approved ? `The operator approved the held action (gate receipt ${hold.gate_receipt_id}); Marrow is recording it. Retry that exact action now.` : null,
    };
  }
  if (delivery.kind === 'recorded' || delivery.kind === 'already_approved') {
    return approved
      ? { ok: true, verdict: 'approved', userText: 'Marrow recorded your approval (client-attested).', agentText: `The operator approved the held action (gate receipt ${hold.gate_receipt_id}). Retry that exact action now; Marrow lets it run once.` }
      : { ok: true, verdict: 'declined', userText: 'Marrow recorded your decline. The held action will not run.', agentText: `The operator declined the held action (gate receipt ${hold.gate_receipt_id}). Do not run it.` };
  }
  return {
    ok: false, verdict: typed.verdict,
    userText: `Marrow could not record your answer (${'code' in delivery && delivery.code ? delivery.code : 'refused'}). ${OWNER_APPROVAL_REQUEST_TEXT}`,
    agentText: null,
  };
}
