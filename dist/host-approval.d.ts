import { type NativeHookHarness } from './hook-contract';
import type { ArbitrationApprovalGuidance, OrdinaryApprovalGuidance } from './runtime-contract';
import { type HoldRecord } from './host-approval-state';
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
export declare const HOST_LABEL: Record<ApprovalHost, string>;
export declare function approvalHostFor(harness: NativeHookHarness, env?: NodeJS.ProcessEnv): ApprovalHost;
/** Cursor events on which a hook "ask" is enforced (never preToolUse). */
export declare const CURSOR_ASK_EVENTS: Set<string>;
export declare const HOST_APPROVAL_REQUEST_TIMEOUT_MS = 4000;
/**
 * One total time budget for a pre-tool hook, counted from the start of the
 * hook process. Codex and Cursor stop a hook after 5 seconds (as
 * @getmarrow/install configures them) and Codex then lets the call run, so
 * their budget leaves room for npx start-up; slow work that does not decide
 * the answer runs after the answer is written, inside the same budget.
 */
export declare function preToolBudgetMs(host: ApprovalHost): number;
/** The hook process's deadline for its pre-tool answer and any follow-up work. */
export declare function preToolDeadline(host: ApprovalHost): number;
/** Time left before the hook must have written its answer (Infinity without a deadline). */
export declare function remainingMs(ctx: {
    deadlineAt?: number;
}): number;
/** A step's timeout inside the budget, or null when there is no time for it before the answer. */
export declare function stepTimeoutMs(ctx: {
    deadlineAt?: number;
}, max: number, reserve?: number): number | null;
/**
 * Work a post-tool hook does for a held call. Codex and Cursor run these hooks
 * with a 5-second timeout (as @getmarrow/install configures them); a hook cut
 * short keeps its queued report, which a later hook resends.
 */
export declare function settleBudgetMs(host: ApprovalHost): number;
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
export declare function hostSessionIdFor(candidates: unknown[], fallback: string): string;
/**
 * Stands in a plan's text for what happened to the owner's one-tap link; it is
 * always replaced (finalizeOwnerRequest) before anyone sees the text, so no
 * text says a request was sent when none was.
 */
export declare const OWNER_APPROVAL_REQUEST_TEXT = "[owner-request]";
/** An older Marrow service: no host approvals and no links; only the account owner can approve. */
export declare const LEGACY_SERVICE_TEXT = "This Marrow service does not support chat or terminal approvals yet, so only the account owner can approve it.";
/** Marrow could not be read while this action waits for an approval: it stays held. */
export declare const HELD_UNREACHABLE_TEXT = "Marrow could not confirm the owner's approval; this action stays held. Retry when Marrow is reachable.";
export type OwnerLinkOutcome = {
    kind: 'sent';
    channel: string;
} | {
    kind: 'already_sent';
} | {
    kind: 'deferred';
} | {
    kind: 'retryable';
} | {
    kind: 'failed';
    code: string | null;
} | {
    kind: 'none';
};
/** The sentence for what happened to the owner's link. Never claims a send that did not happen. */
export declare function ownerRequestText(outcome: OwnerLinkOutcome): string;
export type HoldPlan = {
    kind: 'ask';
    promptText: string;
} | {
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
};
/** Shown when the owner's link is sent only if the operator asks for it. */
export declare const OWNER_LINK_ON_REQUEST_TEXT = "To ask the account owner, retry this exact action; Marrow then sends the owner a one-tap approval link.";
/** The sentence that replaces OWNER_APPROVAL_REQUEST_TEXT once Marrow sent the owner a one-tap link. */
export declare function ownerLinkSentText(channel: string): string;
/** Puts what happened to the owner's link into the plan's text (always, before output). */
export declare function finalizeOwnerRequest(plan: HoldPlan, outcome: OwnerLinkOutcome): HoldPlan;
/** Hosts whose typed reply is a person-only marker, and that marker (backend OPERATOR_MARKER_BY_HOST). */
export declare const TYPED_REPLY_MARKER: Readonly<Record<string, string>>;
/**
 * Decides how a hook answers an ordinary held action. The operator approves
 * where they work: the host's own dialog (Claude Code, Cursor shell and MCP
 * calls), or a typed reply in a local interactive session of a host without a
 * dialog (Codex, Gemini CLI, Cursor otherwise). The approval code and its
 * prompt go only to a user-only channel; model-facing text never contains it.
 * When no operator can answer here, the request goes to the account owner.
 * No text makes a dashboard login the step to take.
 */
export declare function planHeldAction(input: {
    guidance: OrdinaryApprovalGuidance;
    host: ApprovalHost;
    hookEvent: string;
    reason: string;
    /** Claude Code: whether a hook "ask" reaches a person in this permission mode and version. */
    claudePrompt?: {
        available: boolean;
        unavailableReason: string;
        headless?: boolean;
    };
    /** Cursor: true only when sessionStart reported a local, non-background session. */
    cursorInteractive?: boolean | null;
    /** A local interactive session whose typed-reply hook runs (see typedReplyAvailable). */
    typedReply?: boolean;
}): HoldPlan;
/**
 * Arbitration review_required with the server's one-tap path: the owner picks
 * and approves one proposal. The hook denies, asks Marrow to send the owner a
 * link, and the retried action reads the status. Nobody is told to log in.
 */
export declare function planArbitrationHold(guidance: ArbitrationApprovalGuidance): HoldPlan;
/** User-only text with the typed-reply code (Cursor user_message, Codex and Gemini systemMessage). */
export declare function typedReplyUserText(userText: string, code: string): string;
/** What a hold record needs from the runtime's guidance (ordinary or arbitration). */
export type HoldGuidance = Pick<OrdinaryApprovalGuidance, 'gateReceiptId' | 'decisionId' | 'proofRequired' | 'proofFields' | 'expiresAt' | 'approvalLinkPath'> & {
    hostApprovalSupported?: boolean;
    arbitrationReceiptId?: string | null;
};
export declare function arbitrationHoldGuidance(guidance: ArbitrationApprovalGuidance): HoldGuidance;
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
    action: {
        action: string;
        target: string;
        type: string;
        surfaces: string[];
    };
    /** From the plan: whether and when the owner's one-tap link is requested. */
    ownerLink?: 'now' | 'on_request';
    dialogLater?: boolean;
    laterPrompt?: string;
};
export declare function rememberHold(ctx: HoldContext, input: RecordHoldInput): HoldRecord;
/**
 * Remembers the categories the account owner protects, from a hold's guidance,
 * so an owner-protected action stays held while Marrow cannot be reached.
 */
export declare function rememberProtection(ctx: HoldContext, guidance: OrdinaryApprovalGuidance): void;
/** Of these categories, the ones this key last saw the account owner protect. */
export declare function protectedAmong(ctx: HoldContext, categories: string[]): string[];
/**
 * Asks Marrow to send the account owner a one-tap approval link for this hold.
 * A retryable failure (network, rate limit, undelivered) is tried again on a
 * later attempt, up to the server's per-receipt limit; a final refusal is not.
 * Returns what happened. The link itself never reaches this client or the agent.
 */
export declare function requestOwnerLink(ctx: HoldContext, hold: HoldRecord, reserve?: number): Promise<OwnerLinkOutcome>;
/** PermissionRequest (pass-through): the host is about to show its own dialog for an asked call. */
export declare function noteDialogShown(ctx: HoldContext, correlation: string): HoldRecord | null;
/**
 * Who approved, as the status says it. "The account owner" only for the
 * owner's verified approval; anything else is named for what it is.
 */
export declare function approvalSentence(status: MarrowOwnerApprovalStatus): string;
export type WaitingResolution = {
    kind: 'allow';
    hold: HoldRecord;
    contextText: string;
} | {
    kind: 'ask';
    hold: HoldRecord;
    promptText: string;
} | {
    kind: 'deny';
    hold: HoldRecord;
    agentText: string;
    userText: string;
    deferredLink?: boolean;
};
/**
 * The same action, retried after a hold that waited (denied while it waited
 * for an approval). Reads the hold's status first: approved allows it once on
 * the same gate receipt (compare-and-set: a second identical call is denied);
 * pending denies again without a new hold; a status Marrow cannot give keeps
 * it held; declined, expired or used fall back to the normal flow (null).
 */
export declare function resumeWaitingHold(ctx: HoldContext, input: {
    correlation: string;
    toolUseId: string | null;
    generationId: string | null;
    /** Claude Code shows its dialog for this attempt (permission mode and version). */
    dialogAvailable?: boolean;
}): Promise<WaitingResolution | null>;
export type DeliveryResult = {
    kind: 'recorded';
    answeredBy: 'host_operator' | 'host_allow_rule' | 'owner_chat_preapproval';
    verdict: 'approved' | 'declined';
    committed: 'committed' | 'unverified' | 'failed' | 'skipped';
} | {
    kind: 'already_approved';
    committed: 'committed' | 'unverified' | 'failed' | 'skipped';
} | {
    kind: 'queued';
} | {
    kind: 'refused';
    code: string | null;
    committed: 'committed' | 'unverified' | 'failed' | 'skipped';
} | {
    kind: 'dropped';
    code: string | null;
};
/**
 * Sends a hold's queued report (and the commit that follows it) once. A
 * retryable failure (network, 409 STATE_UNAVAILABLE, 429, 5xx) keeps the
 * identical body queued with backoff: the operator's answer is never dropped
 * while its gate receipt can still accept it.
 */
export declare function deliverHold(ctx: HoldContext, holdId: string, deadline?: number): Promise<DeliveryResult | null>;
/** Delivers due queued reports for this key (bounded); called at the start of later hooks. */
export declare function flushHoldOutbox(ctx: HoldContext, limit?: number, budgetMs?: number): Promise<void>;
/**
 * marrow_commit from the MCP server: the hooks bound this gate receipt to the
 * host session (for example Claude Code's session_id), which the MCP server
 * process does not know. The receipt stays the authority; the session only has
 * to match it.
 */
export declare function holdSessionForReceipt(ctx: HoldContext, gateReceiptId: string): string | null;
/** marrow_commit: send a queued host approval for this receipt before the agent's own commit. */
export declare function deliverQueuedForReceipt(ctx: HoldContext, gateReceiptId: string): Promise<void>;
/** How long a post-tool hook waits for Claude Code's async PermissionRequest marker. */
export declare const LATE_MARKER_WAIT_MS = 1500;
/**
 * After the tool ran (PostToolUse/PostToolUseFailure, Cursor after*Execution):
 * the operator allowed an asked call, or a waited hold was approved and retried.
 * Reports the approval (asked calls only), then commits the real outcome when
 * no proof is required and the host reported it; otherwise tells the agent how
 * to close it.
 */
export declare function settleAfterTool(ctx: HoldContext, input: {
    correlation: string;
    toolUseId: string | null;
    generationId: string | null;
    /** null when the host does not say whether the call succeeded (Cursor's after-execution events). */
    success: boolean | null;
    /** Test seam: how long to wait for a late dialog marker. */
    markerWaitMs?: number;
}): Promise<string | null>;
export declare const CLAUDE_CODE_USER_REJECTED = "The user doesn't want to proceed with this tool use. The tool use was rejected (eg. if it was a file edit, the new_string was NOT written to the file). STOP what you are doing and wait for the user to tell you how to proceed.";
export declare const CLAUDE_CODE_USER_REJECTED_WITH_FEEDBACK = "The user doesn't want to proceed with this tool use. The tool use was rejected (eg. if it was a file edit, the new_string was NOT written to the file). To tell you how to proceed, the user said:\n";
/** Interruptions, cancellations and unanswered prompts: never a decline. */
export declare const CLAUDE_CODE_NOT_A_DECISION_PREFIXES: string[];
export type ClaudeCallResolution = 'declined' | 'interrupted' | 'unknown';
export declare function toolResultText(value: unknown): string | null;
/**
 * A structured transcript denial kind wins. Free text is used only for
 * built-in tools: an MCP tool authors its own result text and could imitate a
 * rejection, so for MCP tools only the structured kind counts.
 */
export declare function classifyClaudeToolResult(input: {
    toolName: string;
    text: string | null;
    denialKind?: string | null;
    unanswered?: string | null;
}): ClaudeCallResolution;
export type TranscriptToolResult = {
    text: string | null;
    denialKind: string | null;
    unanswered: string | null;
};
/** Reads only a bounded tail of the host's own transcript, and only the tool results asked for. */
export declare function transcriptToolResults(path: unknown, toolUseIds: Set<string>): Map<string, TranscriptToolResult>;
/** Claude Code PostToolBatch: decide each still-open asked call of the batch per tool_use_id. */
export declare function settleToolBatch(ctx: HoldContext, input: {
    toolCalls: unknown;
    transcriptPath?: unknown;
}): Promise<number>;
/** Claude Code UserPromptSubmit fallback: a rejected dialog can end the turn before PostToolBatch. */
export declare function settleAtPrompt(ctx: HoldContext, transcriptPath: unknown): Promise<number>;
export declare function parseTypedReply(prompt: unknown): {
    verdict: 'approved' | 'declined';
    code: string;
} | null;
export declare function noteCursorSession(ctx: HoldContext, input: {
    isBackgroundAgent: unknown;
}): void;
export declare function cursorSessionEvidence(ctx: HoldContext): {
    interactive: boolean | null;
    promptHook: boolean | null;
};
/**
 * A typed reply counts only from a person: the session must be local and
 * interactive (Cursor: sessionStart says not a background agent; Codex and
 * Gemini CLI: the host process has a terminal and no scripted subcommand or
 * prompt flag), and its prompt hook must already have run, so the reply can
 * reach Marrow at all.
 */
export declare function typedReplyAvailable(ctx: HoldContext, interactive?: (host: string) => boolean | null): boolean;
export type TypedReplyResult = {
    ok: boolean;
    verdict: 'approved' | 'declined';
    userText: string;
    agentText: string | null;
};
/**
 * The host's prompt hook (Codex UserPromptSubmit, Gemini BeforeAgent, Cursor
 * beforeSubmitPrompt): records that the hook runs for this session, and records
 * "marrow approve CODE" / "marrow decline CODE" typed by the operator.
 */
export declare function settleTypedReply(ctx: HoldContext, prompt: unknown, interactive?: (host: string) => boolean | null): Promise<TypedReplyResult | null>;
//# sourceMappingURL=host-approval.d.ts.map