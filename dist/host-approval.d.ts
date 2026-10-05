import { type NativeHookHarness } from './hook-contract';
import type { OrdinaryApprovalGuidance } from './runtime-contract';
import { type HoldRecord } from './host-approval-state';
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
export declare function hostSessionIdFor(candidates: unknown[], fallback: string): string;
export type HoldPlan = {
    kind: 'ask';
    promptText: string;
} | {
    kind: 'deny';
    agentText: string;
    userText: string;
    code: boolean;
};
/**
 * Decides how a hook answers an ordinary held action. Model-facing text never
 * contains an approval code; a code goes only to a user-only channel.
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
    };
    /** Cursor: true only when sessionStart reported a local, non-background session. */
    cursorInteractive?: boolean | null;
    /** Cursor: the beforeSubmitPrompt hook has run for this conversation. */
    cursorPromptHook?: boolean | null;
}): HoldPlan;
/** User-only text with the typed-reply code (Cursor user_message). Never sent to the agent. */
export declare function typedReplyUserText(agentText: string, code: string): string;
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
    action: {
        action: string;
        target: string;
        type: string;
        surfaces: string[];
    };
};
export declare function rememberHold(ctx: HoldContext, input: RecordHoldInput): HoldRecord;
/** PermissionRequest (pass-through): the host is about to show its own dialog for an asked call. */
export declare function noteDialogShown(ctx: HoldContext, correlation: string): HoldRecord | null;
export type WaitingResolution = {
    kind: 'allow';
    hold: HoldRecord;
    contextText: string;
} | {
    kind: 'deny';
    hold: HoldRecord;
    agentText: string;
    userText: string;
};
/**
 * The same action, retried after a hold that waited (denied while it waited
 * for an approval). Reads the hold's status first: approved allows it once on
 * the same gate receipt; pending denies again without a new hold; declined,
 * expired or used fall back to the normal flow (null).
 */
export declare function resumeWaitingHold(ctx: HoldContext, input: {
    correlation: string;
    toolUseId: string | null;
    generationId: string | null;
}): Promise<WaitingResolution | null>;
export type DeliveryResult = {
    kind: 'recorded';
    answeredBy: 'host_operator' | 'host_allow_rule';
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
/** marrow_commit: send a queued host approval for this receipt before the agent's own commit. */
export declare function deliverQueuedForReceipt(ctx: HoldContext, gateReceiptId: string): Promise<void>;
/**
 * After the tool ran (PostToolUse/PostToolUseFailure, Cursor after*Execution):
 * the operator allowed an asked call, or a waited hold was approved and retried.
 * Reports the approval (asked calls only), then commits the real outcome when
 * no proof is required; otherwise tells the agent how to close it with proof.
 */
export declare function settleAfterTool(ctx: HoldContext, input: {
    correlation: string;
    toolUseId: string | null;
    generationId: string | null;
    success: boolean;
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
/** Cursor beforeSubmitPrompt: records that the prompt hook runs, and handles "marrow approve CODE". */
export declare function settleTypedReply(ctx: HoldContext, prompt: unknown): Promise<string | null>;
//# sourceMappingURL=host-approval.d.ts.map