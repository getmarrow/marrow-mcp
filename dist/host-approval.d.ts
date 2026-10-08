import { type NativeHookHarness } from './hook-contract';
import { type ArbitrationApprovalGuidance, type OrdinaryApprovalGuidance } from './runtime-contract';
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
/** Claude Code entrypoints with no one at a dialog (claude -p, the Agent SDKs, its GitHub Action); hooks inherit it. */
export declare const HEADLESS_CLAUDE_ENTRYPOINTS: Set<string>;
export declare function claudeCodeHeadless(env?: NodeJS.ProcessEnv): boolean;
/** Cursor events on which a hook "ask" is enforced (never preToolUse). */
export declare const CURSOR_ASK_EVENTS: Set<string>;
export declare const HOST_APPROVAL_REQUEST_TIMEOUT_MS = 4000;
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
export declare function preToolBudgetMs(host: ApprovalHost): number;
/**
 * The hook process's deadline for its pre-tool answer and any follow-up work.
 * Codex's kill clock starts when it spawns the hook command, so the time npx
 * (or a shell) took to start this process comes out of the budget: the answer
 * comes about 2.6 s after spawn, with at least 1 s for this process itself.
 */
export declare function preToolDeadline(host: ApprovalHost, headStartMs?: () => number): number;
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
}
/** The owner already has a live link (this hold's, or the arbitration's own on the service). */
 | {
    kind: 'already_sent';
    channel?: string;
    expiresAt?: string | null;
} | {
    kind: 'deferred';
} | {
    kind: 'retryable';
} | {
    kind: 'failed';
    code: string | null;
}
/** The service sent nothing on purpose (owner_ping_off): the hold waits quietly. */
 | {
    kind: 'not_sent';
} | {
    kind: 'none';
};
/** The sentence for what happened to the owner's link. Never claims a send that did not happen. */
export declare function ownerRequestText(outcome: OwnerLinkOutcome): string;
export type HoldPlan = {
    kind: 'ask';
    promptText: string;
}
/**
 * Marrow does not block: a person is here but Marrow can neither ask in this
 * host nor observe its answer, so the host's own approval step decides (owner
 * rule). The outcome is recorded as approved through the host's own prompt,
 * not observed by Marrow (an allow rule, client-attested), never as the operator's answer.
 */
 | {
    kind: 'pass';
    contextText: string;
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
    /** Waits quietly: nobody can be asked here (attended) or nobody is here (unattended). */
    quiet?: 'attended' | 'unattended';
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
 * When no one can answer here, the action waits quietly (the owner's link only
 * for owner-locked categories, the owner's own decline when the operator asks,
 * or unattended runs with the owner's pings on).
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
}): HoldPlan;
/**
 * Hosts where an ordinary hold Marrow cannot ask about is left to the host's
 * own approval step: those whose hook can answer neutrally (no decision), so
 * the host's normal permission flow runs. A hook never emits an explicit
 * allow for a held action. Gemini CLI and Grok are not here (their installed
 * guards accept only an explicit allow or a fixed denial), nor is Cursor
 * (preToolUse has no neutral answer and "ask" is not enforced there): those
 * hold quietly.
 */
export declare const PASS_THROUGH_HOSTS: ReadonlySet<ApprovalHost>;
/** The hook_event of an answer given in a host prompt Marrow did not observe (labelled an allow rule). */
export declare const HOST_PROMPT_NOT_OBSERVED = "host_prompt_not_observed";
/** What the person sees when this host cannot ask them: the action waits for them. */
export declare const HELD_FOR_YOU_TEXT = "This action is held until you approve it. Approve it by retrying it in a session with Marrow's prompt.";
/**
 * Arbitration review_required with the server's one-tap path: the owner picks
 * and approves one proposal. The hook denies, asks Marrow to send the owner a
 * link, and the retried action reads the status. Nobody is told to log in.
 */
export declare function planArbitrationHold(guidance: ArbitrationApprovalGuidance, options?: {
    unattended?: boolean;
}): HoldPlan;
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
export declare function rememberHold(ctx: HoldContext, input: RecordHoldInput): HoldRecord;
/**
 * Remembers the categories the account owner protects, from a hold's guidance,
 * so an owner-protected action stays held while Marrow cannot be reached.
 */
export declare function rememberProtection(ctx: HoldContext, guidance: OrdinaryApprovalGuidance): void;
/** Of these categories, the ones this key last saw the account owner protect. */
export declare function protectedAmong(ctx: HoldContext, categories: string[]): string[];
/** Text for a person: the agent's text without receipt ids (the agent keeps them to close the action). */
export declare function forPerson(text: string): string;
/** An agent id worth showing a person: not an automatic seat or key-derived fallback id. */
export declare function personAgentName(agent: string | null | undefined): string | null;
/**
 * Asks Marrow to send the account owner a one-tap approval link for this hold.
 * A retryable failure (network, rate limit, undelivered) is tried again on a
 * later attempt, up to the server's per-receipt limit; a final refusal is not.
 * Returns what happened. The link itself never reaches this client or the agent.
 */
export declare function requestOwnerLink(ctx: HoldContext, hold: HoldRecord, reserve?: number): Promise<OwnerLinkOutcome>;
/**
 * Once per interactive host session (its first prompt): tells the person how
 * many held actions are waiting for them, with the action type and agent only,
 * and refreshes this machine's copy of the owner-locked categories (so they
 * stay held during an outage on a fresh machine). Returns user-only text, or null.
 */
export declare function heldActionsNotice(ctx: HoldContext, budgetMs?: number): Promise<string | null>;
/** PermissionRequest (pass-through): the host is about to show its own dialog for an asked call. */
export declare function noteDialogShown(ctx: HoldContext, correlation: string): HoldRecord | null;
/**
 * Whether Claude Code runs Marrow's pass-through PermissionRequest hook here:
 * seen on this machine for this key, or configured in the user's or the
 * project's Claude Code settings. Without it there is no marker to wait for.
 */
export declare function permissionMarkerHookPresent(ctx: HoldContext, cwd?: string): boolean;
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
/** The proof fields this machine's hold for a receipt asked for (empty when unknown). */
export declare function proofFieldsForReceipt(ctx: HoldContext, gateReceiptId: string): string[];
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
    /** The exact action from this hook event, for the report (never stored). */
    normalizedAction?: Record<string, unknown> | null;
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
 * interactive (Codex and Gemini CLI: the host process has a terminal and no
 * scripted subcommand or prompt flag), the host must still ask before it runs
 * a tool (otherwise the agent could run the prompt hook itself with a code it
 * read from this user's files: Codex with its approval prompt off, Gemini CLI
 * in YOLO mode, and Cursor, whose auto-run cannot be seen, get no typed reply
 * and no code), and its prompt hook must already have run, so the reply can
 * reach Marrow at all.
 */
export declare function typedReplyAvailable(ctx: HoldContext, interactive?: (host: string) => boolean | null, promptOff?: (host: string) => boolean): boolean;
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