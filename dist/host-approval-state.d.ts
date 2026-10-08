/** A hold outlives its 30-minute gate receipt only long enough to settle a late report. */
export declare const HOLD_RECORD_TTL_MS: number;
export declare const APPROVAL_CODE: RegExp;
export type HoldMode = 'ask' | 'wait';
export type HoldState = 'open' | 'allowed' | 'resolved';
export type HoldReport = {
    verdict: 'approved' | 'declined';
    host: string;
    host_session_id: string;
    hook_event: string | null;
    pre_action_event_id: string | null;
    asked_at: string;
    answered_at: string;
    decision_id?: string;
    /** The exact action answered for (secrets removed); kept only until the report is delivered. */
    normalized_action?: Record<string, unknown>;
};
export type HoldCommit = {
    success: boolean;
    outcome: string;
};
export type HoldOutbox = {
    report: HoldReport | null;
    /** The commit that follows the report (a denial, or an outcome that needs no proof). */
    commit: HoldCommit | null;
    attempts: number;
    next_at: number;
};
export type HoldRecord = {
    id: string;
    key_ref: string;
    host: string;
    harness: string;
    session_id: string;
    host_session_id: string;
    agent_id: string | null;
    correlation: string;
    tool_use_id: string | null;
    generation_id: string | null;
    tool_name: string;
    hook_event: string;
    mode: HoldMode;
    state: HoldState;
    gate_receipt_id: string;
    decision_id: string | null;
    asked_at: string;
    dialog_at: string | null;
    pre_action_event_id: string | null;
    proof_required: boolean;
    proof_fields: string[];
    expires_at: string | null;
    code: string | null;
    /**
     * The owner's one-tap approval link: sent; to send (now, or again after a
     * retryable failure); sent only when the operator asks by retrying the action
     * (on_request); could not be sent and will not be retried (failed); or not
     * offered for this hold (null).
     */
    owner_link?: 'sent' | 'unsent' | 'on_request' | 'failed' | null;
    /** Link requests made for this hold (the server allows a few per receipt). */
    link_attempts?: number;
    /** Denied only because Claude Code showed no dialog; a retry where it can asks instead. */
    dialog_later?: boolean;
    /** The host's own prompt text for a later ask (the notice and the reason). */
    ask_text?: string | null;
    /** An older Marrow service without chat or terminal approvals: only the owner approves. */
    legacy_service?: boolean;
    /** Arbitration review: the owner picks a proposal; the commit needs these receipts. */
    arbitration_receipt_id?: string | null;
    /** A hold that waits quietly: a person is here but cannot be asked, or nobody is (unattended). */
    quiet?: 'attended' | 'unattended' | null;
    /** Left to the host's own approval step, which Marrow does not observe. */
    not_observed?: boolean;
    /** The normalized action the runtime call carried (hashes and program names only). */
    normalized_action?: Record<string, unknown>;
    /** Arbitration: a person was at this session when it was held (a retry there is their request for the owner's link). */
    person_present?: boolean;
    action: {
        action: string;
        target: string;
        type: string;
        surfaces: string[];
    };
    outbox: HoldOutbox | null;
    created_at: number;
    updated_at: number;
};
export declare class UnsafeHostApprovalStateError extends Error {
    constructor();
}
export type HoldScope = {
    apiKey: string;
    baseUrl: string;
    agentId?: string | null;
};
export type NewHold = Omit<HoldRecord, 'id' | 'key_ref' | 'code' | 'outbox' | 'created_at' | 'updated_at' | 'state' | 'dialog_at'> & {
    withCode: boolean;
};
/** Records a held action. A previous open hold of the same action and session is replaced. */
export declare function recordHold(scope: HoldScope, input: NewHold, home?: string): HoldRecord;
export type HoldQuery = {
    correlation?: string;
    toolUseId?: string | null;
    sessionId?: string;
    hostSessionId?: string;
    generationId?: string | null;
    mode?: HoldMode;
    states?: HoldState[];
    code?: string;
    id?: string;
};
/** The stored form of a Marrow session id (the bound buildHeaders applies to X-Marrow-Session-Id). */
export declare function boundSessionId(value: string): string;
export declare function findHolds(scope: HoldScope, query: HoldQuery, home?: string): HoldRecord[];
/** Applies a change to one hold under the lock; returns the updated hold, or null when it is gone. */
export declare function updateHold(scope: HoldScope, id: string, change: (hold: HoldRecord) => HoldRecord | null, home?: string): HoldRecord | null;
/**
 * Compare-and-set under the lock: takes an open hold for one run. Returns the
 * claimed hold, or null when another call already claimed or settled it, so
 * one approval never lets two identical calls run.
 */
export declare function claimHold(scope: HoldScope, id: string, change: (hold: HoldRecord) => HoldRecord, home?: string): HoldRecord | null;
/**
 * Remembers which categories the account owner protects, as Marrow reported
 * them for this key: added when a hold says they need the owner's verified
 * approval, removed when a readable answer says they do not.
 */
export declare function noteProtectedCategories(scope: HoldScope, protectedNow: string[], notProtected: string[], home?: string): void;
/** The categories (of those given) this key last saw the account owner protect. */
export declare function protectedCategoriesAmong(scope: HoldScope, categories: string[], home?: string): string[];
/** Marks the oldest matching open ask whose dialog was not yet seen; returns it, if any. */
export declare function markDialogShown(scope: HoldScope, query: HoldQuery, at: string, home?: string): HoldRecord | null;
export declare function setSessionMarker(kind: 'interactive' | 'prompt_hook', scope: HoldScope, hostSessionId: string, value: boolean, home?: string): void;
export declare function sessionMarker(kind: 'interactive' | 'prompt_hook', scope: HoldScope, hostSessionId: string, home?: string): boolean | null;
/** True when this key has any hold that still needs work (cheap check before network). */
export declare function hasPendingHolds(scope: HoldScope, query?: HoldQuery, home?: string): boolean;
//# sourceMappingURL=host-approval-state.d.ts.map