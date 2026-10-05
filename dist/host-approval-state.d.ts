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
/** Marks the oldest matching open ask whose dialog was not yet seen; returns it, if any. */
export declare function markDialogShown(scope: HoldScope, query: HoldQuery, at: string, home?: string): HoldRecord | null;
export declare function setSessionMarker(kind: 'interactive' | 'prompt_hook', scope: HoldScope, hostSessionId: string, value: boolean, home?: string): void;
export declare function sessionMarker(kind: 'interactive' | 'prompt_hook', scope: HoldScope, hostSessionId: string, home?: string): boolean | null;
/** True when this key has any hold that still needs work (cheap check before network). */
export declare function hasPendingHolds(scope: HoldScope, query?: HoldQuery, home?: string): boolean;
//# sourceMappingURL=host-approval-state.d.ts.map