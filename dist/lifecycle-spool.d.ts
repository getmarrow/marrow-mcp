export declare const LIFECYCLE_EVENT_TYPES: readonly ["activation_profile_registered", "prompt_submitted", "goal_started", "pre_action_checked", "risk_gate_requested", "tool_completed", "tool_failed", "command_completed", "command_failed", "verification_evidence_added", "workflow_completed", "session_completed", "learned_workflow_created", "journey_update", "subagent_completed", "handoff_started", "handoff_completed", "proof_pack_closed", "outcome_committed"];
export type LifecycleEventType = typeof LIFECYCLE_EVENT_TYPES[number];
export type LifecycleEvent = {
    event_id?: string;
    event_type: LifecycleEventType;
    harness?: string;
    agent_id?: string;
    action: string;
    target?: string;
    surfaces?: string[];
    workflow_id?: string;
    session_id?: string;
    decision_id?: string;
    correlation_id?: string;
    source?: 'client_self_reported';
    intervention_disposition?: 'followed' | 'ignored' | 'overridden';
    action_changed?: boolean;
    risk_level?: 'low' | 'medium' | 'high';
    outcome_state?: 'pending' | 'closed' | 'unknown' | 'timed_out';
    success?: boolean;
    occurred_at?: string;
};
type RetryReason = 'network_error' | 'ack_timeout' | 'transient_http' | 'rate_limited' | 'authentication_rejected' | 'schema_rejected' | 'permanent_http' | 'retry_after_invalid';
export declare const BACKGROUND_NUDGE_MAX_LIFETIME_MS = 25000;
export type LifecycleSpoolStatus = {
    state: 'clear' | 'pending' | 'attention_required';
    pending: number;
    failed: number;
    recoverable: number;
    server_owned: number;
    recovery_exhausted: number;
    oldest_pending_at: string | null;
    oldest_failed_at: string | null;
    capacity: number;
    available: number;
    recovered_corruption: boolean;
    exact_fix: string | null;
    retry: {
        due: number;
        scheduled: number;
        blocked: number;
        capacity_blocked: number;
        next_attempt_at: string | null;
        reasons: Partial<Record<RetryReason, number>>;
    };
    other_namespaces: {
        state: 'clear' | 'attention_required';
        count: number;
        count_exact: boolean;
        scanned: number;
        scan_limit: number;
        directory_entries_scanned: number;
        directory_entry_limit: number;
        pending: number;
        failed: number;
        event_counts_exact: boolean;
        unreadable: number;
        truncated: boolean;
        blocks_current_namespace: false;
        exact_fix: string | null;
        safe_recovery_action: string | null;
        safe_quarantine_action: string | null;
    };
};
export declare function lifecycleSpoolStatus(input: {
    apiKey: string;
    agentId?: string;
}): LifecycleSpoolStatus;
export declare function shouldNudgeLifecycleSpool(spool: LifecycleSpoolStatus): boolean;
export declare function quarantineLegacyNamespaces(input: {
    apiKey: string;
    agentId?: string;
}): {
    moved: number;
    destination: string | null;
};
export declare function nudgeLifecycleSpool(input: {
    apiKey: string;
    baseUrl: string;
    agentId?: string;
}): Promise<void>;
export declare function drainLifecycleSpool(input: {
    apiKey: string;
    baseUrl: string;
    agentId?: string;
    maxEvents?: number;
    budgetMs?: number;
    requestTimeoutMs?: number;
    retryDeadLetters?: boolean;
    /** Used by the finite background owner; explicit drains attempt each ID once. */
    retryWithinBudget?: boolean;
}): Promise<LifecycleSpoolStatus>;
/**
 * A lifecycle event whose id names exactly its payload: `${base}-${12 hex}`
 * of the fields the service stores, with its time fixed. A resend of the
 * stored event carries the same bytes under the same id; a changed payload
 * (another attempt, another turn) gets a new id, so the service never sees one
 * id with two payloads.
 */
export declare function payloadBoundEvent<E extends Omit<LifecycleEvent, 'event_id'>>(base: string, event: E): E & {
    event_id: string;
    occurred_at: string;
};
export declare function recordLifecycleEvent(input: {
    apiKey: string;
    baseUrl: string;
    event: LifecycleEvent;
    deferDelivery?: boolean;
    /**
     * With a payload-bound id (payloadBoundEvent): a still-queued event under the
     * same base (`${base}-…`) stands for this one, so a quick retry of the same
     * hook adds nothing; once delivered, a new payload is a new record.
     */
    reuseQueuedBase?: string;
}): Promise<{
    event_id: string;
    accepted: boolean;
    queued: boolean;
    failed: boolean;
    pending: number;
    recovered_corruption: boolean;
}>;
/** True when PostToolUse may defer delivery to a detached background nudge. */
export declare function backgroundNudgeEnabled(): boolean;
/** Cheap current-namespace check (no other-namespace inventory): any queued event due now? */
export declare function hasDueLifecycleEvents(input: {
    apiKey: string;
    agentId?: string;
}): boolean;
/**
 * Cross-process guard so a burst of hook invocations starts at most one detached
 * background nudge per credential namespace. The lock file holds a random nonce
 * (plus the claiming pid for diagnostics); only the holder of that nonce releases
 * it. Returns the nonce, or null when not claimed. Best effort: any filesystem
 * problem means no background nudge (the event stays spooled).
 */
export declare function claimBackgroundNudgeLock(input: {
    apiKey: string;
    agentId?: string;
}): string | null;
/** Release only when the lock still carries this nonce (a reclaimed lock is not ours). */
export declare function releaseBackgroundNudgeLock(input: {
    apiKey: string;
    agentId?: string;
    nonce: string;
}): void;
export {};
//# sourceMappingURL=lifecycle-spool.d.ts.map