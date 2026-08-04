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
    adapter_version?: string;
    capability_level?: 'native_hooks' | 'mcp' | 'sdk_passive_runtime' | 'governed_wrapper' | 'event_contract';
    config_fingerprint?: string;
    expected_hooks?: string[];
    observed_hook?: string;
    intervention_disposition?: 'followed' | 'ignored' | 'overridden';
    action_changed?: boolean;
    risk_level?: 'low' | 'medium' | 'high';
    outcome_state?: 'pending' | 'closed' | 'unknown' | 'timed_out';
    success?: boolean;
    occurred_at?: string;
};
export type LifecycleSpoolStatus = {
    state: 'clear' | 'pending' | 'attention_required';
    pending: number;
    failed: number;
    oldest_pending_at: string | null;
    oldest_failed_at: string | null;
    capacity: number;
    available: number;
    recovered_corruption: boolean;
    exact_fix: string | null;
};
export declare function lifecycleSpoolStatus(input: {
    apiKey: string;
    agentId?: string;
}): LifecycleSpoolStatus;
export declare function drainLifecycleSpool(input: {
    apiKey: string;
    baseUrl: string;
    agentId?: string;
}): Promise<LifecycleSpoolStatus>;
export declare function recordLifecycleEvent(input: {
    apiKey: string;
    baseUrl: string;
    event: LifecycleEvent;
}): Promise<{
    event_id: string;
    accepted: boolean;
    queued: boolean;
    failed: boolean;
    pending: number;
    recovered_corruption: boolean;
}>;
//# sourceMappingURL=lifecycle-spool.d.ts.map