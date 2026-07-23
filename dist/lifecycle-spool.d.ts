export declare const LIFECYCLE_EVENT_TYPES: readonly ["prompt_submitted", "goal_started", "pre_action_checked", "risk_gate_requested", "tool_completed", "tool_failed", "command_completed", "command_failed", "verification_evidence_added", "workflow_completed", "session_completed", "learned_workflow_created", "journey_update", "subagent_completed", "handoff_started", "handoff_completed", "proof_pack_closed", "outcome_committed"];
export type LifecycleEventType = typeof LIFECYCLE_EVENT_TYPES[number];
export type LifecycleEvent = {
    event_id?: string;
    event_type: LifecycleEventType;
    harness?: string;
    agent_id?: string;
    action: string;
    workflow_id?: string;
    session_id?: string;
    decision_id?: string;
    risk_level?: 'low' | 'medium' | 'high';
    outcome_state?: 'pending' | 'closed' | 'unknown' | 'timed_out';
    success?: boolean;
    occurred_at?: string;
};
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