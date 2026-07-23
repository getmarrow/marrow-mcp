export type LifecycleEvent = {
    event_id?: string;
    event_type: string;
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
    queued: boolean;
    pending: number;
}>;
//# sourceMappingURL=lifecycle-spool.d.ts.map