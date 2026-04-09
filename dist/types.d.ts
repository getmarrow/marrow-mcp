/**
 * @getmarrow/mcp — Type Definitions
 */
export interface ActionableInsight {
    type: 'frequency' | 'failure_pattern' | 'workflow_gap' | 'hive_trend';
    summary: string;
    action: string;
    severity: 'info' | 'warning' | 'critical';
    count: number;
}
export interface MarrowIntelligence {
    similar: Array<{
        outcome: string;
        confidence: number;
    }>;
    similar_count: number;
    patterns: Array<{
        pattern_id: string;
        decision_type: string;
        frequency: number;
        confidence: number;
    }>;
    patterns_count: number;
    templates: Array<{
        steps: unknown[];
        success_rate: number;
    }>;
    shared: Array<{
        outcome: string;
    }>;
    causal_chain: unknown | null;
    success_rate: number;
    priority_score: number;
    insight: string | null;
    insights: ActionableInsight[];
    cluster_id: string | null;
}
export interface ThinkResult {
    decision_id: string;
    intelligence: MarrowIntelligence;
    stream_url: string;
    previous_committed?: boolean;
    sanitized?: boolean;
    upgrade_hint?: {
        message: string;
        tier: string;
        url: string;
    };
    loop_warnings?: Array<{
        type: 'LOOP_DETECTED';
        severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
        message: string;
        previousFailure: {
            timestamp: string;
            action: string;
            outcome: string;
            reason: string;
        };
        recommendation?: {
            action: string;
            successCount: number;
            confidence: number;
        };
    }>;
}
export interface CommitResult {
    committed: boolean;
    success_rate: number;
    insight: string | null;
}
export interface StatusResult {
    status: string;
    version: string;
    tiers: number;
    uptime_ms: number;
}
export interface AgentPatternsResult {
    failure_patterns: Array<{
        decision_type: string;
        failure_rate: number;
        count: number;
        last_seen: string;
    }>;
    recurring_decisions: Array<{
        decision_type: string;
        frequency: number;
        avg_confidence: number;
        trend: string;
    }>;
    behavioral_drift: {
        success_rate_7d: number;
        success_rate_30d: number;
        drift: string;
        direction: string;
    };
    top_failure_types: string[];
    generated_at: string;
}
export interface MarrowAskResult {
    answer: string;
    stats: {
        total: number;
        success: number;
        failure: number;
        failure_rate: number;
    } | null;
    top_outcomes: string[];
    decisions_matched: number;
}
export interface MarrowMemory {
    id: string;
    text: string;
    status: string;
    createdAt: string;
    updatedAt: string;
    source: string | null;
    tags: string[];
}
export interface OrientResult {
    warnings: Array<{
        type: string;
        failureRate: number;
        message: string;
    }>;
    serverWarnings?: Array<{
        severity: 'HIGH' | 'MEDIUM' | 'LOW';
        message: string;
        pattern: string;
        recommendation?: string;
    }>;
    loopState?: {
        isOpen: boolean;
        lastCommit: string | null;
    };
    shouldPause: boolean;
}
export interface WorkflowResult {
    success: boolean;
    data?: Record<string, unknown>;
    error?: string;
}
//# sourceMappingURL=types.d.ts.map