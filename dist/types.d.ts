/**
 * @getmarrow/mcp — Type Definitions
 */
import type { ActionableInsight as SdkActionableInsight, MarrowAskResult as SdkMarrowAskResult, MarrowDashboardResult as SdkMarrowDashboardResult, MarrowDigestResult as SdkMarrowDigestResult, MarrowMemory as SdkMarrowMemory, Narrative as SdkNarrative } from '@getmarrow/sdk';
export type Narrative = SdkNarrative;
export type ActionableInsight = SdkActionableInsight;
export interface ThinkContribution {
    warnings_consulted: number;
    hive_patterns_surfaced: number;
    similar_decisions_found: number;
    workflow_templates_available: number;
    loop_detected: boolean;
    collective_intelligence: boolean;
    team_context_present: boolean;
    has_signal: boolean;
}
export interface CommitContribution {
    success: boolean;
    pattern_reused: boolean;
    linked_to_prior_decision: boolean;
    warning_avoided: boolean;
    has_signal: boolean;
}
export type MarrowMemory = SdkMarrowMemory;
export type MarrowAskResult = SdkMarrowAskResult;
export interface VelocityMetric {
    current: number;
    previous: number;
    delta_pct: number;
    direction: 'improving' | 'declining' | 'stable';
}
export type MarrowDashboardResult = SdkMarrowDashboardResult;
export type MarrowDigestResult = SdkMarrowDigestResult;
export interface MarrowValueReportResult {
    period: {
        days: number;
        start: string;
        end: string;
    };
    scope: {
        agent_id: string | null;
    };
    summary: string;
    metrics: {
        decisions: {
            total: number;
            recorded: number;
            successful: number;
            failed: number;
        };
        success_rate: number;
        saves: {
            period: number;
            total: number;
        };
    };
    fleet: {
        active_agents: number;
        top_agents: Array<{
            agent_id: string;
            decisions: number;
            success_rate: number;
        }>;
    };
    risks: {
        top_failure_types: Array<{
            decision_type: string;
            failures: number;
            failure_rate: number;
        }>;
    };
    recommendations: string[];
    improvement: Record<string, unknown>;
}
export interface MarrowDecisionBriefRequest {
    action: string;
    type?: string;
    agent_id?: string;
    session_id?: string;
    role?: string;
    surfaces?: string[];
    period?: number | string;
    context?: Record<string, unknown>;
    proof?: Record<string, unknown>;
}
export interface MarrowDecisionBriefResult {
    period: {
        days: number;
        start: string;
        end: string;
    };
    scope: {
        agent_id: string | null;
        session_id: string | null;
        role: 'deploy' | 'audit' | 'patch' | 'review' | 'general';
    };
    summary: string;
    risk: {
        level: 'low' | 'medium' | 'high';
        reasons: string[];
        similar_failures: Array<{
            decision_type: string;
            failures: number;
            failure_rate: number;
        }>;
    };
    workflow: {
        recommended: string;
        steps: string[];
        source: 'role_playbook' | 'risk_pattern' | 'general';
    };
    handoff: {
        required: boolean;
        checkpoint_markers: string[];
        stale_after_minutes: number;
    };
    freshness: {
        check_required: boolean;
        surfaces: string[];
        stale_context_warning: boolean;
    };
    quality: {
        minimum_checks: string[];
        outcome_required: boolean;
        score_floor: number;
    };
    role_playbook: {
        role: 'deploy' | 'audit' | 'patch' | 'review' | 'general';
        guidance: string[];
    };
    failure_alerts: Array<{
        decision_type: string;
        message: string;
        severity: 'info' | 'warning' | 'critical';
    }>;
    proof_pack: {
        required: boolean;
        fields: string[];
    };
    source_of_truth: {
        required_surfaces: string[];
        docs_required: boolean;
    };
    fleet_reliability: {
        active_agents: number;
        outcome_coverage: number;
        measurement_risk: 'low' | 'medium' | 'high';
    };
    next_actions: string[];
}
export interface MarrowWorkflowGateRequest {
    action: string;
    description?: string;
    context?: Record<string, unknown>;
    risk_tolerance?: 'low' | 'medium' | 'high';
    requires_approval?: boolean;
}
export interface MarrowWorkflowGateResult {
    allow: boolean;
    decision: 'allow' | 'warn' | 'review_required' | 'block';
    risk_level: 'low' | 'medium' | 'high';
    reasons: Array<{
        code: string;
        severity: string;
        message: string;
    }>;
    agent_id?: string | null;
    session_id?: string | null;
    gate_event_id?: string | null;
    prior_lessons?: unknown[];
    deployment_playbooks?: unknown[];
    next?: Record<string, unknown>;
}
export interface MarrowAgentRuntimeRequest extends MarrowDecisionBriefRequest {
    risk_tolerance?: 'low' | 'medium' | 'high';
    requires_approval?: boolean;
}
export interface MarrowFirstValueRequest {
    action?: string;
    type?: string;
    role?: string;
    surfaces?: string[];
    context?: Record<string, unknown>;
    proof?: Record<string, unknown>;
    agent_id?: string | null;
    session_id?: string | null;
}
export interface MarrowFirstValueResult {
    ok: boolean;
    active: boolean;
    headline: string;
    setup_decision_captured: boolean;
    outcome_closed: boolean;
    runtime_gate_active: boolean;
    first_value: Record<string, unknown>;
    history_signal: Record<string, unknown>;
    capture: Record<string, unknown>;
    value_proof: Record<string, unknown>;
    next_action: Record<string, unknown>;
    runtime: MarrowAgentRuntimeResult;
}
export interface MarrowAgentRuntimeResult {
    ok: boolean;
    action: string;
    agent_id: string | null;
    session_id: string | null;
    status: Record<string, unknown>;
    decision_brief: MarrowDecisionBriefResult;
    risk_gate: MarrowWorkflowGateResult;
    relevant_lessons: unknown[];
    deployment_playbooks: unknown[];
    template_suggestion: Record<string, unknown>;
    proof_pack: {
        required: boolean;
        enforced: boolean;
        fields: string[];
        missing: string[];
        complete: boolean;
        commit_endpoint: string;
        rule: string;
    };
    before_you_act: string | null;
    before_you_act_injection?: {
        required: boolean;
        state?: 'proceed' | 'warn' | 'block' | 'owner_approval_required';
        source: string;
        message: string | null;
        why_now?: string | null;
        noise_policy?: string | null;
        required_proof?: string[];
        missing_proof?: string[];
        owner_approval_required?: boolean;
        untrusted_memory_notice?: string | null;
        untrusted_memory_excerpt?: string | null;
        must_use_before_action: boolean;
        lesson_id: string | null;
        lesson_score: number | null;
        action_pattern: string | null;
        outcome_success: boolean | null;
        playbook_id: string | null;
        risk_level: string;
    };
    runtime_policy?: {
        interruption: 'proceed' | 'warn' | 'block' | 'owner_approval_required';
        quiet_for_normal_work: boolean;
        interrupts_when: string[];
        blocks_only_when: string[];
    };
    exact_next_action: string | null;
    auto_outcome_closure: Record<string, unknown> | null;
}
export interface MarrowAgentStatusResult {
    period: {
        days: number;
        start: string;
        end: string;
    };
    scope: {
        agent_id: string | null;
    };
    active: boolean;
    state: 'inactive' | 'warming_up' | 'needs_outcomes' | 'learning' | 'proving_value';
    summary: string;
    signals: {
        decisions_logged: number;
        outcomes_recorded: number;
        outcome_coverage: number;
        success_rate: number;
        saves: {
            period: number;
            total: number;
        };
        active_agents: number;
        first_decision_at: string | null;
        last_decision_at: string | null;
    };
    quality: {
        enough_signal: boolean;
        measurement_risk: 'low' | 'medium' | 'high';
    };
    proof: {
        recent_decision_count: number;
        last_decision_at: string | null;
        has_recent_outcomes: boolean;
        has_prevented_failures: boolean;
        raw_data_exposed: false;
    };
    next_actions: string[];
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
    marrow_contributed?: ThinkContribution;
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
    narrative: Narrative;
    marrow_contributed?: CommitContribution;
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
export interface MarrowNudgeResult {
    nudge: boolean;
    message: string | null;
    metrics: {
        total_decisions: number;
        decisions_since_last_nudge: number;
        nudged_at: string | null;
        nudged_decision_count: number;
        saves_count: number;
        highlights: Array<{
            key: string;
            label: string;
            delta_pct?: number;
            value?: number;
            sentence: string;
        }>;
        improvement?: unknown;
    } | null;
}
//# sourceMappingURL=types.d.ts.map