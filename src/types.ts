/**
 * @getmarrow/mcp — Type Definitions
 */

import type {
  ActionableInsight as SdkActionableInsight,
  MarrowAskResult as SdkMarrowAskResult,
  MarrowDashboardResult as SdkMarrowDashboardResult,
  MarrowDigestResult as SdkMarrowDigestResult,
  MarrowMemory as SdkMarrowMemory,
  Narrative as SdkNarrative,
} from '@getmarrow/sdk';

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

export interface MarrowAgentStatusResult {
  period: { days: number; start: string; end: string };
  scope: { agent_id: string | null };
  active: boolean;
  state: 'inactive' | 'warming_up' | 'needs_outcomes' | 'learning' | 'proving_value';
  summary: string;
  signals: {
    decisions_logged: number;
    outcomes_recorded: number;
    outcome_coverage: number;
    success_rate: number;
    saves: { period: number; total: number };
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
  similar: Array<{ outcome: string; confidence: number }>;
  similar_count: number;
  patterns: Array<{
    pattern_id: string;
    decision_type: string;
    frequency: number;
    confidence: number;
  }>;
  patterns_count: number;
  templates: Array<{ steps: unknown[]; success_rate: number }>;
  shared: Array<{ outcome: string }>;
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
  upgrade_hint?: { message: string; tier: string; url: string };
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
  loopState?: { isOpen: boolean; lastCommit: string | null };
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
