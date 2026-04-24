/**
 * @getmarrow/mcp — Type Definitions
 */

export type Narrative = string | null;

export interface ActionableInsight {
  type: 'frequency' | 'failure_pattern' | 'workflow_gap' | 'hive_trend';
  summary: string;
  action: string;
  severity: 'info' | 'warning' | 'critical';
  count: number;
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
  loopState?: { isOpen: boolean; lastCommit: string | null };
  shouldPause: boolean;
}

export interface WorkflowResult {
  success: boolean;
  data?: Record<string, unknown>;
  error?: string;
}

export interface VelocityMetric {
  current: number;
  previous: number;
  delta_pct: number;
  direction: 'improving' | 'declining' | 'stable';
}

export interface Velocity {
  attempts_per_success: VelocityMetric;
  time_to_success_seconds: VelocityMetric;
  drift_rate: VelocityMetric;
}

/** Baseline → current delta for a single improvement metric. */
export interface ImprovementMetricDelta {
  baseline: number;
  current: number;
  delta_pct: number;
}

/** Active improvement block — returned once baseline has been captured. */
export interface ImprovementActive {
  status: 'active';
  days_since_baseline: number;
  decisions_since_baseline: number;
  baseline_captured_at: string;
  trigger_reason: 'time_7d' | 'volume_20';
  attempts_per_success: ImprovementMetricDelta;
  time_to_success_seconds: ImprovementMetricDelta;
  /** 0-100 percentage. Lower = more pattern reuse, less rediscovery. */
  drift_rate: ImprovementMetricDelta;
  /** 0-1 fraction. Higher = better. */
  success_rate: ImprovementMetricDelta;
}

/** Onboarding payload — returned until an account has 7 days OR 20 decisions. */
export interface ImprovementOnboarding {
  status: 'onboarding';
  days_elapsed: number;
  decisions_elapsed: number;
  days_until_time_trigger: number;
  decisions_until_volume_trigger: number;
  reason: string;
}

export type Improvement = ImprovementActive | ImprovementOnboarding;

export interface MarrowDashboardResult {
  account: { agent_count: number; total_decisions: number; active_since: string };
  health: { overall_score: number; label: string; success_rate_7d: number; success_rate_30d: number; trend: string; trend_delta: number };
  top_failures: Array<{ decision_type: string; failure_rate: number; count: number; last_seen: string; top_reason: string | null }>;
  workflow_status: { active: number; completed_this_week: number; stalled: number; stalled_workflows: Array<{ instance_id: string; workflow_name: string; stalled_at_step: number; stalled_since: string; waiting_for: string }> };
  impact: { saves_this_week: number; saves_total: number; failures_prevented_details: Array<unknown> };
  velocity: Velocity;
  improvement: Improvement;
  recent_decisions: { today: number; this_week: number; by_type: Record<string, number> };
}

export interface MarrowDigestResult {
  period: string;
  summary: string;
  decisions: { total: number; successful: number; failed: number };
  success_rate: { current: number; previous_period: number; change: number; direction: string };
  saves: { count: number; details: unknown[] };
  velocity: Velocity;
  improvement: Improvement;
  top_improvements: string[];
  top_risks: string[];
  workflows_completed: number;
  workflows_stalled: number;
}
