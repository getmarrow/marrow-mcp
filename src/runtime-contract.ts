import type { MarrowAgentRuntimeResult, MarrowRuntimePlanCapability } from './types';

const RUNTIME_GATE_DECISIONS = new Set([
  'allow',
  'proceed',
  'warn',
  'review_required',
  'owner_approval_required',
  'block',
  'deny',
  'denied',
]);

const RUNTIME_RISK_LEVELS = new Set(['low', 'medium', 'high', 'critical']);
const RUNTIME_PLAN_MODES = new Set(['advisory', 'pilot', 'enforced', 'unknown']);

function optionalRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function explicitBoolean(source: Record<string, unknown> | null, ...fields: string[]): boolean | null {
  if (!source) return null;
  for (const field of fields) {
    if (typeof source[field] === 'boolean') return source[field] as boolean;
  }
  return null;
}

function boundedPlan(value: unknown): string | null {
  const plan = typeof value === 'string' ? value.trim().toLowerCase() : '';
  return plan && /^[a-z][a-z0-9_-]{0,31}$/.test(plan) ? plan : null;
}

function boundedLimit(value: unknown): number | null {
  return Number.isSafeInteger(value) && Number(value) >= 0 ? Number(value) : null;
}

export function normalizeRuntimePlanCapability(
  value: unknown,
  riskGateValue?: unknown,
): MarrowRuntimePlanCapability | null {
  const runtime = optionalRecord(value);
  const supplied = optionalRecord(runtime?.plan_capability);
  const access = optionalRecord(runtime?.plan_access);
  const features = optionalRecord(access?.features);
  const riskGate = optionalRecord(riskGateValue) || optionalRecord(runtime?.risk_gate);
  if (!supplied && !access && explicitBoolean(riskGate, 'enforced') == null && explicitBoolean(riskGate, 'entitled') == null) {
    return null;
  }

  const currentPlan = boundedPlan(supplied?.current_plan) || boundedPlan(access?.plan);
  const evaluationActive = explicitBoolean(supplied, 'evaluation_active')
    ?? explicitBoolean(access, 'evaluation_access');
  const preActionEntitled = explicitBoolean(supplied, 'pre_action_gate_entitled')
    ?? explicitBoolean(features, 'pre_action_risk_gates')
    ?? explicitBoolean(riskGate, 'entitled');
  const productionEntitled = explicitBoolean(supplied, 'production_enforcement_entitled')
    ?? explicitBoolean(features, 'production_action_enforcement');
  const handoffEntitled = explicitBoolean(supplied, 'handoff_status_entitled')
    ?? explicitBoolean(features, 'fleet_learning');
  const suppliedMode = typeof supplied?.mode === 'string' && RUNTIME_PLAN_MODES.has(supplied.mode)
    ? supplied.mode as MarrowRuntimePlanCapability['mode']
    : null;
  const enforced = explicitBoolean(riskGate, 'enforced');
  const mode: MarrowRuntimePlanCapability['mode'] = suppliedMode
    || (enforced === true
      ? productionEntitled === true ? 'enforced' : 'unknown'
      : enforced === false
      ? preActionEntitled === true ? 'pilot' : 'advisory'
      : productionEntitled === true
      ? 'unknown'
      : preActionEntitled === true
      ? 'pilot'
      : preActionEntitled === false || productionEntitled === false
      ? 'advisory'
      : 'unknown');
  const suppliedLimits = optionalRecord(supplied?.limits);
  const accessLimits = optionalRecord(access?.limits);
  const limitsSource = suppliedLimits || accessLimits;
  const overage = typeof limitsSource?.decision_overage_behavior === 'string'
    ? String(limitsSource.decision_overage_behavior).slice(0, 64)
    : null;

  return {
    current_plan: currentPlan,
    evaluation_active: evaluationActive,
    mode,
    pre_action_gate_entitled: preActionEntitled,
    production_enforcement_entitled: productionEntitled,
    handoff_status_entitled: handoffEntitled,
    limits: limitsSource ? {
      agents: boundedLimit(limitsSource.agents),
      included_decisions_per_month: boundedLimit(limitsSource.included_decisions_per_month),
      decision_overage_behavior: overage,
    } : null,
  };
}

function authoritativeHardGate(
  runtime: MarrowAgentRuntimeResult,
  planCapability: MarrowRuntimePlanCapability | null,
): boolean {
  if (runtime.risk_gate.enforced === false
    || planCapability?.production_enforcement_entitled === false
    || planCapability?.mode === 'advisory'
    || planCapability?.mode === 'pilot') {
    return false;
  }
  const enforcementDecision = String(runtime.risk_gate.enforcement_decision || '').toLowerCase();
  const explicitEnforcement = runtime.risk_gate.enforced === true
    && ['allow', 'proceed', 'warn'].includes(enforcementDecision);
  const serverRequiredSlimGate = (runtime as MarrowAgentRuntimeResult & { response_mode?: unknown }).response_mode === 'slim'
    && runtime.risk_gate.enforced == null
    && !enforcementDecision
    && runtime.gate_receipt?.required === true;
  return explicitEnforcement || serverRequiredSlimGate;
}

function withAuthorizationTruth(runtime: MarrowAgentRuntimeResult): MarrowAgentRuntimeResult {
  const planCapability = normalizeRuntimePlanCapability(runtime, runtime.risk_gate);
  const hardGate = authoritativeHardGate(runtime, planCapability);
  const advisory = runtime.risk_gate.enforced === false
    || planCapability?.production_enforcement_entitled === false
    || planCapability?.mode === 'advisory'
    || planCapability?.mode === 'pilot';
  return {
    ...runtime,
    ...(planCapability ? { plan_capability: planCapability } : {}),
    fresh_runtime_response: true,
    guidance_obtained: true,
    authorization_state: hardGate ? 'hard_gate' : advisory ? 'advisory_only' : 'unverified',
    hard_gate_obtained: hardGate,
  };
}

export function isValidRuntimeResult(value: unknown): value is MarrowAgentRuntimeResult {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const riskGate = (value as Record<string, unknown>).risk_gate;
  if (!riskGate || typeof riskGate !== 'object' || Array.isArray(riskGate)) return false;
  const gate = riskGate as Record<string, unknown>;
  return typeof gate.allow === 'boolean'
    && typeof gate.decision === 'string'
    && RUNTIME_GATE_DECISIONS.has(gate.decision);
}

export function normalizeRuntimeResult(value: unknown): MarrowAgentRuntimeResult | null {
  if (isValidRuntimeResult(value)) return withAuthorizationTruth(value);
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const slim = value as Record<string, unknown>;
  if (slim.response_mode !== 'slim'
    || typeof slim.decision !== 'string'
    || !RUNTIME_GATE_DECISIONS.has(slim.decision)
    || typeof slim.risk_level !== 'string'
    || !RUNTIME_RISK_LEVELS.has(slim.risk_level)
    || typeof slim.gate_required !== 'boolean'
    || typeof slim.proof_required !== 'boolean'
    || typeof slim.proof_complete !== 'boolean') {
    return null;
  }
  const allow = ['allow', 'proceed', 'warn'].includes(slim.decision);
  const gateReceiptId = typeof slim.gate_receipt_id === 'string' && slim.gate_receipt_id
    ? slim.gate_receipt_id
    : null;
  const enforced = explicitBoolean(slim, 'risk_gate_enforced', 'enforced');
  const entitled = explicitBoolean(slim, 'risk_gate_entitled', 'entitled');
  const enforcementDecision = typeof slim.enforcement_decision === 'string'
    ? slim.enforcement_decision.slice(0, 64)
    : undefined;
  const normalized = {
    ...slim,
    ok: slim.ok !== false,
    action: '',
    agent_id: typeof slim.agent_id === 'string' ? slim.agent_id : null,
    session_id: typeof slim.session_id === 'string' ? slim.session_id : null,
    status: { health: slim.health || null, missed_hooks: slim.missed_hooks || [] },
    decision_brief: {} as MarrowAgentRuntimeResult['decision_brief'],
    risk_gate: {
      allow,
      decision: slim.decision === 'proceed' ? 'allow' : slim.decision as MarrowAgentRuntimeResult['risk_gate']['decision'],
      risk_level: slim.risk_level as MarrowAgentRuntimeResult['risk_gate']['risk_level'],
      reasons: [],
      gate_receipt_id: gateReceiptId,
      gate_required: slim.gate_required,
      ...(enforced != null ? { enforced } : {}),
      ...(entitled != null ? { entitled } : {}),
      ...(enforcementDecision ? { enforcement_decision: enforcementDecision } : {}),
    },
    relevant_lessons: [],
    deployment_playbooks: [],
    template_suggestion: {},
    gate_receipt_id: gateReceiptId,
    gate_receipt: gateReceiptId ? {
      id: gateReceiptId,
      required: slim.gate_required,
      decision: slim.decision,
    } : null,
    proof_pack: {
      required: slim.proof_required,
      enforced: slim.proof_required,
      fields: [],
      missing: slim.proof_complete ? [] : ['required_proof'],
      complete: slim.proof_complete,
      commit_endpoint: '/v1/agent/commit',
      rule: slim.proof_required ? 'proof_required_before_complete' : 'outcome_commit_required',
    },
    before_you_act: typeof slim.before_you_act === 'string' ? slim.before_you_act : null,
    exact_next_action: typeof slim.exact_next_action === 'string' ? slim.exact_next_action : null,
    auto_outcome_closure: null,
  } as MarrowAgentRuntimeResult;
  return withAuthorizationTruth(normalized);
}

export function highRiskRuntimeCanClose(
  runtime: MarrowAgentRuntimeResult,
  proof: Record<string, unknown> | undefined,
  explicitReceiptId: unknown,
  now: number = Date.now(),
): boolean {
  const decision = String(runtime.risk_gate?.decision || '').toLowerCase();
  const receiptDecision = String(runtime.gate_receipt?.decision || decision).toLowerCase();
  const receiptId = typeof explicitReceiptId === 'string' && explicitReceiptId.trim()
    ? explicitReceiptId.trim()
    : runtime.gate_receipt?.id || runtime.gate_receipt_id || '';
  const receiptExpired = runtime.gate_receipt?.expires_at
    ? Date.parse(runtime.gate_receipt.expires_at) <= now
    : false;
  const planCapability = runtime.plan_capability || normalizeRuntimePlanCapability(runtime, runtime.risk_gate);
  return Boolean(
    proof
    && Object.keys(proof).length > 0
    && runtime.risk_gate?.allow === true
    && authoritativeHardGate(runtime, planCapability)
    && ['allow', 'proceed', 'warn'].includes(decision)
    && ['allow', 'proceed', 'warn'].includes(receiptDecision)
    && runtime.proof_pack?.complete === true
    && receiptId
    && !receiptExpired
    && runtime.gate_receipt?.owner_approval_required !== true
    && runtime.intervention?.must_stop !== true
    && runtime.intervention?.allow !== false
  );
}
