import type { MarrowAgentRuntimeResult, MarrowRuntimePlanCapability } from './types';

const RUNTIME_GATE_DECISIONS = new Set([
  'allow',
  'proceed',
  'warn',
  'outcome_observation_only',
  'review_required',
  'owner_approval_required',
  'block',
  'deny',
  'denied',
]);

const RUNTIME_RISK_LEVELS = new Set(['low', 'medium', 'high', 'critical']);
const RUNTIME_PLAN_MODES = new Set(['advisory', 'pilot', 'enforced', 'unknown']);
const SAFE_RUNTIME_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/;
const OUTCOME_OBSERVATION_ONLY = 'outcome_observation_only';
const OUTCOME_OBSERVATION_ONLY_ID = /^outcome_observation_only_[a-f0-9]{32}$/;

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

function safeRuntimeIdentifier(value: unknown): string | null {
  const normalized = typeof value === 'string' ? value.trim() : '';
  return normalized && SAFE_RUNTIME_IDENTIFIER.test(normalized) ? normalized : null;
}

export function runtimeAuthorizationReceiptId(
  runtime: MarrowAgentRuntimeResult | null | undefined,
): string | null {
  if (runtime?.runtime_authorization?.kind === OUTCOME_OBSERVATION_ONLY) return null;
  return safeRuntimeIdentifier(runtime?.runtime_authorization?.id);
}

export function isOutcomeObservationOnlyCorrelationId(value: unknown): boolean {
  return typeof value === 'string' && OUTCOME_OBSERVATION_ONLY_ID.test(value);
}

function canonicalRuntimeReceipt(runtime: MarrowAgentRuntimeResult): {
  id: string | null;
  conflict: boolean;
} {
  const identifiers = [
    runtime.runtime_authorization?.id,
    runtime.gate_receipt?.id,
    runtime.gate_receipt_id,
    runtime.risk_gate?.gate_receipt_id,
  ].map(safeRuntimeIdentifier).filter((id): id is string => Boolean(id));
  const unique = [...new Set(identifiers)];
  return {
    id: unique.length === 1 ? unique[0] : null,
    conflict: unique.length > 1,
  };
}

function runtimeRequiresReceipt(runtime: MarrowAgentRuntimeResult): boolean {
  const shape = runtime as MarrowAgentRuntimeResult & {
    response_mode?: unknown;
    gate_required?: unknown;
  };
  return runtime.gate_receipt?.required === true
    || runtime.risk_gate?.gate_required === true
    || runtime.risk_gate?.enforced === true
    || (shape.response_mode === 'slim' && shape.gate_required === true);
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

function hasOutcomeObservationOnlyMarker(runtime: MarrowAgentRuntimeResult): boolean {
  const shape = runtime as MarrowAgentRuntimeResult & {
    enforcement_decision?: unknown;
  };
  return runtime.runtime_authorization?.kind === OUTCOME_OBSERVATION_ONLY
    || runtime.runtime_authorization?.decision_state === OUTCOME_OBSERVATION_ONLY
    || runtime.risk_gate?.decision === OUTCOME_OBSERVATION_ONLY
    || runtime.gate_receipt?.kind === OUTCOME_OBSERVATION_ONLY
    || runtime.gate_receipt?.decision === OUTCOME_OBSERVATION_ONLY
    || shape.enforcement_decision === OUTCOME_OBSERVATION_ONLY;
}

function normalizeOutcomeObservationOnlyRuntime(
  runtime: MarrowAgentRuntimeResult,
): MarrowAgentRuntimeResult | null {
  const shape = runtime as MarrowAgentRuntimeResult & {
    requested_action?: unknown;
    enforcement_decision?: unknown;
    risk_gate_enforced?: unknown;
    loop_integrity?: unknown;
  };
  const authorization = optionalRecord(runtime.runtime_authorization);
  const riskGate = optionalRecord(runtime.risk_gate);
  const gateReceipt = optionalRecord(runtime.gate_receipt);
  const intervention = optionalRecord(runtime.intervention);
  const loopIntegrity = optionalRecord(shape.loop_integrity);
  const completion = optionalRecord(runtime.completion_contract);
  const canonicalReceipt = canonicalRuntimeReceipt(runtime);
  const correlationId = canonicalReceipt.id;
  const decisionId = safeRuntimeIdentifier(runtime.decision_id);
  const nestedDecisionId = safeRuntimeIdentifier(authorization?.decision_id);
  const requiredCommitFields = completion?.required_commit_fields;
  const exactNextAction = typeof runtime.exact_next_action === 'string'
    ? runtime.exact_next_action.trim()
    : '';
  if (!correlationId
    || canonicalReceipt.conflict
    || !isOutcomeObservationOnlyCorrelationId(correlationId)
    || runtime.ok !== true
    || typeof runtime.action !== 'string'
    || !runtime.action.trim()
    || shape.requested_action !== runtime.action
    || (runtime.decision_id != null && !decisionId)
    || nestedDecisionId !== decisionId
    || authorization?.kind !== OUTCOME_OBSERVATION_ONLY
    || authorization?.durable !== false
    || authorization?.decision_state !== OUTCOME_OBSERVATION_ONLY
    || authorization?.decision_creation_required !== !decisionId
    || authorization?.decision_creation_endpoint !== (decisionId ? null : '/v1/agent/think')
    || authorization?.commit_endpoint !== '/v1/agent/commit'
    || authorization?.commit_with !== (decisionId ? 'decision_id' : null)
    || riskGate?.allow !== false
    || riskGate?.enforced !== false
    || riskGate?.decision !== OUTCOME_OBSERVATION_ONLY
    || riskGate?.enforcement_decision !== OUTCOME_OBSERVATION_ONLY
    || riskGate?.gate_receipt_id !== correlationId
    || riskGate?.gate_required !== false
    || riskGate?.bypass_allowed !== false
    || riskGate?.authorization_granted !== false
    || riskGate?.permit_eligible !== false
    || gateReceipt?.id !== correlationId
    || gateReceipt?.kind !== OUTCOME_OBSERVATION_ONLY
    || gateReceipt?.durable !== false
    || gateReceipt?.required !== false
    || gateReceipt?.decision !== OUTCOME_OBSERVATION_ONLY
    || gateReceipt?.authorization_granted !== false
    || gateReceipt?.permit_eligible !== false
    || shape.enforcement_decision !== OUTCOME_OBSERVATION_ONLY
    || shape.risk_gate_enforced !== false
    || runtime.arbitration !== null
    || typeof runtime.before_you_act !== 'string'
    || !runtime.before_you_act.trim()
    || intervention?.allow !== false
    || intervention?.decision !== OUTCOME_OBSERVATION_ONLY
    || intervention?.exact_next_action !== exactNextAction
    || loopIntegrity?.status !== OUTCOME_OBSERVATION_ONLY
    || loopIntegrity?.gate_receipt_required !== false
    || loopIntegrity?.gate_receipt_id !== correlationId
    || loopIntegrity?.agent_instruction !== exactNextAction
    || completion?.gate_receipt_required !== false
    || completion?.gate_receipt_id !== correlationId
    || completion?.decision_state !== OUTCOME_OBSERVATION_ONLY
    || completion?.exact_next_action !== exactNextAction
    || !Array.isArray(requiredCommitFields)
    || requiredCommitFields.join(',') !== 'decision_id,success,outcome'
    || !exactNextAction) {
    return null;
  }
  return {
    ...runtime,
    ...(decisionId ? { decision_id: decisionId } : {}),
    runtime_authorization: {
      ...runtime.runtime_authorization!,
      id: correlationId,
      kind: OUTCOME_OBSERVATION_ONLY,
      durable: false,
      decision_state: OUTCOME_OBSERVATION_ONLY,
      decision_creation_required: !decisionId,
      decision_creation_endpoint: decisionId ? null : '/v1/agent/think',
      ...(decisionId ? { decision_id: decisionId } : {}),
    },
    fresh_runtime_response: true,
    guidance_obtained: true,
    authorization_state: 'unverified',
    hard_gate_obtained: false,
  };
}

export function isOutcomeObservationOnlyRuntime(
  runtime: MarrowAgentRuntimeResult | null | undefined,
): boolean {
  return Boolean(runtime && normalizeOutcomeObservationOnlyRuntime(runtime));
}

function withAuthorizationTruth(runtime: MarrowAgentRuntimeResult): MarrowAgentRuntimeResult | null {
  const rawDecisionId = safeRuntimeIdentifier(runtime.decision_id);
  const canonicalReceipt = canonicalRuntimeReceipt(runtime);
  const receiptId = canonicalReceipt.id;
  const runtimeShape = runtime as MarrowAgentRuntimeResult & {
    performance?: { mode?: unknown };
    response_mode?: unknown;
    gate_required?: unknown;
    risk_level?: unknown;
  };
  if ((!receiptId || canonicalReceipt.conflict)
    && runtimeRequiresReceipt(runtime)
    && runtimeShape.response_mode === 'slim') return null;
  const decisionId = receiptId ? rawDecisionId : null;
  const fastGuidance = runtimeShape.performance?.mode === 'summary_backed_fast_path'
    || (runtimeShape.response_mode === 'slim'
      && runtimeShape.gate_required !== true
      && runtimeShape.risk_level === 'low');
  const durable = Boolean(receiptId
    && (runtime.gate_receipt?.required || runtime.risk_gate?.gate_required || !fastGuidance));
  const runtimeAuthorization = receiptId ? {
    id: receiptId,
    kind: durable ? 'durable_gate_receipt' : 'low_risk_guidance_receipt',
    durable,
    decision_state: decisionId ? 'created' : 'not_created',
    decision_creation_required: !decisionId,
    decision_creation_endpoint: decisionId ? null : '/v1/agent/think',
    ...(decisionId ? { decision_id: decisionId } : {}),
  } : undefined;
  const {
    decision_id: _nullableDecisionId,
    runtime_authorization: _untrustedRuntimeAuthorization,
    ...runtimeWithoutNullableDecision
  } = runtime;
  const normalizedRuntime: MarrowAgentRuntimeResult = {
    ...runtimeWithoutNullableDecision,
    ...(decisionId ? { decision_id: decisionId } : {}),
    ...(runtimeAuthorization ? { runtime_authorization: runtimeAuthorization } : {}),
  };
  const planCapability = normalizeRuntimePlanCapability(normalizedRuntime, normalizedRuntime.risk_gate);
  const hardGate = Boolean(runtimeAuthorization)
    && authoritativeHardGate(normalizedRuntime, planCapability);
  const advisory = normalizedRuntime.risk_gate.enforced === false
    || planCapability?.production_enforcement_entitled === false
    || planCapability?.mode === 'advisory'
    || planCapability?.mode === 'pilot';
  return {
    ...normalizedRuntime,
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
  if (isValidRuntimeResult(value)) {
    if (hasOutcomeObservationOnlyMarker(value)) return normalizeOutcomeObservationOnlyRuntime(value);
    return withAuthorizationTruth(value);
  }
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
  const gateReceiptId = safeRuntimeIdentifier(slim.gate_receipt_id);
  const enforced = explicitBoolean(slim, 'risk_gate_enforced', 'enforced');
  const entitled = explicitBoolean(slim, 'risk_gate_entitled', 'entitled');
  const enforcementDecision = typeof slim.enforcement_decision === 'string'
    ? slim.enforcement_decision.slice(0, 64)
    : undefined;
  const normalized = {
    ...slim,
    ok: slim.ok !== false,
    action: typeof slim.action === 'string' && slim.action.trim()
      ? slim.action
      : typeof slim.requested_action === 'string' && slim.requested_action.trim()
        ? slim.requested_action
        : '',
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

function highRiskRuntimeCanAttemptClosure(
  runtime: MarrowAgentRuntimeResult,
  proof: Record<string, unknown> | undefined,
  explicitReceiptId: unknown,
  now: number,
  requireServerProofComplete: boolean,
): boolean {
  const decision = String(runtime.risk_gate?.decision || '').toLowerCase();
  const receiptDecision = String(runtime.gate_receipt?.decision || decision).toLowerCase();
  const receiptId = runtimeAuthorizationReceiptId(runtime);
  const suppliedReceiptId = safeRuntimeIdentifier(explicitReceiptId);
  const receiptExpired = runtime.gate_receipt?.expires_at
    ? Date.parse(runtime.gate_receipt.expires_at) <= now
    : false;
  const planCapability = runtime.plan_capability || normalizeRuntimePlanCapability(runtime, runtime.risk_gate);
  return Boolean(
    proof
    && Object.keys(proof).length > 0
    && receiptId
    && suppliedReceiptId === receiptId
    && runtime.runtime_authorization?.durable === true
    && runtime.authorization_state === 'hard_gate'
    && runtime.hard_gate_obtained === true
    && runtime.risk_gate?.allow === true
    && authoritativeHardGate(runtime, planCapability)
    && ['allow', 'proceed', 'warn'].includes(decision)
    && ['allow', 'proceed', 'warn'].includes(receiptDecision)
    && (!requireServerProofComplete || runtime.proof_pack?.complete === true)
    && !receiptExpired
    && runtime.gate_receipt?.owner_approval_required !== true
    && runtime.intervention?.must_stop !== true
    && runtime.intervention?.allow !== false
  );
}

export function highRiskRuntimeCanClose(
  runtime: MarrowAgentRuntimeResult,
  proof: Record<string, unknown> | undefined,
  explicitReceiptId: unknown,
  now: number = Date.now(),
): boolean {
  return highRiskRuntimeCanAttemptClosure(runtime, proof, explicitReceiptId, now, true);
}

/**
 * A runtime receipt is immutable authorization, while proof is commit evidence.
 * This permits one missing-to-supplied proof continuation without weakening the
 * gate; the backend still validates and binds the exact proof on commit.
 */
export function highRiskRuntimeCanContinueWithProof(
  runtime: MarrowAgentRuntimeResult,
  proof: Record<string, unknown> | undefined,
  explicitReceiptId: unknown,
  now: number = Date.now(),
): boolean {
  return highRiskRuntimeCanAttemptClosure(runtime, proof, explicitReceiptId, now, false);
}
