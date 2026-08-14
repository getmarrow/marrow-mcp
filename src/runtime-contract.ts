import type { MarrowAgentRuntimeResult } from './types';

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
  if (isValidRuntimeResult(value)) return value;
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
  return {
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
  return Boolean(
    proof
    && Object.keys(proof).length > 0
    && runtime.risk_gate?.allow === true
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
