"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OWNER_APPROVAL_STATUS_POLL_MAX_MS = exports.OWNER_APPROVAL_STATUS_POLL_MIN_MS = exports.OWNER_APPROVAL_STATUS_POLL_DEFAULT_MS = void 0;
exports.runtimeAuthorizationReceiptId = runtimeAuthorizationReceiptId;
exports.isOutcomeObservationOnlyCorrelationId = isOutcomeObservationOnlyCorrelationId;
exports.normalizeRuntimePlanCapability = normalizeRuntimePlanCapability;
exports.isOutcomeObservationOnlyRuntime = isOutcomeObservationOnlyRuntime;
exports.isValidRuntimeResult = isValidRuntimeResult;
exports.normalizeRuntimeResult = normalizeRuntimeResult;
exports.highRiskRuntimeCanClose = highRiskRuntimeCanClose;
exports.highRiskRuntimeCanContinueWithProof = highRiskRuntimeCanContinueWithProof;
exports.ownerApprovalStatusPath = ownerApprovalStatusPath;
exports.approvalLinkPath = approvalLinkPath;
exports.hostApprovalPath = hostApprovalPath;
exports.boundedPollAfterMs = boundedPollAfterMs;
exports.ordinaryApprovalGuidance = ordinaryApprovalGuidance;
exports.ownerReceiptRequired = ownerReceiptRequired;
exports.ownerLinkPolicy = ownerLinkPolicy;
exports.arbitrationApprovalGuidance = arbitrationApprovalGuidance;
exports.runtimeDecisionMatchesAutoScope = runtimeDecisionMatchesAutoScope;
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
function optionalRecord(value) {
    return value && typeof value === 'object' && !Array.isArray(value)
        ? value
        : null;
}
function explicitBoolean(source, ...fields) {
    if (!source)
        return null;
    for (const field of fields) {
        if (typeof source[field] === 'boolean')
            return source[field];
    }
    return null;
}
function boundedPlan(value) {
    const plan = typeof value === 'string' ? value.trim().toLowerCase() : '';
    return plan && /^[a-z][a-z0-9_-]{0,31}$/.test(plan) ? plan : null;
}
function boundedLimit(value) {
    return Number.isSafeInteger(value) && Number(value) >= 0 ? Number(value) : null;
}
function safeRuntimeIdentifier(value) {
    const normalized = typeof value === 'string' ? value.trim() : '';
    return normalized && SAFE_RUNTIME_IDENTIFIER.test(normalized) ? normalized : null;
}
function runtimeAuthorizationReceiptId(runtime) {
    if (runtime?.runtime_authorization?.kind === OUTCOME_OBSERVATION_ONLY)
        return null;
    return safeRuntimeIdentifier(runtime?.runtime_authorization?.id);
}
function isOutcomeObservationOnlyCorrelationId(value) {
    return typeof value === 'string' && OUTCOME_OBSERVATION_ONLY_ID.test(value);
}
function canonicalRuntimeReceipt(runtime) {
    const identifiers = [
        runtime.runtime_authorization?.id,
        runtime.gate_receipt?.id,
        runtime.gate_receipt_id,
        runtime.risk_gate?.gate_receipt_id,
    ].map(safeRuntimeIdentifier).filter((id) => Boolean(id));
    const unique = [...new Set(identifiers)];
    return {
        id: unique.length === 1 ? unique[0] : null,
        conflict: unique.length > 1,
    };
}
function runtimeRequiresReceipt(runtime) {
    const shape = runtime;
    return runtime.gate_receipt?.required === true
        || runtime.risk_gate?.gate_required === true
        || runtime.risk_gate?.enforced === true
        || (shape.response_mode === 'slim' && shape.gate_required === true);
}
function normalizeRuntimePlanCapability(value, riskGateValue) {
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
        ? supplied.mode
        : null;
    const enforced = explicitBoolean(riskGate, 'enforced');
    const mode = suppliedMode
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
function authoritativeHardGate(runtime, planCapability) {
    if (runtime.risk_gate.enforced === false
        || planCapability?.production_enforcement_entitled === false
        || planCapability?.mode === 'advisory'
        || planCapability?.mode === 'pilot') {
        return false;
    }
    const enforcementDecision = String(runtime.risk_gate.enforcement_decision || '').toLowerCase();
    const explicitEnforcement = runtime.risk_gate.enforced === true
        && ['allow', 'proceed', 'warn'].includes(enforcementDecision);
    const serverRequiredSlimGate = runtime.response_mode === 'slim'
        && runtime.risk_gate.enforced == null
        && !enforcementDecision
        && runtime.gate_receipt?.required === true;
    return explicitEnforcement || serverRequiredSlimGate;
}
function hasOutcomeObservationOnlyMarker(runtime) {
    const shape = runtime;
    return runtime.runtime_authorization?.kind === OUTCOME_OBSERVATION_ONLY
        || runtime.runtime_authorization?.decision_state === OUTCOME_OBSERVATION_ONLY
        || runtime.risk_gate?.decision === OUTCOME_OBSERVATION_ONLY
        || runtime.gate_receipt?.kind === OUTCOME_OBSERVATION_ONLY
        || runtime.gate_receipt?.decision === OUTCOME_OBSERVATION_ONLY
        || shape.enforcement_decision === OUTCOME_OBSERVATION_ONLY;
}
function normalizeOutcomeObservationOnlyRuntime(runtime) {
    const shape = runtime;
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
            ...runtime.runtime_authorization,
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
function isOutcomeObservationOnlyRuntime(runtime) {
    return Boolean(runtime && normalizeOutcomeObservationOnlyRuntime(runtime));
}
function withAuthorizationTruth(runtime) {
    const rawDecisionId = safeRuntimeIdentifier(runtime.decision_id);
    const canonicalReceipt = canonicalRuntimeReceipt(runtime);
    const receiptId = canonicalReceipt.id;
    const runtimeShape = runtime;
    if ((!receiptId || canonicalReceipt.conflict)
        && runtimeRequiresReceipt(runtime)
        && runtimeShape.response_mode === 'slim')
        return null;
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
    const { decision_id: _nullableDecisionId, runtime_authorization: _untrustedRuntimeAuthorization, ...runtimeWithoutNullableDecision } = runtime;
    const normalizedRuntime = {
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
function isValidRuntimeResult(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return false;
    const riskGate = value.risk_gate;
    if (!riskGate || typeof riskGate !== 'object' || Array.isArray(riskGate))
        return false;
    const gate = riskGate;
    return typeof gate.allow === 'boolean'
        && typeof gate.decision === 'string'
        && RUNTIME_GATE_DECISIONS.has(gate.decision);
}
function normalizeRuntimeResult(value) {
    if (isValidRuntimeResult(value)) {
        if (hasOutcomeObservationOnlyMarker(value))
            return normalizeOutcomeObservationOnlyRuntime(value);
        return withAuthorizationTruth(value);
    }
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return null;
    const slim = value;
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
        decision_brief: {},
        risk_gate: {
            allow,
            decision: slim.decision === 'proceed' ? 'allow' : slim.decision,
            risk_level: slim.risk_level,
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
    };
    return withAuthorizationTruth(normalized);
}
function highRiskRuntimeCanAttemptClosure(runtime, proof, explicitReceiptId, now, requireServerProofComplete) {
    const decision = String(runtime.risk_gate?.decision || '').toLowerCase();
    const receiptDecision = String(runtime.gate_receipt?.decision || decision).toLowerCase();
    const receiptId = runtimeAuthorizationReceiptId(runtime);
    const suppliedReceiptId = safeRuntimeIdentifier(explicitReceiptId);
    const receiptExpired = runtime.gate_receipt?.expires_at
        ? Date.parse(runtime.gate_receipt.expires_at) <= now
        : false;
    const planCapability = runtime.plan_capability || normalizeRuntimePlanCapability(runtime, runtime.risk_gate);
    return Boolean(proof
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
        && runtime.intervention?.allow !== false);
}
function highRiskRuntimeCanClose(runtime, proof, explicitReceiptId, now = Date.now()) {
    return highRiskRuntimeCanAttemptClosure(runtime, proof, explicitReceiptId, now, true);
}
/**
 * A runtime receipt is immutable authorization, while proof is commit evidence.
 * This permits one missing-to-supplied proof continuation without weakening the
 * gate; the backend still validates and binds the exact proof on commit.
 */
function highRiskRuntimeCanContinueWithProof(runtime, proof, explicitReceiptId, now = Date.now()) {
    return highRiskRuntimeCanAttemptClosure(runtime, proof, explicitReceiptId, now, false);
}
const HOLD_DECISIONS = new Set(['review_required', 'owner_approval_required']);
const APPROVAL_CATEGORY = /^[a-z][a-z0-9_]{0,63}$/;
const PROOF_FIELD = /^[a-z][a-z0-9_]{0,63}$/;
exports.OWNER_APPROVAL_STATUS_POLL_DEFAULT_MS = 5_000;
exports.OWNER_APPROVAL_STATUS_POLL_MIN_MS = 1_000;
exports.OWNER_APPROVAL_STATUS_POLL_MAX_MS = 60_000;
/** The agent-key status read of one gate receipt; built from the receipt id, never taken from a response. */
function ownerApprovalStatusPath(gateReceiptId) {
    return `/v1/agent/gate-receipts/${gateReceiptId}/owner-approval`;
}
/** The agent-key route that asks Marrow to send the owner a one-tap approval link; built from the receipt id. */
function approvalLinkPath(gateReceiptId) {
    return `/v1/agent/gate-receipts/${gateReceiptId}/approval-link`;
}
/** The agent-key route a host hook uses to record the operator's answer; built from the receipt id. */
function hostApprovalPath(gateReceiptId) {
    return `/v1/agent/gate-receipts/${gateReceiptId}/host-approval`;
}
function boundedPollAfterMs(value) {
    const requested = typeof value === 'number' && Number.isFinite(value) ? Math.ceil(value) : exports.OWNER_APPROVAL_STATUS_POLL_DEFAULT_MS;
    return Math.min(exports.OWNER_APPROVAL_STATUS_POLL_MAX_MS, Math.max(exports.OWNER_APPROVAL_STATUS_POLL_MIN_MS, requested));
}
function boundedStrings(value, pattern, limit) {
    return Array.isArray(value)
        ? [...new Set(value.filter((item) => typeof item === 'string' && pattern.test(item)))].slice(0, limit)
        : [];
}
function ordinaryApprovalGuidance(runtime) {
    if (!runtime || runtime.arbitration)
        return null;
    const completion = runtime.completion_contract;
    const approval = optionalRecord(completion?.owner_approval);
    if (!approval || approval.mode !== 'ordinary_non_arbitrated' || ownerReceiptRequired(approval))
        return null;
    if (completion?.arbitration_receipt_required === true)
        return null;
    const decision = String(runtime.risk_gate?.decision || '');
    const receiptDecision = String(runtime.gate_receipt?.decision || '');
    if (decision === 'block' || receiptDecision === 'block')
        return null;
    if (!HOLD_DECISIONS.has(decision) && !HOLD_DECISIONS.has(receiptDecision))
        return null;
    const gateReceiptId = runtimeAuthorizationReceiptId(runtime);
    if (!gateReceiptId)
        return null;
    const statusPath = ownerApprovalStatusPath(gateReceiptId);
    if (approval.approval_status_endpoint !== statusPath)
        return null;
    const decisionIds = [runtime.decision_id, runtime.runtime_authorization?.decision_id, completion?.decision_id]
        .map(safeRuntimeIdentifier)
        .filter((id) => Boolean(id));
    if (new Set(decisionIds).size > 1)
        return null;
    const verifiedApprovalRequired = approval.verified_approval_required === true
        ? true
        : approval.verified_approval_required === false ? false : null;
    const serverHostPath = approval.host_approval_endpoint;
    const hostApprovalAccepted = approval.host_approval_accepted === true
        && verifiedApprovalRequired === false
        && serverHostPath === hostApprovalPath(gateReceiptId)
        && approval.host_approval_trust === 'client_attested'
        && (approval.approval_authority === undefined
            || approval.approval_authority === 'host_operator_or_account_owner'
            || approval.approval_authority === 'host_operator_or_dashboard_owner');
    const refusal = [
        approval.host_approval_refusal_reason,
        approval.host_approval_unavailable_reason,
        approval.host_approval_reason,
    ].find((value) => typeof value === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(value)) || null;
    const proofFields = boundedStrings(runtime.proof_pack?.fields?.length ? runtime.proof_pack.fields : completion?.required_proof_fields, PROOF_FIELD, 24);
    const expiresAt = typeof runtime.gate_receipt?.expires_at === 'string' && Number.isFinite(Date.parse(runtime.gate_receipt.expires_at))
        ? new Date(Date.parse(runtime.gate_receipt.expires_at)).toISOString()
        : null;
    return {
        gateReceiptId,
        decisionId: decisionIds[0] || null,
        trustedCompletionReceiptRequired: approval.trusted_completion_receipt_required === true,
        statusPath,
        pollAfterMs: boundedPollAfterMs(approval.approval_status_poll_after_ms),
        hostApprovalPath: hostApprovalAccepted ? hostApprovalPath(gateReceiptId) : null,
        hostApprovalAccepted,
        hostApprovalSupported: typeof approval.host_approval_accepted === 'boolean',
        hostApprovalRefusal: hostApprovalAccepted ? null : refusal,
        ownerDeclinedAt: typeof approval.owner_declined_at === 'string' && Number.isFinite(Date.parse(approval.owner_declined_at))
            ? new Date(Date.parse(approval.owner_declined_at)).toISOString()
            : null,
        operatorOnly: hostApprovalAccepted && approval.host_approval_operator_only === true,
        earlierDeclineAt: typeof approval.earlier_decline_at === 'string' && Number.isFinite(Date.parse(approval.earlier_decline_at))
            ? new Date(Date.parse(approval.earlier_decline_at)).toISOString()
            : null,
        approvalLinkPath: approval.approval_link_endpoint === approvalLinkPath(gateReceiptId) ? approvalLinkPath(gateReceiptId) : null,
        linkAvailable: typeof approval.approval_link_available === 'boolean' ? approval.approval_link_available : null,
        linkReason: ['owner_locked', 'owner_decline_stands', 'unattended_owner_ping'].includes(String(approval.approval_link_reason))
            ? approval.approval_link_reason
            : null,
        unattendedOwnerPing: typeof approval.unattended_owner_ping === 'boolean' ? approval.unattended_owner_ping : null,
        operatorNotice: hostApprovalAccepted && typeof approval.operator_notice === 'string' && approval.operator_notice.trim()
            ? approval.operator_notice.replace(/[\u0000-\u001f\u007f\u202a-\u202e\u2066-\u2069]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 160)
            : null,
        verifiedApprovalRequired,
        verifiedApprovalCategories: boundedStrings(approval.verified_approval_categories, APPROVAL_CATEGORY, 8),
        approvalCategories: boundedStrings(approval.approval_categories, APPROVAL_CATEGORY, 8),
        approvalAuthority: hostApprovalAccepted ? 'host_operator_or_account_owner' : 'account_owner',
        proofRequired: runtime.proof_pack?.required === true || completion?.proof_required_before_complete === true,
        proofFields,
        expiresAt,
    };
}
/**
 * Whether the owner's server-issued receipt is required (arbitration). The
 * service names it dashboard_receipt_required today and will rename it; both
 * shapes are read, and neither is ever shown as a dashboard step.
 */
function ownerReceiptRequired(approval) {
    return Boolean(approval) && (approval.dashboard_receipt_required === true
        || approval.owner_receipt_required === true
        || approval.server_receipt_required === true);
}
/**
 * When the owner's one-tap link is requested (owner rule: approvals keep people
 * and agents in flow). Only (a) an owner-locked category, (b) the owner's own
 * standing decline once the operator asks to reverse it, or (c) an unattended
 * run when the owner turned on unattended pings. Never for an ordinary hold
 * a person can answer, or one that waits quietly.
 */
function ownerLinkPolicy(guidance, presence) {
    if (!guidance.approvalLinkPath)
        return null;
    const ownerLocked = guidance.linkReason === 'owner_locked'
        || (guidance.linkAvailable === null && guidance.verifiedApprovalRequired === true);
    if (ownerLocked)
        return 'now';
    const declineStands = guidance.linkReason === 'owner_decline_stands'
        || (guidance.linkAvailable === null && guidance.hostApprovalRefusal === 'owner_decline_stands');
    if (declineStands)
        return 'on_request';
    if (presence.unattended && (guidance.linkReason === 'unattended_owner_ping' || guidance.unattendedOwnerPing === true))
        return 'now';
    return null;
}
function arbitrationApprovalGuidance(runtime) {
    const arbitration = runtime?.arbitration;
    if (!runtime || !arbitration)
        return null;
    const completion = runtime.completion_contract;
    const approval = optionalRecord(completion?.owner_approval);
    if (!approval || approval.mode !== 'arbitration_review_required')
        return null;
    if (arbitration.resolution !== 'review_required' && arbitration.owner_approval_required !== true)
        return null;
    const gateReceiptId = runtimeAuthorizationReceiptId(runtime);
    const decisionId = safeRuntimeIdentifier(arbitration.decision_id);
    const arbitrationReceiptId = safeRuntimeIdentifier(arbitration.receipt_id);
    if (!gateReceiptId || !decisionId || !arbitrationReceiptId)
        return null;
    if (approval.approval_link_endpoint !== approvalLinkPath(gateReceiptId)
        || approval.approval_status_endpoint !== ownerApprovalStatusPath(gateReceiptId))
        return null;
    const expiresAt = typeof runtime.gate_receipt?.expires_at === 'string' && Number.isFinite(Date.parse(runtime.gate_receipt.expires_at))
        ? new Date(Date.parse(runtime.gate_receipt.expires_at)).toISOString()
        : null;
    return {
        gateReceiptId,
        decisionId,
        arbitrationReceiptId,
        statusPath: ownerApprovalStatusPath(gateReceiptId),
        linkPath: approvalLinkPath(gateReceiptId),
        pollAfterMs: boundedPollAfterMs(approval.approval_status_poll_after_ms),
        proofRequired: runtime.proof_pack?.required === true || completion?.proof_required_before_complete === true,
        proofFields: boundedStrings(runtime.proof_pack?.fields?.length ? runtime.proof_pack.fields : completion?.required_proof_fields, PROOF_FIELD, 24),
        expiresAt,
    };
}
/** Validate the server's existing decision before auto skips decision creation. */
function runtimeDecisionMatchesAutoScope(runtime, scope) {
    const decisionId = safeRuntimeIdentifier(runtime.decision_id);
    const receiptId = runtimeAuthorizationReceiptId(runtime);
    const completion = runtime.completion_contract;
    const fields = completion?.required_commit_fields;
    return Boolean(decisionId && receiptId
        && runtime.fresh_runtime_response === true
        && runtime.runtime_authorization?.durable === true
        && runtime.runtime_authorization.decision_id === decisionId
        && runtime.runtime_authorization.decision_state === 'created'
        && runtime.runtime_authorization.decision_creation_required === false
        && runtime.gate_receipt?.id === receiptId
        && runtime.gate_receipt.required === true
        && runtime.risk_gate?.gate_receipt_id === receiptId
        && runtime.risk_gate.gate_required === true
        && runtime.action === scope.action.trim()
        && (!scope.agentId || runtime.agent_id === scope.agentId)
        && runtime.session_id === (scope.sessionId || null)
        && completion?.must_commit_outcome === true
        && completion.commit_endpoint === '/v1/agent/commit'
        && completion.gate_receipt_id === receiptId
        && completion.gate_receipt_required === true
        && completion.decision_id === decisionId
        && completion.decision_state === 'created'
        && completion.decision_creation_required === false
        && Array.isArray(fields)
        && ['decision_id', 'success', 'outcome', 'gate_receipt_id'].every((field) => fields.includes(field)));
}
//# sourceMappingURL=runtime-contract.js.map