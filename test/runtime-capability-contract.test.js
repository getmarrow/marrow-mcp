const assert = require('node:assert/strict');
const test = require('node:test');

const {
  highRiskRuntimeCanClose,
  normalizeRuntimePlanCapability,
  normalizeRuntimeResult,
} = require('../dist/runtime-contract.js');

function slim(overrides = {}) {
  return {
    response_mode: 'slim',
    decision: 'allow',
    risk_level: 'high',
    gate_required: true,
    proof_required: true,
    proof_complete: true,
    gate_receipt_id: 'gate-fixture',
    ...overrides,
  };
}

function canClose(runtime) {
  return highRiskRuntimeCanClose(runtime, { verification: 'passed' }, 'gate-fixture');
}

test('legacy slim allow without a server-required gate remains guidance, not high-risk authorization', () => {
  const runtime = normalizeRuntimeResult(slim({ gate_required: false }));
  assert.ok(runtime);
  assert.equal(runtime.fresh_runtime_response, true);
  assert.equal(runtime.guidance_obtained, true);
  assert.equal(runtime.authorization_state, 'unverified');
  assert.equal(runtime.hard_gate_obtained, false);
  assert.equal(canClose(runtime), false);
});

test('deployed slim contract preserves safe closure when the server explicitly requires its gate', () => {
  const runtime = normalizeRuntimeResult(slim({ gate_required: true }));
  assert.ok(runtime);
  assert.equal(runtime.authorization_state, 'hard_gate');
  assert.equal(runtime.hard_gate_obtained, true);
  assert.equal(canClose(runtime), true);
});

test('Free and expired-trial advisory semantics survive slim normalization', () => {
  const runtime = normalizeRuntimeResult(slim({
    decision: 'warn',
    risk_gate_enforced: false,
    risk_gate_entitled: false,
    enforcement_decision: 'advisory',
    plan_capability: {
      current_plan: 'free',
      evaluation_active: false,
      mode: 'advisory',
      pre_action_gate_entitled: false,
      production_enforcement_entitled: false,
      handoff_status_entitled: false,
      limits: {
        agents: 1,
        included_decisions_per_month: 500,
        decision_overage_behavior: 'continue_logging',
      },
    },
  }));
  assert.ok(runtime);
  assert.equal(runtime.risk_gate.allow, true);
  assert.equal(runtime.risk_gate.enforced, false);
  assert.equal(runtime.risk_gate.enforcement_decision, 'advisory');
  assert.equal(runtime.plan_capability.current_plan, 'free');
  assert.equal(runtime.plan_capability.limits.agents, 1);
  assert.equal(runtime.authorization_state, 'advisory_only');
  assert.equal(runtime.hard_gate_obtained, false);
  assert.equal(canClose(runtime), false);
});

test('Team pilot guidance does not authorize governed high-risk closure', () => {
  const runtime = normalizeRuntimeResult(slim({
    risk_gate_enforced: false,
    risk_gate_entitled: true,
    enforcement_decision: 'advisory',
    plan_capability: {
      current_plan: 'team',
      evaluation_active: false,
      mode: 'pilot',
      pre_action_gate_entitled: true,
      production_enforcement_entitled: false,
      handoff_status_entitled: true,
    },
  }));
  assert.ok(runtime);
  assert.equal(runtime.plan_capability.mode, 'pilot');
  assert.equal(runtime.authorization_state, 'advisory_only');
  assert.equal(canClose(runtime), false);
});

test('explicit enforced Business capability can close only with fresh gate proof', () => {
  const runtime = normalizeRuntimeResult(slim({
    risk_gate_enforced: true,
    risk_gate_entitled: true,
    enforcement_decision: 'allow',
    plan_capability: {
      current_plan: 'business',
      evaluation_active: false,
      mode: 'enforced',
      pre_action_gate_entitled: true,
      production_enforcement_entitled: true,
      handoff_status_entitled: true,
    },
  }));
  assert.ok(runtime);
  assert.equal(runtime.authorization_state, 'hard_gate');
  assert.equal(runtime.hard_gate_obtained, true);
  assert.equal(canClose(runtime), true);
  runtime.risk_gate.enforcement_decision = 'advisory';
  assert.equal(canClose(runtime), false);
});

test('full runtime derives capability only from explicit feature evidence, never plan names', () => {
  const full = {
    ok: true,
    action: 'deploy',
    agent_id: 'agent-one',
    session_id: 'session-one',
    status: {},
    decision_brief: {},
    risk_gate: {
      allow: true,
      decision: 'allow',
      risk_level: 'high',
      reasons: [],
      enforced: true,
      entitled: true,
      enforcement_decision: 'allow',
    },
    plan_access: {
      plan: 'business',
      evaluation_access: false,
      features: {
        pre_action_risk_gates: true,
        production_action_enforcement: true,
        fleet_learning: true,
      },
      limits: { agents: 100, included_decisions_per_month: null, decision_overage_behavior: 'continue_logging' },
    },
    relevant_lessons: [],
    deployment_playbooks: [],
    template_suggestion: {},
    gate_receipt_id: 'gate-fixture',
    gate_receipt: { id: 'gate-fixture', required: true, decision: 'allow' },
    proof_pack: { required: true, enforced: true, fields: [], missing: [], complete: true, commit_endpoint: '/v1/agent/commit', rule: 'required' },
    before_you_act: null,
    exact_next_action: null,
    auto_outcome_closure: null,
  };
  const runtime = normalizeRuntimeResult(full);
  assert.ok(runtime);
  assert.equal(runtime.plan_capability.production_enforcement_entitled, true);
  assert.equal(runtime.authorization_state, 'hard_gate');
  assert.equal(canClose(runtime), true);

  const nameOnly = structuredClone(full);
  nameOnly.plan_access = { plan: 'business' };
  delete nameOnly.risk_gate.enforced;
  delete nameOnly.risk_gate.entitled;
  delete nameOnly.risk_gate.enforcement_decision;
  const nameOnlyRuntime = normalizeRuntimeResult(nameOnly);
  assert.ok(nameOnlyRuntime);
  assert.equal(nameOnlyRuntime.plan_capability.production_enforcement_entitled, null);
  assert.equal(nameOnlyRuntime.authorization_state, 'unverified');
  assert.equal(canClose(nameOnlyRuntime), false);
});

test('explicit evaluation features preserve enforcement without tier inference', () => {
  const capability = normalizeRuntimePlanCapability({
    plan_access: {
      plan: 'evaluation',
      evaluation_access: true,
      features: {
        pre_action_risk_gates: true,
        production_action_enforcement: true,
        fleet_learning: true,
      },
    },
  }, { enforced: true, entitled: true });
  assert.deepEqual(capability && {
    plan: capability.current_plan,
    evaluation: capability.evaluation_active,
    mode: capability.mode,
    production: capability.production_enforcement_entitled,
  }, { plan: 'evaluation', evaluation: true, mode: 'enforced', production: true });
});
