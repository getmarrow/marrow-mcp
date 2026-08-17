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

function full(overrides = {}) {
  const base = {
    ok: true,
    action: 'review a governed change',
    agent_id: 'agent-fixture',
    session_id: 'session-fixture',
    status: {},
    decision_brief: {},
    risk_gate: {
      allow: true,
      decision: 'allow',
      risk_level: 'medium',
      reasons: [],
      gate_required: false,
    },
    relevant_lessons: [],
    deployment_playbooks: [],
    template_suggestion: {},
    gate_receipt_id: 'gate-fixture',
    gate_receipt: { id: 'gate-fixture', required: false, decision: 'allow' },
    proof_pack: {
      required: false,
      enforced: false,
      fields: [],
      missing: [],
      complete: true,
      commit_endpoint: '/v1/agent/commit',
      rule: 'outcome_commit_required',
    },
    before_you_act: null,
    exact_next_action: null,
    auto_outcome_closure: null,
  };
  return {
    ...base,
    ...overrides,
    risk_gate: { ...base.risk_gate, ...(overrides.risk_gate || {}) },
    gate_receipt: Object.hasOwn(overrides, 'gate_receipt')
      ? overrides.gate_receipt
      : base.gate_receipt,
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

test('full runtime never preserves malformed authorization without a canonical receipt', () => {
  for (const invalidId of [undefined, '', '   ', 42, {}, 'receipt id with spaces']) {
    const payload = full({
      gate_receipt_id: null,
      gate_receipt: null,
      risk_gate: { gate_receipt_id: null },
      decision_id: null,
      runtime_authorization: {
        id: invalidId,
        kind: 'attacker_selected_kind',
        durable: true,
        decision_state: 'created',
        decision_creation_required: false,
        decision_creation_endpoint: null,
        decision_id: 'synthetic-decision',
      },
    });
    const runtime = normalizeRuntimeResult(payload);
    assert.ok(runtime);
    assert.equal(Object.hasOwn(runtime, 'decision_id'), false);
    assert.equal(Object.hasOwn(runtime, 'runtime_authorization'), false);
    assert.equal(runtime.authorization_state, 'unverified');
    assert.equal(runtime.hard_gate_obtained, false);
  }
});

test('full runtime rebuilds malformed nested authorization from one validated canonical receipt', () => {
  const runtime = normalizeRuntimeResult(full({
    runtime_authorization: {
      id: '',
      kind: 'attacker_selected_kind',
      durable: false,
      decision_state: 'created',
      decision_creation_required: false,
      decision_creation_endpoint: null,
      decision_id: 'synthetic-decision',
    },
  }));
  assert.ok(runtime);
  assert.deepEqual(runtime.runtime_authorization, {
    id: 'gate-fixture',
    kind: 'durable_gate_receipt',
    durable: true,
    decision_state: 'not_created',
    decision_creation_required: true,
    decision_creation_endpoint: '/v1/agent/think',
  });
  assert.equal(Object.hasOwn(runtime, 'decision_id'), false);
});

test('required full and slim gates fail closed on absent, invalid, or conflicting receipts', () => {
  for (const invalidId of [undefined, '', '   ', 42, {}, 'receipt id with spaces']) {
    const fullRuntime = normalizeRuntimeResult(full({
      gate_receipt_id: invalidId,
      gate_receipt: null,
      risk_gate: { gate_required: true, gate_receipt_id: invalidId },
      runtime_authorization: undefined,
    }));
    assert.ok(fullRuntime);
    assert.equal(Object.hasOwn(fullRuntime, 'runtime_authorization'), false);
    assert.equal(fullRuntime.authorization_state, 'unverified');
    assert.equal(fullRuntime.hard_gate_obtained, false);
    assert.equal(normalizeRuntimeResult(slim({
      gate_receipt_id: invalidId,
      runtime_authorization: undefined,
    })), null);
  }

  const conflictingFull = normalizeRuntimeResult(full({
    gate_receipt_id: 'gate-canonical',
    gate_receipt: { id: 'gate-canonical', required: true, decision: 'allow' },
    risk_gate: { gate_required: true, gate_receipt_id: 'gate-canonical' },
    runtime_authorization: { id: 'gate-conflict' },
  }));
  assert.ok(conflictingFull);
  assert.equal(Object.hasOwn(conflictingFull, 'runtime_authorization'), false);
  assert.equal(conflictingFull.hard_gate_obtained, false);
  assert.equal(normalizeRuntimeResult(slim({
    gate_receipt_id: 'gate-canonical',
    runtime_authorization: { id: 'gate-conflict' },
  })), null);
});

test('proof closure consumes only canonical normalized authorization for full and slim runtime', () => {
  const conflicting = normalizeRuntimeResult(full({
    gate_receipt_id: 'gate-top-level',
    gate_receipt: {
      id: 'gate-structured',
      required: true,
      decision: 'allow',
      expires_at: '2030-01-01T00:00:00.000Z',
    },
    risk_gate: {
      enforced: true,
      enforcement_decision: 'allow',
      gate_required: true,
      gate_receipt_id: 'gate-risk',
    },
    proof_pack: {
      required: true,
      enforced: true,
      fields: [],
      missing: [],
      complete: true,
      commit_endpoint: '/v1/agent/commit',
      rule: 'proof_required_before_complete',
    },
  }));
  assert.ok(conflicting);
  assert.equal(Object.hasOwn(conflicting, 'runtime_authorization'), false);
  assert.equal(conflicting.authorization_state, 'unverified');
  assert.equal(conflicting.hard_gate_obtained, false);
  for (const rawReceipt of ['gate-top-level', 'gate-structured', 'gate-risk']) {
    assert.equal(highRiskRuntimeCanClose(
      conflicting,
      { verification: 'passed' },
      rawReceipt,
      Date.parse('2029-01-01T00:00:00.000Z'),
    ), false);
  }

  const validFull = normalizeRuntimeResult(full({
    gate_receipt_id: 'gate-full-canonical',
    gate_receipt: {
      id: 'gate-full-canonical',
      required: true,
      decision: 'allow',
      expires_at: '2030-01-01T00:00:00.000Z',
    },
    risk_gate: {
      enforced: true,
      enforcement_decision: 'allow',
      gate_required: true,
      gate_receipt_id: 'gate-full-canonical',
    },
    runtime_authorization: { id: 'gate-full-canonical' },
    proof_pack: {
      required: true,
      enforced: true,
      fields: [],
      missing: [],
      complete: true,
      commit_endpoint: '/v1/agent/commit',
      rule: 'proof_required_before_complete',
    },
  }));
  assert.ok(validFull);
  assert.equal(highRiskRuntimeCanClose(
    validFull,
    { verification: 'passed' },
    'gate-full-canonical',
    Date.parse('2029-01-01T00:00:00.000Z'),
  ), true);
  assert.equal(highRiskRuntimeCanClose(validFull, { verification: 'passed' }, undefined), false);
  assert.equal(highRiskRuntimeCanClose(validFull, { verification: 'passed' }, 'gate-other'), false);

  const validSlim = normalizeRuntimeResult(slim({
    gate_receipt_id: 'gate-slim-canonical',
    risk_gate_enforced: true,
    risk_gate_entitled: true,
    enforcement_decision: 'allow',
  }));
  assert.ok(validSlim);
  assert.equal(highRiskRuntimeCanClose(
    validSlim,
    { verification: 'passed' },
    'gate-slim-canonical',
  ), true);
  assert.equal(highRiskRuntimeCanClose(validSlim, { verification: 'passed' }, 'gate-other'), false);
  assert.deepEqual(
    highRiskRuntimeCanClose(structuredClone(validSlim), { verification: 'passed' }, 'gate-slim-canonical'),
    highRiskRuntimeCanClose(validSlim, { verification: 'passed' }, 'gate-slim-canonical'),
  );
});

test('optional slim guidance omits invalid authorization and rebuilds from valid top-level receipt truth', () => {
  const missing = normalizeRuntimeResult(slim({
    gate_required: false,
    gate_receipt_id: null,
    runtime_authorization: {
      id: 99,
      decision_id: 'synthetic-decision',
      decision_state: 'created',
    },
  }));
  assert.ok(missing);
  assert.equal(Object.hasOwn(missing, 'runtime_authorization'), false);
  assert.equal(Object.hasOwn(missing, 'decision_id'), false);
  assert.equal(missing.authorization_state, 'unverified');

  const rebuilt = normalizeRuntimeResult(slim({
    gate_required: false,
    risk_level: 'low',
    gate_receipt_id: 'gate-slim-real',
    runtime_authorization: {
      id: '',
      kind: 'attacker_selected_kind',
      durable: true,
      decision_id: 'synthetic-decision',
      decision_state: 'created',
    },
  }));
  assert.ok(rebuilt);
  assert.deepEqual(rebuilt.runtime_authorization, {
    id: 'gate-slim-real',
    kind: 'low_risk_guidance_receipt',
    durable: false,
    decision_state: 'not_created',
    decision_creation_required: true,
    decision_creation_endpoint: '/v1/agent/think',
  });
});

test('nested decision identifiers are rebuilt only from a validated top-level server decision', () => {
  for (const topLevelDecision of [undefined, null, '', '   ', 17, 'decision id with spaces']) {
    const runtime = normalizeRuntimeResult(full({
      decision_id: topLevelDecision,
      runtime_authorization: {
        id: 'gate-fixture',
        decision_id: 'synthetic-decision',
        decision_state: 'created',
      },
    }));
    assert.ok(runtime);
    assert.equal(Object.hasOwn(runtime, 'decision_id'), false);
    assert.equal(Object.hasOwn(runtime.runtime_authorization, 'decision_id'), false);
    assert.equal(runtime.runtime_authorization.decision_state, 'not_created');
    assert.equal(runtime.runtime_authorization.decision_creation_required, true);
  }

  const mismatched = normalizeRuntimeResult(full({
    decision_id: 'decision-server-real',
    runtime_authorization: {
      id: 'gate-fixture',
      decision_id: 'decision-nested-mismatch',
      decision_state: 'created',
    },
  }));
  assert.ok(mismatched);
  assert.equal(mismatched.decision_id, 'decision-server-real');
  assert.equal(mismatched.runtime_authorization.decision_id, 'decision-server-real');
  assert.equal(mismatched.runtime_authorization.decision_state, 'created');

  const matching = normalizeRuntimeResult(full({
    decision_id: 'decision-server-real',
    runtime_authorization: {
      id: 'gate-fixture',
      decision_id: 'decision-server-real',
      decision_state: 'created',
    },
  }));
  assert.ok(matching);
  assert.equal(matching.decision_id, 'decision-server-real');
  assert.equal(matching.runtime_authorization.decision_id, 'decision-server-real');
  assert.equal(matching.runtime_authorization.decision_creation_required, false);
  assert.equal(matching.runtime_authorization.decision_creation_endpoint, null);
});

test('slim top-level decisions obey the same receipt-backed rule as full responses', () => {
  const missingTopLevel = normalizeRuntimeResult(slim({
    gate_required: false,
    gate_receipt_id: 'gate-slim-decision',
    runtime_authorization: {
      id: 'gate-slim-decision',
      decision_id: 'synthetic-decision',
    },
  }));
  assert.ok(missingTopLevel);
  assert.equal(Object.hasOwn(missingTopLevel, 'decision_id'), false);
  assert.equal(missingTopLevel.runtime_authorization.decision_state, 'not_created');

  const mismatchedNested = normalizeRuntimeResult(slim({
    gate_required: false,
    gate_receipt_id: 'gate-slim-decision',
    decision_id: 'decision-slim-real',
    runtime_authorization: {
      id: 'gate-slim-decision',
      decision_id: 'decision-nested-mismatch',
    },
  }));
  assert.ok(mismatchedNested);
  assert.equal(mismatchedNested.decision_id, 'decision-slim-real');
  assert.equal(mismatchedNested.runtime_authorization.decision_id, 'decision-slim-real');

  const matchingNested = normalizeRuntimeResult(slim({
    gate_required: false,
    gate_receipt_id: 'gate-slim-decision',
    decision_id: 'decision-slim-real',
    runtime_authorization: {
      id: 'gate-slim-decision',
      decision_id: 'decision-slim-real',
    },
  }));
  assert.ok(matchingNested);
  assert.equal(matchingNested.decision_id, 'decision-slim-real');
  assert.equal(matchingNested.runtime_authorization.decision_id, 'decision-slim-real');
  assert.equal(matchingNested.runtime_authorization.decision_state, 'created');
});

test('runtime normalization is deterministic across replay and isolated across tenant-bound agents', () => {
  const accountOne = full({
    agent_id: 'tenant-one-agent',
    session_id: 'tenant-one-session',
    gate_receipt_id: 'gate-tenant-one',
    gate_receipt: { id: 'gate-tenant-one', required: true, decision: 'allow' },
    risk_gate: { gate_required: true, gate_receipt_id: 'gate-tenant-one' },
    decision_id: 'decision-tenant-one',
    runtime_authorization: { id: 'gate-tenant-one', decision_id: 'decision-tenant-one' },
    idempotency_key: 'runtime-replay-one',
  });
  const accountTwo = full({
    agent_id: 'tenant-two-agent',
    session_id: 'tenant-two-session',
    gate_receipt_id: 'gate-tenant-two',
    gate_receipt: { id: 'gate-tenant-two', required: true, decision: 'allow' },
    risk_gate: { gate_required: true, gate_receipt_id: 'gate-tenant-two' },
    decision_id: 'decision-tenant-two',
    runtime_authorization: { id: 'gate-tenant-two', decision_id: 'decision-tenant-two' },
    idempotency_key: 'runtime-replay-two',
  });

  const first = normalizeRuntimeResult(accountOne);
  const replay = normalizeRuntimeResult(structuredClone(accountOne));
  const second = normalizeRuntimeResult(accountTwo);
  assert.deepEqual(replay, first);
  assert.equal(first.agent_id, 'tenant-one-agent');
  assert.equal(first.runtime_authorization.id, 'gate-tenant-one');
  assert.equal(first.decision_id, 'decision-tenant-one');
  assert.equal(second.agent_id, 'tenant-two-agent');
  assert.equal(second.runtime_authorization.id, 'gate-tenant-two');
  assert.equal(second.decision_id, 'decision-tenant-two');
  assert.equal(accountOne.runtime_authorization.id, 'gate-tenant-one');
  assert.equal(accountTwo.runtime_authorization.id, 'gate-tenant-two');

  const slimOne = slim({
    gate_required: false,
    agent_id: 'tenant-one-agent',
    session_id: 'tenant-one-session',
    gate_receipt_id: 'gate-slim-tenant-one',
    decision_id: 'decision-slim-tenant-one',
    runtime_authorization: {
      id: 'gate-slim-tenant-one',
      decision_id: 'decision-slim-tenant-one',
    },
    idempotency_key: 'runtime-slim-replay-one',
  });
  const slimTwo = slim({
    gate_required: false,
    agent_id: 'tenant-two-agent',
    session_id: 'tenant-two-session',
    gate_receipt_id: 'gate-slim-tenant-two',
    decision_id: 'decision-slim-tenant-two',
    runtime_authorization: {
      id: 'gate-slim-tenant-two',
      decision_id: 'decision-slim-tenant-two',
    },
    idempotency_key: 'runtime-slim-replay-two',
  });
  const slimFirst = normalizeRuntimeResult(slimOne);
  const slimReplay = normalizeRuntimeResult(structuredClone(slimOne));
  const slimSecond = normalizeRuntimeResult(slimTwo);
  assert.deepEqual(slimReplay, slimFirst);
  assert.equal(slimFirst.agent_id, 'tenant-one-agent');
  assert.equal(slimFirst.runtime_authorization.id, 'gate-slim-tenant-one');
  assert.equal(slimSecond.agent_id, 'tenant-two-agent');
  assert.equal(slimSecond.runtime_authorization.id, 'gate-slim-tenant-two');
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
