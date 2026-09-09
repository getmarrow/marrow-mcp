const assert = require('node:assert/strict');
const test = require('node:test');
const { marrowCommit } = require('../dist/index.js');

function observationOnlyRuntime() {
  const id = 'outcome_observation_only_0123456789abcdef0123456789abcdef';
  const decisionId = 'decision-observation-only';
  const exactNextAction = 'Submit this observation without receipt evidence; obtain separate authorization and proof for trusted promotion.';
  return {
    ok: true,
    action: 'record an already completed action',
    requested_action: 'record an already completed action',
    agent_id: 'agent-fixture',
    session_id: 'session-fixture',
    decision_id: decisionId,
    runtime_authorization: {
      id,
      kind: 'outcome_observation_only',
      durable: false,
      decision_state: 'outcome_observation_only',
      decision_creation_required: false,
      decision_creation_endpoint: null,
      commit_endpoint: '/v1/agent/commit',
      commit_with: 'decision_id',
      decision_id: decisionId,
    },
    risk_gate: {
      allow: false,
      decision: 'outcome_observation_only',
      enforcement_decision: 'outcome_observation_only',
      risk_level: 'high',
      reasons: [],
      enforced: false,
      gate_receipt_id: id,
      gate_required: false,
      bypass_allowed: false,
      authorization_granted: false,
      permit_eligible: false,
    },
    gate_receipt_id: id,
    gate_receipt: {
      id,
      kind: 'outcome_observation_only',
      durable: false,
      required: false,
      decision: 'outcome_observation_only',
      authorization_granted: false,
      permit_eligible: false,
    },
    arbitration: null,
    enforcement_decision: 'outcome_observation_only',
    risk_gate_enforced: false,
    intervention: {
      allow: false,
      decision: 'outcome_observation_only',
      exact_next_action: exactNextAction,
    },
    before_you_act: 'Observation-only runtime mode cannot authorize execution or issue a permit.',
    loop_integrity: {
      status: 'outcome_observation_only',
      gate_receipt_required: false,
      gate_receipt_id: id,
      agent_instruction: exactNextAction,
    },
    completion_contract: {
      required_commit_fields: ['decision_id', 'success', 'outcome'],
      gate_receipt_required: false,
      gate_receipt_id: id,
      decision_state: 'outcome_observation_only',
      exact_next_action: exactNextAction,
    },
    proof_pack: { complete: false },
    exact_next_action: exactNextAction,
  };
}

const originalScope = { decision_id: 'decision-observation-only', action: 'record an already completed action', success: true, outcome: 'The fixture completed.', auto_gate: true };
const observe = { accepted: true, committed: false, outcome_state: 'observed_unverified', outcome_observation_id: 'observation-fixture', authorization_granted: false, trusted_learning_applied: false, exact_next_action: 'Supply separately verified proof.' };
const call = (params) => marrowCommit('scope-key', 'https://api.example.test', params, 'session-fixture', 'agent-fixture');

for (const [label, supplied] of [ ['omitted', {}], ['empty', { surfaces: [] }], ['explicit', { type: 'implementation', surfaces: ['api'], target: 'worker:fixture' }] ]) {
  test(`commit auto_gate preserves ${label} original scope without inventing a handoff surface`, async () => {
    const originalFetch = globalThis.fetch;
    const requests = [];
    globalThis.fetch = async (url, init) => {
      const body = JSON.parse(init.body);
      requests.push({ body, headers: new Headers(init.headers) });
      if (String(url).endsWith('/runtime')) {
        assert.equal(body.type, supplied.type || 'general');
        assert.deepEqual(body.surfaces, supplied.surfaces || []);
        assert.equal(body.target, supplied.target);
        assert.equal(body.action, originalScope.action);
        assert.equal(body.decision_id, originalScope.decision_id);
        assert.equal(body.context.mcp_commit_auto_gate, true);
        assert.equal(body.agent_id, 'agent-fixture');
        assert.equal(body.session_id, 'session-fixture');
        return Response.json({ data: observationOnlyRuntime() });
      }
      assert.equal(body.gate_receipt_id, undefined);
      assert.equal(body.decision_id, originalScope.decision_id);
      return Response.json({ data: observe }, { status: 202 });
    };
    try {
      const result = await call({ ...originalScope, ...supplied });
      assert.equal(result.committed, false);
      assert.equal(result.outcome_state, 'observed_unverified');
      assert.equal(requests.length, 2);
      assert.ok(requests.every(r => r.headers.get('X-Marrow-Agent-Id') === 'agent-fixture' && r.headers.get('X-Marrow-Session-Id') === 'session-fixture'));
    } finally { globalThis.fetch = originalFetch; }
  });
}

for (const [field, value] of [['surfaces', ['other']], ['target', 'worker:other'], ['type', 'security'], ['action', 'Different action']]) {
  test(`commit preserves server rejection of changed ${field} before outcome delivery`, async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = async (url, init) => {
      calls++;
      assert.ok(String(url).endsWith('/runtime'));
      assert.deepEqual(JSON.parse(init.body)[field], value);
      return Response.json({ error: 'Exact original scope required', details: { code: 'MARROW_RUNTIME_OBSERVATION_ACTION_MISMATCH' } }, { status: 409 });
    };
    try {
      await assert.rejects(call({ ...originalScope, [field]: value }), e => e.status === 409 && e.backendCode === 'MARROW_RUNTIME_OBSERVATION_ACTION_MISMATCH');
      assert.equal(calls, 1);
    } finally { globalThis.fetch = originalFetch; }
  });
}

for (const [label, change] of [
  ['decision', r => { r.decision_id = 'other-decision'; r.runtime_authorization.decision_id = 'other-decision'; }],
  ['agent', r => { r.agent_id = 'other-agent'; }],
  ['session', r => { r.session_id = 'other-session'; }],
]) {
  test(`commit rejects a returned foreign ${label} without outcome delivery`, async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = async () => { calls++; const response = observationOnlyRuntime(); change(response); return Response.json({ data: response }); };
    try { await assert.rejects(call(originalScope), /scope does not match/); assert.equal(calls, 1); }
    finally { globalThis.fetch = originalFetch; }
  });
}

for (const code of ['MARROW_PRE_ACTION_GATE_EXPIRED', 'MARROW_PRE_ACTION_GATE_USED']) {
  test(`commit exposes ${code} without automatic renewal or authority extension`, async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = async (url, init) => {
      calls++;
      assert.ok(String(url).endsWith('/commit'));
      assert.equal(JSON.parse(init.body).gate_receipt_id, 'original-authoritative-gate');
      return Response.json({ data: { ...observe, governance_validation: { code } } }, { status: 202 });
    };
    try {
      const result = await call({ ...originalScope, gate_receipt_id: 'original-authoritative-gate' });
      assert.equal(result.committed, false);
      assert.equal(result.outcome_state, 'observed_unverified');
      assert.equal(result.governance_validation.code, code);
      assert.equal(result.authorization_granted, false);
      assert.equal(result.trusted_learning_applied, false);
      assert.equal(calls, 1);
    } finally { globalThis.fetch = originalFetch; }
  });
}

test('observation-only correlation cannot be supplied as gate evidence', async () => {
  await assert.rejects(call({ ...originalScope, gate_receipt_id: observationOnlyRuntime().runtime_authorization.id }), /observation-only/);
});
