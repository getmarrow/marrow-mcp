const assert = require('node:assert/strict');
const test = require('node:test');

const { marrowAsk, marrowOrient } = require('../dist/index.js');

test('ask maps to the canonical decision brief contract', async (t) => {
  const originalFetch = global.fetch;
  let captured;
  global.fetch = async (url, init) => {
    captured = { url: String(url), init };
    return new Response(JSON.stringify({ data: {
      summary: 'Apply the verified deployment playbook.',
      next_actions: ['Run the release checks.'],
      lesson: 'failed: deploy: 3 failures, verify before retry',
      top_outcomes: ['failed: deploy: 3 failures, verify before retry'],
      has_memory: true,
      decision_count: 12,
      decisions_matched: 12,
      low_history: false,
      risk: { similar_failures: [{ decision_type: 'deploy', failures: 3, failure_rate: 0.5 }] },
      failure_alerts: [{ message: 'Prior deploy proof was incomplete.' }],
      fleet_reliability: { outcome_coverage: 0.8 },
    } }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  t.after(() => { global.fetch = originalFetch; });

  const result = await marrowAsk('test-key', 'https://api.example.test', { query: 'How should I deploy?' }, 'session-one', 'agent-one');
  assert.equal(captured.url, 'https://api.example.test/v1/analytics/decision-brief');
  assert.equal(JSON.parse(captured.init.body).action, 'How should I deploy?');
  assert.equal(result.decisions_matched, 12);
  assert.equal(result.low_history, false);
  assert.match(result.answer, /verified deployment playbook/);
  assert.match(result.answer, /verify before retry/);
});

test('ask drops warming copy when a lesson is already present', async (t) => {
  const originalFetch = global.fetch;
  global.fetch = async () => new Response(JSON.stringify({ data: {
    summary: 'Historical guidance is warming. Low-risk work may continue while Marrow refreshes the measured brief.',
    next_actions: ['Proceed with low-risk work and commit the outcome after meaningful state changes.'],
    lesson: 'failed: process: 1 failure, verify before retry',
    top_outcomes: ['failed: process: 1 failure, verify before retry'],
    has_memory: true,
    decision_count: 53,
    decisions_matched: 0,
    low_history: true,
    risk: { similar_failures: [] },
    fleet_reliability: { outcome_coverage: 0 },
  } }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  t.after(() => { global.fetch = originalFetch; });

  const result = await marrowAsk('test-key', 'https://api.example.test', { query: 'what failed' });
  assert.equal(result.lesson, 'failed: process: 1 failure, verify before retry');
  assert.equal(result.has_memory, true);
  assert.equal(result.low_history, false);
  assert.equal(result.decisions_matched, 53);
  assert.equal(result.answer, 'failed: process: 1 failure, verify before retry');
  assert.doesNotMatch(result.answer, /guidance is warming/i);
});

test('orient uses the canonical runtime contract with the bound agent identity', async (t) => {
  const calls = [];
  const originalFetch = global.fetch;
  global.fetch = async (url, init) => {
    calls.push({ url: String(url), init });
    return new Response(JSON.stringify({
      data: {
        ok: true,
        action: 'Orient before security work',
        agent_id: 'jarvis',
        session_id: 'jarvis-session',
        status: {},
        decision_brief: {},
        risk_gate: { allow: true, decision: 'warn', reasons: [] },
        relevant_lessons: [],
        deployment_playbooks: [],
        template_suggestion: {},
        proof_pack: {
          required: false,
          enforced: false,
          fields: [],
          missing: [],
          complete: true,
          commit_endpoint: '/v1/agent/commit',
          rule: 'none',
        },
        before_you_act: 'Review the matching deployment lesson.',
        intervention: {
          contract: 'marrow.before-action-intervention.v1',
          decision: 'warn',
          allow: true,
          must_stop: false,
          must_use_before_action: true,
          headline: 'A prior failure matches this action.',
          before_action: 'Review the matching deployment lesson.',
          exact_next_action: 'Use the proven deployment playbook.',
          relevant_prior_signal: null,
          playbook: { source: 'fleet_lesson', lesson: null },
          reason_codes: ['prior_failure'],
        },
      },
    }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  t.after(() => { global.fetch = originalFetch; });

  const result = await marrowOrient(
    'test-key',
    'https://api.example.test',
    { taskType: 'security', autoWarn: true },
    'jarvis-session',
    'jarvis'
  );

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://api.example.test/v1/agent/runtime');
  assert.equal(calls[0].init.method, 'POST');
  assert.equal(calls[0].init.headers['X-Marrow-Package'], '@getmarrow/mcp');
  assert.equal(calls[0].init.headers['X-Marrow-Package-Version'], '3.9.78');
  const payload = JSON.parse(calls[0].init.body);
  assert.equal(payload.type, 'security');
  assert.equal(payload.agent_id, 'jarvis');
  assert.equal(payload.session_id, 'jarvis-session');
  assert.equal(payload.context.event_kind, 'session_orientation');
  assert.equal(result.shouldPause, false);
  assert.equal(result.warnings[0].type, 'runtime_warn');
  assert.equal(result.serverWarnings[0].severity, 'MEDIUM');
});

test('orient pauses on a runtime block', async (t) => {
  const originalFetch = global.fetch;
  global.fetch = async () => new Response(JSON.stringify({
    data: {
      status: {},
      risk_gate: { allow: false, decision: 'block', reasons: [] },
      relevant_lessons: [],
      deployment_playbooks: [],
      template_suggestion: {},
      proof_pack: { required: true },
      gate_receipt: { id: 'gate-1', required: true },
      intervention: {
        decision: 'block',
        must_stop: true,
        headline: 'Required production proof is missing.',
        before_action: 'Collect the required proof before release.',
      },
    },
  }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  t.after(() => { global.fetch = originalFetch; });

  const result = await marrowOrient('test-key', 'https://api.example.test', {}, 'session', 'agent');

  assert.equal(result.shouldPause, true);
  assert.equal(result.loopState.isOpen, true);
  assert.equal(result.serverWarnings[0].severity, 'HIGH');
});

test('orient maps review-required risk gates when intervention is omitted', async (t) => {
  const originalFetch = global.fetch;
  global.fetch = async () => new Response(JSON.stringify({
    data: {
      status: {},
      risk_gate: {
        allow: false,
        decision: 'review_required',
        reasons: [{ code: 'owner_review', severity: 'high', message: 'Owner review is required.' }],
      },
      relevant_lessons: [],
      deployment_playbooks: [],
      template_suggestion: {},
      proof_pack: { required: false },
      before_you_act: null,
    },
  }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  t.after(() => { global.fetch = originalFetch; });

  const result = await marrowOrient('test-key', 'https://api.example.test', {}, 'session', 'agent');

  assert.equal(result.shouldPause, true);
  assert.equal(result.warnings[0].type, 'runtime_owner_approval_required');
  assert.equal(result.warnings[0].message, 'Owner review is required.');
});

test('orient fails closed on unknown intervention decisions', async (t) => {
  const originalFetch = global.fetch;
  global.fetch = async () => new Response(JSON.stringify({
    data: {
      status: {},
      risk_gate: { allow: true, decision: 'allow', reasons: [] },
      relevant_lessons: [],
      deployment_playbooks: [],
      template_suggestion: {},
      proof_pack: { required: false },
      intervention: {
        decision: 'unexpected_future_value',
        must_stop: false,
        headline: 'Unknown policy result.',
      },
    },
  }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  t.after(() => { global.fetch = originalFetch; });

  const result = await marrowOrient('test-key', 'https://api.example.test', {}, 'session', 'agent');

  assert.equal(result.shouldPause, true);
  assert.equal(result.warnings[0].type, 'runtime_block');
  assert.equal(result.serverWarnings[0].severity, 'HIGH');
});

test('orient honors a blocking gate receipt over proceed signals', async (t) => {
  const originalFetch = global.fetch;
  global.fetch = async () => new Response(JSON.stringify({
    data: {
      status: {},
      risk_gate: { allow: true, decision: 'allow', reasons: [] },
      relevant_lessons: [],
      deployment_playbooks: [],
      template_suggestion: {},
      proof_pack: { required: true },
      gate_receipt: {
        id: 'gate-block',
        required: true,
        decision: 'block',
        exact_fix: 'Collect deployment proof before continuing.',
      },
      intervention: { decision: 'proceed', allow: true, must_stop: false },
    },
  }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  t.after(() => { global.fetch = originalFetch; });

  const result = await marrowOrient('test-key', 'https://api.example.test', {}, 'session', 'agent');

  assert.equal(result.shouldPause, true);
  assert.equal(result.warnings[0].type, 'runtime_block');
  assert.equal(result.warnings[0].message, 'Collect deployment proof before continuing.');
});

test('orient honors intervention enforcement owner approval over proceed', async (t) => {
  const originalFetch = global.fetch;
  global.fetch = async () => new Response(JSON.stringify({
    data: {
      status: {},
      risk_gate: { allow: true, decision: 'allow', reasons: [] },
      relevant_lessons: [],
      deployment_playbooks: [],
      template_suggestion: {},
      proof_pack: { required: false },
      intervention: {
        decision: 'proceed',
        allow: true,
        must_stop: false,
        enforcement: { owner_approval_required: true },
        before_action: 'Obtain owner approval before continuing.',
      },
    },
  }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  t.after(() => { global.fetch = originalFetch; });

  const result = await marrowOrient('test-key', 'https://api.example.test', {}, 'session', 'agent');

  assert.equal(result.shouldPause, true);
  assert.equal(result.warnings[0].type, 'runtime_owner_approval_required');
});

test('orient honors explicit owner approval and standalone deny signals', async (t) => {
  const originalFetch = global.fetch;
  const responses = [
    {
      risk_gate: { allow: true, decision: 'allow', reasons: [] },
      intervention: { decision: 'owner_approval_required', allow: true, must_stop: false },
    },
    {
      risk_gate: { allow: true, decision: 'allow', reasons: [] },
      intervention: { decision: 'proceed', allow: false, must_stop: false },
    },
  ];
  global.fetch = async () => {
    const response = responses.shift();
    return new Response(JSON.stringify({
      data: {
        status: {},
        ...response,
        relevant_lessons: [],
        deployment_playbooks: [],
        template_suggestion: {},
        proof_pack: { required: false },
      },
    }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  t.after(() => { global.fetch = originalFetch; });

  const ownerApproval = await marrowOrient('test-key', 'https://api.example.test', {}, 'session', 'agent');
  const explicitDeny = await marrowOrient('test-key', 'https://api.example.test', {}, 'session', 'agent');

  assert.equal(ownerApproval.shouldPause, true);
  assert.equal(ownerApproval.warnings[0].type, 'runtime_owner_approval_required');
  assert.equal(explicitDeny.shouldPause, true);
  assert.equal(explicitDeny.warnings[0].type, 'runtime_block');
});

test('orient fails closed on unknown required gate receipt decisions', async (t) => {
  const originalFetch = global.fetch;
  global.fetch = async () => new Response(JSON.stringify({
    data: {
      status: {},
      risk_gate: { allow: true, decision: 'allow', reasons: [] },
      relevant_lessons: [],
      deployment_playbooks: [],
      template_suggestion: {},
      proof_pack: { required: true },
      gate_receipt: { id: 'gate-future', required: true, decision: 'future_policy_value' },
      intervention: { decision: 'proceed', allow: true, must_stop: false },
    },
  }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  t.after(() => { global.fetch = originalFetch; });

  const result = await marrowOrient('test-key', 'https://api.example.test', {}, 'session', 'agent');

  assert.equal(result.shouldPause, true);
  assert.equal(result.warnings[0].type, 'runtime_block');
});

test('orient applies the strictest signal across contradictory gate fields', async (t) => {
  const originalFetch = global.fetch;
  const cases = [
    {
      risk_gate: { allow: true, decision: 'allow', reasons: [] },
      intervention: { decision: 'proceed', allow: true, must_stop: false },
      gate_receipt: { id: 'gate-owner', required: true, owner_approval_required: true },
      expectedType: 'runtime_owner_approval_required',
    },
    {
      risk_gate: { allow: true, decision: 'allow', reasons: [] },
      intervention: { decision: 'proceed', allow: true, must_stop: false },
      gate_receipt: { id: 'gate-review', required: true, decision: 'review_required' },
      expectedType: 'runtime_owner_approval_required',
    },
    {
      risk_gate: { allow: true, decision: 'block', reasons: [] },
      intervention: { decision: 'proceed', allow: true, must_stop: false },
      expectedType: 'runtime_block',
    },
    {
      risk_gate: { allow: false, decision: 'allow', reasons: [] },
      intervention: { decision: 'proceed', allow: true, must_stop: false },
      expectedType: 'runtime_block',
    },
  ];
  global.fetch = async () => {
    const current = cases.shift();
    return new Response(JSON.stringify({
      data: {
        status: {},
        risk_gate: current.risk_gate,
        intervention: current.intervention,
        gate_receipt: current.gate_receipt,
        relevant_lessons: [],
        deployment_playbooks: [],
        template_suggestion: {},
        proof_pack: { required: Boolean(current.gate_receipt?.required) },
      },
    }), { status: 200, headers: { 'Content-Type': 'application/json' } });
  };
  t.after(() => { global.fetch = originalFetch; });

  for (const expectedType of [
    'runtime_owner_approval_required',
    'runtime_owner_approval_required',
    'runtime_block',
    'runtime_block',
  ]) {
    const result = await marrowOrient('test-key', 'https://api.example.test', {}, 'session', 'agent');
    assert.equal(result.shouldPause, true);
    assert.equal(result.warnings[0].type, expectedType);
  }
});
