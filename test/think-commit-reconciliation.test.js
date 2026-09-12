const test = require('node:test');
const assert = require('node:assert/strict');

const { MarrowRequestError } = require('../dist/request-reliability.js');
const { marrowCommit, marrowThink } = require('../dist/index.js');

function response(data, status = 200) {
  return Response.json({ data }, { status });
}

function requestRecord(url, init = {}) {
  const headers = new Headers(init.headers);
  return {
    url: String(url),
    body: String(init.body || ''),
    idempotencyKey: headers.get('Idempotency-Key'),
  };
}

function reconciliationError(error, backendCode) {
  return error instanceof MarrowRequestError
    && error.code === 'invalid_response'
    && error.status === 202
    && error.backendCode === backendCode
    && !/decision-|fixture|bearer|https?:\/\//i.test(`${error.message} ${error.exactFix}`);
}

test('marrowThink reconciles documented 202 with one generated key and byte-identical request', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    const call = requestRecord(url, init);
    calls.push(call);
    if (calls.length === 1) {
      return response({
        reconciliation_state: 'runtime_continuation_persistence_pending',
        retryable: true,
        committed: false,
        decision_state: 'created',
        decision_id: 'decision-reconciled-think',
        idempotency_key: call.idempotencyKey,
      }, 202);
    }
    return response({
      decision_id: 'decision-reconciled-think',
      intelligence: { insights: [] },
      stream_url: '',
    });
  };

  try {
    const result = await marrowThink('fixture-key', 'https://api.example.test', {
      action: 'Reconcile one bounded decision',
    });
    assert.equal(result.decision_id, 'decision-reconciled-think');
    assert.equal(calls.length, 2);
    assert.match(calls[0].idempotencyKey, /^mcp-think:[0-9a-f-]{36}$/);
    assert.equal(calls[1].idempotencyKey, calls[0].idempotencyKey);
    assert.equal(calls[1].body, calls[0].body);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('marrowCommit reconciles documented 202 and preserves an explicit caller key exactly', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  const explicitKey = 'caller-controlled-commit-key';
  globalThis.fetch = async (url, init) => {
    const call = requestRecord(url, init);
    calls.push(call);
    if (calls.length === 1) {
      return response({
        reconciliation_state: 'runtime_continuation_invalidation_pending',
        retryable: true,
        committed: false,
        outcome_persisted: true,
        decision_id: 'decision-reconciled-commit',
        idempotency_key: call.idempotencyKey,
      }, 202);
    }
    return response({ committed: true, decision_id: 'decision-reconciled-commit' });
  };

  try {
    const result = await marrowCommit('fixture-key', 'https://api.example.test', {
      decision_id: 'decision-reconciled-commit',
      success: true,
      outcome: 'Bounded reconciliation passed',
      auto_gate: false,
    }, undefined, undefined, undefined, explicitKey);
    assert.equal(result.committed, true);
    assert.equal(calls.length, 2);
    assert.deepEqual(calls.map((call) => call.idempotencyKey), [explicitKey, explicitKey]);
    assert.equal(calls[1].body, calls[0].body);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('marrowThink preserves an explicit caller key exactly', async () => {
  const originalFetch = globalThis.fetch;
  const explicitKey = 'caller-controlled-think-key';
  let call;
  globalThis.fetch = async (url, init) => {
    call = requestRecord(url, init);
    return response({ decision_id: 'decision-explicit-think', intelligence: { insights: [] }, stream_url: '' });
  };
  try {
    await marrowThink('fixture-key', 'https://api.example.test', {
      action: 'Preserve the supplied invocation key',
    }, undefined, undefined, undefined, { idempotencyKey: explicitKey });
    assert.equal(call.idempotencyKey, explicitKey);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('marrowThink exhausts a documented 202 after exactly three identical attempts', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    const call = requestRecord(url, init);
    calls.push(call);
    return response({
      reconciliation_state: 'runtime_continuation_persistence_pending',
      retryable: true,
      committed: false,
      decision_state: 'created',
      decision_id: 'decision-exhausted-think',
      idempotency_key: call.idempotencyKey,
    }, 202);
  };

  try {
    await assert.rejects(
      () => marrowThink('fixture-key', 'https://api.example.test', {
        action: 'Fail closed after bounded reconciliation',
      }),
      (error) => reconciliationError(error, 'MCP_RECONCILIATION_EXHAUSTED'),
    );
    assert.equal(calls.length, 3);
    assert.equal(new Set(calls.map((call) => call.idempotencyKey)).size, 1);
    assert.equal(new Set(calls.map((call) => call.body)).size, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('marrowCommit exhausts a documented 202 after exactly three identical attempts', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    const call = requestRecord(url, init);
    calls.push(call);
    return response({
      reconciliation_state: 'pending',
      retryable: true,
      committed: false,
      decision_id: 'decision-exhausted-commit',
      idempotency_key: call.idempotencyKey,
    }, 202);
  };
  try {
    await assert.rejects(
      () => marrowCommit('fixture-key', 'https://api.example.test', {
        decision_id: 'decision-exhausted-commit',
        success: true,
        outcome: 'Remain fail closed',
        auto_gate: false,
      }),
      (error) => reconciliationError(error, 'MCP_RECONCILIATION_EXHAUSTED'),
    );
    assert.equal(calls.length, 3);
    assert.match(calls[0].idempotencyKey, /^mcp-commit:[0-9a-f-]{36}$/);
    assert.equal(new Set(calls.map((call) => call.idempotencyKey)).size, 1);
    assert.equal(new Set(calls.map((call) => call.body)).size, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('think and commit reject unknown, malformed, and drifted 202 correlation without retry', async (t) => {
  const cases = [
    {
      name: 'unknown think state',
      invoke: () => marrowThink('fixture-key', 'https://api.example.test', { action: 'Unknown state' }),
      data: {
        reconciliation_state: 'some_future_state', retryable: true, committed: false,
        decision_state: 'created', decision_id: 'decision-unknown', idempotency_key: 'filled-by-mock',
      },
    },
    {
      name: 'malformed commit state',
      invoke: () => marrowCommit('fixture-key', 'https://api.example.test', {
        decision_id: 'decision-malformed', success: true, outcome: 'Malformed', auto_gate: false,
      }),
      data: {
        reconciliation_state: 'pending', retryable: false, committed: false,
        decision_id: 'decision-malformed', idempotency_key: 'filled-by-mock',
      },
    },
    {
      name: 'malformed think state',
      invoke: () => marrowThink('fixture-key', 'https://api.example.test', { action: 'Malformed think' }),
      data: {
        reconciliation_state: 'runtime_continuation_persistence_pending', retryable: false, committed: false,
        decision_state: 'created', decision_id: 'decision-malformed-think', idempotency_key: 'filled-by-mock',
      },
    },
    {
      name: 'unknown commit state',
      invoke: () => marrowCommit('fixture-key', 'https://api.example.test', {
        decision_id: 'decision-unknown-commit', success: true, outcome: 'Unknown commit', auto_gate: false,
      }),
      data: {
        reconciliation_state: 'some_future_state', retryable: true, committed: false,
        decision_id: 'decision-unknown-commit', idempotency_key: 'filled-by-mock',
      },
    },
    {
      name: 'drifted commit decision',
      invoke: () => marrowCommit('fixture-key', 'https://api.example.test', {
        decision_id: 'decision-expected', success: true, outcome: 'Drifted', auto_gate: false,
      }),
      data: {
        reconciliation_state: 'pending', retryable: true, committed: false,
        decision_id: 'decision-different', idempotency_key: 'filled-by-mock',
      },
    },
  ];

  for (const fixture of cases) {
    await t.test(fixture.name, async () => {
      const originalFetch = globalThis.fetch;
      let calls = 0;
      globalThis.fetch = async (_url, init) => {
        calls += 1;
        const key = new Headers(init.headers).get('Idempotency-Key');
        return response({ ...fixture.data, idempotency_key: fixture.data.idempotency_key === 'filled-by-mock' ? key : fixture.data.idempotency_key }, 202);
      };
      try {
        await assert.rejects(
          fixture.invoke,
          (error) => reconciliationError(error, 'MCP_RECONCILIATION_INVALID'),
        );
        assert.equal(calls, 1);
      } finally {
        globalThis.fetch = originalFetch;
      }
    });
  }
});

test('observed_unverified HTTP 202 remains terminal and is never reconciled', async () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    return response({
      accepted: true,
      committed: false,
      outcome_state: 'observed_unverified',
      outcome_observation_id: 'observation-terminal',
      authorization_granted: false,
      trusted_learning_applied: false,
      exact_next_action: 'Obtain authorization before explicit promotion.',
    }, 202);
  };

  try {
    const result = await marrowCommit('fixture-key', 'https://api.example.test', {
      decision_id: 'decision-observed',
      success: true,
      outcome: 'Observed but not authorized',
      auto_gate: false,
    });
    assert.equal(result.committed, false);
    assert.equal(result.outcome_state, 'observed_unverified');
    assert.equal(calls, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

function nonAuthorizingPending(state, key, typed = true) {
  return {
    ...(typed ? { reconciliation_contract: 'agent_write_reconciliation.v1', reconciliation_operation: 'think', safe_to_continue: false } : {}),
    reconciliation_state: state,
    decision_state: state === 'runtime_continuation_persistence_pending' ? 'created' : 'pending',
    idempotency_key: key, committed: false, phase: 'think_pending', resumable: true,
    retryable: true, retry_after_ms: 1000,
  };
}

for (const typed of [true, false]) {
  for (const state of ['pending', 'runtime_decision_authority_pending', 'runtime_continuation_persistence_pending']) {
    test(`marrowThink recovers ${typed ? 'typed' : 'current legacy'} ${state} without inventing an identifier`, async () => {
      const originalFetch = globalThis.fetch; const calls = [];
      globalThis.fetch = async (url, init) => {
        const headers = new Headers(init.headers);
        calls.push({ ...requestRecord(url, init), authorization: headers.get('Authorization'), session: headers.get('X-Marrow-Session-Id'), agent: headers.get('X-Marrow-Agent-Id') });
        if (calls.length === 1) return response(nonAuthorizingPending(state, calls[0].idempotencyKey, typed), 202);
        return response({ decision_id: 'decision-eventually-confirmed', runtime_continuation_persisted: true, idempotency_key: calls[0].idempotencyKey });
      };
      try {
        const result = await marrowThink('fixture-key', 'https://api.example.test', { action: 'Keep the original operation', surfaces: ['workspace'] },
          'session-exact', 'agent-exact', undefined, { idempotencyKey: 'original-operation-key' });
        assert.equal(result.decision_id, 'decision-eventually-confirmed');
        assert.equal(result.runtime_continuation_persisted, true);assert.equal(calls.length, 2);
        assert.deepEqual(calls[1], calls[0]);
        assert.equal(calls[0].idempotencyKey, 'original-operation-key');
        assert.equal(calls[0].authorization, 'Bearer fixture-key');assert.equal(calls[0].session, 'session-exact');assert.equal(calls[0].agent, 'agent-exact');
        assert.equal(new URL(calls[0].url).pathname, '/v1/agent/think');
      } finally { globalThis.fetch = originalFetch; }
    });
  }
}

test('no-ID think exhaustion preserves exactly three attempts and never claims a decision', async () => {
  const originalFetch = globalThis.fetch; const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push(requestRecord(url, init));
    return response(nonAuthorizingPending('runtime_decision_authority_pending', calls[0].idempotencyKey), 202);
  };
  try {
    await assert.rejects(() => marrowThink('fixture-key', 'https://api.example.test', { action: 'Remain pending' }),
      error => reconciliationError(error, 'MCP_RECONCILIATION_EXHAUSTED') && error.retryable === true);
    assert.equal(calls.length, 3);assert.deepEqual(calls[1], calls[0]);assert.deepEqual(calls[2], calls[0]);
  } finally { globalThis.fetch = originalFetch; }
});

test('no-ID think rejects unknown contract, unsafe state and mismatched operation without retry', async t => {
  const mutations = [
    { reconciliation_contract: 'unknown.v2' }, { reconciliation_operation: 'commit' },
    { reconciliation_state: 'unknown' }, { safe_to_continue: true }, { committed: true },
    { idempotency_key: 'different-key' }, { decision_id: '' }, { decision_id: 'unexpected-decision' },
    { retry_after_ms: '1000' }, { phase: 'commit_pending' }, { resumable: false },
    { decision_state: 'outcome_committed' },
  ];
  for (const mutation of mutations) await t.test(Object.keys(mutation)[0], async () => {
    const originalFetch = globalThis.fetch;let calls = 0;
    globalThis.fetch = async (_url, init) => {
      calls += 1;const key = new Headers(init.headers).get('Idempotency-Key');
      return response({ ...nonAuthorizingPending('runtime_decision_authority_pending', key), ...mutation }, 202);
    };
    try {
      await assert.rejects(() => marrowThink('fixture-key', 'https://api.example.test', { action: 'Reject malformed pending' }),
        error => reconciliationError(error, 'MCP_RECONCILIATION_INVALID'));
      assert.equal(calls, 1);
    } finally { globalThis.fetch = originalFetch; }
  });
});

for (const terminal of [{ idempotency_key: 'wrong-key', decision_id: 'decision-final' }, {}]) {
  test(`no-ID recovery rejects ${terminal.decision_id ? 'wrong final key' : 'missing final decision'}`, async () => {
    const originalFetch = globalThis.fetch;let calls = 0;
    globalThis.fetch = async (_url, init) => {
      calls += 1;const key = new Headers(init.headers).get('Idempotency-Key');
      return calls === 1 ? response(nonAuthorizingPending('pending', key), 202) : response(terminal);
    };
    try {
      await assert.rejects(() => marrowThink('fixture-key', 'https://api.example.test', { action: 'Keep final correlation' }),
        error => reconciliationError(error, 'MCP_RECONCILIATION_INVALID'));
      assert.equal(calls, 2);
    } finally { globalThis.fetch = originalFetch; }
  });
}
