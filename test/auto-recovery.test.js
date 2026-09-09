const assert = require('node:assert/strict');
const test = require('node:test');
const { marrowAuto } = require('../dist/index.js');

const params = (id) => ({ action: 'Record recovery fixture', outcome: 'Fixture verified', success: true, operation_id: id });
const invoke = (id, budget = 8000, fn = marrowAuto) => fn('recovery-key', 'https://api.example.test', params(id), 'recovery-session', 'recovery-agent', budget);

test('auto reserves existing budget to confirm a persisted commit after transport timeout', async () => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  let writes = 0;
  globalThis.fetch = async (url, init) => {
    if (String(url).includes('/think')) return Response.json({ data: { decision_id: 'recovery-timeout-decision' } });
    requests.push({ key: new Headers(init.headers).get('Idempotency-Key'), body: init.body, at: Date.now() });
    if (requests.length === 1) {
      writes++;
      return new Promise((resolve, reject) => {
        const network = setTimeout(() => reject(new Error('unexpected network completion')), 9000);
        init.signal.addEventListener('abort', () => { clearTimeout(network); reject(new DOMException('Lost acknowledgement', 'AbortError')); }, { once: true });
      });
    }
    return Response.json({ data: { committed: true, decision_id: 'recovery-timeout-decision', idempotency_key: requests[0].key } });
  };
  try {
    const started = Date.now();
    const result = await invoke('recovery_timeout_budget');
    assert.equal(result.phase, 'closed');
    assert.equal(requests.length, 2);
    assert.equal(requests[0].key, requests[1].key);
    assert.equal(requests[0].body, requests[1].body);
    assert.equal(writes, 1);
    assert.ok(Date.now() - started < 8000);
  } finally { globalThis.fetch = originalFetch; }
});

test('auto reconciles canonical persistence-pending 202 without prematurely committing', async () => {
  const originalFetch = globalThis.fetch;
  let thinkRequests = 0;
  let commitRequests = 0;
  globalThis.fetch = async (url, init) => {
    const key = new Headers(init.headers).get('Idempotency-Key');
    if (String(url).includes('/think')) {
      thinkRequests++;
      if (thinkRequests === 1) return Response.json({ data: { decision_id: 'recovery-pending-decision', decision_state: 'created', committed: false, retryable: true, idempotency_key: key, reconciliation_state: 'runtime_continuation_persistence_pending', retry_after_ms: 25 } }, { status: 202 });
      return Response.json({ data: { decision_id: 'recovery-pending-decision', idempotency_key: key } });
    }
    commitRequests++;
    assert.equal(thinkRequests, 2, 'a pending think decision is not completed authority');
    if (commitRequests === 1) return Response.json({ data: { decision_id: 'recovery-pending-decision', committed: false, retryable: true, idempotency_key: key, reconciliation_state: 'pending', retry_after_ms: 25 } }, { status: 202 });
    return Response.json({ data: { committed: true, decision_id: 'recovery-pending-decision', idempotency_key: key } });
  };
  try {
    const result = await invoke('recovery_canonical_pending');
    assert.equal(result.phase, 'closed');
    assert.equal(thinkRequests, 2);
    assert.equal(commitRequests, 2);
  } finally { globalThis.fetch = originalFetch; }
});

for (const [name, extra] of [
  ['wrong_decision', { decision_id: 'unrelated-decision' }],
  ['wrong_key', { idempotency_key: 'another-operation-commit' }],
  ['pending_claim', { phase: 'commit_pending', resumable: true }],
]) {
  test(`auto never confirms ${name} as exact operation completion`, async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (url) => Response.json({ data: String(url).includes('/think')
      ? { decision_id: 'recovery-expected-decision' }
      : { committed: true, ...extra } }, { status: name === 'pending_claim' && !String(url).includes('/think') ? 202 : 200 });
    try {
      await assert.rejects(invoke(`recovery_reject_${name}`, 500), error => error.code === 'invalid_response');
    } finally { globalThis.fetch = originalFetch; }
  });
}

test('auto refuses changed decision after a correlated pending think', async () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async (url, init) => {
    calls++;
    return calls === 1
      ? Response.json({ data: { decision_id: 'first-decision', decision_state: 'created', committed: false, retryable: true, idempotency_key: new Headers(init.headers).get('Idempotency-Key'), reconciliation_state: 'runtime_continuation_persistence_pending', retry_after_ms: 25 } }, { status: 202 })
      : Response.json({ data: { decision_id: 'changed-decision' } });
  };
  try { await assert.rejects(invoke('recovery_changed_decision', 500), error => error.code === 'invalid_response'); }
  finally { globalThis.fetch = originalFetch; }
});

for (const status of [202, 429]) {
  test(`auto honors HTTP ${status} Retry-After without a nested retry`, async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = async (url, init) => {
      if (String(url).includes('/think')) return Response.json({ data: { decision_id: 'recovery-paced-decision' } });
      calls++;
      return Response.json(status === 202 ? { data: { phase: 'commit_pending', resumable: true, retry_after_ms: 25 } } : { error: 'Busy' }, { status, headers: { 'Retry-After': '2' } });
    };
    try {
      const result = await invoke(`recovery_header_${status}`, 500);
      assert.equal(result.phase, 'commit_pending');
      assert.equal(result.committed, false);
      assert.equal(result.retry_after_ms, 2000);
      assert.equal(calls, 1);
      assert.match(result.exact_next_action, /same operation_id/);
    } finally { globalThis.fetch = originalFetch; }
  });
}

test('auto returns truthful pending on exhausted recovery and resumes exact same operation', async () => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  let accepted = false;
  let writes = 0;
  globalThis.fetch = async (url, init) => {
    if (String(url).includes('/think')) return Response.json({ data: { decision_id: 'recovery-resume-decision' } });
    requests.push({ key: new Headers(init.headers).get('Idempotency-Key'), body: init.body });
    if (!accepted) {
      accepted = true;
      writes++;
      throw new DOMException('Lost ACK after durable write', 'AbortError');
    }
    return Response.json({ data: { committed: true, decision_id: 'recovery-resume-decision', idempotency_key: requests[0].key } });
  };
  try {
    const pending = await invoke('recovery_same_resume', 500);
    assert.equal(pending.committed, false);
    assert.equal(pending.phase, 'commit_pending');
    assert.equal(pending.retry_after_ms, 1000);
    delete require.cache[require.resolve('../dist/index.js')];
    const restarted = require('../dist/index.js').marrowAuto;
    const replayed = await invoke('recovery_same_resume', 500, restarted);
    assert.equal(replayed.committed, true);
    assert.equal(replayed.decision_id, pending.decision_id);
    assert.deepEqual(requests[1], requests[0]);
    assert.equal(writes, 1);
  } finally { globalThis.fetch = originalFetch; }
});

test('auto does not close on a durable unverified observation', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => Response.json({ data: String(url).includes('/think')
    ? { decision_id: 'recovery-observation-decision' }
    : { accepted: true, committed: false, outcome_state: 'observed_unverified', outcome_observation_id: 'observation-fixture', authorization_granted: false, trusted_learning_applied: false, exact_next_action: 'Supply verified proof.' } }, { status: String(url).includes('/think') ? 200 : 202 });
  try {
    const result = await invoke('recovery_unverified_outcome', 500);
    assert.equal(result.committed, false);
    assert.notEqual(result.phase, 'closed');
  } finally { globalThis.fetch = originalFetch; }
});
