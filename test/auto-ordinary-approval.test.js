const assert = require('node:assert/strict');
const test = require('node:test');
const { spawnSync } = require('node:child_process');
const { mkdtempSync, writeFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { marrowAuto } = require('../dist/index.js');

// marrow_auto on an ordinary hold: it waits through the agent-key status read,
// resumes on the same gate receipt once the server records an approval, and
// stops cleanly on a decline or expiry. It never writes proof.owner_approval.
const statusPath = '/v1/agent/gate-receipts/ordinary-gate/owner-approval';
const baseParams = {
  action: 'Deploy the approved fixture', type: 'deploy', surfaces: ['production'],
  outcome: 'Fixture deployment verified', success: true, auto_gate: true,
};
const measuredProof = { summary: 'Deployed.', checks: ['smoke passed'], outcome: 'success' };

function runtimeFixture(approval = {}) {
  return {
    ok: true, action: baseParams.action, agent_id: 'ordinary-agent', session_id: 'ordinary-session',
    decision_id: 'ordinary-runtime-decision',
    runtime_authorization: { id: 'ordinary-gate', kind: 'durable_gate_receipt', durable: true, decision_state: 'created',
      decision_creation_required: false, decision_id: 'ordinary-runtime-decision' },
    risk_gate: { allow: true, decision: 'review_required', risk_level: 'high', enforced: true,
      enforcement_decision: 'owner_approval_required', gate_required: true, gate_receipt_id: 'ordinary-gate' },
    gate_receipt: { id: 'ordinary-gate', required: true, decision: 'review_required',
      owner_approval_required: true, expires_at: '2030-01-01T00:00:00.000Z' },
    proof_pack: { required: true, complete: false, fields: ['summary', 'checks', 'outcome'], missing: ['summary'] },
    completion_contract: {
      must_commit_outcome: true, commit_endpoint: '/v1/agent/commit',
      required_commit_fields: ['decision_id', 'success', 'outcome', 'gate_receipt_id'],
      decision_creation_required: false, decision_state: 'created', decision_id: 'ordinary-runtime-decision',
      gate_receipt_required: true, gate_receipt_id: 'ordinary-gate', owner_approval_required: true,
      arbitration_receipt_required: false,
      owner_approval: {
        mode: 'ordinary_non_arbitrated', proof_path: null, proof_shape: null, dashboard_receipt_required: false,
        trusted_completion_receipt_required: true, receipt_field: 'owner_approval_receipt_id',
        approval_endpoint: '/v1/dashboard/enforcement/owner-approval', approval_authority: 'host_operator_or_dashboard_owner',
        approval_status_endpoint: statusPath, approval_status_poll_after_ms: 5000,
        host_approval_endpoint: '/v1/agent/gate-receipts/ordinary-gate/host-approval', host_approval_accepted: true,
        host_approval_trust: 'client_attested', approval_categories: ['production_deploy'],
        verified_approval_required: false, verified_approval_categories: [],
        ...approval,
      },
    },
  };
}

function statusView(state, extra = {}) {
  const decided = state === 'approved' || state === 'declined';
  return {
    gate_receipt_id: 'ordinary-gate', decision_id: 'ordinary-runtime-decision', gate_decision: 'owner_approval_required',
    owner_approval_receipt_id: state === 'approved' ? 'oar-1' : null, decided_at: null,
    approval_source: decided ? 'dashboard' : null,
    approval_trust: decided ? 'verified' : null,
    approval_answered_by: decided ? 'account_owner' : null,
    expires_at: '2030-01-01T00:00:00.000Z', state, terminal: state !== 'pending', retryable: state === 'pending',
    poll_after_ms: state === 'pending' ? 5000 : null, exact_next_action: `fixture ${state}`,
    ...extra,
  };
}

function invoke(fn, params, timeoutMs = 1500) {
  return fn('ordinary-key', 'https://api.example.test', params, 'ordinary-session', 'ordinary-agent', timeoutMs);
}

function server(states, runtime = runtimeFixture(), statusExtra = {}) {
  const calls = [];
  const queue = [...states];
  const fetch = async (url, init = {}) => {
    const path = new URL(String(url)).pathname;
    const body = init.body ? JSON.parse(init.body) : null;
    calls.push({ path, body, key: new Headers(init.headers).get('Idempotency-Key'), method: init.method || 'GET' });
    if (path.endsWith('/runtime')) return Response.json({ data: runtime });
    if (path === statusPath) {
      const state = queue.length > 1 ? queue.shift() : queue[0];
      return Response.json({ data: statusView(state, statusExtra) });
    }
    if (path.endsWith('/think')) return Response.json({ data: { decision_id: 'unwanted-second-decision' } });
    if (path.endsWith('/commit')) return Response.json({ data: { committed: true, decision_id: body.decision_id } });
    throw new Error(`unexpected ${path}`);
  };
  return { calls, fetch };
}

async function withFetch(fetch, callback) {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = fetch;
  try { return await callback(); } finally { globalThis.fetch = originalFetch; }
}

test('a pending hold waits on the status read and asks to resume after retry_after_ms', async () => {
  const mock = server(['pending']);
  await withFetch(mock.fetch, async () => {
    const waiting = await invoke(marrowAuto, { ...baseParams, operation_id: 'ordinary_wait_pending', proof: measuredProof });
    assert.equal(waiting.phase, 'owner_approval_required');
    assert.equal(waiting.resumable, true);
    assert.equal(waiting.retry_after_ms, 5000);
    assert.equal(waiting.committed, false);
    assert.equal(waiting.decision_id, 'ordinary-runtime-decision');
    assert.equal(waiting.approval.state, 'pending');
    assert.equal(waiting.approval.gate_receipt_id, 'ordinary-gate');
    assert.match(waiting.exact_next_action, /Do not run it yet\. The approval request goes to the account owner\./);
    assert.doesNotMatch(waiting.exact_next_action, /dashboard/i, 'a dashboard login is never the step to take');
    assert.match(waiting.exact_next_action, /same operation_id after retry_after_ms/);
    assert.match(waiting.exact_next_action, /Never write or claim an approval yourself\./);
    assert.doesNotMatch(waiting.exact_next_action, /proof\.owner_approval|approved-release-bundle|arbitrat/);
    assert.deepEqual(mock.calls.map((call) => call.path), ['/v1/agent/runtime', statusPath]);
    assert.equal(mock.calls[1].method, 'GET');
    assert.equal(mock.calls[0].body.proof, undefined, 'the runtime request never carries an approval claim');
  });
});

test('auto polls as advised inside its budget and resumes on the same receipt once approved', async () => {
  const mock = server(['pending', 'approved'], runtimeFixture({ approval_status_poll_after_ms: 1000 }), { poll_after_ms: 1000 });
  await withFetch(mock.fetch, async () => {
    const started = Date.now();
    const closed = await invoke(marrowAuto, { ...baseParams, operation_id: 'ordinary_poll_then_close', proof: measuredProof }, 8000);
    assert.equal(closed.committed, true);
    assert.equal(closed.phase, 'closed');
    assert.ok(Date.now() - started >= 950, 'it waited the advised poll interval');
    assert.deepEqual(mock.calls.map((call) => call.path), ['/v1/agent/runtime', statusPath, statusPath, '/v1/agent/commit']);
    const commit = mock.calls[3].body;
    assert.equal(commit.gate_receipt_id, 'ordinary-gate');
    assert.equal(commit.decision_id, 'ordinary-runtime-decision');
    assert.equal(commit.owner_approval_receipt_id, undefined);
    assert.equal(commit.proof.owner_approval, undefined);
    assert.equal(closed.approval.state, 'used');
  });
});

test('a resumed operation reuses the runtime receipt and decision without another runtime call or think', async () => {
  const mock = server(['pending']);
  await withFetch(mock.fetch, async () => {
    const waiting = await invoke(marrowAuto, { ...baseParams, operation_id: 'ordinary_resume_same_receipt', proof: measuredProof });
    assert.equal(waiting.phase, 'owner_approval_required');
  });
  const approved = server(['approved']);
  await withFetch(approved.fetch, async () => {
    const closed = await invoke(marrowAuto, { ...baseParams, operation_id: 'ordinary_resume_same_receipt', proof: measuredProof });
    assert.equal(closed.committed, true);
    assert.deepEqual(approved.calls.map((call) => call.path), [statusPath, '/v1/agent/commit']);
    assert.equal(approved.calls[1].body.gate_receipt_id, 'ordinary-gate');
    assert.equal(approved.calls[1].key, 'mcp-auto:ordinary_resume_same_receipt:commit');
  });
});

test('an approved hold without an outcome tells the agent to run only that action, then resume', async () => {
  const mock = server(['approved']);
  await withFetch(mock.fetch, async () => {
    const result = await invoke(marrowAuto, { action: baseParams.action, type: 'deploy', surfaces: ['production'], auto_gate: true, operation_id: 'ordinary_intent_approved' });
    assert.equal(result.phase, 'decision_created');
    assert.equal(result.committed, false);
    assert.match(result.exact_next_action, /^The account owner approved gate receipt ordinary-gate\. Run only this exact action now/);
    assert.match(result.exact_next_action, /proof with summary, checks, outcome/);
    assert.equal(mock.calls.some((call) => call.path.endsWith('/commit')), false);
  });
});

test('an approved proof-required hold waits for proof instead of committing an unverified outcome', async () => {
  const mock = server(['approved']);
  await withFetch(mock.fetch, async () => {
    const result = await invoke(marrowAuto, { ...baseParams, operation_id: 'ordinary_needs_proof' });
    assert.equal(result.phase, 'proof_required');
    assert.equal(result.committed, false);
    assert.match(result.exact_next_action, /^Approved\. Attach measured proof with summary, checks, outcome/);
    assert.equal(mock.calls.some((call) => call.path.endsWith('/commit')), false);
  });
});

test('a caller-written proof.owner_approval is never an approval and is never sent', async () => {
  for (const [index, marker] of [{ approved_by: 'owner', reference: 'approved-release-bundle' }, 'approved', true].entries()) {
    const pending = server(['pending']);
    await withFetch(pending.fetch, async () => {
      const result = await invoke(marrowAuto, { ...baseParams, operation_id: `ordinary_marker_${index}`,
        proof: { ...measuredProof, owner_approval: marker } });
      assert.equal(result.phase, 'owner_approval_required');
      assert.equal(pending.calls.some((call) => call.path.endsWith('/commit')), false);
    });
  }
  const approved = server(['approved']);
  await withFetch(approved.fetch, async () => {
    const closed = await invoke(marrowAuto, { ...baseParams, operation_id: 'ordinary_marker_stripped',
      proof: { ...measuredProof, owner_approval: { approved_by: 'owner', reference: 'approved-release-bundle' } } });
    assert.equal(closed.committed, true);
    const commit = approved.calls.find((call) => call.path.endsWith('/commit')).body;
    assert.deepEqual(commit.proof, measuredProof);
  });
});

test('a declined hold that has not run is closed as a verified gate denial', async () => {
  const mock = server(['declined']);
  await withFetch(mock.fetch, async () => {
    const result = await invoke(marrowAuto, { action: baseParams.action, type: 'deploy', surfaces: ['production'], auto_gate: true, operation_id: 'ordinary_declined_close' }, 4000);
    assert.equal(result.committed, true);
    assert.equal(result.phase, 'closed');
    assert.equal(result.closure, 'gate_denial');
    assert.equal(result.approval.state, 'declined');
    assert.match(result.exact_next_action, /^The account owner declined it\. Marrow closed this decision as a denial\. Do not run this action\./);
    const commit = mock.calls.find((call) => call.path.endsWith('/commit')).body;
    assert.equal(commit.success, false);
    assert.equal(commit.gate_receipt_id, 'ordinary-gate');
    assert.match(commit.outcome, /^Denied by Marrow pre-action gate: the account owner declined it \(gate receipt ordinary-gate\); the action did not run\.$/);
    assert.equal(commit.proof, undefined);
  });
});

test('a declined hold with a claimed outcome and an expired hold stop without committing', async () => {
  for (const [state, pattern] of [
    ['declined', /^The account owner declined it \(gate receipt ordinary-gate\)\. Do not run this action\./],
    ['expired', /expired before it was approved\. Do not run the action on it\./],
  ]) {
    const mock = server([state]);
    await withFetch(mock.fetch, async () => {
      const result = await invoke(marrowAuto, { ...baseParams, operation_id: `ordinary_stop_${state}`, proof: measuredProof });
      assert.equal(result.phase, 'review_required');
      assert.equal(result.resumable, false);
      assert.equal(result.committed, false);
      assert.equal(result.approval.state, state);
      assert.match(result.exact_next_action, pattern);
      assert.equal(mock.calls.some((call) => call.path.endsWith('/commit')), false);
    });
  }
});

test('a verified-only category tells the agent only the account owner can approve', async () => {
  const runtime = runtimeFixture({ host_approval_accepted: false, verified_approval_required: true, verified_approval_categories: ['production_deploy'], approval_authority: 'authenticated_dashboard_owner' });
  const mock = server(['pending'], runtime);
  await withFetch(mock.fetch, async () => {
    const waiting = await invoke(marrowAuto, { ...baseParams, operation_id: 'ordinary_verified_only', proof: measuredProof });
    assert.equal(waiting.phase, 'owner_approval_required');
    assert.equal(waiting.approval.verified_approval_required, true);
    assert.deepEqual(waiting.approval.verified_approval_categories, ['production_deploy']);
    assert.match(waiting.exact_next_action, /The account owner approves production_deploy actions personally\. The approval request goes to the account owner\./);
  });
});

test('a service without the approval status read keeps the honest terminal review', async () => {
  const legacy = runtimeFixture();
  legacy.completion_contract.owner_approval = { mode: 'ordinary_non_arbitrated', proof_path: 'proof.owner_approval',
    proof_shape: { approved_by: 'owner', reference: 'approved-release-bundle' }, dashboard_receipt_required: false };
  const mock = server(['approved'], legacy);
  await withFetch(mock.fetch, async () => {
    const result = await invoke(marrowAuto, { ...baseParams, operation_id: 'ordinary_legacy_terminal',
      proof: { ...measuredProof, owner_approval: { approved_by: 'owner', reference: 'approved-release-bundle' } } });
    assert.equal(result.phase, 'review_required');
    assert.equal(result.committed, false);
    assert.match(result.exact_next_action, /No supported ordinary approval path was declared/);
    assert.deepEqual(mock.calls.map((call) => call.path), ['/v1/agent/runtime']);
  });
});

test('a status path that names another receipt is not trusted', async () => {
  const foreign = runtimeFixture({ approval_status_endpoint: '/v1/agent/gate-receipts/foreign-gate/owner-approval' });
  const mock = server(['approved'], foreign);
  await withFetch(mock.fetch, async () => {
    const result = await invoke(marrowAuto, { ...baseParams, operation_id: 'ordinary_foreign_status', proof: measuredProof });
    assert.equal(result.phase, 'review_required');
    assert.equal(mock.calls.some((call) => call.path.includes('foreign-gate')), false);
    assert.equal(mock.calls.some((call) => call.path.endsWith('/commit')), false);
  });
});

for (const [name, mutate] of [
  ['conflicting receipt', (r) => { r.gate_receipt.id = 'foreign-gate'; }],
  ['foreign agent', (r) => { r.agent_id = 'foreign-agent'; }],
  ['foreign session', (r) => { r.session_id = 'foreign-session'; }],
  ['foreign action', (r) => { r.action = 'Different action'; }],
  ['foreign decision', (r) => { r.completion_contract.decision_id = 'foreign-decision'; }],
]) {
  test(`an ordinary hold rejects ${name} before any status read, think or commit`, async () => {
    const runtime = runtimeFixture(); mutate(runtime);
    const mock = server(['approved'], runtime);
    await withFetch(mock.fetch, async () => {
      await assert.rejects(invoke(marrowAuto, { ...baseParams, operation_id: `ordinary_scope_${name.replaceAll(' ', '_')}`, proof: measuredProof }));
      assert.deepEqual(mock.calls.map((call) => call.path), ['/v1/agent/runtime']);
    });
  });
}

test('ordinary same-operation binding rejects changed tenant, action, context, surfaces or receipt', async () => {
  const mock = server(['pending']);
  await withFetch(mock.fetch, async () => {
    const params = { ...baseParams, operation_id: 'ordinary_immutable_binding', context: { ticket: 'one' } };
    await invoke(marrowAuto, params);
    for (const mutation of [{ action: 'different' }, { context: { ticket: 'two' } }, { surfaces: ['different'] },
      { gate_receipt_id: 'foreign-receipt' }]) {
      await assert.rejects(invoke(marrowAuto, { ...params, ...mutation, proof: measuredProof }));
    }
    await assert.rejects(marrowAuto('foreign-key', 'https://api.example.test', params, 'ordinary-session', 'ordinary-agent'));
    assert.equal(mock.calls.filter((call) => call.path.endsWith('/runtime')).length, 1);
  });
});

test('an ordinary approval never substitutes for the arbitration dashboard receipt', async () => {
  const runtime = runtimeFixture();
  runtime.arbitration = { decision_id: runtime.decision_id, receipt_id: 'arbitration-receipt',
    resolution: 'review_required', owner_approval_required: true };
  const mock = server(['approved'], runtime);
  await withFetch(mock.fetch, async () => {
    const result = await invoke(marrowAuto, { ...baseParams, operation_id: 'ordinary_not_arbitration',
      proof: { ...measuredProof, owner_approval: { approved_by: 'owner', reference: 'approved-release-bundle' } }, arbitration_receipt_id: 'arbitration-receipt' });
    assert.equal(result.phase, 'owner_approval_required');
    assert.equal(result.committed, false);
    assert.deepEqual(mock.calls.map((call) => call.path), ['/v1/agent/runtime']);
  });
});

test('the CLI projects the wait and the closure, with the approval state and no approval-writing advice', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-ordinary-cli-'));
  try {
    for (const state of ['pending', 'approved']) {
      const mock = join(directory, `fetch-${state}.cjs`);
      writeFileSync(mock, `
        const fixture = ${JSON.stringify(runtimeFixture())};
        const view = ${JSON.stringify(statusView(state))};
        globalThis.fetch = async (url, init) => {
          const body = JSON.parse(init.body || '{}');
          const path = new URL(String(url)).pathname;
          if (path.endsWith('/runtime')) return Response.json({ data: {
            ...fixture, action: body.action, agent_id: body.agent_id || null, session_id: body.session_id || null,
          } });
          if (path === '${statusPath}') return Response.json({ data: view });
          if (path.endsWith('/think')) throw new Error('unexpected duplicate decision');
          if (path.endsWith('/commit')) return Response.json({ data: { committed: !body.proof?.owner_approval && body.gate_receipt_id === 'ordinary-gate' } });
          return Response.json({ data: { accepted: true } });
        };
      `, { mode: 0o600 });
      const params = { ...baseParams, type: 'implementation', operation_id: `ordinary_cli_projection_${state}`, proof: measuredProof };
      const input = [
        { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
        { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'marrow_auto', arguments: params } },
      ].map(JSON.stringify).join('\n') + '\n';
      const child = spawnSync(process.execPath, [join(__dirname, '../dist/cli.js')], {
        env: { ...process.env, HOME: directory, NODE_OPTIONS: `--require=${mock}`,
          MARROW_API_KEY: 'ordinary-cli-key', MARROW_BASE_URL: 'https://api.example.test',
          MARROW_FLEET_AGENT_ID: 'ordinary-agent', MARROW_AUTO_ENROLL: 'false',
          MARROW_TOOL_PROFILE: 'core', MARROW_REQUEST_TIMEOUT_MS: '1000',
          MARROW_EVENT_SPOOL_PATH: join(directory, 'spool.json') },
        input, encoding: 'utf8', timeout: 15000,
      });
      assert.equal(child.error, undefined);
      assert.equal(child.status, 0, child.stderr);
      const message = child.stdout.trim().split('\n').map(JSON.parse).find((row) => row.id === 2);
      assert.equal(message.error, undefined, JSON.stringify(message));
      const result = JSON.parse(message.result.content[0].text);
      assert.equal(result.decision_id, 'ordinary-runtime-decision');
      const approved = state === 'approved';
      assert.equal(result.phase, approved ? 'closed' : 'owner_approval_required');
      assert.equal(result.completion_state, approved ? 'closed_with_proof' : 'pending_owner_approval');
      assert.equal(result.live_delivery.committed, approved);
      assert.equal(result.approval.state, approved ? 'used' : 'pending');
      assert.doesNotMatch(result.exact_next_action, /arbitrat|proof\.owner_approval|approved-release-bundle/i);
      if (!approved) assert.match(result.exact_next_action, /The approval request goes to the account owner/);
      assert.doesNotMatch(result.exact_next_action, /dashboard/i);
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('the marrow_auto tool description never tells an agent to write its own approval', () => {
  const source = require('node:fs').readFileSync(join(__dirname, '../src/cli.ts'), 'utf8');
  const start = source.indexOf("name: 'marrow_auto'");
  const description = source.slice(start, source.indexOf('inputSchema', start));
  assert.match(description, /Never write or claim an approval yourself\./);
  assert.doesNotMatch(description, /approval supplied in proof|proof\.owner_approval/);
});
