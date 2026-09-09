const assert = require('node:assert/strict');
const test = require('node:test');
const { spawnSync } = require('node:child_process');
const { mkdtempSync, writeFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { marrowAuto } = require('../dist/index.js');

const approval = { approved_by: 'owner', reference: 'approved-release-bundle' };
const baseParams = {
  action: 'Deploy the approved fixture', type: 'deploy', surfaces: ['production'],
  outcome: 'Fixture deployment verified', success: true, auto_gate: true,
};
function runtimeFixture() {
  return {
    ok: true, action: baseParams.action, agent_id: 'ordinary-agent', session_id: 'ordinary-session',
    decision_id: 'ordinary-runtime-decision',
    risk_gate: { allow: false, decision: 'review_required', risk_level: 'high', enforced: true,
      enforcement_decision: 'review_required', gate_required: true, gate_receipt_id: 'ordinary-gate' },
    gate_receipt: { id: 'ordinary-gate', required: true, decision: 'owner_approval_required',
      owner_approval_required: true, expires_at: '2030-01-01T00:00:00.000Z' },
    proof_pack: { required: true, complete: false, fields: ['checks', 'owner_approval'], missing: ['owner_approval'] },
    completion_contract: {
      must_commit_outcome: true, commit_endpoint: '/v1/agent/commit',
      required_commit_fields: ['decision_id', 'success', 'outcome', 'gate_receipt_id'],
      decision_creation_required: false, decision_state: 'created', decision_id: 'ordinary-runtime-decision',
      gate_receipt_required: true, gate_receipt_id: 'ordinary-gate', owner_approval_required: true,
      arbitration_receipt_required: false,
      owner_approval: { mode: 'ordinary_non_arbitrated', proof_path: 'proof.owner_approval',
        proof_shape: approval, dashboard_receipt_required: false },
    },
  };
}
function invoke(fn, params) {
  return fn('ordinary-key', 'https://api.example.test', params, 'ordinary-session', 'ordinary-agent', 8000);
}

test('ordinary approval waits then resumes the exact runtime decision and receipt without think', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    const path = new URL(String(url)).pathname;
    const body = JSON.parse(init.body);
    calls.push({ path, body, key: new Headers(init.headers).get('Idempotency-Key') });
    if (path.endsWith('/runtime')) return Response.json({ data: runtimeFixture() });
    if (path.endsWith('/think')) return Response.json({ data: { decision_id: 'unwanted-second-decision' } });
    return Response.json({ data: { committed: true } });
  };
  try {
    const params = { ...baseParams, operation_id: 'ordinary_approval_resume', proof: { checks: ['passed'] } };
    const waiting = await invoke(marrowAuto, params);
    assert.equal(waiting.phase, 'owner_approval_required');
    assert.equal(waiting.decision_id, 'ordinary-runtime-decision');
    assert.equal(waiting.resumable, false);
    assert.equal(waiting.retry_after_ms, null);
    assert.equal(waiting.committed, false);
    assert.doesNotMatch(waiting.exact_next_action, /marrow_arbitrate|new operation|dashboard/i);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].body.response_mode, 'expanded');
    assert.equal(calls[0].body.proof, undefined, 'runtime request must not manufacture approval');

    const proof = { checks: ['passed'], owner_approval: approval };
    const closed = await invoke(marrowAuto, { ...params, proof });
    assert.equal(closed.committed, true);
    assert.equal(closed.decision_id, waiting.decision_id);
    assert.equal(closed.runtime_gate.risk_gate.allow, false, 'commit evidence does not rewrite action authorization');
    assert.equal(calls.length, 2);
    assert.equal(calls[1].path, '/v1/agent/commit');
    assert.equal(calls[1].body.decision_id, waiting.decision_id);
    assert.equal(calls[1].body.gate_receipt_id, 'ordinary-gate');
    assert.deepEqual(calls[1].body.proof, proof);
    assert.equal(calls[1].body.owner_approval_receipt_id, undefined);
  } finally { globalThis.fetch = originalFetch; }
});

for (const [name, marker] of [['text', 'approved'], ['boolean', true], ['array', [approval]],
  ['wrong owner', { ...approval, approved_by: 'model' }], ['extra field', { ...approval, human_directed: true }]]) {
  test(`ordinary approval does not infer authorization from ${name}`, async () => {
    const originalFetch = globalThis.fetch;
    let commits = 0;
    globalThis.fetch = async (url) => {
      if (String(url).includes('/runtime')) return Response.json({ data: runtimeFixture() });
      if (String(url).includes('/think')) return Response.json({ data: { decision_id: 'unwanted-second-decision' } });
      commits += 1;
      return Response.json({ data: { committed: true } });
    };
    try {
      const result = await invoke(marrowAuto, { ...baseParams,
        operation_id: `ordinary_bad_${name.replaceAll(' ', '_')}`,
        proof: { checks: ['passed'], owner_approval: marker },
        source_meta: { human_directed: true },
      });
      assert.equal(result.phase, 'owner_approval_required');
      assert.equal(result.committed, false);
      assert.equal(commits, 0);
    } finally { globalThis.fetch = originalFetch; }
  });
}

for (const [name, mutate] of [
  ['missing receipt', (r) => { delete r.gate_receipt; delete r.risk_gate.gate_receipt_id; }],
  ['conflicting receipt', (r) => { r.gate_receipt.id = 'foreign-gate'; }],
  ['foreign agent', (r) => { r.agent_id = 'foreign-agent'; }],
  ['foreign session', (r) => { r.session_id = 'foreign-session'; }],
  ['foreign action', (r) => { r.action = 'Different action'; }],
  ['foreign decision', (r) => { r.completion_contract.decision_id = 'foreign-decision'; }],
  ['missing decision', (r) => { delete r.decision_id; }],
]) {
  test(`ordinary approval rejects ${name} before think or commit`, async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      const runtime = runtimeFixture(); mutate(runtime);
      return Response.json({ data: runtime });
    };
    try {
      await assert.rejects(invoke(marrowAuto, { ...baseParams,
        operation_id: `ordinary_scope_${name.replaceAll(' ', '_')}`, proof: { owner_approval: approval },
      }));
      assert.equal(calls, 1);
    } finally { globalThis.fetch = originalFetch; }
  });
}

for (const expiry of ['2000-01-01T00:00:00Z', 'invalid', undefined]) {
  test(`ordinary approval cannot commit with expired or unknown expiry ${expiry}`, async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      const runtime = runtimeFixture(); runtime.gate_receipt.expires_at = expiry;
      return Response.json({ data: runtime });
    };
    try {
      const result = await invoke(marrowAuto, { ...baseParams,
        operation_id: `ordinary_expiry_${expiry === undefined ? 'missing' : expiry === 'invalid' ? 'invalid' : 'past'}`,
        proof: { checks: ['passed'], owner_approval: approval },
      });
      assert.equal(result.phase, 'review_required');
      assert.equal(result.committed, false);
      assert.equal(calls, 1);
    } finally { globalThis.fetch = originalFetch; }
  });
}

test('ordinary same-operation binding rejects changed tenant, action, context, surfaces or receipt', async () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; return Response.json({ data: runtimeFixture() }); };
  try {
    const params = { ...baseParams, operation_id: 'ordinary_immutable_binding', context: { ticket: 'one' } };
    await invoke(marrowAuto, params);
    for (const mutation of [{ action: 'different' }, { context: { ticket: 'two' } }, { surfaces: ['different'] },
      { gate_receipt_id: 'foreign-receipt' }]) {
      await assert.rejects(invoke(marrowAuto, { ...params, ...mutation, proof: { owner_approval: approval } }));
    }
    await assert.rejects(marrowAuto('foreign-key', 'https://api.example.test', params, 'ordinary-session', 'ordinary-agent'));
    assert.equal(calls, 1);
  } finally { globalThis.fetch = originalFetch; }
});

for (const rejection of [403, 409]) {
  test(`ordinary supplied proof preserves authoritative backend rejection ${rejection}`, async () => {
    const originalFetch = globalThis.fetch;
    let commits = 0;
    globalThis.fetch = async (url) => {
      if (String(url).includes('/runtime')) return Response.json({ data: runtimeFixture() });
      commits += 1;
      return Response.json({ error: 'Fixture receipt or required proof rejected', details: {
        code: rejection === 403 ? 'MARROW_PRE_ACTION_GATE_SCOPE_MISMATCH' : 'MARROW_PROOF_PACK_INCOMPLETE',
      } }, { status: rejection });
    };
    try {
      await assert.rejects(invoke(marrowAuto, { ...baseParams, operation_id: `ordinary_backend_reject_${rejection}`,
        proof: { owner_approval: approval },
      }), (error) => error.status === rejection);
      assert.equal(commits, 1);
    } finally { globalThis.fetch = originalFetch; }
  });
}

test('ordinary marker never substitutes for the arbitration dashboard receipt', async () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    const runtime = runtimeFixture();
    runtime.arbitration = { decision_id: runtime.decision_id, receipt_id: 'arbitration-receipt',
      resolution: 'review_required', owner_approval_required: true };
    return Response.json({ data: runtime });
  };
  try {
    const result = await invoke(marrowAuto, { ...baseParams, operation_id: 'ordinary_marker_not_arbitration',
      proof: { checks: ['passed'], owner_approval: approval }, arbitration_receipt_id: 'arbitration-receipt',
    });
    assert.equal(result.phase, 'owner_approval_required');
    assert.equal(result.committed, false);
    assert.equal(calls, 1);
  } finally { globalThis.fetch = originalFetch; }
});

test('ordinary restart and lost commit ACK preserve request scope, one decision and one effect', async () => {
  const originalFetch = globalThis.fetch;
  const requestBodies = new Map();
  const effects = new Set();
  const calls = [];
  let loseAck = true;
  globalThis.fetch = async (url, init) => {
    const path = new URL(String(url)).pathname;
    const key = new Headers(init.headers).get('Idempotency-Key');
    if (requestBodies.has(key)) assert.equal(init.body, requestBodies.get(key));
    else requestBodies.set(key, init.body);
    calls.push(path);
    if (path.endsWith('/runtime')) return Response.json({ data: runtimeFixture() });
    assert.equal(path, '/v1/agent/commit', 'restart must not create another decision');
    const body = JSON.parse(init.body);
    assert.equal(body.decision_id, 'ordinary-runtime-decision');
    effects.add(key);
    if (loseAck) { loseAck = false; throw new DOMException('ACK lost', 'AbortError'); }
    return Response.json({ data: { committed: true } });
  };
  try {
    const params = { ...baseParams, operation_id: 'ordinary_restart_lost_ack' };
    const waiting = await invoke(marrowAuto, params);
    assert.equal(waiting.phase, 'owner_approval_required');
    delete require.cache[require.resolve('../dist/index.js')];
    const restarted = require('../dist/index.js').marrowAuto;
    const closed = await invoke(restarted, { ...params, proof: { checks: ['passed'], owner_approval: approval } });
    assert.equal(closed.committed, true);
    assert.equal(closed.decision_id, waiting.decision_id);
    assert.equal(calls.filter((path) => path.endsWith('/runtime')).length, 2);
    assert.equal(effects.size, 1);
    assert.equal(requestBodies.size, 2);
  } finally { globalThis.fetch = originalFetch; }
});

test('ordinary CLI projects waiting guidance and closure without suggesting arbitration', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-ordinary-cli-'));
  try {
    const mock = join(directory, 'fetch.cjs');
    writeFileSync(mock, `
      const fixture = ${JSON.stringify(runtimeFixture())};
      globalThis.fetch = async (url, init) => {
        const body = JSON.parse(init.body || '{}');
        if (String(url).includes('/runtime')) return Response.json({ data: {
          ...fixture, action: body.action, agent_id: body.agent_id || null, session_id: body.session_id || null,
        } });
        if (String(url).includes('/think')) throw new Error('unexpected duplicate decision');
        if (String(url).includes('/commit')) return Response.json({ data: {
          committed: body.proof?.owner_approval?.approved_by === 'owner',
        } });
        return Response.json({ data: { accepted: true } });
      };
    `, { mode: 0o600 });
    for (const approved of [false, true]) {
      const params = { ...baseParams, type: 'implementation', operation_id: `ordinary_cli_projection_${approved}`,
        proof: { checks: ['passed'], ...(approved ? { owner_approval: approval } : {}) } };
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
        input, encoding: 'utf8', timeout: 3000,
      });
      assert.equal(child.error, undefined);
      assert.equal(child.status, 0, child.stderr);
      const message = child.stdout.trim().split('\n').map(JSON.parse).find((row) => row.id === 2);
      assert.equal(message.error, undefined, JSON.stringify(message));
      const result = JSON.parse(message.result.content[0].text);
      assert.equal(result.decision_id, 'ordinary-runtime-decision');
      assert.equal(result.phase, approved ? 'closed' : 'owner_approval_required');
      assert.equal(result.completion_state, approved ? 'closed_with_proof' : 'pending_owner_approval');
      assert.equal(result.live_delivery.committed, approved);
      assert.doesNotMatch(result.exact_next_action, /dashboard|arbitrat|new operation/i);
    }
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
