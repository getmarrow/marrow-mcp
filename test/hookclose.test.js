'use strict';

// Core-loop step E (bld-hookclose): every hook decision closes with a record, and the
// operator's "no" in the host dialog reaches Marrow as a decline. Each host event runs
// as its own built hook process (dist/cli.js, as marrow-launch runs it) with a fake
// HOME, a dummy key made at run time and the scripted Marrow API of
// test/support/host-approval-fetch-mock.cjs (no network). Row ids: ACCEPTANCE
// bld-hookclose (HC1 a-d, AE1-AE5, AM1-AM6, DR1-DR12).
const assert = require('node:assert/strict');
const test = require('node:test');
const { writeOfficialHostConfigs } = require('./support/official-host-config.cjs');
writeOfficialHostConfigs();
const { projectCwd } = require('./support/hermetic-project.cjs');
const { dummySecret } = require('./support/dummy-secret.cjs');
const { spawnSync } = require('node:child_process');
const { randomBytes } = require('node:crypto');
const { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { CLAUDE_CODE_USER_REJECTED } = require('../dist/host-approval.js');

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const MOCK = join(__dirname, 'support', 'host-approval-fetch-mock.cjs');
const FIXTURES = join(__dirname, 'fixtures', 'host-approvals');
const fixture = (name) => JSON.parse(readFileSync(join(FIXTURES, name), 'utf8'));
const CLAUDE_SESSION = '3b1f0c2e-0000-4000-8000-00000000000a';
const HELD_TOOL_USE = 'toolu_01HELDDEPLOY0000000000001';

function hostRuntime(receipt = 'gate-held', decision = 'decision-review', proof = true) {
  return {
    ok: true,
    action: 'classified Bash action: deploy on production',
    decision_id: decision,
    runtime_authorization: { id: receipt, kind: 'durable_gate_receipt', durable: true, decision_state: 'created', decision_creation_required: false, decision_id: decision },
    gate_receipt: { id: receipt, decision: 'review_required', required: true, owner_approval_required: true, expires_at: '2030-01-01T00:30:00.000Z' },
    proof_pack: proof
      ? { required: true, fields: ['summary', 'checks', 'outcome', 'blockers', 'commits_prs_shas', 'rollback_target', 'handoff_result_file', 'deployment_and_smoke'], complete: false }
      : { required: false, fields: [], complete: true },
    completion_contract: {
      decision_id: decision, decision_creation_required: false, decision_state: 'created',
      owner_approval_required: true, arbitration_receipt_required: false, gate_receipt_required: true,
      required_commit_fields: ['decision_id', 'success', 'outcome', 'gate_receipt_id'],
      owner_approval: {
        mode: 'ordinary_non_arbitrated', proof_path: null, proof_shape: null, dashboard_receipt_required: false,
        trusted_completion_receipt_required: true, receipt_field: 'owner_approval_receipt_id',
        approval_endpoint: '/v1/dashboard/enforcement/owner-approval', approval_authority: 'host_operator_or_dashboard_owner',
        approval_status_endpoint: `/v1/agent/gate-receipts/${receipt}/owner-approval`, approval_status_poll_after_ms: 5000,
        host_approval_endpoint: `/v1/agent/gate-receipts/${receipt}/host-approval`, host_approval_accepted: true,
        host_approval_trust: 'client_attested', approval_categories: ['production_deploy'],
        verified_approval_required: false, verified_approval_categories: [],
      },
    },
    risk_gate: { allow: true, decision: 'review_required', enforced: true, gate_required: true, gate_receipt_id: receipt, risk_level: 'high', reasons: [{ message: 'Production deploys need approval.' }] },
    gate_receipt_id: receipt,
    exact_next_action: 'Obtain explicit owner approval before this action runs.',
  };
}

// The commit route's answer to an outcome without full proof (backend unverified-outcome-observation.service.ts:364-377).
const OBSERVED = {
  accepted: true, committed: false, outcome_state: 'observed_unverified',
  outcome_observation_id: `uobs_${'a'.repeat(64)}`, authorization_granted: false, trusted_learning_applied: false,
  exact_next_action: 'Commit again with proof: summary, checks, outcome, blockers.',
};

function harness() {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-hookclose-'));
  const home = join(dir, 'home');
  const mockDir = join(dir, 'mock');
  mkdirSync(home, { mode: 0o700 });
  writeOfficialHostConfigs(home);
  mkdirSync(mockDir);
  // Dummy keys generated for this run; they never leave the mock.
  const apiKey = `mrw_test_${randomBytes(16).toString('hex')}`;
  const otherKey = `mrw_test_${randomBytes(16).toString('hex')}`;
  let config = {};
  const setConfig = (next) => { config = { ...config, ...next }; writeFileSync(join(mockDir, 'config.json'), JSON.stringify(config)); };
  const requests = () => {
    const path = join(mockDir, 'requests.jsonl');
    return existsSync(path) ? readFileSync(path, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line)) : [];
  };
  const outputs = [];
  const run = (entrypoint, payload, env = {}) => {
    const result = spawnSync(process.execPath, [CLI, entrypoint], {
      input: JSON.stringify(payload),
      cwd: projectCwd(),
      env: {
        PATH: process.env.PATH, HOME: home, MARROW_API_KEY: apiKey, MARROW_BASE_URL: 'https://api.example.test',
        MARROW_AGENT_ID: 'agent-one', MARROW_HOOK_BACKGROUND_NUDGE: 'false', MARROW_PASSIVE_TOKEN_USAGE: 'false',
        MARROW_TEST_MOCK_DIR: mockDir, NODE_OPTIONS: `--require=${MOCK}`, ...env,
      },
      encoding: 'utf8',
      timeout: 30_000,
    });
    assert.equal(result.error, undefined);
    outputs.push(result.stdout, result.stderr);
    const output = result.stdout.trim();
    let json = null;
    try { json = output ? JSON.parse(output) : null; } catch { json = null; }
    return { status: result.status, stdout: output, stderr: result.stderr, json };
  };
  const statePath = join(home, '.marrow', 'host-approvals', 'state.json');
  const state = () => (existsSync(statePath) ? JSON.parse(readFileSync(statePath, 'utf8')) : null);
  const editHolds = (change) => {
    const current = state();
    for (const hold of Object.values(current.holds)) change(hold);
    writeFileSync(statePath, JSON.stringify(current));
    chmodSync(statePath, 0o600);
  };
  // A Claude Code transcript: the tool_use of each call, and the tool_result rows given.
  const transcript = (rows) => {
    const target = join(dir, `transcript-${randomBytes(4).toString('hex')}.jsonl`);
    const lines = rows.map((row) => JSON.stringify({
      type: 'user', uuid: `u-${row.id}`,
      ...(row.kind ? { toolDenialKind: row.kind } : {}),
      message: { role: 'user', content: [{ type: 'tool_result', tool_use_id: row.id, content: row.text, is_error: true }] },
    }));
    writeFileSync(target, `${lines.join('\n')}\n`);
    return target;
  };
  const everything = () => [readFileSync(join(mockDir, 'requests.jsonl'), 'utf8'), existsSync(statePath) ? readFileSync(statePath, 'utf8') : '', ...outputs].join('\n');
  return { dir, home, apiKey, otherKey, run, setConfig, requests, state, editHolds, transcript, everything, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

const hostReports = (h) => h.requests().filter((r) => r.path.endsWith('/host-approval'));
const declines = (h) => hostReports(h).filter((r) => r.body.verdict === 'declined');
const commits = (h) => h.requests().filter((r) => r.path === '/v1/agent/commit');
const postEvents = (h) => h.requests().filter((r) => r.path === '/v1/agent/integrations/events' && /^posttool-/.test(r.body?.event_id || ''));
const preEvents = (h) => h.requests().filter((r) => r.path === '/v1/agent/integrations/events' && /^pretool-/.test(r.body?.event_id || ''));
const runtimes = (h) => h.requests().filter((r) => r.path === '/v1/agent/runtime' && /^classified \S+ action: /.test(r.body?.action || ''));
const sessionEvent = (name, extra = {}) => ({ session_id: CLAUDE_SESSION, cwd: '/home/operator/project', hook_event_name: name, ...extra });

// AM6 / DR1: no body the client builds carries an owner-looking or trust field.
const OWNER_LOOKING = ['source', 'trust', 'trusted', 'verified', 'answered_by', 'approval_source', 'approval_trust', 'approved', 'approval',
  'owner_approval', 'owner_approval_receipt_id', 'release', 'release_binding', 'operator', 'authorization_granted', 'trusted_learning_applied', 'verdict_trust'];
function auditBodies(h) {
  const hits = [];
  for (const request of h.requests()) {
    const body = request.body || {};
    if (request.path === '/v1/agent/integrations/events') continue; // lifecycle events: checked by key list below
    for (const key of Object.keys(body)) if (OWNER_LOOKING.includes(key)) hits.push(`${request.path} ${key}`);
    if (body.proof && typeof body.proof === 'object') {
      // H1 names the evidence origin of the host observation: proof.source is exactly hook_post_tool, nothing owner-looking.
      for (const [key, value] of Object.entries(body.proof)) {
        if (OWNER_LOOKING.includes(key) && !(key === 'source' && value === 'hook_post_tool')) hits.push(`${request.path} proof.${key}`);
      }
    }
  }
  for (const event of postEvents(h)) {
    // BASE lifecycle identity: source is always client_self_reported (src/hook-contract.ts:153).
    if ('source' in event.body && event.body.source !== 'client_self_reported') hits.push('posttool source');
    for (const key of ['trust', 'answered_by', 'verdict', 'gate_receipt_id', 'approved', 'owner_approval_receipt_id']) if (key in event.body) hits.push(`posttool ${key}`);
  }
  return hits;
}

// The held deploy asked in the Claude Code dialog (PreToolUse), optionally with the dialog marker.
function heldClaudeCall(h, extra = {}, marker = true) {
  const pre = h.run('claude-pre-action-hook', { ...fixture('claude-pre-tool-use.json'), ...extra });
  assert.equal(pre.json.hookSpecificOutput.permissionDecision, 'ask');
  if (marker) h.run('claude-permission-request-hook', { ...fixture('claude-permission-request.json'), ...(extra.tool_input ? { tool_input: extra.tool_input } : {}) });
  return pre;
}

// The observation waits OBSERVATION_GRACE_MS for the agent's own commit; this makes every queued one due,
// then a later hook (Stop flushes due outbox entries) sends it, as a later hook on the host would.
function afterGrace(h, entry = 'claude-session-hook', payload = sessionEvent('Stop')) {
  if (h.state()) h.editHolds((hold) => { if (hold.outbox) hold.outbox.next_at = 0; });
  h.run(entry, payload);
}

// ---------------------------------------------------------------- HC1 (red on BASE)

test('HC1a E1: a proof-required hold that ran queues one untrusted host observation next to the unchanged approved report; a later hook sends it', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime(), commit: OBSERVED });
    heldClaudeCall(h);
    const post = h.run('claude-hook', fixture('claude-post-tool-use.json'));
    const reports = hostReports(h);
    assert.equal(reports.length, 1);
    assert.equal(reports[0].body.verdict, 'approved');
    assert.deepEqual(Object.keys(reports[0].body).sort(), ['answered_at', 'asked_at', 'decision_id', 'hook_event', 'host', 'host_session_id', 'normalized_action', 'pre_action_event_id', 'verdict']);
    const [queued] = Object.values(h.state().holds);
    assert.ok(queued.outbox && queued.outbox.commit, 'E1: the hold that ran keeps its observation in the outbox');
    assert.equal(queued.outbox.report, null);
    assert.ok(queued.outbox.next_at > Date.now() + 60_000, 'the observation waits for the agent\'s own commit first');
    assert.deepEqual(commits(h), [], 'nothing is sent before the grace period');
    afterGrace(h);
    const list = commits(h);
    assert.equal(list.length, 1, 'E1: the held call that ran closes with one observation');
    const [commit] = list;
    assert.deepEqual(Object.keys(commit.body).sort(), ['decision_id', 'gate_receipt_id', 'outcome', 'proof', 'success']);
    assert.equal(commit.body.success, true);
    assert.equal(commit.body.decision_id, 'decision-review');
    assert.equal(commit.body.gate_receipt_id, 'gate-held');
    assert.match(commit.body.outcome, /completed in Claude Code after it was approved \(gate receipt gate-held\)\.$/);
    assert.deepEqual(commit.body.proof, {
      summary: commit.body.outcome, checks: 'host tool result only', outcome: 'completed', source: 'hook_post_tool', tool_use_id: HELD_TOOL_USE,
    });
    assert.match(commit.idempotency_key, /^mcp-host-approval:[a-f0-9]{40}$/);
    assert.match(post.json.hookSpecificOutput.additionalContext, /unverified observation/);
    assert.deepEqual(auditBodies(h), []);
  } finally { h.cleanup(); }
});

test('HC1b E3: the PostToolUse record of a held call names its local decision and its known result; the runtime call names its correlation', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime(), commit: OBSERVED });
    heldClaudeCall(h);
    h.run('claude-hook', fixture('claude-post-tool-use.json'));
    const [runtime] = runtimes(h);
    const [pre] = preEvents(h);
    assert.equal(runtime.body.correlation_id, pre.body.correlation_id, 'E3: the runtime call sends the correlation it already computes');
    const [post] = postEvents(h);
    assert.equal(post.body.correlation_id, pre.body.correlation_id);
    assert.equal(post.body.decision_id, 'decision-review', 'E3: the local hold names the decision');
    assert.equal(post.body.success, true);
    assert.notEqual(post.body.outcome_state, 'pending', 'E3: a known result is not sent as pending');
    assert.deepEqual(auditBodies(h), []);
  } finally { h.cleanup(); }
});

for (const point of ['Stop', 'SessionStart']) {
  test(`HC1c E2/DR-F1: an open ask hold with a user-rejected transcript result is declined at ${point}`, () => {
    const h = harness();
    try {
      h.setConfig({ runtime: hostRuntime() });
      const path = h.transcript([{ id: HELD_TOOL_USE, kind: 'user-rejected', text: CLAUDE_CODE_USER_REJECTED }]);
      heldClaudeCall(h, { transcript_path: path });
      h.run('claude-session-hook', sessionEvent(point, { transcript_path: path }));
      const list = declines(h);
      assert.equal(list.length, 1, `${point}: the operator's decline is reported`);
      assert.equal(list[0].body.hook_event, point);
      assert.equal(list[0].body.decision_id, 'decision-review');
      const [commit] = commits(h);
      assert.equal(commit.body.success, false);
      assert.equal(commit.body.outcome, 'Denied by Marrow pre-action gate: the operator declined in Claude Code (gate receipt gate-held).');
      assert.equal(Object.values(h.state().holds)[0].state, 'resolved');
      // DR3: a second settle pass sends nothing more.
      h.run('claude-session-hook', sessionEvent(point, { transcript_path: path }));
      assert.equal(declines(h).length, 1);
      assert.equal(commits(h).length, 1);
      assert.deepEqual(auditBodies(h), []);
    } finally { h.cleanup(); }
  });
}

test('HC1c neighbour: UserPromptSubmit with no PostToolBatch declines from the transcript (BASE already settles here)', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime() });
    const path = h.transcript([{ id: HELD_TOOL_USE, kind: 'user-rejected', text: CLAUDE_CODE_USER_REJECTED }]);
    heldClaudeCall(h, { transcript_path: path });
    h.run('claude-context-hook', { ...fixture('claude-user-prompt-submit.json'), transcript_path: path });
    assert.equal(declines(h).length, 1);
    assert.equal(declines(h)[0].body.hook_event, 'UserPromptSubmit');
  } finally { h.cleanup(); }
});

for (const point of ['Stop', 'UserPromptSubmit']) {
  test(`HC1d EH2/AM3: an ask hold open past its expiry with no answer reports unanswered at ${point}, never a decline`, () => {
    const h = harness();
    try {
      h.setConfig({ runtime: hostRuntime() });
      // AM3: the transcript holds no tool_result for this call.
      const path = h.transcript([{ id: 'toolu_other_call', kind: 'user-rejected', text: CLAUDE_CODE_USER_REJECTED }]);
      heldClaudeCall(h, { transcript_path: path });
      h.editHolds((hold) => { hold.expires_at = new Date(Date.now() - 60_000).toISOString(); });
      if (point === 'Stop') h.run('claude-session-hook', sessionEvent('Stop', { transcript_path: path }));
      else h.run('claude-context-hook', { ...fixture('claude-user-prompt-submit.json'), transcript_path: path });
      assert.deepEqual(hostReports(h), [], 'no decline and no approval');
      const list = commits(h);
      assert.equal(list.length, 1, 'EH2: the expired hold closes');
      assert.equal(list[0].body.success, false);
      assert.match(list[0].body.outcome, /^Unanswered: /);
      assert.doesNotMatch(list[0].body.outcome, /declined|approved|completed/);
      assert.equal(list[0].body.proof, undefined);
      // Once per hold.
      h.run('claude-session-hook', sessionEvent('Stop', { transcript_path: path }));
      assert.equal(commits(h).length, 1);
    } finally { h.cleanup(); }
  });
}

// ---------------------------------------------------------------- HC2 records (H1-H4)

test('AE1: a forged decision id in the event or tool_input never closes a decision; only the local hold is joined', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime(), commit: OBSERVED });
    heldClaudeCall(h);
    h.run('claude-hook', { ...fixture('claude-post-tool-use.json'), decision_id: 'decision-forged', gate_receipt_id: 'gate-forged' });
    assert.equal(postEvents(h)[0].body.decision_id, 'decision-review');
    afterGrace(h);
    assert.equal(commits(h)[0].body.decision_id, 'decision-review');
    assert.equal(commits(h)[0].body.gate_receipt_id, 'gate-held');
    // A call Marrow never held, carrying another agent's decision in its input and event.
    h.run('claude-hook', {
      ...fixture('claude-post-tool-use.json'), tool_use_id: 'toolu_unheld', decision_id: 'decision-forged', gate_receipt_id: 'gate-forged',
      tool_input: { command: 'touch notes.txt', decision_id: 'decision-forged', gate_receipt_id: 'gate-forged' },
    });
    afterGrace(h);
    const unheld = postEvents(h).filter((event) => event.body.decision_id !== 'decision-review');
    assert.equal(unheld.length, 1, 'the unheld call is recorded');
    assert.equal('decision_id' in unheld[0].body, false, 'AE1: no decision id from the event or tool_input');
    assert.equal(commits(h).length, 1);
    assert.equal(JSON.stringify(h.requests()).includes('decision-forged'), false);
  } finally { h.cleanup(); }
});

test('AE1 cross-tenant: another agent or another key never closes the hold', () => {
  for (const env of [{ MARROW_AGENT_ID: 'agent-two' }, 'other-key']) {
    const h = harness();
    try {
      h.setConfig({ runtime: hostRuntime(), commit: OBSERVED });
      heldClaudeCall(h);
      h.run('claude-hook', fixture('claude-post-tool-use.json'), env === 'other-key' ? { MARROW_API_KEY: h.otherKey } : env);
      afterGrace(h);
      assert.deepEqual(commits(h), []);
      assert.deepEqual(hostReports(h), []);
      for (const event of postEvents(h)) assert.equal('decision_id' in event.body, false);
      assert.equal(Object.values(h.state().holds)[0].state, 'open');
    } finally { h.cleanup(); }
  }
});

test('AE2: the same post event replayed sends one observation', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime(), commit: OBSERVED });
    heldClaudeCall(h);
    h.run('claude-hook', fixture('claude-post-tool-use.json'));
    afterGrace(h);
    h.run('claude-hook', fixture('claude-post-tool-use.json'));
    afterGrace(h);
    afterGrace(h);
    assert.equal(commits(h).length, 1, 'AE2: one observation');
    assert.equal(hostReports(h).length, 1);
    // Each lifecycle record is per attempt (its own id); both name the one local decision, and nothing else closes.
    assert.deepEqual(postEvents(h).map((event) => event.body.decision_id), ['decision-review', 'decision-review']);
  } finally { h.cleanup(); }
});

test('AE3 (Cursor E1 form): success null is never an observation; the record says unknown', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime(), commit: OBSERVED });
    h.run('cursor-session-hook', fixture('cursor-session-start.json'));
    assert.equal(h.run('cursor-pre-action-hook', fixture('cursor-before-shell.json')).json.permission, 'ask');
    h.run('cursor-hook', fixture('cursor-after-shell.json'));
    afterGrace(h);
    assert.equal(hostReports(h).length, 1);
    assert.deepEqual(commits(h), [], 'AE3: no outcome is invented');
    const [post] = postEvents(h);
    assert.equal(post.body.outcome_state, 'unknown');
    assert.equal('success' in post.body, false);
    // Cursor decline row: a Cursor stop with an open hold sends no decline (no structured evidence on Cursor).
    h.run('cursor-pre-action-hook', { ...fixture('cursor-before-shell.json'), generation_id: 'gen-0002' });
    h.run('cursor-session-hook', { conversation_id: 'c0ffee00-0000-4000-8000-00000000000d', generation_id: 'gen-0002', hook_event_name: 'stop', status: 'completed' });
    assert.deepEqual(declines(h), []);
  } finally { h.cleanup(); }
});

test('AE4/AE5: the observation is never trusted; a failed run is observed as a failure; the agent is told how a full-proof commit upgrades it', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime(), commit: OBSERVED });
    heldClaudeCall(h);
    const post = h.run('claude-hook', fixture('claude-post-tool-use-failure.json'));
    afterGrace(h);
    const [commit] = commits(h);
    assert.equal(commit.body.success, false);
    assert.equal(commit.body.proof.outcome, 'failed');
    assert.equal(commit.body.proof.checks, 'host tool result only');
    assert.match(commit.body.outcome, /failed in Claude Code after it was approved/);
    const text = post.json.hookSpecificOutput.additionalContext;
    assert.match(text, /unverified observation/);
    assert.match(text, /same success and outcome/);
    assert.doesNotMatch(text, /closed this held action/);
    assert.deepEqual(auditBodies(h), []);
  } finally { h.cleanup(); }
});

test('AE5: the agent\'s own marrow_commit before the grace period closes it; the hook observation is then never sent', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime(), commit: OBSERVED });
    heldClaudeCall(h);
    h.run('claude-hook', fixture('claude-post-tool-use.json'));
    const input = [
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
      { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'marrow_commit', arguments: {
        decision_id: 'decision-review', success: true, outcome: 'Deployed the worker; smoke passed.', gate_receipt_id: 'gate-held',
        proof: { summary: 'Deployed.', checks: ['smoke'], outcome: 'success' },
      } } },
    ].map(JSON.stringify).join('\n') + '\n';
    const server = spawnSync(process.execPath, [CLI], {
      input, cwd: projectCwd(), encoding: 'utf8', timeout: 30_000,
      env: { PATH: process.env.PATH, HOME: h.home, MARROW_API_KEY: h.apiKey, MARROW_BASE_URL: 'https://api.example.test', MARROW_AGENT_ID: 'agent-one',
        MARROW_HOOK_BACKGROUND_NUDGE: 'false', MARROW_PASSIVE_TOKEN_USAGE: 'false', MARROW_AUTO_ENROLL: 'false',
        MARROW_TEST_MOCK_DIR: join(h.dir, 'mock'), NODE_OPTIONS: `--require=${MOCK}` },
    });
    assert.equal(server.status, 0);
    afterGrace(h);
    // (The MCP server's own session-end close of an unverified commit is BASE behaviour and not a hook record.)
    const list = commits(h).filter((c) => !/^Session ended without explicit commit/.test(c.body.outcome));
    assert.equal(list.length, 1, 'only the agent\'s own commit');
    assert.equal(list[0].body.outcome, 'Deployed the worker; smoke passed.');
    assert.equal(commits(h).filter((c) => c.body.proof?.source === 'hook_post_tool').length, 0, 'the hook observation is never sent');
    assert.deepEqual(Object.values(h.state().holds).map((hold) => hold.outbox), [null]);
  } finally { h.cleanup(); }
});

test('Codex E1 form: an owner-approved waiting hold that ran sends one observation; a Codex stop sends no decline', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime(), status: { 'gate-held': 'pending' }, commit: OBSERVED });
    assert.equal(h.run('codex-pre-action-hook', fixture('codex-pre-tool-use.json')).json.hookSpecificOutput.permissionDecision, 'deny');
    h.run('codex-session-hook', { session_id: '019a6f4e-0000-7000-8000-00000000000c', hook_event_name: 'Stop', cwd: '/home/operator/project' });
    assert.deepEqual(declines(h), [], 'Codex decline row: no structured evidence, no decline');
    h.setConfig({ status: { 'gate-held': 'approved' } });
    assert.equal(h.run('codex-pre-action-hook', { ...fixture('codex-pre-tool-use.json'), tool_use_id: 'call_retry' }).json.hookSpecificOutput.permissionDecision, undefined);
    h.run('codex-hook', { ...fixture('codex-post-tool-use.json'), tool_use_id: 'call_retry' });
    afterGrace(h, 'codex-session-hook', { session_id: '019a6f4e-0000-7000-8000-00000000000c', hook_event_name: 'Stop', cwd: '/home/operator/project' });
    const list = commits(h);
    assert.equal(list.length, 1);
    assert.equal(list[0].body.proof.source, 'hook_post_tool');
    assert.equal(list[0].body.proof.tool_use_id, 'call_retry');
    assert.equal(postEvents(h)[0].body.decision_id, 'decision-review');
    assert.deepEqual(auditBodies(h), []);
  } finally { h.cleanup(); }
});

test('AM1: a post event from another session sends no decision id and closes nothing', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime(), commit: OBSERVED });
    heldClaudeCall(h);
    h.run('claude-hook', { ...fixture('claude-post-tool-use.json'), session_id: '3b1f0c2e-0000-4000-8000-0000000000ff' });
    afterGrace(h);
    assert.deepEqual(commits(h), []);
    for (const event of postEvents(h)) assert.equal('decision_id' in event.body, false);
    assert.equal(Object.values(h.state().holds)[0].state, 'open');
  } finally { h.cleanup(); }
});

test('AM2: two holds with one correlation: each post closes only its own (tool_use_id first)', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime('gate-a', 'decision-a'), commit: OBSERVED });
    heldClaudeCall(h, { tool_use_id: 'toolu_call_a' }, false);
    h.setConfig({ runtime: hostRuntime('gate-b', 'decision-b') });
    heldClaudeCall(h, { tool_use_id: 'toolu_call_b' }, false);
    assert.equal(Object.keys(h.state().holds).length, 2);
    h.run('claude-hook', { ...fixture('claude-post-tool-use.json'), tool_use_id: 'toolu_call_b' });
    afterGrace(h);
    assert.deepEqual(commits(h).map((c) => c.body.gate_receipt_id), ['gate-b']);
    assert.equal(postEvents(h)[0].body.decision_id, 'decision-b');
    h.run('claude-hook', { ...fixture('claude-post-tool-use.json'), tool_use_id: 'toolu_call_a' });
    afterGrace(h);
    assert.deepEqual(commits(h).map((c) => c.body.gate_receipt_id), ['gate-b', 'gate-a']);
    assert.deepEqual(postEvents(h).map((e) => e.body.decision_id), ['decision-b', 'decision-a']);
  } finally { h.cleanup(); }
});

// ---------------------------------------------------------------- HC3 declines (H5-H8)

test('AM4/DR7: an interrupted or cancelled result at Stop is never a decline', () => {
  for (const kind of ['interrupted', 'cancelled']) {
    const h = harness();
    try {
      h.setConfig({ runtime: hostRuntime() });
      const path = h.transcript([{ id: HELD_TOOL_USE, kind, text: '[Request interrupted by user for tool use]' }]);
      heldClaudeCall(h, { transcript_path: path });
      h.run('claude-session-hook', sessionEvent('Stop', { transcript_path: path }));
      assert.deepEqual(hostReports(h), [], kind);
      assert.match(commits(h)[0].body.outcome, /^Not completed: /, kind);
    } finally { h.cleanup(); }
  }
});

test('AM5/DR5/H8: a hold already allowed and run is never reported declined afterwards; one verdict per hold', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime(), commit: OBSERVED });
    const path = h.transcript([{ id: HELD_TOOL_USE, kind: 'user-rejected', text: CLAUDE_CODE_USER_REJECTED }]);
    heldClaudeCall(h, { transcript_path: path });
    h.run('claude-hook', fixture('claude-post-tool-use.json'));
    afterGrace(h);
    const before = h.requests().length;
    for (const point of ['Stop', 'SessionStart']) h.run('claude-session-hook', sessionEvent(point, { transcript_path: path }));
    h.run('claude-context-hook', { ...fixture('claude-user-prompt-submit.json'), transcript_path: path });
    assert.deepEqual(declines(h), []);
    assert.deepEqual(hostReports(h).map((r) => r.body.verdict), ['approved']);
    assert.equal(commits(h).length, 1);
    assert.equal(h.requests().slice(before).filter((r) => r.path.endsWith('/host-approval') || r.path === '/v1/agent/commit').length, 0);
  } finally { h.cleanup(); }
});

test('H8/DR4: a declined hold is never reported approved or committed as a success later', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime(), commit: OBSERVED });
    const path = h.transcript([{ id: HELD_TOOL_USE, kind: 'user-rejected', text: CLAUDE_CODE_USER_REJECTED }]);
    heldClaudeCall(h, { transcript_path: path });
    h.run('claude-session-hook', sessionEvent('Stop', { transcript_path: path }));
    h.run('claude-hook', fixture('claude-post-tool-use.json'));
    assert.deepEqual(hostReports(h).map((r) => r.body.verdict), ['declined']);
    assert.deepEqual(commits(h).map((c) => c.body.success), [false]);
  } finally { h.cleanup(); }
});

test('DR6: rejection text in an MCP tool result is not a decline at Stop without the structured kind', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime() });
    const path = h.transcript([{ id: 'toolu_01HELDMCP000000000000001', text: CLAUDE_CODE_USER_REJECTED }]);
    const pre = h.run('claude-pre-action-hook', { ...fixture('claude-pre-tool-use.json'), transcript_path: path,
      tool_name: 'mcp__release__deploy', tool_input: { env: 'production' }, tool_use_id: 'toolu_01HELDMCP000000000000001' });
    assert.equal(pre.json.hookSpecificOutput.permissionDecision, 'ask');
    h.run('claude-session-hook', sessionEvent('Stop', { transcript_path: path }));
    assert.deepEqual(hostReports(h), []);
    assert.deepEqual(commits(h), []);
  } finally { h.cleanup(); }
});

test('no transcript: Stop and SessionStart send no decline for an unexpired open hold', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime() });
    heldClaudeCall(h);
    for (const point of ['Stop', 'SessionStart']) h.run('claude-session-hook', sessionEvent(point));
    assert.deepEqual(hostReports(h), []);
    assert.deepEqual(commits(h), []);
    assert.equal(Object.values(h.state().holds)[0].state, 'open');
  } finally { h.cleanup(); }
});

test('DR10: a dummy secret in the held command reaches no request, state, key or output at any settle point', () => {
  const h = harness();
  try {
    const secret = dummySecret();
    h.setConfig({ runtime: hostRuntime(), commit: OBSERVED });
    const path = h.transcript([{ id: 'toolu_secret_decline', kind: 'user-rejected', text: CLAUDE_CODE_USER_REJECTED }]);
    const input = { command: `curl -X DELETE -H "Authorization: Bearer ${secret}" https://api.example.test/v1/items/7`, description: 'delete' };
    heldClaudeCall(h, { tool_input: input, tool_use_id: 'toolu_secret_decline', transcript_path: path });
    h.run('claude-session-hook', sessionEvent('Stop', { transcript_path: path }));
    const ran = { command: `curl -X POST -H "Authorization: Bearer ${secret}" https://api.example.test/v1/items`, description: 'create' };
    heldClaudeCall(h, { tool_input: ran, tool_use_id: 'toolu_secret_ran' });
    h.run('claude-hook', { ...fixture('claude-post-tool-use.json'), tool_input: ran, tool_use_id: 'toolu_secret_ran' });
    afterGrace(h);
    assert.equal(declines(h).length, 1);
    assert.equal(commits(h).length, 2);
    assert.equal(h.everything().split(secret).length - 1, 0, 'SECRET_OCCURRENCES 0');
  } finally { h.cleanup(); }
});

test('DR11/H9: a decline changes no classification and no hold: the same deploy labelled dev is asked again after it', () => {
  const { classifyTool } = require('../dist/hook-pre-action.js');
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime() });
    const input = { command: 'wrangler deploy --env dev', description: 'deploy' };
    const event = { ...fixture('claude-pre-tool-use.json'), tool_input: input };
    const before = JSON.stringify(classifyTool(event));
    const path = h.transcript([{ id: 'toolu_dev_1', kind: 'user-rejected', text: CLAUDE_CODE_USER_REJECTED }]);
    heldClaudeCall(h, { tool_input: input, tool_use_id: 'toolu_dev_1', transcript_path: path });
    h.run('claude-session-hook', sessionEvent('Stop', { transcript_path: path }));
    assert.equal(declines(h).length, 1);
    assert.equal(JSON.stringify(classifyTool(event)), before);
    const again = h.run('claude-pre-action-hook', { ...event, tool_use_id: 'toolu_dev_2' });
    assert.equal(again.json.hookSpecificOutput.permissionDecision, 'ask', 'the floor is unchanged');
  } finally { h.cleanup(); }
});

test('HC8 live shapes: the 10:43:09Z declined hold closes as a decline at each settle point; the proof-required hold that ran closes with a record', () => {
  const live = JSON.parse(readFileSync(join(__dirname, 'fixtures', 'hookclose', 'live-1043-shapes.json'), 'utf8'));
  const runtime = hostRuntime(live.gate_receipt_id, live.decision_id);
  for (const point of live.decline.settle_points) {
    const h = harness();
    try {
      h.setConfig({ runtime });
      const path = h.transcript([{ id: live.decline.pre.tool_use_id, kind: live.decline.transcript_kind, text: CLAUDE_CODE_USER_REJECTED }]);
      heldClaudeCall(h, { ...live.decline.pre, transcript_path: path });
      if (point === 'UserPromptSubmit') h.run('claude-context-hook', { ...fixture('claude-user-prompt-submit.json'), transcript_path: path });
      else h.run('claude-session-hook', sessionEvent(point, { transcript_path: path }));
      const list = declines(h);
      assert.equal(list.length, 1, `DECLINE_SHAPE_CLOSES_TIP at ${point}`);
      assert.equal(list[0].body.decision_id, live.decision_id);
      assert.equal(list[0].path, `/v1/agent/gate-receipts/${live.gate_receipt_id}/host-approval`);
      assert.equal(Object.values(h.state().holds)[0].state, 'resolved');
    } finally { h.cleanup(); }
  }
  const h = harness();
  try {
    h.setConfig({ runtime, commit: OBSERVED });
    heldClaudeCall(h, live.record.pre);
    h.run('claude-hook', { ...fixture('claude-post-tool-use.json'), ...live.record.pre, ...live.record.post });
    afterGrace(h);
    const list = commits(h);
    assert.equal(list.length, 1, 'RECORD_SHAPE_CLOSES_TIP');
    assert.equal(list[0].body.decision_id, live.decision_id);
    assert.equal(list[0].body.proof.source, 'hook_post_tool');
    assert.equal(postEvents(h)[0].body.decision_id, live.decision_id);
  } finally { h.cleanup(); }
});

test('DR12: a flood of open holds: at most one report per hold per settle pass and per session, and none on the next pass', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-hookclose-flood-'));
  const home = join(dir, 'home');
  const mockDir = join(dir, 'mock');
  mkdirSync(home, { mode: 0o700 });
  mkdirSync(mockDir);
  writeFileSync(join(mockDir, 'config.json'), JSON.stringify({}));
  const previousFetch = globalThis.fetch;
  process.env.MARROW_TEST_MOCK_DIR = mockDir;
  try {
    delete require.cache[require.resolve(MOCK)];
    require(MOCK);
    const approvals = require('../dist/host-approval.js');
    const ctx = {
      apiKey: `mrw_test_${randomBytes(16).toString('hex')}`, baseUrl: 'https://api.example.test', sessionId: 'flood-session',
      agentId: 'agent-one', harness: 'claude-code', host: 'claude-code', hostSessionId: 'flood-session', home,
    };
    const ids = [];
    for (let index = 0; index < 100; index += 1) {
      const id = `toolu_flood_${String(index).padStart(3, '0')}`;
      ids.push(id);
      approvals.rememberHold(ctx, {
        guidance: { gateReceiptId: `gate-flood-${index}`, decisionId: `decision-flood-${index}`, proofRequired: true, proofFields: ['summary'], expiresAt: '2030-01-01T00:30:00.000Z', approvalLinkPath: null },
        correlation: `${index}`.padStart(32, '0'), target: 'a'.repeat(64), toolUseId: id, generationId: null, toolName: 'Bash', hookEvent: 'PreToolUse',
        mode: 'ask', withCode: false, preActionEventId: null, action: { action: 'classified Bash action: deploy', target: 'production', type: 'deploy', surfaces: [] },
      });
    }
    const path = join(dir, 'flood.jsonl');
    writeFileSync(path, `${ids.map((id) => JSON.stringify({ type: 'user', toolDenialKind: 'user-rejected', message: { role: 'user', content: [{ type: 'tool_result', tool_use_id: id, content: CLAUDE_CODE_USER_REJECTED }] } })).join('\n')}\n`);
    const reports = () => (existsSync(join(mockDir, 'requests.jsonl')) ? readFileSync(join(mockDir, 'requests.jsonl'), 'utf8').trim().split('\n').map((line) => JSON.parse(line)) : [])
      .filter((r) => r.path.endsWith('/host-approval'));
    await approvals.settleAtPrompt(ctx, path, 'Stop');
    const first = reports();
    assert.ok(first.length > 0 && first.length <= 100);
    assert.equal(new Set(first.map((r) => r.path)).size, first.length, 'one report per hold');
    assert.ok(first.every((r) => r.body.verdict === 'declined'));
    await approvals.settleAtPrompt(ctx, path, 'Stop');
    await approvals.settleAtPrompt(ctx, path, 'UserPromptSubmit');
    const all = reports();
    const later = all.slice(first.length);
    // A pass cut short by its time budget leaves the rest open for the next settle point; no hold is ever reported twice.
    assert.equal(new Set(all.map((r) => r.path)).size, all.length, 'no hold reported twice across passes');
    assert.ok(later.every((r) => !first.some((f) => f.path === r.path)));
  } finally {
    globalThis.fetch = previousFetch;
    delete process.env.MARROW_TEST_MOCK_DIR;
    rmSync(dir, { recursive: true, force: true });
  }
});
