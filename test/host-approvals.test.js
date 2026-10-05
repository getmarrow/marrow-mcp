const assert = require('node:assert/strict');
const test = require('node:test');
const { spawnSync } = require('node:child_process');
const { randomBytes } = require('node:crypto');
const { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const {
  CLAUDE_CODE_NOT_A_DECISION_PREFIXES,
  CLAUDE_CODE_USER_REJECTED,
  CLAUDE_CODE_USER_REJECTED_WITH_FEEDBACK,
  classifyClaudeToolResult,
  parseTypedReply,
} = require('../dist/host-approval.js');
const { ordinaryApprovalGuidance } = require('../dist/runtime-contract.js');
const { normalizeRuntimeResult } = require('../dist/runtime-contract.js');
const { installPermissionRequestHook } = require('../dist/hook.js');
const { PERMISSION_REQUEST_HOOK_COMMAND, ACTION_RESULT_HOOK_COMMAND, NATIVE_HOOK_MATCHER } = require('../dist/hook-contract.js');

// Each host event runs as its own hook process, as a real host runs it, with a
// shared temporary HOME and a scripted Marrow API (test/support/host-approval-fetch-mock.cjs).
// Payloads (test/fixtures/host-approvals) follow the hosts' hook documentation fetched
// 2026-10-05; they were not captured from live host sessions. The Claude Code
// rejection and interruption texts are pinned from the Claude Code 2.1.289 bundle.
const CLI = join(__dirname, '..', 'dist', 'cli.js');
const MOCK = join(__dirname, 'support', 'host-approval-fetch-mock.cjs');
const FIXTURES = join(__dirname, 'fixtures', 'host-approvals');
const fixture = (name) => JSON.parse(readFileSync(join(FIXTURES, name), 'utf8'));

function hostRuntime(receipt = 'gate-held', approval = {}, extra = {}) {
  return {
    ok: true,
    action: 'classified Bash action: deploy on production',
    decision_id: 'decision-review',
    runtime_authorization: { id: receipt, kind: 'durable_gate_receipt', durable: true, decision_state: 'created', decision_creation_required: false, decision_id: 'decision-review' },
    gate_receipt: { id: receipt, decision: 'review_required', required: true, owner_approval_required: true, expires_at: '2030-01-01T00:30:00.000Z' },
    proof_pack: { required: true, fields: ['summary', 'checks', 'outcome', 'blockers', 'commits_prs_shas', 'rollback_target', 'handoff_result_file', 'deployment_and_smoke'], complete: false },
    completion_contract: {
      decision_id: 'decision-review', decision_creation_required: false, decision_state: 'created',
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
        ...approval,
      },
    },
    risk_gate: { allow: true, decision: 'review_required', enforced: true, gate_required: true, gate_receipt_id: receipt, risk_level: 'high', reasons: [{ message: 'Production deploys need approval.' }] },
    gate_receipt_id: receipt,
    exact_next_action: 'Obtain explicit owner approval before this action runs.',
    ...extra,
  };
}

function noProofRuntime(receipt = 'gate-held') {
  const runtime = hostRuntime(receipt);
  runtime.proof_pack = { required: false, fields: [], complete: true };
  return runtime;
}

function harness() {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-host-approvals-'));
  const home = join(dir, 'home');
  const mockDir = join(dir, 'mock');
  mkdirSync(home, { mode: 0o700 });
  mkdirSync(mockDir);
  // A dummy key generated for this run; it never leaves the mock.
  const apiKey = `mrw_test_${randomBytes(16).toString('hex')}`;
  let config = {};
  const setConfig = (next) => { config = { ...config, ...next }; writeFileSync(join(mockDir, 'config.json'), JSON.stringify(config)); };
  const requests = () => {
    const path = join(mockDir, 'requests.jsonl');
    return existsSync(path) ? readFileSync(path, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line)) : [];
  };
  const run = (entrypoint, payload, env = {}) => {
    const result = spawnSync(process.execPath, entrypoint === 'marrow-mcp-server-placeholder' ? [CLI] : [CLI, entrypoint], {
      input: typeof payload === 'string' ? payload : JSON.stringify(payload),
      env: {
        PATH: process.env.PATH, HOME: home, MARROW_API_KEY: apiKey, MARROW_BASE_URL: 'https://api.example.test',
        MARROW_AGENT_ID: 'agent-one', MARROW_HOOK_BACKGROUND_NUDGE: 'false', MARROW_PASSIVE_TOKEN_USAGE: 'false',
        MARROW_TEST_MOCK_DIR: mockDir, NODE_OPTIONS: `--require=${MOCK}`, ...env,
      },
      encoding: 'utf8',
      timeout: 30_000,
    });
    assert.equal(result.error, undefined);
    const output = result.stdout.trim();
    assert.equal(output.includes(apiKey) || result.stderr.includes(apiKey), false, 'the key never appears in hook output');
    let json = null;
    try { json = output ? JSON.parse(output) : null; } catch { json = null; }
    return { status: result.status, stdout: output, stderr: result.stderr, json };
  };
  const transcript = (name) => {
    const target = join(dir, name);
    copyFileSync(join(FIXTURES, name), target);
    return target;
  };
  const state = () => {
    const path = join(home, '.marrow', 'host-approvals', 'state.json');
    return existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : null;
  };
  return { dir, home, run, setConfig, requests, transcript, state, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

const hostReports = (h) => h.requests().filter((r) => r.path.endsWith('/host-approval'));
const commits = (h) => h.requests().filter((r) => r.path === '/v1/agent/commit');
// Pre-action gates only (a prompt hook may also ask the runtime for a brief).
const runtimes = (h) => h.requests().filter((r) => r.path === '/v1/agent/runtime' && /^classified \S+ action: /.test(r.body?.action || ''));

// ---------------------------------------------------------------- Claude Code

test('Claude Code texts are pinned to the 2.1.289 bundle', () => {
  assert.equal(CLAUDE_CODE_USER_REJECTED, "The user doesn't want to proceed with this tool use. The tool use was rejected (eg. if it was a file edit, the new_string was NOT written to the file). STOP what you are doing and wait for the user to tell you how to proceed.");
  assert.equal(CLAUDE_CODE_USER_REJECTED_WITH_FEEDBACK, "The user doesn't want to proceed with this tool use. The tool use was rejected (eg. if it was a file edit, the new_string was NOT written to the file). To tell you how to proceed, the user said:\n");
  assert.ok(CLAUDE_CODE_NOT_A_DECISION_PREFIXES.includes('[Request interrupted by user'));
  // When a Claude Code bundle is available, every pinned text must still be in it.
  const bundle = process.env.MARROW_TEST_CLAUDE_CODE_BUNDLE;
  if (bundle && existsSync(bundle)) {
    const bytes = readFileSync(bundle);
    for (const text of [CLAUDE_CODE_USER_REJECTED, CLAUDE_CODE_USER_REJECTED_WITH_FEEDBACK.replace('\n', '\\n'), ...CLAUDE_CODE_NOT_A_DECISION_PREFIXES]) {
      assert.ok(bytes.includes(Buffer.from(text)), `missing from the Claude Code bundle: ${text.slice(0, 60)}`);
    }
  }
});

test('Claude Code results: only a permission rejection is a decline; interruptions and other denials are not', () => {
  const bash = (text, extra = {}) => classifyClaudeToolResult({ toolName: 'Bash', text, ...extra });
  assert.equal(bash(CLAUDE_CODE_USER_REJECTED), 'declined');
  assert.equal(bash(`${CLAUDE_CODE_USER_REJECTED}\n`), 'declined');
  assert.equal(bash(`${CLAUDE_CODE_USER_REJECTED_WITH_FEEDBACK}use staging`), 'declined');
  for (const text of [
    '[Request interrupted by user]',
    '[Request interrupted by user for tool use]',
    '[Tool call did not complete: the turn was ended to deliver the message that follows. Nothing refused it; re-run it if still needed.]',
    "[Tool call not completed: an approval request was still unanswered when the message that follows arrived and was closed, so the action awaiting approval did not run. Nobody refused it, so this is not the user's decision; ask again if it is still needed.]",
    '[Tool call interrupted: the session ended before this call\'s result was recorded, so its outcome is unknown. Check whether it took effect before relying on it or running it again.]',
  ]) assert.equal(bash(text), 'interrupted', text);
  // A hook, rule, dontAsk, an SDK host or the auto-mode classifier: not the operator.
  assert.equal(bash('Permission for this tool use was denied. The tool use was rejected (eg. if it was a file edit, the new_string was NOT written to the file). Try a different approach or report the limitation to complete your task.'), 'unknown');
  assert.equal(bash('Claude requested permissions to use Bash, but you haven\'t granted it yet.'), 'unknown');
  assert.equal(bash(`prefix ${CLAUDE_CODE_USER_REJECTED}`), 'unknown');
  assert.equal(bash(null), 'unknown');
  // Structured transcript kinds win; MCP tools author their own text, so text alone never counts for them.
  assert.equal(classifyClaudeToolResult({ toolName: 'mcp__release__deploy', text: CLAUDE_CODE_USER_REJECTED }), 'unknown');
  assert.equal(classifyClaudeToolResult({ toolName: 'mcp__release__deploy', text: 'anything', denialKind: 'user-rejected' }), 'declined');
  assert.equal(bash(CLAUDE_CODE_USER_REJECTED, { denialKind: 'permission-rule' }), 'unknown');
  assert.equal(bash(CLAUDE_CODE_USER_REJECTED, { denialKind: 'automode-blocked' }), 'unknown');
  assert.equal(bash('x', { denialKind: 'cancelled' }), 'interrupted');
  assert.equal(bash('x', { unanswered: 'stream-closed' }), 'interrupted');
});

test('Claude Code allow: one click in the host dialog is reported with the PermissionRequest marker, and the agent closes it with proof', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime() });
    const pre = h.run('claude-pre-action-hook', fixture('claude-pre-tool-use.json'));
    assert.equal(pre.json.hookSpecificOutput.permissionDecision, 'ask');
    assert.match(pre.json.hookSpecificOutput.permissionDecisionReason, /^Marrow holds this action for your approval\./);
    // The pass-through hook only notes the dialog; it never answers it.
    const dialog = h.run('claude-permission-request-hook', fixture('claude-permission-request.json'));
    assert.equal(dialog.status, 0);
    assert.equal(dialog.stdout, '');
    const post = h.run('claude-hook', fixture('claude-post-tool-use.json'));
    const [report] = hostReports(h);
    assert.ok(report, 'the click was reported');
    assert.equal(report.path, '/v1/agent/gate-receipts/gate-held/host-approval');
    assert.deepEqual(Object.keys(report.body).sort(), ['answered_at', 'asked_at', 'decision_id', 'hook_event', 'host', 'host_session_id', 'pre_action_event_id', 'verdict']);
    assert.equal(report.body.verdict, 'approved');
    assert.equal(report.body.host, 'claude-code');
    assert.equal(report.body.hook_event, 'PermissionRequest');
    assert.equal(report.body.host_session_id, '3b1f0c2e-0000-4000-8000-00000000000a');
    assert.equal(report.body.decision_id, 'decision-review');
    assert.match(report.body.pre_action_event_id, /^pretool-[a-f0-9]{32}$/);
    assert.ok(Date.parse(report.body.answered_at) >= Date.parse(report.body.asked_at));
    assert.equal(report.session, '3b1f0c2e-0000-4000-8000-00000000000a');
    // Proof is required: the hook never commits without it (that would block the trusted close).
    assert.deepEqual(commits(h), []);
    const context = post.json.hookSpecificOutput;
    assert.equal(context.hookEventName, 'PostToolUse');
    assert.match(context.additionalContext, /^Marrow recorded the approval of this held action \(client-attested\)\. Close it with marrow_commit: decision_id decision-review, gate_receipt_id gate-held, the real success and outcome, and proof with summary, checks, outcome/);
    assert.equal(h.requests().filter((r) => r.path === '/v1/agent/runtime').length, 1, 'one runtime gate for the whole flow');
  } finally { h.cleanup(); }
});

test('Claude Code allow without the dialog marker is reported as the asking event (labelled an allow rule by the server)', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime() });
    h.run('claude-pre-action-hook', fixture('claude-pre-tool-use.json'));
    h.run('claude-hook', fixture('claude-post-tool-use.json'));
    const [report] = hostReports(h);
    assert.equal(report.body.hook_event, 'PreToolUse');
  } finally { h.cleanup(); }
});

test('Claude Code allow of a hold that needs no proof closes trusted with no other step', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: noProofRuntime() });
    h.run('claude-pre-action-hook', fixture('claude-pre-tool-use.json'));
    h.run('claude-permission-request-hook', fixture('claude-permission-request.json'));
    const post = h.run('claude-hook', fixture('claude-post-tool-use.json'));
    const order = h.requests().map((r) => r.path).filter((path) => !path.endsWith('/integrations/events'));
    assert.deepEqual(order, ['/v1/agent/runtime', '/v1/agent/gate-receipts/gate-held/host-approval', '/v1/agent/commit']);
    const [commit] = commits(h);
    assert.equal(commit.body.gate_receipt_id, 'gate-held');
    assert.equal(commit.body.decision_id, 'decision-review');
    assert.equal(commit.body.success, true);
    assert.equal(commit.body.proof, undefined);
    assert.match(commit.idempotency_key, /^mcp-host-approval:[a-f0-9]{40}$/);
    assert.match(post.json.hookSpecificOutput.additionalContext, /^Marrow recorded the approval \(client-attested\) and closed this held action on gate receipt gate-held\./);
  } finally { h.cleanup(); }
});

test('Claude Code allow of a call that then failed reports the approval and commits the failure', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: noProofRuntime() });
    h.run('claude-pre-action-hook', fixture('claude-pre-tool-use.json'));
    h.run('claude-hook', fixture('claude-post-tool-use-failure.json'));
    assert.equal(hostReports(h)[0].body.verdict, 'approved');
    assert.equal(commits(h)[0].body.success, false);
    assert.match(commits(h)[0].body.outcome, /failed in Claude Code after it was approved/);
  } finally { h.cleanup(); }
});

test('Claude Code decline: a permission rejection at PostToolBatch records a decline and closes a verified denial', () => {
  for (const batch of ['claude-post-tool-batch-rejected.json', 'claude-post-tool-batch-rejected-feedback.json']) {
    const h = harness();
    try {
      h.setConfig({ runtime: hostRuntime() });
      h.run('claude-pre-action-hook', fixture('claude-pre-tool-use.json'));
      h.run('claude-permission-request-hook', fixture('claude-permission-request.json'));
      const out = h.run('claude-hook', fixture(batch));
      assert.equal(out.stdout, '', 'the batch hook adds nothing for the model');
      const [report] = hostReports(h);
      assert.equal(report.body.verdict, 'declined');
      assert.equal(report.body.hook_event, 'PostToolBatch');
      const [commit] = commits(h);
      assert.equal(commit.body.success, false);
      assert.equal(commit.body.gate_receipt_id, 'gate-held');
      assert.equal(commit.body.outcome, 'Denied by Marrow pre-action gate: the operator declined in Claude Code (gate receipt gate-held).');
      assert.equal(commit.body.proof, undefined);
    } finally { h.cleanup(); }
  }
});

test('Claude Code interruption is never a decline: no report, and the observed outcome stays unverified', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime() });
    h.run('claude-pre-action-hook', fixture('claude-pre-tool-use.json'));
    h.run('claude-hook', fixture('claude-post-tool-batch-interrupted.json'));
    assert.deepEqual(hostReports(h), []);
    const [commit] = commits(h);
    assert.equal(commit.body.success, false);
    assert.match(commit.body.outcome, /^Not completed: the call was interrupted, cancelled or left unanswered in Claude Code before Marrow recorded an answer/);
    assert.doesNotMatch(commit.body.outcome, /^Denied by Marrow/);
  } finally { h.cleanup(); }
});

test('Claude Code: an unknown denial text (a rule, a hook, an SDK host) reports nothing and commits nothing', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime() });
    h.run('claude-pre-action-hook', fixture('claude-pre-tool-use.json'));
    h.run('claude-hook', fixture('claude-post-tool-batch-unknown.json'));
    assert.deepEqual(hostReports(h), []);
    assert.deepEqual(commits(h), []);
  } finally { h.cleanup(); }
});

test('Claude Code UserPromptSubmit fallback reads the transcript when the rejection ended the turn', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime() });
    const transcript = h.transcript('claude-transcript-rejected.jsonl');
    h.run('claude-pre-action-hook', { ...fixture('claude-pre-tool-use.json'), transcript_path: transcript });
    h.run('claude-context-hook', { ...fixture('claude-user-prompt-submit.json'), transcript_path: transcript });
    const [report] = hostReports(h);
    assert.equal(report.body.verdict, 'declined');
    assert.equal(report.body.hook_event, 'UserPromptSubmit');
    assert.match(commits(h)[0].body.outcome, /^Denied by Marrow pre-action gate: the operator declined in Claude Code/);
    // A second prompt does not report it again.
    h.run('claude-context-hook', { ...fixture('claude-user-prompt-submit.json'), transcript_path: transcript });
    assert.equal(hostReports(h).length, 1);
  } finally { h.cleanup(); }
});

test('Claude Code: rejection text from an MCP tool is not a decline without the structured transcript kind', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime() });
    const transcript = h.transcript('claude-transcript-mcp-text-only.jsonl');
    const pre = h.run('claude-pre-action-hook', { ...fixture('claude-pre-tool-use.json'), transcript_path: transcript,
      tool_name: 'mcp__release__deploy', tool_input: { env: 'production' }, tool_use_id: 'toolu_01HELDMCP000000000000001' });
    assert.equal(pre.json.hookSpecificOutput.permissionDecision, 'ask');
    h.run('claude-context-hook', { ...fixture('claude-user-prompt-submit.json'), transcript_path: transcript });
    assert.deepEqual(hostReports(h), []);
    assert.deepEqual(commits(h), []);
  } finally { h.cleanup(); }
});

test('marrow_commit sends a queued host approval for its gate receipt before the commit, in the hold\'s session', () => {
  const h = harness();
  try {
    h.setConfig({
      runtime: hostRuntime(),
      hostApproval: [
        { status: 503, body: { error: 'unavailable', details: { code: 'SERVICE_UNAVAILABLE' } }, headers: { 'retry-after': '60' } },
        { status: 200 },
      ],
    });
    h.run('claude-pre-action-hook', fixture('claude-pre-tool-use.json'));
    h.run('claude-permission-request-hook', fixture('claude-permission-request.json'));
    const post = h.run('claude-hook', fixture('claude-post-tool-use.json'));
    assert.match(post.json.hookSpecificOutput.additionalContext, /Marrow sends the queued approval first/);
    const input = [
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
      { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'marrow_commit', arguments: {
        decision_id: 'decision-review', success: true, outcome: 'Deployed the worker; smoke passed.', gate_receipt_id: 'gate-held',
        proof: { summary: 'Deployed.', checks: ['smoke'], outcome: 'success' },
      } } },
    ].map(JSON.stringify).join('\n') + '\n';
    // The MCP server process does not know Claude Code's session; the hold record links it.
    const server = h.run('marrow-mcp-server-placeholder', input, { MARROW_AUTO_ENROLL: 'false' });
    assert.equal(server.status, 0, server.stderr);
    const order = h.requests().map((r) => r.path).filter((path) => path.endsWith('/host-approval') || path === '/v1/agent/commit');
    assert.deepEqual(order, ['/v1/agent/gate-receipts/gate-held/host-approval', '/v1/agent/gate-receipts/gate-held/host-approval', '/v1/agent/commit']);
    const reports = hostReports(h);
    assert.deepEqual(reports[1].body, reports[0].body);
    assert.equal(reports[1].body.hook_event, 'PermissionRequest');
    assert.equal(commits(h)[0].session, '3b1f0c2e-0000-4000-8000-00000000000a', 'the commit uses the session the receipt was issued to');
  } finally { h.cleanup(); }
});

test('Claude Code never accepts a typed approval', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime() });
    h.run('claude-pre-action-hook', { ...fixture('claude-pre-tool-use.json'), permission_mode: 'bypassPermissions' });
    const held = h.state().holds;
    assert.equal(Object.values(held)[0].code, null, 'no approval code exists for Claude Code');
    h.run('claude-context-hook', { ...fixture('claude-user-prompt-submit.json'), prompt: 'marrow approve ABCDEF' });
    assert.deepEqual(hostReports(h), []);
  } finally { h.cleanup(); }
});

test('Claude Code auto mode asks only when the input proves a version whose hook ask forces the prompt', () => {
  for (const [label, payload, expected] of [
    ['auto with scratchpad_dir (v2.1.257+)', { ...fixture('claude-pre-tool-use.json'), permission_mode: 'auto' }, 'ask'],
    ['auto without version evidence', (() => { const p = { ...fixture('claude-pre-tool-use.json'), permission_mode: 'auto' }; delete p.scratchpad_dir; return p; })(), 'deny'],
    ['plan', { ...fixture('claude-pre-tool-use.json'), permission_mode: 'plan' }, 'deny'],
    ['dontAsk', { ...fixture('claude-pre-tool-use.json'), permission_mode: 'dontAsk' }, 'deny'],
    ['bypassPermissions', { ...fixture('claude-pre-tool-use.json'), permission_mode: 'bypassPermissions' }, 'deny'],
  ]) {
    const h = harness();
    try {
      h.setConfig({ runtime: hostRuntime() });
      const out = h.run('claude-pre-action-hook', payload);
      assert.equal(out.json.hookSpecificOutput.permissionDecision, expected, label);
      if (expected === 'deny') {
        assert.match(out.json.hookSpecificOutput.permissionDecisionReason, /To approve it here, switch Claude Code to its default permission mode and retry this exact action; Claude Code then asks you\./, label);
        assert.doesNotMatch(out.stdout, /dashboard/i, `${label}: the dashboard is never the step to take`);
        assert.deepEqual(commits(h), [], `${label}: a waiting hold is never closed by the hook`);
      }
    } finally { h.cleanup(); }
  }
});

test('a verified-only category and a standing owner decline deny before the tool runs; the request goes to the owner, never to a dashboard login', () => {
  for (const [label, approval, pattern] of [
    ['verified category', { host_approval_accepted: false, verified_approval_required: true, verified_approval_categories: ['production_deploy'], approval_authority: 'authenticated_dashboard_owner' },
      /The account owner approves production_deploy actions personally\. The approval request goes to the account owner\./],
    ['settings unreadable', { host_approval_accepted: false, verified_approval_required: null, approval_authority: 'authenticated_dashboard_owner' },
      /Marrow could not read the account approval settings/],
    ['owner decline stands', { host_approval_accepted: false, host_approval_refusal_reason: 'owner_decline_stands', approval_authority: 'authenticated_dashboard_owner', verified_approval_required: null },
      /The account owner declined this action earlier\. The approval request goes to the account owner\./],
    ['owner decline stands with time', { host_approval_accepted: false, host_approval_refusal_reason: 'owner_decline_stands', owner_declined_at: '2026-10-05T11:00:00.000Z', approval_authority: 'authenticated_dashboard_owner', verified_approval_required: null },
      /The account owner declined this action at 2026-10-05T11:00:00\.000Z\./],
    ['approval state unavailable', { host_approval_accepted: false, host_approval_refusal_reason: 'approval_state_unavailable', approval_authority: 'authenticated_dashboard_owner', verified_approval_required: null },
      /Marrow could not check how this hold can be approved right now\./],
  ]) {
    const h = harness();
    try {
      h.setConfig({ runtime: hostRuntime('gate-held', approval) });
      const out = h.run('claude-pre-action-hook', fixture('claude-pre-tool-use.json'));
      const decision = out.json.hookSpecificOutput;
      assert.equal(decision.permissionDecision, 'deny', label);
      assert.match(decision.permissionDecisionReason, pattern, label);
      assert.match(decision.permissionDecisionReason, /When it is approved, retry this exact action/, label);
      assert.doesNotMatch(out.stdout, /dashboard/i, label);
      assert.deepEqual(commits(h), [], label);
      assert.deepEqual(hostReports(h), [], label);
    } finally { h.cleanup(); }
  }
});

test('a similar decline elsewhere is shown to the operator in the prompt, never to the agent', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime('gate-held', { similar_action_declined_at: '2026-10-05T10:00:00.000Z', operator_notice: 'The account owner declined a similar action at 2026-10-05T10:00:00.000Z.' }) });
    const out = h.run('claude-pre-action-hook', fixture('claude-pre-tool-use.json'));
    assert.equal(out.json.hookSpecificOutput.permissionDecision, 'ask');
    assert.match(out.json.hookSpecificOutput.permissionDecisionReason, /Note: The account owner declined a similar action at 2026-10-05T10:00:00\.000Z\./);
    assert.equal(out.json.hookSpecificOutput.additionalContext, undefined);
  } finally { h.cleanup(); }
});

test('a waiting hold is re-checked on retry: pending denies again, approved runs once, declined starts over', () => {
  const h = harness();
  try {
    const payload = { ...fixture('claude-pre-tool-use.json'), permission_mode: 'dontAsk' };
    h.setConfig({ runtime: hostRuntime('gate-wait'), status: { 'gate-wait': 'pending' } });
    assert.equal(h.run('claude-pre-action-hook', payload).json.hookSpecificOutput.permissionDecision, 'deny');
    const pending = h.run('claude-pre-action-hook', { ...payload, tool_use_id: 'toolu_retry_1' });
    assert.equal(pending.json.hookSpecificOutput.permissionDecision, 'deny');
    assert.match(pending.json.hookSpecificOutput.permissionDecisionReason, /^Marrow is still holding this action for approval \(gate receipt gate-wait\)/);
    assert.equal(runtimes(h).length, 1, 'a pending retry creates no new hold');

    h.setConfig({ status: { 'gate-wait': 'approved' } });
    const approved = h.run('claude-pre-action-hook', { ...payload, tool_use_id: 'toolu_retry_2' });
    assert.equal(approved.json.hookSpecificOutput.permissionDecision, undefined, 'normal host permission rules apply');
    assert.match(approved.json.hookSpecificOutput.additionalContext, /^Marrow: the account owner approved this held action \(gate receipt gate-wait\)\. Run only this exact action/);
    assert.equal(runtimes(h).length, 1);
    const post = h.run('claude-hook', { ...fixture('claude-post-tool-use.json'), tool_use_id: 'toolu_retry_2' });
    assert.deepEqual(hostReports(h), [], 'a dashboard approval is not reported again by the host');
    assert.match(post.json.hookSpecificOutput.additionalContext, /Close it with marrow_commit: decision_id decision-review, gate_receipt_id gate-wait/);

    // The next attempt of the same action starts over with a new hold.
    h.setConfig({ runtime: hostRuntime('gate-next'), status: { 'gate-next': 'declined' } });
    h.run('claude-pre-action-hook', { ...payload, tool_use_id: 'toolu_retry_3' });
    assert.equal(runtimes(h).length, 2);
    h.run('claude-pre-action-hook', { ...payload, tool_use_id: 'toolu_retry_4' });
    const denial = commits(h).find((c) => c.body.gate_receipt_id === 'gate-next');
    assert.match(denial.body.outcome, /^Denied by Marrow pre-action gate: the account owner declined it \(gate receipt gate-next\); the action did not run\.$/);
    assert.equal(runtimes(h).length, 3, 'after a decline the normal flow asks for a fresh gate');
  } finally { h.cleanup(); }
});

test('a rate-limited or unavailable report is queued with backoff and never dropped', () => {
  const h = harness();
  try {
    h.setConfig({
      runtime: noProofRuntime(),
      hostApproval: [
        { status: 429, body: { error: 'Too many host approval reports.', details: { code: 'MARROW_HOST_APPROVAL_RATE_LIMITED', retryable: true } }, headers: { 'retry-after': '0' } },
        { status: 409, body: { error: 'unavailable', details: { code: 'MARROW_OWNER_APPROVAL_STATE_UNAVAILABLE', retryable: true } } },
        { status: 200 },
      ],
    });
    h.run('claude-pre-action-hook', fixture('claude-pre-tool-use.json'));
    h.run('claude-permission-request-hook', fixture('claude-permission-request.json'));
    const post = h.run('claude-hook', fixture('claude-post-tool-use.json'));
    assert.match(post.json.hookSpecificOutput.additionalContext, /the report is queued and retried automatically/);
    assert.deepEqual(commits(h), [], 'nothing is committed before the approval is recorded');
    const queued = Object.values(h.state().holds)[0];
    assert.equal(queued.outbox.report.verdict, 'approved');
    assert.ok(queued.outbox.next_at > Date.now() - 1000, 'backoff is scheduled');

    // Later hooks resend the identical body once due.
    const hold = Object.values(h.state().holds)[0];
    const statePath = join(h.home, '.marrow', 'host-approvals', 'state.json');
    const raw = JSON.parse(readFileSync(statePath, 'utf8'));
    raw.holds[hold.id].outbox.next_at = 0;
    writeFileSync(statePath, JSON.stringify(raw), { mode: 0o600 });
    h.run('claude-context-hook', fixture('claude-user-prompt-submit.json'));
    raw.holds[hold.id] = JSON.parse(readFileSync(statePath, 'utf8')).holds[hold.id];
    if (raw.holds[hold.id] && raw.holds[hold.id].outbox) {
      raw.holds[hold.id].outbox.next_at = 0;
      writeFileSync(statePath, JSON.stringify(raw), { mode: 0o600 });
      h.run('claude-context-hook', fixture('claude-user-prompt-submit.json'));
    }
    const reports = hostReports(h);
    assert.equal(reports.length, 3);
    assert.deepEqual(reports[1].body, reports[0].body, 'the identical spooled body is resent');
    assert.deepEqual(reports[2].body, reports[0].body);
    assert.equal(commits(h).length, 1, 'the outcome is committed after the approval is recorded');
  } finally { h.cleanup(); }
});

test('a refused report after the run commits the real outcome (unverified); a scope mismatch is dropped', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: noProofRuntime(), hostApproval: [{ status: 409, body: { error: 'stands', details: { code: 'MARROW_OWNER_DECLINE_STANDS' } } }] });
    h.run('claude-pre-action-hook', fixture('claude-pre-tool-use.json'));
    const post = h.run('claude-hook', fixture('claude-post-tool-use.json'));
    assert.match(post.json.hookSpecificOutput.additionalContext, /^Marrow could not record an approval for this held action \(MARROW_OWNER_DECLINE_STANDS\)/);
    assert.equal(commits(h).length, 1);
    assert.equal(commits(h)[0].body.success, true);
  } finally { h.cleanup(); }
  const g = harness();
  try {
    g.setConfig({ runtime: noProofRuntime(), hostApproval: [{ status: 403, body: { error: 'scope', details: { code: 'MARROW_HOST_APPROVAL_SCOPE_MISMATCH' } } }] });
    g.run('claude-pre-action-hook', fixture('claude-pre-tool-use.json'));
    g.run('claude-hook', fixture('claude-post-tool-use.json'));
    g.run('claude-context-hook', fixture('claude-user-prompt-submit.json'));
    assert.equal(hostReports(g).length, 1, 'never retried');
    assert.deepEqual(commits(g), []);
  } finally { g.cleanup(); }
  const k = harness();
  try {
    k.setConfig({ runtime: noProofRuntime(), hostApproval: [{ status: 409, body: { error: 'decided', details: { code: 'MARROW_OWNER_APPROVAL_ALREADY_DECIDED', existing_verdict: 'approved' } } }] });
    k.run('claude-pre-action-hook', fixture('claude-pre-tool-use.json'));
    k.run('claude-hook', fixture('claude-post-tool-use.json'));
    assert.equal(commits(k).length, 1, 'an earlier approval of the same receipt: just commit');
  } finally { k.cleanup(); }
});

test('the PermissionRequest marker matches only the same session, tool and input', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime() });
    h.run('claude-pre-action-hook', fixture('claude-pre-tool-use.json'));
    h.run('claude-permission-request-hook', { ...fixture('claude-permission-request.json'), session_id: 'another-session' });
    h.run('claude-permission-request-hook', { ...fixture('claude-permission-request.json'), tool_input: { command: 'wrangler deploy --env staging' } });
    assert.equal(Object.values(h.state().holds)[0].dialog_at, null);
    h.run('claude-permission-request-hook', fixture('claude-permission-request.json'));
    assert.notEqual(Object.values(h.state().holds)[0].dialog_at, null);
  } finally { h.cleanup(); }
});

test('setup installs the pass-through PermissionRequest and PostToolBatch hooks idempotently and keeps the user\'s own hooks', () => {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-permission-install-'));
  try {
    mkdirSync(join(dir, '.claude'));
    const settingsPath = join(dir, '.claude', 'settings.json');
    const own = { type: 'command', command: '/usr/local/bin/my-permission-hook' };
    writeFileSync(settingsPath, JSON.stringify({ hooks: { PermissionRequest: [{ matcher: 'Bash', hooks: [own] }] } }));
    assert.equal(installPermissionRequestHook(dir).installed, true);
    const first = readFileSync(settingsPath, 'utf8');
    assert.equal(installPermissionRequestHook(dir).installed, false);
    assert.equal(readFileSync(settingsPath, 'utf8'), first);
    const settings = JSON.parse(first);
    assert.deepEqual(settings.hooks.PermissionRequest[0], { matcher: 'Bash', hooks: [own] });
    assert.deepEqual(settings.hooks.PermissionRequest[1], { hooks: [{ async: true, type: 'command', command: PERMISSION_REQUEST_HOOK_COMMAND }], matcher: NATIVE_HOOK_MATCHER });
    assert.deepEqual(settings.hooks.PostToolBatch, [{ hooks: [{ async: true, type: 'command', command: ACTION_RESULT_HOOK_COMMAND }] }]);
    assert.match(PERMISSION_REQUEST_HOOK_COMMAND, /marrow-mcp claude-permission-request-hook$/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('the local hold store is owner-only, holds no command text, and drops a record it cannot read', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime() });
    h.run('claude-pre-action-hook', fixture('claude-pre-tool-use.json'));
    const statePath = join(h.home, '.marrow', 'host-approvals', 'state.json');
    const { statSync } = require('node:fs');
    assert.equal(statSync(statePath).mode & 0o777, 0o600);
    assert.equal(statSync(join(h.home, '.marrow', 'host-approvals')).mode & 0o777, 0o700);
    const raw = readFileSync(statePath, 'utf8');
    assert.doesNotMatch(raw, /wrangler deploy|Deploy the worker/, 'no command or tool input is stored');
    const state = JSON.parse(raw);
    state.holds.hold_000000000000000000000000 = { id: 'hold_000000000000000000000000', broken: true };
    writeFileSync(statePath, JSON.stringify(state), { mode: 0o600 });
    h.run('claude-permission-request-hook', fixture('claude-permission-request.json'));
    const after = h.state();
    assert.equal(after.holds.hold_000000000000000000000000, undefined);
    assert.notEqual(Object.values(after.holds)[0].dialog_at, null, 'the valid hold still works');
  } finally { h.cleanup(); }
});

// ---------------------------------------------------------------- Cursor

test('Cursor asks only on beforeShellExecution/beforeMCPExecution in a local interactive session', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime() });
    assert.equal(h.run('cursor-session-hook', fixture('cursor-session-start.json')).stdout, '{}');
    const shell = h.run('cursor-pre-action-hook', fixture('cursor-before-shell.json'));
    assert.equal(shell.json.permission, 'ask');
    assert.match(shell.json.user_message, /^Marrow holds this action for your approval\./);
    assert.doesNotMatch(shell.json.agent_message, /marrow approve/);
    h.run('cursor-hook', fixture('cursor-after-shell.json'));
    const [report] = hostReports(h);
    assert.equal(report.body.host, 'cursor');
    // Cursor shows no dialog marker: the server labels this an allow rule.
    assert.equal(report.body.hook_event, 'beforeShellExecution');
    assert.equal(report.body.verdict, 'approved');

    h.setConfig({ runtime: hostRuntime('gate-mcp') });
    const mcp = h.run('cursor-pre-action-hook', fixture('cursor-before-mcp.json'));
    assert.equal(mcp.json.permission, 'ask');
  } finally { h.cleanup(); }
});

test('Cursor never asks on preToolUse, in cloud agents (no sessionStart) or in background agents', () => {
  for (const [label, sessionFixture, event] of [
    ['preToolUse', 'cursor-session-start.json', 'cursor-pre-tool-use.json'],
    ['cloud agent', null, 'cursor-before-shell.json'],
    ['background agent', 'cursor-session-start-background.json', 'cursor-before-shell.json'],
  ]) {
    const h = harness();
    try {
      h.setConfig({ runtime: hostRuntime() });
      if (sessionFixture) h.run('cursor-session-hook', fixture(sessionFixture));
      const out = h.run('cursor-pre-action-hook', fixture(event));
      assert.equal(out.json.permission, 'deny', label);
      assert.match(out.json.agent_message, /The approval request goes to the account owner\./, label);
      assert.doesNotMatch(out.stdout, /dashboard/i, label);
      assert.doesNotMatch(out.json.user_message, /marrow approve/, `${label}: no typed approval offered`);
    } finally { h.cleanup(); }
  }
});

test('Cursor typed reply: code only in the user message, local interactive only, reported as beforeSubmitPrompt', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime(), status: { 'gate-held': 'pending' } });
    h.run('cursor-session-hook', fixture('cursor-session-start.json'));
    // The prompt hook has run for this conversation (first user message).
    assert.deepEqual(h.run('cursor-context-hook', { ...fixture('cursor-before-submit-prompt.json'), prompt: 'deploy the worker' }).json, { continue: true });
    const denied = h.run('cursor-pre-action-hook', fixture('cursor-pre-tool-use.json'));
    assert.equal(denied.json.permission, 'deny');
    const code = denied.json.user_message.match(/marrow approve ([A-Z0-9]{6})/)[1];
    assert.doesNotMatch(denied.json.agent_message, new RegExp(code), 'the agent never reads the code');
    assert.doesNotMatch(denied.json.agent_message, /marrow approve/);
    assert.equal(parseTypedReply(`marrow approve ${code.toLowerCase()}`).code, code);
    const reply = h.run('cursor-context-hook', { ...fixture('cursor-before-submit-prompt.json'), prompt: `marrow approve ${code}` });
    assert.deepEqual(reply.json, { continue: true });
    const [report] = hostReports(h);
    assert.equal(report.body.verdict, 'approved');
    assert.equal(report.body.hook_event, 'beforeSubmitPrompt');
    assert.equal(report.body.host, 'cursor');
    // The retried action reads the status and runs once.
    h.setConfig({ status: { 'gate-held': 'approved' } });
    assert.equal(h.run('cursor-pre-action-hook', fixture('cursor-pre-tool-use.json')).json.permission, 'allow');
  } finally { h.cleanup(); }
  const b = harness();
  try {
    b.setConfig({ runtime: hostRuntime() });
    b.run('cursor-session-hook', fixture('cursor-session-start-background.json'));
    b.run('cursor-context-hook', { ...fixture('cursor-before-submit-prompt.json'), prompt: 'deploy' });
    const denied = b.run('cursor-pre-action-hook', fixture('cursor-pre-tool-use.json'));
    assert.doesNotMatch(denied.json.user_message, /marrow approve/);
    const code = Object.values(b.state().holds)[0].code;
    assert.equal(code, null);
  } finally { b.cleanup(); }
});

// ---------------------------------------------------------------- Codex, Gemini, Grok

test('Codex never asks (it fails open); outside a local interactive session it offers no typed code', () => {
  for (const [label, env] of [
    ['no Codex process found', {}],
    ['codex exec', { MARROW_TEST_HOST_PROCESS: '/usr/local/bin/codex exec --json deploy' }],
    ['no terminal', { MARROW_TEST_HOST_PROCESS: '/usr/local/bin/codex', MARROW_TEST_HOST_TTY: '0' }],
  ]) {
    const h = harness();
    try {
      h.setConfig({ runtime: hostRuntime(), status: { 'gate-held': 'pending' } });
      h.run('codex-context-hook', { ...fixture('codex-user-prompt-submit.json'), prompt: 'deploy the worker' }, env);
      const denied = h.run('codex-pre-action-hook', fixture('codex-pre-tool-use.json'), env);
      assert.equal(denied.json.hookSpecificOutput.permissionDecision, 'deny', label);
      assert.equal(denied.json.systemMessage, undefined, label);
      assert.doesNotMatch(denied.stdout, /marrow approve|dashboard/i, label);
      assert.match(denied.json.hookSpecificOutput.permissionDecisionReason, /Codex cannot ask the operator in this session\. The approval request goes to the account owner\./, label);
      h.run('codex-context-hook', { ...fixture('codex-user-prompt-submit.json'), prompt: 'marrow approve ABCDEF' }, env);
      assert.deepEqual(hostReports(h), [], `${label}: no typed approval is accepted`);
      h.setConfig({ status: { 'gate-held': 'approved' } });
      const retried = h.run('codex-pre-action-hook', { ...fixture('codex-pre-tool-use.json'), tool_use_id: 'call_retry' }, env);
      assert.equal(retried.json.hookSpecificOutput.permissionDecision, undefined, `${label}: approved, it runs once`);
    } finally { h.cleanup(); }
  }
});

test('Codex in a local interactive session: the code goes only to the user (systemMessage), the typed reply is recorded, the retry runs once', () => {
  const h = harness();
  const env = { MARROW_TEST_HOST_PROCESS: '/usr/local/bin/codex --model gpt-5-codex' };
  try {
    h.setConfig({ runtime: hostRuntime(), status: { 'gate-held': 'pending' } });
    h.run('codex-context-hook', { ...fixture('codex-user-prompt-submit.json'), prompt: 'deploy the worker' }, env);
    const denied = h.run('codex-pre-action-hook', fixture('codex-pre-tool-use.json'), env);
    const decision = denied.json.hookSpecificOutput;
    assert.equal(decision.permissionDecision, 'deny');
    const code = denied.json.systemMessage.match(/marrow approve ([A-Z0-9]{6})/)[1];
    assert.doesNotMatch(decision.permissionDecisionReason, new RegExp(code), 'the agent never reads the code');
    assert.match(decision.permissionDecisionReason, /The operator was asked to approve it here\./);
    assert.doesNotMatch(denied.stdout, /dashboard/i);
    const reply = h.run('codex-context-hook', { ...fixture('codex-user-prompt-submit.json'), prompt: `marrow approve ${code}` }, env);
    assert.equal(reply.json.systemMessage, 'Marrow recorded your approval (client-attested).');
    assert.match(reply.json.hookSpecificOutput.additionalContext, /^The operator approved the held action \(gate receipt gate-held\)\. Retry that exact action now/);
    const [report] = hostReports(h);
    assert.equal(report.body.host, 'codex');
    assert.equal(report.body.hook_event, 'UserPromptSubmit');
    assert.equal(report.body.verdict, 'approved');
    h.setConfig({ status: { 'gate-held': 'approved' } });
    const retried = h.run('codex-pre-action-hook', { ...fixture('codex-pre-tool-use.json'), tool_use_id: 'call_retry' }, env);
    assert.equal(retried.json.hookSpecificOutput.permissionDecision, undefined);
    assert.equal(runtimes(h).length, 1, 'the retry runs on the same gate receipt');
  } finally { h.cleanup(); }
});

test('Codex typed decline records a decline and closes a denial', () => {
  const h = harness();
  const env = { MARROW_TEST_HOST_PROCESS: '/usr/local/bin/codex resume' };
  try {
    h.setConfig({ runtime: hostRuntime() });
    h.run('codex-context-hook', { ...fixture('codex-user-prompt-submit.json'), prompt: 'deploy the worker' }, env);
    const denied = h.run('codex-pre-action-hook', fixture('codex-pre-tool-use.json'), env);
    const code = denied.json.systemMessage.match(/marrow decline ([A-Z0-9]{6})/)[1];
    const reply = h.run('codex-context-hook', { ...fixture('codex-user-prompt-submit.json'), prompt: `marrow decline ${code}` }, env);
    assert.equal(reply.json.systemMessage, 'Marrow recorded your decline. The held action will not run.');
    assert.equal(hostReports(h)[0].body.verdict, 'declined');
    assert.match(commits(h)[0].body.outcome, /^Denied by Marrow pre-action gate: the operator declined in Codex/);
  } finally { h.cleanup(); }
});

test('Gemini keeps its fixed denial outside a local interactive session, and runs once after approval', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime(), status: { 'gate-held': 'pending' } });
    const gemini = h.run('gemini-pre-action-hook', fixture('gemini-before-tool.json'), { MARROW_TEST_HOST_PROCESS: 'node /usr/lib/node_modules/@google/gemini-cli/dist/gemini.js -p deploy' });
    assert.deepEqual(gemini.json, { decision: 'deny', reason: 'Marrow blocked this action because required governance approval or proof is unavailable.' });
    h.setConfig({ status: { 'gate-held': 'approved' } });
    assert.deepEqual(h.run('gemini-pre-action-hook', fixture('gemini-before-tool.json')).json, { decision: 'allow' });
  } finally { h.cleanup(); }
});

test('Gemini CLI in a local interactive session: the code goes to systemMessage, a BeforeAgent typed reply is recorded', () => {
  const h = harness();
  const env = { MARROW_TEST_HOST_PROCESS: 'node /usr/lib/node_modules/@google/gemini-cli/bin/gemini' };
  try {
    h.setConfig({ runtime: hostRuntime() });
    assert.deepEqual(h.run('gemini-context-hook', { session_id: 'gemini-session-0001', hook_event_name: 'BeforeAgent', prompt: 'deploy the worker' }, env).json, {});
    const denied = h.run('gemini-pre-action-hook', fixture('gemini-before-tool.json'), env);
    assert.equal(denied.json.decision, 'deny');
    const code = denied.json.systemMessage.match(/marrow approve ([A-Z0-9]{6})/)[1];
    assert.doesNotMatch(denied.json.reason, new RegExp(code));
    assert.doesNotMatch(denied.stdout, /dashboard/i);
    const reply = h.run('gemini-context-hook', { session_id: 'gemini-session-0001', hook_event_name: 'BeforeAgent', prompt: `marrow approve ${code}` }, env);
    assert.equal(reply.json.systemMessage, 'Marrow recorded your approval (client-attested).');
    assert.equal(reply.json.hookSpecificOutput.hookEventName, 'BeforeAgent');
    const [report] = hostReports(h);
    assert.equal(report.body.host, 'gemini');
    assert.equal(report.body.hook_event, 'BeforeAgent');
  } finally { h.cleanup(); }
});

test('Grok has no user-only channel: it denies and the request goes to the owner', () => {
  const g = harness();
  try {
    g.setConfig({ runtime: hostRuntime() });
    const grok = g.run('grok-pre-action-hook', fixture('grok-pre-tool-use.json'));
    assert.deepEqual(grok.json, { decision: 'deny', reason: 'Marrow is holding this action for approval; the approval request goes to the account owner. Retry it after approval.' });
    assert.deepEqual(hostReports(g), []);
  } finally { g.cleanup(); }
});

test('a local interactive session is proven only by the nearest host process: a terminal and no scripted mode', () => {
  const { localInteractiveSession } = require('../dist/host-session.js');
  const table = (rows) => (pid) => rows[pid] || null;
  const chain = (host, terminal = true) => table({
    100: { pid: 100, ppid: 90, args: ['/bin/sh', '-c', 'npx marrow-mcp codex-pre-action-hook'], terminal: false },
    90: { pid: 90, ppid: 1, args: host, terminal },
  });
  assert.equal(localInteractiveSession('codex', chain(['/opt/codex/bin/codex-x86_64-unknown-linux-musl', '--model', 'gpt-5-codex']), 100), true);
  assert.equal(localInteractiveSession('codex', chain(['node', '/usr/lib/node_modules/@openai/codex/bin/codex.js', 'resume']), 100), true);
  for (const args of [['codex', 'exec', 'deploy'], ['codex', 'e', 'x'], ['codex', 'app-server'], ['codex', 'mcp-server'], ['codex', 'exec', '--json']]) {
    assert.equal(localInteractiveSession('codex', chain(args), 100), false, args.join(' '));
  }
  assert.equal(localInteractiveSession('codex', chain(['codex'], false), 100), false, 'no terminal');
  assert.equal(localInteractiveSession('codex', chain(['claude']), 100), null, 'no Codex process');
  assert.equal(localInteractiveSession('gemini', chain(['node', '/usr/bin/gemini']), 100), true);
  assert.equal(localInteractiveSession('gemini', chain(['node', '/usr/bin/gemini', '-i', 'start']), 100), true);
  for (const args of [['gemini', '-p', 'x'], ['gemini', '--prompt=x'], ['gemini', '--prompt', 'x'], ['gemini', '--experimental-acp']]) {
    assert.equal(localInteractiveSession('gemini', chain(args), 100), false, args.join(' '));
  }
  assert.equal(localInteractiveSession('claude-code', chain(['claude']), 100), null, 'never typed in Claude Code');
  assert.equal(localInteractiveSession('codex', () => null, 100), null, 'no process evidence');
});

// ---------------------------------------------------------------- guidance

test('runtime guidance is read from the expanded and slim shapes; endpoints are rebuilt from the receipt', () => {
  const expanded = normalizeRuntimeResult(hostRuntime());
  const guidance = ordinaryApprovalGuidance(expanded);
  assert.equal(guidance.hostApprovalAccepted, true);
  assert.equal(guidance.statusPath, '/v1/agent/gate-receipts/gate-held/owner-approval');
  assert.equal(guidance.hostApprovalPath, '/v1/agent/gate-receipts/gate-held/host-approval');
  assert.equal(guidance.trustedCompletionReceiptRequired, true);
  assert.equal(guidance.proofRequired, true);
  const slimRaw = {
    ok: true, response_mode: 'slim', action: 'classified Bash action: deploy on production', decision_id: 'decision-review',
    runtime_authorization: { id: 'gate-slim', kind: 'durable_gate_receipt', durable: true, decision_state: 'created', decision_creation_required: false, decision_id: 'decision-review' },
    decision: 'review_required', enforcement_decision: 'owner_approval_required', risk_gate_enforced: true, risk_level: 'high',
    gate_receipt_id: 'gate-slim', gate_required: true, proof_required: true, proof_complete: false,
    completion_contract: {
      must_commit_outcome: true, commit_endpoint: '/v1/agent/commit', required_commit_fields: ['decision_id', 'success', 'outcome', 'gate_receipt_id'],
      gate_receipt_required: true, arbitration_receipt_required: false, arbitration_receipt_id: null,
      owner_approval: { ...hostRuntime('gate-slim').completion_contract.owner_approval },
      proof_required_before_complete: true, required_proof_fields: ['summary', 'checks'], decision_creation_required: false, decision_state: 'created', decision_id: 'decision-review',
    },
  };
  const slim = ordinaryApprovalGuidance(normalizeRuntimeResult(slimRaw));
  assert.equal(slim.hostApprovalAccepted, true);
  assert.deepEqual(slim.proofFields, ['summary', 'checks']);
  assert.equal(slim.statusPath, '/v1/agent/gate-receipts/gate-slim/owner-approval');
  // Verified-only, unreadable settings, a foreign path or a wrong trust value: no host approval.
  for (const approval of [
    { verified_approval_required: true },
    { verified_approval_required: null },
    { host_approval_endpoint: '/v1/agent/gate-receipts/other/host-approval' },
    { host_approval_trust: 'verified' },
    { approval_authority: 'authenticated_dashboard_owner' },
  ]) {
    assert.equal(ordinaryApprovalGuidance(normalizeRuntimeResult(hostRuntime('gate-held', approval))).hostApprovalAccepted, false, JSON.stringify(approval));
  }
  // Arbitration and blocks are never ordinary holds.
  assert.equal(ordinaryApprovalGuidance(normalizeRuntimeResult(hostRuntime('gate-held', { mode: 'arbitration_review_required' }))), null);
  assert.equal(ordinaryApprovalGuidance(normalizeRuntimeResult({ ...hostRuntime(), risk_gate: { ...hostRuntime().risk_gate, decision: 'block', allow: false } })), null);
});
