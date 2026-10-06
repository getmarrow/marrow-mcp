const assert = require('node:assert/strict');
const test = require('node:test');
const { normalizedHookAction, normalizeShellCommand } = require('../dist/normalized-action.js');
const { ordinaryApprovalGuidance } = require('../dist/runtime-contract.js');
const { withoutServerNextActions } = require('../dist/index.js');

const bash = (command) => normalizedHookAction({ tool_name: 'Bash', tool_input: { command, description: 'held' } });

test('the five commands one coarse "deploy on production" class used to merge are five different normalized actions', () => {
  const commands = [
    'wrangler deploy',
    'wrangler delete --force',
    'terraform destroy -auto-approve',
    'kubectl delete namespace prod',
    'wrangler rollback',
  ];
  const values = commands.map((command) => JSON.stringify(bash(command)));
  assert.equal(new Set(values).size, 5);
  assert.deepEqual(bash('terraform destroy -auto-approve'), {
    tool_kind: 'shell', tool_name: 'Bash', commands: ['terraform destroy -auto-approve'], programs: ['terraform'],
  });
});

test('a retry of the same command produces the same normalized action, whitespace and description aside', () => {
  const first = normalizedHookAction({ tool_name: 'Bash', tool_input: { command: 'kubectl delete namespace prod', description: 'first try' } });
  const retry = normalizedHookAction({ tool_name: 'Bash', tool_input: { command: '  kubectl   delete namespace prod ', description: 'second try' } });
  assert.deepEqual(first, retry);
  const mcp = { tool_name: 'mcp__github__merge_pull_request', tool_input: { number: 7, repo: 'getmarrow/demo' } };
  assert.deepEqual(normalizedHookAction(mcp), normalizedHookAction({ ...mcp, tool_input: { repo: 'getmarrow/demo', number: 7 } }), 'key order does not matter');
});

test('no secrets leave: environment values, URL credentials and tokens are removed', () => {
  const dummy = `ghp_${'a'.repeat(36)}`;
  const { text } = normalizeShellCommand(`API_TOKEN=s3cretvalue123 DEPLOY_ENV=prod wrangler deploy --token=${dummy} && curl https://deploy:hunter2pass@example.test/hook?token=abcdef123456`);
  assert.doesNotMatch(text, /s3cretvalue123|hunter2pass|abcdef123456|aaaaaaaaaaaa/);
  assert.match(text, /^API_TOKEN=\[redacted\] DEPLOY_ENV=\[redacted\] wrangler deploy --token=\[redacted\] && curl https:\/\/\[redacted\]@example\.test\/hook\?token=\[redacted\]$/i);
  const mcp = normalizedHookAction({ tool_name: 'mcp__vault__write', tool_input: { path: 'kv/app', api_key: 'live-value-1234567890', note: 'rotate' } });
  assert.equal(mcp.tool_input.api_key, '[redacted]');
  assert.doesNotMatch(JSON.stringify(mcp), /live-value-1234567890/);
});

test('edits name their paths; large tool inputs are represented by a hash, not their content', () => {
  assert.deepEqual(normalizedHookAction({ tool_name: 'Edit', tool_input: { file_path: '/repo/wrangler.toml', old_string: 'a', new_string: 'b' } }),
    { tool_kind: 'edit', tool_name: 'Edit', paths: ['/repo/wrangler.toml'] });
  const big = normalizedHookAction({ tool_name: 'mcp__docs__write', tool_input: { body: 'x'.repeat(20_000) } });
  assert.equal(big.truncated, true);
  assert.match(big.tool_input.input_sha256, /^[a-f0-9]{64}$/);
});

test('the arbitration receipt field is read under both names and never treated as an ordinary hold', () => {
  const runtime = (approval) => ({
    decision_id: 'd1', runtime_authorization: { id: 'g1', decision_id: 'd1' },
    risk_gate: { decision: 'review_required' }, gate_receipt: { id: 'g1', decision: 'review_required' },
    completion_contract: { decision_id: 'd1', owner_approval: { mode: 'ordinary_non_arbitrated', approval_status_endpoint: '/v1/agent/gate-receipts/g1/owner-approval', ...approval } },
  });
  assert.ok(ordinaryApprovalGuidance(runtime({})));
  assert.equal(ordinaryApprovalGuidance(runtime({ dashboard_receipt_required: true })), null);
  assert.equal(ordinaryApprovalGuidance(runtime({ owner_receipt_required: true })), null);
});

test('the raw runtime_gate marrow_auto returns carries no server next-step text at any depth', () => {
  const stripped = withoutServerNextActions({
    exact_next_action: 'POST /v1/agent/gate-receipts/g1/approval-link',
    decision_brief: { exact_next_actions: ['POST /v1/agent/gate-receipts/g1/approval-link'] },
    intervention: { exact_next_action: 'POST ...', headline: 'held' },
    arbitration: { proposals: [{ exact_next_action: 'x', id: 'p1' }] },
  });
  assert.doesNotMatch(JSON.stringify(stripped), /exact_next_action|approval-link/);
  assert.equal(stripped.intervention.headline, 'held');
  assert.equal(stripped.arbitration.proposals[0].id, 'p1');
});
