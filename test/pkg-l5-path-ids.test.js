'use strict';

// PKG-L5 (security sweep 2026-10-18): path ids accepted `.`, `..` and `...`, so a fixed-method request
// carrying the caller's key could reach another route (`/v1/workflows/../start` is POST `/v1/start`).
// Ids must match ^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$ and never contain `..`. Every id shape the service
// mints (backend 08277ce4: UUIDs, `lease_`/`replay_` + UUID, `rtdec_`/`thinkdec_`/`lcdec_` + 40 hex,
// template slugs) and the test fixtures' shapes still pass. No request is sent for a rejected id.
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes, randomUUID } = require('node:crypto');

const index = require('../dist/index.js');
const { validatePathParam } = index;

const REJECTED = ['.', '..', '...', 'a..b', '-x', '_x', '', 'x'.repeat(257), '../x', 'x/..', '.hidden', '..x', 'x..', 'a/b', '%2e%2e', 'a b', 'a\nb', ' x', 'x '];
const hex40 = () => randomBytes(20).toString('hex');
const SLUGS = ['code-review-deploy', 'incident-response', 'feature-rollout', 'ticket-triage', 'escalation-flow', 'lead-qualify', 'content-publish', 'etl-pipeline',
  'approval-flow', 'change-management', 'claims-triage', 'fraud-review', 'underwriting-decision', 'complaint-escalation', 'patient-triage', 'clinical-documentation',
  'prior-authorization', 'coding-audit', 'order-fulfillment', 'refund-approval', 'return-processing', 'contract-review', 'case-triage', 'document-discovery'];
const real = () => [randomUUID(), `lease_${randomUUID()}`, `replay_${randomUUID()}`, `rtdec_${hex40()}`, `thinkdec_${hex40()}`, `lcdec_${hex40()}`, ...SLUGS,
  'a'.repeat(60), 'x'.repeat(256), 'caf', '0abc',
  // shapes in this repo's and the backend's tests
  'wf_1', 'wf_123', 'wf-deploy', 'in_1', 'lease_12345678', 'replay_12345678', 'replay_existing', 'h-second-agent', 'h-foreign', 'decision-review', 'decision_123', 'd1',
  'thinkdec_c', 'a.b', 'v1.2.3', 'x.y.z'];

test('PKG-L5: `.`, `..`, `...`, `a..b`, a leading `-`, `_` or `.`, empty, over 256 characters and other characters are rejected', () => {
  for (const id of REJECTED) assert.throws(() => validatePathParam(id, 'id'), /id /, JSON.stringify(id.slice(0, 20)));
  assert.throws(() => validatePathParam(undefined, 'id'), /id is required/);
  assert.throws(() => validatePathParam(42, 'id'), /id is required|invalid/);
});

test('PKG-L5: every id shape the service mints and the fixtures use still passes, unchanged', () => {
  for (const id of real()) assert.equal(validatePathParam(id, 'id'), id, id.slice(0, 40));
});

test('PKG-L5: no request is sent for a rejected id, at every call site; an accepted id reaches its own route', async () => {
  const apiKey = `mrw_test_${randomBytes(12).toString('hex')}`;
  const baseUrl = 'https://api.example.test';
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    calls.push(String(url));
    return new Response(JSON.stringify({ data: { ok: true } }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  try {
    const sites = (id) => [
      ['workflow get', () => index.marrowWorkflow(apiKey, baseUrl, { action: 'get', workflowId: id })],
      ['workflow start', () => index.marrowWorkflow(apiKey, baseUrl, { action: 'start', workflowId: id, agentId: 'agent-l5', inputs: {} })],
      ['workflow instances', () => index.marrowWorkflow(apiKey, baseUrl, { action: 'instances', workflowId: id })],
      ['workflow advance (workflow)', () => index.marrowWorkflow(apiKey, baseUrl, { action: 'advance', workflowId: id, instanceId: randomUUID(), stepCompleted: 1, outcome: 'done' })],
      ['workflow advance (instance)', () => index.marrowWorkflow(apiKey, baseUrl, { action: 'advance', workflowId: randomUUID(), instanceId: id, stepCompleted: 1, outcome: 'done' })],
      ['workflow update', () => index.marrowWorkflow(apiKey, baseUrl, { action: 'update', workflowId: id, name: 'n' })],
      ['lease release', () => index.marrowCoordinate(apiKey, baseUrl, { action: 'release_lease', lease_id: id, agent_id: 'agent-l5' }, 'session-l5', 'agent-l5')],
      ['replay comparison', () => index.marrowReplayCompare(apiKey, baseUrl, { comparison_id: id })],
      ['handoff update', () => index.marrowUpdateHandoff(apiKey, baseUrl, id, { status: 'accepted' })],
      ['decision trace', () => index.marrowDecisionTrace(apiKey, baseUrl, id)],
      ['accept detected', () => index.marrowAcceptDetected(apiKey, baseUrl, id)],
      ['install template', () => index.marrowInstallTemplate(apiKey, baseUrl, id)],
    ];
    for (const id of ['.', '..', '...', 'a..b', '-x', '_x', '.hidden']) {
      for (const [name, call] of sites(id)) {
        calls.length = 0;
        await assert.rejects(call(), /must start with a letter or digit|contains invalid characters/, `${name} ${id}`);
        assert.deepEqual(calls, [], `${name} ${JSON.stringify(id)} sent a request`);
      }
    }
    // An accepted id goes to its own route (the call may then fail on the stub's answer; only the URL matters).
    for (const [name, call, route] of [
      ['install template', () => index.marrowInstallTemplate(apiKey, baseUrl, 'code-review-deploy'), '/v1/templates/code-review-deploy/install'],
      ['decision trace', () => index.marrowDecisionTrace(apiKey, baseUrl, 'rtdec_0123456789abcdef0123456789abcdef01234567'), '/v1/agent/governance/trace/rtdec_0123456789abcdef0123456789abcdef01234567'],
    ]) {
      calls.length = 0;
      await call().catch(() => null);
      assert.ok(calls.some((url) => new URL(url).pathname === route), `${name}: ${calls.map((u) => new URL(u).pathname).join(', ')}`);
    }
  } finally {
    globalThis.fetch = realFetch;
  }
});
