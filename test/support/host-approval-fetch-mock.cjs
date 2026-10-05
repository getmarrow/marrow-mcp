'use strict';

// Preloaded into hook subprocesses (NODE_OPTIONS=--require) by
// test/host-approvals.test.js. It answers Marrow API calls from a scripted
// config file and appends every request to requests.jsonl, so a test can drive
// one hook process per host event (as a real host does) and assert the wire.
const { appendFileSync, existsSync, readFileSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');

const directory = process.env.MARROW_TEST_MOCK_DIR;
const configPath = join(directory, 'config.json');
const countersPath = join(directory, 'counters.json');

function load(path, fallback) {
  try { return existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : fallback; } catch { return fallback; }
}

function next(name, list) {
  const counters = load(countersPath, {});
  const index = counters[name] || 0;
  counters[name] = index + 1;
  writeFileSync(countersPath, JSON.stringify(counters));
  return list[Math.min(index, list.length - 1)];
}

globalThis.fetch = async (url, init = {}) => {
  const config = load(configPath, {});
  const parsed = new URL(String(url));
  const path = parsed.pathname;
  const method = String(init.method || 'GET').toUpperCase();
  const headers = new Headers(init.headers);
  const body = init.body ? JSON.parse(String(init.body)) : null;
  appendFileSync(join(directory, 'requests.jsonl'), `${JSON.stringify({
    method, path, body,
    session: headers.get('X-Marrow-Session-Id'),
    agent: headers.get('X-Marrow-Agent-Id'),
    idempotency_key: headers.get('Idempotency-Key'),
    at: new Date().toISOString(),
  })}\n`);
  const json = (value, status = 200, extra = {}) => new Response(JSON.stringify(value), {
    status, headers: { 'content-type': 'application/json', ...extra },
  });
  if (path === '/v1/agent/integrations/events') return json({ data: { accepted: true } });
  if (path === '/v1/agent/runtime') return json({ data: config.runtime });
  if (path === '/v1/agent/think') return json({ data: { decision_id: 'decision-think' } });
  if (path === '/v1/agent/commit') return json({ data: config.commit || { committed: true, decision_id: body.decision_id } });
  const status = path.match(/^\/v1\/agent\/gate-receipts\/([^/]+)\/owner-approval$/);
  if (status && method === 'GET') {
    const state = (config.status || {})[status[1]] || 'pending';
    if (state === 'not_found') return json({ error: 'Gate receipt not found.', details: { code: 'MARROW_GATE_RECEIPT_NOT_FOUND' } }, 404);
    return json({ data: {
      gate_receipt_id: status[1], decision_id: 'decision-review', state, gate_decision: 'owner_approval_required',
      owner_approval_receipt_id: state === 'approved' ? 'oar-fixture' : null, decided_at: null,
      approval_source: ['approved', 'declined'].includes(state) ? (config.statusSource || 'dashboard') : null,
      approval_trust: null, approval_answered_by: ['approved', 'declined'].includes(state) ? 'account_owner' : null,
      expires_at: '2030-01-01T00:30:00.000Z', terminal: state !== 'pending', retryable: state === 'pending',
      poll_after_ms: state === 'pending' ? 5000 : null, exact_next_action: `fixture ${state}`,
    } });
  }
  const host = path.match(/^\/v1\/agent\/gate-receipts\/([^/]+)\/host-approval$/);
  if (host && method === 'POST') {
    const scripted = Array.isArray(config.hostApproval) && config.hostApproval.length ? next('hostApproval', config.hostApproval) : null;
    if (scripted && scripted.status !== 200) return json(scripted.body, scripted.status, scripted.headers || {});
    const marker = body.hook_event === 'PermissionRequest' || (body.host === 'cursor' && body.hook_event === 'beforeSubmitPrompt');
    return json({ data: {
      host_approval: {
        owner_approval_receipt_id: body.verdict === 'approved' ? 'oar-host' : null,
        owner_decline_receipt_id: body.verdict === 'declined' ? 'odr-host' : null,
        gate_receipt_id: host[1], decision_id: body.decision_id || 'decision-review', verdict: body.verdict,
        source: 'host_prompt', trust: 'client_attested',
        answered_by: body.verdict === 'approved' && !marker ? 'host_allow_rule' : 'host_operator',
        host: body.host, recorded_at: new Date().toISOString(), expires_at: '2030-01-01T00:30:00.000Z',
      },
      replayed: false, evidence_recorded: true, exact_next_action: 'fixture recorded',
    } });
  }
  return json({ error: `unexpected ${method} ${path}` }, 500);
};
