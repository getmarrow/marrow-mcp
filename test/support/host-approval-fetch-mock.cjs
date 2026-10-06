'use strict';

// Preloaded into hook subprocesses (NODE_OPTIONS=--require) by
// test/host-approvals.test.js. It answers Marrow API calls from a scripted
// config file and appends every request to requests.jsonl, so a test can drive
// one hook process per host event (as a real host does) and assert the wire.
const { appendFileSync, existsSync, readFileSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');

const directory = process.env.MARROW_TEST_MOCK_DIR;

// A synthetic parent process for the interactive-session check (src/host-session.ts):
// MARROW_TEST_HOST_PROCESS is the host command line, MARROW_TEST_HOST_TTY=0 removes its terminal.
if (process.env.MARROW_TEST_HOST_PROCESS) {
  globalThis[Symbol.for('marrow.test.processTable')] = {
    [String(process.ppid)]: {
      pid: process.ppid, ppid: 1, args: process.env.MARROW_TEST_HOST_PROCESS.split(' '),
      terminal: process.env.MARROW_TEST_HOST_TTY !== '0',
    },
  };
} else {
  globalThis[Symbol.for('marrow.test.processTable')] = {};
}
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
  // A slow Marrow, cancelled like a real request when the caller aborts.
  const sleep = (ms) => new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    init.signal?.addEventListener('abort', () => {
      clearTimeout(timer);
      const error = new Error('This operation was aborted');
      error.name = 'AbortError';
      reject(error);
    }, { once: true });
  });
  // Marrow unreachable for one route family: a network failure, as fetch reports it.
  const unreachable = () => { const error = new TypeError('fetch failed'); error.cause = { code: 'ECONNREFUSED' }; throw error; };
  if (path === '/v1/agent/integrations/events') {
    const events = load(join(directory, 'events.json'), []);
    if (body?.event_id) {
      const previous = events.find((event) => event.event_id === body.event_id);
      if (previous && JSON.stringify(previous) !== JSON.stringify(body)) {
        return json({ error: 'Lifecycle event conflicts with its original durable evidence', details: { code: 'lifecycle_event_payload_conflict' } }, 409);
      }
      if (!previous) writeFileSync(join(directory, 'events.json'), JSON.stringify([...events, body]));
    }
    return json({ data: { accepted: true } });
  }
  if (path === '/v1/agent/runtime') {
    if (config.runtimeDelayMs) await sleep(config.runtimeDelayMs);
    if (config.runtimeUnreachable) unreachable();
    return json({ data: config.runtime });
  }
  if (path === '/v1/agent/think') return json({ data: { decision_id: 'decision-think' } });
  if (path === '/v1/agent/commit') return json({ data: config.commit || { committed: true, decision_id: body.decision_id } });
  const status = path.match(/^\/v1\/agent\/gate-receipts\/([^/]+)\/owner-approval$/);
  if (status && method === 'GET') {
    if (config.statusDelayMs) await sleep(config.statusDelayMs);
    if (config.statusUnreachable) unreachable();
    // A status that follows the host-approval report (as the service records it).
    const recorded = config.statusFollowsHostReport ? load(join(directory, 'host-verdicts.json'), {})[status[1]] : null;
    if (recorded) {
      return json({ data: {
        gate_receipt_id: status[1], decision_id: 'decision-review', state: recorded.verdict, gate_decision: 'owner_approval_required',
        owner_approval_receipt_id: recorded.verdict === 'approved' ? 'oar-host' : null, decided_at: null,
        approval_source: 'host_prompt', approval_trust: 'client_attested', approval_answered_by: recorded.answered_by,
        expires_at: '2030-01-01T00:30:00.000Z', terminal: true, retryable: false, poll_after_ms: null, exact_next_action: 'fixture recorded',
      } });
    }
    const state = (config.status || {})[status[1]] || 'pending';
    if (state === 'not_found') return json({ error: 'Gate receipt not found.', details: { code: 'MARROW_GATE_RECEIPT_NOT_FOUND' } }, 404);
    return json({ data: {
      gate_receipt_id: status[1], decision_id: 'decision-review', state, gate_decision: 'owner_approval_required',
      owner_approval_receipt_id: state === 'approved' || (state === 'used' && config.usedAfterApproval) ? 'oar-fixture' : null, decided_at: null,
      approval_source: ['approved', 'declined', 'used'].includes(state) ? (config.statusSource || 'dashboard') : null,
      approval_trust: ['approved', 'declined', 'used'].includes(state) ? ((config.statusSource || 'dashboard') === 'host_prompt' ? 'client_attested' : 'verified') : null,
      approval_answered_by: ['approved', 'declined', 'used'].includes(state)
        ? ((config.statusSource || 'dashboard') === 'host_prompt' ? (config.statusAnsweredBy || 'host_operator') : 'account_owner') : null,
      expires_at: '2030-01-01T00:30:00.000Z', terminal: state !== 'pending', retryable: state === 'pending',
      poll_after_ms: state === 'pending' ? 5000 : null, exact_next_action: `fixture ${state}`,
    } });
  }
  if (path === '/v1/agent/held-actions' && method === 'GET') {
    if (!config.heldActions) return json({ error: 'Not found' }, 404);
    return json({ data: { scope: 'agent', count: config.heldActions.length, more: false, holds: config.heldActions, exact_next_action: 'fixture held' } });
  }
  if (path === '/v1/agent/approval-settings' && method === 'GET') {
    if (!config.approvalSettings) return json({ error: 'Not found' }, 404);
    return json({ data: config.approvalSettings });
  }
  const link = path.match(/^\/v1\/agent\/gate-receipts\/([^/]+)\/approval-link$/);
  if (link && method === 'POST') {
    if (config.linkDelayMs) await sleep(config.linkDelayMs);
    if (config.approvalLinkNotSent) {
      return json({ data: { sent: false, state: 'not_sent', reason: 'owner_ping_off', approval_link: null, exact_next_action: 'fixture not sent' } });
    }
    const scripted = Array.isArray(config.approvalLink) && config.approvalLink.length ? next('approvalLink', config.approvalLink) : null;
    if (scripted && scripted.status !== 200) return json(scripted.body, scripted.status, scripted.headers || {});
    return json({ data: {
      approval_link: { id: 'link-1', gate_receipt_id: link[1], channel: 'email', recipient_hint: 'o***@example.test', expires_at: '2030-01-01T00:10:00.000Z', delivered_at: new Date().toISOString() },
      exact_next_action: 'fixture link sent',
    } });
  }
  const host = path.match(/^\/v1\/agent\/gate-receipts\/([^/]+)\/host-approval$/);
  if (host && method === 'POST') {
    // A service whose host route does not take normalized_action yet (strict body).
    if (config.hostRouteStrict && body && 'normalized_action' in body) {
      return json({ error: 'Host approval report is invalid.', details: { code: 'MARROW_HOST_APPROVAL_INVALID', fields: ['normalized_action'], reason: 'unknown_fields' } }, 400);
    }
    const scripted = Array.isArray(config.hostApproval) && config.hostApproval.length ? next('hostApproval', config.hostApproval) : null;
    if (scripted && scripted.status !== 200) return json(scripted.body, scripted.status, scripted.headers || {});
    const marker = body.hook_event === 'PermissionRequest' || (body.host === 'cursor' && body.hook_event === 'beforeSubmitPrompt');
    if (config.statusFollowsHostReport) {
      const verdicts = load(join(directory, 'host-verdicts.json'), {});
      verdicts[host[1]] = { verdict: body.verdict, answered_by: body.verdict === 'approved' && !marker ? 'host_allow_rule' : 'host_operator' };
      writeFileSync(join(directory, 'host-verdicts.json'), JSON.stringify(verdicts));
    }
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
