'use strict';

// Test-only preload (never ships): a scripted Marrow API for the F2 pre-action tests. The runtime
// answer and the permit 503 are the bodies a local Worker of backend d4f07a02 (production code)
// returned for a keyed `git push --force origin main` (test/fixtures/f2-recorded-force-push.json).
// F2_SCENARIO picks the failure; F2_LOG records the paths called (no bodies, no headers).
const fs = require('node:fs');
const path = require('node:path');

const scenario = process.env.F2_SCENARIO || 'permit-ok';
const log = process.env.F2_LOG;
const recorded = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'f2-recorded-force-push.json'), 'utf8'));
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const netError = (code) => Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error(code), { code }) });
const unavailable = { error: 'Service unavailable', code: 'SERVICE_UNAVAILABLE', details: { retryable: true, safe_to_continue: false, severity: 'high' } };

globalThis.fetch = async (url, init = {}) => {
  const pathname = new URL(String(url)).pathname;
  let body = {};
  try { body = init.body ? JSON.parse(String(init.body)) : {}; } catch { body = {}; }
  const op = typeof body.operation === 'string' ? body.operation : '';
  if (log) fs.appendFileSync(log, `${pathname}${op ? `#${op}` : ''}\n`);
  if (pathname === '/v1/agent/runtime') {
    if (scenario === 'runtime-refused') throw netError('ECONNREFUSED');
    if (scenario === 'runtime-dns') throw netError('ENOTFOUND');
    if (scenario === 'runtime-503') return json(503, unavailable);
    if (scenario === 'think-503' || scenario === 'think-reset') {
      const data = structuredClone(recorded.runtime.data);
      delete data.decision_id;
      data.runtime_authorization = { ...data.runtime_authorization, decision_creation_required: true, decision_id: null };
      data.completion_contract = { ...data.completion_contract, decision_creation_required: true, decision_id: null };
      return json(200, { data });
    }
    return json(200, recorded.runtime);
  }
  if (pathname === '/v1/agent/think') {
    if (scenario === 'think-503') return json(503, unavailable);
    if (scenario === 'think-reset') throw netError('ECONNRESET');
    return json(200, { data: { decision_id: 'dec_f2_think' } });
  }
  if (pathname === '/v1/agent/enforcement' && op === 'issue') {
    if (scenario === 'permit-503') return json(recorded.enforcement_issue.status, recorded.enforcement_issue.body);
    if (scenario === 'permit-502') return json(502, unavailable);
    return json(200, { data: { permit_id: 'permit-f2', permit: 'signed-permit-f2', protocol_version: 1 } });
  }
  if (pathname === '/v1/agent/enforcement' && op === 'verify') {
    if (scenario === 'verify-reset') throw netError('ECONNRESET');
    return json(200, { data: { permit_id: 'permit-f2', verified: true } });
  }
  if (pathname === '/v1/agent/commit') return json(200, { data: { committed: true } });
  return json(200, { data: { accepted: true } });
};
