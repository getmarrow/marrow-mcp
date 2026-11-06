'use strict';

// Test-only preload (NODE_OPTIONS=--require) for test/hookdata*.test.js: every Marrow API call the hook child makes is
// appended to HOOKDATA_CAPTURE_DIR/requests.jsonl and answered locally with an allow gate; nothing leaves the process.
// An allow gate is the strictest probe of the local classification: a call is held only when the hook itself
// calls it protected.
const { appendFileSync } = require('node:fs');
const { join } = require('node:path');

const directory = process.env.HOOKDATA_CAPTURE_DIR;
globalThis[Symbol.for('marrow.test.processTable')] = {};

globalThis.fetch = async (url, init = {}) => {
  const parsed = new URL(String(url));
  let body = null;
  try { body = init.body ? JSON.parse(String(init.body)) : null; } catch { body = null; }
  appendFileSync(join(directory, 'requests.jsonl'), `${JSON.stringify({ method: String(init.method || 'GET').toUpperCase(), path: parsed.pathname, body })}\n`);
  const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
  if (parsed.pathname === '/v1/agent/runtime') {
    return json({ data: {
      decision_id: 'decision-hookdata',
      risk_gate: { allow: true, decision: 'allow', enforced: true, reasons: [] },
      runtime_authorization: { id: 'gate-hookdata', status: 'allow' },
      proof_pack: { required: false, fields: [], complete: true },
    } });
  }
  if (parsed.pathname === '/v1/agent/integrations/events') return json({ data: { accepted: true } });
  if (parsed.pathname === '/v1/agent/think') return json({ data: { decision_id: 'decision-think' } });
  if (parsed.pathname === '/v1/agent/commit') return json({ data: { committed: true, decision_id: 'decision-hookdata' } });
  return json({ error: 'unexpected route' }, 404);
};
