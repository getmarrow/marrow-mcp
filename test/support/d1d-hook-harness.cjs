'use strict';
// Test-only. Drives the pre-action hook in-process against a stub service (the backend half of D1d is not in this build: the stub answers `decline_check`).
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const crypto = require('node:crypto');
const { runPreActionHookCommand } = require('../../dist/hook-pre-action.js');

const hashOf = (action) => crypto.createHash('sha256').update(JSON.stringify(action)).digest('hex');

async function runHook(respond, event, options = {}) {
  const originalFetch = globalThis.fetch;
  const originalWrite = process.stdout.write;
  const originalEntrypoint = process.argv[2];
  const keys = ['MARROW_API_KEY', 'MARROW_BASE_URL', 'MARROW_AGENT_ID', 'MARROW_FLEET_AGENT_ID', 'MARROW_SESSION_ID', 'MARROW_EVENT_SPOOL_PATH', 'HOME', 'MARROW_AUTO_HOOK'];
  const previous = Object.fromEntries(keys.map((key) => [key, process.env[key]]));
  const directory = options.home || mkdtempSync(join(tmpdir(), 'marrow-d1d-'));
  const calls = [];
  let output = '';
  const exitBefore = process.exitCode;
  delete process.env.MARROW_FLEET_AGENT_ID;
  delete process.env.MARROW_AUTO_HOOK;
  // a dummy value made at run time with a fixed non-key prefix
  process.env.MARROW_API_KEY = options.key || `zq${crypto.randomBytes(8).toString('hex')}`;
  process.env.MARROW_BASE_URL = 'https://api.example.test';
  process.env.MARROW_AGENT_ID = 'agent-one';
  process.env.MARROW_SESSION_ID = 'session-one';
  process.env.MARROW_EVENT_SPOOL_PATH = join(directory, 'spool.json');
  process.env.HOME = directory;
  process.argv[2] = options.entrypoint || 'claude-pre-action-hook';
  process.stdout.write = (chunk) => { output += String(chunk); return true; };
  globalThis.fetch = async (url, init = {}) => {
    const pathname = new URL(String(url)).pathname;
    const body = init.body ? JSON.parse(String(init.body)) : {};
    if (pathname === '/v1/agent/integrations/events') return Response.json({ data: { accepted: true } });
    if (pathname === '/v1/agent/commit') return Response.json({ data: { committed: true, decision_id: body.decision_id } });
    calls.push({ pathname, body });
    return respond(pathname, body, calls.length);
  };
  try {
    await runPreActionHookCommand(event);
    return { calls, output, directory };
  } finally {
    globalThis.fetch = originalFetch;
    process.stdout.write = originalWrite;
    process.argv[2] = originalEntrypoint;
    process.exitCode = exitBefore;
    for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    if (!options.home) rmSync(directory, { recursive: true, force: true });
  }
}

const allow = (extra = {}) => Response.json({ data: {
  runtime_authorization: { id: 'fast_gate_one', durable: false, decision_creation_required: true },
  completion_contract: { decision_creation_required: true },
  risk_gate: { allow: true, decision: 'allow', enforced: true, reasons: [] },
  gate_receipt_id: 'fast_gate_one',
  before_you_act: 'Proceed with the low-risk work.',
  proof_pack: { fields: [] },
  ...extra,
} });
const review = () => Response.json({ data: {
  runtime_authorization: { id: 'gate_review_one', durable: true, decision_creation_required: false },
  risk_gate: { allow: false, decision: 'review_required', enforced: true, reasons: [{ message: 'needs approval' }], gate_receipt_id: 'gate_review_one' },
  gate_receipt_id: 'gate_review_one',
  proof_pack: { fields: [] },
} });
const block = () => Response.json({ data: {
  risk_gate: { allow: false, decision: 'block', enforced: true, reasons: [{ message: 'blocked' }], gate_receipt_id: 'gate_block_one' },
  gate_receipt_id: 'gate_block_one',
  proof_pack: { fields: [] },
} });
// The protected path the original class takes: runtime, think, issue, verify.
function protectedPath(pathname, body) {
  if (pathname === '/v1/agent/think') return Response.json({ data: { decision_id: 'decision-think' } });
  if (pathname === '/v1/agent/enforcement' && body.operation === 'issue') return Response.json({ data: { permit_id: 'permit-one', permit: 'signed-permit' } });
  if (pathname === '/v1/agent/enforcement' && body.operation === 'verify') return Response.json({ data: { permit_id: 'permit-one', verified: true } });
  throw new Error(`unexpected ${pathname}`);
}

module.exports = { runHook, allow, review, block, protectedPath, hashOf };
