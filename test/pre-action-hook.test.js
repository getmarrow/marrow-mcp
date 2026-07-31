const assert = require('node:assert/strict');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const { classifyTool, runPreActionHookCommand } = require('../dist/hook-pre-action.js');
const { deriveAction } = require('../dist/hook.js');

test('pre-action and result hooks use the same privacy-safe action binding', () => {
  const event = {
    session_id: 'session-one',
    tool_use_id: 'tool-one',
    tool_name: 'Bash',
    tool_input: { command: 'wrangler deploy production' },
  };
  assert.equal(deriveAction(event), classifyTool(event).action);
});

test('protected pre-action hook binds runtime gate to a decision before verifying its permit', async () => {
  const originalFetch = globalThis.fetch;
  const originalWrite = process.stdout.write;
  const previous = {
    MARROW_API_KEY: process.env.MARROW_API_KEY,
    MARROW_BASE_URL: process.env.MARROW_BASE_URL,
    MARROW_AGENT_ID: process.env.MARROW_AGENT_ID,
    MARROW_SESSION_ID: process.env.MARROW_SESSION_ID,
    MARROW_EVENT_SPOOL_PATH: process.env.MARROW_EVENT_SPOOL_PATH,
  };
  const directory = mkdtempSync(join(tmpdir(), 'marrow-mcp-pre-action-'));
  const calls = [];
  let output = '';
  process.env.MARROW_API_KEY = 'test-pre-action-key';
  process.env.MARROW_BASE_URL = 'https://api.example.test';
  process.env.MARROW_AGENT_ID = 'agent-one';
  process.env.MARROW_SESSION_ID = 'session-one';
  process.env.MARROW_EVENT_SPOOL_PATH = join(directory, 'spool.json');
  process.stdout.write = (chunk) => {
    output += String(chunk);
    return true;
  };
  globalThis.fetch = async (url, init = {}) => {
    const pathname = new URL(String(url)).pathname;
    const body = init.body ? JSON.parse(String(init.body)) : {};
    if (pathname !== '/v1/agent/integrations/events') calls.push({ pathname, body });
    if (pathname === '/v1/agent/runtime') {
      return Response.json({ data: {
        risk_gate: { allow: true, decision: 'allow', reasons: [] },
        gate_receipt_id: 'gate-one',
        gate_receipt: { id: 'gate-one' },
        proof_pack: { fields: ['command', 'exit_code'] },
      } });
    }
    if (pathname === '/v1/agent/think') {
      return Response.json({ data: { decision_id: 'decision-one', intelligence: {}, stream_url: '' } });
    }
    if (pathname === '/v1/agent/enforcement' && body.operation === 'issue') {
      return Response.json({ data: { permit_id: 'permit-one', permit: 'signed-permit' } });
    }
    if (pathname === '/v1/agent/enforcement' && body.operation === 'verify') {
      return Response.json({ data: { permit_id: 'permit-one', verified: true } });
    }
    return Response.json({ data: { accepted: true } });
  };

  try {
    await runPreActionHookCommand({
      session_id: 'session-one',
      tool_use_id: 'tool-one',
      tool_name: 'Bash',
      tool_input: { command: 'wrangler deploy production' },
    });
    assert.deepEqual(calls.map((entry) => entry.pathname), [
      '/v1/agent/runtime',
      '/v1/agent/think',
      '/v1/agent/enforcement',
      '/v1/agent/enforcement',
    ]);
    assert.equal(calls[2].body.decision_id, 'decision-one');
    assert.equal(calls[2].body.gate_receipt_id, 'gate-one');
    assert.equal(calls[3].body.operation, 'verify');
    assert.equal(calls[3].body.permit, 'signed-permit');
    const result = JSON.parse(output);
    assert.notEqual(result.hookSpecificOutput.permissionDecision, 'deny');
    assert.match(result.hookSpecificOutput.additionalContext, /action permit verified/);
    assert.doesNotMatch(output, /signed-permit/);
  } finally {
    globalThis.fetch = originalFetch;
    process.stdout.write = originalWrite;
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    rmSync(directory, { recursive: true, force: true });
  }
});
