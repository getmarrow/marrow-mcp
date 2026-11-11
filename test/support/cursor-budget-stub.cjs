'use strict';

// Test-only preload (never ships) for test/cursor-hook-budget.test.js: a scripted Marrow API whose routes answer
// after a chosen delay, so a test can see which side of the Cursor hook budget a slow server lands on. It reuses the
// recorded production-shaped runtime body (test/fixtures/f2-recorded-force-push.json). Settings, all from the test:
//   CB_DELAY_RUNTIME / CB_DELAY_THINK / CB_DELAY_ISSUE / CB_DELAY_VERIFY   milliseconds before that route answers
//   CB_SCENARIO  ok | down | verify-false | verify-other-permit | partial-runtime | review (the gate answers review_required)
//                | verify-hang-ignore-abort | verify-cut
//   CB_DELAY_OTHER  milliseconds before any other route (lifecycle events, owner link, status, commit) answers
//   CB_START_DELAY_MS  the process waits this long at start-up (a slow npx start): it counts against the hook budget
//   CB_LOG       file: one line per call, "<path>[#operation] <ms since start>" (no bodies, no headers)
const fs = require('node:fs');
const path = require('node:path');

const scenario = process.env.CB_SCENARIO || 'ok';
const log = process.env.CB_LOG;
if (process.env.CB_START_DELAY_MS) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Number(process.env.CB_START_DELAY_MS));
const started = Date.now();
const recorded = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'f2-recorded-force-push.json'), 'utf8'));
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const delayOf = (name) => Number(process.env[`CB_DELAY_${name}`] || 0);

function wait(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(signal.reason); return; }
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => { clearTimeout(timer); reject(signal.reason); }, { once: true });
  });
}

globalThis.fetch = async (url, init = {}) => {
  const pathname = new URL(String(url)).pathname;
  let body = {};
  try { body = init.body ? JSON.parse(String(init.body)) : {}; } catch { body = {}; }
  const op = typeof body.operation === 'string' ? body.operation : '';
  if (log) fs.appendFileSync(log, `${pathname}${op ? `#${op}` : ''} ${Date.now() - started}\n`);
  if (scenario === 'down') throw Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error('ECONNREFUSED'), { code: 'ECONNREFUSED' }) });
  if (pathname === '/v1/agent/runtime') {
    await wait(delayOf('RUNTIME'), init.signal);
    if (scenario === 'partial-runtime') return json(200, { data: { ok: true } });
    if (scenario === 'review') {
      const data = structuredClone(recorded.runtime.data);
      data.risk_gate = { decision: 'review_required', allow: false, enforced: true, gate_required: true, reason: 'owner review needed' };
      return json(200, { data });
    }
    return json(200, recorded.runtime);
  }
  if (pathname === '/v1/agent/think') {
    await wait(delayOf('THINK'), init.signal);
    return json(200, { data: { decision_id: 'dec_cb_think' } });
  }
  if (pathname === '/v1/agent/enforcement' && op === 'issue') {
    await wait(delayOf('ISSUE'), init.signal);
    return json(200, { data: { permit_id: 'permit-cb', permit: 'signed-permit-cb', protocol_version: 1 } });
  }
  if (pathname === '/v1/agent/enforcement' && op === 'verify') {
    // verify-hang-ignore-abort: never answers and ignores the abort (only the control timeout ends it);
    // verify-cut: the answer's body reader throws part way.
    if (scenario === 'verify-hang-ignore-abort') return new Promise(() => {});
    await wait(delayOf('VERIFY'), init.signal);
    if (scenario === 'verify-cut') {
      const body = new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode('{"data":{"permit_id":"perm')); c.error(new Error('socket hang up')); } });
      return new Response(body, { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (scenario === 'verify-false') return json(200, { data: { permit_id: 'permit-cb', verified: false } });
    if (scenario === 'verify-other-permit') return json(200, { data: { permit_id: 'permit-other', verified: true } });
    return json(200, { data: { permit_id: 'permit-cb', verified: true } });
  }
  await wait(delayOf('OTHER'), init.signal);
  if (pathname === '/v1/agent/commit') return json(200, { data: { committed: true } });
  return json(200, { data: { accepted: true } });
};
