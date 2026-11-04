'use strict';
// D1d, the hook half of "decline wins" (D1r, D4-D7, B1, B9, B10, C1, K1, X1, G2), against a STUB service: the backend half (reading declines on `base_class`, answering `decline_check`)
// is a separate backend change that lands first. Production lowering needs that piece live: without it every answer here is the old server's and the original class is asked.
const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { runHook, allow, review, block, protectedPath, hashOf } = require('./support/d1d-hook-harness.cjs');
const { classifyTool } = require('../dist/hook-pre-action.js');
const mapper = require('../dist/seatbelt/mapper.js');
const hostState = require('../dist/host-approval-state.js');

const ROOT = path.resolve(__dirname, '..');
const CMD = "git grep -c 'deploy' main";
const ev = (command = CMD, extra = {}) => ({ session_id: 's1', tool_use_id: 't1', tool_name: 'Bash', tool_input: { command }, cwd: ROOT, ...extra });
const clearFor = (b) => ({ decline_check: { state: 'clear', action: hashOf(b.normalized_action) } });
const names = (run) => run.calls.map((c) => c.pathname.replace('/v1/agent/', '') + (c.body.operation ? `:${c.body.operation}` : ''));
const runtimeCalls = (run) => run.calls.filter((c) => c.pathname === '/v1/agent/runtime');
const asked = (run) => /deny|approval|permissionDecision/i.test(run.output) && !/Proceed with the low-risk work/.test(run.output.replace(/permit verified/g, ''));
const MASTER_ONLY = ['runtime', 'think', 'enforcement:issue', 'enforcement:verify'];

test('B9/C1: a bound clear lowers: one call, the lowered class with base_class, no risk_level, normalized_action as master sends it', async () => {
  const run = await runHook((p, b) => (p === '/v1/agent/runtime' ? allow(clearFor(b)) : protectedPath(p, b)), ev());
  assert.deepEqual(names(run), ['runtime']);
  const body = run.calls[0].body;
  assert.equal(body.type, 'process');
  assert.deepEqual(body.surfaces, ['github']);
  assert.equal('risk_level' in body, false);
  assert.deepEqual(body.base_class, { action: 'classified Bash action: deploy on production, github', type: 'deploy', surfaces: ['production', 'github'] });
  assert.deepEqual(Object.keys(body.base_class), ['action', 'type', 'surfaces'], 'labels only');
  assert.equal(JSON.stringify(body).includes('git grep'), false, 'no command text in the body');
  assert.equal(asked(run), false);
  // the same call against an old server: master's body, with the normalized action byte-equal and no base_class
  const old = await runHook((p, b) => (p === '/v1/agent/runtime' ? allow() : protectedPath(p, b)), ev());
  const released = old.calls[1].body;
  assert.deepEqual(released.normalized_action, body.normalized_action);
  assert.equal('base_class' in released, false);
  assert.equal(released.type, 'deploy');
  assert.equal(released.risk_level, 'high');
  assert.deepEqual(Object.keys(released).filter((k) => !(k in body)).sort(), ['risk_level']);
  assert.deepEqual(Object.keys(body).filter((k) => !(k in released)).sort(), ['base_class']);
});

test('B10/D1r/D5: no clearance, a mismatched or replayed one, malformed, empty, error: the original class is asked (master control path), nothing lowered', async () => {
  const bad = [undefined, { state: 'clear', action: 'a'.repeat(64) }, { state: 'clear', action: hashOf({ other: 1 }) }, { state: 'declined', action: 'x' }, { state: 'clear' }, { action: 'x' }, 'clear', ['clear'], null, 7, { state: 'CLEAR', action: 'x' }, { state: 'clear', action: 5 }, {}, { state: 'pending' }];
  for (const check of bad) {
    const run = await runHook((p, b) => {
      if (p !== '/v1/agent/runtime') return protectedPath(p, b);
      if (check && typeof check === 'object' && check.state === 'clear' && check.action === undefined) return allow({ decline_check: check });
      return allow(check === undefined ? {} : { decline_check: check });
    }, ev());
    assert.deepEqual(names(run), ['runtime', 'runtime', ...MASTER_ONLY.slice(1)], JSON.stringify(check));
    assert.equal('base_class' in run.calls[1].body, false);
    assert.equal(run.calls[1].body.type, 'deploy');
  }
  // an upper-case copy of the right hash is not the right hash
  const upper = await runHook((p, b) => (p === '/v1/agent/runtime' ? allow({ decline_check: { state: 'clear', action: hashOf(b.normalized_action).toUpperCase() } }) : protectedPath(p, b)), ev());
  assert.equal(runtimeCalls(upper).length, 2);
  // a clearance from an earlier call is never read: the next call, with the service down for the lowered question, is master's
  const first = await runHook((p, b) => (p === '/v1/agent/runtime' ? allow(clearFor(b)) : protectedPath(p, b)), ev());
  assert.equal(runtimeCalls(first).length, 1);
  const second = await runHook((p, b) => (p === '/v1/agent/runtime' ? allow() : protectedPath(p, b)), ev());
  assert.equal(runtimeCalls(second).length, 2);
});

test('B10: error, empty and malformed answers to the lowered question follow master\'s control path', async () => {
  const answers = [
    () => Response.json({ error: 'bad' }, { status: 400 }),
    () => Response.json({ data: {} }),
    () => Response.json({ data: null }),
    () => new Response('not json', { status: 200 }),
    () => Response.json({ data: { risk_gate: 'allow' } }),
    () => { throw Object.assign(new Error('aborted'), { name: 'AbortError' }); },
  ];
  for (const first of answers) {
    let n = 0;
    const run = await runHook((p, b) => {
      if (p !== '/v1/agent/runtime') return protectedPath(p, b);
      n += 1;
      return n === 1 ? first() : allow();
    }, ev());
    // the transport may retry the lowered question; master's own question is the one without base_class
    const released = run.calls.filter((c) => c.pathname === '/v1/agent/runtime' && !('base_class' in c.body));
    assert.equal(released.length, 1, 'master asks once');
    assert.equal(released[0].body.type, 'deploy');
    assert.equal(released[0].body.risk_level, 'high');
    assert.deepEqual(run.calls.filter((c) => c.pathname !== '/v1/agent/runtime').map((c) => c.pathname + (c.body.operation || '')), ['/v1/agent/think', '/v1/agent/enforcementissue', '/v1/agent/enforcementverify']);
  }
});

test('B10: review_required and block on the lowered question stand (one call, held / denied, never looser)', async () => {
  const held = await runHook(() => review(), ev());
  assert.deepEqual(names(held), ['runtime']);
  assert.ok(held.output.length > 0 && asked(held), held.output);
  const blocked = await runHook(() => block(), ev());
  assert.deepEqual(names(blocked), ['runtime']);
  assert.ok(blocked.output.length > 0 && asked(blocked), blocked.output);
  // a held answer that also carries a clearance is still held
  const both = await runHook((p, b) => review().json().then((j) => Response.json({ data: { ...j.data, ...clearFor(b) } })), ev());
  assert.deepEqual(names(both), ['runtime']);
  assert.ok(asked(both));
});

test('A17/X1/F1: no slot proven, an unlisted program, master hit: no lowered question at all (no base_class in any body)', async () => {
  for (const command of ['git commit -m x', "git grep -c deploy main && ./deploy.sh", 'git push origin main', 'ls production && wrangler deploy', "python3 ship.py", 'rm -rf build', 'git grep -n x -- src/commit.ts']) {
    const run = await runHook((p, b) => (p === '/v1/agent/runtime' ? allow(clearFor(b)) : protectedPath(p, b)), ev(command));
    for (const c of runtimeCalls(run)) assert.equal('base_class' in c.body, false, command);
  }
  // forged fields: a client key in the tool input, a base_class or decline_check on the event: never a lowering
  for (const extra of [{ tool_input: { command: CMD, base_class: { type: 'process' } } }, { tool_input: { command: CMD, decline_check: { state: 'clear' } } }, { lowered: { type: 'process' } }, { base_class: { type: 'deploy' } }, { decline_check: { state: 'clear' } }, { tool_input: { command: CMD, extra: 1 } }]) {
    const run = await runHook((p, b) => (p === '/v1/agent/runtime' ? allow(clearFor(b)) : protectedPath(p, b)), ev(CMD, extra));
    const probes = runtimeCalls(run).filter((c) => 'base_class' in c.body);
    assert.equal(probes.length, extra.tool_input && 'extra' in extra.tool_input || extra.tool_input && ('base_class' in extra.tool_input || 'decline_check' in extra.tool_input) ? 0 : 1, JSON.stringify(extra));
    if (probes.length) assert.deepEqual(probes[0].body.base_class.type, 'deploy', 'base_class names the master class, whatever the event says');
  }
});

test('K1/K2: base_class can only name the original class; the clearance is per call', async () => {
  const run = await runHook((p, b) => (p === '/v1/agent/runtime' ? allow(clearFor(b)) : protectedPath(p, b)), ev("git grep -c 'production' main"));
  const probe = runtimeCalls(run)[0].body;
  assert.equal(probe.base_class.type, 'process', 'the word production alone sets the surface, not the type');
  assert.ok(probe.base_class.surfaces.includes('production'));
  assert.equal(probe.surfaces.includes('production'), false);
  // two calls in one session: each gets its own question
  const a = await runHook((p, b) => (p === '/v1/agent/runtime' ? allow(clearFor(b)) : protectedPath(p, b)), ev());
  const b = await runHook((p, bb) => (p === '/v1/agent/runtime' ? allow() : protectedPath(p, bb)), ev());
  assert.equal(runtimeCalls(a).length, 1);
  assert.equal(runtimeCalls(b).length, 2);
});

test('D4: with every local hook state file deleted the live answer decides, and a lowering stores nothing', async () => {
  const home1 = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-d1d-h1-'));
  const home2 = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-d1d-h2-'));
  try {
    const lowered = await runHook((p, b) => (p === '/v1/agent/runtime' ? allow(clearFor(b)) : protectedPath(p, b)), ev(), { home: home1, key: 'zq0123456789abcdef' });
    const plain = await runHook((p, b) => (p === '/v1/agent/runtime' ? allow() : protectedPath(p, b)), ev(), { home: home2, key: 'zq0123456789abcdef' });
    const list = (dir) => { const out = []; const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const f = path.join(d, e.name); if (e.isDirectory()) walk(f); else out.push(path.relative(dir, f)); } }; walk(dir); return out.sort(); };
    const mine = list(home1);
    const theirs = list(home2);
    assert.ok(mine.every((f) => theirs.includes(f)), `lowering stored: ${mine.filter((f) => !theirs.includes(f))}`);
    assert.equal(runtimeCalls(lowered).length, 1);
    assert.equal(runtimeCalls(plain).length, 2);
    // the second answer is decline-stands (no clearance) in a fresh home: held at master's class
    fs.rmSync(home1, { recursive: true, force: true });
    fs.mkdirSync(home1, { recursive: true });
    const again = await runHook(() => review(), ev("git grep -c 'deploy' main", {}), { home: home1, key: 'zq0123456789abcdef' });
    assert.ok(asked(again));
  } finally {
    fs.rmSync(home1, { recursive: true, force: true });
    fs.rmSync(home2, { recursive: true, force: true });
  }
});

test('D6/D7: a queued declined report blocks the lowering; a pending hold is resumed before the control path', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-d1d-h3-'));
  const key = 'zq00112233445566aa';
  try {
    const scope = { apiKey: key, baseUrl: 'https://api.example.test', agentId: 'agent-one' };
    const hold = hostState.recordHold(scope, {
      host: 'claude-code', harness: 'claude-code', session_id: 'x', host_session_id: 'x', agent_id: 'agent-one', correlation: 'b'.repeat(32), target: 'a'.repeat(64), tool_use_id: 'tu', generation_id: null,
      tool_name: 'Bash', hook_event: 'PreToolUse', mode: 'ask', gate_receipt_id: 'gate_x', decision_id: null, asked_at: new Date().toISOString(), pre_action_event_id: null, proof_required: false,
      proof_fields: [], expires_at: null, withCode: false, action: { action: 'a', target: 'b', type: 'deploy', surfaces: ['production'] },
    }, home);
    // before any decline is queued the call is lowered (control, the stub clears)
    const free = await runHook((p, b) => (p === '/v1/agent/runtime' ? allow(clearFor(b)) : protectedPath(p, b)), ev(), { home, key });
    assert.equal(runtimeCalls(free).filter((c) => 'base_class' in c.body).length, 1);
    hostState.updateHold(scope, hold.id, (cur) => ({ ...cur, state: 'resolved', outbox: { report: { verdict: 'declined', host: cur.host, host_session_id: cur.host_session_id, hook_event: null, pre_action_event_id: null, asked_at: new Date().toISOString(), answered_at: new Date().toISOString() }, commit: null, attempts: 0, next_at: Date.now() + 3600e3 } }), home);
    const queued = await runHook((p, b) => (p === '/v1/agent/runtime' ? allow(clearFor(b)) : protectedPath(p, b)), ev(CMD, { tool_use_id: 't9' }), { home, key });
    assert.equal(runtimeCalls(queued).filter((c) => 'base_class' in c.body).length, 0, 'D6: no lowering, no base_class');
    assert.equal(runtimeCalls(queued)[0].body.type, 'deploy');
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
  // D7: resumeWaitingHold runs before the control path (and so before any lowered question) in the hook's source order
  const src = fs.readFileSync(path.join(ROOT, 'src', 'hook-pre-action.ts'), 'utf8');
  assert.ok(src.indexOf('await resumeWaitingHold(') > 0 && src.indexOf('await resumeWaitingHold(') < src.indexOf('const control = async'), 'D7 order');
  assert.ok(src.indexOf('const lowerable =') > src.indexOf('await resumeWaitingHold('), 'the lowered question is built after the resume');
});

test('G2: a fault in the reading, the count proof or the mapper module gives no lowering (master asks and holds)', () => {
  const real = mapper.evaluateSeatbeltShell;
  let n = 0;
  // the hook keeps one answer per text and folder (master's memo): every variant is a new text
  const classify = () => classifyTool({ tool_name: 'Bash', tool_input: { command: `git grep -c 'commit' main${n += 1}` }, cwd: ROOT }, { cwd: ROOT, lowering: true });
  try {
    assert.ok(classify().lowered, 'baseline: lowered when the reading works');
    mapper.evaluateSeatbeltShell = () => { throw new Error('forced'); };
    const thrown = classify();
    assert.equal(thrown.lowered, undefined);
    assert.equal(thrown.protected, true, 'master asks');
    // a reading whose slice is malformed (the count proof throws)
    mapper.evaluateSeatbeltShell = (...args) => { const d = real(...args); return { ...d, slice: { ...d.slice, words: null } }; };
    assert.equal(classify().lowered, undefined);
    mapper.evaluateSeatbeltShell = (...args) => { const d = real(...args); return { ...d, slice: undefined }; };
    assert.equal(classify().lowered, undefined);
    // a budget stop / error: the mapper's own stop (a hit) and a parse other than ok
    mapper.evaluateSeatbeltShell = (...args) => { const d = real(...args); return { ...d, parse: 'too_large', hits: [{ category: 'Sx', reason: 'budget_time' }] }; };
    assert.equal(classify().lowered, undefined);
    mapper.evaluateSeatbeltShell = (...args) => { const d = real(...args); return { ...d, parse: 'dynamic' }; };
    assert.equal(classify().lowered, undefined);
    mapper.evaluateSeatbeltShell = (...args) => { const d = real(...args); return { ...d, flags: ['x'] }; };
    assert.equal(classify().lowered, undefined);
    mapper.evaluateSeatbeltShell = (...args) => { const d = real(...args); return { ...d, slice: { ...d.slice, ok: false } }; };
    assert.equal(classify().lowered, undefined);
  } finally {
    mapper.evaluateSeatbeltShell = real;
  }
});
