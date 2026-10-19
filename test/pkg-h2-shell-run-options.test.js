'use strict';

// R2 (job tue-r1-pwsh-fix, Codex review of 24f17b60): the key of a plain Monitor or PowerShell call left out
// `timeout`, `timeout_ms` and `run_in_background`, so `{script:'sleep 5; git push origin main', timeout_ms:1000}`
// and `timeout_ms:60000` shared normalizedHookAction, stableToolCorrelation and exactHookTarget, and an
// approval of the short run was consumed by the long one (host-approval resumeWaitingHold). Now, for Monitor
// and PowerShell in every form (command or script), the three options are part of the key of the call:
// normalizedHookAction, stableToolCorrelation, exactHookTarget, the hold lookup and the seatbelt receipt key.
// `description` stays out of the key. A secret never reaches a key; text after a redacted span still changes it.
// Bash's own `timeout` field is as it was (round-2 list). Dummy secrets are generated at runtime.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash, randomBytes } = require('node:crypto');
const { mkdtempSync, readFileSync, readdirSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const { exactHookTarget, stableToolCorrelation } = require('../dist/hook-contract.js');
const { normalizedHookAction } = require('../dist/normalized-action.js');
const { findHolds, recordHold } = require('../dist/host-approval-state.js');
const { resumeWaitingHold } = require('../dist/host-approval.js');
const { writeSeatbeltReceipt } = require('../dist/seatbelt/record.js');

const salt = randomBytes(32);
function keys(ev, session = 's') {
  const n = normalizedHookAction(ev, { salt, deadlineAt: Date.now() + 5000 });
  return {
    normalized: JSON.stringify(n),
    hash: n.tool_input.command_sha256 || n.tool_input.input_sha256 || '',
    exact: n.tool_input.exact_hmac || '',
    truncated: n.truncated === true,
    correlation: stableToolCorrelation({ session_id: session, ...ev }),
    target: exactHookTarget(ev),
    kind: n.tool_kind,
  };
}
// Every identifier a hold or an approval is found by.
function assertAllDiffer(a, b, label) {
  assert.notEqual(a.normalized, b.normalized, `${label}: normalizedHookAction`);
  assert.notEqual(a.target, b.target, `${label}: exactHookTarget`);
  if (!a.truncated && !b.truncated) {
    assert.notEqual(a.hash, b.hash, `${label}: hash`);
    assert.notEqual(a.correlation, b.correlation, `${label}: stableToolCorrelation`);
  } else if (a.truncated && b.truncated) {
    assert.notEqual(a.exact, b.exact, `${label}: exact_hmac`);
  }
}
// Calls whose command text differs: the action and its correlation differ (the target never read the text).
function assertTextDiffers(a, b, label) {
  assert.notEqual(a.normalized, b.normalized, `${label}: normalizedHookAction`);
  if (!a.truncated && !b.truncated) {
    assert.notEqual(a.hash, b.hash, `${label}: hash`);
    assert.notEqual(a.correlation, b.correlation, `${label}: stableToolCorrelation`);
  } else if (a.truncated && b.truncated) {
    assert.notEqual(a.exact, b.exact, `${label}: exact_hmac`);
  }
}
function assertAllSame(a, b, label) {
  assert.equal(a.normalized, b.normalized, `${label}: normalizedHookAction`);
  assert.equal(a.correlation, b.correlation, `${label}: stableToolCorrelation`);
  assert.equal(a.target, b.target, `${label}: exactHookTarget`);
}

const TOOLS = ['Monitor', 'PowerShell', 'monitor', 'POWERSHELL', 'Monitor ', ' PowerShell'];
const FORMS = [['command', (text) => ({ command: text })], ['script', (text) => ({ script: text })]];
const FIELDS = [['timeout', 1000, 60000], ['timeout_ms', 1000, 60000], ['run_in_background', false, true]];
const COMMAND = 'sleep 5; git push origin main';

test('R2 keys: Monitor and PowerShell x (command, script) x (timeout, timeout_ms, run_in_background): a different option is a different key everywhere', () => {
  let pairs = 0;
  for (const tool_name of TOOLS) {
    for (const [form, make] of FORMS) {
      for (const [field, one, two] of FIELDS) {
        const a = { tool_name, tool_input: { ...make(COMMAND), [field]: one } };
        const b = { tool_name, tool_input: { ...make(COMMAND), [field]: two } };
        const label = `${JSON.stringify(tool_name)} ${form} ${field}`;
        const ka = keys(a);
        assert.equal(ka.kind, 'shell', label);
        assertAllDiffer(ka, keys(b), label);
        assert.deepEqual(keys(a), ka, `${label}: a retry keeps its key`);
        // The option present against absent is another call too, and so is the same option under another name.
        assertAllDiffer(ka, keys({ tool_name, tool_input: make(COMMAND) }), `${label} vs none`);
        const other = FIELDS.find(([name]) => name !== field);
        assertAllDiffer(ka, keys({ tool_name, tool_input: { ...make(COMMAND), [other[0]]: other[1] } }), `${label} vs ${other[0]}`);
        // Both options: each one counts.
        const both1 = keys({ tool_name, tool_input: { ...make(COMMAND), timeout: 1000, timeout_ms: 1000 } });
        const both2 = keys({ tool_name, tool_input: { ...make(COMMAND), timeout: 1000, timeout_ms: 2000 } });
        assertAllDiffer(both1, both2, `${label} both`);
        pairs += 1;
      }
    }
  }
  assert.equal(pairs, TOOLS.length * FORMS.length * FIELDS.length);
});

test('R2 keys: the issue pair, with the host\'s own session and pre/post event names', () => {
  const short = { tool_name: 'Monitor', tool_input: { script: COMMAND, timeout_ms: 1000 } };
  const long = { tool_name: 'Monitor', tool_input: { script: COMMAND, timeout_ms: 60000 } };
  assertAllDiffer(keys(short), keys(long), 'Monitor script timeout_ms');
  for (const hook_event_name of ['PreToolUse', 'PostToolUse', 'beforeShellExecution']) {
    assert.notEqual(exactHookTarget({ ...short, hook_event_name }), exactHookTarget({ ...long, hook_event_name }), hook_event_name);
  }
  // The pre and the post event of one call give the same target.
  assert.equal(exactHookTarget({ ...short, hook_event_name: 'PreToolUse' }), exactHookTarget({ ...short, hook_event_name: 'PostToolUse' }));
});

test('R2 keys: `description` is not part of the key; a call with no option keeps exactly the hash it had', () => {
  for (const tool_name of ['Monitor', 'PowerShell']) {
    for (const [form, make] of FORMS) {
      assertAllSame(keys({ tool_name, tool_input: { ...make(COMMAND), description: 'a' } }), keys({ tool_name, tool_input: { ...make(COMMAND), description: 'b' } }), `${tool_name} ${form} description`);
      assertAllSame(keys({ tool_name, tool_input: { ...make(COMMAND), description: 'a', timeout: 5 } }), keys({ tool_name, tool_input: { ...make(COMMAND), description: 'b', timeout: 5 } }), `${tool_name} ${form} description with timeout`);
      assertAllDiffer(keys({ tool_name, tool_input: { ...make(COMMAND), description: 'a', timeout: 5 } }), keys({ tool_name, tool_input: { ...make(COMMAND), description: 'a', timeout: 6 } }), `${tool_name} ${form} timeout under one description`);
      assertAllSame(keys({ tool_name, tool_input: make(COMMAND) }), keys({ tool_name, tool_input: { ...make(COMMAND), description: 'x' } }), `${tool_name} ${form} none vs description`);
    }
  }
  // 3.9.104's hash of a plain call without options is unchanged, byte for byte.
  const plain = normalizedHookAction({ tool_name: 'PowerShell', tool_input: { command: 'ls' } }, { salt });
  assert.equal(plain.tool_input.command_sha256, createHash('sha256').update('marrow-normalized-action-v3\nshell-tool\n"PowerShell"\nls').digest('hex'));
  const bash = normalizedHookAction({ tool_name: 'Bash', tool_input: { command: 'ls' } }, { salt });
  assert.equal(bash.tool_input.command_sha256, createHash('sha256').update('marrow-normalized-action-v3\nshell\nls').digest('hex'));
});

test('R2 keys: Bash is as it was (its own timeout field is not touched); Bash, Monitor and PowerShell never share a key', () => {
  const bash = (input) => keys({ tool_name: 'Bash', tool_input: input });
  assertAllSame(bash({ command: 'ls', timeout: 1000 }), bash({ command: 'ls', timeout: 2000 }), 'Bash timeout (equal to 3.9.103; round-2 list)');
  for (const field of ['timeout', 'timeout_ms', 'run_in_background']) {
    const monitor = keys({ tool_name: 'Monitor', tool_input: { command: COMMAND, [field]: field === 'run_in_background' ? true : 5 } });
    const power = keys({ tool_name: 'PowerShell', tool_input: { command: COMMAND, [field]: field === 'run_in_background' ? true : 5 } });
    const sh = bash({ command: COMMAND, [field]: field === 'run_in_background' ? true : 5 });
    assertAllDiffer(monitor, power, `Monitor vs PowerShell ${field}`);
    assertAllDiffer(monitor, sh, `Monitor vs Bash ${field}`);
    assertAllDiffer(power, sh, `PowerShell vs Bash ${field}`);
  }
  // Option-free Monitor X stays different from Monitor X with an option whose rendering looks like command text.
  const text = 'ls\n{"timeout":5}';
  assertTextDiffers(keys({ tool_name: 'Monitor', tool_input: { command: text } }), keys({ tool_name: 'Monitor', tool_input: { command: 'ls', timeout: 5 } }), 'option text cannot be forged');
  assertTextDiffers(keys({ tool_name: 'Monitor', tool_input: { command: `{"timeout":5}\nls` } }), keys({ tool_name: 'Monitor', tool_input: { command: 'ls', timeout: 5 } }), 'option text cannot be forged (leading)');
});

test('R2 keys: irregular calls (both fields, an extra field, a WebSocket) were keyed by their whole input and still are', () => {
  for (const tool_name of ['Monitor', 'PowerShell']) {
    for (const [field, one, two] of FIELDS) {
      const a = keys({ tool_name, tool_input: { command: 'ls', script: 'a', [field]: one } });
      const b = keys({ tool_name, tool_input: { command: 'ls', script: 'a', [field]: two } });
      assert.equal(a.kind, 'other');
      assertAllDiffer(a, b, `${tool_name} command+script ${field}`);
      assertAllDiffer(keys({ tool_name, tool_input: { command: 'ls', ws: { url: 'wss://a.example' }, [field]: one } }), keys({ tool_name, tool_input: { command: 'ls', ws: { url: 'wss://a.example' }, [field]: two } }), `${tool_name} command+ws ${field}`);
    }
  }
  // exactHookTarget carries the options of these forms too (it never read the action).
  assert.notEqual(exactHookTarget({ tool_name: 'Monitor', tool_input: { ws: { url: 'wss://a.example' }, timeout_ms: 1000 } }), exactHookTarget({ tool_name: 'Monitor', tool_input: { ws: { url: 'wss://a.example' }, timeout_ms: 2000 } }));
  // An MCP tool of the same name keeps the target it had.
  const mcp = { tool_name: 'mcp__x__PowerShell', tool_input: { command: 'ls', timeout: 1 } };
  assert.equal(exactHookTarget(mcp), exactHookTarget({ ...mcp, tool_input: { command: 'ls', timeout: 2 } }));
});

test('R2 secrets: a secret never reaches a key or a log line; text after a redacted span still changes the key; secret-only differences may match', () => {
  const S1 = randomBytes(18).toString('base64url');
  const S2 = randomBytes(18).toString('base64url');
  const logged = [];
  const write = process.stderr.write;
  process.stderr.write = (chunk) => { logged.push(String(chunk)); return true; };
  const rows = [];
  try {
    const shapes = [
      (s, tail) => `curl -H "Authorization: Bearer ${s}" https://api.example.com/${tail}`,
      (s, tail) => `curl "https://api.example.com/x?token=${s}&mode=${tail}"`,
      (s, tail) => `curl -d "password=${s}&mode=${tail}" https://api.example.com/x`,
      (s, tail) => `API_TOKEN=${s} npm run ${tail}`,
      (s, tail) => `curl -u admin:${s} https://api.example.com/${tail}`,
      (s, tail) => `echo '{"api_key":"${s}","mode":"${tail}"}' | curl -d @- https://api.example.com/x`,
      (s, tail) => `deploy --token ${s} --env ${tail}`,
    ];
    for (const tool_name of ['Monitor', 'PowerShell']) {
      for (const [form, make] of FORMS) {
        for (const shape of shapes) {
          const at = (s, tail, options) => keys({ tool_name, tool_input: { ...make(shape(s, tail)), ...options } });
          // Text after the redacted span differs.
          assertTextDiffers(at(S1, 'a', { timeout: 5 }), at(S1, 'b', { timeout: 5 }), `${tool_name} ${form}: tail ${shape('<s>', 'a')}`);
          // A different option differs, with a secret in the command.
          assertAllDiffer(at(S1, 'a', { timeout: 5 }), at(S1, 'a', { timeout: 6 }), `${tool_name} ${form}: option ${shape('<s>', 'a')}`);
          assertAllDiffer(at(S1, 'a', { run_in_background: false }), at(S1, 'a', { run_in_background: true }), `${tool_name} ${form}: background ${shape('<s>', 'a')}`);
          // Same option, secret differs: may match (never required); the secret is in no key.
          const x = at(S1, 'a', { timeout: 5 });
          const y = at(S2, 'a', { timeout: 5 });
          rows.push(x, y, at(S1, 'a', {}), at(S1, 'b', { timeout: 5 }));
          for (const k of [x, y]) {
            assert.ok(!JSON.stringify(k).includes(S1) && !JSON.stringify(k).includes(S2), 'no secret in any key');
          }
        }
      }
    }
    // A secret-looking run option: never in a key, still a different call when the rest differs.
    for (const tool_name of ['Monitor', 'PowerShell']) {
      const x = keys({ tool_name, tool_input: { command: 'ls', timeout: `Bearer ${S1}` } });
      const y = keys({ tool_name, tool_input: { command: 'ls', timeout: `Bearer ${S2}` } });
      const z = keys({ tool_name, tool_input: { command: 'ls', timeout: `Bearer ${S1} more` } });
      for (const k of [x, y, z]) assert.ok(!JSON.stringify(k).includes(S1) && !JSON.stringify(k).includes(S2), 'no secret in a key (option)');
      assert.ok(!exactHookTarget({ tool_name, tool_input: { command: 'ls', timeout: `Bearer ${S1}` } }).includes(S1));
      assertAllDiffer(x, keys({ tool_name, tool_input: { command: 'ls', timeout: 5 } }), `${tool_name}: a credential option is not a plain number`);
    }
  } finally { process.stderr.write = write; }
  assert.ok(rows.length > 100);
  assert.deepEqual(logged.filter((line) => line.includes(S1) || line.includes(S2)), [], 'no secret in any log line');
});

test('R2 secrets: a host text with a trimmed edge (non-ASCII space) still keys its options', () => {
  for (const tool_name of ['Monitor', 'PowerShell']) {
    const text = `${COMMAND} `;
    assertAllDiffer(keys({ tool_name, tool_input: { command: text, timeout: 1 } }), keys({ tool_name, tool_input: { command: text, timeout: 2 } }), `${tool_name} untrimmed host text`);
    assertTextDiffers(keys({ tool_name, tool_input: { command: text, timeout: 1 } }), keys({ tool_name, tool_input: { command: COMMAND, timeout: 1 } }), `${tool_name} untrimmed vs trimmed`);
  }
});

// ------------------------------------------------------------------ consumers: hold lookup and consume, receipts

const scopeFor = () => ({ apiKey: `dummy-${randomBytes(8).toString('hex')}`, baseUrl: 'https://api.example.test', agentId: null });
const identity = (ev) => ({ correlation: stableToolCorrelation({ session_id: 's', ...ev }), target: exactHookTarget(ev) });
const holdFor = (ev, receipt) => ({
  host: 'claude-code', harness: 'claude-code', session_id: 's', host_session_id: 's', agent_id: null, ...identity(ev),
  tool_use_id: null, generation_id: null, tool_name: ev.tool_name, hook_event: 'PreToolUse', mode: 'wait', gate_receipt_id: receipt, decision_id: null,
  asked_at: new Date().toISOString(), pre_action_event_id: null, proof_required: false, proof_fields: [], expires_at: null, withCode: false,
  action: { action: 'a', target: 't', type: 'review', surfaces: ['github'] },
});

test('R2 hold lookup: a hold of the 1000 ms call is never found by the 60000 ms call (and the two holds do not replace each other)', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-r2-holds-'));
  try {
    const scope = scopeFor();
    for (const tool_name of ['Monitor', 'PowerShell']) {
      const short = { tool_name, tool_input: { script: COMMAND, timeout_ms: 1000 } };
      const long = { tool_name, tool_input: { script: COMMAND, timeout_ms: 60000 } };
      recordHold(scope, holdFor(short, `gate-${tool_name}-short`), home);
      const query = (ev) => ({ ...identity(ev), sessionId: 's', mode: 'wait', states: ['open'] });
      assert.equal(findHolds(scope, query(short), home).length, 1, `${tool_name}: the same call finds its hold`);
      assert.equal(findHolds(scope, query(long), home).length, 0, `${tool_name}: the long call finds nothing`);
      recordHold(scope, holdFor(long, `gate-${tool_name}-long`), home);
      assert.deepEqual(findHolds(scope, query(short), home).map((h) => h.gate_receipt_id), [`gate-${tool_name}-short`], 'the short hold was not replaced');
      assert.deepEqual(findHolds(scope, query(long), home).map((h) => h.gate_receipt_id), [`gate-${tool_name}-long`]);
    }
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test('R2 host approval: an approved hold for timeout_ms 1000 is NOT consumed by the timeout_ms 60000 call (resumeWaitingHold)', async () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-r2-resume-'));
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init = {}) => {
    const path = new URL(String(url)).pathname;
    calls.push(path);
    const receipt = decodeURIComponent(path.split('/')[4] || '');
    return Response.json({ data: { gate_receipt_id: receipt, state: 'approved', decision_id: 'decision-r2', approval_source: 'host_prompt', approval_trust: 'client_attested', approval_answered_by: 'host_operator', terminal: false } });
  };
  try {
    const scope = scopeFor();
    for (const tool_name of ['Monitor', 'PowerShell']) {
      calls.length = 0;
      const ctx = { apiKey: scope.apiKey, baseUrl: scope.baseUrl, sessionId: 's', harness: 'claude-code', host: 'claude-code', hostSessionId: 's', home };
      const short = { tool_name, tool_input: { script: COMMAND, timeout_ms: 1000 } };
      const long = { tool_name, tool_input: { script: COMMAND, timeout_ms: 60000 } };
      recordHold(scope, holdFor(short, `gate-resume-${tool_name}`), home);
      const longTry = await resumeWaitingHold(ctx, { ...identity(long), toolUseId: 'long-1', generationId: null });
      assert.equal(longTry, null, `${tool_name}: the long call does not resume the short call's hold`);
      assert.deepEqual(calls, [], `${tool_name}: the approval was not even read for the long call`);
      const shortTry = await resumeWaitingHold(ctx, { ...identity(short), toolUseId: 'short-1', generationId: null });
      assert.equal(shortTry && shortTry.kind, 'allow', `${tool_name}: the approved call is allowed once`);
      assert.equal(calls.length, 1);
      // The approval was used by the call it was for: neither call finds it open again.
      assert.equal(await resumeWaitingHold(ctx, { ...identity(short), toolUseId: 'short-2', generationId: null }), null);
      assert.equal(await resumeWaitingHold(ctx, { ...identity(long), toolUseId: 'long-2', generationId: null }), null);
    }
  } finally {
    globalThis.fetch = originalFetch;
    rmSync(home, { recursive: true, force: true });
  }
});

test('R2 seatbelt receipt: the receipt action_key of the 1000 ms and the 60000 ms call differ; a description-only change does not', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-r2-receipt-'));
  try {
    const key = (event) => {
      const status = writeSeatbeltReceipt({ v: 1, mode: 'account', enforcement: 'watch', harness: 'claude-code', decision: 'pass', category: 'none', rule: 'none', reasons: [], flags: [], parse: 'ok', latency_ms: 1 },
        { tool_name: event.tool_name, tool_input: event.tool_input, session: 's' }, { home });
      assert.equal(status, 'written');
      const dir = join(home, '.marrow', 'seatbelt', 'receipts');
      const lines = readFileSync(join(dir, readdirSync(dir).sort().pop()), 'utf8').trim().split('\n');
      return JSON.parse(lines[lines.length - 1]).action_key;
    };
    for (const tool_name of ['Monitor', 'PowerShell']) {
      for (const [form, make] of FORMS) {
        for (const [field, one, two] of FIELDS) {
          assert.notEqual(key({ tool_name, tool_input: { ...make(COMMAND), [field]: one } }), key({ tool_name, tool_input: { ...make(COMMAND), [field]: two } }), `${tool_name} ${form} ${field}`);
        }
        assert.equal(key({ tool_name, tool_input: { ...make(COMMAND), description: 'a' } }), key({ tool_name, tool_input: { ...make(COMMAND), description: 'b' } }), `${tool_name} ${form} description`);
      }
    }
  } finally { rmSync(home, { recursive: true, force: true }); }
});
