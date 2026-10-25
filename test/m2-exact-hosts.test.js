'use strict';
// M2 end to end, one hook process per host event (as a real host runs it), scripted Marrow API
// (test/support/host-approval-fetch-mock.cjs): on every host (Claude Code, Codex, Cursor shell, Gemini, Grok,
// Cline, Windsurf) and on Cursor preToolUse, an owner approval of held action A never releases a different
// action B (an id swapped after the approval): B gets its own runtime gate and A's hold stays open. The exact
// retry of A, and A with only its OTP changed, are released once. Secrets, the API key and the device salt are
// generated at run time and never printed; no slice of them is in any request body, output or local file.
const assert = require('node:assert/strict');
const test = require('node:test');
const { writeOfficialHostConfigs } = require('./support/official-host-config.cjs');
writeOfficialHostConfigs();
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const MOCK = join(__dirname, 'support', 'host-approval-fetch-mock.cjs');
const FIXTURES = join(__dirname, 'fixtures', 'host-approvals');
const fixture = (name) => JSON.parse(readFileSync(join(FIXTURES, name), 'utf8'));

function hostRuntime(receipt) {
  return {
    ok: true,
    action: 'classified Bash action: deploy on production',
    decision_id: `decision-${receipt}`,
    runtime_authorization: { id: receipt, kind: 'durable_gate_receipt', durable: true, decision_state: 'created', decision_creation_required: false, decision_id: `decision-${receipt}` },
    gate_receipt: { id: receipt, decision: 'review_required', required: true, owner_approval_required: true, expires_at: '2030-01-01T00:30:00.000Z' },
    proof_pack: { required: false, fields: [], complete: true },
    completion_contract: {
      decision_id: `decision-${receipt}`, decision_creation_required: false, decision_state: 'created',
      owner_approval_required: true, arbitration_receipt_required: false, gate_receipt_required: true,
      required_commit_fields: ['decision_id', 'success', 'outcome', 'gate_receipt_id'],
      owner_approval: {
        mode: 'ordinary_non_arbitrated', proof_path: null, proof_shape: null, dashboard_receipt_required: false,
        trusted_completion_receipt_required: true, receipt_field: 'owner_approval_receipt_id',
        approval_endpoint: '/v1/dashboard/enforcement/owner-approval', approval_authority: 'host_operator_or_dashboard_owner',
        approval_status_endpoint: `/v1/agent/gate-receipts/${receipt}/owner-approval`, approval_status_poll_after_ms: 5000,
        host_approval_endpoint: `/v1/agent/gate-receipts/${receipt}/host-approval`, host_approval_accepted: true,
        host_approval_trust: 'client_attested', approval_categories: ['production_deploy'],
        verified_approval_required: false, verified_approval_categories: [],
      },
    },
    risk_gate: { allow: true, decision: 'review_required', enforced: true, gate_required: true, gate_receipt_id: receipt, risk_level: 'high', reasons: [{ message: 'Needs approval.' }] },
    gate_receipt_id: receipt,
    exact_next_action: 'Obtain explicit owner approval before this action runs.',
  };
}

function harness(extraEnv = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-m2-hosts-'));
  const home = join(dir, 'home');
  const mockDir = join(dir, 'mock');
  mkdirSync(home, { mode: 0o700 });
  writeOfficialHostConfigs(home);
  mkdirSync(mockDir);
  const apiKey = `mrw_test_${crypto.randomBytes(16).toString('hex')}`;
  let config = {};
  const setConfig = (next) => { config = { ...config, ...next }; writeFileSync(join(mockDir, 'config.json'), JSON.stringify(config)); };
  const requests = () => {
    const path = join(mockDir, 'requests.jsonl');
    return existsSync(path) ? readFileSync(path, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line)) : [];
  };
  const outputs = [];
  const run = (entrypoint, payload, env = {}) => {
    const result = spawnSync(process.execPath, [CLI, entrypoint], {
      input: JSON.stringify(payload),
      env: {
        PATH: process.env.PATH, HOME: home, MARROW_API_KEY: apiKey, MARROW_BASE_URL: 'https://api.example.test',
        MARROW_AGENT_ID: 'agent-one', MARROW_HOOK_BACKGROUND_NUDGE: 'false', MARROW_PASSIVE_TOKEN_USAGE: 'false',
        MARROW_TEST_MOCK_DIR: mockDir, NODE_OPTIONS: `--require=${MOCK}`, ...extraEnv, ...env,
      },
      encoding: 'utf8',
      timeout: 30_000,
    });
    assert.equal(result.error, undefined);
    const output = result.stdout.trim();
    outputs.push(result.stdout, result.stderr);
    assert.equal(output.includes(apiKey) || result.stderr.includes(apiKey), false, 'the key never appears in hook output');
    let json = null;
    try { json = output ? JSON.parse(output) : null; } catch { json = null; }
    return { status: result.status, stdout: output, stderr: result.stderr, json };
  };
  const state = () => {
    const path = join(home, '.marrow', 'host-approvals', 'state.json');
    return existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : { holds: {} };
  };
  const holdFor = (receipt) => Object.values(state().holds || {}).find((hold) => hold.gate_receipt_id === receipt) || null;
  const files = () => {
    const out = [];
    const walk = (path) => {
      let st;
      try { st = statSync(path); } catch { return; }
      if (st.isDirectory()) { for (const name of readdirSync(path)) walk(join(path, name)); return; }
      if (st.isFile() && st.size < 4_000_000) out.push(readFileSync(path, 'latin1'));
    };
    walk(home);
    return out;
  };
  return { dir, home, run, setConfig, requests, state, holdFor, outputs, files, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

const runtimes = (h) => h.requests().filter((r) => r.path === '/v1/agent/runtime' && /^classified \S+ action: /.test(r.body?.action || ''));
const uid = (prefix) => `${prefix}${crypto.randomBytes(4).toString('hex')}`;

// Host event builders: (command or MCP call) -> pre-tool event; `post` -> the matching post-tool event.
const HOSTS = [
  { host: 'claude-code', pre: 'claude-pre-action-hook', event: (c, id) => ({ ...fixture('claude-pre-tool-use.json'), permission_mode: 'dontAsk', tool_use_id: id, tool_input: { command: c, description: 'held' } }),
    mcpEvent: (tool, input, id) => ({ ...fixture('claude-pre-tool-use.json'), permission_mode: 'dontAsk', tool_use_id: id, tool_name: `mcp__${tool.replace(':', '__')}`, tool_input: input }),
    post: 'claude-hook', postEvent: (c, id) => ({ ...fixture('claude-post-tool-use.json'), tool_use_id: id, tool_input: { command: c, description: 'held' } }) },
  { host: 'codex', pre: 'codex-pre-action-hook', env: { MARROW_TEST_HOST_PROCESS: '/usr/local/bin/codex exec deploy' }, event: (c, id) => ({ ...fixture('codex-pre-tool-use.json'), tool_use_id: id, tool_input: { command: c } }),
    post: 'codex-hook', postEvent: (c, id) => ({ ...fixture('codex-post-tool-use.json'), tool_use_id: id, tool_input: { command: ['bash', '-lc', c] } }) },
  { host: 'cursor (beforeShellExecution, cloud agent)', pre: 'cursor-pre-action-hook', event: (c, id) => ({ ...fixture('cursor-before-shell.json'), generation_id: id, command: c }) },
  { host: 'gemini', pre: 'gemini-pre-action-hook', event: (c) => ({ ...fixture('gemini-before-tool.json'), tool_input: { command: c } }),
    post: 'gemini-hook', postEvent: (c) => ({ session_id: fixture('gemini-before-tool.json').session_id, hook_event_name: 'AfterTool', tool_name: 'run_shell_command', tool_input: { command: c }, tool_response: { llmContent: 'ok' } }) },
  { host: 'grok', pre: 'grok-pre-action-hook', event: (c, id) => ({ ...fixture('grok-pre-tool-use.json'), toolUseId: id, toolInput: { command: c } }),
    post: 'grok-hook', postEvent: (c, id) => ({ hookEventName: 'PostToolUse', sessionId: fixture('grok-pre-tool-use.json').sessionId, toolUseId: id, toolName: 'run_terminal_command', toolInput: { command: c }, toolResult: { success: true } }) },
  { host: 'cline', pre: 'cline-pre-action-hook', event: (c) => ({ hookName: 'PreToolUse', taskId: 'task-m2', preToolUse: { toolName: 'execute_command', parameters: { command: c } } }) },
  { host: 'windsurf', pre: 'windsurf-pre-action-hook', event: (c, id) => ({ agent_action_name: 'pre_run_command', trajectory_id: 'traj-m2', execution_id: id, tool_info: { command_line: c, cwd: '/home/operator/project' } }) },
  { host: 'cursor (preToolUse, cloud agent)', pre: 'cursor-pre-action-hook', event: (c, id) => ({ ...fixture('cursor-pre-tool-use.json'), tool_use_id: id, tool_input: { command: c, working_directory: '/home/operator/project' } }),
    mcpEvent: (tool, input, id) => ({ ...fixture('cursor-pre-tool-use.json'), tool_use_id: id, tool_name: `MCP:${tool}`, tool_input: input }) },
];

const camel = (tag) => `PaymentsServiceBlueGreen${tag}${crypto.randomInt(10, 99)}`;
const sha40 = () => crypto.randomBytes(20).toString('hex');
// A dummy URL password made at run time (never printed).
const urlPassword = () => `p${crypto.randomBytes(9).toString('base64url')}`;
const mixed24 = () => { let v; do { v = crypto.randomBytes(18).toString('base64').replace(/[^A-Za-z0-9]/g, '').slice(0, 24); } while (!/[a-z]/.test(v) || !/[A-Z]/.test(v) || !/[0-9]/.test(v) || v.length < 24); return v; };
// [label, held A, swapped B, expect B released (only the lowercase control is a different action that was never merged)]
const SWAPS = () => [
  ['R1 kubectl delete deployment <CamelCase+digit>', `kubectl delete deployment ${camel('A')}`, `kubectl delete deployment ${camel('B')}`],
  ['R2 git push -f <sha40>:main', `git push -f origin ${sha40()}:main`, `git push -f origin ${sha40()}:main`],
  ['R4 aws s3api delete-object --key <path>', 'aws s3api delete-object --bucket prod-assets --key reports/q1.csv', 'aws s3api delete-object --bucket prod-assets --key reports/all.csv'],
  ['H4 trailing CR', 'git push -f origin main\r', 'git push -f origin main'],
  ['H1 printf word join into sh', `printf '%s\\n' 'git push -f' origin main | sh`, `printf '%s\\n' git push -f origin main | sh`],
  ['C0 control: lowercase names', 'kubectl delete deployment payments-blue-green-a', 'kubectl delete deployment payments-blue-green-b'],
  // M2-R1: `#` / `?` end the URL authority, so `deploy:443#@host` is host deploy, port 443 (no password).
  ['M2-R1 # in URL userinfo', `git push -f https://deploy:${urlPassword()}@github.com/acme/proj.git main`, 'git push -f https://deploy:443#@github.com/acme/proj.git main'],
  ['M2-R1 ? in URL userinfo', `git push -f https://deploy:${urlPassword()}@github.com/acme/proj.git main`, 'git push -f https://deploy:443?@github.com/acme/proj.git main'],
];
const MCP_SWAPS = () => [
  ['R7 MCP charge id', ['stripe:create_refund', { charge: `ch_${mixed24()}`, amount: 500 }], ['stripe:create_refund', { charge: `ch_${mixed24()}`, amount: 500 }]],
  ['R7 MCP key (ambiguous name)', ['s3:delete_object', { bucket: 'prod-assets', key: 'reports/q1.csv' }], ['s3:delete_object', { bucket: 'prod-assets', key: 'reports/all.csv' }]],
];

/** Hold A, approve it, run B: B must be gated fresh and A's hold must stay open; then A's exact retry is released once. */
function exploitRound(spec, buildA, buildB, label) {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime('gate-wait'), status: { 'gate-wait': 'pending' } });
    const held = h.run(spec.pre, buildA(uid('a-')), spec.env);
    assert.ok(h.holdFor('gate-wait'), `${spec.host} / ${label}: A is held (${held.stdout || held.stderr})`.slice(0, 300));
    assert.equal(runtimes(h).length, 1, `${spec.host} / ${label}: one gate for A`);
    // The owner approves A out of band; the agent then runs B.
    h.setConfig({ status: { 'gate-wait': 'approved', 'gate-other': 'pending' }, runtime: hostRuntime('gate-other') });
    h.run(spec.pre, buildB(uid('b-')), spec.env);
    const bGated = runtimes(h).length === 2;
    const aStillOpen = h.holdFor('gate-wait')?.state === 'open';
    // A's exact retry is released once on A's approval.
    h.setConfig({ runtime: hostRuntime('gate-third') });
    h.run(spec.pre, buildA(uid('a2-')), spec.env);
    const aReleased = h.holdFor('gate-wait')?.state === 'allowed' && runtimes(h).length === 2;
    return { bGated, aStillOpen, aReleased, h };
  } catch (error) {
    h.cleanup();
    throw error;
  }
}

test('A1/A2: on all 7 hosts and Cursor preToolUse, an approval of A never releases a swapped B; the exact retry of A runs once', () => {
  const counts = { flows: 0, bGated: 0, aStillOpen: 0, aReleased: 0 };
  for (const spec of HOSTS) {
    for (const [label, a, b] of SWAPS()) {
      const { bGated, aStillOpen, aReleased, h } = exploitRound(spec, (id) => spec.event(a, id), (id) => spec.event(b, id), label);
      h.cleanup();
      counts.flows += 1;
      assert.equal(bGated, true, `${spec.host} / ${label}: B reaches its own gate`);
      assert.equal(aStillOpen, true, `${spec.host} / ${label}: B never claims A's approval`);
      assert.equal(aReleased, true, `${spec.host} / ${label}: A's exact retry runs once on A's approval`);
      counts.bGated += 1; counts.aStillOpen += 1; counts.aReleased += 1;
    }
    if (!spec.mcpEvent) continue;
    for (const [label, a, b] of MCP_SWAPS()) {
      const { bGated, aStillOpen, aReleased, h } = exploitRound(spec, (id) => spec.mcpEvent(a[0], a[1], id), (id) => spec.mcpEvent(b[0], b[1], id), label);
      h.cleanup();
      counts.flows += 1;
      assert.equal(bGated, true, `${spec.host} / ${label}: B reaches its own gate`);
      assert.equal(aStillOpen, true, `${spec.host} / ${label}: B never claims A's approval`);
      assert.equal(aReleased, true, `${spec.host} / ${label}: A's exact retry runs once`);
      counts.bGated += 1; counts.aStillOpen += 1; counts.aReleased += 1;
    }
  }
  if (process.env.M2_REPORT) process.stdout.write(`# M2 A1 ${JSON.stringify(counts)}\n`);
  assert.equal(counts.flows, HOSTS.length * SWAPS().length + 2 * MCP_SWAPS().length);
});

test('A2: a retry that differs only in a certain credential (OTP, URL password, Bearer) is released once on every host', () => {
  const otp = () => String(crypto.randomInt(100000, 999999));
  const secret = () => crypto.randomBytes(18).toString('base64url');
  const rows = [
    ['OTP rotated', () => `npm publish --otp ${otp()}`],
    ['URL password', () => `git push -f https://deploy:${secret()}@git.example.test/acme/api.git main`],
    ['Bearer token', () => `curl -X DELETE -H "Authorization: Bearer ${secret()}" https://api.example.test/v1/projects/acme`],
  ];
  for (const spec of HOSTS) {
    for (const [label, make] of rows) {
      const h = harness();
      try {
        h.setConfig({ runtime: hostRuntime('gate-wait'), status: { 'gate-wait': 'pending' } });
        h.run(spec.pre, spec.event(make(), uid('a-')), spec.env);
        assert.ok(h.holdFor('gate-wait'), `${spec.host} / ${label}: held`);
        h.setConfig({ status: { 'gate-wait': 'approved' }, runtime: hostRuntime('gate-other') });
        h.run(spec.pre, spec.event(make(), uid('a2-')), spec.env);
        assert.equal(h.holdFor('gate-wait')?.state, 'allowed', `${spec.host} / ${label}: released on the approval`);
        assert.equal(runtimes(h).length, 1, `${spec.host} / ${label}: no new gate (no extra prompt)`);
      } finally { h.cleanup(); }
    }
  }
});

test('A3: the post-tool event settles the same hold (Claude PostToolUse, Codex argv, Gemini and Grok private payloads)', () => {
  for (const spec of HOSTS.filter((s) => s.post)) {
    const h = harness();
    try {
      const command = `kubectl delete deployment ${camel('A')}`;
      h.setConfig({ runtime: hostRuntime('gate-wait'), status: { 'gate-wait': 'pending' } });
      const id = uid('call-');
      h.run(spec.pre, spec.event(command, id), spec.env);
      h.setConfig({ status: { 'gate-wait': 'approved' } });
      const retry = uid('call-');
      h.run(spec.pre, spec.event(command, retry), spec.env);
      assert.equal(h.holdFor('gate-wait')?.state, 'allowed', `${spec.host}: released`);
      h.run(spec.post, spec.postEvent(command, retry), spec.env);
      assert.equal(h.holdFor('gate-wait')?.state, 'resolved', `${spec.host}: the post event settled the same hold`);
    } finally { h.cleanup(); }
  }
});

test('two agents on one machine: agent two never resumes agent one\'s approved hold', () => {
  const spec = HOSTS[0];
  const h = harness();
  try {
    const command = `kubectl delete deployment ${camel('A')}`;
    h.setConfig({ runtime: hostRuntime('gate-wait'), status: { 'gate-wait': 'pending' } });
    h.run(spec.pre, spec.event(command, uid('a-')));
    h.setConfig({ status: { 'gate-wait': 'approved' }, runtime: hostRuntime('gate-other') });
    h.run(spec.pre, spec.event(command, uid('b-')), { MARROW_AGENT_ID: 'agent-two' });
    assert.equal(runtimes(h).length, 2, 'agent two is gated on its own');
    assert.equal(h.holdFor('gate-wait')?.state, 'open');
  } finally { h.cleanup(); }
});

test('A4 (hosts): with an unsafe salt store the approval state keys the hashes: a held action is resumed on the same install, truncated or not; no note (P1 F2)', () => {
  const passwd = mkdtempSync(join(tmpdir(), 'm2-unsafe-passwd-'));
  try {
    mkdirSync(join(passwd, '.marrow', 'seatbelt'), { recursive: true, mode: 0o700 });
    chmodSync(join(passwd, '.marrow'), 0o700);
    const salt = join(passwd, '.marrow', 'seatbelt', 'salt');
    writeFileSync(salt, crypto.randomBytes(32), { mode: 0o600 });
    chmodSync(salt, 0o640);
    for (const spec of [HOSTS[0], HOSTS[1], HOSTS[4]]) {
      const h = harness({ SBT_PASSWD_HOME: passwd });
      try {
        for (const [receipt, command] of [['gate-wait', `kubectl delete deployment ${camel('A')}`], ['gate-plain', 'kubectl delete deployment payments-blue-green-a']]) {
          const before = runtimes(h).length;
          h.setConfig({ runtime: hostRuntime(receipt), status: { [receipt]: 'pending' } });
          const first = h.run(spec.pre, spec.event(command, uid('a-')), spec.env);
          assert.ok(h.holdFor(receipt), `${spec.host}: held`);
          h.setConfig({ status: { [receipt]: 'approved' }, runtime: hostRuntime(`${receipt}-other`) });
          h.run(spec.pre, spec.event(command, uid('a2-')), spec.env);
          assert.equal(runtimes(h).length, before + 1, `${spec.host}: the held action is resumed on the same install (no new gate)`);
          assert.notEqual(h.holdFor(receipt)?.state, 'open', `${spec.host}: released on the approval`);
          assert.equal(`${first.stderr}`.split('\n').filter((line) => line.includes('private device key')).length, 0, `${spec.host}: no note while the fallback key works`);
        }
      } finally { h.cleanup(); }
    }
  } finally { rmSync(passwd, { recursive: true, force: true }); }
});

test('S3 (hosts): runtime secrets are in no request body, hook output or local file; the device salt is in none of them', () => {
  const secrets = [];
  const secret = () => { const s = crypto.randomBytes(18).toString('base64url'); secrets.push(s); return s; };
  const h = harness();
  try {
    for (const spec of HOSTS) {
      const commands = [
        `curl -X DELETE -H "Authorization: Bearer ${secret()}" https://api.example.test/v1/projects/${camel('A')}`,
        `DB_PASSWORD=${secret()} ./migrate.sh down`,
        `npm publish --otp ${crypto.randomInt(100000, 999999)} --token ${secret()}`,
        `./publish.sh ${secret()}Ab1 production`,
      ];
      for (const command of commands) {
        h.setConfig({ runtime: hostRuntime(`gate-${crypto.randomBytes(3).toString('hex')}`), status: {} });
        h.run(spec.pre, spec.event(command, uid('s-')), spec.env);
        if (spec.post) h.run(spec.post, spec.postEvent(command, uid('s-')), spec.env);
      }
    }
    const passwd = process.env.SBT_PASSWD_HOME;
    const saltPath = join(passwd, '.marrow', 'seatbelt', 'salt');
    const salt = existsSync(saltPath) ? readFileSync(saltPath) : null;
    assert.ok(salt && salt.length === 32, 'the hooks created and used the scratch device salt');
    const haystack = [JSON.stringify(h.requests()), ...h.outputs, ...h.files()].join('\n');
    let leaks = 0;
    for (const s of secrets) for (let k = 0; k + 8 <= s.length; k += 1) if (haystack.includes(s.slice(k, k + 8))) { leaks += 1; break; }
    assert.equal(leaks, 0, 'no 8-character slice of any secret');
    for (const form of [salt.toString('hex'), salt.toString('base64'), salt.toString('base64url')]) {
      for (let k = 0; k + 12 <= form.length; k += 4) assert.equal(haystack.includes(form.slice(k, k + 12)), false, 'no slice of the salt');
    }
    const receiptsDir = join(passwd, '.marrow', 'seatbelt', 'receipts');
    const receipts = existsSync(receiptsDir) ? readdirSync(receiptsDir).map((name) => readFileSync(join(receiptsDir, name), 'utf8')).join('\n') : '';
    for (const s of secrets) for (let k = 0; k + 8 <= s.length; k += 1) assert.equal(receipts.includes(s.slice(k, k + 8)), false, 'not in receipts');
    // Every truncated runtime request carries an exact key and nothing else new.
    for (const request of runtimes(h)) {
      const action = request.body.normalized_action;
      if (action?.truncated === true) assert.match(action.tool_input.exact_hmac, /^[0-9a-f]{32}$/);
      for (const key of Object.keys(action?.tool_input || {})) assert.ok(['command_sha256', 'input_sha256', 'exact_hmac', 'command'].includes(key), key);
    }
  } finally { h.cleanup(); }
});
