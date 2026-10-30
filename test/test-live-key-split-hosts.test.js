'use strict';
// End to end, one hook process per host event (as a real host runs it), scripted Marrow API
// (test/support/host-approval-fetch-mock.cjs) and a loopback-only network guard (test/support/loopback-net-guard.cjs):
// an owner approval of held action A (a test key) never releases the same action B with a live key, on every host.
// A's exact retry with another test key is still released once (no extra prompt). Keys are generated at run time and
// never printed; no key characters are in any request body, output or local file.
const assert = require('node:assert/strict');
const test = require('node:test');
const { writeOfficialHostConfigs } = require('./support/official-host-config.cjs');
writeOfficialHostConfigs();
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const MOCK = join(__dirname, 'support', 'host-approval-fetch-mock.cjs');
const GUARD = join(__dirname, 'support', 'loopback-net-guard.cjs');
const FIXTURES = join(__dirname, 'fixtures', 'host-approvals');
const fixture = (name) => JSON.parse(readFileSync(join(FIXTURES, name), 'utf8'));
const payload = () => crypto.randomBytes(18).toString('base64').replace(/[^A-Za-z0-9]/g, '').slice(0, 24).padEnd(24, 'x');
const live = (prefix = 'sk') => `${prefix}_live_${payload()}`;
const test_ = (prefix = 'sk') => `${prefix}_test_${payload()}`;
const tailOf = (key) => key.slice(key.lastIndexOf('_') + 1);

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

function harness() {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-keyclass-'));
  const home = join(dir, 'home');
  const mockDir = join(dir, 'mock');
  const guardLog = join(dir, 'net-guard.log');
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
  const run = (entrypoint, payloadJson, env = {}) => {
    const result = spawnSync(process.execPath, [CLI, entrypoint], {
      input: JSON.stringify(payloadJson),
      env: {
        PATH: process.env.PATH, HOME: home, MARROW_API_KEY: apiKey, MARROW_BASE_URL: 'https://api.example.test',
        MARROW_AGENT_ID: 'agent-one', MARROW_HOOK_BACKGROUND_NUDGE: 'false', MARROW_PASSIVE_TOKEN_USAGE: 'false',
        MARROW_TEST_MOCK_DIR: mockDir, MARROW_NET_GUARD_LOG: guardLog, NODE_OPTIONS: `--require=${GUARD} --require=${MOCK}`, ...env,
      },
      encoding: 'utf8',
      timeout: 30_000,
    });
    assert.equal(result.error, undefined);
    outputs.push(result.stdout, result.stderr);
    assert.equal(result.stdout.includes(apiKey) || result.stderr.includes(apiKey), false, 'the Marrow key never appears in hook output');
    return { status: result.status, stdout: result.stdout.trim(), stderr: result.stderr };
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
  const guardLines = () => (existsSync(guardLog) ? readFileSync(guardLog, 'utf8').trim().split('\n').filter(Boolean) : []);
  return { run, setConfig, requests, holdFor, outputs, files, guardLines, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

const runtimes = (h) => h.requests().filter((r) => r.path === '/v1/agent/runtime' && /^classified \S+ action: /.test(r.body?.action || ''));
const uid = (prefix) => `${prefix}${crypto.randomBytes(4).toString('hex')}`;

const HOSTS = [
  { host: 'claude-code', pre: 'claude-pre-action-hook', event: (c, id) => ({ ...fixture('claude-pre-tool-use.json'), permission_mode: 'dontAsk', tool_use_id: id, tool_input: { command: c, description: 'held' } }),
    mcpEvent: (tool, input, id) => ({ ...fixture('claude-pre-tool-use.json'), permission_mode: 'dontAsk', tool_use_id: id, tool_name: `mcp__${tool.replace(':', '__')}`, tool_input: input }) },
  { host: 'codex', pre: 'codex-pre-action-hook', env: { MARROW_TEST_HOST_PROCESS: '/usr/local/bin/codex exec deploy' }, event: (c, id) => ({ ...fixture('codex-pre-tool-use.json'), tool_use_id: id, tool_input: { command: c } }) },
  { host: 'cursor (beforeShellExecution, cloud agent)', pre: 'cursor-pre-action-hook', event: (c, id) => ({ ...fixture('cursor-before-shell.json'), generation_id: id, command: c }) },
  { host: 'gemini', pre: 'gemini-pre-action-hook', event: (c) => ({ ...fixture('gemini-before-tool.json'), tool_input: { command: c } }) },
  { host: 'grok', pre: 'grok-pre-action-hook', event: (c, id) => ({ ...fixture('grok-pre-tool-use.json'), toolUseId: id, toolInput: { command: c } }) },
  { host: 'cline', pre: 'cline-pre-action-hook', event: (c) => ({ hookName: 'PreToolUse', taskId: 'task-keyclass', preToolUse: { toolName: 'execute_command', parameters: { command: c } } }) },
  { host: 'windsurf', pre: 'windsurf-pre-action-hook', event: (c, id) => ({ agent_action_name: 'pre_run_command', trajectory_id: 'traj-keyclass', execution_id: id, tool_info: { command_line: c, cwd: '/home/operator/project' } }) },
  { host: 'cursor (preToolUse, cloud agent)', pre: 'cursor-pre-action-hook', event: (c, id) => ({ ...fixture('cursor-pre-tool-use.json'), tool_use_id: id, tool_input: { command: c, working_directory: '/home/operator/project' } }),
    mcpEvent: (tool, input, id) => ({ ...fixture('cursor-pre-tool-use.json'), tool_use_id: id, tool_name: `MCP:${tool}`, tool_input: input }) },
];

const COMMANDS = [
  ['URL password', (k) => `git push -f https://deploy:${k}@github.com/acme/proj.git main`],
  ['Bearer header', (k) => `curl -X DELETE -H "Authorization: Bearer ${k}" https://api.example.test/v1/projects/acme`],
  ['env assignment', (k) => `STRIPE_API_KEY=${k} kubectl delete deployment payments-a`],
  ['flag', (k) => `kubectl delete deployment payments-a --token ${k}`],
];

/** Hold A, approve it, run B: B must be gated fresh and A's hold must stay open; A's exact retry with a rotated key of A's class is released once. */
function round(spec, build, keyA, keyB, keyA2) {
  const h = harness();
  const event = (key, id) => spec.event(build(key), id);
  try {
    h.setConfig({ runtime: hostRuntime('gate-wait'), status: { 'gate-wait': 'pending' } });
    h.run(spec.pre, event(keyA, uid('a-')), spec.env);
    assert.ok(h.holdFor('gate-wait'), `${spec.host}: A is held`);
    assert.equal(runtimes(h).length, 1, `${spec.host}: one gate for A`);
    h.setConfig({ status: { 'gate-wait': 'approved', 'gate-other': 'pending' }, runtime: hostRuntime('gate-other') });
    h.run(spec.pre, event(keyB, uid('b-')), spec.env);
    const bGated = runtimes(h).length === 2;
    const aStillOpen = h.holdFor('gate-wait')?.state === 'open';
    h.setConfig({ runtime: hostRuntime('gate-third') });
    h.run(spec.pre, event(keyA2, uid('a2-')), spec.env);
    const aReleased = h.holdFor('gate-wait')?.state === 'allowed' && runtimes(h).length === 2;
    // Secret scan: no key characters in any request body, output or local file; the guard saw nothing.
    const everything = [JSON.stringify(h.requests()), ...h.outputs, ...h.files()].join('\n');
    for (const key of [keyA, keyB, keyA2]) assert.equal(everything.includes(tailOf(key)), false, `${spec.host}: no key characters anywhere`);
    assert.deepEqual(h.guardLines(), [], `${spec.host}: no non-loopback attempt`);
    return { bGated, aStillOpen, aReleased, requests: h.requests() };
  } finally {
    h.cleanup();
  }
}

test('the loopback guard refuses a non-loopback connect and lookup (canary)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-keyclass-guard-'));
  try {
    const log = join(dir, 'log');
    const script = join(dir, 'canary.cjs');
    writeFileSync(script, [
      "const net = require('node:net'); const dns = require('node:dns'); let refused = 0;",
      "net.connect({ host: '203.0.113.7', port: 9 }).on('error', (e) => { if (e.code === 'ECONNREFUSED' && /guard/.test(e.message)) refused += 1; });",
      "dns.lookup('canary.invalid', (e) => { if (e && e.code === 'ENOTFOUND' && /guard/.test(e.message)) refused += 1; });",
      "setTimeout(() => { process.stdout.write(String(refused)); process.exit(0); }, 400);",
    ].join('\n'));
    const result = spawnSync(process.execPath, ['--require', GUARD, script], { env: { PATH: process.env.PATH, MARROW_NET_GUARD_LOG: log }, encoding: 'utf8', timeout: 20_000 });
    assert.equal(result.stdout, '2');
    assert.deepEqual(readFileSync(log, 'utf8').trim().split('\n'), ['lookup canary.invalid', 'connect 203.0.113.7']);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('E1/E2: on all hosts, an approval of a test-key action never releases the live-key action (and the reverse); the exact retry with a rotated key runs once', () => {
  const counts = { flows: 0 };
  for (const spec of HOSTS) {
    for (const [label, build] of COMMANDS) {
      for (const [name, keyA, keyB, keyA2] of [
        ['test then live', test_(), live(), test_()],
        ['live then test', live(), test_(), live()],
        ['rk test then rk live', test_('rk'), live('rk'), test_('rk')],
      ]) {
        const result = round(spec, build, keyA, keyB, keyA2);
        assert.equal(result.bGated, true, `${spec.host} / ${label} / ${name}: B reaches its own gate`);
        assert.equal(result.aStillOpen, true, `${spec.host} / ${label} / ${name}: B never claims A's approval`);
        assert.equal(result.aReleased, true, `${spec.host} / ${label} / ${name}: A's exact retry (rotated key, same class) runs once`);
        counts.flows += 1;
      }
    }
  }
  if (process.env.KEYCLASS_REPORT) process.stdout.write(`# KEYCLASS E1/E2 ${JSON.stringify(counts)}\n`);
  assert.equal(counts.flows, HOSTS.length * COMMANDS.length * 3);
});

test('E3: an MCP tool call with a key field is split by class too (Claude Code MCP, Cursor MCP)', () => {
  for (const spec of HOSTS.filter((entry) => entry.mcpEvent)) {
    const build = (k, id) => spec.mcpEvent('stripe:create_refund', { api_key: k, charge: 'ch_1', amount: 500 }, id);
    const h = harness();
    try {
      const [a, b, a2] = [test_(), live(), test_()];
      h.setConfig({ runtime: hostRuntime('gate-wait'), status: { 'gate-wait': 'pending' } });
      h.run(spec.pre, build(a, uid('a-')), spec.env);
      assert.ok(h.holdFor('gate-wait'), `${spec.host}: A is held`);
      h.setConfig({ status: { 'gate-wait': 'approved', 'gate-other': 'pending' }, runtime: hostRuntime('gate-other') });
      h.run(spec.pre, build(b, uid('b-')), spec.env);
      assert.equal(runtimes(h).length, 2, `${spec.host}: B (live key) reaches its own gate`);
      assert.equal(h.holdFor('gate-wait')?.state, 'open', `${spec.host}: B never claims A's approval`);
      h.setConfig({ runtime: hostRuntime('gate-third') });
      h.run(spec.pre, build(a2, uid('a2-')), spec.env);
      assert.equal(h.holdFor('gate-wait')?.state, 'allowed', `${spec.host}: A's retry with a rotated test key is released`);
      const everything = [JSON.stringify(h.requests()), ...h.outputs, ...h.files()].join('\n');
      for (const key of [a, b, a2]) assert.equal(everything.includes(tailOf(key)), false, `${spec.host}: no key characters anywhere`);
      assert.deepEqual(h.guardLines(), []);
    } finally { h.cleanup(); }
  }
});
