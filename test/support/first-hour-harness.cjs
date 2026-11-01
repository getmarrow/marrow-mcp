'use strict';

// A keyed Claude Code hook session against a scripted Marrow (no real backend, no network): the
// hosts' hook processes run one per event, as a real host runs them, with a throwaway HOME and
// the same fetch double the host-approval tests use (test/support/host-approval-fetch-mock.cjs).
// The dummy key is generated at run time and never leaves the double.
//
// Used by test/first-hour-tier-a.test.js and tools/fh-diff.cjs (which passes the base build's
// cli.js to get the same scenario on both builds).
const { spawn, spawnSync } = require('node:child_process');
const { randomBytes } = require('node:crypto');
const { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { writeOfficialHostConfigs } = require('./official-host-config.cjs');

const MOCK = join(__dirname, 'host-approval-fetch-mock.cjs');
const FIXTURES = join(__dirname, '..', 'fixtures', 'host-approvals');
const fixture = (name) => JSON.parse(readFileSync(join(FIXTURES, name), 'utf8'));

// A review_required gate the host may approve (client attested), in the given categories.
function hostRuntime(receipt = 'gate-held', approval = {}, extra = {}) {
  return {
    ok: true,
    action: 'classified Bash action: deploy on production',
    decision_id: 'decision-review',
    runtime_authorization: { id: receipt, kind: 'durable_gate_receipt', durable: true, decision_state: 'created', decision_creation_required: false, decision_id: 'decision-review' },
    gate_receipt: { id: receipt, decision: 'review_required', required: true, owner_approval_required: true, expires_at: '2030-01-01T00:30:00.000Z' },
    proof_pack: { required: true, fields: ['summary', 'checks', 'outcome', 'blockers', 'commits_prs_shas', 'rollback_target', 'handoff_result_file', 'deployment_and_smoke'], complete: false },
    completion_contract: {
      decision_id: 'decision-review', decision_creation_required: false, decision_state: 'created',
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
        ...approval,
      },
    },
    risk_gate: { allow: true, decision: 'review_required', enforced: true, gate_required: true, gate_receipt_id: receipt, risk_level: 'high', reasons: [{ message: 'Production deploys need approval.' }] },
    gate_receipt_id: receipt,
    exact_next_action: 'Obtain explicit owner approval before this action runs.',
    ...extra,
  };
}

// The owner approves this category personally: a chat or dialog answer never counts for it.
const ownerLockedRuntime = (receipt = 'gate-locked') => hostRuntime(receipt, { host_approval_accepted: false, verified_approval_required: true, verified_approval_categories: ['production_deploy'], approval_authority: 'account_owner' });

function keyedHarness(options = {}) {
  const cli = options.cli || join(__dirname, '..', '..', 'dist', 'cli.js');
  // `dir`: a fixed folder (tools/fh-diff.cjs runs both builds in the same path); `nodeOptions`: the preloads, the fetch double last.
  const dir = options.dir || mkdtempSync(join(tmpdir(), 'marrow-first-hour-'));
  const home = join(dir, 'home');
  const mockDir = join(dir, 'mock');
  mkdirSync(home, { recursive: true, mode: 0o700 });
  writeOfficialHostConfigs(home);
  mkdirSync(mockDir);
  const apiKey = options.apiKey || `mrw_test_${randomBytes(16).toString('hex')}`;
  const nodeOptions = (options.nodeOptions || [MOCK]).map((file) => `--require=${file}`).join(' ');
  const baseEnv = (env) => ({
    PATH: process.env.PATH, HOME: home, MARROW_API_KEY: apiKey, MARROW_BASE_URL: 'https://api.example.test',
    MARROW_AGENT_ID: 'agent-one', MARROW_HOOK_BACKGROUND_NUDGE: 'false', MARROW_PASSIVE_TOKEN_USAGE: 'false',
    MARROW_TEST_MOCK_DIR: mockDir, NODE_OPTIONS: nodeOptions, ...(options.extraEnv || {}), ...env,
  });
  let config = {};
  const setConfig = (next) => { config = { ...config, ...next }; writeFileSync(join(mockDir, 'config.json'), JSON.stringify(config)); };
  const requests = () => {
    const path = join(mockDir, 'requests.jsonl');
    return existsSync(path) ? readFileSync(path, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line)) : [];
  };
  const run = (entrypoint, payload, env = {}) => {
    const result = spawnSync(process.execPath, [cli, entrypoint], {
      input: typeof payload === 'string' ? payload : JSON.stringify(payload),
      env: baseEnv(env),
      encoding: 'utf8',
      timeout: 30_000,
    });
    if (result.error) throw result.error;
    const output = result.stdout.trim();
    if (output.includes(apiKey) || result.stderr.includes(apiKey)) throw new Error('the key appeared in hook output');
    let json = null;
    try { json = output ? JSON.parse(output) : null; } catch { json = null; }
    return { status: result.status, stdout: output, stderr: result.stderr, json };
  };
  // The same as run, without blocking (tools/fh-diff.cjs runs several machines at once).
  const runAsync = (entrypoint, payload, env = {}) => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, entrypoint], { env: baseEnv(env), stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 60_000);
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', (error) => { clearTimeout(timer); reject(error); });
    child.on('close', (status) => {
      clearTimeout(timer);
      if (stdout.includes(apiKey) || stderr.includes(apiKey)) { reject(new Error('the key appeared in hook output')); return; }
      const output = stdout.trim();
      let json = null;
      try { json = output ? JSON.parse(output) : null; } catch { json = null; }
      resolve({ status, stdout: output, stderr, json });
    });
    child.stdin.on('error', () => {});
    child.stdin.end(typeof payload === 'string' ? payload : JSON.stringify(payload));
  });
  const statePath = join(home, '.marrow', 'host-approvals', 'state.json');
  const state = () => (existsSync(statePath) ? JSON.parse(readFileSync(statePath, 'utf8')) : null);
  const holds = () => Object.values(state()?.holds || {});
  // Every file under the state directory with its bytes, for before/after comparison.
  const stateSnapshot = () => {
    const root = join(home, '.marrow', 'host-approvals');
    if (!existsSync(root)) return {};
    const out = {};
    for (const name of readdirSync(root).sort()) {
      const file = join(root, name);
      out[name] = statSync(file).isFile() ? readFileSync(file).toString('base64') : 'dir';
    }
    return out;
  };
  return { dir, home, apiKey, run, runAsync, setConfig, requests, state, holds, stateSnapshot, statePath, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

module.exports = { fixture, hostRuntime, ownerLockedRuntime, keyedHarness, MOCK, FIXTURES };
