'use strict';

// Patch round P1, F2: with no usable device key the exact-action hashes are keyed with a fallback key derived from the
// host-approval state, so a held action is still resumed, reported and committed. Neither key: a nonce, asked again.
// Dummy values are generated at runtime; nothing here prints a key.
const assert = require('node:assert/strict');
const test = require('node:test');
const crypto = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { nokeyFallbackKey } = require('../dist/host-approval-state.js');
const { normalizeShellCommand } = require('../dist/normalized-action.js');
const keyed = require('./support/keyed-text-hash.cjs');

const ROOT = path.join(__dirname, '..');
const NA = path.join(ROOT, 'dist', 'normalized-action.js');
const HAS = path.join(ROOT, 'dist', 'host-approval-state.js');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const FAKE = path.join(__dirname, 'support', 'passwd-home-fake.cjs');
const MOCK = path.join(__dirname, 'support', 'host-approval-fetch-mock.cjs');
const sha256 = (text) => crypto.createHash('sha256').update(text).digest('hex');
const PATH_ENV = process.env.PATH;

function freshHome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-p1-f2-'));
  fs.chmodSync(dir, 0o700);
  return dir;
}
/** Every path under `dir` with a digest of its content (or its link target): to prove a refused call changed nothing. */
function snapshot(dir, out = {}, root = dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    const rel = path.relative(root, full);
    if (entry.isSymbolicLink()) out[rel] = `link:${fs.readlinkSync(full)}`;
    else if (entry.isDirectory()) { out[rel] = `dir:${fs.statSync(full).mode & 0o777}`; snapshot(full, out, root); } else out[rel] = `file:${fs.statSync(full).mode & 0o777}:${sha256(fs.readFileSync(full, 'latin1'))}`;
  }
  return out;
}
const stateFile = (home) => path.join(home, '.marrow', 'host-approvals', 'state.json');
const readState = (home) => JSON.parse(fs.readFileSync(stateFile(home), 'utf8'));
function saltFile(home) {
  const dir = path.join(home, '.marrow', 'seatbelt');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(path.join(home, '.marrow'), 0o700);
  fs.chmodSync(dir, 0o700);
  return path.join(dir, 'salt');
}

test('K1: the fallback key is made with the state, 32 bytes, HMAC of the state secret under its label, stable, per install, never the secret', () => {
  const home = freshHome();
  const key = nokeyFallbackKey(home);
  assert.equal(key.length, 32);
  assert.equal(fs.statSync(stateFile(home)).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.dirname(stateFile(home))).mode & 0o777, 0o700);
  const secret = Buffer.from(readState(home).secret, 'base64url');
  assert.equal(secret.length, 32);
  assert.ok(key.equals(crypto.createHmac('sha256', secret).update('marrow-nokey-fallback-v1').digest()));
  assert.equal(key.equals(secret), false, 'never the state secret itself');
  assert.ok(nokeyFallbackKey(home).equals(key), 'stable');
  assert.equal(nokeyFallbackKey(freshHome()).equals(key), false, 'per install');
  // A fixed label is not a key: a constant fallback (a mutant) would equal this for every install.
  assert.equal(key.equals(crypto.createHash('sha256').update('marrow-nokey-fallback-v1').digest()), false);
});

test('K1: every unsafe state gives null and is left as it was (symlink, wrong mode, corrupt, wrong version, oversize, a file in place of a directory)', () => {
  const breakers = {
    'corrupt json': (home) => fs.writeFileSync(stateFile(home), 'not json', { mode: 0o600 }),
    'state mode 0644': (home) => fs.chmodSync(stateFile(home), 0o644),
    'state mode 0640': (home) => fs.chmodSync(stateFile(home), 0o640),
    'wrong version': (home) => { const state = readState(home); state.version = 2; fs.writeFileSync(stateFile(home), JSON.stringify(state), { mode: 0o600 }); },
    'short secret': (home) => { const state = readState(home); state.secret = 'abc'; fs.writeFileSync(stateFile(home), JSON.stringify(state), { mode: 0o600 }); },
    'oversize': (home) => fs.writeFileSync(stateFile(home), ' '.repeat(600 * 1024), { mode: 0o600 }),
    'state is a symlink': (home) => { const real = `${stateFile(home)}.real`; fs.renameSync(stateFile(home), real); fs.symlinkSync(real, stateFile(home)); },
    'directory mode 0770': (home) => fs.chmodSync(path.dirname(stateFile(home)), 0o770),
    'directory is a file': (home) => { fs.rmSync(path.dirname(stateFile(home)), { recursive: true }); fs.writeFileSync(path.dirname(stateFile(home)), 'x', { mode: 0o600 }); },
    '.marrow is a file': (home) => { fs.rmSync(path.join(home, '.marrow'), { recursive: true }); fs.writeFileSync(path.join(home, '.marrow'), 'x', { mode: 0o600 }); },
    '.marrow group-writable': (home) => fs.chmodSync(path.join(home, '.marrow'), 0o770),
  };
  for (const [name, brake] of Object.entries(breakers)) {
    const home = freshHome();
    assert.ok(nokeyFallbackKey(home), name);
    brake(home);
    const before = snapshot(home);
    assert.equal(nokeyFallbackKey(home), null, name);
    assert.deepEqual(snapshot(home), before, `${name}: nothing changed, nothing created`);
  }
});

test('K1: a foreign-owner state is refused (owner check)', { skip: typeof process.getuid !== 'function' || process.getuid() === 0 }, () => {
  // Another uid cannot be created without root: the state of this uid is read with its owner checked against ours.
  // The check is the same function the holds use (readState), proved here by the modes it refuses.
  const home = freshHome();
  assert.ok(nokeyFallbackKey(home));
  fs.chmodSync(stateFile(home), 0o666);
  assert.equal(nokeyFallbackKey(home), null);
});

test('K1: 8 processes starting at once on one HOME agree on one key and leave one state', async () => {
  const home = freshHome();
  const code = `const k = require(${JSON.stringify(HAS)}).nokeyFallbackKey(); process.stdout.write(k ? require('node:crypto').createHmac('sha256', k).update('probe').digest('hex') : 'null');`;
  const run = () => new Promise((resolve) => {
    const child = spawn(process.execPath, ['-e', code], { env: { PATH: PATH_ENV, HOME: home, SBT_PASSWD_HOME: home }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', (chunk) => { out += chunk; });
    child.on('close', (status) => resolve({ status, out }));
  });
  const results = await Promise.all(Array.from({ length: 8 }, run));
  assert.ok(results.every((r) => r.status === 0));
  assert.equal(new Set(results.map((r) => r.out)).size, 1, 'one key for every process');
  assert.match(results[0].out, /^[0-9a-f]{64}$/);
  assert.deepEqual(fs.readdirSync(path.dirname(stateFile(home))).sort(), ['state.json']);
  assert.equal(fs.statSync(stateFile(home)).mode & 0o777, 0o600);
});

test('K1: HOME unset does not crash; the key is read from where the state lives', () => {
  const home = freshHome();
  const code = `const k = require(${JSON.stringify(HAS)}).nokeyFallbackKey(); process.stdout.write(k ? 'key' : 'null');`;
  const run = spawnSync(process.execPath, ['-e', code], { env: { PATH: PATH_ENV, SBT_PASSWD_HOME: home }, encoding: 'utf8', timeout: 20_000 });
  assert.equal(run.status, 0);
  assert.match(run.stdout, /^(key|null)$/);
  assert.equal(run.stderr, '');
});

// ---------------------------------------------------------------------------------------------------------------
// The normalizer in a process of its own (HOME and the passwd home are one scratch dir)
// ---------------------------------------------------------------------------------------------------------------
const CHILD = `const na = require(${JSON.stringify(NA)});
const a = na.normalizedHookAction({ tool_name: 'Bash', tool_input: { command: process.argv[1] } });
const b = na.normalizedHookAction({ tool_name: 'PF', tool_input: { command: process.argv[1] } });
process.stdout.write(JSON.stringify({ sha: a.tool_input.command_sha256, sha2: b.tool_input.command_sha256, target: require(${JSON.stringify(path.join(ROOT, 'dist', 'hook-contract.js'))}).exactHookTarget({ tool_name: 'Bash', tool_input: { command: process.argv[1] } }) }));`;
function runChild(home, command, extra = {}) {
  const run = spawnSync(process.execPath, ['-e', CHILD, command], { env: { PATH: PATH_ENV, HOME: home, SBT_PASSWD_HOME: home, ...extra }, encoding: 'utf8', timeout: 20_000 });
  assert.equal(run.status, 0, 'child exit');
  return { out: JSON.parse(run.stdout), stderr: run.stderr };
}

test('K2: with an unsafe device key the hash is keyed by the fallback: stable across processes, never the plain or the device-keyed value, per install; a repaired device key changes it (old holds are asked again)', () => {
  const command = 'ls Payments-Service-Blue-Green-A1';
  const text = normalizeShellCommand(command).text;
  const home = freshHome();
  const device = crypto.randomBytes(32);
  fs.writeFileSync(saltFile(home), device, { mode: 0o600 });
  fs.chmodSync(saltFile(home), 0o644);
  const first = runChild(home, command);
  assert.match(first.out.sha, /^[0-9a-f]{64}$/);
  assert.equal(runChild(home, command).out.sha, first.out.sha, 'stable');
  assert.equal(first.stderr, '', 'no note while the fallback works');
  assert.notEqual(first.out.sha, sha256(`marrow-normalized-action-v3\nshell\n${text}`), 'never the plain hash');
  assert.notEqual(first.out.sha, keyed.shellMac(device, 'Bash', text), 'domain separation: never the device-keyed value');
  const other = freshHome();
  fs.writeFileSync(saltFile(other), device, { mode: 0o600 });
  fs.chmodSync(saltFile(other), 0o644);
  assert.notEqual(runChild(other, command).out.sha, first.out.sha, 'another install: another key even under the same device bytes');
  // The device key becomes usable: every value changes, equal to the device-keyed value.
  fs.chmodSync(saltFile(home), 0o600);
  const repaired = runChild(home, command);
  assert.notEqual(repaired.out.sha, first.out.sha);
  assert.notEqual(repaired.out.target, first.out.target);
  assert.equal(repaired.out.sha, keyed.shellMac(device, 'Bash', text));
});

test('K2: with neither key usable the hash and the target are a nonce per call, one note (no path, no value), never the plain hash', () => {
  const command = 'ls Payments-Service-Blue-Green-A1';
  const home = freshHome();
  fs.mkdirSync(path.join(home, '.marrow'), { mode: 0o700 });
  fs.writeFileSync(path.join(home, '.marrow', 'host-approvals'), 'x', { mode: 0o600 });
  fs.mkdirSync(path.join(home, '.marrow', 'seatbelt'), { mode: 0o700 });
  fs.writeFileSync(path.join(home, '.marrow', 'seatbelt', 'salt'), crypto.randomBytes(16), { mode: 0o600 });
  const first = runChild(home, command);
  assert.notEqual(first.out.sha, first.out.sha2);
  assert.notEqual(runChild(home, command).out.sha, first.out.sha);
  assert.notEqual(first.out.sha, sha256(`marrow-normalized-action-v3\nshell\n${normalizeShellCommand(command).text}`));
  const notes = first.stderr.split('\n').filter((line) => line.includes('private device key'));
  assert.equal(notes.length, 1);
  assert.equal(/\/|\\|salt|secret/.test(notes[0]), false);
});

test('K2: the fallback key and the state secret are in no output, and the state holds the secret only where it always did', () => {
  const home = freshHome();
  const command = 'ls Payments-Service-Blue-Green-A1';
  const salt = saltFile(home);
  fs.writeFileSync(salt, crypto.randomBytes(32), { mode: 0o644 });
  const run = runChild(home, command);
  const secret = Buffer.from(readState(home).secret, 'base64url');
  const key = nokeyFallbackKey(home);
  for (const value of [secret, key]) {
    for (const text of [value.toString('hex'), value.toString('base64'), value.toString('base64url')]) {
      assert.equal(JSON.stringify(run.out).includes(text), false);
      assert.equal(run.stderr.includes(text), false);
    }
  }
  assert.equal(fs.readFileSync(stateFile(home), 'latin1').includes(key.toString('hex')), false, 'the derived key is not stored');
});

// ---------------------------------------------------------------------------------------------------------------
// Real hooks: pre-action, permission request, post-tool-use, the scripted API (host-approval-fetch-mock)
// ---------------------------------------------------------------------------------------------------------------
function hostRuntime(receipt) {
  return {
    ok: true, action: 'classified Bash action: deploy on production', decision_id: `decision-${receipt}`,
    runtime_authorization: { id: receipt, kind: 'durable_gate_receipt', durable: true, decision_state: 'created', decision_creation_required: false, decision_id: `decision-${receipt}` },
    gate_receipt: { id: receipt, decision: 'review_required', required: true, owner_approval_required: true, expires_at: '2030-01-01T00:30:00.000Z' },
    proof_pack: { required: false, fields: [], complete: true },
    completion_contract: {
      decision_id: `decision-${receipt}`, decision_creation_required: false, decision_state: 'created', owner_approval_required: true, arbitration_receipt_required: false,
      gate_receipt_required: true, required_commit_fields: ['decision_id', 'success', 'outcome', 'gate_receipt_id'],
      owner_approval: {
        mode: 'ordinary_non_arbitrated', proof_path: null, proof_shape: null, dashboard_receipt_required: false, trusted_completion_receipt_required: true,
        receipt_field: 'owner_approval_receipt_id', approval_endpoint: '/v1/dashboard/enforcement/owner-approval', approval_authority: 'host_operator_or_dashboard_owner',
        approval_status_endpoint: `/v1/agent/gate-receipts/${receipt}/owner-approval`, approval_status_poll_after_ms: 5000,
        host_approval_endpoint: `/v1/agent/gate-receipts/${receipt}/host-approval`, host_approval_accepted: true, host_approval_trust: 'client_attested',
        approval_categories: ['production_deploy'], verified_approval_required: false, verified_approval_categories: [],
      },
    },
    risk_gate: { allow: true, decision: 'review_required', enforced: true, gate_required: true, gate_receipt_id: receipt, risk_level: 'high', reasons: [{ message: 'Needs approval.' }] },
    gate_receipt_id: receipt, exact_next_action: 'Obtain explicit owner approval before this action runs.',
  };
}
function harness(passwd) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-p1-f2-hooks-'));
  const home = path.join(dir, 'home');
  const mock = path.join(dir, 'mock');
  fs.mkdirSync(home, { mode: 0o700 });
  fs.mkdirSync(mock);
  fs.mkdirSync(path.join(home, '.codex'), { recursive: true });
  fs.writeFileSync(path.join(home, '.codex', 'config.toml'), '[mcp_servers.marrow]\ncommand = "npx"\nargs = ["-y", "@getmarrow/mcp"]\n');
  const apiKey = `mrw_test_${crypto.randomBytes(16).toString('hex')}`;
  const setConfig = (config) => fs.writeFileSync(path.join(mock, 'config.json'), JSON.stringify(config));
  const requests = () => {
    const file = path.join(mock, 'requests.jsonl');
    return fs.existsSync(file) ? fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line)) : [];
  };
  const SESSION = '3b1f0c2e-0000-4000-8000-00000000000a';
  const event = (name, tool, command, id) => ({ session_id: SESSION, cwd: '/home/operator/project', permission_mode: 'default', hook_event_name: name, tool_name: tool, tool_input: { command, description: 'x' }, tool_use_id: id });
  const run = (entry, payload) => {
    const result = spawnSync(process.execPath, [CLI, entry], {
      input: JSON.stringify(payload), encoding: 'utf8', timeout: 30_000, cwd: dir,
      env: {
        PATH: PATH_ENV, HOME: home, TMPDIR: dir, SBT_PASSWD_HOME: passwd, MARROW_API_KEY: apiKey, MARROW_BASE_URL: 'https://api.example.test', MARROW_AGENT_ID: 'agent-one',
        MARROW_HOOK_BACKGROUND_NUDGE: 'false', MARROW_PASSIVE_TOKEN_USAGE: 'false', MARROW_AUTO_ENROLL: 'false', MARROW_TEST_MOCK_DIR: mock,
        NODE_OPTIONS: `--require=${FAKE} --require=${MOCK}`,
      },
    });
    assert.equal(result.error, undefined);
    return { status: result.status, stdout: result.stdout, stderr: result.stderr };
  };
  const pre = (command, id) => run('claude-pre-action-hook', event('PreToolUse', 'Bash', command, id));
  const perm = (command) => run('claude-permission-request-hook', { session_id: SESSION, cwd: '/home/operator/project', permission_mode: 'default', hook_event_name: 'PermissionRequest', tool_name: 'Bash', tool_input: { command, description: 'x' } });
  const post = (command, id) => run('claude-hook', { ...event('PostToolUse', 'Bash', command, id), tool_response: { stdout: 'ok', stderr: '', interrupted: false } });
  const count = (re) => requests().filter((r) => re.test(r.path)).length;
  return { dir, home, mock, setConfig, requests, run, pre, perm, post, counts: () => ({ gates: count(/^\/v1\/agent\/runtime$/), reports: count(/host-approval$/), commits: count(/^\/v1\/agent\/commit$/) }), cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}
const COMMAND = 'wrangler deploy --env production';
const decisionOf = (out) => { try { const j = JSON.parse(out.stdout); return (j.hookSpecificOutput || {}).permissionDecision || null; } catch { return null; } };

/** The host-prompt flow of one action (default mode: ask, the host dialog, post-tool-use). */
function hostPrompt(h) {
  h.setConfig({ runtime: hostRuntime('gate-held') });
  const asked = h.pre(COMMAND, 'toolu_01P1F2000000000000000001');
  h.perm(COMMAND);
  h.post(COMMAND, 'toolu_01P1F2000000000000000001');
  return { asked: decisionOf(asked), ...h.counts() };
}

const KEY_STATES = {
  'usable key': () => ({ passwd: freshHome() }),
  'unsafe salt mode 0644': () => { const passwd = freshHome(); fs.writeFileSync(saltFile(passwd), crypto.randomBytes(32), { mode: 0o600 }); fs.chmodSync(saltFile(passwd), 0o644); return { passwd }; },
  'corrupt salt (short)': () => { const passwd = freshHome(); fs.writeFileSync(saltFile(passwd), crypto.randomBytes(16), { mode: 0o600 }); return { passwd }; },
  'corrupt salt (long)': () => { const passwd = freshHome(); fs.writeFileSync(saltFile(passwd), crypto.randomBytes(64), { mode: 0o600 }); return { passwd }; },
  'salt is a symlink': () => { const passwd = freshHome(); const real = path.join(passwd, 'real-salt'); fs.writeFileSync(real, crypto.randomBytes(32), { mode: 0o600 }); fs.symlinkSync(real, saltFile(passwd)); return { passwd }; },
  'passwd directory unsafe (0770)': () => { const passwd = freshHome(); fs.writeFileSync(saltFile(passwd), crypto.randomBytes(32), { mode: 0o600 }); fs.chmodSync(path.join(passwd, '.marrow', 'seatbelt'), 0o770); return { passwd }; },
  'no passwd home (Windows-like)': () => ({ passwd: path.join(os.tmpdir(), `marrow-p1-f2-nonexistent-${crypto.randomBytes(4).toString('hex')}`) }),
};

test('F2 acceptance: in every key state with a usable approval state the approved action is reported and committed exactly as with a usable key (gates equal)', () => {
  const results = {};
  for (const [name, make] of Object.entries(KEY_STATES)) {
    const { passwd } = make();
    const h = harness(passwd);
    try { results[name] = hostPrompt(h); } finally { h.cleanup(); try { fs.chmodSync(path.join(passwd, '.marrow', 'seatbelt'), 0o700); } catch { /* */ } }
  }
  const usable = results['usable key'];
  assert.equal(usable.asked, 'ask');
  assert.equal(usable.reports, 1);
  assert.equal(usable.commits, 1);
  for (const [name, got] of Object.entries(results)) assert.deepEqual(got, usable, name);
});

test('F2: a held action is resumed on retry with no usable device key (dontAsk): no new gate request', () => {
  const { passwd } = KEY_STATES['unsafe salt mode 0644']();
  const h = harness(passwd);
  try {
    h.setConfig({ runtime: hostRuntime('gate-wait'), status: { 'gate-wait': 'pending' } });
    const first = h.run('claude-pre-action-hook', { session_id: 'sess-dontask', cwd: '/home/operator/project', permission_mode: 'dontAsk', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: COMMAND }, tool_use_id: 't1' });
    assert.ok(['deny', 'ask'].includes(decisionOf(first)));
    assert.equal(h.counts().gates, 1);
    h.setConfig({ status: { 'gate-wait': 'approved' }, runtime: hostRuntime('gate-other') });
    const retry = h.run('claude-pre-action-hook', { session_id: 'sess-dontask', cwd: '/home/operator/project', permission_mode: 'dontAsk', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: COMMAND }, tool_use_id: 't2' });
    assert.equal(h.counts().gates, 1, 'resumed, not asked again');
    assert.match(retry.stdout, /approved this held action/);
  } finally { h.cleanup(); }
});

test('F2 abuse: the device key changes between PreToolUse and PostToolUse: the hold is NOT claimed (no report, no commit) and a retry is asked again', () => {
  for (const direction of ['fallback-then-device', 'device-then-fallback', 'device-deleted']) {
    const passwd = freshHome();
    const salt = saltFile(passwd);
    if (direction === 'fallback-then-device') { fs.writeFileSync(salt, crypto.randomBytes(32), { mode: 0o600 }); fs.chmodSync(salt, 0o644); }
    const h = harness(passwd);
    try {
      h.setConfig({ runtime: hostRuntime('gate-held') });
      const id = 'toolu_01P1F2000000000000000002';
      h.pre(COMMAND, id);
      h.perm(COMMAND);
      if (direction === 'fallback-then-device') fs.chmodSync(salt, 0o600);
      if (direction === 'device-then-fallback') fs.chmodSync(salt, 0o644);
      if (direction === 'device-deleted') fs.rmSync(salt);
      h.post(COMMAND, id);
      assert.deepEqual(h.counts(), { gates: 1, reports: 0, commits: 0 }, `${direction}: not claimed`);
      h.pre(COMMAND, `${id}b`);
      assert.equal(h.counts().gates, 2, `${direction}: asked again`);
    } finally { h.cleanup(); }
  }
});

test('F2: with neither key usable (the approval state cannot be used) the action is asked every time and nothing is reported (as on 5ffbf9c0), one note', () => {
  const { passwd } = KEY_STATES['unsafe salt mode 0644']();
  const h = harness(passwd);
  try {
    fs.mkdirSync(path.join(h.home, '.marrow'), { mode: 0o700 });
    fs.writeFileSync(path.join(h.home, '.marrow', 'host-approvals'), 'x', { mode: 0o600 });
    h.setConfig({ runtime: hostRuntime('gate-held') });
    const first = h.pre(COMMAND, 'toolu_01P1F2000000000000000003');
    h.perm(COMMAND);
    h.post(COMMAND, 'toolu_01P1F2000000000000000003');
    h.pre(COMMAND, 'toolu_01P1F2000000000000000004');
    const counts = h.counts();
    assert.equal(counts.gates, 2, 'asked again every time');
    assert.equal(counts.reports, 0);
    assert.equal(counts.commits, 0);
    assert.equal(first.stderr.split('\n').filter((line) => line.includes('private device key')).length, 1);
  } finally { h.cleanup(); }
});

test('F2 abuse: two API keys on one machine and one state never share a hold', () => {
  const { passwd } = KEY_STATES['unsafe salt mode 0644']();
  const one = harness(passwd);
  try {
    one.setConfig({ runtime: hostRuntime('gate-held') });
    one.pre(COMMAND, 'toolu_01P1F2000000000000000005');
    // Same HOME (same state), another key: the hold is invisible to it (key_ref is keyed by the API key).
    const env = { ...process.env };
    const second = spawnSync(process.execPath, [CLI, 'claude-hook'], {
      input: JSON.stringify({ session_id: '3b1f0c2e-0000-4000-8000-00000000000a', cwd: '/home/operator/project', permission_mode: 'default', hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_input: { command: COMMAND, description: 'x' }, tool_response: { stdout: 'ok', stderr: '', interrupted: false }, tool_use_id: 'toolu_01P1F2000000000000000005' }),
      encoding: 'utf8', timeout: 30_000, cwd: one.dir,
      env: { PATH: PATH_ENV, HOME: one.home, TMPDIR: one.dir, SBT_PASSWD_HOME: passwd, MARROW_API_KEY: `mrw_test_${crypto.randomBytes(16).toString('hex')}`, MARROW_BASE_URL: 'https://api.example.test', MARROW_AGENT_ID: 'agent-one', MARROW_HOOK_BACKGROUND_NUDGE: 'false', MARROW_PASSIVE_TOKEN_USAGE: 'false', MARROW_AUTO_ENROLL: 'false', MARROW_TEST_MOCK_DIR: one.mock, NODE_OPTIONS: `--require=${FAKE} --require=${MOCK}` },
    });
    assert.equal(second.status, 0);
    assert.deepEqual(one.counts(), { gates: 1, reports: 0, commits: 0 });
    void env;
  } finally { one.cleanup(); }
});
