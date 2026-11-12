'use strict';

// The command text of an ordinary raw Claude Code Bash call leaves the machine on the runtime call only, with its plain
// hash and the home-relative folder, so the learned pattern engine can read the action. Text goes only when the
// normalized text is the host's own text, normalizing replaced nothing and the secret-shape scan finds nothing; any
// doubt sends the 3.9.111 action (keyed hash, no text, no folder). The hold, denial, permit and approval records keep
// the plain hash without the text. Every other host, entrypoint or renamed call is unchanged. Each hook row runs the
// built hook in a child process with a fake home and the fetch mock; dummy secrets are made at run time.

const assert = require('node:assert/strict');
const test = require('node:test');
const { createHash, randomBytes } = require('node:crypto');
const { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } = require('node:fs');
const { spawnSync } = require('node:child_process');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const { normalizedHookAction, homeRelativeFolder } = require('../dist/normalized-action.js');
const { writeOfficialHostConfigs } = require('./support/official-host-config.cjs');
const { projectCwd } = require('./support/hermetic-project.cjs');
const { assertNotLiveKey } = require('./support/dummy-secret.cjs');

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const MOCK = join(__dirname, 'support', 'host-approval-fetch-mock.cjs');
const P = (text) => createHash('sha256').update(`marrow-normalized-action-v3\nshell\n${text}`).digest('hex');
const SESSION = '3b1f0c2e-0000-4000-8000-00000000000c';
// A short dummy (no key shape of its own, so the rule under test is what withholds it) and a long hex one.
const dummy = () => assertNotLiveKey(`zq${randomBytes(3).toString('hex')}`);
const dummyHex = (bytes) => assertNotLiveKey(`zq${randomBytes(bytes).toString('hex')}`);
// Calls that reach the runtime (a read such as `ls -l ./out` is a local read-only pass, as in 3.9.112: no runtime call).
const SENT = ['mkdir -p ./out/x', 'touch ./out/new.txt', 'cp ./a ./b'];
const READS = ['ls -l ./out', 'grep -rl foo ./src | head -n 3'];

function allowRuntime() {
  return { ok: true, action: 'classified Bash action', decision_id: 'decision-plain', risk_gate: { allow: true, decision: 'allow', enforced: true, gate_required: false, risk_level: 'low' } };
}

function heldRuntime() {
  const receipt = 'gate-held';
  return {
    ok: true,
    action: 'classified Bash action',
    decision_id: 'decision-held',
    runtime_authorization: { id: receipt, kind: 'durable_gate_receipt', durable: true, decision_state: 'created', decision_creation_required: false, decision_id: 'decision-held' },
    gate_receipt: { id: receipt, decision: 'review_required', required: true, owner_approval_required: true, expires_at: '2030-01-01T00:30:00.000Z' },
    proof_pack: { required: false, fields: [], complete: true },
    completion_contract: {
      decision_id: 'decision-held', decision_creation_required: false, decision_state: 'created',
      owner_approval_required: true, arbitration_receipt_required: false, gate_receipt_required: true,
      required_commit_fields: ['decision_id', 'success', 'outcome', 'gate_receipt_id'],
      owner_approval: {
        mode: 'ordinary_non_arbitrated', proof_path: null, proof_shape: null, dashboard_receipt_required: false,
        trusted_completion_receipt_required: true, receipt_field: 'owner_approval_receipt_id',
        approval_endpoint: '/v1/dashboard/enforcement/owner-approval', approval_authority: 'host_operator_or_dashboard_owner',
        approval_status_endpoint: `/v1/agent/gate-receipts/${receipt}/owner-approval`, approval_status_poll_after_ms: 5000,
        host_approval_endpoint: `/v1/agent/gate-receipts/${receipt}/host-approval`, host_approval_accepted: true,
        host_approval_trust: 'client_attested', approval_categories: ['workspace'],
        verified_approval_required: false, verified_approval_categories: [],
      },
    },
    risk_gate: { allow: true, decision: 'review_required', enforced: true, gate_required: true, gate_receipt_id: receipt, risk_level: 'high', reasons: [{ message: 'Needs approval.' }] },
    gate_receipt_id: receipt,
    exact_next_action: 'Obtain explicit owner approval before this action runs.',
  };
}

// One hook call in its own fake home; `payload` may be a function of the fake home (for an event cwd inside it).
function runHook(entrypoint, payload, { env = {}, runtime = allowRuntime(), after = [], mock = {} } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-all-bash-'));
  try {
    const home = join(dir, 'home');
    const mockDir = join(dir, 'mock');
    mkdirSync(join(home, 'proj'), { recursive: true, mode: 0o700 });
    writeOfficialHostConfigs(home);
    mkdirSync(mockDir);
    writeFileSync(join(mockDir, 'config.json'), JSON.stringify({ runtime, ...mock }));
    const apiKey = `mrw_test_${randomBytes(16).toString('hex')}`;
    let result;
    for (const [step, body] of [[entrypoint, payload], ...after]) {
    result = spawnSync(process.execPath, [CLI, step], {
      input: JSON.stringify(typeof body === 'function' ? body(home) : body),
      cwd: projectCwd(),
      env: {
        PATH: process.env.PATH, HOME: home, MARROW_API_KEY: apiKey,
        MARROW_BASE_URL: 'https://api.example.test', MARROW_AGENT_ID: 'agent-one', MARROW_HOOK_BACKGROUND_NUDGE: 'false',
        MARROW_PASSIVE_TOKEN_USAGE: 'false', MARROW_TEST_MOCK_DIR: mockDir, NODE_OPTIONS: `--require=${MOCK}`, ...env,
      },
      encoding: 'utf8',
      timeout: 30_000,
    });
    assert.equal(result.error, undefined);
    }
    const log = join(mockDir, 'requests.jsonl');
    const requests = existsSync(log) ? readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line)) : [];
    const isRuntime = (r) => r.path === '/v1/agent/runtime' && /^classified \S+ action/.test(r.body?.action || '');
    const files = [];
    const walk = (path) => {
      for (const name of readdirSync(path)) {
        const child = join(path, name);
        if (statSync(child).isDirectory()) walk(child); else files.push(readFileSync(child, 'latin1'));
      }
    };
    walk(home);
    return {
      bodies: requests.filter(isRuntime).map((r) => r.body), others: requests.filter((r) => !isRuntime(r)), requests,
      stdio: `${result.stdout}\n${result.stderr}`, homeBytes: files.join('\n'),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const claudeEvent = (command, extra = {}) => (home) => ({ session_id: SESSION, cwd: join(home, 'proj'), permission_mode: 'default', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command, description: 'x' }, tool_use_id: 'toolu_01ALLBASH00000000000000', ...extra });
const codexEvent = (command) => (home) => ({ session_id: SESSION, cwd: join(home, 'proj'), hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, tool_use_id: 'call_allbash_1', model: 'm', permission_mode: 'default' });
const geminiEvent = (command) => (home) => ({ session_id: SESSION, cwd: join(home, 'proj'), hook_event_name: 'BeforeTool', tool_name: 'run_shell_command', tool_input: { command } });
const grokEvent = (command) => (home) => ({ hookEventName: 'PreToolUse', sessionId: SESSION, toolUseId: 'grok-allbash-1', cwd: join(home, 'proj'), toolName: 'Bash', toolInput: { command } });
const windsurfEvent = (command) => (home) => ({ agent_action_name: 'pre_run_command', trajectory_id: 'traj-allbash-1', execution_id: 'exec-allbash-1', tool_info: { command_line: command, cwd: join(home, 'proj') } });

// The 3.9.111 action: the runtime was called, the keyed hash (not the plain one), no text, no folder, and the whole
// body (but for the device-keyed hash value) equals the opt-out body, which is the 3.9.111 body.
function assertWithheld(entrypoint, payload, text, label, secrets = []) {
  const sent = runHook(entrypoint, payload);
  const off = runHook(entrypoint, payload, { env: { MARROW_HOOK_COMMAND_TEXT: 'off' } });
  assert.equal(off.bodies.length, sent.bodies.length, `${label}: same calls as the opt-out`);
  for (const [i, body] of sent.bodies.entries()) {
    const input = body.normalized_action.tool_input;
    assert.equal('command' in input, false, `${label}: no text`);
    assert.equal('cwd' in body.normalized_action, false, `${label}: no folder`);
    if ('command_sha256' in input) assert.notEqual(input.command_sha256, P(text), `${label}: the keyed hash, not the plain one`);
    const strip = (b) => JSON.stringify({ ...b, normalized_action: { ...b.normalized_action, tool_input: Object.keys(b.normalized_action.tool_input) } });
    assert.equal(strip(body), strip(off.bodies[i]), `${label}: the opt-out (3.9.111) body`);
  }
  assert.equal(JSON.stringify(sent.requests).includes(P(text)), false, `${label}: no plain hash in any request`);
  assert.equal(JSON.stringify(sent.requests).includes('"cwd":"~'), false, `${label}: no folder in any request`);
  for (const secret of secrets) {
    for (const [where, bytes] of [['request', JSON.stringify(sent.requests)], ['home', sent.homeBytes], ['output', sent.stdio]]) {
      assert.equal(bytes.includes(secret), false, `${label}: the dummy secret is in no ${where}`);
    }
  }
  return sent;
}

function findActions(value) {
  if (!value || typeof value !== 'object') return [];
  const own = value.normalized_action ? [{ ...value.normalized_action }] : [];
  return [...own, ...Object.values(value).flatMap(findActions)];
}

// ------------------------------------------------------------------ CL-1: ordinary raw Claude Code Bash calls

test('CL-1 raw Claude Code Bash: the runtime body carries the command text, its plain hash and the home-relative folder', () => {
  for (const text of SENT) {
    const sent = runHook('claude-pre-action-hook', claudeEvent(text));
    assert.equal(sent.bodies.length, 1, `${text}: the runtime was called once`);
    const action = sent.bodies[0].normalized_action;
    assert.deepEqual(action.tool_input, { command_sha256: P(text), command: text }, `${text}: text and plain hash`);
    assert.equal(action.cwd, '~/proj', `${text}: the home-relative folder`);
    assert.equal(action.tool_kind, 'shell');
    assert.equal(action.tool_name, 'Bash');
    for (const other of sent.others) assert.equal(JSON.stringify(other).includes(text), false, `${text}: the text is only on the runtime call (${other.path})`);
  }
});

test('CL-1 hold part: the hold, denial and approval records keep the plain hash without the text or the folder', () => {
  for (const text of SENT) {
    const rejected = (home) => ({ ...claudeEvent(text)(home), hook_event_name: 'PostToolBatch', tool_name: undefined, tool_input: undefined,
      tool_calls: [{ tool_name: 'Bash', tool_input: { command: text, description: 'x' }, tool_use_id: 'toolu_01ALLBASH00000000000000', tool_response: "The user doesn't want to proceed with this tool use. The tool use was rejected (eg. if it was a file edit, the new_string was NOT written to the file). STOP what you are doing and wait for the user to tell you how to proceed." }] });
    const sent = runHook('claude-pre-action-hook', claudeEvent(text), { runtime: heldRuntime(), after: [['claude-hook', rejected]] });
    assert.equal(sent.bodies.length, 1, `${text}: the runtime was called once`);
    const reported = sent.others.flatMap((r) => findActions(r.body));
    assert.ok(reported.length >= 1, `${text}: the decline was reported with its normalized action`);
    for (const action of reported) assert.deepEqual(action.tool_input, { command_sha256: P(text) }, `${text}: the report keeps the plain hash only`);
    for (const action of reported) assert.equal('cwd' in action, false, `${text}: no folder in the report`);
    assert.equal(sent.bodies[0].normalized_action.tool_input.command, text, `${text}: the runtime call has the text`);
    assert.ok(sent.homeBytes.includes(P(text)), `${text}: the hold record keeps the plain hash`);
    assert.equal(sent.homeBytes.includes(text), false, `${text}: no text in any record on disk`);
    assert.equal(sent.homeBytes.includes('~/proj'), false, `${text}: no folder in any record on disk`);
    for (const other of sent.others) {
      assert.equal(JSON.stringify(other).includes(text), false, `${text}: no text in ${other.path}`);
      assert.equal(JSON.stringify(other).includes('"cwd":"~'), false, `${text}: no folder in ${other.path}`);
    }
  }
});

test('CL-1 privacy: with Marrow unreachable, the text and folder reach no file, spool or output', () => {
  for (const text of SENT) {
    for (const runtime of [allowRuntime(), heldRuntime()]) {
      const sent = runHook('claude-pre-action-hook', claudeEvent(text), { runtime, mock: { runtimeUnreachable: true } });
      assert.equal(sent.homeBytes.includes(text), false, `${text}: no text on disk`);
      assert.equal(sent.homeBytes.includes('~/proj'), false, `${text}: no folder on disk`);
      assert.equal(sent.stdio.includes(text), false, `${text}: no text in the output`);
    }
  }
});

test('CL-1 reads stay local read-only passes with no runtime call, as in 3.9.112: nothing leaves', () => {
  for (const text of READS) {
    const sent = runHook('claude-pre-action-hook', claudeEvent(text));
    assert.equal(sent.bodies.length, 0, `${text}: no runtime call`);
    assert.equal(JSON.stringify(sent.requests).includes(text), false, `${text}: no text in any request`);
  }
});

test('CL-1 held for main: a quoting signature or a data hash in the normalized text sends no text (fail closed)', () => {
  assertWithheld('claude-pre-action-hook', claudeEvent("printf 'row\\n' >> ./records/STATE.md"), "printf 'row\\n' >> ./records/STATE.md", 'printf append');
  assertWithheld('claude-pre-action-hook', claudeEvent('cd ~/proj && ls'), 'cd ~/proj && ls', 'cd home');
});

// ------------------------------------------------------------------ CL-2: secret-shaped inputs send no text

function secretVariants() {
  const v = dummy();
  const h = dummyHex(20);
  const jwt = `${'ey'}J${randomBytes(12).toString('base64url')}.${'ey'}J${randomBytes(12).toString('base64url')}.${randomBytes(16).toString('base64url')}`;
  const pem = `${'-----'}BEGIN ${'PRIV'}ATE ${'KEY'}-----`;
  const akia = `${'AK'}IA${randomBytes(8).toString('hex').toUpperCase()}`;
  const b64 = `Zq${randomBytes(24).toString('base64').replace(/[+/=]/g, 'x')}9`;
  return [
    [`FOO=${v} ls`, v], [`export TOKEN=${v}`, v], [`curl -H 'Authorization: Bearer ${v}' u`, v], [`ls --token ${v}`, v],
    [`git clone https://user:${v}@host/r`, v], [`cat <<EOF\n${v}\nEOF`, v], [`cat <<< ${v}`, v], [`ls ${jwt}`, jwt],
    [`echo ${pem}`, 'BEGIN'], [`ls ${akia}`, akia], [`ls ${h}`, h], [`ls ${b64}`, b64], [`mysql -p ${v}`, v], [`mysql -p${v}`, v],
    [`sshpass -p ${v} ssh host`, v], [`psql -p ${v}`, v], [`ls --password ${v}`, v], [`ls --secret ${v}`, v], [`ls --key ${v}`, v],
    [`ls --auth ${v}`, v], [`curl -H X-Api:${v} u`, v], [`curl --header X:${v} u`, v], [`ls && FOO=${v} ls`, v], [`ls; FOO=${v} ls`, v],
    [`ls | FOO=${v} ls`, v], [`ls\nFOO=${v} ls`, v], [`echo "FOO=${v}"`, v], [`curl https://h/x?t=${v}`, v], [`declare X=${v}`, v],
    [`set X=${v}`, v], [`curl -u admin:${v} u`, v], [`ls ./a:${v}@host`, v], [`ls Bearer ${v}`, v], [`ls -p${v}`, v],
  ];
}

test('CL-2 secret-shaped inputs in every position send no text and no folder; the dummy is in no body, record or log', () => {
  for (const [command, secret] of secretVariants()) {
    assertWithheld('claude-pre-action-hook', claudeEvent(command), command, JSON.stringify(command.slice(0, 12)), [secret]);
  }
});

// ------------------------------------------------------------------ CL-3 and COL-1: the text is bound to its plain hash

test('CL-3 the plain hash is the hash of exactly the text sent; one changed character fails the server check', () => {
  const verify = (input) => typeof input.command === 'string' && createHash('sha256').update(`marrow-normalized-action-v3\nshell\n${input.command}`).digest('hex') === input.command_sha256;
  const salt = randomBytes(32);
  for (const text of SENT) {
    const action = normalizedHookAction({ tool_name: 'Bash', tool_input: { command: text } }, { salt, claudeCodeBash: true, bashText: {} });
    assert.equal(action.tool_input.command, text);
    assert.equal(verify(action.tool_input), true, `${text}: verifies`);
    const flipped = `${text.slice(0, -1)}${text.endsWith('x') ? 'y' : 'x'}`;
    assert.equal(verify({ ...action.tool_input, command: flipped }), false, `${text}: one changed character is a mismatch`);
    assert.equal(verify({ ...action.tool_input, command_sha256: `${action.tool_input.command_sha256.slice(0, -1)}${action.tool_input.command_sha256.endsWith('0') ? '1' : '0'}` }), false);
  }
});

test('COL-1 commands that differ in one character get different texts and hashes; ones differing only in a secret send none', () => {
  const salt = randomBytes(32);
  const run = (command) => normalizedHookAction({ tool_name: 'Bash', tool_input: { command } }, { salt, claudeCodeBash: true, bashText: {} });
  const pairs = [['ls -l ./out', 'ls -l ./oux'], ['ls -l ./out', 'ls -L ./out'], ['grep -rl foo ./src', 'grep -rl fop ./src'], ['ls ./a | wc -l', 'ls ./a ; wc -l'], ['mkdir -p ./out/x', 'mkdir -p ./out/y']];
  for (const [a, b] of pairs) {
    const [x, y] = [run(a), run(b)];
    assert.equal(x.tool_input.command, a);
    assert.equal(y.tool_input.command, b);
    assert.notEqual(x.tool_input.command_sha256, y.tool_input.command_sha256, `${a} / ${b}`);
  }
  const [s1, s2] = [dummy(), dummy()];
  const [x, y] = [run(`ls --token ${s1}`), run(`ls --token ${s2}`)];
  for (const [action, secret] of [[x, s1], [y, s2]]) {
    assert.equal('command' in action.tool_input, false);
    assert.equal(JSON.stringify(action).includes(secret), false, 'no secret in the action');
  }
  assert.notEqual(x.tool_input.command_sha256, P(`ls --token ${s1}`), 'the keyed hash, not the plain one');
});

// ------------------------------------------------------------------ CL-4: deadline and size

test('CL-4 normalizing past its deadline or a command over the cap sends no text and no folder', () => {
  const salt = randomBytes(32);
  const late = { cwd: join(require('node:os').homedir(), 'proj') };
  const action = normalizedHookAction({ tool_name: 'Bash', tool_input: { command: 'ls -l ./out' } }, { salt, claudeCodeBash: true, deadlineAt: Date.now() - 1, bashText: late });
  assert.equal(action.truncated, true, 'the truncated placeholder');
  assert.equal('command' in action.tool_input, false);
  assert.equal('cwd' in action, false);
  assert.equal(late.sent, undefined);
  const long = `ls${' ./a'.repeat(2250)}`;
  assert.equal(long.length, 9002);
  assertWithheld('claude-pre-action-hook', claudeEvent(long), long, 'over the cap');
  const atCap = `ls${' ./a'.repeat(2047)}${' ./ab'}`.slice(0, 8192);
  const below = normalizedHookAction({ tool_name: 'Bash', tool_input: { command: atCap } }, { salt, claudeCodeBash: true, bashText: {} });
  assert.equal(atCap.length, 8192);
  assert.equal(below.tool_input.command, atCap, 'exactly at the cap is sent');
  const over = normalizedHookAction({ tool_name: 'Bash', tool_input: { command: `${atCap}b` } }, { salt, claudeCodeBash: true, bashText: {} });
  assert.equal('command' in over.tool_input, false, 'one past the cap is not');
});

// ------------------------------------------------------------------ CL-5: every other host is unchanged

test('CL-5 other hosts, entrypoints and renamed calls send the 3.9.111 action for every ordinary command', () => {
  for (const text of SENT) {
    assertWithheld('codex-pre-action-hook', codexEvent(text), text, `codex ${text}`);
    assertWithheld('gemini-pre-action-hook', geminiEvent(text), text, `gemini ${text}`);
    assertWithheld('grok-pre-action-hook', grokEvent(text), text, `grok ${text}`);
    assertWithheld('windsurf-pre-action-hook', windsurfEvent(text), text, `windsurf ${text}`);
  }
  const text = SENT[0];
  for (const entrypoint of ['cursor-pre-action-hook', 'cline-pre-action-hook', 'pre-action-hook', '--pre-action-hook']) {
    assertWithheld(entrypoint, claudeEvent(text), text, `${entrypoint}`);
  }
  assertWithheld('claude-pre-action-hook', claudeEvent(text, { tool_name: 'bash' }), text, 'renamed tool');
  assertWithheld('claude-pre-action-hook', grokEvent(text), text, 'grok event at the Claude Code entrypoint');
  assertWithheld('claude-pre-action-hook', (home) => ({ ...claudeEvent(text)(home), hookEventName: 'PreToolUse', toolName: 'Bash', toolInput: { command: text } }), text, 'claude + camel fields');
  assertWithheld('claude-pre-action-hook', windsurfEvent(text), text, 'windsurf event at the Claude Code entrypoint');
});

test('CL-5 unit: without the runtime-call option, or with the caller fact false, the action is the 3.9.112 action', () => {
  const salt = randomBytes(32);
  for (const text of SENT) {
    const event = { tool_name: 'Bash', tool_input: { command: text } };
    const base = JSON.stringify(normalizedHookAction(event, { salt, claudeCodeBash: true }));
    assert.equal(base.includes(text), false);
    assert.equal(JSON.stringify(normalizedHookAction(event, { salt, claudeCodeBash: false, bashText: { cwd: '/x' } })), JSON.stringify(normalizedHookAction(event, { salt, claudeCodeBash: false })));
    const sent = normalizedHookAction(event, { salt, claudeCodeBash: true, bashText: {} });
    assert.deepEqual({ ...sent, tool_input: Object.keys(sent.tool_input).filter((k) => k !== 'command') }, { ...JSON.parse(base), tool_input: ['command_sha256'] });
  }
});

// ------------------------------------------------------------------ CL-6: the home-relative folder

test('CL-6 the folder is sent only as ~ or ~/relative/path inside the home folder', () => {
  const home = '/home/operator';
  assert.equal(homeRelativeFolder(home, home), '~');
  assert.equal(homeRelativeFolder(`${home}/proj`, home), '~/proj');
  assert.equal(homeRelativeFolder(`${home}/proj/sub dir/`, home), '~/proj/sub dir');
  const refused = ['/home/operatorx/proj', '/etc', '/', `${home}/../x`, `${home}/a/../../b`, `${home}/./a`, `${home}//a`, `${home}/a\u0001b`,
    `${home}/café`, `${home}/a​b`, `${home}/.ssh`, `${home}/keys`, `${home}/my-token`, `${home}/secret`, `${home}/credentials`,
    `${home}/password`, `${home}/x.pem`, `${home}/app/.env`, `${home}/${'a'.repeat(511)}`, `${home}/a\\b`, 'proj', '~/proj', 42, null, undefined];
  for (const cwd of refused) assert.equal(homeRelativeFolder(cwd, home), null, JSON.stringify(cwd));
  for (const badHome of ['/', '', 'home', '/home/operator/']) assert.equal(homeRelativeFolder('/home/operator/proj', badHome), null, JSON.stringify(badHome));
  const outside = runHook('claude-pre-action-hook', (home2) => ({ ...claudeEvent(SENT[0])(home2), cwd: '/srv/elsewhere' }));
  assert.equal(outside.bodies[0].normalized_action.tool_input.command, SENT[0], 'the text is still sent');
  assert.equal('cwd' in outside.bodies[0].normalized_action, false, 'outside the home folder: no folder');
  const named = runHook('claude-pre-action-hook', (home2) => ({ ...claudeEvent(SENT[0])(home2), cwd: join(home2, 'proj', '.secrets') }));
  assert.equal('cwd' in named.bodies[0].normalized_action, false, 'a secret-named folder: no folder');
});

// ------------------------------------------------------------------ CL-7: the class and the rest of the body are unchanged

test('CL-7 the class labels of the runtime body equal the opt-out body; only the text, plain hash and folder are added', () => {
  for (const text of SENT) {
    const sent = runHook('claude-pre-action-hook', claudeEvent(text));
    const off = runHook('claude-pre-action-hook', claudeEvent(text), { env: { MARROW_HOOK_COMMAND_TEXT: 'off' } });
    const { normalized_action: a, ...restSent } = sent.bodies[0];
    const { normalized_action: b, ...restOff } = off.bodies[0];
    assert.deepEqual(restSent, restOff, `${text}: action, target, type, role, surfaces and risk unchanged`);
    // The 3.9.112 labels of these calls, pinned: the client decides nothing about the class.
    const { session_id: _s, agent_id: _a, ...labels } = restSent;
    assert.deepEqual(labels, { action: 'classified Bash action: process on workspace', target: 'workspace:process', type: 'process', role: 'general', surfaces: ['workspace'] }, `${text}: 3.9.112 labels`);
    const { cwd, tool_input: ia, ...actionSent } = a;
    const { tool_input: ib, ...actionOff } = b;
    assert.equal(cwd, '~/proj');
    assert.deepEqual(actionSent, actionOff, `${text}: kind, tool name and programs unchanged`);
    assert.deepEqual(Object.keys(ib), ['command_sha256']);
    assert.deepEqual(Object.keys(ia).sort(), ['command', 'command_sha256']);
  }
});

// ------------------------------------------------------------------ CL-9: hostile events and chains

test('CL-9 malformed or hostile events send no text', () => {
  const salt = randomBytes(32);
  const none = (event, label) => {
    const action = normalizedHookAction(event, { salt, claudeCodeBash: true, bashText: {} });
    assert.equal('command' in action.tool_input, false, label);
    assert.equal('cwd' in action, false, label);
  };
  none({ tool_name: 'Bash', tool_input: { command: 42 } }, 'number');
  none({ tool_name: 'Bash', tool_input: { command: ['ls', '-l'] } }, 'argument vector');
  none({ tool_name: 'Bash', tool_input: { cmd: 'ls -l ./out' } }, 'cmd field');
  none({ tool_name: 'Bash', tool_input: { command: 'ls -l ./out', cmd: 'ls' } }, 'command and cmd');
  none({ tool_name: 'Monitor', tool_input: { command: 'ls -l ./out' } }, 'Monitor');
  none({ tool_name: 'PowerShell', tool_input: { command: 'ls -l ./out' } }, 'PowerShell');
  none({ tool_name: 'Bash', tool_input: { command: 'ls -l ./out' }, input_truncated: true }, 'input_truncated');
  none({ tool_name: 'Bash', tool_input: { command: 'ls -l ./out' }, input_truncated: false }, 'input_truncated false');
  for (const command of ['ls\t./out', 'ls ./o\u0001ut', 'ls ./café', 'ls ./a​b', 'ls ./ａ', 'ls ./out\r', 'ls ./out\n']) none({ tool_name: 'Bash', tool_input: { command } }, JSON.stringify(command));
  assertWithheld('claude-pre-action-hook', claudeEvent('ls ./out', { input_truncated: true }), 'ls ./out', 'hook input_truncated');
});

test('CL-9 chains, repeated flags, misleading words and unknown flags are sent unchanged: the client decides nothing', () => {
  const salt = randomBytes(32);
  for (const command of ['ls ./a && rm -rf ./b', 'ls ./a ; git push origin master', 'ls ./a || curl -X POST https://example.test/x', 'ls ./a | sh',
    'bash -c ls', 'eval ls', 'ls -l -l -a', 'git commit -m safe-local-only', 'ls ./production-deploy', 'ls --frobnicate ./a', 'rm -rf ./build']) {
    const action = normalizedHookAction({ tool_name: 'Bash', tool_input: { command } }, { salt, claudeCodeBash: true, bashText: {} });
    assert.equal(action.tool_input.command, command, command);
    assert.equal(action.tool_input.command_sha256, P(command), command);
  }
});

// ------------------------------------------------------------------ R1-R3: hash form, CL-1 as amended, text only when equal

test('R1 the plain hash is the push-path form of the text sent, never a bare sha256 of it', () => {
  const sent = runHook('claude-pre-action-hook', claudeEvent('mkdir -p ./out/x'));
  const input = sent.bodies[0].normalized_action.tool_input;
  assert.equal(input.command_sha256, createHash('sha256').update(`marrow-normalized-action-v3\nshell\n${input.command}`).digest('hex'));
  assert.notEqual(input.command_sha256, createHash('sha256').update(input.command).digest('hex'), 'not a bare sha256');
});

test('CL-1 as amended: reads have no runtime call, mkdir sends text, a redirect or a quoting signature sends none', () => {
  const outcome = (text) => {
    const sent = runHook('claude-pre-action-hook', claudeEvent(text));
    if (sent.bodies.length === 0) return 'no runtime call';
    return 'command' in sent.bodies[0].normalized_action.tool_input ? 'text sent' : 'no text';
  };
  assert.deepEqual(Object.fromEntries(['ls -l ./out', 'grep -rl foo ./src | head -n 3', 'mkdir -p ./out/x', "printf 'row\\n' >> ./records/STATE.md", 'cd ~/proj && ls'].map((text) => [text, outcome(text)])), {
    'ls -l ./out': 'no runtime call', 'grep -rl foo ./src | head -n 3': 'no runtime call', 'mkdir -p ./out/x': 'text sent',
    "printf 'row\\n' >> ./records/STATE.md": 'no text', 'cd ~/proj && ls': 'no runtime call',
  });
});

test('R3 text is sent only when the normalized text is exactly the host text', () => {
  const salt = randomBytes(32);
  for (const command of ["printf 'row\\n' >> ./records/STATE.md", 'cd ~/proj && ls', "ls 'a b'", 'echo "x y"', 'sed -i s/a/b/ ./f', 'ls  ./a', 'ls ./a ', 'cat ./a > ./b', 'mkdir -p ./out/x', 'cp ./a ./b']) {
    const action = normalizedHookAction({ tool_name: 'Bash', tool_input: { command } }, { salt, claudeCodeBash: true, bashText: {} });
    if ('command' in action.tool_input) assert.equal(action.tool_input.command, command, `${command}: only the host's own text`);
  }
  for (const command of ["printf 'row\\n' >> ./records/STATE.md", 'cd ~/proj && ls', 'ls  ./a']) {
    const action = normalizedHookAction({ tool_name: 'Bash', tool_input: { command } }, { salt, claudeCodeBash: true, bashText: {} });
    assert.equal('command' in action.tool_input, false, `${command}: no text`);
    assert.notEqual(action.tool_input.command_sha256, P(command), `${command}: the keyed hash`);
  }
});

// ------------------------------------------------------------------ CL-8 / C0.7: the local client update command

test('CL-8 the local client update builds no MCP setup command; the installer update is the one update path', () => {
  const { localClientUpdate } = require('../dist/request-reliability.js');
  const { MCP_ADAPTER_VERSION } = require('../dist/hook-contract.js');
  const update = localClientUpdate();
  assert.deepEqual(update, {
    package: '@getmarrow/mcp', installed_version: MCP_ADAPTER_VERSION, installed_version_verified: true, latest_version: MCP_ADAPTER_VERSION,
    version_status: 'current', metadata_status: 'local_adapter_version', auto_update_command: 'npx @getmarrow/install@latest update',
    launch_command: 'npx -y --package=@getmarrow/mcp@latest marrow-mcp', verification_command: 'npx -y @getmarrow/install@latest doctor --self-test',
    operator_approval_required: true,
  });
  assert.equal('update_command' in update, false);
  assert.equal(Object.values(update).some((value) => /\bsetup\b/.test(String(value))), false, 'no setup command in any field');
  // The context display shows no update command for it; its allow-list still takes a pinned MCP setup form.
  const { buildCombinedContextBlock } = require('../dist/hook-context.js');
  const signals = { warnings: [], loopWarnings: [], similarCount: 0, patternsCount: 0, templatesAvailable: 0, primaryInsight: null, collectiveInsight: null, hasSignal: true };
  const display = (clientUpdate) => buildCombinedContextBlock(signals, null, null, {
    client_update: { ...clientUpdate, latest_version: '9.9.9', version_status: 'behind', update_available: true, notification_state: 'security_required', security_policy: { source: 'server_policy', minimum_secure_version: '9.9.9' } },
    risk_gate: { decision: 'allow', risk_level: 'low', allow: true }, proof_pack: { required: false, fields: [], missing: [] }, auto_outcome_closure: null, exact_next_action: null,
  });
  assert.match(display(update), /Marrow client update required by server policy/);
  assert.doesNotMatch(display(update), /Update command|install@latest update/);
  assert.match(display({ ...update, exact_update_command: 'npx -y --package=@getmarrow/mcp@9.9.9 marrow-mcp setup' }), /Update command \(operator approval\): npx -y --package=@getmarrow\/mcp@9\.9\.9 marrow-mcp setup/);
});
