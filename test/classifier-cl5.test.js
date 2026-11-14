'use strict';

// CL-5 (classifier client half): control routes from the program position (a), the host's command text with the plain
// 3A hash for a raw Claude Code Bash call (b), local floors (c), the typed approval code (d, off on this host) and
// M-SELF-APPROVE (g). Rows CX-P*, CX-A*, CX-C* of the CL-5 spec. Dummy secrets are made at run time and never printed.
const assert = require('node:assert/strict');
const test = require('node:test');
const { createHash, randomBytes } = require('node:crypto');
const { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } = require('node:fs');
const { spawnSync } = require('node:child_process');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const { normalizedHookAction } = require('../dist/normalized-action.js');
const { controlRoute } = require('../dist/control-routes.js');
const { dummySecret, assertNotLiveKey } = require('./support/dummy-secret.cjs');
const { writeOfficialHostConfigs } = require('./support/official-host-config.cjs');
const { projectCwd } = require('./support/hermetic-project.cjs');

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const MOCK = join(__dirname, 'support', 'host-approval-fetch-mock.cjs');
const SESSION = '3b1f0c2e-0000-4000-8000-00000000000c';
const P = (text) => createHash('sha256').update(`marrow-normalized-action-v3\nshell\n${text}`).digest('hex');
const bash = (command, extra = {}) => ({ tool_name: 'Bash', tool_input: { command, ...extra } });
const AN = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const pick = (n) => Array.from(randomBytes(n), (byte) => AN[byte % AN.length]).join('');
const hex = (bytes) => randomBytes(bytes).toString('hex');
const runtimeBody = (r) => r.path === '/v1/agent/runtime' && /^classified /.test(r.body?.action || '');

// ------------------------------------------------------------------ harness: the built hook in a child process, a fake backend

function heldRuntime(receipt = 'gate-cl5') {
  return {
    ok: true,
    decision_id: 'decision-cl5',
    runtime_authorization: { id: receipt, kind: 'durable_gate_receipt', durable: true, decision_state: 'created', decision_creation_required: false, decision_id: 'decision-cl5' },
    gate_receipt: { id: receipt, decision: 'review_required', required: true, owner_approval_required: true, expires_at: '2030-01-01T00:30:00.000Z' },
    proof_pack: { required: false, fields: [], complete: true },
    completion_contract: {
      decision_id: 'decision-cl5', decision_creation_required: false, decision_state: 'created',
      owner_approval_required: true, arbitration_receipt_required: false, gate_receipt_required: true,
      required_commit_fields: ['decision_id', 'success', 'outcome', 'gate_receipt_id'],
      owner_approval: {
        mode: 'ordinary_non_arbitrated', proof_path: null, proof_shape: null, dashboard_receipt_required: false,
        trusted_completion_receipt_required: true, receipt_field: 'owner_approval_receipt_id',
        approval_endpoint: '/v1/dashboard/enforcement/owner-approval', approval_authority: 'host_operator_or_dashboard_owner',
        approval_status_endpoint: `/v1/agent/gate-receipts/${receipt}/owner-approval`, approval_status_poll_after_ms: 5000,
        host_approval_endpoint: `/v1/agent/gate-receipts/${receipt}/host-approval`, host_approval_accepted: true,
        host_approval_trust: 'client_attested', approval_categories: ['source_control'],
        verified_approval_required: false, verified_approval_categories: [],
      },
    },
    risk_gate: { allow: true, decision: 'review_required', enforced: true, gate_required: true, gate_receipt_id: receipt, risk_level: 'high', reasons: [{ message: 'Needs approval.' }] },
    gate_receipt_id: receipt,
    exact_next_action: 'Obtain explicit owner approval before this action runs.',
  };
}

function harness(runtime = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-cl5-'));
  const home = join(dir, 'home');
  const mockDir = join(dir, 'mock');
  mkdirSync(home, { mode: 0o700 });
  writeOfficialHostConfigs(home);
  mkdirSync(mockDir);
  const apiKey = dummySecret();
  writeFileSync(join(mockDir, 'config.json'), JSON.stringify(runtime));
  const output = [];
  const log = join(mockDir, 'requests.jsonl');
  const requests = () => (existsSync(log) ? readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line)) : []);
  const run = (entrypoint, payload, env = {}) => {
    const result = spawnSync(process.execPath, [CLI, entrypoint], {
      input: JSON.stringify(payload),
      cwd: projectCwd(),
      env: {
        PATH: process.env.PATH, HOME: home, MARROW_API_KEY: apiKey, MARROW_BASE_URL: 'https://api.example.test',
        MARROW_AGENT_ID: 'agent-one', MARROW_HOOK_BACKGROUND_NUDGE: 'false', MARROW_PASSIVE_TOKEN_USAGE: 'false',
        MARROW_TEST_MOCK_DIR: mockDir, NODE_OPTIONS: `--require=${MOCK}`, ...env,
      },
      encoding: 'utf8',
      timeout: 30_000,
    });
    assert.equal(result.error, undefined);
    output.push(result.stdout, result.stderr);
    return result;
  };
  // The first runtime body of one PreToolUse call (null: the hook answered locally and sent none).
  const body = (command, extra = {}, entrypoint = 'claude-pre-action-hook', env = {}) => {
    rmSync(log, { force: true });
    const result = run(entrypoint, { session_id: SESSION, cwd: projectCwd(), permission_mode: 'default', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, tool_use_id: `toolu_${hex(6)}`, ...extra }, env);
    const found = requests().find(runtimeBody);
    return { body: found ? found.body : null, result };
  };
  // Every byte the hook wrote outside the fake backend's own request log: home files (state, spool, receipts, logs), stdout, stderr.
  const writtenBytes = () => {
    const parts = [...output];
    const walk = (path) => {
      for (const name of readdirSync(path)) {
        const child = join(path, name);
        const st = statSync(child);
        if (st.isDirectory()) walk(child);
        else if (st.isFile()) parts.push(readFileSync(child, 'latin1'));
      }
    };
    walk(home);
    return parts.join('\n');
  };
  return { dir, home, run, body, requests, writtenBytes, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

/** 'ROUTE' when the runtime call carries the control-off labels (security on marrow-control), else 'none'. */
function routeAnswer(h, command) {
  const { body } = h.body(command);
  return body && body.type === 'security' && Array.isArray(body.surfaces) && body.surfaces.includes('marrow-control') ? 'ROUTE' : 'none';
}

function assertRows(rows, expected) {
  const h = harness();
  try {
    const misses = rows.filter((command) => routeAnswer(h, command) !== expected).map((command) => command.slice(0, 80));
    assert.deepEqual(misses, [], `rows not answered ${expected}`);
  } finally { h.cleanup(); }
}

// ------------------------------------------------------------------ in-process call sites (CONS-2)

function asEntrypoint(entrypoint, fn) {
  const previous = process.argv[2];
  const env = process.env.MARROW_HOOK_COMMAND_TEXT;
  delete process.env.MARROW_HOOK_COMMAND_TEXT;
  process.argv[2] = entrypoint;
  try { return fn(); } finally {
    process.argv[2] = previous;
    if (env === undefined) delete process.env.MARROW_HOOK_COMMAND_TEXT; else process.env.MARROW_HOOK_COMMAND_TEXT = env;
  }
}
function legacy(event) {
  const previous = process.env.MARROW_HOOK_COMMAND_TEXT;
  process.env.MARROW_HOOK_COMMAND_TEXT = 'off';
  try { return normalizedHookAction(event, { deadlineAt: Number.POSITIVE_INFINITY, claudeCodeBash: true, sendCommandText: true }); } finally {
    if (previous === undefined) delete process.env.MARROW_HOOK_COMMAND_TEXT; else process.env.MARROW_HOOK_COMMAND_TEXT = previous;
  }
}
/** The five call sites as each one calls normalizedHookAction, in a Claude Code hook process. */
function fiveSites(event) {
  return asEntrypoint('claude-pre-action-hook', () => ({
    runtime: normalizedHookAction(event, { deadlineAt: Number.POSITIVE_INFINITY, sendCommandText: true, claudeCodeBash: true }),
    contract: normalizedHookAction(event, { deadlineAt: Number.POSITIVE_INFINITY }),
    hook: normalizedHookAction(event),
    approval: normalizedHookAction(event),
    seatbelt: normalizedHookAction(event, { deadlineAt: Date.now() + 60_000 }),
  }));
}
const stripNonce = (action) => (action.tool_input && action.tool_input.exact_hmac ? { ...action, tool_input: { ...action.tool_input, exact_hmac: 'nonce' } } : action);

// ------------------------------------------------------------------ (a) CX-P1..CX-P3: installer words in data are not a route

test('CX-P1 (F4): a printf whose quoted text names the installer next to control is not a control route', () => {
  assertRows([
    `printf '%s ran npx @getmarrow/install control enable\\n' "$(date -u +%FT%TZ)" >> ./records/LOG.md`,
  ].map((row) => row.replace(' "$(date -u +%FT%TZ)"', ' now')), 'none');
  // R4: a text the shell parser cannot read (here the substitution) keeps master's route.
  assertRows([
    `printf '%s ran npx @getmarrow/install control enable\\n' "$(date -u +%FT%TZ)" >> ./records/LOG.md`,
  ], 'ROUTE');
});

test('CX-P2 (F8, CL4-2): folder names that contain the installer name, with or without a dollar sign, are not a route', () => {
  assertRows([
    'for d in marrow marrow-install marrow-mcp; do git --git-dir=$d/repo.git grep -l foo master; done | wc -l',
    'cd ~/agents/builds/getmarrow/marrow-install && git log -1',
    'cat ./marrow-install/README.md | head -5; echo "$HOME done"',
  ], 'none');
  // R4: a text the shell parser cannot read keeps master's route (a dollar sign next to the installer name).
  assertRows([
    'for d in marrow marrow-install marrow-mcp; do (cd $d && git log -1 --format=%h); done',
    'ls ./marrow-install/ && echo "$(date -u +%FT%TZ)"',
  ], 'ROUTE');
});

test('CX-P3: a grep pattern, a commit message and a cat of a file under the installer folder are not a route', () => {
  assertRows([
    'git grep -n "@getmarrow/install control disable" -- src',
    'git commit -m "doc: npx @getmarrow/install control disable needs the owner"',
    'cat ./marrow-install/README.md',
  ], 'none');
  // R4: a text the shell parser cannot read keeps master's route.
  assertRows([
    'git commit -m "doc: npx @getmarrow/install control disable needs the owner ($(date -u +%F))"',
    'grep -rn "marrow-install control disable" ./docs | head -3; echo `date`',
    'echo "$(date -u) npx @getmarrow/install control disable" >> ./notes.md',
  ], 'ROUTE');
});

// ------------------------------------------------------------------ (a) CX-A1, CX-A2: real control-off runs stay routes

test('CX-A1: every real control-off invocation stays a control route', () => {
  assertRows([
    'npx @getmarrow/install control disable --yes',
    'npx -y @getmarrow/install@latest uninstall',
    'marrow-install control off',
    'node ./node_modules/@getmarrow/install/bin/marrow-install.js control disable',
    "bash -c 'npx @getmarrow/install control disable'",
    'sh -c "npx @getmarrow/install control disable"',
    'echo $(npx @getmarrow/install control disable)',
    'echo `npx @getmarrow/install control disable`',
    'echo "$(npx @getmarrow/install control disable)"',
    'true && npx @getmarrow/install control disable',
    'true; npx @getmarrow/install control disable',
    'false || npx @getmarrow/install control disable',
    'echo y | npx @getmarrow/install control disable',
    'FOO=1 npx @getmarrow/install control disable',
    'sudo npx @getmarrow/install control disable',
    'nohup npx @getmarrow/install control disable',
    'timeout 5 npx @getmarrow/install control disable',
    'env -i npx @getmarrow/install control disable',
    'npx @getmarrow/install control $X',
    'npx @getmarrow/install "$(echo disable)"',
    "echo 'x; npx @getmarrow/install control disable",
    '(npx @getmarrow/install control disable)',
    '{ npx @getmarrow/install control disable; }',
    'cd ./marrow-install && npx @getmarrow/install control disable $(true)',
  ], 'ROUTE');
});

test('CX-A1 (spec (a) recursion): eval, su -c and a loop body running the installer are routes (not routes on 3.9.113)', () => {
  assertRows([
    'eval "npx @getmarrow/install control disable"',
    "su -c 'npx @getmarrow/install control disable'",
    'for i in 1; do npx @getmarrow/install control disable; done',
    'for i in $(seq 1); do npx @getmarrow/install control disable; done',
  ], 'ROUTE');
});

test('CX-A2: a runner whose package argument is not a literal, in a text that names the installer, is a route (stricter)', () => {
  assertRows([
    'x=@getmarrow/install; npx $x control disable',
    'P=@getmarrow/install; npx "$P" control disable',
    'npx $(echo @getmarrow/install) control disable',
    'P=@getmarrow/install; npx ${P} control disable',
    'P=@getmarrow/install; npm exec $P -- control disable',
  ], 'ROUTE');
});

test('(a) faults fail closed: a thrown error inside the route check is a route', () => {
  const original = RegExp.prototype.test;
  let calls = 0;
  // The first test passes (the text names the installer); every later one throws.
  RegExp.prototype.test = function (value) { calls += 1; if (calls > 1) throw new Error('fault'); return original.call(this, value); };
  let answer;
  try { answer = controlRoute('npx @getmarrow/install control status'); } finally { RegExp.prototype.test = original; }
  assert.equal(answer, true);
});

// ------------------------------------------------------------------ (g) CX-A8: M-SELF-APPROVE is labelled as a control-off route

test('CX-A8: a call that reports an approval for a gate receipt is security on marrow-control, protected, high', () => {
  const h = harness();
  try {
    const rows = [
      'python3 -I ~/agents/cliff-tools/host_report.py rcpt approve KEY_NAME 2026-11-14T00:00:00Z 2026-11-14T00:01:00Z post',
      'python3 -I ~/agents/cliff-tools/host_report.py --port 8787 rcpt approve KEY_NAME a b post',
      'python3 ./x/approval-link.py rcpt',
      './host_report.py rcpt approve KEY_NAME a b post',
      `node -e "fetch('https://api.getmarrow.ai/v1/agent/gate-receipts/'+r+'/host-approval',{method:'POST'})"`,
      'curl -X POST https://api.getmarrow.ai/v1/agent/gate-receipts/abc/host-approval -d @f',
      'curl "$BASE/v1/agent/GATE-RECEIPTS/abc/Host-Approval"',
      'curl -X POST "https://api.example.test/v1/agent%2Fgate-receipts%2Fabc%2Fapproval-link"',
      'wget -qO- https://api.example.test//v1//agent//gate-receipts//abc//host-approval',
      "bash -c 'python3 host_report.py a b K c d post'",
      'cd x && python3 host_report.py a b K c d post',
      'env X=1 nohup python3 host_report.py a b K c d post',
      "python3 - <<'EOF'\nimport urllib.request\nurllib.request.urlopen(urllib.request.Request('https://api.example.test/v1/agent/gate-receipts/abc/approval-link', method='POST'))\nEOF",
      'echo ok && PYTHONPATH=. python3 tools/Host-Report rcpt',
    ];
    const misses = [];
    for (const command of rows) {
      const { body } = h.body(command);
      const ok = body && body.type === 'security' && body.surfaces.includes('marrow-control') && body.risk_level === 'high';
      if (!ok) misses.push(command.slice(0, 70));
    }
    assert.deepEqual(misses, [], 'self-approve rows not labelled as a control-off route');
  } finally { h.cleanup(); }
});

test('CX-A8: a data operand that only names the report script or path gets no new label', () => {
  assertRows([
    'grep -n host-approval src/x.ts',
    "printf 'ran host_report.py\\n' >> ./LOG.md",
    'git commit -m "host_report.py fix"',
    'sed -n 1,40p host_report.py',
    'cat ./tools/approval-link.py',
  ], 'none');
});

// ------------------------------------------------------------------ (b) CX-P4: the 3A text for a raw Claude Code Bash call

const FRICTION = () => {
  const mark = `cl5${hex(5)}`;
  return [
    `printf '%s ${mark} status line with deploy, push and production words\\n' "$(date -u +%FT%TZ)" >> ~/agents/x/records/LOG.md`,
    `mkdir -p ./scratch/${mark}/src && git --git-dir=/home/agent/builds/m/repo.git show ec38f8fe:src/a.ts > ./scratch/${mark}/src/a.ts`,
    `cat > ./notes-${mark}.md <<'EOF'\nline one\nrm -rf ./src is only data here\nEOF`,
    `printf '\\nnote ${mark}\\n' >> ~/.claude/projects/p/memory/note.md`,
    `printf x > ./src/${mark}.ts`,
    `git --git-dir=repo.git grep -nE "wrangler\\.toml|${mark}" HEAD -- 'src/*.ts' | cut -c1-200 | head -40 > ./scratch/${mark}.txt`,
  ];
};

test('CX-P4: the runtime body carries the host text with the plain 3A hash; no other request or local file carries the text', () => {
  const h = harness({ runtime: heldRuntime() });
  try {
    for (const command of FRICTION()) {
      const { body } = h.body(command);
      assert.ok(body, `runtime call for ${command.slice(0, 40)}`);
      const input = body.normalized_action.tool_input;
      assert.equal(input.command, command, 'the host text unchanged');
      assert.equal(input.command_sha256, P(command), 'the plain 3A hash');
      assert.equal(input.exact_hmac, undefined);
      assert.equal(body.normalized_action.truncated, undefined);
      const others = h.requests().filter((r) => !runtimeBody(r));
      assert.equal(JSON.stringify(others).includes(command.split('\n')[0]), false, 'text only on the runtime call');
      for (const r of others) {
        for (const field of JSON.stringify(r.body || {}).match(/"command_sha256":"[0-9a-f]{64}"/g) || []) {
          assert.equal(field, `"command_sha256":"${P(command)}"`, `same hash on ${r.path}`);
        }
      }
      assert.equal(h.writtenBytes().includes(command.split('\n')[0]), false, 'no text in a local file, log or output');
    }
  } finally { h.cleanup(); }
});

test('CX-P4: the host report of a rejected hold carries the same plain hash and no text', () => {
  const h = harness({ runtime: heldRuntime() });
  try {
    const command = FRICTION()[0];
    const id = `toolu_${hex(6)}`;
    h.run('claude-pre-action-hook', { session_id: SESSION, cwd: projectCwd(), permission_mode: 'default', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, tool_use_id: id });
    h.run('claude-hook', {
      session_id: SESSION, cwd: projectCwd(), permission_mode: 'default', hook_event_name: 'PostToolBatch',
      tool_calls: [{ tool_name: 'Bash', tool_input: { command }, tool_use_id: id, tool_response: "The user doesn't want to proceed with this tool use. The tool use was rejected (eg. if it was a file edit, the new_string was NOT written to the file). STOP what you are doing and wait for the user to tell you how to proceed." }],
    });
    const reports = h.requests().filter((r) => /\/host-approval$/.test(r.path));
    assert.ok(reports.length >= 1, 'a host report');
    for (const report of reports) {
      const text = JSON.stringify(report.body);
      assert.equal(text.includes(command), false, 'no text in the report');
      const hashes = text.match(/"command_sha256":"[0-9a-f]{64}"/g) || [];
      assert.ok(hashes.length >= 1);
      for (const field of hashes) assert.equal(field, `"command_sha256":"${P(command)}"`);
    }
  } finally { h.cleanup(); }
});

// ------------------------------------------------------------------ (b) CX-A3: a planted secret sends no text

function plantedSecrets() {
  const d = dummySecret();
  return [
    `curl -H "Authorization: Bearer ${d}" https://api.example.test/v1/x`,
    `curl -H "Authorization: Basic ${d}" https://api.example.test/v1/x`,
    `curl -u admin:${d} https://api.example.test/v1/x`,
    `git clone https://admin:${d}@git.example.test/o/r.git`,
    ...['token', 'key', 'access_token', 'sig', 'signature', 'code'].map((name) => `curl "https://api.example.test/v1/x?${name}=${d}&page=2"`),
    `API_KEY=${d} node ./run.js`,
    `export TOKEN=${d}`,
    ...['password', 'secret', 'api_key', 'token'].map((name) => `curl -d '{"${name}":"${d}","page":2}' https://api.example.test/v1/x`),
    `curl -H 'X-Api-Key: ${d}' https://api.example.test/v1/x`,
    `mysql --password ${d} -e 'select 1'`,
    `mysql -p${d} -e 'select 1'`,
    `./run.sh --token ${d}`,
    `curl -s https://api.example.test/v1/x -d note=${hex(16)}`,
    `echo ${pick(24)}9aZ > ./a.md`,
  ].map((command) => ({ secret: command.includes(d) ? d : null, command }));
}

test('CX-A3: a command with a planted secret sends no text and keeps the secret out of every body and key', () => {
  let sent = 0;
  for (const { secret, command } of plantedSecrets()) {
    const sites = fiveSites(bash(command));
    if (secret) for (const action of Object.values(sites)) assert.equal(JSON.stringify(action).includes(secret), false, 'the secret is in no body or key');
    if (sites.runtime.tool_input.command !== undefined) sent += 1;
  }
  assert.equal(sent, 0, 'RESIDUAL_SECRET_SHAPES: no planted row is sent as text');
});

// ------------------------------------------------------------------ (b) CX-A4, CX-A5: one hash at every call site; other hosts unchanged

test('CX-A4: the same event gets the same command_sha256 at all five call sites; a sent text always has its 3A hash', () => {
  const rows = [...FRICTION(), 'git push origin feat/x', 'npx wrangler deploy --env production', `curl -H "Authorization: Bearer ${dummySecret()}" https://x.test/a`, 'printf "é" > ./a.md', `printf ${'y'.repeat(8200)} > ./a.md`];
  for (const command of rows) {
    const sites = fiveSites(bash(command));
    const hashes = new Set(Object.values(sites).map((action) => action.tool_input.command_sha256));
    assert.equal(hashes.size, 1, `one hash at five call sites: ${command.slice(0, 40)}`);
    for (const [name, action] of Object.entries(sites)) {
      if (action.tool_input.command !== undefined) assert.equal(action.tool_input.command_sha256, P(action.tool_input.command), `${name}: text with its plain hash`);
      if (name !== 'runtime' && !/^npx wrangler deploy/.test(command)) assert.equal(action.tool_input.command, undefined, `${name}: no text off the runtime call`);
    }
  }
});

test('CX-A4: a call that is not eligible keeps its 3.9.113 action byte for byte', () => {
  for (const command of [`curl -H "Authorization: Bearer ${dummySecret()}" https://x.test/a`, 'printf "é" > ./a.md', `printf ${'y'.repeat(8200)} > ./a.md`, `echo ${pick(24)}9aZ > ./a.md`]) {
    const sites = fiveSites(bash(command));
    assert.deepEqual(stripNonce(sites.runtime), stripNonce(legacy(bash(command))), command.slice(0, 30));
  }
});

test('CX-A4: eligible raw Claude Code Bash rows carry the 3A text on the runtime call and the 3A hash everywhere', () => {
  for (const command of FRICTION()) {
    const sites = fiveSites(bash(command));
    assert.equal(sites.runtime.tool_input.command, command);
    assert.equal(sites.contract.tool_input.command_sha256, P(command));
  }
});

test('CX-A5: other hosts, the opt-out, a renamed or rebuilt call, input_truncated, Monitor and PowerShell keep the 3.9.113 action', () => {
  const command = FRICTION()[0];
  for (const entrypoint of ['codex-pre-action-hook', 'gemini-pre-action-hook', 'cursor-pre-action-hook', 'cline-pre-action-hook', 'windsurf-pre-action-hook', 'grok-pre-action-hook', 'pre-action-hook', 'hook']) {
    const action = asEntrypoint(entrypoint, () => normalizedHookAction(bash(command), { deadlineAt: Number.POSITIVE_INFINITY }));
    assert.deepEqual(action, legacy(bash(command)), entrypoint);
  }
  const off = asEntrypoint('claude-pre-action-hook', () => {
    process.env.MARROW_HOOK_COMMAND_TEXT = 'off';
    return normalizedHookAction(bash(command), { deadlineAt: Number.POSITIVE_INFINITY, claudeCodeBash: true, sendCommandText: true });
  });
  assert.deepEqual(off, legacy(bash(command)), 'MARROW_HOOK_COMMAND_TEXT=off');
  for (const event of [
    { tool_name: 'bash', tool_input: { command } }, { tool_name: 'Bash ', tool_input: { command } }, { tool_name: 'Monitor', tool_input: { command } },
    { tool_name: 'PowerShell', tool_input: { command } }, { tool_name: 'Bash', tool_input: { command, cmd: command } }, { tool_name: 'Bash', tool_input: { cmd: command } },
    { ...bash(command), input_truncated: true },
  ]) {
    const action = asEntrypoint('claude-pre-action-hook', () => normalizedHookAction(event, { deadlineAt: Number.POSITIVE_INFINITY, sendCommandText: true }));
    assert.deepEqual(stripNonce(action), stripNonce(legacy(event)), JSON.stringify(event.tool_name));
  }
  const adapted = asEntrypoint('claude-pre-action-hook', () => normalizedHookAction(bash(command), { deadlineAt: Number.POSITIVE_INFINITY, sendCommandText: true, claudeCodeBash: false }));
  assert.deepEqual(adapted, legacy(bash(command)), 'a renamed or adapter-rebuilt call (claudeCodeBash false)');
});

test('CX-A5: through the real hooks, another host entrypoint and the opt-out send no text', () => {
  const h = harness();
  try {
    const command = FRICTION()[4];
    for (const entrypoint of ['codex-pre-action-hook', 'gemini-pre-action-hook']) {
      const { body } = h.body(command, {}, entrypoint);
      if (body) assert.equal(body.normalized_action.tool_input.command, undefined, entrypoint);
    }
    const { body } = h.body(command, {}, 'claude-pre-action-hook', { MARROW_HOOK_COMMAND_TEXT: 'off' });
    assert.ok(body);
    assert.equal(body.normalized_action.tool_input.command, undefined, 'opt-out');
  } finally { h.cleanup(); }
});

// ------------------------------------------------------------------ CX-C1: collisions

test('CX-C1: eligible calls that differ in any byte get different hashes; secrets never in a key', () => {
  const variants = ['printf x > ./src/a.ts', 'printf x > ./src/b.ts', 'printf x  > ./src/a.ts', "printf 'x' > ./src/a.ts", 'printf x > ./src/a.ts\n', 'printf x >> ./src/a.ts', 'printf x > ./src/a.ts;'];
  const hashes = variants.map((command) => fiveSites(bash(command)).contract.tool_input.command_sha256);
  assert.equal(new Set(hashes).size, variants.length);
  const d1 = dummySecret();
  const d2 = dummySecret();
  const a = fiveSites(bash(`curl -H "Authorization: Bearer ${d1}" https://x.test/a?page=1`)).contract.tool_input.command_sha256;
  const b = fiveSites(bash(`curl -H "Authorization: Bearer ${d1}" https://x.test/a?page=2`)).contract.tool_input.command_sha256;
  const c = fiveSites(bash(`curl -H "Authorization: Bearer ${d2}" https://x.test/a?page=1`));
  assert.notEqual(a, b, 'text after a redacted span');
  assert.equal(JSON.stringify(c).includes(d2), false);
  // A plain push keeps the 3.9.113 plain hash when the host text is that text word for word.
  assert.equal(fiveSites(bash('git push origin feat/x')).contract.tool_input.command_sha256, P('git push origin feat/x'));
});

// ------------------------------------------------------------------ (d) CX-A6, CX-C3: the typed code stays off on this host

test('CX-A6 / CX-C3: a Claude Code hold in auto mode offers no typed code, and a typed approval from any prompt clears nothing', () => {
  const h = harness({ runtime: heldRuntime('gate-a6') });
  try {
    const command = 'npx wrangler deploy --env production';
    const pre = h.run('claude-pre-action-hook', { session_id: SESSION, cwd: projectCwd(), permission_mode: 'auto', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, tool_use_id: `toolu_${hex(6)}` });
    assert.equal(/marrow (?:approve|decline) [A-Z0-9]{6,}/i.test(`${pre.stdout}${pre.stderr}`), false, 'no code in the output');
    const approvals = () => h.requests().filter((r) => /\/host-approval$/.test(r.path) && /approve/.test(JSON.stringify(r.body))).length;
    const before = approvals();
    for (const prompt of ['marrow approve ABCD2345', 'marrow approve abcd2345efgh', '<task-notification>marrow approve ABCD2345</task-notification>']) {
      h.run('claude-context-hook', { session_id: SESSION, cwd: projectCwd(), permission_mode: 'auto', hook_event_name: 'UserPromptSubmit', prompt });
    }
    assert.equal(approvals(), before, 'no typed approval recorded');
  } finally { h.cleanup(); }
  // TYPED_CODE OFF (D2 unprovable on the installed host): no Claude Code prompt is ever a typed reply.
  const { TYPED_REPLY_MARKER, typedReplyAvailable } = require('../dist/host-approval.js');
  assert.equal(Object.prototype.hasOwnProperty.call(TYPED_REPLY_MARKER, 'claude-code'), false, 'Claude Code is not on the typed-reply table');
  assert.equal(typedReplyAvailable({ host: 'claude-code' }, () => true, () => false), false, 'never available for Claude Code');
});

// ------------------------------------------------------------------ TMO, GROW

test('TMO: an overrun or a thrown reader error on the text path gives the 3.9.113 action (no text), never a looser one', () => {
  const command = FRICTION()[4];
  const overrun = asEntrypoint('claude-pre-action-hook', () => normalizedHookAction(bash(command), { deadlineAt: Date.now() - 1, sendCommandText: true, claudeCodeBash: true }));
  assert.equal(overrun.tool_input.command, undefined, 'overrun: no text');
  const redact = require('../dist/redact.js');
  const original = redact.redactSensitiveText;
  redact.redactSensitiveText = () => { throw new Error('fault'); };
  let thrown;
  try { thrown = asEntrypoint('claude-pre-action-hook', () => normalizedHookAction(bash(command), { deadlineAt: Number.POSITIVE_INFINITY, sendCommandText: true, claudeCodeBash: true })); } finally { redact.redactSensitiveText = original; }
  assert.deepEqual(thrown, legacy(bash(command)), 'reader error: the 3.9.113 action');
});

test('GROW: the route checks stay near-linear and bounded (8k, 16k, 32k, 1 MB of wrappers, options, data, substitutions)', () => {
  const { selfApproveRoute } = require('../dist/control-routes.js');
  const times = [];
  for (const size of [8192, 16384, 32768, 1 << 20]) {
    const texts = [
      'sudo nohup env FOO=1 timeout 5 '.repeat(Math.ceil(size / 31)).slice(0, size),
      'npx -y -y -y @getmarrow/install control enable '.repeat(Math.ceil(size / 48)).slice(0, size),
      `printf '${'marrow-install $( `'.repeat(Math.ceil(size / 19)).slice(0, size)}'`,
      `echo marrow-install ${'"$(x)" '.repeat(Math.ceil(size / 7))}`.slice(0, size),
      `curl ${'/gate-receipts/x'.repeat(Math.ceil(size / 16))}`.slice(0, size),
    ];
    const start = process.hrtime.bigint();
    for (const text of texts) { controlRoute(text); selfApproveRoute(text); }
    times.push(Number(process.hrtime.bigint() - start) / 1e6);
  }
  if (process.env.CL5_GROW_LOG) writeFileSync(process.env.CL5_GROW_LOG, JSON.stringify(times));
  // A count-free bound well above the measured times (the hook's own budget is 750 ms for normalizing).
  for (const ms of times) assert.ok(ms < 750, `within the hook budget: ${Math.round(ms)} ms`);
});

// ------------------------------------------------------------------ fix round 1 (MAIN-RULING R1-R3): more abuse rows

const PAD = `; : ${'x'.repeat(9000)}`; // past the shell parser's 8 KB: the lexical fallback reads the text

test('CX-A1 (lexical): a quoted string piped or fed to a shell, eval or source keeps master\'s answer (a route)', () => {
  assertRows([
    `printf 'npx @getmarrow/install control disable\\n' | bash${PAD}`,
    `echo "npx @getmarrow/install control disable" | sh${PAD}`,
    `bash <<< 'npx @getmarrow/install control disable'${PAD}`,
    `eval < ./x 'npx @getmarrow/install control disable'${PAD}`,
    `npx @getmarrow/install control disable${PAD}`,
    `x=@getmarrow/install; npx $x control disable${PAD}`,
    // ADV: eval of a substitution that prints the installer call, and a non-ASCII text the parser cannot read.
    'eval "$(echo npx @getmarrow/install control disable)"',
    'npx @getmarrow/install control disable',
  ], 'ROUTE');
  // R4: in the lexical fallback master's route stands; a text with no control word stays no route.
  assertRows([
    `cd ~/agents/builds/getmarrow/marrow-install && git log -1${PAD}`,
  ], 'none');
  assertRows([
    `printf '%s ran npx @getmarrow/install control enable\\n' "$(date -u +%FT%TZ)" >> ./records/LOG.md${PAD}`,
    `git commit -m "doc: npx @getmarrow/install control disable needs the owner"${PAD}`,
  ], 'ROUTE');
});

test('CX-A4: a push whose host text is its grammar text word for word keeps the 3.9.113 body', () => {
  for (const command of ['git push origin feat/x', 'npx sst deploy --stage staging']) {
    const sites = fiveSites(bash(command));
    for (const site of Object.keys(sites)) assert.equal(sites[site].tool_input.command_sha256, P(command), `${command} at ${site}: the 3.9.113 plain hash`);
    assert.equal(sites.runtime.tool_input.command, command);
  }
  // 3.9.113: the deploy grammar text rides at every call site (a 3A text would ride on the runtime call only).
  const deploy = fiveSites(bash('npx sst deploy --stage staging'));
  for (const site of ['contract', 'hook', 'approval', 'seatbelt']) assert.equal(deploy[site].tool_input.command, 'npx sst deploy --stage staging', site);
  // 3.9.113: a push carries no text off the runtime call, and the opt-out keeps the keyed hash.
  assert.equal(fiveSites(bash('git push origin feat/x')).contract.tool_input.command, undefined);
  assert.notEqual(legacy(bash('git push origin feat/x')).tool_input.command_sha256, P('git push origin feat/x'));
});

/** Generated key families (key-class-rows and seatbelt-fuzz-values, all made at run time) in every Bash position. */
function generatedSecretRows() {
  const rows = require('./support/key-class-rows.cjs');
  const { SHAPES } = require('./support/seatbelt-fuzz-values.cjs');
  const families = [rows.live('sk'), rows.live('rk'), rows.live('pk'), rows.test('sk'), rows.test('pk'), ...rows.LOOKALIKES.map((l) => l.make(rows.payload())), dummySecret()];
  const out = [];
  for (const position of rows.POSITIONS) {
    for (const value of families) {
      const event = position.build(value);
      if (event.tool_name === 'Bash' && typeof event.tool_input?.command === 'string') out.push({ value, event, id: position.id });
    }
  }
  for (const make of SHAPES) {
    for (const id of ['flag-token', 'env-assign', 'header-bearer', 'url-query-token', 'json-body', 'heredoc', 'mysql-p']) {
      const position = rows.POSITIONS.find((p) => p.id === id);
      const value = make();
      if (position) out.push({ value, event: position.build(value), id });
    }
  }
  return out;
}

test('CX-A3 (generated families): no generated secret reaches any body; a sent text has 0 residual secret shapes', () => {
  const { redactSensitiveText } = require('../dist/redact.js');
  let residual = 0;
  let sent = 0;
  const rows = generatedSecretRows();
  assert.ok(rows.length > 200, `rows: ${rows.length}`);
  for (const { value, event, id } of rows) {
    const sites = fiveSites(event);
    const all = JSON.stringify(sites);
    if (all.includes(value)) residual += 1;
    const text = sites.runtime.tool_input.command;
    if (text !== undefined) {
      sent += 1;
      if (redactSensitiveText(text) !== text || text.includes(value)) residual += 1;
      assert.equal(text, event.tool_input.command, `${id}: a sent text is the host text`);
    }
  }
  if (process.env.CL5_A3_LOG) writeFileSync(process.env.CL5_A3_LOG, JSON.stringify({ rows: rows.length, sent, residual }));
  assert.equal(residual, 0, 'RESIDUAL_SECRET_SHAPES');
});

// ------------------------------------------------------------------ (b) CX-A3-JOINED (ruling R3): a hex run hidden by one separator

// Every value is drawn at run time: a short hex head, one separator, a hex run of 13 to 19 characters (a bare run that
// short is sent; joined it is not). A row is { sep, command }; the hex run is isolated only by the separator under test.
function joinedRows() {
  const run = () => assertNotLiveKey(hex(8).slice(0, 13 + (randomBytes(1)[0] % 7)));
  const head = () => hex(2);
  const rows = ['-', '_', '.', ':', '=', '@', ',', '+'].map((sep) => ({ sep, command: `echo ${head()}${sep}${run()} >> ./notes.md` }));
  rows.push({ sep: ';', command: `echo '${head()};${run()}' >> ./notes.md` });
  rows.push({ sep: "'", command: `echo ${head()}'${run()}' >> ./notes.md` });
  rows.push({ sep: '"', command: `echo ${head()}"${run()}" >> ./notes.md` });
  rows.push({ sep: '/ (://)', command: `curl -s https://x.example.test/a/${run()}/b` });
  rows.push({ sep: '? (://)', command: `curl -s 'https://x.example.test/a?${run()}'` });
  rows.push({ sep: '& (://)', command: `curl -s 'https://x.example.test/a?p=1&${run()}'` });
  rows.push({ sep: '# (://)', command: `curl -s https://x.example.test/a#${run()}` });
  rows.push({ sep: '- (4 + 24)', command: `echo ${head()}-${assertNotLiveKey(hex(12))} >> ./notes.md` });
  return rows;
}
const boundaryRows = () => [
  ['uuid', `echo ${require('node:crypto').randomUUID()} >> ./notes.md`],
  ['12-hex piece', `echo build-${hex(6)} >> ./notes.md`],
  ['40-hex piece', `git show v-${hex(20)} > ./scratch/a.txt`],
  ['64-hex piece', `echo v-${hex(32)} >> ./notes.md`],
  ['sha256: + 64 hex', `echo sha256:${hex(32)} >> ./notes.md`],
  ['folder path without ://', `cat ./runs/${hex(8)}/out.txt`],
];
const keptAction = (command) => {
  const sites = fiveSites(bash(command));
  return { sent: sites.runtime.tool_input.command, same: JSON.stringify(stripNonce(sites.runtime)) === JSON.stringify(stripNonce(legacy(bash(command)))) };
};

for (const { sep, command } of joinedRows()) {
  test(`CX-A3-JOINED (R3) ${sep}: a hex run over 12 behind the separator is not eligible (3.9.113 action, no text)`, () => {
    const { sent, same } = keptAction(command);
    assert.equal(sent, undefined, 'no text');
    assert.equal(same, true, 'the 3.9.113 keyed action');
  });
}

for (const [name, command] of boundaryRows()) {
  // sha256: + 64 hex is withheld by the exact pass before R3 (the restack answer, unchanged); every other row is sent.
  const kept = name === 'sha256: + 64 hex';
  test(`CX-A3-JOINED (R3) boundary ${name}: the restack answer (${kept ? 'withheld by the exact pass' : 'sent'})`, () => {
    const { sent, same } = keptAction(command);
    if (kept) assert.equal(sent === undefined && same, true, 'not sent, 3.9.113 action');
    else assert.equal(sent, command, 'sent');
  });
}

test('CX-A3-JOINED (R3) fails closed: a fault in the joined-word check gives the 3.9.113 action (no text)', () => {
  const [, command] = boundaryRows()[0];
  assert.equal(keptAction(command).sent, command, 'eligible without the fault');
  const original = String.prototype.includes;
  // eslint-disable-next-line no-extend-native
  String.prototype.includes = function includes(search, ...rest) { if (search === '://') throw new Error('fault'); return original.call(this, search, ...rest); };
  let kept;
  try { kept = fiveSites(bash(command)).runtime; } finally { String.prototype.includes = original; } // eslint-disable-line no-extend-native
  assert.equal(kept.tool_input.command, undefined, 'fault: no text');
  assert.deepEqual(stripNonce(kept), stripNonce(legacy(bash(command))), 'fault: the 3.9.113 action');
});

// ------------------------------------------------------------------ fix round 2 (MAIN-RULING R2): either word basis
// CORNER: one of the 13 shell characters between :// and a 17-hex segment (the shell-character word loses ://); CONTROL
// without it; FINE: a joined run inside $( ) or backticks (the whitespace word ends in ) or `). Every hex value is drawn here.
const SHELL_CHARS = ['`', '(', ')', '[', ']', '{', '}', '<', '>', '|', '!', '*', '$'];
const run17 = () => assertNotLiveKey(hex(9).slice(0, 17));
for (const c of SHELL_CHARS) {
  test(`CX-A3-JOINED (R2) CORNER ${c}: a 17-hex URL segment behind ${c}id${c} is not eligible (3.9.113 action, no text)`, () => {
    const { sent, same } = keptAction(`curl "https://h/api/${c}id${c}/${run17()}"`);
    assert.equal(sent, undefined, 'no text');
    assert.equal(same, true, 'the 3.9.113 keyed action');
  });
}
test('CX-A3-JOINED (R2) CONTROL: the same URL without a shell character stays withheld', () => {
  const { sent, same } = keptAction(`curl "https://h/api/id/${run17()}"`);
  assert.equal(sent === undefined && same, true, 'not sent, 3.9.113 action');
});
for (const [name, command] of [['$( )', () => `echo $(printf ab-${run17()}) >> ./notes.md`], ['backticks', () => `echo \`printf ab-${run17()}\` >> ./notes.md`]]) {
  test(`CX-A3-JOINED (R2) FINE ${name}: a joined run inside ${name} stays withheld`, () => {
    const { sent, same } = keptAction(command());
    assert.equal(sent === undefined && same, true, 'not sent, 3.9.113 action');
  });
}

test('CX-A7: the local floors stay (self-protect of hook settings and Marrow files; the control route deny text)', () => {
  const { selfProtectKind } = require('../dist/self-protect.js');
  const { CONTROL_ROUTE_DENY_TEXT } = require('../dist/control-routes.js');
  const home = require('node:os').homedir();
  for (const file_path of [join(home, '.claude', 'settings.json'), join(home, '.marrow', 'hooks', 'pre.js')]) {
    assert.notEqual(selfProtectKind({ tool_name: 'Write', tool_input: { file_path, content: 'x' } }), null, 'a protected write');
  }
  assert.notEqual(selfProtectKind({ tool_name: 'Bash', tool_input: { command: `rm -f ${join(home, '.claude', 'settings.json')}` } }), null);
  assert.match(CONTROL_ROUTE_DENY_TEXT, /account owner/);
});

// ------------------------------------------------------------------ fix round 3: R4 (F1a, F1b) and R6 (F3)
const I = 'npx @getmarrow/install';
// The audit's ADV-CR rows: quotes in comments and here-docs, and installer runs through other programs, on texts the parser cannot read.
const fallbackRows = () => [
  ['CR1', `find . -name x -exec ${I} control disable \; #\r`], ['CR2', `python3 -c "import os; os.system('${I} control disable')" #\r`],
  ['CR3', `# it's\r\n${I} control disable\n# it's`], ['CR3-vt', `# it's\u000b\n${I} control disable\n# it's`],
  ['CR3-ff', `# it's\u000c\n${I} control disable\n# it's`], ['CR3-dq', `# it"s\r\n${I} control disable\n# it"s`],
  ['CR3-uninstall', `# it's\r\nnpx -y @getmarrow/install@latest uninstall\n# it's`], ['CR3-9k', `# it's\n${I} control disable\n# it's\n${'true; '.repeat(1400)}`],
  ['CR4', `cat <<EOF\n'\nEOF\n${I} control disable\n# '\r`], ['CR4-noCR', `cat <<EOF\n'\nEOF\n${I} control disable\n# '`],
  ['CR5', `${'true; '.repeat(1400)}find . -exec ${I} control disable \;`], ['CR6', `watch -n1 ${I} control disable #\r`],
  ['CR9', `ssh host ${I} control disable #\r`], ['CR5-33k', `${'true; '.repeat(5600)}find . -exec ${I} control disable \;`],
];

test('R4 (F1a, F1b): a comment, a here-doc or a text the parser cannot read keeps master\'s route (control route, hold label, loop guard)', () => {
  const { classifyTool, controlRouteCall } = require('../dist/hook-pre-action.js');
  for (const [id, command] of fallbackRows()) {
    assert.equal(controlRoute(command), true, `${id}: route`);
    assert.equal(controlRouteCall(bash(command)), true, `${id}: the loop-guard denial`);
    const c = classifyTool({ ...bash(command), cwd: '/srv/w' }, {});
    assert.ok(c.surfaces.includes('marrow-control'), `${id}: held on marrow-control`);
  }
});

test('R4: the clean L1 shape (parsed, no comment, no here-doc, installer words only as printf/echo/grep/git/cat/cd/ls data) keeps no route', () => {
  for (const command of [
    `printf '%s ran ${I} control enable\\n' now >> ./records/LOG.md`,
    `echo "${I} control disable needs the owner" >> ./notes.md`,
    `git commit -m "doc: ${I} control disable needs the owner"`,
    `grep -rn "${I} control disable" ./docs`,
    'cat ./marrow-install/README.md && ls ./marrow-install',
  ]) assert.equal(controlRoute(command), false, command.slice(0, 40));
  assertRows([`printf '%s ran ${I} control enable\\n' now >> ./records/LOG.md`], 'none');
});

test('R4: outside the clean L1 shape the answer is master OR the reader (the reader\'s stricter rows stay routes)', () => {
  for (const command of [
    `eval "${I} control disable"`, `for i in 1; do ${I} control disable; done`, 'x=@getmarrow/install; npx $x control disable',
    'P=@getmarrow/install; npx "$P" control disable', 'python3 -I ~/agents/cliff-tools/host_report.py R D KEY_NAME a b post',
    `bash -c "${I} control disable" # note`, `cat <<'EOF' | bash\n${I} control disable\nEOF`,
  ]) {
    const { classifyTool } = require('../dist/hook-pre-action.js');
    const c = classifyTool({ ...bash(command), cwd: '/srv/w' }, {});
    assert.ok(c.surfaces.includes('marrow-control') || /host_report/.test(command), command.slice(0, 40));
  }
});

test('R4 fails closed: a thrown parser error in the reader is a route', () => {
  const policy = require('../dist/hook-tool-policy.js');
  const original = policy.parseShellSegments;
  policy.parseShellSegments = () => { throw new Error('fault'); };
  try { assert.equal(controlRoute(`echo "${I} control disable"`), true); } finally { policy.parseShellSegments = original; }
});

test('R6 (F3): the f8 family (20 characters, upper case and digits) is never sent, over 2000 runtime draws', () => {
  const { SHAPES } = require('./support/seatbelt-fuzz-values.cjs');
  let sent = 0;
  for (let i = 0; i < 2000; i += 1) {
    const k = SHAPES[4]();
    assertNotLiveKey(k);
    if (fiveSites(bash(`./pay.sh ${k} a`)).runtime.tool_input.command !== undefined) sent += 1;
  }
  assert.equal(sent, 0, 'F8_SENT');
});

test('R6: a letter or digit run of 20, 24 or 32 in any case is withheld; the R3 boundary rows keep their answer', () => {
  const LOW = 'abcdefghjkmnpqrstuvwxyz', UP = 'ABCDEFGHJKLMNPQRSTUVWXYZ', MIX = `${LOW}${UP}`;
  const draw = (alpha, n) => Array.from(randomBytes(n), (byte) => alpha[byte % alpha.length]).join('');
  for (const n of [20, 24, 32]) {
    for (const alpha of [LOW, UP, MIX, `${LOW}0123456789`]) {
      const command = `./tool.sh --name ${draw(alpha, n)} a`;
      assert.equal(keptAction(command).sent, undefined, `${n} withheld`);
    }
  }
  const short = `./tool.sh --name ${draw(LOW, 8)}-${draw(LOW, 8)} a`;
  assert.equal(keptAction(short).sent, short, 'runs under 20 keep their R3 answer (sent)');
  // 41 or 63 hex: a run that is not exactly 40 or 64 is withheld.
  assert.equal(keptAction(`git show v-${hex(20)}a > ./scratch/a.txt`).sent, undefined, '41 hex withheld');
  assert.equal(keptAction(`echo v-${hex(32).toUpperCase()} >> ./notes.md`).sent, undefined, '64 upper-case hex withheld');
  for (const [name, command] of boundaryRows()) if (name !== 'sha256: + 64 hex') assert.equal(keptAction(command).sent, command, `${name} sent`);
});
