const assert = require('node:assert/strict');
const test = require('node:test');
const { writeOfficialHostConfigs } = require('./support/official-host-config.cjs');
writeOfficialHostConfigs();
const { spawnSync } = require('node:child_process');
const { randomBytes } = require('node:crypto');
const { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const { MARROW_OWN_TOOL_NAMES, normalizedMcpToolName, isOfficialMarrowGeminiCall } = require('../dist/own-tool.js');
const { isOfficialMarrowMcpEvent, isOfficialMarrowMcpTool } = require('../dist/hook-tool-policy.js');
const { NATIVE_HOOK_MATCHER, LEGACY_NATIVE_HOOK_MATCHERS, exactHookTarget, normalizeHookEventPayload, stableToolCorrelation } = require('../dist/hook-contract.js');
const { normalizedHookAction } = require('../dist/normalized-action.js');
const { classifyTool, runPreActionHookCommand } = require('../dist/hook-pre-action.js');
const { deriveAction } = require('../dist/hook.js');
const { findHolds, recordHold } = require('../dist/host-approval-state.js');

// Round 3 of the exact own-tool fix (Codex findings on 4311df21, still in c5354487):
//   F1 Gemini `mcp_<server>_<tool>` labels are ambiguous; own only via mcp_context.
//   F2 Cursor preToolUse `MCP:<tool>` has no server: OPEN_DECISION, behaviour kept (pinned below).
//   F3 adapter names joined server/tool without escaping; holds were claimed by correlation alone.
//   F4 the matcher's consuming `.*` did not cross line terminators.
// Host label facts: marrow-install evidence r2/host-label-research.md (Gemini 0.63 mcp_context,
// Cursor CLI MCP:<tool>, Claude Code In()).

const FIXTURE = JSON.parse(readFileSync(join(__dirname, 'fixtures', 'marrow-own-tool-names.json'), 'utf8'));
const OWN = FIXTURE.names;
const CLI = join(__dirname, '..', 'dist', 'cli.js');
const MOCK = join(__dirname, 'support', 'host-approval-fetch-mock.cjs');
const HA_FIXTURES = join(__dirname, 'fixtures', 'host-approvals');
const haFixture = (name) => JSON.parse(readFileSync(join(HA_FIXTURES, name), 'utf8'));
const twice = (payload) => normalizeHookEventPayload(normalizeHookEventPayload(payload));

// ------------------------------------------------------------------ F4 matcher

const PADS = { LF: '\n', CR: '\r', CRLF: '\r\n', U2028: ' ', U2029: ' ', NUL: '\0', TAB: '\t', SPACE: ' ' };

test('F4: the matcher is the shared string (marrow-install writes the same bytes): [\\s\\S]* in every consuming part', () => {
  const joined = OWN.join('|');
  assert.equal(NATIVE_HOOK_MATCHER,
    `^(?!(?:mcp__marrow__(?:${joined})|LS|ListMcpResourcesTool)$)[\\s\\S]*`);
  assert.equal(NATIVE_HOOK_MATCHER.includes('.*'), false, 'no consuming .* is left');
  assert.equal(NATIVE_HOOK_MATCHER.split('[\\s\\S]*').length, 2, 'exactly one consuming part');
  assert.equal(require('../dist/hook.js').AUTO_HOOK_MATCHER, NATIVE_HOOK_MATCHER);
});

test('F4: padded labels (LF, CR, CRLF, U+2028, U+2029, NUL, tab, space) reach the hook under full match and search', () => {
  const full = new RegExp(`^(?:${NATIVE_HOOK_MATCHER})$`);
  const search = new RegExp(NATIVE_HOOK_MATCHER);
  const r2Full = new RegExp(`^(?:${LEGACY_NATIVE_HOOK_MATCHERS[1]})$`);
  const r2Search = new RegExp(LEGACY_NATIVE_HOOK_MATCHERS[1]);
  let checked = 0;
  const bases = [...OWN.flatMap((name) => [`mcp__marrow__${name}`, `functions.mcp__marrow__${name}`]),
    'mcp__evil__delete_all', 'functions.mcp__evil__x', 'mcp__MARROW__marrow_commit', 'mcp__marrow__marrow_delete_all', 'mcp__marrow_marrow__commit'];
  for (const base of bases) {
    // Only the exact Claude Code label of an own tool is skipped.
    const own = base.startsWith('mcp__marrow__') && MARROW_OWN_TOOL_NAMES.has(base.slice('mcp__marrow__'.length));
    assert.equal(full.test(base), !own, base);
    assert.equal(search.test(base), !own, base);
    for (const [label, pad] of Object.entries(PADS)) {
      for (const name of [`${base}${pad}`, `${base}${pad}x`, `${pad}${base}`, `x${pad}${base}`]) {
        assert.equal(full.test(name), true, `full ${label} ${JSON.stringify(name)}`);
        assert.equal(search.test(name), true, `search ${label} ${JSON.stringify(name)}`);
        checked += 1;
      }
    }
  }
  assert.ok(checked > 3700, `checked ${checked}`);
  // Never looser than the r2 string: whatever it sent to the hook still goes there.
  for (const base of bases) {
    for (const pad of ['', ...Object.values(PADS)]) {
      for (const name of [`${base}${pad}`, `${pad}${base}`]) {
        if (r2Full.test(name)) assert.equal(full.test(name), true, JSON.stringify(name));
        if (r2Search.test(name)) assert.equal(search.test(name), true, JSON.stringify(name));
      }
    }
  }
});

// ------------------------------------------------------------- F3 encoding

const ADAPTERS = {
  cursor: (server, tool, input = { x: 1 }) => ({ hook_event_name: 'beforeMCPExecution', conversation_id: 'conv-r3', generation_id: 'gen-r3', mcp_server_name: server, tool_name: tool, tool_input: JSON.stringify(input) }),
  windsurf: (server, tool) => ({ agent_action_name: 'pre_mcp_tool_use', trajectory_id: 'traj-r3', tool_info: { mcp_server_name: server, mcp_tool_name: tool } }),
  grok: (server, tool, input = { x: 1 }) => ({ hookEventName: 'PreToolUse', sessionId: 'grok-r3', toolName: 'use_tool', toolInput: { serverName: server, toolName: tool, arguments: input } }),
};

function keysOf(payload) {
  const event = twice(payload);
  const action = normalizedHookAction(event, { deadlineAt: Number.POSITIVE_INFINITY });
  return {
    name: event.tool_name,
    action: JSON.stringify(action),
    correlation: stableToolCorrelation({ ...event, session_id: 'session-r3' }),
    target: exactHookTarget(event),
    own: isOfficialMarrowMcpEvent(event),
  };
}

const DELIMITERS = [':', '__', '_', '/', '.', ' ', '-', '::', ':_', '"', '\\', '?', '#'];

test('F3: server and tool are encoded without ambiguity: delimiter pairs never share a name, action, correlation or target', () => {
  let pairs = 0;
  for (const d of DELIMITERS) {
    for (const [left, right, tool] of [['marrow', 'prod', 'execute'], ['github', 'org', 'merge'], ['Marrow', 'PROD', 'Execute'], ['marrow', 'marrow', 'commit']]) {
      const a = [`${left}${d}${right}`, tool];
      const b = [left, `${right}${d}${tool}`];
      for (const [host, build] of Object.entries(ADAPTERS)) {
        const ka = keysOf(build(...a));
        const kb = keysOf(build(...b));
        const label = `${host} ${JSON.stringify(a)} vs ${JSON.stringify(b)}`;
        // Grok keeps `use_tool` for a name it cannot bound (e.g. `/`): the nested server and tool stay in its input.
        if (!(host === 'grok' && ka.name === 'use_tool' && kb.name === 'use_tool')) assert.notEqual(ka.name, kb.name, label);
        assert.notEqual(ka.action, kb.action, label);
        assert.notEqual(ka.correlation, kb.correlation, label);
        assert.notEqual(ka.target, kb.target, label);
        // Own only for exactly server `marrow` and a registered tool (`marrow` + `marrow_commit` here).
        assert.equal(ka.own, a[0] === 'marrow' && MARROW_OWN_TOOL_NAMES.has(a[1]), label);
        assert.equal(kb.own, b[0] === 'marrow' && MARROW_OWN_TOOL_NAMES.has(b[1]), label);
        pairs += 1;
      }
    }
  }
  assert.ok(pairs >= 100, `pairs ${pairs}`);
  // The reported pair, exactly.
  const prod = keysOf(ADAPTERS.cursor('marrow:prod', 'execute'));
  const split = keysOf(ADAPTERS.cursor('marrow', 'prod:execute'));
  assert.equal(prod.name, 'MCP:"marrow:prod":"execute"');
  assert.equal(split.name, 'MCP:marrow:prod:execute');
  assert.notEqual(prod.correlation, split.correlation);
});

test('F3: the adapter encoding is injective over a generated corpus of raw server/tool pairs (case, padding, delimiters)', () => {
  const parts = ['', 'a', 'B', 'marrow', 'MARROW', 'prod', 'marrow_commit', ':', '__', '_', '/', '.', ' ', '"', '?', '#', '\\', '\n', 'null', '?string', '"x"'];
  const values = new Set();
  for (const x of parts) for (const y of parts) for (const z of ['', 'q', ':', '"']) values.add(`${x}${y}${z}`);
  const raws = [...values];
  for (const [host, build] of Object.entries({ cursor: ADAPTERS.cursor, windsurf: ADAPTERS.windsurf })) {
    const seen = new Map();
    for (const server of raws) {
      for (const tool of raws.slice(0, 160)) {
        const event = twice(build(server, tool));
        const prior = seen.get(event.tool_name);
        assert.ok(prior === undefined || (prior[0] === server && prior[1] === tool), `${host}: ${JSON.stringify([server, tool])} and ${JSON.stringify(prior)} share ${JSON.stringify(event.tool_name)}`);
        seen.set(event.tool_name, [server, tool]);
      }
    }
    assert.ok(seen.size > 20_000, `${host} ${seen.size}`);
  }
  // A value that is not a string never takes a string's name.
  for (const odd of [undefined, null, 5, {}, ['marrow'], true]) {
    const name = twice(ADAPTERS.cursor(odd, 'execute')).tool_name;
    assert.match(name, /^MCP:\?[a-z]+:"execute"$/);
    for (const server of raws) assert.notEqual(twice(ADAPTERS.cursor(server, 'execute')).tool_name, name);
  }
});

test('F3: exact names keep their released form; the escaped forms are not own and are held', async () => {
  assert.equal(twice(ADAPTERS.cursor('github', 'create_issue')).tool_name, 'MCP:github:create_issue');
  assert.equal(twice(ADAPTERS.windsurf('release-tools', 'deploy_service')).tool_name, 'MCP:release-tools:deploy_service');
  assert.equal(twice(ADAPTERS.grok('github', 'merge.pr')).tool_name, 'MCP:github:merge.pr');
  // A colon-bearing server keeps a (gated) name on every adapter; a padded own-looking one stays unclassified (held).
  assert.equal(twice(ADAPTERS.grok('marrow:prod', 'execute')).tool_name, 'MCP:"marrow:prod":"execute"');
  assert.equal(twice(ADAPTERS.windsurf('marrow:prod', 'execute')).tool_name, 'MCP:"marrow:prod":"execute"');
  assert.equal(twice(ADAPTERS.grok('marrow', 'marrow_commit\t')).tool_name, undefined);
  assert.equal(normalizedMcpToolName(false, 'x', 'unknown', undefined, 'x'), 'MCP:?undefined:"x"');
  assert.equal(normalizedMcpToolName(false, 'marrow_commit', 'marrow', 'marrow', 'marrow_commit'), 'MCP:"marrow":"marrow_commit"', 'never an own-looking plain name');
  for (const name of ['MCP:"marrow:prod":"execute"', 'MCP:"marrow ":"marrow_commit"', 'MCP:?undefined:"marrow_commit"']) {
    assert.equal(isOfficialMarrowMcpTool(name), false, name);
    assert.equal(classifyTool({ tool_name: name, tool_input: { command: 'wrangler deploy --env production' } }).risk, 'high', name);
  }
  // Pre and post events of one call give the same target; the same label from another form does not.
  const before = twice(ADAPTERS.cursor('github', 'merge', { pr: 7 }));
  const after = twice({ ...ADAPTERS.cursor('github', 'merge', { pr: 7 }), hook_event_name: 'afterMCPExecution' });
  assert.equal(exactHookTarget(before), exactHookTarget(after));
  const nativePre = twice({ hook_event_name: 'preToolUse', conversation_id: 'conv-r3', tool_name: 'MCP:github:merge', tool_input: { pr: 7 } });
  const nativePost = twice({ hook_event_name: 'postToolUse', conversation_id: 'conv-r3', tool_name: 'MCP:github:merge', tool_input: { pr: 7 } });
  assert.equal(nativePre.tool_name, before.tool_name, 'Cursor labels a tool named `github:merge` the same (host label)');
  assert.equal(stableToolCorrelation({ ...nativePre, session_id: 's' }), stableToolCorrelation({ ...before, session_id: 's' }));
  assert.notEqual(exactHookTarget(nativePre), exactHookTarget(before), 'a different target all the same');
  assert.equal(exactHookTarget(nativePre), exactHookTarget(nativePost));
});

test('F3: a hold without a target (older version) is never claimed; a hold matches only its exact target', () => {
  const home = mkdtempSync(join(tmpdir(), 'marrow-r3-holds-'));
  try {
    const scope = { apiKey: `dummy-${randomBytes(8).toString('hex')}`, baseUrl: 'https://api.example.test', agentId: null };
    const base = {
      host: 'cursor', harness: 'cursor', session_id: 's', host_session_id: 's', agent_id: null, correlation: 'a'.repeat(32),
      tool_use_id: null, generation_id: null, tool_name: 'MCP:x:y', hook_event: 'beforeMCPExecution', mode: 'wait',
      gate_receipt_id: 'gate-legacy', decision_id: null, asked_at: new Date().toISOString(), pre_action_event_id: null,
      proof_required: false, proof_fields: [], expires_at: null, withCode: false,
      action: { action: 'a', target: 't', type: 'process', surfaces: [] },
    };
    recordHold(scope, base, home);
    const target = 'b'.repeat(64);
    assert.equal(findHolds(scope, { correlation: 'a'.repeat(32) }, home).length, 1);
    assert.equal(findHolds(scope, { correlation: 'a'.repeat(32), target }, home).length, 0, 'legacy hold: no target, never claimed');
    recordHold(scope, { ...base, gate_receipt_id: 'gate-t', target }, home);
    recordHold(scope, { ...base, gate_receipt_id: 'gate-u', target: 'c'.repeat(64) }, home);
    // Same correlation, different targets: neither replaced the other (the legacy one was replaced).
    const holds = findHolds(scope, { correlation: 'a'.repeat(32) }, home).map((h) => h.gate_receipt_id).sort();
    assert.deepEqual(holds, ['gate-t', 'gate-u']);
    assert.deepEqual(findHolds(scope, { correlation: 'a'.repeat(32), target }, home).map((h) => h.gate_receipt_id), ['gate-t']);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

// ------------------------------------------ hook processes with a scripted Marrow (as host-approvals)

function hostRuntime(receipt) {
  return {
    ok: true,
    action: 'classified MCP action: process on workspace',
    decision_id: 'decision-review',
    runtime_authorization: { id: receipt, kind: 'durable_gate_receipt', durable: true, decision_state: 'created', decision_creation_required: false, decision_id: 'decision-review' },
    gate_receipt: { id: receipt, decision: 'review_required', required: true, owner_approval_required: true, expires_at: '2030-01-01T00:30:00.000Z' },
    proof_pack: { required: false, fields: [], complete: true },
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
      },
    },
    risk_gate: { allow: true, decision: 'review_required', enforced: true, gate_required: true, gate_receipt_id: receipt, risk_level: 'high', reasons: [{ message: 'Needs approval.' }] },
    gate_receipt_id: receipt,
    exact_next_action: 'Obtain explicit owner approval before this action runs.',
  };
}

function harness() {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-r3-hooks-'));
  const home = join(dir, 'home');
  const mockDir = join(dir, 'mock');
  mkdirSync(home, { mode: 0o700 });
  writeOfficialHostConfigs(home);
  mkdirSync(mockDir);
  const apiKey = `mrw_test_${randomBytes(16).toString('hex')}`;
  let config = {};
  const setConfig = (next) => { config = { ...config, ...next }; writeFileSync(join(mockDir, 'config.json'), JSON.stringify(config)); };
  const requests = () => {
    const path = join(mockDir, 'requests.jsonl');
    return existsSync(path) ? readFileSync(path, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line)) : [];
  };
  const run = (entrypoint, payload, env = {}) => {
    const result = spawnSync(process.execPath, [CLI, entrypoint], {
      input: JSON.stringify(payload),
      env: {
        PATH: process.env.PATH, HOME: home, MARROW_API_KEY: apiKey, MARROW_BASE_URL: 'https://api.example.test',
        MARROW_AGENT_ID: 'agent-r3', MARROW_HOOK_BACKGROUND_NUDGE: 'false', MARROW_PASSIVE_TOKEN_USAGE: 'false',
        MARROW_TEST_MOCK_DIR: mockDir, NODE_OPTIONS: `--require=${MOCK}`, ...env,
      },
      encoding: 'utf8',
      timeout: 30_000,
    });
    assert.equal(result.error, undefined);
    const output = result.stdout.trim();
    assert.equal(output.includes(apiKey) || result.stderr.includes(apiKey), false, 'the key never appears in hook output');
    let json = null;
    try { json = output ? JSON.parse(output) : null; } catch { json = null; }
    return { status: result.status, stdout: output, json };
  };
  const state = () => {
    const path = join(home, '.marrow', 'host-approvals', 'state.json');
    return existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : null;
  };
  return { home, run, setConfig, requests, state, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

const runtimes = (h) => h.requests().filter((r) => r.path === '/v1/agent/runtime' && /^classified \S+ action: /.test(r.body?.action || ''));
const hostReports = (h) => h.requests().filter((r) => r.path.endsWith('/host-approval'));
const openHolds = (h) => Object.values(h.state()?.holds || {}).filter((hold) => hold.state === 'open').map((hold) => hold.gate_receipt_id).sort();

test('F3: an approved hold is never claimed by a look-alike target (Cursor `marrow:prod`+`execute` vs `marrow`+`prod:execute`)', () => {
  const h = harness();
  try {
    const mcp = haFixture('cursor-before-mcp.json');
    const prod = { ...mcp, mcp_server_name: 'marrow:prod', tool_name: 'execute', tool_input: '{"service":"worker"}' };
    const split = { ...mcp, mcp_server_name: 'marrow', tool_name: 'prod:execute', tool_input: '{"service":"worker"}' };
    h.setConfig({ runtime: hostRuntime('gate-prod'), status: { 'gate-prod': 'pending' } });
    h.run('cursor-session-hook', haFixture('cursor-session-start-background.json'));
    assert.equal(h.run('cursor-pre-action-hook', prod).json.permission, 'deny');
    assert.equal(runtimes(h).length, 1);
    h.setConfig({ runtime: hostRuntime('gate-split'), status: { 'gate-prod': 'approved', 'gate-split': 'pending' } });
    // The look-alike gets its own gate; the first approval stays unclaimed.
    assert.equal(h.run('cursor-pre-action-hook', split).json.permission, 'deny');
    assert.equal(runtimes(h).length, 2, 'the look-alike asked Marrow for its own gate');
    assert.deepEqual(openHolds(h), ['gate-prod', 'gate-split']);
    // The approved target itself runs once on its approval.
    assert.equal(h.run('cursor-pre-action-hook', prod).json.permission, 'allow');
    assert.equal(runtimes(h).length, 2);
    assert.deepEqual(openHolds(h), ['gate-split']);
  } finally { h.cleanup(); }
});

test('F3: same correlation, different target (Cursor tool `github:merge` at preToolUse vs server `github` tool `merge`): no claim, no replaced hold', () => {
  const h = harness();
  try {
    const mcp = haFixture('cursor-before-mcp.json');
    const server = { ...mcp, mcp_server_name: 'github', tool_name: 'merge', tool_input: '{"number":7}' };
    const native = { ...haFixture('cursor-pre-tool-use.json'), tool_name: 'MCP:github:merge', tool_input: { number: 7 } };
    assert.equal(stableToolCorrelation({ ...twice(server), session_id: 's' }), stableToolCorrelation({ ...twice(native), session_id: 's' }), 'the correlations collide');
    h.setConfig({ runtime: hostRuntime('gate-server'), status: { 'gate-server': 'pending' } });
    h.run('cursor-session-hook', haFixture('cursor-session-start-background.json'));
    assert.equal(h.run('cursor-pre-action-hook', server).json.permission, 'deny');
    h.setConfig({ runtime: hostRuntime('gate-native'), status: { 'gate-server': 'approved', 'gate-native': 'pending' } });
    assert.equal(h.run('cursor-pre-action-hook', native).json.permission, 'deny', 'not allowed on the other target\'s approval');
    assert.equal(runtimes(h).length, 2);
    assert.deepEqual(openHolds(h), ['gate-native', 'gate-server'], 'the new hold did not replace the approved one');
    assert.equal(h.run('cursor-pre-action-hook', server).json.permission, 'allow');
  } finally { h.cleanup(); }
});

test('F3: an after-event reports a host approval only for its own target', () => {
  const h = harness();
  try {
    const mcp = haFixture('cursor-before-mcp.json');
    const server = { ...mcp, mcp_server_name: 'github', tool_name: 'merge', tool_input: '{"number":7}' };
    h.setConfig({ runtime: hostRuntime('gate-ask') });
    h.run('cursor-session-hook', haFixture('cursor-session-start.json'));
    assert.equal(h.run('cursor-pre-action-hook', server).json.permission, 'ask');
    // A call to a tool named `github:merge` (another server) finishes first: same label and input.
    h.run('cursor-hook', { ...haFixture('cursor-pre-tool-use.json'), hook_event_name: 'postToolUse', tool_name: 'MCP:github:merge', tool_input: { number: 7 }, tool_output: '{}' });
    assert.deepEqual(hostReports(h), [], 'no approval reported for a different target');
    h.run('cursor-hook', { ...server, hook_event_name: 'afterMCPExecution', result_json: '{}' });
    assert.equal(hostReports(h).length, 1);
    assert.equal(hostReports(h)[0].body.verdict, 'approved');
  } finally { h.cleanup(); }
});

// ------------------------------------------------------------ F1 Gemini

const gemini = (label, context, extra = {}) => ({
  hook_event_name: 'BeforeTool', session_id: 'gemini-r3', tool_name: label, tool_input: { command: 'wrangler deploy --env production' },
  ...(context === undefined ? {} : { mcp_context: context }), ...extra,
});
const ctx = (server, tool) => ({ server_name: server, tool_name: tool, command: 'node', args: ['server.js'] });

test('F1: Gemini (marrow_marrow, commit) vs (marrow, marrow_commit): same label, only the exact server is own', () => {
  const forged = twice(gemini('mcp_marrow_marrow_commit', ctx('marrow_marrow', 'commit')));
  const own = twice(gemini('mcp_marrow_marrow_commit', ctx('marrow', 'marrow_commit')));
  assert.equal(isOfficialMarrowMcpEvent(forged), false);
  assert.equal(forged.tool_name, 'mcp_marrow_marrow_commit');
  assert.equal(classifyTool(forged).risk, 'high');
  assert.equal(classifyTool(forged).protected, true);
  assert.notEqual(deriveAction(forged), null, 'the recorder records it');
  assert.equal(isOfficialMarrowMcpEvent(own), true);
  assert.equal(own.tool_name, 'mcp__marrow__marrow_commit');
  assert.equal(deriveAction(own), null);
  assert.deepEqual(own.mcp_context, { server_name: 'marrow', tool_name: 'marrow_commit' }, 'only server and tool are kept');
  // Two foreign servers with one label: the host label (and so the correlation) is shared, a
  // pre-existing Gemini label collision (Follow-ups); the approval binding uses the exact target.
  const ab = twice(gemini('mcp_a_b_c', ctx('a_b', 'c')));
  const a = twice(gemini('mcp_a_b_c', ctx('a', 'b_c')));
  assert.equal(stableToolCorrelation({ ...ab, session_id: 's' }), stableToolCorrelation({ ...a, session_id: 's' }));
  assert.notEqual(exactHookTarget(ab), exactHookTarget(a));
});

test('F1: a Gemini call without exact mcp_context proof is never own (label only, mismatch, case, padding, prototype, other forms)', () => {
  const cases = [
    ['label only', gemini('mcp_marrow_marrow_commit', undefined)],
    ['context not an object', gemini('mcp_marrow_marrow_commit', 'marrow')],
    ['context without tool', gemini('mcp_marrow_marrow_commit', { server_name: 'marrow' })],
    ['label for another tool', gemini('mcp_marrow_marrow_commit', ctx('marrow', 'marrow_think'))],
    ['label from another server', gemini('mcp_evil_marrow_commit', ctx('marrow', 'marrow_commit'))],
    ['server case', gemini('mcp_Marrow_marrow_commit', ctx('Marrow', 'marrow_commit'))],
    ['server upper', gemini('mcp_MARROW_marrow_commit', ctx('MARROW', 'marrow_commit'))],
    ['tool case', gemini('mcp_marrow_MARROW_COMMIT', ctx('marrow', 'MARROW_COMMIT'))],
    ['unregistered tool', gemini('mcp_marrow_marrow_delete_all', ctx('marrow', 'marrow_delete_all'))],
    ['padded server', gemini('mcp_marrow_marrow_commit', ctx('marrow ', 'marrow_commit'))],
    ['padded tool', gemini('mcp_marrow_marrow_commit', ctx('marrow', 'marrow_commit\n'))],
    ['padded label', gemini('mcp_marrow_marrow_commit ', ctx('marrow', 'marrow_commit'))],
    ['NUL label', gemini('mcp_marrow_marrow_commit\0', ctx('marrow', 'marrow_commit'))],
    ['prototype context', JSON.parse('{"hook_event_name":"BeforeTool","tool_name":"mcp_marrow_marrow_commit","tool_input":{},"mcp_context":{"__proto__":{"server_name":"marrow","tool_name":"marrow_commit"}}}')],
    ['inherited fields', gemini('mcp_marrow_marrow_commit', Object.create(ctx('marrow', 'marrow_commit')))],
    ['non-string server', gemini('mcp_marrow_marrow_commit', { server_name: ['marrow'], tool_name: 'marrow_commit' })],
    ['Claude-form label from server `mcp`', gemini('mcp__marrow__marrow_commit', ctx('mcp', '_marrow__marrow_commit'))],
    ['Claude-form label, no context', gemini('mcp__marrow__marrow_commit', undefined)],
    ['Cursor-form label', gemini('MCP:marrow_commit', undefined)],
    ['Cursor server form label', gemini('MCP:marrow:marrow_commit', ctx('evil', 'marrow:marrow_commit'))],
    ['functions. label', gemini('functions.mcp__marrow__marrow_commit', undefined)],
  ];
  for (const [label, payload] of cases) {
    for (const event of [normalizeHookEventPayload(payload), twice(payload)]) {
      assert.equal(isOfficialMarrowMcpEvent(event), false, label);
      assert.equal(isOfficialMarrowGeminiCall(payload.tool_name, payload.mcp_context), false, label);
      // Held: protected, or left unclassified (no tool name) and denied as unclassifiable.
      if (event.tool_name) {
        assert.equal(classifyTool(event).protected, true, label);
        assert.equal(classifyTool(event).risk, 'high', label);
      }
    }
  }
  // A label in another host's own form, or a padded own label, is left unclassified (held, as r1 did for padding).
  for (const label of ['mcp__marrow__marrow_commit', 'MCP:marrow_commit', 'MCP:marrow:marrow_commit', 'functions.mcp__marrow__marrow_commit', 'mcp_marrow_marrow_commit ']) {
    assert.equal(twice(gemini(label, ctx('mcp', '_marrow__marrow_commit'))).tool_name, undefined, label);
  }
  // An exact Gemini own-looking label without proof keeps its label and takes the normal gate.
  assert.equal(twice(gemini('mcp_marrow_marrow_commit', ctx('marrow_marrow', 'commit'))).tool_name, 'mcp_marrow_marrow_commit');
});

// ---------------------------------------------- no lockout, all 58 names

const HOSTS = [
  { host: 'claude', entry: 'claude-pre-action-hook', allow: '{}', event: (t) => ({ hook_event_name: 'PreToolUse', session_id: 'r3', tool_name: `mcp__marrow__${t}`, tool_input: {} }) },
  { host: 'codex', entry: 'codex-pre-action-hook', allow: '{}', event: (t) => ({ hook_event_name: 'PreToolUse', session_id: 'r3', tool_name: `functions.mcp__marrow__${t}`, tool_input: {} }), checked: true },
  { host: 'codex-bare', entry: 'codex-pre-action-hook', allow: '{}', event: (t) => ({ hook_event_name: 'PreToolUse', session_id: 'r3', tool_name: `mcp__marrow__${t}`, tool_input: {} }) },
  { host: 'gemini', entry: 'gemini-pre-action-hook', allow: '{"decision":"allow"}', event: (t) => gemini(`mcp_marrow_${t}`, ctx('marrow', t)) },
  { host: 'cursor-pre', entry: 'cursor-pre-action-hook', allow: '{"permission":"allow"}', event: (t) => ({ hook_event_name: 'preToolUse', conversation_id: 'conv-r3', tool_name: `MCP:${t}`, tool_input: {} }) },
  { host: 'cursor-pre-server', entry: 'cursor-pre-action-hook', allow: '{"permission":"allow"}', event: (t) => ({ hook_event_name: 'preToolUse', conversation_id: 'conv-r3', tool_name: `MCP:marrow:${t}`, tool_input: {} }), checked: true },
  { host: 'cursor-mcp', entry: 'cursor-pre-action-hook', allow: '{"permission":"allow"}', event: (t) => ADAPTERS.cursor('marrow', t, {}) },
  { host: 'cline', entry: 'cline-pre-action-hook', allow: '{"cancel":false}', event: (t) => ({ hookName: 'PreToolUse', taskId: 'r3', preToolUse: { toolName: 'use_mcp_tool', parameters: { server_name: 'marrow', tool_name: t } } }) },
  { host: 'grok', entry: 'grok-pre-action-hook', allow: '{"decision":"allow"}', event: (t) => ADAPTERS.grok('marrow', t, {}) },
  { host: 'windsurf', entry: 'windsurf-pre-action-hook', allow: '', event: (t) => ADAPTERS.windsurf('marrow', t) },
];
const ENV_KEYS = ['MARROW_API_KEY', 'MARROW_KEY', 'MARROW_BASE_URL', 'MARROW_AGENT_ID', 'MARROW_FLEET_AGENT_ID', 'MARROW_SESSION_ID', 'MARROW_PASSIVE_TOKEN_USAGE'];

/** The real pre-action hook in-process; with a key every Marrow call returns an enforced review_required gate. */
async function runPre(entrypoint, payload, withKey) {
  const calls = [];
  const saved = { write: process.stdout.write, err: process.stderr.write, exitCode: process.exitCode, arg: process.argv[2], fetch: globalThis.fetch };
  const env = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));
  let stdout = '';
  process.exitCode = undefined;
  process.argv[2] = entrypoint;
  for (const key of ENV_KEYS) delete process.env[key];
  if (withKey) Object.assign(process.env, { MARROW_API_KEY: `dummy-${randomBytes(12).toString('hex')}`, MARROW_BASE_URL: 'https://api.example.test', MARROW_AGENT_ID: 'agent-r3', MARROW_PASSIVE_TOKEN_USAGE: 'false' });
  globalThis.fetch = async (url) => {
    const path = new URL(String(url)).pathname;
    calls.push(path);
    if (path === '/v1/agent/runtime') return Response.json({ data: hostRuntime('gate-enforced') });
    if (/\/owner-approval$/.test(path)) return Response.json({ data: { gate_receipt_id: 'gate-enforced', state: 'pending', terminal: false, retryable: true, poll_after_ms: 5000, exact_next_action: 'wait' } });
    return Response.json({ data: { accepted: true } });
  };
  process.stdout.write = (chunk) => { stdout += String(chunk); return true; };
  process.stderr.write = () => true;
  try {
    await runPreActionHookCommand(payload);
    return { stdout, exitCode: process.exitCode ?? 0, calls };
  } finally {
    process.stdout.write = saved.write;
    process.stderr.write = saved.err;
    process.exitCode = saved.exitCode;
    process.argv[2] = saved.arg;
    globalThis.fetch = saved.fetch;
    for (const [key, value] of Object.entries(env)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

test('NO LOCKOUT: all 58 own names in every host form allow on an enforcing plan, with and without a key, and never call Marrow', async () => {
  assert.equal(OWN.length, 58);
  // The plan is enforcing: the same path holds a foreign tool, with and without a key.
  for (const form of HOSTS) {
    for (const withKey of [false, true]) {
      const foreign = await runPre(form.entry, form.host.startsWith('gemini') ? gemini('mcp_marrow_marrow_commit', ctx('marrow_marrow', 'commit'))
        : form.event('marrow_delete_all'), withKey);
      assert.notEqual(foreign.stdout + foreign.exitCode, form.allow + 0, `${form.host} key=${withKey}: a foreign tool is held`);
      if (withKey && form.host !== 'cursor-pre' && form.host !== 'cursor-pre-server') assert.ok(foreign.calls.includes('/v1/agent/runtime'), `${form.host}: governed`);
    }
  }
  let checked = 0;
  for (const tool of OWN) {
    for (const form of HOSTS) {
      const payload = form.event(tool);
      assert.equal(isOfficialMarrowMcpEvent(twice(payload)), true, `${form.host} ${tool} (stdin path normalizes twice)`);
      for (const withKey of [false, true]) {
        const out = await runPre(form.entry, payload, withKey);
        if (form.checked) {
          // 3.9.103: forms Codex/Cursor never emit for a proven `marrow` server are checked (own-server-identity.ts).
          assert.notEqual(out.stdout + out.exitCode, form.allow + 0, `${form.host} ${tool} key=${withKey} is checked`);
          checked += 1;
          continue;
        }
        assert.equal(out.stdout, form.allow, `${form.host} ${tool} key=${withKey}`);
        assert.equal(out.exitCode, 0, `${form.host} ${tool} key=${withKey}`);
        assert.deepEqual(out.calls, [], `${form.host} ${tool} key=${withKey}: no gate, no prompt`);
        checked += 1;
      }
    }
  }
  assert.equal(checked, 58 * HOSTS.length * 2);
});

test('NO LOCKOUT: Cursor cloud and background agents and Gemini hook processes allow all 58 own tools with no gate', () => {
  const h = harness();
  try {
    h.setConfig({ runtime: hostRuntime('gate-any'), status: { 'gate-any': 'pending' } });
    for (const tool of OWN) {
      // Cloud agent: no sessionStart, so preToolUse is the only gate.
      assert.deepEqual(h.run('cursor-pre-action-hook', { ...haFixture('cursor-pre-tool-use.json'), tool_name: `MCP:${tool}`, tool_input: {} }).json, { permission: 'allow' }, `cloud ${tool}`);
      assert.deepEqual(h.run('gemini-pre-action-hook', gemini(`mcp_marrow_${tool}`, ctx('marrow', tool))).json, { decision: 'allow' }, `gemini ${tool}`);
    }
    h.run('cursor-session-hook', haFixture('cursor-session-start-background.json'));
    for (const tool of OWN) {
      assert.deepEqual(h.run('cursor-pre-action-hook', { ...haFixture('cursor-pre-tool-use.json'), tool_name: `MCP:${tool}`, tool_input: {} }).json, { permission: 'allow' }, `background pre ${tool}`);
      assert.deepEqual(h.run('cursor-pre-action-hook', { ...haFixture('cursor-before-mcp.json'), mcp_server_name: 'marrow', tool_name: tool, tool_input: '{}' }).json, { permission: 'allow' }, `background mcp ${tool}`);
    }
    assert.equal(runtimes(h).length, 0, 'no own call ever reached the gate');
    // The same processes hold a foreign tool on this plan.
    assert.equal(h.run('cursor-pre-action-hook', { ...haFixture('cursor-before-mcp.json'), mcp_server_name: 'evil', tool_name: 'marrow_commit', tool_input: '{}' }).json.permission, 'deny');
    assert.equal(h.run('gemini-pre-action-hook', gemini('mcp_marrow_marrow_commit', ctx('marrow_marrow', 'commit'))).json.decision, 'deny');
  } finally { h.cleanup(); }
});

// ------------------------------------------------- F2 Cursor (OPEN_DECISION)

test('F2 DECIDED (3.9.103): Cursor preToolUse `MCP:<own>` is own only when the official `marrow` server is the only configured MCP server; anything else is checked', async () => {
  const project = mkdtempSync(join(tmpdir(), 'marrow-r3-cursor-'));
  const previousHome = process.env.HOME;
  const official = { command: 'npx', args: ['-y', '@getmarrow/mcp'] };
  try {
    const cases = [
      [{ marrow: official }, true],
      [{ marrow: official, evil: { command: 'evil' }, other: { url: 'https://example.test' } }, false],
      [{ marrow: { command: 'npx' } }, false],
      [{ marrow: { command: 'npx', args: ['-y', '@evil/mcp'] } }, false],
      [{ marrow: official, marrow_: official }, false],
    ];
    for (const [servers, own] of cases) {
      mkdirSync(join(project, '.cursor'), { recursive: true });
      writeFileSync(join(project, '.cursor', 'mcp.json'), JSON.stringify({ mcpServers: servers }));
      process.env.HOME = project;
      // One hook process reads the config once; this test rewrites it in one process.
      require('../dist/own-server-identity.js').resetOwnServerIdentityCache();
      for (const withKey of [false, true]) {
        const out = (await runPre('cursor-pre-action-hook', { hook_event_name: 'preToolUse', conversation_id: 'c', tool_name: 'MCP:marrow_commit', tool_input: {} }, withKey)).stdout;
        if (own) assert.equal(out, '{"permission":"allow"}', JSON.stringify(servers));
        else assert.notEqual(out, '{"permission":"allow"}', JSON.stringify(servers));
        for (const name of ['MCP:evil:marrow_commit', 'MCP:marrow_delete_all', 'MCP:Marrow_commit', 'MCP:MARROW:marrow_commit', 'MCP:marrow_commit ', 'MCP:"marrow":"marrow_commit"', 'MCP:marrow:marrow_commit']) {
          const held = await runPre('cursor-pre-action-hook', { hook_event_name: 'preToolUse', conversation_id: 'c', tool_name: name, tool_input: {} }, withKey);
          assert.notEqual(held.stdout, '{"permission":"allow"}', `${JSON.stringify(name)} key=${withKey} (${Object.keys(servers).length} servers)`);
        }
      }
    }
    // Where Cursor does send the server (beforeMCPExecution), only server `marrow` is own.
    for (const server of ['evil', 'marrow:prod', 'Marrow', 'marrow ']) {
      assert.equal(isOfficialMarrowMcpEvent(twice(ADAPTERS.cursor(server, 'marrow_commit'))), false, server);
    }
  } finally {
    process.env.HOME = previousHome;
    rmSync(project, { recursive: true, force: true });
  }
});

test('Production words under foreign names classify high on every host form (never looser)', () => {
  const inputs = [{ command: 'wrangler deploy --env production' }, { command: 'git push origin master' }, { command: 'ls && npm publish' },
    { command: 'echo ok; bash -c "kubectl apply -f prod.yaml"' }, { query: 'read only status' }, {}];
  const names = [
    'mcp_marrow_marrow_commit', 'MCP:"marrow:prod":"execute"', 'MCP:marrow:prod:execute', 'MCP:"marrow":"marrow_commit"',
    'MCP:?undefined:"deploy"', 'mcp__evil__deploy', 'MCP:evil:marrow_commit', 'mcp_evil_deploy',
  ];
  for (const name of names) for (const tool_input of inputs) {
    const result = classifyTool({ tool_name: name, tool_input });
    assert.equal(result.risk, 'high', `${name} ${JSON.stringify(tool_input)}`);
    assert.equal(result.protected, true);
  }
  const deploy = classifyTool({ tool_name: 'mcp_marrow_marrow_commit', tool_input: { command: 'wrangler deploy --env production' } });
  assert.ok(deploy.surfaces.includes('production'));
});
