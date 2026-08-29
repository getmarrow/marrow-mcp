const assert = require('node:assert/strict');
const { mkdtempSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const PRIMARY_TOOLS = [
  'marrow_agent_runtime',
  'marrow_arbitrate',
  'marrow_coordinate',
  'marrow_replay_compare',
  'marrow_decision_brief',
  'marrow_think',
  'marrow_commit',
  'marrow_workflow_gate',
  'marrow_completion_contracts',
  'marrow_evaluate_completion_contract',
  'marrow_agent_status',
  'marrow_value_report',
  'marrow_buyer_proof',
  'marrow_governance_timeline',
  'marrow_decision_trace',
  'marrow_fleet_lessons',
  'marrow_model_usage',
];

const CORE_TOOLS = [
  'marrow_agent_runtime',
  'marrow_think',
  'marrow_commit',
  'marrow_ask',
  'marrow_status',
  'marrow_auto',
  'marrow_handoff_status',
];

function protocolInput(toolName) {
  const rows = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
    { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
  ];
  if (toolName) {
    rows.push({
      jsonrpc: '2.0', id: 3, method: 'tools/call',
      params: { name: toolName, arguments: {} },
    });
  }
  return rows.map((row) => JSON.stringify(row)).join('\n') + '\n';
}

function runMcp(extraEnv = {}, toolName, backendData = { health: 'healthy' }) {
  const home = mkdtempSync(join(tmpdir(), 'marrow-tool-profile-'));
  try {
    const fetchMock = join(home, 'profile-fetch.cjs');
    writeFileSync(fetchMock, `
const backendData = ${JSON.stringify(backendData)};
globalThis.fetch = async () => Response.json({ data: backendData });
`);
    const env = {
      ...process.env,
      HOME: home,
      MARROW_API_KEY: 'fixture-profile-key',
      MARROW_BASE_URL: 'https://api.example.test',
      MARROW_FLEET_AGENT_ID: 'agent-profile-test',
      MARROW_AUTO_ENROLL: 'false',
      NODE_OPTIONS: `--require=${fetchMock}`,
      ...extraEnv,
    };
    if (!Object.hasOwn(extraEnv, 'MARROW_TOOL_PROFILE')) delete env.MARROW_TOOL_PROFILE;
    const child = spawnSync(process.execPath, [join(__dirname, '..', 'dist', 'cli.js')], {
      env,
      input: protocolInput(toolName),
      encoding: 'utf8',
      timeout: 3_000,
    });
    if (child.error) throw child.error;
    return child;
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}

function messages(child) {
  assert.equal(child.status, 0, child.stderr);
  return new Map(child.stdout.trim().split('\n').filter(Boolean).map((line) => JSON.parse(line))
    .filter((message) => message.id != null)
    .map((message) => [message.id, message]));
}

test('unset MCP profile exposes exactly the documented 17-tool primary surface', () => {
  const output = messages(runMcp());
  const names = output.get(2).result.tools.map((tool) => tool.name);
  assert.equal(names.length, 17);
  assert.deepEqual(new Set(names), new Set(PRIMARY_TOOLS));
  assert.equal(names.includes('marrow_create_key'), false);
  assert.equal(names.includes('marrow_status'), false);
});

test('explicit primary MCP profile matches the unset primary surface', () => {
  const output = messages(runMcp({ MARROW_TOOL_PROFILE: 'primary' }));
  assert.deepEqual(
    new Set(output.get(2).result.tools.map((tool) => tool.name)),
    new Set(PRIMARY_TOOLS),
  );
});

test('explicit core MCP profile preserves exactly the existing seven tools', () => {
  const output = messages(runMcp({ MARROW_TOOL_PROFILE: 'core' }));
  const names = output.get(2).result.tools.map((tool) => tool.name);
  assert.equal(names.length, 7);
  assert.deepEqual(new Set(names), new Set(CORE_TOOLS));
});

test('explicit full MCP profile preserves the complete 58-tool catalog', () => {
  const output = messages(runMcp({ MARROW_TOOL_PROFILE: 'full' }));
  const names = output.get(2).result.tools.map((tool) => tool.name);
  assert.equal(names.length, 58);
  for (const name of [...PRIMARY_TOOLS, ...CORE_TOOLS, 'marrow_create_key', 'marrow_install_template']) {
    assert.ok(names.includes(name), `${name} missing from full profile`);
  }
});

test('invalid MCP profiles fail with one bounded repair and never broaden visibility', () => {
  for (const invalid of ['', 'PRIMARY', 'legacy', ' full ']) {
    const output = messages(runMcp({ MARROW_TOOL_PROFILE: invalid }));
    const response = output.get(2);
    assert.equal(response.result, undefined);
    assert.equal(response.error.code, -32602);
    assert.match(response.error.message, /Invalid MARROW_TOOL_PROFILE value/);
    assert.match(response.error.message, /primary, core, or full/);
    assert.match(response.error.message, /unset it for primary/);
    assert.doesNotMatch(response.error.message, /fallback|defaulting to full/i);
  }
});

test('primary agent status reports effective visibility and a fresh backend entitlement projection', () => {
  const availability = PRIMARY_TOOLS.map((name, index) => ({
    name,
    state: index === 0 ? 'entitled' : 'upgrade_required',
    ...(index === 0 ? {} : { feature: 'fleet_learning' }),
    account_management_url: 'https://getmarrow.ai/account/#billing',
  }));
  const output = messages(runMcp({}, 'marrow_agent_status', {
    health: 'healthy',
    primary_tool_availability: availability,
  }));
  const payload = JSON.parse(output.get(3).result.content[0].text);
  assert.equal(payload.mcp_tool_profile.configured_profile, 'unset');
  assert.equal(payload.mcp_tool_profile.effective_profile, 'primary');
  assert.equal(payload.mcp_tool_profile.visible_tool_count, 17);
  assert.deepEqual(new Set(payload.mcp_tool_profile.visible_tool_names), new Set(PRIMARY_TOOLS));
  assert.equal(payload.mcp_tool_profile.local_visibility_grants_entitlement, false);
  assert.equal(payload.mcp_tool_profile.backend_entitlement_projection.evidence_state, 'available');
  assert.equal(payload.mcp_tool_profile.backend_entitlement_projection.authorizes_calls, false);
  assert.deepEqual(payload.mcp_tool_profile.backend_entitlement_projection.primary_tool_availability, availability);
});

test('status labels missing backend entitlement evidence unavailable and non-authorizing', () => {
  const output = messages(runMcp({}, 'marrow_agent_status', { health: 'healthy' }));
  const payload = JSON.parse(output.get(3).result.content[0].text);
  assert.equal(payload.mcp_tool_profile.backend_entitlement_projection.evidence_state, 'unavailable');
  assert.equal(payload.mcp_tool_profile.backend_entitlement_projection.source, 'backend_projection_not_provided');
  assert.equal(payload.mcp_tool_profile.backend_entitlement_projection.authorizes_calls, false);
  assert.equal(payload.mcp_tool_profile.backend_entitlement_projection.primary_tool_availability, null);
});

test('core and full status surfaces report their own effective profile and visible count', () => {
  const core = messages(runMcp({ MARROW_TOOL_PROFILE: 'core' }, 'marrow_status'));
  const corePayload = JSON.parse(core.get(3).result.content[0].text);
  assert.equal(corePayload.mcp_tool_profile.effective_profile, 'core');
  assert.equal(corePayload.mcp_tool_profile.visible_tool_count, 7);

  const full = messages(runMcp({ MARROW_TOOL_PROFILE: 'full' }, 'marrow_runtime_status'));
  const fullPayload = JSON.parse(full.get(3).result.content[0].text);
  assert.equal(fullPayload.mcp_tool_profile.effective_profile, 'full');
  assert.equal(fullPayload.mcp_tool_profile.visible_tool_count, 58);
});
