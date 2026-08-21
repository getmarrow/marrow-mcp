const assert = require('node:assert/strict');
const { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const {
  NATIVE_HOOK_RECEIPTS,
  hostCapabilityInstructions,
  resolveHostCapability,
} = require('../dist/host-capability.js');

function protocolInput() {
  return [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
    { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
    { jsonrpc: '2.0', id: 3, method: 'prompts/list', params: {} },
    { jsonrpc: '2.0', id: 4, method: 'prompts/get', params: { name: 'marrow-always-on' } },
    { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'marrow_status', arguments: {} } },
  ].map((row) => JSON.stringify(row)).join('\n') + '\n';
}

function runProtocol(home, extraEnv = {}) {
  const fetchMock = join(home, 'capability-fetch.cjs');
  writeFileSync(fetchMock, `
globalThis.fetch = async () => {
  await new Promise((resolve) => setTimeout(resolve, 100));
  return Response.json({ data: { health: 'healthy' } });
};
`);
  const env = {
    ...process.env,
    HOME: home,
    MARROW_API_KEY: 'fixture-capability-key',
    MARROW_BASE_URL: 'https://127.0.0.1:9',
    MARROW_AUTO_ENROLL: 'true',
    MARROW_REQUEST_TIMEOUT_MS: '1000',
    NODE_OPTIONS: `--require=${fetchMock}`,
    ...extraEnv,
  };
  for (const key of ['MARROW_CLIENT', 'MARROW_HARNESS', 'MARROW_AGENT_CLIENT']) {
    if (!Object.hasOwn(extraEnv, key)) delete env[key];
  }
  const child = spawnSync(process.execPath, [join(__dirname, '..', 'dist', 'cli.js')], {
    env,
    input: protocolInput(),
    encoding: 'utf8',
    timeout: 3_000,
  });
  if (child.error) throw child.error;
  assert.equal(child.status, 0, child.stderr);
  return new Map(child.stdout.trim().split('\n').filter(Boolean).map((line) => JSON.parse(line))
    .filter((message) => message.id != null)
    .map((message) => [message.id, message]));
}

test('neutral stdio and unknown hosts share the truthful on-demand fallback', () => {
  const neutral = resolveHostCapability();
  const unknown = resolveHostCapability({ hostLabel: 'arbitrary-future-model' });
  assert.equal(neutral.host, 'mcp-client');
  assert.equal(unknown.host, 'mcp-client');
  assert.equal(neutral.host_identity_source, 'generic_fallback');
  assert.equal(neutral.current_mode, 'tools_only_on_demand');
  assert.equal(neutral.coverage_verified, false);
  assert.equal(neutral.tool_invocation, 'on_demand');
  assert.equal(neutral.passive_hooks.provided_by_mcp_transport, false);
  assert.equal(neutral.capability_modes.custom_host.state, 'adapter_required');
  assert.deepEqual(unknown, neutral);
});

test('representative host labels are display-only and never infer coverage', () => {
  const baseline = resolveHostCapability();
  for (const hostLabel of ['grok', 'claude-code', 'codex', 'cursor']) {
    const capability = resolveHostCapability({ hostLabel });
    assert.equal(capability.host, hostLabel);
    assert.equal(capability.host_identity_source, 'adapter_hint');
    assert.equal(capability.host_identity_affects_coverage, false);
    assert.equal(capability.current_mode, baseline.current_mode);
    assert.equal(capability.coverage_scope, baseline.coverage_scope);
    assert.equal(capability.coverage_verified, false);
    assert.equal(capability.certification.model_name_is_evidence, false);
    assert.equal(capability.certification.configuration_detection_is_evidence, false);
  }

  const forgedDetection = resolveHostCapability({
    hostLabel: 'claude-code',
    observedReceipts: ['model:grok', 'config:native-hooks-installed'],
  });
  assert.equal(forgedDetection.coverage_verified, false);
  assert.deepEqual(forgedDetection.certification.observed_receipts, []);
});

test('native passive coverage requires the complete observed hook receipt set', () => {
  const partial = resolveHostCapability({
    hostLabel: 'claude-code',
    observedReceipts: NATIVE_HOOK_RECEIPTS.slice(0, 3),
  });
  assert.equal(partial.current_mode, 'tools_only_on_demand');
  assert.equal(partial.passive_hooks.external_host_hook_state, 'unverified');
  assert.equal(partial.coverage_verified, false);

  const verified = resolveHostCapability({
    hostLabel: 'claude-code',
    observedReceipts: NATIVE_HOOK_RECEIPTS,
  });
  assert.equal(verified.current_mode, 'verified_native_hooks');
  assert.equal(verified.coverage_scope, 'observed_hook_lifecycle_only');
  assert.equal(verified.passive_hooks.external_host_hook_state, 'verified');
  assert.equal(verified.passive_hooks.observed_by_this_process, false);
  assert.equal(verified.passive_hooks.observed_by_marrow, true);
  assert.equal(verified.coverage_verified, true);
  assert.equal(verified.always_on_state, 'verified_passive');
});

test('SDK, runner, and custom adapter evidence retain bounded scopes', () => {
  const sdk = resolveHostCapability({ observedReceipts: ['sdk_passive_runtime:active'] });
  assert.equal(sdk.current_mode, 'owned_sdk_process');
  assert.equal(sdk.coverage_scope, 'owned_node_process_while_installed');
  assert.equal(sdk.capability_modes.native_hooks.state, 'unverified');

  const runner = resolveHostCapability({ observedReceipts: ['governed_runner:wrapped_command'] });
  assert.equal(runner.current_mode, 'governed_wrapped_command');
  assert.equal(runner.coverage_scope, 'wrapped_command_only');
  assert.equal(runner.capability_modes.sdk_passive_runtime.state, 'unverified');

  const adapter = resolveHostCapability({ observedReceipts: ['event_adapter:lifecycle'] });
  assert.equal(adapter.current_mode, 'custom_event_adapter');
  assert.equal(adapter.coverage_scope, 'observed_event_adapter_lifecycle_only');
  assert.equal(adapter.capability_modes.custom_host.state, 'verified');
  assert.equal(resolveHostCapability().capability_modes.custom_host.state, 'adapter_required');
});

test('canonical instructions state every capability boundary without claiming setup as proof', () => {
  const instructions = hostCapabilityInstructions(resolveHostCapability({ hostLabel: 'grok' }));
  assert.match(instructions, /MCP tools-only is on demand/);
  assert.match(instructions, /verified native hooks are passive only for observed hook lifecycle receipts/);
  assert.match(instructions, /owned Node process while installed/);
  assert.match(instructions, /governed runner covers only its wrapped command/);
  assert.match(instructions, /custom host needs a bounded event adapter/);
  assert.match(instructions, /model name, host label, installed configuration, or detected hook file never certifies coverage/);
  assert.match(instructions, /Only observed Marrow receipts do/);
});

test('neutral and representative MCP hosts expose one contract, seven tools, and the retained prompt name', () => {
  let baselineTools;
  let baselinePromptText;
  const hostCases = [
    { label: 'neutral', env: {}, expectedHost: 'mcp-client' },
    { label: 'client hint', env: { MARROW_CLIENT: 'grok' }, expectedHost: 'grok' },
    { label: 'harness hint', env: { MARROW_HARNESS: 'codex' }, expectedHost: 'codex' },
    { label: 'agent client hint', env: { MARROW_AGENT_CLIENT: 'claude-code' }, expectedHost: 'claude-code' },
    { label: 'unknown hint', env: { MARROW_CLIENT: 'unknown-host' }, expectedHost: 'mcp-client' },
  ];
  for (const hostCase of hostCases) {
    const home = mkdtempSync(join(tmpdir(), 'marrow-capability-protocol-'));
    try {
      const messages = runProtocol(home, hostCase.env);
      assert.ok(messages.has(1), `initialize response missing for ${hostCase.label}: ${JSON.stringify([...messages.keys()])}`);
      const initialize = messages.get(1).result;
      const tools = messages.get(2).result.tools;
      const promptList = messages.get(3).result.prompts;
      const prompt = messages.get(4).result;

      assert.equal(tools.length, 7);
      assert.deepEqual(new Set(tools.map((tool) => tool.name)), new Set([
        'marrow_agent_runtime',
        'marrow_think',
        'marrow_commit',
        'marrow_ask',
        'marrow_status',
        'marrow_auto',
        'marrow_handoff_status',
      ]));
      assert.equal(promptList.length, 1);
      assert.equal(promptList[0].name, 'marrow-always-on');
      assert.equal(initialize._meta.host_capability.host, hostCase.expectedHost);
      assert.equal(initialize._meta.host_capability.current_mode, 'tools_only_on_demand');
      assert.equal(promptList[0]._meta.host_capability.current_mode, 'tools_only_on_demand');
      assert.equal(prompt._meta.host_capability.current_mode, 'tools_only_on_demand');
      assert.match(initialize.instructions, /Current coverage: tools_only_on_demand/);
      assert.match(prompt.messages[0].content.text, /custom host needs a bounded event adapter/);
      assert.doesNotMatch(JSON.stringify({ initialize, promptList, prompt }), /automatic, zero-config|Installed hooks handle supported lifecycle capture automatically/);
      if (baselineTools) {
        assert.deepEqual(tools, baselineTools, `${hostCase.label} changed the model-neutral tool schemas`);
        assert.equal(prompt.messages[0].content.text, baselinePromptText, `${hostCase.label} changed the model-neutral prompt contract`);
      } else {
        baselineTools = tools;
        baselinePromptText = prompt.messages[0].content.text;
      }
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }
});

test('setup configures hooks without claiming automatic coverage', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-capability-setup-'));
  try {
    mkdirSync(join(directory, '.claude'), { recursive: true });
    const child = spawnSync(process.execPath, [join(__dirname, '..', 'dist', 'cli.js'), 'setup'], {
      cwd: directory,
      env: { ...process.env, HOME: directory },
      encoding: 'utf8',
      timeout: 3_000,
    });
    if (child.error) throw child.error;
    assert.equal(child.status, 0, child.stderr);
    const instructions = readFileSync(join(directory, 'CLAUDE.md'), 'utf8');
    assert.match(instructions, /MCP baseline is on demand/);
    assert.match(instructions, /Only observed Marrow receipts certify it/);
    assert.doesNotMatch(instructions, /Use it on EVERY session automatically|Passive by default/);

    const cliSource = readFileSync(join(__dirname, '..', 'src', 'cli.ts'), 'utf8');
    assert.match(cliSource, /Coverage remains unverified until Marrow observes action-result receipts/);
    assert.match(cliSource, /MCP tools remain on demand/);
    assert.doesNotMatch(cliSource, /Your agent will now use Marrow automatically|tool calls now auto-log to Marrow|Installed hooks handle supported lifecycle capture automatically/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('README documents the model-neutral capability matrix and receipt-only certification', () => {
  const readme = readFileSync(join(__dirname, '..', 'README.md'), 'utf8');
  assert.match(readme, /\| MCP tools-only \| On demand/);
  assert.match(readme, /\| Verified native hooks \| Passive only/);
  assert.match(readme, /createPassiveRuntime\(\)\.install\(\)/);
  assert.match(readme, /\| Governed runner \| Only the command launched through the wrapper/);
  assert.match(readme, /\| Custom host \| Requires a bounded event adapter/);
  assert.match(readme, /model-neutral/);
  assert.match(readme, /Only observed Marrow receipts do/);
});
