const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { mkdtempSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const { MARROW_OWN_TOOL_NAMES, isMarrowOwnTool } = require('../dist/own-tool.js');
const { CORE_TOOL_NAMES, PRIMARY_TOOL_NAMES, TOOLS } = require('../dist/tool-catalog.js');
const { isOfficialMarrowMcpEvent, isOfficialMarrowMcpTool } = require('../dist/hook-tool-policy.js');
const { normalizeHookEventPayload } = require('../dist/hook-contract.js');
const { classifyTool, runPreActionHookCommand } = require('../dist/hook-pre-action.js');
const { deriveAction, runHookCommand } = require('../dist/hook.js');

const OWN = [...MARROW_OWN_TOOL_NAMES];

// Every host form, as each host emits it for the server named `marrow`:
// Claude Code mcp__<server>__<tool> (test/hook-install.test.js, test/pre-action-hook.test.js),
// Codex functions.<name> (test/hook-install.test.js), Gemini mcp_<server>_<tool>
// (test/gemini-hook.test.js), Cursor MCP:<tool> and MCP:<server>:<tool>
// (test/cursor-hook.test.js, test/host-approvals.test.js), Cline use_mcp_tool
// (test/cline-hook.test.js), Grok use_tool (test/grok-hook.test.js), Windsurf
// pre_mcp_tool_use (test/windsurf-hook.test.js).
const HOSTS = [
  { host: 'claude', entry: 'claude-pre-action-hook', event: (s, t) => ({ hook_event_name: 'PreToolUse', tool_name: `mcp__${s}__${t}`, tool_input: {} }) },
  // functions.mcp__* is an MCP tool too (G1), so a foreign one is held like mcp__*.
  { host: 'codex', entry: 'codex-pre-action-hook', event: (s, t) => ({ hook_event_name: 'PreToolUse', tool_name: `functions.mcp__${s}__${t}`, tool_input: {} }) },
  { host: 'codex-bare', entry: 'codex-pre-action-hook', event: (s, t) => ({ hook_event_name: 'PreToolUse', tool_name: `mcp__${s}__${t}`, tool_input: {} }) },
  // Gemini >= 0.33 labels `mcp_<server>_<tool>` and sends the separate server and tool in mcp_context (r3: the proof).
  { host: 'gemini', entry: 'gemini-pre-action-hook', event: (s, t) => ({ hook_event_name: 'BeforeTool', tool_name: `mcp_${s}_${t}`, tool_input: {}, mcp_context: { server_name: s, tool_name: t } }) },
  { host: 'cursor-pre-no-server', entry: 'cursor-pre-action-hook', server: false, event: (_s, t) => ({ hook_event_name: 'preToolUse', tool_name: `MCP:${t}`, tool_input: {} }) },
  { host: 'cursor-pre', entry: 'cursor-pre-action-hook', event: (s, t) => ({ hook_event_name: 'preToolUse', tool_name: `MCP:${s}:${t}`, tool_input: {} }) },
  { host: 'cursor-mcp', entry: 'cursor-pre-action-hook', event: (s, t) => ({ hook_event_name: 'beforeMCPExecution', mcp_server_name: s, tool_name: t, tool_input: '{}' }) },
  { host: 'cline', entry: 'cline-pre-action-hook', event: (s, t) => ({ hookName: 'PreToolUse', taskId: 'own-tool-task', preToolUse: { toolName: 'use_mcp_tool', parameters: { serverName: s, toolName: t } } }) },
  { host: 'grok', entry: 'grok-pre-action-hook', event: (s, t) => ({ hookEventName: 'PreToolUse', sessionId: 'own-tool-session', toolName: 'use_tool', toolInput: { serverName: s, toolName: t } }) },
  { host: 'windsurf', entry: 'windsurf-pre-action-hook', event: (s, t) => ({ agent_action_name: 'pre_mcp_tool_use', trajectory_id: 'own-tool-trajectory', tool_info: { mcp_server_name: s, mcp_tool_name: t } }) },
];

const ALLOW = {
  claude: '{}', codex: '{}', 'codex-bare': '{}', gemini: '{"decision":"allow"}',
  'cursor-pre-no-server': '{"permission":"allow"}', 'cursor-pre': '{"permission":"allow"}', 'cursor-mcp': '{"permission":"allow"}',
  cline: '{"cancel":false}', grok: '{"decision":"allow"}', windsurf: '',
};

const ENV_KEYS = ['MARROW_API_KEY', 'MARROW_KEY', 'MARROW_BASE_URL', 'MARROW_AGENT_ID', 'MARROW_FLEET_AGENT_ID', 'MARROW_SESSION_ID', 'MARROW_PASSIVE_TOKEN_USAGE'];

async function withEntrypoint(entrypoint, env, callback) {
  const previous = Object.fromEntries(ENV_KEYS.map((key) => [key, process.env[key]]));
  const originalArg = process.argv[2];
  process.argv[2] = entrypoint;
  for (const key of ENV_KEYS) delete process.env[key];
  Object.assign(process.env, env);
  try {
    return await callback();
  } finally {
    process.argv[2] = originalArg;
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

/** Runs the real pre-action hook in-process with no key: own tools allow, everything else is held. */
async function runPre(entrypoint, payload) {
  const originalWrite = process.stdout.write;
  const originalError = process.stderr.write;
  const originalExitCode = process.exitCode;
  let stdout = '';
  process.exitCode = undefined;
  process.stdout.write = (chunk) => { stdout += String(chunk); return true; };
  process.stderr.write = () => true;
  try {
    await withEntrypoint(entrypoint, {}, () => runPreActionHookCommand(payload));
    return { stdout, exitCode: process.exitCode ?? 0 };
  } finally {
    process.stdout.write = originalWrite;
    process.stderr.write = originalError;
    process.exitCode = originalExitCode;
  }
}

test('own-tool set is built from the tool registry and matches what every profile serves', () => {
  assert.deepEqual(OWN.sort(), TOOLS.map((tool) => tool.name).sort());
  assert.equal(OWN.length, new Set(TOOLS.map((tool) => tool.name)).size);
  for (const name of [...PRIMARY_TOOL_NAMES, ...CORE_TOOL_NAMES]) assert.ok(MARROW_OWN_TOOL_NAMES.has(name), name);
  for (const name of OWN) assert.match(name, /^marrow_[a-z0-9_]+$/);

  // Drift: what the real stdio server lists per profile must be exactly inside the own set,
  // and the full profile must list the whole set.
  const home = mkdtempSync(join(tmpdir(), 'marrow-own-tool-registry-'));
  try {
    const fetchMock = join(home, 'fetch.cjs');
    writeFileSync(fetchMock, 'globalThis.fetch = async () => Response.json({ data: { health: "healthy" } });\n');
    const listed = {};
    for (const profile of ['primary', 'core', 'full']) {
      const child = spawnSync(process.execPath, [join(__dirname, '..', 'dist', 'cli.js')], {
        env: {
          PATH: process.env.PATH,
          HOME: home,
          MARROW_API_KEY: `dummy-${randomUUID()}`,
          MARROW_BASE_URL: 'https://api.example.test',
          MARROW_FLEET_AGENT_ID: 'own-tool-registry',
          MARROW_AUTO_ENROLL: 'false',
          MARROW_TOOL_PROFILE: profile,
          NODE_OPTIONS: `--require=${fetchMock}`,
        },
        input: [
          { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
          { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
        ].map((row) => JSON.stringify(row)).join('\n') + '\n',
        encoding: 'utf8',
        timeout: 5_000,
      });
      const row = child.stdout.split('\n').filter(Boolean).map((line) => JSON.parse(line)).find((entry) => entry.id === 2);
      listed[profile] = row.result.tools.map((tool) => tool.name).sort();
      for (const name of listed[profile]) assert.ok(MARROW_OWN_TOOL_NAMES.has(name), `${profile}: ${name}`);
    }
    assert.deepEqual(listed.full, [...OWN].sort());
    assert.deepEqual(listed.primary, [...PRIMARY_TOOL_NAMES].sort());
    assert.deepEqual(listed.core, [...CORE_TOOL_NAMES].sort());
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('every registered tool name is own in every host form, end to end through the pre-action hook', async () => {
  assert.ok(OWN.length >= 58);
  for (const tool of OWN) {
    assert.equal(isMarrowOwnTool('marrow', tool), true);
    for (const form of HOSTS) {
      const payload = form.event('marrow', tool);
      const normalized = normalizeHookEventPayload(payload);
      assert.equal(isOfficialMarrowMcpEvent(normalized), true, `${form.host} ${tool}`);
      assert.equal(classifyTool(normalized).protected, false, `${form.host} ${tool}`);
      assert.equal(deriveAction(normalized), null, `${form.host} ${tool}`);
      const out = await runPre(form.entry, payload);
      assert.equal(out.stdout, ALLOW[form.host], `${form.host} ${tool}`);
      assert.equal(out.exitCode, 0, `${form.host} ${tool}`);
    }
  }
  // Nested aliases that agree, and the other nested wrapper names the hook knows.
  for (const wrapper of ['use_mcp_tool', 'use_tool', 'mcp', 'mcp_tool']) {
    assert.equal(isOfficialMarrowMcpEvent({ tool_name: wrapper, tool_input: { server_name: 'marrow', tool_name: 'marrow_commit' } }), true);
    assert.equal(isOfficialMarrowMcpEvent({ tool_name: wrapper, tool_input: { serverName: 'marrow', server_name: 'marrow', toolName: 'marrow_commit' } }), true);
  }
});

const SERVER_VARIANTS = [
  'MARROW', 'Marrow', 'mARROW', 'marroW', 'marrow2', 'marrow_', '_marrow', 'xmarrow', 'marrowx', 'plugin_marrow_marrow',
  'marrow-evil', 'evil', 'marrow ', ' marrow', 'marrow\n', 'marrow\t', 'marrow\0', 'мarrow', 'mаrrow', 'marrow​',
  'ｍarrow', 'marroẃ', 'MARROW', '',
];
const TOOL_VARIANTS = [
  'marrow_delete_all', 'marrow_exec', 'marrow_x', 'marrow_', 'marrow', 'MARROW_COMMIT', 'Marrow_commit', 'marrow_Commit',
  'marrow_commitx', 'marrow_commit ', ' marrow_commit', 'marrow_commit\n', 'marrow_commit\0', 'marrow_commit\t',
  'marrow_x__deploy_prod', 'marrow_commit__mcp__github__push', 'mаrrow_commit', 'marrow_cоmmit', 'marrow_commit​',
  'commit', 'think', 'delete_all',
];

test('look-alike servers and unregistered or padded tools are never own and are held like any foreign MCP tool', async () => {
  const foreign = {};
  for (const form of HOSTS) {
    foreign[form.host] = await runPre(form.entry, form.event('evil', 'delete_all'));
    if (form.foreignHeld !== false) assert.notEqual(foreign[form.host].stdout + foreign[form.host].exitCode, ALLOW[form.host] + 0, `${form.host} foreign tool must be held`);
  }
  const cases = [];
  for (const server of SERVER_VARIANTS) cases.push(['marrow_commit', server], ['marrow_delete_all', server]);
  for (const tool of TOOL_VARIANTS) cases.push([tool, 'marrow']);
  let checked = 0;
  for (const [tool, server] of cases) {
    assert.equal(isMarrowOwnTool(server, tool), false, JSON.stringify([server, tool]));
    for (const form of HOSTS) {
      if (form.server === false && server !== 'marrow') continue;
      const payload = form.event(server, tool);
      const normalized = normalizeHookEventPayload(payload);
      assert.equal(isOfficialMarrowMcpEvent(normalized), false, `${form.host} ${JSON.stringify([server, tool])}`);
      // A name the adapter cannot bound (inner whitespace or NUL) has no tool_name and is held as unclassifiable.
      if (normalized.tool_name) assert.notEqual(deriveAction(normalized), null, `${form.host} ${JSON.stringify([server, tool])} is recorded`);
      const out = await runPre(form.entry, payload);
      if (form.foreignHeld !== false) assert.notEqual(out.stdout + out.exitCode, ALLOW[form.host] + 0, `${form.host} ${JSON.stringify([server, tool])} must be held`);
      assert.deepEqual(out, foreign[form.host], `${form.host} ${JSON.stringify([server, tool])} takes the foreign-tool gate path`);
      checked += 1;
    }
  }
  assert.ok(checked > 500, `checked ${checked}`);
});

test('raw tool-name table: case, prefixes, look-alike servers, suffixes, whitespace and NUL', () => {
  const own = [
    'mcp__marrow__marrow_commit', 'functions.mcp__marrow__marrow_commit',
    'MCP:marrow_commit', 'MCP:marrow:marrow_commit', 'mcp__marrow__marrow_auto', 'mcp__marrow__marrow_create_key',
    'mcp__marrow__marrow_run', 'MCP:marrow:marrow_handoff_status',
  ];
  for (const name of own) assert.equal(isOfficialMarrowMcpTool(name), true, name);
  const gated = [
    // r3: a Gemini label alone is never own (server `marrow_marrow` + `commit` has the same label); see own-tool-r3
    'mcp_marrow_marrow_commit', 'mcp_marrow_marrow_agent_runtime',
    // F9: case variants of server, tool and host prefix
    'mcp__MARROW__marrow_delete_all', 'mcp__Marrow__marrow_exec', 'mcp__MARROW__marrow_commit', 'mcp__marrow__MARROW_COMMIT',
    'mcp__marrow__Marrow_commit', 'MCP__marrow__marrow_commit', 'Mcp__marrow__marrow_commit', 'mcp:marrow_commit', 'Mcp:marrow:marrow_commit',
    'MCP:MARROW:marrow_commit', 'MCP:Marrow:marrow_commit', 'MCP:MARROW_COMMIT', 'mcp_MARROW_marrow_commit', 'MCP_marrow_marrow_commit',
    'mcp_marrow_MARROW_COMMIT', 'FUNCTIONS.mcp__marrow__marrow_commit', 'Functions.mcp__marrow__marrow_commit',
    // unregistered marrow_* tools on the exact server
    'mcp__marrow__marrow_delete_all', 'mcp__marrow__marrow_', 'mcp__marrow__marrow', 'MCP:marrow_delete_all', 'MCP:marrow:marrow_exec',
    'mcp_marrow_marrow_delete_all', 'functions.mcp__marrow__marrow_delete_all', 'mcp__marrow__marrow_x__deploy_prod',
    // look-alike servers
    'mcp__marrow2__marrow_commit', 'mcp__marrow___marrow_commit', 'mcp__plugin_marrow_marrow__marrow_commit', 'mcp__xmarrow__marrow_commit',
    'mcp__marrow_evil__marrow_commit', 'mcp__мarrow__marrow_commit', 'mcp__mаrrow__marrow_commit', 'mcp__marrow​__marrow_commit',
    'MCP:marrow2:marrow_commit', 'MCP:marrow_:marrow_commit', 'MCP:plugin_marrow_marrow:marrow_commit', 'mcp_marrow2_marrow_commit',
    'mcp_evil_marrow_commit', 'MCP:evil:marrow_commit', 'mcp__evil__marrow_commit',
    // suffix, prefix, whitespace, NUL
    'mcp__marrow__marrow_commitx', 'mcp__marrow__marrow_commit ', ' mcp__marrow__marrow_commit', 'mcp__marrow__marrow_commit\n',
    '\nmcp__marrow__marrow_commit', 'mcp__marrow__marrow_commit\0', 'mcp__marrow__marrow_commit\t', 'MCP:marrow_commit ',
    'MCP:marrow:marrow_commit\n', 'mcp_marrow_marrow_commit\0', 'functions.mcp__marrow__marrow_commit ', 'functions. mcp__marrow__marrow_commit',
    'xmcp__marrow__marrow_commit', 'mcp__evil__mcp__marrow__marrow_commit', 'functions.functions.mcp__marrow__marrow_commit',
    // functions. on forms no host emits, and MCP: with an empty server
    'functions.MCP:marrow_commit', 'functions.mcp_marrow_marrow_commit', 'functions.marrow_commit', 'MCP::marrow_commit', 'MCP:',
    'marrow_commit', 'mcp__marrow__', '', 'mcp__marrow__constructor', 'mcp__marrow____proto__', 'MCP:toString',
  ];
  for (const name of gated) {
    assert.equal(isOfficialMarrowMcpTool(name), false, JSON.stringify(name));
    const event = { tool_name: name, tool_input: {} };
    assert.equal(isOfficialMarrowMcpEvent(event), false, JSON.stringify(name));
    if (/^(?:mcp__|mcp_|MCP:)/i.test(name.trim())) assert.equal(classifyTool(event).protected, true, JSON.stringify(name));
  }
  for (const value of [null, undefined, 42, {}, ['mcp__marrow__marrow_commit'], { toString: () => 'mcp__marrow__marrow_commit' }]) {
    assert.equal(isOfficialMarrowMcpTool(value), false);
    assert.equal(isMarrowOwnTool(value, 'marrow_commit'), false);
    assert.equal(isMarrowOwnTool('marrow', value), false);
  }
});

test('nested use_mcp_tool / use_tool: wrapper, server and tool must be exact and aliases must agree', () => {
  const nested = (tool_name, tool_input) => isOfficialMarrowMcpEvent({ tool_name, tool_input });
  assert.equal(nested('use_mcp_tool', { serverName: 'marrow', toolName: 'marrow_commit' }), true);
  for (const wrapper of ['USE_MCP_TOOL', 'Use_Mcp_Tool', 'use_mcp_tool ', ' use_tool', 'use_tool\n', 'USE_TOOL', 'MCP', 'use_mcp_tool\0', 'functions.use_mcp_tool']) {
    assert.equal(nested(wrapper, { serverName: 'marrow', toolName: 'marrow_commit' }), false, JSON.stringify(wrapper));
  }
  for (const server of SERVER_VARIANTS) assert.equal(nested('use_mcp_tool', { serverName: server, toolName: 'marrow_commit' }), false, JSON.stringify(server));
  for (const tool of TOOL_VARIANTS) assert.equal(nested('use_tool', { serverName: 'marrow', toolName: tool }), false, JSON.stringify(tool));
  // Conflicting aliases: the host may run either one, so the call is not own.
  assert.equal(nested('use_mcp_tool', { serverName: 'marrow', server_name: 'evil', toolName: 'marrow_commit' }), false);
  assert.equal(nested('use_mcp_tool', { serverName: 'evil', server_name: 'marrow', toolName: 'marrow_commit' }), false);
  assert.equal(nested('use_mcp_tool', { serverName: 'marrow', toolName: 'marrow_commit', tool_name: 'marrow_delete_all' }), false);
  assert.equal(nested('use_mcp_tool', { serverName: 'marrow', toolName: 'marrow_delete_all', tool_name: 'marrow_commit' }), false);
  assert.equal(nested('use_mcp_tool', { serverName: 'marrow', server_name: null, toolName: 'marrow_commit' }), false);
  assert.equal(nested('use_mcp_tool', { serverName: 'marrow' }), false);
  assert.equal(nested('use_mcp_tool', { toolName: 'marrow_commit' }), false);
  assert.equal(nested('use_mcp_tool', null), false);
  assert.equal(nested('use_mcp_tool', [{ serverName: 'marrow', toolName: 'marrow_commit' }]), false);
  assert.equal(nested('use_mcp_tool', 'marrow:marrow_commit'), false);
  // A nested-looking input on a tool that is not a nested wrapper never makes it own.
  for (const wrapper of ['Bash', 'mcp__evil__delete_all', 'MCP:evil:delete_all', 'use_mcp_tools', '']) {
    assert.equal(nested(wrapper, { serverName: 'marrow', toolName: 'marrow_commit' }), false, JSON.stringify(wrapper));
  }
  assert.equal(classifyTool({ tool_name: 'use_mcp_tool', tool_input: { serverName: 'MARROW', toolName: 'marrow_delete_all' } }).protected, true);
  assert.equal(classifyTool({ tool_name: 'use_tool', tool_input: { serverName: 'marrow', toolName: 'marrow_delete_all' } }).protected, true);
});

test('adapter normalisation never turns MARROW, Marrow or a padded marrow name into the official form', () => {
  const official = /^mcp__marrow__/;
  const cases = [
    ['MARROW', 'marrow_commit'], ['Marrow', 'marrow_commit'], ['MARROW', 'marrow_delete_all'], ['marrow', 'marrow_delete_all'],
    ['marrow', 'MARROW_COMMIT'], ['marrow ', 'marrow_commit'], [' marrow', 'marrow_commit'], ['marrow\n', 'marrow_commit'],
    ['marrow', 'marrow_commit '], ['marrow', '\tmarrow_commit'], ['marrow\0', 'marrow_commit'], ['marrow2', 'marrow_commit'],
  ];
  for (const [server, tool] of cases) {
    const label = JSON.stringify([server, tool]);
    const windsurf = normalizeHookEventPayload({ agent_action_name: 'pre_mcp_tool_use', tool_info: { mcp_server_name: server, mcp_tool_name: tool } });
    const cursor = normalizeHookEventPayload({ hook_event_name: 'beforeMCPExecution', mcp_server_name: server, tool_name: tool, tool_input: '{}' });
    const grok = normalizeHookEventPayload({ hookEventName: 'PreToolUse', toolName: 'use_tool', toolInput: { serverName: server, toolName: tool } });
    for (const [host, event] of [['windsurf', windsurf], ['cursor', cursor], ['grok', grok]]) {
      assert.doesNotMatch(String(event.tool_name ?? ''), official, `${host} ${label}`);
      assert.equal(isOfficialMarrowMcpEvent(event), false, `${host} ${label}`);
    }
  }
  // Distinct inexact names stay distinct (no key collision between padded variants).
  const padded = ['marrow ', ' marrow', 'marrow\t'].map((server) => normalizeHookEventPayload({
    agent_action_name: 'pre_mcp_tool_use', tool_info: { mcp_server_name: server, mcp_tool_name: 'marrow_commit' },
  }).tool_name);
  assert.equal(new Set(padded).size, padded.length);
  // A padded Grok wrapper or conflicting aliases do not normalise to own either.
  for (const event of [
    { hookEventName: 'PreToolUse', toolName: 'use_tool ', toolInput: { serverName: 'marrow', toolName: 'marrow_commit' } },
    { hookEventName: 'PreToolUse', toolName: 'use_tool', toolInput: { serverName: 'marrow', server_name: 'evil', toolName: 'marrow_commit' } },
  ]) {
    const normalized = normalizeHookEventPayload(event);
    assert.equal(isOfficialMarrowMcpEvent(normalized), false, JSON.stringify(event));
  }
  // Gemini passes its own name through: a padded own name is left unclassified (held), never trimmed into own.
  for (const name of ['mcp_marrow_marrow_commit ', ' mcp_marrow_marrow_commit', 'mcp_marrow_marrow_commit\n']) {
    const gemini = normalizeHookEventPayload({ hook_event_name: 'BeforeTool', tool_name: name, tool_input: {} });
    assert.equal(isOfficialMarrowMcpEvent(gemini), false, JSON.stringify(name));
  }
  // Exact names still normalise to the official form (no lockout).
  assert.equal(normalizeHookEventPayload({ agent_action_name: 'pre_mcp_tool_use', tool_info: { mcp_server_name: 'marrow', mcp_tool_name: 'marrow_commit' } }).tool_name, 'mcp__marrow__marrow_commit');
  assert.equal(normalizeHookEventPayload({ hook_event_name: 'beforeMCPExecution', mcp_server_name: 'marrow', tool_name: 'marrow_commit', tool_input: '{}' }).tool_name, 'mcp__marrow__marrow_commit');
  assert.equal(normalizeHookEventPayload({ hookEventName: 'PreToolUse', toolName: 'use_tool', toolInput: { serverName: 'marrow', toolName: 'marrow_commit' } }).tool_name, 'mcp__marrow__marrow_commit');
});

test('post-action recorder records a look-alike Marrow tool like any foreign tool and skips only own tools', async () => {
  const calls = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ pathname: new URL(String(url)).pathname, body: init.body ? JSON.parse(String(init.body)) : {} });
    return Response.json({ data: { accepted: true } });
  };
  const key = `dummy-${randomUUID()}`;
  const recorded = ['mcp__MARROW__marrow_delete_all', 'mcp__Marrow__marrow_commit', 'mcp__marrow__marrow_delete_all', 'mcp__evil__delete_all'];
  try {
    await withEntrypoint('claude-hook', {
      MARROW_API_KEY: key,
      MARROW_BASE_URL: 'https://api.example.test',
      MARROW_FLEET_AGENT_ID: 'own-tool-post',
      MARROW_PASSIVE_TOKEN_USAGE: 'false',
    }, async () => {
      const originalWrite = process.stdout.write;
      process.stdout.write = () => true;
      try {
        for (const [index, tool_name] of [...recorded, 'mcp__marrow__marrow_commit'].entries()) {
          await runHookCommand({ hook_event_name: 'PostToolUse', session_id: 'own-tool-post', tool_use_id: `post-${index}`, tool_name, tool_input: {}, tool_response: { ok: true } });
        }
        await require('../dist/lifecycle-spool.js').drainLifecycleSpool({
          apiKey: process.env.MARROW_API_KEY, baseUrl: process.env.MARROW_BASE_URL, agentId: process.env.MARROW_FLEET_AGENT_ID,
        });
      } finally {
        process.stdout.write = originalWrite;
      }
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
  const events = calls.filter((call) => call.pathname === '/v1/agent/integrations/events');
  assert.equal(events.length, recorded.length, JSON.stringify(calls.map((call) => call.pathname)));
  assert.doesNotMatch(JSON.stringify(calls), new RegExp(key));
  for (const name of recorded) assert.notEqual(deriveAction({ tool_name: name, tool_input: {} }), null, name);
  assert.equal(deriveAction({ tool_name: 'mcp__marrow__marrow_commit', tool_input: {} }), null);
});
