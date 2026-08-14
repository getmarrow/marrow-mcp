#!/usr/bin/env node
const { spawnSync } = require('node:child_process');
const { resolve } = require('node:path');
const { version: packageVersion } = require('../package.json');

const key = process.env.MARROW_API_KEY || '';
if (!key) {
  process.stderr.write('MARROW_API_KEY is required for the authenticated MCP control-path canary.\n');
  process.exit(2);
}

const cases = [
  ['marrow_status', {}],
  ['marrow_runtime_status', { fast: true }],
  ['marrow_orient', { autoWarn: true }],
  ['marrow_ask', { query: 'What should this agent verify before a safe release?' }],
  ['marrow_agent_runtime', { action: 'Review a local documentation note', type: 'general', surfaces: ['workspace'] }],
  ['marrow_first_value', { action: 'Verify Marrow control-path availability', type: 'review', surfaces: ['api'] }],
  ['marrow_buyer_proof', { periodDays: 7 }],
  ['marrow_governance_control_plane', {}],
  ['marrow_value_report', { period: '7d' }],
  ['marrow_fleet_lessons', { query: 'safe release verification', limit: 3 }],
];

function boundedMs(name, fallback, minimum = 100, maximum = 10_000) {
  const parsed = Number(process.env[name] || fallback);
  return Number.isFinite(parsed) ? Math.max(minimum, Math.min(maximum, Math.floor(parsed))) : fallback;
}

const transportTimeoutMs = boundedMs('MARROW_REQUEST_TIMEOUT_MS', 2_500, 250, 10_000);
const processTimeoutMs = transportTimeoutMs + 3_000;
const expectedVersion = process.env.MARROW_EXPECTED_MCP_VERSION || packageVersion;
const ceilings = {
  marrow_status: boundedMs('MARROW_MCP_STATUS_CEILING_MS', 1_500),
  marrow_ask: boundedMs('MARROW_MCP_ASK_CEILING_MS', 1_000),
  marrow_agent_runtime: boundedMs('MARROW_MCP_RUNTIME_CEILING_MS', 750),
};

function toolPayload(message, name) {
  if (!message) throw new Error(`${name} returned no MCP tool response`);
  if (message.error) throw new Error(`${name} returned JSON-RPC error ${message.error.code}`);
  const result = message.result || {};
  const text = result.content?.[0]?.text;
  if (typeof text !== 'string' || !text.trim()) throw new Error(`${name} returned no MCP tool payload`);
  let payload;
  try { payload = JSON.parse(text); } catch { throw new Error(`${name} returned invalid tool JSON`); }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload) || Object.keys(payload).length === 0) {
    throw new Error(`${name} returned an empty or invalid tool payload`);
  }
  if (result.isError || payload.ok === false || payload.available === false) {
    const code = payload.error?.code || payload.error_code || 'tool_unavailable';
    throw new Error(`${name} unavailable (${code})`);
  }
  return payload;
}

function validatePayload(name, payload) {
  const requireField = (valid, field) => {
    if (!valid) throw new Error(`${name} returned an invalid ${field} contract`);
  };
  if (name === 'marrow_status' || name === 'marrow_runtime_status') {
    requireField(
      typeof payload.status === 'string'
        || typeof payload.health === 'string'
        || typeof payload.active === 'boolean'
        || (payload.runtime && typeof payload.runtime === 'object'),
      'status',
    );
  } else if (name === 'marrow_orient') {
    requireField(Array.isArray(payload.warnings) && typeof payload.shouldPause === 'boolean', 'orientation');
  } else if (name === 'marrow_ask') {
    requireField(typeof payload.answer === 'string' && payload.answer.trim().length > 0, 'answer');
  } else if (name === 'marrow_agent_runtime') {
    requireField(
      payload.risk_gate
        && typeof payload.risk_gate === 'object'
        && typeof payload.risk_gate.allow === 'boolean'
        && typeof payload.risk_gate.decision === 'string'
        && payload.proof_pack
        && typeof payload.proof_pack.complete === 'boolean',
      'runtime gate',
    );
  } else if (name === 'marrow_first_value') {
    requireField(typeof payload.active === 'boolean' && typeof payload.headline === 'string', 'first-value');
  } else if (name === 'marrow_value_report') {
    requireField(
      payload.period
        && typeof payload.period.days === 'number'
        && payload.metrics
        && typeof payload.metrics.decisions?.total === 'number'
        && payload.fleet
        && typeof payload.fleet.active_agents === 'number',
      'value report',
    );
  }
}

function runCase(name, args) {
  const input = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
    { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name, arguments: args } },
  ].map((row) => JSON.stringify(row)).join('\n') + '\n';
  const started = Date.now();
  const child = spawnSync(process.execPath, [resolve(__dirname, '../dist/cli.js')], {
    env: {
      ...process.env,
      MARROW_API_KEY: key,
      MARROW_BASE_URL: process.env.MARROW_BASE_URL || 'https://api.getmarrow.ai',
      MARROW_AUTO_ENROLL: 'false',
      MARROW_TOOL_PROFILE: 'full',
      MARROW_CONTROL_PATH_CANARY: '1',
      MARROW_REQUEST_TIMEOUT_MS: String(transportTimeoutMs),
    },
    input,
    encoding: 'utf8',
    timeout: processTimeoutMs,
    maxBuffer: 256 * 1024,
  });
  const latencyMs = Date.now() - started;
  if (child.error) {
    const code = child.error.code === 'ETIMEDOUT' ? 'process_timeout' : 'process_error';
    throw new Error(`${name} ${code}`);
  }
  if (child.status !== 0) throw new Error(`${name} MCP child exited ${child.status ?? 'unknown'}`);
  const messages = String(child.stdout || '').trim().split('\n').filter(Boolean).map((line) => {
    try { return JSON.parse(line); } catch { throw new Error(`${name} emitted non-JSON stdout`); }
  });
  const initialized = messages.find((message) => message.id === 1);
  const listed = messages.find((message) => message.id === 2);
  const called = messages.find((message) => message.id === 3);
  const version = initialized?.result?.serverInfo?.version;
  if (!version) throw new Error(`${name} MCP initialize produced no version`);
  const names = new Set((listed?.result?.tools || []).map((tool) => tool.name));
  if (!names.has(name)) throw new Error(`${name} is missing from the full MCP contract`);
  const payload = toolPayload(called, name);
  validatePayload(name, payload);
  const live = payload.stale !== true && payload.source !== 'last_known' && payload.available !== false;
  if (!live) throw new Error(`${name} returned cached or unavailable guidance`);
  return { tool: name, ok: true, live: true, latency_ms: latencyMs, package_version: version };
}

try {
  const results = cases.map(([name, args]) => runCase(name, args));
  const versions = [...new Set(results.map((row) => row.package_version))];
  if (versions.length !== 1) throw new Error('MCP canary processes reported inconsistent package versions');
  if (versions[0] !== expectedVersion) {
    throw new Error(`MCP canary loaded ${versions[0]} instead of expected ${expectedVersion}`);
  }
  const core = results.filter((row) => Object.hasOwn(ceilings, row.tool));
  const slow = core.find((row) => row.latency_ms > ceilings[row.tool]);
  if (slow && process.env.MARROW_MCP_CANARY_ENFORCE_LATENCY !== '0') {
    throw new Error(`${slow.tool} exceeded its ${ceilings[slow.tool]}ms release ceiling`);
  }
  process.stdout.write(`${JSON.stringify({
    ok: true,
    package_version: versions[0],
    tools_checked: results.length,
    core_max_ms: Math.max(...core.map((row) => row.latency_ms)),
    latency_within_release_ceiling: !slow,
    results: results.map(({ package_version, ...row }) => row),
  })}\n`);
} catch (error) {
  process.stderr.write(`MCP_CONTROL_PATH_CANARY=FAIL ${error instanceof Error ? error.message : 'unknown_error'}\n`);
  process.exitCode = 1;
}
