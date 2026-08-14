#!/usr/bin/env node
const { spawn } = require('node:child_process');
const { performance } = require('node:perf_hooks');
const { resolve } = require('node:path');
const { version: packageVersion } = require('../package.json');

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

const HOT_PATH_TOOLS = new Set([
  'marrow_status',
  'marrow_runtime_status',
  'marrow_orient',
  'marrow_ask',
  'marrow_agent_runtime',
]);
const OUTPUT_LIMIT_BYTES = 256 * 1024;

function boundedMs(name, fallback, minimum = 100, maximum = 10_000, env = process.env) {
  const parsed = Number(env[name] || fallback);
  return Number.isFinite(parsed) ? Math.max(minimum, Math.min(maximum, Math.floor(parsed))) : fallback;
}

function percentile(values, quantile) {
  if (!values.length) return null;
  const ordered = [...values].sort((a, b) => a - b);
  return ordered[Math.max(0, Math.ceil(quantile * ordered.length) - 1)];
}

function latencyGroup(rows) {
  const values = rows.map((row) => row.latency_ms);
  return {
    count: values.length,
    p50_ms: percentile(values, 0.5),
    p95_ms: percentile(values, 0.95),
    p99_ms: percentile(values, 0.99),
    max_ms: values.length ? Math.max(...values) : null,
  };
}

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

class PersistentMcpClient {
  constructor(input) {
    this.command = input.command;
    this.args = input.args;
    this.env = input.env;
    this.timeoutMs = input.timeoutMs;
    this.spawnProcess = input.spawnProcess || spawn;
    this.maxOutputBytes = input.maxOutputBytes || OUTPUT_LIMIT_BYTES;
    this.nextId = 1;
    this.pending = new Map();
    this.stdoutBuffer = '';
    this.stderrBytes = 0;
    this.closed = false;
  }

  start() {
    if (this.child) return;
    this.child = this.spawnProcess(this.command, this.args, {
      env: this.env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.child.stdout.setEncoding('utf8');
    this.child.stdout.on('data', (chunk) => this.onStdout(chunk));
    this.child.stderr.on('data', (chunk) => {
      this.stderrBytes += Buffer.byteLength(chunk);
      if (this.stderrBytes > this.maxOutputBytes) this.abort(new Error('MCP child exceeded stderr limit'));
    });
    this.child.once('error', (error) => this.abort(new Error(`MCP child failed: ${error.code || 'process_error'}`)));
    this.child.once('exit', (code, signal) => {
      this.closed = true;
      if (this.pending.size > 0) this.rejectAll(new Error(`MCP child exited ${code ?? signal ?? 'unknown'}`));
    });
  }

  onStdout(chunk) {
    this.stdoutBuffer += chunk;
    if (Buffer.byteLength(this.stdoutBuffer) > this.maxOutputBytes) {
      this.abort(new Error('MCP child exceeded stdout limit'));
      return;
    }
    for (;;) {
      const newline = this.stdoutBuffer.indexOf('\n');
      if (newline < 0) break;
      const line = this.stdoutBuffer.slice(0, newline).trim();
      this.stdoutBuffer = this.stdoutBuffer.slice(newline + 1);
      if (!line) continue;
      let message;
      try { message = JSON.parse(line); } catch {
        this.abort(new Error('MCP child emitted malformed JSON'));
        return;
      }
      if (!Number.isSafeInteger(message.id)) continue;
      const pending = this.pending.get(message.id);
      if (!pending) {
        this.abort(new Error(`MCP child returned unexpected response id ${message.id}`));
        return;
      }
      clearTimeout(pending.timer);
      this.pending.delete(message.id);
      pending.resolve(message);
    }
  }

  request(method, params = {}, timeoutMs = this.timeoutMs) {
    if (!this.child || this.closed || !this.child.stdin.writable) {
      return Promise.reject(new Error('MCP child is not writable'));
    }
    const id = this.nextId++;
    return new Promise((resolveRequest, rejectRequest) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        const error = new Error(`${method} timed out`);
        rejectRequest(error);
        this.abort(error);
      }, timeoutMs);
      this.pending.set(id, { resolve: resolveRequest, reject: rejectRequest, timer });
      this.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`, (error) => {
        if (!error) return;
        clearTimeout(timer);
        this.pending.delete(id);
        rejectRequest(new Error(`${method} write failed`));
        this.abort(error);
      });
    });
  }

  rejectAll(error) {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
  }

  abort(error) {
    this.rejectAll(error instanceof Error ? error : new Error('MCP child aborted'));
    if (this.child && !this.closed) this.child.kill('SIGKILL');
  }

  async stop() {
    if (!this.child || this.closed) return;
    this.child.stdin.end();
    await new Promise((resolveExit) => {
      const timer = setTimeout(() => {
        if (!this.closed) this.child.kill('SIGKILL');
        resolveExit();
      }, 500);
      this.child.once('exit', () => {
        clearTimeout(timer);
        resolveExit();
      });
    });
  }
}

async function runCanary(env = process.env, options = {}) {
  const key = env.MARROW_API_KEY || '';
  if (!key) throw new Error('MARROW_API_KEY is required for the authenticated MCP control-path canary');
  const transportTimeoutMs = boundedMs('MARROW_REQUEST_TIMEOUT_MS', 2_500, 250, 10_000, env);
  const totalTimeoutMs = boundedMs('MARROW_MCP_CANARY_TOTAL_TIMEOUT_MS', 30_000, 2_000, 60_000, env);
  const expectedVersion = env.MARROW_EXPECTED_MCP_VERSION || packageVersion;
  const childPath = env.MARROW_MCP_CANARY_CHILD || resolve(__dirname, '../dist/cli.js');
  const childEnv = {
    ...env,
    MARROW_API_KEY: key,
    MARROW_BASE_URL: env.MARROW_BASE_URL || 'https://api.getmarrow.ai',
    MARROW_AUTO_ENROLL: 'false',
    MARROW_TOOL_PROFILE: 'full',
    MARROW_CONTROL_PATH_CANARY: '1',
    MARROW_REQUEST_TIMEOUT_MS: String(transportTimeoutMs),
  };
  delete childEnv.NODE_TEST_CONTEXT;
  const client = new PersistentMcpClient({
    command: process.execPath,
    args: [childPath],
    timeoutMs: transportTimeoutMs,
    env: childEnv,
    spawnProcess: options.spawnProcess,
  });
  const totalTimer = setTimeout(() => client.abort(new Error('MCP canary total timeout')), totalTimeoutMs);
  const processStarted = performance.now();
  client.start();
  try {
    const initialized = await client.request('initialize', {}, transportTimeoutMs + 3_000);
    if (initialized.error) throw new Error(`MCP initialize failed ${initialized.error.code}`);
    const version = initialized.result?.serverInfo?.version;
    if (!version) throw new Error('MCP initialize produced no version');
    if (version !== expectedVersion) throw new Error(`MCP canary loaded ${version} instead of expected ${expectedVersion}`);
    const listed = await client.request('tools/list', {});
    if (listed.error) throw new Error(`MCP tools/list failed ${listed.error.code}`);
    const names = new Set((listed.result?.tools || []).map((tool) => tool.name));
    for (const [name] of cases) {
      if (!names.has(name)) throw new Error(`${name} is missing from the full MCP contract`);
    }
    const initializationMs = Math.round(performance.now() - processStarted);
    const results = [];
    for (const [name, args] of cases) {
      const callStarted = performance.now();
      const called = await client.request('tools/call', { name, arguments: args });
      const latencyMs = Math.round(performance.now() - callStarted);
      const payload = toolPayload(called, name);
      validatePayload(name, payload);
      const live = payload.stale !== true && payload.source !== 'last_known' && payload.available !== false;
      if (!live) throw new Error(`${name} returned cached or unavailable guidance`);
      results.push({ tool: name, ok: true, live: true, latency_ms: latencyMs });
    }
    const hotPath = results.filter((row) => HOT_PATH_TOOLS.has(row.tool));
    const reports = results.filter((row) => !HOT_PATH_TOOLS.has(row.tool));
    return {
      ok: true,
      package_version: version,
      process_count: 1,
      initialization_ms: initializationMs,
      per_tool_latency_excludes_initialization: true,
      tools_checked: results.length,
      latency_groups: {
        hot_path: latencyGroup(hotPath),
        reports: latencyGroup(reports),
      },
      results,
    };
  } finally {
    clearTimeout(totalTimer);
    await client.stop();
  }
}

if (require.main === module) {
  runCanary().then((result) => {
    process.stdout.write(`${JSON.stringify(result)}\n`);
  }).catch((error) => {
    process.stderr.write(`MCP_CONTROL_PATH_CANARY=FAIL ${error instanceof Error ? error.message : 'unknown_error'}\n`);
    process.exitCode = 1;
  });
}

module.exports = { PersistentMcpClient, latencyGroup, percentile, runCanary };
