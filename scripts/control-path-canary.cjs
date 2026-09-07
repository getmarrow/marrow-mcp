#!/usr/bin/env node
const { spawn } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const { performance } = require('node:perf_hooks');
const { resolve } = require('node:path');
let packageVersion;
let MARROW_AUTO_RESPONSE_BUDGET_MAX_MS;
let configurationFailed = false;
try {
  ({ version: packageVersion } = require('../package.json'));
  ({ MARROW_AUTO_RESPONSE_BUDGET_MAX_MS } = require('../dist/index.js'));
} catch {
  // A missing/broken build must still reach the CLI's bounded failure handler.
  configurationFailed = true;
}

const CANARY_TOOL_TIMEOUT_MARGIN_MS = 2_000;
const CANARY_TOOL_TIMEOUT_MAX_MS = 10_000;
const CANARY_DEFAULT_TOOL_TIMEOUT_MS = Math.min(
  CANARY_TOOL_TIMEOUT_MAX_MS,
  (MARROW_AUTO_RESPONSE_BUDGET_MAX_MS || 8_000) + CANARY_TOOL_TIMEOUT_MARGIN_MS,
);

if (CANARY_DEFAULT_TOOL_TIMEOUT_MS < MARROW_AUTO_RESPONSE_BUDGET_MAX_MS + CANARY_TOOL_TIMEOUT_MARGIN_MS) {
  configurationFailed = true;
}

function canaryCases(operationId) {
  return [
  ['marrow_status', {}],
  ['marrow_runtime_status', { fast: true }],
  ['marrow_orient', { autoWarn: true }],
  ['marrow_ask', { query: 'What should this agent verify before a safe release?' }],
  ['marrow_agent_runtime', { action: 'Review a local documentation note', type: 'general', surfaces: ['workspace'] }],
  ['marrow_auto', {
    action: 'Record one bounded MCP control-path canary outcome',
    outcome: 'The MCP auto canary reached one committed outcome.',
    success: true,
    type: 'process',
    proof: { checks: ['mcp_auto_committed'] },
    operation_id: operationId,
  }],
  ['marrow_first_value', { action: 'Verify Marrow control-path availability', type: 'review', surfaces: ['api'] }],
  ['marrow_buyer_proof', { periodDays: 7 }],
  ['marrow_governance_control_plane', {}],
  ['marrow_value_report', { period: '7d' }],
  ['marrow_fleet_lessons', { query: 'safe release verification', limit: 3 }],
  ];
}

const HOT_PATH_TOOLS = new Set([
  'marrow_status',
  'marrow_runtime_status',
  'marrow_orient',
  'marrow_ask',
  'marrow_agent_runtime',
  'marrow_auto',
]);
const OUTPUT_LIMIT_BYTES = 256 * 1024;
const TOOL_NAMES = new Set(canaryCases('').map(([name]) => name));
const errorEvidence = new WeakMap();
const failureRecords = new WeakMap();

function canaryError(errorClass, message = errorClass, httpStatus) {
  const error = new Error(message);
  errorEvidence.set(error, { error_class: errorClass, http_status: httpStatus });
  return error;
}

function upstreamError(payload, fallback, message) {
  const statuses = [payload?.http_status, payload?.status, payload?.status_code,
    payload?.error?.http_status, payload?.error?.status, payload?.error?.status_code];
  const status = statuses.find((value) => Number.isInteger(value) && value >= 100 && value <= 599);
  const code = payload?.error?.code ?? payload?.error_code ?? payload?.code;
  let errorClass = fallback;
  if (status === 401 || ['UNAUTHORIZED', 'AUTH_REQUIRED', 'AUTHENTICATION_REQUIRED', 'INVALID_API_KEY', 'API_KEY_REQUIRED', 'unauthorized', 'invalid_api_key', 'authentication_required'].includes(code)) {
    errorClass = 'authentication';
  } else if (status === 403 || ['FORBIDDEN', 'PERMISSION_DENIED', 'INSUFFICIENT_PERMISSIONS', 'PLAN_REQUIRED', 'UPGRADE_REQUIRED', 'forbidden', 'permission_denied', 'plan_required'].includes(code)) {
    errorClass = 'authorization';
  } else if (status === 503 || code === 'HTTP_503' || code === 'http_503') {
    errorClass = 'unavailable503';
  }
  return canaryError(errorClass, message, status);
}

function safeVersion(value) {
  return typeof value === 'string' && value.length <= 64
    && /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(value) ? value : null;
}

function safeMs(value) {
  return Number.isFinite(value) ? Math.max(0, Math.min(60_000, Math.round(value))) : 0;
}

function failureRecord(error, context = {}) {
  const evidence = errorEvidence.get(error) || { error_class: 'internal' };
  const results = (context.results || []).slice(0, 11).map((row) => Object.freeze({
    tool: row.tool, ok: true, live: true, latency_ms: safeMs(row.latency_ms),
  }));
  return Object.freeze({
    schema_version: 1,
    ok: false,
    stage: context.stage || 'setup',
    tool: TOOL_NAMES.has(context.tool) ? context.tool : null,
    error_class: evidence.error_class,
    package_version: safeVersion(context.version),
    expected_version: safeVersion(context.expectedVersion),
    attempt: Math.max(0, Math.min(3, context.attempt || 0)),
    latency_ms: safeMs(performance.now() - (context.stageStarted ?? performance.now())),
    total_latency_ms: safeMs(performance.now() - (context.started ?? performance.now())),
    process_count: context.processCount === 1 ? 1 : 0,
    initialization_ms: context.initializationMs == null ? null : safeMs(context.initializationMs),
    tools_checked: results.length,
    results: Object.freeze(results),
    ...(evidence.http_status === undefined ? {} : { http_status: evidence.http_status }),
  });
}

function serializeFailure(error) {
  return JSON.stringify(failureRecords.get(error) || failureRecord(error));
}

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
  if (!message) throw canaryError('contract', 'Missing MCP tool response');
  if (message.error) throw upstreamError(message, 'protocol', 'MCP JSON-RPC error');
  const result = message.result || {};
  const text = result.content?.[0]?.text;
  if (typeof text !== 'string' || !text.trim()) throw canaryError('contract', 'Missing MCP tool payload');
  let payload;
  try { payload = JSON.parse(text); } catch { throw canaryError('contract', 'Invalid tool JSON'); }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload) || Object.keys(payload).length === 0) {
    throw canaryError('contract', 'Empty or invalid tool payload');
  }
  if (result.isError || payload.ok === false || payload.available === false) {
    throw upstreamError(payload, 'tool_unavailable', 'MCP tool unavailable');
  }
  return payload;
}

function validatePayload(name, payload) {
  const requireField = (valid, field) => {
    if (!valid) throw canaryError('contract', `${name} returned an invalid ${field} contract`);
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
  } else if (name === 'marrow_auto') {
    requireField(
      payload.live_delivery
        && payload.live_delivery.accepted === true
        && payload.live_delivery.committed === true
        && payload.completion_state === 'closed_with_proof'
        && payload.phase === 'closed'
        && payload.resumable === false
        && typeof payload.decision_id === 'string'
        && payload.decision_id.length > 0,
      'committed auto loop',
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
    try {
      this.child = this.spawnProcess(this.command, this.args, {
        env: this.env,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch { throw canaryError('process_spawn', 'MCP child spawn failed'); }
    this.child.stdout.setEncoding('utf8');
    this.child.stdout.on('data', (chunk) => this.onStdout(chunk));
    this.child.stderr.on('data', (chunk) => {
      this.stderrBytes += Buffer.byteLength(chunk);
      if (this.stderrBytes > this.maxOutputBytes) this.abort(canaryError('output_limit', 'MCP child exceeded stderr limit'));
    });
    this.child.stdin.on?.('error', () => this.abort(canaryError('process_write', 'MCP child write failed')));
    this.child.once('error', () => this.abort(canaryError('process_spawn', 'MCP child spawn failed')));
    this.child.once('exit', (code, signal) => {
      this.closed = true;
      if (this.stopping && code === 0 && !signal && this.pending.size === 0 && !this.fatalError) return;
      this.fatalError ||= canaryError('process_exit', 'MCP child exited');
      this.rejectAll(this.fatalError);
    });
  }

  onStdout(chunk) {
    this.stdoutBuffer += chunk;
    if (Buffer.byteLength(this.stdoutBuffer) > this.maxOutputBytes) {
      this.abort(canaryError('output_limit', 'MCP child exceeded stdout limit'));
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
        this.abort(canaryError('protocol', 'MCP child emitted malformed JSON'));
        return;
      }
      if (!message || typeof message !== 'object' || Array.isArray(message) || message.jsonrpc !== '2.0'
        || (message.id !== undefined && (!Number.isSafeInteger(message.id)
          || (Object.hasOwn(message, 'result') === Object.hasOwn(message, 'error'))))) {
        this.abort(canaryError('protocol', 'MCP child emitted malformed JSON-RPC'));
        return;
      }
      if (!Number.isSafeInteger(message.id)) continue;
      const pending = this.pending.get(message.id);
      if (!pending) {
        this.abort(canaryError('protocol', 'MCP child returned unexpected response id'));
        return;
      }
      clearTimeout(pending.timer);
      this.pending.delete(message.id);
      pending.resolve(message);
    }
  }

  request(method, params = {}, timeoutMs = this.timeoutMs) {
    if (this.fatalError) return Promise.reject(this.fatalError);
    if (!this.child || this.closed || !this.child.stdin.writable) {
      return Promise.reject(canaryError('process_write', 'MCP child is not writable'));
    }
    const id = this.nextId++;
    return new Promise((resolveRequest, rejectRequest) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        const error = canaryError('request_timeout', `${method} timed out`);
        rejectRequest(error);
        this.abort(error);
      }, timeoutMs);
      this.pending.set(id, { resolve: resolveRequest, reject: rejectRequest, timer });
      const onWrite = (error) => {
        if (!error) return;
        clearTimeout(timer);
        this.pending.delete(id);
        const failure = canaryError('process_write', `${method} write failed`);
        rejectRequest(failure);
        this.abort(failure);
      };
      try {
        this.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`, onWrite);
      } catch (error) { onWrite(error); }
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
    this.fatalError ||= error instanceof Error ? error : canaryError('internal');
    this.rejectAll(this.fatalError);
    if (this.child && !this.closed) {
      try { this.child.kill('SIGKILL'); } catch { /* Preserve the original failure. */ }
    }
  }

  async stop() {
    if (!this.child || this.closed) {
      if (this.fatalError) throw this.fatalError;
      return;
    }
    this.stopping = true;
    this.child.stdin.end();
    await new Promise((resolveExit) => {
      const timer = setTimeout(() => {
        if (!this.closed) {
          this.abort(canaryError('process_exit', 'MCP child did not exit during shutdown'));
        }
        resolveExit();
      }, 500);
      this.child.once('exit', () => {
        clearTimeout(timer);
        resolveExit();
      });
    });
    if (this.fatalError) throw this.fatalError;
  }
}

async function runCanary(env = process.env, options = {}) {
  const started = performance.now();
  const context = { started, stageStarted: started, stage: 'setup', results: [],
    expectedVersion: env.MARROW_EXPECTED_MCP_VERSION || packageVersion };
  try {
    return await executeCanary(env, options, context);
  } catch (caught) {
    const error = errorEvidence.has(caught) ? caught : canaryError('internal');
    error.failure = failureRecord(error, context);
    failureRecords.set(error, error.failure);
    throw error;
  }
}

async function executeCanary(env, options, context) {
  if (configurationFailed) throw canaryError('configuration', 'MCP canary build configuration failed');
  const key = env.MARROW_API_KEY || '';
  if (!key) throw canaryError('authentication', 'MARROW_API_KEY is required for the authenticated MCP control-path canary');
  const toolTimeoutMs = boundedMs(
    'MARROW_MCP_CANARY_TOOL_TIMEOUT_MS',
    CANARY_DEFAULT_TOOL_TIMEOUT_MS,
    250,
    CANARY_TOOL_TIMEOUT_MAX_MS,
    env,
  );
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
  };
  // A default canary must exercise the same client deadlines customers receive.
  // Only preserve MARROW_REQUEST_TIMEOUT_MS when the caller explicitly supplied it.
  if (env.MARROW_REQUEST_TIMEOUT_MS) childEnv.MARROW_REQUEST_TIMEOUT_MS = env.MARROW_REQUEST_TIMEOUT_MS;
  else delete childEnv.MARROW_REQUEST_TIMEOUT_MS;
  delete childEnv.NODE_TEST_CONTEXT;
  const client = new PersistentMcpClient({
    command: process.execPath,
    args: [childPath],
    timeoutMs: toolTimeoutMs,
    env: childEnv,
    spawnProcess: options.spawnProcess,
  });
  const totalTimer = setTimeout(() => client.abort(canaryError('total_timeout', 'MCP canary total timeout')), totalTimeoutMs);
  const processStarted = performance.now();
  const cases = canaryCases(`canary_${randomUUID()}`);
  const stage = (value, tool = null, attempt = 0) => {
    Object.assign(context, { stage: value, tool, attempt, stageStarted: performance.now() });
  };
  let failed = false;
  try {
    stage('spawn');
    client.start();
    context.processCount = 1;
    stage('initialize', null, 1);
    const initialized = await client.request('initialize', {}, toolTimeoutMs + 3_000);
    if (client.fatalError) throw client.fatalError;
    if (initialized.error) throw upstreamError(initialized, 'protocol', 'MCP initialize failed');
    const version = initialized.result?.serverInfo?.version;
    context.version = version;
    if (typeof version !== 'string' || !version) throw canaryError('contract', 'MCP initialize produced no version');
    if (version !== expectedVersion) throw canaryError('package_mismatch', 'MCP canary package version mismatch');
    stage('tools_list', null, 1);
    const listed = await client.request('tools/list', {});
    if (client.fatalError) throw client.fatalError;
    if (listed.error) throw upstreamError(listed, 'protocol', 'MCP tools/list failed');
    if (!Array.isArray(listed.result?.tools)) throw canaryError('contract', 'MCP tools/list missing tools');
    const names = new Set(listed.result.tools.map((tool) => tool?.name));
    for (const [name] of cases) {
      if (!names.has(name)) throw canaryError('contract', `${name} is missing from the full MCP contract`);
    }
    const initializationMs = Math.round(performance.now() - processStarted);
    context.initializationMs = initializationMs;
    const results = context.results;
    for (const [name, args] of cases) {
      const callStarted = performance.now();
      let called;
      let payload;
      for (let attempt = 0; attempt < 3; attempt += 1) {
        if (client.fatalError) throw client.fatalError;
        stage('tool_call', name, attempt + 1);
        called = await client.request('tools/call', { name, arguments: args });
        if (client.fatalError) throw client.fatalError;
        stage('tool_validate', name, attempt + 1);
        payload = toolPayload(called, name);
        if (name !== 'marrow_auto' || payload.live_delivery?.committed === true || payload.resumable !== true) break;
        if (attempt < 2) {
          const retryAfterMs = Number(payload.retry_after_ms);
          const delayMs = Number.isFinite(retryAfterMs) ? Math.max(0, Math.min(1_000, retryAfterMs)) : 250;
          await new Promise((resolveDelay) => setTimeout(resolveDelay, delayMs));
        }
      }
      const latencyMs = Math.round(performance.now() - callStarted);
      validatePayload(name, payload);
      const live = payload.stale !== true && payload.source !== 'last_known' && payload.available !== false;
      if (!live) throw canaryError('contract', `${name} returned cached or unavailable guidance`);
      results.push({ tool: name, ok: true, live: true, latency_ms: latencyMs });
    }
    const hotPath = results.filter((row) => HOT_PATH_TOOLS.has(row.tool));
    const reports = results.filter((row) => !HOT_PATH_TOOLS.has(row.tool));
    stage('shutdown');
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
  } catch (error) {
    failed = true;
    throw error;
  } finally {
    clearTimeout(totalTimer);
    try { await client.stop(); } catch (error) {
      if (!failed) throw errorEvidence.has(error) ? error : canaryError('process_write', 'MCP child shutdown failed');
    }
  }
}

if (require.main === module) {
  runCanary().then((result) => {
    process.stdout.write(`${JSON.stringify(result)}\n`);
  }).catch((error) => {
    process.stdout.write(`${serializeFailure(error)}\n`);
    process.stderr.write('MCP_CONTROL_PATH_CANARY=FAIL\n');
    process.exitCode = 1;
  });
}

module.exports = {
  CANARY_DEFAULT_TOOL_TIMEOUT_MS,
  CANARY_TOOL_TIMEOUT_MARGIN_MS,
  MARROW_AUTO_RESPONSE_BUDGET_MAX_MS,
  PersistentMcpClient,
  latencyGroup,
  percentile,
  runCanary,
  serializeFailure,
};
