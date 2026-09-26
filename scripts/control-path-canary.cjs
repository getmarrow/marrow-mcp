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
const CANARY_ASYNC_TOOL_TIMEOUT_MAX_MS = 30_000;
const CANARY_DEFAULT_TOOL_TIMEOUT_MS = Math.min(
  CANARY_TOOL_TIMEOUT_MAX_MS,
  (MARROW_AUTO_RESPONSE_BUDGET_MAX_MS || 8_000) + CANARY_TOOL_TIMEOUT_MARGIN_MS,
);
const CANARY_DEFAULT_ASYNC_TOOL_TIMEOUT_MS = Math.min(
  CANARY_ASYNC_TOOL_TIMEOUT_MAX_MS,
  (MARROW_AUTO_RESPONSE_BUDGET_MAX_MS || 8_000) + CANARY_TOOL_TIMEOUT_MARGIN_MS,
);
const CANARY_DEFAULT_TOTAL_TIMEOUT_MS = 45_000;
const TRANSPORT_RETRY_WAIT_MS = 1_000;

if (CANARY_DEFAULT_TOOL_TIMEOUT_MS < MARROW_AUTO_RESPONSE_BUDGET_MAX_MS + CANARY_TOOL_TIMEOUT_MARGIN_MS) {
  configurationFailed = true;
}
if (CANARY_DEFAULT_ASYNC_TOOL_TIMEOUT_MS < MARROW_AUTO_RESPONSE_BUDGET_MAX_MS + CANARY_TOOL_TIMEOUT_MARGIN_MS) {
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
const ASYNC_PATH_TOOLS = new Set([
  'marrow_auto',
  'marrow_first_value',
]);
const TRANSPORT_RETRY_ERROR_CLASSES = new Set(['tool_unavailable', 'unavailable503']);
const AUTO_TRANSPORT_RETRY_CATEGORIES = new Set([
  'request_failed', 'service_unavailable', 'connection_reset', 'dns_unavailable',
  'tls_failure', 'edge_access_denied', 'rate_limited',
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
  const error = canaryError(errorClass, message, status);
  Object.assign(errorEvidence.get(error), safeBackendDiagnostics(payload));
  return error;
}

const BACKEND_CODES = new Set([
  'request_failed', 'request_timeout', 'MARROW_PLAN_UPGRADE_REQUIRED', 'MARROW_PRE_ACTION_GATE_SCOPE_MISMATCH',
  'MARROW_ARBITRATION_SCOPE_MISMATCH', 'MARROW_TENANT_ADMISSION_REJECTED', 'MARROW_RATE_LIMITED',
  'MARROW_REQUEST_TIMEOUT', 'MARROW_RUNTIME_UNAVAILABLE', 'AUTH_STORE_TIMEOUT', 'UNAUTHORIZED', 'FORBIDDEN',
  'MARROW_RUNTIME_CONTINUATION_UNAVAILABLE', 'MARROW_RUNTIME_STATUS_UNAVAILABLE', 'MARROW_PROOF_PACK_INCOMPLETE',
]);

function safeBackendIdentity(payload) {
  const value = payload?.backend_identity;
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const identity = {};
  if (typeof value.release_ref === 'string' && /^[a-f0-9]{40}$/.test(value.release_ref)) identity.release_ref = value.release_ref;
  if (typeof value.worker_version_id === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value.worker_version_id)) {
    identity.worker_version_id = value.worker_version_id;
  }
  return Object.keys(identity).length ? { backend_identity: identity } : {};
}

function safeBackendDiagnostics(payload) {
  const result = safeBackendIdentity(payload);
  for (const value of [payload, payload?.error, payload?.details]) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) continue;
    if (BACKEND_CODES.has(value.code) || AUTO_HTTP_ERROR_CATEGORIES.has(value.code)) result.backend_code = value.code;
    if (AUTO_HTTP_ERROR_CATEGORIES.has(value.category)
      || ['authorization', 'authentication', 'timeout', 'rate_limit', 'validation', 'server_error', 'network'].includes(value.category)) {
      result.backend_category = value.category;
    }
  }
  return result;
}

function safeVersion(value) {
  return typeof value === 'string' && value.length <= 64
    && /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(value) ? value : null;
}

function safeMs(value) {
  return Number.isFinite(value) ? Math.max(0, Math.min(60_000, Math.round(value))) : 0;
}

function autoTimings(payload) {
  const result = {};
  for (const [group, fields] of [
    ['phase_timings_ms', ['runtime', 'think', 'commit', 'total']],
    ['response_timings_ms', ['core', 'durable_enqueue', 'full_response']],
  ]) {
    const source = payload?.[group];
    if (!source || typeof source !== 'object' || Array.isArray(source)) continue;
    const values = {};
    for (const field of fields) {
      const value = source[field];
      if (typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 60000) {
        values[field] = Math.round(value);
      }
    }
    if (Object.keys(values).length) result[group] = values;
  }
  return result;
}

const AUTO_HTTP_ERROR_CATEGORIES = new Set([
  'authentication_required', 'permission_denied', 'proof_required', 'rate_limited',
  'request_timeout', 'dns_unavailable', 'connection_reset', 'tls_failure',
  'edge_access_denied', 'service_unavailable', 'invalid_response', 'request_failed',
]);
const AUTO_TRACE_CODES = new Set([
  'runtime_pending', 'think_pending', 'commit_pending', 'pending', 'created',
  'committed', 'closed', 'replayed', 'idempotent_replay', 'lost_ack_recovered',
  'duplicate', 'original', 'new',
]);

function safeAutoHttpTrace(payload) {
  const source = payload?.http_attempt_trace;
  if (!source || typeof source !== 'object' || Array.isArray(source)) {
    return { attempts: [], dropped_count: 0 };
  }
  const attempts = [];
  let rejected = Array.isArray(source.attempts) ? Math.max(0, source.attempts.length - 12) : 0;
  for (const value of Array.isArray(source.attempts) ? source.attempts.slice(0, 12) : []) {
    if (!value || typeof value !== 'object' || Array.isArray(value)
      || !['think', 'commit'].includes(value.route_phase)) {
      rejected += 1;
      continue;
    }
    const serverTimings = {};
    const spans = value.server_timings_ms;
    if (spans && typeof spans === 'object' && !Array.isArray(spans)) {
      for (const name of ['auth_ms', 'parse_ms']) {
        const duration = spans[name];
        if (typeof duration === 'number' && Number.isFinite(duration) && duration >= 0 && duration <= 60_000) {
          serverTimings[name] = Math.round(duration);
        }
      }
    }
    const status = Number.isInteger(value.status) && value.status >= 100 && value.status <= 599
      ? value.status : null;
    const errorCategory = AUTO_HTTP_ERROR_CATEGORIES.has(value.error_category)
      ? value.error_category : null;
    attempts.push({
      route_phase: value.route_phase,
      duration_ms: safeMs(value.duration_ms),
      status,
      error_category: errorCategory,
      typed_timeout: errorCategory === 'request_timeout' && value.typed_timeout === true,
      pending_code: AUTO_TRACE_CODES.has(value.pending_code) ? value.pending_code : null,
      replay_code: AUTO_TRACE_CODES.has(value.replay_code) ? value.replay_code : null,
      server_timings_ms: serverTimings,
      server_timing_coverage: Object.keys(serverTimings).length ? 'partial' : 'unavailable',
      requested_wait_ms: value.requested_wait_ms == null ? null : safeMs(value.requested_wait_ms),
      actual_wait_ms: safeMs(value.actual_wait_ms),
    });
  }
  const reportedDropped = Number.isInteger(source.dropped_count) && source.dropped_count >= 0
    ? Math.min(999, source.dropped_count) : 0;
  return { attempts, dropped_count: Math.min(999, reportedDropped + rejected) };
}

function autoOuterAttempt(payload, attempt, durationMs) {
  const phase = ['runtime_pending', 'think_pending', 'decision_created', 'proof_required',
    'review_required', 'owner_approval_required', 'commit_pending', 'closed'].includes(payload?.phase)
    ? payload.phase : null;
  const deliveryFailure = payload?.live_delivery?.failure?.error;
  const errorCategory = AUTO_HTTP_ERROR_CATEGORIES.has(deliveryFailure?.category)
    ? deliveryFailure.category : null;
  return {
    attempt,
    duration_ms: safeMs(durationMs),
    phase,
    status: errorCategory ? 'failed' : payload?.live_delivery?.committed === true
      ? 'committed' : payload?.live_delivery?.accepted === true ? 'pending' : 'unconfirmed',
    error_category: errorCategory,
    ...autoTimings(payload),
    http_attempt_trace: safeAutoHttpTrace(payload),
    requested_wait_ms: payload?.retry_after_ms == null ? null : safeMs(payload.retry_after_ms),
    actual_wait_ms: 0,
  };
}

function safeAutoOuterAttempts(source) {
  if (!Array.isArray(source)) return [];
  return source.slice(0, 3).map((record, index) => ({
    attempt: index + 1,
    duration_ms: safeMs(record?.duration_ms),
    phase: ['runtime_pending', 'think_pending', 'decision_created', 'proof_required',
      'review_required', 'owner_approval_required', 'commit_pending', 'closed'].includes(record?.phase)
      ? record.phase : null,
    status: ['committed', 'pending', 'failed', 'unconfirmed'].includes(record?.status)
      ? record.status : 'unconfirmed',
    error_category: AUTO_HTTP_ERROR_CATEGORIES.has(record?.error_category)
      ? record.error_category : null,
    ...autoTimings(record),
    http_attempt_trace: safeAutoHttpTrace({ http_attempt_trace: record?.http_attempt_trace }),
    requested_wait_ms: record?.requested_wait_ms == null ? null : safeMs(record.requested_wait_ms),
    actual_wait_ms: safeMs(record?.actual_wait_ms),
  }));
}

function autoWaitClass(payload) {
  if (payload?.live_delivery?.committed !== false
    || typeof payload.live_delivery.accepted !== 'boolean'
    || typeof payload.resumable !== 'boolean') return null;
  if (['runtime_pending', 'think_pending', 'commit_pending'].includes(payload.phase)
    && payload.completion_state === 'delivery_pending' && payload.resumable === true) return 'completion_pending';
  if ((payload.phase === 'owner_approval_required' && payload.completion_state === 'pending_owner_approval'
    || payload.phase === 'review_required' && payload.completion_state === 'review_required_terminal')
    && payload.resumable === false) return 'approval_required';
  if (payload.phase === 'proof_required' && payload.completion_state === 'pending_required_proof') return 'proof_required';
  return null;
}

function failureRecord(error, context = {}) {
  const evidence = errorEvidence.get(error) || { error_class: 'internal' };
  const results = (context.results || []).slice(0, 11).map((row) => Object.freeze({
    tool: row.tool, ok: true, live: true, latency_ms: safeMs(row.latency_ms),
    ...(row.tool === 'marrow_auto' ? {
      ...autoTimings(row), attempts: row.attempts, retry_wait_ms: safeMs(row.retry_wait_ms),
      auto_attempt_records: safeAutoOuterAttempts(row.auto_attempt_records),
    } : {}),
    ...(row.outcome_closeout ? { outcome_eligible: row.outcome_eligible, outcome_closeout: row.outcome_closeout } : {}),
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
    stage_latency_ms: safeMs(performance.now() - (context.stageStarted ?? performance.now())),
    tool_operation_latency_ms: safeMs(performance.now() - (context.toolStarted ?? context.stageStarted ?? performance.now())),
    total_latency_ms: safeMs(performance.now() - (context.started ?? performance.now())),
    process_count: context.processCount === 1 ? 1 : 0,
    initialization_ms: context.initializationMs == null ? null : safeMs(context.initializationMs),
    tools_checked: results.length,
    results: Object.freeze(results),
    ...(context.tool === 'marrow_auto' ? {
      ...autoTimings(context.autoMetrics), retry_wait_ms: safeMs(context.retryWaitMs),
      auto_attempt_records: safeAutoOuterAttempts(context.autoAttempts),
      ...(context.autoPhase ? { auto_phase: context.autoPhase } : {}),
    } : {}),
    ...(evidence.http_status === undefined ? {} : { http_status: evidence.http_status }),
    ...safeBackendDiagnostics({ code: evidence.backend_code, category: evidence.backend_category,
      backend_identity: evidence.backend_identity }),
  });
}

async function closeFixtureOutcome(name, payload, env, options) {
  if (name === 'marrow_auto') return { outcome_eligible: true, outcome_closeout: 'closed',
    completion_state: payload.completion_state, phase: payload.phase, resumable: payload.resumable };
  if (!['marrow_agent_runtime', 'marrow_first_value'].includes(name)) return {};
  const runtime = name === 'marrow_first_value' ? payload.runtime : payload;
  const decisionId = runtime?.decision_id || runtime?.runtime_authorization?.decision_id
    || runtime?.completion_contract?.decision_id;
  if (decisionId == null) return { outcome_eligible: false, outcome_closeout: 'not_required' };
  if (typeof decisionId !== 'string' || !decisionId.trim()) throw canaryError('contract', 'Invalid fixture decision identity');
  const commit = options.commitFixture || require('../dist/index.js').marrowCommit;
  let result;
  try {
    result = await commit(env.MARROW_API_KEY, env.MARROW_BASE_URL || 'https://api.getmarrow.ai', {
      decision_id: decisionId,
      success: true,
      outcome: `The MCP canary received and validated the ${name} fixture response.`,
      proof: { checks: ['mcp_canary_contract_validated'] },
      ...(runtime?.gate_receipt?.id || runtime?.risk_gate?.gate_receipt_id ? {
        gate_receipt_id: runtime.gate_receipt?.id || runtime.risk_gate.gate_receipt_id,
      } : {}),
    }, runtime?.session_id || env.MARROW_SESSION_ID, runtime?.agent_id || env.MARROW_FLEET_AGENT_ID);
  } catch (error) {
    const { structuredRequestFailure } = require('../dist/request-reliability.js');
    throw upstreamError(structuredRequestFailure(error), 'tool_unavailable', 'Fixture outcome closeout failed');
  }
  if (result?.committed !== true) throw canaryError('completion_pending', 'Fixture outcome remains open');
  return { outcome_eligible: true, outcome_closeout: 'closed' };
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
    const failure = payload.live_delivery?.failure;
    if (failure) {
      requireField(payload.live_delivery.committed === false && payload.phase == null
        && failure.ok === false, 'failed auto delivery');
      // Transport/auth status takes precedence over a caller-facing proof label.
      const category = failure.error?.category;
      const categories = {
        authentication_required: 'authentication', permission_denied: 'authorization',
        proof_required: 'proof_required', request_timeout: 'request_timeout',
        dns_unavailable: 'tool_unavailable', connection_reset: 'tool_unavailable',
        tls_failure: 'tool_unavailable', edge_access_denied: 'tool_unavailable',
        service_unavailable: 'tool_unavailable', rate_limited: 'tool_unavailable',
        request_failed: 'tool_unavailable', invalid_response: 'contract',
      };
      const classification = typeof category === 'string' && Object.hasOwn(categories, category)
        ? categories[category] : 'contract';
      throw upstreamError(failure, classification, 'Auto delivery failed');
    }
    const waitClass = autoWaitClass(payload);
    if (waitClass) throw canaryError(waitClass, 'Auto completion is awaiting its declared next step');
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
      const expectedExit = (code === 0 && !signal)
        || (this.cleanupKillRequested && code === null && signal === 'SIGKILL');
      if (this.stopping && expectedExit && this.pending.size === 0 && !this.fatalError) return;
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
          // The bounded cleanup deadline intentionally ends an otherwise healthy
          // child. This signal is ours; actual protocol/write errors remain fatal.
          this.cleanupKillRequested = true;
          try { this.child.kill('SIGKILL'); } catch { this.cleanupKillRequested = false; }
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
  const asyncToolTimeoutMs = boundedMs(
    'MARROW_MCP_CANARY_ASYNC_TOOL_TIMEOUT_MS',
    CANARY_DEFAULT_ASYNC_TOOL_TIMEOUT_MS,
    250,
    CANARY_ASYNC_TOOL_TIMEOUT_MAX_MS,
    env,
  );
  const totalTimeoutMs = boundedMs('MARROW_MCP_CANARY_TOTAL_TIMEOUT_MS', CANARY_DEFAULT_TOTAL_TIMEOUT_MS, 2_000, 60_000, env);
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
      context.toolStarted = callStarted;
      const perToolTimeoutMs = ASYNC_PATH_TOOLS.has(name) ? asyncToolTimeoutMs : toolTimeoutMs;
      let called;
      let payload;
      let attempts = 0;
      let recoveredOnRetry = false;
      context.retryWaitMs = 0;
      context.autoMetrics = undefined;
      context.autoPhase = undefined;
      context.autoAttempts = undefined;
      const autoAttemptRecords = [];
      if (name === 'marrow_auto') context.autoAttempts = autoAttemptRecords;
      for (let attempt = 0; attempt < 3; attempt += 1) {
        const outerAttemptStarted = performance.now();
        if (client.fatalError) throw client.fatalError;
        stage('tool_call', name, attempt + 1);
        attempts += 1;
        try {
          called = await client.request('tools/call', { name, arguments: args }, perToolTimeoutMs);
          if (client.fatalError) throw client.fatalError;
          stage('tool_validate', name, attempt + 1);
          payload = toolPayload(called, name);
        } catch (error) {
          const evidence = errorEvidence.get(error);
          if (name === 'marrow_auto') {
            autoAttemptRecords.push({
              attempt: attempt + 1,
              duration_ms: safeMs(performance.now() - outerAttemptStarted),
              phase: null,
              status: 'failed',
              error_category: evidence?.error_class === 'request_timeout' ? 'request_timeout' : null,
              http_attempt_trace: { attempts: [], dropped_count: 0 },
              requested_wait_ms: null,
              actual_wait_ms: 0,
            });
          }
          // One bounded in-run retry for transport-class failures: a single edge
          // reset or 503 must not fail the canary when the very next call succeeds.
          const remaining = totalTimeoutMs - (performance.now() - context.started);
          const mayRetry = name === 'marrow_auto' ? attempt < 2 : attempt < 1;
          if (evidence && TRANSPORT_RETRY_ERROR_CLASSES.has(evidence.error_class)
            && mayRetry && remaining > TRANSPORT_RETRY_WAIT_MS + 250) {
            await new Promise((resolveDelay) => setTimeout(resolveDelay, TRANSPORT_RETRY_WAIT_MS));
            context.retryWaitMs += TRANSPORT_RETRY_WAIT_MS;
            recoveredOnRetry = true;
            continue;
          }
          throw error;
        }
        if (name !== 'marrow_auto') break;
        const outerAttemptRecord = autoOuterAttempt(
          payload,
          attempt + 1,
          performance.now() - outerAttemptStarted,
        );
        autoAttemptRecords.push(outerAttemptRecord);
        context.autoMetrics = autoTimings(payload);
        const waitClass = autoWaitClass(payload);
        context.autoPhase = waitClass ? payload.phase : undefined;
        const autoFailureCategory = payload?.live_delivery?.failure?.error?.category;
        const transportRetryable = waitClass == null
          && AUTO_TRANSPORT_RETRY_CATEGORIES.has(autoFailureCategory);
        if (waitClass !== 'completion_pending' && !transportRetryable) break;
        if (attempt < 2) {
          const requested = payload.retry_after_ms;
          const serverWaitMs = typeof requested === 'number' && Number.isFinite(requested) && requested >= 0
            ? Math.ceil(requested) : null;
          const delayMs = transportRetryable
            ? Math.max(TRANSPORT_RETRY_WAIT_MS, serverWaitMs ?? 0)
            : serverWaitMs ?? 250;
          const remaining = totalTimeoutMs - (performance.now() - context.started);
          if (delayMs >= remaining) break;
          const waitStarted = performance.now();
          await new Promise((resolveDelay) => setTimeout(resolveDelay, delayMs));
          const actualWaitMs = Math.round(performance.now() - waitStarted);
          outerAttemptRecord.actual_wait_ms = actualWaitMs;
          context.retryWaitMs += actualWaitMs;
          if (transportRetryable) recoveredOnRetry = true;
        }
      }
      const latencyMs = Math.round(performance.now() - callStarted);
      validatePayload(name, payload);
      const live = payload.stale !== true && payload.source !== 'last_known' && payload.available !== false;
      if (!live) throw canaryError('contract', `${name} returned cached or unavailable guidance`);
      stage('outcome_closeout', name, attempts);
      const outcome = await closeFixtureOutcome(name, payload, childEnv, options);
      results.push({ tool: name, ok: true, live: true, latency_ms: latencyMs,
        tool_operation_latency_ms: safeMs(performance.now() - callStarted),
        ...outcome,
        ...safeBackendIdentity(payload),
        ...(recoveredOnRetry ? { recovered_on_retry: true } : {}),
        ...(name === 'marrow_auto' ? {
          ...autoTimings(payload),
          attempts,
          retry_wait_ms: context.retryWaitMs,
          auto_attempt_records: safeAutoOuterAttempts(autoAttemptRecords),
        } : {}),
      });
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
      all_outcome_eligible_writes_closed: results.every((row) => row.outcome_eligible !== true || row.outcome_closeout === 'closed'),
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
  CANARY_DEFAULT_ASYNC_TOOL_TIMEOUT_MS,
  CANARY_DEFAULT_TOTAL_TIMEOUT_MS,
  CANARY_TOOL_TIMEOUT_MARGIN_MS,
  CANARY_ASYNC_TOOL_TIMEOUT_MAX_MS,
  MARROW_AUTO_RESPONSE_BUDGET_MAX_MS,
  PersistentMcpClient,
  latencyGroup,
  percentile,
  runCanary,
  serializeFailure,
};
