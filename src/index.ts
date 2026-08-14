/**
 * @getmarrow/mcp — API Functions
 */

import { randomUUID } from 'node:crypto';

import type {
  ThinkResult,
  CommitResult,
  StatusResult,
  AgentPatternsResult,
  OrientResult,
  MarrowAskResult,
  WorkflowResult,
  MarrowDashboardResult,
  MarrowDecisionBriefRequest,
  MarrowDecisionBriefResult,
  MarrowAgentRuntimeRequest,
  MarrowAgentRuntimeResult,
  MarrowArbitrationRequest,
  MarrowFirstValueRequest,
  MarrowFirstValueResult,
  MarrowWorkflowGateRequest,
  MarrowWorkflowGateResult,
  MarrowDigestResult,
  MarrowAgentStatusResult,
  MarrowValueReportResult,
  MarrowModelUsageInput,
  MarrowModelUsageResult,
  MarrowNudgeResult,
  MarrowEnforcementRequest,
  MarrowEnforcementResult,
} from './types';
import {
  MarrowClient,
  type CreateApiKeyParams,
  type CreateApiKeyResult,
  type GetKeyAuditParams,
  type GetKeyAuditResult,
  type ListApiKeysResult,
  type MarrowApiKey,
  type RevokeApiKeyResult,
  type RotateApiKeyResult,
} from '@getmarrow/sdk';
import { redactSensitiveText, redactSensitiveValue } from './redact';
import { recordLifecycleEvent, type LifecycleEvent } from './lifecycle-spool';
import { MCP_ADAPTER_VERSION } from './hook-contract';
import { reliableFetch, requestErrorFromResponse } from './request-reliability';

const fetch = reliableFetch;

export type { Narrative, CommitResult } from './types';

const SOURCE_CLIENTS = new Set(['claude-code', 'cursor', 'windsurf', 'openclaw', 'codex', 'gemini', 'grok', 'deepseek', 'qwen', 'kimi', 'minimax', 'cline', 'opencode', 'hermes', 'glm', 'custom', 'unknown']);

const SAFE_ARBITRATION_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/;
const SAFE_ARBITRATION_EVIDENCE_KIND = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,39}$/;
const SAFE_ARBITRATION_EVIDENCE_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/;
const SECRETISH_ARBITRATION_REFERENCE =
  /(?:^|[._:-])(?:secret|token|password|credential|api[_-]?key|authorization|bearer)(?:$|[._:-])|^(?:sk|pk|ghp|github_pat|npm|cfut|mrw)_[A-Za-z0-9_-]+$/i;

function preserveOpaqueArbitrationValue(
  value: string,
  pattern: RegExp,
  field: string
): string {
  if (value !== value.trim()
    || !pattern.test(value)
    || SECRETISH_ARBITRATION_REFERENCE.test(value)) {
    throw new TypeError(`Agent arbitration ${field} must be a safe opaque identifier.`);
  }
  return value;
}

function defaultSourceClient(): string {
  const raw = String(process.env.MARROW_CLIENT || process.env.MARROW_HARNESS || process.env.MARROW_AGENT_CLIENT || '').trim().toLowerCase().replace(/\s+/g, '-').replace(/^@/, '');
  const aliases: Record<string, string> = {
    claude: 'claude-code',
    claude_code: 'claude-code',
    'claude-code': 'claude-code',
    cursor: 'cursor',
    windsurf: 'windsurf',
    openclaw: 'openclaw',
    codex: 'codex',
    'openai-codex': 'codex',
    gemini: 'gemini',
    google: 'gemini',
    grok: 'grok',
    deepseek: 'deepseek',
    qwen: 'qwen',
    kimi: 'kimi',
    minimax: 'minimax',
    cline: 'cline',
    opencode: 'opencode',
    'open-code': 'opencode',
    hermes: 'hermes',
    'hermes-agent': 'hermes',
    glm: 'glm',
  };
  return aliases[raw] || (SOURCE_CLIENTS.has(raw) ? raw : 'openclaw');
}

function normalizeModelUsage(input: MarrowModelUsageInput = {}): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  const copyString = (key: keyof MarrowModelUsageInput) => {
    const value = input[key];
    if (typeof value === 'string' && value.trim()) body[String(key)] = redactSensitiveText(value).slice(0, 180);
  };
  const copyNumber = (key: keyof MarrowModelUsageInput) => {
    const value = Number(input[key]);
    if (Number.isFinite(value) && value >= 0) body[String(key)] = value;
  };
  (['agent_id', 'session_id', 'workflow_id', 'decision_id', 'provider', 'model', 'task_type', 'action_type', 'source', 'marrow_intervention'] as Array<keyof MarrowModelUsageInput>).forEach(copyString);
  (['input_tokens', 'output_tokens', 'cached_tokens', 'total_tokens', 'cost_usd', 'latency_ms', 'baseline_tokens', 'estimated_tokens_saved', 'estimated_cost_saved_usd', 'estimated_minutes_saved'] as Array<keyof MarrowModelUsageInput>).forEach(copyNumber);
  if (typeof input.success === 'boolean') body.success = input.success;
  return body;
}

/**
 * Validate a path parameter to prevent path traversal attacks.
 * Only allows alphanumeric, hyphens, underscores, and dots.
 */
export function validatePathParam(value: string, paramName: string): string {
  if (!value || typeof value !== 'string') {
    throw new Error(`${paramName} is required`);
  }
  if (!/^[a-zA-Z0-9_.\-]+$/.test(value)) {
    throw new Error(`${paramName} contains invalid characters`);
  }
  if (value.length > 256) {
    throw new Error(`${paramName} exceeds maximum length`);
  }
  return value;
}

const REPLAY_CONSTRAINT_STRING_FIELDS = new Set([
  'environment',
  'tests',
  'policy_profile_id',
  'workflow_type',
  'task_type',
]);
const REPLAY_CONSTRAINT_BOOLEAN_FIELDS = new Set(['required_proof', 'same_workspace']);

function boundCoordinationAgent(input: Record<string, unknown>, agentId?: string): string {
  const boundAgentId = typeof agentId === 'string' ? agentId.trim() : '';
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(boundAgentId)) {
    throw new TypeError('A bound Marrow fleet agent id is required for coordination mutations.');
  }
  for (const field of ['agent_id', 'source_agent_id']) {
    const supplied = input[field];
    if (supplied != null && String(supplied).trim() !== boundAgentId) {
      throw new TypeError(`${field} must match the authenticated Marrow fleet agent id.`);
    }
  }
  return boundAgentId;
}

function normalizeReplayConstraints(value: unknown): Record<string, string | boolean> {
  if (value == null) return {};
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('constraints must be a bounded object.');
  }
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length > 7) throw new TypeError('constraints exceeds the maximum field count.');
  const normalized: Record<string, string | boolean> = {};
  for (const [key, raw] of entries.sort(([left], [right]) => left.localeCompare(right))) {
    if (REPLAY_CONSTRAINT_BOOLEAN_FIELDS.has(key)) {
      if (typeof raw !== 'boolean') throw new TypeError(`constraints.${key} must be boolean.`);
      normalized[key] = raw;
      continue;
    }
    if (!REPLAY_CONSTRAINT_STRING_FIELDS.has(key)) {
      throw new TypeError(`constraints.${key} is not allowed.`);
    }
    const text = typeof raw === 'string' ? raw.trim() : '';
    if (!/^[A-Za-z0-9._:-]{1,80}$/.test(text)) {
      throw new TypeError(`constraints.${key} must be a bounded identifier.`);
    }
    normalized[key] = text;
  }
  return normalized;
}

/**
 * Validate and sanitize a base URL. Requires HTTPS.
 */
export function validateBaseUrl(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'https:') {
      throw new Error('MARROW_BASE_URL must use HTTPS');
    }
    return rawUrl.replace(/\/+$/, '');
  } catch (err) {
    if (err instanceof Error && err.message.includes('HTTPS')) throw err;
    throw new Error(`MARROW_BASE_URL is not a valid URL: ${rawUrl}`);
  }
}

/**
 * Check HTTP response status and parse JSON safely.
 * Throws a descriptive error for non-OK responses.
 */
async function safeJsonResponse(res: Response): Promise<any> {
  if (!res.ok) {
    let detail: Record<string, unknown> | undefined;
    try {
      const contentType = res.headers.get('content-type') || '';
      if (contentType.includes('json')) detail = await res.json() as Record<string, unknown>;
    } catch { /* ignore malformed or non-JSON error bodies */ }
    throw requestErrorFromResponse(res, detail);
  }
  let json: any;
  try {
    json = await res.json();
  } catch {
    throw new Error('Marrow API returned an invalid JSON response');
  }
  if (json.error) {
    throw new Error(String(json.error).slice(0, 240));
  }
  return json;
}

type QueuedRequest = {
  url: string;
  init: RequestInit;
  attempts: number;
};

const retryQueue: QueuedRequest[] = [];
let retryQueueDraining = false;

function isRetryableStatus(status: number): boolean {
  return [408, 425, 429, 500, 502, 503, 504].includes(status);
}

function isRetryableError(error: unknown): boolean {
  const message = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
  if (/\b(401|403|unauthorized|forbidden|invalid api key|insufficient scope|proof pack|required proof|policy|blocked)\b/.test(message)) {
    return false;
  }
  return /\b(timeout|timed out|econnreset|enotfound|eai_again|network|fetch failed|temporar|rate limit)\b/.test(message);
}

async function drainRetryQueue(): Promise<void> {
  if (retryQueueDraining || retryQueue.length === 0) return;
  retryQueueDraining = true;
  const remaining: QueuedRequest[] = [];
  try {
    const queued = retryQueue.splice(0, 5);
    for (const item of queued) {
      try {
        const res = await fetch(item.url, item.init);
        if (!res.ok && isRetryableStatus(res.status) && item.attempts < 2) {
          remaining.push({ ...item, attempts: item.attempts + 1 });
        }
      } catch (error) {
        if (isRetryableError(error) && item.attempts < 2) {
          remaining.push({ ...item, attempts: item.attempts + 1 });
        }
      }
    }
  } finally {
    retryQueue.unshift(...remaining);
    retryQueueDraining = false;
  }
}

async function fetchWithRetryQueue(url: string, init: RequestInit, queueable = false): Promise<Response> {
  await drainRetryQueue();
  try {
    const res = await fetch(url, init);
    if (queueable && !res.ok && isRetryableStatus(res.status)) {
      if (retryQueue.length >= 25) retryQueue.shift();
      retryQueue.push({ url, init, attempts: 0 });
    }
    return res;
  } catch (error) {
    if (queueable && isRetryableError(error)) {
      if (retryQueue.length >= 25) retryQueue.shift();
      retryQueue.push({ url, init, attempts: 0 });
    }
    throw error;
  }
}

function buildHeaders(
  apiKey: string,
  sessionId?: string,
  contentType?: string,
  agentId?: string
): Record<string, string> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${apiKey}`,
  };
  if (contentType) {
    headers['Content-Type'] = contentType;
  }
  if (sessionId) {
    const safe = sessionId.replace(/[^\x20-\x7E]/g, '').slice(0, 256);
    if (safe) {
      headers['X-Marrow-Session-Id'] = safe;
    }
  }
  if (agentId) {
    const safe = agentId.replace(/[^\x20-\x7E]/g, '').slice(0, 256);
    if (safe) {
      headers['X-Marrow-Agent-Id'] = safe;
    }
  }
  headers['X-Marrow-Client'] = defaultSourceClient();
  headers['X-Marrow-Package'] = '@getmarrow/mcp';
  headers['X-Marrow-Package-Version'] = MCP_ADAPTER_VERSION;
  return headers;
}

function createSdkClient(apiKey: string, baseUrl: string, sessionId?: string, agentId?: string): MarrowClient {
  return new MarrowClient(apiKey, { baseUrl, sessionId, agentId });
}

function runtimeGateReceiptId(runtime: MarrowAgentRuntimeResult | null): string | null {
  if (!runtime) return null;
  return runtime.gate_receipt?.id || runtime.gate_receipt_id || null;
}

function clampPeriodDays(value: string | number | undefined, defaultDays: number = 7): number {
  const parsed = typeof value === 'number' ? value : parseInt(String(value || defaultDays), 10);
  if (!Number.isFinite(parsed)) return defaultDays;
  return Math.min(90, Math.max(1, Math.floor(parsed)));
}

export async function marrowCreateKey(
  apiKey: string,
  baseUrl: string,
  params: CreateApiKeyParams,
  sessionId?: string,
  agentId?: string
): Promise<CreateApiKeyResult> {
  return createSdkClient(apiKey, baseUrl, sessionId, agentId).createApiKey(params);
}

export async function marrowListKeys(
  apiKey: string,
  baseUrl: string,
  sessionId?: string,
  agentId?: string
): Promise<ListApiKeysResult> {
  return createSdkClient(apiKey, baseUrl, sessionId, agentId).listApiKeys();
}

export async function marrowGetKey(
  apiKey: string,
  baseUrl: string,
  id: string,
  sessionId?: string,
  agentId?: string
): Promise<MarrowApiKey | null> {
  return createSdkClient(apiKey, baseUrl, sessionId, agentId).getApiKey(id);
}

export async function marrowRevokeKey(
  apiKey: string,
  baseUrl: string,
  id: string,
  sessionId?: string,
  agentId?: string
): Promise<RevokeApiKeyResult> {
  return createSdkClient(apiKey, baseUrl, sessionId, agentId).revokeApiKey(id);
}

export async function marrowRotateKey(
  apiKey: string,
  baseUrl: string,
  id: string,
  sessionId?: string,
  agentId?: string
): Promise<RotateApiKeyResult> {
  return createSdkClient(apiKey, baseUrl, sessionId, agentId).rotateApiKey(id);
}

export async function marrowGetKeyAudit(
  apiKey: string,
  baseUrl: string,
  params?: GetKeyAuditParams,
  sessionId?: string,
  agentId?: string
): Promise<GetKeyAuditResult> {
  return createSdkClient(apiKey, baseUrl, sessionId, agentId).getKeyAudit(params);
}

/**
 * Log intent and get collective intelligence before acting.
 */
export async function marrowThink(
  apiKey: string,
  baseUrl: string,
  params: {
    action: string;
    target?: string;
    surfaces?: string[];
    type?: string;
    context?: Record<string, unknown>;
    previous_decision_id?: string;
    previous_success?: boolean;
    previous_outcome?: string;
    checkLoop?: boolean;
    source_kind?: 'human_directed' | 'agent_autonomous' | 'scheduled' | 'integration' | 'system' | 'unknown';
    source_confidence?: number;
    human_directed?: boolean;
    instruction_ref?: string | null;
    instruction?: string;
    instruction_hash?: string;
    source_meta?: Record<string, unknown>;
  },
  sessionId?: string,
  agentId?: string,
  signal?: AbortSignal,
): Promise<ThinkResult> {
  const body: Record<string, unknown> = {
    action: redactSensitiveText(params.action),
    target: params.target ? redactSensitiveText(params.target) : undefined,
    surfaces: params.surfaces,
    type: params.type || 'general',
  };

  if (params.context) {
    body.context = redactSensitiveValue(params.context) as Record<string, unknown>;
  }

  body.source_kind = params.source_kind || 'agent_autonomous';
  body.source_confidence = params.source_confidence ?? 0.9;
  body.human_directed = params.human_directed ?? false;
  if (params.instruction_ref !== undefined) body.instruction_ref = params.instruction_ref;
  if (params.instruction !== undefined) body.instruction = redactSensitiveText(params.instruction);
  if (params.instruction_hash !== undefined) body.instruction_hash = params.instruction_hash;
  body.source_meta = redactSensitiveValue({
    channel: 'mcp',
    client: defaultSourceClient(),
    user_intent: 'operate',
    ...(params.source_meta || {}),
  }) as Record<string, unknown>;

  if (params.checkLoop) {
    body.checkLoop = true;
  }

  if (params.previous_decision_id) {
    body.previous_decision_id = params.previous_decision_id;
    body.previous_success = params.previous_success ?? true;
    body.previous_outcome = redactSensitiveText(params.previous_outcome ?? '');
  }

  const res = await fetchWithRetryQueue(`${baseUrl}/v1/agent/think`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    body: JSON.stringify(body),
    signal,
  }, true);

  const json = await safeJsonResponse(res);
  return json.data;
}

/**
 * Explicitly commit the result of an action to Marrow.
 */
export async function marrowCommit(
  apiKey: string,
  baseUrl: string,
  params: {
    decision_id: string;
    success: boolean;
    outcome: string;
    caused_by?: string;
    proof?: Record<string, unknown>;
    gate_receipt_id?: string;
    gate_receipt?: string;
    arbitration_receipt_id?: string;
    owner_approval_receipt_id?: string;
    action?: string;
    type?: string;
    surfaces?: string[];
    auto_gate?: boolean;
    model_usage?: MarrowModelUsageInput;
    modelUsage?: MarrowModelUsageInput;
  },
  sessionId?: string,
  agentId?: string
): Promise<CommitResult & { runtime_gate?: MarrowAgentRuntimeResult | null }> {
  let runtimeGate: MarrowAgentRuntimeResult | null = null;
  let gateReceiptId = params.gate_receipt_id || params.gate_receipt;

  if (!gateReceiptId && params.auto_gate !== false && params.action) {
    try {
      runtimeGate = await marrowAgentRuntime(
        apiKey,
        baseUrl,
        {
          action: redactSensitiveText(params.action),
          type: params.type || 'handoff',
          surfaces: params.surfaces || ['handoff'],
          context: { mcp_commit_auto_gate: true },
          proof: params.proof ? redactSensitiveValue(params.proof) as Record<string, unknown> : undefined,
        },
        sessionId,
        agentId
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`marrowCommit auto_gate failed before outcome closure: ${msg}`);
    }
    gateReceiptId = runtimeGateReceiptId(runtimeGate) || undefined;
    if (!gateReceiptId && runtimeGate?.gate_receipt?.required) {
      throw new Error('marrowCommit auto_gate required a gate receipt, but /v1/agent/runtime did not return one');
    }
  }

  const body: Record<string, unknown> = {
    decision_id: params.decision_id,
    success: params.success,
    outcome: redactSensitiveText(params.outcome),
    caused_by: params.caused_by ? redactSensitiveText(params.caused_by) : undefined,
  };
  if (params.proof) body.proof = redactSensitiveValue(params.proof) as Record<string, unknown>;
  if (gateReceiptId) body.gate_receipt_id = gateReceiptId;
  if (params.arbitration_receipt_id) body.arbitration_receipt_id = params.arbitration_receipt_id;
  if (params.owner_approval_receipt_id) body.owner_approval_receipt_id = params.owner_approval_receipt_id;
  const modelUsage = params.model_usage || params.modelUsage;
  if (modelUsage) body.model_usage = normalizeModelUsage(modelUsage);

  const res = await fetchWithRetryQueue(`${baseUrl}/v1/agent/commit`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    body: JSON.stringify(body),
  }, true);

  const json = await safeJsonResponse(res);
  return { ...json.data, runtime_gate: runtimeGate };
}

export async function marrowModelUsage(
  apiKey: string,
  baseUrl: string,
  input: MarrowModelUsageInput,
  sessionId?: string,
  agentId?: string
): Promise<MarrowModelUsageResult> {
  const body = normalizeModelUsage({
    ...input,
    agent_id: input.agent_id || agentId,
    session_id: input.session_id || sessionId,
    source: input.source || 'mcp',
  });
  const res = await fetchWithRetryQueue(`${baseUrl}/v1/agent/model-usage`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    body: JSON.stringify(body),
  }, true);
  const json = await safeJsonResponse(res);
  return json.data;
}

function createTimeoutSignal(timeoutMs?: number, startedAt?: number): {
  signal?: AbortSignal;
  cancel: () => void;
} {
  if (!timeoutMs || timeoutMs <= 0) {
    return { signal: undefined, cancel: () => undefined };
  }

  const elapsed = startedAt ? Date.now() - startedAt : 0;
  const remaining = Math.max(1, timeoutMs - elapsed);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), remaining);
  if (typeof timer.unref === 'function') {
    timer.unref();
  }

  return {
    signal: controller.signal,
    cancel: () => clearTimeout(timer),
  };
}

/**
 * Fire-and-forget style logging helper for tool hooks and simple integrations.
 * Logs intent, and when outcome is supplied, immediately commits it.
 */
export async function marrowAuto(
  apiKey: string,
  baseUrl: string,
  params: {
    action: string;
    outcome?: string;
    success?: boolean;
    type?: string;
    context?: Record<string, unknown>;
    source_meta?: Record<string, unknown>;
    proof?: Record<string, unknown>;
    gate_receipt_id?: string;
    action_for_gate?: string;
    surfaces?: string[];
  },
  sessionId?: string,
  agentId?: string,
  timeoutMs?: number
): Promise<{ decision_id: string; committed: boolean }> {
  const startedAt = Date.now();

  const thinkTimeout = createTimeoutSignal(timeoutMs, startedAt);
  let thinkJson: any;
  try {
    const thinkRes = await fetchWithRetryQueue(`${baseUrl}/v1/agent/think`, {
      method: 'POST',
      headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
      body: JSON.stringify({
        action: redactSensitiveText(params.action),
        type: params.type || 'general',
        context: params.context ? redactSensitiveValue(params.context) as Record<string, unknown> : undefined,
        source_kind: 'agent_autonomous',
        source_confidence: 0.9,
        human_directed: false,
        source_meta: redactSensitiveValue({
          channel: 'mcp',
          client: defaultSourceClient(),
          user_intent: 'operate',
          ...(params.source_meta || {}),
        }) as Record<string, unknown>,
      }),
      signal: thinkTimeout.signal,
    }, true);
    thinkJson = await safeJsonResponse(thinkRes);
  } finally {
    thinkTimeout.cancel();
  }

  const decisionId = thinkJson.data?.decision_id;
  if (!decisionId || typeof decisionId !== 'string') {
    throw new Error('marrowAuto did not receive a decision_id');
  }

  if (params.outcome === undefined) {
    return { decision_id: decisionId, committed: false };
  }

  if (typeof params.success !== 'boolean') {
    return { decision_id: decisionId, committed: false };
  }

  const commitTimeout = createTimeoutSignal(timeoutMs, startedAt);
  try {
    await marrowCommit(
      apiKey,
      baseUrl,
      {
        decision_id: decisionId,
        success: params.success,
        outcome: params.outcome,
        proof: params.proof,
        gate_receipt_id: params.gate_receipt_id,
        action: params.action_for_gate || params.action,
        type: params.type || 'general',
        surfaces: params.surfaces,
      },
      sessionId,
      agentId
    );
  } finally {
    commitTimeout.cancel();
  }

  return { decision_id: decisionId, committed: true };
}

/**
 * Get agent patterns and failure history.
 */
export async function marrowAgentPatterns(
  apiKey: string,
  baseUrl: string,
  params?: { type?: string; limit?: number },
  sessionId?: string,
  agentId?: string
): Promise<AgentPatternsResult> {
  const qs = new URLSearchParams();
  if (params?.type) {
    qs.set('type', params.type);
  }
  if (params?.limit) {
    qs.set('limit', String(params.limit));
  }

  const url =
    `${baseUrl}/v1/agent/patterns` +
    (qs.toString() ? '?' + qs.toString() : '');

  const res = await fetch(url, {
    headers: buildHeaders(apiKey, sessionId, undefined, agentId),
  });

  const json = await safeJsonResponse(res);
  return json.data;
}

/**
 * Get the current before-action warning from the canonical runtime contract.
 * The retired orient/pattern routes required broader legacy scopes and could
 * leave otherwise valid agent-bound keys unable to start a session.
 */
export async function marrowOrient(
  apiKey: string,
  baseUrl: string,
  params?: { taskType?: string; autoWarn?: boolean },
  sessionId?: string,
  agentId?: string,
  signal?: AbortSignal,
): Promise<OrientResult> {
  const taskType = params?.taskType || 'general';
  const runtime = await marrowAgentRuntime(
    apiKey,
    baseUrl,
    {
      action: `Orient before ${taskType} work`,
      type: taskType,
      context: {
        source: 'mcp',
        event_kind: 'session_orientation',
        auto_warn: params?.autoWarn !== false,
      },
    },
    sessionId,
    agentId,
    signal,
  );

  const intervention = runtime.intervention;
  const interventionDecision = intervention?.decision ? String(intervention.decision) : '';
  const gateDecision = runtime.risk_gate?.decision ? String(runtime.risk_gate.decision) : '';
  const receiptDecision = runtime.gate_receipt?.decision ? String(runtime.gate_receipt.decision) : '';
  type OrientDecision = 'proceed' | 'warn' | 'owner_approval_required' | 'block';
  const decisionRank: Record<OrientDecision, number> = {
    proceed: 0,
    warn: 1,
    owner_approval_required: 2,
    block: 3,
  };
  const normalizeDecision = (value: string, source: 'intervention' | 'gate'): OrientDecision | null => {
    if (!value) return null;
    if (value === 'proceed' || value === 'allow') return 'proceed';
    if (value === 'warn') return 'warn';
    if (value === 'owner_approval_required' || value === 'review_required') {
      return 'owner_approval_required';
    }
    if (value === 'block' || value === 'deny' || value === 'denied' || value === 'reject' || value === 'rejected') {
      return 'block';
    }
    // New or malformed policy values must never silently weaken a runtime gate.
    return source === 'intervention' || source === 'gate' ? 'block' : null;
  };
  const normalizedIntervention = normalizeDecision(interventionDecision, 'intervention');
  const normalizedGate = normalizeDecision(gateDecision, 'gate');
  const normalizedReceipt = normalizeDecision(receiptDecision, 'gate');
  const decisions: OrientDecision[] = [
    normalizedIntervention,
    normalizedGate,
    normalizedReceipt,
  ].filter((value): value is OrientDecision => value !== null);
  const interventionDenyContradictsDecision = (intervention?.allow === false || intervention?.must_stop)
    && normalizedIntervention !== 'block'
    && normalizedIntervention !== 'owner_approval_required';
  const gateDenyContradictsDecision = runtime.risk_gate?.allow === false
    && normalizedGate !== 'block'
    && normalizedGate !== 'owner_approval_required';
  if (interventionDenyContradictsDecision || gateDenyContradictsDecision) {
    decisions.push('block');
  }
  if (intervention?.enforcement?.owner_approval_required || runtime.gate_receipt?.owner_approval_required) {
    decisions.push('owner_approval_required');
  }
  const decision = decisions.reduce<OrientDecision>(
    (strictest, candidate) => decisionRank[candidate] > decisionRank[strictest] ? candidate : strictest,
    'proceed'
  );
  const shouldPause = decision === 'block' || decision === 'owner_approval_required';
  const gateReason = Array.isArray(runtime.risk_gate?.reasons)
    ? runtime.risk_gate.reasons.find((reason) => reason && typeof reason.message === 'string')?.message
    : undefined;
  const message = intervention?.before_action
    || intervention?.exact_next_action
    || intervention?.headline
    || runtime.gate_receipt?.exact_fix
    || gateReason
    || runtime.before_you_act
    || (shouldPause ? 'Pause and inspect the runtime gate before acting.' : null);
  const severity: 'HIGH' | 'MEDIUM' | 'LOW' = shouldPause
    ? 'HIGH'
    : decision === 'warn'
      ? 'MEDIUM'
      : 'LOW';
  const serverWarnings = message && (decision !== 'proceed' || params?.autoWarn !== false)
    ? [{
        severity,
        message,
        pattern: `runtime_${decision}`,
        recommendation: intervention?.exact_next_action || undefined,
      }]
    : [];
  const warnings = serverWarnings.map((warning) => ({
    type: warning.pattern,
    failureRate: 0,
    message: warning.message,
    severity: warning.severity,
  }));

  return {
    warnings,
    serverWarnings,
    loopState: {
      isOpen: Boolean(runtime.gate_receipt?.required),
      lastCommit: null,
    },
    shouldPause,
  };
}

/**
 * Query the collective hive for failure patterns and recommendations.
 */
export async function marrowAsk(
  apiKey: string,
  baseUrl: string,
  params: { query: string },
  sessionId?: string,
  agentId?: string,
  signal?: AbortSignal,
): Promise<MarrowAskResult> {
  const res = await fetch(`${baseUrl}/v1/analytics/decision-brief`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    body: JSON.stringify({
      action: params.query,
      type: 'general',
      role: 'general',
      agent_id: agentId,
      session_id: sessionId,
    }),
    signal,
  });

  const json = await safeJsonResponse(res);
  const brief = json.data as MarrowDecisionBriefResult;
  const similarFailures = Array.isArray(brief.risk?.similar_failures) ? brief.risk.similar_failures : [];
  return {
    answer: [brief.summary, brief.next_actions?.[0]].filter(Boolean).join(' '),
    stats: null,
    top_outcomes: Array.isArray(brief.failure_alerts) ? brief.failure_alerts.map((item) => item.message).slice(0, 5) : [],
    decisions_matched: similarFailures.reduce((total, item) => total + Number(item.failures || 0), 0),
    low_history: Number(brief.fleet_reliability?.outcome_coverage || 0) === 0,
  };
}

/**
 * Get API health status.
 */
export async function marrowStatus(
  apiKey: string,
  baseUrl: string,
  sessionId?: string,
  agentId?: string,
  signal?: AbortSignal,
): Promise<StatusResult> {
  const res = await fetch(`${baseUrl}/v1/agent/status?fast=1`, {
    headers: buildHeaders(apiKey, sessionId, undefined, agentId),
    signal,
  });

  const json = await safeJsonResponse(res);
  return json.data;
}

// ─── Workflow Registry API ───────────────────────────────────────

export async function marrowWorkflow(
  apiKey: string,
  baseUrl: string,
  params: {
    action: 'register' | 'list' | 'get' | 'update' | 'start' | 'advance' | 'instances';
    workflowId?: string;
    instanceId?: string;
    name?: string;
    description?: string;
    steps?: Array<{ step: number; agent_role?: string; action_type?: string; description: string }>;
    tags?: string[];
    agentId?: string;
    context?: Record<string, unknown>;
    inputs?: Record<string, unknown>;
    stepCompleted?: number;
    outcome?: string;
    nextAgentId?: string;
    contextUpdate?: Record<string, unknown>;
    status?: string;
  },
  sessionId?: string,
  agentId?: string
): Promise<WorkflowResult> {
  const headers = buildHeaders(apiKey, sessionId, 'application/json', agentId);

  switch (params.action) {
    case 'register': {
      const res = await fetch(`${baseUrl}/v1/workflows/register`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          name: params.name,
          description: params.description,
          steps: params.steps,
          tags: params.tags,
        }),
      });
      const json: any = await res.json();
      if (json.error) return { success: false, error: json.error };
      return { success: true, data: json.data };
    }
    case 'list': {
      const qs = new URLSearchParams();
      if (params.status) qs.set('status', params.status);
      if (params.tags && params.tags.length > 0) qs.set('tags', params.tags.join(','));
      const res = await fetch(`${baseUrl}/v1/workflows?${qs.toString()}`, { headers });
      const json: any = await res.json();
      if (json.error) return { success: false, error: json.error };
      return { success: true, data: json.data };
    }
    case 'get': {
      if (!params.workflowId) return { success: false, error: 'workflowId required' };
      const safeId = validatePathParam(params.workflowId, 'workflowId');
      const res = await fetch(`${baseUrl}/v1/workflows/${safeId}`, { headers });
      const json: any = await res.json();
      if (json.error) return { success: false, error: json.error };
      return { success: true, data: json.data };
    }
    case 'update': {
      if (!params.workflowId) return { success: false, error: 'workflowId required' };
      const safeId = validatePathParam(params.workflowId, 'workflowId');
      const res = await fetch(`${baseUrl}/v1/workflows/${safeId}`, {
        method: 'PUT',
        headers,
        body: JSON.stringify({
          name: params.name,
          description: params.description,
          tags: params.tags,
          status: params.status,
        }),
      });
      const json: any = await res.json();
      if (json.error) return { success: false, error: json.error };
      return { success: true, data: json.data };
    }
    case 'start': {
      if (!params.workflowId) return { success: false, error: 'workflowId required' };
      if (!params.agentId) return { success: false, error: 'agentId required' };
      const safeId = validatePathParam(params.workflowId, 'workflowId');
      const res = await fetch(`${baseUrl}/v1/workflows/${safeId}/start`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          agent_id: params.agentId,
          context: params.context,
          inputs: params.inputs,
        }),
      });
      const json: any = await res.json();
      if (json.error) return { success: false, error: json.error };
      return { success: true, data: json.data };
    }
    case 'advance': {
      if (!params.workflowId) return { success: false, error: 'workflowId required' };
      if (!params.instanceId) return { success: false, error: 'instanceId required' };
      if (params.stepCompleted === undefined) return { success: false, error: 'stepCompleted required' };
      if (params.outcome === undefined) return { success: false, error: 'outcome required' };
      const safeWorkflowId = validatePathParam(params.workflowId, 'workflowId');
      const safeInstanceId = validatePathParam(params.instanceId, 'instanceId');
      const res = await fetch(`${baseUrl}/v1/workflows/${safeWorkflowId}/instances/${safeInstanceId}/step`, {
        method: 'PUT',
        headers,
        body: JSON.stringify({
          step_completed: params.stepCompleted,
          outcome: params.outcome,
          next_agent_id: params.nextAgentId,
          context_update: params.contextUpdate,
        }),
      });
      const json: any = await res.json();
      if (json.error) return { success: false, error: json.error };
      return { success: true, data: json.data };
    }
    case 'instances': {
      if (!params.workflowId) return { success: false, error: 'workflowId required' };
      const safeId = validatePathParam(params.workflowId, 'workflowId');
      const qs = new URLSearchParams();
      if (params.status) qs.set('status', params.status);
      const res = await fetch(`${baseUrl}/v1/workflows/${safeId}/instances?${qs.toString()}`, { headers });
      const json: any = await res.json();
      if (json.error) return { success: false, error: json.error };
      return { success: true, data: json.data };
    }
    default:
      return { success: false, error: `Unknown action: ${params.action}` };
  }
}

// ============= V4 Backend Parity (MCP v3.1) =============

/**
 * Get operator dashboard — account health, top failures, workflow status, saves.
 */
export async function marrowDashboard(
  apiKey: string,
  baseUrl: string,
  sessionId?: string,
  agentId?: string
): Promise<MarrowDashboardResult> {
  const res = await fetch(`${baseUrl}/v1/dashboard`, {
    headers: buildHeaders(apiKey, sessionId, undefined, agentId),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

/**
 * Get periodic summary of agent activity and Marrow impact.
 */
export async function marrowDigest(
  apiKey: string,
  baseUrl: string,
  period: string = '7d',
  sessionId?: string,
  agentId?: string
): Promise<MarrowDigestResult> {
  const days = parseInt(period) || 7;
  const res = await fetch(`${baseUrl}/v1/digest?period=${days}`, {
    headers: buildHeaders(apiKey, sessionId, undefined, agentId),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

/**
 * Get agent-native proof that Marrow is active and collecting useful signal.
 */
export async function marrowAgentStatus(
  apiKey: string,
  baseUrl: string,
  period: string = '7d',
  agentIdFilter?: string,
  sessionId?: string,
  agentId?: string
): Promise<MarrowAgentStatusResult> {
  const days = parseInt(period) || 7;
  const qs = new URLSearchParams({ period: String(days) });
  if (agentIdFilter) qs.set('agent_id', agentIdFilter);
  const res = await fetch(`${baseUrl}/v1/analytics/agent-status?${qs.toString()}`, {
    headers: buildHeaders(apiKey, sessionId, undefined, agentId),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

/**
 * Get live runtime hook diagnostics from /v1/agent/status.
 */
export async function marrowRuntimeStatus(
  apiKey: string,
  baseUrl: string,
  fast: boolean = true,
  sessionId?: string,
  agentId?: string,
  signal?: AbortSignal,
): Promise<Record<string, unknown>> {
  const qs = fast ? '?fast=1' : '';
  const res = await fetch(`${baseUrl}/v1/agent/status${qs}`, {
    headers: buildHeaders(apiKey, sessionId, undefined, agentId),
    signal,
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

/**
 * Get the compact canonical read context used by passive prompt hooks.
 */
export async function marrowAgentContext(
  apiKey: string,
  baseUrl: string,
  sessionId?: string,
  agentId?: string,
  signal?: AbortSignal,
): Promise<Record<string, unknown>> {
  const query = new URLSearchParams({ compact: '1' });
  if (agentId) query.set('agent_id', agentId);
  const res = await fetch(`${baseUrl}/v1/agent/context?${query.toString()}`, {
    headers: buildHeaders(apiKey, sessionId, undefined, agentId),
    signal,
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

/**
 * Get owner-ready proof of Marrow value for an agent or fleet.
 */
export async function marrowValueReport(
  apiKey: string,
  baseUrl: string,
  period: string = '7d',
  agentIdFilter?: string,
  sessionId?: string,
  agentId?: string
): Promise<MarrowValueReportResult> {
  const days = clampPeriodDays(period);
  const qs = new URLSearchParams({ period: String(days) });
  if (agentIdFilter) qs.set('agent_id', agentIdFilter);
  const res = await fetch(`${baseUrl}/v1/analytics/value-report?${qs.toString()}`, {
    headers: buildHeaders(apiKey, sessionId, undefined, agentId),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

/**
 * Get one pre-action operating brief for risky or meaningful agent work.
 */
export async function marrowDecisionBrief(
  apiKey: string,
  baseUrl: string,
  input: MarrowDecisionBriefRequest,
  sessionId?: string,
  agentId?: string
): Promise<MarrowDecisionBriefResult> {
  const body = {
    ...input,
    agent_id: input.agent_id || agentId,
    session_id: input.session_id || sessionId,
  };
  const res = await fetch(`${baseUrl}/v1/analytics/decision-brief`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    body: JSON.stringify(body),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

export async function marrowWorkflowGate(
  apiKey: string,
  baseUrl: string,
  input: MarrowWorkflowGateRequest,
  sessionId?: string,
  agentId?: string
): Promise<MarrowWorkflowGateResult> {
  const res = await fetch(`${baseUrl}/v1/workflow/gate`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    body: JSON.stringify(input),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

export async function marrowAgentRuntime(
  apiKey: string,
  baseUrl: string,
  input: MarrowAgentRuntimeRequest,
  sessionId?: string,
  agentId?: string,
  signal?: AbortSignal,
): Promise<MarrowAgentRuntimeResult> {
  const body = {
    ...input,
    agent_id: input.agent_id || agentId,
    session_id: input.session_id || sessionId,
  };
  const idempotencyKey = `mcp-runtime-${randomUUID()}`;
  const res = await fetch(`${baseUrl}/v1/agent/runtime`, {
    method: 'POST',
    headers: {
      ...buildHeaders(apiKey, sessionId, 'application/json', agentId),
      'Idempotency-Key': idempotencyKey,
    },
    body: JSON.stringify(body),
    signal,
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

export async function marrowEnforcement(
  apiKey: string,
  baseUrl: string,
  input: MarrowEnforcementRequest,
  sessionId?: string,
  agentId?: string,
  signal?: AbortSignal,
): Promise<MarrowEnforcementResult> {
  const body = {
    ...input,
    agent_id: input.agent_id || agentId,
    session_id: input.session_id || sessionId,
  };
  const res = await fetch(`${baseUrl}/v1/agent/enforcement`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    body: JSON.stringify(body),
    signal,
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

/**
 * Resolve conflicting agent proposals through the existing runtime control
 * plane. This is a client convenience, not a separate backend API.
 */
export async function marrowArbitrate(
  apiKey: string,
  baseUrl: string,
  input: MarrowArbitrationRequest & {
    action?: string;
    type?: string;
    agent_id?: string;
    session_id?: string;
    surfaces?: string[];
    context?: Record<string, unknown>;
    proof?: Record<string, unknown>;
  },
  sessionId?: string,
  agentId?: string
): Promise<MarrowAgentRuntimeResult> {
  const { action, type, agent_id, session_id, surfaces, context, proof, ...coordination } = input;
  if (!Array.isArray(coordination.proposals)
    || coordination.proposals.length < 2
    || coordination.proposals.length > 8) {
    throw new RangeError('Agent arbitration requires between 2 and 8 proposals.');
  }
  for (const proposal of coordination.proposals) {
    if (Array.isArray(proposal.evidence) && proposal.evidence.length > 8) {
      throw new RangeError('Agent arbitration accepts at most 8 evidence references per proposal.');
    }
  }
  const safeCoordination: MarrowArbitrationRequest = {
    objective: redactSensitiveText(coordination.objective),
    ...(typeof coordination.owner_intent === 'string'
      ? { owner_intent: redactSensitiveText(coordination.owner_intent) }
      : {}),
    ...(coordination.conflict_type ? { conflict_type: coordination.conflict_type } : {}),
    proposals: coordination.proposals.map((proposal) => ({
          proposal_id: preserveOpaqueArbitrationValue(
            proposal.proposal_id,
            SAFE_ARBITRATION_IDENTIFIER,
            'proposal_id'
          ),
          agent_id: preserveOpaqueArbitrationValue(
            proposal.agent_id,
            SAFE_ARBITRATION_IDENTIFIER,
            'agent_id'
          ),
          action: redactSensitiveText(proposal.action),
          ...(typeof proposal.rationale === 'string'
            ? { rationale: redactSensitiveText(proposal.rationale) }
            : {}),
          ...(typeof proposal.confidence === 'number' ? { confidence: proposal.confidence } : {}),
          ...(proposal.risk_level ? { risk_level: proposal.risk_level } : {}),
          ...(typeof proposal.requires_owner_approval === 'boolean'
            ? { requires_owner_approval: proposal.requires_owner_approval }
            : {}),
          ...(Array.isArray(proposal.evidence)
            ? {
                evidence: proposal.evidence.map((evidence) => ({
                  kind: preserveOpaqueArbitrationValue(
                    evidence.kind,
                    SAFE_ARBITRATION_EVIDENCE_KIND,
                    'evidence kind'
                  ),
                  reference: preserveOpaqueArbitrationValue(
                    evidence.reference,
                    SAFE_ARBITRATION_EVIDENCE_REFERENCE,
                    'evidence reference'
                  ),
                })),
              }
            : {}),
        })),
  };
  return marrowAgentRuntime(apiKey, baseUrl, {
    action: redactSensitiveText(action || `Resolve conflicting agent proposals for ${safeCoordination.objective}`),
    type: type || 'coordination',
    agent_id: agent_id || agentId,
    session_id: session_id || sessionId,
    surfaces,
    context: context ? redactSensitiveValue(context) as Record<string, unknown> : undefined,
    proof: proof ? redactSensitiveValue(proof) as Record<string, unknown> : undefined,
    coordination: safeCoordination,
  }, sessionId, agentId);
}

export async function marrowGovernanceControlPlane(
  apiKey: string,
  baseUrl: string,
  sessionId?: string,
  agentId?: string
): Promise<Record<string, unknown>> {
  const res = await fetch(`${baseUrl}/v1/agent/governance/control-plane`, {
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

export async function marrowHermesIntegration(
  apiKey: string,
  baseUrl: string,
  sessionId?: string,
  agentId?: string
): Promise<Record<string, unknown>> {
  const res = await fetch(`${baseUrl}/v1/agent/integrations/hermes`, {
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

export async function marrowCompletionContracts(
  apiKey: string,
  baseUrl: string,
  sessionId?: string,
  agentId?: string
): Promise<Record<string, unknown>> {
  const res = await fetch(`${baseUrl}/v1/agent/governance/completion-contracts`, {
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

export async function marrowEvaluateCompletionContract(
  apiKey: string,
  baseUrl: string,
  input: Record<string, unknown>,
  sessionId?: string,
  agentId?: string
): Promise<Record<string, unknown>> {
  const res = await fetch(`${baseUrl}/v1/agent/governance/completion-contracts/evaluate`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    body: JSON.stringify(input),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

export async function marrowGovernanceTimeline(
  apiKey: string,
  baseUrl: string,
  options: { agentId?: string; limit?: number } = {},
  sessionId?: string,
  agentId?: string
): Promise<Record<string, unknown>> {
  const qs = new URLSearchParams();
  if (options.agentId || agentId) qs.set('agent_id', options.agentId || agentId || '');
  if (options.limit) qs.set('limit', String(options.limit));
  const res = await fetch(`${baseUrl}/v1/agent/governance/timeline${qs.toString() ? `?${qs.toString()}` : ''}`, {
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

export async function marrowBuyerProof(
  apiKey: string,
  baseUrl: string,
  options: { agentId?: string; periodDays?: number } = {},
  sessionId?: string,
  agentId?: string
): Promise<Record<string, unknown>> {
  const qs = new URLSearchParams();
  if (options.agentId || agentId) qs.set('agent_id', options.agentId || agentId || '');
  if (options.periodDays) qs.set('period_days', String(options.periodDays));
  const res = await fetch(`${baseUrl}/v1/agent/governance/buyer-proof${qs.toString() ? `?${qs.toString()}` : ''}`, {
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

/**
 * Coordinate tenant agents through resource leases and compact proof packets.
 * This is intentionally one MCP surface over the existing governance routes.
 */
export async function marrowCoordinate(
  apiKey: string,
  baseUrl: string,
  input: Record<string, unknown>,
  sessionId?: string,
  agentId?: string
): Promise<Record<string, unknown>> {
  const action = String(input.action || '');
  const headers = buildHeaders(apiKey, sessionId, 'application/json', agentId);
  if (action === 'list_leases') {
    const qs = new URLSearchParams();
    if (typeof input.status === 'string') qs.set('status', input.status);
    if (Number.isFinite(Number(input.limit))) qs.set('limit', String(input.limit));
    const res = await fetch(`${baseUrl}/v1/agent/governance/leases${qs.toString() ? `?${qs}` : ''}`, { headers });
    return (await safeJsonResponse(res)).data;
  }
  if (action === 'acquire_lease') {
    const boundAgentId = boundCoordinationAgent(input, agentId);
    const body = {
      agent_id: boundAgentId,
      resource_type: input.resource_type,
      resource: typeof input.resource === 'string' ? redactSensitiveText(input.resource) : input.resource,
      workflow_id: input.workflow_id,
      ttl_seconds: input.ttl_seconds,
    };
    const res = await fetch(`${baseUrl}/v1/agent/governance/leases/acquire`, {
      method: 'POST', headers, body: JSON.stringify(body),
    });
    return (await safeJsonResponse(res)).data;
  }
  if (action === 'release_lease') {
    const boundAgentId = boundCoordinationAgent(input, agentId);
    const leaseId = validatePathParam(String(input.lease_id || ''), 'lease_id');
    if (!leaseId.startsWith('lease_')) throw new TypeError('lease_id must be a Marrow lease identifier.');
    const res = await fetch(`${baseUrl}/v1/agent/governance/leases/${leaseId}/release`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        agent_id: boundAgentId,
        lease_token: input.lease_token,
      }),
    });
    return (await safeJsonResponse(res)).data;
  }
  if (action === 'list_proof_packets') {
    const qs = new URLSearchParams();
    if (Number.isFinite(Number(input.limit))) qs.set('limit', String(input.limit));
    const res = await fetch(`${baseUrl}/v1/agent/governance/proof-packets${qs.toString() ? `?${qs}` : ''}`, { headers });
    return (await safeJsonResponse(res)).data;
  }
  if (action === 'create_proof_packet') {
    const boundAgentId = boundCoordinationAgent(input, agentId);
    if (input.parent_agent_id != null) {
      throw new TypeError('parent_agent_id must be assigned by trusted Marrow coordination.');
    }
    const body = redactSensitiveValue({
      source_agent_id: boundAgentId,
      lease_id: input.lease_id,
      decision_id: input.decision_id,
      workflow_id: input.workflow_id,
      proof_pack_id: input.proof_pack_id,
      status: input.status,
      summary: input.summary,
      evidence_refs: input.evidence_refs,
    });
    const res = await fetch(`${baseUrl}/v1/agent/governance/proof-packets`, {
      method: 'POST', headers, body: JSON.stringify(body),
    });
    return (await safeJsonResponse(res)).data;
  }
  throw new TypeError('Unsupported coordination action.');
}

/**
 * Compare already-recorded outcomes and proof for the same task. Marrow does
 * not execute either model or workflow through this endpoint.
 */
export async function marrowReplayCompare(
  apiKey: string,
  baseUrl: string,
  input: Record<string, unknown>,
  sessionId?: string,
  agentId?: string
): Promise<Record<string, unknown>> {
  const comparisonId = typeof input.comparison_id === 'string' ? input.comparison_id : '';
  if (comparisonId) {
    const safeId = validatePathParam(comparisonId, 'comparison_id');
    if (!safeId.startsWith('replay_')) throw new TypeError('comparison_id must be a Marrow replay identifier.');
    const res = await fetch(`${baseUrl}/v1/agent/governance/replay-comparisons/${safeId}`, {
      headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    });
    return (await safeJsonResponse(res)).data;
  }
  const body = redactSensitiveValue({
    source_decision_id: input.source_decision_id,
    workspace_binding_id: input.workspace_binding_id,
    constraints: normalizeReplayConstraints(input.constraints),
    baseline: input.baseline,
    candidate: input.candidate,
  });
  const res = await fetch(`${baseUrl}/v1/agent/governance/replay-comparisons`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    body: JSON.stringify(body),
  });
  return (await safeJsonResponse(res)).data;
}

export async function marrowRecommendGovernanceMode(
  apiKey: string,
  baseUrl: string,
  input: Record<string, unknown>,
  sessionId?: string,
  agentId?: string
): Promise<Record<string, unknown>> {
  const res = await fetch(`${baseUrl}/v1/agent/mode/recommend`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    body: JSON.stringify(input),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

export async function marrowListPolicyProfiles(
  apiKey: string,
  baseUrl: string,
  sessionId?: string,
  agentId?: string
): Promise<Record<string, unknown>> {
  const res = await fetch(`${baseUrl}/v1/agent/policy-profiles`, {
    method: 'GET',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

export async function marrowCreatePolicyProfile(
  apiKey: string,
  baseUrl: string,
  input: Record<string, unknown>,
  sessionId?: string,
  agentId?: string
): Promise<Record<string, unknown>> {
  const res = await fetch(`${baseUrl}/v1/agent/policy-profiles`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    body: JSON.stringify(input),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

export async function marrowAssignProjectPolicyProfile(
  apiKey: string,
  baseUrl: string,
  input: Record<string, unknown>,
  sessionId?: string,
  agentId?: string
): Promise<Record<string, unknown>> {
  const res = await fetch(`${baseUrl}/v1/agent/project-policy-profile`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    body: JSON.stringify(input),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

export async function marrowResolvePolicy(
  apiKey: string,
  baseUrl: string,
  input: Record<string, unknown>,
  sessionId?: string,
  agentId?: string
): Promise<Record<string, unknown>> {
  const res = await fetch(`${baseUrl}/v1/agent/policy/resolve`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    body: JSON.stringify(input),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

export async function marrowFirstValue(
  apiKey: string,
  baseUrl: string,
  input: MarrowFirstValueRequest = {},
  sessionId?: string,
  agentId?: string
): Promise<MarrowFirstValueResult> {
  const body = {
    ...input,
    agent_id: input.agent_id || agentId,
    session_id: input.session_id || sessionId,
  };
  const res = await fetch(`${baseUrl}/v1/agent/first-value`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    body: JSON.stringify(body),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

export async function marrowAgentPerformance(
  apiKey: string,
  baseUrl: string,
  period: string = '7d',
  agentIdFilter?: string,
  sessionId?: string,
  agentId?: string
): Promise<unknown> {
  const qs = new URLSearchParams({ period: String(clampPeriodDays(period)) });
  if (agentIdFilter || agentId) qs.set('agent_id', agentIdFilter || agentId || '');
  const res = await fetch(`${baseUrl}/v1/analytics/agent-performance?${qs.toString()}`, {
    headers: buildHeaders(apiKey, sessionId, undefined, agentId),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

export async function marrowFleetLessons(
  apiKey: string,
  baseUrl: string,
  options: { query?: string; type?: string; agentId?: string; limit?: number } = {},
  sessionId?: string,
  agentId?: string
): Promise<unknown> {
  const qs = new URLSearchParams();
  if (options.query) qs.set('query', options.query);
  if (options.type) qs.set('type', options.type);
  if (options.agentId || agentId) qs.set('agent_id', options.agentId || agentId || '');
  if (options.limit) qs.set('limit', String(options.limit));
  const res = await fetch(`${baseUrl}/v1/fleet/lessons${qs.toString() ? `?${qs.toString()}` : ''}`, {
    headers: buildHeaders(apiKey, sessionId, undefined, agentId),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

export async function marrowRecordDeploymentMemory(
  apiKey: string,
  baseUrl: string,
  input: Record<string, unknown>,
  sessionId?: string,
  agentId?: string
): Promise<unknown> {
  const res = await fetch(`${baseUrl}/v1/fleet/deployment-memory`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    body: JSON.stringify({
    ...input,
    agent_id: String(input.agent_id || agentId || ''),
    tests: Array.isArray(input.tests) ? input.tests as string[] : undefined,
    }),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

export async function marrowCreateHandoff(
  apiKey: string,
  baseUrl: string,
  input: Record<string, unknown>,
  sessionId?: string,
  agentId?: string
): Promise<unknown> {
  const res = await fetch(`${baseUrl}/v1/fleet/handoffs`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    body: JSON.stringify({
    ...input,
    from_agent_id: String(input.from_agent_id || agentId || ''),
    to_agent_id: String(input.to_agent_id || ''),
    task: String(input.task || ''),
    }),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

export async function marrowUpdateHandoff(
  apiKey: string,
  baseUrl: string,
  handoffId: string,
  input: Record<string, unknown>,
  sessionId?: string,
  agentId?: string
): Promise<unknown> {
  const safeId = validatePathParam(handoffId, 'handoffId');
  const res = await fetch(`${baseUrl}/v1/fleet/handoffs/${safeId}`, {
    method: 'PATCH',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    body: JSON.stringify({
      status: typeof input.status === 'string' ? input.status : undefined,
      checkpoint: typeof input.checkpoint === 'string' ? input.checkpoint : undefined,
      result_summary: typeof input.result_summary === 'string' ? input.result_summary : undefined,
    }),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

export async function marrowHandoffStatus(
  apiKey: string,
  baseUrl: string,
  options: { status?: string; agentId?: string; limit?: number } = {},
  sessionId?: string,
  agentId?: string
): Promise<unknown> {
  const qs = new URLSearchParams();
  if (options.status) qs.set('status', options.status);
  if (options.agentId || agentId) qs.set('agent_id', options.agentId || agentId || '');
  if (options.limit) qs.set('limit', String(options.limit));
  const res = await fetch(`${baseUrl}/v1/fleet/handoffs/status${qs.toString() ? `?${qs.toString()}` : ''}`, {
    headers: buildHeaders(apiKey, sessionId, undefined, agentId),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

/**
 * Get a periodic improvement nudge when Marrow has something worth surfacing.
 */
export async function marrowNudge(
  apiKey: string,
  baseUrl: string,
  sessionId?: string,
  agentId?: string
): Promise<MarrowNudgeResult> {
  const res = await fetch(`${baseUrl}/v1/agent/nudge`, {
    headers: buildHeaders(apiKey, sessionId, undefined, agentId),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

/**
 * Explicitly end the current session.
 */
export async function marrowSessionEnd(
  apiKey: string,
  baseUrl: string,
  autoCommitOpen: boolean = false,
  sessionId?: string,
  agentId?: string,
  signal?: AbortSignal,
): Promise<unknown> {
  const res = await fetch(`${baseUrl}/v1/agent/session/end`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    body: JSON.stringify({ auto_commit_open: autoCommitOpen }),
    signal,
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

export async function marrowIntegrationEvent(
  apiKey: string,
  baseUrl: string,
  event: LifecycleEvent,
  sessionId?: string,
  agentId?: string,
): Promise<unknown> {
  return recordLifecycleEvent({
    apiKey,
    baseUrl,
    event: {
      ...event,
      session_id: event.session_id || sessionId,
      agent_id: event.agent_id || agentId,
    },
  });
}

export async function marrowDecisionTrace(
  apiKey: string,
  baseUrl: string,
  decisionId: string,
  sessionId?: string,
  agentId?: string,
): Promise<unknown> {
  const safeId = validatePathParam(decisionId, 'decisionId');
  const response = await fetch(`${baseUrl}/v1/agent/governance/trace/${safeId}`, {
    headers: buildHeaders(apiKey, sessionId, undefined, agentId),
  });
  const json = await safeJsonResponse(response);
  return json.data || json;
}

/**
 * Convert a detected decision pattern into an enforced workflow.
 */
export async function marrowAcceptDetected(
  apiKey: string,
  baseUrl: string,
  detectedId: string,
  sessionId?: string,
  agentId?: string
): Promise<unknown> {
  const safeId = validatePathParam(detectedId, 'detectedId');
  const res = await fetch(`${baseUrl}/v1/workflows/accept-detected`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    body: JSON.stringify({ detected_id: safeId }),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

// ============= Template Marketplace (MCP v3.1.3) =============

/**
 * List workflow templates with optional filters.
 */
export async function marrowListTemplates(
  apiKey: string,
  baseUrl: string,
  params?: { industry?: string; category?: string; limit?: number },
  sessionId?: string,
  agentId?: string
): Promise<unknown> {
  const qs = new URLSearchParams();
  if (params?.industry) qs.set('industry', params.industry);
  if (params?.category) qs.set('category', params.category);
  if (params?.limit) qs.set('limit', String(params.limit));
  const query = qs.toString();
  const res = await fetch(`${baseUrl}/v1/templates${query ? '?' + query : ''}`, {
    headers: buildHeaders(apiKey, sessionId, undefined, agentId),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}

/**
 * Install a workflow template as an active workflow.
 */
export async function marrowInstallTemplate(
  apiKey: string,
  baseUrl: string,
  slug: string,
  sessionId?: string,
  agentId?: string
): Promise<unknown> {
  const safeSlug = validatePathParam(slug, 'slug');
  const res = await fetch(`${baseUrl}/v1/templates/${safeSlug}/install`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
  });
  const json = await safeJsonResponse(res);
  return json.data;
}
