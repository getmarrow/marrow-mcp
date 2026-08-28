/**
 * @getmarrow/mcp — API Functions
 */

import { createHash, randomUUID } from 'node:crypto';

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
import { invalidResponseError, MarrowRequestError, normalizeRequestError, reliableFetch, requestErrorFromResponse } from './request-reliability';
import { highRiskRuntimeCanClose, highRiskRuntimeCanContinueWithProof, normalizeRuntimeResult, runtimeAuthorizationReceiptId } from './runtime-contract';

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
  return aliases[raw] || (SOURCE_CLIENTS.has(raw) ? raw : 'custom');
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
    throw invalidResponseError();
  }
  if (!json || typeof json !== 'object' || Array.isArray(json) || json.error) {
    throw invalidResponseError();
  }
  return json;
}

function requireRuntimeResult(value: unknown): MarrowAgentRuntimeResult {
  const runtime = normalizeRuntimeResult(value);
  if (!runtime) throw invalidResponseError();
  return runtime;
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
  return runtimeAuthorizationReceiptId(runtime);
}

function runtimeGateCanAuthorizeCommit(runtime: MarrowAgentRuntimeResult | null): boolean {
  if (!runtimeGateReceiptId(runtime) || !runtime) return false;
  return (runtime.authorization_state === 'hard_gate' && runtime.hard_gate_obtained === true)
    || (runtime.authorization_state === 'advisory_only' && runtime.hard_gate_obtained === false);
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
  options?: { idempotencyKey?: string; responseMode?: 'ack' },
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

  const thinkUrl = `${baseUrl}/v1/agent/think${options?.responseMode === 'ack' ? '?response=ack' : ''}`;
  const thinkInit = {
    method: 'POST',
    headers: {
      ...buildHeaders(apiKey, sessionId, 'application/json', agentId),
      ...(options?.idempotencyKey ? { 'Idempotency-Key': options.idempotencyKey } : {}),
    },
    body: JSON.stringify(body),
    signal,
  } satisfies RequestInit;
  const res = options?.idempotencyKey
    ? await fetch(thinkUrl, thinkInit)
    : await fetchWithRetryQueue(thinkUrl, thinkInit, true);

  const json = await safeJsonResponse(res);
  return markAutoResponseStatus(json.data, res.status);
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
    identified_workflow_id?: string;
    identified_workflow?: { id?: string | null } | null;
    reused_identified_workflow?: boolean;
    model_usage?: MarrowModelUsageInput;
    modelUsage?: MarrowModelUsageInput;
  },
  sessionId?: string,
  agentId?: string,
  signal?: AbortSignal,
  idempotencyKey?: string,
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
        agentId,
        signal,
      );
    } catch (err) {
      if (err instanceof MarrowRequestError) throw err;
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`marrowCommit auto_gate failed before outcome closure: ${msg}`);
    }
    gateReceiptId = runtimeGateReceiptId(runtimeGate) || undefined;
    if (!gateReceiptId || !runtimeGateCanAuthorizeCommit(runtimeGate)) {
      throw new Error('marrowCommit auto_gate required a gate receipt backed by canonical runtime authorization, but /v1/agent/runtime returned missing, conflicting, or unverified receipt state');
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
  const identifiedWorkflowId = typeof params.identified_workflow_id === 'string' && params.identified_workflow_id.trim()
    ? params.identified_workflow_id.trim().slice(0, 128)
    : typeof params.identified_workflow?.id === 'string' && params.identified_workflow.id.trim()
    ? params.identified_workflow.id.trim().slice(0, 128)
    : typeof runtimeGate?.identified_workflow?.id === 'string' && runtimeGate.identified_workflow.id.trim()
    ? runtimeGate.identified_workflow.id.trim().slice(0, 128)
    : undefined;
  if (identifiedWorkflowId) body.identified_workflow_id = identifiedWorkflowId;
  if (params.reused_identified_workflow === true || identifiedWorkflowId) {
    body.reused_identified_workflow = true;
  }
  const modelUsage = params.model_usage || params.modelUsage;
  if (modelUsage) body.model_usage = normalizeModelUsage(modelUsage);

  const commitInit = {
    method: 'POST',
    headers: {
      ...buildHeaders(apiKey, sessionId, 'application/json', agentId),
      ...(idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {}),
    },
    body: JSON.stringify(body),
    signal,
  } satisfies RequestInit;
  const res = idempotencyKey
    ? await fetch(`${baseUrl}/v1/agent/commit`, commitInit)
    : await fetchWithRetryQueue(`${baseUrl}/v1/agent/commit`, commitInit, true);

  const json = await safeJsonResponse(res);
  if (res.status === 202
    && json.data
    && typeof json.data === 'object'
    && !Array.isArray(json.data)
    && (json.data.phase === undefined || json.data.phase === 'commit_pending' || json.data.resumable === true)) {
    return markAutoResponseStatus({ ...json.data, committed: false } as CommitResult, res.status);
  }
  if (!json.data
    || typeof json.data !== 'object'
    || Array.isArray(json.data)
    || typeof json.data.committed !== 'boolean') {
    throw invalidResponseError();
  }
  return markAutoResponseStatus(
    { ...json.data, committed: json.data.committed, runtime_gate: runtimeGate },
    res.status,
  );
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

const SAFE_AUTO_OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,79}$/;
const AUTO_OPERATION_BINDING_TTL_MS = 30 * 60 * 1_000;
const AUTO_OPERATION_BINDING_LIMIT = 256;
const AUTO_RESPONSE_BUDGET_DEFAULT_MS = 8_000;
export const MARROW_AUTO_RESPONSE_BUDGET_MAX_MS = 8_000;
const AUTO_RESPONSE_DEADLINE_MARGIN_MS = 75;
const AUTO_RESPONSE_STATUS = Symbol('marrowAutoResponseStatus');

type AutoOperationBinding = {
  signature: string;
  expiresAt: number;
  runtimeGate?: MarrowAgentRuntimeResult;
  decisionId?: string;
};

const autoOperationBindings = new Map<string, AutoOperationBinding>();

function canonicalAutoBindingValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalAutoBindingValue);
  if (value && typeof value === 'object') {
    return Object.keys(value as Record<string, unknown>).sort().reduce<Record<string, unknown>>((result, key) => {
      result[key] = canonicalAutoBindingValue((value as Record<string, unknown>)[key]);
      return result;
    }, {});
  }
  return value;
}

function autoOperationSignature(input: {
  apiKey: string;
  baseUrl: string;
  agentId?: string;
  sessionId?: string;
  action: string;
  gateAction: string;
  type: string;
  surfaces?: string[];
  context?: Record<string, unknown>;
}): string {
  return createHash('sha256').update(JSON.stringify(canonicalAutoBindingValue({
    api_key: input.apiKey,
    base_url: input.baseUrl.replace(/\/$/, ''),
    agent_id: input.agentId || null,
    session_id: input.sessionId || null,
    action: redactSensitiveText(input.action),
    gate_action: redactSensitiveText(input.gateAction),
    type: input.type,
    surfaces: input.surfaces || [],
    context: input.context ? redactSensitiveValue(input.context) : null,
  }))).digest('hex');
}

function boundAutoOperation(operationId: string, signature: string): AutoOperationBinding {
  const now = Date.now();
  for (const [id, binding] of autoOperationBindings) {
    if (binding.expiresAt <= now) autoOperationBindings.delete(id);
  }
  const existing = autoOperationBindings.get(operationId);
  if (existing) {
    if (existing.signature !== signature) {
      throw new MarrowRequestError({
        code: 'request_failed',
        backendCode: 'MARROW_AUTO_OPERATION_BINDING_CONFLICT',
        message: 'marrow_auto operation_id is already bound to another tenant or action scope.',
        status: 409,
        retryable: false,
        exactFix: 'Retry the original tenant, action, context, and surfaces, or start an intentionally different action with a new operation_id.',
      });
    }
    existing.expiresAt = now + AUTO_OPERATION_BINDING_TTL_MS;
    return existing;
  }
  while (autoOperationBindings.size >= AUTO_OPERATION_BINDING_LIMIT) {
    const oldest = autoOperationBindings.keys().next().value;
    if (typeof oldest !== 'string') break;
    autoOperationBindings.delete(oldest);
  }
  const created = { signature, expiresAt: now + AUTO_OPERATION_BINDING_TTL_MS };
  autoOperationBindings.set(operationId, created);
  return created;
}

function resolveAutoOperationId(value: unknown): string {
  const supplied = typeof value === 'string' ? value.trim() : '';
  if (supplied) {
    if (!SAFE_AUTO_OPERATION_ID.test(supplied)) {
      throw new TypeError('marrow_auto operation_id must be an 8-80 character opaque identifier.');
    }
    return supplied;
  }
  return `auto_${randomUUID()}`;
}

function autoIdempotencyKey(operationId: string, phase: 'runtime' | 'think' | 'commit'): string {
  return `mcp-auto:${operationId}:${phase}`;
}

type AutoPendingResponse = {
  phase?: string;
  resumable?: boolean;
  retry_after_ms?: number | null;
  [AUTO_RESPONSE_STATUS]?: number;
};

function autoResponseBudget(timeoutMs?: number): number {
  const requested = Number(timeoutMs);
  return Number.isFinite(requested) && requested > 0
    ? Math.min(MARROW_AUTO_RESPONSE_BUDGET_MAX_MS, Math.max(500, Math.floor(requested)))
    : AUTO_RESPONSE_BUDGET_DEFAULT_MS;
}

function markAutoResponseStatus<T>(value: T, status: number): T {
  if (value && typeof value === 'object') {
    Object.defineProperty(value, AUTO_RESPONSE_STATUS, { value: status });
  }
  return value;
}

function isAutoPendingResponse(value: unknown, phase: 'think_pending' | 'commit_pending'): value is AutoPendingResponse {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const pending = value as AutoPendingResponse;
  return pending[AUTO_RESPONSE_STATUS] === 202
    && (pending.phase === phase || (pending.phase === undefined && pending.resumable === true));
}

async function waitForAutoContinuation(
  pending: AutoPendingResponse,
  startedAt: number,
  responseBudgetMs: number,
): Promise<boolean> {
  const remaining = responseBudgetMs - (Date.now() - startedAt) - AUTO_RESPONSE_DEADLINE_MARGIN_MS;
  if (remaining <= 0) return false;
  const requestedDelay = Number(pending.retry_after_ms);
  const delayMs = Number.isFinite(requestedDelay)
    ? Math.min(500, Math.max(25, Math.floor(requestedDelay)))
    : 50;
  await new Promise((resolve) => setTimeout(resolve, Math.min(delayMs, remaining)));
  return responseBudgetMs - (Date.now() - startedAt) > AUTO_RESPONSE_DEADLINE_MARGIN_MS;
}

export type MarrowAutoResult = {
  operation_id: string;
  decision_id: string | null;
  committed: boolean;
  phase: 'runtime_pending' | 'think_pending' | 'decision_created' | 'proof_required' | 'owner_approval_required' | 'commit_pending' | 'closed';
  resumable: boolean;
  retry_after_ms: number | null;
  runtime_gate?: MarrowAgentRuntimeResult | null;
  phase_timings_ms: {
    runtime: number | null;
    think: number | null;
    commit: number | null;
    total: number;
  };
};

function autoPartial(input: {
  operationId: string;
  decisionId?: string | null;
  phase: MarrowAutoResult['phase'];
  runtimeGate?: MarrowAgentRuntimeResult | null;
  timings: Omit<MarrowAutoResult['phase_timings_ms'], 'total'>;
  startedAt: number;
  retryAfterMs?: number | null;
  resumable?: boolean;
}): MarrowAutoResult {
  const resumable = input.resumable !== false;
  return {
    operation_id: input.operationId,
    decision_id: input.decisionId || null,
    committed: false,
    phase: input.phase,
    resumable,
    retry_after_ms: resumable
      ? input.retryAfterMs === undefined ? 1_000 : input.retryAfterMs
      : null,
    ...(input.runtimeGate ? { runtime_gate: input.runtimeGate } : {}),
    phase_timings_ms: {
      ...input.timings,
      total: Date.now() - input.startedAt,
    },
  };
}

/**
 * Bounded outcome logging helper for tool hooks and simple integrations.
 * One outer invocation logs intent and, when an outcome is supplied, continues
 * resumable server phases so the outcome normally closes in-band. If the
 * caller's deadline is reached, the same operation ID resumes without opening
 * another decision.
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
    arbitration_receipt_id?: string;
    owner_approval_receipt_id?: string;
    action_for_gate?: string;
    surfaces?: string[];
    auto_gate?: boolean;
    operation_id?: string;
  },
  sessionId?: string,
  agentId?: string,
  timeoutMs?: number
): Promise<MarrowAutoResult> {
  const startedAt = Date.now();
  const responseBudgetMs = autoResponseBudget(timeoutMs);
  const operationId = resolveAutoOperationId(params.operation_id);
  const operationBinding = boundAutoOperation(operationId, autoOperationSignature({
    apiKey,
    baseUrl,
    agentId,
    sessionId,
    action: params.action,
    gateAction: params.action_for_gate || params.action,
    type: params.type || 'general',
    surfaces: params.surfaces,
    context: params.context,
  }));
  const timings: Omit<MarrowAutoResult['phase_timings_ms'], 'total'> = {
    runtime: null,
    think: null,
    commit: null,
  };
  let runtimeGate: MarrowAgentRuntimeResult | null = null;
  let gateReceiptId = params.gate_receipt_id;
  let proofCanClose = params.auto_gate !== true;

  if (params.auto_gate === true) {
    const phaseStarted = Date.now();
    if (operationBinding.runtimeGate) {
      runtimeGate = operationBinding.runtimeGate;
      timings.runtime = 0;
    } else {
      while (!runtimeGate) {
        const runtimeTimeout = createTimeoutSignal(responseBudgetMs, startedAt);
        try {
          runtimeGate = await marrowAgentRuntime(
            apiKey,
            baseUrl,
            {
              action: redactSensitiveText(params.action_for_gate || params.action),
              type: params.type || 'general',
              agent_id: agentId,
              session_id: sessionId,
              surfaces: params.surfaces,
              // Proof is commit evidence, not part of immutable runtime authorization.
              // Keeping it out makes missing -> supplied proof a monotonic continuation.
              context: { source: 'mcp_auto_risk_upgrade', operation_id: operationId },
            },
            sessionId,
            agentId,
            runtimeTimeout.signal,
            autoIdempotencyKey(operationId, 'runtime'),
          );
          operationBinding.runtimeGate = runtimeGate;
        } catch (error) {
          if (normalizeRequestError(error).code !== 'request_timeout'
            || !await waitForAutoContinuation({}, startedAt, responseBudgetMs)) {
            timings.runtime = Date.now() - phaseStarted;
            if (normalizeRequestError(error).code === 'request_timeout') {
              return autoPartial({ operationId, phase: 'runtime_pending', timings, startedAt });
            }
            throw error;
          }
        } finally {
          runtimeTimeout.cancel();
        }
      }
      timings.runtime = Date.now() - phaseStarted;
    }
    gateReceiptId = runtimeAuthorizationReceiptId(runtimeGate) || gateReceiptId;
    if (!gateReceiptId) {
      throw new Error('marrowAuto runtime phase did not return canonical runtime authorization');
    }
    proofCanClose = highRiskRuntimeCanClose(runtimeGate, params.proof, gateReceiptId)
      || highRiskRuntimeCanContinueWithProof(runtimeGate, params.proof, gateReceiptId);
  }

  const thinkStarted = Date.now();
  let decisionId = operationBinding.decisionId || null;
  const reusedDecision = Boolean(decisionId);
  while (!decisionId) {
    const thinkTimeout = createTimeoutSignal(responseBudgetMs, startedAt);
    let thinkResult: ThinkResult;
    try {
      thinkResult = await marrowThink(
        apiKey,
        baseUrl,
        {
          action: params.action,
          type: params.type || 'general',
          context: params.context,
          source_kind: 'agent_autonomous',
          source_confidence: 0.9,
          human_directed: false,
          source_meta: {
            channel: 'mcp',
            client: defaultSourceClient(),
            user_intent: 'operate',
            ...(params.source_meta || {}),
          },
        },
        sessionId,
        agentId,
        thinkTimeout.signal,
        {
          idempotencyKey: autoIdempotencyKey(operationId, 'think'),
          responseMode: 'ack',
        },
      );
    } catch (error) {
      if (normalizeRequestError(error).code !== 'request_timeout'
        || !await waitForAutoContinuation({}, startedAt, responseBudgetMs)) {
        timings.think = Date.now() - thinkStarted;
        if (normalizeRequestError(error).code === 'request_timeout') {
          return autoPartial({ operationId, phase: 'think_pending', runtimeGate, timings, startedAt });
        }
        throw error;
      }
      continue;
    } finally {
      thinkTimeout.cancel();
    }
    decisionId = typeof thinkResult.decision_id === 'string' && thinkResult.decision_id.trim()
      ? thinkResult.decision_id.trim()
      : null;
    if (decisionId) {
      operationBinding.decisionId = decisionId;
      break;
    }
    if (!isAutoPendingResponse(thinkResult, 'think_pending')) throw invalidResponseError();
    if (!await waitForAutoContinuation(thinkResult, startedAt, responseBudgetMs)) {
      timings.think = Date.now() - thinkStarted;
      return autoPartial({ operationId, phase: 'think_pending', runtimeGate, timings, startedAt });
    }
  }
  timings.think = reusedDecision ? 0 : Date.now() - thinkStarted;

  if (params.outcome === undefined || typeof params.success !== 'boolean') {
    return autoPartial({
      operationId,
      decisionId,
      phase: 'decision_created',
      runtimeGate,
      timings,
      startedAt,
      retryAfterMs: null,
    });
  }

  const runtimeRequiresOwnerApproval = Boolean(runtimeGate && (
    runtimeGate.risk_gate?.decision === 'review_required'
    || runtimeGate.gate_receipt?.decision === 'review_required'
    || runtimeGate.gate_receipt?.decision === 'owner_approval_required'
    || runtimeGate.gate_receipt?.owner_approval_required === true
    || runtimeGate.intervention?.decision === 'owner_approval_required'
    || runtimeGate.intervention?.enforcement?.owner_approval_required === true
    || runtimeGate.arbitration?.resolution === 'review_required'
    || runtimeGate.arbitration?.owner_approval_required === true
  ));
  const runtimeArbitrationReceiptId = runtimeGate?.arbitration?.receipt_id;
  const matchingRequiredApprovalReceipts = Boolean(
    params.owner_approval_receipt_id
    && (!runtimeArbitrationReceiptId
      || params.arbitration_receipt_id === runtimeArbitrationReceiptId)
  );

  if (runtimeRequiresOwnerApproval && !matchingRequiredApprovalReceipts) {
    return autoPartial({
      operationId,
      decisionId,
      phase: 'owner_approval_required',
      runtimeGate,
      timings,
      startedAt,
      resumable: false,
    });
  }

  if (!proofCanClose) {
    // A review-required gate becomes eligible for exactly one backend-verified
    // commit only after the caller supplies measured proof and the explicit
    // server-issued approval receipt. The backend remains authoritative for
    // receipt ownership, scope, expiry, single use, and arbitration matching.
    const ownerApprovedCommitAttempt = Boolean(
      runtimeRequiresOwnerApproval
      && params.proof
      && Object.keys(params.proof).length > 0
      && gateReceiptId
      && matchingRequiredApprovalReceipts
    );
    if (ownerApprovedCommitAttempt) proofCanClose = true;
  }

  if (!proofCanClose) {
    return autoPartial({
      operationId,
      decisionId,
      phase: 'proof_required',
      runtimeGate,
      timings,
      startedAt,
      retryAfterMs: null,
    });
  }

  if (Date.now() - startedAt >= responseBudgetMs - 100) {
    return autoPartial({
      operationId,
      decisionId,
      phase: 'commit_pending',
      runtimeGate,
      timings,
      startedAt,
    });
  }

  const commitStarted = Date.now();
  let commitResult: CommitResult & AutoPendingResponse & { runtime_gate?: MarrowAgentRuntimeResult | null };
  while (true) {
    const commitTimeout = createTimeoutSignal(responseBudgetMs, startedAt);
    try {
      commitResult = await marrowCommit(
        apiKey,
        baseUrl,
        {
          decision_id: decisionId,
          success: params.success,
          outcome: params.outcome,
          proof: params.proof,
          gate_receipt_id: gateReceiptId,
          arbitration_receipt_id: params.arbitration_receipt_id,
          owner_approval_receipt_id: params.owner_approval_receipt_id,
          action: params.action_for_gate || params.action,
          type: params.type || 'general',
          surfaces: params.surfaces,
          auto_gate: false,
        },
        sessionId,
        agentId,
        commitTimeout.signal,
        autoIdempotencyKey(operationId, 'commit'),
      );
    } catch (error) {
      if (normalizeRequestError(error).code !== 'request_timeout'
        || !await waitForAutoContinuation({}, startedAt, responseBudgetMs)) {
        timings.commit = Date.now() - commitStarted;
        if (normalizeRequestError(error).code === 'request_timeout') {
          return autoPartial({ operationId, decisionId, phase: 'commit_pending', runtimeGate, timings, startedAt });
        }
        throw error;
      }
      continue;
    } finally {
      commitTimeout.cancel();
    }
    if (commitResult.committed) break;
    if (!isAutoPendingResponse(commitResult, 'commit_pending')) {
      timings.commit = Date.now() - commitStarted;
      return autoPartial({ operationId, decisionId, phase: 'commit_pending', runtimeGate, timings, startedAt });
    }
    if (!await waitForAutoContinuation(commitResult, startedAt, responseBudgetMs)) {
      timings.commit = Date.now() - commitStarted;
      return autoPartial({ operationId, decisionId, phase: 'commit_pending', runtimeGate, timings, startedAt });
    }
  }
  timings.commit = Date.now() - commitStarted;

  return {
    operation_id: operationId,
    decision_id: decisionId,
    committed: true,
    phase: 'closed',
    resumable: false,
    retry_after_ms: null,
    ...(runtimeGate ? { runtime_gate: runtimeGate } : {}),
    phase_timings_ms: {
      ...timings,
      total: Date.now() - startedAt,
    },
  };
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
  const brief = json.data as MarrowDecisionBriefResult & {
    top_outcomes?: string[];
    lesson?: string | null;
    client_update?: Record<string, unknown>;
    has_memory?: boolean;
    low_history?: boolean;
    decision_count?: number;
    decisions_matched?: number;
  };
  const topOutcomes = Array.isArray(brief.top_outcomes) && brief.top_outcomes.length
    ? brief.top_outcomes
    : Array.isArray(brief.failure_alerts) ? brief.failure_alerts.map((item) => item.message).slice(0, 5) : [];
  const lesson = brief.lesson || topOutcomes[0] || null;
  const decisionCount = Number(brief.decision_count || 0);
  const hasMemory = brief.has_memory === true || decisionCount > 0 || Boolean(lesson);
  const summary = typeof brief.summary === 'string' ? brief.summary.trim() : '';
  const warmingSummary = /guidance is warming/i.test(summary);
  const nextAction = typeof brief.next_actions?.[0] === 'string' ? brief.next_actions[0].trim() : '';
  const answer = [
    summary && !warmingSummary ? summary : null,
    lesson,
    !lesson && nextAction && !/warming|historical guidance/i.test(nextAction) ? nextAction : null,
  ].filter(Boolean).join(' ');
  return {
    answer,
    stats: null,
    top_outcomes: topOutcomes,
    lesson,
    has_memory: hasMemory,
    decision_count: decisionCount,
    decisions_matched: Number(brief.decisions_matched || 0) || (lesson ? Math.max(decisionCount, topOutcomes.length, 1) : decisionCount),
    low_history: lesson || hasMemory ? false : brief.low_history === true,
    client_update: brief.client_update,
  } as MarrowAskResult;
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
  const res = await fetch(`${baseUrl}/v1/agent/status?fast=1&compact=1`, {
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
  idempotencyKeyOverride?: string,
): Promise<MarrowAgentRuntimeResult> {
  const body = {
    ...input,
    agent_id: input.agent_id || agentId,
    session_id: input.session_id || sessionId,
  };
  const idempotencyKey = idempotencyKeyOverride || `mcp-runtime-${randomUUID()}`;
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
  const runtime = requireRuntimeResult(json.data);
  if (!runtime.action && typeof input.action === 'string' && input.action.trim()) {
    runtime.action = input.action;
  }
  return runtime;
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
  agentId?: string,
  signal?: AbortSignal,
): Promise<unknown> {
  const qs = new URLSearchParams();
  if (options.status) qs.set('status', options.status);
  if (options.agentId || agentId) qs.set('agent_id', options.agentId || agentId || '');
  if (options.limit) qs.set('limit', String(options.limit));
  const res = await fetch(`${baseUrl}/v1/fleet/handoffs/status${qs.toString() ? `?${qs.toString()}` : ''}`, {
    headers: buildHeaders(apiKey, sessionId, undefined, agentId),
    signal,
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
