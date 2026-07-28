/**
 * @getmarrow/mcp — API Functions
 */

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

export type { Narrative, CommitResult } from './types';

const SOURCE_CLIENTS = new Set(['claude-code', 'cursor', 'windsurf', 'openclaw', 'codex', 'gemini', 'grok', 'deepseek', 'qwen', 'kimi', 'minimax', 'cline', 'opencode', 'hermes', 'glm', 'custom', 'unknown']);

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
    let detail = '';
    try { detail = await res.text(); } catch { /* ignore */ }
    throw new Error(`API error ${res.status}: ${detail.slice(0, 200)}`);
  }
  const json = await res.json();
  if (json.error) {
    throw new Error(json.error);
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
  agentId?: string
): Promise<ThinkResult> {
  const body: Record<string, unknown> = {
    action: redactSensitiveText(params.action),
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

  const commitTimeout = createTimeoutSignal(timeoutMs, startedAt);
  try {
    await marrowCommit(
      apiKey,
      baseUrl,
      {
        decision_id: decisionId,
        success: params.success ?? true,
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
  agentId?: string
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
    agentId
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
  agentId?: string
): Promise<MarrowAskResult> {
  const res = await fetch(`${baseUrl}/v1/agent/ask`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    body: JSON.stringify({ query: params.query }),
  });

  const json = await safeJsonResponse(res);
  return json.data;
}

/**
 * Get API health status.
 */
export async function marrowStatus(
  apiKey: string,
  baseUrl: string,
  sessionId?: string,
  agentId?: string
): Promise<StatusResult> {
  const res = await fetch(`${baseUrl}/health`, {
    headers: buildHeaders(apiKey, sessionId, undefined, agentId),
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
  agentId?: string
): Promise<Record<string, unknown>> {
  const qs = fast ? '?fast=1' : '';
  const res = await fetch(`${baseUrl}/v1/agent/status${qs}`, {
    headers: buildHeaders(apiKey, sessionId, undefined, agentId),
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
  agentId?: string
): Promise<MarrowAgentRuntimeResult> {
  const body = {
    ...input,
    agent_id: input.agent_id || agentId,
    session_id: input.session_id || sessionId,
  };
  const res = await fetch(`${baseUrl}/v1/agent/runtime`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    body: JSON.stringify(body),
  });
  const json = await safeJsonResponse(res);
  return json.data;
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
