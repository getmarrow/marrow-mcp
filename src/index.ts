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
} from './types';

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

function buildHeaders(
  apiKey: string,
  sessionId?: string,
  contentType?: string
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
  return headers;
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
  },
  sessionId?: string
): Promise<ThinkResult> {
  const body: Record<string, unknown> = {
    action: params.action,
    type: params.type || 'general',
  };

  if (params.context) {
    body.context = params.context;
  }

  if (params.checkLoop) {
    body.checkLoop = true;
  }

  if (params.previous_decision_id) {
    body.previous_decision_id = params.previous_decision_id;
    body.previous_success = params.previous_success ?? true;
    body.previous_outcome = params.previous_outcome ?? '';
  }

  const res = await fetch(`${baseUrl}/v1/agent/think`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json'),
    body: JSON.stringify(body),
  });

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
  },
  sessionId?: string
): Promise<CommitResult> {
  const res = await fetch(`${baseUrl}/v1/agent/commit`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json'),
    body: JSON.stringify(params),
  });

  const json = await safeJsonResponse(res);
  return json.data;
}

/**
 * Get agent patterns and failure history.
 */
export async function marrowAgentPatterns(
  apiKey: string,
  baseUrl: string,
  params?: { type?: string; limit?: number },
  sessionId?: string
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
    headers: buildHeaders(apiKey, sessionId),
  });

  const json = await safeJsonResponse(res);
  return json.data;
}

/**
 * Get failure warnings from history before acting.
 * When autoWarn=true, hits the enhanced orient endpoint for active warnings.
 */
export async function marrowOrient(
  apiKey: string,
  baseUrl: string,
  params?: { taskType?: string; autoWarn?: boolean },
  sessionId?: string
): Promise<OrientResult> {
  // If autoWarn, hit the new POST endpoint
  if (params?.autoWarn) {
    const res = await fetch(`${baseUrl}/v1/agent/orient`, {
      method: 'POST',
      headers: buildHeaders(apiKey, sessionId, 'application/json'),
      body: JSON.stringify({
        task: params.taskType,
        autoWarn: true,
      }),
    });

    const json = await safeJsonResponse(res);

    const warnings = (json.data?.warnings || []).map((w: Record<string, unknown>) => ({
      type: String(w.pattern || ''),
      failureRate: 0, // computed server-side from failure count
      message: String(w.message || ''),
      severity: w.severity as 'HIGH' | 'MEDIUM' | 'LOW',
    }));

    return {
      warnings,
      serverWarnings: json.data?.warnings || [],
      loopState: json.data?.loopState || { isOpen: false, lastCommit: null },
      shouldPause: warnings.some((w: { severity?: string }) => w.severity === 'HIGH'),
    };
  }

  // Legacy: compute from agent patterns
  const patterns = await marrowAgentPatterns(
    apiKey,
    baseUrl,
    params?.taskType ? { type: params.taskType } : undefined,
    sessionId
  );

  const warnings = patterns.failure_patterns
    .filter((p) => p.failure_rate > 0.15)
    .map((p) => ({
      type: p.decision_type,
      failureRate: p.failure_rate,
      message: `${p.decision_type} has ${Math.round(p.failure_rate * 100)}% failure rate over ${p.count} decisions — review lessons before acting`,
    }));

  return {
    warnings,
    shouldPause: warnings.some((w) => w.failureRate > 0.4),
  };
}

/**
 * Query the collective hive for failure patterns and recommendations.
 */
export async function marrowAsk(
  apiKey: string,
  baseUrl: string,
  params: { query: string },
  sessionId?: string
): Promise<MarrowAskResult> {
  const res = await fetch(`${baseUrl}/v1/agent/ask`, {
    method: 'POST',
    headers: buildHeaders(apiKey, sessionId, 'application/json'),
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
  sessionId?: string
): Promise<StatusResult> {
  const res = await fetch(`${baseUrl}/health`, {
    headers: buildHeaders(apiKey, sessionId),
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
  sessionId?: string
): Promise<WorkflowResult> {
  const headers = buildHeaders(apiKey, sessionId, 'application/json');

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
