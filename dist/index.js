"use strict";
/**
 * @getmarrow/mcp — API Functions
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.validatePathParam = validatePathParam;
exports.validateBaseUrl = validateBaseUrl;
exports.marrowThink = marrowThink;
exports.marrowCommit = marrowCommit;
exports.marrowAgentPatterns = marrowAgentPatterns;
exports.marrowOrient = marrowOrient;
exports.marrowAsk = marrowAsk;
exports.marrowStatus = marrowStatus;
exports.marrowWorkflow = marrowWorkflow;
exports.marrowDashboard = marrowDashboard;
exports.marrowDigest = marrowDigest;
exports.marrowSessionEnd = marrowSessionEnd;
exports.marrowAcceptDetected = marrowAcceptDetected;
exports.marrowListTemplates = marrowListTemplates;
exports.marrowInstallTemplate = marrowInstallTemplate;
/**
 * Validate a path parameter to prevent path traversal attacks.
 * Only allows alphanumeric, hyphens, underscores, and dots.
 */
function validatePathParam(value, paramName) {
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
function validateBaseUrl(rawUrl) {
    try {
        const parsed = new URL(rawUrl);
        if (parsed.protocol !== 'https:') {
            throw new Error('MARROW_BASE_URL must use HTTPS');
        }
        return rawUrl.replace(/\/+$/, '');
    }
    catch (err) {
        if (err instanceof Error && err.message.includes('HTTPS'))
            throw err;
        throw new Error(`MARROW_BASE_URL is not a valid URL: ${rawUrl}`);
    }
}
/**
 * Check HTTP response status and parse JSON safely.
 * Throws a descriptive error for non-OK responses.
 */
async function safeJsonResponse(res) {
    if (!res.ok) {
        let detail = '';
        try {
            detail = await res.text();
        }
        catch { /* ignore */ }
        throw new Error(`API error ${res.status}: ${detail.slice(0, 200)}`);
    }
    const json = await res.json();
    if (json.error) {
        throw new Error(json.error);
    }
    return json;
}
function buildHeaders(apiKey, sessionId, contentType, agentId) {
    const headers = {
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
    return headers;
}
/**
 * Log intent and get collective intelligence before acting.
 */
async function marrowThink(apiKey, baseUrl, params, sessionId, agentId) {
    const body = {
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
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(body),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
/**
 * Explicitly commit the result of an action to Marrow.
 */
async function marrowCommit(apiKey, baseUrl, params, sessionId, agentId) {
    const res = await fetch(`${baseUrl}/v1/agent/commit`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(params),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
/**
 * Get agent patterns and failure history.
 */
async function marrowAgentPatterns(apiKey, baseUrl, params, sessionId, agentId) {
    const qs = new URLSearchParams();
    if (params?.type) {
        qs.set('type', params.type);
    }
    if (params?.limit) {
        qs.set('limit', String(params.limit));
    }
    const url = `${baseUrl}/v1/agent/patterns` +
        (qs.toString() ? '?' + qs.toString() : '');
    const res = await fetch(url, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
/**
 * Get failure warnings from history before acting.
 * When autoWarn=true, hits the enhanced orient endpoint for active warnings.
 */
async function marrowOrient(apiKey, baseUrl, params, sessionId, agentId) {
    // If autoWarn, hit the new POST endpoint
    if (params?.autoWarn) {
        const res = await fetch(`${baseUrl}/v1/agent/orient`, {
            method: 'POST',
            headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
            body: JSON.stringify({
                task: params.taskType,
                autoWarn: true,
            }),
        });
        const json = await safeJsonResponse(res);
        const warnings = (json.data?.warnings || []).map((w) => ({
            type: String(w.pattern || ''),
            failureRate: 0, // computed server-side from failure count
            message: String(w.message || ''),
            severity: w.severity,
        }));
        return {
            warnings,
            serverWarnings: json.data?.warnings || [],
            loopState: json.data?.loopState || { isOpen: false, lastCommit: null },
            shouldPause: warnings.some((w) => w.severity === 'HIGH'),
        };
    }
    // Legacy: compute from agent patterns
    const patterns = await marrowAgentPatterns(apiKey, baseUrl, params?.taskType ? { type: params.taskType } : undefined, sessionId, agentId);
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
async function marrowAsk(apiKey, baseUrl, params, sessionId, agentId) {
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
async function marrowStatus(apiKey, baseUrl, sessionId, agentId) {
    const res = await fetch(`${baseUrl}/health`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
// ─── Workflow Registry API ───────────────────────────────────────
async function marrowWorkflow(apiKey, baseUrl, params, sessionId, agentId) {
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
            const json = await res.json();
            if (json.error)
                return { success: false, error: json.error };
            return { success: true, data: json.data };
        }
        case 'list': {
            const qs = new URLSearchParams();
            if (params.status)
                qs.set('status', params.status);
            if (params.tags && params.tags.length > 0)
                qs.set('tags', params.tags.join(','));
            const res = await fetch(`${baseUrl}/v1/workflows?${qs.toString()}`, { headers });
            const json = await res.json();
            if (json.error)
                return { success: false, error: json.error };
            return { success: true, data: json.data };
        }
        case 'get': {
            if (!params.workflowId)
                return { success: false, error: 'workflowId required' };
            const safeId = validatePathParam(params.workflowId, 'workflowId');
            const res = await fetch(`${baseUrl}/v1/workflows/${safeId}`, { headers });
            const json = await res.json();
            if (json.error)
                return { success: false, error: json.error };
            return { success: true, data: json.data };
        }
        case 'update': {
            if (!params.workflowId)
                return { success: false, error: 'workflowId required' };
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
            const json = await res.json();
            if (json.error)
                return { success: false, error: json.error };
            return { success: true, data: json.data };
        }
        case 'start': {
            if (!params.workflowId)
                return { success: false, error: 'workflowId required' };
            if (!params.agentId)
                return { success: false, error: 'agentId required' };
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
            const json = await res.json();
            if (json.error)
                return { success: false, error: json.error };
            return { success: true, data: json.data };
        }
        case 'advance': {
            if (!params.workflowId)
                return { success: false, error: 'workflowId required' };
            if (!params.instanceId)
                return { success: false, error: 'instanceId required' };
            if (params.stepCompleted === undefined)
                return { success: false, error: 'stepCompleted required' };
            if (params.outcome === undefined)
                return { success: false, error: 'outcome required' };
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
            const json = await res.json();
            if (json.error)
                return { success: false, error: json.error };
            return { success: true, data: json.data };
        }
        case 'instances': {
            if (!params.workflowId)
                return { success: false, error: 'workflowId required' };
            const safeId = validatePathParam(params.workflowId, 'workflowId');
            const qs = new URLSearchParams();
            if (params.status)
                qs.set('status', params.status);
            const res = await fetch(`${baseUrl}/v1/workflows/${safeId}/instances?${qs.toString()}`, { headers });
            const json = await res.json();
            if (json.error)
                return { success: false, error: json.error };
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
async function marrowDashboard(apiKey, baseUrl, sessionId, agentId) {
    const res = await fetch(`${baseUrl}/v1/dashboard`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
/**
 * Get periodic summary of agent activity and Marrow impact.
 */
async function marrowDigest(apiKey, baseUrl, period = '7d', sessionId, agentId) {
    const days = parseInt(period) || 7;
    const res = await fetch(`${baseUrl}/v1/digest?period=${days}`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
/**
 * Explicitly end the current session.
 */
async function marrowSessionEnd(apiKey, baseUrl, autoCommitOpen = false, sessionId, agentId) {
    const res = await fetch(`${baseUrl}/v1/agent/session/end`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify({ auto_commit_open: autoCommitOpen }),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
/**
 * Convert a detected decision pattern into an enforced workflow.
 */
async function marrowAcceptDetected(apiKey, baseUrl, detectedId, sessionId, agentId) {
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
async function marrowListTemplates(apiKey, baseUrl, params, sessionId, agentId) {
    const qs = new URLSearchParams();
    if (params?.industry)
        qs.set('industry', params.industry);
    if (params?.category)
        qs.set('category', params.category);
    if (params?.limit)
        qs.set('limit', String(params.limit));
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
async function marrowInstallTemplate(apiKey, baseUrl, slug, sessionId, agentId) {
    const safeSlug = validatePathParam(slug, 'slug');
    const res = await fetch(`${baseUrl}/v1/templates/${safeSlug}/install`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
//# sourceMappingURL=index.js.map