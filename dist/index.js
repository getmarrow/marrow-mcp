"use strict";
/**
 * @getmarrow/mcp — API Functions
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.validatePathParam = validatePathParam;
exports.validateBaseUrl = validateBaseUrl;
exports.marrowCreateKey = marrowCreateKey;
exports.marrowListKeys = marrowListKeys;
exports.marrowGetKey = marrowGetKey;
exports.marrowRevokeKey = marrowRevokeKey;
exports.marrowRotateKey = marrowRotateKey;
exports.marrowGetKeyAudit = marrowGetKeyAudit;
exports.marrowThink = marrowThink;
exports.marrowCommit = marrowCommit;
exports.marrowAuto = marrowAuto;
exports.marrowAgentPatterns = marrowAgentPatterns;
exports.marrowOrient = marrowOrient;
exports.marrowAsk = marrowAsk;
exports.marrowStatus = marrowStatus;
exports.marrowWorkflow = marrowWorkflow;
exports.marrowDashboard = marrowDashboard;
exports.marrowDigest = marrowDigest;
exports.marrowAgentStatus = marrowAgentStatus;
exports.marrowValueReport = marrowValueReport;
exports.marrowDecisionBrief = marrowDecisionBrief;
exports.marrowWorkflowGate = marrowWorkflowGate;
exports.marrowAgentRuntime = marrowAgentRuntime;
exports.marrowRecommendGovernanceMode = marrowRecommendGovernanceMode;
exports.marrowListPolicyProfiles = marrowListPolicyProfiles;
exports.marrowCreatePolicyProfile = marrowCreatePolicyProfile;
exports.marrowAssignProjectPolicyProfile = marrowAssignProjectPolicyProfile;
exports.marrowResolvePolicy = marrowResolvePolicy;
exports.marrowFirstValue = marrowFirstValue;
exports.marrowAgentPerformance = marrowAgentPerformance;
exports.marrowFleetLessons = marrowFleetLessons;
exports.marrowRecordDeploymentMemory = marrowRecordDeploymentMemory;
exports.marrowCreateHandoff = marrowCreateHandoff;
exports.marrowUpdateHandoff = marrowUpdateHandoff;
exports.marrowHandoffStatus = marrowHandoffStatus;
exports.marrowNudge = marrowNudge;
exports.marrowSessionEnd = marrowSessionEnd;
exports.marrowAcceptDetected = marrowAcceptDetected;
exports.marrowListTemplates = marrowListTemplates;
exports.marrowInstallTemplate = marrowInstallTemplate;
const sdk_1 = require("@getmarrow/sdk");
const redact_1 = require("./redact");
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
function createSdkClient(apiKey, baseUrl, sessionId, agentId) {
    return new sdk_1.MarrowClient(apiKey, { baseUrl, sessionId, agentId });
}
function runtimeGateReceiptId(runtime) {
    if (!runtime)
        return null;
    return runtime.gate_receipt?.id || runtime.gate_receipt_id || null;
}
function clampPeriodDays(value, defaultDays = 7) {
    const parsed = typeof value === 'number' ? value : parseInt(String(value || defaultDays), 10);
    if (!Number.isFinite(parsed))
        return defaultDays;
    return Math.min(90, Math.max(1, Math.floor(parsed)));
}
async function marrowCreateKey(apiKey, baseUrl, params, sessionId, agentId) {
    return createSdkClient(apiKey, baseUrl, sessionId, agentId).createApiKey(params);
}
async function marrowListKeys(apiKey, baseUrl, sessionId, agentId) {
    return createSdkClient(apiKey, baseUrl, sessionId, agentId).listApiKeys();
}
async function marrowGetKey(apiKey, baseUrl, id, sessionId, agentId) {
    return createSdkClient(apiKey, baseUrl, sessionId, agentId).getApiKey(id);
}
async function marrowRevokeKey(apiKey, baseUrl, id, sessionId, agentId) {
    return createSdkClient(apiKey, baseUrl, sessionId, agentId).revokeApiKey(id);
}
async function marrowRotateKey(apiKey, baseUrl, id, sessionId, agentId) {
    return createSdkClient(apiKey, baseUrl, sessionId, agentId).rotateApiKey(id);
}
async function marrowGetKeyAudit(apiKey, baseUrl, params, sessionId, agentId) {
    return createSdkClient(apiKey, baseUrl, sessionId, agentId).getKeyAudit(params);
}
/**
 * Log intent and get collective intelligence before acting.
 */
async function marrowThink(apiKey, baseUrl, params, sessionId, agentId) {
    const body = {
        action: (0, redact_1.redactSensitiveText)(params.action),
        type: params.type || 'general',
    };
    if (params.context) {
        body.context = (0, redact_1.redactSensitiveValue)(params.context);
    }
    body.source_kind = params.source_kind || 'agent_autonomous';
    body.source_confidence = params.source_confidence ?? 0.9;
    body.human_directed = params.human_directed ?? false;
    if (params.instruction_ref !== undefined)
        body.instruction_ref = params.instruction_ref;
    if (params.instruction !== undefined)
        body.instruction = (0, redact_1.redactSensitiveText)(params.instruction);
    if (params.instruction_hash !== undefined)
        body.instruction_hash = params.instruction_hash;
    body.source_meta = (0, redact_1.redactSensitiveValue)({
        channel: 'mcp',
        client: 'openclaw',
        user_intent: 'operate',
        ...(params.source_meta || {}),
    });
    if (params.checkLoop) {
        body.checkLoop = true;
    }
    if (params.previous_decision_id) {
        body.previous_decision_id = params.previous_decision_id;
        body.previous_success = params.previous_success ?? true;
        body.previous_outcome = (0, redact_1.redactSensitiveText)(params.previous_outcome ?? '');
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
    let runtimeGate = null;
    let gateReceiptId = params.gate_receipt_id || params.gate_receipt;
    if (!gateReceiptId && params.auto_gate !== false && params.action) {
        try {
            runtimeGate = await marrowAgentRuntime(apiKey, baseUrl, {
                action: (0, redact_1.redactSensitiveText)(params.action),
                type: params.type || 'handoff',
                surfaces: params.surfaces || ['handoff'],
                context: { mcp_commit_auto_gate: true },
                proof: params.proof ? (0, redact_1.redactSensitiveValue)(params.proof) : undefined,
            }, sessionId, agentId);
        }
        catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            throw new Error(`marrowCommit auto_gate failed before outcome closure: ${msg}`);
        }
        gateReceiptId = runtimeGateReceiptId(runtimeGate) || undefined;
        if (!gateReceiptId && runtimeGate?.gate_receipt?.required) {
            throw new Error('marrowCommit auto_gate required a gate receipt, but /v1/agent/runtime did not return one');
        }
    }
    const body = {
        decision_id: params.decision_id,
        success: params.success,
        outcome: (0, redact_1.redactSensitiveText)(params.outcome),
        caused_by: params.caused_by ? (0, redact_1.redactSensitiveText)(params.caused_by) : undefined,
    };
    if (params.proof)
        body.proof = (0, redact_1.redactSensitiveValue)(params.proof);
    if (gateReceiptId)
        body.gate_receipt_id = gateReceiptId;
    const res = await fetch(`${baseUrl}/v1/agent/commit`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(body),
    });
    const json = await safeJsonResponse(res);
    return { ...json.data, runtime_gate: runtimeGate };
}
function createTimeoutSignal(timeoutMs, startedAt) {
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
async function marrowAuto(apiKey, baseUrl, params, sessionId, agentId, timeoutMs) {
    const startedAt = Date.now();
    const thinkTimeout = createTimeoutSignal(timeoutMs, startedAt);
    let thinkJson;
    try {
        const thinkRes = await fetch(`${baseUrl}/v1/agent/think`, {
            method: 'POST',
            headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
            body: JSON.stringify({
                action: (0, redact_1.redactSensitiveText)(params.action),
                type: params.type || 'general',
                context: params.context ? (0, redact_1.redactSensitiveValue)(params.context) : undefined,
                source_kind: 'agent_autonomous',
                source_confidence: 0.9,
                human_directed: false,
                source_meta: (0, redact_1.redactSensitiveValue)({
                    channel: 'mcp',
                    client: 'openclaw',
                    user_intent: 'operate',
                    ...(params.source_meta || {}),
                }),
            }),
            signal: thinkTimeout.signal,
        });
        thinkJson = await safeJsonResponse(thinkRes);
    }
    finally {
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
        await marrowCommit(apiKey, baseUrl, {
            decision_id: decisionId,
            success: params.success ?? true,
            outcome: params.outcome,
            proof: params.proof,
            gate_receipt_id: params.gate_receipt_id,
            action: params.action_for_gate || params.action,
            type: params.type || 'general',
            surfaces: params.surfaces,
        }, sessionId, agentId);
    }
    finally {
        commitTimeout.cancel();
    }
    return { decision_id: decisionId, committed: true };
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
 * Get agent-native proof that Marrow is active and collecting useful signal.
 */
async function marrowAgentStatus(apiKey, baseUrl, period = '7d', agentIdFilter, sessionId, agentId) {
    const days = parseInt(period) || 7;
    const qs = new URLSearchParams({ period: String(days) });
    if (agentIdFilter)
        qs.set('agent_id', agentIdFilter);
    const res = await fetch(`${baseUrl}/v1/analytics/agent-status?${qs.toString()}`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
/**
 * Get owner-ready proof of Marrow value for an agent or fleet.
 */
async function marrowValueReport(apiKey, baseUrl, period = '7d', agentIdFilter, sessionId, agentId) {
    const days = clampPeriodDays(period);
    const qs = new URLSearchParams({ period: String(days) });
    if (agentIdFilter)
        qs.set('agent_id', agentIdFilter);
    const res = await fetch(`${baseUrl}/v1/analytics/value-report?${qs.toString()}`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
/**
 * Get one pre-action operating brief for risky or meaningful agent work.
 */
async function marrowDecisionBrief(apiKey, baseUrl, input, sessionId, agentId) {
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
async function marrowWorkflowGate(apiKey, baseUrl, input, sessionId, agentId) {
    const res = await fetch(`${baseUrl}/v1/workflow/gate`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(input),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
async function marrowAgentRuntime(apiKey, baseUrl, input, sessionId, agentId) {
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
async function marrowRecommendGovernanceMode(apiKey, baseUrl, input, sessionId, agentId) {
    const res = await fetch(`${baseUrl}/v1/agent/mode/recommend`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(input),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
async function marrowListPolicyProfiles(apiKey, baseUrl, sessionId, agentId) {
    const res = await fetch(`${baseUrl}/v1/agent/policy-profiles`, {
        method: 'GET',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
async function marrowCreatePolicyProfile(apiKey, baseUrl, input, sessionId, agentId) {
    const res = await fetch(`${baseUrl}/v1/agent/policy-profiles`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(input),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
async function marrowAssignProjectPolicyProfile(apiKey, baseUrl, input, sessionId, agentId) {
    const res = await fetch(`${baseUrl}/v1/agent/project-policy-profile`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(input),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
async function marrowResolvePolicy(apiKey, baseUrl, input, sessionId, agentId) {
    const res = await fetch(`${baseUrl}/v1/agent/policy/resolve`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(input),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
async function marrowFirstValue(apiKey, baseUrl, input = {}, sessionId, agentId) {
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
async function marrowAgentPerformance(apiKey, baseUrl, period = '7d', agentIdFilter, sessionId, agentId) {
    const qs = new URLSearchParams({ period: String(clampPeriodDays(period)) });
    if (agentIdFilter || agentId)
        qs.set('agent_id', agentIdFilter || agentId || '');
    const res = await fetch(`${baseUrl}/v1/analytics/agent-performance?${qs.toString()}`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
async function marrowFleetLessons(apiKey, baseUrl, options = {}, sessionId, agentId) {
    const qs = new URLSearchParams();
    if (options.query)
        qs.set('query', options.query);
    if (options.type)
        qs.set('type', options.type);
    if (options.agentId || agentId)
        qs.set('agent_id', options.agentId || agentId || '');
    if (options.limit)
        qs.set('limit', String(options.limit));
    const res = await fetch(`${baseUrl}/v1/fleet/lessons${qs.toString() ? `?${qs.toString()}` : ''}`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
async function marrowRecordDeploymentMemory(apiKey, baseUrl, input, sessionId, agentId) {
    const res = await fetch(`${baseUrl}/v1/fleet/deployment-memory`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify({
            ...input,
            agent_id: String(input.agent_id || agentId || ''),
            tests: Array.isArray(input.tests) ? input.tests : undefined,
        }),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
async function marrowCreateHandoff(apiKey, baseUrl, input, sessionId, agentId) {
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
async function marrowUpdateHandoff(apiKey, baseUrl, handoffId, input, sessionId, agentId) {
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
async function marrowHandoffStatus(apiKey, baseUrl, options = {}, sessionId, agentId) {
    const qs = new URLSearchParams();
    if (options.status)
        qs.set('status', options.status);
    if (options.agentId || agentId)
        qs.set('agent_id', options.agentId || agentId || '');
    if (options.limit)
        qs.set('limit', String(options.limit));
    const res = await fetch(`${baseUrl}/v1/fleet/handoffs/status${qs.toString() ? `?${qs.toString()}` : ''}`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
/**
 * Get a periodic improvement nudge when Marrow has something worth surfacing.
 */
async function marrowNudge(apiKey, baseUrl, sessionId, agentId) {
    const res = await fetch(`${baseUrl}/v1/agent/nudge`, {
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