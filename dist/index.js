"use strict";
/**
 * @getmarrow/mcp — API Functions
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.marrowThink = marrowThink;
exports.marrowCommit = marrowCommit;
exports.marrowAgentPatterns = marrowAgentPatterns;
exports.marrowOrient = marrowOrient;
exports.marrowAsk = marrowAsk;
exports.marrowStatus = marrowStatus;
function buildHeaders(apiKey, sessionId, contentType) {
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
    return headers;
}
/**
 * Log intent and get collective intelligence before acting.
 */
async function marrowThink(apiKey, baseUrl, params, sessionId) {
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
        headers: buildHeaders(apiKey, sessionId, 'application/json'),
        body: JSON.stringify(body),
    });
    const json = await res.json();
    if (json.error) {
        throw new Error(json.error);
    }
    return json.data;
}
/**
 * Explicitly commit the result of an action to Marrow.
 */
async function marrowCommit(apiKey, baseUrl, params, sessionId) {
    const res = await fetch(`${baseUrl}/v1/agent/commit`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json'),
        body: JSON.stringify(params),
    });
    const json = await res.json();
    if (json.error) {
        throw new Error(json.error);
    }
    return json.data;
}
/**
 * Get agent patterns and failure history.
 */
async function marrowAgentPatterns(apiKey, baseUrl, params, sessionId) {
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
        headers: buildHeaders(apiKey, sessionId),
    });
    const json = await res.json();
    if (json.error) {
        throw new Error(json.error);
    }
    return json.data;
}
/**
 * Get failure warnings from history before acting.
 * When autoWarn=true, hits the enhanced orient endpoint for active warnings.
 */
async function marrowOrient(apiKey, baseUrl, params, sessionId) {
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
        const json = await res.json();
        if (json.error)
            throw new Error(json.error);
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
    const patterns = await marrowAgentPatterns(apiKey, baseUrl, params?.taskType ? { type: params.taskType } : undefined, sessionId);
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
async function marrowAsk(apiKey, baseUrl, params, sessionId) {
    const res = await fetch(`${baseUrl}/v1/agent/ask`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json'),
        body: JSON.stringify({ query: params.query }),
    });
    const json = await res.json();
    if (json.error) {
        throw new Error(json.error);
    }
    return json.data;
}
/**
 * Get API health status.
 */
async function marrowStatus(apiKey, baseUrl, sessionId) {
    const res = await fetch(`${baseUrl}/v1/health`, {
        headers: buildHeaders(apiKey, sessionId),
    });
    const json = await res.json();
    if (json.error) {
        throw new Error(json.error);
    }
    return json.data;
}
//# sourceMappingURL=index.js.map