"use strict";
/**
 * @getmarrow/mcp — API Functions
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.MARROW_AUTO_RESPONSE_BUDGET_MAX_MS = void 0;
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
exports.marrowModelUsage = marrowModelUsage;
exports.marrowAuto = marrowAuto;
exports.marrowAgentPatterns = marrowAgentPatterns;
exports.marrowOrient = marrowOrient;
exports.marrowAsk = marrowAsk;
exports.marrowStatus = marrowStatus;
exports.marrowWorkflow = marrowWorkflow;
exports.marrowDashboard = marrowDashboard;
exports.marrowDigest = marrowDigest;
exports.marrowAgentStatus = marrowAgentStatus;
exports.marrowRuntimeStatus = marrowRuntimeStatus;
exports.marrowAgentContext = marrowAgentContext;
exports.marrowValueReport = marrowValueReport;
exports.marrowDecisionBrief = marrowDecisionBrief;
exports.marrowWorkflowGate = marrowWorkflowGate;
exports.marrowAgentRuntime = marrowAgentRuntime;
exports.marrowEnforcement = marrowEnforcement;
exports.marrowArbitrate = marrowArbitrate;
exports.marrowGovernanceControlPlane = marrowGovernanceControlPlane;
exports.marrowHermesIntegration = marrowHermesIntegration;
exports.marrowCompletionContracts = marrowCompletionContracts;
exports.marrowEvaluateCompletionContract = marrowEvaluateCompletionContract;
exports.marrowGovernanceTimeline = marrowGovernanceTimeline;
exports.marrowBuyerProof = marrowBuyerProof;
exports.marrowCoordinate = marrowCoordinate;
exports.marrowReplayCompare = marrowReplayCompare;
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
exports.marrowIntegrationEvent = marrowIntegrationEvent;
exports.marrowDecisionTrace = marrowDecisionTrace;
exports.marrowAcceptDetected = marrowAcceptDetected;
exports.marrowListTemplates = marrowListTemplates;
exports.marrowInstallTemplate = marrowInstallTemplate;
const node_crypto_1 = require("node:crypto");
const sdk_1 = require("@getmarrow/sdk");
const redact_1 = require("./redact");
const lifecycle_spool_1 = require("./lifecycle-spool");
const hook_contract_1 = require("./hook-contract");
const request_reliability_1 = require("./request-reliability");
const runtime_contract_1 = require("./runtime-contract");
const fetch = request_reliability_1.reliableFetch;
const SOURCE_CLIENTS = new Set(['claude-code', 'cursor', 'windsurf', 'openclaw', 'codex', 'gemini', 'grok', 'deepseek', 'qwen', 'kimi', 'minimax', 'cline', 'opencode', 'hermes', 'glm', 'custom', 'unknown']);
const SAFE_ARBITRATION_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$/;
const SAFE_ARBITRATION_EVIDENCE_KIND = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,39}$/;
const SAFE_ARBITRATION_EVIDENCE_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/;
const SAFE_OUTCOME_OBSERVATION_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/;
const SAFE_INSTRUCTION_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const INSTRUCTION_REFERENCE_LONG_DIGIT_RUN = /\d{7,}/;
const INSTRUCTION_REFERENCE_DATE = /(?:^|[._:-])(?:(?:19|20)\d{2}[._:-](?:0?[1-9]|1[0-2])[._:-](?:0?[1-9]|[12]\d|3[01])|(?:0?[1-9]|1[0-2])[._:-](?:0?[1-9]|[12]\d|3[01])[._:-](?:19|20)\d{2})(?:$|[._:-])/;
const INSTRUCTION_REFERENCE_PROVIDER_ID = /^(?:telegram|tg|discord|slack|signal|whatsapp|wa|matrix|imessage|message|msg|chat|user|thread|channel|room|dm|sms|device)[_:.-]?[A-Za-z]*\d+[A-Za-z0-9_-]*$/i;
const INSTRUCTION_REFERENCE_IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const INSTRUCTION_REFERENCE_IPV6 = /^(?:[a-f0-9]{0,4}:){2,}[a-f0-9:.]{0,}$/i;
const INSTRUCTION_REFERENCE_DOMAIN = /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i;
const INSTRUCTION_REFERENCE_ERROR = 'instruction_ref must be a privacy-safe opaque identifier (1-128 characters using A-Z, a-z, 0-9, ., _, :, or -); date-like references, long digit runs, provider IDs, addresses, and domains are not allowed.';
const SECRETISH_ARBITRATION_REFERENCE = /(?:^|[._:-])(?:secret|token|password|credential|api[_-]?key|authorization|bearer)(?:$|[._:-])|^(?:sk|pk|ghp|github_pat|npm|cfut|mrw)_[A-Za-z0-9_-]+$/i;
function preserveOpaqueArbitrationValue(value, pattern, field) {
    if (value !== value.trim()
        || !pattern.test(value)
        || SECRETISH_ARBITRATION_REFERENCE.test(value)) {
        throw new TypeError(`Agent arbitration ${field} must be a safe opaque identifier.`);
    }
    return value;
}
function preserveInstructionReference(value) {
    if (typeof value !== 'string') {
        throw new TypeError(INSTRUCTION_REFERENCE_ERROR);
    }
    const domainSuffix = value.split('.').pop() || '';
    const domainLike = INSTRUCTION_REFERENCE_DOMAIN.test(value) && /^[a-z]{2,}$/i.test(domainSuffix);
    if (value !== value.trim()
        || !SAFE_INSTRUCTION_REFERENCE.test(value)
        || /^\d+$/.test(value)
        || INSTRUCTION_REFERENCE_LONG_DIGIT_RUN.test(value)
        || INSTRUCTION_REFERENCE_DATE.test(value)
        || INSTRUCTION_REFERENCE_PROVIDER_ID.test(value)
        || INSTRUCTION_REFERENCE_IPV4.test(value)
        || INSTRUCTION_REFERENCE_IPV6.test(value)
        || /^(?:https?:|www\.)/i.test(value)
        || domainLike) {
        throw new TypeError(INSTRUCTION_REFERENCE_ERROR);
    }
    return value;
}
function defaultSourceClient() {
    const raw = String(process.env.MARROW_CLIENT || process.env.MARROW_HARNESS || process.env.MARROW_AGENT_CLIENT || '').trim().toLowerCase().replace(/\s+/g, '-').replace(/^@/, '');
    const aliases = {
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
function normalizeModelUsage(input = {}) {
    const body = {};
    const copyString = (key) => {
        const value = input[key];
        if (typeof value === 'string' && value.trim())
            body[String(key)] = (0, redact_1.redactSensitiveText)(value).slice(0, 180);
    };
    const copyNumber = (key) => {
        const value = Number(input[key]);
        if (Number.isFinite(value) && value >= 0)
            body[String(key)] = value;
    };
    ['agent_id', 'session_id', 'workflow_id', 'decision_id', 'provider', 'model', 'task_type', 'action_type', 'source', 'marrow_intervention'].forEach(copyString);
    ['input_tokens', 'output_tokens', 'cached_tokens', 'total_tokens', 'cost_usd', 'latency_ms', 'baseline_tokens', 'estimated_tokens_saved', 'estimated_cost_saved_usd', 'estimated_minutes_saved'].forEach(copyNumber);
    if (typeof input.success === 'boolean')
        body.success = input.success;
    return body;
}
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
const REPLAY_CONSTRAINT_STRING_FIELDS = new Set([
    'environment',
    'tests',
    'policy_profile_id',
    'workflow_type',
    'task_type',
]);
const REPLAY_CONSTRAINT_BOOLEAN_FIELDS = new Set(['required_proof', 'same_workspace']);
function boundCoordinationAgent(input, agentId) {
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
function normalizeReplayConstraints(value) {
    if (value == null)
        return {};
    if (typeof value !== 'object' || Array.isArray(value)) {
        throw new TypeError('constraints must be a bounded object.');
    }
    const entries = Object.entries(value);
    if (entries.length > 7)
        throw new TypeError('constraints exceeds the maximum field count.');
    const normalized = {};
    for (const [key, raw] of entries.sort(([left], [right]) => left.localeCompare(right))) {
        if (REPLAY_CONSTRAINT_BOOLEAN_FIELDS.has(key)) {
            if (typeof raw !== 'boolean')
                throw new TypeError(`constraints.${key} must be boolean.`);
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
function requiredReplayDecisionId(value, field) {
    const decisionId = typeof value === 'string' ? value.trim() : '';
    if (!decisionId)
        throw new TypeError(`${field} is required.`);
    return decisionId;
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
        let detail;
        try {
            const contentType = res.headers.get('content-type') || '';
            if (contentType.includes('json'))
                detail = await res.json();
        }
        catch { /* ignore malformed or non-JSON error bodies */ }
        throw (0, request_reliability_1.requestErrorFromResponse)(res, detail);
    }
    let json;
    try {
        json = await res.json();
    }
    catch {
        throw (0, request_reliability_1.invalidResponseError)();
    }
    if (!json || typeof json !== 'object' || Array.isArray(json) || json.error) {
        throw (0, request_reliability_1.invalidResponseError)();
    }
    return json;
}
function requireRuntimeResult(value) {
    const runtime = (0, runtime_contract_1.normalizeRuntimeResult)(value);
    if (!runtime)
        throw (0, request_reliability_1.invalidResponseError)();
    return runtime;
}
const retryQueue = [];
let retryQueueDraining = false;
function isRetryableStatus(status) {
    return [408, 425, 429, 500, 502, 503, 504].includes(status);
}
function isRetryableError(error) {
    const message = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
    if (/\b(401|403|unauthorized|forbidden|invalid api key|insufficient scope|proof pack|required proof|policy|blocked)\b/.test(message)) {
        return false;
    }
    return /\b(timeout|timed out|econnreset|enotfound|eai_again|network|fetch failed|temporar|rate limit)\b/.test(message);
}
async function drainRetryQueue() {
    if (retryQueueDraining || retryQueue.length === 0)
        return;
    retryQueueDraining = true;
    const remaining = [];
    try {
        const queued = retryQueue.splice(0, 5);
        for (const item of queued) {
            try {
                const res = await fetch(item.url, item.init);
                if (!res.ok && isRetryableStatus(res.status) && item.attempts < 2) {
                    remaining.push({ ...item, attempts: item.attempts + 1 });
                }
            }
            catch (error) {
                if (isRetryableError(error) && item.attempts < 2) {
                    remaining.push({ ...item, attempts: item.attempts + 1 });
                }
            }
        }
    }
    finally {
        retryQueue.unshift(...remaining);
        retryQueueDraining = false;
    }
}
async function fetchWithRetryQueue(url, init, queueable = false) {
    await drainRetryQueue();
    try {
        const res = await fetch(url, init);
        if (queueable && !res.ok && isRetryableStatus(res.status)) {
            if (retryQueue.length >= 25)
                retryQueue.shift();
            retryQueue.push({ url, init, attempts: 0 });
        }
        return res;
    }
    catch (error) {
        if (queueable && isRetryableError(error)) {
            if (retryQueue.length >= 25)
                retryQueue.shift();
            retryQueue.push({ url, init, attempts: 0 });
        }
        throw error;
    }
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
    headers['X-Marrow-Client'] = defaultSourceClient();
    headers['X-Marrow-Package'] = '@getmarrow/mcp';
    headers['X-Marrow-Package-Version'] = hook_contract_1.MCP_ADAPTER_VERSION;
    return headers;
}
function createSdkClient(apiKey, baseUrl, sessionId, agentId) {
    return new sdk_1.MarrowClient(apiKey, { baseUrl, sessionId, agentId });
}
function runtimeGateReceiptId(runtime) {
    return (0, runtime_contract_1.runtimeAuthorizationReceiptId)(runtime);
}
function runtimeGateCanAuthorizeCommit(runtime) {
    if (!runtimeGateReceiptId(runtime) || !runtime)
        return false;
    return (runtime.authorization_state === 'hard_gate' && runtime.hard_gate_obtained === true)
        || (runtime.authorization_state === 'advisory_only' && runtime.hard_gate_obtained === false);
}
function runtimeGateCanSubmitOutcomeObservation(runtime) {
    if ((0, runtime_contract_1.isOutcomeObservationOnlyRuntime)(runtime))
        return true;
    const receiptId = runtimeGateReceiptId(runtime);
    return Boolean(runtime
        && receiptId
        && runtime.runtime_authorization?.id === receiptId
        && runtime.runtime_authorization.durable === true
        && runtime.fresh_runtime_response === true
        && runtime.guidance_obtained === true);
}
function runtimeGateMatchesCommitScope(runtime, params, sessionId, agentId) {
    const action = (0, redact_1.redactSensitiveText)(params.action);
    const observationOnly = (0, runtime_contract_1.isOutcomeObservationOnlyRuntime)(runtime);
    const runtimeDecisionId = observationOnly
        ? runtime.runtime_authorization?.decision_id || runtime.decision_id
        : runtime.runtime_authorization?.decision_state === 'created'
            ? runtime.runtime_authorization.decision_id || runtime.decision_id
            : undefined;
    return runtime.action === action
        && (!observationOnly || Boolean(runtimeDecisionId))
        && (!runtimeDecisionId || runtimeDecisionId === params.decision_id)
        && (!sessionId || !runtime.session_id || runtime.session_id === sessionId)
        && (!agentId || !runtime.agent_id || runtime.agent_id === agentId);
}
function isDurableObservedOutcome(value) {
    return value.accepted === true
        && value.committed === false
        && value.outcome_state === 'observed_unverified'
        && typeof value.outcome_observation_id === 'string'
        && SAFE_OUTCOME_OBSERVATION_IDENTIFIER.test(value.outcome_observation_id)
        && value.authorization_granted === false
        && value.trusted_learning_applied === false
        && typeof value.exact_next_action === 'string'
        && value.exact_next_action.trim().length > 0;
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
async function marrowThink(apiKey, baseUrl, params, sessionId, agentId, signal, options) {
    const body = {
        action: (0, redact_1.redactSensitiveText)(params.action),
        target: params.target ? (0, redact_1.redactSensitiveText)(params.target) : undefined,
        surfaces: params.surfaces,
        type: params.type || 'general',
    };
    if (params.context) {
        body.context = (0, redact_1.redactSensitiveValue)(params.context);
    }
    body.source_kind = params.source_kind || 'agent_autonomous';
    body.source_confidence = params.source_confidence ?? 0.9;
    body.human_directed = params.human_directed ?? false;
    if (params.instruction_ref !== undefined) {
        body.instruction_ref = params.instruction_ref === null
            ? null
            : preserveInstructionReference(params.instruction_ref);
    }
    if (params.instruction !== undefined)
        body.instruction = (0, redact_1.redactSensitiveText)(params.instruction);
    if (params.instruction_hash !== undefined)
        body.instruction_hash = params.instruction_hash;
    body.source_meta = (0, redact_1.redactSensitiveValue)({
        channel: 'mcp',
        client: defaultSourceClient(),
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
    const thinkUrl = `${baseUrl}/v1/agent/think${options?.responseMode === 'ack' ? '?response=ack' : ''}`;
    const thinkInit = {
        method: 'POST',
        headers: {
            ...buildHeaders(apiKey, sessionId, 'application/json', agentId),
            ...(options?.idempotencyKey ? { 'Idempotency-Key': options.idempotencyKey } : {}),
        },
        body: JSON.stringify(body),
        signal,
    };
    const res = options?.idempotencyKey
        ? await fetch(thinkUrl, thinkInit)
        : await fetchWithRetryQueue(thinkUrl, thinkInit, true);
    const json = await safeJsonResponse(res);
    return markAutoResponseStatus(json.data, res.status);
}
/**
 * Explicitly commit the result of an action to Marrow.
 */
async function marrowCommit(apiKey, baseUrl, params, sessionId, agentId, signal, idempotencyKey) {
    let runtimeGate = null;
    let gateReceiptId = params.gate_receipt_id || params.gate_receipt;
    let observationOnly = false;
    for (const [field, value] of [
        ['gate receipt', gateReceiptId],
        ['arbitration receipt', params.arbitration_receipt_id],
        ['owner approval receipt', params.owner_approval_receipt_id],
    ]) {
        if ((0, runtime_contract_1.isOutcomeObservationOnlyCorrelationId)(value)) {
            throw new TypeError(`An observation-only runtime correlation cannot be used as ${field} or approval evidence.`);
        }
    }
    if (!gateReceiptId && params.auto_gate !== false && params.action) {
        try {
            runtimeGate = await marrowAgentRuntime(apiKey, baseUrl, {
                action: (0, redact_1.redactSensitiveText)(params.action),
                decision_id: params.decision_id,
                response_mode: 'expanded',
                type: params.type || 'handoff',
                surfaces: params.surfaces || ['handoff'],
                context: { mcp_commit_auto_gate: true },
                proof: params.proof ? (0, redact_1.redactSensitiveValue)(params.proof) : undefined,
            }, sessionId, agentId, signal);
        }
        catch (err) {
            if (err instanceof request_reliability_1.MarrowRequestError)
                throw err;
            const msg = err instanceof Error ? err.message : String(err);
            throw new Error(`marrowCommit auto_gate failed before outcome closure: ${msg}`);
        }
        const canSubmitObservation = runtimeGateCanSubmitOutcomeObservation(runtimeGate);
        gateReceiptId = runtimeGateReceiptId(runtimeGate) || undefined;
        if (!gateReceiptId && !canSubmitObservation) {
            throw new Error('marrowCommit auto_gate required a gate receipt backed by canonical runtime authorization, but /v1/agent/runtime returned missing, conflicting, or unverified receipt state');
        }
        if (!runtimeGateMatchesCommitScope(runtimeGate, {
            action: params.action,
            decision_id: params.decision_id,
        }, sessionId, agentId)) {
            throw new Error('marrowCommit auto_gate runtime authorization scope does not match the requested action, decision, session, or agent; outcome submission stopped before commit');
        }
        const canAuthorizeCommit = runtimeGateCanAuthorizeCommit(runtimeGate);
        if (!canAuthorizeCommit && !canSubmitObservation) {
            throw new Error('marrowCommit auto_gate required a gate receipt backed by canonical runtime authorization, but /v1/agent/runtime returned missing, conflicting, or unverified receipt state');
        }
        observationOnly = !canAuthorizeCommit;
        if (observationOnly)
            gateReceiptId = undefined;
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
    if (params.arbitration_receipt_id)
        body.arbitration_receipt_id = params.arbitration_receipt_id;
    if (params.owner_approval_receipt_id)
        body.owner_approval_receipt_id = params.owner_approval_receipt_id;
    const identifiedWorkflowId = typeof params.identified_workflow_id === 'string' && params.identified_workflow_id.trim()
        ? params.identified_workflow_id.trim().slice(0, 128)
        : typeof params.identified_workflow?.id === 'string' && params.identified_workflow.id.trim()
            ? params.identified_workflow.id.trim().slice(0, 128)
            : typeof runtimeGate?.identified_workflow?.id === 'string' && runtimeGate.identified_workflow.id.trim()
                ? runtimeGate.identified_workflow.id.trim().slice(0, 128)
                : undefined;
    if (identifiedWorkflowId)
        body.identified_workflow_id = identifiedWorkflowId;
    if (params.reused_identified_workflow === true || identifiedWorkflowId) {
        body.reused_identified_workflow = true;
    }
    const modelUsage = params.model_usage || params.modelUsage;
    if (modelUsage)
        body.model_usage = normalizeModelUsage(modelUsage);
    const commitInit = {
        method: 'POST',
        headers: {
            ...buildHeaders(apiKey, sessionId, 'application/json', agentId),
            ...(idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {}),
        },
        body: JSON.stringify(body),
        signal,
    };
    const res = idempotencyKey
        ? await fetch(`${baseUrl}/v1/agent/commit`, commitInit)
        : await fetchWithRetryQueue(`${baseUrl}/v1/agent/commit`, commitInit, true);
    const json = await safeJsonResponse(res);
    if (json.data
        && typeof json.data === 'object'
        && !Array.isArray(json.data)
        && json.data.outcome_state === 'observed_unverified') {
        if (!isDurableObservedOutcome(json.data))
            throw (0, request_reliability_1.invalidResponseError)();
        // A backend 202 can mean durable acceptance rather than async work. Do not
        // attach the internal pending marker: this exact observation is terminal
        // delivery and any trusted promotion must be a new explicit commit attempt.
        return { ...json.data, committed: false, runtime_gate: runtimeGate };
    }
    if (observationOnly)
        throw (0, request_reliability_1.invalidResponseError)();
    if (res.status === 202
        && json.data
        && typeof json.data === 'object'
        && !Array.isArray(json.data)
        && (json.data.phase === undefined || json.data.phase === 'commit_pending' || json.data.resumable === true)) {
        return markAutoResponseStatus({ ...json.data, committed: false, runtime_gate: runtimeGate }, res.status);
    }
    if (!json.data
        || typeof json.data !== 'object'
        || Array.isArray(json.data)
        || typeof json.data.committed !== 'boolean') {
        throw (0, request_reliability_1.invalidResponseError)();
    }
    return markAutoResponseStatus({ ...json.data, committed: json.data.committed, runtime_gate: runtimeGate }, res.status);
}
async function marrowModelUsage(apiKey, baseUrl, input, sessionId, agentId) {
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
const SAFE_AUTO_OPERATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,79}$/;
const AUTO_OPERATION_BINDING_TTL_MS = 30 * 60 * 1_000;
const AUTO_OPERATION_BINDING_LIMIT = 256;
const AUTO_RESPONSE_BUDGET_DEFAULT_MS = 8_000;
exports.MARROW_AUTO_RESPONSE_BUDGET_MAX_MS = 8_000;
const AUTO_RESPONSE_DEADLINE_MARGIN_MS = 75;
const AUTO_RESPONSE_STATUS = Symbol('marrowAutoResponseStatus');
const autoOperationBindings = new Map();
function canonicalAutoBindingValue(value) {
    if (Array.isArray(value))
        return value.map(canonicalAutoBindingValue);
    if (value && typeof value === 'object') {
        return Object.keys(value).sort().reduce((result, key) => {
            result[key] = canonicalAutoBindingValue(value[key]);
            return result;
        }, {});
    }
    return value;
}
function autoOperationSignature(input) {
    return (0, node_crypto_1.createHash)('sha256').update(JSON.stringify(canonicalAutoBindingValue({
        api_key: input.apiKey,
        base_url: input.baseUrl.replace(/\/$/, ''),
        agent_id: input.agentId || null,
        session_id: input.sessionId || null,
        action: (0, redact_1.redactSensitiveText)(input.action),
        gate_action: (0, redact_1.redactSensitiveText)(input.gateAction),
        type: input.type,
        surfaces: input.surfaces || [],
        context: input.context ? (0, redact_1.redactSensitiveValue)(input.context) : null,
    }))).digest('hex');
}
function boundAutoOperation(operationId, signature) {
    const now = Date.now();
    for (const [id, binding] of autoOperationBindings) {
        if (binding.expiresAt <= now)
            autoOperationBindings.delete(id);
    }
    const existing = autoOperationBindings.get(operationId);
    if (existing) {
        if (existing.signature !== signature) {
            throw new request_reliability_1.MarrowRequestError({
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
        if (typeof oldest !== 'string')
            break;
        autoOperationBindings.delete(oldest);
    }
    const created = { signature, expiresAt: now + AUTO_OPERATION_BINDING_TTL_MS };
    autoOperationBindings.set(operationId, created);
    return created;
}
function resolveAutoOperationId(value) {
    const supplied = typeof value === 'string' ? value.trim() : '';
    if (supplied) {
        if (!SAFE_AUTO_OPERATION_ID.test(supplied)) {
            throw new TypeError('marrow_auto operation_id must be an 8-80 character opaque identifier.');
        }
        return supplied;
    }
    return `auto_${(0, node_crypto_1.randomUUID)()}`;
}
function autoIdempotencyKey(operationId, phase) {
    return `mcp-auto:${operationId}:${phase}`;
}
function autoResponseBudget(timeoutMs) {
    const requested = Number(timeoutMs);
    return Number.isFinite(requested) && requested > 0
        ? Math.min(exports.MARROW_AUTO_RESPONSE_BUDGET_MAX_MS, Math.max(500, Math.floor(requested)))
        : AUTO_RESPONSE_BUDGET_DEFAULT_MS;
}
function markAutoResponseStatus(value, status) {
    if (value && typeof value === 'object') {
        Object.defineProperty(value, AUTO_RESPONSE_STATUS, { value: status });
    }
    return value;
}
function isAutoPendingResponse(value, phase) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return false;
    const pending = value;
    return pending[AUTO_RESPONSE_STATUS] === 202
        && (pending.phase === phase || (pending.phase === undefined && pending.resumable === true));
}
async function waitForAutoContinuation(pending, startedAt, responseBudgetMs) {
    const remaining = responseBudgetMs - (Date.now() - startedAt) - AUTO_RESPONSE_DEADLINE_MARGIN_MS;
    if (remaining <= 0)
        return false;
    const requestedDelay = Number(pending.retry_after_ms);
    const delayMs = Number.isFinite(requestedDelay)
        ? Math.min(500, Math.max(25, Math.floor(requestedDelay)))
        : 50;
    await new Promise((resolve) => setTimeout(resolve, Math.min(delayMs, remaining)));
    return responseBudgetMs - (Date.now() - startedAt) > AUTO_RESPONSE_DEADLINE_MARGIN_MS;
}
function autoPartial(input) {
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
        ...(input.exactNextAction ? { exact_next_action: input.exactNextAction } : {}),
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
async function marrowAuto(apiKey, baseUrl, params, sessionId, agentId, timeoutMs) {
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
    const timings = {
        runtime: null,
        think: null,
        commit: null,
    };
    let runtimeGate = null;
    let gateReceiptId = params.gate_receipt_id;
    let proofCanClose = params.auto_gate !== true;
    if (params.auto_gate === true) {
        const phaseStarted = Date.now();
        if (operationBinding.runtimeGate) {
            runtimeGate = operationBinding.runtimeGate;
            timings.runtime = 0;
        }
        else {
            while (!runtimeGate) {
                const runtimeTimeout = createTimeoutSignal(responseBudgetMs, startedAt);
                try {
                    runtimeGate = await marrowAgentRuntime(apiKey, baseUrl, {
                        action: (0, redact_1.redactSensitiveText)(params.action_for_gate || params.action),
                        type: params.type || 'general',
                        agent_id: agentId,
                        session_id: sessionId,
                        surfaces: params.surfaces,
                        // Proof is commit evidence, not part of immutable runtime authorization.
                        // Keeping it out makes missing -> supplied proof a monotonic continuation.
                        context: { source: 'mcp_auto_risk_upgrade', operation_id: operationId },
                    }, sessionId, agentId, runtimeTimeout.signal, autoIdempotencyKey(operationId, 'runtime'));
                    operationBinding.runtimeGate = runtimeGate;
                }
                catch (error) {
                    if ((0, request_reliability_1.normalizeRequestError)(error).code !== 'request_timeout'
                        || !await waitForAutoContinuation({}, startedAt, responseBudgetMs)) {
                        timings.runtime = Date.now() - phaseStarted;
                        if ((0, request_reliability_1.normalizeRequestError)(error).code === 'request_timeout') {
                            return autoPartial({ operationId, phase: 'runtime_pending', timings, startedAt });
                        }
                        throw error;
                    }
                }
                finally {
                    runtimeTimeout.cancel();
                }
            }
            timings.runtime = Date.now() - phaseStarted;
        }
        gateReceiptId = (0, runtime_contract_1.runtimeAuthorizationReceiptId)(runtimeGate) || gateReceiptId;
        if (!gateReceiptId) {
            throw new Error('marrowAuto runtime phase did not return canonical runtime authorization');
        }
        proofCanClose = (0, runtime_contract_1.highRiskRuntimeCanClose)(runtimeGate, params.proof, gateReceiptId)
            || (0, runtime_contract_1.highRiskRuntimeCanContinueWithProof)(runtimeGate, params.proof, gateReceiptId);
    }
    const thinkStarted = Date.now();
    let decisionId = operationBinding.decisionId || null;
    const arbitrationDecisionId = typeof runtimeGate?.arbitration?.decision_id === 'string'
        && runtimeGate.arbitration.decision_id.trim()
        ? runtimeGate.arbitration.decision_id.trim()
        : null;
    if (runtimeGate?.arbitration && !arbitrationDecisionId) {
        throw (0, request_reliability_1.invalidResponseError)();
    }
    if (arbitrationDecisionId) {
        if (decisionId && decisionId !== arbitrationDecisionId) {
            throw new request_reliability_1.MarrowRequestError({
                code: 'request_failed',
                backendCode: 'MARROW_ARBITRATION_DECISION_MISMATCH',
                message: 'marrow_auto operation is already bound to a different decision than the runtime arbitration receipt.',
                status: 409,
                retryable: false,
                exactFix: 'Stop this operation. Start a new arbitrated marrow_auto operation and preserve the arbitration decision_id, gate receipt, arbitration receipt, and dashboard approval receipt together.',
            });
        }
        decisionId = arbitrationDecisionId;
        operationBinding.decisionId = arbitrationDecisionId;
    }
    const reusedDecision = Boolean(decisionId);
    while (!decisionId) {
        const thinkTimeout = createTimeoutSignal(responseBudgetMs, startedAt);
        let thinkResult;
        try {
            thinkResult = await marrowThink(apiKey, baseUrl, {
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
            }, sessionId, agentId, thinkTimeout.signal, {
                idempotencyKey: autoIdempotencyKey(operationId, 'think'),
                responseMode: 'ack',
            });
        }
        catch (error) {
            if ((0, request_reliability_1.normalizeRequestError)(error).code !== 'request_timeout'
                || !await waitForAutoContinuation({}, startedAt, responseBudgetMs)) {
                timings.think = Date.now() - thinkStarted;
                if ((0, request_reliability_1.normalizeRequestError)(error).code === 'request_timeout') {
                    return autoPartial({ operationId, phase: 'think_pending', runtimeGate, timings, startedAt });
                }
                throw error;
            }
            continue;
        }
        finally {
            thinkTimeout.cancel();
        }
        decisionId = typeof thinkResult.decision_id === 'string' && thinkResult.decision_id.trim()
            ? thinkResult.decision_id.trim()
            : null;
        if (decisionId) {
            operationBinding.decisionId = decisionId;
            break;
        }
        if (!isAutoPendingResponse(thinkResult, 'think_pending'))
            throw (0, request_reliability_1.invalidResponseError)();
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
    const runtimeReviewRequired = Boolean(runtimeGate && (runtimeGate.risk_gate?.decision === 'review_required'
        || runtimeGate.gate_receipt?.decision === 'review_required'
        || runtimeGate.gate_receipt?.decision === 'owner_approval_required'
        || runtimeGate.gate_receipt?.owner_approval_required === true
        || runtimeGate.intervention?.decision === 'owner_approval_required'
        || runtimeGate.intervention?.enforcement?.owner_approval_required === true
        || runtimeGate.arbitration?.resolution === 'review_required'
        || runtimeGate.arbitration?.owner_approval_required === true));
    const arbitrationRequiresOwnerApproval = Boolean(runtimeGate?.arbitration
        && runtimeReviewRequired
        && (runtimeGate.arbitration.resolution === 'review_required'
            || runtimeGate.arbitration.owner_approval_required === true));
    const genericReviewRequired = runtimeReviewRequired && !runtimeGate?.arbitration;
    const runtimeArbitrationReceiptId = runtimeGate?.arbitration?.receipt_id;
    const matchingRequiredApprovalReceipts = Boolean(params.owner_approval_receipt_id
        && (!runtimeArbitrationReceiptId
            || params.arbitration_receipt_id === runtimeArbitrationReceiptId));
    if (genericReviewRequired) {
        return autoPartial({
            operationId,
            decisionId,
            phase: 'review_required',
            runtimeGate,
            timings,
            startedAt,
            resumable: false,
            exactNextAction: 'Stop this operation. A non-arbitrated review_required gate cannot issue a commit-compatible dashboard approval receipt. Start a new review with marrow_arbitrate, then use that arbitration response\'s exact decision_id, gate receipt, arbitration receipt, and dashboard-issued owner approval receipt. Do not retry this operation or use chat/proof text as approval.',
        });
    }
    if (arbitrationRequiresOwnerApproval && !matchingRequiredApprovalReceipts) {
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
        const ownerApprovedCommitAttempt = Boolean(arbitrationRequiresOwnerApproval
            && params.proof
            && Object.keys(params.proof).length > 0
            && gateReceiptId
            && matchingRequiredApprovalReceipts);
        if (ownerApprovedCommitAttempt)
            proofCanClose = true;
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
    let commitResult;
    while (true) {
        const commitTimeout = createTimeoutSignal(responseBudgetMs, startedAt);
        try {
            commitResult = await marrowCommit(apiKey, baseUrl, {
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
            }, sessionId, agentId, commitTimeout.signal, autoIdempotencyKey(operationId, 'commit'));
        }
        catch (error) {
            if ((0, request_reliability_1.normalizeRequestError)(error).code !== 'request_timeout'
                || !await waitForAutoContinuation({}, startedAt, responseBudgetMs)) {
                timings.commit = Date.now() - commitStarted;
                if ((0, request_reliability_1.normalizeRequestError)(error).code === 'request_timeout') {
                    return autoPartial({ operationId, decisionId, phase: 'commit_pending', runtimeGate, timings, startedAt });
                }
                throw error;
            }
            continue;
        }
        finally {
            commitTimeout.cancel();
        }
        if (commitResult.committed)
            break;
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
 * Get the current before-action warning from the canonical runtime contract.
 * The retired orient/pattern routes required broader legacy scopes and could
 * leave otherwise valid agent-bound keys unable to start a session.
 */
async function marrowOrient(apiKey, baseUrl, params, sessionId, agentId, signal) {
    const taskType = params?.taskType || 'general';
    const runtime = await marrowAgentRuntime(apiKey, baseUrl, {
        action: `Orient before ${taskType} work`,
        type: taskType,
        context: {
            source: 'mcp',
            event_kind: 'session_orientation',
            auto_warn: params?.autoWarn !== false,
        },
    }, sessionId, agentId, signal);
    const intervention = runtime.intervention;
    const interventionDecision = intervention?.decision ? String(intervention.decision) : '';
    const gateDecision = runtime.risk_gate?.decision ? String(runtime.risk_gate.decision) : '';
    const receiptDecision = runtime.gate_receipt?.decision ? String(runtime.gate_receipt.decision) : '';
    const decisionRank = {
        proceed: 0,
        warn: 1,
        owner_approval_required: 2,
        block: 3,
    };
    const normalizeDecision = (value, source) => {
        if (!value)
            return null;
        if (value === 'proceed' || value === 'allow')
            return 'proceed';
        if (value === 'warn')
            return 'warn';
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
    const decisions = [
        normalizedIntervention,
        normalizedGate,
        normalizedReceipt,
    ].filter((value) => value !== null);
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
    const decision = decisions.reduce((strictest, candidate) => decisionRank[candidate] > decisionRank[strictest] ? candidate : strictest, 'proceed');
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
    const severity = shouldPause
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
async function marrowAsk(apiKey, baseUrl, params, sessionId, agentId, signal) {
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
    const brief = json.data;
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
    };
}
/**
 * Get API health status.
 */
async function marrowStatus(apiKey, baseUrl, sessionId, agentId, signal) {
    const res = await fetch(`${baseUrl}/v1/agent/status?fast=1&compact=1`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
        signal,
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
async function marrowAgentStatus(apiKey, baseUrl, period = '7d', agentIdFilter, sessionId, agentId, signal) {
    const days = parseInt(period) || 7;
    const qs = new URLSearchParams({ period: String(days) });
    if (agentIdFilter)
        qs.set('agent_id', agentIdFilter);
    const res = await fetch(`${baseUrl}/v1/analytics/agent-status?${qs.toString()}`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
        signal,
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
/**
 * Get live runtime hook diagnostics from /v1/agent/status.
 */
async function marrowRuntimeStatus(apiKey, baseUrl, fast = true, sessionId, agentId, signal) {
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
async function marrowAgentContext(apiKey, baseUrl, sessionId, agentId, signal) {
    const query = new URLSearchParams({ compact: '1' });
    if (agentId)
        query.set('agent_id', agentId);
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
async function marrowAgentRuntime(apiKey, baseUrl, input, sessionId, agentId, signal, idempotencyKeyOverride) {
    const body = {
        ...input,
        agent_id: input.agent_id || agentId,
        session_id: input.session_id || sessionId,
    };
    const idempotencyKey = idempotencyKeyOverride || `mcp-runtime-${(0, node_crypto_1.randomUUID)()}`;
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
async function marrowEnforcement(apiKey, baseUrl, input, sessionId, agentId, signal) {
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
async function marrowArbitrate(apiKey, baseUrl, input, sessionId, agentId) {
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
    const safeCoordination = {
        objective: (0, redact_1.redactSensitiveText)(coordination.objective),
        ...(typeof coordination.owner_intent === 'string'
            ? { owner_intent: (0, redact_1.redactSensitiveText)(coordination.owner_intent) }
            : {}),
        ...(coordination.conflict_type ? { conflict_type: coordination.conflict_type } : {}),
        proposals: coordination.proposals.map((proposal) => ({
            proposal_id: preserveOpaqueArbitrationValue(proposal.proposal_id, SAFE_ARBITRATION_IDENTIFIER, 'proposal_id'),
            agent_id: preserveOpaqueArbitrationValue(proposal.agent_id, SAFE_ARBITRATION_IDENTIFIER, 'agent_id'),
            action: (0, redact_1.redactSensitiveText)(proposal.action),
            ...(typeof proposal.rationale === 'string'
                ? { rationale: (0, redact_1.redactSensitiveText)(proposal.rationale) }
                : {}),
            ...(typeof proposal.confidence === 'number' ? { confidence: proposal.confidence } : {}),
            ...(proposal.risk_level ? { risk_level: proposal.risk_level } : {}),
            ...(typeof proposal.requires_owner_approval === 'boolean'
                ? { requires_owner_approval: proposal.requires_owner_approval }
                : {}),
            ...(Array.isArray(proposal.evidence)
                ? {
                    evidence: proposal.evidence.map((evidence) => ({
                        kind: preserveOpaqueArbitrationValue(evidence.kind, SAFE_ARBITRATION_EVIDENCE_KIND, 'evidence kind'),
                        reference: preserveOpaqueArbitrationValue(evidence.reference, SAFE_ARBITRATION_EVIDENCE_REFERENCE, 'evidence reference'),
                    })),
                }
                : {}),
        })),
    };
    return marrowAgentRuntime(apiKey, baseUrl, {
        action: (0, redact_1.redactSensitiveText)(action || `Resolve conflicting agent proposals for ${safeCoordination.objective}`),
        type: type || 'coordination',
        agent_id: agent_id || agentId,
        session_id: session_id || sessionId,
        surfaces,
        context: context ? (0, redact_1.redactSensitiveValue)(context) : undefined,
        proof: proof ? (0, redact_1.redactSensitiveValue)(proof) : undefined,
        coordination: safeCoordination,
    }, sessionId, agentId);
}
async function marrowGovernanceControlPlane(apiKey, baseUrl, sessionId, agentId) {
    const res = await fetch(`${baseUrl}/v1/agent/governance/control-plane`, {
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
async function marrowHermesIntegration(apiKey, baseUrl, sessionId, agentId) {
    const res = await fetch(`${baseUrl}/v1/agent/integrations/hermes`, {
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
async function marrowCompletionContracts(apiKey, baseUrl, sessionId, agentId) {
    const res = await fetch(`${baseUrl}/v1/agent/governance/completion-contracts`, {
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
async function marrowEvaluateCompletionContract(apiKey, baseUrl, input, sessionId, agentId) {
    const res = await fetch(`${baseUrl}/v1/agent/governance/completion-contracts/evaluate`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(input),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
async function marrowGovernanceTimeline(apiKey, baseUrl, options = {}, sessionId, agentId) {
    const qs = new URLSearchParams();
    if (options.agentId || agentId)
        qs.set('agent_id', options.agentId || agentId || '');
    if (options.limit)
        qs.set('limit', String(options.limit));
    const res = await fetch(`${baseUrl}/v1/agent/governance/timeline${qs.toString() ? `?${qs.toString()}` : ''}`, {
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
async function marrowBuyerProof(apiKey, baseUrl, options = {}, sessionId, agentId) {
    const qs = new URLSearchParams();
    if (options.agentId || agentId)
        qs.set('agent_id', options.agentId || agentId || '');
    if (options.periodDays)
        qs.set('period_days', String(options.periodDays));
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
async function marrowCoordinate(apiKey, baseUrl, input, sessionId, agentId) {
    const action = String(input.action || '');
    const headers = buildHeaders(apiKey, sessionId, 'application/json', agentId);
    if (action === 'list_leases') {
        const qs = new URLSearchParams();
        if (typeof input.status === 'string')
            qs.set('status', input.status);
        if (Number.isFinite(Number(input.limit)))
            qs.set('limit', String(input.limit));
        const res = await fetch(`${baseUrl}/v1/agent/governance/leases${qs.toString() ? `?${qs}` : ''}`, { headers });
        return (await safeJsonResponse(res)).data;
    }
    if (action === 'acquire_lease') {
        const boundAgentId = boundCoordinationAgent(input, agentId);
        const body = {
            agent_id: boundAgentId,
            resource_type: input.resource_type,
            resource: typeof input.resource === 'string' ? (0, redact_1.redactSensitiveText)(input.resource) : input.resource,
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
        if (!leaseId.startsWith('lease_'))
            throw new TypeError('lease_id must be a Marrow lease identifier.');
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
        if (Number.isFinite(Number(input.limit)))
            qs.set('limit', String(input.limit));
        const res = await fetch(`${baseUrl}/v1/agent/governance/proof-packets${qs.toString() ? `?${qs}` : ''}`, { headers });
        return (await safeJsonResponse(res)).data;
    }
    if (action === 'create_proof_packet') {
        const boundAgentId = boundCoordinationAgent(input, agentId);
        if (input.parent_agent_id != null) {
            throw new TypeError('parent_agent_id must be assigned by trusted Marrow coordination.');
        }
        const body = (0, redact_1.redactSensitiveValue)({
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
async function marrowReplayCompare(apiKey, baseUrl, input, sessionId, agentId) {
    const comparisonId = typeof input.comparison_id === 'string' ? input.comparison_id : '';
    if (comparisonId) {
        const safeId = validatePathParam(comparisonId, 'comparison_id');
        if (!safeId.startsWith('replay_'))
            throw new TypeError('comparison_id must be a Marrow replay identifier.');
        const res = await fetch(`${baseUrl}/v1/agent/governance/replay-comparisons/${safeId}`, {
            headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        });
        return (await safeJsonResponse(res)).data;
    }
    const sourceDecisionId = requiredReplayDecisionId(input.source_decision_id, 'source_decision_id');
    const baseline = input.baseline && typeof input.baseline === 'object' && !Array.isArray(input.baseline)
        ? input.baseline
        : {};
    const candidate = input.candidate && typeof input.candidate === 'object' && !Array.isArray(input.candidate)
        ? input.candidate
        : {};
    const baselineDecisionId = requiredReplayDecisionId(baseline.decision_id, 'baseline.decision_id');
    const candidateDecisionId = requiredReplayDecisionId(candidate.decision_id, 'candidate.decision_id');
    if (baselineDecisionId === candidateDecisionId) {
        throw new TypeError('baseline and candidate decision ids must be distinct.');
    }
    const body = (0, redact_1.redactSensitiveValue)({
        source_decision_id: sourceDecisionId,
        workspace_binding_id: input.workspace_binding_id,
        constraints: normalizeReplayConstraints(input.constraints),
        baseline: { ...baseline, decision_id: baselineDecisionId },
        candidate: { ...candidate, decision_id: candidateDecisionId },
    });
    const res = await fetch(`${baseUrl}/v1/agent/governance/replay-comparisons`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(body),
    });
    return (await safeJsonResponse(res)).data;
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
async function marrowHandoffStatus(apiKey, baseUrl, options = {}, sessionId, agentId, signal) {
    const qs = new URLSearchParams();
    if (options.status)
        qs.set('status', options.status);
    if (options.agentId || agentId)
        qs.set('agent_id', options.agentId || agentId || '');
    if (options.limit)
        qs.set('limit', String(options.limit));
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
async function marrowSessionEnd(apiKey, baseUrl, autoCommitOpen = false, sessionId, agentId, signal) {
    const res = await fetch(`${baseUrl}/v1/agent/session/end`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify({ auto_commit_open: autoCommitOpen }),
        signal,
    });
    const json = await safeJsonResponse(res);
    return json.data;
}
async function marrowIntegrationEvent(apiKey, baseUrl, event, sessionId, agentId) {
    return (0, lifecycle_spool_1.recordLifecycleEvent)({
        apiKey,
        baseUrl,
        event: {
            ...event,
            session_id: event.session_id || sessionId,
            agent_id: event.agent_id || agentId,
        },
    });
}
async function marrowDecisionTrace(apiKey, baseUrl, decisionId, sessionId, agentId) {
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