"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AGENT_APPROVAL_SETTINGS_PATH = exports.HELD_ACTIONS_PATH = exports.ELICITATION_HOOK_EVENT = exports.MARROW_AUTO_RESPONSE_BUDGET_MAX_MS = void 0;
exports.writeReconciliationDelayMs = writeReconciliationDelayMs;
exports.validatePathParam = validatePathParam;
exports.validateBaseUrl = validateBaseUrl;
exports.marrowAutoHttpTraceFromError = marrowAutoHttpTraceFromError;
exports.marrowCreateKey = marrowCreateKey;
exports.marrowListKeys = marrowListKeys;
exports.marrowGetKey = marrowGetKey;
exports.marrowRevokeKey = marrowRevokeKey;
exports.marrowRotateKey = marrowRotateKey;
exports.marrowGetKeyAudit = marrowGetKeyAudit;
exports.marrowThink = marrowThink;
exports.withoutOwnerApprovalClaim = withoutOwnerApprovalClaim;
exports.marrowCommit = marrowCommit;
exports.marrowModelUsage = marrowModelUsage;
exports.approvalStatement = approvalStatement;
exports.ordinaryHoldWaitText = ordinaryHoldWaitText;
exports.marrowAuto = marrowAuto;
exports.withoutServerNextActions = withoutServerNextActions;
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
exports.marrowOwnerApprovalStatus = marrowOwnerApprovalStatus;
exports.marrowRequestApprovalLink = marrowRequestApprovalLink;
exports.marrowHeldActions = marrowHeldActions;
exports.marrowAgentApprovalSettings = marrowAgentApprovalSettings;
exports.marrowHostApproval = marrowHostApproval;
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
const model_usage_1 = require("./model-usage");
/**
 * @getmarrow/mcp — API Functions
 */
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
// Manual think/commit reconciliation (not marrow_auto, which owns its own budget).
// Wall-clock budget across all attempts of one operation; the same idempotency key
// and request hash are reused for every attempt.
const AGENT_WRITE_RECONCILIATION_BUDGET_DEFAULT_MS = 15_000;
const AGENT_WRITE_RECONCILIATION_BUDGET_MIN_MS = 1_000;
const AGENT_WRITE_RECONCILIATION_BUDGET_MAX_MS = 60_000;
const AGENT_WRITE_RECONCILIATION_MAX_ATTEMPTS = 12;
const AGENT_WRITE_RECONCILIATION_MIN_DELAY_MS = 250;
const AGENT_WRITE_RECONCILIATION_MAX_DELAY_MS = 5_000;
// Time that must remain after a wait for the resumed request to be worth sending.
const AGENT_WRITE_RECONCILIATION_REQUEST_MARGIN_MS = 500;
// Optional body field carrying the REAL remaining server lease. Older servers only
// send retry_after_ms (kept at 1000 for old clients). Single place to rename.
const PENDING_LEASE_REMAINING_FIELD = 'lease_remaining_ms';
/** Server-requested wait: lease field if valid, else retry_after_ms; then the larger Retry-After header. */
function pendingWriteRequestedWaitMs(data, headerWait) {
    // An unreadable Retry-After is never turned into an earlier retry: wait at least 1 s.
    if (!headerWait.valid)
        return 1_000;
    const lease = traceMs(data[PENDING_LEASE_REMAINING_FIELD]);
    const body = lease !== null ? lease : traceMs(data.retry_after_ms);
    if (body === null && headerWait.delayMs === null)
        return null;
    return Math.max(body ?? 0, headerWait.delayMs ?? 0);
}
function writeReconciliationBudgetMs() {
    const configured = Number(process.env.MARROW_WRITE_RECONCILIATION_BUDGET_MS);
    return Number.isFinite(configured) && process.env.MARROW_WRITE_RECONCILIATION_BUDGET_MS !== ''
        ? Math.min(AGENT_WRITE_RECONCILIATION_BUDGET_MAX_MS, Math.max(AGENT_WRITE_RECONCILIATION_BUDGET_MIN_MS, Math.floor(configured)))
        : AGENT_WRITE_RECONCILIATION_BUDGET_DEFAULT_MS;
}
/**
 * Delay before resuming a pending write. A server-requested wait (lease field,
 * retry_after_ms or Retry-After, whichever is larger) is honored with a 250 ms floor
 * and no fixed ceiling: the caller stops with the resumable receipt when it does not
 * fit the remaining budget. Without guidance, exponential backoff (250 ms * 2^n,
 * capped at 5 s) with 50-100% jitter.
 */
function writeReconciliationDelayMs(attemptIndex, requestedMs, random = Math.random) {
    if (requestedMs !== null && Number.isFinite(requestedMs) && requestedMs >= 0) {
        return Math.max(AGENT_WRITE_RECONCILIATION_MIN_DELAY_MS, Math.ceil(requestedMs));
    }
    const exponential = Math.min(AGENT_WRITE_RECONCILIATION_MAX_DELAY_MS, AGENT_WRITE_RECONCILIATION_MIN_DELAY_MS * 2 ** Math.max(0, Math.min(10, attemptIndex)));
    return Math.min(AGENT_WRITE_RECONCILIATION_MAX_DELAY_MS, Math.max(AGENT_WRITE_RECONCILIATION_MIN_DELAY_MS, Math.ceil(exponential * (0.5 + 0.5 * random()))));
}
const AUTO_MANAGED_WRITE = Symbol('marrow-auto-managed-write');
const AUTO_HTTP_TRACE = Symbol('marrow-auto-http-trace');
const AUTO_HTTP_TRACE_ERROR = Symbol('marrow-auto-http-trace-error');
const AUTO_HTTP_TRACE_LIMIT = 12;
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
const REPLAY_INPUT_FIELDS = new Set([
    'comparison_id',
    'source_decision_id',
    'workspace_binding_id',
    'constraints',
    'baseline',
    'candidate',
]);
const REPLAY_OUTCOME_REFERENCE_FIELDS = new Set(['decision_id', 'label']);
const SAFE_REPLAY_DECISION_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const SAFE_REPLAY_LABEL = /^[A-Za-z0-9._:-]{1,80}$/;
const SAFE_REPLAY_WORKSPACE_BINDING_ID = /^workspace_[a-f0-9]{24}$/;
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
    if (typeof value !== 'string' || !value) {
        throw new TypeError(`${field} is required.`);
    }
    if (!SAFE_REPLAY_DECISION_ID.test(value)) {
        throw new TypeError(`${field} must be a safe identifier using 1-128 letters, numbers, dots, underscores, colons, or hyphens.`);
    }
    return value;
}
function optionalReplayWorkspaceBindingId(value) {
    if (value == null)
        return undefined;
    if (typeof value !== 'string' || !SAFE_REPLAY_WORKSPACE_BINDING_ID.test(value)) {
        throw new TypeError('workspace_binding_id must be a valid Marrow workspace binding identifier.');
    }
    return value;
}
function normalizeReplayOutcomeReference(value, field) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new TypeError(`${field} must be a bounded replay outcome reference.`);
    }
    const reference = value;
    if (Object.keys(reference).some((key) => !REPLAY_OUTCOME_REFERENCE_FIELDS.has(key))) {
        throw new TypeError(`${field} contains unsupported fields.`);
    }
    const decisionId = requiredReplayDecisionId(reference.decision_id, `${field}.decision_id`);
    if (!Object.prototype.hasOwnProperty.call(reference, 'label')) {
        return { decision_id: decisionId };
    }
    if (typeof reference.label !== 'string'
        || !SAFE_REPLAY_LABEL.test(reference.label)
        || SECRETISH_ARBITRATION_REFERENCE.test(reference.label)) {
        throw new TypeError(`${field}.label must be a privacy-safe identifier using 1-80 letters, numbers, dots, underscores, colons, or hyphens.`);
    }
    return { decision_id: decisionId, label: reference.label };
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
        catch (error) {
            const failure = (0, request_reliability_1.normalizeRequestError)(error);
            if (failure.code === 'request_timeout')
                throw failure;
            // Malformed error bodies do not hide the authoritative HTTP status.
        }
        throw (0, request_reliability_1.requestErrorFromResponse)(res, detail);
    }
    let json;
    try {
        json = await res.json();
    }
    catch (error) {
        const failure = (0, request_reliability_1.normalizeRequestError)(error);
        if (failure.code === 'request_timeout')
            throw failure;
        throw (0, request_reliability_1.invalidResponseError)();
    }
    if (!json || typeof json !== 'object' || Array.isArray(json) || json.error) {
        throw (0, request_reliability_1.invalidResponseError)();
    }
    return json;
}
async function fetchJsonResponse(url, init = {}) {
    return fetch(url, init, { consumeResponse: safeJsonResponse });
}
function requireObjectData(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length === 0) {
        throw (0, request_reliability_1.invalidResponseError)();
    }
    return value;
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
    let queued = false;
    try {
        return await fetch(url, init, { consumeResponse: async (res) => {
                if (queueable && !res.ok && isRetryableStatus(res.status)) {
                    if (retryQueue.length >= 25)
                        retryQueue.shift();
                    retryQueue.push({ url, init, attempts: 0 });
                    queued = true;
                }
                return safeJsonResponse(res);
            } });
    }
    catch (error) {
        if (queueable && !queued && isRetryableError(error)) {
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
function invocationIdempotencyKey(kind, supplied) {
    if (supplied !== undefined) {
        if (!(0, request_reliability_1.privacySafeIdempotencyKey)(supplied)) {
            throw new TypeError('Idempotency key must be a bounded privacy-safe identifier.');
        }
        return supplied;
    }
    return `mcp-${kind}:${(0, node_crypto_1.randomUUID)()}`;
}
function reconciliationError(exhausted, pendingReceipt, retryAfterMs) {
    return new request_reliability_1.MarrowRequestError({
        code: 'invalid_response',
        backendCode: exhausted ? 'MCP_RECONCILIATION_EXHAUSTED' : 'MCP_RECONCILIATION_INVALID',
        message: exhausted
            ? 'Marrow write reconciliation did not complete within the bounded retry window'
            : 'Marrow returned an invalid write reconciliation response',
        status: 202,
        retryable: exhausted,
        // Report the real retry hint (server lease/Retry-After or the backoff that did not fit).
        retryAfterMs: exhausted ? Math.max(250, Math.ceil(retryAfterMs ?? 1000)) : null,
        pendingReceipt,
        exactFix: exhausted
            ? 'Resume with the pending receipt key and request_hash, unchanged arguments, credentials, agent and session. Do not act, create another decision, or assume closure.'
            : 'Check Marrow status and retry explicitly; do not accept or act on the malformed pending response.',
    });
}
function validCorrelationId(value) {
    return typeof value === 'string'
        && value.length > 0
        && value.length <= 256
        && value === value.trim()
        && !/[\u0000-\u001f\u007f-\u009f]/.test(value);
}
function pendingWriteReconciliation(kind, value, idempotencyKey, expectedDecisionId) {
    if (value.retryable !== true || value.committed !== false || value.idempotency_key !== idempotencyKey) {
        return null;
    }
    if (kind === 'think') {
        const decisionId = value.decision_id === undefined ? null
            : validCorrelationId(value.decision_id) ? value.decision_id : undefined;
        if (decisionId === undefined)
            return null;
        const typed = value.reconciliation_contract !== undefined;
        if (typed && (value.reconciliation_contract !== 'agent_write_reconciliation.v1'
            || value.reconciliation_operation !== 'think' || value.safe_to_continue !== false))
            return null;
        const canonicalPending = value.phase === 'think_pending' && value.resumable === true
            && value.safe_to_continue !== true
            // The server sizes retry_after_ms to the remaining lease; any finite,
            // non-negative number (or none) is valid guidance and is clamped when used.
            && (value.retry_after_ms === undefined || value.retry_after_ms === null
                || (typeof value.retry_after_ms === 'number' && Number.isFinite(value.retry_after_ms)
                    && value.retry_after_ms >= 0));
        const state = value.reconciliation_state;
        const validState = state === 'runtime_continuation_persistence_pending' && value.decision_state === 'created'
            || state === 'runtime_decision_authority_pending' && value.decision_state === 'pending' && decisionId === null
            || state === 'pending' && (value.decision_state === 'pending' && decisionId === null
                || value.decision_state === 'created');
        if (canonicalPending && validState)
            return { decisionId };
        // Keep the earlier documented identifier-bearing continuation contract compatible.
        if (!typed && decisionId && state === 'runtime_continuation_persistence_pending'
            && value.decision_state === 'created' && value.safe_to_continue !== true)
            return { decisionId };
        return null;
    }
    if (!validCorrelationId(value.decision_id) || value.decision_id !== expectedDecisionId)
        return null;
    if (value.reconciliation_state === 'pending')
        return { decisionId: value.decision_id };
    return value.reconciliation_state === 'runtime_continuation_invalidation_pending'
        && value.outcome_persisted === true ? { decisionId: value.decision_id } : null;
}
async function waitForWriteReconciliation(delayMs, signal) {
    await new Promise((resolve, reject) => {
        let timer;
        const abort = () => {
            if (timer)
                clearTimeout(timer);
            signal?.removeEventListener('abort', abort);
            reject((0, request_reliability_1.normalizeRequestError)(signal?.reason || new DOMException('Aborted', 'AbortError')));
        };
        if (signal?.aborted) {
            abort();
            return;
        }
        timer = setTimeout(() => {
            signal?.removeEventListener('abort', abort);
            resolve();
        }, delayMs);
        signal?.addEventListener('abort', abort, { once: true });
    });
}
const AUTO_HTTP_STATE_CODES = new Set([
    'runtime_pending', 'think_pending', 'commit_pending', 'pending',
    'created', 'committed', 'closed', 'replayed', 'idempotent_replay',
    'lost_ack_recovered', 'duplicate', 'original', 'new',
]);
function traceMs(value) {
    return typeof value === 'number' && Number.isFinite(value) && value >= 0
        ? Math.min(60_000, Math.round(value))
        : null;
}
function traceCode(value) {
    const code = typeof value === 'string' ? value.toLowerCase() : '';
    return AUTO_HTTP_STATE_CODES.has(code) ? code : null;
}
function serverTimingEvidence(data) {
    const timings = {};
    const add = (name, value) => {
        const duration = traceMs(value);
        if (duration !== null && timings[name] === undefined)
            timings[name] = duration;
    };
    const performanceShape = data?.performance;
    if (performanceShape && typeof performanceShape === 'object' && !Array.isArray(performanceShape)) {
        const performanceData = performanceShape;
        add('auth_ms', performanceData.auth_ms);
        add('parse_ms', performanceData.parse_ms);
        const nestedTimings = performanceData.timings;
        if (nestedTimings && typeof nestedTimings === 'object' && !Array.isArray(nestedTimings)) {
            const nestedData = nestedTimings;
            add('auth_ms', nestedData.auth_ms);
            add('parse_ms', nestedData.parse_ms);
        }
    }
    return {
        server_timings_ms: timings,
        // The backend's detailed think/commit DB and DO stage timings are deferred
        // query-performance records, not response fields. These response spans can
        // therefore be partial at best.
        server_timing_coverage: Object.keys(timings).length ? 'partial' : 'unavailable',
    };
}
function appendAutoHttpAttempt(trace, input) {
    if (!trace)
        return null;
    if (trace.attempts.length >= AUTO_HTTP_TRACE_LIMIT) {
        trace.dropped_count += 1;
        return null;
    }
    const attempt = { ...input, actual_wait_ms: 0 };
    trace.attempts.push(attempt);
    return attempt;
}
function snapshotAutoHttpTrace(trace) {
    return {
        attempts: trace.attempts.map((attempt) => ({
            ...attempt,
            server_timings_ms: { ...attempt.server_timings_ms },
        })),
        dropped_count: trace.dropped_count,
    };
}
function attachAutoHttpTrace(error, trace) {
    if (error instanceof Error) {
        Object.defineProperty(error, AUTO_HTTP_TRACE_ERROR, {
            value: snapshotAutoHttpTrace(trace),
            configurable: true,
        });
    }
    return error;
}
function marrowAutoHttpTraceFromError(error) {
    if (!(error instanceof Error))
        return null;
    const trace = error[AUTO_HTTP_TRACE_ERROR];
    return trace ? snapshotAutoHttpTrace(trace) : null;
}
async function fetchAgentWrite(url, init, kind, idempotencyKey, expectedDecisionId, autoManaged = false, expectedRequestHash, autoHttpTrace) {
    const headers = new Headers(init.headers);
    // Bind the canonical wire body and authenticated scope without exposing either.
    const requestHash = (0, node_crypto_1.createHash)('sha256').update(JSON.stringify(canonicalAutoBindingValue({
        url, key: idempotencyKey, body: JSON.parse(String(init.body)),
        authorization: headers.get('Authorization'),
        session: headers.get('X-Marrow-Session-Id'), agent: headers.get('X-Marrow-Agent-Id'),
    }))).digest('hex');
    if (expectedRequestHash !== undefined && (!/^[a-f0-9]{64}$/.test(expectedRequestHash)
        || expectedRequestHash !== requestHash)) {
        throw new TypeError('Pending request hash does not match this exact operation and authenticated scope.');
    }
    const pendingReceipt = {
        contract: 'mcp_write_pending.v1', operation: kind, committed: false, safe_to_continue: false,
        idempotency_key: idempotencyKey, request_hash: requestHash,
    };
    let reconciledDecisionId = null;
    // A manual receipt resume must validate its very first terminal response.
    let reconciling = expectedRequestHash !== undefined;
    const reconciliationStarted = performance.now();
    const reconciliationBudgetMs = writeReconciliationBudgetMs();
    for (let attempt = 0; attempt < AGENT_WRITE_RECONCILIATION_MAX_ATTEMPTS; attempt += 1) {
        // Automatic writes have one retry owner and leave room for exact replay
        // after a lost ACK inside marrowAuto's unchanged total response deadline.
        const requestStarted = performance.now();
        let receivedStatus = null;
        let response;
        let json;
        try {
            const consumed = await (0, request_reliability_1.reliableFetch)(url, init, autoManaged
                ? {
                    retryOwner: 'caller',
                    timeoutMs: 4_000,
                    consumeResponse: async (currentResponse) => {
                        receivedStatus = currentResponse.status;
                        return { response: currentResponse, json: await safeJsonResponse(currentResponse) };
                    },
                }
                : {
                    consumeResponse: async (currentResponse) => {
                        receivedStatus = currentResponse.status;
                        return { response: currentResponse, json: await safeJsonResponse(currentResponse) };
                    },
                });
            response = consumed.response;
            json = consumed.json;
        }
        catch (error) {
            const failure = (0, request_reliability_1.normalizeRequestError)(error);
            appendAutoHttpAttempt(autoHttpTrace, {
                route_phase: kind,
                duration_ms: traceMs(performance.now() - requestStarted) || 0,
                status: receivedStatus ?? failure.status,
                error_category: failure.code,
                typed_timeout: failure.code === 'request_timeout',
                pending_code: null,
                replay_code: null,
                ...serverTimingEvidence(),
                requested_wait_ms: traceMs(failure.retryAfterMs),
            });
            throw error;
        }
        if (!json.data || typeof json.data !== 'object' || Array.isArray(json.data)) {
            appendAutoHttpAttempt(autoHttpTrace, {
                route_phase: kind,
                duration_ms: traceMs(performance.now() - requestStarted) || 0,
                status: response.status,
                error_category: 'invalid_response',
                typed_timeout: false,
                pending_code: null,
                replay_code: null,
                ...serverTimingEvidence(),
                requested_wait_ms: null,
            });
            throw (0, request_reliability_1.invalidResponseError)();
        }
        const data = json.data;
        const headerWait = (0, request_reliability_1.responseRetryAfter)(response);
        const requestedWait = pendingWriteRequestedWaitMs(data, headerWait);
        const traceAttempt = appendAutoHttpAttempt(autoHttpTrace, {
            route_phase: kind,
            duration_ms: traceMs(performance.now() - requestStarted) || 0,
            status: response.status,
            error_category: null,
            typed_timeout: false,
            pending_code: response.status === 202
                ? traceCode(data.pending_code) || traceCode(data.phase) || `${kind}_pending`
                : null,
            replay_code: traceCode(data.replay_code) || traceCode(data.replay_state)
                || (data.replayed === true ? 'replayed' : null),
            ...serverTimingEvidence(data),
            requested_wait_ms: requestedWait,
        });
        if (autoManaged) {
            const retryGuidance = (0, request_reliability_1.responseRetryAfter)(response);
            if (!retryGuidance.valid) {
                data.resumable = false;
                data.retryable = false;
                data.retry_after_ms = null;
            }
            else if (retryGuidance.delayMs !== null) {
                const bodyDelay = typeof data.retry_after_ms === 'number' && Number.isFinite(data.retry_after_ms)
                    ? data.retry_after_ms : 0;
                data.retry_after_ms = Math.max(bodyDelay, retryGuidance.delayMs);
            }
            if ((data.idempotency_key !== undefined && data.idempotency_key !== idempotencyKey)
                || (kind === 'commit' && data.decision_id !== undefined && data.decision_id !== expectedDecisionId)
                || (response.status === 202 && data.committed === true)) {
                throw reconciliationError(false);
            }
            // Canonical write reconciliation predates auto's phase/resumable fields.
            // Adapt only a validated exact-operation pending response.
            if (response.status === 202 && retryGuidance.valid && data.resumable !== false
                && pendingWriteReconciliation(kind, data, idempotencyKey, expectedDecisionId)) {
                data.phase = `${kind}_pending`;
                data.resumable = true;
            }
        }
        // marrow_auto owns its existing phase/budget continuation contract. Its
        // reserved keys are created only by autoIdempotencyKey below.
        if (response.status === 202 && autoManaged) {
            return { response, data };
        }
        if (response.status !== 202 || (kind === 'commit' && data.outcome_state === 'observed_unverified')) {
            if (reconciling) {
                if (data.idempotency_key !== undefined && data.idempotency_key !== idempotencyKey) {
                    throw reconciliationError(false);
                }
                if (kind === 'think' && (!validCorrelationId(data.decision_id)
                    || (reconciledDecisionId && data.decision_id !== reconciledDecisionId))) {
                    throw reconciliationError(false);
                }
                if (kind === 'commit' && data.decision_id !== undefined && data.decision_id !== expectedDecisionId) {
                    throw reconciliationError(false);
                }
            }
            return { response, data };
        }
        const pending = pendingWriteReconciliation(kind, data, idempotencyKey, expectedDecisionId);
        if (!pending || (reconciledDecisionId && pending.decisionId && pending.decisionId !== reconciledDecisionId)) {
            throw reconciliationError(false);
        }
        reconciling = true;
        if (pending.decisionId)
            reconciledDecisionId = pending.decisionId;
        // Resume the SAME operation after the server's guidance (or jittered backoff).
        // If the wait plus a useful request cannot fit the budget, stop and hand back
        // the resumable pending receipt: never success, never a second decision.
        const delayMs = writeReconciliationDelayMs(attempt, requestedWait);
        const remainingBudget = reconciliationBudgetMs - (performance.now() - reconciliationStarted);
        if (attempt + 1 >= AGENT_WRITE_RECONCILIATION_MAX_ATTEMPTS
            || remainingBudget - delayMs < AGENT_WRITE_RECONCILIATION_REQUEST_MARGIN_MS) {
            throw reconciliationError(true, pendingReceipt, delayMs);
        }
        const waitStarted = performance.now();
        await waitForWriteReconciliation(delayMs, init.signal || undefined);
        if (traceAttempt)
            traceAttempt.actual_wait_ms = traceMs(performance.now() - waitStarted) || 0;
    }
    throw reconciliationError(true, pendingReceipt);
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
    if (options?.requestHash !== undefined && !options.idempotencyKey)
        throw new TypeError('Pending resume requires the original idempotency key.');
    const idempotencyKey = invocationIdempotencyKey('think', options?.idempotencyKey);
    const thinkInit = {
        method: 'POST',
        headers: {
            ...buildHeaders(apiKey, sessionId, 'application/json', agentId),
            'Idempotency-Key': idempotencyKey,
        },
        body: JSON.stringify(body),
        signal,
    };
    const { response, data } = await fetchAgentWrite(thinkUrl, thinkInit, 'think', idempotencyKey, undefined, options?.[AUTO_MANAGED_WRITE] === true, options?.requestHash, options?.[AUTO_HTTP_TRACE]);
    return markAutoResponseStatus(data, response.status);
}
/**
 * Explicitly commit the result of an action to Marrow.
 */
/**
 * A caller-written proof.owner_approval is not an approval: the server issues
 * approvals (host prompt or dashboard) and binds them to the gate receipt. The
 * client never sends such a claim, so a model cannot approve its own hold.
 */
function withoutOwnerApprovalClaim(proof) {
    if (!proof || typeof proof !== 'object' || Array.isArray(proof))
        return undefined;
    if (!Object.prototype.hasOwnProperty.call(proof, 'owner_approval'))
        return proof;
    const { owner_approval: _claim, ...rest } = proof;
    return Object.keys(rest).length > 0 ? rest : undefined;
}
async function marrowCommit(apiKey, baseUrl, params, sessionId, agentId, signal, idempotencyKey) {
    let runtimeGate = null;
    let gateReceiptId = params.gate_receipt_id || params.gate_receipt;
    let observationOnly = false;
    // An approval is issued by the server (host prompt or dashboard), never written by the caller.
    const commitProof = withoutOwnerApprovalClaim(params.proof);
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
                type: params.type || 'general',
                target: params.target ? (0, redact_1.redactSensitiveText)(params.target) : undefined,
                surfaces: params.surfaces || [],
                context: { mcp_commit_auto_gate: true },
                proof: commitProof ? (0, redact_1.redactSensitiveValue)(commitProof) : undefined,
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
    if (commitProof)
        body.proof = (0, redact_1.redactSensitiveValue)(commitProof);
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
        body.model_usage = (0, model_usage_1.normalizeModelUsage)(modelUsage);
    const resolvedIdempotencyKey = invocationIdempotencyKey('commit', idempotencyKey);
    const commitInit = {
        method: 'POST',
        headers: {
            ...buildHeaders(apiKey, sessionId, 'application/json', agentId),
            'Idempotency-Key': resolvedIdempotencyKey,
        },
        body: JSON.stringify(body),
        signal,
    };
    const { response, data } = await fetchAgentWrite(`${baseUrl}/v1/agent/commit`, commitInit, 'commit', resolvedIdempotencyKey, params.decision_id, params[AUTO_MANAGED_WRITE] === true, undefined, params[AUTO_HTTP_TRACE]);
    if (data.outcome_state === 'observed_unverified') {
        if (!isDurableObservedOutcome(data))
            throw (0, request_reliability_1.invalidResponseError)();
        // A backend 202 can mean durable acceptance rather than async work. Do not
        // attach the internal pending marker: this exact observation is terminal
        // delivery and any trusted promotion must be a new explicit commit attempt.
        return { ...data, committed: false, runtime_gate: runtimeGate };
    }
    if (observationOnly)
        throw (0, request_reliability_1.invalidResponseError)();
    if (response.status === 202
        && params[AUTO_MANAGED_WRITE] === true
        && (data.phase === undefined || data.phase === 'commit_pending' || data.resumable === true)) {
        return markAutoResponseStatus({ ...data, committed: false, runtime_gate: runtimeGate }, response.status);
    }
    if (typeof data.committed !== 'boolean') {
        throw (0, request_reliability_1.invalidResponseError)();
    }
    return markAutoResponseStatus({ ...data, committed: data.committed, runtime_gate: runtimeGate }, response.status);
}
async function marrowModelUsage(apiKey, baseUrl, input, sessionId, agentId) {
    const body = (0, model_usage_1.normalizeModelUsage)({
        ...input,
        agent_id: input.agent_id || agentId,
        session_id: input.session_id || sessionId,
        source: input.source || 'mcp',
    });
    const json = await fetchWithRetryQueue(`${baseUrl}/v1/agent/model-usage`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(body),
    }, true);
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
        && pending.resumable !== false && pending.retryable !== false
        && (pending.phase === phase || (pending.phase === undefined && pending.resumable === true));
}
function autoContinuationDelay(pending) {
    const requested = pending.retry_after_ms;
    return typeof requested === 'number' && Number.isFinite(requested) && requested >= 0
        ? Math.max(25, Math.ceil(requested))
        : 50;
}
async function waitForAutoContinuation(pending, startedAt, responseBudgetMs, autoHttpTrace) {
    const remaining = responseBudgetMs - (Date.now() - startedAt) - AUTO_RESPONSE_DEADLINE_MARGIN_MS;
    if (remaining <= 0)
        return false;
    const delayMs = autoContinuationDelay(pending);
    // Never retry early or consume a partial delay that cannot leave request time.
    if (delayMs >= remaining)
        return false;
    const resumeAt = performance.now() + delayMs;
    const waitStarted = performance.now();
    do {
        await new Promise((resolve) => setTimeout(resolve, Math.ceil(resumeAt - performance.now())));
    } while (performance.now() < resumeAt);
    const latestAttempt = autoHttpTrace?.attempts[autoHttpTrace.attempts.length - 1];
    if (latestAttempt) {
        latestAttempt.actual_wait_ms = Math.min(60_000, latestAttempt.actual_wait_ms + Math.max(0, Math.round(performance.now() - waitStarted)));
    }
    return responseBudgetMs - (Date.now() - startedAt) > AUTO_RESPONSE_DEADLINE_MARGIN_MS;
}
/** Link refusals that another request cannot change. */
const FINAL_OWNER_LINK_CODES = new Set([
    'MARROW_APPROVAL_CHANNEL_UNAVAILABLE', 'MARROW_APPROVAL_LINK_LIMITED', 'MARROW_APPROVAL_LINK_NOT_HELD',
    'MARROW_APPROVAL_LINK_SCOPE_MISMATCH', 'MARROW_APPROVAL_LINK_INVALID', 'MARROW_APPROVAL_LINK_DECISION_REQUIRED',
    'MARROW_PRE_ACTION_GATE_USED', 'MARROW_PRE_ACTION_GATE_EXPIRED', 'MARROW_OWNER_APPROVAL_ALREADY_DECIDED',
    'MARROW_GATE_RECEIPT_NOT_FOUND',
]);
const MAX_OWNER_LINK_ATTEMPTS = 3;
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
        ...(input.exactNextAction ? { exact_next_action: input.exactNextAction }
            : resumable && input.phase.endsWith('_pending') ? {
                exact_next_action: 'Resume marrow_auto with this same operation_id, tenant, agent, session, action, surfaces, outcome, proof, and approval receipts after retry_after_ms. Pending is not confirmation of closure.',
            } : {}),
        ...(input.runtimeGate ? { runtime_gate: input.runtimeGate } : {}),
        ...(input.approval ? { approval: input.approval } : {}),
        phase_timings_ms: {
            ...input.timings,
            total: Date.now() - input.startedAt,
        },
        http_attempt_trace: snapshotAutoHttpTrace(input.autoHttpTrace),
    };
}
function autoApprovalState(guidance, status, state) {
    return {
        state: state || status?.state || 'unavailable',
        gate_receipt_id: guidance.gateReceiptId,
        approver: guidance.approvalAuthority,
        verified_approval_required: guidance.verifiedApprovalRequired,
        verified_approval_categories: guidance.verifiedApprovalCategories,
        approval_source: status?.approval_source ?? null,
        answered_by: status?.approval_answered_by ?? null,
        poll_after_ms: status?.poll_after_ms ?? guidance.pollAfterMs,
        expires_at: status?.expires_at ?? guidance.expiresAt,
    };
}
/**
 * What the status says about an approval of this receipt. "The account owner"
 * only for the owner's verified approval; anything else is named for what it is.
 */
function approvalStatement(status, gateReceiptId) {
    if (status.approval_source === 'host_prompt') {
        return status.approval_answered_by === 'host_operator' ? `The operator approved gate receipt ${gateReceiptId} in the host prompt (client-attested).`
            : status.approval_answered_by === 'owner_chat_preapproval' ? `The account owner's chat pre-approval covers gate receipt ${gateReceiptId} (client-attested).`
                : `An allow rule in the host approved gate receipt ${gateReceiptId} (client-attested).`;
    }
    if (status.approval_trust === 'verified'
        && (status.approval_answered_by === 'account_owner' || status.approval_source === 'dashboard' || status.approval_source === 'one_tap')) {
        return `The account owner approved gate receipt ${gateReceiptId}.`;
    }
    return `Marrow recorded an approval for gate receipt ${gateReceiptId}.`;
}
/** What happened to the owner's one-tap link in this operation. Never claims a send that did not happen. */
function ownerLinkSentence(guidance, link) {
    if (!guidance.hostApprovalSupported) {
        return 'This Marrow service does not support chat or terminal approvals yet, so only the account owner can approve it.';
    }
    if (link?.sent)
        return `An approval link was sent to the account owner${link.channel ? ` (${link.channel})` : ''}.`;
    if (link?.final) {
        return `Marrow could not send the account owner an approval link${link.finalCode ? ` (${link.finalCode})` : ''}; tell the operator this action is waiting for the account owner's approval.`;
    }
    if (link?.notSent)
        return 'Nothing was sent to anyone; it waits quietly until a person approves it.';
    if (link && link.attempts > 0) {
        return 'Marrow could not send the account owner an approval link yet; calling marrow_auto again with this same operation_id tries again.';
    }
    // Owner rule: an ordinary hold sends no email. It waits quietly.
    return 'Nobody can approve it from this tool call, so it waits quietly; nothing was sent to anyone. Carry on with other work; a person approves it at their next interactive session, where the host asks them.';
}
/**
 * The text an agent follows while auto waits on a held action. It never asks
 * the agent to write an approval: only the account owner (one-tap link) or
 * the operator's host prompt can approve, and the server records it.
 */
function ordinaryHoldWaitText(guidance, link) {
    if (guidance.hostApprovalRefusal === 'owner_decline_stands' && !link?.sent) {
        // The owner said no: the owner is asked again only when the operator asks.
        const ask = guidance.approvalLinkPath
            ? link && link.attempts > 0
                ? ` ${ownerLinkSentence(guidance, link)}`
                : ' If the operator asks you to ask the owner again, call marrow_auto again with this same operation_id and request_owner_link: true; Marrow then sends the owner a one-tap approval link.'
            : '';
        return `Marrow is holding this action (gate receipt ${guidance.gateReceiptId}). Do not run it. The account owner declined this action${guidance.ownerDeclinedAt ? ` at ${guidance.ownerDeclinedAt}` : ' earlier'}, and only the owner can reverse that.${ask} Never write or claim an approval yourself.`;
    }
    const why = guidance.verifiedApprovalRequired === true
        ? ` The account owner approves ${guidance.verifiedApprovalCategories.join(', ') || 'these'} actions personally.`
        : guidance.hostApprovalRefusal === 'owner_decline_stands'
            ? ` The account owner declined this action${guidance.ownerDeclinedAt ? ` at ${guidance.ownerDeclinedAt}` : ' earlier'}.`
            : '';
    return `Marrow is holding this action for approval (gate receipt ${guidance.gateReceiptId}). Do not run it yet.${why} ${ownerLinkSentence(guidance, link)} Call marrow_auto again with this same operation_id after retry_after_ms; Marrow resumes on the same gate receipt once it is approved. Never write or claim an approval yourself.`;
}
/**
 * Asks Marrow to send the account owner a one-tap link once per operation; a
 * retryable failure is tried again on a later call, within the server's limit.
 */
async function requestAutoOwnerLink(input) {
    const previous = input.binding.ownerLink;
    if (previous?.sent || previous?.final || (previous?.attempts ?? 0) >= MAX_OWNER_LINK_ATTEMPTS)
        return;
    const attempts = (previous?.attempts ?? 0) + 1;
    const timeout = createTimeoutSignal(input.timeoutMs);
    try {
        const link = await marrowRequestApprovalLink(input.apiKey, input.baseUrl, input.gateReceiptId, input.decisionId, input.sessionId, input.agentId, timeout.signal);
        if (link.ok) {
            input.binding.ownerLink = { sent: true, channel: link.link.channel, attempts, finalCode: null, final: false };
        }
        else if (link.notSent) {
            input.binding.ownerLink = { sent: false, notSent: true, channel: null, attempts, finalCode: link.code, final: true };
        }
        else {
            const final = (!link.retryable && Boolean(link.code && FINAL_OWNER_LINK_CODES.has(link.code))) || attempts >= MAX_OWNER_LINK_ATTEMPTS;
            input.binding.ownerLink = { sent: false, channel: null, attempts, finalCode: link.code, final };
        }
    }
    catch {
        input.binding.ownerLink = { sent: false, channel: null, attempts, finalCode: null, final: attempts >= MAX_OWNER_LINK_ATTEMPTS };
    }
    finally {
        timeout.cancel();
    }
}
async function readOrdinaryApprovalForAuto(input) {
    let status = null;
    // Poll as the server advises, inside auto's bounded response budget.
    for (let reads = 0; reads < 3; reads += 1) {
        const remaining = input.responseBudgetMs - (Date.now() - input.startedAt) - AUTO_RESPONSE_DEADLINE_MARGIN_MS;
        if (remaining < 250)
            break;
        const timeout = createTimeoutSignal(input.responseBudgetMs, input.startedAt);
        try {
            const result = await marrowOwnerApprovalStatus(input.apiKey, input.baseUrl, input.guidance.gateReceiptId, input.sessionId, input.agentId, timeout.signal);
            if (result.kind === 'not_found')
                return { status: null, notFound: true };
            status = result.status;
        }
        catch (error) {
            const failure = (0, request_reliability_1.normalizeRequestError)(error);
            if (failure.retryable || failure.code === 'request_timeout')
                break;
            throw error;
        }
        finally {
            timeout.cancel();
        }
        if (!status || (status.state !== 'pending' && status.state !== 'unavailable' && status.state !== 'arbitration_review'))
            break;
        const waitMs = status.poll_after_ms ?? input.guidance.pollAfterMs;
        if (!await waitForAutoContinuation({ retry_after_ms: waitMs }, input.startedAt, input.responseBudgetMs, input.autoHttpTrace))
            break;
    }
    return { status, notFound: false };
}
/**
 * Bounded outcome logging helper for tool hooks and simple integrations.
 * One outer invocation logs intent and, when an outcome is supplied, continues
 * resumable server phases so the outcome normally closes in-band. If the
 * caller's deadline is reached, the same operation ID resumes without opening
 * another decision.
 */
async function marrowAuto(apiKey, baseUrl, params, sessionId, agentId, timeoutMs, options) {
    const autoHttpTrace = { attempts: [], dropped_count: 0 };
    try {
        const result = await marrowAutoWithTrace(apiKey, baseUrl, params, sessionId, agentId, timeoutMs, autoHttpTrace, options);
        // The runtime's next-step texts are written for API clients (endpoints to
        // call); the raw runtime_gate an agent reads never carries them.
        return result.runtime_gate ? { ...result, runtime_gate: withoutServerNextActions(result.runtime_gate) } : result;
    }
    catch (error) {
        throw attachAutoHttpTrace(error, autoHttpTrace);
    }
}
/** Removes every exact_next_action(s) from a server response (bounded depth). */
function withoutServerNextActions(value, depth = 0) {
    if (depth > 16 || !value || typeof value !== 'object')
        return value;
    if (Array.isArray(value))
        return value.map((item) => withoutServerNextActions(item, depth + 1));
    const out = {};
    for (const [key, item] of Object.entries(value)) {
        if (key === 'exact_next_action' || key === 'exact_next_actions')
            continue;
        out[key] = withoutServerNextActions(item, depth + 1);
    }
    return out;
}
/**
 * The operator marker the backend needs to count an elicitation answer as the
 * operator's. Client-attested: Marrow trusts the MCP client to show the dialog
 * to a person (the agent cannot answer it through any tool argument). A client
 * that let the model answer elicitation requests would make the agent's own
 * answer count as the operator's.
 */
exports.ELICITATION_HOOK_EVENT = 'mcp_elicitation';
async function elicitAutoApproval(input) {
    const askedAt = new Date().toISOString();
    const notice = input.guidance.operatorNotice ? ` Note: ${input.guidance.operatorNotice}` : '';
    let answer = null;
    try {
        answer = await input.elicit({
            gateReceiptId: input.guidance.gateReceiptId,
            message: `Marrow holds this action for your approval: ${input.action}.${input.reason ? ` Reason: ${input.reason}` : ''}${notice} Approve only if you authorize this exact action (gate receipt ${input.guidance.gateReceiptId}).`.slice(0, 900),
        });
    }
    catch {
        answer = null;
    }
    if (!answer)
        return null;
    const report = {
        verdict: answer,
        host: input.host || 'other',
        host_session_id: input.hostSessionId || input.sessionId || 'mcp-session',
        hook_event: exports.ELICITATION_HOOK_EVENT,
        pre_action_event_id: null,
        asked_at: askedAt,
        answered_at: new Date().toISOString(),
        ...(input.decisionId ? { decision_id: input.decisionId } : {}),
    };
    const timeout = createTimeoutSignal(4_000);
    try {
        const result = await marrowHostApproval(input.apiKey, input.baseUrl, input.guidance.gateReceiptId, report, input.sessionId, input.agentId, timeout.signal);
        return result.ok ? answer : null;
    }
    catch {
        return null;
    }
    finally {
        timeout.cancel();
    }
}
async function marrowAutoWithTrace(apiKey, baseUrl, params, sessionId, agentId, timeoutMs, autoHttpTrace, options) {
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
                        // Full canonical receipt scope and expiry are required for reuse.
                        response_mode: 'expanded',
                        // Proof is commit evidence, not part of immutable runtime authorization.
                        // Keeping it out makes missing -> supplied proof a monotonic continuation.
                        context: { source: 'mcp_auto_risk_upgrade', operation_id: operationId },
                    }, sessionId, agentId, runtimeTimeout.signal, autoIdempotencyKey(operationId, 'runtime'));
                    operationBinding.runtimeGate = runtimeGate;
                }
                catch (error) {
                    if ((0, request_reliability_1.normalizeRequestError)(error).code !== 'request_timeout'
                        || !await waitForAutoContinuation({}, startedAt, responseBudgetMs, autoHttpTrace)) {
                        timings.runtime = Date.now() - phaseStarted;
                        if ((0, request_reliability_1.normalizeRequestError)(error).code === 'request_timeout') {
                            return autoPartial({ operationId, phase: 'runtime_pending', timings, startedAt, autoHttpTrace });
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
    const ordinaryGuidance = runtimeGate ? (0, runtime_contract_1.ordinaryApprovalGuidance)(runtimeGate) : null;
    const ordinaryApprovalDeclared = Boolean(ordinaryGuidance);
    if (runtimeGate && !runtimeGate.arbitration && (runtimeGate.decision_id || ordinaryApprovalDeclared)) {
        if (!(0, runtime_contract_1.runtimeDecisionMatchesAutoScope)(runtimeGate, {
            action: (0, redact_1.redactSensitiveText)(params.action_for_gate || params.action), agentId, sessionId,
        }) || (params.gate_receipt_id && params.gate_receipt_id !== gateReceiptId))
            throw (0, request_reliability_1.invalidResponseError)();
        const runtimeDecisionId = runtimeGate.decision_id;
        if (decisionId && decisionId !== runtimeDecisionId) {
            throw new request_reliability_1.MarrowRequestError({
                code: 'request_failed', backendCode: 'MARROW_AUTO_RUNTIME_DECISION_MISMATCH',
                message: 'The runtime receipt and auto operation are bound to different decisions.',
                status: 409, retryable: false,
                exactFix: 'Stop and reconcile this operation with its original server-issued decision and gate receipt.',
            });
        }
        decisionId = runtimeDecisionId;
        operationBinding.decisionId = runtimeDecisionId;
    }
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
                exactFix: 'Stop this operation. Start a new arbitrated marrow_auto operation and preserve the arbitration decision_id, gate receipt, arbitration receipt, and owner approval receipt together.',
            });
        }
        decisionId = arbitrationDecisionId;
        operationBinding.decisionId = arbitrationDecisionId;
    }
    const reusedDecision = Boolean(decisionId);
    let pendingThinkDecisionId = operationBinding.pendingThinkDecisionId || null;
    while (!decisionId) {
        const thinkTimeout = createTimeoutSignal(responseBudgetMs, startedAt);
        let thinkResult;
        try {
            thinkResult = await marrowThink(apiKey, baseUrl, {
                action: params.action,
                type: params.type || 'general',
                surfaces: params.surfaces,
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
                [AUTO_MANAGED_WRITE]: true,
                [AUTO_HTTP_TRACE]: autoHttpTrace,
            });
        }
        catch (error) {
            const failure = (0, request_reliability_1.normalizeRequestError)(error);
            const recoverable = error instanceof request_reliability_1.MarrowRequestError && failure.retryable && failure.code !== 'invalid_response';
            if (!recoverable
                || !await waitForAutoContinuation({ retry_after_ms: failure.retryAfterMs }, startedAt, responseBudgetMs, autoHttpTrace)) {
                timings.think = Date.now() - thinkStarted;
                if (recoverable) {
                    return autoPartial({ operationId, decisionId: pendingThinkDecisionId, phase: 'think_pending', runtimeGate, timings, startedAt, autoHttpTrace,
                        retryAfterMs: failure.retryAfterMs ?? undefined });
                }
                throw error;
            }
            continue;
        }
        finally {
            thinkTimeout.cancel();
        }
        const receivedDecisionId = validCorrelationId(thinkResult.decision_id) ? thinkResult.decision_id : null;
        if (pendingThinkDecisionId && receivedDecisionId && receivedDecisionId !== pendingThinkDecisionId) {
            throw reconciliationError(false);
        }
        if (!isAutoPendingResponse(thinkResult, 'think_pending')) {
            if (thinkResult[AUTO_RESPONSE_STATUS] === 202 || !receivedDecisionId) {
                throw (0, request_reliability_1.invalidResponseError)();
            }
            decisionId = receivedDecisionId;
            operationBinding.decisionId = decisionId;
            break;
        }
        if (receivedDecisionId) {
            pendingThinkDecisionId = receivedDecisionId;
            operationBinding.pendingThinkDecisionId = receivedDecisionId;
        }
        if (!await waitForAutoContinuation(thinkResult, startedAt, responseBudgetMs, autoHttpTrace)) {
            timings.think = Date.now() - thinkStarted;
            return autoPartial({ operationId, decisionId: pendingThinkDecisionId, phase: 'think_pending', runtimeGate, timings, startedAt, autoHttpTrace,
                retryAfterMs: autoContinuationDelay(thinkResult) });
        }
    }
    timings.think = reusedDecision ? 0 : Date.now() - thinkStarted;
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
    // Arbitration review with the server's one-tap path: the owner picks a
    // proposal through a link, and the status read hands over the owner's receipt.
    let ownerApprovalReceiptForCommit = params.owner_approval_receipt_id;
    let arbitrationReceiptForCommit = params.arbitration_receipt_id;
    const arbitrationGuidance = arbitrationRequiresOwnerApproval && !params.owner_approval_receipt_id
        ? (0, runtime_contract_1.arbitrationApprovalGuidance)(runtimeGate)
        : null;
    if (arbitrationGuidance) {
        const arbitrationWait = (exactNextAction, retryAfterMs, resumable = true) => autoPartial({
            operationId, decisionId, phase: 'owner_approval_required', runtimeGate, timings, startedAt, autoHttpTrace,
            resumable, retryAfterMs: retryAfterMs ?? undefined, exactNextAction,
        });
        const linkBudget = responseBudgetMs - (Date.now() - startedAt) - AUTO_RESPONSE_DEADLINE_MARGIN_MS - 300;
        if (linkBudget > 300) {
            await requestAutoOwnerLink({
                apiKey, baseUrl, gateReceiptId: arbitrationGuidance.gateReceiptId, decisionId, sessionId, agentId,
                binding: operationBinding, timeoutMs: Math.min(2_000, linkBudget),
            });
        }
        const read = await readOrdinaryApprovalForAuto({
            apiKey, baseUrl, guidance: arbitrationGuidance, sessionId, agentId, startedAt, responseBudgetMs, autoHttpTrace,
        });
        const status = read.status;
        const link = operationBinding.ownerLink;
        const linkText = link?.sent ? `An approval link was sent to the account owner${link.channel ? ` (${link.channel})` : ''}.`
            : link?.final ? `Marrow could not send the account owner an approval link${link.finalCode ? ` (${link.finalCode})` : ''}; tell the operator this action is waiting for the account owner's choice.`
                : link && link.attempts > 0 ? 'Marrow could not send the account owner an approval link yet; calling marrow_auto again with this same operation_id tries again.'
                    : 'Tell the operator this action is waiting for the account owner\'s choice.';
        if (read.notFound) {
            return arbitrationWait(`Marrow could not find gate receipt ${arbitrationGuidance.gateReceiptId} for this agent and session. Do not run any proposal; request fresh runtime guidance for it.`, null, false);
        }
        if (!status || status.state === 'arbitration_review' || status.state === 'pending' || status.state === 'unavailable') {
            return arbitrationWait(`Marrow is holding this action for arbitration review (gate receipt ${arbitrationGuidance.gateReceiptId}). Do not run any proposal yet. The account owner picks and approves one proposal. ${linkText} Call marrow_auto again with this same operation_id after retry_after_ms. Never write or claim an approval yourself.`, status?.poll_after_ms ?? arbitrationGuidance.pollAfterMs);
        }
        if (status.state === 'approved' && status.owner_approval_receipt_id) {
            ownerApprovalReceiptForCommit = status.owner_approval_receipt_id;
            arbitrationReceiptForCommit = arbitrationGuidance.arbitrationReceiptId;
        }
        else if (status.state === 'used') {
            return {
                operation_id: operationId, decision_id: decisionId, committed: false, phase: 'closed', resumable: false, retry_after_ms: null,
                exact_next_action: `Gate receipt ${arbitrationGuidance.gateReceiptId} is already used: this operation is closed. Do not run this action again.`,
                runtime_gate: runtimeGate, closure: status.owner_approval_receipt_id ? 'already_closed' : 'already_closed_denial',
                phase_timings_ms: { ...timings, total: Date.now() - startedAt }, http_attempt_trace: snapshotAutoHttpTrace(autoHttpTrace),
            };
        }
        else if (status.state === 'declined') {
            return arbitrationWait(`The account owner approved none of the proposals (gate receipt ${arbitrationGuidance.gateReceiptId}). Do not run any proposal. If nothing ran, close it with marrow_commit: success false, an outcome that starts "Denied by Marrow pre-action gate", and the same gate_receipt_id.`, null, false);
        }
        else {
            return arbitrationWait(`Gate receipt ${arbitrationGuidance.gateReceiptId} is not waiting for the owner's choice (${status.state}). Do not run any proposal; request fresh runtime guidance for this exact action.`, null, false);
        }
    }
    const matchingRequiredApprovalReceipts = Boolean(ownerApprovalReceiptForCommit
        && (!runtimeArbitrationReceiptId
            || arbitrationReceiptForCommit === runtimeArbitrationReceiptId));
    // An ordinary hold: wait for the approval through the agent-key status read
    // (bounded by this call's budget), then resume on the same gate receipt.
    // Approval comes only from the server (the account owner's one-tap link, or
    // the operator's host prompt recorded by the host hook), never from proof.
    let ordinaryApproval = null;
    let ordinaryApprovalState;
    if (genericReviewRequired && ordinaryGuidance && runtimeGate) {
        // In flow first: where the MCP client can ask its user (elicitation), the
        // person answers right here, once per held action; the answer is reported
        // through the host-approval route (client-attested), never by the agent.
        let elicited = null;
        if (ordinaryGuidance.hostApprovalAccepted && options?.elicitApproval && !operationBinding.elicitedReceipts?.includes(ordinaryGuidance.gateReceiptId)) {
            operationBinding.elicitedReceipts = [...(operationBinding.elicitedReceipts || []), ordinaryGuidance.gateReceiptId].slice(-8);
            elicited = await elicitAutoApproval({
                apiKey, baseUrl, guidance: ordinaryGuidance, decisionId, sessionId, agentId,
                action: (0, redact_1.redactSensitiveText)(params.action_for_gate || params.action).slice(0, 300),
                reason: typeof runtimeGate.risk_gate?.reasons?.[0]?.message === 'string' ? runtimeGate.risk_gate.reasons[0].message.slice(0, 240) : '',
                elicit: options.elicitApproval,
                host: options.elicitHost,
                hostSessionId: options.elicitHostSessionId,
            });
        }
        // Owner rule: the owner's link only for an owner-locked category, the owner's
        // own standing decline when the operator asks, or (with no way to ask anyone
        // here) an unattended run whose owner turned on pings. Otherwise quiet.
        const policy = (0, runtime_contract_1.ownerLinkPolicy)(ordinaryGuidance, { unattended: !options?.elicitApproval });
        const linkWanted = elicited === null && (policy === 'now' || (policy === 'on_request' && params.request_owner_link === true));
        const linkBudget = responseBudgetMs - (Date.now() - startedAt) - AUTO_RESPONSE_DEADLINE_MARGIN_MS - 300;
        if (ordinaryGuidance.approvalLinkPath && linkWanted && linkBudget > 300) {
            await requestAutoOwnerLink({
                apiKey, baseUrl, gateReceiptId: ordinaryGuidance.gateReceiptId, decisionId, sessionId, agentId,
                binding: operationBinding, timeoutMs: Math.min(2_000, linkBudget),
            });
        }
        // After a person answered here, read the status once with its own time (the answer took human time).
        const read = elicited
            ? await readOrdinaryApprovalForAuto({
                apiKey, baseUrl, guidance: ordinaryGuidance, sessionId, agentId, startedAt: Date.now(), responseBudgetMs, autoHttpTrace,
            })
            : await readOrdinaryApprovalForAuto({
                apiKey, baseUrl, guidance: ordinaryGuidance, sessionId, agentId, startedAt, responseBudgetMs, autoHttpTrace,
            });
        const status = read.status;
        ordinaryApprovalState = autoApprovalState(ordinaryGuidance, status, read.notFound ? 'not_found' : undefined);
        const terminal = (exactNextAction) => autoPartial({
            operationId, decisionId, phase: 'review_required', runtimeGate, timings, startedAt, autoHttpTrace,
            resumable: false, exactNextAction, approval: ordinaryApprovalState,
        });
        if (read.notFound) {
            return terminal(`Marrow could not find gate receipt ${ordinaryGuidance.gateReceiptId} for this agent and session. Do not run the action; request fresh runtime guidance for it.`);
        }
        if (!status || status.state === 'pending' || status.state === 'unavailable') {
            return autoPartial({
                operationId, decisionId, phase: 'owner_approval_required', runtimeGate, timings, startedAt, autoHttpTrace,
                resumable: true,
                retryAfterMs: status?.poll_after_ms ?? ordinaryGuidance.pollAfterMs,
                exactNextAction: ordinaryHoldWaitText(ordinaryGuidance, operationBinding.ownerLink),
                approval: ordinaryApprovalState,
            });
        }
        if (status.state === 'declined') {
            const declinedBy = status.approval_source === 'host_prompt' ? 'The operator declined it in the host prompt' : 'The account owner declined it';
            if (params.outcome === undefined && decisionId && Date.now() - startedAt < responseBudgetMs - 250) {
                // The action has not run: close the decision as a verified gate denial.
                const denialTimeout = createTimeoutSignal(responseBudgetMs, startedAt);
                try {
                    const denial = await marrowCommit(apiKey, baseUrl, {
                        decision_id: decisionId,
                        success: false,
                        outcome: `Denied by Marrow pre-action gate: ${declinedBy.charAt(0).toLowerCase()}${declinedBy.slice(1)} (gate receipt ${ordinaryGuidance.gateReceiptId}); the action did not run.`,
                        gate_receipt_id: gateReceiptId,
                        auto_gate: false,
                        [AUTO_MANAGED_WRITE]: true,
                        [AUTO_HTTP_TRACE]: autoHttpTrace,
                    }, sessionId, agentId, denialTimeout.signal, autoIdempotencyKey(operationId, 'commit'));
                    if (denial.committed) {
                        return {
                            operation_id: operationId,
                            decision_id: decisionId,
                            committed: true,
                            phase: 'closed',
                            resumable: false,
                            retry_after_ms: null,
                            exact_next_action: `${declinedBy}. Marrow closed this decision as a denial. Do not run this action.`,
                            runtime_gate: runtimeGate,
                            approval: ordinaryApprovalState,
                            closure: 'gate_denial',
                            phase_timings_ms: { ...timings, total: Date.now() - startedAt },
                            http_attempt_trace: snapshotAutoHttpTrace(autoHttpTrace),
                        };
                    }
                }
                catch { /* the decline stands; the denial closure stays open below */ }
                finally {
                    denialTimeout.cancel();
                }
            }
            return terminal(`${declinedBy} (gate receipt ${ordinaryGuidance.gateReceiptId}). Do not run this action. If it has not run, close it with marrow_commit: success false, an outcome that starts "Denied by Marrow pre-action gate", and the same gate_receipt_id.`);
        }
        if (status.state === 'expired') {
            return terminal(`Gate receipt ${ordinaryGuidance.gateReceiptId} expired before it was approved. Do not run the action on it. If the work is still needed and has not run, start a new marrow_auto operation for a fresh gate.`);
        }
        if (status.state === 'used') {
            // A spent receipt is final: never resume from it, and never call it approved now.
            const approvedBefore = Boolean(status.owner_approval_receipt_id);
            return {
                operation_id: operationId,
                decision_id: decisionId,
                committed: false,
                phase: 'closed',
                resumable: false,
                retry_after_ms: null,
                exact_next_action: approvedBefore
                    ? `Gate receipt ${ordinaryGuidance.gateReceiptId} was approved and is already used: this operation is closed. Do not run this action again.`
                    : `The approval request for gate receipt ${ordinaryGuidance.gateReceiptId} was declined, and the decision is closed as a denial. Do not run this action.`,
                runtime_gate: runtimeGate,
                approval: ordinaryApprovalState,
                closure: approvedBefore ? 'already_closed' : 'already_closed_denial',
                phase_timings_ms: { ...timings, total: Date.now() - startedAt },
                http_attempt_trace: snapshotAutoHttpTrace(autoHttpTrace),
            };
        }
        if (status.state === 'approved') {
            ordinaryApproval = status;
        }
        else {
            return terminal(`Gate receipt ${ordinaryGuidance.gateReceiptId} is not waiting for an approval (${status.state}). Do not run the action on it; stop this operation and request fresh runtime guidance for this exact action.`);
        }
    }
    if (params.outcome === undefined || typeof params.success !== 'boolean') {
        return autoPartial({
            operationId,
            decisionId,
            phase: 'decision_created',
            runtimeGate,
            timings,
            startedAt,
            autoHttpTrace,
            retryAfterMs: null,
            ...(arbitrationGuidance && ownerApprovalReceiptForCommit ? {
                exactNextAction: `The account owner approved one proposal for arbitration receipt ${arbitrationGuidance.arbitrationReceiptId} (owner_approval_receipt_id ${ownerApprovalReceiptForCommit}). Run only the approved proposal now, then call marrow_auto with this same operation_id, the real outcome and success${arbitrationGuidance.proofRequired ? `, and proof with ${arbitrationGuidance.proofFields.join(', ') || 'the required fields'}` : ''}. Marrow closes it with that receipt.`,
            } : {}),
            ...(ordinaryApproval && ordinaryGuidance ? {
                exactNextAction: `${approvalStatement(ordinaryApproval, ordinaryGuidance.gateReceiptId)} Run only this exact action now, then call marrow_auto with this same operation_id, the real outcome and success${ordinaryGuidance.proofRequired ? `, and proof with ${ordinaryGuidance.proofFields.join(', ') || 'the required fields'}` : ''}. Marrow closes it on the same gate receipt.`,
                approval: ordinaryApprovalState,
            } : {}),
        });
    }
    if (ordinaryApproval && ordinaryGuidance) {
        // A proof-required hold closes trusted only with its proof; committing
        // without it would leave an unverified observation that blocks the later
        // trusted close, so auto waits for the proof instead.
        const commitProof = withoutOwnerApprovalClaim(params.proof);
        proofCanClose = !ordinaryGuidance.proofRequired || Boolean(commitProof && Object.keys(commitProof).length > 0);
        if (!proofCanClose) {
            return autoPartial({
                operationId, decisionId, phase: 'proof_required', runtimeGate, timings, startedAt, autoHttpTrace,
                retryAfterMs: null, approval: ordinaryApprovalState,
                exactNextAction: `Approved. Attach measured proof with ${ordinaryGuidance.proofFields.join(', ') || 'the required fields'} and call marrow_auto again with this same operation_id; Marrow closes it on gate receipt ${ordinaryGuidance.gateReceiptId}.`,
            });
        }
    }
    else if (genericReviewRequired) {
        return autoPartial({
            operationId,
            decisionId,
            phase: 'review_required',
            runtimeGate,
            timings,
            startedAt,
            autoHttpTrace,
            resumable: false,
            exactNextAction: 'Stop this operation and obtain the server-supported completion contract for this exact review. No supported ordinary approval path was declared. Preserve the operation and receipt references; do not infer approval or automatically retry.',
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
            autoHttpTrace,
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
            autoHttpTrace,
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
            autoHttpTrace,
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
                arbitration_receipt_id: arbitrationReceiptForCommit,
                owner_approval_receipt_id: ownerApprovalReceiptForCommit,
                action: params.action_for_gate || params.action,
                type: params.type || 'general',
                surfaces: params.surfaces,
                auto_gate: false,
                [AUTO_MANAGED_WRITE]: true,
                [AUTO_HTTP_TRACE]: autoHttpTrace,
            }, sessionId, agentId, commitTimeout.signal, autoIdempotencyKey(operationId, 'commit'));
        }
        catch (error) {
            const failure = (0, request_reliability_1.normalizeRequestError)(error);
            const recoverable = error instanceof request_reliability_1.MarrowRequestError && failure.retryable && failure.code !== 'invalid_response';
            if (!recoverable
                || !await waitForAutoContinuation({ retry_after_ms: failure.retryAfterMs }, startedAt, responseBudgetMs, autoHttpTrace)) {
                timings.commit = Date.now() - commitStarted;
                if (recoverable) {
                    return autoPartial({ operationId, decisionId, phase: 'commit_pending', runtimeGate, timings, startedAt, autoHttpTrace,
                        retryAfterMs: failure.retryAfterMs ?? undefined });
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
        const canResumeCommit = commitResult.resumable !== false && commitResult.retryable !== false;
        if (!isAutoPendingResponse(commitResult, 'commit_pending')) {
            timings.commit = Date.now() - commitStarted;
            return autoPartial({ operationId, decisionId, phase: 'commit_pending', runtimeGate, timings, startedAt, autoHttpTrace,
                resumable: canResumeCommit });
        }
        if (!await waitForAutoContinuation(commitResult, startedAt, responseBudgetMs, autoHttpTrace)) {
            timings.commit = Date.now() - commitStarted;
            return autoPartial({ operationId, decisionId, phase: 'commit_pending', runtimeGate, timings, startedAt, autoHttpTrace,
                retryAfterMs: autoContinuationDelay(commitResult) });
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
        ...(ordinaryApprovalState ? { approval: { ...ordinaryApprovalState, state: 'used' } } : {}),
        phase_timings_ms: {
            ...timings,
            total: Date.now() - startedAt,
        },
        http_attempt_trace: snapshotAutoHttpTrace(autoHttpTrace),
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
    const json = await fetchJsonResponse(url, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
    });
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
    const json = await fetchJsonResponse(`${baseUrl}/v1/analytics/decision-brief`, {
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
    const json = await fetchJsonResponse(`${baseUrl}/v1/agent/status?fast=1&compact=1`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
        signal,
    });
    return json.data;
}
// ─── Workflow Registry API ───────────────────────────────────────
async function marrowWorkflow(apiKey, baseUrl, params, sessionId, agentId) {
    const headers = buildHeaders(apiKey, sessionId, 'application/json', agentId);
    const fetchWorkflowJson = (url, init) => fetch(url, init, {
        consumeResponse: (response) => response.json(),
    });
    switch (params.action) {
        case 'register': {
            const json = await fetchWorkflowJson(`${baseUrl}/v1/workflows/register`, {
                method: 'POST',
                headers,
                body: JSON.stringify({
                    name: params.name,
                    description: params.description,
                    steps: params.steps,
                    tags: params.tags,
                }),
            });
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
            const json = await fetchWorkflowJson(`${baseUrl}/v1/workflows?${qs.toString()}`, { headers });
            if (json.error)
                return { success: false, error: json.error };
            return { success: true, data: json.data };
        }
        case 'get': {
            if (!params.workflowId)
                return { success: false, error: 'workflowId required' };
            const safeId = validatePathParam(params.workflowId, 'workflowId');
            const json = await fetchWorkflowJson(`${baseUrl}/v1/workflows/${safeId}`, { headers });
            if (json.error)
                return { success: false, error: json.error };
            return { success: true, data: json.data };
        }
        case 'update': {
            if (!params.workflowId)
                return { success: false, error: 'workflowId required' };
            const safeId = validatePathParam(params.workflowId, 'workflowId');
            const json = await fetchWorkflowJson(`${baseUrl}/v1/workflows/${safeId}`, {
                method: 'PUT',
                headers,
                body: JSON.stringify({
                    name: params.name,
                    description: params.description,
                    tags: params.tags,
                    status: params.status,
                }),
            });
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
            const json = await fetchWorkflowJson(`${baseUrl}/v1/workflows/${safeId}/start`, {
                method: 'POST',
                headers,
                body: JSON.stringify({
                    agent_id: params.agentId,
                    context: params.context,
                    inputs: params.inputs,
                }),
            });
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
            const json = await fetchWorkflowJson(`${baseUrl}/v1/workflows/${safeWorkflowId}/instances/${safeInstanceId}/step`, {
                method: 'PUT',
                headers,
                body: JSON.stringify({
                    step_completed: params.stepCompleted,
                    outcome: params.outcome,
                    next_agent_id: params.nextAgentId,
                    context_update: params.contextUpdate,
                }),
            });
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
            const json = await fetchWorkflowJson(`${baseUrl}/v1/workflows/${safeId}/instances?${qs.toString()}`, { headers });
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
    const json = await fetchJsonResponse(`${baseUrl}/v1/dashboard`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
    });
    return json.data;
}
/**
 * Get periodic summary of agent activity and Marrow impact.
 */
async function marrowDigest(apiKey, baseUrl, period = '7d', sessionId, agentId) {
    const days = parseInt(period) || 7;
    const json = await fetchJsonResponse(`${baseUrl}/v1/digest?period=${days}`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
    });
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
    const json = await fetchJsonResponse(`${baseUrl}/v1/analytics/agent-status?${qs.toString()}`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
        signal,
    });
    return json.data;
}
/**
 * Get live runtime hook diagnostics from /v1/agent/status.
 */
async function marrowRuntimeStatus(apiKey, baseUrl, fast = true, sessionId, agentId, signal) {
    const qs = fast ? '?fast=1' : '';
    const json = await fetchJsonResponse(`${baseUrl}/v1/agent/status${qs}`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
        signal,
    });
    return json.data;
}
/**
 * Get the compact canonical read context used by passive prompt hooks.
 */
async function marrowAgentContext(apiKey, baseUrl, sessionId, agentId, signal) {
    const query = new URLSearchParams({ compact: '1' });
    if (agentId)
        query.set('agent_id', agentId);
    const json = await fetchJsonResponse(`${baseUrl}/v1/agent/context?${query.toString()}`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
        signal,
    });
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
    const json = await fetchJsonResponse(`${baseUrl}/v1/analytics/value-report?${qs.toString()}`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
    });
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
    const json = await fetchJsonResponse(`${baseUrl}/v1/analytics/decision-brief`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(body),
    });
    return json.data;
}
async function marrowWorkflowGate(apiKey, baseUrl, input, sessionId, agentId) {
    const json = await fetchJsonResponse(`${baseUrl}/v1/workflow/gate`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(input),
    });
    return json.data;
}
async function marrowAgentRuntime(apiKey, baseUrl, input, sessionId, agentId, signal, idempotencyKeyOverride) {
    const body = {
        ...input,
        agent_id: input.agent_id || agentId,
        session_id: input.session_id || sessionId,
    };
    const idempotencyKey = idempotencyKeyOverride || `mcp-runtime-${(0, node_crypto_1.randomUUID)()}`;
    const json = await fetchJsonResponse(`${baseUrl}/v1/agent/runtime`, {
        method: 'POST',
        headers: {
            ...buildHeaders(apiKey, sessionId, 'application/json', agentId),
            'Idempotency-Key': idempotencyKey,
        },
        body: JSON.stringify(body),
        signal,
    });
    const runtime = requireRuntimeResult(json.data);
    if (!runtime.action && typeof input.action === 'string' && input.action.trim()) {
        runtime.action = input.action;
    }
    return runtime;
}
const GATE_RECEIPT_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,199}$/;
const OWNER_APPROVAL_STATES = new Set(['pending', 'approved', 'declined', 'expired', 'used', 'not_held', 'arbitration_review', 'unavailable']);
const SAFE_STATUS_TEXT = (value, limit) => typeof value === 'string' && value.trim() ? (0, redact_1.redactSensitiveText)(value.replace(/[\u0000-\u001f\u007f]/g, ' ').trim()).slice(0, limit) : null;
const SAFE_STATUS_ID = (value) => typeof value === 'string' && GATE_RECEIPT_IDENTIFIER.test(value) ? value : null;
const SAFE_STATUS_TIME = (value) => typeof value === 'string' && value.length <= 40 && Number.isFinite(Date.parse(value)) ? value : null;
function normalizeOwnerApprovalStatus(value, gateReceiptId) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return null;
    const view = value;
    if (view.gate_receipt_id !== gateReceiptId)
        return null;
    const state = typeof view.state === 'string' && OWNER_APPROVAL_STATES.has(view.state) ? view.state : 'unavailable';
    return {
        gate_receipt_id: gateReceiptId,
        decision_id: SAFE_STATUS_ID(view.decision_id),
        state,
        gate_decision: SAFE_STATUS_TEXT(view.gate_decision, 64),
        owner_approval_receipt_id: SAFE_STATUS_ID(view.owner_approval_receipt_id),
        decided_at: SAFE_STATUS_TIME(view.decided_at),
        approval_source: SAFE_STATUS_TEXT(view.approval_source, 32),
        approval_trust: SAFE_STATUS_TEXT(view.approval_trust, 32),
        approval_answered_by: SAFE_STATUS_TEXT(view.approval_answered_by, 32),
        expires_at: SAFE_STATUS_TIME(view.expires_at),
        terminal: view.terminal === true,
        retryable: view.retryable === true,
        poll_after_ms: typeof view.poll_after_ms === 'number' && Number.isFinite(view.poll_after_ms) ? (0, runtime_contract_1.boundedPollAfterMs)(view.poll_after_ms) : null,
        exact_next_action: SAFE_STATUS_TEXT(view.exact_next_action, 600) || '',
    };
}
/**
 * GET /v1/agent/gate-receipts/:id/owner-approval with the agent's own key:
 * whether a held gate receipt was approved (host prompt or dashboard),
 * declined, expired or used. An unknown receipt, or one of another agent or
 * session, answers not_found. Never authorizes anything by itself.
 */
async function marrowOwnerApprovalStatus(apiKey, baseUrl, gateReceiptId, sessionId, agentId, signal) {
    if (!GATE_RECEIPT_IDENTIFIER.test(gateReceiptId))
        throw new TypeError('gate_receipt_id is not a valid gate receipt identifier.');
    return fetch(`${baseUrl}${(0, runtime_contract_1.ownerApprovalStatusPath)(gateReceiptId)}`, {
        method: 'GET',
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
        signal,
    }, {
        consumeResponse: async (response) => {
            if (response.status === 404) {
                await response.body?.cancel().catch(() => undefined);
                return { kind: 'not_found', status: null };
            }
            const json = await safeJsonResponse(response);
            const status = normalizeOwnerApprovalStatus(json.data, gateReceiptId);
            if (!status)
                throw (0, request_reliability_1.invalidResponseError)();
            return { kind: 'found', status };
        },
    });
}
function normalizeHostApprovalReceipt(value, gateReceiptId) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return null;
    const receipt = value;
    if (receipt.gate_receipt_id !== gateReceiptId
        || (receipt.verdict !== 'approved' && receipt.verdict !== 'declined')
        || receipt.source !== 'host_prompt' || receipt.trust !== 'client_attested')
        return null;
    return {
        owner_approval_receipt_id: SAFE_STATUS_ID(receipt.owner_approval_receipt_id),
        owner_decline_receipt_id: SAFE_STATUS_ID(receipt.owner_decline_receipt_id),
        gate_receipt_id: gateReceiptId,
        decision_id: SAFE_STATUS_ID(receipt.decision_id),
        verdict: receipt.verdict,
        source: 'host_prompt',
        trust: 'client_attested',
        answered_by: receipt.answered_by === 'host_operator' || receipt.answered_by === 'owner_chat_preapproval' ? receipt.answered_by : 'host_allow_rule',
        host: SAFE_STATUS_TEXT(receipt.host, 32) || 'other',
        recorded_at: SAFE_STATUS_TIME(receipt.recorded_at) || '',
        expires_at: SAFE_STATUS_TIME(receipt.expires_at) || '',
    };
}
/**
 * POST /v1/agent/gate-receipts/:id/approval-link: asks Marrow to send the
 * account owner a one-tap approval link for one held receipt, to the owner's
 * own channel. The response never contains the link; the owner approves
 * without a login. Returns the channel only (no recipient details).
 */
async function marrowRequestApprovalLink(apiKey, baseUrl, gateReceiptId, decisionId, sessionId, agentId, signal) {
    if (!GATE_RECEIPT_IDENTIFIER.test(gateReceiptId))
        throw new TypeError('gate_receipt_id is not a valid gate receipt identifier.');
    return fetch(`${baseUrl}${(0, runtime_contract_1.approvalLinkPath)(gateReceiptId)}`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(decisionId && GATE_RECEIPT_IDENTIFIER.test(decisionId) ? { decision_id: decisionId } : {}),
        signal,
    }, {
        retryOwner: 'caller',
        consumeResponse: async (response) => {
            let json = null;
            try {
                if ((response.headers.get('content-type') || '').includes('json'))
                    json = await response.json();
                else
                    await response.body?.cancel().catch(() => undefined);
            }
            catch (error) {
                const failure = (0, request_reliability_1.normalizeRequestError)(error);
                if (failure.code === 'request_timeout')
                    throw failure;
                json = null;
            }
            if (response.ok) {
                const data = json?.data && typeof json.data === 'object' ? json.data : null;
                // Quiet by default: the service sent nothing (owner_ping_off), stored nothing, counted nothing.
                if (data?.sent === false && data.state === 'not_sent') {
                    const reason = typeof data.reason === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(data.reason) ? data.reason : 'not_sent';
                    return { ok: false, status: response.status, code: reason, retryable: false, notSent: true };
                }
                const link = data?.approval_link && typeof data.approval_link === 'object' ? data.approval_link : null;
                if (!link || link.gate_receipt_id !== gateReceiptId)
                    throw (0, request_reliability_1.invalidResponseError)();
                return { ok: true, link: {
                        channel: typeof link.channel === 'string' && /^[a-z][a-z0-9_-]{0,31}$/.test(link.channel) ? link.channel : 'owner channel',
                        expires_at: SAFE_STATUS_TIME(link.expires_at),
                    } };
            }
            const details = json?.details && typeof json.details === 'object' && !Array.isArray(json.details)
                ? json.details
                : {};
            const code = typeof details.code === 'string' && /^[A-Za-z0-9_.:-]{1,80}$/.test(details.code) ? details.code : null;
            return { ok: false, status: response.status, code, retryable: response.status === 429 || response.status >= 500 || details.retryable === true };
        },
    });
}
/**
 * GET /v1/agent/held-actions: the held actions still waiting for a person, for
 * the next interactive session's "N held actions are waiting for you". null
 * on a service without the read (404).
 */
async function marrowHeldActions(apiKey, baseUrl, query = {}, sessionId, agentId, signal) {
    const params = new URLSearchParams({ scope: query.scope || 'agent', limit: String(Math.min(Math.max(Math.trunc(query.limit || 20), 1), 50)) });
    return fetch(`${baseUrl}${exports.HELD_ACTIONS_PATH}?${params}`, {
        method: 'GET',
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
        signal,
    }, {
        retryOwner: 'caller',
        consumeResponse: async (response) => {
            if (response.status === 404) {
                await response.body?.cancel().catch(() => undefined);
                return null;
            }
            if (!response.ok)
                throw await (0, request_reliability_1.requestErrorFromResponse)(response);
            const json = await safeJsonResponse(response);
            const data = json.data && typeof json.data === 'object' ? json.data : null;
            if (!data || !Array.isArray(data.holds))
                throw (0, request_reliability_1.invalidResponseError)();
            const holds = data.holds.slice(0, 50).flatMap((item) => {
                if (!item || typeof item !== 'object')
                    return [];
                const hold = item;
                const id = SAFE_STATUS_ID(hold.gate_receipt_id);
                if (!id)
                    return [];
                return [{
                        gate_receipt_id: id,
                        agent_id: SAFE_STATUS_ID(hold.agent_id),
                        decision_type: typeof hold.decision_type === 'string' && /^[A-Za-z0-9][A-Za-z0-9 _.:-]{0,63}$/.test(hold.decision_type) ? hold.decision_type : null,
                        age_seconds: typeof hold.age_seconds === 'number' && Number.isFinite(hold.age_seconds) ? Math.max(0, Math.round(hold.age_seconds)) : 0,
                        expired: hold.expired === true,
                    }];
            });
            const count = typeof data.count === 'number' && Number.isInteger(data.count) && data.count >= holds.length ? Math.min(data.count, 500) : holds.length;
            return { count, countCapped: data.count_capped === true, more: data.more === true, holds };
        },
    });
}
/**
 * The account's owner-locked categories, for keeping those actions held on a
 * machine that has not seen them yet while Marrow cannot be reached. Agent
 * key; null on a service without the read (404). Proposed route:
 * GET /v1/agent/approval-settings -> { verified_approval_categories, unattended_owner_ping }.
 */
async function marrowAgentApprovalSettings(apiKey, baseUrl, sessionId, agentId, signal) {
    return fetch(`${baseUrl}${exports.AGENT_APPROVAL_SETTINGS_PATH}`, {
        method: 'GET',
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
        signal,
    }, {
        retryOwner: 'caller',
        consumeResponse: async (response) => {
            if (response.status === 404) {
                await response.body?.cancel().catch(() => undefined);
                return null;
            }
            if (!response.ok)
                throw await (0, request_reliability_1.requestErrorFromResponse)(response);
            const json = await safeJsonResponse(response);
            const data = json.data && typeof json.data === 'object' ? json.data : null;
            if (!data || !Array.isArray(data.verified_approval_categories))
                throw (0, request_reliability_1.invalidResponseError)();
            return {
                verified_approval_categories: data.verified_approval_categories
                    .filter((item) => typeof item === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(item)).slice(0, 16),
                unattended_owner_ping: typeof data.unattended_owner_ping === 'boolean' ? data.unattended_owner_ping : null,
            };
        },
    });
}
exports.HELD_ACTIONS_PATH = '/v1/agent/held-actions';
exports.AGENT_APPROVAL_SETTINGS_PATH = '/v1/agent/approval-settings';
const HOST_APPROVAL_REPORT_FIELDS = ['verdict', 'host', 'host_session_id', 'hook_event', 'pre_action_event_id', 'asked_at', 'answered_at', 'decision_id', 'normalized_action'];
/**
 * POST /v1/agent/gate-receipts/:id/host-approval: the host's Marrow hook
 * records the operator's answer in the host's own permission prompt (or a
 * typed reply). Recorded client-attested; the server labels it an operator
 * answer only with a dialog or typed-reply marker at a human pace. Hooks call
 * this only for an answer the host actually reported; the model never does.
 */
async function marrowHostApproval(apiKey, baseUrl, gateReceiptId, report, sessionId, agentId, signal) {
    if (!GATE_RECEIPT_IDENTIFIER.test(gateReceiptId))
        throw new TypeError('gate_receipt_id is not a valid gate receipt identifier.');
    const body = {};
    for (const field of HOST_APPROVAL_REPORT_FIELDS) {
        const value = report[field];
        if ((field === 'decision_id' || field === 'normalized_action') && (value === undefined || value === null))
            continue;
        body[field] = value ?? null;
    }
    return fetch(`${baseUrl}${(0, runtime_contract_1.hostApprovalPath)(gateReceiptId)}`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(body),
        signal,
    }, {
        // The caller resends the identical report; the server replays it.
        retryOwner: 'caller',
        consumeResponse: async (response) => {
            let json = null;
            try {
                if ((response.headers.get('content-type') || '').includes('json'))
                    json = await response.json();
                else
                    await response.body?.cancel().catch(() => undefined);
            }
            catch (error) {
                const failure = (0, request_reliability_1.normalizeRequestError)(error);
                if (failure.code === 'request_timeout')
                    throw failure;
                json = null;
            }
            if (response.ok) {
                const data = json?.data && typeof json.data === 'object' ? json.data : null;
                const receipt = normalizeHostApprovalReceipt(data?.host_approval, gateReceiptId);
                if (!receipt)
                    throw (0, request_reliability_1.invalidResponseError)();
                return { ok: true, receipt, replayed: data?.replayed === true };
            }
            const details = json?.details && typeof json.details === 'object' && !Array.isArray(json.details)
                ? json.details
                : {};
            const code = typeof details.code === 'string' && /^[A-Za-z0-9_.:-]{1,80}$/.test(details.code) ? details.code : null;
            const existing = details.existing_verdict === 'approved' || details.existing_verdict === 'declined' ? details.existing_verdict : null;
            const retryAfter = (0, request_reliability_1.responseRetryAfter)(response);
            const fields = Array.isArray(details.fields)
                ? details.fields.filter((item) => typeof item === 'string' && /^[a-z_]{1,64}$/.test(item)).slice(0, 10)
                : [];
            return {
                ok: false,
                status: response.status,
                code,
                existingVerdict: existing,
                retryable: response.status === 429 || response.status >= 500 || details.retryable === true,
                retryAfterMs: retryAfter.valid ? retryAfter.delayMs : null,
                ...(fields.length ? { fields } : {}),
            };
        },
    });
}
async function marrowEnforcement(apiKey, baseUrl, input, sessionId, agentId, signal) {
    const body = {
        ...input,
        agent_id: input.agent_id || agentId,
        session_id: input.session_id || sessionId,
    };
    const json = await fetchJsonResponse(`${baseUrl}/v1/agent/enforcement`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(body),
        signal,
    });
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
    const json = await fetchJsonResponse(`${baseUrl}/v1/agent/governance/control-plane`, {
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    });
    return json.data;
}
async function marrowHermesIntegration(apiKey, baseUrl, sessionId, agentId) {
    const json = await fetchJsonResponse(`${baseUrl}/v1/agent/integrations/hermes`, {
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    });
    return json.data;
}
async function marrowCompletionContracts(apiKey, baseUrl, sessionId, agentId) {
    const json = await fetchJsonResponse(`${baseUrl}/v1/agent/governance/completion-contracts`, {
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    });
    return json.data;
}
async function marrowEvaluateCompletionContract(apiKey, baseUrl, input, sessionId, agentId) {
    const json = await fetchJsonResponse(`${baseUrl}/v1/agent/governance/completion-contracts/evaluate`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(input),
    });
    return json.data;
}
async function marrowGovernanceTimeline(apiKey, baseUrl, options = {}, sessionId, agentId) {
    const qs = new URLSearchParams();
    if (options.agentId || agentId)
        qs.set('agent_id', options.agentId || agentId || '');
    if (options.limit)
        qs.set('limit', String(options.limit));
    const json = await fetchJsonResponse(`${baseUrl}/v1/agent/governance/timeline${qs.toString() ? `?${qs.toString()}` : ''}`, {
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    });
    return json.data;
}
async function marrowBuyerProof(apiKey, baseUrl, options = {}, sessionId, agentId) {
    const qs = new URLSearchParams();
    if (options.agentId || agentId)
        qs.set('agent_id', options.agentId || agentId || '');
    if (options.periodDays)
        qs.set('period_days', String(options.periodDays));
    const json = await fetchJsonResponse(`${baseUrl}/v1/agent/governance/buyer-proof${qs.toString() ? `?${qs.toString()}` : ''}`, {
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    });
    return requireObjectData(json.data);
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
        const json = await fetchJsonResponse(`${baseUrl}/v1/agent/governance/leases${qs.toString() ? `?${qs}` : ''}`, { headers });
        return json.data;
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
        const json = await fetchJsonResponse(`${baseUrl}/v1/agent/governance/leases/acquire`, {
            method: 'POST', headers, body: JSON.stringify(body),
        });
        return json.data;
    }
    if (action === 'release_lease') {
        const boundAgentId = boundCoordinationAgent(input, agentId);
        const leaseId = validatePathParam(String(input.lease_id || ''), 'lease_id');
        if (!leaseId.startsWith('lease_'))
            throw new TypeError('lease_id must be a Marrow lease identifier.');
        const json = await fetchJsonResponse(`${baseUrl}/v1/agent/governance/leases/${leaseId}/release`, {
            method: 'POST',
            headers,
            body: JSON.stringify({
                agent_id: boundAgentId,
                lease_token: input.lease_token,
            }),
        });
        return json.data;
    }
    if (action === 'list_proof_packets') {
        const qs = new URLSearchParams();
        if (Number.isFinite(Number(input.limit)))
            qs.set('limit', String(input.limit));
        const json = await fetchJsonResponse(`${baseUrl}/v1/agent/governance/proof-packets${qs.toString() ? `?${qs}` : ''}`, { headers });
        return json.data;
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
        const json = await fetchJsonResponse(`${baseUrl}/v1/agent/governance/proof-packets`, {
            method: 'POST', headers, body: JSON.stringify(body),
        });
        return json.data;
    }
    throw new TypeError('Unsupported coordination action.');
}
/**
 * Compare already-recorded outcomes and proof for the same task. Marrow does
 * not execute either model or workflow through this endpoint.
 */
async function marrowReplayCompare(apiKey, baseUrl, input, sessionId, agentId) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        throw new TypeError('Replay comparison input must be an object.');
    }
    if (Object.keys(input).some((field) => !REPLAY_INPUT_FIELDS.has(field))) {
        throw new TypeError('Replay comparison input contains unsupported fields.');
    }
    const hasComparisonId = Object.prototype.hasOwnProperty.call(input, 'comparison_id');
    const hasCreateInput = [
        'source_decision_id',
        'workspace_binding_id',
        'constraints',
        'baseline',
        'candidate',
    ].some((field) => Object.prototype.hasOwnProperty.call(input, field));
    if (hasComparisonId && hasCreateInput) {
        throw new TypeError('comparison_id cannot be combined with replay comparison creation inputs.');
    }
    if (hasComparisonId) {
        const comparisonId = typeof input.comparison_id === 'string' ? input.comparison_id.trim() : '';
        const safeId = validatePathParam(comparisonId, 'comparison_id');
        if (!safeId.startsWith('replay_'))
            throw new TypeError('comparison_id must be a Marrow replay identifier.');
        const json = await fetchJsonResponse(`${baseUrl}/v1/agent/governance/replay-comparisons/${safeId}`, {
            headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        });
        return json.data;
    }
    const sourceDecisionId = requiredReplayDecisionId(input.source_decision_id, 'source_decision_id');
    const baseline = normalizeReplayOutcomeReference(input.baseline, 'baseline');
    const candidate = normalizeReplayOutcomeReference(input.candidate, 'candidate');
    if (baseline.decision_id === candidate.decision_id) {
        throw new TypeError('baseline and candidate decision ids must be distinct.');
    }
    const body = (0, redact_1.redactSensitiveValue)({
        source_decision_id: sourceDecisionId,
        workspace_binding_id: optionalReplayWorkspaceBindingId(input.workspace_binding_id),
        constraints: normalizeReplayConstraints(input.constraints),
        baseline,
        candidate,
    });
    const json = await fetchJsonResponse(`${baseUrl}/v1/agent/governance/replay-comparisons`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(body),
    });
    return json.data;
}
async function marrowRecommendGovernanceMode(apiKey, baseUrl, input, sessionId, agentId) {
    const json = await fetchJsonResponse(`${baseUrl}/v1/agent/mode/recommend`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(input),
    });
    return json.data;
}
async function marrowListPolicyProfiles(apiKey, baseUrl, sessionId, agentId) {
    const json = await fetchJsonResponse(`${baseUrl}/v1/agent/policy-profiles`, {
        method: 'GET',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    });
    return json.data;
}
async function marrowCreatePolicyProfile(apiKey, baseUrl, input, sessionId, agentId) {
    const json = await fetchJsonResponse(`${baseUrl}/v1/agent/policy-profiles`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(input),
    });
    return json.data;
}
async function marrowAssignProjectPolicyProfile(apiKey, baseUrl, input, sessionId, agentId) {
    const json = await fetchJsonResponse(`${baseUrl}/v1/agent/project-policy-profile`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(input),
    });
    return json.data;
}
async function marrowResolvePolicy(apiKey, baseUrl, input, sessionId, agentId) {
    const json = await fetchJsonResponse(`${baseUrl}/v1/agent/policy/resolve`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(input),
    });
    return json.data;
}
async function marrowFirstValue(apiKey, baseUrl, input = {}, sessionId, agentId) {
    const body = {
        ...input,
        agent_id: input.agent_id || agentId,
        session_id: input.session_id || sessionId,
    };
    const json = await fetchJsonResponse(`${baseUrl}/v1/agent/first-value`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify(body),
    });
    return requireObjectData(json.data);
}
async function marrowAgentPerformance(apiKey, baseUrl, period = '7d', agentIdFilter, sessionId, agentId) {
    const qs = new URLSearchParams({ period: String(clampPeriodDays(period)) });
    if (agentIdFilter || agentId)
        qs.set('agent_id', agentIdFilter || agentId || '');
    const json = await fetchJsonResponse(`${baseUrl}/v1/analytics/agent-performance?${qs.toString()}`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
    });
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
    const json = await fetchJsonResponse(`${baseUrl}/v1/fleet/lessons${qs.toString() ? `?${qs.toString()}` : ''}`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
    });
    return json.data;
}
async function marrowRecordDeploymentMemory(apiKey, baseUrl, input, sessionId, agentId) {
    const json = await fetchJsonResponse(`${baseUrl}/v1/fleet/deployment-memory`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify({
            ...input,
            agent_id: String(input.agent_id || agentId || ''),
            tests: Array.isArray(input.tests) ? input.tests : undefined,
        }),
    });
    return json.data;
}
async function marrowCreateHandoff(apiKey, baseUrl, input, sessionId, agentId) {
    const json = await fetchJsonResponse(`${baseUrl}/v1/fleet/handoffs`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify({
            ...input,
            from_agent_id: String(input.from_agent_id || agentId || ''),
            to_agent_id: String(input.to_agent_id || ''),
            task: String(input.task || ''),
        }),
    });
    return json.data;
}
async function marrowUpdateHandoff(apiKey, baseUrl, handoffId, input, sessionId, agentId) {
    const safeId = validatePathParam(handoffId, 'handoffId');
    const json = await fetchJsonResponse(`${baseUrl}/v1/fleet/handoffs/${safeId}`, {
        method: 'PATCH',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify({
            status: typeof input.status === 'string' ? input.status : undefined,
            checkpoint: typeof input.checkpoint === 'string' ? input.checkpoint : undefined,
            result_summary: typeof input.result_summary === 'string' ? input.result_summary : undefined,
        }),
    });
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
    const json = await fetchJsonResponse(`${baseUrl}/v1/fleet/handoffs/status${qs.toString() ? `?${qs.toString()}` : ''}`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
        signal,
    });
    return json.data;
}
/**
 * Get a periodic improvement nudge when Marrow has something worth surfacing.
 */
async function marrowNudge(apiKey, baseUrl, sessionId, agentId) {
    const json = await fetchJsonResponse(`${baseUrl}/v1/agent/nudge`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
    });
    return json.data;
}
/**
 * Explicitly end the current session.
 */
async function marrowSessionEnd(apiKey, baseUrl, autoCommitOpen = false, sessionId, agentId, signal) {
    const json = await fetchJsonResponse(`${baseUrl}/v1/agent/session/end`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify({ auto_commit_open: autoCommitOpen }),
        signal,
    });
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
    const json = await fetchJsonResponse(`${baseUrl}/v1/agent/governance/trace/${safeId}`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
    });
    return json.data || json;
}
/**
 * Convert a detected decision pattern into an enforced workflow.
 */
async function marrowAcceptDetected(apiKey, baseUrl, detectedId, sessionId, agentId) {
    const safeId = validatePathParam(detectedId, 'detectedId');
    const json = await fetchJsonResponse(`${baseUrl}/v1/workflows/accept-detected`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
        body: JSON.stringify({ detected_id: safeId }),
    });
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
    const json = await fetchJsonResponse(`${baseUrl}/v1/templates${query ? '?' + query : ''}`, {
        headers: buildHeaders(apiKey, sessionId, undefined, agentId),
    });
    return json.data;
}
/**
 * Install a workflow template as an active workflow.
 */
async function marrowInstallTemplate(apiKey, baseUrl, slug, sessionId, agentId) {
    const safeSlug = validatePathParam(slug, 'slug');
    const json = await fetchJsonResponse(`${baseUrl}/v1/templates/${safeSlug}/install`, {
        method: 'POST',
        headers: buildHeaders(apiKey, sessionId, 'application/json', agentId),
    });
    return json.data;
}
//# sourceMappingURL=index.js.map