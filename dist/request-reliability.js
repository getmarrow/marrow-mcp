"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MarrowRequestError = void 0;
exports.requestErrorFromResponse = requestErrorFromResponse;
exports.invalidResponseError = invalidResponseError;
exports.normalizeRequestError = normalizeRequestError;
exports.reliableFetch = reliableFetch;
exports.localClientUpdate = localClientUpdate;
exports.structuredRequestFailure = structuredRequestFailure;
const hook_contract_1 = require("./hook-contract");
const redact_1 = require("./redact");
const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);
const RUNTIME_PATH = /\/v1\/agent\/runtime(?:[/?]|$)/;
const STATUS_CONTEXT_PATH = /\/v1\/agent\/(?:status|context)(?:[/?]|$)/;
const DECISION_READ_PATH = /\/(?:v1\/agent\/first-value|v1\/analytics\/decision-brief)(?:[/?]|$)/;
class MarrowRequestError extends Error {
    code;
    backendCode;
    status;
    retryable;
    retryAfterMs;
    exactFix;
    fixCommand;
    currentPlan;
    requiredFeature;
    constructor(input) {
        super((0, redact_1.redactSensitiveText)(input.message).slice(0, 240));
        this.name = 'MarrowRequestError';
        this.code = input.code;
        this.backendCode = input.backendCode
            ? (0, redact_1.redactSensitiveText)(input.backendCode).slice(0, 128)
            : null;
        this.status = input.status ?? null;
        this.retryable = input.retryable ?? false;
        this.retryAfterMs = input.retryAfterMs ?? null;
        this.exactFix = (0, redact_1.redactSensitiveText)(input.exactFix).slice(0, 360);
        this.fixCommand = input.fixCommand
            ? (0, redact_1.redactSensitiveText)(input.fixCommand).slice(0, 360)
            : null;
        this.currentPlan = input.currentPlan && /^[a-z][a-z0-9_-]{0,31}$/i.test(input.currentPlan)
            ? input.currentPlan.toLowerCase()
            : null;
        this.requiredFeature = input.requiredFeature && /^[a-z][a-z0-9_-]{0,63}$/i.test(input.requiredFeature)
            ? input.requiredFeature.toLowerCase()
            : null;
    }
}
exports.MarrowRequestError = MarrowRequestError;
function boundedTimeout(url) {
    const configured = Number(process.env.MARROW_REQUEST_TIMEOUT_MS);
    if (Number.isFinite(configured))
        return Math.min(10_000, Math.max(150, Math.floor(configured)));
    // These are hard transport ceilings. Last-known guidance is an outage fallback;
    // it must never shorten a live control read and cause a healthy response to be
    // aborted before it can replace stale guidance.
    if (RUNTIME_PATH.test(url))
        return 4_500;
    if (STATUS_CONTEXT_PATH.test(url))
        return 4_000;
    if (DECISION_READ_PATH.test(url))
        return 4_000;
    return 4_000;
}
function retryAfterMs(response) {
    const raw = response.headers.get('retry-after');
    if (!raw)
        return null;
    const seconds = Number(raw);
    if (Number.isFinite(seconds) && seconds >= 0)
        return Math.min(60_000, Math.round(seconds * 1_000));
    const date = Date.parse(raw);
    return Number.isFinite(date) ? Math.min(60_000, Math.max(0, date - Date.now())) : null;
}
function exactFixForStatus(status) {
    if (status === 401)
        return 'Restore MARROW_API_KEY from the account dashboard or canonical credential store, then restart the MCP process.';
    if (status === 403)
        return 'Use a Marrow key whose account, agent binding, and scopes match this request.';
    if (status === 429)
        return 'Wait for retry_after_ms, then retry once. Batch low-risk events instead of issuing one request per file edit.';
    return 'Retry once after the reported delay. If the error persists, run npx -y @getmarrow/install@latest doctor.';
}
function requestErrorFromResponse(response, detail) {
    const status = response.status;
    const cloudflareEdgeDenial = status === 403 && Boolean(response.headers.get('cf-ray')) && !detail;
    const errorObject = detail?.error && typeof detail.error === 'object' && !Array.isArray(detail.error)
        ? detail.error
        : undefined;
    const nestedDetails = detail?.details && typeof detail.details === 'object' && !Array.isArray(detail.details)
        ? detail.details
        : errorObject?.details && typeof errorObject.details === 'object' && !Array.isArray(errorObject.details)
            ? errorObject.details
            : undefined;
    const rejectionFields = [nestedDetails, errorObject, detail].filter(Boolean);
    const firstString = (...fields) => {
        for (const source of rejectionFields) {
            for (const field of fields) {
                if (typeof source[field] === 'string' && String(source[field]).trim())
                    return String(source[field]);
            }
        }
        return undefined;
    };
    const apiMessage = typeof detail?.error === 'string'
        ? detail.error
        : firstString('message', 'error') || `Marrow API returned HTTP ${status}`;
    const apiFix = firstString('exact_fix', 'exact_next_action', 'fix_command') || exactFixForStatus(status);
    const fixCommand = firstString('fix_command') || null;
    const backendCode = firstString('code') || null;
    const currentPlan = firstString('current_plan') || null;
    const requiredFeature = firstString('required_feature') || null;
    const code = cloudflareEdgeDenial
        ? 'edge_access_denied'
        : status === 401
            ? 'authentication_required'
            : status === 403
                ? 'permission_denied'
                : status === 429
                    ? 'rate_limited'
                    : status >= 500
                        ? 'service_unavailable'
                        : 'request_failed';
    return new MarrowRequestError({
        code,
        backendCode,
        message: `HTTP ${status}: ${apiMessage}`,
        status,
        retryable: cloudflareEdgeDenial ? false : RETRYABLE_STATUS.has(status),
        retryAfterMs: retryAfterMs(response),
        exactFix: cloudflareEdgeDenial
            ? 'Marrow was reached, but the Cloudflare edge denied this network client before API authentication. Record the Cloudflare Ray ID, retry from a trusted network, and send the Ray ID to Marrow support; do not rotate the API key.'
            : apiFix,
        fixCommand,
        currentPlan,
        requiredFeature,
    });
}
function invalidResponseError() {
    return new MarrowRequestError({
        code: 'invalid_response',
        message: 'Marrow API returned an invalid response',
        retryable: true,
        exactFix: 'Retry once, then run npx -y @getmarrow/install@latest doctor if the response remains invalid.',
    });
}
function normalizeRequestError(error) {
    if (error instanceof MarrowRequestError)
        return error;
    const source = error instanceof Error ? error : new Error(String(error));
    const cause = source.cause && typeof source.cause === 'object' ? source.cause : {};
    const causeCode = String(cause.code || '').toUpperCase();
    const message = source.message.toLowerCase();
    if (source.name === 'AbortError' || /abort|timed out|timeout/.test(message)) {
        return new MarrowRequestError({
            code: 'request_timeout', message: 'Marrow control read timed out', retryable: true,
            retryAfterMs: 1_000,
            exactFix: 'Use the returned outage-safe or last-known brief for low-risk context only, wait 1000 ms, then retry once. High-risk work still requires a fresh gate.',
        });
    }
    if (['ENOTFOUND', 'EAI_AGAIN'].includes(causeCode)) {
        return new MarrowRequestError({
            code: 'dns_unavailable', message: 'Marrow API name resolution is temporarily unavailable', retryable: true,
            exactFix: 'Check DNS and outbound HTTPS access to api.getmarrow.ai, then retry once.',
        });
    }
    if (['ECONNRESET', 'ECONNREFUSED', 'UND_ERR_SOCKET'].includes(causeCode)) {
        return new MarrowRequestError({
            code: 'connection_reset', message: 'The Marrow API connection was interrupted', retryable: true,
            exactFix: 'Retry once. If this repeats, run npx -y @getmarrow/install@latest doctor and inspect the MCP ping result.',
        });
    }
    if (/certificate|tls|ssl/.test(message) || causeCode.startsWith('ERR_TLS')) {
        return new MarrowRequestError({
            code: 'tls_failure', message: 'The secure connection to Marrow could not be verified', retryable: false,
            exactFix: 'Check the host clock, TLS interception, and trusted certificate store. Do not disable TLS verification.',
        });
    }
    return new MarrowRequestError({
        code: 'request_failed', message: 'The Marrow API request could not be completed', retryable: true,
        exactFix: 'Run npx -y @getmarrow/install@latest doctor, verify MARROW_API_KEY, and retry once.',
    });
}
function safeToRetry(url, init) {
    const method = String(init.method || 'GET').toUpperCase();
    if (method === 'GET' || method === 'HEAD')
        return true;
    const headers = new Headers(init.headers);
    return headers.has('Idempotency-Key') || /\/v1\/analytics\/decision-brief(?:[/?]|$)/.test(url);
}
async function reliableFetch(url, init = {}) {
    const target = String(url);
    const timeoutMs = boundedTimeout(target);
    const deadline = Date.now() + timeoutMs;
    const externalSignal = init.signal;
    let lastError = null;
    const attempts = safeToRetry(target, init) ? 2 : 1;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
        if (externalSignal?.aborted)
            throw normalizeRequestError(externalSignal.reason || new DOMException('Aborted', 'AbortError'));
        const remaining = deadline - Date.now();
        if (remaining < 50)
            break;
        const controller = new AbortController();
        const abortFromCaller = () => controller.abort(externalSignal?.reason);
        externalSignal?.addEventListener('abort', abortFromCaller, { once: true });
        const timer = setTimeout(() => controller.abort(), remaining);
        timer.unref?.();
        let retryResponse = null;
        let delayMs = 0;
        try {
            const response = await globalThis.fetch(target, { ...init, signal: controller.signal });
            if (!RETRYABLE_STATUS.has(response.status) || attempt + 1 >= attempts)
                return response;
            lastError = requestErrorFromResponse(response);
            retryResponse = response;
            delayMs = lastError.retryAfterMs ?? 50;
        }
        catch (error) {
            lastError = normalizeRequestError(error);
            if (!lastError.retryable || attempt + 1 >= attempts)
                throw lastError;
            delayMs = 50;
        }
        finally {
            clearTimeout(timer);
            externalSignal?.removeEventListener('abort', abortFromCaller);
        }
        const remainingAfterAttempt = deadline - Date.now();
        if (retryResponse && delayMs >= remainingAfterAttempt - 50) {
            return retryResponse;
        }
        if (delayMs > 0) {
            await new Promise((resolve, reject) => {
                const finish = () => {
                    externalSignal?.removeEventListener('abort', abort);
                    resolve();
                };
                const retryTimer = setTimeout(finish, Math.min(delayMs, Math.max(0, remainingAfterAttempt - 50)));
                function abort() {
                    clearTimeout(retryTimer);
                    externalSignal?.removeEventListener('abort', abort);
                    reject(normalizeRequestError(externalSignal?.reason || new DOMException('Aborted', 'AbortError')));
                }
                if (!externalSignal)
                    return;
                if (externalSignal.aborted)
                    abort();
                else
                    externalSignal.addEventListener('abort', abort, { once: true });
            });
        }
    }
    throw lastError || normalizeRequestError(new Error('Marrow request deadline exceeded'));
}
function localClientUpdate() {
    return {
        package: '@getmarrow/mcp',
        installed_version: hook_contract_1.MCP_ADAPTER_VERSION,
        installed_version_verified: true,
        latest_version: null,
        version_status: 'unknown',
        metadata_status: 'local_only_control_path_unavailable',
        update_command: 'npx -y --package=@getmarrow/mcp@latest marrow-mcp setup',
        launch_command: 'npx -y --package=@getmarrow/mcp@latest marrow-mcp',
        verification_command: 'npx -y @getmarrow/install@latest doctor --self-test',
        operator_approval_required: true,
    };
}
function structuredRequestFailure(error) {
    const normalized = normalizeRequestError(error);
    return {
        ok: false,
        available: false,
        error: {
            code: normalized.backendCode || normalized.code,
            category: normalized.code,
            status: normalized.status,
            retryable: normalized.retryable,
            retry_after_ms: normalized.retryAfterMs,
            message: normalized.message,
            exact_fix: normalized.exactFix,
            ...(normalized.fixCommand ? { fix_command: normalized.fixCommand } : {}),
        },
        client_update: localClientUpdate(),
    };
}
//# sourceMappingURL=request-reliability.js.map