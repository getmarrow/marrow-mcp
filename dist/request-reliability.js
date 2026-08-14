"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MarrowRequestError = void 0;
exports.requestErrorFromResponse = requestErrorFromResponse;
exports.normalizeRequestError = normalizeRequestError;
exports.reliableFetch = reliableFetch;
exports.localClientUpdate = localClientUpdate;
exports.structuredRequestFailure = structuredRequestFailure;
const hook_contract_1 = require("./hook-contract");
const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);
const RUNTIME_PATH = /\/v1\/agent\/runtime(?:[/?]|$)/;
const STATUS_CONTEXT_PATH = /\/v1\/agent\/(?:status|context)(?:[/?]|$)/;
const DECISION_READ_PATH = /\/(?:v1\/agent\/first-value|v1\/analytics\/decision-brief)(?:[/?]|$)/;
class MarrowRequestError extends Error {
    code;
    status;
    retryable;
    retryAfterMs;
    exactFix;
    constructor(input) {
        super(input.message);
        this.name = 'MarrowRequestError';
        this.code = input.code;
        this.status = input.status ?? null;
        this.retryable = input.retryable ?? false;
        this.retryAfterMs = input.retryAfterMs ?? null;
        this.exactFix = input.exactFix;
    }
}
exports.MarrowRequestError = MarrowRequestError;
function boundedTimeout(url) {
    const configured = Number(process.env.MARROW_REQUEST_TIMEOUT_MS);
    if (Number.isFinite(configured))
        return Math.min(10_000, Math.max(150, Math.floor(configured)));
    // These are hard transport ceilings. The MCP and passive-hook surfaces use
    // shorter cache-aware deadlines when last-known guidance is available.
    if (RUNTIME_PATH.test(url))
        return 2_000;
    if (STATUS_CONTEXT_PATH.test(url))
        return 1_200;
    if (DECISION_READ_PATH.test(url))
        return 1_500;
    return 2_000;
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
    const apiMessage = typeof detail?.error === 'string'
        ? detail.error
        : typeof detail?.message === 'string'
            ? detail.message
            : `Marrow API returned HTTP ${status}`;
    const apiFix = typeof detail?.exact_fix === 'string'
        ? detail.exact_fix
        : typeof detail?.exact_next_action === 'string'
            ? detail.exact_next_action
            : exactFixForStatus(status);
    const code = status === 401
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
        message: `HTTP ${status}: ${apiMessage}`.slice(0, 240),
        status,
        retryable: RETRYABLE_STATUS.has(status),
        retryAfterMs: retryAfterMs(response),
        exactFix: apiFix.slice(0, 360),
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
            exactFix: 'Use the returned last-known guidance for low-risk context only, then retry. High-risk work still requires a fresh gate.',
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
    if (init.signal) {
        try {
            return await globalThis.fetch(target, init);
        }
        catch (error) {
            throw normalizeRequestError(error);
        }
    }
    const timeoutMs = boundedTimeout(target);
    const deadline = Date.now() + timeoutMs;
    let lastError = null;
    const attempts = safeToRetry(target, init) ? 2 : 1;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
        const remaining = deadline - Date.now();
        if (remaining < 50)
            break;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), remaining);
        timer.unref?.();
        try {
            const response = await globalThis.fetch(target, { ...init, signal: controller.signal });
            if (!RETRYABLE_STATUS.has(response.status) || attempt + 1 >= attempts)
                return response;
            lastError = requestErrorFromResponse(response);
        }
        catch (error) {
            lastError = normalizeRequestError(error);
            if (!lastError.retryable || attempt + 1 >= attempts)
                throw lastError;
        }
        finally {
            clearTimeout(timer);
        }
    }
    throw lastError || normalizeRequestError(new Error('Marrow request deadline exceeded'));
}
function localClientUpdate() {
    return {
        package: '@getmarrow/mcp',
        installed_version: hook_contract_1.MCP_ADAPTER_VERSION,
        version_status: 'unverified',
        update_command: 'npx -y @getmarrow/mcp@latest setup',
        verification_command: 'npx -y @getmarrow/install@latest doctor',
        operator_approval_required: true,
    };
}
function structuredRequestFailure(error) {
    const normalized = normalizeRequestError(error);
    return {
        ok: false,
        available: false,
        error: {
            code: normalized.code,
            status: normalized.status,
            retryable: normalized.retryable,
            retry_after_ms: normalized.retryAfterMs,
            message: normalized.message,
            exact_fix: normalized.exactFix,
        },
        client_update: localClientUpdate(),
    };
}
//# sourceMappingURL=request-reliability.js.map