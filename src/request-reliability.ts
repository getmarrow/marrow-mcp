import { MCP_ADAPTER_VERSION } from './hook-contract';
import { redactSensitiveText } from './redact';

const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);
const RUNTIME_PATH = /\/v1\/agent\/runtime(?:[/?]|$)/;
const STATUS_CONTEXT_PATH = /\/v1\/agent\/(?:status|context)(?:[/?]|$)/;
const DECISION_READ_PATH = /\/(?:v1\/agent\/first-value|v1\/analytics\/decision-brief)(?:[/?]|$)/;

export type MarrowFailureCode =
  | 'authentication_required'
  | 'permission_denied'
  | 'rate_limited'
  | 'request_timeout'
  | 'dns_unavailable'
  | 'connection_reset'
  | 'tls_failure'
  | 'service_unavailable'
  | 'invalid_response'
  | 'request_failed';

export class MarrowRequestError extends Error {
  readonly code: MarrowFailureCode;
  readonly status: number | null;
  readonly retryable: boolean;
  readonly retryAfterMs: number | null;
  readonly exactFix: string;

  constructor(input: {
    code: MarrowFailureCode;
    message: string;
    status?: number | null;
    retryable?: boolean;
    retryAfterMs?: number | null;
    exactFix: string;
  }) {
    super(redactSensitiveText(input.message).slice(0, 240));
    this.name = 'MarrowRequestError';
    this.code = input.code;
    this.status = input.status ?? null;
    this.retryable = input.retryable ?? false;
    this.retryAfterMs = input.retryAfterMs ?? null;
    this.exactFix = redactSensitiveText(input.exactFix).slice(0, 360);
  }
}

function boundedTimeout(url: string): number {
  const configured = Number(process.env.MARROW_REQUEST_TIMEOUT_MS);
  if (Number.isFinite(configured)) return Math.min(10_000, Math.max(150, Math.floor(configured)));
  // These are hard transport ceilings. The MCP and passive-hook surfaces use
  // shorter cache-aware deadlines when last-known guidance is available.
  if (RUNTIME_PATH.test(url)) return 2_000;
  if (STATUS_CONTEXT_PATH.test(url)) return 1_200;
  if (DECISION_READ_PATH.test(url)) return 1_500;
  return 2_000;
}

function retryAfterMs(response: Response): number | null {
  const raw = response.headers.get('retry-after');
  if (!raw) return null;
  const seconds = Number(raw);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.min(60_000, Math.round(seconds * 1_000));
  const date = Date.parse(raw);
  return Number.isFinite(date) ? Math.min(60_000, Math.max(0, date - Date.now())) : null;
}

function exactFixForStatus(status: number): string {
  if (status === 401) return 'Restore MARROW_API_KEY from the account dashboard or canonical credential store, then restart the MCP process.';
  if (status === 403) return 'Use a Marrow key whose account, agent binding, and scopes match this request.';
  if (status === 429) return 'Wait for retry_after_ms, then retry once. Batch low-risk events instead of issuing one request per file edit.';
  return 'Retry once after the reported delay. If the error persists, run npx -y @getmarrow/install@latest doctor.';
}

export function requestErrorFromResponse(response: Response, detail?: Record<string, unknown>): MarrowRequestError {
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
  const code: MarrowFailureCode = status === 401
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
    message: `HTTP ${status}: ${apiMessage}`,
    status,
    retryable: RETRYABLE_STATUS.has(status),
    retryAfterMs: retryAfterMs(response),
    exactFix: apiFix,
  });
}

export function invalidResponseError(): MarrowRequestError {
  return new MarrowRequestError({
    code: 'invalid_response',
    message: 'Marrow API returned an invalid response',
    retryable: true,
    exactFix: 'Retry once, then run npx -y @getmarrow/install@latest doctor if the response remains invalid.',
  });
}

export function normalizeRequestError(error: unknown): MarrowRequestError {
  if (error instanceof MarrowRequestError) return error;
  const source = error instanceof Error ? error : new Error(String(error));
  const cause = source.cause && typeof source.cause === 'object' ? source.cause as Record<string, unknown> : {};
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

function safeToRetry(url: string, init: RequestInit): boolean {
  const method = String(init.method || 'GET').toUpperCase();
  if (method === 'GET' || method === 'HEAD') return true;
  const headers = new Headers(init.headers);
  return headers.has('Idempotency-Key') || /\/v1\/analytics\/decision-brief(?:[/?]|$)/.test(url);
}

export async function reliableFetch(url: string | URL, init: RequestInit = {}): Promise<Response> {
  const target = String(url);
  const timeoutMs = boundedTimeout(target);
  const deadline = Date.now() + timeoutMs;
  const externalSignal = init.signal;
  let lastError: MarrowRequestError | null = null;
  const attempts = safeToRetry(target, init) ? 2 : 1;

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (externalSignal?.aborted) throw normalizeRequestError(externalSignal.reason || new DOMException('Aborted', 'AbortError'));
    const remaining = deadline - Date.now();
    if (remaining < 50) break;
    const controller = new AbortController();
    const abortFromCaller = () => controller.abort(externalSignal?.reason);
    externalSignal?.addEventListener('abort', abortFromCaller, { once: true });
    const timer = setTimeout(() => controller.abort(), remaining);
    timer.unref?.();
    let retryResponse: Response | null = null;
    let delayMs = 0;
    try {
      const response = await globalThis.fetch(target, { ...init, signal: controller.signal });
      if (!RETRYABLE_STATUS.has(response.status) || attempt + 1 >= attempts) return response;
      lastError = requestErrorFromResponse(response);
      retryResponse = response;
      delayMs = lastError.retryAfterMs ?? 50;
    } catch (error) {
      lastError = normalizeRequestError(error);
      if (!lastError.retryable || attempt + 1 >= attempts) throw lastError;
      delayMs = 50;
    } finally {
      clearTimeout(timer);
      externalSignal?.removeEventListener('abort', abortFromCaller);
    }

    const remainingAfterAttempt = deadline - Date.now();
    if (retryResponse && delayMs >= remainingAfterAttempt - 50) {
      return retryResponse;
    }
    if (delayMs > 0) {
      await new Promise<void>((resolve, reject) => {
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
        if (!externalSignal) return;
        if (externalSignal.aborted) abort();
        else externalSignal.addEventListener('abort', abort, { once: true });
      });
    }
  }
  throw lastError || normalizeRequestError(new Error('Marrow request deadline exceeded'));
}

export function localClientUpdate(): Record<string, unknown> {
  return {
    package: '@getmarrow/mcp',
    installed_version: MCP_ADAPTER_VERSION,
    version_status: 'unverified',
    update_command: 'npx -y @getmarrow/mcp@latest setup',
    verification_command: 'npx -y @getmarrow/install@latest doctor',
    operator_approval_required: true,
  };
}

export function structuredRequestFailure(error: unknown): Record<string, unknown> {
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
