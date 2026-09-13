import { MCP_ADAPTER_VERSION } from './hook-contract';
import { redactSensitiveText } from './redact';

const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504]);
const RUNTIME_PATH = /\/v1\/agent\/runtime(?:[/?]|$)/;
const COMMIT_PATH = /\/v1\/agent\/commit(?:[/?]|$)/;
const STATUS_CONTEXT_PATH = /\/v1\/agent\/(?:status|context)(?:[/?]|$)/;
const DECISION_READ_PATH = /\/(?:v1\/agent\/first-value|v1\/analytics\/decision-brief)(?:[/?]|$)/;

export type MarrowFailureCode =
  | 'authentication_required'
  | 'permission_denied'
  | 'proof_required'
  | 'rate_limited'
  | 'request_timeout'
  | 'dns_unavailable'
  | 'connection_reset'
  | 'tls_failure'
  | 'edge_access_denied'
  | 'service_unavailable'
  | 'invalid_response'
  | 'request_failed';

export function privacySafeIdempotencyKey(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)
    && redactSensitiveText(value) === value
    && (/^mcp-(?:think|commit):[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value)
      || !/(?:^|[._:-])(?:\d[ .()-]*){7,}(?:$|[._:-])/.test(value))
    && !/[a-z0-9-]+\.[a-z]{2,}(?:$|[/:])/i.test(value);
}

export interface PendingWriteReceipt {
  contract: 'mcp_write_pending.v1';
  operation: 'think' | 'commit';
  committed: false;
  safe_to_continue: false;
  idempotency_key: string;
  request_hash: string;
}

export class MarrowRequestError extends Error {
  readonly code: MarrowFailureCode;
  readonly backendCode: string | null;
  readonly status: number | null;
  readonly retryable: boolean;
  readonly retryAfterMs: number | null;
  readonly exactFix: string;
  readonly fixCommand: string | null;
  readonly currentPlan: string | null;
  readonly requiredFeature: string | null;
  readonly missingFields: string[];
  readonly pendingReceipt?: PendingWriteReceipt;

  constructor(input: {
    code: MarrowFailureCode;
    backendCode?: string | null;
    message: string;
    status?: number | null;
    retryable?: boolean;
    retryAfterMs?: number | null;
    exactFix: string;
    fixCommand?: string | null;
    currentPlan?: string | null;
    requiredFeature?: string | null;
    missingFields?: string[];
    pendingReceipt?: PendingWriteReceipt;
  }) {
    super(redactSensitiveText(input.message).slice(0, 240));
    this.name = 'MarrowRequestError';
    const receipt = input.pendingReceipt;
    if (receipt?.contract === 'mcp_write_pending.v1'
      && (receipt.operation === 'think' || receipt.operation === 'commit')
      && receipt.committed === false && receipt.safe_to_continue === false
      && privacySafeIdempotencyKey(receipt.idempotency_key) && /^[a-f0-9]{64}$/.test(receipt.request_hash)) {
      this.pendingReceipt = {
        contract: receipt.contract, operation: receipt.operation, committed: false, safe_to_continue: false,
        idempotency_key: receipt.idempotency_key, request_hash: receipt.request_hash,
      };
    }
    this.code = input.code;
    this.backendCode = input.backendCode
      ? redactSensitiveText(input.backendCode).slice(0, 128)
      : null;
    this.status = input.status ?? null;
    this.retryable = input.retryable ?? false;
    this.retryAfterMs = input.retryAfterMs ?? null;
    this.exactFix = redactSensitiveText(input.exactFix).slice(0, 360);
    this.fixCommand = input.fixCommand
      ? redactSensitiveText(input.fixCommand).slice(0, 360)
      : null;
    this.currentPlan = input.currentPlan && /^[a-z][a-z0-9_-]{0,31}$/i.test(input.currentPlan)
      ? input.currentPlan.toLowerCase()
      : null;
    this.requiredFeature = input.requiredFeature && /^[a-z][a-z0-9_-]{0,63}$/i.test(input.requiredFeature)
      ? input.requiredFeature.toLowerCase()
      : null;
    this.missingFields = Array.isArray(input.missingFields)
      ? input.missingFields
        .filter((field): field is string => typeof field === 'string' && field.trim().length > 0)
        .slice(0, 32)
        .map((field) => redactSensitiveText(field).slice(0, 128))
      : [];
  }
}

function boundedTimeout(url: string): number {
  const configured = Number(process.env.MARROW_REQUEST_TIMEOUT_MS);
  if (Number.isFinite(configured)) return Math.min(10_000, Math.max(150, Math.floor(configured)));
  // These are hard transport ceilings. Last-known guidance is an outage fallback;
  // it must never shorten a live control read and cause a healthy response to be
  // aborted before it can replace stale guidance.
  if (COMMIT_PATH.test(url)) return 8_000;
  if (RUNTIME_PATH.test(url)) return 4_500;
  if (STATUS_CONTEXT_PATH.test(url)) return 4_000;
  if (DECISION_READ_PATH.test(url)) return 4_000;
  return 4_000;
}

export function responseRetryAfter(response: Response): { delayMs: number | null; valid: boolean } {
  const raw = response.headers.get('retry-after');
  if (raw === null) return { delayMs: null, valid: true };
  const text = raw.trim();
  const seconds = Number(text);
  const numeric = text !== '' && !Number.isNaN(seconds);
  const parsedDate = numeric ? NaN : Date.parse(text);
  const delayMs = numeric ? Math.ceil(seconds * 1_000) : Math.max(0, parsedDate - Date.now());
  return Number.isSafeInteger(delayMs) && delayMs >= 0
    ? { delayMs, valid: true }
    : { delayMs: null, valid: false };
}

function exactFixForStatus(status: number): string {
  if (status === 401) return 'Restore MARROW_API_KEY from the account dashboard or canonical credential store, then restart the MCP process.';
  if (status === 403) return 'Use a Marrow key whose account, agent binding, and scopes match this request.';
  if (status === 429) return 'Wait for retry_after_ms, then retry once. Batch low-risk events instead of issuing one request per file edit.';
  return 'Retry once after the reported delay. If the error persists, run npx -y @getmarrow/install@latest doctor.';
}

export function requestErrorFromResponse(response: Response, detail?: Record<string, unknown>): MarrowRequestError {
  const status = response.status;
  const retryGuidance = responseRetryAfter(response);
  const cloudflareEdgeDenial = status === 403 && Boolean(response.headers.get('cf-ray')) && !detail;
  const errorObject = detail?.error && typeof detail.error === 'object' && !Array.isArray(detail.error)
    ? detail.error as Record<string, unknown>
    : undefined;
  const nestedDetails = detail?.details && typeof detail.details === 'object' && !Array.isArray(detail.details)
    ? detail.details as Record<string, unknown>
    : errorObject?.details && typeof errorObject.details === 'object' && !Array.isArray(errorObject.details)
      ? errorObject.details as Record<string, unknown>
      : undefined;
  const rejectionFields = [nestedDetails, errorObject, detail].filter(Boolean) as Record<string, unknown>[];
  const firstString = (...fields: string[]): string | undefined => {
    for (const source of rejectionFields) {
      for (const field of fields) {
        if (typeof source[field] === 'string' && String(source[field]).trim()) return String(source[field]);
      }
    }
    return undefined;
  };
  const firstStringArray = (...fields: string[]): string[] => {
    for (const source of rejectionFields) {
      for (const field of fields) {
        if (Array.isArray(source[field])) {
          return (source[field] as unknown[]).filter((value): value is string => typeof value === 'string');
        }
      }
    }
    return [];
  };
  const apiMessage = typeof detail?.error === 'string'
    ? detail.error
    : firstString('message', 'error') || `Marrow API returned HTTP ${status}`;
  const apiFix = firstString('exact_fix', 'exact_next_action', 'fix_command') || exactFixForStatus(status);
  const fixCommand = firstString('fix_command') || null;
  const backendCode = firstString('code') || null;
  const currentPlan = firstString('current_plan') || null;
  const requiredFeature = firstString('required_feature') || null;
  const code: MarrowFailureCode = cloudflareEdgeDenial
    ? 'edge_access_denied'
    : status === 409 && backendCode === 'MARROW_PROOF_PACK_INCOMPLETE'
      ? 'proof_required'
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
    retryable: !cloudflareEdgeDenial && retryGuidance.valid && RETRYABLE_STATUS.has(status),
    retryAfterMs: retryGuidance.delayMs,
    exactFix: cloudflareEdgeDenial
      ? 'Marrow was reached, but the Cloudflare edge denied this network client before API authentication. Record the Cloudflare Ray ID, retry from a trusted network, and send the Ray ID to Marrow support; do not rotate the API key.'
      : !retryGuidance.valid
      ? 'Retry-After could not be interpreted safely. Check service guidance before explicitly retrying the same operation.'
      : apiFix,
    fixCommand,
    currentPlan,
    requiredFeature,
    missingFields: code === 'proof_required' ? firstStringArray('missing_fields') : [],
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

function safeToRetry(url: string, init: RequestInit): boolean {
  const method = String(init.method || 'GET').toUpperCase();
  if (method === 'GET' || method === 'HEAD') return true;
  const headers = new Headers(init.headers);
  return headers.has('Idempotency-Key') || /\/v1\/analytics\/decision-brief(?:[/?]|$)/.test(url);
}

export type ReliableFetchOptions<T = Response> = {
  retryOwner?: 'caller';
  timeoutMs?: number;
  consumeResponse?: (response: Response) => Promise<T>;
};

export async function reliableFetch<T = Response>(
  url: string | URL,
  init: RequestInit = {},
  options: ReliableFetchOptions<T> = {},
): Promise<T> {
  const target = String(url);
  const timeoutMs = typeof options.timeoutMs === 'number' && Number.isFinite(options.timeoutMs) && options.timeoutMs > 0
    ? Math.min(boundedTimeout(target), options.timeoutMs)
    : boundedTimeout(target);
  const deadline = Date.now() + timeoutMs;
  const externalSignal = init.signal;
  let lastError: MarrowRequestError | null = null;
  const attempts = options.retryOwner === 'caller' ? 1 : safeToRetry(target, init) ? 2 : 1;

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    if (externalSignal?.aborted) throw normalizeRequestError(externalSignal.reason || new DOMException('Aborted', 'AbortError'));
    const remaining = deadline - Date.now();
    if (remaining < 50) break;
    const controller = new AbortController();
    const abortFromCaller = () => controller.abort(externalSignal?.reason);
    externalSignal?.addEventListener('abort', abortFromCaller, { once: true });
    const timer = setTimeout(() => controller.abort(new DOMException('Timed out', 'AbortError')), remaining);
    timer.unref?.();
    let delayMs = 0;
    let consumingResponse = false;
    try {
      const response = await globalThis.fetch(target, { ...init, signal: controller.signal });
      const consume = async (): Promise<T> => {
        if (!options.consumeResponse) return response as T;
        return await new Promise<T>((resolve, reject) => {
          const abort = () => {
            controller.signal.removeEventListener('abort', abort);
            reject(controller.signal.reason || new DOMException('Timed out', 'AbortError'));
          };
          if (controller.signal.aborted) {
            abort();
            return;
          }
          controller.signal.addEventListener('abort', abort, { once: true });
          Promise.resolve().then(() => options.consumeResponse!(response)).then(
            (value) => {
              controller.signal.removeEventListener('abort', abort);
              resolve(value);
            },
            (error) => {
              controller.signal.removeEventListener('abort', abort);
              reject(error);
            },
          );
        });
      };
      const consumeTerminalResponse = async (): Promise<T> => {
        consumingResponse = true;
        return await consume();
      };
      if (!RETRYABLE_STATUS.has(response.status) || attempt + 1 >= attempts) return await consumeTerminalResponse();
      lastError = requestErrorFromResponse(response);
      if (!lastError.retryable) return await consumeTerminalResponse();
      delayMs = lastError.retryAfterMs ?? 50;
      const remainingAfterResponse = deadline - Date.now();
      if (delayMs >= remainingAfterResponse - 50) return await consumeTerminalResponse();
      // A response that will be retried is never exposed to a caller. Cancel its
      // body while the same deadline is still active so the connection can be
      // reclaimed without leaving an unread stream behind.
      void response.body?.cancel().catch(() => undefined);
    } catch (error) {
      lastError = normalizeRequestError(error);
      if (consumingResponse) throw lastError;
      if (!lastError.retryable || attempt + 1 >= attempts) throw lastError;
      delayMs = 50;
    } finally {
      clearTimeout(timer);
      externalSignal?.removeEventListener('abort', abortFromCaller);
    }

    const remainingAfterAttempt = deadline - Date.now();
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
    installed_version_verified: true,
    latest_version: MCP_ADAPTER_VERSION,
    version_status: 'current',
    metadata_status: 'local_adapter_version',
    update_command: 'npx -y --package=@getmarrow/mcp@latest marrow-mcp setup',
    launch_command: 'npx -y --package=@getmarrow/mcp@latest marrow-mcp',
    verification_command: 'npx -y @getmarrow/install@latest doctor --self-test',
    operator_approval_required: true,
  };
}

export function structuredRequestFailure(error: unknown): Record<string, unknown> {
  const normalized = normalizeRequestError(error);
  const proofRequired = normalized.code === 'proof_required';
  const clientUpdate = localClientUpdate();
  if (proofRequired) clientUpdate.metadata_status = 'live_control_path_reached_version_unverified';
  return {
    ok: false,
    available: proofRequired,
    error: {
      code: normalized.backendCode || normalized.code,
      category: normalized.code,
      status: normalized.status,
      retryable: normalized.retryable,
      retry_after_ms: normalized.retryAfterMs,
      message: normalized.message,
      exact_fix: normalized.exactFix,
      ...(normalized.fixCommand ? { fix_command: normalized.fixCommand } : {}),
      ...(proofRequired ? { missing_fields: normalized.missingFields } : {}),
    },
    ...(proofRequired ? {
      validation_state: 'proof_required',
      service_reachable: true,
      missing_fields: normalized.missingFields,
    } : {}),
    ...(normalized.pendingReceipt ? { pending_receipt: normalized.pendingReceipt } : {}),
    client_update: clientUpdate,
  };
}
