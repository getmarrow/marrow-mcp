export type MarrowFailureCode = 'authentication_required' | 'permission_denied' | 'rate_limited' | 'request_timeout' | 'dns_unavailable' | 'connection_reset' | 'tls_failure' | 'service_unavailable' | 'invalid_response' | 'request_failed';
export declare class MarrowRequestError extends Error {
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
    });
}
export declare function requestErrorFromResponse(response: Response, detail?: Record<string, unknown>): MarrowRequestError;
export declare function normalizeRequestError(error: unknown): MarrowRequestError;
export declare function reliableFetch(url: string | URL, init?: RequestInit): Promise<Response>;
export declare function localClientUpdate(): Record<string, unknown>;
export declare function structuredRequestFailure(error: unknown): Record<string, unknown>;
//# sourceMappingURL=request-reliability.d.ts.map