export declare function writeStatusCache(input: {
    apiKey: string;
    baseUrl: string;
    agentId?: string;
    status: unknown;
    source: 'runtime' | 'status';
    home?: string;
}): boolean;
export declare function readStatusCache(input: {
    apiKey: string;
    baseUrl: string;
    agentId?: string;
    home?: string;
}): {
    status: Record<string, unknown>;
    source: 'runtime' | 'status';
    stale_ms: number;
    freshness: 'fresh' | 'stale';
} | null;
export declare function cachedStatusPayload(cached: NonNullable<ReturnType<typeof readStatusCache>>): Record<string, unknown>;
//# sourceMappingURL=status-cache.d.ts.map