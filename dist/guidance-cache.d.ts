export declare function writeGuidanceCache(input: {
    apiKey: string;
    baseUrl: string;
    agentId?: string;
    context: string;
    home?: string;
}): void;
export declare function readGuidanceCache(input: {
    apiKey: string;
    baseUrl: string;
    agentId?: string;
    home?: string;
}): {
    context: string;
    stale_ms: number;
} | null;
//# sourceMappingURL=guidance-cache.d.ts.map