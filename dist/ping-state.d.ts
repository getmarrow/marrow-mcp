export declare function updatePingState(input: {
    apiKey: string;
    baseUrl: string;
    agentId?: string;
    latencyMs?: number;
    success: boolean;
    home?: string;
}): {
    last_success_at: string | null;
    sample_count: number;
    p50_ms: number | null;
    p99_ms: number | null;
};
//# sourceMappingURL=ping-state.d.ts.map