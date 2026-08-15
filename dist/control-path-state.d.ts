export type ControlPathStats = {
    tool: string;
    current_ms: number | null;
    p50_ms: number | null;
    p99_ms: number | null;
    sample_count: number;
    success_count: number;
    failure_count: number;
    last_success_at: string | null;
};
export declare function recordControlPathSample(tool: string, elapsedMs: number, success: boolean): ControlPathStats;
export declare function controlPathStats(tool: string): ControlPathStats;
export declare function resetControlPathState(): void;
//# sourceMappingURL=control-path-state.d.ts.map