import type { MarrowModelUsageInput } from './types';
export declare const CODEX_USAGE_LIMITS: {
    readonly fileBytes: number;
    readonly tailBytes: number;
    readonly lineBytes: number;
    readonly lines: 2048;
    readonly readMs: 50;
};
type Counters = [number, number, number, number, number, number | null];
export interface CodexUsageCheckpoint {
    version: 1;
    thread: string;
    turn: string;
    model: string;
    total: Counters;
    submitted?: string;
}
export interface CodexUsageObservation {
    reason: string;
    checkpoint?: CodexUsageCheckpoint;
    usage?: MarrowModelUsageInput;
}
/** Reads one supported event or bounded current transcript. Never returns transcript text. */
export declare function observeCodexNativeUsage(input: unknown, previous?: CodexUsageCheckpoint, options?: {
    sessionsRoot?: string;
}): CodexUsageObservation;
/** Compact private checkpoint avoids duplicate uploads across native hook processes. */
export declare function captureCodexNativeUsage(input: unknown, apiKey: string, baseUrl: string, agentId?: string): Promise<void>;
export {};
//# sourceMappingURL=codex-native-usage.d.ts.map