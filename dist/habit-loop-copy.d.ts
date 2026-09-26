import type { MarrowModelUsageInput } from './types';
export interface MarrowHabitLoopCopy {
    contract: 'marrow.habit-loop.v1';
    headline: string;
    next: string;
    avoid: string[];
    savings: string;
    text: string;
}
export declare function formatHabitLoopCopy(source: unknown): MarrowHabitLoopCopy | null;
export interface ModelUsageCaptureContext {
    /** Observed request endpoint, supplied by the host adapter/config; never taken from response content. */
    endpoint?: string;
    provider?: string;
    pricing_dimensions?: Record<string, string | number>;
    billing_mode?: 'api' | 'subscription';
    usage_kind?: 'delta' | 'cumulative';
    occurred_at?: string;
}
export declare function modelUsageCaptureContextFromEnv(): ModelUsageCaptureContext;
export declare function extractModelUsageFromUnknown(source: unknown, context?: ModelUsageCaptureContext): MarrowModelUsageInput | null;
//# sourceMappingURL=habit-loop-copy.d.ts.map