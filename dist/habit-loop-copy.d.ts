export interface MarrowHabitLoopCopy {
    contract: 'marrow.habit-loop.v1';
    headline: string;
    next: string;
    avoid: string[];
    savings: string;
    text: string;
}
export declare function formatHabitLoopCopy(source: unknown): MarrowHabitLoopCopy | null;
export declare function extractModelUsageFromUnknown(source: unknown): {
    provider?: string;
    model?: string;
    input_tokens?: number;
    output_tokens?: number;
    cached_tokens?: number;
    total_tokens?: number;
} | null;
//# sourceMappingURL=habit-loop-copy.d.ts.map