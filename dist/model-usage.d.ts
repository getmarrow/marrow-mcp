import type { MarrowModelUsageInput } from './types';
/** Compact evidence only. Reject malformed supplied values; never coerce null into observed zero. */
export declare function normalizeModelUsage(input?: MarrowModelUsageInput): Record<string, unknown>;
export declare const MODEL_USAGE_EVIDENCE_PROPERTIES: {
    occurred_at: {
        type: string;
        format: string;
        maxLength: number;
    };
    pricing_dimensions: {
        type: string;
        maxProperties: number;
        additionalProperties: {
            anyOf: ({
                type: string;
                maxLength: number;
                minimum?: undefined;
            } | {
                type: string;
                minimum: number;
                maxLength?: undefined;
            })[];
        };
    };
};
//# sourceMappingURL=model-usage.d.ts.map