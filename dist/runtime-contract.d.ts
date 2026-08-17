import type { MarrowAgentRuntimeResult, MarrowRuntimePlanCapability } from './types';
export declare function runtimeAuthorizationReceiptId(runtime: MarrowAgentRuntimeResult | null | undefined): string | null;
export declare function normalizeRuntimePlanCapability(value: unknown, riskGateValue?: unknown): MarrowRuntimePlanCapability | null;
export declare function isValidRuntimeResult(value: unknown): value is MarrowAgentRuntimeResult;
export declare function normalizeRuntimeResult(value: unknown): MarrowAgentRuntimeResult | null;
export declare function highRiskRuntimeCanClose(runtime: MarrowAgentRuntimeResult, proof: Record<string, unknown> | undefined, explicitReceiptId: unknown, now?: number): boolean;
//# sourceMappingURL=runtime-contract.d.ts.map