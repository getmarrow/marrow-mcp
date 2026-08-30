import type { MarrowAgentRuntimeResult, MarrowRuntimePlanCapability } from './types';
export declare function runtimeAuthorizationReceiptId(runtime: MarrowAgentRuntimeResult | null | undefined): string | null;
export declare function isOutcomeObservationOnlyCorrelationId(value: unknown): boolean;
export declare function normalizeRuntimePlanCapability(value: unknown, riskGateValue?: unknown): MarrowRuntimePlanCapability | null;
export declare function isOutcomeObservationOnlyRuntime(runtime: MarrowAgentRuntimeResult | null | undefined): boolean;
export declare function isValidRuntimeResult(value: unknown): value is MarrowAgentRuntimeResult;
export declare function normalizeRuntimeResult(value: unknown): MarrowAgentRuntimeResult | null;
export declare function highRiskRuntimeCanClose(runtime: MarrowAgentRuntimeResult, proof: Record<string, unknown> | undefined, explicitReceiptId: unknown, now?: number): boolean;
/**
 * A runtime receipt is immutable authorization, while proof is commit evidence.
 * This permits one missing-to-supplied proof continuation without weakening the
 * gate; the backend still validates and binds the exact proof on commit.
 */
export declare function highRiskRuntimeCanContinueWithProof(runtime: MarrowAgentRuntimeResult, proof: Record<string, unknown> | undefined, explicitReceiptId: unknown, now?: number): boolean;
//# sourceMappingURL=runtime-contract.d.ts.map