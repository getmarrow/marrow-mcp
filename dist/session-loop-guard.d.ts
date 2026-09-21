export type LoopGuardOperation = {
    sessionId?: string;
    agentId?: string;
    harness: string;
    toolName?: string;
    toolInput?: unknown;
    invocationId?: string;
    readOnly: boolean;
};
export type LoopGuardDecision = {
    allow: boolean;
    receipt: string;
    reason?: string;
    fingerprint: string;
};
export declare class UnsafeLoopGuardStateError extends Error {
    constructor();
}
export declare function consultSessionLoopGuard(operation: LoopGuardOperation, options?: {
    home?: string;
    now?: number;
}): LoopGuardDecision;
export declare function recordSessionLoopOutcome(operation: LoopGuardOperation, success: boolean, result: unknown, options?: {
    home?: string;
    now?: number;
}): void;
export declare function advanceSessionInstructionEpoch(operation: Pick<LoopGuardOperation, 'sessionId' | 'agentId' | 'harness'>, options?: {
    home?: string;
    now?: number;
}): void;
export declare function clearSessionLoopGuard(operation: Pick<LoopGuardOperation, 'sessionId' | 'agentId' | 'harness'>, options?: {
    home?: string;
}): void;
export declare function sessionLoopGuardPath(home?: string): string;
export declare function sessionLoopGuardEnabled(autoHook: unknown, localControlEnabled: boolean): boolean;
export declare function runSessionLoopGuardSelfTest(): {
    pass: true;
    isolated: true;
    live_hook_observed: false;
    repeat_denied: true;
    mutation_reset: true;
    owner_disabled_bypass: true;
};
//# sourceMappingURL=session-loop-guard.d.ts.map