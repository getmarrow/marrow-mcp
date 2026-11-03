import { type WinEnsure, type WinEnsureOk } from './win-private-state';
type LoopOutcome = 'success' | 'failure';
type LoopKind = 'poll' | 'verification' | 'read' | 'mutation';
type LoopEntry = {
    fingerprint: string;
    kind: LoopKind;
    outcome: LoopOutcome | null;
    result_hash: string | null;
    unchanged_count: number;
    attempts: number;
    updated_at: number;
    receipt: string;
};
type SessionState = {
    work_epoch: number;
    instruction_epoch: number;
    updated_at: number;
    entries: Record<string, LoopEntry>;
    invocations: Record<string, string>;
};
type GuardState = {
    version: 1;
    secret: string;
    sessions: Record<string, SessionState>;
};
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
export interface LoopGuardPlatform {
    platform: NodeJS.Platform;
    ensure(home: string): WinEnsure;
    verify(home: string, proof: WinEnsureOk): boolean;
}
export declare function withLoopGuardPlatform<T>(injected: LoopGuardPlatform, run: () => T): T;
/**
 * Only over the cap: drop the oldest loop-guard entries of OTHER sessions (oldest session first, clamped to `now`,
 * never below LOOP_FLOOR entries and one mapping per kept entry) until the state is under the low-water mark. An entry
 * stamped after `now` (a backward clock step) stays on top of the floor and is never dropped here; master's TTL rule
 * removes it once the clock has passed it. The current session, the secret and the version are never touched.
 * Returns the serialized state, or fails closed as before.
 */
export declare function pruneLoopGuardStateToBytes(state: GuardState, currentKey: string | null, now: number, cap?: number, lowWater?: number): string;
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
export {};
//# sourceMappingURL=session-loop-guard.d.ts.map