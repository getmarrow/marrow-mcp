import type { SeatbeltDecision, SeatbeltEnv, SeatbeltEvent, SeatbeltHit } from './mapper';
/** The mapper's own readers and tables, handed over by its one call site (mapper.ts evaluateSeatbelt). */
export interface WinMapperParts {
    shellInvocations(name: string, input: Record<string, unknown>, deadline: number, rawText: string | null): {
        shell: string[];
        code: string[];
    } | null;
    mcpCall(name: string, input: Record<string, unknown>): {
        name: string;
        label: string;
        args: Record<string, unknown>;
        malformed: boolean;
    } | null;
    pathInputs(input: Record<string, unknown>): string[];
    walkPathInputs(input: Record<string, unknown>, deadline: number, allStrings?: boolean): {
        paths: string[];
        strings: string[];
        truncated: boolean;
        timedOut: boolean;
    };
    patchPaths(patch: string): string[];
    protectedExtra: readonly string[];
    operandOmits: ReadonlySet<string>;
    tools: {
        read: ReadonlySet<string>;
        grep: ReadonlySet<string>;
        write: ReadonlySet<string>;
        delete: ReadonlySet<string>;
        list: ReadonlySet<string>;
        inert: ReadonlySet<string>;
        nonShell: ReadonlySet<string>;
        nativeShell: ReadonlyMap<string, string>;
    };
}
/** The reason codes this module adds. The decision's rule is `<category>.<reason>` when one of them leads it. */
export declare const WINDOWS_REASONS: Readonly<{
    protectedPath: "windows_protected_path";
    persistence: "windows_persistence";
    shim: "windows_shim_write";
    secretPath: "windows_secret_path";
    envDump: "windows_env_dump";
    secretStore: "windows_secret_store";
    oddPath: "windows_odd_path";
}>;
export declare function matcherCells(reset?: boolean): number;
/** The extra hits for one event on win32 (the same tool reading as mapper.ts evaluateEvent). */
export declare function windowsProtectedHits(event: SeatbeltEvent, env: SeatbeltEnv, parts: WinMapperParts, startedAt?: number): SeatbeltHit[];
/** The mapper's decision with the extra hits added. Hits are only added; a stop is never removed. */
export declare function mergeWindowsHits(decision: SeatbeltDecision, extra: SeatbeltHit[]): SeatbeltDecision;
/** The one entry point (mapper.ts evaluateSeatbelt): win32 only; any other platform gets the decision unchanged. */
export declare function withWindowsProtected(decision: SeatbeltDecision, event: SeatbeltEvent, env: SeatbeltEnv, parts: WinMapperParts, startedAt?: number): SeatbeltDecision;
//# sourceMappingURL=win-protected.d.ts.map