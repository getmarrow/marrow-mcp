export interface ResolvedMarrowEnv {
    apiKey: string;
    baseUrl: string;
    agentId?: string;
    sessionId?: string;
    source: string | null;
    missing: boolean;
    exactFix: string;
    /** Set when a base URL from the process environment was not used with an owner-file key. Names the source only, never a value. */
    baseUrlNotice?: string;
    /** Set only on a no-key result: an owner key file exists but failed the owner-only check, so whatever it holds was refused. */
    ownerFileRefused?: boolean;
}
/** Host (with port) of a non-default base URL, for status output; null for the default. */
export declare function nonDefaultBaseUrlHost(baseUrl: string): string | null;
/** Writes a resolver notice to stderr once per process. Notices name a source, never a key or a URL. */
export declare function emitBaseUrlNotice(resolved: {
    baseUrlNotice?: string;
}): void;
export declare function resolveMarrowEnv(options?: {
    cwd?: string;
    env?: NodeJS.ProcessEnv;
    home?: string;
    trustedOnly?: boolean;
}): ResolvedMarrowEnv;
//# sourceMappingURL=env.d.ts.map