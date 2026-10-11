export interface ResolvedMarrowEnv {
    apiKey: string;
    baseUrl: string;
    agentId?: string;
    sessionId?: string;
    source: string | null;
    missing: boolean;
    exactFix: string;
}
/** Host (with port) of a non-default base URL, for status output; null for the default. */
export declare function nonDefaultBaseUrlHost(baseUrl: string): string | null;
export declare function resolveMarrowEnv(options?: {
    cwd?: string;
    env?: NodeJS.ProcessEnv;
    home?: string;
    trustedOnly?: boolean;
}): ResolvedMarrowEnv;
//# sourceMappingURL=env.d.ts.map