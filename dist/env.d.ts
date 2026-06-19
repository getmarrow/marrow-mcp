export interface ResolvedMarrowEnv {
    apiKey: string;
    baseUrl: string;
    agentId?: string;
    sessionId?: string;
    source: string | null;
    missing: boolean;
    exactFix: string;
}
export declare function resolveMarrowEnv(options?: {
    cwd?: string;
    env?: NodeJS.ProcessEnv;
    home?: string;
}): ResolvedMarrowEnv;
//# sourceMappingURL=env.d.ts.map