/** Where resolveMarrowEnv took the agent id from. `fleet_key_match` is the process-env id that also picked a fleet key. */
export type AgentIdOrigin = 'fleet_key_match' | 'process_env' | 'owner_file' | 'none';
export type AgentIdVariable = 'MARROW_FLEET_AGENT_ID' | 'MARROW_AGENT_ID';
/** Names only, never a value: which variable supplied the id and which origin won. */
export interface AgentIdSource {
    origin: AgentIdOrigin;
    variable: AgentIdVariable | null;
    /** fleet_key_match only: the NAME of the key variable the id selected (MARROW_KEY_<X>). */
    keyVariable?: string;
    /** owner_file only: the owner file that supplied the id, as `~/...`. */
    ownerFile?: string;
}
export interface ResolvedMarrowEnv {
    apiKey: string;
    baseUrl: string;
    agentId?: string;
    /** The origin and variable of `agentId`. Explanation only: no decision reads it. */
    agentIdSource: AgentIdSource;
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
export declare const SAFE_AGENT_ID: RegExp;
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