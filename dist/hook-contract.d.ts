import { resolveMarrowEnv, type ResolvedMarrowEnv } from './env';
export declare const MCP_ADAPTER_VERSION = "3.9.74";
export declare const NATIVE_HOOK_MATCHER = "Bash|Edit|Write|MultiEdit|mcp__(?!marrow__marrow_).*";
export declare const GROK_NATIVE_HOOK_MATCHER = "run_terminal_command|search_replace|write|spawn_subagent|use_tool|workflow|image_gen|image_edit|image_to_video|reference_to_video";
export declare const MCP_PACKAGE_SPEC = "@getmarrow/mcp@3.9.74";
export declare const CONTEXT_HOOK_COMMAND: string;
export declare const PRE_ACTION_HOOK_COMMAND: string;
export declare const ACTION_RESULT_HOOK_COMMAND: string;
export declare const SESSION_END_HOOK_COMMAND: string;
export declare const GROK_CONTEXT_HOOK_COMMAND: string;
export declare const GROK_PRE_ACTION_HOOK_COMMAND: string;
export declare const GROK_ACTION_RESULT_HOOK_COMMAND: string;
export declare const GROK_SESSION_END_HOOK_COMMAND: string;
export type NativeHookHarness = 'claude-code' | 'grok' | 'mcp-client';
export interface NativeHookIdentity {
    harness: NativeHookHarness;
    identity_source: 'public_cli_entrypoint' | 'generic_fallback';
    client_self_reported: true;
    agent_id?: string;
    environment: ResolvedMarrowEnv;
}
/**
 * Label client-reported hook activity from the public CLI entrypoint. The
 * entrypoint is not host provenance and cannot certify coverage. Hook JSON is
 * deliberately not an identity input, and the authenticated service remains
 * authoritative for the credential-bound agent identity.
 */
export declare function resolveNativeHookIdentity(entrypoint: unknown, options?: Parameters<typeof resolveMarrowEnv>[0]): NativeHookIdentity;
export declare function clientReportedHookLifecycleIdentity(identity: NativeHookIdentity): Pick<import('./lifecycle-spool').LifecycleEvent, 'harness' | 'agent_id' | 'source'>;
export declare function normalizeHookEventPayload(value: unknown): Record<string, unknown>;
type HookSettings = Record<string, unknown>;
export declare function findHookSettingsPath(startDir?: string): string;
export declare function readHookSettings(startDir?: string): HookSettings;
export declare function readHookSettingsForInstall(startDir?: string): HookSettings;
export type MarrowHookSubcommand = 'context-hook' | 'pre-action-hook' | 'hook' | 'session-hook';
export declare function reconcileMarrowCommandHook(settings: HookSettings, eventName: string, subcommand: MarrowHookSubcommand, command: string, matcher?: string): {
    entries: unknown[];
    changed: boolean;
};
export declare function hasExactCommandHook(settings: HookSettings, eventName: string, command: string, matcher?: string): boolean;
export declare function localHookConfigurationFingerprint(startDir?: string): string;
export declare function stableToolCorrelation(event: {
    session_id?: string;
    tool_use_id?: string;
    tool_name?: string;
    tool_input?: unknown;
}): string;
export declare function stablePromptCorrelation(event: {
    session_id?: string;
    prompt?: string;
}): string;
export declare function stableSessionWorkflowId(sessionId?: string, fallback?: unknown): string;
export declare function grokHookSettingsPath(home?: string): string;
export declare function installGrokNativeHooks(home?: string): {
    settingsPath: string;
    installed: boolean;
};
export {};
//# sourceMappingURL=hook-contract.d.ts.map