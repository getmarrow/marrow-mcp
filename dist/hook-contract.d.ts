export declare const MCP_ADAPTER_VERSION = "3.9.72";
export declare const NATIVE_HOOK_MATCHER = "Bash|Edit|Write|MultiEdit|mcp__(?!marrow__marrow_).*";
export declare const GROK_NATIVE_HOOK_MATCHER = "run_terminal_command|search_replace|write|spawn_subagent|use_tool|workflow|image_gen|image_edit|image_to_video|reference_to_video";
export declare const MCP_PACKAGE_SPEC = "@getmarrow/mcp@3.9.72";
export declare const CONTEXT_HOOK_COMMAND = "npx -y --package=@getmarrow/mcp@3.9.72 marrow-mcp context-hook";
export declare const PRE_ACTION_HOOK_COMMAND = "npx -y --package=@getmarrow/mcp@3.9.72 marrow-mcp pre-action-hook";
export declare const ACTION_RESULT_HOOK_COMMAND = "npx -y --package=@getmarrow/mcp@3.9.72 marrow-mcp hook";
export declare const SESSION_END_HOOK_COMMAND = "npx -y --package=@getmarrow/mcp@3.9.72 marrow-mcp session-hook";
export declare const NATIVE_EXPECTED_HOOKS: readonly ["prompt", "pre_action", "action_result", "session_end"];
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
export declare function nativeHookConfigurationFingerprint(startDir?: string): string;
export declare function nativeHookEvidence(observedHook: typeof NATIVE_EXPECTED_HOOKS[number], startDir?: string): {
    adapter_version: string;
    capability_level: 'native_hooks';
    config_fingerprint: string;
    expected_hooks: string[];
    observed_hook: typeof observedHook;
};
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