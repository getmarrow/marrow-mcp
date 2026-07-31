export declare const AUTO_HOOK_COMMAND = "npx -y @getmarrow/mcp@3.9.51 hook";
export declare const AUTO_HOOK_MATCHER = "Bash|Edit|Write|MultiEdit|mcp__(?!marrow_).*";
interface HookEvent {
    session_id?: string;
    hook_event_name?: string;
    tool_use_id?: string;
    tool_name?: string;
    tool_input?: unknown;
    tool_response?: unknown;
    tool_result?: unknown;
    error?: unknown;
    is_interrupt?: boolean;
}
interface HookInstallResult {
    settingsPath: string;
    installed: boolean;
}
export declare function shouldSkipAutoLog(event: HookEvent): boolean;
export declare function installPostToolUseHook(startDir?: string): HookInstallResult;
export declare function runHookCommand(): Promise<void>;
export {};
//# sourceMappingURL=hook.d.ts.map