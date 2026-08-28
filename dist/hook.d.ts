export declare const AUTO_HOOK_COMMAND: string;
export declare const AUTO_HOOK_MATCHER = "Bash|Edit|Write|MultiEdit|mcp__(?!marrow__marrow_).*";
interface HookEvent {
    session_id?: string;
    conversation_id?: string;
    generation_id?: string;
    task_id?: string;
    hook_event_name?: string;
    tool_use_id?: string;
    tool_name?: string;
    tool_input?: unknown;
    tool_response?: unknown;
    tool_result?: unknown;
    tool_output?: unknown;
    error?: unknown;
    error_message?: unknown;
    failure_type?: unknown;
    duration_ms?: unknown;
    success?: unknown;
    is_interrupt?: boolean;
}
interface HookInstallResult {
    settingsPath: string;
    installed: boolean;
}
export declare function shouldSkipAutoLog(event: HookEvent): boolean;
export declare function deriveAction(event: HookEvent): string | null;
export declare function deriveToolOutcome(event: HookEvent): {
    success: boolean;
    duration_ms?: number;
};
export declare function installPostToolUseHook(startDir?: string): HookInstallResult;
export declare function runHookCommand(input?: unknown): Promise<void>;
export {};
//# sourceMappingURL=hook.d.ts.map