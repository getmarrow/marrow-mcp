export declare const AUTO_HOOK_COMMAND: string;
export declare const AUTO_HOOK_MATCHER = "Bash|Edit|Write|MultiEdit|Read|Glob|Grep|Search|WebSearch|Task|functions\\.(?!mcp__marrow__marrow_).*|mcp__(?!marrow__marrow_).*";
interface HookEvent {
    tool_calls?: unknown;
    transcript_path?: unknown;
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
/** True only when the latest runHookCommand call spooled an event for background delivery. */
export declare function hookSpooledLifecycleEvent(): boolean;
export declare function runHookCommand(input?: unknown): Promise<void>;
/**
 * Claude Code PermissionRequest, pass-through: notes that the host is about to
 * show its own permission dialog for an asked (held) call. It never prints a
 * decision, so it cannot answer the dialog; setup installs it with async: true.
 * PermissionRequest input has no tool_use_id, so the call is matched on the
 * session, the tool name and the tool input.
 */
export declare function runPermissionRequestHookCommand(input?: unknown): Promise<void>;
export declare function installPermissionRequestHook(startDir?: string): HookInstallResult;
export {};
//# sourceMappingURL=hook.d.ts.map