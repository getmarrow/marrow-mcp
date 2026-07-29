import { marrowAgentRuntime } from './index';
export type PreToolUseEvent = {
    session_id?: string;
    hook_event_name?: string;
    tool_use_id?: string;
    tool_name?: string;
    tool_input?: unknown;
};
export declare function preActionHookOutput(runtime: Awaited<ReturnType<typeof marrowAgentRuntime>> | null): Record<string, unknown>;
export declare function installPreActionHook(startDir?: string): {
    settingsPath: string;
    installed: boolean;
};
export declare function runPreActionHookCommand(input?: unknown): Promise<void>;
//# sourceMappingURL=hook-pre-action.d.ts.map