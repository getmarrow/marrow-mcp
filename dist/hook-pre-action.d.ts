import { marrowAgentRuntime, marrowEnforcement } from './index';
export declare const GOVERNED_WRAPPER_COMMAND = "npx @getmarrow/install run --agent <agent-id> -- -- <command>";
export type PreToolUseEvent = {
    session_id?: string;
    hook_event_name?: string;
    tool_use_id?: string;
    tool_name?: string;
    tool_input?: unknown;
};
type PreActionControlResult = {
    runtime: Awaited<ReturnType<typeof marrowAgentRuntime>> | null;
    permit: Awaited<ReturnType<typeof marrowEnforcement>> | null;
    protectedRisk: boolean;
    enforcementError?: string;
};
export declare function classifyTool(event: PreToolUseEvent): {
    action: string;
    target: string;
    type: string;
    role: string;
    surfaces: string[];
    risk: 'low' | 'medium' | 'high';
    protected: boolean;
    readOnly: boolean;
};
export declare function preActionHookOutput(result: PreActionControlResult): Record<string, unknown>;
export declare function grokPreActionAdvisoryOutput(): Record<string, unknown>;
export declare function installPreActionHook(startDir?: string): {
    settingsPath: string;
    installed: boolean;
};
export declare function runPreActionHookCommand(input?: unknown): Promise<void>;
export {};
//# sourceMappingURL=hook-pre-action.d.ts.map