import { marrowAgentRuntime, marrowEnforcement } from './index';
export type PreToolUseEvent = {
    session_id?: string;
    conversation_id?: string;
    generation_id?: string;
    task_id?: string;
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
export declare function localControlAllowOutput(harness: 'claude-code' | 'cline' | 'codex' | 'cursor' | 'gemini' | 'grok' | 'windsurf' | 'mcp-client'): Record<string, unknown> | null;
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
export declare function cursorPreActionHookOutput(result: PreActionControlResult): Record<string, unknown>;
export declare function clinePreActionHookOutput(result: PreActionControlResult): Record<string, unknown>;
export declare function windsurfPreActionDecision(result: PreActionControlResult): {
    exitCode: 0 | 2;
    stderr: string;
};
export declare function geminiPreActionHookOutput(result: PreActionControlResult): {
    decision: 'allow' | 'deny';
    reason?: string;
};
export declare function grokPreActionHookOutput(result: PreActionControlResult): {
    decision: 'allow' | 'deny';
    reason?: string;
};
export declare function preActionHookOutput(result: PreActionControlResult, harness?: 'claude-code' | 'cline' | 'codex' | 'cursor' | 'gemini' | 'grok' | 'windsurf' | 'mcp-client'): Record<string, unknown>;
export declare function installPreActionHook(startDir?: string): {
    settingsPath: string;
    installed: boolean;
};
export declare function runPreActionHookCommand(input?: unknown): Promise<void>;
export {};
//# sourceMappingURL=hook-pre-action.d.ts.map