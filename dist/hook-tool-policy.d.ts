type ToolPolicyEvent = {
    tool_name?: string;
    tool_input?: unknown;
};
export declare function normalizeHookToolName(value: unknown): string;
export declare function isOfficialMarrowMcpTool(value: unknown): boolean;
export declare function isOfficialMarrowMcpEvent(event: ToolPolicyEvent): boolean;
export declare function isMcpHookTool(value: unknown): boolean;
export declare function isProtectedShellMutation(command: string): boolean;
export declare function hookToolCommand(event: ToolPolicyEvent): string;
export declare function isReadOnlyToolEvent(event: ToolPolicyEvent): boolean;
export {};
//# sourceMappingURL=hook-tool-policy.d.ts.map