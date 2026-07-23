export declare const SESSION_HOOK_COMMAND = "npx -y @getmarrow/mcp session-hook";
export declare function installSessionEndHook(startDir?: string): {
    settingsPath: string;
    installed: boolean;
};
export declare function runSessionHookCommand(input?: unknown): Promise<void>;
//# sourceMappingURL=hook-session.d.ts.map