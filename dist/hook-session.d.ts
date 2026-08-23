export declare const SESSION_HOOK_COMMAND: string;
export declare function installSessionEndHook(startDir?: string): {
    settingsPath: string;
    installed: boolean;
};
export declare function sessionEndAutoCommitOpen(value?: unknown): boolean;
export declare function runSessionHookCommand(input?: unknown): Promise<void>;
//# sourceMappingURL=hook-session.d.ts.map