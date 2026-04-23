export declare const AUTO_HOOK_COMMAND = "npx -y @getmarrow/mcp hook";
export declare const AUTO_HOOK_MATCHER = "Bash|Edit|Write|MultiEdit|mcp__(?!marrow_).*";
interface HookInstallResult {
    settingsPath: string;
    installed: boolean;
}
export declare function installPostToolUseHook(startDir?: string): HookInstallResult;
export declare function runHookCommand(): Promise<void>;
export {};
//# sourceMappingURL=hook.d.ts.map