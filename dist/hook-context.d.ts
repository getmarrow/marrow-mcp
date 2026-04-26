/**
 * UserPromptSubmit hook — Marrow context injection.
 *
 * Fires whenever the user submits a message to the agent. Reads the prompt,
 * calls marrow_think, and returns matching warnings/patterns/insights as
 * `additionalContext` so the agent sees Marrow's intelligence in its prompt
 * window without ever calling a tool. Closes the passive read loop:
 *
 *   PostToolUse hook  → auto-LOG every action          (write side, V3.2)
 *   UserPromptSubmit  → auto-INJECT relevant context   (read side, V6.8)
 *
 * Both hooks are installed by `npx @getmarrow/mcp setup`. Either can be
 * disabled with `MARROW_AUTO_HOOK=false`.
 */
export declare const CONTEXT_HOOK_COMMAND = "npx -y @getmarrow/mcp context-hook";
interface InstallResult {
    settingsPath: string;
    installed: boolean;
}
export declare function runContextHookCommand(): Promise<void>;
/**
 * Idempotent installer. Adds (or upgrades to) the UserPromptSubmit hook entry
 * in `.claude/settings.json`. Call this from the same setup command that
 * installs the PostToolUse hook.
 */
export declare function installUserPromptSubmitHook(startDir?: string): InstallResult;
export {};
//# sourceMappingURL=hook-context.d.ts.map