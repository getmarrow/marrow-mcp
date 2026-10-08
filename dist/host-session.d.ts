/**
 * Whether a hook runs inside a local, interactive host session, the only
 * place a typed approval reply ("marrow approve CODE") may come from a person.
 * Codex and Gemini give hooks no interactive flag, and `codex exec` or
 * `gemini -p` take prompts from scripts, so the evidence is the hook's own
 * process ancestry: the nearest host process must have a terminal on its
 * standard input and must not run a non-interactive subcommand or flag.
 * Arguments are inspected in memory for those tokens only; nothing is stored,
 * logged or sent. Missing evidence (another OS, no /proc, no ps) is "not
 * interactive": no typed approval is offered.
 */
export type ProcessInfo = {
    pid: number;
    ppid: number;
    args: string[];
    terminal: boolean;
};
export type ProcessReader = (pid: number) => ProcessInfo | null;
/** true only with positive evidence; false or null means no typed approval is offered. */
export declare function localInteractiveSession(host: string, reader?: ProcessReader, startPid?: number): boolean | null;
type CodexSettings = {
    approval_policy?: string;
    approvals_reviewer?: string;
    sandbox_mode?: string;
    profile?: string;
};
export type ConfigReader = (path: string) => string | null;
/**
 * Only approval_policy, approvals_reviewer, sandbox_mode and profile are
 * kept, at the top level and per profile; every other line is skipped.
 */
export declare function parseCodexSettings(text: string): {
    top: CodexSettings;
    profiles: Record<string, CodexSettings>;
};
/**
 * Whether Codex, as started, shows no approval prompt for a held action:
 * approval bypass (`--dangerously-bypass-approvals-and-sandbox`, `--yolo`),
 * never-ask (`-a never`), automatic review (`--approve-for-me`,
 * `approvals_reviewer`), `--full-auto`, or full access (`-s
 * danger-full-access`), on the command line, in `-c` overrides, or in its
 * config (`$CODEX_HOME/config.toml`, a `-p` profile file and the active
 * profile table). Later sources override earlier ones as Codex applies them:
 * config, profile, `-c`, flags.
 */
export declare function codexApprovalPromptOff(args: string[], readConfig?: ConfigReader, env?: NodeJS.ProcessEnv): boolean;
/**
 * Whether the host's own approval prompt is off in this session, so leaving a
 * held action to it would let it run with no one asked. Codex is read from
 * its process and config (see codexApprovalPromptOff). Cline's auto-approve
 * and Windsurf's Turbo mode live in editor state with no reliable signal, so
 * they are not detected (false).
 */
export declare function hostApprovalPromptOff(host: string, reader?: ProcessReader, startPid?: number, readConfig?: ConfigReader): boolean;
export {};
//# sourceMappingURL=host-session.d.ts.map