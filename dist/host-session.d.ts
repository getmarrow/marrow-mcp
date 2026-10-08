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
    /** Linux: the process start time in clock ticks since boot (/proc/PID/stat field 22). */
    startTicks?: number;
};
export type ProcessReader = (pid: number) => ProcessInfo | null;
/** true only with positive evidence; false or null means no typed approval is offered. */
export declare function localInteractiveSession(host: string, reader?: ProcessReader, startPid?: number): boolean | null;
declare const CODEX_KEYS: readonly ["approval_policy", "approvals_reviewer", "sandbox_mode"];
type CodexKey = typeof CODEX_KEYS[number];
type CodexValues = Partial<Record<CodexKey | 'profile', string>>;
export type ConfigReader = (path: string) => string | null;
/** What one Codex config text says about its approval prompt. */
export type CodexConfigSettings = {
    /** Top-level approval_policy, approvals_reviewer, sandbox_mode and profile. */
    top: CodexValues;
    /** The same three keys per profile (`[profiles.NAME]`, `profiles.NAME.key`, inline tables). */
    profiles: Record<string, CodexValues>;
    /** A line naming one of these keys could not be read: the prompt is then treated as off. */
    unreadable: boolean;
};
/**
 * A small TOML reader for the keys above only: tables and array tables,
 * dotted and quoted keys, basic, literal and multi-line strings, inline
 * tables and arrays. Values of every other key are skipped and never kept.
 */
export declare function parseCodexSettings(input: string): CodexConfigSettings;
/**
 * Whether Codex, as started, shows no approval prompt for a held action:
 * approval bypass (`--dangerously-bypass-approvals-and-sandbox`, `--yolo`),
 * never-ask (`-a never`), automatic review (`--approve-for-me`, or an
 * `approvals_reviewer` other than `user`), `--full-auto`, or full access
 * (`-s danger-full-access`), on the command line, in `-c` overrides
 * (including `profiles.NAME.key`), or in its config: `$CODEX_HOME/config.toml`
 * with its active profile, and a `-p NAME` profile file. A flag decides its
 * own setting; otherwise any of those sources that turns the prompt off
 * counts, since their order cannot be known for certain from outside Codex.
 * A line naming one of these keys that cannot be read also counts as off.
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
/** Gemini CLI started in YOLO mode runs every tool without asking. */
export declare function geminiApprovalPromptOff(args: string[]): boolean;
/**
 * Whether a typed reply could come from someone other than the person: the
 * host runs tools without asking, so the agent could run the prompt hook
 * itself with a code it read from this user's files. Codex: its approval
 * prompt off (codexApprovalPromptOff). Gemini CLI: YOLO. Cursor: its auto-run
 * mode cannot be seen, so always. A host process that cannot be found counts
 * as off.
 */
export declare function typedReplyPromptOff(host: string, reader?: ProcessReader, startPid?: number, readConfig?: ConfigReader): boolean;
/**
 * How long before this process the host started launching it (npx, npm, a
 * `sh -c` wrapper), in milliseconds, so a host's kill clock that started at
 * spawn can be honored. Linux only (from /proc start times); 0 when unknown,
 * including a launcher older than 4 s (a long-lived wrapper, not start-up).
 */
export declare function hookLauncherHeadStartMs(reader?: ProcessReader, selfPid?: number): number;
export {};
//# sourceMappingURL=host-session.d.ts.map