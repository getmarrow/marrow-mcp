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
//# sourceMappingURL=host-session.d.ts.map