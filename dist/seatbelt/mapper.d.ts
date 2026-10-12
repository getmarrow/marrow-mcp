export type SeatbeltCategory = 'none' | 'S0' | 'S1' | 'S2' | 'S3' | 'S4' | 'S5' | 'Sx';
export type SeatbeltParse = 'ok' | 'dynamic' | 'unparsed' | 'too_large';
export interface SeatbeltFs {
    /** File content as text, or null when missing, unreadable, not a regular file or larger than maxBytes. */
    readFile(absPath: string, maxBytes: number): string | null;
    /** realpath(3) of an existing path, or null when it does not exist. */
    realpath(absPath: string): string | null;
    /**
     * Entry names of a directory (no `.` or `..`), or null when it is missing or unreadable. Optional:
     * without it a glob that could reach a symlink cannot be expanded and stops (audit F9).
     */
    readdir?(absPath: string): string[] | null;
}
export interface SeatbeltGit {
    /** Work-tree top level for cwd, or null when cwd is not in a repository. */
    toplevel(cwd: string): string | null;
    /** All values of a config key in git order (system, global, includes, repo); key in git's canonical case. */
    getAll(cwd: string, key: string): string[];
    /** Current branch name, or null when detached or unknown. */
    currentBranch(cwd: string): string | null;
    /** Branch that refs/remotes/<remote>/HEAD points at, or null. */
    remoteHead(cwd: string, remote: string): string | null;
}
export interface SeatbeltEnv {
    /** Event cwd from the harness. Missing or relative means the workspace is unknown. */
    cwd: string | null | undefined;
    /** Home from passwd or the hook's baked --home, never $HOME from the agent env. */
    home: string;
    tmpdir?: string;
    platform?: string;
    fs: SeatbeltFs;
    git: SeatbeltGit;
    /** The classifier's class for the same action. Recorded only; it never decides an S category. */
    classifierClass?: string;
    /** Wall-clock budget for one classification in ms (default LIMITS.timeBudgetMs). Over it: stop. */
    budgetMs?: number;
}
export interface SeatbeltHit {
    category: Exclude<SeatbeltCategory, 'none'>;
    reason: string;
}
export interface SeatbeltDecision {
    decision: 'pass' | 'stop';
    category: SeatbeltCategory;
    rule: string;
    reasons: string[];
    hits: SeatbeltHit[];
    flags: string[];
    parse: SeatbeltParse;
    engine: {
        rules: string;
        classifier_contract: string;
        classifier_source_commit: string;
    };
}
export interface SeatbeltEvent {
    tool_name: string;
    tool_input?: unknown;
}
export declare function evaluateSeatbeltShell(command: string, env: SeatbeltEnv): SeatbeltDecision;
export declare function evaluateSeatbelt(event: SeatbeltEvent, env: SeatbeltEnv): SeatbeltDecision;
//# sourceMappingURL=mapper.d.ts.map