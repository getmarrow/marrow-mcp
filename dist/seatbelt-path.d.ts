import type { SeatbeltFs } from './seatbelt-fs';
export declare const MAX_SYMLINK_HOPS = 40;
export type RealPathResult = {
    status: 'resolved';
    path: string;
    exists: boolean;
} | {
    status: 'unknown';
    reason: 'not_absolute' | 'loop' | 'unreadable' | 'proc_handle';
};
/**
 * realpath of the longest existing prefix, with the remainder appended
 * lexically. followFinal=false leaves a final symlink unresolved (rm -r on a
 * link removes the link, not its target).
 */
export declare function realPath(fs: SeatbeltFs, input: string, options?: {
    followFinal?: boolean;
}): RealPathResult;
/** Comparison key: case-folded (and NFC-normalised) on case-insensitive volumes. */
export declare function pathKey(fs: SeatbeltFs, value: string): string;
/** True when child is root itself or below it. */
export declare function isWithinOrEqual(fs: SeatbeltFs, root: string, child: string): boolean;
export interface PathContext {
    /** Trusted home: passwd or the hook's --home value, never $HOME from the agent's environment. */
    home: string | null;
    /** The event's cwd (absolute), or null when the harness gave none. */
    cwd: string | null;
    /**
     * Shell variables whose value is known when this command's words are
     * expanded: set by an earlier, unconditional statement (`DIR=x; rm -rf
     * "$DIR"`, `DIR=x && rm -rf "$DIR"`). Bash semantics: a prefix assignment
     * (`DIR=x rm -rf "$DIR"`) only goes to the command's environment and is NOT
     * seen by its own argument expansion, which uses the shell's prior value.
     * Never put prefix assignments here; a name not listed is unknown. Values
     * are what the shell holds: tilde-expanded at assignment (a value that still
     * starts with `~` is unknown). A `PWD` set here that is not `cwd` makes
     * `$PWD` and `~+` unknown; `~-`, `~N` and `$OLDPWD` are unknown unless set.
     */
    variables?: Record<string, string>;
    /**
     * The command's own prefix assignments. Accepted only so a caller can pass
     * them without them leaking into expansion: they are never substituted, and
     * a name assigned here and not in `variables` stays unknown.
     */
    prefixAssignments?: Record<string, string>;
    /**
     * The $HOME the agent's shell expands for `~` and `$HOME`. When given and
     * not exactly `home`, both expansions are unknown. (U4 gives
     * `claimed_no_key` whenever env HOME is not the trusted home.)
     */
    shellHome?: string | null;
    /** passwd lookup for ~user. */
    userHome?: (user: string) => string | null;
}
export type ExpandedOperand = {
    kind: 'path';
    path: string;
    trailingFollow: boolean;
    nonAscii: boolean;
} | {
    kind: 'glob';
    path: string;
    staticPrefix: string;
    trailingFollow: boolean;
    nonAscii: boolean;
} | {
    kind: 'dynamic';
    reason: 'empty' | 'substitution' | 'brace' | 'variable' | 'tilde' | 'user_home' | 'no_home' | 'no_cwd' | 'glob_parent' | 'backslash' | 'pattern';
};
/**
 * Expands one path operand the way the shell would, using only trusted values.
 * `raw` is the word with quotes removed; any `$` left in it is treated as an
 * expansion, so a literal `$` can only make the answer stricter.
 */
export declare function expandPathOperand(raw: string, context: PathContext): ExpandedOperand;
export type ResolvedOperand = {
    kind: 'path';
    real: string;
    exists: boolean;
    nonAscii: boolean;
}
/**
 * matches: the real path of every name the glob can reach (followed through
 * links where the shell follows them). parents: the real dirs whose
 * children a final wildcard deletes, judged like a static prefix.
 */
 | {
    kind: 'glob';
    staticReal: string;
    matches: string[];
    parents: string[];
    nonAscii: boolean;
} | {
    kind: 'unknown';
    reason: string;
};
/** Bound on directory entries a glob may enumerate; over it the operand is unknown. */
export declare const MAX_GLOB_ENTRIES = 1024;
/**
 * Expands and realpaths one operand. use='read' follows a final symlink (cat
 * reads the target); use='delete' follows it only after a trailing '/' or '/.'.
 */
export declare function resolveOperand(fs: SeatbeltFs, context: PathContext, raw: string, use: 'read' | 'delete'): ResolvedOperand;
export interface Workspace {
    /** False when the event gave no usable cwd: every recursive delete target is then unknown (A19). */
    known: boolean;
    /** Real project roots (git toplevel of the event cwd, or the cwd). Children only. */
    roots: string[];
    /** Real temp roots (/tmp, /var/tmp, a system TMPDIR). Children only. */
    tempRoots: string[];
    home: string | null;
    reason?: 'no_cwd' | 'cwd_unresolved' | 'home_or_ancestor';
}
/** WS from the event cwd (fixes F3: never the hook process's cwd). */
export declare function resolveWorkspace(fs: SeatbeltFs, input: {
    eventCwd: unknown;
    home: string | null;
    tmpdir?: string | null;
}): Workspace;
export type DeleteTargetClass = 'in_workspace' | 'outside_workspace' | 'workspace_root' | 'home' | 'root' | 'unknown';
/** Where a recursive-delete target falls (S5). Only 'in_workspace' is safe. A glob is the worst of its static prefix and every reachable match. */
export declare function classifyDeleteTarget(fs: SeatbeltFs, workspace: Workspace, target: ResolvedOperand): DeleteTargetClass;
//# sourceMappingURL=seatbelt-path.d.ts.map