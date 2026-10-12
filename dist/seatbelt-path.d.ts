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
    /** Assignments made earlier in the same command (`DIR=x rm -rf "$DIR"`). */
    assignments?: Record<string, string>;
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
    nonAscii: boolean;
} | {
    kind: 'dynamic';
    reason: 'empty' | 'substitution' | 'brace' | 'variable' | 'tilde' | 'user_home' | 'no_home' | 'no_cwd' | 'glob_parent';
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
} | {
    kind: 'glob';
    staticReal: string;
    nonAscii: boolean;
} | {
    kind: 'unknown';
    reason: string;
};
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
/** Where a recursive-delete target falls (S5). Only 'in_workspace' is safe. */
export declare function classifyDeleteTarget(fs: SeatbeltFs, workspace: Workspace, target: ResolvedOperand): DeleteTargetClass;
//# sourceMappingURL=seatbelt-path.d.ts.map