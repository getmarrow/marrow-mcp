import type { SeatbeltFs } from './seatbelt-fs';
export declare const MAX_GIT_CONFIG_BYTES: number;
export declare const MAX_INCLUDE_DEPTH = 10;
export declare const MAX_ALIAS_DEPTH = 10;
/** Total alias nodes and config files visited: a planted config cannot fan out without bound. */
export declare const MAX_ALIAS_STEPS = 256;
export declare const MAX_CONFIG_FILES = 64;
export interface GitConfigEntry {
    /** section[.subsection].name; section and name lower-cased, subsection as written. */
    key: string;
    value: string;
    source: string;
}
export interface GitConfig {
    entries: GitConfigEntry[];
    /** True when some config could not be read (unreadable file, include too deep): answers that depend on it are unknown. */
    incomplete: boolean;
}
/** Canonical config key: git compares section and variable names case-insensitively, subsections exactly. */
export declare function canonicalGitKey(key: string): string;
/** Parses git config text into entries (git-config(1) syntax). */
export declare function parseGitConfigText(text: string, source: string): GitConfigEntry[];
export interface GitDirs {
    /** The worktree's git dir (HEAD lives here). */
    gitDir: string;
    /** The common dir (config, refs, packed-refs). */
    commonDir: string;
}
/** Finds the git dirs for a working directory: a `.git` directory, or a `.git` file (`gitdir:`) plus `commondir`. */
export declare function discoverGitDirs(fs: SeatbeltFs, cwd: string): GitDirs | null | 'unknown';
export interface GitConfigSources {
    /** Trusted home (passwd or --home), for ~/.gitconfig, ~/.config/git/config and `~/` in include paths. */
    home: string | null;
    dirs?: GitDirs | null;
    /** `git -c key=value` pairs, in order. */
    commandConfig?: Array<[string, string]>;
    /** The hook's own environment merged with same-command assignments (GIT_CONFIG_*). */
    env?: Record<string, string | undefined>;
    /** System config files; default /etc/gitconfig plus common package-manager prefixes. */
    systemFiles?: string[];
}
/**
 * Loads config from every scope git reads, plus every include and includeIf
 * (conditions are not evaluated: including more can only add candidates).
 */
export declare function loadGitConfig(fs: SeatbeltFs, sources: GitConfigSources): GitConfig;
/** Every value of a key across all scopes, in load order (git uses the last). */
export declare function gitConfigValues(config: GitConfig, key: string): string[];
/**
 * Built-ins of every supported git (≥2.20): git runs these before it looks at
 * aliases, so an alias with one of these names never applies.
 */
export declare const GIT_CORE_BUILTINS: Set<string>;
/**
 * Commands that shadow an alias only when present: exec-path programs that may
 * not be installed (git-lfs, git-svn ...) and built-ins newer than 2.20. For
 * these the alias is kept as a candidate next to the command itself.
 */
export declare const GIT_MAYBE_COMMANDS: Set<string>;
/** git's split_cmdline: whitespace-separated words with single/double quotes and backslash escapes. Null on an unclosed quote. */
export declare function splitGitCmdline(value: string): string[] | null;
export interface GitInvocation {
    /** `-c` pairs from the global options. */
    config: Array<[string, string]>;
    /** `-C` directories and `--git-dir`/`--work-tree` values, in order. */
    directories: string[];
    /** Global options seen whose effect is not modelled (or whose value is dynamic). */
    unknownGlobals: string[];
    /** `--config-env` pairs: key and the env var name supplying its value. */
    configEnv: Array<[string, string]>;
    subcommand: string | null;
    args: string[];
}
/** Splits `git <global options> <subcommand> <args>` (git.c handle_options: exact option names only). */
export declare function parseGitInvocation(argv: string[]): GitInvocation;
export type GitExpansion = {
    kind: 'git';
    invocation: GitInvocation;
} | {
    kind: 'shell';
    command: string;
    args: string[];
} | {
    kind: 'unknown';
    reason: 'not_found' | 'loop' | 'too_deep' | 'unparsed' | 'config_incomplete' | 'dynamic_config';
};
/**
 * Expands git aliases the way git would, keeping every candidate: each
 * definition of alias.<name> from any scope or include, and `-c alias.*` from
 * the command. Core built-in names are never expanded (git ignores aliases
 * for them); maybe-installed commands keep both answers. `!` aliases become shell commands with the remaining args appended.
 */
export declare function expandGitAliases(argv: string[], context: {
    config: GitConfig;
    env?: Record<string, string | undefined>;
}): GitExpansion[];
/** Long options of `git push` (builtin/push.c), for prefix abbreviation. */
export declare const GIT_PUSH_LONG_OPTIONS: string[];
/**
 * Every long option a `--name[=value]` argument can mean under git's unique
 * prefix abbreviation. Exact names win; an ambiguous prefix keeps all matches
 * (git would refuse, but the mapper must stop if any match is risky). Negated
 * forms are returned as `no-<name>`.
 */
export declare function gitLongOptionCandidates(arg: string, options?: string[], negatable?: Set<string>): string[];
export type GitHead = {
    kind: 'branch';
    branch: string;
} | {
    kind: 'detached';
} | {
    kind: 'unknown';
};
export declare function readGitHead(fs: SeatbeltFs, dirs: GitDirs): GitHead;
/** The remote's default branch from refs/remotes/<remote>/HEAD; null when absent; 'unknown' when unreadable. */
export declare function readRemoteDefaultBranch(fs: SeatbeltFs, dirs: GitDirs, remote: string): string | null | 'unknown';
export declare const BASELINE_PROTECTED_BRANCHES: string[];
/** PB membership (§1.2). Compared case-insensitively; an unresolved target is protected. */
export declare function isProtectedBranch(branch: string | null, extra?: string[]): boolean;
export interface PushRefspec {
    force: boolean;
    delete: boolean;
    /** Destination branch name, or null when it cannot be resolved locally. */
    destination: string | null;
    /** Refspec names more than one branch (a pattern or a matching `:`). */
    all: boolean;
}
/** Resolves one push refspec's destination against HEAD and the upstream config. */
export declare function resolvePushRefspec(refspec: string, head: GitHead): PushRefspec;
export interface ImplicitPushTargets {
    /** Branch names a remote-only `git push [remote]` may update. */
    branches: string[];
    /** push.default=matching or a pattern refspec: may update any branch. */
    all: boolean;
    /** Some target could not be resolved (detached HEAD, unreadable config). */
    unknown: boolean;
    /** remote.<r>.push has a `+` refspec. */
    forceFromConfig: boolean;
    /** remote.<r>.mirror is set. */
    mirror: boolean;
    /** Every remote this push may go to. */
    remotes: string[];
}
/**
 * Targets of `git push` with no refspec (and optionally no remote), as the
 * union of every config candidate: remote.<r>.push, push.default and the
 * branch's upstream.
 */
export declare function implicitPushTargets(config: GitConfig, head: GitHead, remote: string | null): ImplicitPushTargets;
//# sourceMappingURL=seatbelt-git.d.ts.map