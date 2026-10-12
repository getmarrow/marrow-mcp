import type { SeatbeltFs } from './seatbelt-fs';
export declare const MAX_SCRIPT_BYTES: number;
export declare const MAX_MANIFEST_BYTES: number;
export declare const MAX_MAKE_DEPTH = 3;
/** Parse budgets: over any of them the Makefile is 'unknown' (time and memory stay linear in its size). */
export declare const MAX_MAKE_TARGETS_PER_RULE = 256;
export declare const MAX_MAKE_PREREQUISITES = 4096;
export declare const MAX_MAKE_RULES = 4096;
export declare const MAX_MAKE_RECIPE_LINES = 16384;
export declare const MAX_MAKE_COMMANDS = 1024;
export declare const MAX_MAKE_EXPANDED_BYTES: number;
export type PackageScripts = {
    status: 'ok';
    packageDir: string;
    commands: Array<{
        name: string;
        command: string;
    }>;
} | {
    status: 'absent';
} | {
    status: 'unknown';
    reason: string;
};
/**
 * The commands `npm|pnpm|yarn|bun run <name>` executes: pre<name>, <name>,
 * post<name>, from the nearest package.json at or above dir (npm's prefix).
 * A missing script is 'absent' (the runner fails); a malformed manifest is unknown.
 */
export declare function resolvePackageScript(fs: SeatbeltFs, dir: string, name: string): PackageScripts;
/** Lifecycle scripts `npm publish` runs (S3 "lifecycle prepublish*"). */
export declare const PUBLISH_LIFECYCLE: string[];
export declare function packageCommands(fs: SeatbeltFs, dir: string, names: string[]): PackageScripts;
export type MakeResolution = {
    status: 'ok';
    makefile: string;
    commands: string[];
    dynamic: boolean;
} | {
    status: 'absent';
} | {
    status: 'unknown';
    reason: string;
};
/**
 * A simple Makefile recipe parse: explicit rules, recipe lines, prerequisites
 * (depth ≤3) and variable references. Expansion follows GNU make: `=` is
 * deferred, `:=`/`::=` are expanded when read, `?=` and `+=` need the prior
 * value (the environment, when `options.env` is not given, is unknown), target
 * names and prerequisites are expanded when the rule line is read and split
 * into words, recipes after the whole file is read. `$(MAKE) <targets>` in a
 * recipe is followed in the same file. `include`, conditionals, pattern or
 * suffix rules, functions (`$(shell …)`), target-specific variables, variables
 * that change the shell, or an unknown variable make the answer dynamic, which
 * the mapper treats like an unknown script.
 *
 * `options.env` is the environment make would run in (the hook's, plus the
 * command's prefix assignments). A caller MUST pass it: with it omitted every
 * answer is dynamic, because MAKEFLAGS/MAKEFILES, `?=` and the names make
 * exports to recipes all depend on it.
 *
 * Allowlist: an answer is definite only when none of these holds, each of which
 * makes make run something the file does not say, or run it differently:
 * `options.env` omitted, holding a non-string, MAKEFLAGS-like names, shell
 * start-up / loader / git-relocating names, or a PATH entry that is relative,
 * non-canonical or inside the makefile's directory; an assignment (file or
 * command line) to a dot-name, an execution variable, a name make hands to
 * recipes (MAKE_RECIPE_ENV_DENY) or a name in the environment; `export`,
 * `unexport`, `.EXPORT_ALL_VARIABLES`; `?=`/`+=` on a variable make defines
 * itself; a command-line value with `$` or a control character, or a
 * command-line name no expansion reaches; an assignment the command line overrides
 * (make still reads it) that is `!=` or has a right side not proven inert; a recipe-less target that is not
 * .PHONY and could have a source file (built-in rules); a rule for the makefile
 * itself; two recipes for one target. A Makefile with a NUL byte, or a CR that
 * does not end a CRLF, is `unknown` (control_character). The mapper must re-classify `commands`.
 */
export declare function resolveMakeTargets(fs: SeatbeltFs, dir: string, targets: string[], options?: {
    makefile?: string;
    overrides?: Record<string, string>;
    env?: Record<string, string | undefined>;
}): MakeResolution;
export type ScriptFile = {
    status: 'ok';
    path: string;
    interpreter: 'shell' | 'other';
    text: string;
    /**
     * Set when the shebang line itself carries a command (`#!/bin/bash -c "…"`,
     * `#!/usr/bin/env -S sh -c "…"`): that string is what runs, and the file
     * body is only `$0`. The interpreter is then 'other', so a caller that
     * scans the raw text still sees the shebang line.
     */
    shebangCommand?: string;
} | {
    status: 'absent';
} | {
    status: 'unknown';
    reason: 'unreadable' | 'too_large' | 'not_file' | 'shebang';
};
/**
 * A script file run as `./x.sh` or `bash x.sh` (≤64 KB), realpath-ed; the
 * interpreter comes from the shebang, which is the first line up to `\n` only.
 * With no shebang the kernel fails the exec and the invoking shell runs the file
 * as a sh script, unless its first line carries binary magic (control characters).
 */
export declare function readScriptFile(fs: SeatbeltFs, path: string): ScriptFile;
//# sourceMappingURL=seatbelt-scripts.d.ts.map