import type { SeatbeltFs } from './seatbelt-fs';
export declare const MAX_SCRIPT_BYTES: number;
export declare const MAX_MANIFEST_BYTES: number;
export declare const MAX_MAKE_DEPTH = 3;
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
 * (depth ≤3) and `$(VAR)`/`${VAR}` from simple assignments or the command
 * line. `include`, conditionals, pattern rules or an unknown variable make
 * the answer dynamic, which the mapper treats like an unknown script.
 */
export declare function resolveMakeTargets(fs: SeatbeltFs, dir: string, targets: string[], options?: {
    makefile?: string;
    overrides?: Record<string, string>;
}): MakeResolution;
export type ScriptFile = {
    status: 'ok';
    path: string;
    interpreter: 'shell' | 'other';
    text: string;
} | {
    status: 'absent';
} | {
    status: 'unknown';
    reason: 'unreadable' | 'too_large' | 'not_file';
};
/** A script file run as `./x.sh` or `bash x.sh` (≤64 KB), realpath-ed; the interpreter comes from the shebang. */
export declare function readScriptFile(fs: SeatbeltFs, path: string): ScriptFile;
//# sourceMappingURL=seatbelt-scripts.d.ts.map