/** CL-6 client: the exact text of the local script a Claude Code Bash call runs, for the backend to judge. Data only, never a verdict; any doubt
 * attaches nothing (the backend keeps master's answer for that run). Pure apart from the injected reader; nothing is cached, logged or written.
 * Only the first script run is read, only when nothing before it can write a file, and with its local imports or not at all. */
export declare const SCRIPT_LIMITS: {
    readonly entryBytes: 65536;
    readonly totalBytes: 262144;
    readonly entries: 8;
    readonly textBytes: 8192;
    readonly budgetMs: 250;
    readonly depth: 3;
};
export type ScriptKind = 'file' | 'pkg_script' | 'make_recipe' | 'import';
export interface ScriptEntry {
    operand: string;
    kind: ScriptKind;
    sha256: string;
    content: string;
}
export type ScriptAttachments = {
    scripts: ScriptEntry[];
} | {
    none: string;
};
type Lstat = {
    type: 'file' | 'dir' | 'symlink' | 'other';
    size: number;
    nlink: number;
} | null;
/** realpath and lstat: null when missing. read: a regular file's bytes without following a final link; null when not one or over maxBytes. */
export interface ScriptReader {
    realpath(path: string): string | null;
    lstat(path: string): Lstat;
    read(path: string, maxBytes: number): Uint8Array | null;
    now?(): number;
}
export declare function scriptAttachments(commandText: string, cwd: string, home: string, reader: ScriptReader): ScriptAttachments;
/** The host file system for scriptAttachments: realpath, lstat and a no-follow, size-capped read. */
export declare function nodeScriptReader(): ScriptReader;
/** C1: the runtime action gains `scripts` only when it already carries the 3A text; otherwise it is returned as it is. */
export declare function withScripts<T extends {
    tool_input?: unknown;
}>(action: T, attached: ScriptAttachments): T;
/** C4: the hold, approval and seatbelt sites carry only `scripts_sha256`, the sorted content hashes. */
export declare function withScriptsSha256<T extends {
    tool_input?: unknown;
}>(action: T, attached: ScriptAttachments): T;
/** C6: a server that rejects the `scripts` key (400 or 422) gets the SAME call once more without it; nothing is cached. */
export declare function runtimeWithScripts<T extends {
    tool_input?: unknown;
}, R>(action: T, attached: ScriptAttachments, send: (body: T) => Promise<R>): Promise<R>;
export {};
//# sourceMappingURL=script-attach.d.ts.map