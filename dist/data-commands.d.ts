/**
 * MCP-1b: owner-declared data commands.
 *
 * The owner teaches Marrow, once and in a terminal, that one of their own scripts only handles data (a board tool, a notes tool). The declaration is
 * `~/.marrow/data-commands.json`; a command that is exactly `<argv_prefix> <plain literal words>`, whose script still has the hash the owner saw, is then
 * judged by its effect like a data write (data-write.ts): its remaining words are data, not actions. Everything here fails closed: a file that fails any
 * check is ignored whole, an entry that fails any check never matches, and a segment that is not understood in full is not a match, so the
 * 3.9.109 classification runs byte for byte.
 */
export declare const DATA_COMMANDS_VERSION = 1;
export declare const DATA_COMMANDS_DIRECTORY = ".marrow";
export declare const DATA_COMMANDS_FILENAME = "data-commands.json";
export declare const DATA_COMMANDS_MAX_BYTES = 4096;
export declare const DATA_COMMANDS_MAX_ENTRIES = 20;
export declare const DATA_COMMANDS_MAX_SCRIPT_BYTES: number;
export type DataCommandEntry = {
    argv_prefix: string[];
    sha256: string;
};
export type DataCommandsFile = {
    present: boolean;
    entries: DataCommandEntry[];
    ignored: string | null;
};
/** One word of a parsed segment, as data-write.ts reads it: the text after quote removal and what the reader had to expand to get it. */
export type DeclaredWord = {
    text: string;
    date: boolean;
    expands: boolean;
    dollar: boolean;
    escaped: boolean;
    tilde: boolean;
};
export declare function dataCommandsPath(home?: string): string;
/**
 * The declaration file, read with the checks control.json gets (control-state.ts): the folder is a real folder of mode 700 and the file a regular file of
 * mode 600, both owned by this user, no link on either, at most 4 KB, exact schema, at most 20 entries. Any failure ignores the whole file and says why in one line.
 */
export declare function readDataCommands(options?: {
    home?: string;
    uid?: number;
}): DataCommandsFile;
/** Why `prefix` can never be an entry (no file is looked at), or null. The one path word is the script; an interpreter may only run that script directly. */
export declare function entryProblem(prefix: readonly string[]): string | null;
/**
 * Whether the words of one segment (program first) are an owner-declared data command: the first words equal an entry's argv_prefix, the script word
 * names the declared file with no link on the way, the script's hash now is the entry's, and every word after the prefix is a plain literal (no `$`,
 * backtick, glob, brace, `~`, backslash or substitution). Never throws; any doubt is false.
 */
export declare function declaredCommandMatch(words: readonly DeclaredWord[], options?: {
    cwd?: string;
    home?: string;
}): boolean;
/** One line for status and doctor: whether a declaration is in force and, when the file is ignored, why. No hash and no path. */
export declare function dataCommandsEvidence(options?: {
    home?: string;
    uid?: number;
}): {
    state: 'none' | 'active' | 'ignored';
    entries: number;
    usable: number;
    reason: string | null;
};
export type DataCommandsIo = {
    /** Whether stdin, stdout and stderr are each a terminal. */
    isTTY: [boolean, boolean, boolean];
    readLine: () => string | null;
    write: (text: string) => void;
    writeErr: (text: string) => void;
    random?: () => string;
    home?: string;
    uid?: number;
};
export declare const DATA_COMMANDS_USAGE: string;
/** Runs `marrow-mcp data-commands ...` and returns the exit code: 0 done, 1 failed or cancelled, 2 refused (no terminal), 64 usage. */
export declare function runDataCommands(args: string[], io?: DataCommandsIo): number;
//# sourceMappingURL=data-commands.d.ts.map