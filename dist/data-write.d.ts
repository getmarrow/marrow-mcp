/**
 * MCP-1a: the data-write recognizer (DW) and its tightening T1.
 *
 * `dataWriteOnly` answers true only for a command made of nothing but echo, printf, cat (stdin only), tee and literal
 * assignments, whose every file write lands in a plain notes/log file outside every dot folder. It only ever adds an
 * exemption (classifyAsNamed gives such a command the low-risk `process on workspace` label); when it cannot read the
 * whole command it answers false and the 3.9.108 path runs unchanged. It reads no file contents and never throws.
 */
export type DataWriteContext = {
    /** The call's working folder (absolute) for a relative target. */
    cwd?: string;
    /** The passwd home: `~` and the `$HOME` root of a data file. */
    home?: string | null;
    /** The command already ran (PostToolUse): an existing file is then the file the command wrote, so `>` is not refused for it. */
    postTool?: boolean;
    /** MCP-1b: the home whose `.marrow/data-commands.json` declares owner data commands (default: the process's `$HOME`, as for control.json). */
    dataCommandsHome?: string;
};
/** Whether `command` writes notes/log files only, using nothing but echo, printf, cat, tee and literal assignments. */
export declare function dataWriteOnly(command: string, context?: DataWriteContext): boolean;
/** T1: the deny text for a data file run as a program. */
export declare const DATA_FILE_RUN_DENY_TEXT = "Marrow does not run a notes or log file as a program. Put scripts in a file with a script extension.";
/** T1: true when a plain shell command hands a notes/log file to an interpreter, or names one as its program. */
export declare function runsDataFileAsProgram(command: string): boolean;
//# sourceMappingURL=data-write.d.ts.map