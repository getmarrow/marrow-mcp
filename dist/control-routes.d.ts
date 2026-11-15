/**
 * MCP-10: the visible ways to switch Marrow's local control off or remove it through the installer. A command that runs the installer
 * (`npx @getmarrow/install ...`, `marrow-install ...`, `node .../@getmarrow/install/bin/marrow-install.js ...`) with a `control` word other
 * than `enable`/`status`, with `disable` or `uninstall`, or with any argument the shell expands, is a control-off route. The agent's own
 * `--yes` approves nothing: such a command is labelled `security on marrow-control` and held for the account owner.
 * CL-5: only a command in a position that runs counts (the program word, a runner's package or file argument, the code of `-c`, `eval`,
 * `$( )` or backticks); the installer's name in a data operand, a folder name or a message is not a route.
 */
export declare const CONTROL_ROUTE_DENY_TEXT = "Turning Marrow control off needs the account owner. Ask them to run it in their own terminal.";
/**
 * S4 PROVEN-DATA (LOWER-SHAPES r4, C0-C6, C8): whether the strict reader proves every command of the whole text, at every depth, is a
 * data program with data arguments and data-only write targets. Any doubt, any unread byte or any throw is false (the c5af0d83 answer).
 */
export declare function provenDataText(text: string): boolean;
/**
 * Whether the shell text runs the installer in a way that can switch Marrow control off, remove it, or cannot be read as one fixed command.
 * `proven` (round 4, S4): a route stands unless it proves the whole text is data; a throw in it keeps the route (the c5af0d83 answer).
 */
export declare function controlRoute(command: string, depth?: number, proven?: (text: string) => boolean): boolean;
/** Whether a text holds a gate receipt's host-approval or approval-link path (any case, `%2F`, doubled slashes). */
export declare function approvalReportUrl(text: string): boolean;
/**
 * M-SELF-APPROVE (g): a shell text that reports an approval for a gate receipt: a request client or an interpreter (its code,
 * a here-doc or piped stdin) in a text that holds the approval path, or a run of a host-report or approval-link script as the
 * program or an interpreter's script. A grep, a printf, a cat or a commit message that only names it is not one.
 */
export declare function selfApproveRoute(command: string): boolean;
//# sourceMappingURL=control-routes.d.ts.map