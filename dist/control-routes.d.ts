/**
 * MCP-10: the visible ways to switch Marrow's local control off or remove it through the installer. A command that runs the installer
 * (`npx @getmarrow/install ...`, `marrow-install ...`, `node .../@getmarrow/install/bin/marrow-install.js ...`) with a `control` word other
 * than `enable`/`status`, with `disable` or `uninstall`, or with any argument the shell expands, is a control-off route. The agent's own
 * `--yes` approves nothing: such a command is labelled `security on marrow-control` and held for the account owner.
 *
 * MCP-0: the same answer inside every shell construct that runs a command: a loop, an if or case arm, eval, a function or alias body, a wrapper
 * (sudo, env -S, timeout, xargs, find -exec, nohup, nice ...) and a shell fed text (`-c`, a pipe, a file written in the same chain). The text is also
 * read after the shell takes its quoting off (quotes, backslashes, ANSI-C `$'\x69'`), with Unicode
 * compatibility forms folded, invisible characters removed and look-alike letters read as the letters they imitate: such a spelling is a hold, never a pass.
 * `controlRouteVerdict` says more than yes or no, so the seatbelt mapper's own hit (hook-pre-action.ts) can be weighed against what the walk could read.
 */
export declare const CONTROL_ROUTE_DENY_TEXT = "Turning Marrow control off needs the account owner. Ask them to run it in their own terminal.";
/** The text with the shell's quoting taken off: `'..'`, `".."`, a backslash, a line continuation and an ANSI-C `$'\x69'` read as the characters they give. */
export declare function unquoteShell(text: string): string;
/** Compatibility forms folded (NFKC) and invisible characters removed. */
export declare function foldText(text: string): string;
/** The ways the text can be read: as written, folded, unquoted, and each with look-alike letters read as the letters they imitate. */
export declare function controlTextViews(command: string): string[];
/** Whether any reading of the text names the installer (`@getmarrow/install`, `marrow-install`). */
export declare function namesInstaller(command: string): boolean;
/** Whether any reading of the text names the installer or a control-off word (`disable`, `uninstall`). */
export declare function namesControlOff(views: string[]): boolean;
export type ControlVerdict = 'route' | 'cleared' | 'unread' | 'none';
/**
 * What the walk makes of the shell text. `route`: it runs the installer in a way that can switch control off, remove it, or cannot be read as one fixed command.
 * `cleared`: it names the installer and every part that does was read and is no route (`doctor`, `setup`, `control status`, a message that names it).
 * `unread`: it names the installer and a part of it could not be read. `none`: no reading of it names the installer.
 */
export declare function controlRouteVerdict(command: string, depth?: number): ControlVerdict;
/** Whether the shell text runs the installer in a way that can switch Marrow control off, remove it, or cannot be read as one fixed command. */
export declare function controlRoute(command: string, depth?: number): boolean;
//# sourceMappingURL=control-routes.d.ts.map