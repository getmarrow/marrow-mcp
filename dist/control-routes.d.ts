/**
 * MCP-10: the visible ways to switch Marrow's local control off or remove it through the installer. A command that runs the installer
 * (`npx @getmarrow/install ...`, `marrow-install ...`, `node .../@getmarrow/install/bin/marrow-install.js ...`) with a `control` word other
 * than `enable`/`status`, with `disable` or `uninstall`, or with any argument the shell expands, is a control-off route. The agent's own
 * `--yes` approves nothing: such a command is labelled `security on marrow-control` and held for the account owner.
 */
export declare const CONTROL_ROUTE_DENY_TEXT = "Turning Marrow control off needs the account owner. Ask them to run it in their own terminal.";
/** Whether the shell text runs the installer in a way that can switch Marrow control off, remove it, or cannot be read as one fixed command. */
export declare function controlRoute(command: string, depth?: number): boolean;
//# sourceMappingURL=control-routes.d.ts.map