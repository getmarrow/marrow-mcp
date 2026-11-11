/**
 * MCP-10: the visible ways to switch Marrow's local control off or remove it through the installer. A command that runs the installer
 * (`npx @getmarrow/install ...`, `marrow-install ...`, `node .../@getmarrow/install/bin/marrow-install.js ...`) with a `control` word other
 * than `enable`/`status`, with `disable` or `uninstall`, or with any argument the shell expands, is a control-off route. The agent's own
 * `--yes` approves nothing: such a command is labelled `security on marrow-control` and held for the account owner.
 */
export declare const CONTROL_ROUTE_DENY_TEXT = "Turning Marrow control off needs the account owner. Ask them to run it in their own terminal.";
export declare const CONTROL_ROUTE_ASK_TEXT = "Marrow: this would switch Marrow control off or change its hooks. Approve it only if you, the account owner, want that.";
/** Whether a wrapper option takes the next word as its argument (T1). */
export declare function wrapperOptionTakesValue(wrapper: string, option: string): boolean;
/** Whether the shell text can switch Marrow control off or remove it (installer, marrow-mcp, MARROW_AUTO_HOOK), or cannot be read as one fixed
 * command: text naming them that the parser cannot read, that nests deeper than 3 or that spends the time budget is held (T1). */
export declare function controlRoute(command: string, depth?: number, deadline?: number): boolean;
//# sourceMappingURL=control-routes.d.ts.map