/**
 * Whether the `marrow` MCP server a Codex or Cursor hook label names is the
 * official Marrow MCP server. Codex builds its label from the user's server
 * name (servers `mcp__marrow`, `marrow-` and `marrow_` all give
 * `mcp__marrow__<tool>` on codex 0.161), and Cursor's preToolUse label has no
 * server at all, so the label alone never proves the server. The hook reads
 * the host's own MCP configuration and skips the gate only when exactly one
 * configured server can produce the label and it starts the official package.
 *
 * Fail closed: a missing, unreadable, oversized, non-regular or unparsable
 * config, more than one colliding server, an unknown command, a wrapper, an
 * env override, an enabled Codex plugin or a config override on the codex
 * command line means "not proven": the call goes down the normal gate path.
 * Reads are local, size-capped and done at most once per hook process; no
 * config content is ever logged.
 */
export declare const MAX_HOST_CONFIG_BYTES: number;
type OwnToolEvent = {
    tool_name?: unknown;
    tool_input?: unknown;
};
export type ServerIdentity = {
    official: boolean;
    reason: string;
};
export type HostConfigRead = {
    state: 'missing';
} | {
    state: 'bad';
    reason: string;
} | {
    state: 'ok';
    text: string;
};
export type HostConfigReader = (path: string) => HostConfigRead;
/** One config file: missing adds nothing; anything but a readable regular file within the cap is bad. */
export declare function readHostConfigFile(path: string): HostConfigRead;
type TomlTable = Record<string, unknown>;
export declare function parseToml(text: string): TomlTable;
/**
 * Whether (command, args) start the official Marrow MCP server, in one of the
 * exact forms Marrow documents or writes:
 *   npx|npx.cmd [-y|--yes] @getmarrow/mcp[@latest|@X.Y.Z]
 *   npx|npx.cmd [-y|--yes] --package=@getmarrow/mcp[@latest|@X.Y.Z] marrow-mcp
 *   marrow-mcp|marrow-mcp.cmd                      (the installed bin, no args)
 *   /bin/sh -c <installer script> <installer loader> --package=@getmarrow/mcp@V marrow-mcp
 *   node -e <installer loader> -- --package=@getmarrow/mcp@V marrow-mcp
 * Nothing appended, no wrapper, no other package.
 */
export declare function isOfficialMarrowServerLaunch(command: unknown, args: unknown): boolean;
/** A server name a host could turn into the `marrow` label: case, separators and leading `mcp` ignored (wider than any host). */
export declare function serverNameCollidesWithMarrow(name: string): boolean;
/**
 * Codex joins namespace and tool name with `__`, so a server whose namespace
 * trims to `mcp` (`_`, `-`, `__`, `mcp__`, `mcp___`, `MCP__`, and the hashed
 * duplicates of those) plus a tool `marrow__<own>` gives the exact label
 * `mcp__marrow__<own>`. On Codex such a name, or any name outside the plain
 * ASCII form, counts as able to produce the marrow label.
 */
export declare function codexServerNameCanProduceMarrowLabel(name: string): boolean;
export type CodexIdentityOptions = {
    env?: NodeJS.ProcessEnv;
    cwds?: unknown[];
    read?: HostConfigReader;
    /** The codex process argv, or null when it cannot be found. */
    processArgs?: string[] | null;
    /** Test seam: the hook's own working directory (default process.cwd()). */
    processCwd?: string;
    /** The user's home, whose own `.npmrc` is npm's user config (default os.homedir()). */
    userHome?: string;
};
/** Whether the Codex `marrow` server is provably the official Marrow MCP server. */
export declare function codexOfficialMarrowServer(options?: CodexIdentityOptions): ServerIdentity;
export type CursorIdentityOptions = {
    home?: string;
    cwds?: unknown[];
    read?: HostConfigReader;
    onlyServer: boolean;
    processCwd?: string;
    env?: NodeJS.ProcessEnv;
};
/** Whether Cursor's `marrow` server is provably the official one (and, at preToolUse, the only server). */
export declare function cursorOfficialMarrowServer(options: CursorIdentityOptions): ServerIdentity;
/** Test seam: forget the per-process config decision. */
export declare function resetOwnServerIdentityCache(): void;
/**
 * Marrow's own tool on this host, after the server identity check. `event` is
 * the normalised event; `raw` is the host's payload as received (for Cursor's
 * `url` and `workspace_roots`, Codex's `cwd`). Hosts other than Codex and
 * Cursor keep the label rule (isOfficialMarrowMcpEvent) unchanged.
 */
export declare function isOfficialMarrowMcpEventOnHost(harness: string, event: OwnToolEvent, raw?: unknown): boolean;
export {};
//# sourceMappingURL=own-server-identity.d.ts.map