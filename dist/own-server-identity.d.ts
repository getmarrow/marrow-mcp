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
 * env override, an enabled Codex plugin, a config override on the codex
 * command line, or an installer launch that is not exactly the one that
 * started this hook (another version or pack integrity) means "not proven":
 * the call goes down the normal gate path.
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
/** The same bounded read, as raw bytes (for content pins); `maxBytes` is the size cap. */
export declare function readHostConfigBytes(path: string, maxBytes?: number): {
    state: 'missing';
} | {
    state: 'bad';
    reason: string;
} | {
    state: 'ok';
    bytes: Buffer;
};
type TomlTable = Record<string, unknown>;
export declare function parseToml(text: string): TomlTable;
/**
 * Whether (command, args) start the official Marrow MCP server, in one of the
 * exact forms Marrow documents or writes:
 *   npx [-y|--yes] @getmarrow/mcp[@latest|@X.Y.Z]
 *   npx [-y|--yes] --package=@getmarrow/mcp[@latest|@X.Y.Z] marrow-mcp
 *   marrow-mcp                                     (the installed bin, no args)
 * (npx.cmd and marrow-mcp.cmd only on Windows)
 *   /bin/sh -c <installer script> <installer loader> --package=@getmarrow/mcp@V marrow-mcp
 *   node -e <installer loader> -- --package=@getmarrow/mcp@V marrow-mcp
 * Nothing appended, no wrapper, no other package.
 *
 * An installer form is proven only as this process's own launch: V is the
 * version of the installer launcher that started this process (`ownLoader`,
 * default `global.MARROW_L`) and the loader decodes to exactly its bytes, so
 * the version, the pack integrity, the SDK pin and the core are all its own.
 * Another version or integrity, or a hook not started by an installer loader,
 * proves no installer form.
 */
export declare function isOfficialMarrowServerLaunch(command: unknown, args: unknown, ownLoader?: unknown): boolean;
/**
 * The forms isOfficialMarrowServerLaunch lists, with an installer form of any
 * one version throughout (any pack integrity). For recognizing installer-written
 * hooks (setup, doctor); it never proves a server.
 */
export declare function isMarrowServerLaunchShape(command: unknown, args: unknown): boolean;
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
/**
 * Whether the text of a project npm config file only sets keys on the list
 * above (or the default registry's credential fields), so it cannot change
 * what `npx -y @getmarrow/mcp` gets or runs. It reads like npm's ini reader
 * where that is exact, and answers false for anything it does not understand:
 * a section header, a line without `=`, a line ending in a backslash (a
 * continuation in other ini dialects), a quoted or bracketed key, a key with
 * a comment mark, `${…}` or any non-ASCII character in it, a lone CR (npm
 * splits lines there, other readers do not), a control character or Unicode
 * line separator anywhere, a BOM, a key that is not listed
 * (so `registry`, any `@scope:registry`, any other `//host/:…`, `cache`,
 * `proxy`, `cafile`, `node-options` and every other key). Comments (`;`, `#`)
 * and blank lines are ignored. The last `engine-strict` line wins and must be
 * `true` or `false`.
 */
export declare function npmProjectConfigIsHarmless(text: string): boolean;
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
    /** Wall-clock start of the codex process (ms), or null when it cannot be found. */
    processStartMs?: number | null;
    /** The installer launcher that started this hook (default `global.MARROW_L`; null: none). */
    ownLoader?: unknown;
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
    /** The installer launcher that started this hook (default `global.MARROW_L`; null: none). */
    ownLoader?: unknown;
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