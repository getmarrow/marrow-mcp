/**
 * The MCP servers enabled Codex plugins add, read from the plugin cache the
 * way codex 0.161 lays it out (`codex plugin add` writes
 * `$CODEX_HOME/plugins/cache/<marketplace>/<plugin>/<version>/` and enables
 * `[plugins."<plugin>@<marketplace>"]` in `$CODEX_HOME/config.toml`), and
 * whether a plugin is the official Marrow Codex plugin, proven only by the
 * SHA-256 of every file that decides what its `marrow` server runs.
 *
 * Fail closed: a missing cache, more than one version, a symlink whose real
 * path leaves the cache, a file that is not a regular file, over the size cap
 * or unparsable, an unknown `mcpServers` shape, a plugin file changed after
 * codex started (or no codex process to compare with) means "not proven".
 * Nothing read here is ever logged.
 */
export type PluginServers = {
    id: string;
    official: boolean;
    servers: string[];
};
export type PluginScan = {
    bad: string;
} | {
    bad: null;
    plugins: PluginServers[];
};
export type PluginScanOptions = {
    codexHome: string;
    ids: string[];
    /** Wall-clock start of the codex process (ms), or null when it cannot be found. */
    processStartMs: number | null;
};
/** Every enabled plugin's MCP server names; any doubt is `bad`. */
export declare function scanCodexPlugins(options: PluginScanOptions): PluginScan;
//# sourceMappingURL=codex-plugins.d.ts.map