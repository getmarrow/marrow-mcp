/**
 * SHA-256 of every file that decides what the official Marrow Codex plugin's
 * `marrow` MCP server runs, per released plugin (`<manifest name>@<manifest
 * version>`), from github.com/getmarrow/plugins:
 *   .codex-plugin/plugin.json   the manifest (names `.mcp.json`)
 *   .mcp.json                   `node ./scripts/marrow-launch.cjs mcp`
 *   scripts/marrow-launch.cjs   the launcher
 *   scripts/mcp-manifest.json   the launcher's pinned @getmarrow/mcp file list and digest
 *   package.json                the launcher reads the @getmarrow/mcp pin from it
 *   package-lock.json           the launcher's `npm ci` source
 * A plugin release is proven only after its pins are added here and that
 * @getmarrow/mcp is published; until then it fails closed (its own tools are
 * checked like any other server's). `node scripts/codex-plugin-pins-check.cjs
 * <plugins checkout>` recomputes these from a checkout.
 */
export declare const OFFICIAL_CODEX_PLUGIN_PINS: Readonly<Record<string, Readonly<Record<string, string>>>>;
/** The plugin folders in the getmarrow/plugins repository, by manifest name. */
export declare const OFFICIAL_CODEX_PLUGIN_DIRS: Readonly<Record<string, string>>;
//# sourceMappingURL=codex-plugin-pins.d.ts.map