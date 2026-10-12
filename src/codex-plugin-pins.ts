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
export const OFFICIAL_CODEX_PLUGIN_PINS: Readonly<Record<string, Readonly<Record<string, string>>>> = Object.freeze({
  // getmarrow/plugins master b446393
  'marrow@0.1.1': Object.freeze({
    '.codex-plugin/plugin.json': '57de0165c3f271a8367cf224cb88a2a5fce1effef87c2e0839db69cf303d0f58',
    '.mcp.json': '204c90071832e231d445cf648fbb19e3e157aaa290f1c303b230aeff1d522226',
    'scripts/marrow-launch.cjs': '8362944504f6c4a9f8f5dabb4676e419ee05bdad34ced873fab25454a445dbe4',
    'scripts/mcp-manifest.json': 'd3e795e980d68b3f232a4f5e22c3a244d9bac4209fa6ce7b47190204ef65da3e',
    'package.json': '30bc5ec15d58486aa62ed1e0d5a64e115f3619c0739f88918afb281237510447',
    'package-lock.json': 'd9e3d77a7583e7ee438ddc7294fa9090b8d7cf9fc7da9063e66555b39bb75e6e',
  }),
  'marrow-advisory@0.1.1': Object.freeze({
    '.codex-plugin/plugin.json': '03dcda2b35b4e6f0790e69a5a3d324fcab3b447387d1e8683f619bb24c1ac30a',
    '.mcp.json': '204c90071832e231d445cf648fbb19e3e157aaa290f1c303b230aeff1d522226',
    'scripts/marrow-launch.cjs': '8362944504f6c4a9f8f5dabb4676e419ee05bdad34ced873fab25454a445dbe4',
    'scripts/mcp-manifest.json': 'd3e795e980d68b3f232a4f5e22c3a244d9bac4209fa6ce7b47190204ef65da3e',
    'package.json': '7ebeb726b358874e1ecb69bc9bafcb4ec7d5b6ec1fb703af659eb5655680be55',
    'package-lock.json': '266f078eebff4d54fe78431cc84a8d50b7aae972ef15b81592f377823ea47101',
  }),
});

/** The plugin folders in the getmarrow/plugins repository, by manifest name. */
export const OFFICIAL_CODEX_PLUGIN_DIRS: Readonly<Record<string, string>> = Object.freeze({
  marrow: 'codex/marrow',
  'marrow-advisory': 'codex/marrow-advisory',
});
