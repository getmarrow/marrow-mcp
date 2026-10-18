"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OFFICIAL_CODEX_PLUGIN_DIRS = exports.OFFICIAL_CODEX_PLUGIN_PINS = void 0;
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
exports.OFFICIAL_CODEX_PLUGIN_PINS = Object.freeze({
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
    // getmarrow/plugins: the Codex plugins pinned to @getmarrow/mcp 3.9.103 (PKG-M4). The 0.1.1 entries above
    // stay so that installs of the older release are still proven, not turned into new friction.
    'marrow@0.1.2': Object.freeze({
        '.codex-plugin/plugin.json': 'd6319939f5548a1708badcf6d11d63221b63ea4b4a3791743e8d0744798e6fe7',
        '.mcp.json': '204c90071832e231d445cf648fbb19e3e157aaa290f1c303b230aeff1d522226',
        'scripts/marrow-launch.cjs': '8362944504f6c4a9f8f5dabb4676e419ee05bdad34ced873fab25454a445dbe4',
        'scripts/mcp-manifest.json': '66841230e61f22f8d3f55563042c336d88afc15c7adaffdbc34f456abe529f42',
        'package.json': '6312b147d5401084355d8319fb211319bffd7329c76ac7108c6fb47a44fdeb40',
        'package-lock.json': 'f2101e3b18d8a46b0c50bcef9f62d51826fce12e8768e81db3e86c6ca54d3dcc',
    }),
    'marrow-advisory@0.1.2': Object.freeze({
        '.codex-plugin/plugin.json': '611c2b52fc04e7d2decef54def41397ba6793b456caa1bc2f94d96e1e87d257c',
        '.mcp.json': '204c90071832e231d445cf648fbb19e3e157aaa290f1c303b230aeff1d522226',
        'scripts/marrow-launch.cjs': '8362944504f6c4a9f8f5dabb4676e419ee05bdad34ced873fab25454a445dbe4',
        'scripts/mcp-manifest.json': '66841230e61f22f8d3f55563042c336d88afc15c7adaffdbc34f456abe529f42',
        'package.json': '57acd62e39d2a78c49df15746bec5fd3ddce52926320fed852f7a3d8e0fc60f1',
        'package-lock.json': '391392ed09701deae97db4edd7aaa92f884361ba47f5b7e6664ad5b4f87f34bb',
    }),
});
/** The plugin folders in the getmarrow/plugins repository, by manifest name. */
exports.OFFICIAL_CODEX_PLUGIN_DIRS = Object.freeze({
    marrow: 'codex/marrow',
    'marrow-advisory': 'codex/marrow-advisory',
});
//# sourceMappingURL=codex-plugin-pins.js.map