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
    // getmarrow/plugins release/codex-0.1.3: the two Codex plugins pinned to @getmarrow/mcp 3.9.107.
    // The 0.1.1 entries stay so older installs stay proven; the 0.1.2 drafts were never shipped.
    'marrow@0.1.3': Object.freeze({
        '.codex-plugin/plugin.json': '6c772bfff5cdc4ce78072cda02de8639ed24e6c82347ee0273545dba329bc77e',
        '.mcp.json': '204c90071832e231d445cf648fbb19e3e157aaa290f1c303b230aeff1d522226',
        'scripts/marrow-launch.cjs': '8362944504f6c4a9f8f5dabb4676e419ee05bdad34ced873fab25454a445dbe4',
        'scripts/mcp-manifest.json': '9580d83df88010a2575e08ce5c59121cb2b1363578baeb2a68bb6abf75de2240',
        'package.json': '992754b4809addb2f19de3bc81ef87caf77ae97b14f0a8da73669b21b8a7559d',
        'package-lock.json': '70a87cedeb0b099d32245327492e3a5ba4e73a7af24af68d2ce6053cfd51cb07',
    }),
    'marrow-advisory@0.1.3': Object.freeze({
        '.codex-plugin/plugin.json': '5464bc5d38a49bfbbe5794aeb2d7248d47695af912c52eb6037cc0f08a780942',
        '.mcp.json': '204c90071832e231d445cf648fbb19e3e157aaa290f1c303b230aeff1d522226',
        'scripts/marrow-launch.cjs': '8362944504f6c4a9f8f5dabb4676e419ee05bdad34ced873fab25454a445dbe4',
        'scripts/mcp-manifest.json': '9580d83df88010a2575e08ce5c59121cb2b1363578baeb2a68bb6abf75de2240',
        'package.json': '968531e5de020e9dd32b1108dd78ee6e05bd93dde9f431087fdd069f47d95175',
        'package-lock.json': '8c3baacb067c5c6d7a0f2cb64f3de97d8a19e7e746b12c8d8e6625b399415d7f',
    }),
});
/** The plugin folders in the getmarrow/plugins repository, by manifest name. */
exports.OFFICIAL_CODEX_PLUGIN_DIRS = Object.freeze({
    marrow: 'codex/marrow',
    'marrow-advisory': 'codex/marrow-advisory',
});
//# sourceMappingURL=codex-plugin-pins.js.map