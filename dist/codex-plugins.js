"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.scanCodexPlugins = scanCodexPlugins;
const node_crypto_1 = require("node:crypto");
const node_fs_1 = require("node:fs");
const node_path_1 = require("node:path");
const own_server_identity_1 = require("./own-server-identity");
const codex_plugin_pins_1 = require("./codex-plugin-pins");
const MAX_PLUGINS = 32;
/** codex keeps whole-second precision in places and the process start is exact to about a second. */
const START_MARGIN_MS = 2_000;
const PLUGIN_ID = /^([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})@([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})$/;
const MANIFESTS = ['.codex-plugin/plugin.json', '.claude-plugin/plugin.json', '.cursor-plugin/plugin.json'];
const DEFAULT_MCP_FILE = '.mcp.json';
function insideRoot(root, real) {
    return real.startsWith(`${root}${node_path_1.sep}`);
}
/** A file inside the plugin version directory: relative, no `..`, real path inside the cache. */
function readPluginFile(at, rel) {
    if (typeof rel !== 'string' || rel.length === 0 || rel.length > 1024 || rel.includes('\0') || (0, node_path_1.isAbsolute)(rel))
        return { state: 'bad' };
    const clean = (0, node_path_1.normalize)(rel);
    if (clean === '..' || clean.startsWith(`..${node_path_1.sep}`) || (0, node_path_1.isAbsolute)(clean))
        return { state: 'bad' };
    const path = (0, node_path_1.join)(at.dir, clean);
    let real;
    try {
        real = (0, node_fs_1.realpathSync)(path);
    }
    catch (error) {
        const code = error?.code;
        return code === 'ENOENT' || code === 'ENOTDIR' ? { state: 'missing' } : { state: 'bad' };
    }
    if (!insideRoot(at.root, real))
        return { state: 'bad' };
    const read = (0, own_server_identity_1.readHostConfigBytes)(real);
    if (read.state !== 'ok')
        return read.state === 'missing' ? { state: 'missing' } : { state: 'bad' };
    try {
        at.newest = Math.max(at.newest, (0, node_fs_1.statSync)(real).mtimeMs, (0, node_fs_1.lstatSync)(path).mtimeMs);
    }
    catch {
        return { state: 'bad' };
    }
    return read;
}
function withoutBom(text) {
    return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}
function plainObject(value) {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}
/** `{ "mcpServers": { name: {...} } }` or a bare `{ name: {...} }` map; anything else is unknown. */
function serverNames(value) {
    if (!plainObject(value))
        return null;
    const keys = Object.keys(value);
    if (keys.includes('mcpServers')) {
        if (keys.length !== 1 || !plainObject(value.mcpServers))
            return null;
        value = value.mcpServers;
    }
    const map = value;
    if (!Object.values(map).every(plainObject))
        return null;
    return Object.keys(map);
}
function parseJson(text) {
    try {
        return JSON.parse(withoutBom(text));
    }
    catch {
        return undefined;
    }
}
function sha256(bytes) {
    return (0, node_crypto_1.createHash)('sha256').update(bytes).digest('hex');
}
/** One enabled plugin's servers, and whether its files are exactly a pinned official release. */
function scanPlugin(cacheRoot, realRoot, id) {
    const match = PLUGIN_ID.exec(id);
    if (!match)
        return 'a Codex plugin id has an unknown form';
    const [, plugin, marketplace] = match;
    const pluginDir = (0, node_path_1.join)(cacheRoot, marketplace, plugin);
    let versions;
    try {
        versions = (0, node_fs_1.readdirSync)(pluginDir);
    }
    catch {
        return 'an enabled Codex plugin is not in the local cache';
    }
    if (versions.length !== 1)
        return versions.length ? 'more than one version of a Codex plugin is cached' : 'an enabled Codex plugin is not in the local cache';
    const dir = (0, node_path_1.join)(pluginDir, versions[0]);
    let realDir;
    try {
        realDir = (0, node_fs_1.realpathSync)(dir);
        if (!(0, node_fs_1.statSync)(realDir).isDirectory())
            return 'a Codex plugin cache entry is not a directory';
    }
    catch {
        return 'a Codex plugin cache entry is unreadable';
    }
    if (!insideRoot(realRoot, realDir))
        return 'a Codex plugin cache entry leaves the cache';
    const at = { root: realRoot, dir, newest: 0 };
    try {
        at.newest = Math.max((0, node_fs_1.lstatSync)(dir).mtimeMs, (0, node_fs_1.statSync)(realDir).mtimeMs);
    }
    catch {
        return 'a Codex plugin cache entry is unreadable';
    }
    const names = new Set();
    const texts = new Map();
    const take = (rel, required) => {
        const read = readPluginFile(at, rel);
        if (read.state === 'missing')
            return required ? 'a Codex plugin file is missing' : null;
        if (read.state === 'bad')
            return 'a Codex plugin file is unreadable, not a regular file, too large or outside the cache';
        texts.set((0, node_path_1.normalize)(rel), read.bytes);
        const parsed = parseJson(read.bytes.toString('utf8'));
        return parsed === undefined ? 'a Codex plugin file does not parse' : { parsed };
    };
    const manifests = [];
    for (const rel of MANIFESTS) {
        const got = take(rel, false);
        if (typeof got === 'string')
            return got;
        if (got === null)
            continue;
        const manifest = got.parsed;
        if (!plainObject(manifest))
            return 'a Codex plugin manifest is not an object';
        manifests.push(manifest);
        const servers = manifest.mcpServers;
        if (servers === undefined)
            continue;
        let found;
        if (typeof servers === 'string') {
            const file = take(servers, true);
            if (typeof file === 'string')
                return file;
            found = serverNames(file.parsed);
        }
        else {
            found = serverNames(servers);
        }
        if (!found)
            return 'a Codex plugin declares MCP servers in an unknown shape';
        for (const name of found)
            names.add(name);
    }
    if (!manifests.length)
        return 'a Codex plugin has no manifest';
    const fallback = take(DEFAULT_MCP_FILE, false);
    if (typeof fallback === 'string')
        return fallback;
    if (fallback !== null) {
        const found = serverNames(fallback.parsed);
        if (!found)
            return 'a Codex plugin declares MCP servers in an unknown shape';
        for (const name of found)
            names.add(name);
    }
    // The official plugin: one codex manifest naming a pinned release, cached under its own version,
    // and every file that decides what its server runs byte-identical to that release.
    let official = false;
    const primary = manifests.length === 1 && texts.has((0, node_path_1.normalize)(MANIFESTS[0])) ? manifests[0] : null;
    const pins = primary && typeof primary.name === 'string' && typeof primary.version === 'string'
        ? codex_plugin_pins_1.OFFICIAL_CODEX_PLUGIN_PINS[`${primary.name}@${primary.version}`]
        : undefined;
    if (pins && (0, node_path_1.basename)(dir) === primary.version) {
        official = Object.entries(pins).every(([rel, digest]) => {
            if (!texts.has((0, node_path_1.normalize)(rel))) {
                const read = readPluginFile(at, rel);
                if (read.state !== 'ok')
                    return false;
                texts.set((0, node_path_1.normalize)(rel), read.bytes);
            }
            return sha256(texts.get((0, node_path_1.normalize)(rel))) === digest;
        });
    }
    return { id, official, servers: [...names], newest: at.newest };
}
/** Every enabled plugin's MCP server names; any doubt is `bad`. */
function scanCodexPlugins(options) {
    if (!options.ids.length)
        return { bad: null, plugins: [] };
    if (options.ids.length > MAX_PLUGINS)
        return { bad: 'too many Codex plugins are enabled' };
    if (options.processStartMs === null || !Number.isFinite(options.processStartMs)) {
        return { bad: 'the codex process start is unknown, so plugin files cannot be dated' };
    }
    const plugins = (0, node_path_1.join)(options.codexHome, 'plugins');
    try {
        const staging = (0, node_fs_1.readdirSync)((0, node_path_1.join)(plugins, '.remote-plugin-install-staging'));
        if (staging.length)
            return { bad: 'a remote Codex plugin install is staged' };
    }
    catch (error) {
        if (error?.code !== 'ENOENT')
            return { bad: 'the Codex plugin staging folder is unreadable' };
    }
    const cacheRoot = (0, node_path_1.join)(plugins, 'cache');
    let realRoot;
    try {
        realRoot = (0, node_fs_1.realpathSync)(cacheRoot);
    }
    catch {
        return { bad: 'the Codex plugin cache is missing' };
    }
    const out = [];
    for (const id of options.ids) {
        const scanned = scanPlugin(cacheRoot, realRoot, id);
        if (typeof scanned === 'string')
            return { bad: scanned };
        const { newest, ...plugin } = scanned;
        if (!(newest < options.processStartMs - START_MARGIN_MS))
            return { bad: 'a Codex plugin changed after codex started' };
        out.push(plugin);
    }
    return { bad: null, plugins: out };
}
//# sourceMappingURL=codex-plugins.js.map