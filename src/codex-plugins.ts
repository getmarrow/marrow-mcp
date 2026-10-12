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

import { createHash } from 'node:crypto';
import { lstatSync, readdirSync, realpathSync, statSync } from 'node:fs';
import { basename, isAbsolute, join, normalize, sep } from 'node:path';
import { readHostConfigBytes } from './own-server-identity';
import { OFFICIAL_CODEX_PLUGIN_PINS } from './codex-plugin-pins';

const MAX_PLUGINS = 32;
/** codex keeps whole-second precision in places and the process start is exact to about a second. */
const START_MARGIN_MS = 2_000;
const PLUGIN_ID = /^([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})@([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})$/;
const MANIFESTS = ['.codex-plugin/plugin.json', '.claude-plugin/plugin.json', '.cursor-plugin/plugin.json'];
const DEFAULT_MCP_FILE = '.mcp.json';

export type PluginServers = { id: string; official: boolean; servers: string[] };
export type PluginScan = { bad: string } | { bad: null; plugins: PluginServers[] };

type Dir = { root: string; dir: string; newest: number };

function insideRoot(root: string, real: string): boolean {
  return real.startsWith(`${root}${sep}`);
}

/** A file inside the plugin version directory: relative, no `..`, real path inside the cache. */
function readPluginFile(at: Dir, rel: string): { state: 'missing' } | { state: 'bad' } | { state: 'ok'; bytes: Buffer } {
  if (typeof rel !== 'string' || rel.length === 0 || rel.length > 1024 || rel.includes('\0') || isAbsolute(rel)) return { state: 'bad' };
  const clean = normalize(rel);
  if (clean === '..' || clean.startsWith(`..${sep}`) || isAbsolute(clean)) return { state: 'bad' };
  const path = join(at.dir, clean);
  let real: string;
  try {
    real = realpathSync(path);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException)?.code;
    return code === 'ENOENT' || code === 'ENOTDIR' ? { state: 'missing' } : { state: 'bad' };
  }
  if (!insideRoot(at.root, real)) return { state: 'bad' };
  const read = readHostConfigBytes(real);
  if (read.state !== 'ok') return read.state === 'missing' ? { state: 'missing' } : { state: 'bad' };
  try {
    at.newest = Math.max(at.newest, statSync(real).mtimeMs, lstatSync(path).mtimeMs);
  } catch {
    return { state: 'bad' };
  }
  return read;
}

function withoutBom(text: string): string {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

function plainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

/** `{ "mcpServers": { name: {...} } }` or a bare `{ name: {...} }` map; anything else is unknown. */
function serverNames(value: unknown): string[] | null {
  if (!plainObject(value)) return null;
  const keys = Object.keys(value);
  if (keys.includes('mcpServers')) {
    if (keys.length !== 1 || !plainObject(value.mcpServers)) return null;
    value = value.mcpServers;
  }
  const map = value as Record<string, unknown>;
  if (!Object.values(map).every(plainObject)) return null;
  return Object.keys(map);
}

function parseJson(text: string): unknown {
  try { return JSON.parse(withoutBom(text)); } catch { return undefined; }
}

function sha256(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/** One enabled plugin's servers, and whether its files are exactly a pinned official release. */
function scanPlugin(cacheRoot: string, realRoot: string, id: string): PluginServers | string {
  const match = PLUGIN_ID.exec(id);
  if (!match) return 'a Codex plugin id has an unknown form';
  const [, plugin, marketplace] = match;
  const pluginDir = join(cacheRoot, marketplace, plugin);
  let versions: string[];
  try {
    versions = readdirSync(pluginDir);
  } catch {
    return 'an enabled Codex plugin is not in the local cache';
  }
  if (versions.length !== 1) return versions.length ? 'more than one version of a Codex plugin is cached' : 'an enabled Codex plugin is not in the local cache';
  const dir = join(pluginDir, versions[0]);
  let realDir: string;
  try {
    realDir = realpathSync(dir);
    if (!statSync(realDir).isDirectory()) return 'a Codex plugin cache entry is not a directory';
  } catch {
    return 'a Codex plugin cache entry is unreadable';
  }
  if (!insideRoot(realRoot, realDir)) return 'a Codex plugin cache entry leaves the cache';
  const at: Dir = { root: realRoot, dir, newest: 0 };
  try { at.newest = Math.max(lstatSync(dir).mtimeMs, statSync(realDir).mtimeMs); } catch { return 'a Codex plugin cache entry is unreadable'; }

  const names = new Set<string>();
  const texts = new Map<string, Buffer>();
  const take = (rel: string, required: boolean): unknown | null | string => {
    const read = readPluginFile(at, rel);
    if (read.state === 'missing') return required ? 'a Codex plugin file is missing' : null;
    if (read.state === 'bad') return 'a Codex plugin file is unreadable, not a regular file, too large or outside the cache';
    texts.set(normalize(rel), read.bytes);
    const parsed = parseJson(read.bytes.toString('utf8'));
    return parsed === undefined ? 'a Codex plugin file does not parse' : { parsed };
  };
  const manifests: Record<string, unknown>[] = [];
  for (const rel of MANIFESTS) {
    const got = take(rel, false);
    if (typeof got === 'string') return got;
    if (got === null) continue;
    const manifest = (got as { parsed: unknown }).parsed;
    if (!plainObject(manifest)) return 'a Codex plugin manifest is not an object';
    manifests.push(manifest);
    const servers = manifest.mcpServers;
    if (servers === undefined) continue;
    let found: string[] | null;
    if (typeof servers === 'string') {
      const file = take(servers, true);
      if (typeof file === 'string') return file;
      found = serverNames((file as { parsed: unknown }).parsed);
    } else {
      found = serverNames(servers);
    }
    if (!found) return 'a Codex plugin declares MCP servers in an unknown shape';
    for (const name of found) names.add(name);
  }
  if (!manifests.length) return 'a Codex plugin has no manifest';
  const fallback = take(DEFAULT_MCP_FILE, false);
  if (typeof fallback === 'string') return fallback;
  if (fallback !== null) {
    const found = serverNames((fallback as { parsed: unknown }).parsed);
    if (!found) return 'a Codex plugin declares MCP servers in an unknown shape';
    for (const name of found) names.add(name);
  }

  // The official plugin: one codex manifest naming a pinned release, cached under its own version,
  // and every file that decides what its server runs byte-identical to that release.
  let official = false;
  const primary = manifests.length === 1 && texts.has(normalize(MANIFESTS[0])) ? manifests[0] : null;
  const pins = primary && typeof primary.name === 'string' && typeof primary.version === 'string'
    ? OFFICIAL_CODEX_PLUGIN_PINS[`${primary.name}@${primary.version}`]
    : undefined;
  if (pins && basename(dir) === primary!.version) {
    official = Object.entries(pins).every(([rel, digest]) => {
      if (!texts.has(normalize(rel))) {
        const read = readPluginFile(at, rel);
        if (read.state !== 'ok') return false;
        texts.set(normalize(rel), read.bytes);
      }
      return sha256(texts.get(normalize(rel))!) === digest;
    });
  }
  return { id, official, servers: [...names], newest: at.newest } as PluginServers & { newest: number };
}

export type PluginScanOptions = {
  codexHome: string;
  ids: string[];
  /** Wall-clock start of the codex process (ms), or null when it cannot be found. */
  processStartMs: number | null;
};

/** Every enabled plugin's MCP server names; any doubt is `bad`. */
export function scanCodexPlugins(options: PluginScanOptions): PluginScan {
  if (!options.ids.length) return { bad: null, plugins: [] };
  if (options.ids.length > MAX_PLUGINS) return { bad: 'too many Codex plugins are enabled' };
  if (options.processStartMs === null || !Number.isFinite(options.processStartMs)) {
    return { bad: 'the codex process start is unknown, so plugin files cannot be dated' };
  }
  const plugins = join(options.codexHome, 'plugins');
  try {
    const staging = readdirSync(join(plugins, '.remote-plugin-install-staging'));
    if (staging.length) return { bad: 'a remote Codex plugin install is staged' };
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code !== 'ENOENT') return { bad: 'the Codex plugin staging folder is unreadable' };
  }
  const cacheRoot = join(plugins, 'cache');
  let realRoot: string;
  try {
    realRoot = realpathSync(cacheRoot);
  } catch {
    return { bad: 'the Codex plugin cache is missing' };
  }
  const out: PluginServers[] = [];
  for (const id of options.ids) {
    const scanned = scanPlugin(cacheRoot, realRoot, id);
    if (typeof scanned === 'string') return { bad: scanned };
    const { newest, ...plugin } = scanned as PluginServers & { newest: number };
    if (!(newest < options.processStartMs - START_MARGIN_MS)) return { bad: 'a Codex plugin changed after codex started' };
    out.push(plugin);
  }
  return { bad: null, plugins: out };
}
