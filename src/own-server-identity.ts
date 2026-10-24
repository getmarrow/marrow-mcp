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

import { createHash } from 'node:crypto';
import { closeSync, existsSync, fstatSync, lstatSync, openSync, readSync, constants as fsConstants } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { brotliDecompressSync } from 'node:zlib';
import { codexProcessArgs, codexProcessStartMs } from './host-session';
import { scanCodexPlugins } from './codex-plugins';
import {
  MARROW_OWN_TOOL_NAMES,
  isOfficialMarrowMcpEvent,
} from './own-tool';

export const MAX_HOST_CONFIG_BYTES = 256 * 1024;
const MAX_DIR_DEPTH = 64;
const MAX_ROOTS = 8;
const MAX_PATH_LENGTH = 4096;

type OwnToolEvent = { tool_name?: unknown; tool_input?: unknown };

export type ServerIdentity = { official: boolean; reason: string };

// ---------------------------------------------------------------------------
// Bounded file reads
// ---------------------------------------------------------------------------

export type HostConfigRead = { state: 'missing' } | { state: 'bad'; reason: string } | { state: 'ok'; text: string };
export type HostConfigReader = (path: string) => HostConfigRead;

/** One config file: missing adds nothing; anything but a readable regular file within the cap is bad. */
export function readHostConfigFile(path: string): HostConfigRead {
  const read = readHostConfigBytes(path);
  return read.state === 'ok' ? { state: 'ok', text: read.bytes.toString('utf8') } : read;
}

/** The same bounded read, as raw bytes (for content pins); `maxBytes` is the size cap. */
export function readHostConfigBytes(path: string, maxBytes: number = MAX_HOST_CONFIG_BYTES): { state: 'missing' } | { state: 'bad'; reason: string } | { state: 'ok'; bytes: Buffer } {
  let fd: number;
  try {
    fd = openSync(path, fsConstants.O_RDONLY | (fsConstants.O_NONBLOCK ?? 0));
  } catch (error) {
    const code = (error as NodeJS.ErrnoException)?.code;
    return code === 'ENOENT' || code === 'ENOTDIR' ? { state: 'missing' } : { state: 'bad', reason: `unreadable (${code || 'error'})` };
  }
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) return { state: 'bad', reason: 'not a regular file' };
    if (stat.size > maxBytes) return { state: 'bad', reason: 'over the size cap' };
    const buffer = Buffer.alloc(maxBytes + 1);
    let total = 0;
    for (;;) {
      const read = readSync(fd, buffer, total, buffer.length - total, null);
      if (read <= 0) break;
      total += read;
      if (total > maxBytes) return { state: 'bad', reason: 'over the size cap' };
    }
    return { state: 'ok', bytes: Buffer.from(buffer.subarray(0, total)) };
  } catch {
    return { state: 'bad', reason: 'unreadable' };
  } finally {
    try { closeSync(fd); } catch { /* closed */ }
  }
}

/**
 * A real git repository root: `.git` is a directory (not a symlink) holding a
 * regular `HEAD` file and `objects` and `refs` directories, as `git init` makes.
 * codex does not stop at a `.git` that is not a repository (an empty folder,
 * an archive, a generated directory), so neither does this walk. A gitfile
 * (`.git` file of a worktree or submodule) never stops it either: walking on
 * reads more configs than the host, which only adds to the union (stricter).
 */
function realGitRoot(dir: string): boolean {
  try {
    const git = lstatSync(join(dir, '.git'));
    if (!git.isDirectory()) return false;
    return lstatSync(join(dir, '.git', 'HEAD')).isFile()
      && lstatSync(join(dir, '.git', 'objects')).isDirectory()
      && lstatSync(join(dir, '.git', 'refs')).isDirectory();
  } catch {
    return false;
  }
}

/**
 * Every `<dir>/<rel>` from each start directory up to its project root (the
 * nearest real git repository root, where codex stops looking), or up to the
 * filesystem root when there is none; deduplicated. A path deeper than the
 * bound proves nothing (null).
 */
function upwardPaths(starts: string[], rel: string): string[] | null {
  const out = new Set<string>();
  for (const start of starts) {
    let dir = resolve(start);
    for (let depth = 0; ; depth += 1) {
      if (depth >= MAX_DIR_DEPTH) return null;
      out.add(join(dir, rel));
      if (realGitRoot(dir)) break;
      const parent = dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }
  return [...out];
}

/** One leading U+FEFF (Windows editors write it; codex 0.161 accepts it) is not content. */
function withoutBom(text: string): string {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

function usableDir(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_PATH_LENGTH && isAbsolute(value) && !value.includes('\0') ? value : null;
}

// ---------------------------------------------------------------------------
// A strict TOML reader (TOML 1.0 subset codex configs use). Any construct it
// does not understand throws, which the caller treats as "not proven".
// ---------------------------------------------------------------------------

type TomlTable = Record<string, unknown>;
const newTable = (): TomlTable => Object.create(null) as TomlTable;
const DATE_TIME = /^\d{4}-\d{2}-\d{2}(?:[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})?)?|^\d{2}:\d{2}:\d{2}(?:\.\d+)?/;

export function parseToml(text: string): TomlTable {
  if (text.includes('\0')) throw new Error('NUL in config');
  const root = newTable();
  const explicit = new Set<TomlTable>();
  const frozen = new Set<unknown>();
  let pos = 0;
  let current = root;
  const fail = (what: string): never => { throw new Error(`TOML: ${what} at ${pos}`); };
  const skipWs = () => { while (pos < text.length && (text[pos] === ' ' || text[pos] === '\t')) pos += 1; };
  const skipComment = () => {
    if (text[pos] === '#') { while (pos < text.length && text[pos] !== '\n') pos += 1; }
  };
  const skipBlank = () => {
    for (;;) {
      skipWs(); skipComment();
      if (text[pos] === '\r' && text[pos + 1] === '\n') { pos += 2; continue; }
      if (text[pos] === '\n') { pos += 1; continue; }
      return;
    }
  };
  const endOfLine = () => {
    skipWs(); skipComment();
    if (pos >= text.length) return;
    if (text[pos] === '\r' && text[pos + 1] === '\n') { pos += 2; return; }
    if (text[pos] === '\n') { pos += 1; return; }
    fail('expected end of line');
  };
  const escape = (): string => {
    const c = text[pos]; pos += 1;
    const simple: Record<string, string> = { b: '\b', t: '\t', n: '\n', f: '\f', r: '\r', '"': '"', '\\': '\\' };
    if (c in simple) return simple[c];
    if (c === 'u' || c === 'U') {
      const len = c === 'u' ? 4 : 8;
      const hex = text.slice(pos, pos + len);
      if (!/^[0-9A-Fa-f]+$/.test(hex) || hex.length !== len) fail('bad unicode escape');
      pos += len;
      const code = parseInt(hex, 16);
      if (code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) fail('bad code point');
      return String.fromCodePoint(code);
    }
    return fail('bad escape');
  };
  const basicString = (): string => {
    if (text.startsWith('"""', pos)) {
      pos += 3;
      if (text[pos] === '\n') pos += 1; else if (text.startsWith('\r\n', pos)) pos += 2;
      let out = '';
      for (;;) {
        if (pos >= text.length) fail('unterminated string');
        if (text.startsWith('"""', pos)) {
          let quotes = 3;
          while (text[pos + quotes] === '"' && quotes < 5) quotes += 1;
          out += '"'.repeat(quotes - 3);
          pos += quotes;
          return out;
        }
        const c = text[pos];
        if (c === '\\') {
          pos += 1;
          if (/^[ \t]*\r?\n/.test(text.slice(pos, pos + 64)) || text[pos] === '\n' || text[pos] === '\r') {
            while (pos < text.length && /[ \t\r\n]/.test(text[pos])) pos += 1;
          } else out += escape();
          continue;
        }
        out += c; pos += 1;
      }
    }
    pos += 1;
    let out = '';
    for (;;) {
      if (pos >= text.length || text[pos] === '\n') fail('unterminated string');
      const c = text[pos];
      if (c === '"') { pos += 1; return out; }
      if (c === '\\') { pos += 1; out += escape(); continue; }
      out += c; pos += 1;
    }
  };
  const literalString = (): string => {
    if (text.startsWith("'''", pos)) {
      pos += 3;
      if (text[pos] === '\n') pos += 1; else if (text.startsWith('\r\n', pos)) pos += 2;
      const end = text.indexOf("'''", pos);
      if (end < 0) fail('unterminated string');
      let stop = end + 3;
      while (text[stop] === "'" && stop - end < 5) stop += 1;
      const out = text.slice(pos, stop - 3);
      pos = stop;
      return out;
    }
    pos += 1;
    const end = text.indexOf("'", pos);
    const nl = text.indexOf('\n', pos);
    if (end < 0 || (nl >= 0 && nl < end)) fail('unterminated string');
    const out = text.slice(pos, end);
    pos = end + 1;
    return out;
  };
  const keyPart = (): string => {
    skipWs();
    if (text[pos] === '"') { if (text.startsWith('"""', pos)) fail('multi-line key'); return basicString(); }
    if (text[pos] === "'") { if (text.startsWith("'''", pos)) fail('multi-line key'); return literalString(); }
    const match = /^[A-Za-z0-9_-]+/.exec(text.slice(pos, pos + 256));
    if (!match) fail('bad key');
    pos += match![0].length;
    return match![0];
  };
  const dottedKey = (): string[] => {
    const parts = [keyPart()];
    for (;;) {
      skipWs();
      if (text[pos] !== '.') return parts;
      pos += 1;
      parts.push(keyPart());
    }
  };
  const has = (table: TomlTable, key: string) => Object.prototype.hasOwnProperty.call(table, key);
  const descend = (table: TomlTable, key: string, forHeader: boolean): TomlTable => {
    if (!has(table, key)) { const next = newTable(); table[key] = next; return next; }
    const value = table[key];
    if (Array.isArray(value) && forHeader && !frozen.has(value) && value.length > 0) {
      const last = value[value.length - 1];
      if (last && typeof last === 'object' && !Array.isArray(last)) return last as TomlTable;
    }
    if (!value || typeof value !== 'object' || Array.isArray(value) || frozen.has(value)) return fail('key redefined');
    return value as TomlTable;
  };
  const value = (depth: number): unknown => {
    if (depth > 32) fail('nesting too deep');
    skipWs();
    const c = text[pos];
    if (c === '"') return basicString();
    if (c === "'") return literalString();
    if (c === '[') {
      pos += 1;
      const items: unknown[] = [];
      for (;;) {
        skipBlank();
        if (text[pos] === ']') { pos += 1; break; }
        items.push(value(depth + 1));
        skipBlank();
        if (text[pos] === ',') { pos += 1; continue; }
        if (text[pos] === ']') { pos += 1; break; }
        fail('bad array');
      }
      frozen.add(items);
      return items;
    }
    if (c === '{') {
      pos += 1;
      const table = newTable();
      skipWs();
      if (text[pos] === '}') { pos += 1; frozen.add(table); return table; }
      for (;;) {
        const key = dottedKey();
        skipWs();
        if (text[pos] !== '=') fail('expected =');
        pos += 1;
        assign(table, key, value(depth + 1));
        skipWs();
        if (text[pos] === ',') { pos += 1; continue; }
        if (text[pos] === '}') { pos += 1; break; }
        fail('bad inline table');
      }
      frozen.add(table);
      return table;
    }
    const rest = text.slice(pos, pos + 64);
    const date = DATE_TIME.exec(rest);
    if (date) { pos += date[0].length; return date[0]; }
    const word = /^(?:true|false|[+-]?(?:inf|nan)|0x[0-9A-Fa-f_]+|0o[0-7_]+|0b[01_]+|[+-]?\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d[\d_]*)?)/.exec(rest);
    if (!word) return fail('bad value');
    pos += word[0].length;
    if (word[0] === 'true') return true;
    if (word[0] === 'false') return false;
    return Number(word[0].replace(/_/g, ''));
  };
  const assign = (table: TomlTable, key: string[], val: unknown) => {
    let target = table;
    for (const part of key.slice(0, -1)) target = descend(target, part, false);
    const last = key[key.length - 1];
    if (has(target, last)) fail('duplicate key');
    target[last] = val;
  };
  for (;;) {
    skipBlank();
    if (pos >= text.length) break;
    if (text[pos] === '[') {
      const array = text[pos + 1] === '[';
      pos += array ? 2 : 1;
      const key = dottedKey();
      skipWs();
      if (!text.startsWith(array ? ']]' : ']', pos)) fail('bad table header');
      pos += array ? 2 : 1;
      endOfLine();
      let target = root;
      for (const part of key.slice(0, -1)) target = descend(target, part, true);
      const last = key[key.length - 1];
      if (array) {
        if (!has(target, last)) target[last] = [];
        const list = target[last];
        if (!Array.isArray(list) || frozen.has(list)) fail('key redefined');
        const next = newTable();
        (list as unknown[]).push(next);
        current = next;
      } else {
        const existing = has(target, last) ? target[last] : undefined;
        if (existing !== undefined) {
          if (!existing || typeof existing !== 'object' || Array.isArray(existing) || frozen.has(existing) || explicit.has(existing as TomlTable)) fail('table redefined');
          current = existing as TomlTable;
        } else {
          current = newTable();
          target[last] = current;
        }
        explicit.add(current);
      }
      continue;
    }
    const key = dottedKey();
    skipWs();
    if (text[pos] !== '=') fail('expected =');
    pos += 1;
    assign(current, key, value(0));
    endOfLine();
  }
  return root;
}

// ---------------------------------------------------------------------------
// The official server launch
// ---------------------------------------------------------------------------

const PACKAGE_SPEC = /^@getmarrow\/mcp(?:@(?:latest|\d{1,4}\.\d{1,4}\.\d{1,4}(?:-[0-9A-Za-z.]{1,32})?))?$/;
const PINNED_SPEC = /^--package=@getmarrow\/mcp@(\d{1,4}\.\d{1,4}\.\d{1,4})$/;
// The installer's runtime core (src/runtime-core.js, identical in @getmarrow/install 0.1.70
// 60535d61 and feat/install-train-2 03a85d36): SHA-256 of the trimmed source its loader embeds.
// A new installer core must be added here before its local-runtime server counts as official.
const INSTALLER_RUNTIME_CORE_SHA256 = new Set(['73ea57796c017abfd144b43f3b91c9c935314c156ba523cbca525ebc1f977cb0']);
const INSTALLER_UNAVAILABLE_TEXT = 'Marrow could not start its verified local runtime. The owner can repair it by running npx -y @getmarrow/install@latest --repair --cwd <project folder> from a terminal outside the project.';
const LOADER_RE = /^eval\(global\.MARROW_L=require\(\/node:zlib\/\.source\)\.brotliDecompressSync\(Buffer\.from\(\/([A-Za-z0-9_-]{16,16000})\/\.source,\/base64url\/\.source\)\)\+\[\]\)$/;
const LOADER_HEAD = "'use strict';\nconst CFG = ";
const LOADER_TAIL = ')().main(CFG, global.MARROW_L);\n';

/** The installer's POSIX server script for one version (its mcpServerLaunch), byte for byte. */
function installerServerScript(version: string): string {
  return `N="$HOME/.marrow/runtime/mcp/${version}/node"; if [ ! -x "$N" ]; then N=; P="$PATH:/usr/local/bin:/opt/homebrew/bin"; while [ -n "$P" ]; do D="\${P%%:*}"; case "$P" in (*:*) P="\${P#*:}" ;; (*) P= ;; esac; case "$D" in ("$PWD"|"$PWD"/*) ;; (/*) if [ -f "$D/node" ] && [ -x "$D/node" ]; then N="$D/node"; break; fi ;; esac; done; fi; if [ -n "$N" ]; then exec "$N" -e "$0" -- "$@"; fi; printf "%s\\n" "${INSTALLER_UNAVAILABLE_TEXT}" >&2; exit 1`;
}

const MAX_LAUNCHER_BYTES = 1 << 17;
// What the installer core itself requires of CFG before it verifies or runs a runtime, with the
// version bounded as PINNED_SPEC bounds it (so no launch is proven that the shape check refuses).
const CFG_VERSION_RE = /^\d{1,4}\.\d{1,4}\.\d{1,4}$/;
const CFG_INTEGRITY_RE = /^sha512-[A-Za-z0-9+/]{86}==$/;

/** The CFG of a decoded installer launcher with a pinned core, or null when the source is not exactly one. */
function installerLauncherConfig(source: string): Record<string, unknown> | null {
  if (!source.startsWith(LOADER_HEAD)) return null;
  const lineEnd = source.indexOf('\n', LOADER_HEAD.length);
  if (lineEnd < 0) return null;
  const cfgLine = source.slice(LOADER_HEAD.length, lineEnd);
  if (!cfgLine.endsWith(';')) return null;
  let cfg: unknown;
  try { cfg = JSON.parse(cfgLine.slice(0, -1)); } catch { return null; }
  if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg) || JSON.stringify(cfg) !== cfgLine.slice(0, -1)) return null;
  const body = source.slice(lineEnd + 1);
  if (!body.startsWith('(') || !body.endsWith(LOADER_TAIL)) return null;
  const core = body.slice(1, -LOADER_TAIL.length);
  return INSTALLER_RUNTIME_CORE_SHA256.has(createHash('sha256').update(core).digest('hex')) ? cfg as Record<string, unknown> : null;
}

/** Whether a loader decodes to exactly the installer's launcher for this version, with a pinned core. */
function installerLoaderFor(loader: string, version: string): boolean {
  const match = LOADER_RE.exec(loader);
  if (!match) return false;
  let source: string;
  try {
    source = brotliDecompressSync(Buffer.from(match[1], 'base64url'), { maxOutputLength: MAX_LAUNCHER_BYTES }).toString('utf8');
  } catch {
    return false;
  }
  const cfg = installerLauncherConfig(source);
  return cfg !== null && cfg.version === version;
}

/**
 * The installer launcher that started this process: the core runs as
 * `eval(global.MARROW_L=<decoded loader>+[])`, verifies the runtime for its
 * CFG {version, integrity} and then requires that runtime in the same process.
 * Null unless it is exactly an installer launcher with a pinned core and the
 * version and integrity the core itself accepts.
 */
function ownInstallerLauncher(own: unknown): { source: Buffer; version: string } | null {
  if (typeof own !== 'string' || own.length > MAX_LAUNCHER_BYTES) return null;
  const cfg = installerLauncherConfig(own);
  if (!cfg || typeof cfg.version !== 'string' || !CFG_VERSION_RE.test(cfg.version)) return null;
  if (typeof cfg.integrity !== 'string' || !CFG_INTEGRITY_RE.test(cfg.integrity)) return null;
  return { source: Buffer.from(own, 'utf8'), version: cfg.version };
}

/** Whether a loader's canonical base64url payload decodes to exactly these launcher bytes. */
function loaderIsExactly(loader: string, source: Buffer): boolean {
  const match = LOADER_RE.exec(loader);
  if (!match) return false;
  const packed = Buffer.from(match[1], 'base64url');
  if (packed.toString('base64url') !== match[1]) return false;
  try {
    return brotliDecompressSync(packed, { maxOutputLength: MAX_LAUNCHER_BYTES }).equals(source);
  } catch {
    return false;
  }
}

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
export function isOfficialMarrowServerLaunch(command: unknown, args: unknown, ownLoader: unknown = (globalThis as Record<string, unknown>).MARROW_L): boolean {
  if (command !== '/bin/sh' && command !== 'node') return isMarrowServerLaunchShape(command, args);
  const own = ownInstallerLauncher(ownLoader);
  if (!own || !Array.isArray(args) || args.length !== 5 || !args.every((arg) => typeof arg === 'string')) return false;
  const argv = args as string[];
  const spec = `--package=@getmarrow/mcp@${own.version}`;
  if (command === '/bin/sh') {
    return argv[0] === '-c' && argv[1] === installerServerScript(own.version) && argv[3] === spec && argv[4] === 'marrow-mcp'
      && loaderIsExactly(argv[2], own.source);
  }
  return argv[0] === '-e' && argv[2] === '--' && argv[3] === spec && argv[4] === 'marrow-mcp' && loaderIsExactly(argv[1], own.source);
}

/**
 * The forms isOfficialMarrowServerLaunch lists, with an installer form of any
 * one version throughout (any pack integrity). For recognizing installer-written
 * hooks (setup, doctor); it never proves a server.
 */
export function isMarrowServerLaunchShape(command: unknown, args: unknown): boolean {
  if (typeof command !== 'string') return false;
  const list = args === undefined ? [] : args;
  if (!Array.isArray(list) || list.length > 8 || !list.every((arg) => typeof arg === 'string')) return false;
  const argv = list as string[];
  // The `.cmd` shims exist only on Windows; no Marrow installer or README writes them elsewhere.
  const windows = process.platform === 'win32';
  if (command === 'npx' || (windows && command === 'npx.cmd')) {
    const rest = argv[0] === '-y' || argv[0] === '--yes' ? argv.slice(1) : argv;
    if (rest.length === 1) return PACKAGE_SPEC.test(rest[0]);
    return rest.length === 2 && rest[0].startsWith('--package=') && PACKAGE_SPEC.test(rest[0].slice('--package='.length)) && rest[1] === 'marrow-mcp';
  }
  if (command === 'marrow-mcp' || (windows && command === 'marrow-mcp.cmd')) return argv.length === 0;
  if (command === '/bin/sh') {
    const pinned = argv.length === 5 ? PINNED_SPEC.exec(argv[3]) : null;
    return Boolean(pinned) && argv[0] === '-c' && argv[4] === 'marrow-mcp'
      && argv[1] === installerServerScript(pinned![1]) && installerLoaderFor(argv[2], pinned![1]);
  }
  if (command === 'node') {
    const pinned = argv.length === 5 ? PINNED_SPEC.exec(argv[3]) : null;
    return Boolean(pinned) && argv[0] === '-e' && argv[2] === '--' && argv[4] === 'marrow-mcp' && installerLoaderFor(argv[1], pinned![1]);
  }
  return false;
}

/** A server name a host could turn into the `marrow` label: case, separators and leading `mcp` ignored (wider than any host). */
export function serverNameCollidesWithMarrow(name: string): boolean {
  let folded = name.normalize('NFKC').toLowerCase().replace(/[^a-z0-9]/g, '');
  while (folded.startsWith('mcp') && folded !== 'mcp') folded = folded.slice(3);
  return folded === 'marrow';
}

const CODEX_PLAIN_SERVER_NAME = /^[A-Za-z0-9][A-Za-z0-9_-]*$/;

/**
 * Codex joins namespace and tool name with `__`, so a server whose namespace
 * trims to `mcp` (`_`, `-`, `__`, `mcp__`, `mcp___`, `MCP__`, and the hashed
 * duplicates of those) plus a tool `marrow__<own>` gives the exact label
 * `mcp__marrow__<own>`. On Codex such a name, or any name outside the plain
 * ASCII form, counts as able to produce the marrow label.
 */
export function codexServerNameCanProduceMarrowLabel(name: string): boolean {
  if (!CODEX_PLAIN_SERVER_NAME.test(name)) return true;
  const folded = name.normalize('NFKC').toLowerCase().replace(/[^a-z0-9]/g, '');
  return folded === '' || folded === 'mcp' || serverNameCollidesWithMarrow(name);
}

const SERVER_ENV_KEYS = new Set(['MARROW_BASE_URL', 'MARROW_FLEET_AGENT_ID', 'MARROW_TOOL_PROFILE', 'MARROW_API_KEY']);
const CODEX_SERVER_KEYS = new Set(['command', 'args', 'env', 'enabled', 'required', 'startup_timeout_sec', 'startup_timeout_ms', 'tool_timeout_sec', 'enabled_tools', 'disabled_tools']);
const CURSOR_SERVER_KEYS = new Set(['command', 'args', 'env', 'type']);

/**
 * npx and a bare bin name resolve a project-local copy first: a
 * `node_modules/@getmarrow/mcp` or `node_modules/.bin/marrow-mcp` in any
 * working directory or above it could be planted project content, so with
 * one present those two forms prove nothing. npx also reads the project's
 * `.npmrc` (registry, scoped registry), so a `.npmrc` in a working directory
 * or above it, other than the user's own `$HOME/.npmrc`, unproves the npx
 * forms unless it only sets keys that cannot change what npx gets or runs
 * (`projectNpmrc`). A path deeper than the walk bound proves nothing.
 */
function upwardHas(starts: string[], present: (dir: string) => boolean): boolean {
  const seen = new Set<string>();
  for (const start of starts) {
    let dir = resolve(start);
    for (let depth = 0; !seen.has(dir); depth += 1) {
      if (depth >= MAX_DIR_DEPTH) return true;
      seen.add(dir);
      if (present(dir)) return true;
      const parent = dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }
  return false;
}

function localPackageCopy(starts: string[]): boolean {
  return upwardHas(starts, (dir) => existsSync(join(dir, 'node_modules', '@getmarrow', 'mcp'))
    || ['marrow-mcp', 'marrow-mcp.cmd', 'npx', 'npx.cmd'].some((name) => existsSync(join(dir, 'node_modules', '.bin', name))));
}

/** A project npm config larger than this proves nothing; real ones are a few lines. */
const MAX_NPM_PROJECT_CONFIG_BYTES = 64 * 1024;

/**
 * The project npm config keys that cannot change what npx downloads, from
 * where, with what trust, or what it runs: output and logging, `npm install`
 * save and `npm version` / `npm init` settings, lockfile and peer-resolution
 * switches within the same registry tree, and pnpm/yarn names npm ignores.
 * Matching is exact and case-sensitive. Registry, scoped registry, proxy, TLS,
 * cache, prefix, script, include/omit and location keys are deliberately not
 * here, and neither is anything not listed.
 */
const NPM_PROJECT_CONFIG_KEYS: ReadonlySet<string> = new Set([
  'save-exact', 'save-prefix', 'fund', 'audit', 'audit-level', 'loglevel', 'progress', 'color', 'unicode', 'update-notifier',
  'package-lock', 'package-lock-only', 'lockfile-version', 'legacy-peer-deps', 'strict-peer-deps',
  'git-tag-version', 'sign-git-tag', 'tag-version-prefix', 'message',
  'init-author-name', 'init-author-email', 'init-license', 'init-version',
  'auto-install-peers', 'shamefully-hoist', 'strict-peer-dependencies', 'node-linker', 'link-workspace-packages', 'prefer-workspace-packages',
]);

/** The default registry's own credential fields. The value is never read or logged. */
const NPM_DEFAULT_REGISTRY_AUTH_KEY = /^\/\/registry\.npmjs\.org\/:(?:_authToken|_auth|_password|username|email|always-auth)$/;

/** Control characters (NUL, VT, FF, DEL, …) and the Unicode line separators: text a line reader may split or truncate at. */
const NPM_CONFIG_ODD_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u0085\u{2028}\u{2029}]/u;

/** ASCII blanks only: a key padded with any other whitespace is not a key on the list. */
function trimBlanks(text: string): string {
  let start = 0;
  let end = text.length;
  while (start < end && (text[start] === ' ' || text[start] === '\t')) start += 1;
  while (end > start && (text[end - 1] === ' ' || text[end - 1] === '\t')) end -= 1;
  return text.slice(start, end);
}

/** A value the way npm's ini reader sees it: trimmed, then unquoted or cut at the first `;` or `#`. */
function npmIniValue(raw: string): string {
  const value = trimBlanks(raw);
  const quote = value[0];
  if ((quote === '"' || quote === "'") && value.length >= 2 && value[value.length - 1] === quote) return value.slice(1, -1);
  const comment = value.search(/[;#]/);
  return trimBlanks(comment < 0 ? value : value.slice(0, comment));
}

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
export function npmProjectConfigIsHarmless(text: string): boolean {
  if (NPM_CONFIG_ODD_CHARS.test(text)) return false;
  const lines = text.split('\n');
  let engineStrict: string | null = null;
  for (let index = 0; index < lines.length; index += 1) {
    let line = lines[index];
    if (index < lines.length - 1 && line.endsWith('\r')) line = line.slice(0, -1);
    if (line.includes('\r')) return false;
    const trimmed = trimBlanks(line);
    if (trimmed.endsWith('\\')) return false;
    if (trimmed === '' || trimmed[0] === ';' || trimmed[0] === '#') continue;
    const equals = trimmed.indexOf('=');
    if (equals < 0) return false;
    const key = trimBlanks(trimmed.slice(0, equals));
    if (key === 'engine-strict') {
      engineStrict = npmIniValue(trimmed.slice(equals + 1));
      continue;
    }
    if (!NPM_PROJECT_CONFIG_KEYS.has(key) && !NPM_DEFAULT_REGISTRY_AUTH_KEY.test(key)) return false;
  }
  return engineStrict === null || engineStrict === 'true' || engineStrict === 'false';
}

/** One project npm config file: absent, or a plain readable text file whose keys are all harmless. */
function npmProjectConfigIsInert(file: string): boolean {
  const read = readHostConfigBytes(file, MAX_NPM_PROJECT_CONFIG_BYTES);
  if (read.state === 'missing') return true;
  if (read.state === 'bad') return false;
  const text = read.bytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(read.bytes)) return false;
  return npmProjectConfigIsHarmless(text);
}

function projectNpmrc(starts: string[], home: string): boolean {
  const userConfig = resolve(home, '.npmrc');
  return upwardHas(starts, (dir) => {
    const file = join(dir, '.npmrc');
    return file !== userConfig && !npmProjectConfigIsInert(file);
  });
}

/** npm reads any `npm_config_*` variable (any case) as config: registry, userconfig, globalconfig. */
function npmConfigEnv(env: NodeJS.ProcessEnv): boolean {
  return Object.keys(env).some((key) => /^npm_config_/i.test(key));
}

/** Whether a launch resolves through npx or PATH (the forms a local copy can shadow). */
function resolvesLocally(entry: unknown): boolean {
  const command = entry && typeof entry === 'object' ? (entry as Record<string, unknown>).command : undefined;
  return command === 'npx' || command === 'npx.cmd' || command === 'marrow-mcp' || command === 'marrow-mcp.cmd';
}

/** Whether a launch goes through npx (the forms npm config can redirect). */
function launchesWithNpx(entry: unknown): boolean {
  const command = entry && typeof entry === 'object' ? (entry as Record<string, unknown>).command : undefined;
  return command === 'npx' || command === 'npx.cmd';
}

/** One server definition: an official launch with only the keys and env names Marrow writes. */
function officialDefinition(entry: unknown, keys: ReadonlySet<string>, ownLoader: unknown): boolean {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return false;
  const record = entry as Record<string, unknown>;
  const own = Object.keys(record);
  if (!own.every((key) => keys.has(key))) return false;
  if (record.type !== undefined && record.type !== 'stdio') return false;
  if (record.env !== undefined) {
    const env = record.env;
    if (!env || typeof env !== 'object' || Array.isArray(env)) return false;
    if (!Object.keys(env).every((key) => SERVER_ENV_KEYS.has(key) && typeof (env as Record<string, unknown>)[key] === 'string')) return false;
  }
  return isOfficialMarrowServerLaunch(record.command, record.args, ownLoader);
}

type ServerSet = { names: Map<string, unknown[]>; bad: string | null };

function addServers(into: ServerSet, servers: unknown, where: string): void {
  if (servers === undefined) return;
  if (!servers || typeof servers !== 'object' || Array.isArray(servers)) { into.bad = `${where}: servers is not a table`; return; }
  for (const name of Object.keys(servers)) {
    const list = into.names.get(name) ?? [];
    list.push((servers as Record<string, unknown>)[name]);
    into.names.set(name, list);
  }
}

/** The decision over the union of every definition of every server. */
type NpmContext = { env: NodeJS.ProcessEnv; home: string };

/** `undefined` means this process's own installer launcher (`global.MARROW_L`). */
const ownLoaderOf = (given: unknown): unknown => (given === undefined ? (globalThis as Record<string, unknown>).MARROW_L : given);

function decide(set: ServerSet, keys: ReadonlySet<string>, onlyServer: boolean, cwds: string[], npm: NpmContext, ownLoader: unknown, codexNames = false): ServerIdentity {
  if (set.bad) return { official: false, reason: set.bad };
  const colliding = [...set.names.keys()].filter(codexNames ? codexServerNameCanProduceMarrowLabel : serverNameCollidesWithMarrow);
  if (colliding.length !== 1) return { official: false, reason: colliding.length ? 'more than one server can produce the marrow label' : 'no marrow server configured' };
  if (colliding[0] !== 'marrow') return { official: false, reason: 'the colliding server is not named exactly marrow' };
  if (!set.names.get('marrow')!.every((entry) => officialDefinition(entry, keys, ownLoader))) return { official: false, reason: 'the marrow server is not the official Marrow MCP launch' };
  if (set.names.get('marrow')!.some(resolvesLocally) && localPackageCopy(cwds)) return { official: false, reason: 'a project-local Marrow MCP copy could shadow the npx or bin launch' };
  if (set.names.get('marrow')!.some(launchesWithNpx) && (npmConfigEnv(npm.env) || projectNpmrc(cwds, npm.home))) return { official: false, reason: 'npm config in the project or the environment could redirect the npx launch' };
  if (onlyServer && set.names.size !== 1) return { official: false, reason: 'other MCP servers could expose a tool with this name' };
  return { official: true, reason: 'official' };
}

// ---------------------------------------------------------------------------
// Codex
// ---------------------------------------------------------------------------

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

const PROFILE_NAME = /^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}$/;

function codexArgsFacts(args: string[] | null): { bad: string | null; profile: string | null; dirs: string[] } {
  if (!args) return { bad: null, profile: null, dirs: [] };
  if (args.length >= 64) return { bad: 'codex command line may be cut', profile: null, dirs: [] };
  let profile: string | null = null;
  const dirs: string[] = [];
  const tokens = args.slice(1);
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    const valueOf = (long: string, short: string): string | null => {
      if (token === long || token === short) { i += 1; return i < tokens.length ? tokens[i] : ''; }
      if (token.startsWith(`${long}=`)) return token.slice(long.length + 1);
      if (token.startsWith(short) && !token.startsWith('--') && token.length > short.length) return token.slice(short.length).replace(/^=/, '');
      return null;
    };
    const config = valueOf('--config', '-c');
    if (config !== null) {
      if (/mcp_servers|plugins/i.test(config)) return { bad: 'a codex -c override touches MCP servers or plugins', profile: null, dirs: [] };
      continue;
    }
    const prof = valueOf('--profile', '-p');
    if (prof !== null) { profile = prof; continue; }
    const cd = valueOf('--cd', '-C');
    if (cd !== null) { const dir = usableDir(cd); if (dir) dirs.push(dir); }
  }
  return { bad: null, profile, dirs };
}

/** Whether the Codex `marrow` server is provably the official Marrow MCP server. */
export function codexOfficialMarrowServer(options: CodexIdentityOptions = {}): ServerIdentity {
  const env = options.env ?? process.env;
  const read = options.read ?? readHostConfigFile;
  const facts = codexArgsFacts(options.processArgs === undefined ? codexProcessArgs() : options.processArgs);
  if (facts.bad) return { official: false, reason: facts.bad };
  const home = env.CODEX_HOME && env.CODEX_HOME.trim() ? resolve(env.CODEX_HOME) : join(homedir(), '.codex');
  const cwds = [options.processCwd ?? process.cwd(), ...(options.cwds ?? []).map(usableDir).filter((dir): dir is string => Boolean(dir)), ...facts.dirs].slice(0, MAX_ROOTS + 1);
  const projectFiles = upwardPaths(cwds, join('.codex', 'config.toml'));
  if (!projectFiles) return { official: false, reason: 'a working directory is nested too deep' };
  const files = [
    join(home, 'config.toml'),
    join(home, 'managed_config.toml'),
    '/etc/codex/config.toml',
    '/etc/codex/managed_config.toml',
    ...projectFiles,
  ];
  const set: ServerSet = { names: new Map(), bad: null };
  const parsedFiles: TomlTable[] = [];
  let globalParsed: TomlTable | null = null;
  const enabledPlugins: string[] = [];
  const load = (file: string): boolean => {
    const result = read(file);
    if (result.state === 'missing') return true;
    if (result.state === 'bad') { set.bad = `a Codex config is ${result.reason}`; return false; }
    try {
      const parsed = parseToml(withoutBom(result.text));
      if (file === join(home, 'config.toml')) globalParsed = parsed;
      parsedFiles.push(parsed);
      return true;
    } catch {
      set.bad = 'a Codex config does not parse';
      return false;
    }
  };
  for (const file of new Set(files)) if (!load(file)) return { official: false, reason: set.bad! };
  const profileNames = new Set<string>();
  if (facts.profile !== null) {
    if (!PROFILE_NAME.test(facts.profile)) return { official: false, reason: 'unknown codex profile' };
    profileNames.add(facts.profile);
  }
  for (const parsed of parsedFiles) if (typeof parsed.profile === 'string') profileNames.add(parsed.profile);
  for (const name of profileNames) {
    if (!PROFILE_NAME.test(name)) return { official: false, reason: 'unknown codex profile' };
    if (!load(join(home, `${name}.config.toml`))) return { official: false, reason: set.bad! };
  }
  for (const parsed of parsedFiles) {
    if (parsed.project_root_markers !== undefined) return { official: false, reason: 'project_root_markers changes where codex looks for project configs' };
    addServers(set, parsed.mcp_servers, 'mcp_servers');
    const profiles = parsed.profiles;
    if (profiles !== undefined) {
      if (!profiles || typeof profiles !== 'object' || Array.isArray(profiles)) return { official: false, reason: 'profiles is not a table' };
      for (const profile of Object.values(profiles as TomlTable)) {
        if (!profile || typeof profile !== 'object' || Array.isArray(profile)) return { official: false, reason: 'a profile is not a table' };
        addServers(set, (profile as TomlTable).mcp_servers, 'profile mcp_servers');
        if ((profile as TomlTable).plugins !== undefined) return { official: false, reason: 'a profile configures plugins' };
      }
    }
    const plugins = parsed.plugins;
    if (plugins !== undefined) {
      if (!plugins || typeof plugins !== 'object' || Array.isArray(plugins)) return { official: false, reason: 'plugins is not a table' };
      for (const [id, plugin] of Object.entries(plugins as TomlTable)) {
        if (!plugin || typeof plugin !== 'object' || Array.isArray(plugin)) return { official: false, reason: 'a Codex plugin entry is not a table' };
        if ((plugin as TomlTable).enabled === false) continue;
        // `codex plugin add` enables plugins in $CODEX_HOME/config.toml; anywhere else is not proven.
        if (parsed !== globalParsed) return { official: false, reason: 'a Codex plugin is enabled outside the user config' };
        if (!Object.keys(plugin).every((key) => key === 'enabled') || ((plugin as TomlTable).enabled !== undefined && (plugin as TomlTable).enabled !== true)) {
          return { official: false, reason: 'a Codex plugin entry has unknown settings' };
        }
        enabledPlugins.push(id);
      }
    }
  }
  const scan = scanCodexPlugins({
    codexHome: home,
    ids: enabledPlugins,
    processStartMs: options.processStartMs === undefined ? (enabledPlugins.length ? codexProcessStartMs() : null) : options.processStartMs,
  });
  if (scan.bad !== null) return { official: false, reason: scan.bad };
  let officialPlugin = 0;
  for (const plugin of scan.plugins) {
    for (const name of plugin.servers) {
      if (!codexServerNameCanProduceMarrowLabel(name)) continue;
      if (!plugin.official) return { official: false, reason: 'a Codex plugin declares a server that can produce the marrow label' };
      officialPlugin += 1;
    }
  }
  if (officialPlugin > 1) return { official: false, reason: 'more than one Codex plugin declares the marrow server' };
  if (officialPlugin === 1) {
    // The official plugin is the only source of the label: no configured server may produce it too.
    if (set.bad) return { official: false, reason: set.bad };
    if ([...set.names.keys()].some(codexServerNameCanProduceMarrowLabel)) return { official: false, reason: 'the official plugin and another server can both produce the marrow label' };
    return { official: true, reason: 'official plugin' };
  }
  return decide(set, CODEX_SERVER_KEYS, false, cwds, { env, home: options.userHome ?? homedir() }, ownLoaderOf(options.ownLoader), true);
}

// ---------------------------------------------------------------------------
// Cursor
// ---------------------------------------------------------------------------

export type CursorIdentityOptions = {
  home?: string; cwds?: unknown[]; read?: HostConfigReader; onlyServer: boolean; processCwd?: string; env?: NodeJS.ProcessEnv;
  /** The installer launcher that started this hook (default `global.MARROW_L`; null: none). */
  ownLoader?: unknown;
};

/** Whether Cursor's `marrow` server is provably the official one (and, at preToolUse, the only server). */
export function cursorOfficialMarrowServer(options: CursorIdentityOptions): ServerIdentity {
  const read = options.read ?? readHostConfigFile;
  const home = options.home ?? homedir();
  const cwds = [options.processCwd ?? process.cwd(), ...(options.cwds ?? []).map(usableDir).filter((dir): dir is string => Boolean(dir))].slice(0, MAX_ROOTS + 1);
  const projectFiles = upwardPaths(cwds, join('.cursor', 'mcp.json'));
  if (!projectFiles) return { official: false, reason: 'a workspace root is nested too deep' };
  const files = new Set([join(home, '.cursor', 'mcp.json'), ...projectFiles]);
  const set: ServerSet = { names: new Map(), bad: null };
  for (const file of files) {
    const result = read(file);
    if (result.state === 'missing') continue;
    if (result.state === 'bad') return { official: false, reason: `a Cursor MCP config is ${result.reason}` };
    let parsed: unknown;
    try { parsed = JSON.parse(withoutBom(result.text)); } catch { return { official: false, reason: 'a Cursor MCP config does not parse' }; }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { official: false, reason: 'a Cursor MCP config is not an object' };
    addServers(set, (parsed as Record<string, unknown>).mcpServers, 'mcpServers');
  }
  return decide(set, CURSOR_SERVER_KEYS, options.onlyServer, cwds, { env: options.env ?? process.env, home }, ownLoaderOf(options.ownLoader));
}

// ---------------------------------------------------------------------------
// The host-aware own-tool decision
// ---------------------------------------------------------------------------

const memo = new Map<string, ServerIdentity>();

/** Test seam: forget the per-process config decision. */
export function resetOwnServerIdentityCache(): void {
  memo.clear();
}

function rawRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function exactOwnLabel(label: unknown, prefix: string): boolean {
  return typeof label === 'string' && label.startsWith(prefix) && MARROW_OWN_TOOL_NAMES.has(label.slice(prefix.length));
}

/**
 * Marrow's own tool on this host, after the server identity check. `event` is
 * the normalised event; `raw` is the host's payload as received (for Cursor's
 * `url` and `workspace_roots`, Codex's `cwd`). Hosts other than Codex and
 * Cursor keep the label rule (isOfficialMarrowMcpEvent) unchanged.
 */
export function isOfficialMarrowMcpEventOnHost(harness: string, event: OwnToolEvent, raw?: unknown): boolean {
  if (harness !== 'codex' && harness !== 'cursor') return isOfficialMarrowMcpEvent(event);
  const payload = rawRecord(raw ?? event);
  if (harness === 'codex') {
    if (!exactOwnLabel(event.tool_name, 'mcp__marrow__')) return false;
    const cwd = usableDir(payload.cwd);
    const key = `codex\0${process.env.HOME ?? ''}\0${process.env.CODEX_HOME ?? ''}\0${cwd ?? ''}`;
    if (!memo.has(key)) {
      let verdict: ServerIdentity;
      try { verdict = codexOfficialMarrowServer({ cwds: cwd ? [cwd] : [] }); } catch { verdict = { official: false, reason: 'identity check failed' }; }
      memo.set(key, verdict);
    }
    return memo.get(key)!.official;
  }
  // Cursor: beforeMCPExecution is normalised to mcp__marrow__<own> only for server exactly `marrow`;
  // preToolUse carries `MCP:<tool>` with no server.
  const beforeMcp = exactOwnLabel(event.tool_name, 'mcp__marrow__');
  const preToolUse = exactOwnLabel(event.tool_name, 'MCP:') && !String(event.tool_name).startsWith('MCP:marrow:');
  if (!beforeMcp && !preToolUse) return false;
  if (beforeMcp && payload.url !== undefined && payload.url !== null && payload.url !== '') return false;
  // More roots than the bound, a non-array, or any root that is not a usable absolute path proves nothing.
  const given = payload.workspace_roots;
  if (given !== undefined && given !== null && !Array.isArray(given)) return false;
  const roots = Array.isArray(given) ? given : [];
  if (roots.length > MAX_ROOTS || !roots.every((root) => usableDir(root) !== null)) return false;
  const key = `cursor\0${process.env.HOME ?? ''}\0${beforeMcp ? 'server' : 'only'}\0${roots.map(String).join('\0')}`;
  if (!memo.has(key)) {
    let verdict: ServerIdentity;
    try { verdict = cursorOfficialMarrowServer({ cwds: roots, onlyServer: !beforeMcp }); } catch { verdict = { official: false, reason: 'identity check failed' }; }
    memo.set(key, verdict);
  }
  return memo.get(key)!.official;
}
