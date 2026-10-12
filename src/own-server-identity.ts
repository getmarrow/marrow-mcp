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

import { createHash } from 'node:crypto';
import { closeSync, existsSync, fstatSync, openSync, readSync, constants as fsConstants } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { brotliDecompressSync } from 'node:zlib';
import { codexProcessArgs } from './host-session';
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
    if (stat.size > MAX_HOST_CONFIG_BYTES) return { state: 'bad', reason: 'over the size cap' };
    const buffer = Buffer.alloc(MAX_HOST_CONFIG_BYTES + 1);
    let total = 0;
    for (;;) {
      const read = readSync(fd, buffer, total, buffer.length - total, null);
      if (read <= 0) break;
      total += read;
      if (total > MAX_HOST_CONFIG_BYTES) return { state: 'bad', reason: 'over the size cap' };
    }
    return { state: 'ok', text: buffer.subarray(0, total).toString('utf8') };
  } catch {
    return { state: 'bad', reason: 'unreadable' };
  } finally {
    try { closeSync(fd); } catch { /* closed */ }
  }
}

/**
 * Every `<dir>/<rel>` from each start directory up to its project root (the
 * nearest directory holding `.git`, where codex and Cursor stop looking), or up
 * to the filesystem root when there is none; deduplicated, bounded.
 */
function upwardPaths(starts: string[], rel: string): string[] {
  const out = new Set<string>();
  for (const start of starts) {
    let dir = resolve(start);
    for (let depth = 0; depth < MAX_DIR_DEPTH; depth += 1) {
      out.add(join(dir, rel));
      if (existsSync(join(dir, '.git'))) break;
      const parent = dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }
  return [...out];
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

/** Whether a loader decodes to exactly the installer's launcher for this version, with a pinned core. */
function installerLoaderFor(loader: string, version: string): boolean {
  const match = LOADER_RE.exec(loader);
  if (!match) return false;
  let source: string;
  try {
    source = brotliDecompressSync(Buffer.from(match[1], 'base64url'), { maxOutputLength: 1 << 17 }).toString('utf8');
  } catch {
    return false;
  }
  if (!source.startsWith(LOADER_HEAD)) return false;
  const lineEnd = source.indexOf('\n', LOADER_HEAD.length);
  if (lineEnd < 0) return false;
  const cfgLine = source.slice(LOADER_HEAD.length, lineEnd);
  if (!cfgLine.endsWith(';')) return false;
  let cfg: unknown;
  try { cfg = JSON.parse(cfgLine.slice(0, -1)); } catch { return false; }
  if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg) || JSON.stringify(cfg) !== cfgLine.slice(0, -1)) return false;
  if ((cfg as Record<string, unknown>).version !== version) return false;
  const body = source.slice(lineEnd + 1);
  if (!body.startsWith('(') || !body.endsWith(LOADER_TAIL)) return false;
  const core = body.slice(1, -LOADER_TAIL.length);
  return INSTALLER_RUNTIME_CORE_SHA256.has(createHash('sha256').update(core).digest('hex'));
}

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
export function isOfficialMarrowServerLaunch(command: unknown, args: unknown): boolean {
  if (typeof command !== 'string') return false;
  const list = args === undefined ? [] : args;
  if (!Array.isArray(list) || list.length > 8 || !list.every((arg) => typeof arg === 'string')) return false;
  const argv = list as string[];
  if (command === 'npx' || command === 'npx.cmd') {
    const rest = argv[0] === '-y' || argv[0] === '--yes' ? argv.slice(1) : argv;
    if (rest.length === 1) return PACKAGE_SPEC.test(rest[0]);
    return rest.length === 2 && rest[0].startsWith('--package=') && PACKAGE_SPEC.test(rest[0].slice('--package='.length)) && rest[1] === 'marrow-mcp';
  }
  if (command === 'marrow-mcp' || command === 'marrow-mcp.cmd') return argv.length === 0;
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
 * one present those two forms prove nothing.
 */
function localPackageCopy(starts: string[]): boolean {
  const seen = new Set<string>();
  for (const start of starts) {
    let dir = resolve(start);
    for (let depth = 0; depth < MAX_DIR_DEPTH && !seen.has(dir); depth += 1) {
      seen.add(dir);
      if (existsSync(join(dir, 'node_modules', '@getmarrow', 'mcp')) || existsSync(join(dir, 'node_modules', '.bin', 'marrow-mcp'))) return true;
      const parent = dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }
  return false;
}

/** Whether a launch resolves through npx or PATH (the forms a local copy can shadow). */
function resolvesLocally(entry: unknown): boolean {
  const command = entry && typeof entry === 'object' ? (entry as Record<string, unknown>).command : undefined;
  return command === 'npx' || command === 'npx.cmd' || command === 'marrow-mcp' || command === 'marrow-mcp.cmd';
}

/** One server definition: an official launch with only the keys and env names Marrow writes. */
function officialDefinition(entry: unknown, keys: ReadonlySet<string>): boolean {
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
  return isOfficialMarrowServerLaunch(record.command, record.args);
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
function decide(set: ServerSet, keys: ReadonlySet<string>, onlyServer: boolean, cwds: string[], codexNames = false): ServerIdentity {
  if (set.bad) return { official: false, reason: set.bad };
  const colliding = [...set.names.keys()].filter(codexNames ? codexServerNameCanProduceMarrowLabel : serverNameCollidesWithMarrow);
  if (colliding.length !== 1) return { official: false, reason: colliding.length ? 'more than one server can produce the marrow label' : 'no marrow server configured' };
  if (colliding[0] !== 'marrow') return { official: false, reason: 'the colliding server is not named exactly marrow' };
  if (!set.names.get('marrow')!.every((entry) => officialDefinition(entry, keys))) return { official: false, reason: 'the marrow server is not the official Marrow MCP launch' };
  if (set.names.get('marrow')!.some(resolvesLocally) && localPackageCopy(cwds)) return { official: false, reason: 'a project-local Marrow MCP copy could shadow the npx or bin launch' };
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
  const cwds = [process.cwd(), ...(options.cwds ?? []).map(usableDir).filter((dir): dir is string => Boolean(dir)), ...facts.dirs].slice(0, MAX_ROOTS + 1);
  const files = [
    join(home, 'config.toml'),
    join(home, 'managed_config.toml'),
    '/etc/codex/config.toml',
    '/etc/codex/managed_config.toml',
    ...upwardPaths(cwds, join('.codex', 'config.toml')),
  ];
  const set: ServerSet = { names: new Map(), bad: null };
  const parsedFiles: TomlTable[] = [];
  const load = (file: string): boolean => {
    const result = read(file);
    if (result.state === 'missing') return true;
    if (result.state === 'bad') { set.bad = `a Codex config is ${result.reason}`; return false; }
    try {
      parsedFiles.push(parseToml(result.text));
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
      for (const plugin of Object.values(plugins as TomlTable)) {
        if (!plugin || typeof plugin !== 'object' || Array.isArray(plugin) || (plugin as TomlTable).enabled !== false) {
          return { official: false, reason: 'a Codex plugin is enabled (its MCP servers cannot be proven)' };
        }
      }
    }
  }
  return decide(set, CODEX_SERVER_KEYS, false, cwds, true);
}

// ---------------------------------------------------------------------------
// Cursor
// ---------------------------------------------------------------------------

export type CursorIdentityOptions = { home?: string; cwds?: unknown[]; read?: HostConfigReader; onlyServer: boolean };

/** Whether Cursor's `marrow` server is provably the official one (and, at preToolUse, the only server). */
export function cursorOfficialMarrowServer(options: CursorIdentityOptions): ServerIdentity {
  const read = options.read ?? readHostConfigFile;
  const home = options.home ?? homedir();
  const cwds = [process.cwd(), ...(options.cwds ?? []).map(usableDir).filter((dir): dir is string => Boolean(dir))].slice(0, MAX_ROOTS + 1);
  const files = new Set([join(home, '.cursor', 'mcp.json'), ...upwardPaths(cwds, join('.cursor', 'mcp.json'))]);
  const set: ServerSet = { names: new Map(), bad: null };
  for (const file of files) {
    const result = read(file);
    if (result.state === 'missing') continue;
    if (result.state === 'bad') return { official: false, reason: `a Cursor MCP config is ${result.reason}` };
    let parsed: unknown;
    try { parsed = JSON.parse(result.text); } catch { return { official: false, reason: 'a Cursor MCP config does not parse' }; }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return { official: false, reason: 'a Cursor MCP config is not an object' };
    addServers(set, (parsed as Record<string, unknown>).mcpServers, 'mcpServers');
  }
  return decide(set, CURSOR_SERVER_KEYS, options.onlyServer, cwds);
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
  const roots = Array.isArray(payload.workspace_roots) ? payload.workspace_roots.slice(0, MAX_ROOTS) : [];
  const key = `cursor\0${process.env.HOME ?? ''}\0${beforeMcp ? 'server' : 'only'}\0${roots.map(String).join('\0')}`;
  if (!memo.has(key)) {
    let verdict: ServerIdentity;
    try { verdict = cursorOfficialMarrowServer({ cwds: roots, onlyServer: !beforeMcp }); } catch { verdict = { official: false, reason: 'identity check failed' }; }
    memo.set(key, verdict);
  }
  return memo.get(key)!.official;
}
