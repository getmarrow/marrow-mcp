import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const DEFAULT_BASE_URL = 'https://api.getmarrow.ai';
const ALLOWED_ENV_KEYS = new Set([
  'MARROW_API_KEY',
  'MARROW_KEY',
  'MARROW_BASE_URL',
  'MARROW_FLEET_AGENT_ID',
  'MARROW_AGENT_ID',
  'MARROW_SESSION_ID',
]);

const MAX_ENV_FILE_BYTES = 1024 * 1024;
const REPO_KEY_FIX = 'run npx @getmarrow/install doctor, or move the line to ~/.marrow/env, then chmod 600 ~/.marrow/env';

export interface ResolvedMarrowEnv {
  apiKey: string;
  baseUrl: string;
  agentId?: string;
  sessionId?: string;
  source: string | null;
  missing: boolean;
  exactFix: string;
}

/** Host (with port) of a non-default base URL, for status output; null for the default. */
export function nonDefaultBaseUrlHost(baseUrl: string): string | null {
  const normalized = normalizeBaseUrl(baseUrl);
  if (normalized === normalizeBaseUrl(DEFAULT_BASE_URL)) return null;
  try {
    return new URL(baseUrl).host || 'invalid';
  } catch {
    return 'invalid';
  }
}

function normalizeBaseUrl(value: string): string {
  try {
    return new URL(String(value || '').trim()).href.replace(/\/+$/, '');
  } catch {
    return `invalid:${String(value || '')}`;
  }
}

// File paths come from the working directory; keep notices on one printable line.
const MAX_PRINTED_PATH = 200;

// Paths in notices can be attacker-named: control, line-separator and format
// (bidi, zero-width) characters become '?', and the length is capped.
function printablePath(filePath: string): string {
  const clean = filePath.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, '?');
  const chars = Array.from(clean);
  return chars.length > MAX_PRINTED_PATH ? `${chars.slice(0, MAX_PRINTED_PATH - 3).join('')}...` : clean;
}

function stripQuotes(value: string): string {
  const trimmed = String(value || '').trim();
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

type OwnerFileRead =
  | { status: 'absent' }
  | { status: 'rejected' }
  | { status: 'trusted'; values: Record<string, string> };

// The one trust decision for owner files, shared by the MCP and hook paths. It
// is made about the bytes that were read: the file is opened without following
// a symlink, its type, owner and mode come from fstat on that same descriptor,
// and an lstat of the path taken after the read must name the same inode. The
// file must be the owner's and private; home and ~/.marrow must be the owner's
// real directories, not writable by anyone else. Anything else supplies nothing.
function readOwnerEnvFile(filePath: string, home: string): OwnerFileRead {
  const resolvedHome = path.resolve(home);
  const resolvedFile = path.resolve(filePath);
  const read = readEnvFile(resolvedFile, true);
  if (!read) {
    try {
      fs.lstatSync(resolvedFile);
      return { status: 'rejected' };
    } catch {
      return { status: 'absent' };
    }
  }
  try {
    const parent = path.dirname(resolvedFile);
    const homeStat = fs.lstatSync(resolvedHome);
    const parentStat = fs.lstatSync(parent);
    const pathStat = fs.lstatSync(resolvedFile);
    const uid = typeof process.getuid === 'function' ? process.getuid() : null;
    const owned = (stat: fs.Stats) => uid === null || stat.uid === uid;
    const safeDir = (stat: fs.Stats, dir: string) => stat.isDirectory() && !stat.isSymbolicLink()
      && fs.realpathSync(dir) === dir && owned(stat) && (stat.mode & 0o022) === 0;
    const trusted = resolvedFile.startsWith(`${resolvedHome}${path.sep}`)
      && safeDir(homeStat, resolvedHome) && safeDir(parentStat, parent)
      && read.stat.isFile() && owned(read.stat) && (read.stat.mode & 0o077) === 0
      && pathStat.isFile() && pathStat.dev === read.stat.dev && pathStat.ino === read.stat.ino;
    return trusted ? { status: 'trusted', values: read.values } : { status: 'rejected' };
  } catch {
    return { status: 'rejected' };
  }
}

interface EnvFileRead {
  values: Record<string, string>;
  stat: fs.Stats;
}

// Opens without blocking (a planted FIFO cannot hang the server) and reads only
// bounded regular files. noFollow refuses a symlink at open time where supported.
function readEnvFile(filePath: string, noFollow: boolean): EnvFileRead | null {
  const flags = fs.constants.O_RDONLY
    | (fs.constants.O_NONBLOCK || 0)
    | (noFollow ? fs.constants.O_NOFOLLOW || 0 : 0);
  let fd: number;
  try {
    fd = fs.openSync(filePath, flags);
  } catch {
    return null;
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size > MAX_ENV_FILE_BYTES) return null;
    const buffer = Buffer.alloc(stat.size + 1);
    let length = 0;
    while (length < buffer.length) {
      const read = fs.readSync(fd, buffer, length, buffer.length - length, null);
      if (read <= 0) break;
      length += read;
    }
    if (length > stat.size) return null;
    return { values: parseEnvText(buffer.subarray(0, length).toString('utf8')), stat };
  } catch {
    return null;
  } finally {
    fs.closeSync(fd);
  }
}

function parseEnvText(raw: string): Record<string, string> {
  const values: Record<string, string> = {};
  for (const line of raw.split(/\r?\n/)) {
    const match = line.match(/^\s*(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (!match) continue;
    if (!ALLOWED_ENV_KEYS.has(match[1])) continue;
    let value = match[2] || '';
    const hashIndex = value.search(/\s+#/);
    if (hashIndex >= 0) value = value.slice(0, hashIndex);
    values[match[1]] = stripQuotes(value);
  }
  return values;
}

function ownerEnvFiles(home: string): string[] {
  return [
    path.join(home, '.marrow', 'env.local'),
    path.join(home, '.marrow', 'env'),
  ];
}

function repoEnvFiles(cwd: string, ownerFiles: string[]): string[] {
  const files: string[] = [];
  let dir = path.resolve(cwd || process.cwd());
  for (let depth = 0; depth < 8; depth += 1) {
    files.push(path.join(dir, '.marrow', 'env.local'));
    files.push(path.join(dir, '.marrow', 'env'));
    files.push(path.join(dir, '.env.local'));
    files.push(path.join(dir, '.env'));
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return [...new Set(files)].filter((file) => !ownerFiles.includes(file));
}

function pickKey(env: Record<string, string | undefined>): { key: string; source: string | null } {
  if (env.MARROW_API_KEY) return { key: env.MARROW_API_KEY, source: 'MARROW_API_KEY' };
  if (env.MARROW_KEY) return { key: env.MARROW_KEY, source: 'MARROW_KEY' };
  return { key: '', source: null };
}

function matchingFleetIdentity(
  env: Record<string, string | undefined>,
  agentId?: string,
): { key: string; agentId: string; source: string } | null {
  const want = String(agentId || '').trim();
  if (!want) return null;
  for (const [name, boundAgent] of Object.entries(env)) {
    const match = /^MARROW_AGENT_ID_([A-Z0-9]+)$/.exec(name);
    if (!match || String(boundAgent || '').trim() !== want) continue;
    const keyName = `MARROW_KEY_${match[1]}`;
    const key = String(env[keyName] || '').trim();
    if (!key) continue;
    return { key, agentId: want, source: keyName };
  }
  return null;
}

export function resolveMarrowEnv(options: {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  home?: string;
  trustedOnly?: boolean;
} = {}): ResolvedMarrowEnv {
  const env = options.env || process.env;
  const cwd = options.cwd || process.cwd();
  const home = options.home || env.HOME || env.USERPROFILE || os.homedir();
  const requestedAgentId = env.MARROW_FLEET_AGENT_ID || env.MARROW_AGENT_ID;
  const matchedIdentity = matchingFleetIdentity(env, requestedAgentId);
  const direct = pickKey(env);
  if (direct.key && matchedIdentity && matchedIdentity.key !== direct.key) {
    return {
      apiKey: matchedIdentity.key,
      baseUrl: env.MARROW_BASE_URL || DEFAULT_BASE_URL,
      agentId: matchedIdentity.agentId,
      sessionId: env.MARROW_SESSION_ID,
      source: matchedIdentity.source,
      missing: false,
      exactFix: 'Marrow key is matched to the configured agent identity from the process environment.',
    };
  }
  if (direct.key) {
    return {
      apiKey: direct.key,
      baseUrl: env.MARROW_BASE_URL || DEFAULT_BASE_URL,
      agentId: requestedAgentId,
      sessionId: env.MARROW_SESSION_ID,
      source: direct.source,
      missing: false,
      exactFix: 'Marrow key is loaded from the process environment.',
    };
  }

  // Owner files, in the same order and with the same check on the MCP and hook
  // paths. A file that fails the check supplies nothing, key included.
  const ownerFiles = ownerEnvFiles(home);
  let ignored: string | null = null;
  for (const filePath of ownerFiles) {
    const read = readOwnerEnvFile(filePath, home);
    if (read.status === 'rejected') {
      if (!ignored) ignored = ownerFileNotice(filePath, home);
      continue;
    }
    if (read.status !== 'trusted') continue;
    const found = pickKey(read.values);
    if (found.key) return fromFile(filePath, found, read.values, env);
  }
  if (options.trustedOnly === true) return missingKey(env, ignored);

  // Repository-level files (found by walking up from cwd) never supply a key or
  // any other Marrow setting, whatever their owner or mode: a umask-077 clone or a
  // mode-preserving archive yields a private file the owner never wrote. They are
  // read (bounded, non-blocking) only to tell the owner a key there was skipped.
  for (const filePath of repoEnvFiles(cwd, ownerFiles)) {
    try {
      fs.lstatSync(filePath);
    } catch {
      continue;
    }
    const peek = readEnvFile(filePath, false);
    if (pickKey(peek?.values || {}).key && !ignored) ignored = repoKeyNotice(filePath);
  }

  return missingKey(env, ignored);
}

function repoKeyNotice(filePath: string): string {
  return `Marrow key in ${printablePath(filePath)} ignored: keys are read only from ~/.marrow/env or your environment. Fix: ${REPO_KEY_FIX}.`;
}

function ownerFileNotice(filePath: string, home: string): string {
  const file = printablePath(filePath);
  // Windows reports no owner-only mode bits, so owner files never pass there.
  if (process.platform === 'win32') {
    return `Ignored the Marrow key in ${file}: owner-only file permissions cannot be confirmed on Windows. Fix: set MARROW_API_KEY in your environment or in the MCP client's env settings.`;
  }
  // The helper also refuses a home directory others can write, so name it too.
  let homeFix = '';
  try {
    const resolvedHome = path.resolve(home);
    if (resolvedHome !== path.dirname(path.resolve(filePath)) && (fs.lstatSync(resolvedHome).mode & 0o022) !== 0) {
      homeFix = ` && chmod go-w ${printablePath(resolvedHome)}`;
    }
  } catch {
    // Unreadable home: the generic advice stands.
  }
  return `Ignored the Marrow key in ${file}: the file is not owner-only (a symlink, readable or writable by others, owned by another user, or in a directory others can write). Fix: chmod 600 ${file} && chmod 700 ${printablePath(path.dirname(filePath))}${homeFix} (replace a symlink with the file itself).`;
}

function fromFile(
  filePath: string,
  found: { key: string; source: string | null },
  parsed: Record<string, string>,
  env: NodeJS.ProcessEnv,
): ResolvedMarrowEnv {
  return {
    apiKey: found.key,
    baseUrl: parsed.MARROW_BASE_URL || env.MARROW_BASE_URL || DEFAULT_BASE_URL,
    agentId: parsed.MARROW_FLEET_AGENT_ID || parsed.MARROW_AGENT_ID || env.MARROW_FLEET_AGENT_ID || env.MARROW_AGENT_ID,
    sessionId: parsed.MARROW_SESSION_ID || env.MARROW_SESSION_ID,
    source: `${filePath}:${found.source}`,
    missing: false,
    exactFix: `Marrow key was found in ${printablePath(filePath)}. Keep this file private and run npx @getmarrow/install doctor to verify.`,
  };
}

function missingKey(env: NodeJS.ProcessEnv, ignored: string | null): ResolvedMarrowEnv {
  return {
    apiKey: '',
    baseUrl: env.MARROW_BASE_URL || DEFAULT_BASE_URL,
    agentId: env.MARROW_FLEET_AGENT_ID || env.MARROW_AGENT_ID,
    sessionId: env.MARROW_SESSION_ID,
    source: null,
    missing: true,
    exactFix: 'Create an API key at https://getmarrow.ai, then export MARROW_API_KEY from trusted secret storage or place it in ~/.marrow/env with owner-only permissions before running npx -y --package=@getmarrow/mcp@latest marrow-mcp setup.'
      + (ignored ? `\n${ignored}` : ''),
  };
}
