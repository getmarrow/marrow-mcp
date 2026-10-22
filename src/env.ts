import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const DEFAULT_BASE_URL = 'https://api.getmarrow.ai';
const ALLOWED_ENV_KEYS = new Set([
  'MARROW_API_KEY',
  'MARROW_KEY',
  'MARROW_BASE_URL',
  'MARROW_ALLOWED_BASE_URLS',
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
  /** Set when a base URL from the process environment was not used with an owner-file key. Names the source only, never a value. */
  baseUrlNotice?: string;
  /** Set only on a no-key result: an owner key file exists but failed the owner-only check, so whatever it holds was refused. */
  ownerFileRefused?: boolean;
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

// Shell operand for a chmod command built from the REAL path. Returns null when
// the path cannot be printed faithfully (control/format/line-separator characters
// or longer than the print cap), so advice never targets a shortened or '?' path.
function shellOperand(realPath: string): string | null {
  if (/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(realPath) || Array.from(realPath).length > MAX_PRINTED_PATH) return null;
  if (/^[A-Za-z0-9_@%+=:,./][A-Za-z0-9_@%+=:,./-]*$/.test(realPath)) return realPath;
  return `'${realPath.replace(/'/g, `'\\''`)}'`;
}

// Where an owner-file key may be sent. A key read from ~/.marrow/env goes only to the
// default endpoint, the endpoint that same file names (MARROW_BASE_URL), or an exact
// origin that file lists in MARROW_ALLOWED_BASE_URLS. A base URL that only the process
// environment names (a project .mcp.json or .claude/settings.json env block, direnv, a
// devcontainer) never moves it. A key from the process environment is unchanged.
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

// Strict parse of a URL a key may be sent to: https, or http on a loopback host only.
// No credentials, query, fragment, wildcard, whitespace, control or format characters.
function parseKeyTarget(value: unknown): URL | null {
  const text = String(value ?? '').trim();
  if (!text || /[\s\p{Cc}\p{Cf}\\*?#@]/u.test(text)) return null;
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return null;
  }
  if (url.username || url.password || url.search || url.hash) return null;
  if (url.protocol === 'https:') return url;
  if (url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname)) return url;
  return null;
}

function isRootPath(url: URL): boolean {
  return url.pathname === '/' || url.pathname === '';
}

// Exact origins only: an entry with a path, credentials, query, fragment or wildcard is skipped.
function allowedOrigins(value: string | undefined): Set<string> {
  const origins = new Set<string>();
  for (const entry of String(value || '').split(',')) {
    const url = parseKeyTarget(entry);
    if (url && isRootPath(url)) origins.add(url.origin);
  }
  return origins;
}

function ownerKeyBaseUrl(
  filePath: string,
  parsed: Record<string, string>,
  env: NodeJS.ProcessEnv,
): { baseUrl: string; notice?: string } {
  // The owner file names its own endpoint: the existing precedence, the env URL is not consulted.
  if (parsed.MARROW_BASE_URL) return { baseUrl: parsed.MARROW_BASE_URL };
  const candidate = String(env.MARROW_BASE_URL || '').trim();
  if (!candidate) return { baseUrl: DEFAULT_BASE_URL };
  const target = parseKeyTarget(candidate);
  if (target && target.origin === new URL(DEFAULT_BASE_URL).origin && isRootPath(target)) return { baseUrl: DEFAULT_BASE_URL };
  if (target && allowedOrigins(parsed.MARROW_ALLOWED_BASE_URLS).has(target.origin)) {
    return { baseUrl: `${target.origin}${target.pathname.replace(/\/+$/, '')}` };
  }
  return {
    baseUrl: DEFAULT_BASE_URL,
    notice: `ignored MARROW_BASE_URL from the process environment: the key comes from ~/.marrow/${path.basename(filePath)}; list the URL in MARROW_ALLOWED_BASE_URLS in that file to allow it`,
  };
}

const emittedNotices = new Set<string>();

/** Writes a resolver notice to stderr once per process. Notices name a source, never a key or a URL. */
export function emitBaseUrlNotice(resolved: { baseUrlNotice?: string }): void {
  const notice = resolved.baseUrlNotice;
  if (!notice || emittedNotices.has(notice)) return;
  emittedNotices.add(notice);
  try {
    process.stderr.write(`[marrow] ${notice}\n`);
  } catch {
    // A closed stderr never changes the decision.
  }
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
  const read = readEnvFile(resolvedFile, true, Infinity);
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
// regular files. Only untrusted repo files are size-capped (maxBytes); owner files
// keep base parity (no cap), so a file base accepted is never turned into no-key.
// noFollow refuses a symlink at open time where supported.
function readEnvFile(filePath: string, noFollow: boolean, maxBytes: number): EnvFileRead | null {
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
    if (!stat.isFile() || stat.size > maxBytes) return null;
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
  let ownerFileRefused = false;
  for (const filePath of ownerFiles) {
    const read = readOwnerEnvFile(filePath, home);
    if (read.status === 'rejected') {
      ownerFileRefused = true;
      if (!ignored) ignored = ownerFileNotice(filePath, home);
      continue;
    }
    if (read.status !== 'trusted') continue;
    const found = pickKey(read.values);
    if (found.key) return fromFile(filePath, found, read.values, env);
  }
  if (options.trustedOnly === true) return missingKey(env, ignored, ownerFileRefused);

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
    const peek = readEnvFile(filePath, false, MAX_ENV_FILE_BYTES);
    if (pickKey(peek?.values || {}).key && !ignored) ignored = repoKeyNotice(filePath);
  }

  return missingKey(env, ignored, ownerFileRefused);
}

function repoKeyNotice(filePath: string): string {
  return `Marrow key in ${printablePath(filePath)} ignored: keys are read only from ~/.marrow/env or your environment. Fix: ${REPO_KEY_FIX}.`;
}

function symlinkInChain(filePath: string): 'file' | 'folder' | null {
  try {
    if (fs.lstatSync(filePath).isSymbolicLink()) return 'file';
  } catch {
    // Missing or unreadable: not a link we can name.
  }
  let dir = path.dirname(path.resolve(filePath));
  for (;;) {
    try {
      if (fs.lstatSync(dir).isSymbolicLink()) return 'folder';
    } catch {
      // Keep walking up.
    }
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

function ownerFileNotice(filePath: string, home: string): string {
  const file = printablePath(filePath);
  // Windows reports no owner-only mode bits, so owner files never pass there.
  if (process.platform === 'win32') {
    return `Ignored the Marrow key in ${file}: owner-only file permissions cannot be confirmed on Windows. Fix: set MARROW_API_KEY in your environment or in the MCP client's env settings.`;
  }
  // The helper also refuses a home directory others can write, so name it too.
  let homeDir: string | null = null;
  try {
    const resolvedHome = path.resolve(home);
    if (resolvedHome !== path.dirname(path.resolve(filePath)) && (fs.lstatSync(resolvedHome).mode & 0o022) !== 0) {
      homeDir = resolvedHome;
    }
  } catch {
    // Unreadable home: the generic advice stands.
  }
  // chmod follows a symlink and would change its target while the link stays
  // refused, so a symlinked file or folder gets no chmod operand on that path.
  const lead = `Ignored the Marrow key in ${file}: the file is not owner-only (a symlink, readable or writable by others, owned by another user, or in a directory others can write).`;
  const link = symlinkInChain(filePath);
  if (link === 'file') {
    return `${lead} Fix: replace the symlink with the real file (owner-only, mode 600); do not run chmod on the link.`;
  }
  if (link === 'folder') {
    return `${lead} Fix: remove the symlink from the folder chain so the path uses real folders only, then make the file owner-only (mode 600); do not run chmod through the link.`;
  }
  const tail = ' (replace a symlink with the file itself)';
  // Command operands use the real paths, quoted; if any cannot be printed safely, name no path.
  const dirOp = shellOperand(path.dirname(filePath));
  const fileOp = shellOperand(filePath);
  const homeOp = homeDir === null ? '' : shellOperand(homeDir);
  if (fileOp !== null && dirOp !== null && homeOp !== null) {
    const homeFix = homeDir === null ? '' : ` && chmod go-w ${homeOp}`;
    return `${lead} Fix: chmod 600 ${fileOp} && chmod 700 ${dirOp}${homeFix}${tail}.`;
  }
  const homeText = homeDir === null ? '' : ' and chmod go-w on your home folder';
  return `${lead} Fix: run chmod 600 on the file named above and chmod 700 on its folder${homeText}${tail}.`;
}

function fromFile(
  filePath: string,
  found: { key: string; source: string | null },
  parsed: Record<string, string>,
  env: NodeJS.ProcessEnv,
): ResolvedMarrowEnv {
  const target = ownerKeyBaseUrl(filePath, parsed, env);
  return {
    apiKey: found.key,
    baseUrl: target.baseUrl,
    ...(target.notice ? { baseUrlNotice: target.notice } : {}),
    agentId: parsed.MARROW_FLEET_AGENT_ID || parsed.MARROW_AGENT_ID || env.MARROW_FLEET_AGENT_ID || env.MARROW_AGENT_ID,
    sessionId: parsed.MARROW_SESSION_ID || env.MARROW_SESSION_ID,
    source: `${filePath}:${found.source}`,
    missing: false,
    exactFix: `Marrow key was found in ${printablePath(filePath)}. Keep this file private and run npx @getmarrow/install doctor to verify.`,
  };
}

function missingKey(env: NodeJS.ProcessEnv, ignored: string | null, ownerFileRefused: boolean): ResolvedMarrowEnv {
  return {
    apiKey: '',
    baseUrl: env.MARROW_BASE_URL || DEFAULT_BASE_URL,
    agentId: env.MARROW_FLEET_AGENT_ID || env.MARROW_AGENT_ID,
    sessionId: env.MARROW_SESSION_ID,
    source: null,
    missing: true,
    ...(ownerFileRefused ? { ownerFileRefused: true } : {}),
    exactFix: 'Create an API key at https://getmarrow.ai, then export MARROW_API_KEY from trusted secret storage or place it in ~/.marrow/env with owner-only permissions before running npx -y --package=@getmarrow/mcp@latest marrow-mcp setup.'
      + (ignored ? `\n${ignored}` : ''),
  };
}
