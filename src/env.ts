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

// Endpoint and identity settings. Only the process environment and private owner
// files (~/.marrow/env*) may set these; a repository file never can.
const ENDPOINT_IDENTITY_KEYS = ['MARROW_BASE_URL', 'MARROW_FLEET_AGENT_ID', 'MARROW_AGENT_ID', 'MARROW_SESSION_ID'] as const;
const MAX_ENV_FILE_BYTES = 1024 * 1024;
const OWNER_ENV_FIX = 'move the key to ~/.marrow/env (chmod 600) or export MARROW_API_KEY';

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
function printablePath(filePath: string): string {
  return filePath.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, '?');
}

function stripQuotes(value: string): string {
  const trimmed = String(value || '').trim();
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function isPrivateOwnerFile(filePath: string, home: string): boolean {
  try {
    const resolvedHome = path.resolve(home);
    const resolvedFile = path.resolve(filePath);
    const parent = path.dirname(resolvedFile);
    const homeStat = fs.lstatSync(resolvedHome);
    const parentStat = fs.lstatSync(parent);
    const fileStat = fs.lstatSync(resolvedFile);
    const uid = typeof process.getuid === 'function' ? process.getuid() : null;
    return resolvedFile.startsWith(`${resolvedHome}${path.sep}`)
      && homeStat.isDirectory() && !homeStat.isSymbolicLink() && fs.realpathSync(resolvedHome) === resolvedHome
      && parentStat.isDirectory() && !parentStat.isSymbolicLink() && fs.realpathSync(parent) === parent
      && fileStat.isFile() && !fileStat.isSymbolicLink()
      && (uid === null || fileStat.uid === uid && parentStat.uid === uid && homeStat.uid === uid)
      && (fileStat.mode & 0o077) === 0
      && (parentStat.mode & 0o022) === 0
      && (homeStat.mode & 0o022) === 0;
  } catch {
    return false;
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

function currentUid(): number | null {
  return typeof process.getuid === 'function' ? process.getuid() : null;
}

/**
 * Why a key in a repository-level file may not be used, or null when it may.
 * The file must be a regular, non-symlink file owned by this user with no
 * group/other permission bits, and every directory of its real parent chain
 * must be owned by this user or root and not group/other-writable.
 */
function repoKeyFileProblem(filePath: string, opened: fs.Stats | null): { reason: string; fix: string } | null {
  const uid = currentUid();
  const shown = printablePath(filePath);
  if (uid === null) return { reason: 'file ownership cannot be verified on this platform', fix: OWNER_ENV_FIX };
  let linkStat: fs.Stats;
  try {
    linkStat = fs.lstatSync(filePath);
  } catch {
    return { reason: 'file could not be inspected', fix: OWNER_ENV_FIX };
  }
  if (linkStat.isSymbolicLink() || !opened) return { reason: 'file is a symlink or not a regular file', fix: OWNER_ENV_FIX };
  if (!linkStat.isFile() || linkStat.ino !== opened.ino || linkStat.dev !== opened.dev) {
    return { reason: 'file changed while it was read', fix: OWNER_ENV_FIX };
  }
  if (opened.uid !== uid) return { reason: 'file is owned by another user', fix: OWNER_ENV_FIX };
  if ((opened.mode & 0o077) !== 0) return { reason: 'file is readable or writable by group/other', fix: `chmod 600 ${shown}` };
  let dir: string;
  try {
    dir = fs.realpathSync(path.dirname(filePath));
  } catch {
    return { reason: 'directory could not be resolved', fix: OWNER_ENV_FIX };
  }
  for (;;) {
    let dirStat: fs.Stats;
    try {
      dirStat = fs.lstatSync(dir);
    } catch {
      return { reason: 'directory could not be inspected', fix: OWNER_ENV_FIX };
    }
    if (!dirStat.isDirectory()) return { reason: 'directory could not be inspected', fix: OWNER_ENV_FIX };
    if ((dirStat.mode & 0o022) !== 0) {
      return { reason: `directory ${printablePath(dir)} is group/other-writable`, fix: OWNER_ENV_FIX };
    }
    if (dirStat.uid !== uid && dirStat.uid !== 0) {
      return { reason: `directory ${printablePath(dir)} is owned by another user`, fix: OWNER_ENV_FIX };
    }
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

function parseEnvFile(filePath: string, trustedHome?: string): Record<string, string> {
  if (!fs.existsSync(filePath)) return {};
  if (trustedHome && !isPrivateOwnerFile(filePath, trustedHome)) return {};
  return readEnvFile(filePath, false)?.values || {};
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

  const trustedOnly = options.trustedOnly === true;
  const ownerFiles = ownerEnvFiles(home);
  if (trustedOnly) {
    for (const filePath of ownerFiles) {
      const parsed = parseEnvFile(filePath, home);
      const found = pickKey(parsed);
      if (!found.key) continue;
      return fromFile(filePath, found, parsed, env);
    }
    return missingKey(env, null);
  }

  // Owner files keep today's precedence and key handling. Their endpoint and
  // identity settings count only when the file passes the private-owner check;
  // a key from a file whose endpoint is not trusted and differs from the one in
  // use is not sent anywhere.
  let ignored: string | null = null;
  const note = (filePath: string, reason: string, fix: string) => {
    if (!ignored) ignored = `Ignored the Marrow key in ${printablePath(filePath)}: ${reason}. Fix: ${fix}.`;
  };
  for (const filePath of ownerFiles) {
    if (!fs.existsSync(filePath)) continue;
    const read = readEnvFile(filePath, false);
    const found = pickKey(read?.values || {});
    if (!read || !found.key) continue;
    if (isPrivateOwnerFile(filePath, home)) return fromFile(filePath, found, read.values, env);
    if (namesOtherEndpoint(read.values, env)) {
      note(filePath, 'its MARROW_BASE_URL is ignored because the file is not owner-only',
        `chmod 600 ${printablePath(filePath)} && chmod 700 ${printablePath(path.dirname(filePath))}`);
      continue;
    }
    return fromFile(filePath, found, withoutEndpointIdentity(read.values), env);
  }

  // Repository-level files may supply only a key, and only from a private file.
  for (const filePath of repoEnvFiles(cwd, ownerFiles)) {
    let exists = false;
    try {
      fs.lstatSync(filePath);
      exists = true;
    } catch { /* absent */ }
    if (!exists) continue;
    const read = readEnvFile(filePath, true);
    const problem = repoKeyFileProblem(filePath, read?.stat || null);
    if (problem) {
      // Look (bounded, non-blocking) only to tell the owner a key was skipped.
      const peek = read || readEnvFile(filePath, false);
      if (pickKey(peek?.values || {}).key) note(filePath, problem.reason, problem.fix);
      continue;
    }
    const found = pickKey(read?.values || {});
    if (!read || !found.key) continue;
    if (namesOtherEndpoint(read.values, env)) {
      note(filePath, 'repository files cannot set MARROW_BASE_URL', OWNER_ENV_FIX);
      continue;
    }
    return fromFile(filePath, found, withoutEndpointIdentity(read.values), env);
  }

  return missingKey(env, ignored);
}

function withoutEndpointIdentity(values: Record<string, string>): Record<string, string> {
  const kept = { ...values };
  for (const name of ENDPOINT_IDENTITY_KEYS) delete kept[name];
  return kept;
}

// True when the file names a base URL other than the one that would be used.
function namesOtherEndpoint(values: Record<string, string>, env: NodeJS.ProcessEnv): boolean {
  if (!values.MARROW_BASE_URL) return false;
  return normalizeBaseUrl(values.MARROW_BASE_URL) !== normalizeBaseUrl(env.MARROW_BASE_URL || DEFAULT_BASE_URL);
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
