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

export interface ResolvedMarrowEnv {
  apiKey: string;
  baseUrl: string;
  agentId?: string;
  sessionId?: string;
  source: string | null;
  missing: boolean;
  exactFix: string;
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

function parseEnvFile(filePath: string, trustedHome?: string): Record<string, string> {
  if (!fs.existsSync(filePath)) return {};
  if (trustedHome && !isPrivateOwnerFile(filePath, trustedHome)) return {};
  const values: Record<string, string> = {};
  const raw = fs.readFileSync(filePath, 'utf8');
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

function candidateEnvFiles(cwd: string, home: string, trustedOnly: boolean): string[] {
  const ownerFiles = [
    path.join(home, '.marrow', 'env.local'),
    path.join(home, '.marrow', 'env'),
  ];
  if (trustedOnly) return ownerFiles;

  const files: string[] = [...ownerFiles];
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
  return [...new Set(files)];
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

  for (const filePath of candidateEnvFiles(cwd, home, options.trustedOnly === true)) {
    const parsed = parseEnvFile(filePath, options.trustedOnly === true ? home : undefined);
    const found = pickKey(parsed);
    if (!found.key) continue;
    return {
      apiKey: found.key,
      baseUrl: parsed.MARROW_BASE_URL || env.MARROW_BASE_URL || DEFAULT_BASE_URL,
      agentId: parsed.MARROW_FLEET_AGENT_ID || parsed.MARROW_AGENT_ID || env.MARROW_FLEET_AGENT_ID || env.MARROW_AGENT_ID,
      sessionId: parsed.MARROW_SESSION_ID || env.MARROW_SESSION_ID,
      source: `${filePath}:${found.source}`,
      missing: false,
      exactFix: `Marrow key was found in ${filePath}. Keep this file private and run npx @getmarrow/install doctor to verify.`,
    };
  }

  return {
    apiKey: '',
    baseUrl: env.MARROW_BASE_URL || DEFAULT_BASE_URL,
    agentId: env.MARROW_FLEET_AGENT_ID || env.MARROW_AGENT_ID,
    sessionId: env.MARROW_SESSION_ID,
    source: null,
    missing: true,
    exactFix: 'Create an API key at https://getmarrow.ai, then export MARROW_API_KEY from trusted secret storage or place it in ~/.marrow/env with owner-only permissions before running npx -y --package=@getmarrow/mcp@latest marrow-mcp setup.',
  };
}
