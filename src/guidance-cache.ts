import { createHash } from 'crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from 'fs';
import { homedir } from 'os';
import { join } from 'path';

const MAX_CACHE_AGE_MS = 60 * 60 * 1000;
const MAX_CONTEXT_BYTES = 4_000;

interface GuidanceCacheRecord {
  version: 1;
  stored_at: string;
  context: string;
}

function cachePath(apiKey: string, baseUrl: string, agentId?: string, home = homedir()): string {
  const namespace = createHash('sha256')
    .update(`${baseUrl}|${apiKey}|${agentId || 'account'}`)
    .digest('hex')
    .slice(0, 24);
  const directory = join(home, '.marrow', 'cache');
  if (!existsSync(directory)) mkdirSync(directory, { recursive: true, mode: 0o700 });
  const stat = lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) {
    throw new Error('Marrow guidance cache directory must be owner-only and cannot be a symlink');
  }
  return join(directory, `guidance-${namespace}.json`);
}

export function writeGuidanceCache(input: {
  apiKey: string;
  baseUrl: string;
  agentId?: string;
  context: string;
  home?: string;
}): void {
  const context = input.context.slice(0, MAX_CONTEXT_BYTES);
  const path = cachePath(input.apiKey, input.baseUrl, input.agentId, input.home);
  if (existsSync(path) && lstatSync(path).isSymbolicLink()) throw new Error('Marrow guidance cache file cannot be a symlink');
  const temporary = `${path}.tmp-${process.pid}`;
  const record: GuidanceCacheRecord = { version: 1, stored_at: new Date().toISOString(), context };
  writeFileSync(temporary, JSON.stringify(record), { encoding: 'utf8', mode: 0o600, flag: 'w' });
  chmodSync(temporary, 0o600);
  renameSync(temporary, path);
}

export function readGuidanceCache(input: {
  apiKey: string;
  baseUrl: string;
  agentId?: string;
  home?: string;
}): { context: string; stale_ms: number } | null {
  const path = cachePath(input.apiKey, input.baseUrl, input.agentId, input.home);
  if (!existsSync(path)) return null;
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) return null;
  try {
    const record = JSON.parse(readFileSync(path, 'utf8')) as Partial<GuidanceCacheRecord>;
    const storedAt = Date.parse(String(record.stored_at || ''));
    const staleMs = Date.now() - storedAt;
    if (record.version !== 1 || !Number.isFinite(storedAt) || staleMs < 0 || staleMs > MAX_CACHE_AGE_MS) return null;
    if (typeof record.context !== 'string' || !record.context || Buffer.byteLength(record.context, 'utf8') > MAX_CONTEXT_BYTES) return null;
    return { context: record.context, stale_ms: staleMs };
  } catch {
    return null;
  }
}
