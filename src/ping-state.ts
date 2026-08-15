import { createHash } from 'crypto';
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';

interface PingState {
  version: 1;
  last_success_at: string | null;
  samples_ms: number[];
}

export function resolvePingTimeoutMs(value: string | undefined): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return 2_500;
  return Math.min(5_000, Math.max(500, Math.floor(parsed)));
}

function statePath(apiKey: string, baseUrl: string, agentId?: string, home = homedir()): string {
  const namespace = createHash('sha256').update(`${baseUrl}|${apiKey}|${agentId || 'account'}`).digest('hex').slice(0, 24);
  const directory = join(home, '.marrow', 'health');
  if (!existsSync(directory)) mkdirSync(directory, { recursive: true, mode: 0o700 });
  const stat = lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) {
    throw new Error('Marrow health directory must be owner-only and cannot be a symlink');
  }
  return join(directory, `ping-${namespace}.json`);
}

function read(path: string): PingState {
  if (!existsSync(path)) return { version: 1, last_success_at: null, samples_ms: [] };
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0) throw new Error('Marrow health file is not private');
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as Partial<PingState>;
    const samples = Array.isArray(parsed.samples_ms)
      ? parsed.samples_ms.filter((value) => Number.isFinite(value) && value >= 0 && value <= 60_000).slice(-100)
      : [];
    return { version: 1, last_success_at: typeof parsed.last_success_at === 'string' ? parsed.last_success_at : null, samples_ms: samples };
  } catch {
    return { version: 1, last_success_at: null, samples_ms: [] };
  }
}

function percentile(values: number[], fraction: number): number | null {
  if (!values.length) return null;
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.max(0, Math.ceil(sorted.length * fraction) - 1)] ?? null;
}

export function updatePingState(input: {
  apiKey: string;
  baseUrl: string;
  agentId?: string;
  latencyMs?: number;
  success: boolean;
  home?: string;
}): { last_success_at: string | null; sample_count: number; p50_ms: number | null; p99_ms: number | null } {
  const path = statePath(input.apiKey, input.baseUrl, input.agentId, input.home);
  const state = read(path);
  if (input.success && Number.isFinite(input.latencyMs)) state.samples_ms.push(Math.max(0, Math.round(input.latencyMs!)));
  state.samples_ms = state.samples_ms.slice(-100);
  if (input.success) state.last_success_at = new Date().toISOString();
  const temporary = `${path}.tmp-${process.pid}`;
  writeFileSync(temporary, JSON.stringify(state), { encoding: 'utf8', mode: 0o600, flag: 'w' });
  chmodSync(temporary, 0o600);
  renameSync(temporary, path);
  return {
    last_success_at: state.last_success_at,
    sample_count: state.samples_ms.length,
    p50_ms: percentile(state.samples_ms, 0.50),
    p99_ms: percentile(state.samples_ms, 0.99),
  };
}
