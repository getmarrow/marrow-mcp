import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, type Stats } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export const CONTROL_STATE_VERSION = 1;
export const CONTROL_STATE_DIRECTORY = '.marrow';
export const CONTROL_STATE_FILENAME = 'control.json';
export const CONTROL_CHANGED_BY = 'owner_cli';
export const CONTROL_MAX_BYTES = 4096;
export const CONTROL_BYPASS_ACTION = 'protected action bypassed while local control disabled';

export type LocalControlState =
  | { enabled: true; state: 'default_enabled'; changed_at: null }
  | { enabled: boolean; state: 'enabled' | 'disabled'; changed_at: string; change_id: string };

export class UnsafeControlStateError extends Error {
  constructor() {
    super('Local Marrow control state is unsafe or invalid. Protected actions remain blocked; inspect ~/.marrow/control.json and run npx @getmarrow/install control status.');
    this.name = 'UnsafeControlStateError';
  }
}

export function controlStatePath(home = homedir()): string {
  return join(home, CONTROL_STATE_DIRECTORY, CONTROL_STATE_FILENAME);
}

function unsafe(): never { throw new UnsafeControlStateError(); }

function ownedPrivate(stat: Stats, mode: number): boolean {
  return !stat.isSymbolicLink()
    && stat.uid === (typeof process.getuid === 'function' ? process.getuid() : stat.uid)
    && (stat.mode & 0o777) === mode;
}

export function readLocalControlState(options: { home?: string } = {}): LocalControlState {
  const home = options.home || homedir();
  const directory = join(home, CONTROL_STATE_DIRECTORY);
  const target = controlStatePath(home);
  let directoryStat: Stats;
  try { directoryStat = lstatSync(directory); } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { enabled: true, state: 'default_enabled', changed_at: null };
    return unsafe();
  }
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()) return unsafe();
  let targetStat: Stats;
  try { targetStat = lstatSync(target); } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { enabled: true, state: 'default_enabled', changed_at: null };
    return unsafe();
  }
  if (!ownedPrivate(directoryStat, 0o700)) return unsafe();
  if (!targetStat.isFile() || !ownedPrivate(targetStat, 0o600) || targetStat.size < 2 || targetStat.size > CONTROL_MAX_BYTES) return unsafe();
  let fd = -1;
  try {
    fd = openSync(target, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.ino !== targetStat.ino || !ownedPrivate(opened, 0o600)) return unsafe();
    const raw = readFileSync(fd, 'utf8');
    if (Buffer.byteLength(raw) > CONTROL_MAX_BYTES) return unsafe();
    const value = JSON.parse(raw) as Record<string, unknown>;
    const keys = Object.keys(value).sort();
    if (keys.join(',') !== 'change_id,changed_at,changed_by,enabled,version') return unsafe();
    const changedAt = typeof value.changed_at === 'string' ? value.changed_at : '';
    const canonicalAt = changedAt && new Date(changedAt).toISOString() === changedAt;
    const valid = value.version === CONTROL_STATE_VERSION
      && typeof value.enabled === 'boolean'
      && value.changed_by === CONTROL_CHANGED_BY
      && canonicalAt
      && typeof value.change_id === 'string'
      && /^ctl_[a-f0-9]{32}$/.test(value.change_id);
    if (!valid) return unsafe();
    return { enabled: value.enabled as boolean, state: value.enabled ? 'enabled' : 'disabled', changed_at: changedAt, change_id: value.change_id as string };
  } catch (error) {
    if (error instanceof UnsafeControlStateError) throw error;
    return unsafe();
  } finally { if (fd >= 0) closeSync(fd); }
}

export function localControlEvidence(bypassRecordingAvailable: boolean): Record<string, unknown> {
  try {
    const control = readLocalControlState();
    return {
      enabled: control.enabled,
      state: control.state,
      changed_at: control.changed_at,
      bypass_recording_available: bypassRecordingAvailable,
      exact_next_action: control.enabled
        ? 'Run npx @getmarrow/install control disable --yes to disable local enforcement.'
        : 'Run npx @getmarrow/install control enable to resume local enforcement; hook processes poll this state without reinstalling.',
    };
  } catch {
    return { enabled: false, state: 'error', changed_at: null, bypass_recording_available: false, exact_next_action: 'Inspect and replace unsafe ~/.marrow/control.json, then run npx @getmarrow/install control status; protected actions remain blocked.' };
  }
}
