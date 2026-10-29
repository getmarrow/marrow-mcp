import { createHash } from 'node:crypto';
import { closeSync, constants, lstatSync, mkdirSync, openSync, readdirSync, unlinkSync, type Stats } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { CONTROL_STATE_DIRECTORY, controlStatePath } from './control-state';

export const CONTROL_STATUS_COMMAND = 'npx @getmarrow/install control status';
const NOTICE_DIRECTORY = 'control-notice';
const MAX_MARKERS = 200;

/** The control file's path as plain text (the file's contents are never read into a message). */
function plainPath(home?: string): string {
  let path = '~/.marrow/control.json';
  try { path = controlStatePath(home || homedir()); } catch { /* no home directory: name the usual place */ }
  return path.replace(/[\u0000-\u001f\u007f]/g, ' ');
}

/** Appended to the pre-action deny text: the fix first, so a host's length limit trims the path before it trims the fix. */
export function unreadableControlSuffix(home?: string): string {
  return ` Fix: run \`${CONTROL_STATUS_COMMAND}\`. File: ${plainPath(home)}`;
}

/** One plain notice for the person: control stays ON, what to run, which file. */
export function unreadableControlNotice(home?: string): string {
  return `Marrow cannot read its local control file, so Marrow keeps checking actions as if control were on. Run \`${CONTROL_STATUS_COMMAND}\` to see what is wrong. File: ${plainPath(home)}`;
}

function ownDirectory(stat: Stats): boolean {
  return stat.isDirectory() && !stat.isSymbolicLink()
    && stat.uid === (typeof process.getuid === 'function' ? process.getuid() : stat.uid);
}

/**
 * True when this session has not been told yet (and is now marked as told), false when it has.
 * The marker is an empty owner-only file named by a hash of the session key, under ~/.marrow/control-notice.
 * When a marker cannot be stored safely (no ~/.marrow, a link or another owner's directory) the answer is
 * true: a repeated notice is better than a silent one, and nothing is ever written through a link.
 */
export function claimUnreadableControlNotice(sessionKey: string, home?: string): boolean {
  try {
    const marrow = join(home || homedir(), CONTROL_STATE_DIRECTORY);
    if (!ownDirectory(lstatSync(marrow))) return true;
    const directory = join(marrow, NOTICE_DIRECTORY);
    try { mkdirSync(directory, { mode: 0o700 }); } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    }
    if (!ownDirectory(lstatSync(directory))) return true;
    const name = createHash('sha256').update(sessionKey).digest('hex').slice(0, 32);
    closeSync(openSync(join(directory, name), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0), 0o600));
    pruneMarkers(directory);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== 'EEXIST';
  }
}

function pruneMarkers(directory: string): void {
  try {
    const markers = readdirSync(directory)
      .map((name) => ({ name, at: lstatSync(join(directory, name)).mtimeMs }))
      .sort((a, b) => a.at - b.at);
    for (const marker of markers.slice(0, Math.max(0, markers.length - MAX_MARKERS))) unlinkSync(join(directory, marker.name));
  } catch { /* best effort: a stale marker only means one more notice */ }
}
