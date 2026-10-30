import { createHash } from 'node:crypto';
import { closeSync, constants, lstatSync, mkdirSync, openSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const MARKER_FOLDER = 'session-markers';

/**
 * A once-per-host-session marker: a file named by the kind and a hash of the session id (never the id itself), created owner-only inside
 * `~/.marrow/session-markers` (mode 700). True only for the call that creates it; false for every later call of that session, and false
 * when the private folder cannot be used (a notice is then skipped rather than repeated on every hook call).
 */
export function claimSessionMarker(kind: string, sessionId: string, home: string = homedir()): boolean {
  try {
    if (!/^[a-z0-9-]{1,48}$/.test(kind) || !sessionId) return false;
    const marrow = join(home, '.marrow');
    const folder = join(marrow, MARKER_FOLDER);
    for (const directory of [marrow, folder]) {
      try { mkdirSync(directory, { mode: 0o700 }); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') return false; }
      const stat = lstatSync(directory);
      const uid = typeof process.getuid === 'function' ? process.getuid() : stat.uid;
      if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== uid || (stat.mode & 0o077) !== 0) return false;
    }
    const name = `${kind}-${createHash('sha256').update(`${kind}\n${sessionId}`).digest('hex').slice(0, 32)}`;
    const fd = openSync(join(folder, name), constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW || 0), 0o600);
    closeSync(fd);
    return true;
  } catch {
    return false;
  }
}
