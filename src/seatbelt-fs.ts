import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readlinkSync, readSync, type Stats } from 'node:fs';

// The one filesystem view the seatbelt resolvers and mode resolution use. It is
// injected so every resolver is a pure function of (inputs, fs): tests drive an
// in-memory tree, including a case-insensitive one on hosts without APFS.

export type SeatbeltFsEntryType = 'file' | 'dir' | 'symlink' | 'other';

export interface SeatbeltFsEntry {
  type: SeatbeltFsEntryType;
  size: number;
  uid: number;
  /** Owning group. Optional: an entry without it never gets the private-group allowance (seatbelt-mode.ts). */
  gid?: number;
  mode: number;
  dev: number;
  ino: number;
}

export interface SeatbeltFs {
  /** lstat; null when the path does not exist. Any other failure throws. */
  lstat(path: string): SeatbeltFsEntry | null;
  readlink(path: string): string;
  /** A regular file's text, read without following a final symlink; null if it is not a regular file or is larger than maxBytes. Throws on other failures. */
  readFile(path: string, maxBytes: number): string | null;
  readdir(path: string): string[];
  /** True only when names on the volume holding path are proven to compare case-insensitively (APFS/HFS+ default, NTFS, casefold ext4). */
  caseInsensitive(path: string): boolean;
}

function entryOf(stat: Stats): SeatbeltFsEntry {
  const type: SeatbeltFsEntryType = stat.isSymbolicLink() ? 'symlink' : stat.isDirectory() ? 'dir' : stat.isFile() ? 'file' : 'other';
  return { type, size: stat.size, uid: stat.uid, gid: stat.gid, mode: stat.mode & 0o7777, dev: stat.dev, ino: stat.ino };
}

function swapCase(name: string): string {
  return name.replace(/[A-Za-z]/g, (ch) => (ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase()));
}

/**
 * The host filesystem. Case-insensitivity is probed, not assumed from the
 * platform (macOS volumes can be case-sensitive; Linux dirs can casefold): the
 * nearest existing ancestor with a letter in its name is looked up with its
 * case swapped, and only the same inode proves folding. Results are cached per
 * probed directory.
 */
export function nodeSeatbeltFs(): SeatbeltFs {
  const probed = new Map<string, boolean>();
  const probe = (path: string): boolean => {
    let dir = path;
    for (;;) {
      const cut = dir.lastIndexOf('/');
      const name = dir.slice(cut + 1);
      if (cut < 0 || dir === '/') return false;
      if (/[A-Za-z]/.test(name)) {
        const cached = probed.get(dir);
        if (cached !== undefined) return cached;
        let same: boolean | null = null;
        try {
          const a = lstatSync(dir);
          try {
            const b = lstatSync(`${dir.slice(0, cut)}/${swapCase(name)}`);
            same = a.dev === b.dev && a.ino === b.ino;
          } catch {
            same = false;
          }
        } catch {
          same = null;
        }
        if (same !== null) {
          probed.set(dir, same);
          return same;
        }
      }
      dir = dir.slice(0, cut) || '/';
    }
  };
  return {
    lstat(path) {
      try {
        return entryOf(lstatSync(path));
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === 'ENOENT' || code === 'ENOTDIR') return null;
        throw error;
      }
    },
    readlink: (path) => readlinkSync(path, 'utf8'),
    readFile(path, maxBytes) {
      // Non-blocking open so a planted FIFO cannot hang the hook; no final symlink.
      const fd = openSync(path, constants.O_RDONLY | (constants.O_NONBLOCK || 0) | (constants.O_NOFOLLOW || 0));
      try {
        const stat = fstatSync(fd);
        if (!stat.isFile() || stat.size > maxBytes) return null;
        const buffer = Buffer.alloc(stat.size + 1);
        let length = 0;
        while (length < buffer.length) {
          const read = readSync(fd, buffer, length, buffer.length - length, null);
          if (read <= 0) break;
          length += read;
        }
        if (length > stat.size) return null;
        return buffer.subarray(0, length).toString('utf8');
      } finally {
        closeSync(fd);
      }
    },
    readdir: (path) => readdirSync(path),
    caseInsensitive: (path) => probe(path),
  };
}
