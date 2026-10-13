export type SeatbeltFsEntryType = 'file' | 'dir' | 'symlink' | 'other';
export interface SeatbeltFsEntry {
    type: SeatbeltFsEntryType;
    size: number;
    uid: number;
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
/**
 * The host filesystem. Case-insensitivity is probed, not assumed from the
 * platform (macOS volumes can be case-sensitive; Linux dirs can casefold): the
 * nearest existing ancestor with a letter in its name is looked up with its
 * case swapped, and only the same inode proves folding. Results are cached per
 * probed directory.
 */
export declare function nodeSeatbeltFs(): SeatbeltFs;
//# sourceMappingURL=seatbelt-fs.d.ts.map