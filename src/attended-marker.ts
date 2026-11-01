import { createHash, randomBytes } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

/**
 * Attended evidence for a Claude Code session: the owner typed a prompt in it recently. Claude Code's "ask" is an
 * open-ended dialog, so a hold may open one only while somebody is there to answer it; otherwise the hold is a denial.
 *
 * The marker is written only by the UserPromptSubmit hook and holds one millisecond timestamp (no prompt text, no key,
 * no session id): a file named by a hash of the session id inside `~/.marrow/attended-prompts` (mode 700, owner-only,
 * and under `.marrow`, which the self-protect check keeps agents from writing). Anything that is not a plain,
 * owner-only file with a past timestamp inside the window is no evidence: missing, unreadable, empty, malformed,
 * future-dated, another session's, a symlink, or group/world accessible.
 */
export const ATTENDED_WINDOW_MS = 10 * 60 * 1000;

const FOLDER = 'attended-prompts';
const MAX_SESSION_ID = 256;
const STAMP = /^[0-9]{10,16}\n?$/;

function markerName(sessionId: string): string {
  return createHash('sha256').update(`attended-prompt\n${sessionId}`).digest('hex').slice(0, 32);
}

function usableId(sessionId: unknown): sessionId is string {
  return typeof sessionId === 'string' && sessionId.trim().length > 0 && sessionId.length <= MAX_SESSION_ID;
}

function ownerOnly(stat: { uid: number; mode: number }): boolean {
  const uid = typeof process.getuid === 'function' ? process.getuid() : stat.uid;
  return stat.uid === uid && (stat.mode & 0o077) === 0;
}

/** Notes that the owner just typed a prompt in this session. False (and nothing written) when the private folder cannot be used. */
export function recordAttendedPrompt(sessionId: unknown, options: { now?: number; home?: string } = {}): boolean {
  if (!usableId(sessionId)) return false;
  try {
    const marrow = join(options.home ?? homedir(), '.marrow');
    const folder = join(marrow, FOLDER);
    for (const directory of [marrow, folder]) {
      try { mkdirSync(directory, { mode: 0o700 }); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') return false; }
      const stat = lstatSync(directory);
      if (!stat.isDirectory() || stat.isSymbolicLink() || !ownerOnly(stat)) return false;
    }
    const target = join(folder, markerName(sessionId));
    const scratch = join(folder, `.tmp-${process.pid}-${randomBytes(6).toString('hex')}`);
    const fd = openSync(scratch, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW || 0), 0o600);
    try {
      writeSync(fd, `${Math.trunc(options.now ?? Date.now())}\n`);
    } finally {
      closeSync(fd);
    }
    try {
      renameSync(scratch, target);
    } catch (error) {
      try { unlinkSync(scratch); } catch { /* best effort */ }
      throw error;
    }
    return true;
  } catch {
    return false;
  }
}

/** True only when this session's marker is a plain owner-only file whose timestamp is not in the future and is under ATTENDED_WINDOW_MS old. */
export function attendedWithin(sessionId: unknown, options: { now?: number; home?: string; windowMs?: number } = {}): boolean {
  if (!usableId(sessionId)) return false;
  try {
    const marrow = join(options.home ?? homedir(), '.marrow');
    const folder = join(marrow, FOLDER);
    for (const directory of [marrow, folder]) {
      const stat = lstatSync(directory);
      if (!stat.isDirectory() || stat.isSymbolicLink() || !ownerOnly(stat)) return false;
    }
    const path = join(folder, markerName(sessionId));
    const link = lstatSync(path);
    if (!link.isFile() || link.isSymbolicLink() || !ownerOnly(link) || link.size === 0 || link.size > 32) return false;
    const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    let text: string;
    try {
      const stat = fstatSync(fd);
      if (!stat.isFile() || !ownerOnly(stat) || stat.ino !== link.ino || stat.dev !== link.dev) return false;
      text = readFileSync(fd, 'utf8');
    } finally {
      closeSync(fd);
    }
    if (!STAMP.test(text)) return false;
    const stamp = Number(text.trim());
    const now = options.now ?? Date.now();
    const age = now - stamp;
    return Number.isSafeInteger(stamp) && age >= 0 && age < (options.windowMs ?? ATTENDED_WINDOW_MS);
  } catch {
    return false;
  }
}

const MAX_PROMPT_PAYLOAD_BYTES = 8 * 1024 * 1024;

/**
 * The UserPromptSubmit entry's tap: reads the same stdin payload the context hook reads (a second listener, attached before
 * the hook attaches its own, so both see every chunk) and, at its end, notes that the owner typed in this session. Only a
 * Claude Code prompt payload counts: the harness is Claude Code (or the generic entrypoint it spawned), the event name is
 * UserPromptSubmit when given, the prompt is a non-empty string and the session id is a string. Nothing from the payload
 * but that session id's hash and the time is kept. It never writes to stdout and never throws.
 */
export function tapAttendedPrompt(harness: string, stdin: NodeJS.ReadableStream = process.stdin): void {
  if (harness !== 'claude-code' && harness !== 'mcp-client') return;
  try {
    const chunks: Buffer[] = [];
    let size = 0;
    stdin.on('data', (chunk: Buffer | string) => {
      const buffer = typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
      size += buffer.length;
      if (size <= MAX_PROMPT_PAYLOAD_BYTES) chunks.push(buffer);
    });
    stdin.once('end', () => {
      try {
        if (size > MAX_PROMPT_PAYLOAD_BYTES) return;
        const payload = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown> | null;
        if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return;
        if (payload.hook_event_name !== undefined && payload.hook_event_name !== 'UserPromptSubmit') return;
        if (typeof payload.prompt !== 'string' || !payload.prompt.trim()) return;
        recordAttendedPrompt(payload.session_id);
      } catch { /* no marker: the session simply has no attended evidence */ }
    });
  } catch { /* never affects the hook */ }
}
