import { randomBytes } from 'crypto';
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readSync, renameSync, unlinkSync, writeSync } from 'fs';
import { homedir } from 'os';
import { join, parse, resolve, sep } from 'path';
import { strictClientUpdate } from './hook-context';
import { MCP_ADAPTER_VERSION } from './hook-contract';
import { localClientUpdate } from './request-reliability';

// The update notice (FIXVER N1-N5): one fixed line built here from two strict versions and the client's own update
// command, never a server string. It changes no decision, hold, key, body or event; it is only printed.
const STATE_NAME = 'update-notice.json';
const STATE_LIMIT = 1024;

/** N5: MARROW_UPDATE_NOTICE=off (also 0, false, no): no line on any surface and no state read or write. */
export function updateNoticeOff(): boolean {
  return ['off', '0', 'false', 'no'].includes(process.env.MARROW_UPDATE_NOTICE as string);
}

// A plain release: three dot-separated runs of ASCII digits, nothing else.
function plainRelease(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 32 && /^(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})$/.test(value);
}

function notice(answer: unknown): { line: string; installed: string; latest: string } | null {
  const strict = updateNoticeOff() ? null : strictClientUpdate(answer);
  if (!strict || (strict.priority !== 'recommended' && strict.priority !== 'security_required')) return null;
  // N1: the raw fields exactly: this client's own version and a plain newer release.
  const installed = strict.update.installed_version;
  const latest = strict.update.latest_version;
  if (installed !== MCP_ADAPTER_VERSION || !plainRelease(latest) || strict.currentVersion !== installed || strict.latestVersion !== latest) return null;
  const head = strict.priority === 'security_required' ? 'Marrow security update' : 'Marrow update';
  const line = `${head}: this agent runs @getmarrow/mcp ${installed}; ${latest} is out. Tell the user to run: ${localClientUpdate().auto_update_command} (then restart the host).`;
  return line.length <= 200 ? { line, installed, latest } : null;
}

/** The status tool's line: shown on every call while N1 holds (no state). */
export function updateNoticeLine(...answers: unknown[]): string | null {
  return answers.map(notice).find(Boolean)?.line ?? null;
}

// N4: the owner-private Marrow state folder, checked like the lifecycle spool parent (no symlinked component, no
// group- or world-writable non-sticky ancestor, owned by this user, owner-only). Null = unsafe.
function stateFolder(): string | null {
  if (process.platform === 'win32' || typeof process.getuid !== 'function') return null;
  const folder = join(resolve(homedir()), '.marrow');
  try { mkdirSync(folder, { mode: 0o700 }); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'EEXIST') return null; }
  let current = parse(folder).root;
  for (const segment of folder.slice(current.length).split(sep).filter(Boolean)) {
    current = join(current, segment);
    const stat = lstatSync(current);
    if (stat.isSymbolicLink() || !stat.isDirectory() || ((stat.mode & 0o022) !== 0 && (stat.mode & 0o1000) === 0)) return null;
  }
  const stat = lstatSync(folder);
  return stat.uid === process.getuid() && (stat.mode & 0o077) === 0 ? folder : null;
}

// 'shown' only for an owner-only regular file holding exactly today's record for this pair; links and FIFOs are unsafe.
function readState(path: string, record: string): 'shown' | 'not_shown' | 'unsafe' {
  let descriptor: number;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'ENOENT' ? 'not_shown' : 'unsafe';
  }
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile() || stat.uid !== process.getuid!() || (stat.mode & 0o077) !== 0) return 'unsafe';
    const buffer = Buffer.alloc(STATE_LIMIT + 1);
    const length = stat.size > STATE_LIMIT ? 0 : readSync(descriptor, buffer, 0, buffer.length, 0);
    return length > 0 && length <= STATE_LIMIT && buffer.subarray(0, length).toString('utf8') === record ? 'shown' : 'not_shown';
  } catch {
    return 'not_shown';
  } finally {
    closeSync(descriptor);
  }
}

// A new temporary file in the same folder, then a rename over the state name (never written through a link).
function writeState(folder: string, record: string): boolean {
  const temporary = join(folder, `.update-notice.${process.pid}.${randomBytes(6).toString('hex')}.tmp`);
  try {
    const descriptor = openSync(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    try { writeSync(descriptor, record); } finally { closeSync(descriptor); }
    renameSync(temporary, join(folder, STATE_NAME));
    return true;
  } catch {
    try { unlinkSync(temporary); } catch { /* never created */ }
    return false;
  }
}

/** The hooks' line: at most once per UTC day per (installed, latest) pair; an unsafe or unwritable state shows none. Never throws. */
export function hookUpdateNotice(answer: unknown): string | null {
  try {
    const found = notice(answer);
    const folder = found ? stateFolder() : null;
    if (!found || !folder) return null;
    const record = JSON.stringify({ v: 1, installed: found.installed, latest: found.latest, day: new Date().toISOString().slice(0, 10) });
    return readState(join(folder, STATE_NAME), record) === 'not_shown' && writeState(folder, record) ? found.line : null;
  } catch {
    return null;
  }
}

/** N3, pre-action: only into the separate additionalContext of a Claude Code or Codex answer that neither denies nor asks. */
export function withPreActionNotice(output: Record<string, unknown>, harness: string, result: { runtime?: unknown; outage?: boolean; timedOut?: boolean }): Record<string, unknown> {
  if ((harness !== 'claude-code' && harness !== 'codex') || result.outage || result.timedOut || !result.runtime) return output;
  const specific = output.hookSpecificOutput as Record<string, unknown> | undefined;
  if (Object.keys(output).length !== 1 || !specific || typeof specific !== 'object' || Array.isArray(specific)) return output;
  if ('permissionDecision' in specific || 'permissionDecisionReason' in specific || specific.hookEventName !== 'PreToolUse') return output;
  const line = hookUpdateNotice(result.runtime);
  if (!line) return output;
  const context = typeof specific.additionalContext === 'string' && specific.additionalContext ? `${specific.additionalContext}\n${line}` : line;
  return { hookSpecificOutput: { ...specific, additionalContext: context } };
}
