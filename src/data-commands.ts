import { closeSync, constants, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readSync, readFileSync, realpathSync, renameSync, unlinkSync, writeSync, type Stats } from 'node:fs';
import { createHash, randomInt } from 'node:crypto';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { readLocalControlState } from './control-state';
import { proveWindowsPrivate, realWindowsDeps, type WinObject, type WinProof } from './win-private-state';

/**
 * MCP-1b: owner-declared data commands.
 *
 * The owner teaches Marrow, once and in a terminal, that one of their own scripts only handles data (a board tool, a notes tool). The declaration is
 * `~/.marrow/data-commands.json`; a command that is exactly `<argv_prefix> <plain literal words>`, whose script still has the hash the owner saw, is then
 * judged by its effect like a data write (data-write.ts): its remaining words are data, not actions. Everything here fails closed: a file that fails any
 * check is ignored whole, an entry that fails any check never matches, and a segment that is not understood in full is not a match, so the
 * 3.9.109 classification runs byte for byte.
 */
export const DATA_COMMANDS_VERSION = 1;
export const DATA_COMMANDS_DIRECTORY = '.marrow';
export const DATA_COMMANDS_FILENAME = 'data-commands.json';
export const DATA_COMMANDS_MAX_BYTES = 4096;
export const DATA_COMMANDS_MAX_ENTRIES = 20;
export const DATA_COMMANDS_MAX_SCRIPT_BYTES = 1024 * 1024;
const MIN_WORDS = 2;
const MAX_WORDS = 8;

export type DataCommandEntry = { argv_prefix: string[]; sha256: string };
export type DataCommandsFile = { present: boolean; entries: DataCommandEntry[]; ignored: string | null };
/** One word of a parsed segment, as data-write.ts reads it: the text after quote removal and what the reader had to expand to get it. */
export type DeclaredWord = { text: string; date: boolean; expands: boolean; dollar: boolean; exotic: boolean; tilde: boolean };

export function dataCommandsPath(home = homedir()): string {
  return join(home, DATA_COMMANDS_DIRECTORY, DATA_COMMANDS_FILENAME);
}

function currentUid(): number | undefined {
  return typeof process.getuid === 'function' ? process.getuid() : undefined;
}
function ownedPrivate(stat: Stats, mode: number, uid: number | undefined): boolean {
  return !stat.isSymbolicLink() && (uid === undefined || stat.uid === uid) && (stat.mode & 0o777) === mode;
}
function ignoredFile(reason: string): DataCommandsFile {
  return { present: true, entries: [], ignored: `data-commands.json ignored: ${reason}` };
}

// ---- Windows (3.9.109 integration of MCP-1b with the Windows-lane port). ----------------------------
// Mode bits and uid mean nothing on Windows, so a 700 folder and a 600 file prove nothing there. On win32 the file is read only after the port's access-list
// proof (src/win-private-state.ts, the one the session loop guard uses) says that nobody but this user, SYSTEM and Administrators can change `~/.marrow`
// or read the file. No proof, no file: the whole declaration is ignored. The platform and the proof are one injectable set, as in session-loop-guard.ts:
// production uses process.platform and the real proof (PowerShell); a test passes its own deps through withDataCommandsPlatform(). There is no env switch.
export interface DataCommandsPlatform { platform: NodeJS.Platform; prove(home: string, objects: readonly WinObject[]): WinProof }
let injectedPlatform: DataCommandsPlatform | null = null;

export function withDataCommandsPlatform<T>(injected: DataCommandsPlatform, run: () => T): T {
  const previous = injectedPlatform;
  injectedPlatform = injected;
  try { return run(); } finally { injectedPlatform = previous; }
}
function isWin32(): boolean {
  return (injectedPlatform ? injectedPlatform.platform : process.platform) === 'win32';
}
/** True only when the port's proof accepts `~/.marrow` and the declaration file. Never throws; every doubt is false. */
function windowsAclProof(home: string): boolean {
  try {
    const objects: WinObject[] = [
      { rel: DATA_COMMANDS_DIRECTORY, kind: 'dir', policy: 'no_write_by_others' },
      { rel: `${DATA_COMMANDS_DIRECTORY}\\${DATA_COMMANDS_FILENAME}`, kind: 'file', policy: 'no_access_by_others' },
    ];
    const proof = injectedPlatform ? injectedPlatform.prove(home, objects) : proveWindowsPrivate({ home, objects }, realWindowsDeps());
    return proof.ok === true;
  } catch { return false; }
}
/**
 * Declared commands are off while the owner's control file is unreadable or invalid (the control-state fail-closed rule: that state is "control ON", never
 * quiet, and it is not a moment to widen anything). A missing control file, or a valid one, changes nothing here.
 */
function controlStateUnsafe(home: string | undefined): boolean {
  try { readLocalControlState({ home }); return false; } catch { return true; }
}
const CONTROL_UNSAFE_REASON = 'data-commands.json ignored: ~/.marrow/control.json cannot be read, so declared commands stay off until it is fixed (npx @getmarrow/install control status)';
const ABSENT: DataCommandsFile = { present: false, entries: [], ignored: null };
const SHA256 = /^[a-f0-9]{64}$/;
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * The declaration file, read with the checks control.json gets (control-state.ts): the folder is a real folder of mode 700 and the file a regular file of
 * mode 600, both owned by this user, no link on either, at most 4 KB, exact schema, at most 20 entries. Any failure ignores the whole file and says why in one line.
 */
export function readDataCommands(options: { home?: string; uid?: number } = {}): DataCommandsFile {
  const home = options.home || homedir();
  const uid = options.uid ?? currentUid();
  const windows = isWin32();
  const directory = join(home, DATA_COMMANDS_DIRECTORY);
  const target = dataCommandsPath(home);
  let directoryStat: Stats;
  try { directoryStat = lstatSync(directory); } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'ENOENT' ? ABSENT : ignoredFile('the ~/.marrow folder cannot be read');
  }
  if (directoryStat.isSymbolicLink() || !directoryStat.isDirectory()) return ignoredFile('~/.marrow is a link or not a folder');
  let targetStat: Stats;
  try { targetStat = lstatSync(target); } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'ENOENT' ? ABSENT : ignoredFile('the file cannot be read');
  }
  if (!windows && !ownedPrivate(directoryStat, 0o700, uid)) return ignoredFile('the ~/.marrow folder must be mode 700 with you as its owner');
  if (targetStat.isSymbolicLink()) return ignoredFile('the file is a symbolic link');
  if (!targetStat.isFile()) return ignoredFile('the file is not a regular file');
  if (!windows && !ownedPrivate(targetStat, 0o600, uid)) return ignoredFile('the file must be mode 600 with you as its owner');
  if (targetStat.size < 2 || targetStat.size > DATA_COMMANDS_MAX_BYTES) return ignoredFile(`the file must be 2 to ${DATA_COMMANDS_MAX_BYTES} bytes`);
  // Windows: the access-list proof is the only proof of "private" (mode bits are not). It starts PowerShell, so it runs once, here, before the file is read.
  if (windows && !windowsAclProof(home)) return ignoredFile('on Windows the ~/.marrow folder and the file need the access-list proof (only you, SYSTEM and Administrators), and it did not pass');
  let fd = -1;
  try {
    fd = openSync(target, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.ino !== targetStat.ino || (!windows && !ownedPrivate(opened, 0o600, uid))) return ignoredFile('the file changed while it was read');
    const raw = readFileSync(fd, 'utf8');
    if (Buffer.byteLength(raw) > DATA_COMMANDS_MAX_BYTES) return ignoredFile(`the file must be 2 to ${DATA_COMMANDS_MAX_BYTES} bytes`);
    let value: unknown;
    try { value = JSON.parse(raw); } catch { return ignoredFile('the file is not valid JSON'); }
    if (!isPlainObject(value) || Object.keys(value).sort().join(',') !== 'commands,version') return ignoredFile('the file does not have exactly the keys version and commands');
    if (value.version !== DATA_COMMANDS_VERSION) return ignoredFile('the version is not 1');
    const commands = value.commands;
    if (!Array.isArray(commands)) return ignoredFile('commands is not a list');
    if (commands.length > DATA_COMMANDS_MAX_ENTRIES) return ignoredFile(`more than ${DATA_COMMANDS_MAX_ENTRIES} entries`);
    const entries: DataCommandEntry[] = [];
    for (const item of commands) {
      if (!isPlainObject(item) || Object.keys(item).sort().join(',') !== 'argv_prefix,sha256') return ignoredFile('an entry does not have exactly the keys argv_prefix and sha256');
      const prefix = item.argv_prefix;
      if (!Array.isArray(prefix) || !prefix.every((word) => typeof word === 'string')) return ignoredFile('an argv_prefix is not a list of words');
      if (typeof item.sha256 !== 'string' || !SHA256.test(item.sha256)) return ignoredFile('a sha256 is not 64 lowercase hex characters');
      entries.push({ argv_prefix: [...prefix as string[]], sha256: item.sha256 });
    }
    return { present: true, entries, ignored: null };
  } catch { return ignoredFile('the file cannot be read'); } finally { if (fd >= 0) closeSync(fd); }
}

// ─── entry validity ───
// A prefix word is a plain literal: no space, quote, `$`, backtick, glob, brace or `~`, so the one reading of it is the same in every shell.
const SAFE_WORD = /^[A-Za-z0-9_@%+=:,./-]+$/;
const INTERPRETER = /^(?:bash|sh|zsh|dash|fish|node|perl|ruby|deno|bun|python[0-9.]*)$/;
const LAUNCHER = /^(?:env|sudo|doas|xargs|eval|exec|source|\.|npx|nohup|time|command|builtin|nice|ionice|timeout|stdbuf|setsid|su|ssh|watch|busybox|chroot|flock|strace|find|parallel|script|expect|screen|tmux|at|runuser|pkexec|systemd-run|docker|podman|nsenter|unshare)$/;
// Words that hand code (not a file) to an interpreter.
const CODE_FLAG = /^(?:-c|-e|--eval|-m|-p|--print|--command)$/;
const INTERPRETER_FLAGS: Record<string, Set<string>> = {
  python: new Set(['-I', '-B', '-u', '-s', '-S', '-E', '-O', '-OO', '-q', '-b', '-bb']),
};
function flagsFor(interpreter: string): Set<string> {
  return interpreter.startsWith('python') ? INTERPRETER_FLAGS.python : new Set();
}
function baseName(word: string): string {
  const cut = word.lastIndexOf('/');
  return cut < 0 ? word : word.slice(cut + 1);
}

/** Why `prefix` can never be an entry (no file is looked at), or null. The one path word is the script; an interpreter may only run that script directly. */
export function entryProblem(prefix: readonly string[]): string | null {
  if (!Array.isArray(prefix) || !prefix.every((word) => typeof word === 'string')) return 'argv_prefix must be a list of words';
  if (prefix.length < MIN_WORDS || prefix.length > MAX_WORDS) return `argv_prefix must have ${MIN_WORDS} to ${MAX_WORDS} words`;
  if (!prefix.every((word) => SAFE_WORD.test(word))) return 'every word must be plain letters, digits and - _ . / = : , @ % + (no space, quote, $, glob or ~)';
  const paths = prefix.map((word, at) => (word.includes('/') ? at : -1)).filter((at) => at >= 0);
  if (paths.length !== 1) return 'argv_prefix must contain exactly one absolute path, the script';
  const at = paths[0];
  const script = prefix[at];
  if (!script.startsWith('/') || script.endsWith('/') || script.split('/').slice(1).some((part) => part === '' || part === '.' || part === '..')) return 'the script path must be absolute and written plainly (no ., .. or double slash)';
  for (let index = 0; index < prefix.length; index += 1) {
    const word = prefix[index];
    if (CODE_FLAG.test(word)) return `${word} hands code to an interpreter; declare a script file instead`;
    if (index === 0 && INTERPRETER.test(word)) continue;
    if (LAUNCHER.test(baseName(word)) || INTERPRETER.test(baseName(word))) return `${word} is a shell, interpreter or launcher; only the first word may be an interpreter, running the script directly`;
  }
  if (at > 0) {
    const interpreter = prefix[0];
    if (!INTERPRETER.test(interpreter)) return 'the first word must be the script itself or an interpreter (python3, node, bash ...) that runs it';
    const allowed = flagsFor(interpreter);
    for (let index = 1; index < at; index += 1) {
      if (!allowed.has(prefix[index])) return `${prefix[index]} may not stand between the interpreter and the script`;
    }
  }
  return null;
}

type CheckedEntry = { ok: true; path: string; sha256: string } | { ok: false; reason: string };

/** The script's bytes through a descriptor that follows no link: a regular file of at most 1 MB, in a folder chain with no link at all. */
function readScript(path: string): { sha256: string } | { problem: string } {
  let fd = -1;
  try {
    const before = lstatSync(path);
    if (before.isSymbolicLink() || !before.isFile()) return { problem: 'the script is not a regular file (a link or a folder does not count)' };
    if (realpathSync(path) !== path) return { problem: 'the script path goes through a symbolic link' };
    if (before.size > DATA_COMMANDS_MAX_SCRIPT_BYTES) return { problem: 'the script is larger than 1 MB' };
    fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.ino !== before.ino || opened.size > DATA_COMMANDS_MAX_SCRIPT_BYTES) return { problem: 'the script changed while it was read' };
    const bytes = readFileSync(fd);
    if (bytes.length > DATA_COMMANDS_MAX_SCRIPT_BYTES) return { problem: 'the script is larger than 1 MB' };
    return { sha256: createHash('sha256').update(bytes).digest('hex') };
  } catch { return { problem: 'the script cannot be read' }; } finally { if (fd >= 0) try { closeSync(fd); } catch { /* nothing to release */ } }
}

function scriptOf(prefix: readonly string[]): string {
  return prefix.find((word) => word.includes('/')) as string;
}

/** An entry is usable now only if its prefix is valid, its script is a plain regular file of at most 1 MB with no link on the way, and its hash is the entry's. */
function checkEntry(entry: DataCommandEntry): CheckedEntry {
  const problem = entryProblem(entry.argv_prefix);
  if (problem) return { ok: false, reason: problem };
  const path = scriptOf(entry.argv_prefix);
  const read = readScript(path);
  if ('problem' in read) return { ok: false, reason: read.problem };
  if (read.sha256 !== entry.sha256) return { ok: false, reason: 'the script changed since it was declared' };
  return { ok: true, path, sha256: read.sha256 };
}

/** The path as the shell would reach it with no link on the way (`..` allowed), or null when any part is a link or missing. */
function linkFreePath(absolute: string): string | null {
  let current = '';
  for (const part of absolute.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') { current = current.slice(0, current.lastIndexOf('/')); continue; }
    const next = `${current}/${part}`;
    try { if (lstatSync(next).isSymbolicLink()) return null; } catch { return null; }
    current = next;
  }
  return current || '/';
}

// `exotic` covers a backslash and a `!` or `~` the shell may expand (history expansion in an interactive shell, tilde after `=`); inside single quotes they are text.
const plainWord = (word: DeclaredWord): boolean => !word.date && !word.expands && !word.dollar && !word.exotic && !word.tilde;

// A remaining word the script may read as a path is never a way into a hidden folder (~/.marrow, ~/.ssh, .git, an rc file) or a system folder: the
// command then keeps the 3.9.109 reading, where those paths are judged. A word with a space is prose (a note) and stays data.
const SYSTEM_ROOT = /^\/(?:etc|var|usr|bin|sbin|lib|lib32|lib64|proc|sys|boot|root|run|srv|dev)(?:\/|$)/;
function unsafePathWord(word: DeclaredWord): boolean {
  const text = word.text;
  if (/\s/.test(text) || text === '/dev/null') return false;
  if (!text.includes('/') && !/^\.[A-Za-z_]/.test(text)) return false;
  return SYSTEM_ROOT.test(text) || text.split('/').some((part) => part.startsWith('.'));
}

/**
 * Whether the words of one segment (program first) are an owner-declared data command: the first words equal an entry's argv_prefix, the script word
 * names the declared file with no link on the way, the script's hash now is the entry's, and every word after the prefix is a plain literal (no `$`,
 * backtick, glob, brace, `~`, backslash or substitution). Never throws; any doubt is false.
 */
export function declaredCommandMatch(words: readonly DeclaredWord[], options: { cwd?: string; home?: string } = {}): boolean {
  try {
    if (controlStateUnsafe(options.home)) return false;
    const file = readDataCommands({ home: options.home });
    if (!file.entries.length) return false;
    for (const entry of file.entries) {
      const prefix = entry.argv_prefix;
      if (words.length < prefix.length || entryProblem(prefix)) continue;
      const scriptAt = prefix.findIndex((word) => word.includes('/'));
      let same = true;
      for (let at = 0; at < prefix.length && same; at += 1) {
        const word = words[at];
        if (at === scriptAt) {
          if (word.date || word.expands || word.dollar || word.exotic) { same = false; break; }
          const absolute = word.text.startsWith('/') ? word.text : options.cwd && options.cwd.startsWith('/') && word.text ? `${options.cwd}/${word.text}` : '';
          same = absolute !== '' && !absolute.includes('\0') && linkFreePath(absolute) === prefix[at];
        } else same = plainWord(word) && word.text === prefix[at];
      }
      if (!same) continue;
      const rest = words.slice(prefix.length);
      if (!rest.every(plainWord) || rest.some(unsafePathWord)) continue;
      if (checkEntry(entry).ok) return true;
    }
    return false;
  } catch { return false; }
}

/** One line for status and doctor: whether a declaration is in force and, when the file is ignored, why. No hash and no path. */
export function dataCommandsEvidence(options: { home?: string; uid?: number } = {}): { state: 'none' | 'active' | 'ignored'; entries: number; usable: number; reason: string | null } {
  try {
    const file = readDataCommands(options);
    if (!file.present) return { state: 'none', entries: 0, usable: 0, reason: null };
    if (controlStateUnsafe(options.home)) return { state: 'ignored', entries: 0, usable: 0, reason: CONTROL_UNSAFE_REASON };
    if (file.ignored) return { state: 'ignored', entries: 0, usable: 0, reason: file.ignored };
    return { state: 'active', entries: file.entries.length, usable: file.entries.filter((entry) => checkEntry(entry).ok).length, reason: null };
  } catch { return { state: 'ignored', entries: 0, usable: 0, reason: 'data-commands.json ignored: it could not be checked' }; }
}

// ─── owner-only declare: `marrow-mcp data-commands add|remove|list` ───
export type DataCommandsIo = {
  /** Whether stdin, stdout and stderr are each a terminal. */
  isTTY: [boolean, boolean, boolean];
  readLine: () => string | null;
  write: (text: string) => void;
  writeErr: (text: string) => void;
  random?: () => string;
  home?: string;
  uid?: number;
};

const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
function randomCode(): string {
  let code = '';
  for (let at = 0; at < 6; at += 1) code += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
  return code;
}
function readLineSync(): string | null {
  const byte = Buffer.alloc(1);
  let line = '';
  for (let attempts = 0; attempts < 4000; attempts += 1) {
    let count: number;
    try { count = readSync(0, byte, 0, 1, null); } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EAGAIN') { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25); continue; }
      return null;
    }
    if (count === 0) return line === '' ? null : line;
    if (byte[0] === 10) return line;
    if (byte[0] !== 13 && line.length < 64) line += String.fromCharCode(byte[0]);
  }
  return null;
}
function processIo(): DataCommandsIo {
  return {
    isTTY: [Boolean(process.stdin.isTTY), Boolean(process.stdout.isTTY), Boolean(process.stderr.isTTY)],
    readLine: readLineSync,
    write: (text) => { process.stdout.write(text); },
    writeErr: (text) => { process.stderr.write(text); },
  };
}

export const DATA_COMMANDS_USAGE = [
  'Usage: marrow-mcp data-commands list',
  '       marrow-mcp data-commands add -- <argv_prefix...>   (the owner, in a terminal)',
  '       marrow-mcp data-commands remove <n>                (the owner, in a terminal)',
  'Example: marrow-mcp data-commands add -- python3 -I /home/me/tools/board.py set',
  '',
].join('\n');

function whereIsHome(io: DataCommandsIo): { home: string; uid: number | undefined } {
  return { home: io.home || homedir(), uid: io.uid ?? currentUid() };
}

function writeDeclaration(home: string, uid: number | undefined, entries: DataCommandEntry[]): string | null {
  const directory = join(home, DATA_COMMANDS_DIRECTORY);
  const target = dataCommandsPath(home);
  const body = `${JSON.stringify({ version: DATA_COMMANDS_VERSION, commands: entries })}\n`;
  if (Buffer.byteLength(body) > DATA_COMMANDS_MAX_BYTES) return `the file would be larger than ${DATA_COMMANDS_MAX_BYTES} bytes, which Marrow would ignore; remove an entry first`;
  let temporary = '';
  let fd = -1;
  try {
    let stat: Stats | null = null;
    try { stat = lstatSync(directory); } catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') return 'the ~/.marrow folder cannot be read'; }
    if (stat === null) mkdirSync(directory, { mode: 0o700 });
    else if (!stat.isDirectory() || !ownedPrivate(stat, 0o700, uid)) return 'the ~/.marrow folder must be a real folder of mode 700 owned by you; fix that first';
    temporary = join(directory, `.data-commands.${process.pid}.${randomInt(2 ** 31)}.tmp`);
    fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0), 0o600);
    writeSync(fd, body);
    fsyncSync(fd);
    closeSync(fd);
    fd = -1;
    renameSync(temporary, target);
    temporary = '';
    return null;
  } catch { return 'the file could not be written'; } finally {
    if (fd >= 0) try { closeSync(fd); } catch { /* nothing to release */ }
    if (temporary) try { unlinkSync(temporary); } catch { /* already gone */ }
  }
}

function confirmWithCode(io: DataCommandsIo, what: string): boolean {
  const code = (io.random || randomCode)();
  io.write(`${what}\nTo confirm, type this code and press enter (anything else cancels): ${code}\n`);
  const typed = io.readLine();
  return typeof typed === 'string' && typed.trim() === code;
}

function describe(entry: DataCommandEntry): string {
  return entry.argv_prefix.join(' ');
}

/** Runs `marrow-mcp data-commands ...` and returns the exit code: 0 done, 1 failed or cancelled, 2 refused (no terminal), 64 usage. */
export function runDataCommands(args: string[], io: DataCommandsIo = processIo()): number {
  const subcommand = args[0];
  const { home, uid } = whereIsHome(io);
  if (subcommand === 'list') {
    if (args.length !== 1) { io.writeErr(DATA_COMMANDS_USAGE); return 64; }
    const file = readDataCommands({ home, uid });
    if (!file.present) { io.write('No data commands are declared.\n'); return 0; }
    if (file.ignored) { io.write(`${file.ignored}\n`); return 0; }
    if (!file.entries.length) { io.write('No data commands are declared.\n'); return 0; }
    if (controlStateUnsafe(home)) { io.write(`${CONTROL_UNSAFE_REASON}\n`); return 0; }
    file.entries.forEach((entry, at) => {
      const checked = checkEntry(entry);
      io.write(`${at + 1}. ${describe(entry)}  [${checked.ok ? 'active' : `inactive: ${checked.reason}`}]\n`);
    });
    return 0;
  }
  if (subcommand !== 'add' && subcommand !== 'remove') { io.writeErr(DATA_COMMANDS_USAGE); return 64; }
  // Owner only: the declaration loosens a check, so it is never made from a shell without a person at it. This is a guard against the accident, not a
  // proof of the owner: a program that drives a pseudo-terminal can still type the code back (spec friction r3 section 5).
  if (!io.isTTY[0] || !io.isTTY[1] || !io.isTTY[2]) {
    io.writeErr(`data-commands ${subcommand} needs a terminal on stdin, stdout and stderr, and the owner to type back a code. Nothing was written. Run it yourself in your own terminal.\n`);
    return 2;
  }
  const file = readDataCommands({ home, uid });
  if (file.ignored) { io.writeErr(`${file.ignored}. Fix or delete ~/.marrow/data-commands.json first; nothing was changed.\n`); return 1; }
  if (subcommand === 'add') {
    if (args[1] !== '--' || args.length < 3) { io.writeErr(DATA_COMMANDS_USAGE); return 64; }
    const prefix = args.slice(2);
    const problem = entryProblem(prefix);
    if (problem) { io.writeErr(`Not declared: ${problem}.\n`); return 1; }
    if (file.entries.length >= DATA_COMMANDS_MAX_ENTRIES) { io.writeErr(`Not declared: ${DATA_COMMANDS_MAX_ENTRIES} entries are already declared (the most Marrow reads).\n`); return 1; }
    if (file.entries.some((entry) => entry.argv_prefix.join('\0') === prefix.join('\0'))) { io.writeErr('Not declared: this prefix is already declared.\n'); return 1; }
    const pinned = readScript(scriptOf(prefix));
    if ('problem' in pinned) { io.writeErr(`Not declared: ${pinned.problem}.\n`); return 1; }
    const isolated = /^python/.test(prefix[0]) && prefix.slice(1, prefix.findIndex((word) => word.includes('/'))).includes('-I');
    const notice = isolated ? '' : '\nNote: the hash covers only the script. Anything the interpreter loads from next to it (modules or packages in the same folder, unless you use python3 -I) is not covered.';
    const confirmed = confirmWithCode(io, `Declare as a data-only command: ${prefix.join(' ')}\nScript sha256: ${pinned.sha256}\nAfter this, Marrow treats the words after that prefix as data, not as actions, while the script stays exactly as it is now.${notice}`);
    if (!confirmed) { io.writeErr('Cancelled: the code did not match. Nothing was written.\n'); return 1; }
    // The script is read again after the code was typed: the hash written is the one of the bytes on disk now.
    const again = readScript(scriptOf(prefix));
    if ('problem' in again) { io.writeErr(`Not declared: ${again.problem}.\n`); return 1; }
    const failure = writeDeclaration(home, uid, [...file.entries, { argv_prefix: prefix, sha256: again.sha256 }]);
    if (failure) { io.writeErr(`Not declared: ${failure}.\n`); return 1; }
    io.write(`Declared ${file.entries.length + 1} data command(s). Run 'marrow-mcp data-commands list' to check.\n`);
    return 0;
  }
  if (args.length !== 2 || !/^[1-9][0-9]{0,2}$/.test(args[1])) { io.writeErr(DATA_COMMANDS_USAGE); return 64; }
  const number = Number(args[1]);
  if (number > file.entries.length) { io.writeErr(`There is no entry ${number}. Run 'marrow-mcp data-commands list'.\n`); return 1; }
  const confirmed = confirmWithCode(io, `Remove data command ${number}: ${describe(file.entries[number - 1])}`);
  if (!confirmed) { io.writeErr('Cancelled: the code did not match. Nothing was changed.\n'); return 1; }
  const failure = writeDeclaration(home, uid, file.entries.filter((_, at) => at !== number - 1));
  if (failure) { io.writeErr(`Not removed: ${failure}.\n`); return 1; }
  io.write(`Removed. ${file.entries.length - 1} data command(s) remain.\n`);
  return 0;
}
