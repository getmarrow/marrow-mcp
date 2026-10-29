import { existsSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, normalize } from 'node:path';
import { isShellTextTool, parseShellSegments, toolTargetPaths } from './hook-tool-policy';
import type { ToolPolicyEvent } from './hook-tool-policy';

/**
 * T2 (control-file gap): a write, delete, move or chmod of Marrow's own control files, of the hooks settings of any host, or of the
 * files that make a command run later (shell rc and profile files, Claude Code shell snapshots, crontab, systemd user units) is a
 * `security` action. The kinds: `marrow-control` and `persistence`. The label is read by the backend as `secrets_security`, so the
 * action is held per account policy instead of passing as an `audit on secrets` action. Any tool and any shell form: a file tool is
 * judged by its target path (resolved, symlinks followed), a shell command by every redirect target and every word a program that
 * can write is given, a command the parser cannot read by its text. Reads (cat, grep, ls, crontab -l) are not stopped here.
 */
export type SelfProtectKind = 'marrow-control' | 'persistence';

const BEFORE = String.raw`(?:^|[/\s"'=:~}])`;
const CONTROL_FILES: RegExp[] = [
  new RegExp(`${BEFORE}\\.marrow(?![A-Za-z0-9_.-])`, 'i'),
  /\.claude\/settings[^/\s"']*\.json/i,
  /\.(?:codex|cursor|windsurf)\/hooks\.json/i,
  /\.grok\/hooks(?![A-Za-z0-9_-])/i,
  /\.gemini\/settings\.json/i,
];
const PERSISTENCE_FILES: RegExp[] = [
  new RegExp(`${BEFORE}\\.(?:bashrc|bash_profile|bash_aliases|bash_login|bash_logout|profile|zshrc|zprofile|zshenv|zlogin|zlogout)(?![A-Za-z0-9_-])`, 'i'),
  /\.config\/fish(?![A-Za-z0-9_-])/i,
  /\.claude\/shell-snapshots(?![A-Za-z0-9_-])/i,
  /\/var\/spool\/cron/i,
  /\/etc\/cron/i,
  /\.config\/systemd(?![A-Za-z0-9_-])/i,
];
// Programs that only read their operands: naming a protected file to one of them is not a write.
const READING_PROGRAMS = new Set([
  'cat', 'head', 'tail', 'less', 'more', 'grep', 'egrep', 'fgrep', 'rg', 'ls', 'stat', 'file', 'wc', 'diff', 'cmp', 'du', 'echo', 'printf',
  'test', '[', 'readlink', 'realpath', 'basename', 'dirname', 'sha256sum', 'sha1sum', 'md5sum', 'which', 'type', 'jq', 'tree', 'source', '.', 'pwd',
]);
// A folder a host keeps hooks settings in: moving into it is held, so a later relative write there cannot slip past the path test.
const HOST_CONFIG_FOLDER = /\.(?:claude|codex|cursor|windsurf|gemini|grok)(?:\/(?:hooks|shell-snapshots))?\/?$/i;
const FIND_WRITES = /^-(?:delete|exec|execdir|ok|okdir|fprint0?|fprintf|fls)$/;

/** The kind of protected file a path or word names, or null. Control files win over persistence files. */
export function protectedMention(text: string): SelfProtectKind | null {
  if (CONTROL_FILES.some((pattern) => pattern.test(text))) return 'marrow-control';
  if (PERSISTENCE_FILES.some((pattern) => pattern.test(text))) return 'persistence';
  return null;
}

function home(): string {
  return process.env.HOME || homedir();
}

function resolvedPaths(raw: string, cwd: string | undefined): string[] {
  const expanded = raw === '~' ? home() : raw.startsWith('~/') ? join(home(), raw.slice(2))
    : raw.startsWith('$HOME/') ? join(home(), raw.slice(6)) : raw.startsWith('${HOME}/') ? join(home(), raw.slice(8)) : raw;
  const base = isAbsolute(expanded) ? expanded : cwd ? join(cwd, expanded) : expanded;
  const lexical = normalize(base);
  const paths = [lexical];
  // A link (or a link in a parent folder) can lead a harmless-looking name to a protected file: judge where it really points as well.
  try {
    let existing = lexical;
    const tail: string[] = [];
    while (existing.length > 1 && !existsSync(existing)) { tail.unshift(existing.slice(dirname(existing).length + 1)); existing = dirname(existing); }
    const real = join(realpathSync(existing), ...tail);
    if (real !== lexical) paths.push(real);
  } catch { /* an unreadable path is judged by its text only */ }
  return paths;
}

function pathKind(raw: string, cwd: string | undefined): SelfProtectKind | null {
  let found: SelfProtectKind | null = null;
  for (const candidate of [raw, ...resolvedPaths(raw, cwd)]) {
    const kind = protectedMention(candidate);
    if (kind === 'marrow-control') return kind;
    if (kind) found = kind;
  }
  return found;
}

function crontabWrites(args: string[]): boolean {
  // Only a plain listing (`crontab -l`, optionally for a user) is a read; `-`, a file, -e and -r all replace or edit the table.
  const rest = args.filter((arg, index) => arg !== '-u' && args[index - 1] !== '-u');
  return !(rest.length === 1 && rest[0] === '-l');
}

function baseName(word: string): string {
  const cut = word.lastIndexOf('/');
  return cut < 0 ? word : word.slice(cut + 1);
}

function shellKind(command: string): SelfProtectKind | null {
  const segments = parseShellSegments(command);
  // A command the parser cannot read (heredoc, substitution, brace group) is judged by its whole text.
  if (!segments) return protectedMention(command);
  let persistence: SelfProtectKind | null = null;
  const take = (kind: SelfProtectKind | null): SelfProtectKind | null => {
    if (kind === 'marrow-control') return kind;
    if (kind) persistence = kind;
    return null;
  };
  for (const segment of segments) {
    for (const output of segment.outputs) { const kind = take(protectedMention(output)); if (kind) return kind; }
    let at = 0;
    while (at < segment.words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(segment.words[at])) at += 1;
    const program = at < segment.words.length ? baseName(segment.words[at]) : '';
    const args = segment.words.slice(at + 1);
    if (program === 'crontab' && crontabWrites(args)) { const kind = take('persistence'); if (kind) return kind; }
    if ((program === 'cd' || program === 'pushd') && args.some((arg) => HOST_CONFIG_FOLDER.test(arg))) return 'marrow-control';
    if (READING_PROGRAMS.has(program)) continue;
    if (program === 'find' && !args.some((arg) => FIND_WRITES.test(arg))) continue;
    for (const word of segment.words) { const kind = take(protectedMention(word)); if (kind) return kind; }
  }
  return persistence;
}

/**
 * The kind of protected file a mutating call touches, or null. `cwd` resolves relative targets. Call it only for a call that is not
 * read-only: a Read of ~/.bashrc stays a read.
 */
export function selfProtectKind(event: ToolPolicyEvent, cwd?: string): SelfProtectKind | null {
  if (isShellTextTool(event)) {
    const input = event.tool_input && typeof event.tool_input === 'object' ? event.tool_input as Record<string, unknown> : {};
    const texts = typeof event.tool_input === 'string' ? [event.tool_input]
      : ['command', 'cmd', 'script'].map((key) => input[key]).filter((value): value is string => typeof value === 'string' && value.length > 0);
    let found: SelfProtectKind | null = null;
    for (const text of texts) {
      const kind = shellKind(text);
      if (kind === 'marrow-control') return kind;
      if (kind) found = kind;
    }
    return found;
  }
  let found: SelfProtectKind | null = null;
  for (const target of toolTargetPaths(event)) {
    const kind = pathKind(target, cwd);
    if (kind === 'marrow-control') return kind;
    if (kind) found = kind;
  }
  return found;
}
