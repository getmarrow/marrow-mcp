import { execFileSync } from 'node:child_process';
import { readFileSync, readlinkSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, join } from 'node:path';

/**
 * Whether a hook runs inside a local, interactive host session, the only
 * place a typed approval reply ("marrow approve CODE") may come from a person.
 * Codex and Gemini give hooks no interactive flag, and `codex exec` or
 * `gemini -p` take prompts from scripts, so the evidence is the hook's own
 * process ancestry: the nearest host process must have a terminal on its
 * standard input and must not run a non-interactive subcommand or flag.
 * Arguments are inspected in memory for those tokens only; nothing is stored,
 * logged or sent. Missing evidence (another OS, no /proc, no ps) is "not
 * interactive": no typed approval is offered.
 */

export type ProcessInfo = {
  pid: number;
  ppid: number;
  args: string[];
  terminal: boolean;
  /** Linux: the process start time in clock ticks since boot (/proc/PID/stat field 22). */
  startTicks?: number;
};
export type ProcessReader = (pid: number) => ProcessInfo | null;

const MAX_DEPTH = 8;
const CODEX_NON_INTERACTIVE = new Set([
  'exec', 'e', 'app-server', 'mcp', 'mcp-server', 'proto', 'cloud', 'apply', 'a', 'review',
  'login', 'logout', 'completion', 'debug', 'sandbox', 'features', '--json',
]);

function linuxProcess(pid: number): ProcessInfo | null {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
    const close = stat.lastIndexOf(')');
    const fields = stat.slice(close + 2).split(' ');
    const ppid = Number(fields[1]);
    const startTicks = Number(fields[19]);
    const args = readFileSync(`/proc/${pid}/cmdline`).toString('utf8').split('\0').filter(Boolean).slice(0, 64);
    let terminal = false;
    try {
      const stdin = readlinkSync(`/proc/${pid}/fd/0`);
      terminal = /^\/dev\/(?:pts\/\d+|tty\w*)$/.test(stdin);
    } catch { terminal = false; }
    return Number.isSafeInteger(ppid) ? { pid, ppid, args, terminal, ...(Number.isSafeInteger(startTicks) ? { startTicks } : {}) } : null;
  } catch {
    return null;
  }
}

function psProcess(pid: number): ProcessInfo | null {
  try {
    const line = execFileSync('ps', ['-o', 'ppid=,tty=,command=', '-p', String(pid)], {
      encoding: 'utf8', timeout: 1_000, stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    const match = line.match(/^(\d+)\s+(\S+)\s+(.*)$/s);
    if (!match) return null;
    return { pid, ppid: Number(match[1]), args: match[3].split(/\s+/).slice(0, 64), terminal: !/^(?:\?\??|-)$/.test(match[2]) };
  } catch {
    return null;
  }
}

const TEST_PROCESS_TABLE = Symbol.for('marrow.test.processTable');

function defaultReader(): ProcessReader {
  // Test seam: a preloaded test module may supply a synthetic process table.
  const table = (globalThis as Record<symbol, unknown>)[TEST_PROCESS_TABLE];
  if (table && typeof table === 'object') {
    return (pid) => ((table as Record<string, ProcessInfo>)[String(pid)] ?? null);
  }
  if (process.platform === 'linux') return linuxProcess;
  if (process.platform === 'darwin' || process.platform === 'freebsd') return psProcess;
  return () => null;
}

function programNames(args: string[]): string[] {
  return args.slice(0, 2).map((arg) => basename(arg).toLowerCase());
}

function isCodex(args: string[]): boolean {
  return programNames(args).some((name) => /^codex(?:-[a-z0-9_.-]+)?(?:\.exe|\.js|\.mjs)?$/.test(name));
}

function isGemini(args: string[]): boolean {
  return programNames(args).some((name) => /^gemini(?:\.exe|\.js|\.mjs)?$/.test(name));
}

/** The editor app (VS Code and its forks) or its extension host, where Cline and Windsurf's Cascade run for a person. */
function isEditorApp(args: string[]): boolean {
  const names = programNames(args);
  if (names.some((name) => /^(?:code|code-insiders|codium|vscodium|windsurf|windsurf-next|code helper(?: \(plugin\))?)(?:\.exe)?$/.test(name))) return true;
  return args.slice(0, 8).some((arg) => /^--type=extensionHost$/.test(arg) || /[/\\](?:Visual Studio Code|VSCodium|Windsurf)(?:\.app)?[/\\]/i.test(arg));
}

function isGrokCli(args: string[]): boolean {
  return programNames(args).some((name) => /^grok(?:\.exe|\.js|\.mjs)?$/.test(name));
}

function isClineCli(args: string[]): boolean {
  return programNames(args).some((name) => /^cline(?:\.exe|\.js|\.mjs)?$/.test(name));
}

function findHostProcess(match: (args: string[]) => boolean, reader: ProcessReader, startPid: number): ProcessInfo | null {
  let pid = startPid;
  for (let depth = 0; depth < MAX_DEPTH && pid > 1; depth += 1) {
    const info = reader(pid);
    if (!info) return null;
    if (match(info.args)) return info;
    pid = info.ppid;
  }
  return null;
}

/** true only with positive evidence; false or null means no typed approval is offered. */
export function localInteractiveSession(
  host: string,
  reader: ProcessReader = defaultReader(),
  startPid: number = process.ppid,
): boolean | null {
  if (host === 'codex') {
    const codex = findHostProcess(isCodex, reader, startPid);
    if (!codex) return null;
    const tokens = codex.args.slice(1).map((arg) => arg.toLowerCase());
    return codex.terminal && !tokens.some((token) => CODEX_NON_INTERACTIVE.has(token));
  }
  if (host === 'grok') {
    const grok = findHostProcess(isGrokCli, reader, startPid);
    if (!grok) return null;
    const tokens = grok.args.slice(1).map((arg) => arg.toLowerCase());
    return grok.terminal && !tokens.some((token) => ['-p', '--prompt', '--print', '--headless', '--json'].includes(token) || token.startsWith('--prompt='));
  }
  if (host === 'cline' || host === 'windsurf') {
    // In the editor a person is at the session; the Cline CLI counts only with a terminal and no scripted mode.
    const editor = findHostProcess(isEditorApp, reader, startPid);
    if (editor) return true;
    if (host === 'cline') {
      const cli = findHostProcess(isClineCli, reader, startPid);
      if (!cli) return null;
      const tokens = cli.args.slice(1).map((arg) => arg.toLowerCase());
      return cli.terminal && !tokens.some((token) => ['-p', '--prompt', '--yolo', '--json', '--headless', '--oneshot', 'task'].includes(token));
    }
    return null;
  }
  if (host === 'gemini') {
    const gemini = findHostProcess(isGemini, reader, startPid);
    if (!gemini) return null;
    const tokens = gemini.args.slice(1);
    const scripted = tokens.some((token) => token === '-p' || token === '--prompt' || token.startsWith('--prompt=')
      || token === '--experimental-acp' || token === '--acp');
    return gemini.terminal && !scripted;
  }
  return null;
}

// ---------------------------------------------------------------------------
// The host's own approval prompt
// ---------------------------------------------------------------------------

const CODEX_KEYS = ['approval_policy', 'approvals_reviewer', 'sandbox_mode'] as const;
type CodexKey = typeof CODEX_KEYS[number];
type CodexValues = Partial<Record<CodexKey | 'profile', string>>;
/** Codex flags that turn its approval prompt off for the session. */
const CODEX_NO_PROMPT_FLAGS = new Set([
  '--dangerously-bypass-approvals-and-sandbox', '--yolo', '--full-auto', '--approve-for-me', '--not-so-yolo',
]);
const MAX_CONFIG_BYTES = 256 * 1024;
const RELEVANT_KEY_NAME = /(?:^|[^A-Za-z0-9_])(?:approval_policy|approvals_reviewer|sandbox_mode|profiles?)(?:$|[^A-Za-z0-9_])/;

export type ConfigReader = (path: string) => string | null;

/** Reads a config file into memory (never logged); null when missing, unreadable or too large. */
function readConfigFile(path: string): string | null {
  try {
    if (statSync(path).size > MAX_CONFIG_BYTES) return null;
    return readFileSync(path, 'utf8');
  } catch {
    return null;
  }
}

/** What one Codex config text says about its approval prompt. */
export type CodexConfigSettings = {
  /** Top-level approval_policy, approvals_reviewer, sandbox_mode and profile. */
  top: CodexValues;
  /** The same three keys per profile (`[profiles.NAME]`, `profiles.NAME.key`, inline tables). */
  profiles: Record<string, CodexValues>;
  /** A line naming one of these keys could not be read: the prompt is then treated as off. */
  unreadable: boolean;
};

class TomlError extends Error {}

/**
 * A small TOML reader for the keys above only: tables and array tables,
 * dotted and quoted keys, basic, literal and multi-line strings, inline
 * tables and arrays. Values of every other key are skipped and never kept.
 */
export function parseCodexSettings(input: string): CodexConfigSettings {
  const text = input.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n');
  const result: CodexConfigSettings = { top: {}, profiles: {}, unreadable: false };
  const n = text.length;
  let i = 0;
  let table: string[] = [];
  const fail = (): never => { throw new TomlError(); };
  const skipSpaces = () => { while (i < n && (text[i] === ' ' || text[i] === '\t')) i += 1; };
  const skipComment = () => { if (text[i] === '#') while (i < n && text[i] !== '\n') i += 1; };
  const skipBlank = () => {
    for (;;) {
      skipSpaces();
      skipComment();
      if (text[i] !== '\n') return;
      i += 1;
    }
  };
  const record = (path: string[], value: string) => {
    if (path.length === 1 && ((CODEX_KEYS as readonly string[]).includes(path[0]) || path[0] === 'profile')) {
      result.top[path[0] as CodexKey | 'profile'] = value;
    } else if (path.length === 3 && path[0] === 'profiles' && (CODEX_KEYS as readonly string[]).includes(path[2])) {
      (result.profiles[path[1]] ??= {})[path[2] as CodexKey] = value;
    }
  };
  const multiline = (quote: string): string => {
    i += 3;
    if (text[i] === '\n') i += 1;
    const close = text.indexOf(quote.repeat(3), i);
    if (close < 0) fail();
    let end = close;
    while (text[end + 3] === quote && end - close < 2) end += 1;
    const value = text.slice(i, end);
    i = end + 3;
    return value;
  };
  const basicString = (): string => {
    if (text.startsWith('"""', i)) return multiline('"').replace(/\\\n[ \t\n]*/g, '').replace(/\\(["\\])/g, '$1');
    i += 1;
    let out = '';
    while (i < n && text[i] !== '"') {
      if (text[i] === '\n') fail();
      if (text[i] === '\\') {
        const next = text[i + 1];
        const simple: Record<string, string> = { n: '\n', t: '\t', r: '\r', b: '\b', f: '\f', '"': '"', '\\': '\\' };
        if (next in simple) { out += simple[next]; i += 2; continue; }
        const width = next === 'u' ? 4 : next === 'U' ? 8 : 0;
        const hex = text.slice(i + 2, i + 2 + width);
        if (!width || hex.length !== width || !/^[0-9A-Fa-f]+$/.test(hex)) fail();
        out += String.fromCodePoint(parseInt(hex, 16));
        i += 2 + width;
        continue;
      }
      out += text[i];
      i += 1;
    }
    if (text[i] !== '"') fail();
    i += 1;
    return out;
  };
  const literalString = (): string => {
    if (text.startsWith("'''", i)) return multiline("'");
    const close = text.indexOf("'", i + 1);
    const newline = text.indexOf('\n', i + 1);
    if (close < 0 || (newline >= 0 && newline < close)) fail();
    const value = text.slice(i + 1, close);
    i = close + 1;
    return value;
  };
  const keyPart = (): string => {
    skipSpaces();
    if (text[i] === '"') return basicString();
    if (text[i] === "'") return literalString();
    const bare = /^[A-Za-z0-9_-]+/.exec(text.slice(i, i + 256));
    if (!bare) return fail();
    i += bare[0].length;
    return bare[0];
  };
  const key = (): string[] => {
    const parts = [keyPart()];
    for (;;) {
      skipSpaces();
      if (text[i] !== '.') return parts;
      i += 1;
      parts.push(keyPart());
    }
  };
  const value = (path: string[], depth: number): void => {
    if (depth > 16) fail();
    skipSpaces();
    const c = text[i];
    if (c === '"') { record(path, basicString()); return; }
    if (c === "'") { record(path, literalString()); return; }
    if (c === '{' || c === '[') {
      const close = c === '{' ? '}' : ']';
      i += 1;
      skipBlank();
      if (text[i] === close) { i += 1; return; }
      for (;;) {
        if (c === '{') {
          const inner = key();
          skipSpaces();
          if (text[i] !== '=') fail();
          i += 1;
          value([...path, ...inner], depth + 1);
        } else {
          value([...path, '[]'], depth + 1);
        }
        skipBlank();
        if (text[i] === ',') {
          i += 1;
          skipBlank();
          if (text[i] === close) { i += 1; return; }
          continue;
        }
        if (text[i] === close) { i += 1; return; }
        fail();
      }
    }
    const bare = /^[A-Za-z0-9_+.:-]+/.exec(text.slice(i, i + 128));
    if (!bare) return fail();
    i += bare[0].length;
    record(path, bare[0]);
  };
  while (i < n) {
    const lineStart = i;
    try {
      skipBlank();
      if (i >= n) break;
      if (text[i] === '[') {
        const arrayTable = text[i + 1] === '[';
        i += arrayTable ? 2 : 1;
        const header = key();
        skipSpaces();
        if (arrayTable ? !text.startsWith(']]', i) : text[i] !== ']') fail();
        i += arrayTable ? 2 : 1;
        table = arrayTable ? [...header, '[]'] : header;
      } else {
        const name = key();
        skipSpaces();
        if (text[i] !== '=') fail();
        i += 1;
        value([...table, ...name], 0);
      }
      skipSpaces();
      skipComment();
      if (i < n && text[i] !== '\n') fail();
    } catch (error) {
      if (!(error instanceof TomlError)) throw error;
      // This line could not be read. If it names a key that decides the prompt, treat the prompt as off.
      const lineEnd = text.indexOf('\n', Math.max(i, lineStart));
      const stop = lineEnd < 0 ? n : lineEnd;
      if (RELEVANT_KEY_NAME.test(text.slice(lineStart, stop))) result.unreadable = true;
      i = stop + 1;
    }
  }
  return result;
}

function emptySettings(): CodexConfigSettings {
  return { top: {}, profiles: {}, unreadable: false };
}

/** A `-c key=value` override: the value is TOML, or a plain string when it is not (as Codex reads it). */
function parseCodexOverride(text: string): CodexConfigSettings {
  const equals = text.indexOf('=');
  if (equals < 0) {
    const settings = emptySettings();
    settings.unreadable = RELEVANT_KEY_NAME.test(text);
    return settings;
  }
  const keyText = text.slice(0, equals).trim();
  const valueText = text.slice(equals + 1).trim();
  const parsed = parseCodexSettings(`${keyText} = ${valueText}\n`);
  if (!parsed.unreadable) return parsed;
  return parseCodexSettings(`${keyText} = ${JSON.stringify(valueText)}\n`);
}

function mergeSettings(into: CodexConfigSettings, from: CodexConfigSettings): void {
  Object.assign(into.top, from.top);
  for (const [name, values] of Object.entries(from.profiles)) Object.assign((into.profiles[name] ??= {}), values);
  into.unreadable = into.unreadable || from.unreadable;
}

/**
 * Whether Codex, as started, shows no approval prompt for a held action:
 * approval bypass (`--dangerously-bypass-approvals-and-sandbox`, `--yolo`),
 * never-ask (`-a never`), automatic review (`--approve-for-me`, or an
 * `approvals_reviewer` other than `user`), `--full-auto`, or full access
 * (`-s danger-full-access`), on the command line, in `-c` overrides
 * (including `profiles.NAME.key`), or in its config: `$CODEX_HOME/config.toml`
 * with its active profile, and a `-p NAME` profile file. A flag decides its
 * own setting; otherwise any of those sources that turns the prompt off
 * counts, since their order cannot be known for certain from outside Codex.
 * A line naming one of these keys that cannot be read also counts as off.
 */
export function codexApprovalPromptOff(args: string[], readConfig: ConfigReader = readConfigFile, env: NodeJS.ProcessEnv = process.env): boolean {
  const tokens = args.slice(1);
  const cli: { approval?: string; sandbox?: string; profile?: string } = {};
  const overrides = emptySettings();
  const take = (i: number, long: string, short: string | null): { value: string; next: number } | null => {
    const token = tokens[i];
    if (token === long || (short && token === short)) return i + 1 < tokens.length ? { value: tokens[i + 1], next: i + 1 } : null;
    if (token.startsWith(`${long}=`)) return { value: token.slice(long.length + 1), next: i };
    if (short && token.startsWith(short) && !token.startsWith('--') && token.length > short.length) return { value: token.slice(short.length).replace(/^=/, ''), next: i };
    return null;
  };
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    if (CODEX_NO_PROMPT_FLAGS.has(token)) return true;
    const approval = take(i, '--ask-for-approval', '-a');
    if (approval) { cli.approval = approval.value; i = approval.next; continue; }
    const sandbox = take(i, '--sandbox', '-s');
    if (sandbox) { cli.sandbox = sandbox.value; i = sandbox.next; continue; }
    const profile = take(i, '--profile', '-p');
    if (profile) { cli.profile = profile.value; i = profile.next; continue; }
    const config = take(i, '--config', '-c');
    if (config) {
      mergeSettings(overrides, parseCodexOverride(config.value));
      i = config.next;
    }
  }
  if (overrides.unreadable) return true;
  const home = env.CODEX_HOME && env.CODEX_HOME.trim() ? env.CODEX_HOME : join(homedir(), '.codex');
  const baseText = readConfig(join(home, 'config.toml'));
  const base = baseText === null ? emptySettings() : parseCodexSettings(baseText);
  if (base.unreadable) return true;
  const profileName = cli.profile ?? overrides.top.profile ?? base.top.profile;
  const validName = typeof profileName === 'string' && /^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}$/.test(profileName) ? profileName : null;
  const fileText = validName ? readConfig(join(home, `${validName}.config.toml`)) : null;
  const file = fileText === null ? emptySettings() : parseCodexSettings(fileText);
  if (file.unreadable) return true;
  const sources: CodexValues[] = [base.top, file.top, overrides.top];
  if (validName) sources.push(base.profiles[validName] ?? {}, file.profiles[validName] ?? {}, overrides.profiles[validName] ?? {});
  const anyOff = (key: CodexKey, off: (value: string) => boolean) => sources.some((source) => source[key] !== undefined && off(source[key]!.trim().toLowerCase()));
  const approvalOff = cli.approval !== undefined ? cli.approval.trim().toLowerCase() === 'never' : anyOff('approval_policy', (value) => value === 'never');
  const sandboxOff = cli.sandbox !== undefined ? cli.sandbox.trim().toLowerCase() === 'danger-full-access' : anyOff('sandbox_mode', (value) => value === 'danger-full-access');
  const reviewerOff = anyOff('approvals_reviewer', (value) => value !== 'user');
  return approvalOff || sandboxOff || reviewerOff;
}

/**
 * Whether the host's own approval prompt is off in this session, so leaving a
 * held action to it would let it run with no one asked. Codex is read from
 * its process and config (see codexApprovalPromptOff). Cline's auto-approve
 * and Windsurf's Turbo mode live in editor state with no reliable signal, so
 * they are not detected (false).
 */
export function hostApprovalPromptOff(
  host: string,
  reader: ProcessReader = defaultReader(),
  startPid: number = process.ppid,
  readConfig: ConfigReader = readConfigFile,
): boolean {
  if (host !== 'codex') return false;
  const codex = findHostProcess(isCodex, reader, startPid);
  if (!codex) return false;
  return codexApprovalPromptOff(codex.args, readConfig);
}

/** The approval mode Gemini CLI's own flags set (`yolo`, `auto_edit`, `default`, …), or null when they set none. */
export function geminiFlagApprovalMode(args: string[]): string | null {
  const tokens = args.slice(1);
  const modes: string[] = [];
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    const lower = token.toLowerCase();
    if (lower === '--yolo' || lower.startsWith('--yolo=')) {
      if (lower !== '--yolo=false') modes.push('yolo');
    } else if (/^-[A-Za-z]+$/.test(token) && token.includes('y')) {
      // -y, also inside a cluster of short flags (-yd).
      modes.push('yolo');
    } else if (lower === '--approval-mode') {
      modes.push((tokens[i + 1] ?? '').trim().toLowerCase() || 'unknown');
    } else if (lower.startsWith('--approval-mode=')) {
      modes.push(lower.slice('--approval-mode='.length).trim() || 'unknown');
    }
  }
  if (modes.length === 0) return null;
  // Conflicting flags: any mode that does not ask wins.
  return modes.find((mode) => mode !== 'default') ?? 'default';
}

/** Gemini CLI's flags alone turn its approval prompt off (YOLO, auto edit or any mode other than default). */
export function geminiApprovalPromptOff(args: string[]): boolean {
  const mode = geminiFlagApprovalMode(args);
  return mode !== null && mode !== 'default';
}

export type GeminiFileReader = (path: string) => { exists: boolean; text: string | null };

/** Reads a settings file into memory (never logged): missing, or present with its text (null when unreadable or too large). */
function readGeminiFile(path: string): { exists: boolean; text: string | null } {
  try {
    const stat = statSync(path);
    if (!stat.isFile() || stat.size > MAX_CONFIG_BYTES) return { exists: true, text: null };
    return { exists: true, text: readFileSync(path, 'utf8') };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException)?.code;
    return { exists: code !== 'ENOENT' && code !== 'ENOTDIR', text: null };
  }
}

/** JSON with // and block comments (Gemini's settings files allow them), parsed; null when it is not a JSON object. */
function parseJsonWithComments(text: string): Record<string, unknown> | null {
  let out = '';
  let inString = false;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (inString) {
      out += c;
      if (c === '\\') { out += text[i + 1] ?? ''; i += 1; } else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') { inString = true; out += c; continue; }
    if (c === '/' && text[i + 1] === '/') { while (i < text.length && text[i] !== '\n') i += 1; out += '\n'; continue; }
    if (c === '/' && text[i + 1] === '*') { const end = text.indexOf('*/', i + 2); if (end < 0) return null; i = end + 1; continue; }
    out += c;
  }
  try {
    const parsed = JSON.parse(out);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

/** What one Gemini settings file says: its approval mode (null when none), and whether it lets shell commands run without asking. */
function geminiFileApproval(settings: Record<string, unknown>): { mode: string | null; shellAllowed: boolean } {
  const record = (value: unknown) => (value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null);
  const general = record(settings.general);
  const tools = record(settings.tools);
  const modes: string[] = [];
  for (const value of [general?.defaultApprovalMode, settings.defaultApprovalMode, general?.approvalMode, settings.approvalMode, tools?.approvalMode]) {
    if (value === undefined) continue;
    modes.push(typeof value === 'string' && value.trim() ? value.trim().toLowerCase() : 'unknown');
  }
  for (const value of [settings.yolo, general?.yolo, tools?.yolo]) if (value !== undefined && value !== false) modes.push('yolo');
  for (const value of [settings.autoAccept, tools?.autoAccept, general?.autoAccept]) if (value !== undefined && value !== false) modes.push('auto_accept');
  const allowed = [tools?.allowed, settings.allowedTools, tools?.allowedTools].flatMap((value) => (Array.isArray(value) ? value : []));
  const shellAllowed = allowed.some((entry) => typeof entry !== 'string' || /shell|run_shell_command|^\*$/i.test(entry));
  return { mode: modes.length === 0 ? null : modes.find((mode) => mode !== 'default') ?? 'default', shellAllowed };
}

/**
 * Whether Gemini CLI runs tools without asking in this session, by its own
 * precedence: system defaults, the user's ~/.gemini/settings.json, the
 * project's .gemini/settings.json (any found from the working directory up),
 * the system settings file, then the command-line flags. Off when the
 * effective mode is anything but `default` (YOLO, auto edit, auto accept,
 * plan or an unknown value), when shell commands are allowed without asking,
 * or when a settings file exists but cannot be read or parsed.
 */
export function geminiPromptOff(
  args: string[],
  options: { cwd?: string; home?: string; env?: NodeJS.ProcessEnv; read?: GeminiFileReader } = {},
): boolean {
  const env = options.env ?? process.env;
  const home = options.home ?? env.HOME ?? homedir();
  const read = options.read ?? readGeminiFile;
  const userFile = join(home, '.gemini', 'settings.json');
  const projectFiles: string[] = [];
  let dir = options.cwd ?? process.cwd();
  for (let depth = 0; depth < 32; depth += 1) {
    const candidate = join(dir, '.gemini', 'settings.json');
    if (candidate !== userFile) projectFiles.push(candidate);
    const parent = join(dir, '..');
    if (parent === dir) break;
    dir = parent;
  }
  const darwin = process.platform === 'darwin';
  const systemDefaults = env.GEMINI_CLI_SYSTEM_DEFAULTS_PATH || (darwin ? '/Library/Application Support/GeminiCli/system-defaults.json' : '/etc/gemini-cli/system-defaults.json');
  const systemSettings = env.GEMINI_CLI_SYSTEM_SETTINGS_PATH || (darwin ? '/Library/Application Support/GeminiCli/settings.json' : '/etc/gemini-cli/settings.json');
  let unreadable = false;
  let shellAllowed = false;
  const layer = (paths: string[]): string | null => {
    const modes: string[] = [];
    for (const path of paths) {
      const file = read(path);
      if (!file.exists) continue;
      const parsed = file.text === null ? null : parseJsonWithComments(file.text);
      if (!parsed) { unreadable = true; continue; }
      const approval = geminiFileApproval(parsed);
      if (approval.shellAllowed) shellAllowed = true;
      if (approval.mode !== null) modes.push(approval.mode);
    }
    // Several project files: any one that does not ask decides.
    return modes.length === 0 ? null : modes.find((mode) => mode !== 'default') ?? 'default';
  };
  let mode: string | null = null;
  for (const paths of [[systemDefaults], [userFile], projectFiles, [systemSettings]]) {
    const set = layer(paths);
    if (set !== null) mode = set;
  }
  if (unreadable || shellAllowed) return true;
  const flag = geminiFlagApprovalMode(args);
  if (flag !== null) mode = flag;
  return (mode ?? 'default') !== 'default';
}

/**
 * Whether a typed reply could come from someone other than the person: the
 * host runs tools without asking, so the agent could run the prompt hook
 * itself with a code it read from this user's files. Codex: its approval
 * prompt off (codexApprovalPromptOff). Gemini CLI: any mode but default, by
 * flags or settings files (geminiPromptOff). Cursor: its auto-run
 * mode cannot be seen, so always. A host process that cannot be found counts
 * as off.
 */
export function typedReplyPromptOff(
  host: string,
  reader: ProcessReader = defaultReader(),
  startPid: number = process.ppid,
  readConfig: ConfigReader = readConfigFile,
): boolean {
  if (host === 'codex') {
    const codex = findHostProcess(isCodex, reader, startPid);
    return !codex || codexApprovalPromptOff(codex.args, readConfig);
  }
  if (host === 'gemini') {
    const gemini = findHostProcess(isGemini, reader, startPid);
    return !gemini || geminiPromptOff(gemini.args);
  }
  return true;
}

// ---------------------------------------------------------------------------
// Hook start-up time
// ---------------------------------------------------------------------------

/** /proc reports start times in USER_HZ, which is 100 on Linux. */
const TICK_MS = 10;
/** Longer than this is not a hook's own start-up (a long-lived wrapper shell): unknown. */
const MAX_HEAD_START_MS = 4_000;

/** A process that only launches the hook: npx or npm (exec), or a `sh -c` wrapper. */
function isHookLauncher(args: string[]): boolean {
  // npm rewrites its process title: /proc shows "npm exec …" (or "npx …") as one string.
  if (/^(?:npm exec|npx)(?:\s|$)/.test(args[0] || '')) return true;
  const first = basename(args[0] || '').toLowerCase();
  if (first === 'npx' || first === 'npm') return true;
  if (/^(?:node|nodejs)(?:\.exe)?$/.test(first) && /(?:^|[/\\])(?:npx-cli|npm-cli)\.js$|(?:^|[/\\])(?:npx|npm)$/.test(args[1] || '')) return true;
  return /^(?:sh|bash|dash|zsh)$/.test(first) && args.slice(1, 3).some((arg) => /^-[a-z]*c$/.test(arg));
}

/**
 * How long before this process the host started launching it (npx, npm, a
 * `sh -c` wrapper), in milliseconds, so a host's kill clock that started at
 * spawn can be honored. Linux only (from /proc start times); 0 when unknown,
 * including a launcher older than 4 s (a long-lived wrapper, not start-up).
 */
export function hookLauncherHeadStartMs(reader: ProcessReader = defaultReader(), selfPid: number = process.pid): number {
  const self = reader(selfPid);
  if (!self || typeof self.startTicks !== 'number') return 0;
  let earliest = self.startTicks;
  let pid = self.ppid;
  for (let depth = 0; depth < 6 && pid > 1; depth += 1) {
    const info = reader(pid);
    if (!info || typeof info.startTicks !== 'number' || !isHookLauncher(info.args)) break;
    earliest = Math.min(earliest, info.startTicks);
    pid = info.ppid;
  }
  const headStart = Math.max(0, (self.startTicks - earliest) * TICK_MS);
  return headStart > MAX_HEAD_START_MS ? 0 : headStart;
}
