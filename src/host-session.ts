import { execFileSync } from 'node:child_process';
import { readFileSync, readlinkSync } from 'node:fs';
import { basename } from 'node:path';

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

export type ProcessInfo = { pid: number; ppid: number; args: string[]; terminal: boolean };
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
    const args = readFileSync(`/proc/${pid}/cmdline`).toString('utf8').split('\0').filter(Boolean).slice(0, 64);
    let terminal = false;
    try {
      const stdin = readlinkSync(`/proc/${pid}/fd/0`);
      terminal = /^\/dev\/(?:pts\/\d+|tty\w*)$/.test(stdin);
    } catch { terminal = false; }
    return Number.isSafeInteger(ppid) ? { pid, ppid, args, terminal } : null;
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
