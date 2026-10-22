// Env-dump forms: every command an agent can type that prints many or all environment variables.
// One table for both modes: the keyless seatbelt mapper stops them (S4) and the keyed hook policy
// holds them (hook-tool-policy.ts asks the mapper and keeps only the reasons named here). Pure
// word-level predicates over literal arguments; no file contents are read.

/** S4 reasons that mean "prints the environment". The keyed hook keeps only these from a mapper run. */
export const ENV_DUMP_REASONS: ReadonlySet<string> = new Set([
  'env_dump_env', 'env_dump_set', 'env_dump_export', 'env_dump_declare', 'env_dump_declare_secret', 'env_dump_readonly', 'env_dump_printenv',
  'env_dump_printenv_secret', 'interpreter_env_dump', 'ps_environment', 'proc_environ', 'env_dump_compgen', 'env_dump_tmux', 'env_dump_systemctl',
  'env_dump_jq', 'env_dump_strace', 'env_dump_php_info', 'env_dump_npm_run_env', 'tripwire_secret_dumper', 'echo_secret_var',
]);

/**
 * Programs that run the command at the end of their argv with a grammar the mapper does not model. A bare `env` or
 * `printenv` as their last word is that command, not a name (`python -m venv env` and `conda activate env` stay fine:
 * those programs are not listed).
 */
export const EXEC_WRAPPERS: ReadonlySet<string> = new Set([
  'setpriv', 'unshare', 'runuser', 'nsenter', 'chroot', 'fakeroot', 'fakeroot-sysv', 'fakechroot', 'systemd-run', 'firejail', 'bwrap', 'strace', 'ltrace',
  'sg', 'proot', 'torsocks', 'proxychains', 'proxychains4', 'tsocks', 'xvfb-run', 'dbus-run-session', 'cross-env', 'env-cmd', 'dotenv', 'dotenvx', 'direnv',
  'sandbox-exec', 'cgexec', 'sshpass', 'chronic', 'rlwrap',
]);

const letters = (text: string): boolean => /^[a-zA-Z]+$/.test(text);

/** `compgen -e`, `-v`, `-A export` and `-A variable` list the names of the environment's variables. */
export function compgenListsVariables(args: ReadonlyArray<string | null>): boolean {
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === null) continue;
    if (a === '--') return false;
    if (/^-A./.test(a)) { if (/^(?:export|variable)$/.test(a.slice(2))) return true; continue; }
    if (a === '-A') { const v = args[i + 1]; if (v === 'export' || v === 'variable') return true; i += 1; continue; }
    if (/^-[oGWFCXPS]$/.test(a)) { i += 1; continue; }
    if (/^-[a-zA-Z]+$/.test(a) && /[ev]/.test(a.slice(1).replace(/[oGWFCXPS].*$/, ''))) return true;
  }
  return false;
}

/** tmux accepts any unambiguous prefix of a command name or alias: `show-e` and `showe` are show-environment. */
function tmuxShowEnvironmentWord(word: string): boolean {
  return (word.length >= 6 && 'show-environment'.startsWith(word)) || (word.length >= 5 && 'showenv'.startsWith(word));
}

/** `tmux [options] show-environment` (also `showenv`, a unique prefix, and a command after `\\;`) prints a session's variables. */
export function tmuxShowsEnvironment(args: ReadonlyArray<string | null>): boolean {
  let i = 0;
  // Global options come before the first command: -S, -L, -f, -c and -T take a value.
  while (i < args.length && args[i] !== null && (args[i] as string).startsWith('-') && args[i] !== '-') i += /^-[SLfcT]$/.test(args[i] as string) ? 2 : 1;
  let commandStart = true;
  for (; i < args.length; i += 1) {
    const a = args[i];
    if (a === ';' || a === '\\;') { commandStart = true; continue; }
    if (a !== null && commandStart && tmuxShowEnvironmentWord(a)) return true;
    commandStart = false;
  }
  return false;
}

/** `systemctl [--user] show-environment` prints the manager's environment. */
export function systemctlShowsEnvironment(args: ReadonlyArray<string | null>): boolean {
  return args.some((a) => a === 'show-environment');
}

/**
 * BSD `ps e`, `ps auxe`, `ps eww` and `ps -E` print every process's environment. A word of letters that holds `e`, or a dash
 * cluster that holds `E`, outside the value of an option (`ps -p 1 -o etime` asks for a column, not the environment).
 */
export function psPrintsEnvironment(args: ReadonlyArray<string | null>): boolean {
  const longWithValue = /^--(?:sort|pid|ppid|user|User|group|Group|tty|sid|format|cols|columns|width|lines|rows|quick-pid)$/;
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === null) continue;
    if (a.startsWith('--')) { if (longWithValue.test(a)) i += 1; continue; }
    if (/^-[a-zA-Z]+$/.test(a)) {
      for (let k = 1; k < a.length; k += 1) {
        if (a[k] === 'E') return true;
        if ('oOpquUgGstCnND'.includes(a[k])) { if (k === a.length - 1) i += 1; break; }
      }
      continue;
    }
    if (letters(a)) {
      for (let k = 0; k < a.length; k += 1) {
        if (a[k] === 'e') return true;
        if ('oOpqUgGstCnND'.includes(a[k])) { if (k === a.length - 1) i += 1; break; }
      }
    }
  }
  return false;
}

/** The older, looser reading of `ps`: any word of letters that holds `e`, option values included. The keyless seatbelt keeps stopping it. */
export function psLooselyPrintsEnvironment(args: ReadonlyArray<string | null>): boolean {
  return args.some((a) => a !== null && letters(a) && a.includes('e'));
}

/** The environment object in a jq filter: `env`, `$ENV` (not a `.env` field, a key, or text in a string). */
export function jqFilterReadsEnvironment(filter: string): boolean {
  const code = filter.replace(/"(?:[^"\\]|\\.)*"/g, '""');
  return /\$ENV\b/.test(code) || /(?<![.$\w])env\b(?!\s*[:,}])/.test(code);
}

/** The filter of a jq command line: the first word that is not an option or an option's value. With -f the program is a file: none. */
export function jqFilters(args: ReadonlyArray<string | null>): string[] {
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === null) continue;
    if (a === '--arg' || a === '--argjson' || a === '--slurpfile' || a === '--rawfile') { i += 2; continue; }
    if (a === '--indent') { i += 1; continue; }
    if (a === '--from-file' || /^-[a-zA-Z]*f$/.test(a)) return [];
    if (a.startsWith('-') && a !== '-') continue;
    return [a];
  }
  return [];
}

const RUN_SCRIPT_WORDS = new Set(['run', 'run-script', 'rum', 'urn']);

/** `npm run env` (also pnpm, yarn and bun) runs npm's built-in `env` script, which prints the environment. */
export function packageRunsEnvScript(args: ReadonlyArray<string | null>): boolean {
  const at = args.findIndex((a) => a !== null && RUN_SCRIPT_WORDS.has(a));
  if (at < 0) return false;
  for (let i = at + 1; i < args.length; i += 1) {
    const a = args[i];
    if (a === null) return false;
    if (a.startsWith('-')) { if (a === '--prefix' || a === '-C' || a === '--workspace' || a === '-w' || a === '--cwd') i += 1; continue; }
    return a === 'env';
  }
  return false;
}

export { PROC_ENVIRON } from '../secret-paths';

/** A glob that can name `environ`: `/proc/self/env*`, `/proc/1/*`, `/proc/self/task/1/e[n]viron`. */
export function procGlobMatchesEnviron(path: string): boolean {
  const m = /^\/proc\/[^/]+\/(?:task\/[^/]+\/)?([^/]*[*?[][^/]*)$/.exec(path);
  if (!m) return false;
  let source = '';
  for (let i = 0; i < m[1].length; i += 1) {
    const ch = m[1][i];
    if (ch === '*') source += '.*';
    else if (ch === '?') source += '.';
    else if (ch === '[') {
      const end = m[1].indexOf(']', i + 2);
      if (end < 0) return true;
      const body = m[1].slice(i + 1, end).replace(/^[!^]/, '');
      source += `[${body.replace(/[\\\]^]/g, '\\$&')}]`;
      i = end;
    } else source += ch.replace(/[.+^${}()|\\]/g, '\\$&');
  }
  try { return new RegExp(`^${source}$`).test('environ'); } catch { return true; }
}

/** `/proc`, `/proc/<pid>` and `/proc/<pid>/task[/<tid>]`: a folder whose recursive read reaches every `environ` under it. */
export const PROC_PROCESS_DIRECTORY = /^\/proc(?:\/[^/]+(?:\/task(?:\/[^/]+)?)?)?\/?$/;

/** Programs that read or copy every file under a folder named to them. */
export const RECURSIVE_READERS: ReadonlySet<string> = new Set(['grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack', 'tar', 'gtar', 'bsdtar', 'cp', 'rsync', 'zip', 'scp']);

/** Variables whose value runs as a command: a pager, editor, askpass or diff helper set to `env` prints the environment. */
export const HELPER_ENV_VARS: ReadonlySet<string> = new Set(['PAGER', 'GIT_PAGER', 'MANPAGER', 'EDITOR', 'VISUAL', 'GIT_EDITOR', 'GIT_SEQUENCE_EDITOR', 'GIT_EXTERNAL_DIFF',
  'GIT_SSH_COMMAND', 'GIT_SSH', 'GIT_ASKPASS', 'SSH_ASKPASS', 'BROWSER', 'LESSOPEN', 'GIT_PROXY_COMMAND', 'PROMPT_COMMAND']);

/** A command word that is the environment printer, alone or followed by arguments. */
export const ENV_PRINTER_COMMAND = /^\s*(?:\S*\/)?(?:env|printenv)(?:\s|$)/;

/** `man -P env`, `man --pager=printenv`: the pager is the command. */
export function manPagerPrintsEnvironment(args: ReadonlyArray<string | null>): boolean {
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === null) continue;
    if ((a === '-P' || a === '--pager') && args[i + 1] != null && ENV_PRINTER_COMMAND.test(args[i + 1] as string)) return true;
    const m = /^(?:--pager=|-P)([\s\S]+)$/.exec(a);
    if (m && ENV_PRINTER_COMMAND.test(m[1])) return true;
  }
  return false;
}

/** strace shows the whole environment of an exec it traces unless its strings are abbreviated: `-v`, `--no-abbrev`, `-e abbrev=none`, `-e verbose=...`. */
export function straceShowsEnvironment(args: ReadonlyArray<string | null>): boolean {
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    if (a === null) continue;
    if (a === '--') return false;
    if (a === '--no-abbrev') return true;
    if (a === '-e' || a === '--trace' || a === '--abbrev' || a === '--verbose') { if (/(?:abbrev\s*=\s*none|verbose)/.test(String(args[i + 1] ?? ''))) return true; i += a === '-e' || a === '--trace' ? 1 : 0; continue; }
    if (/^-e./.test(a)) { if (/(?:abbrev\s*=\s*none|verbose)/.test(a)) return true; continue; }
    if (/^-[a-zA-Z]+$/.test(a)) {
      for (let k = 1; k < a.length; k += 1) {
        if (a[k] === 'v') return true;
        if ('eopsEuOSabPIUX'.includes(a[k])) { if (k === a.length - 1) i += 1; break; }
      }
      continue;
    }
    if (!a.startsWith('-')) return false;
  }
  return false;
}

const TMUX_COMMAND_VALUE_FLAGS: Record<string, string> = {
  'send-keys': 'tNc', send: 'tNc', 'run-shell': 'cdt', run: 'cdt', 'new-session': 'cefFnstxy', new: 'cefFnstxy', 'new-window': 'cenFt', neww: 'cenFt',
  'split-window': 'ceFltp', splitw: 'ceFltp', 'respawn-pane': 'cet', respawnp: 'cet', 'respawn-window': 'cet', respawnw: 'cet', 'pipe-pane': 't', pipep: 't',
  'if-shell': 't', if: 't',
};

/** `tmux send-keys env Enter`, `tmux new -d printenv`, `tmux run-shell env`: a command window or pane runs the environment printer. */
export function tmuxRunsEnvironmentPrinter(args: ReadonlyArray<string | null>): boolean {
  let i = 0;
  while (i < args.length && args[i] !== null && (args[i] as string).startsWith('-') && args[i] !== '-') i += /^-[SLfcT]$/.test(args[i] as string) ? 2 : 1;
  const name = args[i];
  if (name === null || name === undefined || !(name in TMUX_COMMAND_VALUE_FLAGS)) return false;
  const valueFlags = TMUX_COMMAND_VALUE_FLAGS[name];
  for (i += 1; i < args.length; i += 1) {
    const a = args[i];
    if (a === null) continue;
    if (a === ';' || a === '\\;') return false;
    if (/^-[a-zA-Z]$/.test(a) && valueFlags.includes(a[1])) { i += 1; continue; }
    if (a.startsWith('-') && a.length > 1) continue;
    if (/^(?:\S*\/)?(?:env|printenv)$/.test(a)) return true;
  }
  return false;
}
