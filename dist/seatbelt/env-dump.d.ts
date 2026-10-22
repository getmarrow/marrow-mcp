/** S4 reasons that mean "prints the environment". The keyed hook keeps only these from a mapper run. */
export declare const ENV_DUMP_REASONS: ReadonlySet<string>;
/**
 * Programs that run the command at the end of their argv with a grammar the mapper does not model. A bare `env` or
 * `printenv` as their last word is that command, not a name (`python -m venv env` and `conda activate env` stay fine:
 * those programs are not listed).
 */
export declare const EXEC_WRAPPERS: ReadonlySet<string>;
/** `compgen -e`, `-v`, `-A export` and `-A variable` list the names of the environment's variables. */
export declare function compgenListsVariables(args: ReadonlyArray<string | null>): boolean;
/** `tmux [options] show-environment` (also `showenv`, a unique prefix, and a command after `\\;`) prints a session's variables. */
export declare function tmuxShowsEnvironment(args: ReadonlyArray<string | null>): boolean;
/** `systemctl [--user] show-environment` prints the manager's environment. */
export declare function systemctlShowsEnvironment(args: ReadonlyArray<string | null>): boolean;
/**
 * BSD `ps e`, `ps auxe`, `ps eww` and `ps -E` print every process's environment. A word of letters that holds `e`, or a dash
 * cluster that holds `E`, outside the value of an option (`ps -p 1 -o etime` asks for a column, not the environment).
 */
export declare function psPrintsEnvironment(args: ReadonlyArray<string | null>): boolean;
/** The older, looser reading of `ps`: any word of letters that holds `e`, option values included. The keyless seatbelt keeps stopping it. */
export declare function psLooselyPrintsEnvironment(args: ReadonlyArray<string | null>): boolean;
/** The environment object in a jq filter: `env`, `$ENV` (not a `.env` field, a key, or text in a string). */
export declare function jqFilterReadsEnvironment(filter: string): boolean;
/** The filter of a jq command line: the first word that is not an option or an option's value. With -f the program is a file: none. */
export declare function jqFilters(args: ReadonlyArray<string | null>): string[];
/** `npm run env` (also pnpm, yarn and bun) runs npm's built-in `env` script, which prints the environment. */
export declare function packageRunsEnvScript(args: ReadonlyArray<string | null>): boolean;
export { PROC_ENVIRON } from '../secret-paths';
/** A glob that can name `environ`: `/proc/self/env*`, `/proc/1/*`, `/proc/self/task/1/e[n]viron`. */
export declare function procGlobMatchesEnviron(path: string): boolean;
/** `/proc`, `/proc/<pid>` and `/proc/<pid>/task[/<tid>]`: a folder whose recursive read reaches every `environ` under it. */
export declare const PROC_PROCESS_DIRECTORY: RegExp;
/** Programs that read or copy every file under a folder named to them. */
export declare const RECURSIVE_READERS: ReadonlySet<string>;
/** Variables whose value runs as a command: a pager, editor, askpass or diff helper set to `env` prints the environment. */
export declare const HELPER_ENV_VARS: ReadonlySet<string>;
/** A command word that is the environment printer, alone or followed by arguments. */
export declare const ENV_PRINTER_COMMAND: RegExp;
/** `man -P env`, `man --pager=printenv`: the pager is the command. */
export declare function manPagerPrintsEnvironment(args: ReadonlyArray<string | null>): boolean;
/** strace shows the whole environment of an exec it traces unless its strings are abbreviated: `-v`, `--no-abbrev`, `-e abbrev=none`, `-e verbose=...`. */
export declare function straceShowsEnvironment(args: ReadonlyArray<string | null>): boolean;
/** `tmux send-keys env Enter`, `tmux new -d printenv`, `tmux run-shell env`: a command window or pane runs the environment printer. */
export declare function tmuxRunsEnvironmentPrinter(args: ReadonlyArray<string | null>): boolean;
//# sourceMappingURL=env-dump.d.ts.map