import type { SeatbeltFs } from './seatbelt-fs';
import { realPath } from './seatbelt-path';
import { GIT_RELOCATING_ENV } from './seatbelt-git';

// Indirect command resolution for S2/S3 (spec §1.2, abuse rows A11/A12):
// package.json scripts, Makefile recipes and script files are read at hook
// time so a harmless-looking name cannot hide a deploy or publish. Anything
// that cannot be read exactly comes back 'unknown'.

export const MAX_SCRIPT_BYTES = 64 * 1024;
export const MAX_MANIFEST_BYTES = 1024 * 1024;
export const MAX_MAKE_DEPTH = 3;
/** Parse budgets: over any of them the Makefile is 'unknown' (time and memory stay linear in its size). */
export const MAX_MAKE_TARGETS_PER_RULE = 256;
export const MAX_MAKE_PREREQUISITES = 4096;
export const MAX_MAKE_RULES = 4096;
export const MAX_MAKE_RECIPE_LINES = 16384;
export const MAX_MAKE_COMMANDS = 1024;
export const MAX_MAKE_EXPANDED_BYTES = 256 * 1024;

type Read = { status: 'ok'; text: string; path: string } | { status: 'absent' } | { status: 'unknown'; reason: 'unreadable' | 'too_large' | 'not_file' };

function readResolved(fs: SeatbeltFs, path: string, maxBytes: number): Read {
  const real = realPath(fs, path, { followFinal: true });
  if (real.status !== 'resolved') return { status: 'unknown', reason: 'unreadable' };
  if (!real.exists) return { status: 'absent' };
  try {
    const entry = fs.lstat(real.path);
    if (!entry) return { status: 'absent' };
    if (entry.type !== 'file') return { status: 'unknown', reason: 'not_file' };
    if (entry.size > maxBytes) return { status: 'unknown', reason: 'too_large' };
    const text = fs.readFile(real.path, maxBytes);
    return text === null ? { status: 'unknown', reason: 'too_large' } : { status: 'ok', text, path: real.path };
  } catch {
    return { status: 'unknown', reason: 'unreadable' };
  }
}

function parentOf(dir: string): string | null {
  if (dir === '/') return null;
  return dir.slice(0, dir.lastIndexOf('/')) || '/';
}

export type PackageScripts =
  | { status: 'ok'; packageDir: string; commands: Array<{ name: string; command: string }> }
  | { status: 'absent' }
  | { status: 'unknown'; reason: string };

/**
 * The commands `npm|pnpm|yarn|bun run <name>` executes: pre<name>, <name>,
 * post<name>, from the nearest package.json at or above dir (npm's prefix).
 * A missing script is 'absent' (the runner fails); a malformed manifest is unknown.
 */
export function resolvePackageScript(fs: SeatbeltFs, dir: string, name: string): PackageScripts {
  return packageCommands(fs, dir, [`pre${name}`, name, `post${name}`]);
}

/** Lifecycle scripts `npm publish` runs (S3 "lifecycle prepublish*"). */
export const PUBLISH_LIFECYCLE = ['prepublish', 'prepare', 'prepublishOnly', 'prepack', 'postpack', 'publish', 'postpublish'];

export function packageCommands(fs: SeatbeltFs, dir: string, names: string[]): PackageScripts {
  let current: string | null = dir;
  while (current) {
    const read = readResolved(fs, current === '/' ? '/package.json' : `${current}/package.json`, MAX_MANIFEST_BYTES);
    if (read.status === 'unknown') return { status: 'unknown', reason: read.reason };
    if (read.status === 'ok') {
      let manifest: unknown;
      try {
        manifest = JSON.parse(read.text);
      } catch {
        return { status: 'unknown', reason: 'malformed' };
      }
      if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) return { status: 'unknown', reason: 'malformed' };
      const scripts = (manifest as Record<string, unknown>).scripts;
      if (scripts !== undefined && (typeof scripts !== 'object' || scripts === null || Array.isArray(scripts))) return { status: 'unknown', reason: 'malformed' };
      const table = (scripts || {}) as Record<string, unknown>;
      const commands: Array<{ name: string; command: string }> = [];
      for (const name of names) {
        if (!Object.prototype.hasOwnProperty.call(table, name)) continue;
        const command = table[name];
        if (typeof command !== 'string') return { status: 'unknown', reason: 'malformed' };
        commands.push({ name, command });
      }
      return { status: 'ok', packageDir: current, commands };
    }
    current = parentOf(current);
  }
  return { status: 'absent' };
}

export type MakeResolution =
  | { status: 'ok'; makefile: string; commands: string[]; dynamic: boolean }
  | { status: 'absent' }
  | { status: 'unknown'; reason: string };

// One parsed rule line (`a b c: p q; recipe`): its prerequisites and recipe
// are stored once and shared by every target it names, so a long target list
// costs one entry per name, not names × prerequisites. Prerequisites are
// expanded when the line is read (make's immediate context); `unresolved`
// records that the expansion needed a value this resolver does not have.
interface MakeRuleLine {
  prerequisites: string[];
  unresolved: boolean;
  recipe: string[];
}

interface MakeRule {
  lines: MakeRuleLine[];
}

interface MakeVariable {
  flavor: 'simple' | 'recursive';
  value: string;
  /** The value (or a name in it) could not be resolved: any use is dynamic. */
  unresolved: boolean;
}

const MAKEFILE_NAMES = ['GNUmakefile', 'makefile', 'Makefile'];

/**
 * Special targets that only tune make's behaviour; every other dot-target
 * (suffix rules, .DEFAULT, .SECONDEXPANSION, .ONESHELL, .EXPORT_ALL_VARIABLES
 * ...) can change which recipe runs or what it runs with.
 */
const MAKE_HARMLESS_SPECIAL_TARGETS = new Set(['.PHONY', '.PRECIOUS', '.INTERMEDIATE', '.SECONDARY', '.SILENT', '.IGNORE', '.DELETE_ON_ERROR', '.LOW_RESOLUTION_TIME', '.NOTPARALLEL', '.POSIX']);

/** Variables that change which program runs the recipes or which files make reads: assigning one is dynamic. */
const MAKE_EXECUTION_VARIABLES = new Set(['SHELL', 'MAKE', 'MAKEFLAGS', 'MFLAGS', 'GNUMAKEFLAGS', 'MAKEFILES', 'MAKEOVERRIDES', 'MAKELEVEL', 'MAKE_COMMAND', 'MAKECMDGOALS', 'VPATH', 'CURDIR']);

/** Environment that changes how make itself reads files or resolves variables: any of them present makes the answer dynamic. */
const MAKE_RELOCATING_ENV = ['MAKEFLAGS', 'GNUMAKEFLAGS', 'MFLAGS', 'MAKEFILES', 'MAKEOVERRIDES'];

/** A plain system shell path is the one SHELL value that is understood. */
const MAKE_SAFE_SHELL = /^(?:\/usr)?(?:\/local)?\/bin\/(?:sh|bash|zsh|dash|ksh|ash)$/;

/**
 * Names that change what a recipe's program is or where it runs: shell start-up
 * files, search paths, loaders, relocated tool state. make hands every variable
 * that came from the environment or the command line to each recipe (and all of
 * them under `.EXPORT_ALL_VARIABLES` or `export`), so an assignment to one of
 * these, in the file or on the command line, is dynamic whether or not this
 * resolver can tell that make exports it. Anything else is only a recipe
 * environment change when the name is in the caller's environment.
 */
const MAKE_RECIPE_ENV_DENY = new RegExp(
  '^(?:' +
    [
      'PATH', 'BASH_ENV', 'ENV', 'SHELL', 'SHELLOPTS', 'BASHOPTS', 'IFS', 'CDPATH', 'ZDOTDIR', 'HOME', 'TMPDIR', 'PS4', 'PROMPT_COMMAND',
      'BASH_.*', 'GIT_.*', 'LD_.*', 'DYLD_.*', 'NODE_.*', 'PYTHON.*', 'PERL.*', 'RUBY.*', 'XDG_.*',
      'EDITOR', 'VISUAL', 'PAGER', 'BROWSER', 'LESSOPEN', 'LOCPATH', 'NLSPATH', 'GCONV_PATH', 'HOSTALIASES',
      'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'CLASSPATH', 'GOFLAGS', 'RUSTC_WRAPPER', 'RUSTFLAGS',
    ].join('|') +
    ')$',
);
/** npm reads its configuration from `npm_config_*` in either case. */
const MAKE_RECIPE_ENV_DENY_ANY_CASE = /^(?:npm_config_.*|path)$/i;

/**
 * Names that make every recipe (or the git, node or tool it starts) run other
 * code or somewhere else: shell start-up files, the dynamic loader, relocated
 * git. A routine environment has none of them, so one present in the caller's
 * environment (the hook's, or a prefix assignment of the command) is dynamic.
 */
const MAKE_INJECTION_ENV = new RegExp(`^(?:BASH_ENV|ENV|SHELLOPTS|BASHOPTS|PS4|PROMPT_COMMAND|IFS|CDPATH|ZDOTDIR|BASH_FUNC_.*|LD_.*|DYLD_.*|${GIT_RELOCATING_ENV.join('|')})$`);

/**
 * Variables GNU make defines before it reads any file (`make -p -f /dev/null`
 * 4.3, plus the names of later versions). `CC ?= gcc` does not assign (CC is
 * `cc`) and `RM += -r` is `rm -f -r`: with no assignment from the file their
 * value is not known here, so `?=` and `+=` on them are unresolved.
 */
const MAKE_BUILTIN_VARIABLES = new Set([
  'AR', 'ARFLAGS', 'AS', 'CC', 'CO', 'COFLAGS', 'CPP', 'CTANGLE', 'CWEAVE', 'CXX', 'F77', 'F77FLAGS', 'FC', 'GET', 'LD', 'LEX', 'LINT', 'M2C', 'MAKEINFO', 'OBJC', 'OUTPUT_OPTION', 'PC', 'RM', 'TANGLE', 'TEX', 'TEXI2DVI', 'WEAVE', 'YACC',
  'MAKE_HOST', 'MAKE_VERSION', 'MAKE_TERMOUT', 'MAKE_TERMERR', 'MAKEFILE_LIST', 'SUFFIXES', 'GPATH',
]);
const MAKE_BUILTIN_VARIABLE_FAMILIES = /^(?:COMPILE|LINK|PREPROCESS|YACC|LEX|LINT)\./;

/** Make functions with no side effect (not evaluated here, but a use of their result is unresolved, not an execution at read time). */
const MAKE_PURE_FUNCTIONS = new Set(['subst', 'patsubst', 'strip', 'findstring', 'filter', 'filter-out', 'sort', 'word', 'wordlist', 'words', 'firstword', 'lastword', 'dir', 'notdir', 'suffix', 'basename', 'addsuffix', 'addprefix', 'join', 'wildcard', 'realpath', 'abspath']);

const MAKE_SIMPLE_FLAGS = new Set(['-s', '-k', '-w', '--silent', '--quiet', '--keep-going', '--no-print-directory', '--print-directory']);

/** The very function or object Object.prototype hands every object under this name (`toString`, `constructor`, `__proto__` ...): not an environment variable. */
function inheritedBuiltin(env: object, name: string, value: unknown): boolean {
  if (Object.prototype.hasOwnProperty.call(env, name)) return false;
  if (name === '__proto__') return value === Object.getPrototypeOf(env);
  return name in Object.prototype && value === (Object.prototype as unknown as Record<string, unknown>)[name];
}

/**
 * A simple Makefile recipe parse: explicit rules, recipe lines, prerequisites
 * (depth ≤3) and variable references. Expansion follows GNU make: `=` is
 * deferred, `:=`/`::=` are expanded when read, `?=` and `+=` need the prior
 * value (the environment, when `options.env` is not given, is unknown), target
 * names and prerequisites are expanded when the rule line is read and split
 * into words, recipes after the whole file is read. `$(MAKE) <targets>` in a
 * recipe is followed in the same file. `include`, conditionals, pattern or
 * suffix rules, functions (`$(shell …)`), target-specific variables, variables
 * that change the shell, or an unknown variable make the answer dynamic, which
 * the mapper treats like an unknown script.
 *
 * `options.env` is the environment make would run in (the hook's, plus the
 * command's prefix assignments). A caller MUST pass it: with it omitted every
 * answer is dynamic, because MAKEFLAGS/MAKEFILES, `?=` and the names make
 * exports to recipes all depend on it.
 *
 * Allowlist: an answer is definite only when none of these holds, each of which
 * makes make run something the file does not say, or run it differently:
 * `options.env` omitted, holding a non-string (an own property, enumerable or
 * not), MAKEFLAGS-like names, shell
 * start-up / loader / git-relocating names, or a PATH entry that is relative,
 * non-canonical or inside the makefile's directory; an assignment (file or
 * command line) to a dot-name, an execution variable, a name make hands to
 * recipes (MAKE_RECIPE_ENV_DENY) or a name in the environment; `export`,
 * `unexport`, `.EXPORT_ALL_VARIABLES`; `?=`/`+=` on a variable make defines
 * itself; a command-line value with `$` or a control character, or a
 * command-line name no expansion reaches; an assignment the command line overrides
 * (make still reads it) that is `!=` or has a right side not proven inert; a recipe-less target that is not
 * .PHONY and could have a source file (built-in rules); a rule for the makefile
 * itself; two recipes for one target. A Makefile with a NUL byte, or a CR that
 * does not end a CRLF, is `unknown` (control_character). The mapper must re-classify `commands`.
 */
export function resolveMakeTargets(fs: SeatbeltFs, dir: string, targets: string[], options: { makefile?: string; overrides?: Record<string, string>; env?: Record<string, string | undefined> } = {}): MakeResolution {
  let read: Read = { status: 'absent' };
  if (options.makefile) read = readResolved(fs, options.makefile.startsWith('/') ? options.makefile : `${dir}/${options.makefile}`, MAX_MANIFEST_BYTES);
  else {
    for (const name of MAKEFILE_NAMES) {
      read = readResolved(fs, `${dir}/${name}`, MAX_MANIFEST_BYTES);
      if (read.status !== 'absent') break;
    }
  }
  if (read.status !== 'ok') return read.status === 'absent' ? read : { status: 'unknown', reason: read.reason };
  // make drops the rest of a line after a NUL, and the newline with it: the next line is joined to this one, so a NUL
  // can hide a rule header or a recipe line from a reader that keeps the text. A CR that does not end a CRLF is not a
  // line end to make, though it is one to other readers. Neither is modelled: the file is not read.
  if (read.text.includes('\0') || /\r(?!\n)/.test(read.text)) return { status: 'unknown', reason: 'control_character' };
  const variables = new Map<string, MakeVariable>();
  const rules = new Map<string, MakeRule>();
  const makefileNames = new Set<string>([...MAKEFILE_NAMES, read.path.slice(read.path.lastIndexOf('/') + 1)]);
  let firstTarget: string | null = null;
  const phony = new Set<string>();
  let dynamic = false;
  let current: MakeRuleLine | null = null;
  let prerequisiteCount = 0;
  let recipeCount = 0;
  const overBudget: MakeResolution = { status: 'unknown', reason: 'too_complex' };
  // The environment make would see. Unknown (undefined) means a name the file
  // does not assign may still have a value, ?= / += cannot be resolved, and
  // MAKEFLAGS / MAKEFILES / exported names cannot be ruled out: the answer is
  // dynamic. A caller that states no environment never gets a definite answer.
  const env = options.env;
  /**
   * A string value only. `constructor`, `__proto__` and `toString` (functions and objects Object.prototype hands every
   * object) are not environment variables. Any other value that is neither undefined nor a string is not understood
   * (make is handed it as some text): the answer is dynamic, whichever way the value was reached.
   */
  const envValue = (name: string): string | undefined => {
    if (!env) return undefined;
    const value = env[name];
    if (typeof value === 'string') return value;
    if (value !== undefined && !inheritedBuiltin(env, name, value)) dynamic = true;
    return undefined;
  };
  if (!env || MAKE_RELOCATING_ENV.some((name) => envValue(name) !== undefined)) dynamic = true;
  const makeDirectories = [dir, read.path.slice(0, read.path.lastIndexOf('/')) || '/'].map((directory) => directory.replace(/\/+$/, '') || '/');
  const isTrustedPathEntry = (entry: string): boolean => {
    if (!/^(?:\/|[A-Za-z]:[\\/])/.test(entry) || /(?:^|[\\/])\.{1,2}(?:[\\/]|$)/.test(entry)) return false;
    const bare = entry.replace(/\/+$/, '') || '/';
    return !makeDirectories.some((directory) => directory === '/' || bare === directory || bare.startsWith(`${directory}/`));
  };
  const envNames = new Set<string>();
  if (env) {
    // for...in: a name an object only inherits is still a name make would see; an own property that is not enumerable
    // is one too (the same value `envValue` reads). A value that is not a string is not understood.
    const names = new Set<string>();
    for (const name in env) names.add(name);
    for (const name of Object.getOwnPropertyNames(env)) names.add(name);
    for (const name of names) {
      const value = env[name];
      if (typeof value !== 'string') {
        if (value !== undefined) dynamic = true;
        continue;
      }
      envNames.add(name.toUpperCase());
      if (MAKE_INJECTION_ENV.test(name.toUpperCase())) dynamic = true;
      // A PATH entry that is relative, empty, not canonical or inside the directory make runs in makes `git` or
      // `make` in a recipe a file of the project (the workspace root above it is the mapper's to model).
      if (name.toUpperCase() === 'PATH' && value.split(value.includes(';') ? ';' : ':').some((entry) => !isTrustedPathEntry(entry))) dynamic = true;
    }
  }
  /**
   * make hands this name to every recipe, or it changes what runs or where:
   * assigning it (in the file or on the command line, any operator) is dynamic.
   * Dot-names are make's own settings; a name in the environment is exported
   * with its new value; the rest is MAKE_RECIPE_ENV_DENY and MAKE_EXECUTION_VARIABLES.
   */
  const changesWhatRuns = (name: string): boolean =>
    name.startsWith('.') || MAKE_EXECUTION_VARIABLES.has(name) || MAKE_RECIPE_ENV_DENY.test(name) || MAKE_RECIPE_ENV_DENY_ANY_CASE.test(name) || envNames.has(name.toUpperCase());
  const isBuiltin = (name: string): boolean => MAKE_BUILTIN_VARIABLES.has(name) || MAKE_BUILTIN_VARIABLE_FAMILIES.test(name);
  const commandLine = new Map<string, string>(Object.entries(options.overrides || {}));
  // A command-line variable is exported to every recipe and its value is expanded each time make builds a recipe
  // environment, used or not: only a plain value and a name the Makefile itself uses (and that is not one of the lists) are definite.
  const referenced = new Set<string>();
  for (const [name, value] of commandLine) {
    const shell = name === 'SHELL' && MAKE_SAFE_SHELL.test(value);
    if (!shell && changesWhatRuns(name)) dynamic = true;
    if (/[$\x00-\x1f\x7f]/.test(value)) dynamic = true;
    variables.set(name, { flavor: 'recursive', value, unresolved: false });
  }

  // Every expansion is charged to one budget, so nested variables cannot blow up.
  let expandedBytes = 0;
  let exhausted = false;
  // Set while the right side of an assignment make drops is only looked at: no name is marked as used, and a value this
  // resolver could not compute counts as a function with effects (it may hold one).
  let probing = false;
  const MAKE_AUTOMATIC = /^[@<^*?%+|]$/;
  /**
   * `state.bad` is set when a reference could not be resolved (the reference
   * text is kept as written). `state.fn` is set when make would run a function
   * with side effects (`$(shell …)`, `$(eval …)`, `$(file …)`, unparsed syntax):
   * in a context make expands when it reads the line, that executes whether or
   * not the target is wanted.
   */
  const expand = (text: string, state: { bad: boolean; fn: boolean }, depth = 0): string => {
    if (!text.includes('$')) return text;
    expandedBytes += text.length;
    if (expandedBytes > MAX_MAKE_EXPANDED_BYTES) {
      exhausted = true;
      return '';
    }
    if (depth > 8) {
      state.bad = true;
      state.fn = true;
      return text;
    }
    let out = '';
    let i = 0;
    while (i < text.length) {
      const ch = text[i];
      if (ch !== '$') {
        out += ch;
        i += 1;
        continue;
      }
      const next = text[i + 1];
      if (next === undefined) {
        state.bad = true;
        state.fn = true;
        out += '$';
        i += 1;
        continue;
      }
      if (next === '$') {
        out += '$';
        i += 2;
        continue;
      }
      let reference: string;
      let name: string;
      if (next === '(' || next === '{') {
        const close = next === '(' ? ')' : '}';
        let level = 1;
        let j = i + 2;
        while (j < text.length && level > 0) {
          if (text[j] === next) level += 1;
          else if (text[j] === close) level -= 1;
          j += 1;
        }
        if (level !== 0) {
          // Unbalanced: nothing after this point can be read reliably.
          state.bad = true;
          state.fn = true;
          out += text.slice(i);
          break;
        }
        reference = text.slice(i, j);
        const inner = text.slice(i + 2, j - 1);
        name = inner.includes('$') ? expand(inner, state, depth + 1) : inner;
        i = j;
      } else {
        reference = text.slice(i, i + 2);
        name = next;
        i += 2;
      }
      if (exhausted) return '';
      if (MAKE_AUTOMATIC.test(name)) {
        out += reference;
        continue;
      }
      // A function call (`$(shell …)`, `$(subst …)`), a substitution reference
      // or an automatic-variable modifier is not evaluated here.
      if (!/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(name)) {
        state.bad = true;
        const functionName = /^([A-Za-z][A-Za-z-]*)\s/.exec(name)?.[1];
        if (functionName !== undefined) {
          if (!MAKE_PURE_FUNCTIONS.has(functionName)) state.fn = true;
        } else if (!/^[A-Za-z_][A-Za-z0-9_.-]*:[^\s=]*=\S*$/.test(name)) state.fn = true;
        out += reference;
        continue;
      }
      if (!probing) referenced.add(name);
      const variable = variables.get(name);
      if (variable === undefined) {
        const fromEnv = envValue(name);
        if (fromEnv !== undefined) {
          const inner = { bad: false, fn: false };
          out += expand(fromEnv, inner, depth + 1);
          if (inner.bad) state.bad = true;
          if (inner.fn) state.fn = true;
        } else if (name === 'MAKE' && !options.overrides?.MAKE) out += 'make';
        else {
          state.bad = true;
          out += reference;
        }
        continue;
      }
      if (variable.unresolved) {
        state.bad = true;
        if (probing) state.fn = true;
        out += reference;
        continue;
      }
      if (variable.flavor === 'simple') out += variable.value;
      else {
        const inner = { bad: false, fn: false };
        out += expand(variable.value, inner, depth + 1);
        if (inner.bad) state.bad = true;
        if (inner.fn) state.fn = true;
      }
    }
    return out;
  };
  const words = (value: string): string[] => value.split(/\s+/).filter(Boolean);

  const lines = read.text.replace(/\\\r?\n/g, ' ').split(/\r?\n/);
  for (const rawLine of lines) {
    let line = rawLine;
    if (line.startsWith('\t')) {
      if (current) {
        recipeCount += 1;
        if (recipeCount > MAX_MAKE_RECIPE_LINES) return overBudget;
        current.recipe.push(line.slice(1));
        continue;
      }
      // Outside a rule a tab-led line is ordinary makefile syntax (GNU make read.c).
      line = line.replace(/^\t+/, '');
    }
    // `\#` is a literal hash; this resolver does not model it.
    if (line.includes('\\#')) dynamic = true;
    const trimmed = line.replace(/#.*$/, '').trim();
    if (!trimmed) continue;
    if (/^(-?include|sinclude|ifeq|ifneq|ifdef|ifndef|else|endif|define|endef|export|unexport|undefine|vpath|load|-load)\b/.test(trimmed)) {
      dynamic = true;
      current = null;
      continue;
    }
    const assign = /^(override\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*(\?=|:::=|::=|:=|\+=|!=|=)\s*(.*)$/.exec(trimmed);
    if (assign) {
      const [, overrideKeyword, name, op, value] = assign;
      current = null;
      const safeShell = name === 'SHELL' && (op === '=' || op === ':=' || op === '::=') && MAKE_SAFE_SHELL.test(value.trim());
      if (!safeShell && changesWhatRuns(name)) dynamic = true;
      // A variable given on the command line wins over the file's assignments (unless `override`). make still reads the
      // dropped assignment: `!=` runs its command, and `:=` / `::=` / `:::=` expand their right side, at read time and
      // under `make -n`. The right side is looked at as if it were assigned (`=`, `?=` and `+=` too: make does not
      // expand those, a call in them is still not proven inert): a call with effects, or a value not understood, is dynamic.
      if (commandLine.has(name) && !overrideKeyword) {
        if (op === '!=') dynamic = true;
        else {
          const state = { bad: false, fn: false };
          probing = true;
          try {
            expand(value, state);
          } finally {
            probing = false;
          }
          if (exhausted) return overBudget;
          if (state.fn) dynamic = true;
        }
        continue;
      }
      const existing = variables.get(name);
      if (op === '!=') {
        dynamic = true;
        variables.set(name, { flavor: 'simple', value: '', unresolved: true });
      } else if (op === '=') variables.set(name, { flavor: 'recursive', value, unresolved: false });
      else if (op === ':=' || op === '::=') {
        const state = { bad: false, fn: false };
        variables.set(name, { flavor: 'simple', value: expand(value, state), unresolved: state.bad });
        if (state.fn) dynamic = true;
      } else if (op === ':::=') {
        const state = { bad: false, fn: false };
        variables.set(name, { flavor: 'recursive', value: expand(value, state).replace(/\$/g, '$$$$'), unresolved: state.bad });
        if (state.fn) dynamic = true;
      } else if (op === '?=') {
        // Defined already (in the file or on the command line): unchanged. Otherwise the environment decides.
        if (existing === undefined) {
          const fromEnv = envValue(name);
          if (fromEnv !== undefined) variables.set(name, { flavor: 'recursive', value: fromEnv, unresolved: false });
          else if (env && !isBuiltin(name)) variables.set(name, { flavor: 'recursive', value, unresolved: false });
          else variables.set(name, { flavor: 'recursive', value, unresolved: true });
        }
      } else if (op === '+=') {
        if (existing === undefined) {
          const fromEnv = envValue(name);
          if (fromEnv !== undefined) variables.set(name, { flavor: 'recursive', value: `${fromEnv} ${value}`, unresolved: false });
          else if (env && !isBuiltin(name)) variables.set(name, { flavor: 'recursive', value, unresolved: false });
          else variables.set(name, { flavor: 'recursive', value, unresolved: true });
        } else if (existing.flavor === 'simple') {
          const state = { bad: false, fn: false };
          const added = expand(value, state);
          variables.set(name, { flavor: 'simple', value: `${existing.value} ${added}`.trim(), unresolved: existing.unresolved || state.bad });
          if (state.fn) dynamic = true;
        } else variables.set(name, { flavor: 'recursive', value: `${existing.value} ${value}`.trim(), unresolved: existing.unresolved });
      }
      const stored = variables.get(name);
      if (stored !== undefined && stored.value.length > MAX_MAKE_EXPANDED_BYTES) return overBudget;
      if (exhausted) return overBudget;
      continue;
    }
    const rule = /^([^:=]+)::?([^=]*)$/.exec(trimmed);
    if (!rule) {
      // Target-specific variables (`t: V = x`), `.RECIPEPREFIX`, anything else this parse does not model.
      dynamic = true;
      current = null;
      continue;
    }
    let prereqs = rule[2].trim();
    let inlineRecipe: string | null = null;
    const semi = prereqs.indexOf(';');
    if (semi >= 0) {
      inlineRecipe = prereqs.slice(semi + 1).trim();
      prereqs = prereqs.slice(0, semi);
    }
    const nameState = { bad: false, fn: false };
    const names = words(expand(rule[1].trim(), nameState));
    if (exhausted) return overBudget;
    // A name that cannot be expanded may be the wanted target.
    if (nameState.bad) dynamic = true;
    if (names.length > MAX_MAKE_TARGETS_PER_RULE) return overBudget;
    const prerequisiteState = { bad: false, fn: false };
    const expandedPrerequisites = expand(prereqs, prerequisiteState);
    if (exhausted) return overBudget;
    // Make expands prerequisites when it reads the line: a function with effects runs for every rule, wanted or not.
    if (prerequisiteState.fn) dynamic = true;
    const prerequisiteWords = words(expandedPrerequisites).filter((word) => word !== '|');
    // `$` left over (automatic variables, `$$`), a second `:` (static pattern rule) or a wildcard cannot be followed.
    const unresolved = prerequisiteState.bad || /[$:%*?[]/.test(expandedPrerequisites);
    const ruleLine: MakeRuleLine = { prerequisites: prerequisiteWords, unresolved, recipe: inlineRecipe ? [inlineRecipe] : [] };
    prerequisiteCount += ruleLine.prerequisites.length;
    if (prerequisiteCount > MAX_MAKE_PREREQUISITES) return overBudget;
    current = ruleLine;
    for (const name of names) {
      // make brings the makefile itself up to date first: a rule for it runs whatever target is wanted.
      if (makefileNames.has(name.replace(/^(?:\.\/)+/, ''))) dynamic = true;
      if (name.includes('%')) dynamic = true;
      if (name.startsWith('.') && !MAKE_HARMLESS_SPECIAL_TARGETS.has(name)) dynamic = true;
      if (name === '.PHONY') for (const word of prerequisiteWords) phony.add(word);
      if (name.startsWith('.') && MAKE_HARMLESS_SPECIAL_TARGETS.has(name)) continue;
      if (firstTarget === null && !name.includes('%') && !name.startsWith('.')) firstTarget = name;
      let entry = rules.get(name);
      if (!entry) {
        if (rules.size >= MAX_MAKE_RULES) return overBudget;
        entry = { lines: [] };
        rules.set(name, entry);
      }
      if (entry.lines[entry.lines.length - 1] !== ruleLine) entry.lines.push(ruleLine);
    }
  }

  const commands: string[] = [];
  const listings = new Map<string, string[] | null>();
  /**
   * A target with no recipe of its own that is not .PHONY is searched for in
   * make's built-in rules (`%.o: %.c`, `%: %.c`, `%: %.sh`, RCS/SCCS ...), which
   * run `$(CC)`, `$(COMPILE.c)` ... on a source file. With a file in the
   * directory that could be that source (or one that cannot be listed) the
   * commands make runs are not in the file: dynamic.
   */
  const implicitRuleMayApply = (target: string): boolean => {
    if (/[()$%*?[\]]/.test(target)) return true;
    const slash = target.lastIndexOf('/');
    const where = slash < 0 ? dir : target.startsWith('/') ? target.slice(0, slash) || '/' : `${dir}/${target.slice(0, slash)}`;
    let entries = listings.get(where);
    if (entries === undefined) {
      try {
        entries = fs.readdir(where);
      } catch {
        entries = null;
      }
      listings.set(where, entries);
    }
    if (entries === null) return true;
    const base = target.slice(slash + 1);
    const stem = base.split('.')[0];
    return entries.some((entry) => entry === 'RCS' || entry === 'SCCS' || (entry !== base && (entry.startsWith(`${stem}.`) || entry === `${base},v` || entry === `s.${base}`)));
  };
  const visit = (target: string, depth: number, seen: Set<string>) => {
    if (exhausted || seen.has(target)) return;
    seen.add(target);
    const rule = rules.get(target);
    if (!rule?.lines.some((ruleLine) => ruleLine.recipe.length > 0) && !phony.has(target) && implicitRuleMayApply(target)) dynamic = true;
    if (!rule) return;
    // Two rules with a recipe for one target: make keeps one (a warning) and drops the other, unless they are `::`
    // rules; which commands run, and which variables they expand, is not read here.
    if (rule.lines.filter((ruleLine) => ruleLine.recipe.length > 0).length > 1) dynamic = true;
    for (const ruleLine of rule.lines) {
      if (ruleLine.unresolved) dynamic = true;
      if (depth < MAX_MAKE_DEPTH) for (const prerequisite of ruleLine.prerequisites) visit(prerequisite, depth + 1, seen);
      else if (ruleLine.prerequisites.length > 0) dynamic = true;
    }
    for (const ruleLine of rule.lines) {
      for (const line of ruleLine.recipe) {
        if (commands.length >= MAX_MAKE_COMMANDS) {
          exhausted = true;
          return;
        }
        const state = { bad: false, fn: false };
        const command = expand(line, state).replace(/^[\s@+-]+/, '');
        if (state.bad) dynamic = true;
        commands.push(command);
        // `$(MAKE) …` or a command that starts with `make` (also through a variable: RUN = $(MAKE) x).
        if (/\$[({]MAKE[)}]/.test(line) || /^g?make(\s|$)/.test(command)) {
          // A sub-make reads the default makefile of its directory: -f is not passed down in MAKEFLAGS.
          if (options.makefile) dynamic = true;
          else followSubMake(command, depth, seen);
        }
      }
    }
  };
  // `$(MAKE) a b` runs the same file's targets again: follow plain forms; any
  // other form (-C, -f, VAR=x, a chained command) cannot be followed.
  const followSubMake = (command: string, depth: number, seen: Set<string>) => {
    const tokens = /[;&|<>()`$"'\\\n]/.test(command) ? null : words(command);
    if (!tokens || tokens.length === 0 || tokens[0] !== 'make') {
      dynamic = true;
      return;
    }
    const subTargets: string[] = [];
    for (const token of tokens.slice(1)) {
      if (MAKE_SIMPLE_FLAGS.has(token) || /^-j\d*$/.test(token)) continue;
      if (/^[A-Za-z0-9_][A-Za-z0-9_./+-]*$/.test(token)) subTargets.push(token);
      else {
        dynamic = true;
        return;
      }
    }
    if (depth + 1 > MAX_MAKE_DEPTH) {
      dynamic = true;
      return;
    }
    const wantedHere = subTargets.length > 0 ? subTargets : firstTarget ? [firstTarget] : [];
    if (wantedHere.length === 0) dynamic = true;
    for (const sub of wantedHere) {
      if (!rules.has(sub)) dynamic = true;
      // A fresh `seen`: a sub-make is a new run, though depth still bounds the recursion.
      visit(sub, depth + 1, new Set(seen));
    }
  };
  const wanted = targets.length > 0 ? targets : firstTarget ? [firstTarget] : [];
  for (const target of wanted) visit(target, 0, new Set());
  if (exhausted) return overBudget;
  // A command-line variable the Makefile never mentions can only act through the environment of the recipes.
  for (const [name, value] of commandLine) if (!referenced.has(name) && !(name === 'SHELL' && MAKE_SAFE_SHELL.test(value))) dynamic = true;
  return { status: 'ok', makefile: read.path, commands, dynamic: dynamic || wanted.some((t) => !rules.has(t)) };
}

export type ScriptFile =
  | {
      status: 'ok';
      path: string;
      interpreter: 'shell' | 'other';
      text: string;
      /**
       * Set when the shebang line itself carries a command (`#!/bin/bash -c "…"`,
       * `#!/usr/bin/env -S sh -c "…"`): that string is what runs, and the file
       * body is only `$0`. The interpreter is then 'other', so a caller that
       * scans the raw text still sees the shebang line.
       */
      shebangCommand?: string;
    }
  | { status: 'absent' }
  | { status: 'unknown'; reason: 'unreadable' | 'too_large' | 'not_file' | 'shebang' };

type Shebang = { kind: 'shell' } | { kind: 'other'; command?: string } | { kind: 'unknown' };

const SHELL_PROGRAMS = /^(?:sh|bash|zsh|dash|ksh|ash)$/;
/** Where a shebang's interpreter (or `env`) is trusted to be the program its name says; a copy elsewhere (a repo's `./bin/bash`) is unknown. */
const SYSTEM_BIN_DIRS = new Set(['/bin', '/usr/bin', '/usr/local/bin', '/sbin', '/usr/sbin', '/opt/homebrew/bin', '/opt/local/bin', '/usr/pkg/bin']);
const SHELL_FLAG_LETTERS = 'euxvfnCabhEBHPkT';
const SHELL_OPTION_NAMES = new Set(['pipefail', 'errexit', 'nounset', 'xtrace', 'noglob', 'noclobber', 'verbose', 'noexec', 'posix', 'allexport', 'errtrace', 'functrace']);
const SHELL_LONG_FLAGS = new Set(['--posix', '--noprofile', '--norc']);
const MAX_ENV_SPLIT_DEPTH = 4;
/**
 * The only shebang lines a definite `shell` answer is given for: at most this
 * many bytes (Linux before 5.1 cuts the line at 127; later kernels fail or cut at
 * 255) of printable ASCII and tab. Anything else (CR, VT, FF, NUL, DEL, other
 * control or non-ASCII characters) is split differently by the kernel, env -S and
 * this parser, so it is never `shell`.
 */
const MAX_SHEBANG_LINE = 127;
const PLAIN_SHEBANG_LINE = /^[\x20-\x7e\t]*$/;
/** A control character (anything below space except tab, DEL, NUL ...). */
const CONTROL_CHARACTER = /[\x00-\x08\x0a-\x1f\x7f]/;

/** Things this parse met that are harmless but not on the allowlist: the answer can be `other`, never `shell`. */
interface ShebangFlags {
  degraded: boolean;
}

/** A line that is not on the allowlist is never a definite shell; an answer that was already `other` or `unknown` is kept (never looser). */
function degrade(result: Shebang): Shebang {
  return result.kind === 'shell' ? { kind: 'other' } : result;
}

/** coreutils `env -S` split-string: quotes, backslash escapes, `#` comment. Null for anything else (`$` expansion, `\c`, unknown escapes, unclosed quote). */
function splitEnvString(value: string): string[] | null {
  const escapes: Record<string, string> = { n: '\n', t: '\t', r: '\r', f: '\f', v: '\v', '\\': '\\', '"': '"', "'": "'", '#': '#', $: '$' };
  const tokens: string[] = [];
  let word = '';
  let inWord = false;
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i];
    if (ch === '$') return null;
    if (quote === "'") {
      if (ch === "'") quote = null;
      else if (ch === '\\') {
        const next = value[i + 1];
        if (next !== '\\' && next !== "'") return null;
        word += next;
        i += 1;
      } else word += ch;
      continue;
    }
    if (quote === '"') {
      if (ch === '"') quote = null;
      else if (ch === '\\') {
        const next = value[i + 1];
        if (next === '_') word += ' ';
        else if (next !== undefined && Object.prototype.hasOwnProperty.call(escapes, next)) word += escapes[next];
        else return null;
        i += 1;
      } else word += ch;
      continue;
    }
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === '\f' || ch === '\v') {
      if (inWord) tokens.push(word);
      word = '';
      inWord = false;
      continue;
    }
    if (ch === '#' && !inWord) break;
    if (ch === "'" || ch === '"') {
      quote = ch;
      inWord = true;
      continue;
    }
    if (ch === '\\') {
      const next = value[i + 1];
      if (next === '_') {
        if (inWord) tokens.push(word);
        word = '';
        inWord = false;
      } else if (next !== undefined && Object.prototype.hasOwnProperty.call(escapes, next)) {
        word += escapes[next];
        inWord = true;
      } else return null;
      i += 1;
      continue;
    }
    word += ch;
    inWord = true;
  }
  if (quote) return null;
  if (inWord) tokens.push(word);
  return tokens;
}

/** The words after a shell interpreter: only plain option flags are understood; `-c <command>` is returned as a command. */
function classifyShellArguments(tokens: string[]): Shebang {
  let command = false;
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    if (token === '--') return i + 1 < tokens.length || command ? { kind: 'unknown' } : { kind: 'shell' };
    if (!/^[-+]./.test(token)) {
      // An operand: with -c it is the command string (the rest are $0, $1 ...); otherwise a script other than this file.
      return command ? { kind: 'other', command: token } : { kind: 'unknown' };
    }
    if (token.startsWith('--')) {
      if (!SHELL_LONG_FLAGS.has(token)) return { kind: 'unknown' };
      continue;
    }
    const letters = token.slice(1);
    for (let j = 0; j < letters.length; j += 1) {
      const letter = letters[j];
      if (letter === 'c') {
        command = true;
      } else if (letter === 'o') {
        // `-o name` (also `-euo pipefail`): the name is the next word.
        if (j !== letters.length - 1) return { kind: 'unknown' };
        const name = tokens[i + 1];
        if (name === undefined || !SHELL_OPTION_NAMES.has(name)) return { kind: 'unknown' };
        i += 1;
      } else if (!SHELL_FLAG_LETTERS.includes(letter)) return { kind: 'unknown' };
    }
  }
  return command ? { kind: 'unknown' } : { kind: 'shell' };
}

/**
 * What runs after `env`: options, then the program. Anything but plain
 * `-i`/`-u NAME`/`-S` and a program is unknown (NAME=value, -C, --argv0 ...).
 * `tokens` are argv words; `raw` (with each word's end offset) is the shebang
 * text itself, which `-S` consumes verbatim and splits with env's own quoting.
 */
function walkEnv(tokens: string[], ends: number[] | null, raw: string, depth: number, flags: ShebangFlags): Shebang {
  if (depth > MAX_ENV_SPLIT_DEPTH) return { kind: 'unknown' };
  const split = (attached: string, index: number): Shebang => {
    let value: string;
    let consumed = index;
    if (ends) value = attached + raw.slice(ends[index]);
    else if (attached !== '') value = attached;
    else {
      if (tokens[index + 1] === undefined) return { kind: 'unknown' };
      value = tokens[index + 1];
      consumed = index + 1;
    }
    const words = splitEnvString(value);
    if (!words || words.length === 0) return { kind: 'unknown' };
    // An escape (`\r`, `\t`, `\f` ...) can put a control character, tab included, into a word.
    if (words.some((word) => /[^\x20-\x7e]/.test(word))) flags.degraded = true;
    return walkEnv(ends ? words : [...words, ...tokens.slice(consumed + 1)], null, '', depth + 1, flags);
  };
  for (let i = 0; i < tokens.length; i += 1) {
    const word = tokens[i];
    if (word === '--') return classifyProgram(tokens.slice(i + 1), depth, flags);
    if (word === '-') continue;
    if (word.startsWith('--')) {
      if (word === '--ignore-environment') continue;
      // Harmless to env itself, but not on the allowlist: never a definite shell.
      if (word === '--null' || word === '--debug') {
        flags.degraded = true;
        continue;
      }
      if (word === '--unset') {
        if (tokens[i + 1] === undefined) return { kind: 'unknown' };
        i += 1;
        continue;
      }
      if (word.startsWith('--unset=')) continue;
      if (word === '--split-string') return split('', i);
      if (word.startsWith('--split-string=')) return split(word.slice('--split-string='.length), i);
      return { kind: 'unknown' };
    }
    if (word.startsWith('-')) {
      for (let j = 1; j < word.length; j += 1) {
        const letter = word[j];
        if (letter === 'i') continue;
        if (letter === '0' || letter === 'v') {
          flags.degraded = true;
          continue;
        }
        if (letter === 'u') {
          // The name is the rest of this word or the next one.
          if (j === word.length - 1) {
            if (tokens[i + 1] === undefined) return { kind: 'unknown' };
            i += 1;
          }
          break;
        }
        if (letter === 'S') return split(word.slice(j + 1), i);
        return { kind: 'unknown' };
      }
      continue;
    }
    // NAME=value (BASH_ENV, ENV, PATH, SHELLOPTS, PS4 ...): the interpreter's environment is not modelled.
    if (word.includes('=')) return { kind: 'unknown' };
    return classifyProgram(tokens.slice(i), depth, flags);
  }
  return { kind: 'unknown' };
}

function classifyEnvArguments(raw: string, flags: ShebangFlags): Shebang {
  const tokens: string[] = [];
  const ends: number[] = [];
  const re = /[^ \t]+/g;
  for (let match = re.exec(raw); match; match = re.exec(raw)) {
    tokens.push(match[0]);
    ends.push(match.index + match[0].length);
  }
  return walkEnv(tokens, ends, raw, 0, flags);
}

function classifyProgram(tokens: string[], depth: number, flags: ShebangFlags): Shebang {
  const program = tokens[0];
  if (program === undefined || program === '') return { kind: 'unknown' };
  const slash = program.lastIndexOf('/');
  const base = slash < 0 ? program : program.slice(slash + 1);
  if (base !== 'env' && !SHELL_PROGRAMS.test(base)) return { kind: 'other' };
  // A shell or env named by a relative path, or found outside the system bin
  // dirs, is a file the agent may have planted: its name proves nothing.
  if (slash >= 0 && !SYSTEM_BIN_DIRS.has(slash === 0 ? '/' : program.slice(0, slash))) return { kind: 'unknown' };
  if (base === 'env') return walkEnv(tokens.slice(1), null, '', depth + 1, flags);
  return classifyShellArguments(tokens.slice(1));
}

/**
 * `#!` line → what really runs. 'shell' only for a system shell with plain flags
 * on a plain line; every form that is not understood is 'unknown', and a line
 * that is understood but not plain (control or non-ASCII characters, too long,
 * an env option off the allowlist) is 'other', never 'shell'.
 */
function classifyShebang(line: string): Shebang {
  const body = line.trim();
  const space = body.search(/[ \t]/);
  const interpreter = space < 0 ? body : body.slice(0, space);
  const rest = space < 0 ? '' : body.slice(space).trim();
  if (!interpreter.startsWith('/')) return { kind: 'unknown' };
  const slash = interpreter.lastIndexOf('/');
  const dir = interpreter.slice(0, slash) || '/';
  const base = interpreter.slice(slash + 1);
  let result: Shebang;
  const flags: ShebangFlags = { degraded: false };
  if (base === 'env' || SHELL_PROGRAMS.test(base)) {
    if (!SYSTEM_BIN_DIRS.has(dir)) return { kind: 'unknown' };
    if (base === 'env') result = classifyEnvArguments(rest, flags);
    else result = classifyShellArguments(rest.split(/[ \t]+/).filter(Boolean));
  } else result = { kind: 'other' };
  // The kernel ends the line at \n only; \r and the other control characters stay in it.
  if (line.length + 2 > MAX_SHEBANG_LINE || !PLAIN_SHEBANG_LINE.test(line)) flags.degraded = true;
  return flags.degraded ? degrade(result) : result;
}

/**
 * A script file run as `./x.sh` or `bash x.sh` (≤64 KB), realpath-ed; the
 * interpreter comes from the shebang, which is the first line up to `\n` only.
 * With no shebang the kernel fails the exec and the invoking shell runs the file
 * as a sh script, unless its first line carries binary magic (control characters).
 */
export function readScriptFile(fs: SeatbeltFs, path: string): ScriptFile {
  const read = readResolved(fs, path, MAX_SCRIPT_BYTES);
  if (read.status !== 'ok') return read;
  const newline = read.text.indexOf('\n');
  const firstLine = newline < 0 ? read.text : read.text.slice(0, newline);
  let result: Shebang;
  if (read.text.startsWith('#!')) {
    const line = firstLine.slice(2);
    result = classifyShebang(line);
    // Never looser than the answer this parser gave when it cut the line at its first \r (round 3 and before).
    const cr = line.indexOf('\r');
    if (cr >= 0 && result.kind !== 'unknown' && classifyShebang(line.slice(0, cr)).kind === 'unknown') result = { kind: 'unknown' };
  } else result = CONTROL_CHARACTER.test(firstLine) ? { kind: 'other' } : { kind: 'shell' };
  if (result.kind === 'unknown') return { status: 'unknown', reason: 'shebang' };
  if (result.kind === 'shell') return { status: 'ok', path: read.path, interpreter: 'shell', text: read.text };
  return { status: 'ok', path: read.path, interpreter: 'other', text: read.text, ...(result.command !== undefined ? { shebangCommand: result.command } : {}) };
}
