import type { SeatbeltFs } from './seatbelt-fs';

// Seatbelt path resolution (spec §1.2 S4/S5, abuse rows A13/A19). Every
// answer that cannot be made exactly is 'dynamic' or 'unknown'; the category
// mapper treats those as the dangerous value (§2.1 rule 2).

export const MAX_SYMLINK_HOPS = 40;

export type RealPathResult =
  | { status: 'resolved'; path: string; exists: boolean }
  | { status: 'unknown'; reason: 'not_absolute' | 'loop' | 'unreadable' | 'proc_handle' };

function parts(value: string): string[] {
  return value.split('/').filter((part) => part !== '' && part !== '.');
}

// /proc/<pid>/root names the root directory; the other per-process handles
// (cwd, fd, exe ...) point at the hook process, not the agent's shell.
const PROC_HANDLE = new Set(['cwd', 'fd', 'fdinfo', 'exe', 'map_files', 'task', 'environ']);

/**
 * realpath of the longest existing prefix, with the remainder appended
 * lexically. followFinal=false leaves a final symlink unresolved (rm -r on a
 * link removes the link, not its target).
 */
export function realPath(fs: SeatbeltFs, input: string, options: { followFinal?: boolean } = {}): RealPathResult {
  if (!input.startsWith('/')) return { status: 'unknown', reason: 'not_absolute' };
  const follow = options.followFinal !== false;
  let pending = parts(input);
  let current: string[] = [];
  let exists = true;
  let hops = 0;
  while (pending.length > 0) {
    const name = pending.shift() as string;
    if (name === '..') {
      current.pop();
      continue;
    }
    if (current.length === 2 && current[0] === 'proc') {
      if (name === 'root') {
        current = [];
        exists = true;
        continue;
      }
      if (PROC_HANDLE.has(name)) return { status: 'unknown', reason: 'proc_handle' };
    }
    if (current.length === 1 && current[0] === 'dev' && name === 'fd') return { status: 'unknown', reason: 'proc_handle' };
    if (!exists) {
      current.push(name);
      continue;
    }
    const candidate = `/${[...current, name].join('/')}`;
    let entry;
    try {
      entry = fs.lstat(candidate);
    } catch {
      return { status: 'unknown', reason: 'unreadable' };
    }
    if (!entry) {
      exists = false;
      current.push(name);
      continue;
    }
    const final = pending.length === 0;
    if (entry.type === 'symlink' && (!final || follow)) {
      hops += 1;
      if (hops > MAX_SYMLINK_HOPS) return { status: 'unknown', reason: 'loop' };
      let target: string;
      try {
        target = fs.readlink(candidate);
      } catch {
        return { status: 'unknown', reason: 'unreadable' };
      }
      if (target.startsWith('/')) current = [];
      pending = [...parts(target), ...pending];
      continue;
    }
    if (entry.type !== 'dir' && !final) exists = false;
    current.push(name);
  }
  return { status: 'resolved', path: `/${current.join('/')}`, exists };
}

/** Comparison key: case-folded (and NFC-normalised) on case-insensitive volumes. */
export function pathKey(fs: SeatbeltFs, value: string): string {
  return fs.caseInsensitive(value) ? value.normalize('NFC').toLowerCase() : value;
}

/** True when child is root itself or below it. */
export function isWithinOrEqual(fs: SeatbeltFs, root: string, child: string): boolean {
  const r = pathKey(fs, root);
  const c = pathKey(fs, child);
  if (r === '/') return c.startsWith('/');
  return c === r || c.startsWith(`${r}/`);
}

/**
 * Folded comparison used for the danger checks (root, home, a workspace root
 * or its ancestor). It folds on every volume, so an unproven case-sensitivity
 * can only make a target look more dangerous, never less.
 */
function dangerWithinOrEqual(root: string, child: string): boolean {
  const fold = (v: string) => v.normalize('NFC').toLowerCase();
  const r = fold(root);
  const c = fold(child);
  if (r === '/') return c.startsWith('/');
  return c === r || c.startsWith(`${r}/`);
}

function isStrictlyWithin(fs: SeatbeltFs, root: string, child: string): boolean {
  return isWithinOrEqual(fs, root, child) && pathKey(fs, root) !== pathKey(fs, child);
}

export interface PathContext {
  /** Trusted home: passwd or the hook's --home value, never $HOME from the agent's environment. */
  home: string | null;
  /** The event's cwd (absolute), or null when the harness gave none. */
  cwd: string | null;
  /**
   * Shell variables whose value is known when this command's words are
   * expanded: set by an earlier, unconditional statement (`DIR=x; rm -rf
   * "$DIR"`, `DIR=x && rm -rf "$DIR"`). Bash semantics: a prefix assignment
   * (`DIR=x rm -rf "$DIR"`) only goes to the command's environment and is NOT
   * seen by its own argument expansion, which uses the shell's prior value.
   * Never put prefix assignments here; a name not listed is unknown.
   */
  variables?: Record<string, string>;
  /**
   * The command's own prefix assignments. Accepted only so a caller can pass
   * them without them leaking into expansion: they are never substituted, and
   * a name assigned here and not in `variables` stays unknown.
   */
  prefixAssignments?: Record<string, string>;
  /**
   * The $HOME the agent's shell expands for `~` and `$HOME`. When given and
   * not exactly `home`, both expansions are unknown. (U4 gives
   * `claimed_no_key` whenever env HOME is not the trusted home.)
   */
  shellHome?: string | null;
  /** passwd lookup for ~user. */
  userHome?: (user: string) => string | null;
}

export type ExpandedOperand =
  | { kind: 'path'; path: string; trailingFollow: boolean; nonAscii: boolean }
  | { kind: 'glob'; path: string; staticPrefix: string; trailingFollow: boolean; nonAscii: boolean }
  | { kind: 'dynamic'; reason: 'empty' | 'substitution' | 'brace' | 'variable' | 'tilde' | 'user_home' | 'no_home' | 'no_cwd' | 'glob_parent' | 'backslash' | 'pattern' };

const VARIABLE = /\$(?:\{([^}]*)\}|([A-Za-z_][A-Za-z0-9_]*)|([0-9@*#?$!-]))/g;

/**
 * Expands one path operand the way the shell would, using only trusted values.
 * `raw` is the word with quotes removed; any `$` left in it is treated as an
 * expansion, so a literal `$` can only make the answer stricter.
 */
export function expandPathOperand(raw: string, context: PathContext): ExpandedOperand {
  let value = String(raw ?? '');
  if (value === '') return { kind: 'dynamic', reason: 'empty' };
  // A `\` left after quote removal is a literal name character on POSIX and a
  // separator on Windows: either reading can move the target, so it is unknown.
  if (value.includes('\\')) return { kind: 'dynamic', reason: 'backslash' };
  // The shell's $HOME, when known to differ from the trusted home, makes ~ and $HOME unknown.
  // So does an earlier statement that set HOME (or PWD) in the shell.
  const setEarlier = (name: string) => context.variables !== undefined && Object.prototype.hasOwnProperty.call(context.variables, name);
  const homeForShell = (context.shellHome !== undefined && context.shellHome !== context.home) || (setEarlier('HOME') && context.variables?.HOME !== context.home) ? null : context.home;
  const cwdForShell = setEarlier('PWD') && context.variables?.PWD !== context.cwd ? null : context.cwd;
  // Judged on the operand and substituted values only: a non-ASCII home or cwd is not the agent's choice.
  let nonAscii = /[^\x20-\x7e]/.test(value);
  if (/\$\(|`|<\(|>\(/.test(value)) return { kind: 'dynamic', reason: 'substitution' };
  if (value.includes('}') && /\{[^{}]*(?:,|\.\.)/.test(value)) return { kind: 'dynamic', reason: 'brace' };
  // Patterns this resolver does not enumerate: bash globstar/extglob and zsh's
  // default `**`, `(a|b)`, `<1-9>` and qualifiers, plus extendedglob `^`/`#`.
  if (/\*\*|[()|<>^#]/.test(value)) return { kind: 'dynamic', reason: 'pattern' };
  if (value.startsWith('~')) {
    const slash = value.indexOf('/');
    const prefix = slash < 0 ? value.slice(1) : value.slice(1, slash);
    const rest = slash < 0 ? '' : value.slice(slash);
    let base: string | null;
    if (prefix === '') {
      if (!homeForShell) return { kind: 'dynamic', reason: 'no_home' };
      base = homeForShell;
    } else if (prefix === '+') {
      // `~+` is the shell's $PWD, which an earlier `PWD=…` statement may have changed.
      if (!cwdForShell) return { kind: 'dynamic', reason: 'no_cwd' };
      base = cwdForShell;
    } else if (/^[0-9]+$/.test(prefix)) {
      // `~N` is the Nth entry of the directory stack, which this resolver does not track (`~-` and `~+N`/`~-N` fall to the branch below).
      return { kind: 'dynamic', reason: 'tilde' };
    } else if (/^[A-Za-z0-9._][A-Za-z0-9._-]*$/.test(prefix)) {
      base = context.userHome ? context.userHome(prefix) : null;
      if (!base) return { kind: 'dynamic', reason: 'user_home' };
    } else {
      return { kind: 'dynamic', reason: 'tilde' };
    }
    value = `${base}${rest}`;
  }
  let unresolved: ExpandedOperand | null = null;
  value = value.replace(VARIABLE, (_match, braced: string | undefined, plain: string | undefined) => {
    const name = braced ?? plain;
    if (name === undefined || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
      unresolved = { kind: 'dynamic', reason: 'variable' };
      return '';
    }
    if (name === 'HOME') {
      if (!homeForShell) unresolved = { kind: 'dynamic', reason: 'no_home' };
      return homeForShell || '';
    }
    if (name === 'PWD') {
      if (!cwdForShell) unresolved = { kind: 'dynamic', reason: 'no_cwd' };
      return cwdForShell || '';
    }
    // Only values set before this command count; prefixAssignments never do.
    const assigned = context.variables && Object.prototype.hasOwnProperty.call(context.variables, name)
      ? context.variables[name]
      : undefined;
    if (assigned === undefined) unresolved = { kind: 'dynamic', reason: 'variable' };
    // The shell tilde-expands an assignment's value when it is assigned: a value that still
    // starts with `~` was not expanded by the caller, and bash never expands it later.
    else if (assigned.startsWith('~')) unresolved = { kind: 'dynamic', reason: 'tilde' };
    else if (/[^\x20-\x7e]/.test(assigned)) nonAscii = true;
    return assigned ?? '';
  });
  if (unresolved) return unresolved;
  // Any `$` left ($'..', $"..", a lone $) is an expansion this resolver does not model.
  if (value.includes('$')) return { kind: 'dynamic', reason: 'variable' };
  if (value === '') return { kind: 'dynamic', reason: 'empty' };
  if (!value.startsWith('/')) {
    if (!context.cwd || !context.cwd.startsWith('/')) return { kind: 'dynamic', reason: 'no_cwd' };
    value = `${context.cwd}/${value}`;
  }
  const trailingFollow = /\/\.?$/.test(value);
  const normalized = `/${parts(value).join('/')}`;
  if (/[*?[]/.test(normalized)) {
    const segments = parts(normalized);
    const firstGlob = segments.findIndex((part) => /[*?[]/.test(part));
    // `..` after a wildcard climbs out of whatever the wildcard matched.
    if (segments.slice(firstGlob).includes('..')) return { kind: 'dynamic', reason: 'glob_parent' };
    return { kind: 'glob', path: normalized, staticPrefix: `/${segments.slice(0, firstGlob).join('/')}`, trailingFollow, nonAscii };
  }
  return { kind: 'path', path: normalized, trailingFollow, nonAscii };
}

export type ResolvedOperand =
  | { kind: 'path'; real: string; exists: boolean; nonAscii: boolean }
  /**
   * matches: the real path of every name the glob can reach (followed through
   * links where the shell follows them). parents: the real dirs whose
   * children a final wildcard deletes, judged like a static prefix.
   */
  | { kind: 'glob'; staticReal: string; matches: string[]; parents: string[]; nonAscii: boolean }
  | { kind: 'unknown'; reason: string };

/**
 * Whether a name can match one glob segment. `*` and `?` as in the shell; a
 * bracket expression counts as any one character, and a leading dot is not
 * special, so the answer is a superset of the shell's. Dynamic programming,
 * linear in pattern × name: no backtracking blow-up.
 */
function segmentMayMatch(pattern: string, name: string): boolean {
  const tokens: string[] = [];
  for (let i = 0; i < pattern.length; i += 1) {
    const ch = pattern[i];
    if (ch === '[') {
      // A bracket expression: an optional `!`/`^`, a leading `]` is a member, and
      // `[:class:]`, `[.x.]`, `[=x=]` hold a `]` of their own.
      let j = i + 1;
      if (pattern[j] === '!' || pattern[j] === '^') j += 1;
      if (pattern[j] === ']') j += 1;
      let close = -1;
      while (j < pattern.length) {
        if (pattern[j] === '[' && (pattern[j + 1] === ':' || pattern[j + 1] === '.' || pattern[j + 1] === '=')) {
          const end = pattern.indexOf(`${pattern[j + 1]}]`, j + 2);
          if (end < 0) break;
          j = end + 2;
          continue;
        }
        if (pattern[j] === ']') {
          close = j;
          break;
        }
        j += 1;
      }
      if (close < 0) tokens.push('[');
      else {
        tokens.push('?');
        i = close;
      }
    } else if (ch === '*') {
      if (tokens[tokens.length - 1] !== '*') tokens.push('*');
    } else tokens.push(ch === '?' ? '?' : `=${ch}`);
  }
  let row = new Array<boolean>(name.length + 1).fill(false);
  row[0] = true;
  for (const token of tokens) {
    const next = new Array<boolean>(name.length + 1).fill(false);
    if (token === '*') {
      let any = false;
      for (let j = 0; j <= name.length; j += 1) {
        any = any || row[j];
        next[j] = any;
      }
    } else {
      for (let j = 1; j <= name.length; j += 1) {
        const ch = name[j - 1];
        next[j] = row[j - 1] && (token === '?' || (token === '[' ? ch === '[' : ch === token.slice(1)));
      }
    }
    row = next;
  }
  return row[name.length];
}

/** Bound on directory entries a glob may enumerate; over it the operand is unknown. */
export const MAX_GLOB_ENTRIES = 1024;

/**
 * The real target of every path a glob can name, as far as the filesystem
 * shows it. Each wildcard segment is matched against every entry of the
 * directory (a superset of what the shell matches, dotfiles included, so it
 * can only add targets). A name the shell resolves through a link (a further
 * segment, a trailing `/` or `/.`, or use='read') is realpath-ed; a final name
 * without one is the link itself. Null when it cannot be enumerated for certain.
 */
function globTargets(fs: SeatbeltFs, path: string, trailingFollow: boolean, use: 'read' | 'delete'): { matches: string[]; parents: string[] } | null {
  const segments = parts(path);
  let current: string[] = ['/'];
  let budget = MAX_GLOB_ENTRIES;
  const out: string[] = [];
  const parents: string[] = [];
  for (let i = 0; i < segments.length; i += 1) {
    const segment = segments[i];
    const final = i === segments.length - 1;
    const next: string[] = [];
    for (const dir of current) {
      let names: string[];
      if (/[*?[]/.test(segment)) {
        const real = realPath(fs, dir, { followFinal: true });
        if (real.status !== 'resolved') return null;
        if (!real.exists) continue;
        let entry;
        try {
          entry = fs.lstat(real.path);
        } catch {
          return null;
        }
        if (!entry || entry.type !== 'dir') continue;
        if (final) parents.push(real.path);
        try {
          names = fs.readdir(real.path);
        } catch {
          return null;
        }
        budget -= names.length;
        if (budget < 0) return null;
        names = names.filter((name) => segmentMayMatch(segment, name));
        // bash before 5.2 lets a pattern with a leading `.` match `.` and `..`.
        if (segment.startsWith('.')) for (const dot of ['.', '..']) if (segmentMayMatch(segment, dot)) names.push(dot);
      } else names = [segment];
      for (const name of names) next.push(dir === '/' ? `/${name}` : `${dir}/${name}`);
    }
    current = next;
    if (final) {
      for (const candidate of current) {
        const real = realPath(fs, candidate, { followFinal: use === 'read' || trailingFollow });
        if (real.status !== 'resolved') return null;
        out.push(real.path);
      }
    }
  }
  return { matches: out, parents };
}

/**
 * Expands and realpaths one operand. use='read' follows a final symlink (cat
 * reads the target); use='delete' follows it only after a trailing '/' or '/.'.
 */
export function resolveOperand(fs: SeatbeltFs, context: PathContext, raw: string, use: 'read' | 'delete'): ResolvedOperand {
  const expanded = expandPathOperand(raw, context);
  if (expanded.kind === 'dynamic') return { kind: 'unknown', reason: expanded.reason };
  if (expanded.kind === 'glob') {
    const real = realPath(fs, expanded.staticPrefix, { followFinal: true });
    if (real.status !== 'resolved') return { kind: 'unknown', reason: real.reason };
    const targets = globTargets(fs, expanded.path, expanded.trailingFollow, use);
    if (targets === null) return { kind: 'unknown', reason: 'glob_unresolved' };
    return { kind: 'glob', staticReal: real.path, matches: targets.matches, parents: targets.parents, nonAscii: expanded.nonAscii };
  }
  const real = realPath(fs, expanded.path, { followFinal: use === 'read' || expanded.trailingFollow });
  if (real.status !== 'resolved') return { kind: 'unknown', reason: real.reason };
  return { kind: 'path', real: real.path, exists: real.exists, nonAscii: expanded.nonAscii };
}

export interface Workspace {
  /** False when the event gave no usable cwd: every recursive delete target is then unknown (A19). */
  known: boolean;
  /** Real project roots (git toplevel of the event cwd, or the cwd). Children only. */
  roots: string[];
  /** Real temp roots (/tmp, /var/tmp, a system TMPDIR). Children only. */
  tempRoots: string[];
  home: string | null;
  reason?: 'no_cwd' | 'cwd_unresolved' | 'home_or_ancestor';
}

// TMPDIR comes from the environment, which may not widen the workspace
// (§2.1 rule 5): it is used only when its real path is under a system temp dir.
const SYSTEM_TEMP = ['/tmp', '/var/tmp', '/private/tmp', '/private/var/tmp', '/private/var/folders', '/var/folders'];

function realOrNull(fs: SeatbeltFs, value: string): string | null {
  const real = realPath(fs, value, { followFinal: true });
  return real.status === 'resolved' && real.exists ? real.path : null;
}

function gitToplevel(fs: SeatbeltFs, start: string): string | null {
  let dir = start;
  for (;;) {
    let entry;
    try {
      entry = fs.lstat(dir === '/' ? '/.git' : `${dir}/.git`);
    } catch {
      entry = null;
    }
    if (entry && (entry.type === 'dir' || entry.type === 'file')) return dir;
    if (dir === '/') return null;
    dir = dir.slice(0, dir.lastIndexOf('/')) || '/';
  }
}

/** WS from the event cwd (fixes F3: never the hook process's cwd). */
export function resolveWorkspace(fs: SeatbeltFs, input: { eventCwd: unknown; home: string | null; tmpdir?: string | null }): Workspace {
  const realHome = input.home ? realOrNull(fs, input.home) || input.home : null;
  const tempRoots: string[] = [];
  for (const candidate of ['/tmp', '/var/tmp', input.tmpdir || '']) {
    if (!candidate || !candidate.startsWith('/')) continue;
    const real = realOrNull(fs, candidate);
    if (!real || !SYSTEM_TEMP.some((root) => isWithinOrEqual(fs, root, real))) continue;
    if (realHome && dangerWithinOrEqual(real, realHome)) continue;
    if (!tempRoots.some((root) => pathKey(fs, root) === pathKey(fs, real))) tempRoots.push(real);
  }
  const base = { tempRoots, home: realHome };
  if (typeof input.eventCwd !== 'string' || !input.eventCwd.startsWith('/')) return { known: false, roots: [], ...base, reason: 'no_cwd' };
  const cwd = realPath(fs, input.eventCwd, { followFinal: true });
  if (cwd.status !== 'resolved' || !cwd.exists) return { known: false, roots: [], ...base, reason: 'cwd_unresolved' };
  const dangerous = (dir: string) => dir === '/' || (realHome !== null && dangerWithinOrEqual(dir, realHome));
  const top = gitToplevel(fs, cwd.path);
  // A repo at $HOME (dotfiles) or a project dir that is really $HOME never makes home the workspace.
  const root = top && !dangerous(top) ? top : cwd.path;
  if (dangerous(root)) return { known: true, roots: [], ...base, reason: 'home_or_ancestor' };
  return { known: true, roots: [root], ...base };
}

export type DeleteTargetClass = 'in_workspace' | 'outside_workspace' | 'workspace_root' | 'home' | 'root' | 'unknown';

const DELETE_CLASS_ORDER: DeleteTargetClass[] = ['unknown', 'root', 'home', 'workspace_root', 'outside_workspace', 'in_workspace'];

/** Where a recursive-delete target falls (S5). Only 'in_workspace' is safe. A glob is the worst of its static prefix and every reachable match. */
export function classifyDeleteTarget(fs: SeatbeltFs, workspace: Workspace, target: ResolvedOperand): DeleteTargetClass {
  if (!workspace.known || target.kind === 'unknown' || target.nonAscii) return 'unknown';
  if (target.kind === 'glob') {
    const classes = [classifyReal(fs, workspace, target.staticReal, true)];
    for (const parent of target.parents) classes.push(classifyReal(fs, workspace, parent, true));
    for (const match of target.matches) classes.push(classifyReal(fs, workspace, match, false));
    return DELETE_CLASS_ORDER.find((c) => classes.includes(c)) as DeleteTargetClass;
  }
  return classifyReal(fs, workspace, target.real, false);
}

function classifyReal(fs: SeatbeltFs, workspace: Workspace, real: string, children: boolean): DeleteTargetClass {
  if (real === '/') return 'root';
  const home = workspace.home;
  if (home && dangerWithinOrEqual(real, home)) return 'home';
  for (const root of [...workspace.roots, ...workspace.tempRoots]) {
    if (dangerWithinOrEqual(real, root)) return 'workspace_root';
  }
  // A glob deletes children of its static prefix; a path deletes itself.
  const inside = (root: string) => (children ? isWithinOrEqual(fs, root, real) : isStrictlyWithin(fs, root, real));
  if (workspace.roots.some(inside)) return 'in_workspace';
  // Temp roots never cover anything inside home (a home under /tmp stays protected).
  if (workspace.tempRoots.some(inside) && !(home && dangerWithinOrEqual(home, real))) return 'in_workspace';
  return 'outside_workspace';
}
