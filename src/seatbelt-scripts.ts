import type { SeatbeltFs } from './seatbelt-fs';
import { realPath } from './seatbelt-path';

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
// costs one entry per name, not names × prerequisites.
interface MakeRuleLine {
  prerequisites: string[];
  recipe: string[];
}

interface MakeRule {
  lines: MakeRuleLine[];
}

const MAKEFILE_NAMES = ['GNUmakefile', 'makefile', 'Makefile'];

/**
 * A simple Makefile recipe parse: explicit rules, recipe lines, prerequisites
 * (depth ≤3) and `$(VAR)`/`${VAR}` from simple assignments or the command
 * line. `include`, conditionals, pattern rules or an unknown variable make
 * the answer dynamic, which the mapper treats like an unknown script.
 */
export function resolveMakeTargets(fs: SeatbeltFs, dir: string, targets: string[], options: { makefile?: string; overrides?: Record<string, string> } = {}): MakeResolution {
  let read: Read = { status: 'absent' };
  if (options.makefile) read = readResolved(fs, options.makefile.startsWith('/') ? options.makefile : `${dir}/${options.makefile}`, MAX_MANIFEST_BYTES);
  else {
    for (const name of MAKEFILE_NAMES) {
      read = readResolved(fs, `${dir}/${name}`, MAX_MANIFEST_BYTES);
      if (read.status !== 'absent') break;
    }
  }
  if (read.status !== 'ok') return read.status === 'absent' ? read : { status: 'unknown', reason: read.reason };
  const variables: Record<string, string> = {};
  const rules = new Map<string, MakeRule>();
  let firstTarget: string | null = null;
  let dynamic = false;
  let current: MakeRuleLine | null = null;
  let prerequisiteCount = 0;
  let recipeCount = 0;
  const overBudget: MakeResolution = { status: 'unknown', reason: 'too_complex' };
  const lines = read.text.replace(/\\\r?\n/g, ' ').split(/\r?\n/);
  for (const line of lines) {
    if (line.startsWith('\t')) {
      if (current) {
        recipeCount += 1;
        if (recipeCount > MAX_MAKE_RECIPE_LINES) return overBudget;
        current.recipe.push(line.slice(1));
      }
      continue;
    }
    const trimmed = line.replace(/#.*$/, '').trim();
    if (!trimmed) continue;
    if (/^(-?include|sinclude|ifeq|ifneq|ifdef|ifndef|else|endif|define|endef|export|vpath)\b/.test(trimmed)) {
      dynamic = true;
      current = null;
      continue;
    }
    const assign = /^(?:override\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*(\?=|:::=|::=|:=|\+=|!=|=)\s*(.*)$/.exec(trimmed);
    if (assign) {
      const [, name, op, value] = assign;
      if (op === '!=') dynamic = true;
      else if (op === '+=') variables[name] = `${variables[name] ?? ''} ${value}`.trim();
      else if (op !== '?=' || variables[name] === undefined) variables[name] = value;
      if (variables[name] !== undefined && variables[name].length > MAX_MAKE_EXPANDED_BYTES) return overBudget;
      current = null;
      continue;
    }
    const rule = /^([^:=]+)::?([^=]*)$/.exec(trimmed);
    if (!rule) {
      dynamic = true;
      current = null;
      continue;
    }
    const names = rule[1].trim().split(/\s+/).filter(Boolean);
    let prereqs = rule[2].trim();
    let inlineRecipe: string | null = null;
    const semi = prereqs.indexOf(';');
    if (semi >= 0) {
      inlineRecipe = prereqs.slice(semi + 1).trim();
      prereqs = prereqs.slice(0, semi);
    }
    if (names.length > MAX_MAKE_TARGETS_PER_RULE) return overBudget;
    const ruleLine: MakeRuleLine = { prerequisites: prereqs.split(/\s+/).filter((p) => p && p !== '|'), recipe: inlineRecipe ? [inlineRecipe] : [] };
    prerequisiteCount += ruleLine.prerequisites.length;
    if (prerequisiteCount > MAX_MAKE_PREREQUISITES) return overBudget;
    current = ruleLine;
    for (const name of names) {
      if (name.includes('%')) dynamic = true;
      if (name.startsWith('.')) continue;
      if (firstTarget === null && !name.includes('%')) firstTarget = name;
      let entry = rules.get(name);
      if (!entry) {
        if (rules.size >= MAX_MAKE_RULES) return overBudget;
        entry = { lines: [] };
        rules.set(name, entry);
      }
      if (entry.lines[entry.lines.length - 1] !== ruleLine) entry.lines.push(ruleLine);
    }
  }
  const values = { ...variables, ...(options.overrides || {}) };
  // Every expansion is charged to one budget, so nested variables cannot blow up.
  let expandedBytes = 0;
  let exhausted = false;
  const expand = (text: string, depth = 0): string => {
    expandedBytes += text.length;
    if (expandedBytes > MAX_MAKE_EXPANDED_BYTES) {
      exhausted = true;
      return '';
    }
    return expandOnce(text, depth);
  };
  const expandOnce = (text: string, depth: number): string => text.replace(/\$(?:\(([^()]*)\)|\{([^{}]*)\}|([A-Za-z@<^*?%$]))/g, (match, a, b, c) => {
    const name = (a ?? b ?? c) as string;
    if (name === '$') return '$';
    if (/^[@<^*?%]$/.test(name) || /\s/.test(name) || depth > 8 || values[name] === undefined) {
      if (!/^[@<^*?%]$/.test(name)) dynamic = true;
      return match;
    }
    return expand(values[name], depth + 1);
  });
  const commands: string[] = [];
  const visit = (target: string, depth: number, seen: Set<string>) => {
    if (exhausted || seen.has(target)) return;
    seen.add(target);
    const rule = rules.get(target);
    if (!rule) return;
    for (const ruleLine of rule.lines) {
      if (depth < MAX_MAKE_DEPTH) for (const prerequisite of ruleLine.prerequisites) visit(expand(prerequisite), depth + 1, seen);
      else if (ruleLine.prerequisites.length > 0) dynamic = true;
    }
    for (const ruleLine of rule.lines) {
      for (const line of ruleLine.recipe) {
        if (commands.length >= MAX_MAKE_COMMANDS) {
          exhausted = true;
          return;
        }
        commands.push(expand(line).replace(/^[\s@+-]+/, ''));
      }
    }
  };
  const wanted = targets.length > 0 ? targets : firstTarget ? [firstTarget] : [];
  for (const target of wanted) visit(target, 0, new Set());
  if (exhausted) return overBudget;
  return { status: 'ok', makefile: read.path, commands, dynamic: dynamic || wanted.some((t) => !rules.has(t)) };
}

export type ScriptFile =
  | { status: 'ok'; path: string; interpreter: 'shell' | 'other'; text: string }
  | { status: 'absent' }
  | { status: 'unknown'; reason: 'unreadable' | 'too_large' | 'not_file' };

/** A script file run as `./x.sh` or `bash x.sh` (≤64 KB), realpath-ed; the interpreter comes from the shebang. */
export function readScriptFile(fs: SeatbeltFs, path: string): ScriptFile {
  const read = readResolved(fs, path, MAX_SCRIPT_BYTES);
  if (read.status !== 'ok') return read;
  const shebang = /^#![ \t]*([^\r\n]*)/.exec(read.text);
  const words = shebang ? shebang[1].split(/[ \t]+/).filter(Boolean) : ['sh'];
  let program = (words[0] || '').split('/').pop() || '';
  if (program === 'env') {
    // env's own options and NAME=value words come before the program (`env -S bash -e`, `env -i -u X bash`).
    let i = 1;
    while (i < words.length) {
      const word = words[i];
      if (/^-[^-]*S./.test(word)) {
        // `-Sbash`: the split string starts inside the option word.
        words.splice(i + 1, 0, word.slice(word.indexOf('S') + 1));
        i += 1;
      } else if (word === '-u' || word === '--unset' || word === '-C' || word === '--chdir') i += 2;
      else if (word.startsWith('-') || /^[A-Za-z_][A-Za-z0-9_]*=/.test(word)) i += 1;
      else break;
    }
    program = (words[i] || '').split('/').pop() || '';
  }
  const interpreter = /^(sh|bash|zsh|dash|ksh|ash)$/.test(program) ? 'shell' : 'other';
  return { status: 'ok', path: read.path, interpreter, text: read.text };
}
