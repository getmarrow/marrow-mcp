// Seatbelt category mapper (U2): S0–S5 and S-x hard stops for keyless installs, plus the lexical
// tripwire. Spec: SEATBELT-SPEC.md §1.2 and §2 as amended by the owner decisions of 2026-10-12
// (Q1 non-force push to a protected branch passes with a receipt flag; Q2 no docker push; Q3 project
// .env* reads stop, templates excepted; Q4 curl|sh passes with a receipt flag, decoded exec stops).
//
// Pure: no I/O except the injected fs and git-config reader. Not wired into any hook yet (U5).
//
// It works on argv from the vendored classifier's shell parser (vendor/classifier/shell-parse.js).
// It never takes the classifier's "routine" class as a pass: the classifier allows env dumps and
// deletes under home by design (U0 misses), so every S rule is decided from argv here.

import * as path from 'node:path';
import {
  ARGV_KEYS, CODE_KEYS, COMMAND_KEYS, ENV_TEMPLATE_SUFFIX, EVAL_PRODUCERS, FILE_TOOL_NAMES, GIT_BUILTINS, GIT_CONFIG_ENV_FILES,
  GIT_CONFIG_INCLUDE, GIT_EXEC_CONFIG, GIT_PUSH_LONG, GIT_PUSH_RISKY_LONG, GIT_S4_EXEMPT_SUBS, INERT_PROGRAMS, INTERPRETERS,
  INTERPRETER_DECODE, INTERPRETER_EXEC, INTERPRETER_TREE_DELETE, KEY_EXTENSIONS, KEY_FIXTURE_SEGMENTS, KNOWN_COMMANDS, LIMITS,
  MARROW_OWNER_SUBS, NAME_TRIPWIRE, NON_SCRIPT_NAMES, NPM_ALIASES, NPM_BOOL_FLAGS, NPM_COMMANDS, NPM_VALUE_FLAGS, PACKAGE_BINS,
  PROD_ENV, S4_EXEMPT_PROGRAMS, SCRIPT_SUFFIX, SECRET_PATTERNS, SECRET_VAR, SEATBELT_RULES_VERSION, SHELL_TOOL_NAMES, SHELLS,
  SSH_PUBLIC, TRIPWIRE, secretSamples,
} from './tables';
import { CLASSIFIER_PIN } from './classifier-pin';

/* eslint-disable @typescript-eslint/no-require-imports */
const shellParse: { parseShell: (src: string, opts?: { depth?: number }) => ParsedShell } = require('../../vendor/classifier/shell-parse.js');
const baseline: { BASELINE_POLICY: { protected_paths: string[]; protected_branches: string[] } } = require('../../vendor/classifier/policy-baseline.js');
const classifierModule: { globToRegex: (pattern: string, home: string) => RegExp } = require('../../vendor/classifier/classifier.js');

interface Slot { type: string; name?: string }
interface Word { text: string; dynamic: boolean; quoted: boolean; substitution: boolean; variables: string[]; slots: Slot[]; glob?: boolean }
interface Redirect { op: string; fd: string | null; target: Word | null }
interface ShellCommand {
  words: Word[]; assignments: Word[]; redirects: Redirect[]; heredoc: string | null; heredocDynamic: boolean;
  pipedInput: boolean; pipesOutput: boolean; background: boolean; subshell: boolean;
  forLoop?: { name: string; items: Word[] | null };
}
interface ParsedShell { ok: boolean; commands: ShellCommand[]; substitutions: string[]; reasons: string[]; dynamic: boolean; error: string | null }

export type SeatbeltCategory = 'none' | 'S0' | 'S1' | 'S2' | 'S3' | 'S4' | 'S5' | 'Sx';
export type SeatbeltParse = 'ok' | 'dynamic' | 'unparsed' | 'too_large';

export interface SeatbeltFs {
  /** File content as text, or null when missing, unreadable, not a regular file or larger than maxBytes. */
  readFile(absPath: string, maxBytes: number): string | null;
  /** realpath(3) of an existing path, or null when it does not exist. */
  realpath(absPath: string): string | null;
  /**
   * Entry names of a directory (no `.` or `..`), or null when it is missing or unreadable. Optional:
   * without it a glob that could reach a symlink cannot be expanded and stops (audit F9).
   */
  readdir?(absPath: string): string[] | null;
}
export interface SeatbeltGit {
  /** Work-tree top level for cwd, or null when cwd is not in a repository. */
  toplevel(cwd: string): string | null;
  /** All values of a config key in git order (system, global, includes, repo); key in git's canonical case. */
  getAll(cwd: string, key: string): string[];
  /** Current branch name, or null when detached or unknown. */
  currentBranch(cwd: string): string | null;
  /** Branch that refs/remotes/<remote>/HEAD points at, or null. */
  remoteHead(cwd: string, remote: string): string | null;
}
export interface SeatbeltEnv {
  /** Event cwd from the harness. Missing or relative means the workspace is unknown. */
  cwd: string | null | undefined;
  /** Home from passwd or the hook's baked --home, never $HOME from the agent env. */
  home: string;
  tmpdir?: string;
  platform?: string;
  fs: SeatbeltFs;
  git: SeatbeltGit;
  /** The classifier's class for the same action. Recorded only; it never decides an S category. */
  classifierClass?: string;
  /** Wall-clock budget for one classification in ms (default LIMITS.timeBudgetMs). Over it: stop. */
  budgetMs?: number;
}
export interface SeatbeltHit { category: Exclude<SeatbeltCategory, 'none'>; reason: string }
export interface SeatbeltDecision {
  decision: 'pass' | 'stop';
  category: SeatbeltCategory;
  rule: string;
  reasons: string[];
  hits: SeatbeltHit[];
  flags: string[];
  parse: SeatbeltParse;
  engine: { rules: string; classifier_contract: string; classifier_source_commit: string };
}
export interface SeatbeltEvent { tool_name: string; tool_input?: unknown }

const CATEGORY_ORDER: Array<Exclude<SeatbeltCategory, 'none'>> = ['S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'Sx'];
const RULE_IDS: Record<SeatbeltCategory, string> = {
  none: 'none', S0: 'S0.self_protection', S1: 'S1.protected_branch_force', S2: 'S2.production_deploy', S3: 'S3.package_publish',
  S4: 'S4.credential_access', S5: 'S5.recursive_delete_outside_ws', Sx: 'Sx.obfuscated_exec',
};
const PARSE_RANK: Record<SeatbeltParse, number> = { ok: 0, dynamic: 1, unparsed: 2, too_large: 3 };
const DYN = '\u0001';
const OUTPUT_REDIRECTS = new Set(['>', '>>', '>|', '&>', '&>>', '<>']);
const SAFE_DEVICES = /^\/dev\/(?:null|zero|stdout|stderr|tty|u?random|fd\/\d+)$/;

interface Run {
  env: SeatbeltEnv;
  home: string;
  fold: boolean;
  hits: SeatbeltHit[];
  flags: Set<string>;
  parse: SeatbeltParse;
  wsRoots: string[];
  tmpRoots: string[];
  isProtected: (abs: string) => boolean;
  protectedAnchors: string[];
  secretRegexes: RegExp[];
  branchRegexes: RegExp[];
  topSource: string;
  // Budgets (audit F3, F10): every limit stops, none passes.
  work: number;
  scriptExpansions: number;
  deadline: number;
  exhausted: boolean;
  // Symlinks created by the command itself (`ln -s`), link path -> target (null = unknown).
  links: Map<string, string | null>;
  linksUnknown: boolean;
  // A file system call threw (as opposed to returning null for a missing or unreadable path).
  fsState: { errored: boolean };
  // File reads and parsed package.json files, once per classification.
  reads: Map<string, string | null>;
  packages: Map<string, { pkg: Record<string, unknown> | null; error?: string } | null>;
  // Script / package-script / make expansions already evaluated in the same context.
  seen: Set<string>;
}

interface Ctx {
  cwds: Array<string | null>;
  vars: Map<string, string[] | null>;
  exported: Set<string>;
  aliases: Map<string, string>;
  gitAliases: Map<string, string>;
  gitConfig: Map<string, string[]>;
  written: Set<string>;
  depth: number;
  remote: boolean;
  kubeContext: string | null | undefined;
  tfWorkspace: string | null | undefined;
  pulumiStack: string | null | undefined;
  decodedVars: Set<string>;
  // Field-splitting characters: undefined = default IFS, a string = a literal IFS, null = unknown.
  ifs: string | null | undefined;
  // Inside a scan of an unknown program's argv: unknown programs are not scanned again.
  backstop: boolean;
}

// An argument after variable resolution: `text` is its single literal value, or null when it is
// dynamic (unresolved variable, substitution) or has several values (loop variable). `pattern` keeps
// the literal parts with DYN for each dynamic slot. `alts` lists every value when they are known.
interface Arg { text: string | null; alts: string[] | null; pattern: string; glob: boolean; word: Word | null; nonAscii: boolean }

function litArg(text: string): Arg {
  return { text, alts: [text], pattern: text, glob: false, word: null, nonAscii: /[^\x00-\x7f]/.test(text) };
}
function dynArg(): Arg { return { text: null, alts: null, pattern: DYN, glob: false, word: null, nonAscii: false }; }

// ---------------------------------------------------------------------------------------------
// public entry points

// Any exception, including a stack overflow on pathological input, is a stop (spec 2.1.4).
function failClosed(env: SeatbeltEnv, source: string): SeatbeltDecision {
  const run = newRun(env, source);
  worseParse(run, 'unparsed');
  hit(run, 'Sx', 'mapper_error');
  return finish(run);
}

export function evaluateSeatbeltShell(command: string, env: SeatbeltEnv): SeatbeltDecision {
  try {
    const run = newRun(env, command);
    evalShell(String(command == null ? '' : command), newCtx(run), run);
    return finish(run);
  } catch {
    try { return failClosed(env, ''); } catch { return failClosedBare(); }
  }
}

// Last resort when even building a run fails (a malformed env): a fixed stop.
function failClosedBare(): SeatbeltDecision {
  return {
    decision: 'stop', category: 'Sx', rule: RULE_IDS.Sx, reasons: ['mapper_error'], hits: [{ category: 'Sx', reason: 'mapper_error' }],
    flags: ['parse_unparsed'], parse: 'unparsed',
    engine: { rules: SEATBELT_RULES_VERSION, classifier_contract: CLASSIFIER_PIN.contract, classifier_source_commit: CLASSIFIER_PIN.source_commit },
  };
}

export function evaluateSeatbelt(event: SeatbeltEvent, env: SeatbeltEnv): SeatbeltDecision {
  try {
    return evaluateEvent(event, env);
  } catch {
    try { return failClosed(env, ''); } catch { return failClosedBare(); }
  }
}

function evaluateEvent(event: SeatbeltEvent, env: SeatbeltEnv): SeatbeltDecision {
  const tool = String((event && event.tool_name) || '');
  const rawInput = event && event.tool_input;
  const input = (rawInput && typeof rawInput === 'object' && !Array.isArray(rawInput) ? rawInput : {}) as Record<string, unknown>;
  const name = tool.toLowerCase();

  // A tool that runs a shell command (audit F11): a known shell tool, or any tool whose input names a
  // command, script or argv field, at any depth.
  const invocation = shellInvocations(name, input);
  if (invocation) {
    const run = newRun(env, invocation.shell.join('\n'));
    for (const text of invocation.shell) evalShell(text, newCtx(run), run);
    for (const code of invocation.code) scanInterpreterCode(code, run);
    if (invocation.malformed) { hit(run, 'Sx', 'tool_command_malformed'); worseParse(run, 'unparsed'); }
    if (invocation.truncated) exhaust(run, 'budget_tool_input');
    // The tool may also take file paths (an MCP tool with `command` and `path`).
    if (name.startsWith('mcp__') && name.split('__')[1] !== 'marrow') mcpPathChecks(name, input, newCtx(run), run);
    return finish(run);
  }
  const run = newRun(env, '');
  const ctx = newCtx(run);
  if (['read', 'notebookread', 'read_file', 'view', 'view_file'].includes(name)) {
    for (const p of pathInputs(input)) checkSecretOperand(litArg(p), ctx, run, 'tool_read');
  } else if (['grep', 'grep_files', 'search', 'rg'].includes(name)) {
    for (const p of pathInputs(input)) checkSecretOperand(litArg(p), ctx, run, 'tool_grep');
    for (const key of ['glob', 'include', 'file_pattern']) {
      const g = input[key];
      if (typeof g === 'string' && g) checkGrepGlob(g, ctx, run);
    }
  } else if (['write', 'edit', 'multiedit', 'notebookedit', 'write_file', 'create_file', 'str_replace_editor', 'str_replace_based_edit_tool', 'apply_patch', 'edit_file'].includes(name)) {
    const targets = name === 'apply_patch' ? patchPaths(String(input.patch || input.input || input.content || '')) : pathInputs(input);
    if (name === 'str_replace_editor' || name === 'str_replace_based_edit_tool') {
      if (String(input.command || '') === 'view') {
        for (const p of targets) checkSecretOperand(litArg(p), ctx, run, 'tool_read');
        return finish(run);
      }
    }
    for (const p of targets) {
      if (checkSecretOperand(litArg(p), ctx, run, 'tool_write')) continue;
      checkToolWrite(p, name, input, ctx, run);
    }
  } else if (name.startsWith('mcp__')) {
    if (name.split('__')[1] !== 'marrow') mcpPathChecks(name, input, ctx, run);
  }
  return finish(run);
}

function mcpPathChecks(name: string, input: Record<string, unknown>, ctx: Ctx, run: Run): void {
  const parts = name.split('__');
  const verbs = /write|edit|create|move|delete|remove|rename|put|update|append|save|mkdir|copy|patch|upload/;
  const walked = walkPathInputs(input);
  if (walked.truncated) exhaust(run, 'budget_tool_input');
  for (const p of walked.paths) {
    if (checkSecretOperand(litArg(p), ctx, run, 'mcp_path')) continue;
    if (verbs.test(parts.slice(2).join('_'))) checkProtectedWrite(litArg(p), ctx, run, 'mcp_write', false);
  }
}

// Tools that never run what their `command`/`script` field says (it names a skill, a slash command,
// a sub-agent task), plus Marrow's own tools.
const NON_SHELL_TOOLS = new Set(['slashcommand', 'skill', 'task', 'agent', 'todowrite', 'todoread', 'exitplanmode', 'enterplanmode',
  'websearch', 'webfetch', 'killshell', 'bashoutput', 'askuserquestion', 'sendmessage', 'taskcreate', 'taskupdate', 'tasklist']);

interface ShellInvocation { shell: string[]; code: string[]; malformed: boolean; truncated: boolean }

function shellInvocations(name: string, input: Record<string, unknown>): ShellInvocation | null {
  const known = SHELL_TOOL_NAMES.has(name);
  if (!known) {
    if (FILE_TOOL_NAMES.has(name) || NON_SHELL_TOOLS.has(name) || name.startsWith('mcp__marrow__') || name.startsWith('marrow_')) return null;
  }
  const out: ShellInvocation = { shell: [], code: [], malformed: false, truncated: false };
  let visited = 0;
  const walk = (obj: Record<string, unknown>, depth: number) => {
    for (const [rawKey, value] of Object.entries(obj)) {
      visited += 1;
      if (visited > LIMITS.maxToolNodes) { out.truncated = true; return; }
      const key = rawKey.toLowerCase().replace(/[-\s]/g, '_');
      if (COMMAND_KEYS.has(key)) {
        if (typeof value === 'string') {
          const extra = [...ARGV_KEYS].map((k) => Object.entries(obj).find(([kk]) => kk.toLowerCase() === k)).find((e) => e && Array.isArray(e[1]));
          const argv = extra && Array.isArray(extra[1]) && (extra[1] as unknown[]).every((v) => typeof v === 'string') ? (extra[1] as string[]).map(shellQuote).join(' ') : '';
          if (value.trim() !== '') out.shell.push(argv ? `${value} ${argv}` : value);
        } else if (Array.isArray(value)) {
          if (value.every((v) => typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')) {
            // `commands` / `cmds` is a list of command lines; any other array is one argv vector.
            if (key === 'commands' || key === 'cmds') { for (const v of value) if (String(v).trim()) out.shell.push(String(v)); }
            else if (value.length) out.shell.push((value as unknown[]).map((v) => shellQuote(String(v))).join(' '));
          } else if (value.every((v) => v && typeof v === 'object' && !Array.isArray(v))) {
            // commands: [{command: …}, …]
            if (depth < LIMITS.maxToolDepth) for (const o of value) walk(o as Record<string, unknown>, depth + 1);
          } else out.malformed = true;
        } else if (typeof value === 'number' || typeof value === 'boolean') {
          out.shell.push(String(value));
        } else if (value && typeof value === 'object') {
          // A command that is an object: unknown shape. Read what is inside it, and stop.
          out.malformed = true;
          if (depth < LIMITS.maxToolDepth) walk(value as Record<string, unknown>, depth + 1);
        }
        continue;
      }
      if (CODE_KEYS.has(key) && typeof value === 'string') { if (value.trim()) out.code.push(value); continue; }
      if (value && typeof value === 'object' && depth < LIMITS.maxToolDepth) {
        if (Array.isArray(value)) {
          for (const item of value) if (item && typeof item === 'object' && !Array.isArray(item)) walk(item as Record<string, unknown>, depth + 1);
        } else walk(value as Record<string, unknown>, depth + 1);
      }
    }
  };
  walk(input, 0);
  if (!known && out.shell.length === 0 && out.code.length === 0 && !out.malformed && !out.truncated) return null;
  return out;
}

function shellQuote(s: string): string {
  return /^[A-Za-z0-9_\-./=:@%+,]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`;
}

const PATH_KEYS = ['file_path', 'path', 'notebook_path', 'filepath', 'filename', 'file', 'target_file', 'paths', 'source', 'destination', 'target', 'dir', 'directory', 'uri', 'files', 'src', 'dest', 'from', 'to', 'old_path', 'new_path'];

function pathInputs(input: Record<string, unknown>): string[] {
  const out: string[] = [];
  const add = (v: unknown) => {
    if (typeof v === 'string' && v) out.push(v.replace(/^file:\/\//, ''));
    else if (Array.isArray(v)) v.forEach(add);
  };
  for (const key of PATH_KEYS) add(input[key]);
  if (Array.isArray(input.edits)) for (const e of input.edits) if (e && typeof e === 'object') add((e as Record<string, unknown>).file_path);
  return [...new Set(out)];
}

// Path-like fields at any depth up to LIMITS.maxToolDepth (audit F14). Over the node budget the
// result is truncated and the caller stops.
function walkPathInputs(input: Record<string, unknown>): { paths: string[]; truncated: boolean } {
  const out = new Set<string>();
  let visited = 0;
  let truncated = false;
  const add = (v: unknown) => {
    if (typeof v === 'string' && v) out.add(v.replace(/^file:\/\//, ''));
    else if (Array.isArray(v)) v.forEach(add);
  };
  const walk = (value: unknown, depth: number) => {
    if (truncated || !value || typeof value !== 'object') return;
    if (depth > LIMITS.maxToolDepth) { truncated = true; return; }
    if (Array.isArray(value)) {
      for (const item of value) { visited += 1; if (visited > LIMITS.maxToolNodes) { truncated = true; return; } walk(item, depth + 1); }
      return;
    }
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      visited += 1;
      if (visited > LIMITS.maxToolNodes) { truncated = true; return; }
      if (PATH_KEYS.includes(k.toLowerCase())) add(v);
      if (v && typeof v === 'object') walk(v, depth + 1);
    }
  };
  walk(input, 0);
  return { paths: [...out], truncated };
}

function patchPaths(patch: string): string[] {
  const out: string[] = [];
  const re = /^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$|^(?:\+\+\+|---) (?:[ab]\/)?(.+)$/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(patch))) {
    const p = (m[1] || m[2] || m[3] || '').trim();
    if (p && p !== '/dev/null') out.push(p);
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// run state

// The injected fs returns null for a path that is missing or unreadable. A call that throws is an
// unexpected failure: the answer is then null, and the run records it so the decision is a stop.
function guardFs(env: SeatbeltEnv, state: { errored: boolean }): SeatbeltEnv {
  const fsIn = env.fs;
  const guarded: SeatbeltFs = {
    readFile: (p, max) => { try { return fsIn.readFile(p, max); } catch { state.errored = true; return null; } },
    realpath: (p) => { try { return fsIn.realpath(p); } catch { state.errored = true; return null; } },
  };
  if (fsIn && typeof fsIn.readdir === 'function') {
    guarded.readdir = (p) => { try { return fsIn.readdir ? fsIn.readdir(p) : null; } catch { state.errored = true; return null; } };
  }
  return { ...env, fs: guarded };
}

function newRun(rawEnv: SeatbeltEnv, source: string): Run {
  const fsState = { errored: false };
  const env = guardFs(rawEnv, fsState);
  const platform = env.platform || 'linux';
  const fold = platform === 'darwin' || platform === 'win32';
  const home = path.posix.normalize(String(env.home || '/nonexistent-home'));
  const realOr = (p: string) => safeRealpath(env, p) || p;
  const tmpRoots = new Set<string>();
  for (const t of [env.tmpdir, '/tmp', '/var/tmp']) {
    if (!t || !path.posix.isAbsolute(t)) continue;
    const n = path.posix.normalize(t).replace(/\/$/, '') || '/';
    if (n === '/') continue;
    tmpRoots.add(n);
    tmpRoots.add(realOr(n));
  }
  const wsRoots = new Set<string>();
  const cwd = typeof env.cwd === 'string' && path.posix.isAbsolute(env.cwd) ? path.posix.normalize(env.cwd) : null;
  if (cwd) {
    let top: string | null = null;
    try { top = env.git.toplevel(cwd); } catch { top = null; }
    const root = top && path.posix.isAbsolute(top) ? path.posix.normalize(top) : cwd;
    for (const r of [root, realOr(root)]) {
      const n = r.replace(/\/$/, '') || '/';
      // A workspace never covers the filesystem root, home or an ancestor of home.
      if (n === '/' || n === home || isAncestorOrSelf(n, home) || isAncestorOrSelf(n, realOr(home))) continue;
      wsRoots.add(n);
    }
  }
  const protectedPatterns = baseline.BASELINE_POLICY.protected_paths;
  const protectedRegexes = protectedPatterns.map((p) => classifierModule.globToRegex(fold ? p.toLowerCase() : p, fold ? home.toLowerCase() : home));
  const anchors: string[] = [];
  for (const p of protectedPatterns) {
    if (p.startsWith('~/')) anchors.push(path.posix.join(home, p.slice(2).replace(/\/\*\*$/, '')));
    else if (p.startsWith('/') && !p.includes('*', 1)) anchors.push(p);
  }
  for (const root of wsRoots) {
    for (const rel of ['.claude/settings.json', '.claude/settings.local.json', '.mcp.json', '.cursor/mcp.json', '.cursor/hooks.json', '.codex', '.gemini/settings.json', '.windsurf', '.clinerules/hooks', '.grok', '.marrow', '.git/hooks', '.git/config']) {
      anchors.push(path.posix.join(root, rel));
    }
  }
  return {
    env, home, fold, hits: [], flags: new Set(), parse: 'ok', wsRoots: [...wsRoots], tmpRoots: [...tmpRoots],
    isProtected: (abs: string) => protectedRegexes.some((re) => re.test(fold ? abs.toLowerCase() : abs)),
    protectedAnchors: anchors.map((a) => (fold ? a.toLowerCase() : a)),
    secretRegexes: SECRET_PATTERNS.map((p) => classifierModule.globToRegex(p, home)),
    branchRegexes: baseline.BASELINE_POLICY.protected_branches.map((p) => classifierModule.globToRegex(p, '/nonexistent-home')),
    topSource: source,
    work: 0,
    scriptExpansions: 0,
    deadline: Date.now() + (typeof env.budgetMs === 'number' && env.budgetMs >= 0 ? env.budgetMs : LIMITS.timeBudgetMs),
    exhausted: false,
    links: new Map(),
    linksUnknown: false,
    fsState,
    reads: new Map(),
    packages: new Map(),
    seen: new Set(),
  };
}

function newCtx(run: Run): Ctx {
  const cwd = typeof run.env.cwd === 'string' && path.posix.isAbsolute(run.env.cwd) ? path.posix.normalize(run.env.cwd) : null;
  return {
    cwds: [cwd], vars: new Map([['HOME', [run.home]]]), exported: new Set(['HOME']), aliases: new Map(), gitAliases: new Map(),
    gitConfig: new Map(), written: new Set(), depth: 0, remote: false, kubeContext: undefined, tfWorkspace: undefined, pulumiStack: undefined,
    decodedVars: new Set(), ifs: undefined, backstop: false,
  };
}

function childCtx(ctx: Ctx, overrides: Partial<Ctx> = {}): Ctx {
  return { ...ctx, depth: ctx.depth + 1, backstop: false, ...overrides };
}

function scriptCtx(ctx: Ctx, cwds: Array<string | null>, extraEnv: Map<string, string[] | null>): Ctx {
  // A child process sees exported variables and same-command assignments only.
  const vars = new Map<string, string[] | null>();
  for (const name of ctx.exported) if (ctx.vars.has(name)) vars.set(name, ctx.vars.get(name) ?? null);
  for (const [k, v] of extraEnv) vars.set(k, v);
  return { ...ctx, cwds, vars, exported: new Set([...ctx.exported, ...extraEnv.keys()]), aliases: new Map(), depth: ctx.depth + 1, backstop: false };
}

function hit(run: Run, category: Exclude<SeatbeltCategory, 'none'>, reason: string): true {
  if (!run.hits.some((h) => h.category === category && h.reason === reason)) run.hits.push({ category, reason });
  return true;
}

function worseParse(run: Run, p: SeatbeltParse): void {
  if (PARSE_RANK[p] > PARSE_RANK[run.parse]) run.parse = p;
}

// Budgets (audit F3, F10). One unit per evaluated command or shell text; one script expansion per
// package script, make target or script file. Exceeding any budget (work, script fan-out, wall clock)
// records a stop and ends the evaluation: over the budget never passes.
function exhaust(run: Run, reason: string): false {
  run.exhausted = true;
  worseParse(run, 'too_large');
  hit(run, 'Sx', reason);
  return false;
}

function tick(run: Run): boolean {
  if (run.exhausted) return false;
  run.work += 1;
  if (run.work > LIMITS.maxWork) return exhaust(run, 'budget_work');
  if (Date.now() >= run.deadline) return exhaust(run, 'budget_time');
  return true;
}

function expandScript(run: Run): boolean {
  if (run.exhausted) return false;
  run.scriptExpansions += 1;
  if (run.scriptExpansions > LIMITS.maxScriptExpansions) return exhaust(run, 'budget_scripts');
  return true;
}

// True when this script, package script or make target was already evaluated in the same context:
// its hits are already recorded, so a fan-out of references costs one evaluation each.
function alreadySeen(run: Run, ctx: Ctx, kind: string, id: string, env: Map<string, string[] | null>): boolean {
  const exported = [...ctx.exported].sort().map((n) => `${n}=${JSON.stringify(ctx.vars.get(n) ?? null)}`).join('\u0001');
  const e = [...env.entries()].sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join('\u0001');
  const cwd = ctx.cwds.map((c) => c || '?').join(',');
  // Everything a verdict can depend on: the deploy contexts, git aliases and config, IFS, decoded vars.
  const state = JSON.stringify([ctx.kubeContext, ctx.tfWorkspace, ctx.pulumiStack, [...ctx.gitAliases], [...ctx.gitConfig], ctx.ifs, [...ctx.decodedVars], [...ctx.aliases], ctx.depth, ctx.backstop]);
  const key = `${kind}\u0002${id}\u0002${cwd}\u0002${exported}\u0002${e}\u0002${ctx.remote ? 'r' : 'l'}\u0002${state}`;
  if (run.seen.has(key)) return true;
  run.seen.add(key);
  return false;
}

function finish(run: Run): SeatbeltDecision {
  if (run.fsState.errored) hit(run, 'Sx', 'fs_error');
  const hits = [...run.hits].sort((a, b) => CATEGORY_ORDER.indexOf(a.category) - CATEGORY_ORDER.indexOf(b.category));
  const category: SeatbeltCategory = hits.length ? hits[0].category : 'none';
  if (run.parse !== 'ok') run.flags.add(`parse_${run.parse}`);
  return {
    decision: hits.length ? 'stop' : 'pass',
    category,
    rule: RULE_IDS[category],
    reasons: hits.map((h) => h.reason),
    hits,
    flags: [...run.flags].sort(),
    parse: run.parse,
    engine: { rules: SEATBELT_RULES_VERSION, classifier_contract: CLASSIFIER_PIN.contract, classifier_source_commit: CLASSIFIER_PIN.source_commit },
  };
}

function safeRealpath(env: SeatbeltEnv, p: string): string | null {
  try { const r = env.fs.realpath(p); return typeof r === 'string' && path.posix.isAbsolute(r) ? path.posix.normalize(r) : null; } catch { return null; }
}
function safeRead(env: SeatbeltEnv, p: string, max: number): string | null {
  try { const r = env.fs.readFile(p, max); return typeof r === 'string' ? r : null; } catch { return null; }
}
// One read per file per classification (a script referenced sixty times is read once).
function readCached(run: Run, p: string, max: number): string | null {
  const k = `${p}\u0000${max}`;
  if (run.reads.has(k)) return run.reads.get(k) as string | null;
  const v = safeRead(run.env, p, max);
  run.reads.set(k, v);
  return v;
}
function gitAll(run: Run, ctx: Ctx, cwd: string | null, key: string, overrides?: Map<string, string[]>): string[] | null {
  const lower = canonicalGitKey(key);
  const out: string[] = [];
  if (cwd) {
    try { out.push(...run.env.git.getAll(cwd, key)); } catch { return null; }
  }
  const fromCtx = ctx.gitConfig.get(lower);
  if (fromCtx) out.push(...fromCtx);
  const fromC = overrides && overrides.get(lower);
  if (fromC) out.push(...fromC);
  return out;
}
function canonicalGitKey(key: string): string {
  const first = key.indexOf('.');
  const last = key.lastIndexOf('.');
  if (first < 0) return key.toLowerCase();
  if (first === last) return key.toLowerCase();
  return `${key.slice(0, first).toLowerCase()}.${key.slice(first + 1, last)}.${key.slice(last + 1).toLowerCase()}`;
}

function isAncestorOrSelf(a: string, b: string): boolean {
  if (a === b) return true;
  if (a === '/') return true;
  return b.startsWith(`${a}/`);
}

// ---------------------------------------------------------------------------------------------
// shell evaluation

const STRUCTURAL_REASONS = new Set(['case_statement', 'coproc_statement', 'unterminated_heredoc', 'dangling_redirect']);

function evalShell(src: string, ctx: Ctx, run: Run): void {
  if (!tick(run)) return;
  if (ctx.depth > LIMITS.maxDepth) { worseParse(run, 'too_large'); run.flags.add('depth_limit'); hit(run, 'Sx', 'budget_depth'); tripwire(src, run); return; }
  if (Buffer.byteLength(src) > LIMITS.maxCommandBytes) { worseParse(run, 'too_large'); hit(run, 'Sx', 'budget_size'); tripwire(src.slice(0, LIMITS.maxCommandBytes), run); return; }
  const parsed = shellParse.parseShell(src, { depth: ctx.depth });
  if (!parsed.ok) {
    const big = parsed.error === 'too_large' || parsed.error === 'too_many_commands';
    worseParse(run, big ? 'too_large' : 'unparsed');
    tripwire(src.slice(0, LIMITS.maxCommandBytes), run);
    // Over the parser's budget, or text it cannot parse that also builds words from variables: stop.
    if (big) hit(run, 'Sx', parsed.error === 'too_many_commands' ? 'budget_segments' : 'budget_size');
    else if (/[$`]|(?:^|[\s;&|(])[A-Za-z_][A-Za-z0-9_]*\+?=/.test(src)) hit(run, 'Sx', 'unparsed_dynamic');
    return;
  }
  if (parsed.commands.length > LIMITS.maxSegments) { worseParse(run, 'too_large'); hit(run, 'Sx', 'budget_segments'); tripwire(src, run); return; }
  if (parsed.dynamic) worseParse(run, 'dynamic');
  if (parsed.reasons.some((r) => STRUCTURAL_REASONS.has(r))) { worseParse(run, 'unparsed'); tripwire(src, run); }
  const ansiC = /\$'[^']*\\(?:x[0-9a-fA-F]|[0-7]{2,3}|u[0-9a-fA-F])/.test(src);

  // Command and process substitutions run too; classify them first (S-x checks see them below).
  for (const sub of parsed.substitutions) evalShell(sub, childCtx(ctx), run);

  // Pipelines, for decoded-exec (S-x) and stdin-fed shells.
  const pipelines: ShellCommand[][] = [];
  const groupSource = new Set<ShellCommand>();
  for (const command of parsed.commands) {
    if (command.pipedInput && pipelines.length) {
      const prev = pipelines[pipelines.length - 1];
      // `{ a; b; } | sh`: the group's output is piped but the parser drops the group, so the stage
      // before this one did not itself pipe into it.
      if (!prev[prev.length - 1].pipesOutput) groupSource.add(command);
      prev.push(command);
    } else pipelines.push([command]);
  }
  for (const pipeline of pipelines) {
    for (let i = 0; i < pipeline.length; i += 1) {
      const upstream = pipeline.slice(0, i);
      evalCommand(pipeline[i], ctx, run, { upstream, ansiC, subs: parsed.substitutions, groupSource: groupSource.has(pipeline[i]) });
    }
  }
}

interface CmdInfo { upstream: ShellCommand[]; ansiC: boolean; subs: string[]; groupSource?: boolean }

// Bash brace expansion ({a,b}, {1..3}); quoting is not tracked per part, so it always expands
// (stricter). Sequences are left unresolved.
function expandBraces(text: string): string[] | null {
  const m = text.match(/^(.*?)\{([^{}]*)\}(.*)$/s);
  if (!m) return [text];
  if (/\.\./.test(m[2]) && !m[2].includes(',')) return null;
  if (!m[2].includes(',')) return [text];
  const out: string[] = [];
  for (const part of m[2].split(',')) {
    const sub = expandBraces(`${m[1]}${part}${m[3]}`);
    if (!sub) return null;
    out.push(...sub);
    if (out.length > 16) return null;
  }
  return out;
}

function resolveWord(word: Word, ctx: Ctx, run: Run): Arg {
  const r = resolveWordRaw(word, ctx, run);
  if (r.text === null || !/\{[^{}]*(?:,|\.\.)[^{}]*\}/.test(r.text)) return r;
  const alts = expandBraces(r.text);
  if (alts && alts.length === 1) return { ...r, text: alts[0], alts, pattern: alts[0] };
  return { ...r, text: null, alts, pattern: r.text };
}

function resolveWordRaw(word: Word, ctx: Ctx, run: Run): Arg {
  const nonAscii = /[^\x00-\x7f]/.test(word.text.replace(/\u0000/g, ''));
  if (!word.dynamic) return { text: word.text, alts: [word.text], pattern: word.text, glob: Boolean(word.glob), word, nonAscii };
  const parts = word.text.split('\u0000');
  let values: string[] | null = [parts[0]];
  let pattern = parts[0];
  for (let k = 0; k < word.slots.length; k += 1) {
    const slot = word.slots[k];
    pattern += DYN + (parts[k + 1] || '');
    if (values === null) continue;
    let bound: string[] | null | undefined = null;
    if (slot && slot.type === 'var' && slot.name) {
      const name = slot.name;
      if (name === 'HOME') bound = [run.home];
      else if (name === 'PWD') bound = ctx.cwds.length === 1 && ctx.cwds[0] ? [ctx.cwds[0]] : null;
      else if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) bound = ctx.vars.has(name) ? ctx.vars.get(name) : null;
      else bound = null;
    }
    if (!bound) { values = null; continue; }
    const next: string[] = [];
    for (const prefix of values) for (const option of bound) next.push(`${prefix}${option}${parts[k + 1] || ''}`);
    values = next.length > 16 ? null : next;
  }
  if (values && values.length === 1) {
    const text = values[0];
    return { text, alts: values, pattern: text, glob: Boolean(word.glob), word, nonAscii: nonAscii || /[^\x00-\x7f]/.test(text) };
  }
  return { text: null, alts: values, pattern, glob: Boolean(word.glob), word, nonAscii };
}

function argText(a: Arg): string { return a.text !== null ? a.text : a.pattern.replace(new RegExp(DYN, 'g'), ''); }

function evalCommand(cmd: ShellCommand, ctx: Ctx, run: Run, info: CmdInfo): void {
  if (cmd.forLoop) {
    const items = cmd.forLoop.items;
    if (!items) { ctx.vars.set(cmd.forLoop.name, null); return; }
    const values: string[] = [];
    for (const w of items) {
      const a = resolveWord(w, ctx, run);
      if (a.text === null || a.glob) { ctx.vars.set(cmd.forLoop.name, null); return; }
      values.push(a.text);
    }
    ctx.vars.set(cmd.forLoop.name, values.length ? values : null);
    return;
  }

  // Redirects: writes to protected paths (S0), reads or writes of secret paths (S4).
  for (const r of cmd.redirects) {
    if (!r.target) continue;
    const a = resolveWord(r.target, ctx, run);
    if (r.op === '>&' || r.op === '<&' || r.op === '<<<') {
      if (a.text !== null && /^(?:\d+|-)$/.test(a.text)) continue;
      if (r.op === '<<<') continue;
    }
    if (OUTPUT_REDIRECTS.has(r.op) || r.op === '>&') {
      if (a.text && SAFE_DEVICES.test(a.text)) continue;
      checkSecretOperand(a, ctx, run, 'redirect_write');
      checkProtectedWrite(a, ctx, run, 'redirect_write', false);
      markWritten(a, ctx);
    } else if (r.op === '<') {
      checkSecretOperand(a, ctx, run, 'redirect_read');
    }
  }

  const assignEnv = new Map<string, string[] | null>();
  for (const w of cmd.assignments) {
    const eq = w.text.indexOf('=');
    const rawName = w.text.slice(0, eq);
    const name = rawName.replace(/\+$/, '').replace(/\[.*$/, '');
    const valueWord: Word = { ...w, text: w.text.slice(eq + 1) };
    const v = resolveWord(valueWord, ctx, run);
    let value: string[] | null = v.text !== null ? [v.text] : v.alts;
    // `x+=…` appends to the earlier value (unknown when that is unknown).
    if (/\+$/.test(rawName) && !/\[/.test(rawName)) {
      const before = assignEnv.has(name) ? assignEnv.get(name) : ctx.vars.get(name);
      value = value && before && before.length === 1 ? value.map((x) => `${before[0]}${x}`) : value && before === undefined ? value : null;
    }
    assignEnv.set(name, value);
  }
  if (cmd.words.length === 0) {
    for (const [k, v] of assignEnv) {
      ctx.vars.set(k, v);
      if (k === 'IFS') ctx.ifs = v && v.length === 1 ? v[0] : null;
    }
    // X=$(… | base64 -d): executing $X later is decoded exec.
    if (cmd.assignments.some((w) => w.substitution) && substitutionsDecode(info.subs, run)) for (const k of assignEnv.keys()) ctx.decodedVars.add(k);
    return;
  }

  // `… | base64 -d | tee >(sh)`: a process substitution that is a shell or interpreter, fed by a
  // decoder upstream (the parser does not say whether `<(…)` or `>(…)` was written).
  if (info.upstream.length && cmd.words.some((w) => w.substitution) && info.upstream.some((c) => decoderCommand(c, run, info))) {
    for (const sub of info.subs) {
      const parsedSub = shellParse.parseShell(sub, { depth: ctx.depth + 1 });
      if (parsedSub.ok && parsedSub.commands.some((c) => { const p0 = (c.words[0]?.text || '').split('/').pop() || ''; return SHELLS.has(p0) || INTERPRETERS.has(p0); })) hit(run, 'Sx', 'decoded_process_substitution_exec');
    }
  }

  // BASH_ENV and ENV name a file a shell runs before its own script: read it as a script.
  for (const name of ['BASH_ENV', 'ENV']) {
    const v = assignEnv.has(name) ? assignEnv.get(name) : ctx.exported.has(name) ? ctx.vars.get(name) : undefined;
    if (v === undefined) continue;
    if (v === null || v.length !== 1) { worseParse(run, 'dynamic'); hit(run, 'Sx', 'dynamic_startup_file'); continue; }
    if (v[0]) scriptFile(litArg(v[0]), [], ctx, run, null);
  }

  // Words are field-split like the shell does (audit F2): `x='npm publish'; $x` runs npm with publish,
  // `F='-f origin main'; git push $F` pushes with -f.
  const variants = argvVariants(cmd.words, ctx, run);
  // Shell aliases defined earlier in this command line.
  const first = cmd.words[0];
  if (!first.quoted && !first.dynamic && ctx.aliases.has(first.text) && ctx.depth < LIMITS.maxDepth + 2) {
    const args = variants[0] || [];
    const rest = args.slice(1).map((a) => (a.text !== null ? shellQuote(a.text) : '"$__marrow_dynamic"')).join(' ');
    evalShell(`${ctx.aliases.get(first.text)} ${rest}`, childCtx(ctx), run);
    return;
  }
  for (const args of variants) dispatch(args, ctx, run, { cmd, info, env: assignEnv });
}

// ---------------------------------------------------------------------------------------------
// word expansion with field splitting (audit F2)

function hasVarSlot(w: Word): boolean { return w.slots.some((s) => s.type === 'var'); }

// Default IFS splits on space, tab and newline; a literal IFS assignment is honoured; an unknown IFS
// (null) cannot be split and leaves the word unresolved.
function ifsSplit(value: string, ifs: string | null | undefined): string[] | null {
  if (ifs === null) return null;
  const chars = ifs === undefined ? ' \t\n' : ifs;
  if (chars === '') return [value];
  const set = new Set(chars);
  const fields: string[] = [];
  let cur = '';
  for (const ch of value) {
    if (set.has(ch)) { if (cur !== '') fields.push(cur); cur = ''; } else cur += ch;
  }
  if (cur !== '') fields.push(cur);
  return fields;
}

function fieldArg(value: string, word: Word, base: Arg, unquotedExpansion: boolean): Arg {
  return {
    text: value, alts: [value], pattern: value, word, nonAscii: /[^\x00-\x7f]/.test(value),
    glob: base.glob || (unquotedExpansion && /[*?[]/.test(value)),
  };
}

// Every reading of one word as a list of fields. A resolved variable value is split when the word is
// unquoted (or when `force` asks for the split reading of a partly quoted word).
function wordAlternatives(word: Word, ctx: Ctx, run: Run, force: boolean): Arg[][] {
  const base = resolveWord(word, ctx, run);
  if (!word.dynamic || !hasVarSlot(word)) return [[base]];
  if (base.alts === null || base.alts.length === 0) {
    // Unresolved. An unquoted expansion under an unknown IFS is just as unresolved.
    return [[base]];
  }
  const splits = !word.quoted || force;
  const out: Arg[][] = [];
  const seen = new Set<string>();
  for (const value of base.alts) {
    if (seen.has(value)) continue;
    seen.add(value);
    if (!splits) { out.push([fieldArg(value, word, base, false)]); continue; }
    const fields = ifsSplit(value, ctx.ifs);
    if (fields === null) { out.push([{ ...base, text: null, alts: null, pattern: DYN }]); continue; }
    out.push(fields.map((f) => fieldArg(f, word, base, !word.quoted)));
  }
  return out.length ? out : [[base]];
}

function expandWords(words: Word[], ctx: Ctx, run: Run, force: boolean): Arg[][] {
  let variants: Arg[][] = [[]];
  for (const w of words) {
    const alts = wordAlternatives(w, ctx, run, force);
    if (alts.length === 1 && variants.length === 1) { variants[0] = [...variants[0], ...alts[0]]; continue; }
    const next: Arg[][] = [];
    for (const v of variants) for (const a of alts) next.push([...v, ...a]);
    if (next.length > LIMITS.maxVariants) {
      // Too many readings: keep one reading with every multi-valued word unresolved.
      return [words.flatMap((w2) => {
        const alts2 = wordAlternatives(w2, ctx, run, force);
        return alts2.length === 1 ? alts2[0] : [{ ...dynArg(), word: w2, pattern: DYN }];
      })];
    }
    variants = next;
  }
  return variants;
}

function argvVariants(words: Word[], ctx: Ctx, run: Run): Arg[][] {
  const normal = expandWords(words, ctx, run, false);
  // The parser marks a whole word quoted when any part is (`$x""`, `a"$x"`), so the unquoted
  // expansion inside it would still split. Classify that split reading as well.
  if (words.some((w) => w.quoted && w.dynamic && hasVarSlot(w))) {
    const sig = (v: Arg[]) => v.map((a) => (a.text === null ? `\u0001${a.pattern}` : a.text)).join('\u0000');
    const have = new Set(normal.map(sig));
    for (const v of expandWords(words, ctx, run, true)) {
      if (normal.length >= LIMITS.maxVariants * 2) break;
      if (!have.has(sig(v))) { normal.push(v); have.add(sig(v)); }
    }
  }
  return normal;
}

interface Exec { cmd: ShellCommand; info: CmdInfo; env: Map<string, string[] | null> }

function progName(a: Arg, run: Run): string | null {
  if (a.text === null) return null;
  const base = a.text.replace(/\/+$/, '').split('/').pop() || '';
  return run.fold ? base.toLowerCase() : base;
}

function isOpt(a: Arg): boolean { return a.text !== null && a.text.length > 1 && a.text.startsWith('-'); }

function dispatch(args: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  if (args.length === 0) return;
  if (!tick(run)) return;
  const prog = progName(args[0], run);
  if (prog === null) return dynamicProgram(args, ctx, run, x);
  const rest = args.slice(1);
  const pathLike = args[0].text !== null && args[0].text.includes('/');

  // Generic operand checks apply to every program (S4 reads, S0 writes by write-programs).
  genericOperandChecks(prog, args, ctx, run, x.info.subs);

  switch (prog) {
    case 'cd': case 'pushd': return changeDir(rest, ctx, run, x.cmd.subshell);
    case 'popd': ctx.cwds = [...ctx.cwds, null]; return;
    case 'alias': return defineAliases(rest, ctx, run);
    case 'export': case 'declare': case 'typeset': case 'readonly': case 'local': return declareLike(prog, rest, ctx, run, x);
    case 'set': return setBuiltin(rest, run);
    case 'unset': for (const a of rest) if (a.text) { ctx.vars.delete(a.text); if (a.text === 'IFS') ctx.ifs = undefined; } return;
    case 'printenv': return printenv(rest, run);
    case 'echo': case 'printf': case 'print': return echoLike(args, run, x);
    case 'eval': return evalBuiltin(rest, ctx, run, x.info.subs);
    case 'source': case '.': return sourceFile(rest, ctx, run, x);
    case 'env': return envWrapper(rest, ctx, run, x);
    case 'sudo': case 'doas': case 'pkexec': case 'runas': return privilegeWrapper(prog, rest, ctx, run, x);
    case 'su': return suWrapper(rest, ctx, run, x);
    case 'timeout': case 'nice': case 'nohup': case 'time': case 'command': case 'builtin': case 'exec': case 'stdbuf':
    case 'ionice': case 'chrt': case 'taskset': case 'setsid': case 'unbuffer': case 'caffeinate': case 'retry': case 'flock':
      return simpleWrapper(prog, rest, ctx, run, x);
    case 'xargs': case 'parallel': return xargsWrapper(prog, rest, ctx, run, x);
    case 'watch': return watchWrapper(rest, ctx, run);
    case 'ssh': return sshRemote(rest, ctx, run, x);
    case 'git': return handleGit(rest, ctx, run, x, new Map(), 0);
    case 'gh': return handleGh(rest, ctx, run);
    case 'npm': case 'pnpm': case 'yarn': case 'bun': return handlePackageManager(prog, rest, ctx, run, x);
    case 'npx': case 'bunx': return handleNpx(rest, ctx, run, x);
    case 'corepack': case 'busybox': case 'toybox': return dispatch(rest, ctx, run, x);
    case 'trap': return trapBuiltin(rest, ctx, run, x);
    case 'awk': case 'gawk': case 'mawk': return awkProgram(rest, ctx, run);
    case 'sed': case 'gsed': return sedProgram(rest, ctx, run);
    case 'ps': return psProgram(rest, run);
    case 'tar': case 'gtar': case 'bsdtar': return tarProgram(rest, ctx, run, x);
    case 'concurrently': return concurrentlyWrapper(rest, ctx, run, x);
    case 'npm-run-all': case 'npm-run-all2': case 'run-s': case 'run-p': return runAllWrapper(rest, ctx, run, x);
    case 'make': case 'gmake': return handleMake(rest, ctx, run, x);
    case 'rm': return handleRm(rest, ctx, run);
    case 'rimraf': return checkTreeDeletes(rest.filter((a) => !isOpt(a)), ctx, run, 'rimraf');
    case 'rmdir': return handleRmdir(rest, ctx, run);
    case 'find': return handleFind(rest, ctx, run, x);
    case 'rsync': return handleRsync(rest, ctx, run);
    case 'shred': return handleShred(rest, ctx, run);
    case 'dd': return handleDd(rest, run);
    case 'docker': case 'podman': return handleDocker(rest, ctx, run);
    case 'kubectl': return handleKubectl(rest, ctx, run, x);
    case 'helm': return handleHelm(rest, ctx, run);
    case 'marrow': return handleMarrowCli(rest, run);
    case 'marrow-install': return handleMarrowCli(rest, run);
    case 'claude': return handleClaudeCli(rest, run);
    case 'apply_patch': case 'applypatch': {
      const text = x.cmd.heredoc !== null ? x.cmd.heredoc : rest.map(argText).join('\n');
      for (const p of patchPaths(text)) {
        if (!checkSecretOperand(litArg(p), ctx, run, 'patch_write')) checkProtectedWrite(litArg(p), ctx, run, 'patch_write', false);
      }
      return;
    }
    default: break;
  }
  if (/^mkfs(?:\.|$)/.test(prog)) { hit(run, 'S5', 'mkfs'); return; }
  if (SHELLS.has(prog)) return handleShell(prog, rest, ctx, run, x);
  if (INTERPRETERS.has(prog) || /^python3\.\d+$/.test(prog)) return handleInterpreter(prog, rest, ctx, run, x);
  // Deploy and publish tools run commands too (`heroku run …`, `railway run …`, `lerna exec`): once a
  // handler has taken the command, the argv is still scanned for a command inside it.
  const scanHandled = () => {
    if (!INERT_PROGRAMS.has(prog) && !ctx.backstop && !DATA_ARGV_TOOLS.has(prog)) scanArgvForCommands(rest, ctx, run, x);
  };
  if (handleDeployTool(prog, rest, ctx, run, x)) return scanHandled();
  if (handlePublishTool(prog, rest, ctx, run)) return scanHandled();
  if (handleSecretDumper(prog, rest, run)) return scanHandled();
  if (pathLike) return scriptFile(args[0], rest, ctx, run, x);
  unknownProgram(prog, args, ctx, run, x);
}

// Tools whose arguments are mostly data (variables, payloads); their argv is not scanned for commands.
const DATA_ARGV_TOOLS = new Set(['terraform', 'tofu', 'terragrunt', 'pulumi', 'cdk', 'helm', 'kubectl']);

// ---------------------------------------------------------------------------------------------
// dynamic command words and unknown programs (audit F1, F2)

// A program word that is still dynamic after variable resolution and field splitting. The shell runs
// whatever it expands to and the mapper cannot know it: stop. Two forms stay resolvable: a word that
// ends in a literal program name (`$(npm bin)/eslint`, `"$DIR"/node_modules/.bin/jest`), which is
// classified as that program, and a substitution whose own text is decoded or fetched code.
function dynamicProgram(args: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  worseParse(run, 'dynamic');
  const a = args[0];
  const slash = a.pattern.lastIndexOf('/');
  const tail = slash >= 0 ? a.pattern.slice(slash + 1) : '';
  if (tail && !tail.includes(DYN) && /^[A-Za-z0-9_.@+-]+$/.test(tail)) {
    nameTripwire(tail, run, 'script_unreadable');
    dispatch([litArg(tail), ...args.slice(1)], ctx, run, x);
    return;
  }
  if (a.word && a.word.substitution) checkSubstitutionExec(x.info.subs, ctx, run);
  else if (ctx.decodedVars.size && a.word && a.word.variables.some((v) => ctx.decodedVars.has(v))) hit(run, 'Sx', 'decoded_variable_exec');
  tripwire(args.map(argText).join(' '), run);
  hit(run, 'Sx', 'dynamic_command_word');
}

// The word is exactly one substitution, nothing else.
function isPureSubstitution(a: Arg): boolean {
  return a.text === null && a.pattern === DYN && !!a.word && a.word.slots.length === 1 && a.word.slots[0].type === 'sub';
}

// A word that starts a command the mapper has a handler for (or a script path).
function isCommandWord(a: Arg, run: Run): boolean {
  if (a.text === null) return false;
  const base = progName(a, run) || '';
  if (NESTED_NOT_PROGRAMS.has(base)) return false;
  if (KNOWN_COMMANDS.has(base) || /^python3\.\d+$/.test(base) || /^mkfs(?:\.|$)/.test(base)) return true;
  if (a.text.includes('/')) {
    const name = base.toLowerCase();
    if (NON_SCRIPT_NAMES.has(name)) return false;
    return SCRIPT_SUFFIX.test(name) || (/^\.\.?\//.test(a.text) && !name.includes('.'));
  }
  return false;
}
// Shell builtins and words that only mean something as the first word of a command line. As an
// argument of another program they are plain text.
// Paths that name the program's own stdin.
const STDIN_PATHS = new Set(['/dev/stdin', '/dev/fd/0', '/proc/self/fd/0', '/proc/self/fd/0/']);

// Programs that read their commands from stdin.
const STDIN_EXEC_PROGRAMS = new Set(['at', 'batch', 'atq-run', 'crontab']);
const NESTED_NOT_PROGRAMS = new Set(['set', 'export', 'declare', 'typeset', 'readonly', 'local', 'unset', 'alias', 'cd', 'pushd', 'popd',
  'eval', 'source', '.', 'trap', 'type', 'command', 'builtin', 'exec', 'print']);

// Every command hidden in the argv of a program the mapper has no handler for (`strace -f npm
// publish`, `cross-env NODE_ENV=production vercel --prod`, `tmux new -d 'npm publish'`). Used for
// unknown programs and for known wrappers with open grammars (docker run IMAGE CMD…).
function scanArgvForCommands(rest: Arg[], ctx: Ctx, run: Run, x: Exec, remote = false): void {
  const base: Ctx = remote ? childCtx(ctx, { cwds: [null], remote: true, vars: new Map(), aliases: new Map(), backstop: true }) : { ...ctx, backstop: true };
  const env = new Map(x.env);
  let trials = 0;
  for (let k = 0; k < rest.length; k += 1) {
    if (run.exhausted) return;
    const w = rest[k];
    if (w.text === null) continue;
    const m = /^([A-Za-z_][A-Za-z0-9_]*)=([\s\S]*)$/.exec(w.text);
    if (m && !/\s/.test(m[2])) { env.set(m[1], [m[2]]); continue; }
    // A quoted command string: `script -qc 'npm publish'`, `tmux new 'npm publish'`, `--cmd=npm publish`,
    // `-o ProxyCommand=npm publish`.
    const kv = /^[A-Za-z][A-Za-z0-9_.-]*=([\s\S]+)$/.exec(w.text);
    const value = w.text.startsWith('-') ? (w.text.indexOf('=') > 0 ? w.text.slice(w.text.indexOf('=') + 1) : '') : kv ? kv[1] : w.text;
    if (/\s/.test(value) && value.length > 2) {
      evalShell(value, childCtx(base, { backstop: false }), run);
      if (w.text.startsWith('-') || kv) continue;
    }
    if (w.text.startsWith('-')) continue;
    if (!isCommandWord(w, run)) continue;
    const tail = rest.slice(k);
    const b = progName(w, run);
    if ((b === 'env' || b === 'printenv') && tail.length === 1) continue;
    trials += 1;
    if (trials > LIMITS.maxTailTrials) { exhaust(run, 'budget_argv_scan'); return; }
    dispatch(tail, base, run, { ...x, env: new Map(env) });
  }
}

// What printf and echo -e write: backslash escapes decoded, conversions replaced by the arguments.
function unescapeBackslashes(s: string): string {
  return s.replace(/\\(?:x([0-9a-fA-F]{1,2})|u([0-9a-fA-F]{1,4})|([0-7]{1,3})|([abefnrtv\\'"]))/g, (_m, hex, uni, oct, ch) => {
    if (hex) return String.fromCharCode(parseInt(hex, 16));
    if (uni) return String.fromCharCode(parseInt(uni, 16));
    if (oct) return String.fromCharCode(parseInt(oct, 8));
    const map: Record<string, string> = { a: '\x07', b: '\b', e: '\x1b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v', '\\': '\\', "'": "'", '"': '"' };
    return map[ch] ?? ch;
  });
}
function printfOutput(format: string, args: string[]): string {
  const fmt = unescapeBackslashes(format);
  let out = '';
  let used = 0;
  for (let round = 0; round < 64; round += 1) {
    let consumed = false;
    out += fmt.replace(/%(?:%|[-+ #0]*\d*(?:\.\d+)?[sdiouxXeEfgGcb])/g, (m) => {
      if (m === '%%') return '%';
      consumed = true;
      const v = used < args.length ? args[used] : '';
      used += 1;
      return m.endsWith('b') ? unescapeBackslashes(v) : v;
    });
    if (!consumed || used >= args.length) break;
  }
  return out;
}

// Text fed to a program's stdin that is known statically: a heredoc body, a here-string, or the
// literal output of an upstream echo/printf/cat. `unknown` = a source the mapper cannot read.
function stdinSource(x: Exec, ctx: Ctx, run: Run): { texts: string[]; files: Arg[]; unknown: boolean } {
  const out = { texts: [] as string[], files: [] as Arg[], unknown: false };
  const addWord = (a: Arg) => {
    if (a.text !== null) out.texts.push(a.text);
    else if (a.alts && a.alts.length) out.texts.push(...a.alts);
    else { out.unknown = true; out.texts.push(argText(a)); }
  };
  if (x.cmd.heredoc !== null) out.texts.push(x.cmd.heredoc);
  for (const r of x.cmd.redirects) if (r.op === '<<<' && r.target) addWord(resolveWord(r.target, ctx, run));
  if (out.texts.length) return out;
  const up = x.info.upstream;
  if (!up.length) return out;
  const last = up[up.length - 1];
  const words = last.words.map((w) => resolveWord(w, ctx, run));
  const p = words[0] ? progName(words[0], run) : null;
  if (p === 'echo' || p === 'printf') {
    const flags = words.slice(1).filter((w) => p === 'echo' && /^-[neE]+$/.test(w.text || '')).map((w) => w.text as string);
    const operands = words.slice(1).filter((w) => !(p === 'echo' && /^-[neE]+$/.test(w.text || '')));
    if (operands.every((w) => w.text !== null)) {
      const texts = operands.map((w) => w.text as string);
      if (p === 'printf') out.texts.push(texts.length ? printfOutput(texts[0], texts.slice(1)) : '');
      else out.texts.push(flags.some((f) => f.includes('e') && !f.includes('E')) ? unescapeBackslashes(texts.join(' ')) : texts.join(' '));
    } else { out.unknown = true; out.texts.push(operands.map(argText).join(' ')); }
    return out;
  }
  if (p === 'cat') {
    if (last.heredoc !== null) out.texts.push(last.heredoc);
    for (const r of last.redirects) if (r.op === '<<<' && r.target) addWord(resolveWord(r.target, ctx, run));
    const ops = words.slice(1).filter((w) => !(w.text !== null && w.text.startsWith('-') && w.text.length > 1));
    if (ops.length === 0 && out.texts.length === 0) { out.unknown = true; return out; }
    for (const o of ops) { if (o.text === null) out.unknown = true; else out.files.push(o); }
    return out;
  }
  out.unknown = true;
  return out;
}

// An unknown program may run its argv or its stdin as a command (audit F1, F7).
function unknownProgram(prog: string, args: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  if (INERT_PROGRAMS.has(prog) || ctx.backstop) return;
  const rest = args.slice(1);
  scanArgvForCommands(rest, ctx, run, x);
  // stdin text: `echo 'npm publish' | at now`, `at now <<< 'npm publish'`, `batch <<EOF …`.
  const src = stdinSource(x, ctx, run);
  for (const t of src.texts) {
    if (prog === 'crontab') {
      // `* * * * * <command>` / `@reboot <command>`: the time fields are not words of a command.
      for (const line of t.split('\n')) {
        const body = line.trim();
        if (!body || body.startsWith('#') || /^[A-Za-z_][A-Za-z0-9_]*=/.test(body)) continue;
        evalShell(body.replace(/^(?:@\w+\s+|(?:\S+\s+){5})/, ''), childCtx(ctx), run);
      }
      continue;
    }
    evalShell(t, childCtx(ctx), run);
  }
  if (STDIN_EXEC_PROGRAMS.has(prog)) for (const f of src.files) scriptFile(f, [], ctx, run, null);
  // `at now < job.sh`
  for (const r of x.cmd.redirects) {
    if (r.op === '<' && r.target) { const a = resolveWord(r.target, ctx, run); if (a.text !== null && !a.glob) scriptFile(a, [], ctx, run, null); }
  }
}

// ---------------------------------------------------------------------------------------------
// tripwire and S-x

function tripwire(text: string, run: Run): void {
  const norm = String(text).toLowerCase().replace(/["'\\]/g, '');
  let any = false;
  for (const t of TRIPWIRE) {
    if (t.re.test(norm)) { hit(run, t.category, t.reason); any = true; }
  }
  if (!any && run.parse !== 'ok') run.flags.add('tripwire_clear');
}

function decoderCommand(cmd: ShellCommand, _run: Run, info: CmdInfo): boolean {
  const words = cmd.words.map((w) => w.text);
  let i = 0;
  while (i < words.length && ['sudo', 'env', 'command', 'nice', 'timeout', 'stdbuf'].includes(words[i])) i += 1;
  const prog = (words[i] || '').split('/').pop() || '';
  const rest = words.slice(i + 1);
  const hasShort = (letter: string) => rest.some((w) => /^-[A-Za-z]+$/.test(w) && w.includes(letter));
  if (['base64', 'base32', 'basenc', 'gbase64'].includes(prog)) return hasShort('d') || hasShort('D') || rest.includes('--decode');
  if (prog === 'xxd') return hasShort('r') || rest.includes('-revert');
  if (prog === 'openssl') return rest.includes('-d') || rest.includes('-base64') && rest.includes('-d') || rest[0] === 'base64' && rest.includes('-d');
  if (['uudecode', 'rev', 'tr', 'gunzip', 'zcat', 'bzcat', 'xzcat', 'unxz', 'unzstd', 'zstdcat', 'lzcat'].includes(prog)) return true;
  if (['gzip', 'bzip2', 'xz', 'zstd', 'lz4', 'brotli'].includes(prog)) return hasShort('d') || rest.includes('--decompress');
  if (prog === 'printf' || prog === 'echo' || prog === 'print') {
    const joined = rest.join(' ');
    if (info.ansiC) return true;
    if (prog === 'printf') return /\\x[0-9a-fA-F]|\\[0-7]{1,3}|\\u[0-9a-fA-F]|%b/.test(joined);
    return /\\x[0-9a-fA-F]|\\[0-7]{3}|\\u[0-9a-fA-F]/.test(joined) && (rest.includes('-e') || /^-[a-zA-Z]*e/.test(rest[0] || '') || prog === 'print');
  }
  if (INTERPRETERS.has(prog)) return INTERPRETER_DECODE.test(rest.join(' '));
  return false;
}

function substitutionsDecode(subs: string[], run: Run): boolean {
  for (const s of subs) {
    const parsed = shellParse.parseShell(s);
    const info: CmdInfo = { upstream: [], ansiC: /\$'[^']*\\(?:x[0-9a-fA-F]|[0-7]{2,3})/.test(s), subs: parsed.substitutions || [] };
    if (!parsed.ok) { if (/base64|xxd|rev\b|openssl|gunzip|\\x/.test(s)) return true; continue; }
    if (parsed.commands.some((c) => decoderCommand(c, run, info))) return true;
    if (substitutionsDecode(parsed.substitutions || [], run)) return true;
  }
  return false;
}

function fetcherCommand(cmd: ShellCommand): boolean {
  const words = cmd.words.map((w) => w.text);
  const prog = (words[0] || '').split('/').pop() || '';
  return ['curl', 'wget', 'fetch', 'http', 'https', 'iwr', 'invoke-webrequest', 'aria2c'].includes(prog);
}

// A shell or interpreter that reads its program from stdin: a heredoc, a here-string (audit F7), or a
// pipeline. The Q4 pass (`curl … | sh`, flag remote_exec) covers exactly a fetcher that is the stage
// directly upstream of the shell (audit F8). Any other stage is classified by what it emits.
function stdinExec(prog: string, rest: Arg[], x: Exec, ctx: Ctx, run: Run): void {
  const asShell = SHELLS.has(prog) || prog === 'sh';
  const code = (text: string) => { if (asShell) evalShell(text, childCtx(ctx), run); else scanInterpreterCode(text, run); };
  const source = stdinSource(x, ctx, run);
  const onCommand = x.cmd.heredoc !== null || x.cmd.redirects.some((r) => r.op === '<<<');
  if (onCommand) {
    for (const t of source.texts) code(t);
    if (source.unknown) { worseParse(run, 'dynamic'); hit(run, 'Sx', 'dynamic_stdin_code'); }
    return;
  }
  const upstream = x.info.upstream;
  if (upstream.length === 0) return;
  if (upstream.some((c) => decoderCommand(c, run, x.info))) { hit(run, 'Sx', 'decoded_pipe_exec'); return; }
  const direct = upstream[upstream.length - 1];
  if (upstream.length === 1 && fetcherCommand(direct) && !x.info.groupSource) { run.flags.add('remote_exec'); return; }
  if (x.info.groupSource) {
    // `{ curl …; echo …; } | sh`: the group's output is piped but its members are not visible.
    worseParse(run, 'dynamic');
    tripwire(run.topSource, run);
    hit(run, 'Sx', 'stdin_exec_group_source');
    return;
  }
  if (source.texts.length) {
    for (const t of source.texts) code(t);
    if (source.unknown) { worseParse(run, 'dynamic'); hit(run, 'Sx', 'dynamic_stdin_code'); }
    return;
  }
  if (source.files.length) {
    for (const f of source.files) {
      if (asShell) { scriptFile(f, rest, ctx, run, x); continue; }
      const found = (absCandidates(f.text as string, ctx, run) || []).map((p) => safeRead(run.env, p, LIMITS.maxScriptBytes));
      if (found.length === 0 || found.some((c) => c === null)) nameTripwire(path.posix.basename(f.text as string), run, 'script_unreadable');
      for (const c of found) if (c !== null) scanInterpreterCode(c, run);
    }
    if (source.unknown) { worseParse(run, 'dynamic'); hit(run, 'Sx', 'dynamic_stdin_code'); }
    return;
  }
  // The stage that feeds the interpreter is neither a fetcher directly upstream nor a literal: its
  // output is unknown code.
  worseParse(run, 'dynamic');
  tripwire(upstream.map((c) => c.words.map((w) => w.text.replace(/\u0000/g, '')).join(' ')).join(' | '), run);
  hit(run, 'Sx', 'stdin_exec_unknown_source');
}

// `$(…)` used as code: eval "$(…)", sh -c "$(…)", a program word that is a substitution, source <(…).
function checkSubstitutionExec(subs: string[], ctx: Ctx, run: Run): boolean {
  let classified = true;
  for (const s of subs) {
    const parsed = shellParse.parseShell(s, { depth: ctx.depth + 1 });
    if (!parsed.ok) { tripwire(s, run); classified = false; continue; }
    const info: CmdInfo = { upstream: [], ansiC: /\$'[^']*\\(?:x[0-9a-fA-F]|[0-7]{2,3})/.test(s), subs: parsed.substitutions };
    if (parsed.commands.some((c) => decoderCommand(c, run, info))) { hit(run, 'Sx', 'decoded_substitution_exec'); continue; }
    if (parsed.commands.some((c) => fetcherCommand(c))) { run.flags.add('remote_exec'); continue; }
    const simple = parsed.commands.length === 1 ? parsed.commands[0] : null;
    // Tools whose output is a block of shell variable assignments by design (`eval "$(ssh-agent -s)"`).
    if (simple && simple.words.length && EVAL_PRODUCERS.has((simple.words[0].text || '').split('/').pop() || '')
        && simple.words.slice(1).every((w) => !w.dynamic)) continue;
    if (simple && ['echo', 'printf'].includes(simple.words[0]?.text || '') && simple.words.slice(1).every((w) => !w.dynamic)) {
      evalShell(simple.words.slice(1).map((w) => w.text).filter((t) => !/^-[neE]+$/.test(t)).join(' '), childCtx(ctx), run);
      continue;
    }
    if (simple && simple.words[0]?.text === 'cat' && simple.words.length === 2 && !simple.words[1].dynamic) {
      scriptFile(litArg(simple.words[1].text), [], ctx, run, null);
      continue;
    }
    // The output of some other command is run as code: unknown code (audit F2).
    worseParse(run, 'dynamic');
    tripwire(s, run);
    hit(run, 'Sx', 'dynamic_substitution_exec');
    classified = false;
  }
  return classified;
}

// Environment access in interpreter code: a literal, non-secret name is fine; a secret-looking name,
// the whole environment, or a computed name dumps secrets (S4).
function interpreterEnvDump(code: string): boolean {
  const literal = [
    /\bos\.environ(?:\.get|\.pop|\.setdefault)?\s*[[(]\s*(['"])([A-Za-z0-9_]+)\1/g, /\bos\.getenv\s*\(\s*(['"])([A-Za-z0-9_]+)\1/g,
    /\bprocess\.env\.([A-Za-z_]\w*)()/g, /\bprocess\.env\s*\[\s*(['"])([A-Za-z0-9_]+)\1\s*\]/g,
    /\bENV\s*\[\s*(['"])([A-Za-z0-9_]+)\1\s*\]/g, /\bENV\.fetch\s*\(\s*(['"])([A-Za-z0-9_]+)\1/g, /\$ENV\s*\{\s*(['"]?)([A-Za-z0-9_]+)\1\s*\}/g,
    /\bENVIRON\s*\[\s*(['"])([A-Za-z0-9_]+)\1\s*\]/g, /\bSystem\.getenv\s*\(\s*(['"])([A-Za-z0-9_]+)\1/g, /\bgetenv\s*\(\s*(['"])([A-Za-z0-9_]+)\1/g,
  ];
  let rest = code;
  for (const re of literal) {
    rest = rest.replace(re, (_m, a: string, b: string) => {
      const name = b !== undefined && b !== '' ? b : a;
      return SECRET_VAR.test(name) ? '\u0004SECRETENV\u0004' : '';
    });
  }
  if (rest.includes('\u0004SECRETENV\u0004')) return true;
  // What is left: any other mention of the environment object is a dump or a computed lookup.
  return /\bos\.environ\b|\bprocess\.env\b|%ENV\b|\bENV\b(?!\s*(?:=|==)\s*['"])|\bENVIRON\b|\benviron\b\s*(?:[.)\],;:|]|$)|\$_ENV|\$_SERVER|\bSystem\.getenv\s*\(\s*\)|\bgetenv\s*\(\s*\)|\benvironment\.get_environment_variables|\bGet-ChildItem\s+env:/i.test(rest);
}

function scanInterpreterCode(code: string, run: Run): void {
  if (INTERPRETER_TREE_DELETE.test(code)) hit(run, 'S5', 'interpreter_tree_delete');
  if (interpreterEnvDump(code)) hit(run, 'S4', 'interpreter_env_dump');
  if (INTERPRETER_DECODE.test(code) && INTERPRETER_EXEC.test(code)) hit(run, 'Sx', 'interpreter_decoded_exec');
  tripwire(code, run);
}

// ---------------------------------------------------------------------------------------------
// paths

function expandTilde(text: string, run: Run): string | null {
  if (text === '~' || text.startsWith('~/')) return run.home + text.slice(1);
  const m = text.match(/^~([A-Za-z0-9._-]+)(\/.*)?$/);
  if (m) return `${(run.env.platform === 'darwin' ? '/Users/' : '/home/') + m[1]}${m[2] || ''}`;
  if (text.startsWith('~')) return null;
  return text;
}

function rewriteProc(abs: string, cwds: Array<string | null>): string[] {
  const m = abs.match(/^\/proc\/[^/]+\/(root|cwd)(\/.*)?$/);
  if (!m) return [abs];
  if (m[1] === 'root') return [path.posix.normalize(m[2] || '/')];
  return cwds.map((c) => (c ? path.posix.join(c, m[2] || '') : path.posix.join('/__unknown_cwd__', m[2] || '')));
}

// Absolute candidates for a literal path operand under every possible cwd. Unknown cwd gives a
// placeholder root so home-agnostic secret patterns still match by name.
function absCandidates(text: string, ctx: Ctx, run: Run): string[] | null {
  // Longer than PATH_MAX is not a path the OS can open or delete.
  if (text.length > LIMITS.maxPathChars) return null;
  const t = expandTilde(text, run);
  if (t === null) return null;
  const out: string[] = [];
  if (path.posix.isAbsolute(t)) out.push(path.posix.normalize(t));
  else for (const c of ctx.cwds) out.push(path.posix.resolve(c || '/__unknown_cwd__', t));
  return out.flatMap((p) => rewriteProc(p, ctx.cwds)).map((p) => (p.length > 1 ? p.replace(/\/+$/, '') : p));
}

function realCandidates(abs: string, run: Run, followFinal: boolean): string[] {
  const out = new Set<string>([abs]);
  if (followFinal) {
    const r = longestRealpath(abs, run);
    if (r) out.add(r);
  } else {
    const parent = longestRealpath(path.posix.dirname(abs), run);
    if (parent) out.add(path.posix.join(parent, path.posix.basename(abs)));
  }
  return [...out];
}

// Symlinks the command itself creates (`ln -s ~ x && rm -rf x/`, audit F9): the injected fs cannot
// see them yet, so path resolution applies them first. A link to an unknown target resolves to a
// path outside every workspace.
function applyLinks(abs: string, run: Run): string {
  if (run.links.size === 0) return abs;
  let cur = abs;
  for (let hop = 0; hop < 8; hop += 1) {
    const parts = cur.split('/');
    let prefix = '';
    let replaced = false;
    for (let k = 1; k < parts.length; k += 1) {
      prefix += `/${parts[k]}`;
      if (!run.links.has(prefix)) continue;
      const target = run.links.get(prefix);
      if (target === null || target === undefined) return '/__unknown_link__';
      const rest = parts.slice(k + 1).join('/');
      cur = rest ? path.posix.join(target, rest) : target;
      replaced = true;
      break;
    }
    if (!replaced) return cur;
  }
  return cur;
}

function recordLinks(prog: string, rest: Arg[], ctx: Ctx, run: Run): void {
  const flagged = (long: string) => rest.some((a) => a.text !== null && ((/^-[a-zA-Z]*s[a-zA-Z]*$/.test(a.text) && !a.text.startsWith('--')) || a.text === long));
  if (!((prog === 'ln' && flagged('--symbolic')) || (prog === 'cp' && flagged('--symbolic-link')))) return;
  const ops = nonOptions(rest, new Set(['-t', '--target-directory', '-S', '--suffix']));
  const tDir = targetDirFlag(rest);
  const sources = tDir ? ops : ops.slice(0, -1);
  const dest = tDir || (ops.length ? ops[ops.length - 1] : null);
  if (!dest) return;
  if (dest.text === null) { run.links.set('/__unknown_link_dest__', null); run.linksUnknown = true; return; }
  const destAbs = absCandidates(dest.text, ctx, run);
  if (!destAbs) { run.linksUnknown = true; return; }
  for (const d of destAbs) {
    for (const src of sources.length ? sources : [litArg(path.posix.basename(d))]) {
      const linkParent = path.posix.dirname(d);
      let target: string | null = null;
      if (src.text !== null) {
        const expanded = expandTilde(src.text, run);
        if (expanded !== null) target = path.posix.isAbsolute(expanded) ? path.posix.normalize(expanded) : path.posix.resolve(linkParent, expanded);
      }
      // The destination may be a directory: the link is then dest/<basename of the source>.
      run.links.set(d, target);
      if (src.text !== null) run.links.set(path.posix.join(d, path.posix.basename(src.text.replace(/\/+$/, ''))), target);
    }
  }
}

function longestRealpath(abs: string, run: Run): string | null {
  abs = applyLinks(abs, run);
  let cur = abs;
  const tail: string[] = [];
  for (let k = 0; k < 64; k += 1) {
    const r = safeRealpath(run.env, cur);
    if (r) return tail.length ? path.posix.join(r, ...tail.reverse()) : r;
    const parent = path.posix.dirname(cur);
    if (parent === cur) return null;
    tail.push(path.posix.basename(cur));
    cur = parent;
  }
  return null;
}

function isSecretPath(abs: string, run: Run): boolean {
  const p = run.fold ? abs.toLowerCase() : abs;
  const base = path.posix.basename(p);
  if (/^\.env(?:\.|$)/.test(base) && ENV_TEMPLATE_SUFFIX.test(base)) return false;
  if (KEY_EXTENSIONS.test(base)) {
    const segs = p.split('/');
    if (!segs.some((s) => KEY_FIXTURE_SEGMENTS.has(s))) return true;
  }
  const hits = run.secretRegexes.some((re) => re.test(p) || (run.fold && re.test(abs)));
  if (!hits) return false;
  if (/\/\.ssh\//.test(p) && SSH_PUBLIC.test(base)) return false;
  return true;
}

// Glob matching without backtracking blow-up. A glob built into a RegExp (`a*a*a*a*b` against a
// long name) takes exponential time, and the pattern comes from the agent's command line, so a
// classification could be made to hang. This matcher is O(pattern x text) in the worst case.
type GlobTok =
  | { k: 'lit'; c: string }
  | { k: 'any1' }
  | { k: 'star'; across: boolean }
  | { k: 'cls'; neg: boolean; set: Set<string>; ranges: Array<[string, string]> };

interface GlobOptions { dyn?: boolean; lookalike?: boolean; ci?: boolean; doubleStar?: boolean; stop?: string }

function compileGlob(pattern: string, opts: GlobOptions): { test(text: string): boolean } {
  const toks: GlobTok[] = [];
  const ci = Boolean(opts.ci);
  const stop = opts.stop === undefined ? '/' : opts.stop;
  const pushStar = (across: boolean) => {
    const last = toks[toks.length - 1];
    if (last && last.k === 'star') { last.across = last.across || across; return; }
    toks.push({ k: 'star', across });
  };
  for (let i = 0; i < pattern.length; i += 1) {
    const ch = pattern[i];
    if (opts.dyn && ch === DYN) { pushStar(true); continue; }
    if (ch === '*') {
      let j = i;
      while (pattern[j + 1] === '*') j += 1;
      pushStar(Boolean(opts.doubleStar) && j > i);
      i = j;
      continue;
    }
    if (ch === '?') { toks.push({ k: 'any1' }); continue; }
    if (ch === '[') {
      const end = pattern.indexOf(']', i + 2);
      if (end > 0) {
        let body = pattern.slice(i + 1, end);
        const neg = body.startsWith('!') || body.startsWith('^');
        if (neg) body = body.slice(1);
        const tok: GlobTok = { k: 'cls', neg, set: new Set<string>(), ranges: [] };
        for (let q = 0; q < body.length; q += 1) {
          if (body[q + 1] === '-' && q + 2 < body.length) { tok.ranges.push([ci ? body[q].toLowerCase() : body[q], ci ? body[q + 2].toLowerCase() : body[q + 2]]); q += 2; } else tok.set.add(ci ? body[q].toLowerCase() : body[q]);
        }
        toks.push(tok);
        i = end;
        continue;
      }
      toks.push({ k: 'lit', c: '[' });
      continue;
    }
    if (opts.lookalike && /[^\x00-\x7f]/.test(ch)) { toks.push({ k: 'any1' }); continue; }
    toks.push({ k: 'lit', c: ci ? ch.toLowerCase() : ch });
  }
  const one = (t: GlobTok, c: string): boolean => {
    if (t.k === 'lit') return t.c === c;
    if (t.k === 'any1') return c !== stop || stop === '';
    if (t.k === 'cls') {
      const hit1 = t.set.has(c) || t.ranges.some(([lo, hi]) => c >= lo && c <= hi);
      return t.neg ? !hit1 : hit1;
    }
    return false;
  };
  return {
    test(text: string): boolean {
      const str = ci ? text.toLowerCase() : text;
      let p = 0;
      let s = 0;
      let starP = -1;
      let starS = 0;
      while (s < str.length) {
        const t = toks[p];
        if (t && t.k !== 'star' && one(t, str[s])) { p += 1; s += 1; continue; }
        if (t && t.k === 'star') { starP = p; starS = s; p += 1; continue; }
        if (starP >= 0) {
          const star = toks[starP] as { k: 'star'; across: boolean };
          // The star takes one more character; one that cannot cross the separator ends the match.
          if (!star.across && str[starS] === stop && stop !== '') return false;
          starS += 1;
          s = starS;
          p = starP + 1;
          continue;
        }
        return false;
      }
      while (p < toks.length && toks[p].k === 'star') p += 1;
      return p === toks.length;
    },
  };
}

// Matches a glob or partly dynamic operand against concrete secret examples.
function patternToRegex(pattern: string, lookalike: boolean): { test(text: string): boolean } {
  return compileGlob(pattern, { dyn: true, lookalike, ci: true });
}

function sampleMatch(a: Arg, ctx: Ctx, run: Run, samples: string[]): boolean {
  const raw = a.pattern;
  const lookalike = a.nonAscii;
  const expanded = raw.startsWith('~') ? (expandTilde(raw, run) ?? raw) : raw;
  const cands: string[] = [];
  if (expanded.startsWith('/') || expanded.startsWith(DYN)) cands.push(expanded);
  if (!expanded.startsWith('/')) for (const c of ctx.cwds) cands.push(`${(c || '/__unknown_cwd__').replace(/\/$/, '')}/${expanded}`);
  for (const cand of cands) {
    const re = patternToRegex(cand.replace(/\/\.\//g, '/'), lookalike);
    if (samples.some((s) => re.test(s) && isSecretPath(s, run))) return true;
  }
  return false;
}

function cwdsList(ctx: Ctx): string[] { return ctx.cwds.map((c) => c || '/__unknown_cwd__'); }

// S4: a secret path as an operand. Returns true on a stop.
function checkSecretOperand(a: Arg, ctx: Ctx, run: Run, reason: string): boolean {
  if (a.text === null && a.alts && a.alts.length) {
    for (const v of a.alts) if (checkSecretOperand({ ...litArg(v), glob: a.glob, word: a.word }, ctx, run, reason)) return true;
    return false;
  }
  for (const text of operandPaths(a)) {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) continue;
    if (a.text === null || a.glob || a.nonAscii) {
      const probe: Arg = a.text === null ? a : { ...a, pattern: text };
      if (/[A-Za-z0-9._~/-]/.test(probe.pattern.replace(new RegExp(DYN, 'g'), '')) && sampleMatch(probe, ctx, run, secretSamples(run.home, cwdsList(ctx)))) {
        return hit(run, 'S4', `${reason}_secret_pattern`);
      }
      if (a.text === null) continue;
    }
    const abs = absCandidates(text, ctx, run);
    if (!abs) continue;
    for (const p of abs) for (const r of realCandidates(p, run, true)) if (isSecretPath(r, run)) return hit(run, 'S4', `${reason}_secret_path`);
  }
  return false;
}

// Path-ish parts of an operand: the value after `--opt=`, after `@` (curl -d @file) and after `:`
// for git object paths (HEAD:.env).
function operandPaths(a: Arg): string[] {
  // Only the head of a long argument can be a path (`--opt=<path>`, `@<path>`, `REV:<path>`).
  const t = (a.text !== null ? a.text : a.pattern).slice(0, LIMITS.maxPathChars);
  const out = [t];
  const eq = t.match(/^--?[A-Za-z0-9-]+=(.+)$/);
  if (eq) out.push(eq[1]);
  const at = t.match(/(?:^|=)@(.+)$/);
  if (at) out.push(at[1]);
  const colon = t.match(/^[^/:]+:(.+)$/);
  if (colon && !/^[a-z]+:\/\//i.test(t)) out.push(colon[1]);
  return out.map((p) => (a.text === null ? p : p)).filter(Boolean);
}

// S0: a write, move or delete on a protected path. `tree` also stops on an ancestor of a protected
// anchor (rm -rf ~/.claude, mv .claude x).
function checkProtectedWrite(a: Arg, ctx: Ctx, run: Run, reason: string, tree: boolean): boolean {
  if (a.text === null) {
    // Partly dynamic target: stop when its literal part can only be a protected location.
    const lit = a.pattern.replace(new RegExp(DYN, 'g'), '');
    if (/\.marrow|\.claude|\.codex|\.cursor|\.gemini|\.bashrc|\.zshrc|\.profile|hooks\.json|settings\.json|\.mcp\.json/.test(lit)) return hit(run, 'S0', `${reason}_protected_dynamic`);
    return false;
  }
  const abs = absCandidates(a.text, ctx, run);
  if (!abs) return false;
  for (const p of abs) {
    for (const r of realCandidates(p, run, false)) {
      const probe = run.fold ? r.toLowerCase() : r;
      if (run.isProtected(probe)) return hit(run, 'S0', `${reason}_protected_path`);
      if (tree && run.protectedAnchors.some((anchor) => isAncestorOrSelf(probe, anchor))) return hit(run, 'S0', `${reason}_protected_ancestor`);
    }
  }
  return false;
}

function markWritten(a: Arg, ctx: Ctx): void {
  if (a.text === null) return;
  for (const c of ctx.cwds) ctx.written.add(path.posix.resolve(c || '/__unknown_cwd__', a.text));
}

// ---------------------------------------------------------------------------------------------
// S5 workspace boundary

function strictChildOf(p: string, roots: string[]): boolean {
  return roots.some((r) => p !== r && p.startsWith(`${r}/`));
}

function isSafeDeleteTarget(p: string, run: Run): boolean {
  const roots = [...run.wsRoots, ...run.tmpRoots];
  if (p === '/' || p === run.home) return false;
  if (run.wsRoots.some((w) => isAncestorOrSelf(p, w))) return false;
  if (run.tmpRoots.includes(p)) return false;
  return strictChildOf(p, roots);
}

// kind: 'tree' = the target and everything under it; 'children' = entries under the target dir.
function checkDeleteTarget(a: Arg, ctx: Ctx, run: Run, reason: string, kind: 'tree' | 'children' | 'find'): boolean {
  if (ctx.remote) return hit(run, 'S5', `${reason}_remote`);
  if (a.text === null && a.alts && a.alts.length) {
    for (const v of a.alts) if (checkDeleteTarget({ ...litArg(v), glob: a.glob }, ctx, run, reason, kind)) return true;
    return false;
  }
  if (a.text === null) return hit(run, 'S5', `${reason}_dynamic_target`);
  if (a.nonAscii) return hit(run, 'S5', `${reason}_non_ascii_target`);
  // A symlink whose target the mapper could not resolve was made earlier in this command line.
  if (run.linksUnknown) return hit(run, 'S5', `${reason}_after_unknown_symlink`);
  let text = a.text;
  let effKind: 'tree' | 'children' | 'find' = kind;
  // A glob whose match is followed as a directory (`./l*/`, `./l*/x`) can reach a symlink to
  // anywhere (audit F9): expand it against the injected fs and judge each match, or stop.
  if (a.glob && globFollowsLinks(a.text)) {
    const matches = expandGlob(a.text, ctx, run);
    if (matches === null) return hit(run, 'S5', `${reason}_glob_unresolved`);
    for (const m of matches) {
      if (checkDeleteTarget({ ...litArg(m), glob: false }, ctx, run, reason, kind)) return true;
    }
    return false;
  }
  if (a.glob) {
    const segs = text.split('/');
    const firstGlob = segs.findIndex((s) => /[*?[]/.test(s));
    const prefix = segs.slice(0, firstGlob).join('/') || (text.startsWith('/') ? '/' : '.');
    const lastIsBroad = firstGlob === segs.length - 1 && /^[*?.[\]!^-]*$/.test(segs[firstGlob]);
    text = prefix;
    effKind = lastIsBroad ? 'tree' : 'children';
  }
  const abs = absCandidates(text, ctx, run);
  if (!abs) return hit(run, 'S5', `${reason}_unresolved_home`);
  const follow = /\/\.?$|\/\*$/.test(a.text) || effKind === 'children';
  for (const p of abs) {
    if (p.startsWith('/__unknown_cwd__')) return hit(run, 'S5', `${reason}_unknown_cwd`);
    for (const r of realCandidates(p, run, follow)) {
      const ok = effKind === 'children'
        ? (r !== '/' && r !== run.home && (isSafeDeleteTarget(r, run) || run.wsRoots.includes(r) || run.tmpRoots.includes(r)))
        : effKind === 'find'
          ? (r !== '/' && r !== run.home && (isSafeDeleteTarget(r, run) || run.wsRoots.includes(r)))
          : isSafeDeleteTarget(r, run);
      if (!ok) return hit(run, 'S5', `${reason}_outside_workspace`);
    }
  }
  return false;
}

function globChars(s: string): boolean { return /[*?[]/.test(s); }

// A glob component is followed as a directory when it is not the last component, or when the
// pattern ends in `/` (a trailing slash follows a symlink).
function globFollowsLinks(text: string): boolean {
  const comps = text.split('/');
  let last = comps.length - 1;
  while (last > 0 && comps[last] === '') last -= 1;
  const trailing = text.endsWith('/') || /\/\.$/.test(text);
  for (let i = 0; i < comps.length; i += 1) {
    if (!globChars(comps[i])) continue;
    if (i < last) return true;
    if (i === last && trailing) return true;
  }
  return false;
}

function globComponentRegex(comp: string): { test(text: string): boolean } {
  return compileGlob(comp, { ci: false });
}

// Concrete matches of a glob under every possible cwd, or null when they cannot be listed.
function expandGlob(text: string, ctx: Ctx, run: Run): string[] | null {
  const readdir = run.env.fs.readdir;
  if (typeof readdir !== 'function') return null;
  const expanded = expandTilde(text, run);
  if (expanded === null) return null;
  const trailing = /\/+$/.test(expanded);
  const comps = expanded.split('/').filter((c, i) => c !== '' || i === 0);
  let paths: string[];
  if (path.posix.isAbsolute(expanded)) paths = [''];
  else {
    if (ctx.cwds.some((c) => c === null)) return null;
    paths = ctx.cwds.map((c) => (c as string).replace(/\/$/, ''));
  }
  for (const comp of comps) {
    if (comp === '') continue;
    if (!globChars(comp)) { paths = paths.map((p) => `${p}/${comp}`); continue; }
    const re = globComponentRegex(comp);
    const next: string[] = [];
    for (const p of paths) {
      const dir = p || '/';
      const before = run.fsState.errored;
      const names = run.env.fs.readdir ? run.env.fs.readdir(dir) : null;
      if (names === null) {
        if (!before && run.fsState.errored) return null;
        if (safeRealpath(run.env, dir) === null && !run.fsState.errored) continue; // no such directory: no matches
        return null;
      }
      for (const n of names) {
        if (n.startsWith('.') && !comp.startsWith('.')) continue;
        if (re.test(n)) next.push(`${p}/${n}`);
        if (next.length > LIMITS.maxGlobMatches) return null;
      }
    }
    paths = next;
  }
  return [...new Set(paths)].map((p) => (trailing ? `${p}/` : p));
}

function checkTreeDeletes(targets: Arg[], ctx: Ctx, run: Run, reason: string): void {
  for (const t of targets) {
    checkProtectedWrite(t, ctx, run, reason, true);
    checkDeleteTarget(t, ctx, run, reason, 'tree');
  }
}

// ---------------------------------------------------------------------------------------------
// generic operand checks (S4 on every program, S0 on write programs)

const SECRET_DIRS = ['.ssh', '.aws', '.config/gcloud', '.azure', '.kube', '.docker', '.config/gh', '.config/op', '.gnupg', '.marrow'];

// True when `text` names a credential directory, or a directory that holds one (home itself).
function isSecretDirOrAncestor(text: string, ctx: Ctx, run: Run): boolean {
  const abs = absCandidates(text, ctx, run);
  if (!abs) return false;
  const dirs = SECRET_DIRS.map((d) => path.posix.join(run.home, d));
  return abs.some((p) => realCandidates(p, run, true).some((r) => dirs.some((d) => isAncestorOrSelf(r, d) || isAncestorOrSelf(d, r))));
}

// `cat $(echo ~/.ssh/id_rsa)`, `cat $(ls ~/.ssh/id_*)`, `cat $(find ~/.ssh -name 'id_*')`: the path
// is produced by a substitution that the reader then opens.
function substitutionOperandCheck(prog: string, rest: Arg[], ctx: Ctx, run: Run, subs: string[]): void {
  if (S4_EXEMPT_PROGRAMS.has(prog) || prog === 'git' || !rest.some((a) => a.word && a.word.substitution)) return;
  for (const sub of subs) {
    const parsedSub = shellParse.parseShell(sub, { depth: ctx.depth + 1 });
    if (!parsedSub.ok) continue;
    for (const c of parsedSub.commands) {
      const w0 = (c.words[0]?.text || '').split('/').pop() || '';
      if (!['echo', 'printf', 'ls', 'find', 'realpath', 'readlink', 'cat', 'head', 'tail', 'grep', 'rg', 'locate', 'dirname', 'wc'].includes(w0)) continue;
      for (const w of c.words.slice(1)) {
        const a = resolveWord(w, ctx, run);
        if (checkSecretOperand(a, ctx, run, 'operand_via_substitution')) return;
        if (w0 === 'find' && a.text !== null && !a.text.startsWith('-') && isSecretDirOrAncestor(a.text, ctx, run)) { hit(run, 'S4', 'operand_via_substitution_secret_dir'); return; }
      }
    }
  }
}

// grep -r, rg, ag and ack over a credential directory, or over a directory that holds one, print
// matches from the credential files inside it.
function recursiveSecretDirRead(prog: string, rest: Arg[], ctx: Ctx, run: Run): void {
  const searchers = new Set(['grep', 'egrep', 'fgrep', 'zgrep', 'rg', 'ag', 'ack']);
  if (!searchers.has(prog)) return;
  const recursive = prog === 'rg' || prog === 'ag' || prog === 'ack' || rest.some((a) => a.text !== null && (/^-[a-zA-Z]*[rR][a-zA-Z]*$/.test(a.text) || a.text === '--recursive' || a.text === '--dereference-recursive'));
  if (!recursive) return;
  for (const a of nonOptions(rest)) {
    if (a.text === null || !(a.text.includes('/') || a.text === '.' || a.text === '..' || a.text.startsWith('~'))) continue;
    if (isSecretDirOrAncestor(a.text, ctx, run)) { hit(run, 'S4', 'recursive_search_secret_dir'); return; }
  }
}

function genericOperandChecks(prog: string, args: Arg[], ctx: Ctx, run: Run, subs: string[] = []): void {
  const rest = args.slice(1);
  substitutionOperandCheck(prog, rest, ctx, run, subs);
  recursiveSecretDirRead(prog, rest, ctx, run);
  if (!S4_EXEMPT_PROGRAMS.has(prog) && prog !== 'git') {
    let skipNext = false;
    for (let i = 0; i < rest.length; i += 1) {
      const a = rest[i];
      if (skipNext) { skipNext = false; continue; }
      // ssh-style identity flags use the key without printing it.
      if (['scp', 'rsync', 'ssh-copy-id', 'sshfs'].includes(prog) && a.text === '-i') { skipNext = true; continue; }
      checkSecretOperand(a, ctx, run, 'operand');
    }
  }
  // Copying or archiving a directory that holds credential files (cp -r ~/.ssh, tar ~) is a read too.
  if (COPY_PROGRAMS.has(prog)) {
    const secretDirs = ['.ssh', '.aws', '.config/gcloud', '.azure', '.kube', '.docker', '.config/gh', '.config/op', '.gnupg', '.marrow'].map((d) => path.posix.join(run.home, d));
    for (const a of nonOptions(rest)) {
      if (a.text === null) continue;
      const abs = absCandidates(a.text, ctx, run);
      if (!abs) continue;
      if (abs.some((p) => realCandidates(p, run, true).some((r) => secretDirs.some((d) => isAncestorOrSelf(r, d))))) { hit(run, 'S4', 'copy_secret_directory'); break; }
    }
  }
  const writes = writeTargets(prog, rest);
  for (const { arg, tree } of writes) {
    checkProtectedWrite(arg, ctx, run, `${prog}_write`, tree);
    markWritten(arg, ctx);
  }
  recordLinks(prog, rest, ctx, run);
}

const COPY_PROGRAMS = new Set(['cp', 'scp', 'rsync', 'tar', 'zip', '7z', '7za', 'rclone', 'gtar', 'bsdtar', 'ditto']);

function nonOptions(rest: Arg[], valueFlags: Set<string> = new Set()): Arg[] {
  const out: Arg[] = [];
  let after = false;
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (!after && a.text === '--') { after = true; continue; }
    if (!after && isOpt(a)) { if (a.text && valueFlags.has(a.text)) i += 1; continue; }
    out.push(a);
  }
  return out;
}

function writeTargets(prog: string, rest: Arg[]): Array<{ arg: Arg; tree: boolean }> {
  const ops = nonOptions(rest, new Set(['-t', '--target-directory', '-m', '--mode', '-o', '-g', '-S', '--suffix', '-s', '--size', '-r', '--reference']));
  const all = (tree: boolean) => ops.map((arg) => ({ arg, tree }));
  switch (prog) {
    case 'tee': case 'touch': case 'truncate': case 'unlink': case 'shred': return all(false);
    case 'rm': case 'rmdir': return all(true);
    case 'chmod': case 'chown': case 'chgrp': case 'chattr': return ops.slice(1).map((arg) => ({ arg, tree: false }));
    case 'mv': {
      const dest = ops.length >= 2 ? ops[ops.length - 1] : null;
      const into = dest && dest.text !== null ? ops.slice(0, -1).filter((s) => s.text !== null).map((s) => ({ arg: litArg(`${(dest.text as string).replace(/\/+$/, '')}/${path.posix.basename(s.text as string)}`), tree: false })) : [];
      return [...all(true), ...into];
    }
    case 'cp': case 'install': case 'ln': case 'rsync': case 'scp': {
      const t = targetDirFlag(rest);
      const dest = t || (ops.length >= 2 ? ops[ops.length - 1] : null);
      if (!dest) return [];
      const sources = t ? ops : ops.slice(0, -1);
      // Into a directory: the file lands at dest/<basename of each source>.
      const into = dest.text === null ? [] : sources.filter((s) => s.text !== null).map((s) => ({ arg: litArg(`${(dest.text as string).replace(/\/+$/, '')}/${path.posix.basename(s.text as string)}`), tree: false }));
      return [{ arg: dest, tree: false }, ...into];
    }
    case 'sed': case 'gsed': {
      if (!rest.some((a) => a.text !== null && (/^-[a-zA-Z]*i/.test(a.text) || a.text.startsWith('--in-place')))) return [];
      const hasScript = rest.some((a) => a.text === '-e' || a.text === '-f' || a.text === '--expression');
      return (hasScript ? ops : ops.slice(1)).map((arg) => ({ arg, tree: false }));
    }
    case 'perl': {
      if (!rest.some((a) => a.text !== null && /^-[a-zA-Z]*i/.test(a.text))) return [];
      const idx = rest.findIndex((a) => a.text !== null && /^-[a-zA-Z]*e$/.test(a.text));
      return (idx >= 0 ? nonOptions(rest.slice(idx + 2)) : ops.slice(1)).map((arg) => ({ arg, tree: false }));
    }
    case 'curl': case 'wget': {
      const out: Array<{ arg: Arg; tree: boolean }> = [];
      for (let i = 0; i < rest.length; i += 1) {
        const t = rest[i].text || '';
        if ((t === '-o' || t === '--output' || t === '-O' && prog === 'wget' || t === '--output-document' || t === '-P' || t === '--directory-prefix') && rest[i + 1]) out.push({ arg: rest[i + 1], tree: false });
        const eq = t.match(/^--(?:output|output-document|directory-prefix)=(.+)$/);
        if (eq) out.push({ arg: litArg(eq[1]), tree: false });
      }
      return out;
    }
    case 'dd': return rest.filter((a) => a.text && a.text.startsWith('of=')).map((a) => ({ arg: litArg((a.text || '').slice(3)), tree: false }));
    case 'unzip': {
      const i = rest.findIndex((a) => a.text === '-d');
      return i >= 0 && rest[i + 1] ? [{ arg: rest[i + 1], tree: true }] : [];
    }
    case 'tar': {
      const i = rest.findIndex((a) => a.text === '-C' || a.text === '--directory');
      const extracting = rest.some((a) => a.text !== null && (/^-?[a-zA-Z]*x/.test(a.text) && !a.text.startsWith('--') || a.text === '--extract'));
      return extracting && i >= 0 && rest[i + 1] ? [{ arg: rest[i + 1], tree: true }] : [];
    }
    default: return [];
  }
}

function targetDirFlag(rest: Arg[]): Arg | null {
  for (let i = 0; i < rest.length; i += 1) {
    const t = rest[i].text;
    if ((t === '-t' || t === '--target-directory') && rest[i + 1]) return rest[i + 1];
    if (t && t.startsWith('--target-directory=')) return litArg(t.slice('--target-directory='.length));
  }
  return null;
}

// ---------------------------------------------------------------------------------------------
// builtins

function changeDir(rest: Arg[], ctx: Ctx, run: Run, subshell: boolean): void {
  const ops = nonOptions(rest);
  const target = ops[0];
  if (!target) { ctx.cwds = subshell ? [...new Set([...ctx.cwds, run.home])] : [run.home]; return; }
  if (target.text === null || target.text === '-' || target.glob) { ctx.cwds = [...new Set([...ctx.cwds, null])]; return; }
  const next: Array<string | null> = [];
  for (const c of ctx.cwds) {
    const t = expandTilde(target.text, run);
    if (t === null) { next.push(null); continue; }
    if (path.posix.isAbsolute(t)) next.push(path.posix.normalize(t));
    else next.push(c ? path.posix.resolve(c, t) : null);
  }
  // A cd that may fail (missing dir) or runs in a subshell leaves the old cwd possible too.
  const certain = !subshell && next.every((n) => n !== null && safeRealpath(run.env, n) !== null);
  ctx.cwds = certain ? [...new Set(next)] : [...new Set([...ctx.cwds, ...next])];
}

function defineAliases(rest: Arg[], ctx: Ctx, run: Run): void {
  for (const a of rest) {
    if (a.text === null) { worseParse(run, 'dynamic'); tripwire(a.pattern, run); continue; }
    const eq = a.text.indexOf('=');
    if (eq <= 0) continue;
    const name = a.text.slice(0, eq);
    const value = a.text.slice(eq + 1);
    ctx.aliases.set(name, value);
    // Definitions are classified as if executed (spec A10).
    evalShell(value, childCtx(ctx), run);
  }
}

function declareLike(prog: string, rest: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  const opts = rest.filter((a) => isOpt(a)).map((a) => a.text || '');
  const names = rest.filter((a) => !isOpt(a));
  if (names.length === 0) {
    if (prog === 'export' && (opts.length === 0 || opts.some((o) => o.includes('p')))) { hit(run, 'S4', 'env_dump_export'); return; }
    if ((prog === 'declare' || prog === 'typeset') && (opts.length === 0 || opts.some((o) => /[xp]/.test(o)))) { hit(run, 'S4', 'env_dump_declare'); return; }
    if (prog === 'readonly' && (opts.length === 0 || opts.some((o) => o.includes('p')))) { hit(run, 'S4', 'env_dump_readonly'); return; }
    return;
  }
  if ((prog === 'declare' || prog === 'typeset') && opts.some((o) => o.includes('p'))) {
    for (const n of names) if (n.text === null || SECRET_VAR.test(n.text)) { hit(run, 'S4', 'env_dump_declare_secret'); return; }
  }
  for (const n of names) {
    if (n.text === null) { worseParse(run, 'dynamic'); continue; }
    const eq = n.text.indexOf('=');
    const name = eq >= 0 ? n.text.slice(0, eq) : n.text;
    if (name === 'IFS' && eq >= 0) ctx.ifs = n.text.slice(eq + 1);
    if (eq >= 0) ctx.vars.set(name, [n.text.slice(eq + 1)]);
    else if (n.word && n.word.dynamic) ctx.vars.set(name, null);
    if (prog === 'export' || opts.some((o) => o.includes('x'))) ctx.exported.add(name);
  }
  void x;
}

function setBuiltin(rest: Arg[], run: Run): void {
  if (rest.length === 0) hit(run, 'S4', 'env_dump_set');
}

function printenv(rest: Arg[], run: Run): void {
  const names = rest.filter((a) => !isOpt(a));
  if (names.length === 0) { hit(run, 'S4', 'env_dump_printenv'); return; }
  for (const n of names) if (n.text === null || SECRET_VAR.test(n.text)) { hit(run, 'S4', 'env_dump_printenv_secret'); return; }
}

function echoLike(args: Arg[], run: Run, x: Exec): void {
  for (const a of args.slice(1)) {
    if (!a.word) continue;
    for (const slot of a.word.slots) {
      if (slot.type !== 'var' || !slot.name) continue;
      const name = slot.name.replace(/^!/, '');
      if (slot.name.startsWith('!') || SECRET_VAR.test(name.replace(/[^A-Za-z0-9_].*$/, ''))) { hit(run, 'S4', 'echo_secret_var'); return; }
    }
  }
  void x;
}

function evalBuiltin(rest: Arg[], ctx: Ctx, run: Run, subs: string[]): void {
  if (rest.some((a) => a.word && a.word.substitution)) {
    const classified = checkSubstitutionExec(subs, ctx, run);
    // `eval "$(ssh-agent -s)"`: every substitution is a known producer, fetched or literal text.
    if (classified && rest.every((a) => isPureSubstitution(a) || a.text !== null)) {
      const literal = rest.filter((a) => a.text !== null);
      if (literal.length) evalShell(literal.map((a) => a.text).join(' '), childCtx(ctx), run);
      return;
    }
  }
  if (rest.every((a) => a.text !== null)) { evalShell(rest.map((a) => a.text).join(' '), childCtx(ctx), run); return; }
  if (rest.every((a) => a.alts !== null)) {
    for (const a of rest) for (const v of a.alts || []) evalShell(v, childCtx(ctx), run);
    return;
  }
  worseParse(run, 'dynamic');
  if (rest.some((a) => a.word && a.word.variables.some((v) => ctx.decodedVars.has(v)))) hit(run, 'Sx', 'decoded_variable_eval');
  // `eval $x` with an unresolved value runs unknown code (audit F2).
  const joined: Arg = { text: null, alts: null, pattern: rest.map((a) => (a.text !== null ? a.text : a.pattern)).join(' '), glob: false, word: null, nonAscii: false };
  dynamicCode(joined, ctx, run, 'dynamic_eval');
}

function sourceFile(rest: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  const target = rest[0];
  if (!target) return;
  if (target.word && target.word.substitution) { checkSubstitutionExec(x.info.subs, ctx, run); return; }
  if (target.text !== null && (target.text === '-' || STDIN_PATHS.has(target.text))) { stdinExec('sh', rest.slice(1), x, ctx, run); return; }
  scriptFile(target, rest.slice(1), ctx, run, x);
}

function envWrapper(rest: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  let i = 0;
  let clean = false;
  const extra = new Map(x.env);
  let cwds = ctx.cwds;
  while (i < rest.length) {
    const t = rest[i].text;
    if (t === null) {
      // `env PATH=$PATH node -v`: an assignment whose value is dynamic is still an assignment.
      const m = /^([A-Za-z_][A-Za-z0-9_]*)=/.exec(rest[i].pattern);
      if (m) { extra.set(m[1], null); i += 1; continue; }
      break;
    }
    if (t === '-i' || t === '--ignore-environment' || t === '-') { clean = true; i += 1; continue; }
    if (t === '-u' || t === '--unset' || t === '-C' || t === '--chdir') {
      if ((t === '-C' || t === '--chdir') && rest[i + 1]?.text) cwds = [path.posix.resolve(ctx.cwds[0] || '/__unknown_cwd__', rest[i + 1].text as string)];
      i += 2; continue;
    }
    if (t === '-S' || t === '--split-string') {
      const s = rest[i + 1];
      if (s && s.text !== null) evalShell([s.text, ...rest.slice(i + 2).map((a) => (a.text !== null ? shellQuote(a.text) : '"$__d"'))].join(' '), childCtx(ctx), run);
      else tripwire(rest.map(argText).join(' '), run);
      return;
    }
    if (t === '--') { i += 1; break; }
    if (t.startsWith('-')) { i += 1; continue; }
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) { const eq = t.indexOf('='); extra.set(t.slice(0, eq), [t.slice(eq + 1)]); i += 1; continue; }
    break;
  }
  if (i >= rest.length) {
    if (!clean) hit(run, 'S4', 'env_dump_env');
    return;
  }
  dispatch(rest.slice(i), { ...ctx, cwds }, run, { ...x, env: extra });
}

function privilegeWrapper(prog: string, rest: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  const valueFlags = new Set(['-u', '-g', '-C', '-D', '-h', '-p', '-r', '-t', '-U', '-T', '--user', '--group', '--chdir', '--prompt', '--host', '--close-from']);
  let i = 0;
  let shell = false;
  while (i < rest.length) {
    const t = rest[i].text;
    if (t === null) {
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(rest[i].pattern)) { i += 1; continue; }
      break;
    }
    if (t === '--') { i += 1; break; }
    if (valueFlags.has(t)) { i += 2; continue; }
    if (t.startsWith('-')) { if (/^-[a-zA-Z]*[si]/.test(t) && !t.startsWith('--')) shell = true; i += 1; continue; }
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) { i += 1; continue; }
    break;
  }
  if (i >= rest.length) { if (shell) stdinExec('sh', [], x, ctx, run); return; }
  void prog;
  dispatch(rest.slice(i), ctx, run, x);
}

function suWrapper(rest: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  for (let i = 0; i < rest.length; i += 1) {
    const t = rest[i].text;
    if ((t === '-c' || t === '--command') && rest[i + 1]) return shellString(rest[i + 1], ctx, run, x.info.subs);
    if (t && t.startsWith('--command=')) return shellString(litArg(t.slice(10)), ctx, run, x.info.subs);
  }
  if (x.info.upstream.length || x.cmd.heredoc !== null || x.cmd.redirects.some((r) => r.op === '<<<')) stdinExec('sh', [], x, ctx, run);
}

function shellString(a: Arg, ctx: Ctx, run: Run, subs: string[]): void {
  if (a.text !== null) { evalShell(a.text, childCtx(ctx), run); return; }
  if (a.word && a.word.substitution) {
    const classified = checkSubstitutionExec(subs, ctx, run);
    if (classified && isPureSubstitution(a)) return;
  }
  if (a.alts) { for (const v of a.alts) evalShell(v, childCtx(ctx), run); return; }
  dynamicCode(a, ctx, run, 'dynamic_shell_code');
}

// Code text with unresolved parts (audit F2). The literal text is classified with each unknown piece
// as an opaque variable (so `cd $DIR && npm test` is read, `$CMD publish` has a dynamic command word).
// With nothing literal left (`sh -c "$CMD"`) the code is unknowable and the answer is stop.
function dynamicCode(a: Arg, ctx: Ctx, run: Run, reason: string): void {
  worseParse(run, 'dynamic');
  const literal = a.pattern.replace(new RegExp(DYN, 'g'), '');
  if (literal.trim() === '') {
    tripwire(run.topSource, run);
    hit(run, 'Sx', reason);
    return;
  }
  tripwire(literal, run);
  evalShell(a.pattern.replace(new RegExp(DYN, 'g'), '${__marrow_dynamic}'), childCtx(ctx), run);
}

function simpleWrapper(prog: string, rest: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  let i = 0;
  const valueFlags: Record<string, string[]> = {
    timeout: ['-s', '--signal', '-k', '--kill-after'], nice: ['-n', '--adjustment'], ionice: ['-c', '-n', '-p', '-P', '-u', '--class', '--classdata'],
    stdbuf: ['-i', '-o', '-e', '--input', '--output', '--error'], time: ['-f', '-o', '--format', '--output'], exec: ['-a'],
    caffeinate: ['-t', '-w'], taskset: [], chrt: [], retry: ['-t', '--times', '-d', '--delay', '--until'], flock: ['-w', '--timeout', '-E', '--conflict-exit-code'],
  };
  const vf = new Set(valueFlags[prog] || []);
  if (prog === 'command' && rest.some((a) => a.text === '-v' || a.text === '-V')) return;
  while (i < rest.length) {
    const t = rest[i].text;
    if (t === null) break;
    if (t === '--') { i += 1; break; }
    if (vf.has(t)) { i += 2; continue; }
    if (t.startsWith('-')) { i += 1; continue; }
    break;
  }
  if (prog === 'timeout' && i < rest.length) i += 1; // duration
  if (prog === 'chrt' && i < rest.length && /^\d+$/.test(rest[i].text || '')) i += 1;
  if (prog === 'taskset' && i < rest.length) i += 1; // mask
  if (prog === 'flock' && i < rest.length) {
    i += 1; // lock file
    const c = rest.findIndex((a) => a.text === '-c' || a.text === '--command');
    if (c >= 0 && rest[c + 1]) return shellString(rest[c + 1], ctx, run, x.info.subs);
  }
  if (i >= rest.length) return;
  dispatch(rest.slice(i), ctx, run, x);
}

function xargsWrapper(prog: string, rest: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  // Options with a separate value. GNU -i, -l and -e take an attached optional value only.
  const vf = new Set(['-d', '--delimiter', '-E', '--eof', '-I', '-L', '-n', '--max-args', '-P', '--max-procs', '-s', '--max-chars', '-a',
    '--arg-file', '--max-lines', '-j', '--jobs', '--replace-str', '--sshlogin', '-S', '--results', '--joblog', '--tagstring', '-N']);
  let replacement: string | null = '{}';
  let i = 0;
  while (i < rest.length) {
    const t = rest[i].text;
    if (t === null) break;
    if (t === '--') { i += 1; break; }
    if (t === '-I' && rest[i + 1]?.text) replacement = rest[i + 1].text as string;
    else if (/^-I.+/.test(t) && !t.startsWith('--')) replacement = t.slice(2);
    else if (/^--replace(?:=(.+))?$/.test(t)) replacement = (t.match(/^--replace=(.+)$/) || [])[1] || '{}';
    else if (/^-i(.*)$/.test(t) && !t.startsWith('--')) replacement = t.slice(2) || '{}';
    if (vf.has(t)) { i += 2; continue; }
    if (t.startsWith('-')) { i += 1; continue; }
    break;
  }
  let inner = rest.slice(i);
  const marker = '"$__marrow_dynamic"';
  if (prog === 'parallel') {
    const sep = inner.findIndex((a) => a.text !== null && /^::::?\+?$/.test(a.text));
    const inputs = sep >= 0 ? inner.slice(sep + 1) : [];
    inner = sep >= 0 ? inner.slice(0, sep) : inner;
    if (inner.length === 0) {
      // `parallel ::: 'cmd1' 'cmd2'` and `… | parallel`: every input line is a command line.
      if (sep >= 0) {
        for (const v of inputs) if (!(v.text !== null && /^::::?\+?$/.test(v.text))) shellString(v, ctx, run, x.info.subs);
        return;
      }
      const src = stdinSource(x, ctx, run);
      for (const t of src.texts) evalShell(t, childCtx(ctx), run);
      if (src.unknown || src.texts.length === 0) { worseParse(run, 'dynamic'); hit(run, 'Sx', 'parallel_stdin_commands'); }
      return;
    }
    // GNU parallel runs the template through a shell, placeholders become dynamic values.
    const text = inner.map((a) => (a.text !== null ? a.text.replace(/\{(?:[.\/#%]|\/\.|\d+)?\}/g, marker) : marker)).join(' ');
    evalShell(/\{(?:[.\/#%]|\/\.|\d+)?\}/.test(inner.map((a) => a.text || '').join(' ')) ? text : `${text} ${marker}`, childCtx(ctx), run);
    return;
  }
  if (inner.length === 0) inner = [litArg('echo')];
  // Input lines become extra operands: unknown targets (spec A6). The -I replacement string stands
  // for one input line wherever it appears.
  let replaced = false;
  const mapped = inner.map((a) => {
    if (a.text === null || replacement === null || replacement === '') return a;
    if (a.text === replacement) { replaced = true; return dynArg(); }
    if (a.text.includes(replacement)) {
      replaced = true;
      const text = a.text.split(replacement).join(marker);
      return { ...litArg(text), text: null, alts: null, pattern: a.text.split(replacement).join(DYN), word: null } as Arg;
    }
    return a;
  });
  // The input is an unknown operand (spec A6: S1 and S5 targets become unknown and stop). When the
  // upstream stage's output is a literal (`echo ~/.ssh/id_rsa | xargs cat`) that text is read as well,
  // as a second reading: it can only add a stop.
  dispatch([...mapped, dynArg()], ctx, run, x);
  if (!replaced) {
    const src = stdinSource(x, ctx, run);
    const custom = rest.some((a) => a.text === '-d' || a.text === '--delimiter' || a.text === '-a' || a.text === '--arg-file');
    if (src.texts.length === 1 && !src.unknown && src.files.length === 0 && !custom && !/['"\\]/.test(src.texts[0])) {
      const nul = rest.some((a) => a.text === '-0' || a.text === '--null');
      const literal = (nul ? [src.texts[0]] : src.texts[0].split(/\s+/).filter(Boolean)).map((t) => litArg(t));
      dispatch([...mapped, ...literal], ctx, run, x);
    }
  }
}

function watchWrapper(rest: Arg[], ctx: Ctx, run: Run): void {
  const vf = new Set(['-n', '--interval', '-d', '-q', '--equexit', '-g']);
  let i = 0;
  while (i < rest.length && rest[i].text !== null && (rest[i].text as string).startsWith('-')) i += vf.has(rest[i].text as string) ? 2 : 1;
  const inner = rest.slice(i);
  if (inner.every((a) => a.text !== null)) evalShell(inner.map((a) => a.text).join(' '), childCtx(ctx), run);
  else dynamicCode({ text: null, alts: null, pattern: inner.map((a) => (a.text !== null ? a.text : a.pattern)).join(' '), glob: false, word: null, nonAscii: false }, ctx, run, 'dynamic_watch_command');
}

function sshRemote(rest: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  const vf = new Set(['-b', '-c', '-D', '-E', '-e', '-F', '-I', '-i', '-J', '-L', '-l', '-m', '-O', '-o', '-p', '-Q', '-R', '-S', '-W', '-w', '-B']);
  let i = 0;
  while (i < rest.length) {
    const t = rest[i].text;
    if (t === null) break;
    if (vf.has(t)) { i += 2; continue; }
    if (t.startsWith('-')) { i += 1; continue; }
    break;
  }
  const remoteCmd = rest.slice(i + 1);
  if (remoteCmd.length === 0) {
    // `ssh host <<EOF … EOF`, `ssh host <<< 'cmd'`, `echo cmd | ssh host`: the text runs remotely.
    const remote = childCtx(ctx, { cwds: [null], remote: true, vars: new Map(), aliases: new Map() });
    const src = stdinSource(x, ctx, run);
    for (const t of src.texts) evalShell(t, remote, run);
    return;
  }
  const remoteCtx = childCtx(ctx, { cwds: [null], remote: true, vars: new Map(), aliases: new Map() });
  if (remoteCmd.every((a) => a.text !== null)) evalShell(remoteCmd.map((a) => a.text).join(' '), remoteCtx, run);
  else dynamicCode({ text: null, alts: null, pattern: remoteCmd.map((a) => (a.text !== null ? a.text : a.pattern)).join(' '), glob: false, word: null, nonAscii: false }, remoteCtx, run, 'dynamic_remote_command');
}

function handleShell(prog: string, rest: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  for (let i = 0; i < rest.length; i += 1) {
    const t = rest[i].text;
    if (t === null) {
      if (rest[i].word && rest[i].word!.substitution) { checkSubstitutionExec(x.info.subs, ctx, run); return; }
      // A script path or code word that cannot be resolved: a literal file name is read as a script
      // name, anything else is unknown code.
      const a = rest[i];
      const tail = a.pattern.slice(a.pattern.lastIndexOf('/') + 1);
      worseParse(run, 'dynamic');
      if (tail && !tail.includes(DYN) && a.pattern.includes('/')) { nameTripwire(tail, run, 'script_unreadable'); tripwire(a.pattern.replace(new RegExp(DYN, 'g'), ''), run); return; }
      dynamicCode(a, ctx, run, 'dynamic_shell_arg');
      return;
    }
    if (t === '-c' || (/^-[a-zA-Z]*c[a-zA-Z]*$/.test(t) && !t.startsWith('--'))) {
      const code = rest[i + 1];
      if (!code) return;
      return shellString(code, ctx, run, x.info.subs);
    }
    if (t === '-s' || t === '-' || STDIN_PATHS.has(t)) return stdinExec(prog, [], x, ctx, run);
    if (t === '-o' || t === '+o' || t === '-O' || t === '+O' || t === '--rcfile' || t === '--init-file') { i += 1; continue; }
    if (t.startsWith('-') || t.startsWith('+')) continue;
    return scriptFile(rest[i], rest.slice(i + 1), ctx, run, x);
  }
  const input = x.cmd.redirects.find((r) => r.op === '<' && r.target);
  if (input && input.target && x.cmd.heredoc === null) {
    if (input.target.substitution) { checkSubstitutionExec(x.info.subs, ctx, run); return; }
    return scriptFile(resolveWord(input.target, ctx, run), [], ctx, run, x);
  }
  stdinExec(prog, [], x, ctx, run);
}

function handleInterpreter(prog: string, rest: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  const codeFlags: Record<string, RegExp> = {
    node: /^(?:-e|--eval|-p|--print|-pe)$/, nodejs: /^(?:-e|--eval|-p|--print)$/, bun: /^(?:-e|--eval|-p|--print)$/,
    deno: /^(?:eval)$/, php: /^-r$/, ruby: /^-[a-zA-Z]*e$/, perl: /^-[a-zA-Z]*[eE]$/, lua: /^-e$/, irb: /^-e$/,
  };
  const isPython = /^(?:python[23]?(?:\.\d+)?|ipython)$/.test(prog);
  const codeRe = isPython ? /^-[a-zA-Z]*c$/ : (codeFlags[prog] || /^-e$/);
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    const t = a.text;
    if (t === null) {
      worseParse(run, 'dynamic');
      const dyn = a.word && a.word.substitution;
      if (dyn) checkSubstitutionExec(x.info.subs, ctx, run);
      // `python3 $SCRIPT`, `node "$DIR/x.js"`: a script path; with code flags earlier it is the code.
      tripwire(rest.map(argText).join(' '), run);
      if (rest.slice(0, i).some((b) => b.text !== null && (codeRe.test(b.text) || b.text === 'eval'))) hit(run, 'Sx', 'dynamic_interpreter_code');
      return;
    }
    if (codeRe.test(t) || (prog === 'deno' && t === 'eval')) {
      const code = rest[i + 1];
      if (!code) return;
      if (code.word && code.word.substitution) checkSubstitutionExec(x.info.subs, ctx, run);
      if (code.text === null && !code.alts) {
        worseParse(run, 'dynamic');
        if (code.pattern.replace(new RegExp(DYN, 'g'), '').trim() === '') { tripwire(run.topSource, run); hit(run, 'Sx', 'dynamic_interpreter_code'); return; }
      }
      scanInterpreterCode(code.text !== null ? code.text : argText(code), run);
      return;
    }
    if (isPython && t === '-m') {
      const mod = rest[i + 1]?.text || '';
      if (mod === 'twine' && rest.slice(i + 2).some((b) => b.text === 'upload')) { hit(run, 'S3', 'twine_upload'); }
      return;
    }
    if (t === '-' || STDIN_PATHS.has(t)) return stdinInterpreter(prog, x, ctx, run);
    if (t.startsWith('-')) {
      if (isPython && ['-W', '-X', '-Q'].includes(t)) i += 1;
      if (!isPython && ['-r', '--require', '--import', '--loader', '-I', '-M', '--experimental-loader', '--env-file', '--conditions', '-C'].includes(t)) {
        if (t === '--env-file') checkSecretOperand(rest[i + 1] || dynArg(), ctx, run, 'operand');
        i += 1;
      }
      continue;
    }
    return; // a script file: interpreted programs are a documented residual (spec A12)
  }
  stdinInterpreter(prog, x, ctx, run);
}

function stdinInterpreter(prog: string, x: Exec, ctx: Ctx, run: Run): void {
  stdinExec(prog, [], x, ctx, run);
}

// BSD `ps e`, `ps auxe`, `ps eww` print every process's environment.
function psProgram(rest: Arg[], run: Run): void {
  for (const a of rest) {
    if (a.text === null) continue;
    if (/^[a-zA-Z]*e[a-zA-Z]*$/.test(a.text) && !a.text.startsWith('-') && !/^\d+$/.test(a.text)) { hit(run, 'S4', 'ps_environment'); return; }
  }
}

// trap 'cmd' SIGNAL…: the command runs when the signal arrives.
function trapBuiltin(rest: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  const ops = rest.filter((a) => !(a.text !== null && /^-[lp]+$/.test(a.text)));
  if (ops.length < 2) return;
  if (ops[0].text === '' || ops[0].text === '-') return;
  shellString(ops[0], ctx, run, x.info.subs);
}

// awk programs run commands through system() and pipes.
const AWK_EXEC = /\bsystem\s*\(|\|\s*&?\s*["'$a-zA-Z(]|\bgetline\b|\bENVIRON\b|\bPROCINFO\b/;
function awkProgram(rest: Arg[], ctx: Ctx, run: Run): void {
  const vf = new Set(['-F', '-v', '-W', '--field-separator', '--assign', '-i', '-l', '--include', '--load']);
  let program: Arg | null = null;
  for (let i = 0; i < rest.length; i += 1) {
    const t = rest[i].text;
    if (t === '-f' || t === '--file') {
      const f = rest[i + 1];
      if (f && f.text !== null) {
        for (const abs of absCandidates(f.text, ctx, run) || []) {
          const content = safeRead(run.env, abs, LIMITS.maxScriptBytes);
          if (content !== null && AWK_EXEC.test(content)) scanInterpreterCode(content, run);
        }
      }
      i += 1;
      continue;
    }
    if (t !== null && vf.has(t)) { i += 1; continue; }
    if (t !== null && t.startsWith('-') && t.length > 1) continue;
    program = rest[i];
    break;
  }
  if (!program) return;
  const code = program.text !== null ? program.text : argText(program);
  if (AWK_EXEC.test(code)) scanInterpreterCode(code, run);
  void ctx;
}

// GNU sed runs a command with the `e` command and the `s///e` flag.
function sedProgram(rest: Arg[], ctx: Ctx, run: Run): void {
  const scripts: Arg[] = [];
  let seenScript = false;
  for (let i = 0; i < rest.length; i += 1) {
    const t = rest[i].text;
    if (t === '-e' || t === '--expression') { if (rest[i + 1]) scripts.push(rest[i + 1]); seenScript = true; i += 1; continue; }
    if (t !== null && t.startsWith('--expression=')) { scripts.push(litArg(t.slice(13))); seenScript = true; continue; }
    if (t === '-f' || t === '--file') { seenScript = true; i += 1; continue; }
    if (t !== null && t.startsWith('-') && t.length > 1) continue;
    if (!seenScript) { scripts.push(rest[i]); seenScript = true; }
  }
  for (const a of scripts) {
    const code = a.text !== null ? a.text : argText(a);
    if (code.length > 4096) { tripwire(code.slice(0, 4096), run); hit(run, 'Sx', 'sed_script_too_long'); continue; }
    if (/(?:^|[\n;{}])\s*(?:\d+|\$|\/[^/\n]*\/)?(?:,\s*(?:\d+|\$))?\s*!?\s*e(?:\s|$)/.test(code) || /(?:^|[\n;{}])\s*s(.)(?:(?!\1)[^\n])*\1(?:(?!\1)[^\n])*\1[a-zA-Z0-9]*e/.test(code)) {
      tripwire(code, run);
      hit(run, 'Sx', 'sed_exec');
    }
  }
  void ctx;
}

// tar runs programs for compression filters, per-file commands and checkpoint actions.
function tarProgram(rest: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  const named = new Set(['--to-command', '--checkpoint-action', '--use-compress-program', '--rsh-command', '--info-script', '--new-volume-script', '-I', '-F']);
  for (let i = 0; i < rest.length; i += 1) {
    const t = rest[i].text;
    if (t === null) continue;
    let value: Arg | null = null;
    if (named.has(t)) value = rest[i + 1] || null;
    else {
      const eq = t.match(/^(--[a-z-]+)=([\s\S]*)$/);
      if (eq && named.has(eq[1])) value = litArg(eq[2]);
    }
    if (!value) continue;
    const v = value.text !== null ? value.text.replace(/^exec=/, '') : value.pattern;
    if (value.text !== null) evalShell(v, childCtx(ctx), run);
    else dynamicCode({ ...value, pattern: v }, ctx, run, 'dynamic_tar_command');
  }
  void x;
}

// concurrently 'npm run a' 'npm:b' …: every positional argument is a command line.
function concurrentlyWrapper(rest: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  for (const a of rest) {
    if (a.text === null) { shellString(a, ctx, run, x.info.subs); continue; }
    if (a.text.startsWith('-') && a.text.length > 1) continue;
    const m = a.text.match(/^(npm|pnpm|yarn|bun):(.+)$/);
    if (m) { for (const name of scriptNamesMatching(m[2], ctx, run)) evalShell(`${m[1]} run ${shellQuote(name)}`, childCtx(ctx), run); continue; }
    evalShell(a.text, childCtx(ctx), run);
  }
}

// npm-run-all / run-s / run-p: positional arguments are package script names or patterns.
function runAllWrapper(rest: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  const valueFlags = new Set(['--max-parallel', '--npm-path', '-m']);
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    const t = a.text;
    if (t === '--') break;
    if (t !== null && valueFlags.has(t)) { i += 1; continue; }
    if (t !== null && t.startsWith('-') && t.length > 1) continue;
    if (t === null) { dynamicCode(a, ctx, run, 'dynamic_script_name'); continue; }
    const names = scriptNamesMatching(t, ctx, run);
    if (names.length === 0) nameTripwire(t, run, 'package_script_unresolved');
    for (const name of names) runPackageScript(name, [], ctx, run, x, true);
  }
}

// Script names of the package.json in scope that match a name or a `*` / `**` pattern.
function scriptNamesMatching(pattern: string, ctx: Ctx, run: Run): string[] {
  const out = new Set<string>();
  const re = compileGlob(pattern, { stop: ':', doubleStar: true });
  for (const cwd of ctx.cwds) {
    const found = findPackageJson(ctx, run, cwd);
    const scripts = found.pkg && typeof found.pkg.scripts === 'object' && found.pkg.scripts ? Object.keys(found.pkg.scripts as Record<string, unknown>) : [];
    for (const n of scripts) if (re.test(n)) out.add(n);
  }
  if (out.size === 0 && !/\*/.test(pattern)) out.add(pattern);
  return [...out];
}

// ---------------------------------------------------------------------------------------------
// script files, package scripts, make

function scriptFile(target: Arg, extra: Arg[], ctx: Ctx, run: Run, x: Exec | null): void {
  void extra;
  if (target.text === null) { worseParse(run, 'dynamic'); tripwire(argText(target), run); return; }
  const abs = absCandidates(target.text, ctx, run);
  const name = path.posix.basename(target.text);
  if (!abs || abs.some((p) => p.startsWith('/__unknown_cwd__'))) { nameTripwire(name, run, 'script_unreadable'); return; }
  if (abs.some((p) => ctx.written.has(p))) { worseParse(run, 'dynamic'); tripwire(run.topSource, run); return; }
  if (ctx.depth >= LIMITS.maxDepth) { worseParse(run, 'too_large'); hit(run, 'Sx', 'budget_depth'); nameTripwire(name, run, 'script_depth'); return; }
  for (const p of abs) {
    if (alreadySeen(run, ctx, 'script', p, x ? x.env : new Map())) continue;
    if (!expandScript(run)) return;
    const content = readCached(run, p, LIMITS.maxScriptBytes);
    if (content === null) { nameTripwire(name, run, 'script_unreadable'); continue; }
    const shebang = content.startsWith('#!') ? content.slice(0, content.indexOf('\n') >>> 0).toLowerCase() : '';
    if (shebang && !/\b(?:sh|bash|zsh|dash|ksh|ash)\b/.test(shebang)) {
      // Non-shell scripts: decoded exec and tree deletes only (interpreted programs are a residual).
      if (INTERPRETER_TREE_DELETE.test(content)) hit(run, 'S5', 'script_tree_delete');
      if (INTERPRETER_DECODE.test(content) && INTERPRETER_EXEC.test(content)) hit(run, 'Sx', 'script_decoded_exec');
      continue;
    }
    const sctx = scriptCtx(ctx, ctx.cwds, x ? x.env : new Map());
    evalShell(content, sctx, run);
  }
}

function nameTripwire(name: string, run: Run, reason: string): void {
  if (NAME_TRIPWIRE.test(name)) {
    const n = name.toLowerCase();
    const category = /publish|release/.test(n) ? 'S3' : 'S2';
    hit(run, category, `${reason}_name`);
  }
}

function findPackageJson(ctx: Ctx, run: Run, cwd: string | null): { pkg: Record<string, unknown> | null; dir: string | null; error?: string } {
  if (!cwd) return { pkg: null, dir: null, error: 'cwd_unknown' };
  let dir = cwd;
  for (let level = 0; level < 12; level += 1) {
    const file = path.posix.join(dir, 'package.json');
    if (ctx.written.has(file)) return { pkg: null, dir, error: 'written' };
    const raw = readCached(run, file, LIMITS.maxPackageJsonBytes);
    if (raw !== null) {
      const memo = run.packages.get(file);
      if (memo) return { pkg: memo.pkg, dir, error: memo.error };
      let parsedPkg: { pkg: Record<string, unknown> | null; error?: string };
      try { const pkg = JSON.parse(raw); parsedPkg = { pkg: pkg && typeof pkg === 'object' ? pkg : null, error: pkg && typeof pkg === 'object' ? undefined : 'invalid' }; } catch { parsedPkg = { pkg: null, error: 'invalid' }; }
      run.packages.set(file, parsedPkg);
      return { ...parsedPkg, dir };
    }
    const parent = path.posix.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return { pkg: null, dir: null, error: 'missing' };
}

function runPackageScript(name: string, extraArgs: Arg[], ctx: Ctx, run: Run, x: Exec, withHooks: boolean): void {
  if (ctx.depth >= LIMITS.maxDepth) { worseParse(run, 'too_large'); hit(run, 'Sx', 'budget_depth'); nameTripwire(name, run, 'package_script_depth'); return; }
  for (const cwd of ctx.cwds) {
    const found = findPackageJson(ctx, run, cwd);
    if (found.error === 'written') { worseParse(run, 'dynamic'); tripwire(run.topSource, run); continue; }
    const scripts = found.pkg && typeof found.pkg.scripts === 'object' && found.pkg.scripts ? found.pkg.scripts as Record<string, unknown> : null;
    if (!scripts || typeof scripts[name] !== 'string') { nameTripwire(name, run, 'package_script_unresolved'); continue; }
    const hooks = withHooks ? [`pre${name}`, name, `post${name}`] : [name];
    for (const hook of hooks) {
      const body = scripts[hook];
      if (typeof body !== 'string') continue;
      const suffix = hook === name && extraArgs.length ? ` ${extraArgs.map((a) => (a.text !== null ? shellQuote(a.text) : '"$__marrow_dynamic"')).join(' ')}` : '';
      // The same script in the same context was already evaluated: its hits are recorded.
      if (alreadySeen(run, ctx, 'pkg', `${found.dir}\u0002${hook}\u0002${suffix}`, x.env)) continue;
      if (!expandScript(run)) return;
      evalShell(body + suffix, scriptCtx(ctx, [found.dir], x.env), run);
    }
  }
}

function lifecycleScripts(names: string[], ctx: Ctx, run: Run, x: Exec): void {
  if (ctx.depth >= LIMITS.maxDepth) { worseParse(run, 'too_large'); hit(run, 'Sx', 'budget_depth'); return; }
  for (const cwd of ctx.cwds) {
    const found = findPackageJson(ctx, run, cwd);
    if (found.error === 'written') { worseParse(run, 'dynamic'); tripwire(run.topSource, run); continue; }
    const scripts = found.pkg && typeof found.pkg.scripts === 'object' && found.pkg.scripts ? found.pkg.scripts as Record<string, unknown> : null;
    if (!scripts) continue;
    for (const n of names) {
      if (typeof scripts[n] !== 'string') continue;
      if (alreadySeen(run, ctx, 'pkg', `${found.dir}\u0002${n}\u0002`, x.env)) continue;
      if (!expandScript(run)) return;
      evalShell(scripts[n] as string, scriptCtx(ctx, [found.dir], x.env), run);
    }
  }
}

function handleMake(rest: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  let dirs = ctx.cwds;
  let file: string | null = null;
  const targets: Arg[] = [];
  const vars = new Map<string, string | null>();
  for (let i = 0; i < rest.length; i += 1) {
    const t = rest[i].text;
    if (t === null) { targets.push(rest[i]); continue; }
    if (t === '-C' || t === '--directory') { const d = rest[i + 1]?.text; dirs = d ? dirs.map((c) => (c ? path.posix.resolve(c, d) : null)) : [null]; i += 1; continue; }
    if (t === '-f' || t === '--file' || t === '--makefile') { file = rest[i + 1]?.text ?? null; i += 1; continue; }
    if (t === '-j' || t === '-l' || t === '-o' || t === '-W' || t === '-I') { i += 1; continue; }
    if (t.startsWith('-')) continue;
    const eq = t.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (eq) { vars.set(eq[1], eq[2]); continue; }
    targets.push(rest[i]);
  }
  if (ctx.depth >= LIMITS.maxDepth) { worseParse(run, 'too_large'); hit(run, 'Sx', 'budget_depth'); for (const tg of targets) nameTripwire(argText(tg), run, 'make_depth'); return; }
  for (const dir of dirs) {
    let content: string | null = null;
    const names = file ? [file] : ['GNUmakefile', 'makefile', 'Makefile'];
    for (const n of names) {
      if (!dir && !path.posix.isAbsolute(n)) break;
      const p = path.posix.resolve(dir || '/', n);
      if (ctx.written.has(p)) { worseParse(run, 'dynamic'); tripwire(run.topSource, run); return; }
      content = readCached(run, p, LIMITS.maxScriptBytes);
      if (content !== null) break;
    }
    if (content === null) { for (const tg of targets) nameTripwire(argText(tg), run, 'make_unreadable'); continue; }
    const mk = parseMakefile(content);
    for (const [k, v] of vars) mk.vars.set(k, v);
    const wanted = targets.length ? targets.map((tg) => tg.text) : [mk.first];
    const seen = new Set<string>();
    const visit = (target: string | null, depth: number) => {
      if (target === null) { worseParse(run, 'dynamic'); return; }
      if (run.exhausted || seen.has(target) || depth > 8) return;
      seen.add(target);
      const rule = mk.rules.get(target);
      if (!rule) return;
      for (const dep of rule.deps) visit(dep, depth + 1);
      if (alreadySeen(run, ctx, 'make', `${dir}\u0002${target}\u0002${JSON.stringify([...mk.vars])}`, x.env)) return;
      if (!expandScript(run)) return;
      for (const line of rule.recipe) evalShell(expandMakeLine(line, mk.vars), scriptCtx(ctx, [dir], x.env), run);
    };
    for (const w of wanted) visit(w, 0);
  }
}

function parseMakefile(content: string): { rules: Map<string, { deps: string[]; recipe: string[] }>; vars: Map<string, string | null>; first: string | null } {
  const rules = new Map<string, { deps: string[]; recipe: string[] }>();
  const vars = new Map<string, string | null>();
  let first: string | null = null;
  let current: Array<{ deps: string[]; recipe: string[] }> = [];
  const lines = content.replace(/\\\n/g, ' ').split('\n');
  for (const line of lines) {
    if (line.startsWith('\t')) { for (const r of current) r.recipe.push(line.slice(1)); continue; }
    if (/^\s*(?:#|$)/.test(line)) continue;
    const assign = line.match(/^\s*(?:export\s+|override\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*(?::{1,3}|\?|\+|!)?=\s*(.*)$/);
    if (assign) { vars.set(assign[1], /\$[({]/.test(assign[2]) ? null : assign[2].trim()); current = []; continue; }
    const rule = line.match(/^([^:#=\t][^:#=]*?)\s*::?(?!=)\s*([^=;#]*)(?:;\s*(.*))?$/);
    if (rule) {
      const names = rule[1].trim().split(/\s+/);
      const deps = rule[2].trim() ? rule[2].trim().split(/\s+/) : [];
      current = [];
      for (const n of names) {
        if (!first && !n.startsWith('.') && !n.includes('%')) first = n;
        const r = rules.get(n) || { deps: [], recipe: [] };
        r.deps.push(...deps);
        if (rule[3]) r.recipe.push(rule[3]);
        rules.set(n, r);
        current.push(r);
      }
      continue;
    }
    current = [];
  }
  return { rules, vars, first };
}

function expandMakeLine(line: string, vars: Map<string, string | null>): string {
  let out = line.replace(/^[\s@+-]+/, '').replace(/\$\$/g, '\u0002');
  for (let k = 0; k < 4; k += 1) {
    out = out.replace(/\$[({]([A-Za-z_][A-Za-z0-9_.-]*)[)}]/g, (_m, name: string) => {
      if (name === 'MAKE') return 'make';
      const v = vars.get(name);
      return typeof v === 'string' ? v : '"$__marrow_make_var"';
    });
  }
  out = out.replace(/\$[({][^)}]*[)}]|\$[@<^?*%]/g, '"$__marrow_make_var"');
  return out.replace(/\u0002/g, '$');
}

// ---------------------------------------------------------------------------------------------
// flag helpers (last occurrence wins)

type Tri = 'true' | 'false' | 'unknown' | 'absent';

function boolFlag(rest: Arg[], names: string[], negs: string[] = []): Tri {
  let state: Tri = 'absent';
  for (const a of rest) {
    if (a.text === null) { if (state !== 'absent' || names.some((n) => a.pattern.startsWith(n))) state = 'unknown'; continue; }
    if (a.text === '--') break;
    const t = a.text;
    if (names.includes(t)) { state = 'true'; continue; }
    if (negs.includes(t)) { state = 'false'; continue; }
    const eq = t.indexOf('=');
    if (eq > 0 && names.includes(t.slice(0, eq))) {
      const v = t.slice(eq + 1).toLowerCase();
      state = ['true', '1', 'yes', 'on', ''].includes(v) ? 'true' : ['false', '0', 'no', 'off'].includes(v) ? 'false' : 'unknown';
    }
  }
  return state;
}

// Last value of a value flag. undefined = absent, null = dynamic or missing value.
function valueFlag(rest: Arg[], names: string[], shortAttached: string[] = []): string | null | undefined {
  let value: string | null | undefined;
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a.text === null) { if (names.some((n) => a.pattern.startsWith(`${n}=`))) value = null; continue; }
    if (a.text === '--') break;
    const t = a.text;
    if (names.includes(t)) { const v = rest[i + 1]; value = v ? v.text : null; i += 1; continue; }
    const eq = t.indexOf('=');
    if (eq > 0 && names.includes(t.slice(0, eq))) { value = t.slice(eq + 1); continue; }
    for (const s of shortAttached) if (t.startsWith(s) && t.length > s.length && !t.startsWith('--')) value = t.slice(s.length);
  }
  return value;
}

function positionals(rest: Arg[], valueFlags: string[]): Arg[] {
  const vf = new Set(valueFlags);
  const out: Arg[] = [];
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a.text === '--') { out.push(...rest.slice(i + 1)); break; }
    if (a.text !== null && a.text.startsWith('-') && a.text.length > 1) { if (vf.has(a.text)) i += 1; continue; }
    out.push(a);
  }
  return out;
}

// camelCase names count too: ProdStack, appProduction.
function isProdName(v: string): boolean {
  return PROD_ENV.test(v) || PROD_ENV.test(v.replace(/([a-z0-9])([A-Z])/g, '$1-$2'));
}
function prodValue(v: string | null | undefined): boolean {
  return v === null || v === '' || (typeof v === 'string' && isProdName(v));
}
function envValue(x: Exec, ctx: Ctx, name: string): string | null | undefined {
  if (x.env.has(name)) { const v = x.env.get(name); return v && v.length === 1 ? v[0] : null; }
  if (ctx.exported.has(name) && ctx.vars.has(name)) { const v = ctx.vars.get(name); return v && v.length === 1 ? v[0] : null; }
  return undefined;
}

// ---------------------------------------------------------------------------------------------
// S1 git

// Config that arrives outside the repository's own files (audit F6): GIT_CONFIG_COUNT with
// GIT_CONFIG_KEY_<n>/GIT_CONFIG_VALUE_<n>, GIT_CONFIG_PARAMETERS, files named by GIT_CONFIG_GLOBAL,
// GIT_CONFIG_SYSTEM and GIT_CONFIG, and include.path / includeIf.*.path. Entries are expanded like
// `-c`; whatever cannot be read marks the configuration unknown.
const CONFIG_UNKNOWN = 'marrow.configunknown';

function parseGitConfigText(text: string): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  let section = '';
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    const sec = line.match(/^\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]\s*(.*)$/);
    if (sec) {
      section = sec[2] !== undefined ? `${sec[1].toLowerCase()}.${sec[2]}` : sec[1].toLowerCase();
      if (sec[3]) { const kv = sec[3].match(/^([A-Za-z][A-Za-z0-9-]*)\s*=\s*(.*)$/); if (kv) out.push([`${section}.${kv[1].toLowerCase()}`, kv[2].replace(/^"(.*)"$/, '$1')]); }
      continue;
    }
    const kv = line.match(/^([A-Za-z][A-Za-z0-9-]*)\s*(?:=\s*(.*))?$/);
    if (kv && section) out.push([`${section}.${kv[1].toLowerCase()}`, kv[2] === undefined ? 'true' : kv[2].replace(/\s+[#;].*$/, '').replace(/^"(.*)"$/, '$1')]);
  }
  return out;
}

function addConfigEntry(overrides: Map<string, string[]>, key: string, value: string, ctx: Ctx, run: Run, depth: number): void {
  const canon = canonicalGitKey(key);
  overrides.set(canon, [...(overrides.get(canon) || []), value]);
  if (GIT_CONFIG_INCLUDE.test(canon)) {
    // An include is read when its path is absolute and readable; anything else is unknown config.
    const target = expandTilde(value, run);
    if (depth >= 3 || target === null || !path.posix.isAbsolute(target)) { overrides.set(CONFIG_UNKNOWN, ['1']); return; }
    const text = safeRead(run.env, target, LIMITS.maxConfigBytes);
    if (text === null) { overrides.set(CONFIG_UNKNOWN, ['1']); return; }
    for (const [k, v] of parseGitConfigText(text)) addConfigEntry(overrides, k, v, ctx, run, depth + 1);
  }
}

function envGitConfig(x: Exec, ctx: Ctx, run: Run, overrides: Map<string, string[]>): void {
  const count = envValue(x, ctx, 'GIT_CONFIG_COUNT');
  if (count !== undefined) {
    const n = count === null ? NaN : parseInt(count, 10);
    if (!Number.isFinite(n) || n < 0 || n > 64) overrides.set(CONFIG_UNKNOWN, ['1']);
    else {
      for (let k = 0; k < n; k += 1) {
        const key = envValue(x, ctx, `GIT_CONFIG_KEY_${k}`);
        const value = envValue(x, ctx, `GIT_CONFIG_VALUE_${k}`);
        if (key === undefined || key === null || value === null || value === undefined) { overrides.set(CONFIG_UNKNOWN, ['1']); continue; }
        addConfigEntry(overrides, key, value, ctx, run, 0);
      }
    }
  }
  const params = envValue(x, ctx, 'GIT_CONFIG_PARAMETERS');
  if (params === null) overrides.set(CONFIG_UNKNOWN, ['1']);
  else if (params !== undefined && params.trim()) {
    // 'key'='value' 'key2'='value2'  (or the older 'key=value' form), single-quote escaped.
    const re = /'((?:[^']|'\\'')*)'(?:='((?:[^']|'\\'')*)')?/g;
    let m: RegExpExecArray | null;
    let consumed = 0;
    while ((m = re.exec(params))) {
      consumed += m[0].length;
      const unq = (v: string) => v.replace(/'\\''/g, "'");
      if (m[2] !== undefined) addConfigEntry(overrides, unq(m[1]), unq(m[2]), ctx, run, 0);
      else {
        const t = unq(m[1]);
        const eq = t.indexOf('=');
        addConfigEntry(overrides, eq >= 0 ? t.slice(0, eq) : t, eq >= 0 ? t.slice(eq + 1) : 'true', ctx, run, 0);
      }
    }
    if (consumed < params.replace(/\s+/g, '').length) overrides.set(CONFIG_UNKNOWN, ['1']);
  }
  // Environment that moves git to other configuration or another repository (the U3 resolver's
  // GIT_RELOCATING_ENV, plus HOME and XDG_CONFIG_HOME when the command sets them).
  const homeMoved = x.env.has('HOME') || x.env.has('XDG_CONFIG_HOME')
    || (ctx.exported.has('XDG_CONFIG_HOME') && ctx.vars.has('XDG_CONFIG_HOME'))
    || (ctx.vars.get('HOME') !== undefined && (ctx.vars.get('HOME') as string[] | null)?.length === 1 && (ctx.vars.get('HOME') as string[])[0] !== run.home);
  if (homeMoved) overrides.set(CONFIG_UNKNOWN, ['1']);
  for (const name of ['GIT_DIR', 'GIT_COMMON_DIR', 'GIT_WORK_TREE', 'GIT_NAMESPACE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_TEMPLATE_DIR']) {
    if (envValue(x, ctx, name) !== undefined) overrides.set(CONFIG_UNKNOWN, ['1']);
  }
  for (const name of GIT_CONFIG_ENV_FILES) {
    const file = envValue(x, ctx, name);
    if (file === undefined) continue;
    const abs = file === null ? null : expandTilde(file, run);
    const text = abs && path.posix.isAbsolute(abs) ? safeRead(run.env, abs, LIMITS.maxConfigBytes) : null;
    if (text === null) { overrides.set(CONFIG_UNKNOWN, ['1']); continue; }
    for (const [k, v] of parseGitConfigText(text)) addConfigEntry(overrides, k, v, ctx, run, 1);
  }
}

// An exec-capable config value (a hook program, pager, ssh command, filter, credential helper) is a
// shell command; classify it as one.
const BENIGN_EXEC_VALUE = /^(?:true|false|:|cat|less(?: -[A-Za-z]+)?|more|vim?|nvim|nano|emacs|code --wait|subl -w|store|cache(?: .*)?|osxkeychain|manager(?:-core)?|libsecret|wincred|\/dev\/null)$/;
function classifyExecConfig(key: string, value: string, ctx: Ctx, run: Run): void {
  if (!GIT_EXEC_CONFIG.test(key) || key.startsWith('alias.')) return;
  if (/^credential(?:\..+)?\.helper$/.test(key) && !value.startsWith('!') && !path.posix.isAbsolute(value)) return;
  if (/hookspath$/.test(key) || /^submodule\./.test(key) && !value.startsWith('!')) return;
  const code = value.startsWith('!') ? value.slice(1) : value;
  if (BENIGN_EXEC_VALUE.test(code.trim())) return;
  evalShell(code, childCtx(ctx), run);
}

function handleGit(rest: Arg[], ctx: Ctx, run: Run, x: Exec, cOverrides: Map<string, string[]>, aliasDepth: number): void {
  let cwds = ctx.cwds;
  const overrides = new Map(cOverrides);
  if (aliasDepth === 0) envGitConfig(x, ctx, run, overrides);
  let i = 0;
  while (i < rest.length) {
    const a = rest[i];
    const t = a.text;
    if (t === null) {
      // `git $x origin main`: a dynamic word where an option or the subcommand belongs (audit F2).
      worseParse(run, 'dynamic');
      tripwire(rest.slice(i).map(argText).join(' '), run);
      hit(run, 'S1', 'git_dynamic_subcommand');
      return;
    }
    if (t === '-C') {
      const d = rest[i + 1];
      if (!d || d.text === null) cwds = [null];
      else { const exp = expandTilde(d.text, run); cwds = cwds.map((c) => (exp === null ? null : path.posix.isAbsolute(exp) ? path.posix.normalize(exp) : c ? path.posix.resolve(c, exp) : null)); }
      i += 2; continue;
    }
    if (t === '-c') {
      const kv = rest[i + 1];
      if (!kv || kv.text === null) { worseParse(run, 'dynamic'); tripwire(rest.map(argText).join(' '), run); return; }
      const eq = kv.text.indexOf('=');
      const rawKey = eq >= 0 ? kv.text.slice(0, eq) : kv.text;
      const value = eq >= 0 ? kv.text.slice(eq + 1) : 'true';
      addConfigEntry(overrides, rawKey, value, ctx, run, 0);
      classifyExecConfig(canonicalGitKey(rawKey), value, ctx, run);
      i += 2; continue;
    }
    if (t.startsWith('--config-env')) {
      // --config-env=<key>=<ENVVAR>: the value comes from the environment (the hook cannot see it).
      overrides.set(CONFIG_UNKNOWN, ['1']);
      worseParse(run, 'dynamic');
      i += t === '--config-env' ? 2 : 1;
      continue;
    }
    if (['--git-dir', '--work-tree', '--namespace', '--exec-path', '--super-prefix', '--list-cmds', '--attr-source'].includes(t)) {
      if (t === '--git-dir' || t === '--work-tree') overrides.set(CONFIG_UNKNOWN, ['1']);
      i += 2; continue;
    }
    if (/^--(?:git-dir|work-tree)=/.test(t)) overrides.set(CONFIG_UNKNOWN, ['1']);
    if (t.startsWith('-')) { i += 1; continue; }
    break;
  }
  const subArg = rest[i];
  if (!subArg) return;
  if (subArg.text === null) {
    // `git $sub …`: the subcommand could be push -f (audit F2).
    worseParse(run, 'dynamic');
    tripwire(rest.map(argText).join(' '), run);
    hit(run, 'S1', 'git_dynamic_subcommand');
    return;
  }
  const sub = subArg.text;
  const args = rest.slice(i + 1);
  const gctx: Ctx = { ...ctx, cwds };
  // Programs git runs for the agent: GIT_SSH_COMMAND, GIT_EDITOR, GIT_PAGER … set in this command.
  for (const name of ['GIT_SSH_COMMAND', 'GIT_SSH', 'GIT_PROXY_COMMAND', 'GIT_ASKPASS', 'SSH_ASKPASS', 'GIT_EDITOR', 'GIT_SEQUENCE_EDITOR', 'GIT_PAGER', 'GIT_EXTERNAL_DIFF']) {
    const v = envValue(x, ctx, name);
    if (v === undefined) continue;
    if (v === null) { worseParse(run, 'dynamic'); hit(run, 'Sx', 'dynamic_git_exec_env'); continue; }
    if (!BENIGN_EXEC_VALUE.test(v.trim())) evalShell(v, childCtx(ctx), run);
  }
  if (args.some((a) => a.text !== null && /^ext::/.test(a.text))) { hit(run, 'Sx', 'git_ext_transport'); return; }
  gitExecOptions(sub, args, gctx, run, x);
  if (!GIT_BUILTINS.has(sub)) {
    const key = `alias.${sub.toLowerCase()}`;
    let value: string | undefined;
    const fromC = overrides.get(key);
    if (fromC && fromC.length) value = fromC[fromC.length - 1];
    else if (ctx.gitAliases.has(sub.toLowerCase())) value = ctx.gitAliases.get(sub.toLowerCase());
    else {
      for (const c of cwds) {
        const vals = gitAll(run, ctx, c, `alias.${sub}`);
        if (vals === null) { worseParse(run, 'unparsed'); tripwire(rest.map(argText).join(' '), run); return; }
        if (vals.length) value = vals[vals.length - 1];
      }
    }
    if (value === undefined && overrides.has(CONFIG_UNKNOWN)) {
      // The configuration is partly unreadable (redirected files, includes, --config-env): this
      // subcommand may be an alias for `push -f`.
      worseParse(run, 'dynamic');
      hit(run, 'S1', 'git_unresolved_alias_config_unknown');
      return;
    }
    if (value !== undefined) {
      if (aliasDepth >= LIMITS.maxAliasExpansions) { worseParse(run, 'too_large'); hit(run, 'Sx', 'budget_alias_depth'); tripwire(`${value} ${args.map(argText).join(' ')}`, run); return; }
      const restText = args.map((a) => (a.text !== null ? shellQuote(a.text) : '"$__marrow_dynamic"')).join(' ');
      if (value.startsWith('!')) { evalShell(`${value.slice(1)} ${restText}`, childCtx(gctx), run); return; }
      const parsed = shellParse.parseShell(value);
      if (!parsed.ok || parsed.commands.length !== 1) { worseParse(run, 'unparsed'); tripwire(`push ${value} ${restText}`, run); return; }
      const expanded = parsed.commands[0].words.map((w) => resolveWord(w, ctx, run));
      handleGit([...expanded, ...args], gctx, run, x, overrides, aliasDepth + 1);
      return;
    }
    return;
  }
  switch (sub) {
    case 'push': case 'send-pack': return gitPush(args, gctx, run, overrides);
    case 'clean': return gitClean(args, gctx, run);
    case 'config': return gitConfig(args, gctx, run, x, overrides, aliasDepth);
    default: break;
  }
  // Working-tree writes on protected files (git rm --cached and restore --staged only touch the index).
  const indexOnly = args.some((a) => a.text === '--cached' || a.text === '--staged') && !args.some((a) => a.text === '--worktree' || a.text === '-W');
  if (['checkout', 'restore', 'rm', 'mv'].includes(sub) && !indexOnly) {
    for (const a of args) if (a.text === null || !a.text.startsWith('-')) checkProtectedWrite(a, gctx, run, `git_${sub}`, sub === 'rm' || sub === 'mv');
  }
  // `git credential fill` prints the stored password for a host.
  if (sub === 'credential' && args.some((a) => a.text === null || a.text === 'fill' || a.text === 'get')) { hit(run, 'S4', 'git_credential_fill'); return; }
  if (/^credential-/.test(sub) && args.some((a) => a.text === null || a.text === 'get')) { hit(run, 'S4', 'git_credential_get'); return; }
  if (!GIT_S4_EXEMPT_SUBS.has(sub)) {
    // Commit messages are prose, never paths.
    for (let k = 0; k < args.length; k += 1) {
      const t = args[k].text;
      if (t === '-m' || t === '--message' || t === '-F' || t === '--file' || (t !== null && /^-[a-zA-Z]*m$/.test(t))) { k += 1; continue; }
      if (t !== null && /^(?:--message=|-m.)/.test(t)) continue;
      checkSecretOperand(args[k], gctx, run, 'git_operand');
    }
  }
}

// Options that hand git a command to run: rebase --exec, filter-branch filters, bisect run, submodule
// foreach, and the pack programs of fetch and push.
function gitExecOptions(sub: string, args: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  const classify = (a: Arg | undefined | null) => {
    if (!a) return;
    if (a.text !== null) evalShell(a.text, childCtx(ctx), run);
    else dynamicCode(a, ctx, run, 'dynamic_git_exec_option');
  };
  const filters = ['--env-filter', '--tree-filter', '--index-filter', '--parent-filter', '--msg-filter', '--commit-filter', '--tag-name-filter'];
  for (let i = 0; i < args.length; i += 1) {
    const t = args[i].text;
    if (t === null || !t.startsWith('-')) continue;
    const eq = t.startsWith('--') ? t.indexOf('=') : -1;
    const key = eq > 0 ? t.slice(0, eq) : t;
    const inline = eq > 0 ? litArg(t.slice(eq + 1)) : null;
    const value = inline || args[i + 1];
    if (sub === 'rebase' && (key === '-x' || key === '--exec')) classify(value);
    else if (sub === 'rebase' && /^-x.+/.test(t)) classify(litArg(t.slice(2)));
    else if (sub === 'filter-branch' && filters.includes(key)) classify(value);
    else if (['fetch', 'pull', 'clone', 'ls-remote'].includes(sub) && (key === '--upload-pack' || key === '-u')) classify(value);
    else if (['push', 'send-pack'].includes(sub) && (key === '--receive-pack' || key === '--exec')) classify(value);
    else if (sub === 'archive' && key === '--exec') classify(value);
    else if ((sub === 'difftool' || sub === 'mergetool') && (key === '--extcmd' || key === '-x')) classify(value);
    else if (sub === 'clone' && (key === '-c' || key === '--config') && value && value.text !== null) {
      const kv = value.text.indexOf('=');
      if (kv > 0) classifyExecConfig(canonicalGitKey(value.text.slice(0, kv)), value.text.slice(kv + 1), ctx, run);
    }
  }
  if (sub === 'bisect' && args[0]?.text === 'run') dispatch(args.slice(1), ctx, run, x);
  if (sub === 'submodule') {
    const k = args.findIndex((a) => a.text === 'foreach');
    if (k >= 0) classify(args.slice(k + 1).find((a) => !(a.text !== null && a.text.startsWith('-'))));
  }
}

function gitConfig(args: Arg[], ctx: Ctx, run: Run, x: Exec, overrides: Map<string, string[]>, aliasDepth: number): void {
  const vf = new Set(['--file', '-f', '--blob', '--type', '--default', '--comment']);
  const pos = positionals(args, [...vf]);
  if (pos.length < 2 || pos[0].text === null) return;
  const key = canonicalGitKey(pos[0].text);
  if (args.some((a) => a.text !== null && /^--(?:get|unset|list|remove|rename)/.test(a.text))) return;
  const value = pos[1].text;
  if (value === null) {
    worseParse(run, 'dynamic');
    tripwire(`${pos[0].text} ${argText(pos[1])}`, run);
    if (GIT_EXEC_CONFIG.test(key) || GIT_CONFIG_INCLUDE.test(key)) hit(run, 'S0', 'git_config_exec_key_dynamic');
    return;
  }
  // A persistent exec-capable setting runs a program for the owner later (audit F6, adv5).
  if (GIT_EXEC_CONFIG.test(key) && !key.startsWith('alias.')) {
    const benign = BENIGN_EXEC_VALUE.test(value.trim()) && !/hookspath$/.test(key);
    if (!benign && !(/^credential(?:\..+)?\.helper$/.test(key) && !value.startsWith('!') && !path.posix.isAbsolute(value))) hit(run, 'S0', 'git_config_exec_key');
    classifyExecConfig(key, value, ctx, run);
  }
  if (GIT_CONFIG_INCLUDE.test(key)) hit(run, 'S0', 'git_config_include');
  if (key.startsWith('alias.')) {
    const name = key.slice(6).toLowerCase();
    ctx.gitAliases.set(name, value);
    // Classified as if executed (spec A10).
    handleGit([litArg(name)], ctx, run, x, overrides, aliasDepth + 1);
    return;
  }
  ctx.gitConfig.set(key, [...(ctx.gitConfig.get(key) || []), value]);
}

function gitClean(args: Arg[], ctx: Ctx, run: Run): void {
  const flags = args.filter((a) => a.text !== null && /^-[a-zA-Z]+$/.test(a.text)).map((a) => a.text).join('');
  if (!/[dx]/i.test(flags) && !args.some((a) => a.text === '--force')) return;
  for (const c of ctx.cwds) {
    if (!c) { hit(run, 'S5', 'git_clean_unknown_dir'); return; }
    checkDeleteTarget(litArg(c), { ...ctx, cwds: [c] }, run, 'git_clean', 'children');
  }
}

function longOption(name: string, list: string[]): string[] {
  if (list.includes(name)) return [name];
  return list.filter((o) => o.startsWith(name));
}

function gitPush(args: Arg[], ctx: Ctx, run: Run, overrides: Map<string, string[]>): void {
  const risky = new Set<string>();
  let repo: Arg | null = null;
  const refspecs: Arg[] = [];
  let after = false;
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i];
    const t = a.text;
    if (t === null) {
      // A dynamic word can be a force flag or a +refspec: fail closed.
      risky.add('unknown_flag');
      if (!repo) repo = a; else refspecs.push(a);
      continue;
    }
    if (!after && t === '--') { after = true; continue; }
    if (!after && t.startsWith('--')) {
      const name = t.slice(2).split('=')[0];
      const cands = longOption(name, GIT_PUSH_LONG);
      for (const c of cands) if (GIT_PUSH_RISKY_LONG[c]) risky.add(GIT_PUSH_RISKY_LONG[c]);
      if (cands.length === 1 && cands[0] === 'repo' && t.includes('=')) repo = litArg(t.slice(t.indexOf('=') + 1));
      if (cands.length === 1 && ['push-option', 'receive-pack', 'exec', 'repo'].includes(cands[0]) && !t.includes('=')) {
        if (cands[0] === 'repo' && args[i + 1]) repo = args[i + 1];
        i += 1;
      }
      continue;
    }
    if (!after && t.startsWith('-') && t.length > 1) {
      for (let k = 1; k < t.length; k += 1) {
        const ch = t[k];
        if (ch === 'f') risky.add('force');
        else if (ch === 'd') risky.add('delete');
        else if (ch === 'o') { if (k === t.length - 1) i += 1; break; }
      }
      continue;
    }
    if (!repo) repo = a; else refspecs.push(a);
  }
  // Configuration that could not be read may add a `+` refspec or mirror mode to a push with no
  // explicit refspec.
  const configUnknown = overrides.has(CONFIG_UNKNOWN) && refspecs.length === 0;
  if (configUnknown) risky.add('unknown_flag');
  const cwd = ctx.cwds.length === 1 ? ctx.cwds[0] : null;
  const remoteName = repo ? repo.text : undefined;
  let current: string | null = null;
  if (cwd) { try { current = run.env.git.currentBranch(cwd); } catch { current = null; } }
  const cfg = (key: string) => gitAll(run, ctx, cwd, key, overrides) ?? null;
  const last = (vals: string[] | null) => (vals && vals.length ? vals[vals.length - 1] : undefined);
  let remote: string | null = remoteName === undefined
    ? (last(current ? cfg(`branch.${current}.pushRemote`) : null) || last(cfg('remote.pushDefault')) || last(current ? cfg(`branch.${current}.remote`) : null) || 'origin')
    : remoteName;

  // Heroku git deploys are S2.
  const remoteUrl = remote ? last(cfg(`remote.${remote}.url`)) : undefined;
  if ((remote && /heroku/i.test(remote)) || (remoteUrl && /heroku\.com/i.test(remoteUrl))) hit(run, 'S2', 'git_push_heroku');
  if (remote && /^(?:true|yes|on|1)$/i.test(last(cfg(`remote.${remote}.mirror`)) || '')) risky.add('mirror');

  // null in `targets` = a destination that cannot be resolved to one branch: protected. The rule is
  // the U3 resolver's (src/seatbelt-git.ts resolvePushRefspec): git matches a short name with
  // ref_rev_parse_rules, so `heads/main` is refs/heads/main and `tags/x` may name a branch; any name
  // with more than one reading, a pattern, or an odd ref name is unresolved (audit F4).
  const targets: Array<string | null> = [];
  let anyForced = false;
  const consumeRefspec = (spec: string) => {
    let s = spec;
    if (s.startsWith('+')) { anyForced = true; s = s.slice(1); }
    if (s === ':') { targets.push(null); return; }
    const colon = s.indexOf(':');
    const src = colon < 0 ? s : s.slice(0, colon);
    const dst = colon < 0 ? null : s.slice(colon + 1);
    if (colon >= 0 && src === '') risky.add('delete');
    if (s.includes('*')) { targets.push(null); return; }
    targets.push(resolveRefName(dst !== null ? dst : src, current));
  };
  for (const r of refspecs) {
    if (r.text === null) { if (r.pattern.startsWith('+')) anyForced = true; targets.push(null); continue; }
    consumeRefspec(r.text);
  }
  if (risky.has('mirror') || risky.has('all') || risky.has('prune')) targets.push('*');
  if (refspecs.length === 0 && !risky.has('mirror') && !risky.has('all')) {
    const configured = remote ? cfg(`remote.${remote}.push`) : null;
    if (configured === null) targets.push(null);
    else if (configured.length) for (const spec of configured) consumeRefspec(spec);
    else {
      const mode = (last(cfg('push.default')) || 'simple').toLowerCase();
      if (mode === 'matching') targets.push('*');
      else if (mode === 'nothing') { /* pushes nothing */ }
      else if (mode === 'upstream' || mode === 'tracking') {
        const merge = current ? last(cfg(`branch.${current}.merge`)) : undefined;
        targets.push(merge ? resolveRefName(merge, current) : current);
      } else targets.push(current);
    }
  }
  if (repo && repo.text === null) remote = null;
  if (configUnknown) targets.push(null);

  const forced = anyForced || risky.has('force') || risky.has('unknown_flag');
  const destructive = forced || risky.has('delete') || risky.has('mirror') || risky.has('prune');
  const protectedHit = targets.some((tname) => isProtectedBranch(tname, remote, cwd, run));
  if (destructive && protectedHit) {
    const why = risky.has('delete') ? 'delete' : risky.has('mirror') ? 'mirror' : risky.has('prune') ? 'prune' : 'force';
    hit(run, 'S1', `git_push_${why}_protected_branch`);
    run.flags.add(why === 'delete' ? 'delete' : 'force');
    return;
  }
  if (protectedHit) run.flags.add('protected_branch_push');
  if (destructive) run.flags.add(risky.has('delete') ? 'delete' : 'force');
}

const AMBIGUOUS_REF_PREFIX = /^(?:refs|heads|tags|remotes)(?:\/|$)/i;

// One ref name as git would resolve it to a branch under refs/heads/, or null when it cannot be
// resolved to a single branch. Same rule as the U3 resolver.
function resolveRefName(ref: string, current: string | null): string | null {
  if (ref === 'HEAD' || ref === '@') return current;
  if (/[$`~^:?*[\\\s{}]|@\{|\.\.|\/\/|^\/|\/$|\.lock(?:\/|$)/.test(ref)) return null;
  if (ref.startsWith('refs/heads/')) {
    const branch = ref.slice('refs/heads/'.length);
    return branch && !AMBIGUOUS_REF_PREFIX.test(branch) ? branch : null;
  }
  if (/^refs\//i.test(ref)) return null;
  if (AMBIGUOUS_REF_PREFIX.test(ref) || /^(?:head|fetch_head|orig_head|merge_head)$/i.test(ref)) return null;
  return ref || null;
}

function isProtectedBranch(name: string | null, remote: string | null, cwd: string | null, run: Run): boolean {
  if (name === null || name === '*' || name === '') return true;
  const n = name.toLowerCase();
  if (run.branchRegexes.some((re) => re.test(n) || re.test(name))) return true;
  if (!cwd) return false;
  for (const r of new Set([remote || 'origin', 'origin'])) {
    let head: string | null = null;
    try { head = run.env.git.remoteHead(cwd, r); } catch { head = null; }
    if (head && head.replace(/^refs\/heads\//, '').toLowerCase() === n) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------------------------
// gh

function handleGh(rest: Arg[], ctx: Ctx, run: Run): void {
  const pos = positionals(rest, ['-R', '--repo', '-X', '--method', '-f', '-F', '--field', '--raw-field', '-H', '--header', '--input', '-q', '--jq', '-t', '--template', '--hostname', '-p', '--preview', '--cache']);
  const sub = pos[0]?.text;
  const sub2 = pos[1]?.text;
  // Destructive source control beyond a branch (S1, owner decision 2026-10-12): deleting a whole
  // repository or a release. A dynamic subcommand could be either.
  if (sub === 'repo' && (sub2 === 'delete' || sub2 === null)) { hit(run, 'S1', sub2 === null ? 'gh_dynamic_subcommand' : 'gh_repo_delete'); return; }
  if (sub === 'release' && (sub2 === 'delete' || sub2 === 'delete-asset' || sub2 === null)) { hit(run, 'S1', sub2 === null ? 'gh_dynamic_subcommand' : 'gh_release_delete'); return; }
  if (sub === null) { hit(run, 'S1', 'gh_dynamic_subcommand'); return; }
  if (sub === 'auth' && sub2 === 'token') { hit(run, 'S4', 'gh_auth_token'); return; }
  if (sub === 'auth' && sub2 === 'status' && rest.some((a) => a.text === '-t' || a.text === '--show-token')) { hit(run, 'S4', 'gh_auth_show_token'); return; }
  if (sub === 'release' && (sub2 === 'create' || sub2 === 'upload' || sub2 === 'new')) { hit(run, 'S3', 'gh_release_publish'); return; }
  if (sub === 'api' && pos[1]?.text === 'graphql') {
    const body = rest.map(argText).join(' ');
    if (/deleteRef|deleteRepository|deleteRelease|deleteBranchProtectionRule|updateRefs?\b[\s\S]*force|force[\s\S]*updateRefs?\b/i.test(body)) hit(run, 'S1', 'gh_graphql_ref_rewrite');
    return;
  }
  if (sub === 'api') {
    const endpoint = pos[1];
    // null = the method is a dynamic word: UNKNOWN below (a `?? undefined` here made it a GET).
    const method = valueFlag(rest, ['-X', '--method'], ['-X']);
    const fields: string[] = [];
    for (let i = 0; i < rest.length; i += 1) if (['-f', '-F', '--field', '--raw-field'].includes(rest[i].text || '') && rest[i + 1]) fields.push(rest[i + 1].text ?? 'force=true');
    const hasInput = rest.some((a) => a.text === '--input');
    const m = method === null ? 'UNKNOWN' : (method || (fields.length || hasInput ? 'POST' : 'GET')).toUpperCase();
    if (!endpoint) return;
    const ep = endpoint.text;
    if (ep === null) {
      if (/git\/refs|repos\//.test(endpoint.pattern) && m !== 'GET') hit(run, 'S1', 'gh_api_ref_dynamic');
      return;
    }
    let epDecoded = ep;
    try { epDecoded = decodeURIComponent(ep); } catch { epDecoded = ep; }
    // Repository, release and branch-protection deletes (S1, owner decision 2026-10-12).
    const base = epDecoded.replace(/^https?:\/\/[^/]+\/(?:api\/v3\/)?/, '').replace(/^\//, '').replace(/\?.*$/, '');
    if (m === 'DELETE' || m === 'UNKNOWN') {
      if (/^repos\/[^/]+\/[^/]+\/?$/.test(base)) { hit(run, 'S1', 'gh_api_delete_repo'); return; }
      if (/^repos\/[^/]+\/[^/]+\/releases\/[^/]+\/?$/.test(base)) { hit(run, 'S1', 'gh_api_delete_release'); return; }
      const prot = base.match(/^repos\/[^/]+\/[^/]+\/branches\/(.+?)\/protection(?:\/.*)?$/);
      if (prot && isProtectedBranch(resolveRefName(prot[1], null), 'origin', ctx.cwds[0] || null, run)) { hit(run, 'S1', 'gh_api_delete_branch_protection'); return; }
    }
    const ref = base.match(/^repos\/[^/]+\/[^/]+\/git\/refs?\/(.+)$/);
    if (!ref) return;
    // refs/heads/<name>, heads/<name> and any other form: the same rule as `git push` (audit F4).
    const full = ref[1];
    const branch = full.startsWith('heads/') ? full.slice('heads/'.length) : full.startsWith('refs/heads/') ? full.slice('refs/heads/'.length) : full;
    const forced = fields.some((f) => /^force=(?:true|1)$/i.test(f)) || hasInput || m === 'UNKNOWN';
    const resolved = full.startsWith('tags/') || full.startsWith('refs/tags/') ? 'tag' : resolveRefName(`refs/heads/${branch}`, null);
    if ((m === 'DELETE' || ((m === 'PATCH' || m === 'POST' || m === 'UNKNOWN') && forced)) && resolved !== 'tag' && isProtectedBranch(resolved, 'origin', ctx.cwds[0] || null, run)) {
      hit(run, 'S1', m === 'DELETE' ? 'gh_api_delete_protected_ref' : 'gh_api_force_protected_ref');
    }
  }
}

// ---------------------------------------------------------------------------------------------
// package managers (S3 publish, script resolution, npx, S0 uninstall)

const PNPM_BUILTINS = new Set(['add', 'install', 'i', 'update', 'up', 'upgrade', 'remove', 'rm', 'un', 'uninstall', 'link', 'ln', 'unlink', 'import', 'rebuild', 'rb', 'prune', 'fetch', 'patch', 'patch-commit', 'publish', 'pack', 'run', 'exec', 'dlx', 'create', 'test', 't', 'start', 'store', 'list', 'ls', 'outdated', 'why', 'audit', 'licenses', 'deploy', 'env', 'setup', 'init', 'doctor', 'config', 'root', 'bin', 'server', 'recursive', 'ci', 'dedupe', 'help']);
const YARN_BUILTINS = new Set(['add', 'install', 'remove', 'upgrade', 'up', 'info', 'init', 'link', 'unlink', 'list', 'outdated', 'pack', 'publish', 'run', 'test', 'why', 'workspace', 'workspaces', 'global', 'cache', 'config', 'dlx', 'exec', 'npm', 'set', 'version', 'plugin', 'node', 'bin', 'audit', 'check', 'autoclean', 'licenses', 'login', 'logout', 'owner', 'tag', 'team', 'import', 'generate-lock-entry', 'policies', 'dedupe', 'explain', 'constraints', 'patch', 'patch-commit', 'rebuild', 'search', 'stage', 'unplug', 'help']);
const BUN_BUILTINS = new Set(['run', 'test', 'x', 'repl', 'exec', 'install', 'i', 'add', 'a', 'remove', 'rm', 'update', 'outdated', 'link', 'unlink', 'publish', 'patch', 'pm', 'build', 'init', 'create', 'upgrade', 'audit', 'info', 'why']);

// npm's own subcommand resolution (audit F5): an exact name, an alias, or an unambiguous prefix of
// either (`pu`, `publ`, `unpub`, `dep`, `exe`, `x`). Ambiguous prefixes keep every reading: npm would
// refuse them, but a prefix that could be publish is treated as publish.
function npmAliasChain(name: string): string {
  let n = name;
  for (let k = 0; k < 8 && NPM_ALIASES[n]; k += 1) n = NPM_ALIASES[n];
  return n;
}
function npmCandidates(token: string): string[] {
  let c = token;
  if (/[A-Z]/.test(c)) c = c.replace(/([A-Z])/g, (m) => `-${m.toLowerCase()}`);
  if (NPM_COMMANDS.includes(c)) return [npmAliasChain(c)];
  if (NPM_ALIASES[c]) return [npmAliasChain(c)];
  if (!c) return [token];
  const out = new Set<string>();
  for (const n of [...NPM_COMMANDS, ...Object.keys(NPM_ALIASES)]) if (n.startsWith(c)) out.add(npmAliasChain(n));
  return out.size ? [...out] : [token];
}

// Positions in `rest` that may hold the subcommand. An option that takes a value is skipped with its
// value; an option the table does not know may or may not take one, so both readings are kept
// (`npm --loglevel silent publish`, `npm --frob x publish`).
function pmSubCandidates(rest: Arg[]): { idx: number[]; dynamic: boolean } {
  const idx: number[] = [];
  let unknownPending = false;
  for (let i = 0; i < rest.length; i += 1) {
    const a = rest[i];
    if (a.text === null) return { idx, dynamic: true };
    const t = a.text;
    if (t === '--') continue;
    if (t.startsWith('-') && t.length > 1) {
      if (t.includes('=')) continue;
      if (NPM_VALUE_FLAGS.has(t)) { i += 1; continue; }
      if (NPM_BOOL_FLAGS.has(t)) continue;
      unknownPending = true;
      continue;
    }
    idx.push(i);
    if (!unknownPending) break;
    unknownPending = false;
  }
  return { idx, dynamic: false };
}

function handlePackageManager(prog: string, rest: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  const cands = pmSubCandidates(rest);
  if (cands.dynamic) {
    // `npm $cmd`: the subcommand could be publish.
    worseParse(run, 'dynamic');
    tripwire(rest.map(argText).join(' '), run);
    hit(run, 'S3', `${prog}_dynamic_subcommand`);
    return;
  }
  if (cands.idx.length === 0) {
    if (prog !== 'npm') lifecycleScripts(['preinstall', 'install', 'postinstall', 'prepublish', 'preprepare', 'prepare', 'postprepare'], ctx, run, x);
    return;
  }
  const builtins = prog === 'pnpm' ? PNPM_BUILTINS : prog === 'yarn' ? YARN_BUILTINS : prog === 'bun' ? BUN_BUILTINS : null;
  for (const idx of cands.idx) {
    const tail = rest.slice(idx);
    const token = tail[0].text as string;
    const readings = prog === 'npm' ? npmCandidates(token) : [token];
    // pnpm, yarn and bun do not abbreviate, but a prefix of publish that is not one of their own
    // commands is read as publish too.
    if (prog !== 'npm' && token.length >= 2 && 'publish'.startsWith(token) && token !== 'publish' && builtins && !builtins.has(token)) readings.push('publish');
    for (const reading of readings) packageManagerCommand(prog, reading, tail, rest, ctx, run, x);
  }
}

// One reading of the subcommand. `tail` starts at the subcommand token; `all` is the whole argv (global
// flags such as -g can sit on either side of it).
function packageManagerCommand(prog: string, sub: string, tail: Arg[], all: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  const vf = ['-w', '--workspace', '--prefix', '-C', '--dir', '--filter', '-F', '--cwd', '--tag', '--access', '--otp', '--registry', '--cache', '--loglevel'];
  const rest = tail;
  const pos = positionals(rest, vf);
  const subIdx = rest.indexOf(pos[0]);
  // yarn workspace <name> <cmd…> / yarn workspaces foreach [opts] <cmd…> / pnpm recursive <cmd…>
  if (prog === 'yarn' && sub === 'workspace' && pos[1]) return handlePackageManager(prog, rest.slice(rest.indexOf(pos[1]) + 1), ctx, run, x);
  if (prog === 'yarn' && sub === 'workspaces' && pos[1]?.text === 'foreach') {
    const vfw = new Set(['--from', '--include', '--exclude', '-j', '--jobs', '--since']);
    const r2 = rest.slice(rest.indexOf(pos[1]) + 1);
    let k = 0;
    while (k < r2.length && r2[k].text !== null && (r2[k].text as string).startsWith('-')) k += vfw.has(r2[k].text as string) ? 2 : 1;
    return handlePackageManager(prog, r2.slice(k), ctx, run, x);
  }
  if (prog === 'pnpm' && (sub === 'recursive' || sub === 'multi' || sub === 'm')) return handlePackageManager(prog, rest.slice(subIdx + 1), ctx, run, x);
  const after = rest.slice(subIdx + 1);
  const global = all.some((a) => a.text === '-g' || a.text === '--global' || a.text === '--location=global');

  // yarn berry: `yarn npm publish`
  if (prog === 'yarn' && sub === 'npm' && pos[1]?.text === 'publish') return publishCheck(all, run, `${prog}_publish`);
  if (sub === 'publish') return publishCheck(all, run, `${prog}_publish`);
  if (prog === 'npm') {
    if (sub === 'unpublish') { hit(run, 'S3', 'npm_unpublish'); return; }
    if (sub === 'deprecate') { hit(run, 'S3', 'npm_deprecate'); return; }
    if (sub === 'dist-tag' && ['add', 'rm', 'set'].includes(pos[1]?.text || '')) { hit(run, 'S3', 'npm_dist_tag'); return; }
    if (sub === 'token' && ['list', 'ls', 'create'].includes(pos[1]?.text || 'list')) { hit(run, 'S4', 'npm_token'); return; }
    // Reading a registry credential back out of npm's config.
    if ((sub === 'config' && ['get', 'set'].includes(pos[1]?.text || '')) || sub === 'get') {
      const key = sub === 'get' ? pos[1] : pos[2];
      if (key && (key.text === null || /auth|token|password|cert|key|secret/i.test(key.text))) { hit(run, 'S4', 'npm_config_credential'); return; }
    }
    if (sub === 'explore') {
      const dd = after.findIndex((a) => a.text === '--');
      if (dd >= 0) dispatch(after.slice(dd + 1), ctx, run, x);
      return;
    }
    if (sub === 'init') {
      for (const a of pos.slice(1)) if (a.text === null || /^@getmarrow\//.test(a.text)) { hit(run, 'S0', 'npm_init_marrow_installer'); return; }
      return;
    }
  }
  // Removing the Marrow packages globally (S0).
  const removing = ['uninstall', 'remove', 'rm', 'un', 'r'].includes(sub) || (prog === 'yarn' && sub === 'global' && pos[1]?.text === 'remove');
  if (removing && (global || prog === 'yarn') && pos.slice(1).some((a) => a.text === null || /^@getmarrow\//.test(a.text))) { hit(run, 'S0', 'uninstall_marrow_package'); return; }
  if (removing && pos.slice(1).some((a) => a.text !== null && /^@getmarrow\//.test(a.text)) && global) { hit(run, 'S0', 'uninstall_marrow_package'); return; }

  if (prog === 'npm' && sub === 'exec') return npxLike(after, ctx, run, x);
  if (prog === 'pnpm' && (sub === 'dlx' || sub === 'exec')) return npxLike(after, ctx, run, x);
  if (prog === 'yarn' && (sub === 'dlx' || sub === 'exec')) return npxLike(after, ctx, run, x);
  if (prog === 'bun' && (sub === 'x' || sub === 'exec')) return npxLike(after, ctx, run, x);

  const isRun = sub === 'run' || sub === 'run-script';
  if (isRun || (prog === 'npm' && ['start', 'test', 'stop', 'restart'].includes(sub)) || (prog !== 'npm' && ['start', 'test', 't'].includes(sub))) {
    const name = isRun ? pos[1] : litArg(sub === 't' ? 'test' : sub);
    if (!name) return;
    if (name.text === null) {
      // A script name that cannot be resolved: the script may be a deploy (audit F2).
      worseParse(run, 'dynamic');
      tripwire(rest.map(argText).join(' '), run);
      hit(run, 'Sx', 'dynamic_script_name');
      return;
    }
    const dd = after.findIndex((a) => a.text === '--');
    const extra = isRun ? (dd >= 0 ? after.slice(dd + 1) : (prog === 'npm' ? [] : after.slice(after.indexOf(name) + 1))) : (dd >= 0 ? after.slice(dd + 1) : []);
    if (prog === 'bun' && isRun && /[./]/.test(name.text) && !/^[a-z0-9:_-]+$/i.test(name.text)) return;
    return runPackageScript(name.text, extra, ctx, run, x, true);
  }
  if (['install', 'install-test', 'install-ci-test', 'ci', 'pack', 'i'].includes(sub) && pos.length === 1) {
    lifecycleScripts(sub === 'pack' ? ['prepack', 'prepare', 'postpack'] : ['preinstall', 'install', 'postinstall', 'prepublish', 'preprepare', 'prepare', 'postprepare'], ctx, run, x);
    return;
  }
  const builtins = prog === 'pnpm' ? PNPM_BUILTINS : prog === 'yarn' ? YARN_BUILTINS : prog === 'bun' ? BUN_BUILTINS : null;
  if (builtins && !builtins.has(sub)) {
    // `pnpm <script>` / `yarn <script>` / `bun <script>`, else a package binary.
    const found = ctx.cwds.map((c) => findPackageJson(ctx, run, c));
    const isScript = found.some((f) => f.pkg && typeof f.pkg.scripts === 'object' && f.pkg.scripts && typeof (f.pkg.scripts as Record<string, unknown>)[sub] === 'string');
    if (isScript) return runPackageScript(sub, after, ctx, run, x, prog !== 'bun');
    return dispatch([litArg(sub), ...after], ctx, run, x);
  }
}

function publishCheck(after: Arg[], run: Run, reason: string): void {
  const dry = boolFlag(after, ['--dry-run'], ['--no-dry-run']);
  if (dry === 'true') { run.flags.add('dry_run_final_true'); return; }
  hit(run, 'S3', reason);
}

function handleNpx(rest: Arg[], ctx: Ctx, run: Run, x: Exec): void { npxLike(rest, ctx, run, x); }

function npxLike(rest: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  let pkgFlag: Arg | null = null;
  let i = 0;
  while (i < rest.length) {
    const t = rest[i].text;
    if (t === null) break;
    if (t === '--') { i += 1; break; }
    if (t === '-p' || t === '--package') { pkgFlag = rest[i + 1] || null; i += 2; continue; }
    if (t.startsWith('--package=')) { pkgFlag = litArg(t.slice(10)); i += 1; continue; }
    if (t === '-c' || t === '--call') { const c = rest[i + 1]; if (c) shellString(c, ctx, run, x.info.subs); return; }
    if (t.startsWith('-')) { i += 1; continue; }
    break;
  }
  if (pkgFlag && pkgFlag.text !== null && /^@getmarrow\//.test(pkgFlag.text)) { hit(run, 'S0', 'npx_marrow_installer'); return; }
  const spec = rest[i];
  if (!spec) return;
  if (spec.text === null) { worseParse(run, 'dynamic'); tripwire(rest.map(argText).join(' '), run); return; }
  const name = spec.text.startsWith('@') ? spec.text.replace(/^(@[^/]+\/[^@]+)(?:@.*)?$/, '$1') : spec.text.replace(/@.*$/, '');
  if (/^@getmarrow\//.test(name)) { hit(run, 'S0', 'npx_marrow_installer'); return; }
  const bin = pkgFlag ? (spec.text) : (PACKAGE_BINS[name] || name.split('/').pop() || name);
  // `npm exec vercel -- --prod` and `npx vercel -- --prod`: the first `--` only ends npm's own
  // options; what follows is the command's argv (audit F5).
  const fwd = rest.slice(i + 1);
  const sep = fwd.findIndex((a) => a.text === '--');
  const argv = sep >= 0 ? [...fwd.slice(0, sep), ...fwd.slice(sep + 1)] : fwd;
  dispatch([litArg(bin), ...argv], ctx, run, x);
}

// ---------------------------------------------------------------------------------------------
// S3 publish tools

function handlePublishTool(prog: string, rest: Arg[], ctx: Ctx, run: Run): boolean {
  const sub = positionals(rest, [])[0]?.text;
  const stop = (reason: string) => { hit(run, 'S3', reason); return true; };
  switch (prog) {
    case 'np': return stop('np_publish');
    case 'just': case 'task': case 'mage': case 'rake': case 'invoke': case 'nx': case 'turbo': {
      // Task runners whose recipes are not resolved: a target named like a release or deploy trips.
      for (const a of positionals(rest, ['-f', '--justfile', '-t', '--taskfile', '-d', '--dir', '--filter', '-p', '--project'])) {
        if (a.text === null) { worseParse(run, 'dynamic'); continue; }
        if (NAME_TRIPWIRE.test(a.text)) { nameTripwire(a.text, run, `${prog}_target`); }
      }
      return true;
    }
    case 'release-it': case 'semantic-release': {
      if (boolFlag(rest, ['--dry-run', '-d'], ['--no-dry-run']) === 'true') { run.flags.add('dry_run_final_true'); return true; }
      return stop(`${prog}_publish`);
    }
    case 'changeset': case 'changesets': return sub === 'publish' ? stop('changeset_publish') : true;
    case 'lerna': {
      if (sub === 'publish') return stop('lerna_publish');
      if (sub === 'exec') { const dd = rest.findIndex((a) => a.text === '--'); if (dd >= 0) dispatch(rest.slice(dd + 1), ctx, run, emptyExec()); return true; }
      if (sub === 'run') { const name = positionals(rest, ['--scope', '--ignore'])[1]; if (name) nameTripwire(argText(name), run, 'lerna_run'); return true; }
      return true;
    }
    case 'cargo': {
      if (sub === 'release') return rest.some((a) => a.text === '--execute' || a.text === '-x' || a.text === null) ? stop('cargo_release') : true;
      if (sub !== 'publish') return false;
      if (boolFlag(rest, ['--dry-run', '-n'], []) === 'true') { run.flags.add('dry_run_final_true'); return true; }
      return stop('cargo_publish');
    }
    case 'twine': return sub === 'upload' ? stop('twine_upload') : true;
    case 'uv': case 'poetry': {
      if (sub !== 'publish') return false;
      if (boolFlag(rest, ['--dry-run'], []) === 'true') { run.flags.add('dry_run_final_true'); return true; }
      return stop(`${prog}_publish`);
    }
    case 'hatch': case 'flit': return sub === 'publish' ? stop(`${prog}_publish`) : false;
    case 'gem': return sub === 'push' ? stop('gem_push') : false;
    case 'mvn': case 'mvnw':
      return rest.some((a) => a.text === null || a.text === 'deploy' || /^deploy:|^release:perform/.test(a.text)) ? stop('mvn_deploy') : true;
    case 'gradle': case 'gradlew':
      return rest.some((a) => a.text === null || (/^(?::[\w-]+)*:?publish/i.test(a.text) && !/publishToMavenLocal$/i.test(a.text))) ? stop('gradle_publish') : true;
    case 'dotnet': return sub === 'nuget' && positionals(rest, [])[1]?.text === 'push' ? stop('nuget_push') : false;
    case 'pod': return sub === 'trunk' && positionals(rest, [])[1]?.text === 'push' ? stop('pod_trunk_push') : false;
    case 'vsce': case 'ovsx': return sub === 'publish' ? stop(`${prog}_publish`) : true;
    case 'goreleaser': {
      if (sub !== undefined && sub !== null && sub !== 'release') return true;
      if (boolFlag(rest, ['--snapshot'], []) === 'true') return true;
      return stop('goreleaser_release');
    }
    default: return false;
  }
}

// ---------------------------------------------------------------------------------------------
// S2 deploy tools

function handleDeployTool(prog: string, rest: Arg[], ctx: Ctx, run: Run, x: Exec): boolean {
  const stop = (reason: string) => { hit(run, 'S2', reason); run.flags.add('prod'); return true; };
  const pos = (vf: string[]) => positionals(rest, vf);
  switch (prog) {
    case 'wrangler': {
      const p = pos(['--env', '-e', '--config', '-c', '--name', '--branch', '--project-name', '--compatibility-date', '--outdir', '--var', '--define', '--message', '--tag']);
      const s1 = p[0]?.text; const s2 = p[1]?.text;
      if (s1 === null) return stop('wrangler_dynamic_subcommand');
      const env = valueFlag(rest, ['--env', '-e']);
      if (s1 === 'deploy' || s1 === 'publish' || (s1 === 'versions' && s2 === 'deploy') || s1 === 'rollback') {
        if (env === undefined || prodValue(env)) return stop('wrangler_deploy_production');
        return true;
      }
      if (s1 === 'pages' && (s2 === 'deploy' || s2 === 'publish')) {
        // Pages decides production by the project's production branch, which the mapper cannot see:
        // only an explicit branch that is not protected or production-named is a preview.
        const branch = valueFlag(rest, ['--branch']);
        if (branch === undefined || branch === null || branch === '' || isProtectedBranch(resolveRefName(branch, null), 'origin', ctx.cwds[0] || null, run) || isProdName(branch)) return stop('wrangler_pages_production_branch');
        return true;
      }
      return true;
    }
    case 'vercel': {
      const p = pos(['--target', '--scope', '--token', '-t', '--cwd', '-A', '--local-config', '-e', '--env', '-b', '--build-env', '-m', '--meta']);
      const s1 = p[0]?.text;
      if (s1 === 'promote' || s1 === 'rollback') return stop(`vercel_${s1}`);
      const deployish = s1 === undefined || s1 === 'deploy' || (s1 !== null && !['dev', 'env', 'pull', 'link', 'login', 'logout', 'ls', 'list', 'inspect', 'logs', 'domains', 'dns', 'certs', 'secrets', 'teams', 'whoami', 'project', 'projects', 'build', 'init', 'help', 'switch', 'alias', 'remove', 'rm', 'bisect', 'git', 'redeploy', 'integration', 'telemetry'].includes(s1));
      const prod = boolFlag(rest, ['--prod', '--production'], []);
      const target = valueFlag(rest, ['--target']);
      if (s1 === 'redeploy' && (prod === 'true' || prod === 'unknown' || (target !== undefined && prodValue(target)))) return stop('vercel_redeploy_production');
      if (!deployish && s1 !== 'build') return true;
      if (s1 === 'build') return true;
      if (prod === 'true' || prod === 'unknown' || (target !== undefined && prodValue(target))) return stop('vercel_deploy_production');
      return true;
    }
    case 'netlify': case 'ntl': {
      const s1 = pos(['--dir', '-d', '--functions', '-f', '--site', '-s', '--auth', '--alias', '-a', '--message', '-m', '--filter', '--context'])[0]?.text;
      if (s1 !== 'deploy') return true;
      const prod = boolFlag(rest, ['--prod', '-p', '--prodIfUnlocked', '--prod-if-unlocked'], []);
      if (prod === 'true' || prod === 'unknown') return stop('netlify_deploy_production');
      return true;
    }
    case 'fly': case 'flyctl': {
      const p = pos(['-a', '--app', '-c', '--config', '-i', '--image', '-r', '--region', '-e', '--env', '--strategy', '--build-arg']);
      if (p[0]?.text === 'deploy' || (p[0]?.text === 'apps' && p[1]?.text === 'destroy')) return stop('fly_deploy');
      return true;
    }
    case 'firebase': {
      const p = pos(['--project', '-P', '--only', '--except', '-m', '--message', '--config', '-c', '--token']);
      if (p[0]?.text === 'deploy' || p[0]?.text === null) return stop('firebase_deploy');
      return true;
    }
    case 'heroku': {
      const s1 = pos(['-a', '--app', '-r', '--remote'])[0]?.text || '';
      if (s1 === 'auth:token') { hit(run, 'S4', 'heroku_auth_token'); return true; }
      if (/^(?:releases:rollback|rollback|container:release|container:push|pipelines:promote|builds:create|deploy|apps:destroy|destroy)$/.test(s1)) return stop('heroku_deploy');
      return true;
    }
    case 'gcloud': {
      const p = pos(['--project', '--region', '--image', '--source', '--platform', '--account', '--configuration', '--format', '--service-account', '--version', '-q']);
      const s = p.map((a) => a.text);
      if (s[0] === 'auth' && (s[1] === 'print-access-token' || s[1] === 'print-identity-token' || (s[1] === 'application-default' && /^print-/.test(s[2] || '')))) { hit(run, 'S4', 'gcloud_print_token'); return true; }
      if (s[0] === 'secrets' && s[1] === 'versions' && s[2] === 'access') { hit(run, 'S4', 'gcloud_secret_value'); return true; }
      if (s[0] === 'app' && s[1] === 'deploy') return stop('gcloud_app_deploy');
      if ((s[0] === 'run' && (s[1] === 'deploy' || (s[1] === 'services' && ['update', 'replace', 'update-traffic', 'delete'].includes(s[2] || '')))) || (s[0] === 'functions' && (s[1] === 'deploy' || s[1] === 'delete'))) {
        let project = valueFlag(rest, ['--project']);
        if (project === undefined) project = envValue(x, ctx, 'CLOUDSDK_CORE_PROJECT');
        if (project === undefined || prodValue(project)) return stop('gcloud_deploy_production');
        return true;
      }
      return true;
    }
    case 'sst': {
      const s1 = pos(['--stage', '--region', '--profile'])[0]?.text;
      if (s1 !== 'deploy' && s1 !== 'remove') return true;
      let stage = valueFlag(rest, ['--stage']);
      if (stage === undefined) stage = envValue(x, ctx, 'SST_STAGE');
      if (stage === undefined) stage = envValue(x, ctx, 'STAGE');
      if (stage === undefined) {
        for (const c of ctx.cwds) {
          if (!c) { stage = null; break; }
          const f = safeRead(run.env, path.posix.join(c, '.sst', 'stage'), 4096);
          if (f !== null) stage = f.trim();
        }
      }
      if (stage !== undefined && prodValue(stage)) return stop('sst_deploy_production');
      return true;
    }
    case 'serverless': case 'sls': {
      const s1 = pos(['--stage', '-s', '--region', '-r', '--config', '-c', '--aws-profile', '--param'])[0]?.text;
      if (s1 !== 'deploy' && s1 !== 'remove' && s1 !== 'rollback') return true;
      let stage = valueFlag(rest, ['--stage', '-s']);
      if (stage === undefined) stage = envValue(x, ctx, 'SLS_STAGE');
      if (stage === undefined) {
        for (const c of ctx.cwds) {
          const f = c ? safeRead(run.env, path.posix.join(c, 'serverless.yml'), LIMITS.maxScriptBytes) : null;
          const m = f && f.match(/^\s+stage:\s*['"]?([^'"\s#]+)/m);
          if (m) stage = /\$\{/.test(m[1]) ? null : m[1];
        }
      }
      if (stage !== undefined && prodValue(stage)) return stop('serverless_deploy_production');
      return true;
    }
    case 'cdk': {
      const p = pos(['-c', '--context', '--profile', '-a', '--app', '--require-approval', '-o', '--output', '--parameters', '-e', '--exclusively', '--role-arn', '--toolkit-stack-name', '--method', '--concurrency', '--outputs-file']);
      const s1 = p[0]?.text;
      if (s1 !== 'deploy' && s1 !== 'destroy') return true;
      const stacks = p.slice(1);
      const contexts: Array<string | null> = [];
      for (let i = 0; i < rest.length; i += 1) if ((rest[i].text === '-c' || rest[i].text === '--context') && rest[i + 1]) contexts.push(rest[i + 1].text);
      const profile = valueFlag(rest, ['--profile']);
      if (rest.some((a) => a.text === '--all') || stacks.length === 0 || stacks.some((s) => s.text === null || isProdName(s.text) || /\*/.test(s.text))
        || contexts.some((c) => c === null || PROD_ENV.test(c.split('=').slice(1).join('='))) || (profile !== undefined && prodValue(profile))) return stop('cdk_deploy_production');
      return true;
    }
    case 'terraform': case 'tofu': case 'terragrunt': {
      let i = 0;
      let dirs = ctx.cwds;
      while (i < rest.length && rest[i].text !== null && (rest[i].text as string).startsWith('-')) {
        const t = rest[i].text as string;
        if (t.startsWith('-chdir=')) { const d = t.slice(7); dirs = dirs.map((c) => (c ? path.posix.resolve(c, d) : null)); }
        i += 1;
      }
      let s1 = rest[i]?.text;
      let args = rest.slice(i + 1);
      // terragrunt run-all apply / apply-all / destroy-all
      if (prog === 'terragrunt' && (s1 === 'run-all' || s1 === 'run') && args[0]) { s1 = args[0].text; args = args.slice(1); }
      if (s1 === 'apply-all' || s1 === 'destroy-all') s1 = s1.slice(0, -4);
      if (s1 === 'workspace' && (args[0]?.text === 'select' || args[0]?.text === 'new')) {
        const ws = positionals(args.slice(1), [])[0];
        ctx.tfWorkspace = ws ? ws.text : null;
        return true;
      }
      if (s1 === null) return stop('terraform_dynamic_subcommand');
      if (s1 !== 'apply' && s1 !== 'destroy' && s1 !== 'import' && !(s1 === 'state' && ['rm', 'mv', 'push'].includes(args[0]?.text || ''))) return true;
      const varFiles: Array<string | null> = [];
      const varValues: Array<string | null> = [];
      for (let k = 0; k < args.length; k += 1) {
        const a = args[k];
        if (a.text === null) { if (/^-var/.test(a.pattern)) varValues.push(null); continue; }
        const t = a.text.replace(/^--/, '-');
        if (t === '-var-file' && args[k + 1]) { varFiles.push(args[k + 1].text); k += 1; continue; }
        if (t.startsWith('-var-file=')) { varFiles.push(t.slice(10)); continue; }
        if (t === '-var' && args[k + 1]) { varValues.push(args[k + 1].text); k += 1; continue; }
        if (t.startsWith('-var=')) { varValues.push(t.slice(5)); continue; }
      }
      const planFiles = positionals(args, ['-var', '-var-file', '-target', '-replace', '-state', '-state-out', '-backup', '-lock-timeout', '-parallelism']);
      let workspace = envValue(x, ctx, 'TF_WORKSPACE');
      if (workspace === undefined) workspace = ctx.tfWorkspace;
      if (workspace === undefined) {
        for (const d of dirs) {
          if (!d) { workspace = null; break; }
          const f = safeRead(run.env, path.posix.join(d, '.terraform', 'environment'), 4096);
          if (f !== null) workspace = f.trim();
        }
      }
      const envVar = (v: string | null) => v === null || (/^\s*(?:env|environment|stage|workspace|tier|deploy_env|target)\s*=/i.test(v) && PROD_ENV.test(v.split('=').slice(1).join('=')));
      if (workspace !== undefined && prodValue(workspace)) return stop('terraform_prod_workspace');
      if (dirs.some((d) => d === null || isProdName(d.split('/').slice(-3).join('/')))) return stop('terraform_prod_dir');
      if (varFiles.some((f) => f === null || PROD_ENV.test(path.posix.basename(f).replace(/\.tfvars(?:\.json)?$/, '')) || PROD_ENV.test(f))) return stop('terraform_prod_var_file');
      if (varValues.some(envVar)) return stop('terraform_prod_var');
      if (planFiles.some((p) => p.text === null || PROD_ENV.test(p.text))) return stop('terraform_prod_plan');
      // Nothing says which environment this is. The default workspace is often production, so an
      // apply needs positive evidence of a non-production one (production is never looser).
      const nonProd = /(?:^|[^a-z0-9])(?:dev|development|stag|staging|stage|test|testing|qa|sandbox|preview|local|demo|uat)(?:[^a-z0-9]|$)/i;
      const evidence = (typeof workspace === 'string' && workspace !== 'default' && nonProd.test(workspace))
        || varFiles.some((f) => f !== null && nonProd.test(f)) || varValues.some((v) => v !== null && nonProd.test(v))
        || dirs.some((d) => d !== null && nonProd.test(d.split('/').slice(-3).join('/')))
        || planFiles.some((p) => p.text !== null && nonProd.test(p.text));
      if (!evidence) return stop('terraform_environment_unresolved');
      return true;
    }
    case 'pulumi': {
      const p = pos(['-s', '--stack', '-C', '--cwd', '--config', '-c', '--target', '-t', '-m', '--message', '--config-file', '--parallel', '-p']);
      const s1 = p[0]?.text;
      if (s1 === 'stack' && p[1]?.text === 'select') { ctx.pulumiStack = p[2] ? p[2].text : (valueFlag(rest, ['-s', '--stack']) ?? null); return true; }
      if (!['up', 'update', 'destroy', 'refresh', 'import'].includes(s1 || '') && s1 !== null) return true;
      let stack = valueFlag(rest, ['-s', '--stack']);
      if (stack === undefined) stack = envValue(x, ctx, 'PULUMI_STACK');
      if (stack === undefined) stack = ctx.pulumiStack === undefined ? null : ctx.pulumiStack;
      if (prodValue(stack)) return stop('pulumi_production_stack');
      return true;
    }
    case 'eb': return pos(['--profile', '-r', '--region', '-l', '--label', '-m', '--message'])[0]?.text === 'deploy' ? stop('eb_deploy') : true;
    case 'railway': {
      const s1 = pos(['-e', '--environment', '-s', '--service', '-p', '--project', '-d', '--detach', '-m', '--message'])[0]?.text;
      if (s1 !== 'up' && s1 !== 'deploy' && s1 !== 'redeploy' && s1 !== null) return true;
      const environment = valueFlag(rest, ['-e', '--environment'], ['-e']);
      if (environment === undefined || prodValue(environment)) return stop('railway_deploy_production');
      return true;
    }
    case 'aws': {
      const p = pos(['--profile', '--region', '--output', '--query', '--endpoint-url', '--stack-name', '--template-file', '--parameter-overrides', '--capabilities', '--s3-bucket', '--role-arn']);
      const s = p.map((a) => a.text);
      if (s[0] === 'configure' && s[1] === 'get' && (s[2] === null || /secret|key|token/i.test(s[2] || ''))) { hit(run, 'S4', 'aws_configure_get_secret'); return true; }
      if (s[0] === 'configure' && s[1] === 'export-credentials') { hit(run, 'S4', 'aws_export_credentials'); return true; }
      if (s[0] === 'sts' && ['get-session-token', 'assume-role', 'get-federation-token'].includes(s[1] || '')) { hit(run, 'S4', 'aws_sts_credentials'); return true; }
      if (s[0] === 'secretsmanager' && s[1] === 'get-secret-value') { hit(run, 'S4', 'aws_secret_value'); return true; }
      if (s[0] === 'ssm' && /^get-parameters?(?:-by-path)?$/.test(s[1] || '') && rest.some((a) => a.text === '--with-decryption' || a.text === null)) { hit(run, 'S4', 'aws_ssm_decrypt'); return true; }
      if (s[0] === 'kms' && s[1] === 'decrypt') { hit(run, 'S4', 'aws_kms_decrypt'); return true; }
      if (s[0] === 'cloudformation' && ['deploy', 'update-stack', 'delete-stack', 'create-stack'].includes(s[1] || '')) {
        const stack = valueFlag(rest, ['--stack-name']);
        const profile = valueFlag(rest, ['--profile']);
        if (stack === undefined || prodValue(stack) || (profile !== undefined && prodValue(profile))) return stop('aws_cloudformation_production');
      }
      return true;
    }
    case 'az': {
      const p = pos(['--subscription', '-o', '--output', '--query', '--resource', '--scope', '--tenant', '-t']);
      if (p[0]?.text === 'account' && p[1]?.text === 'get-access-token') { hit(run, 'S4', 'az_get_access_token'); return true; }
      if (p[0]?.text === 'keyvault' && p[1]?.text === 'secret' && ['show', 'download'].includes(p[2]?.text || '')) { hit(run, 'S4', 'az_keyvault_secret'); return true; }
      return true;
    }
    default: return false;
  }
}

function kubeContextFromConfig(run: Run, ctx: Ctx, x: Exec, explicitConfig: string | null | undefined): string | null {
  const configs: string[] = [];
  if (explicitConfig === null) return null;
  if (explicitConfig) configs.push(explicitConfig);
  else {
    const envCfg = envValue(x, ctx, 'KUBECONFIG');
    if (envCfg === null) return null;
    if (envCfg) configs.push(...envCfg.split(':'));
    else configs.push(path.posix.join(run.home, '.kube', 'config'));
  }
  for (const c of configs) {
    const abs = absCandidates(c, ctx, run);
    if (!abs) return null;
    const content = safeRead(run.env, abs[0], LIMITS.maxConfigBytes);
    if (content === null) continue;
    const m = content.match(/^current-context:\s*['"]?([^'"\s#]+)/m);
    if (m) return m[1];
  }
  return null;
}

function handleKubectl(rest: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  const vf = ['-n', '--namespace', '--context', '--cluster', '--kubeconfig', '-s', '--server', '--user', '-f', '--filename', '-l', '--selector', '-o', '--output', '-c', '--container', '--replicas', '-p', '--patch', '--type', '-k', '--kustomize', '--as', '--token', '--image'];
  const p = positionals(rest, vf);
  const s1 = p[0]?.text;
  if (s1 === 'exec') {
    const dd = rest.findIndex((a) => a.text === '--');
    if (dd >= 0) {
      const inner = rest.slice(dd + 1);
      dispatch(inner, childCtx(ctx, { cwds: [null], remote: true, vars: new Map(), aliases: new Map() }), run, { ...x, env: new Map() });
    }
    return;
  }
  if (s1 === 'run' || s1 === 'debug' || s1 === 'create') {
    // `kubectl run NAME --image=X -- cmd args…`: runs in the cluster.
    const dd = rest.findIndex((a) => a.text === '--');
    if (dd >= 0) dispatch(rest.slice(dd + 1), childCtx(ctx, { cwds: [null], remote: true, vars: new Map(), aliases: new Map() }), run, { ...x, env: new Map() });
  }
  if (s1 === 'config' && p[1]?.text === 'use-context') { ctx.kubeContext = p[2] ? p[2].text : null; return; }
  if (s1 === 'get' && /^(?:secrets?|sec)(?:\/|$)/.test(p[1]?.text || '')) {
    // Only name and wide listings are free of secret values.
    const format = valueFlag(rest, ['-o', '--output'], ['-o']);
    if (format !== undefined && (format === null || !/^(?:name|wide)$/.test(format))) { hit(run, 'S4', 'kubectl_secret_value'); return; }
  }
  if (s1 === 'config' && p[1]?.text === 'view' && rest.some((a) => a.text === '--raw')) { hit(run, 'S4', 'kubectl_config_raw'); return; }
  if (s1 === null) { hit(run, 'S2', 'kubectl_dynamic_verb'); return; }
  if (!['apply', 'delete', 'rollout', 'scale', 'replace', 'patch', 'set', 'create', 'edit', 'drain', 'autoscale'].includes(s1 || '')) return;
  const ns = valueFlag(rest, ['-n', '--namespace'], ['-n']);
  let context = valueFlag(rest, ['--context']);
  if (context === undefined) context = ctx.kubeContext;
  if (context === undefined) context = kubeContextFromConfig(run, ctx, x, valueFlag(rest, ['--kubeconfig']));
  if (prodValue(context) || (ns !== undefined && prodValue(ns))) { hit(run, 'S2', 'kubectl_production_context'); run.flags.add('prod'); return; }
  // `kubectl delete ns production`, `kubectl delete deploy/api-prod`: the object itself is production.
  if (s1 === 'delete' || s1 === 'drain' || s1 === 'scale') {
    for (const a of p.slice(1)) {
      if (a.text === null || prodValue(a.text.replace(/^[a-z.]+\//, '')) && a.text !== '') { hit(run, 'S2', 'kubectl_production_object'); run.flags.add('prod'); return; }
    }
  }
}

function handleHelm(rest: Arg[], ctx: Ctx, run: Run): void {
  const vf = ['-n', '--namespace', '--kube-context', '--kubeconfig', '-f', '--values', '--set', '--set-string', '--version', '--repo', '-o', '--output', '--timeout'];
  const p = positionals(rest, vf);
  const s1 = p[0]?.text;
  if (!['install', 'upgrade', 'uninstall', 'delete', 'rollback', 'del', 'un'].includes(s1 || '') && s1 !== null) return;
  const ns = valueFlag(rest, ['-n', '--namespace'], ['-n']);
  let context = valueFlag(rest, ['--kube-context']);
  if (context === undefined) context = ctx.kubeContext;
  if (context === undefined) context = kubeContextFromConfig(run, ctx, emptyExec(), valueFlag(rest, ['--kubeconfig']));
  const valueFiles: Array<string | null> = [];
  for (let i = 0; i < rest.length; i += 1) if ((rest[i].text === '-f' || rest[i].text === '--values') && rest[i + 1]) valueFiles.push(rest[i + 1].text);
  if (s1 === null || prodValue(context) || (ns !== undefined && prodValue(ns)) || valueFiles.some((f) => f === null || PROD_ENV.test(path.posix.basename(f)))) { hit(run, 'S2', 'helm_production_context'); run.flags.add('prod'); }
}

function emptyExec(): Exec {
  return { cmd: { words: [], assignments: [], redirects: [], heredoc: null, heredocDynamic: false, pipedInput: false, pipesOutput: false, background: false, subshell: false }, info: { upstream: [], ansiC: false, subs: [] }, env: new Map() };
}

function handleDocker(rest: Arg[], ctx: Ctx, run: Run): void {
  // docker [global opts] exec|compose exec|container exec [opts] CONTAINER CMD...
  const globalVf = new Set(['-H', '--host', '--context', '-c', '--config', '-l', '--log-level', '--tlscacert', '--tlscert', '--tlskey']);
  let i = 0;
  while (i < rest.length && rest[i].text !== null && (rest[i].text as string).startsWith('-')) i += globalVf.has(rest[i].text as string) ? 2 : 1;
  const s0 = rest[i]?.text;
  if (s0 === 'run' || s0 === 'create' || s0 === 'start') {
    // `docker run [opts] IMAGE CMD…`: the command runs in a container (remote paths are unknowable).
    scanArgvForCommands(rest.slice(i + 1), ctx, run, emptyExec(), true);
    return;
  }
  if (s0 === 'compose' || s0 === 'container') {
    i += 1;
    if (s0 === 'compose') while (i < rest.length && rest[i].text !== null && (rest[i].text as string).startsWith('-')) i += ['-f', '--file', '-p', '--project-name', '--env-file', '--profile'].includes(rest[i].text as string) ? 2 : 1;
    if (rest[i]?.text === 'run' && s0 === 'container') { scanArgvForCommands(rest.slice(i + 1), ctx, run, emptyExec(), true); return; }
    if (rest[i]?.text !== 'exec' && rest[i]?.text !== 'run') return;
  } else if (s0 !== 'exec') return;
  i += 1;
  const execVf = new Set(['-u', '--user', '-w', '--workdir', '-e', '--env', '--env-file', '--detach-keys', '--index']);
  while (i < rest.length && rest[i].text !== null && (rest[i].text as string).startsWith('-')) i += execVf.has(rest[i].text as string) ? 2 : 1;
  const inner = rest.slice(i + 1);
  if (inner.length) dispatch(inner, childCtx(ctx, { cwds: [null], remote: true, vars: new Map(), aliases: new Map() }), run, emptyExec());
  // docker push is out of scope for v1 (owner decision Q2).
}

function handleMarrowCli(rest: Arg[], run: Run): void {
  const sub = positionals(rest, [])[0];
  if (!sub) return;
  if (sub.text === null || MARROW_OWNER_SUBS.has(sub.text)) hit(run, 'S0', 'marrow_owner_command');
}

function handleClaudeCli(rest: Arg[], run: Run): void {
  const s = positionals(rest, []).map((a) => a.text);
  if (s[0] === 'plugin' && ['uninstall', 'remove', 'disable', 'rm'].includes(s[1] || '') && (s[2] === null || /marrow/i.test(s[2] || ''))) hit(run, 'S0', 'claude_plugin_uninstall_marrow');
  if (s[0] === 'mcp' && ['remove', 'rm'].includes(s[1] || '') && (s[2] === null || /marrow/i.test(s[2] || ''))) hit(run, 'S0', 'claude_mcp_remove_marrow');
}

// ---------------------------------------------------------------------------------------------
// S4 secret dumpers that are separate programs

function handleSecretDumper(prog: string, rest: Arg[], run: Run): boolean {
  const s = positionals(rest, ['-a', '-s', '-l', '--vault', '--account', '--format', '-field', '--field', '-mount']).map((a) => a.text);
  const stop = (reason: string) => { hit(run, 'S4', reason); return true; };
  // A subcommand that is not a dump is not handled here: `op run -- <cmd>` and `pass git …` run a
  // command, so their argv goes through the unknown-program scan.
  switch (prog) {
    case 'security':
      if (/^find-(?:generic|internet)-password$/.test(rest[0]?.text || '') && rest.some((a) => a.text === '-w' || a.text === '-g')) return stop('keychain_password');
      return false;
    case 'gpg': case 'gpg2':
      return rest.some((a) => a.text !== null && /^--export-secret(?:-subkeys|-keys)?$|^--export-ssh-key$/.test(a.text)) ? stop('gpg_export_secret') : false;
    case 'secret-tool': return s[0] === 'lookup' || s[0] === null ? stop('secret_tool_lookup') : false;
    case 'op': return (s[0] === 'read' || (s[0] === 'item' && s[1] === 'get') || s[0] === null) ? stop('op_read') : false;
    case 'vault': return ((s[0] === 'kv' && ['get', 'read'].includes(s[1] || '')) || s[0] === 'read' || s[0] === null) ? stop('vault_read') : false;
    case 'pass': {
      if (s[0] === 'show' || s[0] === null) return stop('pass_show');
      if (s[0] && !['ls', 'list', 'find', 'search', 'init', 'insert', 'add', 'edit', 'generate', 'rm', 'remove', 'delete', 'mv', 'rename', 'cp', 'copy', 'git', 'help', 'version', 'grep', 'otp'].includes(s[0]) && !rest.some((a) => a.text === '-c' || a.text === '--clip')) return stop('pass_show');
      return false;
    }
    default: return false;
  }
}

// ---------------------------------------------------------------------------------------------
// S5 delete programs

function handleRm(rest: Arg[], ctx: Ctx, run: Run): void {
  let recursive = false;
  const targets: Arg[] = [];
  let after = false;
  for (const a of rest) {
    if (a.text === null) {
      if (!after && a.pattern.startsWith('-')) { recursive = true; continue; }
      targets.push(a); continue;
    }
    if (!after && a.text === '--') { after = true; continue; }
    if (!after && a.text.startsWith('--')) { const n = a.text.slice(2); if (n.length >= 1 && 'recursive'.startsWith(n)) recursive = true; continue; }
    if (!after && a.text.startsWith('-') && a.text.length > 1) { if (/[rR]/.test(a.text)) recursive = true; continue; }
    targets.push(a);
  }
  if (!recursive) return;
  for (const t of targets) checkDeleteTarget(t, ctx, run, 'rm_recursive', 'tree');
}

function handleRmdir(rest: Arg[], ctx: Ctx, run: Run): void {
  if (!rest.some((a) => a.text === '-p' || a.text === '--parents' || (a.text !== null && /^-[a-z]*p/.test(a.text)))) return;
  for (const t of nonOptions(rest)) {
    checkDeleteTarget(t, ctx, run, 'rmdir_parents', 'tree');
    if (t.text && path.posix.isAbsolute(expandTilde(t.text, run) || '')) hit(run, 'S5', 'rmdir_parents_absolute');
  }
}

function handleFind(rest: Arg[], ctx: Ctx, run: Run, x: Exec): void {
  const starts: Arg[] = [];
  let i = 0;
  while (i < rest.length && rest[i].text !== null && /^-[HLP]$|^-O\d$|^-D$/.test(rest[i].text as string)) i += rest[i].text === '-D' ? 2 : 1;
  while (i < rest.length) {
    const t = rest[i].text;
    if (t !== null && (t.startsWith('-') || t === '(' || t === '!' || t === ')')) break;
    starts.push(rest[i]);
    i += 1;
  }
  if (starts.length === 0) starts.push(litArg('.'));
  const expr = rest.slice(i);
  let deletes = false;
  for (let k = 0; k < expr.length; k += 1) {
    const t = expr[k].text;
    if (t === '-delete') deletes = true;
    if (t === '-exec' || t === '-execdir' || t === '-ok' || t === '-okdir') {
      const end = expr.findIndex((a, idx) => idx > k && (a.text === ';' || a.text === '+' || a.text === '\\;'));
      const inner = expr.slice(k + 1, end < 0 ? expr.length : end).map((a) => (a.text !== null && a.text.includes('{}') ? dynArg() : a));
      const innerProg = inner[0] ? progName(inner[0], run) : null;
      if (innerProg === 'rm' || innerProg === 'shred' || innerProg === 'unlink' || innerProg === 'rmdir') deletes = true;
      // Inner commands run with matched paths as dynamic operands.
      if (innerProg !== 'rm') dispatch(inner, ctx, run, x);
      k = end < 0 ? expr.length : end;
    }
  }
  // find … -name .env -exec cat {} : the matched names are secret files read by the inner command.
  const names: string[] = [];
  let readerExec = false;
  for (let k = 0; k < expr.length; k += 1) {
    const t = expr[k].text;
    if ((t === '-name' || t === '-iname' || t === '-path' || t === '-ipath' || t === '-wholename') && expr[k + 1]) names.push(expr[k + 1].text ?? '*');
    if ((t === '-exec' || t === '-execdir' || t === '-ok' || t === '-okdir') && expr[k + 1]) {
      const p = progName(expr[k + 1], run);
      if (p === null || !S4_EXEMPT_PROGRAMS.has(p)) readerExec = true;
    }
  }
  if (readerExec && names.length) {
    const samples = secretSamples(run.home, cwdsList(ctx));
    for (const n of names) {
      const re = patternToRegex(n.replace(/^\*\*\//, ''), false);
      if (samples.some((smp) => (re.test(path.posix.basename(smp)) || re.test(smp)) && isSecretPath(smp, run))) { hit(run, 'S4', 'find_exec_secret_name'); break; }
    }
  }
  if (deletes) for (const s of starts) {
    checkProtectedWrite(s, ctx, run, 'find_delete', false);
    checkDeleteTarget(s, ctx, run, 'find_delete', 'find');
  }
}

function handleRsync(rest: Arg[], ctx: Ctx, run: Run): void {
  // The remote shell (-e / --rsh) is a command.
  for (let k = 0; k < rest.length; k += 1) {
    const t = rest[k].text;
    const v = t === '-e' || t === '--rsh' ? rest[k + 1] : t !== null && t.startsWith('--rsh=') ? litArg(t.slice(6)) : null;
    if (v && v.text !== null && /\s|\//.test(v.text) && !/^ssh(?:\s+-[A-Za-z0-9]+(?:\s+\S+)?)*$/.test(v.text.trim())) evalShell(v.text, childCtx(ctx), run);
  }
  if (!rest.some((a) => a.text !== null && /^--(?:del|delete(?:-[a-z]+)?|remove-source-files)$/.test(a.text))) return;
  const ops = nonOptions(rest, new Set(['-e', '--rsh', '--exclude', '--include', '--filter', '-f', '--files-from', '--port', '--password-file', '--log-file', '--backup-dir', '--suffix', '--chmod', '--chown']));
  const dest = ops[ops.length - 1];
  if (!dest) return;
  if (dest.text !== null && /^[^/]*:/.test(dest.text)) { hit(run, 'S5', 'rsync_delete_remote'); return; }
  checkDeleteTarget(dest, ctx, run, 'rsync_delete', 'children');
  checkProtectedWrite(dest, ctx, run, 'rsync_delete', true);
}

function handleShred(rest: Arg[], ctx: Ctx, run: Run): void {
  if (!rest.some((a) => a.text === '-u' || a.text === '--remove' || (a.text !== null && /^-[a-z]*u/.test(a.text)))) return;
  for (const t of nonOptions(rest, new Set(['-n', '--iterations', '-s', '--size']))) checkDeleteTarget(t, ctx, run, 'shred_remove', 'tree');
}

function handleDd(rest: Arg[], run: Run): void {
  for (const a of rest) {
    if (a.text === null) { if (a.pattern.startsWith('of=')) hit(run, 'S5', 'dd_dynamic_device'); continue; }
    if (a.text.startsWith('of=/dev/') && !SAFE_DEVICES.test(a.text.slice(3))) hit(run, 'S5', 'dd_device_write');
  }
}

// ---------------------------------------------------------------------------------------------
// Grep tool glob, Edit/Write tool on protected files

function checkGrepGlob(glob: string, ctx: Ctx, run: Run): void {
  const g = glob.replace(/^\*\*\//, '');
  const re = patternToRegex(g, false);
  const samples = secretSamples(run.home, cwdsList(ctx));
  if (samples.some((s) => re.test(path.posix.basename(s)) && isSecretPath(s, run))) hit(run, 'S4', 'tool_grep_glob_secret');
}

const JSON_HOOK_CONFIG = /(?:^|\/)(?:\.claude\/settings(?:\.local)?\.json|\.codex\/hooks\.json|\.cursor\/hooks\.json|\.cursor\/mcp\.json|\.gemini\/settings\.json|\.mcp\.json)$/;

function checkToolWrite(p: string, tool: string, input: Record<string, unknown>, ctx: Ctx, run: Run): void {
  const abs = absCandidates(p, ctx, run);
  if (!abs) { hit(run, 'S0', 'tool_write_unresolved'); return; }
  let isProt = false;
  for (const a of abs) for (const r of realCandidates(a, run, true)) if (run.isProtected(run.fold ? r.toLowerCase() : r)) isProt = true;
  if (!isProt) return;
  const target = abs[0];
  if (!JSON_HOOK_CONFIG.test(target) || tool === 'apply_patch' || tool === 'notebookedit') { hit(run, 'S0', 'tool_write_protected_path'); return; }
  const before = safeRead(run.env, target, LIMITS.maxConfigBytes);
  let after: string | null = null;
  if (tool === 'write' || tool === 'write_file' || tool === 'create_file' || (tool.startsWith('str_replace') && input.command === 'create')) {
    after = typeof input.content === 'string' ? input.content : typeof input.file_text === 'string' ? input.file_text : null;
  } else {
    if (before === null) { hit(run, 'S0', 'tool_edit_hook_config_unreadable'); return; }
    const edits: Array<Record<string, unknown>> = Array.isArray(input.edits) ? input.edits as Array<Record<string, unknown>> : [input];
    after = before;
    for (const e of edits) {
      const oldS = typeof e.old_string === 'string' ? e.old_string : typeof e.old_str === 'string' ? e.old_str : null;
      const newS = typeof e.new_string === 'string' ? e.new_string : typeof e.new_str === 'string' ? e.new_str : null;
      if (oldS === null || newS === null || oldS === '') { after = null; break; }
      if (!after.includes(oldS)) { after = null; break; }
      after = e.replace_all === true ? after.split(oldS).join(newS) : after.replace(oldS, () => newS);
    }
  }
  if (after === null) { hit(run, 'S0', 'tool_edit_hook_config_unknown_result'); return; }
  const was = marrowExtract(before === null ? '{}' : before);
  const now = marrowExtract(after);
  if (was === null || now === null || was !== now) hit(run, 'S0', 'tool_edit_hook_config_changes_marrow');
}

// The parts of a hook/MCP config that keep Marrow running: hook entries that mention Marrow, any
// other hook switch (disableAllHooks …), Marrow MCP servers and env that the hook runtime reads.
function marrowExtract(text: string): string | null {
  let json: unknown;
  try { json = JSON.parse(text); } catch { return null; }
  if (!json || typeof json !== 'object' || Array.isArray(json)) return null;
  const obj = json as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  const hooks = obj.hooks;
  if (hooks && typeof hooks === 'object') {
    const h: Record<string, unknown> = {};
    for (const [event, entries] of Object.entries(hooks as Record<string, unknown>)) {
      const list = Array.isArray(entries) ? entries : [entries];
      const kept = list.filter((e) => /marrow/i.test(JSON.stringify(e)));
      if (kept.length) h[event] = kept;
    }
    out.hooks = h;
  } else if (hooks !== undefined) out.hooks = hooks;
  for (const [k, v] of Object.entries(obj)) if (k !== 'hooks' && /hook/i.test(k)) out[k] = v;
  const servers = obj.mcpServers;
  if (servers && typeof servers === 'object') {
    const m: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(servers as Record<string, unknown>)) if (/marrow/i.test(k) || /marrow/i.test(JSON.stringify(v))) m[k] = v;
    out.mcpServers = m;
  }
  const env = obj.env;
  if (env && typeof env === 'object') {
    const e: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(env as Record<string, unknown>)) if (/^MARROW_|^NODE_OPTIONS$|^NODE_PATH$|^PATH$|^HOME$/.test(k)) e[k] = v;
    out.env = e;
  }
  return JSON.stringify(Object.keys(out).sort().map((k) => [k, out[k]]));
}
