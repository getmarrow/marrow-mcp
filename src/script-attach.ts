import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync, type Stats } from 'node:fs';
import { posix } from 'node:path';
import { isSecretPath, parseShellSegments, secretPatternRegex } from './hook-tool-policy';
import { looksLikeKey, normalizeShellCommand } from './normalized-action';
import { redactSensitiveText } from './redact';
import { APPROVAL_STATE_TREE, PRESENT_SECRET_PATTERNS, SECRET_PATTERNS } from './secret-paths';

/** CL-6 client: the exact text of the local script a Claude Code Bash call runs, for the backend to judge. Data only, never a verdict; any doubt
 * attaches nothing (the backend keeps master's answer for that run). Pure apart from the injected reader; nothing is cached, logged or written.
 * Only the first script run is read, only when nothing before it can write a file, and with its local imports or not at all. */
export const SCRIPT_LIMITS = { entryBytes: 65_536, totalBytes: 262_144, entries: 8, textBytes: 8192, budgetMs: 250, depth: 3 } as const;
export type ScriptKind = 'file' | 'pkg_script' | 'make_recipe' | 'import';
export interface ScriptEntry { operand: string; kind: ScriptKind; sha256: string; content: string }
export type ScriptAttachments = { scripts: ScriptEntry[] } | { none: string };
type Lstat = { type: 'file' | 'dir' | 'symlink' | 'other'; size: number; nlink: number } | null;
/** realpath and lstat: null when missing. read: a regular file's bytes without following a final link; null when not one or over maxBytes. */
export interface ScriptReader { realpath(path: string): string | null; lstat(path: string): Lstat; read(path: string, maxBytes: number): Uint8Array | null; now?(): number }

const SAFE_WORD = /^[A-Za-z0-9_./~+@%:,-]+$/;
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
// An assignment before a run that can load other code (a shell, make or interpreter start file, a library or module path): attaches nothing.
const LOADER_VAR = /^(?:PATH|ENV|BASH_ENV|SHELLOPTS|BASHOPTS|IFS|CDPATH|MAKE\w*|MFLAGS|LD_\w*|DYLD_\w*|NODE_\w*|PYTHON\w*|PERL\w*|RUBY\w*|npm_config_\w*|GIT_\w*|\w*(?:OPTS|OPTIONS|LIB|PATH))=/i;
// A shebang the client reads as plain: an interpreter path, an optional env target and at most one short warning or trace flag.
const PLAIN_SHEBANG = /^(?!#!)|^#![ \t]*\/[\w/.-]+(?:[ \t]+[a-z][\w.-]*)?(?:[ \t]+-(?:w|e|u|x|eu|ex|I|B|E))?[ \t]*(?:\n|$)/;
// Code that moves where imports resolve from.
const IMPORT_PATH_CHANGE = /\bsys\.path\b|\baddsitedir\b|\bmodule\.paths\b|\bcreateRequire\b|\bNODE_PATH\b|\bPYTHONPATH\b/;
const PRINTABLE = /^[\x20-\x7e\n\t]*$/;
// A pipe or a background job: the other commands of the call run while the script does.
const CONCURRENT = /(?:^|[^|])\|(?!\|)|(?:^|[^&<>])&(?![&>])/;
// Programs that write no file (their literal redirects are checked).
const INERT = new Set(['ls', 'cat', 'echo', 'printf', 'grep', 'egrep', 'fgrep', 'wc', 'head', 'tail', 'cut', 'tr', 'uniq', 'pwd', 'true', 'false',
  'test', '[', 'date', 'jq', 'basename', 'dirname', 'realpath', 'readlink', 'which', 'stat', 'file', 'diff', 'cmp', 'nl', 'column', 'sha256sum', 'md5sum']);
// The flags each interpreter may carry before its file (none takes a value, code or a module); any other flag attaches nothing.
const INTERPRETERS: Record<string, RegExp> = { bash: /^-[euxv]+$/, sh: /^-[euxv]+$/, zsh: /^-[euxv]+$/, python: /^-[IBuOEsSq]+$/,
  python3: /^-[IBuOEsSq]+$/, node: /^--(?:no-warnings|enable-source-maps)$/, ruby: /^-w$/, perl: /^-w$/, php: /^-n$/ };
const JS_FILE = /\.(?:[cm]?[jt]sx?)$/;
const CREDENTIAL_DIR = /(?:^|\/)(?:\.ssh|\.aws|\.gnupg|\.marrow\/credentials|\.config\/gh|\.config\/gcloud|\.codex|\.docker|\.kube|\.azure)(?:\/|$)|(?:^|\/)auth\.json$/i;
const SECRET_RES = [...SECRET_PATTERNS, ...PRESENT_SECRET_PATTERNS].map(secretPatternRegex);
const PEM = /-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----/;
const KEY_WORD_SPLIT = /[^A-Za-z0-9+=_-]+/;
const DIGEST = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i;
// R7: a script whose file name names a credential is never read.
const SECRET_NAME = /secret|credential|token|passw|\.env/i;
// R5: a credential word on a line with a quoted literal or a word:word operand (curl -u, sshpass -p, an auth tuple or header).
const CREDENTIAL_WORD = /auth|user|pass|pwd|secret|token|api_?key|credential|basic/i;
const QUOTED_OR_PAIR = /'[^'\n]*'|"[^"\n]*"|`[^`\n]*`|[^\s:]:[^\s:]/;
// R8: code that loads or runs other code the client does not attach (a dynamic import, a worker, a fork, node or python run by a call).
const DYNAMIC_LOADER = /\bimportlib\b|__import__|\brunpy\b|\bexec[ \t]*\([ \t]*open[ \t]*\(|\bWorker\b|\bworker_threads\b|\bfork[ \t]*\(/;
const EXEC_CALL = /\b(?:spawn|spawnSync|exec|execSync|execFile|execFileSync|system|popen|Popen|run|call|check_call|check_output|getoutput|getstatusoutput|exec[lv]\w*|spawn[lv]\w*)\b/;
const INTERPRETER_WORD = /\b(?:node|nodejs|python[0-9.]*|deno|bun)\b/;
const NODE_IMPORT = /\b(?:require|import)[ \t]{0,16}\([ \t]{0,16}(['"`])([^'"`\n]{0,512})\1|\b(?:from|import)[ \t]{0,16}(['"])([^'"\n]{0,512})\3/g;
const SHELL_SOURCE = /(?:^|[;&|({]|\bthen|\bdo|\belse)[ \t]{0,64}(?:source|\.)[ \t]{1,64}([^ \t\n;&|)]{1,512})/gm;
const OTHER_IMPORT = /\brequire_relative\b|\buse[ \t]+lib\b|\b(?:require|load|include|include_once|require_once|do)[ \t(]{0,16}['"][.~/]/;

class BudgetExceeded extends Error {}
type Run = { operand: string; kind: Exclude<ScriptKind, 'import'>; dir: string; lang: string };
type Ctx = { reader: ScriptReader; home: string; roots: string[]; tick: () => void };
type Entry = { operand: string; kind: ScriptKind; content: string; real: string; lexical: string };

export function scriptAttachments(commandText: string, cwd: string, home: string, reader: ScriptReader): ScriptAttachments {
  const now = (): number => (reader.now ? reader.now() : Date.now());
  const deadline = now() + SCRIPT_LIMITS.budgetMs;
  const tick = (): void => { if (now() > deadline) throw new BudgetExceeded(); };
  try { return collect(String(commandText), cwd, home, reader, tick); } catch (error) { return { none: error instanceof BudgetExceeded ? 'budget' : 'error' }; }
}

function collect(text: string, cwd: string, home: string, reader: ScriptReader, tick: () => void): ScriptAttachments {
  if (Buffer.byteLength(text) > SCRIPT_LIMITS.textBytes || !PRINTABLE.test(text)) return { none: 'text' };
  if (process.platform === 'win32' || ![cwd, home].every((p) => typeof p === 'string' && p.startsWith('/') && !/[\\\0]/.test(p))) return { none: 'platform' };
  const segments = parseShellSegments(text);
  if (!segments || segments.length > 64) return { none: 'parse' };
  const concurrent = CONCURRENT.test(text);
  const program = (words: string[]): string => words.find((w) => !ASSIGNMENT.test(w)) || '';
  if (segments.some((s) => /^(?:cd|pushd|popd)$/.test(program(s.words))) && (concurrent || text.includes('||'))) return { none: 'cd' };
  const [realCwd, realHome] = (tick(), [reader.realpath(cwd), reader.realpath(home)]);
  if (!realCwd || !realHome) return { none: 'platform' };
  const ctx: Ctx = { reader, home: realHome, roots: [realCwd, realHome].filter((r) => r !== '/'), tick };
  let [dir, run, tainted, busy] = [realCwd, null as Run | null, false, 0];
  const writes: string[] = [];
  for (const segment of segments) {
    if (segment.outputs.some((target) => !SAFE_WORD.test(target))) return { none: 'write' };
    writes.push(...segment.outputs.map((target) => joinRaw(dir, expandHome(target, realHome))));
    const words = segment.words.slice(segment.words.indexOf(program(segment.words)));
    if (!program(segment.words)) { if (segment.words.length) { tainted = true; busy += 1; } continue; }
    if (/^(?:cd|pushd|popd)$/.test(words[0])) {
      const bad = words[0] === 'popd' || words.length !== 2 || !SAFE_WORD.test(words[1]) || /^[-~]/.test(words[1]) && !words[1].startsWith('~/');
      const next = bad ? null : (tick(), reader.realpath(joinRaw(dir, expandHome(words[1], realHome))));
      if (!next || reader.lstat(next)?.type !== 'dir') return { none: 'cd' };
      dir = next; continue;
    }
    const found = segment.words.slice(0, segment.words.indexOf(words[0])).some((w) => LOADER_VAR.test(w)) ? null : scriptRun(words, text, dir);
    if (found && !tainted && !run) run = found;
    if (found || !INERT.has(words[0]) || words.some((w) => /^-o|^--output/.test(w))) { tainted = true; busy += 1; }
  }
  if (!run || (concurrent && busy > 1)) return { none: 'no_script' };
  const group = loadGroup(ctx, run);
  if (!group) return { none: 'not_attached' };
  // R5, R8: every attached text, line by line (the file, an import, the package.json entry or the Makefile).
  if (group.some((e) => e.content.split('\n').some((line) => (tick(), withheldLine(line))) || dynamicLoader(e.content))) return { none: 'not_attached' };
  // A redirect into the script (by any name or link) changes what runs, even after the script starts: bash reads as it goes.
  const written = new Set(writes.map((w) => (secretPathLike(posix.resolve(w)) ? posix.resolve(w) : (tick(), reader.realpath(w) ?? posix.resolve(w))).toLowerCase()));
  if (group.some((e) => written.has(e.real.toLowerCase()) || written.has(posix.resolve(e.lexical).toLowerCase()))) return { none: 'written' };
  return { scripts: group.map(({ operand, kind, content }) => ({ operand, kind, sha256: createHash('sha256').update(content, 'utf8').digest('hex'), content })) };
}

const expandHome = (word: string, home: string): string => (word.startsWith('~/') ? `${home}${word.slice(1)}` : word);
/** The path as the shell names it (no lexical `..` folding, so the reader resolves it as the kernel does). */
const joinRaw = (dir: string, name: string): string => (name.startsWith('/') ? name : `${dir === '/' ? '' : dir}/${name}`);

/** The script a simple command runs (C2), or null. The program and the operand must be plain words spelled as in the text. */
function scriptRun(words: string[], text: string, dir: string): Run | null {
  const [program, ...rest] = words;
  if (!text.includes(program)) return null;
  const file = (operand: string | undefined, lang: string): Run | null => (operand !== undefined && SAFE_WORD.test(operand) && text.includes(operand)
    && !/^-|^~(?!\/)/.test(operand) ? { operand, kind: 'file', dir, lang } : null);
  if (program === 'source' || program === '.') return rest[0]?.includes('/') ? file(rest[0], 'shell') : null;
  if (program.includes('/')) return file(program, '');
  const flags = INTERPRETERS[program];
  let i = 0;
  if (flags) {
    for (; i < rest.length && rest[i].startsWith('-'); i += 1) if (!flags.test(rest[i])) return null;
    return file(rest[i], /^(?:bash|sh|zsh)$/.test(program) ? 'shell' : program.startsWith('python') ? 'python' : program === 'node' ? 'node' : 'other');
  }
  if (program === 'deno' || program === 'bun') {
    for (i = rest[0] === 'run' ? 1 : program === 'bun' ? 0 : rest.length; i < rest.length && /^(?:-A|--allow-[a-z-]+)$/.test(rest[i]) && program === 'deno'; i += 1);
    return JS_FILE.test(rest[i] || '') ? file(rest[i], 'node') : null;
  }
  const name = !/^(?:npm|pnpm|yarn)$/.test(program) ? undefined : rest.length === 1 && /^(?:test|start)$/.test(rest[0]) ? rest[0] : rest.length === 2 && rest[0] === 'run' ? rest[1] : null;
  if (name !== undefined) return name && SAFE_WORD.test(name) && !name.startsWith('-') && text.includes(name) ? { operand: name, kind: 'pkg_script', dir, lang: '' } : null;
  if (program === 'make' && rest.length === 1 && SAFE_WORD.test(rest[0]) && !rest[0].startsWith('-')) return { operand: rest[0], kind: 'make_recipe', dir, lang: '' };
  return null;
}

const secretPathLike = (path: string): boolean => [path.slice(-4096), path.slice(-4096).toLowerCase()].some((p) => CREDENTIAL_DIR.test(p) || APPROVAL_STATE_TREE.test(p)
  || isSecretPath(p) || SECRET_RES.some((re) => re.test(p)));

/** True when the client's own replacer changes nothing and no word is key-shaped (40/64-hex digests aside) or a PEM block. */
const secretFree = (text: string): boolean => !PEM.test(text) && redactSensitiveText(text) === text
  && !text.split(KEY_WORD_SPLIT).some((word) => word.length >= 12 && looksLikeKey(word) && !DIGEST.test(word));

/** R5: a line the 3A path would withhold (the normalizer's secret marker, the shared redactor, a key-shaped word, a 20+ letter or digit run, as eligibleHostText runs them), or a credential line. */
const withheldLine = (line: string): boolean => ((n) => n.truncated || n.text.includes('[secret'))(normalizeShellCommand(line)) || redactSensitiveText(line) !== line
  || line.split(/[\s=:,;@/?&'"`()[\]{}<>|!*$]+/).some((word) => !(/^[0-9a-f]+$/i.test(word) && (word.length <= 12 || word.length === 40 || word.length === 64)) && looksLikeKey(word))
  || (line.match(/[A-Za-z0-9]{20,}/g) ?? []).some((run) => !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(run)) || (CREDENTIAL_WORD.test(line) && QUOTED_OR_PAIR.test(line));

/** R8: the content loads code dynamically, or runs node or python through a call. */
function dynamicLoader(text: string): boolean {
  return DYNAMIC_LOADER.test(text) || text.split('\n').some((line) => EXEC_CALL.test(line) && INTERPRETER_WORD.test(line));
}

/** C3: the file's exact text, or null. A secret-class path is refused before it is resolved, and its target before it is read. */
function load(ctx: Ctx, lexical: string): { real: string; text: string } | null {
  const real = secretPathLike(posix.normalize(lexical)) ? null : (ctx.tick(), ctx.reader.realpath(lexical));
  if (!real || secretPathLike(real) || [lexical, real].some((p) => SECRET_NAME.test(posix.basename(p))) || !ctx.roots.some((root) => real.startsWith(`${root}/`))) return null;
  const stat = (ctx.tick(), ctx.reader.lstat(real));
  if (!stat || stat.type !== 'file' || stat.nlink !== 1 || stat.size > SCRIPT_LIMITS.entryBytes) return null;
  const bytes = (ctx.tick(), ctx.reader.read(real, SCRIPT_LIMITS.entryBytes));
  if (!bytes || bytes.length > SCRIPT_LIMITS.entryBytes || bytes.includes(0)) return null;
  const text = ((): string | null => { try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); } catch { return null; } })();
  return text !== null && secretFree(text) ? { real, text } : null;
}

/** The run's entry and its local imports (breadth first, depth 3), all or nothing. npm also runs pre<name> and post<name>: a run with either is not attached. */
function loadGroup(ctx: Ctx, run: Run): Entry[] | null {
  const at = (name: string): string => joinRaw(run.dir, expandHome(name, ctx.home));
  if (run.kind === 'pkg_script') {
    const pkg = load(ctx, at('package.json'));
    const scripts = pkg ? (JSON.parse(pkg.text) as { scripts?: Record<string, unknown> } | null)?.scripts : undefined;
    const entry = scripts && Object.prototype.hasOwnProperty.call(scripts, run.operand) ? scripts[run.operand] : undefined;
    if (!pkg || typeof entry !== 'string' || [`pre${run.operand}`, `post${run.operand}`].some((k) => k in scripts!) || !secretFree(entry)) return null;
    return [{ operand: run.operand, kind: 'pkg_script', content: entry, real: pkg.real, lexical: at('package.json') }];
  }
  if (run.kind === 'make_recipe') {
    const name = ['GNUmakefile', 'makefile', 'Makefile'].find((n) => (ctx.tick(), ctx.reader.lstat(at(n))) !== null);
    const mk = name ? load(ctx, at(name)) : null;
    return mk && !/^[ \t]*-?s?include[ \t]/m.test(mk.text) ? [{ operand: run.operand, kind: 'make_recipe', content: mk.text, real: mk.real, lexical: at(name!) }] : null;
  }
  const first = load(ctx, at(run.operand));
  const out: Entry[] = first && PLAIN_SHEBANG.test(first.text) ? [{ operand: run.operand, kind: 'file', content: first.text, real: first.real, lexical: at(run.operand) }] : [];
  let total = first ? Buffer.byteLength(first.text) : 0;
  for (let i = 0, depth = 0, level = 1; i < out.length; i += 1) {
    if (i === level) { depth += 1; level = out.length; }
    const found = importsOf(ctx, out[i], i === 0 && run.lang ? run.lang : langOf(out[i]), run.dir);
    if (found === null || (found.length && depth >= SCRIPT_LIMITS.depth)) return null;
    for (const next of found) {
      const seen = out.find((e) => e.operand === next.operand || e.real === next.real);
      if (seen && (seen.real !== next.real || seen.operand !== next.operand && seen.kind === 'import')) return null;
      if (!seen && (out.push(next) > SCRIPT_LIMITS.entries || (total += Buffer.byteLength(next.content)) > SCRIPT_LIMITS.totalBytes)) return null;
    }
  }
  return out.length ? out : null;
}

const langOf = (e: Entry): string => (/\.py$/.test(e.real) || /^#![^\n]*python/.test(e.content) ? 'python' : JS_FILE.test(e.real) || /^#![^\n]*\b(?:node|deno|bun)\b/.test(e.content) ? 'node'
  : /\.(?:sh|bash|zsh)$/.test(e.real) || /^#![^\n]*\b(?:ba|z)?sh\b/.test(e.content) ? 'shell' : 'other');

/** The local files an entry imports (C2), or null when one cannot be read or resolved without doubt (a local package's submodule, or a name that is both a file and a folder, included). */
function importsOf(ctx: Ctx, entry: Entry, lang: string, runDir: string): Entry[] | null {
  const dir = posix.dirname(entry.real);
  const found: Entry[] = [];
  const add = (operand: string, lexical: string): boolean => { const f = load(ctx, lexical); if (f) found.push({ operand, kind: 'import', content: f.text, real: f.real, lexical }); return f !== null; };
  const exists = (p: string): Lstat => (ctx.tick(), ctx.reader.lstat(p));
  if (IMPORT_PATH_CHANGE.test(entry.content)) return null;
  if (lang === 'python') {
    for (const statement of entry.content.split(/[\n;]/)) {
      const [s, from] = [statement.trim(), /^from\s+(\S+)\s+import\b/.exec(statement.trim())];
      for (const name of from ? [from[1]] : /^import\s/.test(s) ? s.slice(7).split(',').map((n) => n.trim().split(/\s/)[0]) : []) {
        if (!name || name.startsWith('.')) return null;
        const head = name.split('.')[0];
        const [file, folder] = [exists(posix.join(dir, `${head}.py`)), exists(posix.join(dir, head))];
        if (!file && !folder) continue;
        if (name !== head || (file && folder) || !add(name, posix.join(dir, file ? `${head}.py` : `${head}/__init__.py`))) return null;
      }
    }
  } else if (lang === 'node') {
    for (const m of entry.content.matchAll(NODE_IMPORT)) {
      const spec = m[2] ?? m[4];
      if (/^(?:\/|~|file:)/.test(spec) || spec.includes('${')) return null;
      if (!/^\.\.?\//.test(spec)) continue;
      const hit = ['', '.js', '.json', '.node'].map((ext) => `${posix.join(dir, spec)}${ext}`).find((p) => exists(p) !== null);
      if (!hit || hit.endsWith('.node') || exists(hit)?.type === 'dir' || !add(spec, hit)) return null;
    }
  } else if (lang === 'shell') {
    for (const m of entry.content.matchAll(SHELL_SOURCE)) {
      // `source` reads from the process's folder: only literal ./, ../, / or ~/ paths, in a script that never changes folder.
      if (/[$`"'\\*?[{]/.test(m[1]) || !/^(?:\.\.?\/|\/|~\/)/.test(m[1]) || /\b(?:cd|pushd|popd)\b/.test(entry.content) || !add(m[1], joinRaw(runDir, expandHome(m[1], ctx.home)))) return null;
    }
  } else if (OTHER_IMPORT.test(entry.content)) return null;
  return found;
}

/** The host file system for scriptAttachments: realpath, lstat and a no-follow, size-capped read. */
export function nodeScriptReader(): ScriptReader {
  const missing = (error: unknown): null => { if (/^(?:ENOENT|ENOTDIR)$/.test(String((error as { code?: string })?.code))) return null; throw error; };
  const type = (s: Stats): 'file' | 'dir' | 'symlink' | 'other' => (s.isSymbolicLink() ? 'symlink' : s.isDirectory() ? 'dir' : s.isFile() ? 'file' : 'other');
  return {
    realpath: (p) => { try { return realpathSync.native(p); } catch (error) { return missing(error); } },
    lstat: (p) => { try { const s = lstatSync(p); return { type: type(s), size: s.size, nlink: s.nlink }; } catch (error) { return missing(error); } },
    read: (p, maxBytes) => {
      const fd = openSync(p, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
      try {
        const stat = fstatSync(fd);
        const buffer = Buffer.alloc(stat.isFile() && stat.nlink === 1 && stat.size <= maxBytes ? maxBytes + 1 : 0);
        let n = 0;
        for (let r = 1; r > 0 && n < buffer.length; n += r) r = readSync(fd, buffer, n, buffer.length - n, null);
        return buffer.length && n <= maxBytes ? buffer.subarray(0, n) : null;
      } finally { closeSync(fd); }
    },
  };
}

/** C1: the runtime action gains `scripts` only when it already carries the 3A text; otherwise it is returned as it is. */
export function withScripts<T extends { tool_input?: unknown }>(action: T, attached: ScriptAttachments): T {
  const input = action.tool_input as Record<string, unknown> | undefined;
  return 'scripts' in attached && attached.scripts.length && typeof input?.command === 'string' ? { ...action, tool_input: { ...input, scripts: attached.scripts } } : action;
}
/** C4: the hold, approval and seatbelt sites carry only `scripts_sha256`, the sorted content hashes. */
export function withScriptsSha256<T extends { tool_input?: unknown }>(action: T, attached: ScriptAttachments): T {
  const hashes = 'scripts' in attached ? attached.scripts.map((e) => e.sha256).sort() : [];
  return hashes.length ? { ...action, tool_input: { ...(action.tool_input as Record<string, unknown>), scripts_sha256: hashes } } : action;
}
/** C6: a server that rejects the `scripts` key (400 or 422) gets the SAME call once more without it; nothing is cached. */
export async function runtimeWithScripts<T extends { tool_input?: unknown }, R>(action: T, attached: ScriptAttachments, send: (body: T) => Promise<R>): Promise<R> {
  const body = withScripts(action, attached);
  try { return await send(body); } catch (error) {
    if (body !== action && [400, 422].includes((error as { status?: unknown })?.status as number)) return send(action);
    throw error;
  }
}
