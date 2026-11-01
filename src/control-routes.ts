import { parseShellSegments, type ShellSegment } from './hook-tool-policy';

/**
 * MCP-10: the visible ways to switch Marrow's local control off or remove it through the installer. A command that runs the installer
 * (`npx @getmarrow/install ...`, `marrow-install ...`, `node .../@getmarrow/install/bin/marrow-install.js ...`) with a `control` word other
 * than `enable`/`status`, with `disable` or `uninstall`, or with any argument the shell expands, is a control-off route. The agent's own
 * `--yes` approves nothing: such a command is labelled `security on marrow-control` and held for the account owner.
 *
 * MCP-0: the same answer inside every shell construct that runs a command: a loop, an if or case arm, eval, a function or alias body, a wrapper
 * (sudo, env -S, timeout, xargs, find -exec, nohup, nice ...), a shell fed text (`-c`, a pipe, a file written in the same chain) and the inline
 * script of an interpreter. The text is also read after the shell takes its quoting off (quotes, backslashes, ANSI-C `$'\x69'`), with Unicode
 * compatibility forms folded, invisible characters removed and look-alike letters read as the letters they imitate: such a spelling is a hold, never a pass.
 * `controlRouteVerdict` says more than yes or no, so the seatbelt mapper's own hit (hook-pre-action.ts) can be weighed against what the walk could read.
 */
export const CONTROL_ROUTE_DENY_TEXT = 'Turning Marrow control off needs the account owner. Ask them to run it in their own terminal.';

const INSTALLER_PACKAGE = /(?:^|=)@getmarrow\/install(?:@[^\s/]*)?$/i;
const LEGACY_INSTALLER_BIN = /(?:^|\/)marrow-install(?:\.[cm]?js)?$/i;
// The walk also knows the owner CLI `marrow control ...` / `marrow uninstall` (the seatbelt mapper treats it as the installer's owner commands).
const INSTALLER_BIN = /(?:^|\/)marrow(?:-install)?(?:\.[cm]?js)?$/i;
const OWNER_CLI_TEXT = /\bmarrow\s+(?:control|uninstall|claim|unclaim)\b/i;
const INSTALLER_PATH = /@getmarrow\/install\//i;
const INSTALLER_TEXT = /@getmarrow\/install|marrow-install/i;
const LEGACY_WRAPPER = /^(?:sudo|env|nohup|time|exec|command|builtin|nice|ionice|stdbuf|timeout|xargs|setsid)$/;
const WRAPPER = /^(?:sudo|doas|env|nohup|time|exec|command|builtin|nice|ionice|stdbuf|timeout|xargs|setsid|eval|unbuffer)$/;
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const SHELL_PROGRAM = /^(?:sh|bash|zsh|dash|ksh)$/;
// Programs that can run an installer package or file: a grep, a cat or a commit message that merely names it is not a route.
const RUNNER = /^(?:npx|pnpx|bunx|npm|pnpm|yarn|bun|node|nodejs|deno|corepack)$/;
// Programs whose inline script (`-e`, `-c`, `-r`, `eval`) can run a command.
const INTERPRETER = /^(?:node|nodejs|deno|bun|python[0-9.]*|pypy[0-9]*|perl|ruby|php|lua|osascript|pwsh|powershell|rscript|tclsh)$/;
// Programs that only print, copy or move the text they are given. (git, gh, sed, awk and find can run a command: they are not here.)
const DATA_PROGRAM = /^(?:echo|printf|cat|tac|head|tail|less|more|grep|egrep|fgrep|rg|ag|ls|wc|cp|mv|ln|rm|touch|mkdir|rmdir|tee|diff|cmp|sort|uniq|cut|tr|basename|dirname|realpath|readlink|stat|file|du|which|type|whereis|pwd|cd|pushd|popd|test|\[|true|false|date|sleep|jq)$/;
// A program given by path (a script the chain may have written) that is not a system binary, and the flags that hand an interpreter its script inline.
const SCRIPT_PATH = /^(?:\.{1,2}\/|~\/|\/(?!(?:usr\/)?(?:local\/)?s?bin\/))/;
const INLINE_SCRIPT_FLAG = /^(?:-[A-Za-z]*[ecrpE][A-Za-z]*|--eval|--print|--command|eval)$/;
const SAFE_CONTROL_SUBCOMMAND = new Set(['enable', 'status']);
// Words that start a command without being one (`do npx ...`, `then ...`) and words that start no command (`for x in ...`, `done`).
const COMMAND_KEYWORD = new Set(['!', 'if', 'then', 'elif', 'else', 'do', 'while', 'until', '{', 'coproc']);
const NO_COMMAND_KEYWORD = new Set(['for', 'select', 'case', 'done', 'fi', 'esac', '}', 'in', 'function']);
// The words the unparseable-text rule looks for (3.9.109: `control|disable|uninstall|[$`]`), and the control-off words alone (mapper-failure rule).
const FALLBACK_WORDS = /control|disable|uninstall|[$`]/i;
const CHAIN_CONTROL_WORDS = /control|disable|uninstall/i;
const CONTROL_OFF_WORDS = /\b(?:disable|uninstall)\b|\bcontrol\b\s*(?:off|remove|stop)\b/i;
// An inline script that builds a word out of parts cannot be read for what it runs.
const COMPOSED_TEXT = /\+|\$\{|%[sd]|\.format\(|\.join\(|\bf["']|concat|atob|fromCharCode|\bchr\(|\\x|\\u/;
const MAX_DEPTH = 3;
const MAX_DECODE_CHARS = 262_144;

// ---- reading the text the way the shell does -----------------------------------------------------------------------------------------------

const ANSI_C_SIMPLE: Record<string, string> = { a: '\x07', b: '\b', e: '\x1b', E: '\x1b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v', '\\': '\\', "'": "'", '"': '"', '?': '?' };

function codePoint(value: number): string {
  return Number.isInteger(value) && value >= 0 && value <= 0x10ffff && !(value >= 0xd800 && value <= 0xdfff) ? String.fromCodePoint(value) : '';
}

// Reads the inside of a double-quoted run from index; returns the index after the closing quote.
function doubleQuoted(text: string, from: number, out: string[]): number {
  let at = from;
  while (at < text.length) {
    const char = text[at];
    if (char === '"') return at + 1;
    if (char === '\\' && at + 1 < text.length && '$`"\\\n'.includes(text[at + 1])) {
      if (text[at + 1] !== '\n') out.push(text[at + 1]);
      at += 2;
      continue;
    }
    out.push(char);
    at += 1;
  }
  return at;
}

// Reads the inside of an ANSI-C `$'...'` run from index; returns the index after the closing quote.
function ansiC(text: string, from: number, out: string[]): number {
  let at = from;
  while (at < text.length) {
    const char = text[at];
    if (char === "'") return at + 1;
    if (char !== '\\' || at + 1 >= text.length) { out.push(char); at += 1; continue; }
    const next = text[at + 1];
    const hex = next === 'x' ? /^[0-9a-fA-F]{1,2}/.exec(text.slice(at + 2, at + 4)) : next === 'u' ? /^[0-9a-fA-F]{1,4}/.exec(text.slice(at + 2, at + 6)) : next === 'U' ? /^[0-9a-fA-F]{1,8}/.exec(text.slice(at + 2, at + 10)) : null;
    const octal = /^[0-7]{1,3}/.exec(text.slice(at + 1, at + 4));
    if (hex) { out.push(codePoint(parseInt(hex[0], 16))); at += 2 + hex[0].length; } else if (next === 'c' && at + 2 < text.length) {
      out.push(String.fromCharCode(text.charCodeAt(at + 2) & 0x1f));
      at += 3;
    } else if (octal) { out.push(String.fromCharCode(parseInt(octal[0], 8) & 0xff)); at += 1 + octal[0].length; } else if (ANSI_C_SIMPLE[next] !== undefined) { out.push(ANSI_C_SIMPLE[next]); at += 2; } else { out.push('\\', next); at += 2; }
  }
  return at;
}

/** The text with the shell's quoting taken off: `'..'`, `".."`, a backslash, a line continuation and an ANSI-C `$'\x69'` read as the characters they give. */
export function unquoteShell(text: string): string {
  const out: string[] = [];
  let at = 0;
  while (at < text.length) {
    const char = text[at];
    const next = text[at + 1];
    if (char === '\\') {
      if (next === undefined) { out.push(char); break; }
      if (next !== '\n') out.push(next);
      at += 2;
    } else if (char === "'") {
      const end = text.indexOf("'", at + 1);
      out.push(text.slice(at + 1, end < 0 ? text.length : end));
      at = end < 0 ? text.length : end + 1;
    } else if (char === '"') at = doubleQuoted(text, at + 1, out);
    else if (char === '$' && next === "'") at = ansiC(text, at + 2, out);
    else if (char === '$' && next === '"') at = doubleQuoted(text, at + 2, out);
    else { out.push(char); at += 1; }
  }
  return out.join('');
}

const INVISIBLE = /[­͏؜ᅟᅠ឴឵᠋-᠏​-‏‪-‮⁠-⁯ㅤ︀-️﻿ﾠ￹-￻]|[\u{e0000}-\u{e0fff}]/gu;
// Letters of other alphabets that are drawn like a Latin letter (NFKC already folds the full-width and styled forms): read as that letter.
const LOOKALIKE: Record<string, string> = {
  'а': 'a', 'в': 'b', 'с': 'c', 'ԁ': 'd', 'е': 'e', 'һ': 'h', 'і': 'i', 'ј': 'j', 'к': 'k', 'ӏ': 'l', 'м': 'm', 'о': 'o', 'р': 'p', 'ԛ': 'q', 'ѕ': 's', 'т': 't', 'ѵ': 'v', 'ԝ': 'w', 'х': 'x', 'у': 'y',
  'α': 'a', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x',
  'ɑ': 'a', 'ɡ': 'g', 'ı': 'i', 'ɩ': 'i', 'օ': 'o', 'ո': 'n', 'ս': 'u',
  'ᴀ': 'a', 'ʙ': 'b', 'ᴄ': 'c', 'ᴅ': 'd', 'ᴇ': 'e', 'ɢ': 'g', 'ʜ': 'h', 'ᴊ': 'j', 'ᴋ': 'k', 'ʟ': 'l', 'ᴍ': 'm', 'ɴ': 'n', 'ᴏ': 'o', 'ᴘ': 'p', 'ʀ': 'r', 'ꜱ': 's', 'ᴛ': 't', 'ᴜ': 'u', 'ᴠ': 'v', 'ᴡ': 'w', 'ᴢ': 'z',
};

/** Compatibility forms folded (NFKC) and invisible characters removed. */
export function foldText(text: string): string {
  return text.replace(INVISIBLE, '').normalize('NFKC').replace(INVISIBLE, '');
}

function skeleton(text: string): string {
  let out = '';
  for (const char of text) {
    const lower = char.toLowerCase();
    const letter = LOOKALIKE[lower];
    out += letter === undefined ? char : char === lower ? letter : letter.toUpperCase();
  }
  return out;
}

/** The ways the text can be read: as written, folded, unquoted, and each with look-alike letters read as the letters they imitate. */
export function controlTextViews(command: string): string[] {
  const views = [command];
  if (command.length > MAX_DECODE_CHARS) return views;
  const folded = foldText(command);
  const decoded = foldText(unquoteShell(command));
  for (const view of [folded, decoded, skeleton(folded), skeleton(decoded)]) if (!views.includes(view)) views.push(view);
  return views;
}

const foldWord = (word: string): string => skeleton(foldText(word));

/** Whether any reading of the text names the installer (`@getmarrow/install`, `marrow-install`). */
export function namesInstaller(command: string): boolean {
  return controlTextViews(command).some(namesInstallerView);
}

/** Whether any reading of the text names the installer or a control-off word (`disable`, `uninstall`). */
export function namesControlOff(views: string[]): boolean {
  return views.some((view) => namesInstallerView(view) || CONTROL_OFF_WORDS.test(view));
}

// ---- the walk -------------------------------------------------------------------------------------------------------------------------------

export type ControlVerdict = 'route' | 'cleared' | 'unread' | 'none';

type Walk = {
  depth: number;
  route: boolean;
  /** A part of the text names the installer and the walk could not read what it does with it. */
  unread: boolean;
  /** A part of the chain gives text to a shell (a file or input to run), without a `-c` string. */
  executes: boolean;
  /** A part of the chain that runs no installer names it (an echo, a printf, a heredoc): text a later part may run. */
  named: boolean;
  defs: Map<string, string>;
  aliases: Map<string, string>;
};

function baseName(word: string): string {
  const cut = word.lastIndexOf('/');
  return cut < 0 ? word : word.slice(cut + 1);
}

function installerArguments(words: string[], bin: RegExp = INSTALLER_BIN): string[] | null {
  const marker = words.findIndex((word) => INSTALLER_PACKAGE.test(word) || bin.test(word) || INSTALLER_PATH.test(word));
  return marker < 0 ? null : words.slice(marker + 1);
}

const namesInstallerView = (view: string): boolean => INSTALLER_TEXT.test(view) || OWNER_CLI_TEXT.test(view);

function routeArguments(args: string[], segment: ShellSegment): boolean {
  if (segment.expansions.length > 0 || args.some((arg) => /[$`*?[~]/.test(arg))) return true;
  if (args.some((arg) => /^-{0,2}(?:disable|uninstall)$/i.test(arg))) return true;
  const control = args.findIndex((arg) => arg.toLowerCase() === 'control');
  if (control < 0) return false;
  const subcommands = args.slice(control + 1).filter((arg) => !arg.startsWith('-')).map((arg) => arg.toLowerCase());
  return !(subcommands.length > 0 && subcommands.every((arg) => SAFE_CONTROL_SUBCOMMAND.has(arg)));
}

// The options of a wrapper that take the next word as their value (`sudo -u root`, `timeout -s KILL 30`, `nice -n 5`, `env -u NAME`).
const VALUE_OPTIONS: Record<string, Set<string>> = {
  sudo: new Set(['-u', '-g', '-h', '-p', '-C', '-D', '-r', '-t', '-T', '-U', '-R', '--user', '--group', '--host', '--prompt', '--chdir', '--role', '--type']),
  doas: new Set(['-u', '-C']),
  env: new Set(['-u', '-C', '-P', '--unset', '--chdir']),
  timeout: new Set(['-s', '-k', '--signal', '--kill-after']),
  nice: new Set(['-n', '--adjustment']),
  ionice: new Set(['-c', '-n', '-p', '-P', '-u', '--class', '--classdata']),
  stdbuf: new Set(['-i', '-o', '-e', '--input', '--output', '--error']),
  exec: new Set(['-a']),
  time: new Set(['-f', '-o', '--format', '--output']),
  xargs: new Set(['-n', '-I', '-P', '-d', '-L', '-s', '-E', '-a', '--max-args', '--max-procs', '--delimiter', '--max-lines', '--max-chars', '--arg-file', '--eof']),
};
const DURATION = /^\d+(?:\.\d+)?[smhd]?$/;

const splitWords = (text: string): string[] => text.split(/\s+/).filter(Boolean);

function substitute(word: string, defs: Map<string, string>): string {
  if (!defs.size || !word.includes('$')) return word;
  return word.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (all, braced: string | undefined, plain: string | undefined) => defs.get(braced ?? plain ?? '') ?? all);
}

function note(word: string, defs: Map<string, string>): void {
  const equals = word.indexOf('=');
  if (equals > 0) defs.set(word.slice(0, equals), word.slice(equals + 1));
}

function nested(text: string, st: Walk): void {
  const verdict = controlRouteVerdict(text, st.depth + 1);
  if (verdict === 'route') st.route = true;
  else if (verdict === 'unread') st.unread = true;
}

/** Words after the wrappers (sudo, env, timeout, nice, xargs ...), the text an `eval` or `env -S` hands to a shell is read at once (null). */
function unwrap(words: string[], st: Walk): { words: string[]; xargs: boolean } | null {
  let at = 0;
  let xargs = false;
  while (at < words.length && WRAPPER.test(baseName(words[at]))) {
    const wrapper = baseName(words[at]);
    at += 1;
    if (wrapper === 'eval') { nested(words.slice(at).join(' '), st); return null; }
    if (wrapper === 'xargs') xargs = true;
    const values = VALUE_OPTIONS[wrapper];
    while (at < words.length) {
      const word = words[at];
      if (wrapper === 'env' && (word === '-S' || word === '--split-string' || /^-S.+/.test(word) || word.startsWith('--split-string='))) {
        const attached = word.startsWith('--split-string=') ? word.slice(15) : /^-S.+/.test(word) ? word.slice(2) : words[at + 1] ?? '';
        const used = word === '-S' || word === '--split-string' ? 2 : 1;
        nested([attached, ...words.slice(at + used)].join(' '), st);
        return null;
      }
      if (word === '--') { at += 1; break; }
      if (word.startsWith('-') && word.length > 1) { at += 1; if (values?.has(word)) at += 1; continue; }
      if (ASSIGNMENT.test(word) || /^\d+$/.test(word) || (wrapper === 'timeout' && DURATION.test(word))) { at += 1; continue; }
      break;
    }
  }
  return { words: words.slice(at), xargs };
}

// `find ... -exec CMD ... ;` runs CMD: each clause is a command of its own.
function findClauses(words: string[]): string[][] {
  const clauses: string[][] = [];
  words.forEach((word, index) => {
    if (!['-exec', '-execdir', '-ok', '-okdir'].includes(word)) return;
    const rest = words.slice(index + 1);
    const end = rest.findIndex((item) => item === ';' || item === '+');
    clauses.push(end < 0 ? rest : rest.slice(0, end));
  });
  return clauses;
}

function inlineCodeRoutes(code: string, others: string[]): boolean {
  const tokens = code.split(/[^A-Za-z0-9_@/.$-]+/).filter(Boolean);
  const first = tokens.findIndex((token) => INSTALLER_TEXT.test(token) || token === 'marrow');
  const args = [...(first < 0 ? tokens : tokens.slice(first + 1)), ...others];
  return routeArguments(args, { words: [], outputs: [], inputs: [], expansions: [] });
}

function segmentCheck(segment: ShellSegment, st: Walk): void {
  let at = 0;
  while (at < segment.words.length && COMMAND_KEYWORD.has(segment.words[at])) at += 1;
  let words = segment.words.slice(at);
  if (!words.length || NO_COMMAND_KEYWORD.has(words[0])) return;
  at = 0;
  while (at < words.length && ASSIGNMENT.test(words[at])) { note(words[at], st.defs); at += 1; }
  words = words.slice(at);
  if (!words.length) return;
  if (/^(?:export|declare|typeset|local|readonly)$/.test(words[0])) { for (const word of words.slice(1)) note(word, st.defs); return; }
  if (words[0] === 'alias') {
    for (const word of words.slice(1)) {
      const equals = word.indexOf('=');
      if (equals > 0) st.aliases.set(word.slice(0, equals), word.slice(equals + 1));
    }
    return;
  }
  words = words.map((word) => substitute(word, st.defs));
  const expansions = segment.expansions.filter((name) => !st.defs.has(foldWord(name)));
  for (let round = 0; round < 4 && st.aliases.has(words[0]); round += 1) words = [...splitWords(st.aliases.get(words[0]) as string), ...words.slice(1)];
  if (/\s/.test(words[0])) words = [...splitWords(words[0]), ...words.slice(1)];
  const unwrapped = unwrap(words, st);
  if (!unwrapped || !unwrapped.words.length) return;
  words = unwrapped.words;
  const here: ShellSegment = { ...segment, words, expansions };
  const program = words[0];
  const name = baseName(program);
  // A program the walk cannot name (an expansion, a script by path) runs what an earlier part of the chain wrote or set.
  if (/[$`]/.test(program) || SCRIPT_PATH.test(program)) st.executes = true;
  if (SHELL_PROGRAM.test(name)) {
    const flag = words.findIndex((word, index) => index > 0 && /^-[A-Za-z]*c[A-Za-z]*$/.test(word));
    if (flag > 0 && words[flag + 1] !== undefined) nested(words[flag + 1], st);
    else st.executes = true;
    return;
  }
  if (name === '.' || name === 'source') { st.executes = true; return; }
  if (name === 'find') { for (const clause of findClauses(words)) segmentCheck({ ...here, words: clause }, st); }
  if (INTERPRETER.test(name)) {
    // No inline script flag: it runs a file, a module or its input.
    if (!words.slice(1).some((word) => INLINE_SCRIPT_FLAG.test(word))) st.executes = true;
    words.forEach((word, index) => {
      if (index === 0 || !namesInstallerView(word) || !/[\s('"`]/.test(word)) return;
      if (inlineCodeRoutes(word, words.filter((_, other) => other !== index && other !== 0))) st.route = true;
      else if (COMPOSED_TEXT.test(word)) st.unread = true;
    });
  }
  const runs = RUNNER.test(name) || INSTALLER_BIN.test(program) || INSTALLER_PATH.test(program) || /[$`]/.test(program);
  if (runs) {
    for (const word of words.slice(1)) if (/\s/.test(word) && namesInstallerView(word) && !INTERPRETER.test(name)) nested(word, st);
    const args = installerArguments(words);
    if (args !== null && (unwrapped.xargs || routeArguments(args, here))) st.route = true;
    return;
  }
  if (words.some(namesInstallerView)) {
    st.named = true;
    // `!cmd` is a shell alias in a git or gh setting (`git -c alias.x='!cmd' x`): the text after the bang is a command.
    for (const word of words) {
      const alias = /^(?:[^=\s]*=)?!([^]+)$/.exec(word);
      if (alias && namesInstallerView(alias[1])) nested(alias[1], st);
    }
    if (!DATA_PROGRAM.test(name) && !INTERPRETER.test(name) && name !== 'find') st.unread = true;
  }
}

function walkSegments(segments: ShellSegment[], views: string[], depth: number): ControlVerdict {
  const st: Walk = { depth, route: false, unread: false, executes: false, named: false, defs: new Map(), aliases: new Map() };
  for (const segment of segments) {
    segmentCheck({ ...segment, words: segment.words.map(foldWord) }, st);
    if (st.route) return 'route';
  }
  // Text one part of the chain prints or writes and another part hands to a shell (`echo '...' | sh`, `printf ... > f; . f`) is the command it names.
  if (st.executes && st.named && views.some((view) => CHAIN_CONTROL_WORDS.test(view))) return 'route';
  return st.unread ? 'unread' : 'cleared';
}

/**
 * What the walk makes of the shell text. `route`: it runs the installer in a way that can switch control off, remove it, or cannot be read as one fixed command.
 * `cleared`: it names the installer and every part that does was read and is no route (`doctor`, `setup`, `control status`, a message that names it).
 * `unread`: it names the installer and a part of it could not be read. `none`: no reading of it names the installer.
 */
export function controlRouteVerdict(command: string, depth = 0): ControlVerdict {
  try {
    if (typeof command !== 'string') return 'none';
    const views = controlTextViews(command);
    if (!views.some(namesInstallerView)) return 'none';
    if (depth > MAX_DEPTH) return 'route';
    const segments = parseShellSegments(command);
    // A command the parser cannot read that names the installer next to a control word is held, never guessed at.
    if (!segments) return views.some((view) => FALLBACK_WORDS.test(view)) ? 'route' : 'unread';
    return walkSegments(segments, views, depth);
  } catch {
    return 'route';
  }
}

// 3.9.109's reading (control-routes.ts at 990aaaa6, lines 41-67), kept as it was: the walk above can only add routes to it, never take one away.
function legacySegmentIsRoute(segment: ShellSegment, depth: number): boolean {
  let at = 0;
  while (at < segment.words.length && ASSIGNMENT.test(segment.words[at])) at += 1;
  while (at < segment.words.length && LEGACY_WRAPPER.test(baseName(segment.words[at]))) {
    at += 1;
    while (at < segment.words.length && (segment.words[at].startsWith('-') || ASSIGNMENT.test(segment.words[at]) || /^\d+$/.test(segment.words[at]))) at += 1;
  }
  const words = segment.words.slice(at);
  if (!words.length) return false;
  if (SHELL_PROGRAM.test(baseName(words[0]))) {
    const flag = words.findIndex((word, index) => index > 0 && /^-[A-Za-z]*c[A-Za-z]*$/.test(word));
    if (flag > 0 && words[flag + 1] !== undefined) return controlRoute(words[flag + 1], depth + 1);
  }
  const program = words[0];
  const runs = RUNNER.test(baseName(program)) || LEGACY_INSTALLER_BIN.test(program) || INSTALLER_PATH.test(program) || /[$`]/.test(program);
  const args = runs ? installerArguments(words, LEGACY_INSTALLER_BIN) : null;
  return args !== null && routeArguments(args, segment);
}

function legacyRoute(command: string, depth: number): boolean {
  try {
    if (typeof command !== 'string' || !INSTALLER_TEXT.test(command)) return false;
    if (depth > MAX_DEPTH) return true;
    const segments = parseShellSegments(command);
    if (!segments) return /control|disable|uninstall|[$`]/i.test(command);
    return segments.some((segment) => legacySegmentIsRoute(segment, depth));
  } catch {
    return true;
  }
}

/** Whether the shell text runs the installer in a way that can switch Marrow control off, remove it, or cannot be read as one fixed command. */
export function controlRoute(command: string, depth = 0): boolean {
  return legacyRoute(command, depth) || controlRouteVerdict(command, depth) === 'route';
}
