import { parseShellSegments, type ShellSegment } from './hook-tool-policy';

/**
 * MCP-10: the visible ways to switch Marrow's local control off or remove it through the installer. A command that runs the installer
 * (`npx @getmarrow/install ...`, `marrow-install ...`, `node .../@getmarrow/install/bin/marrow-install.js ...`) with a `control` word other
 * than `enable`/`status`, with `disable` or `uninstall`, or with any argument the shell expands, is a control-off route. The agent's own
 * `--yes` approves nothing: such a command is labelled `security on marrow-control` and held for the account owner.
 * CL-5: only a command in a position that runs counts (the program word, a runner's package or file argument, the code of `-c`, `eval`,
 * `$( )` or backticks); the installer's name in a data operand, a folder name or a message is not a route.
 */
export const CONTROL_ROUTE_DENY_TEXT = 'Turning Marrow control off needs the account owner. Ask them to run it in their own terminal.';

const INSTALLER_PACKAGE = /(?:^|=)@getmarrow\/install(?:@[^\s/]*)?$/i;
const INSTALLER_BIN = /(?:^|\/)marrow-install(?:\.[cm]?js)?$/i;
const INSTALLER_PATH = /@getmarrow\/install\//i;
const INSTALLER_TEXT = /@getmarrow\/install|marrow-install/i;
const INSTALLER_TEXT_ALL = /@getmarrow\/install|marrow-install/gi;
const L1_PROGRAM = /^(?:printf|echo|grep|git|cat|cd|ls)$/; // CL-5 L1: the owner-decided data programs
const WRAPPER = /^(?:sudo|env|nohup|time|exec|command|builtin|nice|ionice|stdbuf|timeout|xargs|setsid)$/;
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const KEYWORD = /^(?:do|then|else|elif|if|while|until|!)$/;
const SHELL_PROGRAM = /^(?:sh|bash|zsh|dash|ksh|su)$/;
const STDIN_SHELL = /^(?:sh|bash|zsh|dash|ksh|su|eval|source|\.)$/; // reads its code from stdin, a here-doc or a file
// Programs that can run an installer package or file: a grep, a cat or a commit message that merely names it is not a route.
const RUNNER = /^(?:npx|pnpx|bunx|npm|pnpm|yarn|bun|node|nodejs|deno|corepack)$/;
const RUNNER_SUBCOMMAND = /^(?:exec|x|dlx|run)$/;
const DYNAMIC = /[$`*?[]/;
const SAFE_CONTROL_SUBCOMMAND = new Set(['enable', 'status']);
const INTERPRETER = /^(?:python[0-9.]*|node|nodejs|deno|bun|ruby|perl|php)$/i; // M-SELF-APPROVE (g): runs code that can send a request
const HTTP_CLIENT = /^(?:curl|wget|http|https|httpie|xh|aria2c|nc)$/i;
const REPORT_SCRIPT = /^(?:host[_-]?report|approval[_-]link|host[_-]approval)(?:\.[^/]*)?$/i;
const REPORT_TEXT = /host[_-]?report|approval[_-]link|host[_-]approval/i;
const MAX_DEPTH = 3;
// Past this size a text keeps the 3.9.113 answer (the whole-text word check), so the reading stays inside the hook's budget.
const MAX_READ = 32_768;

type Rule = (words: string[], dynamic: boolean, depth: number) => boolean;

function baseName(word: string): string {
  const cut = word.lastIndexOf('/');
  return cut < 0 ? word : word.slice(cut + 1);
}

function installerArguments(words: string[]): string[] | null {
  const marker = words.findIndex((word) => INSTALLER_PACKAGE.test(word) || INSTALLER_BIN.test(word) || INSTALLER_PATH.test(word));
  return marker < 0 ? null : words.slice(marker + 1);
}

function routeArguments(args: string[], dynamic: boolean): boolean {
  if (dynamic || args.some((arg) => /[$`*?[~]/.test(arg))) return true;
  if (args.some((arg) => /^-{0,2}(?:disable|uninstall)$/i.test(arg))) return true;
  const control = args.findIndex((arg) => arg.toLowerCase() === 'control');
  if (control < 0) return false;
  const subcommands = args.slice(control + 1).filter((arg) => !arg.startsWith('-')).map((arg) => arg.toLowerCase());
  return !(subcommands.length > 0 && subcommands.every((arg) => SAFE_CONTROL_SUBCOMMAND.has(arg)));
}

/** The words from the program on: leading assignments, shell keywords and wrappers (with their options) skipped. */
function programWords(words: string[]): string[] {
  let at = 0;
  for (;;) {
    const start = at;
    while (at < words.length && (ASSIGNMENT.test(words[at]) || KEYWORD.test(words[at]))) at += 1;
    while (at < words.length && WRAPPER.test(baseName(words[at]))) {
      at += 1;
      while (at < words.length && (words[at].startsWith('-') || ASSIGNMENT.test(words[at]) || /^\d+$/.test(words[at]))) at += 1;
    }
    if (at === start) return words.slice(at);
  }
}

/** The code a shell `-c`, `su -c` or `eval` runs, or null. */
function innerCode(words: string[]): string | null {
  if (words[0] === 'eval') return words.length > 1 ? words.slice(1).join(' ') : null;
  if (!SHELL_PROGRAM.test(baseName(words[0]))) return null;
  const flag = words.findIndex((word, index) => index > 0 && /^-[A-Za-z]*c[A-Za-z]*$/.test(word));
  return flag > 0 && words[flag + 1] !== undefined ? words[flag + 1] : null;
}

/** A runner's package or file argument that is not a literal (`npx $x`, `npm exec "$P"`, `node ${F}`). */
function dynamicRunnerArgument(words: string[]): boolean {
  let subcommand = !/^(?:npx|pnpx|bunx|node|nodejs)$/.test(baseName(words[0]));
  for (let at = 1; at < words.length; at += 1) {
    const word = words[at];
    if (/^(?:-p|--package)$/.test(word)) { if (DYNAMIC.test(words[at + 1] ?? '')) return true; at += 1; continue; }
    if (word.startsWith('-')) { if (/^--package=/.test(word) && DYNAMIC.test(word)) return true; continue; }
    if (DYNAMIC.test(word)) return true;
    if (subcommand && RUNNER_SUBCOMMAND.test(word)) { subcommand = false; continue; }
    return false;
  }
  return false;
}

/**
 * The commands of a text the shell parser cannot read, split at `; & | ( ) { }` and newlines; `$( )` and backtick bodies go
 * to `nested` (read as commands one level down). A quoted string is one data word (eval and `-c` read it as code); an
 * unbalanced quote reads the rest of the text as commands. One pass over the text.
 */
function lexicalCommands(text: string, nested: string[]): { words: string[]; dynamic: boolean }[] {
  const commands: { words: string[]; dynamic: boolean }[] = [];
  let words: string[] = [];
  let word = '';
  let inWord = false;
  let dynamic = false;
  const endWord = (): void => { if (inWord) words.push(word); word = ''; inWord = false; };
  const endCommand = (): void => { endWord(); if (words.length) commands.push({ words, dynamic }); words = []; dynamic = false; };
  // The end of the `$(` body that opens at `open` (matching parenthesis, or the end of the text).
  const closing = (open: number): number => {
    let level = 1;
    for (let at = open + 2; at < text.length; at += 1) {
      if (text[at] === '(') level += 1;
      else if (text[at] === ')' && --level === 0) return at;
    }
    return text.length;
  };
  const substitution = (at: number): number => {
    dynamic = true;
    inWord = true;
    const tick = text[at] === '`';
    const end = tick ? text.indexOf('`', at + 1) : closing(at);
    const stop = end < 0 ? text.length : end;
    nested.push(text.slice(at + (tick ? 1 : 2), stop));
    word += tick ? '`' : '$(';
    return stop;
  };
  for (let at = 0; at < text.length; at += 1) {
    const char = text[at];
    if (char === '\\') { word += text[at + 1] ?? ''; inWord = true; at += 1; continue; }
    if (char === "'") {
      const end = text.indexOf("'", at + 1);
      if (end < 0) { endCommand(); continue; }
      word += text.slice(at + 1, end);
      inWord = true;
      at = end;
      continue;
    }
    if (char === '"') {
      let end = at + 1;
      let quoted = '';
      while (end < text.length && text[end] !== '"') {
        if (text[end] === '\\') { quoted += text[end + 1] ?? ''; end += 2; continue; }
        if (text[end] === '`' || (text[end] === '$' && text[end + 1] === '(')) {
          const before = word;
          word = '';
          end = substitution(end) + 1;
          quoted += word;
          word = before;
          continue;
        }
        if (text[end] === '$') dynamic = true;
        quoted += text[end];
        end += 1;
      }
      if (end >= text.length) { endCommand(); continue; }
      word += quoted;
      inWord = true;
      at = end;
      continue;
    }
    if (char === '`' || (char === '$' && text[at + 1] === '(')) { at = substitution(at); continue; }
    if (char === '$') dynamic = true;
    if (char === ' ' || char === '\t') { endWord(); continue; }
    if (';&|(){}\n'.includes(char)) { endCommand(); continue; }
    word += char;
    inWord = true;
  }
  endCommand();
  return commands;
}

/** Whether `rule` holds for any command of the text, read by the shell parser or, where it cannot, lexically. */
function anyCommand(text: string, depth: number, rule: Rule): boolean {
  if (depth > MAX_DEPTH) return true;
  const segments = parseShellSegments(text);
  if (segments) return segments.some((segment) => rule(segment.words, segment.expansions.length > 0, depth));
  const nested: string[] = [];
  const commands = lexicalCommands(text, nested);
  // A non-ASCII text, or a STDIN_SHELL that may run a quoted string of it: master's word check.
  if (rule === installerRule && (/[^\x00-\x7f]/.test(text) || commands.some(({ words }) => STDIN_SHELL.test(baseName(programWords(words)[0] ?? '')) && innerCode(programWords(words)) === null))) return /control|disable|uninstall|[$`]/i.test(text);
  if (commands.some((command) => rule(command.words, command.dynamic, depth))) return true;
  return nested.some((inner) => anyCommand(inner, depth + 1, rule));
}

const installerRule: Rule = (all, dynamic, depth) => {
  const words = programWords(all);
  const code = words.length ? innerCode(words) : null;
  if (!words.length || code !== null) return code !== null && (/[$`]/.test(code) || anyCommand(code, depth + 1, installerRule));
  const program = words[0];
  const runner = RUNNER.test(baseName(program));
  // CX-A2: a runner whose package or file is a variable or a substitution, in a text that names the installer.
  if (runner && dynamicRunnerArgument(words)) return true;
  const runs = runner || INSTALLER_BIN.test(program) || INSTALLER_PATH.test(program) || /[$`]/.test(program);
  const args = runs ? installerArguments(words) : null;
  return args !== null && routeArguments(args, dynamic);
};

/** 3.9.113's reading of one parsed command (master's rule, unchanged). */
function masterSegmentIsRoute(segment: ShellSegment, depth: number): boolean {
  let at = 0;
  while (at < segment.words.length && ASSIGNMENT.test(segment.words[at])) at += 1;
  while (at < segment.words.length && WRAPPER.test(baseName(segment.words[at]))) {
    at += 1;
    while (at < segment.words.length && (segment.words[at].startsWith('-') || ASSIGNMENT.test(segment.words[at]) || /^\d+$/.test(segment.words[at]))) at += 1;
  }
  const words = segment.words.slice(at);
  if (!words.length) return false;
  if (/^(?:sh|bash|zsh|dash|ksh)$/.test(baseName(words[0]))) {
    const flag = words.findIndex((word, index) => index > 0 && /^-[A-Za-z]*c[A-Za-z]*$/.test(word));
    if (flag > 0 && words[flag + 1] !== undefined) return masterControlRoute(words[flag + 1], depth + 1);
  }
  const program = words[0];
  const runs = RUNNER.test(baseName(program)) || INSTALLER_BIN.test(program) || INSTALLER_PATH.test(program) || /[$`]/.test(program);
  const args = runs ? installerArguments(words) : null;
  return args !== null && routeArguments(args, segment.expansions.length > 0);
}

/** 3.9.113's text-wide rule (master's answer, unchanged). */
function masterControlRoute(command: string, depth = 0): boolean {
  try {
    if (typeof command !== 'string' || !INSTALLER_TEXT.test(command)) return false;
    if (depth > 3) return true;
    const segments = parseShellSegments(command);
    // A command the parser cannot read that names the installer next to a control word is held, never guessed at.
    if (!segments) return /control|disable|uninstall|[$`]/i.test(command);
    return segments.some((segment) => masterSegmentIsRoute(segment, depth));
  } catch {
    return true;
  }
}

/**
 * Ruling R4: the clean L1 shape, the only text where the reader may answer "no route" against master. The text parses, holds no
 * here-doc and no `#`, and every installer mention is a data operand of printf, echo, grep, git, cat, cd or ls (none in a redirect,
 * a substitution or a word the parser joined).
 */
function cleanL1Text(command: string): boolean {
  if (/<<|#/.test(command)) return false;
  const segments = parseShellSegments(command);
  if (!segments) return false;
  let operands = 0;
  for (const segment of segments) {
    const at = segment.words.findIndex((word) => INSTALLER_TEXT.test(word));
    if (at < 0) continue;
    const words = programWords(segment.words);
    const program = segment.words.length - words.length;
    if (!L1_PROGRAM.test(words[0] ?? '') || at <= program || segment.expansions.length > 0) return false;
    operands += segment.words.reduce((n, word) => n + (word.match(INSTALLER_TEXT_ALL) ?? []).length, 0);
  }
  return operands >= (command.match(INSTALLER_TEXT_ALL) ?? []).length;
}

/** Whether the shell text runs the installer in a way that can switch Marrow control off, remove it, or cannot be read as one fixed command. */
export function controlRoute(command: string, depth = 0): boolean {
  try {
    if (typeof command !== 'string' || !INSTALLER_TEXT.test(command)) return false;
    if (command.length > MAX_READ) return /control|disable|uninstall|[$`]/i.test(command);
    if (anyCommand(command, depth, installerRule)) return true;
    // R4: outside the clean L1 shape, master's route stands (a route if either reading says route).
    return !cleanL1Text(command) && masterControlRoute(command, depth);
  } catch {
    return true;
  }
}

/** Whether a text holds a gate receipt's host-approval or approval-link path (any case, `%2F`, doubled slashes). */
export function approvalReportUrl(text: string): boolean {
  const path = text.toLowerCase().replace(/%2f/g, '/').replace(/\/{2,}/g, '/');
  const at = path.indexOf('/gate-receipts/');
  return at >= 0 && (path.includes('/host-approval', at) || path.includes('/approval-link', at));
}

/**
 * M-SELF-APPROVE (g): a shell text that reports an approval for a gate receipt: a request client or an interpreter (its code,
 * a here-doc or piped stdin) in a text that holds the approval path, or a run of a host-report or approval-link script as the
 * program or an interpreter's script. A grep, a printf, a cat or a commit message that only names it is not one.
 */
export function selfApproveRoute(command: string): boolean {
  try {
    if (typeof command !== 'string') return false;
    const url = approvalReportUrl(command);
    if (!url && !REPORT_TEXT.test(command)) return false;
    if (command.length > MAX_READ) return true;
    const rule: Rule = (all, _dynamic, depth) => {
      const words = programWords(all);
      if (!words.length || (innerCode(words) !== null && anyCommand(innerCode(words) as string, depth + 1, rule))) return words.length > 0;
      const program = baseName(words[0]);
      if (REPORT_SCRIPT.test(program)) return true;
      if (url && (INTERPRETER.test(program) || HTTP_CLIENT.test(program) || SHELL_PROGRAM.test(program))) return true;
      if (!INTERPRETER.test(program)) return false;
      const script = words.slice(1).find((word) => !word.startsWith('-'));
      return script !== undefined && REPORT_SCRIPT.test(baseName(script));
    };
    return anyCommand(command, 0, rule);
  } catch {
    return true;
  }
}
