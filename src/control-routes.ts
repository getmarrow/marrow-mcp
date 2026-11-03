import { parseShellSegments, type ShellSegment } from './hook-tool-policy';

/**
 * MCP-10: the visible ways to switch Marrow's local control off or remove it through the installer. A command that runs the installer
 * (`npx @getmarrow/install ...`, `marrow-install ...`, `node .../@getmarrow/install/bin/marrow-install.js ...`) with a `control` word other
 * than `enable`/`status`, with `disable` or `uninstall`, or with any argument the shell expands, is a control-off route. The agent's own
 * `--yes` approves nothing: such a command is labelled `security on marrow-control` and held for the account owner.
 */
export const CONTROL_ROUTE_DENY_TEXT = 'Turning Marrow control off needs the account owner. Ask them to run it in their own terminal.';

const INSTALLER_PACKAGE = /(?:^|=)@getmarrow\/install(?:@[^\s/]*)?$/i;
const INSTALLER_BIN = /(?:^|\/)marrow-install(?:\.[cm]?js)?$/i;
const INSTALLER_PATH = /@getmarrow\/install\//i;
const INSTALLER_TEXT = /@getmarrow\/install|marrow-install/i;
const WRAPPER = /^(?:sudo|env|nohup|time|exec|command|builtin|nice|ionice|stdbuf|timeout|xargs|setsid)$/;
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const SHELL_PROGRAM = /^(?:sh|bash|zsh|dash|ksh)$/;
// Programs that can run an installer package or file: a grep, a cat or a commit message that merely names it is not a route.
const RUNNER = /^(?:npx|pnpx|bunx|npm|pnpm|yarn|bun|node|nodejs|deno|corepack)$/;
const SAFE_CONTROL_SUBCOMMAND = new Set(['enable', 'status']);

function baseName(word: string): string {
  const cut = word.lastIndexOf('/');
  return cut < 0 ? word : word.slice(cut + 1);
}

function installerArguments(words: string[]): string[] | null {
  const marker = words.findIndex((word) => INSTALLER_PACKAGE.test(word) || INSTALLER_BIN.test(word) || INSTALLER_PATH.test(word));
  return marker < 0 ? null : words.slice(marker + 1);
}

function routeArguments(args: string[], segment: ShellSegment): boolean {
  if (segment.expansions.length > 0 || args.some((arg) => /[$`*?[~]/.test(arg))) return true;
  if (args.some((arg) => /^-{0,2}(?:disable|uninstall)$/i.test(arg))) return true;
  const control = args.findIndex((arg) => arg.toLowerCase() === 'control');
  if (control < 0) return false;
  const subcommands = args.slice(control + 1).filter((arg) => !arg.startsWith('-')).map((arg) => arg.toLowerCase());
  return !(subcommands.length > 0 && subcommands.every((arg) => SAFE_CONTROL_SUBCOMMAND.has(arg)));
}

function segmentIsRoute(segment: ShellSegment, depth: number): boolean {
  let at = 0;
  while (at < segment.words.length && ASSIGNMENT.test(segment.words[at])) at += 1;
  while (at < segment.words.length && WRAPPER.test(baseName(segment.words[at]))) {
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
  const runs = RUNNER.test(baseName(program)) || INSTALLER_BIN.test(program) || INSTALLER_PATH.test(program) || /[$`]/.test(program);
  const args = runs ? installerArguments(words) : null;
  return args !== null && routeArguments(args, segment);
}

/** Whether the shell text runs the installer in a way that can switch Marrow control off, remove it, or cannot be read as one fixed command. */
function legacyRoute(command: string, depth = 0): boolean {
  try {
    if (typeof command !== 'string' || !INSTALLER_TEXT.test(command)) return false;
    if (depth > 3) return true;
    const segments = parseShellSegments(command);
    // A command the parser cannot read that names the installer next to a control word is held, never guessed at.
    if (!segments) return /control|disable|uninstall|[$`]/i.test(command);
    return segments.some((segment) => segmentIsRoute(segment, depth));
  } catch {
    return true;
  }
}

/** Limits of one call in counted steps (no clock; over a limit the text is held when it names the installer) and the steps the last top-level call counted. Exported for tests. */
export const CONTROL_READ_LIMITS = { bytes: 8192, chars: 262144, steps: 600000, segments: 256, rounds: 4, defs: 64, depth: 3, braces: 64 };
export const CONTROL_READ_STATS = { steps: 0 };
type Budget = { steps: number }; type Walk = { b: Budget; depth: number; named: boolean };
const INVISIBLE = /[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0]/g;
// Look-alikes NFKC leaves alone (Cyrillic, Greek, Latin small capitals): each entry is the look-alike then the letter it passes for.
const LOOKALIKE = new Map(('\u0430a \u0435e \u043eo \u0441c \u0440p \u0445x \u0456i \u0455s \u0501d \u051dw \u043cm \u0442t \u0433r \u04cfl \u0261g \u1d0dm \u0280r \u0274n \u1d1bt \u029fl \u1d1cu \u0299b \u1d05d \u0262g \u1d07e \u1d00a \u1d04c \u026ai \u1d0fo \u1d21w \ua731s \u0131i \u03bfo \u03b1a \u03b9i \u03bdv').split(' ').map((entry) => [entry[0], entry[1]] as [string, string]));
const KEYWORD = new Set(['do', 'then', 'else', 'elif', 'if', 'while', 'until', '!']);
const REFERENCE = /\$\{(\w+)\}|\$(\w+)/g;
// Wrappers read past their options: [letters of the short options that take a value, long options that take a value].
const WRAPPER_OPTIONS = new Map<string, [string, string[]]>([
  ['sudo', ['ughpCDRTUrt', ['user', 'group', 'host', 'prompt', 'chdir', 'chroot', 'command-timeout', 'other-user', 'role', 'type', 'close-from']]], ['doas', ['uC', []]], ['env', ['uCS', ['unset', 'chdir', 'split-string']]],
  ['nohup', ['', []]], ['time', ['fo', ['format', 'output']]], ['exec', ['a', []]], ['command', ['', []]], ['builtin', ['', []]], ['nice', ['n', ['adjustment']]], ['setsid', ['', []]], ['unbuffer', ['', []]],
  ['ionice', ['cnpPu', ['class', 'classdata', 'pid', 'pgid', 'uid']]], ['stdbuf', ['ioe', ['input', 'output', 'error']]], ['timeout', ['sk', ['signal', 'kill-after']]],
  ['xargs', ['IndEaLPs', ['replace', 'delimiter', 'eof', 'arg-file', 'max-lines', 'max-args', 'max-procs', 'max-chars']]],
]);
const TARGETS = ['marrow-install', 'marrow-install.js', 'marrow-install.cjs', 'marrow-install.mjs', '@getmarrow/install'];
const segmentOf = (words: string[]): ShellSegment => ({ words, outputs: [], inputs: [], expansions: [] });
const tick = (b: Budget, steps = 1): void => { b.steps -= steps; CONTROL_READ_STATS.steps += steps; if (b.steps < 0) throw new RangeError('control-route budget'); };
const canon = (word: string): string => Array.from(word.normalize('NFKC').replace(INVISIBLE, ''), (ch) => LOOKALIKE.get(ch) ?? ch).join('');
/** `$'...'` from `from`: the decoded body and the index of the closing quote. */
function ansiC(text: string, from: number): [string, number] {
  let end = from;
  while (end < text.length && text[end] !== "'") end += text[end] === '\\' ? 2 : 1;
  const body = text.slice(from, end).replace(/\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{1,4}|U[0-9a-fA-F]{1,8}|[0-7]{1,3}|c[\s\S]|[\s\S])/g, (_, esc: string) => {
    const hex = esc.length > 1 && 'xuU'.includes(esc[0]);
    if (hex || /^[0-7]/.test(esc)) return String.fromCodePoint(Math.min(parseInt(hex ? esc.slice(1) : esc, hex ? 16 : 8), 0x10ffff));
    return esc.length > 1 && esc[0] === 'c' ? String.fromCharCode(esc.charCodeAt(1) & 31) : esc;
  });
  return [body, Math.min(end, text.length)];
}
/** The inside of a quoted span starting at `at` and the index of its closing quote; null when it never closes. */
function quoted(text: string, at: number): [string, number] | null {
  let inner = '';
  for (let end = at + 1; end < text.length; end += 1) {
    if (text[end] === text[at]) return [inner, end];
    if (text[at] === '"' && text[end] === '\\' && '"\\$`\n'.includes(text[end + 1] ?? '\u0000')) { end += 1; if (text[end] !== '\n') inner += text[end]; } else inner += text[end];
  }
  return null;
}
/** Splits shell text into simple commands of canonical words (quotes, backslashes, line continuations and `$'..'` read as the shell reads them). */
function lex(text: string, b: Budget): string[][] {
  const segments: string[][] = [];
  let words: string[] = [];
  let word = '';
  let open = false; let skip = false; let last = -1; // skip: the next word is a redirect target
  const push = (chunk: string) => { word += chunk; open = true; };
  const endWord = () => { if (open && skip) skip = false; else if (open) words.push(canon(word)); word = ''; open = false; };
  const endSegment = () => { endWord(); if (words.length) segments.push(words); words = []; };
  for (let at = 0; at < text.length; at += 1) {
    tick(b, at - last);
    last = at;
    const ch = text[at];
    const next = text[at + 1];
    if (ch === "'" || ch === '"') {
      const span = quoted(text, at);
      if (!span) push(ch);
      else { push(span[0]); at = span[1]; if (ch === '"' && /\$\(|`/.test(span[0])) segments.push(...lex(span[0], b)); }
    } else if (ch === '\\') { if (next === '\n') at += 1; else { push(next ?? ch); at += next === undefined ? 0 : 1; } }
    else if (ch === '$' && next === "'") { const [value, close] = ansiC(text, at + 2); push(value); at = close; }
    else if (ch === '$' && next === '(') { push('$'); endSegment(); at += 1; }
    else if (ch === '$' && next === '{') { const close = text.indexOf('}', at); const end = close < 0 ? text.length - 1 : close; push(text.slice(at, end + 1)); at = end; }
    else if (ch === '`') { push(ch); endSegment(); }
    else if (ch === '#' && !open) { const nl = text.indexOf('\n', at); at = nl < 0 ? text.length : nl - 1; }
    else if (ch === ' ' || ch === '\t') { if (open && (word === '{' || word === '}')) { word = ''; open = false; endSegment(); } else endWord(); }
    else if (ch === '\n' || ch === ';' || ch === '|' || ch === '(' || ch === ')' || (ch === '&' && next !== '>')) endSegment();
    else if (ch === '<' || ch === '>' || ch === '&') {
      if (next === '(') { endSegment(); at += 1; continue; }
      if (open && /^\d+$/.test(word)) { word = ''; open = false; } else endWord();
      let end = at;
      while ('<>&|'.includes(text[end + 1] ?? '\u0000')) end += 1;
      if (text.slice(at, end + 1) === '<<<') words.push('<<<'); else skip = true;
      at = end;
    } else push(ch);
  }
  endSegment();
  return segments;
}
/** Every name a text binds: assignments (also after export, declare, local, readonly), aliases, `for NAME in LIST` and `read NAME <<< VALUE`. */
function bindings(segments: string[][]): Map<string, string[]> {
  const defs = new Map<string, string[]>();
  let count = 0;
  // A binding that reads its own name (PATH=$PATH:/x) is an append, not a carrier.
  const bind = (name: string, value: string | undefined) => { if (value !== undefined && !value.includes(`$${name}`) && !value.includes(`\${${name}}`)) { defs.set(name, [...(defs.get(name) ?? []), value]); count += 1; } };
  for (const words of segments) {
    if ((words[0] === 'for' || words[0] === 'select') && words[2] === 'in') words.slice(3).forEach((value) => bind(words[1], value));
    const fed = words.indexOf('<<<');
    if (words[0] === 'read' && fed > 0) words.slice(1, fed).filter((name) => !name.startsWith('-')).forEach((name) => bind(name, words[fed + 1]));
    for (const word of words) if (ASSIGNMENT.test(word)) bind(word.slice(0, word.indexOf('=')), word.slice(word.indexOf('=') + 1));
  }
  if (count > CONTROL_READ_LIMITS.defs) throw new RangeError('control-route definitions');
  return defs;
}
/** Index of the first word after a wrapper's options and their values (`sudo -u root`, `timeout -s KILL 30`, `stdbuf -oL`, `--user=root`). */
function skipOptions(words: string[], from: number, name: string): number {
  const [letters, longs] = WRAPPER_OPTIONS.get(name) ?? ['', []];
  let at = from;
  while (at < words.length) {
    const word = words[at];
    if (word === '--') return at + 1;
    if (ASSIGNMENT.test(word)) at += 1;
    else if (!word.startsWith('-') || word === '-') break;
    else if (word.startsWith('--')) at += word.includes('=') || !longs.includes(word.slice(2)) ? 1 : 2;
    else at += [...word.slice(1)].findIndex((ch) => letters.includes(ch)) === word.length - 2 ? 2 : 1;
  }
  return /^\d[\d.]*[smhd]?$/.test(words[at] ?? '') ? at + 1 : at;
}
function expandBraces(word: string, level: number, b: Budget): string[] | null {
  const open = word.indexOf('{');
  if (open < 0) return [word];
  let nest = 0; let close = -1;
  const cuts = [open];
  for (let at = open; at < word.length && close < 0; at += 1) {
    if (word[at] === '{') nest += 1;
    else if (word[at] === '}' && (nest -= 1) === 0) close = at;
    else if (word[at] === ',' && nest === 1) cuts.push(at);
  }
  const sequence = close < 0 ? null : /^(\w)\.\.(\w)$/.exec(word.slice(open + 1, close));
  if (close < 0 || (cuts.length === 1 && !sequence)) return [word];
  const [from, to] = sequence ? [sequence[1].charCodeAt(0), sequence[2].charCodeAt(0)] : [0, 0];
  cuts.push(close);
  const alternatives = cuts.length > 2 ? cuts.slice(1).map((cut, index) => word.slice(cuts[index] + 1, cut)) : Array.from({ length: Math.abs(to - from) + 1 }, (_, index) => String.fromCharCode(from + Math.sign(to - from) * index));
  if (level >= 2 || alternatives.length > CONTROL_READ_LIMITS.braces) return null;
  const out: string[] = [];
  for (const alternative of alternatives) {
    const rest = expandBraces(word.slice(0, open) + alternative + word.slice(close + 1), level + 1, b);
    if (!rest || out.push(...rest) > CONTROL_READ_LIMITS.braces) return null;
    tick(b, rest.length);
  }
  return out;
}
/** Glob (`*`, `?`, `[set]` read as any one character) of `pattern` against all of `text`, by sets of pattern positions (no backtracking). */
function glob(pattern: string, text: string): boolean {
  const tokens = pattern.match(/\*|\?|\[[^\]]+\]|[\s\S]/g) ?? [];
  const settle = (set: Set<number>) => { for (const index of set) if (tokens[index] === '*') set.add(index + 1); return set; };
  let states = settle(new Set([0]));
  for (const ch of text) {
    const next = new Set<number>();
    for (const index of states) {
      const token = tokens[index];
      if (token === '*') next.add(index);
      else if (token !== undefined && (token === '?' || token === ch || (token.length > 2 && token[0] === '['))) next.add(index + 1);
    }
    states = settle(next);
  }
  return states.has(tokens.length);
}
/** The installer name a brace or glob word can expand to (at least 6 literal characters of it), else the word itself. */
function installerWord(word: string, b: Budget): string {
  if (!/[{*?[]/.test(word)) return word;
  const cut = word.indexOf('@', 1);
  const head = cut < 0 ? word : word.slice(0, cut);
  const forms = expandBraces(head, 0, b);
  const parts = (form: string) => { const slash = form.lastIndexOf('/'); return [form.slice(slash + 1), form.slice(form.lastIndexOf('/', slash - 1) + 1)]; };
  // Over the brace budget: 6 or more literal characters of the name must stand together in the last two path parts (a shell cannot expand a longer word).
  const last = parts(head)[1];
  const target = forms
    ? forms.flatMap(parts).map((part) => ([...part.replace(/\[[^\]]*\]/g, '')].filter((ch) => ch !== '*' && ch !== '?').length >= 6 ? TARGETS.find((name) => glob(part, name)) : undefined)).find(Boolean)
    : [TARGETS[0], TARGETS[4]].find((name) => last.length <= 128 && Array.from({ length: name.length - 5 }, (_, at) => name.slice(at, at + 6)).some((run) => last.includes(run)));
  if (forms) tick(b, forms.length * 4);
  return target ? target + (cut < 0 ? '' : word.slice(cut)) : word;
}
const isOff = (args: string[]) => routeArguments(args.filter((arg) => !/[$`*?[~]/.test(arg)), segmentOf([]));
/** One simple command: past keywords, assignments, aliases, variables and wrappers, then the legacy argument rules on what really runs. */
function simple(words: string[], world: Map<string, string>, w: Walk): boolean {
  tick(w.b);
  const resolve = (word: string): string => {
    for (let round = 0; round <= CONTROL_READ_LIMITS.rounds; round += 1) {
      const next = word.includes('$') ? word.replace(REFERENCE, (all, braced, bare) => world.get(braced ?? bare) ?? all) : word;
      if (next === word) return word;
      word = next;
    }
    throw new RangeError('control-route rounds');
  };
  let list = words.map(resolve).map((word) => (word.startsWith('npm:') ? word.slice(4) : word));
  let fed = false;
  let aliases = 0;
  let from = 0;
  for (;;) {
    tick(w.b);
    while (from < list.length && (KEYWORD.has(list[from]) || ASSIGNMENT.test(list[from]))) from += 1;
    if (from >= list.length) return false;
    const alias = world.get(list[from]);
    if (/\s/.test(list[from]) || alias !== undefined) {
      if (alias !== undefined && (aliases += 1) > CONTROL_READ_LIMITS.rounds) throw new RangeError('control-route rounds');
      list = [...(alias ?? list[from]).split(/\s+/).filter(Boolean), ...list.slice(from + 1)];
      from = 0;
      continue;
    }
    const wrapper = baseName(list[from]);
    if (!WRAPPER_OPTIONS.has(wrapper)) break;
    const end = skipOptions(list, from + 1, wrapper);
    const options = list.slice(from + 1, end);
    const split = wrapper === 'env' ? options.findIndex((option) => /^-[A-Za-z]*S|^--split-string/.test(option)) : -1;
    if (split >= 0) {
      const option = options[split];
      const text = option.endsWith('S') || option === '--split-string' ? options[split + 1] : option.startsWith('--') ? option.slice(option.indexOf('=') + 1) : option.slice(option.indexOf('S') + 1);
      return controlRoute([text ?? '', ...list.slice(end)].join(' '), w.depth + 1);
    }
    fed = fed || wrapper === 'xargs';
    from = end;
  }
  list = list.slice(from);
  const program = baseName(list[0]);
  if (program === 'eval') return controlRoute(list.slice(1).join(' '), w.depth + 1);
  for (let at = 0; program === 'find' && at < list.length; at += 1) {
    if (!['-exec', '-execdir', '-ok', '-okdir'].includes(list[at])) continue;
    let end = at + 1;
    while (end < list.length && list[end] !== ';' && list[end] !== '+') end += 1;
    if (simple(list.slice(at + 1, end), world, w)) return true;
  }
  // A shell that xargs feeds takes its script from stdin, which the text cannot show.
  if (fed && SHELL_PROGRAM.test(program) && !list.slice(1).some((word) => !word.startsWith('-'))) return w.named;
  // An expansion at command position that nothing above resolves, followed in the same segment by a control-off word.
  if (/[$`]/.test(list[0]) && isOff(list.slice(1))) return true;
  list = list.map((word, index) => (!word.startsWith('-') && (index === 0 || RUNNER.test(program)) ? installerWord(word, w.b) : word));
  // xargs appends stdin words to the installer's arguments: a `$` stands for them.
  return segmentIsRoute(segmentOf(fed ? [...list, '$'] : list), w.depth);
}
function newRoute(command: string, depth: number): boolean {
  if (typeof command !== 'string') return false;
  if (depth === 0) CONTROL_READ_STATS.steps = 0;
  let named = INSTALLER_TEXT.test(command);
  try {
    const b: Budget = { steps: CONTROL_READ_LIMITS.steps };
    if (command.length > CONTROL_READ_LIMITS.chars) { CONTROL_READ_STATS.steps += command.length; return named; }
    const segments = lex(command, b);
    named = named || segments.some((words) => words.some((word) => INSTALLER_TEXT.test(word)));
    if (depth > CONTROL_READ_LIMITS.depth) return named;
    if (command.length > CONTROL_READ_LIMITS.bytes) return named || segments.some((words) => words.some((word) => installerWord(word, b) !== word));
    if (segments.length > CONTROL_READ_LIMITS.segments) throw new RangeError('control-route segments');
    const defs = bindings(segments);
    for (let k = 0; k < Math.max(1, ...[...defs.values()].map((values) => values.length)); k += 1) {
      const world = new Map([...defs].map(([name, values]) => [name, values[Math.min(k, values.length - 1)]] as [string, string]));
      if (segments.some((words) => simple(words, world, { b, depth, named }))) return true;
    }
    return false;
  } catch {
    return named;
  }
}
/** Whether the shell text runs the installer in a way that can switch Marrow control off or remove it: master's route, or the extra reading of the same text. */
export function controlRoute(command: string, depth = 0): boolean {
  return legacyRoute(command, depth) || newRoute(command, depth);
}
