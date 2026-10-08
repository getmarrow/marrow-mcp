import { createHash } from 'node:crypto';
import { redactSensitiveText, redactSensitiveValue } from './redact';
import {
  hookToolCommand,
  isMcpHookTool,
  isShellGovernedTool,
  normalizeHookToolName,
  toolTargetPaths,
} from './hook-tool-policy';

/**
 * The exact action a hook-classified tool call performs, in the service's
 * normalized_action shape (marrow.gate.v1 `action`), so Marrow binds a gate,
 * a hold and an approval to that exact command or tool call, not to the
 * coarse classification ("deploy on production") the hook also sends.
 *
 * What leaves the machine: the tool kind, the host's tool name, the program
 * names of a shell command, file paths of an edit, and a SHA-256 of the
 * command or tool input. The command text and tool input themselves are never
 * sent. Before hashing, secret-bearing values are replaced (environment
 * values, credentials in URLs, values after password, token, OTP and key flags
 * and in known secret positions, text piped into a command, here-strings and
 * heredoc bodies, and any argument shaped like a key), so the hash is of a
 * secret-free form: the same command gives the same hash on every machine and
 * on every retry, and two commands that differ only in a secret value give
 * the same hash. A program name or path that looks like a key is dropped.
 */
export type NormalizedHookAction = {
  tool_kind: 'shell' | 'edit' | 'mcp' | 'other';
  tool_name: string;
  programs?: string[];
  paths?: string[];
  tool_input: { command_sha256: string } | { input_sha256: string } | Record<string, never>;
};

const SECRET = '[secret]';
const HASH_VERSION = 'marrow-normalized-action-v2';
const EDIT_TOOLS = /^(?:edit|write|multiedit|apply_patch|notebookedit|replace|write_file|edit_file|delete_file|search_replace|delete|create_file)$/i;

type ToolEvent = { tool_name?: unknown; tool_input?: unknown };

// ---------------------------------------------------------------------------
// Key-shaped values
// ---------------------------------------------------------------------------

const KNOWN_KEY_PREFIX = /^(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{12,}$|^(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}$|^github_pat_[A-Za-z0-9_]{20,}$|^(?:sk|pk|rk)[-_](?:live|test|proj|ant)?[-_]?[A-Za-z0-9_-]{16,}$|^xox[abprs]-[A-Za-z0-9-]{10,}$|^AIza[0-9A-Za-z_-]{30,}$|^glpat-[A-Za-z0-9_-]{16,}$|^npm_[A-Za-z0-9]{20,}$|^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/;

/** A value shaped like a key, token or password hash (mixed-case random text, long hex, known prefixes). */
export function looksLikeKey(value: string): boolean {
  const text = value.trim();
  if (!text) return false;
  if (KNOWN_KEY_PREFIX.test(text)) return true;
  if (/-----BEGIN [A-Z ]*(?:PRIVATE KEY|CERTIFICATE)-----/.test(text)) return true;
  // A content digest (sha256:...) names content; it is not a secret.
  if (/^(?:sha(?:1|256|384|512)):[0-9a-f]+$/i.test(text)) return false;
  if (/^[0-9a-f]{32,}$/i.test(text)) return true;
  if (text.length >= 20 && /^[A-Za-z0-9+/=_-]+$/.test(text) && /[a-z]/.test(text) && /[A-Z]/.test(text) && /[0-9]/.test(text)) return true;
  return false;
}

/** Replaces key-shaped parts of a word (split at = : , ; @ / ? & and quotes). */
function redactKeyShapedParts(word: string): string {
  if (looksLikeKey(word)) return SECRET;
  return word.split(/([=:,;@/?&'"])/).map((part) => (looksLikeKey(part) ? SECRET : part)).join('');
}

const SECRET_NAME = /pass(?:word|wd|phrase)?|secret|token|otp|api[-_]?key|apikey|access[-_]?key|private[-_]?key|client[-_]?secret|auth|cred|cookie|session|bearer|signature|(?:^|[-_])pin$|(?:^|[-_])key$/i;

// ---------------------------------------------------------------------------
// Shell words
// ---------------------------------------------------------------------------

type Token = { value: string; op: boolean };

const OPERATORS = ['<<<', '&&', '||', '|&', '>>', '<<', ';;', '|', '&', ';', '<', '>', '(', ')', '\n'];

/** Splits a command into words and operators, honoring quotes and escapes (an approximation of the shell). */
function tokenize(command: string): Token[] {
  const tokens: Token[] = [];
  let current = '';
  let started = false;
  const push = () => {
    if (started) tokens.push({ value: current, op: false });
    current = '';
    started = false;
  };
  for (let i = 0; i < command.length; i += 1) {
    const ch = command[i];
    if (ch === '\\' && i + 1 < command.length) {
      current += command[i + 1];
      started = true;
      i += 1;
      continue;
    }
    if (ch === '\'' || ch === '"') {
      const end = command.indexOf(ch, i + 1);
      const body = end < 0 ? command.slice(i + 1) : command.slice(i + 1, end);
      current += ch === '"' ? body.replace(/\\(["\\$`])/g, '$1') : body;
      started = true;
      i = end < 0 ? command.length : end;
      continue;
    }
    if (ch === ' ' || ch === '\t' || ch === '\r') {
      push();
      continue;
    }
    const op = OPERATORS.find((candidate) => command.startsWith(candidate, i));
    if (op) {
      push();
      tokens.push({ value: op === '\n' ? ';' : op, op: true });
      i += op.length - 1;
      continue;
    }
    current += ch;
    started = true;
  }
  push();
  return tokens;
}

/** Heredoc bodies are input to the command, never part of it: replaced before tokenizing. */
function withoutHeredocBodies(command: string): string {
  return command.replace(/<<-?[ \t]*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1([^\n]*)\n[\s\S]*?(?:\n[ \t]*\2[ \t]*(?=\n|$)|$)/g,
    (_match, _quote, tag: string, rest: string) => `<<${tag} ${SECRET}${rest}`);
}

const WRAPPERS = new Set(['sudo', 'doas', 'env', 'time', 'nohup', 'exec', 'command', 'nice', 'ionice', 'stdbuf', 'timeout', 'xargs', 'npx', 'bunx', 'pnpx']);
const MYSQL_FAMILY = new Set(['mysql', 'mariadb', 'mysqldump', 'mysqladmin', 'mysqlimport', 'mysqlshow', 'mysqlcheck', 'mysqlsh']);
const REGISTRY_LOGIN = new Set(['docker', 'podman', 'nerdctl', 'buildah', 'helm', 'oras', 'crane', 'skopeo', 'regctl']);
const CURL_FAMILY = new Set(['curl', 'wget', 'http', 'https', 'xh']);
const OPENSSL_PASS_FLAGS = new Set(['-pass', '-passin', '-passout', '-k', '-kfile', '-password']);
const AUTH_HEADER = /authorization|token|key|secret|cookie|bearer|basic/i;

function basename(word: string): string {
  return word.replace(/^.*\//, '');
}

const ASSIGNMENT = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s;

/** Redacts one simple command (a segment between operators); returns its program name. */
function redactSegment(words: string[], pipedOut: boolean): { words: string[]; program: string | null } {
  const out = [...words];
  let index = 0;
  // Leading environment assignments: every value is replaced (names stay).
  while (index < out.length && ASSIGNMENT.test(out[index])) {
    out[index] = out[index].replace(ASSIGNMENT, `$1=${SECRET}`);
    index += 1;
  }
  // Wrappers (sudo, env, npx, timeout ...) and their own flags and assignments.
  while (index < out.length && WRAPPERS.has(basename(out[index]))) {
    index += 1;
    while (index < out.length && (out[index].startsWith('-') || ASSIGNMENT.test(out[index]) || /^\d+[smhd]?$/.test(out[index]))) {
      if (ASSIGNMENT.test(out[index])) out[index] = out[index].replace(ASSIGNMENT, `$1=${SECRET}`);
      index += 1;
    }
  }
  if (index >= out.length) return { words: out, program: null };
  const program = basename(out[index]).toLowerCase();
  // export/declare/local/readonly/typeset NAME=value: values replaced, like a leading assignment.
  if (['export', 'declare', 'typeset', 'local', 'readonly', 'set'].includes(program)) {
    const assigned = out.slice(index + 1).map((word) => (ASSIGNMENT.test(word) ? word.replace(ASSIGNMENT, `$1=${SECRET}`) : word));
    return { words: [...out.slice(0, index + 1), ...assigned], program };
  }
  const args = out.slice(index + 1);
  const positionals = args.filter((arg) => !arg.startsWith('-'));
  const subcommands = positionals.slice(0, 3).map((arg) => arg.toLowerCase());
  const secretContext = subcommands.some((arg) => /secret/.test(arg));
  const loginContext = subcommands.includes('login');

  // Text piped into another command (echo X | wrangler secret put NAME) is that
  // command's input, and text written to a file (echo X > .env) is data: both replaced.
  if (program === 'echo' || program === 'printf') {
    const redirect = args.findIndex((arg) => arg === '>' || arg === '>>');
    if (pipedOut || redirect >= 0) {
      const data = redirect >= 0 ? args.slice(0, redirect) : args;
      const rest = redirect >= 0 ? args.slice(redirect) : [];
      return { words: [...out.slice(0, index + 1), ...(data.length ? [SECRET] : []), ...rest], program };
    }
  }

  let afterSecretWord = -1;
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    const next = () => {
      if (i + 1 < args.length && !args[i + 1].startsWith('-')) {
        args[i + 1] = SECRET;
        i += 1;
      }
    };
    // --flag=value (or -flag=value), when the flag names a secret.
    const long = /^(--?[A-Za-z0-9][A-Za-z0-9_.-]*)=(.*)$/s.exec(arg);
    if (long) {
      const name = long[1].replace(/^-+/, '');
      if (name === 'from-literal' || name === 'from-env-literal') {
        args[i] = `${long[1]}=${long[2].replace(/^([^=]*)=.*$/s, `$1=${SECRET}`)}`;
      } else if (SECRET_NAME.test(name) || (CURL_FAMILY.has(program) && /^(?:u|user|proxy-user)$/.test(name))
        || (CURL_FAMILY.has(program) && name === 'header' && AUTH_HEADER.test(long[2]))) {
        args[i] = `${long[1]}=${SECRET}`;
      }
      continue;
    }
    // --flag value
    if (/^--[A-Za-z0-9]/.test(arg)) {
      const name = arg.slice(2);
      if (SECRET_NAME.test(name) || (CURL_FAMILY.has(program) && /^(?:user|proxy-user)$/.test(name))) next();
      else if (CURL_FAMILY.has(program) && name === 'header') {
        if (i + 1 < args.length && AUTH_HEADER.test(args[i + 1])) args[++i] = SECRET;
      } else if (program === 'gh' && secretContext && name === 'body') next();
      continue;
    }
    // Short flags by program: -p<pw>/-p <pw> (mysql, sshpass, registry login), -a (redis), -u user:pass (curl).
    if (/^-[A-Za-z]/.test(arg)) {
      if (MYSQL_FAMILY.has(program) && /^-p.+/.test(arg)) args[i] = `-p${SECRET}`;
      else if (program === 'sshpass' && /^-p/.test(arg)) { if (arg.length > 2) args[i] = `-p${SECRET}`; else next(); }
      else if (REGISTRY_LOGIN.has(program) && loginContext && /^-p/.test(arg)) { if (arg.length > 2) args[i] = `-p${SECRET}`; else next(); }
      else if (['redis-cli', 'keydb-cli', 'valkey-cli'].includes(program) && /^-a/.test(arg)) { if (arg.length > 2) args[i] = `-a${SECRET}`; else next(); }
      else if (CURL_FAMILY.has(program) && (arg === '-u' || arg === '-U')) next();
      else if (CURL_FAMILY.has(program) && arg === '-H') { if (i + 1 < args.length && AUTH_HEADER.test(args[i + 1])) args[++i] = SECRET; }
      else if (program === 'openssl' && OPENSSL_PASS_FLAGS.has(arg)) next();
      else if (program === 'gh' && secretContext && arg === '-b') next();
      continue;
    }
    // NAME=value arguments: a secret-named value, or any value in a secrets command.
    if (ASSIGNMENT.test(arg)) {
      const name = ASSIGNMENT.exec(arg)![1];
      if (secretContext || SECRET_NAME.test(name)) args[i] = `${name}=${SECRET}`;
      continue;
    }
    if (program === 'openssl' && /^(?:pass|env|file|fd):/.test(arg)) { args[i] = arg.replace(/:.*/s, `:${SECRET}`); continue; }
    // aws configure set <key-ish name> <value>
    if (program === 'aws' && subcommands[0] === 'configure' && args[i - 1]?.toLowerCase() === 'set' && SECRET_NAME.test(arg)) {
      next();
      continue;
    }
    // In a secrets command (gh secret set NAME, doppler secrets set NAME VALUE ...),
    // the name stays; later positionals are values.
    if (secretContext) {
      if (afterSecretWord >= 0) {
        afterSecretWord += 1;
        if (afterSecretWord > 2) args[i] = SECRET;
      } else if (/secret/i.test(arg)) {
        afterSecretWord = 0;
      }
    }
    // htpasswd -b FILE USER PASSWORD: the last positional.
    if (program === 'htpasswd' && args.some((value) => /^-[a-zA-Z]*b/.test(value)) && i === args.length - 1) args[i] = SECRET;
  }
  return { words: [...out.slice(0, index + 1), ...args], program };
}

function quoteWord(word: string): string {
  return /[\s'"\\|&;<>()$`*?]/.test(word) ? `'${word.replace(/'/g, `'\\''`)}'` : word;
}

/**
 * The secret-free normalized form of a shell command: whitespace and quoting
 * normalized, secret values replaced (see the module comment). Exported for
 * tests; it is hashed and never sent.
 */
export function normalizeShellCommand(command: string): { text: string; programs: string[] } {
  const tokens = tokenize(withoutHeredocBodies(command.replace(/\r\n?/g, '\n')));
  const words: string[] = [];
  const programs: string[] = [];
  let segment: string[] = [];
  const flush = (pipedOut: boolean) => {
    if (!segment.length) return;
    const result = redactSegment(segment, pipedOut);
    words.push(...result.words.map((word) => quoteWord(redactKeyShapedParts(redactSensitiveText(word)))));
    if (result.program && /^[a-z0-9][a-z0-9._+-]{0,63}$/.test(result.program) && !looksLikeKey(result.program) && !programs.includes(result.program)) {
      programs.push(result.program);
    }
    segment = [];
  };
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    if (!token.op) {
      segment.push(token.value);
      continue;
    }
    if (token.value === '<<<') {
      // A here-string is the command's input.
      flush(false);
      words.push('<<<');
      if (i + 1 < tokens.length && !tokens[i + 1].op) { words.push(SECRET); i += 1; }
      continue;
    }
    if (['>', '>>', '<', '<<'].includes(token.value)) {
      // A redirection (and a heredoc tag) belongs to the current command.
      segment.push(token.value);
      continue;
    }
    flush(token.value === '|' || token.value === '|&');
    if (token.value !== ';' || (words.length && words[words.length - 1] !== ';')) words.push(token.value);
  }
  flush(false);
  while (words.length && words[words.length - 1] === ';') words.pop();
  return { text: words.join(' '), programs: programs.slice(0, 16) };
}

function sha256(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

function sortedValue(value: unknown, depth = 0): unknown {
  if (depth > 6 || !value || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((item) => sortedValue(item, depth + 1));
  return Object.fromEntries(Object.keys(value as Record<string, unknown>).sort()
    .map((key) => [key, sortedValue((value as Record<string, unknown>)[key], depth + 1)]));
}

/** A tool input with secret-named fields and key-shaped values removed; hashed, never sent. */
function redactedInput(value: unknown, depth = 0): unknown {
  if (depth > 6) return SECRET;
  if (typeof value === 'string') {
    const text = redactSensitiveText(value);
    return looksLikeKey(text) ? SECRET : text.split(/(\s+)/).map(redactKeyShapedParts).join('');
  }
  if (Array.isArray(value)) return value.slice(0, 64).map((item) => redactedInput(item, depth + 1));
  if (value && typeof value === 'object') {
    const redacted = redactSensitiveValue(value) as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(redacted)) out[key] = SECRET_NAME.test(key) ? SECRET : redactedInput(item, depth + 1);
    return out;
  }
  return value;
}

/**
 * The command a shell tool runs. Codex may send an argument vector
 * (["bash", "-lc", "<command>"]): its command is the same text a string form
 * would carry, so both give the same normalized action.
 */
function shellCommand(event: ToolEvent): string {
  const input = event.tool_input && typeof event.tool_input === 'object' && !Array.isArray(event.tool_input)
    ? event.tool_input as Record<string, unknown> : null;
  const argv = Array.isArray(input?.command) ? input!.command : Array.isArray(input?.cmd) ? input!.cmd : null;
  if (argv && argv.every((item) => typeof item === 'string')) {
    const words = argv as string[];
    if (words.length === 3 && /^(?:.*\/)?(?:ba|z|da|k)?sh$/.test(words[0]) && /^-[a-z]*c$/.test(words[1])) return words[2];
    return words.map((word) => (/[\s'"]/.test(word) ? `'${word.replace(/'/g, `'\\''`)}'` : word)).join(' ');
  }
  return hookToolCommand(event as Parameters<typeof hookToolCommand>[0]);
}

function inputHash(input: unknown): { input_sha256: string } | Record<string, never> {
  if (input === undefined || input === null) return {};
  return { input_sha256: sha256(`${HASH_VERSION}\ninput\n${JSON.stringify(sortedValue(redactedInput(input)))}`) };
}

export function normalizedHookAction(event: ToolEvent): NormalizedHookAction {
  const toolName = normalizeHookToolName(event.tool_name) || 'tool';
  // The host's own tool name (stable across retries); the policy name decides the kind.
  const hostToolName = (typeof event.tool_name === 'string' && event.tool_name.trim() ? event.tool_name.trim() : toolName).slice(0, 128);
  if (isMcpHookTool(event.tool_name) || /^MCP:/i.test(hostToolName)) {
    return { tool_kind: 'mcp', tool_name: hostToolName, tool_input: inputHash(event.tool_input) };
  }
  if (isShellGovernedTool(event as Parameters<typeof isShellGovernedTool>[0])) {
    const { text, programs } = normalizeShellCommand(shellCommand(event));
    return {
      tool_kind: 'shell',
      tool_name: hostToolName,
      programs,
      tool_input: { command_sha256: sha256(`${HASH_VERSION}\nshell\n${text}`) },
    };
  }
  if (EDIT_TOOLS.test(toolName)) {
    const paths = toolTargetPaths(event as Parameters<typeof toolTargetPaths>[0])
      .map((path) => redactKeyShapedParts(redactSensitiveText(path)).slice(0, 512)).slice(0, 64);
    return { tool_kind: 'edit', tool_name: hostToolName, paths, tool_input: inputHash(event.tool_input) };
  }
  return { tool_kind: 'other', tool_name: hostToolName, tool_input: inputHash(event.tool_input) };
}
