import { realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import { posix } from 'node:path';
import { isOfficialMarrowMcpEvent, isOfficialMarrowMcpTool } from './own-tool';
import { APPROVAL_STATE_TREE, ENV_TEMPLATE_WORDS, PROC_ENVIRON, PROC_PROCESS_TREE, SECRET_PATTERNS } from './secret-paths';

export { isOfficialMarrowMcpEvent, isOfficialMarrowMcpTool };

/**
 * Marks the Bash twin of a PowerShell call (toolPolicyReading): its text is PowerShell, not Bash. A symbol,
 * so no field of a host event or of a tool input (JSON has no symbols) can set or clear it.
 */
export const SHELL_DIALECT = Symbol('marrow.shellDialect');

export type ToolPolicyEvent = {
  tool_name?: string;
  tool_input?: unknown;
  [SHELL_DIALECT]?: ShellDialect;
};

/** The shell a command text is written in, when it is not Bash's own. */
export type ShellDialect = 'powershell';

const READ_ONLY_TOOLS = new Set([
  'read',
  'read_file',
  'grep',
  'glob',
  'ls',
  'list_dir',
  'notebookread',
  'todoread',
  'tasklist',
  'taskget',
  'sessions_list',
  'sessions_history',
  'session_status',
  'search_tool',
  'web_search',
  'open_page',
  'get_command_or_subagent_output',
  'marrow_list_memories',
  'marrow_retrieve_memories',
  'marrow_get_memory',
  'marrow_dashboard',
  'marrow_digest',
  'marrow_status',
  'marrow_orient',
  'marrow_ask',
]);

// Session-local planning state: no external side effect, so words in a task
// subject such as "publish" never make the bookkeeping call itself protected.
const LOCAL_TASK_TOOLS = new Set(['taskcreate', 'taskupdate', 'taskoutput', 'todowrite', 'tasklist', 'taskget', 'todoread']);

// Tools that read file content; a secret target makes the read protected.
const CONTENT_READ_TOOLS = new Set(['read', 'read_file', 'notebookread', 'grep']);
// File-editing tools are judged by the file they write, never by the text they write.
const FILE_EDIT_TOOLS = new Set(['edit', 'write', 'multiedit', 'search_replace', 'notebookedit', 'write_to_file', 'replace_in_file']);
const SHELL_TOOLS = new Set(['bash', 'run_terminal_command', 'shell', 'execute_command', 'run_shell_command']);

const READ_ONLY_BASH_COMMANDS = new Set([
  'read', 'grep', 'rg', 'ls', 'cat', 'find', 'tail', 'head', 'wc', 'file',
  'stat', 'which', 'type', 'echo', 'printf', 'pwd', 'date', 'env', 'printenv',
  'whoami', 'uname', 'jq', 'cd', 'sort', 'cut', 'tr', 'nl', 'du', 'basename',
  'dirname', 'realpath', 'readlink', 'true',
]);
// Read-only programs whose arguments are names, text, or metadata targets rather
// than file content, so a secret-looking argument is not a secret read.
const NON_CONTENT_BASH_COMMANDS = new Set([
  'ls', 'find', 'stat', 'file', 'du', 'which', 'type', 'echo', 'printf', 'pwd',
  'date', 'whoami', 'uname', 'cd', 'basename', 'dirname', 'realpath', 'readlink',
  'true', 'tr', 'env', 'printenv',
]);
const READ_ONLY_TOOLCHAIN_COMMANDS = [
  /^(?:node|npm)\s+(?:-v|--version)$/i,
  /^(?:npm|pnpm|yarn)\s+(?:test|audit(?!\s+fix)|run\s+(?:test|check|lint|typecheck|build))(?:\s|$)/i,
  /^(?:node\s+--test|npx\s+(?:vitest|tsc\s+--noemit)|pytest|python(?:3)?\s+-m\s+(?:pytest|unittest)|cargo\s+(?:test|check)|go\s+test)(?:\s|$)/i,
  /^(?:npm|pnpm)\s+(?:view|info|show|ls|list|outdated|explain|why)(?:\s|$)/i,
  /^yarn\s+(?:info|list|why|outdated)(?:\s|$)/i,
];
const READ_ONLY_GIT_SUBCOMMANDS = new Set(['status', 'diff', 'show', 'log', 'branch', 'rev-parse', 'ls-files', 'ls-remote']);
const READ_ONLY_GH_COMMAND = /^(?:pr\s+(?:view|list|status|diff|checks)|issue\s+(?:view|list|status)|run\s+(?:view|list)|repo\s+view|release\s+(?:view|list)|workflow\s+(?:view|list))(?:\s|$)/i;
const STANDARD_PROGRAM_PATH = /^\/(?:usr\/)?(?:local\/)?s?bin\/([A-Za-z0-9._-]+)$/;

const SECRET_STORE_DIRECTORY = /^(?:\.ssh|\.gnupg|\.aws|\.azure|\.kube|\.docker|\.password-store|\.secrets?)$/i;
// A plainly named secrets/credentials directory holds secret material, but source code may live in one too.
const NAMED_SECRET_DIRECTORY = /^(?:secrets?|credentials?)$/i;
const SECRET_FILE = /^(?:\.env(?:\..+)?|.+\.env|\.dev\.vars|\.git-credentials|\.netrc|_netrc|\.npmrc|\.yarnrc\.ya?ml|\.pypirc|\.pgpass|\.my\.cnf|\.htpasswd|\.?credentials\.(?:json|ya?ml|toml|ini|csv|txt|xml)|secrets?\.(?:json|ya?ml|toml|env|txt)|id_(?:rsa|dsa|ecdsa|ed25519)(?:_[A-Za-z0-9]+)?|.+\.(?:pem|key|p12|pfx|jks|keystore|kdbx|ppk))$/i;
// One list with the keyless seatbelt (ENV_TEMPLATE_WORDS, src/secret-paths.ts): a `.env` template is `.example`, `.sample` or `.template` and nothing else, so
// `.env.dist`, `.env.defaults` and `.env.default` are secret files in both modes. A test keeps this list equal to the keyless table's.
const ENV_TEMPLATE_FILE = new RegExp(`(?:^|\\.)env\\.(?:${ENV_TEMPLATE_WORDS.join('|')})$`, 'i');
const SECRET_KEYWORD_FILE = /(?:^|[._-])(?:secrets?|credentials?|tokens?|api[_-]?keys?|passwords?|private[_-]?keys?)(?:[._-]|$)/i;
const SOURCE_OR_DOC_FILE = /\.(?:[cm]?[jt]sx?|md|mdx|rst|py|rb|go|rs|java|kt|swift|c|cc|cpp|h|hpp|cs|php|sh|bash|zsh|ps1|sql|html|css|scss|vue|svelte|map|snap|lock)$/i;
const SECRET_VARIABLE_PART = new Set(['KEY', 'APIKEY', 'TOKEN', 'SECRET', 'PASSWORD', 'PASSWD', 'PAT', 'CREDENTIAL', 'CREDENTIALS', 'AUTH']);
const GOVERNANCE_CONTROL_FILE = /(?:^|\/)\.marrow\/control\.json$/;
const MAX_SHELL_ANALYSIS_BYTES = 8192;
// Characters whose shell meaning the splitter does not model exactly. Bash
// treats a lone carriage return, other control characters and Unicode spaces
// or line separators as word characters, so splitting on them could hide one
// command inside another; such input takes the conservative whole-command path.
const UNMODELED_SHELL_CHARACTER = /[\u0000-\u0008\u000b-\u001f\u007f-\u00a0\u00ad\u061c\u1680\u180e\u2000-\u200f\u2028-\u202f\u205f-\u206f\u3000\ufeff\ufff9-\ufffb]/;
// PowerShell reads the typographic single and double quotation marks as quotes; Bash does not, so
// a PowerShell text holding one has quoting the splitter cannot follow.
const POWERSHELL_QUOTE_CHARACTER = /[\u2018-\u201f]/;
// Programs whose options can execute, write, or change what runs; an expanded
// variable could supply such an option, so they are not read-only with one.
const OPTION_SENSITIVE_PROGRAMS = new Set(['find', 'rg', 'sort', 'git', 'gh', 'date', 'env', 'file', 'npm', 'pnpm', 'yarn', 'node', 'npx',
  'pytest', 'python', 'python3', 'cargo', 'go']);

const MUTATION_TOOL_VERB = /(?:^|__|_)(?:create|update|delete|remove|write|edit|send|post|put|patch|execute|run|deploy|publish|merge|push|commit|revoke|rotate|charge|refund|cancel|approve)(?:_|$)/;
const READ_ONLY_TOOL_VERB = /(?:^|__|_)(?:get|list|read|search|find|fetch|status|inspect|query)(?:_|$)/;

const PROTECTED_SHELL_MUTATION_FAMILIES = [
  /\b(?:npm|pnpm|yarn)(?:\s+npm)?\b[\s\S]{0,8192}\b(?:publish|unpublish|deprecate|access|owner|team|token|login|logout|profile\s+(?:set|enable-2fa|disable-2fa)|org\s+(?:set|rm|remove)|dist-tag|tag\s+(?:add|remove))\b/i,
  /\b(?:cargo\s+(?:publish|yank|owner)|twine\s+upload|gem\s+(?:push|yank|owner)|(?:dotnet\s+nuget|nuget)\s+(?:push|delete))\b/i,
  /\bgit\b[\s\S]{0,8192}\b(?:push|commit|merge|rebase|reset|tag|clean|rm|update-ref|cherry-pick|revert|worktree\s+(?:add|move|remove|prune|repair|lock|unlock)|branch\s+(?:-[dDmM]|--delete|--move)|remote\s+(?:add|remove|rename|set-url|set-head|prune|update)|checkout\s+-[bB]|switch\s+-[cC])\b/i,
  /\bgh\b[\s\S]{0,8192}\b(?:auth\s+logout|pr\s+(?:merge|close|reopen|edit|review|comment)|issue\s+(?:create|close|reopen|edit|comment)|run\s+(?:cancel|delete|rerun)|release\s+(?:create|delete|edit|upload)|repo\s+(?:archive|delete|edit|fork|rename|transfer)|workflow\s+run|secret\s+(?:set|delete)|variable\s+(?:set|delete))\b/i,
  /\bgh\s+api\b[\s\S]{0,8192}(?:(?:--method|-X)(?:=|\s+)(?:POST|PUT|PATCH|DELETE)\b|(?:-f|-F|--field|--raw-field|--input)(?:=|\s+))/i,
  /\b(?:kubectl|oc)\b[\s\S]{0,8192}\b(?:apply|create|delete|edit|patch|replace|rollout|scale|set|drain|cordon|uncordon|taint|exec|cp|run|expose|autoscale|label|annotate|reconcile|certificate\s+(?:approve|deny))\b/i,
  /\b(?:terraform|terragrunt|tofu)\b[\s\S]{0,8192}\b(?:apply|destroy|import|taint|untaint|force-unlock|state\s+(?:mv|rm|push|replace-provider)|workspace\s+(?:new|delete))\b/i,
  /\bpulumi\b[\s\S]{0,8192}\b(?:up|destroy|import|refresh|stack\s+rm|config\s+(?:set|rm))\b/i,
  /\bhelm\b[\s\S]{0,8192}\b(?:install|upgrade|uninstall|rollback|push)\b/i,
  /\bflux\b[\s\S]{0,8192}\b(?:bootstrap|create|delete|install|reconcile|resume|suspend|tag|uninstall)\b/i,
  /\bnomad\b[\s\S]{0,8192}\b(?:job\s+(?:dispatch|plan|promote|run|scale|stop)|alloc\s+stop|deployment\s+(?:fail|promote)|node\s+drain|acl\s+(?:bootstrap|policy|role|token))\b/i,
  /\bcdk\b[\s\S]{0,8192}\b(?:bootstrap|deploy|destroy|import|rollback|watch)\b/i,
  /\bansible-playbook\b/i,
  /\bansible\b[\s\S]{0,8192}(?:(?:-m|--module-name)(?:=|\s+)(?:shell|command|raw|script)\b|(?:-a|--args)(?:=|\s+))/i,
  /\b(?:docker|podman)\b[\s\S]{0,8192}\b(?:push|buildx\s+build\b[\s\S]*--push)\b/i,
  /\bwrangler\b[\s\S]{0,8192}\b(?:deploy|delete|rollback|execute|apply|put|bulk|secret|publish)\b/i,
  /\bcurl\b[\s\S]{0,8192}(?:(?:-X\s*|--request(?:=|\s+))(?:POST|PUT|PATCH|DELETE)\b|--(?:json|data(?:-ascii|-raw|-binary|-urlencode)?)(?:=|\s+)|-[dF](?:\s+|[^A-Za-z])|--form(?:-string)?(?:=|\s+)|(?:-T|--upload-file|-K|--config)(?:=|\s+))/i,
  /\b(?:http|xh)\b[\s\S]{0,8192}(?:\b(?:POST|PUT|PATCH|DELETE)\b|(?:--form|--raw|-f)\b|\s[^\s=:@]+(?::=|=|@))/i,
  /\bwget\b[\s\S]{0,8192}(?:--post-data|--post-file|--body-data|--body-file|--method(?:=|\s+)(?:POST|PUT|PATCH|DELETE))\b/i,
  /\b(?:psql|mysql|sqlite3|duckdb)\b[\s\S]{0,8192}(?:\b(?:drop|delete|update|insert|replace|alter|truncate|create|grant|revoke|call|do)\b|(?:-f|--file|\.read|source)(?:=|\s+)|\s<\s*[^\s])/i,
  /\bredis-cli\b[\s\S]{0,8192}(?:--pipe\b|\b(?:set|setex|psetex|mset|del|unlink|getdel|incr|decr|append|expire|persist|rename|move|flushall|flushdb|shutdown|eval|evalsha|fcall|fcall_ro|function|script\s+(?:load|flush|kill)|config\s+set|acl\s+setuser|hset|hdel|lpush|rpush|lpop|rpop|sadd|srem|zadd|zrem|xadd|xdel|publish|restore|migrate)\b)/i,
  /\baws\b[\s\S]{0,8192}\b(?:create|update|delete|put|attach|detach|associate|disassociate|terminate|stop|start|reboot|modify|restore|rotate|tag|untag|deploy|sync|s3\s+(?:cp|mv|rm)|s3api\s+put-object|ssm\s+(?:put-parameter|delete-parameter|delete-parameters))\b/i,
  /\bgcloud\b[\s\S]{0,8192}\b(?:create|update|delete|deploy|add|remove|set|destroy|disable|restore|storage\s+(?:cp|mv|rm|rsync)|pubsub\s+(?:topics|subscriptions)\s+(?:create|delete|update))\b/i,
  /\baz\b[\s\S]{0,8192}\b(?:create|update|delete|set|deploy|start|stop|restart|restore|storage\s+blob\s+(?:upload|delete|copy)|group\s+(?:create|delete|update))\b/i,
  /\brclone\b[\s\S]{0,8192}\b(?:copy|copyto|sync|move|moveto|delete|deletefile|purge|mkdir|rmdir|bisync)\b/i,
  /\bgsutil\b[\s\S]{0,8192}\b(?:cp|mv|rm|rsync|setacl|setmeta|web)\b/i,
  /(?:^|[;&|]\s*|\bsudo\s+|\benv\s+)mc\b[\s\S]{0,8192}\b(?:cp|mv|rm|mirror|mb|rb|anonymous|admin)\b/i,
  /\boci\b[\s\S]{0,8192}\bos\b[\s\S]{0,8192}\b(?:put|upload|bulk-upload|delete|rename|restore|reencrypt)\b/i,
  /\b(?:vault|op)\b[\s\S]{0,8192}\b(?:write|put|patch|delete|edit|create|move|rotate|revoke|destroy|share|operator\s+(?:init|rekey|generate-root|seal|unseal))\b/i,
  /\bpass\b[\s\S]{0,8192}\b(?:insert|edit|generate|rm|remove|mv|cp|init|git)\b/i,
  /(?:^|[\s;&|]|\bsudo\s+|\benv\s+)(?:(?:\/[^\s/]+)*\/)?(?:rm\b|unlink\b|shred\b|truncate\b|dd\b[\s\S]{0,8192}\bof=|find\b[\s\S]{0,8192}\s-delete\b|xargs\b[\s\S]{0,8192}(?:(?:\/[^\s/]+)*\/)?rm\b)/i,
  /(?:^|[\s;&|])["']\/(?:[^\/"']+\/)*(?:rm|unlink|shred|truncate)["'](?:\s|$)/i,
];

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

export function normalizeHookToolName(value: unknown): string {
  const raw = String(value || '').trim();
  const withoutNamespace = raw.replace(/^functions\./i, '');
  const mapped = /^(?:exec|exec_command)$/i.test(withoutNamespace) ? 'bash'
    : /^(?:apply_patch|write_file)$/i.test(withoutNamespace) ? 'edit'
    : /^(?:view_image|read_file)$/i.test(withoutNamespace) ? 'read_file'
    : withoutNamespace;
  return mapped.replace(/^mcp__/, '').replace(/^MCP:/i, '').trim().toLowerCase();
}

/** An MCP tool in any host form, including Codex's `functions.` namespace (repeated or padded). */
export function isMcpHookTool(value: unknown): boolean {
  return /^(?:functions\.\s*)*(?:mcp__|mcp_|MCP:)/i.test(String(value || '').trim());
}

export function isProtectedShellMutation(command: string): boolean {
  const raw = String(command || '');
  if (raw.length > 8192) return true;
  const bounded = raw.slice(0, 8192);
  return PROTECTED_SHELL_MUTATION_FAMILIES.some((pattern) => pattern.test(bounded));
}

export function hookToolCommand(event: ToolPolicyEvent): string {
  if (typeof event.tool_input === 'string') return event.tool_input.trim();
  const input = asRecord(event.tool_input);
  if (!input) return '';
  for (const key of ['command', 'cmd', 'description', 'query', 'path', 'file_path', 'url', 'name']) {
    const value = stringValue(input[key]);
    if (value) return value;
  }
  try {
    return JSON.stringify(input).slice(0, 4096);
  } catch {
    return '';
  }
}

export type ShellSegment = {
  words: string[];
  outputs: string[];
  inputs: string[];
  expansions: string[];
};

type RedirectKind = 'out' | 'in' | 'dup_out' | 'dup_in';
export type ShellSegmentVerdict = 'read' | 'secret' | 'other';

/**
 * Splits a shell command into simple commands at |, ||, &&, ;, & and newlines,
 * honoring quotes. Returns null for syntax whose effect cannot be judged from
 * the words alone (command or process substitution, subshells, heredocs,
 * complex parameter expansion); callers then fall back to whole-command rules.
 */
export function parseShellSegments(command: string, dialect?: ShellDialect): ShellSegment[] | null {
  if (command.length > MAX_SHELL_ANALYSIS_BYTES || UNMODELED_SHELL_CHARACTER.test(command)) return null;
  const powershell = dialect === 'powershell';
  if (powershell && POWERSHELL_QUOTE_CHARACTER.test(command)) return null;
  const segments: ShellSegment[] = [];
  let segment: ShellSegment = { words: [], outputs: [], inputs: [], expansions: [] };
  let word = '';
  let inWord = false;
  let redirect: RedirectKind | null = null;
  const finishWord = (): void => {
    if (!inWord) return;
    if (redirect === 'out' || redirect === 'in') (redirect === 'out' ? segment.outputs : segment.inputs).push(word);
    else if (redirect) {
      // >&2 and <&0 duplicate descriptors; any other >&target names a file.
      if (!/^(?:\d+|-|\d+-)$/.test(word)) (redirect === 'dup_out' ? segment.outputs : segment.inputs).push(word);
    } else segment.words.push(word);
    redirect = null;
    word = '';
    inWord = false;
  };
  const finishSegment = (): boolean => {
    finishWord();
    if (redirect) return false;
    if (segment.words.length || segment.outputs.length || segment.inputs.length) segments.push(segment);
    segment = { words: [], outputs: [], inputs: [], expansions: [] };
    return true;
  };
  // Reads $NAME, ${NAME} or a special parameter at index; returns the consumed length, or -1 when unsupported.
  const expansion = (index: number): number => {
    const rest = command.slice(index);
    // $( runs a command; $'...' and $"..." decode escapes the words would hide.
    if (rest.startsWith('$(') || rest.startsWith("$'") || rest.startsWith('$"')) return -1;
    const braced = /^\$\{([A-Za-z_][A-Za-z0-9_]*)\}/.exec(rest);
    if (braced) {
      segment.expansions.push(braced[1]);
      word += braced[0];
      inWord = true;
      return braced[0].length;
    }
    if (rest.startsWith('${')) return -1;
    const named = /^\$([A-Za-z_][A-Za-z0-9_]*)/.exec(rest);
    if (named) {
      segment.expansions.push(named[1]);
      word += named[0];
      inWord = true;
      return named[0].length;
    }
    word += '$';
    inWord = true;
    return 1;
  };
  let index = 0;
  while (index < command.length) {
    const char = command[index];
    const next = command[index + 1];
    if (char === "'") {
      const end = command.indexOf("'", index + 1);
      if (end < 0) return null;
      word += command.slice(index + 1, end);
      inWord = true;
      index = end + 1;
      continue;
    }
    if (char === '"') {
      inWord = true;
      index += 1;
      let closed = false;
      while (index < command.length) {
        const inner = command[index];
        if (inner === '"') { closed = true; index += 1; break; }
        if (inner === '`') return null;
        if (!powershell && inner === '\\' && index + 1 < command.length && '$`"\\\n'.includes(command[index + 1])) {
          if (command[index + 1] !== '\n') word += command[index + 1];
          index += 2;
          continue;
        }
        if (inner === '$') {
          const consumed = expansion(index);
          if (consumed < 0) return null;
          index += consumed;
          continue;
        }
        word += inner;
        index += 1;
      }
      if (!closed) return null;
      continue;
    }
    // PowerShell's escape is the backtick (unmodeled); a backslash there is a path separator.
    if (char === '\\' && !powershell) {
      if (next === undefined) return null;
      if (next !== '\n') { word += next; inWord = true; }
      index += 2;
      continue;
    }
    // Braces expand or group commands, so the words would not be what runs.
    if (char === '`' || char === '(' || char === ')' || char === '{') return null;
    // A PowerShell here-string (@' or @") holds lines of text up to a closing quote at a line start: not words.
    if (powershell && char === '@' && (next === "'" || next === '"')) return null;
    if (char === '$') {
      const consumed = expansion(index);
      if (consumed < 0) return null;
      index += consumed;
      continue;
    }
    if (char === ' ' || char === '\t') { finishWord(); index += 1; continue; }
    if (char === '\n' || char === ';') {
      if (!finishSegment()) return null;
      index += 1;
      continue;
    }
    if (char === '|') {
      if (!finishSegment()) return null;
      index += next === '|' || next === '&' ? 2 : 1;
      continue;
    }
    if (char === '&') {
      if (next === '>') {
        finishWord();
        if (redirect) return null;
        redirect = 'out';
        index += command[index + 2] === '>' ? 3 : 2;
        continue;
      }
      if (!finishSegment()) return null;
      index += next === '&' ? 2 : 1;
      continue;
    }
    if (char === '>' || char === '<') {
      // A digits-only word directly before the operator is a descriptor (2>).
      if (inWord && /^\d+$/.test(word)) { word = ''; inWord = false; } else finishWord();
      if (redirect) return null;
      if (char === '<' && next === '<') return null;
      if (next === '(') return null;
      let cursor = index + 1;
      if (char === '>' && (command[cursor] === '>' || command[cursor] === '|')) cursor += 1;
      if (command[cursor] === '&') {
        redirect = char === '>' ? 'dup_out' : 'dup_in';
        cursor += 1;
      } else if (char === '<' && command[cursor] === '>') {
        redirect = 'out';
        cursor += 1;
      } else {
        redirect = char === '>' ? 'out' : 'in';
      }
      index = cursor;
      continue;
    }
    if (char === '#' && !inWord) {
      while (index < command.length && command[index] !== '\n') index += 1;
      continue;
    }
    word += char;
    inWord = true;
    index += 1;
  }
  if (!finishSegment()) return null;
  return segments;
}

function pathCandidates(value: string): string[] {
  const candidates = [value];
  const assigned = value.indexOf('=');
  if (assigned >= 0) candidates.push(value.slice(assigned + 1));
  const revision = value.lastIndexOf(':');
  if (revision >= 0) candidates.push(value.slice(revision + 1));
  return candidates.filter(Boolean);
}

function homeDirectory(): string {
  return process.env.HOME || homedir();
}

function expandHome(value: string): string {
  if (value === '~' || value.startsWith('~/')) return `${homeDirectory()}${value.slice(1)}`;
  return value.replace(/^\$(?:HOME|\{HOME\})(?=\/|$)/, homeDirectory());
}

/** Resolves ~, $HOME, ., .. and repeated slashes against the directory the command runs in. */
export function normalizedToolPath(value: string, base = process.cwd()): string {
  return posix.resolve(base.replace(/\\/g, '/'), expandHome(value.trim().replace(/\\/g, '/')));
}

function secretPath(value: string, base: string): boolean {
  const cleaned = value.trim().replace(/\\/g, '/');
  if (!cleaned) return false;
  const rawName = cleaned.replace(/\/+$/, '').split('/').pop() || '';
  // A bare word such as "token" is usually a search term or argument, not a file.
  const pathLike = cleaned.includes('/') || cleaned.startsWith('~') || rawName.startsWith('.') || /\.[A-Za-z0-9]+$/.test(rawName);
  const path = normalizedToolPath(cleaned, base);
  const parts = path.split('/').filter(Boolean);
  const name = parts[parts.length - 1] || '';
  const directories = pathLike ? parts : parts.slice(0, -1);
  if (directories.some((part) => SECRET_STORE_DIRECTORY.test(part))) return true;
  if (!SOURCE_OR_DOC_FILE.test(name) && directories.some((part) => NAMED_SECRET_DIRECTORY.test(part))) return true;
  if (PROC_ENVIRON.test(path) || /^\/etc\/g?shadow$/.test(path)) return true;
  // Claude Code local settings can carry agent keys in their env block.
  if (name === 'settings.local.json' && parts[parts.length - 2] === '.claude') return true;
  if (!pathLike) return SECRET_FILE.test(name) && !ENV_TEMPLATE_FILE.test(name);
  if (ENV_TEMPLATE_FILE.test(name)) return false;
  if (SECRET_FILE.test(name)) return true;
  // One table: every path the keyless seatbelt stops as a secret (S4) is a secret here too.
  // Only the last 4096 characters (PATH_MAX) are read: the patterns end at `$`, and a two-`**`
  // pattern backtracks quadratically, so an unbounded path could stall the hook past its timeout.
  const tail = path.length > SECRET_PATH_TABLE_CHARS ? path.slice(-SECRET_PATH_TABLE_CHARS) : path;
  if (SEATBELT_SECRET_PATHS.some((pattern) => pattern.test(tail)) || APPROVAL_STATE_TREE.test(tail)) return true;
  return SECRET_KEYWORD_FILE.test(name) && !SOURCE_OR_DOC_FILE.test(name);
}

/**
 * A SECRET_PATTERNS glob (src/secret-paths.ts) as a regex, the way the vendored classifier's globToRegex reads
 * it (the table holds only `**`/`*` globs, home-agnostic `**`/ prefixes and absolute paths).
 */
export function secretPatternRegex(pattern: string): RegExp {
  let p = pattern;
  let anchored = true;
  if (p.startsWith('**/')) { anchored = false; p = p.slice(3); }
  let out = '';
  for (let i = 0; i < p.length; i += 1) {
    const ch = p[i];
    if (ch === '*' && p[i + 1] === '*') {
      if (p[i + 2] === '/') { out += '(?:.*/)?'; i += 2; }
      else if (out.endsWith('/') && i + 2 === p.length) { out = `${out.slice(0, -1)}(?:/.*)?`; i += 1; }
      else { out += '.*'; i += 1; }
    } else if (ch === '*') out += '[^/]*';
    else if (ch === '?') out += '[^/]';
    else out += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`${anchored ? '^' : '(?:^|/)'}${out}$`);
}

const SEATBELT_SECRET_PATHS: readonly RegExp[] = SECRET_PATTERNS.map(secretPatternRegex);
const SECRET_PATH_TABLE_CHARS = 4096;

// A glob such as .env* or *.pem names secret files without spelling one out.
function globVariants(value: string): string[] {
  if (!/[*?[]/.test(value)) return [value];
  const firstInClass = value.replace(/\[!?\^?([^\]])[^\]]*\]/g, '$1');
  return [value, firstInClass.replace(/[*?]/g, ''), firstInClass.replace(/[*?]/g, 'x')];
}

/** True for a path that holds secret or credential material. */
export function isSecretPath(value: string, base = process.cwd()): boolean {
  return pathCandidates(String(value || '')).flatMap(globVariants).some((candidate) => secretPath(candidate, base));
}

/** The host-approvals folder, or ~/.marrow that holds it: a search tool that walks either reads the state file. */
function isApprovalStateFolder(value: string, base = process.cwd()): boolean {
  const folder = posix.join(homeDirectory(), '.marrow', 'host-approvals').toLowerCase();
  return pathCandidates(String(value || '')).some((candidate) => {
    const walked = normalizedToolPath(candidate, base).replace(/\/+$/, '').toLowerCase();
    return walked === folder || walked === posix.dirname(folder);
  });
}

/** A process folder (`/proc`, `/proc/self/task`): a search tool that walks it reads the `environ` of every process under it. */
function isProcessFolder(value: string, base = process.cwd()): boolean {
  return pathCandidates(String(value || '')).some((candidate) => PROC_PROCESS_TREE.test(normalizedToolPath(candidate, base)));
}

/**
 * True when a path the tool names is a symbolic link, or goes through one, to a secret file (or, for a write, to a protected one): a read or an edit
 * through it is of the file it points at, whatever the link is called. Only a path that exists and resolves elsewhere is read; nothing else changes.
 */
function secretThroughLink(value: string, write: boolean, base = process.cwd()): boolean {
  return pathCandidates(String(value || '')).some((candidate) => {
    let real: string;
    try {
      const lexical = normalizedToolPath(candidate, base);
      real = realpathSync(lexical);
      if (real === lexical) return false;
    } catch { return false; }
    return write ? isProtectedWriteTarget(real) : isSecretPath(real);
  });
}

/** True for a secret file or Marrow's own local control state. */
export function isProtectedWriteTarget(value: string, base = process.cwd()): boolean {
  return pathCandidates(String(value || '')).flatMap(globVariants).some((candidate) => secretPath(candidate, base)
    || GOVERNANCE_CONTROL_FILE.test(normalizedToolPath(candidate, base)));
}

/** True for an environment variable name that conventionally holds a secret. */
export function isSecretVariableName(value: string): boolean {
  return String(value || '').toUpperCase().split('_').some((part) => SECRET_VARIABLE_PART.has(part));
}

// Whether a shell command prints the environment is answered by the pre-action hook, which passes its check in as an argument. The
// policy loads nothing for it, so the PostToolUse path (hook.ts calls isReadOnlyToolEvent with no check) never pays for the answer.
export type EnvironmentPrintCheck = (command: string) => boolean;

function programName(value: string): string | null {
  if (!value.includes('/')) return value.toLowerCase();
  const standard = STANDARD_PROGRAM_PATH.exec(value);
  return standard ? standard[1].toLowerCase() : null;
}

// Positional file arguments for content readers, skipping the pattern or filter
// operand of grep, rg and jq, and option values that are not files.
function contentReadTargets(program: string, args: string[]): string[] {
  const targets: string[] = [];
  const patternFirst = ['grep', 'egrep', 'fgrep', 'rg', 'jq'].includes(program);
  const valueOptions = program === 'jq'
    ? new Set(['--indent', '--tab'])
    : new Set(['-A', '-B', '-C', '-m', '-d', '-D', '-g', '-t', '-T', '-j', '-M', '--max-count', '--context', '--glob', '--type', '--type-not', '--threads', '--max-columns']);
  let patternSeen = !patternFirst;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (program === 'jq' && (arg === '--arg' || arg === '--argjson')) { index += 2; continue; }
    if (program === 'jq' && (arg === '--slurpfile' || arg === '--rawfile')) {
      if (args[index + 2] !== undefined) targets.push(args[index + 2]);
      index += 2;
      continue;
    }
    if (['-e', '--regexp', '-f', '--file', '--from-file'].includes(arg)) {
      if (arg !== '-e' && arg !== '--regexp' && args[index + 1] !== undefined) targets.push(args[index + 1]);
      patternSeen = true;
      index += 1;
      continue;
    }
    if (valueOptions.has(arg)) { index += 1; continue; }
    if (arg.startsWith('-')) {
      if (arg.includes('=')) targets.push(arg);
      continue;
    }
    if (!patternSeen) { patternSeen = true; continue; }
    targets.push(arg);
  }
  return targets;
}

// GNU getopt and git accept any unambiguous prefix of a long option.
function longOptionPrefix(arg: string, names: string[]): boolean {
  if (!arg.startsWith('--')) return false;
  const name = arg.slice(2).split('=')[0];
  return name.length > 0 && names.some((candidate) => candidate.startsWith(name));
}

const GIT_BRANCH_LIST_FLAGS = new Set(['--list', '-l', '-a', '--all', '-r', '--remotes', '-v', '-vv', '--verbose', '--show-current',
  '-i', '--ignore-case', '--color', '--no-color', '--column', '--no-column', '--omit-empty']);
const GIT_BRANCH_VALUE_FLAGS = new Set(['--contains', '--no-contains', '--merged', '--no-merged', '--points-at', '--sort', '--format']);

// `git branch` only lists when every argument is a list option or a --list pattern.
function gitBranchListsOnly(args: string[]): boolean {
  const listing = args.includes('--list') || args.includes('-l');
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (GIT_BRANCH_LIST_FLAGS.has(arg)) continue;
    if (GIT_BRANCH_VALUE_FLAGS.has(arg)) { index += 1; continue; }
    if ([...GIT_BRANCH_VALUE_FLAGS].some((flag) => arg.startsWith(`${flag}=`))) continue;
    if (!arg.startsWith('-') && listing) continue;
    return false;
  }
  return true;
}

function readOnlyProgramInvocation(program: string, args: string[]): boolean {
  if (program === 'git') {
    let index = 0;
    while (index < args.length) {
      if (args[index] === '-C' && args[index + 1] !== undefined) index += 2;
      else if (args[index] === '--no-pager') index += 1;
      else break;
    }
    const subcommand = args[index] || '';
    const rest = args.slice(index + 1);
    if (!READ_ONLY_GIT_SUBCOMMANDS.has(subcommand)) return false;
    if (subcommand === 'branch') return gitBranchListsOnly(rest);
    if (subcommand === 'ls-remote') return !rest.some((arg) => longOptionPrefix(arg, ['upload-pack', 'exec']));
    return !rest.some((arg) => longOptionPrefix(arg, ['output', 'ext-diff']));
  }
  if (program === 'gh') return READ_ONLY_GH_COMMAND.test(args.join(' '));
  if (READ_ONLY_TOOLCHAIN_COMMANDS.some((pattern) => pattern.test([program, ...args].join(' ')))) return true;
  if (!READ_ONLY_BASH_COMMANDS.has(program)) return false;
  if (program === 'find') return !args.some((arg) => /^-(?:exec|execdir|ok|okdir|delete|fprint0?|fprintf|fls)$/.test(arg));
  if (program === 'rg') return !args.some((arg) => longOptionPrefix(arg, ['pre', 'hostname-bin']));
  if (program === 'sort') return !args.some((arg) => longOptionPrefix(arg, ['output', 'compress-program']) || /^-[A-Za-z]*o/.test(arg));
  if (program === 'env') return args.every((arg) => arg === '-0' || arg === '--null');
  if (program === 'date') return !args.some((arg) => /^-[A-Za-z]*s/.test(arg) || longOptionPrefix(arg, ['set']));
  if (program === 'file') return !args.some((arg) => /^-[A-Za-z]*C/.test(arg) || longOptionPrefix(arg, ['compile']));
  return true;
}

/**
 * Classifies one simple command: a read-only inspection, a secret access, or anything else.
 * In the PowerShell dialect no command is a read-only inspection and no program is exempt from
 * the content-read check (Bash's allowlists name Bash programs; `type` and `cat` read files in
 * PowerShell, and `ls env:` and `echo $env:X` print the environment): every word is judged as a
 * file a command may read.
 */
export function shellSegmentVerdict(segment: ShellSegment, cwd: string | null = process.cwd(), dialect?: ShellDialect): ShellSegmentVerdict {
  const powershell = dialect === 'powershell';
  // After a cd Marrow cannot follow, relative paths are unknown, so nothing that follows is read-only.
  const base = cwd ?? process.cwd();
  const secret = (value: string) => isSecretPath(value, base);
  const protectedTarget = (value: string) => isProtectedWriteTarget(value, base);
  const writes = segment.outputs.filter((target) => !['/dev/null', '/dev/stdout', '/dev/stderr'].includes(target));
  if (segment.inputs.some(secret) || writes.some(protectedTarget)) return 'secret';
  if (!segment.words.length) return writes.length || cwd === null || powershell ? 'other' : 'read';
  // A leading assignment can redirect a pager or helper into arbitrary code.
  const program = /^[A-Za-z_][A-Za-z0-9_]*=/.test(segment.words[0]) ? null : programName(segment.words[0]);
  const args = segment.words.slice(1);
  if (program === 'gh' && /^auth\s+(?:token\b|status\b.*(?:--show-token|-t\b))/.test(args.join(' '))) return 'secret';
  const expandedOption = program !== null && OPTION_SENSITIVE_PROGRAMS.has(program) && segment.expansions.length > 0;
  if (program && !expandedOption && readOnlyProgramInvocation(program, args)) {
    // Printing a secret variable copies it into the agent transcript.
    if (segment.expansions.some(isSecretVariableName)) return 'secret';
    if (program === 'printenv' && args.some(isSecretVariableName)) return 'secret';
    // A bare env or printenv prints every secret the process holds.
    if ((program === 'env' || program === 'printenv') && args.every((arg) => arg.startsWith('-'))) return 'secret';
    if (program === 'jq' && args.some((arg) => /\$ENV\b|(?:^|[^A-Za-z0-9_$.])env\b/.test(arg))) return 'secret';
    if (program === 'cd' && args.some(secret)) return 'secret';
    if (powershell || !NON_CONTENT_BASH_COMMANDS.has(program)) {
      const targets = ['grep', 'egrep', 'fgrep', 'rg', 'jq'].includes(program) ? contentReadTargets(program, args) : args.filter((arg) => !arg.startsWith('-') || arg.includes('='));
      if (targets.some(secret)) return 'secret';
    }
    // A PowerShell parameter binds its value in the same word (-Path:.env).
    if (powershell && segment.words.some(protectedTarget)) return 'secret';
    return writes.length || cwd === null || powershell ? 'other' : 'read';
  }
  return segment.words.some(protectedTarget) ? 'secret' : 'other';
}

// The directory later simple commands run in after this one, or null when it cannot be known.
function nextWorkingDirectory(segment: ShellSegment, cwd: string | null): string | null {
  if (cwd === null || programName(segment.words[0] || '') !== 'cd') return cwd;
  const targets = segment.words.slice(1).filter((arg) => arg !== '--');
  if (!targets.length) return homeDirectory();
  if (targets.length > 1 || targets[0] === '-' || targets[0].startsWith('-') || segment.expansions.some((name) => name !== 'HOME')) return null;
  return normalizedToolPath(targets[0], cwd);
}

/** `parse`: the dialect the words are split in; `dialect`: the dialect the simple commands are judged in (default: the same). */
function shellAnalysis(command: string, dialect?: ShellDialect, parse: ShellDialect | 'bash' | undefined = dialect): { segments: ShellSegment[]; verdicts: ShellSegmentVerdict[] } | null {
  const segments = parseShellSegments(command, parse === 'bash' ? undefined : parse);
  if (!segments) return null;
  let cwd: string | null = process.cwd();
  const verdicts = segments.map((segment) => {
    const verdict = shellSegmentVerdict(segment, cwd, dialect);
    cwd = nextWorkingDirectory(segment, cwd);
    return verdict;
  });
  return { segments, verdicts };
}

/**
 * True when the policy's own reading is the whole answer for a shell command: it parses, every simple command in it is a recognised read-only
 * program (a `cat`, `grep`, `ls`, `jq`, `ps`, never a wrapper such as `bash -c`, `eval`, `sudo`, `ssh`, `xargs` or a program that writes), and no word
 * holds a glob, a brace or a variable (those can spell a name the text does not hold). Such a command names its files in the words the policy already
 * judges, so a second reading of it by the mapper could only add the mapper's own over-stops (the pattern or filter operand of `grep .env README.md`).
 */
export function policyReadsAllWords(command: string): boolean {
  try {
    const analysis = shellAnalysis(command);
    if (!analysis?.segments.length || !analysis.verdicts.every((verdict) => verdict === 'read')) return false;
    return analysis.segments.every((segment) => segment.expansions.length === 0 && ![...segment.words, ...segment.inputs, ...segment.outputs].some((word) => /[*?[{]/.test(word)));
  } catch { return false; }
}

function stringLeaves(value: unknown, depth = 0, output: string[] = []): string[] {
  if (output.length >= 64 || depth > 4) return output;
  if (typeof value === 'string') output.push(value);
  else if (Array.isArray(value)) value.forEach((item) => stringLeaves(item, depth + 1, output));
  else if (value && typeof value === 'object') Object.values(value).forEach((item) => stringLeaves(item, depth + 1, output));
  return output;
}

/** Files a file-reading or file-editing tool targets, including apply_patch file headers. */
export function toolTargetPaths(event: ToolPolicyEvent): string[] {
  const paths: string[] = [];
  const input = asRecord(event.tool_input);
  if (input) {
    for (const key of ['file_path', 'path', 'target_file', 'filename', 'notebook_path', 'glob']) {
      const value = stringValue(input[key]);
      if (value) paths.push(value);
    }
  }
  for (const leaf of stringLeaves(event.tool_input)) {
    if (!leaf.includes('*** Begin Patch')) continue;
    for (const match of leaf.matchAll(/^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+)$/gm)) paths.push(match[1].trim());
  }
  return [...new Set(paths)];
}

// The shell text exactly as the host will run it; hookToolCommand trims, and a
// trimmed control or Unicode space character must still reach the parser check.
function shellCommandText(event: ToolPolicyEvent): string {
  if (typeof event.tool_input === 'string') return event.tool_input;
  const input = asRecord(event.tool_input);
  for (const key of ['command', 'cmd']) {
    if (typeof input?.[key] === 'string' && String(input[key]).trim()) return String(input[key]);
  }
  return hookToolCommand(event);
}

/**
 * True when a tool reads secret or credential material, or writes a secret file
 * or Marrow's local control state. Unparseable shell falls back to a token scan.
 * A Monitor command, and any shell text another tool carries, is read as Bash
 * reads its command; a PowerShell command in the PowerShell dialect, which
 * reads every word as a file the command may read (toolPolicyReading).
 */
export function isSecretMaterialAccess(event: ToolPolicyEvent, printsEnvironment?: EnvironmentPrintCheck): boolean {
  const reading = toolPolicyReading(event);
  if (reading.shell.some((twin) => isSecretMaterialAccessAsNamed(twin, printsEnvironment))) return true;
  if (reading.exact) return false;
  if (reading.base === 'read') return isSecretMaterialAccessAsNamed(readEquivalent(event), printsEnvironment);
  return reading.base === 'named' && isSecretMaterialAccessAsNamed(event, printsEnvironment);
}

/** isSecretMaterialAccess for the call's own tool name only (every tool before the built-ins were hooked). */
export function isSecretMaterialAccessAsNamed(event: ToolPolicyEvent, printsEnvironment?: EnvironmentPrintCheck): boolean {
  const tool = normalizeHookToolName(event.tool_name);
  if (CONTENT_READ_TOOLS.has(tool)) return toolTargetPaths(event).some((path) => isSecretPath(path) || secretThroughLink(path, false) || (tool === 'grep' && (isProcessFolder(path) || isApprovalStateFolder(path))));
  if (FILE_EDIT_TOOLS.has(tool)) return toolTargetPaths(event).some((path) => isProtectedWriteTarget(path) || secretThroughLink(path, true));
  if (!SHELL_TOOLS.has(tool)) return false;
  const command = shellCommandText(event);
  if (printsEnvironment && event[SHELL_DIALECT] !== 'powershell' && printsEnvironment(command)) return true;
  const analysis = shellAnalysis(command, event[SHELL_DIALECT]);
  if (event[SHELL_DIALECT] === 'powershell') {
    // The words are split as PowerShell splits them; text whose quoting Bash splits differently (an escaped quote,
    // a typographic quote) is also split as Bash splits it, judged with no allowlist: a secret either finds is one.
    // Where either split cannot be modelled, every token of the text is judged as a path.
    const asBash = shellAnalysis(command, 'powershell', 'bash');
    if (analysis?.verdicts.includes('secret') || asBash?.verdicts.includes('secret')) return true;
    if (analysis && asBash) return false;
  } else if (analysis) return analysis.verdicts.includes('secret');
  return command.split(/[\s'"`;&|<>(){}]+/).some((token) => isProtectedWriteTarget(token));
}

/**
 * The text whose words decide a tool's action type, surfaces and keyword
 * protection. Read-only shell segments, task bookkeeping and the content an
 * editing tool writes are excluded: naming a word is not performing it.
 */
export function toolClassificationText(event: ToolPolicyEvent): string {
  const tool = normalizeHookToolName(event.tool_name);
  if (LOCAL_TASK_TOOLS.has(tool)) return tool;
  if (FILE_EDIT_TOOLS.has(tool)) return [tool, ...toolTargetPaths(event)].join(' ');
  const command = hookToolCommand(event);
  if (SHELL_TOOLS.has(tool)) {
    const analysis = shellAnalysis(shellCommandText(event), event[SHELL_DIALECT]);
    if (analysis) {
      return [tool, ...analysis.segments
        .filter((_, index) => analysis.verdicts[index] !== 'read')
        .map((segment) => [...segment.words, ...segment.outputs].join(' '))].join(' ; ');
    }
  }
  let serialized = '';
  try { serialized = JSON.stringify(event.tool_input || {}); } catch { serialized = ''; }
  return `${tool} ${command} ${serialized}`;
}

/**
 * Whether a tool runs its text as a shell command: Bash and the other terminal tools (Codex exec, Cursor Shell, ...),
 * Monitor and PowerShell. Every other tool whose text is read as shell words (ToolSearch, a prompt, a path, an unknown
 * tool's `command`) only borrows the parser, so no word of it is known to be a program.
 */
export function isShellTextTool(event: ToolPolicyEvent): boolean {
  if (isMcpHookTool(event.tool_name)) return false;
  const tool = normalizeHookToolName(event.tool_name);
  return SHELL_TOOLS.has(tool) || SHELL_COMMAND_TOOLS.has(tool);
}

/** Editing and task tools are judged by their target, not by shell-like text in their input. */
export function isShellGovernedTool(event: ToolPolicyEvent): boolean {
  const tool = normalizeHookToolName(event.tool_name);
  return !FILE_EDIT_TOOLS.has(tool) && !LOCAL_TASK_TOOLS.has(tool);
}

function pathOnlyInput(value: unknown): boolean {
  const input = asRecord(value);
  if (!input) return false;
  const keys = Object.keys(input);
  return keys.length > 0
    && keys.every((key) => ['path', 'file_path', 'filename', 'target_file'].includes(key))
    && Object.values(input).every((item) => typeof item === 'string' && item.trim().length > 0);
}

/**
 * Whether a call only reads. A shell reading (Monitor, a native git
 * equivalent) is read-only exactly when Bash running its text is; a PowerShell
 * call never is (Bash's read-only commands are Bash's); any other
 * call carrying shell text is read-only only when both its own reading and
 * Bash running the text are (never more than before).
 */
export function isReadOnlyToolEvent(event: ToolPolicyEvent): boolean {
  const reading = toolPolicyReading(event);
  if (reading.dialect === 'powershell') return false;
  const shellReadOnly = reading.shell.every((twin) => isReadOnlyToolEventAsNamed(twin));
  if (reading.exact) return reading.shell.length > 0 && shellReadOnly;
  const own = reading.base === 'read' ? isReadOnlyToolEventAsNamed(readEquivalent(event))
    : reading.base === 'non_acting' ? false
    : isReadOnlyToolEventAsNamed(event);
  return own && shellReadOnly;
}

/** isReadOnlyToolEvent for the call's own tool name only (every tool before the built-ins were hooked). */
export function isReadOnlyToolEventAsNamed(event: ToolPolicyEvent, printsEnvironment?: EnvironmentPrintCheck): boolean {
  const tool = normalizeHookToolName(event.tool_name);
  if (!tool) return false;
  // Nothing PowerShell runs is a read-only inspection: the Bash twin of a PowerShell call never is.
  if (event[SHELL_DIALECT] === 'powershell') return false;
  if (LOCAL_TASK_TOOLS.has(tool)) return true;
  if (READ_ONLY_TOOLS.has(tool)) return !isSecretMaterialAccess(event, printsEnvironment);
  if (['edit', 'write', 'multiedit', 'search_replace', 'run_terminal_command', 'spawn_subagent'].includes(tool)) return false;
  if (MUTATION_TOOL_VERB.test(tool)) return false;
  if (READ_ONLY_TOOL_VERB.test(tool)) return true;

  const command = hookToolCommand(event);
  if (tool === 'bash' && command) {
    // Printing the environment is never a read-only inspection.
    if (printsEnvironment && printsEnvironment(shellCommandText(event))) return false;
    // A compound command is read-only only when every simple command in it is.
    const analysis = shellAnalysis(shellCommandText(event));
    return Boolean(analysis?.segments.length && analysis.verdicts.every((verdict) => verdict === 'read'));
  }

  return !['edit', 'write', 'multiedit', 'search_replace'].includes(tool)
    && pathOnlyInput(event.tool_input)
    && !toolTargetPaths(event).some((path) => isSecretPath(path));
}

// ---------------------------------------------------------------------------
// How a call is read for classification. Keys always keep the call's
// own tool name and input (normalized-action, hook-contract).
// ---------------------------------------------------------------------------

// Claude Code tools that run their `command` (or `script`) as a shell command: Monitor in the same
// shell environment as Bash, PowerShell in PowerShell. Any case or padding of the name. Monitor's
// text goes through Bash's rules exactly. PowerShell's does not: Bash's allowlists name Bash
// programs (`type`, `cat`, `find`, `ls`, `echo` read or print different things in PowerShell), so a
// PowerShell call is never read-only and is classified as the stricter of its own (named) reading
// and Bash's reading of its text with no allowlist applied (the PowerShell dialect of the splitter).
const SHELL_COMMAND_TOOLS = new Set(['monitor', 'powershell']);
// How long a Monitor or PowerShell call may run and whether it runs in the background: they are
// part of what is approved (a short-timeout approval is not a long-timeout one).
const SHELL_COMMAND_TOOL_RUN_FIELDS = ['timeout', 'timeout_ms', 'run_in_background'] as const;
// The fields a Monitor or PowerShell call may carry besides its shell text without changing what runs.
const SHELL_COMMAND_TOOL_FIELDS = new Set(['description', ...SHELL_COMMAND_TOOL_RUN_FIELDS]);
// Tools whose `command` names something other than shell text (a slash command, a skill, an editor
// operation), and Workflow, whose `script` is JavaScript that only starts sub-agents.
const NON_SHELL_COMMAND_TOOLS = new Set(['slashcommand', 'skill', 'str_replace_editor', 'str_replace_based_edit_tool', 'workflow']);
// Claude Code built-ins that run a fixed local git command (exact host label): read as Bash running it.
const NATIVE_SHELL_EQUIVALENTS: ReadonlyMap<string, string> = new Map([
  ['EnterWorktree', 'git worktree add'],
  ['ExitWorktree', 'git worktree remove'],
]);
// Claude Code built-ins no released Marrow matcher hooked that never act themselves (exact host
// label): what they lead to (a sub-agent's tools, a scheduled prompt, the agent's next step after a
// fetch, a message or a question) reaches the hook on its own. As for task bookkeeping, words in
// their prompt, message, plan or URL are not performed by the call, so they never make it
// protected; the call is still reported to Marrow (never read-only). Monitor is here only without
// shell text (its WebSocket source). The tools that only report, notify, structure output, render or
// hand text back, and what each one does:
//   Artifact, ArtifactCheck, ArtifactComments, ArtifactData: the host's artifact pane (render a page
//     for the user, check it, comment on it, give it data); no command, no local file.
//   ListAgents: lists the agents SendMessage can reach.
//   PushNotification: a desktop or phone notification with a one-line `message`.
//   ReportFindings: hands a code review's findings to the host UI to render.
//   StructuredOutput: hands the final structured result back to the caller.
//   SubagentHandback: hands a sub-agent's text back to the agent that started it.
//   Workflow: its `script` (JavaScript) only starts sub-agents, whose own tools reach the hook.
// Tools a released matcher already hooked keep their reading (BashOutput, NotebookRead,
// ReadMcpResourceTool, Task*, TodoWrite, ToolSearch); RemoteTrigger and DesignSync act on remote
// services and stay as named.
const NON_ACTING_NATIVE_TOOLS = new Set(['Agent', 'SendMessage', 'WebFetch', 'AskUserQuestion', 'EnterPlanMode', 'ExitPlanMode',
  'SlashCommand', 'CronCreate', 'CronDelete', 'CronList', 'ScheduleWakeup', 'KillShell', 'Monitor',
  'Artifact', 'ArtifactCheck', 'ArtifactComments', 'ArtifactData', 'ListAgents', 'PushNotification', 'ReportFindings',
  'StructuredOutput', 'SubagentHandback', 'Workflow']);
// Claude Code's Skill loads a skill's instructions (exact host label): read as Read.
const READ_EQUIVALENT_NATIVE_TOOLS = new Set(['Skill']);

export type ToolPolicyReading = {
  /** How the call's own name is read: as named (every tool before the built-ins were hooked), as Read, or as a call whose words are not actions. */
  base: 'named' | 'read' | 'non_acting';
  /** Bash calls the call amounts to: its command or script text, or a native tool's fixed git command. */
  shell: BashTwin[];
  /** Read exactly as Bash running `shell` (its own reading ignored); otherwise the stricter of both. */
  exact: boolean;
  /** An exact reading that is a shell tool (Monitor): classified under Bash's own label. */
  bashLabel: boolean;
  /** Set when `shell` is not Bash's text: the dialect its twins are read in (PowerShell: never read-only, no allowlist). */
  dialect?: ShellDialect;
};

type BashTwin = { tool_name: string; tool_input: { command: string }; [SHELL_DIALECT]?: ShellDialect };

function bashTwin(command: string): BashTwin {
  return { tool_name: 'Bash', tool_input: { command } };
}

function powerShellTwin(command: string): BashTwin {
  return { tool_name: 'Bash', tool_input: { command }, [SHELL_DIALECT]: 'powershell' };
}

/** The string `command` and `script` texts of a call that are not blank (both when both are set). */
function shellTexts(event: ToolPolicyEvent): string[] {
  const input = asRecord(event.tool_input);
  if (!input) return [];
  const texts: string[] = [];
  for (const key of ['command', 'script']) {
    const value = input[key];
    if (typeof value === 'string' && value.trim() && !texts.includes(value)) texts.push(value);
  }
  return texts;
}

export function toolPolicyReading(event: ToolPolicyEvent): ToolPolicyReading {
  const named: ToolPolicyReading = { base: 'named', shell: [], exact: false, bashLabel: false };
  const tool = normalizeHookToolName(event.tool_name);
  // Bash and the other shell tools are read as they always were; Marrow's own and MCP calls keep their reading plus any shell text.
  if (!tool || SHELL_TOOLS.has(tool)) return named;
  const label = typeof event.tool_name === 'string' ? event.tool_name : '';
  const texts = NON_SHELL_COMMAND_TOOLS.has(tool) ? [] : shellTexts(event);
  const equivalent = isMcpHookTool(event.tool_name) ? undefined : NATIVE_SHELL_EQUIVALENTS.get(label);
  if (equivalent !== undefined) return { base: 'named', shell: [equivalent, ...texts].map(bashTwin), exact: true, bashLabel: false };
  if (tool === 'monitor' && texts.length && !isMcpHookTool(event.tool_name)) {
    return { base: 'named', shell: texts.map(bashTwin), exact: true, bashLabel: true };
  }
  // PowerShell: the stricter of its named reading and Bash's reading of the text in the PowerShell dialect.
  if (tool === 'powershell' && texts.length && !isMcpHookTool(event.tool_name)) {
    return { base: 'named', shell: texts.map(powerShellTwin), exact: false, bashLabel: false, dialect: 'powershell' };
  }
  const base: ToolPolicyReading['base'] = isMcpHookTool(event.tool_name) ? 'named'
    : READ_EQUIVALENT_NATIVE_TOOLS.has(label) ? 'read'
    : NON_ACTING_NATIVE_TOOLS.has(label) ? 'non_acting'
    : 'named';
  return { base, shell: texts.map(bashTwin), exact: false, bashLabel: false };
}

/** The Read call a Read-equivalent tool is read as (same input). */
export function readEquivalent(event: ToolPolicyEvent): ToolPolicyEvent {
  return { tool_name: 'Read', tool_input: event.tool_input };
}

/**
 * The shell text of a plain Monitor or PowerShell call (one command or script string, no field
 * that changes what runs besides it), else null. Only such a call is keyed as shell text.
 */
export function shellCommandToolText(event: ToolPolicyEvent): string | null {
  if (isMcpHookTool(event.tool_name) || !SHELL_COMMAND_TOOLS.has(normalizeHookToolName(event.tool_name))) return null;
  const input = asRecord(event.tool_input);
  if (!input) return null;
  const texts = Object.keys(input).filter((key) => !SHELL_COMMAND_TOOL_FIELDS.has(key));
  if (texts.length !== 1 || !['command', 'script'].includes(texts[0])) return null;
  const value = input[texts[0]];
  return typeof value === 'string' && value.trim() ? value : null;
}

/**
 * The run options (`timeout`, `timeout_ms`, `run_in_background`) a Monitor or PowerShell call carries, in a
 * fixed order and as sent, or null for any other call or when it carries none. They are part of the key
 * of the call (normalized-action, hook-contract exactHookTarget); `description` is not.
 */
export function shellCommandToolRunOptions(event: ToolPolicyEvent): Record<string, unknown> | null {
  if (isMcpHookTool(event.tool_name) || !SHELL_COMMAND_TOOLS.has(normalizeHookToolName(event.tool_name))) return null;
  const input = asRecord(event.tool_input);
  if (!input) return null;
  const options: Record<string, unknown> = {};
  for (const key of SHELL_COMMAND_TOOL_RUN_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(input, key)) options[key] = input[key];
  }
  return Object.keys(options).length ? options : null;
}

/** A Claude Code built-in keyed by its whole input (a native git equivalent, Skill, or a call whose words are not actions). */
export function isWholeInputNativeTool(event: ToolPolicyEvent): boolean {
  const reading = toolPolicyReading(event);
  if ((reading.exact && !reading.bashLabel) || reading.base !== 'named') return true;
  // A Monitor or PowerShell call is keyed as shell text only when it is a plain one.
  return ((reading.exact && reading.bashLabel) || reading.dialect === 'powershell') && shellCommandToolText(event) === null;
}
