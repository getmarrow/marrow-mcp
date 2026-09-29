import { homedir } from 'node:os';
import { posix } from 'node:path';

type ToolPolicyEvent = {
  tool_name?: string;
  tool_input?: unknown;
};

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
const ENV_TEMPLATE_FILE = /(?:^|\.)env\.(?:example|sample|template|dist|defaults?)$/i;
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

export function isOfficialMarrowMcpTool(value: unknown): boolean {
  const tool = String(value || '').trim().replace(/^functions\./i, '');
  return /^mcp__marrow__marrow_[a-z0-9_]+$/i.test(tool)
    || /^MCP:(?:marrow:)?marrow_[a-z0-9_]+$/i.test(tool)
    || /^mcp_marrow_marrow_[a-z0-9_]+$/i.test(tool);
}

export function isOfficialMarrowMcpEvent(event: ToolPolicyEvent): boolean {
  if (isOfficialMarrowMcpTool(event.tool_name)) return true;
  const tool = String(event.tool_name || '').trim().toLowerCase();
  if (!['use_mcp_tool', 'use_tool', 'mcp', 'mcp_tool'].includes(tool)) return false;
  const input = asRecord(event.tool_input);
  if (!input) return false;
  const server = String(input.serverName ?? input.server_name ?? '').trim().toLowerCase();
  const name = String(input.toolName ?? input.tool_name ?? '').trim();
  return server === 'marrow' && /^marrow_[a-z0-9_]+$/i.test(name);
}

export function isMcpHookTool(value: unknown): boolean {
  return /^(?:mcp__|mcp_|MCP:)/i.test(String(value || '').trim());
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
export function parseShellSegments(command: string): ShellSegment[] | null {
  if (command.length > MAX_SHELL_ANALYSIS_BYTES || UNMODELED_SHELL_CHARACTER.test(command)) return null;
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
        if (inner === '\\' && index + 1 < command.length && '$`"\\\n'.includes(command[index + 1])) {
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
    if (char === '\\') {
      if (next === undefined) return null;
      if (next !== '\n') { word += next; inWord = true; }
      index += 2;
      continue;
    }
    // Braces expand or group commands, so the words would not be what runs.
    if (char === '`' || char === '(' || char === ')' || char === '{') return null;
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
  if (/^\/proc\/[^/]+\/environ$/.test(path) || /^\/etc\/g?shadow$/.test(path)) return true;
  // Claude Code local settings can carry agent keys in their env block.
  if (name === 'settings.local.json' && parts[parts.length - 2] === '.claude') return true;
  if (!pathLike) return SECRET_FILE.test(name) && !ENV_TEMPLATE_FILE.test(name);
  if (ENV_TEMPLATE_FILE.test(name)) return false;
  if (SECRET_FILE.test(name)) return true;
  return SECRET_KEYWORD_FILE.test(name) && !SOURCE_OR_DOC_FILE.test(name);
}

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

/** True for a secret file or Marrow's own local control state. */
export function isProtectedWriteTarget(value: string, base = process.cwd()): boolean {
  return pathCandidates(String(value || '')).flatMap(globVariants).some((candidate) => secretPath(candidate, base)
    || GOVERNANCE_CONTROL_FILE.test(normalizedToolPath(candidate, base)));
}

/** True for an environment variable name that conventionally holds a secret. */
export function isSecretVariableName(value: string): boolean {
  return String(value || '').toUpperCase().split('_').some((part) => SECRET_VARIABLE_PART.has(part));
}

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

/** Classifies one simple command: a read-only inspection, a secret access, or anything else. */
export function shellSegmentVerdict(segment: ShellSegment, cwd: string | null = process.cwd()): ShellSegmentVerdict {
  // After a cd Marrow cannot follow, relative paths are unknown, so nothing that follows is read-only.
  const base = cwd ?? process.cwd();
  const secret = (value: string) => isSecretPath(value, base);
  const protectedTarget = (value: string) => isProtectedWriteTarget(value, base);
  const writes = segment.outputs.filter((target) => !['/dev/null', '/dev/stdout', '/dev/stderr'].includes(target));
  if (segment.inputs.some(secret) || writes.some(protectedTarget)) return 'secret';
  if (!segment.words.length) return writes.length || cwd === null ? 'other' : 'read';
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
    if (!NON_CONTENT_BASH_COMMANDS.has(program)) {
      const targets = ['grep', 'egrep', 'fgrep', 'rg', 'jq'].includes(program) ? contentReadTargets(program, args) : args.filter((arg) => !arg.startsWith('-') || arg.includes('='));
      if (targets.some(secret)) return 'secret';
    }
    return writes.length || cwd === null ? 'other' : 'read';
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

function shellAnalysis(command: string): { segments: ShellSegment[]; verdicts: ShellSegmentVerdict[] } | null {
  const segments = parseShellSegments(command);
  if (!segments) return null;
  let cwd: string | null = process.cwd();
  const verdicts = segments.map((segment) => {
    const verdict = shellSegmentVerdict(segment, cwd);
    cwd = nextWorkingDirectory(segment, cwd);
    return verdict;
  });
  return { segments, verdicts };
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
 */
export function isSecretMaterialAccess(event: ToolPolicyEvent): boolean {
  const tool = normalizeHookToolName(event.tool_name);
  if (CONTENT_READ_TOOLS.has(tool)) return toolTargetPaths(event).some((path) => isSecretPath(path));
  if (FILE_EDIT_TOOLS.has(tool)) return toolTargetPaths(event).some((path) => isProtectedWriteTarget(path));
  if (!SHELL_TOOLS.has(tool)) return false;
  const command = shellCommandText(event);
  const analysis = shellAnalysis(command);
  if (analysis) return analysis.verdicts.includes('secret');
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
    const analysis = shellAnalysis(shellCommandText(event));
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

export function isReadOnlyToolEvent(event: ToolPolicyEvent): boolean {
  const tool = normalizeHookToolName(event.tool_name);
  if (!tool) return false;
  if (LOCAL_TASK_TOOLS.has(tool)) return true;
  if (READ_ONLY_TOOLS.has(tool)) return !isSecretMaterialAccess(event);
  if (['edit', 'write', 'multiedit', 'search_replace', 'run_terminal_command', 'spawn_subagent'].includes(tool)) return false;
  if (MUTATION_TOOL_VERB.test(tool)) return false;
  if (READ_ONLY_TOOL_VERB.test(tool)) return true;

  const command = hookToolCommand(event);
  if (tool === 'bash' && command) {
    // A compound command is read-only only when every simple command in it is.
    const analysis = shellAnalysis(shellCommandText(event));
    return Boolean(analysis?.segments.length && analysis.verdicts.every((verdict) => verdict === 'read'));
  }

  return !['edit', 'write', 'multiedit', 'search_replace'].includes(tool)
    && pathOnlyInput(event.tool_input)
    && !toolTargetPaths(event).some((path) => isSecretPath(path));
}
