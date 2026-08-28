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

const READ_ONLY_BASH_COMMANDS = new Set([
  'read', 'grep', 'rg', 'ls', 'cat', 'find', 'tail', 'head', 'wc', 'file',
  'stat', 'which', 'type', 'echo', 'printf', 'pwd', 'date', 'env', 'printenv',
  'whoami', 'uname',
]);

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
  return String(value || '').replace(/^mcp__/, '').replace(/^MCP:/i, '').trim().toLowerCase();
}

export function isOfficialMarrowMcpTool(value: unknown): boolean {
  const tool = String(value || '').trim();
  return /^mcp__marrow__marrow_[a-z0-9_]+$/i.test(tool)
    || /^MCP:(?:marrow:)?marrow_[a-z0-9_]+$/i.test(tool);
}

export function isOfficialMarrowMcpEvent(event: ToolPolicyEvent): boolean {
  if (isOfficialMarrowMcpTool(event.tool_name)) return true;
  const tool = String(event.tool_name || '').trim().toLowerCase();
  if (!['use_mcp_tool', 'mcp', 'mcp_tool'].includes(tool)) return false;
  const input = asRecord(event.tool_input);
  if (!input) return false;
  const server = String(input.serverName ?? input.server_name ?? '').trim().toLowerCase();
  const name = String(input.toolName ?? input.tool_name ?? '').trim();
  return server === 'marrow' && /^marrow_[a-z0-9_]+$/i.test(name);
}

export function isMcpHookTool(value: unknown): boolean {
  return /^(?:mcp__|MCP:)/i.test(String(value || '').trim());
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
  for (const key of ['command', 'description', 'query', 'path', 'file_path', 'url', 'name']) {
    const value = stringValue(input[key]);
    if (value) return value;
  }
  try {
    return JSON.stringify(input).slice(0, 4096);
  } catch {
    return '';
  }
}

function hasWriteLikeShellSyntax(command: string): boolean {
  return /(^|[^>])>(?!>)|>>|\b(?:tee|touch|mkdir|rm|mv|cp|install|uninstall|publish|deploy|release)\b|\bsed\s+-i\b|\bperl\s+-i\b/i.test(command)
    || /\b(?:curl|wget|nc|ncat|netcat|scp|rsync|ssh|ftp|tftp)\b/i.test(command)
    || /\bgit\s+(?:push|merge|commit|rebase|reset|checkout|switch|tag)\b/i.test(command)
    || isProtectedShellMutation(command);
}

function hasCompoundShellSyntax(command: string): boolean {
  return /[|;&`\n\r]|\$\(|\$\{/.test(command);
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
  if (READ_ONLY_TOOLS.has(tool)) return true;
  if (['edit', 'write', 'multiedit', 'search_replace', 'run_terminal_command', 'spawn_subagent'].includes(tool)) return false;
  if (MUTATION_TOOL_VERB.test(tool)) return false;
  if (READ_ONLY_TOOL_VERB.test(tool)) return true;

  const command = hookToolCommand(event).replace(/\s+/g, ' ').trim();
  if ((tool === 'bash' || tool === 'run_terminal_command') && command && !hasCompoundShellSyntax(command) && !hasWriteLikeShellSyntax(command)) {
    if (/^(?:node|npm)\s+(?:-v|--version)$/i.test(command)) return true;
    if (/^git\s+(?:status|diff|show|log|branch|rev-parse|ls-files|ls-remote)(?:\s|$)/i.test(command)) return true;
    const firstToken = command.split(/[\s|;&]+/, 1)[0]?.toLowerCase();
    if (firstToken && READ_ONLY_BASH_COMMANDS.has(firstToken)) return true;
  }

  return !['edit', 'write', 'multiedit', 'search_replace'].includes(tool) && pathOnlyInput(event.tool_input);
}
