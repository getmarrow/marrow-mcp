type ToolPolicyEvent = {
  tool_name?: string;
  tool_input?: unknown;
};

const READ_ONLY_TOOLS = new Set([
  'read',
  'grep',
  'glob',
  'ls',
  'notebookread',
  'todoread',
  'tasklist',
  'taskget',
  'sessions_list',
  'sessions_history',
  'session_status',
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
  /\b(?:npm|pnpm|yarn)(?:\s+npm)?\b[\s\S]{0,8192}\b(?:publish|unpublish|deprecate|access|owner|team|token|dist-tag|tag\s+(?:add|remove))\b/i,
  /\b(?:cargo\s+(?:publish|yank|owner)|twine\s+upload|gem\s+(?:push|yank|owner)|(?:dotnet\s+nuget|nuget)\s+(?:push|delete))\b/i,
  /\bgit\b[\s\S]{0,8192}\b(?:push|commit|merge|rebase|reset|tag|clean|rm|cherry-pick|revert|branch\s+(?:-[dDmM]|--delete|--move)|remote\s+(?:add|remove|rename|set-url|set-head|prune|update)|checkout\s+-[bB]|switch\s+-[cC])\b/i,
  /\bgh\b[\s\S]{0,8192}\b(?:pr\s+(?:merge|close|reopen|edit|review|comment)|issue\s+(?:create|close|reopen|edit|comment)|release\s+(?:create|delete|edit|upload)|repo\s+(?:archive|delete|edit|rename)|workflow\s+run|secret\s+(?:set|delete)|variable\s+(?:set|delete))\b/i,
  /\bgh\s+api\b[\s\S]{0,8192}(?:(?:--method|-X)(?:=|\s+)(?:POST|PUT|PATCH|DELETE)\b|(?:-f|-F|--field|--raw-field|--input)(?:=|\s+))/i,
  /\b(?:kubectl|oc)\b[\s\S]{0,8192}\b(?:apply|create|delete|edit|patch|replace|rollout|scale|set|drain|cordon|uncordon|taint|exec|cp|run|expose|autoscale|label|annotate|reconcile)\b/i,
  /\b(?:terraform|terragrunt|tofu)\b[\s\S]{0,8192}\b(?:apply|destroy|import|taint|untaint|force-unlock|state\s+(?:mv|rm|push)|workspace\s+(?:new|delete))\b/i,
  /\bpulumi\b[\s\S]{0,8192}\b(?:up|destroy|import|refresh|stack\s+rm|config\s+(?:set|rm))\b/i,
  /\bhelm\b[\s\S]{0,8192}\b(?:install|upgrade|uninstall|rollback|push)\b/i,
  /\b(?:docker|podman)\b[\s\S]{0,8192}\b(?:push|buildx\s+build\b[\s\S]*--push)\b/i,
  /\bwrangler\b[\s\S]{0,8192}\b(?:deploy|delete|rollback|execute|apply|put|bulk|secret|publish)\b/i,
  /\bcurl\b[\s\S]{0,8192}(?:(?:-X\s*|--request(?:=|\s+))(?:POST|PUT|PATCH|DELETE)\b|--data(?:-raw|-binary|-urlencode)?(?:=|\s+)|-[dF](?:\s+|[^A-Za-z])|--form(?:=|\s+)|(?:-T|--upload-file)(?:=|\s+))/i,
  /\b(?:http|xh)\b[\s\S]{0,8192}(?:\b(?:POST|PUT|PATCH|DELETE)\b|(?:--form|--raw|-f)\b|\s[^\s=:@]+(?::=|=|@))/i,
  /\bwget\b[\s\S]{0,8192}(?:--post-data|--post-file|--method(?:=|\s+)(?:POST|PUT|PATCH|DELETE))\b/i,
  /\b(?:psql|mysql|sqlite3|duckdb)\b[\s\S]{0,8192}(?:\b(?:drop|delete|update|insert|alter|truncate|create|grant|revoke)\b|(?:-f|--file|\.read|source)(?:=|\s+)|\s<\s*[^\s])/i,
  /\bredis-cli\b[\s\S]{0,8192}\b(?:set|setex|psetex|mset|del|unlink|getdel|incr|decr|append|expire|persist|rename|move|flushall|flushdb|shutdown|config\s+set|acl\s+setuser|hset|hdel|lpush|rpush|lpop|rpop|sadd|srem|zadd|zrem|xadd|xdel|publish|restore|migrate)\b/i,
  /\baws\b[\s\S]{0,8192}\b(?:create|update|delete|put|attach|detach|associate|disassociate|terminate|stop|start|reboot|modify|restore|rotate|tag|untag|deploy|sync|s3\s+(?:cp|mv|rm)|s3api\s+put-object|ssm\s+(?:put-parameter|delete-parameter|delete-parameters))\b/i,
  /\bgcloud\b[\s\S]{0,8192}\b(?:create|update|delete|deploy|add|remove|set|destroy|disable|restore|storage\s+(?:cp|mv|rm)|pubsub\s+(?:topics|subscriptions)\s+(?:create|delete|update))\b/i,
  /\baz\b[\s\S]{0,8192}\b(?:create|update|delete|set|deploy|start|stop|restart|restore|storage\s+blob\s+(?:upload|delete|copy)|group\s+(?:create|delete|update))\b/i,
  /\brclone\b[\s\S]{0,8192}\b(?:copy|copyto|sync|move|moveto|delete|deletefile|purge|mkdir|rmdir|bisync)\b/i,
  /\b(?:vault|op)\b[\s\S]{0,8192}\b(?:write|put|patch|delete|edit|create|rotate|revoke|destroy|share)\b/i,
  /(?:^|[;&|]\s*|\bsudo\s+|\benv\s+)(?:rm\b|shred\b|truncate\b|find\b[\s\S]{0,8192}\s-delete\b)/i,
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
  return String(value || '').replace(/^mcp__/, '').trim().toLowerCase();
}

export function isOfficialMarrowMcpTool(value: unknown): boolean {
  return /^mcp__marrow__marrow_[a-z0-9_]+$/i.test(String(value || '').trim());
}

export function isProtectedShellMutation(command: string): boolean {
  const bounded = String(command || '').slice(0, 8192);
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
  if (MUTATION_TOOL_VERB.test(tool)) return false;
  if (READ_ONLY_TOOL_VERB.test(tool)) return true;

  const command = hookToolCommand(event).replace(/\s+/g, ' ').trim();
  if (tool === 'bash' && command && !hasCompoundShellSyntax(command) && !hasWriteLikeShellSyntax(command)) {
    if (/^(?:node|npm)\s+(?:-v|--version)$/i.test(command)) return true;
    if (/^git\s+(?:status|diff|show|log|branch|rev-parse|ls-files|ls-remote)(?:\s|$)/i.test(command)) return true;
    const firstToken = command.split(/[\s|;&]+/, 1)[0]?.toLowerCase();
    if (firstToken && READ_ONLY_BASH_COMMANDS.has(firstToken)) return true;
  }

  return !['edit', 'write', 'multiedit'].includes(tool) && pathOnlyInput(event.tool_input);
}
