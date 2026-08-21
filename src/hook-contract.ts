import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

export const MCP_ADAPTER_VERSION = '3.9.71';
export const NATIVE_HOOK_MATCHER = 'Bash|Edit|Write|MultiEdit|mcp__(?!marrow__marrow_).*';
export const GROK_NATIVE_HOOK_MATCHER = 'run_terminal_command|search_replace|write|spawn_subagent|use_tool|workflow|image_gen|image_edit|image_to_video|reference_to_video';
export const MCP_PACKAGE_SPEC = `@getmarrow/mcp@${MCP_ADAPTER_VERSION}`;
export const CONTEXT_HOOK_COMMAND = `npx -y --package=${MCP_PACKAGE_SPEC} marrow-mcp context-hook`;
export const PRE_ACTION_HOOK_COMMAND = `npx -y --package=${MCP_PACKAGE_SPEC} marrow-mcp pre-action-hook`;
export const ACTION_RESULT_HOOK_COMMAND = `npx -y --package=${MCP_PACKAGE_SPEC} marrow-mcp hook`;
export const SESSION_END_HOOK_COMMAND = `npx -y --package=${MCP_PACKAGE_SPEC} marrow-mcp session-hook`;
export const NATIVE_EXPECTED_HOOKS = ['prompt', 'pre_action', 'action_result', 'session_end'] as const;

const HOOK_CAMEL_TO_SNAKE: Record<string, string> = {
  hookEventName: 'hook_event_name',
  sessionId: 'session_id',
  toolName: 'tool_name',
  toolInput: 'tool_input',
  toolResponse: 'tool_response',
  toolResult: 'tool_result',
  toolUseId: 'tool_use_id',
  transcriptPath: 'transcript_path',
};

export function normalizeHookEventPayload(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const source = value as Record<string, unknown>;
  const normalized: Record<string, unknown> = { ...source };
  for (const [camel, snake] of Object.entries(HOOK_CAMEL_TO_SNAKE)) {
    if (normalized[snake] == null && normalized[camel] != null) normalized[snake] = normalized[camel];
  }
  return normalized;
}

type HookSettings = Record<string, unknown>;

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

export function findHookSettingsPath(startDir = process.cwd()): string {
  let dir = startDir;
  let fallback: string | null = null;
  for (let depth = 0; depth < 8; depth += 1) {
    const candidate = join(dir, '.claude', 'settings.json');
    if (existsSync(candidate) || existsSync(join(dir, '.claude'))) return candidate;
    if (!fallback && existsSync(join(dir, '.git'))) fallback = candidate;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return fallback || join(startDir, '.claude', 'settings.json');
}

export function readHookSettings(startDir = process.cwd()): HookSettings {
  const path = findHookSettingsPath(startDir);
  if (!existsSync(path)) return {};
  try {
    return asRecord(JSON.parse(readFileSync(path, 'utf8'))) || {};
  } catch {
    return {};
  }
}

export function readHookSettingsForInstall(startDir = process.cwd()): HookSettings {
  const path = findHookSettingsPath(startDir);
  if (!existsSync(path)) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    const detail = error instanceof Error ? error.message : 'invalid JSON';
    throw new Error(`Cannot update Claude hook settings at ${path}: ${detail}`);
  }
  const settings = asRecord(parsed);
  if (!settings) {
    throw new Error(`Cannot update Claude hook settings at ${path}: root must be a JSON object`);
  }
  return settings;
}

export type MarrowHookSubcommand = 'context-hook' | 'pre-action-hook' | 'hook' | 'session-hook';

function marrowHookSubcommand(command: unknown): MarrowHookSubcommand | null {
  if (typeof command !== 'string') return null;
  const match = command.trim().match(
    /^npx\s+(?:-y\s+)?(?:--package=@getmarrow\/mcp(?:@[^\s]+)?\s+marrow-mcp|@getmarrow\/mcp(?:@[^\s]+)?)\s+(context-hook|pre-action-hook|hook|session-hook)$/,
  );
  return match?.[1] as MarrowHookSubcommand | undefined || null;
}

export function reconcileMarrowCommandHook(
  settings: HookSettings,
  eventName: string,
  subcommand: MarrowHookSubcommand,
  command: string,
  matcher?: string,
): { entries: unknown[]; changed: boolean } {
  const hooks = asRecord(settings.hooks);
  const original = Array.isArray(hooks?.[eventName]) ? hooks[eventName] as unknown[] : [];
  let preferredHandler: Record<string, unknown> | null = null;
  const retained: unknown[] = [];

  for (const entry of original) {
    const record = asRecord(entry);
    if (!record || !Array.isArray(record.hooks)) {
      retained.push(entry);
      continue;
    }
    const remaining: unknown[] = [];
    for (const hook of record.hooks) {
      const handler = asRecord(hook);
      const detected = marrowHookSubcommand(handler?.command);
      if (handler?.type === 'command' && detected) {
        const exactMatcher = matcher === undefined
          ? record.matcher === undefined
          : record.matcher === matcher;
        if (detected === subcommand && (!preferredHandler || (handler.command === command && exactMatcher))) {
          preferredHandler = handler;
        }
        continue;
      }
      remaining.push(hook);
    }
    if (remaining.length > 0) retained.push({ ...record, hooks: remaining });
  }

  const handler = { ...(preferredHandler || {}), type: 'command', command };
  const canonicalEntry: Record<string, unknown> = { hooks: [handler] };
  if (matcher !== undefined) canonicalEntry.matcher = matcher;
  retained.push(canonicalEntry);

  return {
    entries: retained,
    changed: JSON.stringify(original) !== JSON.stringify(retained),
  };
}

function marrowHookDescriptors(
  settings: HookSettings,
  eventName: string,
  subcommand?: MarrowHookSubcommand,
): Array<{ matcher: string | null; command: string; timeout: number | null }> {
  const hooks = asRecord(settings.hooks);
  const entries = hooks?.[eventName];
  if (!Array.isArray(entries)) return [];
  return entries.flatMap((entry) => {
    const record = asRecord(entry);
    if (!record || !Array.isArray(record.hooks)) return [];
    return record.hooks.flatMap((hook) => {
      const handler = asRecord(hook);
      const detected = marrowHookSubcommand(handler?.command);
      if (handler?.type !== 'command' || !detected || (subcommand && detected !== subcommand)) return [];
      return [{
        matcher: typeof record.matcher === 'string' ? record.matcher : null,
        command: String(handler.command).trim(),
        timeout: typeof handler.timeout === 'number' && Number.isFinite(handler.timeout)
          ? handler.timeout
          : null,
      }];
    });
  });
}

export function hasExactCommandHook(
  settings: HookSettings,
  eventName: string,
  command: string,
  matcher?: string,
): boolean {
  const hooks = asRecord(settings.hooks);
  const entries = hooks?.[eventName];
  if (!Array.isArray(entries)) return false;
  return entries.some((entry) => {
    const record = asRecord(entry);
    if (!record || (matcher !== undefined && record.matcher !== matcher) || !Array.isArray(record.hooks)) return false;
    return record.hooks.some((hook) => {
      const handler = asRecord(hook);
      return handler?.type === 'command'
        && typeof handler.command === 'string'
        && handler.command.trim() === command;
    });
  });
}

function exactHookDescriptors(
  settings: HookSettings,
  eventName: string,
  command: string,
  matcher?: string,
): Array<{ matcher: string | null; command: string; timeout: number | null }> {
  const hooks = asRecord(settings.hooks);
  const entries = hooks?.[eventName];
  if (!Array.isArray(entries)) return [];
  return entries.flatMap((entry) => {
    const record = asRecord(entry);
    if (!record || (matcher !== undefined && record.matcher !== matcher) || !Array.isArray(record.hooks)) return [];
    return record.hooks.flatMap((hook) => {
      const handler = asRecord(hook);
      if (handler?.type !== 'command' || typeof handler.command !== 'string' || handler.command.trim() !== command) return [];
      return [{
        matcher: typeof record.matcher === 'string' ? record.matcher : null,
        command,
        timeout: typeof handler.timeout === 'number' && Number.isFinite(handler.timeout)
          ? handler.timeout
          : null,
      }];
    });
  });
}

export function nativeHookConfigurationFingerprint(startDir = process.cwd()): string {
  const settings = readHookSettings(startDir);
  const contract = {
    schema: 'marrow-claude-native-hooks.v3',
    adapter_version: MCP_ADAPTER_VERSION,
    expected_hooks: NATIVE_EXPECTED_HOOKS,
    configured: {
      prompt: hasExactCommandHook(settings, 'UserPromptSubmit', CONTEXT_HOOK_COMMAND),
      pre_action: hasExactCommandHook(settings, 'PreToolUse', PRE_ACTION_HOOK_COMMAND, NATIVE_HOOK_MATCHER),
      action_result_success: hasExactCommandHook(settings, 'PostToolUse', ACTION_RESULT_HOOK_COMMAND, NATIVE_HOOK_MATCHER),
      action_result_failure: hasExactCommandHook(settings, 'PostToolUseFailure', ACTION_RESULT_HOOK_COMMAND, NATIVE_HOOK_MATCHER),
      session_end: hasExactCommandHook(settings, 'Stop', SESSION_END_HOOK_COMMAND),
    },
    descriptors: {
      prompt: exactHookDescriptors(settings, 'UserPromptSubmit', CONTEXT_HOOK_COMMAND),
      pre_action: exactHookDescriptors(settings, 'PreToolUse', PRE_ACTION_HOOK_COMMAND, NATIVE_HOOK_MATCHER),
      action_result_success: exactHookDescriptors(settings, 'PostToolUse', ACTION_RESULT_HOOK_COMMAND, NATIVE_HOOK_MATCHER),
      action_result_failure: exactHookDescriptors(settings, 'PostToolUseFailure', ACTION_RESULT_HOOK_COMMAND, NATIVE_HOOK_MATCHER),
      session_end: exactHookDescriptors(settings, 'Stop', SESSION_END_HOOK_COMMAND),
    },
    active_marrow_handlers: {
      prompt: marrowHookDescriptors(settings, 'UserPromptSubmit'),
      pre_action: marrowHookDescriptors(settings, 'PreToolUse'),
      action_result_success: marrowHookDescriptors(settings, 'PostToolUse'),
      action_result_failure: marrowHookDescriptors(settings, 'PostToolUseFailure'),
      session_end: marrowHookDescriptors(settings, 'Stop'),
    },
  };
  return createHash('sha256').update(JSON.stringify(contract)).digest('hex');
}

export function nativeHookEvidence(
  observedHook: typeof NATIVE_EXPECTED_HOOKS[number],
  startDir = process.cwd(),
): {
  adapter_version: string;
  capability_level: 'native_hooks';
  config_fingerprint: string;
  expected_hooks: string[];
  observed_hook: typeof observedHook;
} {
  return {
    adapter_version: MCP_ADAPTER_VERSION,
    capability_level: 'native_hooks',
    config_fingerprint: nativeHookConfigurationFingerprint(startDir),
    expected_hooks: [...NATIVE_EXPECTED_HOOKS],
    observed_hook: observedHook,
  };
}

function stableHash(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex').slice(0, 32);
}

export function stableToolCorrelation(event: {
  session_id?: string;
  tool_use_id?: string;
  tool_name?: string;
  tool_input?: unknown;
}): string {
  return stableHash([
    event.session_id || '',
    event.tool_use_id || '',
    event.tool_name || 'tool',
    event.tool_use_id ? null : event.tool_input ?? null,
  ]);
}

export function stablePromptCorrelation(event: {
  session_id?: string;
  prompt?: string;
}): string {
  return stableHash([event.session_id || '', event.prompt || '']);
}

export function stableSessionWorkflowId(sessionId?: string, fallback?: unknown): string {
  return `session-${stableHash([sessionId || '', sessionId ? null : fallback ?? null])}`;
}

export function grokHookSettingsPath(home = process.env.HOME || homedir()): string {
  return join(home, '.grok', 'hooks', 'marrow.json');
}

export function installGrokNativeHooks(home = process.env.HOME || homedir()): { settingsPath: string; installed: boolean } {
  const settingsPath = grokHookSettingsPath(home);
  const command = (subcommand: MarrowHookSubcommand) => (
    subcommand === 'context-hook' ? CONTEXT_HOOK_COMMAND
      : subcommand === 'pre-action-hook' ? PRE_ACTION_HOOK_COMMAND
      : subcommand === 'session-hook' ? SESSION_END_HOOK_COMMAND
      : ACTION_RESULT_HOOK_COMMAND
  );
  const handler = (subcommand: MarrowHookSubcommand) => ({
    type: 'command',
    command: command(subcommand),
    timeout: 15,
  });
  const next = {
    hooks: {
      UserPromptSubmit: [{ hooks: [handler('context-hook')] }],
      PreToolUse: [{ matcher: GROK_NATIVE_HOOK_MATCHER, hooks: [handler('pre-action-hook')] }],
      PostToolUse: [{ matcher: GROK_NATIVE_HOOK_MATCHER, hooks: [handler('hook')] }],
      PostToolUseFailure: [{ matcher: GROK_NATIVE_HOOK_MATCHER, hooks: [handler('hook')] }],
      Stop: [{ hooks: [handler('session-hook')] }],
      SessionEnd: [{ hooks: [handler('session-hook')] }],
    },
  };
  let previous = '';
  if (existsSync(settingsPath)) {
    try { previous = readFileSync(settingsPath, 'utf8'); } catch { previous = ''; }
  }
  const serialized = `${JSON.stringify(next, null, 2)}\n`;
  mkdirSync(dirname(settingsPath), { recursive: true, mode: 0o700 });
  writeFileSync(settingsPath, serialized, { mode: 0o600 });
  return { settingsPath, installed: previous !== serialized };
}
