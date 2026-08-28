import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { resolveMarrowEnv, type ResolvedMarrowEnv } from './env';

export const MCP_ADAPTER_VERSION = '3.9.76';
export const NATIVE_HOOK_MATCHER = 'Bash|Edit|Write|MultiEdit|mcp__(?!marrow__marrow_).*';
export const GROK_NATIVE_HOOK_MATCHER = 'run_terminal_command|search_replace|write|spawn_subagent|use_tool|workflow|image_gen|image_edit|image_to_video|reference_to_video';
export const MCP_PACKAGE_SPEC = `@getmarrow/mcp@${MCP_ADAPTER_VERSION}`;
const hookCommand = (entrypoint: string) => `npx -y --package=${MCP_PACKAGE_SPEC} marrow-mcp ${entrypoint}`;
export const CONTEXT_HOOK_COMMAND = hookCommand('claude-context-hook');
export const PRE_ACTION_HOOK_COMMAND = hookCommand('claude-pre-action-hook');
export const ACTION_RESULT_HOOK_COMMAND = hookCommand('claude-hook');
export const SESSION_END_HOOK_COMMAND = hookCommand('claude-session-hook');
export const GROK_CONTEXT_HOOK_COMMAND = hookCommand('grok-context-hook');
export const GROK_PRE_ACTION_HOOK_COMMAND = hookCommand('grok-pre-action-hook');
export const GROK_ACTION_RESULT_HOOK_COMMAND = hookCommand('grok-hook');
export const GROK_SESSION_END_HOOK_COMMAND = hookCommand('grok-session-hook');
export const GROK_FIXED_DENIAL = 'Marrow blocked this protected action.';
export const GROK_LAUNCH_FAILURE = 'Marrow governance adapter was unavailable; this action is blocked.';
const GROK_PRE_ACTION_GUARD_SOURCE = [
  'const {spawn}=require("node:child_process");',
  `const valid=new Set([${JSON.stringify('{"decision":"allow"}')},${JSON.stringify(`{"decision":"deny","reason":"${GROK_FIXED_DENIAL}"}`)}]);`,
  'let child=null,timer=null,done=false,input=[],inputBytes=0,output="",outputBytes=0;',
  `const fail=()=>{if(done)return;done=true;if(timer)clearTimeout(timer);if(child&&!child.killed)child.kill("SIGKILL");process.stderr.write(${JSON.stringify(`${GROK_LAUNCH_FAILURE}\n`)});process.exitCode=2;process.stdin.destroy();};`,
  'process.stdin.on("error",fail);',
  'process.stdin.on("data",chunk=>{const value=Buffer.from(chunk);inputBytes+=value.length;if(inputBytes>65536){fail();return;}input.push(value);});',
  'process.stdin.on("end",()=>{if(done)return;try{',
  `child=spawn(process.platform==="win32"?"npx.cmd":"npx",${JSON.stringify(['-y', `--package=${MCP_PACKAGE_SPEC}`, 'marrow-mcp', 'grok-pre-action-hook'])},{stdio:["pipe","pipe","ignore"]});`,
  'timer=setTimeout(fail,5000);',
  'child.stdout.on("data",chunk=>{if(done)return;outputBytes+=chunk.length;if(outputBytes>512){fail();return;}output+=chunk.toString("utf8");});',
  'child.on("error",fail);child.stdin.on("error",fail);',
  'child.on("close",code=>{if(done)return;if(code!==0||!valid.has(output)){fail();return;}done=true;if(timer)clearTimeout(timer);process.stdout.write(output);});',
  'child.stdin.end(Buffer.concat(input));}catch{fail();}});',
].join('');
export const GROK_PRE_ACTION_GUARD_COMMAND = `node -e '${GROK_PRE_ACTION_GUARD_SOURCE}'`;
export const CURSOR_PRE_ACTION_HOOK_COMMAND = hookCommand('cursor-pre-action-hook');
export const CURSOR_ACTION_RESULT_HOOK_COMMAND = hookCommand('cursor-hook');
export const CURSOR_SESSION_END_HOOK_COMMAND = hookCommand('cursor-session-hook');
export const CLINE_PRE_ACTION_HOOK_COMMAND = hookCommand('cline-pre-action-hook');
export const CLINE_ACTION_RESULT_HOOK_COMMAND = hookCommand('cline-hook');
export const CLINE_SESSION_END_HOOK_COMMAND = hookCommand('cline-session-hook');
export const WINDSURF_PRE_ACTION_HOOK_COMMAND = hookCommand('windsurf-pre-action-hook');
export const WINDSURF_ACTION_RESULT_HOOK_COMMAND = hookCommand('windsurf-hook');
export const WINDSURF_SESSION_END_HOOK_COMMAND = hookCommand('windsurf-session-hook');
export const GEMINI_PRE_ACTION_HOOK_COMMAND = hookCommand('gemini-pre-action-hook');
export const GEMINI_ACTION_RESULT_HOOK_COMMAND = hookCommand('gemini-hook');
export const GEMINI_SESSION_END_HOOK_COMMAND = hookCommand('gemini-session-hook');
const LOCAL_CONFIGURED_HOOK_STAGES = ['prompt', 'pre_action', 'action_result', 'session_end'] as const;

export type NativeHookHarness = 'claude-code' | 'cline' | 'codex' | 'cursor' | 'gemini' | 'grok' | 'windsurf' | 'mcp-client';

export interface NativeHookIdentity {
  harness: NativeHookHarness;
  identity_source: 'public_cli_entrypoint' | 'generic_fallback';
  client_self_reported: true;
  agent_id?: string;
  environment: ResolvedMarrowEnv;
}

const RECOGNIZED_NATIVE_ENTRYPOINTS: Record<string, Exclude<NativeHookHarness, 'mcp-client'>> = {
  'claude-context-hook': 'claude-code',
  'claude-pre-action-hook': 'claude-code',
  'claude-hook': 'claude-code',
  'claude-session-hook': 'claude-code',
  'codex-context-hook': 'codex',
  'codex-pre-action-hook': 'codex',
  'codex-hook': 'codex',
  'codex-session-hook': 'codex',
  'grok-context-hook': 'grok',
  'grok-pre-action-hook': 'grok',
  'grok-hook': 'grok',
  'grok-session-hook': 'grok',
  'cursor-pre-action-hook': 'cursor',
  'cursor-hook': 'cursor',
  'cursor-session-hook': 'cursor',
  'cline-pre-action-hook': 'cline',
  'cline-hook': 'cline',
  'cline-session-hook': 'cline',
  'windsurf-pre-action-hook': 'windsurf',
  'windsurf-hook': 'windsurf',
  'windsurf-session-hook': 'windsurf',
  'gemini-pre-action-hook': 'gemini',
  'gemini-hook': 'gemini',
  'gemini-session-hook': 'gemini',
};

/**
 * Label client-reported hook activity from the public CLI entrypoint. The
 * entrypoint is not host provenance and cannot certify coverage. Hook JSON is
 * deliberately not an identity input, and the authenticated service remains
 * authoritative for the credential-bound agent identity.
 */
export function resolveNativeHookIdentity(
  entrypoint: unknown,
  options: Parameters<typeof resolveMarrowEnv>[0] = {},
): NativeHookIdentity {
  const recognizedHarness = RECOGNIZED_NATIVE_ENTRYPOINTS[String(entrypoint || '').trim()] as Exclude<NativeHookHarness, 'mcp-client'> | undefined;
  const harness: NativeHookHarness = recognizedHarness || 'mcp-client';
  const environment = resolveMarrowEnv({ ...options, trustedOnly: true });
  const candidateAgentId = String(environment.agentId || '').trim();
  const agentId = /^[A-Za-z0-9._:-]{1,128}$/.test(candidateAgentId) ? candidateAgentId : undefined;
  return {
    harness,
    identity_source: recognizedHarness ? 'public_cli_entrypoint' : 'generic_fallback',
    client_self_reported: true,
    ...(agentId ? { agent_id: agentId } : {}),
    environment: { ...environment, agentId },
  };
}

export function clientReportedHookLifecycleIdentity(
  identity: NativeHookIdentity,
): Pick<import('./lifecycle-spool').LifecycleEvent, 'harness' | 'agent_id' | 'source'> {
  return {
    harness: identity.harness,
    ...(identity.agent_id ? { agent_id: identity.agent_id } : {}),
    source: 'client_self_reported',
  };
}

const HOOK_CAMEL_TO_SNAKE: Record<string, string> = {
  hookEventName: 'hook_event_name',
  sessionId: 'session_id',
  toolName: 'tool_name',
  toolInput: 'tool_input',
  toolResponse: 'tool_response',
  toolResult: 'tool_result',
  toolOutput: 'tool_output',
  toolUseId: 'tool_use_id',
  conversationId: 'conversation_id',
  generationId: 'generation_id',
  errorMessage: 'error_message',
  failureType: 'failure_type',
  durationMs: 'duration_ms',
  eventName: 'hook_event_name',
  transcriptPath: 'transcript_path',
  taskId: 'task_id',
  hookName: 'hook_event_name',
};

const CURSOR_EVENT_NAMES: Record<string, string> = {
  preToolUse: 'PreToolUse',
  postToolUse: 'PostToolUse',
  postToolUseFailure: 'PostToolUseFailure',
  stop: 'Stop',
};

function boundedCorrelationId(value: unknown): string | undefined {
  const candidate = typeof value === 'string' ? value.trim().slice(0, 128) : '';
  return candidate && /^[A-Za-z0-9._:-]+$/.test(candidate) ? candidate : undefined;
}

function boundedWindsurfName(value: unknown): string | undefined {
  const candidate = typeof value === 'string' ? value.trim().slice(0, 128) : '';
  return candidate && /^[A-Za-z0-9._:-]+$/.test(candidate) ? candidate : undefined;
}

function normalizeWindsurfHookEvent(source: Record<string, unknown>): Record<string, unknown> {
  const action = typeof source.agent_action_name === 'string' ? source.agent_action_name.trim() : '';
  const supported = new Set([
    'pre_write_code', 'pre_run_command', 'pre_mcp_tool_use',
    'post_write_code', 'post_run_command', 'post_mcp_tool_use',
    'post_cascade_response',
  ]);
  if (!supported.has(action)) return {};
  const info = source.tool_info && typeof source.tool_info === 'object' && !Array.isArray(source.tool_info)
    ? source.tool_info as Record<string, unknown>
    : {};
  const normalized: Record<string, unknown> = { hook_event_name: action };
  const trajectoryId = boundedCorrelationId(source.trajectory_id);
  const executionId = boundedCorrelationId(source.execution_id);
  if (trajectoryId) normalized.session_id = trajectoryId;
  if (executionId) normalized.tool_use_id = executionId;
  if (action.endsWith('_run_command')) {
    normalized.tool_name = 'Bash';
    const command = typeof info.command_line === 'string' ? info.command_line.slice(0, 8192) : '';
    normalized.tool_input = { command };
  } else if (action.endsWith('_write_code')) {
    normalized.tool_name = 'Write';
    normalized.tool_input = {};
  } else if (action.endsWith('_mcp_tool_use')) {
    const server = boundedWindsurfName(info.mcp_server_name) || 'unknown';
    const tool = boundedWindsurfName(info.mcp_tool_name) || 'unknown';
    normalized.tool_name = server.toLowerCase() === 'marrow' && /^marrow_[a-z0-9_]+$/i.test(tool)
      ? `mcp__marrow__${tool}`
      : `MCP:${server}:${tool}`;
    normalized.tool_input = {};
  }
  if (action.startsWith('post_') && action !== 'post_cascade_response') normalized.success = true;
  return normalized;
}

function normalizeGeminiHookEvent(source: Record<string, unknown>): Record<string, unknown> {
  const hookEventName = typeof source.hook_event_name === 'string' ? source.hook_event_name.trim() : '';
  if (!['BeforeTool', 'AfterTool', 'AfterAgent'].includes(hookEventName)) return {};
  const normalized: Record<string, unknown> = { hook_event_name: hookEventName };
  const sessionId = boundedCorrelationId(source.session_id);
  if (sessionId) normalized.session_id = sessionId;
  if (hookEventName === 'AfterAgent') return normalized;
  const toolName = typeof source.tool_name === 'string' ? source.tool_name.trim().slice(0, 256) : '';
  if (toolName && /^[A-Za-z0-9._:-]+$/.test(toolName)) {
    normalized.tool_name = toolName === 'run_shell_command' ? 'Bash'
      : toolName === 'write_file' ? 'Write'
      : ['replace', 'edit_file'].includes(toolName) ? 'Edit'
      : toolName;
  }
  if (hookEventName === 'BeforeTool') {
    normalized.tool_input = source.tool_input;
    return normalized;
  }
  normalized.tool_input = {};
  const response = source.tool_response && typeof source.tool_response === 'object' && !Array.isArray(source.tool_response)
    ? source.tool_response as Record<string, unknown>
    : null;
  normalized.success = source.success === false
    || response?.success === false
    || response?.error != null
    || /^(?:failed|error|blocked)$/i.test(String(response?.status || ''))
    ? false
    : true;
  const duration = typeof source.duration_ms === 'number' && Number.isFinite(source.duration_ms)
    ? Math.max(0, Math.min(300_000, Math.round(source.duration_ms)))
    : undefined;
  if (duration !== undefined) normalized.duration_ms = duration;
  return normalized;
}

function normalizeGrokHookEvent(source: Record<string, unknown>): Record<string, unknown> {
  const hookEventName = typeof source.hookEventName === 'string' ? source.hookEventName.trim() : '';
  if (!['PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'Stop'].includes(hookEventName)) return {};
  const normalized: Record<string, unknown> = { hook_event_name: hookEventName };
  const sessionId = boundedCorrelationId(source.sessionId);
  const toolUseId = boundedCorrelationId(source.toolUseId);
  if (sessionId) normalized.session_id = sessionId;
  if (toolUseId) normalized.tool_use_id = toolUseId;
  if (hookEventName === 'Stop') return normalized;
  const toolName = typeof source.toolName === 'string' ? source.toolName.trim().slice(0, 256) : '';
  const toolInput = source.toolInput && typeof source.toolInput === 'object' && !Array.isArray(source.toolInput)
    ? source.toolInput as Record<string, unknown>
    : null;
  const server = boundedWindsurfName(toolInput?.serverName ?? toolInput?.server_name);
  const nestedTool = boundedWindsurfName(toolInput?.toolName ?? toolInput?.tool_name);
  const boundedToolName = toolName === 'use_tool' && server && nestedTool
    ? server.toLowerCase() === 'marrow' && /^marrow_[a-z0-9_]+$/i.test(nestedTool)
      ? `mcp__marrow__${nestedTool}`
      : `MCP:${server}:${nestedTool}`
    : toolName;
  if (boundedToolName && /^[A-Za-z0-9._:-]+$/.test(boundedToolName)) normalized.tool_name = boundedToolName;
  if (hookEventName === 'PreToolUse') {
    normalized.tool_input = source.toolInput;
    return normalized;
  }
  normalized.tool_input = {};
  const result = source.toolResult && typeof source.toolResult === 'object' && !Array.isArray(source.toolResult)
    ? source.toolResult as Record<string, unknown>
    : null;
  normalized.success = hookEventName === 'PostToolUseFailure'
    || source.success === false
    || result?.success === false
    || result?.error != null
    || result?.isError === true
    || result?.is_error === true
    || typeof result?.exitCode === 'number' && result.exitCode !== 0
    || typeof result?.exit_code === 'number' && result.exit_code !== 0
    || /^(?:failed|error|blocked)$/i.test(String(result?.status || ''))
    ? false
    : true;
  const duration = typeof source.durationMs === 'number' && Number.isFinite(source.durationMs)
    ? Math.max(0, Math.min(300_000, Math.round(source.durationMs)))
    : undefined;
  if (duration !== undefined) normalized.duration_ms = duration;
  return normalized;
}

export function normalizeHookEventPayload(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const source = value as Record<string, unknown>;
  if (typeof source.agent_action_name === 'string') return normalizeWindsurfHookEvent(source);
  if (['PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'Stop'].includes(String(source.hookEventName || ''))) {
    return normalizeGrokHookEvent(source);
  }
  if (['BeforeTool', 'AfterTool', 'AfterAgent'].includes(String(source.hook_event_name || ''))) {
    return normalizeGeminiHookEvent(source);
  }
  const normalized: Record<string, unknown> = { ...source };
  for (const [camel, snake] of Object.entries(HOOK_CAMEL_TO_SNAKE)) {
    if (normalized[snake] == null && normalized[camel] != null) normalized[snake] = normalized[camel];
  }
  const clinePre = source.preToolUse && typeof source.preToolUse === 'object' && !Array.isArray(source.preToolUse)
    ? source.preToolUse as Record<string, unknown>
    : null;
  const clinePost = source.postToolUse && typeof source.postToolUse === 'object' && !Array.isArray(source.postToolUse)
    ? source.postToolUse as Record<string, unknown>
    : null;
  const clineTool = clinePre || clinePost;
  if (clineTool) {
    if (normalized.tool_name == null) normalized.tool_name = clineTool.toolName ?? clineTool.tool_name;
    if (normalized.tool_input == null) normalized.tool_input = clineTool.parameters;
    if (normalized.tool_result == null) normalized.tool_result = clineTool.result;
    if (normalized.success == null) normalized.success = clineTool.success;
    if (normalized.duration_ms == null) normalized.duration_ms = clineTool.durationMs ?? clineTool.duration_ms;
    if (normalized.hook_event_name == null) normalized.hook_event_name = clinePre ? 'PreToolUse' : 'PostToolUse';
  }
  if (normalized.hook_event_name == null && typeof normalized.event === 'string') {
    normalized.hook_event_name = normalized.event;
  }
  if (typeof normalized.hook_event_name === 'string') {
    normalized.hook_event_name = CURSOR_EVENT_NAMES[normalized.hook_event_name] || normalized.hook_event_name;
  }
  for (const field of ['session_id', 'tool_use_id', 'conversation_id', 'generation_id', 'task_id']) {
    const bounded = boundedCorrelationId(normalized[field]);
    if (bounded) normalized[field] = bounded;
    else delete normalized[field];
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
    /^npx\s+(?:-y\s+)?(?:--package=@getmarrow\/mcp(?:@[^\s]+)?\s+marrow-mcp|@getmarrow\/mcp(?:@[^\s]+)?)\s+(?:(?:claude|cline|codex|cursor|gemini|grok|windsurf)-)?(context-hook|pre-action-hook|hook|session-hook)$/,
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

export function localHookConfigurationFingerprint(startDir = process.cwd()): string {
  const settings = readHookSettings(startDir);
  const contract = {
    schema: 'marrow-claude-native-hooks.v3',
    adapter_version: MCP_ADAPTER_VERSION,
    configured_stages: LOCAL_CONFIGURED_HOOK_STAGES,
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
  for (const component of [join(home, '.grok'), join(home, '.grok', 'hooks'), settingsPath]) {
    if (existsSync(component) && lstatSync(component).isSymbolicLink()) {
      throw new Error(`Cannot update Grok hook settings at ${settingsPath}: symbolic path components are not allowed`);
    }
  }
  let previous = '';
  let settings: HookSettings = {};
  if (existsSync(settingsPath)) {
    previous = readFileSync(settingsPath, 'utf8');
    let parsed: unknown;
    try {
      parsed = JSON.parse(previous);
    } catch (error) {
      const detail = error instanceof Error ? error.message : 'invalid JSON';
      throw new Error(`Cannot update Grok hook settings at ${settingsPath}: ${detail}`);
    }
    const record = asRecord(parsed);
    if (!record) throw new Error(`Cannot update Grok hook settings at ${settingsPath}: root must be a JSON object`);
    settings = record;
  }
  const hooks = asRecord(settings.hooks) || {};
  const grokSubcommand = (command: unknown): MarrowHookSubcommand | null => {
    const direct = marrowHookSubcommand(command);
    if (direct) return direct;
    if (typeof command !== 'string') return null;
    const match = command.match(/marrow-mcp\s+grok-(context-hook|pre-action-hook|hook|session-hook)(?:\s|['"]|$)/)
      || command.match(/["']marrow-mcp["']\s*,\s*["']grok-(context-hook|pre-action-hook|hook|session-hook)["']/);
    return match?.[1] as MarrowHookSubcommand | undefined || null;
  };
  const reconcile = (
    eventName: string,
    subcommand: MarrowHookSubcommand,
    canonical?: Record<string, unknown>,
  ): unknown[] => {
    const original = Array.isArray(hooks[eventName]) ? hooks[eventName] as unknown[] : [];
    const retained: unknown[] = [];
    for (const entry of original) {
      const record = asRecord(entry);
      if (!record || !Array.isArray(record.hooks)) {
        retained.push(entry);
        continue;
      }
      const remaining = record.hooks.filter((hook) => grokSubcommand(asRecord(hook)?.command) !== subcommand);
      if (remaining.length > 0) retained.push({ ...record, hooks: remaining });
    }
    return canonical ? [...retained, canonical] : retained;
  };
  const context = { hooks: [{ type: 'command', command: GROK_CONTEXT_HOOK_COMMAND, timeout: 5 }] };
  const pre = { matcher: GROK_NATIVE_HOOK_MATCHER, hooks: [{ type: 'command', command: GROK_PRE_ACTION_GUARD_COMMAND, timeout: 7 }] };
  const result = { matcher: GROK_NATIVE_HOOK_MATCHER, hooks: [{ type: 'command', command: GROK_ACTION_RESULT_HOOK_COMMAND, timeout: 5 }] };
  const stop = { hooks: [{ type: 'command', command: GROK_SESSION_END_HOOK_COMMAND, timeout: 3 }] };
  const nextHooks: Record<string, unknown> = {
    ...hooks,
    UserPromptSubmit: reconcile('UserPromptSubmit', 'context-hook', context),
    PreToolUse: reconcile('PreToolUse', 'pre-action-hook', pre),
    PostToolUse: reconcile('PostToolUse', 'hook', result),
    PostToolUseFailure: reconcile('PostToolUseFailure', 'hook', result),
    Stop: reconcile('Stop', 'session-hook', stop),
  };
  const sessionEnd = reconcile('SessionEnd', 'session-hook');
  if (sessionEnd.length > 0) nextHooks.SessionEnd = sessionEnd;
  else delete nextHooks.SessionEnd;
  settings.hooks = nextHooks;
  const serialized = `${JSON.stringify(settings, null, 2)}\n`;
  mkdirSync(dirname(settingsPath), { recursive: true, mode: 0o700 });
  writeFileSync(settingsPath, serialized, { mode: 0o600 });
  return { settingsPath, installed: previous !== serialized };
}
