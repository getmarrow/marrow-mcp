import { createHash, randomUUID } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { emitBaseUrlNotice, resolveMarrowEnv, type ResolvedMarrowEnv } from './env';
import { keyedTargetHash, normalizedHookAction, shellToolRunOptionsKey } from './normalized-action';
import { isMarrowServerLaunchShape } from './own-server-identity';
import {
  geminiMcpTarget, isGeminiOwnLabel, isMarrowOwnTool, isOfficialMarrowGeminiCall, isOfficialMarrowMcpTool, isOfficialMarrowNestedInput,
  listNativeHookMatcher, nativeHookMatcher, normalizedMcpToolName, r2NativeHookMatcher,
} from './own-tool';

export const MCP_ADAPTER_VERSION = '3.9.106';
export const NATIVE_HOOK_MATCHER = nativeHookMatcher();
/**
 * Matchers older versions wrote, so a hook carrying one needs repair: the
 * released one skips every `mcp__marrow__marrow_*` tool; the r2 one (never
 * released) skips `functions.mcp__marrow__<own>` and, under a full match, any
 * name with a line terminator; the 3.9.102/3.9.103 list skips every built-in
 * outside its fixed list (Monitor, PowerShell, WebFetch, Agent).
 */
export const LEGACY_NATIVE_HOOK_MATCHERS: readonly string[] = [
  'Bash|Edit|Write|MultiEdit|Read|Glob|Grep|Search|WebSearch|Task|functions\\.(?!mcp__marrow__marrow_).*|mcp__(?!marrow__marrow_).*',
  r2NativeHookMatcher(),
  listNativeHookMatcher(),
];
export const GROK_NATIVE_HOOK_MATCHER = 'run_terminal_command|search_replace|write|spawn_subagent|use_tool|workflow|image_gen|image_edit|image_to_video|reference_to_video';
export const MCP_PACKAGE_SPEC = `@getmarrow/mcp@${MCP_ADAPTER_VERSION}`;
const hookCommand = (entrypoint: string) => `npx -y --package=${MCP_PACKAGE_SPEC} marrow-mcp ${entrypoint}`;
export const CONTEXT_HOOK_COMMAND = hookCommand('claude-context-hook');
export const PRE_ACTION_HOOK_COMMAND = hookCommand('claude-pre-action-hook');
export const ACTION_RESULT_HOOK_COMMAND = hookCommand('claude-hook');
export const SESSION_END_HOOK_COMMAND = hookCommand('claude-session-hook');
/**
 * Pass-through PermissionRequest hook: notes that Claude Code is about to show
 * its own permission dialog for a held call, so the operator's answer can be
 * labelled an operator approval. It never returns a decision and is installed
 * with async: true, so it cannot answer or delay the dialog.
 */
export const PERMISSION_REQUEST_HOOK_COMMAND = hookCommand('claude-permission-request-hook');
export const GROK_CONTEXT_HOOK_COMMAND = hookCommand('grok-context-hook');
export const GROK_PRE_ACTION_HOOK_COMMAND = hookCommand('grok-pre-action-hook');
export const GROK_ACTION_RESULT_HOOK_COMMAND = hookCommand('grok-hook');
export const GROK_SESSION_END_HOOK_COMMAND = hookCommand('grok-session-hook');
export const GROK_FIXED_DENIAL = 'Marrow blocked this protected action.';
export const GROK_LAUNCH_FAILURE = 'Marrow governance adapter was unavailable; this action is blocked.';
export const MARROW_OUTAGE_WARNING = 'Marrow is offline. This action is allowed. The record stays queued locally and is sent when Marrow is back.';
const GROK_PRE_ACTION_GUARD_SOURCE = [
  'const {spawn}=require("node:child_process");',
  `const valid=value=>{try{const parsed=JSON.parse(value);return JSON.stringify(parsed)===value&&parsed&&Object.keys(parsed).every(key=>["decision","reason"].includes(key))&&(parsed.decision==="allow"&&parsed.reason===undefined||parsed.decision==="deny"&&typeof parsed.reason==="string"&&parsed.reason.length>0&&parsed.reason.length<=500);}catch{return false;}};`,
  'let child=null,timer=null,done=false,input=[],inputBytes=0,output="",outputBytes=0,err="";',
  `const outage=${JSON.stringify(`${MARROW_OUTAGE_WARNING}\n`)};`,
  `const fail=()=>{if(done)return;done=true;if(timer)clearTimeout(timer);if(child&&!child.killed)child.kill("SIGKILL");process.stderr.write(${JSON.stringify(`${GROK_LAUNCH_FAILURE}\n`)});process.exitCode=2;process.stdin.destroy();};`,
  'process.stdin.on("error",fail);',
  'process.stdin.on("data",chunk=>{const value=Buffer.from(chunk);inputBytes+=value.length;if(inputBytes>65536){fail();return;}input.push(value);});',
  'process.stdin.on("end",()=>{if(done)return;try{',
  `child=spawn(process.platform==="win32"?"npx.cmd":"npx",${JSON.stringify(['-y', `--package=${MCP_PACKAGE_SPEC}`, 'marrow-mcp', 'grok-pre-action-hook'])},{stdio:["pipe","pipe","pipe"]});`,
  'timer=setTimeout(fail,10000);',
  'child.stdout.on("data",chunk=>{if(done)return;outputBytes+=chunk.length;if(outputBytes>512){fail();return;}output+=chunk.toString("utf8");});',
  'child.stderr.on("data",chunk=>{if(done)return;if(err.length<1024)err+=chunk.toString("utf8");});',
  'child.on("error",fail);child.stdin.on("error",fail);',
  'child.on("close",code=>{if(done)return;if(code!==0||!valid(output)){fail();return;}done=true;if(timer)clearTimeout(timer);if(err===outage)process.stderr.write(err);process.stdout.write(output);});',
  'child.stdin.end(Buffer.concat(input));}catch{fail();}});',
].join('');
export const GROK_PRE_ACTION_GUARD_COMMAND = `node -e '${GROK_PRE_ACTION_GUARD_SOURCE}'`;
export const CURSOR_PRE_ACTION_HOOK_COMMAND = hookCommand('cursor-pre-action-hook');
export const CURSOR_ACTION_RESULT_HOOK_COMMAND = hookCommand('cursor-hook');
export const CURSOR_SESSION_END_HOOK_COMMAND = hookCommand('cursor-session-hook');
export const CURSOR_CONTEXT_HOOK_COMMAND = hookCommand('cursor-context-hook');
export const CLINE_PRE_ACTION_HOOK_COMMAND = hookCommand('cline-pre-action-hook');
export const CLINE_ACTION_RESULT_HOOK_COMMAND = hookCommand('cline-hook');
export const CLINE_SESSION_END_HOOK_COMMAND = hookCommand('cline-session-hook');
export const WINDSURF_PRE_ACTION_HOOK_COMMAND = hookCommand('windsurf-pre-action-hook');
export const WINDSURF_ACTION_RESULT_HOOK_COMMAND = hookCommand('windsurf-hook');
export const WINDSURF_SESSION_END_HOOK_COMMAND = hookCommand('windsurf-session-hook');
export const GEMINI_PRE_ACTION_HOOK_COMMAND = hookCommand('gemini-pre-action-hook');
export const GEMINI_ACTION_RESULT_HOOK_COMMAND = hookCommand('gemini-hook');
export const GEMINI_SESSION_END_HOOK_COMMAND = hookCommand('gemini-session-hook');
export const GEMINI_CONTEXT_HOOK_COMMAND = hookCommand('gemini-context-hook');
const LOCAL_CONFIGURED_HOOK_STAGES = ['prompt', 'pre_action', 'action_result', 'session_end', 'session_loop_guard'] as const;

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
  'claude-permission-request-hook': 'claude-code',
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
  'cursor-context-hook': 'cursor',
  'cline-pre-action-hook': 'cline',
  'cline-hook': 'cline',
  'cline-session-hook': 'cline',
  'windsurf-pre-action-hook': 'windsurf',
  'windsurf-hook': 'windsurf',
  'windsurf-session-hook': 'windsurf',
  'gemini-pre-action-hook': 'gemini',
  'gemini-hook': 'gemini',
  'gemini-session-hook': 'gemini',
  'gemini-context-hook': 'gemini',
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
  emitBaseUrlNotice(environment);
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

type PrivateHookLoopGuardPayload = { toolInput?: unknown; toolResult?: unknown };
const PRIVATE_HOOK_LOOP_GUARD_PAYLOAD = new WeakMap<object, PrivateHookLoopGuardPayload>();

function attachPrivateHookLoopGuardPayload(
  normalized: Record<string, unknown>,
  payload: PrivateHookLoopGuardPayload,
): Record<string, unknown> {
  PRIVATE_HOOK_LOOP_GUARD_PAYLOAD.set(normalized, payload);
  return normalized;
}

export function privateHookLoopGuardPayload(event: object): PrivateHookLoopGuardPayload {
  return PRIVATE_HOOK_LOOP_GUARD_PAYLOAD.get(event) || {};
}

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
  // input_truncated: this adapter cut or dropped the input, so the exact action
  // is not known; the normalized action is then marked truncated (never bound).
  if (action.endsWith('_run_command')) {
    normalized.tool_name = 'Bash';
    const command = typeof info.command_line === 'string' ? info.command_line.slice(0, 8192) : '';
    normalized.tool_input = { command };
    if (typeof info.command_line === 'string' && info.command_line.length > 8192) normalized.input_truncated = true;
  } else if (action.endsWith('_write_code')) {
    normalized.tool_name = 'Write';
    normalized.tool_input = {};
    normalized.input_truncated = true;
  } else if (action.endsWith('_mcp_tool_use')) {
    const server = boundedWindsurfName(info.mcp_server_name) || 'unknown';
    const tool = boundedWindsurfName(info.mcp_tool_name) || 'unknown';
    normalized.tool_name = normalizedMcpToolName(
      isMarrowOwnTool(info.mcp_server_name, info.mcp_tool_name), tool, server, info.mcp_server_name, info.mcp_tool_name,
    );
    normalized.tool_input = {};
    normalized.input_truncated = true;
  }
  if (action.startsWith('post_') && action !== 'post_cascade_response') normalized.success = true;
  return normalized;
}

function normalizeGeminiHookEvent(source: Record<string, unknown>): Record<string, unknown> {
  const hookEventName = typeof source.hook_event_name === 'string' ? source.hook_event_name.trim() : '';
  if (!['BeforeTool', 'AfterTool', 'AfterAgent', 'BeforeAgent'].includes(hookEventName)) return {};
  const normalized: Record<string, unknown> = { hook_event_name: hookEventName };
  const sessionId = boundedCorrelationId(source.session_id);
  if (sessionId) normalized.session_id = sessionId;
  if (hookEventName === 'AfterAgent') return normalized;
  if (hookEventName === 'BeforeAgent') {
    // Only a short typed reply is ever read from the prompt.
    if (typeof source.prompt === 'string' && source.prompt.length <= 64) normalized.prompt = source.prompt;
    return normalized;
  }
  const toolName = typeof source.tool_name === 'string' ? source.tool_name.trim().slice(0, 256) : '';
  // Gemini's separate server and tool. The label `mcp_<server>_<tool>` is ambiguous
  // (`marrow_marrow` + `commit` = `marrow` + `marrow_commit`), so only this proves a call is Marrow's own.
  const mcpTarget = geminiMcpTarget(source.mcp_context);
  if (mcpTarget) normalized.mcp_context = mcpTarget;
  const own = isOfficialMarrowGeminiCall(source.tool_name, mcpTarget);
  // A label in another host's own form (`mcp__marrow__<own>` from a server named `mcp`, `MCP:<own>`
  // from an older Gemini) without that proof: never own, left unclassified (held), as a padded one is.
  const otherFormOwnLabel = !own && isOfficialMarrowMcpTool(toolName);
  // A padded Marrow tool name is not Marrow's own: leave it unclassified (held).
  const paddedOwnName = toolName !== source.tool_name && (otherFormOwnLabel || isGeminiOwnLabel(toolName));
  // A trimmed or cut name is not the host's exact tool: never bound, so it never shares a key with the exact one.
  // Kept on the second normalization (hooks normalize on read and again on use).
  if (source.input_truncated === true || (toolName && toolName !== source.tool_name)) normalized.input_truncated = true;
  if (own && mcpTarget) {
    normalized.tool_name = `mcp__marrow__${mcpTarget.tool_name}`;
  } else if (toolName && !paddedOwnName && !otherFormOwnLabel && /^[A-Za-z0-9._:-]+$/.test(toolName)) {
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
  return attachPrivateHookLoopGuardPayload(normalized, {
    toolInput: source.tool_input,
    toolResult: source.tool_response,
  });
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
  const adapterBuilt = Boolean(toolName === 'use_tool' && server && nestedTool);
  const boundedToolName = adapterBuilt
    ? normalizedMcpToolName(
      source.toolName === 'use_tool' && isOfficialMarrowNestedInput(toolInput), nestedTool!, server!,
      toolInput?.serverName ?? toolInput?.server_name, toolInput?.toolName ?? toolInput?.tool_name,
    )
    : toolName;
  // The adapter's own encoding: an escaped name quotes inexact or colon-bearing server and tool names.
  // An inexact name that bounds to Marrow's own stays unclassified (held), as before.
  if (boundedToolName && (/^[A-Za-z0-9._:-]+$/.test(boundedToolName) || (adapterBuilt && !isMarrowOwnTool(server, nestedTool)))) {
    normalized.tool_name = boundedToolName;
  }
  // A trimmed, cut or replaced name is not the host's exact tool: never bound, so it never shares a key with the exact one.
  if (toolName !== source.toolName || (toolName === 'use_tool' && (server !== (toolInput?.serverName ?? toolInput?.server_name)
    || nestedTool !== (toolInput?.toolName ?? toolInput?.tool_name)))) normalized.input_truncated = true;
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
  return attachPrivateHookLoopGuardPayload(normalized, {
    toolInput: source.toolInput,
    toolResult: source.toolResult,
  });
}

const CURSOR_EXECUTION_EVENTS = new Set(['beforeShellExecution', 'afterShellExecution', 'beforeMCPExecution', 'afterMCPExecution']);

/**
 * Cursor's shell and MCP execution hooks carry no tool_name/tool_input; map
 * them onto the same tool shape as Cursor's preToolUse so the before and after
 * events of one call correlate. Cursor gives no call id: correlation uses the
 * conversation, the generation and the call itself.
 */
function normalizeCursorExecutionEvent(source: Record<string, unknown>): Record<string, unknown> {
  const event = String(source.hook_event_name);
  // Already normalized (hooks normalize once on read and again on use).
  const raw = event.endsWith('ShellExecution') ? typeof source.command === 'string' : typeof source.mcp_server_name === 'string';
  if (!raw && source.tool_name && source.tool_input && typeof source.tool_input === 'object') return { ...source };
  const normalized: Record<string, unknown> = { hook_event_name: event };
  for (const field of ['conversation_id', 'generation_id']) {
    const bounded = boundedCorrelationId(source[field]);
    if (bounded) normalized[field] = bounded;
  }
  if (normalized.conversation_id) normalized.session_id = normalized.conversation_id;
  if (event.endsWith('ShellExecution')) {
    normalized.tool_name = 'Shell';
    normalized.tool_input = { command: typeof source.command === 'string' ? source.command.slice(0, 65_536) : '' };
    if (typeof source.command === 'string' && source.command.length > 65_536) normalized.input_truncated = true;
    // Cursor reports no exit status: the outcome is unknown, never assumed to be a success.
    if (event === 'afterShellExecution') normalized.outcome_unknown = true;
    return normalized;
  }
  const server = boundedWindsurfName(source.mcp_server_name) || 'unknown';
  const tool = boundedWindsurfName(source.tool_name) || 'unknown';
  normalized.tool_name = normalizedMcpToolName(
    isMarrowOwnTool(source.mcp_server_name, source.tool_name), tool, server, source.mcp_server_name, source.tool_name,
  );
  // A trimmed, cut or replaced (`unknown`) name is not the host's exact tool: never bound, so it never shares a key.
  if (server !== source.mcp_server_name || tool !== source.tool_name) normalized.input_truncated = true;
  let input: unknown = {};
  if (typeof source.tool_input === 'string' && source.tool_input.length <= 262_144) {
    try {
      input = JSON.parse(source.tool_input);
    } catch {
      input = { raw: source.tool_input.slice(0, 4096) };
      if (source.tool_input.length > 4096) normalized.input_truncated = true;
    }
  } else if (source.tool_input && typeof source.tool_input === 'object') {
    input = source.tool_input;
  } else if (typeof source.tool_input === 'string') {
    normalized.input_truncated = true;
  }
  normalized.tool_input = input;
  if (event === 'afterMCPExecution') normalized.outcome_unknown = true;
  return normalized;
}

export function normalizeHookEventPayload(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const source = value as Record<string, unknown>;
  if (CURSOR_EXECUTION_EVENTS.has(String(source.hook_event_name || ''))) return normalizeCursorExecutionEvent(source);
  if (typeof source.agent_action_name === 'string') return normalizeWindsurfHookEvent(source);
  if (['PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'Stop'].includes(String(source.hookEventName || ''))) {
    return normalizeGrokHookEvent(source);
  }
  if (['BeforeTool', 'AfterTool', 'AfterAgent', 'BeforeAgent'].includes(String(source.hook_event_name || ''))) {
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

// ---------------------------------------------------------------------------
// The installer's local-runtime hook forms (@getmarrow/install, src/mcp-runtime.js):
// the same entrypoint run from ~/.marrow/runtime/mcp/<version>/run when present,
// else through npx; or (later installers) run by node on the installer's inline
// loader, with no npx. Recognized only in their exact generated shape, and only
// when every version in them is the same; anything else is not Marrow's.
// ---------------------------------------------------------------------------

const LOCAL_ARGS = '--package=@getmarrow/mcp@(\\d+\\.\\d+\\.\\d+) marrow-mcp ([a-z][a-z-]{0,63})';
const LOCAL_PLAIN_RE = new RegExp(`^/bin/sh -c 'M="\\$HOME/\\.marrow/runtime/mcp/(\\d+\\.\\d+\\.\\d+)/run"; if \\[ -x "\\$M" \\]; then exec "\\$M" ${LOCAL_ARGS}; fi; exec npx -y --package=@getmarrow/mcp@\\2 marrow-mcp \\3'$`);
const LOCAL_INNER_RE = new RegExp(`\\{ M="\\$HOME/\\.marrow/runtime/mcp/(\\d+\\.\\d+\\.\\d+)/run"; if \\[ -x "\\$M" \\]; then "\\$M" ${LOCAL_ARGS}; else npx -y --package=@getmarrow/mcp@\\2 marrow-mcp \\3; fi; \\}`, 'g');
const LOCAL_SPAWN_RE = /spawn\(\.\.\.\(\(f,m,a\)=>f\.existsSync\(m\)\?\[m,a\.slice\(1\)\]:\[process\.platform==="win32"\?"npx\.cmd":"npx",a\]\)\(require\("node:fs"\),\(process\.env\.HOME\|\|""\)\+"\/\.marrow\/runtime\/mcp\/(\d+\.\d+\.\d+)\/run",(\["-y","--package=@getmarrow\/mcp@(\d+\.\d+\.\d+)","marrow-mcp","[a-z-]+"\])\),/g;
const LOCAL_GUARD_PREFIX_RE = /^N="\$HOME\/\.marrow\/runtime\/mcp\/(\d+\.\d+\.\d+)\/node"; \[ -x "\$N" \] \|\| N=node; exec "\$N" -e '/;
const SPAWN_NPX = 'spawn(process.platform==="win32"?"npx.cmd":"npx",';

// The inline-loader plain form (POSIX): /bin/sh picks node (the private runtime's,
// else an absolute one outside the project) and runs the loader, passed as $0; with
// no usable node it prints the installer's fixed text and exits 2 (pre-action) or 1.
const INSTALLER_REPAIR = 'The owner can repair it by running npx -y @getmarrow/install@latest --repair --cwd <project folder> from a terminal outside the project.';
const INSTALLER_HOLD_TEXT = `Marrow held this action: its verified local runtime could not start. ${INSTALLER_REPAIR}`;
const INSTALLER_UNAVAILABLE_TEXT = `Marrow could not start its verified local runtime. ${INSTALLER_REPAIR}`;
const INSTALLER_NODE_SEARCH = (version: string) => `N="$HOME/.marrow/runtime/mcp/${version}/node"; if [ ! -x "$N" ]; then N=; P="$PATH:/usr/local/bin:/opt/homebrew/bin"; while [ -n "$P" ]; do D="\${P%%:*}"; case "$P" in (*:*) P="\${P#*:}" ;; (*) P= ;; esac; case "$D" in ("$PWD"|"$PWD"/*) ;; (/*) if [ -f "$D/node" ] && [ -x "$D/node" ]; then N="$D/node"; break; fi ;; esac; done; fi; `;
function installerLoaderPlain(version: string, sub: string, loader: string): string {
  const pre = /-pre-action-hook$/.test(sub);
  return `/bin/sh -c '${INSTALLER_NODE_SEARCH(version)}if [ -n "$N" ]; then exec "$N" -e "$0" -- --package=@getmarrow/mcp@${version} marrow-mcp ${sub}; fi; printf "%s\\n" "${pre ? INSTALLER_HOLD_TEXT : INSTALLER_UNAVAILABLE_TEXT}" >&2; exit ${pre ? 2 : 1}' "${loader}"`;
}
// Only picks out the parts; the command must then equal installerLoaderPlain of them exactly.
const LOADER_PLAIN_RE = /^\/bin\/sh -c 'N="\$HOME\/\.marrow\/runtime\/mcp\/(\d+\.\d+\.\d+)\/node"; [^']* -- --package=@getmarrow\/mcp@\1 marrow-mcp ([a-z][a-z-]{0,63}); fi; printf [^']*' "([^"'\s]{16,16384})"$/;
const MAX_LOADER_PLAIN_LENGTH = 32_768;
// The loader must decode to the installer's launcher for this version with a pinned
// runtime core: the installer's server launch shape (node -e <loader>), any pack integrity.
const installerLoaderFor = (loader: string, version: string): boolean =>
  isMarrowServerLaunchShape('node', ['-e', loader, '--', `--package=@getmarrow/mcp@${version}`, 'marrow-mcp']);

/**
 * The npx form of an installer local-runtime hook command, or the command
 * unchanged when it is not exactly one (another shape, a suffix, a different
 * runtime path, or versions that differ anywhere in it).
 */
export function delocalizeMarrowHookCommand(command: unknown): unknown {
  if (typeof command !== 'string') return command;
  const plain = LOCAL_PLAIN_RE.exec(command);
  if (plain) return plain[1] === plain[2] ? `npx -y --package=@getmarrow/mcp@${plain[2]} marrow-mcp ${plain[3]}` : command;
  const loaderPlain = command.length <= MAX_LOADER_PLAIN_LENGTH ? LOADER_PLAIN_RE.exec(command) : null;
  if (loaderPlain) {
    const [, version, sub, loader] = loaderPlain;
    return installerLoaderPlain(version, sub, loader) === command && installerLoaderFor(loader, version)
      ? `npx -y --package=@getmarrow/mcp@${version} marrow-mcp ${sub}`
      : command;
  }
  const guard = LOCAL_GUARD_PREFIX_RE.exec(command);
  if (guard) {
    let consistent = true;
    let spawns = 0;
    const body = command.slice(guard[0].length).replace(LOCAL_SPAWN_RE, (_match, runVersion: string, argsJson: string, packageVersion: string) => {
      spawns += 1;
      if (runVersion !== guard[1] || packageVersion !== guard[1]) consistent = false;
      return `${SPAWN_NPX}${argsJson},`;
    });
    return consistent && spawns > 0 ? `node -e '${body}` : command;
  }
  if (command.startsWith('/bin/sh -c \'')) {
    let consistent = true;
    let blocks = 0;
    const body = command.slice('/bin/sh -c \''.length).replace(LOCAL_INNER_RE, (_match, runVersion: string, version: string, sub: string) => {
      blocks += 1;
      if (runVersion !== version) consistent = false;
      return `npx -y --package=@getmarrow/mcp@${version} marrow-mcp ${sub}`;
    });
    return consistent && blocks > 0 ? `sh -c '${body}` : command;
  }
  return command;
}

/** Whether a hook command is `canonical` itself or the installer's local form of it. */
export function isMarrowHookCommand(command: unknown, canonical: string): boolean {
  if (typeof command !== 'string') return false;
  const trimmed = command.trim();
  return trimmed === canonical || delocalizeMarrowHookCommand(trimmed) === canonical;
}

export type MarrowHookSubcommand = 'context-hook' | 'pre-action-hook' | 'hook' | 'session-hook' | 'permission-request-hook';

function marrowHookSubcommand(command: unknown): MarrowHookSubcommand | null {
  if (typeof command !== 'string') return null;
  const npxForm = delocalizeMarrowHookCommand(command.trim()) as string;
  const match = npxForm.match(
    /^npx\s+(?:-y\s+)?(?:--package=@getmarrow\/mcp(?:@[^\s]+)?\s+marrow-mcp|@getmarrow\/mcp(?:@[^\s]+)?)\s+(?:(?:claude|cline|codex|cursor|gemini|grok|windsurf)-)?(context-hook|pre-action-hook|hook|session-hook|permission-request-hook)$/,
  );
  return match?.[1] as MarrowHookSubcommand | undefined || null;
}

export function reconcileMarrowCommandHook(
  settings: HookSettings,
  eventName: string,
  subcommand: MarrowHookSubcommand,
  command: string,
  matcher?: string,
  handlerFields: Record<string, unknown> = {},
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
        if (detected === subcommand && (!preferredHandler || (isMarrowHookCommand(handler.command, command) && exactMatcher))) {
          preferredHandler = handler;
        }
        continue;
      }
      remaining.push(hook);
    }
    if (remaining.length > 0) retained.push({ ...record, hooks: remaining });
  }

  // An existing entry for this exact command keeps its form (the installer's local runtime or npx).
  const keptCommand = preferredHandler && isMarrowHookCommand(preferredHandler.command, command)
    ? String(preferredHandler.command).trim()
    : command;
  const handler = { ...(preferredHandler || {}), ...handlerFields, type: 'command', command: keptCommand };
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
        && isMarrowHookCommand(handler.command, command);
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
      if (handler?.type !== 'command' || !isMarrowHookCommand(handler.command, command)) return [];
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

const NATIVE_MATCHER_HOOK_EVENTS = ['PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'PermissionRequest'] as const;

/**
 * Marrow handlers on a tool event whose matcher is not the current
 * NATIVE_HOOK_MATCHER (an older version's, a hand edit, or none). The host
 * still runs them, but they may skip tools the current matcher covers, so
 * setup rewrites them; until then they are reported, never counted as healthy.
 */
export function staleMatcherHooks(settings: HookSettings): Array<{ event: string; subcommand: MarrowHookSubcommand; matcher: string | null; legacy: boolean }> {
  const hooks = asRecord(settings.hooks);
  return NATIVE_MATCHER_HOOK_EVENTS.flatMap((event) => {
    const entries = hooks?.[event];
    if (!Array.isArray(entries)) return [];
    return entries.flatMap((entry) => {
      const record = asRecord(entry);
      if (!record || !Array.isArray(record.hooks) || record.matcher === NATIVE_HOOK_MATCHER) return [];
      const matcher = typeof record.matcher === 'string' ? record.matcher : null;
      return record.hooks.flatMap((hook) => {
        const handler = asRecord(hook);
        const subcommand = marrowHookSubcommand(handler?.command);
        if (handler?.type !== 'command' || !subcommand) return [];
        return [{ event, subcommand, matcher, legacy: matcher !== null && LEGACY_NATIVE_HOOK_MATCHERS.includes(matcher) }];
      });
    });
  });
}

export function localHookRepairStatus(startDir = process.cwd()): { needs_repair: boolean; stale_matchers: ReturnType<typeof staleMatcherHooks> } {
  const stale = staleMatcherHooks(readHookSettings(startDir));
  return { needs_repair: stale.length > 0, stale_matchers: stale };
}

export function localHookConfigurationFingerprint(startDir = process.cwd()): string {
  const settings = readHookSettings(startDir);
  const contract = {
    schema: 'marrow-claude-native-hooks.v5',
    stale_matchers: staleMatcherHooks(settings),
    adapter_version: MCP_ADAPTER_VERSION,
    configured_stages: LOCAL_CONFIGURED_HOOK_STAGES,
    configured: {
      prompt: hasExactCommandHook(settings, 'UserPromptSubmit', CONTEXT_HOOK_COMMAND),
      pre_action: hasExactCommandHook(settings, 'PreToolUse', PRE_ACTION_HOOK_COMMAND, NATIVE_HOOK_MATCHER),
      action_result_success: hasExactCommandHook(settings, 'PostToolUse', ACTION_RESULT_HOOK_COMMAND, NATIVE_HOOK_MATCHER),
      action_result_failure: hasExactCommandHook(settings, 'PostToolUseFailure', ACTION_RESULT_HOOK_COMMAND, NATIVE_HOOK_MATCHER),
      session_end: hasExactCommandHook(settings, 'Stop', SESSION_END_HOOK_COMMAND),
      session_loop_guard: hasExactCommandHook(settings, 'PreToolUse', PRE_ACTION_HOOK_COMMAND, NATIVE_HOOK_MATCHER)
        && hasExactCommandHook(settings, 'PostToolUse', ACTION_RESULT_HOOK_COMMAND, NATIVE_HOOK_MATCHER),
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

function stableCanonical(value: unknown, depth = 0): unknown {
  if (depth > 8) return '[depth]';
  if (Array.isArray(value)) return value.slice(0, 128).map((item) => stableCanonical(item, depth + 1));
  if (value && typeof value === 'object') {
    const source = value as Record<string, unknown>;
    return Object.fromEntries(Object.keys(source).sort().slice(0, 128)
      .map((key) => [key, stableCanonical(source[key], depth + 1)]));
  }
  return typeof value === 'string' ? value.slice(0, 16_384) : value;
}

function stableHash(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(stableCanonical(value))).digest('hex').slice(0, 32);
}

let lastIdentity: { toolName: unknown; toolInput: unknown; value: unknown } | null = null;

function lengthOf(value: unknown): number {
  try { return JSON.stringify(value)?.length ?? 0; } catch { return 0; }
}

/**
 * What identifies a tool call in ids sent to Marrow: its normalized action
 * (secrets replaced by markers, data hashed), never the raw input, which may
 * hold a secret. No deadline (only the size caps), so every hook process
 * derives the same identity for the same call. A truncated action is
 * identified by its exact_hmac (keyed on this machine; only certain
 * credentials hidden), so a held call's approval is only ever resumed by the
 * same exact call; a truncated action without one matches nothing.
 */
function actionIdentity(toolName: unknown, toolInput: unknown): unknown {
  if (lastIdentity && lastIdentity.toolName === toolName && lastIdentity.toolInput === toolInput) return lastIdentity.value;
  const action = normalizedHookAction({ tool_name: toolName, tool_input: toolInput }, { deadlineAt: Number.POSITIVE_INFINITY });
  // A placeholder (input over the size caps) keeps the input's length, so two such calls rarely share it.
  const placeholder = Object.keys(action.tool_input).length === 0;
  const exact = (action.tool_input as { exact_hmac?: unknown }).exact_hmac;
  const value = {
    kind: action.tool_kind, programs: action.programs ?? null, paths: action.paths ?? null,
    input: action.truncated === true && (typeof exact !== 'string' || !/^[0-9a-f]{32}$/.test(exact)) ? { unmatched: randomUUID() } : action.tool_input,
    ...(placeholder ? { size: lengthOf(toolInput) } : {}),
  };
  lastIdentity = { toolName, toolInput, value };
  return value;
}

/**
 * The correlation of one tool call (pre- and post-tool events, holds): the
 * session, the tool and the call's normalized action. Calls that differ only
 * in a secret share it; a retry of the same call keeps it.
 */
export function stableToolCorrelation(event: {
  session_id?: string;
  tool_use_id?: string;
  tool_name?: string;
  tool_input?: unknown;
}): string {
  return stableHash([
    event.session_id || '',
    event.tool_name || 'tool',
    actionIdentity(event.tool_name, event.tool_input ?? null),
  ]);
}

/** Hook events whose MCP tool name the adapter built from a separate server and tool. */
const ADAPTER_MCP_EVENTS = new Set(['beforeMCPExecution', 'afterMCPExecution', 'pre_mcp_tool_use', 'post_mcp_tool_use']);

/**
 * The exact target of one tool call, for binding a hold's approval to it: the
 * tool name exactly as normalised (adapters encode server and tool without
 * ambiguity), whether an adapter built that name from a separate server and
 * tool (Cursor `MCP:a:b` at preToolUse is a tool named `a:b`; at
 * beforeMCPExecution it is server `a`, tool `b`), the nested server and tool
 * fields of the input, and Gemini's mcp_context server and tool. The pre and
 * post events of one call give the same target. Only the hash is kept.
 */
export function exactHookTarget(event: { hook_event_name?: unknown; tool_name?: unknown; tool_input?: unknown; mcp_context?: unknown }): string {
  try {
    const input = event.tool_input && typeof event.tool_input === 'object' && !Array.isArray(event.tool_input)
      ? event.tool_input as Record<string, unknown>
      : null;
    const nested = input
      ? ['serverName', 'server_name', 'toolName', 'tool_name'].map((key) => (Object.prototype.hasOwnProperty.call(input, key) ? input[key] ?? null : null))
      : null;
    const mcp = geminiMcpTarget(event.mcp_context);
    // A Monitor or PowerShell call's run options (timeout, timeout_ms, run_in_background) bind its approval
    // too; the element is absent for every other call, whose target is unchanged.
    const runOptions = shellToolRunOptionsKey(event);
    // Keyed with the per-install device key (the nested names and run options are tool input, so they may hold a
    // value the redactor did not see); without a usable key no target can match, so the hold stays held.
    const keyed = keyedTargetHash([
      typeof event.tool_name === 'string' ? event.tool_name : null,
      ADAPTER_MCP_EVENTS.has(String(event.hook_event_name ?? '')) ? 'adapter-mcp' : 'host-name',
      nested,
      mcp ? [mcp.server_name, mcp.tool_name] : null,
      ...(runOptions === null ? [] : [runOptions]),
    ]);
    if (keyed !== null) return keyed;
    return createHash('sha256').update(`unmatched:${randomUUID()}`).digest('hex');
  } catch {
    // Not serialisable: a target nothing else can match (it stays held).
    return createHash('sha256').update(`unmatched:${randomUUID()}`).digest('hex');
  }
}

/**
 * The correlation of one submitted prompt: the session and the host's own
 * prompt, turn or generation id, never the prompt text (it may hold a secret). A host
 * that gives no id gets a fresh one per prompt event.
 */
export function stablePromptCorrelation(event: {
  session_id?: string;
  prompt_id?: unknown;
  turn_id?: unknown;
  generation_id?: unknown;
}): string {
  const turn = [event.prompt_id, event.turn_id, event.generation_id].find((value) => typeof value === 'string' && value.trim());
  return stableHash([event.session_id || '', turn ?? randomUUID()]);
}

/** A local path with the person's home directory as `~`, so no user name is hashed into an id. */
function withoutHomeDirectory(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  const home = homedir();
  if (home && home !== '/' && (value === home || value.startsWith(`${home}/`))) return `~${value.slice(home.length)}`;
  return value;
}

export function stableSessionWorkflowId(sessionId?: string, fallback?: unknown): string {
  const local = Array.isArray(fallback) ? fallback.map(withoutHomeDirectory) : withoutHomeDirectory(fallback);
  return `session-${stableHash([sessionId || '', sessionId ? null : local ?? null])}`;
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
    const canonicalCommand = canonical && Array.isArray(canonical.hooks) ? asRecord(canonical.hooks[0])?.command : undefined;
    let keptCommand: string | null = null;
    for (const entry of original) {
      const record = asRecord(entry);
      if (!record || !Array.isArray(record.hooks)) {
        retained.push(entry);
        continue;
      }
      for (const hook of record.hooks) {
        const command = asRecord(hook)?.command;
        // An entry already running this exact command keeps its form (the installer's local runtime or npx).
        if (!keptCommand && typeof canonicalCommand === 'string' && isMarrowHookCommand(command, canonicalCommand)) keptCommand = String(command).trim();
      }
      const remaining = record.hooks.filter((hook) => grokSubcommand(asRecord(hook)?.command) !== subcommand);
      if (remaining.length > 0) retained.push({ ...record, hooks: remaining });
    }
    if (!canonical) return retained;
    const kept = keptCommand && Array.isArray(canonical.hooks)
      ? { ...canonical, hooks: [{ ...(asRecord(canonical.hooks[0]) || {}), command: keptCommand }] }
      : canonical;
    return [...retained, kept];
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
