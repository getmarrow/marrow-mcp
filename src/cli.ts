#!/usr/bin/env node
/**
 * Marrow MCP stdio server - runtime control and proof for MCP-compatible agents.
 * Exposes pre-action governance, intent capture, outcome closure, and fleet evidence.
 *
 * Usage:
 *   npx @getmarrow/mcp                          (reads MARROW_API_KEY from env)
 *   npx @getmarrow/mcp --key mrw_abc123          (pass key via CLI flag)
 *   MARROW_API_KEY=mrw_abc123 npx @getmarrow/mcp
 */

import {
  marrowThink,
  marrowCommit,
  marrowAuto,
  marrowOrient,
  marrowStatus,
  marrowAsk,
  marrowWorkflow,
  marrowDashboard,
  marrowDigest,
  marrowAgentStatus,
  marrowAgentContext,
  marrowRuntimeStatus,
  marrowValueReport,
  marrowDecisionBrief,
  marrowAgentRuntime,
  marrowArbitrate,
  marrowCoordinate,
  marrowReplayCompare,
  marrowGovernanceControlPlane,
  marrowHermesIntegration,
  marrowCompletionContracts,
  marrowEvaluateCompletionContract,
  marrowGovernanceTimeline,
  marrowDecisionTrace,
  marrowBuyerProof,
  marrowModelUsage,
  marrowRecommendGovernanceMode,
  marrowListPolicyProfiles,
  marrowCreatePolicyProfile,
  marrowAssignProjectPolicyProfile,
  marrowResolvePolicy,
  marrowFirstValue,
  marrowWorkflowGate,
  marrowAgentPerformance,
  marrowFleetLessons,
  marrowRecordDeploymentMemory,
  marrowCreateHandoff,
  marrowUpdateHandoff,
  marrowHandoffStatus,
  marrowSessionEnd,
  marrowAcceptDetected,
  marrowListTemplates,
  marrowInstallTemplate,
  marrowCreateKey,
  marrowListKeys,
  marrowGetKey,
  marrowRevokeKey,
  marrowRotateKey,
  marrowGetKeyAudit,
  validatePathParam,
  validateBaseUrl,
} from './index';
import { localControlEvidence } from './control-state';
import { installPostToolUseHook, runHookCommand } from './hook';
import { installGrokNativeHooks } from './hook-contract';
import { compactRuntimeContext, installUserPromptSubmitHook, runContextHookCommand } from './hook-context';
import { installSessionEndHook, runSessionHookCommand, sessionEndAutoCommitOpen } from './hook-session';
import { installPreActionHook, runPreActionHookCommand } from './hook-pre-action';
import { resolveMarrowEnv } from './env';
import {
  drainLifecycleSpool,
  lifecycleSpoolStatus,
  nudgeLifecycleSpool,
  quarantineLegacyNamespaces,
  recordLifecycleEvent,
} from './lifecycle-spool';
import { lifecycleSpoolCommandOutcome } from './spool-command';
import { readGuidanceCache, writeGuidanceCache } from './guidance-cache';
import { localClientUpdate, MarrowRequestError, structuredRequestFailure } from './request-reliability';
import { MCP_ADAPTER_VERSION } from './hook-contract';
import { resolvePingTimeoutMs, updatePingState } from './ping-state';
import { controlPathStats, recordControlPathSample } from './control-path-state';
import { redactSensitiveText, redactSensitiveValue } from './redact';
import { cachedStatusPayload, readStatusCache, writeStatusCache } from './status-cache';
import { formatHabitLoopCopy } from './habit-loop-copy';
import { hostCapabilityInstructions, resolveHostCapability } from './host-capability';
import type { MarrowAutoResult } from './index';
import type { ThinkResult, MarrowMemory } from './types';

// Parse CLI args
function parseArgs(): { apiKey?: string; setup?: boolean; hook?: boolean; contextHook?: boolean; preActionHook?: boolean; sessionHook?: boolean; spoolStatus?: boolean; drainSpool?: boolean; ping?: boolean } {
  const args = process.argv.slice(2);
  const result: { apiKey?: string; setup?: boolean; hook?: boolean; contextHook?: boolean; preActionHook?: boolean; sessionHook?: boolean; spoolStatus?: boolean; drainSpool?: boolean; ping?: boolean } = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--key' && i + 1 < args.length) {
      result.apiKey = args[i + 1];
      i++;
    }
    if (args[i] === 'setup' || args[i] === '--setup') {
      result.setup = true;
    }
    if (['hook', '--hook', 'claude-hook', 'cline-hook', 'codex-hook', 'cursor-hook', 'gemini-hook', 'grok-hook', 'windsurf-hook'].includes(args[i])) {
      result.hook = true;
    }
    if (['context-hook', '--context-hook', 'claude-context-hook', 'codex-context-hook', 'grok-context-hook'].includes(args[i])) {
      result.contextHook = true;
    }
    if (['pre-action-hook', '--pre-action-hook', 'claude-pre-action-hook', 'cline-pre-action-hook', 'codex-pre-action-hook', 'cursor-pre-action-hook', 'gemini-pre-action-hook', 'grok-pre-action-hook', 'windsurf-pre-action-hook'].includes(args[i])) {
      result.preActionHook = true;
    }
    if (['session-hook', '--session-hook', 'claude-session-hook', 'cline-session-hook', 'codex-session-hook', 'cursor-session-hook', 'gemini-session-hook', 'grok-session-hook', 'windsurf-session-hook'].includes(args[i])) {
      result.sessionHook = true;
    }
    if (args[i] === 'spool-status' || args[i] === '--spool-status') {
      result.spoolStatus = true;
    }
    if (args[i] === 'drain-spool' || args[i] === '--drain-spool') {
      result.drainSpool = true;
    }
    if (args[i] === 'ping' || args[i] === '--ping') {
      result.ping = true;
    }
  }
  return result;
}

function reportLifecycleSpool(input: { apiKey: string; baseUrl?: string; agentId?: string }) {
  try {
    quarantineLegacyNamespaces({ apiKey: input.apiKey, agentId: input.agentId });
  } catch { /* owner-only quarantine is best effort */ }
  const spool = lifecycleSpoolStatus({ apiKey: input.apiKey, agentId: input.agentId });
  if (input.baseUrl && spool.pending > 0) {
    void nudgeLifecycleSpool({ apiKey: input.apiKey, baseUrl: input.baseUrl, agentId: input.agentId });
  }
  return spool;
}

async function runPingCommand(): Promise<void> {
  if (cliArgs.apiKey) {
    process.stderr.write('Error: ping requires MARROW_API_KEY from trusted environment or owner configuration; --key is not accepted.\n');
    process.exitCode = 1;
    return;
  }
  const resolved = resolveMarrowEnv({ trustedOnly: true });
  if (!resolved.apiKey) {
    process.stdout.write(JSON.stringify({ ok: false, error: 'missing_key', exact_fix: resolved.exactFix }) + '\n');
    process.exitCode = 1;
    return;
  }
  const baseUrl = validateBaseUrl(resolved.baseUrl || 'https://api.getmarrow.ai');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), resolvePingTimeoutMs(process.env.MARROW_PING_TIMEOUT_MS));
  timer.unref?.();
  const started = Date.now();
  try {
    const status = await marrowRuntimeStatus(resolved.apiKey, baseUrl, true, resolved.sessionId, resolved.agentId, controller.signal);
    const latencyMs = Date.now() - started;
    const history = updatePingState({ apiKey: resolved.apiKey, baseUrl, agentId: resolved.agentId, latencyMs, success: true });
    process.stdout.write(JSON.stringify({
      ok: status.ok === true,
      health: status.health || 'available',
      current_ms: latencyMs,
      p50_ms: history.p50_ms,
      p99_ms: history.p99_ms,
      sample_count: history.sample_count,
      last_success_at: history.last_success_at,
      lifecycle_spool: reportLifecycleSpool({ apiKey: resolved.apiKey, baseUrl, agentId: resolved.agentId }),
    }, null, 2) + '\n');
  } catch (error) {
    const history = updatePingState({ apiKey: resolved.apiKey, baseUrl, agentId: resolved.agentId, success: false });
    const message = error instanceof Error ? error.message : String(error);
    process.stdout.write(JSON.stringify({
      ok: false,
      error: /401|unauthorized/i.test(message) ? 'authentication_failed' : /403|forbidden/i.test(message) ? 'permission_denied' : /abort|timeout/i.test(message) ? 'timeout' : 'unavailable',
      p50_ms: history.p50_ms,
      p99_ms: history.p99_ms,
      sample_count: history.sample_count,
      last_success_at: history.last_success_at,
      lifecycle_spool: reportLifecycleSpool({ apiKey: resolved.apiKey, baseUrl, agentId: resolved.agentId }),
    }, null, 2) + '\n');
    process.exitCode = 1;
  } finally {
    clearTimeout(timer);
  }
}

async function runSpoolCommand(drain: boolean): Promise<void> {
  if (cliArgs.apiKey) {
    process.stderr.write('Error: lifecycle spool commands require MARROW_API_KEY from trusted environment or owner configuration; --key is not accepted.\n');
    process.exitCode = 1;
    return;
  }
  const resolved = resolveMarrowEnv({ trustedOnly: true });
  const apiKey = resolved.apiKey || '';
  if (!apiKey) {
    process.stderr.write(`Error: MARROW_API_KEY required. ${resolved.exactFix}\n`);
    process.exitCode = 1;
    return;
  }
  const baseUrl = validateBaseUrl(resolved.baseUrl || 'https://api.getmarrow.ai');
  try {
    quarantineLegacyNamespaces({ apiKey, agentId: resolved.agentId || undefined });
  } catch { /* owner-only quarantine is best effort */ }
  const status = drain
    ? await drainLifecycleSpool({ apiKey, baseUrl, agentId: resolved.agentId || undefined })
    : lifecycleSpoolStatus({ apiKey, agentId: resolved.agentId || undefined });
  const outcome = lifecycleSpoolCommandOutcome(status, drain);
  process.stdout.write(`${JSON.stringify(outcome.output, null, 2)}\n`);
  if (outcome.exitCode !== 0) process.exitCode = outcome.exitCode;
}

// ─── Setup command: inject Marrow instructions into CLAUDE.md ───
function runSetup(): void {
  const fs = require('fs') as typeof import('fs');
  const path = require('path') as typeof import('path');

  const MARROW_BLOCK_START = '<!-- marrow:start -->';
  const MARROW_BLOCK_END = '<!-- marrow:end -->';

  const marrowInstructions = `${MARROW_BLOCK_START}
## Marrow — Agent Control and Proof (auto-injected by @getmarrow/mcp setup)

Use Marrow according to the capability evidence returned by the MCP server:

1. **MCP baseline is on demand:** MCP transport exposes tools; it does not provide passive hooks. Public hook callbacks and local configuration are client-self-reported activity, not certified coverage.
2. **Before risky actions:** Respect the returned \`allow\`, \`warn\`, \`review_required\`, or \`block\` decision and its proof contract. Call \`marrow_agent_runtime\` explicitly when verified passive coverage cannot cover the action.
3. **After meaningful work:** Record the real success or failure with \`marrow_commit\` or \`marrow_auto\`. A tool exit or session end is not proof that the business outcome succeeded.
4. **Unfinished work:** Leave pending outcomes visible. Do not invent success to clear a closure item.
5. **To explain an intervention:** Use \`marrow_decision_trace\`, then relay its \`intervention_receipt\` in one factual sentence when Marrow blocked, warned, or required review. Stay quiet for routine low-risk work.
6. **To query authorized history:** Call \`marrow_ask("plain english question")\` — ask what failed, what worked, and what policy should apply.
7. **When an update is reported:** Tell the operator and use the returned exact update and verification commands only when local change policy permits. Never silently change packages or configuration.

Do not skip the gate or outcome. Marrow's value comes from controlling the action before execution and preserving evidence afterward.

Capability boundaries: configured native hooks provide cooperative client-reported control and lifecycle evidence only; \`createPassiveRuntime().install()\` covers only its owned Node process while installed; a governed wrapper covers only its wrapped command; and a custom host needs a bounded event adapter. A model name, host label, API key, public hook entrypoint, installed configuration, or client-self-reported callback is not proof of coverage or enforcement. Codex, Grok, and Gemini use configured native hooks only after restart and the host's hook review; the governed wrapper remains an explicit bounded fallback.

For bounded outcome capture: \`marrow_auto({ action: "did X", outcome: "result Y", success: true })\`. One outer invocation normally completes think and commit in-band within its bounded client budget. If the host or network deadline is reached, retry with the returned \`operation_id\`; Marrow continues the same operation and never opens a second decision.
${MARROW_BLOCK_END}`;

  let dir = process.cwd();
  let claudeMdPath: string | null = null;

  for (let i = 0; i < 5; i++) {
    const candidate = path.join(dir, 'CLAUDE.md');
    if (fs.existsSync(candidate)) {
      claudeMdPath = candidate;
      break;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }

  if (!claudeMdPath) {
    claudeMdPath = path.join(process.cwd(), 'CLAUDE.md');
    process.stdout.write(`Creating ${claudeMdPath}\n`);
  }

  let content = '';
  if (fs.existsSync(claudeMdPath)) {
    content = fs.readFileSync(claudeMdPath, 'utf8');

    if (content.includes(MARROW_BLOCK_START)) {
      const startIdx = content.indexOf(MARROW_BLOCK_START);
      const endIdx = content.indexOf(MARROW_BLOCK_END);
      if (endIdx > startIdx) {
        content = content.slice(0, startIdx) + marrowInstructions + content.slice(endIdx + MARROW_BLOCK_END.length);
        fs.writeFileSync(claudeMdPath, content);
        process.stdout.write(`Updated Marrow instructions in ${claudeMdPath}\n`);
      }
    } else {
      const separator = content.length > 0 && !content.endsWith('\n') ? '\n\n' : content.length > 0 ? '\n' : '';
      fs.writeFileSync(claudeMdPath, content + separator + marrowInstructions + '\n');
      process.stdout.write(`Added Marrow instructions to ${claudeMdPath}\n`);
    }
  } else {
    fs.writeFileSync(claudeMdPath, marrowInstructions + '\n');
    process.stdout.write(`Added Marrow instructions to ${claudeMdPath}\n`);
  }

  const hookInstall = installPostToolUseHook(process.cwd());
  if (hookInstall.installed) {
    process.stdout.write('Configured PostToolUse hook. Activity is client-self-reported and does not certify action-result coverage.\n');
  } else {
    process.stdout.write('PostToolUse hook configuration is present. Activity is client-self-reported and does not certify action-result coverage.\n');
  }

  const contextHookInstall = installUserPromptSubmitHook(process.cwd());
  if (contextHookInstall.installed) {
    process.stdout.write('Configured UserPromptSubmit hook. Activity is client-self-reported and does not certify passive prompt coverage.\n');
  } else {
    process.stdout.write('UserPromptSubmit hook configuration is present. Activity is client-self-reported and does not certify passive prompt coverage.\n');
  }
  const preActionHookInstall = installPreActionHook(process.cwd());
  if (preActionHookInstall.installed) {
    process.stdout.write('Configured PreToolUse hook. Activity is client-self-reported and does not certify pre-action control.\n');
  } else {
    process.stdout.write('PreToolUse hook configuration is present. Activity is client-self-reported and does not certify pre-action control.\n');
  }
  const sessionHookInstall = installSessionEndHook(process.cwd());
  if (sessionHookInstall.installed) {
    process.stdout.write('Configured Stop hook. Activity is client-self-reported and does not certify session-end coverage.\n');
  } else {
    process.stdout.write('Stop hook configuration is present. Activity is client-self-reported and does not certify session-end coverage.\n');
  }

  const grokHookInstall = installGrokNativeHooks();
  if (grokHookInstall.installed) {
    process.stdout.write(`Configured Grok native pre-action, result, and nonblocking turn-closeout hooks at ${grokHookInstall.settingsPath}. Restart Grok and inspect /hooks before relying on them. Activity remains client-self-reported and does not certify observed coverage.\n`);
  } else {
    process.stdout.write(`Grok native hook configuration is present at ${grokHookInstall.settingsPath}. Restart Grok and inspect /hooks before relying on it. Activity remains client-self-reported and does not certify observed coverage.\n`);
  }

  process.stdout.write(`Hook settings: ${hookInstall.settingsPath}\n`);
  process.stdout.write('Set MARROW_AUTO_HOOK=false to disable passive hooks.\n');
  process.stdout.write('Set MARROW_PASSIVE_BRIEF=false to disable automatic decision briefs, or MARROW_PASSIVE_BRIEF=always to brief every prompt.\n');
  process.stdout.write('Set MARROW_HOOK_DEBUG=true for write-side hook diagnostics, or MARROW_CONTEXT_HOOK_DEBUG=true for prompt-context diagnostics.\n');
  process.stdout.write('Setup completed. MCP tools remain on demand; configured hook activity is client-self-reported and does not certify passive coverage or enforcement.\n');
  process.exit(0);
}

const cliArgs = parseArgs();

function formatKeyMaterialWarning(): string {
  return 'Copy this key now. Marrow will only show the full plaintext key once.';
}

// ─── Standalone CLI: key management ───
if (process.argv[2] === 'keys') {
  const cmd = process.argv[3];
  const resolvedEnv = resolveMarrowEnv();
  const API_KEY = cliArgs.apiKey || resolvedEnv.apiKey || '';
  if (!API_KEY) {
    process.stderr.write(`Error: MARROW_API_KEY required. ${resolvedEnv.exactFix}\n`);
    process.exit(1);
  }

  const getFlag = (name: string, short?: string): string | undefined => {
    const idx = process.argv.findIndex(a => a === `--${name}` || (short ? a === `-${short}` : false));
    return idx >= 0 ? process.argv[idx + 1] : undefined;
  };
  const getFlagList = (name: string): string[] => {
    const val = getFlag(name);
    return val ? val.split(',').map(s => s.trim()) : [];
  };

  const runCli = async () => {
    try {
      if (cmd === 'create') {
        const name = getFlag('name', 'n');
        if (!name) { process.stderr.write('Error: --name required\n'); process.exit(1); }
        const result = await marrowCreateKey(API_KEY, 'https://api.getmarrow.ai', {
          name,
          key_type: (getFlag('type', 't') || 'live') as 'live' | 'test',
          scopes: getFlagList('scopes') as any,
          agent_ids: getFlagList('agents'),
          expires_at: getFlag('expires'),
        }, undefined, undefined);
        process.stdout.write(JSON.stringify({ ...result, warning: formatKeyMaterialWarning() }, null, 2) + '\n');
      } else if (cmd === 'list') {
        const result = await marrowListKeys(API_KEY, 'https://api.getmarrow.ai', undefined, undefined);
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } else if (cmd === 'get') {
        const id = getFlag('id', 'i') || process.argv[4];
        if (!id) { process.stderr.write('Error: --id required\n'); process.exit(1); }
        const result = await marrowGetKey(API_KEY, 'https://api.getmarrow.ai', id, undefined, undefined);
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } else if (cmd === 'rotate') {
        const id = getFlag('id', 'i') || process.argv[4];
        if (!id) { process.stderr.write('Error: --id required\n'); process.exit(1); }
        const result = await marrowRotateKey(API_KEY, 'https://api.getmarrow.ai', id, undefined, undefined);
        process.stdout.write(JSON.stringify({ ...result, warning: formatKeyMaterialWarning() }, null, 2) + '\n');
      } else if (cmd === 'revoke') {
        const id = getFlag('id', 'i') || process.argv[4];
        if (!id) { process.stderr.write('Error: --id required\n'); process.exit(1); }
        const result = await marrowRevokeKey(API_KEY, 'https://api.getmarrow.ai', id, undefined, undefined);
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } else if (cmd === 'audit') {
        const limit = parseInt(getFlag('limit', 'l') || '20', 10);
        const result = await marrowGetKeyAudit(API_KEY, 'https://api.getmarrow.ai', { limit }, undefined, undefined);
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } else {
        process.stderr.write(`Usage: npx @getmarrow/mcp keys <create|list|get|rotate|revoke|audit> [options]\n\n`);
        process.stderr.write(`  create  --name <name> [--type live|test] [--scopes scope1,scope2] [--agents id1,id2] [--expires ISO]\n`);
        process.stderr.write(`  list\n`);
        process.stderr.write(`  get     --id <key-id>\n`);
        process.stderr.write(`  rotate  --id <key-id>\n`);
        process.stderr.write(`  revoke  --id <key-id>\n`);
        process.stderr.write(`  audit   [--limit <n>]\n`);
        process.stderr.write(`\nOptions: --key <api-key>\n`);
        process.exit(1);
      }
    } catch (e: any) {
      process.stderr.write(`Error: ${e.message || e}\n`);
      process.exit(1);
    }
  };
  void runCli().then(() => process.exit(0));
}

// Only start MCP server if not handling a CLI command
if (process.argv[2] !== 'keys') {

if (cliArgs.hook) {
  void runHookCommand();
} else if (cliArgs.contextHook) {
  void runContextHookCommand();
} else if (cliArgs.preActionHook) {
  void runPreActionHookCommand().catch(() => {
    process.stderr.write('Marrow pre-action governance failed closed. Retry after restoring the trusted configuration.\n');
    process.exitCode = 2;
  });
} else if (cliArgs.sessionHook) {
  void runSessionHookCommand();
} else if (cliArgs.spoolStatus) {
  void runSpoolCommand(false);
} else if (cliArgs.drainSpool) {
  void runSpoolCommand(true);
} else if (cliArgs.ping) {
  void runPingCommand();
} else if (cliArgs.setup) {
  runSetup();
} else {
const resolvedEnv = resolveMarrowEnv();
const API_KEY = cliArgs.apiKey || resolvedEnv.apiKey || '';

// [SECURITY #3] Validate BASE_URL — require HTTPS to prevent SSRF / credential leakage
const rawBaseUrl = resolvedEnv.baseUrl || 'https://api.getmarrow.ai';
const BASE_URL = validateBaseUrl(rawBaseUrl);

const SESSION_ID = resolvedEnv.sessionId || undefined;
// One identity must bind headers, bodies, queries, cache, and lifecycle events.
// resolveMarrowEnv already gives MARROW_FLEET_AGENT_ID precedence over MARROW_AGENT_ID.
// When no identity is configured, omit it and let the API resolve the key's
// bound agent instead of inventing a process-local identity that changes on restart.
const FLEET_AGENT_ID = resolvedEnv.agentId || undefined;
const AUTO_ENROLL = process.env.MARROW_AUTO_ENROLL !== 'false'; // on by default

if (!API_KEY) {
  process.stderr.write('Error: MARROW_API_KEY environment variable is required\n');
  process.stderr.write(`${resolvedEnv.exactFix}\n`);
  process.stderr.write('Usage: MARROW_API_KEY=mrw_yourkey npx @getmarrow/mcp\n');
  process.stderr.write('   or: npx @getmarrow/mcp --key mrw_yourkey\n');
  process.exit(1);
}

// [SECURITY #12] Warn if API key is visible in process args
if (cliArgs.apiKey) {
  process.stderr.write('[marrow] Warning: --key flag exposes API key in process list. Use MARROW_API_KEY env var for production.\n');
}

// Auto-orient on startup — cache warnings, inject into EVERY marrow_think response
let cachedOrientWarnings: Array<{ type: string; failureRate: number; message: string }> = [];
let thinkCallCount = 0;
let orientCallCount = 0;
let initialized = false;

function formatWarningActionably(w: { type: string; failureRate: number; message: string }): string {
  const pct = Math.round(w.failureRate * 100);
  return `⚠️ ${w.type} has ${pct}% failure rate — check what went wrong last time before proceeding`;
}

// [FIX #4] Log orient refresh failures instead of silently ignoring
async function refreshOrientWarnings(): Promise<void> {
  try {
    const r = await marrowOrient(API_KEY, BASE_URL, undefined, SESSION_ID, FLEET_AGENT_ID);
    cachedOrientWarnings = r.warnings;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`[marrow] Warning: failed to refresh orient warnings: ${msg}\n`);
  }
}

// Auto-commit tracking for session close
let lastDecisionId: string | null = null;
let lastCommitted = false;

// [FIX #5] Log auto-commit failures instead of silently ignoring; remove broken AbortController
async function autoCommitOnClose(): Promise<void> {
  if (lastDecisionId && !lastCommitted) {
    try {
      await marrowCommit(
        API_KEY,
        BASE_URL,
        {
          decision_id: lastDecisionId,
          success: false,
          outcome: 'Session ended without explicit commit',
        },
        SESSION_ID,
        FLEET_AGENT_ID
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`[marrow] Warning: auto-commit on close failed: ${msg}\n`);
    }
  }
}

// [FIX #10] Handle both SIGTERM and SIGINT for clean shutdown
async function gracefulShutdown(): Promise<void> {
  const forceExit = setTimeout(() => process.exit(0), 5000);
  forceExit.unref();
  await autoCommitOnClose();
  process.exit(0);
}

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

function send(response: unknown): void {
  process.stdout.write(JSON.stringify(response) + '\n');
}

function success(id: string | number, result: unknown): void {
  send({ jsonrpc: '2.0', id, result });
}

function error(id: string | number, code: number, message: string): void {
  send({ jsonrpc: '2.0', id, error: { code, message } });
}

function toolSuccess(id: string | number, value: unknown, isError = false): void {
  success(id, {
    content: [{ type: 'text', text: JSON.stringify(value, null, 2) }],
    ...(isError ? { isError: true } : {}),
  });
}

function toolFailure(toolName: string | undefined, failure: MarrowRequestError): Record<string, unknown> {
  const result = structuredRequestFailure(failure);
  const proofValidation = failure.code === 'proof_required';
  const infrastructureFailure = !proofValidation && !['authentication_required', 'permission_denied'].includes(failure.code);
  const supportsStale = ['marrow_agent_runtime', 'marrow_orient', 'marrow_ask', 'marrow_handoff_status', 'marrow_runtime_status', 'marrow_status'].includes(toolName || '');
  const spool = reportLifecycleSpool({ apiKey: API_KEY, baseUrl: BASE_URL, agentId: FLEET_AGENT_ID });
  result.failure_kind = proofValidation ? 'validation' : infrastructureFailure ? 'infrastructure' : 'authorization';
  result.control_path = controlPathStats(toolName || 'marrow_control');
  result.lifecycle_spool = {
    state: spool.failed > 0 || spool.pending > 0 ? spool.state : 'clear',
    pending: spool.pending,
    failed: spool.failed,
    exact_fix: spool.failed > 0 || spool.pending > 0 ? spool.exact_fix : null,
    drain_command: 'npx -y --package=@getmarrow/mcp@latest marrow-mcp drain-spool',
    legacy_namespaces: spool.other_namespaces?.count || 0,
  };
  result.host_capability = mcpHostCapability();
  if (proofValidation) {
    result.proof_required = true;
    result.exact_next_action = failure.exactFix;
  }
  if (infrastructureFailure && supportsStale) {
    let cached: { context: string; stale_ms: number } | null = null;
    try {
      cached = readGuidanceCache({ apiKey: API_KEY, baseUrl: BASE_URL, agentId: FLEET_AGENT_ID });
    } catch { /* owner-only cache is best effort */ }
    result.stale_brief = cached?.context || [
      '## Marrow control-path outage brief',
      '- This is an infrastructure failure; Marrow returned no policy decision and did not deny the action.',
      '- Preserve local evidence and continue only low-risk, reversible work under the owner\'s existing safeguards.',
      '- Do not perform high-risk work until a fresh Marrow runtime gate returns allow, warn, review_required, or block.',
    ].join('\n');
    result.stale_source = cached ? 'last_known_guidance' : 'local_outage_safety';
    result.stale_ms = cached?.stale_ms ?? null;
    result.authorization_state = 'unavailable';
    result.gate_obtained = false;
    result.stale_can_authorize_high_risk = false;
    const retryAfterMs = failure.retryAfterMs;
    result.exact_next_action = cached
      ? 'Use this last-known brief for low-risk context only. Obtain a fresh Marrow runtime gate before high-risk work.'
      : retryAfterMs != null
        ? `Wait ${retryAfterMs} ms, then retry once. Do not perform high-risk work without a fresh Marrow runtime gate.`
        : failure.exactFix;
  }
  return result;
}

function mcpHostCapability() {
  return resolveHostCapability({
    hostLabel: process.env.MARROW_CLIENT || process.env.MARROW_HARNESS || process.env.MARROW_AGENT_CLIENT,
  });
}

function clientOperationalPayload(toolName: string, value: unknown): Record<string, unknown> {
  const payload = value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : { data: value };
  const spool = reportLifecycleSpool({ apiKey: API_KEY, baseUrl: BASE_URL, agentId: FLEET_AGENT_ID });
  const habitLoopCopy = formatHabitLoopCopy(payload) || formatHabitLoopCopy(payload.data);
  return {
    ...payload,
    ...(habitLoopCopy ? { habit_loop_copy: habitLoopCopy } : {}),
    host_capability: payload.host_capability || mcpHostCapability(),
    client_update: payload.client_update
      || (payload.data && typeof payload.data === 'object' && !Array.isArray(payload.data)
        ? (payload.data as Record<string, unknown>).client_update
        : null)
      || localClientUpdate(),
    control_path: controlPathStats(toolName),
    local_control: localControlEvidence(Boolean(API_KEY)),
    lifecycle_spool: {
      state: spool.failed > 0 || spool.pending > 0 ? spool.state : 'clear',
      pending: spool.pending,
      failed: spool.failed,
      exact_fix: spool.failed > 0 || spool.pending > 0 ? spool.exact_fix : null,
      drain_command: 'npx -y --package=@getmarrow/mcp@latest marrow-mcp drain-spool',
      legacy_namespaces: spool.other_namespaces?.count || 0,
    },
    mcp_tool_profile: mcpToolProfileStatus(payload),
  };
}

// [FIX #9] Runtime validation helper for required string params
function requireString(args: Record<string, unknown>, name: string): string {
  const val = args[name];
  if (typeof val !== 'string' || !val.trim()) {
    throw new Error(`"${name}" is required and must be a non-empty string`);
  }
  return val;
}

function requireBoolean(args: Record<string, unknown>, name: string): boolean {
  const value = args[name];
  if (typeof value !== 'boolean') throw new Error(`"${name}" is required and must be boolean`);
  return value;
}

const HIGH_RISK_ACTION = /\b(?:billing|credential|database|delete|deploy|destructive|financial|key|merge|migrat(?:e|ion)|payment|production|publish|release|remove|rollback|secret|security|token|truncate|wipe)\b/i;

function isHighRiskAction(action: unknown, type: unknown): boolean {
  return HIGH_RISK_ACTION.test(`${String(type || '')} ${String(action || '')}`);
}

async function withControlDeadline<T>(
  operation: (signal: AbortSignal) => Promise<T>,
  options: { highRisk?: boolean; cacheAware?: boolean; toolName?: string } = {},
): Promise<T> {
  const toolName = options.toolName || 'marrow_control';
  const configuredTimeoutMs = Number(process.env.MARROW_REQUEST_TIMEOUT_MS);
  const runtimeBudget = toolName === 'marrow_agent_runtime' || toolName === 'marrow_auto.runtime';
  const commitBudget = toolName === 'marrow_commit';
  const timeoutMs = Number.isFinite(configuredTimeoutMs)
    ? Math.min(10_000, Math.max(150, Math.floor(configuredTimeoutMs)))
    : commitBudget ? 8_000 : options.highRisk || runtimeBudget ? 4_500 : 4_000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  timer.unref?.();
  const startedAt = Date.now();
  try {
    const result = await operation(controller.signal);
    recordControlPathSample(toolName, Date.now() - startedAt, true);
    return result;
  } catch (error) {
    recordControlPathSample(toolName, Date.now() - startedAt, false);
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function storeRuntimeGuidance(runtime: unknown): void {
  try {
    writeGuidanceCache({
      apiKey: API_KEY,
      baseUrl: BASE_URL,
      agentId: FLEET_AGENT_ID,
      context: compactRuntimeContext(runtime as Parameters<typeof compactRuntimeContext>[0]),
    });
  } catch { /* owner-only cache is best effort */ }
}

function storeLastKnownStatus(status: unknown, source: 'runtime' | 'status'): void {
  try {
    writeStatusCache({
      apiKey: API_KEY,
      baseUrl: BASE_URL,
      agentId: FLEET_AGENT_ID,
      status,
      source,
    });
  } catch { /* owner-only cache is best effort */ }
}

function refreshStatusInBackground(): void {
  void marrowStatus(API_KEY, BASE_URL, SESSION_ID, FLEET_AGENT_ID)
    .then((status) => storeLastKnownStatus(status, 'status'))
    .catch(() => undefined);
}

// [FIX #6 & #7] Safe JSON response helper for memory API functions
async function safeMemoryResponse(res: Response): Promise<any> {
  if (!res.ok) {
    let detail = '';
    try { detail = await res.text(); } catch { /* ignore */ }
    throw new Error(`API error ${res.status}: ${detail.slice(0, 200)}`);
  }
  const json: any = await res.json();
  if (json.error) {
    throw new Error(json.error);
  }
  return json;
}

// Memory API functions — all patched with safeMemoryResponse and validatePathParam
async function marrowListMemories(
  apiKey: string,
  baseUrl: string,
  params?: { status?: string; query?: string; limit?: number; agentId?: string },
  sessionId?: string
): Promise<MarrowMemory[]> {
  const qs = new URLSearchParams();
  if (params?.status) qs.set('status', params.status);
  if (params?.query) qs.set('query', params.query);
  if (params?.limit) qs.set('limit', String(params.limit));
  if (params?.agentId) qs.set('agent_id', params.agentId);

  const res = await fetch(`${baseUrl}/v1/memories?${qs.toString()}`, {
    headers: {
      Authorization: `Bearer ${apiKey}`,
      ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
    },
  });
  const json = await safeMemoryResponse(res);
  return json.data?.memories || [];
}

async function marrowGetMemory(
  apiKey: string,
  baseUrl: string,
  id: string,
  sessionId?: string
): Promise<MarrowMemory | null> {
  const safeId = validatePathParam(id, 'id');
  const res = await fetch(`${baseUrl}/v1/memories/${safeId}`, {
    headers: {
      Authorization: `Bearer ${apiKey}`,
      ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
    },
  });
  const json = await safeMemoryResponse(res);
  return json.data?.memory || null;
}

async function marrowUpdateMemory(
  apiKey: string,
  baseUrl: string,
  id: string,
  patch: { text?: string; source?: string | null; tags?: string[]; actor?: string; note?: string },
  sessionId?: string
): Promise<MarrowMemory> {
  const safeId = validatePathParam(id, 'id');
  const res = await fetch(`${baseUrl}/v1/memories/${safeId}`, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
    },
    body: JSON.stringify(patch),
  });
  const json = await safeMemoryResponse(res);
  return json.data?.memory;
}

async function marrowDeleteMemory(
  apiKey: string,
  baseUrl: string,
  id: string,
  meta?: { actor?: string; note?: string },
  sessionId?: string
): Promise<MarrowMemory> {
  const safeId = validatePathParam(id, 'id');
  const res = await fetch(`${baseUrl}/v1/memories/${safeId}`, {
    method: 'DELETE',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
    },
    body: JSON.stringify(meta || {}),
  });
  const json = await safeMemoryResponse(res);
  return json.data?.memory;
}

async function marrowMarkOutdated(
  apiKey: string,
  baseUrl: string,
  id: string,
  meta?: { actor?: string; note?: string },
  sessionId?: string
): Promise<MarrowMemory> {
  const safeId = validatePathParam(id, 'id');
  const res = await fetch(`${baseUrl}/v1/memories/${safeId}/outdated`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
    },
    body: JSON.stringify(meta || {}),
  });
  const json = await safeMemoryResponse(res);
  return json.data?.memory;
}

async function marrowSupersedeMemory(
  apiKey: string,
  baseUrl: string,
  id: string,
  replacement: { text: string; source?: string; tags?: string[]; actor?: string; note?: string },
  sessionId?: string
): Promise<{ old: MarrowMemory; replacement: MarrowMemory }> {
  const safeId = validatePathParam(id, 'id');
  const res = await fetch(`${baseUrl}/v1/memories/${safeId}/supersede`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
    },
    body: JSON.stringify(replacement),
  });
  const json = await safeMemoryResponse(res);
  return json.data;
}

async function marrowShareMemory(
  apiKey: string,
  baseUrl: string,
  id: string,
  agentIds: string[],
  actor?: string,
  sessionId?: string
): Promise<MarrowMemory> {
  const safeId = validatePathParam(id, 'id');
  const res = await fetch(`${baseUrl}/v1/memories/${safeId}/share`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
    },
    body: JSON.stringify({ agent_ids: agentIds, actor }),
  });
  const json = await safeMemoryResponse(res);
  return json.data?.memory;
}

async function marrowExportMemories(
  apiKey: string,
  baseUrl: string,
  params?: { format?: string; status?: string; tags?: string },
  sessionId?: string
): Promise<{ exported_at: string; account_id: string; count: number; memories: MarrowMemory[] }> {
  const qs = new URLSearchParams();
  if (params?.format) qs.set('format', params.format);
  if (params?.status) qs.set('status', params.status);
  if (params?.tags) qs.set('tags', params.tags);

  const res = await fetch(`${baseUrl}/v1/memories/export?${qs.toString()}`, {
    headers: {
      Authorization: `Bearer ${apiKey}`,
      ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
    },
  });
  const json = await safeMemoryResponse(res);
  return json.data;
}

async function marrowImportMemories(
  apiKey: string,
  baseUrl: string,
  memories: Array<{ text: string; source?: string; tags?: string[] }>,
  mode: 'merge' | 'replace',
  sessionId?: string
): Promise<{ imported: number; skipped: number; errors: string[] }> {
  const res = await fetch(`${baseUrl}/v1/memories/import`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
    },
    body: JSON.stringify({ memories, mode }),
  });
  const json = await safeMemoryResponse(res);
  return json.data;
}

async function marrowRetrieveMemories(
  apiKey: string,
  baseUrl: string,
  query: string,
  params?: { limit?: number; from?: string; to?: string; tags?: string; source?: string; status?: string; shared?: boolean },
  sessionId?: string
): Promise<{ memories: MarrowMemory[]; query: string; count: number }> {
  const qs = new URLSearchParams();
  qs.set('q', query);
  if (params?.limit) qs.set('limit', String(params.limit));
  if (params?.from) qs.set('from', params.from);
  if (params?.to) qs.set('to', params.to);
  if (params?.tags) qs.set('tags', params.tags);
  if (params?.source) qs.set('source', params.source);
  if (params?.status) qs.set('status', params.status);
  if (params?.shared !== undefined) qs.set('shared', String(params.shared));

  const res = await fetch(`${baseUrl}/v1/memories/retrieve?${qs.toString()}`, {
    headers: {
      Authorization: `Bearer ${apiKey}`,
      ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
    },
  });
  const json = await safeMemoryResponse(res);
  return json.data;
}

// Tool definitions (unchanged)
const TOOLS = [
  {
    name: 'marrow_orient',
    description:
      'Call at session start or before meaningful work. ' +
      'Returns authorized prior lessons and failure warnings for the current account or agent. ' +
      'If shouldPause=true, stop and review the lesson before acting. ' +
      'Use marrow_agent_runtime for the policy gate before a consequential side effect.',
    inputSchema: {
      type: 'object',
      properties: {
        taskType: {
          type: 'string',
          enum: ['implementation', 'security', 'architecture', 'process', 'general'],
          description:
            'Optional: filter warnings to a specific task type you are about to perform',
        },
        autoWarn: {
          type: 'boolean',
          description:
            'Enable active intervention: scans recent failures, returns HIGH/MEDIUM/LOW severity warnings with recommendations. Recommended: true.',
        },
      },
      required: [],
    },
  },
  {
    name: 'marrow_think',
    description:
      'Record intent and retrieve authorized governance intelligence before acting. ' +
      'Returns a decision_id for outcome closure plus relevant patterns, prior outcomes, and recommendedNext. ' +
      'Pass previous_outcome to auto-commit the last decision and open a new one. ' +
      'Response MAY include: onboarding_hint (new accounts), intelligence.collective (cross-account patterns), intelligence.team_context (recent decisions from other sessions).',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', description: 'What the agent is about to do' },
        type: {
          type: 'string',
          enum: ['implementation', 'security', 'architecture', 'process', 'general'],
          description: 'Type of action (default: general)',
        },
        context: { type: 'object', description: 'Optional metadata about the current situation' },
        previous_decision_id: { type: 'string', description: 'decision_id from previous think() call — auto-commits that session' },
        previous_success: { type: 'boolean', description: 'Did the previous action succeed?' },
        previous_outcome: { type: 'string', description: 'What happened in the previous action (required if previous_decision_id provided)' },
        checkLoop: { type: 'boolean', description: 'Enable loop detection: warns if you are about to retry a failed approach. Recommended: true.' },
        source_kind: {
          type: 'string',
          enum: ['human_directed', 'agent_autonomous', 'scheduled', 'integration', 'system', 'unknown'],
          description: 'Optional provenance source. Defaults to agent_autonomous for MCP calls.',
        },
        human_directed: { type: 'boolean', description: 'True only when the action is directly requested by the owner/user.' },
        instruction_ref: { type: 'string', description: 'Optional privacy-safe opaque reference. Dates, long digit runs, provider IDs, addresses, and domains are rejected locally; valid values are preserved exactly.' },
        source_meta: { type: 'object', description: 'Optional provenance metadata. PII and raw provider IDs are rejected by the API.' },
      },
      required: ['action'],
    },
  },
  {
    name: 'marrow_commit',
    description:
      'Close a recorded action with success/failure, a specific outcome, and required proof. ' +
      'decision_id comes from marrow_think, marrow_auto, or an arbitration runtime that actually created a decision. ' +
      'Use the gate receipt from marrow_agent_runtime for consequential work. ' +
      'The exact non-authorizing outcome_observation_only runtime correlation may submit an observed_unverified result, but is never sent as receipt evidence and never authorizes action or trusted learning. ' +
      'Only committed:true closes trusted outcome learning.',
    inputSchema: {
      type: 'object',
      properties: {
        decision_id: { type: 'string', description: 'decision_id from marrow_think, marrow_auto, or an arbitration runtime that created a decision' },
        success: { type: 'boolean', description: 'Did the action succeed?' },
        outcome: { type: 'string', description: 'What happened — be specific, this trains the hive' },
        caused_by: { type: 'string', description: 'Optional: what caused this action' },
        proof: {
          type: 'object',
          description: 'Optional required proof pack for gated work: summary, checks, outcome, blockers, commits_prs_shas, rollback_target, handoff_result_file, deployment_and_smoke.',
        },
        gate_receipt_id: { type: 'string', description: 'Canonical receipt id from marrow_agent_runtime.runtime_authorization.id for risky work.' },
        arbitration_receipt_id: { type: 'string', description: 'Required for arbitrated work: use marrow_arbitrate.arbitration.receipt_id from the same runtime response.' },
        owner_approval_receipt_id: { type: 'string', description: 'Single-use owner approval receipt issued by authenticated dashboard review for review_required arbitration.' },
        action: { type: 'string', description: 'Optional original action. If provided and gate_receipt_id is omitted, MCP can fetch a matching runtime gate receipt before commit.' },
        type: { type: 'string', description: 'Optional original action type for auto gate lookup, e.g. deploy, publish, merge, handoff, implementation.' },
        surfaces: { type: 'array', items: { type: 'string' }, description: 'Optional surfaces for auto gate receipt, e.g. github, cloudflare, npm, production.' },
        auto_gate: { type: 'boolean', description: 'If true/default and action is provided, fetch runtime truth bound to this existing decision. Authorizing receipts preserve normal closure; exact outcome_observation_only correlation can submit only an observed_unverified result and is omitted from receipt evidence.' },
        model_usage: { type: 'object', description: 'Optional compact token/cost/latency counts. Do not include raw prompts or completions.' },
      },
      required: ['decision_id', 'success', 'outcome'],
    },
  },
  {
    name: 'marrow_model_usage',
    description:
      'Record compact model token usage for value proof. Use when the harness exposes provider/model token counts. Do not send raw prompts, completions, tool logs, secrets, or customer content.',
    inputSchema: {
      type: 'object',
      properties: {
        provider: { type: 'string', description: 'Model provider, e.g. openai, anthropic, google, xai, qwen, deepseek.' },
        model: { type: 'string', description: 'Model name.' },
        input_tokens: { type: 'number' },
        output_tokens: { type: 'number' },
        cached_tokens: { type: 'number' },
        total_tokens: { type: 'number' },
        cost_usd: { type: 'number' },
        latency_ms: { type: 'number' },
        task_type: { type: 'string' },
        action_type: { type: 'string' },
        marrow_intervention: { type: 'string', description: 'runtime_gate, risk_gate, prior_lesson, proof_pack, before_you_act, fleet_lesson, or other compact reason.' },
        estimated_tokens_saved: { type: 'number' },
        estimated_cost_saved_usd: { type: 'number' },
        estimated_minutes_saved: { type: 'number' },
        decision_id: { type: 'string' },
        workflow_id: { type: 'string' },
        success: { type: 'boolean' },
      },
      required: [],
    },
  },
  {
    name: 'marrow_run',
    description:
      'Governed outcome capture. Records intent, obtains a gate for risky work, and closes only with an explicit measured result.',
    inputSchema: {
      type: 'object',
      properties: {
        description: { type: 'string', description: 'What the agent did' },
        success: { type: 'boolean', description: 'Whether it succeeded' },
        outcome: { type: 'string', description: 'One-line summary of what happened' },
        type: {
          type: 'string',
          enum: ['implementation', 'security', 'architecture', 'process', 'general'],
          description: 'Type of action (default: general)',
        },
        proof: { type: 'object', description: 'Measured evidence required to close high-risk work.' },
        gate_receipt_id: { type: 'string', description: 'Fresh receipt returned by marrow_agent_runtime.' },
      },
      required: ['description', 'success', 'outcome'],
    },
  },
  {
    name: 'marrow_auto',
    description:
      'Durably capture low-risk activity. One outer invocation normally completes in-band within the bounded client budget; a deadline continuation reuses the same operation_id and never opens a second decision. Outcomes remain pending unless success is explicit; risky completion still requires a fresh gate and measured proof.',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', description: 'What you are about to do or just did' },
        outcome: { type: 'string', description: 'What happened (if already done). Omit to log intent only.' },
        success: { type: 'boolean', description: 'Measured result. Omit when the outcome is not yet proven.' },
        type: {
          type: 'string',
          enum: ['implementation', 'security', 'architecture', 'process', 'general'],
          description: 'Type of action (default: general)',
        },
        proof: { type: 'object', description: 'Measured completion evidence for gated work.' },
        gate_receipt_id: { type: 'string', description: 'Fresh receipt returned by marrow_agent_runtime.' },
        arbitration_receipt_id: { type: 'string', description: 'For arbitrated work, the arbitration receipt returned by the same server-side review flow.' },
        owner_approval_receipt_id: { type: 'string', description: 'Short-lived, single-use receipt issued by authenticated dashboard owner approval. Chat text is not an approval receipt.' },
        operation_id: {
          type: 'string',
          description: 'Opaque 8-80 character resume token. Reuse it only with the original tenant, action, context, and surfaces; proof may be added after proof_required.',
        },
      },
      required: ['action'],
    },
  },
  {
    name: 'marrow_ask',
    description:
      'Query the collective hive in plain English. ' +
      'Ask about failure patterns, what worked, what broke, or get a recommendation before acting. ' +
      'Returns direct answer + supporting evidence.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Plain English question about your decision history' },
      },
      required: ['query'],
    },
  },
  {
    name: 'marrow_status',
    description: 'Check Marrow platform health and status.',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  {
    name: 'marrow_create_key',
    description: 'Create a new API key. Full plaintext key is returned once — copy it now.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Human-readable key name' },
        key_type: { type: 'string', enum: ['live', 'test'], description: 'Key type (default: live)' },
        scopes: { type: 'array', items: { type: 'string' }, description: 'Allowed scopes' },
        agent_ids: { type: 'array', items: { type: 'string' }, description: 'Optional agent bindings' },
        expires_at: { type: 'string', description: 'Optional ISO-8601 expiry' },
      },
      required: ['name'],
    },
  },
  {
    name: 'marrow_list_keys',
    description: 'List API keys. Keys are masked here by design.',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  {
    name: 'marrow_get_key',
    description: 'Get a single API key by ID. The key value is masked after creation.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'API key ID' },
      },
      required: ['id'],
    },
  },
  {
    name: 'marrow_revoke_key',
    description: 'Revoke an API key by ID.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'API key ID' },
      },
      required: ['id'],
    },
  },
  {
    name: 'marrow_rotate_key',
    description: 'Rotate an API key by ID. Full plaintext key is returned once — copy it now.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'API key ID' },
      },
      required: ['id'],
    },
  },
  {
    name: 'marrow_list_memories',
    description: 'List memories with optional filters (status, query, limit, agent_id for shared memories).',
    inputSchema: {
      type: 'object',
      properties: {
        status: { type: 'string', enum: ['active', 'outdated', 'deleted'], description: 'Filter by status' },
        query: { type: 'string', description: 'Search query' },
        limit: { type: 'number', description: 'Max results (default: 20)' },
        agentId: { type: 'string', description: 'Agent ID for shared memories' },
      },
      required: [],
    },
  },
  {
    name: 'marrow_get_memory',
    description: 'Get a single memory by ID.',
    inputSchema: { type: 'object', properties: { id: { type: 'string', description: 'Memory ID' } }, required: ['id'] },
  },
  {
    name: 'marrow_update_memory',
    description: 'Update memory text, tags, or metadata.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Memory ID' },
        text: { type: 'string', description: 'New text' },
        source: { type: 'string', description: 'Source' },
        tags: { type: 'array', items: { type: 'string' }, description: 'Tags' },
        actor: { type: 'string', description: 'Actor name' },
        note: { type: 'string', description: 'Audit note' },
      },
      required: ['id'],
    },
  },
  {
    name: 'marrow_delete_memory',
    description: 'Soft delete a memory.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Memory ID' },
        actor: { type: 'string', description: 'Actor name' },
        note: { type: 'string', description: 'Audit note' },
      },
      required: ['id'],
    },
  },
  {
    name: 'marrow_mark_outdated',
    description: 'Mark a memory as outdated.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Memory ID' },
        actor: { type: 'string', description: 'Actor name' },
        note: { type: 'string', description: 'Audit note' },
      },
      required: ['id'],
    },
  },
  {
    name: 'marrow_supersede_memory',
    description: 'Atomically replace a memory with a new version.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Memory ID to supersede' },
        text: { type: 'string', description: 'New memory text' },
        source: { type: 'string', description: 'Source' },
        tags: { type: 'array', items: { type: 'string' }, description: 'Tags' },
        actor: { type: 'string', description: 'Actor name' },
        note: { type: 'string', description: 'Audit note' },
      },
      required: ['id', 'text'],
    },
  },
  {
    name: 'marrow_share_memory',
    description: 'Share a memory with specific agents.',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Memory ID' },
        agentIds: { type: 'array', items: { type: 'string' }, description: 'Agent IDs to share with' },
        actor: { type: 'string', description: 'Actor name' },
      },
      required: ['id', 'agentIds'],
    },
  },
  {
    name: 'marrow_export_memories',
    description: 'Export memories to JSON or CSV.',
    inputSchema: {
      type: 'object',
      properties: {
        format: { type: 'string', enum: ['json', 'csv'], description: 'Export format' },
        status: { type: 'string', enum: ['active', 'all'], description: 'Filter by status' },
        tags: { type: 'string', description: 'Comma-separated tags' },
      },
      required: [],
    },
  },
  {
    name: 'marrow_import_memories',
    description: 'Import memories with merge (dedup) or replace mode.',
    inputSchema: {
      type: 'object',
      properties: {
        memories: { type: 'array', items: { type: 'object', properties: { text: { type: 'string' }, source: { type: 'string' }, tags: { type: 'array', items: { type: 'string' } } } }, description: 'Memories to import' },
        mode: { type: 'string', enum: ['merge', 'replace'], description: 'Import mode' },
      },
      required: ['memories', 'mode'],
    },
  },
  {
    name: 'marrow_retrieve_memories',
    description: 'Full-text search memories with filters (from, to, tags, source, status, shared).',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Search query' },
        limit: { type: 'number', description: 'Max results' },
        from: { type: 'string', description: 'From date (ISO-8601)' },
        to: { type: 'string', description: 'To date (ISO-8601)' },
        tags: { type: 'string', description: 'Comma-separated tags' },
        source: { type: 'string', description: 'Source filter' },
        status: { type: 'string', enum: ['active', 'outdated', 'deleted'], description: 'Status filter' },
        shared: { type: 'boolean', description: 'Include shared memories' },
      },
      required: ['query'],
    },
  },
  {
    name: 'marrow_workflow',
    description:
      'Interact with Marrow Workflow Registry. Register, start, and advance multi-step workflows. ' +
      'Actions: register (create workflow template), list (show all), get (details), start (begin instance), ' +
      'advance (complete a step), instances (list runs).',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', enum: ['register', 'list', 'get', 'update', 'start', 'advance', 'instances'], description: 'Workflow action to perform' },
        workflowId: { type: 'string', description: 'Workflow ID (required for get/start/advance/instances)' },
        instanceId: { type: 'string', description: 'Instance ID (required for advance)' },
        name: { type: 'string', description: 'Workflow name (for register)' },
        description: { type: 'string', description: 'Workflow description (for register/update)' },
        steps: { type: 'array', description: 'Step definitions (for register)', items: { type: 'object', properties: { step: { type: 'number', description: 'Step order (1, 2, 3...)' }, agent_role: { type: 'string', description: 'Expected agent role (e.g., "builder", "auditor")' }, action_type: { type: 'string', description: 'Action type (e.g., "build", "audit", "patch")' }, description: { type: 'string', description: 'Step description' } }, required: ['step', 'description'] } },
        tags: { type: 'array', items: { type: 'string' }, description: 'Tags (for register)' },
        agentId: { type: 'string', description: 'Agent ID starting the workflow (for start)' },
        context: { type: 'object', description: 'Workflow context (for start)' },
        inputs: { type: 'object', description: 'Workflow inputs (for start)' },
        stepCompleted: { type: 'number', description: 'Step number completed (for advance)' },
        outcome: { type: 'string', description: 'Step outcome (for advance)' },
        nextAgentId: { type: 'string', description: 'Next agent for the following step (for advance)' },
        contextUpdate: { type: 'object', description: 'Context changes (for advance)' },
        status: { type: 'string', enum: ['running', 'completed', 'failed', 'cancelled', 'active', 'archived'], description: 'Filter by status (for list/instances)' },
      },
      required: ['action'],
    },
  },
  {
    name: 'marrow_dashboard',
    description:
      'Get operator dashboard — account health, top failures, workflow status, recent activity, Marrow\'s saves metric. ' +
      'One call returns everything an operator needs to see.',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  {
    name: 'marrow_digest',
    description:
      'Get periodic summary of agent activity and Marrow impact (default 7-day period). ' +
      'Shows decision counts, success rate trend vs previous period, saves, top improvements and risks.',
    inputSchema: {
      type: 'object',
      properties: {
        period: { type: 'string', description: 'Time period: 7d (default), 14d, or 30d' },
      },
      required: [],
    },
  },
  {
    name: 'marrow_agent_status',
    description:
      'Check whether Marrow is passively active for this agent or fleet. ' +
      'Returns connected state, signal quality, non-sensitive proof, and next actions. ' +
      'Use at session start or before owner reporting to prove Marrow is working without a dashboard.',
    inputSchema: {
      type: 'object',
      properties: {
        period: { type: 'string', description: 'Time period: 7d (default), 14d, or 30d' },
        agentId: { type: 'string', description: 'Optional agent_id/session_id filter. Defaults to the canonical fleet-bound agent identity.' },
      },
      required: [],
    },
  },
  {
    name: 'marrow_runtime_status',
    description:
      'Read live Marrow runtime hook diagnostics from /v1/agent/status. ' +
      'Use this when an agent needs exact passive hook, token-capture, outcome-closure, client-update, and repair-command status.',
    inputSchema: {
      type: 'object',
      properties: {
        fast: { type: 'boolean', description: 'Use fast cached summary path when available. Defaults to true.' },
      },
      required: [],
    },
  },
  {
    name: 'marrow_value_report',
    description:
      'Get owner-ready proof of Marrow value for this agent or fleet. ' +
      'Returns summary, decision metrics, saves, active agents, top risks, recommendations, and improvement data without raw decision text.',
    inputSchema: {
      type: 'object',
      properties: {
        period: { type: 'string', description: 'Time period: 7d (default), 14d, 30d, or a day count up to 90.' },
        agentId: { type: 'string', description: 'Optional agent_id/session_id filter. Defaults to the canonical fleet-bound agent identity.' },
      },
      required: [],
    },
  },
  {
    name: 'marrow_decision_brief',
    description:
      'One pre-action call before meaningful or risky work. Returns risk level, workflow/playbook steps, ' +
      'handoff requirements, freshness/source-of-truth checks, minimum verification checks, proof-pack fields, ' +
      'and next actions. Use this before deploys, publishes, merges, audits, patches, secret changes, or production work.',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', description: 'What the agent is about to do.' },
        type: { type: 'string', description: 'Decision type, e.g. deploy, audit, patch, review.' },
        role: { type: 'string', description: 'Agent role/playbook: deploy, audit, patch, review, or general.' },
        agentId: { type: 'string', description: 'Optional agent_id filter. Defaults to the canonical fleet-bound agent identity.' },
        sessionId: { type: 'string', description: 'Optional session id. Defaults to MARROW_SESSION_ID.' },
        surfaces: {
          type: 'array',
          items: { type: 'string' },
          description: 'Surfaces to keep current, e.g. github, npm, docs, production, secrets.',
        },
        period: { type: 'number', description: 'Lookback period in days, default 7, max 90.' },
      },
      required: ['action'],
    },
  },
  {
    name: 'marrow_first_value',
    description:
      'First-run Marrow value proof. Returns what is captured, whether outcome closure/runtime gate are active, ' +
      'a plain-English first useful lesson, and a five-minute try-this-now prompt for agents and owners.',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', description: 'Optional action to test. Defaults to a production deploy safety prompt.' },
        type: { type: 'string', description: 'Decision type, e.g. deploy, audit, patch, review.' },
        role: { type: 'string', description: 'Agent role/playbook: deploy, audit, patch, review, or general.' },
        agentId: { type: 'string', description: 'Optional agent_id filter. Defaults to the canonical fleet-bound agent identity.' },
        sessionId: { type: 'string', description: 'Optional session id. Defaults to MARROW_SESSION_ID.' },
        surfaces: { type: 'array', items: { type: 'string' }, description: 'Surfaces to test, e.g. production, deploy, github, npm.' },
        context: { type: 'object', description: 'Optional non-sensitive metadata.' },
        proof: { type: 'object', description: 'Optional proof fields already collected.' },
      },
      required: [],
    },
  },
  {
    name: 'marrow_agent_runtime',
    description:
      'One-call agent-native Marrow loop. Returns passive status, decision brief, risk gate, relevant lessons, ' +
      'template suggestion, required proof pack, before-you-act instruction, and exact next action. ' +
      'Its runtime_authorization is the authoritative gate receipt; it returns decision_id only when runtime actually creates a decision. ' +
      'Use marrow_auto or marrow_think to create the decision_id required for outcome closure. ' +
      'Use this before meaningful work when you want Marrow to guide the whole action in one call.',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', description: 'What the agent is about to do.' },
        type: { type: 'string', description: 'Decision type, e.g. deploy, audit, patch, review.' },
        role: { type: 'string', description: 'Agent role/playbook: deploy, audit, patch, review, or general.' },
        agentId: { type: 'string', description: 'Optional agent_id filter. Defaults to the canonical fleet-bound agent identity.' },
        sessionId: { type: 'string', description: 'Optional session id. Defaults to MARROW_SESSION_ID.' },
        surfaces: {
          type: 'array',
          items: { type: 'string' },
          description: 'Surfaces to keep current, e.g. github, npm, docs, production, secrets.',
        },
        context: { type: 'object', description: 'Optional non-sensitive metadata.' },
        proof: { type: 'object', description: 'Optional proof fields already collected, such as checks, rollback_target, smoke_result.' },
        period: { type: 'number', description: 'Lookback period in days, default 7, max 90.' },
      },
      required: ['action'],
    },
  },
  {
    name: 'marrow_arbitrate',
    description:
      'Resolve conflicting next-step proposals from two or more tenant agents before execution. ' +
      'Uses the existing Marrow runtime gate and returns a durable arbitration receipt with the selected, ' +
      'synthesized, review-required, or blocked action and exactly why it changed.',
    inputSchema: {
      type: 'object',
      properties: {
        objective: { type: 'string', description: 'The shared owner or workflow objective.' },
        ownerIntent: { type: 'string', description: 'Optional bounded owner intent used for deterministic alignment.' },
        conflictType: {
          type: 'string',
          enum: ['action_conflict', 'policy_conflict', 'evidence_conflict', 'authority_conflict', 'risk_conflict'],
        },
        proposals: {
          type: 'array',
          minItems: 2,
          maxItems: 8,
          items: {
            type: 'object',
            properties: {
              proposal_id: { type: 'string', description: 'Stable opaque proposal id.' },
              agent_id: { type: 'string', description: 'Existing agent id in this Marrow account.' },
              action: { type: 'string', description: 'Proposed next action.' },
              rationale: { type: 'string', description: 'Optional concise rationale; redacted before transport.' },
              confidence: { type: 'number', minimum: 0, maximum: 1 },
              risk_level: { type: 'string', enum: ['low', 'medium', 'high'] },
              requires_owner_approval: { type: 'boolean' },
              evidence: {
                type: 'array',
                maxItems: 8,
                items: {
                  type: 'object',
                  properties: {
                    kind: { type: 'string' },
                    reference: { type: 'string', description: 'Opaque identifier only; no URL, path, or raw evidence.' },
                  },
                  required: ['kind', 'reference'],
                },
              },
            },
            required: ['proposal_id', 'agent_id', 'action'],
          },
        },
        action: { type: 'string', description: 'Optional runtime action label.' },
        type: { type: 'string', description: 'Optional runtime action type. Defaults to coordination.' },
        agentId: { type: 'string', description: 'Requesting agent id. Defaults to the canonical fleet-bound agent identity.' },
        sessionId: { type: 'string', description: 'Optional workflow session id.' },
        surfaces: { type: 'array', items: { type: 'string' } },
        context: { type: 'object', description: 'Optional non-sensitive runtime metadata.' },
        proof: { type: 'object', description: 'Optional proof already available to the runtime gate.' },
      },
      required: ['objective', 'proposals'],
    },
  },
  {
    name: 'marrow_coordinate',
    description:
      'Coordinate tenant agents without sharing transcripts. Acquire or release a bounded resource lease, ' +
      'list current leases, or create/list compact evidence-backed child proof packets for a parent agent.',
    inputSchema: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['list_leases', 'acquire_lease', 'release_lease', 'list_proof_packets', 'create_proof_packet'],
        },
        resource_type: { type: 'string', enum: ['file', 'directory', 'service', 'workflow', 'deployment', 'custom'] },
        resource: { type: 'string', maxLength: 160, description: 'Bounded tenant-visible resource label. Do not send secrets.' },
        workflow_id: { type: 'string' },
        ttl_seconds: { type: 'number', minimum: 30, maximum: 3600 },
        lease_id: { type: 'string' },
        lease_token: { type: 'string', description: 'One-time lease capability returned by acquire_lease.' },
        status: { type: 'string', enum: ['active', 'released', 'expired', 'incomplete', 'complete', 'failed'] },
        limit: { type: 'number', minimum: 1, maximum: 100 },
        decision_id: { type: 'string' },
        proof_pack_id: { type: 'string' },
        summary: { type: 'string', maxLength: 280, description: 'Compact result summary; no raw transcript.' },
        evidence_refs: {
          type: 'array', maxItems: 20, items: { type: 'string' },
          description: 'Opaque durable evidence identifiers only.',
        },
      },
      required: ['action'],
    },
  },
  {
    name: 'marrow_replay_compare',
    description:
      'Compare two already-recorded outcomes for the same tenant task using durable proof. ' +
      'This does not run a model or replay customer content; it returns complete or insufficient_evidence.',
    inputSchema: {
      type: 'object',
      properties: {
        comparison_id: { type: 'string', minLength: 1, description: 'Fetch a prior replay comparison by id.' },
        source_decision_id: { type: 'string', description: 'Original task decision used to bind the comparison.' },
        workspace_binding_id: { type: 'string', description: 'Optional privacy-safe workspace binding from runtime.' },
        constraints: {
          type: 'object',
          additionalProperties: false,
          maxProperties: 7,
          description: 'Allowlisted comparison labels only; prompts, code, transcripts, credentials, and nested content are rejected.',
          properties: {
            environment: { type: 'string', maxLength: 80 },
            tests: { type: 'string', maxLength: 80 },
            policy_profile_id: { type: 'string', maxLength: 80 },
            workflow_type: { type: 'string', maxLength: 80 },
            task_type: { type: 'string', maxLength: 80 },
            required_proof: { type: 'boolean' },
            same_workspace: { type: 'boolean' },
          },
        },
        baseline: {
          type: 'object',
          properties: { label: { type: 'string' }, decision_id: { type: 'string' } },
          required: ['decision_id'],
        },
        candidate: {
          type: 'object',
          properties: { label: { type: 'string' }, decision_id: { type: 'string' } },
          required: ['decision_id'],
        },
      },
      oneOf: [
        {
          required: ['comparison_id'],
          not: {
            anyOf: [
              { required: ['source_decision_id'] },
              { required: ['workspace_binding_id'] },
              { required: ['constraints'] },
              { required: ['baseline'] },
              { required: ['candidate'] },
            ],
          },
        },
        {
          required: ['source_decision_id', 'baseline', 'candidate'],
          not: { required: ['comparison_id'] },
        },
      ],
    },
  },
  {
    name: 'marrow_governance_control_plane',
    description:
      'Return Marrow control-plane proof: governance, runtime gates, proof packs, fleet intelligence, supported harnesses, and exact next action.',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  {
    name: 'marrow_hermes_integration',
    description:
      'Return the Hermes Agent integration guide mapping /goal, verification evidence, /learn, /journey, and background subagents into Marrow proof and outcome workflows.',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  {
    name: 'marrow_completion_contracts',
    description:
      'List Marrow completion contracts for deploy, merge, publish, database migration, security change, support response, and Hermes goal workflows.',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  {
    name: 'marrow_evaluate_completion_contract',
    description:
      'Evaluate whether an agent has enough proof to mark work complete. Returns complete, missing_proof, review_required, or blocked with missing proof fields.',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', description: 'Action/workflow being completed, e.g. deploy, publish, db_migration, hermes_goal.' },
        workflow_type: { type: 'string', description: 'Optional workflow type if action is not supplied.' },
        risk_level: { type: 'string', enum: ['low', 'medium', 'high'], description: 'Optional risk override.' },
        evidence: { type: 'object', description: 'Non-sensitive proof fields already collected.' },
      },
      required: [],
    },
  },
  {
    name: 'marrow_governance_timeline',
    description:
      'Return the recent fleet governance timeline across decisions, risk gates, and proof-pack events.',
    inputSchema: {
      type: 'object',
      properties: {
        agentId: { type: 'string', description: 'Optional agent filter. Defaults to the canonical fleet-bound agent identity.' },
        limit: { type: 'number', description: 'Max events to return, default 25, max 100.' },
      },
      required: [],
    },
  },
  {
    name: 'marrow_decision_trace',
    description: 'Inspect the tenant-scoped path behind one governed decision and return its owner-readable intervention receipt with gate, required workflow, permit follow-through, proof, and observed outcome.',
    inputSchema: {
      type: 'object',
      properties: {
        decisionId: { type: 'string', description: 'Decision ID owned by this account and agent scope.' },
      },
      required: ['decisionId'],
    },
  },
  {
    name: 'marrow_buyer_proof',
    description:
      'Return buyer-grade value proof: failures avoided, risky actions reviewed, proofs completed, token/time saved, failure classes, agent leaderboard, and reliability score.',
    inputSchema: {
      type: 'object',
      properties: {
        agentId: { type: 'string', description: 'Optional agent filter. Defaults to the canonical fleet-bound agent identity.' },
        periodDays: { type: 'number', description: 'Lookback period in days, default 30, max 90.' },
      },
      required: [],
    },
  },
  {
    name: 'marrow_mode_recommend',
    description:
      'Recommend passive, pilot, or enforce mode from project/workflow signals. Marrow never auto-switches here; the agent/user must accept or override.',
    inputSchema: {
      type: 'object',
      properties: {
        project: { type: 'object', description: 'Project signals: name, type, frameworks, signals, package_scripts, config_files.' },
        workflow: { type: 'object', description: 'Workflow context: action, type, branch, environment.' },
        agent: { type: 'object', description: 'Agent context: id and role.' },
        selected_mode: { type: 'string', enum: ['passive', 'pilot', 'enforce'], description: 'Optional final user-selected mode to log.' },
        selection_source: { type: 'string', enum: ['accepted', 'overridden', 'ignored', 'system'], description: 'How the final mode was selected.' },
      },
      required: [],
    },
  },
  {
    name: 'marrow_policy_profiles',
    description: 'List saved Marrow governance policy profiles for this account. Returns default-business when none are saved.',
    inputSchema: { type: 'object', properties: {}, required: [] },
  },
  {
    name: 'marrow_create_policy_profile',
    description: 'Create or update an explicit governance policy profile. Mutating call; requires a key with full scope.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Profile name, e.g. default-business or production-agents.' },
        description: { type: 'string', description: 'Optional profile description.' },
        rules: { type: 'array', items: { type: 'object' }, description: 'Rules with match fields and mode passive/pilot/enforce.' },
      },
      required: ['name'],
    },
  },
  {
    name: 'marrow_assign_project_policy_profile',
    description: 'Assign an active governance policy profile to a project key. Mutating call; requires a key with full scope.',
    inputSchema: {
      type: 'object',
      properties: {
        project_key: { type: 'string', description: 'Stable project key, e.g. marrow-api or clinic-api.' },
        profile_id: { type: 'string', description: 'Active policy profile id.' },
      },
      required: ['project_key', 'profile_id'],
    },
  },
  {
    name: 'marrow_policy_resolve',
    description:
      'Resolve the explicit mode for a project/workflow from saved policy profiles, falling back to recommendation. Does not auto-apply.',
    inputSchema: {
      type: 'object',
      properties: {
        profile_id: { type: 'string', description: 'Optional policy profile id.' },
        profile_name: { type: 'string', description: 'Optional policy profile name.' },
        project: { type: 'object', description: 'Project signals: name, type, frameworks, signals, package_scripts, config_files.' },
        workflow: { type: 'object', description: 'Workflow context: action, type, branch, environment.' },
        agent: { type: 'object', description: 'Agent context: id and role.' },
      },
      required: [],
    },
  },
  {
    name: 'marrow_workflow_gate',
    description:
      'Pre-action risk gate for deploys, publishes, merges, DB migrations, key rotation, destructive commands, and production work. ' +
      'Returns allow, warn, review_required, or block plus prior lessons/playbooks.',
    inputSchema: {
      type: 'object',
      properties: {
        action: { type: 'string', description: 'What the agent is about to do.' },
        description: { type: 'string', description: 'Optional extra context for the action.' },
        riskTolerance: { type: 'string', enum: ['low', 'medium', 'high'], description: 'Default high. Use medium/low for stricter gates.' },
        requiresApproval: { type: 'boolean', description: 'Set true when owner approval is required before proceeding.' },
        context: { type: 'object', description: 'Optional metadata. Do not include secrets or raw payloads.' },
      },
      required: ['action'],
    },
  },
  {
    name: 'marrow_agent_performance',
    description:
      'Get agent-facing fleet value metrics: avoided mistakes, reused winning decisions, failed patterns, token/time saved estimate, reliability score, and next improvements.',
    inputSchema: {
      type: 'object',
      properties: {
        period: { type: 'string', description: 'Time period: 7d (default), 14d, 30d, or day count up to 90.' },
        agentId: { type: 'string', description: 'Optional agent_id/session_id filter. Defaults to the canonical fleet-bound agent identity.' },
      },
      required: [],
    },
  },
  {
    name: 'marrow_fleet_lessons',
    description:
      'Retrieve ranked reusable fleet lessons before similar work. Use before deploys, handoffs, migrations, audits, and repeated task types.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Search phrase for similar work.' },
        type: { type: 'string', enum: ['success', 'failure', 'deploy', 'incident', 'handoff', 'general'] },
        agentId: { type: 'string', description: 'Optional agent filter.' },
        limit: { type: 'number', description: 'Max lessons to return, default 10.' },
      },
      required: [],
    },
  },
  {
    name: 'marrow_record_deployment_memory',
    description:
      'Record deploy or incident memory: PR, commit, tests, smoke result, rollback plan, production health, and incident notes.',
    inputSchema: {
      type: 'object',
      properties: {
        release_id: { type: 'string' },
        pr_url: { type: 'string' },
        commit_sha: { type: 'string' },
        environment: { type: 'string' },
        status: { type: 'string', enum: ['planned', 'dry_run', 'deployed', 'verified', 'rolled_back', 'incident'] },
        tests: { type: 'array', items: { type: 'string' } },
        smoke_result: { type: 'string' },
        rollback_plan: { type: 'string' },
        prod_health: { type: 'string' },
        incident_summary: { type: 'string' },
      },
      required: [],
    },
  },
  {
    name: 'marrow_create_handoff',
    description:
      'Create a structured cross-agent handoff that Marrow can track for pending, stale, blocked, and complete states.',
    inputSchema: {
      type: 'object',
      properties: {
        to_agent_id: { type: 'string' },
        task: { type: 'string' },
        workflow_id: { type: 'string' },
        from_agent_id: { type: 'string' },
        checkpoint: { type: 'string' },
        stale_after_seconds: { type: 'number' },
      },
      required: ['to_agent_id', 'task'],
    },
  },
  {
    name: 'marrow_update_handoff',
    description:
      'Update a Marrow handoff checkpoint/status when an agent accepts, blocks, completes, or needs review.',
    inputSchema: {
      type: 'object',
      properties: {
        handoffId: { type: 'string' },
        status: { type: 'string', enum: ['pending', 'accepted', 'working', 'blocked', 'complete', 'stale', 'cancelled'] },
        checkpoint: { type: 'string' },
        result_summary: { type: 'string' },
      },
      required: ['handoffId'],
    },
  },
  {
    name: 'marrow_handoff_status',
    description:
      'Ask who is pending, stuck, stale, blocked, or complete across the agent fleet.',
    inputSchema: {
      type: 'object',
      properties: {
        status: { type: 'string' },
        agentId: { type: 'string' },
        limit: { type: 'number' },
      },
      required: [],
    },
  },
  {
    name: 'marrow_session_end',
    description:
      'Explicitly end the current session. Optionally auto-commits any open decision. ' +
      'Prevents orphaned decisions when an agent finishes a task.',
    inputSchema: {
      type: 'object',
      properties: {
        autoCommitOpen: { type: 'boolean', description: 'Whether to auto-commit any open decision (default: true)' },
      },
      required: [],
    },
  },
  {
    name: 'marrow_accept_detected',
    description:
      'Convert a detected decision pattern into an enforced workflow. ' +
      'The pattern ID comes from suggested_workflows in the orient() response.',
    inputSchema: {
      type: 'object',
      properties: {
        detectedId: { type: 'string', description: 'ID of the detected pattern to accept' },
      },
      required: ['detectedId'],
    },
  },
  {
    name: 'marrow_list_templates',
    description:
      'Browse pre-built workflow templates. Filter by industry (insurance, healthcare, ecommerce, legal, saas, fintech, media, enterprise) or category. ' +
      'Use to discover available workflows before installing.',
    inputSchema: {
      type: 'object',
      properties: {
        industry: { type: 'string', description: 'Filter by industry (e.g., insurance, healthcare, saas)' },
        category: { type: 'string', description: 'Filter by category (e.g., claims, engineering, support)' },
        limit: { type: 'number', description: 'Max results (default: 20)' },
      },
      required: [],
    },
  },
  {
    name: 'marrow_install_template',
    description:
      'Install a workflow template into your fleet as an active workflow. ' +
      'Use after marrow_list_templates to pick one.',
    inputSchema: {
      type: 'object',
      properties: {
        slug: { type: 'string', description: 'Template slug to install (e.g., code-review-deploy, claims-triage)' },
      },
      required: ['slug'],
    },
  },
];

const CORE_TOOL_NAMES = new Set([
  'marrow_agent_runtime',
  'marrow_think',
  'marrow_commit',
  'marrow_ask',
  'marrow_status',
  'marrow_auto',
  'marrow_handoff_status',
]);

const PRIMARY_TOOL_NAMES = new Set([
  'marrow_agent_runtime',
  'marrow_arbitrate',
  'marrow_coordinate',
  'marrow_replay_compare',
  'marrow_decision_brief',
  'marrow_think',
  'marrow_commit',
  'marrow_workflow_gate',
  'marrow_completion_contracts',
  'marrow_evaluate_completion_contract',
  'marrow_agent_status',
  'marrow_value_report',
  'marrow_buyer_proof',
  'marrow_governance_timeline',
  'marrow_decision_trace',
  'marrow_fleet_lessons',
  'marrow_model_usage',
]);

type MarrowToolProfile = 'primary' | 'core' | 'full';

function activeToolProfile(): MarrowToolProfile {
  const configured = process.env.MARROW_TOOL_PROFILE;
  if (configured === undefined || configured === 'primary') return 'primary';
  if (configured === 'core' || configured === 'full') return configured;
  throw new Error(
    'Invalid MARROW_TOOL_PROFILE value. Set MARROW_TOOL_PROFILE=primary, core, or full, '
    + 'or unset it for primary; then restart MCP.',
  );
}

function toolsForProfile(profile: MarrowToolProfile): typeof TOOLS {
  if (profile === 'full') return TOOLS;
  const visibleNames = profile === 'primary' ? PRIMARY_TOOL_NAMES : CORE_TOOL_NAMES;
  return TOOLS.filter((tool) => visibleNames.has(tool.name));
}

function advertisedTools(): typeof TOOLS {
  return toolsForProfile(activeToolProfile());
}

function toolAllowedByActiveProfile(toolName: string | undefined): boolean {
  return Boolean(toolName && toolsForProfile(activeToolProfile()).some((tool) => tool.name === toolName));
}

function recordValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

type ValidatedBackendPrimaryToolAvailability = {
  projection: Record<string, unknown>;
  evidenceState: 'available' | 'unavailable';
};

function nonNegativeInteger(value: unknown): value is number {
  return Number.isInteger(value) && Number(value) >= 0;
}

function validatedPrimaryToolAvailability(value: unknown): ValidatedBackendPrimaryToolAvailability | null {
  const projection = recordValue(value);
  const evidence = recordValue(projection?.entitlement_evidence);
  const counts = recordValue(projection?.counts);
  const tools = projection?.tools;
  const expectedNames = [...PRIMARY_TOOL_NAMES];
  if (!projection
    || projection.profile !== 'primary'
    || (projection.current_plan !== null && typeof projection.current_plan !== 'string')
    || typeof projection.owner_management_url !== 'string'
    || !evidence
    || (evidence.state !== 'available' && evidence.state !== 'unavailable')
    || typeof evidence.source !== 'string'
    || typeof evidence.authoritative !== 'boolean'
    || evidence.authorizing !== false
    || !counts
    || !nonNegativeInteger(counts.total)
    || !nonNegativeInteger(counts.entitled)
    || !nonNegativeInteger(counts.upgrade_required)
    || !nonNegativeInteger(counts.unavailable)
    || counts.total !== expectedNames.length
    || counts.entitled + counts.upgrade_required + counts.unavailable !== counts.total
    || !Array.isArray(tools)
    || tools.length !== expectedNames.length) {
    return null;
  }
  if ((evidence.state === 'available' && evidence.authoritative !== true)
    || (evidence.state === 'unavailable' && evidence.authoritative !== false)) {
    return null;
  }
  const derivedCounts = { entitled: 0, upgrade_required: 0, unavailable: 0 };
  for (let index = 0; index < tools.length; index++) {
    const tool = recordValue(tools[index]);
    const state = tool?.state;
    if (!tool
      || tool.name !== expectedNames[index]
      || (state !== 'entitled' && state !== 'upgrade_required' && state !== 'unavailable')
      || typeof tool.always_available !== 'boolean'
      || (tool.plan_feature !== null && typeof tool.plan_feature !== 'string')
      || (tool.minimum_plan !== null && typeof tool.minimum_plan !== 'string')
      || typeof tool.owner_management_url !== 'string') {
      return null;
    }
    derivedCounts[state]++;
  }
  if (derivedCounts.entitled !== counts.entitled
    || derivedCounts.upgrade_required !== counts.upgrade_required
    || derivedCounts.unavailable !== counts.unavailable) {
    return null;
  }
  return {
    projection,
    evidenceState: evidence.state,
  };
}

function backendPrimaryToolAvailability(value: unknown): ValidatedBackendPrimaryToolAvailability | null {
  const payload = recordValue(value);
  if (!payload) return null;
  const data = recordValue(payload.data);
  const status = recordValue(payload.status);
  const entitlements = recordValue(payload.entitlements);
  const entitlementProjection = recordValue(payload.entitlement_projection);
  const statusEntitlements = recordValue(status?.entitlements);
  const statusProjection = recordValue(status?.entitlement_projection);
  const candidates = [
    payload.primary_tool_availability,
    data?.primary_tool_availability,
    status?.primary_tool_availability,
    entitlements?.primary_tool_availability,
    entitlementProjection?.primary_tool_availability,
    statusEntitlements?.primary_tool_availability,
    statusProjection?.primary_tool_availability,
  ];
  for (const candidate of candidates) {
    const validated = validatedPrimaryToolAvailability(candidate);
    if (validated) return validated;
  }
  return null;
}

function mcpToolProfileStatus(value: unknown): Record<string, unknown> {
  const profile = activeToolProfile();
  const visibleToolNames = toolsForProfile(profile).map((tool) => tool.name);
  const payload = recordValue(value);
  const cachedOrStale = payload?.cached === true
    || payload?.stale === true
    || payload?.status_freshness === 'stale';
  const backendProjection = cachedOrStale ? null : backendPrimaryToolAvailability(payload);
  const backendProjectionAvailable = backendProjection?.evidenceState === 'available';
  return {
    configured_profile: process.env.MARROW_TOOL_PROFILE ?? 'unset',
    effective_profile: profile,
    visible_tool_count: visibleToolNames.length,
    visible_tool_names: visibleToolNames,
    local_visibility_grants_entitlement: false,
    backend_entitlement_projection: {
      evidence_state: backendProjectionAvailable ? 'available' : 'unavailable',
      source: cachedOrStale
        ? 'cached_or_stale_status'
        : backendProjection
          ? 'authenticated_backend'
          : 'backend_projection_not_provided',
      authorizes_calls: false,
      primary_tool_availability: backendProjectionAvailable ? backendProjection.projection : null,
    },
  };
}

function withMcpToolProfileStatus(value: unknown): Record<string, unknown> {
  const payload = recordValue(value) || { data: value };
  return {
    ...payload,
    mcp_tool_profile: mcpToolProfileStatus(payload),
  };
}

// Request handler
async function handleRequest(req: {
  id: string | number;
  method: string;
  params?: { name?: string; arguments?: Record<string, unknown> };
}): Promise<void> {
  const { id, method, params } = req;

  // [FIX #15] Enforce initialize-first per MCP spec
  if (!initialized && method !== 'initialize') {
    error(id, -32002, 'Server not initialized. Send initialize first.');
    return;
  }

  try {
    if (method === 'initialize') {
      initialized = true;
      const hostCapability = mcpHostCapability();
      success(id, {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {}, prompts: {} },
        serverInfo: { name: 'marrow', version: MCP_ADAPTER_VERSION },
        ...(AUTO_ENROLL ? {
          instructions: `Call marrow_think before meaningful work to create the decision_id. Use marrow_agent_runtime before consequential actions and obey fresh allow/warn/review_required/block only when risk_gate.enforced is true; if enforced is false the gate is advisory, not a live block. Use marrow_ask for relevant prior lessons, and close outcomes with marrow_commit using that decision_id. Infrastructure failures are not policy denials; continue only low-risk reversible work from the returned outage-safe brief, and require a fresh gate for high-risk work. ${hostCapabilityInstructions(hostCapability)}`,
        } : {}),
        _meta: { host_capability: hostCapability },
      });

      // Auto-enroll: emit enrollment notification on connection
      if (AUTO_ENROLL) {
        send({
          jsonrpc: '2.0',
          method: 'notifications/message',
          params: {
            level: 'info',
            logger: 'marrow',
            data: {
              type: 'auto_enroll',
              message: `Marrow operating contract available. MCP tools are on demand. ${hostCapability.exact_next_action}`,
              agentId: FLEET_AGENT_ID,
              client_update: localClientUpdate(),
              host_capability: hostCapability,
            },
          },
        });
      }
      return;
    }

    if (method === 'prompts/list') {
      if (AUTO_ENROLL) {
        success(id, {
          prompts: [
            {
              name: 'marrow-always-on',
              description:
                'Marrow control and proof contract. MCP tools are on demand; host activity is client-self-reported and coverage remains unverified without independent authority.',
              arguments: [],
              _meta: { host_capability: mcpHostCapability() },
            },
          ],
        });
      } else {
        success(id, { prompts: [] });
      }
      return;
    }

    if (method === 'prompts/get') {
      const promptName = params?.name;
      if (promptName !== 'marrow-always-on' || !AUTO_ENROLL) {
        error(id, -32602, 'Unknown prompt');
        return;
      }
      const hostCapability = mcpHostCapability();
      success(id, {
        description: 'Marrow control and proof contract — MCP tools are on demand, host activity is client-self-reported, and coverage is unverified without independent authority',
        _meta: { host_capability: hostCapability },
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `You have Marrow — the agent control and proof layer around this workflow.

## Capability-qualified operating contract

${hostCapabilityInstructions(hostCapability)}

Configured native hooks can cooperatively report or inject context for these bounded lifecycle stages, but their callbacks are client-self-reported activity and do not certify control:
- UserPromptSubmit can request relevant policy, warnings, lessons, and a decision brief before risky work.
- PostToolUse can record compact tool success or failure receipts.
- Stop can keep unfinished outcomes visible instead of silently treating session exit as success.

Hooks never make a blocked action safe and are not an external execution choke point. Before a consequential action, respect the returned allow, warn, review_required, or block decision and its required proof. Codex, Grok, and Gemini use configured native hooks only after restart and host hook review; the governed wrapper remains an explicit bounded fallback.

When runtime/status returns a client_update notice, tell the operator and use its exact update and verification commands only when local change policy permits. Never silently change packages or configuration.

## Outcome closure

A successful command or tool exit is not proof that the business outcome succeeded. After meaningful work, close the real outcome with marrow_commit or marrow_auto and include success or failure plus the required evidence. If the result is unknown, leave it pending. Never invent success to clear a closure item.

Use marrow_decision_trace when you need to explain why Marrow changed an action. Its intervention_receipt packages the relevant gate, required workflow, permit follow-through, proof, and recorded outcome without raw context, proof values, or another tenant's data. After a meaningful intervention, relay one factual receipt summary to the operator. Stay quiet for routine low-risk work.

## Owner-visible value

When Marrow returns a factual value signal, relay the single most useful result in one plain sentence. Mention a prevented repeat failure, reused proven lesson, completed proof, or measured improvement only when the response contains evidence. Do not invent savings, success rates, customer examples, pricing, or upgrade claims.

Use marrow_ask for authorized history questions such as:
- "what keeps breaking our deploys?"
- "which proof is missing from this workflow?"
- "what worked last time we published?"

Marrow is not a replacement agent or a standalone memory app. Context and prior lessons support the control loop; policy before action, proof after action, accountable outcomes, and fleet improvement are the product.`,
            },
          },
        ],
      });
      return;
    }

    if (method === 'tools/list') {
      success(id, { tools: advertisedTools() });
      return;
    }

    if (method === 'tools/call') {
      const toolName = params?.name;
      const args = (params?.arguments || {}) as Record<string, unknown>;

      if (!toolAllowedByActiveProfile(toolName)) {
        const repair = toolName && PRIMARY_TOOL_NAMES.has(toolName)
          ? 'Unset MARROW_TOOL_PROFILE or set MARROW_TOOL_PROFILE=primary, then restart MCP.'
          : 'Set MARROW_TOOL_PROFILE=full, then restart MCP for the complete advanced/legacy catalog.';
        error(id, -32601, `Tool is not available in the active Marrow tool profile. ${repair}`);
        return;
      }

      if (toolName === 'marrow_orient') {
        orientCallCount++;
        const wantAutoWarn = (args.autoWarn as boolean) ?? true;
        const taskType = args.taskType as string;
        const result = await withControlDeadline(
          (signal) => marrowOrient(
            API_KEY,
            BASE_URL,
            { taskType, autoWarn: wantAutoWarn },
            SESSION_ID,
            FLEET_AGENT_ID,
            signal,
          ),
          { highRisk: isHighRiskAction(`Orient before ${taskType || 'general'} work`, taskType), toolName: 'marrow_orient' },
        );

        if (AUTO_ENROLL && orientCallCount === 1) {
          const enrollmentText = `\n\n**Marrow control and proof active**\n\n` +
            `Marrow applies relevant policy and prior lessons before consequential actions, then records evidence and the real outcome afterward.\n\n` +
            `1. Respect allow, warn, review_required, and block decisions before acting.\n` +
            `2. Use marrow_agent_runtime when a risky action needs an explicit gate.\n` +
            `3. Close meaningful work with marrow_commit; a tool exit alone is not outcome proof.\n` +
            `4. Use marrow_decision_trace to explain the prior failure, lesson, gate, proof, workflow, and outcome path.\n\n` +
            `${hostCapabilityInstructions(mcpHostCapability())}\n\nLeave unknown outcomes pending instead of inventing success.\n`;

          const orientText = JSON.stringify(result, null, 2);
          success(id, {
            content: [{ type: 'text', text: enrollmentText + orientText }],
          });
        } else {
          success(id, {
            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
          });
        }
        return;
      }

      if (toolName === 'marrow_think') {
        // [FIX #9] Validate required param
        const action = requireString(args, 'action');

        const result = await marrowThink(
          API_KEY,
          BASE_URL,
          {
            action,
            type: args.type as string,
            context: args.context as Record<string, unknown>,
            previous_decision_id: args.previous_decision_id as string,
            previous_success: args.previous_success as boolean,
            previous_outcome: args.previous_outcome as string,
            checkLoop: (args.checkLoop as boolean) ?? true,
            source_kind: args.source_kind as any,
            human_directed: args.human_directed as boolean,
            instruction_ref: args.instruction_ref as string,
            source_meta: args.source_meta as Record<string, unknown>,
          },
          SESSION_ID,
          FLEET_AGENT_ID
        );

        // Refresh orient warnings every 5th think call
        thinkCallCount++;
        if (thinkCallCount % 5 === 0) {
          refreshOrientWarnings();
        }

        // Inject cached orient warnings into intelligence.insights
        if (cachedOrientWarnings.length > 0) {
          const existingInsights = result.intelligence?.insights || [];
          result.intelligence.insights = [
            ...cachedOrientWarnings.map((w) => ({
              type: 'failure_pattern' as const,
              summary: w.message,
              action: `Review past ${w.type} failures before proceeding`,
              severity: (w.failureRate > 0.4 ? 'critical' : 'warning') as
                | 'critical'
                | 'warning',
              count: 0,
            })),
            ...existingInsights,
          ];
        }

        lastDecisionId = result.decision_id;
        lastCommitted = false;

        success(id, {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        });
        return;
      }

      if (toolName === 'marrow_commit') {
        // [FIX #9] Validate required params
        const decision_id = requireString(args, 'decision_id');
        const outcome = requireString(args, 'outcome');
        const commitSuccess = requireBoolean(args, 'success');

        const result = await withControlDeadline(
          (signal) => marrowCommit(
            API_KEY,
            BASE_URL,
            {
              decision_id,
              success: commitSuccess,
              outcome,
              caused_by: args.caused_by as string,
              proof: args.proof as Record<string, unknown>,
              gate_receipt_id: args.gate_receipt_id as string,
              arbitration_receipt_id: args.arbitration_receipt_id as string,
              owner_approval_receipt_id: args.owner_approval_receipt_id as string,
              action: args.action as string,
              type: args.type as string,
              surfaces: args.surfaces as string[],
              auto_gate: args.auto_gate as boolean,
              model_usage: args.model_usage as any,
            },
            SESSION_ID,
            FLEET_AGENT_ID,
            signal,
          ),
          { highRisk: true, cacheAware: false, toolName: 'marrow_commit' },
        );
        const commitResult = { ...result, narrative: result.narrative ?? null };
        lastCommitted = result.committed;
        lastDecisionId = result.committed ? null : decision_id;
        success(id, {
          content: [{ type: 'text', text: JSON.stringify(commitResult, null, 2) }],
        });
        return;
      }

      if (toolName === 'marrow_model_usage') {
        const result = await marrowModelUsage(
          API_KEY,
          BASE_URL,
          args as any,
          SESSION_ID,
          FLEET_AGENT_ID
        );
        success(id, {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        });
        return;
      }

      if (toolName === 'marrow_run') {
        // [FIX #9] Validate required params
        const description = requireString(args, 'description');
        const outcome = requireString(args, 'outcome');
        const measuredSuccess = requireBoolean(args, 'success');

        // [FIX #16] Handle partial failures — return think result even if commit fails
        let thinkResult: ThinkResult | null = null;
        try {
          await marrowOrient(API_KEY, BASE_URL, undefined, SESSION_ID, FLEET_AGENT_ID);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          process.stderr.write(`[marrow] marrow_run orient failed (continuing): ${msg}\n`);
        }

        thinkResult = await marrowThink(
          API_KEY,
          BASE_URL,
          {
            action: description,
            type: (args.type as string) || 'general',
          },
          SESSION_ID,
          FLEET_AGENT_ID
        );

        let commitResult = null;
        try {
          commitResult = await marrowCommit(
            API_KEY,
            BASE_URL,
            {
              decision_id: thinkResult.decision_id,
              success: measuredSuccess,
              outcome,
              proof: args.proof && typeof args.proof === 'object' && !Array.isArray(args.proof)
                ? redactSensitiveValue(args.proof) as Record<string, unknown>
                : undefined,
              gate_receipt_id: typeof args.gate_receipt_id === 'string' ? args.gate_receipt_id : undefined,
              action: description,
              type: (args.type as string) || 'general',
            },
            SESSION_ID,
            FLEET_AGENT_ID
          );
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          process.stderr.write(`[marrow] marrow_run commit failed: ${msg}\n`);
          success(id, {
            content: [{
              type: 'text',
              text: JSON.stringify({
                think: thinkResult,
                commit: null,
                commit_error: msg,
                decision_id: thinkResult.decision_id,
              }, null, 2),
            }],
          });
          return;
        }

        success(id, {
          content: [{
            type: 'text',
            text: JSON.stringify({ think: thinkResult, commit: commitResult }, null, 2),
          }],
        });
        return;
      }

      if (toolName === 'marrow_auto') {
        const action = requireString(args, 'action');
        const outcome = args.outcome as string | undefined;
        const outcomeSuccess = typeof args.success === 'boolean' ? args.success : undefined;
        const type = (args.type as string) || 'general';
        const highRisk = isHighRiskAction(action, type);
        const suppliedProof = args.proof && typeof args.proof === 'object' && !Array.isArray(args.proof)
          ? redactSensitiveValue(args.proof) as Record<string, unknown>
          : undefined;
        const suppliedRuntimeReceiptId = typeof args.gate_receipt_id === 'string'
          ? args.gate_receipt_id
          : undefined;
        const suppliedArbitrationReceiptId = typeof args.arbitration_receipt_id === 'string'
          ? args.arbitration_receipt_id
          : undefined;
        const suppliedOwnerApprovalReceiptId = typeof args.owner_approval_receipt_id === 'string'
          ? args.owner_approval_receipt_id
          : undefined;

        const delivery = () => marrowAuto(API_KEY, BASE_URL, {
          action,
          outcome,
          success: outcomeSuccess,
          type,
          proof: suppliedProof,
          gate_receipt_id: suppliedRuntimeReceiptId || undefined,
          arbitration_receipt_id: suppliedArbitrationReceiptId,
          owner_approval_receipt_id: suppliedOwnerApprovalReceiptId,
          // Low-risk one-shot capture does not need a policy gate. Consequential
          // work obtains exactly one canonical runtime authorization inside auto.
          auto_gate: highRisk,
          operation_id: typeof args.operation_id === 'string' ? args.operation_id : undefined,
        }, SESSION_ID, FLEET_AGENT_ID, 8_000);

        let delivered: MarrowAutoResult | null = null;
        let deliveryFailure: Record<string, unknown> | null = null;
        try {
          delivered = await delivery();
        } catch (err) {
          deliveryFailure = structuredRequestFailure(err);
        }
        const runtimeGate = delivered?.runtime_gate || null;
        if (runtimeGate) storeRuntimeGuidance(runtimeGate);

        const receipt = await recordLifecycleEvent({
          apiKey: API_KEY,
          baseUrl: BASE_URL,
          deferDelivery: false,
          event: {
            ...(delivered?.operation_id ? {
              event_id: `auto_${delivered.committed ? 'closed' : 'pending'}_${delivered.operation_id}`,
            } : {}),
            event_type: delivered?.committed
              ? 'outcome_committed'
              : !highRisk && outcomeSuccess === false
              ? 'tool_failed'
              : !highRisk && outcomeSuccess === true
              ? 'tool_completed'
              : 'goal_started',
            harness: process.env.MARROW_CLIENT || process.env.MARROW_HARNESS || 'mcp',
            agent_id: FLEET_AGENT_ID,
            session_id: SESSION_ID,
            decision_id: delivered?.decision_id || undefined,
            action,
            outcome_state: delivered?.committed ? 'closed' : 'pending',
            success: delivered?.committed ? outcomeSuccess : highRisk ? undefined : outcomeSuccess,
            source: 'client_self_reported',
          },
        });

        const response: Record<string, unknown> = {
          action,
          outcome: outcome || 'pending',
          warnings: cachedOrientWarnings.map(formatWarningActionably),
          logging: delivered?.committed
            ? 'governed_commit_confirmed'
            : delivered?.resumable
            ? 'resume_required'
            : delivered
            ? 'intent_confirmed'
            : 'durably_queued',
          receipt,
          completion_state: delivered?.committed
            ? 'closed_with_proof'
            : delivered?.phase === 'review_required'
            ? 'review_required_terminal'
            : delivered?.phase === 'owner_approval_required'
            ? 'pending_owner_approval'
            : delivered?.phase === 'proof_required'
            ? 'pending_required_proof'
            : delivered?.phase === 'decision_created' || outcomeSuccess === undefined
            ? 'pending_evidence'
            : 'delivery_pending',
          decision_id: delivered?.decision_id || null,
          operation_id: delivered?.operation_id || (typeof args.operation_id === 'string' ? args.operation_id : null),
          phase: delivered?.phase || null,
          resumable: delivered?.resumable || false,
          retry_after_ms: delivered?.retry_after_ms ?? null,
          phase_timings_ms: delivered?.phase_timings_ms || null,
          exact_next_action: delivered?.committed
            ? 'The governed outcome is closed. Reuse this decision_id only for read-only trace inspection.'
            : delivered?.exact_next_action
            ? delivered.exact_next_action
            : delivered?.phase === 'owner_approval_required'
            ? 'Approve this exact arbitration decision in the authenticated Marrow dashboard, then call marrow_auto once with this same operation_id, arbitration_receipt_id, and the server-issued owner_approval_receipt_id. Do not retry proof or use chat approval text.'
            : delivered?.phase === 'proof_required'
            ? 'Attach the required measured proof and retry marrow_auto with this same operation_id and unchanged action, context, and surfaces.'
            : delivered?.resumable
            ? 'Retry marrow_auto with this same operation_id. Do not start a new auto operation.'
            : 'Close this decision after the real outcome is known.',
          live_delivery: {
            accepted: Boolean(delivered?.decision_id),
            committed: Boolean(delivered?.committed),
            ...(deliveryFailure ? { failure: deliveryFailure } : {}),
          },
          host_capability: mcpHostCapability(),
          client_update: localClientUpdate(),
          ...(runtimeGate ? { runtime_gate: runtimeGate } : {}),
        };

        success(id, {
          content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
        });
        return;
      }

      if (toolName === 'marrow_ask') {
        const query = requireString(args, 'query');
        const result = await withControlDeadline(
          (signal) => marrowAsk(API_KEY, BASE_URL, { query }, SESSION_ID, FLEET_AGENT_ID, signal),
          { toolName: 'marrow_ask' },
        );
        try {
          writeGuidanceCache({
            apiKey: API_KEY,
            baseUrl: BASE_URL,
            agentId: FLEET_AGENT_ID,
            context: `## Marrow answer\n- ${String(result.answer || 'No relevant lesson found.').slice(0, 1200)}`,
          });
        } catch { /* owner-only cache is best effort */ }
        toolSuccess(id, clientOperationalPayload('marrow_ask', result));
        return;
      }

      if (toolName === 'marrow_status') {
        let cached: ReturnType<typeof readStatusCache> = null;
        try {
          cached = readStatusCache({ apiKey: API_KEY, baseUrl: BASE_URL, agentId: FLEET_AGENT_ID });
        } catch { /* owner-only cache is best effort */ }
        if (cached?.freshness === 'fresh') {
          const startedAt = Date.now();
          refreshStatusInBackground();
          recordControlPathSample('marrow_status', Date.now() - startedAt, true);
          toolSuccess(id, clientOperationalPayload('marrow_status', cachedStatusPayload(cached)));
          return;
        }
        try {
          const result = await withControlDeadline(
            (signal) => marrowStatus(API_KEY, BASE_URL, SESSION_ID, FLEET_AGENT_ID, signal),
            { cacheAware: false, toolName: 'marrow_status' },
          );
          storeLastKnownStatus(result, 'status');
          toolSuccess(id, clientOperationalPayload('marrow_status', result));
        } catch (error) {
          if (cached) {
            const startedAt = Date.now();
            recordControlPathSample('marrow_status', Date.now() - startedAt, false);
            toolSuccess(id, clientOperationalPayload('marrow_status', cachedStatusPayload(cached)));
            return;
          }
          throw error;
        }
        return;
      }

      if (toolName === 'marrow_create_key') {
        const name = requireString(args, 'name');
        const result = await marrowCreateKey(API_KEY, BASE_URL, {
          name,
          key_type: args.key_type as 'live' | 'test' | undefined,
          scopes: args.scopes as any,
          agent_ids: args.agent_ids as string[] | undefined,
          expires_at: args.expires_at as string | undefined,
        }, SESSION_ID, FLEET_AGENT_ID);
        success(id, {
          content: [{ type: 'text', text: JSON.stringify({ ...result, warning: formatKeyMaterialWarning() }, null, 2) }],
        });
        return;
      }

      if (toolName === 'marrow_list_keys') {
        const result = await marrowListKeys(API_KEY, BASE_URL, SESSION_ID, FLEET_AGENT_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_get_key') {
        const keyId = requireString(args, 'id');
        const result = await marrowGetKey(API_KEY, BASE_URL, keyId, SESSION_ID, FLEET_AGENT_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_revoke_key') {
        const keyId = requireString(args, 'id');
        const result = await marrowRevokeKey(API_KEY, BASE_URL, keyId, SESSION_ID, FLEET_AGENT_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_rotate_key') {
        const keyId = requireString(args, 'id');
        const result = await marrowRotateKey(API_KEY, BASE_URL, keyId, SESSION_ID, FLEET_AGENT_ID);
        success(id, {
          content: [{ type: 'text', text: JSON.stringify({ ...result, warning: formatKeyMaterialWarning() }, null, 2) }],
        });
        return;
      }

      // Memory control tools — all use requireString for id validation
      if (toolName === 'marrow_list_memories') {
        const result = await marrowListMemories(
          API_KEY, BASE_URL,
          { status: args.status as string, query: args.query as string, limit: args.limit as number, agentId: args.agentId as string },
          SESSION_ID
        );
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_get_memory') {
        const memId = requireString(args, 'id');
        const result = await marrowGetMemory(API_KEY, BASE_URL, memId, SESSION_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_update_memory') {
        const memId = requireString(args, 'id');
        const result = await marrowUpdateMemory(API_KEY, BASE_URL, memId,
          { text: args.text as string, source: args.source as string | null, tags: args.tags as string[], actor: args.actor as string, note: args.note as string },
          SESSION_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_delete_memory') {
        const memId = requireString(args, 'id');
        const result = await marrowDeleteMemory(API_KEY, BASE_URL, memId, { actor: args.actor as string, note: args.note as string }, SESSION_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_mark_outdated') {
        const memId = requireString(args, 'id');
        const result = await marrowMarkOutdated(API_KEY, BASE_URL, memId, { actor: args.actor as string, note: args.note as string }, SESSION_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_supersede_memory') {
        const memId = requireString(args, 'id');
        const newText = requireString(args, 'text');
        const result = await marrowSupersedeMemory(API_KEY, BASE_URL, memId,
          { text: newText, source: args.source as string, tags: args.tags as string[], actor: args.actor as string, note: args.note as string },
          SESSION_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_share_memory') {
        const memId = requireString(args, 'id');
        const result = await marrowShareMemory(API_KEY, BASE_URL, memId, (args.agentIds as string[]) || [], args.actor as string, SESSION_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_export_memories') {
        const result = await marrowExportMemories(API_KEY, BASE_URL,
          { format: args.format as string, status: args.status as string, tags: args.tags as string },
          SESSION_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_import_memories') {
        const result = await marrowImportMemories(API_KEY, BASE_URL,
          (args.memories as Array<{ text: string; source?: string; tags?: string[] }>) || [],
          (args.mode as 'merge' | 'replace') || 'merge',
          SESSION_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_retrieve_memories') {
        const query = requireString(args, 'query');
        const result = await marrowRetrieveMemories(API_KEY, BASE_URL, query,
          { limit: args.limit as number, from: args.from as string, to: args.to as string, tags: args.tags as string, source: args.source as string, status: args.status as string, shared: args.shared as boolean },
          SESSION_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_workflow') {
        const result = await marrowWorkflow(API_KEY, BASE_URL, {
          action: args.action as any,
          workflowId: args.workflowId as string,
          instanceId: args.instanceId as string,
          name: args.name as string,
          description: args.description as string,
          steps: args.steps as any,
          tags: args.tags as string[],
          agentId: args.agentId as string,
          context: args.context as Record<string, unknown>,
          inputs: args.inputs as Record<string, unknown>,
          stepCompleted: args.stepCompleted as number,
          outcome: args.outcome as string,
          nextAgentId: args.nextAgentId as string,
          contextUpdate: args.contextUpdate as Record<string, unknown>,
          status: args.status as string,
        }, SESSION_ID, FLEET_AGENT_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_dashboard') {
        const result = await marrowDashboard(API_KEY, BASE_URL, SESSION_ID, FLEET_AGENT_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_digest') {
        const result = await marrowDigest(API_KEY, BASE_URL, (args.period as string) || '7d', SESSION_ID, FLEET_AGENT_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_agent_status') {
        const result = await withControlDeadline(
          async (signal) => {
            const [analyticsStatus, context] = await Promise.all([
              marrowAgentStatus(
                API_KEY,
                BASE_URL,
                (args.period as string) || '7d',
                (args.agentId as string) || FLEET_AGENT_ID,
                SESSION_ID,
                FLEET_AGENT_ID,
                signal,
              ),
              marrowAgentContext(API_KEY, BASE_URL, SESSION_ID, FLEET_AGENT_ID, signal)
                .catch(() => null),
            ]);
            const contextProjection = recordValue(context)?.primary_tool_availability;
            return {
              ...analyticsStatus,
              ...(contextProjection === undefined ? {} : { primary_tool_availability: contextProjection }),
            };
          },
          { cacheAware: false, toolName: 'marrow_agent_status' },
        );
        success(id, { content: [{ type: 'text', text: JSON.stringify(withMcpToolProfileStatus({ ...result, local_control: localControlEvidence(Boolean(API_KEY)) }), null, 2) }] });
        return;
      }

      if (toolName === 'marrow_runtime_status') {
        const result = await withControlDeadline(
          (signal) => marrowRuntimeStatus(
            API_KEY,
            BASE_URL,
            args.fast !== false,
            SESSION_ID,
            FLEET_AGENT_ID,
            signal,
          ),
          { cacheAware: false, toolName: 'marrow_runtime_status' },
        );
        success(id, { content: [{ type: 'text', text: JSON.stringify(withMcpToolProfileStatus(result), null, 2) }] });
        return;
      }

      if (toolName === 'marrow_value_report') {
        const result = await marrowValueReport(
          API_KEY,
          BASE_URL,
          (args.period as string) || '7d',
          (args.agentId as string) || FLEET_AGENT_ID,
          SESSION_ID,
          FLEET_AGENT_ID
        );
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_decision_brief') {
        const result = await marrowDecisionBrief(
          API_KEY,
          BASE_URL,
          {
            action: args.action as string,
            type: args.type as string | undefined,
            role: args.role as string | undefined,
            agent_id: (args.agentId as string) || FLEET_AGENT_ID,
            session_id: (args.sessionId as string) || SESSION_ID,
            surfaces: Array.isArray(args.surfaces) ? args.surfaces as string[] : undefined,
            period: args.period as number | undefined,
          },
          SESSION_ID,
          FLEET_AGENT_ID
        );
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_first_value') {
        const result = await marrowFirstValue(
          API_KEY,
          BASE_URL,
          {
            action: args.action ? redactSensitiveText(args.action as string) : undefined,
            type: args.type as string | undefined,
            role: args.role as string | undefined,
            agent_id: (args.agentId as string) || FLEET_AGENT_ID,
            session_id: (args.sessionId as string) || SESSION_ID,
            surfaces: Array.isArray(args.surfaces) ? args.surfaces as string[] : undefined,
            context: args.context && typeof args.context === 'object' && !Array.isArray(args.context)
              ? redactSensitiveValue(args.context) as Record<string, unknown>
              : undefined,
            proof: args.proof && typeof args.proof === 'object' && !Array.isArray(args.proof)
              ? redactSensitiveValue(args.proof) as Record<string, unknown>
              : undefined,
          },
          SESSION_ID,
          FLEET_AGENT_ID
        );
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_agent_runtime') {
        const runtimeInput = {
            action: redactSensitiveText(args.action as string),
            type: args.type as string | undefined,
            role: args.role as string | undefined,
            agent_id: (args.agentId as string) || FLEET_AGENT_ID,
            session_id: (args.sessionId as string) || SESSION_ID,
            surfaces: Array.isArray(args.surfaces) ? args.surfaces as string[] : undefined,
            context: args.context && typeof args.context === 'object' && !Array.isArray(args.context)
              ? redactSensitiveValue(args.context) as Record<string, unknown>
              : undefined,
            proof: args.proof && typeof args.proof === 'object' && !Array.isArray(args.proof)
              ? redactSensitiveValue(args.proof) as Record<string, unknown>
              : undefined,
            period: args.period as number | undefined,
          };
        const result = await withControlDeadline(
          (signal) => marrowAgentRuntime(
            API_KEY,
            BASE_URL,
            runtimeInput,
            SESSION_ID,
            FLEET_AGENT_ID,
            signal,
          ),
          { highRisk: isHighRiskAction(runtimeInput.action, runtimeInput.type), toolName: 'marrow_agent_runtime' },
        );
        storeRuntimeGuidance(result);
        storeLastKnownStatus(result.status, 'runtime');
        toolSuccess(id, clientOperationalPayload('marrow_agent_runtime', result));
        return;
      }

      if (toolName === 'marrow_arbitrate') {
        const result = await marrowArbitrate(
          API_KEY,
          BASE_URL,
          {
            objective: redactSensitiveText(args.objective as string),
            owner_intent: typeof args.ownerIntent === 'string' ? redactSensitiveText(args.ownerIntent) : undefined,
            conflict_type: args.conflictType as 'action_conflict' | 'policy_conflict' | 'evidence_conflict' | 'authority_conflict' | 'risk_conflict' | undefined,
            proposals: Array.isArray(args.proposals)
              ? args.proposals as any
              : [],
            action: typeof args.action === 'string' ? redactSensitiveText(args.action) : undefined,
            type: args.type as string | undefined,
            agent_id: (args.agentId as string) || FLEET_AGENT_ID,
            session_id: (args.sessionId as string) || SESSION_ID,
            surfaces: Array.isArray(args.surfaces) ? args.surfaces as string[] : undefined,
            context: args.context && typeof args.context === 'object' && !Array.isArray(args.context)
              ? redactSensitiveValue(args.context) as Record<string, unknown>
              : undefined,
            proof: args.proof && typeof args.proof === 'object' && !Array.isArray(args.proof)
              ? redactSensitiveValue(args.proof) as Record<string, unknown>
              : undefined,
          },
          SESSION_ID,
          FLEET_AGENT_ID
        );
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_coordinate') {
        const coordinationArgs = { ...args };
        delete coordinationArgs.agent_id;
        delete coordinationArgs.source_agent_id;
        const result = await marrowCoordinate(
          API_KEY,
          BASE_URL,
          coordinationArgs,
          SESSION_ID,
          FLEET_AGENT_ID
        );
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_replay_compare') {
        const result = await marrowReplayCompare(
          API_KEY,
          BASE_URL,
          args,
          SESSION_ID,
          FLEET_AGENT_ID
        );
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_governance_control_plane') {
        const result = await marrowGovernanceControlPlane(API_KEY, BASE_URL, SESSION_ID, FLEET_AGENT_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_hermes_integration') {
        const result = await marrowHermesIntegration(API_KEY, BASE_URL, SESSION_ID, FLEET_AGENT_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_completion_contracts') {
        const result = await marrowCompletionContracts(API_KEY, BASE_URL, SESSION_ID, FLEET_AGENT_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_evaluate_completion_contract') {
        const input: Record<string, unknown> = {
          action: args.action as string | undefined,
          workflow_type: args.workflow_type as string | undefined,
          risk_level: args.risk_level as string | undefined,
          evidence: args.evidence && typeof args.evidence === 'object' && !Array.isArray(args.evidence)
            ? redactSensitiveValue(args.evidence) as Record<string, unknown>
            : undefined,
        };
        const result = await marrowEvaluateCompletionContract(API_KEY, BASE_URL, input, SESSION_ID, FLEET_AGENT_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_governance_timeline') {
        const result = await marrowGovernanceTimeline(
          API_KEY,
          BASE_URL,
          {
            agentId: (args.agentId as string) || FLEET_AGENT_ID,
            limit: args.limit as number | undefined,
          },
          SESSION_ID,
          FLEET_AGENT_ID
        );
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_decision_trace') {
        const decisionId = args.decisionId as string;
        if (!decisionId) { error(id, -32602, 'decisionId is required'); return; }
        const result = await marrowDecisionTrace(API_KEY, BASE_URL, decisionId, SESSION_ID, FLEET_AGENT_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_buyer_proof') {
        const result = await marrowBuyerProof(
          API_KEY,
          BASE_URL,
          {
            agentId: (args.agentId as string) || FLEET_AGENT_ID,
            periodDays: args.periodDays as number | undefined,
          },
          SESSION_ID,
          FLEET_AGENT_ID
        );
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_mode_recommend') {
        const result = await marrowRecommendGovernanceMode(
          API_KEY,
          BASE_URL,
          {
            project: args.project && typeof args.project === 'object' && !Array.isArray(args.project)
              ? redactSensitiveValue(args.project) as Record<string, unknown> as any
              : undefined,
            workflow: args.workflow && typeof args.workflow === 'object' && !Array.isArray(args.workflow)
              ? redactSensitiveValue(args.workflow) as Record<string, unknown> as any
              : undefined,
            agent: args.agent && typeof args.agent === 'object' && !Array.isArray(args.agent)
              ? redactSensitiveValue(args.agent) as Record<string, unknown> as any
              : { id: FLEET_AGENT_ID },
            selected_mode: args.selected_mode as any,
            selection_source: args.selection_source as any,
          },
          SESSION_ID,
          FLEET_AGENT_ID
        );
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_policy_profiles') {
        const result = await marrowListPolicyProfiles(API_KEY, BASE_URL, SESSION_ID, FLEET_AGENT_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_create_policy_profile') {
        const result = await marrowCreatePolicyProfile(
          API_KEY,
          BASE_URL,
          {
            name: args.name as string,
            description: args.description as string | undefined,
            rules: Array.isArray(args.rules) ? args.rules as any : undefined,
          },
          SESSION_ID,
          FLEET_AGENT_ID
        );
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_assign_project_policy_profile') {
        const result = await marrowAssignProjectPolicyProfile(
          API_KEY,
          BASE_URL,
          {
            project_key: args.project_key as string,
            profile_id: args.profile_id as string,
          },
          SESSION_ID,
          FLEET_AGENT_ID
        );
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_policy_resolve') {
        const result = await marrowResolvePolicy(
          API_KEY,
          BASE_URL,
          {
            profile_id: args.profile_id as string | undefined,
            profile_name: args.profile_name as string | undefined,
            project: args.project && typeof args.project === 'object' && !Array.isArray(args.project)
              ? redactSensitiveValue(args.project) as Record<string, unknown> as any
              : undefined,
            workflow: args.workflow && typeof args.workflow === 'object' && !Array.isArray(args.workflow)
              ? redactSensitiveValue(args.workflow) as Record<string, unknown> as any
              : undefined,
            agent: args.agent && typeof args.agent === 'object' && !Array.isArray(args.agent)
              ? redactSensitiveValue(args.agent) as Record<string, unknown> as any
              : { id: FLEET_AGENT_ID },
          },
          SESSION_ID,
          FLEET_AGENT_ID
        );
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_workflow_gate') {
        const result = await marrowWorkflowGate(
          API_KEY,
          BASE_URL,
          {
            action: redactSensitiveText(args.action as string),
            description: args.description ? redactSensitiveText(args.description as string) : undefined,
            risk_tolerance: args.riskTolerance as 'low' | 'medium' | 'high' | undefined,
            requires_approval: args.requiresApproval as boolean | undefined,
            context: args.context && typeof args.context === 'object' && !Array.isArray(args.context)
              ? redactSensitiveValue(args.context) as Record<string, unknown>
              : undefined,
          },
          SESSION_ID,
          FLEET_AGENT_ID
        );
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_agent_performance') {
        const result = await marrowAgentPerformance(
          API_KEY,
          BASE_URL,
          (args.period as string) || '7d',
          (args.agentId as string) || FLEET_AGENT_ID,
          SESSION_ID,
          FLEET_AGENT_ID
        );
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_fleet_lessons') {
        const result = await marrowFleetLessons(
          API_KEY,
          BASE_URL,
          {
            query: args.query as string | undefined,
            type: args.type as string | undefined,
            agentId: (args.agentId as string) || FLEET_AGENT_ID,
            limit: args.limit as number | undefined,
          },
          SESSION_ID,
          FLEET_AGENT_ID
        );
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_record_deployment_memory') {
        const result = await marrowRecordDeploymentMemory(API_KEY, BASE_URL, args, SESSION_ID, FLEET_AGENT_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_create_handoff') {
        const result = await marrowCreateHandoff(API_KEY, BASE_URL, args, SESSION_ID, FLEET_AGENT_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_update_handoff') {
        const handoffId = args.handoffId as string;
        if (!handoffId) { error(id, -32602, 'handoffId is required'); return; }
        const result = await marrowUpdateHandoff(API_KEY, BASE_URL, handoffId, args, SESSION_ID, FLEET_AGENT_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_handoff_status') {
        try {
          const result = await withControlDeadline(
            (signal) => marrowHandoffStatus(
              API_KEY,
              BASE_URL,
              {
                status: args.status as string | undefined,
                agentId: (args.agentId as string) || FLEET_AGENT_ID,
                limit: args.limit as number | undefined,
              },
              SESSION_ID,
              FLEET_AGENT_ID,
              signal,
            ),
            { cacheAware: false, toolName: 'marrow_handoff_status' },
          );
          toolSuccess(id, clientOperationalPayload('marrow_handoff_status', result));
        } catch (error) {
          if (error instanceof MarrowRequestError && error.backendCode === 'MARROW_PLAN_UPGRADE_REQUIRED') {
            toolSuccess(id, clientOperationalPayload('marrow_handoff_status', {
              ok: true,
              available: false,
              state: 'not_entitled',
              failure_kind: 'entitlement',
              authorization_state: 'plan_limited',
              credential_valid: true,
              feature: 'fleet_handoff_status',
              current_plan: error.currentPlan,
              required_plan: 'team',
              required_feature: error.requiredFeature || 'fleet_learning',
              service_reachable: true,
              exact_next_action: 'Use status, ask, runtime, auto, and commit on the current plan. Upgrade to Team before relying on fleet handoff status.',
            }));
          } else {
            throw error;
          }
        }
        return;
      }

      if (toolName === 'marrow_session_end') {
        const result = await marrowSessionEnd(API_KEY, BASE_URL, sessionEndAutoCommitOpen(args.autoCommitOpen), SESSION_ID, FLEET_AGENT_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_accept_detected') {
        const detectedId = args.detectedId as string;
        if (!detectedId) { error(id, -32602, 'detectedId is required'); return; }
        const result = await marrowAcceptDetected(API_KEY, BASE_URL, detectedId, SESSION_ID, FLEET_AGENT_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_list_templates') {
        const result = await marrowListTemplates(API_KEY, BASE_URL, {
          industry: args.industry as string | undefined,
          category: args.category as string | undefined,
          limit: args.limit as number | undefined,
        }, SESSION_ID, FLEET_AGENT_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      if (toolName === 'marrow_install_template') {
        const slug = args.slug as string;
        if (!slug) { error(id, -32602, 'slug is required'); return; }
        const result = await marrowInstallTemplate(API_KEY, BASE_URL, slug, SESSION_ID, FLEET_AGENT_ID);
        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
        return;
      }

      error(id, -32601, `Method not found: ${toolName}`);
      return;
    }

    error(id, -32601, `Method not found: ${method}`);
  } catch (err) {
    if (err instanceof MarrowRequestError && method === 'tools/call') {
      toolSuccess(id, toolFailure(params?.name, err), true);
      return;
    }
    const message = err instanceof Error ? err.message : String(err);
    error(id, -32602, redactSensitiveText(message).slice(0, 240));
  }
}

// MCP stdio loop — raw stdin, no readline (readline writes prompts to stdout which breaks MCP)
let buffer = '';
let pendingRequests = 0;
let stdinEnded = false;

function checkExit(): void {
  if (stdinEnded && pendingRequests === 0) {
    autoCommitOnClose().then(() => process.exit(0));
  }
}

process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk: string) => {
  buffer += chunk;
  const lines = buffer.split('\n');
  buffer = lines.pop() || ''; // keep incomplete line in buffer
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // [FIX #1] Wrap JSON.parse in try-catch to prevent crash on malformed input
    let msg;
    try {
      msg = JSON.parse(trimmed);
    } catch (parseErr) {
      process.stderr.write(`[marrow] JSON parse error: ${parseErr}\n`);
      send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
      continue;
    }

    // MCP notifications (no id) must be silently ignored per spec
    if (msg.id === undefined || msg.id === null) continue;
    pendingRequests++;
    handleRequest(msg)
      .catch((err) => {
        process.stderr.write(`[marrow] Handler error: ${err}\n`);
      })
      .finally(() => {
        pendingRequests--;
        checkExit();
      });
  }
});

process.stdin.on('end', () => {
  stdinEnded = true;
  if (buffer.trim()) {
    let msg;
    try {
      msg = JSON.parse(buffer.trim());
    } catch (err) {
      process.stderr.write(`[marrow] JSON parse error on remaining buffer: ${err}\n`);
      checkExit();
      return;
    }
    if (msg.id === undefined || msg.id === null) {
      checkExit();
      return;
    }
    pendingRequests++;
    handleRequest(msg)
      .catch((err) => {
        process.stderr.write(`[marrow] Handler error on remaining: ${err}\n`);
      })
      .finally(() => {
        pendingRequests--;
        checkExit();
      });
  } else {
    checkExit();
  }
});

process.stdin.on('error', (err) => {
  process.stderr.write(`[marrow] stdin error: ${err}\n`);
  process.exit(1);
});
} // Close the if (process.argv[2] !== 'keys') block
}
