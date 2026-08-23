/**
 * UserPromptSubmit hook — Marrow context injection.
 *
 * Fires whenever the user submits a message to the agent. Reads the prompt,
 * calls marrow_think, and returns matching warnings/patterns/insights as
 * `additionalContext` so the agent sees Marrow's intelligence in its prompt
 * window without ever calling a tool. Closes the passive read loop:
 *
 *   PostToolUse hook  → auto-LOG every action          (write side, V3.2)
 *   UserPromptSubmit  → auto-INJECT relevant context   (read side, V6.8)
 *
 * Both hooks are installed by `npx @getmarrow/mcp setup`. Either can be
 * disabled with `MARROW_AUTO_HOOK=false`.
 */

import { marrowAgentContext, marrowAgentRuntime, validateBaseUrl } from './index';
import type { MarrowAgentRuntimeResult, MarrowDecisionBriefResult, MarrowValueReportResult } from './types';
import { recordLifecycleEvent } from './lifecycle-spool';
import { readGuidanceCache, writeGuidanceCache } from './guidance-cache';
import {
  CONTEXT_HOOK_COMMAND as CONTRACT_CONTEXT_HOOK_COMMAND,
  findHookSettingsPath,
  nativeHookLifecycleIdentity,
  normalizeHookEventPayload,
  readHookSettingsForInstall,
  reconcileMarrowCommandHook,
  resolveNativeHookIdentity,
  stablePromptCorrelation,
  stableSessionWorkflowId,
} from './hook-contract';

export const CONTEXT_HOOK_COMMAND = CONTRACT_CONTEXT_HOOK_COMMAND;
const HOOK_DEBUG = process.env.MARROW_CONTEXT_HOOK_DEBUG === 'true' || process.env.MARROW_HOOK_DEBUG === 'true';
const MARROW_API_TIMEOUT_MS = 400;
const MAX_CONTEXT_BYTES = 4000; // safety cap on injected context size
const PASSIVE_BRIEF_MODE = process.env.MARROW_PASSIVE_BRIEF || 'auto';

const RISKY_PROMPT_TERMS = /\b(?:audit|auth|cloudflare|commit|config|credential|database|deploy|environment|github|incident|key|merge|migration|npm|package|patch|permission|production|publish|release|rollback|secret|security|token|upgrade|worker|write)\b/i;
const MUTATING_PROMPT_TERMS = /\b(?:add|apply|change|commit|configure|create|delete|deploy|edit|fix|harden|merge|modify|patch|publish|push|release|remove|rollback|rotate|ship|update|upgrade|write)\b/i;
const EXPLICIT_MUTATING_PROMPT_TERMS = /\b(?:add|apply|commit|configure|create|delete|edit|fix|harden|merge|modify|patch|publish|push|release|remove|rollback|rotate|ship|update|upgrade|write)\b|\bdeploy\s+(?:latest|release|to|worker|cloudflare|production|prod)\b/i;
const READ_ONLY_PROMPT_TERMS = /\b(?:analyze|assess|brainstorm|check|compare|describe|explain|inspect|look at|plan only|read|report on|review|review only|summarize|tell me|what are|what is|why|without changing|without editing|no changes|do not edit)\b/i;

interface UserPromptSubmitEvent {
  session_id?: string;
  hook_event_name?: string;
  prompt?: string;
}

interface InstallResult {
  settingsPath: string;
  installed: boolean;
}

function debug(msg: string): void {
  if (HOOK_DEBUG) process.stderr.write(msg + '\n');
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : undefined;
}

const CLIENT_VERSION_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

interface ParsedClientVersion {
  major: string;
  minor: string;
  patch: string;
  prerelease: string[] | null;
}

function parseClientVersion(value: unknown): ParsedClientVersion | null {
  const version = typeof value === 'string' ? value.trim() : '';
  if (version.length > 64) return null;
  const match = CLIENT_VERSION_PATTERN.exec(version);
  return match ? {
    major: match[1],
    minor: match[2],
    patch: match[3],
    prerelease: match[4] ? match[4].split('.') : null,
  } : null;
}

function strictClientVersion(value: unknown): string | undefined {
  const version = typeof value === 'string' ? value.trim() : '';
  return parseClientVersion(version) ? version : undefined;
}

function compareNumericIdentifier(left: string, right: string): number {
  if (left.length !== right.length) return left.length < right.length ? -1 : 1;
  return left === right ? 0 : left < right ? -1 : 1;
}

function compareClientVersions(left: string, right: string): number {
  const parsedLeft = parseClientVersion(left);
  const parsedRight = parseClientVersion(right);
  if (!parsedLeft || !parsedRight) throw new Error('compareClientVersions requires strict semantic versions');
  for (const key of ['major', 'minor', 'patch'] as const) {
    const compared = compareNumericIdentifier(parsedLeft[key], parsedRight[key]);
    if (compared !== 0) return compared;
  }
  if (!parsedLeft.prerelease && !parsedRight.prerelease) return 0;
  if (!parsedLeft.prerelease) return 1;
  if (!parsedRight.prerelease) return -1;
  const length = Math.max(parsedLeft.prerelease.length, parsedRight.prerelease.length);
  for (let index = 0; index < length; index += 1) {
    const leftIdentifier = parsedLeft.prerelease[index];
    const rightIdentifier = parsedRight.prerelease[index];
    if (leftIdentifier == null) return -1;
    if (rightIdentifier == null) return 1;
    if (leftIdentifier === rightIdentifier) continue;
    const leftNumeric = /^\d+$/.test(leftIdentifier);
    const rightNumeric = /^\d+$/.test(rightIdentifier);
    if (leftNumeric && rightNumeric) return compareNumericIdentifier(leftIdentifier, rightIdentifier);
    if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
    return leftIdentifier < rightIdentifier ? -1 : 1;
  }
  return 0;
}

function boundedClientCommand(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length > 240 || /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/.test(value)) return undefined;
  return value.trim() || undefined;
}

function validClientCommandTarget(value: string): boolean {
  return value === 'latest' || Boolean(strictClientVersion(value));
}

function strictClientUpdateCommand(value: unknown): string | undefined {
  const command = boundedClientCommand(value);
  if (!command) return undefined;
  const match = /^(?:npx @getmarrow\/install@(\S+) --repair|npx @getmarrow\/mcp@(\S+) setup|npx -y --package=@getmarrow\/mcp@(\S+) marrow-mcp setup|npm install @getmarrow\/sdk@(\S+))$/.exec(command);
  const target = match?.[1] || match?.[2] || match?.[3] || match?.[4];
  return target && validClientCommandTarget(target) ? command : undefined;
}

function strictClientVerificationCommand(value: unknown): string | undefined {
  const command = boundedClientCommand(value);
  if (!command) return undefined;
  const match = /^npx(?: -y)? @getmarrow\/install@(\S+) doctor(?: --self-test)?$/.exec(command);
  return match && validClientCommandTarget(match[1]) ? command : undefined;
}

async function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    process.stdin.on('data', (chunk: Buffer) => chunks.push(chunk));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', () => resolve(''));
    // No data after 100ms means no input — return empty (Claude Code may still pipe data shortly after start)
    setTimeout(() => resolve(Buffer.concat(chunks).toString('utf8')), 5000);
  });
}

interface ContextSignals {
  warnings: string[];
  loopWarnings: string[];
  similarCount: number;
  patternsCount: number;
  templatesAvailable: number;
  primaryInsight: string | null;
  collectiveInsight: string | null;
  hasSignal: boolean;
}

interface PassiveBriefInput {
  action: string;
  type: string;
  role: string;
  surfaces: string[];
}

function defaultRuntimeInput(prompt: string): PassiveBriefInput {
  const classification = classifyPrompt(prompt);
  return {
    action: classification.action,
    type: classification.type,
    role: classification.role,
    surfaces: classification.surfaces,
  };
}

function classifyPrompt(prompt: string): PassiveBriefInput {
  const lower = prompt.toLowerCase();
  let type = 'general';
  if (/\b(?:deploy|release|publish|cloudflare|worker|npm)\b/.test(lower)) type = 'deploy';
  else if (/\b(?:audit|security|secret|token|credential|permission|opsec)\b/.test(lower)) type = 'audit';
  else if (/\b(?:patch|fix|bug|harden|remediate)\b/.test(lower)) type = 'patch';
  else if (/\b(?:review|merge|pr|pull request)\b/.test(lower)) type = 'review';
  const surfaces = unique([
    /\b(?:github|git|merge|pr|pull request|commit|push)\b/.test(lower) ? 'github' : '',
    /\b(?:npm|package|publish|sdk|mcp)\b/.test(lower) ? 'npm' : '',
    /\b(?:doc|docs|readme|getmarrow\.ai)\b/.test(lower) ? 'docs' : '',
    /\b(?:prod|production|deploy|release|cloudflare|worker)\b/.test(lower) ? 'production' : '',
    /\b(?:secret|token|credential|key|permission)\b/.test(lower) ? 'secrets' : '',
  ]);
  const role = ['deploy', 'audit', 'patch', 'review'].includes(type) ? type : 'general';
  const resolvedSurfaces = surfaces.length > 0 ? surfaces : ['workspace'];
  return {
    action: `classified agent request: ${type} on ${resolvedSurfaces.join(', ')}`,
    type,
    role,
    surfaces: resolvedSurfaces,
  };
}

export function extractSignals(thinkResult: unknown): ContextSignals {
  const result = asRecord(thinkResult) || {};
  const intel = asRecord(result.intelligence) || {};

  const warnings = Array.isArray(result.warnings)
    ? result.warnings
        .map((w) => {
          const r = asRecord(w);
          return r ? asString(r.message) : undefined;
        })
        .filter((s): s is string => !!s)
    : [];

  const loopWarnings = Array.isArray(result.loop_warnings)
    ? result.loop_warnings
        .map((w) => {
          const r = asRecord(w);
          return r ? asString(r.message) : undefined;
        })
        .filter((s): s is string => !!s)
    : [];

  const similarCount = typeof intel.similar_count === 'number' ? intel.similar_count : 0;
  const patternsCount = typeof intel.patterns_count === 'number' ? intel.patterns_count : 0;
  const templates = Array.isArray(intel.templates) ? intel.templates.length : 0;
  const primaryInsight = asString(intel.insight) ?? null;

  const collective = asRecord(intel.collective);
  const collectiveInsight = collective ? asString(collective.insight) ?? null : null;

  const hasSignal =
    warnings.length > 0 ||
    loopWarnings.length > 0 ||
    similarCount > 0 ||
    patternsCount > 0 ||
    templates > 0 ||
    !!primaryInsight ||
    !!collectiveInsight;

  return {
    warnings,
    loopWarnings,
    similarCount,
    patternsCount,
    templatesAvailable: templates,
    primaryInsight,
    collectiveInsight,
    hasSignal,
  };
}

function buildContextBlock(signals: ContextSignals): string {
  const lines: string[] = ['## Marrow context for this request'];

  if (signals.loopWarnings.length > 0) {
    for (const w of signals.loopWarnings.slice(0, 2)) {
      lines.push(`- 🚨 Loop detected: ${w}`);
    }
  }

  if (signals.warnings.length > 0) {
    for (const w of signals.warnings.slice(0, 3)) {
      lines.push(`- ⚠️ ${w}`);
    }
  }

  if (signals.primaryInsight) {
    lines.push(`- ${signals.primaryInsight}`);
  }

  if (signals.collectiveInsight) {
    lines.push(`- Hive: ${signals.collectiveInsight}`);
  }

  if (signals.similarCount > 0) {
    lines.push(`- Marrow has ${signals.similarCount} similar past decision${signals.similarCount === 1 ? '' : 's'} for this kind of action.`);
  }

  if (signals.patternsCount > 0) {
    lines.push(`- ${signals.patternsCount} pattern${signals.patternsCount === 1 ? '' : 's'} from your history match this task type.`);
  }

  if (signals.templatesAvailable > 0) {
    lines.push(`- ${signals.templatesAvailable} installed workflow template${signals.templatesAvailable === 1 ? '' : 's'} relevant — consider using marrow_workflow.`);
  }

  lines.push('');
  lines.push('Use this context to avoid repeating known failures and to leverage past successful patterns.');

  let block = lines.join('\n');
  if (block.length > MAX_CONTEXT_BYTES) {
    block = block.slice(0, MAX_CONTEXT_BYTES - 1) + '…';
  }
  return block;
}

function unique(values: string[]): string[] {
  return Array.from(new Set(values.filter(Boolean)));
}

function inferPassiveBriefInput(prompt: string): PassiveBriefInput | null {
  const classification = classifyPrompt(prompt);
  const isRisky = RISKY_PROMPT_TERMS.test(prompt);
  const isMutating = MUTATING_PROMPT_TERMS.test(prompt);
  const isExplicitlyMutating = EXPLICIT_MUTATING_PROMPT_TERMS.test(prompt);
  const isReadOnly = READ_ONLY_PROMPT_TERMS.test(prompt);

  const shouldBrief =
    PASSIVE_BRIEF_MODE === 'always' ||
    (PASSIVE_BRIEF_MODE !== 'false' && isRisky && (isReadOnly ? isExplicitlyMutating : isMutating));

  if (!shouldBrief) return null;

  return classification;
}

function appendPassiveBrief(lines: string[], brief: MarrowDecisionBriefResult | null): void {
  if (!brief) return;

  lines.push('');
  lines.push('## Marrow passive decision brief');
  lines.push(`- Risk: ${brief.risk.level}${brief.risk.reasons.length ? ` — ${brief.risk.reasons.slice(0, 2).join('; ')}` : ''}`);
  lines.push(`- Workflow: ${brief.workflow.recommended}`);

  for (const step of brief.workflow.steps.slice(0, 4)) {
    lines.push(`  - ${step}`);
  }

  if (brief.handoff.required) {
    lines.push(`- Handoff required. Checkpoint markers: ${brief.handoff.checkpoint_markers.slice(0, 5).join(', ')}`);
  }

  if (brief.freshness.check_required) {
    lines.push(`- Freshness required for: ${brief.freshness.surfaces.join(', ')}`);
  }

  if (brief.quality.minimum_checks.length > 0) {
    lines.push(`- Minimum checks: ${brief.quality.minimum_checks.slice(0, 5).join('; ')}`);
  }

  if (brief.proof_pack.required) {
    lines.push(`- Proof pack fields: ${brief.proof_pack.fields.slice(0, 6).join(', ')}`);
  }

  if (brief.next_actions.length > 0) {
    lines.push(`- Next: ${brief.next_actions.slice(0, 3).join('; ')}`);
  }

  lines.push('- Continue the Marrow loop: log intent, do the work, verify, then commit the outcome.');
}

function appendAgentRuntime(lines: string[], runtime: MarrowAgentRuntimeResult | null): void {
  if (!runtime) return;
  lines.push('');
  lines.push('## Marrow agent runtime');
  const runtimeRecord = asRecord(runtime);
  const habit = asRecord(runtimeRecord?.habit_loop);
  const firstHour = asRecord(habit?.first_hour) || asRecord(runtimeRecord?.first_hour);
  if (habit && (habit.interrupt === true || firstHour)) {
    if (asString(habit.headline)) lines.push(`- Habit: ${asString(habit.headline)}`);
    const savings = asRecord(habit.session_savings);
    if (savings && savings.evidence_backed !== true) {
      lines.push('- Empty savings are healthy. Do not invent token counts.');
    }
    if (asString(habit.exact_next_action)) lines.push(`- First-hour next: ${asString(habit.exact_next_action)}`);
  }
  if (runtime.intervention) {
    lines.push(`Intervention: ${runtime.intervention.decision}. ${runtime.intervention.agent_copy || runtime.intervention.headline}`);
    lines.push(`- Contract: ${runtime.intervention.contract}`);
    if (runtime.intervention.must_use_before_action) {
      lines.push('Action gate: REQUIRED. Apply this Marrow intervention before acting.');
      lines.push('Do not proceed until the intervention, lesson, playbook, or proof requirement is applied. If it cannot be applied, stop and report the work as blocked.');
    }
    if (runtime.intervention.playbook?.source) {
      lines.push(`- Playbook source: ${runtime.intervention.playbook.source}`);
    }
    if (Array.isArray(runtime.intervention.playbook?.required_steps) && runtime.intervention.playbook.required_steps.length > 0) {
      lines.push(`- Required steps: ${runtime.intervention.playbook.required_steps.slice(0, 5).join('; ')}`);
    }
    if (Array.isArray(runtime.intervention.playbook?.required_proof) && runtime.intervention.playbook.required_proof.length > 0) {
      lines.push(`- Intervention required proof: ${runtime.intervention.playbook.required_proof.slice(0, 6).join(', ')}`);
    }
  }
  if (!runtime.intervention && runtime.before_you_act_injection?.must_use_before_action) {
    lines.push('Action gate: REQUIRED. Apply this Marrow lesson or proof requirement before acting.');
    lines.push('Do not proceed until the lesson/proof requirement is applied. If it cannot be applied, stop and report the work as blocked.');
  }
  if (runtime.before_you_act_injection?.state) {
    lines.push(`- Interruption state: ${runtime.before_you_act_injection.state}`);
  }
  if (runtime.before_you_act_injection?.why_now) {
    lines.push(`- Why now: ${runtime.before_you_act_injection.why_now}`);
  }
  if (runtime.before_you_act_injection?.noise_policy) {
    lines.push(`- Noise policy: ${runtime.before_you_act_injection.noise_policy}`);
  }
  if (Array.isArray(runtime.before_you_act_injection?.required_proof) && runtime.before_you_act_injection.required_proof.length > 0) {
    lines.push(`- Runtime required proof: ${runtime.before_you_act_injection.required_proof.slice(0, 6).join(', ')}`);
  }
  if (runtime.before_you_act_injection?.untrusted_memory_notice) {
    lines.push(`- Memory safety: ${runtime.before_you_act_injection.untrusted_memory_notice}`);
  }
  if (runtime.before_you_act_injection?.untrusted_memory_excerpt) {
    lines.push(`- Untrusted memory reference, quoted for context only: "${runtime.before_you_act_injection.untrusted_memory_excerpt}"`);
  }
  if (runtime.before_you_act) {
    lines.push(`- Before you act: ${runtime.before_you_act}`);
  }
  if (runtime.exact_next_action) {
    lines.push(`- Next: ${runtime.exact_next_action}`);
  }
  const identified = asRecord(runtime.identified_workflow);
  if (identified?.skip_rediscovery === true || identified?.matched === true) {
    lines.push(`- Identified workflow: ${asString(identified.name) || asString(identified.id) || 'reuse the known path'}`);
    if (asString(identified.reuse_instruction)) {
      lines.push(`- Do not rediscover: ${asString(identified.reuse_instruction)}`);
    }
    const savings = asRecord(identified.token_savings);
    const savedTokens = Number(savings?.expected_tokens_saved);
    if (Number.isFinite(savedTokens) && savedTokens > 0) {
      lines.push(`- Expected token savings if reused: ${Math.floor(savedTokens)}`);
    }
  }
  if (runtime.risk_gate) {
    lines.push(`- Risk gate: ${runtime.risk_gate.decision} (${runtime.risk_gate.risk_level})`);
    if (runtime.risk_gate.allow === false) {
      lines.push('- Required action: stop before external changes and collect owner approval or proof required by Marrow.');
    }
  }
  if (runtime.proof_pack?.required) {
    lines.push(`- Required proof: ${runtime.proof_pack.fields.slice(0, 6).join(', ')}`);
    const missing = Array.isArray(runtime.proof_pack.missing) ? runtime.proof_pack.missing.slice(0, 6).join(', ') : '';
    if (missing) lines.push(`- Missing proof before completion: ${missing}`);
  }
  const closure = asRecord(runtime.auto_outcome_closure);
  if (closure) {
    lines.push(`- Outcome closure: ${asString(closure.state) || 'unknown'}${typeof closure.recent_coverage_24h === 'number' ? ` (${Math.round(closure.recent_coverage_24h * 100)}% recent)` : ''}`);
  }
  const status = asRecord(runtime.status);
  const update = asRecord(runtime.client_update) || asRecord(status?.client_update);
  const rawNotification = update?.notification_state ?? update?.notification;
  const notification = rawNotification === 'unknown' || rawNotification === 'version_unknown' || rawNotification === 'recommended' || rawNotification === 'security_required' || rawNotification === 'none'
    ? rawNotification
    : undefined;
  const versionStatus = update?.version_status === 'unknown' || update?.version_status === 'behind' || update?.version_status === 'current' || update?.version_status === 'ahead'
    ? update.version_status
    : undefined;
  const currentVersion = strictClientVersion(update?.installed_version) || strictClientVersion(update?.current_version);
  const latestVersion = strictClientVersion(update?.latest_version);
  const versionComparison = currentVersion && latestVersion
    ? compareClientVersions(currentVersion, latestVersion)
    : null;
  const securityPolicy = asRecord(update?.security_policy);
  const minimumSecureVersion = strictClientVersion(securityPolicy?.minimum_secure_version);
  const coherentVersionStatus = versionStatus === 'behind'
    ? versionComparison != null && versionComparison < 0
    : versionStatus === 'current'
    ? versionComparison === 0
    : versionStatus === 'ahead'
    ? versionComparison != null && versionComparison > 0
    : versionStatus === 'unknown';
  const versionUnknown = versionStatus === 'unknown' || notification === 'unknown' || notification === 'version_unknown';
  const explicitSecurityPolicy = securityPolicy?.source === 'server_policy'
    && versionStatus === 'behind'
    && coherentVersionStatus
    && Boolean(currentVersion && latestVersion && minimumSecureVersion)
    && compareClientVersions(currentVersion!, minimumSecureVersion!) < 0
    && compareClientVersions(minimumSecureVersion!, latestVersion!) <= 0;
  const priority = versionUnknown
    ? 'version_unknown'
    : notification === 'security_required' && update?.update_available === true && coherentVersionStatus && Boolean(currentVersion && latestVersion) && explicitSecurityPolicy
    ? 'security_required'
    : notification === 'recommended' && versionStatus === 'behind' && update?.update_available === true && coherentVersionStatus && versionComparison != null && versionComparison < 0
    ? 'recommended'
    : null;
  if (update && priority) {
    const current = currentVersion || 'unknown';
    const latest = latestVersion || 'unknown';
    const updateSummary = priority === 'version_unknown'
      ? 'Marrow client version unrecognized'
      : priority === 'security_required'
      ? 'Marrow client update required by server policy'
      : 'Marrow client update available';
    lines.push(`- ${updateSummary}: installed=${current}; latest=${latest}. Hosted Marrow services are already current; no local changes were applied.`);
    const updateCommand = strictClientUpdateCommand(update.update_command) || strictClientUpdateCommand(update.exact_update_command);
    const verifyCommand = strictClientVerificationCommand(update.verification_command) || strictClientVerificationCommand(update.exact_verification_command);
    if (updateCommand) lines.push(`- Update command (operator approval): ${updateCommand}`);
    if (verifyCommand) lines.push(`- Verify after update: ${verifyCommand}`);
  }
}

export function buildCombinedContextBlock(
  signals: ContextSignals,
  brief: MarrowDecisionBriefResult | null,
  valueReport: MarrowValueReportResult | null,
  runtime: MarrowAgentRuntimeResult | null = null
): string {
  const lines = buildContextBlock(signals).split('\n');
  appendAgentRuntime(lines, runtime);
  appendPassiveBrief(lines, brief);
  appendValueSummary(lines, valueReport);

  let block = lines.join('\n');
  if (block.length > MAX_CONTEXT_BYTES) {
    block = block.slice(0, MAX_CONTEXT_BYTES - 1) + '…';
  }
  return block;
}

function emitNoContext(): void {
  process.stdout.write('{}');
}

function emitContext(context: string): void {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'UserPromptSubmit',
      additionalContext: context,
    },
  }));
}

/**
 * Race a promise against a timeout. If timeout fires first, returns null.
 */
async function withTimeout<T>(operation: (signal: AbortSignal) => Promise<T>, ms: number): Promise<{
  value: T | null;
  error: unknown;
  timedOut: boolean;
}> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | null = null;
  try {
    const value = await Promise.race([
      operation(controller.signal),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new Error(`Marrow request timed out after ${ms}ms`));
        }, ms);
        timer.unref?.();
      }),
    ]);
    return { value, error: null, timedOut: false };
  } catch (error) {
    return { value: null, error, timedOut: error instanceof Error && /timed out|abort/i.test(error.message) };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function isAuthenticationFailure(error: unknown): boolean {
  return error instanceof Error && /\b(?:401|403|unauthorized|forbidden|invalid api key|insufficient scope)\b/i.test(error.message);
}

export function compactRuntimeContext(runtime: MarrowAgentRuntimeResult): string {
  const intervention = runtime.intervention;
  const lines = ['## Marrow before-action'];
  const decision = intervention?.decision || runtime.risk_gate?.decision || 'review_required';
  lines.push(`- Decision: ${decision}; risk: ${runtime.risk_gate?.risk_level || runtime.decision_brief?.risk?.level || 'unknown'}.`);
  const why = intervention?.before_action || intervention?.headline || runtime.before_you_act || runtime.decision_brief?.summary;
  if (why) lines.push(`- Why: ${String(why).slice(0, 320)}`);
  const steps = intervention?.playbook?.required_steps || runtime.decision_brief?.workflow?.steps || [];
  if (steps.length) lines.push(`- Apply: ${steps.slice(0, 2).join('; ').slice(0, 360)}`);
  const proof = runtime.proof_pack?.fields || intervention?.playbook?.required_proof || [];
  if (proof.length) lines.push(`- Proof: ${proof.slice(0, 4).join(', ')}`);
  const next = intervention?.exact_next_action || runtime.exact_next_action || runtime.decision_brief?.next_actions?.[0];
  if (next) lines.push(`- Next: ${String(next).slice(0, 320)}`);
  lines.push('- Record the measured outcome after meaningful work.');
  return lines.slice(0, 8).join('\n').slice(0, 1_600);
}

function compactAgentContext(context: Record<string, unknown>): string {
  const status = asRecord(context.status);
  const policy = asRecord(context.effective_policy);
  const lines = ['## Marrow fleet context'];
  lines.push(`- Health: ${asString(status?.health) || (status?.ok === true ? 'healthy' : 'available')}.`);
  const policyMode = asString(policy?.mode) || asString(policy?.governance_mode);
  if (policyMode) lines.push(`- Active governance mode: ${policyMode}.`);
  const warning = Array.isArray(status?.failure_reasons) ? asRecord(status.failure_reasons[0]) : null;
  if (warning?.message) lines.push(`- Warning: ${String(warning.message).slice(0, 320)}`);
  const next = asString(context.exact_next_action) || asString(status?.next_action);
  if (next) lines.push(`- Next: ${next.slice(0, 360)}`);
  lines.push('- Use a fresh Marrow runtime gate before high-risk or state-changing work.');
  return lines.slice(0, 7).join('\n').slice(0, 1_400);
}

export async function runContextHookCommand(): Promise<void> {
  // Kill switch — same flag as PostToolUse
  if (process.env.MARROW_AUTO_HOOK === 'false') {
    emitNoContext();
    process.exit(0);
    return;
  }

  try {
    const raw = (await readStdin()).trim();
    if (!raw) {
      debug('[marrow-context-hook] no stdin');
      emitNoContext();
      process.exit(0);
      return;
    }

    let event: UserPromptSubmitEvent;
    try {
      event = normalizeHookEventPayload(JSON.parse(raw)) as UserPromptSubmitEvent;
    } catch {
      debug('[marrow-context-hook] invalid JSON');
      emitNoContext();
      process.exit(0);
      return;
    }

    const prompt = asString(event.prompt);
    if (!prompt) {
      debug('[marrow-context-hook] no prompt field');
      emitNoContext();
      process.exit(0);
      return;
    }

    const identity = resolveNativeHookIdentity(process.argv[2]);
    const resolvedEnv = identity.environment;
    const apiKey = resolvedEnv.apiKey || '';
    if (!apiKey) {
      debug(`[marrow-context-hook] missing MARROW_API_KEY. ${resolvedEnv.exactFix}`);
      emitNoContext();
      process.exit(0);
      return;
    }

    const baseUrl = validateBaseUrl(resolvedEnv.baseUrl || 'https://api.getmarrow.ai');
    const sessionId = resolvedEnv.sessionId || asString(event.session_id);
    const agentId = identity.agent_id;

    const passiveBriefInput = inferPassiveBriefInput(prompt);
    const runtimeInput = passiveBriefInput || defaultRuntimeInput(prompt);
    const requestCorrelation = stablePromptCorrelation({ session_id: sessionId, prompt });
    const workflowId = stableSessionWorkflowId(sessionId, requestCorrelation);
    void recordLifecycleEvent({
      apiKey,
      baseUrl,
      deferDelivery: true,
      event: {
        event_id: `prompt-${requestCorrelation}`,
        event_type: 'prompt_submitted',
        ...nativeHookLifecycleIdentity(identity, 'prompt'),
        session_id: sessionId,
        workflow_id: workflowId,
        correlation_id: requestCorrelation,
        action: `user prompt submitted: ${passiveBriefInput?.type || 'general'}`,
        risk_level: passiveBriefInput ? 'medium' : 'low',
        outcome_state: 'pending',
      },
    }).catch(() => {});
    const live = passiveBriefInput && process.env.MARROW_AGENT_RUNTIME !== 'false'
      ? await withTimeout(
          (signal) => marrowAgentRuntime(apiKey, baseUrl, runtimeInput, sessionId, agentId, signal),
          MARROW_API_TIMEOUT_MS,
        )
      : await withTimeout(
          (signal) => marrowAgentContext(apiKey, baseUrl, sessionId, agentId, signal),
          MARROW_API_TIMEOUT_MS,
        );

    let context = live.value
      ? passiveBriefInput
        ? compactRuntimeContext(live.value as MarrowAgentRuntimeResult)
        : compactAgentContext(live.value as Record<string, unknown>)
      : '';
    if (context) {
      try { writeGuidanceCache({ apiKey, baseUrl, agentId, context }); } catch { /* cache is best effort */ }
    } else if (!isAuthenticationFailure(live.error)) {
      let cached: { context: string; stale_ms: number } | null = null;
      try { cached = readGuidanceCache({ apiKey, baseUrl, agentId }); } catch { /* cache is best effort */ }
      if (cached) {
        const staleSeconds = Math.max(1, Math.round(cached.stale_ms / 1000));
        const staleWarning = passiveBriefInput
          ? '- Fresh Marrow authorization is unavailable. Cached guidance cannot authorize high-risk action.'
          : '- Live Marrow read unavailable; using clearly labeled last-known guidance.';
        context = `## Marrow cached guidance (stale ${staleSeconds}s)\n${staleWarning}\n${cached.context.replace(/^##[^\n]*\n?/, '')}`.slice(0, 1_600);
      }
    }

    if (!context) {
      debug(`[marrow-context-hook] governance read unavailable${live.timedOut ? ' (timeout)' : ''}`);
      emitNoContext();
      process.exit(0);
      return;
    }

    if (passiveBriefInput && live.value) {
      void recordLifecycleEvent({
        apiKey,
        baseUrl,
        deferDelivery: true,
        event: {
          event_id: `preaction-${requestCorrelation}`,
          event_type: 'pre_action_checked',
          ...nativeHookLifecycleIdentity(identity, 'prompt'),
          session_id: sessionId,
          workflow_id: workflowId,
          correlation_id: requestCorrelation,
          action: `pre-action check: ${passiveBriefInput?.type || 'general'}`,
          risk_level: (live.value as MarrowAgentRuntimeResult).risk_gate?.risk_level,
          outcome_state: 'pending',
        },
      }).catch(() => {});
    }
    debug(`[marrow-context-hook] injected ${context.length} bytes of context`);
    emitContext(context);
    process.exit(0);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    debug(`[marrow-context-hook] ${msg}`);
    emitNoContext();
    process.exit(0);
  }
}

function appendValueSummary(lines: string[], report: MarrowValueReportResult | null): void {
  if (!report) return;
  lines.push('');
  lines.push('## Marrow value summary');
  lines.push(`- ${report.summary}`);
  lines.push(`- Decisions: ${report.metrics.decisions.total}; success rate: ${Math.round(report.metrics.success_rate * 100)}%; saves: ${report.metrics.saves.period}.`);
  if (report.recommendations.length > 0) {
    lines.push(`- Next improvement: ${report.recommendations[0]}`);
  }
}

/**
 * Idempotent installer. Adds (or upgrades to) the UserPromptSubmit hook entry
 * in `.claude/settings.json`. Call this from the same setup command that
 * installs the PostToolUse hook.
 */
export function installUserPromptSubmitHook(startDir: string = process.cwd()): InstallResult {
  const fs = require('fs') as typeof import('fs');
  const path = require('path') as typeof import('path');

  const settingsPath = findHookSettingsPath(startDir);
  const settings = readHookSettingsForInstall(startDir);

  const hooks = asRecord(settings.hooks) || {};
  const reconciled = reconcileMarrowCommandHook(
    settings,
    'UserPromptSubmit',
    'context-hook',
    CONTEXT_HOOK_COMMAND,
  );

  settings.hooks = {
    ...hooks,
    UserPromptSubmit: reconciled.entries,
  };

  fs.mkdirSync(path.dirname(settingsPath), { recursive: true });
  fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + '\n');

  return {
    settingsPath,
    installed: reconciled.changed,
  };
}
