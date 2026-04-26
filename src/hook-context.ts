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

import { marrowThink, validateBaseUrl } from './index';

export const CONTEXT_HOOK_COMMAND = 'npx -y @getmarrow/mcp context-hook';
const HOOK_DEBUG = process.env.MARROW_CONTEXT_HOOK_DEBUG === 'true';
const MARROW_API_TIMEOUT_MS = 2000;
const MAX_CONTEXT_BYTES = 4000; // safety cap on injected context size

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

function extractSignals(thinkResult: unknown): ContextSignals {
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
async function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T | null> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), ms);
    promise
      .then((value) => {
        clearTimeout(timer);
        resolve(value);
      })
      .catch(() => {
        clearTimeout(timer);
        resolve(null);
      });
  });
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
      event = JSON.parse(raw) as UserPromptSubmitEvent;
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

    const apiKey = process.env.MARROW_API_KEY || '';
    if (!apiKey) {
      debug('[marrow-context-hook] missing MARROW_API_KEY');
      emitNoContext();
      process.exit(0);
      return;
    }

    const baseUrl = validateBaseUrl(process.env.MARROW_BASE_URL || 'https://api.getmarrow.ai');
    const sessionId = process.env.MARROW_SESSION_ID || asString(event.session_id);
    const agentId = process.env.MARROW_FLEET_AGENT_ID || undefined;

    // Truncate prompt for the action field (Marrow think actions don't need full multi-K-token prompts)
    const action = prompt.length > 500 ? prompt.slice(0, 500) + '…' : prompt;

    const thinkResult = await withTimeout(
      marrowThink(apiKey, baseUrl, { action, type: 'general' }, sessionId, agentId),
      MARROW_API_TIMEOUT_MS
    );

    if (!thinkResult) {
      debug('[marrow-context-hook] marrow_think timed out or errored');
      emitNoContext();
      process.exit(0);
      return;
    }

    const signals = extractSignals(thinkResult);
    if (!signals.hasSignal) {
      debug('[marrow-context-hook] no signal — no context to inject');
      emitNoContext();
      process.exit(0);
      return;
    }

    const context = buildContextBlock(signals);
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

/**
 * Idempotent installer. Adds (or upgrades to) the UserPromptSubmit hook entry
 * in `.claude/settings.json`. Call this from the same setup command that
 * installs the PostToolUse hook.
 */
export function installUserPromptSubmitHook(startDir: string = process.cwd()): InstallResult {
  const fs = require('fs') as typeof import('fs');
  const path = require('path') as typeof import('path');

  // Re-implement findSettingsPath here to avoid circular dependency on hook.ts
  let dir = startDir;
  let settingsPath: string | null = null;
  for (let i = 0; i < 5; i++) {
    const candidate = path.join(dir, '.claude', 'settings.json');
    const projectMarker = path.join(dir, '.git');
    const claudeDir = path.join(dir, '.claude');
    if (fs.existsSync(candidate) || fs.existsSync(claudeDir) || fs.existsSync(projectMarker)) {
      settingsPath = candidate;
      break;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  if (!settingsPath) {
    settingsPath = path.join(startDir, '.claude', 'settings.json');
  }

  let settings: Record<string, unknown> = {};
  if (fs.existsSync(settingsPath)) {
    const raw = fs.readFileSync(settingsPath, 'utf8').trim();
    if (raw) {
      const parsed = JSON.parse(raw);
      const record = asRecord(parsed);
      if (!record) {
        throw new Error(`Existing settings file is not a JSON object: ${settingsPath}`);
      }
      settings = record;
    }
  }

  const hooks = asRecord(settings.hooks) || {};
  const userPromptSubmit = Array.isArray(hooks.UserPromptSubmit) ? [...hooks.UserPromptSubmit] : [];

  const alreadyInstalled = userPromptSubmit.some((entry) => {
    const record = asRecord(entry);
    if (!record || !Array.isArray(record.hooks)) return false;
    return record.hooks.some((hook) => {
      const hookRecord = asRecord(hook);
      return !!(hookRecord && typeof hookRecord.command === 'string' && hookRecord.command.includes(CONTEXT_HOOK_COMMAND));
    });
  });

  if (!alreadyInstalled) {
    userPromptSubmit.push({
      hooks: [{ type: 'command', command: CONTEXT_HOOK_COMMAND }],
    });
  }

  settings.hooks = {
    ...hooks,
    UserPromptSubmit: userPromptSubmit,
  };

  fs.mkdirSync(path.dirname(settingsPath), { recursive: true });
  fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + '\n');

  return {
    settingsPath,
    installed: !alreadyInstalled,
  };
}
