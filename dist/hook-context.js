"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.CONTEXT_HOOK_COMMAND = void 0;
exports.runContextHookCommand = runContextHookCommand;
exports.installUserPromptSubmitHook = installUserPromptSubmitHook;
const index_1 = require("./index");
const redact_1 = require("./redact");
exports.CONTEXT_HOOK_COMMAND = 'npx -y @getmarrow/mcp context-hook';
const HOOK_DEBUG = process.env.MARROW_CONTEXT_HOOK_DEBUG === 'true' || process.env.MARROW_HOOK_DEBUG === 'true';
const MARROW_API_TIMEOUT_MS = 2000;
const MAX_CONTEXT_BYTES = 4000; // safety cap on injected context size
const PASSIVE_BRIEF_MODE = process.env.MARROW_PASSIVE_BRIEF || 'auto';
const PASSIVE_VALUE_MODE = process.env.MARROW_PASSIVE_VALUE_SUMMARY || 'auto';
const RISKY_PROMPT_TERMS = /\b(?:audit|auth|cloudflare|commit|config|credential|database|deploy|environment|github|incident|key|merge|migration|npm|package|patch|permission|production|publish|release|rollback|secret|security|token|upgrade|worker|write)\b/i;
const MUTATING_PROMPT_TERMS = /\b(?:add|apply|change|commit|configure|create|delete|deploy|edit|fix|harden|merge|modify|patch|publish|push|release|remove|rollback|rotate|ship|update|upgrade|write)\b/i;
const EXPLICIT_MUTATING_PROMPT_TERMS = /\b(?:add|apply|commit|configure|create|delete|edit|fix|harden|merge|modify|patch|publish|push|release|remove|rollback|rotate|ship|update|upgrade|write)\b|\bdeploy\s+(?:latest|release|to|worker|cloudflare|production|prod)\b/i;
const READ_ONLY_PROMPT_TERMS = /\b(?:analyze|assess|brainstorm|check|compare|describe|explain|inspect|look at|plan only|read|report on|review|review only|summarize|tell me|what are|what is|why|without changing|without editing|no changes|do not edit)\b/i;
function debug(msg) {
    if (HOOK_DEBUG)
        process.stderr.write(msg + '\n');
}
function asRecord(value) {
    return value && typeof value === 'object' && !Array.isArray(value)
        ? value
        : null;
}
function asString(value) {
    return typeof value === 'string' && value.trim().length > 0 ? value.trim() : undefined;
}
async function readStdin() {
    return new Promise((resolve) => {
        const chunks = [];
        process.stdin.on('data', (chunk) => chunks.push(chunk));
        process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        process.stdin.on('error', () => resolve(''));
        // No data after 100ms means no input — return empty (Claude Code may still pipe data shortly after start)
        setTimeout(() => resolve(Buffer.concat(chunks).toString('utf8')), 5000);
    });
}
function defaultRuntimeInput(prompt) {
    const redactedPrompt = (0, redact_1.redactSensitiveText)(prompt);
    const action = redactedPrompt.length > 500 ? redactedPrompt.slice(0, 500) + '…' : redactedPrompt;
    return {
        action,
        type: 'general',
        role: 'general',
        surfaces: ['workspace'],
    };
}
function extractSignals(thinkResult) {
    const result = asRecord(thinkResult) || {};
    const intel = asRecord(result.intelligence) || {};
    const warnings = Array.isArray(result.warnings)
        ? result.warnings
            .map((w) => {
            const r = asRecord(w);
            return r ? asString(r.message) : undefined;
        })
            .filter((s) => !!s)
        : [];
    const loopWarnings = Array.isArray(result.loop_warnings)
        ? result.loop_warnings
            .map((w) => {
            const r = asRecord(w);
            return r ? asString(r.message) : undefined;
        })
            .filter((s) => !!s)
        : [];
    const similarCount = typeof intel.similar_count === 'number' ? intel.similar_count : 0;
    const patternsCount = typeof intel.patterns_count === 'number' ? intel.patterns_count : 0;
    const templates = Array.isArray(intel.templates) ? intel.templates.length : 0;
    const primaryInsight = asString(intel.insight) ?? null;
    const collective = asRecord(intel.collective);
    const collectiveInsight = collective ? asString(collective.insight) ?? null : null;
    const hasSignal = warnings.length > 0 ||
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
function buildContextBlock(signals) {
    const lines = ['## Marrow context for this request'];
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
function unique(values) {
    return Array.from(new Set(values.filter(Boolean)));
}
function inferPassiveBriefInput(prompt) {
    const redactedPrompt = (0, redact_1.redactSensitiveText)(prompt);
    const action = redactedPrompt.length > 500 ? redactedPrompt.slice(0, 500) + '…' : redactedPrompt;
    const lower = prompt.toLowerCase();
    const isRisky = RISKY_PROMPT_TERMS.test(prompt);
    const isMutating = MUTATING_PROMPT_TERMS.test(prompt);
    const isExplicitlyMutating = EXPLICIT_MUTATING_PROMPT_TERMS.test(prompt);
    const isReadOnly = READ_ONLY_PROMPT_TERMS.test(prompt);
    const shouldBrief = PASSIVE_BRIEF_MODE === 'always' ||
        (PASSIVE_BRIEF_MODE !== 'false' && isRisky && (isReadOnly ? isExplicitlyMutating : isMutating));
    if (!shouldBrief)
        return null;
    let type = 'general';
    if (/\b(?:deploy|release|publish|cloudflare|worker|npm)\b/.test(lower))
        type = 'deploy';
    else if (/\b(?:audit|security|secret|token|credential|permission|opsec)\b/.test(lower))
        type = 'audit';
    else if (/\b(?:patch|fix|bug|harden|remediate)\b/.test(lower))
        type = 'patch';
    else if (/\b(?:review|merge|pr|pull request)\b/.test(lower))
        type = 'review';
    let role = 'general';
    if (type === 'deploy')
        role = 'deploy';
    else if (type === 'audit')
        role = 'audit';
    else if (type === 'patch')
        role = 'patch';
    else if (type === 'review')
        role = 'review';
    const surfaces = unique([
        /\b(?:github|git|merge|pr|pull request|commit|push)\b/.test(lower) ? 'github' : '',
        /\b(?:npm|package|publish|sdk|mcp)\b/.test(lower) ? 'npm' : '',
        /\b(?:doc|docs|readme|getmarrow\.ai)\b/.test(lower) ? 'docs' : '',
        /\b(?:prod|production|deploy|release|cloudflare|worker)\b/.test(lower) ? 'production' : '',
        /\b(?:secret|token|credential|key|permission)\b/.test(lower) ? 'secrets' : '',
    ]);
    return {
        action,
        type,
        role,
        surfaces: surfaces.length > 0 ? surfaces : ['workspace'],
    };
}
function appendPassiveBrief(lines, brief) {
    if (!brief)
        return;
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
function appendAgentRuntime(lines, runtime) {
    if (!runtime)
        return;
    lines.push('');
    lines.push('## Marrow agent runtime');
    if (runtime.before_you_act_injection?.must_use_before_action) {
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
    if (runtime.risk_gate) {
        lines.push(`- Risk gate: ${runtime.risk_gate.decision} (${runtime.risk_gate.risk_level})`);
        if (runtime.risk_gate.allow === false) {
            lines.push('- Required action: stop before external changes and collect owner approval or proof required by Marrow.');
        }
    }
    if (runtime.proof_pack?.required) {
        lines.push(`- Required proof: ${runtime.proof_pack.fields.slice(0, 6).join(', ')}`);
        const missing = Array.isArray(runtime.proof_pack.missing) ? runtime.proof_pack.missing.slice(0, 6).join(', ') : '';
        if (missing)
            lines.push(`- Missing proof before completion: ${missing}`);
    }
    const closure = asRecord(runtime.auto_outcome_closure);
    if (closure) {
        lines.push(`- Outcome closure: ${asString(closure.state) || 'unknown'}${typeof closure.recent_coverage_24h === 'number' ? ` (${Math.round(closure.recent_coverage_24h * 100)}% recent)` : ''}`);
    }
}
function buildCombinedContextBlock(signals, brief, valueReport, runtime = null) {
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
function emitNoContext() {
    process.stdout.write('{}');
}
function emitContext(context) {
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
async function withTimeout(promise, ms) {
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
async function runContextHookCommand() {
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
        let event;
        try {
            event = JSON.parse(raw);
        }
        catch {
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
        const baseUrl = (0, index_1.validateBaseUrl)(process.env.MARROW_BASE_URL || 'https://api.getmarrow.ai');
        const sessionId = process.env.MARROW_SESSION_ID || asString(event.session_id);
        const agentId = process.env.MARROW_FLEET_AGENT_ID || undefined;
        // Truncate prompt for the action field (Marrow think actions don't need full multi-K-token prompts)
        const redactedPrompt = (0, redact_1.redactSensitiveText)(prompt);
        const action = redactedPrompt.length > 500 ? redactedPrompt.slice(0, 500) + '…' : redactedPrompt;
        const passiveBriefInput = inferPassiveBriefInput(prompt);
        const runtimeInput = passiveBriefInput || defaultRuntimeInput(prompt);
        const shouldFetchValueSummary = PASSIVE_VALUE_MODE === 'always' ||
            (PASSIVE_VALUE_MODE !== 'false' && (Boolean(passiveBriefInput) || /(?:status|summary|report|improve|better|value|metrics|passive|fleet)/i.test(prompt)));
        const [thinkResult, runtimeResult, briefResult, valueReport] = await Promise.all([
            withTimeout((0, index_1.marrowThink)(apiKey, baseUrl, { action, type: passiveBriefInput?.type || 'general' }, sessionId, agentId), MARROW_API_TIMEOUT_MS),
            process.env.MARROW_AGENT_RUNTIME === 'false'
                ? Promise.resolve(null)
                : runtimeInput
                    ? withTimeout((0, index_1.marrowAgentRuntime)(apiKey, baseUrl, runtimeInput, sessionId, agentId), MARROW_API_TIMEOUT_MS)
                    : Promise.resolve(null),
            passiveBriefInput && process.env.MARROW_RUNTIME_FALLBACK_BRIEF === 'true'
                ? withTimeout((0, index_1.marrowDecisionBrief)(apiKey, baseUrl, passiveBriefInput, sessionId, agentId), MARROW_API_TIMEOUT_MS)
                : Promise.resolve(null),
            shouldFetchValueSummary
                ? withTimeout((0, index_1.marrowValueReport)(apiKey, baseUrl, process.env.MARROW_VALUE_REPORT_PERIOD || '7d', agentId, sessionId, agentId), MARROW_API_TIMEOUT_MS)
                : Promise.resolve(null),
        ]);
        if (!thinkResult && !runtimeResult && !briefResult && !valueReport) {
            debug('[marrow-context-hook] marrow_think timed out or errored');
            emitNoContext();
            process.exit(0);
            return;
        }
        const signals = extractSignals(thinkResult);
        if (!signals.hasSignal && !runtimeResult && !briefResult && !valueReport) {
            debug('[marrow-context-hook] no signal — no context to inject');
            emitNoContext();
            process.exit(0);
            return;
        }
        const context = buildCombinedContextBlock(signals, briefResult || runtimeResult?.decision_brief || null, valueReport, runtimeResult);
        debug(`[marrow-context-hook] injected ${context.length} bytes of context`);
        emitContext(context);
        process.exit(0);
    }
    catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        debug(`[marrow-context-hook] ${msg}`);
        emitNoContext();
        process.exit(0);
    }
}
function appendValueSummary(lines, report) {
    if (!report)
        return;
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
function installUserPromptSubmitHook(startDir = process.cwd()) {
    const fs = require('fs');
    const path = require('path');
    // Re-implement findSettingsPath here to avoid circular dependency on hook.ts
    let dir = startDir;
    let settingsPath = null;
    for (let i = 0; i < 5; i++) {
        const candidate = path.join(dir, '.claude', 'settings.json');
        const projectMarker = path.join(dir, '.git');
        const claudeDir = path.join(dir, '.claude');
        if (fs.existsSync(candidate) || fs.existsSync(claudeDir) || fs.existsSync(projectMarker)) {
            settingsPath = candidate;
            break;
        }
        const parent = path.dirname(dir);
        if (parent === dir)
            break;
        dir = parent;
    }
    if (!settingsPath) {
        settingsPath = path.join(startDir, '.claude', 'settings.json');
    }
    let settings = {};
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
        if (!record || !Array.isArray(record.hooks))
            return false;
        return record.hooks.some((hook) => {
            const hookRecord = asRecord(hook);
            return !!(hookRecord && typeof hookRecord.command === 'string' && hookRecord.command.includes(exports.CONTEXT_HOOK_COMMAND));
        });
    });
    if (!alreadyInstalled) {
        userPromptSubmit.push({
            hooks: [{ type: 'command', command: exports.CONTEXT_HOOK_COMMAND }],
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
//# sourceMappingURL=hook-context.js.map