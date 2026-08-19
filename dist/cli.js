#!/usr/bin/env node
"use strict";
/**
 * Marrow MCP stdio server - runtime control and proof for MCP-compatible agents.
 * Exposes pre-action governance, intent capture, outcome closure, and fleet evidence.
 *
 * Usage:
 *   npx @getmarrow/mcp                          (reads MARROW_API_KEY from env)
 *   npx @getmarrow/mcp --key mrw_abc123          (pass key via CLI flag)
 *   MARROW_API_KEY=mrw_abc123 npx @getmarrow/mcp
 */
Object.defineProperty(exports, "__esModule", { value: true });
const index_1 = require("./index");
const hook_1 = require("./hook");
const hook_context_1 = require("./hook-context");
const hook_session_1 = require("./hook-session");
const hook_pre_action_1 = require("./hook-pre-action");
const env_1 = require("./env");
const lifecycle_spool_1 = require("./lifecycle-spool");
const spool_command_1 = require("./spool-command");
const guidance_cache_1 = require("./guidance-cache");
const request_reliability_1 = require("./request-reliability");
const hook_contract_1 = require("./hook-contract");
const ping_state_1 = require("./ping-state");
const control_path_state_1 = require("./control-path-state");
const redact_1 = require("./redact");
const runtime_contract_1 = require("./runtime-contract");
const status_cache_1 = require("./status-cache");
const habit_loop_copy_1 = require("./habit-loop-copy");
const host_capability_1 = require("./host-capability");
// Parse CLI args
function parseArgs() {
    const args = process.argv.slice(2);
    const result = {};
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--key' && i + 1 < args.length) {
            result.apiKey = args[i + 1];
            i++;
        }
        if (args[i] === 'setup' || args[i] === '--setup') {
            result.setup = true;
        }
        if (args[i] === 'hook' || args[i] === '--hook') {
            result.hook = true;
        }
        if (args[i] === 'context-hook' || args[i] === '--context-hook') {
            result.contextHook = true;
        }
        if (args[i] === 'pre-action-hook' || args[i] === '--pre-action-hook') {
            result.preActionHook = true;
        }
        if (args[i] === 'session-hook' || args[i] === '--session-hook') {
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
async function runPingCommand() {
    if (cliArgs.apiKey) {
        process.stderr.write('Error: ping requires MARROW_API_KEY from trusted environment or owner configuration; --key is not accepted.\n');
        process.exitCode = 1;
        return;
    }
    const resolved = (0, env_1.resolveMarrowEnv)({ trustedOnly: true });
    if (!resolved.apiKey) {
        process.stdout.write(JSON.stringify({ ok: false, error: 'missing_key', exact_fix: resolved.exactFix }) + '\n');
        process.exitCode = 1;
        return;
    }
    const baseUrl = (0, index_1.validateBaseUrl)(resolved.baseUrl || 'https://api.getmarrow.ai');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), (0, ping_state_1.resolvePingTimeoutMs)(process.env.MARROW_PING_TIMEOUT_MS));
    timer.unref?.();
    const started = Date.now();
    try {
        const status = await (0, index_1.marrowRuntimeStatus)(resolved.apiKey, baseUrl, true, resolved.sessionId, resolved.agentId, controller.signal);
        const latencyMs = Date.now() - started;
        const history = (0, ping_state_1.updatePingState)({ apiKey: resolved.apiKey, baseUrl, agentId: resolved.agentId, latencyMs, success: true });
        process.stdout.write(JSON.stringify({
            ok: status.ok === true,
            health: status.health || 'available',
            current_ms: latencyMs,
            p50_ms: history.p50_ms,
            p99_ms: history.p99_ms,
            sample_count: history.sample_count,
            last_success_at: history.last_success_at,
            lifecycle_spool: (0, lifecycle_spool_1.lifecycleSpoolStatus)({ apiKey: resolved.apiKey, agentId: resolved.agentId }),
        }, null, 2) + '\n');
    }
    catch (error) {
        const history = (0, ping_state_1.updatePingState)({ apiKey: resolved.apiKey, baseUrl, agentId: resolved.agentId, success: false });
        const message = error instanceof Error ? error.message : String(error);
        process.stdout.write(JSON.stringify({
            ok: false,
            error: /401|unauthorized/i.test(message) ? 'authentication_failed' : /403|forbidden/i.test(message) ? 'permission_denied' : /abort|timeout/i.test(message) ? 'timeout' : 'unavailable',
            p50_ms: history.p50_ms,
            p99_ms: history.p99_ms,
            sample_count: history.sample_count,
            last_success_at: history.last_success_at,
            lifecycle_spool: (0, lifecycle_spool_1.lifecycleSpoolStatus)({ apiKey: resolved.apiKey, agentId: resolved.agentId }),
        }, null, 2) + '\n');
        process.exitCode = 1;
    }
    finally {
        clearTimeout(timer);
    }
}
async function runSpoolCommand(drain) {
    if (cliArgs.apiKey) {
        process.stderr.write('Error: lifecycle spool commands require MARROW_API_KEY from trusted environment or owner configuration; --key is not accepted.\n');
        process.exitCode = 1;
        return;
    }
    const resolved = (0, env_1.resolveMarrowEnv)({ trustedOnly: true });
    const apiKey = resolved.apiKey || '';
    if (!apiKey) {
        process.stderr.write(`Error: MARROW_API_KEY required. ${resolved.exactFix}\n`);
        process.exitCode = 1;
        return;
    }
    const baseUrl = (0, index_1.validateBaseUrl)(resolved.baseUrl || 'https://api.getmarrow.ai');
    const status = drain
        ? await (0, lifecycle_spool_1.drainLifecycleSpool)({ apiKey, baseUrl, agentId: resolved.agentId || undefined })
        : (0, lifecycle_spool_1.lifecycleSpoolStatus)({ apiKey, agentId: resolved.agentId || undefined });
    const outcome = (0, spool_command_1.lifecycleSpoolCommandOutcome)(status, drain);
    process.stdout.write(`${JSON.stringify(outcome.output, null, 2)}\n`);
    if (outcome.exitCode !== 0)
        process.exitCode = outcome.exitCode;
}
// ─── Setup command: inject Marrow instructions into CLAUDE.md ───
function runSetup() {
    const fs = require('fs');
    const path = require('path');
    const MARROW_BLOCK_START = '<!-- marrow:start -->';
    const MARROW_BLOCK_END = '<!-- marrow:end -->';
    const marrowInstructions = `${MARROW_BLOCK_START}
## Marrow — Agent Control and Proof (auto-injected by @getmarrow/mcp setup)

Use Marrow according to the capability evidence returned by the MCP server:

1. **MCP baseline is on demand:** MCP transport exposes tools; it does not provide passive hooks. Call Marrow tools explicitly unless observed receipts verify another capability mode.
2. **Before risky actions:** Respect the returned \`allow\`, \`warn\`, \`review_required\`, or \`block\` decision and its proof contract. Call \`marrow_agent_runtime\` explicitly when verified passive coverage cannot cover the action.
3. **After meaningful work:** Record the real success or failure with \`marrow_commit\` or \`marrow_auto\`. A tool exit or session end is not proof that the business outcome succeeded.
4. **Unfinished work:** Leave pending outcomes visible. Do not invent success to clear a closure item.
5. **To explain an intervention:** Use \`marrow_decision_trace\`, then relay its \`intervention_receipt\` in one factual sentence when Marrow blocked, warned, or required review. Stay quiet for routine low-risk work.
6. **To query authorized history:** Call \`marrow_ask("plain english question")\` — ask what failed, what worked, and what policy should apply.
7. **When an update is reported:** Tell the operator and use the returned exact update and verification commands only when local change policy permits. Never silently change packages or configuration.

Do not skip the gate or outcome. Marrow's value comes from controlling the action before execution and preserving evidence afterward.

Capability boundaries: verified native hooks cover only their observed lifecycle; \`createPassiveRuntime().install()\` covers only its owned Node process while installed; a governed runner covers only its wrapped command; and a custom host needs a bounded event adapter. A model name, host label, or installed configuration is not proof of coverage. Only observed Marrow receipts certify it.

For one-shot logging: \`marrow_auto({ action: "did X", outcome: "result Y", success: true })\` — one call, done.
${MARROW_BLOCK_END}`;
    let dir = process.cwd();
    let claudeMdPath = null;
    for (let i = 0; i < 5; i++) {
        const candidate = path.join(dir, 'CLAUDE.md');
        if (fs.existsSync(candidate)) {
            claudeMdPath = candidate;
            break;
        }
        const parent = path.dirname(dir);
        if (parent === dir)
            break;
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
        }
        else {
            const separator = content.length > 0 && !content.endsWith('\n') ? '\n\n' : content.length > 0 ? '\n' : '';
            fs.writeFileSync(claudeMdPath, content + separator + marrowInstructions + '\n');
            process.stdout.write(`Added Marrow instructions to ${claudeMdPath}\n`);
        }
    }
    else {
        fs.writeFileSync(claudeMdPath, marrowInstructions + '\n');
        process.stdout.write(`Added Marrow instructions to ${claudeMdPath}\n`);
    }
    const hookInstall = (0, hook_1.installPostToolUseHook)(process.cwd());
    if (hookInstall.installed) {
        process.stdout.write('Configured PostToolUse hook. Coverage remains unverified until Marrow observes action-result receipts.\n');
    }
    else {
        process.stdout.write('PostToolUse hook configuration is present. Coverage remains unverified until Marrow observes action-result receipts.\n');
    }
    const contextHookInstall = (0, hook_context_1.installUserPromptSubmitHook)(process.cwd());
    if (contextHookInstall.installed) {
        process.stdout.write('Configured UserPromptSubmit hook. Passive prompt coverage remains unverified until Marrow observes prompt receipts.\n');
    }
    else {
        process.stdout.write('UserPromptSubmit hook configuration is present. Passive prompt coverage remains unverified until Marrow observes prompt receipts.\n');
    }
    const preActionHookInstall = (0, hook_pre_action_1.installPreActionHook)(process.cwd());
    if (preActionHookInstall.installed) {
        process.stdout.write('Configured PreToolUse hook. Pre-action coverage remains unverified until Marrow observes pre-action receipts.\n');
    }
    else {
        process.stdout.write('PreToolUse hook configuration is present. Pre-action coverage remains unverified until Marrow observes pre-action receipts.\n');
    }
    const sessionHookInstall = (0, hook_session_1.installSessionEndHook)(process.cwd());
    if (sessionHookInstall.installed) {
        process.stdout.write('Configured Stop hook. Session-end coverage remains unverified until Marrow observes session-end receipts.\n');
    }
    else {
        process.stdout.write('Stop hook configuration is present. Session-end coverage remains unverified until Marrow observes session-end receipts.\n');
    }
    process.stdout.write(`Hook settings: ${hookInstall.settingsPath}\n`);
    process.stdout.write('Set MARROW_AUTO_HOOK=false to disable passive hooks.\n');
    process.stdout.write('Set MARROW_PASSIVE_BRIEF=false to disable automatic decision briefs, or MARROW_PASSIVE_BRIEF=always to brief every prompt.\n');
    process.stdout.write('Set MARROW_HOOK_DEBUG=true for write-side hook diagnostics, or MARROW_CONTEXT_HOOK_DEBUG=true for prompt-context diagnostics.\n');
    process.stdout.write('Setup completed. MCP tools remain on demand; passive coverage is reported only after Marrow observes the required hook receipts.\n');
    process.exit(0);
}
const cliArgs = parseArgs();
function formatKeyMaterialWarning() {
    return 'Copy this key now. Marrow will only show the full plaintext key once.';
}
// ─── Standalone CLI: key management ───
if (process.argv[2] === 'keys') {
    const cmd = process.argv[3];
    const resolvedEnv = (0, env_1.resolveMarrowEnv)();
    const API_KEY = cliArgs.apiKey || resolvedEnv.apiKey || '';
    if (!API_KEY) {
        process.stderr.write(`Error: MARROW_API_KEY required. ${resolvedEnv.exactFix}\n`);
        process.exit(1);
    }
    const getFlag = (name, short) => {
        const idx = process.argv.findIndex(a => a === `--${name}` || (short ? a === `-${short}` : false));
        return idx >= 0 ? process.argv[idx + 1] : undefined;
    };
    const getFlagList = (name) => {
        const val = getFlag(name);
        return val ? val.split(',').map(s => s.trim()) : [];
    };
    const runCli = async () => {
        try {
            if (cmd === 'create') {
                const name = getFlag('name', 'n');
                if (!name) {
                    process.stderr.write('Error: --name required\n');
                    process.exit(1);
                }
                const result = await (0, index_1.marrowCreateKey)(API_KEY, 'https://api.getmarrow.ai', {
                    name,
                    key_type: (getFlag('type', 't') || 'live'),
                    scopes: getFlagList('scopes'),
                    agent_ids: getFlagList('agents'),
                    expires_at: getFlag('expires'),
                }, undefined, undefined);
                process.stdout.write(JSON.stringify({ ...result, warning: formatKeyMaterialWarning() }, null, 2) + '\n');
            }
            else if (cmd === 'list') {
                const result = await (0, index_1.marrowListKeys)(API_KEY, 'https://api.getmarrow.ai', undefined, undefined);
                process.stdout.write(JSON.stringify(result, null, 2) + '\n');
            }
            else if (cmd === 'get') {
                const id = getFlag('id', 'i') || process.argv[4];
                if (!id) {
                    process.stderr.write('Error: --id required\n');
                    process.exit(1);
                }
                const result = await (0, index_1.marrowGetKey)(API_KEY, 'https://api.getmarrow.ai', id, undefined, undefined);
                process.stdout.write(JSON.stringify(result, null, 2) + '\n');
            }
            else if (cmd === 'rotate') {
                const id = getFlag('id', 'i') || process.argv[4];
                if (!id) {
                    process.stderr.write('Error: --id required\n');
                    process.exit(1);
                }
                const result = await (0, index_1.marrowRotateKey)(API_KEY, 'https://api.getmarrow.ai', id, undefined, undefined);
                process.stdout.write(JSON.stringify({ ...result, warning: formatKeyMaterialWarning() }, null, 2) + '\n');
            }
            else if (cmd === 'revoke') {
                const id = getFlag('id', 'i') || process.argv[4];
                if (!id) {
                    process.stderr.write('Error: --id required\n');
                    process.exit(1);
                }
                const result = await (0, index_1.marrowRevokeKey)(API_KEY, 'https://api.getmarrow.ai', id, undefined, undefined);
                process.stdout.write(JSON.stringify(result, null, 2) + '\n');
            }
            else if (cmd === 'audit') {
                const limit = parseInt(getFlag('limit', 'l') || '20', 10);
                const result = await (0, index_1.marrowGetKeyAudit)(API_KEY, 'https://api.getmarrow.ai', { limit }, undefined, undefined);
                process.stdout.write(JSON.stringify(result, null, 2) + '\n');
            }
            else {
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
        }
        catch (e) {
            process.stderr.write(`Error: ${e.message || e}\n`);
            process.exit(1);
        }
    };
    void runCli().then(() => process.exit(0));
}
// Only start MCP server if not handling a CLI command
if (process.argv[2] !== 'keys') {
    if (cliArgs.hook) {
        void (0, hook_1.runHookCommand)();
    }
    else if (cliArgs.contextHook) {
        void (0, hook_context_1.runContextHookCommand)();
    }
    else if (cliArgs.preActionHook) {
        void (0, hook_pre_action_1.runPreActionHookCommand)().catch(() => {
            process.stderr.write('Marrow pre-action governance failed closed. Retry after restoring the trusted configuration.\n');
            process.exitCode = 2;
        });
    }
    else if (cliArgs.sessionHook) {
        void (0, hook_session_1.runSessionHookCommand)();
    }
    else if (cliArgs.spoolStatus) {
        void runSpoolCommand(false);
    }
    else if (cliArgs.drainSpool) {
        void runSpoolCommand(true);
    }
    else if (cliArgs.ping) {
        void runPingCommand();
    }
    else if (cliArgs.setup) {
        runSetup();
    }
    else {
        const resolvedEnv = (0, env_1.resolveMarrowEnv)();
        const API_KEY = cliArgs.apiKey || resolvedEnv.apiKey || '';
        // [SECURITY #3] Validate BASE_URL — require HTTPS to prevent SSRF / credential leakage
        const rawBaseUrl = resolvedEnv.baseUrl || 'https://api.getmarrow.ai';
        const BASE_URL = (0, index_1.validateBaseUrl)(rawBaseUrl);
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
        let cachedOrientWarnings = [];
        let thinkCallCount = 0;
        let orientCallCount = 0;
        let initialized = false;
        function formatWarningActionably(w) {
            const pct = Math.round(w.failureRate * 100);
            return `⚠️ ${w.type} has ${pct}% failure rate — check what went wrong last time before proceeding`;
        }
        // [FIX #4] Log orient refresh failures instead of silently ignoring
        async function refreshOrientWarnings() {
            try {
                const r = await (0, index_1.marrowOrient)(API_KEY, BASE_URL, undefined, SESSION_ID, FLEET_AGENT_ID);
                cachedOrientWarnings = r.warnings;
            }
            catch (err) {
                const msg = err instanceof Error ? err.message : String(err);
                process.stderr.write(`[marrow] Warning: failed to refresh orient warnings: ${msg}\n`);
            }
        }
        // Auto-commit tracking for session close
        let lastDecisionId = null;
        let lastCommitted = false;
        // [FIX #5] Log auto-commit failures instead of silently ignoring; remove broken AbortController
        async function autoCommitOnClose() {
            if (lastDecisionId && !lastCommitted) {
                try {
                    await (0, index_1.marrowCommit)(API_KEY, BASE_URL, {
                        decision_id: lastDecisionId,
                        success: false,
                        outcome: 'Session ended without explicit commit',
                    }, SESSION_ID, FLEET_AGENT_ID);
                }
                catch (err) {
                    const msg = err instanceof Error ? err.message : String(err);
                    process.stderr.write(`[marrow] Warning: auto-commit on close failed: ${msg}\n`);
                }
            }
        }
        // [FIX #10] Handle both SIGTERM and SIGINT for clean shutdown
        async function gracefulShutdown() {
            const forceExit = setTimeout(() => process.exit(0), 5000);
            forceExit.unref();
            await autoCommitOnClose();
            process.exit(0);
        }
        process.on('SIGTERM', gracefulShutdown);
        process.on('SIGINT', gracefulShutdown);
        function send(response) {
            process.stdout.write(JSON.stringify(response) + '\n');
        }
        function success(id, result) {
            send({ jsonrpc: '2.0', id, result });
        }
        function error(id, code, message) {
            send({ jsonrpc: '2.0', id, error: { code, message } });
        }
        function toolSuccess(id, value, isError = false) {
            success(id, {
                content: [{ type: 'text', text: JSON.stringify(value, null, 2) }],
                ...(isError ? { isError: true } : {}),
            });
        }
        function toolFailure(toolName, failure) {
            const result = (0, request_reliability_1.structuredRequestFailure)(failure);
            const proofValidation = failure.code === 'proof_required';
            const infrastructureFailure = !proofValidation && !['authentication_required', 'permission_denied'].includes(failure.code);
            const supportsStale = ['marrow_agent_runtime', 'marrow_orient', 'marrow_ask', 'marrow_handoff_status', 'marrow_runtime_status', 'marrow_status'].includes(toolName || '');
            const spool = (0, lifecycle_spool_1.lifecycleSpoolStatus)({ apiKey: API_KEY, agentId: FLEET_AGENT_ID });
            result.failure_kind = proofValidation ? 'validation' : infrastructureFailure ? 'infrastructure' : 'authorization';
            result.control_path = (0, control_path_state_1.controlPathStats)(toolName || 'marrow_control');
            result.lifecycle_spool = {
                ...spool,
                drain_command: 'npx -y --package=@getmarrow/mcp@latest marrow-mcp drain-spool',
            };
            result.host_capability = mcpHostCapability();
            if (proofValidation) {
                result.proof_required = true;
                result.exact_next_action = failure.exactFix;
            }
            if (infrastructureFailure && supportsStale) {
                let cached = null;
                try {
                    cached = (0, guidance_cache_1.readGuidanceCache)({ apiKey: API_KEY, baseUrl: BASE_URL, agentId: FLEET_AGENT_ID });
                }
                catch { /* owner-only cache is best effort */ }
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
            return (0, host_capability_1.resolveHostCapability)({
                hostLabel: process.env.MARROW_CLIENT || process.env.MARROW_HARNESS || process.env.MARROW_AGENT_CLIENT,
            });
        }
        function clientOperationalPayload(toolName, value) {
            const payload = value && typeof value === 'object' && !Array.isArray(value)
                ? value
                : { data: value };
            const spool = (0, lifecycle_spool_1.lifecycleSpoolStatus)({ apiKey: API_KEY, agentId: FLEET_AGENT_ID });
            const habitLoopCopy = (0, habit_loop_copy_1.formatHabitLoopCopy)(payload) || (0, habit_loop_copy_1.formatHabitLoopCopy)(payload.data);
            return {
                ...payload,
                ...(habitLoopCopy ? { habit_loop_copy: habitLoopCopy } : {}),
                host_capability: payload.host_capability || mcpHostCapability(),
                client_update: payload.client_update || (0, request_reliability_1.localClientUpdate)(),
                control_path: (0, control_path_state_1.controlPathStats)(toolName),
                lifecycle_spool: {
                    ...spool,
                    drain_command: 'npx -y --package=@getmarrow/mcp@latest marrow-mcp drain-spool',
                },
            };
        }
        // [FIX #9] Runtime validation helper for required string params
        function requireString(args, name) {
            const val = args[name];
            if (typeof val !== 'string' || !val.trim()) {
                throw new Error(`"${name}" is required and must be a non-empty string`);
            }
            return val;
        }
        function requireBoolean(args, name) {
            const value = args[name];
            if (typeof value !== 'boolean')
                throw new Error(`"${name}" is required and must be boolean`);
            return value;
        }
        const HIGH_RISK_ACTION = /\b(?:billing|credential|database|delete|deploy|destructive|financial|key|merge|migrat(?:e|ion)|payment|production|publish|release|remove|rollback|secret|security|token|truncate|wipe)\b/i;
        function isHighRiskAction(action, type) {
            return HIGH_RISK_ACTION.test(`${String(type || '')} ${String(action || '')}`);
        }
        async function withControlDeadline(operation, options = {}) {
            const toolName = options.toolName || 'marrow_control';
            const configuredTimeoutMs = Number(process.env.MARROW_REQUEST_TIMEOUT_MS);
            const runtimeBudget = toolName === 'marrow_agent_runtime' || toolName === 'marrow_auto.runtime';
            const timeoutMs = Number.isFinite(configuredTimeoutMs)
                ? Math.min(10_000, Math.max(150, Math.floor(configuredTimeoutMs)))
                : options.highRisk || runtimeBudget ? 4_500 : 4_000;
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), timeoutMs);
            timer.unref?.();
            const startedAt = Date.now();
            try {
                const result = await operation(controller.signal);
                (0, control_path_state_1.recordControlPathSample)(toolName, Date.now() - startedAt, true);
                return result;
            }
            catch (error) {
                (0, control_path_state_1.recordControlPathSample)(toolName, Date.now() - startedAt, false);
                throw error;
            }
            finally {
                clearTimeout(timer);
            }
        }
        function storeRuntimeGuidance(runtime) {
            try {
                (0, guidance_cache_1.writeGuidanceCache)({
                    apiKey: API_KEY,
                    baseUrl: BASE_URL,
                    agentId: FLEET_AGENT_ID,
                    context: (0, hook_context_1.compactRuntimeContext)(runtime),
                });
            }
            catch { /* owner-only cache is best effort */ }
        }
        function storeLastKnownStatus(status, source) {
            try {
                (0, status_cache_1.writeStatusCache)({
                    apiKey: API_KEY,
                    baseUrl: BASE_URL,
                    agentId: FLEET_AGENT_ID,
                    status,
                    source,
                });
            }
            catch { /* owner-only cache is best effort */ }
        }
        function refreshStatusInBackground() {
            void (0, index_1.marrowStatus)(API_KEY, BASE_URL, SESSION_ID, FLEET_AGENT_ID)
                .then((status) => storeLastKnownStatus(status, 'status'))
                .catch(() => undefined);
        }
        // [FIX #6 & #7] Safe JSON response helper for memory API functions
        async function safeMemoryResponse(res) {
            if (!res.ok) {
                let detail = '';
                try {
                    detail = await res.text();
                }
                catch { /* ignore */ }
                throw new Error(`API error ${res.status}: ${detail.slice(0, 200)}`);
            }
            const json = await res.json();
            if (json.error) {
                throw new Error(json.error);
            }
            return json;
        }
        // Memory API functions — all patched with safeMemoryResponse and validatePathParam
        async function marrowListMemories(apiKey, baseUrl, params, sessionId) {
            const qs = new URLSearchParams();
            if (params?.status)
                qs.set('status', params.status);
            if (params?.query)
                qs.set('query', params.query);
            if (params?.limit)
                qs.set('limit', String(params.limit));
            if (params?.agentId)
                qs.set('agent_id', params.agentId);
            const res = await fetch(`${baseUrl}/v1/memories?${qs.toString()}`, {
                headers: {
                    Authorization: `Bearer ${apiKey}`,
                    ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
                },
            });
            const json = await safeMemoryResponse(res);
            return json.data?.memories || [];
        }
        async function marrowGetMemory(apiKey, baseUrl, id, sessionId) {
            const safeId = (0, index_1.validatePathParam)(id, 'id');
            const res = await fetch(`${baseUrl}/v1/memories/${safeId}`, {
                headers: {
                    Authorization: `Bearer ${apiKey}`,
                    ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
                },
            });
            const json = await safeMemoryResponse(res);
            return json.data?.memory || null;
        }
        async function marrowUpdateMemory(apiKey, baseUrl, id, patch, sessionId) {
            const safeId = (0, index_1.validatePathParam)(id, 'id');
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
        async function marrowDeleteMemory(apiKey, baseUrl, id, meta, sessionId) {
            const safeId = (0, index_1.validatePathParam)(id, 'id');
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
        async function marrowMarkOutdated(apiKey, baseUrl, id, meta, sessionId) {
            const safeId = (0, index_1.validatePathParam)(id, 'id');
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
        async function marrowSupersedeMemory(apiKey, baseUrl, id, replacement, sessionId) {
            const safeId = (0, index_1.validatePathParam)(id, 'id');
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
        async function marrowShareMemory(apiKey, baseUrl, id, agentIds, actor, sessionId) {
            const safeId = (0, index_1.validatePathParam)(id, 'id');
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
        async function marrowExportMemories(apiKey, baseUrl, params, sessionId) {
            const qs = new URLSearchParams();
            if (params?.format)
                qs.set('format', params.format);
            if (params?.status)
                qs.set('status', params.status);
            if (params?.tags)
                qs.set('tags', params.tags);
            const res = await fetch(`${baseUrl}/v1/memories/export?${qs.toString()}`, {
                headers: {
                    Authorization: `Bearer ${apiKey}`,
                    ...(sessionId ? { 'X-Marrow-Session-Id': sessionId } : {}),
                },
            });
            const json = await safeMemoryResponse(res);
            return json.data;
        }
        async function marrowImportMemories(apiKey, baseUrl, memories, mode, sessionId) {
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
        async function marrowRetrieveMemories(apiKey, baseUrl, query, params, sessionId) {
            const qs = new URLSearchParams();
            qs.set('q', query);
            if (params?.limit)
                qs.set('limit', String(params.limit));
            if (params?.from)
                qs.set('from', params.from);
            if (params?.to)
                qs.set('to', params.to);
            if (params?.tags)
                qs.set('tags', params.tags);
            if (params?.source)
                qs.set('source', params.source);
            if (params?.status)
                qs.set('status', params.status);
            if (params?.shared !== undefined)
                qs.set('shared', String(params.shared));
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
                description: 'Call at session start or before meaningful work. ' +
                    'Returns authorized prior lessons and failure warnings for the current account or agent. ' +
                    'If shouldPause=true, stop and review the lesson before acting. ' +
                    'Use marrow_agent_runtime for the policy gate before a consequential side effect.',
                inputSchema: {
                    type: 'object',
                    properties: {
                        taskType: {
                            type: 'string',
                            enum: ['implementation', 'security', 'architecture', 'process', 'general'],
                            description: 'Optional: filter warnings to a specific task type you are about to perform',
                        },
                        autoWarn: {
                            type: 'boolean',
                            description: 'Enable active intervention: scans recent failures, returns HIGH/MEDIUM/LOW severity warnings with recommendations. Recommended: true.',
                        },
                    },
                    required: [],
                },
            },
            {
                name: 'marrow_think',
                description: 'Record intent and retrieve authorized governance intelligence before acting. ' +
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
                        instruction_ref: { type: 'string', description: 'Optional opaque non-PII instruction reference.' },
                        source_meta: { type: 'object', description: 'Optional provenance metadata. PII and raw provider IDs are rejected by the API.' },
                    },
                    required: ['action'],
                },
            },
            {
                name: 'marrow_commit',
                description: 'Close a recorded action with success/failure, a specific outcome, and required proof. ' +
                    'Use the decision_id from marrow_think and the gate receipt from marrow_agent_runtime for consequential work. ' +
                    'Outcome closure is required for accountable fleet learning.',
                inputSchema: {
                    type: 'object',
                    properties: {
                        decision_id: { type: 'string', description: 'decision_id from the marrow_think call' },
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
                        auto_gate: { type: 'boolean', description: 'If true/default and action is provided, call marrow_agent_runtime to obtain gate_receipt_id before commit.' },
                        model_usage: { type: 'object', description: 'Optional compact token/cost/latency counts. Do not include raw prompts or completions.' },
                    },
                    required: ['decision_id', 'success', 'outcome'],
                },
            },
            {
                name: 'marrow_model_usage',
                description: 'Record compact model token usage for value proof. Use when the harness exposes provider/model token counts. Do not send raw prompts, completions, tool logs, secrets, or customer content.',
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
                description: 'One-call governed outcome capture. Records intent, obtains a gate for risky work, and closes only with an explicit measured result.',
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
                description: 'Durably capture low-risk activity without blocking. Outcomes remain pending unless success is explicit; risky completion still requires a fresh gate and measured proof.',
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
                    },
                    required: ['action'],
                },
            },
            {
                name: 'marrow_ask',
                description: 'Query the collective hive in plain English. ' +
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
                description: 'Interact with Marrow Workflow Registry. Register, start, and advance multi-step workflows. ' +
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
                description: 'Get operator dashboard — account health, top failures, workflow status, recent activity, Marrow\'s saves metric. ' +
                    'One call returns everything an operator needs to see.',
                inputSchema: { type: 'object', properties: {}, required: [] },
            },
            {
                name: 'marrow_digest',
                description: 'Get periodic summary of agent activity and Marrow impact (default 7-day period). ' +
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
                description: 'Check whether Marrow is passively active for this agent or fleet. ' +
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
                description: 'Read live Marrow runtime hook diagnostics from /v1/agent/status. ' +
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
                description: 'Get owner-ready proof of Marrow value for this agent or fleet. ' +
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
                description: 'One pre-action call before meaningful or risky work. Returns risk level, workflow/playbook steps, ' +
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
                description: 'First-run Marrow value proof. Returns what is captured, whether outcome closure/runtime gate are active, ' +
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
                description: 'One-call agent-native Marrow loop. Returns passive status, decision brief, risk gate, relevant lessons, ' +
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
                description: 'Resolve conflicting next-step proposals from two or more tenant agents before execution. ' +
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
                description: 'Coordinate tenant agents without sharing transcripts. Acquire or release a bounded resource lease, ' +
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
                description: 'Compare two already-recorded outcomes for the same tenant task using durable proof. ' +
                    'This does not run a model or replay customer content; it returns complete or insufficient_evidence.',
                inputSchema: {
                    type: 'object',
                    properties: {
                        comparison_id: { type: 'string', description: 'Fetch a prior replay comparison by id.' },
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
                    required: [],
                },
            },
            {
                name: 'marrow_governance_control_plane',
                description: 'Return Marrow control-plane proof: governance, runtime gates, proof packs, fleet intelligence, supported harnesses, and exact next action.',
                inputSchema: { type: 'object', properties: {}, required: [] },
            },
            {
                name: 'marrow_hermes_integration',
                description: 'Return the Hermes Agent integration guide mapping /goal, verification evidence, /learn, /journey, and background subagents into Marrow proof and outcome workflows.',
                inputSchema: { type: 'object', properties: {}, required: [] },
            },
            {
                name: 'marrow_completion_contracts',
                description: 'List Marrow completion contracts for deploy, merge, publish, database migration, security change, support response, and Hermes goal workflows.',
                inputSchema: { type: 'object', properties: {}, required: [] },
            },
            {
                name: 'marrow_evaluate_completion_contract',
                description: 'Evaluate whether an agent has enough proof to mark work complete. Returns complete, missing_proof, review_required, or blocked with missing proof fields.',
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
                description: 'Return the recent fleet governance timeline across decisions, risk gates, and proof-pack events.',
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
                description: 'Return buyer-grade value proof: failures avoided, risky actions reviewed, proofs completed, token/time saved, failure classes, agent leaderboard, and reliability score.',
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
                description: 'Recommend passive, pilot, or enforce mode from project/workflow signals. Marrow never auto-switches here; the agent/user must accept or override.',
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
                description: 'Resolve the explicit mode for a project/workflow from saved policy profiles, falling back to recommendation. Does not auto-apply.',
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
                description: 'Pre-action risk gate for deploys, publishes, merges, DB migrations, key rotation, destructive commands, and production work. ' +
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
                description: 'Get agent-facing fleet value metrics: avoided mistakes, reused winning decisions, failed patterns, token/time saved estimate, reliability score, and next improvements.',
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
                description: 'Retrieve ranked reusable fleet lessons before similar work. Use before deploys, handoffs, migrations, audits, and repeated task types.',
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
                description: 'Record deploy or incident memory: PR, commit, tests, smoke result, rollback plan, production health, and incident notes.',
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
                description: 'Create a structured cross-agent handoff that Marrow can track for pending, stale, blocked, and complete states.',
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
                description: 'Update a Marrow handoff checkpoint/status when an agent accepts, blocks, completes, or needs review.',
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
                description: 'Ask who is pending, stuck, stale, blocked, or complete across the agent fleet.',
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
                description: 'Explicitly end the current session. Optionally auto-commits any open decision. ' +
                    'Prevents orphaned decisions when an agent finishes a task.',
                inputSchema: {
                    type: 'object',
                    properties: {
                        autoCommitOpen: { type: 'boolean', description: 'Whether to auto-commit any open decision (default: false)' },
                    },
                    required: [],
                },
            },
            {
                name: 'marrow_accept_detected',
                description: 'Convert a detected decision pattern into an enforced workflow. ' +
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
                description: 'Browse pre-built workflow templates. Filter by industry (insurance, healthcare, ecommerce, legal, saas, fintech, media, enterprise) or category. ' +
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
                description: 'Install a workflow template into your fleet as an active workflow. ' +
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
            'marrow_commit',
            'marrow_ask',
            'marrow_status',
            'marrow_auto',
            'marrow_handoff_status',
        ]);
        function advertisedTools() {
            return process.env.MARROW_TOOL_PROFILE === 'full'
                ? TOOLS
                : TOOLS.filter((tool) => CORE_TOOL_NAMES.has(tool.name));
        }
        function toolAllowedByActiveProfile(toolName) {
            return process.env.MARROW_TOOL_PROFILE === 'full'
                ? Boolean(toolName && TOOLS.some((tool) => tool.name === toolName))
                : Boolean(toolName && CORE_TOOL_NAMES.has(toolName));
        }
        // Request handler
        async function handleRequest(req) {
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
                        serverInfo: { name: 'marrow', version: hook_contract_1.MCP_ADAPTER_VERSION },
                        ...(AUTO_ENROLL ? {
                            instructions: `Use marrow_agent_runtime before consequential actions, obey fresh allow/warn/review_required/block results, use marrow_ask for relevant prior lessons, and close meaningful outcomes with marrow_commit. Infrastructure failures are not policy denials; continue only low-risk reversible work from the returned outage-safe brief, and require a fresh gate for high-risk work. ${(0, host_capability_1.hostCapabilityInstructions)(hostCapability)}`,
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
                                    client_update: (0, request_reliability_1.localClientUpdate)(),
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
                                    description: 'Marrow control and proof contract, qualified by verified host capability and observed lifecycle receipts.',
                                    arguments: [],
                                    _meta: { host_capability: mcpHostCapability() },
                                },
                            ],
                        });
                    }
                    else {
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
                        description: 'Marrow control and proof contract — coverage is capability-qualified and receipt-verified',
                        _meta: { host_capability: hostCapability },
                        messages: [
                            {
                                role: 'user',
                                content: {
                                    type: 'text',
                                    text: `You have Marrow — the agent control and proof layer around this workflow.

## Capability-qualified operating contract

${(0, host_capability_1.hostCapabilityInstructions)(hostCapability)}

When verified by observed receipts, native hooks can cover these bounded lifecycle stages:
- UserPromptSubmit can request relevant policy, warnings, lessons, and a decision brief before risky work.
- PostToolUse can record compact tool success or failure receipts.
- Stop can keep unfinished outcomes visible instead of silently treating session exit as success.

Hooks never make a blocked action safe. Before a consequential action, respect the returned allow, warn, review_required, or block decision and its required proof. Call marrow_agent_runtime explicitly when verified passive coverage cannot cover the action.

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
                    const args = (params?.arguments || {});
                    if (!toolAllowedByActiveProfile(toolName)) {
                        error(id, -32601, 'Tool is not available in the active Marrow tool profile. Set MARROW_TOOL_PROFILE=full and restart MCP for advanced operator tools.');
                        return;
                    }
                    if (toolName === 'marrow_orient') {
                        orientCallCount++;
                        const wantAutoWarn = args.autoWarn ?? true;
                        const taskType = args.taskType;
                        const result = await withControlDeadline((signal) => (0, index_1.marrowOrient)(API_KEY, BASE_URL, { taskType, autoWarn: wantAutoWarn }, SESSION_ID, FLEET_AGENT_ID, signal), { highRisk: isHighRiskAction(`Orient before ${taskType || 'general'} work`, taskType), toolName: 'marrow_orient' });
                        if (AUTO_ENROLL && orientCallCount === 1) {
                            const enrollmentText = `\n\n**Marrow control and proof active**\n\n` +
                                `Marrow applies relevant policy and prior lessons before consequential actions, then records evidence and the real outcome afterward.\n\n` +
                                `1. Respect allow, warn, review_required, and block decisions before acting.\n` +
                                `2. Use marrow_agent_runtime when a risky action needs an explicit gate.\n` +
                                `3. Close meaningful work with marrow_commit; a tool exit alone is not outcome proof.\n` +
                                `4. Use marrow_decision_trace to explain the prior failure, lesson, gate, proof, workflow, and outcome path.\n\n` +
                                `${(0, host_capability_1.hostCapabilityInstructions)(mcpHostCapability())}\n\nLeave unknown outcomes pending instead of inventing success.\n`;
                            const orientText = JSON.stringify(result, null, 2);
                            success(id, {
                                content: [{ type: 'text', text: enrollmentText + orientText }],
                            });
                        }
                        else {
                            success(id, {
                                content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                            });
                        }
                        return;
                    }
                    if (toolName === 'marrow_think') {
                        // [FIX #9] Validate required param
                        const action = requireString(args, 'action');
                        const result = await (0, index_1.marrowThink)(API_KEY, BASE_URL, {
                            action,
                            type: args.type,
                            context: args.context,
                            previous_decision_id: args.previous_decision_id,
                            previous_success: args.previous_success,
                            previous_outcome: args.previous_outcome,
                            checkLoop: args.checkLoop ?? true,
                            source_kind: args.source_kind,
                            human_directed: args.human_directed,
                            instruction_ref: args.instruction_ref,
                            source_meta: args.source_meta,
                        }, SESSION_ID, FLEET_AGENT_ID);
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
                                    type: 'failure_pattern',
                                    summary: w.message,
                                    action: `Review past ${w.type} failures before proceeding`,
                                    severity: (w.failureRate > 0.4 ? 'critical' : 'warning'),
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
                        const result = await withControlDeadline((signal) => (0, index_1.marrowCommit)(API_KEY, BASE_URL, {
                            decision_id,
                            success: commitSuccess,
                            outcome,
                            caused_by: args.caused_by,
                            proof: args.proof,
                            gate_receipt_id: args.gate_receipt_id,
                            arbitration_receipt_id: args.arbitration_receipt_id,
                            owner_approval_receipt_id: args.owner_approval_receipt_id,
                            action: args.action,
                            type: args.type,
                            surfaces: args.surfaces,
                            auto_gate: args.auto_gate,
                            model_usage: args.model_usage,
                        }, SESSION_ID, FLEET_AGENT_ID, signal), { highRisk: true, cacheAware: false, toolName: 'marrow_commit' });
                        const commitResult = { ...result, narrative: result.narrative ?? null };
                        lastCommitted = result.committed;
                        lastDecisionId = result.committed ? null : decision_id;
                        success(id, {
                            content: [{ type: 'text', text: JSON.stringify(commitResult, null, 2) }],
                        });
                        return;
                    }
                    if (toolName === 'marrow_model_usage') {
                        const result = await (0, index_1.marrowModelUsage)(API_KEY, BASE_URL, args, SESSION_ID, FLEET_AGENT_ID);
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
                        let thinkResult = null;
                        try {
                            await (0, index_1.marrowOrient)(API_KEY, BASE_URL, undefined, SESSION_ID, FLEET_AGENT_ID);
                        }
                        catch (err) {
                            const msg = err instanceof Error ? err.message : String(err);
                            process.stderr.write(`[marrow] marrow_run orient failed (continuing): ${msg}\n`);
                        }
                        thinkResult = await (0, index_1.marrowThink)(API_KEY, BASE_URL, {
                            action: description,
                            type: args.type || 'general',
                        }, SESSION_ID, FLEET_AGENT_ID);
                        let commitResult = null;
                        try {
                            commitResult = await (0, index_1.marrowCommit)(API_KEY, BASE_URL, {
                                decision_id: thinkResult.decision_id,
                                success: measuredSuccess,
                                outcome,
                                proof: args.proof && typeof args.proof === 'object' && !Array.isArray(args.proof)
                                    ? (0, redact_1.redactSensitiveValue)(args.proof)
                                    : undefined,
                                gate_receipt_id: typeof args.gate_receipt_id === 'string' ? args.gate_receipt_id : undefined,
                                action: description,
                                type: args.type || 'general',
                            }, SESSION_ID, FLEET_AGENT_ID);
                        }
                        catch (err) {
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
                        const outcome = args.outcome;
                        const outcomeSuccess = typeof args.success === 'boolean' ? args.success : undefined;
                        const type = args.type || 'general';
                        const highRisk = isHighRiskAction(action, type);
                        const suppliedProof = args.proof && typeof args.proof === 'object' && !Array.isArray(args.proof)
                            ? (0, redact_1.redactSensitiveValue)(args.proof)
                            : undefined;
                        let runtimeGate = null;
                        if (highRisk) {
                            runtimeGate = await withControlDeadline((signal) => (0, index_1.marrowAgentRuntime)(API_KEY, BASE_URL, {
                                action: (0, redact_1.redactSensitiveText)(action),
                                type,
                                agent_id: FLEET_AGENT_ID,
                                session_id: SESSION_ID,
                                proof: suppliedProof,
                                context: { source: 'mcp_auto_risk_upgrade' },
                            }, SESSION_ID, FLEET_AGENT_ID, signal), { highRisk: true, toolName: 'marrow_auto.runtime' });
                            storeRuntimeGuidance(runtimeGate);
                        }
                        const canonicalRuntimeReceiptId = (0, runtime_contract_1.runtimeAuthorizationReceiptId)(runtimeGate);
                        const suppliedRuntimeReceiptId = typeof args.gate_receipt_id === 'string'
                            ? args.gate_receipt_id
                            : canonicalRuntimeReceiptId;
                        const proofCanClose = !highRisk
                            || (0, runtime_contract_1.highRiskRuntimeCanClose)(runtimeGate, suppliedProof, suppliedRuntimeReceiptId);
                        const acceptedSuccess = proofCanClose ? outcomeSuccess : undefined;
                        const delivery = () => (0, index_1.marrowAuto)(API_KEY, BASE_URL, {
                            action,
                            outcome,
                            success: acceptedSuccess,
                            type,
                            proof: suppliedProof,
                            gate_receipt_id: suppliedRuntimeReceiptId || undefined,
                            // Low-risk one-shot capture does not need a policy gate. Consequential
                            // work already obtained and validated canonical runtime authorization.
                            auto_gate: highRisk,
                        }, SESSION_ID, FLEET_AGENT_ID, 8_000);
                        let delivered = null;
                        let deliveryFailure = null;
                        try {
                            delivered = await delivery();
                        }
                        catch (err) {
                            deliveryFailure = (0, request_reliability_1.structuredRequestFailure)(err);
                        }
                        const receipt = await (0, lifecycle_spool_1.recordLifecycleEvent)({
                            apiKey: API_KEY,
                            baseUrl: BASE_URL,
                            deferDelivery: false,
                            event: {
                                event_type: delivered?.committed
                                    ? 'outcome_committed'
                                    : !highRisk && acceptedSuccess === false
                                        ? 'tool_failed'
                                        : !highRisk && acceptedSuccess === true
                                            ? 'tool_completed'
                                            : 'goal_started',
                                harness: process.env.MARROW_CLIENT || process.env.MARROW_HARNESS || 'mcp',
                                agent_id: FLEET_AGENT_ID,
                                session_id: SESSION_ID,
                                decision_id: delivered?.decision_id,
                                action,
                                outcome_state: delivered?.committed ? 'closed' : 'pending',
                                success: delivered?.committed ? acceptedSuccess : highRisk ? undefined : acceptedSuccess,
                                adapter_version: hook_contract_1.MCP_ADAPTER_VERSION,
                                capability_level: 'mcp',
                            },
                        });
                        const response = {
                            action,
                            outcome: outcome || 'pending',
                            warnings: cachedOrientWarnings.map(formatWarningActionably),
                            logging: delivered?.committed
                                ? 'governed_commit_confirmed'
                                : delivered
                                    ? 'intent_confirmed'
                                    : 'durably_queued',
                            receipt,
                            completion_state: delivered?.committed
                                ? 'closed_with_proof'
                                : !proofCanClose
                                    ? 'pending_required_proof'
                                    : outcomeSuccess === undefined
                                        ? 'pending_evidence'
                                        : 'delivery_pending',
                            decision_id: delivered?.decision_id || null,
                            live_delivery: {
                                accepted: Boolean(delivered),
                                committed: Boolean(delivered?.committed),
                                ...(deliveryFailure ? { failure: deliveryFailure } : {}),
                            },
                            host_capability: mcpHostCapability(),
                            client_update: (0, request_reliability_1.localClientUpdate)(),
                            ...(runtimeGate ? { runtime_gate: runtimeGate } : {}),
                        };
                        success(id, {
                            content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
                        });
                        return;
                    }
                    if (toolName === 'marrow_ask') {
                        const query = requireString(args, 'query');
                        const result = await withControlDeadline((signal) => (0, index_1.marrowAsk)(API_KEY, BASE_URL, { query }, SESSION_ID, FLEET_AGENT_ID, signal), { toolName: 'marrow_ask' });
                        try {
                            (0, guidance_cache_1.writeGuidanceCache)({
                                apiKey: API_KEY,
                                baseUrl: BASE_URL,
                                agentId: FLEET_AGENT_ID,
                                context: `## Marrow answer\n- ${String(result.answer || 'No relevant lesson found.').slice(0, 1200)}`,
                            });
                        }
                        catch { /* owner-only cache is best effort */ }
                        toolSuccess(id, clientOperationalPayload('marrow_ask', result));
                        return;
                    }
                    if (toolName === 'marrow_status') {
                        let cached = null;
                        try {
                            cached = (0, status_cache_1.readStatusCache)({ apiKey: API_KEY, baseUrl: BASE_URL, agentId: FLEET_AGENT_ID });
                        }
                        catch { /* owner-only cache is best effort */ }
                        if (cached) {
                            const startedAt = Date.now();
                            refreshStatusInBackground();
                            (0, control_path_state_1.recordControlPathSample)('marrow_status', Date.now() - startedAt, true);
                            toolSuccess(id, clientOperationalPayload('marrow_status', (0, status_cache_1.cachedStatusPayload)(cached)));
                            return;
                        }
                        const result = await withControlDeadline((signal) => (0, index_1.marrowStatus)(API_KEY, BASE_URL, SESSION_ID, FLEET_AGENT_ID, signal), { cacheAware: false, toolName: 'marrow_status' });
                        storeLastKnownStatus(result, 'status');
                        toolSuccess(id, clientOperationalPayload('marrow_status', result));
                        return;
                    }
                    if (toolName === 'marrow_create_key') {
                        const name = requireString(args, 'name');
                        const result = await (0, index_1.marrowCreateKey)(API_KEY, BASE_URL, {
                            name,
                            key_type: args.key_type,
                            scopes: args.scopes,
                            agent_ids: args.agent_ids,
                            expires_at: args.expires_at,
                        }, SESSION_ID, FLEET_AGENT_ID);
                        success(id, {
                            content: [{ type: 'text', text: JSON.stringify({ ...result, warning: formatKeyMaterialWarning() }, null, 2) }],
                        });
                        return;
                    }
                    if (toolName === 'marrow_list_keys') {
                        const result = await (0, index_1.marrowListKeys)(API_KEY, BASE_URL, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_get_key') {
                        const keyId = requireString(args, 'id');
                        const result = await (0, index_1.marrowGetKey)(API_KEY, BASE_URL, keyId, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_revoke_key') {
                        const keyId = requireString(args, 'id');
                        const result = await (0, index_1.marrowRevokeKey)(API_KEY, BASE_URL, keyId, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_rotate_key') {
                        const keyId = requireString(args, 'id');
                        const result = await (0, index_1.marrowRotateKey)(API_KEY, BASE_URL, keyId, SESSION_ID, FLEET_AGENT_ID);
                        success(id, {
                            content: [{ type: 'text', text: JSON.stringify({ ...result, warning: formatKeyMaterialWarning() }, null, 2) }],
                        });
                        return;
                    }
                    // Memory control tools — all use requireString for id validation
                    if (toolName === 'marrow_list_memories') {
                        const result = await marrowListMemories(API_KEY, BASE_URL, { status: args.status, query: args.query, limit: args.limit, agentId: args.agentId }, SESSION_ID);
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
                        const result = await marrowUpdateMemory(API_KEY, BASE_URL, memId, { text: args.text, source: args.source, tags: args.tags, actor: args.actor, note: args.note }, SESSION_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_delete_memory') {
                        const memId = requireString(args, 'id');
                        const result = await marrowDeleteMemory(API_KEY, BASE_URL, memId, { actor: args.actor, note: args.note }, SESSION_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_mark_outdated') {
                        const memId = requireString(args, 'id');
                        const result = await marrowMarkOutdated(API_KEY, BASE_URL, memId, { actor: args.actor, note: args.note }, SESSION_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_supersede_memory') {
                        const memId = requireString(args, 'id');
                        const newText = requireString(args, 'text');
                        const result = await marrowSupersedeMemory(API_KEY, BASE_URL, memId, { text: newText, source: args.source, tags: args.tags, actor: args.actor, note: args.note }, SESSION_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_share_memory') {
                        const memId = requireString(args, 'id');
                        const result = await marrowShareMemory(API_KEY, BASE_URL, memId, args.agentIds || [], args.actor, SESSION_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_export_memories') {
                        const result = await marrowExportMemories(API_KEY, BASE_URL, { format: args.format, status: args.status, tags: args.tags }, SESSION_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_import_memories') {
                        const result = await marrowImportMemories(API_KEY, BASE_URL, args.memories || [], args.mode || 'merge', SESSION_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_retrieve_memories') {
                        const query = requireString(args, 'query');
                        const result = await marrowRetrieveMemories(API_KEY, BASE_URL, query, { limit: args.limit, from: args.from, to: args.to, tags: args.tags, source: args.source, status: args.status, shared: args.shared }, SESSION_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_workflow') {
                        const result = await (0, index_1.marrowWorkflow)(API_KEY, BASE_URL, {
                            action: args.action,
                            workflowId: args.workflowId,
                            instanceId: args.instanceId,
                            name: args.name,
                            description: args.description,
                            steps: args.steps,
                            tags: args.tags,
                            agentId: args.agentId,
                            context: args.context,
                            inputs: args.inputs,
                            stepCompleted: args.stepCompleted,
                            outcome: args.outcome,
                            nextAgentId: args.nextAgentId,
                            contextUpdate: args.contextUpdate,
                            status: args.status,
                        }, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_dashboard') {
                        const result = await (0, index_1.marrowDashboard)(API_KEY, BASE_URL, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_digest') {
                        const result = await (0, index_1.marrowDigest)(API_KEY, BASE_URL, args.period || '7d', SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_agent_status') {
                        const result = await (0, index_1.marrowAgentStatus)(API_KEY, BASE_URL, args.period || '7d', args.agentId || FLEET_AGENT_ID, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_runtime_status') {
                        const result = await withControlDeadline((signal) => (0, index_1.marrowRuntimeStatus)(API_KEY, BASE_URL, args.fast !== false, SESSION_ID, FLEET_AGENT_ID, signal), { cacheAware: false, toolName: 'marrow_runtime_status' });
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_value_report') {
                        const result = await (0, index_1.marrowValueReport)(API_KEY, BASE_URL, args.period || '7d', args.agentId || FLEET_AGENT_ID, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_decision_brief') {
                        const result = await (0, index_1.marrowDecisionBrief)(API_KEY, BASE_URL, {
                            action: args.action,
                            type: args.type,
                            role: args.role,
                            agent_id: args.agentId || FLEET_AGENT_ID,
                            session_id: args.sessionId || SESSION_ID,
                            surfaces: Array.isArray(args.surfaces) ? args.surfaces : undefined,
                            period: args.period,
                        }, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_first_value') {
                        const result = await (0, index_1.marrowFirstValue)(API_KEY, BASE_URL, {
                            action: args.action ? (0, redact_1.redactSensitiveText)(args.action) : undefined,
                            type: args.type,
                            role: args.role,
                            agent_id: args.agentId || FLEET_AGENT_ID,
                            session_id: args.sessionId || SESSION_ID,
                            surfaces: Array.isArray(args.surfaces) ? args.surfaces : undefined,
                            context: args.context && typeof args.context === 'object' && !Array.isArray(args.context)
                                ? (0, redact_1.redactSensitiveValue)(args.context)
                                : undefined,
                            proof: args.proof && typeof args.proof === 'object' && !Array.isArray(args.proof)
                                ? (0, redact_1.redactSensitiveValue)(args.proof)
                                : undefined,
                        }, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_agent_runtime') {
                        const runtimeInput = {
                            action: (0, redact_1.redactSensitiveText)(args.action),
                            type: args.type,
                            role: args.role,
                            agent_id: args.agentId || FLEET_AGENT_ID,
                            session_id: args.sessionId || SESSION_ID,
                            surfaces: Array.isArray(args.surfaces) ? args.surfaces : undefined,
                            context: args.context && typeof args.context === 'object' && !Array.isArray(args.context)
                                ? (0, redact_1.redactSensitiveValue)(args.context)
                                : undefined,
                            proof: args.proof && typeof args.proof === 'object' && !Array.isArray(args.proof)
                                ? (0, redact_1.redactSensitiveValue)(args.proof)
                                : undefined,
                            period: args.period,
                        };
                        const result = await withControlDeadline((signal) => (0, index_1.marrowAgentRuntime)(API_KEY, BASE_URL, runtimeInput, SESSION_ID, FLEET_AGENT_ID, signal), { highRisk: isHighRiskAction(runtimeInput.action, runtimeInput.type), toolName: 'marrow_agent_runtime' });
                        storeRuntimeGuidance(result);
                        storeLastKnownStatus(result.status, 'runtime');
                        toolSuccess(id, clientOperationalPayload('marrow_agent_runtime', result));
                        return;
                    }
                    if (toolName === 'marrow_arbitrate') {
                        const result = await (0, index_1.marrowArbitrate)(API_KEY, BASE_URL, {
                            objective: (0, redact_1.redactSensitiveText)(args.objective),
                            owner_intent: typeof args.ownerIntent === 'string' ? (0, redact_1.redactSensitiveText)(args.ownerIntent) : undefined,
                            conflict_type: args.conflictType,
                            proposals: Array.isArray(args.proposals)
                                ? args.proposals
                                : [],
                            action: typeof args.action === 'string' ? (0, redact_1.redactSensitiveText)(args.action) : undefined,
                            type: args.type,
                            agent_id: args.agentId || FLEET_AGENT_ID,
                            session_id: args.sessionId || SESSION_ID,
                            surfaces: Array.isArray(args.surfaces) ? args.surfaces : undefined,
                            context: args.context && typeof args.context === 'object' && !Array.isArray(args.context)
                                ? (0, redact_1.redactSensitiveValue)(args.context)
                                : undefined,
                            proof: args.proof && typeof args.proof === 'object' && !Array.isArray(args.proof)
                                ? (0, redact_1.redactSensitiveValue)(args.proof)
                                : undefined,
                        }, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_coordinate') {
                        const coordinationArgs = { ...args };
                        delete coordinationArgs.agent_id;
                        delete coordinationArgs.source_agent_id;
                        const result = await (0, index_1.marrowCoordinate)(API_KEY, BASE_URL, coordinationArgs, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_replay_compare') {
                        const result = await (0, index_1.marrowReplayCompare)(API_KEY, BASE_URL, args, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_governance_control_plane') {
                        const result = await (0, index_1.marrowGovernanceControlPlane)(API_KEY, BASE_URL, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_hermes_integration') {
                        const result = await (0, index_1.marrowHermesIntegration)(API_KEY, BASE_URL, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_completion_contracts') {
                        const result = await (0, index_1.marrowCompletionContracts)(API_KEY, BASE_URL, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_evaluate_completion_contract') {
                        const input = {
                            action: args.action,
                            workflow_type: args.workflow_type,
                            risk_level: args.risk_level,
                            evidence: args.evidence && typeof args.evidence === 'object' && !Array.isArray(args.evidence)
                                ? (0, redact_1.redactSensitiveValue)(args.evidence)
                                : undefined,
                        };
                        const result = await (0, index_1.marrowEvaluateCompletionContract)(API_KEY, BASE_URL, input, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_governance_timeline') {
                        const result = await (0, index_1.marrowGovernanceTimeline)(API_KEY, BASE_URL, {
                            agentId: args.agentId || FLEET_AGENT_ID,
                            limit: args.limit,
                        }, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_decision_trace') {
                        const decisionId = args.decisionId;
                        if (!decisionId) {
                            error(id, -32602, 'decisionId is required');
                            return;
                        }
                        const result = await (0, index_1.marrowDecisionTrace)(API_KEY, BASE_URL, decisionId, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_buyer_proof') {
                        const result = await (0, index_1.marrowBuyerProof)(API_KEY, BASE_URL, {
                            agentId: args.agentId || FLEET_AGENT_ID,
                            periodDays: args.periodDays,
                        }, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_mode_recommend') {
                        const result = await (0, index_1.marrowRecommendGovernanceMode)(API_KEY, BASE_URL, {
                            project: args.project && typeof args.project === 'object' && !Array.isArray(args.project)
                                ? (0, redact_1.redactSensitiveValue)(args.project)
                                : undefined,
                            workflow: args.workflow && typeof args.workflow === 'object' && !Array.isArray(args.workflow)
                                ? (0, redact_1.redactSensitiveValue)(args.workflow)
                                : undefined,
                            agent: args.agent && typeof args.agent === 'object' && !Array.isArray(args.agent)
                                ? (0, redact_1.redactSensitiveValue)(args.agent)
                                : { id: FLEET_AGENT_ID },
                            selected_mode: args.selected_mode,
                            selection_source: args.selection_source,
                        }, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_policy_profiles') {
                        const result = await (0, index_1.marrowListPolicyProfiles)(API_KEY, BASE_URL, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_create_policy_profile') {
                        const result = await (0, index_1.marrowCreatePolicyProfile)(API_KEY, BASE_URL, {
                            name: args.name,
                            description: args.description,
                            rules: Array.isArray(args.rules) ? args.rules : undefined,
                        }, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_assign_project_policy_profile') {
                        const result = await (0, index_1.marrowAssignProjectPolicyProfile)(API_KEY, BASE_URL, {
                            project_key: args.project_key,
                            profile_id: args.profile_id,
                        }, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_policy_resolve') {
                        const result = await (0, index_1.marrowResolvePolicy)(API_KEY, BASE_URL, {
                            profile_id: args.profile_id,
                            profile_name: args.profile_name,
                            project: args.project && typeof args.project === 'object' && !Array.isArray(args.project)
                                ? (0, redact_1.redactSensitiveValue)(args.project)
                                : undefined,
                            workflow: args.workflow && typeof args.workflow === 'object' && !Array.isArray(args.workflow)
                                ? (0, redact_1.redactSensitiveValue)(args.workflow)
                                : undefined,
                            agent: args.agent && typeof args.agent === 'object' && !Array.isArray(args.agent)
                                ? (0, redact_1.redactSensitiveValue)(args.agent)
                                : { id: FLEET_AGENT_ID },
                        }, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_workflow_gate') {
                        const result = await (0, index_1.marrowWorkflowGate)(API_KEY, BASE_URL, {
                            action: (0, redact_1.redactSensitiveText)(args.action),
                            description: args.description ? (0, redact_1.redactSensitiveText)(args.description) : undefined,
                            risk_tolerance: args.riskTolerance,
                            requires_approval: args.requiresApproval,
                            context: args.context && typeof args.context === 'object' && !Array.isArray(args.context)
                                ? (0, redact_1.redactSensitiveValue)(args.context)
                                : undefined,
                        }, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_agent_performance') {
                        const result = await (0, index_1.marrowAgentPerformance)(API_KEY, BASE_URL, args.period || '7d', args.agentId || FLEET_AGENT_ID, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_fleet_lessons') {
                        const result = await (0, index_1.marrowFleetLessons)(API_KEY, BASE_URL, {
                            query: args.query,
                            type: args.type,
                            agentId: args.agentId || FLEET_AGENT_ID,
                            limit: args.limit,
                        }, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_record_deployment_memory') {
                        const result = await (0, index_1.marrowRecordDeploymentMemory)(API_KEY, BASE_URL, args, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_create_handoff') {
                        const result = await (0, index_1.marrowCreateHandoff)(API_KEY, BASE_URL, args, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_update_handoff') {
                        const handoffId = args.handoffId;
                        if (!handoffId) {
                            error(id, -32602, 'handoffId is required');
                            return;
                        }
                        const result = await (0, index_1.marrowUpdateHandoff)(API_KEY, BASE_URL, handoffId, args, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_handoff_status') {
                        try {
                            const result = await withControlDeadline((signal) => (0, index_1.marrowHandoffStatus)(API_KEY, BASE_URL, {
                                status: args.status,
                                agentId: args.agentId || FLEET_AGENT_ID,
                                limit: args.limit,
                            }, SESSION_ID, FLEET_AGENT_ID, signal), { cacheAware: false, toolName: 'marrow_handoff_status' });
                            toolSuccess(id, clientOperationalPayload('marrow_handoff_status', result));
                        }
                        catch (error) {
                            if (error instanceof request_reliability_1.MarrowRequestError && error.backendCode === 'MARROW_PLAN_UPGRADE_REQUIRED') {
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
                            }
                            else {
                                throw error;
                            }
                        }
                        return;
                    }
                    if (toolName === 'marrow_session_end') {
                        const result = await (0, index_1.marrowSessionEnd)(API_KEY, BASE_URL, Boolean(args.autoCommitOpen), SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_accept_detected') {
                        const detectedId = args.detectedId;
                        if (!detectedId) {
                            error(id, -32602, 'detectedId is required');
                            return;
                        }
                        const result = await (0, index_1.marrowAcceptDetected)(API_KEY, BASE_URL, detectedId, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_list_templates') {
                        const result = await (0, index_1.marrowListTemplates)(API_KEY, BASE_URL, {
                            industry: args.industry,
                            category: args.category,
                            limit: args.limit,
                        }, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    if (toolName === 'marrow_install_template') {
                        const slug = args.slug;
                        if (!slug) {
                            error(id, -32602, 'slug is required');
                            return;
                        }
                        const result = await (0, index_1.marrowInstallTemplate)(API_KEY, BASE_URL, slug, SESSION_ID, FLEET_AGENT_ID);
                        success(id, { content: [{ type: 'text', text: JSON.stringify(result, null, 2) }] });
                        return;
                    }
                    error(id, -32601, `Method not found: ${toolName}`);
                    return;
                }
                error(id, -32601, `Method not found: ${method}`);
            }
            catch (err) {
                if (err instanceof request_reliability_1.MarrowRequestError && method === 'tools/call') {
                    toolSuccess(id, toolFailure(params?.name, err), true);
                    return;
                }
                const message = err instanceof Error ? err.message : String(err);
                error(id, -32602, (0, redact_1.redactSensitiveText)(message).slice(0, 240));
            }
        }
        // MCP stdio loop — raw stdin, no readline (readline writes prompts to stdout which breaks MCP)
        let buffer = '';
        let pendingRequests = 0;
        let stdinEnded = false;
        function checkExit() {
            if (stdinEnded && pendingRequests === 0) {
                autoCommitOnClose().then(() => process.exit(0));
            }
        }
        process.stdin.setEncoding('utf8');
        process.stdin.on('data', (chunk) => {
            buffer += chunk;
            const lines = buffer.split('\n');
            buffer = lines.pop() || ''; // keep incomplete line in buffer
            for (const line of lines) {
                const trimmed = line.trim();
                if (!trimmed)
                    continue;
                // [FIX #1] Wrap JSON.parse in try-catch to prevent crash on malformed input
                let msg;
                try {
                    msg = JSON.parse(trimmed);
                }
                catch (parseErr) {
                    process.stderr.write(`[marrow] JSON parse error: ${parseErr}\n`);
                    send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
                    continue;
                }
                // MCP notifications (no id) must be silently ignored per spec
                if (msg.id === undefined || msg.id === null)
                    continue;
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
                }
                catch (err) {
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
            }
            else {
                checkExit();
            }
        });
        process.stdin.on('error', (err) => {
            process.stderr.write(`[marrow] stdin error: ${err}\n`);
            process.exit(1);
        });
    } // Close the if (process.argv[2] !== 'keys') block
}
//# sourceMappingURL=cli.js.map