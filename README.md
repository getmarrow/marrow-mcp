# @getmarrow/mcp

> **Memory and decision intelligence for MCP-compatible agents.**

![npm](https://img.shields.io/npm/v/@getmarrow/mcp)
![npm](https://img.shields.io/npm/dw/@getmarrow/mcp)
![npm bundle size](https://img.shields.io/bundlephobia/minzip/@getmarrow/mcp)
![GitHub](https://img.shields.io/github/license/getmarrow/marrow-mcp)
![TypeScript](https://img.shields.io/badge/TypeScript-5.3%2B-blue)
![Node.js](https://img.shields.io/badge/Node.js-18%2B-green)

Marrow gives your agent a memory that compounds.

With `@getmarrow/mcp`, any MCP-compatible client can log intent before acting, inspect live loop state during work, and commit outcomes back to the hive when the work is done. That means your agent stops operating like an amnesiac and starts carrying forward real decision history.

**Your agent stops repeating the same mistakes. It learns from prior sessions — and from the wider Marrow hive — through a clean MCP tool surface.**

---

## Auto-Logging

Marrow auto-logs at three layers — transparent to your agent, invisible to you:

| Layer | How | Agent effort |
|-------|-----|-------------|
| Server-side | Every authenticated API call auto-logged as a decision | Zero |
| SDK | `marrow.think()` / `marrow.commit()` — explicit control | Minimal |
| MCP hooks | `npx @getmarrow/mcp setup` — PostToolUse + UserPromptSubmit hooks | Zero |

**Passive mode in action:** Run `npx @getmarrow/mcp setup` once. Every tool call your agent makes (Bash, file edits, MCP calls) is auto-logged in the background. Marrow intelligence is auto-injected into your agent's context. Fail-silent, 2-second timeout, never blocks your prompt.

Disable: `MARROW_AUTO_HOOK=false`. Debug: `MARROW_HOOK_DEBUG=true`.

---

## Improvement Since Onboarding

`marrow_dashboard` and `marrow_digest` now return an `improvement` block comparing your agents' current performance against their day-1 baseline — a frozen snapshot of the first week of activity. Baseline captures automatically once an account reaches 7 days OR 20 decisions (whichever first).

Four measured deltas, all from real decision data:

- `attempts_per_success` — baseline week vs current week
- `time_to_success_seconds` — median think → successful commit
- `drift_rate` — % of decisions without a matching prior pattern
- `success_rate` — baseline vs current outcome fraction

Sample response:

```json
{
  "improvement": {
    "status": "active",
    "days_since_baseline": 20,
    "decisions_since_baseline": 2124,
    "baseline_captured_at": "2026-04-23T15:07:41.919Z",
    "trigger_reason": "time_7d",
    "time_to_success_seconds": { "baseline": 244, "current": 24, "delta_pct": -90.16 }
  }
}
```

Accounts with <7 days of activity AND <20 decisions get an onboarding payload showing days/decisions until baseline fires. No heuristics, no estimates — every number comes from the agent's own decision history. Token-usage savings remain on the enterprise roadmap.

---

## What's New in v3.9.12

### Agent Status Tool

New MCP tool: `marrow_agent_status`.

Use it at session start or before owner reporting to prove Marrow is passively active. It returns connected state, signal quality, non-sensitive proof, and next actions for the configured agent or fleet.

```json
{
  "active": true,
  "state": "proving_value",
  "signals": {
    "decisions_logged": 42,
    "outcome_coverage": 0.88,
    "success_rate": 0.81
  },
  "quality": { "enough_signal": true, "measurement_risk": "low" }
}
```

No raw action, context, or outcome text is returned.

### Previous: v3.9.9 — Hook Noise Filtering

MCP hooks now skip auto-logging for read-only operations. Tools like `read`, `grep`, `ls`, `sessions_list`, `marrow_list_memories`, and other context-read operations no longer generate Marrow decisions. Only meaningful tool calls (edits, writes, deploys) are logged.

This reduces noise in your decision history and keeps your Marrow training data clean — automatically, no agent discipline required.

### Previous: v3.9.4 — Standalone CLI + Multi-API-Key Management

**Standalone CLI commands (new in v3.9.0):**
```bash
npx @getmarrow/mcp keys create --name "Prod" --type live
npx @getmarrow/mcp keys list
npx @getmarrow/mcp keys rotate --id key_abc123
npx @getmarrow/mcp keys revoke --id key_abc123
npx @getmarrow/mcp keys audit --limit 20
```

**MCP tools (for Claude/Cursor agents):**

- `marrow_create_key` — Create named, scoped API keys (`live`/`test` type, optional scopes and agent bindings)
- `marrow_list_keys` — List all API keys with masked display and tier limits
- `marrow_get_key` — Get key details, usage stats, and expiry info
- `marrow_revoke_key` — Permanently revoke a key
- `marrow_rotate_key` — Atomically rotate (revoke old + create new, returns new key once)

Create/rotate return the full key exactly once with a warning. All other tools return masked keys only.

```bash
npx @getmarrow/mcp --key mrw_...
# Now available: marrow_create_key, marrow_list_keys, marrow_get_key,
#                 marrow_revoke_key, marrow_rotate_key
```

---

### Previous: v3.7.0 — Passive Context Injection

Marrow's passive loop is now complete. v3.2.0 shipped the **write side** — every tool call your agent makes is auto-logged via a PostToolUse hook. v3.7.0 ships the **read side** — Marrow's intelligence is auto-injected into your agent's prompt window via a UserPromptSubmit hook. No agent discipline required for either side.

When you run `npx @getmarrow/mcp setup`, both hooks install automatically. From the next user prompt forward:

1. You type a message to your agent
2. Hook fires, takes your prompt, queries Marrow for relevant warnings + hive patterns + similar past decisions
3. Marrow context (if any) is injected into your agent's view as `additionalContext`
4. Agent responds knowing what failed last time, what worked, and what patterns to leverage

The hook is fail-silent: 2-second timeout on the Marrow API call, errors swallowed, never blocks your prompt. No signal → no injection. `MARROW_AUTO_HOOK=false` disables both hooks. `MARROW_CONTEXT_HOOK_DEBUG=true` enables stderr diagnostics.

This closes the loop Buu identified: Marrow now *just works* — your agent reads from the hive without you ever telling it to.

---

## Agent-Narrated Marrow Contribution

Marrow now tells the agent exactly what it contributed to each decision, so the agent can surface that contribution to the user in plain English — no dashboard required.

Three new fields:

- `marrow_think` returns `marrow_contributed` describing what intelligence Marrow surfaced for this decision (warnings consulted, hive patterns, similar decisions, workflow templates, loop detection, collective insight).
- `marrow_commit` returns `marrow_contributed` describing concrete signals on the commit itself (pattern reused, warning avoided, workflow step).
- `marrow_session_end` returns `session_summary` aggregating Marrow's contribution across the session, plus a one-line `narrative` for the agent to surface as it wraps up.

Each object includes `has_signal: boolean` — when true, the agent narrates Marrow's role in 1 sentence; when false, it stays quiet. The built-in `marrow-always-on` system prompt now instructs agents on tone and timing for these narrations.

Sample think response:

```json
{
  "decision_id": "...",
  "intelligence": { "...": "..." },
  "marrow_contributed": {
    "warnings_consulted": 2,
    "hive_patterns_surfaced": 12,
    "similar_decisions_found": 8,
    "workflow_templates_available": 1,
    "loop_detected": false,
    "collective_intelligence": true,
    "team_context_present": false,
    "has_signal": true
  }
}
```

The user installed Marrow to make their agent better. They should hear, in plain English, what Marrow actually did. Their agent's reply IS the dashboard.

---

## Agent-Narrated Milestones

`marrow_commit` returns a `narrative` field. When a milestone fires (first commit, baseline capture, decision 100/500/1000/5000, weekly recap), the backend returns a human-readable string the agent relays to the user. Otherwise it returns `null`.

```json
{
  "committed": true,
  "narrative": "Baseline captured. Your first-week averages: 42s per task, 1.3 attempts per success."
}
```

Narratives are aggregated metrics only — no user data, no decision content, no heuristics.

---

## Velocity Metrics

`marrow_dashboard` and `marrow_digest` include three measured velocity metrics:

- `attempts_per_success` — avg decisions before an agent lands a success
- `time_to_success_seconds` — median seconds from `marrow_think` to successful `marrow_commit`
- `drift_rate` — % of decisions that didn't link to a known pattern

Each reports `{current, previous, delta_pct, direction}` so operators see whether agents are trending toward or away from improvement.

All metrics are computed from real decision data — no estimates, no heuristics.

---

## Passive Mode

Running `npx @getmarrow/mcp setup` installs a PostToolUse hook into `.claude/settings.json`. After setup, every tool call your agent makes (Bash, file edits, MCP calls) is auto-logged to Marrow in the background — no agent discipline required.

Disable via: `MARROW_AUTO_HOOK=false`

For troubleshooting hook behavior, set `MARROW_HOOK_DEBUG=true` to re-enable one-line stderr diagnostics.

**Operator visibility + auto-intelligence tools.**

## Operator Tools

### marrow_dashboard

Operator dashboard in one call. Account health, top failures, workflow status, recent activity, Marrow's saves metric. Now includes velocity metrics (see v3.3.0 section above).

### marrow_digest

Periodic summary with success rate trend vs previous period. Optional `period` parameter (default `7d`). Now includes velocity summary (see v3.3.0 section above).

### marrow_agent_status

Agent-native proof that Marrow is connected and collecting useful signal. Optional `period` and `agentId` parameters. Returns `active`, `state`, `signals`, `quality`, `proof`, and `next_actions` without exposing raw decision text.

### marrow_session_end

Explicitly end a session and optionally auto-commit any open decision. Prevents orphaned decisions.

### marrow_accept_detected

Convert a detected recurring pattern into an enforced workflow. Pattern ID comes from `orient()` response's `suggested_workflows`.

## Intelligence Fields in marrow_think Response

`marrow_think` surfaces three additional fields when the backend provides them:
- `onboarding_hint` — contextual tip for new accounts
- `intelligence.collective` — anonymized insights aggregated across all Marrow accounts (k-anonymity ≥5 accounts per insight)
- `intelligence.team_context` — recent decisions from other sessions in the same account, so multi-agent teams stay aware of each other's work

---

## Available Templates

24 pre-built workflow templates across 8 industries. Browse via `marrow_list_templates` and install with `marrow_install_template`.

- **Insurance (4):** `claims-triage`, `fraud-review`, `underwriting-decision`, `complaint-escalation`
- **Healthcare (4):** `patient-triage`, `clinical-documentation`, `prior-authorization`, `coding-audit`
- **E-commerce (3):** `order-fulfillment`, `refund-approval`, `return-processing`
- **Legal (3):** `contract-review`, `case-triage`, `document-discovery`
- **SaaS (6):** `code-review-deploy`, `incident-response`, `feature-rollout`, `ticket-triage`, `escalation-flow`, `lead-qualify`
- **Fintech (2):** `etl-pipeline`, `approval-flow`
- **Media (1):** `content-publish`
- **Enterprise (1):** `change-management`

Full catalog with descriptions: [https://getmarrow.ai/docs/#template-marketplace](https://getmarrow.ai/docs/#template-marketplace)

```
marrow_list_templates({ industry: 'insurance' })
marrow_install_template({ slug: 'claims-triage' })
```

## Claude Code Compatibility

Marrow MCP works natively with Claude Code. The server runs as a long-running process and handles the full MCP protocol correctly.

## One-Command Agent Setup

Inject Marrow instructions directly into your project's `CLAUDE.md`:

```bash
npx @getmarrow/mcp setup
```

After setup, your agent uses Marrow automatically every session, and Claude Code PostToolUse hooks auto-log tool calls in the background — no human prompting required.

## Auto-Enroll by Default
The `marrow-always-on` prompt is served to all MCP clients automatically. Set `MARROW_AUTO_ENROLL=false` to opt out.

## Security Hardening
- **Input validation** — all URL path parameters are sanitized to prevent path traversal
- **SSRF protection** — `MARROW_BASE_URL` must use HTTPS
- **Crash protection** — malformed JSON on stdin no longer kills the server
- **Error handling** — proper error logging throughout
- **HTTP status checking** — API errors return clear messages

### Auto-Warn on Orient
The `marrow_orient` tool now accepts `autoWarn: true` and warns you BEFORE you start a task that recently failed:

```json
{
  "name": "marrow_orient",
  "arguments": {
    "autoWarn": true,
    "task": "Fix authentication error"
  }
}
```

**Response includes warnings:**
```
⚠️ HIGH: This task type failed 4x with approach='retry-without-fix'.
         Try approach='apply-patch-first' (89% success rate)
```

### Loop Detection on Think
The `marrow_think` tool now accepts `checkLoop: true` and detects if you're about to retry a failed approach:

```json
{
  "name": "marrow_think",
  "arguments": {
    "action": "Retry auth with method='internal'",
    "checkLoop": true
  }
}
```

**Response includes loop warnings:**
```
🚨 LOOP DETECTED: You're retrying a failed approach.
   Previous failure: 'retry-without-fix' approach not supported.
   Suggested: Use 'apply-patch-first' approach instead.
```

### Rate Limiting
- `marrow_orient`: 30 requests/minute per account
- `marrow_think`: 60 requests/minute per account
- Automatic 429 responses when limit exceeded

### Enhanced PII Protection
- Automatic stripping of emails, phone numbers, API keys from all responses
- Applied to `recentLessons`, `warnings`, and `outcome` fields
- Deep object stripping for complex data structures

---

## The Problem

Most agents still operate with shallow memory.

They might keep a short context window, maybe write a note or two, then lose the important part:
- what they were trying to do
- what they actually did
- whether it worked
- what pattern that should teach the next run

That creates a familiar failure loop:
- the same mistakes repeat
- work gets marked done without structured outcome memory
- agents drift between sessions
- hosts have no clean way to inspect whether the work loop is actually closed

**Marrow fixes this.**

Through MCP, your agent can:
- orient at session start
- log intent before meaningful action
- inspect loop state before handoff or completion
- commit outcomes back to memory cleanly

---

## How It Works

Marrow exposes a simple operating loop through MCP:

```text
orient -> think -> act -> check -> commit
```

That gives agents an actual memory discipline:
- **orient** → pick up recent lessons and current loop state
- **think** → log intent and receive decision intelligence
- **act** → perform the meaningful work
- **check** → inspect whether the loop is still open or missing something
- **commit** → log the outcome and close the loop

The value compounds with use. Each decision your agent logs makes the hive smarter — failure rates drop, patterns emerge, and the next session starts with real intelligence instead of a blank slate. Teams running multiple agents see this compound fastest, but even a single agent builds meaningful history within a few sessions.

---

## Install

### Quick Start (Claude Code)

```bash
# 1. Add the MCP server
claude mcp add marrow -e MARROW_API_KEY=mrw_your_api_key -- npx @getmarrow/mcp

# 2. Set up auto-enrollment (agent uses Marrow automatically)
npx @getmarrow/mcp setup
```

That's it. Your agent will use Marrow automatically in every session.

### Manual Setup

Run it directly with `npx`:

```bash
# Option 1: Pass API key via CLI flag
npx @getmarrow/mcp --key mrw_your_api_key

# Option 2: Use environment variable
MARROW_API_KEY=mrw_your_api_key npx @getmarrow/mcp
```

Or register it in your MCP client config.

---

## MCP Tools

### Core Loop Tools

#### `marrow_orient`
**Call this first** at session start. Returns failure warnings from your history so you avoid known mistakes immediately.

#### `marrow_think`
Log intent before meaningful action. Returns pattern insights, similar past decisions, and a recommended next step.

#### `marrow_commit`
Log the outcome after acting. Closes the decision loop.

#### `marrow_run`
Zero-ceremony wrapper. Handles orient → think → commit in a single call.

#### `marrow_auto`
Fire-and-forget logging. Pass what you're about to do (and optionally the outcome). Marrow handles everything in the background.

### Memory Management Tools

#### `marrow_list_memories`
List memories with optional filters:
- `status` — Filter by status (active, outdated, deleted)
- `query` — Search query
- `limit` — Max results
- `agentId` — Include memories shared with this agent

#### `marrow_get_memory`
Get a single memory by ID.

#### `marrow_update_memory`
Update memory text, tags, or metadata.

#### `marrow_delete_memory`
Soft delete a memory.

#### `marrow_mark_outdated`
Mark a memory as outdated.

#### `marrow_supersede_memory`
Atomically replace a memory with a new version.

#### `marrow_share_memory`
Share a memory with specific agents.

#### `marrow_export_memories`
Export memories to JSON or CSV format.

#### `marrow_import_memories`
Import memories with merge (dedup) or replace mode.

#### `marrow_retrieve_memories`
Full-text search with filters:
- `query` — Search query (required)
- `limit` — Max results
- `from` / `to` — Date range (ISO-8601)
- `tags` — Comma-separated tags
- `source` — Source filter
- `status` — Status filter
- `shared` — Include shared memories

### Query Tools

#### `marrow_ask`
Query the collective hive in plain English. Ask about failure patterns, what worked, what broke, or get a recommendation.

#### `marrow_status`
Check Marrow platform health and status.

---

## Claude Code Config

```bash
claude mcp add marrow -e MARROW_API_KEY=mrw_your_api_key -- npx @getmarrow/mcp
```

## Claude Desktop Config

```json
{
  "mcpServers": {
    "marrow": {
      "command": "npx",
      "args": ["@getmarrow/mcp", "--key", "mrw_your_api_key"]
    }
  }
}
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `MARROW_API_KEY` | Yes | Your API key from getmarrow.ai (or use `--key` flag) |
| `MARROW_BASE_URL` | No | Custom API URL (default: `https://api.getmarrow.ai`). Must use HTTPS. |
| `MARROW_SESSION_ID` | No | Session identifier for multi-agent setups |
| `MARROW_FLEET_AGENT_ID` | No | Agent identifier sent as `X-Marrow-Agent-Id` for fleet attribution |
| `MARROW_AUTO_ENROLL` | No | Auto-enrollment prompt (default: `true`). Set to `false` to disable. |
| `MARROW_AUTO_HOOK` | No | PostToolUse auto-logging kill switch. Set to `false` to disable the hook without editing settings. |
| `MARROW_HOOK_DEBUG` | No | When set to `true`, the hook emits one-line stderr diagnostics for invalid JSON, missing API key, and runtime failures. |

---

## The Always-On Prompt

Marrow includes a built-in prompt called `marrow-always-on` that instructs agents to use Marrow automatically. It's served by default — no configuration needed.

**To use:** In your MCP client, request the `marrow-always-on` prompt and include it in your system instructions. For Claude Code, run `npx @getmarrow/mcp setup` instead — it handles this automatically.

---

## Why This Matters

Without Marrow:
- Agents repeat the same failures session after session
- Successful patterns get lost when the context window clears
- There's no structured trail of what was tried and what worked
- Every new session starts from zero

With Marrow:
- Failure patterns surface before you repeat them
- Successful outcomes compound across sessions
- Every decision has a trail: intent → action → outcome
- The hive gets smarter with every logged decision

**Marrow tells you what went wrong last time before you do it again.**

---

## License

MIT

---

## Related Packages

- **[@getmarrow/sdk](https://www.npmjs.com/package/@getmarrow/sdk)** — TypeScript/Node.js SDK for programmatic access to Marrow. Use this for custom agent integrations outside of MCP.

**📖 Full API reference with all endpoints:** [https://getmarrow.ai/docs/#api-reference](https://getmarrow.ai/docs/#api-reference)
