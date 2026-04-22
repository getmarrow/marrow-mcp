# @getmarrow/mcp

> **Memory and decision intelligence for MCP-compatible agents.**

![npm](https://img.shields.io/npm/v/@getmarrow/mcp)
![npm](https://img.shields.io/npm/dw/@getmarrow/mcp)
![npm bundle size](https://img.shields.io/bundlephobia/minzip/@getmarrow/mcp)
![GitHub](https://img.shields.io/github/license/MajinBuu0x9/marrow-mcp)
![TypeScript](https://img.shields.io/badge/TypeScript-5.3%2B-blue)
![Node.js](https://img.shields.io/badge/Node.js-18%2B-green)

Marrow gives your agent a memory that compounds.

With `@getmarrow/mcp`, any MCP-compatible client can log intent before acting, inspect live loop state during work, and commit outcomes back to the hive when the work is done. That means your agent stops operating like an amnesiac and starts carrying forward real decision history.

**Your agent stops repeating the same mistakes. It learns from prior sessions — and from the wider Marrow hive — through a clean MCP tool surface.**

---

## What's New in v3.1.4

**Operator visibility + auto-intelligence tools.**

### Four New Tools

- **`marrow_dashboard`** — operator dashboard in one call. Account health, top failures, workflow status, recent activity, Marrow's saves metric.
- **`marrow_digest`** — periodic summary with success rate trend vs previous period. Optional `period` parameter (default `7d`).
- **`marrow_session_end`** — explicitly end a session and optionally auto-commit any open decision. Prevents orphaned decisions.
- **`marrow_accept_detected`** — convert a detected recurring pattern into an enforced workflow. Pattern ID comes from `orient()` response's `suggested_workflows`.

### Enhanced `marrow_think` Response
`marrow_think` now surfaces three additional fields when the backend provides them:
- `onboarding_hint` — contextual tip for new accounts
- `intelligence.collective` — anonymized insights aggregated across all Marrow accounts (k-anonymity ≥5 accounts per insight)
- `intelligence.team_context` — recent decisions from other sessions in the same account, so multi-agent teams stay aware of each other's work

Your agent should check for and use these fields — they represent collective intelligence and team-level context that wasn't available in prior versions.

### Since v3.1.0 (cumulative through v3.1.4)

**v3.1.1** — Published fixes

**v3.1.2** — Agent identity: new `MARROW_FLEET_AGENT_ID` env var adds X-Marrow-Agent-Id header to all requests so decisions tag your specific agent for fleet dashboards.

**v3.1.3** — Template marketplace tools: `marrow_list_templates` (filter by industry/category) and `marrow_install_template` (install workflow by slug). 24 pre-built templates across insurance, healthcare, ecommerce, legal, saas, fintech, media, enterprise.

**v3.1.4** — README / docs sync (this release).

Example usage in an agent:
```
marrow_list_templates({ industry: 'insurance' })
  → [claims-triage, fraud-review, underwriting-decision, complaint-escalation]
marrow_install_template({ slug: 'claims-triage' })
  → workflow installed in your fleet
```

---

## Claude Code Compatibility

Marrow MCP works natively with Claude Code. The server runs as a long-running process and handles the full MCP protocol correctly.

## One-Command Agent Setup

Inject Marrow instructions directly into your project's `CLAUDE.md`:

```bash
npx @getmarrow/mcp setup
```

After setup, your agent uses Marrow automatically every session — no human prompting required.

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
| `MARROW_AUTO_ENROLL` | No | Auto-enrollment prompt (default: `true`). Set to `false` to disable. |

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
