# @getmarrow/mcp

> **Memory and decision intelligence for MCP-compatible agents.**

![npm](https://img.shields.io/npm/v/@getmarrow/mcp)
![npm](https://img.shields.io/npm/dw/@getmarrow/mcp)

`@getmarrow/mcp` connects your Claude, Cursor, or any MCP client to Marrow's collective memory. Every tool call auto-logged, intelligence auto-injected — no agent discipline required.

---

## Install

```bash
npm install @getmarrow/mcp
```

## One-Command Setup (Claude Code)

```bash
npx @getmarrow/mcp setup
```

Installs PostToolUse + UserPromptSubmit hooks. Every tool call auto-logs to Marrow. Intelligence auto-injected into your agent's context. Zero agent code required.

Disable: `MARROW_AUTO_HOOK=false`. Debug: `MARROW_HOOK_DEBUG=true`.

## Manual MCP Config

Add to your Claude Desktop or MCP client config:

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

## Core MCP Tools

| Tool | Description |
|------|-------------|
| `marrow_orient` | Session-start failure warnings |
| `marrow_think` | Log intent + get hive intelligence |
| `marrow_commit` | Record outcome — closes decision loop |
| `marrow_run` | Zero-ceremony: orient → think → commit |
| `marrow_auto` | Fire-and-forget background logging |
| `marrow_dashboard` | Account health, failures, velocity |
| `marrow_digest` | Weekly summary with trends |
| `marrow_session_end` | Close session with summary |

### 🆕 v3.8.2 — Multi-API-Key Management

| Tool | Description |
|------|-------------|
| `marrow_create_key` | Create scoped API keys |
| `marrow_list_keys` | List all keys (masked) |
| `marrow_get_key` | Key details + usage stats |
| `marrow_rotate_key` | Atomically rotate a key |
| `marrow_revoke_key` | Permanently revoke |

### Memory Management Tools

| Tool | Description |
|------|-------------|
| `marrow_list_memories` | List with filters |
| `marrow_get_memory` | Single memory by ID |
| `marrow_update_memory` | Update text or tags |
| `marrow_delete_memory` | Soft-delete a memory |
| `marrow_share_memory` | Share with specific agents |

## Auto-Logging

Marrow auto-logs at three layers:

| Layer | How | Effort |
|-------|-----|--------|
| Server-side | Every API call auto-logged | Zero |
| SDK | `marrow.think()` / `marrow.commit()` | Minimal |
| MCP hooks | `npx @getmarrow/mcp setup` | Zero |

Passive mode: run setup once, auto-logging runs silently forever.

## Full Documentation

📖 **Complete API reference, metrics, features, and examples:**
**[https://getmarrow.ai/docs](https://getmarrow.ai/docs)**

- [Auto-Logging](https://getmarrow.ai/docs/#auto-logging)
- [Metrics & Intelligence](https://getmarrow.ai/docs/#metrics-intelligence)
- [API Key Management](https://getmarrow.ai/docs/#api-key-management)
- [API Reference](https://getmarrow.ai/docs/#api-reference)
