# Changelog

## 3.9.99

- Chat and terminal approvals: one click in the host's own permission prompt (Claude Code with a pass-through `PermissionRequest` marker hook and an async `PostToolBatch` hook that `marrow-mcp setup` adds; Cursor shell and MCP calls; MCP clients with elicitation through `marrow_auto`), or a typed reply in local interactive Codex, Gemini CLI and Cursor sessions, with the code shown only to the person. A decline is a permission rejection, never an interruption.
- Quiet by default: an ordinary hold never emails anyone. Attended hosts that cannot ask, and unattended runs (headless Claude Code including its GitHub Action, `codex exec`, `gemini -p`, Cursor cloud and background agents), hold the action and the agent carries on. The account owner's one-tap link only for owner-locked categories, the owner's standing decline when the operator asks, or unattended runs with the owner's pings on.
- The first prompt of an interactive session shows "N held actions are waiting for you" (action type and agent only), and refreshes the owner-locked categories for outages.
- `marrow_auto` waits on the approval status and resumes on the same gate receipt, treats a spent receipt as final, strips the server's `exact_next_action` from the `runtime_gate` it returns, and never writes `proof.owner_approval`; a caller-written `proof.owner_approval` is stripped from every commit. New `request_owner_link` parameter.
- A slow Marrow is not an outage: a holdable action stays held, routine actions keep flowing. Per-host budgets from the hosts' real 5 s limits. Real outages keep the outage policy; a waiting hold and owner-locked categories stay held on every host.
- One approval lets exactly one call run. Lifecycle records are per attempt.
- Hook-classified calls send `normalized_action` with the runtime call and the host-approval report: the tool kind and name, program names (and edit paths) and a SHA-256 of the secret-free command or tool input. The command text is never sent. An `mcp_elicitation` answer is client-attested.
- On a service without host approvals, Claude Code behaves as 3.9.98 (asks in its dialog).
- SDK `3.7.65`.

## 3.9.98

- Fix `npx @getmarrow/mcp setup` and every other `npx @getmarrow/mcp …` command. Since 3.9.57 they failed with "could not determine executable to run", because the package had two executables and none named after the package. The package now also provides an executable named `mcp`, so those commands work again. `marrow-mcp` and `marrow-mcp-canary` are unchanged.
- Note for global installs: `npm install -g @getmarrow/mcp` now also adds a command named `mcp`, which may share a name with other tools. `npx` users are unaffected.
- Add the `npx:check` release check and a test that pack the package and run it through `npx`, so this cannot regress unnoticed.

## 3.9.97

- Free and starter gates are advisory again: an advisory runtime gate no longer hard-blocks the action. Enforcement is skipped only on a positive advisory contract; enforced tiers are unchanged, and a `block` decision still denies on every plan.
- Claude Code shows an owner-approval prompt for an enforced review, only in its default, acceptEdits and auto permission modes. In plan, dontAsk and bypassPermissions modes, and for arbitration reviews, the action is still denied. Policy, proof and fail-closed behavior are otherwise unchanged.
- Far fewer false blocks: read-only shell commands are classified as read-only and are no longer stopped.
- Clearer denial messages that state the reason and the next step.
- Send `protocol_version` when verifying an action permit.
- On a denial the hook makes a best-effort attempt, capped at 2.5 s, to close the decision with a denied outcome. If the backend does not confirm, the decision stays open.
- Faster hooks: PostToolUse telemetry is spooled and delivered by a detached background nudge that honors opt-outs, uses a nonce lock, and honors large `Retry-After` values.
- Better retry of pending writes: honor `retry_after_ms`, resume the same write, and read the optional `lease_remaining_ms`; the passive lifecycle acknowledgement window is wider.
- Hook lifecycle receipts are much less likely to be dropped when many hook processes write the spool at once: each event takes the spool lock fewer times (once when deferred, twice around inline delivery instead of four times), and the lock wait is a 10 s time budget with randomized 10-30 ms polling instead of a fixed attempt count. A receipt can still be lost if the lock is held for the full 10 s, for example by a lock left behind by a killed hook process.
- Test suites run in an isolated HOME so local Marrow configuration cannot affect results.

## 3.9.96

- Send only accepted `source_meta` when the native pre-action hook creates a decision; Think rejected the hook's extra keys with HTTP 400, denying protected actions after an allowing gate. The gate receipt and correlation still bind on the action permit.
- Send the risk level of enforced actions so the runtime issues a durable gate receipt that can back an action permit instead of a non-durable fast-path receipt.
- Stop unprotected actions at the runtime gate without creating a decision or requesting a permit.
- Name reached control rejections by HTTP status and stable failure code without echoing service text. Policy, proof and fail-closed behavior are unchanged.

## 3.9.95

- Preserve supplied model usage through the real native session-hook stdin boundary.
- Capture only the latest proven native Codex model-call delta with stable dedupe, cache/reasoning subset semantics and bounded private transcript reads for supported schema `0.157.1`.
- Reject noncanonical/symlink paths and abstain on unknown versions, missing context, counter resets or unproven child identity. No billing dimensions, coverage, baselines or savings are inferred.

## 3.9.93

- Use canonical Auto operation IDs in the full eleven-tool canary so numeric UUIDs pass existing privacy validation and reach durable outcome closure.
- Preserve authentication, proof gates, idempotency, request deadlines and retries.

## 3.9.92

- Keep JSON response bodies and cancellation within existing control-call deadlines without expanding retry budgets.
- Reject malformed First Value and buyer-proof response envelopes.
- Retain allowlisted backend failure categories, stage and operation timings, and verified fixture outcome closure in the control-path canary.

Historical unavailable receipts lack backend failure identity; these regressions reproduce current defects without asserting a historical cause.
