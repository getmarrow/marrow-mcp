# Changelog

## 3.9.97

- Free and starter gates are advisory again: an advisory runtime gate no longer hard-blocks the action. Enforcement is skipped only on a positive advisory contract; enforced tiers are unchanged, and a `block` decision still denies on every plan.
- Claude Code shows an owner-approval prompt for an enforced review, only in its default, acceptEdits and auto permission modes. In plan, dontAsk and bypassPermissions modes, and for arbitration reviews, the action is still denied. Policy, proof and fail-closed behavior are otherwise unchanged.
- Far fewer false blocks: read-only shell commands are classified as read-only and are no longer stopped.
- Clearer denial messages that state the reason and the next step.
- Send `protocol_version` when verifying an action permit.
- On a denial the hook makes a best-effort attempt, capped at 2.5 s, to close the decision with a denied outcome. If the backend does not confirm, the decision stays open.
- Faster hooks: PostToolUse telemetry is spooled and delivered by a detached background nudge that honors opt-outs, uses a nonce lock, and honors large `Retry-After` values.
- Better retry of pending writes: honor `retry_after_ms`, resume the same write, and read the optional `lease_remaining_ms`; the passive lifecycle acknowledgement window is wider.
- Hook lifecycle receipts are no longer silently dropped when many hook processes write the spool at once: each event takes the spool lock fewer times (once when deferred, twice around inline delivery instead of four times), and the lock wait is a 10 s time budget with randomized 10-30 ms polling instead of a fixed attempt count.
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
