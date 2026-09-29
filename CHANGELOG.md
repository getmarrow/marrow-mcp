# Changelog

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
