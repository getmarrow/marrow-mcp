# Marrow AI MCP Server

> `@getmarrow/mcp`: the control layer for AI agents. Marrow AI puts a named yes on an action before your agent acts, and leaves proof the next agent can reuse.

**Which Marrow?** This is Marrow AI from [getmarrow.ai](https://getmarrow.ai) (npm `@getmarrow/mcp`, MCP Registry `ai.getmarrow/marrow`). It is not affiliated with marrow.id, HyperMarrow, marrow.works or other projects named Marrow.

[getmarrow.ai](https://getmarrow.ai) · [Docs](https://getmarrow.ai/docs/) · [Marrow AI for MCP](https://getmarrow.ai/marrow-for-mcp) · [MCP Registry entry](https://registry.modelcontextprotocol.io/v0.1/servers/ai.getmarrow%2Fmarrow/versions/latest) · [Changelog](https://github.com/getmarrow/marrow-mcp/blob/master/CHANGELOG.md) · [![getmarrow/marrow-mcp MCP server](https://glama.ai/mcp/servers/getmarrow/marrow-mcp/badges/score.svg)](https://glama.ai/mcp/servers/getmarrow/marrow-mcp)

Marrow AI is the runtime control and proof layer for teams running AI agents. It applies policy and prior lessons before consequential actions, then records the evidence and outcome afterward.

Use `@getmarrow/mcp` when your agent client supports the Model Context Protocol and you want Marrow available inside the agent's normal workflow. It works with Claude Code, Claude Desktop, Cursor and other MCP-compatible clients without replacing the model or harness.

## Quick start

1. **Create a key.** Sign up at [getmarrow.ai/signup](https://getmarrow.ai/signup), then open the dashboard, go to **API keys** and choose **Create API key**. The key is shown once.
2. **Activate.** Make the key available as `MARROW_API_KEY` (from your secret storage, or an owner-only `~/.marrow/env`), then run the installer from a terminal:

   ```bash
   npx -y @getmarrow/install@latest activate
   ```

   Fallback if you cannot set the key first (a key typed on a command line stays in your shell history): `MARROW_API_KEY=<your_key> npx -y @getmarrow/install@latest activate`.
3. **Restart** the agent host and review/enable its hook trust.
4. **Verify:**

   ```bash
   npx -y @getmarrow/install@latest doctor --self-test
   ```

**What is enforced.** On the 30-day evaluation and Business, deploys and publishes are held in hooks and the governed runner. Team and Free warn. If Marrow is unreachable, hooks let actions run with a warning, and the governed runner stops protected actions it cannot verify. Over MCP, the agent gets the decision and is expected to follow it. Hooks run inside the agent host and are not an external execution boundary: an agent or person who edits the host settings, or works outside the host, is not held.

## Agent Discovery

- **Publisher:** Marrow AI. Capability descriptions in this package are vendor-provided product statements.
- **Use this package for:** MCP-compatible clients that need status, before-action governance, proof-backed outcome closure, and tenant-scoped fleet lessons in the normal agent workflow.
- **Product category:** agent fleet governance and control layer.
- **Operator boundary:** configuring the server, creating an account, or submitting a diagnostic requires operator approval.
- **Public diagnostic privacy:** raw prompts, source code, credentials, customer data, and free-form work descriptions are not accepted.
- **Machine-readable product facts:** https://getmarrow.ai/llms.txt and https://getmarrow.ai/.well-known/marrow.json

Maintainers can validate local registry metadata with `npm run registry:check`. After an approved registry publication, `npm run registry:verify` confirms that the official registry returns the exact package name and version; package metadata alone is not treated as publication proof.

Public operating guides:

- [Governance Readiness Assessment](https://getmarrow.ai/governance-readiness)
- [Marrow for MCP clients](https://getmarrow.ai/marrow-for-mcp)
- [Marrow for OpenAI Codex](https://getmarrow.ai/marrow-for-codex)
- [Marrow for Claude Code](https://getmarrow.ai/marrow-for-claude-code)
- [Marrow for Cursor](https://getmarrow.ai/marrow-for-cursor)
- [Marrow for Hermes Agent](https://getmarrow.ai/marrow-for-hermes)
- [Marrow for OpenClaw](https://getmarrow.ai/marrow-for-openclaw)

The assessment accepts bounded selections only. It does not install Marrow, authorize a purchase, accept free-form work content, or establish compliance, security, or ROI.

## Where Marrow fits

Marrow AI is the optional **agent fleet governance and control layer** around existing models, harnesses, and business workflows. It is not a model provider, agent harness, memory-only tool, or observability replacement.

Marrow fits when one or more of these is true:

- Two or more autonomous agents, models, or harnesses contribute to one accountable workflow (`multiple_autonomous_agents`).
- Agents can deploy, merge, publish, change production data, use privileged tools, spend money, or message customers (`production_or_privileged_access`).
- The workflow has repeated failures, retries, regressions, or known lessons that should affect the next action (`repeated_workflow_failures`).
- Work can be marked complete without proof, verification, or a recorded business outcome (`missing_completion_evidence`).
- Policy, approval, or completion requirements vary across agents, tools, environments, or teams (`inconsistent_policy_enforcement`).
- Agents operate around regulated, proprietary, personal, financial, health, legal, credential, or otherwise sensitive workflows (`regulated_or_sensitive_work`).

## Where Marrow is not a fit

- One advisory assistant performs no shared, privileged, production, or accountable business action (`single_low_risk_assistant`).
- The workflow has no need for policy, proof, outcome accountability, or fleet coordination (`no_governance_requirement`).
- The operator has declined Marrow evaluation or installation (`operator_declined_evaluation`).

Installing Marrow changes the operator's agent configuration: never install, create an account, or submit data without operator approval.

Verify current claims through the [public evidence manifest](https://getmarrow.ai/.well-known/marrow-evidence.json), [reference graph](https://getmarrow.ai/.well-known/marrow-reference-graph.json), and [integration cards](https://getmarrow.ai/.well-known/marrow-integrations/index.json).

## Install

For most installations, follow the [Quick start](#quick-start): the universal installer's `activate` command. The steps below are the manual, MCP-only route.

Get a key at [getmarrow.ai/signup](https://getmarrow.ai/signup) and keep it in an owner-only key file: put `MARROW_API_KEY=<your_key>` in `~/.marrow/env`, then run `chmod 700 ~/.marrow && chmod 600 ~/.marrow/env` (Marrow rejects a key file whose folder others can write):

```bash
mkdir -p ~/.marrow && chmod 700 ~/.marrow
# put MARROW_API_KEY=<your_key> in ~/.marrow/env
chmod 600 ~/.marrow/env
```

Fallback if you cannot use the key file (a key typed on a command line stays in your shell history): set it through trusted secret storage, or `export MARROW_API_KEY=<your_key>` for the session.

Hooks-only setup (`marrow-mcp setup` writes hooks and `CLAUDE.md` instructions, and adds no MCP server). It needs the key first: without one it prints how to get it and exits 2 before writing anything.

```bash
npx -y --package=@getmarrow/mcp@latest marrow-mcp setup
```

The MCP server and Claude Code's cooperative pre-action hook read the key only from the process environment or an owner-controlled `~/.marrow/env` (or `~/.marrow/env.local`) with owner-only permissions (`chmod 600`). An owner file that is a symlink, readable or writable by others, owned by another user, or in a directory others can write supplies nothing, key included; the missing-key message names it with the `chmod` fix. Repository-local files (`.env`, `.env.local`, `.marrow/env*` in the working directory or its parents) are never read for `MARROW_API_KEY` or any other `MARROW_*` setting, whatever their permissions, so project content cannot replace the account, agent, or API endpoint. If one holds a key, the missing-key message names that file and the fix: run `npx @getmarrow/install doctor`, or move the line to `~/.marrow/env`, then `chmod 600 ~/.marrow/env`. The public hook callback is still a client self-report, not certified host provenance or an external enforcement boundary.

Then configure the MCP server:

```json
{
  "mcpServers": {
    "marrow": {
      "command": "npx",
      "args": ["-y", "--package=@getmarrow/mcp@latest", "marrow-mcp"]
    }
  }
}
```

After setup writes MCP configuration or hooks, restart the agent host and review/enable its hook trust. Then verify the reloaded environment:

```bash
npx -y @getmarrow/install@latest doctor --self-test
```

Successful setup alone does not mean this process reloaded or that hooks are active. Keep savings at zero until observed usage supplies evidence.

## Tool Profiles

Ordinary setup does not require `MARROW_TOOL_PROFILE`. When the variable is unset, Marrow uses the `primary` profile and exposes exactly the 17 tools in [Primary MCP Tools](#primary-mcp-tools).

- `MARROW_TOOL_PROFILE=primary` explicitly selects the same 17-tool primary surface.
- `MARROW_TOOL_PROFILE=core` preserves the seven-tool runtime, think, commit, ask, status, auto, and handoff-status surface.
- `MARROW_TOOL_PROFILE=full` exposes the complete advanced and legacy catalog for integrations that require it.

An invalid value returns a bounded configuration error with the exact allowed values; it never falls back to `full`. Restart the MCP process after changing the profile.

Local visibility does not grant paid access. Every tool call continues through Marrow's backend authentication, tenant, key-permission, plan, proof, and policy enforcement. MCP status responses include `mcp_tool_profile` with the configured and effective profile, visible tool names/count, and a backend primary-tool entitlement projection when fresh authenticated evidence is provided. Missing or cached entitlement evidence is labeled unavailable and cannot authorize a call.

## Keeping MCP Current

Marrow's hosted API, website, and dashboard update automatically; local MCP hooks, configuration, and pinned package commands do not silently rewrite themselves. Keeping them current delivers new client-side features, compatibility improvements, and any published security fixes. During authenticated status/runtime activity, Marrow returns a `client_update` notice when the package is behind or unknown, and passive context shows the agent the exact update and verification commands.

```bash
npx -y @getmarrow/install@latest activate
npx -y @getmarrow/install@latest doctor

# Manual MCP-only setup
npx -y --package=@getmarrow/mcp@latest marrow-mcp setup

# Verify live read latency, last success, and local backlog
npx -y --package=@getmarrow/mcp@latest marrow-mcp ping
```

Detection and notification are automatic. After explicit installer activation, the local controller may restore only Marrow-managed hooks/configuration. Package upgrades, owner policy, credentials, and unrelated configuration remain explicit and subject to the operator's normal change policy.

## Pending write recovery

A direct `marrow_think` can receive a durable pending response before the backend can safely expose a decision ID. The client recognizes the explicit `agent_write_reconciliation.v1` think contract and the corresponding current legacy pending shapes. It retries the identical authenticated request with the original idempotency key, agent and session, at most three reconciliation rounds with the existing one-second wait between rounds. Each round retains up to two transport attempts for retryable failures, so one invocation can send up to six HTTP requests, all with the same key and body. It never creates a placeholder decision or starts an automatic operation to recover a direct think call. Unknown states, conflicting keys and unsafe responses fail closed; exhaustion returns a retryable structured `pending_receipt` with `committed:false`, the original `idempotency_key`, and `request_hash`. To resume manually, pass both fields to `marrow_think` with the same arguments, credentials, agent and session. The hash binds that exact canonical request and scope; drift is rejected before sending. No prompt, credential, or raw scope is included in the receipt. Caller keys must be privacy-safe opaque identifiers.

A saved `observed_unverified` outcome is terminal observation evidence, not a committed outcome. Receipt expiry cannot retroactively authorize completed work. Preserve the original decision, receipt, proof and key; an already authorized durable checkpoint may finish through its existing exact recovery path. Do not repeat the action merely to obtain a fresh receipt.

## Keyless seatbelt

When a pre-action hook has no usable Marrow key and the machine shows no sign of a Marrow account (for example an owner key file, a claim marker or Marrow's local approval state), the hook runs a local seatbelt instead of holding every protected action:

- **It stops seven kinds of action:** a change to Marrow's hooks or settings or an owner-only Marrow command (S0), a force-push or delete of a protected branch (S1), a production deploy (S2), a package publish (S3), reading credentials or secrets, including a project `.env` file other than a template (S4), a recursive delete outside the workspace (S5), and decoded data run by a shell or interpreter (S-x). The stop is the host's own deny, with text that tells the agent to leave the action to the machine owner.
- **Everything else gets no Marrow decision, so the host's own approval step decides:** Claude Code and Codex get an empty answer, Cline is not cancelled and Windsurf gets no output. Gemini CLI gets `{"decision":"allow"}`, the only answer its installed guard passes without blocking. Cursor asks with its own approval prompt before a shell command that a hook without a key used to hold. Cursor's other tools (MCP calls included) and Grok have no neutral answer, so they keep holding what a hook without a key held before. An action that a hook without a key already let through gets the same answer as before.
- **It fails closed:** an internal error, a check that runs past 300 ms, or input the host cut short stops the action. Windsurf and Cline do not tell the hook the working folder, so there a recursive delete outside the temporary folders stops.
- **Local receipts:** each seatbelt decision is written to `~/.marrow/seatbelt/receipts/` on this machine, as codes and keyed hashes only (no command text, argument, path, URL or tool name), kept for up to 90 days or 50 MB. Nothing is uploaded. Agents cannot edit the receipts or read the device salt that keys them (S0, S4); receipts are a record, not an authority.
- **It is a seatbelt, not a vault:** it runs on the machine as your user and makes no network call. A determined agent can get around a local check, for example with a script it writes now and runs later, an interpreter, or a tool path with no hook.
- **With an account:** a machine linked to an account but with no working key keeps every hold it had, and these stops apply too. With a working key nothing changes; the seatbelt only checks the action after Marrow has answered, without changing the answer.

`marrow-mcp setup` still needs a key; hooks without a key come from the installer.

## Hook behavior details

These behaviors shipped in 3.9.100 and still apply.

- **One Marrow entry per hook event:** `marrow-mcp setup` recognizes the installer's local-runtime hook commands exactly (same version throughout, no additions), keeps whichever form is there (local runtime or npx), and never adds a second entry. Your own hooks stay as they are.
- **Plain words without a key:** on a machine linked to a Marrow account, a protected action with no working key is denied with "Marrow is linked to an account but has no working key; owner: run `marrow doctor`." A machine with no account runs the [keyless seatbelt](#keyless-seatbelt). The hooks read the key from `MARROW_API_KEY` or an owner-only `~/.marrow/env.local` or `~/.marrow/env`, never from a file others can read.
- **First-prompt briefs say so:** the prompt hook marks its brief `context.prompt_brief: true`; a brief authorizes nothing.
- **Deploy text only word for word:** the exact command text is sent only for `sst deploy --stage <stage>` (optionally `--verbose`, optionally after one `npx` or `bunx`), with a stage of lower-case letters, digits and dashes, in a single clause with nothing else in it, so Marrow can judge the stage itself. Every other command, including other deploy tools, sends only the hash; no free-text word leaves the machine.
- **No lifecycle event id with two payloads:** an event id names its payload, so a later run is a new record and a resend carries the same bytes.

## Setup and key handling

These behaviors shipped in 3.9.101 and still apply.

- **Setup with no key stops:** `marrow-mcp setup` with no key, or with a key only in an untrusted place such as a project `.env`, stops, writes nothing and tells you how to get a key.
- **Keys are read from trusted places only:** the key comes from the environment or an owner-only `~/.marrow/env`.
- **Key-file steps include `chmod 700 ~/.marrow`** before `chmod 600 ~/.marrow/env`.
- **Hold messages say where to approve:** a held action says how to approve it where your host really asks.
- **One enforcement sentence:** the "what is enforced" wording matches the public site.

## What's New in v3.9.102

- **A cloned project's `.env` cannot redirect the MCP server:** repository-local `.env`, `.env.local` and `.marrow/env*` files are never read for `MARROW_API_KEY` or any other `MARROW_*` setting, so project content cannot point the server at another account, agent or API endpoint.
- **Safer key-file advice:** an owner file that is a symlink, readable or writable by others, owned by another user, or in a directory others can write supplies nothing, and the missing-key message names the file with the `chmod` fix.
- **Only Marrow's own tools skip the gate, by exact name:** a tool is Marrow's own only when its server is exactly `marrow` and its tool name is exactly one this package registers. Look-alike servers, other cases, extra spaces or suffixes go through the pre-action gate like any other MCP tool. Re-run `marrow-mcp setup` to refresh hooks written with the old matcher.

Earlier behaviors are kept under [Setup and key handling](#setup-and-key-handling) and [Hook behavior details](#hook-behavior-details). v3.9.99 brought approvals in the host prompt; see [Approvals in the Host Prompt](#approvals-in-the-host-prompt).

Earlier release notes moved from this README to [CHANGELOG.md](https://github.com/getmarrow/marrow-mcp/blob/master/CHANGELOG.md).

## Observed usage and calculated cost

Session-hook commands retain observed usage supplied on stdin for capture. Session totals remain cumulative and unpriced without a proven delta; this does not add transcript collection or manufacture missing model usage.

A connector tool call does not automatically expose the upstream chat model's usage. Native hooks capture only usage actually present in their event. Adapters can pass an observed request endpoint to `extractModelUsageFromUnknown`; native hooks accept explicit host configuration through `MARROW_MODEL_USAGE_ENDPOINT`. First-party billing is recognized only for HTTPS `api.openai.com` and `api.anthropic.com`, with no credentials or custom port. Set this only when it describes the requests whose responses the hook observes; do not label a proxy or mixed-provider stream as first-party. Endpoints and response content are never sent as usage evidence.

`MARROW_MODEL_USAGE_PRICING_DIMENSIONS` accepts a compact JSON object of dimensions actually established by the request configuration (for example tier, region and modality). Missing dimensions remain unknown. Observed service tier, Anthropic inference geography and single-TTL cache-creation counts take precedence. Mixed cache TTL writes remain unresolved. Set `MARROW_MODEL_USAGE_BILLING_MODE=subscription` only for subscription usage; displayed cost then means an API-equivalent estimate, not an invoice. Never use these settings to fill gaps by guessing.

Direct `marrow_model_usage` and Commit `model_usage` also accept billing host, token semantics, cache writes, response/event identity, occurrence time, pricing dimensions and explicit coverage/comparison metadata. Invalid supplied values fail validation; absent counts do not become observed zero. Stable IDs retain retry identity. Session totals and partial stream-start observations remain cumulative and unpriced without a proven delta. This hook does not assemble SSE streams or read transcripts. If cost is unavailable, inspect the returned reason and coverage: missing host/model/counts/variant evidence cannot be recovered from a successful tool call. No capture infers complete coverage, overhead or a causal baseline; baseline and net savings stay pending until those are proven.

## Governed Action Flow

With `MARROW_TOOL_PROFILE` unset, the default primary profile uses `marrow_agent_runtime` followed by `marrow_commit`. It exposes 17 tools; `marrow_auto` is available only after an explicit `core` or `full` selection and MCP restart. Primary status and lessons use `marrow_agent_status` and `marrow_fleet_lessons`.

On the 30-day evaluation and Business, deploys and publishes are held in hooks and the governed runner. Team and Free warn. If Marrow is unreachable, hooks let actions run with a warning, and the governed runner stops protected actions it cannot verify. Over MCP, the agent gets the decision and is expected to follow it. Hooks run inside the agent host, so a host edited or bypassed by an agent or person is not held. Before deploys, merges, publishes, migrations, credential changes, financial operations, or customer-impacting work:

1. Call `marrow_agent_runtime` or `marrow_decision_brief`.
2. Stop when the returned decision is `block` or `review_required`; otherwise follow its prior lesson and proof contract.
3. Reuse a server-created runtime `decision_id` when the completion contract identifies it. Call `marrow_think` when decision creation is still required; explicitly selected core/full profiles can also use `marrow_auto`. Keep `marrow_agent_runtime.runtime_authorization.id` separate as the gate receipt for consequential work.
4. Perform the action only when its gate allows it. Codex, Grok, and Gemini use configured native hooks only after restart and host hook review. The governed wrapper remains an explicit bounded fallback: `npx @getmarrow/install run --agent <agent-id> -- -- <command>`.
5. Call `marrow_commit` with that `decision_id`, the outcome, gate receipt, and required proof.

`marrow_agent_runtime` returns `runtime_authorization` with the authoritative gate receipt. An ordinary or arbitrated runtime that creates a decision also returns its server-created `decision_id`; follow `completion_contract.decision_creation_required` and preserve the returned scope. When decision creation is required, call `marrow_think`; core/full can also use `marrow_auto`. Auto requests the existing expanded runtime response to check receipt identity, decision, action, agent, session, and expiry before reusing that decision; it does not obtain a second authorization fetch.

A `review_required`, `block`, or `outcome_observation_only` result never permits the action. If the action already occurred and its real result must be preserved, `marrow_commit` can ask runtime to bind observation delivery to the existing decision, action, session, and agent. The exact backend `outcome_observation_only` correlation is non-durable and non-authorizing, so MCP never sends it as a gate, arbitration, or owner-approval receipt. An accepted observation reports `committed: false`, `outcome_state: "observed_unverified"`, `authorization_granted: false`, and `trusted_learning_applied: false`, plus the backend's `exact_next_action`. This is durable delivery, so do not retry or spool the same observation. To promote it into trusted learning, obtain the named authorization and proof, then make an explicit new commit attempt using the exact observed payload. Never synthesize a decision, receipt, approval, or authorization.

`marrow_auto` returns an `operation_id`, phase, and resumable state. For a resumable pending phase, respect `retry_after_ms` and use the same operation ID, tenant, agent, session, action, type, surfaces, outcome, proof and receipt payload; auto never shortens the requested finite delay to fit its core budget. When the phase is `proof_required`, supply the requested measured evidence before retrying that operation. Stable phase idempotency keys preserve the original decision and outcome across retries; the backend remains authoritative for acceptance and conflicts. A four-second automatic write attempt ceiling leaves replay time inside the existing eight-second total budget. Long server delays remain pending without waiting beyond that budget. Malformed or unbounded Retry-After headers stop automatic continuation. Only committed:true confirms closure; pending is not evidence that a server write failed.

If a receipt expires while the same decision remains open, explicitly request normal runtime again with the original action, type, surfaces, agent and session. A fresh request key is required: replaying the old runtime key replays its old receipt. Verify the returned `runtime.decision_id` still matches the original, keep the new `runtime.runtime_authorization.id` as `gate_receipt_id`, and satisfy the current proof and approval contract. For a scope with an explicit target, use the `marrowAgentRuntime` library or `POST /v1/agent/runtime` preserving that target; the public MCP runtime schema does not expose target. Do not renew through post-action `auto_gate`: it only obtains observation truth. A fresh receipt never retrospectively authorizes an action taken without permission, and a changed scope is a different decision. Expired or used receipts may return an accepted `observed_unverified` result with `committed:false`; that is not closure.

For an ordinary hold (`completion_contract.owner_approval.mode: "ordinary_non_arbitrated"`), auto waits in `owner_approval_required` and reads the gate receipt's approval status as the server advises. Call auto again with the same operation ID after `retry_after_ms`; once the server has recorded an approval (see [Approvals in the Host Prompt](#approvals-in-the-host-prompt)), auto resumes on the same decision and gate receipt. A decline closes the decision as a gate denial when the action has not run, and a spent gate receipt is final: auto reports the operation as closed and never asks to run it again. A caller-written `proof.owner_approval` is never an approval: MCP strips it, and only an approval the server records counts. Unknown ordinary completion contracts remain stopped without automatically starting arbitration.

For arbitration, the account owner picks and approves one proposal through a one-tap link (see [Approvals in the Host Prompt](#approvals-in-the-host-prompt)); auto waits on the status read and commits with the `owner_approval_receipt_id` it returns. Otherwise call auto with the same operation ID, `arbitration_receipt_id`, and the server-issued `owner_approval_receipt_id`. Proof or chat text cannot substitute for this receipt. A CLI closed response reports `phase: "closed"`, `live_delivery.committed: true`, and `resumable: false`; the library result uses `committed: true`. An outcome record never changes a stopped action into an allowed action.

The CLI's lifecycle `receipt.queued: true` means its stable event is stored locally for later bounded delivery; `receipt.accepted: false` must not be read as server acceptance. Transient failures preserve the queued event and retry schedule for later bounded delivery, including after restart. Server retry guidance is respected. Authentication failures remain failed with explicit credential-repair guidance and are never auto-retried; conflicted events are server-owned evidence and are never replayed; every other dead letter self-heals through bounded automatic recovery during passive nudges. Process exit can interrupt the background nudge, leaving the event for a later run. `phase_timings_ms.total` measures core auto phases. `response_timings_ms` contains numeric `core`, `durable_enqueue`, and `full_response`; the last ends at response construction and excludes subsequent stdout drain and host processing. Canary `latency_ms` independently measures the MCP round trip, while `attempts` and `retry_wait_ms` describe measured outer tool retries, not internal database or network calls.

Example pre-action request:

```json
{
  "tool": "marrow_agent_runtime",
  "arguments": {
    "action": "deploy the production worker",
    "type": "deploy",
    "role": "deploy",
    "surfaces": ["repository", "deployment", "production"]
  }
}
```

Example closeout:

```json
{
  "tool": "marrow_think",
  "arguments": {
    "action": "deploy the production worker",
    "type": "process",
    "checkLoop": true
  }
}
```

```json
{
  "tool": "marrow_commit",
  "arguments": {
    "decision_id": "decision_id returned by marrow_think",
    "gate_receipt_id": "receipt id returned by marrow_agent_runtime",
    "success": true,
    "outcome": "Production deploy succeeded and smoke checks passed.",
    "proof": {
      "checks": ["tests passed", "secret scan passed", "production smoke passed"],
      "rollback_target": "previous release"
    }
  }
}
```

High-risk work can be allowed, warned, held for review, or blocked according to account policy. Low-risk work can use passive guidance and bounded cached state where the runtime contract permits it.

When two or more agents disagree on the next action, call `marrow_arbitrate`
before either proposal executes. It uses the same `/v1/agent/runtime` control
plane and returns `selected`, `synthesized`, `review_required`, or `blocked`
with a durable tenant-scoped receipt explaining the policy, evidence, authority,
risk, and dissent behind the result.

```json
{
  "tool": "marrow_arbitrate",
  "arguments": {
    "objective": "Release the audited backend change safely",
    "ownerIntent": "Production deploys require independent audit proof",
    "proposals": [
      {
        "proposal_id": "deploy-now",
        "agent_id": "jarvis",
        "action": "Deploy the tested commit now",
        "risk_level": "high"
      },
      {
        "proposal_id": "audit-first",
        "agent_id": "barvis",
        "action": "Audit the exact commit, then release only if it passes"
      }
    ]
  }
}
```

Marrow resolves agent roles from the account rather than trusting caller claims.
Evidence references must be opaque identifiers; do not send raw prompts, logs,
URLs, paths, credentials, or customer content. The arbitration response owns the
`decision_id`, gate receipt, and arbitration receipt used at commit. A
`review_required` result needs the account owner's approval of one proposal
through a one-tap link; pass the resulting short-lived, single-use
`owner_approval_receipt_id` to `marrow_commit`. An agent cannot authorize itself
with a proof field.

Use `marrow_coordinate` when parallel agents could edit the same file, service,
deployment, or workflow. An acquired lease returns a one-time release capability.
Child agents can then create a compact proof packet containing only a bounded
summary and opaque durable evidence references. Complete is accepted only when
the linked outcome and required proof are actually closed.

Use `marrow_replay_compare` after two model or workflow variants have each
recorded an outcome. It compares that existing evidence under one tenant task;
it does not run models, retain prompts, or infer a winner from labels.

## Approvals in the Host Prompt

When Marrow holds an action for approval (`review_required`), the person approves it where they already work, and nobody has to log in. The hooks record the answer with Marrow; the agent never reports or claims an approval. The Marrow dashboard shows receipts and history; it is not where approvals happen.

| Host and session | What the person does |
| --- | --- |
| Claude Code (`default`, `acceptEdits`; `auto` from v2.1.257) | Answers Claude Code's own permission dialog. In `plan`, `dontAsk` and `bypassPermissions` modes they switch to the default mode and retry. |
| Cursor shell and MCP calls, local session | Answers Cursor's own approval prompt |
| Codex and Gemini CLI, local interactive session with their own approval prompt on | Types the reply the hook showed them only, such as `marrow approve CODE` |
| MCP clients with elicitation (`marrow_auto`) | Answers the client's own dialog (client-attested) |
| Codex TUI before its prompt hook, Cline and Windsurf in the editor | Uses the host's own approval step, if they have it on: the hook answers neutrally, never with an explicit allow, and Marrow records the result as not observed by Marrow |
| Grok, Gemini without its prompt hook, Cursor at `preToolUse` and Cursor's other tools, Codex with its approval prompt off, Gemini CLI in any mode but `default` (`--yolo`, `-y`, `--approval-mode`, or `general.defaultApprovalMode` in its system, user or project `settings.json`, or shell commands allowed without asking, or a settings file it cannot read), or no evidence of a person | No typed reply and no code (the agent could answer one itself); the action waits quietly for the owner |
| Unattended runs (headless Claude Code, `codex exec`, `gemini -p`, Cursor cloud) | Nothing in the run: the action waits quietly and the agent carries on |
| Arbitration review | The account owner picks one proposal through a one-tap link |

- **The owner's email link is the exception.** It is sent only for a category the owner locked, for the owner's own standing decline once the operator asks to reverse it (retrying, or `request_owner_link: true` on `marrow_auto`), for an unattended run when the owner turned on unattended pings, or for an arbitration review when the operator asks. An ordinary hold never emails anyone.
- **Codex with its approval prompt off holds quietly** (`--yolo`, `-a never`, `--full-auto`, `--approve-for-me`, `-s danger-full-access`, the same through `-c` or `$CODEX_HOME` config). Not read: Codex settings from managed or project configs. Not detected: Cline's auto-approve and Windsurf's Turbo mode (they live in editor state with no reliable signal). With those on, the host runs the action without asking; Marrow records it as not observed by Marrow, never as the person's answer. Owner-locked categories still hold.
- **Held actions at the next session.** At the first prompt of an interactive session the person sees "N held actions are waiting for you", with the action type and agent only, and approves one by retrying it there.
- **One approval, one run.** Of two identical calls on one approval, one runs and the other is denied.
- **The exact action, never its text.** Hook-classified calls send `normalized_action`: the tool kind and name, program names (and edit paths, with the home directory as `~`) and a SHA-256 of a normalized form. Event and correlation ids come from that normalized form, never from the raw command, input or prompt. Credentials are replaced where they stood, data a command reads is hashed so `SELECT` and `DROP` are different actions, and anything else that may be secret is withheld. An action that carried a credential or a withheld value is marked `truncated: true`: Marrow never reuses an approval for it, so a held one asks each time. The verdict, the hold and the prompt are the same as without the mark. A credential value ends only at whitespace, a quote, or a separator followed by another `name=` field, so actions that differ after it stay different actions and no part of a password with `#`, `,`, `&` or `;` in it stays in the hashed form. A password given as a plain argument to an unknown program (`./deploy.sh hunter2`) cannot be recognized; it stays only inside the hash.
- **Slow and down are different.** Codex and the 5-second hosts answer within their hook limits (Codex within 2 s of starting, and on Linux about 2.6 s from launch when npx starts in under about 1.6 s). A slow Marrow keeps a holdable action held; a real outage keeps the outage policy, and a waiting hold or owner-locked category stays held.
- **Honest labels and texts.** Without a dialog or typed-reply marker an approval is recorded as the host's allow rule. Text a person reads names no receipt ids. A refused action names a plain fix.

## Passive Use

`npx -y --package=@getmarrow/mcp@latest marrow-mcp setup` configures supported prompt, pre-action, tool-result, permission-marker, and session-stop hooks. Configuration, public hook argv, and API-key-authenticated callbacks are client self-reports. They preserve raw lifecycle activity but do not prove that the host invoked a hook or certify passive control.

### Capability and coverage contract

| Integration mode | Coverage Marrow can claim |
| --- | --- |
| MCP tools-only | On demand; covers only explicit MCP tool calls |
| Configured native hooks | Cooperative telemetry/context only; activity is client-self-reported and coverage remains unverified |
| `createPassiveRuntime().install()` | Only the owned Node process, and only while that runtime is installed and running |
| Governed runner | Only the command launched through the wrapper |
| Custom host | Requires a bounded event adapter; covers only the lifecycle events whose receipts Marrow observes |

This contract is model-neutral. A model name, host header, API key, public hook entrypoint, config file, installed hook entry, successful MCP handshake, or client-self-reported lifecycle callback does not certify passive coverage or enforcement. An unknown MCP host therefore gets the generic `mcp-client` identity and the same on-demand tools, schemas, and API semantics as a named host. Public lifecycle callbacks and hook activity are client-self-reported and cannot verify or certify passive coverage; independent authority is required.

When invoked by a supported host, the configured hooks send compact classifications and lifecycle receipts. They do not need raw prompts, completions, command output, tool output, or credentials. A completed tool or session does not automatically become a successful business outcome; explicit success/failure closure is required.

Setup installs distinct Claude Code and Grok hook entrypoints. The public entrypoint supplies only a client-reported display label; it is not host provenance. Hook event JSON cannot select the lifecycle harness or agent. Agent identity comes only from owner configuration when present, otherwise the request omits it so the authenticated service can derive the credential-bound identity. Every hook lifecycle event is marked `source: client_self_reported` and omits `capability_level: native_hooks`, adapter certification, configuration fingerprints, expected hooks, and observed-hook certification fields. Legacy, unknown, and custom entrypoints stay generic.

Claude Code hooks may cooperatively request guidance and apply the harness permission response, but that does not certify always-on control. Codex native hooks map a block to the supported synchronous deny response; a review-required hold follows [Approvals in the Host Prompt](#approvals-in-the-host-prompt). Cursor and Composer use the same Cursor-native pre-action, result, failure, and stop adapters. Cline uses native pre-action and post-tool adapters plus TaskCancel closeout; its documented TaskComplete hook remains coming soon and is not claimed as observed coverage. Windsurf uses native pre-action, success-result, and response-closeout adapters and requires Restricted Mode to be off. Gemini CLI uses native BeforeTool, AfterTool, and AfterAgent adapters; AfterAgent is the deterministic per-turn closeout and no SessionEnd delivery is claimed. Grok uses global native PreToolUse, PostToolUse/PostToolUseFailure, and one nonblocking Stop closeout; Marrow's generated Grok file contains no duplicate SessionEnd closeout. These native paths keep MCP on demand and require restart plus host hook review. Where a native contract cannot make a generic ask enforceable (Cursor at `preToolUse`, Gemini, and Grok), protected review-required or unavailable-control work is denied and waits for approval; Cline and Windsurf hand an ordinary hold to the host's own prompt when a person is evidenced. All activity remains client-self-reported rather than verified host telemetry, and the governed wrapper remains an explicit bounded fallback. Unknown and custom hosts remain on demand unless they provide a bounded event adapter, whose activity is still not certification without an independent authority.

Transient lifecycle receipts use a bounded owner-only spool and are retried with stable event IDs. Dead letters self-heal: recoverable failures are retried automatically with bounded attempts and cooldown during passive nudges, and conflicted events are recognized as server-owned evidence that is never replayed. Operators can inspect and drain it without exposing event content:

```bash
npx -y --package=@getmarrow/mcp@latest marrow-mcp spool-status
npx -y --package=@getmarrow/mcp@latest marrow-mcp drain-spool
```

The output contains only state, bounded pending/failed/recoverable/server-owned/recovery-exhausted counts, oldest receipt timestamps, capacity, and an exact fix. Only authentication-class dead letters require the operator: restore the credential binding, then drain. A drain applies only to the active credential-and-agent namespace: isolated legacy namespace debt is reported separately and never changes a successful active-namespace drain into a failure. Legacy files are never replayed, merged, deleted, or attributed to the active identity. Restore the exact original identity to drain one, or preserve the selected file unchanged in a separate owner-only quarantine directory when that identity is unavailable. Authentication failures in the active namespace remain explicit durable failures with repair guidance; recovery-exhausted events stop cycling instead of retrying indefinitely, and `drain-spool` remains an explicit operator tool rather than a user requirement.

Check the installed runtime:

```text
marrow_agent_status
```

Status diagnostics distinguish missing keys, invalid keys, wrong bound-agent identity, network limits, missing hooks, and incomplete proof. They include an exact repair action without exposing secrets.

## Primary MCP Tools

| Tool | Purpose |
| --- | --- |
| `marrow_agent_runtime` | One-call pre-action status, policy gate, relevant lessons, proof requirements, and exact next action |
| `marrow_arbitrate` | Resolve conflicting agent proposals before execution and return an explainable arbitration receipt |
| `marrow_coordinate` | Acquire/release resource leases and exchange compact child proof packets across tenant agents |
| `marrow_replay_compare` | Compare two existing proof-backed outcomes without executing a model |
| `marrow_decision_brief` | Compact operating brief for meaningful work |
| `marrow_think` | Record intent and retrieve relevant governance intelligence |
| `marrow_commit` | Close an action with outcome, receipt, and proof |
| `marrow_workflow_gate` | Evaluate a workflow action against policy |
| `marrow_completion_contracts` | List proof contracts for consequential action types |
| `marrow_evaluate_completion_contract` | Check whether evidence is sufficient to call work complete |
| `marrow_agent_status` | Verify capture, identity, outcome coverage, and hook health |
| `marrow_value_report` | Return account/agent value evidence without requiring a dashboard |
| `marrow_buyer_proof` | Return owner-ready governance and reliability evidence |
| `marrow_governance_timeline` | Inspect decisions, gates, proof packs, and outcomes over time |
| `marrow_decision_trace` | Explain one governed decision and return its owner-readable intervention receipt |
| `marrow_fleet_lessons` | Retrieve proven lessons authorized for the current account or agent |
| `marrow_model_usage` | Record compact token, cost, and latency counts when the harness exposes them |

The package also exposes key management, fleet handoff, deployment history, adaptive policy, context/lesson, query, and workflow-example tools. See the [complete source-of-truth documentation](https://getmarrow.ai/docs/) for every tool and field.

## Context and Workflow Examples

The stable `marrow_*memory*` tools manage authorized context and prior lessons used by governance decisions. They are advanced supporting APIs, not a separate product category.

The template tools expose 24 configurable workflow examples. They are starting points for policy design, not customer case studies, regulatory validation, legal advice, or proof of production use in each listed industry.

## Trust and Data Boundaries

- Private account, fleet, workflow, proof, and agent data remains tenant-scoped by default.
- Agent-bound keys can be restricted to an allowed identity and permission set.
- Sanitized aggregate contribution is optional and never means sharing raw prompts, code, secrets, proof packs, account identifiers, agent identifiers, or customer identities.
- Existing API keys are never returned after creation; key material should be supplied through the client's secret store.
- Marrow returns guidance and policy data. Agents must not execute returned text as shell input.
- An agent cannot approve itself: a caller-written `proof.owner_approval` is stripped, chat or proof text is never an approval receipt, and only an approval the server records counts.
- Approvals given in your tool's prompt are reported by software on your machine. An agent running as your user could fake one for a single held action. For actions that must have your own approval, lock that category (verified only); then only your one-tap link or the dashboard counts, and Marrow never learns from or reuses tool-reported approvals across agents.
- Never connect an agent to the email inbox that receives Marrow approval mail. An agent that can read that inbox can open the one-tap link itself.

See the [Trust Center](https://getmarrow.ai/trust/) for implemented controls, current limits, and roadmap status.

## Environment

| Variable | Required | Purpose |
| --- | --- | --- |
| `MARROW_API_KEY` | Yes | Account or agent-bound API key |
| `MARROW_BASE_URL` | No | API base override |
| `MARROW_AGENT_ID` | No | Bound agent identity for MCP tools |
| `MARROW_FLEET_AGENT_ID` | No | Fleet agent identity used by passive setup |
| `MARROW_HOOK_BACKGROUND_NUDGE` | No | Default on: PostToolUse only spools the event and starts one detached background process that delivers it, so the hook adds almost no latency. Set to `false` to keep bounded inline delivery (750 ms) inside the hook. Never runs when `MARROW_AUTO_HOOK=false` or local control is disabled |
| `MARROW_WRITE_RECONCILIATION_BUDGET_MS` | No | Default `15000`, range 1000-60000: total time a pending think or commit may wait, resuming the same idempotency key and request hash after the server's `retry_after_ms` or `Retry-After`. When the next wait does not fit, the call returns the resumable pending receipt and never reports success |

## Documentation

- [Source-of-truth docs](https://getmarrow.ai/docs/)
- [Trust Center](https://getmarrow.ai/trust/)
- [Status](https://getmarrow.ai/status/)
- [GitHub](https://github.com/getmarrow/marrow-mcp)

## License

MIT

## Related Packages

- [@getmarrow/install](https://www.npmjs.com/package/@getmarrow/install) - default installer, self-test, governed runner, and operator TUI
- [@getmarrow/sdk](https://www.npmjs.com/package/@getmarrow/sdk) - Node.js and TypeScript integration for owned agent runtimes

Codex native usage capture accepts a bound `thread/tokenUsage/updated` event or a bounded current transcript with the supported `0.157.1` schema. It records only the latest observed model call when matching model/turn counters prove that call's delta; it does not reconstruct whole turns or history. Repeated hooks use a compact private checkpoint and stable usage ID. Unknown versions, missing context, counter resets, unsafe/oversized files, and unproven subagent bindings abstain. Cached input and reasoning output remain subsets. Billing endpoint, tier, region, and subscription mode require explicit capture configuration; native model names do not establish a price or savings baseline.
