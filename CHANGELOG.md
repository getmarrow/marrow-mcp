# Changelog

## 3.9.100

- `marrow-mcp setup` recognizes the installer's local-runtime hook commands (`/bin/sh -c 'M="$HOME/.marrow/runtime/mcp/<version>/run"; …'`, the `{ M=…; }` block inside `sh -c`, and the node guard) only in their exact generated shape with the same version throughout. An entry for the same command keeps its form, so Claude Code and Grok get one Marrow entry per event in either order; an older version's local form is replaced; a look-alike (another path, a suffix, mixed versions) is left alone as the person's own hook. Doctor and coverage read the local form too. Setup still never writes Codex, Cursor, Gemini or Windsurf hook files.
- No key: a protected action says "Marrow can't find your key: run `npx @getmarrow/install` once in this machine's terminal." Keys are read from `MARROW_API_KEY`, then an owner-only `~/.marrow/env.local` or `~/.marrow/env`.
- The first-prompt brief carries `context.prompt_brief: true`; the service treats only flagged requests as briefs.
- `normalized_action.tool_input.command` (the normalized words) is sent only for the service's one allowed deploy grammar: `sst deploy --stage V` (or `--stage=V`), optionally with `--verbose`, optionally after one `npx` or `bunx`; one stage matching `^[a-z0-9-]{1,32}$`; a single clause of ASCII words with no operator, quote, variable, substitution, subshell or wrapper; no other word; not truncated. Wrangler, vercel, netlify, serverless/sls, railway, `pnpx`, `npm exec` and `pnpm dlx` send no text (their non-production flags can fall back to production settings). Everything else sends the hash only. No environment label is added; the service decides.
- Lifecycle event ids name their payload (`<kind>-<correlation>-<12 hex>` of the stored fields and time), so the service never receives one id with two payloads; a quick retry of the Stop hook reuses its queued record.
- Typed replies on Gemini CLI also follow its settings files, by Gemini's precedence (system defaults, `~/.gemini/settings.json`, the project's `.gemini/settings.json`, the system settings file, then flags): any mode but `default` (auto edit, plan, YOLO, auto accept or an unknown value), shell commands allowed without asking, or a settings file that cannot be read or parsed means no typed reply and no code. A `--approval-mode default` flag overrides a settings mode; `--yolo` overrides a settings `default`.
- Version 3.9.100 in `package.json`, `server.json` and the hook commands.

## 3.9.99

These approvals turn on when the Marrow service update ships; until then held actions work as in 3.9.98: Claude Code asks in its dialog and other hosts hold for the account owner.

Approvals given in your tool's prompt are reported by software on your machine. An agent running as your user could fake one for a single held action. For actions that must have your own approval, lock that category (verified only); then only your one-tap link or the dashboard counts, and Marrow never learns from or reuses tool-reported approvals across agents. Never connect an agent to the email inbox that receives Marrow approval mail. An agent that can read that inbox can open the one-tap link itself.

- Plain words where something is wrong: a refused protected action names the fix (for example "Marrow doesn't know this agent yet. Run `npx @getmarrow/install` again in this terminal, then retry.") instead of "Restore trusted governance". Text a person reads in a prompt or notice no longer shows gate receipt ids or automatic seat agent ids. Lifecycle events with no known agent omit `agent_id` so the service resolves it. A `marrow_commit` retry that added proof but conflicts with the outcome Marrow already holds says which proof fields are still missing.
- Arbitration links say whether a person at this session asked (`person_present`): only on the operator's request. A live link is never resent; the agent is told the owner already has it.
- Normalized actions are built in linear time with size and time limits (anything withheld for size or time, or cut by a host adapter, is marked `truncated`). The Codex hook answers within 2 seconds of starting, and on Linux within about 2.6 seconds of Codex launching it when npx starts in under about 1.6 seconds (npx start-up comes out of its share).
- Chat and terminal approvals: one click in the host's own permission prompt (Claude Code with a pass-through `PermissionRequest` marker hook and an async `PostToolBatch` hook that `marrow-mcp setup` adds; Cursor shell and MCP calls; MCP clients with elicitation through `marrow_auto`), or a typed reply in local interactive Codex and Gemini CLI sessions, with the code shown only to the person. No typed reply and no code where the agent could answer one itself: Codex with its approval prompt off, Gemini CLI in YOLO mode (`--yolo`, `-y`, `--approval-mode yolo`) and Cursor (its auto-run cannot be seen); the action waits for the owner. A decline is a permission rejection, never an interruption.
- Where Marrow can neither ask in the host nor observe the answer and the hook can answer neutrally (a local Codex TUI before its prompt hook ran and not started with its approval prompt off by flags, `-c` or config; Cline and Windsurf inside the editor), an ordinary hold is left to the host's own approval step: the hook gives no decision, never an explicit allow. The outcome is recorded as approved through the host's prompt, not observed by Marrow (`host_prompt_not_observed`, an allow rule). Grok, Gemini CLI and Cursor `preToolUse` have no neutral answer and hold quietly. Owner-locked categories still hold.
- Quiet by default: an ordinary hold never emails anyone. Attended hosts that cannot ask, and unattended runs (headless Claude Code including its GitHub Action, `codex exec`, `gemini -p`, Cursor cloud and background agents), hold the action and the agent carries on. The account owner's one-tap link only for owner-locked categories, the owner's standing decline when the operator asks, or unattended runs with the owner's pings on.
- The first prompt of an interactive session shows "N held actions are waiting for you" (action type and agent only), and refreshes the owner-locked categories for outages.
- `marrow_auto` waits on the approval status and resumes on the same gate receipt, treats a spent receipt as final, strips the server's `exact_next_action` from the `runtime_gate` it returns, and never writes `proof.owner_approval`; a caller-written `proof.owner_approval` is stripped from every commit. New `request_owner_link` parameter.
- A slow Marrow is not an outage: a holdable action stays held, routine actions keep flowing. Per-host budgets from the hosts' real 5 s limits. Real outages keep the outage policy; a waiting hold and owner-locked categories stay held on every host.
- One approval lets exactly one call run. Lifecycle records are per attempt.
- Hook-classified calls send `normalized_action` with the runtime call and the host-approval report: the tool kind and name, program names (and edit paths, with the home directory as `~` and another user's home as `/home/[user]`), a SHA-256 of a normalized form of the command or tool input, and `truncated: true` when that hash could not cover everything that decides the action. The command text is never sent. Credentials are replaced where they stood, and the action is marked `truncated` (Marrow cannot see a replacement inside the hash), so an approval is never reused for an action that carried a secret: a held one asks each time, while verdicts, holds and prompts are unchanged; data a command reads (pipes, heredocs, here-strings, environment values) is hashed, so commands that differ only in their data are different actions; anything else that may be secret is withheld and marked `truncated`, so Marrow always asks. A credential value ends at whitespace or a quote; at `&`, `;` or `|` only before a `name=`/`name:` field or a shell operator; at `#` or `,` only before a `name=`/`name:` field, so no part of a password holding those characters stays in the hashed form. Credential names match by containing a credential word (`SECRET_KEY_BASE`, `GITHUB_TOKEN_V2`, `DBPASS`), except names of references (`…_FILE`, `…_NAME`, `…_ID`, `…_PATH`) and ordinary words (`BYPASS`, `COMPASS`). A credential value that still holds `name=value` marks the action `truncated`, so actions that differ after a credential stay different actions; in a secrets command the value of a target flag such as `--repo` or `--namespace` stays part of the action. A password given as a plain argument to an unknown program cannot be recognized; it stays only inside the hash. Lifecycle event and correlation ids come from the normalized action, never from the raw command or tool input, so calls that differ only in a secret share them and a retry keeps them; a prompt event's id comes from the host's prompt, turn or generation id (a fresh one when the host gives none), never from the prompt text. An `mcp_elicitation` answer is client-attested.
- On a service without host approvals, Claude Code behaves as 3.9.98 (asks in its dialog), and `marrow_auto` returns `owner_approval_required` at once instead of waiting on the approval status.
- SDK `3.7.65`.
- Package metadata: the MCP Registry name moves from `io.github.getmarrow/marrow` to `ai.getmarrow/marrow` (`mcpName` and `server.json`), and the registry entry gains a `title`, `websiteUrl` and `icons`.
- New npm description and keywords. README retitled "Marrow AI MCP Server" with a which-Marrow note; release notes previously kept in the README move to this file so npm shows the whole README.
- The metadata change itself changes no commands, tools, hooks, policy, proof or fail-closed behavior.

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

## Release notes previously kept in the README (moved in 3.9.99, text unchanged)

### v3.9.87

v3.9.87 hardens the authenticated control-path canary against single-sample transport blips so monitoring stops flapping on a healthy service. The canary now retries transport-class delivery failures (`request_failed`, `service_unavailable`, `connection_reset`, `dns_unavailable`, `tls_failure`, `edge_access_denied`, `rate_limited`) in-run with the same idempotent operation before declaring a failure, gives the asynchronous `marrow_auto` and `marrow_first_value` calls a separate deadline ceiling (thirty seconds via `MARROW_MCP_CANARY_ASYNC_TOOL_TIMEOUT_MS`), and raises the default total canary budget to forty-five seconds so bounded retries fit. Results recovered by a retry are annotated with `recovered_on_retry: true`. Authentication, authorization, contract, and package-identity failures remain immediate hard failures with no retry. Tool surface, client contracts, and request deadlines are unchanged.

v3.9.86 was published with the adapter version constant still at `3.9.85`, so the strict canary identity check rejected it; it is deprecated — use `3.9.87`. SDK `3.7.62` and installer `0.1.56` are unchanged; install MCP `3.9.87`, reload the host, review hook trust, and verify before claiming the updated client is active.

### v3.9.98

v3.9.98 fixes `npx @getmarrow/mcp setup` and every other `npx @getmarrow/mcp …` command. Since 3.9.57 they failed with "could not determine executable to run", because the package had two executables and none named after the package. The package now also provides an executable named `mcp`, so those commands work again. `marrow-mcp` and `marrow-mcp-canary` are unchanged, and the `npx -y --package=@getmarrow/mcp@latest marrow-mcp …` commands shown in this README keep working. If you install the package globally (`npm install -g @getmarrow/mcp`), it now also adds a command named `mcp`, which may share a name with other tools; `npx` users are unaffected. Tools, hooks and policy behavior are unchanged.

### v3.9.97

v3.9.97 makes native hook control easier to live with. Free and starter gates are advisory again, so an advisory gate no longer hard-blocks work; a `block` decision still denies on every plan. In Claude Code's default, acceptEdits and auto permission modes, an enforced review now shows an owner-approval prompt instead of a denial. In plan, dontAsk and bypassPermissions modes, and for arbitration reviews, the action is still denied. Read-only commands such as `git show`, `git log` and `ls` no longer trigger false blocks, and denial messages now say plainly why an action was stopped and what to do next. The hook sends `protocol_version` when it verifies an action permit. When an action is denied, the hook makes a best-effort attempt, capped at 2.5 s, to close the decision with a denied outcome; if the backend does not confirm, the decision stays open. Hooks return faster because telemetry is delivered by a detached background process that honors opt-outs and never blocks the action (see `MARROW_HOOK_BACKGROUND_NUDGE` in Environment). Pending writes are retried more reliably: the client honors `retry_after_ms` and the optional `lease_remaining_ms`, and resumes the same write instead of starting a new one (see `MARROW_WRITE_RECONCILIATION_BUDGET_MS`). Hook lifecycle receipts are much less likely to be dropped when many hook processes write the spool at once: each event takes the spool lock fewer times, and the lock wait is a 10 s time budget with randomized polling. A receipt can still be lost if the lock is held for the full 10 s. Policy decisions, proof requirements and fail-closed behavior are unchanged, except that an enforced review now asks the owner (in the modes above) instead of denying. Update, reload the host and review hook trust before relying on the new hook.

### v3.9.96

v3.9.96 fixes native pre-action hooks that denied protected actions after the runtime gate allowed them. The hook sent `source_meta` fields that Think rejects, and without a risk level the runtime answered protected actions on its low-risk fast path, whose receipt cannot back an action permit. Protected actions now request a durable gate and create their decision with accepted metadata only; unprotected actions stop at the gate without creating a decision or permit. A rejected control call now names its HTTP status and failure code without echoing service text. Policy decisions, proof requirements and fail-closed behavior are unchanged. Update, reload the host and review hook trust before relying on the new hook.

### v3.9.95

v3.9.95 fixes supplied model usage lost when native session hooks consumed stdin. It also captures the latest proven Codex model-call delta from bound token-usage events or a bounded transcript using the supported Codex `0.157.1` schema. Unknown versions, model/turn identity, unsafe paths, counter resets and unproven child bindings abstain. Billing dimensions remain unknown unless explicitly supplied. Capture is not proof of complete coverage, a comparable baseline, overhead or savings. Update and reload the owning host before claiming active capture.

### v3.9.94

v3.9.94 preserves compact model-cost evidence through native capture, direct usage submission and Commit. It captures OpenAI Chat/Responses cache subsets and Anthropic cache reads/writes with their actual token semantics and stable provider response identity. Published 3.9.93 strips these fields, so this correction requires updating MCP and reloading the host. It does not change authentication, plans, or claim baseline savings.

### v3.9.93

v3.9.93 fixes the full eleven-tool canary's Auto operation identifiers. The canary now uses Auto's canonical UUID namespace, so valid numeric UUIDs reach Think and Commit instead of failing locally before a request. Privacy validation, authentication, proof requirements, deadlines, and retries are unchanged. Published 3.9.92 cannot provide this harness correction; update and reload the host before verifying activation. SDK 3.7.63 is unchanged.

### v3.9.92

v3.9.92 keeps response-body consumption and cancellation inside the existing MCP request deadline, including Orient, First Value, buyer proof, and other JSON control calls. Malformed secondary-call responses fail explicitly. The full eleven-tool canary retains bounded backend error categories and elapsed operation timings, and closes any outcome-eligible fixture decisions before reporting success. These are client reliability corrections that the published 3.9.91 bytes cannot provide; they do not establish the cause of older unavailable receipts. Reload the host after updating and verify the installed version before claiming activation.

### v3.9.91

v3.9.91 keeps the unreachable-control allow, and stops treating every control failure as an outage. A rejected key, a permission denial, a malformed response, or any other reached-and-rejected control call still denies a protected action. Only a timeout, a network failure, or an unavailable service warns and allows. The pre-action wait is 8 seconds so the deployed auth grace can finish before the hook gives up. The published `3.9.90` package cannot deliver this distinction. SDK `3.7.63` is unchanged.

### v3.9.90

v3.9.90 is a reliability fix for every supported native hook. When Marrow or the MCP control path is unreachable, the hook warns, allows the action, and leaves the record in the local spool so it is sent after Marrow accepts traffic again. A real block or review decision still stops the action. A missing local key, an unsafe local control file, and malformed input still stop it. The published `3.9.89` package cannot deliver this behavior. SDK `3.7.63` is unchanged. Installer `0.1.58` still pins MCP `3.9.89` until the installer release that follows this publish.

### v3.9.89

v3.9.89 adds a default-enabled, private local session loop guard for every supported native-hook installation, independent of Marrow plan or fleet entitlement. It hashes bounded operation inputs and results into owner-only state under `~/.marrow`, stops unchanged successful verification repeats, stops the third unchanged poll or failed attempt, resets after meaningful mutation or a new owner prompt, and clears the session at close. Routine read-only results remain local, so ordinary checks add no Marrow API or database writes; one compact client-reported block marker is emitted only when a configured hook actually denies a repeat. Official Marrow tools remain excluded. `MARROW_AUTO_HOOK=false` and the existing owner local-control disable remain the explicit opt-outs.

The pre-action path now reuses a valid runtime-created decision and calls Think only when the runtime completion contract explicitly requires decision creation. Setup reports the loop guard as configured without claiming live enforcement before host restart, trust review, and an observed hook invocation. `marrow-mcp loop-guard-self-test` verifies the local behavior against isolated temporary state without touching the user's ledger. SDK `3.7.62` and installer `0.1.57` are unchanged.

### v3.9.88

v3.9.88 makes the lifecycle spool self-healing so users never need a manual `drain-spool` for ordinary failures. Dead letters are now classified: authentication rejections (401/403) stay `attention_required` with credential-restore guidance and are never auto-retried; conflicts (409) are marked `server_owned` because the server already holds durable evidence for that event id, and are never replayed; every other dead letter (transport, schema, or legacy rows without a status) is `recoverable` and retried automatically by the passive nudge — at most 5 events per nudge, 3 recovery attempts each, with a 15-minute cooldown between attempts, inside the existing bounded nudge budget. Recovery bookkeeping stays local and never changes the server request. `spool-status` gains `recoverable`, `server_owned`, and `recovery_exhausted` counts, and `failed` now counts only auth-class dead letters that genuinely need the operator. Explicit `drain-spool` keeps full authority: it still retries every operator-fixable dead letter including the auth class, clears recovery exhaustion for a fresh budget, and skips server-owned events. SDK `3.7.62` and installer `0.1.56` are unchanged.

### v3.9.85

v3.9.85 keeps the existing Marrow Auto request and response deadlines active through response-body consumption and JSON parsing, so a server that sends headers and then stalls ends with the same typed bounded timeout as a stalled header response. The retry owner, four-second write-attempt ceiling, and eight-second Auto response budget are unchanged.

Auto responses now include a capped, privacy-safe HTTP attempt trace with route phase, duration, status or typed error category, pending and replay state, exact numeric response auth/parse spans when exposed, and requested and measured wait. Timing coverage is explicitly partial or unavailable because detailed backend DB and Durable Object stages are not returned in these responses. The control-path canary preserves each outer Auto attempt and its inner HTTP trace on success and failure, so a slow first attempt is no longer overwritten by a later fast continuation. The trace contains no request bodies, credentials, action text, or identifiers. SDK `3.7.62` and installer `0.1.56` are unchanged; install MCP `3.9.85`, reload the host, review hook trust, and verify before claiming the updated client is active.

### v3.9.84

v3.9.84 adds bounded direct-think recovery without inventing a decision ID, and an exact scoped pending receipt for manual continuation. Saved unverified observations remain terminal untrusted evidence. It also preserves confirmation of pending automatic writes by replaying the same authenticated operation and request, with one retry owner and a four-second attempt ceiling inside the unchanged eight-second total budget. Numeric and date-based server retry delays are preserved. Conflicting receipts never confirm closure, and unavailable or unverified results remain pending.

Post-action commit lookup now preserves the original general/empty-surface defaults and optional explicit target. It remains observation-only. Receipt expiry retains unverified observation evidence unless an existing historically authorized checkpoint supports exact recovery; it does not extend the old receipt or grant retrospective permission. Transient lifecycle delivery retries preserve the queued event and its stable identity across restart within bounded scheduling and attempt limits. Queued, server-accepted, and committed remain separate facts.

Before upgrading, finish existing pending auto operations with their current verified client. Older auto requests omitted supplied surfaces from think; correcting nonempty surfaces can therefore expose an idempotency conflict for that old operation. Do not reinterpret the conflict, open a replacement operation, use a silent legacy fallback, or automatically downgrade. Omitted/empty surface operations preserve their original canonical scope. This is a scope-correctness change, not a promise that every pending old-client operation can resume across an upgrade.

Default primary guidance uses runtime followed by commit and exposes exactly 17 tools. Auto remains available in explicitly selected core/full profiles. SDK `3.7.62` and installer `0.1.56` are unchanged; install MCP `3.9.84`, reload the host, review hook trust, and verify before claiming the updated client is active.

### v3.9.82

v3.9.82 batches client reliability fixes for `marrow_auto`. Continuations honor the server's finite retry delay within the existing eight-second core budget; when the delay cannot fit, the same operation remains pending with retry guidance. Gated auto reuses the server-created decision after checking its canonical scope, and ordinary owner approval can resume that decision when the backend explicitly declares the supported proof contract. The installed bytes of v3.9.81 cannot provide these client changes; update MCP for this behavior. SDK and installer versions are unchanged.

Auto now durably queues its lifecycle receipt before responding and starts the existing bounded background delivery afterward. A queued receipt is not server acceptance, while `live_delivery.committed` separately reports confirmed governed closure. New numeric response timings distinguish core work, durable enqueue, and response construction. The canary preserves these measurements and distinguishes pending completion, owner approval, and missing proof from malformed responses or transport failures; an uncommitted canary still fails. These changes do not promise fixed latency or eliminate outages.

### v3.9.81

v3.9.81 adds bounded structured failure evidence to the authenticated eleven-tool control-path canary. Failed runs identify the observed stage, tool, error class, timing, and completed checks without retaining credentials, customer payloads, or arbitrary error text. Protocol and write failures observed after the final response or during shutdown now fail closed; the canary's own bounded cleanup remains compatible with a successful run. The eleven live-tool requirements, client deadlines, package identity checks, and retry limits are unchanged.

### v3.9.80

v3.9.80 is a reliability patch for direct `marrow_think` and `marrow_commit` calls. Each invocation now carries one stable bounded idempotency key. Only the backend's documented pending-persistence states are reconciled, using the byte-identical request and key after a fixed one-second delay for at most three reconciliation rounds. The existing transport layer permits up to two attempts per round, for up to six HTTP requests with the same key and body. A 202 response is never reported as successful completion; unknown, malformed, correlation-drifted, or exhausted pending responses fail closed with a structured error. Explicit caller-supplied idempotency keys remain unchanged, and durable `observed_unverified` outcomes retain their terminal, non-authorizing semantics.

### v3.9.79

v3.9.79 aligns `marrow_replay_compare` with the production replay contract. Its public MCP schema now exposes two exclusive modes: fetch an existing comparison with `comparison_id`, or create one with `source_decision_id`, `baseline.decision_id`, and `candidate.decision_id`. Empty, incomplete, mixed-mode, blank-ID, unsafe-ID, same-decision, and undeclared content-bearing fields fail locally before any request, while comparison fetches and valid distinct-decision comparisons keep their existing behavior. Outbound baseline and candidate references contain only validated decision IDs and optional privacy-safe identifier labels. Replay comparison still uses only already-recorded durable evidence and never runs a model or replays customer content. This release requires SDK `^3.7.62`, keeping the active MCP dependency floor aligned with the current SDK release.

### v3.9.78

v3.9.78 separates durable post-action observation from action authorization. For outcome closure only, `marrow_commit` sends the existing `decision_id` to runtime and can use the backend's exact `outcome_observation_only` response to submit the already-completed result without forwarding its non-durable correlation ID as receipt evidence. That response never permits an action: it has `allow: false`, `durable: false`, and no authorization. The accepted result remains `committed: false`, `outcome_state: "observed_unverified"`, `authorization_granted: false`, and `trusted_learning_applied: false`; it is terminal delivery and is not retried from the local queue. Trusted promotion requires an explicit new commit attempt with the backend-required authorization and proof for the exact observed payload. Missing, malformed, conflicting, or cross-scope runtime truth still fails closed, and privacy-unsafe `instruction_ref` values such as dates and long numeric IDs now fail locally before any network call.

### v3.9.77

v3.9.77 makes `primary` the ordinary MCP profile when `MARROW_TOOL_PROFILE` is unset. The default surface now matches the 17 documented Primary MCP Tools, while explicit `core` preserves the seven-tool control loop and explicit `full` preserves the complete catalog. Invalid values fail with an exact bounded repair instead of broadening visibility. Status responses report the effective profile, visible names/count, and fresh backend-projected entitlement states when provided; local visibility and cached evidence never authorize access. The exact-version 11-tool control-path canary remains pinned to `full`.

### v3.9.76

v3.9.76 fixes owner-approved `marrow_auto` closeout by binding an arbitrated operation to the exact server-created arbitration decision, rejecting decision mismatches before commit, and returning an honest terminal action for non-arbitrated `review_required` gates. Chat and proof text cannot substitute for a dashboard-issued approval receipt, and only a backend `committed: true` response closes the operation.

### v3.9.75

v3.9.75 adds explicit Codex, Cursor/Composer, Cline, Windsurf, and Gemini CLI native hook entrypoints. Gemini BeforeTool returns strict fixed allow/deny JSON, AfterTool returns neutral JSON after compact outcome capture, and AfterAgent closes one turn without reading prompt/response content or requesting a retry. Project hook trust and enablement remain user-controlled, and configuration stays client-self-reported rather than certified coverage.

### v3.9.74

v3.9.74 keeps one automatic operation bound to its original runtime authorization and decision across timeout and proof-required retries, then closes that exact decision once verified proof is supplied. One outer `marrow_auto` invocation normally completes think and commit in-band within its bounded eight-second client budget. The release canary allows that complete client budget plus bounded response overhead rather than cutting the operation off at five seconds.

### v3.9.72

v3.9.72 requires SDK `3.7.61` so MCP installations cannot resolve to an SDK that recursively intercepts its own Marrow control-plane traffic. The MCP tool contract is unchanged; this release aligns the tested package chain.

### v3.9.71

v3.9.71 makes the advertised Grok control loop true:

- default tools include `marrow_think` so the official loop can create a `decision_id` without `MARROW_TOOL_PROFILE=full`;
- process identity prefers `MARROW_KEY_<ROLE>` when it matches `MARROW_AGENT_ID`, so a leaked fleet env cannot 403 every status call;
- Grok native hooks are installed under `~/.grok/hooks/marrow.json` and hook parsers accept Grok camelCase envelopes;
- Grok native PreToolUse, PostToolUse/PostToolUseFailure, and nonblocking Stop hooks provide bounded client-reported gating, result evidence, and one turn closeout. The governed wrapper remains an explicit bounded fallback;
- idle spool nudge drains up to 40 current-namespace events so the queue does not sit as a nag;
- if `risk_gate.enforced` is false, the gate is advisory — do not describe it as a live block;
- `marrow_commit.decision_id` comes from `marrow_think`, `marrow_auto`, or an arbitration runtime that actually created a decision. A normal runtime may create or reuse a decision: follow runtime.decision_id and completion_contract. Keep runtime.runtime_authorization.id separate as gate_receipt_id.

### v3.9.69

v3.9.69 keeps the always-on spool from growing into a nag queue:

- status, runtime, and ask quarantine leftover credential-namespace files instead of replaying them;
- pending current-namespace events are nudged in the background so 8 queued receipts are not a healthy idle state;
- explicit `drain-spool` still retries failed current-namespace events.

### v3.9.68

v3.9.68 stops Ask from fighting a real lesson:

- `marrow_ask` does not concatenate "Historical guidance is warming" onto a lesson;
- `decisions_matched` follows the server count, not a similar-failure sum that can be 0;
- `low_history` is false when hive memory or a lesson is already present.

### v3.9.67

v3.9.67 gives writes room to finish:

- `marrow_commit` uses an 8s transport ceiling instead of aborting on the 4s read cliff;
- the MCP tool deadline for commit matches that write ceiling.

### v3.9.66

v3.9.66 keeps the slim runtime honest for live sessions:

- slim `marrow_agent_runtime` echoes the requested action instead of an empty string;
- `marrow_ask` returns a real lesson/`top_outcomes` line when hive memory exists;
- local `client_update` no longer reports `latest_version: null` when the adapter version is known;
- tool payloads only ask for a spool drain when the current namespace has pending or failed events.

### v3.9.65

v3.9.65 makes the first hour useful and closes the session honestly:

- prompt context prints first-hour copy: the gate is live, empty savings are healthy, and the next deploy, merge, or publish goes through Marrow;
- Stop hooks and `marrow_session_end` auto-commit open work;
- session usage is recorded only when the host emits counts.

### v3.9.64

v3.9.64 prints the live habit loop and records observed model usage without inventing savings:

- `marrow_status` and other control tools include `habit_loop_copy` from `marrow.habit-loop.v1`;
- PostToolUse hooks send compact token counts only when the tool result actually includes usage;
- empty savings stay honest until those observed counts land.

### v3.9.63

v3.9.63 closes identified-workflow reuse on the MCP control path:

- `marrow_commit` sends `identified_workflow_id` from auto-gate runtime when Marrow already identified the path;
- hook context tells the agent not to rediscover a matched workflow and only mentions token savings when evidence exists;
- the live API still attributes reuse from the gate receipt if a client omits the id.

### v3.9.62

v3.9.62 integrates four model-neutral reliability and capability contracts:

- standalone `marrow_status` uses the bounded compact API contract and can return a fresh, owner-only last-known status projection without treating it as a live gate or authorization;
- ordinary runtime responses expose typed `runtime_authorization` backed by the authoritative gate receipt and omit `decision_id` unless the server actually created a decision;
- `spool-status` and `drain-spool` report the active credential namespace separately from isolated legacy debt, and a clear active namespace exits successfully without replaying, merging, editing, or deleting old-key files;
- initialize, prompt, setup, and tool responses qualify coverage by `host_capability`: MCP tools are on demand, while client-self-reported hook activity remains visible but never certifies coverage or control.

In v3.9.62, the default surface was seven tools (runtime, think, commit, ask, status, auto, handoff status) and the prompt remained named `marrow-always-on`. Host and model labels are display-only and never change auth, tenant, plan, policy, proof, schema, or API behavior. Grok hook activity is client-self-reported and does not certify observed coverage; the governed wrapper remains an explicit bounded fallback.

### v3.9.61

v3.9.61 keeps an authoritative proof-pack rejection distinct from a control-path outage:

- backend `MARROW_PROOF_PACK_INCOMPLETE` responses are reported as `validation` / `proof_required`, not infrastructure failures;
- the exact missing proof fields and backend repair instruction remain visible to the agent;
- live proof validation does not return a stale outage brief or unavailable authorization state;
- proof enforcement remains fail-closed, and successful commit behavior is unchanged.

### v3.9.60

v3.9.60 restores the complete control-and-proof loop for ordinary MCP clients:

- cached guidance no longer cuts live status, ask, runtime, or handoff reads down to an impossible 500 ms deadline;
- `marrow_auto` normally waits for the bounded think-and-commit path and reports the live decision and proof result in-band; if the client deadline is reached, the returned operation ID continues that same decision;
- `marrow_commit` now shares the same abort and deadline contract as the other control calls;
- transient retries use a one-second delay so a slow edge path is not immediately hit again;
- spool status surfaces backlogs under older credential namespaces without replaying them across an unverified tenant boundary;
- a plan-gated handoff is reported as unavailable for the current plan, not as an API or authentication outage;
- the release canary runs with the customer's default client deadlines instead of silently overriding them.

The current package gives MCP-only hosts the same model-neutral control instructions and seven-tool default surface, but MCP transport alone remains on demand. A host or model label never changes that coverage contract. Public lifecycle callbacks and hook activity are client-self-reported and cannot verify or certify passive coverage; independent authority is required. Codex, Grok, and Gemini can use configured native hooks after restart and host hook review; the governed wrapper remains an explicit bounded fallback.

### v3.9.59

v3.9.59 makes the six-tool control path reliable and honest across ordinary edge and geographic latency:

- the default health deadline is 2.5 seconds instead of an unrealistically narrow 400 ms;
- `MARROW_PING_TIMEOUT_MS` can tune the probe between 500 ms and 5 seconds;
- authenticated control reads tolerate cold network/TLS paths while cached reads still return quickly;
- status, ask, runtime, and handoff responses report measured current/p50/p99 latency plus owner-only queue health;
- a first-session outage returns a clearly labeled local safety brief, and infrastructure failures are never mislabeled as policy denials;
- timeout errors return a concrete retry delay instead of an unresolved placeholder;
- Cloudflare edge denials are separated from key-scope or Marrow policy rejections;
- MCP initialization carries the capability-qualified control/proof instructions even when a client does not request the optional prompt template;
- update, launch, setup, spool, and ping commands use the unambiguous `npx --package ... marrow-mcp` form;
- explicit spool drains tolerate slow edge delivery without extending passive hook latency.

### v3.9.58

v3.9.58 makes latency evidence accurate by reusing one initialized MCP process for the complete control-path canary:

- startup, initialization, and tool discovery are measured separately from authenticated tool calls;
- hot-path steering and report latency are reported as separate p50, p95, p99, and maximum groups;
- response IDs, malformed output, RPC failures, timeouts, and incomplete tool contracts fail closed;
- one bounded process prevents package and process startup time from being mistaken for API latency.

The compact agent control path introduced in v3.9.57 remains the default:

- `marrow_status`, `marrow_ask`, and `marrow_agent_runtime` use authenticated routes with bounded retries and typed failures;
- transient read failures return an owner-only last-known brief when available, while cached guidance can never authorize high-risk work;
- normal tool errors return structured `ok`, `error_code`, `exact_fix`, `stale_brief`, and `client_update` data instead of raw MCP `fetch failed` errors;
- the v3.9.58 default agent surface was seven tools: runtime, think, commit, ask, status, auto, and handoff status; `MARROW_TOOL_PROFILE=full` selected legacy or advanced integrations;
- risky `marrow_auto` calls obtain a fresh runtime gate automatically and cannot self-close as successful without required proof;
- `marrow_run` requires an explicit outcome and never invents proof or a successful result;
- the package includes an exact-version control-path canary covering every route reported in the production incident.

### v3.9.56

v3.9.56 adds tenant-scoped coordination and evidence-only replay to the existing MCP governance surface:

- each normal user prompt performs one compact `/v1/agent/context` read; risky or mutating prompts perform one `/v1/agent/runtime` call instead;
- prompt lifecycle receipts are accepted into the owner-only local spool immediately and delivered asynchronously by later lifecycle activity;
- the prompt read deadline is 400 ms, injected guidance is limited to 3–8 concise lines, and raw prompts are not stored in the guidance cache;
- transient failures can use an owner-only, account/key/agent-scoped last-known brief for at most one hour, clearly labeled with its age;
- 401 and 403 responses never use cached guidance, and cached runtime guidance cannot authorize high-risk work;
- `marrow_ask` now maps to the canonical decision brief contract instead of a separate route;
- `npx -y --package=@getmarrow/mcp@latest marrow-mcp ping` reports current latency, rolling measured p50/p99, last success, and lifecycle backlog health;
- `marrow_coordinate` acquires/releases tenant-scoped resource leases and carries compact child proof packets without sharing transcripts;
- `marrow_replay_compare` compares already-recorded baseline and candidate outcomes with durable proof and never executes either model;
- both new tools preserve agent-bound key scope, reject unsafe path identifiers, and return unavailable or incomplete evidence rather than manufacturing a winner.

The package remains backward compatible with supported server aliases while advertising only implemented tools.

This release is paired with SDK `3.7.56` and installer `0.1.41`. The deterministic release order is SDK first, MCP second, installer third, and the API release last.

### v3.9.54

v3.9.54 makes Marrow's intervention visible through the existing decision-trace workflow:

- `marrow_decision_trace` returns an owner-readable receipt for an evidence-backed block, warning, or review;
- passive setup tells agents to relay one factual receipt after a meaningful intervention and remain quiet for routine low-risk work;
- the receipt reports required workflow, proof, permit follow-through, and recorded outcome without raw context, proof values, credentials, or cross-tenant data.

It preserves the bounded MCP lifecycle recovery introduced in v3.9.53.

### v3.9.53

v3.9.53 adds exact lifecycle backlog visibility and bounded recovery for MCP-routed agent activity:

- compact, redacted receipts remain in an owner-only spool through transient failures;
- `spool-status` reports exact pending, failed, capacity, and oldest-receipt evidence;
- `drain-spool` retries queued receipts without manufacturing a new lifecycle event;
- a successful current receipt performs one bounded best-effort retry of older queued work;
- terminal rejections and exhausted retries remain explicit dead letters for operator action.

It preserves the signed action-permit and update controls introduced in v3.9.52.

### v3.9.52

v3.9.52 combines operator-controlled client update notices with signed, action-bound permit verification in the cooperative Claude Code hook path. That permit flow does not authenticate hook provenance or certify always-on coverage. Official MCP requests identify the installed package version, and passive context renders a request-specific server advisory with exact update and verification commands:

- update availability or unrecognized version metadata appears during normal authenticated runtime/status activity;
- messaging clearly states that hosted Marrow services are already current and that no local change was applied;
- agents are instructed to tell the operator and respect local change policy instead of silently changing packages or configuration;
- unknown versions do not imply a vulnerability, while server-designated security requirements remain distinct;
- existing MCP tools and older server responses remain compatible when no advisory is returned.

The Claude Code `PreToolUse` hook cooperatively verifies the permit before returning control to that harness. It obtains the runtime gate, records the exact governed decision, requests a permit bound to that gate, decision, target, and canonical action surfaces, and consumes it before returning. The callback itself remains client-self-reported and is not a certified external choke point:

- protected deploy, publish, merge, migration, credential, and production actions fail closed on timeout or permit failure;
- the permit is bound to the authenticated account, key, agent, session, action, target, canonical action surfaces, decision, and runtime gate;
- raw tool input and permit tokens are never written into hook output or lifecycle telemetry;
- matching result and closure hooks preserve one correlation so every exact server-required proof field can close the consumed permit automatically;
- the bounded hook timeout prevents a control-plane wait from hanging the agent indefinitely;
- low-risk work retains passive/advisory behavior unless account policy requires stronger enforcement.

It preserves native-hook activity diagnostics introduced in v3.9.50, with the current trust boundary applied:

- agents and owners can distinguish “MCP configured” from client-reported pre-action, result, and session activity without treating either as certification;
- `PreToolUse` requests the Marrow runtime gate before matched actions and maps `block` to deny and `review_required` to operator review;
- matching `PreToolUse` and result hooks share Claude Code's tool-use correlation while the session shares one workflow identity;
- generic integration events and public hook entrypoints cannot claim certified native-hook coverage;
- retries preserve correlation and explicitly `client_self_reported` activity in the owner-only durable spool;
- configuration drift can be diagnosed without sending configuration contents;
- missing outcome closure remains visible rather than treating tool or session exit as business success;
- existing MCP tools and lifecycle inputs remain compatible.

It preserves `marrow_arbitrate` from v3.9.49, the session-orientation hardening introduced in v3.9.48, and the always-on lifecycle introduced in v3.9.44:

- `server.json` and `mcpName` identify the stdio server, required secret, source repository, and package version for registry consumers;
- GitHub, npm, and MCP registry surfaces use separate signed discovery placements;
- package language consistently describes agent governance, runtime control, proof, and fleet intelligence;
- bounded positive and negative recommendation criteria stop agents from forcing Marrow into irrelevant workflows;
- current evidence, integration paths, and published references are linked from one review-dated contract;
- `UserPromptSubmit` obtains relevant task guidance without storing raw prompt text;
- `PreToolUse` checks matched tool actions before execution without sending raw tool input;
- `PostToolUse` and `PostToolUseFailure` record compact result receipts;
- `Stop` keeps unfinished outcomes visible instead of silently treating a session exit as success;
- transient lifecycle delivery failures use an owner-only, bounded local spool with stable event IDs;
- `marrow_decision_trace` explains the tenant-scoped path from prior failure and lesson through gate, proof, workflow, and outcome, and returns an owner-readable intervention receipt.

Existing MCP tools and stable context API names remain compatible. Authentication, policy, proof, and validation failures are surfaced rather than retried as network failures.

Client hook activity alone never produces certified coverage percentages. An installed config or API-key-authenticated callback is shown as client-self-reported activity; certification requires an independent authority not supplied by the public MCP hook entrypoints.
