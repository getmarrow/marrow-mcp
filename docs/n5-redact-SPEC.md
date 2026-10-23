# SPEC: sec-n5-hotfix (MCP, base b8973d3a, branch fix/n5-redact-20261023)

Status: PHASE 1 (spec before code). Build/test only. Nothing is pushed or published. No backend change in this job.
Dummy secrets are generated at runtime in-process and are never printed or written. Rows record yes/no and counts.

## 0. What the code says (read on b8973d3a; changes the SEC1 picture in one place)

1. `exact_hmac` is ALREADY a per-install keyed MAC. `normalized-action.ts:1550` computes HMAC-SHA256(device salt, `marrow-exact-action-v1`, kind, tool name, material), 128 bits. The device salt is `deviceSalt()` in `src/seatbelt/record.ts:683`: `~/.marrow/seatbelt/salt` under the PASSWD home (`os.userInfo().homedir`), 32 random bytes, mode 0600, dir 0700, owner-checked, O_NOFOLLOW, created once by temp file + `link()` (never overwrites), null on any failure (then `exact_hmac` is a random nonce). SEC1 F6 ("identical across HOME") is a black-box misread: it changed the `HOME` variable, which does not move the passwd home. Checked here with the real module: same passwd home -> same value (also across two `HOME` values); other passwd home -> other value (scratch/probe2.cjs). So F1/F5 for `exact_hmac` is NOT an offline-guess surface. SPEC consequence: reuse this key store (section 2), do not invent a second one.
2. What IS unkeyed: `command_sha256` (shell) and `input_sha256` (mcp/edit/other) = plain `sha256(HASH_VERSION \n domain \n text)` (`normalized-action.ts:1358,1637`). The text can hold a value the redactor did not recognise, so a short secret can be brute-forced offline. Identical across installs (probe2: same `command_sha256` under two passwd homes).
3. `programs[]` gets the lower-cased basename of a stage's program word when it matches `^[a-z0-9][a-z0-9._+-]{0,63}$` and is not key-shaped (`normalized-action.ts:1145`). For `"S" | smbpasswd -s` the program word is the secret (F2/F4).
4. MCP's own decision does not read the normalized action: `classified.risk/protected` come from the command text (`hook-pre-action.ts`), `normalizedHookAction` output is attached to the gate request (`:1520-1539`), to hold records and to the correlation (`hook-contract.ts:826-837`). So changes to `programs[]` and hash fields cannot move an MCP decision, risk level or number of gate requests; the backend's reading of them is the consumer risk (section 3).
5. `src/normalized-action.ts` may touch `seatbelt/` only through the one lazy `require` of the device salt inside a try (`test/seatbelt-vendor.test.js:73` counts exactly 2 occurrences). So the known-program list must be a LOCAL constant (no import of `seatbelt/tables`), kept in step with the tables by a parity test.

## 1. Fail-closed spec (a): first word of a pipeline stage that feeds a password program

Definitions: a stage K "feeds a secret sink" iff it is joined by `|` or `|&` to a later stage that `takesSecrets`, directly or through more piped stages (existing `sinkAfter[k]`). `p` = the stage's program word as today (after assignments and wrappers, basename, lower-cased). `lone` = the stage has exactly one word (`segment.words.length === 1`; a redirection, an argument or a wrapper makes it not lone).

Rule R1 (replaces the unconditional push at `normalized-action.ts:1145`). For a stage that feeds a secret sink, `p` is added to `programs[]` only if BOTH hold:
- K1: `p` is a known program name (local set `KNOWN_FEEDER_PROGRAMS`: the seatbelt `KNOWN_COMMANDS` and `INERT_PROGRAMS` tables plus the SEC1 prototype's feeder names: gopass, lpass, bw, pwgen, cmd, get-content, write-output, write-host, read-host, convertto-securestring, get-secret);
- K2: the stage is not lone, OR (it is lone AND `p` is one of `cat`, `yes`, `pbpaste` AND the source word is exactly `p`: no path, no other case).

Otherwise: `programs[]` gets the fixed marker `unlisted-feeder` (once, deduplicated) in place of `p`, and the action is marked `truncated` (never bound, `exact_hmac` present). Stages that do not feed a secret sink are unchanged (same programs[] as base).

Why this is sounder than the prototype's 50-name list: the known set is the compiled-in vocabulary the seatbelt already uses, so every program the seatbelt and classifier treat as dangerous (git, npm, pnpm, wrangler, rm, docker, terraform, curl, ssh, ...) keeps its name in `programs[]` and keeps today's binding behaviour; only words that are NOT known programs are withheld. A literal password is a lone word (one token, quotes removed by the tokenizer), so K2 keeps lone known words out unless they are the three real stdin producers. Residual (stated, not hidden): a secret that is, exactly, `cat`/`yes`/`pbpaste`, or a known program name followed by arguments, is sent as that name. Such a value is a dictionary word that no hash can protect; the text hash is keyed (section 2), so it cannot be confirmed from the wire.

Fail-closed properties (each has a test):
1. No word that is first in a feeder stage appears in `programs[]` unless K1 and K2 hold. Never in clear, never case-folded: `"Cat" | smbpasswd` (lone, not exactly `cat`) is withheld; `CAT x | smbpasswd` keeps `cat` (it has an argument, so it is a program with arguments, the same name base sends).
2. A withheld word always sets `truncated` (so it never binds). A kept word changes nothing vs base (decision, risk, truncated, programs).
3. The marker is constant (`unlisted-feeder`), not derived from the word. No length, case, prefix or hash of the word is in `programs[]`.
4. Distinct feeders never merge: the word stays in the hashed `text` (keyed, section 2) and `exact_hmac`. `rm -rf x | smbpasswd` vs `cat x | smbpasswd` differ by program name (both known, kept) AND by text. `foo1 x | smbpasswd` vs `foo2 x | smbpasswd` share `programs[]` but differ in `command_sha256` and `exact_hmac`.
5. Applies at every depth the normalizer already walks (`bash -c`, `pwsh -c`, `cmd /c`, `ssh host`, `su -c`, `eval`) because it sits in `normalizeInner`; all hosts and labels share the code (Bash, PowerShell.command/.script, Monitor, Agent via the same path, Codex Bash, Cursor).
6. No change to what is classified: `classified.*`, seatbelt (keyless) and the local gate count are untouched; the classifier twin and `vendor/classifier` are not edited.

## 2. Fail-closed spec (b): per-install keyed hash for UNBINDABLE actions

Scope. An action is unbindable when `truncated === true` (this includes a withheld feeder word, a replaced secret, a cut input, a name over 128 chars). For such an action:
- shell: `tool_input.command_sha256` = HMAC (below) over the same preimage as today (`HASH_VERSION \n domain \n text`, quoting signature still excluded for truncated);
- mcp, edit, other (the Agent tool, Edit `new_string`, WebFetch, Skill...): `tool_input.input_sha256` = HMAC over the same preimage as today (`HASH_VERSION \n input \n text`). Same code path (`inputHash`), so F3 and the Edit case are covered for their truncated forms.
- `exact_hmac` is already keyed; its domain moves `v1 -> v2` (the version tag), format unchanged (32 hex, the backend nulls anything else).
Output format is unchanged: 64 lowercase hex (the backend's binding test reads 64-hex; an unbindable action never binds anyway). No new wire field (the backend keeps `tool_input` as sent and hashes it into keys; a new field is an unverified backend input).

Key. One key store: the device salt (`~/.marrow/seatbelt/salt`, passwd home, 32 random bytes, 0600 in 0700, owner-checked, `O_NOFOLLOW`, size 32). Decision on the path: reuse, do not add a second store. Reason: it already implements every case this brief lists (atomic first create, symlink, mode, owner, size, read-only home) and has tests; a second store would copy the code and its failure modes. The key used for text hashes is a derived sub-key, so a text MAC can never equal an `exact_hmac` or a receipt MAC even for equal input: `K_text = HMAC-SHA256(salt, "marrow-text-hmac-key-v2")`; `command_sha256`/`input_sha256` = `HMAC-SHA256(K_text, "marrow-text-hmac-v2\n" + kind + "\n" + JSON(tool name) + "\n" + preimage)` as 64 hex (full digest). Tool name and kind are in the input, so a Bash and a Monitor with equal text differ (as today through `domain`). The key never leaves the process: not sent, not logged, not in state.json, not in error text (the existing one-line note, printed once per process, names no path and no value).

Key states (each is a test):
| state | result |
|---|---|
| file missing | created (temp file, O_EXCL, 0600, then `link()`; never overwrites; `EEXIST` -> read the winner) |
| concurrent first start (N processes) | one key; every process reads the same 32 bytes; no process sees a half-written key (link is atomic) |
| unreadable (EACCES), wrong mode (group/other bits), symlink, not our uid, size != 32 (corrupt), dir unsafe | `deviceSalt()` is null: `command_sha256`/`input_sha256` = random 64-hex nonce, `exact_hmac` = random nonce (as today); the action stays HELD, matches nothing, asks again. NEVER the plain sha256, never a fixed value |
| read-only HOME (cannot create) | same as above (fail closed) |
| no `getuid` (Windows) | same as above; nothing new: `exact_hmac` is already a nonce there |
| rotation (owner deletes the salt file) | next use creates a new key; every keyed value changes; old holds do not match (asked again). Nothing else keeps the old key |
| key version | `v2` is inside the MAC input; a future change to `v3` makes every `v2` value unequal. Old plain hashes (v1 era) cannot equal a MAC |

Bindable actions (`truncated !== true`): UNCHANGED. Their `command_sha256`/`input_sha256`/`correlation` stay the plain sha256 over text the normalizer believes holds no secret, because the backend binds on the equality of those hashes (and across the fleet: `fleet_action_key`), a deploy's `command` is judged word for word, and a per-install key would make every learned approval stop matching and split approvals between machines. Where the normalizer's redactor fails to see a secret (SEC1 N1 `sudo -u root smbpasswd -a u1 S`, N5 `cmd /c "time { echo S; } | smbpasswd ..."`, an Agent/Edit input with a secret the redactor does not recognise) the bindable hash still depends on the secret. That is NOT removable without losing binding, so it is listed in the table and in FOLLOW-UPS, and it is NOT claimed fixed. (The right fix is to make the redactor see those values, which makes the action unbindable and so keyed; that is a redaction-coverage change and belongs to its own audited item.)

Not changed: `exactHookTarget` (`hold.target`) and `runOptionsKey` (an unkeyed hash of timeout/run-in-background JSON, never a secret by name; kept inside the preimage so a keyed text hash still covers it).

### Migration (existing holds and approvals)
- Existing holds in `~/.marrow/host-approvals/state.json` match by `correlation` = sha256 over `[session, tool, identity{kind, programs, paths, input}]`, where `input` carries `command_sha256` and `exact_hmac`. For an unbindable action both change (key + domain `v2`) and, for a withheld feeder, `programs[]` changes: the new correlation never equals an old one. An old hold is therefore never claimed by a new action; the retry makes a fresh gate request and a fresh hold (it is asked again). Old holds expire as today (TTL). Tested: create a hold with the base build, retry with the branch build, expect a new gate request and a different correlation, and the old hold not resumed.
- Bindable actions keep identical hashes: their old holds and the backend's stored approvals/learned approvals continue to match exactly as today (no regression, nothing looser).
- Stored backend approval keys are untouched. A learned/task approval bound on an old key of an UNBINDABLE action did not exist (the backend never binds a truncated action); for the one case where base was bindable and the branch is now unbindable (a feeder the base sent as a program name that is now withheld, e.g. `unknownprog | smbpasswd -s`), the learned approval simply stops matching and the user is asked again. That is stricter (more asks), never looser; the owner decides if any such approval needs re-teaching.
- No state.json schema change (`STATE_VERSION` stays 1). `state.secret` (a different, in-file random value used only for hold ids/codes) is not used and not touched.

## 3. Round-1 consumers of this change's output (security inputs) and how each is tested

Backend repo is not in the inputs. Rows marked [SEC1] are "read from SEC1 AUDIT, not re-verified"; any backend change goes to FOLLOW-UPS. MCP-side rows are tested here with real dummy-key runs of `dist/cli.js`.

| # | consumer (file:line) | what it takes from us | abuse cases tested in round 1 | how | status |
|---|---|---|---|---|---|
| C1 | backend agent-runtime.service.ts:3617-3635 [SEC1] | `normalized_action_hash = sha256(canonicalJson(sanitized))`; `fleet_action_key` only when bindable | (i) two actions differing only after a redacted span get different bodies; (ii) a withheld feeder never yields the same body as another program; (iii) an unbindable action's body no longer carries a guessable value; (iv) bindable body identical to base | wire capture through the repo mock, base vs branch, byte compare of `normalized_action` | MCP side tested; backend behaviour [SEC1] |
| C2 | backend owner-approval-events.service.ts:209-238 [SEC1] | `gateActionKeys`: unkeyed sha256 of {v:3, agent, action, type, target, surfaces, normalized} | an unkeyed key over our normalized_action: after the change the preimage has no clear/guessable secret for unbindable actions (offline-guess test: recompute the base formula on the wire value, expect no match on branch); keys of actions that differ outside a secret stay different | recompute sha256(preimage) with the attacker's formula on both builds | tested on wire value; key function [SEC1] |
| C3 | backend runtime-shadow.service.ts:116-135 [SEC1] | keeps `programs/commands/argv/paths/hosts` and `tool_input` as sent; only a malformed `exact_hmac` becomes null | the marker `unlisted-feeder` is a valid program string (matches `^[a-z0-9][a-z0-9._+-]{0,63}$`, length 15, not key-shaped); new command_sha256 is 64 hex; exact_hmac stays 32 hex; no new field | shape asserts on every wire body | tested here |
| C4 | backend automatic-approval.service.ts:188-260 (normalizedActionIdentifies) and learned/task approvals on fleet_action_key [SEC1] | binds only if not truncated, nothing cut/redacted, full commands/argv or 64-hex command_sha256/input_sha256 | (i) a withheld-feeder action is `truncated: true` so it can never bind; (ii) a forged client field (`tool_input` risk labels, `truncated:false` sent by an agent in tool_input) cannot make an unbindable action bindable: `truncated` is set by the normalizer, never read from input; (iii) an old learned approval on a bindable base action: unchanged hashes keep matching; (iv) the one base-bindable -> branch-unbindable case (unknown feeder) stops matching (stricter) | tests on `truncated` for all forms; forged-field rows | tested MCP side; binding [SEC1] |
| C5 | backend host-owner-approval.service.ts review_request_hash [SEC1] | hashes the normalized action | the hash input changes only for unbindable actions; no secret in it | wire capture of `/host-approval` body base vs branch | tested wire; hash [SEC1] |
| C6 | MCP host-approvals `state.json` (holds, `correlation`, `normalized_action`, `exact_hmac` as hold key), `hook-contract.ts actionIdentity/stableToolCorrelation` | same fields as the wire | clear/case-folded/dependent counts in state.json; migration (old hold vs new action); `unmatched` branch for a malformed exact | scan state.json after each run; base-then-branch hold test | tested here |
| C7 | MCP session loop guard, hook stdout/stderr, spool/lifecycle, receipts (`seatbelt/record.ts actionKey` hashes the normalized action with the device salt and keeps `programs` mapped through the known list) | derived from the same action | scan for secret slices (clear, case-folded, 8-char window); receipts store only known-list names or `other` | scan HOME + TMPDIR + passwd-home scratch after each run | tested here |
| C8 | marrow-install 0.1.74 FINAL (080a82dc) | vendors the MCP by version + source SHA + tarball integrity; `vendor/classifier` is generated by the installer and mirrored by `src/seatbelt/classifier-pin.ts`; installer fixture `test/fixtures/mcp-3.9.105` | `vendor/classifier` and `classifier-pin.ts` are NOT edited -> `test/seatbelt-vendor.test.js` must still pass (run and report). A new MCP version/sha/integrity changes the installer pin | run seatbelt-vendor test; installer not in inputs | installer re-vendor = FOLLOW-UP (a re-pin and re-publish of the installer against the new MCP; not run here) |
| C9 | plugins (Claude/Cursor/Codex launchers pin the MCP by version/sha); `src/codex-plugin-pins.ts` (SHA-256 of OFFICIAL Codex plugin FILES) | MCP build identity | `codex-plugin-pins.ts` is not edited; the pins cover plugin files not normalizer output, so no plugin file hash moves. New MCP version -> plugin launcher re-pin | run `codex-plugin-pins` tests in the suite | plugin re-pin = FOLLOW-UP |
| C10 | backend classifier twin `decision-v2/classifier-v1.ts`, `classifier-redact.ts` [SEC1] | twin of `vendor/classifier`, not of normalized-action.ts | not touched (no vendor edit). The backend v2 analysis reads `programs[]`: it will see `unlisted-feeder` for a withheld word. NOT VERIFIED what it does with it | FOLLOW-UP (backend): treat the marker as an unknown program for classification (never "inert"), confirm it does not lower risk. MCP still sends `risk_level` from its own classifier (equal to base on every row) | follow-up |

## 4. Abuse cases (all must be run; results go in the RESULT table)

Hosts/labels x forms. Labels: Bash, PowerShell.command, PowerShell.script, Monitor, Agent (prompt), Task, Codex Bash (codex-pre-action-hook), Cursor beforeShellExecution, Cursor preToolUse Shell. Forms: PF first word dq / sq / bare / `$()`-feeder / after `&&` / after `|`-chain / `|&` / htpasswd -i, PF-echo (control), N5 (cmd /c, pwsh -c), N1 (sudo positional), N2 (exec fd, here-string, pwsh here-string), WebFetch/Write/Skill controls.
- forged client fields: `tool_input` carrying `risk_level: low`, `read_only`, `approved`, `truncated: false`, `tool_kind`, `exact_hmac`, `command_sha256`, `programs` (hostile values: a forged `exact_hmac` must not make an action match; sent fields are ignored/overwritten by the normalizer); event-level `tool_kind`/`risk_level`.
- chaining: `&&`, `;`, `||`, `|`, `|&`, subshell `( )`, `bash -c`, `pwsh -c`, `cmd /c`, `ssh h`, `su -c`, `eval`, `sudo`, `env`, `time`, `nohup`.
- ambiguity: lone word vs word + args; padded names (`PowerShell `, `Monitor\n`), upper/lower case feeder names, path-prefixed feeder (`/bin/cat`, `./pw`), word that is the marker itself, a first word that equals `smbpasswd`, 40-char hex / alnum / base64url shapes, 8/16/40 lengths, unicode and CR.
- cross-tenant / cross-install: same action under two passwd homes (key) must give different `command_sha256` and `exact_hmac` for unbindable actions; same under two API keys / agent ids / HOME values must give equal values (the key is per install, not per tenant: documented) and the key is never in the body.
- production mislabelled: prod deploy with `description: staging`, cwd `/srv/production`, `--env staging --env production` (last wins), `E=production; --env $E`, `echo staging && wrangler deploy --env production`, `staging/../production`, unknown flag `--frobnicate`.
- dangerous feeders (must keep risk, deny/hold and keyless seatbelt denial exactly as base): `git push --force | smbpasswd -s`, `npm publish | smbpasswd -s`, `wrangler deploy prod | htpasswd -i`, `cat .env | smbpasswd -s`, `rm -rf x | smbpasswd`, `cat x | smbpasswd`, `unknownprog | smbpasswd -s`, `TERRAFORM apply | smbpasswd`.
- collisions (binding rules): differ outside the secret -> DIFFERENT keys: URL query text after a token, form body after a password, header text after Bearer, env assignment then `--env`, JSON op after a token, `--password=S -e` text, flag after the secret, other program name, other flags, chained commands; differ only in the secret value -> MAY match; `rm -rf x | smbpasswd` != `cat x | smbpasswd`; `foo1 x | smbpasswd` != `foo2 x | smbpasswd`; PowerShell command vs script with the same text (F8: equal on base, by design, unchanged); Bash vs Monitor/PowerShell with the same text differ.
- keyed-hash failure states (section 2 table), migration (old hold vs new), hostile state (symlinked salt, group-readable salt, short salt, salt dir 0777), and concurrent first start.
- secrets never in key/logs: scan every body leaf, URL, header value, state.json, hook stdout/stderr, TMPDIR/HOME files for the clear value, a case-folded form, an 8-char window, base64/hex encodings.
- looser-than-base check: for EVERY row the decision, risk_level, sent/not-sent and number of gate requests on the branch must equal base or be stricter; any looser row fails the job.

## 5. How reach is measured (so "target 0" is checkable)

For each form x label, with a twin pair (same class/length, no 6-char window shared) and a repeat of the first (A2): `clear` = full value present; `folded` = case-folded or 8-char slice present; `dependent` = field equal A vs A2 but different A vs B (noise excluded); `offline-guessable` = dependent AND the attacker formula (unkeyed sha256 of the known preimage with the right candidate) reproduces the wire value, OR the value is identical under two passwd homes (unkeyed). Target on the branch: clear 0, folded 0, offline-guessable 0 for every UNBINDABLE action (wire and state.json). Bindable rows (N1, N5, plain Agent prompt) are expected to stay dependent and unkeyed; they are marked BINDABLE and listed in FOLLOW-UPS.

## 6. Expected deltas vs b8973d3a (the yardstick)

- programs[]: only for a feeder stage whose first word fails K1/K2 (marker + truncated). Everything else byte-identical.
- unbindable actions: `command_sha256`/`input_sha256`/`exact_hmac` values change (keyed/v2); format identical; everything else identical.
- bindable actions: byte-identical wire bodies.
- decisions, risk levels, number of gate requests, keyless seatbelt answers: identical on every row.
- stricter only: more actions are `truncated` (asked each time); no action becomes bindable that was not.

## 7. FOLLOW-UPS (do not do in this job)

Backend: (1) treat `programs[]` marker `unlisted-feeder` as unknown (never lowers risk; verify decision-v2 behaviour); (2) hash the stored key with a server key instead of unkeyed sha256 (`gateActionKeys`) so a stored key cannot be brute-forced if a body reaches the DB with a short secret in a bindable hash; (3) redact `programs[]` server-side (`sanitizeNormalizedAction` keeps it as sent, :116-119) as defense in depth. MCP/next: (4) make the redactor see the SEC1 N1 (`sudo -u root` wrapper parse takes `root` as the program) and N5 (`time { ...; } | ...` group) values so those actions become unbindable and keyed; (5) PowerShell `Write-Output S | smbpasswd` style printers (if the probe shows they leave S in a bindable text); (6) bindable Agent/Edit input hash secret-dependence (needs a binding-preserving design); (7) a keyed per-install `correlation` for bindable holds (local only). Release chain: installer re-vendor + re-pin against the new MCP version/sha/integrity; plugins re-pin; CHANGELOG/website docs line; version number (this branch does not bump `package.json`).

## 8. Test plan (Phase 2/3)

Unit: `test/n5-redact-keyed.test.js` (feeder rule R1 table, keyed hash states, nonce on failure, domain separation, collisions, forged fields, known-list parity with seatbelt tables, shape asserts). Real-hook wire: scratch harness (not shipped) runs `dist/cli.js` per host event with the repo mock, base and branch, all SEC1 rows (inputs/abuse.tsv, abuse-feeder-Pa-vs-D.tsv) plus the extra rows above; table with columns case | label | base | branch | expected | verdict. Full suites twice (npm ci --ignore-scripts and build under `env -i` with an empty HOME, node --test concurrency 4). `seatbelt-vendor` parity test result reported.

## 9. Amendments made during the build (after the Phase 1 commit; nothing else in this spec changed)

1. K1 compares the program STEM: `programStem` (removes `.sh .bash .py .js .mjs .ts .rb .pl .ps1 .exe`) plus `.cmd .bat .com`, so `git.exe`, `npm.cmd`, `WRANGLER.EXE` keep their names like `git`, `npm`, `wrangler` (found by the adversarial pass: without it a Windows spelling of a dangerous feeder lost its name). K2 (lone word) still needs the exact lower-case name, no extension, no path.
2. Nested shells: only `bash/sh/zsh -c`, `eval`, `ssh host CMD` and `su -c` are re-parsed by the normalizer. `pwsh -c '...'` and `cmd /c "..."` keep their quoted text as ONE word, so a feeder inside them is not seen: those actions (SEC1 N5) stay bindable with a plain hash that depends on the value. The test file pins this as a KNOWN GAP (follow-up item 4 in section 7); it is not claimed fixed.
3. The first-word rule runs inside `normalizeInner`, so a withheld word inside `bash -c '...'` sets `truncated` (programs[] of nested text is not listed, as on base).

## 10. BUILD 2 AMENDMENT: full scope (every hooked tool, unknown tool names, Codex, Cursor). Written and committed BEFORE any build-2 code.

Base for this amendment: build 1 tip 4e6b5c2 (on b8973d3a). Sections 0-9 stay in force unless this section says otherwise. Dummy secrets are made at run time and never printed; rows record yes/no and counts.

### 10.0 What build 1 left (re-measured on 4e6b5c2 with the real normalizer, dummy secrets of three shapes)

- All 11 G-1 tools and the unknown-name tool are BINDABLE on 4e6b5c2 with a PLAIN `input_sha256` or `command_sha256` that depends on the secret (WebFetch, Workflow, KillShell, SendMessage, CronCreate, PushNotification, ExitPlanMode, SlashCommand: `input_sha256`; RemoteTrigger, BashOutput, ToolSearch, FooTool: `command_sha256`). Also NotebookEdit, Skill, TodoWrite, TaskOutput, Agent and Edit carry a plain input hash of text that may hold a secret.
- ToolSearch (`query`) and any unknown tool with a `command` field (FooTool) put the clear or case-folded first word of the field into `programs[]`. So do Read/Glob/Grep/LS (path basename), WebSearch (query), Task (description) on every build including base: the normalizer reads the text of ANY tool that is not file-editing or a local task tool as a shell command (`isShellGovernedTool`: "not a file-edit tool and not a local task tool"), so the first word of a free-text field is listed as a "program".
- The holds `correlation` (state.json) and the lifecycle `correlation_id` (sent to the backend in POST /v1/agent/integrations/events) are `sha256` over [session, tool, identity{kind, programs, paths, input}] where `input` is the tool_input above, so they inherit every one of those dependences.
- `exactHookTarget` (hold.target in state.json, never sent) is an unkeyed sha256 over the tool name, the nested `serverName/server_name/toolName/tool_name` input fields and the run options as sent.

### 10.1 Scope: one shared path, no per-tool list

Every host event reaches the wire, state.json, the correlation and the seatbelt receipt key through `normalizedHookAction` (hook-pre-action.ts Claude/Codex/Cursor, hook.ts PostToolUse, host-approval.ts PostToolBatch, hook-contract.ts `actionIdentity`, seatbelt/record.ts `actionKey`). The three rules below sit in that path (and in `exactHookTarget`), so a tool added later is covered without a list, and an unknown tool name is covered because nothing keys on the name.

### 10.2 Rule U: EVERY text hash is the per-install keyed MAC (replaces section 2's "bindable actions keep the plain hash")

For every action that carries `tool_input.command_sha256` or `tool_input.input_sha256` (shell, mcp, edit, other; truncated or not; every tool name) the value is `HMAC-SHA256(K_text, "marrow-text-hmac-v2\n" + kind + "\n" + JSON(tool name) + "\n" + preimage)` as 64 hex, with the same K_text, the same preimage, the same output format as build 1. No new wire field.

Exception E1 (the only one): when the action carries the clear deploy `command` text (`deployText !== null && deployText === text`, the grammar-bound deploy form the service judges word for word) the hash stays the plain hash over text that is itself sent in clear, so it exposes nothing new and every learned/deploy approval keeps matching as on b8973d3a. E1 additionally requires that the run options of a Monitor/PowerShell call (part of the preimage) are numbers or booleans; any other type (a string, an object) takes the keyed form.

Decision on plain bindable hashes of non-command inputs (the build 1 known gap M1): they are KEYED, bindable still. Reasons: (1) a free-text field (prompt, message, plan, query, filter, shell_id, script, url, new_string, content) cannot be proven secret-free: the redactor knows names and shapes, not intent; (2) a keyed hash keeps binding where binding is safe: the key is stable on one install, so the same call on the same install resumes the same hold and matches the same learned approval; (3) cost, stated plainly: an approval learned on one machine no longer matches on another (the backend key now differs per install), an approval learned BEFORE this change never matches again (the user is asked once more), and a machine with no usable device key asks every time (below). Each of these is MORE asks, never fewer, so none is looser than b8973d3a. This is the owner-visible behaviour change of the hotfix; the CHANGELOG says so.

Key states (extends the section 2 table; nothing is weakened):
| state | result for a bindable action (new) | result for a truncated action (as build 1) |
|---|---|---|
| key present and safe | keyed 64 hex, stable | keyed 64 hex + exact_hmac |
| key missing | created once (O_EXCL temp file + link), then keyed | same |
| unreadable, wrong mode, symlink, other uid, wrong size, unsafe dir, read-only home, no `getuid` | random 64-hex nonce per call: the action matches no hold and no approval and is asked again. NEVER the plain hash, never a fixed value | nonce (as build 1) |
| rotation (file deleted) | every keyed value changes; every old hold and learned approval stops matching (asked again) | same |
Consequence to state in RESULT: on a machine whose device key cannot be made or read, no hash-bound step resumes (approval retry, post-tool link) until the owner fixes the key store; actions are still gated by the same decision, they are only never resumed from a hold. The one stderr line per process (no path, no value) names this; its text is updated from "a held action that hides a value" to every held action.

### 10.3 Rule P (programs[] for tools that are not shell tools)

A shell tool is a tool whose text IS a shell command: after `normalizeHookToolName`, one of `bash, run_terminal_command, shell, execute_command, run_shell_command` (Bash, Codex exec/exec_command, Cursor Shell, Gemini/Cline/Cursor terminal tools) or `monitor`, `powershell`. For every other tool whose text is read as shell text (the 11 G-1 tools that are shell-kind, ToolSearch, BashOutput, RemoteTrigger, WebSearch, Read, Glob, Grep, LS, Task, and any unknown tool name with a `command`, `cmd`, `query`, `path`, `url`, `name` or `description` field), the program word of EVERY stage must be a known program stem (the section 1 set `KNOWN_FEEDER_PROGRAMS`, Windows spellings by stem, exact as build 1) to be listed. Any other word that base would have listed is replaced by the constant `unlisted-program` (deduplicated; derived from nothing about the word; matches `^[a-z0-9][a-z0-9._+-]{0,63}$`; not key-shaped). The action is NOT marked truncated: the text hash is keyed (rule U), so binding is safe and unchanged in kind.
- A known word (`git`, `npm`, `wrangler`, `rm`, ...) keeps its name, so `FooTool {command: "git push --force"}` lists `git` exactly as base: classification inputs for dangerous programs are unchanged.
- Genuine shell tools: unchanged from build 1 (rule R1 for feeder stages only). Not widened to every unknown word of a Bash command: that would change programs[] for ordinary commands, a classification input the backend reads (follow-up item to decide with the backend).
- Different unknown words never merge: the keyed hash of the full text separates them.
- Residual (stated): a secret that equals a known program name is sent as that name (a dictionary word; no hash protects it).

### 10.4 Rule T: `exactHookTarget` is keyed

`hold.target` becomes `HMAC-SHA256(K_text, "marrow-hook-target-v2\n" + JSON(parts))` over the same parts as today (tool name, adapter flag, nested server/tool fields, MCP context, run-options key). No usable key: the existing "unmatched" nonce (the hold is never claimed). The run-options key itself stays an internal plain hash that only ever sits inside a keyed preimage.

### 10.5 Collision rules (binding; each has a test and table rows)

- Same preimage, so any action pair that differed outside a secret on b8973d3a still differs (the MAC is injective over distinct preimages up to 2^-256). Tool name and kind are inside the MAC: the same text under ToolSearch.query vs FooTool.command, Bash vs Monitor, Agent vs Task, WebFetch vs Workflow differ.
- Actions that differ only in a secret the redactor replaces still share keys (as base); actions that differ in a free-text secret the redactor does not see now differ by a keyed value (as they differed by a plain value on base).
- `rm -rf x | smbpasswd` vs `cat x | smbpasswd` still differ (R1 names, text hash). `unlisted-program` withheld words differ by text hash.
- Forged client fields: `tool_input` fields named `command_sha256`, `input_sha256`, `exact_hmac`, `programs`, `truncated`, `risk_level`, `tool_kind` sent BY the tool are data inside the hashed text, never read as normalizer output.
- A secret never appears in a key, a log, state.json, stdout/stderr, or the key store path in an error.

### 10.6 Migration (state and test it; fail closed)

| stored thing | old value | new action | result |
|---|---|---|---|
| hold in host-approvals state.json (written by b8973d3a or 4e6b5c2) | correlation over plain `command_sha256`/`input_sha256`, target plain, exact_hmac `v1` or `v2` | keyed hashes, keyed target | different correlation, different target: never claimed; the retry makes a new gate request and a new hold (asked again). Old holds expire by TTL. `STATE_VERSION` unchanged |
| backend learned/task approval on `fleet_action_key` or stored `normalized_action_hash` made from an old plain hash | plain hash | keyed hash | never matches again (asked again): stricter. The old stored key is a secret-dependent unkeyed value that stays in the backend: follow-up to purge |
| deploy approval (E1) | plain hash + clear `command` | same | unchanged, still matches |
| seatbelt receipts (local, `actionKey`) | key over the normalized action with plain hashes | key over keyed hashes | old receipts never match new keys (local audit trail only) |

### 10.7 Round-1 consumers added to section 3

| # | consumer | what changes | test |
|---|---|---|---|
| C11 | lifecycle events POST /v1/agent/integrations/events (`correlation_id`) and the spool on disk | correlation inherits keyed hashes | capture every request body of each hook run; count clear / folded / dependent; scan the spool |
| C12 | PostToolUse / PostToolBatch settle (host-approval POST body `normalized_action`) | same function | host-approval body scan, hold-resume flow |
| C13 | seatbelt `actionKey` (local receipts) | keyed hashes inside the key material | receipts scan; seatbelt tests |
| C14 | session loop guard (state.json, in-file HMAC secret), hook stdout/stderr | not changed; scanned | scan for clear, folded, 8-char windows |
| C15 | backend `agent-runtime.service.ts:3617-3635`, `owner-approval-events.service.ts:209-238`, `runtime-shadow.service.ts:116-135` [read from SEC1 AUDIT, not re-verified] | all keep `tool_input` and `programs[]` as sent; `normalized_action_hash`/`gateActionKeys` now hash keyed values (unguessable), `programs[]` may be `unlisted-program` | wire shape asserts (64-hex, 32-hex exact_hmac, programs regex); backend behaviour on the marker is a FOLLOW-UP, never verified here |
| C16 | marrow-install 0.1.74 / plugins / Codex plugin pins | `vendor/classifier`, `classifier-pin.ts`, `codex-plugin-pins.ts` not edited | `seatbelt-vendor` and pins tests in the suite; installer re-vendor + plugin re-pin follow-ups |

### 10.8 Abuse cases added to section 4 (all run base vs branch through the real hooks, plus the in-process normalizer for the shapes)

Rows for each of WebFetch (prompt), Workflow (script), KillShell (shell_id), SendMessage (message), CronCreate (prompt), PushNotification (message), ExitPlanMode (plan), SlashCommand (command), RemoteTrigger (prompt), BashOutput (filter), ToolSearch (query), FooTool (command); controls NotebookEdit (new_source), Skill (args), TodoWrite (content), TaskOutput (task_id); Agent (prompt), Task, Edit (new_string), Write (content), WebSearch (query), Read/Glob/Grep (path); build 1's known-gap cases N1 (`sudo -u root smbpasswd -a u1 S`), N5 (`cmd /c`, `pwsh -c`); each with a free-text secret of shapes hex16, lower24, alnum20 in the named field. Plus: tool name lookalikes (`Tool `, `toolsearch`, `TOOLSEARCH`, `mcp__x__y`), forged fields inside `tool_input`, chained commands inside a FooTool command (`git push --force | S`, `a && S`), dangerous program inside an unknown tool (`FooTool {command: "git push --force"}` keeps `git`), deploy text (E1 plain), run options as string, no-key / unsafe-key / read-only home (nonce, stderr note), two installs (differ), and all of the 83 SEC1 rows and build 1's rows again.

### 10.9 Expected deltas vs b8973d3a (the yardstick for the LOOSER line)

- `command_sha256` / `input_sha256` values change for every action except E1 deploys; format identical (64 hex). `hold.target` and `correlation` values change.
- `programs[]` changes only for (a) build 1's withheld feeder words and (b) words of non-shell tools that are not known program stems (new constant).
- No decision, risk level, gate-request count, seatbelt (keyless) answer or proof field changes. Never fewer holds. Any row where the branch is less strict than base is a LOOSER finding.

### 10.10 Follow-ups added (not done here)

Backend: treat `unlisted-feeder` and `unlisted-program` as unknown programs (never lowering risk); purge or expire stored keys derived from old plain hashes; hash stored keys with a server key; redact `programs[]` server-side. MCP/next: make the redactor see SEC1 N1/N5 (they are cut by keying, not by redaction); a key store for hosts with a read-only home or Windows (today those ask every time); decide with the backend whether Bash programs[] should withhold every unknown word; `Grep` pattern and `Glob` pattern are not part of the hashed text (only `path`), a pre-existing collision, equal to base. Release chain: installer re-vendor/re-pin, plugin re-pin, CHANGELOG/website line (no version bump here).
