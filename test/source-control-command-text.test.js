'use strict';

// The text of a plain push or pull request, sent for the source-control quiet of the learned pattern engine (C-M1..C-M5).
// Every row of the abuse and collision tables is a test here. Dummy secrets are made at run time and never printed.
const assert = require('node:assert/strict');
const test = require('node:test');
const { createHash, randomBytes } = require('node:crypto');
const { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } = require('node:fs');
const { spawnSync } = require('node:child_process');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const { normalizedHookAction, sourceControlCommandText } = require('../dist/normalized-action.js');
const { classifyTool } = require('../dist/hook-pre-action.js');
const { shellMac } = require('./support/keyed-text-hash.cjs');
const { dummySecret } = require('./support/dummy-secret.cjs');
const { writeOfficialHostConfigs } = require('./support/official-host-config.cjs');
const { projectCwd } = require('./support/hermetic-project.cjs');

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const MOCK = join(__dirname, 'support', 'host-approval-fetch-mock.cjs');
const SRC = join(__dirname, '..', 'src');
const REVIEW_CLASS = 'classified Bash action: review on github';

const P = (text) => createHash('sha256').update(`marrow-normalized-action-v3\nshell\n${text}`).digest('hex');
const salt = randomBytes(32);
const salt2 = randomBytes(32);
const bash = (command, extra = {}) => ({ tool_name: 'Bash', tool_input: { command, ...extra } });

function withEnv(value, fn) {
  const previous = process.env.MARROW_HOOK_COMMAND_TEXT;
  if (value === undefined) delete process.env.MARROW_HOOK_COMMAND_TEXT;
  else process.env.MARROW_HOOK_COMMAND_TEXT = value;
  try { return fn(); } finally {
    if (previous === undefined) delete process.env.MARROW_HOOK_COMMAND_TEXT;
    else process.env.MARROW_HOOK_COMMAND_TEXT = previous;
  }
}
const norm = (event, options = {}) => withEnv(undefined, () => normalizedHookAction(event, { deadlineAt: Number.POSITIVE_INFINITY, salt, ...options }));
const sent = (event, options = {}) => norm(event, { sendCommandText: true, ...options });
// The 3.9.111 answer: the opt-out gives it byte for byte (C-M4 golden compares it with the 3.9.111 code).
const legacy = (event, options = {}) => withEnv('off', () => normalizedHookAction(event, { deadlineAt: Number.POSITIVE_INFINITY, salt, sendCommandText: true, ...options }));

/** Hash only, exactly as 3.9.111: no text, with or without sendCommandText, and the same bytes as the opt-out. */
function assertHashOnly(event, label) {
  // A cut input keys a random nonce (it matches nothing): that one field is compared as present, not by value.
  const nonce = (action) => (event.input_truncated === true && action.tool_input.exact_hmac
    ? { ...action, tool_input: { ...action.tool_input, exact_hmac: 'nonce' } } : action);
  const withText = sent(event);
  assert.equal(withText.tool_input.command, undefined, `${label}: no text`);
  assert.deepEqual(nonce(withText), nonce(legacy(event)), `${label}: 3.9.111 bytes`);
  assert.deepEqual(nonce(norm(event)), nonce(legacy(event)), `${label}: default caller unchanged`);
}
/** Text sent: the normalized text, with the plain hash of it at every call site. */
function assertTextSent(event, text, label) {
  const action = sent(event);
  assert.equal(action.tool_input.command, text, `${label}: text`);
  assert.equal(action.tool_input.command_sha256, P(text), `${label}: plain hash`);
  assert.deepEqual(Object.keys(action.tool_input).sort(), ['command', 'command_sha256'], label);
  assert.equal(action.truncated, undefined, label);
  const quiet = norm(event);
  assert.deepEqual(quiet.tool_input, { command_sha256: P(text) }, `${label}: default caller gets the plain hash, no text`);
}

// ------------------------------------------------------------------ in scope

test('text sent: a plain git push and gh pr create the hook treats as a review on GitHub (normalized text, plain hash)', () => {
  assertTextSent(bash('git push origin feat/x'), 'git push origin feat/x', 'push');
  assertTextSent(bash('git push -u origin feat/x'), 'git push -u origin feat/x', 'push -u');
  assertTextSent(bash('gh pr create --base feat/a --head feat/b --title "Fix the thing"'), "gh pr create --base feat/a --head feat/b --title 'Fix the thing'", 'pr');
  // The class the one sending caller checks (S2).
  assert.equal(classifyTool(bash('git push origin feat/x')).action, REVIEW_CLASS);
});

// ------------------------------------------------------------------ CM1: one test per S-condition

test('CM1 S1: only the host Bash tool, byte-equal, with one string command', () => {
  const text = 'git push origin feat/x';
  for (const toolName of ['bash', 'BASH', 'Bash ', ' Bash', 'Monitor', 'PowerShell', 'shell', 'run_terminal_cmd', 'mcp__x__Bash']) {
    assertHashOnly({ tool_name: toolName, tool_input: { command: text } }, `tool ${toolName}`);
  }
  assertHashOnly({ tool_name: 'Bash', tool_input: { cmd: text } }, 'cmd key');
  assertHashOnly({ tool_name: 'Bash', tool_input: { command: text, cmd: text } }, 'cmd beside command');
  assertHashOnly({ tool_name: 'Bash', tool_input: { command: ['bash', '-lc', text] } }, 'argv');
  assertHashOnly({ tool_name: 'Bash', tool_input: text }, 'string input');
  assertHashOnly({ ...bash(text), input_truncated: true }, 'input_truncated');
  assert.equal(sourceControlCommandText({ ...bash(text), input_truncated: false }, text, { truncated: false, sigs: [] }, ['git']), null, 'input_truncated present');
  assert.equal(sourceControlCommandText(bash(text), text, { truncated: false, sigs: [] }, ['git']), text, 'the same call without it');
});

test('CM1 S3: every forbidden character, one by one, anywhere in the raw text, sends no text', () => {
  for (const ch of [';', '&', '|', '`', '$', '(', ')', '<', '>', '\\', '{', '}', '[', ']', '*', '?', '~', '!', '#', '=', '^']) {
    assertHashOnly(bash(`git push origin feat${ch}x`), `char ${JSON.stringify(ch)}`);
    assertHashOnly(bash(`gh pr create --base feat/a --title 'a ${ch} b'`), `quoted char ${JSON.stringify(ch)}`);
    assert.equal(sourceControlCommandText(bash(`git push origin a${ch}`), 'git push origin a', { truncated: false, sigs: [] }, ['git']), null, `raw ${JSON.stringify(ch)}`);
  }
  for (const ch of ['\t', '\r', '\n', '\0', '\x7f', '\x1b', ' ', 'é', '‍']) {
    assertHashOnly(bash(`git push origin feat${ch}x`), `byte ${JSON.stringify(ch)}`);
    assert.equal(sourceControlCommandText(bash(`git push origin a${ch}`), 'git push origin a', { truncated: false, sigs: [] }, ['git']), null, `raw byte ${JSON.stringify(ch)}`);
  }
  // The normalized text is checked too.
  assert.equal(sourceControlCommandText(bash('git push origin a'), 'git push origin a;', { truncated: false, sigs: [] }, ['git']), null);
});

test('CM1 S3: length 1 to 1024 bytes (A19 over-length)', () => {
  const at = (n) => `git push origin f${'x'.repeat(n - 'git push origin f'.length)}`;
  assertTextSent(bash(at(1024)), at(1024), '1024 bytes');
  assertHashOnly(bash(at(1025)), '1025 bytes');
  assert.equal(sourceControlCommandText(bash('git push origin a'), at(1025), { truncated: false, sigs: [] }, ['git']), null, 'normalized over 1024');
  assert.equal(sourceControlCommandText(bash(''), '', { truncated: false, sigs: [] }, ['git']), null, 'empty');
});

test('CM1 S4: truncated, quoting signature, secret marker, backslash and programs send no text', () => {
  const ok = { truncated: false, sigs: [] };
  const text = 'git push origin feat/x';
  assert.equal(sourceControlCommandText(bash(text), text, ok, ['git']), text);
  assert.equal(sourceControlCommandText(bash(text), text, { truncated: true, sigs: [] }, ['git']), null, 'truncated');
  assert.equal(sourceControlCommandText(bash(text), text, { truncated: false, sigs: ['0:L*'] }, ['git']), null, 'sigs');
  assert.equal(sourceControlCommandText(bash(text), 'git push origin [secret]', ok, ['git']), null, 'marker');
  for (const programs of [[], ['gh'], ['git', 'git'], ['git', 'rm'], ['hub'], ['Git']]) {
    assert.equal(sourceControlCommandText(bash(text), text, ok, programs), null, `programs ${JSON.stringify(programs)}`);
  }
  assert.equal(sourceControlCommandText(bash('gh pr create --fill'), 'gh pr create --fill', ok, ['gh']), 'gh pr create --fill');
  // An apostrophe in quotes normalizes to '\'' : a backslash in the normalized text.
  assertHashOnly(bash(`gh pr create --base feat/a --title "it's done"`), 'apostrophe');
  // Plain spaces at the ends change nothing (as in 3.9.111): the normalized text is sent; a tab or CR is A27.
  assertTextSent(bash(' git push origin feat/x'), 'git push origin feat/x', 'leading space');
  assertTextSent(bash('git push  origin feat/x '), 'git push origin feat/x', 'inner and trailing space');
});

test('CM1 S5: only the git push and gh pr create heads', () => {
  for (const command of ['git commit -m wip', 'git -C dir push origin a', 'gh api repos/o/r', 'gh pr merge 1', 'git pushx origin a',
    'git push', 'gh pr create', 'gh pr view 1', 'git status', 'echo git push origin a', 'env git push origin a', 'sudo git push origin a',
    'command git push origin a', 'git fetch origin', '/usr/bin/git push origin a', 'gh pr createx --fill']) {
    assertHashOnly(bash(command), command);
  }
});

// ------------------------------------------------------------------ abuse rows (M)

test('A5 chain in every form: S3 rejects, hash only', () => {
  for (const command of ['git push origin a && rm -rf x', 'git push origin a ; rm -rf x', 'git push origin a || rm -rf x', 'git push origin a | tee x',
    'git push origin $(echo a)', 'git push origin `echo a`', '( git push origin a )', 'bash -c "git push origin a"', 'git push origin a\nrm -rf x',
    'git push origin a & rm -rf x', 'git push origin a > out', 'for b in a; do git push origin $b; done', 'timeout 5 git push origin a', 'xargs git push origin < l']) {
    assertHashOnly(bash(command), command);
  }
});

test('A6 a quote hides a clause: S3 rejects the ; inside quotes', () => {
  assertHashOnly(bash('git push origin "feat; rm -rf x"'), 'double quotes');
  assertHashOnly(bash("git push origin 'feat; rm -rf x'"), 'single quotes');
});

test('A8 variables, globs, tilde, braces: S3 rejects', () => {
  for (const command of ['git push origin $BR', 'git push origin ${BR}', 'git push origin feat/*', 'git push origin feat/?', 'git push ~ feat/x', 'git push origin {a,b}', 'git push origin feat/[ab]']) {
    assertHashOnly(bash(command), command);
  }
});

test('A9 misleading title: classified as the same call without the prose (L2), never the review class, so the hook sends no text (S2)', () => {
  const event = bash("gh pr create --base feat/a --title 'deploy to production'");
  const classified = classifyTool(event).action;
  assert.notEqual(classified, REVIEW_CLASS);
  assert.equal(classified, classifyTool(bash("gh pr create --base feat/a --title 'x'")).action);
  // The one sending caller gates on the class (source pin below); the end-to-end run checks the body.
});

test('A16 secret in a URL: [secret] marker, no text, keyed and truncated as 3.9.111', () => {
  const d = dummySecret();
  const event = bash(`git push https://u:${d}@host/o/r feat/x`);
  assertHashOnly(event, 'url password');
  const action = sent(event);
  assert.equal(action.truncated, true);
  assert.equal(JSON.stringify(action).includes(d), false);
});

test('A17 secret in a title or branch: no text', () => {
  const ghToken = `ghp_${randomBytes(18).toString('hex')}`;
  for (const command of [`git push origin feat/${ghToken}`, `gh pr create --base feat/a --title '${ghToken}'`, "gh pr create --base feat/a --title 'token=abc'",
    `gh pr create --base feat/a --title 'fix ${ghToken}'`]) {
    const event = bash(command);
    assertHashOnly(event, 'secret in title or branch');
    assert.equal(JSON.stringify(sent(event)).includes(ghToken), false);
  }
});

test('A19 over-length: raw 1025 bytes and normalized over 1024 send no text', () => {
  assertHashOnly(bash(`git push origin feat/${'x'.repeat(1025 - 20)}`), 'raw 1025');
  // 1024 raw bytes whose normalized form grows past 1024 (double quotes become single quotes around an apostrophe-free word is
  // the same length; a quoted space-free word loses its quotes): checked on the normalized text directly.
  assert.equal(sourceControlCommandText(bash('git push origin a'), `git push origin ${'a'.repeat(1009)}`, { truncated: false, sigs: [] }, ['git']), null);
});

test('A20 non-ASCII and homoglyphs: S3 rejects', () => {
  for (const command of ['gіt push origin feat/x', 'git push origin feat/x', 'git ｐush origin feat/x', 'git push‍ origin feat/x',
    'git push origin ‏feat/x', 'git push origin feаt/x', '﻿git push origin feat/x']) {
    assertHashOnly(bash(command), JSON.stringify(command));
  }
});

test('A26 Monitor, PowerShell, cmd and argv: hash only (S1)', () => {
  const text = 'git push origin feat/x';
  assertHashOnly({ tool_name: 'Monitor', tool_input: { command: text } }, 'Monitor');
  assertHashOnly({ tool_name: 'PowerShell', tool_input: { command: text } }, 'PowerShell');
  assertHashOnly({ tool_name: 'Bash', tool_input: { cmd: text } }, 'cmd');
  assertHashOnly({ tool_name: 'Bash', tool_input: { command: ['bash', '-lc', text] } }, 'argv');
  // Codex and Cursor shell event shapes.
  assertHashOnly({ tool_name: 'shell', tool_input: { command: ['bash', '-lc', text] } }, 'codex');
  assertHashOnly({ tool_name: 'run_terminal_cmd', tool_input: { command: text } }, 'cursor');
});

test('A27 CR and untrimmed text: hash only', () => {
  assertHashOnly(bash('git push origin feat/x\r'), 'trailing CR');
  assertHashOnly(bash('\tgit push origin feat/x'), 'leading tab');
  assertHashOnly(bash('git push origin feat/x\r\n'), 'CRLF');
});

test('A30 / CM3 opt-out: MARROW_HOOK_COMMAND_TEXT=off gives the 3.9.111 keyed hash and no text; any other value keeps the default', () => {
  const text = 'git push origin feat/x';
  const off = legacy(bash(text));
  assert.deepEqual(off, { tool_kind: 'shell', tool_name: 'Bash', programs: ['git'], tool_input: { command_sha256: shellMac(salt, 'Bash', text) } });
  assert.deepEqual(withEnv('off', () => normalizedHookAction(bash(text), { deadlineAt: Number.POSITIVE_INFINITY, salt })), off, 'default caller');
  for (const value of ['OFF', '0', 'false', '', 'off ', 'Off', 'no']) {
    const action = withEnv(value, () => normalizedHookAction(bash(text), { deadlineAt: Number.POSITIVE_INFINITY, salt, sendCommandText: true }));
    assert.equal(action.tool_input.command, text, `value ${JSON.stringify(value)} keeps the default`);
  }
});

test('CM5 the header names the one exception in the section 8 words', () => {
  const header = readFileSync(join(SRC, 'normalized-action.ts'), 'utf8').split('*/')[0];
  assert.match(header, /For one kind of command the text is also sent \(sourceControlCommandText\): a plain `git push` or\s+\* `gh pr create` that the hook already treats as a review on GitHub/);
  assert.match(header, /no chaining, pipes, variables or substitutions, and no credential found in\s+\* it/);
  assert.match(header, /learned pattern\s+\* engine/);
  assert.match(header, /`MARROW_HOOK_COMMAND_TEXT=off` keeps every command hash-only/);
});

test('CM2 source pin: only the hook runtime call passes sendCommandText, gated on the review-on-GitHub class; the hold gets no text', () => {
  const pre = readFileSync(join(SRC, 'hook-pre-action.ts'), 'utf8');
  assert.match(pre, /const sendCommandText = classified\.action === 'classified Bash action: review on github';/);
  assert.equal((pre.match(/sendCommandText/g) || []).length, 3, 'declared, passed once, used once for the hold copy');
  assert.match(pre, /normalized_action: runtimeAction,/);
  for (const file of ['hook-contract.ts', 'host-approval.ts', 'hook.ts', 'lifecycle-spool.ts', 'runtime-contract.ts', 'host-approval-state.ts']) {
    const text = existsSync(join(SRC, file)) ? readFileSync(join(SRC, file), 'utf8') : '';
    assert.equal(text.includes('sendCommandText'), false, `${file} keeps the default`);
  }
});

// ------------------------------------------------------------------ collision table C1-C10

test('COLL C1: the text never enters the hash: with and without the text field, the same command_sha256', () => {
  const event = bash('git push origin feat/x');
  assert.equal(sent(event).tool_input.command_sha256, norm(event).tool_input.command_sha256);
  const stripped = (({ command, ...rest }) => rest)(sent(event).tool_input);
  assert.deepEqual(stripped, norm(event).tool_input);
});

test('COLL C2: 3.9.111 keyed hash vs the plain hash: different', () => {
  const event = bash('git push origin feat/x');
  assert.notEqual(legacy(event).tool_input.command_sha256, sent(event).tool_input.command_sha256);
});

test('COLL C3: two installs (different device keys): keyed hashes differ in 3.9.111, plain hashes are equal', () => {
  const event = bash('git push origin feat/x');
  assert.notEqual(legacy(event, { salt }).tool_input.command_sha256, legacy(event, { salt: salt2 }).tool_input.command_sha256);
  assert.equal(sent(event, { salt }).tool_input.command_sha256, sent(event, { salt: salt2 }).tool_input.command_sha256);
});

test('COLL C4: two commands that differ after a redacted span stay different, with no text', () => {
  const d = dummySecret();
  const a = sent(bash(`git push https://u:${d}@h/o/r a`));
  const b = sent(bash(`git push https://u:${d}@h/o/r b`));
  assert.equal(a.tool_input.command, undefined);
  assert.notEqual(a.tool_input.command_sha256, b.tool_input.command_sha256);
  assert.notEqual(a.tool_input.exact_hmac, b.tool_input.exact_hmac);
  assert.deepEqual(a, legacy(bash(`git push https://u:${d}@h/o/r a`)));
});

test('COLL C5: same command, different secret value: truncated, never bound, unchanged from 3.9.111', () => {
  const a = sent(bash(`git push https://u:${dummySecret()}@h/o/r feat/x`));
  const b = sent(bash(`git push https://u:${dummySecret()}@h/o/r feat/x`));
  assert.equal(a.truncated, true);
  assert.equal(b.truncated, true);
  assert.equal(a.tool_input.command, undefined);
  assert.equal(a.tool_input.command_sha256, b.tool_input.command_sha256, 'may match (truncated, never bound)');
});

test('COLL C6 and C7: quoting style gives equal hashes; a changed space inside quotes gives different ones', () => {
  const single = sent(bash("gh pr create --base feat/a --title 'a b'"));
  const double = sent(bash('gh pr create --base feat/a --title "a b"'));
  const twoSpaces = sent(bash("gh pr create --base feat/a --title 'a  b'"));
  assert.equal(single.tool_input.command_sha256, double.tool_input.command_sha256);
  assert.equal(single.tool_input.command, double.tool_input.command);
  assert.notEqual(single.tool_input.command_sha256, twoSpaces.tool_input.command_sha256);
  assert.equal(legacy(bash("gh pr create --base feat/a --title 'a b'")).tool_input.command_sha256, legacy(bash('gh pr create --base feat/a --title "a b"')).tool_input.command_sha256);
});

test('COLL C8: opt-out install vs default install: different hashes', () => {
  const event = bash('git push origin feat/x');
  assert.notEqual(legacy(event).tool_input.command_sha256, norm(event).tool_input.command_sha256);
});

test('COLL C9: Bash vs Monitor: different hashes, Monitor sends no text and stays keyed', () => {
  const text = 'git push origin feat/x';
  const monitor = sent({ tool_name: 'Monitor', tool_input: { command: text } });
  assert.equal(monitor.tool_input.command, undefined);
  assert.notEqual(monitor.tool_input.command_sha256, sent(bash(text)).tool_input.command_sha256);
  assert.notEqual(monitor.tool_input.command_sha256, P(text));
});

test('COLL C10: no secret in any key: every dummy position gives no text and the dummy is in no action', () => {
  for (const command of dummyPositions(dummySecret()).commands) {
    const action = sent(bash(command.text));
    assert.equal(action.tool_input.command, undefined, command.position);
    assert.equal(JSON.stringify(action).includes(command.secret), false, command.position);
  }
});

function dummyPositions(d) {
  const token = `ghp_${randomBytes(18).toString('hex')}`;
  const commands = [
    { position: 'remote URL', secret: d, text: `git push https://u:${d}@host/o/r feat/x` },
    { position: 'branch', secret: token, text: `git push origin feat/${token}` },
    { position: 'title', secret: token, text: `gh pr create --base feat/a --title '${token}'` },
    { position: 'body', secret: token, text: `gh pr create --base feat/a --title 'x' --body 'key ${token}'` },
    { position: 'env prefix', secret: d, text: `GITHUB_TOKEN=${d} git push origin feat/x` },
  ];
  return { commands };
}

// ------------------------------------------------------------------ end to end: the built hook in a child process

function harness() {
  const dir = mkdtempSync(join(tmpdir(), 'marrow-cmdtext-'));
  const home = join(dir, 'home');
  const mockDir = join(dir, 'mock');
  mkdirSync(home, { mode: 0o700 });
  writeOfficialHostConfigs(home);
  mkdirSync(mockDir);
  const apiKey = `mrw_test_${randomBytes(16).toString('hex')}`;
  writeFileSync(join(mockDir, 'config.json'), JSON.stringify({ runtime: heldRuntime() }));
  const run = (entrypoint, payload, env = {}) => {
    const result = spawnSync(process.execPath, [CLI, entrypoint], {
      input: JSON.stringify(payload),
      cwd: projectCwd(),
      env: {
        PATH: process.env.PATH, HOME: home, MARROW_API_KEY: apiKey, MARROW_BASE_URL: 'https://api.example.test',
        MARROW_AGENT_ID: 'agent-one', MARROW_HOOK_BACKGROUND_NUDGE: 'false', MARROW_PASSIVE_TOKEN_USAGE: 'false',
        MARROW_TEST_MOCK_DIR: mockDir, NODE_OPTIONS: `--require=${MOCK}`, ...env,
      },
      encoding: 'utf8',
      timeout: 30_000,
    });
    assert.equal(result.error, undefined);
    output.push(result.stdout, result.stderr);
    return result;
  };
  const output = [];
  const requests = () => {
    const path = join(mockDir, 'requests.jsonl');
    return existsSync(path) ? readFileSync(path, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line)) : [];
  };
  // Every byte the hook wrote: request bodies (mock log), every file under the fake home (state, spool, receipts, logs), stdout and stderr.
  const allBytes = () => {
    const parts = [...output];
    const walk = (path) => {
      for (const name of readdirSync(path)) {
        const child = join(path, name);
        const st = statSync(child);
        if (st.isDirectory()) walk(child);
        else if (st.isFile()) parts.push(readFileSync(child, 'latin1'));
      }
    };
    walk(dir);
    return parts.join('\n');
  };
  return { dir, home, run, requests, allBytes, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

// The held runtime answer of test/host-approvals.test.js (hostRuntime), for a review on GitHub, with no proof pack.
function heldRuntime(receipt = 'gate-held') {
  return {
    ok: true,
    action: REVIEW_CLASS,
    decision_id: 'decision-review',
    runtime_authorization: { id: receipt, kind: 'durable_gate_receipt', durable: true, decision_state: 'created', decision_creation_required: false, decision_id: 'decision-review' },
    gate_receipt: { id: receipt, decision: 'review_required', required: true, owner_approval_required: true, expires_at: '2030-01-01T00:30:00.000Z' },
    proof_pack: { required: false, fields: [], complete: true },
    completion_contract: {
      decision_id: 'decision-review', decision_creation_required: false, decision_state: 'created',
      owner_approval_required: true, arbitration_receipt_required: false, gate_receipt_required: true,
      required_commit_fields: ['decision_id', 'success', 'outcome', 'gate_receipt_id'],
      owner_approval: {
        mode: 'ordinary_non_arbitrated', proof_path: null, proof_shape: null, dashboard_receipt_required: false,
        trusted_completion_receipt_required: true, receipt_field: 'owner_approval_receipt_id',
        approval_endpoint: '/v1/dashboard/enforcement/owner-approval', approval_authority: 'host_operator_or_dashboard_owner',
        approval_status_endpoint: `/v1/agent/gate-receipts/${receipt}/owner-approval`, approval_status_poll_after_ms: 5000,
        host_approval_endpoint: `/v1/agent/gate-receipts/${receipt}/host-approval`, host_approval_accepted: true,
        host_approval_trust: 'client_attested', approval_categories: ['source_control'],
        verified_approval_required: false, verified_approval_categories: [],
      },
    },
    risk_gate: { allow: true, decision: 'review_required', enforced: true, gate_required: true, gate_receipt_id: receipt, risk_level: 'high', reasons: [{ message: 'Pushes need approval.' }] },
    gate_receipt_id: receipt,
    exact_next_action: 'Obtain explicit owner approval before this action runs.',
  };
}

const SESSION = '3b1f0c2e-0000-4000-8000-00000000000a';
const preEvent = (command, id) => ({ session_id: SESSION, cwd: '/home/operator/project', permission_mode: 'default', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command, description: 'x' }, tool_use_id: id });
const batchRejected = (command, id) => ({
  session_id: SESSION, cwd: '/home/operator/project', permission_mode: 'default', hook_event_name: 'PostToolBatch',
  tool_calls: [{ tool_name: 'Bash', tool_input: { command, description: 'x' }, tool_use_id: id, tool_response: "The user doesn't want to proceed with this tool use. The tool use was rejected (eg. if it was a file edit, the new_string was NOT written to the file). STOP what you are doing and wait for the user to tell you how to proceed." }],
});
const postEvent = (command, id) => ({ session_id: SESSION, cwd: '/home/operator/project', permission_mode: 'default', hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_input: { command, description: 'x' }, tool_response: { stdout: 'ok', stderr: '', interrupted: false, isImage: false }, tool_use_id: id, duration_ms: 10 });
const runtimeBodies = (h) => h.requests().filter((r) => r.path === '/v1/agent/runtime' && /^classified \S+ action: /.test(r.body?.action || '')).map((r) => r.body);
const actionsIn = (h) => h.requests().filter((r) => r.path !== '/v1/agent/runtime').flatMap((r) => findActions(r.body)).filter(Boolean);
function findActions(value) {
  if (!value || typeof value !== 'object') return [];
  const own = value.normalized_action ? [{ ...value.normalized_action }] : [];
  return [...own, ...Object.values(value).flatMap(findActions)];
}

test('CM2 / CONS end to end: the runtime body alone carries the text; the hold, the decline report and the lifecycle record carry the same plain hash and no text', () => {
  const text = 'git push origin feat/cmdtext-e2e';
  const h = harness();
  try {
    h.run('claude-pre-action-hook', preEvent(text, 'toolu_01CMDTEXT000000000000001'));
    const [body] = runtimeBodies(h);
    assert.ok(body, 'the runtime was called');
    assert.equal(body.action, REVIEW_CLASS);
    assert.deepEqual(body.normalized_action.tool_input, { command_sha256: P(text), command: text });
    // The hold (local state) binds the same plain hash, no text.
    const state = readFileSync(join(h.home, '.marrow', 'host-approvals', 'state.json'), 'utf8');
    assert.equal(state.includes(text), false, 'no text in the hold');
    assert.ok(state.includes(P(text)), 'the hold carries the plain hash');
    // The decline report (host-approval.ts PostToolBatch settle).
    h.run('claude-hook', batchRejected(text, 'toolu_01CMDTEXT000000000000001'));
    const reported = actionsIn(h);
    assert.ok(reported.length >= 1, 'the decline was reported with its normalized action');
    for (const action of reported) assert.deepEqual(action.tool_input, { command_sha256: P(text) });
    // Only the runtime request holds the text, and no other byte anywhere.
    const others = h.requests().filter((r) => r.path !== '/v1/agent/runtime' || !/^classified /.test(r.body?.action || ''));
    assert.equal(JSON.stringify(others).includes(text), false, 'no text in any other request');
  } finally {
    h.cleanup();
  }
});

test('CONS lifecycle and commit spool (hook.ts): the same plain hash, no command bytes', () => {
  const text = 'git push origin feat/cmdtext-life';
  const h = harness();
  try {
    writeFileSync(join(h.dir, 'mock', 'config.json'), JSON.stringify({ runtime: heldRuntime(), commitStatus: 503 }));
    h.run('claude-pre-action-hook', preEvent(text, 'toolu_01CMDTEXT000000000000002'));
    h.run('claude-hook', postEvent(text, 'toolu_01CMDTEXT000000000000002'));
    const bytesOutsideRuntime = [h.allBytes().replace(JSON.stringify(text), '')].join('');
    // The text may appear only inside the runtime request line(s) of the mock log.
    const log = readFileSync(join(h.dir, 'mock', 'requests.jsonl'), 'utf8').split('\n').filter((line) => !line.includes('"path":"/v1/agent/runtime"')).join('\n');
    assert.equal(log.includes(text), false, 'no text in any non-runtime request');
    const files = [];
    const walk = (p) => { for (const n of readdirSync(p)) { const c = join(p, n); if (statSync(c).isDirectory()) walk(c); else files.push(c); } };
    walk(h.home);
    for (const file of files) assert.equal(readFileSync(file, 'latin1').includes(text), false, 'no text in a home file (state, spool, receipts, logs)');
    const commitActions = actionsIn(h);
    for (const action of commitActions) assert.deepEqual(action.tool_input, { command_sha256: P(text) });
    assert.ok(bytesOutsideRuntime.length > 0);
  } finally {
    h.cleanup();
  }
});

test('A9 end to end: a misleading title is not the review class, so the runtime body has no text', () => {
  const h = harness();
  try {
    const command = "gh pr create --base feat/a --title 'deploy to production'";
    h.run('claude-pre-action-hook', preEvent(command, 'toolu_01CMDTEXT000000000000003'));
    for (const body of runtimeBodies(h)) {
      assert.notEqual(body.action, REVIEW_CLASS);
      assert.equal(body.normalized_action.tool_input.command, undefined);
    }
    assert.equal(h.allBytes().includes('deploy to production'), false);
  } finally {
    h.cleanup();
  }
});

test('A18 dummy secret never leaves: one dummy in each position, scanned over every captured byte', () => {
  const d = dummySecret();
  const { commands } = dummyPositions(d);
  const h = harness();
  try {
    commands.forEach((command, i) => {
      h.run('claude-pre-action-hook', preEvent(command.text, `toolu_01CMDTEXTA18000000000000${i}`));
      h.run('claude-hook', postEvent(command.text, `toolu_01CMDTEXTA18000000000000${i}`));
    });
    assert.ok(h.requests().length > 0, 'the hook reached the mock');
    const bytes = h.allBytes();
    for (const command of commands) assert.equal(bytes.includes(command.secret), false, `dummy in ${command.position} never leaves`);
  } finally {
    h.cleanup();
  }
});

test('A30 end to end: the opt-out sends the 3.9.111 body (keyed hash, no text) on the runtime call', () => {
  const text = 'git push origin feat/cmdtext-off';
  const h = harness();
  try {
    h.run('claude-pre-action-hook', preEvent(text, 'toolu_01CMDTEXT000000000000004'), { MARROW_HOOK_COMMAND_TEXT: 'off' });
    const [body] = runtimeBodies(h);
    assert.ok(body);
    assert.deepEqual(Object.keys(body.normalized_action.tool_input), ['command_sha256']);
    assert.notEqual(body.normalized_action.tool_input.command_sha256, P(text));
    assert.equal(h.allBytes().includes(text), false);
    assert.equal(h.allBytes().includes(P(text)), false, 'the plain hash is nowhere either');
  } finally {
    h.cleanup();
  }
});
