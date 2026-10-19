'use strict';

// First-hour fixes: message and output changes only (copy C1-C16). The rules, reason codes and
// decisions are proved unchanged by tools/fh-diff.cjs against the base build; these tests pin the
// words, their bounds and the structured flag that replaced a string comparison.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const seatbelt = require(path.join(ROOT, 'dist', 'seatbelt', 'hook.js'));
const pre = require(path.join(ROOT, 'dist', 'hook-pre-action.js'));

const CATEGORIES = ['S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'Sx', 'hook'];
const ASCII = /^[\t\n\x20-\x7e]*$/;
const NEVER = [/\bactivate\b/, /marrow-mcp setup/, /\brisk\b/i, /\brisky\b/i, /\bscore\b/i, /\bclassifier\b/i, /Marrow AI/];

test('FH-1 C1/C2/C3: stop texts lead with the label, say what to do, and end with the code', () => {
  const lead = 'If you (the person at this machine) meant it, run it yourself in your own terminal. Agent: do not retry it another way and do not edit Marrow settings; tell the user it was stopped.';
  const keyless = seatbelt.seatbeltStopText('S2', 'S2.production_deploy', 'wrangler_production', 'seatbelt');
  assert.equal(keyless, `MARROW SEATBELT stopped this action: production deploy. ${lead} For approval prompts instead of stops, add a Marrow key: getmarrow.ai/docs#start-here (Claude Code plugin: put MARROW_API_KEY in ~/.marrow/env, chmod 600, then /reload-plugins). Code: S2.production_deploy/wrangler_production.`);
  const account = seatbelt.seatbeltStopText('S3', 'S3.package_publish', 'npm_publish', 'account');
  assert.equal(account, `MARROW SEATBELT stopped this action: package publish. ${lead} Code: S3.package_publish/npm_publish.`);
  const linked = seatbelt.seatbeltStopText('S1', 'S1.force_push', 'protected_branch', 'claimed_no_key', true);
  assert.equal(linked, `MARROW SEATBELT stopped this action: force-push or delete of a protected branch. ${lead} ${pre.CLAIMED_NO_KEY_TEXT} Code: S1.force_push/protected_branch.`);
});

test('FH-1 C9: S4 names what it protects; an unreadable script is named as unreadable, on every category', () => {
  const s4 = seatbelt.seatbeltStopText('S4', 'S4.credential_access', 'operand_secret_path', 'seatbelt');
  assert.ok(s4.startsWith('MARROW SEATBELT stopped this action: reading, copying or writing secrets (like .env files or private keys). '));
  assert.doesNotMatch(s4, /credential or secret access/);
  for (const category of CATEGORIES) {
    const text = seatbelt.seatbeltStopText(category, `${category}.x`, 'script_unreadable', 'seatbelt');
    assert.match(text, /^MARROW SEATBELT stopped this action: a script Marrow could not read \(treated as .+\)\. If you /, category);
  }
  assert.ok(seatbelt.seatbeltStopText('S2', 'S2.production_deploy', 'script_unreadable', 'seatbelt').startsWith('MARROW SEATBELT stopped this action: a script Marrow could not read (treated as production deploy). '));
  // The other labels are unchanged.
  for (const [category, label] of [['S0', 'a change to Marrow seatbelt settings or an owner-only command'], ['S1', 'force-push or delete of a protected branch'], ['S2', 'production deploy'], ['S3', 'package publish'], ['S5', 'recursive delete outside the workspace'], ['Sx', 'obfuscated execution'], ['hook', 'a safety check that could not finish']]) {
    assert.ok(seatbelt.seatbeltStopText(category, `${category}.x`, 'some_reason', 'account').startsWith(`MARROW SEATBELT stopped this action: ${label}. `), category);
  }
});

test('FH-1: no new text tells anyone to run activate or marrow-mcp setup, uses the avoided words, or leaves ASCII', () => {
  const texts = [pre.NO_KEY_TEXT, pre.SEATBELT_HELD_TEXT];
  for (const mode of ['seatbelt', 'account', 'claimed_no_key']) {
    for (const linked of [true, false]) for (const category of CATEGORIES) texts.push(seatbelt.seatbeltStopText(category, `${category}.rule`, 'script_unreadable', mode, linked));
  }
  for (const text of texts) {
    assert.match(text, ASCII);
    for (const word of NEVER) assert.doesNotMatch(text, word, text.slice(0, 60));
  }
});

test('FH-1 C7: the no-key hold keeps the substring the plugin launcher test matches', () => {
  assert.match(pre.NO_KEY_TEXT, /no API key/);
  assert.ok(pre.NO_KEY_TEXT.startsWith('Marrow has no API key on this machine, so it held this action. '));
  assert.ok(pre.NO_KEY_TEXT.endsWith('Agent: do not retry this action.'));
  assert.ok(pre.NO_KEY_TEXT.length <= 500);
});

test('FH-1 C6: the held text keeps its prefix and says what the person can do', () => {
  assert.ok(pre.SEATBELT_HELD_TEXT.startsWith('MARROW SEATBELT held this action: this host cannot show its own approval prompt here, and no Marrow account is linked to approve it. '));
  assert.ok(pre.SEATBELT_HELD_TEXT.endsWith('For approval prompts, add a Marrow key: getmarrow.ai/docs#start-here.'));
  assert.ok(pre.SEATBELT_HELD_TEXT.length <= 500);
});

test('FH-1: every stop keeps its code at the end on each host; Gemini stays within its guard limit of 500', () => {
  const reasons = ['operand_secret_path', 'script_unreadable', 'npm_publish', 'hook_error'];
  const rules = ['S4.credential_access', 'S2.production_deploy', 'S0.owner_only', 'U5.fail_closed'];
  for (const harness of ['claude-code', 'codex', 'cursor', 'cline', 'gemini']) {
    for (const mode of ['seatbelt', 'account']) {
      for (const category of CATEGORIES) {
        for (const rule of rules) {
          for (const reason of reasons) {
            const out = pre.localLoopGuardDenyOutput(harness, seatbelt.seatbeltStopText(category, rule, reason, mode));
            const shown = out.hookSpecificOutput ? out.hookSpecificOutput.permissionDecisionReason : out.permission ? out.user_message : out.errorMessage || out.reason;
            assert.ok(shown.endsWith(` Code: ${rule}/${reason}.`), `${harness} ${mode} ${category}: ${shown.slice(-90)}`);
            assert.ok(shown.length <= (harness === 'gemini' ? 500 : 800));
          }
        }
      }
    }
  }
  // The longest codes the format allows are cut at the host's limit and never throw.
  const longest = seatbelt.seatbeltStopText('S4', `S4.${'y'.repeat(61)}`, 'z'.repeat(64), 'seatbelt');
  assert.ok(pre.localLoopGuardDenyOutput('gemini', longest).reason.length <= 500);
  assert.ok(pre.localLoopGuardDenyOutput('claude-code', longest).hookSpecificOutput.permissionDecisionReason.length <= 800);
  assert.equal(pre.localLoopGuardDenyOutput('windsurf', longest), null);
  assert.deepEqual(Object.keys(pre.localLoopGuardDenyOutput('gemini', longest)).sort(), ['decision', 'reason']);
});

test('FH-1 consumer: the Cline credentials branch follows a structured flag, not a text comparison', () => {
  const result = (extra) => ({ runtime: null, permit: null, protectedRisk: true, ...extra });
  const text = 'any words at all';
  assert.deepEqual(pre.clinePreActionHookOutput(result({ enforcementError: text, credentialsUnavailable: true })), { cancel: true, errorMessage: text });
  // Without the flag the same words are not treated as a missing key, whatever they say.
  for (const words of [pre.NO_KEY_TEXT, pre.CLAIMED_NO_KEY_TEXT, pre.SETUP_UNCONFIRMED_TEXT]) {
    const out = pre.clinePreActionHookOutput(result({ enforcementError: words }));
    assert.equal(out.cancel, true);
    assert.match(out.errorMessage, /^Marrow could not confirm a permit for this protected action\./);
  }
  // The existing failures keep their words.
  assert.match(pre.clinePreActionHookOutput(result({ failure: 'unavailable' })).errorMessage, /^Marrow is unavailable/);
  assert.match(pre.clinePreActionHookOutput(result({ failure: 'credential_scope' })).errorMessage, /^This Marrow API key is not authorized/);
});

// ------------------------------------------------------------------------------------------ FH-4

const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');
const { spawnSync, execFileSync } = require('node:child_process');
const fallback = require(path.join(ROOT, 'dist', 'seatbelt', 'fallback-copy.js'));

const CLI = path.join(ROOT, 'dist', 'cli.js');
const PRELOAD = path.join(__dirname, 'support', 'seatbelt-hook-preload.cjs');

const TABLE = {
  strict: ['MARROW_SEATBELT_STRICT=1 is set', 'unset MARROW_SEATBELT_STRICT'],
  key_rejected: ['the Marrow key on this machine was rejected', 'run npx -y @getmarrow/install@latest doctor'],
  home_unknown: ['it cannot find your login home folder (common in containers that run as a user with no home)', 'run the agent as a user that has a home folder'],
  home_unusable: ['your login home folder is missing, is not a folder, or is /', 'give this user a real home folder'],
  env_home_unusable: ['HOME points to a folder that is missing, is not a folder, or is /', 'set HOME to your login home folder'],
  home_mismatch: ['HOME is not your login home folder', 'start the agent with HOME set to your login home folder'],
  evidence_unknown: ['a folder or file it checks (your home folder, ~/.claude or ~/.marrow) can be written by other users, belongs to another user, or could not be read', 'make sure it belongs to you, then run chmod go-w on it'],
  setup_unconfirmed: ['it could not confirm this machine\'s setup', 'run npx -y @getmarrow/install@latest doctor'],
};

test('FH-4 C4/C5: each reason has its words; the first reason in the fixed order is picked; nothing known gives the generic row', () => {
  for (const [code, [why, fix]] of Object.entries(TABLE)) {
    const sentence = `Marrow uses its stricter no-key mode here because ${why}. Fix (for the person at this machine, not the agent): ${fix}, or add a Marrow key (getmarrow.ai/docs#start-here).`;
    assert.equal(fallback.fallbackSentence(code), sentence, code);
    assert.equal(fallback.setupUnconfirmedText(code), `Marrow stopped this action: there is no Marrow key on this machine, and ${sentence} Agent: do not retry it another way and do not edit Marrow settings; tell the user why it was stopped. Code: ${code}.`, code);
    assert.match(fallback.setupUnconfirmedText(code), ASCII);
    for (const word of NEVER) assert.doesNotMatch(fallback.setupUnconfirmedText(code), word, code);
  }
  const order = ['strict', 'key_rejected', 'home_unknown', 'home_unusable', 'env_home_unusable', 'home_mismatch', 'evidence_unknown'];
  for (let i = 0; i < order.length; i += 1) {
    assert.equal(fallback.pickFallbackReason([...order].reverse().filter((_, j) => order.length - 1 - j >= i)), order[i]);
    assert.equal(fallback.pickFallbackReason(['account_evidence', order[i]]), order[i]);
  }
  for (const none of [[], ['account_evidence'], null, undefined, 'strict', 7, {}, ['STRICT'], ['__proto__'], ['toString']]) assert.equal(fallback.pickFallbackReason(none), 'setup_unconfirmed', JSON.stringify(none));
  // An unknown code never reaches the text: only the table words and the fixed code are printed.
  for (const odd of ['__proto__', 'toString', 'constructor', '', null, undefined, 'a'.repeat(300), '../../etc']) {
    assert.equal(fallback.setupUnconfirmedText(odd), fallback.setupUnconfirmedText('setup_unconfirmed'));
    assert.equal(fallback.fallbackCode(odd), 'setup_unconfirmed');
  }
  // The generic constants of both modules are the same text as the generic row.
  assert.equal(pre.SETUP_UNCONFIRMED_TEXT, fallback.setupUnconfirmedText('setup_unconfirmed'));
  assert.equal(seatbelt.SETUP_UNCONFIRMED_TEXT, pre.SETUP_UNCONFIRMED_TEXT);
});

test('FH-4 C4: a stop in the fallback names the reason and ends with its codes; an account-linked machine keeps the account text', () => {
  const text = seatbelt.seatbeltStopText('S1', 'S1.force_push', 'protected_branch', 'claimed_no_key', false, 'home_mismatch');
  assert.ok(text.startsWith('MARROW SEATBELT stopped this action: force-push or delete of a protected branch. If you (the person at this machine) meant it, '));
  assert.ok(text.includes(` ${fallback.fallbackSentence('home_mismatch')} Code: S1.force_push/protected_branch; mode: home_mismatch.`));
  assert.ok(text.endsWith('; mode: home_mismatch.'));
  assert.doesNotMatch(text, /linked to an account/);
  // No mode reason given: the generic row.
  assert.ok(seatbelt.seatbeltStopText('S1', 'S1.force_push', 'protected_branch', 'claimed_no_key', false).endsWith('; mode: setup_unconfirmed.'));
  // Account-linked (C3) and the other modes never print a mode code.
  for (const [mode, linked] of [['claimed_no_key', true], ['account', false], ['seatbelt', false]]) {
    assert.doesNotMatch(seatbelt.seatbeltStopText('S1', 'S1.force_push', 'protected_branch', mode, linked, 'strict'), /mode: /);
  }
});

function home(root, name = 'home') {
  const dir = path.join(root, name);
  fs.mkdirSync(path.join(dir, 'proj'), { recursive: true, mode: 0o700 });
  fs.chmodSync(dir, 0o700);
  fs.mkdirSync(path.join(dir, '.claude'), { mode: 0o700 });
  const git = (...args) => execFileSync('git', args, { cwd: path.join(dir, 'proj'), env: { PATH: process.env.PATH, HOME: dir, GIT_CONFIG_NOSYSTEM: '1' }, stdio: 'ignore' });
  git('init', '-q', '-b', 'feat/x');
  git('remote', 'add', 'origin', 'git@github.com:acme/proj.git');
  git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '--allow-empty', '-m', 'init');
  return dir;
}

// The real Claude Code pre-action hook, keyless, offline (the preload refuses every network attempt).
function hookRun(root, command, { env = {}, passwd = 'home', homeEnv } = {}) {
  const dir = path.join(root, 'home');
  const net = path.join(root, `net-${crypto.randomBytes(3).toString('hex')}.log`);
  const event = { hook_event_name: 'PreToolUse', session_id: `fh-${crypto.randomBytes(6).toString('hex')}`, tool_use_id: 't1', tool_name: 'Bash', tool_input: { command }, cwd: path.join(dir, 'proj') };
  const result = spawnSync(process.execPath, ['--require', PRELOAD, CLI, 'claude-pre-action-hook'], {
    cwd: path.join(dir, 'proj'), input: JSON.stringify(event), encoding: 'utf8', timeout: 30_000,
    env: { PATH: process.env.PATH, HOME: homeEnv ?? dir, SBT_PASSWD_HOME: passwd === 'home' ? dir : passwd, SBT_NETSPY: net, MARROW_HOOK_BACKGROUND_NUDGE: 'false', ...env },
  });
  assert.equal(result.error, undefined);
  assert.equal(fs.existsSync(net), false, 'no network attempt');
  const json = result.stdout.trim() ? JSON.parse(result.stdout) : null;
  return { status: result.status, json, text: json?.hookSpecificOutput?.permissionDecisionReason || '', stderr: result.stderr };
}

// env_home_unusable is not driven here: with HOME missing the loop guard's own state is unsafe and that denial comes first.
test('FH-4 C4/C5 end to end: the real hook names the real reason for a stop and for a hold (offline, no state written)', () => {
  const cases = [
    ['strict', () => ({ env: { MARROW_SEATBELT_STRICT: '1' } })],
    ['home_mismatch', (root) => ({ homeEnv: fs.mkdtempSync(path.join(root, 'other-')) })],
    ['home_unusable', (root) => ({ passwd: path.join(root, 'missing-passwd-home'), homeEnv: path.join(root, 'home') })],
    ['evidence_unknown', (root) => { fs.chmodSync(path.join(root, 'home', '.claude'), 0o777); return {}; }],
  ];
  for (const [code, options] of cases) {
    const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-fh4-')));
    try {
      home(root);
      const opts = options(root);
      // A protected action outside the seatbelt floor is a hold (C5); a floor stop is C4.
      const hold = hookRun(root, 'git push origin main', opts);
      assert.equal(hold.json.hookSpecificOutput.permissionDecision, 'deny', code);
      assert.equal(hold.text, fallback.setupUnconfirmedText(code), `${code} hold`);
      assert.ok(hold.text.startsWith('Marrow stopped this action: there is no Marrow key on this machine, and '), code);
      const stop = hookRun(root, 'npm publish', opts);
      assert.equal(stop.json.hookSpecificOutput.permissionDecision, 'deny', code);
      assert.ok(stop.text.endsWith(` Code: S3.package_publish/npm_publish; mode: ${code}.`), `${code} stop: ${stop.text.slice(-120)}`);
      assert.ok(stop.text.includes(fallback.fallbackSentence(code)), code);
      // No hold was recorded for a later approval (E2): nothing under ~/.marrow/host-approvals.
      assert.equal(fs.existsSync(path.join(root, 'home', '.marrow', 'host-approvals')), false, `${code}: no approval state`);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
});

test('FH-4: a mode resolution that throws keeps the generic reason; the hold is still a stop', () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-fh4-')));
  try {
    home(root);
    const stop = hookRun(root, 'npm publish', { env: { SBT_THROW: 'mode' } });
    assert.equal(stop.json.hookSpecificOutput.permissionDecision, 'deny');
    assert.ok(stop.text.startsWith('MARROW SEATBELT stopped this action: a safety check that could not finish. '));
    assert.ok(stop.text.endsWith(' Code: U5.fail_closed/hook_error; mode: setup_unconfirmed.'), stop.text.slice(-100));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

// ------------------------------------------------------------------------------------------ FH-2

const { consultSessionLoopGuard, recordSessionLoopOutcome } = require(path.join(ROOT, 'dist', 'session-loop-guard.js'));

function guardHome() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-fh2-'));
}

test('FH-2 C10: the loop guard says what happened and what to do next, by tool name only', () => {
  const root = guardHome();
  try {
    const secret = `tok_${crypto.randomBytes(12).toString('hex')}`;
    const op = (toolName, over = {}) => ({ sessionId: 's1', agentId: 'a1', harness: 'claude-code', toolName, toolInput: { file_path: `/tmp/${secret}`, command: `echo ${secret}` }, readOnly: true, ...over });
    const first = consultSessionLoopGuard(op('Read', { invocationId: 'i1' }), { home: root });
    assert.equal(first.allow, true);
    recordSessionLoopOutcome(op('Read', { invocationId: 'i1', toolInput: {} }), true, { output: 'x' }, { home: root });
    const passed = consultSessionLoopGuard(op('Read', { invocationId: 'i2' }), { home: root });
    assert.equal(passed.allow, false);
    assert.equal(passed.reason, `Marrow loop guard: you already ran this exact Read call in this session and nothing has changed since, so it was not run again. Use the earlier result. If an edit just failed, re-read only the lines you need (Read with offset and limit). Receipt: ${passed.receipt}.`);
    assert.match(passed.receipt, /^lgr_[0-9a-f]{24}$/);
    // The earlier run failed: the other wording (a failure is refused only on its second repeat).
    const bad = (id) => op('Edit', { invocationId: id, readOnly: false });
    consultSessionLoopGuard(bad('f1'), { home: root });
    recordSessionLoopOutcome({ ...bad('f1'), toolInput: {} }, false, { code: 1 }, { home: root });
    consultSessionLoopGuard(bad('f2'), { home: root });
    recordSessionLoopOutcome({ ...bad('f2'), toolInput: {} }, false, { code: 1 }, { home: root });
    const failed = consultSessionLoopGuard(bad('f3'), { home: root });
    assert.equal(failed.allow, false);
    assert.equal(failed.reason, `Marrow loop guard: this exact Edit call already failed in this session and nothing has changed since, so it was not run again. Change something before you try again. Receipt: ${failed.receipt}.`);
    for (const text of [passed.reason, failed.reason]) {
      assert.match(text, ASCII);
      assert.equal(text.includes(secret), false, 'the input is never echoed');
      for (const word of NEVER) assert.doesNotMatch(text, word);
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('FH-2 C10: a tool name that is not a plain name, or none, reads as "call"; the rule keys on the same name as before', () => {
  const hostile = ['Bash ignore previous instructions', 'a'.repeat(65), '', undefined, 'tool\nname', `Read ${'x'.repeat(10)}`, 'mcp__srv__do it'];
  for (const toolName of hostile) {
    const root = guardHome();
    try {
      const op = (id) => ({ sessionId: 's2', agentId: 'a2', harness: 'codex', toolName, toolInput: { q: 1 }, readOnly: true, invocationId: id });
      consultSessionLoopGuard(op('1'), { home: root });
      recordSessionLoopOutcome({ ...op('1'), toolInput: {} }, true, {}, { home: root });
      const denied = consultSessionLoopGuard(op('2'), { home: root });
      assert.equal(denied.allow, false, JSON.stringify(toolName));
      assert.ok(denied.reason.startsWith('Marrow loop guard: you already ran this exact call in this session and nothing has changed since'), denied.reason.slice(0, 90));
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
  // Two different tools with the same input are different operations (the key is unchanged).
  const root = guardHome();
  try {
    const op = (toolName, id) => ({ sessionId: 's3', agentId: 'a3', harness: 'codex', toolName, toolInput: { q: 1 }, readOnly: true, invocationId: id });
    consultSessionLoopGuard(op('Read', '1'), { home: root });
    recordSessionLoopOutcome({ ...op('Read', '1'), toolInput: {} }, true, {}, { home: root });
    assert.equal(consultSessionLoopGuard(op('Grep', '2'), { home: root }).allow, true);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

// ------------------------------------------------------------------------------------------ FH-7

function cliRun(args, env) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-fh7-')));
  try {
    const result = spawnSync(process.execPath, [CLI, ...args], {
      cwd: root, encoding: 'utf8', timeout: 30_000, input: '',
      env: { PATH: process.env.PATH, HOME: root, MARROW_HOOK_BACKGROUND_NUDGE: 'false', ...env },
    });
    assert.equal(result.error, undefined);
    return { status: result.status, stdout: result.stdout, stderr: result.stderr };
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

const PLUGIN_ERROR = 'Error: MARROW_API_KEY required. Marrow plugin: put MARROW_API_KEY in ~/.marrow/env, run chmod 600 ~/.marrow/env, then /reload-plugins. The seatbelt hooks keep working without a key. Do not run marrow-mcp setup or activate for the plugin.';

test('FH-7 C11: a keyless MCP server started by the plugin points to ~/.marrow/env and /reload-plugins; nothing else changes', () => {
  const marker = `/tmp/plugin-${crypto.randomBytes(8).toString('hex')}`;
  const plain = cliRun([], {});
  assert.equal(plain.status, 1);
  assert.match(plain.stderr, /^Error: MARROW_API_KEY environment variable is required\n/);
  assert.match(plain.stderr, /marrow-mcp setup/, 'without the plugin the old fix stays');
  for (const value of ['', '   ']) {
    const same = cliRun([], { CLAUDE_PLUGIN_ROOT: value });
    assert.equal(same.status, 1);
    assert.equal(same.stderr, plain.stderr, `an empty marker (${JSON.stringify(value)}) changes nothing`);
  }
  const plugin = cliRun([], { CLAUDE_PLUGIN_ROOT: marker });
  assert.equal(plugin.status, plain.status, 'the exit code is unchanged');
  assert.equal(plugin.stdout, plain.stdout);
  assert.ok(plugin.stderr.startsWith(`${PLUGIN_ERROR}\n`));
  assert.doesNotMatch(plugin.stderr.replace(PLUGIN_ERROR, ''), /marrow-mcp setup|activate/);
  assert.equal(plugin.stderr.includes(marker), false, 'the value of the marker is never printed');
  assert.match(plugin.stderr, /Get a key: https:\/\/getmarrow\.ai\/signup/);
  assert.match(PLUGIN_ERROR, ASCII);
});

test('FH-7 C11: the other two "MARROW_API_KEY required" sites follow the same marker', () => {
  const marker = `/tmp/plugin-${crypto.randomBytes(8).toString('hex')}`;
  for (const args of [['keys', 'list'], ['spool-status']]) {
    const plain = cliRun(args, {});
    assert.equal(plain.status, 1, args.join(' '));
    assert.match(plain.stderr, /^Error: MARROW_API_KEY required\. Create an API key/, args.join(' '));
    const plugin = cliRun(args, { CLAUDE_PLUGIN_ROOT: marker });
    assert.equal(plugin.status, 1, args.join(' '));
    assert.equal(plugin.stderr, `${PLUGIN_ERROR}\n`, args.join(' '));
    assert.equal(plugin.stdout, plain.stdout);
  }
});
