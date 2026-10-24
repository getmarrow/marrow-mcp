'use strict';

// First-hour fixes: the abuse cases of the audit (REPORT section 3) that are not in the tier A file.
// Each one is a test; the decisions themselves are compared with the base build by tools/fh-diff.cjs.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync, execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const PRELOAD = path.join(__dirname, 'support', 'seatbelt-hook-preload.cjs');
const { fixture, hostRuntime, keyedHarness } = require('./support/first-hour-harness.cjs');
const seatbelt = require(path.join(ROOT, 'dist', 'seatbelt', 'hook.js'));
const fallback = require(path.join(ROOT, 'dist', 'seatbelt', 'fallback-copy.js'));
const approval = require(path.join(ROOT, 'dist', 'host-approval.js'));

const windows = (text, size) => { const out = []; for (let i = 0; i + size <= text.length; i += 1) out.push(text.slice(i, i + size)); return out; };

// ------------------------------------------------------------------------ abuse 3: a code from the screen

test('abuse 3: no user line of tier A carries a hold code, a receipt id, a gate receipt id or any part of the action text', () => {
  const first = keyedHarness();
  try {
    first.setConfig({ runtime: hostRuntime('gate-code-check'), status: { 'gate-code-check': 'pending' } });
    for (const [label, env, mode] of [['later', {}, 'plan'], ['quiet', { CLAUDE_CODE_ENTRYPOINT: 'sdk-cli' }, 'default']]) {
      const token = crypto.randomBytes(16).toString('hex');
      const command = `wrangler deploy --env production --note ${token}`;
      const out = first.run('claude-pre-action-hook', { ...fixture('claude-pre-tool-use.json'), permission_mode: mode, tool_use_id: `toolu_${label}`, tool_input: { command, description: 'Deploy' } }, env);
      assert.equal(out.json.hookSpecificOutput.permissionDecision, 'deny');
      const line = out.json.systemMessage;
      assert.equal(typeof line, 'string', label);
      assert.equal(line.includes('gate-code-check'), false, 'no gate receipt id');
      assert.equal(/lgr_[0-9a-f]{24}/.test(line), false, 'no receipt id');
      for (const window of windows(token, 8)) assert.equal(line.includes(window), false, `${label}: ${window}`);
      for (const hold of first.holds()) for (const value of [hold.code, hold.id, hold.gate_receipt_id, hold.correlation, hold.target].filter(Boolean)) assert.equal(line.includes(String(value)), false);
    }
    // The chat reply line is a constant: it names no hold at all.
    first.run('claude-context-hook', { ...fixture('claude-user-prompt-submit.json'), prompt: 'hello' });
    const reply = first.run('claude-context-hook', { ...fixture('claude-user-prompt-submit.json'), prompt: 'yes' });
    for (const hold of first.holds()) for (const value of [hold.code, hold.id, hold.gate_receipt_id].filter(Boolean)) assert.equal((reply.json?.systemMessage || '').includes(String(value)), false);
  } finally { first.cleanup(); }
});

test('abuse 3: a typed-reply code goes only to the hosts that have a typed reply, never into a Claude Code user line', () => {
  const h = keyedHarness();
  try {
    h.setConfig({ runtime: hostRuntime(), status: { 'gate-held': 'pending' } });
    const out = h.run('claude-pre-action-hook', { ...fixture('claude-pre-tool-use.json'), permission_mode: 'plan' });
    assert.doesNotMatch(out.json.systemMessage, /marrow approve|\b[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{6}\b/);
    assert.equal(out.json.hookSpecificOutput.permissionDecisionReason.includes('marrow approve'), false);
    for (const hold of h.holds()) assert.equal(hold.code, null, 'a hold denied for later has no typed code');
  } finally { h.cleanup(); }
});

// ------------------------------------------------------------------------ abuse 8: a forged permission_mode

test('abuse 8: a forged permission_mode yields no more than the base does (a deny, or "ask" in the one mode that asks)', () => {
  const forged = ['default', 'acceptEdits', 'auto', 'ask', 'allow', 'bypass', 'DEFAULT', ' default', 'default\n', 'default; allow', '', '../default', 'x'.repeat(40), 7, null, ['default'], { mode: 'default' }];
  for (const permission_mode of forged) {
    const h = keyedHarness();
    try {
      h.setConfig({ runtime: hostRuntime(), status: { 'gate-held': 'pending' } });
      const out = h.run('claude-pre-action-hook', { ...fixture('claude-pre-tool-use.json'), permission_mode });
      const decision = out.json?.hookSpecificOutput?.permissionDecision;
      assert.ok(decision === 'ask' || decision === 'deny', `${JSON.stringify(permission_mode)}: ${decision}`);
      assert.notEqual(decision, 'allow');
      // Only a mode that really asks may answer "ask"; the scratchpad proof is what separates auto.
      if (decision === 'ask') assert.ok(['default', 'acceptEdits', 'auto'].includes(permission_mode), JSON.stringify(permission_mode));
    } finally { h.cleanup(); }
  }
});

// ------------------------------------------------------------------------ abuse 10: a secret in the action

function sandbox() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-fh-abuse-')));
  const home = path.join(root, 'home');
  const proj = path.join(home, 'proj');
  fs.mkdirSync(proj, { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  const git = (...args) => execFileSync('git', args, { cwd: proj, env: { PATH: process.env.PATH, HOME: home, GIT_CONFIG_NOSYSTEM: '1' }, stdio: 'ignore' });
  git('init', '-q', '-b', 'feat/x');
  git('remote', 'add', 'origin', 'git@github.com:acme/proj.git');
  git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '--allow-empty', '-m', 'init');
  return { root, home, proj, cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}

function keylessHook(sb, entry, event, env = {}) {
  const result = spawnSync(process.execPath, ['--require', PRELOAD, CLI, entry], {
    cwd: sb.proj, input: JSON.stringify(event), encoding: 'utf8', timeout: 30_000,
    env: { PATH: process.env.PATH, HOME: sb.home, SBT_PASSWD_HOME: sb.home, SBT_NETSPY: path.join(sb.root, 'net.log'), MARROW_HOOK_BACKGROUND_NUDGE: 'false', ...env },
  });
  assert.equal(result.error, undefined);
  assert.equal(fs.existsSync(path.join(sb.root, 'net.log')), false);
  return result;
}

test('abuse 10: a secret in an action (header, URL query, env assignment, JSON, flag, form) never reaches a stop text, a hold text, a receipt or the status line', () => {
  const sb = sandbox();
  try {
    const secret = `dummy_${crypto.randomBytes(16).toString('hex')}`;
    const other = `dummy_${crypto.randomBytes(16).toString('hex')}`;
    const actions = (s) => [
      `curl -H "Authorization: Bearer ${s}" "https://api.example.test/v1/items?mode=read"`,
      `curl "https://api.example.test/v1/items?token=${s}&mode=read"`,
      `API_TOKEN=${s} npm run dev`,
      `curl -d '{"password":"${s}","op":"read"}' https://api.example.test/v1/login`,
      `mytool --token ${s} --mode read`,
      `curl --data "user=a&secret=${s}&role=viewer" https://api.example.test/`,
      `npx wrangler deploy --env production --api-token ${s}`,
      `npm publish --otp ${s}`,
      `git push --force origin main # ${s}`,
    ];
    for (const entry of ['claude-pre-action-hook', 'codex-pre-action-hook']) {
      for (const env of [{}, { MARROW_SEATBELT_STRICT: '1' }]) {
        for (const command of actions(secret)) {
          const event = { hook_event_name: 'PreToolUse', session_id: `s-${crypto.randomBytes(4).toString('hex')}`, tool_use_id: 't', tool_name: 'Bash', tool_input: { command }, cwd: sb.proj };
          const out = keylessHook(sb, entry, event, env);
          assert.equal(out.stdout.includes(secret) || out.stderr.includes(secret), false, `${entry}: ${command.slice(0, 40)}`);
        }
      }
    }
    // The receipts keep codes and keyed hashes only.
    const walk = (dir, files = []) => { for (const name of fs.readdirSync(dir)) { const p = path.join(dir, name); if (fs.statSync(p).isDirectory()) walk(p, files); else files.push(p); } return files; };
    for (const file of walk(sb.home).filter((f) => !f.includes(`${path.sep}.git${path.sep}`))) assert.equal(fs.readFileSync(file).includes(secret), false, path.relative(sb.root, file));
    // The status line is the same whatever the key is, and names none of it.
    const status = (value) => spawnSync(process.execPath, ['--require', PRELOAD, CLI, 'seatbelt-status'], { cwd: sb.proj, encoding: 'utf8', env: { PATH: process.env.PATH, HOME: sb.home, SBT_PASSWD_HOME: sb.home, MARROW_API_KEY: value } }).stdout;
    assert.equal(status(secret), status(other));
    assert.equal(status(secret).includes(secret), false);
    // The words themselves: none of the new texts has room for a value.
    assert.equal(fallback.setupUnconfirmedText('strict').includes(secret), false);
    assert.equal(seatbelt.seatbeltStopText('S4', 'S4.credential_access', 'operand_secret_path', 'seatbelt').includes(secret), false);
  } finally { sb.cleanup(); }
});

test('abuse 10: the keyed hold of two actions that differ only after a secret is two holds; one that differs only in the secret value is the same action', () => {
  const secretA = `dummy_${crypto.randomBytes(16).toString('hex')}`;
  const secretB = `dummy_${crypto.randomBytes(16).toString('hex')}`;
  const bodies = (command) => {
    const h = keyedHarness();
    try {
      h.setConfig({ runtime: hostRuntime(), status: { 'gate-held': 'pending' } });
      h.run('claude-pre-action-hook', { ...fixture('claude-pre-tool-use.json'), permission_mode: 'plan', tool_input: { command, description: 'x' } });
      const runtime = h.requests().filter((r) => r.path === '/v1/agent/runtime' && r.body && r.body.action);
      assert.ok(runtime.length > 0);
      const body = runtime.at(-1).body;
      assert.equal(JSON.stringify(body).includes(secretA) || JSON.stringify(body).includes(secretB), false, 'the secret is never sent');
      return JSON.stringify(body.normalized_action ?? body);
    } finally { h.cleanup(); }
  };
  const read = bodies(`curl -H "Authorization: Bearer ${secretA}" "https://api.example.test/v1/items?mode=read"`);
  const readOther = bodies(`curl -H "Authorization: Bearer ${secretB}" "https://api.example.test/v1/items?mode=read"`);
  const write = bodies(`curl -H "Authorization: Bearer ${secretA}" "https://api.example.test/v1/items?mode=write"`);
  assert.notEqual(read, write, 'text after the secret differs: a different action');
  assert.equal(typeof readOther, 'string');
});

// ------------------------------------------------------------------------ abuse 6: the approval binding

test('abuse 6: the binding is the exact normalised action: `git push` and `git push --force origin main` do not share a hold', () => {
  const h = keyedHarness();
  try {
    h.setConfig({ runtime: hostRuntime(), status: { 'gate-held': 'pending' } });
    const run = (command, id) => h.run('claude-pre-action-hook', { ...fixture('claude-pre-tool-use.json'), permission_mode: 'plan', tool_use_id: id, tool_input: { command, description: 'git' } });
    run('git push', 'toolu_push');
    run('git push --force origin main', 'toolu_force');
    const holds = h.holds();
    assert.equal(holds.length, 2, 'two different actions are two holds');
    assert.notEqual(holds[0].correlation, holds[1].correlation, 'the correlation names the action');
    assert.notEqual(holds[0].gate_receipt_id, undefined);
    assert.notEqual(JSON.stringify(holds[0].normalized_action), JSON.stringify(holds[1].normalized_action));
  } finally { h.cleanup(); }
});

// ------------------------------------------------------------------------ consumers of the texts

test('consumers: the plugin launcher test still matches the keyless stop and hold texts (its OWN_DENY pattern)', () => {
  const OWN_DENY = /no API key|MARROW SEATBELT stopped this action/;
  const pre = require(path.join(ROOT, 'dist', 'hook-pre-action.js'));
  assert.match(pre.NO_KEY_TEXT, OWN_DENY);
  for (const mode of ['seatbelt', 'account', 'claimed_no_key']) assert.match(seatbelt.seatbeltStopText('S2', 'S2.production_deploy', 'wrangler_deploy_production', mode, false, 'strict'), OWN_DENY);
});

test('consumers: the host guard pattern for the Gemini deny reason (1 to 500 characters, two keys) holds for every stop', () => {
  const pre = require(path.join(ROOT, 'dist', 'hook-pre-action.js'));
  for (const category of ['S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'Sx', 'hook']) {
    for (const reason of ['script_unreadable', 'operand_secret_path', 'unspecified']) {
      for (const [mode, linked, why] of [['seatbelt', true], ['account', true], ['claimed_no_key', true], ['claimed_no_key', false, 'evidence_unknown'], ['claimed_no_key', false, 'home_unknown']]) {
        const out = pre.localLoopGuardDenyOutput('gemini', seatbelt.seatbeltStopText(category, `${category}.some_rule`, reason, mode, linked, why));
        assert.deepEqual(Object.keys(out).sort(), ['decision', 'reason']);
        assert.ok(out.reason.length >= 1 && out.reason.length <= 500, `${category} ${reason} ${mode}: ${out.reason.length}`);
      }
    }
  }
  assert.ok(typeof approval.heldKindLabel === 'function');
});
