'use strict';

// Audit I1 (mutant B12): the keyless kill switch. With SEATBELT_ROLLOUT.keyless forced to 'off' (test
// preload), a keyless machine is claimed_no_key: 3.9.103's holds plus the floor, with the "keyless mode
// is off here" text, never the seatbelt pass. Keyless temporary home; nothing reaches a server.
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
const { SETUP_UNCONFIRMED_TEXT, SEATBELT_ROLLOUT } = require('../dist/seatbelt/hook.js');

function run(rollout, harness, command) {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-i1-')));
  try {
    const home = path.join(root, 'home');
    const proj = path.join(home, 'proj');
    fs.mkdirSync(proj, { recursive: true, mode: 0o700 });
    fs.chmodSync(home, 0o700);
    execFileSync('git', ['init', '-q', '-b', 'feat/x'], { cwd: proj, env: { PATH: process.env.PATH, HOME: home, GIT_CONFIG_NOSYSTEM: '1' }, stdio: 'ignore' });
    const sid = `i1-${crypto.randomBytes(6).toString('hex')}`;
    const event = { hook_event_name: 'PreToolUse', session_id: sid, tool_use_id: 't1', tool_name: 'Bash', tool_input: { command }, cwd: proj };
    const env = { PATH: process.env.PATH, HOME: home, SBT_PASSWD_HOME: home, SBT_NETSPY: path.join(root, 'net.log'), MARROW_HOOK_BACKGROUND_NUDGE: 'false' };
    if (rollout) env.SBT_ROLLOUT_KEYLESS = rollout;
    const r = spawnSync(process.execPath, ['--require', PRELOAD, CLI, `${harness}-pre-action-hook`], { cwd: proj, encoding: 'utf8', timeout: 30_000, input: JSON.stringify(event), env });
    const net = fs.existsSync(path.join(root, 'net.log')) ? fs.readFileSync(path.join(root, 'net.log'), 'utf8') : '';
    return { status: r.status, out: r.stdout, err: r.stderr, net };
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

const reason = (out) => {
  const j = JSON.parse(out);
  return j.hookSpecificOutput && j.hookSpecificOutput.permissionDecision === 'deny' ? j.hookSpecificOutput.permissionDecisionReason : null;
};

test('I1: the shipped rollout is keyless on; the kill switch off makes a keyless machine claimed_no_key (holds, never the seatbelt pass)', () => {
  assert.equal(SEATBELT_ROLLOUT.keyless, 'on');
  for (const harness of ['claude', 'codex']) {
    // On: `git push origin main` (held by 3.9.103) gets the seatbelt pass, Claude's and Codex's neutral answer.
    const on = run(null, harness, 'git push origin main');
    assert.equal(on.status, 0, on.err);
    assert.deepEqual(JSON.parse(on.out), {}, `${harness} on: ${on.out}`);
    // Off: the 3.9.103 hold, with the "keyless mode is off here" text (no account evidence).
    const off = run('off', harness, 'git push origin main');
    assert.equal(off.status, 0, off.err);
    assert.equal(reason(off.out), SETUP_UNCONFIRMED_TEXT, `${harness} off: ${off.out}`);
    // Off: the floor still stops an S action (claimed_no_key = holds plus the floor).
    const floor = run('off', harness, 'npm publish');
    assert.match(String(reason(floor.out)), /^MARROW SEATBELT stopped this action: package publish/, `${harness} floor: ${floor.out}`);
    for (const r of [on, off, floor]) assert.equal(r.net, '');
  }
});
