'use strict';
// CLIENT-MISS3 round 2 (fix A, main ruling R2): programs[] and every normalized field of env and wrapper forms stay as 3.9.114;
// the env option table is read only by the control route (ctl-disable stays held). Rows B2-a (subset), B2-b, PE-1, PE-2, CTL,
// AB-P1..AB-P6, COL-P1 of the patch spec. Every expectation below was recorded from the 3.9.114 dist (BASE 48b1fbec80ab), never
// from this branch. Flags: T truncated, S the command text sent, H exact_hmac present. Dummy values are generated at run time.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');

const DIST = path.join(__dirname, '..', 'dist');
const hook = require(path.join(DIST, 'hook-pre-action.js'));
const norm = require(path.join(DIST, 'normalized-action.js'));
const routes = require(path.join(DIST, 'control-routes.js'));

const SALT = crypto.randomBytes(32);
// A dummy value: a fixed non-key prefix letter plus run-time hex (hex holds no key-prefix letters).
const DUMMY = `f${crypto.randomBytes(20).toString('hex').slice(1)}`;
const ROUTE_ACTION = 'classified Bash action: security on marrow-control';

function run(command, { off = false, toolInput = null } = {}) {
  const before = process.env.MARROW_HOOK_COMMAND_TEXT;
  if (off) process.env.MARROW_HOOK_COMMAND_TEXT = 'off'; else delete process.env.MARROW_HOOK_COMMAND_TEXT;
  try {
    const event = { session_id: 's', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: toolInput || { command }, tool_use_id: 't', cwd: '/w' };
    const c = hook.classifyTool(event, { keyed: true });
    const na = norm.normalizedHookAction(event, { deadlineAt: Date.now() + 5000, sendCommandText: false, claudeCodeBash: true, salt: SALT });
    return { c, na };
  } finally {
    if (before === undefined) delete process.env.MARROW_HOOK_COMMAND_TEXT; else process.env.MARROW_HOOK_COMMAND_TEXT = before;
  }
}
const flags = (na) => `${na.truncated === true ? 'T' : ''}${typeof na.tool_input.command === 'string' ? 'S' : ''}${'exact_hmac' in na.tool_input ? 'H' : ''}`;

// PE-1 / PE-2 (B2-a subset: every env and wrapper form with cat and npm, text on and off): 3.9.114 programs and flags.
const PE_TABLE = {"env -u A cat":{"on":[["a"],"S"],"off":[["a"],""]},"env -u A npm":{"on":[["a"],"S"],"off":[["a"],""]},"env -uA cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"env -uA npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"env --unset A cat":{"on":[["a"],"S"],"off":[["a"],""]},"env --unset A npm":{"on":[["a"],"S"],"off":[["a"],""]},"env --unset=A cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"env --unset=A npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"env -u A -u B cat":{"on":[["a"],"S"],"off":[["a"],""]},"env -u A -u B npm":{"on":[["a"],"S"],"off":[["a"],""]},"env -u LS cat":{"on":[["ls"],"S"],"off":[["ls"],""]},"env -u LS npm":{"on":[["ls"],"S"],"off":[["ls"],""]},"env -u GH_TOKEN cat":{"on":[["gh_token"],"TH"],"off":[["gh_token"],"TH"]},"env -u GH_TOKEN npm":{"on":[["gh_token"],"TH"],"off":[["gh_token"],"TH"]},"env -C /tmp cat":{"on":[["tmp"],"S"],"off":[["tmp"],""]},"env -C /tmp npm":{"on":[["tmp"],"S"],"off":[["tmp"],""]},"env -C/tmp cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"env -C/tmp npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"env --chdir /tmp cat":{"on":[["tmp"],"S"],"off":[["tmp"],""]},"env --chdir /tmp npm":{"on":[["tmp"],"S"],"off":[["tmp"],""]},"env --chdir=/tmp cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"env --chdir=/tmp npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"env -C ./cat cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"env -C ./cat npm":{"on":[["cat"],"S"],"off":[["cat"],""]},"env -cat /usr/bin cat":{"on":[["bin"],"S"],"off":[["bin"],""]},"env -npm /usr/bin npm":{"on":[["bin"],"S"],"off":[["bin"],""]},"env -a x cat":{"on":[["x"],"S"],"off":[["x"],""]},"env -a x npm":{"on":[["x"],"S"],"off":[["x"],""]},"env --argv0 x cat":{"on":[["x"],"S"],"off":[["x"],""]},"env --argv0 x npm":{"on":[["x"],"S"],"off":[["x"],""]},"env -a echo cat":{"on":[["echo"],"S"],"off":[["echo"],""]},"env -a echo npm":{"on":[["echo"],"S"],"off":[["echo"],""]},"env -S \"cat x\"":{"on":[[],"S"],"off":[[],""]},"env -S \"npm x\"":{"on":[[],"S"],"off":[[],""]},"env -S cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"env -S npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"env --split-string=\"cat x\"":{"on":[[],"S"],"off":[[],""]},"env --split-string=\"npm x\"":{"on":[[],"S"],"off":[[],""]},"env -iu A cat":{"on":[["a"],"S"],"off":[["a"],""]},"env -iu A npm":{"on":[["a"],"S"],"off":[["a"],""]},"env -vC /tmp cat":{"on":[["tmp"],"S"],"off":[["tmp"],""]},"env -vC /tmp npm":{"on":[["tmp"],"S"],"off":[["tmp"],""]},"env -i0 cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"env -i0 npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"env -- cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"env -- npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"env - cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"env - npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"env -i cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"env -i npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"env -0 cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"env -0 npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"env -v cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"env -v npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"env A=1 cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"env A=1 npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"env -i A=1 B=2 cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"env -i A=1 B=2 npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"env --ignore-signal cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"env --ignore-signal npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"env --default-signal=INT cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"env --default-signal=INT npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"env --block-signal=PIPE cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"env --block-signal=PIPE npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"env --frobnicate cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"env --frobnicate npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"env -Z cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"env -Z npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"env -u":{"on":[[],"S"],"off":[[],""]},"sudo cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"sudo npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"sudo -u root cat":{"on":[["root"],"S"],"off":[["root"],""]},"sudo -u root npm":{"on":[["root"],"S"],"off":[["root"],""]},"sudo -E cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"sudo -E npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"sudo -u root -E cat":{"on":[["root"],"S"],"off":[["root"],""]},"sudo -u root -E npm":{"on":[["root"],"S"],"off":[["root"],""]},"doas -u root cat":{"on":[["root"],"S"],"off":[["root"],""]},"doas -u root npm":{"on":[["root"],"S"],"off":[["root"],""]},"timeout 5 cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"timeout 5 npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"timeout -s KILL 5 cat":{"on":[["kill"],"S"],"off":[["kill"],""]},"timeout -s KILL 5 npm":{"on":[["kill"],"S"],"off":[["kill"],""]},"timeout -s KILL cat":{"on":[["kill"],"S"],"off":[["kill"],""]},"timeout -s KILL npm":{"on":[["kill"],"S"],"off":[["kill"],""]},"nice cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"nice npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"nice -n 5 cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"nice -n 5 npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"ionice -c 3 cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"ionice -c 3 npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"stdbuf -oL cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"stdbuf -oL npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"xargs cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"xargs npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"xargs -I{} cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"xargs -I{} npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"xargs -n 1 cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"xargs -n 1 npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"exec cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"exec npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"exec -a x cat":{"on":[["x"],"S"],"off":[["x"],""]},"exec -a x npm":{"on":[["x"],"S"],"off":[["x"],""]},"time cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"time npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"nohup cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"nohup npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"command cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"command npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"command -v cat":{"on":[["cat"],"S"],"off":[["cat"],""]},"command -v npm":{"on":[["npm"],"S"],"off":[["npm"],""]},"setsid cat":{"on":[["setsid"],"S"],"off":[["setsid"],""]},"setsid npm":{"on":[["setsid"],"S"],"off":[["setsid"],""]},"chrt 5 cat":{"on":[["chrt"],"S"],"off":[["chrt"],""]},"chrt 5 npm":{"on":[["chrt"],"S"],"off":[["chrt"],""]},"sudo env -u A cat":{"on":[["a"],"S"],"off":[["a"],""]},"sudo env -u A npm":{"on":[["a"],"S"],"off":[["a"],""]},"env -u A sudo -u root cat":{"on":[["a"],"S"],"off":[["a"],""]},"env -u A sudo -u root npm":{"on":[["a"],"S"],"off":[["a"],""]},"bash -c 'env -u A cat'":{"on":[["bash"],"S"],"off":[["bash"],""]},"bash -c 'env -u A npm'":{"on":[["bash"],"S"],"off":[["bash"],""]},"env -u A cat && cat":{"on":[["a","cat"],"S"],"off":[["a","cat"],""]},"env -u A npm && npm":{"on":[["a","npm"],"S"],"off":[["a","npm"],""]},"env -u A cat; cat":{"on":[["a","cat"],"S"],"off":[["a","cat"],""]},"env -u A npm; npm":{"on":[["a","npm"],"S"],"off":[["a","npm"],""]},"env -u A cat || cat":{"on":[["a","cat"],"S"],"off":[["a","cat"],""]},"env -u A npm || npm":{"on":[["a","npm"],"S"],"off":[["a","npm"],""]},"cat | env -u A cat":{"on":[["cat","a"],"S"],"off":[["cat","a"],""]},"npm | env -u A npm":{"on":[["npm","a"],"S"],"off":[["npm","a"],""]},"(env -u A cat)":{"on":[["a"],"S"],"off":[["a"],""]},"(env -u A npm)":{"on":[["a"],"S"],"off":[["a"],""]},"env -u A nice -n 5 cat":{"on":[["a"],"S"],"off":[["a"],""]},"env -u A nice -n 5 npm":{"on":[["a"],"S"],"off":[["a"],""]},"timeout 5 env -C /tmp cat":{"on":[["tmp"],"S"],"off":[["tmp"],""]},"timeout 5 env -C /tmp npm":{"on":[["tmp"],"S"],"off":[["tmp"],""]},"env -u \uff21 cat":{"on":[[],""],"off":[[],""]},"env -u \uff21 npm":{"on":[[],""],"off":[[],""]},"env -u A\u200b cat":{"on":[[],""],"off":[[],""]},"env -u A\u200b npm":{"on":[[],""],"off":[[],""]},"env -u \u217cs cat":{"on":[[],""],"off":[[],""]},"env -u \u217cs npm":{"on":[[],""],"off":[[],""]}};

test('PE-1/PE-2 (B2-a forms): programs[] and the normalized flags of every env and wrapper form are byte-equal to 3.9.114', () => {
  let n = 0;
  for (const [command, modes] of Object.entries(PE_TABLE)) {
    for (const [mode, [programs, flagCode]] of Object.entries(modes)) {
      const { na } = run(command, { off: mode === 'off' });
      assert.deepEqual(na.programs, programs, `${command} (${mode}): programs as 3.9.114`);
      assert.equal(flags(na), flagCode, `${command} (${mode}): truncated, sent text and exact_hmac as 3.9.114`);
      if (flagCode.includes('S')) assert.equal(na.tool_input.command, command);
      n += 1;
    }
  }
  assert.ok(n >= 280, `rows ${n}`);
});

const ROWS = {
  'B2b-1': 'sudo -u root ls', 'B2b-2': 'env -u A cat', 'B2b-3': 'env --unset A cat', 'B2b-4': 'env -C /tmp rm -rf build', 'B2b-5': 'env -P /usr/bin ls',
  'B2b-6': 'env -a x echo hi', 'B2b-7': 'env -iu A true', 'B2b-8': 'env -S "cat x"', 'B2b-9': 'timeout -s KILL true', 'B2b-10': 'nice -n 5 echo', 'B2b-11': 'xargs -I{} rm',
  'AB-P1': 'env -S "npm publish"', 'AB-P2': 'env -u LS npm publish', 'AB-P3': `GH_TOKEN=${DUMMY} env -u GH_TOKEN cat`, 'AB-P3b': `env -u GH_TOKEN cat ${DUMMY}`,
  'AB-P4a': 'sudo env -u A cat', 'AB-P4b': 'env -u A sudo -u root ls', 'AB-P4c': "bash -c 'env -u A cat'", 'AB-P5a': 'env -u A -u B cat', 'AB-P5b': 'env --frobnicate cat',
  'COL-P1a': 'env -u A cat', 'COL-P1b': 'env -u B cat',
  CTL: 'cd /tmp && env -u MARROW_API_KEY npx -y @getmarrow/install@0.1.76 control disable --yes 2>&1 | tail -n 3',
};
// [programs, flags, classified action] on 3.9.114 for each row, text on and (':off') off.
const EXPECTED = {"B2b-1":[["root"],"S","classified Bash action: process on workspace"],"B2b-2":[["a"],"S","classified Bash action: process on workspace"],"B2b-3":[["a"],"S","classified Bash action: process on workspace"],"B2b-4":[["tmp"],"S","classified Bash action: process on workspace"],"B2b-5":[["bin"],"S","classified Bash action: process on workspace"],"B2b-6":[["x"],"S","classified Bash action: process on workspace"],"B2b-7":[["a"],"S","classified Bash action: process on workspace"],"B2b-8":[[],"S","classified Bash action: process on workspace"],"B2b-9":[["kill"],"S","classified Bash action: process on workspace"],"B2b-10":[["echo"],"S","classified Bash action: process on workspace"],"B2b-11":[["rm"],"S","classified Bash action: process on workspace"],"AB-P1":[[],"S","classified Bash action: publish on npm"],"AB-P2":[["ls"],"S","classified Bash action: publish on npm"],"AB-P3":[["gh_token"],"TH","classified Bash action: process on workspace"],"AB-P3b":[["gh_token"],"TH","classified Bash action: process on workspace"],"AB-P4a":[["a"],"S","classified Bash action: process on workspace"],"AB-P4b":[["a"],"S","classified Bash action: process on workspace"],"AB-P4c":[["bash"],"S","classified Bash action: process on workspace"],"AB-P5a":[["a"],"S","classified Bash action: process on workspace"],"AB-P5b":[["cat"],"S","classified Bash action: process on workspace"],"COL-P1a":[["a"],"S","classified Bash action: process on workspace"],"COL-P1b":[["b"],"S","classified Bash action: process on workspace"],"CTL":[["cd","marrow_api_key","1","tail"],"TH","classified Bash action: process on workspace"],"AB-P6":[["a"],"S","classified Bash action: process on workspace"],"B2b-1:off":[["root"],"","classified Bash action: process on workspace"],"B2b-2:off":[["a"],"","classified Bash action: process on workspace"],"B2b-3:off":[["a"],"","classified Bash action: process on workspace"],"B2b-4:off":[["tmp"],"","classified Bash action: process on workspace"],"B2b-5:off":[["bin"],"","classified Bash action: process on workspace"],"B2b-6:off":[["x"],"","classified Bash action: process on workspace"],"B2b-7:off":[["a"],"","classified Bash action: process on workspace"],"B2b-8:off":[[],"","classified Bash action: process on workspace"],"B2b-9:off":[["kill"],"","classified Bash action: process on workspace"],"B2b-10:off":[["echo"],"","classified Bash action: process on workspace"],"B2b-11:off":[["rm"],"","classified Bash action: process on workspace"],"AB-P1:off":[[],"","classified Bash action: publish on npm"],"AB-P2:off":[["ls"],"","classified Bash action: publish on npm"],"AB-P3:off":[["gh_token"],"TH","classified Bash action: process on workspace"],"AB-P3b:off":[["gh_token"],"TH","classified Bash action: process on workspace"],"AB-P4a:off":[["a"],"","classified Bash action: process on workspace"],"AB-P4b:off":[["a"],"","classified Bash action: process on workspace"],"AB-P4c:off":[["bash"],"","classified Bash action: process on workspace"],"AB-P5a:off":[["a"],"","classified Bash action: process on workspace"],"AB-P5b:off":[["cat"],"","classified Bash action: process on workspace"],"COL-P1a:off":[["a"],"","classified Bash action: process on workspace"],"COL-P1b:off":[["b"],"","classified Bash action: process on workspace"],"CTL:off":[["cd","marrow_api_key","1","tail"],"TH","classified Bash action: process on workspace"],"AB-P6:off":[["a"],"","classified Bash action: process on workspace"]};

test('B2-b, AB-P1..AB-P5 (and AB-ENV-PROG / ACC-3 programs re-pointed by R2): programs and flags byte-equal to 3.9.114', () => {
  for (const off of [false, true]) {
    for (const [id, command] of Object.entries(ROWS)) {
      const [programs, flagCode, action] = EXPECTED[`${id}${off ? ':off' : ''}`];
      const { c, na } = run(command, { off });
      assert.deepEqual(na.programs, programs, `${id}: programs byte-equal to 3.9.114`);
      assert.equal(flags(na), flagCode, `${id}: flags as 3.9.114`);
      if (id !== 'CTL') assert.equal(c.action, action, `${id}: classified as 3.9.114`);
    }
  }
});

test('CTL: ctl-disable behind env -u stays held by the control route (security on marrow-control, risk high)', () => {
  for (const off of [false, true]) {
    const { c, na } = run(ROWS.CTL, { off });
    assert.equal(routes.controlRoute(ROWS.CTL), true);
    assert.equal(c.action, ROUTE_ACTION);
    assert.equal(c.type, 'security');
    assert.equal(c.risk, 'high');
    assert.equal(c.readOnly, false);
    assert.equal(na.truncated, true, 'a credential-named env value keeps the body cut, as 3.9.114');
  }
});

test('AB-P3: a credential-named NAME and a dummy value never reach a body or a key; truncated as 3.9.114', () => {
  for (const id of ['AB-P3', 'AB-P3b']) {
    for (const off of [false, true]) {
      const { na } = run(ROWS[id], { off });
      assert.ok(!JSON.stringify(na).includes(DUMMY), `${id}: no dummy value in the body`);
      assert.equal(na.truncated, true, `${id}: truncated as 3.9.114`);
    }
  }
});

test('AB-P6: a forged programs field inside tool_input is ignored as on 3.9.114', () => {
  for (const off of [false, true]) {
    const [programs, flagCode] = EXPECTED[`AB-P6${off ? ':off' : ''}`];
    const { na } = run('env -u A cat', { off, toolInput: { command: 'env -u A cat', programs: ['ls'] } });
    assert.deepEqual(na.programs, programs);
    assert.equal(flags(na), flagCode);
  }
});

test('COL-P1: commands that differ only in the env NAME keep distinct keys', () => {
  for (const off of [false, true]) {
    const a = run(ROWS['COL-P1a'], { off }).na.tool_input;
    const b = run(ROWS['COL-P1b'], { off }).na.tool_input;
    assert.notEqual(a.command_sha256, b.command_sha256);
  }
});

// X1 (main ruling R1 of the round 1 result): FX-3 only for credential-store and Marrow-state DIRECTORY listings.
const policy = require(path.join(DIST, 'hook-tool-policy.js'));
const HOME = process.env.HOME;

test('X1: a listing that only names a secret-looking FILE keeps the 3.9.114 local answer', () => {
  for (const command of ['ls .env.dist', 'ls -la .env.defaults', 'stat .env.dist', 'ls app.env.example', 'ls -la .env']) {
    const event = { tool_name: 'Bash', tool_input: { command }, cwd: HOME };
    assert.equal(hook.classifyTool(event).readOnly, true, `${command}: read-only as 3.9.114`);
    const [segment] = policy.parseShellSegments(command);
    assert.equal(policy.shellSegmentVerdict(segment, HOME), 'read', command);
  }
});

test('X1: credential-store and Marrow-state directory listings go to the server with the listing verdict', () => {
  for (const command of ['ls ~/.marrow/credentials', 'ls -la ~/.ssh', 'cd ~/.marrow/host-approvals; ls ~+', 'ls ~/.ssh/id_ed25519', 'ls ~/.marrow/credentials/x.env']) {
    const event = { tool_name: 'Bash', tool_input: { command }, cwd: HOME };
    assert.equal(hook.classifyTool(event).readOnly, false, `${command}: the server answers`);
    assert.equal(policy.isReadOnlyToolEvent({ tool_name: 'Bash', tool_input: { command } }), false, command);
  }
  for (const command of ['ls ~/.marrow/credentials', 'ls -la ~/.ssh']) {
    const [segment] = policy.parseShellSegments(command);
    assert.equal(policy.shellSegmentVerdict(segment, HOME), 'listing', command);
  }
});
