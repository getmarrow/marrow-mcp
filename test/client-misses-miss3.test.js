'use strict';
// CLIENT-MISS3 (16 Nov dogfood misses, MCP client items C1, C2, C4). Stricter only:
// FX-1 a bare 40/64 lower-case hex commit id in argument position is no longer withheld as a secret: the text reaches the
//      raise-only readers with `truncated: true`, the plain hash and the 3.9.114 exact_hmac (never bindable);
// FX-2 env and wrapper options are read before the program, so the control route sees the installer behind them;
// FX-3 a listing of a credential store is answered by the server (not read-only), never by a local allow.
// Ids and dummy secrets are generated at run time; no value is printed. Paths live under the private test HOME.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const { execFileSync, spawn } = require('node:child_process');

const DIST = path.join(__dirname, '..', 'dist');
const hook = require(path.join(DIST, 'hook-pre-action.js'));
const norm = require(path.join(DIST, 'normalized-action.js'));
const routes = require(path.join(DIST, 'control-routes.js'));
const policy = require(path.join(DIST, 'hook-tool-policy.js'));

const hex = (bytes) => crypto.randomBytes(bytes).toString('hex');
// An id: lower-case hex that starts with a letter (never read as a number or an option).
const newId = (bytes = 20) => `a${hex(bytes).slice(1)}`;
const ID = newId();
const ID_B = newId();
const ID64 = newId(32);
// Dummy secrets: a fixed non-key prefix letter plus run-time hex (hex holds no key-prefix letters).
const S1 = `f${hex(20).slice(1)}`;
const S2 = `e${hex(20).slice(1)}`;
const SECRETS = [S1, S2];
const SALT = crypto.randomBytes(32);
const HOME = process.env.HOME;
const TABLE = process.env.MISS3_TABLE_OUT || '';
const plainHash = (text) => crypto.createHash('sha256').update(`marrow-normalized-action-v3\nshell\n${text}`).digest('hex');
const NPX = 'npx -y @getmarrow/install control disable --yes';
const ROUTE_ACTION = 'classified Bash action: security on marrow-control';

function event(command, extra = {}) {
  return { session_id: 's', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, tool_use_id: 't', cwd: HOME, ...extra };
}

/** The runtime body the hook builds (as mk-client-bodies does): labels plus the normalized action (fixed run-time salt). */
function body(command, { off = false, ev = null } = {}) {
  const source = ev || event(command);
  const before = process.env.MARROW_HOOK_COMMAND_TEXT;
  if (off) process.env.MARROW_HOOK_COMMAND_TEXT = 'off';
  try {
    const c = hook.classifyTool(source, { keyed: true });
    const na = norm.normalizedHookAction(source, { deadlineAt: Date.now() + 2000, sendCommandText: c.action === 'classified Bash action: review on github', claudeCodeBash: true, salt: SALT });
    return { c, na };
  } finally {
    if (off) { if (before === undefined) delete process.env.MARROW_HOOK_COMMAND_TEXT; else process.env.MARROW_HOOK_COMMAND_TEXT = before; }
  }
}

const rows = [];
function record(id, data) {
  if (!TABLE) return;
  const line = JSON.stringify({ id, ...data });
  for (const secret of [...SECRETS, ID, ID_B, ID64]) assert.ok(!line.includes(secret), 'a table line holds no id or secret value');
  rows.push(line);
}
function summary(command, opts) {
  const { c, na } = body(command, opts);
  const ti = na.tool_input || {};
  return { sent: typeof ti.command === 'string', truncated: na.truncated === true, programs: na.programs, read_only: c.readOnly,
    action: c.action, type: c.type, risk: c.risk, sha: ti.command_sha256 || null, hmac: ti.exact_hmac || null, route: routes.controlRoute(command) };
}
test.after(() => { if (TABLE && rows.length) fs.appendFileSync(TABLE, `${rows.join('\n')}\n`); });

/** Runs every row (so the table holds every row), then fails with the ids of the rows that failed (never their text). */
async function each(table, fn) {
  assert.deepEqual(await collect(table, fn), []);
}
async function collect(table, fn) {
  const failed = [];
  for (const [id, command] of Object.entries(table)) {
    try { await fn(id, command); } catch (error) { failed.push(`${id}: ${String(error.message).split('\n')[0].replace(/[0-9a-f]{32,}/g, '<hex>')}`); }
  }
  return failed;
}

// ---------------------------------------------------------------------------------------------------------------------------
// FX-1: commit ids visible, body still cut
// ---------------------------------------------------------------------------------------------------------------------------
const ID_SENT = {
  'ship-deploy': `python3 -I /home/u/scripts/marrow-ship.py ${ID}`,
  'ship-64': `./deploy.sh ${ID64}`,
  'AB-ID-1': `true && python3 -I x/marrow-ship.py ${ID}`,
  'AB-ID-2': `cd /x; ./deploy.sh ${ID} | tail -3`,
  'AB-ID-3': `(cd /x && ./deploy.sh ${ID})`,
  'AB-ID-4': `bash -c "./deploy.sh ${ID}"`,
  'AB-ID-5': `eval "./deploy.sh ${ID}"`,
  'AB-ID-6': `"./deploy.sh" '${ID}'`,
  'AB-ID-7': `$(./deploy.sh ${ID})`,
};

test('FX-1 (ACC-2, AB-ID-1..7): the id stays visible; text sent with the plain hash, truncated kept, exact_hmac as with the text off', async () => {
  await each(ID_SENT, async (id, command) => {
    const { na } = body(command);
    const off = body(command, { off: true }).na;
    record(id, summary(command));
    assert.equal(na.tool_input.command, command, `${id}: text sent`);
    assert.equal(na.tool_input.command_sha256, plainHash(command), `${id}: plain hash of the host text`);
    assert.equal(na.truncated, true, `${id}: the body stays cut (no binding)`);
    assert.match(na.tool_input.exact_hmac, /^[0-9a-f]{32}$/, `${id}: exact_hmac kept`);
    assert.equal(na.tool_input.exact_hmac, off.tool_input.exact_hmac, `${id}: exact_hmac is the same with the text off`);
    assert.equal(off.tool_input.command, undefined, `${id}: no text with the text off`);
    assert.equal(off.truncated, true);
    assert.deepEqual(na.programs, off.programs);
    assert.deepEqual(Object.keys(na).sort(), ['programs', 'tool_input', 'tool_kind', 'tool_name', 'truncated']);
  });
  // The hold and report copies carry no text (withoutSentText), the same hash.
  const { na } = body(ID_SENT['ship-deploy']);
  const held = norm.withoutSentText(na);
  assert.equal(held.tool_input.command, undefined);
  assert.equal(held.tool_input.command_sha256, na.tool_input.command_sha256);
  assert.equal(held.truncated, true);
});

test('FX-1 programs and labels: equal to the same command with a non-hex word in place of the id', async () => {
  const { c, na } = body(ID_SENT['ship-deploy']);
  const ref = body('python3 -I /home/u/scripts/marrow-ship.py x').c;
  assert.deepEqual(na.programs, ['python3']);
  for (const field of ['action', 'type', 'risk', 'target', 'role', 'protected']) assert.deepEqual(c[field], ref[field], field);
});

const ID_WITHHELD = {
  'AB-CRED-1': `deploy --token ${S1}`,
  'AB-CRED-2': `deploy token ${S1}`,
  'AB-CRED-3': `TOKEN=${S1} deploy`,
  'AB-CRED-4': `export GH=${S1}`,
  'AB-CRED-5': `curl -H "Authorization: Bearer ${S1}" https://h/a`,
  'AB-CRED-6': `curl 'https://h/x?token=${S1}&a=1'`,
  'AB-CRED-7': `curl 'https://h/x?sha=${S1}'`,
  'AB-CRED-8': `curl -d '{"sha":"${S1}"}' https://h`,
  'AB-CRED-9': `printf '%s' ${S1} | gh auth login --with-token`,
  'AB-CRED-10': `git -c http.extraHeader="Authorization: basic ${S1}" fetch`,
  'AB-CRED-11': `mysql -p${S1}`,
  'AB-CRED-12': `sshpass -p ${S1} ssh h`,
  'AB-CRED-13': `echo ${S1} > ~/.git-credentials`,
  'AB-CRED-14': `./deploy.sh ${S1}; gh auth status`,
  'AB-CRED-15': `./deploy.sh ${S1} --session x`,
  'AB-CRED-16': `./sign-release.sh ${S1}`,
  'AB-CRED-17': `./deploy.sh ${S1} # TOK"EN"`,
  'AB-SHAPE-1': `./deploy.sh ${S1.toUpperCase()}`,
  'AB-SHAPE-2': `./deploy.sh ${S1.slice(0, 32)}`,
  'AB-SHAPE-3': `./deploy.sh ${S1.slice(0, 39)}`,
  'AB-SHAPE-4': `./deploy.sh ${S1}a`,
  'AB-SHAPE-5': `./deploy.sh ${S1}${S2.slice(0, 23)}`,
  'AB-SHAPE-6': `./deploy.sh ${S1}${S2.slice(0, 25)}`,
  'AB-SHAPE-7': `git push origin ${S1}:refs/heads/x`,
  'AB-SHAPE-9': `./deploy.sh ${S1.slice(0, 20)}ａ${S1.slice(21)}`,
  'AB-SHAPE-10': `./deploy.sh ${S1.slice(0, 20)}​${S1.slice(20)}`,
  'AB-VAR-1': `ID=${S1}; ./deploy.sh $ID`,
  'AB-VAR-3': `./deploy.sh \${ID:-${S1}}`,
  'COL-9': `deploy --match-head-commit ${S1}`,
  'AB-OPT-1': `./deploy.sh -r ${S1}`,
  'AB-HERE-1': `./deploy.sh <<< ${S1}`,
  'AB-REDIR-1': `./deploy.sh > ${S1}`,
  'AB-PIPEDATA-1': `echo ${S1} | ./deploy.sh`,
};

test('FX-1 fail-closed (AB-CRED, AB-SHAPE, AB-VAR): hex after a credential word or in any other position stays withheld, text not sent', async () => {
  await each(ID_WITHHELD, async (id, command) => {
    const { na } = body(command);
    record(id, summary(command));
    const text = JSON.stringify(na);
    assert.equal(na.tool_input.command, undefined, `${id}: text not sent`);
    // A non-ASCII character splits the hex, and `${ID:-hex}` is one joined word: 3.9.114 sends no text and withholds no word
    // (not cut, keyed hash); unchanged.
    if (!/^AB-(?:SHAPE-(?:9|10)|VAR-3)$/.test(id)) assert.equal(na.truncated, true, `${id}: truncated`);
    for (const secret of SECRETS) assert.ok(!text.includes(secret) && !text.includes(secret.toUpperCase()), `${id}: the value is in no field`);
  });
});

test('FX-1 AB-VAR-2 and the id range form: answer as 3.9.114 (no id word, nothing newly withheld or sent)', async () => {
  const rangeCmd = `git log ${ID}..${ID_B}`;
  const range = body(rangeCmd).na;
  record('AB-SHAPE-8', summary(rangeCmd));
  // 3.9.114 sends this text (no word is a bare id: the range is one word); unchanged, never cut by FX-1.
  assert.equal(range.tool_input.command, rangeCmd);
  assert.equal(range.truncated, undefined);
  const varCmd = './deploy.sh "$ID"';
  record('AB-VAR-2', summary(varCmd));
  assert.equal(body(varCmd).na.truncated, undefined);
});

test('FX-1 consumer length rule: a text over 8192 bytes or with non-ASCII stays hash-only (as 3.9.114)', async () => {
  const long = `./deploy.sh ${ID} ${'x '.repeat(4200)}`;
  const { na } = body(long);
  record('AB-LEN-1', summary(long));
  assert.equal(na.tool_input.command, undefined);
  assert.equal(na.truncated, true);
  assert.notEqual(na.tool_input.command_sha256, plainHash(long));
});

// ---------------------------------------------------------------------------------------------------------------------------
// FX-2: env and wrapper options read before the program
// ---------------------------------------------------------------------------------------------------------------------------
const ENV_ROUTES = {
  'ctl-disable': `cd /tmp && env -u MARROW_API_KEY -u MARROW_KEY -u MARROW_AGENT_ID -u MARROW_FLEET_AGENT_ID npx -y @getmarrow/install@0.1.76 control disable --yes 2>&1 | tail -n 3`,
  'AB-ENV-1': `env -u MARROW_API_KEY ${NPX}`,
  'AB-ENV-2': `env -i ${NPX}`,
  'AB-ENV-3': `env -- ${NPX}`,
  'AB-ENV-4': `env A=1 B=2 ${NPX}`,
  'AB-ENV-5': `env -C /tmp ${NPX}`,
  'AB-ENV-6': `env -S '${NPX}'`,
  'AB-ENV-7': `env -S"npx @getmarrow/install control disable"`,
  'AB-ENV-8': `env --unset=MARROW_KEY ${NPX}`,
  'AB-ENV-9': `env -iu MARROW_KEY ${NPX}`,
  'AB-ENV-10': `env -u A -u B -u C -u D ${NPX}`,
  'AB-ENV-11': `env -Z ${NPX}`,
  'AB-ENV-12': `env env -u K ${NPX}`,
  'AB-ENV-13': `env -S 'env -u K ${NPX}'`,
  'AB-ENV-14': `sudo -u alice ${NPX}`,
  'AB-ENV-15': `doas -u root ${NPX}`,
  'AB-ENV-16': `timeout -s KILL 60 ${NPX}`,
  'AB-ENV-17': `stdbuf -o L ${NPX}`,
  'AB-ENV-17b': `watch -n 5 ${NPX}`,
  'AB-ENV-18': `nice -n 5 env -u K ${NPX}`,
  'AB-ENV-19': `bash -c 'env -u K ${NPX}'`,
  'AB-ENV-20': `eval "env -u K ${NPX}"`,
  'AB-ENV-21': `echo $(env -u K ${NPX})`,
  'AB-ENV-22': `env -u "$V" ${NPX}`,
  'AB-ENV-23': 'env -u K "$RUNNER" @getmarrow/install control disable',
  'AB-ENV-24': 'xargs -I {} npx @getmarrow/install control {}',
  'AB-ENV-27': `env -uK ${NPX}`,
  'AB-ENV-28': `env --chdir /tmp ${NPX}`,
  'AB-ENV-29': `env -u ${NPX}`,
  'AB-ENV-30': `sudo -u root -g wheel env -u K ${NPX}`,
  'AB-ENV-31': `exec -a name ${NPX}`,
  'AB-ENV-32': `time -f %e ${NPX}`,
  'AB-ENV-33': `ionice -c 3 ${NPX}`,
  'AB-ENV-34': `chrt -f 10 ${NPX}`,
  'AB-ENV-35': `taskset -c 0-3 ${NPX}`,
  'AB-ENV-36': `unbuffer ${NPX}`,
  'AB-ENV-37': `timeout --signal KILL 60 ${NPX}`,
  'AB-ENV-38': `env -S 'npx -y \${PKG} control disable' @getmarrow/install`,
  'AB-ENV-39': `$W -u K ${NPX}`,
  'AB-ENV-40': `${'env -u K '.repeat(70)}${NPX}`,
};

test('FX-2 (ACC-3, AB-ENV-1..24): the installer behind env and wrapper options is the control route, held as without the prefix', async () => {
  const ref = body(NPX).c;
  assert.equal(ref.action, ROUTE_ACTION);
  await each(ENV_ROUTES, async (id, command) => {
    const { c } = body(command);
    record(id, summary(command));
    assert.equal(routes.controlRoute(command), true, `${id}: control route`);
    assert.equal(c.action, ROUTE_ACTION, `${id}: security on marrow-control`);
    assert.equal(c.type, 'security', id);
    assert.equal(c.risk, ref.risk, `${id}: risk as without the prefix`);
    assert.equal(c.readOnly, false, id);
  });
});

test('FX-2 AB-ENV-PROG (ACC-3 programs, re-pointed by main ruling R2): programs byte-equal to 3.9.114; env options are read only by the control route', async () => {
  // Expectations recorded from the 3.9.114 dist: the normalized program list keeps the 3.9.114 reading of env words.
  const { na } = body(ENV_ROUTES['ctl-disable']);
  assert.deepEqual(na.programs, ['cd', 'marrow_api_key', '1', 'tail']);
  assert.equal(na.truncated, true, 'the credential-named value keeps the body cut, as 3.9.114');
  const one = body(ENV_ROUTES['AB-ENV-1']).na;
  assert.deepEqual(one.programs, ['marrow_api_key']);
  assert.equal(one.truncated, true);
  assert.equal(typeof one.tool_input.command, 'undefined');
  for (const [command, programs] of [[`env -Z ${NPX}`, ['install']], ['env -u', []], [`env -u "$V" ${NPX}`, []], [`env -S 'npx x' y`, []],
    ['env -u HOME_DIR -C /tmp -i A=1 node build.js', ['home_dir']]]) {
    const row = body(command).na;
    assert.deepEqual(row.programs, programs, `${command}: programs as 3.9.114`);
    assert.notEqual(row.truncated, true, `${command}: not cut, as 3.9.114`);
  }
});

const NOT_ROUTES = {
  'AB-ENV-25': `env -u K npx -y @getmarrow/install control status`,
  'AB-ENV-26': `env -u K echo npx @getmarrow/install control disable`,
  'DH-ENV-1': `git commit -m "env -u K npx @getmarrow/install control disable"`,
  'DH-ENV-2': `echo "sudo -u x npx @getmarrow/install control disable"`,
  'DH-ENV-3': `grep -rn 'timeout -s KILL 5 marrow-install' docs`,
  'PL13-1': `env -Z npx -y some-other-tool control disable`,
  'PL13-2': `sudo -Q -u root npx -y other-pkg control disable`,
  'PL13-3': `timeout -s KILL 60 npm test`,
};

test('FX-2 never wider than asked: safe subcommand, data words, and texts without the installer are not routes', async () => {
  await each(NOT_ROUTES, async (id, command) => {
    record(id, summary(command));
    assert.equal(routes.controlRoute(command), false, `${id}: not a route`);
    assert.notEqual(body(command).c.action, ROUTE_ACTION, id);
  });
  assert.deepEqual(body(NOT_ROUTES['AB-ENV-25']).c.action, body('npx -y @getmarrow/install control status').c.action);
});

// ---------------------------------------------------------------------------------------------------------------------------
// FX-3: credential-store listings go to the server
// ---------------------------------------------------------------------------------------------------------------------------
const LS_SERVER = {
  'cred-ls': 'ls ~/.marrow/bin 2>/dev/null | head -30; ls ~/.marrow/credentials 2>/dev/null | grep -iE \'app|release|github\' | head',
  'AB-LS-1': 'ls ~/.ssh',
  'AB-LS-2': 'ls -la ~/.aws/',
  'AB-LS-3': 'ls $HOME/.gnupg',
  'AB-LS-4': 'ls ${HOME}/.kube',
  'AB-LS-5': `ls ${HOME}/.docker`,
  'AB-LS-6': 'cd ~ && ls .ssh',
  'AB-LS-7': 'ls ~/.marrow',
  'AB-LS-8': 'ls ~/.marrow/credentials/',
  'AB-LS-9': 'ls ~/.config/gh',
  'AB-LS-10': 'ls /etc/ssl/private',
  'AB-LS-11': 'ls ~/.ssh/*',
  'AB-LS-12': 'find ~/.marrow -maxdepth 1',
  'AB-LS-13': 'du -a ~/.aws',
  'AB-LS-14': 'stat ~/.ssh/id_ed25519',
  'AB-LS-15': 'file ~/.ssh/*',
  'AB-LS-16': 'tree ~/.ssh',
  'AB-LS-17': 'ls -R ~',
  'AB-LS-18': 'find ~ -name \'*.pem\'',
  'AB-LS-19': 'ls "$CREDS_DIR"',
  'AB-LS-20': 'D=~/.ssh; ls $D',
  'AB-LS-21a': 'ls ~/.SSH',
  'AB-LS-21b': 'ls ~/.ssh/../.ssh',
  'AB-LS-21c': 'ls ~//.ssh',
  'AB-LS-22': 'true; ls ~/.ssh 2>/dev/null | head',
  'AB-LS-23': 'ls ~/.marrow/bin ~/.ssh',
  'AB-LS-24': 'ls --color=auto ~/.azure',
  'AB-LS-25': 'ls ~/.password-store ~/.secrets',
  'AB-LS-26': 'ls -lR /etc/ssl',
  'AB-LS-27': 'du ~',
  'AB-LS-28': 'ls ~/.Marrow/Credentials',
};
const BASE_SERVER = new Set(['AB-LS-16', 'AB-LS-20']);
const LS_LOCAL = {
  'AB-LS-KEEP-1': 'ls ~/.marrow/bin',
  'AB-LS-KEEP-2': 'ls ~/.ssh-backup',
  'AB-LS-KEEP-3': 'ls ~/.ѕsh',
  'AB-LS-KEEP-4': 'ls /tmp',
  'AB-LS-KEEP-5': 'du -s ~',
  'AB-LS-KEEP-6': 'ls ~',
  'DH-LS-1': 'echo ~/.ssh',
  'DH-LS-2': 'ls -la src',
  'DH-LS-3': 'ls ~/.marrow/bin/marrow-ship.py',
};

test('FX-3 (ACC-4, AB-LS-1..22): a credential-store listing is not read-only (the server answers); never a local secret hold', async () => {
  await each(LS_SERVER, async (id, command) => {
    const { c, na } = body(command);
    record(id, summary(command));
    assert.equal(c.readOnly, false, `${id}: not read-only`);
    assert.notEqual(c.action, ROUTE_ACTION, id);
    assert.equal(policy.isReadOnlyToolEvent({ tool_name: 'Bash', tool_input: { command } }), false, `${id}: PostToolUse reader`);
    assert.equal(na.tool_kind, 'shell');
  });
  // Never 'read', never 'secret' (no local hold); the listing's words stay out of the labels, as a read segment's (3.9.114 labels).
  for (const command of ['ls ~/.ssh', 'ls ~/.marrow', 'find ~ -name x']) {
    const [segment] = policy.parseShellSegments(command);
    assert.equal(policy.shellSegmentVerdict(segment, HOME), 'listing', command);
  }
  assert.equal(policy.toolClassificationText({ tool_name: 'Bash', tool_input: { command: 'ls ~/.ssh/deploy_key && npm test' } }),
    policy.toolClassificationText({ tool_name: 'Bash', tool_input: { command: 'ls /srv/deploy_key && npm test' } }));
  assert.equal(policy.policyReadsAllWords('ls ~/.ssh'), policy.policyReadsAllWords('ls /srv'));
});

test('FX-3 keeps: HOME/.marrow/bin, look-alikes and plain listings stay local; data words unchanged', async () => {
  await each(LS_LOCAL, async (id, command) => {
    record(id, summary(command));
    assert.equal(body(command).c.readOnly, true, `${id}: read-only as 3.9.114`);
  });
});

test('TMO: a thrown reader error in the listing check answers not read-only; an overrun deadline keeps the cut placeholder', async () => {
  // A reader error inside the listing check (its expansion list throws when read): 'other', never 'read'.
  const expansions = [];
  expansions.filter = () => { throw new Error('reader error'); };
  const bad = { words: ['ls', '~/.ssh'], outputs: [], inputs: [], expansions };
  let verdict;
  try { verdict = policy.shellSegmentVerdict(bad, HOME); } catch { verdict = 'threw'; }
  assert.notEqual(verdict, 'read');
  const late = norm.normalizedHookAction(event(ID_SENT['ship-deploy']), { deadlineAt: Date.now() - 1, claudeCodeBash: true, salt: SALT });
  assert.equal(late.truncated, true);
  assert.equal(late.tool_input.command, undefined);
  assert.equal(routes.controlRoute(`env -u K ${NPX}`, 0, () => { throw new Error('x'); }), true);
});

test('AB-FORGE: forged event fields never lower an answer', async () => {
  const command = ID_SENT['ship-deploy'];
  const forms = {
    casing: event(command, { tool_name: 'bash' }),
    cmd: event(command, { tool_input: { command, cmd: command } }),
    cut: event(command, { input_truncated: true }),
    nonString: event(command, { tool_input: { command: [command] } }),
    long: event(`${command} ${'y'.repeat(9000)}`),
  };
  for (const [id, ev] of Object.entries(forms)) {
    const { na } = body('', { ev });
    record(`AB-FORGE-${id}`, { sent: typeof na.tool_input.command === 'string', truncated: na.truncated === true });
    assert.equal(na.tool_input.command, undefined, `${id}: no text`);
  }
  assert.equal(body('', { ev: event('ls ~/.ssh', { tool_name: 'bash' }) }).c.readOnly, false);
  assert.match(body('', { ev: event(`env -u K ${NPX}`, { tool_name: 'bash' }) }).c.action, /security on marrow-control$/);
});

// ---------------------------------------------------------------------------------------------------------------------------
// Collisions
// ---------------------------------------------------------------------------------------------------------------------------
test('COL-1..11: actions that differ outside a secret get different keys; secrets never in a key', async () => {
  const key = (command, off = false) => { const { na } = body(command, { off }); return `${na.tool_input.command_sha256}|${na.tool_input.exact_hmac || ''}`; };
  const sha = (command, off = false) => body(command, { off }).na.tool_input.command_sha256;
  const ship = (id) => `python3 -I /home/u/scripts/marrow-ship.py ${id}`;
  const differ = [
    ['COL-1', sha(ship(ID)), sha(ship(ID_B))],
    ['COL-1h', body(ship(ID)).na.tool_input.exact_hmac, body(ship(ID_B)).na.tool_input.exact_hmac],
    ['COL-2', sha(ship(ID), true), sha(ship(ID_B), true)],
    ['COL-4', key(`deploy --token ${S1} x`), key(`deploy --token ${S1} y`)],
    ['COL-5', key(`curl 'https://h/x?token=${S1}&ref=main'`), key(`curl 'https://h/x?token=${S1}&ref=prod'`)],
    ['COL-6', key(`GH=${S1} run a`), key(`GH=${S1} run b`)],
    ['COL-7', key(`curl -H "Authorization: Bearer ${S1}" https://h/a`), key(`curl -H "Authorization: Bearer ${S1}" https://h/b`)],
    ['COL-8', key(`curl -d '{"key":"${S1}","op":"a"}' https://h`), key(`curl -d '{"key":"${S1}","op":"b"}' https://h`)],
    ['COL-9', body(`deploy --match-head-commit ${ID}`).na.tool_input.exact_hmac, body(`deploy --match-head-commit ${ID_B}`).na.tool_input.exact_hmac],
    ['COL-10a', key(`env -u K1 ${NPX}`), key(`env -u K2 ${NPX}`)],
    ['COL-10b', key(`env -u K npx -y @getmarrow/install control disable`), key(`env -u K npx -y @getmarrow/install control status`)],
    ['COL-11', key('ls ~/.ssh'), key('ls ~/.aws')],
  ];
  for (const [id, a, b] of differ) {
    record(id, { differ: a !== b });
    assert.ok(a && b, `${id}: keys present`);
    assert.notEqual(a, b, `${id}: different keys`);
  }
  // COL-3: differ only in the secret: may match; neither value anywhere.
  const a = body(`deploy --token ${S1} x`).na;
  const b = body(`deploy --token ${S2} x`).na;
  record('COL-3', { match: a.tool_input.command_sha256 === b.tool_input.command_sha256 });
  for (const secret of SECRETS) assert.ok(!JSON.stringify([a, b]).includes(secret));
});

// ---------------------------------------------------------------------------------------------------------------------------
// The real hook entrypoint (ACC-1): dist/cli.js claude-pre-action-hook, real event JSON on stdin, private HOME, dummy key,
// a self-signed https loopback recorder. Every request, the spool and stderr are searched for every dummy secret (COL-12).
// ---------------------------------------------------------------------------------------------------------------------------
let opensslOk = true;
try { execFileSync('openssl', ['version'], { stdio: 'ignore' }); } catch { opensslOk = false; }

async function withRecorder(fn) {
  const dir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'marrow-miss3-'));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(dir, 'k.pem'), '-out', path.join(dir, 'c.pem'),
    '-days', '1', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
  const calls = [];
  const server = https.createServer({ key: fs.readFileSync(path.join(dir, 'k.pem')), cert: fs.readFileSync(path.join(dir, 'c.pem')) }, (req, res) => {
    let raw = '';
    req.on('data', (chunk) => { raw += chunk; });
    req.on('end', () => {
      calls.push({ url: req.url, raw });
      const reply = (data) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ data })); };
      if (req.url === '/v1/agent/runtime') return reply({ decision_id: 'decision-one', gate_receipt_id: 'gate-one', risk_gate: { allow: true, decision: 'allow', enforced: true, reasons: [] } });
      return reply({ accepted: true });
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const run = async (command, { keyed = true, off = false, entry = 'claude-pre-action-hook', ev = null } = {}) => {
    const home = fs.mkdtempSync(path.join(dir, 'home-'));
    const env = {
      PATH: process.env.PATH, HOME: home, SBT_PASSWD_HOME: path.join(dir, 'pw'), MARROW_AUTO_HOOK: 'true',
      MARROW_BASE_URL: `https://127.0.0.1:${server.address().port}`, NODE_EXTRA_CA_CERTS: path.join(dir, 'c.pem'),
      MARROW_AGENT_ID: 'agent-one', MARROW_SESSION_ID: 'session-one', MARROW_EVENT_SPOOL_PATH: path.join(home, 'spool.json'),
    };
    if (keyed) env.MARROW_API_KEY = `dummy-miss3-${hex(12)}`;
    if (off) env.MARROW_HOOK_COMMAND_TEXT = 'off';
    if (process.env.MISS3_NETGUARD) env.NODE_OPTIONS = `--require ${process.env.MISS3_NETGUARD}`;
    fs.mkdirSync(env.SBT_PASSWD_HOME, { recursive: true, mode: 0o700 });
    calls.length = 0;
    const child = spawn(process.execPath, [path.join(DIST, 'cli.js'), entry], { cwd: home, env });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.stdin.end(JSON.stringify(ev || { session_id: 'session-one', tool_use_id: 'tool-one', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command }, cwd: home }));
    await new Promise((resolve) => child.on('close', resolve));
    const spool = fs.existsSync(env.MARROW_EVENT_SPOOL_PATH) ? fs.readFileSync(env.MARROW_EVENT_SPOOL_PATH, 'utf8') : '';
    const runtime = calls.find((call) => call.url === '/v1/agent/runtime');
    const all = `${stdout}\n${stderr}\n${spool}\n${calls.map((call) => call.raw).join('\n')}`;
    for (const secret of SECRETS) assert.ok(!all.includes(secret), 'COL-12: no dummy secret in any body, event, spool, output or log');
    // Paths and home words never reach a hook message.
    return { stdout, runtime: runtime ? JSON.parse(runtime.raw) : null, urls: calls.map((call) => call.url) };
  };
  try { return await fn(run); } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const decision = (stdout) => { try { return JSON.parse(stdout).hookSpecificOutput?.permissionDecision ?? 'none'; } catch { return 'unparsed'; } };

test('ACC-1 real hook: ship-deploy and AB-ID rows send the text cut; withheld rows send none', { skip: !opensslOk }, async () => {
  await withRecorder(async (run) => {
    const failed = [];
    failed.push(...await collect(ID_SENT, async (id, command) => {
      const result = await run(command);
      const na = result.runtime && result.runtime.normalized_action;
      record(`E2E-${id}`, { runtime: !!result.runtime, sent: typeof na?.tool_input?.command === 'string', truncated: na?.truncated === true, decision: decision(result.stdout) });
      assert.ok(na, `${id}: runtime call made`);
      assert.equal(na.tool_input.command, command, `${id}: text sent`);
      assert.equal(na.tool_input.command_sha256, plainHash(command), id);
      assert.equal(na.truncated, true, id);
      assert.match(na.tool_input.exact_hmac, /^[0-9a-f]{32}$/, id);
    }));
    // Text off and another host: no text, keyed hash over the id (COL-2).
    const offA = await run(ID_SENT['ship-deploy'], { off: true });
    assert.equal(offA.runtime.normalized_action.tool_input.command, undefined);
    assert.equal(offA.runtime.normalized_action.truncated, true);
    const codex = await run('', { entry: 'codex-pre-action-hook', ev: { hookEventName: 'PreToolUse', sessionId: 'codex-session', toolUseId: 'codex-tool', toolName: 'Bash', toolInput: { command: ID_SENT['ship-deploy'] } } });
    if (codex.runtime) assert.equal(codex.runtime.normalized_action.tool_input.command, undefined, 'other host: no text');
    failed.push(...await collect(ID_WITHHELD, async (id, command) => {
      const result = await run(command);
      const na = result.runtime && result.runtime.normalized_action;
      record(`E2E-${id}`, { runtime: !!result.runtime, sent: typeof na?.tool_input?.command === 'string', truncated: na ? na.truncated === true : null, decision: decision(result.stdout) });
      if (na) {
        assert.equal(na.tool_input.command, undefined, `${id}: no text`);
        if (!/^AB-(?:SHAPE-(?:9|10)|VAR-3)$/.test(id)) assert.equal(na.truncated, true, id);
      }
    }));
    assert.deepEqual(failed, []);
  });
});

test('ACC-1 real hook: ctl-disable and AB-ENV rows are held as the same command without the prefix', { skip: !opensslOk }, async () => {
  await withRecorder(async (run) => {
    const failed = [];
    const bare = await run(NPX);
    assert.equal(bare.runtime.action, ROUTE_ACTION);
    failed.push(...await collect(ENV_ROUTES, async (id, command) => {
      const result = await run(command);
      record(`E2E-${id}`, { runtime: !!result.runtime, action_route: result.runtime?.action === ROUTE_ACTION, decision: decision(result.stdout) });
      assert.equal(result.runtime?.action, ROUTE_ACTION, `${id}: security on marrow-control`);
      assert.equal(result.runtime.risk_level, bare.runtime.risk_level, id);
      assert.equal(decision(result.stdout), decision(bare.stdout), `${id}: held as without the prefix`);
    }));
    failed.push(...await collect(NOT_ROUTES, async (id, command) => {
      const result = await run(command);
      record(`E2E-${id}`, { runtime: !!result.runtime, action_route: result.runtime?.action === ROUTE_ACTION, decision: decision(result.stdout) });
      assert.notEqual(result.runtime?.action, ROUTE_ACTION, id);
    }));
    assert.deepEqual(failed, []);
  });
});

test('ACC-1 real hook: cred-ls and AB-LS rows make the runtime call; keyless answers as 3.9.114 (as a plain local listing)', { skip: !opensslOk }, async () => {
  await withRecorder(async (run) => {
    const failed = [];
    const keylessLocal = await run('ls /tmp', { keyed: false });
    assert.deepEqual(keylessLocal.urls, []);
    failed.push(...await collect(LS_SERVER, async (id, command) => {
      const result = await run(command);
      const keyless = await run(command, { keyed: false });
      record(`E2E-${id}`, { runtime: !!result.runtime, decision: decision(result.stdout), keyless_same: keyless.stdout === keylessLocal.stdout, keyless_calls: keyless.urls.length });
      assert.ok(result.runtime, `${id}: runtime call made`);
      // tree and an assignment segment are server rows on 3.9.114 already (a protected secret word): unchanged, in the table.
      if (BASE_SERVER.has(id)) return;
      assert.equal(decision(result.stdout), 'none', `${id}: no new hold (the server allowed)`);
      assert.equal(keyless.stdout, keylessLocal.stdout, `${id}: keyless as 3.9.114`);
      assert.deepEqual(keyless.urls, [], `${id}: keyless makes no call`);
    }));
    failed.push(...await collect(LS_LOCAL, async (id, command) => {
      const result = await run(command);
      record(`E2E-${id}`, { runtime: !!result.runtime, decision: decision(result.stdout) });
      assert.equal(result.runtime, null, `${id}: answered locally as 3.9.114`);
    }));
    assert.deepEqual(failed, []);
  });
});
