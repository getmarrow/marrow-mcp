'use strict';

// N5 hotfix: (a) the first word of a pipeline stage that feeds a password program is withheld unless it is a known
// program; (b) a truncated action's text hash is a per-install MAC, never a plain hash. Dummy values are generated
// at runtime; nothing here prints one.
const assert = require('node:assert/strict');
const test = require('node:test');
const { createHash, randomBytes } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { normalizedHookAction, normalizeShellCommand } = require('../dist/normalized-action.js');
const tables = require('../dist/seatbelt/tables.js');
const { COLLISION_CASES } = require('./support/normalized-collision-cases.cjs');
const keyedHash = require('./support/keyed-text-hash.cjs');

const ROOT = path.join(__dirname, '..');
const FAKE = path.join(__dirname, 'support', 'passwd-home-fake.cjs');
const SALT_A = randomBytes(32);
const SALT_B = randomBytes(32);
const HASH_VERSION = 'marrow-normalized-action-v3';
const sha256 = (text) => createHash('sha256').update(text).digest('hex');
const bash = (command, options = {}) => normalizedHookAction({ tool_name: 'Bash', tool_input: { command } }, { salt: SALT_A, ...options });
// What an attacker who knows the algorithm and guesses the value computes for a plain Bash command.
const plainShellHash = (command) => sha256(`${HASH_VERSION}\nshell\n${normalizeShellCommand(command).text}`);
// What this install sends for the same command: the per-install keyed hash (SALT_A is the test seam key).
const keyedShellHash = (command, salt = SALT_A) => keyedHash.shellMac(salt, 'Bash', normalizeShellCommand(command).text);

const ALPHABETS = {
  hex: '0123456789abcdef',
  alnum: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
  b64url: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_',
};
function dummy(shape, length) {
  const alphabet = ALPHABETS[shape];
  return Array.from(randomBytes(length), (byte) => alphabet[byte % alphabet.length]).join('');
}
const SHAPES = [];
for (const shape of Object.keys(ALPHABETS)) for (const length of [8, 16, 40]) SHAPES.push([shape, length]);

function reaches(action, value) {
  const text = JSON.stringify(action);
  const lower = value.toLowerCase();
  if (text.includes(value) || text.toLowerCase().includes(lower)) return true;
  for (let i = 0; i + 8 <= value.length; i += 1) if (text.toLowerCase().includes(lower.slice(i, i + 8))) return true;
  return false;
}

test('(a) first word of a stage that feeds a password program is withheld: every shape, quoting and host form', () => {
  for (const [shape, length] of SHAPES) {
    const value = dummy(shape, length);
    // `nested`: inside bash -c / pwsh -c / cmd /c the inner programs are not listed at all (as on base); the text is still hashed.
    const forms = [
      [`"${value}" | smbpasswd -s -a u1`, false], [`'${value}' | smbpasswd -s -a u1`, false], [`${value} | smbpasswd -s -a u1`, false],
      [`${value} | htpasswd -i site u1`, false], [`cd /tmp && "${value}" | smbpasswd -s -a u1`, false], [`"${value}" | tr a b | smbpasswd -s`, false],
      [`"${value}" |& smbpasswd -s`, false], [`bash -c '"${value}" | smbpasswd -s -a u1'`, true],
    ];
    for (const [command, nested] of forms) {
      for (const label of ['Bash', 'PowerShell', 'Monitor', 'Shell']) {
        const action = normalizedHookAction({ tool_name: label, tool_input: { command } }, { salt: SALT_A });
        // The whole action is scanned (programs and the keyed hashes): it is what the wire body carries.
        assert.equal(reaches(action, value), false, `${label}: the value reached the action for ${shape}/${length}`);
        assert.equal(action.truncated, true, `${label}: a withheld word never binds`);
        if (!nested) assert.ok(action.programs.includes('unlisted-feeder'), `${label}: marker present`);
      }
    }
  }
});

test('N1 and N5 forms (the redactor does not see the value): bindable, but the hash is keyed per install, never the plain hash; no clear value reaches programs[]', () => {
  // The redactor does not see the value (sudo -u root parses `root` as the program; cmd /c and pwsh -c keep their quoted text as one word),
  // so the action stays bindable. Build 2: its hash is the per-install keyed MAC (SPEC section 10.2), so a guessed value cannot be tested offline.
  const value = dummy('alnum', 12);
  for (const command of [`sudo -u root smbpasswd -a u1 ${value}`, `cmd /c "${value} | smbpasswd -s -a u1"`, `pwsh -c '"${value}" | smbpasswd -s -a u1'`]) {
    const action = bash(command);
    assert.equal(action.truncated, undefined, command.split(' ')[0]);
    assert.equal(reaches({ programs: action.programs }, value), false, 'programs[] holds no clear or case-folded value');
    assert.equal(action.tool_input.command_sha256, keyedShellHash(command), 'the per-install keyed hash');
    assert.notEqual(action.tool_input.command_sha256, plainShellHash(command), 'never the plain hash an attacker can compute');
    assert.notEqual(action.tool_input.command_sha256, keyedShellHash(command, SALT_B), 'differs per install');
    assert.notEqual(action.tool_input.command_sha256, keyedShellHash(command.split(value).join(dummy('alnum', 12))), 'the same install still tells two values apart (keyed)');
  }
});

test('(a) a 40-hex word (key-shaped) never reached programs[]; it is still withheld and the action is still cut', () => {
  const value = dummy('hex', 40);
  const action = bash(`"${value}" | smbpasswd -s -a u1`);
  assert.equal(reaches(action, value), false);
  assert.equal(action.truncated, true);
});

test('(a) known programs keep their name and their base behaviour (not cut, same programs[])', () => {
  const kept = [
    ['git push --force | smbpasswd -s', ['git', 'smbpasswd']], ['npm publish | smbpasswd -s', ['npm', 'smbpasswd']],
    ['wrangler deploy --env production | htpasswd -i site u1', ['wrangler', 'htpasswd']], ['cat .env | smbpasswd -s', ['cat', 'smbpasswd']],
    ['rm -rf x | smbpasswd -s', ['rm', 'smbpasswd']], ['cat x | smbpasswd -s', ['cat', 'smbpasswd']], ['cat | smbpasswd -s', ['cat', 'smbpasswd']],
    ['yes | smbpasswd -s', ['yes', 'smbpasswd']], ['CAT x | smbpasswd -s', ['cat', 'smbpasswd']], ['/bin/cat x | smbpasswd -s', ['cat', 'smbpasswd']],
    ['X=1 cat | smbpasswd -s', ['cat', 'smbpasswd']], ['terraform apply | smbpasswd -s', ['terraform', 'smbpasswd']],
    ['git.exe push --force | smbpasswd -s', ['git.exe', 'smbpasswd']], ['npm.cmd publish | smbpasswd -s', ['npm.cmd', 'smbpasswd']],
    ['WRANGLER.EXE deploy --env production | smbpasswd -s', ['wrangler.exe', 'smbpasswd']],
  ];
  for (const [command, programs] of kept) {
    const action = bash(command);
    assert.deepEqual(action.programs, programs, command);
    assert.equal(action.truncated, undefined, `${command}: bindable as on base`);
    assert.equal(action.tool_input.command_sha256, keyedShellHash(command), `${command}: keyed hash (bindable on this install)`);
  }
});

test('(a) a lone word is a value unless it is exactly a stdin producer; case games do not leak a case-folded value', () => {
  for (const word of ['Cat', 'CAT', 'Yes', '/bin/cat', './cat', 'whoami', 'date', 'test', 'echo', 'git', 'rm', 'git.exe', 'cat.exe']) {
    const action = bash(`${word} | smbpasswd -s -a u1`);
    assert.ok(!(action.programs || []).some((p) => p === word.toLowerCase().replace(/^.*\//, '')), `${word}: withheld`);
    assert.ok(action.programs.includes('unlisted-feeder'), word);
    assert.equal(action.truncated, true, word);
  }
  // Not a feeder stage: unchanged.
  assert.deepEqual(bash('Cat x && smbpasswd -s').programs, ['cat', 'smbpasswd']);
  assert.deepEqual(bash('whoami').programs, ['whoami']);
});

test('(a) every program the seatbelt tables know keeps its name when it feeds a password program (parity)', () => {
  const names = [...tables.KNOWN_COMMANDS, ...tables.INERT_PROGRAMS].filter((name) => /^[a-z0-9][a-z0-9._+-]{0,63}$/.test(name));
  assert.ok(names.length > 300);
  for (const name of names) {
    const action = bash(`${name} x | smbpasswd -s -a u1`);
    // A name that parses as a wrapper (sudo, env, time ...) is read through to the next word, as on base.
    const base = normalizeShellCommand(`${name} x | smbpasswd -s -a u1`);
    const baseProgram = base.programs[0];
    if (/^[a-z0-9][a-z0-9._+-]{0,63}$/.test(baseProgram || '')) {
      assert.ok(action.programs.includes(baseProgram) || baseProgram === undefined, `${name}: table name lost from programs[] (add it to KNOWN_FEEDER_PROGRAMS)`);
    }
  }
});

test('(a) the marker is constant: nothing about the withheld word is in programs[]', () => {
  const first = bash(`"${dummy('alnum', 12)}" | smbpasswd -s -a u1`);
  const second = bash(`"${dummy('alnum', 31)}" | smbpasswd -s -a u1`);
  assert.deepEqual(first.programs, ['unlisted-feeder', 'smbpasswd']);
  assert.deepEqual(second.programs, first.programs);
  assert.match(first.programs[0], /^[a-z0-9][a-z0-9._+-]{0,63}$/);
});

test('(b) a truncated action carries a keyed text hash: not the plain hash, 64 hex, stable per key, different per key', () => {
  const command = `"${dummy('alnum', 12)}" | smbpasswd -s -a u1`;
  const a1 = bash(command);
  const a2 = bash(command);
  const b = bash(command, { salt: SALT_B });
  assert.match(a1.tool_input.command_sha256, /^[0-9a-f]{64}$/);
  assert.match(a1.tool_input.exact_hmac, /^[0-9a-f]{32}$/);
  assert.notEqual(a1.tool_input.command_sha256, plainShellHash(command), 'the attacker formula does not reproduce the wire value');
  assert.equal(a1.tool_input.command_sha256, a2.tool_input.command_sha256);
  assert.equal(a1.tool_input.exact_hmac, a2.tool_input.exact_hmac);
  assert.notEqual(a1.tool_input.command_sha256, b.tool_input.command_sha256, 'another install, another value');
  assert.notEqual(a1.tool_input.exact_hmac, b.tool_input.exact_hmac);
  // Domain separation: the text MAC is not the exact MAC (or a prefix of it).
  assert.notEqual(a1.tool_input.command_sha256.slice(0, 32), a1.tool_input.exact_hmac);
});

test('(b) no usable key: a random value that matches nothing (never the plain hash), the action is still cut', () => {
  const command = `"${dummy('hex', 16)}" | smbpasswd -s -a u1`;
  for (const salt of [null, Buffer.alloc(8, 1)]) {
    const one = bash(command, { salt });
    const two = bash(command, { salt });
    assert.equal(one.truncated, true);
    assert.match(one.tool_input.command_sha256, /^[0-9a-f]{64}$/);
    assert.notEqual(one.tool_input.command_sha256, plainShellHash(command));
    assert.notEqual(one.tool_input.command_sha256, two.tool_input.command_sha256, 'a nonce per call');
    assert.notEqual(one.tool_input.exact_hmac, two.tool_input.exact_hmac);
  }
});

test('(b) a bindable action is bindable still, with a per-install keyed hash (shell, mcp, edit, other)', () => {
  assert.equal(bash('ls -la').tool_input.command_sha256, keyedShellHash('ls -la'));
  assert.equal(bash('git push --force | smbpasswd -s').tool_input.command_sha256, keyedShellHash('git push --force | smbpasswd -s'));
  for (const [tool, input, kind] of [['mcp__x__run', { a: 1 }, 'mcp'], ['Edit', { file_path: '/w/a.txt', new_string: 'hello' }, 'edit'], ['Agent', { prompt: 'summarize the readme' }, 'other']]) {
    const action = normalizedHookAction({ tool_name: tool, tool_input: input }, { salt: SALT_A });
    assert.equal(action.truncated, undefined, tool);
    const json = JSON.stringify(Object.fromEntries(Object.entries(input).sort()));
    assert.equal(action.tool_input.input_sha256, keyedHash.inputMac(SALT_A, kind, tool, json), tool);
    assert.notEqual(action.tool_input.input_sha256, sha256(`${HASH_VERSION}\ninput\n${json}`), `${tool}: never the plain hash`);
    assert.equal(action.tool_input.exact_hmac, undefined, tool);
  }
});

test('(b) a truncated tool input (mcp, edit, other) is keyed too (the Agent and Edit input_sha256)', () => {
  const token = dummy('alnum', 24);
  for (const [tool, input] of [['mcp__x__run', { token, op: 'a' }], ['Agent', { prompt: 'x', api_key: token }], ['Edit', { file_path: '/w/a.txt', new_string: 'k', password: token }]]) {
    const action = normalizedHookAction({ tool_name: tool, tool_input: input }, { salt: SALT_A });
    assert.equal(action.truncated, true, tool);
    const other = normalizedHookAction({ tool_name: tool, tool_input: input }, { salt: SALT_B });
    assert.match(action.tool_input.input_sha256, /^[0-9a-f]{64}$/);
    assert.notEqual(action.tool_input.input_sha256, other.tool_input.input_sha256, `${tool}: keyed per install`);
    const none = normalizedHookAction({ tool_name: tool, tool_input: input }, { salt: null });
    assert.notEqual(none.tool_input.input_sha256, normalizedHookAction({ tool_name: tool, tool_input: input }, { salt: null }).tool_input.input_sha256, `${tool}: nonce without a key`);
  }
});

test('collisions: actions that differ outside the secret get different keys; a keyed hash keeps every pair apart', () => {
  const strip = (action) => JSON.stringify(action);
  const pairs = [
    ['rm -rf x | smbpasswd -s', 'cat x | smbpasswd -s'],
    ['foo1 x | smbpasswd -s', 'foo2 x | smbpasswd -s'],
    ['"abcDEF12" | smbpasswd -s -a u1', '"abcDEF12" | smbpasswd -s -a u2'],
    ['"abcDEF12" | smbpasswd -s -a u1', '"abcDEF12" | htpasswd -i u1'],
    ['"abcDEF12" | smbpasswd -s -a u1', '"abcDEF12" | smbpasswd -s -a u1 && git push --force'],
    ['git push --force | smbpasswd -s', 'git push | smbpasswd -s'],
    ['"abcDEF12" | smbpasswd -s -a u1', 'cd /x && "abcDEF12" | smbpasswd -s -a u1'],
    ['"abcDEF12" | smbpasswd -s -a u1', 'bash -c \'"abcDEF12" | smbpasswd -s -a u1\''],
    ['"abcDEF12" | smbpasswd -s -a u1', '"abcDEF12" |& smbpasswd -s -a u1'],
  ];
  // `-a u1` vs `-a u2`: the redactor withholds the user name of a password program as it does on base, so the text
  // hash is equal and only exact_hmac (keyed, exact form) tells them apart; nothing here makes that worse.
  const userNamePair = (left, right) => left.endsWith('-a u1') && right.endsWith('-a u2');
  for (const [left, right] of pairs) {
    const a = bash(left);
    const b = bash(right);
    assert.notEqual(strip(a), strip(b), `${left} vs ${right}`);
    if (a.truncated && b.truncated) assert.notEqual(a.tool_input.exact_hmac, b.tool_input.exact_hmac, `${left} vs ${right}: exact_hmac`);
    if (a.truncated && b.truncated && a.tool_input.command_sha256 === b.tool_input.command_sha256 && !userNamePair(left, right)) assert.fail(`${left} vs ${right}: command_sha256 collides`);
  }
  assert.equal(bash('"abcDEF12" | smbpasswd -s -a u1').tool_input.command_sha256, bash('"abcDEF12" | smbpasswd -s -a u2').tool_input.command_sha256, 'the same on base (pre-existing)');
  assert.equal(normalizeShellCommand('"abcDEF12" | smbpasswd -s -a u1').text, normalizeShellCommand('"abcDEF12" | smbpasswd -s -a u2').text);
  // Only the value differs: a withheld first word is part of the hashed text, so these two DIFFER (it is not a recognised secret).
  const x = bash(`"${dummy('alnum', 12)}" | smbpasswd -s -a u1`);
  const y = bash(`"${dummy('alnum', 12)}" | smbpasswd -s -a u1`);
  assert.deepEqual(x.programs, y.programs);
  assert.notEqual(x.tool_input.command_sha256, y.tool_input.command_sha256);
});

test('collision matrix (shared cases): truncated actions are keyed, keys of differing actions stay different, the secret never appears', () => {
  for (const testCase of COLLISION_CASES) {
    const s1 = `pw-${randomBytes(6).toString('hex')}`;
    const s2 = `pw-${randomBytes(6).toString('hex')}`;
    const make = (input) => (input.kind === 'mcp'
      ? normalizedHookAction({ tool_name: input.tool, tool_input: input.input }, { salt: SALT_A })
      : normalizedHookAction({ tool_name: 'Bash', tool_input: { command: input.command } }, { salt: SALT_A }));
    const inA = testCase.build(s1, testCase.values[0]);
    const first = make(inA);
    const second = make(testCase.build(s1, testCase.values[1]));
    const other = make(testCase.build(s2, testCase.values[0]));
    const sent = (action) => JSON.stringify({ ...action, tool_input: { ...action.tool_input, exact_hmac: undefined } });
    assert.equal(JSON.stringify(first).includes(s1), false, testCase.path);
    if (testCase.secretOnly) assert.equal(sent(first), sent(second), `${testCase.path}: the same action`);
    else if (!testCase.afterEqual) assert.notEqual(sent(first), sent(second), `${testCase.path}: differs after the secret`);
    assert.equal(sent(first), sent(other), `${testCase.path}: only the secret differs, the key stays equal`);
    if (first.truncated && inA.kind !== 'mcp') assert.notEqual(first.tool_input.command_sha256, plainShellHash(inA.command), `${testCase.path}: keyed`);
  }
});

test('forged client fields change nothing: the normalizer sets truncated, programs and hashes itself', () => {
  const command = `"${dummy('alnum', 12)}" | smbpasswd -s -a u1`;
  const plain = normalizedHookAction({ tool_name: 'Bash', tool_input: { command } }, { salt: SALT_A });
  const forged = normalizedHookAction({
    tool_name: 'Bash', truncated: false, tool_kind: 'other', programs: ['git'], risk_level: 'low', approved: true,
    tool_input: { command, truncated: false, programs: ['git'], exact_hmac: '0'.repeat(32), command_sha256: '0'.repeat(64), risk_level: 'low', read_only: true },
  }, { salt: SALT_A });
  assert.deepEqual(forged, plain);
  assert.equal(forged.truncated, true);
});

test('PowerShell command and script with the same text still share one key (by design); Monitor and Bash differ', () => {
  const command = `"${dummy('alnum', 12)}" | smbpasswd -s -a u1`;
  const ps1 = normalizedHookAction({ tool_name: 'PowerShell', tool_input: { command } }, { salt: SALT_A });
  const ps2 = normalizedHookAction({ tool_name: 'PowerShell', tool_input: { script: command } }, { salt: SALT_A });
  const mon = normalizedHookAction({ tool_name: 'Monitor', tool_input: { command } }, { salt: SALT_A });
  const sh = bash(command);
  assert.equal(JSON.stringify(ps1), JSON.stringify(ps2));
  assert.notEqual(ps1.tool_input.command_sha256, mon.tool_input.command_sha256);
  assert.notEqual(ps1.tool_input.command_sha256, sh.tool_input.command_sha256);
  assert.notEqual(mon.tool_input.command_sha256, sh.tool_input.command_sha256);
});

// ---- key store states: a child process per state (the device salt is cached per process) ----

const CHILD = `
const { normalizedHookAction } = require(${JSON.stringify(path.join(ROOT, 'dist/normalized-action.js'))});
const command = process.argv[1];
const a = normalizedHookAction({ tool_name: 'Bash', tool_input: { command } }, {});
const b = normalizedHookAction({ tool_name: 'Bash', tool_input: { command } }, {});
process.stdout.write(JSON.stringify({ sha: a.tool_input.command_sha256, hmac: a.tool_input.exact_hmac, sha2: b.tool_input.command_sha256, truncated: a.truncated === true }));
`;

function runChild(passwdHome, command) {
  const result = spawnSync(process.execPath, ['-e', CHILD, command], {
    env: { PATH: process.env.PATH, HOME: passwdHome, SBT_PASSWD_HOME: passwdHome },
    encoding: 'utf8', timeout: 20_000,
  });
  assert.equal(result.status, 0, 'child exit');
  assert.equal(result.stdout.includes('mrw_'), false);
  return { out: JSON.parse(result.stdout), stderr: result.stderr };
}

function freshHome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-n5-'));
  fs.chmodSync(dir, 0o700);
  return dir;
}

function seatbeltDir(home) {
  const marrow = path.join(home, '.marrow');
  const dir = path.join(marrow, 'seatbelt');
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(marrow, 0o700);
  fs.chmodSync(dir, 0o700);
  return dir;
}

const PF = `"${dummy('alnum', 14)}" | smbpasswd -s -a u1`;

test('key store: missing -> created 0600 in a 0700 dir; stable across processes; never printed', () => {
  const home = freshHome();
  const first = runChild(home, PF);
  const second = runChild(home, PF);
  const salt = path.join(home, '.marrow', 'seatbelt', 'salt');
  const stat = fs.statSync(salt);
  assert.equal(stat.size, 32);
  assert.equal(stat.mode & 0o077, 0);
  assert.equal(fs.statSync(path.dirname(salt)).mode & 0o077, 0);
  assert.equal(first.out.sha, second.out.sha);
  assert.equal(first.out.sha, first.out.sha2);
  assert.notEqual(first.out.sha, plainShellHash(PF));
  const key = fs.readFileSync(salt);
  for (const text of [JSON.stringify(first.out), first.stderr]) {
    assert.equal(text.includes(key.toString('hex')) || text.includes(key.toString('base64')) || text.includes(key.toString('base64url')), false);
  }
  // Rotation: the owner removes the file; the next start makes a new key and every keyed value changes.
  fs.unlinkSync(salt);
  const rotated = runChild(home, PF);
  assert.notEqual(rotated.out.sha, first.out.sha);
  assert.notEqual(rotated.out.hmac, first.out.hmac);
  // Another install: another passwd home, another value.
  const other = runChild(freshHome(), PF);
  assert.notEqual(other.out.sha, first.out.sha);
});

test('key store: concurrent first start: one key, every process agrees', () => {
  const home = freshHome();
  const script = `
    const { spawn } = require('node:child_process');
    const code = ${JSON.stringify(CHILD)};
    const runs = Array.from({ length: 8 }, () => new Promise((resolve) => {
      const child = spawn(process.execPath, ['-e', code, process.argv[1]], { env: { PATH: process.env.PATH, HOME: ${JSON.stringify(home)}, SBT_PASSWD_HOME: ${JSON.stringify(home)}, NODE_OPTIONS: ${JSON.stringify(`--require=${FAKE}`)} }, stdio: ['ignore', 'pipe', 'pipe'] });
      let out = '';
      child.stdout.on('data', (chunk) => { out += chunk; });
      child.on('close', () => resolve(out));
    }));
    Promise.all(runs).then((all) => process.stdout.write(JSON.stringify(all)));
  `;
  const result = spawnSync(process.execPath, ['-e', script, PF], {
    env: { PATH: process.env.PATH, HOME: home, SBT_PASSWD_HOME: home }, encoding: 'utf8', timeout: 60_000,
  });
  assert.equal(result.status, 0);
  const outs = JSON.parse(result.stdout).map((text) => JSON.parse(text));
  assert.equal(outs.length, 8);
  assert.equal(new Set(outs.map((o) => o.sha)).size, 1, 'one key for every process');
  assert.equal(new Set(outs.map((o) => o.hmac)).size, 1);
  const leftovers = fs.readdirSync(path.join(home, '.marrow', 'seatbelt')).filter((name) => name.startsWith('.salt.'));
  assert.deepEqual(leftovers, []);
});

test('key store: unsafe or unreadable device key -> the approval-state fallback key (stable); with the state unusable too -> a nonce per call (asked again), never the plain hash', () => {
  const states = {
    'wrong mode (group-readable)': (dir) => { fs.writeFileSync(path.join(dir, 'salt'), randomBytes(32), { mode: 0o644 }); fs.chmodSync(path.join(dir, 'salt'), 0o644); },
    'corrupt (short)': (dir) => { fs.writeFileSync(path.join(dir, 'salt'), randomBytes(16), { mode: 0o600 }); },
    'corrupt (long)': (dir) => { fs.writeFileSync(path.join(dir, 'salt'), randomBytes(64), { mode: 0o600 }); },
    'symlink': (dir) => { const target = path.join(dir, '..', 'real-salt'); fs.writeFileSync(target, randomBytes(32), { mode: 0o600 }); fs.symlinkSync(target, path.join(dir, 'salt')); },
    'unreadable': (dir) => { fs.writeFileSync(path.join(dir, 'salt'), randomBytes(32), { mode: 0o000 }); fs.chmodSync(path.join(dir, 'salt'), 0o000); },
    'directory unsafe (group-writable)': (dir) => { fs.writeFileSync(path.join(dir, 'salt'), randomBytes(32), { mode: 0o600 }); fs.chmodSync(dir, 0o770); },
  };
  for (const [name, make] of Object.entries(states)) {
    const home = freshHome();
    make(seatbeltDir(home));
    const first = runChild(home, PF);
    assert.equal(first.out.truncated, true, name);
    assert.match(first.out.sha, /^[0-9a-f]{64}$/, name);
    assert.notEqual(first.out.sha, plainShellHash(PF), `${name}: never the plain hash`);
    assert.equal(first.out.sha, first.out.sha2, `${name}: stable inside the process (fallback key)`);
    assert.equal(runChild(home, PF).out.sha, first.out.sha, `${name}: stable across processes (fallback key)`);
    const blocked = freshHome();
    make(seatbeltDir(blocked));
    fs.writeFileSync(path.join(blocked, '.marrow', 'host-approvals'), 'x', { mode: 0o600 });
    const { out } = runChild(blocked, PF);
    assert.equal(out.truncated, true, name);
    assert.match(out.sha, /^[0-9a-f]{64}$/, name);
    assert.notEqual(out.sha, plainShellHash(PF), `${name}: never the plain hash`);
    assert.notEqual(out.sha, out.sha2, `${name}: a nonce per call`);
    assert.notEqual(runChild(blocked, PF).out.sha, out.sha, `${name}: nothing matches across processes`);
  }
});

test('key store: read-only home (no key can be made) -> nonce, fail closed', () => {
  const home = freshHome();
  fs.chmodSync(home, 0o500);
  try {
    const { out } = runChild(home, PF);
    assert.equal(out.truncated, true);
    assert.notEqual(out.sha, plainShellHash(PF));
    assert.notEqual(out.sha, out.sha2);
    assert.equal(fs.existsSync(path.join(home, '.marrow')), false, 'nothing was created');
  } finally {
    fs.chmodSync(home, 0o700);
  }
});
