'use strict';

// 3.9.106 hotfix, Phase A: the Windows private-state proof (spec A1, with the stage-1 audit rulings).
// Rows: U-G (grammar), U-C (chain and canonical), U-A (spawn and output), U-S (binary descriptor). Linux, no
// Windows needed: every OS call goes through the injected deps of test/support/win-private-world.cjs.
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
  WIN_ACL_ENCODED,
  WIN_ACL_SCRIPT,
  ensureWindowsPrivateState,
  evaluateDescriptor,
  proveWindowsPrivate,
  validWindowsPath,
  verifyWindowsPrivateState,
} = require('../dist/win-private-state.js');
const { makeWorld, sd, sdBuffer, aceBuffer, errno, SID, FULL, INHERIT } = require('./support/win-private-world.cjs');

const MARROW = { rel: '.marrow', kind: 'dir', policy: 'no_write_by_others' };
const GUARD = { rel: '.marrow\\session-loop-guard', kind: 'dir', policy: 'no_access_by_others' };
const STATE = { rel: '.marrow\\session-loop-guard\\state.json', kind: 'file', policy: 'no_access_by_others' };
const OBJECTS = [MARROW, GUARD];
const prove = (world, objects = OBJECTS) => proveWindowsPrivate({ home: world.home, objects }, world.deps);
const ensure = (world) => ensureWindowsPrivateState(world.home, world.deps);
const reason = (result) => (result.ok ? 'ok' : result.reason);

// ---- U-G -------------------------------------------------------------------------------------

test('U-G1 to G3: ordinary, lower-case and 8.3 paths are accepted', () => {
  for (const good of ['C:\\Users\\buu', 'c:\\users\\buu', 'C:\\Users\\RUNNER~1\\AppData\\Local\\Temp\\h', 'D:\\a']) assert.equal(validWindowsPath(good), true, good);
});

test('U-G4: every alias, device, UNC, relative, stream and odd form is refused', () => {
  const bad = ['C:foo', '\\Users\\x', '\\\\srv\\s\\x', '\\\\?\\C:\\x', '\\\\.\\C:\\x', '//?/C:/x', '/c/Users/x', 'C:/Users/x',
    'C:\\Users\\x\\', 'C:\\', 'C:\\Users\\..\\x', 'C:\\Users\\.\\x', 'C:\\Users\\x.', 'C:\\Users\\x ', 'C:\\Users\\x:s', 'C:\\Users\\CON\\x',
    'C:\\Users\\nul.txt', 'C:\\Us"ers', 'C:\\Users\\a\u0001b', `C:\\${'a'.repeat(238)}`, 'C:\\Users\\\\x', 'C:\\Users\\a?b', 'C:\\Users\\a*b',
    'C:\\Users\\a<b', 'C:\\Users\\a|b', 'C:\\Users\\com1.txt', 'C:\\Users\\Aux', 'C:\\Users\\LPT9', '~', 'x', 'C:\\Users\\nul .txt', '', undefined, null, 5, {}];
  for (const value of bad) assert.equal(validWindowsPath(value), false, String(value));
  assert.equal(validWindowsPath(`C:\\${'a'.repeat(237)}`), true);
});

test('U-G5 and G9: HOME and the rest of the process env are never read, only SystemRoot and windir', () => {
  const world = makeWorld({ env: { HOME: '/c/Users/x', MARROW_API_KEY: 'x', MARROW_SEATBELT_STRICT: '1' } });
  const result = ensure(world);
  assert.equal(result.ok, true);
  assert.deepEqual([...world.reads].sort(), ['SystemRoot', 'windir']);
  const source = fs.readFileSync(path.join(__dirname, '..', 'dist', 'win-private-state.js'), 'utf8');
  assert.doesNotMatch(source, /\.HOME\b|\['HOME'\]|USERPROFILE|process\.env\.[A-Z_]+/);
});

test('U-G6: the platform comes only from the deps parameter, never from the environment', () => {
  const world = makeWorld({ platform: 'linux', env: { OS: 'Windows_NT' } });
  assert.equal(reason(ensure(world)), 'platform');
  assert.equal(reason(prove(world)), 'platform');
  assert.equal(world.calls.spawn.length, 0);
  assert.equal(world.calls.mkdir.length, 0);
});

test('U-G8: MARROW_SEATBELT_STRICT has no effect on the proof', () => {
  const plain = makeWorld();
  const strict = makeWorld({ env: { MARROW_SEATBELT_STRICT: '1' } });
  assert.deepEqual(ensure(strict), ensure(plain));
  const bad = makeWorld({ env: { MARROW_SEATBELT_STRICT: '0' } });
  bad.setAcl(`${bad.home}\\.marrow`, sd({ extra: [{ sid: 'BU', mask: FULL, flags: INHERIT }] }));
  assert.equal(reason(ensure(bad)), 'acl');
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'win-private-state.ts'), 'utf8');
  assert.doesNotMatch(source, /SEATBELT_STRICT|MARROW_API|MARROW_KEY/);
  assert.equal((source.match(/process\.env/g) || []).length, 1, 'process.env is read once, in the production deps, and nowhere else');
});

// ---- U-C -------------------------------------------------------------------------------------

test('U-C1: a link at any level of the chain is refused', () => {
  const levels = ['C:\\Users', 'C:\\Users\\buu', 'C:\\Users\\buu\\.marrow', 'C:\\Users\\buu\\.marrow\\session-loop-guard'];
  for (const level of levels) {
    const world = makeWorld();
    world.set(level, { kind: 'link' });
    assert.equal(reason(ensure(world)), 'chain', level);
    assert.equal(world.calls.spawn.length, 0, level);
  }
  const world = makeWorld({ state: true });
  world.set(`${world.home}\\.marrow\\session-loop-guard\\state.json`, { kind: 'link' });
  assert.equal(reason(ensure(world)), 'chain');
  // a file where a directory belongs
  const odd = makeWorld();
  odd.set(`${odd.home}\\.marrow`, { kind: 'file' });
  assert.equal(reason(ensure(odd)), 'chain');
});

test('U-C2 and C3: a UNC canonical path, or a different component count, is refused', () => {
  const unc = makeWorld();
  unc.canon.set(unc.key(unc.home), '\\\\srv\\share\\buu');
  assert.equal(reason(ensure(unc)), 'canonical');
  const shorter = makeWorld();
  shorter.canon.set(shorter.key(shorter.home), 'C:\\buu');
  assert.equal(reason(ensure(shorter)), 'canonical');
  const longer = makeWorld();
  longer.canon.set(longer.key(`${longer.home}\\.marrow`), `${longer.home}\\x\\.marrow`);
  assert.equal(reason(ensure(longer)), 'canonical');
  const device = makeWorld();
  device.canon.set(device.key(device.home), '\\\\?\\C:\\Users\\buu');
  assert.equal(reason(ensure(device)), 'canonical');
});

test('U-C8 and AB26: a folder that lstat shows as ordinary but resolves elsewhere, or sits on another volume, is refused', () => {
  const sibling = makeWorld();
  sibling.addDirs(`${sibling.home}\\x`);
  sibling.canon.set(sibling.key(`${sibling.home}\\.marrow`), `${sibling.home}\\x`);
  assert.equal(reason(ensure(sibling)), 'canonical', 'a volume-GUID junction to a sibling inside the home');
  const elsewhere = makeWorld();
  elsewhere.canon.set(elsewhere.key(`${elsewhere.home}\\.marrow`), 'D:\\Users\\buu\\.marrow');
  assert.equal(reason(ensure(elsewhere)), 'canonical', 'same component count, another volume');
  const parentRedirect = makeWorld();
  parentRedirect.canon.set(parentRedirect.key('C:\\Users'), 'C:\\Other');
  assert.equal(reason(ensure(parentRedirect)), 'canonical', 'C:\\Users resolves to C:\\Other');
  const mount = makeWorld();
  mount.set(`${mount.home}\\.marrow`, { dev: 99n });
  assert.equal(reason(ensure(mount)), 'chain', 'a volume mount point: another dev inside the chain');
  const tilde = makeWorld({ home: 'C:\\Users\\a~b' });
  tilde.addDirs('C:\\Users\\other\\.marrow\\session-loop-guard');
  tilde.addDirs('C:\\Users\\other\\AppData\\Local\\Temp');
  tilde.canon.set(tilde.key('C:\\Users\\a~b'), 'C:\\Users\\other');
  assert.equal(reason(ensure(tilde)), 'canonical', 'a tilde that is not an 8.3 NAME~1 form is just a redirect');
  const odd = makeWorld();
  odd.set(`${odd.home}\\.marrow`, { kind: 'file' });
  assert.equal(reason(ensure(odd)), 'chain');
});

test('U-C2 and C3: a UNC canonical path, or a different component count, is refused', () => {
  const unc = makeWorld();
  unc.canon.set(unc.key(unc.home), '\\\\srv\\share\\buu');
  assert.equal(reason(ensure(unc)), 'canonical');
  const shorter = makeWorld();
  shorter.canon.set(shorter.key(shorter.home), 'C:\\buu');
  assert.equal(reason(ensure(shorter)), 'canonical');
  const longer = makeWorld();
  longer.canon.set(longer.key(`${longer.home}\\.marrow`), `${longer.home}\\x\\.marrow`);
  assert.equal(reason(ensure(longer)), 'canonical');
  const device = makeWorld();
  device.canon.set(device.key(device.home), '\\\\?\\C:\\Users\\buu');
  assert.equal(reason(ensure(device)), 'canonical');
});

test('U-C8 and AB26: a folder that lstat shows as ordinary but resolves elsewhere, or sits on another volume, is refused', () => {
  const sibling = makeWorld();
  sibling.addDirs(`${sibling.home}\\x`);
  sibling.canon.set(sibling.key(`${sibling.home}\\.marrow`), `${sibling.home}\\x`);
  assert.equal(reason(ensure(sibling)), 'canonical', 'a volume-GUID junction to a sibling inside the home');
  const elsewhere = makeWorld();
  elsewhere.canon.set(elsewhere.key(`${elsewhere.home}\\.marrow`), 'D:\\Users\\buu\\.marrow');
  assert.equal(reason(ensure(elsewhere)), 'canonical', 'same component count, another volume');
  const parentRedirect = makeWorld();
  parentRedirect.canon.set(parentRedirect.key('C:\\Users'), 'C:\\Other');
  assert.equal(reason(ensure(parentRedirect)), 'canonical', 'C:\\Users resolves to C:\\Other');
  const mount = makeWorld();
  mount.set(`${mount.home}\\.marrow`, { dev: 99n });
  assert.equal(reason(ensure(mount)), 'chain', 'a volume mount point: another dev inside the chain');
  const tilde = makeWorld();
  tilde.addDirs(`${tilde.home}\\x`);
  tilde.canon.set(tilde.key(`${tilde.home}\\.marrow`), `${tilde.home}\\x`);
  const named = makeWorld();
  named.addDirs(`${named.home}\\a~b\\.marrow`);
  named.canon.set(named.key(`${named.home}\\a~b`), `${named.home}\\other`);
  assert.equal(reason(ensure(named)), 'ok', 'a name with a tilde that is not 8.3 is only a problem if the home path uses it');
  const odd = makeWorld();
  odd.canon.set(odd.key(`${odd.home}\\.marrow`), `${odd.home}\\.MARROW`);
  assert.equal(ensure(odd).ok, true, 'a case difference is not a redirect');
  const wow = makeWorld();
  wow.canon.set(wow.key('C:\\Windows\\System32'), 'C:\\Windows\\SysWOW64');
  wow.canon.set(wow.key('C:\\Windows\\System32\\WindowsPowerShell'), 'C:\\Windows\\SysWOW64\\WindowsPowerShell');
  wow.canon.set(wow.key('C:\\Windows\\System32\\WindowsPowerShell\\v1.0'), 'C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0');
  wow.canon.set(wow.key('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'), 'C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe');
  assert.equal(ensure(wow).ok, true, '32-bit node on 64-bit Windows: the OS redirection System32 -> SysWOW64 is allowed');
});

test('U-G4b: the extra DOS device names are refused (COM0, LPT0, CONIN$, CONOUT$, superscript digits)', () => {
  for (const name of ['COM0', 'LPT0', 'CONIN$', 'CONOUT$', 'COM\u00b9', 'LPT\u00b2', 'com3.log']) assert.equal(validWindowsPath(`C:\\Users\\${name}`), false, name);
});

test('U-C4: an 8.3 home expands, and the spawn receives only long canonical paths', () => {
  const world = makeWorld({ home: 'C:\\Users\\RUNNER~1' });
  world.addDirs('C:\\Users\\runneradmin');
  world.addDirs('C:\\Users\\runneradmin\\.marrow\\session-loop-guard');
  world.addDirs('C:\\Users\\runneradmin\\AppData\\Local\\Temp');
  world.canon.set(world.key('C:\\Users\\RUNNER~1'), 'C:\\Users\\runneradmin');
  world.canon.set(world.key('C:\\Users\\runneradmin'), 'C:\\Users\\runneradmin');
  const result = ensure(world);
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.marrow, 'C:\\Users\\runneradmin\\.marrow');
  assert.equal(result.directory, 'C:\\Users\\runneradmin\\.marrow\\session-loop-guard');
  const env = world.calls.spawn[0].options.env;
  assert.equal(env.MARROW_WINACL_P1, 'C:\\Users\\runneradmin\\.marrow');
  assert.equal(env.MARROW_WINACL_P2, 'C:\\Users\\runneradmin\\.marrow\\session-loop-guard');
  assert.equal(env.TEMP, 'C:\\Users\\runneradmin\\AppData\\Local\\Temp');
  assert.ok(!Object.values(env).some((value) => /~/.test(value)));
  for (const created of world.calls.mkdir) assert.doesNotMatch(created, /~/);
});

test('U-C5: an lstat error anywhere is a refusal', () => {
  for (const level of ['C:\\Users', 'C:\\Users\\buu\\.marrow', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe']) {
    const world = makeWorld();
    world.lstatError.set(world.key(level), 'EACCES');
    assert.equal(ensure(world).ok, false, level);
  }
});

test('U-C6: a hard-linked state file is refused, a single link passes', () => {
  const world = makeWorld({ state: true });
  assert.equal(ensure(world).ok, true);
  assert.equal(ensure(world).stateProven, true);
  world.set(`${world.home}\\.marrow\\session-loop-guard\\state.json`, { nlink: 2n });
  assert.equal(reason(ensure(world)), 'chain');
});

test('U-C: the directories are created when absent, and an existing one is not created again', () => {
  const fresh = makeWorld({ marrow: false });
  const result = ensure(fresh);
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.deepEqual(fresh.calls.mkdir, [`${fresh.home}\\.marrow`, `${fresh.home}\\.marrow\\session-loop-guard`]);
  assert.equal(result.stateProven, false);
  const existing = makeWorld();
  assert.equal(ensure(existing).ok, true);
  assert.deepEqual(existing.calls.mkdir, []);
});

test('U-A5: a failing mkdir (another user profile) is a refusal; a concurrent create is not', () => {
  const denied = makeWorld({ marrow: false, mkdirError: 'EACCES' });
  assert.equal(reason(ensure(denied)), 'mkdir');
  assert.equal(denied.calls.spawn.length, 0);
  const raced = makeWorld({ marrow: false });
  const original = raced.deps.mkdir;
  raced.deps.mkdir = (p) => { original(p); throw errno('EEXIST'); };
  assert.equal(ensure(raced).ok, true);
});

// ---- U-A -------------------------------------------------------------------------------------

test('U-A1, A2, A20, A21: the exact exe, argv, options, env allowlist and a constant script', () => {
  const canary = `synthetic-${randomBytes(12).toString('hex')}`;
  const world = makeWorld({ env: { MARROW_API_KEY: canary, MARROW_KEY: canary, TOKEN: canary } });
  assert.equal(ensure(world).ok, true);
  const [call] = world.calls.spawn;
  assert.equal(call.file, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
  assert.deepEqual(call.args, ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', WIN_ACL_ENCODED]);
  assert.equal(Buffer.from(call.args[4], 'base64').toString('utf16le'), WIN_ACL_SCRIPT, 'the encoded command is the constant script');
  const o = call.options;
  assert.equal(o.shell, false);
  assert.equal(o.windowsHide, true);
  assert.equal(o.timeout, 5000);
  assert.equal(o.maxBuffer, 65536);
  assert.equal(o.cwd, 'C:\\Windows\\System32');
  assert.equal(o.encoding, 'utf8');
  assert.deepEqual(o.stdio, ['ignore', 'pipe', 'pipe']);
  assert.equal(o.input, undefined, 'nothing on standard input');
  assert.deepEqual(Object.keys(o.env).sort(), ['MARROW_WINACL_N', 'MARROW_WINACL_NONCE', 'MARROW_WINACL_P1', 'MARROW_WINACL_P2',
    'PSModulePath', 'SystemRoot', 'TEMP', 'TMP', 'windir']);
  assert.equal(o.env.PSModulePath, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules');
  assert.equal(o.env.MARROW_WINACL_N, '2');
  assert.match(o.env.MARROW_WINACL_NONCE, /^[0-9a-f]{32}$/);
  assert.equal(JSON.stringify(call).includes(canary), false);
  // The script text is a constant: nothing about the paths is in it, and a second call with other paths sends the same bytes.
  const other = makeWorld({ home: 'C:\\Users\\someone-else' });
  assert.equal(ensure(other).ok, true);
  assert.deepEqual(other.calls.spawn[0].args, call.args);
  assert.doesNotMatch(WIN_ACL_SCRIPT, /Users|\.marrow|buu|C:\\|"/);
  assert.match(WIN_ACL_SCRIPT, /Microsoft\.PowerShell\.Security\\Get-Acl -LiteralPath \(\[Environment\]::GetEnvironmentVariable\('MARROW_WINACL_P'\+\$i\)\)/);
});

test('U-A3 and A4: SystemRoot must be a plain root that equals windir and is not under the profile', () => {
  const cases = [
    { SystemRoot: 'C:\\Windows', windir: 'C:\\Other' },
    { SystemRoot: 'Windows', windir: 'Windows' },
    { SystemRoot: '\\\\srv\\share', windir: '\\\\srv\\share' },
    { SystemRoot: 'C:\\Users\\buu\\fake', windir: 'C:\\Users\\buu\\fake' },
    { SystemRoot: undefined, windir: undefined },
    { SystemRoot: undefined, windir: 'C:\\Windows' },
    { SystemRoot: 'C:\\Windows\\..', windir: 'C:\\Windows\\..' },
    { SystemRoot: 'C:\\Win dows', windir: 'C:\\Win dows' },
  ];
  for (const env of cases) {
    const world = makeWorld({ env });
    world.deps.env = new Proxy({ ...env }, {});
    assert.equal(reason(ensure(world)), 'sysroot', JSON.stringify(env));
    assert.equal(world.calls.spawn.length, 0, JSON.stringify(env));
  }
  const same = makeWorld({ env: { SystemRoot: 'C:\\Windows', windir: 'c:\\windows' } });
  assert.equal(ensure(same).ok, true);
});

test('U-A6: a link in the powershell path, or an exe under the profile, is refused', () => {
  for (const level of ['C:\\Windows', 'C:\\Windows\\System32', 'C:\\Windows\\System32\\WindowsPowerShell', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0',
    'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe']) {
    const world = makeWorld();
    world.set(level, { kind: 'link' });
    assert.equal(ensure(world).ok, false, level);
    assert.equal(world.calls.spawn.length, 0, level);
  }
  const under = makeWorld();
  under.canon.set(under.key('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'), 'C:\\Users\\buu\\AppData\\Local\\powershell.exe');
  assert.equal(reason(ensure(under)), 'canonical', 'the per-prefix canonical check refuses it before the under-the-profile check');
  assert.equal(under.calls.spawn.length, 0);
});

const OUTPUT_CASES = [
  ['A7 nonce mismatch', (w, env) => w.output(env, { nonce: 'f'.repeat(32) }), 'output'],
  ['A7 nonce mismatch at END only', (w, env) => w.output(env, { transform: (l) => [...l.slice(0, -1), `END ${'e'.repeat(32)}`] }), 'output'],
  ['A8 extra line', (w, env) => w.output(env, { transform: (l) => [l[0], 'noise', ...l.slice(1)] }), 'output'],
  ['A8 extra trailing line', (w, env) => `${w.output(env)}\r\n`, 'output'],
  ['A9 missing END', (w, env) => w.output(env, { transform: (l) => l.slice(0, -1) }), 'output'],
  ['A9 missing BEGIN', (w, env) => w.output(env, { transform: (l) => l.slice(1) }), 'output'],
  ['A10 ACL out of order', (w, env) => w.output(env, { transform: (l) => [l[0], l[1], l[3], l[2], l[4]] }), 'output'],
  ['A11 duplicate ACL index', (w, env) => w.output(env, { transform: (l) => [l[0], l[1], l[2], l[2], l[4]] }), 'output'],
  ['A12 SID malformed', (w, env) => w.output(env, { sid: 'S-1-5' }), 'output'],
  ['A24 empty descriptor', (w, env) => w.output(env, { transform: (l) => [l[0], l[1], 'ACL 1 ', l[3], l[4]] }), 'output'],
  ['A12 SID not a SID', (w, env) => w.output(env, { sid: 'DOMAIN\\user' }), 'output'],
  ['A12 SID line missing', (w, env) => w.output(env, { transform: (l) => [l[0], ...l.slice(2)] }), 'output'],
  ['A17 stdout of 70 KiB', () => 'x'.repeat(70 * 1024), 'output'],
  ['A18 descriptor line of 17 KiB', (w, env) => w.output(env, { transform: (l) => [l[0], l[1], `ACL 1 ${'A'.repeat(17 * 1024)}`, l[3], l[4]] }), 'output'],
  ['empty stdout', () => '', 'output'],
  ['stdout not a string', () => null, 'output'],
];

for (const [label, build, expected] of OUTPUT_CASES) {
  test(`U-${label}: refused`, () => {
    const world = makeWorld();
    world.spawnOverride = ({ options }) => ({ status: 0, signal: null, stdout: build(world, options.env), stderr: '' });
    assert.equal(reason(ensure(world)), expected);
  });
}

const SPAWN_FAILURES = [
  ['A13 exit 1', { status: 1, signal: null, stdout: '' }],
  ['A24 exit 3 (the script catch)', { status: 3, signal: null, stdout: 'BEGIN x\r\n' }],
  ['A14 ETIMEDOUT', { status: null, signal: 'SIGTERM', error: Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }), stdout: '' }, 'timeout'],
  ['A15 signal set', { status: null, signal: 'SIGKILL', stdout: '' }],
  ['A16 ENOENT', { status: null, signal: null, error: Object.assign(new Error('spawn'), { code: 'ENOENT' }), stdout: '' }],
  ['AB37 maxBuffer', { status: null, signal: null, error: Object.assign(new Error('buffer'), { code: 'ENOBUFS' }), stdout: 'x' }],
  ['no result at all', undefined],
];
for (const [label, result, expected = 'spawn'] of SPAWN_FAILURES) {
  test(`U-${label}: refused`, () => {
    const world = makeWorld();
    world.spawnOverride = () => result;
    assert.equal(reason(ensure(world)), expected);
  });
}

test('U-A: a throwing spawn is a refusal', () => {
  const world = makeWorld();
  world.spawnOverride = () => { throw new Error('boom'); };
  assert.equal(reason(ensure(world)), 'spawn');
});

test('U-A19 and AB36: stderr noise and a non-English Windows are fine, stderr is never echoed', () => {
  const world = makeWorld();
  world.spawnOverride = ({ options }) => ({ status: 0, signal: null, stdout: world.output(options.env), stderr: 'Fehler: secret-looking-noise' });
  const result = ensure(world);
  assert.equal(result.ok, true);
  assert.equal(JSON.stringify(result).includes('noise'), false);
});

test('U-A22: an ACL result is reused for 2 s while the folder identity is unchanged, never longer, never past a change', () => {
  const world = makeWorld();
  assert.equal(prove(world).ok, true);
  assert.equal(world.calls.spawn.length, 1);
  world.clock += 1999;
  assert.equal(prove(world).ok, true);
  assert.equal(world.calls.spawn.length, 1, 'reused inside 2 s');
  world.clock += 2;
  assert.equal(prove(world).ok, true);
  assert.equal(world.calls.spawn.length, 2, '2.001 s later it asks again');
  world.clock += 10;
  world.set(`${world.home}\\.marrow`, { ctimeNs: 2000n });
  world.set(`${world.home}\\.marrow\\session-loop-guard`, { ctimeNs: 3000n });
  assert.equal(prove(world).ok, true);
  assert.equal(world.calls.spawn.length, 2, 'ctime moves whenever an entry is created inside a folder: it is not part of the identity');
  world.set(`${world.home}`, { ino: 9999n });
  assert.equal(prove(world).ok, true);
  assert.equal(world.calls.spawn.length, 3, 'a replaced chain folder asks again');
  world.set(`${world.home}\\.marrow\\session-loop-guard`, { birthtimeNs: 7n });
  assert.equal(prove(world).ok, true);
  assert.equal(world.calls.spawn.length, 4);
  world.clock -= 5000;
  assert.equal(prove(world).ok, true);
  assert.equal(world.calls.spawn.length, 5, 'a clock that went backwards is never a hit');
  assert.ok([...world.deps.cache.values()].every((entry) => Object.keys(entry).sort().join() === 'at,signature'), 'the cache is in memory only: a time and a folder identity');
});

test('U-COL7: two object lists, or the same folder identity under other canonical paths, never share a cached result', () => {
  const first = makeWorld();
  assert.equal(prove(first).ok, true);
  const second = makeWorld({ home: 'C:\\Users\\someone-else' });
  second.deps.cache = first.deps.cache;
  assert.equal(prove(second).ok, true);
  assert.equal(second.calls.spawn.length, 1, 'same stats, different paths: it asked');
  const third = makeWorld({ state: true });
  third.deps.cache = first.deps.cache;
  assert.equal(prove(third, [MARROW, GUARD, STATE]).ok, true);
  assert.equal(third.calls.spawn.length, 1, 'a longer list is a different key');
  third.setAcl(`${third.home}\\.marrow\\session-loop-guard\\state.json`, sd({ extra: [{ sid: 'BU', mask: 1, flags: INHERIT }] }));
  assert.equal(reason(prove(third, [MARROW, GUARD])), 'ok', 'the shorter list is its own entry and does not see the state file');
  assert.equal(reason(prove(third, [MARROW, GUARD, STATE])), 'ok', 'inside 2 s the identical list and identity is a hit; the change shows in the next window');
  third.clock += 3000;
  assert.equal(reason(prove(third, [MARROW, GUARD, STATE])), 'acl');
});

test('U-A22: a refusal is never cached and the lstat chain work runs on every call, hit or not', () => {
  const world = makeWorld();
  assert.equal(prove(world).ok, true);
  world.set(`${world.home}\\.marrow`, { kind: 'link' });
  assert.equal(reason(prove(world)), 'chain', 'a link inside the 2 s window is still refused');
  world.set(`${world.home}\\.marrow`, { kind: 'dir' });
  world.setAcl(`${world.home}\\.marrow`, sd({ extra: [{ sid: 'BU', mask: FULL, flags: INHERIT }] }));
  world.clock += 5000;
  assert.equal(reason(prove(world)), 'acl');
  assert.equal(reason(prove(world)), 'acl', 'a failure is not a cache entry');
  assert.equal(world.calls.spawn.length, 3);
});

test('U-A: a duplicate object and too many objects are refused', () => {
  const world = makeWorld();
  assert.equal(reason(prove(world, [MARROW, MARROW])), 'canonical');
  assert.equal(reason(prove(world, [])), 'internal');
  assert.equal(reason(proveWindowsPrivate({ home: 'C:foo', objects: OBJECTS }, world.deps)), 'path');
});

// ---- U-S (binary descriptor) -----------------------------------------------------------------

const ME = SID;
const TRUSTED = new Set([ME, 'S-1-5-18', 'S-1-5-32-544']);
const NW = 'no_write_by_others';
const NA = 'no_access_by_others';
const judge = (encoded, policy) => evaluateDescriptor(encoded, TRUSTED, policy);
const grant = (sid, mask, flags = INHERIT, type = 0) => ({ sid, mask, flags, type });

test('U-S1 to S4: a private DACL passes, a foreign owner or a Modify grant to Users does not', () => {
  for (const policy of [NW, NA]) {
    assert.equal(judge(sd(), policy), null);
    assert.equal(judge(sd({ owner: 'BA' }), policy), null, 'S2 BA (deliberate deviation from POSIX: admin = root)');
    assert.equal(judge(sd({ owner: 'SY' }), policy), null, 'S2 SY');
    assert.equal(judge(sd({ owner: 'S-1-5-21-1-2-3-1002' }), policy), 'owner', 'S3');
    assert.equal(judge(sd({ extra: [grant('BU', 0x1301bf)] }), policy), 'acl', 'S4');
  }
});

test('U-S5: a read grant to Users passes the dir that others may read and fails the state dir', () => {
  assert.equal(judge(sd({ extra: [grant('BU', 0x1200a9)] }), NW), null);
  assert.equal(judge(sd({ extra: [grant('BU', 0x1200a9)] }), NA), 'acl');
  assert.equal(judge(sd({ extra: [grant('WD', 0x120089)] }), NW), null);
  assert.equal(judge(sd({ extra: [grant('AU', 0x80000000)] }), NA), 'acl');
});

test('U-S6, S7, S23, S24, S25: write rights for others fail, mask zero is a no-op, every write bit counts', () => {
  assert.equal(judge(sd({ extra: [grant('WD', 0x120116, 0)] }), NW), 'acl');
  assert.equal(judge(sd({ extra: [grant('AU', 0x40000000, 0)] }), NW), 'acl');
  for (const bit of [0x2, 0x4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000, 0x1000000, 0x2000000, 0x10000000, 0x40000000]) {
    assert.equal(judge(sd({ extra: [grant('BU', bit)] }), NW), 'acl', bit.toString(16));
  }
  for (const bit of [0x1, 0x8, 0x20, 0x80, 0x20000, 0x100000, 0x80000000, 0x20000000, 0x120089, 0x1200a0]) {
    assert.equal(judge(sd({ extra: [grant('BU', bit)] }), NW), null, bit.toString(16));
  }
  assert.equal(judge(sd({ extra: [grant('BU', 0)] }), NW), null);
  assert.equal(judge(sd({ extra: [grant('BU', 0)] }), NA), null);
  assert.equal(judge(sd({ extra: [grant('BU', 0x20000)] }), NA), 'acl');
});

test('U-S8 to S10: creator owner only when inherit-only, creator group never', () => {
  assert.equal(judge(sd({ extra: [grant('CO', FULL, 0x1b)] }), NW), null);
  assert.equal(judge(sd({ extra: [grant('CO', FULL, 0x1b)] }), NA), null);
  assert.equal(judge(sd({ extra: [grant('CO', FULL, 0x03)] }), NW), 'acl');
  assert.equal(judge(sd({ extra: [grant('CO', FULL, 0x03)] }), NA), 'acl');
  assert.equal(judge(sd({ extra: [grant('CG', FULL, 0x0b)] }), NW), 'acl');
  assert.equal(judge(sd({ extra: [grant('CG', 0, 0x0b)] }), NW), 'acl');
});

test('U-S11 to S22: a null or missing DACL, odd ACE types, bad sizes and unknown bits are refused; a deny, an empty DACL and a SACL are fine', () => {
  assert.equal(judge(sd({ nullDacl: true }), NW), 'descriptor', 'present but null DACL');
  assert.equal(judge(sd({ control: 0x8000 }), NW), 'descriptor', 'DACL not present');
  assert.equal(judge(sdBuffer({ aces: [] }).toString('base64'), NW), null, 'S13 an empty DACL');
  assert.equal(judge(sd({ extra: [grant('BU', FULL, INHERIT, 1)] }), NA), null, 'S14 a deny ACE only removes access');
  for (const type of [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]) {
    assert.equal(judge(sd({ extra: [grant('BU', FULL, 0, type)] }), NW), 'descriptor', `ACE type ${type}`);
  }
  assert.equal(judge(sd({ extra: [grant('BU', 1, 0x40)] }), NW), 'descriptor', 'unknown ACE flag (audit flag in a DACL)');
  assert.equal(judge(sd({ extra: [grant('BU', 1, 0x20)] }), NW), 'descriptor', 'critical flag');
  assert.equal(judge(sd({ extra: [{ ...grant('BU', 1), size: 20 }] }), NW), 'descriptor', 'ACE size that disagrees with its SID');
  assert.equal(judge(sd({ extra: [{ ...grant('BU', 1), size: 4 }] }), NW), 'descriptor', 'ACE size too small');
  assert.equal(judge(sd({ aclSizeDelta: 4 }), NW), 'descriptor', 'ACL size larger than its ACEs');
  assert.equal(judge(sd({ aclSizeDelta: -4 }), NW), 'descriptor', 'ACL size smaller than its ACEs');
  assert.equal(judge(sd({ aclCount: 9 }), NW), 'descriptor', 'ACE count beyond the ACL');
  assert.equal(judge(sd({ aclCount: 2 }), NW), 'descriptor', 'fewer ACEs than the ACL holds');
  assert.equal(judge(sd({ trailing: 1 }), NW), 'descriptor', 'a trailing byte');
  assert.equal(judge(sd({ control: 0x8000 | 0x4 | 0x0040 }), NW), 'descriptor', 'unknown control bit');
  assert.equal(judge(sd({ control: 0x4 }), NW), 'descriptor', 'not self-relative');
  assert.equal(judge(sd({ control: 0x8000 | 0x4 | 0x1000 | 0x400 | 0x100 }), NW), null, 'protected, auto-inherit-required and auto-inherited together');
  assert.equal(judge(sd({ control: 0x8000 | 0x4 | 0x1000 }), NW), null, 'protected only');
  // a SACL part we never read is ignored
  const withSacl = sdBuffer({ control: 0x8000 | 0x4 | 0x10 | 0x400, trailing: 12 });
  withSacl.writeUInt32LE(withSacl.length - 12, 12);
  assert.equal(judge(withSacl.toString('base64'), NW), null, 'S22');
});

test('U-S: truncation, bad SIDs and bad encodings are refused', () => {
  const good = Buffer.from(sd(), 'base64');
  for (let cut = 1; cut < good.length; cut += 7) assert.equal(judge(good.subarray(0, cut).toString('base64'), NW), 'descriptor', `cut ${cut}`);
  const badRevision = Buffer.from(good);
  badRevision[20] = 2;
  assert.equal(judge(badRevision.toString('base64'), NW), 'descriptor', 'SID revision');
  const noSubs = Buffer.from(good);
  noSubs[21] = 0;
  assert.equal(judge(noSubs.toString('base64'), NW), 'descriptor', 'SID with no sub-authority');
  const tooMany = Buffer.from(good);
  tooMany[21] = 16;
  assert.equal(judge(tooMany.toString('base64'), NW), 'descriptor', 'SID with 16 sub-authorities');
  const badOwner = Buffer.from(good);
  badOwner.writeUInt32LE(4, 4);
  assert.equal(judge(badOwner.toString('base64'), NW), 'descriptor', 'owner offset inside the header');
  const noOwner = Buffer.from(good);
  noOwner.writeUInt32LE(0, 4);
  assert.equal(judge(noOwner.toString('base64'), NW), 'descriptor', 'no owner');
  const overlap = Buffer.from(good);
  overlap.writeUInt32LE(20, 16);
  assert.equal(judge(overlap.toString('base64'), NW), 'descriptor', 'the DACL read from the owner bytes');
  const saclFlagless = Buffer.from(good);
  saclFlagless.writeUInt32LE(24, 12);
  assert.equal(judge(saclFlagless.toString('base64'), NW), 'descriptor', 'a SACL offset without the SACL flag');
  const badGroup = Buffer.from(good);
  badGroup.writeUInt32LE(good.length + 8, 8);
  assert.equal(judge(badGroup.toString('base64'), NW), 'descriptor', 'group offset beyond the end');
  for (const value of [undefined, null, 5, '', {}, 'x'.repeat(20000), '!!!!', 'AAA', 'AAAA=AAA', `${sd()}\n`, ` ${sd()}`]) assert.equal(judge(value, NW), 'descriptor', String(value).slice(0, 10));
  assert.equal(judge(Buffer.alloc(13000, 1).toString('base64'), NW), 'descriptor', 'over the size cap');
});

test('AB59 and AB60: a RID 500 owner who is the current user, and a domain group, are NOT denied (aliases never appear in binary)', () => {
  const admin = 'S-1-5-21-1-2-3-500';
  const trusted = new Set([admin, 'S-1-5-18', 'S-1-5-32-544']);
  assert.equal(evaluateDescriptor(sd({ owner: admin, me: admin }), trusted, NA), null, 'owner is the built-in Administrator who runs the hook');
  assert.equal(evaluateDescriptor(sd({ group: 'S-1-5-21-1-2-3-513' }), TRUSTED, NA), null, 'G:DU style primary group');
  assert.equal(evaluateDescriptor(sd({ group: 'S-1-5-21-9-9-9-512' }), TRUSTED, NA), null, 'the group is syntax only, never evaluated');
  assert.equal(evaluateDescriptor(sd({ noGroup: true }), TRUSTED, NA), null, 'no group at all');
  assert.equal(evaluateDescriptor(sd({ owner: 'S-1-5-21-1-2-3-512' }), TRUSTED, NA), 'owner', 'O:DA is another principal');
  assert.equal(evaluateDescriptor(sd({ owner: admin }), TRUSTED, NA), 'owner', 'a RID 500 owner who is not the caller');
});

test('U-S through the proof: .marrow passes a Users read grant, session-loop-guard and state.json do not (AB30, AB31, AB32)', () => {
  const grantRead = sd({ extra: [grant('BU', 0x1200a9)] });
  const world = makeWorld({ state: true });
  world.setAcl(`${world.home}\\.marrow`, grantRead);
  assert.equal(prove(world, [MARROW]).ok, true);
  world.clock += 5000;
  world.setAcl(`${world.home}\\.marrow\\session-loop-guard`, grantRead);
  assert.equal(reason(prove(world, [MARROW, GUARD])), 'acl');
  const stateOnly = makeWorld({ state: true });
  stateOnly.setAcl(`${stateOnly.home}\\.marrow\\session-loop-guard\\state.json`, grantRead);
  assert.equal(reason(prove(stateOnly, [MARROW, GUARD, STATE])), 'acl');
  const inherited = makeWorld();
  inherited.setAcl(`${inherited.home}\\.marrow`, sd({ extra: [grant('BU', 0x1301bf, 0x03)] }));
  assert.equal(reason(ensure(inherited)), 'acl', 'AB30');
  const foreign = makeWorld();
  foreign.setAcl(`${foreign.home}\\.marrow`, sd({ owner: 'S-1-5-21-9-9-9-1002' }));
  assert.equal(reason(ensure(foreign)), 'owner', 'AB23');
  const admin = makeWorld();
  admin.setAcl(`${admin.home}\\.marrow`, sd({ owner: 'BA' }));
  assert.equal(ensure(admin).ok, true, 'AB41');
  const nullDacl = makeWorld();
  nullDacl.setAcl(`${nullDacl.home}\\.marrow\\session-loop-guard`, sd({ nullDacl: true }));
  assert.equal(reason(ensure(nullDacl)), 'descriptor', 'AB32');
  const denyOnly = makeWorld();
  denyOnly.setAcl(`${denyOnly.home}\\.marrow`, sd({ extra: [grant('BU', FULL, INHERIT, 1)] }));
  assert.equal(ensure(denyOnly).ok, true, 'AB33');
});

test('U-A23: the script has one ACL line per Get-Acl call, so a failed call can never print an older value; U-A24: its catch exits 3 and it ends in exit 0', () => {
  assert.equal((WIN_ACL_SCRIPT.match(/Get-Acl/g) || []).length, 1);
  const line = WIN_ACL_SCRIPT.split('\n').find((text) => text.includes('Get-Acl'));
  assert.match(line, /WriteLine\('ACL '\+\$i\+' '\+\[Convert\]::ToBase64String\(\(Microsoft\.PowerShell\.Security\\Get-Acl/);
  assert.ok(line.indexOf('WriteLine(') < line.indexOf('Get-Acl'), 'the write wraps the call');
  assert.doesNotMatch(line, /\$\w+=[^;]*Get-Acl/, 'no variable holds a Get-Acl result');
  assert.match(WIN_ACL_SCRIPT, /^\$ErrorActionPreference='Stop'\n\$ProgressPreference='SilentlyContinue'\ntry\{\n/);
  assert.match(WIN_ACL_SCRIPT, /\nexit 0\n\}catch\{exit 3\}\n$/);
  assert.match(WIN_ACL_SCRIPT, /WindowsIdentity\]::GetCurrent\(\)\.User\.Value/);
  assert.doesNotMatch(WIN_ACL_SCRIPT, /whoami|Read-Host|\$input/);
});

// ---- lock time: the structural half only ---------------------------------------------------------------

test('RC-3: the lock-time check never spawns, accepts a new plain state file in an unchanged folder, and refuses a changed folder', () => {
  const world = makeWorld();
  const proof = ensure(world);
  assert.equal(proof.ok, true);
  assert.equal(world.calls.spawn.length, 1);
  const verify = () => verifyWindowsPrivateState(world.home, proof, world.deps);
  assert.equal(verify(), true);
  world.set(`${world.home}\\.marrow\\session-loop-guard`, { ctimeNs: 4242n });
  assert.equal(verify(), true, 'ctime moves whenever the lock or a temp file is created');
  const stateFile = `${world.home}\\.marrow\\session-loop-guard\\state.json`;
  const bornAt = (ms) => BigInt(ms) * 1_000_000n;
  world.add(stateFile, 'file', { birthtimeNs: bornAt(world.clock + 5) });
  assert.equal(verify(), true, 'a state file created after the proof began, single link, in the same folders');
  world.set(stateFile, { birthtimeNs: 500n });
  assert.equal(verify(), false, 'a file moved in from elsewhere keeps its old birth time and its old DACL: refused');
  world.set(stateFile, { birthtimeNs: bornAt(world.clock - 100) });
  assert.equal(verify(), true, 'inside the file-system clock tolerance');
  world.set(stateFile, { birthtimeNs: bornAt(world.clock + 5) });
  world.set(`${world.home}\\.marrow\\session-loop-guard\\state.json`, { ino: 4n, nlink: 2n });
  assert.equal(verify(), false, 'a hard link');
  world.set(`${world.home}\\.marrow\\session-loop-guard\\state.json`, { nlink: 1n, kind: 'link' });
  assert.equal(verify(), false, 'a symlink');
  world.set(`${world.home}\\.marrow\\session-loop-guard\\state.json`, { kind: 'file', nlink: 1n });
  assert.equal(verify(), true);
  for (const [level, change] of [[`${world.home}`, { ino: 77n }], [`${world.home}\\.marrow`, { birthtimeNs: 77n }], [`${world.home}\\.marrow\\session-loop-guard`, { ino: 78n }], ['C:\\Users', { dev: 9n }]]) {
    const before = { ...world.nodes.get(world.key(level)) };
    world.set(level, change);
    assert.equal(verify(), false, `${level} replaced`);
    world.set(level, { ino: before.ino, birthtimeNs: before.birthtimeNs, dev: before.dev });
  }
  world.set(`${world.home}\\.marrow`, { kind: 'link' });
  assert.equal(verify(), false, 'a junction');
  world.set(`${world.home}\\.marrow`, { kind: 'dir' });
  world.canon.set(world.key(`${world.home}\\.marrow`), `${world.home}\\x\\.marrow`);
  assert.equal(verify(), false, 'a canonical path that moved');
  world.canon.clear();
  assert.equal(verify(), true);
  assert.equal(verifyWindowsPrivateState('C:foo', proof, world.deps), false);
  assert.equal(verifyWindowsPrivateState(world.home, proof, { ...world.deps, platform: 'linux' }), false);
  assert.equal(world.calls.spawn.length, 1, 'verification never starts a process');
});

test('RC-3: the state file the proof covered stays fine; a replacement is fine only if born after the proof began', () => {
  const world = makeWorld({ state: true });
  const proof = ensure(world);
  assert.equal(proof.ok, true);
  assert.match(proof.stateKey, /^\d+:\d+$/);
  const stateFile = `${world.home}\\.marrow\\session-loop-guard\\state.json`;
  assert.equal(verifyWindowsPrivateState(world.home, proof, world.deps), true, 'the proven file, old birth time and all');
  world.set(stateFile, { ino: 123456n });
  assert.equal(verifyWindowsPrivateState(world.home, proof, world.deps), false, 'replaced by an older file (a restore or a move)');
  world.set(stateFile, { ino: 123457n, birthtimeNs: BigInt(world.clock + 20) * 1_000_000n });
  assert.equal(verifyWindowsPrivateState(world.home, proof, world.deps), true, 'replaced by a file created after the proof (a writer)');
  world.clock += 500;
  world.set(stateFile, { ino: 5n });
  const again = ensure(world);
  assert.equal(again.ok, true);
  assert.equal(world.calls.spawn.length, 2, 'a replaced state file is a different object: the cached answer does not cover it');
});

test('RC-3: an 8.3 home verifies against its own long-name proof', () => {
  const world = makeWorld({ home: 'C:\\Users\\RUNNER~1' });
  world.addDirs('C:\\Users\\runneradmin\\.marrow\\session-loop-guard');
  world.addDirs('C:\\Users\\runneradmin\\AppData\\Local\\Temp');
  world.canon.set(world.key('C:\\Users\\RUNNER~1'), 'C:\\Users\\runneradmin');
  const proof = ensure(world);
  assert.equal(proof.ok, true, JSON.stringify(proof));
  assert.equal(verifyWindowsPrivateState(world.home, proof, world.deps), true);
});

// ---- abuse rows that need the home itself ----------------------------------------------------------

test('AB28 and AB29: UNC, device, drive-relative, MSYS, forward-slash, stream and trailing-dot homes are refused before any I/O', () => {
  const homes = ['\\\\localhost\\C$\\Users\\x', '\\\\?\\C:\\Users\\x', '\\\\.\\C:\\Users\\x', 'C:Users\\x', '/c/Users/x', 'C:/Users/x', 'C:\\Users\\x:s', 'C:\\Users\\x.',
    '//?/C:/Users/x', '~', '%USERPROFILE%', 'C:\\Users\\x\\..\\y', '', undefined];
  for (const home of homes) {
    const world = makeWorld();
    let touched = 0;
    for (const name of ['lstatBig', 'realpathNative', 'spawnSync', 'mkdir']) {
      const original = world.deps[name];
      world.deps[name] = (...args) => { touched += 1; return original(...args); };
    }
    assert.equal(reason(ensureWindowsPrivateState(home, world.deps)), 'path', String(home));
    assert.equal(touched, 0, `${home} touched the disk or spawned`);
  }
});

test('AB22 and AB40: a key in the environment never selects the home or the state, and is not in the result', () => {
  const canary = `synthetic-${randomBytes(12).toString('hex')}`;
  const world = makeWorld({ env: { MARROW_API_KEY: canary, MARROW_HOME: 'C:\\Users\\other', USERPROFILE: 'C:\\Users\\other' } });
  const result = ensure(world);
  assert.equal(result.ok, true);
  assert.ok(result.marrow.startsWith(world.home), 'the home is the caller\'s argument, not an env value');
  assert.equal(JSON.stringify(result).includes(canary), false);
  assert.deepEqual([...world.reads].sort(), ['SystemRoot', 'windir']);
});

test('AB42: a .marrow the Cursor launcher created first (with cursor-plugin inside) passes, and AB34: PATH and cwd fakes are never the exe', () => {
  const world = makeWorld({ env: { PATH: 'C:\\Users\\buu\\evil;C:\\fake' } });
  world.addDirs(`${world.home}\\.marrow\\cursor-plugin\\mcp-3.9.106-abc`);
  world.add(`${world.home}\\powershell.exe`, 'file');
  world.add(`${world.home}\\.marrow\\icacls.exe`, 'file');
  assert.equal(ensure(world).ok, true);
  assert.equal(world.calls.spawn[0].file, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
  assert.equal(Object.keys(world.calls.spawn[0].options.env).includes('PATH'), false);
  assert.equal(world.calls.spawn[0].options.cwd, 'C:\\Windows\\System32');
});
