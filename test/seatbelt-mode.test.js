const assert = require('node:assert/strict');
const test = require('node:test');
const { randomBytes } = require('node:crypto');
const { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, chmodSync, symlinkSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const { createFakeFs } = require('./support/seatbelt-fake-fs.cjs');
const { nodeSeatbeltFs } = require('../dist/seatbelt-fs.js');
const { resolveSeatbeltMode, resolveSeatbeltModeOnHost, ACCOUNT_EVIDENCE, MODE_ENV_NAMES, homeFlags } = require('../dist/seatbelt-mode.js');

const UID = 1000;
const HOME = '/home/u';

// Each evidence item of spec §1.1 and how to plant it in a fake home.
const PLANT = {
  env_file: (fs) => fs.file(`${HOME}/.marrow/env`, 'MARROW_API_KEY=placeholder\n', { mode: 0o600 }),
  env_local_file: (fs) => fs.file(`${HOME}/.marrow/env.local`, '', { mode: 0o600 }),
  device_binding: (fs) => fs.file(`${HOME}/.marrow/device/binding.json`, '{}'),
  claimed_marker: (fs) => fs.file(`${HOME}/.marrow/claimed`, ''),
  host_approvals_state: (fs) => fs.file(`${HOME}/.marrow/host-approvals/state.json`, '{"protected_categories":["deploy"]}'),
  mcp_spool: (fs) => fs.file(`${HOME}/.marrow/spool/mcp-abc.json`, '{}'),
  runner_holds_salt: (fs) => fs.file(`${HOME}/.marrow/runner-holds/.salt`, 'x'),
  hook_claimed_marker: (fs) => fs.file(`${HOME}/.claude/settings.json`, JSON.stringify({ hooks: { PreToolUse: [{ hooks: [{ command: "/bin/sh -c 'exec marrow-mcp claude-pre-action-hook --claimed'" }] }] } })),
};
const PLANTABLE = Object.keys(PLANT);

function cleanHome() {
  return createFakeFs({ uid: UID }).mkdir(HOME, { mode: 0o700, uid: UID }).mkdir(`${HOME}/.marrow`, { mode: 0o700, uid: UID }).file(`${HOME}/.marrow/control.json`, '{}', { mode: 0o600 });
}

function mode(fs, overrides = {}) {
  return resolveSeatbeltMode({ fs, passwdHome: HOME, argv: ['claude-pre-action-hook'], key: 'none', uid: UID, ...overrides });
}

test('a machine with no account evidence and no key is in seatbelt mode (control.json alone is not evidence)', () => {
  const r = mode(cleanHome());
  assert.equal(r.mode, 'seatbelt');
  assert.ok(ACCOUNT_EVIDENCE.every((id) => r.evidence[id] === 'absent'));
  assert.equal(mode(createFakeFs({ uid: UID }).mkdir(HOME, { uid: UID })).mode, 'seatbelt');
});

test('abuse-ratchet: every subset of evidence; seatbelt only for the empty set (2^8 cases)', () => {
  for (let mask = 0; mask < 1 << PLANTABLE.length; mask += 1) {
    const fs = cleanHome();
    const planted = PLANTABLE.filter((_, i) => mask & (1 << i));
    for (const id of planted) PLANT[id](fs);
    const r = mode(fs);
    assert.equal(r.mode, planted.length === 0 ? 'seatbelt' : 'claimed_no_key', planted.join(','));
    for (const id of planted) assert.equal(r.evidence[id], 'present', id);
  }
});

test('abuse-ratchet: deleting any single evidence item never yields seatbelt while another remains', () => {
  for (const removed of PLANTABLE) {
    const fs = cleanHome();
    for (const id of PLANTABLE) if (id !== removed) PLANT[id](fs);
    assert.equal(mode(fs).mode, 'claimed_no_key', `removed ${removed}`);
  }
});

test('key state: usable key -> account; rejected (401) -> claimed_no_key, never seatbelt', () => {
  assert.equal(mode(cleanHome(), { key: 'present' }).mode, 'account');
  assert.equal(mode(cleanHome(), { key: 'rejected' }).mode, 'claimed_no_key');
  const fs = cleanHome();
  PLANT.claimed_marker(fs);
  assert.equal(mode(fs, { key: 'present' }).mode, 'account');
  assert.equal(mode(fs, { key: 'rejected' }).mode, 'claimed_no_key');
});

test('unknown evidence is stricter: unreadable probes, a spool that is not a dir, an oversized hook config', () => {
  assert.equal(mode(cleanHome().fail(`${HOME}/.marrow/env`)).mode, 'claimed_no_key');
  assert.equal(mode(cleanHome().fail(`${HOME}/.marrow/device`)).mode, 'claimed_no_key');
  assert.equal(mode(cleanHome().mkdir(`${HOME}/.marrow/spool`).fail(`${HOME}/.marrow/spool`)).mode, 'claimed_no_key');
  assert.equal(mode(cleanHome().file(`${HOME}/.marrow/spool`, 'x')).mode, 'claimed_no_key');
  assert.equal(mode(cleanHome().file(`${HOME}/.claude/settings.json`, 'x'.repeat(1024 * 1024 + 1))).mode, 'claimed_no_key');
  assert.equal(mode(cleanHome().fifo(`${HOME}/.codex/hooks.json`)).mode, 'claimed_no_key');
  const spoolOther = cleanHome().file(`${HOME}/.marrow/spool/other.json`, '{}');
  assert.equal(mode(spoolOther).mode, 'seatbelt');
});

test('ownership/mode mismatch on ~/.marrow: symlinked, foreign-owned or non-directory ~/.marrow is unknown, so not seatbelt', () => {
  const linked = createFakeFs({ uid: UID }).mkdir(HOME, { uid: UID }).mkdir('/elsewhere', { uid: UID }).symlink(`${HOME}/.marrow`, '/elsewhere');
  assert.equal(mode(linked).mode, 'claimed_no_key');
  assert.equal(mode(linked).evidence.marrow_dir, 'unknown');
  const foreign = createFakeFs({ uid: UID }).mkdir(HOME, { uid: UID }).mkdir(`${HOME}/.marrow`, { uid: 0, mode: 0o755 });
  assert.equal(mode(foreign).mode, 'claimed_no_key');
  const file = createFakeFs({ uid: UID }).mkdir(HOME, { uid: UID }).file(`${HOME}/.marrow`, '');
  assert.equal(mode(file).mode, 'claimed_no_key');
  const foreignFile = cleanHome().file(`${HOME}/.marrow/claimed`, '', { uid: 0, mode: 0o666 });
  assert.equal(mode(foreignFile).mode, 'claimed_no_key');
  const writable = createFakeFs({ uid: UID }).mkdir(HOME, { uid: UID }).mkdir(`${HOME}/.marrow`, { uid: UID, mode: 0o777 });
  assert.equal(mode(writable).mode, 'claimed_no_key');
  assert.equal(mode(createFakeFs({ uid: UID }).mkdir(HOME, { uid: UID }).mkdir(`${HOME}/.marrow`, { uid: UID, mode: 0o720 })).mode, 'claimed_no_key');
  const brokenLink = cleanHome().symlink(`${HOME}/.marrow/env`, '/nowhere');
  assert.equal(mode(brokenLink).mode, 'claimed_no_key');
});

test('home: passwd or --home only; missing, relative, dotted or mismatched homes are never seatbelt', () => {
  assert.equal(mode(cleanHome(), { passwdHome: null }).mode, 'claimed_no_key');
  assert.equal(mode(cleanHome(), { passwdHome: null, argv: ['--home', HOME] }).mode, 'seatbelt');
  assert.equal(mode(cleanHome(), { argv: [`--home=${HOME}`] }).mode, 'seatbelt');
  assert.equal(mode(cleanHome(), { argv: ['--home', 'home/u'] }).mode, 'claimed_no_key');
  assert.equal(mode(cleanHome(), { argv: ['--home', '/home/u/../u'] }).mode, 'claimed_no_key');
  assert.equal(mode(cleanHome(), { argv: ['--home'] }).mode, 'claimed_no_key');
  assert.equal(mode(cleanHome(), { passwdHome: '/nonexistent' }).mode, 'claimed_no_key');
  const two = cleanHome().mkdir('/home/v', { uid: UID });
  const r = mode(two, { argv: ['--home', '/home/v'] });
  assert.equal(r.mode, 'claimed_no_key');
  assert.ok(r.reasons.includes('home_mismatch'));
  // Evidence in either home counts.
  const ev = cleanHome().mkdir('/home/v', { uid: UID }).file('/home/v/.marrow/claimed', '');
  assert.ok(mode(ev, { passwdHome: '/home/v', argv: ['--home', HOME] }).evidence.claimed_marker === 'present');
  assert.deepEqual(homeFlags(['--home', '/a', '--home=/b', 'x']), ['/a', '/b']);
});

test('the --claimed marker on the running hook command line is evidence', () => {
  assert.equal(mode(cleanHome(), { argv: ['claude-pre-action-hook', '--claimed'] }).mode, 'claimed_no_key');
  assert.equal(mode(cleanHome(), { argv: ['claude-pre-action-hook', '--claimed=1'] }).mode, 'claimed_no_key');
  assert.equal(mode(cleanHome(), { argv: ['claude-pre-action-hook', '--claimedx'] }).mode, 'seatbelt');
  for (const file of ['.codex/hooks.json', '.cursor/hooks.json', '.gemini/settings.json', '.codeium/windsurf/hooks.json', '.grok/hooks/marrow.json']) {
    assert.equal(mode(cleanHome().file(`${HOME}/${file}`, '{"command":"marrow-mcp hook --claimed"}')).mode, 'claimed_no_key', file);
  }
});

test('MARROW_SEATBELT_STRICT can only tighten', () => {
  assert.equal(mode(cleanHome(), { strict: true }).mode, 'claimed_no_key');
  assert.equal(mode(cleanHome(), { strict: true, key: 'present' }).mode, 'account');
});

// ---- Host wiring on the real filesystem (dummy keys generated at runtime) ----

function dummyKey() {
  return `mrw_dummy_${randomBytes(16).toString('hex')}`;
}

function realHome(t) {
  const base = realpathSync(mkdtempSync(join(tmpdir(), 'seatbelt-mode-')));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const home = join(base, 'home');
  mkdirSync(home, { mode: 0o700 });
  return { base, home };
}

const SEATBELT_CLAIMS = {
  MARROW_MODE: 'seatbelt',
  MARROW_SEATBELT: '1',
  MARROW_SEATBELT_MODE: 'seatbelt',
  MARROW_CLAIMED: '0',
  MARROW_NO_ACCOUNT: '1',
  MARROW_SEATBELT_STRICT: '0',
  MARROW_CONTROL: 'disabled',
  MARROW_HOME: '/nonexistent',
  XDG_CONFIG_HOME: '/nonexistent',
};

test('env vars can never select seatbelt: a claimed machine stays claimed_no_key whatever the env says', (t) => {
  const { base, home } = realHome(t);
  mkdirSync(join(home, '.marrow'), { mode: 0o700 });
  writeFileSync(join(home, '.marrow', 'claimed'), '', { mode: 0o600 });
  const clean = join(base, 'clean');
  mkdirSync(clean, { mode: 0o700 });
  const env = { ...SEATBELT_CLAIMS, HOME: clean, USERPROFILE: clean };
  const r = resolveSeatbeltModeOnHost({ env, passwdHome: home, argv: ['claude-pre-action-hook'] });
  assert.equal(r.mode, 'claimed_no_key');
  assert.deepEqual(r.homes, [home]);
});

test('env vars can never select seatbelt: a forged $HOME is never read (mode reads only the listed names)', (t) => {
  const { base, home } = realHome(t);
  const forged = join(base, 'forged');
  mkdirSync(join(forged, '.marrow'), { recursive: true, mode: 0o700 });
  writeFileSync(join(forged, '.marrow', 'claimed'), '');
  const read = new Set();
  const env = new Proxy({ ...SEATBELT_CLAIMS, HOME: forged, USERPROFILE: forged }, {
    get(target, name) { if (typeof name === 'string') read.add(name); return target[name]; },
  });
  const r = resolveSeatbeltModeOnHost({ env, passwdHome: home, argv: [] });
  assert.equal(r.mode, 'seatbelt');
  assert.deepEqual(r.homes, [home]);
  for (const name of read) assert.ok(MODE_ENV_NAMES.includes(name), `mode resolution read env ${name}`);
  assert.ok(!read.has('HOME') && !read.has('MARROW_MODE') && !read.has('MARROW_SEATBELT'));
});

test('an env key can only move the mode to account (stricter than seatbelt), never to seatbelt', (t) => {
  const { home } = realHome(t);
  assert.equal(resolveSeatbeltModeOnHost({ env: { MARROW_API_KEY: dummyKey() }, passwdHome: home, argv: [] }).mode, 'account');
  assert.equal(resolveSeatbeltModeOnHost({ env: { MARROW_KEY: dummyKey() }, passwdHome: home, argv: [] }).mode, 'account');
  assert.equal(resolveSeatbeltModeOnHost({ env: { MARROW_API_KEY: dummyKey() }, passwdHome: home, argv: [], keyRejected: true }).mode, 'claimed_no_key');
  assert.equal(resolveSeatbeltModeOnHost({ env: { MARROW_SEATBELT_STRICT: '1' }, passwdHome: home, argv: [] }).mode, 'claimed_no_key');
});

test('owner key file: private -> account; wrong mode -> rejected key but the file is still evidence (claimed_no_key)', (t) => {
  const { home } = realHome(t);
  mkdirSync(join(home, '.marrow'), { mode: 0o700 });
  const file = join(home, '.marrow', 'env');
  writeFileSync(file, `MARROW_API_KEY=${dummyKey()}\n`, { mode: 0o600 });
  assert.equal(resolveSeatbeltModeOnHost({ env: {}, passwdHome: home, argv: [] }).mode, 'account');
  chmodSync(file, 0o644);
  const loose = resolveSeatbeltModeOnHost({ env: {}, passwdHome: home, argv: [] });
  assert.equal(loose.mode, 'claimed_no_key');
  assert.equal(loose.evidence.env_file, 'present');
  writeFileSync(file, '', { mode: 0o600 });
  chmodSync(file, 0o600);
  assert.equal(resolveSeatbeltModeOnHost({ env: {}, passwdHome: home, argv: [] }).mode, 'claimed_no_key');
});

test('A18: a planted repo .env / .marrow/env (key and base URL) is ignored; the cwd is never consulted', (t) => {
  const { base, home } = realHome(t);
  const repo = join(base, 'cloned');
  mkdirSync(join(repo, '.marrow'), { recursive: true });
  writeFileSync(join(repo, '.env'), `MARROW_API_KEY=${dummyKey()}\nMARROW_BASE_URL=https://attacker.invalid\n`, { mode: 0o600 });
  writeFileSync(join(repo, '.env.local'), `MARROW_API_KEY=${dummyKey()}\n`, { mode: 0o600 });
  writeFileSync(join(repo, '.marrow', 'env'), `MARROW_API_KEY=${dummyKey()}\n`, { mode: 0o600 });
  writeFileSync(join(repo, '.marrow', 'claimed'), '');
  const saved = process.cwd();
  process.chdir(repo);
  try {
    const r = resolveSeatbeltModeOnHost({ env: { HOME: repo }, passwdHome: home, argv: [] });
    assert.equal(r.mode, 'seatbelt');
    assert.deepEqual(r.homes, [home]);
    // The same planted files in a claimed machine change nothing either.
    mkdirSync(join(home, '.marrow'), { mode: 0o700 });
    writeFileSync(join(home, '.marrow', 'claimed'), '');
    assert.equal(resolveSeatbeltModeOnHost({ env: { HOME: repo }, passwdHome: home, argv: [] }).mode, 'claimed_no_key');
  } finally {
    process.chdir(saved);
  }
});

test('real fs: a symlinked ~/.marrow and a symlinked home are handled', (t) => {
  const { base, home } = realHome(t);
  const elsewhere = join(base, 'elsewhere');
  mkdirSync(elsewhere, { mode: 0o700 });
  symlinkSync(elsewhere, join(home, '.marrow'));
  assert.equal(resolveSeatbeltModeOnHost({ env: {}, passwdHome: home, argv: [] }).mode, 'claimed_no_key');
  const home2 = join(base, 'home2');
  mkdirSync(home2, { mode: 0o700 });
  const linkHome = join(base, 'linkhome');
  symlinkSync(home2, linkHome);
  const r = resolveSeatbeltModeOnHost({ env: {}, passwdHome: linkHome, argv: [], fs: nodeSeatbeltFs() });
  assert.equal(r.mode, 'seatbelt');
  assert.deepEqual(r.homes, [home2]);
});
