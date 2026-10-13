// Regression tests from Barvis's exact-SHA audit of 5069b1c6 (seatbelt U3/U4), copied from its evidence/mode.test.cjs.
// Only change: AUDIT_DIST points at this repo's dist.
'use strict';
// Barvis U4 audit tests (own fixtures). Dummy key material is generated at runtime and never printed.
const assert = require('node:assert/strict');
const test = require('node:test');
const { randomBytes } = require('node:crypto');
const fsn = require('node:fs');
const { join } = require('node:path');
const { execFileSync, spawn } = require('node:child_process');
const D = require('node:path').join(__dirname, '..', 'dist');
const { nodeSeatbeltFs } = require(`${D}/seatbelt-fs.js`);
const { resolveSeatbeltMode, resolveSeatbeltModeOnHost } = require(`${D}/seatbelt-mode.js`);
const { createFakeFs } = require(`${D}/../test/support/seatbelt-fake-fs.cjs`);

const ROOT = fsn.mkdtempSync('/tmp/barvis-u4-');
let n = 0;
const fresh = () => {
  const d = join(ROOT, `h${n++}`);
  fsn.mkdirSync(d, { mode: 0o700 });
  return fsn.realpathSync(d);
};
const dummyKey = () => `mrw_dummy_${randomBytes(12).toString('hex')}`;
const uid = process.getuid();

// Evidence items that can be planted as files (+ argv marker).
const ITEMS = {
  env: (h) => { fsn.mkdirSync(`${h}/.marrow`, { recursive: true, mode: 0o700 }); fsn.writeFileSync(`${h}/.marrow/env`, 'X=1\n', { mode: 0o600 }); },
  env_local: (h) => { fsn.mkdirSync(`${h}/.marrow`, { recursive: true, mode: 0o700 }); fsn.writeFileSync(`${h}/.marrow/env.local`, 'X=1\n', { mode: 0o600 }); },
  binding: (h) => { fsn.mkdirSync(`${h}/.marrow/device`, { recursive: true, mode: 0o700 }); fsn.writeFileSync(`${h}/.marrow/device/binding.json`, '{}'); },
  claimed: (h) => { fsn.mkdirSync(`${h}/.marrow`, { recursive: true, mode: 0o700 }); fsn.writeFileSync(`${h}/.marrow/claimed`, ''); },
  state: (h) => { fsn.mkdirSync(`${h}/.marrow/host-approvals`, { recursive: true, mode: 0o700 }); fsn.writeFileSync(`${h}/.marrow/host-approvals/state.json`, '{}'); },
  spool: (h) => { fsn.mkdirSync(`${h}/.marrow/spool`, { recursive: true, mode: 0o700 }); fsn.writeFileSync(`${h}/.marrow/spool/mcp-abc.json`, '[]'); },
  salt: (h) => { fsn.mkdirSync(`${h}/.marrow/runner-holds`, { recursive: true, mode: 0o700 }); fsn.writeFileSync(`${h}/.marrow/runner-holds/.salt`, 'x'); },
  hookcfg: (h) => { fsn.mkdirSync(`${h}/.claude`, { recursive: true }); fsn.writeFileSync(`${h}/.claude/settings.json`, JSON.stringify({ hooks: { PreToolUse: [{ hooks: [{ command: 'marrow-mcp pre-action-hook --claimed' }] }] } })); },
};
const NAMES = [...Object.keys(ITEMS), 'argv'];
const modeFor = (home, set, extra = {}) => resolveSeatbeltModeOnHost({
  fs: nodeSeatbeltFs(), passwdHome: home, uid, env: extra.env || {},
  argv: ['pre-action-hook', ...(set.includes('argv') ? ['--claimed'] : [])],
});

test('M1 every subset of 9 evidence items (512): seatbelt only for the empty set (real fs)', () => {
  const bad = [];
  for (let mask = 0; mask < 1 << NAMES.length; mask += 1) {
    const set = NAMES.filter((_, i) => mask & (1 << i));
    const h = fresh();
    for (const name of set) if (ITEMS[name]) ITEMS[name](h);
    const m = modeFor(h, set).mode;
    if ((set.length === 0) !== (m === 'seatbelt')) bad.push(`${set.join('+')}=>${m}`);
  }
  assert.deepEqual(bad, []);
});

test('M2 env claims cannot select seatbelt on a claimed home', () => {
  const h = fresh();
  ITEMS.claimed(h);
  const env = { MARROW_MODE: 'seatbelt', MARROW_SEATBELT: '1', MARROW_CLAIMED: '0', MARROW_SEATBELT_STRICT: '0', MARROW_HOME: fresh(), HOME: fresh(), USER: 'nobody', XDG_CONFIG_HOME: fresh(), XDG_DATA_HOME: fresh(), MARROW_NO_ACCOUNT: '1', MARROW_UNCLAIMED: '1' };
  assert.notEqual(modeFor(h, [], { env }).mode, 'seatbelt');
});

test('M3 HOME env pointing at a claimed home while passwd home is clean -> must be stricter than seatbelt', () => {
  const passwd = fresh();
  const envHome = fresh();
  ITEMS.claimed(envHome);
  ITEMS.binding(envHome);
  ITEMS.hookcfg(envHome);
  const m = modeFor(passwd, [], { env: { HOME: envHome } }).mode;
  assert.notEqual(m, 'seatbelt', `HOME=${'<tmp claimed home>'} passwd=<clean> gave ${m}`);
});

test('M3b HOME env with a trusted owner key file (0600) while passwd home is clean -> 3.9.102 would use the key (account); head must not be seatbelt', () => {
  const passwd = fresh();
  const envHome = fresh();
  fsn.mkdirSync(`${envHome}/.marrow`, { mode: 0o700 });
  fsn.writeFileSync(`${envHome}/.marrow/env`, `MARROW_API_KEY=${dummyKey()}\n`, { mode: 0o600 });
  const m = modeFor(passwd, [], { env: { HOME: envHome } }).mode;
  assert.notEqual(m, 'seatbelt');
});

test('M3c CODEX_HOME / CLAUDE_CONFIG_DIR relocated hook config carrying --claimed is a witness (clean ~/.marrow)', () => {
  const passwd = fresh();
  const codex = fresh();
  fsn.writeFileSync(`${codex}/hooks.json`, JSON.stringify({ hooks: { PreToolUse: [{ command: 'marrow-mcp codex-pre-action-hook --claimed' }] } }));
  const m = modeFor(passwd, [], { env: { CODEX_HOME: codex } }).mode;
  assert.notEqual(m, 'seatbelt');
});

test('M4 planted repo .env/.marrow (A18) with cwd = repo: ignored, never account', () => {
  const passwd = fresh();
  const repo = fresh();
  fsn.mkdirSync(`${repo}/.marrow`);
  for (const f of ['.env', '.env.local', '.marrow/env', '.marrow/env.local']) fsn.writeFileSync(`${repo}/${f}`, `MARROW_API_KEY=${dummyKey()}\nMARROW_BASE_URL=https://attacker.example.invalid\n`, { mode: 0o600 });
  fsn.writeFileSync(`${repo}/.marrow/claimed`, '');
  const old = process.cwd();
  process.chdir(repo);
  try {
    assert.equal(modeFor(passwd, []).mode, 'seatbelt');
    ITEMS.claimed(passwd);
    assert.equal(modeFor(passwd, []).mode, 'claimed_no_key');
  } finally { process.chdir(old); }
});

const notSeatbelt = (h, label) => { const r = modeFor(h, []); assert.notEqual(r.mode, 'seatbelt', `${label}: ${r.mode}`); };

test('M5 unreadable ~/.marrow (0000) -> stricter', () => {
  const h = fresh(); fsn.mkdirSync(`${h}/.marrow`, { mode: 0o700 }); fsn.chmodSync(`${h}/.marrow`, 0o000);
  try { notSeatbelt(h, 'unreadable'); } finally { fsn.chmodSync(`${h}/.marrow`, 0o700); }
});
test('M5 ~/.marrow 0300 (no read, has exec) with only a spool file -> stricter', () => {
  const h = fresh(); ITEMS.spool(h); fsn.chmodSync(`${h}/.marrow/spool`, 0o300);
  try { notSeatbelt(h, 'spool unreadable'); } finally { fsn.chmodSync(`${h}/.marrow/spool`, 0o700); }
});
test('M5 oversize hook config (>1 MB, no marker) -> stricter', () => {
  const h = fresh(); fsn.mkdirSync(`${h}/.claude`); fsn.writeFileSync(`${h}/.claude/settings.json`, ' '.repeat(1024 * 1024 + 10)); notSeatbelt(h, 'oversize');
});
test('M5 FIFO as hook config and as ~/.marrow/env -> stricter, no hang', () => {
  const h = fresh(); fsn.mkdirSync(`${h}/.codex`); execFileSync('mkfifo', [`${h}/.codex/hooks.json`]); notSeatbelt(h, 'fifo hook');
  const h2 = fresh(); fsn.mkdirSync(`${h2}/.marrow`, { mode: 0o700 }); execFileSync('mkfifo', [`${h2}/.marrow/env`]); notSeatbelt(h2, 'fifo env');
});
test('M5 symlinked ~/.marrow, dangling symlinked evidence, symlinked hook config dir -> stricter', () => {
  const h = fresh(); const t = fresh(); fsn.symlinkSync(t, `${h}/.marrow`); notSeatbelt(h, 'marrow symlink');
  const h2 = fresh(); fsn.mkdirSync(`${h2}/.marrow`, { mode: 0o700 }); fsn.symlinkSync('/nonexistent/x', `${h2}/.marrow/claimed`); notSeatbelt(h2, 'dangling claimed');
  const h3 = fresh(); const t3 = fresh(); fsn.writeFileSync(`${t3}/settings.json`, '{"c":"x --claimed"}'); fsn.symlinkSync(t3, `${h3}/.claude`); notSeatbelt(h3, 'claude dir symlink with marker');
});
test('M5 group/world-writable ~/.marrow -> stricter', () => {
  for (const mode of [0o770, 0o777, 0o702]) { const h = fresh(); fsn.mkdirSync(`${h}/.marrow`); fsn.chmodSync(`${h}/.marrow`, mode); notSeatbelt(h, `mode ${mode.toString(8)}`); }
});
test('M5 world-writable subdir ~/.marrow/device (others can delete binding.json) -> stricter', () => {
  const h = fresh(); fsn.mkdirSync(`${h}/.marrow/device`, { recursive: true }); fsn.chmodSync(`${h}/.marrow`, 0o700); fsn.chmodSync(`${h}/.marrow/device`, 0o777);
  notSeatbelt(h, 'world-writable device dir');
});
test('M5 group/world-writable home dir itself (others can rename ~/.marrow) -> stricter', () => {
  const h = fresh(); fsn.chmodSync(h, 0o777);
  try { notSeatbelt(h, 'world-writable home'); } finally { fsn.chmodSync(h, 0o700); }
});
test('M5 foreign-owned ~/.marrow and foreign-owned home (fake fs, uid mismatch) -> stricter', () => {
  const f = createFakeFs({ uid: 1000 });
  f.mkdir('/home/u', { uid: 1000, mode: 0o755 }).mkdir('/home/u/.marrow', { uid: 0, mode: 0o755 });
  assert.notEqual(resolveSeatbeltMode({ fs: f, passwdHome: '/home/u', argv: [], key: 'none', uid: 1000 }).mode, 'seatbelt');
  const g = createFakeFs({ uid: 1000 });
  g.mkdir('/home/u', { uid: 4242, mode: 0o755 });
  assert.notEqual(resolveSeatbeltMode({ fs: g, passwdHome: '/home/u', argv: [], key: 'none', uid: 1000 }).mode, 'seatbelt', 'home owned by another uid');
});

test('M6 TOCTOU: evidence flapping under a concurrent writer while another item stays -> never seatbelt (2000 runs)', async () => {
  const h = fresh(); ITEMS.env(h); ITEMS.claimed(h);
  const child = spawn('bash', ['-c', `while :; do rm -f '${h}/.marrow/claimed'; : > '${h}/.marrow/claimed'; rm -rf '${h}/.marrow/device'; mkdir -p '${h}/.marrow/device'; done`], { stdio: 'ignore' });
  try {
    let seat = 0;
    for (let i = 0; i < 2000; i += 1) if (modeFor(h, []).mode === 'seatbelt') seat += 1;
    assert.equal(seat, 0);
  } finally { child.kill('SIGTERM'); }
});

test('M6b TOCTOU: ~/.marrow swapped dir<->symlink during resolution with only one evidence item; count seatbelt answers (residual = deletion)', async () => {
  const h = fresh(); const empty = fresh(); ITEMS.claimed(h);
  fsn.renameSync(`${h}/.marrow`, `${h}/.marrow-real`); fsn.symlinkSync('.marrow-real', `${h}/.marrow`);
  const child = spawn('bash', ['-c', `cd '${h}'; while :; do ln -sfn '${empty}' .marrow.tmp && mv -T .marrow.tmp .marrow; ln -sfn .marrow-real .marrow.tmp && mv -T .marrow.tmp .marrow; done`], { stdio: 'ignore' });
  let seat = 0;
  try { for (let i = 0; i < 2000; i += 1) if (modeFor(h, []).mode === 'seatbelt') seat += 1; } finally { child.kill('SIGTERM'); }
  console.log(`# M6b seatbelt answers under symlink swap: ${seat}/2000`);
  assert.equal(seat, 0);
});

test('M7 contradictory: --home differs from passwd; repeated --home; --home= empty; key rejected', () => {
  const a = fresh(); const b = fresh();
  const r = (argv, extra = {}) => resolveSeatbeltModeOnHost({ fs: nodeSeatbeltFs(), passwdHome: a, uid, env: {}, argv, ...extra }).mode;
  assert.equal(r(['--home', b]), 'claimed_no_key');
  assert.equal(r(['--home', a, '--home', b]), 'claimed_no_key');
  assert.equal(r(['--home=']), 'claimed_no_key');
  assert.equal(resolveSeatbeltModeOnHost({ fs: nodeSeatbeltFs(), passwdHome: a, uid, env: { MARROW_API_KEY: dummyKey() }, argv: [], keyRejected: true }).mode, 'claimed_no_key');
});

test('M8 ratchet: project/env actions cannot clear claimed evidence', () => {
  const h = fresh(); ITEMS.claimed(h);
  const repo = fresh();
  fsn.writeFileSync(`${repo}/.env`, 'MARROW_SEATBELT_STRICT=0\nMARROW_MODE=seatbelt\n');
  const old = process.cwd(); process.chdir(repo);
  try {
    for (const env of [{}, { MARROW_SEATBELT_STRICT: '0' }, { HOME: repo }, { MARROW_API_KEY: '' }, { MARROW_KEY: ' ' }])
      assert.notEqual(modeFor(h, [], { env }).mode, 'seatbelt', JSON.stringify(Object.keys(env)));
  } finally { process.chdir(old); }
});

test('M9 passwd home "/" (service user) or a world-writable passwd home -> stricter', () => {
  const r = resolveSeatbeltMode({ fs: createFakeFs().mkdir('/x'), passwdHome: '/', argv: [], key: 'none', uid: 1000 });
  assert.notEqual(r.mode, 'seatbelt', `home=/ gave ${r.mode}`);
});

test.after(() => { try { execFileSync('chmod', ['-R', 'u+rwx', ROOT]); fsn.rmSync(ROOT, { recursive: true, force: true }); } catch {} });
