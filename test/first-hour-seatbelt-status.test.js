'use strict';

// `marrow-mcp seatbelt-status` (FH-3s): one JSON line for the installer's doctor. Read-only, offline,
// and it names nothing but fixed codes. Every run here uses a throwaway home that is also the passwd
// home (test/support/seatbelt-hook-preload.cjs); the real home is never probed.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const PRELOAD = path.join(__dirname, 'support', 'seatbelt-hook-preload.cjs');
const REASONS = ['strict', 'key_rejected', 'home_unknown', 'home_unusable', 'env_home_unusable', 'home_mismatch', 'account_evidence', 'evidence_unknown'];

function sandbox() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-status-')));
  const home = path.join(root, 'home');
  fs.mkdirSync(home, { mode: 0o700 });
  fs.chmodSync(home, 0o700);
  return { root, home, cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}

// Every file under a folder with its mode and bytes, so a write of any kind shows.
function snapshot(dir) {
  const out = {};
  const walk = (current) => {
    for (const name of fs.readdirSync(current).sort()) {
      const file = path.join(current, name);
      const stat = fs.lstatSync(file);
      const rel = path.relative(dir, file);
      if (stat.isDirectory()) { out[rel] = `dir ${(stat.mode & 0o777).toString(8)}`; walk(file); }
      else out[rel] = `${(stat.mode & 0o777).toString(8)} ${stat.isSymbolicLink() ? 'link' : fs.readFileSync(file).toString('base64')}`;
    }
  };
  walk(dir);
  return out;
}

function status(sb, { env = {}, homeEnv, extraArgs = [] } = {}) {
  const net = path.join(sb.root, 'net.log');
  const result = spawnSync(process.execPath, ['--require', PRELOAD, CLI, 'seatbelt-status', ...extraArgs], {
    cwd: sb.home, encoding: 'utf8', timeout: 30_000, input: '',
    env: { PATH: process.env.PATH, HOME: homeEnv ?? sb.home, SBT_PASSWD_HOME: sb.home, SBT_NETSPY: net, MARROW_HOOK_BACKGROUND_NUDGE: 'false', ...env },
  });
  assert.equal(result.error, undefined);
  assert.equal(fs.existsSync(net), false, 'the network is never opened');
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

const LINE = /^\{"mode":"(seatbelt|claimed_no_key|account|unknown)","reasons":\[("[a-z_]+"(,"[a-z_]+")*)?\]\}\n$/;

test('FH-3s: a clean home is seatbelt with no reasons; the output is one line of JSON, exit 0', () => {
  const sb = sandbox();
  try {
    const out = status(sb);
    assert.equal(out.status, 0);
    assert.equal(out.stdout, '{"mode":"seatbelt","reasons":[]}\n');
    assert.equal(out.stderr, '');
    assert.match(out.stdout, LINE);
  } finally { sb.cleanup(); }
});

test('FH-3s: the mode and reasons follow the same resolution the hook uses', () => {
  const rows = [
    ['strict', (sb) => ({ env: { MARROW_SEATBELT_STRICT: '1' } }), 'claimed_no_key', ['strict']],
    ['HOME that is not the passwd home', (sb) => ({ homeEnv: fs.mkdtempSync(path.join(sb.root, 'other-')) }), 'claimed_no_key', ['home_mismatch']],
    ['HOME that is missing', (sb) => ({ homeEnv: path.join(sb.root, 'gone') }), 'claimed_no_key', ['env_home_unusable']],
    ['account evidence', (sb) => { fs.mkdirSync(path.join(sb.home, '.marrow'), { mode: 0o700 }); fs.writeFileSync(path.join(sb.home, '.marrow', 'claimed'), ''); return {}; }, 'claimed_no_key', ['account_evidence']],
    ['a world-writable ~/.claude', (sb) => { fs.mkdirSync(path.join(sb.home, '.claude')); fs.chmodSync(path.join(sb.home, '.claude'), 0o777); return {}; }, 'claimed_no_key', ['evidence_unknown']],
    ['a key in the environment', (sb) => ({ env: { MARROW_API_KEY: `mrw_test_${crypto.randomBytes(8).toString('hex')}` } }), 'account', []],
  ];
  for (const [label, setup, mode, reasons] of rows) {
    const sb = sandbox();
    try {
      const out = status(sb, setup(sb));
      assert.equal(out.status, 0, label);
      assert.deepEqual(JSON.parse(out.stdout), { mode, reasons }, label);
      assert.match(out.stdout, LINE, label);
    } finally { sb.cleanup(); }
  }
});

test('FH-3s: the rollout table is honoured (keyless off = the stricter mode, as the hook)', () => {
  const sb = sandbox();
  try {
    const out = status(sb, { env: { SBT_ROLLOUT_KEYLESS: 'off' } });
    assert.deepEqual(JSON.parse(out.stdout), { mode: 'claimed_no_key', reasons: [] });
  } finally { sb.cleanup(); }
});

test('FH-3s: it writes nothing, anywhere under the home, in any state', () => {
  for (const prepare of [() => {}, (sb) => { fs.mkdirSync(path.join(sb.home, '.marrow', 'host-approvals'), { recursive: true, mode: 0o700 }); fs.writeFileSync(path.join(sb.home, '.marrow', 'host-approvals', 'state.json'), '{}\n', { mode: 0o600 }); }, (sb) => fs.chmodSync(sb.home, 0o777)]) {
    const sb = sandbox();
    try {
      prepare(sb);
      const before = snapshot(sb.root);
      status(sb);
      status(sb, { env: { MARROW_SEATBELT_STRICT: '1' } });
      assert.deepEqual(snapshot(sb.root), before);
    } finally { sb.cleanup(); }
  }
});

test('FH-3s: the output is byte-identical when only a secret value differs, and never holds a value, path or user name', () => {
  const sb = sandbox();
  try {
    const one = status(sb, { env: { MARROW_API_KEY: `mrw_test_${crypto.randomBytes(16).toString('hex')}` } });
    const secretTwo = `mrw_test_${crypto.randomBytes(16).toString('hex')}`;
    const two = status(sb, { env: { MARROW_API_KEY: secretTwo, MARROW_SESSION_ID: `sess-${crypto.randomBytes(6).toString('hex')}` } });
    assert.equal(one.stdout, two.stdout);
    assert.equal(two.stdout.includes(secretTwo), false);
    for (const out of [one, two, status(sb), status(sb, { homeEnv: path.join(sb.root, 'gone') })]) {
      assert.equal(out.stdout.includes(sb.root), false);
      assert.equal(out.stdout.includes(os.userInfo().username), false);
      assert.equal(out.stdout.includes('/'), false);
      assert.match(out.stdout, LINE);
      for (const code of JSON.parse(out.stdout).reasons) assert.ok(REASONS.includes(code), code);
    }
  } finally { sb.cleanup(); }
});

test('FH-3s: an internal error prints the unknown line and still exits 0', () => {
  const sb = sandbox();
  try {
    const out = status(sb, { env: { SBT_THROW: 'mode' } });
    assert.equal(out.status, 0);
    assert.equal(out.stdout, '{"mode":"unknown","reasons":[]}\n');
    const load = status(sb, { env: { SBT_THROW: 'load' } });
    assert.equal(load.status, 0);
    assert.equal(load.stdout, '{"mode":"unknown","reasons":[]}\n');
  } finally { sb.cleanup(); }
});

test('FH-3s: it starts nothing else, takes no input and ignores extra arguments', () => {
  const sb = sandbox();
  try {
    const out = status(sb, { extraArgs: ['--home', path.join(sb.root, 'elsewhere'), '--key', 'ignored', '-h'] });
    assert.equal(out.status, 0);
    assert.equal(out.stdout, '{"mode":"seatbelt","reasons":[]}\n');
    assert.equal(out.stderr, '');
    // The help text does not list it: it is for the installer's doctor, not a user feature.
    const help = spawnSync(process.execPath, [CLI, '--help'], { encoding: 'utf8', env: { PATH: process.env.PATH, HOME: sb.home } });
    assert.equal(help.stdout.includes('seatbelt-status'), false);
  } finally { sb.cleanup(); }
});
