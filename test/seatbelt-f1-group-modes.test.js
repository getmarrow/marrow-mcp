'use strict';

// F1 (host matrix 10-13): umask 002 / user-private-group machines. A group-writable home or evidence
// dir is accepted only when its group is the owner's private group (Debian OpenSSH
// "user-group-modes"); every other case keeps the U4 answer. A mode fallback never says "linked to
// an account". Fake fs for the account files; real fs for symlinks, hard links and the hook CLI.
// No keys anywhere; no network.
const test = require('node:test');
const assert = require('node:assert/strict');
const fsn = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync, spawn, execFileSync } = require('node:child_process');

const { createFakeFs } = require('./support/seatbelt-fake-fs.cjs');
const { nodeSeatbeltFs } = require('../dist/seatbelt-fs.js');
const { resolveSeatbeltMode, resolveSeatbeltModeOnHost, privateGroupId } = require('../dist/seatbelt-mode.js');
const seatbeltHook = require('../dist/seatbelt/hook.js');
const preAction = require('../dist/hook-pre-action.js');

const UID = 1000;
const GID = 1000;
const HOME = '/home/u';
const NSS = 'passwd: files systemd\ngroup: files systemd\nshadow: files\nhosts: files dns\n';
const PASSWD = 'root:x:0:0:root:/root:/bin/bash\nu:x:1000:1000:U:/home/u:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n';
const GROUP = 'root:x:0:\nsudo:x:27:u\nu:x:1000:\nnogroup:x:65534:\n';

// A Ubuntu-like machine: umask 002 made the home and ~/.claude 0775, group = the owner's private group.
function machine({ nss = NSS, passwd = PASSWD, group = GROUP, homeMode = 0o775, claudeMode = 0o775, claudeGid = GID, claudeUid = UID, etc = {} } = {}) {
  const f = createFakeFs({ uid: UID });
  const sys = { uid: 0, mode: 0o644 };
  if (nss !== null) f.file('/etc/nsswitch.conf', nss, { ...sys, ...(etc.nss || {}) });
  if (passwd !== null) f.file('/etc/passwd', passwd, { ...sys, ...(etc.passwd || {}) });
  if (group !== null) f.file('/etc/group', group, { ...sys, ...(etc.group || {}) });
  f.mkdir('/home', { uid: 0, mode: 0o755 });
  f.mkdir(HOME, { uid: UID, gid: GID, mode: homeMode });
  if (claudeMode !== null) f.mkdir(`${HOME}/.claude`, { uid: claudeUid, gid: claudeGid, mode: claudeMode });
  return f;
}
const resolve = (f, extra = {}) => resolveSeatbeltMode({
  fs: f, passwdHome: HOME, argv: ['claude-pre-action-hook'], key: 'none', uid: UID, privateGid: () => privateGroupId(f, UID), ...extra,
});
const modeOf = (f, extra) => resolve(f, extra).mode;

test('F1 fix: home and ~/.claude 0775 with the owner\'s private group -> seatbelt (was claimed_no_key)', () => {
  assert.equal(privateGroupId(machine(), UID), GID);
  assert.equal(modeOf(machine()), 'seatbelt');
  // The U4 answer without the allowance (no group database): unchanged.
  assert.equal(resolveSeatbeltMode({ fs: machine(), passwdHome: HOME, argv: [], key: 'none', uid: UID }).mode, 'claimed_no_key');
  // The owner named as the only supplementary member of its own group is still private.
  assert.equal(modeOf(machine({ group: GROUP.replace('u:x:1000:', 'u:x:1000:u') })), 'seatbelt');
  // 0770 / 2775 (setgid) are group-only too.
  assert.equal(modeOf(machine({ homeMode: 0o770, claudeMode: 0o2775 })), 'seatbelt');
  // Account evidence still wins: never seatbelt.
  assert.equal(modeOf(machine().file(`${HOME}/.marrow/claimed`, '', { uid: UID })), 'claimed_no_key');
  assert.equal(modeOf(machine().file(`${HOME}/.claude/settings.json`, '{"c":"marrow-mcp pre-action-hook --claimed"}', { uid: UID })), 'claimed_no_key');
});

test('F1 abuse: the group has another member -> claimed_no_key', () => {
  for (const line of ['u:x:1000:bob', 'u:x:1000:u,bob', 'u:x:1000:bob,u', 'u:x:1000: u , bob ']) {
    assert.equal(modeOf(machine({ group: GROUP.replace('u:x:1000:', line) })), 'claimed_no_key', line);
  }
});

test('F1 abuse: another passwd entry has the same primary gid -> claimed_no_key', () => {
  for (const extra of ['bob:x:1001:1000:Bob:/home/bob:/bin/sh\n', 'svc:x:999:1000::/var/svc:/usr/sbin/nologin\n', 'u2:x:1000:1000:alias of u:/home/u:/bin/sh\n']) {
    assert.equal(modeOf(machine({ passwd: PASSWD + extra })), 'claimed_no_key', extra.trim());
  }
});

test('F1 abuse: world-writable (any bit 0o002) -> claimed_no_key, private group or not', () => {
  for (const [homeMode, claudeMode] of [[0o777, 0o755], [0o755, 0o777], [0o757, 0o755], [0o755, 0o773], [0o1777, 0o755]]) {
    assert.equal(modeOf(machine({ homeMode, claudeMode })), 'claimed_no_key', `${homeMode.toString(8)} ${claudeMode.toString(8)}`);
  }
});

test('F1 abuse: another owner, another group, root -> claimed_no_key', () => {
  assert.equal(modeOf(machine({ claudeUid: 4242 })), 'claimed_no_key', 'dir owned by another uid');
  assert.equal(modeOf(machine({ claudeUid: 4242, claudeMode: 0o755 })), 'claimed_no_key', 'other owner, 0755 (U4)');
  assert.equal(modeOf(machine({ claudeGid: 100 })), 'claimed_no_key', 'group users (100), not the private group');
  assert.equal(modeOf(machine({ claudeMode: null }).mkdir(`${HOME}/.claude`, { uid: UID, mode: 0o775 })), 'claimed_no_key', 'entry without a gid');
  const rootBox = machine({ passwd: 'root:x:0:0:root:/root:/bin/bash\n', group: 'root:x:0:\n' });
  assert.equal(privateGroupId(rootBox, 0), null, 'root never gets the allowance');
  const rootOwnGroup = machine({ passwd: 'root:x:0:5000:root:/root:/bin/bash\n', group: 'rootgrp:x:5000:\n' });
  assert.equal(privateGroupId(rootOwnGroup, 0), null, 'root with its own private-looking group: still none');
  assert.equal(privateGroupId(machine(), null), null, 'no uid (Windows)');
});

test('F1 abuse: a symlinked ~/.claude (or one reached through a symlink) keeps the U4 rule', () => {
  const linked = machine({ claudeMode: null }).mkdir(`${HOME}/real-claude`, { uid: UID, gid: GID, mode: 0o775 }).symlink(`${HOME}/.claude`, `${HOME}/real-claude`);
  // The target itself sits in the home: probe it only through the link by moving it out of the home.
  const outside = machine({ claudeMode: null }).mkdir('/srv/claude', { uid: UID, gid: GID, mode: 0o775 }).symlink(`${HOME}/.claude`, '/srv/claude');
  assert.equal(modeOf(outside), 'claimed_no_key', 'symlink to a private-group 0775 dir');
  const outside755 = machine({ claudeMode: null }).mkdir('/srv/claude', { uid: UID, gid: GID, mode: 0o755 }).symlink(`${HOME}/.claude`, '/srv/claude');
  assert.equal(modeOf(outside755), 'seatbelt', 'symlink to a 0755 dir: U4 answer (target judged)');
  const shared = machine({ claudeMode: null }).mkdir('/shared', { uid: UID, gid: 100, mode: 0o777 }).symlink(`${HOME}/.claude`, '/shared');
  assert.equal(modeOf(shared), 'claimed_no_key', 'symlink to a shared dir');
  // In-home target: the link is refused (strict), the real dir itself is private -> still claimed_no_key overall.
  assert.equal(modeOf(linked), 'claimed_no_key', 'symlink inside the home');
  // A symlinked parent (.codeium -> elsewhere): its children are reached through a link -> strict.
  const parent = machine({ claudeMode: 0o755 }).mkdir('/srv/codeium', { uid: UID, gid: GID, mode: 0o755 }).mkdir('/srv/codeium/windsurf', { uid: UID, gid: GID, mode: 0o775 })
    .symlink(`${HOME}/.codeium`, '/srv/codeium');
  assert.equal(modeOf(parent), 'claimed_no_key', 'group-writable dir under a symlinked parent');
});

test('F1 abuse: account files unreadable, unsafe or not local -> claimed_no_key (fail closed)', () => {
  const cases = {
    'no /etc/group': machine({ group: null }),
    'no /etc/passwd': machine({ passwd: null }),
    'no nsswitch.conf': machine({ nss: null }),
    '/etc/group EACCES': machine().fail('/etc/group', 'EACCES'),
    '/etc/passwd EIO': machine().fail('/etc/passwd', 'EIO'),
    '/etc/group not root-owned': machine({ etc: { group: { uid: UID } } }),
    '/etc/group group-writable': machine({ etc: { group: { mode: 0o664 } } }),
    '/etc/passwd world-writable': machine({ etc: { passwd: { mode: 0o666 } } }),
    '/etc/group is a symlink': machine({ group: null }).file('/etc/group.real', GROUP, { uid: 0, mode: 0o644 }).symlink('/etc/group', '/etc/group.real'),
    'NSS ldap for group': machine({ nss: 'passwd: files\ngroup: files ldap\n' }),
    'NSS sss for passwd': machine({ nss: 'passwd: files sss\ngroup: files\n' }),
    'NSS winbind': machine({ nss: 'passwd: files winbind\ngroup: files winbind\n' }),
    'NSS nis with action': machine({ nss: 'passwd: files [NOTFOUND=continue] nis\ngroup: files\n' }),
    'NSS group line missing': machine({ nss: 'passwd: files\n' }),
    'NSS empty source list': machine({ nss: 'passwd:\ngroup: files\n' }),
    'user only in LDAP (no local passwd entry)': machine({ passwd: 'root:x:0:0:root:/root:/bin/bash\n' }),
    'group only in LDAP (no local group entry)': machine({ group: 'root:x:0:\n' }),
    'NIS + line in passwd': machine({ passwd: `${PASSWD}+::::::\n` }),
    'NIS + line in group': machine({ group: `${GROUP}+:::\n` }),
    'NIS +name line with numeric fields': machine({ group: `${GROUP}+nisgroup:x:2000:\n` }),
    'NIS -name line in passwd': machine({ passwd: `${PASSWD}-bob:x:1001:1001::/home/bob:/bin/sh\n` }),
    'comment line in group': machine({ group: `# local\n${GROUP}` }),
    'malformed group line': machine({ group: `${GROUP}broken\n` }),
    'two group entries for the gid': machine({ group: `${GROUP}u2:x:1000:\n` }),
    'two passwd entries for the uid': machine({ passwd: `${PASSWD}toor:x:1000:2000::/home/u:/bin/sh\n` }),
    'private gid 0': machine({ passwd: 'u:x:1000:0:U:/home/u:/bin/bash\n', group: 'root:x:0:\n' }),
    'oversized /etc/group': machine({ group: `${GROUP}${'x'.repeat(4 * 1024 * 1024)}\n` }),
  };
  for (const [name, f] of Object.entries(cases)) {
    assert.equal(privateGroupId(f, UID), null, name);
    assert.equal(modeOf(f), 'claimed_no_key', name);
  }
  // A throwing provider is a refusal too.
  assert.equal(modeOf(machine(), { privateGid: () => { throw new Error('boom'); } }), 'claimed_no_key');
  for (const bad of [0, -1, 1.5, '1000', NaN]) assert.equal(modeOf(machine(), { privateGid: bad }), 'claimed_no_key', String(bad));
});

test('F1 host wiring: the allowance is Linux only and reads the account files lazily (none for 0755 homes)', () => {
  const reads = [];
  const f = machine({ homeMode: 0o755, claudeMode: 0o755 });
  const spy = { ...f, lstat: (p) => { if (p.startsWith('/etc/')) reads.push(p); return f.lstat(p); }, readFile: (p, n) => { if (p.startsWith('/etc/')) reads.push(p); return f.readFile(p, n); } };
  assert.equal(resolveSeatbeltModeOnHost({ fs: spy, passwdHome: HOME, uid: UID, env: {}, argv: [] }).mode, 'seatbelt');
  assert.deepEqual(reads, [], '0755 machine: no account file read');
  const g = machine();
  if (process.platform === 'linux') assert.equal(resolveSeatbeltModeOnHost({ fs: g, passwdHome: HOME, uid: UID, env: {}, argv: [] }).mode, 'seatbelt');
  const real = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { value: 'darwin' });
  try {
    assert.equal(resolveSeatbeltModeOnHost({ fs: machine(), passwdHome: HOME, uid: UID, env: {}, argv: [] }).mode, 'claimed_no_key', 'not Linux: U4 rule');
  } finally { Object.defineProperty(process, 'platform', real); }
});

// Real filesystem: hard links, symlinks and concurrent mode changes. The private group answer is
// injected as this process's gid (the dirs are created with it), so the rows run on any machine.
const ROOT = fsn.realpathSync(fsn.mkdtempSync(path.join(os.tmpdir(), 'marrow-f1-')));
test.after(() => fsn.rmSync(ROOT, { recursive: true, force: true }));
let n = 0;
function realHome(homeMode = 0o775, claudeMode = 0o775) {
  const h = path.join(ROOT, `h${n += 1}`);
  fsn.mkdirSync(h); fsn.chmodSync(h, homeMode);
  if (claudeMode !== null) { fsn.mkdirSync(path.join(h, '.claude')); fsn.chmodSync(path.join(h, '.claude'), claudeMode); }
  return h;
}
const GIDNOW = typeof process.getgid === 'function' ? process.getgid() : null;
const realMode = (h, privateGid = GIDNOW) => resolveSeatbeltModeOnHost({ fs: nodeSeatbeltFs(), passwdHome: h, uid: process.getuid(), env: {}, argv: [], privateGid }).mode;

test('F1 real fs: private-group 0775 home and ~/.claude -> seatbelt; any other group -> claimed_no_key', { skip: process.platform === 'win32' }, () => {
  const h = realHome();
  assert.equal(fsn.statSync(h).gid, GIDNOW);
  assert.equal(realMode(h), 'seatbelt');
  assert.equal(realMode(h, GIDNOW + 7919), 'claimed_no_key');
  assert.equal(realMode(h, null), 'claimed_no_key');
});

test('F1 abuse (real fs): hard-linked hook config gives the same answer as under 0755', { skip: process.platform === 'win32' }, () => {
  const marked = path.join(ROOT, `cfg-marked-${n}`); fsn.writeFileSync(marked, '{"c":"marrow-mcp pre-action-hook --claimed"}');
  const plain = path.join(ROOT, `cfg-plain-${n}`); fsn.writeFileSync(plain, '{"c":"marrow-mcp pre-action-hook"}');
  for (const [src, want] of [[marked, 'claimed_no_key'], [plain, 'seatbelt']]) {
    for (const modes of [[0o755, 0o755], [0o775, 0o775]]) {
      const h = realHome(...modes);
      fsn.linkSync(src, path.join(h, '.claude', 'settings.json'));
      assert.equal(fsn.statSync(path.join(h, '.claude', 'settings.json')).nlink >= 2, true);
      assert.equal(realMode(h), want, `${path.basename(src)} ${modes.map((m) => m.toString(8))}`);
    }
  }
});

test('F1 abuse (real fs): symlinked ~/.claude to a private-group 0775 dir -> claimed_no_key; to 0755 -> seatbelt (U4)', { skip: process.platform === 'win32' }, () => {
  const t775 = path.join(ROOT, `t775-${n}`); fsn.mkdirSync(t775); fsn.chmodSync(t775, 0o775);
  const t755 = path.join(ROOT, `t755-${n}`); fsn.mkdirSync(t755); fsn.chmodSync(t755, 0o755);
  const a = realHome(0o775, null); fsn.symlinkSync(t775, path.join(a, '.claude'));
  assert.equal(realMode(a), 'claimed_no_key');
  const b = realHome(0o775, null); fsn.symlinkSync(t755, path.join(a === b ? b : b, '.claude'));
  assert.equal(realMode(b), 'seatbelt');
});

test('F1 TOCTOU (real fs): ~/.claude flapping 0775 <-> 0777 never crashes; with a claimed marker never seatbelt (1500 runs)', { skip: process.platform === 'win32' }, async () => {
  const h = realHome();
  const c = path.join(h, '.claude');
  const child = spawn('bash', ['-c', `while :; do chmod 0777 '${c}'; chmod 0775 '${c}'; done`], { stdio: 'ignore' });
  try {
    const seen = new Set();
    for (let i = 0; i < 1500; i += 1) seen.add(realMode(h));
    for (const m of seen) assert.ok(['seatbelt', 'claimed_no_key'].includes(m));
    fsn.mkdirSync(path.join(h, '.marrow'), { mode: 0o700 }); fsn.writeFileSync(path.join(h, '.marrow', 'claimed'), '');
    let seat = 0;
    for (let i = 0; i < 1500; i += 1) if (realMode(h) === 'seatbelt') seat += 1;
    assert.equal(seat, 0);
  } finally { child.kill('SIGTERM'); }
});

test('F1 text: a mode fallback never says "linked to an account"; account evidence still does', () => {
  assert.equal(seatbeltHook.SETUP_UNCONFIRMED_TEXT, preAction.SETUP_UNCONFIRMED_TEXT);
  assert.equal(seatbeltHook.CLAIMED_NO_KEY_TEXT, preAction.CLAIMED_NO_KEY_TEXT);
  assert.doesNotMatch(preAction.SETUP_UNCONFIRMED_TEXT, /linked to an account/);
  const fallback = seatbeltHook.seatbeltStopText('S1', 'S1.force_push', 'protected_branch', 'claimed_no_key', false);
  assert.doesNotMatch(fallback, /linked to an account/);
  assert.ok(fallback.endsWith(`${preAction.SETUP_UNCONFIRMED_TEXT} Code: S1.force_push/protected_branch.`));
  assert.ok(seatbeltHook.seatbeltStopText('S1', 'S1.force_push', 'protected_branch', 'claimed_no_key').endsWith(`${preAction.CLAIMED_NO_KEY_TEXT} Code: S1.force_push/protected_branch.`));
});

// The matrix repro through the real hook CLI: a keyless Claude/Codex/Cursor hook in a 0775 home.
const CLI = path.join(__dirname, '..', 'dist', 'cli.js');
const PRELOAD = path.join(__dirname, 'support', 'seatbelt-hook-preload.cjs');
const ENTRY = { claude: 'claude-pre-action-hook', codex: 'codex-pre-action-hook', cursor: 'cursor-pre-action-hook' };
function cliSandbox(mode) {
  const home = path.join(ROOT, `cli${n += 1}`);
  const proj = path.join(home, 'proj');
  fsn.mkdirSync(proj, { recursive: true });
  for (const d of [home, proj]) fsn.chmodSync(d, mode);
  fsn.mkdirSync(path.join(home, '.claude')); fsn.chmodSync(path.join(home, '.claude'), mode);
  const git = (...args) => execFileSync('git', args, { cwd: proj, env: { PATH: process.env.PATH, HOME: home, GIT_CONFIG_NOSYSTEM: '1' }, stdio: 'ignore' });
  git('init', '-q', '-b', 'feat/x');
  git('remote', 'add', 'origin', 'git@github.com:acme/proj.git');
  git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '--allow-empty', '-m', 'init');
  return { home, proj };
}
function hook(sb, harness, command, extraEnv = {}) {
  const sid = `f1-${crypto.randomBytes(5).toString('hex')}`;
  const event = harness === 'cursor' ? { hook_event_name: 'beforeShellExecution', conversation_id: sid, generation_id: 'g1', command, cwd: sb.proj }
    : { hook_event_name: 'PreToolUse', session_id: sid, tool_use_id: 't1', tool_name: 'Bash', tool_input: { command }, cwd: sb.proj };
  const r = spawnSync(process.execPath, ['--require', PRELOAD, CLI, ENTRY[harness]], {
    cwd: sb.proj, input: JSON.stringify(event), encoding: 'utf8', timeout: 30_000,
    env: { PATH: process.env.PATH, HOME: sb.home, SBT_PASSWD_HOME: sb.home, SBT_NETSPY: path.join(sb.home, 'net.log'), MARROW_HOOK_BACKGROUND_NUDGE: 'false', ...extraEnv },
  });
  let j = null; try { j = r.stdout.trim() ? JSON.parse(r.stdout) : null; } catch { j = null; }
  const permission = j ? (j.permission || j.hookSpecificOutput?.permissionDecision || j.decision || null) : null;
  const text = j ? String(j.agent_message || j.hookSpecificOutput?.permissionDecisionReason || j.reason || '') : '';
  return { decision: r.status === 2 || permission === 'deny' ? 'stop' : 'pass', text };
}

test('F1 matrix repro (CLI): 0775 home on this machine; answers match the private-group verdict, texts never claim an account', { skip: process.platform !== 'linux' }, (t) => {
  const privateHere = privateGroupId(nodeSeatbeltFs(), process.getuid()) === GIDNOW && GIDNOW !== null;
  t.diagnostic(`private group on this machine: ${privateHere}`);
  const sb = cliSandbox(0o775);
  for (const harness of Object.keys(ENTRY)) {
    const s1 = hook(sb, harness, 'git push --force origin main');
    assert.equal(s1.decision, 'stop', `${harness} S1 always stops`);
    const featurePush = hook(sb, harness, 'git push -f origin feat/x');
    const cleanup = hook(sb, harness, 'rm -rf node_modules dist');
    if (privateHere) {
      assert.equal(featurePush.decision, 'pass', `${harness}: private group -> seatbelt passes a feature-branch push`);
      assert.equal(cleanup.decision, 'pass', `${harness}: workspace cleanup passes`);
    } else {
      assert.equal(featurePush.decision, 'stop', `${harness}: not private -> held as before`);
    }
    for (const r of [s1, featurePush, cleanup]) assert.doesNotMatch(r.text, /linked to an account/, `${harness}: no account claim without account evidence`);
  }
  // A fallback without account evidence (strict here, a shared folder elsewhere) holds the same, but never claims an account.
  for (const harness of Object.keys(ENTRY)) {
    const held = hook(sb, harness, 'git push -f origin feat/x', { MARROW_SEATBELT_STRICT: '1' });
    assert.equal(held.decision, 'stop', `${harness} strict holds`);
    assert.match(held.text, /keyless mode is off here/, `${harness} strict text`);
    assert.doesNotMatch(held.text, /linked to an account/, `${harness} strict text`);
    const floor = hook(sb, harness, 'npm publish', { MARROW_SEATBELT_STRICT: '1' });
    assert.equal(floor.decision, 'stop');
    assert.doesNotMatch(floor.text, /linked to an account/, `${harness} strict floor text`);
  }
  // With account evidence the account text stays.
  fsn.mkdirSync(path.join(sb.home, '.marrow'), { recursive: true, mode: 0o700 }); fsn.writeFileSync(path.join(sb.home, '.marrow', 'claimed'), '');
  const claimed = hook(sb, 'claude', 'git push -f origin feat/x');
  assert.equal(claimed.decision, 'stop');
  assert.match(claimed.text, /linked to an account/);
});
