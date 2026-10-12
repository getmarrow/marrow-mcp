const assert = require('node:assert/strict');
const test = require('node:test');
const { mkdtempSync, mkdirSync, symlinkSync, writeFileSync, rmSync, realpathSync, existsSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const { createFakeFs } = require('./support/seatbelt-fake-fs.cjs');
const { nodeSeatbeltFs } = require('../dist/seatbelt-fs.js');
const {
  realPath,
  pathKey,
  expandPathOperand,
  resolveOperand,
  resolveWorkspace,
  classifyDeleteTarget,
} = require('../dist/seatbelt-path.js');

function linuxTree() {
  return createFakeFs()
    .mkdir('/home/u', { mode: 0o700 })
    .file('/home/u/.ssh/id_rsa', 'dummy')
    .file('/home/u/.aws/credentials', 'dummy')
    .mkdir('/work/repo/.git')
    .mkdir('/work/repo/src')
    .mkdir('/work/repo/node_modules')
    .mkdir('/work/other')
    .mkdir('/tmp/build-1')
    .mkdir('/var/tmp')
    .mkdir('/root')
    .symlink('/work/repo/homelink', '/home/u')
    .symlink('/work/repo/awslink', '/home/u/.aws')
    .symlink('/home/u/proj', '/work/repo')
    .symlink('/home/u/projhome', '/home/u');
}

function classify(fs, cwd, raw, extra = {}) {
  const ws = resolveWorkspace(fs, { eventCwd: cwd, home: '/home/u', tmpdir: extra.tmpdir });
  const context = { home: '/home/u', cwd, assignments: extra.assignments, userHome: extra.userHome };
  return classifyDeleteTarget(fs, ws, resolveOperand(fs, context, raw, 'delete'));
}

// T-path-*: the symlink / .. / $HOME matrix on a case-sensitive (Linux) tree.
const MATRIX = [
  ['node_modules', 'in_workspace'],
  ['dist', 'in_workspace'],
  ['../node_modules', 'in_workspace'],
  ['./a/../../..', 'workspace_root'],
  ['..', 'workspace_root'],
  ['.', 'in_workspace'],
  ['../../other', 'outside_workspace'],
  ['../../../work', 'workspace_root'],
  ['~', 'home'],
  ['~/', 'home'],
  ['$HOME', 'home'],
  ['${HOME}/', 'home'],
  ['$HOME/.ssh', 'outside_workspace'],
  ['~${EMPTY}/', 'unknown'],
  ['$DIR/', 'unknown'],
  ['../homelink', 'in_workspace'],
  ['../homelink/', 'home'],
  ['../homelink/.', 'home'],
  ['../homelink/*', 'home'],
  ['../awslink/', 'outside_workspace'],
  ['/', 'root'],
  ['//', 'root'],
  ['/./', 'root'],
  ['/tmp/build-1', 'in_workspace'],
  ['/tmp', 'workspace_root'],
  ['/tmp/*', 'workspace_root'],
  ['/var/tmp/x', 'in_workspace'],
  ['/proc/self/root/home/u', 'home'],
  ['/proc/1/root/', 'root'],
  ['/proc/self/cwd/x', 'unknown'],
  ['/dev/fd/3', 'unknown'],
  ['nöde_modules', 'unknown'],
  ['.ѕsh', 'unknown'],
  ['$(pwd)/x', 'unknown'],
  ['`pwd`', 'unknown'],
  ['{a,/}', 'unknown'],
  ['node_modules/*/../../..', 'unknown'],
  ['../*', 'workspace_root'],
  ['./*', 'in_workspace'],
  ['node_modules/*', 'in_workspace'],
  ['~root/x', 'unknown'],
  ['~+/dist', 'in_workspace'],
  ['~-/x', 'unknown'],
  ['$1', 'unknown'],
  ['${DIR:-/}', 'unknown'],
];

for (const [raw, expected] of MATRIX) {
  test(`T-path matrix (linux tree, cwd=/work/repo/src): rm -r ${raw} -> ${expected}`, () => {
    assert.equal(classify(linuxTree(), '/work/repo/src', raw), expected);
  });
}

test('T-path: same-command assignments resolve, unset ones stay unknown', () => {
  const fs = linuxTree();
  assert.equal(classify(fs, '/work/repo', '$DIR/', { assignments: { DIR: 'dist' } }), 'in_workspace');
  assert.equal(classify(fs, '/work/repo', '$DIR', { assignments: { DIR: '/home/u' } }), 'home');
  assert.equal(classify(fs, '/work/repo', '$DIR', { assignments: { DIR: '' } }), 'unknown');
});

test('T-path: ~user only through the passwd lookup', () => {
  const fs = linuxTree();
  assert.equal(classify(fs, '/work/repo', '~root/x', { userHome: (u) => (u === 'root' ? '/root' : null) }), 'outside_workspace');
  assert.equal(classify(fs, '/work/repo', '~nobody/x', { userHome: () => null }), 'unknown');
});

test('A19: no or relative event cwd makes every recursive delete target unknown', () => {
  const fs = linuxTree();
  for (const cwd of [null, undefined, '', 'work/repo', 42]) {
    const ws = resolveWorkspace(fs, { eventCwd: cwd, home: '/home/u' });
    assert.equal(ws.known, false);
    for (const raw of ['node_modules', '/tmp/build-1', '/work/repo/dist']) {
      assert.equal(classifyDeleteTarget(fs, ws, resolveOperand(fs, { home: '/home/u', cwd: null }, raw, 'delete')), 'unknown');
    }
  }
});

test('F3: the workspace comes from the event cwd, never the hook process cwd', () => {
  const fs = linuxTree();
  const ws = resolveWorkspace(fs, { eventCwd: '/work/other', home: '/home/u' });
  assert.deepEqual(ws.roots, ['/work/other']);
  assert.notEqual(ws.roots[0], process.cwd());
  assert.equal(classify(fs, '/work/other', '/work/repo/node_modules'), 'outside_workspace');
});

test('symlink of a project dir into $HOME: ~/proj resolves to the real repo; a link to $HOME itself is never a workspace', () => {
  const fs = linuxTree();
  assert.deepEqual(resolveWorkspace(fs, { eventCwd: '/home/u/proj/src', home: '/home/u' }).roots, ['/work/repo']);
  assert.equal(classify(fs, '/home/u/proj/src', 'node_modules'), 'in_workspace');
  assert.equal(classify(fs, '/home/u/proj/src', '~/proj/node_modules'), 'in_workspace');
  const linked = resolveWorkspace(fs, { eventCwd: '/home/u/projhome', home: '/home/u' });
  assert.deepEqual(linked.roots, []);
  assert.equal(linked.reason, 'home_or_ancestor');
  assert.equal(classify(fs, '/home/u/projhome', 'node_modules'), 'outside_workspace');
  assert.equal(classify(fs, '/home/u/projhome', '.'), 'home');
});

test('a git repo at $HOME (dotfiles) never makes home the workspace', () => {
  const fs = linuxTree().mkdir('/home/u/.git').mkdir('/home/u/notes');
  assert.deepEqual(resolveWorkspace(fs, { eventCwd: '/home/u/notes', home: '/home/u' }).roots, ['/home/u/notes']);
  assert.equal(classify(fs, '/home/u/notes', 'x'), 'in_workspace');
  assert.equal(classify(fs, '/home/u/notes', '..'), 'home');
  assert.equal(classify(fs, '/home/u/notes', '../.ssh'), 'outside_workspace');
  assert.deepEqual(resolveWorkspace(fs, { eventCwd: '/home/u', home: '/home/u' }).roots, []);
  assert.deepEqual(resolveWorkspace(fs, { eventCwd: '/', home: '/home/u' }).roots, []);
});

test('TMPDIR can only add a system temp dir, never widen the workspace (env cannot change WS)', () => {
  const fs = linuxTree().mkdir('/var/folders/ab/T');
  assert.equal(classify(fs, '/work/repo', '/work/other/x', { tmpdir: '/work/other' }), 'outside_workspace');
  assert.equal(classify(fs, '/work/repo', '/home/u/x', { tmpdir: '/home/u' }), 'outside_workspace');
  assert.equal(classify(fs, '/work/repo', '/var/folders/ab/T/x', { tmpdir: '/var/folders/ab/T' }), 'in_workspace');
  assert.equal(classify(fs, '/work/repo', '/var/folders/ab/T', { tmpdir: '/var/folders/ab/T' }), 'workspace_root');
});

test('a home under /tmp keeps /tmp from covering it', () => {
  const fs = createFakeFs().mkdir('/tmp/h/.ssh').mkdir('/tmp/x').mkdir('/work/r/.git');
  const ws = resolveWorkspace(fs, { eventCwd: '/work/r', home: '/tmp/h' });
  assert.ok(!ws.tempRoots.includes('/tmp'));
  const target = resolveOperand(fs, { home: '/tmp/h', cwd: '/work/r' }, '/tmp/h/.ssh', 'delete');
  assert.equal(classifyDeleteTarget(fs, ws, target), 'outside_workspace');
});

test('symlink loops and unreadable components are unknown', () => {
  const fs = linuxTree().symlink('/work/repo/a', '/work/repo/b').symlink('/work/repo/b', '/work/repo/a').mkdir('/locked/x').fail('/locked/x');
  assert.deepEqual(realPath(fs, '/work/repo/a/x'), { status: 'unknown', reason: 'loop' });
  assert.deepEqual(realPath(fs, '/locked/x/y'), { status: 'unknown', reason: 'unreadable' });
  assert.equal(classify(fs, '/work/repo', 'a/'), 'unknown');
  assert.deepEqual(realPath(fs, 'relative'), { status: 'unknown', reason: 'not_absolute' });
});

test('read operands follow the final symlink (cat link reads the target)', () => {
  const fs = linuxTree();
  const read = resolveOperand(fs, { home: '/home/u', cwd: '/work/repo' }, 'awslink', 'read');
  assert.deepEqual(read, { kind: 'path', real: '/home/u/.aws', exists: true, nonAscii: false });
  const del = resolveOperand(fs, { home: '/home/u', cwd: '/work/repo' }, 'awslink', 'delete');
  assert.equal(del.real, '/work/repo/awslink');
});

test('$HOME and ~ come from the trusted home, never from an assignment or the process env', () => {
  const saved = process.env.HOME;
  process.env.HOME = '/work/repo';
  try {
    const expanded = expandPathOperand('$HOME/.ssh/id_rsa', { home: '/home/u', cwd: '/work/repo', assignments: { HOME: '/work/repo' } });
    assert.equal(expanded.path, '/home/u/.ssh/id_rsa');
    assert.equal(expandPathOperand('~/.aws', { home: '/home/u', cwd: '/x' }).path, '/home/u/.aws');
    assert.deepEqual(expandPathOperand('~/x', { home: null, cwd: '/x' }), { kind: 'dynamic', reason: 'no_home' });
  } finally {
    process.env.HOME = saved;
  }
});

// Case-insensitive volume (APFS default). The build server has no APFS, so
// these run on an injected case-folding fs; say so in the result.
function apfsTree() {
  return createFakeFs({ caseInsensitive: true })
    .mkdir('/Users/u', { mode: 0o700 })
    .file('/Users/u/.ssh/id_rsa', 'dummy')
    .mkdir('/Users/u/Work/Repo/.git')
    .mkdir('/Users/u/Work/Repo/node_modules')
    .mkdir('/private/tmp')
    .symlink('/tmp', 'private/tmp')
    .mkdir('/private/var/tmp');
}

test('T-path case-variant paths on a case-insensitive volume (injected APFS emulation)', () => {
  const fs = apfsTree();
  const ws = resolveWorkspace(fs, { eventCwd: '/users/U/work/REPO', home: '/Users/u' });
  assert.equal(ws.known, true);
  const ctx = { home: '/Users/u', cwd: '/users/U/work/REPO' };
  const cls = (raw) => classifyDeleteTarget(fs, ws, resolveOperand(fs, ctx, raw, 'delete'));
  assert.equal(cls('/USERS/U/WORK/REPO/NODE_MODULES'), 'in_workspace');
  assert.equal(cls('/USERS/U'), 'home');
  assert.equal(cls('../../../../USERS/u/'), 'home');
  assert.equal(cls('/users/u/work/repo'), 'workspace_root');
  assert.equal(cls('/TMP/x'), 'in_workspace');
  assert.equal(cls('/PRIVATE/TMP'), 'workspace_root');
  const read = resolveOperand(fs, ctx, '~/.SSH/ID_RSA', 'read');
  assert.equal(pathKey(fs, read.real), pathKey(fs, '/Users/u/.ssh/id_rsa'));
  assert.equal(read.exists, true);
});

test('case-variant paths on a case-sensitive volume: never folded into the workspace, always folded for danger checks', () => {
  const fs = linuxTree().mkdir('/work/Repo');
  assert.notEqual(pathKey(fs, '/HOME/U'), pathKey(fs, '/home/u'));
  assert.equal(classify(fs, '/work/repo', '/work/Repo/x'), 'outside_workspace');
  assert.equal(classify(fs, '/work/repo', '/work/REPO/x'), 'outside_workspace');
  // Unproven case-sensitivity can only look more dangerous.
  assert.equal(classify(fs, '/work/repo', '/HOME/U'), 'home');
  assert.equal(classify(fs, '/work/repo', '/WORK/REPO'), 'workspace_root');
});

test('adversarial fix: a non-ASCII home or cwd does not make in-workspace targets unknown; a non-ASCII operand or value does', () => {
  const fs = createFakeFs().mkdir('/home/jos\u00e9/proj/.git');
  const ctx = { home: '/home/jos\u00e9', cwd: '/home/jos\u00e9/proj' };
  const ws = resolveWorkspace(fs, { eventCwd: ctx.cwd, home: ctx.home });
  assert.equal(classifyDeleteTarget(fs, ws, resolveOperand(fs, ctx, 'node_modules', 'delete')), 'in_workspace');
  assert.equal(classifyDeleteTarget(fs, ws, resolveOperand(fs, ctx, 'n\u00f6de', 'delete')), 'unknown');
  assert.equal(classifyDeleteTarget(fs, ws, resolveOperand(fs, { ...ctx, assignments: { D: '\u0455sh' } }, '$D', 'delete')), 'unknown');
});

test("adversarial fix: a leftover $ ($'..', $\"..\", lone $) is dynamic", () => {
  for (const raw of ["$'\\x2f'", '$"x"', 'a$', '$']) {
    assert.equal(expandPathOperand(raw, { home: '/home/u', cwd: '/work/repo' }).kind, 'dynamic', raw);
  }
});

test('adversarial fix: case-insensitivity on the host is probed, not assumed (ext4 build server: not folded)', (t) => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), 'seatbelt-case-')));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  mkdirSync(join(base, 'Proj'));
  const fs = nodeSeatbeltFs();
  const folds = existsSync(join(base, 'pROJ'));
  assert.equal(fs.caseInsensitive(join(base, 'Proj', 'x')), folds);
  if (!folds) assert.equal(pathKey(fs, join(base, 'Proj')), join(base, 'Proj'));
});

test('T-path matrix on the real Linux filesystem (nodeSeatbeltFs)', (t) => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), 'seatbelt-path-')));
  t.after(() => rmSync(base, { recursive: true, force: true }));
  const home = join(base, 'home');
  const repo = join(base, 'work', 'repo');
  mkdirSync(join(home, '.ssh'), { recursive: true, mode: 0o700 });
  writeFileSync(join(home, '.ssh', 'id_rsa'), 'dummy');
  mkdirSync(join(repo, '.git'), { recursive: true });
  mkdirSync(join(repo, 'src'));
  mkdirSync(join(base, 'work', 'other'));
  symlinkSync(home, join(repo, 'homelink'));
  symlinkSync(join(repo, 'a'), join(repo, 'b'));
  symlinkSync(join(repo, 'b'), join(repo, 'a'));
  symlinkSync(repo, join(home, 'proj'));
  const fs = nodeSeatbeltFs();
  const ws = resolveWorkspace(fs, { eventCwd: join(repo, 'src'), home });
  assert.deepEqual(ws.roots, [repo]);
  const cls = (raw, cwd = join(repo, 'src')) => classifyDeleteTarget(fs, resolveWorkspace(fs, { eventCwd: cwd, home }), resolveOperand(fs, { home, cwd }, raw, 'delete'));
  assert.equal(cls('../node_modules'), 'in_workspace');
  assert.equal(cls('./a/../../..'), 'workspace_root');
  assert.equal(cls('../../other'), 'outside_workspace');
  assert.equal(cls('~'), 'home');
  assert.equal(cls('$HOME/'), 'home');
  assert.equal(cls('../homelink'), 'in_workspace');
  assert.equal(cls('../homelink/'), 'home');
  assert.equal(cls('../a/'), 'unknown');
  assert.equal(cls('node_modules', join(home, 'proj', 'src')), 'in_workspace');
  assert.equal(cls('/'), 'root');
  if (existsSync('/proc/self/root')) assert.equal(cls(`/proc/self/root${home}`), 'home');
});

test('security pass: brace detection is linear on long operands', () => {
  const started = Date.now();
  assert.equal(expandPathOperand(`${'{'.repeat(20000)}a`, { home: '/home/u', cwd: '/w' }).kind, 'path');
  assert.equal(expandPathOperand(`{${'a'.repeat(20000)},b}`, { home: '/home/u', cwd: '/w' }).kind, 'dynamic');
  assert.ok(Date.now() - started < 1000);
});
