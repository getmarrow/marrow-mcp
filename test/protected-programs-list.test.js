const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const { classifyTool, localApprovalCategories } = require('../dist/hook-pre-action.js');
const { normalizedHookAction } = require('../dist/normalized-action.js');
const policy = require('../dist/hook-tool-policy.js');

// T4 (MCP 3.9.113): the owner's list of production scripts (~/.marrow/protected-programs.json) makes a run of a listed script deploy on
// production, held, whatever its flags (dry runs included). The list only adds holds. Dummy names only: the owner's real names never
// appear in product code or tests.

const root = mkdtempSync(join(tmpdir(), 'marrow-t4-'));
const home = join(root, 'home');
const proj = join(home, 'proj');
mkdirSync(join(home, '.marrow'), { recursive: true });
mkdirSync(join(proj, 'tests'), { recursive: true });
writeFileSync(join(proj, 'ship-dummy.py'), '# dummy\n');
symlinkSync(join(proj, 'ship-dummy.py'), join(proj, 'ship'));
const savedHome = process.env.HOME;
process.env.HOME = home;
test.after(() => { process.env.HOME = savedHome; rmSync(root, { recursive: true, force: true }); });

const LIST = join(home, '.marrow', 'protected-programs.json');
const LAST_GOOD = join(home, '.marrow', 'protected-programs.last-good.json');
const OWNER_LIST = {
  version: 1,
  programs: [
    { name: 'ship-dummy.py', class: 'deploy' },
    { name: 'stage-all-dummy.py', class: 'deploy' },
    { name: 'switch-dummy.py', class: 'deploy', args: ['apply'] },
    { name: 'pub-dummy.py', class: 'publish' },
    { name: 'sec-dummy.sh', class: 'security' },
  ],
};
const setList = (value) => {
  rmSync(LIST, { recursive: true, force: true });
  if (value !== undefined) writeFileSync(LIST, typeof value === 'string' ? value : JSON.stringify(value));
};
const clearAll = () => { setList(undefined); rmSync(LAST_GOOD, { force: true }); };

const bash = (command, cwd = proj) => classifyTool({ tool_name: 'Bash', tool_input: { command }, cwd });
const DEPLOY = 'classified Bash action: deploy on production';
const held = (command, cwd) => {
  const result = bash(command, cwd);
  return result.protected === true && result.type === 'deploy' && result.surfaces.includes('production') && result.readOnly === false;
};
// The answer with no list at all (BASE behaviour for every row).
const unlisted = (command, cwd) => { const saved = existing(); clearAll(); const result = bash(command, cwd); restore(saved); return result; };
const existing = () => { try { return readFileSync(LIST, 'utf8'); } catch { return undefined; } };
const restore = (saved) => setList(saved);

test.beforeEach(() => { clearAll(); setList(OWNER_LIST); });

// --- the misses and the abuse rows (spec T4): RED on BASE, GREEN on the tip ---
const HELD_ROWS = [
  ['miss ship-deploy', 'python3 ship-dummy.py 0123abcd'],
  ['miss prod-cfg-apply', 'python3 switch-dummy.py apply'],
  ['A1 isolated mode, absolute path', 'python3 -I /home/someone/scripts/ship-dummy.py 0123abcd'],
  ['A2 /usr/bin/env wrapper', '/usr/bin/env python3 ship-dummy.py'],
  ['A3 direct path run', './ship-dummy.py'],
  ['A4 timeout wrapper', 'timeout 600 python3 ship-dummy.py'],
  ['A5 after cd in a chain', 'cd x && python3 ship-dummy.py'],
  ['A6 --dry-run direct', 'ship-dummy.py --dry-run'],
  ['A6b --dry-run through the interpreter', 'python3 ship-dummy.py --dry-run'],
  ['A6c -n through the interpreter', 'python3 ship-dummy.py -n'],
  ['A9 symlink run directly', './ship apply'],
  ['A9b symlink as the script operand', 'python3 ship'],
  ['A12 subcommand scope with a flag first', 'python3 switch-dummy.py --force apply'],
  ['A12b subcommand scope as option value', 'switch-dummy.py --mode=apply'],
  ['A12c subcommand from a variable', 'python3 switch-dummy.py "$STEP"'],
  ['A13 env assignment prefix', 'FOO=1 python3 stage-all-dummy.py'],
  ['A14 sudo with an option value', 'sudo -u root python3 ship-dummy.py'],
  ['A15 nice and env -i', 'nice -n 5 env -i python3 ship-dummy.py'],
  ['A16 piped into', 'echo y | python3 ship-dummy.py'],
  ['A17 after a semicolon', 'true; python3 ship-dummy.py'],
  ['A18 || chain', 'false || bash stage-all-dummy.py'],
  ['A19 subshell', '(python3 ship-dummy.py)'],
  ['A20 command substitution', 'echo $(python3 ship-dummy.py)'],
  ['A21 sh -c', "sh -c 'python3 ship-dummy.py'"],
  ['A22 nested bash -c', `bash -c "bash -c 'python3 ship-dummy.py'"`],
  ['A23 interpreter option value before the script', 'python3 -W ignore ship-dummy.py'],
  ['A24 versioned interpreter', 'python3.12 ship-dummy.py'],
  ['A25 uv run', 'uv run ship-dummy.py'],
  ['A26 find -exec', 'find . -name x -exec python3 ship-dummy.py {} ;'],
  ['A27 xargs', 'echo a | xargs python3 ship-dummy.py'],
  ['A28 upper case name', 'python3 SHIP-DUMMY.PY'],
  ['A29 last of repeated flags', 'ship-dummy.py --dry-run --no-dry-run --dry-run'],
  ['A30 unknown flags', 'ship-dummy.py --zzz-unknown -Q'],
  ['A31 misleading words in the message', 'python3 ship-dummy.py --note "read only, just a test, no change"'],
  ['A32 source', 'source ship-dummy.py'],
  ['A33 timeout with a signal option', 'timeout -s KILL 600 python3 ship-dummy.py'],
  ['A34 eval of a command text', 'eval "python3 ship-dummy.py"'],
  ['A35 env -S command text', 'env -S "python3 ship-dummy.py --dry-run"'],
  ['A36 ssh command text', "ssh host 'python3 ship-dummy.py'"],
  ['A37 watch', 'watch -n 5 python3 ship-dummy.py'],
  ['A38 sudo sh -c', "sudo sh -c './ship-dummy.py'"],
];
for (const [name, command] of HELD_ROWS) {
  test(`T4 ${name}: held as deploy on production`, () => {
    assert.equal(held(command), true, command);
    assert.equal(bash(command).action, DEPLOY);
  });
}

test('T4 A7 bash -c with the listed script stays held', () => {
  assert.equal(held('bash -c "python3 ship-dummy.py"'), true);
});

test('T4 publish and security classes take their own surface', () => {
  const pub = bash('python3 pub-dummy.py');
  assert.equal(pub.type, 'publish');
  assert.ok(pub.surfaces.includes('npm'));
  assert.equal(pub.protected, true);
  const sec = bash('bash sec-dummy.sh');
  assert.equal(sec.type, 'security');
  assert.ok(sec.surfaces.includes('secrets'));
  assert.equal(sec.protected, true);
});

test('T4 chain of two listed classes keeps the strictest and every surface', () => {
  const both = bash('python3 ship-dummy.py && bash sec-dummy.sh');
  assert.equal(both.type, 'security');
  assert.ok(both.surfaces.includes('production') && both.surfaces.includes('secrets'));
  assert.equal(both.protected, true);
});

// --- rows that must stay as BASE answers them (GREEN on BASE and on the tip) ---
const UNCHANGED_ROWS = [
  ['M1 cat', 'cat ship-dummy.py'],
  ['M2 grep', 'grep -n apply ship-dummy.py'],
  ['M3 git add', 'git add ship-dummy.py'],
  ['M4 python -m pytest', 'python3 -m pytest tests/test_ship_dummy.py'],
  ['M5 python -m with the listed name as module argument', 'python3 -m pytest ship-dummy.py'],
  ['M6 python -c', 'python3 -c "print(1)" ship-dummy.py'],
  ['A8 renamed copy (known limit: generic rule only)', 'python3 ms.py'],
  ['A12d subcommand scope: other subcommand', 'python3 switch-dummy.py status'],
  ['U1 unicode hyphen look-alike is another name', 'python3 ship‐dummy.py'],
  ['U2 unlisted script', 'python3 other.py'],
  ['U3 echo of the name', 'echo ship-dummy.py'],
  ['U4 ls', 'ls -la ship-dummy.py'],
];
for (const [name, command] of UNCHANGED_ROWS) {
  test(`T4 ${name}: answered as with no list`, () => {
    assert.deepEqual(bash(command), unlisted(command), command);
  });
}

test('T4 generic word rules still hold wrangler deploy and npm publish, with or without a list', () => {
  for (const command of ['wrangler deploy', 'npx wrangler d1 execute db --remote', 'npm publish']) {
    const listed = bash(command);
    assert.equal(listed.protected, true, command);
    assert.deepEqual(listed, unlisted(command), command);
  }
});

test('T4 absent list: a listed name runs as BASE answers it (fresh user)', () => {
  clearAll();
  const result = bash('python3 ship-dummy.py');
  assert.equal(result.action, 'classified Bash action: process on workspace');
  assert.equal(result.protected, false);
});

test('T4 A10 the agent editing, moving or deleting the list is a marrow-control hold', () => {
  const control = (result) => result.type === 'security' && result.surfaces.includes('marrow-control') && result.protected === true;
  for (const command of [`rm ${LIST}`, `mv ${LIST} ${join(home, 'x.json')}`, 'rm ~/.marrow/protected-programs.json']) {
    assert.equal(control(bash(command)), true, command);
    assert.deepEqual(bash(command), unlisted(command), command);
  }
  assert.equal(control(classifyTool({ tool_name: 'Write', tool_input: { file_path: LIST, content: '{}' }, cwd: proj })), true);
  assert.equal(control(classifyTool({ tool_name: 'Edit', tool_input: { file_path: LAST_GOOD, old_string: 'a', new_string: 'b' }, cwd: proj })), true);
});

// --- fail closed: present but malformed or unreadable ---
test('T4 A11 malformed list: a name from the last good copy and every marrow-* run are held', () => {
  bash('true'); // a good read writes the hash-only last good copy
  const copy = readFileSync(LAST_GOOD, 'utf8');
  assert.equal(copy.includes('ship-dummy'), false, 'the copy holds hashes only');
  setList('{"version":1,"programs":[{"name":');
  assert.equal(held('python3 ship-dummy.py'), true);
  assert.equal(held('./stage-all-dummy.py --dry-run'), true);
  assert.equal(held('python3 switch-dummy.py status'), true);
  assert.equal(held('python3 marrow-anything.py'), true);
  assert.deepEqual(bash('python3 other.py'), unlisted('python3 other.py'));
  assert.deepEqual(bash('cat ship-dummy.py'), unlisted('cat ship-dummy.py'));
});

test('T4 A11b malformed shapes fail closed', () => {
  for (const bad of ['', 'null', '[]', '{"version":2,"programs":[]}', '{"version":1}', '{"version":1,"programs":[{"name":"a/b.py","class":"deploy"}]}',
    '{"version":1,"programs":[{"name":"x.py","class":"allow"}]}', '{"version":1,"programs":[{"name":"x.py","class":"deploy","args":"apply"}]}']) {
    setList(bad);
    assert.equal(held('python3 marrow-anything.py'), true, bad);
    assert.equal(held('python3 ship-dummy.py'), false, `no last good copy yet: ${bad}`);
  }
});

test('T4 A11c unreadable list (a folder in its place) fails closed', () => {
  bash('true');
  setList(undefined);
  mkdirSync(LIST);
  assert.equal(held('python3 ship-dummy.py'), true);
  assert.equal(held('marrow-other.sh'), true);
});

test('T4 a list entry never removes a hold', () => {
  setList({ version: 1, programs: [{ name: 'git', class: 'deploy' }, { name: 'rm', class: 'deploy' }] });
  const push = bash('git push origin master');
  assert.equal(push.protected, true);
  const removal = bash('rm -rf build');
  assert.equal(removal.protected, true);
  setList({ version: 1, programs: [] });
  assert.deepEqual(bash('git push origin master'), unlisted('git push origin master'));
});

// --- TMO: a time budget overrun and a thrown reader error hold ---
test('T4 TMO forced overrun of the time budget holds', () => {
  let clock = 0;
  const classes = policy.protectedProgramClasses('python3 other.py; ls; echo a', proj, { read: () => JSON.stringify(OWNER_LIST), now: () => (clock += 1000) });
  assert.deepEqual(classes, ['deploy']);
});

test('T4 TMO a thrown reader error holds a name from the last good copy', () => {
  bash('true');
  const classes = policy.protectedProgramClasses('python3 ship-dummy.py', proj, { read: () => { throw Object.assign(new Error('io'), { code: 'EIO' }); }, now: Date.now });
  assert.deepEqual(classes, ['deploy']);
});

test('T4 TMO a reader that is absent gives no list', () => {
  const classes = policy.protectedProgramClasses('python3 ship-dummy.py', proj, { read: () => null, now: Date.now });
  assert.deepEqual(classes, []);
});

// --- GROW: long inputs answer, held ---
test('T4 GROW long inputs are still held', () => {
  for (const size of [8192, 16384, 32768, 1 << 20]) {
    const pad = 'a '.repeat(size / 2);
    assert.equal(held(`python3 ship-dummy.py ${pad}`), true, `args ${size}`);
    assert.equal(held(`${'timeout 1 '.repeat(size / 10)}python3 ship-dummy.py`), true, `wrappers ${size}`);
    assert.equal(held(`python3 ${'-W x '.repeat(size / 5)}ship-dummy.py`), true, `options ${size}`);
  }
});

// --- COLL: the action key, exact hash and approval binding inputs do not read the list ---
const SALT = randomBytes(32);
const dummySecret = () => {
  const value = `dummyval${randomBytes(12).toString('hex')}`;
  assert.equal(/^(?:sk_|pk_|rk_|ghp_|xox)/.test(value), false);
  return value;
};
const key = (command) => normalizedHookAction({ tool_name: 'Bash', tool_input: { command }, cwd: proj }, { salt: SALT });

test('T4 COLL the normalized action is byte-equal with and without the list', () => {
  for (const command of ['python3 ship-dummy.py 0123abcd', 'python3 switch-dummy.py apply', 'ship-dummy.py --dry-run', 'cat ship-dummy.py']) {
    const listed = JSON.stringify(key(command));
    clearAll();
    assert.equal(JSON.stringify(key(command)), listed, command);
    setList(OWNER_LIST);
  }
});

test('T4 COLL actions that differ outside a secret get different keys; the secret is in no key or label', () => {
  const secret = dummySecret();
  const pairs = [
    ['python3 ship-dummy.py', 'python3 ship-dummy.py --dry-run'],
    ['python3 ship-dummy.py 0123abcd', 'python3 ship-dummy.py 4567ef01'],
    ['python3 ship-dummy.py', 'python3 stage-all-dummy.py'],
    [`python3 switch-dummy.py --token=${secret} apply`, `python3 switch-dummy.py --token=${secret} status`],
    [`TOKEN=${secret} python3 ship-dummy.py a`, `TOKEN=${secret} python3 ship-dummy.py b`],
  ];
  for (const [a, b] of pairs) {
    const ka = key(a);
    const kb = key(b);
    assert.notEqual(ka.exact_hash ?? JSON.stringify(ka), kb.exact_hash ?? JSON.stringify(kb), `${a} | ${b}`);
    assert.notEqual(JSON.stringify(ka), JSON.stringify(kb));
    for (const text of [JSON.stringify(ka), JSON.stringify(kb), JSON.stringify(bash(a)), JSON.stringify(bash(b))]) assert.equal(text.includes(secret), false);
  }
});

test('T4 COLL actions that differ only in the secret may match and never carry it', () => {
  const one = dummySecret();
  const two = dummySecret();
  const a = key(`python3 ship-dummy.py --token=${one}`);
  const b = key(`python3 ship-dummy.py --token=${two}`);
  assert.equal(JSON.stringify(a).includes(one), false);
  assert.equal(JSON.stringify(b).includes(two), false);
});

test('T4 CONS-KEY class text changes from process to deploy for a listed run (old decisions re-ask once)', () => {
  const listed = bash('python3 ship-dummy.py');
  const before = unlisted('python3 ship-dummy.py');
  assert.equal(before.action, 'classified Bash action: process on workspace');
  assert.equal(listed.action, DEPLOY);
  assert.notEqual(listed.target, before.target);
  assert.equal(listed.role, 'deploy');
  assert.equal(listed.risk, 'high');
});

test('T4 the last good copy holds no plain name and is private', () => {
  bash('true');
  const copy = readFileSync(LAST_GOOD, 'utf8');
  for (const entry of OWNER_LIST.programs) assert.equal(copy.toLowerCase().includes(entry.name.replace(/\..*$/, '')), false);
  assert.equal(require('node:fs').statSync(LAST_GOOD).mode & 0o077, 0);
});

test('T4 CONS hold UX: the local approval categories of a listed run are production_deploy, as wrangler deploy\'s are', () => {
  assert.ok(localApprovalCategories(bash('python3 ship-dummy.py --dry-run')).includes('production_deploy'));
  assert.equal(localApprovalCategories(unlisted('python3 ship-dummy.py --dry-run')).includes('production_deploy'), false);
  assert.equal(bash('python3 ship-dummy.py').risk, 'high');
});
