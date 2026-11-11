const assert = require('node:assert/strict');
const test = require('node:test');
const os = require('node:os');
const { posix } = require('node:path');
const { randomBytes } = require('node:crypto');
const { normalizedHookAction } = require('../dist/normalized-action.js');

// T2: a shell delete sends its targets in paths[] so the service's delete floor (programs[] + paths[]) sees them.
// The floor's DELETES set; `find … -delete` sends its start points too.
const DELETES = new Set(['rm', 'rmdir', 'unlink', 'shred', 'srm', 'wipe', 'trash', 'trash-put', 'rimraf']);
const UNRESOLVED = '$unresolved';

// One salt per run (generated at runtime), so keys compare within the run.
const salt = randomBytes(32);
// Relative targets are joined lexically to the working directory (a fixed folder here, nothing is read or written).
const CWD = '/srv/work';
const here = () => CWD;
function act(command, options = {}, cwd = () => CWD) {
  const saved = process.cwd;
  process.cwd = cwd;
  try {
    return normalizedHookAction({ tool_name: 'Bash', tool_input: { command } }, { salt, ...options });
  } finally {
    process.cwd = saved;
  }
}
const keyOf = (action) => JSON.stringify(action.tool_input);

// The person's home is sent as /home/[user].
function sent(path) {
  const home = os.homedir();
  if (path === home || path.startsWith(`${home}/`)) return `/home/[user]${path.slice(home.length)}`;
  return path.replace(/^(\/(?:home|Users))\/[^/]+(?=\/|$)/, '$1/[user]');
}
const deleteNamed = (action) => (action.programs || []).some((program) => DELETES.has(program));

// Dummy key-shaped value (fixed non-key prefix + runtime hex); every draw is checked to be no live-key shape.
function dummyToken() {
  const token = `Zq9${randomBytes(12).toString('hex')}X`;
  assert.ok(!/^(?:sk|pk|rk)_|^gh[pousr]_|^xox/.test(token));
  return token;
}

// [command, expected paths] rows of spec T2 (abuse rows and the miss itself): every row must change from BASE.
const held = () => [
  ['rm-builds (system path)', 'rm -rf /opt/builds', ['/opt/builds']],
  ['rm -rf / ', 'rm -rf /', ['/']],
  ['rm -rf ~', 'rm -rf ~', ['/home/[user]']],
  ['rm -rf /home/<user>', 'rm -rf /home/alice', ['/home/[user]']],
  ['variable target', 'rm -rf "$D"', [UNRESOLVED]],
  ['glob in the first component', 'rm -rf /*', [UNRESOLVED]],
  ['parent of home', 'rm -rf ~/../', [posix.resolve('/home/[user]', '..')]],
  ['cd then relative', 'cd / && rm -rf home', [sent(posix.join(here(), 'home')), '/home']],
  ['find -delete', 'find ~ -delete', ['/home/[user]']],
  ['xargs input', 'xargs rm -rf < list', [UNRESOLVED]],
  ['sudo -u x', 'sudo -u x rm -rf /etc', ['/etc']],
  ['bash -c', "bash -c 'rm -rf ~'", ['/home/[user]']],
  ['tmp escape', 'rm -rf /tmp/../home/u', ['/home/[user]']],
  ['above cwd', 'rm -rf node_modules/../../x', [UNRESOLVED]],
  ['database dir', 'rm -rf /home/u/pgdata', ['/home/[user]/pgdata']],
  ['unicode look-alike', 'rⅿ -rf /', ['/']],
  ['backslash', '\\rm -rf /', ['/']],
  ['command rm', 'command rm -rf /', ['/']],
  ['busybox rm', 'busybox rm -rf /', ['/']],
  ['-- then a dash name', 'rm -rf -- -x /', [sent(posix.join(here(), '-x')), '/']],
  ['repeated flags', 'rm -r -f -r /etc', ['/etc']],
  ['unknown flag', 'rm --no-preserve-root -rf /', ['/']],
  ['substitution', 'rm -rf $(cat list)', [UNRESOLVED]],
  ['brace expansion', 'rm -rf /{etc,usr}', [UNRESOLVED]],
  ['other user tilde', 'rm -rf ~bob', [UNRESOLVED]],
  ['find -exec rm', 'find /etc -exec rm {} +', ['/etc']],
  ['subshell cd', '(cd /etc; rm -rf ssh)', [sent(posix.join(here(), 'ssh')), '/etc/ssh']],
  ['cd to a variable', 'cd "$X" && rm -rf y', [UNRESOLVED]],
  ['other delete program', 'shred -u /etc/hosts', ['/etc/hosts']],
  ['chained second segment', 'ls && rm -rf /var', ['/var']],
  ['piped xargs', 'ls | xargs rm', [UNRESOLVED]],
];

for (const [name, command, paths] of held()) {
  test(`T2 abuse: ${name}: the targets are sent and a delete program is named`, () => {
    const action = act(command);
    assert.deepEqual(action.paths, paths);
    assert.ok(deleteNamed(action) || (action.programs || []).includes('find'), JSON.stringify(action.programs));
  });
}

test('T2 pass rows: tmp, scratch and a regenerable leaf under home send their literal paths', () => {
  assert.deepEqual(act('rm -rf /tmp/build-x').paths, ['/tmp/build-x']);
  assert.deepEqual(act('rm -rf scratch').paths, [sent(posix.join(here(), 'scratch'))]);
  assert.deepEqual(act('rm -rf ~/proj/node_modules').paths, ['/home/[user]/proj/node_modules']);
  assert.deepEqual(act('rm -rf /tmp/rm-rf-home').paths, ['/tmp/rm-rf-home']);
});

test('T2 misleading words: no delete runs, no paths are sent (as BASE)', () => {
  for (const command of ['echo rm -rf /', 'git commit -m "rm -rf old"', 'ls /tmp/rm-rf-home', 'grep -r rm /etc', 'cat rm']) {
    assert.equal(act(command).paths, undefined, command);
  }
});

test('T2: more than 64 targets are cut and the action is truncated', () => {
  const action = act(`rm ${Array.from({ length: 70 }, (_, i) => `/tmp/f${i}`).join(' ')}`);
  assert.equal(action.paths.length, 64);
  assert.equal(action.truncated, true);
});

test('T2 collision: different targets give different keys', () => {
  assert.notEqual(keyOf(act('rm -rf /tmp/a')), keyOf(act('rm -rf /tmp/b')));
});

test('T2 collision: two users\' homes share the sent path but never the key', () => {
  const first = act('rm -rf /home/u/x');
  const second = act('rm -rf /home/v/x');
  assert.deepEqual(first.paths, ['/home/[user]/x']);
  assert.deepEqual(second.paths, ['/home/[user]/x']);
  assert.notEqual(keyOf(first), keyOf(second));
});

test('T2 collision: text after a secret span keeps keys apart; only-the-secret variants may match; no secret is sent', () => {
  const token = dummyToken();
  const other = dummyToken();
  const a = act(`rm /tmp/${token}/a`);
  const b = act(`rm /tmp/${token}/b`);
  const a2 = act(`rm /tmp/${other}/a`);
  assert.notEqual(keyOf(a), keyOf(b));
  assert.deepEqual(a.paths, a2.paths);
  for (const action of [a, b, a2]) {
    const text = JSON.stringify(action);
    assert.ok(!text.includes(token) && !text.includes(other));
    assert.ok(action.paths[0].includes('[secret]') || action.paths[0] === UNRESOLVED);
    assert.equal(action.truncated, true);
  }
});

test('T2 collision: one approval binds one exact target (decision reuse by class text cannot cover another)', () => {
  const keys = ['rm -rf /tmp/a', 'rm -rf /etc', 'rm -rf ~', 'rm -rf /tmp/a /etc'].map((command) => keyOf(act(command)));
  assert.equal(new Set(keys).size, keys.length);
});

test('T2 privacy: no user name and no home path leaves the machine', () => {
  const home = os.homedir();
  for (const command of ['rm -rf ~/proj', 'rm -rf /home/alice/x', `rm -rf ${home}/y`, 'rm -rf /Users/alice/z']) {
    const text = JSON.stringify(act(command).paths);
    assert.ok(!text.includes('alice') && !text.includes(home), command);
  }
});

test('T2 fail-closed: an unreadable working directory sends relative targets as unresolved', () => {
  const unreadable = () => { throw new Error('ENOENT'); };
  assert.deepEqual(act('rm -rf build', {}, unreadable).paths, [UNRESOLVED]);
  assert.deepEqual(act('rm -rf /etc', {}, unreadable).paths, ['/etc']);
});

test('T2 fail-closed: a path the redactor replaces whole is sent as unresolved', () => {
  const action = act(`rm -rf ${dummyToken()}`);
  assert.deepEqual(action.paths, [UNRESOLVED]);
  assert.equal(action.truncated, true);
});

test('T2 fail-closed: an unreadable home sends home targets as unresolved', () => {
  const saved = os.homedir;
  os.homedir = () => { throw new Error('no home'); };
  try {
    assert.deepEqual(act('rm -rf ~').paths, [UNRESOLVED]);
  } finally {
    os.homedir = saved;
  }
});

test('T2 fail-closed: a spent time budget gives a truncated action (held), never a partial path list', () => {
  const action = act('rm -rf /tmp/a', { deadlineAt: Date.now() - 1 });
  assert.equal(action.truncated, true);
  assert.equal(action.paths, undefined);
});
