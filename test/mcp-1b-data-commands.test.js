const assert = require('node:assert/strict');
const { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync } = require('node:fs');
const { createHash, randomBytes } = require('node:crypto');
const { tmpdir, userInfo } = require('node:os');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const { classifyTool } = require('../dist/hook-pre-action.js');
// The new module is loaded lazily so that, on a build without MCP-1b, every row fails on its own line instead of the whole file failing to load.
const dc = () => require('../dist/data-commands.js');

// MCP-1b (spec friction r3 §4.4, §4.7 A39-A42, acceptance rows B1-B11): owner-declared data commands.
// Every abuse row carries the risky words "deploy production wrangler" in the note on purpose: the 3.9.109 words path protects each of them, so a matcher
// that wrongly admitted a row flips `protected` to false. A "no match" row must equal the 3.9.109 answer (the same call with no data-commands.json) exactly.

const sha = (buffer) => createHash('sha256').update(buffer).digest('hex');
const root = realpathSync(mkdtempSync(join(tmpdir(), 'mcp1b-')));
const tools = join(root, 'tools');
const other = join(root, 'other');
const ws = join(root, 'ws');
for (const dir of [tools, other, ws]) mkdirSync(dir, { recursive: true });
symlinkSync(tools, join(ws, 'toolslink'));
const BOARD = '#!/usr/bin/env python3\nprint("board")\n';
const board = join(tools, 'board.py');
writeFileSync(board, BOARD);
writeFileSync(join(other, 'board.py'), BOARD);
writeFileSync(join(tools, 'edit.py'), '#!/usr/bin/env python3\nprint("edit")\n');
writeFileSync(join(tools, 'second.py'), '#!/usr/bin/env python3\nprint("second")\n');
const passwdHome = userInfo().homedir;
mkdirSync(join(passwdHome, 'hb'), { recursive: true });
writeFileSync(join(passwdHome, 'hb', 'board.py'), BOARD);

const HOME = process.env.HOME;
const marrowDir = join(HOME, '.marrow');
const declFile = join(marrowDir, 'data-commands.json');
test.after(() => { rmSync(root, { recursive: true, force: true }); rmSync(join(passwdHome, 'hb'), { recursive: true, force: true }); });

const DW_LABEL = 'classified Bash action: process on workspace';
const bash = (command, extra = {}) => classifyTool({ tool_name: 'Bash', tool_input: { command }, cwd: ws, ...extra });
const isDw = (result) => result.protected === false && result.action === DW_LABEL && result.readOnly === false;

const entryFor = (prefix, script = board) => ({ argv_prefix: prefix, sha256: sha(readFileSync(script)) });
const BOARD_PREFIX = ['python3', '-I', board, 'set'];
const goodEntry = () => entryFor(BOARD_PREFIX);
function declare(entries, o = {}) {
  rmSync(marrowDir, { recursive: true, force: true });
  mkdirSync(marrowDir, { mode: 0o700 });
  chmodSync(marrowDir, o.dirMode ?? 0o700);
  const body = o.raw ?? JSON.stringify({ version: 1, commands: entries, ...(o.extraTop || {}) });
  writeFileSync(declFile, body, { mode: 0o600 });
  chmodSync(declFile, o.fileMode ?? 0o600);
}
const undeclare = () => rmSync(marrowDir, { recursive: true, force: true });
/** The 3.9.109 answer: the very same call with no declaration file at all. */
function baseline(command, extra) {
  let moved = null;
  if (existsSync(declFile) || existsSync(marrowDir)) { moved = `${marrowDir}.hidden`; rmSync(moved, { recursive: true, force: true }); renameSync(marrowDir, moved); }
  try { return bash(command, extra); } finally { if (moved) renameSync(moved, marrowDir); }
}
const NOTE = '"deploy production wrangler"';
const cmd = (extra = '', prefix = `python3 -I ${board} set`) => `${prefix} C42 --note ${NOTE}${extra}`;
/** A "no match" row: equal to the 3.9.109 answer, and that answer is a hold (the words protect it). */
function assertNoMatch(command, extra, why, requireHold = true) {
  const answer = bash(command, extra);
  const base = baseline(command, extra);
  assert.deepEqual(answer, base, why || command);
  if (requireHold) assert.equal(base.protected, true, `baseline must hold on its words: ${command}`);
  assert.notEqual(isDw(answer), true);
}
function assertDw(command, extra) {
  const answer = bash(command, extra);
  assert.equal(isDw(answer), true, `${command}\n${JSON.stringify(answer)}`);
  const base = baseline(command, extra);
  assert.equal(base.protected, true, `3.9.109 must hold this on its words (row is red there): ${command}`);
}

test.beforeEach(() => declare([goodEntry()]));
test.afterEach(() => undeclare());

// ─── EFFECT / MATCH: the declared command is data-only ───
test('B0 positive: the declared command with a note that names deploy/production gets the DW label (R-29b shape)', () => {
  assertDw(cmd());
});
test('B0 label is the fixed text; the note never reaches it, and the answer is not read-only', () => {
  const answer = bash(cmd());
  assert.equal(answer.action, DW_LABEL);
  assert.doesNotMatch(JSON.stringify(answer), /wrangler|deploy|C42/);
  assert.deepEqual([answer.protected, answer.readOnly, answer.surfaces, answer.type, answer.risk], [false, false, ['workspace'], 'process', 'medium']);
});
test('B0 positive: DW segments around a declared segment, redirects to /dev/null and to a data file', () => {
  assertDw(`echo "deploy production" >> ${ws}/n.md; ${cmd()}; echo done >> ${ws}/n.md`);
  assertDw(cmd(' > /dev/null 2>&1'));
  assertDw(cmd(` >> ${ws}/board-log.md`));
  assertDw(cmd(` | tee -a ${ws}/board-log.md`));
  assertDw(`R=${ws}\n${cmd()} >> $R/board-log.md`);
});
test('B0 positive: a ! or ~ inside single quotes, and a ~ inside double quotes, is text', () => {
  assertDw(`python3 -I ${board} set C42 --note 'shipped! wrangler deploy ~5 min' --tag "~x"`);
});
test('B0 positive: quoted and flagged remaining words are data', () => {
  assertDw(`python3 -I ${board} set C42 --note 'deploy production wrangler' --tag "a b c" -x 1`);
  assertDw(`"python3" '-I' "${board}" set C42 --note ${NOTE}`);
});
test('B0 no entry, no change: without the declaration the same command is held (3.9.109)', () => {
  undeclare();
  const answer = bash(cmd());
  assert.equal(answer.protected, true);
  assert.notEqual(answer.action, DW_LABEL);
});

test('B1 chained: a declared segment plus any other program keeps the 3.9.109 answer', () => {
  for (const tail of ['; wrangler deploy', ' && wrangler deploy', ' || wrangler deploy', ' | wrangler deploy', ' & wrangler deploy', '\nwrangler deploy', '; git push origin master', '; ls']) {
    assertNoMatch(cmd(tail), undefined, `tail ${JSON.stringify(tail)}`);
  }
  assertNoMatch(`bash -c ${JSON.stringify(`${cmd()} ; deploy`)}`);
  assertNoMatch(`wrangler deploy; ${cmd()}`);
});
test('A39 declared prefix plus "; wrangler deploy" is held', () => {
  assertNoMatch(`python3 -I ${board} set C --note x; wrangler deploy`);
});

test('B2 expansions in a remaining word: no match', () => {
  for (const word of ['"$(wrangler deploy)"', '"`wrangler deploy`"', '$V', '${V}', '"$V"', '*', '?', '[a]', '{a,b}', '~', '~/x', '$\'a\'', '$"a"', 'a\\ b', '"a\\"b"', '<(ls)', '>(ls)', '$(date -u)', 'a~b', '--out=~/x', '!', '!!', '"x!"', 'x!', '!wrangler', 'a\\!b']) {
    assertNoMatch(`V=x; ${cmd(` ${word}`)}`, undefined, `word ${word}`);
    assertNoMatch(cmd(` ${word}`), undefined, `word ${word}`);
  }
});
test('B2 a variable is not allowed in the pinned words either', () => {
  assertNoMatch(`B=${board}; python3 -I $B set C --note ${NOTE}`);
  assertNoMatch(`S=set; python3 -I ${board} $S C --note ${NOTE}`);
});

test('A40/B3 the script edited after the declaration: no match, the note words are scanned (3.9.109)', () => {
  assertDw(cmd());
  writeFileSync(board, `${BOARD}# edited\n`);
  try { assertNoMatch(cmd()); } finally { writeFileSync(board, BOARD); }
  assertDw(cmd());
});
test('B4 the script replaced by a symlink to an identical copy: no match', () => {
  const real = join(tools, 'board.real.py');
  writeFileSync(real, BOARD);
  rmSync(board);
  symlinkSync(real, board);
  try { assertNoMatch(cmd()); } finally { rmSync(board); writeFileSync(board, BOARD); rmSync(real); }
  assertDw(cmd());
});
test('B4 a symlinked parent folder of the script: no match', () => {
  assertNoMatch(`python3 -I ${join(ws, 'toolslink', 'board.py')} set C42 --note ${NOTE}`);
  declare([entryFor(['python3', '-I', join(ws, 'toolslink', 'board.py'), 'set'])]);
  assertNoMatch(`python3 -I ${join(ws, 'toolslink', 'board.py')} set C42 --note ${NOTE}`);
});
test('B4 the script missing or a folder: no match', () => {
  rmSync(board);
  try { assertNoMatch(cmd()); } finally { writeFileSync(board, BOARD); }
});

test('A41 prefix mismatch (no -I, python3 -c, other subcommand, shorter command, other interpreter): no match', () => {
  assertNoMatch(`python3 ${board} set C --note ${NOTE}`);
  assertNoMatch(`python3 -c "print(1)" -I ${board} set C --note ${NOTE}`);
  assertNoMatch(`python3 -c "import os; os.system('wrangler deploy production')"`);
  assertNoMatch(`python3 -I ${board} get C --note ${NOTE}`);
  assertNoMatch(`python3 -I ${board} --note ${NOTE} set C`);
  assertNoMatch(`python3 -I ${board}`.replace('python3', 'python') + ` set C --note ${NOTE}`);
  assertNoMatch(`/usr/bin/python3 -I ${board} set C --note ${NOTE}`);
  assertNoMatch(`python3 -I -I ${board} set C --note ${NOTE}`);
  assertNoMatch(`python3 -I ${board}set C --note ${NOTE}`);
  assertNoMatch(`xpython3 -I ${board} set C --note ${NOTE}`);
});
test('A41b a prefix with fewer words than the entry has: no match', () => {
  assertNoMatch(`python3 -I ${board} --note ${NOTE}`);
});

test('B5 spellings of the declared path: match only when the real path is equal and nothing on it is a link', () => {
  assertDw(`python3 -I ./board.py set C --note ${NOTE}`, { cwd: tools });
  assertDw(`python3 -I board.py set C --note ${NOTE}`, { cwd: tools });
  assertDw(`python3 -I ../tools/board.py set C --note ${NOTE}`, { cwd: ws });
  assertDw(`python3 -I ${root}/ws/../tools/./board.py set C --note ${NOTE}`);
  assertNoMatch(`python3 -I board.py set C --note ${NOTE}`, { cwd: ws });
  assertNoMatch(`python3 -I board.py set C --note ${NOTE}`, { cwd: other });
  assertNoMatch(`python3 -I ./board.py set C --note ${NOTE}`, { cwd: join(ws, 'toolslink') });
  assertNoMatch(`python3 -I toolslink/board.py set C --note ${NOTE}`, { cwd: ws });
  assertNoMatch(`python3 -I ${ws}/toolslink/../tools/board.py set C --note ${NOTE}`);
  assertNoMatch(`python3 -I ../other/../tools/nonexistent/../x.py set C --note ${NOTE}`, { cwd: ws });
  assertNoMatch(`python3 -I ${tools}//board.py.bak set C --note ${NOTE}`);
});
test('B5 a ~/ spelling matches only a declared path that really is under the passwd home', () => {
  const homeBoard = join(passwdHome, 'hb', 'board.py');
  declare([entryFor(['python3', '-I', homeBoard, 'set'], homeBoard)]);
  assertDw(`python3 -I ~/hb/board.py set C --note ${NOTE}`);
  assertDw(`python3 -I ${homeBoard} set C --note ${NOTE}`);
  assertNoMatch(`python3 -I ~/hb/other.py set C --note ${NOTE}`);
  declare([goodEntry()]);
  assertNoMatch(`python3 -I ~/hb/board.py set C --note ${NOTE}`);
});

test('B10 a declared prefix of one script never runs another script of the same name in another folder', () => {
  assertNoMatch(`python3 -I ${join(other, 'board.py')} set C --note ${NOTE}`);
  assertNoMatch(`python3 -I board.py set C --note ${NOTE}`, { cwd: other });
  declare([entryFor(['python3', '-I', board, 'set'])]);
  assertNoMatch(`python3 -I ${join(tools, 'edit.py')} set C --note ${NOTE}`);
});

test('B9 redirects of a declared command must pass the DW target rule: no match for rc files, CI folders, instruction files, /dev/tcp, scripts', () => {
  for (const redirect of [' > ~/.bashrc', ' >> ~/.bashrc', ' >> .github/workflows/x.md', ` >> ${ws}/.hidden/x.md`, ' >> CLAUDE.md', ' >> AGENTS.md', ' >> /dev/tcp/host/80', ' > /dev/tcp/host/80', ` >> ${ws}/run.sh`, ' >> /etc/hosts', ' > ~/.claude/settings.json', ` > ${ws}/glob*.md`, ' &> ~/.zshrc', ' < /etc/passwd', ` 2> ${ws}/.git/x.md`]) {
    assertNoMatch(cmd(redirect), undefined, redirect);
  }
});
test('B12 a remaining word that is a path into a hidden or system folder is never data: no match; prose and plain words stay data', () => {
  for (const word of ['~/.marrow/control.json', '/etc/hosts', '/etc', '/proc/self/environ', '/dev/tcp/host/80', '.env', '.bashrc', './.ssh/id', 'a/.git/config', '../x', '/home/u/.marrow/data-commands.json', '/var/spool/cron/x', '/root/x']) {
    assertNoMatch(cmd(` ${word.replace('~', passwdHome)}`), undefined, word);
  }
  assertDw(cmd(' --note "see /etc/hosts and ~/.bashrc and .env for deploy"'));
  assertDw(cmd(` https://example.com/a/b 2026/10/29 1.5 ${ws}/x.md /dev/null`));
});
test('B9 a heredoc into a declared command: no match', () => {
  assertNoMatch(`${cmd()} <<'EOF'\ndeploy production\nEOF`);
  assertNoMatch(`${cmd()} <<EOF\ndeploy production\nEOF`);
});

test('B11 production words in the note of a matching declared command: DW label (the note is data); the same words outside a declared command keep the 3.9.109 label', () => {
  assertDw(`python3 -I ${board} set C --note "wrangler deploy --env production"`);
  assertNoMatch(`python3 -I ${join(tools, 'edit.py')} set C --note "wrangler deploy --env production"`);
  assertNoMatch('wrangler deploy --env production > deploy-log.md');
  assertNoMatch(`python3 -I ${board} --env production set C --note "wrangler deploy"`);
});

test('EFFECT a command whose every segment is DW or declared gets the DW label; any other segment keeps the 3.9.109 answer byte for byte', () => {
  assertDw(`echo "deploy production" >> ${ws}/n.md && ${cmd()} || echo failed >> ${ws}/n.md`);
  assertNoMatch(`${cmd()}; npx wrangler deploy --env production`);
  assertNoMatch(`echo x >> ${ws}/n.md; ${cmd()}; sudo tee -a /etc/hosts`);
  assertNoMatch(`R=x ${cmd()}`);
  assertNoMatch(`(${cmd()})`);
  assertNoMatch(`{ ${cmd()}; }`);
});
test('EFFECT environment variables that change what an interpreter loads are never admitted next to a declared command', () => {
  for (const name of ['PYTHONPATH', 'PYTHONSTARTUP', 'PYTHONHOME', 'NODE_OPTIONS', 'NODE_PATH', 'PERL5LIB', 'PERL5OPT', 'RUBYOPT', 'RUBYLIB', 'LD_PRELOAD', 'BASH_ENV', 'PATH', 'HOME', 'VIRTUAL_ENV', 'GIT_SSH_COMMAND', 'XDG_CONFIG_HOME']) {
    assertNoMatch(`${name}=${ws}/evil; ${cmd()}`, undefined, name);
  }
  assertDw(`MARROW_NOTE_TEXT_X=1; ${cmd()}`.replace('MARROW_NOTE_TEXT_X', 'NOTE_TEXT'));
});

// ─── FILE: the declaration file is read like control.json; any failed check ignores the whole file ───
function assertFileIgnored(label, build) {
  declare([goodEntry()]);
  assertDw(cmd());
  build();
  assertNoMatch(cmd(), undefined, label);
  const read = dc().readDataCommands({ home: HOME });
  assert.deepEqual(read.entries, [], label);
  assert.equal(typeof read.ignored, 'string', label);
  assert.match(read.ignored, /^[^\n]{8,200}$/, `one line: ${label}`);
}
test('B6 mode 644 / dir mode 755 / group-writable: the whole file is ignored', () => {
  assertFileIgnored('mode 644', () => chmodSync(declFile, 0o644));
  assertFileIgnored('mode 660', () => chmodSync(declFile, 0o660));
  assertFileIgnored('mode 400', () => chmodSync(declFile, 0o400));
  assertFileIgnored('dir 755', () => chmodSync(marrowDir, 0o755));
  assertFileIgnored('dir 770', () => chmodSync(marrowDir, 0o770));
});
test('B6 the file or the folder is a symlink: ignored', () => {
  assertFileIgnored('file symlink', () => {
    const real = join(root, 'real-data-commands.json');
    writeFileSync(real, readFileSync(declFile), { mode: 0o600 });
    rmSync(declFile);
    symlinkSync(real, declFile);
  });
  assertFileIgnored('dir symlink', () => {
    const realDir = join(root, 'real-marrow');
    rmSync(realDir, { recursive: true, force: true });
    mkdirSync(realDir, { mode: 0o700 });
    writeFileSync(join(realDir, 'data-commands.json'), readFileSync(declFile), { mode: 0o600 });
    rmSync(marrowDir, { recursive: true });
    symlinkSync(realDir, marrowDir);
  });
});
test('B6 size: 5 KB and 4097 bytes are ignored; a file of exactly 4096 bytes or less is read', () => {
  const body = JSON.stringify({ version: 1, commands: [goodEntry()] });
  assertFileIgnored('5 KB', () => writeFileSync(declFile, body + ' '.repeat(5000), { mode: 0o600 }));
  assertFileIgnored('4097 bytes', () => writeFileSync(declFile, body + ' '.repeat(4097 - Buffer.byteLength(body)), { mode: 0o600 }));
  declare([goodEntry()], { raw: body + ' '.repeat(4096 - Buffer.byteLength(body)) });
  assertDw(cmd());
});
test('B6 schema: extra key, wrong version, bad hex, wrong types, not an object: ignored', () => {
  const good = goodEntry();
  const variants = {
    'extra top key': JSON.stringify({ version: 1, commands: [good], note: 'x' }),
    'extra entry key': JSON.stringify({ version: 1, commands: [{ ...good, comment: 'x' }] }),
    'missing version': JSON.stringify({ commands: [good] }),
    'version 2': JSON.stringify({ version: 2, commands: [good] }),
    'version string': JSON.stringify({ version: '1', commands: [good] }),
    'uppercase hex': JSON.stringify({ version: 1, commands: [{ ...good, sha256: good.sha256.toUpperCase() }] }),
    '63 hex': JSON.stringify({ version: 1, commands: [{ ...good, sha256: good.sha256.slice(1) }] }),
    '65 hex': JSON.stringify({ version: 1, commands: [{ ...good, sha256: `${good.sha256}0` }] }),
    'non hex': JSON.stringify({ version: 1, commands: [{ ...good, sha256: `g${good.sha256.slice(1)}` }] }),
    'sha number': JSON.stringify({ version: 1, commands: [{ ...good, sha256: 5 }] }),
    'argv not array': JSON.stringify({ version: 1, commands: [{ ...good, argv_prefix: 'python3 -I x' }] }),
    'argv number word': JSON.stringify({ version: 1, commands: [{ ...good, argv_prefix: ['python3', 1, board] }] }),
    'commands object': JSON.stringify({ version: 1, commands: { 0: good } }),
    'top-level array': JSON.stringify([good]),
    'not json': '{"version":1,',
    'one bad entry beside a good one': JSON.stringify({ version: 1, commands: [good, { ...good, sha256: 'zz' }] }),
    'duplicate key trick': `{"version":1,"commands":[${JSON.stringify(good)}],"version":2}`,
    'empty file': '',
  };
  for (const [label, raw] of Object.entries(variants)) {
    declare([good]);
    assertDw(cmd());
    declare([good], { raw });
    assertNoMatch(cmd(), undefined, label);
    assert.deepEqual(dc().readDataCommands({ home: HOME }).entries, [], label);
  }
});
test('B6 21 entries: ignored; 20 entries: read, and every entry is usable', () => {
  const many = (n) => Array.from({ length: n }, (_, i) => entryFor(['python3', '-I', board, `s${i}`]));
  declare(many(21));
  assert.ok(statSync(declFile).size <= 4096, 'fixture stays under the size limit so only the count is tested');
  assertNoMatch(`python3 -I ${board} s0 C --note ${NOTE}`);
  assert.deepEqual(dc().readDataCommands({ home: HOME }).entries, []);
  declare(many(20));
  assertDw(`python3 -I ${board} s0 C --note ${NOTE}`);
  assertDw(`python3 -I ${board} s19 C --note ${NOTE}`);
  assertNoMatch(`python3 -I ${board} s20 C --note ${NOTE}`);
});
test('B6 another owner: ignored (checked with the process uid taken as someone else)', () => {
  const mine = dc().readDataCommands({ home: HOME });
  assert.equal(mine.entries.length, 1);
  const theirs = dc().readDataCommands({ home: HOME, uid: process.getuid() + 1 });
  assert.deepEqual(theirs.entries, []);
  assert.match(theirs.ignored, /owner|uid/i);
});
test('B6 absent file or folder: nothing declared, no complaint', () => {
  undeclare();
  const read = dc().readDataCommands({ home: HOME });
  assert.deepEqual([read.present, read.entries, read.ignored], [false, [], null]);
});
test('B6 a file the hook cannot read as a regular file (a folder, a fifo-sized oddity): ignored', () => {
  assertFileIgnored('folder instead of file', () => { rmSync(declFile); mkdirSync(declFile, { mode: 0o600 }); });
});

// ─── ENTRY VALIDITY ───
function withEntries(entries, fn) {
  declare([...entries, goodEntry()]);
  fn();
}
test('B7 entries that cannot be a plain "interpreter + script" or a script are ignored; the rest of the file still works', () => {
  const second = join(tools, 'second.py');
  const bad = [
    ['bash'], ['python3'], ['python3', '-c'], ['sh', '-c'], ['env', 'python3', second], ['sudo', 'python3', second], ['doas', 'python3', second], ['npx', 'x'],
    ['python3', '-c', second], ['python3', '-m', second], ['python3', '-Ic', second], ['node', '-e', second], ['node', '--eval', second], ['bash', '-c', second], ['sh', '-e', second],
    ['xargs', second], ['eval', second], ['exec', second], ['source', second], ['.', second], ['nohup', second], ['time', second], ['perl', '-e', second], ['ruby', '-e', second],
    ['python3', second, '-c'], ['python3', second, 'env'],
    ['python3', second, join(tools, 'edit.py')], ['python3', 'second.py'], ['python3', './second.py'], ['python3', '~/second.py'], ['python3', join(tools, 'missing.py')],
    ['python3', tools], [second], ['cat', second], ['rm', second], ['python3', 'set', second], ['python3', '-I', 'set', second],
    ['python3', second, 'a', 'b', 'c', 'd', 'e', 'f', 'g'],
    ['python3', `${second} `], ['python3', `${second};ls`], ['python3', '$HOME/x.py'], ['python3', `${tools}/../tools/second.py`], ['python3', '-I', second, '--out=/etc/x'], ['python3', '-I', second, '*'],
  ];
  for (const prefix of bad) {
    const writes = [{ argv_prefix: prefix, sha256: sha(readFileSync(second)) }, goodEntry()];
    declare(writes);
    const words = prefix.map((word) => (/[\s;*$]/.test(word) ? JSON.stringify(word) : word)).join(' ');
    assertNoMatch(`${words} C --note ${NOTE}`, undefined, JSON.stringify(prefix), false);
    assertDw(cmd());
  }
});
test('B7 the entries the acceptance names, one by one, in a file of their own', () => {
  const second = join(tools, 'second.py');
  for (const prefix of [['bash'], ['python3'], ['python3', '-c'], ['env', 'python3', second], ['sudo', 'python3', second], ['npx', 'x']]) {
    declare([{ argv_prefix: prefix, sha256: sha(readFileSync(second)) }]);
    assert.equal(dc().readDataCommands({ home: HOME }).entries.length, 1, 'the file itself is well formed');
    assertNoMatch(`${prefix.join(' ')} C --note ${NOTE}`, undefined, JSON.stringify(prefix));
  }
});
test('B7 an interpreter plus the script IS valid, and so is the script alone and a few safe interpreter flags', () => {
  const second = join(tools, 'second.py');
  for (const prefix of [['python3', second], ['python3', '-I', second], ['python3', '-I', '-B', second, 'set'], ['python3.11', second], [second, 'set'], ['bash', second], ['node', second], ['python3', second, 'set', 'card'], ['python3', second, '--flag']]) {
    declare([entryFor(prefix, second)]);
    assertDw(`${prefix.join(' ')} C --note ${NOTE}`);
  }
});
test('B7 a script over 1 MB is not declared-matching', () => {
  const big = join(tools, 'big.py');
  writeFileSync(big, `#!/usr/bin/env python3\n# ${'x'.repeat(1024 * 1024)}\n`);
  declare([entryFor(['python3', big], big)]);
  assertNoMatch(`python3 ${big} C --note ${NOTE}`);
  const exact = join(tools, 'exact.py');
  writeFileSync(exact, 'x'.repeat(1024 * 1024));
  declare([entryFor(['python3', exact], exact)]);
  assertDw(`python3 ${exact} C --note ${NOTE}`);
});

// ─── COLLISION: the label changes, the approval key does not ───
const keyOf = (command) => JSON.stringify(require('../dist/normalized-action.js').normalizedHookAction({ tool_name: 'Bash', tool_input: { command }, cwd: ws }, { salt: Buffer.alloc(32, 7) }));
test('K1b two declared commands that differ only in a note have the same label and different approval keys (normalized action)', () => {
  const second = `python3 -I ${board} set C42 --note "another note"`;
  const a = bash(cmd());
  const b = bash(second);
  assert.equal(a.action, b.action);
  assert.equal(a.action, DW_LABEL);
  assert.notEqual(keyOf(cmd()), keyOf(second));
  assert.notEqual(keyOf(cmd()), keyOf(cmd(' --tag x')));
});
test('K1b text after a secret-shaped span still changes the key; a different secret value alone may not', () => {
  // A dummy made at run time: 48 random hex characters, no known key prefix, shaped like a key only because it is long hex.
  const fake = randomBytes(24).toString('hex');
  assert.equal(require('../dist/normalized-action.js').looksLikeKey(fake), true);
  assert.doesNotMatch(fake, /^(?:sk|pk|rk|ghp|xox)/i);
  const one = `python3 -I ${board} set C42 --note "k=${fake} A"`;
  const two = `python3 -I ${board} set C42 --note "k=${fake} B"`;
  assert.notEqual(keyOf(one), keyOf(two));
  assert.doesNotMatch(keyOf(one), new RegExp(fake));
  assert.doesNotMatch(JSON.stringify(bash(one)), new RegExp(fake));
});
test('K1b the declaration does not change the approval key: same command, with and without the file', () => {
  const withFile = keyOf(cmd());
  undeclare();
  const without = keyOf(cmd());
  declare([goodEntry()]);
  assert.equal(withFile, without);
});

// ─── CONSUMERS: every shell tool name of every harness shares the classifier ───
test('CONSUMER every shell-tool spelling that classifyTool treats as Bash gets the same answer for a declared command', () => {
  for (const tool_name of ['Bash', 'bash', 'shell', 'run_terminal_command', 'execute_command', 'run_shell_command']) {
    const answer = classifyTool({ tool_name, tool_input: { command: cmd() }, cwd: ws });
    assert.deepEqual([answer.protected, answer.readOnly, answer.action], [false, false, `classified ${tool_name} action: process on workspace`], tool_name);
  }
});
test('CONSUMER a PowerShell dialect call and a tool with a second command text never become declared-matching', () => {
  const ps = classifyTool({ tool_name: 'PowerShell', tool_input: { command: cmd() }, cwd: ws });
  assert.equal(ps.protected, true);
  const two = classifyTool({ tool_name: 'Bash', tool_input: { command: cmd(), cmd: 'wrangler deploy' }, cwd: ws });
  assert.equal(two.protected, true);
  const mcp = classifyTool({ tool_name: 'mcp__x__run', tool_input: { command: cmd() }, cwd: ws });
  assert.equal(mcp.protected, true);
});
test('CONSUMER PostToolUse classification of a declared command is the same DW label', () => {
  const post = classifyTool({ tool_name: 'Bash', tool_input: { command: cmd() }, cwd: ws }, { postTool: true });
  assert.equal(isDw(post), true);
});
test('A42 writes to the declaration file by Bash, Write and Edit stay security holds (T2)', () => {
  for (const command of [`echo '{}' > ${HOME}/.marrow/data-commands.json`, `echo '{}' | tee -a ~/.marrow/data-commands.json`, `cp ${ws}/x.json ~/.marrow/data-commands.json`, `mv ${ws}/x.json ${HOME}/.marrow/data-commands.json`, `chmod 644 ~/.marrow/data-commands.json`, `rm ~/.marrow/data-commands.json`]) {
    const answer = bash(command);
    assert.equal(answer.protected, true, command);
    assert.match(answer.action, /security/, command);
  }
  for (const tool_name of ['Write', 'Edit']) {
    const answer = classifyTool({ tool_name, tool_input: { file_path: `${HOME}/.marrow/data-commands.json`, content: '{}', new_string: '{}', old_string: '' }, cwd: ws });
    assert.equal(answer.protected, true, tool_name);
    assert.match(answer.action, /security/, tool_name);
  }
});

// ─── OWNER-ONLY DECLARE ───
const CLI = join(__dirname, '..', 'dist', 'cli.js');
function cliRun(args, options = {}) {
  return spawnSync(process.execPath, [CLI, 'data-commands', ...args], { encoding: 'utf8', timeout: 30000, env: { ...process.env, HOME }, ...options });
}
function memoryIo(overrides = {}) {
  const out = []; const err = [];
  return { out, err, io: { isTTY: [true, true, true], readLine: () => null, write: (text) => out.push(text), writeErr: (text) => err.push(text), random: () => 'AB3K7Q', home: HOME, ...overrides } };
}
test('B8 add with no terminal on any of the three descriptors: exit 2, nothing written (function level, all 7 non-terminal combinations)', () => {
  undeclare();
  for (let mask = 0; mask < 7; mask += 1) {
    const flags = [Boolean(mask & 1), Boolean(mask & 2), Boolean(mask & 4)];
    const { io, out, err } = memoryIo({ isTTY: flags, readLine: () => 'AB3K7Q' });
    const code = dc().runDataCommands(['add', '--', 'python3', '-I', board, 'set'], io);
    assert.equal(code, 2, `tty flags ${flags}`);
    assert.equal(existsSync(declFile), false, `tty flags ${flags}`);
    assert.equal(existsSync(marrowDir), false, `no folder either: ${flags}`);
    assert.doesNotMatch(out.join('') + err.join(''), /AB3K7Q/);
  }
});
test('B8 remove with no terminal: exit 2, the file is untouched', () => {
  declare([goodEntry()]);
  const before = readFileSync(declFile, 'utf8');
  for (const flags of [[false, true, true], [true, false, true], [true, true, false], [false, false, false]]) {
    const { io } = memoryIo({ isTTY: flags, readLine: () => 'AB3K7Q' });
    assert.equal(dc().runDataCommands(['remove', '1'], io), 2);
    assert.equal(readFileSync(declFile, 'utf8'), before);
  }
});
test('B8 the real CLI: piped stdin/stdout/stderr (an agent shell) refuses with exit 2 and writes nothing', () => {
  undeclare();
  const run = cliRun(['add', '--', 'python3', '-I', board, 'set'], { input: 'AB3K7Q\n' });
  assert.equal(run.status, 2, run.stderr);
  assert.equal(existsSync(declFile), false);
  assert.equal(existsSync(marrowDir), false);
  assert.match(run.stderr, /terminal/i);
  const none = cliRun(['add', '--', 'python3', '-I', board, 'set'], { stdio: ['ignore', 'ignore', 'ignore'] });
  assert.equal(none.status, 2);
  assert.equal(existsSync(declFile), false);
});
test('B8 the real CLI: list runs with no terminal, writes nothing and prints one line when nothing is declared or the file is ignored', () => {
  undeclare();
  const none = cliRun(['list']);
  assert.equal(none.status, 0, none.stderr);
  assert.equal(none.stdout.trim().split('\n').length, 1);
  assert.equal(existsSync(marrowDir), false);
  declare([goodEntry()], { fileMode: 0o644 });
  const ignored = cliRun(['list']);
  assert.equal(ignored.status, 0, ignored.stderr);
  assert.match(ignored.stdout.trim(), /^data-commands\.json ignored: [^\n]+$/);
  assert.equal(cliRun(['--help']).status, 64);
  assert.equal(cliRun([]).status, 64);
});
test('B8 the real CLI under `script` with stdout piped away: not a terminal on all three descriptors, so refused', { skip: !existsSync('/usr/bin/script') }, () => {
  undeclare();
  const run = spawnSync('script', ['-qec', `${process.execPath} ${CLI} data-commands add -- python3 -I ${board} set | cat`, '/dev/null'], { encoding: 'utf8', timeout: 30000, input: 'AB3K7Q\n', env: { ...process.env, HOME } });
  assert.equal(existsSync(declFile), false, run.stdout);
  const piped = spawnSync('script', ['-qec', `${process.execPath} ${CLI} data-commands add -- python3 -I ${board} set 2>&1 </dev/null`, '/dev/null'], { encoding: 'utf8', timeout: 30000, input: 'AB3K7Q\n', env: { ...process.env, HOME } });
  assert.equal(existsSync(declFile), false, piped.stdout);
});
test('B8 the real CLI: a terminal on all three descriptors, a wrong code writes nothing and the right code writes one entry with mode 600', { skip: !existsSync('/usr/bin/python3') }, () => {
  undeclare();
  const driver = `
import os, pty, re, select, sys, time
mode, node, cli, home = sys.argv[1:5]
args = sys.argv[5:]
env = dict(os.environ); env['HOME'] = home
pid, fd = pty.fork()
if pid == 0:
    os.execve(node, [node, cli, 'data-commands'] + args, env)
buf = b''
sent = False
end = time.time() + 20
while time.time() < end:
    r, _, _ = select.select([fd], [], [], 0.5)
    if r:
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        buf += data
    m = re.search(rb'code[^A-Z0-9]{0,60}([A-Z2-9]{6})', buf)
    if m and not sent:
        os.write(fd, (m.group(1).decode() if mode == 'right' else 'WRONG1').encode() + b'\\n')
        sent = True
status = None
for _ in range(50):
    got, st = os.waitpid(pid, os.WNOHANG)
    if got:
        status = st
        break
    time.sleep(0.1)
if status is None:
    os.kill(pid, 9)
    os.waitpid(pid, 0)
    sys.stdout.write('killed\\n')
else:
    sys.stdout.write(str(os.waitstatus_to_exitcode(status)) + '\\n')
`;
  const run = (mode, args) => spawnSync('python3', ['-I', '-c', driver, mode, process.execPath, CLI, HOME, ...args], { encoding: 'utf8', timeout: 60000 });
  const wrong = run('wrong', ['add', '--', 'python3', '-I', board, 'set']);
  assert.equal(wrong.stdout.trim().split('\n').pop(), '1', wrong.stdout + wrong.stderr);
  assert.equal(existsSync(declFile), false);
  const right = run('right', ['add', '--', 'python3', '-I', board, 'set']);
  assert.equal(right.stdout.trim().split('\n').pop(), '0', right.stdout + right.stderr);
  assert.equal(statSync(declFile).mode & 0o777, 0o600);
  assert.equal(statSync(marrowDir).mode & 0o777, 0o700);
  assert.deepEqual(JSON.parse(readFileSync(declFile, 'utf8')), { version: 1, commands: [goodEntry()] });
  assert.deepEqual(readdirSync(marrowDir), ['data-commands.json']);
  assertDw(cmd());
});
test('B8 add (typed code right): computes the sha256 itself, writes mode 600 atomically, leaves no temp file, and the entry then matches', () => {
  undeclare();
  const { io, out } = memoryIo({ readLine: () => 'AB3K7Q' });
  assert.equal(dc().runDataCommands(['add', '--', 'python3', '-I', board, 'set'], io), 0, out.join(''));
  assert.equal(statSync(declFile).mode & 0o777, 0o600);
  assert.equal(statSync(marrowDir).mode & 0o777, 0o700);
  assert.deepEqual(JSON.parse(readFileSync(declFile, 'utf8')), { version: 1, commands: [goodEntry()] });
  assert.deepEqual(readdirSync(marrowDir), ['data-commands.json']);
  assert.match(out.join(''), /AB3K7Q/, 'the code is shown on the terminal');
  assertDw(cmd());
});
test('B8 add tells the owner what the hash covers: a note unless python runs isolated (-I)', () => {
  for (const [prefix, noted] of [[['python3', board], true], [['python3', '-I', board, 'set'], false], [['node', board], true], [[board, 'set'], true]]) {
    undeclare();
    const { io, out } = memoryIo({ readLine: () => 'AB3K7Q' });
    assert.equal(dc().runDataCommands(['add', '--', ...prefix], io), 0, JSON.stringify(prefix));
    assert.equal(/hash covers only the script/.test(out.join('')), noted, JSON.stringify(prefix));
  }
});
test('B8 add: a wrong, empty or missing typed code writes nothing and exits 1', () => {
  for (const typed of ['WRONG1', 'ab3k7q', '', null, 'AB3K7Q extra', ' AB3K7Q ']) {
    undeclare();
    const { io } = memoryIo({ readLine: () => typed });
    const code = dc().runDataCommands(['add', '--', 'python3', '-I', board, 'set'], io);
    if (typed === ' AB3K7Q ') { assert.ok(code === 0 || code === 1); undeclare(); continue; }
    assert.equal(code, 1, JSON.stringify(typed));
    assert.equal(existsSync(declFile), false, JSON.stringify(typed));
  }
});
test('B8 add refuses an invalid prefix (exit 1, nothing written), with the reason', () => {
  for (const prefix of [['bash'], ['python3', '-c', board], ['env', 'python3', board], ['python3', 'board.py'], ['python3', join(tools, 'nope.py')], ['python3', board, board]]) {
    undeclare();
    const { io, err, out } = memoryIo({ readLine: () => 'AB3K7Q' });
    assert.equal(dc().runDataCommands(['add', '--', ...prefix], io), 1, JSON.stringify(prefix));
    assert.equal(existsSync(declFile), false);
    assert.match(out.join('') + err.join(''), /\S/);
  }
});
test('B8 add needs the `--` separator and a non-empty prefix; unknown subcommands exit 64 and write nothing', () => {
  undeclare();
  const { io } = memoryIo({ readLine: () => 'AB3K7Q' });
  assert.notEqual(dc().runDataCommands(['add', 'python3', '-I', board, 'set'], io), 0);
  assert.notEqual(dc().runDataCommands(['add', '--'], io), 0);
  assert.notEqual(dc().runDataCommands(['frobnicate'], io), 0);
  assert.notEqual(dc().runDataCommands([], io), 0);
  assert.equal(existsSync(declFile), false);
});
test('B8 add refuses a duplicate prefix, a 21st entry, an existing ignored file and a folder with the wrong mode', () => {
  declare([goodEntry()]);
  let { io } = memoryIo({ readLine: () => 'AB3K7Q' });
  assert.notEqual(dc().runDataCommands(['add', '--', ...BOARD_PREFIX], io), 0);
  assert.equal(JSON.parse(readFileSync(declFile, 'utf8')).commands.length, 1);
  declare(Array.from({ length: 20 }, (_, i) => entryFor(['python3', '-I', board, `s${i}`])));
  ({ io } = memoryIo({ readLine: () => 'AB3K7Q' }));
  assert.notEqual(dc().runDataCommands(['add', '--', 'python3', '-I', board, 'extra'], io), 0);
  assert.equal(JSON.parse(readFileSync(declFile, 'utf8')).commands.length, 20);
  declare([goodEntry()], { fileMode: 0o644 });
  ({ io } = memoryIo({ readLine: () => 'AB3K7Q' }));
  assert.notEqual(dc().runDataCommands(['add', '--', 'python3', '-I', join(tools, 'second.py')], io), 0);
  assert.equal(statSync(declFile).mode & 0o777, 0o644, 'an ignored file is left for the owner to fix');
  undeclare();
  mkdirSync(marrowDir, { mode: 0o755 });
  chmodSync(marrowDir, 0o755);
  ({ io } = memoryIo({ readLine: () => 'AB3K7Q' }));
  assert.notEqual(dc().runDataCommands(['add', '--', ...BOARD_PREFIX], io), 0);
  assert.equal(existsSync(declFile), false);
});
test('B8 add never writes a file the hook would then ignore: refuses when the result would pass 4096 bytes', () => {
  const long = join(tools, `${'a'.repeat(200)}.py`);
  writeFileSync(long, BOARD);
  const bytes = (list) => Buffer.byteLength(`${JSON.stringify({ version: 1, commands: list })}\n`);
  const entries = [];
  while (bytes([...entries, entryFor(['python3', long, `w${entries.length}`], long)]) <= 4096) entries.push(entryFor(['python3', long, `w${entries.length}`], long));
  declare(entries);
  assert.ok(statSync(declFile).size <= 4096 && entries.length >= 5);
  const before = readFileSync(declFile, 'utf8');
  const { io } = memoryIo({ readLine: () => 'AB3K7Q' });
  assert.notEqual(dc().runDataCommands(['add', '--', 'python3', long, `w${entries.length}`], io), 0);
  assert.equal(readFileSync(declFile, 'utf8'), before);
  assert.deepEqual(readdirSync(marrowDir), ['data-commands.json']);
});
test('B8 list is read-only, needs no terminal, numbers entries and says why a file is ignored in one line', () => {
  declare([goodEntry(), entryFor(['python3', '-I', join(tools, 'second.py'), 'x'], join(tools, 'second.py'))]);
  const before = readFileSync(declFile, 'utf8');
  let { io, out } = memoryIo({ isTTY: [false, false, false] });
  assert.equal(dc().runDataCommands(['list'], io), 0);
  const text = out.join('');
  assert.match(text, /^\s*1[.)]?\s.*board\.py/m);
  assert.match(text, /^\s*2[.)]?\s.*second\.py/m);
  assert.equal(readFileSync(declFile, 'utf8'), before);
  chmodSync(declFile, 0o644);
  ({ io, out } = memoryIo({ isTTY: [false, false, false] }));
  assert.equal(dc().runDataCommands(['list'], io), 0);
  assert.match(out.join('').trim(), /ignored/i);
  assert.equal(out.join('').trim().split('\n').length, 1, 'one line');
  undeclare();
  ({ io, out } = memoryIo({ isTTY: [false, false, false] }));
  assert.equal(dc().runDataCommands(['list'], io), 0);
  assert.equal(existsSync(marrowDir), false, 'list writes nothing, not even the folder');
});
test('B8 list marks an entry whose script changed or vanished as not matching', () => {
  declare([goodEntry()]);
  writeFileSync(board, `${BOARD}# edited\n`);
  try {
    const { io, out } = memoryIo({ isTTY: [false, false, false] });
    assert.equal(dc().runDataCommands(['list'], io), 0);
    assert.match(out.join(''), /changed|differs|mismatch|not matching|inactive/i);
  } finally { writeFileSync(board, BOARD); }
});
test('B8 remove <n> needs the typed code, removes exactly entry n, keeps mode 600; a bad n changes nothing', () => {
  const second = join(tools, 'second.py');
  declare([goodEntry(), entryFor(['python3', '-I', second, 'x'], second), entryFor(['python3', second, 'y'], second)]);
  const before = readFileSync(declFile, 'utf8');
  let { io } = memoryIo({ readLine: () => 'AB3K7Q' });
  for (const bad of ['0', '4', '-1', 'x', '1.5', '']) assert.notEqual(dc().runDataCommands(['remove', bad], io), 0, bad);
  assert.notEqual(dc().runDataCommands(['remove'], io), 0);
  assert.equal(readFileSync(declFile, 'utf8'), before);
  ({ io } = memoryIo({ readLine: () => 'nope' }));
  assert.equal(dc().runDataCommands(['remove', '1'], io), 1);
  assert.equal(readFileSync(declFile, 'utf8'), before);
  ({ io } = memoryIo({ readLine: () => 'AB3K7Q' }));
  assert.equal(dc().runDataCommands(['remove', '2'], io), 0);
  const after = JSON.parse(readFileSync(declFile, 'utf8'));
  assert.deepEqual(after.commands.map((entry) => entry.argv_prefix.slice(-1)[0]), ['set', 'y']);
  assert.equal(statSync(declFile).mode & 0o777, 0o600);
  assert.deepEqual(readdirSync(marrowDir), ['data-commands.json']);
  assertDw(cmd());
});
test('B8 the typed code is random per run: six characters from an unambiguous alphabet, never reused from a fixed value', () => {
  const codes = new Set();
  for (let i = 0; i < 12; i += 1) {
    undeclare();
    const out = [];
    const io = { isTTY: [true, true, true], readLine: () => 'x', write: (text) => out.push(text), writeErr: (text) => out.push(text), home: HOME };
    dc().runDataCommands(['add', '--', ...BOARD_PREFIX], io);
    const shown = /type this code[^:]*: ([A-Z2-9]{6})\b/.exec(out.join(''));
    assert.ok(shown, out.join(''));
    codes.add(shown[1]);
  }
  assert.ok(codes.size >= 10, `${codes.size} distinct codes in 12 runs`);
});
test('doctor/status evidence: one line saying why a declaration file is ignored, and how many entries are in force', () => {
  declare([goodEntry()]);
  let evidence = dc().dataCommandsEvidence();
  assert.deepEqual([evidence.state, evidence.entries], ['active', 1]);
  chmodSync(declFile, 0o644);
  evidence = dc().dataCommandsEvidence();
  assert.deepEqual([evidence.state, evidence.entries], ['ignored', 0]);
  assert.match(String(evidence.reason), /^[^\n]{8,200}$/);
  undeclare();
  evidence = dc().dataCommandsEvidence();
  assert.deepEqual([evidence.state, evidence.entries, evidence.reason], ['none', 0, null]);
  assert.doesNotMatch(JSON.stringify(evidence), /[a-f0-9]{64}/, 'no hash in the evidence');
});
