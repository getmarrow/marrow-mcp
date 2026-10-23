'use strict';

// Every form in the fixture table that prints many or all environment variables must stop, keyless (seatbelt S4)
// and keyed (a protected action).
// The table is a known list of forms, not every command a shell can run. The rows are STRINGS fed to the checkers: nothing here runs a command or
// reads an environment. Friction rows must stay as they were, script files are out of reach by design, and each new
// rule has a mutant that a row kills.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');
const os = require('node:os');
const path = require('node:path');

const forms = require('./fixtures/env-dump-forms.cjs');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');

const ROOT = path.join(__dirname, '..');

function checkersFor(root) {
  const { classifyTool } = require(path.join(root, 'dist/hook-pre-action.js'));
  const { evaluateSeatbelt } = require(path.join(root, 'dist/seatbelt/mapper.js'));
  return {
    keyed: (command) => { const c = classifyTool({ tool_name: 'Bash', tool_input: { command } }); return c.protected === true && c.readOnly === false; },
    keyless: (command) => evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command } }, makeEnv({ classifierClass: 'routine' })),
  };
}
const live = checkersFor(ROOT);
const { mayPrintEnvironment } = require('../dist/hook-pre-action.js');
const stopRows = Object.entries(forms.stop).flatMap(([group, cmds]) => cmds.map((cmd) => ({ group, cmd })));
const passRows = Object.entries(forms.pass).flatMap(([group, cmds]) => cmds.map((cmd) => ({ group, cmd })));
const keylessStops = (checkers, cmd) => checkers.keyless(cmd).decision === 'stop';

test('every env-dump form stops keyless with an S4 reason', () => {
  assert.ok(stopRows.length >= 450, `${stopRows.length} stop rows`);
  const missed = stopRows.filter((r) => !live.keyless(r.cmd).hits.some((h) => h.category === 'S4')).map((r) => r.cmd);
  assert.deepEqual(missed, []);
});

test('every env-dump form is a protected action keyed', () => {
  assert.deepEqual(stopRows.filter((r) => !live.keyed(r.cmd)).map((r) => r.cmd), []);
});

// Pinned from the 3.9.103 line: these friction rows were already stopped for another reason before this change and are left as they were.
const ALREADY_STOPPED_KEYED = new Set(["git commit -m 'env dump fix'", 'git commit -m "printenv fix"', "git commit -m 'block printenv and process.env dumps'"]);
const ALREADY_STOPPED_KEYLESS = new Set(['ps -p 1 -o etime', 'ps -C node -o pid=', "jq '.env' package.json"]);

test('friction rows: env as a launcher, one non-secret name, one non-secret read, words that only mention env all pass as before', () => {
  assert.ok(passRows.length >= 150, `${passRows.length} friction rows`);
  assert.deepEqual(passRows.filter((r) => live.keyed(r.cmd) !== ALREADY_STOPPED_KEYED.has(r.cmd)).map((r) => r.cmd), []);
  assert.deepEqual(passRows.filter((r) => keylessStops(live, r.cmd) !== ALREADY_STOPPED_KEYLESS.has(r.cmd)).map((r) => r.cmd), []);
});

test('script files that dump the environment are out of reach: the check sees the command line, never file contents', () => {
  for (const cmd of forms.outOfReach) {
    assert.equal(live.keyed(cmd), false, cmd);
    assert.equal(keylessStops(live, cmd), false, cmd);
  }
});

test('the two modes agree: no row stops in one and not the other', () => {
  const all = [...stopRows, ...passRows];
  assert.deepEqual(all.filter((r) => live.keyed(r.cmd) !== keylessStops(live, r.cmd)).map((r) => r.cmd), [
    'ps -p 1 -o etime', 'ps -C node -o pid=', "git commit -m 'env dump fix'", 'git commit -m "printenv fix"', "git commit -m 'block printenv and process.env dumps'", "jq '.env' package.json",
  ]);
});

test('the keyed hook loads the mapper only for a command that holds an env-printing word; every stop row does, ordinary build work does not', () => {
  assert.deepEqual(stopRows.filter((r) => !mayPrintEnvironment(r.cmd)).map((r) => r.cmd), []);
  for (const cmd of ['git status', 'git push origin main', 'ls -la', 'wrangler deploy', 'npm test', 'node --test test/a.test.js', 'rm -rf build']) assert.equal(mayPrintEnvironment(cmd), false, cmd);
});

test('a read-only reading never hides a dump: a dynamic name, a pipe, a redirect and a heredoc stop keyed', () => {
  for (const cmd of ['printenv "$NAME"', 'env | sort', 'env > /tmp/e.txt', "node <<'EOF'\nconsole.log(process.env)\nEOF"]) assert.equal(live.keyed(cmd), true, cmd);
});

test('collisions: a command that differs only after an env word is not stopped for it, and one that differs by a secret name stops', () => {
  assert.equal(live.keyed('printenv HOME'), false);
  assert.equal(live.keyed('printenv GITHUB_TOKEN'), true);
  assert.equal(live.keyed('env FOO=1 npm test'), false);
  assert.equal(live.keyed('env FOO=1 env'), true);
  assert.equal(live.keyed('node -p "process.env.HOME"'), false);
  assert.equal(live.keyed('node -p "process.env.HOME, process.env"'), true);
});

// ---- patch round 2 (audit of 30a7f4e6): nawk, pypy, the policy stays free of the mapper, the filter is counted ----
const NAWK_ARGV_ROWS = [
  `nawk 'BEGIN{system(ARGV[1] " " ARGV[2] " " ARGV[3])}' wrangler deploy --prod`,
  `nawk 'BEGIN{for(i=1;i<ARGC;i++) s=s ARGV[i] " "; system(s)}' git push --force origin main`,
  `nawk 'BEGIN{system(ARGV[1])}' 'git push --force origin main'`,
  `nawk 'BEGIN{system(ARGV[1] " " ARGV[2])}' npm publish`,
  `nawk 'BEGIN{cmd=ARGV[1] " " ARGV[2]; cmd | getline x; print x}' npm publish`,
  `nawk 'BEGIN{print ARGV[1] " " ARGV[2] | "sh"}' npm publish`,
];

test('nawk (and awk, gawk, mawk) programs that build a command from their own arguments stop keyless and keyed', () => {
  for (const cmd of NAWK_ARGV_ROWS) {
    assert.equal(keylessStops(live, cmd), true, cmd);
    assert.equal(live.keyed(cmd), true, cmd);
    for (const awk of ['awk', 'gawk', 'mawk']) assert.equal(keylessStops(live, cmd.replace(/^nawk/, awk)), true, `${awk}: ${cmd}`);
  }
  // nawk keeps what it was stopped for before it was read as awk: the argument scan of an unknown program.
  for (const cmd of ["nawk '{print}' npm publish", "nawk '{print}' wrangler deploy --prod"]) assert.equal(keylessStops(live, cmd), true, cmd);
});

test('awk friction rows still pass: plain print, field separators, a file read with getline, a literal date', () => {
  for (const cmd of ["awk '{print $1}' file.txt", "awk -F, '{print $2}' data.csv", "awk '{s+=$1} END{print s}' nums.txt", "nawk '{print $1}' file.txt", "nawk -F, '{print $2}' data.csv",
    "awk 'BEGIN{while((getline l < ARGV[1])>0) n++; print n}' file.txt", `awk 'BEGIN{"date" | getline d; print d}'`]) {
    assert.equal(keylessStops(live, cmd), false, cmd);
    assert.equal(live.keyed(cmd), false, cmd);
  }
});

test('pypy keeps its -e reading (a stop) and gains python -c', () => {
  for (const prog of ['pypy', 'pypy3']) {
    for (const flag of ['-e', '-c']) {
      const cmd = `${prog} ${flag} 'import os; os.system("npm publish")'`;
      assert.equal(keylessStops(live, cmd), true, cmd);
      assert.equal(live.keyed(cmd), true, cmd);
    }
    assert.equal(keylessStops(live, `${prog} -c 'print(1)'`), false);
    assert.equal(keylessStops(live, `${prog} script.py`), false);
  }
  assert.equal(keylessStops(live, "pypy3 -c 'import os; print(os.environ)'"), true);
});

// Counts mapper loads and evaluateSeatbeltShell calls in a fresh process (test/support/env-filter-count.cjs). `post` drives the REAL PostToolUse
// handler (dist/hook.js runHookCommand) with a private HOME and every network and process entry point trapped; `classify` is the pre-action classification.
function countRows(rootDir, mode, rows, eventName) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-envdump-count-'));
  try {
    const file = path.join(dir, 'rows.json');
    fs.writeFileSync(file, JSON.stringify(rows));
    const out = spawnSync(process.execPath, [path.join(rootDir, 'test', 'support', 'env-filter-count.cjs'), mode, file, ...(eventName ? [eventName] : [])], { encoding: 'utf8' });
    assert.equal(out.status, 0, out.stderr.slice(0, 300));
    return JSON.parse(out.stdout);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
const postPathRows = () => [...stopRows.map((r) => r.cmd), ...passRows.map((r) => r.cmd), ...forms.outOfReach, ...ORDINARY_NO_LOAD];

test('the tool policy never uses the mapper: only the pre-action hook does (U5)', () => {
  const policy = fs.readFileSync(path.join(ROOT, 'src', 'hook-tool-policy.ts'), 'utf8');
  assert.equal(/seatbelt\//.test(policy), false);
});

test('counted, no clock: the real PostToolUse handler never loads the mapper or calls it, for the stop rows and for everyday commands', () => {
  const rows = postPathRows();
  assert.ok(rows.length >= 650, `${rows.length} rows`);
  for (const eventName of ['PostToolUse', 'PostToolUseFailure']) {
    const counted = countRows(ROOT, 'post', rows, eventName);
    assert.deepEqual({ loads: counted.loads, calls: counted.calls, trapped: counted.trapped, stdoutBytes: counted.stdoutBytes }, { loads: 0, calls: 0, trapped: 0, stdoutBytes: 0 }, eventName);
    assert.equal(counted.perCommand.length, rows.length);
    // The handler reached its classification for every row (a handler that returned early would pass this test for nothing).
    assert.ok(counted.classifyCalls >= rows.length, `${eventName}: ${counted.classifyCalls} classifications for ${rows.length} rows`);
  }
});

// Ordinary work: none of these can print the environment, so the keyed hook must not load the mapper for any of them.
const ORDINARY_NO_LOAD = [
  "jq '.name' package.json", "jq -r '.version' package.json", 'jq . package.json', "jq '.scripts' package.json", "jq -c '.dependencies | keys' package.json",
  'docker ps', 'docker ps -a', 'docker images', 'docker logs web', 'docker compose up -d', 'ps aux', 'ps -p 1', 'pgrep node', 'top -bn1',
  'git status', 'git log --oneline -5', 'git diff', 'git diff --stat', 'git add -A', 'git commit -m "fix login redirect"', 'git commit -m "set up ci"', 'git commit -m "set up the release job"',
  'git checkout -b env-fix', 'git checkout -b fix/env-loading', 'git switch -c feature/new-env-handling', 'git checkout main', 'git stash', 'git show HEAD', 'git branch -a', 'git fetch origin',
  'node -e "console.log(process.env.HOME)"', "node -p 'process.env.NODE_ENV'", "node -e 'console.log(process.env.PATH.split(\":\").length)'", 'node --test test/a.test.js', 'node script.js',
  'npm test', 'npm run build', 'npm ci', 'npm install', 'npm ls', 'npm run dev', 'npx tsc --noEmit', 'pnpm install', 'yarn build',
  'ls -la', 'ls src', 'cat package.json', 'cat README.md', 'head -20 src/index.ts', 'tail -n 50 server.log', 'wc -l src/a.ts', 'grep -rn TODO src', 'rg foo src', 'find . -name "*.ts" -newer package.json',
  'mkdir -p build', 'cp a.txt b.txt', 'mv a.txt b.txt', 'rm -rf build', 'touch notes.md', 'pwd', 'whoami', 'date', 'uname -a', 'df -h', 'du -sh src', 'echo hello', 'sleep 1', 'true',
  'python3 script.py', 'python3 -m pytest', 'pytest -q', 'make build', 'make test', 'tsc -p .', 'eslint src', 'prettier --check .', 'cargo build', 'go test ./...',
  'curl -s https://example.com/health', 'wget -q https://example.com/a.txt', 'tar -czf out.tgz build', 'unzip a.zip', 'sed -n 1,5p README.md', 'sort a.txt', 'uniq -c a.txt', 'diff a.txt b.txt',
  'kubectl get pods', 'wrangler whoami', 'gh pr list', 'gh pr view 12', 'set -e', 'set -euo pipefail',
];

test('counted, no clock: the keyed hook never loads the mapper for ordinary commands, and runs it for every stop row', () => {
  assert.ok(ORDINARY_NO_LOAD.length >= 40, `${ORDINARY_NO_LOAD.length} ordinary commands`);
  for (const named of ["jq '.name' package.json", 'docker ps', 'ps aux', 'git checkout -b env-fix', 'node -e "console.log(process.env.HOME)"', 'git commit -m "set up ci"']) assert.ok(ORDINARY_NO_LOAD.includes(named), named);
  const count = (rows) => countRows(ROOT, 'classify', rows);
  const ordinary = count(ORDINARY_NO_LOAD);
  assert.deepEqual({ loads: ordinary.loads, calls: ordinary.calls }, { loads: 0, calls: 0 });
  for (const cmd of ORDINARY_NO_LOAD) assert.equal(mayPrintEnvironment(cmd), false, cmd);
  // The pre-action path is where the stop rows reach the mapper: one load, and at least one call for every row.
  const stops = count(stopRows.map((r) => r.cmd));
  assert.equal(stops.loads, 1);
  assert.deepEqual(stopRows.filter((r, i) => stops.perCommand[i] < 1).map((r) => r.cmd), []);
});

test('the filter words: what it reads closely, and what no spelling can hide', () => {
  const loads = (cmd) => mayPrintEnvironment(cmd);
  // bare set only (the mapper's rule is no operand); the word in a message, set -e and an assignment are not
  for (const cmd of ['set', 'set | sort', 'true; set', '(set)', '{ set; }', 'bash -c set', 'FOO=1 set', 'set 2>&1', 'set > out.txt', 'true\nset\ntrue', 'set # all', 'builtin set']) assert.equal(loads(cmd), true, cmd);
  for (const cmd of ['set -e', 'set -euo pipefail', 'git commit -m "set up ci"', 'set=1', 'npm set registry x']) assert.equal(loads(cmd), false, cmd);
  // an expansion can spell a narrowed word: those commands are read as before
  for (const cmd of ['x=; set $x', 'set "$@"', 'jq -n $f', 'a=p; b=s; ps $x', 'echo {p,q}s e; ps']) assert.equal(loads(cmd), true, cmd);
  // ps: an e or E after it
  for (const cmd of ['ps e', 'ps auxe', 'ps -E', 'ps eww', 'sudo ps e', 'docker run x ps e', 'ps aux; ps e']) assert.equal(loads(cmd), true, cmd);
  for (const cmd of ['ps aux', 'docker ps', 'docker ps -a', 'ps -p 1']) assert.equal(loads(cmd), false, cmd);
  // jq: env in the text
  for (const cmd of ['jq -n env', "jq -n '$ENV'", "jq 'env|keys' x.json", 'jq -n env-1', 'jq -f - <<EOF\nenv\nEOF']) assert.equal(loads(cmd), true, cmd);
  for (const cmd of ["jq '.name' package.json", 'jq -r .version package.json', "jq -c '.a | keys' x.json"]) assert.equal(loads(cmd), false, cmd);
  // /proc and a computed process name; process.env.NAME for a non-secret NAME holds nothing, a secret name or the whole object does
  for (const cmd of ['grep -ra . /proc/self/', 'cd /proc && grep -r . self', 'cat /proc/1/environ', "node -e \"console.log(process['en' + 'v'])\"", 'node -e "console.log(process.env)"', 'node -e "x = process.env.GITHUB_TOKEN"',
    'node -p "process.env.HOME, process.env"', 'node -e "process.env.keys"', 'node -e "process.env.HOME; const { env } = process"', 'node -e "process; env-1"']) assert.equal(loads(cmd), true, cmd);
  for (const cmd of ['node -e "console.log(process.env.HOME)"', "node -p 'process.env.NODE_ENV'", 'node -e "console.log(process.version, process.argv)"']) assert.equal(loads(cmd), false, cmd);
  // env joined to a branch name in a plain git command holds nothing; with a secret-looking word, a chain, a substitution or any other program it does
  for (const cmd of ['git checkout -b env-fix', 'git switch -c fix/env-loading', 'git branch my-env-fix']) assert.equal(loads(cmd), false, cmd);
  for (const cmd of ['git checkout -b env-token-fix', 'git checkout -b env-fix; env', 'git checkout -b env-fix && printenv', 'git checkout -b env-fix $(env)', 'git log --pager=env', 'git checkout env', 'echo env-fix', 'python3 -m venv env', 'ruby -e "p ENV-1"']) assert.equal(loads(cmd), true, cmd);
  // quotes, backslashes and an ANSI-C quote cannot split a word out of the filter
  for (const cmd of ["e'n'v", 'pr\\intenv', "$'\\x65nv'", 'compg""en -e', "t'm'ux show-e"]) assert.equal(loads(cmd), true, cmd);
});

test('the filter is linear on hostile text: a long run of ps words or blanks does not stall it', () => {
  for (const text of [`${'ps '.repeat(40000)}`, `process${' '.repeat(100000)}x`, `${'process '.repeat(20000)}x`, `set${' '.repeat(100000)}x`, `git ${'a-'.repeat(50000)}`]) {
    const started = process.hrtime.bigint();
    mayPrintEnvironment(text);
    // a generous bound that only a quadratic scan would miss (the linear scans take a few milliseconds)
    assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 2000, 'the filter took over two seconds');
  }
});

test('the filter keeps the mapper\'s own secret-name pattern', () => {
  const { SECRET_VAR } = require('../dist/seatbelt/tables.js');
  const { ENV_FILTER_SECRET_NAME } = require('../dist/hook-pre-action.js');
  assert.equal(ENV_FILTER_SECRET_NAME.source, SECRET_VAR.source);
  assert.equal(ENV_FILTER_SECRET_NAME.flags, SECRET_VAR.flags);
});

// ---- mutants: each new rule, switched off in a copy of the build, must let a killer row through ----
const off = (name) => ({ from: new RegExp(`function ${name}\\(([^)]*)\\) \\{`), to: (m, args) => `function ${name}(${args}) { return false;` });
const text = (from, to) => ({ from: new RegExp(from.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')), to: () => to });
const MUTANTS = [
  { id: 'compgen names', file: 'seatbelt/env-dump.js', edit: off('compgenListsVariables'), killers: ['compgen -e', 'compgen -A variable'] },
  { id: 'tmux show-environment', file: 'seatbelt/env-dump.js', edit: off('tmuxShowsEnvironment'), killers: ['tmux show-environment', 'tmux showenv -g'] },
  { id: 'tmux runs env printer', file: 'seatbelt/env-dump.js', edit: off('tmuxRunsEnvironmentPrinter'), killers: ['tmux send-keys -t x env Enter', 'tmux run-shell env'] },
  { id: 'systemctl show-environment', file: 'seatbelt/env-dump.js', edit: off('systemctlShowsEnvironment'), killers: ['systemctl show-environment'] },
  { id: 'ps precise', file: 'seatbelt/env-dump.js', edit: off('psPrintsEnvironment'), killers: ['ps -E', 'ps e'] },
  { id: 'jq env', file: 'seatbelt/env-dump.js', edit: off('jqFilterReadsEnvironment'), killers: ["jq -n env", "jq -n '$ENV'"] },
  { id: 'npm run env', file: 'seatbelt/env-dump.js', edit: off('packageRunsEnvScript'), killers: ['npm run env', 'pnpm run env'] },
  { id: 'strace verbose', file: 'seatbelt/env-dump.js', edit: off('straceShowsEnvironment'), killers: ['strace -v -e execve true', 'strace --no-abbrev true'] },
  { id: 'man pager', file: 'seatbelt/env-dump.js', edit: off('manPagerPrintsEnvironment'), killers: ['man -P env ls'] },
  { id: 'proc glob', file: 'seatbelt/env-dump.js', edit: off('procGlobMatchesEnviron'), killers: ['cat /proc/12345/env*', 'cat /proc/12345/task/678/envi?on'] },
  { id: 'proc task path', file: 'secret-paths.js', edit: { from: /task\\\/\[\^\/\]\+\\\/\)\?environ\$\/|'\/proc\/\*\/task\/\*\/environ'/g, to: (m) => (m.startsWith("'") ? "'/proc/*/task/*/environZ'" : 'task\\/[^/]+\\/)?environZ$/') }, killers: ['cat /proc/self/task/1/environ', 'cat < /proc/self/task/1/environ'] },
  { id: 'proc recursive folder', file: 'seatbelt/mapper.js', edit: text('(folder !== null && folder.test(p))', 'false'), killers: ['grep -ra . /proc/self/', 'cp -r /proc/self /tmp/x'] },
  { id: 'exec wrapper tail', file: 'seatbelt/mapper.js', edit: text('EXEC_WRAPPERS.has(prog)', 'false'), killers: ['setpriv --reuid=1000 env', 'unshare -r env'] },
  { id: 'helper variable', file: 'seatbelt/mapper.js', edit: text('HELPER_ENV_VARS.has(name)', 'false'), killers: ['PAGER=env man ls'] },
  { id: 'xargs bare env', file: 'seatbelt/mapper.js', edit: off('xargsRunsBareEnv'), killers: ['echo x | xargs -I{} env', 'parallel env ::: x'] },
  { id: 'nawk', file: 'seatbelt/mapper.js', edit: text("case 'nawk':", "case 'nawkX':"), killers: ["nawk 'BEGIN{for (k in ENVIRON) n++; print n}'"] },
  { id: 'php info', file: 'seatbelt/mapper.js', edit: text("w === '-i' || w === '--info'", "w === '-iX' || w === '--infoX'"), killers: ['php -i'] },
  { id: 'attached code flag', file: 'seatbelt/mapper.js', edit: text('if (attachedCode)', 'if (false)'), killers: ['node --eval="console.log(process.env)"', "perl -e'print %ENV'"] },
  { id: 'pypy code flag', file: 'seatbelt/mapper.js', edit: text('|pypy3?(?:\\.\\d+)?', ''), killers: ["pypy3 -c 'import os; print(os.environ)'"] },
  { id: 'ts-node print', file: 'seatbelt/mapper.js', edit: text("'ts-node': /^(?:-e|--eval|-p|--print)$/", "'ts-node': /^(?:-eX)$/"), killers: ["npx ts-node -p 'process.env'"] },
  { id: 'phpinfo', file: 'seatbelt/mapper.js', edit: text('phpinfo', 'phpinfoX'), killers: ["php -r 'phpinfo();'"] },
  { id: 'os.environb', file: 'seatbelt/mapper.js', edit: text('os\\.environb?\\b', 'os\\.environ\\b'), killers: ['python3 -c "import os; print(os.environb[b\'HOME\'])"'] },
  { id: 'process without env spelling', file: 'seatbelt/mapper.js', edit: text('return (/\\bprocess\\b/.test(rest) &&', 'return (false &&'), killers: ['node -e "const e = process[\'en\' + \'v\']; console.log(e)"'] },
  { id: 'globalThis computed', file: 'seatbelt/mapper.js', edit: text('|| /\\b(?:globalThis|global)', '|| false && /\\b(?:globalThis|global)'), killers: ["node -e \"console.log(globalThis['pro' + 'cess']['en' + 'v'])\""] },
  { id: 'nawk keeps the unknown-program scan', file: 'seatbelt/mapper.js', edit: { from: /case 'nawk':\s*awkProgram\(rest, ctx, run, x\);\s*break;/, to: () => "case 'nawk': return awkProgram(rest, ctx, run, x);" }, killers: ["nawk '{print}' npm publish", "nawk '{print}' wrangler deploy --prod"] },
  { id: 'awk program that runs its arguments', file: 'seatbelt/mapper.js', edit: text('AWK_RUNS_ARGV.test(text) &&', 'false &&'), killers: ["gawk 'BEGIN{system(ARGV[1] \" \" ARGV[2])}' npm publish", "mawk 'BEGIN{system(ARGV[1])}' 'git push --force origin main'"] },
  { id: 'pypy -e is still code', file: 'seatbelt/mapper.js', edit: text('(?:-[a-zA-Z]*c|-e)', '(?:-[a-zA-Z]*c)'), killers: ["pypy3 -e 'import os; os.system(\"npm publish\")'"] },
  // Part B (audit LOWs L1 and L3 of Part A). Several rules guard the same class on purpose (the shared table, the env-dump reason, the glob scan), so a
  // mutant that switches one off keeps another standing: where that is so the killer rows are the ones only that rule reaches.
  { id: 'part B: redirect to a known path carries the env-dump reason', file: 'seatbelt/mapper.js', edit: { from: /if \(env_dump_1\.PROC_ENVIRON\.test\(r\)\)\s*hit\(run, 'S4', 'proc_environ'\);/, to: () => '' }, killers: ['P=/proc/self/task/1; cat < $P/environ', 'f=environ; cat < /proc/self/task/1/$f'], keyedOnly: true },
  { id: 'part B: glob or dynamic redirect target carries the env-dump reason', file: 'seatbelt/mapper.js', edit: { from: /if \(sampleMatch\(probe, ctx, run, samples\.filter\(\(s\) => env_dump_1\.PROC_ENVIRON\.test\(s\)\)\)\)\s*hit\(run, 'S4', 'proc_environ'\);/, to: () => '' }, killers: ['cat < /proc/self/task/1/e*', 'cat < /p[r]oc/self/en[v]iron', 'cat < /proc/self/$(echo task/1)/environ'], keyedOnly: true },
  { id: 'part B: glob in a folder reaches the mapper (keyed)', file: 'hook-pre-action.js', edit: { from: /if \(globInFolderPart\(words\)\)\s*return true;/, to: () => '' }, killers: ['cat /???c/self/task/1/e*', 'cat < /p*/self/e*', 'cd / && cat p?oc/self/e?viron'], keyedOnly: true },
  { id: 'part B: parent segments in a glob', file: 'seatbelt/mapper.js', edit: text("collapseParents(cand.replace(/\\/\\.\\//g, '/'))", "cand.replace(/\\/\\.\\//g, '/')"), killers: ['cat < /tmp/../p*/self/e*', 'cat < $HOME/../../p*/self/e*'] },
  { id: 'part B: parameter default word', file: 'seatbelt/mapper.js', edit: text('function parameterDefaultReading(a) {', 'function parameterDefaultReading(a) { return null;'), killers: ['cat < ${P:-/proc/self/task/1/environ}', 'cat ${P:=/proc/self/environ}'] },
  { id: 'part B: cd into a process folder by a dynamic id', file: 'seatbelt/mapper.js', edit: text('...procFolderGuesses(target, ctx), null', 'null'), killers: ['cd /proc/$$ && cat < environ', 'cd /proc/$(pgrep -o node)/task/1 && cat environ'] },
  { id: 'part B: find exec under /proc', file: 'seatbelt/mapper.js', edit: text('named.some((smp) => env_dump_1.PROC_ENVIRON.test(smp))', 'false'), killers: ['find /proc/self/task -name environ -exec cat {} +'], keyedOnly: true },
  { id: 'part B: awk program that starts a command', file: 'seatbelt/mapper.js', edit: text('if (env_dump_1.AWK_STARTS_COMMAND.test(text)) {', 'if (false) {'), killers: ["awk 'BEGIN{system(ARGV[1])}' env", "awk -v c=printenv 'BEGIN{system(c)}'"] },
  { id: 'part B: code that starts a command takes its operand', file: 'seatbelt/mapper.js', edit: text('else if (env_dump_1.CODE_STARTS_COMMAND.test(codeText)) {', 'else if (false) {'), killers: ["perl -e 'system(shift)' env", "lua -e 'os.execute(arg[1])' env", "php -r 'passthru($argv[1]);' printenv"] },
  { id: 'part B: repeated code flag', file: 'seatbelt/mapper.js', edit: text('for (let j = i + 2; j < rest.length; j += 1) {', 'for (let j = rest.length; j < rest.length; j += 1) {'), killers: ["perl -e 'print 1' -e 'system(shift)' env"] },
  { id: 'part B: value set on the command line reaches env-reading code', file: 'seatbelt/mapper.js', edit: off('assignedEnvPrinters'), killers: ["X=env awk 'BEGIN{system(ENVIRON[\"X\"])}'", "C=env perl -e 'system $ENV{C}'"] },
  { id: 'part B: operand that is a command line holding env', file: 'seatbelt/env-dump.js', edit: text('(/\\s/.test(word) && /\\b(?:env|printenv)\\b/.test(word))', 'false'), killers: ["perl -e 'system(shift)' 'sh -c env'"] },
  { id: 'part B: positional parameters of sh -c', file: 'seatbelt/mapper.js', edit: off('positionalCommands'), killers: ["sh -c '\"$@\"' _ env", "bash -c 'exec \"$@\"' x printenv", "bash -c 'for c; do \"$c\"; done' _ env"], keyedOnly: true },
  { id: 'filter: bare set', file: 'hook-pre-action.js', edit: text('|\\bset\\b(?=', '|\\bsetX\\b(?='), killers: ['set', 'true; set | sort'], keyedOnly: true },
  { id: 'filter: ps with e', file: 'hook-pre-action.js', edit: text('/[eE]/.test(words.slice(ps.index + 2))', 'false'), killers: ['ps e', 'ps -E'], keyedOnly: true },
  { id: 'filter: /proc folder', file: 'hook-pre-action.js', edit: text('|\\bproc\\b|', '|\\bprocX\\b|'), killers: ['grep -ra . /proc/self/'], keyedOnly: true },
  { id: 'filter: computed process name', file: 'hook-pre-action.js', edit: text('|\\bprocess\\s*(?:\\?\\.\\s*)?\\[', ''), killers: ["node -e \"const e = process['en' + 'v']; console.log(e)\""], keyedOnly: true },
  { id: 'keyed asks the mapper', file: 'hook-pre-action.js', edit: text('isSecretMaterialAccessAsNamed)(event, printsEnvironment)', 'isSecretMaterialAccessAsNamed)(event)'), killers: ['bash -c env', 'compgen -e'], keyedOnly: true },
  { id: 'keyed read-only bypass', file: 'hook-pre-action.js', edit: text('isReadOnlyToolEventAsNamed)(event, printsEnvironment)', 'isReadOnlyToolEventAsNamed)(event)'), killers: ['printenv "$NAME"'], keyedOnly: true },
];

function mutantBuild(file, edit) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-envdump-mutant-'));
  fs.cpSync(path.join(ROOT, 'dist'), path.join(dir, 'dist'), { recursive: true });
  fs.symlinkSync(path.join(ROOT, 'vendor'), path.join(dir, 'vendor'));
  fs.symlinkSync(path.join(ROOT, 'node_modules'), path.join(dir, 'node_modules'));
  fs.copyFileSync(path.join(ROOT, 'package.json'), path.join(dir, 'package.json'));
  // The counting helper reads the build next to it, so a mutant copy carries its own.
  fs.mkdirSync(path.join(dir, 'test', 'support'), { recursive: true });
  for (const helper of ['env-filter-count.cjs', 'passwd-home-fake.cjs']) fs.copyFileSync(path.join(ROOT, 'test', 'support', helper), path.join(dir, 'test', 'support', helper));
  const target = path.join(dir, 'dist', file);
  const before = fs.readFileSync(target, 'utf8');
  const after = before.replace(edit.from, edit.to);
  assert.notEqual(after, before, `the mutant edit found its text in ${file}`);
  fs.writeFileSync(target, after);
  return dir;
}

for (const mutant of MUTANTS) {
  test(`mutant killed: ${mutant.id}`, () => {
    for (const cmd of mutant.killers) {
      assert.equal(live.keyed(cmd), true, `${cmd} keyed`);
      if (!mutant.keyedOnly) assert.equal(keylessStops(live, cmd), true, `${cmd} keyless`);
    }
    const dir = mutantBuild(mutant.file, mutant.edit);
    try {
      const mutated = checkersFor(dir);
      const survived = mutant.killers.filter((cmd) => mutated.keyed(cmd) && (mutant.keyedOnly || keylessStops(mutated, cmd)));
      assert.ok(survived.length < mutant.killers.length, `no killer row noticed the mutant: ${mutant.id}`);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
}

// The PostToolUse path asks no environment-print check (classifyTool's postTool option). Putting the mapper call back on it, in either place the
// handler classifies, must fail the counted test: the real handler then loads the mapper and calls it.
const POST_PATH_MUTANTS = [
  { id: 'post path asks the mapper (classifyAsNamed ignores postTool)', file: 'hook-pre-action.js', edit: text('options.postTool === true ? undefined : shellPrintsEnvironment', 'shellPrintsEnvironment') },
  { id: 'post path asks the mapper (deriveAction drops postTool)', file: 'hook.js', edit: text('classifyTool)(event, { postTool: true }).action', 'classifyTool)(event, {}).action') },
];

for (const mutant of POST_PATH_MUTANTS) {
  test(`mutant killed: ${mutant.id}`, () => {
    const rows = postPathRows();
    const live = countRows(ROOT, 'post', rows, 'PostToolUse');
    assert.deepEqual({ loads: live.loads, calls: live.calls }, { loads: 0, calls: 0 });
    const dir = mutantBuild(mutant.file, mutant.edit);
    try {
      const mutated = countRows(dir, 'post', rows, 'PostToolUse');
      assert.ok(mutated.loads >= 1 && mutated.calls >= 1, `the counted post-path test did not notice the mutant: ${mutant.id}`);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
}


// ---- Part B (audit LOWs L1 and L3 of Part A): tool events, outage, hashes, the filter's glob rule, and friction ----
const { classifyTool: classifyEvent } = require('../dist/hook-pre-action.js');
const toolStops = (tool, input) => evaluateSeatbeltEvent({ tool_name: tool, tool_input: input }, makeEnv({ classifierClass: 'routine' })).decision === 'stop';
const toolKeyed = (tool, input) => { const c = classifyEvent({ tool_name: tool, tool_input: input }); return c.protected === true && c.readOnly === false; };
const { evaluateSeatbelt: evaluateSeatbeltEvent } = require('../dist/seatbelt/mapper.js');

test('part B: the Read and Grep tools on a process environ file or a process folder stop keyless and keyed; other /proc files and ordinary folders do not', () => {
  const stops = [
    ['Read', { file_path: '/proc/self/task/1/environ' }], ['Read', { file_path: '/proc/1234/task/1234/environ' }], ['Read', { file_path: '/proc/thread-self/environ' }],
    ['Read', { file_path: '/proc/self/task/1/../1/environ' }], ['Grep', { pattern: 'x', path: '/proc/self/task/1/environ' }], ['Grep', { pattern: 'x', path: '/proc/self/task' }],
    ['Grep', { pattern: 'x', path: '/proc' }], ['Grep', { pattern: 'x', path: '/proc/self/task/1/' }], ['Grep', { pattern: 'x', path: '/proc/1234' }],
  ];
  for (const [tool, input] of stops) {
    assert.equal(toolStops(tool, input), true, `${tool} ${JSON.stringify(input)} keyless`);
    assert.equal(toolKeyed(tool, input), true, `${tool} ${JSON.stringify(input)} keyed`);
  }
  const passes = [
    ['Read', { file_path: '/proc/self/task/1/status' }], ['Read', { file_path: '/home/u/proj/src/environ.ts' }], ['Grep', { pattern: 'x', path: '/proc/cpuinfo' }],
    ['Grep', { pattern: 'x', path: '/proc/sys/kernel' }], ['Grep', { pattern: 'x', path: '/home/u/proj/src' }],
  ];
  for (const [tool, input] of passes) {
    assert.equal(toolStops(tool, input), false, `${tool} ${JSON.stringify(input)} keyless`);
    assert.equal(toolKeyed(tool, input), false, `${tool} ${JSON.stringify(input)} keyed`);
  }
});

test('part B: the normalized action (the approval key input) is the command text only, so a row hashes equal to itself and differs from every other row', () => {
  const { normalizedHookAction } = require('../dist/normalized-action.js');
  // The text hash is keyed per install (a null salt gives a random value that matches nothing), so the rows are hashed under a dummy key made now.
  const salt = require('node:crypto').randomBytes(32);
  const hash = (command) => JSON.stringify(normalizedHookAction({ tool_name: 'Bash', tool_input: { command } }, { salt }).tool_input);
  const a = hash('cat < /proc/self/task/1/environ');
  assert.equal(a, hash('cat < /proc/self/task/1/environ'));
  for (const other of ['cat < /proc/self/task/2/environ', 'cat < /proc/self/task/1/environ; true', 'cat < /proc/self/task/1/status', 'cat 0< /proc/self/task/1/environ']) {
    assert.notEqual(a, hash(other), other);
  }
  // Text after a redacted span still counts: only the secret VALUE may be ignored, never what follows it.
  const dummy = `${'x'.repeat(24)}`;
  assert.notEqual(hash(`awk 'BEGIN{system(ARGV[1])}' env TOKEN=${dummy}`), hash(`awk 'BEGIN{system(ARGV[1])}' printenv TOKEN=${dummy}`));
  assert.notEqual(hash(`perl -e 'system(shift)' env --token=${dummy} one`), hash(`perl -e 'system(shift)' env --token=${dummy} two`));
});

test('part B: an outage still holds every form that now carries an S4 hit, and the outage code is unchanged', () => {
  const { outageRisk } = require('../dist/seatbelt/hook.js');
  const risk = (command) => outageRisk({ tool_name: 'Bash', tool_input: { command } }, Date.now() + 5000).risk;
  for (const cmd of ['cat /proc/self/environ', 'cat < /proc/self/task/1/environ', "awk 'BEGIN{system(ARGV[1])}' env", "perl -e 'system(shift)' printenv", 'cd /proc/$$ && cat < environ']) {
    assert.equal(risk(cmd), 'high', `held in an outage: ${cmd}`);
  }
  assert.equal(risk('ls -la'), 'not_high');
});

test('part B: the keyed prefilter reads a glob in a folder of a path, after a cd, or from the filesystem root, and stays off for ordinary globs', () => {
  for (const cmd of ['cat /???c/self/task/1/e*', 'cat < /p*/self/e*', 'cat /p[r]oc/self/en[v]iron', 'cat ~/../../p*/self/e*', 'cat $HOME/../../p?oc/self/e?', 'cd / && cat p*/self/e*', 'pushd / ; cat p?oc/s*/e*']) assert.equal(mayPrintEnvironment(cmd), true, cmd);
  for (const cmd of ['ls src/*/index.ts', 'cat < src/*/x.txt', 'node --test test/**/*.test.js', 'ls dist/*/', 'rm -rf build/*', 'git add src/*.ts', 'ls /tmp/*.log', 'cat /var/log/*.log', 'cd src && ls *.ts']) assert.equal(mayPrintEnvironment(cmd), false, cmd);
  // The hook may itself run in `/` (a container): a relative glob folder is then read too. A child process keeps this test's own cwd alone.
  const probe = "const { mayPrintEnvironment } = require(process.argv[1]); process.stdout.write(JSON.stringify(['cat p*/self/e*', 'ls src/*/index.ts'].map(mayPrintEnvironment)));";
  const out = spawnSync(process.execPath, ['-e', probe, path.join(ROOT, 'dist', 'hook-pre-action.js')], { cwd: '/', encoding: 'utf8' });
  assert.equal(out.status, 0, out.stderr.slice(0, 300));
  assert.deepEqual(JSON.parse(out.stdout), [true, true]);
});

test('part B: the glob rule of the filter is linear on hostile text', () => {
  for (const text of [`/${'a/'.repeat(60000)}x`, `cat ${'/p*'.repeat(30000)}`, `${'~/'.repeat(50000)}`, `${'. '.repeat(50000)}*`]) {
    const started = process.hrtime.bigint();
    mayPrintEnvironment(text);
    assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 2000, 'the filter took over two seconds');
  }
});

test('part B: friction rows that must stay allowed in both modes, and rows whose answer must not move from the base', () => {
  // Over-blocking only where fail-closed requires it: a word, a message or a file that merely says environ, an interpreter whose code cannot start a command,
  // and a here-string that prints a path as text (the keyless pass is the base answer; the keyed hold is the base answer too: owner decision OD3).
  for (const cmd of ['cat < environment.ts', 'cat < src/environ.ts', 'cat < /proc/self/status', 'cat < /proc/self/task/1/stat', 'cat < /proc/self/cmdline', 'echo "see /proc/self/task/1/environ docs"',
    "python3 -m venv env", 'source env/bin/activate', 'conda activate env', "perl -e 'print shift' env", "node -e 'console.log(process.argv[1])' env", "sh -c 'echo \"$@\"' _ env",
    "awk 'BEGIN{print ARGV[1]}' env", "awk '/x/{print}' env", "perl -e 'print 1' -e 'print 2'", "C=ls perl -e 'system $ENV{C}'", "C=env node -e 'console.log(process.env.C)'"]) {
    assert.equal(keylessStops(live, cmd), false, `keyless ${cmd}`);
    assert.equal(live.keyed(cmd), false, `keyed ${cmd}`);
  }
  assert.equal(keylessStops(live, 'cat <<< /proc/self/task/1/environ'), false);
});
