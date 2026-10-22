'use strict';

// Every form an agent can type that prints many or all environment variables must stop, keyless (seatbelt S4)
// and keyed (a protected action). The rows are STRINGS fed to the checkers: nothing here runs a command or reads
// an environment. Friction rows must stay as they were, script files are out of reach by design, and each new
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

test('the tool policy never uses the mapper: only the pre-action hook does (U5), and the post-tool path loads none', () => {
  const policy = fs.readFileSync(path.join(ROOT, 'src', 'hook-tool-policy.ts'), 'utf8');
  assert.equal(/seatbelt\//.test(policy), false);
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-envdump-count-')), 'rows.json');
  try {
    fs.writeFileSync(file, JSON.stringify([...stopRows.map((r) => r.cmd), ...ORDINARY_NO_LOAD]));
    const out = spawnSync(process.execPath, [path.join(__dirname, 'support', 'env-filter-count.cjs'), 'post', file], { encoding: 'utf8' });
    assert.equal(out.status, 0, out.stderr.slice(0, 300));
    const counted = JSON.parse(out.stdout);
    assert.deepEqual({ loads: counted.loads, calls: counted.calls }, { loads: 0, calls: 0 });
  } finally {
    fs.rmSync(path.dirname(file), { recursive: true, force: true });
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
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-envdump-count-'));
  const count = (rows) => {
    const file = path.join(dir, 'rows.json');
    fs.writeFileSync(file, JSON.stringify(rows));
    const out = spawnSync(process.execPath, [path.join(__dirname, 'support', 'env-filter-count.cjs'), 'classify', file], { encoding: 'utf8' });
    assert.equal(out.status, 0, out.stderr.slice(0, 300));
    return JSON.parse(out.stdout);
  };
  try {
    const ordinary = count(ORDINARY_NO_LOAD);
    assert.deepEqual({ loads: ordinary.loads, calls: ordinary.calls }, { loads: 0, calls: 0 });
    for (const cmd of ORDINARY_NO_LOAD) assert.equal(mayPrintEnvironment(cmd), false, cmd);
    const stops = count(stopRows.map((r) => r.cmd));
    assert.equal(stops.loads, 1);
    assert.deepEqual(stopRows.filter((r, i) => stops.perCommand[i] < 1).map((r) => r.cmd), []);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
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
  { id: 'proc glob', file: 'seatbelt/env-dump.js', edit: off('procGlobMatchesEnviron'), killers: ['cat /proc/self/env*', 'cat /proc/self/envi?on'] },
  { id: 'proc task path', file: 'secret-paths.js', edit: text('task\\/[^/]+\\/)?environ$/', 'task\\/[^/]+\\/)?environZ$/'), killers: ['cat /proc/self/task/1/environ'] },
  { id: 'proc recursive folder', file: 'seatbelt/mapper.js', edit: text('PROC_PROCESS_DIRECTORY.test(p)', 'false'), killers: ['grep -ra . /proc/self/', 'cp -r /proc/self /tmp/x'] },
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
  { id: 'filter: bare set', file: 'hook-pre-action.js', edit: text('|\\bset\\b(?=', '|\\bsetX\\b(?='), killers: ['set', 'true; set | sort'], keyedOnly: true },
  { id: 'filter: ps with e', file: 'hook-pre-action.js', edit: text('/[eE]/.test(words.slice(ps.index + 2))', 'false'), killers: ['ps e', 'ps -E'], keyedOnly: true },
  { id: 'filter: /proc folder', file: 'hook-pre-action.js', edit: text('|\\bproc\\b|', '|\\bprocX\\b|'), killers: ['grep -ra . /proc/self/'], keyedOnly: true },
  { id: 'filter: computed process name', file: 'hook-pre-action.js', edit: text('|\\bprocess\\s*(?:\\?\\.\\s*)?\\[', ''), killers: ["node -e \"const e = process['en' + 'v']; console.log(e)\""], keyedOnly: true },
  { id: 'keyed asks the mapper', file: 'hook-pre-action.js', edit: text('isSecretMaterialAccessAsNamed)(event, shellPrintsEnvironment)', 'isSecretMaterialAccessAsNamed)(event)'), killers: ['bash -c env', 'compgen -e'], keyedOnly: true },
  { id: 'keyed read-only bypass', file: 'hook-pre-action.js', edit: text('isReadOnlyToolEventAsNamed)(event, shellPrintsEnvironment)', 'isReadOnlyToolEventAsNamed)(event)'), killers: ['printenv "$NAME"'], keyedOnly: true },
];

function mutantBuild(file, edit) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-envdump-mutant-'));
  fs.cpSync(path.join(ROOT, 'dist'), path.join(dir, 'dist'), { recursive: true });
  fs.symlinkSync(path.join(ROOT, 'vendor'), path.join(dir, 'vendor'));
  fs.symlinkSync(path.join(ROOT, 'node_modules'), path.join(dir, 'node_modules'));
  fs.copyFileSync(path.join(ROOT, 'package.json'), path.join(dir, 'package.json'));
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
