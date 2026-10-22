'use strict';

// Every form an agent can type that prints many or all environment variables must stop, keyless (seatbelt S4)
// and keyed (a protected action). The rows are STRINGS fed to the checkers: nothing here runs a command or reads
// an environment. Friction rows must stay as they were, script files are out of reach by design, and each new
// rule has a mutant that a row kills.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
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
  const { mayPrintEnvironment } = require('../dist/hook-tool-policy.js');
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
  { id: 'keyed asks the mapper', file: 'hook-tool-policy.js', edit: text('shellPrintsEnvironment(command))', 'false)'), killers: ['bash -c env', 'compgen -e'], keyedOnly: true },
  { id: 'keyed read-only bypass', file: 'hook-tool-policy.js', edit: text('if (shellPrintsEnvironment(shellCommandText(event)))', 'if (false)'), killers: ['printenv "$NAME"'], keyedOnly: true },
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
