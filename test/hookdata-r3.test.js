'use strict';
// Data words (FIX1-HOOKDATA-R3): risk words only in a data position of a plain write to an ordinary file are data; the real verb, target,
// flags, chaining and folder still decide, and every write into a run-later file keeps asking (owner A141). Hook INPUT strings only:
// nothing here is ever run. Dummy secrets are generated at runtime.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const R = require('./support/hookdata-r3-rows.cjs');
const { classifyTool } = require('../dist/hook-pre-action.js');
const policy = require('../dist/hook-tool-policy.js');
const { writesRunLaterFile } = require('../dist/self-protect.js');
const na = require('../dist/normalized-action.js');
const GOLDEN = require('./fixtures/hookdata-r3-golden.json');

const root = fs.realpathSync(R.fixture(fs.mkdtempSync(path.join(os.tmpdir(), 'hookdata-r3-'))));
const savedHome = process.env.HOME;
const savedCwd = process.cwd();
process.env.HOME = path.join(root, 'home');
process.chdir(root);
test.after(() => { process.chdir(savedCwd); process.env.HOME = savedHome; fs.rmSync(root, { recursive: true, force: true }); fs.rmSync(`${root}-out`, { recursive: true, force: true }); });

const W = R.W;
const decide = (event) => R.answer({ classifyTool }, event);
const bash = (command, extra = {}, cwd = root) => ({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command, ...extra }, cwd });
const FN1 = `echo "2026-11-09 ${W} rotated" >> logs/run.log`;
const FN2 = `cat >> notes/NOTES.md <<'EOF'\nchecklist ${W}\nEOF`;

// Every spec row (FN, SA, B1-B4, B6, FU1, FU2, A-rows): the tip answer; FN rows are a plain allow with the word classes gone.
for (const row of R.rows()) {
  const family = row.b ?? row.fu ?? (row.id.startsWith('FN') ? 'FN' : row.id.startsWith('SA') ? 'SA' : 'ABUSE');
  test(`data words ${family} ${row.id.replace(/\n/g, ' ')}: ${row.expect.tip}`, () => {
    const answer = decide(R.eventFor(row, root));
    assert.equal(answer.decision, row.expect.tip, row.id);
    if (row.expect.master === 'ask' && row.expect.tip === 'allow') assert.deepEqual([answer.type, answer.surfaces], ['process', 'workspace'], row.id);
    if (row.raised) assert.match(answer.surfaces, /persistence/, `${row.id}: a run-later hold says persistence, never production`);
  });
}

test('RAISE: a run-later write with no risk word asks, by name (package.json, workflow heredoc, tee -a Makefile)', () => {
  for (const command of ['echo "{}" > package.json', 'cat <<EOF > .github/workflows/x.yml\nname: ci\nEOF', 'echo "all:" | tee -a Makefile',
    'cp notes/NOTES.md .husky/pre-commit', 'sed -i s/a/b/ .git/config', 'git config core.editor vim', 'cd .git && echo x >> config']) {
    const answer = decide(bash(command));
    assert.equal(answer.decision, 'ask', command);
    assert.equal(answer.type, 'security', command);
    assert.match(answer.surfaces, /persistence/, command);
    assert.equal(writesRunLaterFile(bash(command), root), true, command);
  }
  assert.equal(decide(bash('truncate -s 0 Makefile')).decision, 'ask', 'truncate already asks on master: no second hold');
  assert.equal(writesRunLaterFile(bash('truncate -s 0 Makefile'), root), true);
});

test('RAISE: no new hold for reads, mentions or ordinary writes', () => {
  for (const command of ['cat package.json', 'grep -n test Makefile', 'echo "see package.json" >> notes/NOTES.md', 'git add package.json', 'git config --get user.name',
    'ls .github/workflows', 'echo x >> notes/plain.md', 'cp a.txt b.txt', 'git restore notes/NOTES.md', 'sed -n 1p Makefile', 'cp Makefile notes/x.md']) {
    assert.equal(writesRunLaterFile(bash(command), root), false, command);
  }
});

test('FN never stricter: FN6 grep pattern and FN7 echo | tee stay allowed on every host shape', () => {
  for (const host of ['claude', 'codex', 'cursor', 'gemini', 'grok', 'monitor']) {
    for (const command of [`grep -rn "${W}" docs`, `echo "${W}" | tee -a logs/run.log`]) {
      const event = R.HOSTS[host](command); event.cwd = root;
      assert.equal(decide(event).decision, 'allow', `${host} ${command}`);
    }
  }
});

test('PLATFORM_FORMS: one lowered row and one master row per host shape; PowerShell is never lowered', () => {
  for (const host of ['claude', 'codex', 'cursor', 'gemini', 'grok', 'monitor']) {
    const lowered = R.HOSTS[host](FN1); lowered.cwd = root;
    const real = R.HOSTS[host]('wrangler deploy --env production'); real.cwd = root;
    assert.equal(decide(lowered).decision, 'allow', host);
    assert.equal(decide(real).decision, 'ask', host);
  }
  assert.equal(policy.dataWordText({ tool_name: 'Bash', tool_input: { command: FN1 }, cwd: root, [policy.SHELL_DIALECT]: 'powershell' }, root), null, 'a PowerShell twin');
  const ps = R.HOSTS.powershell(FN1); ps.cwd = root;
  assert.equal(decide(ps).decision, 'ask');
  assert.equal(decide({ ...bash(FN1), tool_name: 'UnknownShell' }).decision, 'ask', 'unknown tool name = master');
});

test('R10 size bound (B5): over 8192 bytes the master answer comes back before any new scan', () => {
  const big = `echo "${W} ${'x'.repeat(8200)}" >> logs/run.log`;
  assert.equal(policy.dataWordText(bash(big), root), null);
  assert.equal(decide(bash(big)).decision, 'ask');
  const megabyte = `cat >> notes/NOTES.md <<'EOF'\n${`${W}\n`.repeat(40000)}EOF`;
  assert.equal(policy.dataWordText(bash(megabyte), root), null);
  assert.equal(policy.splitHeredocs(megabyte), null);
  const edge = `echo "${W}" >> logs/run.log`;
  const pad = `echo "${W} ${'y'.repeat(8192 - edge.length - 1)}" >> logs/run.log`;
  assert.equal(pad.length, 8192);
  assert.equal(decide(bash(pad)).decision, 'allow', 'at the bound the data words are data');
  assert.equal(decide(bash(`${pad} `)).decision, 'ask', 'one byte over: master');
});

test('R6 working folder (B2): every folder source must agree, be absolute, readable and outside dot folders', () => {
  assert.equal(decide(bash(FN1, { workdir: root })).decision, 'allow');
  assert.equal(decide(bash(FN1, { cwd: root, working_directory: root, directory: root })).decision, 'allow');
  for (const extra of [{ workdir: path.join(root, 'notes') }, { cwd: 'notes' }, { working_directory: path.join(root, 'missing') }, { directory: 7 },
    { project_dir: root }, { root }, { path: root }, { env: { A: '1' } }, { cwd: path.join(root, '.git') }]) {
    assert.equal(decide(bash(FN1, extra)).decision, 'ask', JSON.stringify(Object.keys(extra)));
  }
  assert.equal(decide(bash(FN1, {}, path.join(root, 'notes'))).decision, 'ask', 'event cwd differs from the process folder');
  fs.writeFileSync(path.join(root, '.github', 'ISSUE_TEMPLATE', 'bug.md'), 'x\n');
  for (const dir of ['.github', '.github/ISSUE_TEMPLATE']) {
    const at = path.join(root, dir);
    process.chdir(at);
    try { assert.equal(policy.dataWordText({ tool_name: 'Bash', tool_input: { command: `echo "${W}" >> bug.md`, workdir: at }, cwd: at }, at), null, `a dot folder: ${dir}`); }
    finally { process.chdir(root); }
  }
  assert.equal(policy.dataWordText(bash(FN1, { cwd: '.' }), root), null, 'a relative folder key, even one naming the same folder');
  assert.equal(decide({ tool_name: 'Bash', tool_input: { command: FN1 } }).decision, 'allow', 'absent event cwd: the process folder alone');
  assert.equal(policy.dataWordText(bash(FN1), path.join(root, 'notes')), null, 'option cwd differs');
});

test('R7 unknown folder (B3): any cd form keeps the master answer', () => {
  for (const cd of ['cd -', 'cd ~-', 'cd', 'cd +1', 'pushd .', 'popd', 'cd notes', `cd ${root}`]) {
    assert.equal(policy.dataWordText(bash(`${cd} && ${FN1}`), root), null, cd);
  }
});

test('R8 links (B4): a hard link or a symlink target keeps the master answer', () => {
  for (const target of R.LINK_TARGETS) {
    assert.equal(policy.dataWordText(bash(`echo "${W}" >> ${linkHard(target)}`), root), null, target);
    assert.equal(policy.dataWordText(bash(`echo "${W}" >> ${linkSoft(target)}`), root), null, target);
  }
  fs.writeFileSync(path.join(root, 'notes', 'plain-a.md'), 'x\n');
  fs.linkSync(path.join(root, 'notes', 'plain-a.md'), path.join(root, 'notes', 'plain-b.md'));
  assert.equal(policy.dataWordText(bash(`echo "${W}" >> notes/plain-b.md`), root), null, 'any hard link (nlink > 1)');
  fs.symlinkSync(path.join(root, 'notes', 'missing-target.md'), path.join(root, 'notes', 'dangling.md'));
  assert.equal(policy.dataWordText(bash(`echo "${W}" >> notes/dangling.md`), root), null, 'a dangling link');
  fs.symlinkSync(path.join(root, '.github'), path.join(root, 'notes', 'gh'));
  assert.equal(policy.dataWordText(bash(`echo "${W}" >> notes/gh/workflows/ci.yml`), root), null, 'a linked folder');
});
function linkHard(target) { const at = path.join(root, `t-hl-${path.basename(target)}.txt`); if (!fs.existsSync(at)) fs.linkSync(path.join(root, target), at); return path.basename(at); }
function linkSoft(target) { const at = path.join(root, 'notes', `t-sl-${path.basename(target)}.md`); if (!fs.existsSync(at)) fs.symlinkSync(path.join(root, target), at); return `notes/${path.basename(at)}`; }

test('R11 / B6 veto: a real verb in data keeps the master reading and labels (SA9, merge siblings, publish)', () => {
  for (const [command, want] of [[`cat > records/x.md <<'EOF'\n${W}\ngit push origin master\nEOF`, ['ask', 'deploy', 'production,github']],
    ['echo "git merge-file .git/config a b" >> notes/x.md', ['ask', 'review', 'github']], ['echo "npm publish now" >> notes/x.md', ['ask', 'publish', 'npm']]]) {
    assert.equal(policy.dataWordText(bash(command), root), null, command);
    const answer = decide(bash(command));
    assert.deepEqual([answer.decision, answer.type, answer.surfaces], want, command);
  }
});

test('B6 merge siblings and git writers: never a data sink, a run-later target asks', () => {
  for (const command of ['git merge-file .git/config a b', 'git checkout-index -f .git/config', 'git restore --source HEAD~1 package.json', 'git checkout -- Makefile']) {
    assert.equal(policy.dataWordText(bash(command), root), null, command);
    assert.equal(decide(bash(command)).decision, 'ask', command);
  }
  assert.equal(decide(bash('git merge-file config a b', {}, path.join(root, '.git'))).decision, 'ask');
});

test('R1 data sinks: only a literal echo, printf or cat; interpreters, shells and other programs are never data', () => {
  for (const program of ['tee', 'sponge', 'git', 'python3', 'node', 'bash', 'sh', 'awk', 'xargs', 'env', 'sudo', 'perl', 'ssh', 'dd']) {
    assert.equal(policy.dataWordText(bash(`${program} >> notes/NOTES.md <<'EOF'\n${W}\nEOF`), root), null, program);
  }
  assert.equal(policy.dataWordText(bash(`echo "${W}" >> notes/NOTES.md`), root), 'bash ; echo notes/NOTES.md');
  assert.equal(policy.dataWordText(bash(FN2), root), 'bash ; cat notes/NOTES.md');
});

test('R2 fully read: substitutions, variables, unterminated bodies and unmodelled heredoc forms keep the master answer', () => {
  for (const command of [`echo "${W} $(id)" >> notes/NOTES.md`, `echo "${W} \${HOME}" >> notes/NOTES.md`, `cat > notes/x.md <<EOF\n${W} \`id\`\nEOF`,
    `cat > notes/x.md <<EOF\n${W} $HOME\nEOF`, `cat > notes/x.md <<EOF\n${W} \\$x\nEOF`, `cat > notes/x.md <<'EOF'\n${W}\n`, `cat <<< "${W}" > notes/x.md`,
    `cat <<-EOF > notes/x.md\n${W}\nEOF`, `cat > notes/x.md << 'E F'\n${W}\nE F`, `cat > notes/x.md <<$'EOF'\n${W}\nEOF`]) {
    assert.equal(policy.dataWordText(bash(command), root), null, command);
  }
  assert.equal(policy.dataWordText(bash(`cat > notes/x.md <<'EOF'\n${W} $(id) \`id\`\nEOF`), root), 'bash ; cat notes/x.md', 'a quoted tag keeps $( as text');
});

test('splitHeredocs follows quotes and comments: an operator inside them is not one', () => {
  assert.equal(policy.splitHeredocs(`echo hi >> notes/a.md # <<EOF\nwrangler deploy\nEOF`).bodies.length, 0);
  assert.equal(policy.splitHeredocs(`echo "x <<EOF y" >> notes/a.md\nwrangler deploy\nEOF`).bodies.length, 0);
  assert.equal(policy.splitHeredocs(`echo 'x <<EOF' >> notes/a.md`).bodies.length, 0);
  const split = policy.splitHeredocs(`cat <<'A' >> notes/a.md\none\nA\nls`);
  assert.deepEqual(split.bodies, [{ body: 'one', quoted: true }]);
  assert.equal(split.head, `cat   >> notes/a.md\nls`);
  assert.equal(policy.splitHeredocs('cat <<EOF\nx\nEOF\r'), null, 'a CRLF end tag is not an end tag');
  assert.equal(policy.splitHeredocs('cat > notes/x.md <<\nx\n\n'), null, 'an empty tag');
  assert.equal(policy.splitHeredocs('cat <<< x > notes/x.md'), null, 'a here-string');
  assert.equal(policy.splitHeredocs('cat <<-EOF > notes/x.md\nx\nEOF'), null, 'a tab-stripping heredoc');
});

test('R5 targets and section 4: only an ordinary data file in the folder is a data target', () => {
  const ok = ['notes/NOTES.md', 'logs/run.log', './notes/x.md', `${root}/records/x.md`, 'docs/x.txt', 'out.json', 'notes/brief', 'notes/Makefile.md', 'notes/deploy-notes.md'];
  const no = ['package.json', 'package-lock.json', 'notes/package.json', 'package-x.json', 'notes/package-notes.md', 'Makefile', 'x.mk', 'notes/run.sh', 'gen.py', 'x.ts', 'notes/exec.md', 'notes/bang.md', '.hidden.md',
    '.github/ISSUE_TEMPLATE/bug.md', 'README', 'x.bin', '../x.md', '/dev/null', '/proc/self/fd/1', '/etc/hosts', '~/notes.md', 'notes/*.md', 'notes/{a,b}.md',
    'notes/$F.md', 'missing/x.md', 'tsconfig.json', 'docker-compose.yml', 'vite.config.ts', '.env.local'];
  for (const target of ok) assert.notEqual(policy.dataWordText(bash(`echo "plain" >> ${target}`), root), null, target);
  fs.mkdirSync(`${root}-out/notes`, { recursive: true });
  no.push(`${root}-out/notes/x.md`);
  for (const target of no) assert.equal(policy.dataWordText(bash(`echo "plain" >> ${target}`), root), null, target);
});

test('FU1 section 4 list: every run-later name, folder and ending is named by isRunLaterPath; ordinary names are not', () => {
  for (const p of ['.git/config', '.git/hooks/pre-push', '.git/config.worktree', '.git/info/attributes', '.git/modules/sub/config', '.gitmodules', '.gitattributes',
    '/h/.gitconfig', '/h/.config/git/config', 'x/.gitconfig', '.github/workflows/ci.yml', '.github/actions/a/action.yml', '.github/dependabot.yml', '.gitlab-ci.yml',
    '.circleci/config.yml', 'azure-pipelines.yml', 'Jenkinsfile', 'bitbucket-pipelines.yml', '.travis.yml', 'buildkite/pipeline.yml', 'package.json', 'package.yaml',
    'package-lock.json', 'Makefile', 'GNUmakefile', 'a.mk', 'justfile', 'Taskfile.yml', 'Taskfile.yaml', 'Rakefile', 'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
    'tsconfig.json', '.npmrc', '.yarnrc.yml', '.pnpmrc', 'pyproject.toml', 'setup.py', 'setup.cfg', 'tox.ini', 'noxfile.py', 'build.gradle', 'build.gradle.kts', 'pom.xml',
    'composer.json', 'Cargo.toml', 'build.rs', 'conftest.py', 'jest.config.js', 'vitest.config.ts', 'webpack.config.js', 'vite.config.ts', 'rollup.config.mjs', 'x.config.cjs',
    '.husky/pre-commit', '.pre-commit-config.yaml', '.lefthook.yml', '.vscode/tasks.json', '.vscode/settings.json', '.envrc', '.env', '.env.local', '.tool-versions',
    '.claude/x.md', '.cursor/x', '.codex/x', '/h/.marrow/x', '/h/.bashrc', '.bash_profile', '.profile', '.zshrc', '.zshenv', '.zprofile', '.zlogin', '/etc/profile',
    '/etc/bash.bashrc', '/etc/environment', '/etc/cron.d/x', 'crontab', '/h/.config/systemd/user/x.service', 'x.timer', '/h/Library/LaunchAgents/x.plist', '/h/.ssh/config']) {
    assert.equal(policy.isRunLaterPath(p), true, p);
  }
  assert.equal(policy.isRunLaterPath(path.join(root, 'bare.git', 'config')), true, 'a bare repo config');
  assert.equal(policy.isRunLaterPath(path.join(process.env.HOME, '.myrc')), true, 'an rc file in the home root');
  for (const p of ['notes/NOTES.md', 'notes/Makefile.md', 'docs/package-notes.md', 'config', 'notes/config', 'x.json', '.git-notes/x.md', '.github/ISSUE_TEMPLATE/x.md']) {
    assert.equal(policy.isRunLaterPath(p), false, p);
  }
  assert.equal(policy.isRunLaterPath('MAKEFILE'), false, 'byte-exact, no case folding (and no lowering either: no data ending)');
});

test('UNICODE_FOLD: a look-alike sink word, tag or name is not folded', () => {
  assert.equal(policy.dataWordText(bash(`ech\u043e "${W}" >> notes/NOTES.md`), root), null);
  assert.equal(policy.dataWordText(bash(`c\u0430t >> notes/NOTES.md <<'EOF'\n${W}\nEOF`), root), null);
  assert.equal(policy.splitHeredocs(`cat <<'E\u041eF'\nx\nE\u041eF`), null);
});

test('R12 no switch: no env var or client field turns the lowering on for a master shape', () => {
  const saved = { ...process.env };
  try {
    process.env.MARROW_DATA_WORDS = 'on'; process.env.MARROW_HOOK_COMMAND_TEXT = 'send';
    for (const extra of [{ data_words: true }, { lower: 'on' }, { sink: 'bash' }]) {
      assert.equal(decide(bash(`echo "${W}" > notes/run.sh`, extra)).decision, 'ask', JSON.stringify(extra));
      assert.equal(decide(bash(FN1, extra)).decision, 'ask', `an unknown field keeps the master answer: ${JSON.stringify(extra)}`);
    }
    assert.equal(decide(bash(`echo "${W}" > notes/run.sh`)).decision, 'ask');
  } finally { for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key]; Object.assign(process.env, saved); }
});

test('A-forge: forged event fields cannot lower (tool name, command key, transcript path)', () => {
  assert.equal(policy.dataWordText({ ...bash(FN1), tool_name: 'Bash ' }, root), 'bash ; echo logs/run.log', 'a padded name is read as Bash on master too');
  for (const event of [{ ...bash(FN1), tool_name: 'Edit' }, { tool_name: 'Bash', tool_input: { cmd: FN1 }, cwd: root },
    { tool_name: 'Bash', tool_input: { command: FN1, script: 'wrangler deploy' }, cwd: root }, { ...bash(FN1), transcript_path: '/x' } ]) {
    const text = policy.dataWordText(event, root);
    if (event.transcript_path) assert.equal(text, 'bash ; echo logs/run.log', 'a transcript path is not read');
    else assert.equal(text, null, JSON.stringify(Object.keys(event.tool_input)));
  }
});

test('PostToolUse: a lowered call gets the label of any ordinary data write and is never read-only', () => {
  const post = classifyTool(bash(FN1), { postTool: true, cwd: root });
  const plain = classifyTool(bash('echo "plain words" >> logs/run.log'), { postTool: true, cwd: root });
  assert.deepEqual([post.type, post.surfaces, post.readOnly, post.target], [plain.type, plain.surfaces, plain.readOnly, plain.target]);
  assert.equal(post.readOnly, false);
});

// Keys (FU3 and section 10): the normalized action of every command with no redacted span is byte-equal to master (golden).
const salt = Buffer.alloc(32, 5);
const keyOf = (command, s = salt) => JSON.stringify(na.normalizedHookAction({ tool_name: 'Bash', tool_input: { command } }, { salt: s, claudeCodeBash: true }).tool_input);
const sha = (text) => crypto.createHash('sha256').update(text).digest('hex');

test('FU3 golden: keys, deploy text and normalized text of every command with no redacted span equal master (C8 included)', () => {
  let n = 0;
  for (const [command, want] of Object.entries(GOLDEN)) {
    assert.equal(sha(keyOf(command)), want.key, command);
    assert.equal(na.deployCommandText(command), want.deploy, command);
    assert.equal(na.normalizeShellCommand(command).text, want.text, command);
    n += 1;
  }
  assert.ok(n > 200 && GOLDEN['git push origin feat/x'] && GOLDEN['gh pr create --title x --body y']);
});

test('FU3 / C2: commands that differ only after a redacted span get different keys; the secret is in no key', () => {
  const dummy = `zzdummy${crypto.randomBytes(8).toString('hex')}`;
  assert.equal(na.looksLikeKey(dummy), false);
  const pairs = [[`grep -rn 'password=${dummy} alpha deploy' docs`, `grep -rn 'password=${dummy} beta deploy' docs`],
    [`grep -rn "password=${dummy} alpha" docs`, `grep -rn "password=${dummy} beta" docs`],
    [`curl 'https://example.invalid/x?token=${dummy}&a=1'`, `curl 'https://example.invalid/x?token=${dummy}&a=2'`],
    [`curl -H 'Authorization: Bearer ${dummy}' https://example.invalid/a`, `curl -H 'Authorization: Bearer ${dummy}' https://example.invalid/b`],
    [`API_TOKEN=${dummy} npm run a`, `API_TOKEN=${dummy} npm run b`], [`curl -d 'password=${dummy}&x=1' https://example.invalid`, `curl -d 'password=${dummy}&x=2' https://example.invalid`],
    [`echo '{"password":"${dummy}","x":1}' > notes/a.json`, `echo '{"password":"${dummy}","x":2}' > notes/a.json`], [`tool --password=${dummy} --target a`, `tool --password=${dummy} --target b`]];
  for (const [a, b] of pairs) {
    assert.notEqual(keyOf(a), keyOf(b), a.split(dummy).join('<dummy>'));
    assert.equal(keyOf(a).includes(dummy) || keyOf(b).includes(dummy), false);
    assert.equal(na.normalizeShellCommand(a).text.includes(dummy), false);
  }
});

test('C1 C3 C4 C6 C7 A-tenant: collision rows', () => {
  const d1 = `zzdummy${crypto.randomBytes(8).toString('hex')}`;
  const d2 = `zzdummy${crypto.randomBytes(8).toString('hex')}`;
  assert.notEqual(keyOf(`${FN2}\nls a`), keyOf(`${FN2}\nls b`), 'C1: after the end tag');
  const c3a = keyOf(`curl -H 'Authorization: Bearer ${d1}' https://example.invalid/a`);
  const c3b = keyOf(`curl -H 'Authorization: Bearer ${d2}' https://example.invalid/a`);
  assert.equal(c3a.includes(d1) || c3b.includes(d2), false, 'C3: the value is in no key');
  assert.notEqual(keyOf(`echo "deploy now" >> notes/NOTES.md`), keyOf(`echo "backup now" >> notes/NOTES.md`), 'C4: data words differ, keys differ');
  assert.notEqual(keyOf(`echo "${W}" | tee -a logs/run.log`), keyOf(`echo "${W}" | tee -a .github/workflows/ci.yml`), 'C6: keys');
  assert.notEqual(decide(bash(`echo "x" | tee -a logs/run.log`)).decision, decide(bash(`echo "x" | tee -a .github/workflows/ci.yml`)).decision, 'C6: decisions');
  assert.notEqual(keyOf(FN1, Buffer.alloc(32, 1)), keyOf(FN1, Buffer.alloc(32, 2)), 'C7 / A-tenant: device keys differ');
  assert.notEqual(decide(bash(FN1)).decision, decide(bash(FN1, { workdir: path.join(root, '.git') })).decision, 'C5: cwd source decides');
});

test('A-prod (R11): a real verb keeps its production label wherever the data words are', () => {
  for (const command of ['wrangler deploy --env production', `wrangler deploy --env 'production' && echo "${W}" >> logs/run.log`, 'git push origin production',
    `echo "${W}" >> logs/run.log; npm run deploy -- --env production`, 'kubectl apply -f prod.yml']) {
    const answer = decide(bash(command));
    assert.equal(answer.decision, 'ask', command);
    assert.match(`${answer.type}/${answer.surfaces}`, /production|deploy|github/, command);
  }
});
