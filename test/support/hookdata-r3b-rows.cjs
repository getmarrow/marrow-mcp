'use strict';
// Rows of the round 2 patch (FIX1-HOOKDATA-R3-PATCH): `source` / `.` run a file and the `git config` verb are not run-later writes, so
// they keep the master answer; a data sink into .git/config and a run-later file written in the same chain keep asking (owner A141).
// Hook INPUT strings only: nothing here is ever run. kind: 'master' = the answer equals master's; 'sink' = a run-later write held by name.
const fs = require('node:fs');
const path = require('node:path');
const R = require('./hookdata-r3-rows.cjs');

const W = R.W;

function fixture(root) {
  R.fixture(root);
  for (const dir of ['env/bin', 'scripts']) fs.mkdirSync(path.join(root, dir), { recursive: true });
  for (const file of ['env/bin/activate', 'x.sh', 'x.ps1', 'scripts/production.sh', '.env']) fs.writeFileSync(path.join(root, file), 'x\n');
  return root;
}

function rows() {
  const r = [];
  const add = (id, command, kind, extra = {}) => r.push({ id, command, kind, ...extra });
  // P1: run forms (POSIX `source` / `.`, PowerShell dot-source) keep master's answer.
  add('P1-source-activate', 'source env/bin/activate', 'master');
  add('P1-dot-activate', '. env/bin/activate', 'master');
  add('P1-source-sh', 'source ./x.sh', 'master');
  add('P1-dot-sh', '. ./x.sh', 'master');
  add('P1-source-stdin', `source /dev/stdin <<EOF\n${W}\nEOF`, 'master');
  add('P1-dot-stdin', `. /dev/stdin <<'EOF'\necho hi\nEOF`, 'master');
  add('P1-source-args', 'source ./x.sh one two', 'master');
  add('P1-source-dashdash', 'source -- ./x.sh', 'master');
  add('P1-source-unknown-flag', 'source -z ./x.sh', 'master');
  add('P1-source-assign', 'FOO=1 source ./x.sh', 'master');
  add('P1-builtin-source', 'builtin source ./x.sh', 'master');
  add('P1-command-dot', 'command . ./x.sh', 'master');
  add('P1-source-rc', 'source ~/.bashrc', 'master');
  add('P1-source-env', 'source .env', 'master');
  add('P1-source-var', 'source $F', 'master');
  add('P1-dot-var-home', '. "$HOME/x.sh"', 'master');
  add('P1-source-var-assign', 'S=./x.sh; source $S', 'master');
  add('P1-source-word-path', 'source scripts/production.sh', 'master');
  add('P1-source-abs', (root) => `source ${path.join(root, 'x.sh')}`, 'master');
  add('P1-ps-dot', '. ./x.ps1', 'master', { tool: 'PowerShell' });
  add('P1-ps-dot-temp', '. $env:TEMP\\x.ps1', 'master', { tool: 'PowerShell' });
  // P2: the `git config` verb keeps master's answer.
  add('P2-alias-log', 'git config alias.e log', 'master');
  add('P2-core-editor', 'git config core.editor vim', 'master');
  add('P2-global-name', 'git config --global user.name x', 'master');
  add('P2-alias-shell', `git config alias.x '!sh -c "wrangler deploy"'`, 'master');
  add('P2-alias-shell-id', `git config alias.x '!sh -c id'`, 'master');
  add('P2-file-gitconfig-shell', `git config --file .git/config alias.x '!sh -c id'`, 'master');
  add('P2-file-gitconfig-log', 'git config --file .git/config alias.e log', 'master');
  add('P2-file-eq', 'git config --file=.git/config alias.e log', 'master');
  add('P2-unset', 'git config --unset alias.e', 'master');
  add('P2-get', 'git config --get user.name', 'master');
  add('P2-list', 'git config -l', 'master');
  add('P2-repeated-scope', 'git config --global --local alias.e log', 'master');
  add('P2-unknown-flag', 'git config --frobnicate alias.e log', 'master');
  add('P2-git-C', 'git -C . config alias.e log', 'master');
  add('P2-word-name', `git config user.name "${W}"`, 'master');
  add('P2-word-alias', 'git config alias.deploy "push origin production"', 'master');
  add('P2-hookspath', 'git config core.hooksPath .husky', 'master');
  // P2 sink: a data sink into .git/config (5b write forms) stays held by name, with or without a word.
  add('P2-sink-append', 'echo x >> .git/config', 'sink');
  add('P2-sink-tee', 'echo "[alias]" | tee -a .git/config', 'sink');
  add('P2-sink-sed', 'sed -i s/a/b/ .git/config', 'sink');
  add('P2-sink-heredoc', "cat >> .git/config <<'EOF'\n[alias]\n\tx = !sh -c id\nEOF", 'sink');
  add('P2-sink-cp', 'cp notes/NOTES.md .git/config', 'sink');
  add('P2-sink-after-verb', 'git config alias.e log && echo x >> .git/config', 'sink');
  add('P2-sink-cd', 'cd .git && echo x >> config', 'sink');
  // P7: a run-later file written in the same chain and then sourced still asks; chains, words and production keep master's answer.
  add('P7-write-envrc-source', "cat > .envrc <<'EOF'\nexport A=1\nEOF\nsource .envrc", 'sink');
  add('P7-write-husky-dot', 'echo "npm test" > .husky/pre-commit && . .husky/pre-commit', 'sink');
  add('P7-tee-bashrc-source', 'echo "alias x=y" | tee -a ~/.bashrc; source ~/.bashrc', 'sink');
  add('P7-cp-githook-dot', 'cp notes/NOTES.md .git/hooks/pre-push || . .git/hooks/pre-push', 'sink');
  add('P7-mv-make-dot', 'mv notes/NOTES.md Makefile; . ./Makefile', 'sink');
  add('P7-sed-envrc-source', 'sed -i s/a/b/ .envrc && source .envrc', 'sink');
  add('P7-write-words-envrc', `echo "${W}" > .envrc && source .envrc`, 'sink');
  // A code file (.sh, .ps1) written and then run keeps master's answer (section 4: a code write is master); with words it asks as on master.
  add('P7-write-sh-source', "cat > run.sh <<'EOF'\necho hi\nEOF\nsource run.sh", 'master');
  add('P7-write-sh-dot', 'echo "echo hi" > run.sh && . ./run.sh', 'master');
  add('P7-write-words-source', `echo "${W}" > run.sh && source run.sh`, 'master');
  add('P7-write-ps1-dot', `echo "${W}" > x.ps1; . ./x.ps1`, 'master');
  add('P7-write-ordinary-source', `echo "${W}" > notes/x.md && source notes/x.md`, 'master');
  add('P7-write-ordinary-dot', `echo "${W}" >> logs/run.log; . logs/run.log`, 'master');
  add('P7-write-ordinary-nowords', 'echo "echo hi" > notes/x.md && source notes/x.md', 'master');
  add('P7-ps-write-dot-temp', `Set-Content $env:TEMP\\x.ps1 "${W}"; . $env:TEMP\\x.ps1`, 'master', { tool: 'PowerShell' });
  add('P7-ps-redirect-dot-temp', `"${W}" > $env:TEMP\\x.ps1; . $env:TEMP\\x.ps1`, 'master', { tool: 'PowerShell' });
  add('P7-chain-and', 'source ./x.sh && wrangler deploy --env production', 'master');
  add('P7-chain-semi', 'true; . ./x.sh', 'master');
  add('P7-chain-or', 'source ./x.sh || npm publish', 'master');
  add('P7-chain-pipe', 'echo hi | source /dev/stdin', 'master');
  add('P7-chain-subshell', '(source env/bin/activate && npm test)', 'master');
  add('P7-chain-bash-c', `bash -c 'source ./x.sh'`, 'master');
  add('P7-chain-nl', 'source env/bin/activate\npytest -q', 'master');
  add('P7-chain-git-config-push', 'git config alias.e log && git push origin master', 'master');
  add('P7-prod-env', 'source env/bin/activate && wrangler deploy --env production', 'master');
  add('P7-prod-arg', `. ./x.sh 'production'`, 'master');
  add('P7-prod-git-config', 'git config deploy.env production', 'master');
  add('P7-msg-run-later', 'git config alias.e log # this will run later', 'master');
  return r;
}

// Host shapes each row is judged on: a PowerShell row only as PowerShell, every other row on every POSIX host shape.
const HOSTS = ['claude', 'codex', 'cursor', 'gemini', 'grok', 'monitor'];

/**
 * The answers of one built dist ({ classifyTool, na }) for every row and host: decision, classification and the normalized key
 * (fixed test salt, sha256 cut to 16 hex). The fixture root is written as <root> so a recorded answer compares across runs.
 */
function record(dist, root) {
  const salt = Buffer.alloc(32, 9);
  const out = {};
  for (const row of rows()) {
    for (const host of row.tool ? ['powershell'] : HOSTS) {
      const event = R.eventFor(row.tool ? { ...row, tool: undefined } : row, root, host);
      const answer = R.answer(dist, event);
      const tool = { tool_name: event.tool_name, tool_input: { ...event.tool_input, command: event.tool_input.command.split(root).join('<root>') } };
      const key = JSON.stringify(dist.na.normalizedHookAction(tool, { salt, claudeCodeBash: true }).tool_input);
      answer.key = require('node:crypto').createHash('sha256').update(key).digest('hex').slice(0, 16);
      out[`${row.id}@${host}`] = JSON.parse(JSON.stringify(answer).split(root).join('<root>'));
    }
  }
  return out;
}

// Audit fix round: run-later file names are judged folded; look-alike spellings, sibling run-later files and words in the tool
// description keep the master answer. Each row: master = master's decision (recorded from a master build), head = the audited
// head's decision (012ed3c4). Hook INPUT strings only: nothing here is ever run.
const CASE_NAMES = ['Package.json', 'PACKAGE.json', 'Tsconfig.json', 'Composer.json', 'Docker-compose.yml', 'taskfile.yml', 'Pyproject.toml', 'cargo.toml',
  'Azure-pipelines.yml'];
const LOOK_ALIKES = ['p\u0430ckage.json', '\uff50ackage.json'];
const SIBLINGS = ['wrangler.toml', 'deno.json', 'vercel.json', 'netlify.toml', 'firebase.json', 'pnpm-workspace.yaml', 'tsconfig.build.json'];
const WORDS = { W, R: 'release to prod', S: 'rotate the secret token' };
const SINKS = {
  'echo-dq': (w, t) => `echo "${w}" >> ${t}`,
  'echo-sq': (w, t) => `echo '${w}' > ${t}`,
  printf: (w, t) => `printf '%s\\n' "${w}" >> ${t}`,
  'cat-q': (w, t) => `cat >> ${t} <<'EOF'\n${w}\nEOF`,
  'cat-u': (w, t) => `cat > ${t} <<EOF\n${w}\nEOF`,
};
const PLAIN_HEREDOC = `cat >> notes/NOTES.md <<'EOF'\nplain words only\nEOF`;

function cutRows() {
  const r = [];
  const add = (id, cls, command, master, head, extra = {}) => r.push({ id, cls, command, master, head, ...extra });
  for (const name of [...CASE_NAMES, ...LOOK_ALIKES]) {
    const cls = LOOK_ALIKES.includes(name) ? 'F-B' : 'F-A';
    add(`RLspell|"${name}"|w`, cls, `echo "${W}" >> "${name}"`, 'ask', 'allow');
    add(`RLspell-bare|"${name}"|w`, cls, `echo "${W}" >> ${name}`, 'ask', 'allow');
  }
  for (const [target, cls] of [['Package.json', 'F-A'], ['wrangler.toml', 'FU-1']]) {
    for (const [sink, make] of Object.entries(SINKS)) {
      for (const [set, words] of Object.entries(WORDS)) {
        for (const folder of ['event-root', 'workdir-root']) add(`gen:${sink}|${set}|none|${target}|${folder}`, cls, make(words, target), 'ask',
          cls === 'FU-1' && sink.startsWith('cat') && set !== 'R' ? 'ask' : 'allow', { folder });
      }
    }
  }
  add('N56', 'F-A', `echo "${W}" >> Package.json`, 'ask', 'allow');
  add('N57', 'FU-1', `echo "${W}" >> wrangler.toml`, 'ask', 'allow');
  for (const [id, description] of [['N58', 'deploy production'], ['desc-deploy-verb', 'wrangler deploy --env production'],
    ['desc-force-push', 'git push --force origin main'], ['desc-production', 'update the production database']]) {
    add(id, 'F-C', PLAIN_HEREDOC, 'ask', 'allow', { input: { description } });
  }
  add('desc-timeout-words', 'F-C', PLAIN_HEREDOC, 'ask', 'allow', { input: { description: 'x', timeout: 'deploy production' } });
  add('desc-echo-parsed', 'F-C', 'echo "plain words only" >> notes/NOTES.md', 'allow', 'allow', { input: { description: 'deploy production' } });
  for (const name of [...SIBLINGS, 'Wrangler.TOML', 'DENO.json', 'fly.toml', 'serverless.yml', 'render.yaml', 'app.yaml']) {
    // The head reads the wrangler program word in a wrangler.toml target name, so those rows already ask there.
    const wrangler = name.toLowerCase() === 'wrangler.toml';
    add(`sib-echo|${name}`, 'FU-1', `echo "${W}" >> ${name}`, 'ask', name === 'Wrangler.TOML' ? 'ask' : 'allow');
    add(`sib-printf|${name}`, 'FU-1', `printf '%s\\n' "${W}" >> ${name}`, 'ask', name === 'Wrangler.TOML' ? 'ask' : 'allow');
    add(`sib-heredoc|${name}`, 'FU-1', `cat >> ${name} <<'EOF'\n${W}\nEOF`, 'ask', wrangler ? 'ask' : 'allow');
    add(`sib-tee|${name}`, 'FU-1', `echo "${W}" | tee -a ${name}`, 'allow', 'allow');
  }
  for (const name of ['Package.JSON', 'PACKAGE.json']) {
    const write = `echo "${W}" >> ${name}`;
    for (const [chain, command] of [['and', `${write} && ls`], ['semi', `ls; ${write}`], ['or', `${write} || true`], ['pipe', `${write} | cat`],
      ['subshell', `(${write})`], ['bash-c', `bash -c '${write.replace(/"/g, '')}'`]]) add(`mixed-${chain}|${name}`, 'mixed', command, 'ask', 'ask');
  }
  add('mixed-repeat-last', 'mixed', `echo "${W}" > notes/a.md > Package.json`, 'ask', 'ask');
  add('mixed-repeat-first', 'mixed', `echo "${W}" > Package.json > notes/a.md`, 'ask', 'ask');
  add('mixed-var', 'mixed', `F=Package.json; echo "${W}" >> $F`, 'ask', 'ask');
  add('mixed-var-bare', 'mixed', `echo "${W}" >> $F`, 'ask', 'ask');
  add('mixed-trailing-dot', 'mixed', `echo "${W}" >> "Package.json."`, 'ask', 'ask');
  add('mixed-trailing-space', 'mixed', `echo "${W}" >> "Package.json "`, 'ask', 'ask');
  add('mixed-noext-trailing-space', 'mixed', `echo "${W}" >> "notes/Makefile "`, 'ask', 'allow');
  add('mixed-noext-trailing-dot', 'mixed', `echo "${W}" >> "notes/Jenkinsfile."`, 'ask', 'ask');
  add('mixed-noext-case', 'mixed', `echo "${W}" >> notes/JenkinsFile`, 'ask', 'allow');
  add('mixed-nfd', 'mixed', `echo "${W}" >> "pa\u0301ckage.json"`, 'ask', 'allow');
  add('mixed-nfd-notes', 'mixed', `echo "${W}" >> "notes/re\u0301sume\u0301.md"`, 'ask', 'allow');
  add('mixed-zwj', 'mixed', `echo "${W}" >> "pack\u200dage.json"`, 'ask', 'ask');
  add('mixed-zwj-noext', 'mixed', `echo "${W}" >> "notes/Make\u200dfile"`, 'ask', 'ask');
  add('mixed-fullwidth-notes', 'mixed', `echo "${W}" >> "\uff4eotes.md"`, 'ask', 'allow');
  add('mixed-prefix-case', 'mixed', `echo "${W}" >> Jest.config.json`, 'ask', 'allow');
  add('mixed-package-prefix-case', 'mixed', `echo "${W}" >> Package-notes.json`, 'ask', 'allow');
  // Run-later folders with no dot part: the run-later list inside the ordinary test still decides (master answer).
  for (const dir of ['buildkite', 'systemd', 'cron.d', 'LaunchAgents']) {
    add(`folder-${dir}`, 'mixed', `echo "${W}" >> ${dir}/notes.json`, 'ask', 'ask', { dirs: [dir] });
    // Through a linked folder only the ordinary test sees the run-later folder (the hold by name reads the path as written).
    add(`folder-link-${dir}`, 'mixed', `echo "${W}" >> lnk-${dir}/notes.json`, 'ask', 'ask', { dirs: [dir], links: [[`lnk-${dir}`, dir]] });
  }
  add('mixed-colon-stream', 'mixed', `echo "${W}" >> "notes/Makefile:x"`, 'ask', 'allow');
  return r;
}

/** The event of a cut row in a fixture root: the folder comes from the event cwd or from tool_input.workdir. */
function cutEvent(row, root, host = 'claude') {
  for (const dir of row.dirs ?? []) fs.mkdirSync(path.join(root, dir), { recursive: true });
  for (const [from, to] of row.links ?? []) if (!fs.existsSync(path.join(root, from))) fs.symlinkSync(path.join(root, to), path.join(root, from));
  const event = R.HOSTS[host](row.command, { ...(row.folder === 'workdir-root' ? { workdir: root } : {}), ...(row.input ?? {}) });
  event.cwd = root;
  return event;
}

module.exports = { W, fixture, rows, record, HOSTS, cutRows, cutEvent, SIBLINGS };

// Last fix round: run-later FOLDER names are judged folded too (NFKC, then lower case); a look-alike, colon, trailing dot or space in a
// folder below the working folder and an /etc spelling keep the master answer. want = the expected answer (master asks on every row
// with data words; 'allow' only where the row is an owner-decided data write that stays quiet). Hook INPUT strings only: never run.
const FD_WORDS = 'deploy production';
const FD_SINKS = {
  echo: (t) => `echo ${FD_WORDS} > ${t}`,
  printf: (t) => `printf '%s\\n' "${FD_WORDS}" > ${t}`,
  heredoc: (t) => `cat > ${t} <<EOF\n${FD_WORDS}\nEOF`,
  append: (t) => `echo ${FD_WORDS} >> ${t}`,
};
const fdQuote = (t) => (/[ \\]/.test(t) ? `'${t}'` : t);

function folderRows() {
  const r = [];
  const add = (id, target, want, extra = {}) => {
    for (const [sink, make] of Object.entries(FD_SINKS)) {
      const quote = extra.bare ? (t) => t : fdQuote;
      r.push({ id: `${id}|${sink}|${target}`, command: (root) => make(quote(typeof target === 'function' ? target(root) : target)), want, ...extra });
    }
  };
  const one = (id, command, want, extra = {}) => r.push({ id, command, want, ...extra });
  const leaf = (id, dir, file, want = 'ask') => add(id, `${dir}/${file}`, want, { dirs: [dir] });
  leaf('F-D1', 'Buildkite', 'pipeline.json');
  leaf('F-D2', 'BUILDKITE', 'p.json');
  leaf('F-D3', '.BUILDKITE', 'p.json');
  leaf('F-D4', 'CRON.D', 'x.log');
  leaf('F-D5', 'Cron.d', 'x.log');
  leaf('F-D6', 'cron.d', 'x.log');
  leaf('F-D7', 'SystemD', 'x.txt');
  leaf('F-D8', 'systemd', 'x.txt');
  leaf('F-D9', 'launchagents', 'x.txt');
  leaf('F-D10', 'LaunchAgents', 'x.txt');
  leaf('F-D11a', 'Launchdaemons', 'x.txt');
  leaf('F-D11b', 'LAUNCHDAEMONS', 'x.txt');
  leaf('F-D12a', '\u212auildkite', 'p.json');
  leaf('F-D12b', 'build\u212aite', 'p.json');
  leaf('F-D13a', 'b\u0131ldkite', 'p.json');
  leaf('F-D13b', 'BU\u0130LDKITE', 'p.json');
  leaf('F-D14a', '\uff42uildkite', 'p.json');
  leaf('F-D14b', '\uff53ystemd', 'x.txt');
  leaf('F-D14c', '\uff43\uff52\uff4f\uff4e.\uff44', 'x.log');
  leaf('F-D14d', 'cron\uff0ed', 'x.log');
  leaf('F-D15a', 'cron.d.', 'x.log');
  leaf('F-D15b', 'Buildkite.', 'p.json');
  leaf('F-D16a', 'cron.d ', 'x.log');
  leaf('F-D16b', 'Buildkite ', 'p.json');
  add('F-D17a', 'notes/../Buildkite/p.json', 'ask', { dirs: ['Buildkite'] });
  add('F-D17b', 'docs/../SystemD/x.txt', 'ask', { dirs: ['SystemD'] });
  add('F-D18a', './Buildkite/p.json', 'ask', { dirs: ['Buildkite'] });
  add('F-D18b', '././CRON.D/x.log', 'ask', { dirs: ['CRON.D'] });
  // The shell drops an unquoted backslash: the target is the plain file Buildkitep.json in the working folder (the decided class);
  // a quoted or doubled backslash names a file with a backslash in it and asks.
  add('F-D19a', 'Buildkite\\p.json', 'allow', { dirs: ['Buildkite'], bare: true });
  add('F-D19b', 'Buildkite\\p.json', 'ask', { dirs: ['Buildkite'] });
  add('F-D19c', 'Buildkite\\\\p.json', 'ask', { dirs: ['Buildkite'], bare: true });
  add('F-D20a', 'lk/notes/p.json', 'ask', { dirs: ['Buildkite', 'lk'], links: [['lk/notes', 'Buildkite']] });
  add('F-D20b', 'lk/docs/x.log', 'ask', { dirs: ['CRON.D', 'lk'], links: [['lk/docs', 'CRON.D']] });
  add('F-D20c', 'lk2/Buildkite/a.md', 'allow', { dirs: ['notes', 'lk2'], links: [['lk2/Buildkite', 'notes']] });
  add('F-D20d', 'notes/lx.md', 'ask', { dirs: ['SystemD', 'notes'], files: ['SystemD/x.md'], links: [['notes/lx.md', 'SystemD/x.md']] });
  add('F-D21a', 'a/B/Buildkite/p.json', 'ask', { dirs: ['a/B/Buildkite'] });
  add('F-D21b', 'notes/Cron.D/x.log', 'ask', { dirs: ['notes/Cron.D'] });
  add('F-D21c', 'Notes/SystemD/x.txt', 'ask', { dirs: ['Notes/SystemD'] });
  add('F-D21d', 'docs/LaunchAgents/x.md', 'ask', { dirs: ['docs/LaunchAgents'] });
  for (const [id, cwd] of [['F-D22a', 'w1/SystemD'], ['F-D22b', 'w2/Buildkite/work'], ['F-D22c', 'w3/CRON.D'], ['F-D22d', 'w4/\uff4caunchagents']]) {
    add(id, 'notes/a.md', 'ask', { dirs: [`${cwd}/notes`], cwd });
    for (const key of ['cwd', 'workdir', 'working_directory']) add(`${id}-${key}`, 'notes/a.md', 'ask', { dirs: [`${cwd}/notes`], cwd, inputCwd: key });
    add(`F-D23${id.slice(-1)}`, (root) => `${root}/${cwd}/notes/a.md`, 'ask', { dirs: [`${cwd}/notes`], cwd });
  }
  add('F-D23e', (root) => `${root}/Buildkite/p.json`, 'ask', { dirs: ['Buildkite'] });
  for (const target of ['/ETC/x.log', '/Etc/cron.d/x.log', '/\uff45tc/x.log']) add(`F-D24|${target}`, target, 'ask');
  for (const [id, command] of [['F-D25-cd', 'cd Buildkite && echo deploy > p.json'], ['F-D25-semi', 'echo hi; echo deploy > Buildkite/p.json'],
    ['F-D25-or', 'true || echo deploy > CRON.D/x.log'],['F-D25-subshell', '(echo deploy > Buildkite/p.json)'],
    ['F-D25-bash-c', "bash -c 'echo deploy > Buildkite/p.json'"], ['F-D26-last', 'echo deploy > notes/a.md > Buildkite/p.json'],
    ['F-D26-first', 'echo deploy > Buildkite/p.json > notes/a.md'], ['F-D27-var', 'echo deploy > $D/p.json'], ['F-D27-glob', 'echo deploy > Build*/p.json'],
    ['F-D27-brace', 'echo deploy > {Buildkite,notes}/p.json']]) one(id, () => command, 'ask', { dirs: ['Buildkite', 'CRON.D', 'SystemD', 'notes'] });
  // The lone verb through tee is allowed on master too (the hold by name reads the folder as written): master's answer stays.
  for (const [id, command] of [['F-D25-pipe', 'echo deploy | tee SystemD/x.txt'], ['F-D25-pipe-words', 'echo deploy production | tee SystemD/x.txt']]) {
    one(id, () => command, 'allow', { dirs: ['SystemD'] });
  }
  leaf('F-D28a', 'cron\u200d.d', 'x.log');
  leaf('F-D28b', 'Buildki\u0301te', 'p.json');
  leaf('F-D28c', 'sys\u200btemd', 'x.txt');
  leaf('F-D28d', 'n\u00f6tes', 'a.md');
  leaf('F-D28e', 'notes:x', 'a.md');
  for (const [id, command] of [['F-D29-env-flag', 'echo deploy --env production > Buildkite/p.json'], ['F-D29-node-env', 'NODE_ENV=production echo deploy > Buildkite/p.json'],
    ['F-D29-file-word', 'echo deploy > Buildkite/production.json'], ['F-D29-prod-folder', 'echo deploy > notes/prod/SystemD/x.txt'],
    ['F-D29-real-verb', 'wrangler deploy > Buildkite/p.json'], ['F-D29-real-verb-env', 'wrangler deploy --env production > CRON.D/x.log']]) {
    one(id, () => command, 'ask', { dirs: ['Buildkite', 'CRON.D', 'notes/prod/SystemD'] });
  }
  for (const target of ['notes/a.md', 'docs/x.md', 'logs/run.log', 'reports/R.md', 'tmp/x.txt']) add(`F-D30|${target}`, target, 'allow', { dirs: [target.split('/')[0]] });
  add('F-D30-home', 'notes/a.md', 'allow', { dirs: ['h\u00f6me/work/notes'], cwd: 'h\u00f6me/work' });
  add('F-D30-Notes-noext', 'Notes/x', 'ask', { dirs: ['Notes'] });
  add('F-D30-Notes-md', 'Notes/x.md', 'allow', { dirs: ['Notes'] });
  // A FILE named like a run-later folder in a data folder is judged by its file name (the folder fold reads folders only).
  for (const target of ['notes/buildkite', 'notes/SystemD']) add(`F-D32|${target}`, target, 'allow', { dirs: ['notes'] });
  // The run-later list still decides inside the ordinary test where no folder fold applies: a bare repository's config in a data folder,
  // written through a link (the hold by name reads the path as written).
  add('F-D33', 'lnkbare/config', 'ask', { dirs: ['bare/notes/objects'], files: ['bare/notes/HEAD'], links: [['lnkbare', 'bare/notes']] });
  for (const [id, dir] of [['F-D31a', 'buildkites'], ['F-D31b', 'my-cron.d'], ['F-D31c', 'systemd-notes'], ['F-D31d', 'Buildkite2'], ['F-D31e', 'xcron.d']]) leaf(id, dir, 'x.json', 'allow');
  return r;
}

/** The class sweep: 5 non-dotted run-later folders x 5 spellings x 4 positions x 3 sinks = 300 rows, every one asks (equality after fold). */
function sweepRows() {
  const r = [];
  const spell = { buildkite: ['buildkite', 'BUILDKITE', 'buildkite', 'BuildKite', 'build\u212aite'], 'cron.d': ['cron.d', 'CRON.D', 'cron.d', 'Cron.D', '\uff43ron.d'],
    systemd: ['systemd', 'SYSTEMD', 'systemd', 'SystemD', '\uff53ystemd'], LaunchAgents: ['LaunchAgents', 'LAUNCHAGENTS', 'launchagents', 'launchAgents', '\uff2caunchAgents'],
    LaunchDaemons: ['LaunchDaemons', 'LAUNCHDAEMONS', 'launchdaemons', 'launchDaemons', '\uff2caunchDaemons'] };
  const forms = ['exact', 'upper', 'lower', 'mixed', 'look'];
  for (const [folder, names] of Object.entries(spell)) {
    names.forEach((dir, at) => {
      for (const sink of ['echo', 'printf', 'heredoc']) {
        const make = FD_SINKS[sink];
        const id = `sweep|${folder}|${forms[at]}|${sink}`;
        r.push({ id: `${id}|leaf`, command: () => make(`${dir}/x.json`), want: 'ask', dirs: [dir] });
        r.push({ id: `${id}|nested`, command: () => make(`notes/${dir}/x.json`), want: 'ask', dirs: [`notes/${dir}`] });
        r.push({ id: `${id}|cwd`, command: () => make('notes/x.json'), want: 'ask', dirs: [`sw/${dir}/notes`], cwd: `sw/${dir}` });
        r.push({ id: `${id}|absolute`, command: (root) => make(`${root}/${dir}/x.json`), want: 'ask', dirs: [dir] });
      }
    });
  }
  return r;
}

/** The event of a folder row: its folders, files and links made in the fixture root; the working folder is root or row.cwd below it. */
function folderEvent(row, root, host = 'claude') {
  for (const dir of row.dirs ?? []) fs.mkdirSync(path.join(root, dir), { recursive: true });
  for (const file of row.files ?? []) if (!fs.existsSync(path.join(root, file))) fs.writeFileSync(path.join(root, file), 'x\n');
  for (const [from, to] of row.links ?? []) if (!fs.existsSync(path.join(root, from))) fs.symlinkSync(path.join(root, to), path.join(root, from));
  const cwd = path.join(root, row.cwd ?? '');
  const event = R.HOSTS[host](row.command(root), row.inputCwd ? { [row.inputCwd]: cwd } : {});
  event.cwd = cwd;
  return event;
}

Object.assign(module.exports, { folderRows, sweepRows, folderEvent });
