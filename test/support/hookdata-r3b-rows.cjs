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

module.exports = { W, fixture, rows, record, HOSTS };
