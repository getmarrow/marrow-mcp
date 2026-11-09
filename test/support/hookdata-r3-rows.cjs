'use strict';
// Rows of the data-words spec (FIX1-HOOKDATA-R3): every input is a hook INPUT string judged by classifyTool, never run.
// expect: { master, tip } with 'ask' | 'allow'. A row may carry setup(fixture) (links), cwd (relative folder) and input (extra tool_input fields).
const fs = require('node:fs');
const path = require('node:path');

const W = 'deploy production secrets';
const BODY = `checklist ${W}\nsecond line\n`;
const LONG = `${'notes line with plain text\n'.repeat(260)}${W}\n`;

function fixture(root) {
  for (const dir of ['notes', 'records', 'logs', 'briefs', 'docs', 'reports', '.git/hooks', '.git/modules/sub', '.github/workflows',
    '.github/actions/a', '.github/ISSUE_TEMPLATE', '.husky', '.circleci', '.vscode', 'bare.git/objects', 'home/.config/git', 'cdtarget']) {
    fs.mkdirSync(path.join(root, dir), { recursive: true });
  }
  for (const file of ['.git/config', '.git/modules/sub/config', 'bare.git/HEAD', 'bare.git/config', 'package.json', 'Makefile', '.husky/pre-commit',
    '.github/workflows/ci.yml', 'notes/NOTES.md', 'logs/run.log', 'docs/run.sh']) {
    fs.writeFileSync(path.join(root, file), file.endsWith('.json') ? '{}\n' : 'x\n');
  }
  fs.writeFileSync(path.join(root, 'notes', 'exec.md'), 'x\n');
  fs.chmodSync(path.join(root, 'notes', 'exec.md'), 0o755);
  fs.writeFileSync(path.join(root, 'notes', 'bang.md'), '#!/bin/sh\n');
  return root;
}

const links = {
  hard: (target) => (root) => { const at = path.join(root, `hl-${path.basename(target)}.txt`); if (!fs.existsSync(at)) fs.linkSync(path.join(root, target), at); return path.basename(at); },
  soft: (target) => (root) => { const at = path.join(root, 'notes', `sl-${path.basename(target)}.md`); if (!fs.existsSync(at)) fs.symlinkSync(path.join(root, target), at); return `notes/${path.basename(at)}`; },
};

const LINK_TARGETS = ['.git/config', 'package.json', '.github/workflows/ci.yml', '.husky/pre-commit', 'Makefile'];

function rows() {
  const r = [];
  const add = (id, command, master, tip, extra = {}) => r.push({ id, command, expect: { master, tip }, ...extra });
  // FN: the only loosening rows (master ASK, tip ALLOW).
  add('FN1', `echo "2026-11-09 ${W} rotated" >> logs/run.log`, 'ask', 'allow');
  add('FN1-single', `echo '2026-11-09 ${W} rotated' >> logs/run.log`, 'ask', 'allow');
  add('FN1-printf', `printf '%s\\n' "2026-11-09 ${W} rotated" >> logs/run.log`, 'ask', 'allow');
  add('FN1-gt', `echo "${W}" > logs/new.log`, 'ask', 'allow');
  add('FN1-abs', (root) => `echo "${W}" >> ${root}/logs/run.log`, 'ask', 'allow');
  add('FN1-dot', `echo "${W}" >> ./notes/x.md`, 'ask', 'allow');
  add('FN1-start', `echo "deploy is the first word" >> logs/run.log`, 'ask', 'allow');
  add('FN1-end', `echo "last word is production" >> logs/run.log`, 'ask', 'allow');
  add('FN2', `cat >> notes/NOTES.md <<'EOF'\n${BODY}EOF`, 'ask', 'allow');
  add('FN2-dq', `cat >> notes/NOTES.md <<"EOF"\n${BODY}EOF`, 'ask', 'allow');
  add('FN2-crlf', `cat >> notes/NOTES.md <<'EOF'\nchecklist ${W}\r\nsecond\r\nEOF`, 'ask', 'allow');
  add('FN2-long', `cat >> notes/NOTES.md <<'EOF'\n${LONG}EOF`, 'ask', 'allow');
  add('FN2-op-first', `cat <<'EOF' >> notes/NOTES.md\n${BODY}EOF`, 'ask', 'allow');
  add('FN3', `cat > records/DOGFOOD-20261109.md <<'EOF'\n# Dogfood\n${W} named here\nEOF`, 'ask', 'allow');
  add('FN4', `cat > briefs/job-brief.md <<EOF\nbrief: ${W}\nEOF`, 'ask', 'allow');
  add('FN4-noext', `cat > notes/brief <<EOF\nbrief: ${W}\nEOF`, 'ask', 'allow');
  add('FN8', `echo 'see package.json scripts before the deploy' >> notes/NOTES.md`, 'ask', 'allow');
  add('FN9', `cat >> notes/NOTES.md <<'EOF'\nthe Makefile deploy target and .github/workflows/ci.yml production job\nEOF`, 'ask', 'allow');
  add('FN10', `printf '%s\\n' 'the .github/workflows release job' >> notes/NOTES.md`, 'ask', 'allow');
  // Never stricter (already allowed on master).
  add('FN6', `grep -rn "${W}" docs`, 'allow', 'allow');
  add('FN7', `echo "${W}" | tee -a logs/run.log`, 'allow', 'allow');
  // SA: must still ask (byte-equal to master).
  add('SA1-bash-c', `bash -c 'wrangler deploy --env production <<EOF\nx\nEOF'`, 'ask', 'ask');
  add('SA1-sh-c', `sh -c "cat <<EOF | sh\n${W}\nEOF"`, 'ask', 'ask');
  add('SA1-bash-c-echo', `bash -c 'echo ${W} >> logs/run.log'`, 'ask', 'ask');
  add('SA1-bash-heredoc', `bash <<EOF\necho ${W}\nEOF`, 'ask', 'ask');
  add('SA1-sh-heredoc', `sh <<'EOF'\necho ${W}\nEOF`, 'ask', 'ask');
  add('SA2-words', `cat <<EOF > .github/workflows/x.yml\nname: ${W}\nEOF`, 'ask', 'ask');
  add('SA2-nowords', `cat <<EOF > .github/workflows/x.yml\nname: ci\nEOF`, 'allow', 'ask', { raised: true });
  add('SA3-tee', `echo "deploy production" | tee -a ~/.bashrc`, 'ask', 'ask');
  add('SA3-zshrc', `echo "${W}" >> ~/.zshrc`, 'ask', 'ask');
  add('SA3-profile', `echo "${W}" > ~/.profile`, 'ask', 'ask');
  add('SA4-sh', `echo "wrangler deploy --env production" | sh`, 'ask', 'ask');
  add('SA4-bash', `echo "${W}" | bash`, 'allow', 'allow', { masterAllows: true });
  add('SA4-zsh', `echo "${W}" | zsh`, 'allow', 'allow', { masterAllows: true });
  add('SA4-xargs', `echo "${W}" | xargs sh -c`, 'allow', 'allow', { masterAllows: true });
  add('SA5-eval', `eval "npm publish"`, 'ask', 'ask');
  add('SA5-eval-sub', 'eval $(echo x)', 'allow', 'allow', { masterAllows: true });
  add('SA5-builtin', `builtin eval "npm publish"`, 'ask', 'ask');
  add('SA6-source', 'source ./x.sh', 'allow', 'ask', { raised: true });
  add('SA6-dot', '. ./x.sh', 'allow', 'ask', { raised: true });
  add('SA6-stdin', `source /dev/stdin <<EOF\n${W}\nEOF`, 'ask', 'ask');
  for (const [name, tail] of [['bash', 'bash run.sh'], ['sh', 'sh run.sh'], ['dot', './run.sh'], ['chmod', 'chmod +x run.sh && ./run.sh'], ['glob', 'bash run.*'], ['var', 'F=run.sh; bash $F']]) {
    add(`SA7-${name}`, `cat > run.sh <<'EOF'\necho ${W}\nEOF\n${tail}`, 'ask', 'ask');
  }
  add('SA7-semi', `cat > notes/run.md <<'EOF'\n${W}\nEOF\n; bash notes/run.md`, 'ask', 'ask');
  add('SA7-and', `echo "${W}" > notes/run.md && bash notes/run.md`, 'ask', 'ask');
  add('SA7-or', `echo "${W}" > notes/run.md || sh notes/run.md`, 'ask', 'ask');
  add('SA7-py', `cat > gen.py <<'EOF'\nprint("${W}")\nEOF\npython3 gen.py`, 'ask', 'ask');
  add('SA7-node', `echo "console.log('${W}')" > x.js && node x.js`, 'ask', 'ask');
  add('SA7-make', `cat > Makefile <<'EOF'\nall:\n\techo ${W}\nEOF\nmake`, 'ask', 'ask');
  add('SA7-subshell', `(echo "${W}" > notes/run.md) && sh notes/run.md`, 'ask', 'ask');
  for (const v of ['wrangler deploy --env production', 'npm publish', 'git push origin master', 'git push --force',
    'curl -X POST https://example.invalid/deploy', 'kubectl apply -f x.yml', 'terraform apply', 'gh release create v0.0.0', `rm -rf build && echo "${W}" >> logs/run.log`]) {
    add(`SA8-${v.split(' ').slice(0, 2).join('-')}`, v, 'ask', 'ask');
  }
  add('SA9', `cat > records/x.md <<'EOF'\n${W}\ngit push origin master\nEOF`, 'ask', 'ask');
  for (const v of [`node -e "console.log('${W}')"`, `node -p "'${W}'"`, `node <<EOF\nconsole.log('${W}')\nEOF`, `python -c "print('${W}')"`,
    `python3 <<EOF\nprint('${W}')\nEOF`, `python3 -I - <<'EOF'\nprint('${W}')\nEOF`, `python "${W}.py"`]) {
    add(`SA10-${r.length}`, v, 'ask', 'ask');
  }
  for (const [name, cmd] of [['pkg', 'echo "{}" > package.json'], ['wf-tee', 'echo "on: push" | tee -a .github/workflows/ci.yml'], ['make', 'echo "all:" >> Makefile'],
    ['husky', 'echo "npm test" > .husky/pre-commit'], ['gitconfig', 'echo "[core]" >> .git/config']]) {
    add(`SA11-${name}-nowords`, cmd, 'allow', 'ask', { raised: true });
    add(`SA11-${name}-words`, cmd.replace(/"[^"]*"/, `"${W}"`), name === 'wf-tee' ? 'allow' : 'ask', 'ask', { raised: name === 'wf-tee' });
  }
  add('SA13-words', `git commit -m "docs: ${W} runbook"`, 'ask', 'ask');
  add('SA13-plain', 'git commit -m "docs: update runbook"', 'ask', 'ask');
  for (const v of ['git push origin production', 'npm run deploy', 'docker push registry.invalid/prod', 'some-tool --env=production', 'some-tool -e prod']) {
    add(`SA12-${r.length}`, v, 'ask', 'ask');
  }
  // B-1: the L01 shape (python3 -I - markdown edit) with multi-argument Path()/open() on a run-later file stays master (ask on the held text).
  for (const call of ["Path('.git','config')", "Path('.git', 'config')", "Path('.','.git','config')", "Path('.', '.git', 'config')",
    "Path('.github','workflows','ci.yml')", "Path('.github', 'workflows', 'ci.yml')", "Path('.github', 'workflows/ci.yml')", "open('.git','config')"]) {
    add(`B1-${call}`, ["python3 -I - <<'EOF'", 'from pathlib import Path', `p = ${call}`, 'text = p.read_text()',
      "p.write_text(text.replace('Deploy to production on Friday', 'Deploy to production on Monday'))", 'EOF'].join('\n'), 'ask', 'ask', { b: 'B1' });
  }
  // B-2: the shell folder in tool_input (each CWD_KEYS spelling) is honoured: a run-later folder keeps master.
  for (const dir of ['.git', '.github/workflows', '.husky']) {
    for (const [key, host] of [['working_directory', 'Shell'], ['workdir', 'Bash'], ['cwd', 'Bash'], ['directory', 'run_shell_command']]) {
      add(`B2-${key}-${dir}`, `echo "${W}" >> config`, 'ask', 'ask', { b: 'B2', tool: host, inputDir: { key, dir } });
    }
  }
  add('B2-heredoc', `cat >> config <<'EOF'\n${W}\nEOF`, 'ask', 'ask', { b: 'B2', inputDir: { key: 'workdir', dir: '.git' } });
  add('B2-event-cwd', `echo "${W}" >> config`, 'ask', 'ask', { b: 'B2', eventDir: '.git' });
  // B-3: an unknown folder (cd -, cd ~-, pushd, popd, cd, cd +1, cd -1) keeps master.
  for (const cd of ['cd -', 'cd ~-', 'popd', 'cd', 'cd +1', 'cd -1', 'pushd +1', 'cd ""', 'cd $OLDPWD', 'cd .git']) {
    add(`B3-${cd}`, `${cd} && echo "${W}" >> config`, 'ask', 'ask', { b: 'B3' });
  }
  // B-4: hard links and symlinks to run-later files.
  for (const target of LINK_TARGETS) {
    add(`B4-hard-${target}`, (root) => `echo "${W}" >> ${links.hard(target)(root)}`, 'ask', 'ask', { b: 'B4' });
    add(`B4-soft-${target}`, (root) => `echo "${W}" >> ${links.soft(target)(root)}`, 'ask', 'ask', { b: 'B4' });
  }
  // B-6: merge siblings and other git writers of a run-later target.
  for (const v of ['git merge-file .git/config a b', 'git merge-tree a b', 'git merge-base a b && rm -rf build', 'git apply x.patch',
    'git am x.mbox', 'git checkout-index -f .git/config', 'git restore --source HEAD~1 package.json', 'git restore --source HEAD~1 Makefile']) {
    add(`B6-${r.length}`, v, v.includes('merge') || v.includes('rm -rf') ? 'ask' : 'allow', /git (?:apply|am) /.test(v) ? 'allow' : 'ask', { b: 'B6', raised: /checkout-index|restore/.test(v) });
  }
  add('B6-cwd', 'git merge-file config a b', 'ask', 'ask', { b: 'B6', eventDir: '.git' });
  // F-1: run-later siblings, written with no word and with words.
  for (const file of ['.gitmodules', '.pre-commit-config.yaml', 'justfile', 'Taskfile.yml', 'docker-compose.yml', '.vscode/tasks.json',
    '.git/modules/sub/config', 'bare.git/config', '.gitlab-ci.yml', '.circleci/config.yml', 'package.yaml', 'rules.mk', '.envrc', 'tsconfig.json',
    '.github/actions/a/action.yml', 'home/.gitconfig', 'home/.config/git/config', '.git/hooks/pre-push', '.npmrc', 'vite.config.ts', '/etc/profile.d/x.sh']) {
    add(`FU1-nowords-${file}`, `echo "x = 1" >> ${file}`, /\.git\/hooks|\.npmrc/.test(file) ? 'ask' : 'allow', 'ask', { fu: 'FU1', raised: !/\.git\/hooks|\.npmrc/.test(file) });
    add(`FU1-words-${file}`, `echo "${W}" >> ${file}`, 'ask', 'ask', { fu: 'FU1' });
    add(`FU1-heredoc-${file}`, `cat >> ${file} <<'EOF'\n${W}\nEOF`, 'ask', 'ask', { fu: 'FU1' });
  }
  add('FU2-dR32-template', `echo "${W}" >> .github/ISSUE_TEMPLATE/bug.md`, 'ask', 'ask', { fu: 'FU2' });
  add('FU2-dR32-pr', `echo "${W}" >> .github/PULL_REQUEST_TEMPLATE.md`, 'ask', 'ask', { fu: 'FU2' });
  // R2/R5/R9 and the A-rows: around each FN row the master answer stays.
  const fnEcho = `echo "${W}" >> notes/NOTES.md`;
  for (const [name, cmd] of [
    ['A-chain-and', `${fnEcho} && wrangler deploy`], ['A-chain-semi', `${fnEcho}; npm publish`], ['A-chain-or', `${fnEcho} || git push origin master`],
    ['A-chain-pipe', `${fnEcho} | sh`], ['A-chain-bg', `${fnEcho} & echo "${W}" >> logs/run.log`], ['A-chain-nl', `${fnEcho}\necho "${W}" >> logs/run.log`],
    ['A-chain-subshell', `(${fnEcho})`], ['A-chain-brace', `{ ${fnEcho}; }`], ['A-chain-after-eof', `cat >> notes/NOTES.md <<'EOF'\n${W}\nEOF\necho "${W}" >> logs/run.log`],
    ['A-chain-sudo', `sudo ${fnEcho}`], ['A-chain-env', `env ${fnEcho}`], ['A-chain-time', `time ${fnEcho}`], ['A-chain-nohup', `nohup ${fnEcho}`],
    ['A-var-target', `echo "${W}" >> $F`], ['A-var-arg', `echo "${W} $HOME" >> notes/NOTES.md`], ['A-var-brace', `echo "${W}" >> notes/{a,b}.md`],
    ['A-var-glob', `echo "${W}" >> notes/*.md`], ['A-var-sub', `echo "${W} $(id)" >> notes/NOTES.md`], ['A-var-tick', `echo "${W} \`id\`" >> notes/NOTES.md`],
    ['A-var-alias', `alias echo=bash; echo "${W}" >> notes/NOTES.md`], ['A-var-func', `echo() { bash; }; echo "${W}" >> notes/NOTES.md`],
    ['A-var-unquoted-body-sub', `cat > notes/x.md <<EOF\n${W} $(id)\nEOF`], ['A-var-unquoted-body-var', `cat > notes/x.md <<EOF\n${W} \${HOME}\nEOF`],
    ['A-var-path-word', `./echo "${W}" >> notes/NOTES.md`], ['A-var-abs-word', `/bin/echo "${W}" >> notes/NOTES.md`], ['A-var-command', `command echo "${W}" >> notes/NOTES.md`],
    ['A-var-builtin', `builtin echo "${W}" >> notes/NOTES.md`], ['A-var-lookalike', `echо "${W}" >> notes/NOTES.md`], ['A-var-tilde', `echo "${W}" >> ~/notes.md`],
    ['A-var-dotdot', `echo "${W}" >> ../outside.md`], ['A-var-dev', `echo "${W}" >> /dev/tcp/127.0.0.1/9`], ['A-var-proc', `echo "${W}" >> /proc/self/fd/1`],
    ['A-flag-clobber', `echo "${W}" >| notes/NOTES.md`], ['A-flag-amp', `echo "${W}" &> notes/NOTES.md`], ['A-flag-fd', `echo "${W}" 2> notes/NOTES.md`],
    ['A-flag-rw', `echo "${W}" <> notes/NOTES.md`], ['A-flag-two', `echo "${W}" > notes/a.md > notes/b.md`], ['A-flag-echo-e', `echo -e "${W}" >> notes/NOTES.md`],
    ['A-flag-printf-v', `printf -v x "${W}" >> notes/NOTES.md`], ['A-flag-herestring', `cat <<< "${W}" >> notes/NOTES.md`], ['A-flag-dash-heredoc', `cat <<-EOF >> notes/NOTES.md\n${W}\nEOF`],
    ['A-flag-cat-file', `cat x <<'EOF' >> notes/NOTES.md\n${W}\nEOF`], ['A-flag-unterminated', `cat >> notes/NOTES.md <<'EOF'\n${W}\n`], ['A-flag-tee-heredoc', `tee notes/NOTES.md <<'EOF'\n${W}\nEOF`],
    ['A-flag-two-heredocs', `cat >> notes/NOTES.md <<'A' <<'B'\n${W}\nA\n${W}\nB`], ['A-flag-comment-op', `echo hi >> notes/NOTES.md # <<EOF\nwrangler deploy\nEOF`],
    ['A-flag-quoted-op', `echo "x <<EOF y" >> notes/NOTES.md\nwrangler deploy\nEOF`],
    ['A-word-sh-target', `echo "${W}" >> notes/run.sh`], ['A-word-py-target', `echo "${W}" >> gen.py`], ['A-word-exec', `echo "${W}" >> notes/exec.md`],
    ['A-word-shebang', `echo "${W}" >> notes/bang.md`], ['A-word-dotfile', `echo "${W}" >> notes/.hidden.md`], ['A-word-unknown-ext', `echo "${W}" >> notes/x.bin`],
    ['A-word-noext-root', `echo "${W}" >> README`], ['A-word-missing-folder', `echo "${W}" >> nofolder/x.md`], ['A-word-git-notes', `echo "${W}" >> .git-notes/x.md`],
  ]) add(name, cmd, 'ask', 'ask', { a: true });
  add('A-word-makefile-md', `echo "${W}" >> notes/Makefile.md`, 'ask', 'allow', { a: true, fnVariant: 'FN1' });
  add('A-word-deploy-notes', `echo "plain text" >> notes/deploy-notes.md`, 'ask', 'ask', { a: true });
  add('A-word-run-later-msg', `echo "this file will run later" >> notes/NOTES.md`, 'allow', 'allow', { a: true });
  add('A-word-branch', 'git checkout -b production', 'ask', 'ask', { a: true });
  return r;
}

const HOSTS = {
  claude: (command, extra = {}) => ({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command, description: 'x', ...extra } }),
  codex: (command, extra = {}) => ({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command, ...extra } }),
  cursor: (command, extra = {}) => ({ hook_event_name: 'preToolUse', tool_name: 'Shell', tool_input: { command, ...extra } }),
  gemini: (command, extra = {}) => ({ hook_event_name: 'BeforeTool', tool_name: 'run_shell_command', tool_input: { command, ...extra } }),
  grok: (command, extra = {}) => ({ hook_event_name: 'PreToolUse', tool_name: 'run_terminal_command', tool_input: { command, ...extra } }),
  monitor: (command) => ({ hook_event_name: 'PreToolUse', tool_name: 'Monitor', tool_input: { command } }),
  powershell: (command) => ({ hook_event_name: 'PreToolUse', tool_name: 'PowerShell', tool_input: { command } }),
};

/** The event of a row in a fixture root (cwd = root unless the row moves it). */
function eventFor(row, root, host = 'claude') {
  const command = typeof row.command === 'function' ? row.command(root) : row.command;
  const extra = row.inputDir ? { [row.inputDir.key]: path.join(root, row.inputDir.dir) } : {};
  const make = row.tool ? (c, e) => ({ hook_event_name: 'PreToolUse', tool_name: row.tool, tool_input: { command: c, ...e } }) : HOSTS[host];
  const event = make(command, extra);
  event.cwd = row.eventDir ? path.join(root, row.eventDir) : root;
  return event;
}

/** The answer of one built dist (root of a clone) for an event. */
function answer(dist, event) {
  const c = dist.classifyTool(event, { cwd: event.cwd });
  return { decision: c.protected ? 'ask' : 'allow', type: c.type, surfaces: c.surfaces.join(','), target: c.target, risk: c.risk, role: c.role, action: c.action };
}

module.exports = { W, fixture, rows, HOSTS, eventFor, answer, LINK_TARGETS };
