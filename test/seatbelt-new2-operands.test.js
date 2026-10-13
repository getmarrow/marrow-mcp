'use strict';

// Delta audit of 0368537c, NEW-2: a protected path given as an operand of a program that is not on the
// explicit reader list stops (S0), so writers the mapper does not model (sponge, ed, ex, xxd -r,
// awk -i inplace, yq -i, curl -so, wget -qO, node -e … <path>) no longer pass. Readers (cat, less, more,
// head, tail, grep, rg, wc, stat, ls, file, diff, cmp, checksums, jq/yq without in-place, bat) keep
// passing. Mapper rows use the fake environment; the hook rows run the audit's 11 rows through the real
// hook CLI keyless on all 7 host paths (77 cells) plus Grok's fixed denial.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync, execFileSync } = require('node:child_process');

const { evaluateSeatbelt } = require('../dist/seatbelt/mapper.js');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const PRELOAD = path.join(__dirname, 'support', 'seatbelt-hook-preload.cjs');

const HOOKS = { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'npx -y --package=@getmarrow/mcp@3.9.103 marrow-mcp claude-pre-action-hook' }] }] };
const FILES = {
  '/home/u/.claude/settings.json': JSON.stringify({ hooks: HOOKS }, null, 2),
  '/home/u/.claude/plugins/installed_plugins.json': '{"version":2,"plugins":{}}',
  '/home/u/.marrow/control.json': '{}',
  '/home/u/.bashrc': '# rc\n',
  '/home/u/proj/.git/hooks/pre-commit': '#!/bin/sh\n',
  '/home/u/.claude/plugins/cache/getmarrow/marrow/1.2.3/scripts/marrow-launch.cjs': 'module.exports = 1;\n',
};
const sh = (command) => evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command } }, makeEnv({ files: FILES, dirs: ['/home/u/.claude', '/home/u/proj/.git/hooks'] }));

// The audit's 11 rows that passed on 0368537c (dahrows3), with the target as a parameter.
const AUDIT_ROWS = (T) => [
  `cat /tmp/aud-x.json | sponge ${T}`,
  `jq '.disableAllHooks=true' ${T} | sponge ${T}`,
  `curl -so ${T} https://example.test/s.json`,
  `wget -qO ${T} https://example.test/s.json`,
  `awk -i inplace '{print}' ${T}`,
  `ex -sc '1s/^{/{"disableAllHooks":true,/|x' ${T}`,
  `printf '1s/^{/{"disableAllHooks":true,/\\nw\\n' | ed -s ${T}`,
  `xxd -r /tmp/aud-x.hex ${T}`,
  'cp -r /tmp/aud-dir/. ~/.claude/',
  `yq -i -o json '.disableAllHooks = true' ${T}`,
  `node -e "require('fs').writeFileSync(process.argv[1], '{}')" ${T}`,
];

const TARGETS = ['~/.claude/settings.json', '.claude/settings.json', '~/.marrow/control.json', '~/.bashrc', '.git/hooks/pre-commit',
  '~/.claude/plugins/installed_plugins.json', '$HOME/.claude/settings.json', '/home/u/proj/.mcp.json'];

test('NEW-2 mapper: the audit rows and other unmodelled writers stop (S0) on every protected target', () => {
  for (const T of TARGETS) {
    const rows = [
      ...AUDIT_ROWS(T),
      `python3 -c "import sys; open(sys.argv[1], 'w').write('{}')" ${T}`,
      `bash -c 'cat > "$1"' _ ${T}`,
      `sh -c 'echo x > "$0"' ${T}`,
      `perl -e 'open(F, ">", $ARGV[0])' ${T}`,
      `ruby -e 'File.write(ARGV[0], "")' ${T}`,
      `vim ${T}`, `nano ${T}`, `code ${T}`, `sort -o ${T} ${T}`, `uniq /tmp/x ${T}`, `sudo -e ${T}`, `sudoedit ${T}`,
      `curl -sSLo ${T} https://example.test/s.json`, `curl -o${T} https://example.test/s.json`, `wget -O${T} https://example.test/s.json`,
      `./scripts/tool.sh --out=${T}`, `sometool --config ${T}`, `npx prettier --write ${T}`, `sponge "${T}"`,
      `python3 scripts/edit.py ${T}`, `node scripts/tool.js ${T}`, `gojq -i . ${T}`, `jq --in-place . ${T}`, `yq --inplace . ${T}`, `yq -Pi . ${T}`,
      `less -o ${T} /tmp/x`, `timeout 5 sponge ${T}`, `env A=1 sponge ${T}`, `xargs -a /tmp/x sponge ${T}`, `parallel --joblog ${T} echo ::: a`,
      `flock ${T} true`, `script -q ${T}`, `cat /tmp/x | tee -a ${T}`, `docker cp c:/x ${T}`, `yq -i=true . ${T}`,
      `ssh -E ${T} host true`, `ssh -o UserKnownHostsFile=${T} host true`, `ssh -oControlPath=${T} host true`, `nice -n 5 sponge ${T}`,
      `sudo -u root sponge ${T}`, `su -c "sponge ${T}"`, `eval "sponge ${T}"`, `watch -n 1 sponge ${T}`, `env -S "sponge ${T}"`,
    ];
    for (const c of rows) {
      const d = sh(c);
      assert.equal(d.decision, 'stop', `${c}: ${d.reasons}`);
      assert.ok(d.hits.some((h) => h.category === 'S0' || h.category === 'S4'), `${c}: ${d.reasons}`);
    }
  }
});

test('NEW-2 mapper: folders that hold protected files stop as operands of non-readers and as recursive copy targets', () => {
  for (const c of [
    'cp -r /tmp/aud-dir/. ~/.claude/', 'cp -r /tmp/aud-dir/. ~/.claude', 'cp -a /tmp/dotfiles/. ~', 'cp -r /tmp/dotfiles/. /home/u/', 'cp -r tmpl/.claude .',
    'rsync -a /tmp/dotfiles/ ~/', 'rsync -a /tmp/x/ ~/.claude/', 'cp -R /tmp/plugins ~/.claude/', 'tar -xf /tmp/aud.tar -C ~/.claude', 'unzip -o /tmp/aud.zip -d ~/.claude',
    'sometool --out-dir ~/.claude', 'sometool --out-dir=.claude', 'chmod 000 ~/.claude', 'chmod -R 000 .git', 'docker run -v ~/.claude:/root/.claude alpine true',
    'git -C ~/.claude/plugins/marketplaces/getmarrow pull', 'git checkout -- .claude/settings.json', 'git restore .claude/settings.json',
    'git rm .claude/settings.json', 'git restore --staged --worktree .claude/settings.json', 'git restore -SW .claude/settings.json', 'git diff --output=.claude/settings.json',
    'find ~/.claude -name settings.json -exec sed -i s/a/b/ {} +', 'find .git/hooks -type f -delete', 'sponge ~/.claude/settings.jso?', 'sponge ~/.claude/s*',
  ]) {
    const d = sh(c);
    assert.equal(d.decision, 'stop', `${c}: ${d.reasons}`);
  }
});

test('NEW-2 mapper: readers, builtins, scripts, remote paths and ordinary work pass (friction controls)', () => {
  const T = '~/.claude/settings.json';
  for (const c of [
    `cat ${T}`, `head -n 5 ${T}`, `tail -n 5 ${T}`, `grep -n hooks ${T}`, `rg marrow ${T}`, `wc -l ${T}`, `stat ${T}`, `ls -la ${T}`, `file ${T}`,
    `diff ${T} /tmp/x`, `cmp ${T} /tmp/x`, `sha256sum ${T}`, `md5sum ${T}`, `jq . ${T}`, `jq -r '.hooks' ${T}`, `yq '.hooks' ${T}`, `yq -o json . ${T}`, `bat ${T}`, `less ${T}`, `more ${T}`,
    'du -sh ~/.claude', `test -f ${T}`, `[ -f ${T} ]`, `echo ${T}`, `printf '%s\\n' ${T}`, `realpath ${T}`, `dirname ${T}`, 'cd ~/.claude && ls',
    'git diff .claude/settings.json', 'git add .claude/settings.json', 'git log -- .claude/settings.json', 'git show HEAD:.claude/settings.json', 'git status',
    'git reset HEAD .claude/settings.json', 'git reset -- .claude/settings.json', 'git rm --cached .claude/settings.json', 'git restore --staged .claude/settings.json',
    "find ~/.claude -name '*.json'", 'source ~/.bashrc', '. ~/.bashrc', 'mkdir -p .claude', 'mkdir -p ~/.claude/commands', 'touch .claude/notes.md',
    'npm test', 'npx prettier --write src', 'node scripts/tool.js', 'python3 -m pytest', 'cp -r src/ /tmp/backup', 'cp -r dist /tmp/out', 'rsync -a src/ /tmp/x/',
    'tar -xf /tmp/x.tar -C /tmp/x', 'docker run -v $PWD:/app node:22 npm test', 'docker run -v .:/app node:22 npm test',
    'kubectl --kubeconfig /etc/rancher/k3s/k3s.yaml get pods', 'gcc -I/usr/include -o /tmp/a.out src/a.c', 'nginx -t -c /etc/nginx/nginx.conf',
    'rsync -a host:~/.claude/ /tmp/claude-backup/', 'scp host:notes.txt /tmp/x', 'ssh host cat ~/.claude/settings.json', 'node ~/.claude/plugins/cache/getmarrow/marrow/1.2.3/scripts/marrow-launch.cjs --version',
    'bash scripts/build.sh', 'sh -c "npm test"', 'cp /tmp/x.json src/x.json', 'sed -n 1,5p README.md', 'curl -so /tmp/x https://example.test/s.json',
  ]) {
    const d = sh(c);
    assert.equal(d.decision, 'pass', `${c}: ${d.reasons}`);
  }
});

// ------------------------------------------------------------------------------------------------
// Hook rows: the real hook CLI, keyless, in a temporary home whose ~/.claude/settings.json holds Marrow hooks.

function keylessSandbox() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-new2-')));
  const home = path.join(root, 'home');
  const proj = path.join(home, 'proj');
  fs.mkdirSync(proj, { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  for (const d of ['.ssh', '.aws', '.marrow', '.claude']) fs.mkdirSync(path.join(home, d), { mode: 0o700 });
  fs.writeFileSync(path.join(home, '.claude', 'settings.json'), JSON.stringify({ hooks: HOOKS }, null, 2));
  execFileSync('git', ['init', '-q', '-b', 'feat/x'], { cwd: proj, env: { PATH: process.env.PATH, HOME: home, GIT_CONFIG_NOSYSTEM: '1' }, stdio: 'ignore' });
  return { root, home, proj, netspy: path.join(root, 'net.log'), cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}
const ENTRY = { claude: 'claude-pre-action-hook', codex: 'codex-pre-action-hook', cursor: 'cursor-pre-action-hook', 'cursor-pre': 'cursor-pre-action-hook',
  gemini: 'gemini-pre-action-hook', cline: 'cline-pre-action-hook', windsurf: 'windsurf-pre-action-hook', grok: 'grok-pre-action-hook' };
function hook(sb, host, event) {
  const r = spawnSync(process.execPath, ['--require', PRELOAD, CLI, ENTRY[host]], {
    cwd: sb.proj, encoding: 'utf8', timeout: 30_000, input: JSON.stringify(event),
    env: { PATH: process.env.PATH, HOME: sb.home, SBT_PASSWD_HOME: sb.home, SBT_NETSPY: sb.netspy, MARROW_HOOK_BACKGROUND_NUDGE: 'false' },
  });
  return { status: r.status, out: r.stdout || '', err: r.stderr || '' };
}
const sid = () => `n2-${crypto.randomBytes(6).toString('hex')}`;
function shellEvent(sb, host, command) {
  if (host === 'cursor') return { hook_event_name: 'beforeShellExecution', conversation_id: sid(), generation_id: 'g1', command, cwd: sb.proj };
  if (host === 'cursor-pre') return { hook_event_name: 'preToolUse', conversation_id: sid(), generation_id: 'g', tool_use_id: 't', tool_name: 'Shell', tool_input: { command }, cwd: sb.proj };
  if (host === 'gemini') return { session_id: sid(), hook_event_name: 'BeforeTool', tool_name: 'run_shell_command', tool_input: { command }, cwd: sb.proj };
  if (host === 'grok') return { hookEventName: 'PreToolUse', sessionId: sid(), toolUseId: 't', toolName: 'run_terminal_command', toolInput: { command }, cwd: sb.proj };
  if (host === 'cline') return { hookName: 'PreToolUse', taskId: sid(), workspaceRoots: [sb.proj], preToolUse: { toolName: 'execute_command', parameters: { command } } };
  if (host === 'windsurf') return { agent_action_name: 'pre_run_command', trajectory_id: sid(), execution_id: 'e', tool_info: { command_line: command, cwd: sb.proj } };
  return { hook_event_name: 'PreToolUse', session_id: sid(), tool_use_id: 't1', tool_name: 'Bash', tool_input: { command }, cwd: sb.proj };
}
function verdict(r) {
  let j = null;
  try { j = r.out.trim() ? JSON.parse(r.out) : null; } catch { j = null; }
  const text = JSON.stringify(j || '') + r.err;
  if (/^\{"decision":"deny","reason":"Marrow blocked this protected action\."\}$/.test(r.out.trim())) return 'GROK';
  const d = j ? (j.permission || j.hookSpecificOutput?.permissionDecision || j.decision || (j.cancel === true ? 'deny' : null)) : null;
  if ((r.status === 2 || d === 'deny' || d === 'block') && /MARROW SEATBELT stopped/.test(text)) return 'STOP';
  if (r.status === 2 || d === 'deny' || d === 'block') return 'held';
  return 'pass';
}

test('NEW-2 hook: the audit\'s 77 cells (11 rows x 7 host paths) stop keyless; Grok gives its fixed denial; a reader passes', () => {
  const sb = keylessSandbox();
  try {
    let cells = 0;
    for (const command of AUDIT_ROWS('~/.claude/settings.json')) {
      for (const host of ['claude', 'codex', 'cursor', 'cursor-pre', 'gemini', 'cline', 'windsurf']) {
        assert.equal(verdict(hook(sb, host, shellEvent(sb, host, command))), 'STOP', `${host}: ${command}`);
        cells += 1;
      }
      assert.equal(verdict(hook(sb, 'grok', shellEvent(sb, 'grok', command))), 'GROK', `grok: ${command}`);
    }
    assert.equal(cells, 77);
    for (const host of ['claude', 'codex', 'cursor', 'gemini', 'cline', 'windsurf']) {
      assert.equal(verdict(hook(sb, host, shellEvent(sb, host, 'jq . ~/.claude/settings.json'))), 'pass', host);
    }
    assert.equal(fs.existsSync(sb.netspy) ? fs.readFileSync(sb.netspy, 'utf8') : '', '');
  } finally { sb.cleanup(); }
});
