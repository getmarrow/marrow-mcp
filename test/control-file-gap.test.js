const assert = require('node:assert/strict');
const { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

const { classifyTool, localApprovalCategories } = require('../dist/hook-pre-action.js');

// Control-file gap (spec friction r3 §4.3 T2, §4.6 F-R3-1, §5 rows C6-C8, A11-A15): a write to ~/.marrow/**, to any host's hooks settings,
// or to a file that makes a command run later is `security on marrow-control` / `security on persistence`, whatever the tool or shell form.

const root = mkdtempSync(join(tmpdir(), 'marrow-cfg-'));
const home = join(root, 'home');
mkdirSync(join(home, '.marrow'), { recursive: true });
mkdirSync(join(home, '.claude'), { recursive: true });
mkdirSync(join(home, 'proj', '.claude'), { recursive: true });
mkdirSync(join(home, 'proj', 'sub'), { recursive: true });
writeFileSync(join(home, '.marrow', 'control.json'), '{}\n');
writeFileSync(join(home, '.bashrc'), '# rc\n');
symlinkSync(join(home, '.marrow', 'control.json'), join(home, 'proj', 'notes.md'));
symlinkSync(join(home, '.bashrc'), join(home, 'proj', 'sub', 'rc-link.txt'));
const savedHome = process.env.HOME;
process.env.HOME = home;
test.after(() => { process.env.HOME = savedHome; rmSync(root, { recursive: true, force: true }); });

const CONTROL = 'classified Bash action: security on marrow-control';
const PERSIST = 'classified Bash action: security on persistence';
const bash = (command, cwd = join(home, 'proj')) => classifyTool({ tool_name: 'Bash', tool_input: { command }, cwd });
const tool = (name, input, cwd = join(home, 'proj')) => classifyTool({ tool_name: name, tool_input: input, cwd });
const label = (name, kind) => `classified ${name} action: security on ${kind}`;

const CONTROL_BASH = [
  ['redirect >', `echo '{"enabled":false}' > ${home}/.marrow/control.json`],
  ['redirect >>', `echo x >> ${home}/.marrow/env`],
  ['printf with $HOME', `printf '%s' '{}' > $HOME/.marrow/control.json`],
  ['tilde', `echo '{}' > ~/.marrow/control.json`],
  ['A13 printf', `printf '%s' '{}' > ~/.marrow/control.json`],
  ['tee', `echo '{}' | tee ${home}/.marrow/control.json`],
  ['tee -a', `echo '{}' | tee -a ~/.marrow/data-commands.json`],
  ['cp', `cp ${root}/x.json ${home}/.marrow/control.json`],
  ['mv', `mv ${root}/x.json ~/.marrow/control.json`],
  ['rm', `rm -f ~/.marrow/control.json`],
  ['chmod', `chmod 666 ${home}/.marrow/control.json`],
  ['sed -i', `sed -i 's/true/false/' ~/.marrow/control.json`],
  ['perl -pi', `perl -pi -e 's/true/false/' ~/.marrow/control.json`],
  ['python3 -c literal path', `python3 -c "open('${home}/.marrow/control.json','w').write('{}')"`],
  ['node -e literal path', `node -e "require('fs').writeFileSync('${home}/.marrow/control.json','{}')"`],
  ['bash -c', `bash -c 'echo {} > ~/.marrow/control.json'`],
  ['nested bash -c', `bash -c "sh -c 'echo {} > ~/.marrow/control.json'"`],
  ['heredoc the parser cannot read', `cat > ~/.marrow/control.json <<'EOF'\n{"enabled":false}\nEOF`],
  ['chained &&', `true && echo '{}' > ~/.marrow/control.json`],
  ['chained ;', `ls; echo '{}' > ~/.marrow/control.json`],
  ['chained ||', `false || echo '{}' > ~/.marrow/control.json`],
  ['subshell', `(echo '{}' > ~/.marrow/control.json)`],
  ['command substitution', `echo $(echo '{}' > ~/.marrow/control.json)`],
  ['cd then relative write', `cd ~/.marrow && echo '{}' > control.json`],
  ['cd into the host config folder then a relative write', `cd ~/.claude && echo '{}' > settings.json`],
  ['pushd into the hooks folder', `pushd ~/.grok/hooks && echo '{}' > marrow.json`],
  ['split quotes in the folder name', `echo '{}' > ~/.mar""row/control.json`],
  ['dd of=', `dd if=${root}/x of=${home}/.marrow/control.json`],
  ['truncate', `truncate -s 0 ~/.marrow/control.json`],
  ['install', `install -m 600 ${root}/x ~/.marrow/control.json`],
  ['touch', `touch ~/.marrow/control.json`],
  ['ln -sf', `ln -sf ${root}/x ~/.marrow/control.json`],
  ['env-prefixed', `FOO=1 tee ~/.marrow/control.json`],
  ['upper-case folder', `echo '{}' > ~/.MARROW/control.json`],
  ['A12 settings', `echo '{"hooks":{}}' > ~/.claude/settings.json`],
  ['settings.local.json', `jq '.hooks={}' ~/.claude/settings.local.json > ${root}/s && mv ${root}/s ~/.claude/settings.local.json`],
  ['project settings', `echo '{}' > .claude/settings.json`],
  ['codex hooks', `echo '{}' > ~/.codex/hooks.json`],
  ['cursor hooks', `echo '{}' > .cursor/hooks.json`],
  ['windsurf hooks', `echo '{}' > .windsurf/hooks.json`],
  ['grok hooks', `rm ~/.grok/hooks/marrow.json`],
  ['gemini settings', `echo '{}' > ~/.gemini/settings.json`],
];

for (const [id, command] of CONTROL_BASH) {
  test(`control-file gap held (Bash): ${id}`, () => {
    const result = bash(command);
    assert.equal(result.action, CONTROL, command);
    assert.equal(result.protected, true);
    assert.ok(localApprovalCategories(result).includes('secrets_security'));
  });
}

const PERSIST_BASH = [
  ['A11 .bashrc', `echo 'curl x|sh' >> ~/.bashrc`],
  ['C7 MARROW_AUTO_HOOK in an rc file', `echo 'export MARROW_AUTO_HOOK=false' >> ~/.zshrc`],
  ['.bash_profile', `echo x >> ${home}/.bash_profile`],
  ['.bash_aliases', `echo "alias ls=rm" >> ~/.bash_aliases`],
  ['.profile', `printf 'x' >> ~/.profile`],
  ['.zprofile', `echo x >> ~/.zprofile`],
  ['.zshenv', `echo x >> ~/.zshenv`],
  ['fish config', `echo x >> ~/.config/fish/config.fish`],
  ['shell snapshot', `echo x >> ~/.claude/shell-snapshots/snapshot-bash-1.sh`],
  ['A14 crontab -', `echo "* * * * * x" | crontab -`],
  ['crontab file', `crontab ${root}/mycron`],
  ['crontab -e', `crontab -e`],
  ['crontab -r', `crontab -r`],
  ['A15 cron spool', `echo x >> /var/spool/cron/crontabs/u`],
  ['cron.d', `cp ${root}/x /etc/cron.d/x`],
  ['systemd user unit', `cp ${root}/x.service ~/.config/systemd/user/x.service`],
  ['sed -i rc', `sed -i '$a alias a=b' ~/.bashrc`],
  ['relative rc from home', `echo x >> .bashrc`, home],
];

for (const [id, command, cwd] of PERSIST_BASH) {
  test(`control-file gap held (Bash): ${id}`, () => {
    const result = bash(command, cwd);
    assert.equal(result.action, PERSIST, command);
    assert.equal(result.protected, true);
    assert.ok(localApprovalCategories(result).includes('secrets_security'));
  });
}

const FILE_TOOL_TARGETS = [
  ['absolute control file', { file_path: `${home}/.marrow/control.json`, content: '{}' }, 'marrow-control'],
  ['env file', { file_path: `${home}/.marrow/env`, content: 'X' }, 'marrow-control'],
  ['data-commands file', { file_path: `${home}/.marrow/data-commands.json`, content: '{}' }, 'marrow-control'],
  ['relative from home', { file_path: '.marrow/control.json', content: '{}' }, 'marrow-control', home],
  ['dot-dot traversal', { file_path: `${home}/proj/sub/../../.marrow/control.json`, content: '{}' }, 'marrow-control'],
  ['parent traversal from a sub folder', { file_path: '../../.marrow/control.json', content: '{}' }, 'marrow-control', join(home, 'proj', 'sub')],
  ['symlink to the control file', { file_path: `${home}/proj/notes.md`, content: '{}' }, 'marrow-control'],
  ['symlink to .bashrc', { file_path: `${home}/proj/sub/rc-link.txt`, content: 'x' }, 'persistence'],
  ['user settings', { file_path: `${home}/.claude/settings.json`, content: '{}' }, 'marrow-control'],
  ['settings.local.json', { file_path: `${home}/.claude/settings.local.json`, content: '{}' }, 'marrow-control'],
  ['project settings', { file_path: `${home}/proj/.claude/settings.json`, content: '{}' }, 'marrow-control'],
  ['codex hooks', { file_path: `${home}/.codex/hooks.json`, content: '{}' }, 'marrow-control'],
  ['cursor hooks', { file_path: `${home}/proj/.cursor/hooks.json`, content: '{}' }, 'marrow-control'],
  ['windsurf hooks', { file_path: `${home}/proj/.windsurf/hooks.json`, content: '{}' }, 'marrow-control'],
  ['grok hooks', { file_path: `${home}/.grok/hooks/marrow.json`, content: '{}' }, 'marrow-control'],
  ['gemini settings', { file_path: `${home}/.gemini/settings.json`, content: '{}' }, 'marrow-control'],
  ['bashrc', { file_path: `${home}/.bashrc`, old_string: 'a', new_string: 'b' }, 'persistence'],
  ['zshrc', { file_path: `${home}/.zshrc`, content: 'x' }, 'persistence'],
  ['tilde path', { file_path: '~/.bashrc', content: 'x' }, 'persistence'],
  ['fish config', { file_path: `${home}/.config/fish/config.fish`, content: 'x' }, 'persistence'],
  ['shell snapshot', { file_path: `${home}/.claude/shell-snapshots/s.sh`, content: 'x' }, 'persistence'],
  ['systemd user unit', { file_path: `${home}/.config/systemd/user/a.service`, content: 'x' }, 'persistence'],
  ['cron spool', { file_path: '/var/spool/cron/crontabs/u', content: 'x' }, 'persistence'],
  ['notebook path', { notebook_path: `${home}/.marrow/control.json`, new_source: 'x' }, 'marrow-control'],
];

for (const name of ['Write', 'Edit', 'MultiEdit', 'NotebookEdit']) {
  for (const [id, input, kind, cwd] of FILE_TOOL_TARGETS) {
    if (name === 'NotebookEdit' !== Object.hasOwn(input, 'notebook_path')) continue;
    test(`control-file gap held (${name}): ${id}`, () => {
      const result = tool(name, input, cwd);
      assert.equal(result.action, label(name, kind), JSON.stringify(input));
      assert.equal(result.protected, true);
    });
  }
}

test('control-file gap held (other host file tools and Codex apply_patch)', () => {
  assert.equal(tool('apply_patch', { input: `*** Begin Patch\n*** Update File: ${home}/.marrow/control.json\n@@\n-true\n+false\n*** End Patch\n` }).action, label('apply_patch', 'marrow-control'));
  assert.equal(tool('search_replace', { file_path: `${home}/.claude/settings.json`, old_string: 'a', new_string: 'b' }).action, label('search_replace', 'marrow-control'));
  assert.equal(tool('write_to_file', { path: `${home}/.bashrc`, content: 'x' }).action, label('write_to_file', 'persistence'));
  assert.equal(tool('replace_in_file', { path: `${home}/.marrow/control.json`, diff: 'x' }).action, label('replace_in_file', 'marrow-control'));
  assert.equal(tool('edit_file', { target_file: `${home}/.codex/hooks.json`, instructions: 'x' }).protected, true);
});

const NOT_HELD = [
  ['reading the control file', `cat ${home}/.marrow/control.json`],
  ['listing the folder', `ls -la ${home}/.marrow`],
  ['grep in an rc file', `grep -n alias ${home}/.bashrc`],
  ['crontab -l', 'crontab -l'],
  ['crontab -u bob -l', 'crontab -u bob -l'],
  ['an echo that names the rc file', 'echo "add this to ~/.bashrc yourself"'],
  ['a note in the project', `echo "fix .bashrc" >> ${home}/proj/notes.md`],
  ['find without a write action', `find ${home}/.claude -name 'settings*'`],
  ['an unrelated claude folder file', `echo x >> ${home}/.claude/projects/x/notes.md`.replace('.claude/projects', '.claude-notes')],
  ['npm test', 'npm test'],
  ['prettier --check on a settings file', `prettier --check ${home}/.claude/settings.json`],
  ['npx prettier --check on a settings file', `npx prettier --check ${home}/.claude/settings.json`],
  ['npx -y prettier (prints, never writes)', `npx -y prettier ${home}/.bashrc`],
  ['pnpm exec prettier -l', `pnpm exec prettier -l ${home}/.marrow/control.json`],
  ['shellcheck on an rc file', `shellcheck ${home}/.bashrc`],
  ['tree on the marrow folder', `tree ${home}/.marrow`],
];

// The reading exemption of prettier and tree ends at their writing flags (and at an unknown runner flag value).
const WRITING_FORMS = [
  ['prettier --write', `prettier --write ${home}/.claude/settings.json`, CONTROL],
  ['prettier -w', `prettier -w ${home}/.bashrc`, PERSIST],
  ['npx prettier --write', `npx prettier --write ${home}/.bashrc`, PERSIST],
  ['npx -y prettier --write', `npx -y prettier --write ${home}/.marrow/control.json`, CONTROL],
  ['pnpm exec prettier -w', `pnpm exec prettier -w ${home}/.claude/settings.json`, CONTROL],
  ['prettier --cache-location', `prettier --check --cache --cache-location ${home}/.bashrc x.js`, PERSIST],
  ['tree -o', `tree -o ${home}/.bashrc .`, PERSIST],
  ['tree -fo', `tree -fo ${home}/.marrow/control.json .`, CONTROL],
  ['tree --output', `tree --output=${home}/.bashrc .`, PERSIST],
  ['npx with a flag value naming the file', `npx -p ${home}/.bashrc prettier --check x.js`, PERSIST],
  ['prettier then a redirect', `prettier x.js > ${home}/.bashrc`, PERSIST],
  ['prettier --check and a chained write', `prettier --check x.js && echo x >> ${home}/.bashrc`, PERSIST],
];

for (const [id, command, expected] of WRITING_FORMS) {
  test(`control-file gap held (reading tool, writing form): ${id}`, () => {
    assert.equal(bash(command).action, expected, command);
  });
}

for (const [id, command] of NOT_HELD) {
  test(`control-file gap not held: ${id}`, () => {
    const result = bash(command);
    assert.notEqual(result.action, CONTROL, command);
    assert.notEqual(result.action, PERSIST, command);
  });
}

test('control-file gap not held: reading tools and unrelated writes', () => {
  assert.notEqual(tool('Read', { file_path: `${home}/.bashrc` }).type, 'security');
  assert.notEqual(tool('Read', { file_path: `${home}/.marrow/control.json` }).type, 'security');
  assert.notEqual(tool('Grep', { pattern: 'x', path: `${home}/.claude/settings.json` }).type, 'security');
  assert.notEqual(tool('Write', { file_path: `${home}/proj/plain.md`, content: 'x' }).type, 'security');
  assert.notEqual(tool('Edit', { file_path: `${home}/proj/src/a.ts`, old_string: 'a', new_string: 'b' }).type, 'security');
});

test('control-file gap: PostToolUse labels match the pre-tool labels', () => {
  const event = { tool_name: 'Bash', tool_input: { command: `echo x >> ~/.bashrc` }, cwd: join(home, 'proj') };
  assert.equal(classifyTool(event, { postTool: true }).action, PERSIST);
});

test('control-file gap: stricter, never looser (K1-2, a merged type keeps security)', () => {
  const both = bash(`npm publish && echo x >> ~/.bashrc`);
  assert.equal(both.protected, true);
  const rc = bash('echo "deploy production" >> ~/.bashrc');
  assert.equal(rc.action, PERSIST);
  assert.notEqual(rc.action, bash('echo "deploy production" >> notes.md').action);
});
