'use strict';

// RC-1 (3.9.106, AUDIT-STAGE1 RC-1, RULINGS-STAGE1 ruling 1): the Windows S0/S4 stops, as PORTS of the POSIX S0/S4
// rows that already exist in this repo's tests. Each Windows row names its source row (`port of <file>:<line>`).
// A Windows variant changes only the PATH FORM of the source row: drive letter, backslashes, mixed separators,
// upper case, UNC, an 8.3 short profile name, and the `\\?\` prefix. Verb rows use only the forms written in
// AUDIT-STAGE1 section 1 (RC-1 a/b/d, L-1..L-4, AB44..AB51). Commands are only EVALUATED by the mapper; nothing runs.
// The platform is a parameter (env.platform), never read from process.env. No secret value is used anywhere.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { evaluateSeatbelt } = require('../dist/seatbelt/mapper.js');
const { seatbeltStopText } = require('../dist/seatbelt/hook.js');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');
const canonical = require('./fixtures/seatbelt/canonical.cjs');

const CODE = /^[A-Za-z0-9_.:-]{1,64}$/; // seatbelt/hook.ts CODE
// Absolute caps for the step-count row (M-4). Measured on this tree: a 60 KB hostile text takes 329 scan ticks and 1.74 million matcher
// cells, a 64 KB padded line at most 7286 ticks and 118 thousand cells. Any scanner that takes one tick per word and statement stays under
// one tick per two bytes (34000 for 64 KB); the node cap that a quadratic one runs into is 200000.
const SCAN_ABSOLUTE_MAX = 34000;
const CELLS_ABSOLUTE_MAX = 3000000;
const CELLS_PER_BYTE_MAX = 10;
const WIN_CODES = new Set(['windows_protected_path', 'windows_persistence', 'windows_shim_write', 'windows_secret_path', 'windows_env_dump', 'windows_secret_store']);

// The env the win32 hook builds (seatbelt/hook.ts mapperEnv): no POSIX home, cwd null for a Windows cwd.
function winEnv() {
  const env = makeEnv({ cwd: null, platform: 'win32' });
  env.home = '/nonexistent-home';
  return env;
}
const linuxEnv = () => makeEnv({});
const bash = (command) => ({ tool_name: 'Bash', tool_input: { command } });
const tool = (tool_name, tool_input) => ({ tool_name, tool_input });
const canonRow = (id) => {
  const r = canonical.rows.find((x) => x.id === id);
  assert.ok(r, `canonical row ${id}`);
  return r;
};
const canonInput = (id) => { const r = canonRow(id); return r.event || bash(r.cmd); };
const canonByCmd = (cmd) => {
  const r = canonical.rows.find((x) => x.cmd === cmd);
  assert.ok(r, `canonical row for ${cmd}`);
  return r;
};

// ---- path forms (the only change a ported row may make)
const bs = (t) => t.replace(/\//g, '\\');
const mix = (t) => t.split('/').map((c, i) => (i % 2 ? `/${c}` : `\\${c}`)).join('').slice(1);
/** A home path `~/<t>` in its Windows forms. */
function homeForms(t) {
  return {
    drive: `C:\\Users\\x\\${bs(t)}`,
    mixed: `C:/Users\\x/${mix(t)}`,
    upper: `C:\\USERS\\X\\${bs(t).toUpperCase()}`,
    unc: `\\\\server\\share\\Users\\x\\${bs(t)}`,
    short: `C:\\Users\\RUNNER~1\\${bs(t)}`,
    device: `\\\\?\\C:\\Users\\x\\${bs(t)}`,
  };
}
/** A workspace path `<ws>/<t>` (or a relative `<t>`) in its Windows forms. */
function wsForms(t) {
  return {
    relative: bs(t),
    drive: `C:\\Users\\x\\proj\\${bs(t)}`,
    mixed: `C:/Users\\x/proj\\${mix(t)}`,
    upper: `C:\\USERS\\X\\PROJ\\${bs(t).toUpperCase()}`,
    unc: `\\\\server\\share\\proj\\${bs(t)}`,
    short: `C:\\Users\\RUNNER~1\\proj\\${bs(t)}`,
    device: `\\\\?\\C:\\Users\\x\\proj\\${bs(t)}`,
  };
}
/** Shell text also has the `~\` form (AUDIT-STAGE1 L-4a: `gc ~\.ssh\id_rsa`). */
const shellHomeForms = (t) => ({ ...homeForms(t), tilde: `~\\${bs(t)}` });

// ---- the rows
// kind 'stop': every Windows form stops on win32 with a hit of `cat`.
// kind 'parity': a POSIX out-of-scope (pass) row; its Windows forms get no Windows hit.
// `posix`: the source input, re-run on linux and pinned to 3.9.105 (PIN below).
const ROWS = [];
function port(id, src, cat, posix, forms, make, kind = 'stop') {
  for (const [form, p] of Object.entries(forms)) ROWS.push({ id: `${id}/${form}`, base: id, src, cat, posix, input: make(p), kind });
}
function verb(id, src, cat, posix, inputs) {
  inputs.forEach((input, i) => ROWS.push({ id: `${id}/${i}`, base: id, src, cat, posix, input, kind: 'stop' }));
}

// S0, hook configs (L-1a, AB44)
// port of test/fixtures/seatbelt/canonical.cjs:126 (s0-edit-hooks-off)
port('s0-edit-hooks-off', 'test/fixtures/seatbelt/canonical.cjs:126 s0-edit-hooks-off', 'S0', canonInput('s0-edit-hooks-off'), wsForms('.claude/settings.json'),
  (p) => tool('Edit', { file_path: p, old_string: 'marrow-mcp claude-pre-action-hook', new_string: 'true' }));
// port of test/fixtures/seatbelt/canonical.cjs:127 (s0-write-hooks-empty)
port('s0-write-hooks-empty', 'test/fixtures/seatbelt/canonical.cjs:127 s0-write-hooks-empty', 'S0', canonInput('s0-write-hooks-empty'), wsForms('.claude/settings.json'),
  (p) => tool('Write', { file_path: p, content: '{}' }));
// port of test/fixtures/seatbelt/canonical.cjs:128 (s0-edit-disable-all)
port('s0-edit-disable-all', 'test/fixtures/seatbelt/canonical.cjs:128 s0-edit-disable-all', 'S0', canonInput('s0-edit-disable-all'), homeForms('.claude/settings.json'),
  (p) => tool('Edit', { file_path: p, old_string: '"permissions": {', new_string: '"disableAllHooks": true, "permissions": {' }));
// port of test/fixtures/seatbelt/adversarial.cjs:213 (self-write-node-options)
port('self-write-node-options', 'test/fixtures/seatbelt/adversarial.cjs:213 self-write-node-options', 'S0',
  tool('Edit', { file_path: '/home/u/proj/.claude/settings.json', old_string: '"permissions": {', new_string: '"env": {"NODE_OPTIONS": "--require /tmp/x.js"}, "permissions": {' }),
  wsForms('.claude/settings.json'),
  (p) => tool('Edit', { file_path: p, old_string: '"permissions": {', new_string: '"env": {"NODE_OPTIONS": "--require /tmp/x.js"}, "permissions": {' }));
// port of test/fixtures/seatbelt/canonical.cjs:118 (s0-0: echo '{}' > .claude/settings.json)
port('s0-0', 'test/fixtures/seatbelt/canonical.cjs:118 s0-0', 'S0', canonInput('s0-0'), wsForms('.claude/settings.json'), (p) => bash(`echo '{}' > ${p}`));
// port of test/fixtures/seatbelt/canonical.cjs:118 (s0-1: echo x >> ~/.claude/settings.json)
port('s0-1', 'test/fixtures/seatbelt/canonical.cjs:118 s0-1', 'S0', canonInput('s0-1'), shellHomeForms('.claude/settings.json'), (p) => bash(`echo x >> ${p}`));
// port of test/fixtures/seatbelt/canonical.cjs:120 (s0-9: tee .codex/hooks.json < /dev/null)
port('s0-9', 'test/fixtures/seatbelt/canonical.cjs:120 s0-9', 'S0', canonInput('s0-9'), wsForms('.codex/hooks.json'), (p) => bash(`tee ${p} < /dev/null`));
// port of test/fixtures/seatbelt/canonical.cjs:120 (s0-10: mv .claude/settings.json /tmp/s.json)
port('s0-10', 'test/fixtures/seatbelt/canonical.cjs:120 s0-10', 'S0', canonInput('s0-10'), wsForms('.claude/settings.json'), (p) => bash(`mv ${p} /tmp/s.json`));
// port of test/fixtures/seatbelt/canonical.cjs:120 (s0-11: cp /tmp/x.json ~/.codex/hooks.json)
port('s0-11', 'test/fixtures/seatbelt/canonical.cjs:120 s0-11', 'S0', canonInput('s0-11'), shellHomeForms('.codex/hooks.json'), (p) => bash(`cp /tmp/x.json ${p}`));
// port of test/fixtures/seatbelt/canonical.cjs:123 (s0-24: echo {} > .mcp.json)
port('s0-24', 'test/fixtures/seatbelt/canonical.cjs:123 s0-24', 'S0', canonInput('s0-24'), wsForms('.mcp.json'), (p) => bash(`echo {} > ${p}`));
// port of test/fixtures/seatbelt/adversarial.cjs:203 (self-truncate: truncate -s 0 .cursor/hooks.json)
port('self-truncate', 'test/fixtures/seatbelt/adversarial.cjs:203 self-truncate', 'S0', bash('truncate -s 0 .cursor/hooks.json'), wsForms('.cursor/hooks.json'),
  (p) => bash(`truncate -s 0 ${p}`));
// AUDIT-STAGE1 AB44 / L-1a: Edit `~\.cursor\hooks.json`, `.gemini\settings.json` (no POSIX tool row for these files;
// the POSIX twin is the Edit of .claude/settings.json above, canonical.cjs:126).
port('ab44-cursor-hooks', 'AUDIT-STAGE1 AB44 (POSIX twin canonical.cjs:126)', 'S0', null, homeForms('.cursor/hooks.json'),
  (p) => tool('Edit', { file_path: p, old_string: 'marrow-mcp cursor-pre-action-hook', new_string: 'true' }));
port('l1a-gemini-settings', 'AUDIT-STAGE1 L-1a (POSIX twin canonical.cjs:126)', 'S0', null, homeForms('.gemini/settings.json'),
  (p) => tool('Edit', { file_path: p, old_string: 'marrow-mcp', new_string: 'true' }));

// S0, Marrow's own files and code copies (L-1b, AB45, AB61)
// port of test/fixtures/seatbelt/canonical.cjs:130 (s0-write-control)
port('s0-write-control', 'test/fixtures/seatbelt/canonical.cjs:130 s0-write-control', 'S0', canonInput('s0-write-control'), homeForms('.marrow/control.json'),
  (p) => tool('Write', { file_path: p, content: '{"enabled":false}' }));
// port of test/fixtures/seatbelt/canonical.cjs:119 (s0-4: rm -rf ~/.marrow)
port('s0-4', 'test/fixtures/seatbelt/canonical.cjs:119 s0-4', 'S0', canonInput('s0-4'), shellHomeForms('.marrow'), (p) => bash(`rm -rf ${p}`));
// port of test/fixtures/seatbelt/canonical.cjs:119 (s0-5: rm ~/.marrow/control.json)
port('s0-5', 'test/fixtures/seatbelt/canonical.cjs:119 s0-5', 'S0', canonInput('s0-5'), shellHomeForms('.marrow/control.json'), (p) => bash(`rm ${p}`));
// port of test/fixtures/seatbelt/canonical.cjs:120 (s0-12: chmod 000 ~/.marrow)
port('s0-12', 'test/fixtures/seatbelt/canonical.cjs:120 s0-12', 'S0', canonInput('s0-12'), shellHomeForms('.marrow'), (p) => bash(`chmod 000 ${p}`));
// AUDIT-STAGE1 AB61: rewrite `~\.marrow\cursor-plugin\...\dist\seatbelt\mapper.js` (POSIX twin canonical.cjs:130, `.marrow/**`).
port('ab61-cursor-plugin-copy', 'AUDIT-STAGE1 AB61 (POSIX twin canonical.cjs:130)', 'S0', null, homeForms('.marrow/cursor-plugin/dist/seatbelt/mapper.js'),
  (p) => tool('Write', { file_path: p, content: 'module.exports = 0;' }));
// port of test/seatbelt-new1-plugins.test.js:86 ('NEW-1 mapper: tool writes and deletes of the Marrow plugin files stop')
const NEW1 = 'test/seatbelt-new1-plugins.test.js:86 NEW-1 mapper tool writes';
for (const t of ['.claude/plugins/installed_plugins.json', '.claude/plugins/cache/getmarrow/marrow/1.2.3/hooks/hooks.json', '.cursor/plugins/marrow/hooks.json']) {
  const posixPath = `/home/u/${t}`;
  port(`new1-write-${t}`, NEW1, 'S0', tool('Write', { file_path: posixPath, content: '{}' }), homeForms(t), (p) => tool('Write', { file_path: p, content: '{}' }));
  port(`new1-edit-${t}`, NEW1, 'S0', tool('Edit', { file_path: posixPath, old_string: 'a', new_string: 'b' }), homeForms(t), (p) => tool('Edit', { file_path: p, old_string: 'a', new_string: 'b' }));
  port(`new1-delete-${t}`, NEW1, 'S0', tool('delete_file', { file_path: posixPath }), homeForms(t), (p) => tool('delete_file', { file_path: p }));
}
// port of test/seatbelt-new1-plugins.test.js:94 (the npx cache copy), in the Windows npm cache place of AUDIT-STAGE1 AB45
// (`%LOCALAPPDATA%\npm-cache\_npx\*\node_modules\@getmarrow\mcp\dist\*.js`).
const NPX = 'AppData/Local/npm-cache/_npx/0123abcd/node_modules/@getmarrow/mcp/dist/cli.js';
port('ab45-npx-write', `${NEW1} + AUDIT-STAGE1 AB45`, 'S0', tool('Write', { file_path: '/home/u/.npm/_npx/0123abcd/node_modules/@getmarrow/mcp/dist/cli.js', content: '{}' }),
  { ...homeForms(NPX), localappdata: '%LOCALAPPDATA%\\npm-cache\\_npx\\0123abcd\\node_modules\\@getmarrow\\mcp\\dist\\cli.js' },
  (p) => tool('Write', { file_path: p, content: '{}' }));
// port of test/seatbelt-new1-plugins.test.js:107 and :122 (shell writes of the plugin and npx copies)
port('new1-shell-plugin', 'test/seatbelt-new1-plugins.test.js:107', 'S0', bash("echo '{}' > ~/.claude/plugins/cache/getmarrow/marrow/1.2.3/hooks/hooks.json"),
  shellHomeForms('.claude/plugins/cache/getmarrow/marrow/1.2.3/hooks/hooks.json'), (p) => bash(`echo '{}' > ${p}`));
port('new1-shell-npx', 'test/seatbelt-new1-plugins.test.js:122 + AUDIT-STAGE1 AB45', 'S0',
  bash("echo 'module.exports=0' > ~/.npm/_npx/0123abcd/node_modules/@getmarrow/mcp/dist/cli.js"), shellHomeForms(NPX), (p) => bash(`echo 'module.exports=0' > ${p}`));
// port of test/seatbelt-new1-plugins.test.js:111 (rm -rf ~/.claude/plugins/cache/getmarrow)
port('new1-rm-plugin', 'test/seatbelt-new1-plugins.test.js:111', 'S0', bash('rm -rf ~/.claude/plugins/cache/getmarrow'),
  shellHomeForms('.claude/plugins/cache/getmarrow'), (p) => bash(`rm -rf ${p}`));

// S0, git hooks and config, PATH folders (L-1c, AB46)
// port of test/fixtures/seatbelt/canonical.cjs:123 (s0-23: echo x > .git/hooks/pre-commit)
port('s0-23', 'test/fixtures/seatbelt/canonical.cjs:123 s0-23', 'S0', canonInput('s0-23'), wsForms('.git/hooks/pre-commit'), (p) => bash(`echo x > ${p}`));
// AUDIT-STAGE1 AB46: write `.git\hooks\pre-commit`, `.git\config`, `~\.gitconfig` (no POSIX test row for the last two).
port('ab46-git-hooks', 'AUDIT-STAGE1 AB46', 'S0', null, wsForms('.git/hooks/pre-commit'), (p) => tool('Write', { file_path: p, content: 'exit 0' }));
port('ab46-git-config', 'AUDIT-STAGE1 AB46', 'S0', null, wsForms('.git/config'), (p) => tool('Write', { file_path: p, content: '[core]' }));
port('ab46-gitconfig', 'AUDIT-STAGE1 AB46', 'S0', null, homeForms('.gitconfig'), (p) => tool('Write', { file_path: p, content: '[core]' }));
// AUDIT-STAGE1 L-1c: `node_modules\.bin\*` (no POSIX test row).
port('l1c-node-bin', 'AUDIT-STAGE1 L-1c', 'S0', null, wsForms('node_modules/.bin/jest'), (p) => tool('Write', { file_path: p, content: 'exit 0' }));
// port of test/fixtures/seatbelt/canonical.cjs:123 (s0-20: echo x > ~/.local/bin/git)
port('s0-20', 'test/fixtures/seatbelt/canonical.cjs:123 s0-20', 'S0', canonInput('s0-20'), shellHomeForms('.local/bin/git'), (p) => bash(`echo x > ${p}`));

// S0, program shims (RC-1d, L-3, AB49); POSIX analog: canonical.cjs:123 s0-20 (a program planted on PATH)
verb('rc1d-shim-shell', 'AUDIT-STAGE1 RC-1d / AB49 (POSIX analog canonical.cjs:123 s0-20)', 'S0', canonInput('s0-20'),
  ['node.cmd', 'node.bat', 'npx.cmd'].map((n) => bash(`echo x > ${n}`)));
verb('rc1d-shim-tool', 'AUDIT-STAGE1 RC-1d / AB49 (POSIX analog canonical.cjs:123 s0-20)', 'S0', null,
  ['node.cmd', 'node.bat', 'npx.cmd'].flatMap((n) => [tool('Write', { file_path: n, content: '@echo off' }), tool('Write', { file_path: `C:\\Users\\x\\proj\\${n}`, content: '@echo off' })]));

// S0, persistence and environment poisoning (L-2, AB47, AB48)
// port of test/fixtures/seatbelt/canonical.cjs:129 (s0-write-bashrc) and :119 (s0-6), as the PowerShell `$PROFILE`.
port('s0-write-bashrc', 'test/fixtures/seatbelt/canonical.cjs:129 s0-write-bashrc', 'S0', canonInput('s0-write-bashrc'), homeForms('.bashrc'),
  (p) => tool('Write', { file_path: p, content: 'alias git=true' }));
port('s0-6', 'test/fixtures/seatbelt/canonical.cjs:119 s0-6', 'S0', canonInput('s0-6'), shellHomeForms('.bashrc'), (p) => bash(`echo 'alias git=true' >> ${p}`));
verb('l2-profile', 'AUDIT-STAGE1 L-2 / AB48 `$PROFILE` write (POSIX analog canonical.cjs:119 s0-6)', 'S0', canonInput('s0-6'),
  [bash("echo 'alias git=true' >> $PROFILE")]);
port('l2-profile-path', 'AUDIT-STAGE1 L-2 / RC-1a (POSIX analog canonical.cjs:129 s0-write-bashrc)', 'S0', canonInput('s0-write-bashrc'),
  homeForms('Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1'), (p) => tool('Write', { file_path: p, content: 'alias git=true' }));
// port of test/fixtures/seatbelt/canonical.cjs:124 (s0-25: echo x > ~/.config/systemd/user/m.service), as the Startup folder.
port('s0-25', 'test/fixtures/seatbelt/canonical.cjs:124 s0-25', 'S0', canonInput('s0-25'), shellHomeForms('.config/systemd/user/m.service'), (p) => bash(`echo x > ${p}`));
port('l2-startup', 'AUDIT-STAGE1 L-2 / AB48 Startup folder (POSIX analog canonical.cjs:124 s0-25)', 'S0', canonInput('s0-25'),
  homeForms('AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/m.cmd'), (p) => tool('Write', { file_path: p, content: 'x' }));
verb('l2-startup-shell', 'AUDIT-STAGE1 L-2 / AB48 Startup folder (POSIX analog canonical.cjs:124 s0-25)', 'S0', canonInput('s0-25'),
  Object.values(homeForms('AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/m.cmd')).map((p) => bash(`echo x > "${p}"`)));
verb('l2-run-tasks', 'AUDIT-STAGE1 L-2 / AB48 Run key, schtasks, Register-ScheduledTask, AutoRun (POSIX analog canonical.cjs:124 s0-25)', 'S0', canonInput('s0-25'), [
  bash('reg add HKCU\\...\\Run'), bash('schtasks /create'), bash('Register-ScheduledTask'), bash('reg add HKCU\\...\\Command Processor\\AutoRun'),
]);
verb('l2-env-poison', 'AUDIT-STAGE1 L-2 / AB47 (POSIX analog adversarial.cjs:213 self-write-node-options)', 'S0',
  tool('Edit', { file_path: '/home/u/proj/.claude/settings.json', old_string: '"permissions": {', new_string: '"env": {"NODE_OPTIONS": "--require /tmp/x.js"}, "permissions": {' }), [
    bash('setx NODE_OPTIONS ...'), bash("[Environment]::SetEnvironmentVariable('NODE_OPTIONS',...,'User')"), bash("[Environment]::SetEnvironmentVariable(...,'User')"),
    bash('reg add HKCU\\Environment'),
  ]);

// S4, secret files (L-4a, AB50)
// port of test/fixtures/seatbelt/canonical.cjs:77-87 (secretPaths x readers: s4-path-<i>-0 `cat`, s4-path-<i>-2 `cp ... /tmp/x`; s4-read-tool-<i>)
const SECRET_PATHS = ['~/.ssh/id_rsa', '~/.ssh/id_ed25519', '~/.ssh/id_ecdsa', '~/.ssh/deploy_key', '~/.aws/credentials', '~/.aws/sso/cache/abc.json',
  '~/.config/gcloud/application_default_credentials.json', '~/.config/gcloud/access_tokens.db', '~/.azure/accessTokens.json', '~/.kube/config',
  '~/.docker/config.json', '~/.npmrc', '~/.pypirc', '~/.netrc', '~/.git-credentials', '~/.config/gh/hosts.yml', '~/.config/op/config',
  '~/.gnupg/private-keys-v1.d/abc.key', '~/.marrow/env', '~/.marrow/env.local', '~/.claude.json', '.claude/settings.local.json',
  '.env', '.env.local', '.env.production', 'app/.env', 'certs/server.pem', 'tls.key', 'cert.p12', 'cert.pfx'];
SECRET_PATHS.forEach((sp) => {
  const i = canonical.rows.findIndex((r) => r.id.startsWith('s4-path-') && r.id.endsWith('-0') && r.cmd === `cat ${sp}`);
  assert.ok(i >= 0, sp);
  const idx = canonical.rows[i].id.split('-')[2];
  const home = sp.startsWith('~/');
  const t = home ? sp.slice(2) : sp;
  const shellForms = home ? shellHomeForms(t) : wsForms(t);
  const toolForms = home ? homeForms(t) : wsForms(t);
  port(`s4-path-${idx}-0`, `test/fixtures/seatbelt/canonical.cjs:86 s4-path-${idx}-0`, 'S4', canonInput(`s4-path-${idx}-0`), shellForms, (p) => bash(`cat ${p}`));
  port(`s4-path-${idx}-2`, `test/fixtures/seatbelt/canonical.cjs:86 s4-path-${idx}-2`, 'S4', canonInput(`s4-path-${idx}-2`), shellForms, (p) => bash(`cp ${p} /tmp/x`));
  port(`s4-read-tool-${idx}`, `test/fixtures/seatbelt/canonical.cjs:87 s4-read-tool-${idx}`, 'S4', canonInput(`s4-read-tool-${idx}`), toolForms,
    (p) => tool('Read', { file_path: p }));
});
// port of test/fixtures/seatbelt/canonical.cjs:97-99 (s4-grep-env, s4-write-env, s4-mcp-read)
port('s4-grep-env', 'test/fixtures/seatbelt/canonical.cjs:97 s4-grep-env', 'S4', canonInput('s4-grep-env'), wsForms('.env.local'), (p) => tool('Grep', { pattern: 'KEY', path: p }));
port('s4-write-env', 'test/fixtures/seatbelt/canonical.cjs:98 s4-write-env', 'S4', canonInput('s4-write-env'), wsForms('.env.local'), (p) => tool('Write', { file_path: p, content: 'A=1' }));
port('s4-mcp-read', 'test/fixtures/seatbelt/canonical.cjs:99 s4-mcp-read', 'S4', canonInput('s4-mcp-read'), homeForms('.ssh/id_ed25519'),
  (p) => tool('mcp__filesystem__read_file', { path: p }));
// AUDIT-STAGE1 L-4a / AB50 verbatim, paired with canonical.cjs:95 `cat /home/u/.ssh/id_rsa` and `cat $HOME/.aws/credentials`.
verb('l4a-type-aws', 'AUDIT-STAGE1 L-4a / AB50 (POSIX analog canonical.cjs:95 `cat $HOME/.aws/credentials`)', 'S4', bash(canonByCmd('cat $HOME/.aws/credentials').cmd),
  [bash('type C:\\Users\\x\\.aws\\credentials')]);
verb('l4a-ssh', 'AUDIT-STAGE1 L-4a / AB50 (POSIX analog canonical.cjs:95 `cat /home/u/.ssh/id_rsa`)', 'S4', bash(canonByCmd('cat /home/u/.ssh/id_rsa').cmd),
  [bash('gc ~\\.ssh\\id_rsa'), bash('cat ~\\.ssh\\id_rsa')]);

// S4, environment dumps (L-4b, AB51, RC-1b)
verb('l4b-env-dump', 'AUDIT-STAGE1 L-4b / AB51 / RC-1b (POSIX analog canonical.cjs:90 `env`, `printenv`, `set`)', 'S4', bash(canonByCmd('env').cmd), [
  bash('gci env:'), bash('dir env:'), bash('Get-ChildItem Env:'), bash('set'), bash('ls env:'), bash('get-item env:'), bash('get-childitem env:'),
]);
verb('l4b-echo-secret', 'AUDIT-STAGE1 L-4b / AB51 (POSIX analog canonical.cjs:91 `printf "%s" "$AWS_SECRET_ACCESS_KEY"`)', 'S4',
  bash(canonByCmd('printf "%s" "$AWS_SECRET_ACCESS_KEY"').cmd), [bash('echo $env:AWS_SECRET_ACCESS_KEY')]);

// 8.3 short names of the protected component itself (a path form), for the same source rows.
// port of test/fixtures/seatbelt/canonical.cjs:86 (s4-path-0-0 `cat ~/.ssh/id_rsa`, s4-path-4-0 `cat ~/.aws/credentials`)
port('s4-path-0-0-short', 'test/fixtures/seatbelt/canonical.cjs:86 s4-path-0-0', 'S4', canonInput('s4-path-0-0'),
  { ssh: 'C:\\Users\\x\\SSH~1\\id_rsa', both: 'C:\\Users\\x\\SSH~1\\ID_RSA~1' }, (p) => bash(`cat ${p}`));
port('s4-path-4-0-short', 'test/fixtures/seatbelt/canonical.cjs:86 s4-path-4-0', 'S4', canonInput('s4-path-4-0'),
  { aws: 'C:\\Users\\x\\AWS~1\\credentials', both: 'C:\\Users\\x\\AWS~1\\CREDEN~1' }, (p) => bash(`cat ${p}`));
// port of test/fixtures/seatbelt/canonical.cjs:127 (s0-write-hooks-empty) and :130 (s0-write-control)
port('s0-write-hooks-empty-short', 'test/fixtures/seatbelt/canonical.cjs:127 s0-write-hooks-empty', 'S0', canonInput('s0-write-hooks-empty'),
  { file: 'C:\\Users\\x\\proj\\.claude\\SETTIN~1.JSO', both: 'C:\\Users\\x\\proj\\CLAUDE~1\\SETTIN~1.JSO' }, (p) => tool('Write', { file_path: p, content: '{}' }));
port('s0-write-control-short', 'test/fixtures/seatbelt/canonical.cjs:130 s0-write-control', 'S0', canonInput('s0-write-control'),
  { both: 'C:\\Users\\x\\MARROW~1\\CONTRO~1.JSO' }, (p) => tool('Write', { file_path: p, content: '{"enabled":false}' }));

// Parity: POSIX out-of-scope rows; their Windows forms get no Windows hit.
// port of test/fixtures/seatbelt/canonical.cjs:132 (s0-out-cat-settings)
port('s0-out-cat-settings', 'test/fixtures/seatbelt/canonical.cjs:132 s0-out-cat-settings', 'S0', canonInput('s0-out-cat-settings'), wsForms('.claude/settings.json'),
  (p) => bash(`cat ${p}`), 'parity');
// port of test/fixtures/seatbelt/canonical.cjs:100-101 (s4-out-2 cat ~/.ssh/id_ed25519.pub, s4-out-3 cat .env.example, s4-out-8 cat ~/.ssh/known_hosts)
port('s4-out-2', 'test/fixtures/seatbelt/canonical.cjs:100 s4-out-2', 'S4', canonInput('s4-out-2'), shellHomeForms('.ssh/id_ed25519.pub'), (p) => bash(`cat ${p}`), 'parity');
port('s4-out-3', 'test/fixtures/seatbelt/canonical.cjs:100 s4-out-3', 'S4', canonInput('s4-out-3'), wsForms('.env.example'), (p) => bash(`cat ${p}`), 'parity');
port('s4-out-8', 'test/fixtures/seatbelt/canonical.cjs:101 s4-out-8', 'S4', canonInput('s4-out-8'), shellHomeForms('.ssh/known_hosts'), (p) => bash(`cat ${p}`), 'parity');
// port of test/fixtures/seatbelt/canonical.cjs:102 (s4-out-read-example)
port('s4-out-read-example', 'test/fixtures/seatbelt/canonical.cjs:102 s4-out-read-example', 'S4', canonInput('s4-out-read-example'), wsForms('.env.example'),
  (p) => tool('Read', { file_path: p }), 'parity');

const winHits = (d) => d.reasons.filter((r) => WIN_CODES.has(r));

// ---- the 3.9.105 decisions of the POSIX source rows (generated from the 8ffda003 dist mapper; see RESULT.md)
const PIN = require('./fixtures/seatbelt/win-protected-port-pins.json');
const sig = (d) => [d.decision, d.category, d.rule, d.reasons];
const posixSources = () => {
  const out = new Map();
  for (const r of ROWS) if (r.posix) out.set(r.base, r.posix);
  return out;
};

test('RC-1 port: every Windows form of a POSIX S0/S4 stop row stops on win32 with the same category', () => {
  const failed = [];
  for (const r of ROWS.filter((x) => x.kind === 'stop')) {
    const d = evaluateSeatbelt(r.input, winEnv());
    if (!(d.decision === 'stop' && d.hits.some((h) => h.category === r.cat))) failed.push(`${r.id} [${r.src}]: ${d.decision} ${d.rule} ${d.reasons}`);
  }
  assert.deepEqual(failed, []);
  assert.ok(ROWS.filter((x) => x.kind === 'stop').length >= 400, `${ROWS.length} rows`);
});

test('RC-1 port: POSIX out-of-scope rows get no Windows hit in their Windows forms (parity)', () => {
  const failed = [];
  for (const r of ROWS.filter((x) => x.kind === 'parity')) {
    const d = evaluateSeatbelt(r.input, winEnv());
    if (winHits(d).length) failed.push(`${r.id}: ${d.reasons}`);
  }
  assert.deepEqual(failed, []);
});

test('POSIX control: every source row gives the same decision as at 3.9.105 (linux and darwin)', () => {
  const sources = posixSources();
  assert.equal(Object.keys(PIN).length, sources.size);
  for (const [id, input] of sources) {
    for (const platform of ['linux', 'darwin']) {
      const env = makeEnv({ platform });
      assert.deepEqual(sig(evaluateSeatbelt(input, env)), PIN[id], `${id} ${platform}`);
    }
  }
});

test('G1/G2: off win32 the Windows module is never loaded, and Windows-form rows are decided by the POSIX mapper alone', () => {
  const script = `
    const { evaluateSeatbelt } = require(${JSON.stringify(path.join(__dirname, '..', 'dist', 'seatbelt', 'mapper.js'))});
    const { makeEnv } = require(${JSON.stringify(path.join(__dirname, 'support', 'seatbelt-fakes.cjs'))});
    const inputs = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
    for (const platform of ['linux', 'darwin', undefined]) for (const i of inputs) {
      const env = makeEnv({}); env.platform = platform;
      // A forged platform in the event never selects the Windows branch (AB1).
      const d = evaluateSeatbelt({ ...i, platform: 'win32', tool_input: i.tool_input }, env);
      if (d.reasons.some((r) => r.startsWith('windows_'))) { console.log('HIT'); process.exit(1); }
    }
    const loaded = Object.keys(require.cache).some((k) => k.endsWith('win-protected.js'));
    console.log(loaded ? 'LOADED' : 'NOT_LOADED');
  `;
  const inputs = ROWS.map((r) => r.input);
  const res = spawnSync(process.execPath, ['-e', script], { input: JSON.stringify(inputs), encoding: 'utf8', timeout: 120000, env: { PATH: process.env.PATH } });
  assert.equal(res.status, 0, res.stderr);
  assert.equal(res.stdout.trim(), 'NOT_LOADED');
});

test('U-COL8: Windows hits carry fixed codes only; the stop text and receipt fields hold no path, name or value', () => {
  for (const r of ROWS.filter((x) => x.kind === 'stop')) {
    const d = evaluateSeatbelt(r.input, winEnv());
    for (const c of [d.rule, d.category, ...d.reasons, ...d.flags]) assert.match(c, CODE, `${r.id}: ${c}`);
    for (const c of winHits(d)) assert.ok(WIN_CODES.has(c));
    const text = seatbeltStopText(d.category, d.rule, d.reasons[0], 'claimed_no_key');
    const blob = JSON.stringify([d.rule, d.reasons, d.flags, d.hits, text]).toLowerCase();
    for (const piece of ['users', 'runner', 'server', 'share', 'proj', 'credentials', 'id_rsa', 'node_options', '\\\\', 'c:']) {
      assert.ok(!blob.includes(piece), `${r.id}: ${piece}`);
    }
  }
});

test('the matching normalisation never reaches the event: evaluateSeatbelt leaves the event and its input unchanged', () => {
  for (const r of ROWS) {
    const before = JSON.stringify(r.input);
    evaluateSeatbelt(r.input, winEnv());
    assert.equal(JSON.stringify(r.input), before, r.id);
  }
});

test('fail closed: a throw inside the Windows module is a stop (Sx mapper_error)', () => {
  const env = winEnv();
  // A tool input whose getter throws only when the Windows module reads it (the mapper's own reads pass).
  let thrown = 0;
  const input = {};
  Object.defineProperty(input, 'file_path', {
    enumerable: true,
    get() { if (/dist[\\/]seatbelt[\\/]win-protected\.js/.test(String(new Error().stack))) { thrown += 1; throw new Error('boom'); } return 'C:\\Users\\x\\proj\\a.txt'; },
  });
  const d = evaluateSeatbelt({ tool_name: 'Read', tool_input: input }, env);
  assert.ok(thrown >= 1, 'the module read the input');
  assert.equal(d.decision, 'stop');
  assert.deepEqual(d.reasons, ['mapper_error']);
  // The same input off win32: the module is not reached.
  thrown = 0;
  evaluateSeatbelt({ tool_name: 'Read', tool_input: input }, linuxEnv());
  assert.equal(thrown, 0);
});

test('only adds: a mapper stop keeps its category and rule on win32', () => {
  // port of test/fixtures/seatbelt/canonical.cjs s1 rows: `git push -f origin main` stays S1 on win32.
  const d = evaluateSeatbelt(canonInput('s1-main-0'), winEnv());
  assert.equal(d.decision, 'stop');
  assert.equal(d.category, 'S1');
});

// M-4 (patch round 3): this row was a wall-clock guard (under 300 ms for 60 KB, 10 of 10 failures alone on a loaded runner). It is a
// STEP-COUNT guard now, with the same 60 KB input and no clock: the work is counted at the LIMITS boundary. win-protected reads
// LIMITS.maxToolNodes once in each tick() (its Scan.work) and the mapper reads LIMITS.maxWork once per run.work step, so a Proxy
// over LIMITS counts both with no change to the code under test. The budget is roomy (30 s) so budget_time cannot appear; what
// is pinned is that the work is bounded in absolute terms and grows linearly (ratio) from 6 KB to 60 KB.
const tables = require('../dist/seatbelt/tables.js');
const { matcherCells } = require('../dist/seatbelt/win-protected.js');

function counted(run) {
  const real = tables.LIMITS;
  const n = { scan: 0, mapper: 0, cells: 0, result: null };
  matcherCells(true);
  tables.LIMITS = new Proxy(real, { get(target, key, receiver) {
    if (key === 'maxToolNodes') n.scan += 1;
    else if (key === 'maxWork') n.mapper += 1;
    return Reflect.get(target, key, receiver);
  } });
  try { n.result = run(); } finally { tables.LIMITS = real; n.cells = matcherCells(true); }
  return n;
}
const roomy = () => { const env = winEnv(); env.budgetMs = 30000; return env; };

function hostileText(bytes) {
  const parts = [];
  for (let i = 0; parts.join('; ').length < bytes; i += 1) {
    const r = ROWS[i % ROWS.length];
    parts.push(r.input.tool_input.command || `type ${r.input.tool_input.file_path || r.input.tool_input.path || 'a'}`);
    parts.push(`type C:\\${'*\\'.repeat(400)}x`);
  }
  return parts.join('; ').slice(0, bytes);
}

test('work: a 60 KB hostile Windows text is decided within a step budget (no clock), and the work grows linearly from 6 KB', () => {
  const small = counted(() => evaluateSeatbelt(bash(hostileText(6 * 1024)), roomy()));
  const big = counted(() => evaluateSeatbelt(bash(hostileText(60 * 1024)), roomy()));
  for (const r of [small, big]) {
    assert.equal(r.result.decision, 'stop');
    assert.ok(!r.result.reasons.includes('budget_time'), `reasons ${r.result.reasons}`);
  }
  // A scanner that is linear takes about one tick per word and statement; a quadratic one reaches the node cap (200000).
  assert.ok(small.scan > 0 && big.scan > 0, `scan ticks ${small.scan} ${big.scan}`);
  assert.ok(big.scan <= SCAN_ABSOLUTE_MAX, `60 KB took ${big.scan} scan ticks (cap ${SCAN_ABSOLUTE_MAX})`);
  assert.ok(big.scan <= 12 * small.scan, `60 KB took ${big.scan} scan ticks, 6 KB took ${small.scan} (ratio > 12)`);
  assert.ok(big.cells <= CELLS_ABSOLUTE_MAX, `60 KB took ${big.cells} matcher cells (cap ${CELLS_ABSOLUTE_MAX})`);
  assert.ok(big.cells <= 12 * Math.max(small.cells, 1), `60 KB took ${big.cells} matcher cells, 6 KB took ${small.cells} (ratio > 12)`);
  assert.ok(big.mapper <= tables.LIMITS.maxWork + 1, `mapper work ${big.mapper}`);
  assert.ok(big.mapper <= 12 * Math.max(small.mapper, 1), `60 KB took ${big.mapper} mapper steps, 6 KB took ${small.mapper} (ratio > 12)`);
  assert.ok(!big.result.reasons.includes('budget_work'), `the node cap was reached: ${big.result.reasons}`);
  // The hostile text has few statements (its words are long), so shapes whose statement and word counts grow with the bytes are
  // counted too: a scanner that is quadratic in the statements or in the words shows up here, not in the row above.
  const SHAPES = {
    'many statements': (bytes) => 'type fx; '.repeat(Math.ceil(bytes / 9)).slice(0, bytes),
    'many words': (bytes) => `echo ${'a '.repeat(Math.ceil(bytes / 2))}`.slice(0, bytes),
    'many redirects': (bytes) => 'echo x > fx; '.repeat(Math.ceil(bytes / 13)).slice(0, bytes),
    'many chained commands': (bytes) => 'cmd /c type fx && '.repeat(Math.ceil(bytes / 18)).slice(0, bytes),
    'many stream words': (bytes) => 'type fxfile:s '.repeat(Math.ceil(bytes / 14)).slice(0, bytes),
  };
  for (const [name, make] of Object.entries(SHAPES)) {
    const s6 = counted(() => evaluateSeatbelt(bash(make(6 * 1024)), roomy()));
    const s60 = counted(() => evaluateSeatbelt(bash(make(60 * 1024)), roomy()));
    for (const r of [s6, s60]) {
      assert.ok(['pass', 'stop'].includes(r.result.decision), `${name}: ${r.result.decision}`);
      assert.ok(!r.result.reasons.includes('budget_time'), `${name}: ${r.result.reasons}`);
    }
    assert.ok(s60.scan <= SCAN_ABSOLUTE_MAX, `${name}: 60 KB took ${s60.scan} scan ticks (cap ${SCAN_ABSOLUTE_MAX})`);
    assert.ok(s60.scan <= 12 * Math.max(s6.scan, 1), `${name}: 60 KB took ${s60.scan} scan ticks, 6 KB took ${s6.scan} (ratio > 12)`);
    assert.ok(s60.cells <= CELLS_ABSOLUTE_MAX, `${name}: 60 KB took ${s60.cells} matcher cells`);
    assert.ok(s60.cells <= 12 * Math.max(s6.cells, 1), `${name}: 60 KB took ${s60.cells} matcher cells, 6 KB took ${s6.cells} (ratio > 12)`);
  }
  // Many git messages in one text: the message strip is linear.
  const gitText = (bytes) => 'git commit -m "a" '.repeat(Math.floor(bytes / 18));
  const g6 = counted(() => evaluateSeatbelt(bash(gitText(6 * 1024)), roomy()));
  const g60 = counted(() => evaluateSeatbelt(bash(gitText(60 * 1024)), roomy()));
  for (const r of [g6, g60]) assert.ok(!r.result.reasons.includes('budget_time'), `reasons ${r.result.reasons}`);
  assert.ok(g60.scan <= SCAN_ABSOLUTE_MAX, `git text: 60 KB took ${g60.scan} scan ticks`);
  assert.ok(g60.scan <= 12 * Math.max(g6.scan, 1), `git text: 60 KB took ${g60.scan} scan ticks, 6 KB took ${g6.scan} (ratio > 12)`);
  // One ordinary row costs a few ticks, not a few thousand.
  const one = ROWS.find((r) => r.base === 's4-path-4-0');
  const o = counted(() => evaluateSeatbelt(one.input, roomy()));
  assert.ok(o.scan > 0 && o.scan <= 200, `one row: ${o.scan} scan ticks`);
  assert.ok(o.mapper <= 200, `one row: ${o.mapper} mapper steps`);
  assert.ok(o.cells <= 2000, `one row: ${o.cells} matcher cells`);
});

test('work: padded Windows inputs of 4, 18 and 64 KB (stream, prefix, file: URL, option and colon words) grow linearly in steps and are all decided', () => {
  const unit = {
    streams: 'type fxfile:s a.txt::$DATA ',
    prefixes: 'tool.exe -o\\\\srv\\share\\x @list FileSystem::C:\\fx\\a.txt ',
    urls: 'curl file:///C:/fx/a.txt file://srv/share/a -Stream s ',
    colons: 'echo a:b:c:d:e:f:g:h:i:j:k:l:m:n ',
  };
  for (const [name, text] of Object.entries(unit)) {
    const pad = (bytes) => text.repeat(Math.ceil(bytes / text.length)).slice(0, bytes);
    const runs = [4 * 1024, 18 * 1024, 64 * 1024].map((bytes) => counted(() => evaluateSeatbelt(bash(pad(bytes)), roomy())));
    for (const r of runs) {
      assert.ok(['pass', 'stop'].includes(r.result.decision), `${name}: ${r.result.decision}`);
      assert.ok(!r.result.reasons.includes('budget_time'), `${name}: ${r.result.reasons}`);
    }
    assert.ok(runs[2].scan <= SCAN_ABSOLUTE_MAX, `${name}: 64 KB took ${runs[2].scan} scan ticks`);
    assert.ok(runs[2].cells <= CELLS_PER_BYTE_MAX * 64 * 1024, `${name}: 64 KB took ${runs[2].cells} matcher cells`);
    assert.ok(runs[2].cells <= 20 * Math.max(runs[0].cells, 1), `${name}: 64 KB took ${runs[2].cells} matcher cells, 4 KB took ${runs[0].cells}`);
    assert.ok(runs[2].scan <= 20 * Math.max(runs[0].scan, 1), `${name}: 64 KB took ${runs[2].scan} scan ticks, 4 KB took ${runs[0].scan} (ratio > 20 for 16x the input)`);
    assert.ok(runs[1].scan <= 20 * Math.max(runs[0].scan, 1), `${name}: 18 KB took ${runs[1].scan} scan ticks, 4 KB took ${runs[0].scan}`);
  }
  // One 64 KB word (a very long name behind a prefix, a colon run, a file: URL) is one decision, not a scan per character.
  for (const word of [`-o\\\\srv\\share\\${'a'.repeat(64000)}`, `${'a:'.repeat(32000)}`, `file:///C:/${'a'.repeat(64000)}`, `a.txt:${'s:'.repeat(30000)}$DATA`]) {
    const r = counted(() => evaluateSeatbelt(bash(`type ${word}`), roomy()));
    assert.ok(['pass', 'stop'].includes(r.result.decision));
    assert.ok(r.scan <= 20, `one long word took ${r.scan} scan ticks`);
  }
});

module.exports = { ROWS };
