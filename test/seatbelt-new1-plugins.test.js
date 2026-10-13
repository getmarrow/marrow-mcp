'use strict';

// Delta audit of 0368537c, NEW-1: the Marrow agent plugins are protected on keyless hosts. Their files
// (Claude Code plugin cache and marketplace clone, the plugin registry files, the Codex cache under any
// CODEX_HOME, a project's Cursor plugins, the npx cache copy of @getmarrow) are S0, and the Marrow plugin
// switch (`enabledPlugins["marrow@getmarrow"]`, user or project settings) is compared like a hook entry.
// Another plugin's switch and files stay a pass. Mapper rows use the fake environment; the hook rows run
// the real hook CLI keyless in a temporary home (the audit's c3, dah2 and dah4 cells: 41).
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
const USER_SETTINGS = { hooks: HOOKS, enabledPlugins: { 'marrow@getmarrow': true, 'acme-lint@acme': true } };
const PLUGIN = '/home/u/.claude/plugins/cache/getmarrow/marrow/1.2.3';
const FILES = {
  '/home/u/.claude/settings.json': JSON.stringify(USER_SETTINGS, null, 2),
  '/home/u/.claude/plugins/installed_plugins.json': JSON.stringify({ version: 2, plugins: { 'marrow@getmarrow': [{ installPath: PLUGIN }] } }),
  '/home/u/.claude/plugins/known_marketplaces.json': JSON.stringify({ getmarrow: { source: { source: 'github', repo: 'getmarrow/plugins' } } }),
  [`${PLUGIN}/hooks/hooks.json`]: JSON.stringify({ hooks: HOOKS }),
  [`${PLUGIN}/scripts/marrow-launch.cjs`]: 'module.exports = 1;\n',
  '/home/u/.claude/plugins/cache/acme/acme-lint/1.0.0/hooks/hooks.json': '{}',
  '/home/u/proj/.claude/settings.json': JSON.stringify({ permissions: { allow: [] } }),
};
const env = () => makeEnv({ files: FILES });
const ev = (tool_name, tool_input) => evaluateSeatbelt({ tool_name, tool_input }, env());
const sh = (command) => ev('Bash', { command });
const isS0Stop = (d) => d.decision === 'stop' && d.hits.some((h) => h.category === 'S0');

test('NEW-1 mapper: Edit, MultiEdit and Write that turn the Marrow plugin off in user or project settings stop (S0)', () => {
  const on = '"marrow@getmarrow": true';
  const rows = [
    ['Edit', { file_path: '/home/u/.claude/settings.json', old_string: on, new_string: '"marrow@getmarrow": false' }],
    ['MultiEdit', { file_path: '/home/u/.claude/settings.json', edits: [{ old_string: on, new_string: '"marrow@getmarrow": false' }] }],
    ['Edit', { file_path: '/home/u/.claude/settings.json', old_string: `${on},\n`, new_string: '' }],
    ['Write', { file_path: '/home/u/.claude/settings.json', content: JSON.stringify({ hooks: HOOKS, enabledPlugins: { 'marrow@getmarrow': false } }) }],
    ['Write', { file_path: '/home/u/.claude/settings.json', content: JSON.stringify({ hooks: HOOKS }) }],
    ['Edit', { file_path: '/home/u/proj/.claude/settings.json', old_string: '"permissions"', new_string: '"enabledPlugins": {"marrow@getmarrow": false}, "permissions"' }],
    ['Write', { file_path: '/home/u/proj/.claude/settings.json', content: '{"enabledPlugins":{"marrow@getmarrow":false}}' }],
    ['Write', { file_path: '/home/u/proj/.claude/settings.local.json', content: '{"enabledPlugins":{"marrow@getmarrow":false}}' }],
    ['Write', { file_path: '/home/u/.claude/settings.local.json', content: '{"enabledPlugins":{"marrow@getmarrow":false}}' }],
    ['Write', { file_path: '/home/u/proj/.claude/settings.json', content: '{"enabledPlugins":[]}' }],
    ['Write', { file_path: '/home/u/proj/.claude/settings.json', content: '{"extraKnownMarketplaces":{"getmarrow":{"source":{"source":"github","repo":"evil/plugins"}}}}' }],
    ['Write', { file_path: '/home/u/proj/.claude/settings.json', content: '{"strictKnownMarketplaces":[]}' }],
    ['write_to_file', { path: '/home/u/proj/.claude/settings.json', content: '{"enabledPlugins":{"marrow@getmarrow":false}}' }],
    ['replace', { file_path: '/home/u/.claude/settings.json', old_string: on, new_string: '"marrow@getmarrow": false' }],
  ];
  for (const [tool, input] of rows) {
    const d = ev(tool, input);
    // settings.local.json is a secret path too (it may hold env values): it stops as S4 first.
    const local = /settings\.local\.json$/.test(input.file_path || input.path || '');
    assert.ok(local ? d.decision === 'stop' && d.hits.some((h) => h.category === 'S0' || h.category === 'S4') : isS0Stop(d), `${tool} ${JSON.stringify(input).slice(0, 160)}: ${d.decision} ${d.reasons}`);
  }
});

test('NEW-1 mapper: another plugin\'s switch and files stay a pass; reading the Marrow plugin stays a pass', () => {
  const rows = [
    ['Edit', { file_path: '/home/u/.claude/settings.json', old_string: '"acme-lint@acme": true', new_string: '"acme-lint@acme": false' }],
    ['Edit', { file_path: '/home/u/proj/.claude/settings.json', old_string: '"permissions"', new_string: '"enabledPlugins": {"acme-lint@acme": false}, "permissions"' }],
    ['Write', { file_path: '/home/u/.claude/plugins/cache/acme/acme-lint/1.0.0/hooks/hooks.json', content: '{"hooks":{}}' }],
    ['Read', { file_path: `${PLUGIN}/hooks/hooks.json` }],
    ['Read', { file_path: '/home/u/.claude/plugins/installed_plugins.json' }],
  ];
  for (const [tool, input] of rows) {
    const d = ev(tool, input);
    assert.equal(d.decision, 'pass', `${tool} ${JSON.stringify(input).slice(0, 160)}: ${d.reasons}`);
  }
  for (const c of ['ls -la ~/.claude/plugins', `cat ${PLUGIN}/hooks/hooks.json`, 'cat ~/.claude/plugins/installed_plugins.json', 'grep -r marrow ~/.claude/plugins/cache',
    'echo x > ~/.claude/plugins/cache/acme/acme-lint/1.0.0/notes.txt', 'claude plugin disable acme-lint@acme']) {
    const d = sh(c);
    assert.equal(d.decision, 'pass', `${c}: ${d.reasons}`);
  }
});

test('NEW-1 mapper: tool writes and deletes of the Marrow plugin files stop (S0): Claude cache and registry, Codex cache, Cursor project plugins, npx cache', () => {
  const targets = [
    `${PLUGIN}/hooks/hooks.json`, `${PLUGIN}/scripts/marrow-launch.cjs`, `${PLUGIN}/.claude-plugin/plugin.json`,
    '/home/u/.claude/plugins/installed_plugins.json', '/home/u/.claude/plugins/known_marketplaces.json',
    '/home/u/.claude/plugins/marketplaces/getmarrow/.claude-plugin/marketplace.json',
    '/home/u/.claude/plugins/cache/my-fork/marrow/0.1.0/hooks/hooks.json',
    '/home/u/.codex/plugins/cache/getmarrow/marrow/1.2.3/hooks.json', '/srv/codex-home/plugins/cache/getmarrow/marrow/1.2.3/hooks.json',
    '/home/u/proj/.cursor/plugins/marrow-cursor/hooks.json', '/home/u/.cursor/plugins/marrow/hooks.json',
    '/home/u/.npm/_npx/0123abcd/node_modules/@getmarrow/mcp/dist/cli.js',
  ];
  for (const p of targets) {
    for (const [tool, input] of [['Write', { file_path: p, content: '{}' }], ['Edit', { file_path: p, old_string: 'a', new_string: 'b' }], ['delete_file', { file_path: p }]]) {
      const d = ev(tool, input);
      assert.ok(isS0Stop(d), `${tool} ${p}: ${d.decision} ${d.reasons}`);
    }
  }
});

test('NEW-1 mapper: shell writes, moves, deletes and mode changes of the Marrow plugin stop (S0)', () => {
  const rows = [
    `echo '{}' > ${PLUGIN}/hooks/hooks.json`,
    "echo '{}' > ~/.claude/plugins/cache/getmarrow/marrow/1.2.3/hooks/hooks.json",
    "printf 'process.exit(0)\\n' > ~/.claude/plugins/cache/getmarrow/marrow/1.2.3/scripts/marrow-launch.cjs",
    'echo \'{"version":2,"plugins":{}}\' > ~/.claude/plugins/installed_plugins.json',
    "echo '{}' > ~/.claude/plugins/known_marketplaces.json",
    'rm -rf ~/.claude/plugins/cache/getmarrow',
    'rm ~/.claude/plugins/installed_plugins.json',
    'mv ~/.claude/plugins/cache/getmarrow /tmp/x',
    'mv ~/.claude/plugins/cache /tmp/x',
    'mv ~/.claude/plugins /tmp/x',
    'chmod -R 000 ~/.claude/plugins/cache/getmarrow',
    'chmod 000 ~/.claude/plugins/cache/getmarrow/marrow/1.2.3/scripts/marrow-launch.cjs',
    'cp /tmp/x.json ~/.claude/plugins/installed_plugins.json',
    'sed -i s/marrow/x/ ~/.claude/plugins/installed_plugins.json',
    'truncate -s 0 ~/.claude/plugins/cache/getmarrow/marrow/1.2.3/hooks/hooks.json',
    'tee ~/.codex/plugins/cache/getmarrow/marrow/1.2.3/hooks.json < /dev/null',
    "echo 'module.exports=0' > ~/.npm/_npx/0123abcd/node_modules/@getmarrow/mcp/dist/cli.js",
    "echo '{}' > .cursor/plugins/marrow-cursor/hooks.json",
    'claude plugin marketplace remove getmarrow',
    'claude plugin uninstall marrow@getmarrow',
    'claude plugin disable marrow@getmarrow',
  ];
  for (const c of rows) {
    const d = sh(c);
    assert.equal(d.decision, 'stop', `${c}: ${d.reasons}`);
    assert.ok(d.hits.some((h) => h.category === 'S0' || h.category === 'S5'), `${c}: ${d.reasons}`);
  }
});

// ------------------------------------------------------------------------------------------------
// Hook rows: the real hook CLI, keyless, in a temporary home.

function keylessSandbox() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-new1-')));
  const home = path.join(root, 'home');
  const proj = path.join(home, 'proj');
  fs.mkdirSync(proj, { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  for (const d of ['.ssh', '.aws', '.marrow', '.claude']) fs.mkdirSync(path.join(home, d), { mode: 0o700 });
  execFileSync('git', ['init', '-q', '-b', 'feat/x'], { cwd: proj, env: { PATH: process.env.PATH, HOME: home, GIT_CONFIG_NOSYSTEM: '1' }, stdio: 'ignore' });
  const put = (rel, text) => { const p = path.join(home, rel); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, text); };
  put('.claude/settings.json', JSON.stringify(USER_SETTINGS, null, 2));
  put('proj/.claude/settings.json', JSON.stringify({ permissions: { allow: [] } }));
  put('.claude/plugins/cache/getmarrow/marrow/1.2.3/hooks/hooks.json', JSON.stringify({ hooks: HOOKS }));
  put('.claude/plugins/cache/getmarrow/marrow/1.2.3/scripts/marrow-launch.cjs', 'module.exports = 1;\n');
  put('.claude/plugins/installed_plugins.json', JSON.stringify({ version: 2, plugins: { 'marrow@getmarrow': [{}] } }));
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
const sid = () => `n1-${crypto.randomBytes(6).toString('hex')}`;
function shellEvent(sb, host, command) {
  if (host === 'cursor') return { hook_event_name: 'beforeShellExecution', conversation_id: sid(), generation_id: 'g1', command, cwd: sb.proj };
  if (host === 'cursor-pre') return { hook_event_name: 'preToolUse', conversation_id: sid(), generation_id: 'g', tool_use_id: 't', tool_name: 'Shell', tool_input: { command }, cwd: sb.proj };
  if (host === 'gemini') return { session_id: sid(), hook_event_name: 'BeforeTool', tool_name: 'run_shell_command', tool_input: { command }, cwd: sb.proj };
  if (host === 'grok') return { hookEventName: 'PreToolUse', sessionId: sid(), toolUseId: 't', toolName: 'run_terminal_command', toolInput: { command }, cwd: sb.proj };
  if (host === 'cline') return { hookName: 'PreToolUse', taskId: sid(), workspaceRoots: [sb.proj], preToolUse: { toolName: 'execute_command', parameters: { command } } };
  if (host === 'windsurf') return { agent_action_name: 'pre_run_command', trajectory_id: sid(), execution_id: 'e', tool_info: { command_line: command, cwd: sb.proj } };
  return { hook_event_name: 'PreToolUse', session_id: sid(), tool_use_id: 't1', tool_name: 'Bash', tool_input: { command }, cwd: sb.proj };
}
function toolEvent(sb, host, tool, input) {
  if (host === 'gemini') return { session_id: sid(), hook_event_name: 'BeforeTool', tool_name: tool, tool_input: input, cwd: sb.proj };
  if (host === 'cline') return { hookName: 'PreToolUse', taskId: sid(), workspaceRoots: [sb.proj], preToolUse: { toolName: tool, parameters: input } };
  return { hook_event_name: 'PreToolUse', session_id: sid(), tool_use_id: 't1', tool_name: tool, tool_input: input, cwd: sb.proj };
}
/** STOP: the seatbelt's own stop; GROK: Grok's fixed denial; otherwise the host's pass. */
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

test('NEW-1 hook: the audit\'s tool cells (Claude/Codex Edit, MultiEdit, Write; Gemini replace; Cline write_to_file) stop keyless; the other-plugin control passes', () => {
  const sb = keylessSandbox();
  try {
    const user = path.join(sb.home, '.claude', 'settings.json');
    const projSettings = path.join(sb.proj, '.claude', 'settings.json');
    const plug = path.join(sb.home, '.claude/plugins/cache/getmarrow/marrow/1.2.3');
    const flip = { old_string: '"marrow@getmarrow": true', new_string: '"marrow@getmarrow": false' };
    const cells = [];
    for (const host of ['claude', 'codex']) {
      cells.push([host, 'Edit user plugin off', 'Edit', { file_path: user, ...flip }]);
      cells.push([host, 'MultiEdit user plugin off', 'MultiEdit', { file_path: user, edits: [flip] }]);
      cells.push([host, 'Edit project add plugin off', 'Edit', { file_path: projSettings, old_string: '"permissions"', new_string: '"enabledPlugins":{"marrow@getmarrow":false},"permissions"' }]);
      cells.push([host, 'Write plugin hooks.json {}', 'Write', { file_path: path.join(plug, 'hooks/hooks.json'), content: '{}' }]);
      cells.push([host, 'Write installed_plugins.json', 'Write', { file_path: path.join(sb.home, '.claude/plugins/installed_plugins.json'), content: '{"version":2,"plugins":{}}' }]);
      cells.push([host, 'Write user settings plugin off', 'Write', { file_path: user, content: JSON.stringify({ hooks: HOOKS, enabledPlugins: { 'marrow@getmarrow': false } }) }]);
      cells.push([host, 'Write project settings plugin off', 'Write', { file_path: projSettings, content: '{"enabledPlugins":{"marrow@getmarrow":false}}' }]);
    }
    cells.push(['gemini', 'replace user plugin off', 'replace', { file_path: user, ...flip }]);
    cells.push(['gemini', 'write_file user plugin off', 'write_file', { file_path: user, content: JSON.stringify({ hooks: HOOKS, enabledPlugins: { 'marrow@getmarrow': false } }) }]);
    cells.push(['gemini', 'write_file project plugin off', 'write_file', { file_path: projSettings, content: '{"enabledPlugins":{"marrow@getmarrow":false}}' }]);
    cells.push(['cline', 'write_to_file project plugin off', 'write_to_file', { path: projSettings, content: '{"enabledPlugins":{"marrow@getmarrow":false}}' }]);
    cells.push(['cline', 'write_to_file user plugin off', 'write_to_file', { path: user, content: JSON.stringify({ hooks: HOOKS, enabledPlugins: { 'marrow@getmarrow': false } }) }]);
    for (const [host, label, tool, input] of cells) {
      const v = verdict(hook(sb, host, toolEvent(sb, host, tool, input)));
      assert.equal(v, 'STOP', `${host} ${label}`);
    }
    // Control: another plugin off, Marrow untouched.
    for (const host of ['claude', 'codex']) {
      const v = verdict(hook(sb, host, toolEvent(sb, host, 'Edit', { file_path: user, old_string: '"acme-lint@acme": true', new_string: '"acme-lint@acme": false' })));
      assert.equal(v, 'pass', `${host} control`);
    }
    assert.equal(fs.existsSync(sb.netspy) ? fs.readFileSync(sb.netspy, 'utf8') : '', '');
  } finally { sb.cleanup(); }
});

test('NEW-1 hook: the audit\'s shell cells (plugin hooks.json, marrow-launch.cjs, installed_plugins.json) stop on all 7 host paths; Grok gives its fixed denial', () => {
  const sb = keylessSandbox();
  try {
    const rows = [
      "echo '{}' > ~/.claude/plugins/cache/getmarrow/marrow/1.2.3/hooks/hooks.json",
      "printf 'process.exit(0)\\n' > ~/.claude/plugins/cache/getmarrow/marrow/1.2.3/scripts/marrow-launch.cjs",
      'echo \'{"version":2,"plugins":{}}\' > ~/.claude/plugins/installed_plugins.json',
    ];
    for (const command of rows) {
      for (const host of ['claude', 'codex', 'cursor', 'cursor-pre', 'gemini', 'cline', 'windsurf']) {
        assert.equal(verdict(hook(sb, host, shellEvent(sb, host, command))), 'STOP', `${host}: ${command}`);
      }
      assert.equal(verdict(hook(sb, 'grok', shellEvent(sb, 'grok', command))), 'GROK', `grok: ${command}`);
    }
    // Control: a write to another plugin's folder passes.
    assert.equal(verdict(hook(sb, 'claude', shellEvent(sb, 'claude', 'echo x > ~/.claude/plugins/cache/acme/acme-lint/1.0.0/notes.txt'))), 'pass');
    assert.equal(fs.existsSync(sb.netspy) ? fs.readFileSync(sb.netspy, 'utf8') : '', '');
  } finally { sb.cleanup(); }
});
