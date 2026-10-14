'use strict';

// Patch round 5 (R4-F1, R4-L2 and the benign controls) through the real hook CLI, keyless, in a temporary home, on the 7 host paths
// (Claude, Codex, Cursor and Cursor preToolUse, Gemini, Cline, Windsurf); Grok gives its fixed denial. The folder-option rows of
// R4-F2 and the zip row of R4-L1 are in the fixed table (test/support/long-options-table.cjs, run by seatbelt-long-options-hook.test.js).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync, execFileSync } = require('node:child_process');

const { HOOKS, TARGETS, fill, PARSERS } = require('./support/long-options-table.cjs');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const PRELOAD = path.join(__dirname, 'support', 'seatbelt-hook-preload.cjs');

function keylessSandbox() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-p3-')));
  const home = path.join(root, 'home');
  const proj = path.join(home, 'proj');
  fs.mkdirSync(proj, { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  for (const d of ['.ssh', '.aws', '.marrow', '.claude']) fs.mkdirSync(path.join(home, d), { mode: 0o700 });
  execFileSync('git', ['init', '-q', '-b', 'feat/x'], { cwd: proj, env: { PATH: process.env.PATH, HOME: home, GIT_CONFIG_NOSYSTEM: '1' }, stdio: 'ignore' });
  const put = (rel, text) => { const p = path.join(home, rel); fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, text); };
  put('.claude/settings.json', JSON.stringify({ hooks: HOOKS }, null, 2));
  put('.claude/plugins/installed_plugins.json', '{"version":2,"plugins":{}}');
  put('.claude/plugins/cache/getmarrow/marrow/1.2.3/scripts/marrow-launch.cjs', 'module.exports = 1;\n');
  put('.npm/_npx/abc123/node_modules/@getmarrow/mcp/dist/cli.js', 'module.exports = 1;\n');
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
const sid = () => `p3-${crypto.randomBytes(6).toString('hex')}`;
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
  if (host === 'cursor-pre') return { hook_event_name: 'preToolUse', conversation_id: sid(), generation_id: 'g', tool_use_id: 't', tool_name: tool, tool_input: input, cwd: sb.proj };
  return { hook_event_name: 'PreToolUse', session_id: sid(), tool_use_id: 't1', tool_name: tool, tool_input: input, cwd: sb.proj };
}
/** STOP: the seatbelt's own stop; GROK: Grok's fixed denial; held: the host's own hold; otherwise the host's pass. */
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
const HOSTS7 = ['claude', 'codex', 'cursor', 'cursor-pre', 'gemini', 'cline', 'windsurf'];


const STOPS = [
  // R4-F1: env -S / --split-string with no command (exact, attached, and the first-4 / made-up spellings that reach the plain env rule)
  'env --split-string=', 'env --split-string="FOO=1"', 'env -SFOO=1', "env -S ''", 'env -S "FOO=1"', 'env --spli=', 'env --zz-unknown',
  // chains, subshells, shells and wrappers around them
  "true && env -S ''", "(env --split-string=)", "bash -c \"env -S ''\"", "sudo env -S 'FOO=1'", "env -S '' | head -1",
];
const PASSES = [
  "env -i -S ''", 'env --ignore-environment --split-string=', "env - -S 'FOO=1'", 'env -S "FOO=1 node app.js"', 'env --split-string="NODE_ENV=prod npm start"', 'sudo --user=www node server.js',
  'env --chdir=/tmp vim notes.txt', 'cd /tmp && vim plugins/installed_plugins.json', "echo env -S ''",
];

test('R4-F1 (hook): env -S / --split-string with no command stops on the 7 host paths and Grok; the benign rows pass', () => {
  const sb = keylessSandbox();
  try {
    for (const host of HOSTS7) {
      for (const c of STOPS) assert.equal(verdict(hook(sb, host, shellEvent(sb, host, c))), 'STOP', `${host}: ${c}`);
      for (const c of PASSES) {
        const v = verdict(hook(sb, host, shellEvent(sb, host, c)));
        assert.ok(v === 'pass' || v === 'held', `${host}: ${c}: ${v}`);
        assert.notEqual(v, 'STOP', `${host}: ${c}`);
      }
    }
    for (const c of STOPS) assert.equal(verdict(hook(sb, 'grok', shellEvent(sb, 'grok', c))), 'GROK', `grok: ${c}`);
    assert.equal(fs.existsSync(sb.netspy) ? fs.readFileSync(sb.netspy, 'utf8') : '', '');
  } finally { sb.cleanup(); }
});

test('R4-L2 (hook): attached env -CDIR / sudo -DDIR, a nested wrapper and a sudo value option, 3 targets, 7 host paths', () => {
  const sb = keylessSandbox();
  try {
    for (const t of TARGETS) {
      for (const raw of [`env -C{PA} cp /tmp/p5-x {F}`, `sudo -D{PA} cp /tmp/p5-x {F}`, `env --zz-unknown env -C sub cp /tmp/p5-x {F}`, `sudo --role r cp /tmp/p5-x {T}`, `env --zz-unknown vim {N}`, `sudo -D{PN} vim {N}`]) {
        const command = fill(raw, t, sb.home);
        for (const host of HOSTS7) assert.equal(verdict(hook(sb, host, shellEvent(sb, host, command))), 'STOP', `${host} (${t.name}): ${command}`);
      }
    }
  } finally { sb.cleanup(); }
});
