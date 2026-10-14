'use strict';

// Patch round 3 (delta audit F-OPT, friction, F-AWK, F-CODEX): the fixed table of test/support/long-options-table.cjs
// through the real hook CLI, keyless, in a temporary home, on the 7 host paths (Claude, Codex, Cursor and Cursor
// preToolUse, Gemini, Cline, Windsurf); Grok gives its fixed denial. The mapper rows are in
// seatbelt-long-options.test.js.
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

// One representative row per parser family, cycling the three S0 targets, on the 7 host paths.
const HOOK_ROWS = [
  'cpDestination (source read)', 'cpDestination (--target-directory)', 'writeTargets tar -C', 'writeTargets sed -i', 'writeTargets curl', 'reader cat', 'reader rg', 'reader jq',
  'reader bat', 'reader tree', 'reader prettier', 'sedReadOnly', 'awkReadOnly', 'find (read)', 'find (-delete)', 'git read-only (diff)', 'git index-only (reset)',
  'git index-only (restore)', 'git grep pager command', 'tar --to-command', 'tar --create (inputs are reads)',
  // patch round 4: attached short values, zip -TT / -lf, the working folder of env / sudo / doas
  'attached -t value (cp)', 'attached -t value (cp, short cluster)', 'attached -t value (mv)', 'attached -t value (install)', 'zip -TT (command)', 'zip --unzip-command',
  'zip -TT in a cluster', 'zip -lf (log file)', 'env --chdir (relative write)', 'sudo --chdir (relative write)', 'doas (relative write)', 'env -C value unreadable', 'sudo -D value unreadable',
  // patch round 5: the same folder options with an editor or an interpreter operand, zip -TT after an unread letter
  'env --chdir (editor operand)', 'sudo --chdir (editor operand)', 'doas (editor operand)', 'env -C value unreadable (interpreter operand)', 'sudo -D value unreadable (interpreter operand)',
  'zip -TT after an unread letter',
].map((name) => PARSERS.find((p) => p.parser === name));

test('long options (hook): the fixed table through the real hook CLI on the 7 host paths; Grok gives its fixed denial', () => {
  const sb = keylessSandbox();
  try {
    let cells = 0;
    HOOK_ROWS.forEach((row, n) => {
      const t = TARGETS[n % TARGETS.length];
      const [exactCmd, want] = row.exact;
      const variants = [['exact', fill(exactCmd, t, sb.home), want === 'pass' ? 'pass' : 'STOP'], ['short', fill(row.short, t, sb.home), 'STOP'], ['unknown', fill(row.unk, t, sb.home), 'STOP']];
      for (const [label, command, expected] of variants) {
        for (const host of HOSTS7) {
          const v = verdict(hook(sb, host, shellEvent(sb, host, command)));
          // A pass row must not be the seatbelt's stop; a host may still hold the action for its own reasons (cursor holds git reset).
          if (expected === 'pass') assert.ok(v === 'pass' || v === 'held', `${row.parser} ${label} on ${host} (${t.name}): ${command}: ${v}`);
          else assert.equal(v, expected, `${row.parser} ${label} on ${host} (${t.name}): ${command}`);
          cells += 1;
        }
        const g = verdict(hook(sb, 'grok', shellEvent(sb, 'grok', command)));
        if (expected === 'STOP') assert.equal(g, 'GROK', `${row.parser} ${label} on grok: ${command}`);
      }
    });
    assert.equal(cells, HOOK_ROWS.length * 3 * HOSTS7.length);
    assert.equal(fs.existsSync(sb.netspy) ? fs.readFileSync(sb.netspy, 'utf8') : '', '');
  } finally { sb.cleanup(); }
});

test('friction and F-AWK (hook): tree, prettier --check and archive creation pass; their writing forms and awk program writers stop on the 7 host paths', () => {
  const sb = keylessSandbox();
  try {
    const t = TARGETS[0];
    const passes = [`tree ${t.D}`, `prettier --check ${t.T}`, `npx prettier --check ${t.T}`, `tar czf /tmp/p3-out.tgz ${t.D}`, `zip -r /tmp/p3-out.zip ${t.D}`,
      // patch round 4: the benign rows next to the new rules
      'zip -rq out.zip src', 'env --unset=FOO cp a b', 'sudo --user=www cp a /var/www/x', 'sudo --preserve-env=PATH cp a /tmp/p4-share-x', 'cp -tbuild a.txt', `zip -rq /tmp/p3-out.zip ${t.D}`];
    const stops = [`tree -o /tmp/p3-out.txt ${t.D}`, `prettier --write ${t.T}`, `tar czf ${t.T} /tmp/p3-src`, `tar xzf /tmp/p3.tgz -C ${t.D}`, `awk 'BEGIN{print "x" > "${sb.home}/.claude/settings.json"}'`,
      `awk 'BEGIN{system("rm ${sb.home}/.claude/settings.json")}'`];
    for (const host of HOSTS7) {
      for (const c of passes) assert.equal(verdict(hook(sb, host, shellEvent(sb, host, c))), 'pass', `${host}: ${c}`);
      for (const c of stops) assert.equal(verdict(hook(sb, host, shellEvent(sb, host, c))), 'STOP', `${host}: ${c}`);
    }
    for (const c of stops) assert.equal(verdict(hook(sb, 'grok', shellEvent(sb, 'grok', c))), 'GROK', `grok: ${c}`);
  } finally { sb.cleanup(); }
});

test('F-CODEX: a write under ~/.codex stops (S0) on every host, also a native write tool that leaves the Marrow part as it was', () => {
  const sb = keylessSandbox();
  try {
    const hooks = path.join(sb.home, '.codex', 'hooks.json');
    const config = path.join(sb.home, '.codex', 'config.toml');
    // Shell writes: all 7 host paths.
    for (const c of [`echo '{}' > ~/.codex/hooks.json`, `printf '{}' > ${hooks}`, `echo x > ~/.codex/config.toml`, `tee ~/.codex/hooks.json < /tmp/p3-x`]) {
      for (const host of HOSTS7) assert.equal(verdict(hook(sb, host, shellEvent(sb, host, c))), 'STOP', `${host}: ${c}`);
      assert.equal(verdict(hook(sb, 'grok', shellEvent(sb, 'grok', c))), 'GROK');
    }
    // Native write tools (the file does not exist yet, and the content holds no hook entry at all).
    const cells = [
      ['claude', 'Write', { file_path: hooks, content: '{}' }], ['codex', 'Write', { file_path: hooks, content: '{}' }], ['gemini', 'write_file', { file_path: hooks, content: '{}' }],
      ['cline', 'write_to_file', { path: hooks, content: '{}' }], ['cursor-pre', 'Write', { file_path: hooks, content: '{}' }],
      ['claude', 'Write', { file_path: path.join(sb.proj, '.codex', 'hooks.json'), content: '{}' }], ['gemini', 'write_file', { file_path: path.join(sb.proj, '.codex', 'hooks.json'), content: '{}' }],
      ['claude', 'Write', { file_path: config, content: 'x = 1\n' }], ['gemini', 'write_file', { file_path: config, content: 'x = 1\n' }], ['gemini', 'replace', { file_path: hooks, old_string: '"hooks"', new_string: '"hooks"' }],
    ];
    for (const [host, tool, input] of cells) assert.equal(verdict(hook(sb, host, toolEvent(sb, host, tool, input))), 'STOP', `${host} ${tool} ${input.file_path || input.path}`);
    // Control: a file outside every protected folder.
    for (const [host, tool, input] of [['gemini', 'write_file', { file_path: path.join(sb.proj, 'notes.md'), content: 'x' }], ['claude', 'Write', { file_path: path.join(sb.proj, 'notes.md'), content: 'x' }]]) {
      assert.equal(verdict(hook(sb, host, toolEvent(sb, host, tool, input))), 'pass', `${host} control`);
    }
  } finally { sb.cleanup(); }
});
