'use strict';

// Audit H1 (abf9926b): host-native tool names and MCP calls in every host form. A tool the mapper does
// not recognise never gets the keyless seatbelt pass: the hook gives master's answer for that host.
// Mapper rows use the fake environment (home /home/u, workspace /home/u/proj); the hook rows run the
// real hook CLI in a temporary keyless home (no key anywhere; nothing reaches a server).
const test = require('node:test');
const assert = require('node:assert/strict');
const { withoutKeylessNotice } = require('./support/keyless-notice-strip.cjs');
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

const ev = (tool_name, tool_input) => evaluateSeatbelt({ tool_name, tool_input }, makeEnv());
const S0W = ['/home/u/.marrow/control.json', '/home/u/.claude/settings.json', '/home/u/.bashrc', '/home/u/.marrow/seatbelt/salt'];
const S4R = ['/home/u/.ssh/id_rsa', '/home/u/proj/.env.local', '/home/u/.aws/credentials', '/home/u/.marrow/env'];

test('H1 mapper: host-native write, edit and delete tools on protected paths stop (S0); the same tools in the workspace pass, recognised', () => {
  for (const p of S0W) {
    const rows = [
      // Content that is not the file's JSON: a settings or hook file it would break or change.
      ['write_to_file', { path: p, content: 'alias git=true' }],
      ['replace_in_file', { path: p, diff: '------- SEARCH\na\n=======\nb\n+++++++ REPLACE' }],
      ['apply_diff', { path: p, diff: 'x' }],
      ['insert_content', { path: p, line: 1, content: 'x' }],
      ['search_and_replace', { path: p, search: 'a', replace: 'b' }],
      ['replace', { file_path: p, old_string: 'a', new_string: 'b' }],
      ['search_replace', { path: p, old_string: 'a', new_string: 'b' }],
      ['delete_file', { file_path: p }],
      ['Delete', { path: p }],
      ['functions.apply_patch', { input: `*** Begin Patch\n*** Update File: ${p}\n@@\n-a\n+b\n*** End Patch` }],
    ];
    for (const [tool, input] of rows) {
      const d = ev(tool, input);
      assert.equal(d.decision, 'stop', `${tool} ${p}`);
      assert.ok(d.hits.some((h) => h.category === 'S0' || h.category === 'S4'), `${tool} ${p}: ${d.reasons}`);
    }
  }
  for (const [tool, input] of [['write_to_file', { path: '/home/u/proj/src/x.ts', content: 'x' }], ['replace_in_file', { path: 'src/x.ts', diff: 'x' }],
    ['delete_file', { file_path: '/home/u/proj/src/old.ts' }], ['replace', { file_path: '/home/u/proj/src/x.ts', old_string: 'a', new_string: 'b' }]]) {
    const d = ev(tool, input);
    assert.equal(d.decision, 'pass', tool);
    assert.equal(d.recognized, true, tool);
  }
});

test('H1 mapper: host-native read, search and list tools on secrets stop (S4), including Gemini absolute_path, dir_path and include', () => {
  for (const p of S4R) {
    for (const [tool, input] of [['read_file', { path: p }], ['read_file', { absolute_path: p }], ['read_many_files', { include: [p] }],
      ['read_many_files', { paths: [p] }], ['read_multiple_files', { paths: [p] }], ['search_files', { path: p, regex: 'KEY' }],
      ['grep_search', { pattern: 'KEY', dir_path: p }], ['search_file_content', { pattern: 'KEY', path: p }], ['view_image', { path: p }]]) {
      const d = ev(tool, input);
      assert.equal(d.decision, 'stop', `${tool} ${JSON.stringify(input)}`);
      assert.ok(d.hits.some((h) => h.category === 'S4'), `${tool}: ${d.reasons}`);
    }
  }
  for (const [tool, input] of [['list_files', { path: '/home/u/proj' }], ['list_code_definition_names', { path: 'src' }], ['read_file', { absolute_path: '/home/u/proj/README.md' }]]) {
    const d = ev(tool, input);
    assert.equal(d.decision, 'pass', tool);
    assert.equal(d.recognized, true, tool);
  }
});

test('H1 mapper: MCP calls in every host form get every string value checked; arguments as a JSON string, an object, nested or an array', () => {
  const forms = (args, verb) => [
    [`mcp__filesystem__${verb}`, args],
    [`MCP:filesystem:${verb}`, args],
    [`mcp_filesystem_${verb}`, args],
    [`filesystem__${verb}`, args],
    ['use_mcp_tool', { server_name: 'filesystem', tool_name: verb, arguments: JSON.stringify(args) }],
    ['use_mcp_tool', { server_name: 'filesystem', tool_name: verb, arguments: args }],
    ['use_tool', { server_name: 'filesystem', tool_name: verb, arguments: JSON.stringify(args) }],
  ];
  for (const p of S0W) {
    for (const args of [{ path: p, content: 'x' }, { request: { target_path: p }, content: 'x' }, { ops: [p] }, { note: 'x', where: p }]) {
      for (const [tool, input] of forms(args, 'write_file')) {
        const d = ev(tool, input);
        assert.equal(d.decision, 'stop', `${tool} ${JSON.stringify(input)}`);
        assert.ok(d.hits.some((h) => h.category === 'S0' || h.category === 'S4'), `${tool}: ${d.reasons}`);
      }
    }
  }
  for (const p of S4R) {
    // A secret path in a field that is not named like a path, at any depth, still stops.
    for (const args of [{ path: p }, { q: { location: p } }, { list: ['a', p] }]) {
      for (const [tool, input] of forms(args, 'read_file')) {
        const d = ev(tool, input);
        assert.equal(d.decision, 'stop', `${tool} ${JSON.stringify(input)}`);
        assert.ok(d.hits.some((h) => h.category === 'S4'), `${tool}: ${d.reasons}`);
      }
    }
    const res = ev('access_mcp_resource', { server_name: 'filesystem', uri: `file://${p}` });
    assert.equal(res.decision, 'stop', `access_mcp_resource ${p}`);
  }
  // A command field inside MCP arguments is a shell command, whatever the host form.
  for (const [tool, input] of forms({ command: 'npm publish' }, 'run')) assert.equal(ev(tool, input).decision, 'stop', tool);
  // Routine MCP calls pass and are recognised; free text with a line break is data, not a path.
  for (const [tool, input] of [...forms({ owner: 'acme', repo: 'proj', title: 'Update README' }, 'create_issue'),
    ...forms({ body: 'see ~/.ssh/id_rsa\nfor the setup' }, 'create_issue')]) {
    const d = ev(tool, input);
    assert.equal(d.decision, 'pass', `${tool} ${JSON.stringify(input)}`);
    assert.equal(d.recognized, true, tool);
  }
});

test('H1 mapper: malformed or oversized MCP arguments and unknown tools are not recognised (master answer), and their S hits still stop', () => {
  for (const args of ['{not json', '"just a string"', '42', 'null x', 7, true]) {
    const d = ev('use_mcp_tool', { server_name: 'filesystem', tool_name: 'write_file', arguments: args });
    assert.equal(d.decision, 'pass', String(args));
    assert.equal(d.recognized, false, String(args));
  }
  const big = JSON.stringify({ path: '/home/u/proj/x', content: 'a'.repeat(1_100_000) });
  const over = ev('use_mcp_tool', { server_name: 'filesystem', tool_name: 'write_file', arguments: big });
  assert.equal(over.recognized, false, 'oversized arguments are not read: master answer');
  for (const tool of ['deploy_tool', 'create_issue', 'upload', 'npm', 'x', ' write_to_file', 'write_to_file ', 'writetofile', 'prod:execute', 'marrow_commit', 'Write​']) {
    const d = ev(tool, { anything: 'here', path: '/home/u/proj/src/x.ts' });
    assert.equal(d.decision, 'pass', tool);
    assert.equal(d.recognized, false, JSON.stringify(tool));
  }
  // An unknown tool's path fields still get the S4 and S0 checks.
  assert.equal(ev('frobnicate', { file_path: '/home/u/.ssh/id_rsa' }).decision, 'stop');
  // Case variants of known names are the same tool.
  assert.equal(ev('Write_To_File', { path: '/home/u/.marrow/control.json', content: 'x' }).decision, 'stop');
  assert.equal(ev('READ_FILE', { absolute_path: '/home/u/.ssh/id_rsa' }).decision, 'stop');
  // A known write tool that names no target it can read is not recognised.
  assert.equal(ev('write_to_file', { content: 'x' }).recognized, false);
  assert.equal(ev('delete_file', {}).recognized, false);
});

function keylessSandbox() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-h1-')));
  const home = path.join(root, 'home');
  const proj = path.join(home, 'proj');
  fs.mkdirSync(proj, { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  for (const d of ['.ssh', '.aws', '.marrow', '.claude']) fs.mkdirSync(path.join(home, d), { mode: 0o700 });
  execFileSync('git', ['init', '-q', '-b', 'feat/x'], { cwd: proj, env: { PATH: process.env.PATH, HOME: home, GIT_CONFIG_NOSYSTEM: '1' }, stdio: 'ignore' });
  return { root, home, proj, netspy: path.join(root, 'net.log'), cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}

function hook(sb, harness, event) {
  const r = spawnSync(process.execPath, ['--require', PRELOAD, CLI, `${harness}-pre-action-hook`], {
    cwd: sb.proj, encoding: 'utf8', timeout: 30_000, input: JSON.stringify(event),
    env: { PATH: process.env.PATH, HOME: sb.home, SBT_PASSWD_HOME: sb.home, SBT_NETSPY: sb.netspy, MARROW_HOOK_BACKGROUND_NUDGE: 'false' },
  });
  return { status: r.status, out: withoutKeylessNotice(r.stdout), err: r.stderr };
}

const sid = () => `h1-${crypto.randomBytes(6).toString('hex')}`;
const cline = (sb, toolName, parameters) => ({ hookName: 'PreToolUse', taskId: sid(), workspaceRoots: [sb.proj], preToolUse: { toolName, parameters } });
const gemini = (sb, tool_name, tool_input, extra = {}) => ({ session_id: sid(), hook_event_name: 'BeforeTool', tool_name, tool_input, cwd: sb.proj, ...extra });
const stopped = (harness, r) => {
  if (harness === 'cline') { const j = JSON.parse(r.out); return j.cancel === true && /^MARROW SEATBELT stopped this action/.test(j.errorMessage); }
  const j = JSON.parse(r.out);
  return j.decision === 'deny' && /^MARROW SEATBELT stopped this action/.test(j.reason);
};

test('H1 hook: the audit\'s 24 Cline and Gemini cells (master held, abf9926b passed) now stop keyless', () => {
  const sb = keylessSandbox();
  try {
    const H = (p) => (p.startsWith('~/') ? path.join(sb.home, p.slice(2)) : path.join(sb.proj, p));
    const s0 = [['~/.marrow/control.json', '{"enabled":false}'], ['~/.claude/settings.json', '{}'], ['~/.bashrc', 'alias git=true'], ['~/.marrow/seatbelt/salt', 'x']];
    const s4 = ['~/.ssh/id_rsa', '.env.local', '~/.aws/credentials', '~/.marrow/env'];
    const cells = [
      ['cline', 'write_to_file control.json', cline(sb, 'write_to_file', { path: H(s0[0][0]), content: s0[0][1] })],
      ['cline', 'replace_in_file control.json', cline(sb, 'replace_in_file', { path: H(s0[0][0]), diff: '------- SEARCH\na\n=======\nb\n+++++++ REPLACE' })],
      ...s0.map(([p, c]) => ['cline', `use_mcp_tool write_file ${p}`, cline(sb, 'use_mcp_tool', { server_name: 'filesystem', tool_name: 'write_file', arguments: JSON.stringify({ path: H(p), content: c }) })]),
      ...s4.map((p) => ['cline', `use_mcp_tool read_file ${p}`, cline(sb, 'use_mcp_tool', { server_name: 'filesystem', tool_name: 'read_file', arguments: JSON.stringify({ path: H(p) }) })]),
      ...s0.map(([p, c]) => ['gemini', `mcp_filesystem_write_file ${p}`, gemini(sb, 'mcp_filesystem_write_file', { path: H(p), content: c }, { mcp_context: { server_name: 'filesystem', tool_name: 'write_file' } })]),
      ...s0.map(([p, c]) => ['gemini', `filesystem__write_file ${p}`, gemini(sb, 'filesystem__write_file', { path: H(p), content: c }, { mcp_context: { server_name: 'filesystem', tool_name: 'write_file' } })]),
      ...s0.map(([p]) => ['gemini', `delete_file ${p}`, gemini(sb, 'delete_file', { file_path: H(p) })]),
    ];
    for (const [harness, label, event] of cells) {
      const r = hook(sb, harness, event);
      assert.equal(r.status, 0, `${harness} ${label}: ${r.err}`);
      assert.ok(stopped(harness, r), `${harness} ${label}: ${r.out}`);
    }
    // The approved pass class on the same tools stays a pass.
    assert.deepEqual(JSON.parse(hook(sb, 'cline', cline(sb, 'write_to_file', { path: H('src/x.ts'), content: 'x' })).out), { cancel: false });
    assert.deepEqual(JSON.parse(hook(sb, 'gemini', gemini(sb, 'write_file', { file_path: H('src/x.ts'), content: 'x' })).out), { decision: 'allow' });
    assert.equal(fs.existsSync(sb.netspy) ? fs.readFileSync(sb.netspy, 'utf8') : '', '');
  } finally { sb.cleanup(); }
});

test('H1 hook: a tool the mapper does not recognise gets master\'s answer on every host, never the seatbelt pass', () => {
  const sb = keylessSandbox();
  try {
    // Gemini and Grok: master holds every action that is not read-only (the no-key hold; Grok's fixed denial).
    const gem = hook(sb, 'gemini', gemini(sb, 'deploy_worker', { name: 'api' }));
    // (Gemini's hold text is master's fixed governance denial for a held action without a key.)
    assert.deepEqual(JSON.parse(gem.out), { decision: 'deny', reason: 'Marrow blocked this action because required governance approval or proof is unavailable.' });
    const grok = hook(sb, 'grok', { hookEventName: 'PreToolUse', sessionId: sid(), toolUseId: 't', toolName: 'deploy_worker', toolInput: { name: 'api' }, cwd: sb.proj });
    assert.deepEqual(JSON.parse(grok.out), { decision: 'deny', reason: 'Marrow blocked this protected action.' });
    // Cline: an MCP call whose arguments cannot be read is master's protected MCP hold, never `{"cancel":false}`.
    for (const args of ['{not json', '42', 'a'.repeat(1_100_000)]) {
      const bad = hook(sb, 'cline', cline(sb, 'use_mcp_tool', { server_name: 'filesystem', tool_name: 'write_file', arguments: args }));
      const j = JSON.parse(bad.out);
      assert.equal(j.cancel, true, bad.out.slice(0, 200));
      assert.ok(!/MARROW SEATBELT/.test(j.errorMessage), j.errorMessage);
    }
    // Claude and Codex: master does not hold a non-MCP tool it does not rate protected; same answer here.
    for (const harness of ['claude', 'codex']) {
      const r = hook(sb, harness, { hook_event_name: 'PreToolUse', session_id: sid(), tool_use_id: 't1', tool_name: 'deploy_worker', tool_input: { name: 'api' }, cwd: sb.proj });
      assert.equal(r.status, 0, r.err);
      assert.deepEqual(JSON.parse(r.out), {}, `${harness}: ${r.out}`);
      assert.ok(!/MARROW SEATBELT/.test(r.out + r.err));
    }
    assert.equal(fs.existsSync(sb.netspy) ? fs.readFileSync(sb.netspy, 'utf8') : '', '');
  } finally { sb.cleanup(); }
});
