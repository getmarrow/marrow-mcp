'use strict';

// Hook labels from command positions only (SPEC client-labels, section CLIENT-LABELS): a commit message, a proven
// wrangler dry run and an edit-tool file name no longer set deploy, production or secrets labels on the keyed
// pre-action path. Every other call, every keyless and
// PostToolUse call and every call with its switch off keeps the 3.9.114 output. Every row here is a hook INPUT
// written as data; nothing in it is ever run.
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { chmodSync, existsSync, mkdirSync, rmSync, symlinkSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');
const test = require('node:test');

const { classifyTool, preActionHookOutput } = require('../dist/hook-pre-action.js');
const { normalizeShellCommand } = require('../dist/normalized-action.js');

const SWITCHES = ['MARROW_HOOK_LABEL_COMMIT', 'MARROW_HOOK_LABEL_DRYRUN', 'MARROW_HOOK_LABEL_PATH', 'MARROW_HOOK_LABELS'];
// FX-ROOT: a fixed folder inside the checkout, at the repo root beside test/ (never under it, never a temp folder).
// Its name holds no upper-case letter, digit or dot, so the fixture path answers the same on every machine.
// Runs of this file in one checkout are sequential (CI shards run each file once).
const ROOT = join(__dirname, '..', 'label-shapes-fixture');
function removeFixture() {
  try { chmodSync(join(ROOT, 'unreadable', 'wrangler.toml'), 0o600); } catch {} finally { rmSync(ROOT, { recursive: true, force: true }); }
}
removeFixture(); // a leftover from a killed run
test.after(removeFixture);

function folder(name, files = {}) {
  const dir = join(ROOT, name);
  mkdirSync(dir, { recursive: true });
  for (const [file, text] of Object.entries(files)) {
    mkdirSync(join(dir, file, '..'), { recursive: true });
    writeFileSync(join(dir, file), text);
  }
  return dir;
}
const CLEAN = folder('clean', { 'wrangler.toml': 'name = "worker"\nmain = "src/index.ts"\n' });
const NOCONF = folder('noconf');
const BUILD = folder('withbuild', { 'wrangler.toml': 'name = "w"\n[build]\ncommand = "npm run gen"\n' });
const PARENT_BUILD = join(folder('parentbuild', { 'wrangler.json': '{"name":"w","Build":{"command":"x"}}' }), 'child');
mkdirSync(PARENT_BUILD, { recursive: true });
const REDIRECT = folder('redirect', { '.wrangler/deploy/config.json': '{"configPath":"../../x/wrangler.toml"}' });
const LINKED = folder('linked');
symlinkSync(join(CLEAN, 'wrangler.toml'), join(LINKED, 'wrangler.toml'));
const UNREADABLE = folder('unreadable', { 'wrangler.toml': 'name = "w"\n' });
chmodSync(join(UNREADABLE, 'wrangler.toml'), 0o000);
const OVERSIZE = folder('oversize', { 'wrangler.toml': `name = "w"\n#${'x'.repeat(262144)}\n` });
const MISSING = join(ROOT, 'missing-folder');
assert.equal(existsSync(MISSING), false, `the missing fixture folder exists: ${MISSING}`);

// A dummy secret-shaped value made at runtime (fixed non-key prefix + random letters and digits): never a live key shape.
function dummySecret() {
  let out = '';
  while (out.length < 38) out += randomBytes(48).toString('base64').replace(/[^A-Za-z0-9]/g, '');
  const value = `mt${out.slice(0, 38)}`;
  assert.doesNotMatch(value, /^(?:sk_|pk_|rk_|ghp_|xox)/);
  return value;
}

function withEnv(vars, fn) {
  const saved = Object.fromEntries(SWITCHES.map((key) => [key, process.env[key]]));
  for (const key of SWITCHES) delete process.env[key];
  Object.assign(process.env, vars);
  try { return fn(); } finally {
    for (const key of SWITCHES) { if (saved[key] === undefined) delete process.env[key]; else process.env[key] = saved[key]; }
  }
}
const bash = (command, cwd = CLEAN, extra = {}) => ({ session_id: 's1', tool_use_id: 't1', hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command, ...extra }, cwd });
const tool = (name, input, cwd = CLEAN) => ({ session_id: 's1', tool_use_id: 't1', hook_event_name: 'PreToolUse', tool_name: name, tool_input: input, cwd });
const tip = (event, vars = {}) => withEnv(vars, () => classifyTool(event, { keyed: true }));
const base = (event) => tip(event, { MARROW_HOOK_LABELS: 'off' });
const label = (c) => `${c.type} on ${c.surfaces.join(', ')}`;

const COMMIT = { action: 'classified Bash action: process on github', target: 'github:process', type: 'process', role: 'general', surfaces: ['github'], risk: 'high', protected: true, readOnly: false };
const DRY = { action: 'classified Bash action: process on workspace', target: 'workspace:process', type: 'process', role: 'general', surfaces: ['workspace'], risk: 'high', protected: true, readOnly: false };
const PATH = (name) => ({ action: `classified ${name} action: process on workspace`, target: 'workspace:process', type: 'process', role: 'general', surfaces: ['workspace'], risk: 'medium', protected: false, readOnly: false });

const HEREDOC = "git commit -q -m \"$(cat <<'EOF'\nfix: release notes for the production token path\n\nMerge the key handling note. No secret changed.\nEOF\n)\"";
// Authored twins of the 1A target rows (exact dogfood texts run only in the uncommitted scratch harness).
const COMMIT_TWINS = [
  ['TW-C1', HEREDOC],
  ['TW-C2', "git add -A && git commit -m 'fix production key rotation docs'"],
  ['TW-C3', 'git add src/a.ts docs/b.md && git commit -s -m "deploy notes for the release token"'],
  ['TW-C4', "git commit -q -m \"$(cat <<\"EOF\"\nwrangler deploy production secret credential\nEOF\n)\""],
  ['TW-C5', "git add . && git commit --all --quiet -m 'publish the database migration notes'"],
];
const DRY_TWINS = [
  ['TW-D1', `cd ${CLEAN} && npx wrangler deploy --dry-run --outdir /tmp/wr-out 2>&1 | tail -10`, CLEAN],
  ['TW-D2', 'npx wrangler deploy --dry-run', CLEAN],
  ['TW-D3', 'wrangler deploy --outdir=dist-out --dry-run | head -5', NOCONF],
  ['TW-D4', `cd ${MISSING} && npx wrangler deploy --dry-run`, NOCONF],
];
const PATH_TWINS = [
  ['TW-P1', 'Write', { file_path: 'schema-check.py', content: 'ROWS = ["password_hash", "api_key"]\n' }],
  ['TW-P2', 'Edit', { file_path: 'src/deploy-release.ts', old_string: 'a', new_string: 'b' }],
  ['TW-P3', 'MultiEdit', { file_path: 'docs/migration-notes.md', edits: [{ old_string: 'a', new_string: 'b' }] }],
  ['TW-P4', 'write', { file_path: 'release/deploy.py', content: 'x' }],
];
const TARGET_ROWS = [...COMMIT_TWINS.map(([id, c]) => [id, bash(c)]), ...DRY_TWINS.map(([id, c, w]) => [id, bash(c, w)]), ...PATH_TWINS.map(([id, n, i]) => [id, tool(n, i)])];

// FX-PRE: the rows below only prove the lowering when the client redactor keeps every text they send. A fixture
// path the redactor reads as key-shaped makes the action truncated and the row answers 3.9.114 instead, so this
// precondition fails loudly and names the fixture path. It is never skipped.
function assertFixtureNotCut(rows) {
  for (const [id, event] of rows) {
    const texts = [`cd ${event.cwd}`];
    if (event.tool_name === 'Bash') texts.push(event.tool_input.command);
    for (const text of texts) assert.equal(normalizeShellCommand(text).truncated, false, `${id}: fixture path is cut by the client redactor: ${ROOT}`);
  }
}

test('targets: a commit message, a proven dry run and a source-file name set no label words (keyed PreToolUse)', () => {
  assertFixtureNotCut(TARGET_ROWS);
  for (const [id, command] of COMMIT_TWINS) {
    assert.deepEqual(tip(bash(command)), COMMIT, id);
    assert.notEqual(label(base(bash(command))), 'process on github', `${id} differs from 3.9.114`);
  }
  for (const [id, command, cwd] of DRY_TWINS) {
    assert.deepEqual(tip(bash(command, cwd)), DRY, id);
    assert.equal(base(bash(command, cwd)).protected, true, id);
  }
  for (const [id, name, input] of PATH_TWINS) assert.deepEqual(tip(tool(name, input)), PATH(name), id);
});

test('targets: protected, risk and readOnly are exactly 3.9.114 on every twin', () => {
  const twins = [...COMMIT_TWINS.map(([id, c]) => [id, bash(c)]), ...DRY_TWINS.map(([id, c, w]) => [id, bash(c, w)]), ...PATH_TWINS.map(([id, n, i]) => [id, tool(n, i)])];
  for (const [id, event] of twins) {
    const before = base(event);
    const after = tip(event);
    assert.equal(after.protected, before.protected, id);
    assert.equal(after.risk, before.risk, id);
    assert.equal(after.readOnly, before.readOnly, id);
  }
  assert.equal(label(base(bash(HEREDOC))), 'deploy on production, github, secrets');
  assert.equal(label(base(bash('npx wrangler deploy --dry-run'))), 'deploy on production');
  assert.equal(label(base(tool(...PATH_TWINS[0].slice(1)))), 'migration on database');
});

const secretA = dummySecret();
const COMMIT_ABUSE = [
  ['AB-CM-1', "git commit --no-verify -m 'fix production key'"], ['AB-CM-2', "git commit -n -m 'fix production key'"],
  ['AB-CM-3', "git -c core.hooksPath=/dev/null commit -m 'fix production key'"], ['AB-CM-4', "GIT_DIR=x git commit -m 'fix production key'"],
  ['AB-CM-5', "git commit --amend -m 'fix production key'"], ['AB-CM-6', "git commit -m 'a production' -m 'b key'"],
  ['AB-CM-7', 'git commit -F msg.txt'], ['AB-CM-8', 'git commit -m "$(cat ~/.npmrc)"'],
  ['AB-CM-9', 'git commit -m "$(cat <<EOF\nfix production $(id)\nEOF\n)"'], ['AB-CM-9b', 'git commit -m "$(cat <<EOF\nfix production key\nEOF\n)"'], ['AB-CM-10', "git commit -m \"$(bash <<'EOF'\necho production key\nEOF\n)\""],
  ['AB-CM-11', "git commit -m \"$(cat <<'EOF'\nfix production key\nEOF\n)$(id)\""], ['AB-CM-12', 'git commit -m "deploy $HOME"'],
  ['AB-CM-13', "git commit -m 'fix production key' && git push origin main"], ['AB-CM-14', "git commit -m 'fix production key'; npx wrangler deploy"],
  ['AB-CM-15', "git commit -m 'fix production key' || git push"], ['AB-CM-16', "git commit -m 'fix production key' | sh"],
  ['AB-CM-17', "git commit -m 'fix production key' > ~/.bashrc"], ['AB-CM-18', "git commit -m 'fix production key' &"],
  ['AB-CM-19', "bash -c \"git commit -m 'x production'\""], ['AB-CM-20', "sh -c \"git commit -m 'x production'\""],
  ['AB-CM-21', "eval \"git commit -m 'x production'\""], ['AB-CM-22', "(git commit -m 'x production')"],
  ['AB-CM-23', "$(git commit -m 'x production')"], ['AB-CM-24', "cd /x && git commit -m 'production key'"],
  ['AB-CM-25', "git add ~/.npmrc && git commit -m 'x production'"], ['AB-CM-26', "git add .env && git commit -m 'x production'"],
  ['AB-CM-27', "git add ../x && git commit -m 'x production'"], ['AB-CM-28', "git add .husky/pre-commit && git commit -m 'x production'"],
  ['AB-CM-29', "git add .github/workflows/release.yml && git commit -m 'x production'"], ['AB-CM-30', "git add 'src/*.ts' && git commit -m 'x production'"],
  ['AB-CM-31', "git add $F && git commit -m 'x production'"], ['AB-CM-32', "git add -f secret.pem && git commit -m 'x production'"],
  ['AB-CM-33', "git commit -m 'npx @getmarrow/install control disable'"], ['AB-CM-34', `git commit -m 'fix production ${secretA}'`],
  ['AB-CM-35', 'git commit -m "fix production $(id)"'], ['AB-CM-36', 'git commit -m "`id` production"'],
  ['AB-CM-37', "git commit -m 'x'\\''y production'"], ['AB-CM-38', "git commit -m 'café production'"],
  ['AB-CM-39', "g​it commit -m 'x production'"], ['AB-CM-40', "gіt commit -m 'x production'"],
  ['AB-CM-40b', "git cоmmit -m 'x production'"], ['AB-CM-41', "git commit -m 'x production' -q -q"],
  ['AB-CM-42', "git commit -m 'x production' --author 'a <b>'"], ['AB-CM-43', "git commit -m 'x production' # note"],
  ['AB-CM-44', "git commit -m \"$(cat <<'EOF'\nproduction\nEOF\n)\" && git push"], ['AB-CM-45', "git commit -m \"$(cat <<'EOF'\nproduction\nEOF\nid\n)\""],
  ['AB-CM-46', "git commit -m \"$(cat <<'EOF' | sh\nproduction\nEOF\n)\""], ['AB-CM-47', "/usr/bin/git commit -m 'x production'"],
  ['AB-CM-48', "git add -A\ngit commit -m 'x production'"], ['AB-CM-49', "git add -A ; git commit -m 'x production'"],
  ['AB-CM-50', "git commit -m 'x production'\n"], ['AB-CM-51', "git commit -mx -m 'production'"],
  ['AB-CM-52', "xargs git commit -m 'x production'"], ['AB-CM-53', "timeout 5 git commit -m 'x production'"],
  ['AB-CM-54', "git commit -m 'x production' -m"], ['AB-CM-55', "git commit -m \"$(cat <<'EOF'\nEOF\n)\" --message=deploy"],
  ['AB-CM-56', "git add -A && git add . && git commit -m 'x production'"], ['AB-CM-57', "git add src/.env.ts && git commit -m 'x production'"], ['AB-CM-61', "git add -f src/a.ts && git commit -m 'x production'"],
  ['AB-CM-62', "git add -p && git commit -m 'x production'"], ['AB-CM-63', "git add -- src && git commit -m 'x production'"], ['AB-CM-64', "git add --force src && git commit -m 'x production'"], ['AB-CM-58', "git commit -q -m \"$(cat <<'EOF'\nx production\nEOF\n)\" -s"],
  ['AB-CM-59', "git commit -m \"$(cat <<'EOF'\nfix(x): production \"; id; echo \"\nEOF\n)\""], ['AB-CM-60', "git commit -m \"$(cat <<'EOF'\nproduction $(id)\nEOF\n)\""],
];
const DRY_ABUSE = [
  ['AB-DR-1', 'npx wrangler deploy --dry-run=false'], ['AB-DR-2', 'npx wrangler deploy --no-dry-run'],
  ['AB-DR-3', 'npx wrangler deploy --dry-run --dry-run=false'], ['AB-DR-4', 'npx wrangler deploy --dry-run=false --dry-run'],
  ['AB-DR-5', 'npx wrangler deploy --dry-run --no-dry-run'], ['AB-DR-6', 'npx wrangler deploy --dry-run --dry-run'],
  ['AB-DR-7', 'npx wrangler deploy --dryRun=false --dry-run'], ['AB-DR-8', 'npx wrangler deploy --dry-run false'],
  ['AB-DR-9', 'npx wrangler deploy --dry-run true'], ['AB-DR-10', 'npx wrangler deploy --outdir --dry-run'],
  ['AB-DR-11', 'npx wrangler deploy --outdir=--dry-run'], ['AB-DR-12', 'echo "--dry-run" && npx wrangler deploy'],
  ['AB-DR-13', 'npx wrangler deploy # --dry-run'], ['AB-DR-14', 'wrangler versions upload --dry-run'],
  ['AB-DR-15', 'npx wrangler deploy --dry-run && npx wrangler deploy'], ['AB-DR-16', 'npx wrangler deploy --dry-run; wrangler deploy --env production'],
  ['AB-DR-17', 'npx wrangler deploy --dry-run --env production'], ['AB-DR-18', 'npx wrangler deploy --dry-run -c other.toml'],
  ['AB-DR-19', 'npx wrangler deploy --dry-run --config x'], ['AB-DR-20', 'npx wrangler deploy --dry-run --name prod'],
  ['AB-DR-21', 'npx wrangler deploy --dry-run src/index.ts'], ['AB-DR-22', `CLOUDFLARE_API_TOKEN=${dummySecret()} npx wrangler deploy --dry-run`],
  ['AB-DR-23', 'CLOUDFLARE_ENV=production npx wrangler deploy --dry-run'], ['AB-DR-24', 'npx wrangler@latest deploy --dry-run'],
  ['AB-DR-25', 'npx -y wrangler deploy --dry-run'], ['AB-DR-26', './node_modules/.bin/wrangler deploy --dry-run'],
  ['AB-DR-27', 'bash -c "npx wrangler deploy --dry-run"'], ['AB-DR-28', 'eval "npx wrangler deploy --dry-run"'],
  ['AB-DR-29', 'cd $D && npx wrangler deploy --dry-run'], ['AB-DR-30', 'cd x || npx wrangler deploy --dry-run'],
  ['AB-DR-31', 'npx wrangler deploy --dry-run --outdir ~/.ssh'], ['AB-DR-32', 'npx wrangler deploy --dry-run --outdir /var/www'],
  ['AB-DR-33', 'npx wrangler deploy --dry-run --outdir /tmp'], ['AB-DR-34', 'npx wrangler deploy --dry-run --outdir ../x'],
  ['AB-DR-35', 'npx wrangler deploy --dry-run --outdir .hidden'], ['AB-DR-36', 'npx wrangler deploy --dry-run --outdir /tmp/../etc'],
  ['AB-DR-37', 'npx wrangler deploy --dry-run', BUILD], ['AB-DR-38', 'npx wrangler deploy --dry-run', PARENT_BUILD],
  ['AB-DR-39', 'npx wrangler deploy --dry-run', REDIRECT], ['AB-DR-40', 'npx wrangler deploy --dry-run', LINKED],
  ['AB-DR-41', 'npx wrangler deploy --dry-run', UNREADABLE], ['AB-DR-42', 'npx wrangler deploy --dry-run', OVERSIZE],
  ['AB-DR-43', 'npx wrangler deploy --dry-run 2>&1 | tee f'], ['AB-DR-44', 'npx wrangler deploy --dry-run | sh'],
  ['AB-DR-45', 'npx wrangler deploy --dry-run > f'], ['AB-DR-46', `cd ${BUILD} && npx wrangler deploy --dry-run`, NOCONF],
  ['AB-DR-47', 'npx wrangler deploy --dry-run --outdir /tmp/a --outdir /tmp/b'], ['AB-DR-48', 'npx wrangler deploy --dry-run | tail -n 5'],
  ['AB-DR-49', 'npx wrangler deploy --dry-run', 'relative/dir'], ['AB-DR-50', 'npx wrangler deploy --dry-run', null],
  ['AB-DR-51', 'npx wrаngler deploy --dry-run'], ['AB-DR-52', 'npx wrangler deploy —dry-run'],
  ['AB-DR-53', 'npx wrangler deploy --dry-run\n'], ['AB-DR-54', `cd ${CLEAN}/../withbuild && npx wrangler deploy --dry-run`, NOCONF],
  ['AB-DR-55', 'npx wrangler deploy --DRY-RUN'], ['AB-DR-56', 'npx wrangler deploy --dry-run | tail -10 | sh'],
  ['AB-DR-57', 'npx  wrangler deploy --dry-run'], ['AB-DR-58', 'npx wrangler deploy --dry-run --outdir /tmp/x/.cache'],
];
const PATH_ABUSE = [
  ['AB-PA-1', 'Write', '.github/workflows/release.yml'], ['AB-PA-2', 'Write', 'deploy.sh'], ['AB-PA-3', 'Write', 'scripts/release.bash'],
  ['AB-PA-4', 'Write', 'Dockerfile'], ['AB-PA-5', 'Write', 'migrations/0042.sql'], ['AB-PA-6', 'Write', 'wrangler.toml'],
  ['AB-PA-7', 'Write', 'package.json'], ['AB-PA-8', 'Write', '.env.production'], ['AB-PA-9', 'Write', '~/.marrow/control.json'],
  ['AB-PA-10', 'Write', '.claude/settings.json'], ['AB-PA-11', 'Write', '.git/hooks/pre-commit'], ['AB-PA-12', 'Write', 'src/../.ssh/x.py'],
  ['AB-PA-13', 'Write', 'src/*.py'], ['AB-PA-14', 'Write', 'src/rélease.py'],
  ['AB-PA-1e', 'Edit', '.github/workflows/release.yml'], ['AB-PA-2m', 'MultiEdit', 'deploy.sh'], ['AB-PA-12e', 'Edit', 'src/../.ssh/x.py'],
  ['AB-PA-15', 'NotebookEdit', 'release/deploy.py'], ['AB-PA-16', 'mcp__x__write', 'release/deploy.py'], ['AB-PA-17', 'Write', '.marrow/deploy.py'],
  ['AB-PA-18', 'Write', 'release/deploy.py.sh'], ['AB-PA-19', 'Write', 'docs/release'], ['AB-PA-20', 'Write', '.github/scripts/release.py'],
];
const pathEvent = (name, rel) => tool(name, { file_path: rel, content: 'x' });

test('abuse: every shape break, chain, path and look-alike keeps the 3.9.114 labels', () => {
  for (const [id, command, cwd] of COMMIT_ABUSE) assert.deepEqual(tip(bash(command, cwd)), base(bash(command, cwd)), id);
  for (const row of DRY_ABUSE) {
    const event = bash(row[1], row.length > 2 ? row[2] : CLEAN);
    if (row[0] === 'AB-DR-41' && process.getuid?.() === 0) continue; // root reads a mode-000 file
    assert.deepEqual(tip(event), base(event), row[0]);
  }
  for (const [id, name, rel] of PATH_ABUSE) assert.deepEqual(tip(pathEvent(name, rel)), base(pathEvent(name, rel)), id);
  assert.deepEqual(tip(bash(DRY_ABUSE[36][1], BUILD)).surfaces, ['production']);
});

const NEVER = ['git push origin main', 'git push origin release', 'git commit -m x && git push', 'gh pr merge 1 --merge', 'git merge release',
  'npx wrangler deploy', 'wrangler deploy --env production', 'wrangler d1 migrations apply db --remote', "wrangler d1 execute db --remote --command 'DROP TABLE x'",
  'cat ~/.npmrc', 'env', 'printenv', 'git config core.hooksPath x', 'npx -y @getmarrow/install control disable'];

test('never-lowered: push, merge, deploy, migration, secret read, governance and control routes keep 3.9.114', () => {
  for (const command of NEVER) {
    const before = base(bash(command));
    assert.deepEqual(tip(bash(command)), before, command);
    if (!['env', 'printenv', 'cat ~/.npmrc', 'git config core.hooksPath x'].includes(command)) assert.equal(before.protected, true, command);
  }
});

test('switches: each rule off alone, all off, or a typo value gives 3.9.114; the other rules keep their targets', () => {
  assertFixtureNotCut([...TARGET_ROWS, ['TW-C1', bash(HEREDOC)]]);
  const rows = { MARROW_HOOK_LABEL_COMMIT: COMMIT_TWINS.map(([, c]) => bash(c)), MARROW_HOOK_LABEL_DRYRUN: DRY_TWINS.map(([, c, w]) => bash(c, w)), MARROW_HOOK_LABEL_PATH: PATH_TWINS.map(([, n, i]) => tool(n, i)) };
  const expected = (event) => (event.tool_name === 'Bash' ? (/commit/.test(event.tool_input.command) ? COMMIT : DRY) : PATH(event.tool_name));
  for (const value of ['off', 'of', 'OFF', '0', 'false', ' on']) {
    for (const [name, events] of Object.entries(rows)) {
      for (const event of events) {
        const before = base(event);
        assert.notDeepEqual(before, expected(event), name);
        assert.deepEqual(tip(event, { [name]: value }), before, `${name}=${value}`);
        assert.deepEqual(tip(event, { MARROW_HOOK_LABELS: value }), before, `MARROW_HOOK_LABELS=${value}`);
        for (const other of Object.keys(rows).filter((key) => key !== name)) assert.deepEqual(tip(event, { [other]: value }), expected(event), `${other}=${value}`);
      }
    }
  }
  for (const value of ['', 'on']) assert.deepEqual(tip(bash(HEREDOC), { MARROW_HOOK_LABEL_COMMIT: value, MARROW_HOOK_LABELS: value }), COMMIT);
});

test('host: keyless, PostToolUse and PowerShell keep 3.9.114; Monitor never lower than the Bash call', () => {
  const events = [...COMMIT_TWINS.map(([, c]) => bash(c)), ...DRY_TWINS.map(([, c, w]) => bash(c, w)), ...PATH_TWINS.map(([, n, i]) => tool(n, i))];
  for (const event of events) {
    const before = base(event);
    assert.deepEqual(withEnv({}, () => classifyTool(event)), withEnv({ MARROW_HOOK_LABELS: 'off' }, () => classifyTool(event)));
    assert.deepEqual(withEnv({}, () => classifyTool(event, { keyed: true, postTool: true })), withEnv({ MARROW_HOOK_LABELS: 'off' }, () => classifyTool(event, { keyed: true, postTool: true })));
    assert.deepEqual(withEnv({}, () => classifyTool(event, { postTool: true })), withEnv({ MARROW_HOOK_LABELS: 'off' }, () => classifyTool(event, { postTool: true })));
    assert.equal(withEnv({}, () => classifyTool(event, { keyed: false })).type, withEnv({}, () => classifyTool(event)).type);
    if (event.tool_name !== 'Bash') continue;
    const shell = { ...event, tool_name: 'PowerShell' };
    assert.deepEqual(tip(shell), base(shell), 'PowerShell');
    const monitor = { ...event, tool_name: 'Monitor' };
    const seen = tip(monitor);
    assert.equal(seen.protected, before.protected);
    assert.ok(label(seen) === label(tip(event)) || label(seen) === label(base(monitor)), 'Monitor');
  }
});

test('forge: tool name casing, extra keys, a truncated input, a non-string, long or NUL command keep 3.9.114', () => {
  const forms = [];
  for (const [, command, cwd] of [COMMIT_TWINS[0], DRY_TWINS[1]]) {
    forms.push({ ...bash(command, cwd), tool_name: 'bash' }, { ...bash(command, cwd), tool_name: 'BASH' });
    forms.push(bash(command, cwd, { cmd: 'echo x' }), bash(command, cwd, { script: 'echo x' }), bash(command, cwd, { env: { A: '1' } }));
    forms.push({ ...bash(command, cwd), input_truncated: true }, { ...bash(command, cwd), input_truncated: false });
    forms.push(bash(`${command} ${' '.repeat(9000)}`, cwd), bash(`${command}\u0000`, cwd), bash(`${command}\t`, cwd));
    forms.push({ ...bash(command, cwd), tool_input: [command] }, { ...bash(command, cwd), tool_input: command });
  }
  forms.push(bash(['git', 'commit']), bash(42), tool('Write', { file_path: `${CLEAN}/src/release.py`, content: 'x', path: `${CLEAN}/.github/x.py` }));
  forms.push(tool('Write', { file_path: `${CLEAN}/src/${'a'.repeat(1100)}.py`, content: 'x' }), tool('Write', { file_path: `${CLEAN}/src/release.py\u0000.sh`, content: 'x' }));
  forms.push(tool('MultiEdit', { file_path: `${CLEAN}/src/release.py`, edits: [{ old_string: '*** Begin Patch\n*** Update File: .github/workflows/release.yml\n' }] }));
  for (const event of forms) assert.deepEqual(tip(event), base(event), JSON.stringify(event).slice(0, 80));
});

test('grow: 8k, 16k and 32k texts are refused by the 4000-character bound; 4000 characters of quotes and lines stay fast', () => {
  for (const size of [8000, 16000, 32000]) {
    const command = `git commit -m '${'production key '.repeat(size / 15)}'`;
    assert.deepEqual(tip(bash(command)), base(bash(command)), String(size));
  }
  const heredoc = `git commit -m "$(cat <<'EOF'\n${'deploy x\n'.repeat(440)}EOF\n)"`;
  assert.ok(heredoc.length <= 4000);
  assert.deepEqual(tip(bash(heredoc)), COMMIT);
});
