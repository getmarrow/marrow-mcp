'use strict';

// R1-4 (fixr1 audit, LOW, pre-existing): keyless S4 did not stop `git log -p` of a secret file, while its
// neighbours `git show HEAD:.env`, `git diff HEAD~1 -- .env` and `git cat-file -p HEAD:.env` stopped.
// `git log` (and `git whatchanged` / `git format-patch`) with patch output now reads its operands like
// `git show -- <path>`: `.env`, `<name>.env` (present, or named as history after `--`) and every
// SECRET_PATTERNS path stop S4. Without patch output `git log` keeps its answer.
// Fake environment: home /home/u, workspace /home/u/proj (test/support/seatbelt-fakes.cjs). File contents are dummies.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync, execFileSync } = require('node:child_process');

const { evaluateSeatbelt } = require('../dist/seatbelt/mapper.js');
const { isSecretMaterialAccess } = require('../dist/hook-tool-policy.js');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');

// prod.env is present; old.env is not (deleted, only in history).
const FILES = { '/home/u/proj/.env': 'DUMMY=1\n', '/home/u/proj/prod.env': 'DUMMY=1\n', '/home/u/proj/sub/.env': 'DUMMY=1\n', '/home/u/proj/x/.env': 'DUMMY=1\n',
  '/home/u/proj/config/prod.env': 'DUMMY=1\n', '/home/u/proj/src/app.ts': 'export {};\n', '/home/u/proj/.npmrc': 'dummy\n' };
const SHELLS = [
  ['Bash', (command) => ({ command })],
  ['Monitor', (command) => ({ command, description: 'watch', timeout_ms: 60000 })],
  ['PowerShell', (command) => ({ command })],
];
const run = (tool, command, options = {}) => evaluateSeatbelt({ tool_name: tool, tool_input: SHELLS.find((s) => s[0] === tool)[1](command) }, makeEnv({ files: FILES, ...options }));
const bare = (command) => evaluateSeatbelt({ tool_name: 'Bash', tool_input: { command } }, makeEnv());

function assertStopS4(command, options) {
  for (const [tool] of SHELLS) {
    const d = run(tool, command, options);
    assert.equal(d.decision, 'stop', `${tool}: ${command}: ${d.reasons}`);
    assert.equal(d.category, 'S4', `${tool}: ${command}: ${d.reasons}`);
  }
}

test('R1-4: the audit rows and the brief rows stop S4 (Bash, Monitor, PowerShell)', () => {
  for (const command of ['git log -p -- .env', 'git log -p -- prod.env', 'git log -p -- old.env', "git log -p --all -- '*.env'", 'git log --patch -- .env',
    'git whatchanged -p -- .env', 'git format-patch -1 -- .env', 'git -C sub log -p -- .env', 'cd x && git log -p -- .env', 'ls && git log -p -- .env',
    "bash -c 'git log -p -- .env'"]) {
    assertStopS4(command);
  }
});

test('R1-4: every spelling git takes for patch output stops (checked against git 2.43: each of these prints the file)', () => {
  for (const command of ['git log -u -- .env', 'git log -U0 -- .env', 'git log --unified=1 -- .env', 'git log --unified -- .env', 'git log --patch-with-stat -- .env',
    'git log --patch-with-raw -- .env', 'git log -c -- .env', 'git log --cc -- .env', 'git log --dd -- .env', 'git log --remerge-diff -- .env',
    'git log --diff-merges=first-parent -- .env', 'git log --diff-merges=separate -- .env', 'git log --diff-merges off -p -- .env', 'git log --binary -- .env',
    'git log --check -- .env', 'git log -pp -- .env', 'git log -sp -- .env', 'git log -up -- .env', 'git log -pu -- .env', 'git log -sU1 -- .env', 'git log -s -U3 -- .env',
    'git log -n1 -p -- .env', 'git log -p --stat -- .env', 'git log --stat -p -- .env', 'git log -p --oneline -- .env', 'git log -p --raw -- .env', 'git log -p --format=%H -- .env',
    'git log -p --output=out.txt -- .env', 'git log -p -R -- .env', 'git log -p --first-parent -- .env', 'git log -p -g -- .env', 'git log -p HEAD~3..HEAD -- prod.env',
    'git log -p main -- prod.env', 'git log -p -- src/app.ts .env', 'git log -p -n 3 -- .env', 'git log -p --since 2.weeks -- .env']) {
    assertStopS4(command);
  }
});

test('R1-4: -L<range>:<file> prints the history of <file> (attached, separate, function name and regex forms)', () => {
  for (const command of ['git log -L1,5:.env', 'git log -L 1,5:.env', 'git log -L:main:.env', 'git log -L/KEY/,+3:.env', 'git log -L1,5:config/prod.env',
    'git log -L1,5:./.env', 'git log -L1,1:src/app.ts -L1,1:.env', 'git log -L1,5:~/.aws/credentials']) {
    assertStopS4(command);
  }
  // Patch output suppressed (git: "Patch output can be suppressed using --no-patch"), or a file that is no secret.
  for (const command of ['git log -L1,5:.env --no-patch', 'git log -L1,5:.env -s', 'git log -L1,5:src/app.ts', 'git log -L:main:src/app.ts']) {
    assert.equal(run('Bash', command).decision, 'pass', command);
  }
});

test('R1-4: every secret path family stops: .env, <name>.env (present or named as history), SECRET_PATTERNS', () => {
  for (const command of ['git log -p -- .env.local', 'git log -p -- .env.production', 'git log -p -- config/prod.env', 'git log -p -- missing.env', 'git log -p -- ~/.ssh/id_rsa',
    'git log -p -- ~/.aws/credentials', 'git log -p -- .npmrc', 'git log -p -- .dev.vars', 'git log -p -- ~/.marrow/fleet.env', "git log -p -- ':/.env'", 'git log -p -- server.pem',
    'git log -p -- ~/.config/gh/hosts.yml', 'git log -p -- ~/.claude/settings.local.json', 'git log -p .env', 'git log -p prod.env']) {
    assertStopS4(command);
  }
  // The keyed policy already treats them as secret access (the keyless answer now agrees).
  for (const command of ['git log -p -- .env', 'git log -p -- prod.env', 'git log -p -- ~/.ssh/id_rsa']) {
    assert.equal(isSecretMaterialAccess({ tool_name: 'Bash', tool_input: { command } }), true, `keyed: ${command}`);
  }
});

test('R1-4 abuse: chains, subshells, shells, pipes, wrappers, aliases and variables', () => {
  for (const command of ['ls; git log -p -- .env', 'false || git log -p -- .env', 'git log -p -- .env | head', '(git log -p -- .env)', 'sh -c "git log -p -- prod.env"',
    'echo $(git log -p -- .env)', 'cd sub && git log -p -- .env', 'env FOO=1 git log -p -- .env', 'nohup git log -p -- .env', 'timeout 5 git log -p -- .env',
    "git -c alias.lp='log -p' lp -- .env", 'git --no-pager log -p -- .env', 'F=.env; git log -p -- $F', 'P=-p; git log $P -- .env', 'git log $X -- .env',
    'git log -p $X -- .env', 'git log --oneline -- src/app.ts && git log -p -- .env', 'echo "git log --oneline"; git log -p -- .env']) {
    assertStopS4(command);
  }
});

test('R1-4 abuse: repeated flags (the last one wins), values that look like flags, unknown and shortened options', () => {
  // A later -p/-u after -s or --no-patch turns patch output back on.
  for (const command of ['git log --no-patch -p -- .env', 'git log -s -p -- .env', 'git log -p -s -p -- .env', 'git log -s -u -- .env']) assertStopS4(command);
  // A -s that is the value of the word before it is no option (git log -p --author -s prints patches).
  for (const command of ['git log -p --author -s -- .env', 'git log -p -S -s -- .env', 'git log -p -pS -s -- .env', 'git log -p --grep -s -- .env',
    'git log -p --end-of-options -s -- .env', 'git log -p $X -s -- .env']) {
    assertStopS4(command);
  }
  // git takes no abbreviation here; a shortened or unknown long option is read strictly (it never turns patch output off).
  for (const command of ['git log --pat -- .env', 'git log -p --no-pat -- .env', 'git log --no-pat -p -- .env', 'git log --patch-w -- .env', 'git log --future-flag -- .env']) {
    assertStopS4(command);
  }
  // -m and -F are flags of log, whatchanged and format-patch, not a message: the next word is read.
  for (const command of ['git log -p -m .env', 'git log -p -F .env', 'git whatchanged -p -m .env', 'git format-patch --stdout -1 -m .env']) assertStopS4(command);
});

// Today's answers (unchanged dist of security-r1-int a19819e, observed with the same fakes): every row passed with category none.
const UNCHANGED_PASS = ['git log --oneline -- .env', 'git log --stat -- .env', 'git log -- .env', 'git log --name-only -- .env', 'git log --name-status -- .env',
  'git log --format=%H -- .env', 'git log --follow -- .env', 'git log -m -- .env', 'git log --word-diff -- .env', 'git log -W -- .env', 'git log -S KEY -- .env',
  'git log --diff-merges=off -- .env', 'git log -p -s -- .env', 'git log -p --no-patch -- .env', 'git log -ps -- .env', 'git log -U3 -s -- .env', 'git log -p -Sfoo -s -- .env',
  'git log -p -n5 -s -- .env', 'git log -p -5 -s -- .env', 'git log -p --format=%H -s -- .env', 'git log -- -p .env', 'git log -- .env -p',
  'git log -p -- src/app.ts', 'git log -p', 'git log -p -3', 'git log -p -- .env.example', 'git log -p -- prod.env.example', 'git log --oneline -p -- src/app.ts',
  'git log --author="secret .env fan" --oneline -- src/app.ts', 'git log --grep=deploy -p -- src/app.ts', 'git log -p missing.env', 'git log -p -- config/'];

test('R1-4: without patch output, or without a secret operand, git log keeps the answer it had before', () => {
  for (const command of UNCHANGED_PASS) {
    for (const [tool] of SHELLS) {
      const d = run(tool, command);
      assert.equal(d.decision, 'pass', `${tool}: ${command}: ${d.reasons}`);
      assert.equal(d.category, 'none', `${tool}: ${command}`);
    }
  }
  // A repo with no secret file at all (the bare fixture): git log -p and its everyday forms pass.
  for (const command of ['git log -p', 'git log -p -3', 'git log -p -- src/index.ts', 'git log --stat', 'git log --oneline -- .env', 'git log -p --follow -- README.md']) {
    assert.equal(bare(command).decision, 'pass', command);
  }
});

test('R1-4: the neighbours keep their stop (git show, git diff, git cat-file)', () => {
  for (const command of ['git show HEAD:.env', 'git show -- .env', 'git diff HEAD~1 -- .env', 'git cat-file -p HEAD:.env', 'git show HEAD:config/prod.env']) assertStopS4(command);
});

test('R1-4: no secret appears in a stop reason (names of rules only)', () => {
  const d = run('Bash', 'git log -p -- .env');
  assert.deepEqual(d.reasons, ['git_operand_secret_path']);
  for (const r of d.reasons.concat(d.flags)) assert.match(r, /^[a-z0-9_]+$/);
});

// The real hook CLI, keyless, in a temporary home with a real git work tree (dummy file contents).
const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const PRELOAD = path.join(__dirname, 'support', 'seatbelt-hook-preload.cjs');
const HOOKS = { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'npx -y --package=@getmarrow/mcp@3.9.103 marrow-mcp claude-pre-action-hook' }] }] };

function sandbox() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-r14-')));
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
  put('proj/.env', 'DUMMY=1\n');
  put('proj/prod.env', 'DUMMY=1\n');
  put('proj/src/app.ts', 'export {};\n');
  return { root, home, proj, netspy: path.join(root, 'net.log'), cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}
function hook(sb, event) {
  const r = spawnSync(process.execPath, ['--require', PRELOAD, CLI, 'claude-pre-action-hook'], {
    cwd: sb.proj, encoding: 'utf8', timeout: 60_000, input: JSON.stringify(event),
    env: { PATH: process.env.PATH, HOME: sb.home, SBT_PASSWD_HOME: sb.home, SBT_NETSPY: sb.netspy, MARROW_HOOK_BACKGROUND_NUDGE: 'false' },
  });
  let j = null;
  try { j = r.stdout && r.stdout.trim() ? JSON.parse(r.stdout) : null; } catch { j = null; }
  const text = JSON.stringify(j || '') + (r.stderr || '');
  const d = j ? (j.hookSpecificOutput?.permissionDecision || j.decision || null) : null;
  // STOP is the seatbelt's S4 stop only (a fail-closed budget stop on a loaded machine is not the answer under test).
  if ((r.status === 2 || d === 'deny' || d === 'block') && /MARROW SEATBELT stopped/.test(text)) return { v: /S4\.credential_access/.test(text) ? 'STOP' : 'stop-other' };
  if (r.status === 2 || d === 'deny' || d === 'block') return { v: 'held' };
  return { v: 'pass' };
}
const sid = () => `r14-${crypto.randomBytes(6).toString('hex')}`;
const event = (sb, tool, command) => ({ hook_event_name: 'PreToolUse', session_id: sid(), tool_use_id: 't1', tool_name: tool,
  tool_input: tool === 'Monitor' ? { command, description: 'watch', timeout_ms: 60000 } : { command }, cwd: sb.proj });

test('R1-4 (real hook): git log -p of a secret stops S4 for Bash and Monitor; git log --oneline and git log -p of a source file pass', () => {
  const sb = sandbox();
  try {
    for (const tool of ['Bash', 'Monitor']) {
      for (const command of ['git log -p -- .env', 'git log -p -- prod.env', 'git log -p -- old.env', 'git log --patch -- .env', 'ls && git log -p -- .env']) {
        const r = hook(sb, event(sb, tool, command));
        assert.equal(r.v, 'STOP', `${tool}: ${command}`);
      }
      for (const command of ['git log --oneline -- .env', 'git log --stat -- .env', 'git log -p -- src/app.ts', 'git log -p']) {
        assert.equal(hook(sb, event(sb, tool, command)).v, 'pass', `${tool}: ${command}`);
      }
    }
    assert.equal(fs.existsSync(sb.netspy) ? fs.readFileSync(sb.netspy, 'utf8') : '', '');
  } finally { sb.cleanup(); }
});

// Consumers of the mapper's answer: the keyless stop (above), the account floor (same decision) and the outage
// hold (outageRisk). The new stop can only raise the outage reading: never not_high (high, or unknown when a loaded
// machine runs over the 300 ms budget; both hold).
test('R1-4 consumers: the outage hold never reads git log -p of a secret as not_high', () => {
  const { outageRisk } = require('../dist/seatbelt/hook.js');
  const sb = sandbox();
  try {
    for (const tool of ['Bash', 'Monitor']) {
      for (const command of ['git log -p -- .env', 'git log -p -- prod.env', 'git log --patch -- old.env']) {
        const r = outageRisk({ tool_name: tool, tool_input: tool === 'Monitor' ? { command, description: 'w', timeout_ms: 60000 } : { command }, cwd: sb.proj, truncated: false },
          Date.now() + 60_000);
        assert.notEqual(r.risk, 'not_high', `${tool}: ${command}`);
      }
    }
  } finally { sb.cleanup(); }
});
