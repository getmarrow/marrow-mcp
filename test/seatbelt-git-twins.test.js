'use strict';

// Client twins of the backend git reading fixes (SPEC TWINS, MCP 3.9.115), on the keyless seatbelt mapper.
// T-G5: the shell body after `-c` or a c-cluster (and `script -c`) is read past one `--`; any other option word in the body
//   place, or no body, is unreadable code (a stop), never a skipped body. `bash -c "<body>"` answers as before.
// T-G4: `hub push …` is read exactly as `git push …`; every other hub subcommand answers as before.
// T-G1/T-G3: the backend dry-run cluster and git config rows are proof rows here (the mapper held them before this change).
// Every row is hook INPUT text: nothing in this file is run. Dummy keys are made at run time and never printed.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const https = require('node:https');
const path = require('node:path');
const test = require('node:test');
const { execFileSync, spawn } = require('node:child_process');
const { evaluateSeatbeltShell } = require('../dist/seatbelt/mapper.js');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');
const { assertNotLiveKey } = require('./support/dummy-secret.cjs');

const ROOT = path.resolve(__dirname, '..');
const read = (command) => evaluateSeatbeltShell(command, makeEnv());
const sorted = (list) => [...(list || [])].sort().join(',');
const view = (d) => [d.decision, d.category, d.parse, sorted(d.reasons), sorted(d.risk)].join('|');
// The answer fields a reader of the mapper uses: the stop, its category and reasons, the parse grade and the risk tags.
const answer = (d) => ({ decision: d.decision, category: d.category, parse: d.parse, reasons: sorted(d.reasons), risk: sorted(d.risk) });
const hitSet = (d) => new Set(d.hits.map((h) => `${h.category}:${h.reason}`));

// Chained and wrapped places a body form is tried in (AB-T5: after `&&`, `||`, `;`, a pipe, inside `( )`, `$( )` and `eval`).
const WRAPS = [
  ['plain', (c) => c],
  ['and', (c) => `true && ${c}`],
  ['or', (c) => `false || ${c}`],
  ['semi', (c) => `echo a; ${c}`],
  ['pipe', (c) => `echo a | ${c}`],
  ['subshell', (c) => `( ${c} )`],
  ['substitution', (c) => `echo $( ${c} )`],
  ['eval', (c) => (c.includes("'") ? null : `eval '${c}'`)],
];

// AB-T5 `--` rows: the form with one `--` after the c-cluster answers exactly as the same body without it.
const DASHDASH = [
  'bash -c -- "git push origin main"',
  'bash -c -- "git push origin :main"',
  'bash -c -- "git push --force origin main"',
  'bash -lc -- "npm publish"',
  'zsh -fc -- "rm -rf ~/x"',
  'script -qc -- "git push origin main" /dev/null',
  'script -qc -- "npm publish" /dev/null',
  'script -c -- "npm publish"',
  'script --command -- "npm publish"',
  'sudo bash -c -- "git push origin main"',
  'sudo bash -c -- "npm publish"',
  'bash -euc -- "git push origin :main"',
  'bash -o pipefail -c -- "npm publish"',
  'dash -c -- "npm publish"',
  'env X=1 bash -c -- "git push origin :main"',
  'bash -c -- "$X"',
];
const withoutDashDash = (c) => c.replace(' -- ', ' ');

// AB-T5 option rows: an option word (or nothing) where the body belongs is unreadable code: a stop, never a pass.
const OPTION_WORD = [
  "sh -c -x 'git push --force origin feat/x'",
  "bash -c +o 'git push origin main'",
  'env X=1 bash -c -x "git push origin main"',
  'bash -c -x "npm publish"',
  'bash -lc +x "npm publish"',
  'bash -c -e -- "npm publish"',
  'bash -c -- -- "npm publish"',
  'bash -c -c "npm publish"',
  'bash -c -- -x "npm publish"',
  'bash -c -- "-c \'npm publish\'"',
  'bash -c',
  'bash -c --',
  'zsh -fc -x "rm -rf ~/x"',
  'script -qc -x "npm publish" /dev/null',
  'script -qc --',
  'script -c',
  'sudo bash -c -x "git push origin :main"',
];

// AB-T4: each hub push form answers as the same git push form.
const HUB = [
  ['hub push origin main', 'git push origin main'],
  ['hub push --force origin feat/x', 'git push --force origin feat/x'],
  ['hub push origin +feat/x:main', 'git push origin +feat/x:main'],
  ['hub push origin :main', 'git push origin :main'],
  ['hub push --force origin main', 'git push --force origin main'],
  ['hub push -f origin main', 'git push -f origin main'],
  ['hub -C repo push origin main', 'git -C repo push origin main'],
  ['hub -C repo push origin :main', 'git -C repo push origin :main'],
  ['/usr/local/bin/hub push origin main', 'git push origin main'],
  ['/usr/local/bin/hub push origin :main', 'git push origin :main'],
  ['bash -c "hub push origin main"', 'bash -c "git push origin main"'],
  ['bash -c -- "hub push origin :main"', 'bash -c "git push origin :main"'],
  ['hub -c remote.origin.mirror=true push origin feat/x', 'git -c remote.origin.mirror=true push origin feat/x'],
  ['hub --no-pager push origin :main', 'git --no-pager push origin :main'],
  ['true && hub push origin :main', 'true && git push origin :main'],
];

// Keep rows: the answer view each gave on BASE 48b1fbec80ab (decision|category|parse|reasons|risk). `bash -c "<body>"`, every
// other hub subcommand, data that only mentions the words, look-alikes, and the backend GR-A1..A4/GR-A7/GR-P rows.
const KEEP = [
  ["bash -c \"git push origin main\"", "pass|none|ok||git_push"],
  ["bash -c \"git push origin :main\"", "stop|S1|ok|git_push_delete_protected_branch|git_push"],
  ["sh -c 'git push --force origin feat/x'", "pass|none|ok||git_push"],
  ["bash -lc \"npm publish\"", "stop|S3|ok|npm_publish|"],
  ["zsh -fc \"rm -rf ~/x\"", "stop|S5|ok|rm_recursive_outside_workspace|"],
  ["script -qc \"git push origin main\" /dev/null", "pass|none|ok||git_push"],
  ["script -c \"npm publish\"", "stop|S3|ok|npm_publish|"],
  ["script --command=\"npm publish\"", "stop|S3|ok|npm_publish|"],
  ["script --command \"npm publish\"", "stop|S3|ok|npm_publish|"],
  ["bash -c \"echo hi\"", "pass|none|ok||"],
  ["bash -c \"$X\"", "stop|Sx|dynamic|dynamic_shell_code|"],
  ["bash -euc \"git push origin main\"", "pass|none|ok||git_push"],
  ["bash -o pipefail -euc \"git push origin :main\"", "stop|S1|ok|git_push_delete_protected_branch|git_push"],
  ["bash -x -c \"npm publish\"", "stop|S3|ok|npm_publish|"],
  ["bash -c 'exec \"$@\"' x git push origin :main", "stop|S1|dynamic|dynamic_command_word,git_push_delete_protected_branch|git_push"],
  ["bash scripts/build.sh", "pass|none|ok||"],
  ["bash -s", "pass|none|ok||"],
  ["echo npm publish | bash", "stop|S3|ok|npm_publish|"],
  ["hub status", "pass|none|ok||"],
  ["hub browse", "pass|none|ok||"],
  ["hub pull-request -m x", "pass|none|ok||"],
  ["hub api repos/o/r", "pass|none|ok||"],
  ["hub clone a/b", "pass|none|ok||"],
  ["hub sync", "pass|none|ok||"],
  ["hub release create v1", "pass|none|ok||"],
  ["hub ci-status", "pass|none|ok||"],
  ["hub fork", "pass|none|ok||"],
  ["hub", "pass|none|ok||"],
  ["hub $SUB origin main", "pass|none|dynamic||"],
  ["hub -C repo status", "pass|none|ok||"],
  ["echo \"bash -c -- git push origin main\"", "pass|none|ok||"],
  ["git commit -m \"hub push origin main\"", "pass|none|ok||"],
  ["grep -n \"hub push\" notes.md", "pass|none|ok||"],
  ["cat <<'EOF'\nbash -c -- \"npm publish\"\nhub push origin :main\nEOF", "pass|none|ok||"],
  ["printf '%s\\n' \"sh -c -x 'git push --force origin main'\"", "pass|none|ok||"],
  ["npm test -- --grep \"bash -c -- npm publish\"", "pass|none|ok||"],
  ["echo hub push origin :main | xargs echo", "pass|none|ok||"],
  ["git log --grep=\"hub push\"", "pass|none|ok||"],
  ["rg -n 'bash -c --' src", "pass|none|ok||"],
  ["bash -c −− \"git push origin :main\"", "pass|none|ok||"],
  ["ｈｕｂ push origin :main", "pass|none|ok||"],
  ["bash -c —— \"npm publish\"", "pass|none|ok||"],
  ["git push -on origin :main", "stop|S1|ok|git_push_delete_protected_branch|git_push"],
  ["git push -uon origin :main", "stop|S1|ok|git_push_delete_protected_branch|git_push"],
  ["git push -fon origin main", "stop|S1|ok|git_push_force_protected_branch|git_push"],
  ["git push -4on origin :main", "stop|S1|ok|git_push_delete_protected_branch|git_push"],
  ["git -C repo push -on origin :main", "stop|S1|ok|git_push_delete_protected_branch|git_push"],
  ["git -c user.name=x push -on origin :main", "stop|S1|ok|git_push_delete_protected_branch|git_push"],
  ["git clean -en", "pass|none|ok||"],
  ["git clean -fen", "pass|none|ok||"],
  ["git clean -e -n", "pass|none|ok||"],
  ["git push -o -n origin :main", "stop|S1|ok|git_push_delete_protected_branch|git_push"],
  ["git push --push-option -n origin :main", "stop|S1|ok|git_push_delete_protected_branch|git_push"],
  ["git push -o --dry-run origin :main", "stop|S1|ok|git_push_delete_protected_branch|git_push"],
  ["git push --repo -n :main", "stop|S1|ok|git_push_delete_protected_branch|git_push"],
  ["git commit -m --dry-run", "pass|none|ok||"],
  ["git add --pathspec-from-file -n", "pass|none|ok||"],
  ["git push -n --no-dry-run origin :main", "stop|S1|ok|git_push_delete_protected_branch|git_push"],
  ["git push --dry-run --no-dry-run origin :main", "stop|S1|ok|git_push_delete_protected_branch|git_push"],
  ["git push --no-dry-run -n origin :main", "stop|S1|ok|git_push_delete_protected_branch|git_push"],
  ["git push -nZ origin :main", "stop|S1|ok|git_push_delete_protected_branch|git_push"],
  ["git push -Zn origin :main", "stop|S1|ok|git_push_delete_protected_branch|git_push"],
  ["make -Cn deploy", "stop|S2|ok|make_unreadable_name|"],
  ["make -fn Makefile deploy", "stop|S2|ok|make_unreadable_name|"],
  ["rsync -aTn x src host:/dst", "pass|none|ok||"],
  ["rsync -en ssh src host:/dst", "pass|none|ok||"],
  ["cargo publish -pn", "stop|S3|ok|cargo_publish|"],
  ["just -fn justfile deploy", "stop|S2|ok|just_target_name|"],
  ["git -c remote.origin.mirror=true push origin feat/x", "stop|S1|ok|git_push_mirror_protected_branch|git_push"],
  ["git -c remote.origin.push=refs/heads/x:refs/heads/main push origin", "pass|none|ok||git_push"],
  ["git -c remote.origin.pushurl=https://example.invalid/r.git push origin feat/x", "stop|S1|ok|git_push_force_protected_branch|git_push"],
  ["git -c remote.origin.url=https://example.invalid/r.git push origin feat/x", "stop|S1|ok|git_push_force_protected_branch|git_push"],
  ["git -c Remote.Origin.PushURL=https://example.invalid/r.git push origin feat/x", "stop|S1|ok|git_push_force_protected_branch|git_push"],
  ["git -c include.path=/x/y push origin feat/x", "stop|S1|ok|git_push_force_protected_branch|git_push"],
  ["git -c includeIf.onbranch:feat.path=/x/y push origin feat/x", "stop|S1|ok|git_push_force_protected_branch|git_push"],
  ["git -c push.default=matching push origin", "pass|none|ok||git_push"],
  ["git -c branch.feat.pushRemote=other push", "pass|none|ok||git_push"],
  ["git -c x.y=1 -c remote.origin.mirror=true push origin feat/x", "stop|S1|ok|git_push_mirror_protected_branch|git_push"],
  ["git -c \"$CFG\" push origin feat/x", "pass|none|dynamic||"],
  ["git --config-env=remote.origin.mirror=X push origin feat/x", "stop|S1|dynamic|git_push_force_protected_branch|git_push"],
  ["git push -n origin main", "pass|none|ok||git_push"],
  ["git push --dry-run origin main", "pass|none|ok||git_push"],
  ["git push -fn origin main", "stop|S1|ok|git_push_force_protected_branch|git_push"],
  ["git push -nf origin main", "stop|S1|ok|git_push_force_protected_branch|git_push"],
  ["git push -no origin main", "pass|none|ok||git_push"],
  ["git push origin main -n", "pass|none|ok||git_push"],
  ["git clean -fdn", "pass|none|ok||"],
  ["git add -An", "pass|none|ok||"],
  ["git rm -rn x", "pass|none|ok||"],
  ["git commit --dry-run", "pass|none|ok||"],
  ["rsync -avn src/ dst/", "pass|none|ok||"],
  ["make -n", "pass|none|ok||"],
  ["cargo publish --dry-run", "pass|none|ok||"],
  ["cargo publish -n", "pass|none|ok||"],
  ["just -n deploy", "stop|S2|ok|just_target_name|"],
  ["bash -c \"git push origin feat/x\"", "pass|none|ok||git_push"],
  ["bash -lc \"npm test\"", "pass|none|ok||"],
  ["git -c user.name=Bot -c user.email=b@example.invalid commit -m x", "pass|none|ok||"],
  ["GIT_CONFIG_NOSYSTEM=1 git push origin feat/x", "pass|none|ok||git_push"],
  ["git push origin feat/x", "pass|none|ok||git_push"],
  ["git push origin main", "pass|none|ok||git_push"],
];

test('T-G5: a `--` after the c-cluster is skipped and the body answers as the form without it, in every chained place', () => {
  for (const form of DASHDASH) {
    for (const [name, wrap] of WRAPS) {
      const twin = wrap(form);
      if (twin === null) continue;
      assert.deepEqual(answer(read(twin)), answer(read(wrap(withoutDashDash(form)))), `${name}: ${twin}`);
    }
  }
});

test('T-G5: the `--` rows whose body is a stop are stopped (never a pass)', () => {
  for (const form of DASHDASH) {
    const plain = read(withoutDashDash(form));
    if (plain.decision !== 'stop') continue;
    for (const [name, wrap] of WRAPS) {
      const twin = wrap(form);
      if (twin === null) continue;
      const d = read(twin);
      assert.equal(d.decision, 'stop', `${name}: ${twin}`);
      for (const h of hitSet(plain)) assert.ok(hitSet(d).has(h) || name !== 'plain', `${twin} keeps ${h}`);
    }
  }
});

test('T-G5: an option word, a second `--` or a missing body where the body belongs is unreadable code: a stop, in every chained place', () => {
  for (const form of OPTION_WORD) {
    for (const [name, wrap] of WRAPS) {
      const twin = wrap(form);
      if (twin === null) continue;
      const d = read(twin);
      assert.equal(d.decision, 'stop', `${name}: ${twin}`);
      assert.notEqual(d.parse, 'ok', `${name}: ${twin} is not read as plain text`);
      assert.ok(d.reasons.includes('dynamic_shell_code'), `${name}: ${twin} carries the closed reason word`);
    }
  }
});

test('T-G5: the body comes after the option values of the cluster, and the word master read there is still read', () => {
  // bash runs `cmd` in `bash -co pipefail 'cmd'` (the value of o comes first); master read `pipefail` as the body.
  assert.deepEqual(answer(read('bash -co pipefail "npm publish"')), answer(read('bash -oc pipefail "npm publish"')));
  assert.equal(read('bash -co pipefail -- "git push origin :main"').decision, 'stop');
  // `xargs bash -c --` with a piped command: master's reading (the `--` word with the pipe) keeps its hit, besides the new stop.
  const d = read('echo "npm publish" | xargs bash -c --');
  assert.ok(d.reasons.includes('npm_publish') && d.reasons.includes('dynamic_shell_code'), d.reasons.join(','));
});

test('T-G4: hub push answers as git push (stop, category, reasons and risk tags)', () => {
  for (const [hub, git] of HUB) {
    const h = answer(read(hub));
    const g = answer(read(git));
    assert.deepEqual({ decision: h.decision, category: h.category, reasons: h.reasons, risk: h.risk }, { decision: g.decision, category: g.category, reasons: g.reasons, risk: g.risk }, hub);
  }
});

test('keep rows: bash -c "<body>", every other hub subcommand, data, look-alikes and the backend proof rows answer as on BASE', () => {
  assert.ok(KEEP.length >= 90);
  for (const [command, base] of KEEP) assert.equal(view(read(command)), base, command);
});

test('AB-T1/AB-T3 proof rows: no dry-run cluster or config spelling reads as a plain feature push or a no-push', () => {
  const plainFeature = view(read('git push origin feat/x'));
  for (const command of ['git push -on origin :main', 'git push -4on origin :main', 'git push -o -n origin :main', 'git push --no-dry-run -n origin :main', 'git push -Zn origin :main', 'hub push -on origin :main']) {
    assert.equal(read(command).decision, 'stop', command);
  }
  for (const command of ['git -c remote.origin.mirror=true push origin feat/x', 'git -c remote.origin.pushurl=https://example.invalid/r.git push origin feat/x',
    'git -c include.path=/x/y push origin feat/x', 'git -c includeIf.onbranch:feat.path=/x/y push origin feat/x', 'hub -c remote.origin.mirror=true push origin feat/x']) {
    assert.notEqual(view(read(command)), plainFeature, command);
    assert.equal(read(command).decision, 'stop', command);
  }
});

// ---- the real hook entrypoint (keyless and keyed), as a host runs it ----
let opensslOk = true;
try { execFileSync('openssl', ['version'], { stdio: 'ignore' }); } catch { opensslOk = false; }
const PASSWD = path.join(__dirname, 'support', 'passwd-home-fake.cjs');
const PRELOAD = path.join(__dirname, 'support', 'seatbelt-hook-preload.cjs');

// FX-HOME: every hook fixture lives inside the repo checkout, never in the machine's temp folder, so the
// home-delete rows answer the same on every machine. FX-CLEAN: removed in `finally` and again on process exit.
const WORK = path.join(ROOT, '.test-work');
const fixtures = new Set();
function dropFixture(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
  fixtures.delete(dir);
  try { fs.rmdirSync(WORK); } catch { /* another fixture still in use, or already gone */ }
}
process.on('exit', () => {
  for (const dir of [...fixtures]) { try { dropFixture(dir); } catch { /* best-effort cleanup */ } }
});

async function hookRun(commands, mode) {
  fs.mkdirSync(WORK, { recursive: true, mode: 0o700 });
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(WORK, 'marrow-twins-')));
  fixtures.add(dir);
  const home = path.join(dir, 'home');
  const proj = path.join(home, 'proj');
  fs.mkdirSync(proj, { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  const key = assertNotLiveKey(`zq${crypto.randomBytes(16).toString('hex')}`);
  let server = null;
  let bodies = [];
  try {
    if (mode !== 'keyless') {
      execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(dir, 'k.pem'), '-out', path.join(dir, 'c.pem'),
        '-days', '1', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
      server = https.createServer({ key: fs.readFileSync(path.join(dir, 'k.pem')), cert: fs.readFileSync(path.join(dir, 'c.pem')) }, (req, res) => {
        let raw = '';
        req.on('data', (c) => { raw += c; });
        req.on('end', () => {
          if (req.url === '/v1/agent/runtime') bodies.push(raw);
          if (mode === 'outage' && req.url === '/v1/agent/runtime') { res.writeHead(503, { 'content-type': 'application/json' }); res.end('{"error":"unavailable"}'); return; }
          res.writeHead(200, { 'content-type': 'application/json' });
          if (req.url === '/v1/agent/runtime') res.end(JSON.stringify({ data: { decision_id: 'decision-runtime', gate_receipt_id: 'gate-one', risk_gate: { allow: true, decision: 'allow', enforced: true, reasons: [] } } }));
          else if (req.url === '/v1/agent/enforcement') res.end(JSON.stringify({ data: { permit_id: 'permit-one', permit: 'signed-permit', verified: true } }));
          else res.end(JSON.stringify({ data: { accepted: true } }));
        });
      });
      await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    }
    const runOne = async (command, keyed) => {
      bodies = [];
      const env = { PATH: process.env.PATH, HOME: home, SBT_PASSWD_HOME: home, MARROW_HOOK_BACKGROUND_NUDGE: 'false', SBT_HOOK_DEADLINE: 'roomy' };
      if (process.env.NODE_OPTIONS) env.NODE_OPTIONS = process.env.NODE_OPTIONS;
      if (keyed) {
        Object.assign(env, { MARROW_API_KEY: key, MARROW_BASE_URL: `https://127.0.0.1:${server.address().port}`, NODE_EXTRA_CA_CERTS: path.join(dir, 'c.pem'),
          MARROW_AGENT_ID: 'agent-one', MARROW_SESSION_ID: 'session-one', MARROW_AUTO_HOOK: 'true' });
      }
      const child = spawn(process.execPath, ['--require', PASSWD, '--require', PRELOAD, path.join(ROOT, 'dist', 'cli.js'), 'claude-pre-action-hook'], { cwd: proj, env });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (c) => { stdout += c; });
      child.stderr.on('data', (c) => { stderr += c; });
      child.stdin.end(JSON.stringify({ hook_event_name: 'PreToolUse', session_id: 'session-one', tool_use_id: 'tool-one', tool_name: 'Bash', tool_input: { command }, cwd: proj }));
      const status = await new Promise((resolve) => child.on('close', resolve));
      assert.equal(`${stdout}${stderr}${bodies.join('')}`.includes(key), false, 'the dummy key never appears in hook output or a body');
      let j = null;
      try { j = stdout.trim() ? JSON.parse(stdout) : null; } catch { j = null; }
      return { command, status, deny: status === 2 || j?.hookSpecificOutput?.permissionDecision === 'deny', bodies: bodies.map((b) => JSON.parse(b)) };
    };
    // FX-PRE: before any row, the plain home delete must stop in this fixture (keyless, so no Marrow decides it).
    // The seatbelt reads a recursive delete under a temp root as scratch work; a fixture home there would turn
    // the home-delete rows into passes. Fail loudly; never skip a row or turn one off.
    const pre = await runOne('rm -rf ~/x', false);
    assert.ok(pre.status === 0 && pre.deny === true,
      'FX-PRE: the plain `rm -rf ~/x` passed in the fixture home: the fixture home reads as scratch (temp) on this machine, so the home-delete rows cannot be proven here');
    bodies = [];
    const out = [];
    for (const command of commands) out.push(await runOne(command, mode !== 'keyless'));
    return out;
  } finally {
    if (server) { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); }
    dropFixture(dir);
  }
}

const HOOK_STOPS = [
  'bash -lc -- "npm publish"', 'zsh -fc -- "rm -rf ~/x"', 'bash -c -- "git push origin :main"', "sh -c -x 'git push --force origin feat/x'",
  'hub push origin :main', 'hub push --force origin main', 'true && bash -c -- "npm publish"', 'script -qc -- "npm publish" /dev/null', 'bash -c +o "npm publish"',
];
const HOOK_SAME = ['echo "bash -c -- git push origin main"', 'grep -n "hub push" notes.md', 'git commit -m "hub push origin main"', 'bash -c "echo hi"', 'hub status', 'bash -c -- "echo hi"'];

test('the keyless hook rows are the round 1 rows: none removed, reworded or weakened', () => {
  assert.equal(HOOK_STOPS.length, 9);
  assert.equal(HOOK_SAME.length, 6);
  assert.equal(crypto.createHash('sha256').update(JSON.stringify([HOOK_STOPS, HOOK_SAME])).digest('hex'),
    'df8b171fda224bfbae6f5b7e7e9bdf79272224989dac05b584065b4d9fc59ca5');
});

test('keyless hook: the wrapped publish, delete and force push forms are stopped; data and plain forms pass', { timeout: 120_000 }, async () => {
  const out = await hookRun([...HOOK_STOPS, ...HOOK_SAME], 'keyless');
  for (const row of out) {
    assert.equal(row.status, 0, row.command);
    assert.equal(row.deny, HOOK_STOPS.includes(row.command), row.command);
  }
});

test('keyed hook, Marrow unreachable: the wrapped forms are held; keyed bodies carry the command as sent and nothing from the mapper', { skip: !opensslOk, timeout: 120_000 }, async () => {
  const held = ['bash -c -- "npm publish"', 'bash -c -- "git push origin main"', 'hub push --force origin main', 'hub push origin main'];
  const outage = await hookRun(held, 'outage');
  for (const row of outage) assert.equal(row.deny, true, `offline: ${row.command}`);
  const live = (await hookRun([...held, ...HOOK_SAME], 'keyed')).filter((row) => {
    assert.equal(row.deny, false, `reachable Marrow decides: ${row.command}`);
    assert.ok(row.bodies.length <= 1, row.command);
    assert.ok(row.bodies.length === 1 || !held.includes(row.command), `a runtime call for ${row.command}`);
    return row.bodies.length === 1;
  });
  for (const row of live) {
    const body = row.bodies[0];
    assert.equal(body.normalized_action.tool_input.command, row.command);
    assert.match(body.normalized_action.tool_input.command_sha256, /^[0-9a-f]{64}$/);
  }
  // COL: actions that differ outside a secret get different bodies and hashes.
  const hashes = live.map((row) => row.bodies[0].normalized_action.tool_input.command_sha256);
  assert.equal(new Set(hashes).size, hashes.length);
});
