'use strict';

// F2 (host matrix 10-13): a keyed high-risk action was allowed as "Marrow is offline" although the
// Worker had answered (runtime 200, then the permit service 503 with safe_to_continue:false). Every
// host shares the one control path, so all 7 hook entries are driven through the real CLI with the
// recorded production-shaped bodies (test/support/f2-fetch-scenarios.cjs). A reached answer is
// honored; a real outage holds high-risk actions (the server's failure_mode:
// fail_closed_for_high_risk) and keeps the outage allow for routine ones. Dummy key generated here.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync, execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const PASSWD = path.join(__dirname, 'support', 'passwd-home-fake.cjs');
const SCENARIOS = path.join(__dirname, 'support', 'f2-fetch-scenarios.cjs');
// Test-only preload (never packed): a spawned hook gets a 30 s seatbelt budget unless a test sets SBT_SLOW_MS or
// SBT_HOOK_BUDGET=production. Without it these hosts ran on the production 300 ms budget, which a loaded suite
// run overruns (an overrun is "unknown", and the outage hold then keeps the classifier's answer).
const PRELOAD = path.join(__dirname, 'support', 'seatbelt-hook-preload.cjs');
const { MARROW_OUTAGE_WARNING, HELD_OFFLINE_TEXT, classifyTool, outageHolds } = require('../dist/hook-pre-action.js');
const recorded = require('./fixtures/f2-recorded-force-push.json');

const SHAPES = {
  claude: (c, cwd) => ({ hook_event_name: 'PreToolUse', session_id: 'f2-claude', tool_use_id: 't1', tool_name: 'Bash', tool_input: { command: c }, cwd }),
  codex: (c, cwd) => ({ hook_event_name: 'PreToolUse', session_id: 'f2-codex', turn_id: 't1', tool_use_id: 't1', tool_name: 'Bash', tool_input: { command: c }, cwd }),
  cursor: (c, cwd) => ({ hook_event_name: 'beforeShellExecution', conversation_id: 'f2-cursor', generation_id: 'g1', command: c, cwd }),
  gemini: (c, cwd) => ({ session_id: 'f2-gemini', hook_event_name: 'BeforeTool', tool_name: 'run_shell_command', tool_input: { command: c }, cwd }),
  grok: (c, cwd) => ({ hookEventName: 'PreToolUse', sessionId: 'f2-grok', toolUseId: 't', toolName: 'run_terminal_command', toolInput: { command: c }, cwd }),
  cline: (c, cwd) => ({ hookName: 'PreToolUse', taskId: 'f2-cline', workspaceRoots: [cwd], preToolUse: { toolName: 'execute_command', parameters: { command: c } } }),
  windsurf: (c, cwd) => ({ agent_action_name: 'pre_run_command', trajectory_id: 'f2-windsurf', execution_id: 'e1', tool_info: { command_line: c, cwd } }),
};
const HOSTS = Object.keys(SHAPES);
// The 7 hosts every outage test below must drive. A host dropped from SHAPES would silently shrink every loop.
const ALL_HOSTS = ['claude', 'codex', 'cursor', 'gemini', 'grok', 'cline', 'windsurf'];
const HIGH = 'git push --force origin main';
const ROUTINE = 'mkdir -p build/out';

// Hosts driven since the last driven.clear(): an outage test that loops HOSTS must have reached all 7.
const driven = new Set();
function assertAllHostsDriven() {
  assert.deepEqual([...driven].sort(), [...ALL_HOSTS].sort(), 'every one of the 7 hosts was driven');
  driven.clear();
}

const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-f2-')));
test.after(() => fs.rmSync(base, { recursive: true, force: true }));
let n = 0;

function hook(host, command, scenario, prep = null, extraEnv = {}) {
  driven.add(host);
  const home = path.join(base, `h${n += 1}`);
  const proj = path.join(home, 'proj');
  fs.mkdirSync(proj, { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  execFileSync('git', ['init', '-q', '-b', 'main'], { cwd: proj, stdio: 'ignore' });
  if (prep) prep(proj);
  const logFile = path.join(home, 'calls.log');
  const key = `mrw_test_${crypto.randomBytes(16).toString('hex')}`;
  const r = spawnSync(process.execPath, ['--require', PASSWD, '--require', PRELOAD, '--require', SCENARIOS, CLI, `${host}-pre-action-hook`], {
    cwd: proj, input: JSON.stringify(SHAPES[host](command, proj)), encoding: 'utf8', timeout: 30_000,
    env: {
      PATH: process.env.PATH, HOME: home, SBT_PASSWD_HOME: home, MARROW_API_KEY: key, MARROW_BASE_URL: 'https://api.example.test',
      MARROW_HOOK_BACKGROUND_NUDGE: 'false', F2_SCENARIO: scenario, F2_LOG: logFile, ...extraEnv,
    },
  });
  assert.equal(r.error, undefined);
  const all = `${r.stdout}\n${r.stderr}`;
  assert.equal(all.includes(key), false, 'the key never appears in hook output');
  let j = null;
  try { j = r.stdout.trim() ? JSON.parse(r.stdout) : null; } catch { j = null; }
  const stop = r.status === 2 || j?.hookSpecificOutput?.permissionDecision === 'deny' || j?.permission === 'deny' || j?.decision === 'deny' || j?.cancel === true;
  const calls = fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8').trim().split('\n').filter(Boolean) : [];
  return { stop, status: r.status, out: all, json: j, calls };
}

test('F2 classification: the force push is high risk and the routine command is medium on the shared classifier', () => {
  assert.equal(classifyTool({ tool_name: 'Bash', tool_input: { command: HIGH } }).risk, 'high');
  assert.equal(classifyTool({ tool_name: 'Bash', tool_input: { command: ROUTINE } }).risk, 'medium');
  // The recorded server answer itself states the failure mode the fix follows.
  assert.equal(recorded.runtime.data.failure_mode.if_marrow_unreachable, 'fail_closed_for_high_risk');
  assert.equal(recorded.enforcement_issue.status, 503);
  assert.equal(recorded.enforcement_issue.body.details.safe_to_continue, false);
});

test('F2 (recorded bodies): runtime 200 then permit 503 denies the keyed force push on all 7 hosts, never "offline, allowed"', () => {
  for (const host of HOSTS) {
    const r = hook(host, HIGH, 'permit-503');
    assert.equal(r.stop, true, `${host}: ${r.out.slice(0, 300)}`);
    assert.equal(r.out.includes(MARROW_OUTAGE_WARNING), false, `${host} must not claim an outage`);
    assert.equal(r.out.includes(HELD_OFFLINE_TEXT), false, `${host}: Marrow answered, so it is not "cannot be reached"`);
    assert.doesNotMatch(r.out, /This action is allowed/, host);
    assert.deepEqual(r.calls.filter((c) => /runtime|enforcement/.test(c)).slice(0, 2), ['/v1/agent/runtime', '/v1/agent/enforcement#issue'], host);
  }
});

test('F2: every other failure after the gate answered (think 503/reset, permit 502, verify reset) denies on all 7 hosts', () => {
  for (const scenario of ['think-503', 'think-reset', 'permit-502', 'verify-reset']) {
    for (const host of HOSTS) {
      const r = hook(host, HIGH, scenario);
      assert.equal(r.stop, true, `${scenario} ${host}: ${r.out.slice(0, 300)}`);
      assert.equal(r.out.includes(MARROW_OUTAGE_WARNING), false, `${scenario} ${host}`);
      assert.equal(r.out.includes(HELD_OFFLINE_TEXT), false, `${scenario} ${host}`);
      assert.ok(r.calls.includes('/v1/agent/runtime'), `${scenario} ${host} reached the gate`);
    }
  }
});

test('F2: a failure after the gate answered keeps the outage policy for a routine action (Windsurf, Gemini, Grok need a permit for every mutation)', () => {
  for (const scenario of ['permit-503', 'verify-reset', 'think-503']) {
    for (const host of HOSTS) {
      const r = hook(host, ROUTINE, scenario);
      assert.equal(r.stop, false, `${scenario} ${host}: ${r.out.slice(0, 300)}`);
    }
  }
});

test('F2: a real outage (refused, DNS, runtime 503) holds the high-risk action on all 7 hosts', () => {
  driven.clear();
  for (const scenario of ['runtime-refused', 'runtime-dns', 'runtime-503']) {
    for (const host of HOSTS) {
      const r = hook(host, HIGH, scenario);
      assert.equal(r.stop, true, `${scenario} ${host}: ${r.out.slice(0, 300)}`);
      assert.doesNotMatch(r.out, /This action is allowed/, `${scenario} ${host}`);
      if (['claude', 'codex', 'cursor', 'cline'].includes(host)) assert.ok(r.out.includes(HELD_OFFLINE_TEXT), `${scenario} ${host}: ${r.out.slice(0, 300)}`);
    }
  }
  assertAllHostsDriven();
});

test('F2: a real outage keeps the outage allow for routine and read-only actions', () => {
  driven.clear();
  for (const scenario of ['runtime-refused', 'runtime-503']) {
    for (const host of HOSTS) {
      const r = hook(host, ROUTINE, scenario);
      assert.equal(r.stop, false, `${scenario} ${host}: ${r.out.slice(0, 300)}`);
      if (['claude', 'codex', 'cursor', 'windsurf'].includes(host)) assert.ok(r.out.includes(MARROW_OUTAGE_WARNING), `${scenario} ${host}`);
    }
  }
  for (const host of HOSTS) assert.equal(hook(host, 'ls -la', 'runtime-refused').stop, false, `ls -la ${host}`);
  assertAllHostsDriven();
});

test('F2: a server allow with a verified permit is honored on all 7 hosts (the fix only changes failures)', () => {
  for (const host of HOSTS) {
    const r = hook(host, HIGH, 'permit-ok');
    assert.equal(r.stop, false, `${host}: ${r.out.slice(0, 300)}`);
    assert.ok(r.calls.includes('/v1/agent/enforcement#verify'), host);
  }
});

// I3 (owner decision on the audit of abf9926b): during a real outage only an action the seatbelt
// mapper reads as high-risk is held: an S0-S5/S-x hit, or a program on the outage list (git push,
// publish, deploy, remote delete). Words in a message, a path or a comment never hold a shell command.
// Never looser than master, which allowed every action in an outage; F2 part 1 is unchanged above.
test('I3 outageHolds: the mapper reading decides a shell command; anything it cannot read keeps the classifier answer', () => {
  assert.equal(outageHolds(false, () => ({ shell: true, risk: 'high' })), true);
  assert.equal(outageHolds(false, () => ({ shell: false, risk: 'high' })), true);
  assert.equal(outageHolds(true, () => ({ shell: true, risk: 'not_high' })), false);
  assert.equal(outageHolds(true, () => ({ shell: false, risk: 'not_high' })), true, 'a non-shell tool keeps F2');
  assert.equal(outageHolds(true, () => ({ shell: true, risk: 'unknown' })), true);
  assert.equal(outageHolds(false, () => ({ shell: true, risk: 'unknown' })), false);
  assert.equal(outageHolds(true, () => { throw new Error('mapper crash'); }), true);
  assert.equal(outageHolds(false, () => { throw new Error('mapper crash'); }), false);
});

const I3_ALLOWED = [
  // Words in messages, echo text, paths and comments (the audit's word false positives).
  'git commit -m "npm publish to prod"', 'mkdir -p /tmp/production/x', 'echo "git push -f origin main"', 'cat docs/production-deploy.md',
  'git commit -am "rm -rf / deploy"', 'echo publish', 'ls -la # deploy to production', 'grep -rn "wrangler deploy" docs',
  // Routine local work.
  'rm -rf node_modules dist', 'npm test', 'git reset --hard HEAD~1', 'git clean -fdx', 'terraform plan', 'kubectl get pods',
  'npm publish --dry-run', 'git branch -D old', 'curl -X POST https://api.example.test/v1/x', 'rm -rf /tmp/build-123',
  // A dynamic argument after a listed program's subcommand is not a dynamic subcommand.
  'npm install "$PKG"', 'docker run --rm "$IMG"', 'terraform plan -var "env=$ENV"',
];
const I3_HELD = [
  // The program list, with chains, wrappers, variables, aliases, repeated and unknown flags.
  'git push origin main', 'git push -f origin feat/x', 'git push --frob origin feat/x', 'ls && git push origin main', 'false || git push origin main',
  'echo ok; git push origin main', 'bash -c "git push origin main"', 'sh -c \'npm publish\'', 'X=push; git $X origin main', 'git -c alias.p=push p origin main',
  '(cd . && git push origin main)', 'env GIT_TRACE=1 git push origin main', 'timeout 60 npx wrangler deploy', 'npm publish', 'npm publish --dry-run --dry-run=false',
  'pnpm publish', 'yarn npm publish', 'npm unpublish pkg@1.0.0', 'docker push acme/app:1', 'wrangler deploy --env staging', 'wrangler deploy --env production',
  'vercel', 'vercel --prod', 'fly deploy', 'terraform apply -auto-approve', 'terraform destroy', 'pulumi up --yes', 'gh pr merge 5 --squash',
  'curl -X DELETE https://api.example.test/v1/users/1', 'curl -X GET -X DELETE https://api.example.test/v1/users/1', 'heroku releases:rollback v12 -a app',
  'kubectl --context prod delete deployment api', 'rm -rf /var/lib/app', 'python3 -c "import shutil;shutil.rmtree(\'/etc\')"',
  // A listed program whose subcommand word is dynamic may be the listed one.
  'wrangler "$CMD"', 'terraform $(cat action.txt) -auto-approve', 'vercel "$1"', 'docker "$CMD" acme/app:1', 'fly "$CMD"', 'heroku "$CMD" -a app',
];
// Cline and Windsurf send no cwd, so the mapper cannot place a relative `rm -rf` or `git clean` in the
// workspace: an S5 hit (unknown directory), held in an outage there as F2 and the keyless seatbelt do.
const I3_NO_CWD_HOSTS = new Set(['cline', 'windsurf']);
const I3_CWD_RELATIVE = new Set(['rm -rf node_modules dist', 'git clean -fdx']);

test('I3: a real outage allows routine shell commands whose only high-risk signal is a word, on all 7 hosts', () => {
  driven.clear();
  const wrong = [];
  for (const command of I3_ALLOWED) {
    for (const host of HOSTS) {
      const r = hook(host, command, 'runtime-refused');
      if (I3_NO_CWD_HOSTS.has(host) && I3_CWD_RELATIVE.has(command)) {
        if (!r.stop) wrong.push(`${host}: ${command}: expected the no-cwd hold`);
        continue;
      }
      if (r.stop || r.out.includes(HELD_OFFLINE_TEXT)) wrong.push(`${host}: ${command}: ${r.out.replace(/\s+/g, ' ').slice(0, 160)}`);
    }
  }
  assert.deepEqual(wrong, []);
  assertAllHostsDriven();
});

// The hosts above run on the test preload's 30 s hook budget, so load cannot flip their answers. The production
// budget keeps this test: SBT_SLOW_MS makes the preload leave HOOK_BUDGET_MS at 300, a mapper that overruns it is
// "unknown", and the outage hold then keeps the client classifier's answer (`git branch -D old` is high there).
// A slow mapper can only hold more, never less, so load cannot make this test flaky.
test('I3: the production 300 ms hook budget still applies in an outage: an overrun holds a high-classified command (fail closed), a routine one keeps flowing', () => {
  assert.equal(require('../dist/seatbelt/hook.js').HOOK_BUDGET_MS, 300, 'the production budget is 300 ms; only the test preload gives a spawned hook 30 s');
  assert.equal(classifyTool({ tool_name: 'Bash', tool_input: { command: 'git branch -D old' } }).risk, 'high');
  driven.clear();
  const wrong = [];
  for (const host of HOSTS) {
    const slow = { SBT_SLOW_MS: '400' };
    const held = hook(host, 'git branch -D old', 'runtime-refused', null, slow);
    if (!held.stop) wrong.push(`${host}: git branch -D old was not held when the mapper overran 300 ms: ${held.out.replace(/\s+/g, ' ').slice(0, 160)}`);
    const flows = hook(host, ROUTINE, 'runtime-refused', null, slow);
    if (flows.stop) wrong.push(`${host}: ${ROUTINE} was held when the mapper overran 300 ms: ${flows.out.replace(/\s+/g, ' ').slice(0, 160)}`);
  }
  assert.deepEqual(wrong, []);
  assertAllHostsDriven();
});

test('I3: a real outage holds the outage-list programs and S-class commands on all 7 hosts (chains, wrappers, variables, aliases, flags)', () => {
  driven.clear();
  const wrong = [];
  for (const command of I3_HELD) {
    for (const host of HOSTS) {
      const r = hook(host, command, 'runtime-refused');
      if (!r.stop || /This action is allowed/.test(r.out)) wrong.push(`${host}: ${command}: ${r.out.replace(/\s+/g, ' ').slice(0, 160)}`);
    }
  }
  assert.deepEqual(wrong, []);
  // A package script that publishes is read through package.json.
  const prep = (proj) => fs.writeFileSync(path.join(proj, 'package.json'), JSON.stringify({ name: 'p', version: '1.0.0', scripts: { release: 'npm publish' } }));
  for (const host of HOSTS) assert.equal(hook(host, 'npm run release', 'runtime-refused', prep).stop, true, `npm run release ${host}`);
  assertAllHostsDriven();
});

// T-1 (delta audit of 0368537c): a command the mapper cannot fully read (a dynamic argument), with no hit
// and no outage-list program, keeps the client classifier's answer in an outage: high is held.
const T1_UNKNOWN_HIGH = ['psql "$DB" -c "DROP TABLE users"', 'mysql -h "$HOST" -e "drop database prod"', 'redis-cli -h "$H" FLUSHALL',
  'aws ec2 terminate-instances --instance-ids "$ID"'];

test('T-1: an outage holds a high-risk command the mapper reads as unknown (dynamic argument), on all 7 hosts', () => {
  driven.clear();
  const wrong = [];
  for (const command of T1_UNKNOWN_HIGH) {
    assert.equal(classifyTool({ tool_name: 'Bash', tool_input: { command } }).risk, 'high', command);
    for (const host of HOSTS) {
      const r = hook(host, command, 'runtime-refused');
      if (!r.stop || /This action is allowed/.test(r.out)) wrong.push(`${host}: ${command}: ${r.out.replace(/\s+/g, ' ').slice(0, 160)}`);
    }
  }
  assert.deepEqual(wrong, []);
  assertAllHostsDriven();
});

// T-3 (delta audit of 0368537c): asking a listed CLI for its help only prints text, so an outage does not
// hold it. Only the exact minimal shapes count (`<cli> --help`, `<cli> --version`, `<cli> <listed sub> --help`);
// any other word, a git option before the subcommand, chains, wrappers, substitutions and redirections
// keep their hold.
const T3_ALLOWED = ['git push --help', 'npm publish --help', 'wrangler deploy --help', 'terraform apply --help', 'vercel --version'];
const T3_HELD = ['git -c core.pager=sh push --help', 'git -C /tmp push --help', 'git --exec-path=/tmp push --help', 'git --git-dir=/tmp/x push --help',
  'npm publish --help --otp=123456', 'npm publish --help && git push origin main', '$(echo npm) publish --help', 'git push -f origin main --help',
  'git push origin main -- --help', 'sudo npm publish --help', 'env npm publish --help', 'npm publish --help > /tmp/x', 'npx wrangler deploy --help',
  'NPM_CONFIG_DRY_RUN=false npm publish --help', 'npm publish --help=false', 'helm upgrade api ./chart --version 1.2.3', 'wrangler deploy --version',
  'f() { npm publish; }; f --help', 'git push --help | sh', 'bash -c "npm publish --help"', 'docker push acme/app:1 --help',
  'kubectl --context prod delete deployment api --help'];

test('T-3: in an outage, --help on a listed CLI is never held (all 7 hosts); the abuse forms around it stay held', () => {
  driven.clear();
  const wrong = [];
  for (const command of T3_ALLOWED) {
    for (const host of HOSTS) {
      const r = hook(host, command, 'runtime-refused');
      if (r.stop || r.out.includes(HELD_OFFLINE_TEXT)) wrong.push(`allowed ${host}: ${command}: ${r.out.replace(/\s+/g, ' ').slice(0, 160)}`);
    }
  }
  for (const command of T3_HELD) {
    for (const host of HOSTS) {
      const r = hook(host, command, 'runtime-refused');
      if (!r.stop || /This action is allowed/.test(r.out)) wrong.push(`held ${host}: ${command}: ${r.out.replace(/\s+/g, ' ').slice(0, 160)}`);
    }
  }
  assert.deepEqual(wrong, []);
  assertAllHostsDriven();
});
