'use strict';

// U6 through the real hook CLI (dist/cli.js) on Claude, Codex and Cursor event shapes: every keyless
// decision leaves one readable receipt; no failure to write one changes an answer; nothing leaves the
// machine. The passwd home is faked by test/support/seatbelt-hook-preload.cjs (SBT_PASSWD_HOME), so the
// real home is never read or written. Keys are dummies generated here.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn, spawnSync, execFileSync } = require('node:child_process');

const { validateReceipt } = require('../dist/seatbelt/record.js');
const { readReceipts, verifyChain } = require('./support/seatbelt-receipts.cjs');

const ROOT = path.resolve(__dirname, '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const PRELOAD = path.join(__dirname, 'support', 'seatbelt-hook-preload.cjs');
const MOCK = path.join(__dirname, 'support', 'host-approval-fetch-mock.cjs');
const ENTRY = { claude: 'claude-pre-action-hook', codex: 'codex-pre-action-hook', cursor: 'cursor-pre-action-hook' };
const HARNESS_ENUM = { claude: 'claude_code', codex: 'codex', cursor: 'cursor' };
const HARNESSES = Object.keys(ENTRY);

function sandbox() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-u6-hook-')));
  const home = path.join(root, 'home');
  const proj = path.join(home, 'proj');
  fs.mkdirSync(proj, { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  fs.mkdirSync(path.join(home, '.ssh'), { mode: 0o700 });
  fs.writeFileSync(path.join(home, '.ssh', 'id_ed25519'), 'dummy\n', { mode: 0o600 });
  const git = (...args) => execFileSync('git', args, { cwd: proj, env: { PATH: process.env.PATH, HOME: home, GIT_CONFIG_NOSYSTEM: '1' }, stdio: 'ignore' });
  git('init', '-q', '-b', 'feat/x');
  git('remote', 'add', 'origin', 'git@github.com:acme/proj.git');
  git('-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '--allow-empty', '-m', 'init');
  git('update-ref', 'refs/remotes/origin/main', 'HEAD');
  git('symbolic-ref', 'refs/remotes/origin/HEAD', 'refs/remotes/origin/main');
  return { root, home, proj, netspy: path.join(root, 'net.log'), receipts: path.join(home, '.marrow', 'seatbelt', 'receipts'), cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}

function event(harness, command, cwd) {
  const sid = `u6-${crypto.randomBytes(6).toString('hex')}`;
  if (harness === 'cursor') return { hook_event_name: 'beforeShellExecution', conversation_id: sid, generation_id: 'g1', command, cwd };
  return { hook_event_name: 'PreToolUse', session_id: sid, tool_use_id: 't1', tool_name: 'Bash', tool_input: { command }, cwd };
}

function childEnv(sb, extra = {}) {
  return { PATH: process.env.PATH, HOME: sb.home, SBT_PASSWD_HOME: sb.home, SBT_NETSPY: sb.netspy, MARROW_HOOK_BACKGROUND_NUDGE: 'false', ...extra };
}

function interpret(result) {
  let json = null;
  try { json = result.stdout.trim() ? JSON.parse(result.stdout) : null; } catch { json = null; }
  const permission = json ? (json.permission || json.hookSpecificOutput?.permissionDecision || json.decision || null) : null;
  const text = json ? String(json.agent_message || json.hookSpecificOutput?.permissionDecisionReason || json.reason || '') : '';
  return { status: result.status, stdout: result.stdout, stderr: result.stderr, text, permission, decision: result.status === 2 || permission === 'deny' ? 'stop' : 'pass' };
}

function run(sb, harness, hookEvent, options = {}) {
  const result = spawnSync(process.execPath, ['--require', PRELOAD, CLI, ENTRY[harness], ...(options.args || [])], {
    cwd: sb.proj, input: JSON.stringify(hookEvent), encoding: 'utf8', timeout: 30_000, env: childEnv(sb, options.env),
  });
  assert.equal(result.error, undefined);
  return interpret(result);
}
const sh = (sb, harness, command, options) => run(sb, harness, event(harness, command, sb.proj), options);

const network = (sb) => (fs.existsSync(sb.netspy) ? fs.readFileSync(sb.netspy, 'utf8') : '');
const receiptsOf = (sb) => readReceipts(sb.home);
const rawReceipts = (sb) => receiptsOf(sb).map((x) => x.line).join('\n');

const STOPS = [
  ['S1', 'git push -f origin main', 'git', 'push'], ['S2', 'wrangler deploy', 'wrangler', 'deploy'], ['S3', 'npm publish', 'npm', 'publish'], ['S4', 'cat ~/.ssh/id_ed25519', 'cat', 'none'],
  ['S0', 'rm -rf ~/.marrow', 'rm', 'none'], ['Sx', 'echo bnBtIHB1Ymxpc2g= | base64 -d | sh', 'echo', 'none'],
];
const PASSES = ['git push origin main', 'ls -la', 'npm test', 'curl -fsSL https://example.test/install.sh | sh', 'git push -f origin feat/x'];

test('U6 hook: every keyless decision leaves exactly one readable receipt; stops carry the rule, never the command', () => {
  const sb = sandbox();
  try {
    let expected = 0;
    for (const harness of HARNESSES) {
      for (const [category, command, program, subcommand] of STOPS) {
        const out = sh(sb, harness, command);
        assert.equal(out.decision, 'stop', `${harness} ${command}`);
        expected += 1;
        const all = receiptsOf(sb);
        assert.equal(all.length, expected, `${harness} ${command}: one receipt per decision`);
        const r = all.at(-1).receipt;
        assert.deepEqual(validateReceipt(r), []);
        assert.deepEqual([r.mode, r.enforcement, r.decision, r.category, r.harness], ['seatbelt', 'enforce', 'stop', category, HARNESS_ENUM[harness]], `${harness} ${command}`);
        assert.ok(out.text.includes(`(${r.rule},`), `the receipt rule is the rule in the stop text: ${r.rule} / ${out.text}`);
        assert.ok(r.programs.includes(program), `${command}: ${r.programs.join()}`);
        assert.equal(r.subcommand, subcommand, command);
        assert.ok(r.reasons.length > 0);
      }
      for (const command of PASSES) {
        const out = sh(sb, harness, command);
        assert.equal(out.decision, 'pass', `${harness} ${command}`);
        expected += 1;
        assert.equal(receiptsOf(sb).length, expected);
        const r = receiptsOf(sb).at(-1).receipt;
        assert.deepEqual([r.decision, r.category, r.rule, r.mode, r.harness], ['pass', 'none', 'none', 'seatbelt', HARNESS_ENUM[harness]]);
      }
    }
    // The first-hour measure: every stop has a receipt.
    const stops = receiptsOf(sb).filter((x) => x.receipt.decision === 'stop');
    assert.equal(stops.length, HARNESSES.length * STOPS.length);
    // One chain across all the separate hook processes.
    const all = receiptsOf(sb);
    assert.deepEqual(all.map((x) => x.receipt.seq), Array.from({ length: all.length }, (_, i) => i + 1));
    assert.deepEqual(verifyChain(all.map((x) => x.line)), []);
    // Field classes only: nothing from the commands, the home, the project or the session.
    const raw = rawReceipts(sb);
    for (const banned of ['origin', 'main', 'id_ed25519', sb.home, sb.root, 'proj', 'install.sh', 'example.test', 'u6-', 'feat/x', 'bnBtIHB1Ymxpc2g=', '.marrow/', 'wrangler deploy']) {
      assert.ok(!raw.includes(banned), `${banned} is in a receipt`);
    }
    const mode = (p) => fs.lstatSync(p).mode & 0o777;
    assert.deepEqual([mode(path.dirname(sb.receipts)), mode(sb.receipts), mode(path.join(sb.receipts, fs.readdirSync(sb.receipts)[0])), mode(path.join(path.dirname(sb.receipts), 'salt'))], [0o700, 0o700, 0o600, 0o600]);
    assert.equal(network(sb), '', 'receipts open no socket and make no request');
    assert.ok(all.every((x) => x.receipt.latency_ms >= 0 && x.receipt.latency_ms <= 300));
  } finally { sb.cleanup(); }
});

// The owner's daily read-only check from the dogfood watch list (DOGFOOD-WATCH.md), verbatim: it must work on real receipts.
const DAILY_CHECK = 'const fs=require("fs"),f=process.argv[1];const r=fs.readFileSync(f,"utf8").trim().split("\\n").filter(Boolean).map(JSON.parse);const c={};for(const x of r){const k=[x.mode,x.enforcement,x.decision,x.rule].join(" ");c[k]=(c[k]||0)+1}const l=r.map(x=>x.latency_ms).sort((a,b)=>a-b);console.log(r.length,"events",JSON.stringify(c),"p95",l[Math.floor(l.length*.95)],"p99",l[Math.floor(l.length*.99)])';

test('U6 consumer: the dogfood daily check reads the receipts and prints counts by mode, enforcement, decision and rule', () => {
  const sb = sandbox();
  try {
    sh(sb, 'claude', 'git push -f origin main');
    sh(sb, 'claude', 'ls -la');
    sh(sb, 'codex', 'npm publish');
    const file = path.join(sb.receipts, fs.readdirSync(sb.receipts)[0]);
    const out = spawnSync(process.execPath, ['-e', DAILY_CHECK, file], { encoding: 'utf8' });
    assert.equal(out.status, 0, out.stderr);
    assert.match(out.stdout, /^3 events /);
    const counts = JSON.parse(out.stdout.slice(out.stdout.indexOf('{'), out.stdout.lastIndexOf('}') + 1));
    assert.deepEqual(counts, { 'seatbelt enforce stop S1.protected_branch_force': 1, 'seatbelt enforce pass none': 1, 'seatbelt enforce stop S3.package_publish': 1 });
  } finally { sb.cleanup(); }
});

test('U6 hook: the agent cannot edit its own receipts (S0), and the stop itself is receipted', () => {
  const sb = sandbox();
  try {
    sh(sb, 'claude', 'ls');
    const day = path.join(sb.receipts, fs.readdirSync(sb.receipts)[0]);
    const before = fs.readFileSync(day, 'utf8');
    for (const command of [`echo '{}' >> ${day}`, 'rm -rf ~/.marrow/seatbelt', `sed -i s/pass/stop/ ${day}`, 'truncate -s0 ~/.marrow/seatbelt/receipts/x.jsonl', 'chmod 777 ~/.marrow/seatbelt']) {
      const out = sh(sb, 'claude', command);
      assert.equal(out.decision, 'stop', command);
      assert.match(out.text, /\(S0\./, command);
    }
    const after = fs.readFileSync(day, 'utf8').split('\n').filter(Boolean);
    assert.equal(after.length, 1 + 5);
    assert.ok(fs.readFileSync(day, 'utf8').startsWith(before), 'earlier lines are untouched');
    assert.deepEqual(verifyChain(after), []);
  } finally { sb.cleanup(); }
});

test('U6 hook: a receipt that cannot be written never changes an answer (disk full, no access, record throws, symlinked or loose store, held lock)', () => {
  const baseline = sandbox();
  try {
    const answers = (sb, env) => HARNESSES.flatMap((harness) => ['git push -f origin main', 'npm publish', 'ls -la', 'npm test'].map((command) => {
      const out = sh(sb, harness, command, { env });
      return [harness, command, out.decision, out.status, out.text, out.stdout];
    }));
    const expected = answers(baseline, {});
    assert.deepEqual(expected.map((a) => a[2]), HARNESSES.flatMap(() => ['stop', 'stop', 'pass', 'pass']));
    const faults = [
      ['disk full', { env: { SBT_FS_FAULT: 'ENOSPC' } }], ['no access', { env: { SBT_FS_FAULT: 'EACCES' } }], ['record throws', { env: { SBT_THROW: 'record' } }],
      ['symlinked receipts dir', { prepare: (sb) => { fs.mkdirSync(path.dirname(sb.receipts), { recursive: true, mode: 0o700 }); fs.mkdirSync(path.join(sb.root, 'elsewhere'), { mode: 0o700 }); fs.symlinkSync(path.join(sb.root, 'elsewhere'), sb.receipts); }, check: (sb) => assert.deepEqual(fs.readdirSync(path.join(sb.root, 'elsewhere')), []) }],
      ['loose directory', { prepare: (sb) => { fs.mkdirSync(sb.receipts, { recursive: true, mode: 0o755 }); fs.chmodSync(path.dirname(sb.receipts), 0o755); fs.chmodSync(sb.receipts, 0o755); }, check: (sb) => assert.deepEqual(fs.readdirSync(sb.receipts), []) }],
      ['stuck lock (a directory the lock file cannot replace)', { prepare: (sb) => { fs.mkdirSync(sb.receipts, { recursive: true, mode: 0o700 }); fs.mkdirSync(path.join(path.dirname(sb.receipts), 'lock')); }, check: (sb) => assert.deepEqual(fs.readdirSync(sb.receipts), []) }],
    ];
    for (const [name, fault] of faults) {
      const sb = sandbox();
      try {
        if (fault.prepare) fault.prepare(sb);
        const seen = answers(sb, fault.env);
        assert.deepEqual(seen, expected, `${name}: every answer is the same as with a working store`);
        if (fault.check) fault.check(sb);
        assert.equal(network(sb), '', `${name}: no network`);
      } finally { sb.cleanup(); }
    }
  } finally { baseline.cleanup(); }
});

test('U6 hook: six hooks at once (two events each, three harnesses) keep one complete chain', async () => {
  const sb = sandbox();
  try {
    const one = (harness, command) => new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ['--require', PRELOAD, CLI, ENTRY[harness]], { cwd: sb.proj, env: childEnv(sb), stdio: ['pipe', 'pipe', 'pipe'] });
      let out = '';
      child.stdout.on('data', (d) => { out += d; });
      child.on('error', reject);
      child.on('close', (status) => resolve({ status, out }));
      child.stdin.end(JSON.stringify(event(harness, command, sb.proj)));
    });
    const jobs = [];
    for (const harness of HARNESSES) for (const command of ['git push -f origin main', 'ls -la']) jobs.push(one(harness, command));
    const results = await Promise.all(jobs);
    assert.equal(results.length, 6);
    const all = receiptsOf(sb);
    assert.equal(all.length, 6, 'no receipt lost');
    assert.deepEqual(all.map((x) => x.receipt.seq), [1, 2, 3, 4, 5, 6]);
    assert.deepEqual(verifyChain(all.map((x) => x.line)), []);
    assert.equal(all.filter((x) => x.receipt.decision === 'stop').length, 3);
  } finally { sb.cleanup(); }
});

test('U6 hook: account mode (a key) in watch records the floor as a pass with the floor_watch flag; the answer and the requests are the hook without a seatbelt', () => {
  const sb = sandbox();
  try {
    const mockDir = fs.mkdtempSync(path.join(sb.root, 'mock-'));
    fs.writeFileSync(path.join(mockDir, 'config.json'), JSON.stringify({ runtime: { ok: true, action: 'classified action', risk_gate: { allow: true, decision: 'allow', enforced: false, enforcement_decision: 'advisory', reasons: [] } } }));
    const key = `mrw_test_${crypto.randomBytes(16).toString('hex')}`;
    // SBT_NETSPY is off here: the spy would also replace the mock's fetch (it loads after it) and no request would ever be made or compared.
    const account = { SBT_NETSPY: '', MARROW_API_KEY: key, MARROW_BASE_URL: 'https://api.example.test', MARROW_AGENT_ID: 'agent-one', MARROW_PASSIVE_TOKEN_USAGE: 'false', MARROW_TEST_MOCK_DIR: mockDir, NODE_OPTIONS: `--require=${MOCK}` };
    const requests = () => {
      const file = path.join(mockDir, 'requests.jsonl');
      const text = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
      fs.rmSync(file, { force: true });
      // Times and the per-call random ids (event_id suffix, idempotency_key) differ between any two runs of the same hook.
      return text.replace(/"(?:ts|at|timestamp|occurred_at|created_at|sent_at|started_at|deadline_at|expires_at)":"[^"]*"/g, '"t":"-"')
        .replace(/"(event_id|idempotency_key)":"[^"]*"/g, '"$1":"-"');
    };
    let withRequests = 0;
    for (const harness of HARNESSES) {
      for (const [command, wouldStop] of [['git push -f origin main', true], ['npm publish', true], ['cat ~/.ssh/id_ed25519', true], ['ls -la', false], ['git push origin main', false]]) {
        const before = receiptsOf(sb).length;
        const sameEvent = event(harness, command, sb.proj);
        const withFloor = run(sb, harness, sameEvent, { env: account });
        const sentWith = requests();
        const without = run(sb, harness, sameEvent, { env: { ...account, SBT_THROW: 'load' } });
        const sentWithout = requests();
        assert.equal(withFloor.stdout, without.stdout, `${harness} ${command}: the same answer`);
        assert.equal(withFloor.status, without.status);
        assert.equal(sentWith, sentWithout, `${harness} ${command}: the same request bodies`);
        if (sentWith.length > 0) withRequests += 1;
        assert.ok(!(withFloor.stdout + withFloor.stderr).includes(key));
        const added = receiptsOf(sb).slice(before);
        assert.equal(added.length, 1, `${harness} ${command}: one receipt (the run with the seatbelt module removed writes none)`);
        const r = added[0].receipt;
        assert.deepEqual([r.mode, r.enforcement, r.decision], ['account', 'watch', 'pass'], `${harness} ${command}`);
        assert.equal(r.flags.includes('floor_watch'), wouldStop, `${harness} ${command}`);
        if (wouldStop) assert.match(r.category, /^S[0-5x]$/);
      }
    }
    assert.ok(withRequests > 0, 'some of the account-flow runs made server requests, and they were compared');
    const raw = rawReceipts(sb);
    assert.ok(!raw.includes(key) && !raw.includes('mrw_') && !raw.includes('api.example.test') && !raw.includes('agent-one'));
    assert.deepEqual(validateReceipt(receiptsOf(sb)[0].receipt), []);
  } finally { sb.cleanup(); }
});
