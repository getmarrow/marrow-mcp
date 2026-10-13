'use strict';

// Latency of the real hook process with receipts off vs on (not a test; run by hand or by the gate):
//   node test/support/seatbelt-u6-bench.cjs [events=100]
// Each round runs the same event twice, once with the record hook stubbed out (SBT_RECORD, as the U5 tests do)
// and once with the receipt writer, in a scratch passwd home. Prints wall-clock percentiles of the whole
// hook process and the seatbelt path's own latency_ms from the receipts. Prints counts and times only.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync, execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..', '..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const PRELOAD = path.join(__dirname, 'seatbelt-hook-preload.cjs');
const N = Number(process.argv[2] || 100);
const COMMANDS = ['ls -la', 'git status', 'npm test', 'git push origin feat/x', 'rm -rf node_modules dist', 'git push -f origin main', 'npm publish', 'cat ~/.ssh/id_ed25519', 'wrangler deploy', 'git diff --stat'];

const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'marrow-u6-bench-')));
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

function once(command, stub) {
  const input = JSON.stringify({ hook_event_name: 'PreToolUse', session_id: `bench-${crypto.randomBytes(4).toString('hex')}`, tool_use_id: 't', tool_name: 'Bash', tool_input: { command }, cwd: proj });
  const env = { PATH: process.env.PATH, HOME: home, SBT_PASSWD_HOME: home, MARROW_HOOK_BACKGROUND_NUDGE: 'false' };
  if (stub) env.SBT_RECORD = path.join(root, 'stub.jsonl');
  const start = process.hrtime.bigint();
  const result = spawnSync(process.execPath, ['--require', PRELOAD, CLI, 'claude-pre-action-hook'], { cwd: proj, input, encoding: 'utf8', timeout: 30_000, env });
  const ms = Number(process.hrtime.bigint() - start) / 1e6;
  if (result.error || (result.status !== 0)) throw new Error(`hook failed: ${result.status}`);
  return ms;
}

const pct = (list, p) => { const s = [...list].sort((a, b) => a - b); return Math.round(s[Math.min(s.length - 1, Math.floor(s.length * p))] * 10) / 10; };
const stats = (list) => ({ n: list.length, p50: pct(list, 0.5), p95: pct(list, 0.95), p99: pct(list, 0.99), max: pct(list, 1) });

const off = [];
const on = [];
for (let i = 0; i < N; i += 1) {
  const command = COMMANDS[i % COMMANDS.length];
  off.push(once(command, true));
  on.push(once(command, false));
}
const dir = path.join(home, '.marrow', 'seatbelt', 'receipts');
const receipts = fs.readdirSync(dir).flatMap((name) => fs.readFileSync(path.join(dir, name), 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line)));
const own = receipts.map((r) => r.latency_ms);
console.log(JSON.stringify({
  events: N, receipts: receipts.length, stops: receipts.filter((r) => r.decision === 'stop').length,
  process_ms_receipts_off: stats(off), process_ms_receipts_on: stats(on), seatbelt_path_latency_ms: stats(own),
  added_ms: { p50: Math.round((pct(on, 0.5) - pct(off, 0.5)) * 10) / 10, p95: Math.round((pct(on, 0.95) - pct(off, 0.95)) * 10) / 10 },
}));
fs.rmSync(root, { recursive: true, force: true });
