// Regression tests from Barvis's delta audit of db578c2c (seatbelt U3/U4 patch round), copied from its evidence/delta2.test.cjs.
// Only change: AUDIT_DIST points at this repo's dist.
'use strict';
// Barvis delta audit (db578c2c): follow-ups to delta.test.cjs. No secrets.
const assert = require('node:assert/strict');
const test = require('node:test');
const fsn = require('node:fs');
const { join } = require('node:path');
const { execFileSync } = require('node:child_process');
const D = require('node:path').join(__dirname, '..', 'dist');
const { nodeSeatbeltFs } = require(`${D}/seatbelt-fs.js`);
const G = require(`${D}/seatbelt-git.js`);
const P = require(`${D}/seatbelt-path.js`);
const S = require(`${D}/seatbelt-scripts.js`);

const ROOT = fsn.realpathSync(fsn.mkdtempSync('/tmp/barvis-delta2-'));
let n = 0;
const fresh = () => { const d = join(ROOT, `d${n++}`); fsn.mkdirSync(d, { mode: 0o700 }); return d; };
const nfs = nodeSeatbeltFs();
const gitEnv = (home) => ({ ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, '.config'), GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' });
const show = (exps) => exps.map((e) => e.kind === 'git' ? `git ${e.invocation.subcommand} ${e.invocation.args.join(' ')}` : `${e.kind}:${e.reason || e.command || ''}`);
const risky = (exps) => exps.some((e) => e.kind !== 'git' || e.invocation.subcommand !== 'status');

test('N2 -c include.path / GIT_CONFIG_COUNT include.path override a benign repo alias (git uses the last definition)', () => {
  const home = fresh(); const r = fresh(); const env = gitEnv(home);
  execFileSync('git', ['init', '-q', '-b', 'feat', r], { env });
  execFileSync('git', ['-C', r, 'config', 'alias.k', 'status'], { env });
  const inc = join(fresh(), 'inc.cfg'); fsn.writeFileSync(inc, '[alias]\n\tk = push -f origin main\n');
  const o1 = execFileSync('git', ['-c', `include.path=${inc}`, 'config', '--get', 'alias.k'], { cwd: r, env }).toString().trim();
  const o2 = execFileSync('git', ['config', '--get', 'alias.k'], { cwd: r, env: { ...env, GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'include.path', GIT_CONFIG_VALUE_0: inc } }).toString().trim();
  const cfg = (e) => G.loadGitConfig(nfs, { home, dirs: G.discoverGitDirs(nfs, r, e), env: e, systemFiles: [] });
  const e2 = { GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'include.path', GIT_CONFIG_VALUE_0: inc };
  const x1 = G.expandGitAliases(['-c', `include.path=${inc}`, 'k'], { config: cfg({}), env: {} });
  const x2 = G.expandGitAliases(['k'], { config: cfg(e2), env: e2 });
  console.log(`# N2 oracle -c="${o1}" oracle COUNT="${o2}" resolver -c=${JSON.stringify(show(x1))} resolver COUNT=${JSON.stringify(show(x2))}`);
  assert.equal(o1, 'push -f origin main');
  assert.ok(risky(x1), '-c include.path: definite `git status` while git runs push -f');
  assert.ok(risky(x2), 'GIT_CONFIG_COUNT include.path: definite `git status` while git runs push -f');
});

test('N3 `PWD=<elsewhere>; rm -rf ~+/x` uses the shell PWD (bash oracle) but the resolver uses the event cwd', () => {
  const home = fresh(); const r = join(home, 'proj'); fsn.mkdirSync(join(r, '.git'), { recursive: true });
  const oracle = execFileSync('bash', ['-c', 'cd "$1"; PWD="$2"; printf %s ~+/.ssh', '_', r, home]).toString();
  const ws = P.resolveWorkspace(nfs, { eventCwd: r, home });
  const c = P.classifyDeleteTarget(nfs, ws, P.resolveOperand(nfs, { home, cwd: r, variables: { PWD: home } }, '~+/.ssh', 'delete'));
  const cDollar = P.classifyDeleteTarget(nfs, ws, P.resolveOperand(nfs, { home, cwd: r, variables: { PWD: home } }, '$PWD/.ssh', 'delete'));
  console.log(`# N3 oracle=${oracle === `${home}/.ssh` ? '$HOME/.ssh' : oracle} resolver(~+/.ssh)=${c} resolver($PWD/.ssh)=${cDollar}`);
  assert.notEqual(c, 'in_workspace');
});

test('N4 multi-word variable as a prerequisite: `STEPS = build deploy` / `all: $(STEPS)` (GNU make splits words)', () => {
  const dir = fresh();
  fsn.writeFileSync(join(dir, 'Makefile'), 'STEPS = build deploy\nall: $(STEPS)\nbuild:\n\techo build\ndeploy:\n\tvercel --prod\n');
  const res = S.resolveMakeTargets(nfs, dir, ['all']);
  const res2 = S.resolveMakeTargets(nfs, dir, ['all'], { overrides: { STEPS: 'build deploy' } });
  console.log(`# N4 resolver=${JSON.stringify(res.status === 'ok' ? { commands: res.commands, dynamic: res.dynamic } : res)} override=${JSON.stringify(res2.status === 'ok' ? { commands: res2.commands, dynamic: res2.dynamic } : res2)}`);
  assert.ok(res.status !== 'ok' || res.dynamic || res.commands.some((c) => /vercel/.test(c)), 'definite ok without the vercel recipe');
});

test.after(() => { fsn.rmSync(ROOT, { recursive: true, force: true }); });
