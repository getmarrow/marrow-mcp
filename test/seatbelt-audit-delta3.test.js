// Regression tests from Barvis's delta audit of db578c2c (seatbelt U3/U4 patch round), copied from its evidence/delta3.test.cjs.
// Only change: AUDIT_DIST points at this repo's dist.
'use strict';
// Barvis delta audit (db578c2c): regression rows. No secrets. Payloads are harmless `echo`.
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
const { resolveSeatbeltModeOnHost } = require(`${D}/seatbelt-mode.js`);

const ROOT = fsn.realpathSync(fsn.mkdtempSync('/tmp/barvis-delta3-'));
let n = 0;
const fresh = () => { const d = join(ROOT, `d${n++}`); fsn.mkdirSync(d, { mode: 0o700 }); return d; };
const nfs = nodeSeatbeltFs();

test('R-F11 `env -S` shebang with a payload in the shebang line is classified `shell` (body parse cannot see it)', () => {
  const dir = fresh();
  const cases = {
    env_S_bash_c: '#!/usr/bin/env -S bash -c "echo PAYLOAD_RAN"\necho body\n',
    env_S_BASH_ENV: '#!/usr/bin/env -S BASH_ENV=./evil.sh bash\necho body\n',
    env_S_bash_plain: '#!/usr/bin/env -S bash -e\necho body\n',
  };
  fsn.writeFileSync(join(dir, 'evil.sh'), 'echo PAYLOAD_RAN_BASH_ENV\n');
  const out = {};
  for (const [name, text] of Object.entries(cases)) {
    const f = join(dir, `${name}.sh`); fsn.writeFileSync(f, text, { mode: 0o755 });
    let ran = '';
    try { ran = execFileSync(f, [], { cwd: dir, stdio: ['ignore', 'pipe', 'ignore'] }).toString(); } catch { ran = '(exec failed)'; }
    out[name] = { interpreter: S.readScriptFile(nfs, f).interpreter, payloadRan: /PAYLOAD_RAN/.test(ran) };
  }
  console.log(`# R-F11 ${JSON.stringify(out)}`);
  assert.equal(out.env_S_bash_plain.interpreter, 'shell');
  const hidden = Object.entries(out).filter(([, v]) => v.payloadRan && v.interpreter === 'shell');
  assert.deepEqual(hidden, [], 'a shebang payload runs while the script is handed to U2 as a plain shell body');
});

test('R-routine routine commands resolve the same as round 1 (definite, in_workspace, not protected, seatbelt on a clean home)', () => {
  const home = fresh(); const r = join(home, 'proj'); fsn.mkdirSync(r);
  const genv = { ...process.env, HOME: home, GIT_CONFIG_NOSYSTEM: '1' };
  execFileSync('git', ['init', '-q', '-b', 'feat', r], { env: genv });
  fsn.mkdirSync(join(r, 'node_modules')); fsn.mkdirSync(join(r, 'build')); fsn.writeFileSync(join(r, 'build/a.o'), '');
  fsn.writeFileSync(join(r, 'package.json'), JSON.stringify({ scripts: { build: 'tsc', test: 'node --test' } }));
  const cfg = G.loadGitConfig(nfs, { home, dirs: G.discoverGitDirs(nfs, r, { HOME: home }), env: { HOME: home }, systemFiles: [] });
  const ws = P.resolveWorkspace(nfs, { eventCwd: r, home });
  const cls = (raw) => P.classifyDeleteTarget(nfs, ws, P.resolveOperand(nfs, { home, cwd: r, shellHome: home }, raw, 'delete'));
  const out = {
    git_status: G.expandGitAliases(['status'], { config: cfg, env: { HOME: home } }).map((e) => e.kind),
    git_push_feat: G.isProtectedBranch(G.resolvePushRefspec('feat', { kind: 'branch', branch: 'feat' }).destination),
    git_push_feat_force: G.isProtectedBranch(G.resolvePushRefspec('+feat:feat', { kind: 'branch', branch: 'feat' }).destination),
    rm_node_modules: cls('node_modules'), rm_build_glob: cls('build/*'), rm_build_dot: cls('build/.'), rm_dist_missing: cls('dist'),
    npm_build: S.resolvePackageScript(nfs, r, 'build').status,
    mode_clean_home_eq: resolveSeatbeltModeOnHost({ fs: nfs, passwdHome: home, uid: process.getuid(), env: { HOME: home }, argv: ['pre-action-hook'] }).mode,
    config_incomplete_when_HOME_eq: cfg.incomplete,
  };
  console.log(`# R-routine ${JSON.stringify(out)}`);
  assert.deepEqual(out.git_status, ['git']);
  assert.equal(out.git_push_feat, false); assert.equal(out.git_push_feat_force, false);
  for (const k of ['rm_node_modules', 'rm_build_glob', 'rm_build_dot', 'rm_dist_missing']) assert.equal(out[k], 'in_workspace', k);
  assert.equal(out.mode_clean_home_eq, 'seatbelt');
  assert.equal(out.config_incomplete_when_HOME_eq, false);
});

test.after(() => { fsn.rmSync(ROOT, { recursive: true, force: true }); });
