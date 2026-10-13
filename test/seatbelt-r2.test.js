const assert = require('node:assert/strict');
const test = require('node:test');

// Patch round for Barvis's audit of 5069b1c6: one test per blocker edge the
// audit's own tests (seatbelt-audit-*.test.js) do not already pin.

const { createFakeFs } = require('./support/seatbelt-fake-fs.cjs');
const G = require('../dist/seatbelt-git.js');
const P = require('../dist/seatbelt-path.js');
const S = require('../dist/seatbelt-scripts.js');
const DEP = require('../dist/seatbelt-deploy.js');

const FEAT = { kind: 'branch', branch: 'feat' };

test('B2: push destinations resolve like ref_rev_parse_rules; every spelling of a protected branch is protected', () => {
  const protectedSpecs = [
    'main', 'refs/heads/main', 'heads/main', 'HEADS/main', 'Refs/heads/main', 'feat:main', 'feat:heads/main', '+feat:heads/main',
    '+heads/main', 'feat:heads/production', 'feat:refs/heads/heads/main', 'feat:tags/main', 'feat:remotes/origin/main',
    'feat:refs/remotes/origin/main', 'feat:main@{u}', 'feat:@{upstream}', 'feat:{main}', 'feat:main^{}', 'feat:ma..in',
    'feat:/main', 'feat:main/', 'feat:main.lock', 'feat:refs/tags/v1', 'feat:head', 'feat:FETCH_HEAD', 'HEAD:heads/feat',
  ];
  const bad = [];
  for (const spec of protectedSpecs) {
    const r = G.resolvePushRefspec(spec, FEAT);
    if (!r.all && !G.isProtectedBranch(r.destination)) bad.push(`${spec} -> ${r.destination}`);
  }
  assert.deepEqual(bad, []);
  assert.equal(G.resolvePushRefspec('refs/heads/main', FEAT).destination, 'main');
  assert.equal(G.resolvePushRefspec('heads/main', FEAT).destination, null);
  // Plain feature branches stay resolvable (not every name becomes protected).
  for (const [spec, dest] of [['feat:feature/x', 'feature/x'], ['HEAD:refs/heads/feature/y', 'feature/y'], ['feat', 'feat'], ['HEAD', 'feat']]) {
    const r = G.resolvePushRefspec(spec, FEAT);
    assert.equal(r.destination, dest, spec);
    assert.equal(G.isProtectedBranch(r.destination), false, spec);
  }
  assert.ok(G.GIT_PUSH_RISKY_OPTIONS.includes('prune'), 'F13: --prune deletes remote branches');
});

function repoFs() {
  return createFakeFs()
    .mkdir('/home/u')
    .file('/w/.git/HEAD', 'ref: refs/heads/feat\n')
    .file('/w/.git/config', '[alias]\n\tp = status\n')
    .file('/etc/gitconfig', '[alias]\n\tsys = push -f origin main\n')
    .file('/evil/config', '[alias]\n\tp = push -f origin main\n[remote "origin"]\n\tpush = +refs/heads/*:refs/heads/*\n');
}

test('B3: GIT_DIR and every relocating env make discovery unknown, config incomplete and expansion non-definite', () => {
  const fs = repoFs();
  for (const name of G.GIT_RELOCATING_ENV) {
    const env = { [name]: '/evil' };
    assert.equal(G.discoverGitDirs(fs, '/w', env), 'unknown', name);
    const config = G.loadGitConfig(fs, { home: '/home/u', dirs: G.discoverGitDirs(fs, '/w'), env, systemFiles: [] });
    assert.equal(config.incomplete, true, name);
    const exps = G.expandGitAliases(['p', 'origin'], { config, env });
    assert.ok(exps.some((e) => e.kind === 'unknown'), `${name}: ${JSON.stringify(exps.map((e) => e.kind))}`);
    assert.equal(G.implicitPushTargets(config, FEAT, 'origin').unknown, true, name);
  }
  // Without relocation the same alias is one definite answer.
  const clean = G.loadGitConfig(fs, { home: '/home/u', dirs: G.discoverGitDirs(fs, '/w'), env: {}, systemFiles: [] });
  assert.equal(clean.incomplete, false);
  assert.deepEqual(G.expandGitAliases(['p', 'origin'], { config: clean, env: {} }).map((e) => e.kind), ['git']);
  // -C / --git-dir / --work-tree on the command line, also inside an alias.
  for (const argv of [['-C', '/evil', 'p'], ['--git-dir=/evil', 'p'], ['--work-tree', '/x', 'push', 'origin', 'feat']]) {
    assert.ok(G.expandGitAliases(argv, { config: clean, env: {} }).some((e) => e.kind === 'unknown' && e.reason === 'relocated'), argv.join(' '));
  }
  const viaAlias = G.loadGitConfig(createFakeFs().mkdir('/home/u').file('/w/.git/HEAD', 'ref: refs/heads/feat\n').file('/w/.git/config', '[alias]\n\tq = -C /evil p\n'), { home: '/home/u', dirs: { gitDir: '/w/.git', commonDir: '/w/.git' }, systemFiles: [] });
  assert.ok(G.expandGitAliases(['q'], { config: viaAlias }).some((e) => e.kind === 'unknown' && e.reason === 'relocated'));
});

test('B3: GIT_CONFIG_GLOBAL/SYSTEM/GIT_CONFIG are added, never substituted; NOSYSTEM cannot drop the system file; relative paths and other HOME are incomplete', () => {
  const fs = repoFs().file('/g/cfg', '[alias]\n\tglob = push --mirror\n');
  const dirs = G.discoverGitDirs(fs, '/w');
  const load = (env) => G.loadGitConfig(fs, { home: '/home/u', dirs, env, systemFiles: ['/etc/gitconfig'] });
  for (const name of ['GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG']) {
    const c = load({ [name]: '/g/cfg' });
    assert.ok(G.gitConfigValues(c, 'alias.glob').length === 1, name);
    assert.ok(G.gitConfigValues(c, 'alias.sys').length === 1, `${name} keeps the default files`);
    assert.equal(load({ [name]: 'g/cfg' }).incomplete, true, `relative ${name}`);
  }
  for (const value of ['1', '0', 'true', '']) assert.ok(G.gitConfigValues(load({ GIT_CONFIG_NOSYSTEM: value }), 'alias.sys').length === 1, `NOSYSTEM=${value}`);
  assert.equal(load({ HOME: '/elsewhere' }).incomplete, true);
  assert.equal(load({ HOME: '/home/u' }).incomplete, false);
  assert.equal(load({ XDG_CONFIG_HOME: 'rel' }).incomplete, true);
  const xdg = repoFs().file('/x/git/config', '[alias]\n\tx = push -f\n');
  assert.equal(G.gitConfigValues(G.loadGitConfig(xdg, { home: '/home/u', env: { XDG_CONFIG_HOME: '/x' }, systemFiles: [] }), 'alias.x').length, 1);
});

test('G4: a bare repo, a cwd inside .git and a symlinked .git are found or unknown, never "no repo"', () => {
  const fs = createFakeFs().file('/b/HEAD', 'ref: refs/heads/main\n').mkdir('/b/objects').mkdir('/b/refs').file('/b/config', '[alias]\n\tp = push -f\n');
  assert.deepEqual(G.discoverGitDirs(fs, '/b'), { gitDir: '/b', commonDir: '/b' });
  const inside = createFakeFs().file('/w/.git/HEAD', 'ref: refs/heads/main\n').mkdir('/w/.git/objects').mkdir('/w/.git/refs/heads');
  assert.deepEqual(G.discoverGitDirs(inside, '/w/.git/refs/heads'), { gitDir: '/w/.git', commonDir: '/w/.git' });
  const linked = createFakeFs().mkdir('/real/.git').symlink('/w/.git', '/real/.git').mkdir('/w/src');
  assert.equal(G.discoverGitDirs(linked, '/w/src'), 'unknown');
  assert.equal(G.discoverGitDirs(createFakeFs().mkdir('/plain/dir'), '/plain/dir'), null);
});

test('F14: commands removed from upstream git keep the alias candidate', () => {
  for (const name of ['whatchanged', 'pack-redundant']) {
    assert.equal(G.GIT_CORE_BUILTINS.has(name), false);
    assert.equal(G.GIT_MAYBE_COMMANDS.has(name), true);
  }
});

function treeWithLinks() {
  return createFakeFs()
    .mkdir('/home/u/.ssh')
    .mkdir('/home/u/proj/.git')
    .mkdir('/home/u/proj/vendor/real/sub')
    .mkdir('/home/u/proj/build/a')
    .symlink('/home/u/proj/vendor/cache', '../..')
    .symlink('/home/u/proj/vendor/root', '/')
    .symlink('/home/u/proj/build/a/deep', '/home/u');
}

function cls(fs, raw, use = 'delete') {
  const ws = P.resolveWorkspace(fs, { eventCwd: '/home/u/proj', home: '/home/u' });
  return P.classifyDeleteTarget(fs, ws, P.resolveOperand(fs, { home: '/home/u', cwd: '/home/u/proj' }, raw, use));
}

test('B4: a glob is judged by every target it can reach through a link, at any depth', () => {
  const fs = treeWithLinks();
  assert.equal(cls(fs, 'vendor/*/'), 'root');
  assert.equal(cls(fs, 'vendor/*/.ssh'), 'outside_workspace', '~/.ssh and /.ssh through the links');
  assert.equal(cls(fs, 'vendor/c*/'), 'home');
  assert.equal(cls(fs, 'vendor/?ache/x'), 'outside_workspace');
  assert.equal(cls(fs, 'vendor/?ache/*'), 'home');
  assert.equal(cls(fs, 'vendor/[c]ache/'), 'home');
  assert.equal(cls(fs, 'build/*/*/'), 'home', 'link at the second wildcard level');
  assert.equal(cls(fs, 'build/*/deep/x'), 'outside_workspace');
  assert.equal(cls(fs, 'vendor/.*/'), 'workspace_root', 'bash <5.2: .* matches ..');
  // A final name without `/` is the link itself (rm removes the link): still inside.
  assert.equal(cls(fs, 'vendor/*'), 'in_workspace');
  // Names the pattern cannot match are not counted; plain dirs stay inside.
  assert.equal(cls(fs, 'vendor/r*l/'), 'in_workspace');
  assert.equal(cls(fs, 'vendor/real/*/'), 'in_workspace');
  assert.equal(cls(fs, 'vendor/x*/'), 'in_workspace');
  // Reads follow the final link.
  const read = P.resolveOperand(fs, { home: '/home/u', cwd: '/home/u/proj' }, 'vendor/*', 'read');
  assert.ok(read.kind === 'glob' && read.matches.includes('/') && read.matches.includes('/home/u'));
});

test('B4: a glob that cannot be enumerated for certain is unknown', () => {
  const big = treeWithLinks();
  for (let i = 0; i <= P.MAX_GLOB_ENTRIES; i += 1) big.mkdir(`/home/u/proj/many/d${i}`);
  assert.equal(cls(big, 'many/*/'), 'unknown');
  assert.equal(cls(treeWithLinks().fail('/home/u/proj/vendor/real'), 'vendor/*/x'), 'unknown');
  // Pathological patterns stay linear.
  const t = Date.now();
  cls(treeWithLinks(), `vendor/${'*a'.repeat(200)}b/`);
  assert.ok(Date.now() - t < 1000);
});

test('F12: a backslash left after quote removal is unknown', () => {
  assert.equal(cls(treeWithLinks(), '../x\\..\\proj\\sub'), 'unknown');
  assert.deepEqual(P.expandPathOperand('a\\b', { home: '/home/u', cwd: '/w' }), { kind: 'dynamic', reason: 'backslash' });
});

function makeOf(text) {
  const fs = createFakeFs().file('/w/Makefile', text);
  const t = process.hrtime.bigint();
  const heap = process.memoryUsage().heapUsed;
  const r = S.resolveMakeTargets(fs, '/w', ['deploy'], { env: {} });
  return { r, ms: Number(process.hrtime.bigint() - t) / 1e6, heapMB: (process.memoryUsage().heapUsed - heap) / 1e6 };
}

test('B6: the Makefile parse is linear and bounded from 1 KB to the 1 MB cap (mk.cjs shape); over budget is unknown', { timeout: 60000 }, () => {
  const rows = [];
  for (const kb of [1, 4, 16, 64, 256, 1000]) {
    // mk.cjs: k targets x k prerequisites on one rule, then a deploy rule.
    let k = 1;
    const shape = (n) => `${Array.from({ length: n }, (_, i) => `t${i}`).join(' ')}: ${Array.from({ length: n }, (_, i) => `p${i}`).join(' ')}\n\techo\ndeploy:\n\tvercel --prod\n`;
    while (shape(k * 2).length <= kb * 1024) k *= 2;
    const text = shape(k);
    const { r, ms, heapMB } = makeOf(text);
    rows.push({ shape: 'mk.cjs', bytes: text.length, targets: k, ms: Math.round(ms), heapMB: Math.round(heapMB), status: r.status });
    if (k > S.MAX_MAKE_TARGETS_PER_RULE) assert.equal(r.status, 'unknown', `${text.length} bytes`);
    else assert.ok(r.status === 'ok' && r.commands.includes('vercel --prod'));
    assert.ok(ms < 1500, `${text.length} bytes took ${ms} ms`);
    // Many small rules, each with its own prerequisites.
    const lines = [];
    let size = 0;
    for (let i = 0; size < kb * 1024; i += 1) {
      const line = `r${i}: q${i} s${i}\n\techo ${i}\n`;
      lines.push(line);
      size += line.length;
    }
    const many = `${lines.join('')}deploy: r0\n\tvercel --prod\n`;
    const m = makeOf(many);
    rows.push({ shape: 'rules', bytes: many.length, targets: lines.length, ms: Math.round(m.ms), heapMB: Math.round(m.heapMB), status: m.r.status });
    assert.ok(m.ms < 1500, `${many.length} bytes of rules took ${m.ms} ms`);
    assert.ok(m.r.status === 'unknown' || m.r.commands.includes('vercel --prod'));
  }
  // Nested variables cannot blow up expansion (deep nesting is dynamic, wide nesting hits the byte budget).
  const deep = Array.from({ length: 30 }, (_, i) => `V${i + 1} = $(V${i}) $(V${i})`).join('\n');
  const d = makeOf(`V0 = x\n${deep}\ndeploy:\n\techo $(V30)\n`);
  assert.ok(d.r.status === 'unknown' || d.r.dynamic);
  assert.ok(d.ms < 1500);
  const wide = Array.from({ length: 6 }, (_, i) => `W${i + 1} = ${`$(W${i}) `.repeat(64)}`).join('\n');
  const w = makeOf(`W0 = xxxxxxxx\n${wide}\ndeploy:\n\techo $(W6)\n`);
  assert.equal(w.r.status, 'unknown');
  assert.ok(w.ms < 1500);
  console.log(`# B6 timings ${JSON.stringify(rows)}`);
});

test('F11: env shebangs with options and assignments name the real interpreter', () => {
  // Round 3 (N5): `-i PATH=/bin bash` was listed here as a shell. A NAME=value word changes the
  // interpreter's environment (BASH_ENV, ENV, PATH ...), so it is no longer understood: unknown.
  for (const line of ['#!/usr/bin/env -S bash -e', '#!/usr/bin/env -Sbash -e', '#!/usr/bin/env -u X bash', '#!/usr/bin/env -i bash', '#! /bin/bash -e', '#!/usr/bin/env bash']) {
    const fs = createFakeFs().file('/s/x.sh', `${line}\nvercel --prod\n`);
    assert.equal(S.readScriptFile(fs, '/s/x.sh').interpreter, 'shell', line);
  }
  assert.deepEqual(S.readScriptFile(createFakeFs().file('/s/x.sh', '#!/usr/bin/env -i PATH=/bin bash\nvercel --prod\n'), '/s/x.sh'), { status: 'unknown', reason: 'shebang' });
  assert.equal(S.readScriptFile(createFakeFs().file('/s/x', '#!/usr/bin/env -S python3\n'), '/s/x').interpreter, 'other');
});

test('F9: relative or JSON KUBECONFIG, a missing current-context and context env are unknown', () => {
  const kube = 'current-context: staging\ncontexts:\n- name: staging\n  context:\n    namespace: dev\n';
  const fs = createFakeFs().file('/home/u/.kube/config', kube).file('/k/json', '{"current-context":"prod"}').file('/k/none', 'clusters: []\n');
  assert.equal(DEP.readKubeContexts(fs, '/home/u').status, 'ok');
  assert.equal(DEP.readKubeContexts(fs, '/home/u', './evil.yaml').status, 'unknown');
  assert.equal(DEP.readKubeContexts(fs, '/home/u', '/k/json').status, 'unknown');
  assert.equal(DEP.readKubeContexts(createFakeFs().file('/home/u/.kube/config', 'clusters: []\n'), '/home/u').status, 'unknown');
  assert.equal(DEP.readKubeContexts(createFakeFs().file('/home/u/.kube/config', 'current-context: ""\n'), '/home/u').status, 'unknown');
  assert.equal(DEP.readKubeContexts(fs, '/home/u', undefined, { KUBECONTEXT: 'prod' }).status, 'unknown');
});

test('F10: deploy-relocating env makes every reader unknown; wrangler returns per-env worker names and routes', () => {
  const fs = createFakeFs()
    .file('/d/wrangler.toml', 'name = "api"\nroute = "api.example.invalid/*"\n[env.staging]\nname = "api"\n[env.dev]\n')
    .file('/d/.vercel/project.json', '{}')
    .file('/d/fly.toml', 'app = "a"\n')
    .file('/d/.firebaserc', '{"projects":{"default":"p"}}')
    .file('/d/samconfig.toml', '[default.deploy.parameters]\nstack_name = "s"\n')
    .file('/d/.sst/stage', 'dev')
    .file('/d/.terraform/environment', 'staging')
    .file('/home/u/.config/gcloud/configurations/config_default', '[core]\nproject = p\n');
  const readers = {
    wrangler: (env) => DEP.readWranglerConfig(fs, '/d', undefined, env),
    vercel: (env) => DEP.readVercelLink(fs, '/d', env),
    fly: (env) => DEP.readFlyConfig(fs, '/d', undefined, env),
    firebase: (env) => DEP.readFirebaseProjects(fs, '/d', env),
    sam: (env) => DEP.readSamConfig(fs, '/d', env),
    sst: (env) => DEP.readSstStage(fs, '/d', env),
    terraform: (env) => DEP.readTerraformWorkspace(fs, '/d', env),
    gcloud: (env) => DEP.readGcloudProject(fs, '/home/u', env),
  };
  for (const [tool, read] of Object.entries(readers)) {
    assert.equal(read({}).status, 'ok', tool);
    for (const name of DEP.DEPLOY_RELOCATING_ENV[tool]) assert.equal(read({ [name]: 'x' }).status, 'unknown', `${tool} ${name}`);
  }
  const w = DEP.readWranglerConfig(fs, '/d');
  assert.deepEqual(w.targets, [
    { environment: null, name: 'api', routes: ['api.example.invalid/*'] },
    { environment: 'staging', name: 'api', routes: [] },
    { environment: 'dev', name: 'api-dev', routes: [] },
  ]);
  const json = createFakeFs().file('/d/wrangler.json', '{"name":"api","routes":[{"pattern":"a.example.invalid/*"}],"env":{"staging":{"routes":["a.example.invalid/*"]}}}');
  assert.deepEqual(DEP.readWranglerConfig(json, '/d').targets[1], { environment: 'staging', name: 'api-staging', routes: ['a.example.invalid/*'] });
  assert.equal(DEP.readWranglerConfig(createFakeFs().file('/d/wrangler.json', '{"routes":[1]}'), '/d').status, 'unknown');
  assert.equal(DEP.readWranglerConfig(createFakeFs().file('/d/wrangler.toml', 'name = "a"\nroutes = [ "x/*" ]\n'), '/d').status, 'unknown');
});

test('adversarial pass: git exec vectors are reported by name only (no subsection, URL or value)', () => {
  const token = `dummy_${require('node:crypto').randomBytes(8).toString('hex')}`;
  const fs = createFakeFs().mkdir('/home/u').file('/w/.git/HEAD', 'ref: refs/heads/feat\n')
    .file('/w/.git/config', `[core]\n\tsshCommand = ssh -i x\n[url "https://u:${token}@example.invalid/"]\n\tinsteadOf = gh:\n[alias]\n\ts = !sh\n\tp = status\n[diff "x"]\n\ttextconv = cat\n`);
  const config = G.loadGitConfig(fs, { home: '/home/u', dirs: G.discoverGitDirs(fs, '/w'), systemFiles: [] });
  const vectors = G.gitExecVectors(config, { GIT_SSH_COMMAND: 'x', GIT_PAGER: 'y' });
  assert.deepEqual(vectors.sort(), ['GIT_PAGER', 'GIT_SSH_COMMAND', 'alias.*', 'core.sshcommand', 'diff.*.textconv', 'url.*.insteadof']);
  assert.ok(!JSON.stringify(vectors).includes(token));
  assert.deepEqual(G.gitExecVectors(G.loadGitConfig(createFakeFs().mkdir('/home/u'), { home: '/home/u', systemFiles: [] }), {}), []);
});

test('adversarial pass: globstar, extglob and zsh patterns are unknown, never a single-level guess', () => {
  const fs = treeWithLinks();
  for (const raw of ['vendor/**/x', 'vendor/**/', '@(vendor)/', '!(src)', 'vendor/+(cache)/', 'vendor/(cache|real)/', 'vendor/<1-9>/', 'vendor/*(@)', '^src', 'vendor/c#/']) {
    assert.equal(cls(fs, raw), 'unknown', raw);
  }
  assert.equal(cls(fs, 'vendor/real/sub'), 'in_workspace');
});
