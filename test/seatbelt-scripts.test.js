const assert = require('node:assert/strict');
const test = require('node:test');

const { createFakeFs } = require('./support/seatbelt-fake-fs.cjs');
const { resolvePackageScript, packageCommands, PUBLISH_LIFECYCLE, resolveMakeTargets, readScriptFile, MAX_SCRIPT_BYTES } = require('../dist/seatbelt-scripts.js');
const {
  readWranglerConfig, readVercelLink, readFlyConfig, readFirebaseProjects, readKubeContexts,
  readSamConfig, readSstStage, readTerraformWorkspace, readGcloudProject, parseJsonc,
} = require('../dist/seatbelt-deploy.js');

const PKG = JSON.stringify({ name: 'p', scripts: { predeploy: 'npm test', deploy: 'vercel --prod', postdeploy: 'echo done', ship: 'npm run deploy', prepublishOnly: 'changeset publish', test: 'jest' } });

test('A12 package scripts: pre/main/post from the nearest package.json (npm prefix walk)', () => {
  const fs = createFakeFs().file('/p/package.json', PKG).mkdir('/p/sub/deep');
  const r = resolvePackageScript(fs, '/p/sub/deep', 'deploy');
  assert.equal(r.status, 'ok');
  assert.equal(r.packageDir, '/p');
  assert.deepEqual(r.commands, [{ name: 'predeploy', command: 'npm test' }, { name: 'deploy', command: 'vercel --prod' }, { name: 'postdeploy', command: 'echo done' }]);
  assert.deepEqual(resolvePackageScript(fs, '/p', 'ship').commands.map((c) => c.command), ['npm run deploy']);
  assert.deepEqual(resolvePackageScript(fs, '/p', 'missing').commands, []);
  assert.deepEqual(packageCommands(fs, '/p', PUBLISH_LIFECYCLE).commands, [{ name: 'prepublishOnly', command: 'changeset publish' }]);
});

test('package scripts: absent, malformed, non-string, unreadable, oversized and FIFO manifests', () => {
  assert.deepEqual(resolvePackageScript(createFakeFs().mkdir('/q'), '/q', 'x'), { status: 'absent' });
  assert.equal(resolvePackageScript(createFakeFs().file('/q/package.json', '{nope'), '/q', 'x').status, 'unknown');
  assert.equal(resolvePackageScript(createFakeFs().file('/q/package.json', '{"scripts":{"x":1}}'), '/q', 'x').status, 'unknown');
  assert.equal(resolvePackageScript(createFakeFs().file('/q/package.json', '{"scripts":[]}'), '/q', 'x').status, 'unknown');
  assert.equal(resolvePackageScript(createFakeFs().file('/q/package.json', PKG).fail('/q/package.json'), '/q', 'deploy').status, 'unknown');
  assert.equal(resolvePackageScript(createFakeFs().file('/q/package.json', 'x'.repeat(1024 * 1024 + 1)), '/q', 'x').status, 'unknown');
  assert.equal(resolvePackageScript(createFakeFs().fifo('/q/package.json'), '/q', 'x').status, 'unknown');
});

test('package scripts: a symlinked package.json is followed (realpath)', () => {
  const fs = createFakeFs().file('/real/package.json', PKG).symlink('/p/package.json', '/real/package.json');
  assert.deepEqual(resolvePackageScript(fs, '/p', 'deploy').commands.map((c) => c.command), ['npm test', 'vercel --prod', 'echo done']);
});

const MAKEFILE = `STAGE ?= dev
DEPLOY = vercel --prod
.PHONY: release ship build
release: build
\t@$(DEPLOY)
build:
\tnpm run build
ship: ; wrangler deploy --env $(STAGE)
cost:
\techo $$HOME
`;

test('A12 Makefile: recipes, prerequisites, variables and command-line overrides', () => {
  const fs = createFakeFs().file('/m/Makefile', MAKEFILE);
  assert.deepEqual(resolveMakeTargets(fs, '/m', ['release']), { status: 'ok', makefile: '/m/Makefile', commands: ['npm run build', 'vercel --prod'], dynamic: false });
  assert.deepEqual(resolveMakeTargets(fs, '/m', []).commands, ['npm run build', 'vercel --prod']);
  assert.deepEqual(resolveMakeTargets(fs, '/m', ['ship']).commands, ['wrangler deploy --env dev']);
  assert.deepEqual(resolveMakeTargets(fs, '/m', ['ship'], { overrides: { STAGE: 'production' } }).commands, ['wrangler deploy --env production']);
  assert.deepEqual(resolveMakeTargets(fs, '/m', ['cost']).commands, ['echo $HOME']);
  assert.equal(resolveMakeTargets(fs, '/m', ['nosuch']).dynamic, true);
});

test('Makefile: include, conditionals, unknown variables, pattern rules and -f are dynamic or honoured', () => {
  const inc = createFakeFs().file('/m/Makefile', 'include deploy.mk\nall:\n\techo hi\n');
  assert.equal(resolveMakeTargets(inc, '/m', ['all']).dynamic, true);
  const unknownVar = createFakeFs().file('/m/makefile', 'go:\n\t$(TOOL) deploy\n');
  assert.equal(resolveMakeTargets(unknownVar, '/m', ['go']).dynamic, true);
  const pattern = createFakeFs().file('/m/GNUmakefile', '%.out: %.in\n\tcp $< $@\n');
  assert.equal(resolveMakeTargets(pattern, '/m', ['a.out']).dynamic, true);
  const named = createFakeFs().file('/m/build/ops.mk', 'x:\n\tnpm publish\n');
  assert.deepEqual(resolveMakeTargets(named, '/m', ['x'], { makefile: 'build/ops.mk' }).commands, ['npm publish']);
  assert.deepEqual(resolveMakeTargets(createFakeFs().mkdir('/m'), '/m', ['x']), { status: 'absent' });
  assert.equal(resolveMakeTargets(createFakeFs().file('/m/Makefile', 'x').fail('/m/Makefile'), '/m', ['x']).status, 'unknown');
});

test('A11 script files: the "safe" name is read for its content; size, type and symlinks handled', () => {
  const fs = createFakeFs()
    .file('/s/scripts/safe-test-deploy.sh', '#!/usr/bin/env bash\nset -e\nvercel --prod\n')
    .file('/s/tool.py', '#!/usr/bin/python3\nprint(1)\n')
    .file('/s/big.sh', 'x'.repeat(MAX_SCRIPT_BYTES + 1))
    .symlink('/s/link.sh', '/s/scripts/safe-test-deploy.sh')
    .fifo('/s/pipe.sh');
  const safe = readScriptFile(fs, '/s/scripts/safe-test-deploy.sh');
  assert.equal(safe.status, 'ok');
  assert.equal(safe.interpreter, 'shell');
  assert.match(safe.text, /vercel --prod/);
  assert.equal(readScriptFile(fs, '/s/tool.py').interpreter, 'other');
  assert.deepEqual(readScriptFile(fs, '/s/big.sh'), { status: 'unknown', reason: 'too_large' });
  assert.equal(readScriptFile(fs, '/s/link.sh').path, '/s/scripts/safe-test-deploy.sh');
  assert.deepEqual(readScriptFile(fs, '/s/pipe.sh'), { status: 'unknown', reason: 'not_file' });
  assert.deepEqual(readScriptFile(fs, '/s/none.sh'), { status: 'absent' });
});

test('S2 deploy readers: wrangler toml/json/jsonc environments', () => {
  const toml = createFakeFs().file('/d/wrangler.toml', 'name = "w"\n[env.staging]\nname = "w-s"\n[env.production]\nroute = "x"\n[[env.production.kv_namespaces]]\nbinding = "K"\n');
  const r = readWranglerConfig(toml, '/d');
  assert.equal(r.status, 'ok');
  assert.deepEqual(r.environments, ['staging', 'production']);
  const jsonc = createFakeFs().file('/d/wrangler.jsonc', '{\n // c\n "name": "w", "env": { "prod": {}, "dev": {}, },\n}');
  assert.deepEqual(readWranglerConfig(jsonc, '/d').environments, ['prod', 'dev']);
  assert.equal(readWranglerConfig(createFakeFs().file('/d/wrangler.toml', '[env.prod\n'), '/d').status, 'unknown');
  assert.equal(readWranglerConfig(createFakeFs().file('/d/wrangler.json', '{bad'), '/d').status, 'unknown');
  assert.deepEqual(readWranglerConfig(createFakeFs().mkdir('/d'), '/d'), { status: 'absent' });
  assert.deepEqual(readWranglerConfig(createFakeFs().file('/d/cfg/w.toml', '[env.live]\n'), '/d', 'cfg/w.toml').environments, ['live']);
});

test('S2 deploy readers: vercel link, fly app, firebase projects', () => {
  const fs = createFakeFs()
    .file('/d/.vercel/project.json', '{"projectId":"prj_x","orgId":"team_y"}')
    .file('/d/fly.toml', 'app = "shop-production"\nprimary_region = "iad"\n')
    .file('/d/.firebaserc', '{"projects":{"default":"acme-prod","staging":"acme-stg"}}');
  assert.equal(readVercelLink(fs, '/d').linked, true);
  assert.deepEqual(readFlyConfig(fs, '/d').apps, ['shop-production']);
  const fb = readFirebaseProjects(fs, '/d');
  assert.deepEqual(fb.defaultProjects, ['acme-prod']);
  assert.deepEqual(fb.aliases, { default: 'acme-prod', staging: 'acme-stg' });
  assert.equal(readVercelLink(createFakeFs().file('/d/.vercel/project.json', 'x'), '/d').status, 'unknown');
});

test('S2 deploy readers: kube current context + namespace; KUBECONFIG only adds candidates', () => {
  const kube = `apiVersion: v1
contexts:
- context:
    cluster: c1
    namespace: payments-prod
  name: prod-eu
- context:
    cluster: c2
  name: dev
current-context: prod-eu
`;
  const fs = createFakeFs().file('/home/u/.kube/config', kube).file('/k/other', 'current-context: dev\n');
  assert.deepEqual(readKubeContexts(fs, '/home/u').contexts, [{ name: 'prod-eu', namespace: 'payments-prod' }]);
  const both = readKubeContexts(fs, '/home/u', '/k/other');
  assert.deepEqual(both.contexts.map((c) => c.name), ['prod-eu', 'dev']);
  assert.deepEqual(readKubeContexts(createFakeFs().mkdir('/home/u'), '/home/u'), { status: 'absent' });
  assert.equal(readKubeContexts(createFakeFs().file('/home/u/.kube/config', kube).fail('/home/u/.kube/config'), '/home/u').status, 'unknown');
});

test('S2 deploy readers: samconfig, sst stage, terraform workspace, gcloud project', () => {
  const fs = createFakeFs()
    .file('/d/samconfig.toml', 'version = 0.1\n[default.deploy.parameters]\nstack_name = "api-dev"\n[prod.deploy.parameters]\nstack_name = "api-prod"\n')
    .file('/d/.sst/stage', 'production\n')
    .file('/d/.terraform/environment', 'live')
    .file('/home/u/.config/gcloud/active_config', 'work')
    .file('/home/u/.config/gcloud/configurations/config_work', '[core]\nproject = acme-prod\naccount = x@example.invalid\n');
  const sam = readSamConfig(fs, '/d');
  assert.deepEqual(sam.configEnvs, ['default', 'prod']);
  assert.deepEqual(sam.stacks, ['api-dev', 'api-prod']);
  assert.equal(readSstStage(fs, '/d').stage, 'production');
  assert.equal(readTerraformWorkspace(fs, '/d').workspace, 'live');
  assert.equal(readGcloudProject(fs, '/home/u').project, 'acme-prod');
  assert.equal(readSstStage(createFakeFs().file('/d/.sst/stage', '$(x)'), '/d').status, 'unknown');
  assert.equal(readGcloudProject(fs, null).status, 'unknown');
  assert.equal(parseJsonc('{"a":"// not a comment",}').a, '// not a comment');
});

test('security pass: pathological Makefile, TOML and kubeconfig inputs finish quickly (no polynomial regex backtracking)', () => {
  const spaces = ' '.repeat(200000);
  const started = Date.now();
  const make = createFakeFs().file('/m/Makefile', `a${spaces}b\nx:\n\techo ok\n`);
  assert.deepEqual(resolveMakeTargets(make, '/m', ['x']).commands, ['echo ok']);
  assert.equal(readWranglerConfig(createFakeFs().file('/d/wrangler.toml', `[${spaces}x\n`), '/d').status, 'unknown');
  const kube = createFakeFs().file('/home/u/.kube/config', `${'\n'.repeat(100000)}current-context: c\n- name:${' '.repeat(100000)}\n`);
  assert.equal(readKubeContexts(kube, '/home/u').status, 'ok');
  assert.ok(Date.now() - started < 2000, `took ${Date.now() - started} ms`);
});
