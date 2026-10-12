'use strict';

// In-memory fs and git-config reader for the seatbelt mapper tests. Nothing here touches the real
// filesystem or git. File contents are dummies; no fixture holds a real or realistic secret.
const path = require('node:path').posix;

const HOME = '/home/u';
const WS = '/home/u/proj';

const BASE_FILES = {
  [`${WS}/package.json`]: JSON.stringify({
    name: 'proj',
    scripts: {
      build: 'tsc -p .', test: 'node --test', lint: 'eslint .', dev: 'next dev', start: 'node server.js', typecheck: 'tsc --noEmit',
      format: 'prettier --write .', clean: 'rm -rf dist coverage', deploy: 'vercel --prod', ship: 'npm publish',
      release: 'changeset publish', 'deploy:stage': 'sst deploy --stage $STAGE', 'deploy:preview': 'vercel',
      'deploy:staging': 'wrangler deploy --env staging', prepare: 'husky install', 'db:migrate': 'prisma migrate deploy',
    },
  }),
  [`${WS}/safe-test-deploy.sh`]: '#!/bin/sh\nnpm test\nvercel --prod\n',
  [`${WS}/safe.sh`]: '#!/bin/sh\nnpm test\ngit status\n',
  [`${WS}/scripts/build.sh`]: '#!/usr/bin/env bash\nset -euo pipefail\nrm -rf dist\ntsc -p .\n',
  [`${WS}/scripts/nested.sh`]: '#!/bin/sh\n./scripts/inner.sh\n',
  [`${WS}/scripts/inner.sh`]: '#!/bin/sh\nnpm publish\n',
  [`${WS}/scripts/tool.js`]: '#!/usr/bin/env node\nconsole.log(1)\n',
  [`${WS}/Makefile`]: 'APP = proj\n\nbuild:\n\ttsc -p .\n\ntest: build\n\tnpm test\n\nrelease: test\n\tnpm publish\n\ndeploy:\n\twrangler deploy\n\nclean:\n\trm -rf dist\n\nship: release\n',
  [`${WS}/README.md`]: '# proj\n',
  [`${WS}/src/index.ts`]: 'export const x = 1;\n',
  [`${WS}/.env.local`]: 'DUMMY=1\n',
  [`${WS}/.env.example`]: 'DUMMY=\n',
  [`${WS}/.claude/settings.json`]: JSON.stringify({
    permissions: { allow: ['Bash(npm test)'] },
    hooks: { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'marrow-mcp claude-pre-action-hook' }] }] },
  }, null, 2),
  [`${HOME}/.kube/config`]: 'apiVersion: v1\ncurrent-context: kind-dev\n',
  [`${HOME}/.ssh/id_ed25519`]: 'dummy\n',
  [`${HOME}/.ssh/id_ed25519.pub`]: 'dummy\n',
  [`${HOME}/.aws/credentials`]: 'dummy\n',
};
const BASE_DIRS = ['/', '/home', HOME, WS, `${WS}/sub`, `${WS}/src`, `${WS}/dist`, `${WS}/node_modules`, `${WS}/scripts`, `${WS}/.claude`,
  `${HOME}/other-repo`, `${HOME}/.ssh`, `${HOME}/.aws`, `${HOME}/.marrow`, `${HOME}/.kube`, '/tmp', '/var', '/var/tmp', '/srv', '/srv/app', '/etc', '/usr', '/usr/local', '/usr/local/bin'];
const BASE_LINKS = { [`${WS}/link`]: HOME, [`${WS}/awslink`]: `${HOME}/.aws`, [`${WS}/inlink`]: `${WS}/src` };

function makeEnv(options = {}) {
  const files = { ...BASE_FILES, ...(options.files || {}) };
  for (const k of options.removeFiles || []) delete files[k];
  const links = { ...BASE_LINKS, ...(options.links || {}) };
  const dirs = new Set(BASE_DIRS.concat(options.dirs || []));
  for (const f of Object.keys(files)) for (let d = path.dirname(f); ; d = path.dirname(d)) { dirs.add(d); if (d === '/') break; }
  const exists = (p) => Object.prototype.hasOwnProperty.call(files, p) || dirs.has(p) || Object.prototype.hasOwnProperty.call(links, p);
  function realpath(p) {
    const parts = path.normalize(p).split('/').filter(Boolean);
    let cur = '/';
    for (let i = 0; i < parts.length; i += 1) {
      let next = path.join(cur, parts[i]);
      let hops = 0;
      while (Object.prototype.hasOwnProperty.call(links, next) && hops < 16) { next = path.resolve(path.dirname(next), links[next]); hops += 1; }
      if (!exists(next)) return null;
      cur = next;
    }
    return cur;
  }
  const config = { 'remote.origin.url': ['git@github.com:acme/proj.git'], ...(options.gitConfig || {}) };
  const reads = [];
  const env = {
    cwd: options.cwd === undefined ? WS : options.cwd,
    home: HOME,
    tmpdir: '/tmp',
    platform: options.platform || 'linux',
    classifierClass: options.classifierClass,
    fs: {
      readFile(p, max) {
        reads.push(p);
        const r = realpath(p);
        if (r === null || !Object.prototype.hasOwnProperty.call(files, r)) return null;
        const v = files[r];
        return Buffer.byteLength(v) > max ? null : v;
      },
      realpath,
    },
    git: {
      toplevel(cwd) {
        if (options.toplevel !== undefined) return options.toplevel;
        return cwd === WS || cwd.startsWith(`${WS}/`) ? WS : null;
      },
      getAll(_cwd, key) {
        if (options.gitThrows) throw new Error('git unavailable');
        const lower = key.toLowerCase();
        for (const [k, v] of Object.entries(config)) if (k.toLowerCase() === lower) return v.slice();
        return [];
      },
      currentBranch() { return options.current === undefined ? 'feat/work' : options.current; },
      remoteHead(_cwd, remote) {
        const heads = options.remoteHeads || { origin: 'main' };
        return heads[remote] || null;
      },
    },
  };
  env.reads = reads;
  return env;
}

module.exports = { makeEnv, HOME, WS };
