'use strict';

// T-3 (delta audit of 0368537c): the outage help exemption accepts only the exact minimal shapes
// `<cli> --help`, `<cli> --version` and `<cli> <listed subcommand> --help` as the whole action. Every
// other shape (extra words, git options before the subcommand, wrappers, prefixes, chains, pipes,
// substitutions, redirections, quotes, paths, package runners) is not help. Keyless stops never change.
const test = require('node:test');
const assert = require('node:assert/strict');

const { evaluateSeatbeltShell } = require('../dist/seatbelt/mapper.js');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');

const ev = (c) => evaluateSeatbeltShell(c, makeEnv());

const HELP = ['git push --help', 'npm publish --help', 'pnpm publish --help', 'wrangler deploy --help', 'terraform apply --help', 'vercel --version', 'vercel --help',
  'git --version', 'gh pr --help', 'kubectl delete --help', 'helm upgrade --help', 'fly deploy --help'];
const NOT_HELP = [
  // git options before the subcommand (pager, alias, exec path, repository and config redirection).
  'git -c core.pager=sh push --help', 'git -c alias.push=x push --help', 'git -C /tmp push --help', 'git --exec-path=/tmp push --help',
  'git --git-dir=/tmp/x push --help', 'git --work-tree=/tmp push --help', 'git --config-env=core.pager=X push --help', 'git -p push --help',
  // Extra words or flags.
  'npm publish --help --otp=123456', 'git push origin main --help', 'git push -f origin main --help', 'git push --help origin main',
  'kubectl delete deployment api --context prod --help', 'npm publish --version', 'wrangler deploy --version', 'helm upgrade api ./chart --version 1.2.3',
  'npm publish --help=false', 'git push origin main -- --help', 'npm --help publish',
  // Chains, pipes, lines, substitutions, redirections, comments.
  'npm publish --help && git push origin main', 'npm publish --help; npm publish', 'npm publish --help || npm publish', 'npm publish --help & npm publish',
  'git push --help | sh', 'git push --help\ngit push origin main', '$(echo npm) publish --help', 'npm publish --help $(npm publish)', '`echo git` push --help',
  'npm publish --help > /tmp/x', 'npm publish --help # x', 'npm  publish --help', ' npm publish --help',
  // Wrappers, prefixes, nesting, paths, package runners, quoting, globs, functions.
  'sudo npm publish --help', 'env npm publish --help', 'NPM_X=1 npm publish --help', 'command git push --help', 'nice git push --help', 'bash -c "npm publish --help"',
  'npx wrangler deploy --help', './wrangler deploy --help', '/usr/bin/git push --help', 'npm "publish" --help', "git 'push' --help", 'git pus? --help',
  'f() { npm publish; }; f --help', 'alias git="npm publish"; git push --help',
  // Programs and subcommands off the list.
  'npm run --help', 'npm run deploy --help', 'docker push --help', 'make deploy --help', 'railway run --help', 'aws s3 rm --help', 'gcloud run deploy --help',
];

test('T-3 mapper: the exact minimal help shapes are marked help-only; keyless stops do not change', () => {
  for (const c of HELP) assert.equal(ev(c).outageHelpOnly, true, c);
  assert.equal(ev('npm publish --help').decision, 'stop', 'the keyless S3 stop is unchanged');
  assert.equal(ev('wrangler deploy --help').decision, 'stop', 'the keyless S2 stop is unchanged');
});

test('T-3 mapper: every other shape is not help-only', () => {
  for (const c of NOT_HELP) assert.notEqual(ev(c).outageHelpOnly, true, JSON.stringify(c));
});
