'use strict';

// Extra rows for tools/fh-diff.cjs: the shapes the audit corpus lacks (REPORT section 3, abuse list 7
// and 10). Chaining, pipes, subshells, bash -c, repeated flags (the last one wins), variables, words
// in messages and paths that only look like a risky action, unknown flags, production mislabelled,
// and actions that carry a secret in a header, a URL query, an environment assignment, a JSON body,
// a flag value or a form body. {{S1}} and {{S2}} are dummy secrets the tool derives at run time
// (two different values); {{WS}} and {{HOME}} are the demo project and the fake home.
const B = (command, description = 'extra') => ({ tool: 'Bash', input: { command, description } });

const SHAPES = [
  // chaining, pipes, subshells, bash -c
  ['X001', B('git status && git push --force origin main')],
  ['X002', B('git push --force origin main; echo done')],
  ['X003', B('true || npm publish')],
  ['X004', B('echo x | npm publish')],
  ['X005', B('(cd packages/ui && npm publish)')],
  ['X006', B('bash -c "npm publish"')],
  ['X007', B("sh -c 'git push -f origin main'")],
  ['X008', B('$(echo npm) publish')],
  ['X009', B('eval "npm publish"')],
  ['X010', B('X=main; git push -f origin $X')],
  ['X011', B('git push -f origin "$BRANCH"')],
  ['X012', B('npx wrangler deploy --env production && echo ok')],
  ['X013', B('cd . && vercel deploy --prod')],
  ['X014', B('echo ok | tee out.txt | npm publish')],
  ['X015', B('npm test && (git push origin main || true)')],
  ['X016', B('bash -lc "cd packages/ui && vercel --prod"')],
  // repeated flags (last one wins)
  ['X020', B('npx wrangler deploy --env staging --env production')],
  ['X021', B('npx wrangler deploy --env production --env staging')],
  ['X022', B('vercel --prod --no-prod')],
  ['X023', B('vercel --no-prod --prod')],
  ['X024', B('git push --force --no-force origin main')],
  ['X025', B('git push --no-force --force origin main')],
  ['X026', B('npm publish --dry-run --no-dry-run')],
  ['X027', B('npm publish --no-dry-run --dry-run')],
  // variables
  ['X030', B('ENVIRONMENT=production; npx wrangler deploy --env $ENVIRONMENT')],
  ['X031', B('npm publish $PKG')],
  ['X032', B('STAGE=prod npm run deploy')],
  ['X033', B('git push origin $(git branch --show-current)')],
  ['X034', B('git push origin HEAD:main')],
  ['X035', B('git push origin +HEAD:refs/heads/main')],
  // misleading words in messages, paths and notes
  ['X040', B('git commit -m "deploy to production"')],
  ['X041', B('echo "npm publish"')],
  ['X042', B('cat README.md # git push --force origin main')],
  ['X043', B('grep -r "force-push" docs/')],
  ['X044', B('ls prod-env/')],
  ['X045', B('mkdir production')],
  ['X046', B('git log --grep="publish"')],
  ['X047', B('echo wrangler deploy --env production > notes.txt')],
  ['X048', B('cat notes-about-env-files.txt')],
  ['X049', B('git commit -m "update .env handling" && git push origin feat/login-form')],
  // unknown flags
  ['X050', B('npm publish --made-up-flag')],
  ['X051', B('git push --unknown-flag origin main')],
  ['X052', B('npx wrangler deploy --weird')],
  ['X053', B('docker push --quiet acme/app:1')],
  ['X054', B('vercel --prod --some-new-flag')],
  // production mislabelled
  ['X060', { tool: 'Bash', input: { command: 'vercel deploy --prod', description: 'Deploy to the staging environment' } }],
  ['X061', B('NODE_ENV=staging npx wrangler deploy --env production')],
  ['X062', B('git push origin main  # staging only')],
  ['X063', B('npm run deploy:production')],
  ['X064', B('kubectl apply -f deploy.yml --context=production')],
  ['X065', B('terraform apply -auto-approve -var env=prod')],
  ['X066', { tool: 'Bash', input: { command: 'npm publish', description: 'dry run, nothing is published' } }],
];

// A secret in each carrier, with the text after it differing in the third row of a group.
const carriers = [
  ['header', (s, tail) => `curl -H "Authorization: Bearer ${s}" "https://api.example.test/v1/items?mode=${tail}"`],
  ['query', (s, tail) => `curl "https://api.example.test/v1/items?token=${s}&mode=${tail}"`],
  ['env', (s, tail) => `API_TOKEN=${s} npm run ${tail === 'read' ? 'dev' : 'build'}`],
  ['json', (s, tail) => `curl -d '{"password":"${s}","op":"${tail}"}' https://api.example.test/v1/login`],
  ['flag', (s, tail) => `mytool --token ${s} --mode ${tail}`],
  ['flag_eq', (s, tail) => `mytool --token=${s} --mode ${tail}`],
  ['form', (s, tail) => `curl --data "user=a&secret=${s}&role=${tail === 'read' ? 'viewer' : 'admin'}" https://api.example.test/`],
  ['xheader', (s, tail) => `curl -H "X-Api-Key: ${s}" -H "X-Trace: ${tail}" https://api.example.test/`],
  ['deploy', (s, tail) => `npx wrangler deploy --env ${tail === 'read' ? 'staging' : 'production'} --api-token ${s}`],
];

const SECRETS = [];
const PAIRS = [];
carriers.forEach(([name, make], index) => {
  const id = (n) => `S${String(index * 3 + n).padStart(3, '0')}`;
  SECRETS.push([id(1), B(make('{{S1}}', 'read'), `secret in ${name}`)]);
  SECRETS.push([id(2), B(make('{{S2}}', 'read'), `secret in ${name}, other value`)]);
  SECRETS.push([id(3), B(make('{{S1}}', 'write'), `secret in ${name}, other tail`)]);
  PAIRS.push({ group: name, a: id(1), b: id(2), relation: 'same' }, { group: name, a: id(1), b: id(3), relation: 'different' });
});

const EXTRA = [...SHAPES, ...SECRETS].map(([id, ev]) => ({ id, cat: 'extra', tool: ev.tool, input: ev.input, post: null }));
module.exports = { EXTRA, PAIRS };
