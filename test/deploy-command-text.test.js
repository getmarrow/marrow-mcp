const assert = require('node:assert/strict');
const test = require('node:test');
const { randomBytes } = require('node:crypto');
const { deployCommandText, normalizedHookAction } = require('../dist/normalized-action.js');

const sent = (command) => normalizedHookAction({ tool_name: 'Bash', tool_input: { command } }).tool_input.command;

test('Deploy command text: only a whole command in an allowed grammar is sent, word for word', () => {
  const allowed = [
    'vercel deploy --target staging', 'vercel --target preview', 'vercel deploy --target=staging', 'vercel --target production',
    'npx vercel deploy --target staging', 'pnpx vercel --target staging', 'bunx vercel --target staging', 'npm exec vercel --target staging', 'pnpm dlx vercel --target staging',
    'netlify deploy', 'npx netlify deploy',
    'serverless deploy --stage dev', 'sls deploy --stage=staging', 'sst deploy --stage pr-12',
    'railway up --environment staging', 'railway up --environment=preview',
    '  vercel\tdeploy  --target   staging  ',
  ];
  for (const command of allowed) {
    const text = deployCommandText(command);
    assert.ok(text, `${command}: grammar`);
    assert.equal(sent(command), text, `${command}: sent as the normalized words`);
    assert.equal(text, command.trim().split(/[ \t]+/).join(' '));
  }
});

test('Deploy command text, abuse cases: chains, wrappers, repeats, variables, unknown words, production flags, wrangler and free text send no text', () => {
  const word = `w${randomBytes(4).toString('hex')}`;
  const none = [
    // chained and wrapped
    'vercel deploy --target staging && vercel deploy --prod', 'vercel deploy --target staging; vercel deploy --prod',
    'vercel deploy --target staging || vercel deploy --prod', 'vercel deploy --target staging | tee log', 'vercel deploy --target staging &',
    'vercel deploy --target staging\nvercel deploy --prod', 'vercel deploy --target `echo staging`', 'vercel deploy --target $(echo staging)',
    '(vercel deploy --target staging)', 'bash -c "vercel deploy --target staging"', 'sh -c \'vercel deploy --target staging\'',
    'eval vercel deploy --target staging', 'xargs vercel deploy --target staging', 'env vercel deploy --target staging', 'sudo vercel deploy --target staging',
    // repeated, variables, unknown, production
    'vercel --target staging --target production', 'vercel --target=staging --target=production', 'ENV=production vercel deploy --target $ENV',
    'vercel deploy --target $ENV', 'vercel deploy --target "staging"', "vercel deploy --target 'staging'", 'vercel deploy --target staging --yes',
    'vercel deploy --prod', 'vercel deploy --prod --target staging', 'vercel deploy --target staging --prod', 'vercel deploy', 'vercel deploy --target Staging',
    'vercel deploy --target staging_1', `vercel deploy --target ${'a'.repeat(33)}`, 'netlify deploy --prod', 'netlify deploy --alias staging',
    'sls deploy', 'sls deploy --stage dev --stage prod', 'sls deploy -s dev', 'railway up', 'railway up -e staging', 'railway up --environment staging --detach',
    'npx -y vercel --target staging', 'npx npx vercel --target staging', 'npm vercel --target staging',
    // wrangler is excluded: --env staging deploys production when the environment is missing
    'wrangler deploy --env staging', 'npx wrangler deploy --env staging', 'wrangler versions upload --env staging',
    // misleading words and free text
    'vercel deploy --target staging -m after-prod', `./deploy.sh ${word}`, `vercel deploy ./${word}.txt --target staging`, `vercel deploy --target staging ${word}`,
    `vercel deploy --target staging # ${word}`, 'vercel deploy --target staging ', 'vercel deploy --target staging',
  ];
  for (const command of none) {
    assert.equal(deployCommandText(command), null, JSON.stringify(command));
    assert.equal(sent(command), undefined, `${JSON.stringify(command)}: no command text in the normalized action`);
  }
  // A truncated action never carries text.
  assert.equal(normalizedHookAction({ tool_name: 'Bash', tool_input: { command: 'vercel deploy --target staging' }, input_truncated: true }).tool_input.command, undefined);
});
