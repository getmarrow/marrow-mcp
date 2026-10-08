const assert = require('node:assert/strict');
const test = require('node:test');
const { randomBytes, randomInt } = require('node:crypto');
const { normalizedHookAction, normalizeShellCommand, looksLikeKey } = require('../dist/normalized-action.js');
const { ordinaryApprovalGuidance } = require('../dist/runtime-contract.js');
const { withoutServerNextActions } = require('../dist/index.js');

// Dummy secrets generated at runtime, in the shapes real ones have. None is printed.
const b64 = (n) => randomBytes(n).toString('base64').replace(/[+/=]/g, 'A').slice(0, n);
const mark = () => `ZZQSYNTH${randomBytes(5).toString('hex').toUpperCase()}`;
// A live-key prefix assembled at runtime, so no key-shaped literal sits in this file.
const LIVE_PREFIX = ['sk', 'live', ''].join('_');

const bash = (command) => normalizedHookAction({ tool_name: 'Bash', tool_input: { command, description: 'held' } });
const leaks = (value, secret) => JSON.stringify(value).includes(secret);

test('only program names and a hash leave the machine: no command text', () => {
  const value = bash('wrangler deploy --env production');
  assert.deepEqual(Object.keys(value).sort(), ['programs', 'tool_input', 'tool_kind', 'tool_name']);
  assert.deepEqual(value.programs, ['wrangler']);
  assert.match(value.tool_input.command_sha256, /^[a-f0-9]{64}$/);
  assert.doesNotMatch(JSON.stringify(value), /deploy|production/);
});

test('HIGH-R3-1: the realistic secret forms never leave, in the normalized action or anywhere in its JSON', () => {
  const aws = b64(40), pw = b64(16), otp = String(randomInt(100000, 999999)), hex = randomBytes(20).toString('hex');
  const cases = [
    [`aws configure set aws_secret_access_key ${aws}`, aws],
    [`mysql -u root -p${pw} prod`, pw],
    [`docker login -u bob -p ${pw} registry.example.com`, pw],
    [`npm publish --otp ${otp}`, otp],
    [`PGPASSWORD=${pw} psql -h db -c 'select 1'`, pw],
    [`curl -u admin:${pw} https://api.example.com/deploy`, pw],
    [`echo ${hex} | wrangler secret put API_KEY`, hex],
    [`gh auth login --with-token ${hex}`, hex],
    [`sshpass -p ${pw} ssh root@prod`, pw],
    [`redis-cli -a ${pw} FLUSHALL`, pw],
  ];
  for (const [command, secret] of cases) {
    const value = bash(command);
    assert.equal(leaks(value, secret), false, command.split(' ').slice(0, 2).join(' '));
    assert.equal(normalizeShellCommand(command).text.includes(secret), false, `normalized form of ${command.split(' ')[0]}`);
  }
});

test('HIGH-R3-1: the audit\'s synthetic set, and more forms (plain-word secrets, attached flags, here-strings, heredocs, files)', () => {
  const M = mark();
  const cases = {
    env_assign: `API_TOKEN=${M} npm publish`,
    export_assign: `export DEPLOY_KEY=${M}; wrangler deploy`,
    export_neutral_name: `export FOO=${M}; wrangler deploy`,
    url_creds: `git push https://x-access-token:${M}@github.com/o/r.git main`,
    flag_otp: `npm publish --otp ${M}`,
    flag_otp_eq: `npm publish --otp=${M}`,
    flag_password_eq: `mysql --password=${M} -e 'drop table x'`,
    flag_passwd: `tool --passwd ${M} run`,
    flag_token: `deploy --token ${M}`,
    flag_secret_x: `deploy --secret-value ${M}`,
    flag_api_key: `deploy --api-key ${M}`,
    short_p: `mysql -u root -p${M} prod`,
    docker_login: `docker login -u bob -p ${M} registry.example.com`,
    docker_login_attached: `docker login -u bob -p${M} registry.example.com`,
    bearer_header: `curl -H "Authorization: Bearer ${M}" https://api.example.com/deploy`,
    x_api_key_header: `curl -H "X-Api-Key: ${M}" https://api.example.com`,
    curl_user: `curl --user admin:${M} https://api.example.com`,
    gh_token_like: `gh secret set FOO --body ghp_${M}abcdefghijklmnopqrstuv`,
    gh_secret_body: `gh secret set FOO --body ${M}`,
    aws_configure: `aws configure set aws_secret_access_key ${M}`,
    echo_pipe: `echo ${M} | wrangler secret put API_KEY`,
    printf_pipe: `printf '%s' "${M}" | vercel env add API_KEY production`,
    echo_to_file: `echo ${M} > .env.local`,
    here_string: `wrangler secret put API_KEY <<< "${M}"`,
    heredoc: `cat <<EOF > .env\nSECRET=${M}\nEOF`,
    heredoc_quoted: `kubectl apply -f - <<'YAML'\ndata: ${M}\nYAML`,
    stripe: `stripe refunds create --api-key ${LIVE_PREFIX}${M}0123456789abcdef`,
    sshpass: `sshpass -p ${M} ssh root@prod`,
    redis_a: `redis-cli -a ${M} FLUSHALL`,
    k8s_literal: `kubectl create secret generic app --from-literal=db=${M}`,
    doppler: `doppler secrets set NAME ${M}`,
    openssl: `openssl enc -aes-256-cbc -pass pass:${M} -in a -out b`,
    vault_kv: `vault kv put secret/app password=${M}`,
    sudo_env: `sudo env TOKEN=${M} ./deploy.sh`,
  };
  for (const [name, command] of Object.entries(cases)) {
    assert.equal(leaks(bash(command), M), false, name);
    assert.equal(normalizeShellCommand(command).text.includes(M), false, `${name} (normalized form)`);
  }
  assert.equal(leaks(normalizedHookAction({ tool_name: 'Bash', tool_input: { command: ['bash', '-lc', `npm publish --otp ${M}`] } }), M), false, 'codex argv');
});

test('MCP and other tool inputs are hashed: no field value leaves, secret-named or not', () => {
  const M = mark();
  const mcp = normalizedHookAction({ tool_name: 'mcp__stripe__create_refund', tool_input: { amount: 10, api_key: M, note: `token ${M}`, nested: { password: M }, free: M } });
  assert.equal(leaks(mcp, M), false);
  assert.deepEqual(Object.keys(mcp.tool_input), ['input_sha256']);
  const same = normalizedHookAction({ tool_name: 'mcp__stripe__create_refund', tool_input: { free: M, nested: { password: M }, note: `token ${M}`, api_key: M, amount: 10 } });
  assert.deepEqual(mcp, same, 'key order does not matter');
});

test('the five commands one coarse class used to merge give five different hashes; a retry gives the same hash', () => {
  const commands = ['wrangler deploy', 'wrangler delete --force', 'terraform destroy -auto-approve', 'kubectl delete namespace prod', 'wrangler rollback'];
  const hashes = commands.map((command) => bash(command).tool_input.command_sha256);
  assert.equal(new Set(hashes).size, 5);
  assert.deepEqual(bash('terraform destroy -auto-approve').programs, ['terraform']);
  const first = normalizedHookAction({ tool_name: 'Bash', tool_input: { command: 'kubectl delete namespace prod', description: 'first try' } });
  const retry = normalizedHookAction({ tool_name: 'Bash', tool_input: { command: '  kubectl   delete namespace prod ', description: 'second try' } });
  assert.deepEqual(first, retry);
  assert.notEqual(bash('wrangler deploy --env production').tool_input.command_sha256, bash('wrangler deploy --env staging').tool_input.command_sha256);
});

test('the hash is the same on every machine: it depends only on the secret-free command (pinned)', () => {
  assert.equal(bash('wrangler deploy --env production').tool_input.command_sha256,
    require('node:crypto').createHash('sha256').update('marrow-normalized-action-v2\nshell\nwrangler deploy --env production').digest('hex'));
  // Two commands that differ only in a secret value are the same action.
  assert.equal(bash(`npm publish --otp ${randomInt(100000, 999999)}`).tool_input.command_sha256, bash(`npm publish --otp ${randomInt(100000, 999999)}`).tool_input.command_sha256);
  // Codex's argument vector and the string form are the same action.
  assert.deepEqual(normalizedHookAction({ tool_name: 'Bash', tool_input: { command: ['bash', '-lc', 'wrangler deploy --env production'] } }), bash('wrangler deploy --env production'));
});

test('key-shaped values are recognized; ordinary words, paths, versions and digests are not', () => {
  for (const key of [b64(40), randomBytes(32).toString('hex'), `ghp_${b64(36)}`, `AKIA${b64(16).toUpperCase().replace(/[^A-Z0-9]/g, 'Q')}`, `xoxb-${randomBytes(12).toString('hex')}`]) assert.equal(looksLikeKey(key), true);
  for (const word of ['production', '/home/operator/project/src/index.ts', 'v3.9.99', 'sha256:' + randomBytes(32).toString('hex'), 'wrangler', 'getmarrow/marrow-mcp']) assert.equal(looksLikeKey(word), false, word);
});

test('the arbitration receipt field is read under both names and never treated as an ordinary hold', () => {
  const runtime = (approval) => ({
    decision_id: 'd1', runtime_authorization: { id: 'g1', decision_id: 'd1' },
    risk_gate: { decision: 'review_required' }, gate_receipt: { id: 'g1', decision: 'review_required' },
    completion_contract: { decision_id: 'd1', owner_approval: { mode: 'ordinary_non_arbitrated', approval_status_endpoint: '/v1/agent/gate-receipts/g1/owner-approval', ...approval } },
  });
  assert.ok(ordinaryApprovalGuidance(runtime({})));
  assert.equal(ordinaryApprovalGuidance(runtime({ dashboard_receipt_required: true })), null);
  assert.equal(ordinaryApprovalGuidance(runtime({ owner_receipt_required: true })), null);
});

test('the raw runtime_gate marrow_auto returns carries no server next-step text at any depth', () => {
  const stripped = withoutServerNextActions({
    exact_next_action: 'POST /v1/agent/gate-receipts/g1/approval-link',
    decision_brief: { exact_next_actions: ['POST /v1/agent/gate-receipts/g1/approval-link'] },
    intervention: { exact_next_action: 'POST ...', headline: 'held' },
    arbitration: { proposals: [{ exact_next_action: 'x', id: 'p1' }] },
  });
  assert.doesNotMatch(JSON.stringify(stripped), /exact_next_action|approval-link/);
  assert.equal(stripped.intervention.headline, 'held');
  assert.equal(stripped.arbitration.proposals[0].id, 'p1');
});
