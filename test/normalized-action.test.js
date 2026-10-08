const assert = require('node:assert/strict');
const test = require('node:test');
const { randomBytes, randomInt } = require('node:crypto');
const { normalizedHookAction, normalizeShellCommand, looksLikeKey, classifySecretName } = require('../dist/normalized-action.js');
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


// ---------------------------------------------------------------- Fix round 4 (MEDIUM-R1-1 and L-R4-1)

const shell = (command) => normalizedHookAction({ tool_name: 'Bash', tool_input: { command } });
const hashOf = (command) => shell(command).tool_input.command_sha256;
const digest = (text) => require('node:crypto').createHash('sha256').update(text).digest('hex');

test('MEDIUM-R1-1: commands that differ only in the data they read get different hashes; the same data the same hash', () => {
  const pairs = [
    ['pipe', 'echo "SELECT count(*) FROM users" | npx wrangler d1 execute marrow-db --remote --command -', 'echo "DROP TABLE users" | npx wrangler d1 execute marrow-db --remote --command -'],
    ['heredoc', "psql \"$PROD_URL\" <<'SQL'\nSELECT 1;\nSQL", "psql \"$PROD_URL\" <<'SQL'\nDROP TABLE decisions;\nSQL"],
    ['heredoc on /dev/stdin', 'npx wrangler d1 execute marrow-db --remote --file=/dev/stdin <<EOF\nSELECT 1;\nEOF', 'npx wrangler d1 execute marrow-db --remote --file=/dev/stdin <<EOF\nDROP TABLE users;\nEOF'],
    ['here-string', 'npx wrangler d1 execute marrow-db --remote --command - <<< "SELECT 1"', 'npx wrangler d1 execute marrow-db --remote --command - <<< "DROP TABLE users"'],
    ['kubectl here-string', 'kubectl apply -f deploy.yaml <<< "replicas: 3"', 'kubectl apply -f deploy.yaml <<< "replicas: 0"'],
    ['printf pipe', "printf 'SELECT * FROM users WHERE id = 1' | psql prod", "printf 'DELETE FROM users' | psql prod"],
    ['inside bash -c', "bash -c 'echo \"SELECT 1\" | psql prod'", "bash -c 'echo \"DROP TABLE users\" | psql prod'"],
    ['environment value', 'TARGET=staging ./deploy.sh', 'TARGET=production ./deploy.sh'],
  ];
  for (const [label, a, b] of pairs) {
    const left = shell(a);
    const right = shell(b);
    assert.notEqual(left.tool_input.command_sha256, right.tool_input.command_sha256, `${label}: different data, different action`);
    assert.equal(left.truncated, undefined, `${label}: exact`);
    assert.equal(right.truncated, undefined, `${label}: exact`);
    assert.doesNotMatch(JSON.stringify(left), /SELECT|staging/, `${label}: the data never leaves`);
    assert.doesNotMatch(JSON.stringify(right), /DROP|DELETE|production/, `${label}: the data never leaves`);
  }
  // The same data: the same hash on a retry, whatever the quoting, spacing or line endings.
  assert.equal(hashOf('echo "DROP TABLE users" | npx wrangler d1 execute marrow-db --remote --command -'), hashOf("echo  'DROP TABLE users'  |  npx wrangler d1 execute marrow-db --remote --command -"));
  assert.equal(hashOf("psql prod <<'SQL'\nDROP TABLE x;\nSQL"), hashOf('psql prod <<SQL\r\nDROP TABLE x;\r\nSQL'));
  assert.equal(hashOf('kubectl apply -f d.yaml <<< "replicas: 0"'), hashOf("kubectl apply -f d.yaml <<< 'replicas: 0'"));
  // And on every machine: the hash depends only on the command and its data (pinned).
  const data = digest('marrow-normalized-action-v2\ndata\nDROP TABLE users');
  assert.equal(hashOf('echo "DROP TABLE users" | psql prod'), digest(`marrow-normalized-action-v2\nshell\necho [data:${data}] | psql prod`));
});

test('MEDIUM-R1-1: data that feeds a secrets command or file, or looks secret, is withheld and the action is marked truncated (Marrow always asks)', () => {
  const M = mark();
  const key = `${randomBytes(24).toString('base64').replace(/[+/=]/g, 'A')}aZ9`;
  const cases = {
    wrangler_secret_pipe: `echo ${M} | wrangler secret put API_KEY`,
    gh_secret_pipe: `printf '%s' ${M} | gh secret set API_KEY`,
    docker_password_stdin: `echo ${M} | docker login -u bob --password-stdin registry.example.com`,
    through_base64: `echo ${M} | base64 -d | wrangler secret put API_KEY`,
    aws_configure_heredoc: `aws configure <<EOF\nAKID\n${M}\nus-east-1\njson\nEOF`,
    vault_heredoc: `vault kv put secret/app - <<EOF\n${M}\nEOF`,
    env_file: `cat > .env <<EOF\nAPP_MODE=${M}\nEOF`,
    tee_env: `echo ${M} | tee .env.production`,
    pgpass: `printf '%s' ${M} > ~/.pgpass`,
    yaml_password: `cat <<EOF | kubectl apply -f -\nkind: Secret\nstringData:\n  password: ${M}\nEOF`,
    key_shaped_data: `echo ${key} | kubectl apply -f -`,
    here_string_secret: `wrangler secret put API_KEY <<< "${M}"`,
    ssh_add: `ssh-add - <<< "${M}"`,
    json_password: `psql prod <<< '{"password": "${M}"}'`,
  };
  for (const [name, command] of Object.entries(cases)) {
    const action = shell(command);
    const secret = name === 'key_shaped_data' ? key : M;
    assert.equal(action.truncated, true, `${name}: truncated`);
    assert.equal(JSON.stringify(action).includes(secret), false, `${name}: not sent`);
    assert.equal(normalizeShellCommand(command).text.includes(secret), false, `${name}: not in the hashed form`);
  }
  // Two secrets for the same secrets command are one withheld action.
  assert.equal(hashOf(`echo ${mark()} | wrangler secret put API_KEY`), hashOf(`echo ${mark()} | wrangler secret put API_KEY`));
});

test('MEDIUM-R1-1 (same class): a withheld value that may name the target marks the action truncated; a replaced credential too (never reused)', () => {
  // Credential-named values are replaced where they stood (only the credential differs), and the action is never reused.
  const token = shell(`API_TOKEN=${mark()} npm publish`);
  assert.equal(token.truncated, true);
  assert.equal(token.tool_input.command_sha256, hashOf(`API_TOKEN=${mark()} npm publish`));
  // An ambiguous name (an S3 object key) and random-looking values (a commit, ids) are withheld and marked truncated.
  for (const command of [
    'aws s3api delete-object --bucket b --key reports/a.csv',
    `git reset --hard ${randomBytes(20).toString('hex')}`,
    `curl -X DELETE https://api.cloudflare.com/client/v4/zones/${randomBytes(16).toString('hex')}/dns_records/${randomBytes(16).toString('hex')}`,
    `KEY=${mark()} ./rotate.sh`,
  ]) {
    assert.equal(shell(command).truncated, true, command.slice(0, 40));
  }
  // Names that only look secret-ish keep their values: git --author, a secret's id.
  assert.notEqual(hashOf('git commit --author "Ann <a@x.io>" -m x'), hashOf('git commit --author "Bob <b@x.io>" -m x'));
  assert.notEqual(hashOf('aws secretsmanager delete-secret --secret-id prod/db'), hashOf('aws secretsmanager delete-secret --secret-id staging/db'));
  assert.equal(shell('aws secretsmanager delete-secret --secret-id prod/db').truncated, undefined);
  assert.equal(shell('wrangler deploy --env production').truncated, undefined);
  assert.equal(classifySecretName('AWS_SECRET_ACCESS_KEY'), 'credential');
  assert.equal(classifySecretName('author'), 'plain');
  assert.equal(classifySecretName('secret-id'), 'reference');
  assert.equal(classifySecretName('key'), 'ambiguous');
});

test('L-R4-1: URL credentials, more password flags, positional passwords, inline literals and remote commands are redacted inside the hashed form', () => {
  const word = `Summer${randomInt(1000, 9999)}!`;
  const pw = b64(14);
  const cases = {
    postgres_url: `psql postgresql://app:${pw}@db.internal/prod -c 'select 1'`,
    https_url: `git clone https://bob:${word}@git.example.com/o/r.git`,
    redis_url: `redis-cli -u redis://:${pw}@cache:6379 FLUSHALL`,
    mongodb_srv_url: `mongosh "mongodb+srv://admin:${pw}@cluster0.example.net/prod"`,
    mongo_p: `mongo -u admin -p ${word} prod`,
    mongodump_p_attached: `mongodump -u admin -p${pw} --db prod`,
    az_login_p: `az login -u bob -p ${word}`,
    twine_p: `twine upload -u __token__ -p ${pw} dist/*`,
    sqlcmd_P: `sqlcmd -S db -U sa -P ${word} -Q 'select 1'`,
    bcp_P_attached: `bcp dbo.t out t.dat -S db -U sa -P${word}`,
    oc_login_p: `oc login https://api.example.com -u dev -p ${word}`,
    useradd_p: `useradd -m -p ${pw} deploy`,
    set_password_script: `./set-password.sh admin ${word}`,
    mysqladmin_password: `mysqladmin -u root password ${word}`,
    redis_auth: `redis-cli AUTH ${word}`,
    redis_requirepass: `redis-cli CONFIG SET requirepass ${word}`,
    rabbitmq_add_user: `rabbitmqctl add_user deploy ${word}`,
    vault_login: `vault login ${pw}`,
    netlify_env_set: `netlify env:set STRIPE_SECRET_KEY ${word}`,
    npm_config_token: `npm config set //registry.npmjs.org/:_authToken ${word}`,
    keytool_storepass: `keytool -list -keystore k.jks -storepass ${word}`,
    java_property: `java -Ddb.password=${word} -jar app.jar`,
    python_literal: `python -c "import requests; requests.post(u, headers={'X-Token': '${word}'})"`,
    node_bearer_literal: `node -e "fetch(u, { headers: { authorization: 'Bearer ${pw}x' } })"`,
    json_body: `curl -X POST https://api.example.com/x -d '{"client_secret": "${word}"}'`,
    url_query: `curl "https://api.example.com/v1/x?api_key=${pw}"`,
    ssh_remote: `ssh deploy@prod 'echo ${word} > /etc/app/pass'`,
    ssh_remote_env: `ssh -i ~/.ssh/id deploy@prod "DB_PASSWORD=${word} ./migrate.sh"`,
    bash_c: `bash -c "PGPASSWORD=${word} psql -h db prod"`,
    eval: `eval "mysql -uroot -p${word} prod"`,
    su_c: `su - deploy -c "sshpass -p ${word} ssh prod"`,
  };
  for (const [name, command] of Object.entries(cases)) {
    const secret = command.includes(word) ? word : pw;
    assert.equal(normalizeShellCommand(command).text.includes(secret), false, `${name}: not in the hashed form`);
    assert.equal(JSON.stringify(shell(command)).includes(secret), false, `${name}: not sent`);
  }
});

test('MCP and other inputs: a replaced credential, ambiguous names, random-looking values and cut inputs mark it truncated', () => {
  const mcp = (input) => normalizedHookAction({ tool_name: 'mcp__cloudflare__dns_delete', tool_input: input });
  assert.equal(mcp({ api_token: b64(30), zone: 'example.com', name: 'www' }).truncated, true);
  assert.equal(mcp({ zone: 'example.com', name: 'www' }).truncated, undefined);
  assert.notEqual(mcp({ zone: 'example.com', name: 'www' }).tool_input.input_sha256, mcp({ zone: 'example.com', name: 'api' }).tool_input.input_sha256);
  assert.equal(mcp({ zone_id: randomBytes(16).toString('hex'), name: 'www' }).truncated, true);
  assert.equal(mcp({ key: 'reports/a.csv' }).truncated, true);
  assert.equal(mcp({ items: Array.from({ length: 65 }, (_, i) => i) }).truncated, true);
  const secret = b64(14);
  assert.equal(JSON.stringify(mcp({ password: secret, note: `client_secret=${secret}` })).includes(secret), false);
});


// ---------------------------------------------------------------- Fix round 5 (MEDIUM-R5-1, LOW-R5-1, LOW-R5-3)

const { normalizeHookEventPayload } = require('../dist/hook-contract.js');
const { MAX_SCAN_CHARS } = require('../dist/normalized-action.js');

function medianMs(run) {
  const times = [];
  for (let i = 0; i < 3; i += 1) {
    const started = process.hrtime.bigint();
    run();
    times.push(Number(process.hrtime.bigint() - started) / 1e6);
  }
  return times.sort((a, b) => a - b)[1];
}

test('MEDIUM-R5-1: a 64 KB token of any shape normalizes in under 100 ms and is withheld as truncated', () => {
  const shapes = {
    one_word: 'a'.repeat(65_536),
    eq_pairs: 'a='.repeat(32_768),
    colon_pairs: 'a:'.repeat(32_768),
    scheme_like: 'a://u:'.repeat(10_923),
    json_like: '{"a":'.repeat(13_107),
    query: `https://x/y?${'a=1&'.repeat(16_384)}`,
  };
  for (const [name, token] of Object.entries(shapes)) {
    for (const command of [`deploy ${token}`, `psql -c '${token}'`, `echo '${token}' | psql prod`]) {
      let action;
      const ms = medianMs(() => { action = shell(command); });
      assert.ok(ms < 100, `${name}: ${ms.toFixed(0)} ms`);
      assert.equal(action.truncated, true, `${name}: over ${MAX_SCAN_CHARS} characters, not scanned`);
    }
  }
  // Many words up to 64 KB stay linear too.
  for (const command of ['deploy ' + 'ab '.repeat(21_845), 'echo a' + ' | cat'.repeat(10_922), 'A=b '.repeat(16_384) + 'deploy']) {
    const ms = medianMs(() => shell(command));
    assert.ok(ms < 100, `${command.slice(0, 12)}: ${ms.toFixed(0)} ms`);
  }
});

test('LOW-R5-1: credential literals are scanned without recursion; thousands of nested names neither crash nor slow down', () => {
  // The forms that overflowed the stack at about 4 KB in 87fd70d.
  for (const token of ['a='.repeat(1_950), 'a:'.repeat(1_950), '{"a":'.repeat(780), 'a='.repeat(8_000)]) {
    const ms = medianMs(() => shell(`deploy ${token}`));
    assert.ok(ms < 100, `${token.slice(0, 6)} x${token.length}: ${ms.toFixed(0)} ms`);
  }
  assert.equal(shell(`deploy ${'a='.repeat(1_950)}`).truncated, undefined, 'under the cap: scanned, exact');
  assert.equal(shell(`deploy ${'a='.repeat(4_000)}`).truncated, true, 'over 2048 names in one text: withheld');
  // Nested credentials are still found in one pass.
  const secret = b64(16);
  assert.equal(normalizeShellCommand(`curl "https://api.example.com/x?a=1&b=2&api_key=${secret}&c=3"`).text.includes(secret), false);
  assert.equal(normalizeShellCommand(`curl -d '{"user": {"name": "x", "password": "${secret}"}}'`).text.includes(secret), false);
  assert.equal(normalizeShellCommand(`curl -d '{"password": "two words ${secret}"}'`).text.includes(secret), false, 'a quoted value with spaces');
});

test('MEDIUM-R5-1: past its deadline or size limits, normalization gives a truncated placeholder (kind and tool name only)', () => {
  const past = normalizedHookAction({ tool_name: 'Bash', tool_input: { command: 'wrangler deploy --env production' } }, { deadlineAt: Date.now() - 1 });
  assert.deepEqual(past, { tool_kind: 'shell', tool_name: 'Bash', tool_input: {}, truncated: true });
  assert.deepEqual(normalizedHookAction({ tool_name: 'mcp__db__query', tool_input: { sql: 'select 1' } }, { deadlineAt: Date.now() - 1 }), { tool_kind: 'mcp', tool_name: 'mcp__db__query', tool_input: {}, truncated: true });
  assert.equal(normalizeShellCommand('wrangler deploy', Date.now() - 1).truncated, true);
  assert.equal(shell(`deploy ${'x '.repeat(140_000)}`).truncated, true, 'over 256 KB');
  assert.equal(shell(`deploy ${'x '.repeat(5_000)}`).truncated, true, 'over 4096 words');
  assert.equal(shell('wrangler deploy --env production').truncated, undefined, 'a normal command is unaffected');
});

test('LOW-R5-3: input a host adapter cut or dropped is marked truncated; uncut input is not', () => {
  const action = (event) => normalizedHookAction(normalizeHookEventPayload(event));
  const pad = `echo ${'a'.repeat(9_000)} ; `;
  const cut = {
    windsurf_command_over_8k: { agent_action_name: 'pre_run_command', trajectory_id: 't', execution_id: 'e1', tool_info: { command_line: `${pad}psql -c "DROP TABLE users"` } },
    windsurf_mcp_arguments_dropped: { agent_action_name: 'pre_mcp_tool_use', trajectory_id: 't', execution_id: 'e2', tool_info: { mcp_server_name: 'db', mcp_tool_name: 'execute', mcp_tool_arguments: { sql: 'DROP TABLE users' } } },
    windsurf_write_code_dropped: { agent_action_name: 'pre_write_code', trajectory_id: 't', execution_id: 'e3', tool_info: { file_path: '/repo/.github/workflows/deploy.yml', edits: [{ old_string: 'x', new_string: 'y' }] } },
    cursor_command_over_64k: { hook_event_name: 'beforeShellExecution', conversation_id: 'c', generation_id: 'g1', command: `echo ${'a'.repeat(70_000)} ; psql -c "DROP TABLE users"` },
    cursor_mcp_over_256k: { hook_event_name: 'beforeMCPExecution', conversation_id: 'c', generation_id: 'g2', mcp_server_name: 'db', tool_name: 'execute', tool_input: JSON.stringify({ pad: 'a'.repeat(270_000), sql: 'DROP TABLE users' }) },
    cursor_mcp_unparseable_over_4k: { hook_event_name: 'beforeMCPExecution', conversation_id: 'c', generation_id: 'g3', mcp_server_name: 'db', tool_name: 'execute', tool_input: `{bad ${'a'.repeat(5_000)} DROP TABLE users` },
  };
  for (const [name, event] of Object.entries(cut)) assert.equal(action(event).truncated, true, name);
  const whole = {
    windsurf_short_command: { agent_action_name: 'pre_run_command', trajectory_id: 't', execution_id: 'e4', tool_info: { command_line: 'wrangler deploy --env production' } },
    cursor_mcp_small: { hook_event_name: 'beforeMCPExecution', conversation_id: 'c', generation_id: 'g4', mcp_server_name: 'db', tool_name: 'execute', tool_input: JSON.stringify({ sql: 'DROP TABLE users' }) },
    cursor_command: { hook_event_name: 'beforeShellExecution', conversation_id: 'c', generation_id: 'g5', command: 'wrangler deploy --env production' },
  };
  for (const [name, event] of Object.entries(whole)) assert.equal(action(event).truncated, undefined, name);
});

// ---------------------------------------------------------------- Fix round 6 (MEDIUM-R6-1)

test('MEDIUM-R6-1: a credential value ends at the next query or form field, so token-first variants are different actions', () => {
  const T = `Zq9${randomBytes(6).toString('hex')}`;
  const pairs = [
    ['webhook query', `curl -X POST "https://hooks.example.com/deploy?token=${T}&env=staging"`, `curl -X POST "https://hooks.example.com/deploy?token=${T}&env=production"`],
    ['access_token query', `curl "https://api.example.com/scale?access_token=${T}&replicas=3"`, `curl "https://api.example.com/scale?access_token=${T}&replicas=0"`],
    ['form body -d', `curl -d 'api_key=${T}&sql=SELECT 1' https://db.example.com/q`, `curl -d 'api_key=${T}&sql=DROP TABLE users' https://db.example.com/q`],
    ['--data-urlencode', `curl --data-urlencode 'token=${T}&env=staging' https://x.example.com`, `curl --data-urlencode 'token=${T}&env=production' https://x.example.com`],
    ['--data=', `curl '--data=api_key=${T}&op=read' https://x.example.com`, `curl '--data=api_key=${T}&op=delete' https://x.example.com`],
    // A `#` ends the value only before a name= field (LOW-R7-2); a bare #tail may be part of the secret.
    ['fragment field', `curl "https://x.example.com/a?token=${T}#env=staging"`, `curl "https://x.example.com/a?token=${T}#env=production"`],
    ['cookie header', `curl -H "Cookie: session=${T}; env=staging" https://x.example.com`, `curl -H "Cookie: session=${T}; env=production" https://x.example.com`],
    ['json body', `curl -d '{"token": "${T}", "env": "staging"}' https://x.example.com`, `curl -d '{"token": "${T}", "env": "production"}' https://x.example.com`],
  ];
  for (const [label, a, b] of pairs) {
    const left = shell(a);
    const right = shell(b);
    assert.notEqual(left.tool_input.command_sha256, right.tool_input.command_sha256, `${label}: different actions`);
    for (const command of [a, b]) {
      assert.equal(normalizeShellCommand(command).text.includes(T), false, `${label}: the credential is withheld`);
      assert.equal(JSON.stringify(shell(command)).includes(T), false, `${label}: not sent`);
    }
  }
  // The same token-first command is the same action on a retry.
  assert.equal(hashOf(pairs[0][1]), hashOf(pairs[0][1].replace('curl -X POST', 'curl  -X  POST')));
  // A withheld value that itself held name=value fields cannot be told apart: truncated.
  assert.equal(shell(`deploy --token=${T}=env=prod`).truncated, true);
  assert.equal(shell(`TOKEN=${T}=x ./deploy.sh`).truncated, true);
  assert.equal(shell(`curl -H "Cookie: session=${T}; env=staging" https://x.example.com`).truncated, true);
  // Any replaced credential marks the action truncated (never reused); base64 padding is not a field.
  assert.equal(shell(`curl -H "Authorization: Bearer ${T}" https://x.example.com`).truncated, true);
  assert.equal(shell(`deploy --token ${T}==`).truncated, true);
  assert.equal(shell(`deploy --token ${T}==`).tool_input.command_sha256, shell(`deploy --token ${T.slice(0, -1)}Q==`).tool_input.command_sha256);
  assert.equal(shell(`curl "https://hooks.example.com/deploy?token=${T}"`).truncated, true);
  assert.equal(shell('curl https://hooks.example.com/status').truncated, undefined, 'no secret: exact, may be reused');
});

test('LOW-R7-2: no part of a secret containing # , & ; | ) stays in the normalized text; a following name= field still ends it', () => {
  const part = () => `p${randomBytes(5).toString('hex')}`;
  const builds = [
    ['?token=ab<sep>cd', (s) => `curl "https://x.example.com/a?token=${s}"`],
    ['form password=ab<sep>cd&env=x', (s) => `curl -d 'password=${s}&env=prod' https://x.example.com`],
    ['header X-Api-Key: ab<sep>cd', (s) => `curl -H 'X-Api-Key: ${s}' https://x.example.com`],
    ['PASSWORD=ab<sep>cd', (s) => `PASSWORD='${s}' ./deploy.sh`],
    ['--password=ab<sep>cd', (s) => `deploy '--password=${s}'`],
    ['sshpass -p ab<sep>cd', (s) => `sshpass -p '${s}' ssh root@prod`],
    ['API_KEY=ab<sep>cd quoted', (s) => `API_KEY='${s}' deploy`],
    ['json-ish {token:ab<sep>cd}', (s) => `curl -d '{token:${s}}' https://x.example.com`],
    ['?code=ab<sep>cd', (s) => `curl "https://x.example.com/cb?code=${s}"`],
    ['Bearer ab<sep>cd', (s) => `curl -H "Authorization: Bearer ${s}" https://x.example.com`],
    ['curl -b sid=ab<sep>cd', (s) => `curl -b "sid=${s}" https://x.example.com`],
  ];
  for (const sep of ['#', ',', '&', ';', '|', ')', '}', ']']) {
    for (const [label, build] of builds) {
      const head = `${part()}${part()}`;
      const tail = part();
      const text = normalizeShellCommand(build(`${head}${sep}${tail}`)).text;
      assert.equal(text.includes(head) || text.includes(tail), false, `${label} with ${JSON.stringify(sep)}: no part of the secret stays`);
    }
  }
  // A following name= / name: field still ends the value, so actions that differ after it stay different.
  const s = `p${randomBytes(8).toString('hex')}`;
  const keyed = (command) => normalizedHookAction({ tool_name: 'Bash', tool_input: { command } }).tool_input.command_sha256;
  for (const [a, b] of [
    [`curl "https://x.example.com/a?token=${s}&env=staging"`, `curl "https://x.example.com/a?token=${s}&env=production"`],
    [`curl "https://x.example.com/a?token=${s}#env=staging"`, `curl "https://x.example.com/a?token=${s}#env=production"`],
    [`curl -d 'password=${s},env=staging' https://x`, `curl -d 'password=${s},env=production' https://x`],
    [`curl -H "Cookie: session=${s}; mode=read" https://x`, `curl -H "Cookie: session=${s}; mode=delete" https://x`],
    [`curl -d '{token:${s},env:staging}' https://x`, `curl -d '{token:${s},env:production}' https://x`],
    [`deploy --token=${s},env=staging`, `deploy --token=${s},env=production`],
  ]) {
    assert.notEqual(keyed(a), keyed(b), a.replace(s, '<s>'));
    assert.equal(normalizeShellCommand(a).text.includes(s), false);
  }
  assert.match(normalizeShellCommand(`curl "https://x.example.com/a?token=${s}&env=prod"`).text, /&env=prod/, '?token=S&env=prod keeps env');
});

test('Credential names match by containing a credential word, with explicit non-secret exclusions', () => {
  for (const name of ['SECRET_KEY_BASE', 'GITHUB_TOKEN_V2', 'DBPASS', 'ADMINPASS', 'MYPWD', 'AWSCREDS', 'MYAPIKEY', 'SIGNINGKEY', 'DB_PASSWORD_PROD', 'npm_token']) {
    assert.equal(classifySecretName(name), 'credential', name);
  }
  for (const name of ['TOKEN_FILE', 'SECRET_NAME', 'API_KEY_ID', 'PASSWORD_PATH', 'BYPASS_CACHE', 'COMPASS_URL', 'PASSIVE_MODE', 'PASSPORT_PATH', 'TARGET', 'ENV']) {
    assert.notEqual(classifySecretName(name), 'credential', name);
  }
});
