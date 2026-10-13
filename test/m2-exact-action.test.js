'use strict';
// M2 (normalized_action collisions as approval keys): the collision and abuse matrix at the normalizer,
// the local correlation and the receipt key. Every id, secret and salt is generated at run time and never
// printed: rows report counts only.
const assert = require('node:assert/strict');
const test = require('node:test');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { chmodSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const NA = join(__dirname, '..', 'dist', 'normalized-action.js');
const { normalizedHookAction, normalizeShellCommand } = require(NA);
const { stableToolCorrelation } = require('../dist/hook-contract.js');
const { deviceSalt, writeSeatbeltReceipt } = require('../dist/seatbelt/record.js');

const N = Number(process.env.M2_PAIRS || 200);
const norm = (event, options = {}) => normalizedHookAction(event, { deadlineAt: Date.now() + 5_000, ...options });
const corr = (event, session = 'session-m2') => stableToolCorrelation({ ...event, session_id: session });
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// ---- runtime generators (design-m2/fuzz.cjs) ----------------------------------------------------
const pick = (s) => s[crypto.randomInt(s.length)];
const UP = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const LO = 'abcdefghijklmnopqrstuvwxyz';
const DI = '0123456789';
const HEX = '0123456789abcdef';
function shuffle(chars) {
  for (let i = chars.length - 1; i > 0; i -= 1) { const j = crypto.randomInt(i + 1); [chars[i], chars[j]] = [chars[j], chars[i]]; }
  return chars.join('');
}
const mixed = (len) => shuffle([pick(UP), pick(LO), pick(DI), ...Array.from({ length: len - 3 }, () => pick(UP + LO + DI))]);
const camel = () => { const words = ['Release', 'Candidate', 'Branch', 'Payments', 'Service', 'Blue', 'Green', 'Feature', 'Retry', 'Logic', 'Checkout', 'Ledger', 'Invoice', 'Sync', 'Worker']; let s = ''; while (s.length < 20) s += pick(words); return `${s}${crypto.randomInt(1, 99)}`; };
const lower = (len) => Array.from({ length: len }, (_, i) => (i % 7 === 6 ? '-' : pick(LO + DI))).join('');
const hex = (len) => Array.from({ length: len }, () => pick(HEX)).join('');
const word = (len) => Array.from({ length: len }, () => pick(LO)).join('');
const upperDigits = (len) => shuffle([pick(UP), pick(DI), ...Array.from({ length: len - 2 }, () => pick(UP + DI))]);
// A leading letter: a value that starts with `-` reads as a flag, a different (and stricter) case.
const dummySecret = () => `s${crypto.randomBytes(24).toString('base64url')}`;

const bash = (command) => ({ tool_name: 'Bash', tool_input: { command } });
const mcp = (tool, input) => ({ tool_name: tool, tool_input: input });
const write = (file_path, content) => ({ tool_name: 'Write', tool_input: { file_path, content } });

// D1: every merge class of the design (R1-R12, 34 truncated + R12); two values that differ outside any secret.
const CLASSES = [
  ['R1 git push branch (CamelCase+digit)', camel, (v) => bash(`git push origin ${v}:main`)],
  ['R1 git push branch (random mixed 20-32)', () => mixed(20 + crypto.randomInt(13)), (v) => bash(`git push origin ${v}:main`)],
  ['R1 git push feature/<CamelCase> ref', camel, (v) => bash(`git push origin feature/${v}`)],
  ['R1 git checkout branch', camel, (v) => bash(`git checkout ${v}`)],
  ['R1 kubectl delete deployment <Camel>', camel, (v) => bash(`kubectl delete deployment ${v}`)],
  ['R1 ssh host label <mixed>', () => mixed(22), (v) => bash(`ssh ${v} sudo systemctl restart api`)],
  ['R1 terraform -target=<mixed>', () => mixed(24), (v) => bash(`terraform destroy -auto-approve -target=${v}`)],
  ['R1 s3 key <mixed> in s3:// path', () => mixed(24), (v) => bash(`aws s3 rm s3://prod-assets/exports/${v}`)],
  ['R1 SQL literal <mixed> id', () => mixed(24), (v) => bash(`psql -c "DELETE FROM accounts WHERE id='${v}'"`)],
  ['R1 Stripe-like id pi_<mixed24>', () => `pi_${mixed(24)}`, (v) => bash(`stripe refunds create --payment-intent=${v}`)],
  ['R2 git reset --hard <sha40>', () => hex(40), (v) => bash(`git reset --hard ${v}`)],
  ['R2 git push <sha40>:main', () => hex(40), (v) => bash(`git push -f origin ${v}:main`)],
  ['R2 docker rm <container64>', () => hex(64), (v) => bash(`docker rm -f ${v}`)],
  ['R2 image digest sha256:<64>', () => hex(64), (v) => bash(`kubectl set image deployment/web web=registry.example.test/web@sha256:${v}`)],
  ['R2 md5-like id <hex32> in URL', () => hex(32), (v) => bash(`curl -X DELETE https://api.example.test/v1/objects/${v}`)],
  ['R3 URL path id <mixed24>', () => mixed(24), (v) => bash(`curl -X DELETE https://api.example.test/v1/users/${v}`)],
  ['R3 URL query id=<mixed24>', () => mixed(24), (v) => bash(`curl -X DELETE "https://api.example.test/v1/users?id=${v}&hard=true"`)],
  ['R3 URL query session=<lower> (ambiguous name)', () => lower(10), (v) => bash(`curl -X POST "https://api.example.test/v1/purge?session=${v}&scope=all"`)],
  ['R4 --key <path> flag (ambiguous name)', () => `reports/${word(6)}.csv`, (v) => bash(`aws s3api delete-object --bucket prod-assets --key ${v}`)],
  ['R4 helm --set key=<value> (ambiguous name)', () => word(8), (v) => bash(`helm upgrade api ./chart --set key=${v}`)],
  ['R4 --session <value> flag (ambiguous name)', () => `${word(6)}-db`, (v) => bash(`dbctl drop --session ${v}`)],
  ['R5 commit message word after Token', () => word(9), (v) => bash(`git commit -am "Token ${v} cleanup"`)],
  ['R6 program named for a secret: positional', () => pick(['production', 'staging', 'dev', 'eu-prod', 'us-prod']) + word(3), (v) => bash(`./rotate-password.sh ${v}`)],
  ['R7 MCP input charge id <mixed27>', () => `ch_${mixed(24)}`, (v) => mcp('mcp__stripe__create_refund', { charge: v, amount: 500 })],
  ['R7 MCP input branch <Camel>', camel, (v) => mcp('mcp__github__delete_branch', { owner: 'acme', repo: 'api', branch: v })],
  ['R7 MCP input field "key" (ambiguous)', () => `reports/${word(6)}.csv`, (v) => mcp('mcp__s3__delete_object', { bucket: 'prod-assets', key: v })],
  ['R7 MCP input field "max_tokens" (credential stem)', () => crypto.randomInt(1, 100000), (v) => mcp('mcp__llm__complete', { prompt: 'summarize the incident', max_tokens: v })],
  ['R8 edit path dir <Camel>', camel, (v) => write(`/repo/services/${v}/index.ts`, 'export {};\n')],
  ['R8 edit path other user home', () => word(6), (v) => write(`/home/${v}/project/app.ts`, 'export {};\n')],
  ['R9 large write content >16KB, same path', () => crypto.randomBytes(9000).toString('hex'), (v) => write('/repo/src/data.ts', v)],
  ['R9 large MCP string >16KB', () => crypto.randomBytes(9000).toString('hex'), (v) => mcp('mcp__db__execute', { sql: v })],
  ['R10 MCP array >64 entries, differ at 65+', () => crypto.randomInt(1e9), (v) => mcp('mcp__ops__delete_many', { ids: [...Array.from({ length: 64 }, (_, i) => `id-${i}`), `id-${v}`] })],
  ['R10 MCP nesting >6, differ deep', () => word(6), (v) => mcp('mcp__ops__apply', { a: { b: { c: { d: { e: { f: { g: { env: v } } } } } } } })],
  ['R11 tool name >128 chars, differ after 128', () => word(8), (v) => mcp(`mcp__${'x'.repeat(130)}${v}`, { a: 1 })],
  ['R12 DEPLOY_REF=<Camel> (data probe)', camel, (v) => bash(`DEPLOY_REF=${v} ./deploy.sh`)],
  ['C0 control: lowercase uuid id', () => crypto.randomUUID(), (v) => bash(`curl -X DELETE https://api.example.test/v1/users/${v}`)],
  ['C0 control: short sha7', () => hex(7), (v) => bash(`git reset --hard ${v}`)],
  ['C0 control: lowercase k8s name', () => lower(24), (v) => bash(`kubectl delete deployment ${v}`)],
  ['C0 control: UPPER+digit id (no lowercase)', () => upperDigits(24), (v) => bash(`curl -X DELETE https://api.example.test/v1/users/${v}`)],
];

test('D1: every design merge class (R1-R12), N runtime pairs each: 0 merged normalized_action, 0 merged correlation', () => {
  const rows = [];
  for (const [label, gen, make] of CLASSES) {
    let pairs = 0; let merged = 0; let corrMerged = 0; let truncated = 0;
    for (let i = 0; i < N; i += 1) {
      const a = gen(); let b = gen();
      for (let guard = 0; String(b) === String(a) && guard < 10; guard += 1) b = gen();
      if (String(a) === String(b)) continue;
      pairs += 1;
      const ea = make(a); const eb = make(b);
      const na = norm(ea); const nb = norm(eb);
      if (same(na, nb)) merged += 1;
      if (corr(ea) === corr(eb)) corrMerged += 1;
      if (na.truncated === true && nb.truncated === true) truncated += 1;
    }
    rows.push({ label, pairs, merged, corrMerged, truncated });
  }
  if (process.env.M2_REPORT) process.stdout.write(`# M2 D1 ${JSON.stringify(rows)}\n`);
  for (const row of rows) {
    assert.ok(row.pairs >= N * 0.9, `${row.label}: pairs ${row.pairs}`);
    assert.equal(row.merged, 0, `${row.label}: merged normalized_action`);
    assert.equal(row.corrMerged, 0, `${row.label}: merged correlation`);
  }
  // The truncated classes stay truncated (the server never binds them); the controls stay exact.
  for (const row of rows.filter((r) => /^R(?:[1-9]|1[01]) /.test(r.label))) assert.equal(row.truncated, row.pairs, `${row.label}: still truncated`);
  for (const row of rows.filter((r) => r.label.startsWith('C0'))) assert.equal(row.truncated, 0, `${row.label}: exact`);
});

test('D1 (receipt key): the seatbelt receipt action_key of two classes members differs (one runtime pair per class)', () => {
  const home = mkdtempSync(join(tmpdir(), 'm2-receipt-'));
  try {
    const keys = (event) => {
      const status = writeSeatbeltReceipt({ v: 1, mode: 'account', enforcement: 'watch', harness: 'claude-code', decision: 'pass', category: 'none', rule: 'none', reasons: [], flags: [], parse: 'ok', latency_ms: 1 },
        { tool_name: event.tool_name, tool_input: event.tool_input, session: 's' }, { home });
      assert.equal(status, 'written');
      const dir = join(home, '.marrow', 'seatbelt', 'receipts');
      const file = readdirSync(dir).sort().pop();
      const lines = readFileSync(join(dir, file), 'utf8').trim().split('\n');
      return JSON.parse(lines[lines.length - 1]).action_key;
    };
    let merged = 0;
    for (const [, gen, make] of CLASSES.filter(([label]) => !label.startsWith('C0'))) {
      const a = gen(); let b = gen();
      while (String(a) === String(b)) b = gen();
      if (keys(make(a)) === keys(make(b))) merged += 1;
    }
    assert.equal(merged, 0);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test('D2: H1-H5 (printf/echo word joins, trailing CR, lone CR) are different actions; H1-H3 untruncated, H4/H5 truncated', () => {
  const pairs = [
    ['H1', bash(`printf '%s\\n' alpha bravo | sh`), bash(`printf '%s\\n' 'alpha bravo' | sh`), false],
    ['H2', bash('echo -n DROP TABLE x > /tmp/q.sql'), bash('echo "-n DROP TABLE x" > /tmp/q.sql'), false],
    ['H3', bash(`echo -e 'a\\nb' | psql`), bash(`echo '-e a\\nb' | psql`), false],
    ['H4', bash('git push origin main\r'), bash('git push origin main'), 'first'],
    ['H5', bash('rm -rf build\rdist'), bash('rm -rf build ; dist'), 'first'],
  ];
  for (const [label, a, b, truncated] of pairs) {
    const na = norm(a); const nb = norm(b);
    assert.equal(same(na, nb), false, `${label}: different normalized_action`);
    assert.notEqual(corr(a), corr(b), `${label}: different correlation`);
    if (truncated === false) {
      assert.equal(na.truncated, undefined, `${label}: exact (untruncated)`);
      assert.equal(nb.truncated, undefined, `${label}: exact (untruncated)`);
      assert.notEqual(na.tool_input.command_sha256, nb.tool_input.command_sha256, `${label}: different sent hash`);
    } else {
      assert.equal(na.truncated, true, `${label}: a lone CR is truncated`);
      assert.match(na.tool_input.exact_hmac, /^[0-9a-f]{32}$/);
    }
  }
  // Ends that bash keeps in the last word (lone CR, non-ASCII space, vertical tab) are not trimmed away from the key.
  for (const [a, b] of [['git push origin main\r', 'git push origin main\r\r'], ['rm -rf build\u00a0', 'rm -rf build'], ['rm -rf build\v', 'rm -rf build\u00a0'], ['\u00a0rm -rf build', 'rm -rf build']]) {
    const na = norm(bash(a)); const nb = norm(bash(b));
    assert.equal(same(na, nb), false, JSON.stringify([a, b]));
    assert.notEqual(corr(bash(a)), corr(bash(b)));
  }
  assert.equal(norm(bash('rm -rf build\u00a0')).tool_input.command, undefined);
  assert.equal(same(norm(bash('git push origin main\r')), norm(bash('git push origin main\r'))), true, 'the same text is the same action');
  // ASCII spaces, tabs and newlines at the ends change nothing.
  assert.equal(same(norm(bash(' git status\t\n')), norm(bash('git status'))), true);
  // CRLF is still a line end (unchanged), and the same command is the same action.
  assert.equal(same(norm(bash('git status\r\n')), norm(bash('git status\n'))), true);
  assert.equal(norm(bash('git status\r\n')).truncated, undefined);
  // The allowed equal forms stay equal (same meaning): Codex argv vs string, tab vs space, description.
  assert.equal(same(norm({ tool_name: 'Bash', tool_input: { command: ['git', 'push', 'origin', 'a b'] } }), norm(bash(`git push origin 'a b'`))), true);
  assert.equal(same(norm(bash('git\tpush origin main')), norm(bash('git push origin main'))), true);
  assert.equal(same(norm({ tool_name: 'Bash', tool_input: { command: 'make deploy', description: 'a' } }), norm({ tool_name: 'Bash', tool_input: { command: 'make deploy', description: 'b' } })), true);
});

test('D3: placeholders (deadline, size) key the raw input: different inputs differ, the same input matches; over 1 MB is a nonce', () => {
  const past = { deadlineAt: Date.now() - 1 };
  const a = normalizedHookAction(bash('kubectl delete namespace payments-prod'), past);
  const b = normalizedHookAction(bash('kubectl delete namespace payments-staging'), past);
  assert.deepEqual(Object.keys(a.tool_input), ['exact_hmac']);
  assert.notEqual(a.tool_input.exact_hmac, b.tool_input.exact_hmac, 'H6: two placeholders of different commands differ');
  assert.equal(normalizedHookAction(bash('kubectl delete namespace payments-prod'), past).tool_input.exact_hmac, a.tool_input.exact_hmac, 'a retry of the same placeholder matches');
  // A command over the 256 KB normalization limit: raw command keyed.
  const big = (tail) => bash(`echo ${'x '.repeat(140_000)}; kubectl delete namespace ${tail}`);
  assert.notEqual(norm(big('a')).tool_input.exact_hmac, norm(big('b')).tool_input.exact_hmac);
  assert.equal(norm(big('a')).tool_input.exact_hmac, norm(big('a')).tool_input.exact_hmac);
  // Over 1 MB: a fresh nonce every time (matches nothing, not even itself).
  const huge = mcp('mcp__db__execute', { sql: 'x'.repeat(1_100_000) });
  const h1 = norm(huge); const h2 = norm(huge);
  assert.equal(h1.truncated, true);
  assert.notEqual(h1.tool_input.exact_hmac, h2.tool_input.exact_hmac, 'nonce, never reused');
  const hugeAgain = mcp('mcp__db__execute', { sql: 'x'.repeat(1_100_000) });
  assert.notEqual(corr(huge), corr(hugeAgain), 'the correlation of a nonce never matches (a fresh process sees a fresh nonce)');
});

test('D4: differences after a redacted span still differ (URL query, form, header, env, JSON, flag, heredoc, MCP, write)', () => {
  const s = dummySecret();
  const rows = [
    (v) => bash(`curl "https://x.example.test/a?token=${s}&env=${v}"`),
    (v) => bash(`curl -d 'api_key=${s}&op=${v}' https://x.example.test`),
    (v) => bash(`curl -H "Authorization: Bearer ${s}" -H "X-Env: ${v}" https://x.example.test`),
    (v) => bash(`DEPLOY_TOKEN=${s} TARGET=${v} ./deploy.sh`),
    (v) => bash(`curl -d '{"token": "${s}", "env": "${v}"}' https://x.example.test`),
    (v) => bash(`deploy --token ${s} --env ${v}`),
    (v) => bash(`cat <<EOF | post\n{"api_key":"${s}","env":"${v}"}\nEOF`),
    (v) => mcp('mcp__ops__deploy', { api_key: s, env: v }),
    (v) => write('/repo/.env.example', `API_KEY=${s}\nENV=${v}\n`),
  ];
  for (const make of rows) {
    const a = make('staging'); const b = make('production');
    assert.equal(same(norm(a), norm(b)), false);
    assert.notEqual(corr(a), corr(b));
  }
});

test('D5: a credential position that holds a shell reference ($VAR, ${VAR}, $(...), backquotes) differs by the reference', () => {
  const pairs = [
    ['API_KEY=$READONLY_KEY ./deploy.sh', 'API_KEY=$ADMIN_KEY ./deploy.sh'],
    ['export API_KEY=$READONLY_KEY; ./deploy.sh', 'export API_KEY=$ADMIN_KEY; ./deploy.sh'],
    ['deploy --token $RO_TOKEN', 'deploy --token $ADMIN_TOKEN'],
    ['curl -H "Authorization: Bearer ${TOKEN_RO}" https://a.example.test', 'curl -H "Authorization: Bearer ${TOKEN_ADMIN}" https://a.example.test'],
    ['mysql -p"$(cat ro.pw)" -e "drop table t"', 'mysql -p"$(cat admin.pw)" -e "drop table t"'],
    ['mysql -p"$(cat $(echo ro).pw)" -e "drop table t"', 'mysql -p"$(cat $(echo admin).pw)" -e "drop table t"'],
    ['deploy --password `cat ro.pw`', 'deploy --password `cat admin.pw`'],
    ['git push https://deploy:$RO_PW@git.example.test/a.git main', 'git push https://deploy:$ADMIN_PW@git.example.test/a.git main'],
  ];
  for (const [a, b] of pairs) {
    const na = norm(bash(a)); const nb = norm(bash(b));
    assert.equal(na.truncated, true);
    assert.equal(same(na, nb), false, a);
    assert.notEqual(corr(bash(a)), corr(bash(b)), a);
    assert.equal(same(na, norm(bash(a))), true, `${a}: the same command matches`);
  }
  // Basic USER:PASSWORD: the user names who acts (as curl -u); only the password is certain.
  const basic = (user, pw) => bash(`curl -X DELETE -H "Authorization: Basic ${Buffer.from(`${user}:${pw}`).toString('base64')}" https://a.example.test/v1/x`);
  const pw1 = dummySecret(); const pw2 = dummySecret();
  assert.equal(same(norm(basic('readonly', pw1)), norm(basic('admin', pw1))), false, 'Basic: a different user');
  assert.equal(same(norm(basic('admin', pw1)), norm(basic('admin', pw2))), true, 'Basic: only the password differs');
});

test('D6: values under credential-looking names that name or count something, key ids and public keys differ in the exact key', () => {
  // Every key-like shape is built here at run time (never a literal in the file).
  const awsId = () => `${['AK', 'IA'].join('')}${upperDigits(16)}`;
  const publishable = () => `${['pk', 'live'].join('_')}_${hex(20)}`;
  const block = (label, body) => `${'-'.repeat(5)}BEGIN ${label}${'-'.repeat(5)}\\n${body}\\n${'-'.repeat(5)}END ${label}${'-'.repeat(5)}`;
  const cert = ['CERTIFICATE'].join('');
  const privateLabel = ['PRIVATE', 'KEY'].join(' ');
  const pairs = [
    ['SECRETNAME=prod/db-one ./rotate.sh', 'SECRETNAME=prod/api-two ./rotate.sh'],
    ['TOKENID=one ./revoke.sh', 'TOKENID=two ./revoke.sh'],
    ['./setup --passwordless=prod-a', './setup --passwordless=prod-b'],
    [`aws iam delete-access-key --user-name ci --access-key-id ${awsId()}`, `aws iam delete-access-key --user-name ci --access-key-id ${awsId()}`],
    [`curl -X DELETE https://a.example.test/v1/keys/${publishable()}`, `curl -X DELETE https://a.example.test/v1/keys/${publishable()}`],
    [`echo "${block(cert, hex(40))}" > /etc/ssl/ca.pem`, `echo "${block(cert, hex(40))}" > /etc/ssl/ca.pem`],
  ];
  for (const [a, b] of pairs) assert.equal(same(norm(bash(a)), norm(bash(b))), false, a.slice(0, 40));
  for (const [a, b] of [[{ credentials: 'prod/db-one' }, { credentials: 'prod/api-two' }], [{ max_tokens: 10 }, { max_tokens: 99999 }]]) {
    assert.equal(same(norm(mcp('mcp__x__run', a)), norm(mcp('mcp__x__run', b))), false, Object.keys(a)[0]);
  }
  // A private key block and a certain credential name still match across a rotation.
  const pk = (x) => bash(`echo "${block(privateLabel, x)}" > ~/.ssh/deploy`);
  assert.equal(same(norm(pk(dummySecret())), norm(pk(dummySecret()))), true, 'private key block');
  for (const name of ['PGPASSWORD', 'GITHUB_TOKEN', 'DB_PASS', 'client_secret', 'AWS_SECRET_ACCESS_KEY', 'x_api_key']) {
    assert.equal(same(norm(bash(`${name}=${dummySecret()} ./x.sh`)), norm(bash(`${name}=${dummySecret()} ./x.sh`))), true, name);
  }
});

test('D7: quoting that changes what the shell expands is a different action (sent hash and exact key); same-meaning quoting is not', () => {
  const differ = [
    ['rm -rf "$HOME"', "rm -rf '$HOME'"], ['rm -rf $HOME', 'rm -rf \\$HOME'], ['rm -rf *', "rm -rf '*'"], ['rm -rf *', 'rm -rf \\*'],
    ['rm -rf ./*', "rm -rf './*'"], ['rm -rf ~', "rm -rf '~'"], ['rm -rf ~/x', 'rm -rf "~/x"'], ['echo "$(id)" | sh', "echo '$(id)' | sh"],
    ['git push origin "$BRANCH"', "git push origin '$BRANCH'"], ['rm -rf {a,b}', "rm -rf '{a,b}'"], ['rm -rf a?', "rm -rf 'a?'"],
    ['cat <<EOF > run.sh\nrm -rf $TARGET\nEOF', "cat <<'EOF' > run.sh\nrm -rf $TARGET\nEOF"],
    ["bash -c 'rm -rf *'", `bash -c 'rm -rf "*"'`], ["ssh prod 'rm -rf ~/x'", `ssh prod 'rm -rf "~/x"'`],
    ['psql <<< "$QUERY"', "psql <<< '$QUERY'"], ['X=$HOME ./run.sh', "X='$HOME' ./run.sh"],
  ];
  for (const [a, b] of differ) {
    const na = norm(bash(a)); const nb = norm(bash(b));
    assert.equal(same(na, nb), false, `${a} | ${b}`);
    assert.notEqual(corr(bash(a)), corr(bash(b)));
    if (na.truncated !== true && nb.truncated !== true) assert.notEqual(na.tool_input.command_sha256, nb.tool_input.command_sha256, `${a}: the sent hash`);
  }
  // With a certain credential in the command (truncated), the exact key still sees the quoting.
  const s = dummySecret();
  assert.equal(same(norm(bash(`curl -H "Authorization: Bearer ${s}" -d @'*' https://a.example.test`)), norm(bash(`curl -H "Authorization: Bearer ${s}" -d @* https://a.example.test`))), false);
  const equal = [
    ["rm -rf '*'", 'rm -rf "*"'], ["rm -rf '*'", 'rm -rf \\*'], ['rm -rf "$HOME"', 'rm -rf $HOME'], ["echo 'a b' > f", 'echo "a b" > f'],
    ["git commit -m 'fix it'", 'git commit -m "fix it"'],
  ];
  for (const [a, b] of equal) assert.equal(same(norm(bash(a)), norm(bash(b))), true, `${a} | ${b}`);
  // An argument vector runs without a shell: its `*` is literal, as a quoted one.
  const argv = (words) => ({ tool_name: 'Bash', tool_input: { command: words } });
  assert.equal(same(norm(argv(['rm', '-rf', '*'])), norm(bash("rm -rf '*'"))), true);
  assert.equal(same(norm(argv(['rm', '-rf', '*'])), norm(bash('rm -rf *'))), false);
});

test('S1: actions that differ only in a certain credential share normalized_action and correlation (an approved hold resumes after an OTP rotates)', () => {
  const rows = [
    ['OTP', (x) => bash(`npm publish --otp ${x}`), () => String(crypto.randomInt(100000, 999999))],
    ['--token', (x) => bash(`vercel deploy --prod --token ${x}`), dummySecret],
    ['Bearer', (x) => bash(`curl -H "Authorization: Bearer ${x}" -X DELETE https://api.example.test/v1/deploy`), dummySecret],
    ['credential env', (x) => bash(`DB_PASSWORD=${x} ./migrate.sh down`), dummySecret],
    ['URL password', (x) => bash(`git push https://deploy:${x}@git.example.test/acme/api.git main`), dummySecret],
    ['mysql -p', (x) => bash(`mysql -u root -p${x} prod -e "drop table x"`), dummySecret],
    ['MCP api_key', (x) => mcp('mcp__ops__deploy', { api_key: x, env: 'production' }), dummySecret],
    ['secrets-command value', (x) => bash(`gh secret set DEPLOY_KEY --body ${x}`), dummySecret],
    ['known key format', (x) => bash(`deploy --env production ${['gh', 'p'].join('')}_${x.replace(/[^A-Za-z0-9]/g, 'a').padEnd(36, 'b')}`), dummySecret],
    ['curl -u password (user kept)', (x) => bash(`curl -u admin:${x} -X DELETE https://api.example.test/v1/a`), dummySecret],
  ];
  for (const [label, make, gen] of rows) {
    let equal = 0; let leaks = 0;
    for (let i = 0; i < 25; i += 1) {
      const x1 = gen(); const x2 = gen();
      const a = make(x1); const b = make(x2);
      const na = norm(a); const nb = norm(b);
      assert.equal(na.truncated, true, `${label}: truncated (never bound on the server)`);
      if (same(na, nb) && corr(a) === corr(b)) equal += 1;
      const visible = JSON.stringify([na, nb, corr(a), corr(b)]);
      for (const x of [x1, x2]) if (x.length >= 8) for (let k = 0; k + 8 <= x.length; k += 1) if (visible.includes(x.slice(k, k + 8))) { leaks += 1; break; }
    }
    assert.equal(equal, 25, `${label}: differ only in a certain credential -> same key`);
    assert.equal(leaks, 0, `${label}: no 8-character slice of the secret`);
  }
  // The user of curl -u names who acts: a different user is a different action.
  const pw = dummySecret();
  assert.equal(same(norm(bash(`curl -u readonly:${pw} -X DELETE https://api.example.test/v1/a`)), norm(bash(`curl -u admin:${pw} -X DELETE https://api.example.test/v1/a`))), false);
});

test('S2: actions that differ only in a value that MAY be a secret (key shape, ambiguous name) are different (allowed)', () => {
  const rows = [
    (x) => bash(`./publish.sh ${x} production`),
    (x) => bash(`curl "https://api.example.test/purge?session=${x}"`),
    (x) => mcp('mcp__ops__run', { key: x }),
    (x) => bash(`git commit -m "Token ${x.replace(/[^a-z]/g, '').slice(0, 7) || 'abc'} rotation"`),
  ];
  for (const make of rows) {
    const a = make(`K${mixed(24)}`); const b = make(`K${mixed(24)}`);
    assert.equal(same(norm(a), norm(b)), false);
  }
});

test('S2 (stricter than the design text): data a secrets command or file reads differs outside a certain credential (vault policy, authorized_keys, gpg input)', () => {
  const pairs = [
    [`echo 'path "secret/app/*" { capabilities = ["read"] }' | vault policy write app -`, `echo 'path "secret/app/*" { capabilities = ["sudo"] }' | vault policy write app -`],
    [`echo "ssh-ed25519 AAAAC3Nza${mixed(30)} owner@laptop" >> ~/.ssh/authorized_keys`, `echo "ssh-ed25519 AAAAC3Nza${mixed(30)} other@host" >> ~/.ssh/authorized_keys`],
    [`echo "release v1.2.3" | gpg --clearsign`, `echo "release v9.9.9" | gpg --clearsign`],
    [`cat <<EOF > .env.production\nDEBUG=false\nEOF`, `cat <<EOF > .env.production\nDEBUG=true\nEOF`],
  ];
  for (const [a, b] of pairs) {
    const na = norm(bash(a)); const nb = norm(bash(b));
    assert.equal(na.truncated, true);
    assert.equal(na.tool_input.command_sha256, nb.tool_input.command_sha256, 'the sent hash is unchanged (all secret)');
    assert.notEqual(na.tool_input.exact_hmac, nb.tool_input.exact_hmac, 'the exact key separates them');
  }
  // A password written into a secrets file still matches across a rotation (only the certain credential differs).
  const write1 = norm(bash(`cat <<EOF > .env.production\nDB_PASSWORD=${dummySecret()}\nEOF`));
  const write2 = norm(bash(`cat <<EOF > .env.production\nDB_PASSWORD=${dummySecret()}\nEOF`));
  assert.equal(same(write1, write2), true);
});

test('S3: 1,000 runtime secrets x 10 carriers: no 8-char slice in normalized_action or correlation; the salt in neither', () => {
  const carriers = [
    (s) => bash(`curl -H "Authorization: Bearer ${s}" https://api.example.test/x`),
    (s) => bash(`API_TOKEN=${s} ./deploy.sh production`),
    (s) => bash(`mysql -p${s} -e "drop database app"`),
    (s) => bash(`git clone https://deploy:${s}@git.example.test/acme/api.git`),
    (s) => mcp('mcp__ops__deploy', { api_key: s, env: 'production' }),
    (s) => bash(`vercel deploy --token ${s}`),
    (s) => bash(`./publish.sh ${s} production`),
    (s) => bash(`echo '{"password":"${s}","env":"prod"}' | post`),
    (s) => bash(`curl "https://api.example.test/x?session=${s}&scope=all"`),
    (s) => write('/repo/config.ts', `export const key = "${s}";`),
  ];
  const salt = deviceSalt();
  assert.ok(Buffer.isBuffer(salt) && salt.length === 32, 'the test machine has a salt (scratch passwd home)');
  const saltForms = [salt.toString('hex'), salt.toString('base64'), salt.toString('base64url'), salt.toString('latin1')];
  let leaks = 0; let saltSeen = 0;
  for (let i = 0; i < 100; i += 1) {
    for (const carry of carriers) {
      const s = dummySecret();
      const event = carry(s);
      const visible = JSON.stringify([norm(event), corr(event)]);
      for (let k = 0; k + 8 <= s.length; k += 1) if (visible.includes(s.slice(k, k + 8))) { leaks += 1; break; }
      if (saltForms.some((form) => visible.includes(form.slice(0, 16)))) saltSeen += 1;
    }
  }
  assert.equal(leaks, 0);
  assert.equal(saltSeen, 0);
});

test('A5: chaining around R1/R2 values (&&, ;, ||, |, subshell, bash -c, ssh, eval) keeps them different', () => {
  const wraps = [
    (c) => `true && ${c}`, (c) => `${c}; echo done`, (c) => `false || ${c}`, (c) => `${c} | tee /tmp/log`,
    (c) => `(${c})`, (c) => `bash -c '${c}'`, (c) => `ssh deploy-host '${c}'`, (c) => `eval '${c}'`,
    (c) => `bash -c "ssh h 'bash -c \\"${c}\\"'"`,
  ];
  for (const wrap of wraps) {
    for (const [gen, make] of [[camel, (v) => `kubectl delete deployment ${v}`], [() => hex(40), (v) => `git push -f origin ${v}:main`]]) {
      let merged = 0;
      for (let i = 0; i < 20; i += 1) {
        const a = gen(); let b = gen();
        while (a === b) b = gen();
        if (same(norm(bash(wrap(make(a)))), norm(bash(wrap(make(b)))))) merged += 1;
      }
      assert.equal(merged, 0, wrap('X'));
    }
  }
});

test('A4 (unit): the device salt fails closed: missing store, symlink, group-readable, wrong size, wrong owner, read-only home', () => {
  const uid = process.getuid();
  const base = mkdtempSync(join(tmpdir(), 'm2-salt-'));
  const prepare = (name, setup) => {
    const home = join(base, name);
    mkdirSync(join(home, '.marrow', 'seatbelt', 'receipts'), { recursive: true, mode: 0o700 });
    chmodSync(join(home, '.marrow'), 0o700);
    setup(home, join(home, '.marrow', 'seatbelt', 'salt'));
    return home;
  };
  try {
    const good = prepare('good', () => {});
    const salt = deviceSalt({ home: good, uid });
    assert.ok(salt && salt.length === 32, 'created once (32 bytes)');
    assert.equal(deviceSalt({ home: good, uid }).equals(salt), true, 'stable');
    const elsewhere = join(base, 'elsewhere');
    writeFileSync(elsewhere, crypto.randomBytes(32), { mode: 0o600 });
    const bad = {
      symlink: prepare('symlink', (_h, p) => symlinkSync(elsewhere, p)),
      group_readable: prepare('group', (_h, p) => { writeFileSync(p, crypto.randomBytes(32), { mode: 0o600 }); chmodSync(p, 0o640); }),
      wrong_size: prepare('size', (_h, p) => writeFileSync(p, crypto.randomBytes(31), { mode: 0o600 })),
      read_only_store: prepare('ro', (h) => chmodSync(join(h, '.marrow', 'seatbelt'), 0o500)),
      store_group_writable: prepare('gw', (h) => chmodSync(join(h, '.marrow', 'seatbelt'), 0o770)),
    };
    for (const [label, home] of Object.entries(bad)) assert.equal(deviceSalt({ home, uid }), null, label);
    assert.equal(deviceSalt({ home: good, uid: uid + 1 }), null, 'wrong owner');
    const roHome = join(base, 'ro-home');
    mkdirSync(roHome, { mode: 0o500 });
    assert.equal(deviceSalt({ home: roHome, uid }), null, 'read-only home (nothing can be created)');
    assert.equal(deviceSalt({ home: 'relative/home', uid }), null, 'relative home');
    chmodSync(join(bad.read_only_store, '.marrow', 'seatbelt'), 0o700);
  } finally { rmSync(base, { recursive: true, force: true }); }
});

test('A4 (unit) + mutants: without a salt exact_hmac is a fresh nonce every time (never unsalted, never merged, never reused)', () => {
  const event = bash(`kubectl delete deployment ${camel()}`);
  const n1 = norm(event, { salt: null }); const n2 = norm(event, { salt: null });
  assert.match(n1.tool_input.exact_hmac, /^[0-9a-f]{32}$/);
  assert.notEqual(n1.tool_input.exact_hmac, n2.tool_input.exact_hmac, 'the same action without a salt never matches itself');
  const s1 = crypto.randomBytes(32); const s2 = crypto.randomBytes(32);
  const k1 = norm(event, { salt: s1 }).tool_input.exact_hmac;
  assert.equal(norm(event, { salt: s1 }).tool_input.exact_hmac, k1, 'salted: deterministic');
  assert.notEqual(norm(event, { salt: s2 }).tool_input.exact_hmac, k1, 'two machines: no link');
  // Not an unsalted hash of any obvious material.
  const unsalted = crypto.createHash('sha256').update(JSON.stringify(event)).digest('hex').slice(0, 32);
  assert.notEqual(n1.tool_input.exact_hmac, unsalted);
  // Untruncated actions carry no exact key at all (nothing new is sent for them).
  assert.equal(norm(bash('wrangler deploy --env production')).tool_input.exact_hmac, undefined);
});

test('A4 (process): a broken salt store gives a nonce, one stderr note without paths or values, and no crash', () => {
  const base = mkdtempSync(join(tmpdir(), 'm2-salt-proc-'));
  try {
    const home = join(base, 'passwd-home');
    mkdirSync(join(home, '.marrow', 'seatbelt'), { recursive: true, mode: 0o700 });
    chmodSync(join(home, '.marrow'), 0o700);
    const salt = join(home, '.marrow', 'seatbelt', 'salt');
    writeFileSync(salt, crypto.randomBytes(32), { mode: 0o600 });
    chmodSync(salt, 0o644);
    const script = `const na = require(${JSON.stringify(NA)});
      const e = { tool_name: 'Bash', tool_input: { command: 'kubectl delete deployment PaymentsServiceBlueGreenA1' } };
      const a = na.normalizedHookAction(e).tool_input.exact_hmac; const b = na.normalizedHookAction(e).tool_input.exact_hmac;
      process.stdout.write(JSON.stringify({ a, b }));`;
    const run = spawnSync(process.execPath, ['-e', script], { env: { ...process.env, SBT_PASSWD_HOME: home }, encoding: 'utf8', timeout: 20_000 });
    assert.equal(run.status, 0, 'no crash');
    const out = JSON.parse(run.stdout);
    assert.match(out.a, /^[0-9a-f]{32}$/);
    assert.notEqual(out.a, out.b, 'nonce: the same action never matches');
    const notes = run.stderr.split('\n').filter((line) => line.includes('private device key'));
    assert.equal(notes.length, 1, 'one note per process');
    assert.equal(/\/|\\|marrow\/seatbelt|salt/.test(notes[0]), false, 'no path in the note');
  } finally { rmSync(base, { recursive: true, force: true }); }
});

test('A8: the two passes stay inside the hook budget (corpus commands and a 256 KB input)', () => {
  const corpus = [
    'git push -f origin ReleaseCandidateBranchAlpha1:main', 'kubectl delete deployment PaymentsServiceBlueGreenA1',
    `curl -H "Authorization: Bearer ${dummySecret()}" -X DELETE https://api.example.test/v1/users/${mixed(24)}`,
    `cat <<EOF | psql prod\n${'SELECT 1;\n'.repeat(500)}EOF`, `echo '${JSON.stringify({ api_key: dummySecret(), rows: Array.from({ length: 200 }, (_, i) => `r${i}`) })}' | post`,
  ];
  const times = [];
  for (let round = 0; round < 20; round += 1) for (const command of corpus) {
    const started = process.hrtime.bigint();
    normalizedHookAction(bash(command), { deadlineAt: Date.now() + 750 });
    times.push(Number(process.hrtime.bigint() - started) / 1e6);
  }
  times.sort((x, y) => x - y);
  const p95 = times[Math.floor(times.length * 0.95)];
  assert.ok(p95 < 150, `corpus p95 ${p95.toFixed(1)} ms`);
  const big = mcp('mcp__db__execute', { sql: `${'x'.repeat(200_000)} ${mixed(24)}`, items: Array.from({ length: 64 }, (_, i) => ({ id: `${mixed(22)}${i}`, value: 'y'.repeat(800) })) });
  const started = Date.now();
  const action = normalizedHookAction(big, { deadlineAt: Date.now() + 750 });
  assert.ok(Date.now() - started < 750, `256 KB input took ${Date.now() - started} ms`);
  assert.equal(action.truncated, true);
});

test('every truncation site has an exact-pass decision (grep count against the list)', () => {
  const source = readFileSync(join(__dirname, '..', 'src', 'normalized-action.ts'), 'utf8');
  const lines = source.split('\n');
  const sites = lines.filter((line) => line.includes('state.truncated = true'));
  const unmarked = sites.filter((line) => !/\/\/ exact: (?:kept|raw|certain|nonce|n\/a)\b/.test(line));
  assert.deepEqual(unmarked, [], 'every `state.truncated = true` names its exact-pass decision');
  // The list: 17 marked sites, and every `withheld(` call keeps the original in the exact pass.
  assert.equal(sites.length, 17, `truncation sites: ${sites.length}`);
  const withheldCalls = (source.match(/\bwithheld\(state,/g) || []).length;
  assert.equal(withheldCalls, 17, `withheld() sites: ${withheldCalls}`);
  assert.match(source, /const HASH_VERSION = 'marrow-normalized-action-v3';/, 'R4: the key version is v3');
});

test('V1 (unit): v3 keys never equal the v2 keys of the same text', () => {
  const sha = (text) => crypto.createHash('sha256').update(text).digest('hex');
  for (const command of ['wrangler deploy --env production', 'git push origin main', 'kubectl delete namespace prod']) {
    const v3 = norm(bash(command)).tool_input.command_sha256;
    assert.equal(v3, sha(`marrow-normalized-action-v3\nshell\n${normalizeShellCommand(command).text}`));
    assert.notEqual(v3, sha(`marrow-normalized-action-v2\nshell\n${normalizeShellCommand(command).text}`));
  }
});

test('two agents on one machine share the salt but never a hold correlation; two sessions never share one', () => {
  const event = bash(`kubectl delete deployment ${camel()}`);
  assert.notEqual(corr(event, 'session-a'), corr(event, 'session-b'));
  // The hold store is scoped by key and agent (host-approval-state scopeOf); the e2e host test checks agents.
  assert.equal(corr(event, 'session-a'), corr(event, 'session-a'));
});
