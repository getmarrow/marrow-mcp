'use strict';

// Test-only (never ships). Rows for the Stripe-style key class (sk_/rk_/pk_ live vs test): where a key can sit in an
// action (POSITIONS), the abuse shapes (LOOKALIKES, CHAINS), and the Unicode names. Dummy keys are generated at
// runtime; nothing here prints one. The same rows run against the head and against a master build (the refinement harness).
const { randomBytes } = require('node:crypto');

const AN = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const pick = (n) => Array.from(randomBytes(n), (byte) => AN[byte % AN.length]).join('');
// Always holds a digit: a payload with none (1 in 60) takes another path-span branch on master too, which is not what the rows test.
const payload = () => { const body = pick(24); return /\d/.test(body) ? body : `${body.slice(0, 23)}${randomBytes(1)[0] % 10}`; };
const live = (prefix = 'sk') => `${prefix}_live_${payload()}`;
const test = (prefix = 'sk') => `${prefix}_test_${payload()}`;

const sh = (command) => ({ tool_name: 'Bash', tool_input: { command } });
const mcp = (input, tool = 'mcp__pay__charge') => ({ tool_name: tool, tool_input: input });
const edit = (file) => ({ tool_name: 'Edit', tool_input: { file_path: file, old_string: 'a', new_string: 'b' } });
const b64 = (text) => Buffer.from(text, 'latin1').toString('base64');
const deep = (key, levels) => { let node = { api_key: key }; for (let i = 0; i < levels; i += 1) node = { n: node }; return node; };

/** build(key, tail): an event with `key` in one position; `tail` differs outside the key (after it). */
const POSITIONS = [
  { id: 'curl-u', build: (k, t = 'a') => sh(`curl -u ${k}: https://api.example.com/${t}`) },
  { id: 'curl-user-flag', build: (k, t = 'a') => sh(`curl --user ${k}: https://api.example.com/${t}`) },
  { id: 'curl-user-eq', build: (k, t = 'a') => sh(`curl --user=${k}: https://api.example.com/${t}`) },
  { id: 'header-bearer', build: (k, t = 'a') => sh(`curl -H "Authorization: Bearer ${k}" https://api.example.com/${t}`) },
  { id: 'header-bearer-then-header', build: (k, t = 'a') => sh(`curl -H "Authorization: Bearer ${k}" -H "X-Env: ${t}" https://api.example.com`) },
  { id: 'header-x-api-key', build: (k, t = 'a') => sh(`curl --header="X-Api-Key: ${k}" https://api.example.com/${t}`) },
  { id: 'header-basic-b64', build: (k, t = 'a') => sh(`curl -H "Authorization: Basic ${b64(`${k}:`)}" https://api.example.com/${t}`) },
  { id: 'env-assign', build: (k, t = 'a') => sh(`STRIPE_API_KEY=${k} TARGET=${t} ./deploy.sh`) },
  { id: 'env-assign-ambiguous-name', build: (k, t = 'a') => sh(`STRIPE_KEY=${k} ./pay.sh ${t}`) },
  { id: 'export', build: (k, t = 'a') => sh(`export STRIPE_SECRET_KEY=${k}; curl https://${t}.example.com/pay`) },
  { id: 'env-wrapper', build: (k, t = 'a') => sh(`env STRIPE_API_KEY=${k} ./pay.sh ${t}`) },
  { id: 'flag-api-key-space', build: (k, t = 'a') => sh(`stripe charges list --api-key ${k} --limit ${t}`) },
  { id: 'flag-api-key-eq', build: (k, t = 'a') => sh(`stripe charges list --api-key=${k} --limit ${t}`) },
  { id: 'flag-token', build: (k, t = 'a') => sh(`deploy --token ${k} --env ${t}`) },
  { id: 'flag-unknown-program-bare', build: (k, t = 'a') => sh(`./pay.sh ${k} ${t}`) },
  { id: 'bare-after-subcommand', build: (k, t = 'a') => sh(`stripe refunds create ${k} --charge ${t}`) },
  { id: 'url-query', build: (k, t = 'a') => sh(`curl "https://api.example.com/run?api_key=${k}&target=${t}"`) },
  { id: 'url-query-token', build: (k, t = 'a') => sh(`curl "https://api.example.com/run?token=${k}&env=${t}"`) },
  { id: 'url-userinfo', build: (k, t = 'a') => sh(`git push https://deploy:${k}@github.com/org/${t}.git main`) },
  { id: 'form-body', build: (k, t = 'a') => sh(`curl -d 'api_key=${k}&sql=${t}' https://db.example.com/q`) },
  { id: 'json-body', build: (k, t = 'a') => sh(`curl -d '{"api_key": "${k}", "env": "${t}"}' https://x.example.com`) },
  { id: 'json-body-nested', build: (k, t = 'a') => sh(`curl -d '{"auth": {"password": "${k}"}, "sql": "${t}"}' https://x.example.com`) },
  { id: 'echo-pipe-json', build: (k, t = 'a') => sh(`echo '{"api_key":"${k}","env":"${t}"}' | post`) },
  { id: 'echo-pipe-docker-login', build: (k, t = 'a') => sh(`echo ${k} | docker login --password-stdin ${t}.example.com`) },
  { id: 'heredoc', build: (k, t = 'a') => sh(`cat <<EOF | post\napi_key=${k}\nenv=${t}\nEOF`) },
  { id: 'here-string', build: (k, t = 'a') => sh(`post <<< '{"token":"${k}","env":"${t}"}'`) },
  { id: 'gh-secret-set', build: (k, t = 'a') => sh(`gh secret set STRIPE_KEY --body ${k} --repo org/${t}`) },
  { id: 'kubectl-from-literal', build: (k, t = 'a') => sh(`kubectl create secret generic s --from-literal=stripe=${k} -n ${t}`) },
  { id: 'mysql-p', build: (k, t = 'a') => sh(`mysql -u root -p${k} -h ${t}.example.com`) },
  { id: 'openssl-pass', build: (k, t = 'a') => sh(`openssl enc -aes-256-cbc -pass pass:${k} -in ${t}`) },
  { id: 'redis-a', build: (k, t = 'a') => sh(`redis-cli -a ${k} -h ${t}`) },
  { id: 'chain-and', build: (k, t = 'a') => sh(`cd /tmp && STRIPE_API_KEY=${k} ./pay.sh ${t}`) },
  { id: 'chain-semicolon', build: (k, t = 'a') => sh(`echo hi; STRIPE_API_KEY=${k} ./pay.sh ${t}`) },
  { id: 'chain-or', build: (k, t = 'a') => sh(`false || stripe charges list --api-key ${k} --limit ${t}`) },
  { id: 'chain-pipe', build: (k, t = 'a') => sh(`cat in.txt | stripe charges list --api-key ${k} --limit ${t}`) },
  { id: 'bash-c', build: (k, t = 'a') => sh(`bash -c 'STRIPE_API_KEY=${k} ./pay.sh ${t}'`) },
  { id: 'bash-c-nested-quote', build: (k, t = 'a') => sh(`bash -c "sh -c 'stripe charges list --api-key ${k} --limit ${t}'"`) },
  { id: 'ssh-host', build: (k, t = 'a') => sh(`ssh ${t}.example.com 'stripe charges list --api-key ${k}'`) },
  { id: 'eval', build: (k, t = 'a') => sh(`eval 'STRIPE_API_KEY=${k} ./pay.sh ${t}'`) },
  { id: 'subshell', build: (k, t = 'a') => sh(`(STRIPE_API_KEY=${k} ./pay.sh ${t})`) },
  { id: 'command-subst', build: (k, t = 'a') => sh(`echo "$(stripe charges list --api-key ${k} --limit ${t})"`) },
  { id: 'sudo', build: (k, t = 'a') => sh(`sudo -E STRIPE_API_KEY=${k} ./pay.sh ${t}`) },
  { id: 'powershell-tool', build: (k, t = 'a') => ({ tool_name: 'PowerShell', tool_input: { command: `$env:STRIPE_API_KEY="${k}"; ./pay.ps1 ${t}` } }) },
  { id: 'monitor-tool', build: (k, t = 'a') => ({ tool_name: 'Monitor', tool_input: { command: `STRIPE_API_KEY=${k} ./watch.sh ${t}`, timeout_ms: 1000 } }) },
  { id: 'mcp-credential-field', build: (k, t = 'a') => mcp({ api_key: k, memo: t }) },
  { id: 'mcp-credential-field-token', build: (k, t = 'a') => mcp({ token: k, memo: t }) },
  { id: 'mcp-free-text', build: (k, t = 'a') => mcp({ note: `use ${k} for this`, memo: t }) },
  { id: 'mcp-free-text-whole', build: (k, t = 'a') => mcp({ note: k, memo: t }) },
  { id: 'mcp-header-object', build: (k, t = 'a') => mcp({ headers: { Authorization: `Bearer ${k}` }, memo: t }) },
  { id: 'mcp-array', build: (k, t = 'a') => mcp({ args: ['--api-key', k, t] }) },
  { id: 'mcp-object-under-credential-name', build: (k, t = 'a') => mcp({ credentials: { user: 'u', key: k }, memo: t }) },
  { id: 'mcp-depth-over-6', build: (k, t = 'a') => mcp({ tree: deep(k, 8), memo: t }) },
  { id: 'edit-path-bare', build: (k, t = 'a') => edit(`/p/${t}/${k}`) },
  { id: 'edit-path-token-query', build: (k, t = 'a') => edit(`/p/${t}.txt?token=${k}`) },
  { id: 'edit-path-ext', build: (k, t = 'a') => edit(`/p/${k}.${t}`) },
  { id: 'edit-content', build: (k, t = 'a') => ({ tool_name: 'Edit', tool_input: { file_path: `/p/${t}.txt`, old_string: 'a', new_string: `key ${k}` } }) },
  { id: 'other-tool', build: (k, t = 'a') => ({ tool_name: 'WebFetch', tool_input: { url: `https://api.example.com/${t}`, prompt: `with ${k}` } }) },
];

/** Shapes that a backend, a shell or a client might read as the LIVE key but that are not the canonical lowercase test key. */
const ZW = '​';
const LOOKALIKES = [
  { id: 'SK_LIVE_ upper', make: (p) => `SK_LIVE_${p}`, expect: 'live' },
  { id: 'sk_Live_ mixed', make: (p) => `sk_Live_${p}`, expect: 'live' },
  { id: 'Sk_LiVe_ alternating', make: (p) => `Sk_LiVe_${p}`, expect: 'live' },
  { id: 'sk_live- dash tail', make: (p) => `sk_live-${p}`, expect: 'live' },
  { id: 'sk-live- dashes', make: (p) => `sk-live-${p}`, expect: 'live' },
  { id: 'rk_LIVE_', make: (p) => `rk_LIVE_${p}`, expect: 'live' },
  { id: 'pk_Live_', make: (p) => `pk_Live_${p}`, expect: 'live' },
  { id: 'zero-width space inside live', make: (p) => `sk_li${ZW}ve_${p}`, expect: 'live' },
  { id: 'zero-width joiner after prefix', make: (p) => `sk‍_live_${p}`, expect: 'live' },
  { id: 'soft hyphen inside', make: (p) => `sk_li­ve_${p}`, expect: 'live' },
  { id: 'BOM before', make: (p) => `﻿sk_live_${p}`, expect: 'live' },
  { id: 'bidi mark inside', make: (p) => `sk_‎live_${p}`, expect: 'live' },
  { id: 'tag character inside', make: (p) => `sk_l\u{e0069}ive_${p}`, expect: 'live' },
  { id: 'combining mark inside', make: (p) => `sk_líve_${p}`, expect: 'live' },
  { id: 'NFKC full-width', make: (p) => `ｓｋ＿ｌｉｖｅ＿${p}`, expect: 'live' },
  { id: 'NFKC long s', make: (p) => `ſk_live_${p}`, expect: 'live' },
  { id: 'NFKC kelvin sign', make: (p) => `sK_live_${p}`, expect: 'live' },
  { id: 'percent-encoded underscore', make: (p) => `sk%5Flive%5F${p}`, expect: 'live' },
  { id: 'percent-encoded letter', make: (p) => `sk_%6Cive_${p}`, expect: 'live' },
  { id: 'unknown prefix sk_prod_', make: (p) => `sk_prod_${p}`, expect: 'live' },
  { id: 'malformed sk_ + payload', make: (p) => `sk_${p}`, expect: 'live' },
  { id: 'unknown prefix pk_staging_', make: (p) => `pk_staging_${p}`, expect: 'live' },
  { id: 'test spelled upper SK_TEST_', make: (p) => `SK_TEST_${p}`, expect: 'live' },
  { id: 'test with dash sk-test-', make: (p) => `sk-test-${p}`, expect: 'live' },
  { id: 'test mixed sk_Test_', make: (p) => `sk_Test_${p}`, expect: 'live' },
  { id: 'test with zero-width', make: (p) => `sk_te${ZW}st_${p}`, expect: 'live' },
  { id: 'test full-width', make: (p) => `ｓｋ＿ｔｅｓｔ＿${p}`, expect: 'live' },
  { id: 'test prefix sk_testing_ (not canonical)', make: (p) => `sk_testing_${p}`, expect: 'live' },
  // Homoglyphs and digit look-alikes are not read as a key by Stripe or the backend: never `test`, no class needed.
  { id: 'Cyrillic s homoglyph live', make: (p) => `ѕk_live_${p}`, expect: 'not-test' },
  { id: 'digit one for l', make: (p) => `sk_1ive_${p}`, expect: 'not-test' },
  { id: 'Greek omicron in live', make: (p) => `sk_liveο${p}`, expect: 'not-test' },
];

module.exports = { POSITIONS, LOOKALIKES, live, test, payload, sh, mcp, edit, b64, pick };
