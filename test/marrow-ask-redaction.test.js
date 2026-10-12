const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const test = require('node:test');

const { marrowAsk } = require('../dist/index.js');

/** Runtime dummy values only: never a real credential. */
const dummy = (bytes = 18) => randomBytes(bytes).toString('hex');

async function sentBody(query) {
  const original = globalThis.fetch;
  let body = null;
  globalThis.fetch = async (_url, init) => {
    body = String(init.body);
    return new Response(JSON.stringify({ data: { answer: 'ok' } }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  try {
    await marrowAsk(`mrw_${dummy(12)}`, 'https://api.example.test', { query }, 'session-1', 'agent-1');
  } finally {
    globalThis.fetch = original;
  }
  return JSON.parse(body);
}

function slices(secret) {
  const out = [];
  for (let i = 0; i + 8 <= secret.length; i += 1) out.push(secret.slice(i, i + 8));
  return out;
}

test('marrow_ask: the question leaves the process redacted in every shape the redactor covers; text after a redacted span survives', async () => {
  const shapes = {
    'URL query': (s) => [`what failed at https://hooks.example.test/cb?token=${s}&next=deploy-staging-7 yesterday`, s],
    'URL signature': (s) => [`replay https://cdn.example.test/file?sig=${s}&region=eu-west-9 now`, s],
    'Authorization header': (s) => [`curl -H "Authorization: Bearer ${s}" returned 403 for project-alpha`, s],
    'env assignment': (s) => [`ran with DEPLOY_API_KEY=${s} then wrangler deploy --env staging-4`, s],
    'JSON body (key-shaped value)': (s) => [`payload {"note":"x","value":"ghp_${s}"} for repo-beta`, `ghp_${s}`],
    'Marrow key': (s) => [`my key mrw_${s} stopped working on agent-gamma`, `mrw_${s}`],
    'flag with =': (s) => [`tool --api-key=${s} --region us-east-3 failed`, s],
    'flag with space': (s) => [`cli --token ${s} --env prod-delta failed`, s],
  };
  for (const [name, shape] of Object.entries(shapes)) {
    const [query, secret] = shape(dummy());
    const sent = await sentBody(query);
    const text = JSON.stringify(sent);
    assert.equal(typeof sent.action, 'string', name);
    for (const slice of slices(secret)) assert.equal(text.includes(slice), false, `${name}: no 8-character slice of the secret is sent`);
    // What follows the redacted span is kept, so the question still means what it said.
    const tail = query.split(secret).pop().trim().split(/\s+/).pop();
    assert.ok(sent.action.includes(tail), `${name}: text after the redacted span survives`);
  }
});

test('marrow_ask: questions that differ only after a redacted span stay different; differing only in the secret may match', async () => {
  const secret = dummy();
  const a = await sentBody(`deploy with DEPLOY_TOKEN=${secret} to staging`);
  const b = await sentBody(`deploy with DEPLOY_TOKEN=${secret} to production`);
  assert.notEqual(a.action, b.action);
  const c = await sentBody(`deploy with DEPLOY_TOKEN=${dummy()} to staging`);
  assert.equal(a.action, c.action);
  const plain = await sentBody('how did the last staging deploy go?');
  assert.equal(plain.action, 'how did the last staging deploy go?', 'a question without secrets is sent unchanged');
});
