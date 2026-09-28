const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { mkdtempSync, rmSync, writeFileSync } = require('node:fs');
const { createServer } = require('node:http');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');
const test = require('node:test');

async function runCli(input) {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-session-stdin-'));
  const calls = [];
  const server = createServer((request, response) => {
    let body = '';
    request.on('data', chunk => { body += chunk; });
    request.on('end', () => {
      calls.push({ path: request.url, body: JSON.parse(body || '{}') });
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({ data: { recorded: true, committed: 1, accepted: true } }));
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const transport = join(directory, 'local-transport.cjs');
    writeFileSync(transport, `const nativeFetch = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const url = new URL(String(input));
  if (url.origin !== 'https://fixture.example.test') throw new Error('Unexpected fixture egress');
  return nativeFetch('http://127.0.0.1:${server.address().port}' + url.pathname, init);
};\n`);
    const child = spawn(process.execPath, ['--require', transport, resolve(__dirname, '../dist/cli.js'), 'codex-session-hook'], {
      cwd: directory,
      env: { PATH: process.env.PATH, HOME: directory, USERPROFILE: directory,
        MARROW_API_KEY: 'fixture-session-stdin-key', MARROW_AGENT_ID: 'fixture-session-agent',
        MARROW_FLEET_AGENT_ID: 'fixture-session-agent', MARROW_CLIENT: 'codex',
        MARROW_BASE_URL: 'https://fixture.example.test',
        MARROW_EVENT_SPOOL_PATH: join(directory, 'spool.json'),
        MARROW_MODEL_USAGE_ENDPOINT: 'https://api.openai.com/v1/responses',
        MARROW_PASSIVE_TOKEN_USAGE: 'true' },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', data => { stdout += data; });
    child.stderr.on('data', data => { stderr += data; });
    const completion = new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (code, signal) => resolve({ code, signal }));
    });
    const timeout = setTimeout(() => child.kill('SIGKILL'), 5000);
    child.stdin.end(typeof input === 'string' ? input : JSON.stringify(input));
    const result = await completion.finally(() => clearTimeout(timeout));
    assert.equal(result.code, 0, `CLI failed: ${stderr}`);
    assert.equal(result.signal, null);
    return { calls, stdout, stderr };
  } finally {
    await new Promise(resolve => server.close(resolve));
    rmSync(directory, { recursive: true, force: true });
  }
}

test('real Codex session CLI captures supplied stdin usage once and keeps cumulative/privacy semantics', async () => {
  const sentinel = 'PRIVATE_PROMPT_SENTINEL';
  const result = await runCli({ session_id: 'fixture-session', hook_event_name: 'SessionEnd',
    id: 'resp_stdin_fixture', model: 'gpt-4.1-mini', input: sentinel,
    usage: { input_tokens: 100, output_tokens: 8, total_tokens: 108, input_tokens_details: { cached_tokens: 20 } } });
  const usage = result.calls.filter(call => call.path === '/v1/agent/model-usage');
  assert.equal(usage.length, 1);
  assert.equal(usage[0].body.session_id, 'fixture-session');
  assert.equal(usage[0].body.agent_id, 'fixture-session-agent');
  assert.equal(usage[0].body.input_tokens, 100);
  assert.equal(usage[0].body.output_tokens, 8);
  assert.equal(usage[0].body.cached_tokens, 20);
  assert.equal(usage[0].body.total_tokens, 108);
  assert.equal(usage[0].body.usage_event_id, 'openai:resp_stdin_fixture');
  assert.equal(usage[0].body.usage_kind, 'cumulative');
  assert.equal(usage[0].body.source, 'mcp_session_end');
  assert.equal(usage[0].body.coverage_complete, undefined);
  assert.equal(usage[0].body.overhead_complete, undefined);
  assert.equal(usage[0].body.baseline_usage_id, undefined);
  assert.equal(JSON.stringify(result).includes(sentinel), false);
  assert.equal(result.calls.filter(call => call.path === '/v1/agent/session/end').length, 1);
});

test('real session CLI does not invent usage for absent counts or malformed stdin', async () => {
  for (const input of [{ session_id: 'fixture-empty', hook_event_name: 'SessionEnd' }, '{invalid-json']) {
    const result = await runCli(input);
    assert.equal(result.calls.filter(call => call.path === '/v1/agent/model-usage').length, 0);
    assert.equal(result.calls.filter(call => call.path === '/v1/agent/session/end').length, 1);
  }
});
