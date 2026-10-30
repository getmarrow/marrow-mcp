'use strict';
// N1 (MCP 3.9.109): the pre-action hook dials the Marrow API with IPv4 tried first and happy eyeballs on, set once at hook start before any
// request. Transport only: the host, port, path and headers of its requests do not change.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { mkdtempSync, mkdirSync, readFileSync, existsSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const dns = require('node:dns');
const net = require('node:net');
const http = require('node:http');
const { dummySecret } = require('./support/dummy-secret.cjs');

const CLI = join(__dirname, '..', 'dist', 'cli.js');
const CAPTURE = join(__dirname, 'support', 'n1-capture.cjs');
const toolEvent = (session, command) => ({ session_id: session, tool_use_id: `t-${session}`, hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command } });

function runHook(entry, command) {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-n1-'));
  try {
    const home = join(directory, 'home');
    mkdirSync(home, { recursive: true, mode: 0o700 });
    const capture = join(directory, 'capture.ndjson');
    const result = spawnSync(process.execPath, [CLI, entry], {
      cwd: home,
      env: {
        PATH: process.env.PATH, HOME: home, MARROW_API_KEY: dummySecret(), MARROW_KEY: '', MARROW_AUTO_HOOK: 'true',
        MARROW_EVENT_SPOOL_PATH: join(home, 'spool.json'), NODE_OPTIONS: `--require ${CAPTURE}`, CAPTURE_FILE: capture,
      },
      input: JSON.stringify(toolEvent('s-n1', command)),
      encoding: 'utf8',
      timeout: 20_000,
    });
    const lines = existsSync(capture) ? readFileSync(capture, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line)) : [];
    return { result, start: lines.find((line) => line.phase === 'start'), requests: lines.filter((line) => line.phase === 'request') };
  } finally { rmSync(directory, { recursive: true, force: true }); }
}

const ENTRIES = ['claude-pre-action-hook', 'cursor-pre-action-hook', 'codex-pre-action-hook', 'gemini-pre-action-hook'];

for (const entry of ENTRIES) {
  test(`N1: ${entry} has IPv4-first and happy eyeballs in force before its first request`, () => {
    const { result, start, requests } = runHook(entry, 'npm publish');
    assert.equal(result.status, 0, result.stderr);
    // The process started with the opposite settings, so only the hook can have set them.
    assert.deepEqual([start.order, start.autoSelectFamily], ['verbatim', false]);
    assert.ok(requests.length >= 1, 'a protected action asks Marrow, so the hook makes a request');
    for (const request of requests) {
      assert.equal(request.order, 'ipv4first', request.url);
      assert.equal(request.autoSelectFamily, true, request.url);
    }
  });
}

test('N1: host, port, path and headers of the hook requests are the ones it always sent', () => {
  const { requests } = runHook('claude-pre-action-hook', 'npm publish');
  assert.ok(requests.length >= 1);
  const gate = requests[0];
  const url = new URL(gate.url);
  assert.equal(url.protocol, 'https:');
  assert.equal(url.hostname, 'api.getmarrow.ai');
  assert.equal(url.port, '');
  assert.match(url.pathname, /^\/v1\//);
  assert.equal(gate.method, 'POST');
  assert.ok(gate.headers.includes('authorization') && gate.headers.includes('content-type'), JSON.stringify(gate.headers));
  // Every request goes to the one Marrow host; nothing else was dialled.
  for (const request of requests) assert.equal(new URL(request.url).host, 'api.getmarrow.ai');
});

test('N1: a keyless hook (no request) leaves the process settings alone apart from setting them once at start', () => {
  const directory = mkdtempSync(join(tmpdir(), 'marrow-n1-'));
  try {
    const home = join(directory, 'home');
    mkdirSync(home, { recursive: true, mode: 0o700 });
    const capture = join(directory, 'capture.ndjson');
    const result = spawnSync(process.execPath, [CLI, 'claude-pre-action-hook'], {
      cwd: home,
      env: { PATH: process.env.PATH, HOME: home, MARROW_API_KEY: '', MARROW_KEY: '', MARROW_AUTO_HOOK: 'true', NODE_OPTIONS: `--require ${CAPTURE}`, CAPTURE_FILE: capture },
      input: JSON.stringify(toolEvent('s-n1-keyless', 'ls')),
      encoding: 'utf8',
      timeout: 20_000,
    });
    assert.equal(result.status, 0, result.stderr);
    const requests = readFileSync(capture, 'utf8').split('\n').filter(Boolean).map((line) => JSON.parse(line)).filter((line) => line.phase === 'request');
    assert.deepEqual(requests, [], 'a keyless hook dials nothing');
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

// ---- a resolver that lists an unreachable IPv6 address first ---------------------------------------------------------------------------

// What Node's own lookup does with the default result order, for a name whose resolver lists an unreachable IPv6 address first
// (100::/64 is the discard-only prefix) and the IPv4 loopback second.
function dualStackLookup(_hostname, options, callback) {
  const opts = typeof options === 'function' ? {} : options || {};
  const cb = typeof options === 'function' ? options : callback;
  const listed = [{ address: '100::1', family: 6 }, { address: '127.0.0.1', family: 4 }];
  const ordered = dns.getDefaultResultOrder() === 'ipv4first' ? [...listed].sort((a, b) => a.family - b.family) : listed;
  process.nextTick(() => (opts.all ? cb(null, ordered) : cb(null, ordered[0].address, ordered[0].family)));
}

function reach(port, budgetMs) {
  return new Promise((resolve) => {
    const started = process.hrtime.bigint();
    const done = (reached) => resolve({ reached, ms: Number(process.hrtime.bigint() - started) / 1e6 });
    const request = http.get({ host: 'n1-dual.localhost', port, path: '/', lookup: dualStackLookup, agent: false }, (response) => { response.resume(); done(response.statusCode === 200); });
    request.on('error', () => done(false));
    setTimeout(() => { request.destroy(); done(false); }, budgetMs).unref();
  });
}

test('N1: with the settings applied, an unreachable IPv6 address listed first still reaches the IPv4 server on 127.0.0.1 inside 1 s', async () => {
  const { preferIpv4FirstWithHappyEyeballs } = require('../dist/ipv4-first.js');
  const server = http.createServer((_request, response) => response.end('ok'));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const before = [dns.getDefaultResultOrder(), net.getDefaultAutoSelectFamily()];
  try {
    // Negative control: the opposite settings do not get there (the first address is the one that is dialled).
    dns.setDefaultResultOrder('verbatim');
    net.setDefaultAutoSelectFamily(false);
    const without = await reach(server.address().port, 1000);
    assert.equal(without.reached, false, 'without the settings the unreachable address blocks the connection');
    preferIpv4FirstWithHappyEyeballs();
    assert.equal(dns.getDefaultResultOrder(), 'ipv4first');
    assert.equal(net.getDefaultAutoSelectFamily(), true);
    const withN1 = await reach(server.address().port, 1000);
    assert.equal(withN1.reached, true);
    assert.ok(withN1.ms < 1000, `reached in ${withN1.ms} ms`);
  } finally {
    dns.setDefaultResultOrder(before[0]);
    net.setDefaultAutoSelectFamily(before[1]);
    await new Promise((resolve) => server.close(resolve));
  }
});

test('N1: the helper survives a Node without either setting (older Node)', () => {
  const script = [
    "const dns = require('node:dns'); const net = require('node:net');",
    'delete dns.setDefaultResultOrder; delete net.setDefaultAutoSelectFamily;',
    `const { preferIpv4FirstWithHappyEyeballs } = require(${JSON.stringify(join(__dirname, '..', 'dist', 'ipv4-first.js'))});`,
    'preferIpv4FirstWithHappyEyeballs(); preferIpv4FirstWithHappyEyeballs(); process.stdout.write("ok");',
  ].join('\n');
  const result = spawnSync(process.execPath, ['-e', script], { encoding: 'utf8', timeout: 20_000, env: { PATH: process.env.PATH } });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, 'ok');
});
