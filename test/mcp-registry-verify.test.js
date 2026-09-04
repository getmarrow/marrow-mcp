const test = require('node:test');
const assert = require('node:assert/strict');

const { endpoint, verifyRegistry } = require('../scripts/mcp-registry-verify.cjs');

const expectedName = 'io.github.getmarrow/marrow';
const expectedVersion = '3.9.80';

function fixtureFetch(scenario, calls) {
  return async (input) => {
    const url = String(input);
    calls.push(url);
    if (url.includes('?') || url.includes('/v0.1/servers?')) {
      return Response.json({
        servers: Array.from({ length: 30 }, (_, index) => ({
          server: { name: expectedName, version: `3.8.${index}` },
        })),
      });
    }
    if (scenario === 'http_failure') return new Response('unavailable', { status: 503 });
    if (scenario === 'transport_failure') throw new Error('private transport detail');
    const fixtures = {
      exact: { server: { name: expectedName, version: expectedVersion } },
      wrong_version: { server: { name: expectedName, version: '3.9.79' } },
      wrong_name: { server: { name: 'io.github.example/wrong', version: expectedVersion } },
      malformed: { servers: [] },
    };
    return Response.json(fixtures[scenario]);
  };
}

test('uses the official exact-version endpoint and cannot miss latest behind the oldest search page', async () => {
  const calls = [];
  const match = await verifyRegistry(fixtureFetch('exact', calls));
  assert.deepEqual(match, { name: expectedName, version: expectedVersion });
  assert.deepEqual(calls, [
    `https://registry.modelcontextprotocol.io/v0.1/servers/${encodeURIComponent(expectedName)}/versions/${expectedVersion}`,
  ]);
  assert.equal(String(endpoint).includes('?'), false);
});

test('fails closed on wrong exact-version identity', async (t) => {
  for (const scenario of ['wrong_version', 'wrong_name']) {
    await t.test(scenario, async () => {
      await assert.rejects(
        verifyRegistry(fixtureFetch(scenario, [])),
        (error) => error instanceof Error
          && error.message === 'MCP Registry identity mismatch'
          && !/3\.9\.79|example\/wrong/.test(error.message),
      );
    });
  }
});

test('fails closed on malformed, HTTP-error, and unavailable responses', async (t) => {
  const fixtures = [
    ['malformed', 'MCP Registry response is malformed'],
    ['http_failure', 'MCP Registry query failed with HTTP 503'],
    ['transport_failure', 'MCP Registry query is unavailable'],
  ];
  for (const [scenario, expected] of fixtures) {
    await t.test(scenario, async () => {
      await assert.rejects(
        verifyRegistry(fixtureFetch(scenario, [])),
        (error) => error instanceof Error
          && error.message === expected
          && !/private transport detail|unavailable<|<html/i.test(error.message),
      );
    });
  }
});
