const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const readme = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
const cliSource = fs.readFileSync(path.join(root, 'src/cli.ts'), 'utf8');
const canonical = 'Marrow is the runtime control and proof layer for teams running AI agents.';

test('npm entry point matches the product positioning contract', () => {
  assert.match(pkg.description, /runtime control/i);
  assert.match(pkg.description, /proof/i);
  assert.ok(readme.includes(canonical));
  assert.ok(readme.includes(`## What's New in v${pkg.version}`));
  assert.equal((readme.match(/^## What's New in v/gm) || []).length, 1);
  assert.ok(readme.indexOf('## Governed Action Flow') < readme.indexOf('## Context and Workflow Examples'));
  const runtimeIndex = readme.indexOf('Call `marrow_agent_runtime`');
  const thinkIndex = readme.indexOf('Call `marrow_think`');
  const commitIndex = readme.indexOf('Call `marrow_commit`');
  assert.ok(runtimeIndex >= 0 && runtimeIndex < thinkIndex && thinkIndex < commitIndex);
  assert.match(readme, /"outcome": "Production deploy succeeded and smoke checks passed\."/);
  assert.doesNotMatch(readme, /"profile": "production"/);
  assert.ok(cliSource.includes(`serverInfo: { name: 'marrow', version: '${pkg.version}' }`));
  assert.equal(pkg.dependencies['@getmarrow/sdk'], '^3.7.43');

  for (const [, json] of readme.matchAll(/```json\n([\s\S]*?)```/g)) {
    assert.doesNotThrow(() => JSON.parse(json));
  }
});
