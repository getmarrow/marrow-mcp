const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const test = require('node:test');

const { normalizedHookAction } = require('../dist/normalized-action.js');

const action = (command) => normalizedHookAction({ tool_name: 'Bash', tool_input: { command } }, { deadlineAt: Number.POSITIVE_INFINITY });

test('normalized-action header states exactly what leaves the machine: only an exact deploy command is sent as text', () => {
  const header = readFileSync(join(__dirname, '..', 'src', 'normalized-action.ts'), 'utf8').split('*/')[0];
  assert.doesNotMatch(header, /The command text and the\s+\* tool input themselves are never sent/);
  assert.match(header, /The tool input is never sent/);
  assert.match(header, /`tool_input\.command`/);
  assert.match(header, /sst deploy --stage production/);
  // The behaviour the comment describes (unchanged; the normalized action is an approval key).
  assert.equal(action('sst deploy --stage production').tool_input.command, 'sst deploy --stage production');
  for (const command of ['echo hello', 'sst deploy --stage production && echo x', 'ls -la', 'API_TOKEN=abcdefghijkl sst deploy --stage production']) {
    assert.equal(action(command).tool_input.command, undefined, command);
    assert.match(action(command).tool_input.command_sha256, /^[0-9a-f]{64}$/);
  }
});
