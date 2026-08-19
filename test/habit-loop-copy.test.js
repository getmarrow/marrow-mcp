const assert = require('node:assert/strict');
const test = require('node:test');

const { extractModelUsageFromUnknown, formatHabitLoopCopy } = require('../dist/habit-loop-copy.js');

test('pretty-prints nested habit-loop copy for MCP tool payloads', () => {
  const copy = formatHabitLoopCopy({
    data: {
      habit_loop: {
        contract: 'marrow.habit-loop.v1',
        headline: 'Marrow is on and quiet.',
        exact_next_action: 'Use runtime only before deploy.',
        session_savings: { evidence_backed: false, message: 'No reuse yet. Empty savings are honest.' },
      },
    },
  });
  assert.ok(copy);
  assert.match(copy.text, /Use runtime only before deploy/);
  assert.match(copy.savings, /Empty savings are honest/);
});

test('does not invent savings when evidence is still empty', () => {
  const copy = formatHabitLoopCopy({
    habit_loop: {
      contract: 'marrow.habit-loop.v1',
      session_savings: { tokens: 0, evidence_backed: false },
    },
  });
  assert.match(copy.savings, /Empty savings are honest/);
  assert.doesNotMatch(copy.text, /[1-9]\d* tokens saved/);
});

test('extracts observed usage and ignores empty objects', () => {
  assert.equal(extractModelUsageFromUnknown({ ok: true }), null);
  const usage = extractModelUsageFromUnknown({
    provider: 'openai',
    model: 'gpt-test',
    usage: { prompt_tokens: 11, completion_tokens: 7, total_tokens: 18 },
  });
  assert.deepEqual(usage, {
    provider: 'openai',
    model: 'gpt-test',
    input_tokens: 11,
    output_tokens: 7,
    cached_tokens: undefined,
    total_tokens: 18,
  });
});
