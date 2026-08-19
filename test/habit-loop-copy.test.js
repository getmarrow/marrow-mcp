const assert = require('node:assert/strict');
const test = require('node:test');

const { extractModelUsageFromUnknown, formatHabitLoopCopy } = require('../dist/habit-loop-copy.js');
const { buildCombinedContextBlock } = require('../dist/hook-context.js');

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

test('context block prints first-hour copy without inventing savings', () => {
  const text = buildCombinedContextBlock({
    warnings: [],
    loopWarnings: [],
    similarCount: 0,
    patternsCount: 0,
    templatesAvailable: 0,
    primaryInsight: null,
    collectiveInsight: null,
    hasSignal: false,
  }, null, null, {
    habit_loop: {
      interrupt: true,
      headline: 'Marrow is on. The first win is one real action plus a commit.',
      exact_next_action: 'Tell the owner Marrow is on. Empty savings are healthy. Run the next deploy, merge, or publish through Marrow, then POST /v1/agent/commit.',
      session_savings: { evidence_backed: false, message: 'No reuse yet. Empty savings are honest.' },
    },
  });
  assert.match(text, /first win is one real action/);
  assert.match(text, /Empty savings are healthy/);
  assert.doesNotMatch(text, /[1-9]\d* tokens saved/);
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
