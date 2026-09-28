const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const { join } = require('node:path');
const { tmpdir } = require('node:os');
const { observeCodexNativeUsage: observe, captureCodexNativeUsage: capture, CODEX_USAGE_LIMITS } = require('../dist/codex-native-usage');
const thread = '11111111-1111-4111-8111-111111111111';
const turn = '22222222-2222-4222-8222-222222222222';
const model = 'gpt-6-astra';
const counts = (input, output, cached = 0, reasoning = 0) => ({ input_tokens: input, cached_input_tokens: cached, output_tokens: output, reasoning_output_tokens: reasoning, total_tokens: input + output, cache_write_input_tokens: 0 });
const token = (total, last) => ({ type: 'event_msg', timestamp: '2026-09-28T10:00:00Z', payload: { type: 'token_count', info: { total_token_usage: total, last_token_usage: last, model_context_window: 1000000 } } });
const context = { type: 'turn_context', payload: { turn_id: turn, model } };
function fixture(extra = {}) {
  const root = fs.mkdtempSync(join(tmpdir(), 'native-usage-'));
  const file = join(root, 'fixture.jsonl');
  const header = { type: 'session_meta', payload: { id: thread, cli_version: '0.157.1', model_provider: 'openai', ...extra } };
  const rows = [header, context, token(counts(100, 10, 20, 2), counts(100, 10, 20, 2)), token(counts(150, 18, 30, 5), counts(50, 8, 10, 3))];
  const write = () => fs.writeFileSync(file, rows.map(r => JSON.stringify(r)).join('\n') + '\n', { mode: 0o600 });
  write();
  return { root, file, rows, write, input: { session_id: thread, turn_id: turn, model, transcript_path: file }, close: () => fs.rmSync(root, { recursive: true, force: true }) };
}

test('native transcript proves only latest call delta; cache and reasoning stay subsets; privacy and money unknown', () => {
  const f = fixture();
  try {
    f.rows.splice(2, 0, { type: 'response_item', payload: { text: 'PRIVATE_BODY_SENTINEL' } }); f.write();
    const out = observe(f.input, undefined, { sessionsRoot: f.root });
    assert.equal(out.reason, 'observed_delta');
    assert.equal(out.usage.input_tokens, 50); assert.equal(out.usage.output_tokens, 8);
    assert.equal(out.usage.cached_tokens, 10); assert.equal(out.usage.total_tokens, 58);
    assert.equal(out.usage.usage_kind, 'delta'); assert.equal(out.usage.token_semantics, 'input_includes_cache');
    for (const field of ['billing_host', 'pricing_dimensions', 'coverage_complete', 'overhead_complete', 'baseline_usage_id']) assert.equal(out.usage[field], undefined);
    assert.equal(JSON.stringify(out).includes('PRIVATE_BODY_SENTINEL'), false);
    f.rows.push(f.rows.at(-1)); f.write();
    assert.equal(observe(f.input, undefined, { sessionsRoot: f.root }).usage.usage_event_id, out.usage.usage_event_id);
  } finally { f.close(); }
});

test('reset, first observation, missing model, unsupported version and child identity abstain', () => {
  for (const kind of ['reset', 'first', 'model', 'version', 'child', 'hook-child']) {
    const f = fixture();
    try {
      if (kind === 'reset') f.rows.push(token(counts(3, 1), counts(3, 1)));
      if (kind === 'first') f.rows.pop();
      if (kind === 'model') delete f.input.model;
      if (kind === 'version') f.rows[0].payload.cli_version = 'unknown';
      if (kind === 'child') f.rows[0].payload.parent_thread_id = thread;
      if (kind === 'hook-child') f.input.subagent_transcript_path = f.file;
      f.write(); assert.equal(observe(f.input, undefined, { sessionsRoot: f.root }).usage, undefined, kind);
    } finally { f.close(); }
  }
});

test('only current matching turn is eligible; no attribution of prior-model history', () => {
  const f = fixture();
  try {
    f.rows.splice(1, 0, { type: 'turn_context', payload: { turn_id: '33333333-3333-4333-8333-333333333333', model: 'gpt-6-sol' } }, token(counts(5, 1), counts(5, 1)));
    f.write(); assert.equal(observe(f.input, undefined, { sessionsRoot: f.root }).usage.input_tokens, 50);
    f.rows.push({ type: 'turn_context', payload: { turn_id: turn, model: 'gpt-6-sol' } }); f.write();
    assert.equal(observe(f.input, undefined, { sessionsRoot: f.root }).usage, undefined);
  } finally { f.close(); }
});

test('path escape, symlink, oversized file and line are rejected', () => {
  const f = fixture();
  try {
    assert.equal(observe(f.input, undefined, { sessionsRoot: join(f.root, 'other') }).reason, 'transcript_path_rejected');
    const link = join(f.root, 'link.jsonl'); fs.symlinkSync(f.file, link);
    assert.equal(observe({ ...f.input, transcript_path: link }, undefined, { sessionsRoot: f.root }).reason, 'transcript_path_rejected');
    fs.truncateSync(f.file, CODEX_USAGE_LIMITS.fileBytes + 1);
    assert.equal(observe(f.input, undefined, { sessionsRoot: f.root }).reason, 'transcript_size_limit');
    f.write(); fs.appendFileSync(f.file, 'x'.repeat(CODEX_USAGE_LIMITS.lineBytes + 1) + '\n');
    assert.equal(observe(f.input, undefined, { sessionsRoot: f.root }).reason, 'transcript_line_limit');
  } finally { f.close(); }
});

test('rejects noncanonical symlink traversal before opening an outside transcript', () => {
  const inside = fixture(), outside = fixture();
  try {
    const child = join(outside.root, 'child');
    fs.mkdirSync(child, { mode: 0o700 });
    fs.symlinkSync(child, join(inside.root, 'link'));
    // Do not join/normalize this spelling: the OS follows link before resolving .. .
    const traversal = `${inside.root}/link/../fixture.jsonl`;
    assert.equal(fs.readFileSync(traversal, 'utf8'), fs.readFileSync(outside.file, 'utf8'));
    const result = observe({ ...inside.input, transcript_path: traversal }, undefined, { sessionsRoot: inside.root });
    assert.equal(result.reason, 'transcript_path_rejected');
    assert.equal(result.usage, undefined);
    assert.equal(observe(inside.input, undefined, { sessionsRoot: inside.root }).reason, 'observed_delta');
  } finally { inside.close(); outside.close(); }
});

test('documented event needs bound model/turn and checkpoint delta; repeat/reset do not become usage', () => {
  const camel = v => Object.fromEntries(Object.entries(v).map(([k, n]) => [k.replace(/_([a-z])/g, (_, c) => c.toUpperCase()), n]));
  const event = { method: 'thread/tokenUsage/updated', session_id: thread, turn_id: turn, model, params: { threadId: thread, turnId: turn, tokenUsage: { total: camel(counts(100, 10)), last: camel(counts(100, 10)), modelContextWindow: 1000000 } } };
  const first = observe(event); assert.equal(first.usage, undefined);
  event.params.tokenUsage = { total: camel(counts(150, 18)), last: camel(counts(50, 8)) };
  const next = observe(event, first.checkpoint); assert.equal(next.usage.total_tokens, 58);
  assert.equal(observe(event, next.checkpoint).usage, undefined);
  event.params.tokenUsage = { total: camel(counts(3, 1)), last: camel(counts(3, 1)) };
  assert.equal(observe(event, next.checkpoint).usage, undefined);
  delete event.model; assert.equal(observe(event).reason, 'model_missing');
});

test('repeated native captures submit one normalized compact request with persistent checkpoint', async () => {
  const f = fixture(), originalFetch = global.fetch, oldHome = process.env.HOME, oldCodex = process.env.CODEX_HOME;
  const calls = [];
  try {
    process.env.HOME = f.root; process.env.CODEX_HOME = f.root;
    fs.mkdirSync(join(f.root, 'sessions'), { mode: 0o700 }); const moved = join(f.root, 'sessions', 'fixture.jsonl'); fs.renameSync(f.file, moved); f.input.transcript_path = moved;
    global.fetch = async (url, init) => {
      assert.equal(String(url), 'https://fixture.example.test/v1/agent/model-usage');
      calls.push(JSON.parse(init.body));
      return new Response(JSON.stringify({ data: { recorded: true } }), { status: 200 });
    };
    await capture(f.input, 'fixture-key', 'https://fixture.example.test', 'fixture-agent');
    await capture(f.input, 'fixture-key', 'https://fixture.example.test', 'fixture-agent');
    assert.equal(calls.length, 1); assert.equal(calls[0].input_tokens, 50); assert.equal(calls[0].session_id, thread);
    assert.equal(calls[0].coverage_complete, undefined);
  } finally {
    global.fetch = originalFetch;
    if (oldHome === undefined) delete process.env.HOME; else process.env.HOME = oldHome;
    if (oldCodex === undefined) delete process.env.CODEX_HOME; else process.env.CODEX_HOME = oldCodex;
    f.close();
  }
});
