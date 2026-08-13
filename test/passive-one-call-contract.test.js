const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const test = require('node:test');

test('prompt hook keeps one governance call and defers lifecycle delivery', () => {
  const source = readFileSync(resolve(__dirname, '../src/hook-context.ts'), 'utf8');
  assert.doesNotMatch(source.split('export async function runContextHookCommand')[1], /marrowThink\(/);
  assert.match(source, /passiveBriefInput[\s\S]*marrowAgentRuntime[\s\S]*:\s*await withTimeout\([\s\S]*marrowAgentContext/);
  assert.ok((source.match(/deferDelivery:\s*true/g) || []).length >= 2);
  assert.match(source, /MARROW_API_TIMEOUT_MS\s*=\s*400/);
});
