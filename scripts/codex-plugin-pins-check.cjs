#!/usr/bin/env node
'use strict';
// Recomputes the official Codex plugin pins from a getmarrow/plugins checkout and compares them with
// the pins this package ships (dist/codex-plugin-pins.js). Run it in CI on both sides:
//   node scripts/codex-plugin-pins-check.cjs <plugins checkout>
// Exit 0: every Codex plugin in the checkout has pins here for its manifest version and they match.
// Exit 1: a mismatch or a missing release (the plugin would fail closed for users: add its pins to
// src/codex-plugin-pins.ts and publish @getmarrow/mcp before releasing the plugin).
const { createHash } = require('node:crypto');
const { readFileSync } = require('node:fs');
const { join, resolve } = require('node:path');
const { OFFICIAL_CODEX_PLUGIN_PINS, OFFICIAL_CODEX_PLUGIN_DIRS } = require('../dist/codex-plugin-pins.js');

const checkout = process.argv[2];
if (!checkout) {
  process.stderr.write('usage: codex-plugin-pins-check.cjs <plugins checkout>\n');
  process.exit(2);
}
let failed = 0;
for (const [name, rel] of Object.entries(OFFICIAL_CODEX_PLUGIN_DIRS)) {
  const dir = resolve(checkout, rel);
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(join(dir, '.codex-plugin', 'plugin.json'), 'utf8'));
  } catch {
    process.stdout.write(`FAIL ${name}: no readable .codex-plugin/plugin.json in ${rel}\n`);
    failed += 1;
    continue;
  }
  const key = `${manifest.name}@${manifest.version}`;
  const pins = OFFICIAL_CODEX_PLUGIN_PINS[key];
  if (manifest.name !== name || !pins) {
    process.stdout.write(`FAIL ${key}: no pins in @getmarrow/mcp for this release (add them to src/codex-plugin-pins.ts first)\n`);
    failed += 1;
    continue;
  }
  for (const [file, digest] of Object.entries(pins)) {
    let actual = 'missing';
    try { actual = createHash('sha256').update(readFileSync(join(dir, file))).digest('hex'); } catch { /* missing */ }
    const ok = actual === digest;
    if (!ok) failed += 1;
    process.stdout.write(`${ok ? 'ok  ' : 'FAIL'} ${key} ${file}${ok ? '' : ` expected ${digest} got ${actual}`}\n`);
  }
}
process.exit(failed ? 1 : 0);
