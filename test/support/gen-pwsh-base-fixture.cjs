'use strict';

// Writes test/fixtures/pwsh-base-868a9c18.json: what the 3.9.103 build (master 868a9c18) answers for every
// PowerShell event of test/support/pwsh-table.cjs, from its classifyTool and its keyless evaluateSeatbelt.
// Run once against a built checkout of that commit (it needs that build's dist, so it is not a test):
//   node test/support/gen-pwsh-base-fixture.cjs <built base checkout> > test/fixtures/pwsh-base-868a9c18.json
// The fixture holds booleans and labels only (no command output, no value of any credential).
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { tableEvents, eventKey } = require('./pwsh-table.cjs');
const { makeEnv } = require('./seatbelt-fakes.cjs');

const root = path.resolve(process.argv[2] || '');
const head = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
if (head !== '868a9c18530a75fcee5052441d0d3d2383511df4') throw new Error('not the 3.9.103 base commit');
const { classifyTool } = require(path.join(root, 'dist', 'hook-pre-action.js'));
const { evaluateSeatbelt } = require(path.join(root, 'dist', 'seatbelt', 'mapper.js'));

const rows = {};
for (const { event } of tableEvents()) {
  const key = eventKey(event);
  if (rows[key]) continue;
  const c = classifyTool(event);
  const s = evaluateSeatbelt(event, makeEnv());
  rows[key] = {
    readOnly: c.readOnly, protected: c.protected, risk: c.risk, type: c.type, surfaces: c.surfaces, target: c.target,
    seatbelt: { decision: s.decision, category: s.category || null },
  };
}
// One event per line, so a review reads it.
const lines = Object.keys(rows).map((key) => `${JSON.stringify(key)}:${JSON.stringify(rows[key])}`);
process.stdout.write(`{"base":"${head}","events":${lines.length},"rows":{\n${lines.join(',\n')}\n}}\n`);
