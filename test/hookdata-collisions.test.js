'use strict';

// Collision rows for the hook data-words change (ACCEPTANCE bld-hookdata K1-K3, K5). Commands that differ only in data now share
// a type and surfaces; the hold binding (classified action text + target + surfaces + type + normalized action hash) must still
// differ, because the normalized action hashes the whole command. Dummy secrets are generated at run time and never printed.
const assert = require('node:assert/strict');
const { createHash, randomBytes } = require('node:crypto');
const test = require('node:test');

const { classifyTool } = require('../dist/hook-pre-action.js');
const { toolDataWordsText } = require('../dist/hook-tool-policy.js');
const { normalizedHookAction } = require('../dist/normalized-action.js');
const { dummySecret } = require('./support/dummy-secret.cjs');
const BASE = require('./fixtures/hookdata/base-classification.json');
const { rows } = require('./support/hookdata-rows.cjs');

const NL = '\n';
const salt = randomBytes(32);
const bash = (command, extra = {}) => ({ tool_name: 'Bash', tool_input: { command, ...extra } });
function binding(event) {
  const c = classifyTool(event);
  const normalized = normalizedHookAction(event, { salt });
  const key = createHash('sha256').update(JSON.stringify([c.action, c.target, c.surfaces, c.type, normalized])).digest('hex');
  return { key, c, normalized };
}

// Each template turns one data value into a command whose data the tip leaves out of the classification text.
const TEMPLATES = [
  (x) => `printf '%s\\n' '${x}' > test/fixtures/x.txt`,
  (x) => `echo '${x}' >> reports/run-log.md`,
  (x) => `cat > notes.txt <<'EOF'${NL}${x}${NL}EOF`,
  (x) => `python3 -I - <<'EOF'${NL}from pathlib import Path${NL}Path('n.md').write_text('${x}')${NL}EOF`,
  (x) => `python3 -c 'print("${x}")'`,
  (x) => `node -e 'console.log("${x}")'`,
  (x) => `python3 harness.py --text "${x}"`,
  (x) => `grep -rn '${x}' src/ > hits.txt`,
  (x) => `cat <<< '${x}' > out.txt`,
  (x) => `timeout 5 printf '${x}' > out.txt`,
];
const VALUES = ['deploy to production', 'ship backend release', 'publish the package', 'production deploy fixture', 'release notes v1',
  'deploy staging', 'prod rollout', 'migrate data', 'release candidate', 'deploy'];

test('K1: 200 pairs that differ only in data share type and surfaces but never a binding', () => {
  const pairs = [];
  for (const template of TEMPLATES) {
    for (let i = 0; i < VALUES.length; i += 1) {
      const a = VALUES[i];
      const b = VALUES[(i + 1) % VALUES.length];
      pairs.push([template(a), template(b)]);
      pairs.push([template(a), template(`${a} `)]);
    }
  }
  assert.equal(pairs.length, 200);
  // Flag order, repeated flags and text after a redacted span (each already its own binding on BASE) stay apart too.
  pairs.push([`grep -n -r 'deploy' src > h`, `grep -r -n 'deploy' src > h`], [`grep -n 'x' f > h`, `grep -n -n 'x' f > h`]);
  const token = dummySecret();
  pairs.push([`printf 'key=${token} deploy one' > f`, `printf 'key=${token} deploy two' > f`]);
  let collisions = 0;
  let shared = 0;
  for (const [first, second] of pairs) {
    const x = binding(bash(first));
    const y = binding(bash(second));
    if (x.c.type === y.c.type && JSON.stringify(x.c.surfaces) === JSON.stringify(y.c.surfaces)) shared += 1;
    if (x.key === y.key) collisions += 1;
  }
  assert.equal(collisions, 0, 'KEY_COLLISIONS');
  // The cut shapes (python3 -c, node -e) and a flagged L10 run keep BASE, so their pairs no longer share type and surfaces.
  assert.ok(shared >= 150, `pairs sharing type and surfaces: ${shared}`);
});

test('K2: commands that differ only in a dummy secret may share a key; no secret byte in any key, label or text', () => {
  let leaks = 0;
  for (const template of TEMPLATES) {
    const first = dummySecret();
    const second = dummySecret();
    for (const secret of [first, second]) {
      const event = bash(template(`token=${secret}`));
      const { key, c, normalized } = binding(event);
      // toolClassificationText is BASE (unchanged); the lowered text is the only new text.
      const surface = JSON.stringify([key, c, normalized, toolDataWordsText(event)]);
      if (surface.includes(secret)) leaks += 1;
    }
  }
  assert.equal(leaks, 0, 'SECRET_OCCURRENCES');
});

test('K3: a call reclassified from deploy to process gets a new action text, so an approval under the old text never covers it', () => {
  for (const row of rows.filter((item) => item.expect === 'ALLOW' && item.shape !== 'base')) {
    const event = bash(row.command, row.extra);
    const tip = classifyTool(event);
    const base = BASE.rows[row.id].pre;
    const stored = createHash('sha256').update(JSON.stringify([base.action, base.target, base.surfaces, base.type, normalizedHookAction(event, { salt })])).digest('hex');
    if (base.action !== tip.action) assert.notEqual(binding(event).key, stored, row.id);
    else assert.equal(row.shape, 'L12', `${row.id}: only git merge-base forms keep their action text (review on github)`);
  }
});

test('K5: PreToolUse and PostToolUse give one action text for every lowered row', () => {
  for (const row of rows.filter((item) => item.expect === 'ALLOW')) {
    const event = bash(row.command, row.extra);
    assert.equal(classifyTool(event, { postTool: true }).action, classifyTool(event).action, row.id);
  }
});
