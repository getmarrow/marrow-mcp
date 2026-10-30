const assert = require('node:assert/strict');
const test = require('node:test');

const { normalizedHookAction } = require('../dist/normalized-action.js');
const R = require('./support/key-class-rows.cjs');

// mcp-109-n2 (reaudit-mcp109 ks-shortcut): the test/live key split holds under each early return of the pre-action hook. For every position of
// test/support/key-class-rows.cjs (dummy keys drawn at run time by that helper, never printed) and each prefix (none, an MCP-10 route, a T2
// control-file write, a T2 persistence write): a test key and a live key give DIFFERENT approval keys, text after the key gives a DIFFERENT
// key, and the secret is never in the key.
const PREFIXES = {
  none: '',
  mcp10: 'npx @getmarrow/install control disable && ',
  t2c: "echo '{}' > ~/.marrow/control.json && ",
  t2p: 'echo x >> ~/.bashrc && ',
};
const key = (event) => JSON.stringify(normalizedHookAction({ ...event, cwd: '/tmp' }));
const withPrefix = (event, prefix) => (event.tool_name === 'Bash' && prefix ? { ...event, tool_input: { ...event.tool_input, command: prefix + event.tool_input.command } } : event);

test('mcp-109-n2 key split: test != live, tail differs, no secret in the key under each early-return prefix', () => {
  let rows = 0;
  for (const position of R.POSITIONS) {
    for (const [name, prefix] of Object.entries(PREFIXES)) {
      for (const kind of ['sk', 'rk', 'pk']) {
        const live = R.live(kind);
        const dummy = R.test(kind);
        const liveEvent = position.build(live);
        if (name !== 'none' && liveEvent.tool_name !== 'Bash') continue;
        const keyLive = key(withPrefix(liveEvent, prefix));
        const keyTest = key(withPrefix(position.build(dummy), prefix));
        const keyTail = key(withPrefix(position.build(live, 'zz9'), prefix));
        rows += 1;
        const id = `${position.id}/${name}/${kind}`;
        assert.notEqual(keyLive, keyTest, `${id}: test key equals live key`);
        assert.notEqual(keyLive, keyTail, `${id}: text after the key does not change the key`);
        for (const secret of [live, dummy, live.slice(8), dummy.slice(8)]) assert.ok(!keyLive.includes(secret) && !keyTest.includes(secret) && !keyTail.includes(secret), `${id}: secret in key`);
      }
    }
  }
  assert.ok(rows >= 500, `rows ${rows}`);
});
