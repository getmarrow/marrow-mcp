'use strict';

// Child process of the concurrent-writer test: node seatbelt-u6-writer.cjs <home> <count> <tag>.
// Writes <count> receipts through dist/seatbelt/record.js into <home> and prints how many were written.
const { writeSeatbeltReceipt } = require('../../dist/seatbelt/record.js');

const [home, count, tag] = process.argv.slice(2);
let written = 0;
for (let i = 0; i < Number(count); i += 1) {
  const result = writeSeatbeltReceipt(
    { v: 1, mode: 'seatbelt', enforcement: 'enforce', harness: 'claude-code', decision: i % 5 === 0 ? 'stop' : 'pass', category: 'none', rule: 'none', reasons: [], flags: [], parse: 'ok', latency_ms: 1 },
    { tool_name: 'Bash', tool_input: { command: `echo ${tag} ${i}` }, cwd: home, session: tag },
    { home, lockWaitMs: 20_000 },
  );
  if (result === 'written') written += 1;
}
process.stdout.write(JSON.stringify({ written }));
