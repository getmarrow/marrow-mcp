'use strict';

// Helpers for the U6 receipt tests: a scratch home (the real home is never touched), a reader for
// ~/.marrow/seatbelt/receipts, and a chain verifier a later consumer (the first-hour report) can copy.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

function scratchHome(prefix = 'marrow-u6-') {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  const home = path.join(root, 'home');
  fs.mkdirSync(home, { mode: 0o700 });
  const sb = path.join(home, '.marrow', 'seatbelt');
  return { root, home, sb, receipts: path.join(sb, 'receipts'), cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}

/** Every receipt line in file-name order: { file, line, receipt }. */
function readReceipts(home) {
  const dir = path.join(home, '.marrow', 'seatbelt', 'receipts');
  if (!fs.existsSync(dir)) return [];
  const out = [];
  for (const file of fs.readdirSync(dir).filter((name) => /^\d{4}-\d{2}-\d{2}\.jsonl$/.test(name)).sort()) {
    for (const line of fs.readFileSync(path.join(dir, file), 'utf8').split('\n')) {
      if (line.trim() === '') continue;
      out.push({ file, line, receipt: JSON.parse(line) });
    }
  }
  return out;
}

/** Problems in a chain of raw lines: a line whose prev is not the sha256 of the line before it, or whose seq is not the next one. */
function verifyChain(lines) {
  const problems = [];
  for (let k = 1; k < lines.length; k += 1) {
    const prev = JSON.parse(lines[k - 1]);
    const now = JSON.parse(lines[k]);
    if (now.prev !== crypto.createHash('sha256').update(lines[k - 1]).digest('hex')) problems.push(`prev@${k}`);
    if (now.seq !== prev.seq + 1) problems.push(`seq@${k}`);
  }
  return problems;
}

const record = (over = {}) => ({
  v: 1, mode: 'seatbelt', enforcement: 'enforce', harness: 'claude-code', decision: 'pass', category: 'none', rule: 'none',
  reasons: [], flags: [], parse: 'ok', latency_ms: 3, ...over,
});
const STOP = {
  decision: 'stop', category: 'S1', rule: 'S1.protected_branch_force', reasons: ['git_push_force_protected_branch'], flags: ['force', 'protected_branch_push'],
};
const bash = (command, extra = {}) => ({ tool_name: 'Bash', tool_input: { command }, session: 'session-one', ...extra });

module.exports = { scratchHome, readReceipts, verifyChain, record, STOP, bash };
