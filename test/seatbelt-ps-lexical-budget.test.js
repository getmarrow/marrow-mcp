'use strict';

// 3.9.106 patch round, finding M-1 (HIGH): psLexical was quadratic in the number of words of one statement (it re-read the
// rest of the statement for every delete verb), and the wall-clock budget was not checked inside its loops. A 18 KB
// `if;rd;rd;...` took 8 to 12 s and 48 KB took 52 s, on every OS. These rows pin the fix by STEP COUNT, never by wall clock:
// the steps are the calls psLexical makes into the tables module (programs named, statements read, words handed to the
// delete checks), counted at that boundary. In-memory fakes only; no key, token or real path.
const test = require('node:test');
const assert = require('node:assert/strict');

const { evaluateSeatbelt } = require('../dist/seatbelt/mapper.js');
const tables = require('../dist/seatbelt/tables.js');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');

const MAX_WORDS = tables.LIMITS.maxWords;
const POSIX_RULE = 'S5.recursive_delete_outside_ws';
const SX_RULE = 'Sx.obfuscated_exec';
const PLATFORMS = ['linux', 'darwin', 'win32'];

function pad(head, unit, bytes) {
  let s = head;
  while (Buffer.byteLength(s) < bytes) s += unit;
  return s;
}
const rowA = (bytes) => pad('rm -rf ~/projects # & if', ';rd', bytes);
const rowB = (bytes) => pad('if', ';rd', bytes);

function decide(platform, cmd, tool = 'Bash') {
  return evaluateSeatbelt({ tool_name: tool, tool_input: { command: cmd } }, makeEnv({ platform, cwd: platform === 'win32' ? null : undefined }));
}

// Steps psLexical takes, counted at the tables boundary: one per program word named, one per statement and per word the
// tokenizer returns, and every word handed to a delete check (an O(n^2) check shows up here as n^2/2).
function steps(platform, cmd, tool = 'Bash') {
  const wrapped = ['windowsProgramName', 'psStatements', 'windowsDeleteStops', 'windowsDeleteStopsFrom'];
  const saved = wrapped.map((n) => tables[n]);
  let count = 0;
  tables.windowsProgramName = function (...a) { count += 1; return saved[0].apply(this, a); };
  tables.psStatements = function (...a) { const r = saved[1].apply(this, a); for (const st of r.statements) count += 1 + st.words.length; return r; };
  tables.windowsDeleteStops = function (words, ...a) { count += words.length; return saved[2].call(this, words, ...a); };
  tables.windowsDeleteStopsFrom = function (words, ...a) { count += words.length; const f = saved[3].call(this, words, ...a); return (p) => { count += 1; return f(p); }; };
  try {
    const d = decide(platform, cmd, tool);
    return { count, d };
  } finally {
    wrapped.forEach((n, i) => { tables[n] = saved[i]; });
  }
}

test('M-1: the suffix answer of windowsDeleteStopsFrom equals windowsDeleteStops(words.slice(p + 1)) for every p', () => {
  const vocab = ['-r', '-Recurse', '-Force', '-ea', '/s', '/q', '/f', '/a:h', 'a', 'x.txt', 'C:\\x', '$v', '%X%', '!X!', '{', '}', '@a', '`', '', '-Path', '--x', '-', '/', '-whatif'];
  let seed = 7;
  const rnd = (n) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
  let checked = 0;
  for (let round = 0; round < 3000; round += 1) {
    const words = Array.from({ length: rnd(9) }, () => vocab[rnd(vocab.length)]);
    for (const pipedFirst of [false, true]) {
      const from = tables.windowsDeleteStopsFrom(words, pipedFirst);
      for (let p = 0; p < Math.max(words.length, 1); p += 1) {
        assert.equal(from(p), tables.windowsDeleteStops(words.slice(p + 1), pipedFirst && p === 0), `${JSON.stringify(words)} p=${p} piped=${pipedFirst}`);
        checked += 1;
      }
    }
  }
  assert.ok(checked > 10000);
});

// The 3.9.105 / 337f5e46 algorithm of windowsDeleteStops, kept here word for word as the reference.
function referenceDeleteStops(words, piped) {
  if (piped) return true;
  let targets = 0;
  for (const raw of words) {
    if (raw === null) return true;
    const t = tables.psNormalize(raw);
    if (t === '' || t === '}') continue;
    if (/[`%!{}]/.test(t) || t[0] === '@') return true;
    if (t[0] === '-' || t[0] === '/') { if (referenceOptionStops(t)) return true; continue; }
    if (t.includes('$')) return true;
    targets += 1;
  }
  return targets === 0;
}
const PS_DELETE_OPTIONS = ['path', 'literalpath', 'filter', 'include', 'exclude', 'force', 'whatif', 'confirm', 'erroraction', 'verbose', 'debug'];
function referenceOptionStops(word) {
  if (word[0] === '/') {
    for (const part of word.slice(1).split('/')) if (!/^(?:[qfp]|a(?::[a-z-]{0,12})?)$/i.test(part)) return true;
    return false;
  }
  if (word.startsWith('--')) return true;
  const colon = word.indexOf(':');
  const name = (colon > 0 ? word.slice(1, colon) : word.slice(1)).toLowerCase();
  const value = colon > 0 ? word.slice(colon + 1) : null;
  if (name === '' || name.startsWith('r')) return true;
  if (name !== 'ea' && PS_DELETE_OPTIONS.filter((k) => k.startsWith(name)).length !== 1) return true;
  if (value !== null && value.includes('$') && !/^\$(?:true|false)$/i.test(value)) return true;
  return false;
}

test('M-1: windowsDeleteStops (refactored into one word classifier) answers exactly as the 3.9.105 algorithm, null words included', () => {
  const vocab = ['-r', '-R', '-Recurse', '-Recurse:$true', '-Force', '-Force:$false', '-Confirm:$false', '-ea', '-Path', '-Pa', '-F', '-f', '-whatif', '--x', '-', '/s', '/q', '/f', '/p', '/a:h', '/a', '/s/q', '/?', '/',
    'a', 'x.txt', 'C:\\x', '.\\a\\b', '$v', '$env:A', '%X%', '!X!', '{', '}', '@a', '`', '', ' ', '\u2013r', '\u2014Recurse', null, null];
  let seed = 11;
  const rnd = (n) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
  let checked = 0;
  for (let round = 0; round < 6000; round += 1) {
    const words = Array.from({ length: rnd(8) }, () => vocab[rnd(vocab.length)]);
    for (const piped of [false, true]) {
      assert.equal(tables.windowsDeleteStops(words, piped), referenceDeleteStops(words, piped), `${JSON.stringify(words)} piped=${piped}`);
      checked += 1;
    }
  }
  assert.ok(checked >= 12000);
});

test('M-1: windowsDeleteStopsFrom reads each word once (a Proxy counts the reads), not once per delete verb', () => {
  for (const n of [1000, 64000]) {
    const reads = { n: 0 };
    const words = new Proxy(Array.from({ length: n }, () => 'rd'), { get(t, k, r) { if (typeof k === 'string' && /^\d+$/.test(k)) reads.n += 1; return Reflect.get(t, k, r); } });
    const from = tables.windowsDeleteStopsFrom(words, false);
    for (let p = 0; p < n; p += 1) from(p);
    assert.equal(reads.n, n, `n=${n}`);
  }
});

for (const [label, make] of [['A: rm -rf ~/projects # & if;rd;rd...', rowA], ['B: if;rd;rd...', rowB]]) {
  test(`M-1 ${label}: steps stay bounded and scale at most 20x from 4 KB to 64 KB on every platform, and the decision is a stop`, () => {
    for (const platform of PLATFORMS) {
      const small = steps(platform, make(4000));
      const mid = steps(platform, make(18000));
      const big = steps(platform, make(64000));
      for (const r of [small, mid, big]) {
        assert.equal(r.d.decision, 'stop', `${platform}`);
        assert.ok(r.d.reasons.includes('budget_words'), `${platform}: the word budget is part of the stop: ${r.d.reasons.join(',')}`);
        assert.equal(r.d.parse, 'too_large', platform);
      }
      assert.ok(big.count <= 20 * Math.max(small.count, 1), `${platform}: 64 KB took ${big.count} steps, 4 KB took ${small.count}`);
      assert.ok(big.count <= 4 * MAX_WORDS * 64, `${platform}: absolute cap, 64 KB took ${big.count} steps`);
      assert.ok(mid.count <= 20 * Math.max(small.count, 1), `${platform}: 18 KB took ${mid.count} steps, 4 KB took ${small.count}`);
    }
  });
}

test('M-1 A: on linux and darwin the primary rule is the 3.9.105 one (S5.recursive_delete_outside_ws), padded or not', () => {
  for (const platform of ['linux', 'darwin']) {
    for (const bytes of [4000, 18000, 64000]) {
      const d = decide(platform, rowA(bytes));
      assert.equal(d.decision, 'stop');
      assert.equal(d.rule, POSIX_RULE, `${platform} ${bytes}: ${d.rule} [${d.reasons.join(',')}]`);
      assert.ok(d.reasons.includes('rm_recursive_outside_workspace'));
      assert.equal(d.category, 'S5');
    }
  }
});

test('M-1 B: on linux and darwin the padded `if;rd;rd...` keeps its 3.9.105 budget stop in the reasons and stops on the budget', () => {
  for (const platform of ['linux', 'darwin']) {
    const d = decide(platform, rowB(18000));
    assert.equal(d.decision, 'stop');
    assert.ok(d.reasons.includes('budget_segments') && d.reasons.includes('budget_words'), d.reasons.join(','));
    assert.ok(d.rule === SX_RULE || d.rule === 'S5.windows_shell_delete_unparsed', d.rule);
  }
});

test('M-1: other padded shapes (cmd, iex, rm, del, start, call, a wide cmd line) are linear and still decided', () => {
  const shapes = [['if', ';cmd'], ['if', ';cmd /c'], ['if', ';iex'], ['if', ';rm'], ['if', ';del'], ['if', ',call'], ['for', ';%a'], ['cmd', ';/c'], ['if', ';start'], ['rd ', '(a)']];
  for (const [head, unit] of shapes) {
    for (const platform of ['linux', 'win32']) {
      const small = steps(platform, pad(head, unit, 4000));
      const big = steps(platform, pad(head, unit, 40000));
      assert.ok(big.count <= 20 * Math.max(small.count, 1), `${platform} ${head}${unit}: 40 KB ${big.count} vs 4 KB ${small.count}`);
      assert.ok(big.count <= 4 * MAX_WORDS * 64, `${platform} ${head}${unit}: ${big.count} steps`);
      assert.equal(big.d.decision === 'stop' || big.d.decision === 'pass', true);
    }
  }
});

test('M-1: statements that stay under the word budget (many short ones) scale linearly from 4 KB to 40 KB', () => {
  for (const [platform, tool] of [['linux', 'PowerShell'], ['win32', 'Bash'], ['win32', 'PowerShell']]) {
    const small = steps(platform, pad('rd a', ';rd a', 4000), tool);
    const big = steps(platform, pad('rd a', ';rd a', 40000), tool);
    assert.ok(small.count > 0 && big.count > 0, `${platform} ${tool}: ${small.count} ${big.count}`);
    assert.ok(big.count <= 20 * small.count, `${platform} ${tool}: 40 KB ${big.count} vs 4 KB ${small.count}`);
  }
});

test('M-1: a statement of more words than one command may have stops on the word budget; a long script of short statements does not', () => {
  const wide = `if${' rd'.repeat(MAX_WORDS + 1)}`;
  const d = decide('win32', wide);
  assert.equal(d.decision, 'stop');
  assert.ok(d.reasons.includes('budget_words'), d.reasons.join(','));
  // 200 short statements on native Windows (about 600 words in all): no word-budget stop from the lexical check.
  const script = Array.from({ length: 200 }, (_, i) => `npm run build${i % 3}`).join('\n');
  const ok = decide('win32', script);
  assert.ok(!ok.reasons.includes('budget_words'), ok.reasons.join(','));
});

test('M-1: the budget stop never turns a stop into a pass (padding after a real delete keeps the A3 stop on win32)', () => {
  for (const bytes of [200, 4000, 64000]) {
    const d = decide('win32', pad('Remove-Item -Recurse C:\\x # & if', ';rd', bytes));
    assert.equal(d.decision, 'stop', `${bytes}`);
  }
  for (const bytes of [200, 4000, 64000]) {
    const d = decide('linux', pad('rm -rf ~/projects # & if', ';cmd /c', bytes));
    assert.equal(d.decision, 'stop', `${bytes}`);
    assert.equal(d.rule === POSIX_RULE || d.rule === 'S5.windows_shell_delete_unparsed', true, d.rule);
  }
});
