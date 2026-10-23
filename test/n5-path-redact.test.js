'use strict';

// Patch round P1, F1: a known-format secret inside an edit path is replaced as a span (`[secret]`), the text around it
// stays, and the action is marked truncated. Dummy values are generated at runtime; nothing here prints one.
const assert = require('node:assert/strict');
const test = require('node:test');
const { randomBytes } = require('node:crypto');
const { normalizedHookAction, KNOWN_KEY_PREFIX } = require('../dist/normalized-action.js');

const SALT = randomBytes(32);
const AN = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const UPPER_DIGIT = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const B64U = `${AN}-_`;
const pick = (alphabet, length) => Array.from(randomBytes(length), (byte) => alphabet[byte % alphabet.length]).join('');
const mixed = (length) => { for (;;) { const text = pick(AN, length); if (/[A-Z]/.test(text) && /[a-z]/.test(text) && /\d/.test(text)) return text; } };

// One shape per alternative of KNOWN_KEY_PREFIX (11) plus the hex run: the key is the format name.
const SHAPES = {
  ghp: () => `ghp_${mixed(36)}`,
  gho: () => `gho_${mixed(36)}`,
  github_pat: () => `github_pat_${mixed(22)}_${mixed(59)}`,
  akia: () => `AKIA${pick(UPPER_DIGIT, 16)}`,
  asia: () => `ASIA${pick(UPPER_DIGIT, 16)}`,
  sk_proj: () => `sk-proj-${mixed(48)}`,
  sk_live: () => `sk_live_${mixed(24)}`,
  sk_ant: () => `sk-ant-${mixed(40)}`,
  rk_live: () => `rk_live_${mixed(24)}`,
  pk_live: () => `pk_live_${mixed(24)}`,
  xoxb: () => `xoxb-${pick('0123456789', 12)}-${pick('0123456789', 12)}-${mixed(24)}`,
  aiza: () => `AIza${mixed(35)}`,
  glpat: () => `glpat-${mixed(20)}`,
  npm: () => `npm_${mixed(36)}`,
  mrw: () => `mrw_live_${randomBytes(16).toString('hex')}`,
  cfut: () => `cfut_${mixed(40)}`,
  jwt: () => `eyJ${pick(B64U, 30)}.eyJ${pick(B64U, 40)}.${pick(B64U, 43)}`,
  hex40: () => randomBytes(20).toString('hex'),
  hex64: () => randomBytes(32).toString('hex'),
};
// Words that are not key-shaped: never touched (no friction, byte-identical to 5ffbf9c0).
const PLAIN_WORDS = ['Dashboard2UserPermissionsTable', 'UserPermissionsTable2', pick('abcdefghijklmnopqrstuvwxyz', 24), randomBytes(8).toString('hex'), randomBytes(15).toString('hex'), 'risk-assessment-document', 'task-queue-handler', 'disk-usage-report-2024', 'README'];

const FORMS = {
  ext: (s) => [`/p/${s}.txt`, `/p/[secret].txt`],
  dotenv: (s) => [`/p/.env.${s}`, `/p/.env.[secret]`],
  backup: (s) => [`/p/backup-${s}.json`, `/p/backup-[secret].json`],
  winDir: (s) => [`C:\\Users\\op\\${s}\\a.txt`, `C:\\Users\\op\\[secret]\\a.txt`],
  winExt: (s) => [`C:\\p\\${s}.txt`, `C:\\p\\[secret].txt`],
  fileUrl: (s) => [`file:///p/${s}.txt`, `file:///p/[secret].txt`],
  tilde: (s) => [`~/p/${s}.txt`, `~/p/[secret].txt`],
  // a path of only [A-Za-z0-9+/=_-] characters is one word to the older word rule, which withholds the whole of it (as on 5ffbf9c0 and base)
  bare: (s) => [`/p/${s}`, ['/p/[secret]', '[secret]']],
  dir: (s) => [`/p/${s}/a.txt`, `/p/[secret]/a.txt`],
  query: (s) => [`/p/a.txt?token=${s}`, `/p/a.txt?token=[secret]`],
  // `key=` is a credential assignment: the older assignment rule takes the value to the end of the word (as on 5ffbf9c0 and base)
  eq: (s) => [`/p/key=${s}.txt`, `/p/key=[secret]`],
  deep: (s) => [`/a/b/c/${s}.tar.gz`, `/a/b/c/[secret].tar.gz`],
  twice: (s) => [`/p/${s}.bak/${s}.txt`, `/p/[secret].bak/[secret].txt`],
};
const TOOLS = {
  Edit: (file) => ({ file_path: file, old_string: 'a', new_string: 'b' }),
  Write: (file) => ({ file_path: file, content: 'b' }),
  NotebookEdit: (file) => ({ notebook_path: file, new_source: 'x' }),
  MultiEdit: (file) => ({ file_path: file, edits: [{ old_string: 'a', new_string: 'b' }] }),
};
const act = (tool, file, options = {}) => normalizedHookAction({ tool_name: tool, tool_input: TOOLS[tool](file) }, { salt: SALT, ...options });
const pathsOf = (action) => action.paths;

test('R1/R2/R3: every known format x every path form x every edit tool: only the span is replaced, the action is truncated, no value is left', () => {
  let cells = 0;
  for (const [shape, make] of Object.entries(SHAPES)) {
    for (const [form, build] of Object.entries(FORMS)) {
      for (const tool of Object.keys(TOOLS)) {
        const secret = make();
        const [input, expected] = build(secret);
        const action = act(tool, input);
        const text = JSON.stringify(action);
        const label = `${shape}/${form}/${tool}`;
        if (Array.isArray(expected)) assert.ok(expected.includes(pathsOf(action)[0]), label);
        else assert.deepEqual(pathsOf(action), [expected], label);
        assert.equal(action.truncated, true, `${label}: truncated`);
        assert.equal(text.includes(secret), false, `${label}: clear`);
        assert.equal(text.toLowerCase().includes(secret.toLowerCase()), false, `${label}: folded`);
        cells += 1;
      }
    }
  }
  assert.equal(cells, Object.keys(SHAPES).length * Object.keys(FORMS).length * 4);
});

test('R2: words that are not key-shaped are not touched: the path is the same as before and the action is not truncated', () => {
  for (const word of PLAIN_WORDS) {
    for (const file of [`/p/${word}.tsx`, `/p/${word}`, `/p/.env.${word}`, `/p/backup-${word}.json`, `C:\\p\\${word}.txt`, `~/p/${word}/a.txt`]) {
      for (const tool of Object.keys(TOOLS)) {
        const action = act(tool, file);
        // A bare word of 20+ mixed characters is withheld by the older word rule on both builds; the extension forms never were.
        if (action.truncated === true) assert.match(JSON.stringify(action.paths), /\[secret\]/, `${tool} ${file}`);
        else assert.deepEqual(action.paths, [file], `${tool} ${file}`);
      }
    }
  }
  // The ordinary CamelCase file name with an extension is the example of the brief: untouched, bindable.
  const ordinary = act('Edit', '/p/src/Dashboard2UserPermissionsTable.tsx');
  assert.deepEqual(ordinary.paths, ['/p/src/Dashboard2UserPermissionsTable.tsx']);
  assert.equal(ordinary.truncated, undefined);
});

test('R2: the left boundary: a format literal inside a longer word is not a span', () => {
  for (const file of ['/p/risk-assessment-document.md', '/p/task-queue-handler-v2.ts', '/p/xsk-learn-model-utils.py', '/p/Askew_ghp_notes.txt', '/p/disk-usage-report-2024.csv']) {
    const action = act('Edit', file);
    assert.deepEqual(action.paths, [file], file);
    assert.equal(action.truncated, undefined, file);
  }
  // After a separator it is a span.
  const secret = SHAPES.sk_proj();
  assert.deepEqual(act('Edit', `/p/x-${secret}.txt`).paths, ['/p/x-[secret].txt']);
  assert.deepEqual(act('Edit', `/p/x_${secret}.txt`).paths, ['/p/x_[secret].txt']);
});

test('R2: the right side ends at the first non-token character; the rest of the name stays', () => {
  const ghp = SHAPES.ghp();
  assert.deepEqual(act('Edit', `/p/${ghp}_notes.txt`).paths, ['/p/[secret]_notes.txt']);
  assert.deepEqual(act('Edit', `/p/${ghp}.tar.gz`).paths, ['/p/[secret].tar.gz']);
  assert.deepEqual(act('Edit', `/p/${ghp}?x=1#frag`).paths, ['/p/[secret]?x=1#frag']);
  assert.deepEqual(act('Edit', `${ghp}`).paths, ['[secret]']);
  const jwt = SHAPES.jwt();
  assert.deepEqual(act('Edit', `/p/${jwt}.json`).paths, ['/p/[secret].json']);
});

test('R4: a token inside a sensitive name keeps the sensitive text visible for the service classifier', () => {
  const token = SHAPES.ghp();
  for (const [input, expected] of [
    [`/p/.env.${token}`, '/p/.env.[secret]'],
    [`/p/.ssh/${token}`, '/p/.ssh/[secret]'],
    [`/p/secrets/${token}.pem`, '/p/secrets/[secret].pem'],
    [`/etc/${token}.conf`, '/etc/[secret].conf'],
    [`/p/id_rsa.${token}`, '/p/id_rsa.[secret]'],
    [`/p/credentials/${token}.json`, '/p/credentials/[secret].json'],
    [`/p/production/config/${token}.yaml`, '/p/production/config/[secret].yaml'],
  ]) assert.deepEqual(act('Write', input).paths, [expected], input);
  // /home/<user> is the older rule: the name is replaced, the span is replaced, `.ssh/` stays.
  assert.deepEqual(act('Write', `/home/someone/.ssh/${token}`).paths, ['/home/[user]/.ssh/[secret]']);
});

test('collisions: a difference outside the span gives a different path text and different keys; a difference only in the secret may match', () => {
  const s1 = SHAPES.ghp();
  const s2 = SHAPES.ghp();
  const pairs = [
    [`/p/${s1}.txt`, `/p/${s1}.md`, 'differ'],
    [`/p/x/${s1}.txt`, `/p/y/${s1}.txt`, 'differ'],
    [`/p/${s1}.txt`, `/p/${s1}.TXT`, 'differ'],
    [`/p/backup-${s1}.txt`, `/p/Backup-${s1}.txt`, 'differ'],
    [`/p/.env.${s1}`, `/p/.env.${s1}.bak`, 'differ'],
    [`C:\\p\\${s1}.txt`, `C:\\q\\${s1}.txt`, 'differ'],
    [`file:///p/${s1}.txt`, `file:///p/${s1}.json`, 'differ'],
    [`/p/key=${s1}.txt`, `/p/key=${s1}.md`, 'differ-keys-only'],
    [`/p/${s1}.txt`, `/p/${s2}.txt`, 'may-match'],
  ];
  for (const [a, b, kind] of pairs) {
    const left = act('Edit', a);
    const right = act('Edit', b);
    const sameText = JSON.stringify(left.paths) === JSON.stringify(right.paths);
    if (kind === 'differ-keys-only') {
      // the older assignment rule hides the whole value word, so the text may match; the exact key never does
      assert.notEqual(left.tool_input.exact_hmac, right.tool_input.exact_hmac);
    } else if (kind === 'differ') {
      assert.equal(sameText, false, `paths differ: ${kind}`);
      assert.notEqual(left.tool_input.input_sha256, right.tool_input.input_sha256, 'input_sha256 differs');
      assert.notEqual(left.tool_input.exact_hmac, right.tool_input.exact_hmac, 'exact_hmac differs');
    } else {
      assert.equal(sameText, true, 'only the secret differs: same text');
      // the keys also differ (the secret is part of the keyed material): the older, conservative behaviour, never a collision
      assert.notEqual(left.tool_input.exact_hmac, right.tool_input.exact_hmac);
    }
  }
});

test('R3: a path without a span does not change the truncated state; a path with one always sets it', () => {
  assert.equal(act('Edit', '/p/src/a.ts').truncated, undefined);
  assert.equal(act('Edit', `/p/${SHAPES.hex40()}.txt`).truncated, true);
  assert.equal(act('Edit', `/p/${SHAPES.akia()}`).truncated, true);
});

test('straddling the 512-character cut: a token that crosses it is replaced whole, never halved', () => {
  for (const pad of [490, 500, 505, 511, 512, 600]) {
    const secret = SHAPES.ghp();
    const file = `/${'z'.repeat(pad)}/${secret}.txt`;
    const action = act('Edit', file);
    const sent = JSON.stringify(action.paths);
    for (let i = 0; i + 6 <= secret.length; i += 1) assert.equal(sent.includes(secret.slice(i, i + 6)), false, `pad ${pad} slice ${i}`);
    assert.equal(action.truncated, true);
    // The pad is not a hex run, so the token really does start before the cut and end after it (the test is not vacuous).
    assert.ok(action.paths[0].startsWith(`/${'z'.repeat(Math.min(pad, 511))}`), `pad ${pad} is kept`);
  }
});

test('R5: a token cut by the scan window leaves no part of itself, even after earlier tokens shrank the text', () => {
  for (const cutAt of [1000, 1008, 1012, 1016, 1020]) {
    const earlier = [];
    let text = '';
    while (text.length < 700) { const token = SHAPES.ghp(); earlier.push(token); text += `/${token}`; }
    while (text.length + 2 <= cutAt) text += '/q';
    while (text.length < cutAt) text += 'q';
    const last = SHAPES.ghp();
    const file = `${text}/${last}${'/q'.repeat(100)}`;
    const action = act('Edit', file);
    const sent = JSON.stringify(action);
    for (const token of [...earlier, last]) for (let i = 0; i + 6 <= token.length; i += 1) assert.equal(sent.includes(token.slice(i, i + 6)), false, `cut ${cutAt}`);
    assert.equal(action.truncated, true);
  }
});

test('R5: long, hostile paths finish fast and give a truncated, bounded result', () => {
  const secret = SHAPES.ghp();
  const hostile = [
    'sk-'.repeat(33_000), 'eyJ-'.repeat(25_000), 'ghp_'.repeat(25_000), `${'a'.repeat(100_000)}`, `/${'AKIA'.repeat(25_000)}`, '/p/'.repeat(33_000),
    'sk-'.repeat(5_000), 'eyJ-'.repeat(4_000), 'eyJ.'.repeat(4_000), `${'0'.repeat(30)}x`.repeat(450), `${'ab'.repeat(15)}-`.repeat(500), '9'.repeat(16_000),
    `/${'z'.repeat(1_200)}/${secret}.txt`, `/${'z'.repeat(1_023)}/${secret}`,
  ];
  for (const file of hostile) {
    const started = process.hrtime.bigint();
    const action = act('Edit', file);
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(ms < 200, `${file.slice(0, 12)}...(${file.length}): ${ms.toFixed(1)} ms`);
    assert.equal(action.truncated, true, `${file.slice(0, 12)}...(${file.length}) truncated`);
    assert.ok(action.paths[0].length <= 512);
    assert.equal(JSON.stringify(action).includes(secret), false);
  }
});

test('R5: the scan cost does not grow with the path (a bounded window, not the whole text)', () => {
  // Best of three, and relative to a path of a fifth of the size: no fixed wall-clock limit that a loaded machine could break.
  const best = (file) => {
    let fastest = Infinity;
    for (let round = 0; round < 3; round += 1) {
      const started = process.hrtime.bigint();
      act('Edit', file);
      fastest = Math.min(fastest, Number(process.hrtime.bigint() - started) / 1e6);
    }
    return fastest;
  };
  // `eyJ-` repeated is a candidate span start at every fourth character and never completes (a JWT needs its dots).
  const small = best('eyJ-'.repeat(800));
  const large = best('eyJ-'.repeat(4000));
  assert.ok(large < Math.max(small * 12, 40), `16000 characters took ${large.toFixed(1)} ms, 3200 characters ${small.toFixed(1)} ms`);
});

test('R5: 64+ targets: the first 64 are scanned, the action is truncated, no value is left', () => {
  const tokens = Array.from({ length: 70 }, () => SHAPES.ghp());
  const patch = tokens.map((token) => `*** Update File: /p/${token}.txt`).join('\n');
  const action = normalizedHookAction({ tool_name: 'apply_patch', tool_input: { input: `*** Begin Patch\n${patch}\n*** End Patch` } }, { salt: SALT });
  assert.equal(action.paths.length, 64);
  assert.equal(action.truncated, true);
  assert.ok(action.paths.every((entry) => entry === '/p/[secret].txt'));
  for (const token of tokens) assert.equal(JSON.stringify(action).includes(token), false);
});

test('abuse: separators, traversal, lookalikes, NUL and newline: only a real span is replaced, nothing else changes', () => {
  const token = SHAPES.ghp();
  const cases = [
    [`/p/../${token}.txt`, '/p/../[secret].txt'],
    [`/p/${token}/../${token}.txt`, '/p/[secret]/../[secret].txt'],
    [`/p/\uFF0F${token}.txt`, '/p/\uFF0F[secret].txt'],
    [`C:\\p\\..\\${token}`, 'C:\\p\\..\\[secret]'],
    [`%USERPROFILE%\\${token}.txt`, '%USERPROFILE%\\[secret].txt'],
    [`$HOME/${token}.txt`, '$HOME/[secret].txt'],
    [`~someone/${token}.txt`, '~someone/[secret].txt'],
    [`/p/${token}\n/p/${token}.txt`, '/p/[secret]\n/p/[secret].txt'],
    [`/p/${token}\u0000.txt`, '/p/[secret]\u0000.txt'],
    [`/p/ghp_${token.slice(4, 10)}/${token.slice(10)}.txt`, null],
  ];
  for (const [input, expected] of cases) {
    const action = act('Edit', input);
    if (expected !== null) assert.deepEqual(action.paths, [expected], JSON.stringify(input).slice(0, 40));
    else assert.equal(JSON.stringify(action).includes(token), false);
  }
  // Not a known format: a prefix in another case, a token split across `/`. Equal to 5ffbf9c0 (a word is not a key).
  const split = act('Edit', `/p/${token.slice(0, 10)}/${token.slice(10)}.txt`);
  assert.deepEqual(split.paths, [`/p/${token.slice(0, 10)}/${token.slice(10)}.txt`]);
  for (const file of [`/p/GHP_${token.slice(4)}.txt`, `/p/AkIa${pick(UPPER_DIGIT, 16)}.txt`]) assert.deepEqual(act('Edit', file).paths, [file]);
});

test('drift: every alternative of KNOWN_KEY_PREFIX is a path span, and the scanner has no format of its own', () => {
  const alternatives = KNOWN_KEY_PREFIX.source.split('|^');
  assert.equal(alternatives.length, 11, 'KNOWN_KEY_PREFIX changed: add its sample here');
  assert.ok(alternatives.every((alt, index) => (index === 0 ? alt.startsWith('^') : true) && alt.endsWith('$')), 'every alternative is anchored');
  // A sample per alternative (one shape of SHAPES names it), each of which is a whole-word key AND a path span.
  const samples = [SHAPES.akia(), SHAPES.ghp(), SHAPES.github_pat(), SHAPES.sk_proj(), SHAPES.xoxb(), SHAPES.aiza(), SHAPES.glpat(), SHAPES.npm(), SHAPES.mrw(), SHAPES.cfut(), SHAPES.jwt()];
  assert.equal(samples.length, alternatives.length);
  const covered = new Set();
  for (const sample of samples) {
    const index = alternatives.findIndex((alt) => new RegExp(`^${alt.replace(/^\^/, '')}`).test(sample));
    assert.notEqual(index, -1, 'sample matches an alternative');
    covered.add(index);
    assert.deepEqual(act('Edit', `/p/${sample}.txt`).paths, ['/p/[secret].txt']);
  }
  assert.equal(covered.size, alternatives.length, 'one sample per alternative');
});

test('forged client fields: a path cannot carry its own truncated or paths flag; the action is built from the tool input only', () => {
  const secret = SHAPES.ghp();
  const action = normalizedHookAction({ tool_name: 'Edit', tool_input: { file_path: `/p/${secret}.txt`, truncated: false, paths: ['/p/clean.txt'], exact_hmac: 'f'.repeat(32), input_sha256: '0'.repeat(64), old_string: 'a', new_string: 'b' } }, { salt: SALT });
  assert.deepEqual(action.paths, ['/p/[secret].txt']);
  assert.equal(action.truncated, true);
  assert.notEqual(action.tool_input.exact_hmac, 'f'.repeat(32));
  assert.notEqual(action.tool_input.input_sha256, '0'.repeat(64));
});
