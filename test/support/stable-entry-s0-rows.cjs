'use strict';
// MCP-2 T3 / M1: the writes that must stay S0-held (self-protect) and the reads that stay not-S0, against the three places the
// stable entry and the identity restore live under ~/.marrow: `runtime/current`, `runtime/launcher/<sha256>.cjs` and
// `identity-record.json`. Rows are data so a before/after table (BASE vs candidate) can be printed from the same list.
// Nothing here touches a real file or holds a key: commands are text for the in-memory mapper (test/support/seatbelt-fakes.cjs).
const DIGEST = 'a'.repeat(64);
const TARGETS = [
  { id: 'current', rel: '.marrow/runtime/current', dir: '.marrow/runtime', name: 'current' },
  { id: 'launcher', rel: `.marrow/runtime/launcher/${DIGEST}.cjs`, dir: '.marrow/runtime/launcher', name: `${DIGEST}.cjs` },
  { id: 'record', rel: '.marrow/identity-record.json', dir: '.marrow', name: 'identity-record.json' },
];
const ABS_HOME = '/home/u';
// The four ways a command names a file under the home.
const SPELLINGS = [['tilde', (rel) => `~/${rel}`], ['HOME', (rel) => `$HOME/${rel}`], ['braced', (rel) => `"\${HOME}/${rel}"`], ['absolute', (rel) => `${ABS_HOME}/${rel}`]];
// One write each: redirect, append, truncate-redirect, copy, move, remove, link, mode, in-place edit, dd, truncate, install, tee.
const WRITES = [
  ['redirect', (p) => `printf x > ${p}`], ['append', (p) => `printf x >> ${p}`], ['colon-redirect', (p) => `: > ${p}`],
  ['cp', (p) => `cp x ${p}`], ['mv', (p) => `mv x ${p}`], ['rm', (p) => `rm ${p}`], ['ln', (p) => `ln -sf /virtual/x ${p}`],
  ['chmod', (p) => `chmod 666 ${p}`], ['sed-i', (p) => `sed -i s/a/b/ ${p}`], ['dd', (p) => `dd if=/dev/null of=${p}`],
  ['truncate', (p) => `truncate -s0 ${p}`], ['install', (p) => `install x ${p}`], ['tee', (p) => `echo x | tee ${p}`],
];
// The same write inside each chain, wrapper and subshell the brief names.
const WRAPS = [
  ['plain', (w) => w], ['and', (w) => `true && ${w}`], ['semicolon', (w) => `true; ${w}`], ['or', (w) => `false || ${w}`],
  ['and-after', (w) => `${w} && true`], ['subshell', (w) => `( ${w} )`], ['group', (w) => `{ ${w}; }`],
  ['bash-c', (w) => `bash -c '${w}'`], ['sh-c', (w) => `sh -c "${w.replace(/"/g, '\\"')}"`], ['pipe-after', (w) => `${w} | cat`],
];

const bash = (command) => ({ tool_name: 'Bash', tool_input: { command } });
const rows = [];
const add = (id, kind, event) => rows.push({ id, kind, event });

for (const t of TARGETS) {
  // Write, Edit and the other file tools name the file by its absolute path.
  const abs = `${ABS_HOME}/${t.rel}`;
  add(`${t.id}/Write`, 'tool', { tool_name: 'Write', tool_input: { file_path: abs, content: 'x' } });
  add(`${t.id}/Edit`, 'tool', { tool_name: 'Edit', tool_input: { file_path: abs, old_string: 'a', new_string: 'b' } });
  add(`${t.id}/MultiEdit`, 'tool', { tool_name: 'MultiEdit', tool_input: { file_path: abs, edits: [] } });
  add(`${t.id}/NotebookEdit`, 'tool', { tool_name: 'NotebookEdit', tool_input: { notebook_path: abs, new_source: 'x' } });
  add(`${t.id}/Write-trailing-slash`, 'tool', { tool_name: 'Write', tool_input: { file_path: `${abs}/`, content: 'x' } });
  add(`${t.id}/Write-dotdot`, 'tool', { tool_name: 'Write', tool_input: { file_path: `${ABS_HOME}/.marrow/runtime/../${t.rel.slice('.marrow/'.length)}`, content: 'x' } });
  // Every write spelled every way, plain.
  for (const [spell, spelled] of SPELLINGS) {
    for (const [write, make] of WRITES) add(`${t.id}/${spell}/${write}`, 'shell', bash(make(spelled(t.rel))));
  }
  // The chains, wrappers and subshells around a redirect and a tee, with the home spelled `~` and `$HOME`.
  for (const [spell, spelled] of SPELLINGS.slice(0, 2)) {
    for (const [wrap, wrapper] of WRAPS) {
      for (const [write, make] of [WRITES[0], WRITES[3], WRITES[4], WRITES[12]]) add(`${t.id}/${spell}/${wrap}/${write}`, 'shell', bash(wrapper(make(spelled(t.rel)))));
    }
  }
  // cd into the folder, then a relative write (the brief's `cd ~/.marrow/runtime && mv x current`).
  const cd = `~/${t.dir}`;
  add(`${t.id}/cd-and-mv`, 'shell', bash(`cd ${cd} && mv x ${t.name}`));
  add(`${t.id}/cd-semicolon-redirect`, 'shell', bash(`cd ${cd}; printf x > ${t.name}`));
  add(`${t.id}/cd-and-dot-redirect`, 'shell', bash(`cd ${cd} && printf x > ./${t.name}`));
  add(`${t.id}/cd-or-cp`, 'shell', bash(`cd ${cd} || cp x ${t.name}`));
  add(`${t.id}/cd-subshell-mv`, 'shell', bash(`( cd ${cd} && mv x ${t.name} )`));
  add(`${t.id}/cd-bash-c-mv`, 'shell', bash(`bash -c 'cd ${cd} && mv x ${t.name}'`));
  add(`${t.id}/cd-tee`, 'shell', bash(`cd ${cd} && echo x | tee ${t.name}`));
  add(`${t.id}/var-then-redirect`, 'shell', bash(`x=~/${t.rel}; printf y > $x`));
  add(`${t.id}/env-prefix-redirect`, 'shell', bash(`env FOO=1 printf x > ~/${t.rel}`));
}
// A homoglyph segment INSIDE the real folder is still a file of Marrow's folder.
add('homoglyph/Write-current-cyrillic-c', 'tool', { tool_name: 'Write', tool_input: { file_path: `${ABS_HOME}/.marrow/runtime/сurrent`, content: 'x' } });
add('homoglyph/redirect-current-cyrillic-c', 'shell', bash('printf x > ~/.marrow/runtime/сurrent'));
add('homoglyph/redirect-launcher-cyrillic-a', 'shell', bash(`printf x > ~/.marrow/runtime/launcher/а${DIGEST.slice(1)}.cjs`));
add('homoglyph/redirect-record-cyrillic-i', 'shell', bash('printf x > ~/.marrow/іdentity-record.json'));
add('trailing-space/redirect-current', 'shell', bash('printf x > ~/.marrow/runtime/current\\ '));

// Reads stay not-S0 (no key sits in any of these files): `cat` of `current` is the row the brief names.
const READS = [];
for (const t of TARGETS) {
  for (const [spell, spelled] of SPELLINGS.slice(0, 2)) {
    for (const [read, make] of [['cat', (p) => `cat ${p}`], ['head', (p) => `head -c 100 ${p}`], ['sha256sum', (p) => `sha256sum ${p}`], ['stat', (p) => `stat ${p}`]]) {
      READS.push({ id: `${t.id}/${spell}/${read}`, event: bash(make(spelled(t.rel))) });
    }
  }
}
READS.push({ id: 'ls-runtime', event: bash('ls ~/.marrow/runtime') });

// A different folder whose name only looks like `.marrow` (a homoglyph or a case change on Linux): not Marrow's files, so BASE does
// not hold it and neither may this change (a pass here is BASE behavior; the real folder above stays held).
const FOREIGN = [
  { id: 'foreign/cyrillic-a-dir', event: bash('printf x > ~/.mаrrow/runtime/current') },
  { id: 'foreign/fullwidth-m-dir', event: bash('printf x > ~/.ｍarrow/runtime/current') },
  { id: 'foreign/upper-case-dir-linux', event: bash('printf x > ~/.MARROW/runtime/current') },
  { id: 'foreign/Write-cyrillic-a-dir', event: { tool_name: 'Write', tool_input: { file_path: `${ABS_HOME}/.mаrrow/runtime/current`, content: 'x' } } },
];

module.exports = { DIGEST, TARGETS, ROWS: rows, READS, FOREIGN, ABS_HOME };
