'use strict';

// Reads of the host-approvals state file (~/.marrow/host-approvals/state.json: holds, the secret that keys them, the no-device-key fallback key)
// get the decision a read of the device salt gets: keyless S4 stop, keyed protected action, outage hold. Names beside it (temp copy, backups) are
// the same file. Listing or stat of the folder, other state.json files and words that only mention it are unchanged. Dummy paths only.
const test = require('node:test');
const assert = require('node:assert/strict');

const { evaluateSeatbelt, evaluateSeatbeltShell } = require('../dist/seatbelt/mapper.js');
const { outageRisk } = require('../dist/seatbelt/hook.js');
const { classifyTool, outageHolds, mayReadApprovalState, mayPrintEnvironment } = require('../dist/hook-pre-action.js');
const { SECRET_PATTERNS, APPROVAL_STATE_PATH, APPROVAL_STATE_TREE, APPROVAL_STATE_REASON } = require('../dist/secret-paths.js');
const { makeEnv } = require('./support/seatbelt-fakes.cjs');

const HOME = '/home/u';
const STATE = { p: '~/.marrow/host-approvals/state.json', abs: `${HOME}/.marrow/host-approvals/state.json`, dir: '~/.marrow/host-approvals', file: 'state.json', base: 'host-approvals', g1: 'state.*', g2: 'st?te.json' };
const SALT = { p: '~/.marrow/seatbelt/salt', abs: `${HOME}/.marrow/seatbelt/salt`, dir: '~/.marrow/seatbelt', file: 'salt', base: 'seatbelt', g1: 'sal*', g2: 's?lt' };
const env = (t, extra = {}) => makeEnv({ files: { [t.abs]: 'x', ...(extra.files || {}) }, dirs: [`${HOME}/.marrow/${t.base}`], ...extra });
const keyless = (t, command, extra) => evaluateSeatbeltShell(command, env(t, extra));
const keyed = (event) => classifyTool(JSON.parse(JSON.stringify(event).split(HOME).join(process.env.HOME || HOME)));
const bash = (command) => ({ tool_name: 'Bash', tool_input: { command } });

// Forms with the state file named or spelled in the text: every one must stop keyless (S4), be a protected keyed action and be held in an outage.
const GATED = {
  cat: (t) => `cat ${t.p}`, head: (t) => `head -n 5 ${t.p}`, sed: (t) => `sed -n p ${t.p}`, awk: (t) => `awk 1 ${t.p}`, grep: (t) => `grep x ${t.p}`, rg: (t) => `rg x ${t.p}`,
  less: (t) => `less ${t.p}`, cp: (t) => `cp ${t.p} /tmp/x`, mv: (t) => `mv ${t.p} /tmp/x`, dd: (t) => `dd if=${t.p} of=/tmp/x`, install: (t) => `install ${t.p} /tmp/x`,
  tar: (t) => `tar cf /tmp/x.tar ${t.p}`, tarC: (t) => `tar -c -C ${t.dir} ${t.file} -f /tmp/x.tar`, zip: (t) => `zip /tmp/x.zip ${t.p}`, base64: (t) => `base64 ${t.p}`,
  xxd: (t) => `xxd ${t.p}`, od: (t) => `od -An -tx1 ${t.p}`, strings: (t) => `strings ${t.p}`, jq: (t) => `jq -r .secret ${t.p}`, sha: (t) => `sha256sum ${t.p}`,
  nodeE: (t) => `node -e "console.log(require('fs').readFileSync('${t.abs}','utf8'))"`, pythonC: (t) => `python3 -c "print(open('${t.abs}').read())"`,
  perlE: (t) => `perl -e 'open F,"${t.abs}";print <F>'`, rubyE: (t) => `ruby -e 'puts File.read("${t.abs}")'`,
  lt: (t) => `cat < ${t.p}`, hereSubst: (t) => `echo "$(< ${t.p})"`, execLt: (t) => `exec 3< ${t.p}; cat <&3`, procsub: (t) => `diff <(cat ${t.p}) /dev/null`,
  findExec: (t) => `find ${t.dir} -name '${t.file}' -exec cat {} \\;`, findMarrow: (t) => `find ~/.marrow -name ${t.file} -exec cat {} \\;`, xargs: (t) => `echo ${t.p} | xargs cat`,
  forLoop: (t) => `for f in ${t.p}; do cat $f; done`, grepRDir: (t) => `grep -r x ${t.dir}`, grepRMarrow: (t) => `grep -r x ~/.marrow`, rgMarrow: (t) => `rg x ~/.marrow`, grepRHome: (t) => `grep -r x ~`,
  catStar: (t) => `cat ${t.dir}/*`, tarDir: (t) => `tar cf /tmp/x.tar ${t.dir}`, cpRDir: (t) => `cp -r ${t.dir} /tmp/x`, dockerRun: (t) => `docker run --rm -v ${t.dir}:/d alpine cat /d/${t.file}`,
  bashC: (t) => `bash -c 'cat ${t.p}'`, shC: (t) => `sh -c "cat ${t.p}"`, eval: (t) => `eval 'cat ${t.p}'`, sudoSh: (t) => `sudo -n sh -c 'cat ${t.p}'`, envS: (t) => `env -S 'cat ${t.p}'`,
  ssh: (t) => `ssh localhost 'cat ${t.p}'`, nested: (t) => `bash -c "bash -c 'cat ${t.p}'"`, bashCcd: (t) => `bash -c 'cd ${t.dir} && cat ${t.file}'`, echoBash: (t) => `echo 'cat ${t.p}' | bash`,
  and: (t) => `true && cat ${t.p}`, or: (t) => `false || cat ${t.p}`, semi: (t) => `ls; cat ${t.p}`, pipe: (t) => `echo a | cat ${t.p}`, subshell: (t) => `(cat ${t.p})`, bg: (t) => `cat ${t.p} &`,
  flagsLast: (t) => `cat -n -n ${t.p}`, unknownFlag: (t) => `cat --frobnicate ${t.p}`, headNN: (t) => `head -n 1 -n 2 ${t.p}`,
  varSimple: (t) => `P=${t.p}; cat "$P"`, varDefault: (t) => `cat \${V:-${t.p}}`, homeVar: (t) => `cat $HOME/.marrow/${t.base}/${t.file}`, homeBrace: (t) => `cat \${HOME}/.marrow/${t.base}/${t.file}`,
  cdAnd: (t) => `cd ${t.dir} && cat ${t.file}`, cdDot: (t) => `cd ${t.dir}; cat ./${t.file}`, cdChain: (t) => `cd ~/.marrow && cd ${t.base} && cat ${t.file}`, cdUp: (t) => `cd ${t.dir}/.. && cat ${t.base}/${t.file}`,
  dotdot: (t) => `cat ~/.marrow/x/../${t.base}/${t.file}`, slashes: (t) => `cat ~/.marrow//${t.base}//${t.file}`, dotSeg: (t) => `cat ~/.marrow/./${t.base}/./${t.file}`, abs: (t) => `cat ${t.abs}`,
  globName: (t) => `cat ${t.dir}/${t.g1}`, globQ: (t) => `cat ${t.dir}/${t.g2}`, globDir: (t) => `cat ~/.marrow/*/${t.file}`, brace: (t) => `cat ~/.marrow/${t.base}/{${t.file},x}`,
  // names beside the file (the salt has none: its pattern is the file name only)
  bak: (t) => `cat ${t.p}.bak`, tmp: (t) => `cat ${t.dir}/.state-12345-0123456789abcdef.tmp`, lock: (t) => `cat ${t.dir}/.state.lock`, copy: (t) => `cat ${t.dir}/copy-of-${t.file}`,
};
const NAMES_BESIDE = new Set(['bak', 'tmp', 'lock', 'copy']);
const HELD_IN_OUTAGE = (command) => outageHolds(keyed(bash(command)).protected, () => outageRisk(bash(command), Date.now() + 5000));

test('every read form of the state file stops keyless (S4), is a protected keyed action and is held in an outage', () => {
  for (const [name, form] of Object.entries(GATED)) {
    const command = form(STATE);
    const d = keyless(STATE, command);
    assert.equal(d.decision, 'stop', `${name}: ${command}`);
    // A write (mv) or code naming ~/.marrow (node -e, python3 -c, ...) is S0 first; the S4 hit on the state file is there beside it.
    assert.ok(d.category === 'S4' || d.category === 'S0', `${name}: ${command}: ${d.category} ${d.reasons}`);
    // A bind mount of the folder is stopped as S0 (the mount), not by an S4 hit on a file operand.
    if (name !== 'dockerRun') assert.ok(d.hits.some((h) => h.category === 'S4'), `${name}: S4 hit`);
    const k = keyed(bash(command));
    assert.equal(k.protected, true, `keyed ${name}: ${command}`);
    assert.equal(k.readOnly, false, `keyed ${name}`);
    assert.equal(HELD_IN_OUTAGE(command), true, `outage ${name}: ${command}`);
  }
});

test('parity: each form is gated at least as strictly as the same form on the device salt, in every mode', () => {
  for (const [name, form] of Object.entries(GATED)) {
    if (NAMES_BESIDE.has(name)) continue;
    const salt = keyless(SALT, form(SALT));
    const state = keyless(STATE, form(STATE));
    if (salt.decision === 'stop') assert.equal(state.decision, 'stop', `keyless ${name}`);
    if (keyed(bash(form(SALT))).protected) assert.equal(keyed(bash(form(STATE))).protected, true, `keyed ${name}`);
    if (HELD_IN_OUTAGE(form(SALT))) assert.equal(HELD_IN_OUTAGE(form(STATE)), true, `outage ${name}`);
  }
});

test('direct and wrapper forms carry the reason the keyed hook keeps; walks over the folder, ~/.marrow and the home do too', () => {
  for (const name of ['cat', 'bashC', 'cdAnd', 'globName', 'globDir', 'grepRDir', 'grepRMarrow', 'grepRHome', 'findMarrow', 'abs', 'bak']) {
    assert.ok(keyless(STATE, GATED[name](STATE)).hits.some((h) => h.category === 'S4' && h.reason === APPROVAL_STATE_REASON), name);
  }
  for (const text of ['cat ~/.marrow/seatbelt/salt', 'cat ~/.marrow/seatbelt/state.json']) {
    assert.ok(!keyless(SALT, text).hits.some((h) => h.reason === APPROVAL_STATE_REASON), text);
  }
});

test('file tools: Read, Grep (a file, the folder, ~/.marrow, a glob that reaches it), Edit, Write and NotebookEdit', () => {
  const folder = `${HOME}/.marrow/host-approvals`;
  const gated = [
    ['Read', { file_path: STATE.abs }], ['Read', { file_path: STATE.p }], ['Read', { file_path: `${STATE.abs}.bak` }], ['Read', { file_path: `${folder}/.state-1-aa.tmp` }],
    ['Read', { file_path: `${HOME}/.marrow/x/../host-approvals/state.json` }], ['read_file', { path: STATE.abs }],
    ['Grep', { pattern: 'x', path: STATE.abs }], ['Grep', { pattern: '.', path: folder }], ['Grep', { pattern: '.', path: `${folder}/` }], ['Grep', { pattern: '.', path: '~/.marrow/host-approvals' }],
    ['Grep', { pattern: 'x', path: folder, glob: 'state.json' }], ['Grep', { pattern: 'x', path: `${HOME}/.marrow` }], ['Grep', { pattern: 'x', path: '~/.marrow' }],
    ['Grep', { pattern: 'x', path: HOME, glob: '.marrow/host-approvals/state.json' }], ['Grep', { pattern: 'x', glob: STATE.abs }],
    ['Edit', { file_path: STATE.abs, old_string: 'a', new_string: 'b' }], ['Write', { file_path: STATE.abs, content: 'x' }], ['NotebookEdit', { notebook_path: STATE.abs, new_source: 'x' }],
  ];
  for (const [tool_name, tool_input] of gated) {
    const label = `${tool_name} ${JSON.stringify(tool_input)}`;
    const d = evaluateSeatbelt({ tool_name, tool_input }, env(STATE));
    assert.equal(d.decision, 'stop', `keyless ${label}`);
    const k = keyed({ tool_name, tool_input });
    assert.equal(k.protected, true, `keyed ${label}`);
    assert.equal(k.readOnly, false, `keyed ${label}`);
    const reading = outageRisk({ tool_name, tool_input }, Date.now() + 5000);
    assert.ok(outageHolds(k.protected, () => reading), `outage ${label}`);
  }
});

test('unchanged: listing or stat of the folder, other state.json files, other ~/.marrow files, and words that only mention it', () => {
  const pass = [
    'ls ~/.marrow/host-approvals', 'ls -la ~/.marrow/host-approvals', 'ls ~/.marrow/host-approvals/', 'stat ~/.marrow/host-approvals', '[ -d ~/.marrow/host-approvals ] && echo yes',
    'cd ~/.marrow/host-approvals && ls', 'cd ~/.marrow/host-approvals && pwd', 'ls ~/.marrow', 'cat README.md', 'git status', 'npm test', 'git log --oneline -5', 'mkdir -p build/out',
    'cat state.json', 'cat src/state.json', 'cat /home/u/proj/state.json', 'cat /home/u/proj/host-approvals/state.json', 'cat docs/host-approvals.md', 'cat docs/host-approvals/state.json',
    'cat ~/.marrow/seatbelt/state.json', 'cat ~/.marrow/session-loop-guard/state.json', 'cat ~/.marrow/control.json', 'cat ~/.marrow/spool/x.json',
    'echo host-approvals', 'echo ~/.marrow/host-approvals/state.json', 'grep -rn host-approvals docs/', 'grep -n "host-approvals" src/*.ts', 'grep -rn "host-approvals/state.json" src',
    'git log -- src/host-approval-state.ts', 'git diff --stat', 'rg -n state.json src', 'find . -name state.json', 'find src -name "state*.json"',
    'grep -rn foo src', 'grep -r foo .',
  ];
  const files = { '/home/u/proj/state.json': '{}', '/home/u/proj/src/state.json': '{}', '/home/u/proj/host-approvals/state.json': '{}', '/home/u/proj/docs/host-approvals.md': 'x',
    '/home/u/proj/docs/host-approvals/state.json': 'x', '/home/u/.marrow/seatbelt/state.json': '{}', '/home/u/.marrow/session-loop-guard/state.json': '{}', '/home/u/.marrow/control.json': '{}',
    '/home/u/.marrow/spool/x.json': '{}' };
  for (const command of pass) {
    assert.equal(keyless(STATE, command, { files }).decision, 'pass', `keyless ${command}`);
    assert.equal(keyed(bash(command)).protected, false, `keyed ${command}`);
  }
  for (const [tool_name, tool_input] of [['Read', { file_path: `${HOME}/.marrow/host-approvals` }], ['Glob', { pattern: `${HOME}/.marrow/host-approvals/*` }], ['Read', { file_path: '/home/u/proj/state.json' }],
    ['Read', { file_path: '/home/u/.marrow/seatbelt/state.json' }], ['Grep', { pattern: 'host-approvals', path: '/home/u/proj/src' }], ['Grep', { pattern: 'x', glob: 'state.json', path: '/home/u/proj' }]]) {
    assert.equal(evaluateSeatbelt({ tool_name, tool_input }, env(STATE, { files })).decision, 'pass', `keyless ${tool_name}`);
    assert.equal(keyed({ tool_name, tool_input }).protected, false, `keyed ${tool_name} ${JSON.stringify(tool_input)}`);
  }
});

test('the pattern table lists the folder children, not the folder; the keyed path match is case-insensitive; a case-folding host folds in the mapper', () => {
  assert.ok(SECRET_PATTERNS.includes('**/.marrow/host-approvals/*'));
  assert.ok(APPROVAL_STATE_PATH.test('/home/u/.marrow/host-approvals/state.json') && APPROVAL_STATE_PATH.test('/Users/u/.MARROW/Host-Approvals/State.JSON'));
  assert.ok(!APPROVAL_STATE_PATH.test('/home/u/.marrow/host-approvals') && !APPROVAL_STATE_PATH.test('/home/u/.marrow/host-approvals/') && !APPROVAL_STATE_PATH.test('/home/u/.marrow/seatbelt/state.json'));
  assert.equal(keyed(bash('cat ~/.MARROW/Host-Approvals/State.json')).protected, true);
  const mac = makeEnv({ platform: 'darwin', files: { [STATE.abs]: 'x' }, dirs: [`${HOME}/.marrow/host-approvals`] });
  assert.equal(evaluateSeatbeltShell('cat ~/.MARROW/Host-Approvals/State.json', mac).decision, 'stop');
});

test('the keyed hook asks the mapper only for a command that can reach the file: ordinary commands never load it', () => {
  for (const command of ['git status', 'npm test', 'ls', 'cat README.md', 'grep -rn foo src', 'grep -r foo .', 'rg -n state.json src', 'find . -name "*.ts"', 'ls ~/.cache', 'cat ~/notes.txt', 'tar cf /tmp/x.tar src']) {
    assert.equal(mayReadApprovalState(command) || mayPrintEnvironment(command), false, command);
  }
  for (const command of ['cat ~/.marrow/host-approvals/state.json', 'bash -c "cat ~/.marrow/h*/s*"', 'cat ~/.marrow/*/state.json', "cat $'~/.marrow'", 'grep -r x ~', 'rg x /', 'find ~/.marrow -type f', 'cat "$HOME/.marrow/$A/state.json"', 'cd ~/.marrow; cat h*/s*']) {
    assert.equal(mayReadApprovalState(command), true, command);
  }
});

test('keyed: `cd <folder>; cat ~+/state.json` is read as the salt form is (the hook never expands ~+, so the path is <folder>/~+/state.json); the folder itself stays open', () => {
  const forms = (t) => [`cd ${t.dir}; cat ~+/${t.file}`, `cd ${t.dir} && head -n 1 ~+/${t.file}`, `cd ${t.dir}; grep x ~+/${t.file}`, `cd ${t.dir}; cp ~+/${t.file} /tmp/x`];
  for (const [salt, state] of forms(SALT).map((s, i) => [s, forms(STATE)[i]])) {
    assert.equal(keyed(bash(salt)).protected, true, salt);
    assert.equal(keyed(bash(state)).protected, true, state);
  }
  assert.ok(APPROVAL_STATE_TREE.test('/home/u/.marrow/host-approvals/state.json') && APPROVAL_STATE_TREE.test('/home/u/.marrow/host-approvals/~+/state.json'));
  assert.ok(!APPROVAL_STATE_TREE.test('/home/u/.marrow/host-approvals') && !APPROVAL_STATE_TREE.test('/home/u/.marrow/seatbelt/state.json') && !APPROVAL_STATE_TREE.test('/home/u/proj/host-approvals/state.json'));
  for (const command of ['cd ~/.marrow/host-approvals; ls ~+', 'cd ~/.marrow/host-approvals; pwd', 'cd ~/.marrow/host-approvals && ls -la']) assert.equal(keyed(bash(command)).protected, false, command);
});
