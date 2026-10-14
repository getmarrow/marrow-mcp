'use strict';

// The fixed table of the long-option round (patch round 3), shared by test/seatbelt-long-options.test.js (mapper rows)
// and test/seatbelt-long-options-hook.test.js (the real hook CLI on the 7 host paths).

const HOOKS = { PreToolUse: [{ matcher: '*', hooks: [{ type: 'command', command: 'npx -y --package=@getmarrow/mcp@3.9.103 marrow-mcp claude-pre-action-hook' }] }] };
const FILES = {
  '/home/u/.claude/settings.json': JSON.stringify({ hooks: HOOKS }, null, 2),
  '/home/u/.claude/plugins/installed_plugins.json': '{"version":2,"plugins":{}}',
  '/home/u/.claude/plugins/cache/getmarrow/marrow/1.2.3/scripts/marrow-launch.cjs': 'module.exports = 1;\n',
  '/home/u/.npm/_npx/abc123/node_modules/@getmarrow/mcp/dist/cli.js': 'module.exports = 1;\n',
  '/home/u/.codex/hooks.json': JSON.stringify({ hooks: HOOKS }, null, 2),
  '/home/u/.bashrc': '# rc\n',
};
const DIRS = ['/home/u/.claude', '/home/u/.claude/plugins', '/home/u/.claude/plugins/cache/getmarrow', '/home/u/.claude/plugins/cache/getmarrow/marrow', '/home/u/.claude/plugins/cache/getmarrow/marrow/1.2.3/scripts',
  '/home/u/.npm/_npx/abc123/node_modules', '/home/u/.npm/_npx/abc123/node_modules/@getmarrow', '/home/u/.npm/_npx/abc123/node_modules/@getmarrow/mcp/dist', '/home/u/.codex'];

// The three S0 targets: a file and a folder that holds it. {A} is the file's absolute path (for awk program text).
// Patch round 4 (relative destinations): {P} is a folder to work in (`cd {P}` or the folder an env / sudo / doas chdir option
// names, with a literal `~` or an absolute path), {R} a relative name of a protected folder inside it (an attached `-t{R}`
// value) and {F} a relative name of the protected file inside {PA}, the same folder as an absolute path.
// Patch round 5: {PN} is a protected folder as an absolute path and {N} a relative name inside it that some protected path ends with
// (the operand of a program that is no writer, e.g. `vim {N}`).
const TARGETS = [
  { name: 'settings', T: '~/.claude/settings.json', D: '~/.claude', A: '/home/u/.claude/settings.json', P: '~/.claude', PA: '/home/u/.claude', R: 'plugins', F: 'settings.json', PN: '/home/u/.claude', N: 'plugins/installed_plugins.json' },
  { name: 'plugins', T: '~/.claude/plugins/cache/getmarrow/marrow/1.2.3/scripts/marrow-launch.cjs', D: '~/.claude/plugins/cache/getmarrow/marrow', A: '/home/u/.claude/plugins/cache/getmarrow/marrow/1.2.3/scripts/marrow-launch.cjs',
    P: '~/.claude/plugins/cache/getmarrow', PA: '/home/u/.claude/plugins/cache/getmarrow/marrow/1.2.3/scripts', R: 'marrow', F: 'marrow-launch.cjs', PN: '/home/u/.claude/plugins/cache/getmarrow', N: 'marrow/1.2.3/scripts/marrow-launch.cjs' },
  { name: 'npx copy', T: '~/.npm/_npx/abc123/node_modules/@getmarrow/mcp/dist/cli.js', D: '~/.npm/_npx/abc123/node_modules/@getmarrow', A: '/home/u/.npm/_npx/abc123/node_modules/@getmarrow/mcp/dist/cli.js',
    P: '~/.npm/_npx/abc123/node_modules', PA: '/home/u/.npm/_npx/abc123/node_modules/@getmarrow/mcp/dist', R: '@getmarrow', F: 'cli.js', PN: '/home/u/.npm/_npx/abc123/node_modules', N: '@getmarrow/mcp/dist/cli.js' },
];
const fill = (cmd, t, home) => {
  const h = (x) => (home ? x.replace('/home/u', home) : x);
  return cmd.replace(/\{T\}/g, t.T).replace(/\{D\}/g, t.D).replace(/\{A\}/g, h(t.A)).replace(/\{PN\}/g, h(t.PN)).replace(/\{N\}/g, t.N).replace(/\{PA\}/g, h(t.PA)).replace(/\{P\}/g, t.P).replace(/\{R\}/g, t.R).replace(/\{F\}/g, t.F);
};

// ------------------------------------------------------------------------------------------------
// The fixed table. exact: the option spelled in full (the answer it had before this round); short: the option cut to
// its first 4 letters; unk: a made-up `--zz-unknown`. Both of the last two must stop (S0).
// `reasons` names a reason code the strict row must carry (the parser under test stopped it, not another rule).
const PARSERS = [
  // cpDestination
  { parser: 'cpDestination (source read)', exact: ['cp --reflink=auto {T} /tmp/p3-dst', 'pass'], short: 'cp --refl=auto {T} /tmp/p3-dst', unk: 'cp --zz-unknown {T} /tmp/p3-dst', reasons: ['cp_write_protected', 'protected_path_operand'] },
  { parser: 'cpDestination (--target-directory)', exact: ['cp --target-directory={D} /tmp/p3-x', 'stop'], short: 'cp --targ={D} /tmp/p3-x', unk: 'cp --zz-unknown {D} /tmp/p3-x', reasons: ['cp_write_protected', 'protected_path_operand'] },
  { parser: 'cpDestination (link copy)', exact: ['cp --link {T} /tmp/p3-l', 'stop'], short: 'cp --li {T} /tmp/p3-l', unk: 'cp --zz-unknown {T} /tmp/p3-l', reasons: ['cp_write_protected', 'protected_path_operand'] },
  { parser: 'cpDestination (value word last)', exact: ['cp {T} /tmp/p3-dst --sparse always', 'pass'], short: 'cp /tmp/p3-x {T} --spar always', unk: 'cp /tmp/p3-x {T} --zz-unknown always', reasons: ['protected_path_operand'] },
  // modelled writers (writeTargets / targetDirFlag)
  { parser: 'writeTargets mv', exact: ['mv --target-directory={D} /tmp/p3-x', 'stop'], short: 'mv --targ={D} /tmp/p3-x', unk: 'mv --zz-unknown={D} /tmp/p3-x', reasons: 'mv_write_protected' },
  { parser: 'writeTargets install', exact: ['install --target-directory={D} /tmp/p3-x', 'stop'], short: 'install --targ={D} /tmp/p3-x', unk: 'install --zz-unknown={D} /tmp/p3-x', reasons: 'install_write_protected' },
  { parser: 'writeTargets ln', exact: ['ln --target-directory={D} /tmp/p3-x', 'stop'], short: 'ln --targ={D} /tmp/p3-x', unk: 'ln --zz-unknown={D} /tmp/p3-x', reasons: 'ln_write_protected' },
  { parser: 'writeTargets tar -C', exact: ['tar --extract --directory={D} -f /tmp/p3.tar', 'stop'], short: 'tar --extract --dire={D} -f /tmp/p3.tar', unk: 'tar --extract --zz-unknown={D} -f /tmp/p3.tar', reasons: 'tar_write_protected' },
  { parser: 'writeTargets sed -i', exact: ['sed --in-place=.bak s/a/b/ {T}', 'stop'], short: 'sed --in-p=.bak s/a/b/ {T}', unk: 'sed --zz-unknown s/a/b/ {T}', reasons: 'sed_write_protected' },
  { parser: 'writeTargets curl', exact: ['curl --output {T} https://example.test/x', 'stop'], short: 'curl --outp {T} https://example.test/x', unk: 'curl --zz-unknown {T} https://example.test/x', reasons: 'curl_write_protected' },
  { parser: 'writeTargets wget', exact: ['wget --output-document={T} https://example.test/x', 'stop'], short: 'wget --outp={T} https://example.test/x', unk: 'wget --zz-unknown={T} https://example.test/x', reasons: 'wget_write_protected' },
  { parser: 'writeTargets rsync', exact: ['rsync --archive /tmp/p3-s/ {D}/', 'stop'], short: 'rsync --arch /tmp/p3-s/ {D}/', unk: 'rsync --zz-unknown /tmp/p3-s/ {D}/', reasons: 'rsync_write_protected' },
  // reader exclusions (operandRuleApplies): a reader keeps passing; a long option it does not list makes it no reader
  { parser: 'reader cat', exact: ['cat --number {T}', 'pass'], short: 'cat --numb {T}', unk: 'cat --zz-unknown {T}' },
  { parser: 'reader grep', exact: ['grep --line-number x {T}', 'pass'], short: 'grep --line x {T}', unk: 'grep --zz-unknown x {T}' },
  { parser: 'reader rg', exact: ['rg --hidden x {T}', 'pass'], short: 'rg --hidd x {T}', unk: 'rg --zz-unknown x {T}' },
  { parser: 'reader jq', exact: ['jq --compact-output . {T}', 'pass'], short: 'jq --comp . {T}', unk: 'jq --zz-unknown . {T}' },
  { parser: 'reader yq', exact: ['yq --output-format=json . {T}', 'pass'], short: 'yq --outp=json . {T}', unk: 'yq --zz-unknown . {T}' },
  { parser: 'reader bat', exact: ['bat --paging=never {T}', 'pass'], short: 'bat --pagi=never {T}', unk: 'bat --zz-unknown {T}' },
  { parser: 'reader less', exact: ['less --quiet {T}', 'pass'], short: 'less --quie {T}', unk: 'less --zz-unknown {T}' },
  { parser: 'reader more', exact: ['more --silent {T}', 'pass'], short: 'more --sile {T}', unk: 'more --zz-unknown {T}' },
  { parser: 'reader head', exact: ['head --lines=5 {T}', 'pass'], short: 'head --line=5 {T}', unk: 'head --zz-unknown {T}' },
  { parser: 'reader tail', exact: ['tail --lines=5 {T}', 'pass'], short: 'tail --line=5 {T}', unk: 'tail --zz-unknown {T}' },
  { parser: 'reader wc', exact: ['wc --lines {T}', 'pass'], short: 'wc --line {T}', unk: 'wc --zz-unknown {T}' },
  { parser: 'reader ls', exact: ['ls --almost-all {T}', 'pass'], short: 'ls --almo {T}', unk: 'ls --zz-unknown {T}' },
  { parser: 'reader du', exact: ['du --human-readable {T}', 'pass'], short: 'du --huma {T}', unk: 'du --zz-unknown {T}' },
  { parser: 'reader stat', exact: ['stat --terse {T}', 'pass'], short: 'stat --ters {T}', unk: 'stat --zz-unknown {T}' },
  { parser: 'reader diff', exact: ['diff --brief {T} /tmp/p3-x', 'pass'], short: 'diff --brie {T} /tmp/p3-x', unk: 'diff --zz-unknown {T} /tmp/p3-x' },
  { parser: 'reader cmp', exact: ['cmp --silent {T} /tmp/p3-x', 'pass'], short: 'cmp --sile {T} /tmp/p3-x', unk: 'cmp --zz-unknown {T} /tmp/p3-x' },
  { parser: 'reader file', exact: ['file --brief {T}', 'pass'], short: 'file --brie {T}', unk: 'file --zz-unknown {T}' },
  { parser: 'reader sha256sum', exact: ['sha256sum --binary {T}', 'pass'], short: 'sha256sum --bina {T}', unk: 'sha256sum --zz-unknown {T}' },
  { parser: 'reader tree', exact: ['tree --noreport {D}', 'pass'], short: 'tree --nore {D}', unk: 'tree --zz-unknown {D}' },
  { parser: 'reader prettier', exact: ['prettier --check {T}', 'pass'], short: 'prettier --chec {T}', unk: 'prettier --zz-unknown {T}' },
  // sedReadOnly, awkReadOnly, find
  { parser: 'sedReadOnly', exact: ['sed --quiet 1p {T}', 'pass'], short: 'sed --quie 1p {T}', unk: 'sed --zz-unknown 1p {T}' },
  { parser: 'awkReadOnly', exact: ["awk --field-separator=: '{print $1}' {T}", 'pass'], short: "awk --fiel=: '{print $1}' {T}", unk: "awk --zz-unknown '{print $1}' {T}" },
  { parser: 'find (read)', exact: ['find {T} -name x', 'pass'], short: 'find {T} -nam x', unk: 'find {T} --zz-unknown' },
  { parser: 'find (-delete)', exact: ['find {D} -delete', 'stop'], short: 'find {D} -dele', unk: 'find {D} --zz-unknown' },
  // git read-only and index-only checks
  { parser: 'git read-only (diff)', exact: ['git diff --stat {T}', 'pass'], short: 'git diff --sta {T}', unk: 'git diff --zz-unknown {T}' },
  { parser: 'git read-only (log)', exact: ['git log --oneline -- {T}', 'pass'], short: 'git log --onel -- {T}', unk: 'git log --zz-unknown -- {T}' },
  { parser: 'git read-only (--output)', exact: ['git diff --output=/tmp/p3-out.patch {T}', 'pass'], short: 'git diff --outp={T}', unk: 'git diff --zz-unknown={T}' },
  { parser: 'git index-only (reset)', exact: ['git reset --mixed -- {T}', 'pass'], short: 'git reset --har -- {T}', unk: 'git reset --zz-unknown -- {T}' },
  { parser: 'git index-only (restore)', exact: ['git restore --staged {T}', 'pass'], short: 'git restore --staged --work {T}', unk: 'git restore --staged --zz-unknown {T}', reasons: ['git_restore_protected_path', 'protected_path_operand'] },
  { parser: 'git index-only (rm)', exact: ['git rm --cached {T}', 'pass'], short: 'git rm --cach {T}', unk: 'git rm --cached --zz-unknown {T}' },
  { parser: 'git grep pager command', exact: ['git grep --open-files-in-pager="rm {T}" foo', 'stop'], short: 'git grep --open-f="rm {T}" foo', unk: 'git grep --zz-unknown="rm {T}" foo' },
  // Patch round 4 (P3-F1): the attached value of a single-letter option is a destination whatever its first character
  { parser: 'attached -t value (cp)', exact: ['cd {P} && cp --reflink=auto -t{R} /tmp/p4-x', 'stop'], short: 'cd {P} && cp --refl=auto -t{R} /tmp/p4-x', unk: 'cd {P} && cp --zz-unknown -t{R} /tmp/p4-x', reasons: ['cp_write_protected', 'protected_path_operand'] },
  { parser: 'attached -t value (cp, short cluster)', exact: ['cd {P} && cp --reflink=auto -rt{R} /tmp/p4-x', 'stop'], short: 'cd {P} && cp --refl=auto -rt{R} /tmp/p4-x', unk: 'cd {P} && cp --zz-unknown -rt{R} /tmp/p4-x', reasons: ['protected_path_operand'] },
  { parser: 'attached -t value (mv)', exact: ['cd {P} && mv -t{R} /tmp/p4-x', 'stop'], short: 'cd {P} && mv --verb -t{R} /tmp/p4-x', unk: 'cd {P} && mv --zz-unknown -t{R} /tmp/p4-x', reasons: ['protected_path_operand'] },
  { parser: 'attached -t value (install)', exact: ['cd {P} && install -t{R} /tmp/p4-x', 'stop'], short: 'cd {P} && install --verb -t{R} /tmp/p4-x', unk: 'cd {P} && install --zz-unknown -t{R} /tmp/p4-x', reasons: ['protected_path_operand'] },
  // Patch round 4 (P3-F2): zip reads a documented multi-letter option by its meaning (-TT runs a command, -lf writes a log file)
  { parser: 'zip -TT (command)', exact: ['zip /tmp/p4.zip /tmp/p4-in -T -TT "rm {T}"', 'stop'], short: 'zip /tmp/p4.zip /tmp/p4-in -T --unzi="rm {T}"', unk: 'zip /tmp/p4.zip /tmp/p4-in -T --zz-unknown="rm {T}"', reasons: 'protected_path_operand' },
  { parser: 'zip --unzip-command', exact: ['zip /tmp/p4.zip /tmp/p4-in -T --unzip-command="rm {T}"', 'stop'], short: 'zip /tmp/p4.zip /tmp/p4-in -T --unzip-comm="rm {T}"', unk: 'zip /tmp/p4.zip /tmp/p4-in -T --zz-unknown "rm {T}"', reasons: 'rm_write_protected' },
  { parser: 'zip -TT in a cluster', exact: ['zip /tmp/p4.zip /tmp/p4-in -rTT "rm {T}"', 'stop'], short: 'zip /tmp/p4.zip /tmp/p4-in -r --unzi="rm {T}"', unk: 'zip /tmp/p4.zip /tmp/p4-in -r --zz-unknown="rm {T}"', reasons: 'rm_write_protected' },
  { parser: 'zip -lf (log file)', exact: ['zip /tmp/p4.zip /tmp/p4-in -lf {T}', 'stop'], short: 'zip /tmp/p4.zip /tmp/p4-in --logf {T}', unk: 'zip /tmp/p4.zip /tmp/p4-in --zz-unknown {T}', reasons: 'protected_path_operand' },
  { parser: 'zip multi-letter flags read', exact: ['zip -rq /tmp/p4.zip {D}', 'pass'], short: 'zip -rq /tmp/p4.zip {D} --recurse-pat', unk: 'zip -rq /tmp/p4.zip {D} --zz-unknown' },
  // Patch round 4 (Residual 1): env / sudo / doas and the working folder of the command they run. A relative write destination
  // under an unknown folder is a possible write to the protected file named {F} inside {PA}.
  { parser: 'env --chdir (relative write)', exact: ['env --chdir={PA} cp /tmp/p4-x {F}', 'stop'], short: 'env --chdi={PA} cp /tmp/p4-x {F}', unk: 'env --zz-unknown={PA} cp /tmp/p4-x {F}', reasons: 'cp_write_protected' },
  { parser: 'sudo --chdir (relative write)', exact: ['sudo --chdir={PA} cp /tmp/p4-x {F}', 'stop'], short: 'sudo --chdi={PA} cp /tmp/p4-x {F}', unk: 'sudo --zz-unknown cp /tmp/p4-x {F}', reasons: 'cp_write_protected' },
  { parser: 'doas (relative write)', exact: ['doas --chdir={PA} cp /tmp/p4-x {F}', 'stop'], short: 'doas --chdi={PA} cp /tmp/p4-x {F}', unk: 'doas --zz-unknown cp /tmp/p4-x {F}', reasons: 'cp_write_protected' },
  { parser: 'env -C value unreadable', exact: ['env -C {PA} cp /tmp/p4-x {F}', 'stop'], short: 'env -C "$D" cp /tmp/p4-x {F}', unk: 'env --chdir "$D" cp /tmp/p4-x {F}', reasons: 'cp_write_protected' },
  { parser: 'sudo -D value unreadable', exact: ['sudo -D {PA} cp /tmp/p4-x {F}', 'stop'], short: 'sudo -D "$D" cp /tmp/p4-x {F}', unk: 'sudo --chdir "$D" cp /tmp/p4-x {F}', reasons: 'cp_write_protected' },
  // Patch round 5 (R4-F2): the same working-folder options with a program that is no writer (an editor, an interpreter). Under an
  // unknown folder a relative operand that a protected path ends with stops (S0, protected_path_operand); a known folder resolves it.
  { parser: 'env --chdir (editor operand)', exact: ['env --chdir={PN} vim {N}', 'stop'], short: 'env --chdi={PN} vim {N}', unk: 'env --zz-unknown={PN} vim {N}', reasons: 'protected_path_operand' },
  { parser: 'sudo --chdir (editor operand)', exact: ['sudo --chdir={PN} vim {N}', 'stop'], short: 'sudo --chdi={PN} vim {N}', unk: 'sudo --zz-unknown vim {N}', reasons: 'protected_path_operand' },
  { parser: 'doas (editor operand)', exact: ['doas --chdir={PN} vim {N}', 'stop'], short: 'doas --chdi={PN} vim {N}', unk: 'doas --zz-unknown vim {N}', reasons: 'protected_path_operand' },
  { parser: 'env -C value unreadable (interpreter operand)', exact: ['env -C {PN} node tool.js {N}', 'stop'], short: 'env -C "$D" node tool.js {N}', unk: 'env --chdir "$D" node tool.js {N}', reasons: 'protected_path_operand' },
  { parser: 'sudo -D value unreadable (interpreter operand)', exact: ['sudo -D {PN} python3 tool.py {N}', 'stop'], short: 'sudo -D "$D" python3 tool.py {N}', unk: 'sudo --chdir "$D" python3 tool.py {N}', reasons: 'protected_path_operand' },
  // Patch round 5 (R4-L1): a -TT after a letter the zip scan cannot read (-m moves the inputs) still takes a command
  { parser: 'zip -TT after an unread letter', exact: ['zip /tmp/p5.zip /tmp/p5-in -T -mTT "rm {T}"', 'stop'], short: 'zip /tmp/p5.zip /tmp/p5-in -T -mTT"rm {T}"', unk: 'zip /tmp/p5.zip /tmp/p5-in -T -mTT="rm {T}"', reasons: 'rm_write_protected' },
  // tar option reader (commands the options run)
  { parser: 'tar --to-command', exact: ['tar -xf /tmp/p3.tar --to-command="rm {T}"', 'stop'], short: 'tar -xf /tmp/p3.tar --to-comm="rm {T}"', unk: 'tar -xf /tmp/p3.tar --zz-unknown="rm {T}"' },
  { parser: 'tar --create (inputs are reads)', exact: ['tar --create --file=/tmp/p3-out.tar {T}', 'pass'], short: 'tar --crea --file=/tmp/p3-out.tar {T}', unk: 'tar --create --zz-unknown --file=/tmp/p3-out.tar {T}' },
];

module.exports = { HOOKS, FILES, DIRS, TARGETS, fill, PARSERS };
