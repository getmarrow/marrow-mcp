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
const DIRS = ['/home/u/.claude', '/home/u/.claude/plugins/cache/getmarrow/marrow', '/home/u/.npm/_npx/abc123/node_modules/@getmarrow', '/home/u/.codex'];

// The three S0 targets: a file and a folder that holds it. {A} is the file's absolute path (for awk program text).
const TARGETS = [
  { name: 'settings', T: '~/.claude/settings.json', D: '~/.claude', A: '/home/u/.claude/settings.json' },
  { name: 'plugins', T: '~/.claude/plugins/cache/getmarrow/marrow/1.2.3/scripts/marrow-launch.cjs', D: '~/.claude/plugins/cache/getmarrow/marrow', A: '/home/u/.claude/plugins/cache/getmarrow/marrow/1.2.3/scripts/marrow-launch.cjs' },
  { name: 'npx copy', T: '~/.npm/_npx/abc123/node_modules/@getmarrow/mcp/dist/cli.js', D: '~/.npm/_npx/abc123/node_modules/@getmarrow', A: '/home/u/.npm/_npx/abc123/node_modules/@getmarrow/mcp/dist/cli.js' },
];
const fill = (cmd, t, home) => cmd.replace(/\{T\}/g, t.T).replace(/\{D\}/g, t.D).replace(/\{A\}/g, home ? t.A.replace('/home/u', home) : t.A);

// ------------------------------------------------------------------------------------------------
// The fixed table. exact: the option spelled in full (the answer it had before this round); short: the option cut to
// its first 4 letters; unk: a made-up `--zz-unknown`. Both of the last two must stop (S0).
// `reasons` names a reason code the strict row must carry (the parser under test stopped it, not another rule).
const PARSERS = [
  // cpDestination
  { parser: 'cpDestination (source read)', exact: ['cp --reflink=auto {T} /tmp/p3-dst', 'pass'], short: 'cp --refl=auto {T} /tmp/p3-dst', unk: 'cp --zz-unknown {T} /tmp/p3-dst' },
  { parser: 'cpDestination (--target-directory)', exact: ['cp --target-directory={D} /tmp/p3-x', 'stop'], short: 'cp --targ={D} /tmp/p3-x', unk: 'cp --zz-unknown {D} /tmp/p3-x' },
  { parser: 'cpDestination (link copy)', exact: ['cp --link {T} /tmp/p3-l', 'stop'], short: 'cp --li {T} /tmp/p3-l', unk: 'cp --zz-unknown {T} /tmp/p3-l' },
  { parser: 'cpDestination (value word last)', exact: ['cp {T} /tmp/p3-dst --sparse always', 'pass'], short: 'cp /tmp/p3-x {T} --spar always', unk: 'cp /tmp/p3-x {T} --zz-unknown always' },
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
  { parser: 'git index-only (restore)', exact: ['git restore --staged {T}', 'pass'], short: 'git restore --staged --work {T}', unk: 'git restore --staged --zz-unknown {T}' },
  { parser: 'git index-only (rm)', exact: ['git rm --cached {T}', 'pass'], short: 'git rm --cach {T}', unk: 'git rm --cached --zz-unknown {T}' },
  { parser: 'git grep pager command', exact: ['git grep --open-files-in-pager="rm {T}" foo', 'stop'], short: 'git grep --open-f="rm {T}" foo', unk: 'git grep --zz-unknown="rm {T}" foo' },
  // tar option reader (commands the options run)
  { parser: 'tar --to-command', exact: ['tar -xf /tmp/p3.tar --to-command="rm {T}"', 'stop'], short: 'tar -xf /tmp/p3.tar --to-comm="rm {T}"', unk: 'tar -xf /tmp/p3.tar --zz-unknown="rm {T}"' },
  { parser: 'tar --create (inputs are reads)', exact: ['tar --create --file=/tmp/p3-out.tar {T}', 'pass'], short: 'tar --crea --file=/tmp/p3-out.tar {T}', unk: 'tar --create --zz-unknown --file=/tmp/p3-out.tar {T}' },
];

module.exports = { HOOKS, FILES, DIRS, TARGETS, fill, PARSERS };
