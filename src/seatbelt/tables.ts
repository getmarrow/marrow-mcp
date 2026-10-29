// Seatbelt rule tables (spec SEATBELT-SPEC.md §1.2 as amended by the owner decisions of 2026-10-12).
// Compiled into the package on purpose: no local file can extend or relax them (spec §2.1.7).

export const SEATBELT_RULES_VERSION = 'marrow.seatbelt.rules.v1';

// Budgets. A command that exceeds ANY budget stops (never passes): padding, deep nesting, wide
// fan-out and slow repositories must not turn into "pass" (audit F3, F10).
export const LIMITS = Object.freeze({
  // The vendored parser's own limits (vendor/classifier/shell-parse.js MAX_SOURCE_BYTES / MAX_COMMANDS).
  maxCommandBytes: 64 * 1024,
  maxSegments: 256,
  maxDepth: 6,
  maxScriptBytes: 64 * 1024,
  // WK-5: the largest patch file the mapper reads for `patch`, `git apply` and `git am`; a bigger one is an unknown write.
  maxPatchBytes: 1024 * 1024,
  maxPackageJsonBytes: 256 * 1024,
  maxConfigBytes: 1024 * 1024,
  maxAliasExpansions: 5,
  // Work per classification: evaluated commands and shell texts (deterministic), script expansions
  // (package scripts, make targets, script files), and a wall-clock ceiling well under hook timeouts.
  maxWork: 4000,
  maxScriptExpansions: 150,
  maxVariants: 16,
  timeBudgetMs: 300,
  maxGlobMatches: 256,
  maxToolNodes: 200000,
  maxToolDepth: 12,
  maxTailTrials: 64,
  maxPathChars: 4096,
  // N6: a command, or an expanded argv, with more words than this stops (the per-word checks do file
  // system calls, so the count is the deterministic bound on one command's cost). A brace word longer
  // than maxBraceChars is not expanded (unresolved = stop). maxParseCost bounds the estimated work of
  // the vendored parser's `${` handling, which is quadratic on a run of unterminated `${`.
  maxToolJsonChars: 1024 * 1024,
  maxWords: 1024,
  maxBraceChars: 1024,
  maxParseCost: 24_000_000,
  // A3 (Windows hotfix): nested PowerShell / cmd texts (pwsh -c, cmd /c, iex, Start-Process, decoded
  // -EncodedCommand) stop beyond this many levels, and a base64 -EncodedCommand value longer than this many
  // characters is not decoded: it stops as unreadable. 32767 is the longest command line Windows can start.
  maxPsDepth: 4,
  maxEncodedChars: 32_767,
});

// S4 secret paths: one table with the keyed policy (src/secret-paths.ts).
export { PRESENT_SECRET_PATTERNS, SECRET_PATTERNS } from '../secret-paths';
// Key material by extension, except under node_modules or test fixture folders.
export const KEY_EXTENSIONS = /\.(?:pem|key|p12|pfx)$/;
export const KEY_FIXTURE_SEGMENTS = new Set(['node_modules', 'fixtures', '__fixtures__', 'testdata', 'test', 'tests', '__tests__']);
// Q3: only these .env templates are excepted. Never widen this to other .env files.
export const ENV_TEMPLATE_SUFFIX = /\.(?:example|sample|template)$/;
// ssh public keys and ssh metadata are never secret.
export const SSH_PUBLIC = /\.pub$/;

// Concrete examples of every secret pattern, used to judge glob and partly dynamic operands
// (a glob or "$X/.env" is a stop when it can expand to one of these).
export function secretSamples(home: string, cwds: string[]): string[] {
  const h = home.replace(/\/$/, '');
  const out = [
    `${h}/.ssh/id_rsa`, `${h}/.ssh/id_ed25519`, `${h}/.ssh/id_ecdsa`, `${h}/.ssh/id_dsa`, `${h}/.ssh/deploy_key`,
    `${h}/.aws/credentials`, `${h}/.aws/sso/cache/token.json`, `${h}/.config/gcloud/application_default_credentials.json`,
    `${h}/.config/gcloud/credentials.db`, `${h}/.config/gcloud/access_tokens.db`, `${h}/.azure/accessTokens.json`,
    `${h}/.kube/config`, `${h}/.docker/config.json`, `${h}/.npmrc`, `${h}/.pypirc`, `${h}/.netrc`, `${h}/.git-credentials`,
    `${h}/.config/gh/hosts.yml`, `${h}/.config/op/config`, `${h}/.gnupg/private-keys-v1.d/k.key`, `${h}/.marrow/env`,
    `${h}/.marrow/env.local`, `${h}/.claude.json`, `${h}/.claude/settings.local.json`, '/proc/self/environ', '/proc/1/environ', '/proc/self/task/1/environ',
    `${h}/.env`, '/root/.ssh/id_rsa', '/root/.aws/credentials', `${h}/.marrow/seatbelt/salt`,
    `${h}/.marrow/fleet.env`, `${h}/.marrow/credentials/k`,
    `${h}/.marrow/host-approvals/state.json`, `${h}/.marrow/host-approvals/.state-1-aa.tmp`,
  ];
  for (const c of cwds) {
    const d = c.replace(/\/$/, '');
    out.push(`${d}/.env`, `${d}/.env.local`, `${d}/.env.production`, `${d}/app/.env`, `${d}/app.env`, `${d}/.dev.vars`, `${d}/server.pem`,
      `${d}/tls.key`, `${d}/cert.p12`, `${d}/cert.pfx`, `${d}/.claude/settings.local.json`, `${d}/.npmrc`);
  }
  return out;
}

export const SECRET_VAR = /KEY|TOKEN|SECRET|PASS|CRED/i;

// Protected-branch baseline (classifier policy-baseline protected_branches; same list as spec §1.2).
export const PROD_ENV = /(?:^|[^a-z0-9])(?:prod|production|live|main)(?:[^a-z0-9]|$)/i;

// Programs that take a path operand without printing or copying its content (S4 does not apply).
export const S4_EXEMPT_PROGRAMS = new Set([
  'ls', 'stat', 'test', '[', '[[', 'du', 'chmod', 'chown', 'chgrp', 'touch', 'mkdir', 'rm', 'rmdir', 'unlink',
  'ssh', 'ssh-add', 'sftp', 'realpath', 'readlink', 'dirname', 'basename', 'echo', 'which', 'type', 'find', 'wc',
  'kubectl', 'helm', 'cd', 'pushd', 'shred', 'file',
]);
export const GIT_S4_EXEMPT_SUBS = new Set(['rm', 'check-ignore', 'check-attr', 'ls-files', 'status', 'log', 'restore']);

export const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'ash', 'mksh', 'yash', 'rbash', 'csh', 'tcsh']);
export const INTERPRETERS = new Set(['python', 'python2', 'python3', 'node', 'nodejs', 'ruby', 'perl', 'php', 'deno', 'bun', 'lua', 'pwsh', 'powershell', 'osascript', 'tclsh', 'irb', 'ipython',
  'tsx', 'ts-node', 'pypy', 'pypy3', 'luajit', 'php-cli', 'rscript', 'texlua', 'julia', 'groovy', 'racket', 'guile', 'runghc', 'raku', 'perl6', 'Rscript', 'R']);

// Interpreter one-liners that delete trees (S5). The two forms that need "a call, then an option
// before its closing parenthesis" are not regexes with a gap: a bounded gap lets padding turn a stop
// into a pass (audit N5) and an unbounded one is quadratic on a run of the opener. They are one
// linear scan each (interpreterTreeDelete), with the same meaning the unbounded regexes had.
const INTERPRETER_TREE_DELETE_WORDS = /rmSync|rmdirSync|rimraf|rmtree|rm_rf|FileUtils\.rm_r|FileUtils\.remove_dir|FileUtils\.remove_entry|remove_entry|remove_tree|File::Path|remove_dir_all|removedirs|deleteRecursively/;
// A delete call and a recursive option anywhere in the same code: padding, a nested call in the path
// argument, options kept in a variable and `fs['rm']` all end in the same two facts (audit N5).
const DELETE_CALL = /\.rm\s*\(|\brm\s*\(|\[\s*['"`]rm(?:dir)?['"`]\s*\]|\brmdir\s*\(|\.rmdir\s*\(|\bremoveSync?\s*\(|\.remove(?:All)?\s*\(/;
// Deleting file by file under a walk of a tree.
const WALK_WORD = /os\.walk|\.rglob\s*\(|\bwalk\s*\(|Dir\.glob|Dir\[|\.glob\s*\(|scandir|readdirSync|readdir\s*\(|FileList|glob\.glob|find_files/;
const FILE_DELETE_CALL = /os\.remove|os\.unlink|\.unlink\s*\(|File\.delete|File\.unlink|unlinkSync|fs\.unlink|\bunlink\s*\(/;
// Decoded data that is then executed inside interpreter code (S-x).
const INTERPRETER_DECODE_WORDS = /b64decode|base64|atob\s*\(|fromCharCode|fromCodePoint|unhexlify|bytes\.fromhex|codecs\.decode|\.decode\(\s*['"](?:hex|base64|rot)|\bpack\s*\(?\s*['"][HhBbuU]|\bchr\s*\(|\bhex\s*\(|\bgunzip|\binflate|\bzlib\b|\bunpack\b|\bpack\b\s*\(?\s*['"]|\.reverse\(\)|\[::-1\]|\bscalar\s+reverse|\bunescape\s*\(|\bdecodeURI(?:Component)?\s*\(|\bnew\s+Buffer\b|\bBuffer\s*\[|\bglobalThis\s*\[|\bglobal\s*\[|\bprocess\s*\[/i;
// `Buffer.from(x, 'hex')`: the call and an encoding literal in the same code.
const BUFFER_CALL = /\bBuffer\b/;
const ENCODING_LITERAL = /['"`](?:base64|hex)['"`]/i;

export function interpreterTreeDelete(code: string): boolean {
  if (INTERPRETER_TREE_DELETE_WORDS.test(code)) return true;
  if (code.includes('recursive') && DELETE_CALL.test(code)) return true;
  if (WALK_WORD.test(code) && FILE_DELETE_CALL.test(code)) return true;
  // `Remove-Item … -Recurse` on one line.
  for (const line of code.split('\n')) {
    const at = line.toLowerCase().indexOf('remove-item');
    if (at >= 0 && line.toLowerCase().indexOf('-recurse', at + 11) >= 0) return true;
  }
  return false;
}

export function interpreterDecodeToken(code: string): boolean {
  // `Buffer.from(x, enc).toString()` turns bytes into text whatever the encoding is called.
  return INTERPRETER_DECODE_WORDS.test(code) || (BUFFER_CALL.test(code) && (ENCODING_LITERAL.test(code) || /\.toString\s*\(/.test(code)));
}
export const INTERPRETER_EXEC = /\bexec\b|\beval\b|\bFunction\s*\(|\bsystem\b|popen|spawn|execSync|execFile|child_process|subprocess|\bcompile\s*\(|`/;

// Owner-only commands an agent must never run (S0).
export const MARROW_OWNER_SUBS = new Set(['claim', 'unclaim', 'control', 'uninstall']);

// npm-style package names to the binary they run.
export const PACKAGE_BINS: Record<string, string> = {
  '@changesets/cli': 'changeset', 'netlify-cli': 'netlify', 'firebase-tools': 'firebase', 'aws-cdk': 'cdk',
  '@vscode/vsce': 'vsce', vsce: 'vsce', ovsx: 'ovsx', vercel: 'vercel', wrangler: 'wrangler', np: 'np',
  'release-it': 'release-it', 'semantic-release': 'semantic-release', lerna: 'lerna', serverless: 'serverless',
  sst: 'sst', rimraf: 'rimraf', '@railway/cli': 'railway', 'heroku': 'heroku',
};

// Git builtin subcommands: git ignores an alias that has a builtin name.
export const GIT_BUILTINS = new Set(('add am annotate apply archive bisect blame branch bundle cat-file check-attr check-ignore '
  + 'check-mailmap checkout checkout-index cherry cherry-pick citool clean clone column commit commit-graph commit-tree config '
  + 'count-objects credential describe diff diff-files diff-index diff-tree difftool fast-export fast-import fetch fetch-pack '
  + 'filter-branch fmt-merge-msg for-each-ref for-each-repo format-patch fsck gc get-tar-commit-id grep gui hash-object help '
  + 'index-pack init init-db instaweb interpret-trailers log ls-files ls-remote ls-tree mailinfo mailsplit maintenance merge '
  + 'merge-base merge-file merge-index merge-tree mergetool mktag mktree multi-pack-index mv name-rev notes pack-objects '
  + 'pack-refs patch-id prune prune-packed pull push range-diff read-tree rebase receive-pack reflog remote repack replace '
  + 'request-pull rerere reset restore rev-list rev-parse revert rm send-email send-pack shortlog show show-branch show-index '
  + 'show-ref sparse-checkout stash status stripspace submodule switch symbolic-ref tag unpack-file unpack-objects update-index '
  + 'update-ref update-server-info upload-archive upload-pack var verify-commit verify-pack verify-tag version whatchanged '
  + 'worktree write-tree').split(' '));

export const GIT_PUSH_LONG = [
  'force', 'force-with-lease', 'force-if-includes', 'mirror', 'delete', 'all', 'branches', 'prune', 'tags', 'follow-tags',
  'dry-run', 'porcelain', 'verbose', 'quiet', 'progress', 'no-verify', 'verify', 'atomic', 'no-atomic', 'set-upstream',
  'signed', 'no-signed', 'push-option', 'repo', 'receive-pack', 'exec', 'thin', 'no-thin', 'ipv4', 'ipv6',
  'recurse-submodules', 'no-recurse-submodules', 'no-force-with-lease', 'no-force-if-includes', 'no-progress',
];
export const GIT_PUSH_RISKY_LONG: Record<string, string> = {
  force: 'force', 'force-with-lease': 'force', 'force-if-includes': 'force', mirror: 'mirror', delete: 'delete',
  all: 'all', branches: 'all', prune: 'prune',
};

// Lexical tripwire (spec §2.1.3). Matched case-insensitively after removing quotes and backslashes.
export const TRIPWIRE: ReadonlyArray<{ re: RegExp; category: 'S0' | 'S1' | 'S2' | 'S3' | 'S4' | 'S5' | 'Sx'; reason: string }> = [
  { re: /\bpush\b[^;&|\n]{0,200}?(?:\s-[a-z0-9]*f|force|\s\+|--mirror|--delete|\s-d\b|\s:)/, category: 'S1', reason: 'tripwire_force_push' },
  { re: /publish/, category: 'S3', reason: 'tripwire_publish' },
  { re: /deploy|--prod\b/, category: 'S2', reason: 'tripwire_deploy' },
  { re: /\.ssh\b|id_rsa|id_ed25519|id_ecdsa|\.aws\b|\.npmrc|\.netrc|\.pypirc|\.git-credentials|\.docker\/config|\.kube\/config|gh\/hosts\.yml|\.gnupg|\.claude\.json|settings\.local\.json|\/environ\b|\.dev\.vars|\.pem\b|\.p12\b|\.pfx\b|\.marrow\/env|\.marrow\/seatbelt\/salt/, category: 'S4', reason: 'tripwire_secret_path' },
  // The host-approvals state file named in code or text the mapper cannot follow; the reason is the one the keyed hook keeps.
  { re: /\.marrow\/host-approvals\/[^\s\/]/, category: 'S4', reason: 'host_approvals_state' },
  { re: /(?:^|[^a-z0-9_$)\].])\.env(?![a-z0-9_])(?!\.(?:example|sample|template)\b)/, category: 'S4', reason: 'tripwire_env_file' },
  { re: /printenv|export\s+-p|declare\s+-[a-z]*[xp]|(?:^|[;&|({\s])(?:env|set|export)\s*(?:$|[;&|)}])|auth\s+token|print-(?:access|identity)-token|get-session-token|get-access-token|auth:token|find-(?:generic|internet)-password|secret-tool|op\s+read|vault\s+(?:kv|read)|pass\s+show|token\s+list|(?:process\.env|os\.environ|\$env|env\.to_h|system\.getenv\(\))\s*(?:\)|;|$|\||,|\.items|\.keys|\.copy)|(?:environ|\benv)\W{0,3}[a-z_]{0,256}(?:key|token|secret|pass|cred)|\$\{?!?[a-z_]{0,256}(?:key|token|secret|pass|cred)/, category: 'S4', reason: 'tripwire_secret_dumper' },
  { re: /rmtree|rmsync|rmdirsync|rimraf|rm_rf|\brm_r\b|mkfs/, category: 'S5', reason: 'tripwire_recursive_delete' },
  { re: /\.marrow|@getmarrow|settings\.json|hooks\.json|\.mcp\.json|\.bashrc|\.zshrc|\.bash_profile|\.zprofile|\.zshenv|\.profile\b/, category: 'S0', reason: 'tripwire_self_protection' },
  // NEW-1: the Marrow plugins named in code or text the mapper cannot follow (`python3 -c "open('…/installed_plugins.json','w')"`).
  { re: /installed_plugins\.json|known_marketplaces\.json|plugins\/(?:cache|marketplaces)\/getmarrow|\.claude\/plugins\/\S{0,200}marrow|\.cursor\/plugins|marrow-launch\.cjs/, category: 'S0', reason: 'tripwire_plugin_protection' },
  { re: /base64\s+(?:-[a-z]*d|--decode)|xxd\s+-[a-z]*r|b64decode|atob\s*\(/, category: 'Sx', reason: 'tripwire_decoded_exec' },
];
// Script, Makefile-target and package-script names that trip when their content cannot be read.
export const NAME_TRIPWIRE = /publish|deploy|release|ship|prod/i;

// ---------------------------------------------------------------------------------------------
// Unknown wrappers (audit F1). A program the mapper has no handler for is not "harmless": its argv
// may hold a command (`strace npm publish`, `tmux new -d 'npm publish'`). Only programs in
// INERT_PROGRAMS (text, file and info tools whose arguments are never run) skip the argv scan.

// Every program name the dispatcher has a handler for. test/seatbelt-audit-regression.test.js checks
// that each `case '<name>'` in mapper.ts is listed, so a tail-position scan sees every handler.
export const KNOWN_COMMANDS = new Set([
  'cd', 'pushd', 'popd', 'alias', 'export', 'declare', 'typeset', 'readonly', 'local', 'set', 'unset', 'printenv', 'echo', 'printf',
  'print', 'eval', 'source', '.', 'env', 'sudo', 'doas', 'pkexec', 'runas', 'su', 'timeout', 'nice', 'nohup', 'time', 'command',
  'builtin', 'exec', 'stdbuf', 'ionice', 'chrt', 'taskset', 'setsid', 'unbuffer', 'caffeinate', 'retry', 'flock', 'xargs', 'parallel',
  'watch', 'ssh', 'git', 'gh', 'npm', 'pnpm', 'yarn', 'bun', 'npx', 'bunx', 'corepack', 'make', 'gmake', 'rm', 'rimraf', 'rmdir', 'find',
  'rsync', 'shred', 'dd', 'docker', 'podman', 'kubectl', 'helm', 'marrow', 'marrow-install', 'claude', 'apply_patch', 'applypatch',
  'patch', 'trap', 'script', 'cpio', 'pax', 'read', 'mapfile', 'readarray', 'getopts', 'busybox', 'toybox', 'concurrently', 'npm-run-all', 'npm-run-all2', 'run-s', 'run-p', 'railway',
  // deploy tools
  'wrangler', 'vercel', 'netlify', 'ntl', 'fly', 'flyctl', 'firebase', 'heroku', 'gcloud', 'sst', 'serverless', 'sls', 'cdk', 'terraform',
  'tofu', 'terragrunt', 'pulumi', 'eb', 'aws', 'az',
  // publish tools and task runners
  'np', 'just', 'task', 'mage', 'rake', 'invoke', 'nx', 'turbo', 'release-it', 'semantic-release', 'changeset', 'changesets', 'lerna',
  'cargo', 'twine', 'uv', 'poetry', 'hatch', 'flit', 'gem', 'pdm', 'maturin', 'jsr', 'lein', 'sbt', 'nuget', 'dart', 'flutter', 'cabal', 'stack', 'opam',
  'mix', 'rebar3', 'conda', 'anaconda', 'mamba', 'mvn', 'mvnw', 'gradle', 'gradlew', 'dotnet', 'pod', 'vsce', 'ovsx', 'goreleaser',
  // secret dumpers
  'security', 'secret-tool', 'op', 'vault', 'pass', 'gpg', 'gpg2',
  // shells and interpreters
  'sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'ash', 'mksh', 'yash', 'rbash', 'csh', 'tcsh',
  'python', 'python2', 'python3', 'node', 'nodejs', 'ruby', 'perl', 'php', 'deno', 'lua', 'pwsh', 'powershell', 'osascript', 'tclsh',
  'irb', 'ipython', 'awk', 'gawk', 'mawk', 'nawk', 'sed', 'gsed', 'tar', 'gtar', 'bsdtar', 'ps',
  // A3: the Windows command interpreter (its /c text is read as PowerShell / cmd text)
  'cmd',
]);

// Programs whose arguments are text, patterns or paths and are never run. Their argv is not scanned
// for a command. A program with an exec-capable flag (find -exec, xargs, tar --to-command) is not
// listed here; it has a handler or is scanned.
export const INERT_PROGRAMS = new Set([
  'ls', 'cat', 'head', 'tail', 'less', 'more', 'wc', 'sort', 'uniq', 'cut', 'tr', 'tee', 'grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack',
  'jq', 'yq', 'diff', 'cmp', 'comm', 'join', 'paste', 'column', 'fmt', 'fold', 'nl', 'od', 'hexdump', 'xxd', 'strings', 'cp', 'mv',
  'mkdir', 'touch', 'ln', 'chmod', 'chown', 'chgrp', 'true', 'false', 'sleep', 'date', 'uname', 'hostname', 'whoami', 'id', 'pwd',
  'stat', 'du', 'df', 'free', 'uptime', 'ps', 'pgrep', 'file', 'which', 'whereis', 'type', 'basename', 'dirname', 'realpath', 'readlink',
  'md5sum', 'sha1sum', 'sha256sum', 'sha512sum', 'shasum', 'cksum', 'b2sum', 'base64', 'curl', 'wget', 'http', 'https', 'ping',
  'nslookup', 'dig', 'host', 'man', 'help', 'history', 'clear', 'tput', 'stty', 'sync', 'pbcopy', 'pbpaste', 'xclip', 'wl-copy',
  'notify-send', 'say', 'logger', 'wait', 'jobs', 'kill', 'ulimit', 'umask', 'test', '[', '[[', 'seq', 'yes', 'expr', 'let', 'return',
  'exit', 'break', 'continue', 'shift', 'read', 'getopts', 'hash', 'rev', 'tac', 'sed', 'gsed', 'zip', 'unzip', 'gzip',
  'gunzip', 'bzip2', 'xz', 'zstd', 'tar', 'truncate', 'unlink', 'mktemp', 'install', 'ssh-add', 'ssh-keygen',
  'ssh-keyscan', 'openssl', 'gpg', 'gpg2', 'tree', 'bat', 'fd', 'exa', 'eza', 'lsof', 'netstat', 'ss', 'ip', 'ifconfig', 'top', 'htop',
  'nproc', 'getconf', 'locale', 'cal', 'bc', 'dc', 'zcat', 'bzcat', 'xzcat', 'diff3', 'colordiff',
  'git-lfs', 'tsc', 'eslint', 'prettier', 'jest', 'vitest', 'mocha',
]);

// Executable-looking argument paths worth reading as a script when an unknown program is given one.
export const SCRIPT_SUFFIX = /\.(?:sh|bash|zsh|ksh|command)$/;
export const NON_SCRIPT_NAMES = new Set(['makefile', 'gnumakefile', 'dockerfile', 'readme', 'license', 'licence', 'changelog', 'procfile', 'gemfile', 'rakefile', 'vagrantfile', 'jenkinsfile']);

// `eval "$(<producer> …)"` forms that only print shell variable assignments.
export const EVAL_PRODUCERS = new Set(['ssh-agent', 'direnv', 'opam', 'pyenv', 'rbenv', 'nodenv', 'jenv', 'goenv', 'fnm', 'zoxide', 'starship',
  'mise', 'asdf', 'volta', 'dircolors', 'keychain', 'gpg-agent', 'lesspipe', 'lesspipe.sh', 'thefuck', 'conda', 'micromamba', 'luarocks', 'cs']);

// ---------------------------------------------------------------------------------------------
// npm subcommand resolution (audit F5). Same tables as npm 10 lib/utils/cmd-list.js; the lookup
// below keeps every reading an abbreviation can have (ambiguous prefixes included), so a prefix that
// could be publish is treated as publish.
export const NPM_COMMANDS = ['access', 'adduser', 'audit', 'bugs', 'cache', 'ci', 'completion', 'config', 'dedupe', 'deprecate', 'diff',
  'dist-tag', 'docs', 'doctor', 'edit', 'exec', 'explain', 'explore', 'find-dupes', 'fund', 'get', 'help', 'help-search', 'hook', 'init',
  'install', 'install-ci-test', 'install-test', 'link', 'll', 'login', 'logout', 'ls', 'org', 'outdated', 'owner', 'pack', 'ping', 'pkg',
  'prefix', 'profile', 'prune', 'publish', 'query', 'rebuild', 'repo', 'restart', 'root', 'run-script', 'sbom', 'search', 'set',
  'shrinkwrap', 'star', 'stars', 'start', 'stop', 'team', 'test', 'token', 'uninstall', 'unpublish', 'unstar', 'update', 'version',
  'view', 'whoami',
  // older and newer npm releases
  'bin', 'birthday', 'cit', 'dist-tags', 'install-clean', 'issues', 'rum', 'unpkg', 'xmas', 'config-set', 'ddp', 'hlep'];
export const NPM_ALIASES: Record<string, string> = {
  author: 'owner', home: 'docs', issues: 'bugs', info: 'view', show: 'view', find: 'search', add: 'install', unlink: 'uninstall',
  remove: 'uninstall', rm: 'uninstall', r: 'uninstall', un: 'uninstall', rb: 'rebuild', list: 'ls', ln: 'link', create: 'init',
  i: 'install', it: 'install-test', cit: 'install-ci-test', up: 'update', c: 'config', s: 'search', se: 'search', tst: 'test', t: 'test',
  ddp: 'dedupe', v: 'view', run: 'run-script', 'clean-install': 'ci', 'clean-install-test': 'install-ci-test', x: 'exec', why: 'explain',
  la: 'll', verison: 'version', ic: 'ci', innit: 'init', in: 'install', ins: 'install', inst: 'install', insta: 'install',
  instal: 'install', isnt: 'install', isnta: 'install', isntal: 'install', isntall: 'install', 'install-clean': 'ci',
  'isntall-clean': 'ci', hlep: 'help', 'dist-tags': 'dist-tag', upgrade: 'update', udpate: 'update', rum: 'run-script',
  sit: 'install-ci-test', urn: 'run-script', ogr: 'org', 'add-user': 'adduser',
};
// Global options that take a value (the value is never the subcommand).
export const NPM_VALUE_FLAGS = new Set(['-w', '--workspace', '--prefix', '-C', '--dir', '--filter', '-F', '--cwd', '--tag', '--access',
  '--otp', '--registry', '--cache', '--loglevel', '--userconfig', '--globalconfig', '--scope', '--location', '--omit', '--include',
  '--before', '--min-release-age', '--install-strategy', '--workspaces-update', '--package', '-p', '--call', '-c', '--node-options',
  '--script-shell', '--foreground-scripts-value', '--logs-dir', '--logs-max', '--otp-value', '--init-module', '--fetch-retries',
  '--maxsockets', '--proxy', '--https-proxy', '--noproxy', '--cafile', '--tag-version-prefix', '--message', '-m', '--depth',
  '--engine-strict-value', '--cpu', '--os', '--libc', '--jsonfile']);
// Global options that never take a value.
export const NPM_BOOL_FLAGS = new Set(['-g', '--global', '-S', '--save', '-D', '--save-dev', '-O', '--save-optional', '-E', '--save-exact',
  '-B', '--save-bundle', '-f', '--force', '-d', '-dd', '-ddd', '-s', '--silent', '-q', '--quiet', '-v', '--verbose', '--json', '--no-json',
  '--dry-run', '--no-dry-run', '--no-audit', '--audit', '--no-fund', '--fund', '--ignore-scripts', '--no-ignore-scripts', '--production',
  '--prod', '--legacy-peer-deps', '--no-legacy-peer-deps', '--strict-peer-deps', '--no-save', '--package-lock-only', '--no-package-lock',
  '--prefer-offline', '--prefer-online', '--offline', '--no-offline', '-y', '--yes', '--no', '-l', '--long', '-p', '--parseable',
  '--no-progress', '--progress', '--workspaces', '-ws', '--include-workspace-root', '--if-present', '--ignore-engines',
  '--no-optional', '--no-bin-links', '--foreground-scripts', '--install-links', '--global-style', '--no-color', '--color', '--unicode',
  '--no-unicode', '--verify-store-integrity', '--frozen-lockfile', '--no-frozen-lockfile', '--recursive', '-r', '--workspace-root',
  '--link', '--sign-git-tag', '--no-git-tag-version', '--git-tag-version', '--allow-same-version', '--no-commit-hooks',
  '--commit-hooks', '--audit-level-none', '--update-notifier', '--no-update-notifier', '--ignore-workspace-root-check', '-w-root']);

// ---------------------------------------------------------------------------------------------
// git config that makes git run another program (audit F6; same list as the U3 resolver,
// src/seatbelt-git.ts GIT_EXEC_CONFIG). A value set for one of these is a shell command.
export const GIT_EXEC_CONFIG = /^(?:core\.(?:sshcommand|pager|editor|fsmonitor|hookspath|gitproxy|askpass)|sequence\.editor|diff\.external|diff\..+\.(?:command|textconv)|merge\..+\.driver|filter\..+\.(?:clean|smudge|process)|credential(?:\..+)?\.helper|pager\..+|gpg(?:\..+)?\.program|uploadpack\.packobjectshook|remote\..+\.(?:receivepack|uploadpack|vcs)|submodule\..+\.update|alias\..+)$/;
// Config keys that redirect or extend where git reads configuration from.
export const GIT_CONFIG_INCLUDE = /^(?:include\.path|includeif\..+\.path)$/;
// Environment variables that redirect git's configuration files.
export const GIT_CONFIG_ENV_FILES = ['GIT_CONFIG', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM'];

// ---------------------------------------------------------------------------------------------
// Tools that run a shell command (audit F11).
// Names (lower-cased) of tools whose input is a shell command. Any other tool is scanned too: an
// input field named like COMMAND_KEYS is a shell command wherever it sits (top level or nested).
export const SHELL_TOOL_NAMES = new Set(['bash', 'shell', 'local_shell', 'exec_command', 'container.exec', 'run_terminal_command',
  'run_terminal_cmd', 'execute_command', 'run_shell_command', 'run_command', 'terminal', 'shell_command', 'bash_command', 'execute_bash',
  'run_bash', 'bashtool', 'bash_tool', 'powershell', 'run_in_terminal', 'terminal_command', 'exec', 'sh', 'zsh', 'cmd', 'command',
  'developer__shell', 'run_shell', 'shell_exec', 'execute_shell', 'process']);
// Tools with their own handling (file read, search, write); `command` there is not a shell string.
export const FILE_TOOL_NAMES = new Set(['read', 'notebookread', 'read_file', 'view', 'view_file', 'grep', 'grep_files', 'search', 'rg',
  'write', 'edit', 'multiedit', 'notebookedit', 'write_file', 'create_file', 'str_replace_editor', 'str_replace_based_edit_tool',
  'apply_patch', 'edit_file', 'glob', 'ls', 'list_dir', 'list_directory']);
// Input field names (lower-cased) that hold a shell command, script or argv.
export const COMMAND_KEYS = new Set(['command', 'cmd', 'commandline', 'command_line', 'cmdline', 'cmd_line', 'shell_command', 'shellcommand',
  'bash_command', 'script', 'shell', 'bash', 'sh', 'exec', 'run', 'execute', 'argv', 'commands', 'cmds',
  // audit N4: argv-style tools and string-named variants
  'program', 'executable', 'exe', 'binary', 'bin', 'shell_cmd', 'shellcmd', 'cmdstring', 'cmd_string', 'command_string', 'commandstring', 'cmdstr',
  'cmd_str', 'command_text', 'commandtext', 'cmd_text', 'shell_script', 'bash_script', 'script_text']);
// A field name that is not listed above but names a command by word: `cmdString`, `my_shell_cmd`,
// `run_command`. Matched on name segments, so `description` is not `script`.
const COMMAND_SEGMENTS = new Set(['cmd', 'cmds', 'command', 'commands', 'shell', 'bash', 'zsh', 'script', 'scripts', 'exec', 'execute', 'argv', 'commandline',
  'cmdline', 'program', 'executable', 'binary', 'bin', 'cmdstring']);
export function commandLikeKey(raw: string): boolean {
  return raw.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/).some((s) => COMMAND_SEGMENTS.has(s));
}
// Companion argument-vector fields next to a `command` string (MCP exec servers: {command:'git', args:[…]}).
export const ARGV_KEYS = new Set(['args', 'argv', 'arguments', 'params', 'argument']);
export const ARGV_SEGMENTS = new Set(['args', 'argv', 'arguments', 'params', 'parameters', 'argument', 'arg', 'arg1', 'arg2', 'arg3', 'operands', 'operand', 'options', 'option', 'flags', 'flag', 'subcommand',
  'subcommands', 'positional', 'positionals', 'opts', 'rest', 'remaining', 'tail', 'more']);
// The argument-list names whose value must be a list or text; any other shape is unknown.
export const ARGV_STRICT = new Set(['args', 'argv', 'arguments', 'params', 'parameters', 'argument']);
// Fields that hold interpreter code (scanned like `node -e`).
export const CODE_KEYS = new Set(['code', 'python', 'javascript', 'js', 'node', 'ruby', 'perl', 'php', 'python_code', 'source_code',
  // audit N4
  'source', 'snippet', 'code_snippet', 'script_source', 'python_script', 'js_code', 'javascript_code', 'node_code', 'ruby_code',
  'perl_code', 'php_code']);
const CODE_SEGMENTS = new Set(['code', 'python', 'javascript', 'js', 'ruby', 'perl', 'php', 'snippet', 'source', 'py', 'rb', 'lua', 'ts', 'typescript']);
export function codeLikeKey(raw: string): boolean {
  const segs = raw.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/);
  // `source_path` / `source_file` name a file, not code.
  if (segs.some((s) => s === 'path' || s === 'file' || s === 'dir' || s === 'url' || s === 'uri' || s === 'id' || s === 'name' || s === 'type' || s === 'lang' || s === 'language')) return false;
  return segs.some((s) => CODE_SEGMENTS.has(s));
}
// Fields that carry a program's standard input or typed keys (audit N4). Next to a command they are
// that command's stdin; on a terminal or process tool they are typed into a shell or REPL.
export const STDIN_KEYS = new Set(['stdin', 'input', 'std_in', 'standard_input', 'stdin_text', 'stdin_data', 'input_text', 'inputtext',
  'keys', 'send_keys', 'keystrokes', 'stdin_content']);
// Name segments of a tool that drives a terminal, shell, process or REPL.
export const TERMINAL_SEGMENTS = new Set(['terminal', 'shell', 'process', 'interact', 'pty', 'console', 'repl', 'bash', 'exec', 'execute',
  'stdin', 'keys', 'keystroke', 'keystrokes', 'command', 'commands', 'cmd', 'tty', 'ssh', 'tmux', 'iterm', 'iterm2', 'session', 'sh',
  'zsh', 'powershell', 'pwsh', 'run', 'input', 'term', 'screen', 'stuff', 'type', 'typing', 'keyboard', 'send']);

// ---------------------------------------------------------------------------------------------
// Friction trims T1/T3: what can change the checked-out branch.

// Build tools and generators that are not assumed to switch branches. Any other program with no
// handler is "may change the branch" for the trims (audit T1).
export const BUILD_TOOLS = new Set(['vite', 'astro', 'next', 'nuxt', 'nuxi', 'webpack', 'rollup', 'esbuild', 'tsup', 'parcel', 'gatsby', 'hugo',
  'jekyll', 'zola', 'mkdocs', 'sphinx-build', 'eleventy', '11ty', 'hexo', 'docusaurus', 'vuepress', 'vitepress', 'svelte-kit', 'sass', 'postcss',
  'tailwindcss', 'ng', 'vue-cli-service', 'react-scripts', 'expo', 'remix', 'solid-start', 'qwik', 'biome', 'swc', 'babel', 'rustc',
  'gcc', 'g++', 'clang', 'cc', 'nodemon', 'zip', 'jq', 'yq', 'sort', 'uniq', 'cmake', 'ninja', 'swift', 'xcodebuild']);
// Task runners and package builders that run project code (recipes, build scripts, plugins) the
// mapper does not read: a command before the trims may have switched the branch in one of them.
export const HEAD_RUNNERS = new Set(['just', 'task', 'mage', 'rake', 'invoke', 'nx', 'turbo', 'lerna', 'mvn', 'mvnw', 'gradle', 'gradlew', 'dotnet',
  'sbt', 'ant', 'bazel', 'buck', 'pants', 'tsx', 'ts-node', 'pytest', 'tox', 'nox', 'pip', 'pip3', 'bundle', 'cargo', 'go', 'deno', 'flutter', 'dart']);
// Programs whose purpose is to switch branches, worktrees or revisions.
export const HEAD_CHANGERS = new Set(['hub', 'jj', 'sl', 'hg', 'git-town', 'gt', 'gitui', 'lazygit', 'tig', 'git-branchless', 'stg', 'git-flow',
  'gitflow', 'svn', 'bzr', 'pijul', 'fossil', 'repo', 'west']);
// `gh` subcommands that cannot change the local checkout.
export const GH_HEAD_SAFE = new Set(['api', 'auth', 'issue', 'run', 'workflow', 'release', 'label', 'gist', 'status', 'search', 'browse',
  'config', 'extension', 'ruleset', 'secret', 'variable', 'cache', 'codespace', 'ssh-key', 'gpg-key', 'org', 'project', 'alias', 'completion', 'help', 'version']);
// Fields of a terminal or process tool that hold typed text (next to, or instead of, stdin/input).
export const TERMINAL_TEXT_KEYS = new Set(['chunks', 'chunk', 'expression', 'expr', 'source', 'cells', 'cell', 'text', 'data', 'content', 'message', 'payload', 'body', 'value', 'line', 'lines', 'statement', 'task',
  'job', 'action', 'string', 'chars', 'characters', 'typed', 'write', 'send', 'prompt']);
// Fields that give a command's environment.
export const ENV_KEYS = new Set(['env', 'environment', 'envs', 'env_vars', 'envvars', 'environment_variables', 'extra_env', 'env_vars_override']);
// Fields that give a command's working directory.
export const CWD_KEYS = new Set(['cwd', 'workdir', 'working_dir', 'working_directory', 'work_dir', 'workingdir', 'workingdirectory', 'current_directory',
  'currentdir', 'directory', 'dir', 'folder', 'cwd_path', 'run_in', 'cwds', 'workdirs', 'root', 'base_dir', 'basedir', 'base_directory', 'pwd', 'chdir', 'cd', 'project', 'project_dir',
  'project_path', 'repo_path', 'repo_dir', 'working_path', 'path', 'rootdir', 'root_dir', 'workspace', 'workspace_dir']);
// Option objects that may hold the working directory or environment of the command next to them.
export const OPTION_OBJECT_KEYS = new Set(['options', 'opts', 'context', 'session', 'execution', 'spawn_options', 'exec_options', 'config', 'settings', 'env_options', 'process', 'run_options']);
// A sibling that names the language of a code field.
export const LANGUAGE_KEYS = new Set(['runtime', 'language', 'lang', 'interpreter', 'engine', 'kind', 'type', 'shell', 'mode']);

// ---------------------------------------------------------------------------------------------
// A3: Windows shell deletes (PowerShell and cmd). Everything below only ADDS stops.

// The reasons A3 adds. When one of them is the first hit of the decision's category, the decision's rule is
// `<category>.<reason>` (S5.windows_shell_delete_unparsed, Sx.encoded_powershell_unreadable,
// Sx.powershell_script_unreadable, Sx.dynamic_powershell_code); every one matches the hook's CODE pattern.
export const A3_REASONS: ReadonlySet<string> = new Set(['windows_shell_delete_unparsed', 'encoded_powershell_unreadable',
  'powershell_script_unreadable', 'dynamic_powershell_code']);

// Delete verbs in every text. rm and rmdir keep their POSIX handlers: they count only in PowerShell / cmd text
// and on native Windows.
export const WIN_DELETE_VERBS: ReadonlySet<string> = new Set(['remove-item', 'ri', 'del', 'erase', 'rd']);
export const WIN_SHELL_DELETE_VERBS: ReadonlySet<string> = new Set(['rm', 'rmdir']);

/** A program word as Windows names it: both separators split the path, a .exe/.cmd/.bat/.com suffix goes, case folds. */
export function windowsProgramName(text: string): string {
  const base = text.replace(/[\\/]+$/, '').split(/[\\/]/).pop() || '';
  return base.replace(/\.(?:exe|cmd|bat|com)$/i, '').toLowerCase();
}

// Remove-Item parameters that cannot recurse. A prefix counts only when it names exactly one of them (`-f` is
// Filter or Force, so it is unknown). `ea` is the ErrorAction alias.
const PS_DELETE_OPTIONS = ['path', 'literalpath', 'filter', 'include', 'exclude', 'force', 'whatif', 'confirm', 'erroraction', 'verbose', 'debug'];

function deleteOptionStops(word: string): boolean {
  if (word[0] === '/') {
    // cmd switches, alone or run together (/s/q): /q /f /p /a[:attrs] are fine; /s (recursion) and everything else stops.
    for (const part of word.slice(1).split('/')) if (!/^(?:[qfp]|a(?::[a-z-]{0,12})?)$/i.test(part)) return true;
    return false;
  }
  if (word.startsWith('--')) return true; // GNU long options (--recursive and every other one)
  const colon = word.indexOf(':');
  const name = (colon > 0 ? word.slice(1, colon) : word.slice(1)).toLowerCase();
  const value = colon > 0 ? word.slice(colon + 1) : null;
  if (name === '' || name.startsWith('r')) return true; // -r, -rec, -Recurse, -Recurse:$true and a typo of them
  if (name !== 'ea' && PS_DELETE_OPTIONS.filter((k) => k.startsWith(name)).length !== 1) return true;
  if (value !== null && value.includes('$') && !/^\$(?:true|false)$/i.test(value)) return true;
  return false;
}

/**
 * A3 rules (i) to (iv) for one command whose program is a delete verb. `words` are its arguments (null = not a literal:
 * a variable, a substitution, several values). True = stop: pipeline input, a recursion marker, an option outside the
 * known non-recursive set, or an argument that is not a plain literal (a `$` expression, a splat, a backtick, `%VAR%`,
 * `!VAR!`, a script block).
 */
export function windowsDeleteStops(words: ReadonlyArray<string | null>, piped: boolean): boolean {
  if (piped) return true;
  let targets = 0;
  for (const raw of words) {
    const k = deleteWordClass(raw);
    if (k === DELETE_WORD_STOPS) return true;
    if (k === DELETE_WORD_TARGET) targets += 1;
  }
  // A delete with no target at all gets its target from somewhere the text does not show (a splat, a default parameter value).
  return targets === 0;
}

// How one argument of a delete verb counts: nothing (a blank piece, a safe option), a target, or a stop on its own.
const DELETE_WORD_SKIP = 0;
const DELETE_WORD_TARGET = 1;
const DELETE_WORD_STOPS = 2;
function deleteWordClass(raw: string | null): 0 | 1 | 2 {
  if (raw === null) return DELETE_WORD_STOPS;
  const t = psNormalize(raw);
  if (t === '' || t === '}') return DELETE_WORD_SKIP; // a lone `}` is the end of a script block that bash read as a word
  if (/[`%!{}]/.test(t) || t[0] === '@') return DELETE_WORD_STOPS;
  if (t[0] === '-' || t[0] === '/') return deleteOptionStops(t) ? DELETE_WORD_STOPS : DELETE_WORD_SKIP;
  if (t.includes('$')) return DELETE_WORD_STOPS;
  return DELETE_WORD_TARGET;
}

/**
 * `windowsDeleteStops(words.slice(p + 1), piped && p === 0)` for every p, from one pass over `words`. A suffix stops when
 * it holds a word that stops on its own or no target at all, so the last word of each kind answers every p. The result is
 * a function of p; each call is constant time.
 */
export function windowsDeleteStopsFrom(words: ReadonlyArray<string>, pipedFirst: boolean): (p: number) => boolean {
  let lastStop = -1;
  let lastTarget = -1;
  for (let i = 0; i < words.length; i += 1) {
    const k = deleteWordClass(words[i]);
    if (k === DELETE_WORD_STOPS) lastStop = i;
    else if (k === DELETE_WORD_TARGET) lastTarget = i;
  }
  return (p) => (pipedFirst && p === 0) || lastStop > p || lastTarget <= p;
}

// A delete verb anywhere in text bash could not read (rule vi). A verb is a whole word that does not continue a name,
// a variable or a path component (the text had its backticks and carets removed first).
export const WIN_DELETE_WORDS = /(?<![\w.$-])(?:remove-item|ri|rm|rmdir|rd|del|erase)(?![\w-])/i;
// Outside PowerShell / cmd text only the unambiguous cmdlet name counts, and only as the start of a statement, when bash
// cannot read the text (a commit message that quotes it is not a command).
export const WIN_CMDLET_WORD = /(?:^|[\n;|&(]|&&|\|\|)[ \t]*(?:remove-item)(?![\w-])/i;
export const PS_EVAL_WORDS = /(?:^|[\n;|(]|&&|\|\|)[ \t]*(?:iex|invoke-expression)(?![\w-])/i;
// `& $cmd`, `& (expr)`, `& @args` at the start of a statement (and `. $x` in PowerShell text): code that is not a literal.
export const PS_DYNAMIC_CALL = /(?:^|[\n;|(]|&&|\|\|)[ \t]*(?:&[ \t]*(?:[$(@]|"[^"\n]{0,300}\$)|\.[ \t]+(?:[$(@]|"[^"\n]{0,300}\$))/;
export const PS_DYNAMIC_AMP = /(?:^|[\n;|(]|&&|\|\|)[ \t]*&[ \t]*(?:[$(@]|"[^"\n]{0,300}\$)/;
// A script block called with `&` or `.` at the start of a statement: PowerShell, never bash.
export const PS_BLOCK_CALL = /(?:^|[\n;|(]|&&|\|\|)[ \t]*[&.][ \t]*\{/;
// Plain shell text that looks like PowerShell with script blocks: its blocks are read as statements too (a probe).
export const PS_SNIFF = /remove-item|foreach-object|where-object|invoke-command|-scriptblock|get-childitem|%[ \t]*\{|(?:^|[\n;&|(])[ \t]*(?:rd|rmdir|del|erase|cmd)[/,;=]|(?:^|[\n;|(]|&&|\|\|)[ \t]*[&.][ \t]*\{/i;

/**
 * .NET and COM deletes of a whole tree (rule v). The text is lower-cased with all white space removed, so padding and
 * spacing change nothing. `strict` (PowerShell / cmd text) also stops `.Delete(<anything but $false/0/false>)`; outside
 * it only the PowerShell-only forms count, so a C# search for `.Delete(true)` keeps its answer.
 */
export function dotNetTreeDelete(text: string, strict: boolean): boolean {
  const t = text.toLowerCase().replace(/\s+/g, '');
  if (t.includes('directory]::delete') || t.includes('::deletedirectory') || t.includes('deletefolder(')) return true;
  // A member name that is built at run time (`[IO.Directory]::('De'+'lete')`, `[IO.Directory]::$m`).
  if (t.includes('directory]::(') || t.includes('directory]::$')) return true;
  if (/\.delete\(\$(?!false)/.test(t)) return true;
  if (!strict) return false;
  // Any delete call next to a walk of the tree in the same text (the analog of `find -delete`), and FileSystemObject.DeleteFile.
  if (t.includes('.deletefile(') || t.includes('.deletefile"') || t.includes(".deletefile'") || t.includes('.deletefolder"') || t.includes(".deletefolder'")) return true; // VBScript may leave out the parentheses
  if ((t.includes('.delete(') || t.includes('::delete(')) && ['get-childitem', 'gci', '-recurse', 'foreach', '|%', '%{', 'while(', 'for('].some((w) => t.includes(w))) return true;
  if (t.includes('::delete') && t.includes('directory')) return true;
  if (t.includes('directory') && t.includes('getmethod') && t.includes('delete')) return true;
  for (const m of t.matchAll(/\.delete\(([^)]{0,16})/g)) if (m[1] !== '' && !/^(?:\$false|0|false)$/.test(m[1])) return true;
  return false;
}

// powershell.exe / pwsh options. A prefix of -Command is -Command (-c, -co, -com ...). -e* is -EncodedCommand, except
// -ex* (ExecutionPolicy) and its alias -ep, which stays a policy only while its value is one.
export type PsOptionKind = 'command' | 'encoded' | 'file' | 'value' | 'flag';
const PS_VALUE_OPTIONS = ['windowstyle', 'executionpolicy', 'inputformat', 'outputformat', 'version', 'workingdirectory', 'wd',
  'configurationname', 'settingsfile', 'custompipename'];
export function psOption(raw: string): { kind: PsOptionKind; name: string; attached: string | null } | null {
  const word = psNormalize(raw);
  if (word.length < 2 || (word[0] !== '-' && word[0] !== '/')) return null;
  const colon = word.indexOf(':');
  const name = (colon > 0 ? word.slice(1, colon) : word.slice(1)).toLowerCase();
  const attached = colon > 0 ? word.slice(colon + 1) : null;
  if (!/^[a-z?]+$/.test(name)) return null;
  let kind: PsOptionKind = 'flag';
  // Every -c* parameter carries code (-Command, -CommandWithArgs, -cwa, any prefix); -conf* and -cu* (pipe name) take a value.
  if (name[0] === 'c' && !name.startsWith('conf') && !name.startsWith('cu')) kind = 'command';
  else if (name === 'ep') kind = 'value';
  else if (name[0] === 'e' && !name.startsWith('ex')) kind = 'encoded';
  else if ('file'.startsWith(name)) kind = 'file';
  else if (PS_VALUE_OPTIONS.some((v) => v.startsWith(name))) kind = 'value';
  return { kind, name, attached };
}
export const PS_EXECUTION_POLICIES = /^(?:bypass|unrestricted|remotesigned|allsigned|restricted|undefined|default)$/i;

/** The text of a base64 UTF-16LE -EncodedCommand value, or null when it cannot be read (the caller then stops). */
export function decodeEncodedCommand(value: string): string | null {
  const compact = value.replace(/\s+/g, '');
  if (compact.length === 0 || compact.length > LIMITS.maxEncodedChars) return null;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(compact) || compact.length % 4 !== 0) return null;
  let bytes: Buffer;
  try { bytes = Buffer.from(compact, 'base64'); } catch { return null; }
  if (bytes.length === 0 || bytes.length % 2 !== 0) return null;
  const text = bytes.toString('utf16le');
  // NUL and other control characters (tab, CR and LF are fine), and the replacement character an invalid pair leaves.
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f�￾￿]/.test(text)) return null;
  return text;
}

/** PowerShell reads U+2013, U+2014 and U+2015 as the parameter dash and the smart quotes as quotes: the same text with plain ones. */
export function psNormalize(text: string): string {
  // PowerShell also reads a vertical tab, a form feed, U+00A0, U+0085 and the Unicode space separators as blanks (bash does not), and
  // U+2028 / U+2029 as line ends: every one of them becomes a plain blank or line break first.
  return text.replace(/[\u2028\u2029]/g, '\n').replace(/[\u000b\u000c\u00a0\u0085\u1680\u2000-\u200a\u202f\u205f\u3000]/g, ' ').replace(/[\u2013\u2014\u2015]/g, '-').replace(/[\u2018\u2019\u201a\u201b]/g, '\'').replace(/[\u201c\u201d\u201e]/g, '"');
}

/** PowerShell / cmd text with its escapes taken out: a backtick (PowerShell) or caret (cmd) before a line break joins the lines, any other one goes; dashes and quotes plain. */
export function psClean(text: string): string {
  return psNormalize(text.replace(/[`^]\r?\n/g, ' ').replace(/[`^]/g, ''));
}

/**
 * The same PowerShell / cmd text with its block braces turned into line breaks and its call operators dropped, so
 * `& { ri -r x }`, `Invoke-Command -ScriptBlock { rd /s x }` and `% { rm $_ }` show their bodies as commands. Quotes and
 * `${name}` are left alone. A reading for the delete checks only; it never replaces the text's own reading.
 */
export function psFlatten(text: string): string {
  let out = '';
  let quote: string | null = null;
  let braced = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (quote !== null) { out += ch; if (ch === quote) quote = null; continue; }
    if (braced) { out += ch; if (ch === '}') braced = false; continue; }
    if (ch === '\'' || ch === '"') { quote = ch; out += ch; continue; }
    if (ch === '$' && text[i + 1] === '{') { braced = true; out += '${'; i += 1; continue; }
    out += ch === '{' || ch === '}' ? '\n' : ch;
  }
  return out.replace(/(^|[\n;|(]|&&|\|\|)([ \t]*)(?:&[ \t]*|\.[ \t]+)(?=[^\s&])/g, '$1$2').replace(/(^|[\n;|(]|&&|\|\|)([ \t]*)[&.][ \t]*(?=\n|$)/g, '$1$2');
}

// PowerShell text that builds or runs code from pieces, and the settings that change what a plain command does. Only the
// PowerShell / cmd context looks at it: `$PSDefaultParameterValues['Remove-Item:Recurse']=$true` makes `Remove-Item C:\x`
// recursive, and `[scriptblock]::Create($s).Invoke()` is code nobody can read.
export function psDynamicCode(text: string): boolean {
  const t = text.toLowerCase();
  const c = t.replace(/\s+/g, '');
  if (c.includes('[scriptblock]::create') || c.includes('.invoke(') || c.includes('executioncontext.invokecommand') || c.includes('add-type')) return true;
  // COM objects that start programs (`WScript.Shell`.Run, `Shell.Application`.ShellExecute).
  if (c.includes('wscript.shell') || c.includes('shell.application') || c.includes('.shellexecute(')) return true;
  if (/(?:^|[\n;|(]|&&|\|\|)[ \t]*(?:invoke-command|icm)(?![\w-])[^\n;|]{0,1024}[ \t]-f[a-z]*(?![\w-])/.test(t)) return true;
  if (/(?:foreach-object|foreach|%)[ \t]+-m[a-z]*(?![\w-])/.test(t) || /\|[ \t]*(?:%|foreach-object|foreach)[ \t]+[a-z]/.test(t)) return true;
  return false;
}
export function psDefaultParameters(text: string): boolean { return text.toLowerCase().includes('psdefaultparametervalues'); }

// A PowerShell / cmd tokenizer, for the delete checks. Quotes hold data ('' and "" are a quote inside), `$( )` and `( )` hold
// statements of their own, and `;` `&` `&&` `|` `||` line breaks and braces end a statement. `cmd` mode reads the text as cmd
// does: `;` `,` `=` only separate words, and an internal command ends at `/` (`rd/s/q`, `cmd/c`). `ok` is false for text it
// does not read (an unterminated quote or group, a here-string, a block comment, too deep a nesting).
export interface PsStatement { words: string[]; piped: boolean }
const CMD_INTERNAL = new Set(['rd', 'rmdir', 'del', 'erase', 'rm', 'cmd', 'call', 'start']);
export const PS_KEYWORDS: ReadonlySet<string> = new Set(['if', 'for', 'foreach', 'while', 'else', 'elseif', 'do', 'then', 'call', 'start', 'switch', 'try', 'catch', 'finally', '%', 'foreach-object']);

function splitInternal(words: string[]): string[] {
  const first = words[0];
  const at = first.indexOf('/');
  if (at <= 0) return words;
  const head = first.slice(0, at);
  if (!CMD_INTERNAL.has(head.toLowerCase().replace(/\.(?:exe|cmd|bat|com)$/, ''))) return words;
  return [head, ...first.slice(at).split(/(?=\/)/), ...words.slice(1)];
}

export function psStatements(text: string, cmd: boolean): { statements: PsStatement[]; ok: boolean } {
  const out: PsStatement[] = [];
  let ok = true;
  const scan = (start: number, closer: boolean, depth: number): number => {
    let words: string[] = [];
    let cur = '';
    let has = false;
    let piped = false;
    let i = start;
    const endWord = () => { if (has) words.push(cur); cur = ''; has = false; };
    const endStmt = (pipe: boolean) => {
      endWord();
      // cmd: a leading `@` (echo off for this command) is no part of the command name.
      if (cmd && words.length && /^@+/.test(words[0])) { words[0] = words[0].replace(/^@+/, ''); if (words[0] === '') words.shift(); }
      if (words.length) out.push({ words: cmd ? splitInternal(words) : words, piped });
      words = [];
      piped = pipe;
    };
    while (i < text.length) {
      const ch = text[i];
      if (ch === '"' || (ch === '\'' && !cmd)) {
        has = true;
        i += 1;
        let closed = false;
        while (i < text.length) {
          const c = text[i];
          if (c === ch) { if (text[i + 1] === ch) { cur += ch; i += 2; continue; } closed = true; break; }
          if (c === '`' && ch === '"' && !cmd && i + 1 < text.length) { cur += text[i + 1]; i += 2; continue; } // `" is a quote character inside the string
          if (ch === '"' && c === '$' && text[i + 1] === '(') {
            cur += '$';
            if (depth >= 20) { ok = false; return text.length; }
            i = scan(i + 2, true, depth + 1);
            continue;
          }
          cur += c;
          i += 1;
        }
        if (!closed) ok = false;
        i += 1;
        continue;
      }
      if ((ch === '`' && !cmd) || (ch === '^' && cmd)) {
        // The escape character: a line break after it joins the lines; any other character after it is plain text (a quote or `&` too).
        const nx = text[i + 1];
        if (nx === undefined) { i += 1; continue; }
        if (nx === '\n' || nx === '\r') { endWord(); i += nx === '\r' && text[i + 2] === '\n' ? 3 : 2; continue; }
        cur += nx;
        has = true;
        i += 2;
        continue;
      }
      if (ch === ' ' || ch === '\t' || ch === ',' || ch === '=') { endWord(); i += 1; continue; }
      if (ch === '\n' || ch === '\r' || ch === '{' || ch === '}') { endStmt(false); i += 1; continue; }
      if (ch === ';') { if (cmd) endWord(); else endStmt(false); i += 1; continue; }
      if (ch === '|') { if (text[i + 1] === '|') { endStmt(false); i += 2; } else { endStmt(true); i += 1; } continue; }
      if (ch === '&') {
        if (text[i + 1] === '&') { endStmt(false); i += 2; continue; }
        if (words.length === 0 && !has) { i += 1; continue; } // the call operator
        endStmt(false);
        i += 1;
        continue;
      }
      if (ch === '(') {
        if (depth >= 20) { ok = false; return text.length; }
        // The group is part of the current word (an expression, not a literal): a `$` in the word says so.
        if (!cur.endsWith('$')) cur += '$';
        has = true;
        i = scan(i + 1, true, depth + 1);
        continue;
      }
      if (ch === ')') {
        if (closer) { endStmt(false); return i + 1; }
        endStmt(false);
        i += 1;
        continue;
      }
      if (ch === '#' && !has && !cmd) { while (i < text.length && text[i] !== '\n') i += 1; continue; }
      if (ch === '<' && text[i + 1] === '#') { ok = false; i += 2; continue; }
      if (ch === '@' && (text[i + 1] === '\'' || text[i + 1] === '"') && !has) { ok = false; }
      cur += ch;
      has = true;
      i += 1;
    }
    if (closer) ok = false;
    endStmt(false);
    return i;
  };
  scan(0, false, 0);
  return { statements: out, ok };
}

// PowerShell cmdlets that print or read text and run none of it. A string argument of one is still read as a command line by
// the usual unknown-program scan (so `Write-Host "npm publish"` keeps its stop), but a delete verb inside it is no A3 stop.
export const PS_OUTPUT_CMDLETS: ReadonlySet<string> = new Set(['write-host', 'write-output', 'write-verbose', 'write-warning', 'write-error', 'write-debug',
  'write-information', 'select-string', 'get-content', 'out-string', 'out-host', 'out-null', 'get-help', 'measure-object']);
// PowerShell statement keywords and block cmdlets: bash reads their script blocks as their arguments. In PowerShell text those
// arguments are scanned as before, but a delete verb found in them is no A3 stop (the blocks are read as statements by the
// lexical check and the flattened reading, where each command has its real owner).
export const PS_BLOCK_WORDS: ReadonlySet<string> = new Set(['try', 'catch', 'finally', 'if', 'elseif', 'else', 'foreach', 'for', 'while', 'do', 'switch',
  'foreach-object', 'where-object', '%', '?']);
