"use strict";
// Seatbelt rule tables (spec SEATBELT-SPEC.md §1.2 as amended by the owner decisions of 2026-10-12).
// Compiled into the package on purpose: no local file can extend or relax them (spec §2.1.7).
Object.defineProperty(exports, "__esModule", { value: true });
exports.CWD_KEYS = exports.ENV_KEYS = exports.TERMINAL_TEXT_KEYS = exports.GH_HEAD_SAFE = exports.HEAD_CHANGERS = exports.HEAD_RUNNERS = exports.BUILD_TOOLS = exports.TERMINAL_SEGMENTS = exports.STDIN_KEYS = exports.CODE_KEYS = exports.ARGV_STRICT = exports.ARGV_SEGMENTS = exports.ARGV_KEYS = exports.COMMAND_KEYS = exports.FILE_TOOL_NAMES = exports.SHELL_TOOL_NAMES = exports.GIT_CONFIG_ENV_FILES = exports.GIT_CONFIG_INCLUDE = exports.GIT_EXEC_CONFIG = exports.NPM_BOOL_FLAGS = exports.NPM_VALUE_FLAGS = exports.NPM_ALIASES = exports.NPM_COMMANDS = exports.EVAL_PRODUCERS = exports.NON_SCRIPT_NAMES = exports.SCRIPT_SUFFIX = exports.INERT_PROGRAMS = exports.KNOWN_COMMANDS = exports.NAME_TRIPWIRE = exports.TRIPWIRE = exports.GIT_PUSH_RISKY_LONG = exports.GIT_PUSH_LONG = exports.GIT_BUILTINS = exports.PACKAGE_BINS = exports.MARROW_OWNER_SUBS = exports.INTERPRETER_EXEC = exports.INTERPRETERS = exports.SHELLS = exports.GIT_S4_EXEMPT_SUBS = exports.S4_EXEMPT_PROGRAMS = exports.PROD_ENV = exports.SECRET_VAR = exports.SSH_PUBLIC = exports.ENV_TEMPLATE_SUFFIX = exports.KEY_FIXTURE_SEGMENTS = exports.KEY_EXTENSIONS = exports.SECRET_PATTERNS = exports.PRESENT_SECRET_PATTERNS = exports.LIMITS = exports.SEATBELT_RULES_VERSION = void 0;
exports.LANGUAGE_KEYS = exports.OPTION_OBJECT_KEYS = void 0;
exports.secretSamples = secretSamples;
exports.interpreterTreeDelete = interpreterTreeDelete;
exports.interpreterDecodeToken = interpreterDecodeToken;
exports.commandLikeKey = commandLikeKey;
exports.codeLikeKey = codeLikeKey;
exports.SEATBELT_RULES_VERSION = 'marrow.seatbelt.rules.v1';
// Budgets. A command that exceeds ANY budget stops (never passes): padding, deep nesting, wide
// fan-out and slow repositories must not turn into "pass" (audit F3, F10).
exports.LIMITS = Object.freeze({
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
});
// S4 secret paths: one table with the keyed policy (src/secret-paths.ts).
var secret_paths_1 = require("../secret-paths");
Object.defineProperty(exports, "PRESENT_SECRET_PATTERNS", { enumerable: true, get: function () { return secret_paths_1.PRESENT_SECRET_PATTERNS; } });
Object.defineProperty(exports, "SECRET_PATTERNS", { enumerable: true, get: function () { return secret_paths_1.SECRET_PATTERNS; } });
// Key material by extension, except under node_modules or test fixture folders.
exports.KEY_EXTENSIONS = /\.(?:pem|key|p12|pfx)$/;
exports.KEY_FIXTURE_SEGMENTS = new Set(['node_modules', 'fixtures', '__fixtures__', 'testdata', 'test', 'tests', '__tests__']);
// Q3: only these .env templates are excepted. Never widen this to other .env files.
exports.ENV_TEMPLATE_SUFFIX = /\.(?:example|sample|template)$/;
// ssh public keys and ssh metadata are never secret.
exports.SSH_PUBLIC = /\.pub$/;
// Concrete examples of every secret pattern, used to judge glob and partly dynamic operands
// (a glob or "$X/.env" is a stop when it can expand to one of these).
function secretSamples(home, cwds) {
    const h = home.replace(/\/$/, '');
    const out = [
        `${h}/.ssh/id_rsa`, `${h}/.ssh/id_ed25519`, `${h}/.ssh/id_ecdsa`, `${h}/.ssh/id_dsa`, `${h}/.ssh/deploy_key`,
        `${h}/.aws/credentials`, `${h}/.aws/sso/cache/token.json`, `${h}/.config/gcloud/application_default_credentials.json`,
        `${h}/.config/gcloud/credentials.db`, `${h}/.config/gcloud/access_tokens.db`, `${h}/.azure/accessTokens.json`,
        `${h}/.kube/config`, `${h}/.docker/config.json`, `${h}/.npmrc`, `${h}/.pypirc`, `${h}/.netrc`, `${h}/.git-credentials`,
        `${h}/.config/gh/hosts.yml`, `${h}/.config/op/config`, `${h}/.gnupg/private-keys-v1.d/k.key`, `${h}/.marrow/env`,
        `${h}/.marrow/env.local`, `${h}/.claude.json`, `${h}/.claude/settings.local.json`, '/proc/self/environ', '/proc/1/environ',
        `${h}/.env`, '/root/.ssh/id_rsa', '/root/.aws/credentials', `${h}/.marrow/seatbelt/salt`,
        `${h}/.marrow/fleet.env`, `${h}/.marrow/credentials/k`,
    ];
    for (const c of cwds) {
        const d = c.replace(/\/$/, '');
        out.push(`${d}/.env`, `${d}/.env.local`, `${d}/.env.production`, `${d}/app/.env`, `${d}/app.env`, `${d}/.dev.vars`, `${d}/server.pem`, `${d}/tls.key`, `${d}/cert.p12`, `${d}/cert.pfx`, `${d}/.claude/settings.local.json`, `${d}/.npmrc`);
    }
    return out;
}
exports.SECRET_VAR = /KEY|TOKEN|SECRET|PASS|CRED/i;
// Protected-branch baseline (classifier policy-baseline protected_branches; same list as spec §1.2).
exports.PROD_ENV = /(?:^|[^a-z0-9])(?:prod|production|live|main)(?:[^a-z0-9]|$)/i;
// Programs that take a path operand without printing or copying its content (S4 does not apply).
exports.S4_EXEMPT_PROGRAMS = new Set([
    'ls', 'stat', 'test', '[', '[[', 'du', 'chmod', 'chown', 'chgrp', 'touch', 'mkdir', 'rm', 'rmdir', 'unlink',
    'ssh', 'ssh-add', 'sftp', 'realpath', 'readlink', 'dirname', 'basename', 'echo', 'which', 'type', 'find', 'wc',
    'kubectl', 'helm', 'cd', 'pushd', 'shred', 'file',
]);
exports.GIT_S4_EXEMPT_SUBS = new Set(['rm', 'check-ignore', 'check-attr', 'ls-files', 'status', 'log', 'restore']);
exports.SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'ash', 'mksh', 'yash', 'rbash', 'csh', 'tcsh']);
exports.INTERPRETERS = new Set(['python', 'python2', 'python3', 'node', 'nodejs', 'ruby', 'perl', 'php', 'deno', 'bun', 'lua', 'pwsh', 'powershell', 'osascript', 'tclsh', 'irb', 'ipython',
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
function interpreterTreeDelete(code) {
    if (INTERPRETER_TREE_DELETE_WORDS.test(code))
        return true;
    if (code.includes('recursive') && DELETE_CALL.test(code))
        return true;
    if (WALK_WORD.test(code) && FILE_DELETE_CALL.test(code))
        return true;
    // `Remove-Item … -Recurse` on one line.
    for (const line of code.split('\n')) {
        const at = line.toLowerCase().indexOf('remove-item');
        if (at >= 0 && line.toLowerCase().indexOf('-recurse', at + 11) >= 0)
            return true;
    }
    return false;
}
function interpreterDecodeToken(code) {
    // `Buffer.from(x, enc).toString()` turns bytes into text whatever the encoding is called.
    return INTERPRETER_DECODE_WORDS.test(code) || (BUFFER_CALL.test(code) && (ENCODING_LITERAL.test(code) || /\.toString\s*\(/.test(code)));
}
exports.INTERPRETER_EXEC = /\bexec\b|\beval\b|\bFunction\s*\(|\bsystem\b|popen|spawn|execSync|execFile|child_process|subprocess|\bcompile\s*\(|`/;
// Owner-only commands an agent must never run (S0).
exports.MARROW_OWNER_SUBS = new Set(['claim', 'unclaim', 'control', 'uninstall']);
// npm-style package names to the binary they run.
exports.PACKAGE_BINS = {
    '@changesets/cli': 'changeset', 'netlify-cli': 'netlify', 'firebase-tools': 'firebase', 'aws-cdk': 'cdk',
    '@vscode/vsce': 'vsce', vsce: 'vsce', ovsx: 'ovsx', vercel: 'vercel', wrangler: 'wrangler', np: 'np',
    'release-it': 'release-it', 'semantic-release': 'semantic-release', lerna: 'lerna', serverless: 'serverless',
    sst: 'sst', rimraf: 'rimraf', '@railway/cli': 'railway', 'heroku': 'heroku',
};
// Git builtin subcommands: git ignores an alias that has a builtin name.
exports.GIT_BUILTINS = new Set(('add am annotate apply archive bisect blame branch bundle cat-file check-attr check-ignore '
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
exports.GIT_PUSH_LONG = [
    'force', 'force-with-lease', 'force-if-includes', 'mirror', 'delete', 'all', 'branches', 'prune', 'tags', 'follow-tags',
    'dry-run', 'porcelain', 'verbose', 'quiet', 'progress', 'no-verify', 'verify', 'atomic', 'no-atomic', 'set-upstream',
    'signed', 'no-signed', 'push-option', 'repo', 'receive-pack', 'exec', 'thin', 'no-thin', 'ipv4', 'ipv6',
    'recurse-submodules', 'no-recurse-submodules', 'no-force-with-lease', 'no-force-if-includes', 'no-progress',
];
exports.GIT_PUSH_RISKY_LONG = {
    force: 'force', 'force-with-lease': 'force', 'force-if-includes': 'force', mirror: 'mirror', delete: 'delete',
    all: 'all', branches: 'all', prune: 'prune',
};
// Lexical tripwire (spec §2.1.3). Matched case-insensitively after removing quotes and backslashes.
exports.TRIPWIRE = [
    { re: /\bpush\b[^;&|\n]{0,200}?(?:\s-[a-z0-9]*f|force|\s\+|--mirror|--delete|\s-d\b|\s:)/, category: 'S1', reason: 'tripwire_force_push' },
    { re: /publish/, category: 'S3', reason: 'tripwire_publish' },
    { re: /deploy|--prod\b/, category: 'S2', reason: 'tripwire_deploy' },
    { re: /\.ssh\b|id_rsa|id_ed25519|id_ecdsa|\.aws\b|\.npmrc|\.netrc|\.pypirc|\.git-credentials|\.docker\/config|\.kube\/config|gh\/hosts\.yml|\.gnupg|\.claude\.json|settings\.local\.json|\/environ\b|\.dev\.vars|\.pem\b|\.p12\b|\.pfx\b|\.marrow\/env|\.marrow\/seatbelt\/salt/, category: 'S4', reason: 'tripwire_secret_path' },
    { re: /(?:^|[^a-z0-9_$)\].])\.env(?![a-z0-9_])(?!\.(?:example|sample|template)\b)/, category: 'S4', reason: 'tripwire_env_file' },
    { re: /printenv|export\s+-p|declare\s+-[a-z]*[xp]|(?:^|[;&|({\s])(?:env|set|export)\s*(?:$|[;&|)}])|auth\s+token|print-(?:access|identity)-token|get-session-token|get-access-token|auth:token|find-(?:generic|internet)-password|secret-tool|op\s+read|vault\s+(?:kv|read)|pass\s+show|token\s+list|(?:process\.env|os\.environ|\$env|env\.to_h|system\.getenv\(\))\s*(?:\)|;|$|\||,|\.items|\.keys|\.copy)|(?:environ|\benv)\W{0,3}[a-z_]{0,256}(?:key|token|secret|pass|cred)|\$\{?!?[a-z_]{0,256}(?:key|token|secret|pass|cred)/, category: 'S4', reason: 'tripwire_secret_dumper' },
    { re: /rmtree|rmsync|rmdirsync|rimraf|rm_rf|\brm_r\b|mkfs/, category: 'S5', reason: 'tripwire_recursive_delete' },
    { re: /\.marrow|@getmarrow|settings\.json|hooks\.json|\.mcp\.json|\.bashrc|\.zshrc|\.bash_profile|\.zprofile|\.zshenv|\.profile\b/, category: 'S0', reason: 'tripwire_self_protection' },
    // NEW-1: the Marrow plugins named in code or text the mapper cannot follow (`python3 -c "open('…/installed_plugins.json','w')"`).
    { re: /installed_plugins\.json|known_marketplaces\.json|plugins\/(?:cache|marketplaces)\/getmarrow|\.claude\/plugins\/\S{0,200}marrow|\.cursor\/plugins|marrow-launch\.cjs/, category: 'S0', reason: 'tripwire_plugin_protection' },
    { re: /base64\s+(?:-[a-z]*d|--decode)|xxd\s+-[a-z]*r|b64decode|atob\s*\(/, category: 'Sx', reason: 'tripwire_decoded_exec' },
];
// Script, Makefile-target and package-script names that trip when their content cannot be read.
exports.NAME_TRIPWIRE = /publish|deploy|release|ship|prod/i;
// ---------------------------------------------------------------------------------------------
// Unknown wrappers (audit F1). A program the mapper has no handler for is not "harmless": its argv
// may hold a command (`strace npm publish`, `tmux new -d 'npm publish'`). Only programs in
// INERT_PROGRAMS (text, file and info tools whose arguments are never run) skip the argv scan.
// Every program name the dispatcher has a handler for. test/seatbelt-audit-regression.test.js checks
// that each `case '<name>'` in mapper.ts is listed, so a tail-position scan sees every handler.
exports.KNOWN_COMMANDS = new Set([
    'cd', 'pushd', 'popd', 'alias', 'export', 'declare', 'typeset', 'readonly', 'local', 'set', 'unset', 'printenv', 'echo', 'printf',
    'print', 'eval', 'source', '.', 'env', 'sudo', 'doas', 'pkexec', 'runas', 'su', 'timeout', 'nice', 'nohup', 'time', 'command',
    'builtin', 'exec', 'stdbuf', 'ionice', 'chrt', 'taskset', 'setsid', 'unbuffer', 'caffeinate', 'retry', 'flock', 'xargs', 'parallel',
    'watch', 'ssh', 'git', 'gh', 'npm', 'pnpm', 'yarn', 'bun', 'npx', 'bunx', 'corepack', 'make', 'gmake', 'rm', 'rimraf', 'rmdir', 'find',
    'rsync', 'shred', 'dd', 'docker', 'podman', 'kubectl', 'helm', 'marrow', 'marrow-install', 'claude', 'apply_patch', 'applypatch',
    'patch', 'git-apply', 'git-am', 'trap', 'script', 'cpio', 'pax', 'read', 'mapfile', 'readarray', 'getopts', 'busybox', 'toybox', 'concurrently', 'npm-run-all', 'npm-run-all2', 'run-s', 'run-p', 'railway',
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
]);
// Programs whose arguments are text, patterns or paths and are never run. Their argv is not scanned
// for a command. A program with an exec-capable flag (find -exec, xargs, tar --to-command) is not
// listed here; it has a handler or is scanned.
exports.INERT_PROGRAMS = new Set([
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
exports.SCRIPT_SUFFIX = /\.(?:sh|bash|zsh|ksh|command)$/;
exports.NON_SCRIPT_NAMES = new Set(['makefile', 'gnumakefile', 'dockerfile', 'readme', 'license', 'licence', 'changelog', 'procfile', 'gemfile', 'rakefile', 'vagrantfile', 'jenkinsfile']);
// `eval "$(<producer> …)"` forms that only print shell variable assignments.
exports.EVAL_PRODUCERS = new Set(['ssh-agent', 'direnv', 'opam', 'pyenv', 'rbenv', 'nodenv', 'jenv', 'goenv', 'fnm', 'zoxide', 'starship',
    'mise', 'asdf', 'volta', 'dircolors', 'keychain', 'gpg-agent', 'lesspipe', 'lesspipe.sh', 'thefuck', 'conda', 'micromamba', 'luarocks', 'cs']);
// ---------------------------------------------------------------------------------------------
// npm subcommand resolution (audit F5). Same tables as npm 10 lib/utils/cmd-list.js; the lookup
// below keeps every reading an abbreviation can have (ambiguous prefixes included), so a prefix that
// could be publish is treated as publish.
exports.NPM_COMMANDS = ['access', 'adduser', 'audit', 'bugs', 'cache', 'ci', 'completion', 'config', 'dedupe', 'deprecate', 'diff',
    'dist-tag', 'docs', 'doctor', 'edit', 'exec', 'explain', 'explore', 'find-dupes', 'fund', 'get', 'help', 'help-search', 'hook', 'init',
    'install', 'install-ci-test', 'install-test', 'link', 'll', 'login', 'logout', 'ls', 'org', 'outdated', 'owner', 'pack', 'ping', 'pkg',
    'prefix', 'profile', 'prune', 'publish', 'query', 'rebuild', 'repo', 'restart', 'root', 'run-script', 'sbom', 'search', 'set',
    'shrinkwrap', 'star', 'stars', 'start', 'stop', 'team', 'test', 'token', 'uninstall', 'unpublish', 'unstar', 'update', 'version',
    'view', 'whoami',
    // older and newer npm releases
    'bin', 'birthday', 'cit', 'dist-tags', 'install-clean', 'issues', 'rum', 'unpkg', 'xmas', 'config-set', 'ddp', 'hlep'];
exports.NPM_ALIASES = {
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
exports.NPM_VALUE_FLAGS = new Set(['-w', '--workspace', '--prefix', '-C', '--dir', '--filter', '-F', '--cwd', '--tag', '--access',
    '--otp', '--registry', '--cache', '--loglevel', '--userconfig', '--globalconfig', '--scope', '--location', '--omit', '--include',
    '--before', '--min-release-age', '--install-strategy', '--workspaces-update', '--package', '-p', '--call', '-c', '--node-options',
    '--script-shell', '--foreground-scripts-value', '--logs-dir', '--logs-max', '--otp-value', '--init-module', '--fetch-retries',
    '--maxsockets', '--proxy', '--https-proxy', '--noproxy', '--cafile', '--tag-version-prefix', '--message', '-m', '--depth',
    '--engine-strict-value', '--cpu', '--os', '--libc', '--jsonfile']);
// Global options that never take a value.
exports.NPM_BOOL_FLAGS = new Set(['-g', '--global', '-S', '--save', '-D', '--save-dev', '-O', '--save-optional', '-E', '--save-exact',
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
exports.GIT_EXEC_CONFIG = /^(?:core\.(?:sshcommand|pager|editor|fsmonitor|hookspath|gitproxy|askpass)|sequence\.editor|diff\.external|diff\..+\.(?:command|textconv)|merge\..+\.driver|filter\..+\.(?:clean|smudge|process)|credential(?:\..+)?\.helper|pager\..+|gpg(?:\..+)?\.program|uploadpack\.packobjectshook|remote\..+\.(?:receivepack|uploadpack|vcs)|submodule\..+\.update|alias\..+)$/;
// Config keys that redirect or extend where git reads configuration from.
exports.GIT_CONFIG_INCLUDE = /^(?:include\.path|includeif\..+\.path)$/;
// Environment variables that redirect git's configuration files.
exports.GIT_CONFIG_ENV_FILES = ['GIT_CONFIG', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM'];
// ---------------------------------------------------------------------------------------------
// Tools that run a shell command (audit F11).
// Names (lower-cased) of tools whose input is a shell command. Any other tool is scanned too: an
// input field named like COMMAND_KEYS is a shell command wherever it sits (top level or nested).
exports.SHELL_TOOL_NAMES = new Set(['bash', 'shell', 'local_shell', 'exec_command', 'container.exec', 'run_terminal_command',
    'run_terminal_cmd', 'execute_command', 'run_shell_command', 'run_command', 'terminal', 'shell_command', 'bash_command', 'execute_bash',
    'run_bash', 'bashtool', 'bash_tool', 'powershell', 'run_in_terminal', 'terminal_command', 'exec', 'sh', 'zsh', 'cmd', 'command',
    'developer__shell', 'run_shell', 'shell_exec', 'execute_shell', 'process']);
// Tools with their own handling (file read, search, write); `command` there is not a shell string.
exports.FILE_TOOL_NAMES = new Set(['read', 'notebookread', 'read_file', 'view', 'view_file', 'grep', 'grep_files', 'search', 'rg',
    'write', 'edit', 'multiedit', 'notebookedit', 'write_file', 'create_file', 'str_replace_editor', 'str_replace_based_edit_tool',
    'apply_patch', 'edit_file', 'glob', 'ls', 'list_dir', 'list_directory']);
// Input field names (lower-cased) that hold a shell command, script or argv.
exports.COMMAND_KEYS = new Set(['command', 'cmd', 'commandline', 'command_line', 'cmdline', 'cmd_line', 'shell_command', 'shellcommand',
    'bash_command', 'script', 'shell', 'bash', 'sh', 'exec', 'run', 'execute', 'argv', 'commands', 'cmds',
    // audit N4: argv-style tools and string-named variants
    'program', 'executable', 'exe', 'binary', 'bin', 'shell_cmd', 'shellcmd', 'cmdstring', 'cmd_string', 'command_string', 'commandstring', 'cmdstr',
    'cmd_str', 'command_text', 'commandtext', 'cmd_text', 'shell_script', 'bash_script', 'script_text']);
// A field name that is not listed above but names a command by word: `cmdString`, `my_shell_cmd`,
// `run_command`. Matched on name segments, so `description` is not `script`.
const COMMAND_SEGMENTS = new Set(['cmd', 'cmds', 'command', 'commands', 'shell', 'bash', 'zsh', 'script', 'scripts', 'exec', 'execute', 'argv', 'commandline',
    'cmdline', 'program', 'executable', 'binary', 'bin', 'cmdstring']);
function commandLikeKey(raw) {
    return raw.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/).some((s) => COMMAND_SEGMENTS.has(s));
}
// Companion argument-vector fields next to a `command` string (MCP exec servers: {command:'git', args:[…]}).
exports.ARGV_KEYS = new Set(['args', 'argv', 'arguments', 'params', 'argument']);
exports.ARGV_SEGMENTS = new Set(['args', 'argv', 'arguments', 'params', 'parameters', 'argument', 'arg', 'arg1', 'arg2', 'arg3', 'operands', 'operand', 'options', 'option', 'flags', 'flag', 'subcommand',
    'subcommands', 'positional', 'positionals', 'opts', 'rest', 'remaining', 'tail', 'more']);
// The argument-list names whose value must be a list or text; any other shape is unknown.
exports.ARGV_STRICT = new Set(['args', 'argv', 'arguments', 'params', 'parameters', 'argument']);
// Fields that hold interpreter code (scanned like `node -e`).
exports.CODE_KEYS = new Set(['code', 'python', 'javascript', 'js', 'node', 'ruby', 'perl', 'php', 'python_code', 'source_code',
    // audit N4
    'source', 'snippet', 'code_snippet', 'script_source', 'python_script', 'js_code', 'javascript_code', 'node_code', 'ruby_code',
    'perl_code', 'php_code']);
const CODE_SEGMENTS = new Set(['code', 'python', 'javascript', 'js', 'ruby', 'perl', 'php', 'snippet', 'source', 'py', 'rb', 'lua', 'ts', 'typescript']);
function codeLikeKey(raw) {
    const segs = raw.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/);
    // `source_path` / `source_file` name a file, not code.
    if (segs.some((s) => s === 'path' || s === 'file' || s === 'dir' || s === 'url' || s === 'uri' || s === 'id' || s === 'name' || s === 'type' || s === 'lang' || s === 'language'))
        return false;
    return segs.some((s) => CODE_SEGMENTS.has(s));
}
// Fields that carry a program's standard input or typed keys (audit N4). Next to a command they are
// that command's stdin; on a terminal or process tool they are typed into a shell or REPL.
exports.STDIN_KEYS = new Set(['stdin', 'input', 'std_in', 'standard_input', 'stdin_text', 'stdin_data', 'input_text', 'inputtext',
    'keys', 'send_keys', 'keystrokes', 'stdin_content']);
// Name segments of a tool that drives a terminal, shell, process or REPL.
exports.TERMINAL_SEGMENTS = new Set(['terminal', 'shell', 'process', 'interact', 'pty', 'console', 'repl', 'bash', 'exec', 'execute',
    'stdin', 'keys', 'keystroke', 'keystrokes', 'command', 'commands', 'cmd', 'tty', 'ssh', 'tmux', 'iterm', 'iterm2', 'session', 'sh',
    'zsh', 'powershell', 'pwsh', 'run', 'input', 'term', 'screen', 'stuff', 'type', 'typing', 'keyboard', 'send']);
// ---------------------------------------------------------------------------------------------
// Friction trims T1/T3: what can change the checked-out branch.
// Build tools and generators that are not assumed to switch branches. Any other program with no
// handler is "may change the branch" for the trims (audit T1).
exports.BUILD_TOOLS = new Set(['vite', 'astro', 'next', 'nuxt', 'nuxi', 'webpack', 'rollup', 'esbuild', 'tsup', 'parcel', 'gatsby', 'hugo',
    'jekyll', 'zola', 'mkdocs', 'sphinx-build', 'eleventy', '11ty', 'hexo', 'docusaurus', 'vuepress', 'vitepress', 'svelte-kit', 'sass', 'postcss',
    'tailwindcss', 'ng', 'vue-cli-service', 'react-scripts', 'expo', 'remix', 'solid-start', 'qwik', 'biome', 'swc', 'babel', 'rustc',
    'gcc', 'g++', 'clang', 'cc', 'nodemon', 'zip', 'jq', 'yq', 'sort', 'uniq', 'cmake', 'ninja', 'swift', 'xcodebuild']);
// Task runners and package builders that run project code (recipes, build scripts, plugins) the
// mapper does not read: a command before the trims may have switched the branch in one of them.
exports.HEAD_RUNNERS = new Set(['just', 'task', 'mage', 'rake', 'invoke', 'nx', 'turbo', 'lerna', 'mvn', 'mvnw', 'gradle', 'gradlew', 'dotnet',
    'sbt', 'ant', 'bazel', 'buck', 'pants', 'tsx', 'ts-node', 'pytest', 'tox', 'nox', 'pip', 'pip3', 'bundle', 'cargo', 'go', 'deno', 'flutter', 'dart']);
// Programs whose purpose is to switch branches, worktrees or revisions.
exports.HEAD_CHANGERS = new Set(['hub', 'jj', 'sl', 'hg', 'git-town', 'gt', 'gitui', 'lazygit', 'tig', 'git-branchless', 'stg', 'git-flow',
    'gitflow', 'svn', 'bzr', 'pijul', 'fossil', 'repo', 'west']);
// `gh` subcommands that cannot change the local checkout.
exports.GH_HEAD_SAFE = new Set(['api', 'auth', 'issue', 'run', 'workflow', 'release', 'label', 'gist', 'status', 'search', 'browse',
    'config', 'extension', 'ruleset', 'secret', 'variable', 'cache', 'codespace', 'ssh-key', 'gpg-key', 'org', 'project', 'alias', 'completion', 'help', 'version']);
// Fields of a terminal or process tool that hold typed text (next to, or instead of, stdin/input).
exports.TERMINAL_TEXT_KEYS = new Set(['chunks', 'chunk', 'expression', 'expr', 'source', 'cells', 'cell', 'text', 'data', 'content', 'message', 'payload', 'body', 'value', 'line', 'lines', 'statement', 'task',
    'job', 'action', 'string', 'chars', 'characters', 'typed', 'write', 'send', 'prompt']);
// Fields that give a command's environment.
exports.ENV_KEYS = new Set(['env', 'environment', 'envs', 'env_vars', 'envvars', 'environment_variables', 'extra_env', 'env_vars_override']);
// Fields that give a command's working directory.
exports.CWD_KEYS = new Set(['cwd', 'workdir', 'working_dir', 'working_directory', 'work_dir', 'workingdir', 'workingdirectory', 'current_directory',
    'currentdir', 'directory', 'dir', 'folder', 'cwd_path', 'run_in', 'cwds', 'workdirs', 'root', 'base_dir', 'basedir', 'base_directory', 'pwd', 'chdir', 'cd', 'project', 'project_dir',
    'project_path', 'repo_path', 'repo_dir', 'working_path', 'path', 'rootdir', 'root_dir', 'workspace', 'workspace_dir']);
// Option objects that may hold the working directory or environment of the command next to them.
exports.OPTION_OBJECT_KEYS = new Set(['options', 'opts', 'context', 'session', 'execution', 'spawn_options', 'exec_options', 'config', 'settings', 'env_options', 'process', 'run_options']);
// A sibling that names the language of a code field.
exports.LANGUAGE_KEYS = new Set(['runtime', 'language', 'lang', 'interpreter', 'engine', 'kind', 'type', 'shell', 'mode']);
//# sourceMappingURL=tables.js.map