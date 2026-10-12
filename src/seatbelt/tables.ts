// Seatbelt rule tables (spec SEATBELT-SPEC.md §1.2 as amended by the owner decisions of 2026-10-12).
// Compiled into the package on purpose: no local file can extend or relax them (spec §2.1.7).

export const SEATBELT_RULES_VERSION = 'marrow.seatbelt.rules.v1';

export const LIMITS = Object.freeze({
  maxCommandBytes: 8 * 1024,
  maxSegments: 64,
  maxDepth: 3,
  maxScriptBytes: 64 * 1024,
  maxPackageJsonBytes: 256 * 1024,
  maxConfigBytes: 1024 * 1024,
  maxAliasExpansions: 5,
});

// S4 secret paths. Home-anchored entries in the spec are matched home-agnostic ("**/"), which is
// stricter: another user's or root's credential file is just as secret.
export const SECRET_PATTERNS: readonly string[] = [
  '**/.ssh/id_*', '**/.ssh/*_key', '**/.aws/credentials', '**/.aws/sso/cache/**',
  '**/.config/gcloud/**/*credentials*', '**/.config/gcloud/**/access_tokens.db', '**/.azure/**',
  '**/.kube/config', '**/.docker/config.json', '**/.npmrc', '**/.pypirc', '**/.netrc', '**/.git-credentials',
  '**/.config/gh/hosts.yml', '**/.config/op/**', '**/.gnupg/private-keys*', '**/.gnupg/private-keys*/**',
  '**/.marrow/env*', '**/.claude.json', '**/.claude/settings.local.json', '/proc/*/environ',
  '**/.env', '**/.env.*', '**/.dev.vars',
];
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
    `${h}/.marrow/env.local`, `${h}/.claude.json`, `${h}/.claude/settings.local.json`, '/proc/self/environ', '/proc/1/environ',
    `${h}/.env`, '/root/.ssh/id_rsa', '/root/.aws/credentials',
  ];
  for (const c of cwds) {
    const d = c.replace(/\/$/, '');
    out.push(`${d}/.env`, `${d}/.env.local`, `${d}/.env.production`, `${d}/app/.env`, `${d}/.dev.vars`, `${d}/server.pem`,
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

export const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'ash', 'busybox', 'mksh', 'yash']);
export const INTERPRETERS = new Set(['python', 'python2', 'python3', 'node', 'nodejs', 'ruby', 'perl', 'php', 'deno', 'bun', 'lua', 'pwsh', 'powershell', 'osascript', 'tclsh', 'irb', 'ipython']);

// Interpreter one-liners that delete trees (S5).
export const INTERPRETER_TREE_DELETE = /rmSync|rmdirSync|rimraf|shutil\.rmtree|rm_rf|FileUtils\.rm_r|FileUtils\.remove_dir|remove_dir_all|removedirs|\.rm\s*\([^)]*recursive|Remove-Item[^\n]*-Recurse|deleteRecursively/;
// Decoded data that is then executed inside interpreter code (S-x).
export const INTERPRETER_DECODE = /b64decode|base64|atob\s*\(|fromCharCode|unhexlify|bytes\.fromhex|codecs\.decode|\.decode\(\s*['"](?:hex|base64|rot)|Buffer\.from\([^)]*['"](?:base64|hex)['"]|\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}/i;
export const INTERPRETER_EXEC = /\bexec\s*\(|\beval\s*\(|\bFunction\s*\(|\bsystem\s*\(|popen|spawn|execSync|execFile|child_process|subprocess|os\.system|\bcompile\s*\(|`/;

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
  { re: /\.ssh\b|id_rsa|id_ed25519|id_ecdsa|\.aws\b|\.npmrc|\.netrc|\.pypirc|\.git-credentials|\.docker\/config|\.kube\/config|gh\/hosts\.yml|\.gnupg|\.claude\.json|settings\.local\.json|\/environ\b|\.dev\.vars|\.pem\b|\.p12\b|\.pfx\b|\.marrow\/env/, category: 'S4', reason: 'tripwire_secret_path' },
  { re: /(?:^|[^a-z0-9_$)\].])\.env(?![a-z0-9_])(?!\.(?:example|sample|template)\b)/, category: 'S4', reason: 'tripwire_env_file' },
  { re: /printenv|export\s+-p|declare\s+-[a-z]*[xp]|(?:^|[;&|({\s])(?:env|set|export)\s*(?:$|[;&|)}])|auth\s+token|print-(?:access|identity)-token|get-session-token|get-access-token|auth:token|find-(?:generic|internet)-password|secret-tool|op\s+read|vault\s+(?:kv|read)|pass\s+show|token\s+list|(?:process\.env|os\.environ|\$env|env\.to_h|system\.getenv\(\))\s*(?:\)|;|$|\||,|\.items|\.keys|\.copy)|(?:environ|\benv)\W{0,3}[a-z_]*(?:key|token|secret|pass|cred)|\$\{?!?[a-z_]*(?:key|token|secret|pass|cred)/, category: 'S4', reason: 'tripwire_secret_dumper' },
  { re: /\brm\b[^;&|\n]*?[\s,(\[](?:-[a-z]*r[a-z]*|--recursive)\b|rmtree|rmsync|rmdirsync|rimraf|rm_rf|\brm_r\b|mkfs|\bdd\b[^;&|\n]*of=\/dev\//, category: 'S5', reason: 'tripwire_recursive_delete' },
  { re: /\.marrow|@getmarrow|settings\.json|hooks\.json|\.mcp\.json|\.bashrc|\.zshrc|\.bash_profile|\.zprofile|\.zshenv|\.profile\b/, category: 'S0', reason: 'tripwire_self_protection' },
  { re: /base64\s+(?:-[a-z]*d|--decode)|xxd\s+-[a-z]*r|b64decode|atob\s*\(/, category: 'Sx', reason: 'tripwire_decoded_exec' },
];
// Script, Makefile-target and package-script names that trip when their content cannot be read.
export const NAME_TRIPWIRE = /publish|deploy|release|ship|prod/i;
