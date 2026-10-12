'use strict';

// Built-in baseline policy (contract marrow.classifier.v1). It is the same data shape the server
// signs and ships in a policy bundle; a verified bundle replaces it. The baseline is deliberately
// conservative: it only names work that is safe to allow locally without a server round trip.
// Everything it does not name is "unknown" and goes to the server gate.
//
// Program rule forms:
//   'routine' | 'unknown' | 'risky'      fixed class for any arguments
//   { read: true }                        routine unless an argument is a secret path
//   { write: true }                       path arguments are write targets (protected -> risky)
//   { sub: {...}, default, skip }         first non-option argument selects the class
//   { handler: '<name>' }                 special handling in classifier.js

const SUB_FLAGS_WITH_VALUE = {
  git: ['-C', '-c', '--git-dir', '--work-tree', '--namespace', '--exec-path'],
  docker: ['-H', '--host', '--context', '-c', '--config', '-l', '--log-level'],
  kubectl: ['-n', '--namespace', '--context', '--cluster', '--kubeconfig', '-s', '--server', '--user'],
  npm: ['--prefix', '-C', '-w', '--workspace'],
  pnpm: ['-C', '--dir', '--filter', '-F', '-w'],
  yarn: ['--cwd'],
  gh: ['-R', '--repo'],
  cargo: ['--manifest-path', '-Z', '--config'],
  terraform: ['-chdir'],
};

const BASELINE_POLICY = Object.freeze({
  contract: 'marrow.classifier.v1',
  version: 0,
  source: 'builtin_baseline',

  tools: {
    read_only: [
      'read', 'grep', 'glob', 'ls', 'websearch', 'web_search', 'todowrite', 'todoread', 'task', 'agent',
      'exitplanmode', 'notebookread', 'bashoutput', 'killshell', 'askuserquestion', 'skill', 'toolsearch',
      'slashcommand', 'list_dir', 'read_file', 'grep_files', 'view_image', 'update_plan', 'listmcpresourcestool',
      'readmcpresourcetool', 'taskoutput', 'taskstop', 'enterplanmode', 'monitor',
    ],
    edit: ['write', 'edit', 'multiedit', 'notebookedit', 'apply_patch', 'write_file', 'create_file', 'str_replace_editor', 'str_replace_based_edit_tool'],
    shell: ['bash', 'shell', 'local_shell', 'exec_command', 'container.exec', 'run_terminal_command', 'execute_command', 'run_shell_command'],
    fetch: ['webfetch', 'web_fetch', 'fetch'],
    // Marrow's own MCP tools are governed server-side; the exact official namespace only.
    marrow_mcp_prefix: 'mcp__marrow__marrow_',
  },

  // A mutation verb anywhere in an unknown or MCP tool name makes it risky; read verbs never
  // override it (ADV-06: fetch_prod_secrets, query_and_drop_table, status_wipe).
  mutation_verbs: [
    'delete', 'drop', 'wipe', 'purge', 'destroy', 'truncate', 'terminate', 'grant', 'revoke', 'disable', 'flush',
    'deploy', 'publish', 'release', 'merge', 'refund', 'charge', 'payout', 'transfer', 'pay', 'rotate', 'secret',
    'secrets', 'credential', 'credentials', 'token', 'password', 'rollback', 'shutdown', 'kill', 'reset', 'remove',
    'rm', 'overwrite', 'force', 'prod', 'production', 'send', 'email', 'invite', 'approve', 'archive', 'unpublish',
  ],

  protected_branches: ['main', 'master', 'production', 'prod', 'release', 'release/*', 'releases/*', 'live', 'stable', 'trunk', 'hotfix/*', 'deploy', 'deploy/*', 'gh-pages'],

  // Writing these is risky: they disable or redirect Marrow, a harness's hooks, or the shell.
  protected_paths: [
    '~/.marrow/**', '**/.marrow/**',
    '~/.claude.json', '~/.claude/settings.json', '~/.claude/settings.local.json', '**/.claude/settings.json', '**/.claude/settings.local.json',
    '**/.mcp.json', '~/.cursor/**', '**/.cursor/mcp.json', '**/.cursor/hooks.json', '~/.codex/**', '**/.codex/**',
    '~/.gemini/**', '**/.gemini/settings.json', '**/.windsurf/**', '~/.codeium/**', '**/.clinerules/hooks/**',
    '~/.grok/**', '**/.grok/**', '~/.hermes/**', '~/.openclaw/**',
    '~/.config/systemd/user/**', '~/Library/LaunchAgents/**', '**/.config/environment.d/**', '**/.pam_environment',
    // Directories on PATH: an executable written here shadows a routine program later.
    '~/.local/bin/**', '~/bin/**', '/usr/local/bin/**', '/opt/homebrew/bin/**', '**/node_modules/.bin/**',
    '**/.bashrc', '**/.bash_profile', '**/.bash_login', '**/.profile', '**/.zshrc', '**/.zshenv', '**/.zprofile', '**/.config/fish/**',
    '**/.claude.json', '**/.config/systemd/user/**',
    '/etc/**', '/usr/**', '/bin/**', '/sbin/**', '/boot/**', '/lib/**', '/var/lib/**', '/System/**',
    '**/.git/hooks/**', '**/.git/config',
    '**/.npmrc', '**/.gitconfig', '**/.git-credentials', '**/.ssh/**', '**/.aws/**', '**/.kube/**', '**/.docker/config.json',
  ],
  // Reading these is risky (credential exposure).
  secret_paths: [
    // Home-agnostic on purpose: another user's or root's credential files are just as secret.
    '**/.env', '**/.env.*', '**/.aws/**', '**/.ssh/**', '**/.npmrc', '**/.git-credentials', '**/.netrc', '**/.config/gh/**',
    '**/.docker/config.json', '**/.kube/config', '**/.marrow/env', '**/.marrow/env.local', '**/.claude.json', '**/*.pem', '**/*.key',
    '**/id_rsa', '**/id_rsa.*', '**/id_ed25519', '**/id_ed25519.*', '**/id_ecdsa', '**/credentials.json', '**/.dev.vars',
    '**/.config/gcloud/**', '**/.azure/**', '**/.pypirc', '**/.gem/credentials', '**/.cargo/credentials*', '/etc/shadow',
    '**/.hermes/config.yaml', '**/.openclaw/.env',
  ],
  secret_path_exceptions: ['**/.env.example', '**/.env.sample', '**/.env.template', '**/.env.dist'],
  // Edits here are not blocked locally but go to the server gate.
  review_paths: ['**/.husky/**', '**/.githooks/**', '**/lefthook.yml', '**/.pre-commit-config.yaml', '**/.github/workflows/**', '**/Dockerfile', '**/wrangler.toml', '**/wrangler.json', '**/terraform/**', '**/*.tf', '**/k8s/**', '**/helm/**'],

  url_mutation_pattern: '(delete|wipe|drop|destroy|purge|truncate|refund|charge|payout|transfer|dispatch|deploy|publish|admin|_method=|confirm=|execute|reset)',
  interpreter_danger_pattern: '(rmtree|rmSync|rmdirSync|unlink|os\\.remove|os\\.system|subprocess|child_process|execSync|spawnSync|exec\\(|system\\(|File\\.delete|FileUtils\\.rm|shutil|\\.aws|\\.ssh|\\.env|credentials|id_rsa|id_ed25519|wrangler|deploy|publish|DROP |TRUNCATE|DELETE FROM|/dev/sd|mkfs|dd if=)',
  sql_mutation_pattern: '\\b(drop|delete|truncate|update|alter|insert|grant|revoke|flushall|flushdb|replace into)\\b',

  wrappers: ['env', 'timeout', 'nice', 'nohup', 'time', 'command', 'builtin', 'exec', 'stdbuf', 'ionice', 'chrt', 'taskset', 'setsid', 'unbuffer', 'caffeinate', 'xargs', 'watch', 'retry'],
  privilege_wrappers: ['sudo', 'doas', 'su', 'pkexec', 'runas'],
  shells: ['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'ash', 'busybox'],
  interpreters: ['python', 'python2', 'python3', 'node', 'nodejs', 'ruby', 'perl', 'php', 'deno', 'bun', 'lua', 'rscript', 'osascript', 'pwsh', 'powershell', 'tclsh', 'jshell', 'groovy', 'scala', 'swift', 'irb', 'ipython'],
  routine_python_modules: ['pytest', 'unittest', 'mypy', 'black', 'ruff', 'flake8', 'pylint', 'pip', 'venv', 'json.tool', 'doctest', 'compileall', 'py_compile', 'coverage', 'isort'],
  routine_npx: ['tsc', 'eslint', 'prettier', 'vitest', 'jest', 'mocha', 'biome', 'c8', 'nyc', 'typescript', 'markdownlint', 'markdownlint-cli2', 'cspell', 'depcheck', 'knip', 'lint-staged', 'playwright',
    'husky', 'vite', 'next', 'webpack', 'webpack-cli', 'rollup', 'esbuild', 'tsup', 'parcel', 'astro', 'nuxi', 'storybook'],
  routine_package_scripts_depth: 3,

  programs: {
    // Read-only inspection.
    ls: 'routine', ll: 'routine', dir: 'routine', pwd: 'routine', echo: 'routine', printf: 'routine', true: 'routine', false: 'routine',
    ':': 'routine', test: 'routine', '[': 'routine', '[[': 'routine', which: 'routine', type: 'routine', whereis: 'routine', whoami: 'routine',
    id: 'routine', uname: 'routine', hostname: 'routine', date: 'routine', uptime: 'routine', sleep: 'routine', seq: 'routine',
    basename: 'routine', dirname: 'routine', realpath: 'routine', readlink: 'routine', cd: { handler: 'cd' }, pushd: 'routine', popd: 'routine',
    export: { handler: 'export' }, unset: 'routine', set: 'routine', shopt: 'unknown', trap: 'unknown', wait: 'routine', jobs: 'routine', read: 'routine',
    exit: 'routine', return: 'routine', local: { handler: 'export' }, declare: { handler: 'export' }, typeset: { handler: 'export' }, readonly: { handler: 'export' }, history: 'routine', help: 'routine',
    hash: 'unknown', enable: 'unknown',
    ps: 'routine', top: 'routine', htop: 'routine', free: 'routine', df: 'routine', du: { read: true }, lsof: 'routine', nproc: 'routine',
    cat: { read: true }, head: { read: true }, tail: { read: true }, less: { read: true }, more: { read: true }, wc: { read: true },
    grep: { read: true }, egrep: { read: true }, fgrep: { read: true }, rg: { handler: 'rg' }, ag: { read: true }, ack: { read: true },
    find: { handler: 'find' }, fd: { handler: 'fd' }, tree: { read: true }, file: { read: true }, stat: { read: true }, diff: { read: true },
    cmp: { read: true }, comm: { read: true }, sort: { read: true }, uniq: { read: true }, cut: { read: true }, tr: 'routine', paste: { read: true },
    column: { read: true }, nl: { read: true }, fold: { read: true }, rev: { read: true }, tac: { read: true }, jq: { read: true }, yq: { read: true },
    xxd: { read: true }, od: { read: true }, hexdump: { read: true }, strings: { read: true }, base64: { read: true }, base32: { read: true },
    sha256sum: { read: true }, sha1sum: { read: true }, md5sum: { read: true }, shasum: { read: true }, cksum: { read: true },
    awk: { handler: 'awk' }, gawk: { handler: 'awk' }, mawk: { handler: 'awk' }, sed: { handler: 'sed' },
    env: 'routine', printenv: 'routine',
    // Local file changes inside the workspace.
    mkdir: { write: true }, touch: { write: true }, cp: { write: true }, mv: { write: true }, ln: { write: true }, tee: { write: true },
    install: { write: true }, truncate: { write: true }, rmdir: { write: true }, rm: { handler: 'rm' }, unlink: { write: true },
    chmod: { handler: 'chmod' }, chown: { handler: 'chmod' }, chgrp: { handler: 'chmod' },
    tar: { handler: 'archive' }, zip: { read: true }, unzip: { handler: 'archive' }, gzip: { read: true }, gunzip: { read: true }, xz: { read: true }, unxz: { read: true }, bzip2: { read: true }, zstd: { read: true }, '7z': 'unknown',
    patch: 'routine',
    // Developer tools.
    git: { handler: 'git' },
    gh: { handler: 'gh' },
    npm: { handler: 'pkg' }, pnpm: { handler: 'pkg' }, yarn: { handler: 'pkg' }, bun: { handler: 'bun' },
    npx: { handler: 'npx' }, pnpx: { handler: 'npx' }, bunx: { handler: 'npx' },
    tsc: 'routine', eslint: 'routine', prettier: 'routine', biome: 'routine', jest: 'routine', vitest: 'routine', mocha: 'routine',
    // Dev servers, bundlers and git-hook installers: they run project config the agent may have
    // written, so agentd's workspace taint escalates them after process-spawning code is written.
    husky: 'routine', vite: 'routine', next: 'routine', webpack: 'routine', 'webpack-cli': 'routine', rollup: 'routine', esbuild: 'routine',
    tsup: 'routine', parcel: 'routine', astro: 'routine', nuxi: 'routine', nuxt: 'routine', storybook: 'routine', gatsby: 'routine', remix: 'routine',
    pytest: 'routine', ruff: 'routine', black: 'routine', mypy: 'routine', flake8: 'routine', pylint: 'routine', isort: 'routine',
    shellcheck: 'routine', actionlint: 'routine', yamllint: 'routine', hadolint: 'routine', golangci_lint: 'routine', 'golangci-lint': 'routine',
    gofmt: 'routine', rustfmt: 'routine', clang_format: 'routine', 'clang-format': 'routine', cloc: 'routine', tokei: 'routine',
    node: { handler: 'interpreter' }, nodejs: { handler: 'interpreter' },
    cargo: { sub: { build: 'routine', test: 'routine', check: 'routine', clippy: 'routine', fmt: 'routine', doc: 'routine', tree: 'routine', metadata: 'routine', bench: 'routine', add: 'routine', update: 'routine', search: 'routine', publish: 'risky', yank: 'risky', owner: 'risky', login: 'risky', logout: 'risky' }, default: 'unknown' },
    go: { sub: { build: 'routine', test: 'routine', vet: 'routine', fmt: 'routine', mod: 'routine', list: 'routine', version: 'routine', env: 'routine', doc: 'routine', get: 'routine' }, default: 'unknown' },
    pip: { handler: 'pip' }, pip3: { handler: 'pip' },
    uv: { sub: { pip: 'routine', sync: 'routine', lock: 'routine', add: 'routine', venv: 'routine', tree: 'routine', publish: 'risky' }, default: 'unknown' },
    poetry: { sub: { install: 'routine', show: 'routine', lock: 'routine', check: 'routine', add: 'routine', build: 'routine', publish: 'risky' }, default: 'unknown' },
    twine: { sub: { check: 'routine', upload: 'risky' }, default: 'unknown' },
    gem: { sub: { list: 'routine', install: 'routine', build: 'routine', push: 'risky', yank: 'risky', owner: 'risky' }, default: 'unknown' },
    mvn: { sub: { compile: 'routine', test: 'routine', package: 'routine', verify: 'routine', clean: 'routine', deploy: 'risky', release: 'risky' }, default: 'unknown' },
    dotnet: { sub: { build: 'routine', test: 'routine', restore: 'routine', format: 'routine', nuget: 'unknown' }, default: 'unknown' },
    docker: { handler: 'docker' }, podman: { handler: 'docker' },
    kubectl: { sub: { get: 'routine', describe: 'routine', logs: 'routine', explain: 'routine', version: 'routine', 'api-resources': 'routine', top: 'routine', diff: 'routine', config: 'unknown', apply: 'risky', delete: 'risky', exec: 'risky', scale: 'risky', rollout: 'risky', patch: 'risky', replace: 'risky', create: 'risky', edit: 'risky', drain: 'risky', cordon: 'risky', taint: 'risky', label: 'risky', annotate: 'risky', 'port-forward': 'unknown', cp: 'risky', run: 'risky', set: 'risky', auth: 'unknown' }, default: 'unknown', skip: 'kubectl' },
    helm: { sub: { list: 'routine', ls: 'routine', status: 'routine', template: 'routine', lint: 'routine', show: 'routine', search: 'routine', repo: 'unknown', install: 'risky', upgrade: 'risky', uninstall: 'risky', delete: 'risky', rollback: 'risky' }, default: 'unknown' },
    terraform: { sub: { plan: 'routine', validate: 'routine', fmt: 'routine', init: 'routine', show: 'routine', output: 'routine', providers: 'routine', graph: 'routine', version: 'routine', apply: 'risky', destroy: 'risky', import: 'risky', state: 'risky', taint: 'risky', untaint: 'risky', 'force-unlock': 'risky', workspace: 'unknown', console: 'unknown' }, default: 'unknown', skip: 'terraform' },
    tofu: { sub: { plan: 'routine', validate: 'routine', fmt: 'routine', init: 'routine', show: 'routine', apply: 'risky', destroy: 'risky', import: 'risky', state: 'risky' }, default: 'unknown' },
    pulumi: { sub: { preview: 'routine', stack: 'unknown', up: 'risky', destroy: 'risky', refresh: 'risky', cancel: 'risky' }, default: 'unknown' },
    wrangler: { sub: { dev: 'routine', whoami: 'routine', types: 'routine', tail: 'routine', deploy: 'risky', publish: 'risky', secret: 'risky', rollback: 'risky', delete: 'risky', d1: 'risky', kv: 'unknown', r2: 'unknown', versions: 'unknown', login: 'risky' }, default: 'unknown' },
    fly: { sub: { status: 'routine', logs: 'routine', version: 'routine', deploy: 'risky', ssh: 'risky', secrets: 'risky', scale: 'risky', destroy: 'risky', apps: 'unknown', postgres: 'risky', machine: 'risky', console: 'risky' }, default: 'unknown' },
    flyctl: { sub: { status: 'routine', logs: 'routine', deploy: 'risky', ssh: 'risky', secrets: 'risky', scale: 'risky', destroy: 'risky' }, default: 'unknown' },
    vercel: 'risky', netlify: 'risky', heroku: 'risky', firebase: 'risky', railway: 'risky', serverless: 'risky', sls: 'risky', cdk: 'risky', eksctl: 'risky',
    aws: 'risky', gcloud: 'risky', az: 'risky', doctl: 'risky', supabase: 'risky', stripe: 'risky', 'ansible-playbook': 'risky', ansible: 'risky',
    // Databases: opaque by default; SQL mutation text makes them risky.
    psql: { handler: 'sql' }, mysql: { handler: 'sql' }, sqlite3: { handler: 'sql' }, mongosh: { handler: 'sql' }, mongo: { handler: 'sql' },
    'redis-cli': { handler: 'sql' }, cqlsh: { handler: 'sql' }, 'clickhouse-client': { handler: 'sql' }, pg_dump: 'unknown', pg_restore: 'risky', dropdb: 'risky', createdb: 'unknown',
    // Network and remote execution.
    curl: { handler: 'http' }, wget: { handler: 'http' }, http: { handler: 'http' }, https: { handler: 'http' }, xh: { handler: 'http' },
    ssh: 'risky', scp: 'risky', sftp: 'risky', rsync: { handler: 'rsync' }, mosh: 'risky', telnet: 'risky', nc: 'risky', ncat: 'risky', socat: 'risky',
    // System changes.
    dd: 'risky', mkfs: 'risky', 'mkfs.ext4': 'risky', 'mkfs.xfs': 'risky', fdisk: 'risky', parted: 'risky', wipefs: 'risky', shred: 'risky',
    shutdown: 'risky', reboot: 'risky', halt: 'risky', poweroff: 'risky', init: 'risky', iptables: 'risky', ufw: 'risky', nft: 'risky',
    useradd: 'risky', userdel: 'risky', usermod: 'risky', passwd: 'risky', chpasswd: 'risky', visudo: 'risky', mount: 'risky', umount: 'risky',
    swapoff: 'risky', crontab: { sub: { '-l': 'routine' }, default: 'risky', flags: true },
    systemctl: { handler: 'systemctl' }, service: 'risky', launchctl: { sub: { list: 'routine', print: 'routine' }, default: 'risky' },
    kill: { handler: 'kill' }, pkill: { handler: 'kill' }, killall: { handler: 'kill' },
    // Marrow self-protection: control and uninstall are owner-only.
    'marrow-agentd': { sub: { status: 'routine', doctor: 'routine', version: 'routine', hook: 'routine', control: 'risky', stop: 'risky', uninstall: 'risky', run: 'risky' }, default: 'risky' },
    'marrow-install': { sub: { doctor: 'routine', status: 'routine', detect: 'routine', control: 'risky', uninstall: 'risky', agentd: 'risky' }, default: 'unknown' },
    'marrow-mcp': 'unknown',
    // Opaque task runners: targets can do anything (ADV-06 H6); the server decides.
    make: 'unknown', just: 'unknown', task: 'unknown', rake: 'unknown', invoke: 'unknown', nox: 'unknown', tox: 'unknown',
    gradle: 'unknown', gradlew: 'unknown', turbo: 'unknown', nx: 'unknown', lerna: 'unknown',
    eval: 'unknown', source: { handler: 'source' }, '.': { handler: 'source' }, alias: 'unknown',
    open: 'unknown', 'xdg-open': 'unknown', code: 'unknown', vim: 'unknown', nvim: 'unknown', nano: 'unknown', emacs: 'unknown',
  },

  // Behaviour when the server gate cannot answer. Risky actions always fail closed.
  outage: { risky: 'deny', unknown: 'deny' },
  sub_flags_with_value: SUB_FLAGS_WITH_VALUE,
});

module.exports = { BASELINE_POLICY };
