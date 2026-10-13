'use strict';

// Local action classifier, contract marrow.classifier.v1. It decides only one thing on its own:
// whether an action is ROUTINE (safe to allow locally with a receipt). Every other action is
// RISKY or UNKNOWN and goes to the server gate, which is authoritative. It classifies the parsed
// program and argv, never raw text, and it defaults anything it cannot resolve to not-routine
// (ADV-06). The rule tables come from the signed policy bundle (policy-baseline.js shape).

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { parseShell } = require('./shell-parse');
const { redactArgv, redactText, safeToken } = require('./redact');

const RANK = { routine: 0, unknown: 1, risky: 2 };
const MAX_DEPTH = 3;
const MAX_ALTERNATIVES = 16;
const SCRIPT_MAX_BYTES = 64 * 1024;
const PACKAGE_JSON_MAX_BYTES = 256 * 1024;
const SYSTEM_BIN = /^\/(?:usr\/(?:local\/)?)?s?bin\/|^\/opt\/homebrew\/bin\/|^\/snap\/bin\//;
const OUTPUT_REDIRECTS = new Set(['>', '>>', '>|', '&>', '&>>', '<>']);
const MAX_TRACKED_COMMANDS = 32;
const INSTALL_SUBS = new Set(['install', 'i', 'ci', 'add', 'rebuild', 'install-test', 'it', 'cit', 'clean-install', 'update', 'up', 'upgrade', 'import', 'pack']);
const INSTALL_LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepublish', 'preprepare', 'prepare', 'postprepare', 'dependencies'];
const PACK_LIFECYCLE = ['prepack', 'prepare', 'postpack'];
const MAX_COMMAND_CHARS = 1000;
const MAX_PATH_CHARS = 4096;
// Environment names that change what a later program runs or loads (PATH hijack, preload,
// interpreter options, npm/git config, Marrow's own settings).
// Only the variables that change which code runs or which server/trust store is used. Ordinary
// settings (NODE_ENV, CI, DEBUG, GIT_AUTHOR_NAME, PYTHONUNBUFFERED, RUST_LOG, TZ...) stay routine.
const SENSITIVE_ENV = new RegExp('^(?:' + [
  'PATH', 'IFS', 'ENV', 'BASH_ENV', 'SHELLOPTS', 'BASHOPTS', 'PS4', 'PROMPT_COMMAND', 'CDPATH', 'HOME', 'ZDOTDIR', 'SHELL',
  'LD_[A-Z_]*', 'DYLD_[A-Z_]*',
  'NODE_OPTIONS', 'NODE_PATH', 'NODE_EXTRA_CA_CERTS', 'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_REPL_EXTERNAL_MODULE',
  'NPM_CONFIG_[A-Z_]*', 'npm_config_[A-Za-z_]*', 'YARN_[A-Z_]*', 'PNPM_[A-Z_]*', 'BUN_[A-Z_]*',
  'PYTHONPATH', 'PYTHONSTARTUP', 'PYTHONHOME', 'PYTHONBREAKPOINT', 'PYTHONUSERBASE', 'PYTHONEXECUTABLE',
  'PIP_INDEX_URL', 'PIP_EXTRA_INDEX_URL', 'PIP_TRUSTED_HOST', 'PIP_CONFIG_FILE', 'UV_INDEX_URL', 'UV_EXTRA_INDEX_URL',
  'RUBYOPT', 'RUBYLIB', 'GEM_HOME', 'GEM_PATH', 'BUNDLE_GEMFILE', 'PERL5OPT', 'PERL5LIB', 'PERLLIB', 'PERL5DB',
  'GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_EXEC_PATH', 'GIT_CONFIG[A-Z_]*', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_ASKPASS', 'GIT_EDITOR',
  'GIT_SEQUENCE_EDITOR', 'GIT_PAGER', 'GIT_TEMPLATE_DIR', 'GIT_EXTERNAL_DIFF', 'GIT_PROXY_COMMAND', 'GIT_ALLOW_PROTOCOL',
  'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_NAMESPACE',
  'SSH_[A-Z_]*', 'PAGER', 'EDITOR', 'VISUAL', 'BROWSER', 'XDG_[A-Z_]*', 'SSL_[A-Z_]*', 'CURL_[A-Z_]*',
  'REQUESTS_CA_BUNDLE', 'HTTPS?_PROXY', 'https?_proxy', 'ALL_PROXY', 'all_proxy', 'NO_PROXY', 'no_proxy', 'MARROW_[A-Z_]*',
].join('|') + ')$');
const INTERNAL_HOST = /^(?:localhost|.*\.localhost|.*\.internal|metadata|metadata\.google\.internal|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|169\.254\.\d+\.\d+|0\.0\.0\.0|\[?::1\]?|\[?f[cd][0-9a-f]{2}:.*|\[?fe80:.*)$/i;
const DEVICE_TARGETS = new Set(['/dev/null', '/dev/stdout', '/dev/stderr', '/dev/tty', '/dev/fd/1', '/dev/fd/2']);

function globToRegex(pattern, home) {
  let p = String(pattern);
  let anchored = true;
  if (p.startsWith('~/')) p = `${home.replace(/\/$/, '')}/${p.slice(2)}`;
  else if (p === '~') p = home;
  if (p.startsWith('**/')) { anchored = false; p = p.slice(3); }
  let out = '';
  for (let i = 0; i < p.length; i += 1) {
    const ch = p[i];
    if (ch === '*' && p[i + 1] === '*') {
      if (p[i + 2] === '/') { out += '(?:.*/)?'; i += 2; }
      else if (out.endsWith('/') && i + 2 === p.length) { out = `${out.slice(0, -1)}(?:/.*)?`; i += 1; }
      else { out += '.*'; i += 1; }
    } else if (ch === '*') out += '[^/]*';
    else if (ch === '?') out += '[^/]';
    else out += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(`${anchored ? '^' : '(?:^|/)'}${out}$`);
}

function compileMatcher(patterns, home) {
  const regexes = (patterns || []).map((pattern) => globToRegex(pattern, home));
  return (absPath) => regexes.some((regex) => regex.test(absPath));
}

function splitVerbs(name) {
  return String(name)
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

class Result {
  constructor() {
    this.class = 'routine';
    this.reasons = [];
    this.programs = [];
    this.paths = [];
    this.hosts = [];
    this.commands = [];
    // True when the action had more than the tracked commands/arguments/characters. A truncated
    // action is never covered by a server lease (the server did not see all of it).
    this.truncated = false;
  }
  raise(cls, reason) {
    if (RANK[cls] > RANK[this.class]) this.class = cls;
    if (reason && cls !== 'routine') {
      const token = safeToken(reason, 80);
      if (!this.reasons.includes(token) && this.reasons.length < 24) this.reasons.push(token);
    }
    return this;
  }
  merge(other) {
    if (!other) return this;
    this.raise(other.class);
    for (const reason of other.reasons) if (!this.reasons.includes(reason) && this.reasons.length < 24) this.reasons.push(reason);
    for (const key of ['programs', 'paths', 'hosts', 'commands']) {
      for (const value of other[key]) this.add(key, value);
    }
    if (other.truncated) this.truncated = true;
    return this;
  }
  add(key, value) {
    if (!value || this[key].includes(value)) return;
    if (this[key].length >= MAX_TRACKED_COMMANDS) { this.truncated = true; return; }
    this[key].push(value);
  }
  note(key, value) {
    if (!value) return;
    this.add(key, key === 'programs' || key === 'hosts' ? safeToken(value, 64) : value);
  }
}

function createClassifier(policy, options = {}) {
  const home = options.home || os.homedir();
  const tmpRoots = [os.tmpdir(), '/tmp', '/var/tmp'].map((p) => p.replace(/\/$/, ''));
  const tables = policy;
  const programs = tables.programs || {};
  const isProtected = compileMatcher(tables.protected_paths, home);
  const isSecretRaw = compileMatcher(tables.secret_paths, home);
  const isSecretException = compileMatcher(tables.secret_path_exceptions, home);
  const isReview = compileMatcher(tables.review_paths, home);
  const isProtectedBranch = compileMatcher(tables.protected_branches, '/nonexistent-home');
  const urlMutation = new RegExp(tables.url_mutation_pattern || '(?!)', 'i');
  const interpreterDanger = new RegExp(tables.interpreter_danger_pattern || '(?!)', 'i');
  const sqlMutation = new RegExp(tables.sql_mutation_pattern || '(?!)', 'i');
  const mutationVerbs = new Set(tables.mutation_verbs || []);
  const toolSets = {
    readOnly: new Set((tables.tools && tables.tools.read_only) || []),
    edit: new Set((tables.tools && tables.tools.edit) || []),
    shell: new Set((tables.tools && tables.tools.shell) || []),
    fetch: new Set((tables.tools && tables.tools.fetch) || []),
  };
  const marrowPrefix = (tables.tools && tables.tools.marrow_mcp_prefix) || 'mcp__marrow__marrow_';
  const wrappers = new Set(tables.wrappers || []);
  const privilegeWrappers = new Set(tables.privilege_wrappers || []);
  const shells = new Set(tables.shells || []);
  const interpreters = new Set(tables.interpreters || []);
  const routinePythonModules = new Set(tables.routine_python_modules || []);
  const routineNpx = new Set(tables.routine_npx || []);
  const subFlagsWithValue = tables.sub_flags_with_value || {};
  const daemonPids = new Set((options.protectedPids || []).map(String));

  const isSecret = (abs) => isSecretRaw(abs) && !isSecretException(abs);

  // ---------- context helpers ----------
  function newContext(cwd) {
    const resolved = typeof cwd === 'string' && path.isAbsolute(cwd) ? path.normalize(cwd) : null;
    // `written` is shared by every copy of the context for one action: a script or package.json
    // written earlier in the same command line is never classified by its current contents.
    return { cwd: resolved, cwdUnknown: !resolved, vars: new Map([['HOME', home]]), depth: 0, written: new Set() };
  }

  // Returns every literal value a word can take (a loop variable has several), or null when a
  // part cannot be resolved statically.
  function resolveWordAlternatives(word, ctx) {
    if (!word) return null;
    if (!word.dynamic) return [word.text];
    if (!word.slots || word.slots.length === 0) return null;
    const parts = word.text.split('\u0000');
    let values = [parts[0]];
    for (let k = 0; k < word.slots.length; k += 1) {
      const slot = word.slots[k];
      if (!slot || slot.type !== 'var' || !ctx.vars.has(slot.name)) return null;
      const bound = ctx.vars.get(slot.name);
      const options = Array.isArray(bound) ? bound : [bound];
      const next = [];
      for (const prefix of values) for (const option of options) next.push(`${prefix}${option}${parts[k + 1] || ''}`);
      if (next.length > MAX_ALTERNATIVES) return null;
      values = next;
    }
    return values;
  }

  function resolveWordText(word, ctx) {
    const values = resolveWordAlternatives(word, ctx);
    return values && values.length === 1 ? values[0] : null;
  }

  function expandTilde(text) {
    if (text === '~') return home;
    if (text.startsWith('~/')) return path.join(home, text.slice(2));
    return text;
  }

  function absPath(text, ctx) {
    const expanded = expandTilde(text);
    if (path.isAbsolute(expanded)) return path.normalize(expanded);
    if (ctx.cwdUnknown || !ctx.cwd) return null;
    return path.resolve(ctx.cwd, expanded);
  }

  function inWorkspace(abs, ctx) {
    if (!abs) return false;
    const roots = [...tmpRoots];
    if (ctx.cwd && !ctx.cwdUnknown && ctx.cwd !== '/' && ctx.cwd !== home) roots.push(ctx.cwd);
    for (const root of [...roots]) { const real = realOf(root); if (real !== root && real !== '/' && real !== home) roots.push(real); }
    return roots.some((root) => abs === root || abs.startsWith(`${root}/`));
  }

  // A target whose subtree includes the home directory, the filesystem root or the workspace
  // itself (for example `~`, `/`, `.`, `..`, `./*`).
  // A glob is broad only when it matches every entry of a directory that covers the home
  // directory, the root or the workspace (`*`, `./*`, `~/*`, `.*`, `/tmp/*` with the workspace in
  // /tmp). A glob with a literal part (`*.log`, `build-*`) deletes only matching entries and is
  // judged like any other path.
  function isBroadTarget(raw, ctx) {
    const abs = absPath(raw, ctx);
    const covers = (dir) => dir && (dir === '/' || dir === home || home.startsWith(`${dir}/`) || (ctx.cwd && (dir === ctx.cwd || ctx.cwd.startsWith(`${dir}/`))));
    if (['/', '~', '*', '.', '..', './', '../', '/*', '~/*', './*', '../*', '.*', './.*'].includes(raw)) return true;
    if (/[*?[]/.test(raw)) {
      const name = path.basename(raw);
      const matchesAll = name.replace(/\[[^\]]*\]|[*?.{},]/g, '') === '';
      if (!matchesAll) return false; // `*.log`, `*/build`: only matching entries
      const parts = raw.split('/');
      const firstGlob = parts.findIndex((part) => /[*?[]/.test(part));
      const fixed = parts.slice(0, firstGlob).join('/') || (raw.startsWith('/') ? '/' : '.');
      return covers(absPath(fixed, ctx));
    }
    return covers(abs);
  }

  function relLabel(abs, ctx) {
    if (!abs) return '[unresolved]';
    if (ctx.cwd && abs.startsWith(`${ctx.cwd}/`)) return redactText(path.relative(ctx.cwd, abs), 120);
    if (abs.startsWith(`${home}/`)) return redactText(`~/${path.relative(home, abs)}`, 120);
    return redactText(abs, 120);
  }

  // The real location behind symlinks, for the path itself or its nearest existing ancestor. A
  // workspace file that is a symlink to ~/.bashrc is judged as ~/.bashrc.
  function realOf(abs) {
    let current = abs;
    const rest = [];
    for (let level = 0; level < 64; level += 1) {
      try {
        return path.join(fs.realpathSync(current), ...rest.reverse());
      } catch {
        const parent = path.dirname(current);
        if (parent === current) return abs;
        rest.push(path.basename(current));
        current = parent;
      }
    }
    return abs;
  }

  function checkReadPath(text, ctx, result, reason = 'secret_read') {
    if (text.length > MAX_PATH_CHARS) { result.raise('unknown', 'oversize_path'); return; }
    const abs = absPath(text, ctx);
    if (!abs) return;
    if (/^\/dev\/(?:tcp|udp)\//.test(abs)) { result.raise('unknown', 'dev_tcp_network'); return; }
    const real = realOf(abs);
    if (isSecret(abs) || isSecret(real)) { result.raise('risky', reason); result.note('paths', relLabel(abs, ctx)); }
  }

  function checkWritePath(text, ctx, result, { recursiveDelete = false } = {}) {
    if (text == null) { result.raise('unknown', 'dynamic_write_target'); return; }
    if (DEVICE_TARGETS.has(text)) return;
    if (text.length > MAX_PATH_CHARS) { result.raise('unknown', 'oversize_path'); return; }
    const abs = absPath(text, ctx);
    if (!abs) { result.raise('unknown', 'write_target_cwd_unknown'); return; }
    if (/^\/dev\/(?:tcp|udp)\//.test(abs)) { result.raise('unknown', 'dev_tcp_network'); return; }
    const real = realOf(abs);
    if (ctx.written) { ctx.written.add(abs); ctx.written.add(real); }
    result.note('paths', relLabel(abs, ctx));
    if (isProtected(abs) || isProtected(real)) { result.raise('risky', real !== abs && !isProtected(abs) ? 'symlink_to_protected_path' : 'protected_path_write'); return; }
    // Writing a credential store in the home directory (~/.aws, ~/.ssh...) is risky; creating or
    // editing a project .env file inside the workspace goes to the server gate instead.
    if (isSecret(abs) || isSecret(real)) { result.raise(inWorkspace(abs, ctx) && inWorkspace(real, ctx) ? 'unknown' : 'risky', 'secret_path_write'); return; }
    if (isReview(abs) || isReview(real)) { result.raise('unknown', 'review_path_write'); return; }
    if (inWorkspace(abs, ctx) && inWorkspace(real, ctx)) return;
    // Outside the workspace: a non-recursive write to an ordinary (non-dot) path under the home
    // directory, such as ~/agents/<role>/results/report.md, is routine. Dotfiles and dot-dirs,
    // ~/Library, ~/Applications, ~/bin and ~/snap hold configuration or executables and stay
    // gated; recursive deletes outside the workspace stay risky.
    if (!recursiveDelete && isHomeDataPath(abs) && isHomeDataPath(real)) return;
    result.raise(recursiveDelete ? 'risky' : 'unknown', 'write_outside_workspace');
  }

  function isHomeDataPath(abs) {
    if (!abs || !abs.startsWith(`${home}/`)) return false;
    const top = abs.slice(home.length + 1).split('/')[0];
    return Boolean(top) && !top.startsWith('.') && !['Library', 'Applications', 'bin', 'snap'].includes(top);
  }

  // ---------- tools ----------
  function toolInputPaths(input) {
    const out = [];
    for (const key of ['file_path', 'path', 'notebook_path', 'filePath', 'target_file', 'filename', 'file']) {
      if (input && typeof input[key] === 'string') out.push(input[key]);
    }
    if (input && Array.isArray(input.edits)) {
      for (const edit of input.edits) if (edit && typeof edit.file_path === 'string') out.push(edit.file_path);
    }
    return out;
  }

  function patchPaths(text) {
    const out = [];
    const re = /^\*\*\* (?:Update|Add|Delete) File: (.+)$|^\*\*\* Move to: (.+)$|^(?:\+\+\+|---) (?:[ab]\/)?(.+)$/gm;
    let match;
    while ((match = re.exec(String(text || ''))) !== null) {
      const value = (match[1] || match[2] || match[3] || '').trim();
      if (value && value !== '/dev/null' && out.length < 64) out.push(value);
    }
    return out;
  }

  function classifyUrl(url, result) {
    let parsed = null;
    try { parsed = new URL(url); } catch { parsed = null; }
    if (parsed) result.note('hosts', parsed.host.toLowerCase());
    if (!parsed) { result.raise('unknown', 'unparseable_url'); return; }
    // Loopback, private and link-local hosts include cloud metadata endpoints that hand out
    // credentials; a GET there is not routine.
    // A plain request to the local dev server (localhost / 127.0.0.1 / ::1) is routine; cloud
    // metadata, link-local and private-network hosts are not (write methods and bodies are judged
    // separately by the http handler).
    const loopback = /^(?:localhost|127\.\d+\.\d+\.\d+|\[?::1\]?)$/i.test(parsed.hostname);
    if (!loopback && (INTERNAL_HOST.test(parsed.hostname) || /^\d+$/.test(parsed.hostname))) result.raise('unknown', 'internal_host');
    const target = `${parsed.pathname}${parsed.search}`;
    if (urlMutation.test(target)) result.raise('unknown', 'url_mutation_hint');
  }

  function classifyTool(event) {
    const result = new Result();
    const rawName = String(event.tool_name || '');
    const name = rawName.replace(/^functions\./, '');
    const lower = name.toLowerCase();
    const input = event.tool_input && typeof event.tool_input === 'object' ? event.tool_input : {};
    const ctx = newContext(event.cwd);
    result.tool = { name: redactText(rawName, 96), kind: 'other' };

    if (!name) return result.raise('unknown', 'missing_tool_name');
    if (lower.startsWith(marrowPrefix) && /^[a-z0-9_]+$/.test(lower.slice(marrowPrefix.length))) {
      result.tool.kind = 'marrow';
      return result;
    }
    if (lower.startsWith('mcp__') || lower.startsWith('mcp:')) {
      result.tool.kind = 'mcp';
      const verbs = splitVerbs(name.split(/__|:/).slice(2).join('_') || name);
      if (verbs.some((verb) => mutationVerbs.has(verb))) return result.raise('risky', 'mcp_mutation_verb');
      return result.raise('unknown', 'mcp_tool');
    }
    if (toolSets.shell.has(lower)) {
      result.tool.kind = 'shell';
      const command = input.command !== undefined ? input.command : input.cmd;
      if (Array.isArray(command)) return result.merge(classifyArgvArray(command.map(String), ctx, input.workdir));
      if (typeof command !== 'string' || !command.trim()) return result.raise('unknown', 'missing_command');
      if (typeof input.workdir === 'string' && path.isAbsolute(input.workdir)) { ctx.cwd = input.workdir; ctx.cwdUnknown = false; }
      return result.merge(classifyShellSource(command, ctx, 0));
    }
    if (toolSets.edit.has(lower)) {
      result.tool.kind = 'edit';
      const targets = lower === 'apply_patch'
        ? patchPaths(typeof input === 'string' ? input : input.input || input.patch || input.command || '')
        : toolInputPaths(input);
      if (lower === 'apply_patch' && targets.length === 0 && typeof event.tool_input === 'string') targets.push(...patchPaths(event.tool_input));
      if (targets.length === 0) return result.raise('unknown', 'edit_without_path');
      for (const target of targets) checkWritePath(target, ctx, result);
      return result;
    }
    if (toolSets.readOnly.has(lower)) {
      result.tool.kind = 'read';
      for (const target of toolInputPaths(input)) checkReadPath(target, ctx, result);
      if (typeof input.pattern === 'string' && /\.(?:aws|ssh)\b|\.env\b|id_rsa|id_ed25519|credentials/.test(input.pattern) && lower === 'glob') result.raise('unknown', 'secret_glob');
      return result;
    }
    if (toolSets.fetch.has(lower)) {
      result.tool.kind = 'fetch';
      if (typeof input.url === 'string') classifyUrl(input.url, result);
      else result.raise('unknown', 'fetch_without_url');
      return result;
    }
    const verbs = splitVerbs(name);
    if (verbs.some((verb) => mutationVerbs.has(verb))) return result.raise('risky', 'tool_mutation_verb');
    return result.raise('unknown', 'unlisted_tool');
  }

  // Codex can send an exact argv (`["bash","-lc","git status"]`).
  function classifyArgvArray(argv, ctx, workdir) {
    if (typeof workdir === 'string' && path.isAbsolute(workdir)) { ctx.cwd = workdir; ctx.cwdUnknown = false; }
    const words = argv.map((text) => ({ text, dynamic: false, quoted: true, slots: [] }));
    const command = { words, assignments: [], redirects: [], heredoc: null, pipedInput: false };
    return classifySimple(command, ctx, 0);
  }

  // ---------- shell ----------
  function classifyShellSource(source, ctx, depth) {
    const result = new Result();
    if (depth > MAX_DEPTH) return result.raise('unknown', 'nesting_depth');
    const parsed = parseShell(source, { depth });
    if (!parsed.ok) return result.raise('unknown', `unparseable:${parsed.error}`);
    for (const reason of parsed.reasons) {
      if (['case_statement', 'coproc_statement', 'unterminated_heredoc', 'dangling_redirect'].includes(reason)) result.raise('unknown', reason);
    }
    // Each substitution is classified on its own. Its output becomes a dynamic word, which every
    // handler treats conservatively (dynamic program -> unknown, dynamic write/delete/read target
    // -> unknown or risky), so a routine substitution used as, say, a commit message stays routine.
    for (const inner of parsed.substitutions) {
      result.merge(classifyShellSource(inner, { ...ctx, vars: new Map(ctx.vars) }, depth + 1));
    }
    for (const command of parsed.commands) {
      if (command.forLoop) {
        const { name, items } = command.forLoop;
        const values = [];
        let resolvable = Array.isArray(items) && typeof name === 'string';
        for (const item of items || []) {
          const alternatives = resolveWordAlternatives(item, ctx);
          if (!alternatives) { resolvable = false; break; }
          values.push(...alternatives);
        }
        if (resolvable && values.length > 0 && values.length <= MAX_ALTERNATIVES) ctx.vars.set(name, values);
        else if (typeof name === 'string') ctx.vars.delete(name);
        continue;
      }
      for (const assignment of command.assignments) {
        const eq = assignment.text.indexOf('=');
        const name = assignment.text.slice(0, eq).replace(/\+$/, '');
        const valueWord = { ...assignment, text: assignment.text.slice(eq + 1) };
        const value = resolveWordText(valueWord, ctx);
        if (command.words.length === 0) {
          if (value === null) ctx.vars.delete(name);
          else ctx.vars.set(name, value);
        }
        if (SENSITIVE_ENV.test(name)) result.raise('unknown', 'sensitive_env_assignment');
      }
      result.merge(classifySimple(command, ctx, depth));
    }
    return result;
  }

  function classifySimple(command, ctx, depth) {
    const result = new Result();
    for (const redirect of command.redirects) {
      if (redirect.op === '>&' || redirect.op === '<&') {
        const text = redirect.target ? resolveWordText(redirect.target, ctx) : null;
        if (text !== null && /^(?:[0-9]+|-)$/.test(text)) continue;
        checkWritePath(text, ctx, result);
        continue;
      }
      if (OUTPUT_REDIRECTS.has(redirect.op)) {
        checkWritePath(redirect.target ? resolveWordText(redirect.target, ctx) : null, ctx, result);
      } else if (redirect.op === '<' || redirect.op === '<<<') {
        const text = redirect.target ? resolveWordText(redirect.target, ctx) : null;
        if (redirect.op === '<' && text) checkReadPath(text, ctx, result);
      }
    }
    if (command.words.length === 0) return result;
    const perWord = command.words.map((word) => resolveWordAlternatives(word, ctx));
    let combos = [[]];
    for (let k = 0; k < perWord.length; k += 1) {
      const options = perWord[k] || [null];
      const next = [];
      for (const combo of combos) for (const option of options) next.push([...combo, { word: command.words[k], text: option }]);
      if (next.length > MAX_ALTERNATIVES) return result.raise('unknown', 'too_many_alternatives');
      combos = next;
    }
    for (const args of combos) result.merge(classifyWords(args, command, ctx, depth, false));
    return result;
  }

  // `args` is [{word, text|null}]; `extraDynamic` marks argv that gains unseen arguments (xargs).
  function classifyWords(args, command, ctx, depth, extraDynamic) {
    const result = new Result();
    let i = 0;
    for (;;) {
      if (i >= args.length) return result;
      const first = args[i];
      if (first.text === null) return result.raise('unknown', 'dynamic_program');
      const program = first.text;
      if (program === '') return result.raise('unknown', 'empty_program');
      const base = programBase(program);
      if (privilegeWrappers.has(base)) {
        result.raise('risky', 'privilege_escalation');
        result.note('programs', base);
        i = skipWrapperOptions(base, args, i + 1);
        continue;
      }
      if (wrappers.has(base)) {
        result.note('programs', base);
        if (base === 'env' && args.slice(i + 1).some((a) => a.text === '-S' || (a.text || '').startsWith('--split-string'))) return result.raise('unknown', 'env_split_string');
        if (base === 'env' && args.slice(i + 1).some((a) => a.text === null || (/^[A-Za-z_][A-Za-z0-9_]*=/.test(a.text) && SENSITIVE_ENV.test(a.text.slice(0, a.text.indexOf('=')))))) result.raise('unknown', 'sensitive_env_assignment');
        if (base === 'watch') {
          const rest = args.slice(skipWrapperOptions(base, args, i + 1));
          if (rest.some((a) => a.text === null)) return result.raise('unknown', 'dynamic_watch');
          return result.merge(classifyShellSource(rest.map((a) => a.text).join(' '), ctx, depth + 1));
        }
        if (base === 'retry') return result.raise('unknown', 'retry_wrapper');
        if (base === 'xargs') extraDynamic = true;
        if (base === 'command' && args[i + 1] && /^-[vV]$/.test(args[i + 1].text || '')) return result;
        if (base === 'env' && args.length === i + 1) return result;
        i = skipWrapperOptions(base, args, i + 1);
        if (i >= args.length) return result;
        continue;
      }
      result.note('programs', base);
      const argvTexts = args.slice(i).map((a) => (a.text === null ? '[dynamic]' : a.text));
      if (argvTexts.length > 32 || argvTexts.reduce((n, t) => n + t.length + 1, 0) > MAX_COMMAND_CHARS) result.truncated = true;
      result.add('commands', redactArgv(argvTexts, { maxArgs: 32, maxLength: 400 }).join(' ').slice(0, MAX_COMMAND_CHARS));
      if (program.includes('/') && !SYSTEM_BIN.test(program)) {
        return result.merge(classifyScriptExecution(program, args.slice(i + 1), command, ctx, depth));
      }
      return result.merge(classifyProgram(base, args.slice(i + 1), command, ctx, depth, extraDynamic));
    }
  }

  function programBase(program) {
    const base = path.basename(program);
    return base.replace(/\.exe$/i, '');
  }

  function skipWrapperOptions(base, args, index) {
    let i = index;
    const valueFlags = {
      env: ['-u', '--unset', '-C', '--chdir'],
      timeout: ['-s', '--signal', '-k', '--kill-after'],
      nice: ['-n', '--adjustment'],
      ionice: ['-c', '-n', '-p', '--class', '--classdata'],
      stdbuf: ['-i', '-o', '-e'],
      xargs: ['-n', '-I', '-P', '-d', '-L', '-a', '-E', '-s', '--max-args', '--max-procs', '--delimiter', '--arg-file', '-i'],
      sudo: ['-u', '-g', '-h', '-p', '-C', '-U', '-r', '-t', '--user', '--group', '--host', '--prompt'],
      doas: ['-u', '-C'],
      su: ['-c', '-s', '-g'],
      exec: ['-a'],
      watch: ['-n', '--interval', '-d', '--differences'],
      chrt: [],
      taskset: [],
    }[base] || [];
    while (i < args.length) {
      const text = args[i].text;
      if (text === null) return i;
      if (text === '--') return i + 1;
      if (base === 'env' && /^[A-Za-z_][A-Za-z0-9_]*=/.test(text)) { i += 1; continue; }
      if (!text.startsWith('-') || text === '-') break;
      if (valueFlags.includes(text)) { i += 2; continue; }
      i += 1;
    }
    if (base === 'timeout' && i < args.length && /^[0-9.]+[smhd]?$/.test(args[i].text || '')) i += 1;
    if ((base === 'chrt' || base === 'taskset') && i < args.length) i += 1;
    return i;
  }

  function positionals(args, valueFlags = []) {
    const out = [];
    for (let i = 0; i < args.length; i += 1) {
      const text = args[i].text;
      if (text === null) { out.push(args[i]); continue; }
      if (text === '--') { out.push(...args.slice(i + 1)); break; }
      if (text.startsWith('-') && text !== '-') {
        if (valueFlags.includes(text)) i += 1;
        continue;
      }
      out.push(args[i]);
    }
    return out;
  }

  function hasFlag(args, ...flags) {
    return args.some((a) => a.text !== null && flags.some((flag) => (flag.length === 2 && flag[0] === '-' && flag[1] !== '-'
      ? a.text === flag || (/^-[A-Za-z]+$/.test(a.text) && a.text.includes(flag[1]))
      : a.text === flag || a.text.startsWith(`${flag}=`))));
  }

  function flagValue(args, ...flags) {
    for (let i = 0; i < args.length; i += 1) {
      const text = args[i].text;
      if (text === null) continue;
      for (const flag of flags) {
        if (text === flag) return args[i + 1] ? args[i + 1].text : null;
        if (text.startsWith(`${flag}=`)) return text.slice(flag.length + 1);
      }
    }
    return undefined;
  }

  function classifyProgram(base, args, command, ctx, depth, extraDynamic) {
    const result = new Result();
    const rule = programs[base];
    if (shells.has(base) && rule === undefined) return result.merge(classifyShellProgram(base, args, command, ctx, depth));
    if (interpreters.has(base) && (rule === undefined || (rule && rule.handler === 'interpreter'))) return result.merge(classifyInterpreter(base, args, command, ctx));
    if (rule === undefined) return result.raise('unknown', `unlisted_program:${base.slice(0, 40)}`);
    if (rule === 'routine') {
      if (extraDynamic) return result;
      return result;
    }
    if (rule === 'unknown') return result.raise('unknown', `opaque_program:${base}`);
    if (rule === 'risky') return result.raise('risky', `risky_program:${base}`);
    if (rule.read) return classifyReadProgram(base, args, ctx, result);
    if (rule.write) {
      const pos = positionals(args, ['-m', '--mode', '-o', '--owner', '-g', '--group', '-t', '--target-directory', '-S', '--suffix']);
      // cp/mv/ln/install read their sources and write the last argument; the rest (mkdir, touch,
      // tee...) only write. A secret file copied anywhere is a secret read.
      const copies = ['cp', 'mv', 'ln', 'install'].includes(base);
      pos.forEach((arg, index) => {
        if (copies && index < pos.length - 1 && arg.text !== null) checkReadPath(arg.text, ctx, result);
        checkWritePath(arg.text, ctx, result);
      });
      if (extraDynamic) result.raise('unknown', 'xargs_targets');
      return result;
    }
    if (rule.sub) return classifySubcommand(base, rule, args, result);
    const handler = HANDLERS[rule.handler];
    if (!handler) return result.raise('unknown', `unhandled:${base}`);
    return result.merge(handler(base, args, command, ctx, depth, extraDynamic));
  }

  // `grep -c NAME ~/.marrow/env` (count, list or quiet output; the pattern a plain variable name)
  // reveals only whether a name is present - the owner's own rule for checking credentials. Any
  // other pattern could probe the value one character at a time, so it stays a secret read.
  function isNameOnlyGrep(base, args) {
    if (!['grep', 'egrep', 'fgrep'].includes(base)) return false;
    const flags = args.filter((a) => a.text !== null && a.text.startsWith('-')).map((a) => a.text);
    if (flags.some((f) => !/^-(?:[cqlLsFwx]+|-count|-quiet|-silent|-files-with-matches|-files-without-match|-fixed-strings|-word-regexp|-no-messages)$/.test(f))) return false;
    if (!flags.some((f) => /^-[a-zA-Z]*[cqlL]|^--(?:count|quiet|silent|files-with-matches|files-without-match)$/.test(f))) return false;
    const positional = args.filter((a) => a.text === null || !a.text.startsWith('-'));
    return positional.length >= 2 && positional[0].text !== null && /^\^?[A-Za-z_][A-Za-z0-9_]*=?$/.test(positional[0].text);
  }

  function classifyReadProgram(base, args, ctx, result) {
    if (isNameOnlyGrep(base, args)) return result;
    // A recursive read rooted at the home directory or above reads every credential file in it.
    const recursive = (['grep', 'egrep', 'fgrep'].includes(base) && hasFlag(args, '-r', '-R', '--recursive', '--dereference-recursive'))
      || (['rg', 'ag', 'ack'].includes(base) && hasFlag(args, '--hidden', '-u', '-uu', '-uuu', '--no-ignore'))
      || (base === 'zip' && hasFlag(args, '-r', '--recurse-paths'));
    if (recursive) {
      const targets = args.filter((a) => a.text !== null && !a.text.startsWith('-'));
      if (targets.some((a) => isBroadTarget(a.text, ctx) && absPath(a.text, ctx) !== ctx.cwd) || (ctx.cwd === home)) result.raise('unknown', 'recursive_read_of_home');
    }
    const patternFirst = ['grep', 'egrep', 'fgrep', 'rg', 'ag', 'ack', 'jq', 'yq'].includes(base)
      && !hasFlag(args, '-e', '-f', '--regexp', '--file');
    let skippedPattern = !patternFirst;
    for (const arg of args) {
      if (arg.text === null) {
        if (!skippedPattern) { skippedPattern = true; continue; }
        result.raise('unknown', 'dynamic_read_target');
        continue;
      }
      const value = arg.text.startsWith('-') ? (arg.text.includes('=') ? arg.text.slice(arg.text.indexOf('=') + 1) : null) : arg.text;
      if (!arg.text.startsWith('-') && !skippedPattern) { skippedPattern = true; continue; }
      if (value) checkReadPath(value, ctx, result);
    }
    return result;
  }

  function classifySubcommand(base, rule, args, result) {
    const valueFlags = subFlagsWithValue[rule.skip || base] || [];
    let selector = null;
    if (rule.flags) selector = args[0] ? args[0].text : null;
    else {
      const first = positionals(args, valueFlags)[0];
      selector = first ? first.text : undefined;
    }
    if (selector === undefined) return result;
    if (selector === null) return result.raise('unknown', `dynamic_subcommand:${base}`);
    const cls = Object.prototype.hasOwnProperty.call(rule.sub, selector) ? rule.sub[selector] : rule.default || 'unknown';
    return result.raise(cls, `${base}:${String(selector).slice(0, 32)}`);
  }

  function classifyScriptExecution(program, args, command, ctx, depth) {
    const result = new Result();
    const abs = absPath(program, ctx);
    if (!abs) return result.raise('unknown', 'script_cwd_unknown');
    result.note('paths', relLabel(abs, ctx));
    return result.merge(classifyScriptFile(abs, ctx, depth));
  }

  function readSmallFile(abs, max) {
    try {
      const stat = fs.statSync(abs);
      if (!stat.isFile() || stat.size > max) return null;
      return fs.readFileSync(abs, 'utf8');
    } catch {
      return null;
    }
  }

  function classifyScriptFile(abs, ctx, depth) {
    const result = new Result();
    if (ctx.written && (ctx.written.has(abs) || ctx.written.has(realOf(abs)))) return result.raise('unknown', 'script_written_in_same_command');
    if (isProtected(abs) && !abs.startsWith(`${home}/.marrow/agentd/`)) result.raise('unknown', 'protected_path_exec');
    const content = readSmallFile(abs, SCRIPT_MAX_BYTES);
    if (content === null) return result.raise('unknown', 'script_unreadable');
    if (content.includes('\u0000')) return result.raise('unknown', 'binary_executable');
    const shebang = content.startsWith('#!') ? content.slice(2, content.indexOf('\n') >>> 0).trim() : '';
    const interp = shebang ? programBase(shebang.split(/\s+/)[0] === '/usr/bin/env' || shebang.startsWith('/usr/bin/env ')
      ? shebang.split(/\s+/).filter((s) => !s.startsWith('-'))[1] || '' : shebang.split(/\s+/)[0]) : '';
    if (!shebang || shells.has(interp)) {
      const scriptCtx = { ...ctx, vars: new Map(ctx.vars) };
      return result.merge(classifyShellSource(content, scriptCtx, depth + 1));
    }
    if (interpreterDanger.test(content)) return result.raise('risky', 'script_interpreter_danger');
    return result.raise('unknown', `script_interpreter:${interp.slice(0, 24)}`);
  }

  function classifyShellProgram(base, args, command, ctx, depth) {
    const result = new Result();
    for (let i = 0; i < args.length; i += 1) {
      const text = args[i].text;
      if (text === null) return result.raise('unknown', 'dynamic_shell_arg');
      if (text === '-c' || (/^-[a-zA-Z]*c[a-zA-Z]*$/.test(text) && !text.startsWith('--'))) {
        const body = args[i + 1];
        if (!body || body.text === null) return result.raise('unknown', 'dynamic_shell_body');
        return result.merge(classifyShellSource(body.text, { ...ctx, vars: new Map(ctx.vars) }, depth + 1));
      }
      if (text === '-s' || text === '--') break;
      if (text.startsWith('-') || text.startsWith('+')) continue;
      const abs = absPath(text, ctx);
      if (!abs) return result.raise('unknown', 'script_cwd_unknown');
      result.note('paths', relLabel(abs, ctx));
      return result.merge(classifyScriptFile(abs, ctx, depth));
    }
    if (command.heredoc !== null && command.heredoc !== undefined) {
      if (command.heredocDynamic) return result.raise('unknown', 'dynamic_heredoc');
      return result.merge(classifyShellSource(command.heredoc, { ...ctx, vars: new Map(ctx.vars) }, depth + 1));
    }
    return result.raise('unknown', 'shell_reads_stdin');
  }

  function classifyInterpreter(base, args, command, ctx) {
    const result = new Result();
    if (args.length === 0) {
      if (command.heredoc) return result.raise(interpreterDanger.test(command.heredoc) ? 'risky' : 'unknown', 'interpreter_stdin');
      return result.raise('unknown', 'interpreter_stdin');
    }
    if (args.every((a) => a.text !== null && /^(?:--version|-v|-V|--help|-h)$/.test(a.text))) return result;
    for (let i = 0; i < args.length; i += 1) {
      const text = args[i].text;
      if (text === null) return result.raise('unknown', 'dynamic_interpreter_arg');
      if (['-c', '-e', '--eval', '-p', '--print', '-E', '-r', '-x'].includes(text) || /^-[A-Za-z]*[ce]$/.test(text)) {
        const body = args[i + 1] ? args[i + 1].text : null;
        if (body === null) return result.raise('unknown', 'dynamic_inline_code');
        return result.raise(interpreterDanger.test(body) ? 'risky' : 'unknown', 'inline_code');
      }
      if (text === '-m' && base.startsWith('python')) {
        const module = args[i + 1] ? args[i + 1].text : null;
        if (module && routinePythonModules.has(module)) {
          if (module === 'pip' && args[i + 2] && ['uninstall'].includes(args[i + 2].text)) return result.raise('unknown', 'pip_uninstall');
          return result;
        }
        return result.raise('unknown', `python_module:${String(module).slice(0, 32)}`);
      }
      if ((base === 'node' || base === 'nodejs') && ['--test', '--check', '-c'].includes(text)) {
        if (text === '--test') return result;
        return result;
      }
      if (text.startsWith('-')) continue;
      const abs = absPath(text, ctx);
      if (abs) result.note('paths', relLabel(abs, ctx));
      const content = abs ? readSmallFile(abs, SCRIPT_MAX_BYTES) : null;
      if (content && interpreterDanger.test(content)) return result.raise('risky', 'script_interpreter_danger');
      return result.raise('unknown', 'interpreter_script');
    }
    return result.raise('unknown', 'interpreter');
  }

  // ---------- program handlers ----------
  const HANDLERS = {
    export(base, args) {
      const result = new Result();
      for (const arg of args) {
        if (arg.text === null) { result.raise('unknown', 'dynamic_export'); continue; }
        if (/^-[a-zA-Z]*f/.test(arg.text)) result.raise('unknown', 'export_function');
        const name = arg.text.split('=')[0].replace(/\+$/, '');
        if (SENSITIVE_ENV.test(name)) result.raise('unknown', 'sensitive_env_assignment');
      }
      return result;
    },
    pip(base, args, command, ctx) {
      const result = new Result();
      const pos = positionals(args, ['-r', '--requirement', '-c', '--constraint', '-i', '--index-url', '--extra-index-url', '-t', '--target', '--prefix', '--root']);
      const sub = pos[0] ? pos[0].text : undefined;
      if (sub === undefined || ['list', 'show', 'freeze', 'check', 'help', '--version'].includes(sub)) return result;
      if (sub === null) return result.raise('unknown', 'dynamic_pip_arg');
      if (sub !== 'install') return result.raise('unknown', `pip:${String(sub).slice(0, 24)}`);
      // Installing a local path, an editable project, a VCS URL or a requirements file can run
      // code the agent wrote (setup.py, build backends).
      if (hasFlag(args, '-e', '--editable', '--index-url', '-i', '--extra-index-url')) return result.raise('unknown', 'pip_install_local_or_index');
      for (let i = 0; i < args.length; i += 1) {
        const text = args[i].text;
        if (text !== '-r' && text !== '--requirement' && !(text || '').startsWith('--requirement=')) continue;
        const file = text.startsWith('--requirement=') ? text.slice(14) : (args[i + 1] ? args[i + 1].text : null);
        if (!requirementsArePlain(file, ctx)) return result.raise('unknown', 'pip_requirements_not_plain');
      }
      for (const arg of pos.slice(1)) {
        if (arg.text === null || /[/\\]|^\.|^(?:git|hg|svn|bzr)\+|\.(?:whl|zip|tar\.gz|tgz)$|@/.test(arg.text)) return result.raise('unknown', 'pip_install_local_or_url');
      }
      return result;
    },
    cd(base, args, command, ctx) {
      const result = new Result();
      const target = positionals(args)[0];
      if (!target) { ctx.cwd = home; ctx.cwdUnknown = false; return result; }
      if (target.text === null || target.text === '-') { ctx.cwdUnknown = true; return result; }
      const abs = absPath(target.text, ctx);
      if (!abs) { ctx.cwdUnknown = true; return result; }
      ctx.cwd = abs;
      ctx.cwdUnknown = false;
      return result;
    },
    rg(base, args, command, ctx) {
      const result = new Result();
      if (hasFlag(args, '--pre')) return result.raise('unknown', 'rg_pre');
      return classifyReadProgram(base, args, ctx, result);
    },
    find(base, args, command, ctx, depth) {
      const result = new Result();
      for (let i = 0; i < args.length; i += 1) {
        const text = args[i].text;
        if (text === null) continue;
        if (['-exec', '-execdir', '-ok', '-okdir'].includes(text)) {
          const inner = [];
          let j = i + 1;
          while (j < args.length && args[j].text !== ';' && args[j].text !== '+') {
            inner.push(args[j].text === '{}' ? { word: args[j].word, text: null } : args[j]);
            j += 1;
          }
          result.raise('unknown', 'find_exec');
          result.merge(classifyWords(inner.map((a, k) => (k === 0 ? a : a)), { redirects: [], heredoc: null }, ctx, depth + 1, true));
          i = j;
          continue;
        }
        if (text === '-delete') result.raise('unknown', 'find_delete');
        if (/^-f(?:print|printf|ls)/.test(text)) result.raise('unknown', 'find_write');
        if (!text.startsWith('-') && !['(', ')', '!', ','].includes(text)) checkReadPath(text, ctx, result);
      }
      return result;
    },
    fd(base, args, command, ctx) {
      const result = new Result();
      if (hasFlag(args, '-x', '-X', '--exec', '--exec-batch')) return result.raise('unknown', 'fd_exec');
      return classifyReadProgram(base, args, ctx, result);
    },
    awk(base, args, command, ctx) {
      const result = new Result();
      if (hasFlag(args, '-f', '--file')) return result.raise('unknown', 'awk_program_file');
      const pos = positionals(args, ['-F', '-v', '--field-separator', '--assign']);
      const program = pos[0];
      if (!program) return result.raise('unknown', 'awk_without_program');
      if (program.text === null) return result.raise('unknown', 'dynamic_awk_program');
      if (/system\s*\(|\|\s*"|\|&|print[^;}]*>|getline\s*<|"\s*\|\s*getline/.test(program.text)) {
        return result.raise(interpreterDanger.test(program.text) ? 'risky' : 'unknown', 'awk_side_effect');
      }
      for (const arg of pos.slice(1)) {
        if (arg.text === null) result.raise('unknown', 'dynamic_read_target');
        else checkReadPath(arg.text, ctx, result);
      }
      return result;
    },
    sed(base, args, command, ctx) {
      const result = new Result();
      const inPlace = args.some((a) => a.text !== null && (/^-[a-zA-Z]*i/.test(a.text) || a.text.startsWith('--in-place')));
      const explicitScript = hasFlag(args, '-e', '--expression', '-f', '--file');
      const pos = positionals(args, ['-e', '--expression', '-f', '--file', '-l']);
      const scripts = [];
      for (let i = 0; i < args.length; i += 1) if (['-e', '--expression'].includes(args[i].text) && args[i + 1]) scripts.push(args[i + 1].text);
      const files = explicitScript ? pos : pos.slice(1);
      if (!explicitScript && pos[0]) scripts.push(pos[0].text);
      if (hasFlag(args, '-f', '--file')) result.raise('unknown', 'sed_script_file');
      for (const script of scripts) {
        if (script === null) { result.raise('unknown', 'dynamic_sed_script'); continue; }
        if (/(^|[;}\n])\s*[0-9,$/!]*\s*e\b|\bw\s+\S|\bW\s+\S/.test(script)) result.raise('unknown', 'sed_exec_or_write');
        // GNU sed's `e` flag on s/// executes the pattern space as a command.
        if (/[/|#,:@!_]\s*[gpIiMm0-9]*e[gpIiMm0-9]*\s*(?:$|[;}\n])/.test(script)) result.raise('unknown', 'sed_exec_flag');
      }
      for (const file of files) {
        if (inPlace) checkWritePath(file.text, ctx, result);
        else if (file.text === null) result.raise('unknown', 'dynamic_read_target');
        else checkReadPath(file.text, ctx, result);
      }
      return result;
    },
    rm(base, args, command, ctx, depth, extraDynamic) {
      const result = new Result();
      const recursive = hasFlag(args, '-r', '-R', '--recursive');
      const force = hasFlag(args, '-f', '--force');
      const targets = positionals(args);
      if (extraDynamic) result.raise(recursive || force ? 'risky' : 'unknown', 'rm_dynamic_targets');
      for (const target of targets) {
        if (target.text === null) { result.raise(recursive ? 'risky' : 'unknown', 'rm_dynamic_target'); continue; }
        const raw = target.text;
        const abs = absPath(raw, ctx);
        if (isBroadTarget(raw, ctx)) { result.raise('risky', 'rm_broad_target'); result.note('paths', relLabel(abs, ctx)); continue; }
        // Deleting a repository's .git loses every unpushed commit.
        if (abs && (path.basename(abs) === '.git' || abs.includes('/.git/'))) { result.raise('risky', 'rm_git_dir'); continue; }
        checkWritePath(raw, ctx, result, { recursiveDelete: recursive });
      }
      return result;
    },
    chmod(base, args, command, ctx) {
      const result = new Result();
      const recursive = hasFlag(args, '-R', '--recursive');
      const pos = positionals(args, ['--reference']);
      for (const target of pos.slice(1)) {
        if (recursive && target.text !== null && isBroadTarget(target.text, ctx)) { result.raise('risky', `${base}_recursive_broad`); continue; }
        checkWritePath(target.text, ctx, result, { recursiveDelete: recursive });
      }
      return result;
    },
    archive(base, args, command, ctx) {
      const result = new Result();
      const dest = flagValue(args, '-C', '--directory', '-d');
      if (dest === null) return result.raise('unknown', 'dynamic_extract_target');
      if (dest !== undefined) checkWritePath(dest, ctx, result);
      for (const arg of positionals(args, ['-C', '--directory', '-d', '-f', '--file'])) {
        if (arg.text !== null) checkReadPath(arg.text, ctx, result);
      }
      const archiveFile = flagValue(args, '-f', '--file');
      if (typeof archiveFile === 'string' && /^-?[a-zA-Z]*c/.test((args[0] && args[0].text) || '')) checkWritePath(archiveFile, ctx, result);
      return result;
    },
    git(base, args, command, ctx) {
      const result = new Result();
      let i = 0;
      let gitCwd = ctx.cwd;
      let gitCwdUnknown = ctx.cwdUnknown;
      while (i < args.length) {
        const text = args[i].text;
        if (text === null) return result.raise('unknown', 'dynamic_git_arg');
        if (text === '-C') {
          const dir = args[i + 1] ? args[i + 1].text : null;
          const abs = dir === null ? null : absPath(dir, { cwd: gitCwd, cwdUnknown: gitCwdUnknown });
          gitCwd = abs; gitCwdUnknown = !abs; i += 2; continue;
        }
        if (text === '-c') {
          const setting = args[i + 1] ? args[i + 1].text : null;
          if (setting === null || /^(?:core\.(?:hookspath|sshcommand|pager|editor|fsmonitor|gitproxy)|alias\.|credential\.|url\.|protocol\.|http\.)/i.test(setting)) result.raise('unknown', 'git_sensitive_config_override');
          i += 2; continue;
        }
        if (text.startsWith('--git-dir') || text.startsWith('--work-tree')) { result.raise('unknown', 'git_dir_override'); i += text.includes('=') ? 1 : 2; continue; }
        if (text.startsWith('-')) { i += 1; continue; }
        break;
      }
      if (i >= args.length) return result;
      const sub = args[i].text;
      const rest = args.slice(i + 1);
      const gitCtx = { ...ctx, cwd: gitCwd, cwdUnknown: gitCwdUnknown };
      const has = (...flags) => hasFlag(rest, ...flags);
      const pos = positionals(rest);
      const routineSubs = new Set(['status', 'diff', 'log', 'show', 'blame', 'fetch', 'pull', 'add', 'commit', 'switch', 'rev-parse', 'ls-files', 'ls-tree', 'cat-file', 'describe', 'shortlog', 'grep', 'reflog', 'bisect', 'format-patch', 'mv', 'rm', 'init', 'clone', 'cherry-pick', 'revert', 'merge', 'rebase', 'apply', 'am', 'difftool', 'range-diff', 'show-ref', 'for-each-ref', 'count-objects', 'fsck', 'verify-commit', 'whatchanged', 'help', 'version', 'merge-base', 'name-rev', 'rev-list', 'check-ignore', 'check-attr', 'var', 'stage', 'show-branch', 'mergetool', 'restore-staged', 'sparse-checkout', 'maintenance']);
      switch (sub) {
        case 'push': return result.merge(classifyGitPush(rest, gitCtx));
        case 'branch': return has('-D', '--force', '-f', '-M', '-C') ? result.raise('unknown', 'git_branch_force') : result;
        case 'checkout': return (has('-f', '--force') || pos.some((a) => a.text === '.') || rest.some((a) => a.text === '--')) ? result.raise('unknown', 'git_checkout_discard') : result;
        case 'restore': return pos.some((a) => a.text === '.' || a.text === ':/') ? result.raise('unknown', 'git_restore_all') : result;
        case 'reset': return has('--hard', '--merge', '--keep') ? result.raise('unknown', 'git_reset_hard') : result;
        case 'clean': return has('-n', '--dry-run') ? result : result.raise('unknown', 'git_clean');
        case 'stash': return pos[0] && ['drop', 'clear'].includes(pos[0].text) ? result.raise('unknown', 'git_stash_drop') : result;
        case 'tag': return has('-d', '--delete', '-f', '--force') ? result.raise('unknown', 'git_tag_delete') : result;
        case 'remote': return pos[0] && ['add', 'remove', 'rm', 'set-url', 'rename', 'prune', 'set-head', 'set-branches'].includes(pos[0].text) ? result.raise('unknown', 'git_remote_change') : result;
        case 'config': {
          if (has('--get', '--get-all', '--list', '-l', '--show-origin', '--get-regexp', '--show-scope') || pos.length <= 1) return result;
          const key = pos[0] && pos[0].text ? pos[0].text.toLowerCase() : '';
          if (/^(?:core\.(?:hookspath|sshcommand|fsmonitor)|alias\.|credential\.|url\.)/.test(key)) return result.raise('risky', 'git_config_sensitive');
          return result.raise('unknown', 'git_config_set');
        }
        // Without --force git refuses to remove a worktree with changes, so plain remove is safe.
        case 'worktree': return pos[0] && ((pos[0].text === 'remove' && has('-f', '--force')) || pos[0].text === 'move') ? result.raise('unknown', 'git_worktree_remove') : result;
        case 'submodule': return pos[0] && pos[0].text === 'foreach' ? result.raise('unknown', 'git_submodule_foreach') : result;
        case 'filter-branch': case 'filter-repo': return result.raise('risky', 'git_history_rewrite');
        case 'gc': case 'prune': case 'repack': case 'update-ref': case 'replace': case 'notes': case 'lfs': case 'send-email': case 'daemon': case 'svn': case 'p4':
          return result.raise('unknown', `git:${sub}`);
        default:
          if (routineSubs.has(sub)) return result;
          return result.raise('unknown', `git:${String(sub).slice(0, 32)}`);
      }
    },
    gh(base, args) {
      const result = new Result();
      const pos = positionals(args, subFlagsWithValue.gh || []);
      if (pos.length === 0) return result;
      if (pos.some((a, k) => k < 2 && a.text === null)) return result.raise('unknown', 'dynamic_gh_arg');
      const [group, action] = [pos[0].text, pos[1] ? pos[1].text : null];
      const maps = {
        pr: { routine: ['view', 'list', 'status', 'diff', 'checks', 'create', 'comment', 'edit', 'ready', 'checkout', 'develop'], risky: ['merge'] },
        issue: { routine: ['view', 'list', 'status', 'create', 'comment', 'edit', 'develop'], risky: ['delete', 'transfer'] },
        run: { routine: ['view', 'list', 'watch', 'download'], risky: [] },
        workflow: { routine: ['list', 'view'], risky: ['run', 'enable', 'disable'] },
        repo: { routine: ['view', 'list', 'clone', 'fork', 'set-default'], risky: ['delete', 'archive', 'rename', 'edit', 'unarchive'] },
        release: { routine: ['list', 'view', 'download'], risky: ['create', 'delete', 'upload', 'edit', 'delete-asset'] },
        secret: { routine: ['list'], risky: ['set', 'delete', 'remove'] },
        variable: { routine: ['list', 'get'], risky: ['set', 'delete', 'remove'] },
        auth: { routine: ['status'], risky: ['token', 'login', 'logout', 'refresh', 'setup-git', 'switch'] },
        'ssh-key': { routine: ['list'], risky: ['add', 'delete'] },
        'gpg-key': { routine: ['list'], risky: ['add', 'delete'] },
        gist: { routine: ['view', 'list'], risky: [] },
        extension: { routine: ['list'], risky: [] },
        cache: { routine: ['list'], risky: [] },
        config: { routine: ['get', 'list'], risky: [] },
        label: { routine: ['list'], risky: ['delete'] },
      };
      if (['search', 'browse', 'status', 'help', 'version', 'completion'].includes(group)) return result;
      if (group === 'pr' && action === 'review' && hasFlag(args, '--approve')) return result.raise('unknown', 'gh_pr_approve');
      if (group === 'pr' && action === 'review') return result;
      if (group === 'api') {
        const method = String(flagValue(args, '-X', '--method') || 'GET').toUpperCase();
        if (method === 'DELETE') return result.raise('risky', 'gh_api_delete');
        if (method !== 'GET' || hasFlag(args, '-f', '-F', '--field', '--raw-field', '--input')) return result.raise('unknown', 'gh_api_write');
        const endpoint = pos[1] ? pos[1].text : null;
        if (endpoint === null || urlMutation.test(endpoint) || /\/dispatches\b|\/merges?\b/.test(endpoint)) return result.raise('unknown', 'gh_api_mutation_hint');
        return result;
      }
      const map = maps[group];
      if (!map) return result.raise('unknown', `gh:${String(group).slice(0, 24)}`);
      if (action === null) return result.raise('unknown', 'dynamic_gh_arg');
      if (!action || map.routine.includes(action)) return result;
      if (map.risky.includes(action)) return result.raise('risky', `gh:${group}:${action}`);
      return result.raise('unknown', `gh:${group}:${String(action).slice(0, 24)}`);
    },
    pkg(base, args, command, ctx, depth) {
      const result = new Result();
      const pos = positionals(args, subFlagsWithValue[base] || []);
      if (pos.length === 0) return base === 'yarn' ? result : result;
      if (pos[0].text === null) return result.raise('unknown', 'dynamic_pkg_subcommand');
      const sub = pos[0].text;
      const routineSubs = new Set(['install', 'i', 'ci', 'add', 'remove', 'rm', 'uninstall', 'un', 'ls', 'list', 'll', 'la', 'outdated', 'view', 'info', 'show', 'why', 'explain', 'audit', 'pack', 'doctor', 'help', 'prune', 'dedupe', 'rebuild', 'init', 'fund', 'bin', 'root', 'prefix', 'search', 'update', 'up', 'upgrade', 'whoami', 'licenses', 'exec-env', 'store', 'import', 'install-test', 'it', 'cit', 'clean-install']);
      const riskySubs = new Set(['publish', 'unpublish', 'deprecate', 'dist-tag', 'owner', 'access', 'team', 'token', 'adduser', 'login', 'logout', 'org', 'profile', 'hook', 'star', 'unstar', 'npm', 'trust']);
      if (riskySubs.has(sub)) return result.raise('risky', `${base}:${sub}`);
      if (sub === 'config' || sub === 'c' || sub === 'set') {
        const action = pos[1] ? pos[1].text : null;
        return ['get', 'list', 'ls'].includes(action) ? result : result.raise('risky', `${base}:config_set`);
      }
      if (['exec', 'x', 'dlx', 'create', 'link', 'ln', 'version', 'set-script', 'patch', 'edit', 'repo', 'docs'].includes(sub)) return result.raise('unknown', `${base}:${sub}`);
      if (['test', 't', 'tst', 'start', 'stop', 'restart'].includes(sub)) return result.merge(classifyPackageScript(sub === 't' || sub === 'tst' ? 'test' : sub, ctx, depth));
      if (sub === 'run' || sub === 'run-script' || sub === 'rum' || sub === 'urn') {
        const name = pos[1] ? pos[1].text : undefined;
        if (name === undefined) return result;
        if (name === null) return result.raise('unknown', 'dynamic_script_name');
        return result.merge(classifyPackageScript(name, ctx, depth));
      }
      // Installing, packing or rebuilding runs the ROOT package's lifecycle scripts (for example
      // "postinstall"), which the agent can write; classify them by content.
      if (INSTALL_SUBS.has(sub)) return result.merge(classifyLifecycleScripts(ctx, depth, sub === 'pack' ? PACK_LIFECYCLE : INSTALL_LIFECYCLE));
      if (routineSubs.has(sub)) return result;
      if (base === 'yarn' || base === 'pnpm') return result.merge(classifyPackageScript(sub, ctx, depth));
      return result.raise('unknown', `${base}:${String(sub).slice(0, 24)}`);
    },
    bun(base, args, command, ctx, depth) {
      const result = new Result();
      const pos = positionals(args);
      if (pos.length === 0) return result;
      const sub = pos[0].text;
      if (sub === null) return result.raise('unknown', 'dynamic_bun_arg');
      if (['install', 'i', 'add', 'update'].includes(sub)) return result.merge(classifyLifecycleScripts(ctx, depth, INSTALL_LIFECYCLE));
      if (['remove', 'outdated', 'pm', 'test', 'build'].includes(sub)) return result;
      if (sub === 'publish') return result.raise('risky', 'bun:publish');
      if (sub === 'x') return result.merge(HANDLERS.npx('bunx', args.slice(1), command, ctx, depth));
      if (sub === 'run') {
        const name = pos[1] ? pos[1].text : undefined;
        if (!name) return result.raise('unknown', 'bun_run');
        if (/\.[cm]?[jt]sx?$/.test(name)) return result.raise('unknown', 'bun_run_file');
        return result.merge(classifyPackageScript(name, ctx, depth));
      }
      return result.raise('unknown', 'bun_file_or_script');
    },
    npx(base, args, command, ctx, depth) {
      const result = new Result();
      let spec;
      let rest = [];
      for (let i = 0; i < args.length; i += 1) {
        const text = args[i].text;
        if (text === null) return result.raise('unknown', 'dynamic_npx_arg');
        if (text === '-c' || text === '--call') {
          const body = args[i + 1] ? args[i + 1].text : null;
          if (body === null) return result.raise('unknown', 'dynamic_npx_call');
          return result.merge(classifyShellSource(body, { ...ctx, vars: new Map(ctx.vars) }, depth + 1));
        }
        if (text === '-p' || text === '--package') {
          const pkg = args[i + 1] ? args[i + 1].text : '';
          if (/@getmarrow\//.test(pkg || '')) result.note('programs', 'marrow-package');
          i += 1; continue;
        }
        if (text.startsWith('--package=')) continue;
        if (text.startsWith('-')) continue;
        spec = text;
        rest = args.slice(i + 1);
        break;
      }
      if (!spec) return result.raise('unknown', 'npx_without_spec');
      const name = spec.replace(/^(@[^/]+\/[^@]+|[^@]+)@.*$/, '$1');
      if (/^@getmarrow\/install$|^marrow-install$/.test(name) || /^marrow-mcp$/.test(name)) {
        const action = positionals(rest)[0];
        const verb = action ? action.text : '';
        if (['control', 'uninstall', 'agentd', 'disable'].includes(verb) || verb === null) return result.raise('risky', 'marrow_control_change');
        if (['doctor', 'status', 'detect'].includes(verb)) return result;
        return result.raise('unknown', 'marrow_cli');
      }
      if (routineNpx.has(name)) return result;
      return result.raise('unknown', `npx:${String(name).slice(0, 32)}`);
    },
    interpreter(base, args, command, ctx) {
      return classifyInterpreter(base, args, command, ctx);
    },
    source(base, args, command, ctx, depth) {
      const result = new Result();
      const target = positionals(args)[0];
      if (!target || target.text === null) return result.raise('unknown', 'dynamic_source');
      const abs = absPath(target.text, ctx);
      if (!abs) return result.raise('unknown', 'script_cwd_unknown');
      return result.merge(classifyScriptFile(abs, ctx, depth));
    },
    docker(base, args) {
      const result = new Result();
      const pos = positionals(args, subFlagsWithValue.docker || []);
      if (pos.length === 0) return result;
      if (pos.some((a, k) => k < 2 && a.text === null)) return result.raise('unknown', 'dynamic_docker_arg');
      const [sub, sub2] = [pos[0].text, pos[1] ? pos[1].text : ''];
      const routine = ['ps', 'images', 'logs', 'inspect', 'version', 'info', 'build', 'pull', 'stats', 'top', 'port', 'diff', 'history', 'search', 'events', 'buildx'];
      const risky = ['rm', 'rmi', 'push', 'login', 'logout', 'prune', 'swarm', 'service', 'stack', 'secret', 'config', 'node', 'plugin', 'trust', 'manifest'];
      if (sub === 'compose') {
        if (['ps', 'logs', 'config', 'build', 'pull', 'ls', 'top', 'images', 'version'].includes(sub2)) return result;
        if (sub2 === 'down') return hasFlag(args, '-v', '--volumes', '--rmi') ? result.raise('risky', 'docker_compose_down_volumes') : result.raise('unknown', 'docker_compose_down');
        if (['rm', 'push', 'kill'].includes(sub2)) return result.raise('risky', `docker_compose_${sub2}`);
        return result.raise('unknown', `docker_compose_${String(sub2).slice(0, 16)}`);
      }
      if (['network', 'volume', 'image', 'container', 'system', 'builder', 'context'].includes(sub)) {
        if (['ls', 'list', 'inspect', 'df', 'show', 'history'].includes(sub2)) return result;
        if (['rm', 'remove', 'prune', 'delete'].includes(sub2)) return result.raise('risky', `docker_${sub}_${sub2}`);
        return result.raise('unknown', `docker_${sub}_${String(sub2).slice(0, 16)}`);
      }
      if (routine.includes(sub)) return result;
      if (risky.includes(sub)) return result.raise('risky', `docker_${sub}`);
      return result.raise('unknown', `docker_${String(sub).slice(0, 16)}`);
    },
    sql(base, args, command) {
      const result = new Result();
      const text = [...args.map((a) => a.text || ''), command.heredoc || ''].join(' ');
      if (sqlMutation.test(text)) return result.raise('risky', 'sql_mutation');
      return result.raise('unknown', `database_client:${base}`);
    },
    http(base, args, command, ctx) {
      const result = new Result();
      const methodFlag = flagValue(args, '-X', '--request', '--method');
      if (methodFlag === null) return result.raise('unknown', 'dynamic_http_method');
      if (methodFlag && !['GET', 'HEAD', 'OPTIONS'].includes(String(methodFlag).toUpperCase())) result.raise('unknown', 'http_write_method');
      if (methodFlag && String(methodFlag).toUpperCase() === 'DELETE') result.raise('risky', 'http_delete');
      const dataFlags = ['-d', '--data', '--data-raw', '--data-binary', '--data-urlencode', '-F', '--form', '--form-string', '-T', '--upload-file', '--json', '--post-data', '--post-file', '--body-data', '--body-file'];
      for (let i = 0; i < args.length; i += 1) {
        const text = args[i].text;
        if (text === null) { result.raise('unknown', 'dynamic_http_arg'); continue; }
        const flag = dataFlags.find((f) => text === f || text.startsWith(`${f}=`));
        if (flag) {
          result.raise('unknown', 'http_body');
          const value = text === flag ? (args[i + 1] ? args[i + 1].text : null) : text.slice(flag.length + 1);
          if (value === null) result.raise('unknown', 'dynamic_http_body');
          else if (/(^|=)@/.test(value)) checkReadPath(value.replace(/^.*?@/, ''), ctx, result, 'secret_upload');
          else if (flag === '--post-file' || flag === '--body-file' || flag === '-T' || flag === '--upload-file') checkReadPath(value, ctx, result, 'secret_upload');
          if (text === flag) i += 1;
          continue;
        }
        const outputFlags = base === 'wget' ? ['-O', '--output-document'] : ['-o', '--output'];
        if (outputFlags.includes(text)) {
          const target = args[i + 1] ? args[i + 1].text : null;
          if (target !== '-') checkWritePath(target, ctx, result);
          i += 1;
          continue;
        }
        if (['-K', '--config', '--next', '-:'].includes(text)) result.raise('unknown', 'http_config');
        if (/^https?:\/\//i.test(text) || /^[a-z0-9.-]+\.[a-z]{2,}(?:[:/]|$)/i.test(text)) classifyUrl(/^https?:/i.test(text) ? text : `https://${text}`, result);
        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(text) && (base === 'http' || base === 'https' || base === 'xh')) result.raise(text === 'DELETE' ? 'risky' : 'unknown', 'http_write_method');
      }
      return result;
    },
    rsync(base, args, command, ctx) {
      const result = new Result();
      const pos = positionals(args, ['-e', '--rsh', '--exclude', '--include', '--filter', '-f']);
      if (pos.some((a) => a.text === null)) return result.raise('unknown', 'dynamic_rsync_arg');
      if (pos.some((a) => /^[^/][^:]*:/.test(a.text) && !/^[A-Za-z]:\\/.test(a.text))) return result.raise('risky', 'rsync_remote');
      if (hasFlag(args, '--delete', '--delete-before', '--delete-after', '--delete-during', '--remove-source-files')) result.raise('unknown', 'rsync_delete');
      if (pos.length) checkWritePath(pos[pos.length - 1].text, ctx, result);
      for (const arg of pos.slice(0, -1)) checkReadPath(arg.text, ctx, result);
      return result;
    },
    systemctl(base, args) {
      const result = new Result();
      const pos = positionals(args, ['-H', '--host', '-M', '--machine', '-t', '--type', '--state', '-p', '--property']);
      const sub = pos[0] ? pos[0].text : undefined;
      if (sub === undefined) return result;
      if (['status', 'show', 'cat', 'list-units', 'list-unit-files', 'is-active', 'is-enabled', 'is-failed', 'list-timers', 'list-sockets', 'list-dependencies', 'help'].includes(sub)) return result;
      return result.raise('risky', `systemctl:${String(sub).slice(0, 24)}`);
    },
    kill(base, args) {
      const result = new Result();
      const text = args.map((a) => a.text || '').join(' ');
      if (/marrow/i.test(text) || args.some((a) => a.text !== null && daemonPids.has(a.text))) return result.raise('risky', 'kill_marrow');
      if (args.some((a) => a.text === null)) return result.raise('unknown', 'dynamic_kill_target');
      if (args.some((a) => a.text === '-1' || a.text === '1')) return result.raise('risky', 'kill_all');
      return result.raise('unknown', `${base}`);
    },
  };

  function classifyGitPush(rest, ctx) {
    const result = new Result();
    const riskyFlags = ['--force', '-f', '--force-with-lease', '--force-if-includes', '--mirror', '--delete', '-d', '--prune', '--tags', '--follow-tags', '--all'];
    if (hasFlag(rest, ...riskyFlags)) return result.raise('risky', 'git_push_force_or_bulk');
    if (hasFlag(rest, '--no-verify')) result.raise('unknown', 'git_push_no_verify');
    const pos = positionals(rest, ['-o', '--push-option', '--repo', '--receive-pack', '--exec']);
    if (pos.some((a) => a.text === null)) return result.raise('unknown', 'dynamic_git_push_arg');
    const refspecs = pos.slice(1).map((a) => a.text);
    const current = () => currentBranch(ctx);
    const targets = [];
    if (refspecs.length === 0) targets.push(current());
    for (const spec of refspecs) {
      if (spec.startsWith('+')) return result.raise('risky', 'git_push_forced_refspec');
      if (spec.startsWith(':')) return result.raise('risky', 'git_push_delete_refspec');
      const [src, dst] = spec.includes(':') ? spec.split(':', 2) : [spec, spec];
      let target = dst || src;
      if (target === 'HEAD' || target === '@') target = current();
      if (target && /^refs\/tags\/|^v?\d+\.\d+/.test(target)) return result.raise('risky', 'git_push_tag');
      targets.push(target);
    }
    for (const target of targets) {
      if (!target) { result.raise('unknown', 'git_push_branch_unknown'); continue; }
      const branch = target.replace(/^refs\/heads\//, '');
      if (isProtectedBranch(branch) || isProtectedBranch(`/${branch}`)) return result.raise('risky', 'git_push_protected_branch');
    }
    return result;
  }

  function currentBranch(ctx) {
    if (!ctx.cwd || ctx.cwdUnknown) return null;
    let dir = ctx.cwd;
    for (let level = 0; level < 24; level += 1) {
      const gitPath = path.join(dir, '.git');
      try {
        const stat = fs.statSync(gitPath);
        let gitDir = gitPath;
        if (stat.isFile()) {
          const pointer = readSmallFile(gitPath, 4096) || '';
          const match = pointer.match(/^gitdir:\s*(.+)$/m);
          if (!match) return null;
          gitDir = path.resolve(dir, match[1].trim());
        }
        const head = readSmallFile(path.join(gitDir, 'HEAD'), 4096) || '';
        const ref = head.match(/^ref:\s*refs\/heads\/(.+)$/m);
        return ref ? ref[1].trim() : null;
      } catch {
        const parent = path.dirname(dir);
        if (parent === dir) return null;
        dir = parent;
      }
    }
    return null;
  }

  function findPackageJson(ctx) {
    let dir = ctx.cwd;
    for (let level = 0; level < 12; level += 1) {
      if (ctx.written && ctx.written.has(path.join(dir, 'package.json'))) return { error: 'package_json_written_in_same_command' };
      const raw = readSmallFile(path.join(dir, 'package.json'), PACKAGE_JSON_MAX_BYTES);
      if (raw !== null) {
        try { return { pkg: JSON.parse(raw), dir }; } catch { return { error: 'package_json_invalid' }; }
      }
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
    return { pkg: null, dir: null };
  }

  // A requirements file is routine only if every line is a plain package spec from the index
  // (no -e, local paths, URLs, nested -r or index overrides).
  function requirementsArePlain(file, ctx) {
    if (file === null || file === undefined) return false;
    const abs = absPath(file, ctx);
    if (!abs || (ctx.written && ctx.written.has(abs))) return false;
    const content = readSmallFile(abs, SCRIPT_MAX_BYTES);
    if (content === null) return false;
    const spec = /^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9,._-]+\])?\s*(?:(?:===|==|>=|<=|~=|!=|<|>)\s*[A-Za-z0-9.*+!_-]+\s*,?\s*)*(?:;[^#]*)?(?:\s+--hash=[a-z0-9]+:[a-f0-9]+)*$/;
    return content.split(/\r?\n/).every((line) => {
      const trimmed = line.replace(/(^|\s)#.*$/, '').trim();
      return trimmed === '' || spec.test(trimmed);
    });
  }

  function classifyLifecycleScripts(ctx, depth, names) {
    const result = new Result();
    if (!ctx.cwd || ctx.cwdUnknown) return result.raise('unknown', 'package_script_cwd_unknown');
    if (depth >= (tables.routine_package_scripts_depth || 3)) return result.raise('unknown', 'package_script_depth');
    const found = findPackageJson(ctx);
    if (found.error) return result.raise('unknown', found.error);
    if (!found.pkg || !found.pkg.scripts || typeof found.pkg.scripts !== 'object') return result;
    for (const name of names) {
      if (typeof found.pkg.scripts[name] !== 'string') continue;
      const inner = classifyShellSource(found.pkg.scripts[name], { ...ctx, cwd: found.dir, cwdUnknown: false, vars: new Map(ctx.vars) }, depth + 1);
      result.merge(inner);
      if (inner.class !== 'routine') result.raise(inner.class, `lifecycle_script:${name}`);
    }
    return result;
  }

  function classifyPackageScript(name, ctx, depth) {
    const result = new Result();
    if (depth >= (tables.routine_package_scripts_depth || 3)) return result.raise('unknown', 'package_script_depth');
    if (!ctx.cwd || ctx.cwdUnknown) return result.raise('unknown', 'package_script_cwd_unknown');
    for (let d = ctx.cwd, k = 0; k < 12; k += 1) {
      if (ctx.written && ctx.written.has(path.join(d, 'package.json'))) return result.raise('unknown', 'package_json_written_in_same_command');
      const parent = path.dirname(d);
      if (parent === d) break;
      d = parent;
    }
    let dir = ctx.cwd;
    let pkg = null;
    let pkgDir = null;
    for (let level = 0; level < 12 && !pkg; level += 1) {
      const raw = readSmallFile(path.join(dir, 'package.json'), PACKAGE_JSON_MAX_BYTES);
      if (raw !== null) {
        try { pkg = JSON.parse(raw); pkgDir = dir; } catch { return result.raise('unknown', 'package_json_invalid'); }
        break;
      }
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
    if (!pkg || !pkg.scripts || typeof pkg.scripts !== 'object') return result.raise('unknown', 'package_script_missing');
    const body = pkg.scripts[name];
    if (typeof body !== 'string') return result.raise('unknown', 'package_script_missing');
    const scriptCtx = { ...ctx, cwd: pkgDir, cwdUnknown: false, vars: new Map(ctx.vars) };
    for (const hook of [`pre${name}`, name, `post${name}`]) {
      if (typeof pkg.scripts[hook] !== 'string') continue;
      const inner = classifyShellSource(pkg.scripts[hook], { ...scriptCtx, vars: new Map(scriptCtx.vars) }, depth + 1);
      result.merge(inner);
      if (inner.class !== 'routine') result.raise(inner.class, `package_script:${hook.slice(0, 32)}`);
    }
    return result;
  }

  // ---------- public ----------
  function classify(event) {
    const result = classifyTool(event);
    return {
      class: result.class,
      reasons: result.reasons,
      tool: result.tool,
      programs: result.programs,
      paths: result.paths,
      hosts: result.hosts,
      commands: result.commands,
      truncated: result.truncated,
    };
  }

  return { classify, classifyShell: (source, cwd) => classifyShellSource(source, newContext(cwd), 0) };
}

module.exports = { createClassifier, globToRegex, RANK };
