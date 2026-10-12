"use strict";
// Seatbelt category mapper (U2): S0–S5 and S-x hard stops for keyless installs, plus the lexical
// tripwire. Spec: SEATBELT-SPEC.md §1.2 and §2 as amended by the owner decisions of 2026-10-12
// (Q1 non-force push to a protected branch passes with a receipt flag; Q2 no docker push; Q3 project
// .env* reads stop, templates excepted; Q4 curl|sh passes with a receipt flag, decoded exec stops).
//
// Pure: no I/O except the injected fs and git-config reader. Not wired into any hook yet (U5).
//
// It works on argv from the vendored classifier's shell parser (vendor/classifier/shell-parse.js).
// It never takes the classifier's "routine" class as a pass: the classifier allows env dumps and
// deletes under home by design (U0 misses), so every S rule is decided from argv here.
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.evaluateSeatbeltShell = evaluateSeatbeltShell;
exports.evaluateSeatbelt = evaluateSeatbelt;
const path = __importStar(require("node:path"));
const tables_1 = require("./tables");
const classifier_pin_1 = require("./classifier-pin");
/* eslint-disable @typescript-eslint/no-require-imports */
const shellParse = require('../../vendor/classifier/shell-parse.js');
const baseline = require('../../vendor/classifier/policy-baseline.js');
const classifierModule = require('../../vendor/classifier/classifier.js');
const CATEGORY_ORDER = ['S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'Sx'];
const RULE_IDS = {
    none: 'none', S0: 'S0.self_protection', S1: 'S1.protected_branch_force', S2: 'S2.production_deploy', S3: 'S3.package_publish',
    S4: 'S4.credential_access', S5: 'S5.recursive_delete_outside_ws', Sx: 'Sx.obfuscated_exec',
};
const PARSE_RANK = { ok: 0, dynamic: 1, unparsed: 2, too_large: 3 };
const DYN = '\u0001';
const OUTPUT_REDIRECTS = new Set(['>', '>>', '>|', '&>', '&>>', '<>']);
const SAFE_DEVICES = /^\/dev\/(?:null|zero|stdout|stderr|tty|u?random|fd\/\d+)$/;
function litArg(text) {
    return { text, alts: [text], pattern: text, glob: false, word: null, nonAscii: /[^\x00-\x7f]/.test(text) };
}
function dynArg() { return { text: null, alts: null, pattern: DYN, glob: false, word: null, nonAscii: false }; }
// ---------------------------------------------------------------------------------------------
// public entry points
function evaluateSeatbeltShell(command, env) {
    const run = newRun(env, command);
    evalShell(String(command == null ? '' : command), newCtx(run), run);
    return finish(run);
}
function evaluateSeatbelt(event, env) {
    const tool = String((event && event.tool_name) || '');
    const input = (event && event.tool_input && typeof event.tool_input === 'object' ? event.tool_input : {});
    const name = tool.toLowerCase();
    const shellText = shellCommandOf(name, input);
    if (shellText !== null)
        return evaluateSeatbeltShell(shellText, env);
    const run = newRun(env, '');
    const ctx = newCtx(run);
    if (['read', 'notebookread', 'read_file', 'view', 'view_file'].includes(name)) {
        for (const p of pathInputs(input))
            checkSecretOperand(litArg(p), ctx, run, 'tool_read');
    }
    else if (['grep', 'grep_files', 'search', 'rg'].includes(name)) {
        for (const p of pathInputs(input))
            checkSecretOperand(litArg(p), ctx, run, 'tool_grep');
        for (const key of ['glob', 'include', 'file_pattern']) {
            const g = input[key];
            if (typeof g === 'string' && g)
                checkGrepGlob(g, ctx, run);
        }
    }
    else if (['write', 'edit', 'multiedit', 'notebookedit', 'write_file', 'create_file', 'str_replace_editor', 'str_replace_based_edit_tool', 'apply_patch', 'edit_file'].includes(name)) {
        const targets = name === 'apply_patch' ? patchPaths(String(input.patch || input.input || input.content || '')) : pathInputs(input);
        if (name === 'str_replace_editor' || name === 'str_replace_based_edit_tool') {
            if (String(input.command || '') === 'view') {
                for (const p of targets)
                    checkSecretOperand(litArg(p), ctx, run, 'tool_read');
                return finish(run);
            }
        }
        for (const p of targets) {
            if (checkSecretOperand(litArg(p), ctx, run, 'tool_write'))
                continue;
            checkToolWrite(p, name, input, ctx, run);
        }
    }
    else if (name.startsWith('mcp__')) {
        const parts = name.split('__');
        if (parts[1] !== 'marrow') {
            const verbs = /write|edit|create|move|delete|remove|rename|put|update|append|save|mkdir|copy|patch|upload/;
            for (const p of pathInputs(input, true)) {
                if (checkSecretOperand(litArg(p), ctx, run, 'mcp_path'))
                    continue;
                if (verbs.test(parts.slice(2).join('_')))
                    checkProtectedWrite(litArg(p), ctx, run, 'mcp_write', false);
            }
        }
    }
    return finish(run);
}
function shellCommandOf(name, input) {
    const shellTools = ['bash', 'shell', 'local_shell', 'exec_command', 'container.exec', 'run_terminal_command', 'execute_command', 'run_shell_command', 'run_command', 'terminal'];
    if (!shellTools.includes(name))
        return null;
    const c = input.command !== undefined ? input.command : input.cmd;
    if (Array.isArray(c))
        return c.map((part) => shellQuote(String(part))).join(' ');
    return typeof c === 'string' ? c : '';
}
function shellQuote(s) {
    return /^[A-Za-z0-9_\-./=:@%+,]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`;
}
function pathInputs(input, deep = false) {
    const keys = ['file_path', 'path', 'notebook_path', 'filepath', 'filename', 'file', 'target_file', 'paths', 'source', 'destination', 'target', 'dir', 'directory', 'uri', 'files'];
    const out = [];
    const add = (v) => {
        if (typeof v === 'string' && v)
            out.push(v.replace(/^file:\/\//, ''));
        else if (Array.isArray(v))
            v.forEach(add);
    };
    for (const key of keys)
        add(input[key]);
    if (deep) {
        for (const value of Object.values(input)) {
            if (value && typeof value === 'object' && !Array.isArray(value)) {
                for (const key of keys)
                    add(value[key]);
            }
        }
    }
    if (Array.isArray(input.edits))
        for (const e of input.edits)
            if (e && typeof e === 'object')
                add(e.file_path);
    return [...new Set(out)];
}
function patchPaths(patch) {
    const out = [];
    const re = /^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$|^(?:\+\+\+|---) (?:[ab]\/)?(.+)$/gm;
    let m;
    while ((m = re.exec(patch))) {
        const p = (m[1] || m[2] || m[3] || '').trim();
        if (p && p !== '/dev/null')
            out.push(p);
    }
    return out;
}
// ---------------------------------------------------------------------------------------------
// run state
function newRun(env, source) {
    const platform = env.platform || 'linux';
    const fold = platform === 'darwin' || platform === 'win32';
    const home = path.posix.normalize(String(env.home || '/nonexistent-home'));
    const realOr = (p) => safeRealpath(env, p) || p;
    const tmpRoots = new Set();
    for (const t of [env.tmpdir, '/tmp', '/var/tmp']) {
        if (!t || !path.posix.isAbsolute(t))
            continue;
        const n = path.posix.normalize(t).replace(/\/$/, '') || '/';
        if (n === '/')
            continue;
        tmpRoots.add(n);
        tmpRoots.add(realOr(n));
    }
    const wsRoots = new Set();
    const cwd = typeof env.cwd === 'string' && path.posix.isAbsolute(env.cwd) ? path.posix.normalize(env.cwd) : null;
    if (cwd) {
        let top = null;
        try {
            top = env.git.toplevel(cwd);
        }
        catch {
            top = null;
        }
        const root = top && path.posix.isAbsolute(top) ? path.posix.normalize(top) : cwd;
        for (const r of [root, realOr(root)]) {
            const n = r.replace(/\/$/, '') || '/';
            // A workspace never covers the filesystem root, home or an ancestor of home.
            if (n === '/' || n === home || isAncestorOrSelf(n, home) || isAncestorOrSelf(n, realOr(home)))
                continue;
            wsRoots.add(n);
        }
    }
    const protectedPatterns = baseline.BASELINE_POLICY.protected_paths;
    const protectedRegexes = protectedPatterns.map((p) => classifierModule.globToRegex(fold ? p.toLowerCase() : p, fold ? home.toLowerCase() : home));
    const anchors = [];
    for (const p of protectedPatterns) {
        if (p.startsWith('~/'))
            anchors.push(path.posix.join(home, p.slice(2).replace(/\/\*\*$/, '')));
        else if (p.startsWith('/') && !p.includes('*', 1))
            anchors.push(p);
    }
    for (const root of wsRoots) {
        for (const rel of ['.claude/settings.json', '.claude/settings.local.json', '.mcp.json', '.cursor/mcp.json', '.cursor/hooks.json', '.codex', '.gemini/settings.json', '.windsurf', '.clinerules/hooks', '.grok', '.marrow', '.git/hooks', '.git/config']) {
            anchors.push(path.posix.join(root, rel));
        }
    }
    return {
        env, home, fold, hits: [], flags: new Set(), parse: 'ok', wsRoots: [...wsRoots], tmpRoots: [...tmpRoots],
        isProtected: (abs) => protectedRegexes.some((re) => re.test(fold ? abs.toLowerCase() : abs)),
        protectedAnchors: anchors.map((a) => (fold ? a.toLowerCase() : a)),
        secretRegexes: tables_1.SECRET_PATTERNS.map((p) => classifierModule.globToRegex(p, home)),
        branchRegexes: baseline.BASELINE_POLICY.protected_branches.map((p) => classifierModule.globToRegex(p, '/nonexistent-home')),
        topSource: source,
    };
}
function newCtx(run) {
    const cwd = typeof run.env.cwd === 'string' && path.posix.isAbsolute(run.env.cwd) ? path.posix.normalize(run.env.cwd) : null;
    return {
        cwds: [cwd], vars: new Map([['HOME', [run.home]]]), exported: new Set(['HOME']), aliases: new Map(), gitAliases: new Map(),
        gitConfig: new Map(), written: new Set(), depth: 0, remote: false, kubeContext: undefined, tfWorkspace: undefined, pulumiStack: undefined,
        decodedVars: new Set(),
    };
}
function childCtx(ctx, overrides = {}) {
    return { ...ctx, depth: ctx.depth + 1, ...overrides };
}
function scriptCtx(ctx, cwds, extraEnv) {
    // A child process sees exported variables and same-command assignments only.
    const vars = new Map();
    for (const name of ctx.exported)
        if (ctx.vars.has(name))
            vars.set(name, ctx.vars.get(name) ?? null);
    for (const [k, v] of extraEnv)
        vars.set(k, v);
    return { ...ctx, cwds, vars, exported: new Set([...ctx.exported, ...extraEnv.keys()]), aliases: new Map(), depth: ctx.depth + 1 };
}
function hit(run, category, reason) {
    if (!run.hits.some((h) => h.category === category && h.reason === reason))
        run.hits.push({ category, reason });
    return true;
}
function worseParse(run, p) {
    if (PARSE_RANK[p] > PARSE_RANK[run.parse])
        run.parse = p;
}
function finish(run) {
    const hits = [...run.hits].sort((a, b) => CATEGORY_ORDER.indexOf(a.category) - CATEGORY_ORDER.indexOf(b.category));
    const category = hits.length ? hits[0].category : 'none';
    if (run.parse !== 'ok')
        run.flags.add(`parse_${run.parse}`);
    return {
        decision: hits.length ? 'stop' : 'pass',
        category,
        rule: RULE_IDS[category],
        reasons: hits.map((h) => h.reason),
        hits,
        flags: [...run.flags].sort(),
        parse: run.parse,
        engine: { rules: tables_1.SEATBELT_RULES_VERSION, classifier_contract: classifier_pin_1.CLASSIFIER_PIN.contract, classifier_source_commit: classifier_pin_1.CLASSIFIER_PIN.source_commit },
    };
}
function safeRealpath(env, p) {
    try {
        const r = env.fs.realpath(p);
        return typeof r === 'string' && path.posix.isAbsolute(r) ? path.posix.normalize(r) : null;
    }
    catch {
        return null;
    }
}
function safeRead(env, p, max) {
    try {
        const r = env.fs.readFile(p, max);
        return typeof r === 'string' ? r : null;
    }
    catch {
        return null;
    }
}
function gitAll(run, ctx, cwd, key, overrides) {
    const lower = canonicalGitKey(key);
    const out = [];
    if (cwd) {
        try {
            out.push(...run.env.git.getAll(cwd, key));
        }
        catch {
            return null;
        }
    }
    const fromCtx = ctx.gitConfig.get(lower);
    if (fromCtx)
        out.push(...fromCtx);
    const fromC = overrides && overrides.get(lower);
    if (fromC)
        out.push(...fromC);
    return out;
}
function canonicalGitKey(key) {
    const first = key.indexOf('.');
    const last = key.lastIndexOf('.');
    if (first < 0)
        return key.toLowerCase();
    if (first === last)
        return key.toLowerCase();
    return `${key.slice(0, first).toLowerCase()}.${key.slice(first + 1, last)}.${key.slice(last + 1).toLowerCase()}`;
}
function isAncestorOrSelf(a, b) {
    if (a === b)
        return true;
    if (a === '/')
        return true;
    return b.startsWith(`${a}/`);
}
// ---------------------------------------------------------------------------------------------
// shell evaluation
const STRUCTURAL_REASONS = new Set(['case_statement', 'coproc_statement', 'unterminated_heredoc', 'dangling_redirect']);
function evalShell(src, ctx, run) {
    if (ctx.depth > tables_1.LIMITS.maxDepth) {
        worseParse(run, 'unparsed');
        run.flags.add('depth_limit');
        tripwire(src, run);
        return;
    }
    if (Buffer.byteLength(src) > tables_1.LIMITS.maxCommandBytes) {
        worseParse(run, 'too_large');
        tripwire(src, run);
        return;
    }
    const parsed = shellParse.parseShell(src, { depth: ctx.depth });
    if (!parsed.ok) {
        worseParse(run, parsed.error === 'too_large' || parsed.error === 'too_many_commands' ? 'too_large' : 'unparsed');
        tripwire(src, run);
        return;
    }
    if (parsed.commands.length > tables_1.LIMITS.maxSegments) {
        worseParse(run, 'too_large');
        tripwire(src, run);
        return;
    }
    if (parsed.dynamic)
        worseParse(run, 'dynamic');
    if (parsed.reasons.some((r) => STRUCTURAL_REASONS.has(r))) {
        worseParse(run, 'unparsed');
        tripwire(src, run);
    }
    const ansiC = /\$'[^']*\\(?:x[0-9a-fA-F]|[0-7]{2,3}|u[0-9a-fA-F])/.test(src);
    // Command and process substitutions run too; classify them first (S-x checks see them below).
    for (const sub of parsed.substitutions)
        evalShell(sub, childCtx(ctx), run);
    // Pipelines, for decoded-exec (S-x) and stdin-fed shells.
    const pipelines = [];
    for (const command of parsed.commands) {
        if (command.pipedInput && pipelines.length)
            pipelines[pipelines.length - 1].push(command);
        else
            pipelines.push([command]);
    }
    for (const pipeline of pipelines) {
        for (let i = 0; i < pipeline.length; i += 1) {
            const upstream = pipeline.slice(0, i);
            evalCommand(pipeline[i], ctx, run, { upstream, ansiC, subs: parsed.substitutions });
        }
    }
}
// Bash brace expansion ({a,b}, {1..3}); quoting is not tracked per part, so it always expands
// (stricter). Sequences are left unresolved.
function expandBraces(text) {
    const m = text.match(/^(.*?)\{([^{}]*)\}(.*)$/s);
    if (!m)
        return [text];
    if (/\.\./.test(m[2]) && !m[2].includes(','))
        return null;
    if (!m[2].includes(','))
        return [text];
    const out = [];
    for (const part of m[2].split(',')) {
        const sub = expandBraces(`${m[1]}${part}${m[3]}`);
        if (!sub)
            return null;
        out.push(...sub);
        if (out.length > 16)
            return null;
    }
    return out;
}
function resolveWord(word, ctx, run) {
    const r = resolveWordRaw(word, ctx, run);
    if (r.text === null || !/\{[^{}]*(?:,|\.\.)[^{}]*\}/.test(r.text))
        return r;
    const alts = expandBraces(r.text);
    if (alts && alts.length === 1)
        return { ...r, text: alts[0], alts, pattern: alts[0] };
    return { ...r, text: null, alts, pattern: r.text };
}
function resolveWordRaw(word, ctx, run) {
    const nonAscii = /[^\x00-\x7f]/.test(word.text.replace(/\u0000/g, ''));
    if (!word.dynamic)
        return { text: word.text, alts: [word.text], pattern: word.text, glob: Boolean(word.glob), word, nonAscii };
    const parts = word.text.split('\u0000');
    let values = [parts[0]];
    let pattern = parts[0];
    for (let k = 0; k < word.slots.length; k += 1) {
        const slot = word.slots[k];
        pattern += DYN + (parts[k + 1] || '');
        if (values === null)
            continue;
        let bound = null;
        if (slot && slot.type === 'var' && slot.name) {
            const name = slot.name;
            if (name === 'HOME')
                bound = [run.home];
            else if (name === 'PWD')
                bound = ctx.cwds.length === 1 && ctx.cwds[0] ? [ctx.cwds[0]] : null;
            else if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(name))
                bound = ctx.vars.has(name) ? ctx.vars.get(name) : null;
            else
                bound = null;
        }
        if (!bound) {
            values = null;
            continue;
        }
        const next = [];
        for (const prefix of values)
            for (const option of bound)
                next.push(`${prefix}${option}${parts[k + 1] || ''}`);
        values = next.length > 16 ? null : next;
    }
    if (values && values.length === 1) {
        const text = values[0];
        return { text, alts: values, pattern: text, glob: Boolean(word.glob), word, nonAscii: nonAscii || /[^\x00-\x7f]/.test(text) };
    }
    return { text: null, alts: values, pattern, glob: Boolean(word.glob), word, nonAscii };
}
function argText(a) { return a.text !== null ? a.text : a.pattern.replace(new RegExp(DYN, 'g'), ''); }
function evalCommand(cmd, ctx, run, info) {
    if (cmd.forLoop) {
        const items = cmd.forLoop.items;
        if (!items) {
            ctx.vars.set(cmd.forLoop.name, null);
            return;
        }
        const values = [];
        for (const w of items) {
            const a = resolveWord(w, ctx, run);
            if (a.text === null || a.glob) {
                ctx.vars.set(cmd.forLoop.name, null);
                return;
            }
            values.push(a.text);
        }
        ctx.vars.set(cmd.forLoop.name, values.length ? values : null);
        return;
    }
    // Redirects: writes to protected paths (S0), reads or writes of secret paths (S4).
    for (const r of cmd.redirects) {
        if (!r.target)
            continue;
        const a = resolveWord(r.target, ctx, run);
        if (r.op === '>&' || r.op === '<&' || r.op === '<<<') {
            if (a.text !== null && /^(?:\d+|-)$/.test(a.text))
                continue;
            if (r.op === '<<<')
                continue;
        }
        if (OUTPUT_REDIRECTS.has(r.op) || r.op === '>&') {
            if (a.text && SAFE_DEVICES.test(a.text))
                continue;
            checkSecretOperand(a, ctx, run, 'redirect_write');
            checkProtectedWrite(a, ctx, run, 'redirect_write', false);
            markWritten(a, ctx);
        }
        else if (r.op === '<') {
            checkSecretOperand(a, ctx, run, 'redirect_read');
        }
    }
    const assignEnv = new Map();
    for (const w of cmd.assignments) {
        const eq = w.text.indexOf('=');
        const name = w.text.slice(0, eq).replace(/\+$/, '').replace(/\[.*$/, '');
        const valueWord = { ...w, text: w.text.slice(eq + 1) };
        const v = resolveWord(valueWord, ctx, run);
        assignEnv.set(name, v.text !== null ? [v.text] : v.alts);
    }
    if (cmd.words.length === 0) {
        for (const [k, v] of assignEnv)
            ctx.vars.set(k, v);
        // X=$(… | base64 -d): executing $X later is decoded exec.
        if (cmd.assignments.some((w) => w.substitution) && substitutionsDecode(info.subs, run))
            for (const k of assignEnv.keys())
                ctx.decodedVars.add(k);
        return;
    }
    const args = cmd.words.map((w) => resolveWord(w, ctx, run));
    // Shell aliases defined earlier in this command line.
    const first = cmd.words[0];
    if (!first.quoted && !first.dynamic && ctx.aliases.has(first.text) && ctx.depth < tables_1.LIMITS.maxDepth + 2) {
        const rest = args.slice(1).map((a) => (a.text !== null ? shellQuote(a.text) : '"$__marrow_dynamic"')).join(' ');
        evalShell(`${ctx.aliases.get(first.text)} ${rest}`, childCtx(ctx), run);
        return;
    }
    dispatch(args, ctx, run, { cmd, info, env: assignEnv });
}
function progName(a, run) {
    if (a.text === null)
        return null;
    const base = a.text.replace(/\/+$/, '').split('/').pop() || '';
    return run.fold ? base.toLowerCase() : base;
}
function isOpt(a) { return a.text !== null && a.text.length > 1 && a.text.startsWith('-'); }
function dispatch(args, ctx, run, x) {
    if (args.length === 0)
        return;
    const prog = progName(args[0], run);
    if (prog === null) {
        // The program itself is dynamic: decode-exec check on its substitution, then the tripwire.
        worseParse(run, 'dynamic');
        if (args[0].word && args[0].word.substitution)
            checkSubstitutionExec(x.info.subs, ctx, run);
        else if (ctx.decodedVars.size && args[0].word && args[0].word.variables.some((v) => ctx.decodedVars.has(v)))
            hit(run, 'Sx', 'decoded_variable_exec');
        tripwire(args.map(argText).join(' '), run);
        return;
    }
    const rest = args.slice(1);
    const pathLike = args[0].text !== null && args[0].text.includes('/');
    // Generic operand checks apply to every program (S4 reads, S0 writes by write-programs).
    genericOperandChecks(prog, args, ctx, run);
    switch (prog) {
        case 'cd':
        case 'pushd': return changeDir(rest, ctx, run, x.cmd.subshell);
        case 'popd':
            ctx.cwds = [...ctx.cwds, null];
            return;
        case 'alias': return defineAliases(rest, ctx, run);
        case 'export':
        case 'declare':
        case 'typeset':
        case 'readonly':
        case 'local': return declareLike(prog, rest, ctx, run, x);
        case 'set': return setBuiltin(rest, run);
        case 'unset':
            for (const a of rest)
                if (a.text)
                    ctx.vars.delete(a.text);
            return;
        case 'printenv': return printenv(rest, run);
        case 'echo':
        case 'printf':
        case 'print': return echoLike(args, run, x);
        case 'eval': return evalBuiltin(rest, ctx, run, x.info.subs);
        case 'source':
        case '.': return sourceFile(rest, ctx, run, x);
        case 'env': return envWrapper(rest, ctx, run, x);
        case 'sudo':
        case 'doas':
        case 'pkexec':
        case 'runas': return privilegeWrapper(prog, rest, ctx, run, x);
        case 'su': return suWrapper(rest, ctx, run, x);
        case 'timeout':
        case 'nice':
        case 'nohup':
        case 'time':
        case 'command':
        case 'builtin':
        case 'exec':
        case 'stdbuf':
        case 'ionice':
        case 'chrt':
        case 'taskset':
        case 'setsid':
        case 'unbuffer':
        case 'caffeinate':
        case 'retry':
        case 'flock':
            return simpleWrapper(prog, rest, ctx, run, x);
        case 'xargs':
        case 'parallel': return xargsWrapper(prog, rest, ctx, run, x);
        case 'watch': return watchWrapper(rest, ctx, run);
        case 'ssh': return sshRemote(rest, ctx, run);
        case 'git': return handleGit(rest, ctx, run, x, new Map(), 0);
        case 'gh': return handleGh(rest, ctx, run);
        case 'npm':
        case 'pnpm':
        case 'yarn':
        case 'bun': return handlePackageManager(prog, rest, ctx, run, x);
        case 'npx':
        case 'bunx': return handleNpx(rest, ctx, run, x);
        case 'corepack': return dispatch(rest, ctx, run, x);
        case 'make':
        case 'gmake': return handleMake(rest, ctx, run, x);
        case 'rm': return handleRm(rest, ctx, run);
        case 'rimraf': return checkTreeDeletes(rest.filter((a) => !isOpt(a)), ctx, run, 'rimraf');
        case 'rmdir': return handleRmdir(rest, ctx, run);
        case 'find': return handleFind(rest, ctx, run, x);
        case 'rsync': return handleRsync(rest, ctx, run);
        case 'shred': return handleShred(rest, ctx, run);
        case 'dd': return handleDd(rest, run);
        case 'docker':
        case 'podman': return handleDocker(rest, ctx, run);
        case 'kubectl': return handleKubectl(rest, ctx, run, x);
        case 'helm': return handleHelm(rest, ctx, run);
        case 'marrow': return handleMarrowCli(rest, run);
        case 'marrow-install': return handleMarrowCli(rest, run);
        case 'claude': return handleClaudeCli(rest, run);
        case 'apply_patch':
        case 'applypatch': {
            const text = x.cmd.heredoc !== null ? x.cmd.heredoc : rest.map(argText).join('\n');
            for (const p of patchPaths(text)) {
                if (!checkSecretOperand(litArg(p), ctx, run, 'patch_write'))
                    checkProtectedWrite(litArg(p), ctx, run, 'patch_write', false);
            }
            return;
        }
        default: break;
    }
    if (/^mkfs(?:\.|$)/.test(prog)) {
        hit(run, 'S5', 'mkfs');
        return;
    }
    if (tables_1.SHELLS.has(prog))
        return handleShell(prog, rest, ctx, run, x);
    if (tables_1.INTERPRETERS.has(prog) || /^python3\.\d+$/.test(prog))
        return handleInterpreter(prog, rest, ctx, run, x);
    if (handleDeployTool(prog, rest, ctx, run, x))
        return;
    if (handlePublishTool(prog, rest, ctx, run))
        return;
    if (handleSecretDumper(prog, rest, run))
        return;
    if (pathLike)
        return scriptFile(args[0], rest, ctx, run, x);
}
// ---------------------------------------------------------------------------------------------
// tripwire and S-x
function tripwire(text, run) {
    const norm = String(text).toLowerCase().replace(/["'\\]/g, '');
    let any = false;
    for (const t of tables_1.TRIPWIRE) {
        if (t.re.test(norm)) {
            hit(run, t.category, t.reason);
            any = true;
        }
    }
    if (!any && run.parse !== 'ok')
        run.flags.add('tripwire_clear');
}
function decoderCommand(cmd, _run, info) {
    const words = cmd.words.map((w) => w.text);
    let i = 0;
    while (i < words.length && ['sudo', 'env', 'command', 'nice', 'timeout', 'stdbuf'].includes(words[i]))
        i += 1;
    const prog = (words[i] || '').split('/').pop() || '';
    const rest = words.slice(i + 1);
    const hasShort = (letter) => rest.some((w) => /^-[A-Za-z]+$/.test(w) && w.includes(letter));
    if (['base64', 'base32', 'basenc', 'gbase64'].includes(prog))
        return hasShort('d') || hasShort('D') || rest.includes('--decode');
    if (prog === 'xxd')
        return hasShort('r') || rest.includes('-revert');
    if (prog === 'openssl')
        return rest.includes('-d') || rest.includes('-base64') && rest.includes('-d') || rest[0] === 'base64' && rest.includes('-d');
    if (['uudecode', 'rev', 'tr', 'gunzip', 'zcat', 'bzcat', 'xzcat', 'unxz', 'unzstd', 'zstdcat', 'lzcat'].includes(prog))
        return true;
    if (['gzip', 'bzip2', 'xz', 'zstd', 'lz4', 'brotli'].includes(prog))
        return hasShort('d') || rest.includes('--decompress');
    if (prog === 'printf' || prog === 'echo' || prog === 'print') {
        const joined = rest.join(' ');
        if (info.ansiC)
            return true;
        if (prog === 'printf')
            return /\\x[0-9a-fA-F]|\\[0-7]{1,3}|\\u[0-9a-fA-F]|%b/.test(joined);
        return /\\x[0-9a-fA-F]|\\[0-7]{3}|\\u[0-9a-fA-F]/.test(joined) && (rest.includes('-e') || /^-[a-zA-Z]*e/.test(rest[0] || '') || prog === 'print');
    }
    if (tables_1.INTERPRETERS.has(prog))
        return tables_1.INTERPRETER_DECODE.test(rest.join(' '));
    return false;
}
function substitutionsDecode(subs, run) {
    for (const s of subs) {
        const parsed = shellParse.parseShell(s);
        const info = { upstream: [], ansiC: /\$'[^']*\\(?:x[0-9a-fA-F]|[0-7]{2,3})/.test(s), subs: parsed.substitutions || [] };
        if (!parsed.ok) {
            if (/base64|xxd|rev\b|openssl|gunzip|\\x/.test(s))
                return true;
            continue;
        }
        if (parsed.commands.some((c) => decoderCommand(c, run, info)))
            return true;
        if (substitutionsDecode(parsed.substitutions || [], run))
            return true;
    }
    return false;
}
function fetcherCommand(cmd) {
    const words = cmd.words.map((w) => w.text);
    const prog = (words[0] || '').split('/').pop() || '';
    return ['curl', 'wget', 'fetch', 'http', 'https', 'iwr', 'invoke-webrequest', 'aria2c'].includes(prog);
}
// A shell or interpreter that reads its program from stdin inside a pipeline.
function stdinExec(prog, rest, x, ctx, run) {
    const upstream = x.info.upstream;
    if (upstream.length === 0)
        return;
    if (upstream.some((c) => decoderCommand(c, run, x.info))) {
        hit(run, 'Sx', 'decoded_pipe_exec');
        return;
    }
    if (upstream.some((c) => fetcherCommand(c))) {
        run.flags.add('remote_exec');
        return;
    }
    const last = upstream[upstream.length - 1];
    const words = last.words.map((w) => resolveWord(w, ctx, run));
    const p = words[0] ? progName(words[0], run) : null;
    if ((p === 'echo' || p === 'printf') && words.slice(1).every((w) => w.text !== null)) {
        const text = words.slice(1).filter((w) => !(p === 'echo' && /^-[neE]+$/.test(w.text || ''))).map((w) => w.text).join(' ');
        if (tables_1.SHELLS.has(prog))
            evalShell(text, childCtx(ctx), run);
        else
            scanInterpreterCode(text, run);
        return;
    }
    if (p === 'cat' && words.length === 2 && words[1].text !== null && tables_1.SHELLS.has(prog)) {
        scriptFile(words[1], rest, ctx, run, x);
        return;
    }
    worseParse(run, 'dynamic');
    tripwire(upstream.map((c) => c.words.map((w) => w.text.replace(/\u0000/g, '')).join(' ')).join(' | '), run);
}
// `$(…)` used as code: eval "$(…)", sh -c "$(…)", a program word that is a substitution, source <(…).
function checkSubstitutionExec(subs, ctx, run) {
    for (const s of subs) {
        const parsed = shellParse.parseShell(s, { depth: ctx.depth + 1 });
        if (!parsed.ok) {
            tripwire(s, run);
            continue;
        }
        const info = { upstream: [], ansiC: /\$'[^']*\\(?:x[0-9a-fA-F]|[0-7]{2,3})/.test(s), subs: parsed.substitutions };
        if (parsed.commands.some((c) => decoderCommand(c, run, info))) {
            hit(run, 'Sx', 'decoded_substitution_exec');
            continue;
        }
        if (parsed.commands.some((c) => fetcherCommand(c))) {
            run.flags.add('remote_exec');
            continue;
        }
        const simple = parsed.commands.length === 1 ? parsed.commands[0] : null;
        if (simple && ['echo', 'printf'].includes(simple.words[0]?.text || '') && simple.words.slice(1).every((w) => !w.dynamic)) {
            evalShell(simple.words.slice(1).map((w) => w.text).filter((t) => !/^-[neE]+$/.test(t)).join(' '), childCtx(ctx), run);
            continue;
        }
        if (simple && simple.words[0]?.text === 'cat' && simple.words.length === 2 && !simple.words[1].dynamic) {
            scriptFile(litArg(simple.words[1].text), [], ctx, run, null);
            continue;
        }
        worseParse(run, 'dynamic');
        tripwire(s, run);
    }
}
function scanInterpreterCode(code, run) {
    if (tables_1.INTERPRETER_TREE_DELETE.test(code))
        hit(run, 'S5', 'interpreter_tree_delete');
    if (tables_1.INTERPRETER_DECODE.test(code) && tables_1.INTERPRETER_EXEC.test(code))
        hit(run, 'Sx', 'interpreter_decoded_exec');
    tripwire(code, run);
}
// ---------------------------------------------------------------------------------------------
// paths
function expandTilde(text, run) {
    if (text === '~' || text.startsWith('~/'))
        return run.home + text.slice(1);
    const m = text.match(/^~([A-Za-z0-9._-]+)(\/.*)?$/);
    if (m)
        return `${(run.env.platform === 'darwin' ? '/Users/' : '/home/') + m[1]}${m[2] || ''}`;
    if (text.startsWith('~'))
        return null;
    return text;
}
function rewriteProc(abs, cwds) {
    const m = abs.match(/^\/proc\/[^/]+\/(root|cwd)(\/.*)?$/);
    if (!m)
        return [abs];
    if (m[1] === 'root')
        return [path.posix.normalize(m[2] || '/')];
    return cwds.map((c) => (c ? path.posix.join(c, m[2] || '') : path.posix.join('/__unknown_cwd__', m[2] || '')));
}
// Absolute candidates for a literal path operand under every possible cwd. Unknown cwd gives a
// placeholder root so home-agnostic secret patterns still match by name.
function absCandidates(text, ctx, run) {
    const t = expandTilde(text, run);
    if (t === null)
        return null;
    const out = [];
    if (path.posix.isAbsolute(t))
        out.push(path.posix.normalize(t));
    else
        for (const c of ctx.cwds)
            out.push(path.posix.resolve(c || '/__unknown_cwd__', t));
    return out.flatMap((p) => rewriteProc(p, ctx.cwds)).map((p) => (p.length > 1 ? p.replace(/\/+$/, '') : p));
}
function realCandidates(abs, run, followFinal) {
    const out = new Set([abs]);
    if (followFinal) {
        const r = longestRealpath(abs, run);
        if (r)
            out.add(r);
    }
    else {
        const parent = longestRealpath(path.posix.dirname(abs), run);
        if (parent)
            out.add(path.posix.join(parent, path.posix.basename(abs)));
    }
    return [...out];
}
function longestRealpath(abs, run) {
    let cur = abs;
    const tail = [];
    for (let k = 0; k < 64; k += 1) {
        const r = safeRealpath(run.env, cur);
        if (r)
            return tail.length ? path.posix.join(r, ...tail.reverse()) : r;
        const parent = path.posix.dirname(cur);
        if (parent === cur)
            return null;
        tail.push(path.posix.basename(cur));
        cur = parent;
    }
    return null;
}
function isSecretPath(abs, run) {
    const p = run.fold ? abs.toLowerCase() : abs;
    const base = path.posix.basename(p);
    if (/^\.env(?:\.|$)/.test(base) && tables_1.ENV_TEMPLATE_SUFFIX.test(base))
        return false;
    if (tables_1.KEY_EXTENSIONS.test(base)) {
        const segs = p.split('/');
        if (!segs.some((s) => tables_1.KEY_FIXTURE_SEGMENTS.has(s)))
            return true;
    }
    const hits = run.secretRegexes.some((re) => re.test(p) || (run.fold && re.test(abs)));
    if (!hits)
        return false;
    if (/\/\.ssh\//.test(p) && tables_1.SSH_PUBLIC.test(base))
        return false;
    return true;
}
// Matches a glob or partly dynamic operand against concrete secret examples.
function patternToRegex(pattern, lookalike) {
    let out = '';
    for (let i = 0; i < pattern.length; i += 1) {
        const ch = pattern[i];
        if (ch === DYN)
            out += '.*';
        else if (ch === '*')
            out += '[^/]*';
        else if (ch === '?')
            out += '[^/]';
        else if (ch === '[') {
            const end = pattern.indexOf(']', i + 2);
            if (end > 0) {
                out += '[^/]';
                i = end;
            }
            else
                out += '\\[';
        }
        else if (lookalike && /[^\x00-\x7f]/.test(ch))
            out += '.';
        else
            out += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
    return new RegExp(`^${out}$`, 'i');
}
function sampleMatch(a, ctx, run, samples) {
    const raw = a.pattern;
    const lookalike = a.nonAscii;
    const expanded = raw.startsWith('~') ? (expandTilde(raw, run) ?? raw) : raw;
    const cands = [];
    if (expanded.startsWith('/') || expanded.startsWith(DYN))
        cands.push(expanded);
    if (!expanded.startsWith('/'))
        for (const c of ctx.cwds)
            cands.push(`${(c || '/__unknown_cwd__').replace(/\/$/, '')}/${expanded}`);
    for (const cand of cands) {
        const re = patternToRegex(cand.replace(/\/\.\//g, '/'), lookalike);
        if (samples.some((s) => re.test(s) && isSecretPath(s, run)))
            return true;
    }
    return false;
}
function cwdsList(ctx) { return ctx.cwds.map((c) => c || '/__unknown_cwd__'); }
// S4: a secret path as an operand. Returns true on a stop.
function checkSecretOperand(a, ctx, run, reason) {
    if (a.text === null && a.alts && a.alts.length) {
        for (const v of a.alts)
            if (checkSecretOperand({ ...litArg(v), glob: a.glob, word: a.word }, ctx, run, reason))
                return true;
        return false;
    }
    for (const text of operandPaths(a)) {
        if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text))
            continue;
        if (a.text === null || a.glob || a.nonAscii) {
            const probe = a.text === null ? a : { ...a, pattern: text };
            if (/[A-Za-z0-9._~/-]/.test(probe.pattern.replace(new RegExp(DYN, 'g'), '')) && sampleMatch(probe, ctx, run, (0, tables_1.secretSamples)(run.home, cwdsList(ctx)))) {
                return hit(run, 'S4', `${reason}_secret_pattern`);
            }
            if (a.text === null)
                continue;
        }
        const abs = absCandidates(text, ctx, run);
        if (!abs)
            continue;
        for (const p of abs)
            for (const r of realCandidates(p, run, true))
                if (isSecretPath(r, run))
                    return hit(run, 'S4', `${reason}_secret_path`);
    }
    return false;
}
// Path-ish parts of an operand: the value after `--opt=`, after `@` (curl -d @file) and after `:`
// for git object paths (HEAD:.env).
function operandPaths(a) {
    const t = a.text !== null ? a.text : a.pattern;
    const out = [t];
    const eq = t.match(/^--?[A-Za-z0-9-]+=(.+)$/);
    if (eq)
        out.push(eq[1]);
    const at = t.match(/(?:^|=)@(.+)$/);
    if (at)
        out.push(at[1]);
    const colon = t.match(/^[^/:]+:(.+)$/);
    if (colon && !/^[a-z]+:\/\//i.test(t))
        out.push(colon[1]);
    return out.map((p) => (a.text === null ? p : p)).filter(Boolean);
}
// S0: a write, move or delete on a protected path. `tree` also stops on an ancestor of a protected
// anchor (rm -rf ~/.claude, mv .claude x).
function checkProtectedWrite(a, ctx, run, reason, tree) {
    if (a.text === null) {
        // Partly dynamic target: stop when its literal part can only be a protected location.
        const lit = a.pattern.replace(new RegExp(DYN, 'g'), '');
        if (/\.marrow|\.claude|\.codex|\.cursor|\.gemini|\.bashrc|\.zshrc|\.profile|hooks\.json|settings\.json|\.mcp\.json/.test(lit))
            return hit(run, 'S0', `${reason}_protected_dynamic`);
        return false;
    }
    const abs = absCandidates(a.text, ctx, run);
    if (!abs)
        return false;
    for (const p of abs) {
        for (const r of realCandidates(p, run, false)) {
            const probe = run.fold ? r.toLowerCase() : r;
            if (run.isProtected(probe))
                return hit(run, 'S0', `${reason}_protected_path`);
            if (tree && run.protectedAnchors.some((anchor) => isAncestorOrSelf(probe, anchor)))
                return hit(run, 'S0', `${reason}_protected_ancestor`);
        }
    }
    return false;
}
function markWritten(a, ctx) {
    if (a.text === null)
        return;
    for (const c of ctx.cwds)
        ctx.written.add(path.posix.resolve(c || '/__unknown_cwd__', a.text));
}
// ---------------------------------------------------------------------------------------------
// S5 workspace boundary
function strictChildOf(p, roots) {
    return roots.some((r) => p !== r && p.startsWith(`${r}/`));
}
function isSafeDeleteTarget(p, run) {
    const roots = [...run.wsRoots, ...run.tmpRoots];
    if (p === '/' || p === run.home)
        return false;
    if (run.wsRoots.some((w) => isAncestorOrSelf(p, w)))
        return false;
    if (run.tmpRoots.includes(p))
        return false;
    return strictChildOf(p, roots);
}
// kind: 'tree' = the target and everything under it; 'children' = entries under the target dir.
function checkDeleteTarget(a, ctx, run, reason, kind) {
    if (ctx.remote)
        return hit(run, 'S5', `${reason}_remote`);
    if (a.text === null && a.alts && a.alts.length) {
        for (const v of a.alts)
            if (checkDeleteTarget({ ...litArg(v), glob: a.glob }, ctx, run, reason, kind))
                return true;
        return false;
    }
    if (a.text === null)
        return hit(run, 'S5', `${reason}_dynamic_target`);
    if (a.nonAscii)
        return hit(run, 'S5', `${reason}_non_ascii_target`);
    let text = a.text;
    let effKind = kind;
    if (a.glob) {
        const segs = text.split('/');
        const firstGlob = segs.findIndex((s) => /[*?[]/.test(s));
        const prefix = segs.slice(0, firstGlob).join('/') || (text.startsWith('/') ? '/' : '.');
        const lastIsBroad = firstGlob === segs.length - 1 && /^[*?.[\]!^-]*$/.test(segs[firstGlob]);
        text = prefix;
        effKind = lastIsBroad ? 'tree' : 'children';
    }
    const abs = absCandidates(text, ctx, run);
    if (!abs)
        return hit(run, 'S5', `${reason}_unresolved_home`);
    const follow = /\/\.?$|\/\*$/.test(a.text) || effKind === 'children';
    for (const p of abs) {
        if (p.startsWith('/__unknown_cwd__'))
            return hit(run, 'S5', `${reason}_unknown_cwd`);
        for (const r of realCandidates(p, run, follow)) {
            const ok = effKind === 'children'
                ? (r !== '/' && r !== run.home && (isSafeDeleteTarget(r, run) || run.wsRoots.includes(r) || run.tmpRoots.includes(r)))
                : effKind === 'find'
                    ? (r !== '/' && r !== run.home && (isSafeDeleteTarget(r, run) || run.wsRoots.includes(r)))
                    : isSafeDeleteTarget(r, run);
            if (!ok)
                return hit(run, 'S5', `${reason}_outside_workspace`);
        }
    }
    return false;
}
function checkTreeDeletes(targets, ctx, run, reason) {
    for (const t of targets) {
        checkProtectedWrite(t, ctx, run, reason, true);
        checkDeleteTarget(t, ctx, run, reason, 'tree');
    }
}
// ---------------------------------------------------------------------------------------------
// generic operand checks (S4 on every program, S0 on write programs)
function genericOperandChecks(prog, args, ctx, run) {
    const rest = args.slice(1);
    if (!tables_1.S4_EXEMPT_PROGRAMS.has(prog) && prog !== 'git') {
        let skipNext = false;
        for (let i = 0; i < rest.length; i += 1) {
            const a = rest[i];
            if (skipNext) {
                skipNext = false;
                continue;
            }
            // ssh-style identity flags use the key without printing it.
            if (['scp', 'rsync', 'ssh-copy-id', 'sshfs'].includes(prog) && a.text === '-i') {
                skipNext = true;
                continue;
            }
            checkSecretOperand(a, ctx, run, 'operand');
        }
    }
    // Copying or archiving a directory that holds credential files (cp -r ~/.ssh, tar ~) is a read too.
    if (COPY_PROGRAMS.has(prog)) {
        const secretDirs = ['.ssh', '.aws', '.config/gcloud', '.azure', '.kube', '.docker', '.config/gh', '.config/op', '.gnupg', '.marrow'].map((d) => path.posix.join(run.home, d));
        for (const a of nonOptions(rest)) {
            if (a.text === null)
                continue;
            const abs = absCandidates(a.text, ctx, run);
            if (!abs)
                continue;
            if (abs.some((p) => realCandidates(p, run, true).some((r) => secretDirs.some((d) => isAncestorOrSelf(r, d))))) {
                hit(run, 'S4', 'copy_secret_directory');
                break;
            }
        }
    }
    const writes = writeTargets(prog, rest);
    for (const { arg, tree } of writes) {
        checkProtectedWrite(arg, ctx, run, `${prog}_write`, tree);
        markWritten(arg, ctx);
    }
}
const COPY_PROGRAMS = new Set(['cp', 'scp', 'rsync', 'tar', 'zip', '7z', '7za', 'rclone', 'gtar', 'bsdtar', 'ditto']);
function nonOptions(rest, valueFlags = new Set()) {
    const out = [];
    let after = false;
    for (let i = 0; i < rest.length; i += 1) {
        const a = rest[i];
        if (!after && a.text === '--') {
            after = true;
            continue;
        }
        if (!after && isOpt(a)) {
            if (a.text && valueFlags.has(a.text))
                i += 1;
            continue;
        }
        out.push(a);
    }
    return out;
}
function writeTargets(prog, rest) {
    const ops = nonOptions(rest, new Set(['-t', '--target-directory', '-m', '--mode', '-o', '-g', '-S', '--suffix', '-s', '--size', '-r', '--reference']));
    const all = (tree) => ops.map((arg) => ({ arg, tree }));
    switch (prog) {
        case 'tee':
        case 'touch':
        case 'truncate':
        case 'unlink':
        case 'shred': return all(false);
        case 'rm':
        case 'rmdir': return all(true);
        case 'chmod':
        case 'chown':
        case 'chgrp':
        case 'chattr': return ops.slice(1).map((arg) => ({ arg, tree: false }));
        case 'mv': {
            const dest = ops.length >= 2 ? ops[ops.length - 1] : null;
            const into = dest && dest.text !== null ? ops.slice(0, -1).filter((s) => s.text !== null).map((s) => ({ arg: litArg(`${dest.text.replace(/\/+$/, '')}/${path.posix.basename(s.text)}`), tree: false })) : [];
            return [...all(true), ...into];
        }
        case 'cp':
        case 'install':
        case 'ln':
        case 'rsync':
        case 'scp': {
            const t = targetDirFlag(rest);
            const dest = t || (ops.length >= 2 ? ops[ops.length - 1] : null);
            if (!dest)
                return [];
            const sources = t ? ops : ops.slice(0, -1);
            // Into a directory: the file lands at dest/<basename of each source>.
            const into = dest.text === null ? [] : sources.filter((s) => s.text !== null).map((s) => ({ arg: litArg(`${dest.text.replace(/\/+$/, '')}/${path.posix.basename(s.text)}`), tree: false }));
            return [{ arg: dest, tree: false }, ...into];
        }
        case 'sed':
        case 'gsed': {
            if (!rest.some((a) => a.text !== null && (/^-[a-zA-Z]*i/.test(a.text) || a.text.startsWith('--in-place'))))
                return [];
            const hasScript = rest.some((a) => a.text === '-e' || a.text === '-f' || a.text === '--expression');
            return (hasScript ? ops : ops.slice(1)).map((arg) => ({ arg, tree: false }));
        }
        case 'perl': {
            if (!rest.some((a) => a.text !== null && /^-[a-zA-Z]*i/.test(a.text)))
                return [];
            const idx = rest.findIndex((a) => a.text !== null && /^-[a-zA-Z]*e$/.test(a.text));
            return (idx >= 0 ? nonOptions(rest.slice(idx + 2)) : ops.slice(1)).map((arg) => ({ arg, tree: false }));
        }
        case 'curl':
        case 'wget': {
            const out = [];
            for (let i = 0; i < rest.length; i += 1) {
                const t = rest[i].text || '';
                if ((t === '-o' || t === '--output' || t === '-O' && prog === 'wget' || t === '--output-document' || t === '-P' || t === '--directory-prefix') && rest[i + 1])
                    out.push({ arg: rest[i + 1], tree: false });
                const eq = t.match(/^--(?:output|output-document|directory-prefix)=(.+)$/);
                if (eq)
                    out.push({ arg: litArg(eq[1]), tree: false });
            }
            return out;
        }
        case 'dd': return rest.filter((a) => a.text && a.text.startsWith('of=')).map((a) => ({ arg: litArg((a.text || '').slice(3)), tree: false }));
        case 'unzip': {
            const i = rest.findIndex((a) => a.text === '-d');
            return i >= 0 && rest[i + 1] ? [{ arg: rest[i + 1], tree: true }] : [];
        }
        case 'tar': {
            const i = rest.findIndex((a) => a.text === '-C' || a.text === '--directory');
            const extracting = rest.some((a) => a.text !== null && (/^-?[a-zA-Z]*x/.test(a.text) && !a.text.startsWith('--') || a.text === '--extract'));
            return extracting && i >= 0 && rest[i + 1] ? [{ arg: rest[i + 1], tree: true }] : [];
        }
        default: return [];
    }
}
function targetDirFlag(rest) {
    for (let i = 0; i < rest.length; i += 1) {
        const t = rest[i].text;
        if ((t === '-t' || t === '--target-directory') && rest[i + 1])
            return rest[i + 1];
        if (t && t.startsWith('--target-directory='))
            return litArg(t.slice('--target-directory='.length));
    }
    return null;
}
// ---------------------------------------------------------------------------------------------
// builtins
function changeDir(rest, ctx, run, subshell) {
    const ops = nonOptions(rest);
    const target = ops[0];
    if (!target) {
        ctx.cwds = subshell ? [...new Set([...ctx.cwds, run.home])] : [run.home];
        return;
    }
    if (target.text === null || target.text === '-' || target.glob) {
        ctx.cwds = [...new Set([...ctx.cwds, null])];
        return;
    }
    const next = [];
    for (const c of ctx.cwds) {
        const t = expandTilde(target.text, run);
        if (t === null) {
            next.push(null);
            continue;
        }
        if (path.posix.isAbsolute(t))
            next.push(path.posix.normalize(t));
        else
            next.push(c ? path.posix.resolve(c, t) : null);
    }
    // A cd that may fail (missing dir) or runs in a subshell leaves the old cwd possible too.
    const certain = !subshell && next.every((n) => n !== null && safeRealpath(run.env, n) !== null);
    ctx.cwds = certain ? [...new Set(next)] : [...new Set([...ctx.cwds, ...next])];
}
function defineAliases(rest, ctx, run) {
    for (const a of rest) {
        if (a.text === null) {
            worseParse(run, 'dynamic');
            tripwire(a.pattern, run);
            continue;
        }
        const eq = a.text.indexOf('=');
        if (eq <= 0)
            continue;
        const name = a.text.slice(0, eq);
        const value = a.text.slice(eq + 1);
        ctx.aliases.set(name, value);
        // Definitions are classified as if executed (spec A10).
        evalShell(value, childCtx(ctx), run);
    }
}
function declareLike(prog, rest, ctx, run, x) {
    const opts = rest.filter((a) => isOpt(a)).map((a) => a.text || '');
    const names = rest.filter((a) => !isOpt(a));
    if (names.length === 0) {
        if (prog === 'export' && (opts.length === 0 || opts.some((o) => o.includes('p')))) {
            hit(run, 'S4', 'env_dump_export');
            return;
        }
        if ((prog === 'declare' || prog === 'typeset') && (opts.length === 0 || opts.some((o) => /[xp]/.test(o)))) {
            hit(run, 'S4', 'env_dump_declare');
            return;
        }
        if (prog === 'readonly' && (opts.length === 0 || opts.some((o) => o.includes('p')))) {
            hit(run, 'S4', 'env_dump_readonly');
            return;
        }
        return;
    }
    if ((prog === 'declare' || prog === 'typeset') && opts.some((o) => o.includes('p'))) {
        for (const n of names)
            if (n.text === null || tables_1.SECRET_VAR.test(n.text)) {
                hit(run, 'S4', 'env_dump_declare_secret');
                return;
            }
    }
    for (const n of names) {
        if (n.text === null) {
            worseParse(run, 'dynamic');
            continue;
        }
        const eq = n.text.indexOf('=');
        const name = eq >= 0 ? n.text.slice(0, eq) : n.text;
        if (eq >= 0)
            ctx.vars.set(name, [n.text.slice(eq + 1)]);
        else if (n.word && n.word.dynamic)
            ctx.vars.set(name, null);
        if (prog === 'export' || opts.some((o) => o.includes('x')))
            ctx.exported.add(name);
    }
    void x;
}
function setBuiltin(rest, run) {
    if (rest.length === 0)
        hit(run, 'S4', 'env_dump_set');
}
function printenv(rest, run) {
    const names = rest.filter((a) => !isOpt(a));
    if (names.length === 0) {
        hit(run, 'S4', 'env_dump_printenv');
        return;
    }
    for (const n of names)
        if (n.text === null || tables_1.SECRET_VAR.test(n.text)) {
            hit(run, 'S4', 'env_dump_printenv_secret');
            return;
        }
}
function echoLike(args, run, x) {
    for (const a of args.slice(1)) {
        if (!a.word)
            continue;
        for (const slot of a.word.slots) {
            if (slot.type !== 'var' || !slot.name)
                continue;
            const name = slot.name.replace(/^!/, '');
            if (slot.name.startsWith('!') || tables_1.SECRET_VAR.test(name.replace(/[^A-Za-z0-9_].*$/, ''))) {
                hit(run, 'S4', 'echo_secret_var');
                return;
            }
        }
    }
    void x;
}
function evalBuiltin(rest, ctx, run, subs) {
    if (rest.some((a) => a.word && a.word.substitution))
        checkSubstitutionExec(subs, ctx, run);
    if (rest.every((a) => a.text !== null)) {
        evalShell(rest.map((a) => a.text).join(' '), childCtx(ctx), run);
        return;
    }
    if (rest.every((a) => a.alts !== null)) {
        for (const a of rest)
            for (const v of a.alts || [])
                evalShell(v, childCtx(ctx), run);
        return;
    }
    worseParse(run, 'dynamic');
    if (rest.some((a) => a.word && a.word.variables.some((v) => ctx.decodedVars.has(v))))
        hit(run, 'Sx', 'decoded_variable_eval');
    tripwire(rest.map(argText).join(' '), run);
}
function sourceFile(rest, ctx, run, x) {
    const target = rest[0];
    if (!target)
        return;
    if (target.word && target.word.substitution) {
        checkSubstitutionExec(x.info.subs, ctx, run);
        return;
    }
    if (target.text === '/dev/stdin' || target.text === '-') {
        stdinExec('sh', rest.slice(1), x, ctx, run);
        return;
    }
    scriptFile(target, rest.slice(1), ctx, run, x);
}
function envWrapper(rest, ctx, run, x) {
    let i = 0;
    let clean = false;
    const extra = new Map(x.env);
    let cwds = ctx.cwds;
    while (i < rest.length) {
        const t = rest[i].text;
        if (t === null)
            break;
        if (t === '-i' || t === '--ignore-environment' || t === '-') {
            clean = true;
            i += 1;
            continue;
        }
        if (t === '-u' || t === '--unset' || t === '-C' || t === '--chdir') {
            if ((t === '-C' || t === '--chdir') && rest[i + 1]?.text)
                cwds = [path.posix.resolve(ctx.cwds[0] || '/__unknown_cwd__', rest[i + 1].text)];
            i += 2;
            continue;
        }
        if (t === '-S' || t === '--split-string') {
            const s = rest[i + 1];
            if (s && s.text !== null)
                evalShell([s.text, ...rest.slice(i + 2).map((a) => (a.text !== null ? shellQuote(a.text) : '"$__d"'))].join(' '), childCtx(ctx), run);
            else
                tripwire(rest.map(argText).join(' '), run);
            return;
        }
        if (t === '--') {
            i += 1;
            break;
        }
        if (t.startsWith('-')) {
            i += 1;
            continue;
        }
        if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) {
            const eq = t.indexOf('=');
            extra.set(t.slice(0, eq), [t.slice(eq + 1)]);
            i += 1;
            continue;
        }
        break;
    }
    if (i >= rest.length) {
        if (!clean)
            hit(run, 'S4', 'env_dump_env');
        return;
    }
    dispatch(rest.slice(i), { ...ctx, cwds }, run, { ...x, env: extra });
}
function privilegeWrapper(prog, rest, ctx, run, x) {
    const valueFlags = new Set(['-u', '-g', '-C', '-D', '-h', '-p', '-r', '-t', '-U', '-T', '--user', '--group', '--chdir', '--prompt', '--host', '--close-from']);
    let i = 0;
    let shell = false;
    while (i < rest.length) {
        const t = rest[i].text;
        if (t === null)
            break;
        if (t === '--') {
            i += 1;
            break;
        }
        if (valueFlags.has(t)) {
            i += 2;
            continue;
        }
        if (t.startsWith('-')) {
            if (/^-[a-zA-Z]*[si]/.test(t) && !t.startsWith('--'))
                shell = true;
            i += 1;
            continue;
        }
        break;
    }
    if (i >= rest.length) {
        if (shell)
            stdinExec('sh', [], x, ctx, run);
        return;
    }
    void prog;
    dispatch(rest.slice(i), ctx, run, x);
}
function suWrapper(rest, ctx, run, x) {
    for (let i = 0; i < rest.length; i += 1) {
        const t = rest[i].text;
        if ((t === '-c' || t === '--command') && rest[i + 1])
            return shellString(rest[i + 1], ctx, run, x.info.subs);
        if (t && t.startsWith('--command='))
            return shellString(litArg(t.slice(10)), ctx, run, x.info.subs);
    }
    if (x.info.upstream.length)
        stdinExec('sh', [], x, ctx, run);
}
function shellString(a, ctx, run, subs) {
    if (a.text !== null) {
        evalShell(a.text, childCtx(ctx), run);
        return;
    }
    if (a.word && a.word.substitution)
        checkSubstitutionExec(subs, ctx, run);
    if (a.alts) {
        for (const v of a.alts)
            evalShell(v, childCtx(ctx), run);
        return;
    }
    worseParse(run, 'dynamic');
    tripwire(a.pattern.replace(new RegExp(DYN, 'g'), ' '), run);
}
function simpleWrapper(prog, rest, ctx, run, x) {
    let i = 0;
    const valueFlags = {
        timeout: ['-s', '--signal', '-k', '--kill-after'], nice: ['-n', '--adjustment'], ionice: ['-c', '-n', '-p', '-P', '-u', '--class', '--classdata'],
        stdbuf: ['-i', '-o', '-e', '--input', '--output', '--error'], time: ['-f', '-o', '--format', '--output'], exec: ['-a'],
        caffeinate: ['-t', '-w'], taskset: [], chrt: [], retry: ['-t', '--times', '-d', '--delay', '--until'], flock: ['-w', '--timeout', '-E', '--conflict-exit-code'],
    };
    const vf = new Set(valueFlags[prog] || []);
    if (prog === 'command' && rest.some((a) => a.text === '-v' || a.text === '-V'))
        return;
    while (i < rest.length) {
        const t = rest[i].text;
        if (t === null)
            break;
        if (t === '--') {
            i += 1;
            break;
        }
        if (vf.has(t)) {
            i += 2;
            continue;
        }
        if (t.startsWith('-')) {
            i += 1;
            continue;
        }
        break;
    }
    if (prog === 'timeout' && i < rest.length)
        i += 1; // duration
    if (prog === 'chrt' && i < rest.length && /^\d+$/.test(rest[i].text || ''))
        i += 1;
    if (prog === 'taskset' && i < rest.length)
        i += 1; // mask
    if (prog === 'flock' && i < rest.length) {
        i += 1; // lock file
        const c = rest.findIndex((a) => a.text === '-c' || a.text === '--command');
        if (c >= 0 && rest[c + 1])
            return shellString(rest[c + 1], ctx, run, x.info.subs);
    }
    if (i >= rest.length)
        return;
    dispatch(rest.slice(i), ctx, run, x);
}
function xargsWrapper(prog, rest, ctx, run, x) {
    const vf = new Set(['-d', '--delimiter', '-E', '-e', '-I', '-i', '-L', '-l', '-n', '--max-args', '-P', '--max-procs', '-s', '--max-chars', '-a', '--arg-file', '-j', '--jobs']);
    let i = 0;
    while (i < rest.length) {
        const t = rest[i].text;
        if (t === null)
            break;
        if (t === '--') {
            i += 1;
            break;
        }
        if (vf.has(t)) {
            i += 2;
            continue;
        }
        if (t.startsWith('-')) {
            i += 1;
            continue;
        }
        break;
    }
    let inner = rest.slice(i);
    if (prog === 'parallel') {
        const sep = inner.findIndex((a) => a.text === ':::' || a.text === '::::');
        if (sep >= 0)
            inner = inner.slice(0, sep);
    }
    if (inner.length === 0)
        inner = [litArg('echo')];
    // Input lines become extra operands: unknown targets (spec A6).
    dispatch([...inner.map((a) => (a.text === '{}' ? dynArg() : a)), dynArg()], ctx, run, x);
}
function watchWrapper(rest, ctx, run) {
    const vf = new Set(['-n', '--interval', '-d', '-q', '--equexit', '-g']);
    let i = 0;
    while (i < rest.length && rest[i].text !== null && rest[i].text.startsWith('-'))
        i += vf.has(rest[i].text) ? 2 : 1;
    const inner = rest.slice(i);
    if (inner.every((a) => a.text !== null))
        evalShell(inner.map((a) => a.text).join(' '), childCtx(ctx), run);
    else
        tripwire(inner.map(argText).join(' '), run);
}
function sshRemote(rest, ctx, run) {
    const vf = new Set(['-b', '-c', '-D', '-E', '-e', '-F', '-I', '-i', '-J', '-L', '-l', '-m', '-O', '-o', '-p', '-Q', '-R', '-S', '-W', '-w', '-B']);
    let i = 0;
    while (i < rest.length) {
        const t = rest[i].text;
        if (t === null)
            break;
        if (vf.has(t)) {
            i += 2;
            continue;
        }
        if (t.startsWith('-')) {
            i += 1;
            continue;
        }
        break;
    }
    const remoteCmd = rest.slice(i + 1);
    if (remoteCmd.length === 0)
        return;
    const remoteCtx = childCtx(ctx, { cwds: [null], remote: true, vars: new Map(), aliases: new Map() });
    if (remoteCmd.every((a) => a.text !== null))
        evalShell(remoteCmd.map((a) => a.text).join(' '), remoteCtx, run);
    else {
        worseParse(run, 'dynamic');
        tripwire(remoteCmd.map(argText).join(' '), run);
    }
}
function handleShell(prog, rest, ctx, run, x) {
    void prog;
    for (let i = 0; i < rest.length; i += 1) {
        const t = rest[i].text;
        if (t === null) {
            if (rest[i].word && rest[i].word.substitution) {
                checkSubstitutionExec(x.info.subs, ctx, run);
                return;
            }
            worseParse(run, 'dynamic');
            tripwire(rest.map(argText).join(' '), run);
            return;
        }
        if (t === '-c' || (/^-[a-zA-Z]*c[a-zA-Z]*$/.test(t) && !t.startsWith('--'))) {
            const code = rest[i + 1];
            if (!code)
                return;
            return shellString(code, ctx, run, x.info.subs);
        }
        if (t === '-s' || t === '-')
            return stdinExec('sh', [], x, ctx, run);
        if (t === '-o' || t === '+o' || t === '-O' || t === '+O' || t === '--rcfile' || t === '--init-file') {
            i += 1;
            continue;
        }
        if (t.startsWith('-') || t.startsWith('+'))
            continue;
        return scriptFile(rest[i], rest.slice(i + 1), ctx, run, x);
    }
    if (x.cmd.heredoc !== null) {
        evalShell(x.cmd.heredoc, childCtx(ctx), run);
        return;
    }
    const input = x.cmd.redirects.find((r) => r.op === '<' && r.target);
    if (input && input.target) {
        if (input.target.substitution) {
            checkSubstitutionExec(x.info.subs, ctx, run);
            return;
        }
        return scriptFile(resolveWord(input.target, ctx, run), [], ctx, run, x);
    }
    stdinExec('sh', [], x, ctx, run);
}
function handleInterpreter(prog, rest, ctx, run, x) {
    const codeFlags = {
        node: /^(?:-e|--eval|-p|--print|-pe)$/, nodejs: /^(?:-e|--eval|-p|--print)$/, bun: /^(?:-e|--eval|-p|--print)$/,
        deno: /^(?:eval)$/, php: /^-r$/, ruby: /^-[a-zA-Z]*e$/, perl: /^-[a-zA-Z]*[eE]$/, lua: /^-e$/, irb: /^-e$/,
    };
    const isPython = /^(?:python[23]?(?:\.\d+)?|ipython)$/.test(prog);
    const codeRe = isPython ? /^-[a-zA-Z]*c$/ : (codeFlags[prog] || /^-e$/);
    for (let i = 0; i < rest.length; i += 1) {
        const a = rest[i];
        const t = a.text;
        if (t === null) {
            worseParse(run, 'dynamic');
            tripwire(rest.map(argText).join(' '), run);
            return;
        }
        if (codeRe.test(t) || (prog === 'deno' && t === 'eval')) {
            const code = rest[i + 1];
            if (!code)
                return;
            if (code.word && code.word.substitution)
                checkSubstitutionExec(x.info.subs, ctx, run);
            scanInterpreterCode(code.text !== null ? code.text : argText(code), run);
            return;
        }
        if (isPython && t === '-m') {
            const mod = rest[i + 1]?.text || '';
            if (mod === 'twine' && rest.slice(i + 2).some((b) => b.text === 'upload')) {
                hit(run, 'S3', 'twine_upload');
            }
            return;
        }
        if (t === '-')
            return stdinInterpreter(prog, x, ctx, run);
        if (t.startsWith('-')) {
            if (isPython && ['-W', '-X', '-Q'].includes(t))
                i += 1;
            if (!isPython && ['-r', '--require', '--import', '--loader', '-I', '-M', '--experimental-loader', '--env-file', '--conditions', '-C'].includes(t)) {
                if (t === '--env-file')
                    checkSecretOperand(rest[i + 1] || dynArg(), ctx, run, 'operand');
                i += 1;
            }
            continue;
        }
        return; // a script file: interpreted programs are a documented residual (spec A12)
    }
    stdinInterpreter(prog, x, ctx, run);
}
function stdinInterpreter(prog, x, ctx, run) {
    if (x.cmd.heredoc !== null) {
        scanInterpreterCode(x.cmd.heredoc, run);
        return;
    }
    stdinExec(prog, [], x, ctx, run);
}
// ---------------------------------------------------------------------------------------------
// script files, package scripts, make
function scriptFile(target, extra, ctx, run, x) {
    void extra;
    if (target.text === null) {
        worseParse(run, 'dynamic');
        tripwire(argText(target), run);
        return;
    }
    const abs = absCandidates(target.text, ctx, run);
    const name = path.posix.basename(target.text);
    if (!abs || abs.some((p) => p.startsWith('/__unknown_cwd__'))) {
        nameTripwire(name, run, 'script_unreadable');
        return;
    }
    if (abs.some((p) => ctx.written.has(p))) {
        worseParse(run, 'dynamic');
        tripwire(run.topSource, run);
        return;
    }
    if (ctx.depth >= tables_1.LIMITS.maxDepth) {
        worseParse(run, 'unparsed');
        nameTripwire(name, run, 'script_depth');
        return;
    }
    for (const p of abs) {
        const content = safeRead(run.env, p, tables_1.LIMITS.maxScriptBytes);
        if (content === null) {
            nameTripwire(name, run, 'script_unreadable');
            continue;
        }
        const shebang = content.startsWith('#!') ? content.slice(0, content.indexOf('\n') >>> 0).toLowerCase() : '';
        if (shebang && !/\b(?:sh|bash|zsh|dash|ksh|ash)\b/.test(shebang)) {
            // Non-shell scripts: decoded exec and tree deletes only (interpreted programs are a residual).
            if (tables_1.INTERPRETER_TREE_DELETE.test(content))
                hit(run, 'S5', 'script_tree_delete');
            if (tables_1.INTERPRETER_DECODE.test(content) && tables_1.INTERPRETER_EXEC.test(content))
                hit(run, 'Sx', 'script_decoded_exec');
            continue;
        }
        const sctx = scriptCtx(ctx, ctx.cwds, x ? x.env : new Map());
        evalShell(content, sctx, run);
    }
}
function nameTripwire(name, run, reason) {
    if (tables_1.NAME_TRIPWIRE.test(name)) {
        const n = name.toLowerCase();
        const category = /publish|release/.test(n) ? 'S3' : 'S2';
        hit(run, category, `${reason}_name`);
    }
}
function findPackageJson(ctx, run, cwd) {
    if (!cwd)
        return { pkg: null, dir: null, error: 'cwd_unknown' };
    let dir = cwd;
    for (let level = 0; level < 12; level += 1) {
        const file = path.posix.join(dir, 'package.json');
        if (ctx.written.has(file))
            return { pkg: null, dir, error: 'written' };
        const raw = safeRead(run.env, file, tables_1.LIMITS.maxPackageJsonBytes);
        if (raw !== null) {
            try {
                const pkg = JSON.parse(raw);
                return { pkg: pkg && typeof pkg === 'object' ? pkg : null, dir, error: pkg && typeof pkg === 'object' ? undefined : 'invalid' };
            }
            catch {
                return { pkg: null, dir, error: 'invalid' };
            }
        }
        const parent = path.posix.dirname(dir);
        if (parent === dir)
            break;
        dir = parent;
    }
    return { pkg: null, dir: null, error: 'missing' };
}
function runPackageScript(name, extraArgs, ctx, run, x, withHooks) {
    if (ctx.depth >= tables_1.LIMITS.maxDepth) {
        worseParse(run, 'unparsed');
        nameTripwire(name, run, 'package_script_depth');
        return;
    }
    for (const cwd of ctx.cwds) {
        const found = findPackageJson(ctx, run, cwd);
        if (found.error === 'written') {
            worseParse(run, 'dynamic');
            tripwire(run.topSource, run);
            continue;
        }
        const scripts = found.pkg && typeof found.pkg.scripts === 'object' && found.pkg.scripts ? found.pkg.scripts : null;
        if (!scripts || typeof scripts[name] !== 'string') {
            nameTripwire(name, run, 'package_script_unresolved');
            continue;
        }
        const hooks = withHooks ? [`pre${name}`, name, `post${name}`] : [name];
        for (const hook of hooks) {
            const body = scripts[hook];
            if (typeof body !== 'string')
                continue;
            const suffix = hook === name && extraArgs.length ? ` ${extraArgs.map((a) => (a.text !== null ? shellQuote(a.text) : '"$__marrow_dynamic"')).join(' ')}` : '';
            evalShell(body + suffix, scriptCtx(ctx, [found.dir], x.env), run);
        }
    }
}
function lifecycleScripts(names, ctx, run, x) {
    if (ctx.depth >= tables_1.LIMITS.maxDepth)
        return;
    for (const cwd of ctx.cwds) {
        const found = findPackageJson(ctx, run, cwd);
        if (found.error === 'written') {
            worseParse(run, 'dynamic');
            tripwire(run.topSource, run);
            continue;
        }
        const scripts = found.pkg && typeof found.pkg.scripts === 'object' && found.pkg.scripts ? found.pkg.scripts : null;
        if (!scripts)
            continue;
        for (const n of names)
            if (typeof scripts[n] === 'string')
                evalShell(scripts[n], scriptCtx(ctx, [found.dir], x.env), run);
    }
}
function handleMake(rest, ctx, run, x) {
    let dirs = ctx.cwds;
    let file = null;
    const targets = [];
    const vars = new Map();
    for (let i = 0; i < rest.length; i += 1) {
        const t = rest[i].text;
        if (t === null) {
            targets.push(rest[i]);
            continue;
        }
        if (t === '-C' || t === '--directory') {
            const d = rest[i + 1]?.text;
            dirs = d ? dirs.map((c) => (c ? path.posix.resolve(c, d) : null)) : [null];
            i += 1;
            continue;
        }
        if (t === '-f' || t === '--file' || t === '--makefile') {
            file = rest[i + 1]?.text ?? null;
            i += 1;
            continue;
        }
        if (t === '-j' || t === '-l' || t === '-o' || t === '-W' || t === '-I') {
            i += 1;
            continue;
        }
        if (t.startsWith('-'))
            continue;
        const eq = t.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
        if (eq) {
            vars.set(eq[1], eq[2]);
            continue;
        }
        targets.push(rest[i]);
    }
    if (ctx.depth >= tables_1.LIMITS.maxDepth) {
        worseParse(run, 'unparsed');
        for (const tg of targets)
            nameTripwire(argText(tg), run, 'make_depth');
        return;
    }
    for (const dir of dirs) {
        let content = null;
        const names = file ? [file] : ['GNUmakefile', 'makefile', 'Makefile'];
        for (const n of names) {
            if (!dir && !path.posix.isAbsolute(n))
                break;
            const p = path.posix.resolve(dir || '/', n);
            if (ctx.written.has(p)) {
                worseParse(run, 'dynamic');
                tripwire(run.topSource, run);
                return;
            }
            content = safeRead(run.env, p, tables_1.LIMITS.maxScriptBytes);
            if (content !== null)
                break;
        }
        if (content === null) {
            for (const tg of targets)
                nameTripwire(argText(tg), run, 'make_unreadable');
            continue;
        }
        const mk = parseMakefile(content);
        for (const [k, v] of vars)
            mk.vars.set(k, v);
        const wanted = targets.length ? targets.map((tg) => tg.text) : [mk.first];
        const seen = new Set();
        const visit = (target, depth) => {
            if (target === null) {
                worseParse(run, 'dynamic');
                return;
            }
            if (seen.has(target) || depth > 8)
                return;
            seen.add(target);
            const rule = mk.rules.get(target);
            if (!rule)
                return;
            for (const dep of rule.deps)
                visit(dep, depth + 1);
            for (const line of rule.recipe)
                evalShell(expandMakeLine(line, mk.vars), scriptCtx(ctx, [dir], x.env), run);
        };
        for (const w of wanted)
            visit(w, 0);
    }
}
function parseMakefile(content) {
    const rules = new Map();
    const vars = new Map();
    let first = null;
    let current = [];
    const lines = content.replace(/\\\n/g, ' ').split('\n');
    for (const line of lines) {
        if (line.startsWith('\t')) {
            for (const r of current)
                r.recipe.push(line.slice(1));
            continue;
        }
        if (/^\s*(?:#|$)/.test(line))
            continue;
        const assign = line.match(/^\s*(?:export\s+|override\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*(?::{1,3}|\?|\+|!)?=\s*(.*)$/);
        if (assign) {
            vars.set(assign[1], /\$[({]/.test(assign[2]) ? null : assign[2].trim());
            current = [];
            continue;
        }
        const rule = line.match(/^([^:#=\t][^:#=]*?)\s*::?(?!=)\s*([^=;#]*)(?:;\s*(.*))?$/);
        if (rule) {
            const names = rule[1].trim().split(/\s+/);
            const deps = rule[2].trim() ? rule[2].trim().split(/\s+/) : [];
            current = [];
            for (const n of names) {
                if (!first && !n.startsWith('.') && !n.includes('%'))
                    first = n;
                const r = rules.get(n) || { deps: [], recipe: [] };
                r.deps.push(...deps);
                if (rule[3])
                    r.recipe.push(rule[3]);
                rules.set(n, r);
                current.push(r);
            }
            continue;
        }
        current = [];
    }
    return { rules, vars, first };
}
function expandMakeLine(line, vars) {
    let out = line.replace(/^[\s@+-]+/, '').replace(/\$\$/g, '\u0002');
    for (let k = 0; k < 4; k += 1) {
        out = out.replace(/\$[({]([A-Za-z_][A-Za-z0-9_.-]*)[)}]/g, (_m, name) => {
            if (name === 'MAKE')
                return 'make';
            const v = vars.get(name);
            return typeof v === 'string' ? v : '"$__marrow_make_var"';
        });
    }
    out = out.replace(/\$[({][^)}]*[)}]|\$[@<^?*%]/g, '"$__marrow_make_var"');
    return out.replace(/\u0002/g, '$');
}
function boolFlag(rest, names, negs = []) {
    let state = 'absent';
    for (const a of rest) {
        if (a.text === null) {
            if (state !== 'absent' || names.some((n) => a.pattern.startsWith(n)))
                state = 'unknown';
            continue;
        }
        if (a.text === '--')
            break;
        const t = a.text;
        if (names.includes(t)) {
            state = 'true';
            continue;
        }
        if (negs.includes(t)) {
            state = 'false';
            continue;
        }
        const eq = t.indexOf('=');
        if (eq > 0 && names.includes(t.slice(0, eq))) {
            const v = t.slice(eq + 1).toLowerCase();
            state = ['true', '1', 'yes', 'on', ''].includes(v) ? 'true' : ['false', '0', 'no', 'off'].includes(v) ? 'false' : 'unknown';
        }
    }
    return state;
}
// Last value of a value flag. undefined = absent, null = dynamic or missing value.
function valueFlag(rest, names, shortAttached = []) {
    let value;
    for (let i = 0; i < rest.length; i += 1) {
        const a = rest[i];
        if (a.text === null) {
            if (names.some((n) => a.pattern.startsWith(`${n}=`)))
                value = null;
            continue;
        }
        if (a.text === '--')
            break;
        const t = a.text;
        if (names.includes(t)) {
            const v = rest[i + 1];
            value = v ? v.text : null;
            i += 1;
            continue;
        }
        const eq = t.indexOf('=');
        if (eq > 0 && names.includes(t.slice(0, eq))) {
            value = t.slice(eq + 1);
            continue;
        }
        for (const s of shortAttached)
            if (t.startsWith(s) && t.length > s.length && !t.startsWith('--'))
                value = t.slice(s.length);
    }
    return value;
}
function positionals(rest, valueFlags) {
    const vf = new Set(valueFlags);
    const out = [];
    for (let i = 0; i < rest.length; i += 1) {
        const a = rest[i];
        if (a.text === '--') {
            out.push(...rest.slice(i + 1));
            break;
        }
        if (a.text !== null && a.text.startsWith('-') && a.text.length > 1) {
            if (vf.has(a.text))
                i += 1;
            continue;
        }
        out.push(a);
    }
    return out;
}
// camelCase names count too: ProdStack, appProduction.
function isProdName(v) {
    return tables_1.PROD_ENV.test(v) || tables_1.PROD_ENV.test(v.replace(/([a-z0-9])([A-Z])/g, '$1-$2'));
}
function prodValue(v) {
    return v === null || v === '' || (typeof v === 'string' && isProdName(v));
}
function envValue(x, ctx, name) {
    if (x.env.has(name)) {
        const v = x.env.get(name);
        return v && v.length === 1 ? v[0] : null;
    }
    if (ctx.exported.has(name) && ctx.vars.has(name)) {
        const v = ctx.vars.get(name);
        return v && v.length === 1 ? v[0] : null;
    }
    return undefined;
}
// ---------------------------------------------------------------------------------------------
// S1 git
function handleGit(rest, ctx, run, x, cOverrides, aliasDepth) {
    let cwds = ctx.cwds;
    const overrides = new Map(cOverrides);
    let i = 0;
    while (i < rest.length) {
        const a = rest[i];
        const t = a.text;
        if (t === null) {
            worseParse(run, 'dynamic');
            tripwire(rest.slice(i).map(argText).join(' '), run);
            return;
        }
        if (t === '-C') {
            const d = rest[i + 1];
            if (!d || d.text === null)
                cwds = [null];
            else {
                const exp = expandTilde(d.text, run);
                cwds = cwds.map((c) => (exp === null ? null : path.posix.isAbsolute(exp) ? path.posix.normalize(exp) : c ? path.posix.resolve(c, exp) : null));
            }
            i += 2;
            continue;
        }
        if (t === '-c') {
            const kv = rest[i + 1];
            if (!kv || kv.text === null) {
                worseParse(run, 'dynamic');
                tripwire(rest.map(argText).join(' '), run);
                return;
            }
            const eq = kv.text.indexOf('=');
            const key = canonicalGitKey(eq >= 0 ? kv.text.slice(0, eq) : kv.text);
            overrides.set(key, [...(overrides.get(key) || []), eq >= 0 ? kv.text.slice(eq + 1) : 'true']);
            i += 2;
            continue;
        }
        if (t.startsWith('--config-env')) {
            worseParse(run, 'dynamic');
            tripwire(rest.map(argText).join(' '), run);
            return;
        }
        if (['--git-dir', '--work-tree', '--namespace', '--exec-path', '--super-prefix', '--list-cmds', '--attr-source'].includes(t)) {
            i += 2;
            continue;
        }
        if (t.startsWith('-')) {
            i += 1;
            continue;
        }
        break;
    }
    const subArg = rest[i];
    if (!subArg)
        return;
    const sub = subArg.text;
    const args = rest.slice(i + 1);
    const gctx = { ...ctx, cwds };
    if (!tables_1.GIT_BUILTINS.has(sub)) {
        const key = `alias.${sub.toLowerCase()}`;
        let value;
        const fromC = overrides.get(key);
        if (fromC && fromC.length)
            value = fromC[fromC.length - 1];
        else if (ctx.gitAliases.has(sub.toLowerCase()))
            value = ctx.gitAliases.get(sub.toLowerCase());
        else {
            for (const c of cwds) {
                const vals = gitAll(run, ctx, c, `alias.${sub}`);
                if (vals === null) {
                    worseParse(run, 'unparsed');
                    tripwire(rest.map(argText).join(' '), run);
                    return;
                }
                if (vals.length)
                    value = vals[vals.length - 1];
            }
        }
        if (value !== undefined) {
            if (aliasDepth >= tables_1.LIMITS.maxAliasExpansions) {
                worseParse(run, 'unparsed');
                tripwire(`${value} ${args.map(argText).join(' ')}`, run);
                return;
            }
            const restText = args.map((a) => (a.text !== null ? shellQuote(a.text) : '"$__marrow_dynamic"')).join(' ');
            if (value.startsWith('!')) {
                evalShell(`${value.slice(1)} ${restText}`, childCtx(gctx), run);
                return;
            }
            const parsed = shellParse.parseShell(value);
            if (!parsed.ok || parsed.commands.length !== 1) {
                worseParse(run, 'unparsed');
                tripwire(`push ${value} ${restText}`, run);
                return;
            }
            const expanded = parsed.commands[0].words.map((w) => resolveWord(w, ctx, run));
            handleGit([...expanded, ...args], gctx, run, x, overrides, aliasDepth + 1);
            return;
        }
        return;
    }
    switch (sub) {
        case 'push':
        case 'send-pack': return gitPush(args, gctx, run, overrides);
        case 'clean': return gitClean(args, gctx, run);
        case 'config': return gitConfig(args, gctx, run, x, overrides, aliasDepth);
        default: break;
    }
    // Working-tree writes on protected files (git rm --cached and restore --staged only touch the index).
    const indexOnly = args.some((a) => a.text === '--cached' || a.text === '--staged') && !args.some((a) => a.text === '--worktree' || a.text === '-W');
    if (['checkout', 'restore', 'rm', 'mv'].includes(sub) && !indexOnly) {
        for (const a of args)
            if (a.text === null || !a.text.startsWith('-'))
                checkProtectedWrite(a, gctx, run, `git_${sub}`, sub === 'rm' || sub === 'mv');
    }
    if (!tables_1.GIT_S4_EXEMPT_SUBS.has(sub)) {
        // Commit messages are prose, never paths.
        for (let k = 0; k < args.length; k += 1) {
            const t = args[k].text;
            if (t === '-m' || t === '--message' || t === '-F' || t === '--file' || (t !== null && /^-[a-zA-Z]*m$/.test(t))) {
                k += 1;
                continue;
            }
            if (t !== null && /^(?:--message=|-m.)/.test(t))
                continue;
            checkSecretOperand(args[k], gctx, run, 'git_operand');
        }
    }
}
function gitConfig(args, ctx, run, x, overrides, aliasDepth) {
    const vf = new Set(['--file', '-f', '--blob', '--type', '--default', '--comment']);
    const pos = positionals(args, [...vf]);
    if (pos.length < 2 || pos[0].text === null)
        return;
    const key = canonicalGitKey(pos[0].text);
    if (args.some((a) => a.text !== null && /^--(?:get|unset|list|remove|rename)/.test(a.text)))
        return;
    const value = pos[1].text;
    if (value === null) {
        worseParse(run, 'dynamic');
        tripwire(`${pos[0].text} ${argText(pos[1])}`, run);
        return;
    }
    if (key.startsWith('alias.')) {
        const name = key.slice(6).toLowerCase();
        ctx.gitAliases.set(name, value);
        // Classified as if executed (spec A10).
        handleGit([litArg(name)], ctx, run, x, overrides, aliasDepth + 1);
        return;
    }
    ctx.gitConfig.set(key, [...(ctx.gitConfig.get(key) || []), value]);
}
function gitClean(args, ctx, run) {
    const flags = args.filter((a) => a.text !== null && /^-[a-zA-Z]+$/.test(a.text)).map((a) => a.text).join('');
    if (!/[dx]/i.test(flags) && !args.some((a) => a.text === '--force'))
        return;
    for (const c of ctx.cwds) {
        if (!c) {
            hit(run, 'S5', 'git_clean_unknown_dir');
            return;
        }
        checkDeleteTarget(litArg(c), { ...ctx, cwds: [c] }, run, 'git_clean', 'children');
    }
}
function longOption(name, list) {
    if (list.includes(name))
        return [name];
    return list.filter((o) => o.startsWith(name));
}
function gitPush(args, ctx, run, overrides) {
    const risky = new Set();
    let repo = null;
    const refspecs = [];
    let after = false;
    for (let i = 0; i < args.length; i += 1) {
        const a = args[i];
        const t = a.text;
        if (t === null) {
            // A dynamic word can be a force flag or a +refspec: fail closed.
            risky.add('unknown_flag');
            if (!repo)
                repo = a;
            else
                refspecs.push(a);
            continue;
        }
        if (!after && t === '--') {
            after = true;
            continue;
        }
        if (!after && t.startsWith('--')) {
            const name = t.slice(2).split('=')[0];
            const cands = longOption(name, tables_1.GIT_PUSH_LONG);
            for (const c of cands)
                if (tables_1.GIT_PUSH_RISKY_LONG[c])
                    risky.add(tables_1.GIT_PUSH_RISKY_LONG[c]);
            if (cands.length === 1 && cands[0] === 'repo' && t.includes('='))
                repo = litArg(t.slice(t.indexOf('=') + 1));
            if (cands.length === 1 && ['push-option', 'receive-pack', 'exec', 'repo'].includes(cands[0]) && !t.includes('=')) {
                if (cands[0] === 'repo' && args[i + 1])
                    repo = args[i + 1];
                i += 1;
            }
            continue;
        }
        if (!after && t.startsWith('-') && t.length > 1) {
            for (let k = 1; k < t.length; k += 1) {
                const ch = t[k];
                if (ch === 'f')
                    risky.add('force');
                else if (ch === 'd')
                    risky.add('delete');
                else if (ch === 'o') {
                    if (k === t.length - 1)
                        i += 1;
                    break;
                }
            }
            continue;
        }
        if (!repo)
            repo = a;
        else
            refspecs.push(a);
    }
    const cwd = ctx.cwds.length === 1 ? ctx.cwds[0] : null;
    const remoteName = repo ? repo.text : undefined;
    let current = null;
    if (cwd) {
        try {
            current = run.env.git.currentBranch(cwd);
        }
        catch {
            current = null;
        }
    }
    const cfg = (key) => gitAll(run, ctx, cwd, key, overrides) ?? null;
    const last = (vals) => (vals && vals.length ? vals[vals.length - 1] : undefined);
    let remote = remoteName === undefined
        ? (last(current ? cfg(`branch.${current}.pushRemote`) : null) || last(cfg('remote.pushDefault')) || last(current ? cfg(`branch.${current}.remote`) : null) || 'origin')
        : remoteName;
    // Heroku git deploys are S2.
    const remoteUrl = remote ? last(cfg(`remote.${remote}.url`)) : undefined;
    if ((remote && /heroku/i.test(remote)) || (remoteUrl && /heroku\.com/i.test(remoteUrl)))
        hit(run, 'S2', 'git_push_heroku');
    if (remote && /^(?:true|yes|on|1)$/i.test(last(cfg(`remote.${remote}.mirror`)) || ''))
        risky.add('mirror');
    const targets = [];
    let anyForced = false;
    const addTarget = (dst) => {
        if (dst === null) {
            targets.push(null);
            return;
        }
        let d = dst;
        if (d === 'HEAD' || d === '@') {
            targets.push(current);
            return;
        }
        if (d.startsWith('refs/tags/') || d.startsWith('refs/notes/') || d.startsWith('refs/remotes/'))
            return;
        d = d.replace(/^refs\/heads\//, '');
        if (d.includes('*')) {
            targets.push('*');
            return;
        }
        targets.push(d);
    };
    const consumeRefspec = (spec) => {
        let s = spec;
        if (s.startsWith('+')) {
            anyForced = true;
            s = s.slice(1);
        }
        if (risky.has('delete') && !s.includes(':')) {
            addTarget(s);
            return;
        }
        const colon = s.indexOf(':');
        if (colon < 0) {
            addTarget(s);
            return;
        }
        const src = s.slice(0, colon);
        const dst = s.slice(colon + 1);
        if (src === '')
            risky.add('delete');
        if (dst === '') {
            if (src === 'HEAD' || src === '@')
                addTarget(current);
            else
                addTarget(src);
            return;
        }
        addTarget(dst);
    };
    for (const r of refspecs) {
        if (r.text === null) {
            if (r.pattern.startsWith('+'))
                anyForced = true;
            targets.push(null);
            continue;
        }
        consumeRefspec(r.text);
    }
    if (risky.has('mirror') || risky.has('all') || risky.has('prune'))
        targets.push('*');
    if (refspecs.length === 0 && !risky.has('mirror') && !risky.has('all')) {
        const configured = remote ? cfg(`remote.${remote}.push`) : null;
        if (configured === null)
            targets.push(null);
        else if (configured.length)
            for (const spec of configured)
                consumeRefspec(spec);
        else {
            const mode = (last(cfg('push.default')) || 'simple').toLowerCase();
            if (mode === 'matching')
                targets.push('*');
            else if (mode === 'nothing') { /* pushes nothing */ }
            else if (mode === 'upstream' || mode === 'tracking') {
                const merge = current ? last(cfg(`branch.${current}.merge`)) : undefined;
                targets.push(merge ? merge.replace(/^refs\/heads\//, '') : current);
            }
            else
                targets.push(current);
        }
    }
    if (repo && repo.text === null)
        remote = null;
    const forced = anyForced || risky.has('force') || risky.has('unknown_flag');
    const destructive = forced || risky.has('delete') || risky.has('mirror') || risky.has('prune');
    const protectedHit = targets.some((tname) => isProtectedBranch(tname, remote, cwd, run));
    if (destructive && protectedHit) {
        const why = risky.has('delete') ? 'delete' : risky.has('mirror') ? 'mirror' : risky.has('prune') ? 'prune' : 'force';
        hit(run, 'S1', `git_push_${why}_protected_branch`);
        run.flags.add(why === 'delete' ? 'delete' : 'force');
        return;
    }
    if (protectedHit)
        run.flags.add('protected_branch_push');
    if (destructive)
        run.flags.add(risky.has('delete') ? 'delete' : 'force');
}
function isProtectedBranch(name, remote, cwd, run) {
    if (name === null || name === '*' || name === '')
        return true;
    const n = name.toLowerCase();
    if (run.branchRegexes.some((re) => re.test(n) || re.test(name)))
        return true;
    if (!cwd)
        return false;
    for (const r of new Set([remote || 'origin', 'origin'])) {
        let head = null;
        try {
            head = run.env.git.remoteHead(cwd, r);
        }
        catch {
            head = null;
        }
        if (head && head.replace(/^refs\/heads\//, '').toLowerCase() === n)
            return true;
    }
    return false;
}
// ---------------------------------------------------------------------------------------------
// gh
function handleGh(rest, ctx, run) {
    const pos = positionals(rest, ['-R', '--repo', '-X', '--method', '-f', '-F', '--field', '--raw-field', '-H', '--header', '--input', '-q', '--jq', '-t', '--template', '--hostname', '-p', '--preview', '--cache']);
    const sub = pos[0]?.text;
    const sub2 = pos[1]?.text;
    if (sub === 'auth' && sub2 === 'token') {
        hit(run, 'S4', 'gh_auth_token');
        return;
    }
    if (sub === 'auth' && sub2 === 'status' && rest.some((a) => a.text === '-t' || a.text === '--show-token')) {
        hit(run, 'S4', 'gh_auth_show_token');
        return;
    }
    if (sub === 'release' && (sub2 === 'create' || sub2 === 'upload' || sub2 === 'new')) {
        hit(run, 'S3', 'gh_release_publish');
        return;
    }
    if (sub === 'api' && pos[1]?.text === 'graphql') {
        const body = rest.map(argText).join(' ');
        if (/deleteRef|updateRefs?\b[\s\S]*force|force[\s\S]*updateRefs?\b/i.test(body))
            hit(run, 'S1', 'gh_graphql_ref_rewrite');
        return;
    }
    if (sub === 'api') {
        const endpoint = pos[1];
        const method = (valueFlag(rest, ['-X', '--method'], ['-X']) ?? undefined);
        const fields = [];
        for (let i = 0; i < rest.length; i += 1)
            if (['-f', '-F', '--field', '--raw-field'].includes(rest[i].text || '') && rest[i + 1])
                fields.push(rest[i + 1].text ?? 'force=true');
        const hasInput = rest.some((a) => a.text === '--input');
        const m = method === null ? 'UNKNOWN' : (method || (fields.length || hasInput ? 'POST' : 'GET')).toUpperCase();
        if (!endpoint)
            return;
        const ep = endpoint.text;
        if (ep === null) {
            if (/git\/refs/.test(endpoint.pattern) && m !== 'GET')
                hit(run, 'S1', 'gh_api_ref_dynamic');
            return;
        }
        const ref = ep.match(/^\/?repos\/[^/]+\/[^/]+\/git\/refs\/heads\/(.+)$/);
        if (!ref)
            return;
        const forced = fields.some((f) => /^force=(?:true|1)$/i.test(f)) || hasInput || m === 'UNKNOWN';
        if ((m === 'DELETE' || ((m === 'PATCH' || m === 'POST' || m === 'UNKNOWN') && forced)) && isProtectedBranch(ref[1], 'origin', ctx.cwds[0] || null, run)) {
            hit(run, 'S1', m === 'DELETE' ? 'gh_api_delete_protected_ref' : 'gh_api_force_protected_ref');
        }
    }
}
// ---------------------------------------------------------------------------------------------
// package managers (S3 publish, script resolution, npx, S0 uninstall)
const NPM_SUB_ALIASES = {
    'run-script': 'run', rum: 'run', urn: 'run', t: 'test', tst: 'test', i: 'install', in: 'install', ins: 'install', inst: 'install',
    insta: 'install', instal: 'install', isnt: 'install', isnta: 'install', isntal: 'install', isntall: 'install', add: 'install',
    ci: 'ci', 'clean-install': 'ci', ic: 'ci', 'install-clean': 'ci', 'isntall-clean': 'ci', un: 'uninstall', unlink: 'uninstall',
    remove: 'uninstall', rm: 'uninstall', r: 'uninstall', x: 'exec', 'dist-tags': 'dist-tag',
};
const PNPM_BUILTINS = new Set(['add', 'install', 'i', 'update', 'up', 'upgrade', 'remove', 'rm', 'un', 'uninstall', 'link', 'ln', 'unlink', 'import', 'rebuild', 'rb', 'prune', 'fetch', 'patch', 'patch-commit', 'publish', 'pack', 'run', 'exec', 'dlx', 'create', 'test', 't', 'start', 'store', 'list', 'ls', 'outdated', 'why', 'audit', 'licenses', 'deploy', 'env', 'setup', 'init', 'doctor', 'config', 'root', 'bin', 'server', 'recursive', 'ci', 'dedupe', 'help']);
const YARN_BUILTINS = new Set(['add', 'install', 'remove', 'upgrade', 'up', 'info', 'init', 'link', 'unlink', 'list', 'outdated', 'pack', 'publish', 'run', 'test', 'why', 'workspace', 'workspaces', 'global', 'cache', 'config', 'dlx', 'exec', 'npm', 'set', 'version', 'plugin', 'node', 'bin', 'audit', 'check', 'autoclean', 'licenses', 'login', 'logout', 'owner', 'tag', 'team', 'import', 'generate-lock-entry', 'policies', 'dedupe', 'explain', 'constraints', 'patch', 'patch-commit', 'rebuild', 'search', 'stage', 'unplug', 'help']);
const BUN_BUILTINS = new Set(['run', 'test', 'x', 'repl', 'exec', 'install', 'i', 'add', 'a', 'remove', 'rm', 'update', 'outdated', 'link', 'unlink', 'publish', 'patch', 'pm', 'build', 'init', 'create', 'upgrade', 'audit', 'info', 'why']);
function handlePackageManager(prog, rest, ctx, run, x) {
    const vf = ['-w', '--workspace', '--prefix', '-C', '--dir', '--filter', '-F', '--cwd', '--tag', '--access', '--otp', '--registry', '--cache'];
    const pos = positionals(rest, vf);
    const rawSub = pos[0]?.text;
    if (rawSub === null) {
        worseParse(run, 'dynamic');
        tripwire(rest.map(argText).join(' '), run);
        return;
    }
    if (rawSub === undefined) {
        if (prog !== 'npm')
            lifecycleScripts(['preinstall', 'install', 'postinstall', 'prepublish', 'preprepare', 'prepare', 'postprepare'], ctx, run, x);
        return;
    }
    const sub = prog === 'npm' ? (NPM_SUB_ALIASES[rawSub] || rawSub) : rawSub;
    const subIdx = rest.indexOf(pos[0]);
    // yarn workspace <name> <cmd…> / yarn workspaces foreach [opts] <cmd…> / pnpm recursive <cmd…>
    if (prog === 'yarn' && sub === 'workspace' && pos[1])
        return handlePackageManager(prog, rest.slice(rest.indexOf(pos[1]) + 1), ctx, run, x);
    if (prog === 'yarn' && sub === 'workspaces' && pos[1]?.text === 'foreach') {
        const vfw = new Set(['--from', '--include', '--exclude', '-j', '--jobs', '--since']);
        const r2 = rest.slice(rest.indexOf(pos[1]) + 1);
        let k = 0;
        while (k < r2.length && r2[k].text !== null && r2[k].text.startsWith('-'))
            k += vfw.has(r2[k].text) ? 2 : 1;
        return handlePackageManager(prog, r2.slice(k), ctx, run, x);
    }
    if (prog === 'pnpm' && (sub === 'recursive' || sub === 'multi' || sub === 'm'))
        return handlePackageManager(prog, rest.slice(subIdx + 1), ctx, run, x);
    const after = rest.slice(subIdx + 1);
    const global = rest.some((a) => a.text === '-g' || a.text === '--global' || a.text === '--location=global');
    // yarn berry: `yarn npm publish`
    if (prog === 'yarn' && sub === 'npm' && pos[1]?.text === 'publish')
        return publishCheck(after, run, `${prog}_publish`);
    if (sub === 'publish')
        return publishCheck(after, run, `${prog}_publish`);
    if (prog === 'npm') {
        if (sub === 'unpublish') {
            hit(run, 'S3', 'npm_unpublish');
            return;
        }
        if (sub === 'deprecate') {
            hit(run, 'S3', 'npm_deprecate');
            return;
        }
        if (sub === 'dist-tag' && ['add', 'rm', 'set'].includes(pos[1]?.text || '')) {
            hit(run, 'S3', 'npm_dist_tag');
            return;
        }
        if (sub === 'token' && ['list', 'ls', 'create'].includes(pos[1]?.text || 'list')) {
            hit(run, 'S4', 'npm_token');
            return;
        }
    }
    // Removing the Marrow packages globally (S0).
    const removing = ['uninstall', 'remove', 'rm', 'un', 'r'].includes(sub) || (prog === 'yarn' && sub === 'global' && pos[1]?.text === 'remove');
    if (removing && (global || prog === 'yarn') && pos.slice(1).some((a) => a.text === null || /^@getmarrow\//.test(a.text))) {
        hit(run, 'S0', 'uninstall_marrow_package');
        return;
    }
    if (removing && pos.slice(1).some((a) => a.text !== null && /^@getmarrow\//.test(a.text)) && global) {
        hit(run, 'S0', 'uninstall_marrow_package');
        return;
    }
    if (prog === 'npm' && sub === 'exec')
        return npxLike(after, ctx, run, x);
    if (prog === 'pnpm' && (sub === 'dlx' || sub === 'exec'))
        return npxLike(after, ctx, run, x);
    if (prog === 'yarn' && (sub === 'dlx' || sub === 'exec'))
        return npxLike(after, ctx, run, x);
    if (prog === 'bun' && (sub === 'x' || sub === 'exec'))
        return npxLike(after, ctx, run, x);
    if (sub === 'run' || (prog === 'npm' && ['start', 'test', 'stop', 'restart'].includes(sub)) || (prog !== 'npm' && ['start', 'test', 't'].includes(sub))) {
        const name = sub === 'run' ? pos[1] : litArg(sub === 't' ? 'test' : sub);
        if (!name)
            return;
        if (name.text === null) {
            worseParse(run, 'dynamic');
            tripwire(rest.map(argText).join(' '), run);
            return;
        }
        const dd = after.findIndex((a) => a.text === '--');
        const extra = sub === 'run' ? (dd >= 0 ? after.slice(dd + 1) : (prog === 'npm' ? [] : after.slice(after.indexOf(name) + 1))) : (dd >= 0 ? after.slice(dd + 1) : []);
        if (prog === 'bun' && sub === 'run' && /[./]/.test(name.text) && !/^[a-z0-9:_-]+$/i.test(name.text))
            return;
        return runPackageScript(name.text, extra, ctx, run, x, true);
    }
    if (['install', 'ci', 'pack', 'i'].includes(sub) && pos.length === 1) {
        lifecycleScripts(sub === 'pack' ? ['prepack', 'prepare', 'postpack'] : ['preinstall', 'install', 'postinstall', 'prepublish', 'preprepare', 'prepare', 'postprepare'], ctx, run, x);
        return;
    }
    const builtins = prog === 'pnpm' ? PNPM_BUILTINS : prog === 'yarn' ? YARN_BUILTINS : prog === 'bun' ? BUN_BUILTINS : null;
    if (builtins && !builtins.has(sub)) {
        // `pnpm <script>` / `yarn <script>` / `bun <script>`, else a package binary.
        const found = ctx.cwds.map((c) => findPackageJson(ctx, run, c));
        const isScript = found.some((f) => f.pkg && typeof f.pkg.scripts === 'object' && f.pkg.scripts && typeof f.pkg.scripts[sub] === 'string');
        if (isScript)
            return runPackageScript(sub, after, ctx, run, x, prog !== 'bun');
        return dispatch([litArg(sub), ...after], ctx, run, x);
    }
}
function publishCheck(after, run, reason) {
    const dry = boolFlag(after, ['--dry-run'], ['--no-dry-run']);
    if (dry === 'true') {
        run.flags.add('dry_run_final_true');
        return;
    }
    hit(run, 'S3', reason);
}
function handleNpx(rest, ctx, run, x) { npxLike(rest, ctx, run, x); }
function npxLike(rest, ctx, run, x) {
    let pkgFlag = null;
    let i = 0;
    while (i < rest.length) {
        const t = rest[i].text;
        if (t === null)
            break;
        if (t === '--') {
            i += 1;
            break;
        }
        if (t === '-p' || t === '--package') {
            pkgFlag = rest[i + 1] || null;
            i += 2;
            continue;
        }
        if (t.startsWith('--package=')) {
            pkgFlag = litArg(t.slice(10));
            i += 1;
            continue;
        }
        if (t === '-c' || t === '--call') {
            const c = rest[i + 1];
            if (c)
                shellString(c, ctx, run, x.info.subs);
            return;
        }
        if (t.startsWith('-')) {
            i += 1;
            continue;
        }
        break;
    }
    if (pkgFlag && pkgFlag.text !== null && /^@getmarrow\//.test(pkgFlag.text)) {
        hit(run, 'S0', 'npx_marrow_installer');
        return;
    }
    const spec = rest[i];
    if (!spec)
        return;
    if (spec.text === null) {
        worseParse(run, 'dynamic');
        tripwire(rest.map(argText).join(' '), run);
        return;
    }
    const name = spec.text.startsWith('@') ? spec.text.replace(/^(@[^/]+\/[^@]+)(?:@.*)?$/, '$1') : spec.text.replace(/@.*$/, '');
    if (/^@getmarrow\//.test(name)) {
        hit(run, 'S0', 'npx_marrow_installer');
        return;
    }
    const bin = pkgFlag ? (spec.text) : (tables_1.PACKAGE_BINS[name] || name.split('/').pop() || name);
    dispatch([litArg(bin), ...rest.slice(i + 1)], ctx, run, x);
}
// ---------------------------------------------------------------------------------------------
// S3 publish tools
function handlePublishTool(prog, rest, ctx, run) {
    const sub = positionals(rest, [])[0]?.text;
    const stop = (reason) => { hit(run, 'S3', reason); return true; };
    switch (prog) {
        case 'np': return stop('np_publish');
        case 'just':
        case 'task':
        case 'mage':
        case 'rake':
        case 'invoke':
        case 'nx':
        case 'turbo': {
            // Task runners whose recipes are not resolved: a target named like a release or deploy trips.
            for (const a of positionals(rest, ['-f', '--justfile', '-t', '--taskfile', '-d', '--dir', '--filter', '-p', '--project'])) {
                if (a.text === null) {
                    worseParse(run, 'dynamic');
                    continue;
                }
                if (tables_1.NAME_TRIPWIRE.test(a.text)) {
                    nameTripwire(a.text, run, `${prog}_target`);
                }
            }
            return true;
        }
        case 'release-it':
        case 'semantic-release': {
            if (boolFlag(rest, ['--dry-run', '-d'], ['--no-dry-run']) === 'true') {
                run.flags.add('dry_run_final_true');
                return true;
            }
            return stop(`${prog}_publish`);
        }
        case 'changeset':
        case 'changesets': return sub === 'publish' ? stop('changeset_publish') : true;
        case 'lerna': {
            if (sub === 'publish')
                return stop('lerna_publish');
            if (sub === 'exec') {
                const dd = rest.findIndex((a) => a.text === '--');
                if (dd >= 0)
                    dispatch(rest.slice(dd + 1), ctx, run, emptyExec());
                return true;
            }
            if (sub === 'run') {
                const name = positionals(rest, ['--scope', '--ignore'])[1];
                if (name)
                    nameTripwire(argText(name), run, 'lerna_run');
                return true;
            }
            return true;
        }
        case 'cargo': {
            if (sub === 'release')
                return rest.some((a) => a.text === '--execute' || a.text === '-x' || a.text === null) ? stop('cargo_release') : true;
            if (sub !== 'publish')
                return false;
            if (boolFlag(rest, ['--dry-run', '-n'], []) === 'true') {
                run.flags.add('dry_run_final_true');
                return true;
            }
            return stop('cargo_publish');
        }
        case 'twine': return sub === 'upload' ? stop('twine_upload') : true;
        case 'uv':
        case 'poetry': {
            if (sub !== 'publish')
                return false;
            if (boolFlag(rest, ['--dry-run'], []) === 'true') {
                run.flags.add('dry_run_final_true');
                return true;
            }
            return stop(`${prog}_publish`);
        }
        case 'hatch':
        case 'flit': return sub === 'publish' ? stop(`${prog}_publish`) : false;
        case 'gem': return sub === 'push' ? stop('gem_push') : false;
        case 'mvn':
        case 'mvnw':
            return rest.some((a) => a.text === null || a.text === 'deploy' || /^deploy:|^release:perform/.test(a.text)) ? stop('mvn_deploy') : true;
        case 'gradle':
        case 'gradlew':
            return rest.some((a) => a.text === null || (/^(?::[\w-]+)*:?publish/i.test(a.text) && !/publishToMavenLocal$/i.test(a.text))) ? stop('gradle_publish') : true;
        case 'dotnet': return sub === 'nuget' && positionals(rest, [])[1]?.text === 'push' ? stop('nuget_push') : false;
        case 'pod': return sub === 'trunk' && positionals(rest, [])[1]?.text === 'push' ? stop('pod_trunk_push') : false;
        case 'vsce':
        case 'ovsx': return sub === 'publish' ? stop(`${prog}_publish`) : true;
        case 'goreleaser': {
            if (sub !== undefined && sub !== null && sub !== 'release')
                return true;
            if (boolFlag(rest, ['--snapshot'], []) === 'true')
                return true;
            return stop('goreleaser_release');
        }
        default: return false;
    }
}
// ---------------------------------------------------------------------------------------------
// S2 deploy tools
function handleDeployTool(prog, rest, ctx, run, x) {
    const stop = (reason) => { hit(run, 'S2', reason); run.flags.add('prod'); return true; };
    const pos = (vf) => positionals(rest, vf);
    switch (prog) {
        case 'wrangler': {
            const p = pos(['--env', '-e', '--config', '-c', '--name', '--branch', '--project-name', '--compatibility-date', '--outdir', '--var', '--define', '--message', '--tag']);
            const s1 = p[0]?.text;
            const s2 = p[1]?.text;
            if (s1 === null)
                return stop('wrangler_dynamic_subcommand');
            const env = valueFlag(rest, ['--env', '-e']);
            if (s1 === 'deploy' || s1 === 'publish' || (s1 === 'versions' && s2 === 'deploy') || s1 === 'rollback') {
                if (env === undefined || prodValue(env))
                    return stop('wrangler_deploy_production');
                return true;
            }
            if (s1 === 'pages' && (s2 === 'deploy' || s2 === 'publish')) {
                let branch = valueFlag(rest, ['--branch']);
                if (branch === undefined) {
                    let c = null;
                    try {
                        c = ctx.cwds.length === 1 && ctx.cwds[0] ? run.env.git.currentBranch(ctx.cwds[0]) : null;
                    }
                    catch {
                        c = null;
                    }
                    branch = c;
                }
                if (branch === null || isProtectedBranch(branch, 'origin', ctx.cwds[0] || null, run) || tables_1.PROD_ENV.test(branch || ''))
                    return stop('wrangler_pages_production_branch');
                return true;
            }
            return true;
        }
        case 'vercel': {
            const p = pos(['--target', '--scope', '--token', '-t', '--cwd', '-A', '--local-config', '-e', '--env', '-b', '--build-env', '-m', '--meta']);
            const s1 = p[0]?.text;
            if (s1 === 'promote' || s1 === 'rollback')
                return stop(`vercel_${s1}`);
            const deployish = s1 === undefined || s1 === 'deploy' || (s1 !== null && !['dev', 'env', 'pull', 'link', 'login', 'logout', 'ls', 'list', 'inspect', 'logs', 'domains', 'dns', 'certs', 'secrets', 'teams', 'whoami', 'project', 'projects', 'build', 'init', 'help', 'switch', 'alias', 'remove', 'rm', 'bisect', 'git', 'redeploy', 'integration', 'telemetry'].includes(s1));
            const prod = boolFlag(rest, ['--prod', '--production'], []);
            const target = valueFlag(rest, ['--target']);
            if (s1 === 'redeploy' && (prod === 'true' || prod === 'unknown' || (target !== undefined && prodValue(target))))
                return stop('vercel_redeploy_production');
            if (!deployish && s1 !== 'build')
                return true;
            if (s1 === 'build')
                return true;
            if (prod === 'true' || prod === 'unknown' || (target !== undefined && prodValue(target)))
                return stop('vercel_deploy_production');
            return true;
        }
        case 'netlify':
        case 'ntl': {
            const s1 = pos(['--dir', '-d', '--functions', '-f', '--site', '-s', '--auth', '--alias', '-a', '--message', '-m', '--filter', '--context'])[0]?.text;
            if (s1 !== 'deploy')
                return true;
            const prod = boolFlag(rest, ['--prod', '-p', '--prodIfUnlocked', '--prod-if-unlocked'], []);
            if (prod === 'true' || prod === 'unknown')
                return stop('netlify_deploy_production');
            return true;
        }
        case 'fly':
        case 'flyctl': {
            const p = pos(['-a', '--app', '-c', '--config', '-i', '--image', '-r', '--region', '-e', '--env', '--strategy', '--build-arg']);
            if (p[0]?.text === 'deploy' || (p[0]?.text === 'apps' && p[1]?.text === 'destroy'))
                return stop('fly_deploy');
            return true;
        }
        case 'firebase': {
            const p = pos(['--project', '-P', '--only', '--except', '-m', '--message', '--config', '-c', '--token']);
            if (p[0]?.text === 'deploy' || p[0]?.text === null)
                return stop('firebase_deploy');
            return true;
        }
        case 'heroku': {
            const s1 = pos(['-a', '--app', '-r', '--remote'])[0]?.text || '';
            if (s1 === 'auth:token') {
                hit(run, 'S4', 'heroku_auth_token');
                return true;
            }
            if (/^(?:releases:rollback|rollback|container:release|container:push|pipelines:promote|builds:create|deploy|apps:destroy|destroy)$/.test(s1))
                return stop('heroku_deploy');
            return true;
        }
        case 'gcloud': {
            const p = pos(['--project', '--region', '--image', '--source', '--platform', '--account', '--configuration', '--format', '--service-account', '--version', '-q']);
            const s = p.map((a) => a.text);
            if (s[0] === 'auth' && (s[1] === 'print-access-token' || s[1] === 'print-identity-token' || (s[1] === 'application-default' && /^print-/.test(s[2] || '')))) {
                hit(run, 'S4', 'gcloud_print_token');
                return true;
            }
            if (s[0] === 'app' && s[1] === 'deploy')
                return stop('gcloud_app_deploy');
            if ((s[0] === 'run' && (s[1] === 'deploy' || (s[1] === 'services' && ['update', 'replace', 'update-traffic', 'delete'].includes(s[2] || '')))) || (s[0] === 'functions' && (s[1] === 'deploy' || s[1] === 'delete'))) {
                let project = valueFlag(rest, ['--project']);
                if (project === undefined)
                    project = envValue(x, ctx, 'CLOUDSDK_CORE_PROJECT');
                if (project === undefined || prodValue(project))
                    return stop('gcloud_deploy_production');
                return true;
            }
            return true;
        }
        case 'sst': {
            const s1 = pos(['--stage', '--region', '--profile'])[0]?.text;
            if (s1 !== 'deploy' && s1 !== 'remove')
                return true;
            let stage = valueFlag(rest, ['--stage']);
            if (stage === undefined)
                stage = envValue(x, ctx, 'SST_STAGE');
            if (stage === undefined)
                stage = envValue(x, ctx, 'STAGE');
            if (stage === undefined) {
                for (const c of ctx.cwds) {
                    if (!c) {
                        stage = null;
                        break;
                    }
                    const f = safeRead(run.env, path.posix.join(c, '.sst', 'stage'), 4096);
                    if (f !== null)
                        stage = f.trim();
                }
            }
            if (stage !== undefined && prodValue(stage))
                return stop('sst_deploy_production');
            return true;
        }
        case 'serverless':
        case 'sls': {
            const s1 = pos(['--stage', '-s', '--region', '-r', '--config', '-c', '--aws-profile', '--param'])[0]?.text;
            if (s1 !== 'deploy' && s1 !== 'remove' && s1 !== 'rollback')
                return true;
            let stage = valueFlag(rest, ['--stage', '-s']);
            if (stage === undefined)
                stage = envValue(x, ctx, 'SLS_STAGE');
            if (stage === undefined) {
                for (const c of ctx.cwds) {
                    const f = c ? safeRead(run.env, path.posix.join(c, 'serverless.yml'), tables_1.LIMITS.maxScriptBytes) : null;
                    const m = f && f.match(/^\s+stage:\s*['"]?([^'"\s#]+)/m);
                    if (m)
                        stage = /\$\{/.test(m[1]) ? null : m[1];
                }
            }
            if (stage !== undefined && prodValue(stage))
                return stop('serverless_deploy_production');
            return true;
        }
        case 'cdk': {
            const p = pos(['-c', '--context', '--profile', '-a', '--app', '--require-approval', '-o', '--output', '--parameters', '-e', '--exclusively', '--role-arn', '--toolkit-stack-name', '--method', '--concurrency', '--outputs-file']);
            const s1 = p[0]?.text;
            if (s1 !== 'deploy' && s1 !== 'destroy')
                return true;
            const stacks = p.slice(1);
            const contexts = [];
            for (let i = 0; i < rest.length; i += 1)
                if ((rest[i].text === '-c' || rest[i].text === '--context') && rest[i + 1])
                    contexts.push(rest[i + 1].text);
            const profile = valueFlag(rest, ['--profile']);
            if (rest.some((a) => a.text === '--all') || stacks.length === 0 || stacks.some((s) => s.text === null || isProdName(s.text) || /\*/.test(s.text))
                || contexts.some((c) => c === null || tables_1.PROD_ENV.test(c.split('=').slice(1).join('='))) || (profile !== undefined && prodValue(profile)))
                return stop('cdk_deploy_production');
            return true;
        }
        case 'terraform':
        case 'tofu':
        case 'terragrunt': {
            let i = 0;
            let dirs = ctx.cwds;
            while (i < rest.length && rest[i].text !== null && rest[i].text.startsWith('-')) {
                const t = rest[i].text;
                if (t.startsWith('-chdir=')) {
                    const d = t.slice(7);
                    dirs = dirs.map((c) => (c ? path.posix.resolve(c, d) : null));
                }
                i += 1;
            }
            const s1 = rest[i]?.text;
            const args = rest.slice(i + 1);
            if (s1 === 'workspace' && (args[0]?.text === 'select' || args[0]?.text === 'new')) {
                const ws = positionals(args.slice(1), [])[0];
                ctx.tfWorkspace = ws ? ws.text : null;
                return true;
            }
            if (s1 === null)
                return stop('terraform_dynamic_subcommand');
            if (s1 !== 'apply' && s1 !== 'destroy' && s1 !== 'import' && !(s1 === 'state' && ['rm', 'mv', 'push'].includes(args[0]?.text || '')))
                return true;
            const varFiles = [];
            const varValues = [];
            for (let k = 0; k < args.length; k += 1) {
                const a = args[k];
                if (a.text === null) {
                    if (/^-var/.test(a.pattern))
                        varValues.push(null);
                    continue;
                }
                const t = a.text.replace(/^--/, '-');
                if (t === '-var-file' && args[k + 1]) {
                    varFiles.push(args[k + 1].text);
                    k += 1;
                    continue;
                }
                if (t.startsWith('-var-file=')) {
                    varFiles.push(t.slice(10));
                    continue;
                }
                if (t === '-var' && args[k + 1]) {
                    varValues.push(args[k + 1].text);
                    k += 1;
                    continue;
                }
                if (t.startsWith('-var=')) {
                    varValues.push(t.slice(5));
                    continue;
                }
            }
            const planFiles = positionals(args, ['-var', '-var-file', '-target', '-replace', '-state', '-state-out', '-backup', '-lock-timeout', '-parallelism']);
            let workspace = envValue(x, ctx, 'TF_WORKSPACE');
            if (workspace === undefined)
                workspace = ctx.tfWorkspace;
            if (workspace === undefined) {
                for (const d of dirs) {
                    if (!d) {
                        workspace = null;
                        break;
                    }
                    const f = safeRead(run.env, path.posix.join(d, '.terraform', 'environment'), 4096);
                    if (f !== null)
                        workspace = f.trim();
                }
            }
            const envVar = (v) => v === null || (/^\s*(?:env|environment|stage|workspace|tier|deploy_env|target)\s*=/i.test(v) && tables_1.PROD_ENV.test(v.split('=').slice(1).join('=')));
            if (workspace !== undefined && prodValue(workspace))
                return stop('terraform_prod_workspace');
            if (dirs.some((d) => d === null || isProdName(d.split('/').slice(-3).join('/'))))
                return stop('terraform_prod_dir');
            if (varFiles.some((f) => f === null || tables_1.PROD_ENV.test(path.posix.basename(f).replace(/\.tfvars(?:\.json)?$/, '')) || tables_1.PROD_ENV.test(f)))
                return stop('terraform_prod_var_file');
            if (varValues.some(envVar))
                return stop('terraform_prod_var');
            if (planFiles.some((p) => p.text === null || tables_1.PROD_ENV.test(p.text)))
                return stop('terraform_prod_plan');
            return true;
        }
        case 'pulumi': {
            const p = pos(['-s', '--stack', '-C', '--cwd', '--config', '-c', '--target', '-t', '-m', '--message', '--config-file', '--parallel', '-p']);
            const s1 = p[0]?.text;
            if (s1 === 'stack' && p[1]?.text === 'select') {
                ctx.pulumiStack = p[2] ? p[2].text : (valueFlag(rest, ['-s', '--stack']) ?? null);
                return true;
            }
            if (!['up', 'update', 'destroy', 'refresh', 'import'].includes(s1 || '') && s1 !== null)
                return true;
            let stack = valueFlag(rest, ['-s', '--stack']);
            if (stack === undefined)
                stack = envValue(x, ctx, 'PULUMI_STACK');
            if (stack === undefined)
                stack = ctx.pulumiStack === undefined ? null : ctx.pulumiStack;
            if (prodValue(stack))
                return stop('pulumi_production_stack');
            return true;
        }
        case 'eb': return pos(['--profile', '-r', '--region', '-l', '--label', '-m', '--message'])[0]?.text === 'deploy' ? stop('eb_deploy') : true;
        case 'aws': {
            const p = pos(['--profile', '--region', '--output', '--query', '--endpoint-url', '--stack-name', '--template-file', '--parameter-overrides', '--capabilities', '--s3-bucket', '--role-arn']);
            const s = p.map((a) => a.text);
            if (s[0] === 'configure' && s[1] === 'get' && (s[2] === null || /secret|key|token/i.test(s[2] || ''))) {
                hit(run, 'S4', 'aws_configure_get_secret');
                return true;
            }
            if (s[0] === 'configure' && s[1] === 'export-credentials') {
                hit(run, 'S4', 'aws_export_credentials');
                return true;
            }
            if (s[0] === 'sts' && ['get-session-token', 'assume-role', 'get-federation-token'].includes(s[1] || '')) {
                hit(run, 'S4', 'aws_sts_credentials');
                return true;
            }
            if (s[0] === 'cloudformation' && ['deploy', 'update-stack', 'delete-stack', 'create-stack'].includes(s[1] || '')) {
                const stack = valueFlag(rest, ['--stack-name']);
                const profile = valueFlag(rest, ['--profile']);
                if (stack === undefined || prodValue(stack) || (profile !== undefined && prodValue(profile)))
                    return stop('aws_cloudformation_production');
            }
            return true;
        }
        case 'az': {
            const p = pos(['--subscription', '-o', '--output', '--query', '--resource', '--scope', '--tenant', '-t']);
            if (p[0]?.text === 'account' && p[1]?.text === 'get-access-token') {
                hit(run, 'S4', 'az_get_access_token');
                return true;
            }
            return true;
        }
        default: return false;
    }
}
function kubeContextFromConfig(run, ctx, x, explicitConfig) {
    const configs = [];
    if (explicitConfig === null)
        return null;
    if (explicitConfig)
        configs.push(explicitConfig);
    else {
        const envCfg = envValue(x, ctx, 'KUBECONFIG');
        if (envCfg === null)
            return null;
        if (envCfg)
            configs.push(...envCfg.split(':'));
        else
            configs.push(path.posix.join(run.home, '.kube', 'config'));
    }
    for (const c of configs) {
        const abs = absCandidates(c, ctx, run);
        if (!abs)
            return null;
        const content = safeRead(run.env, abs[0], tables_1.LIMITS.maxConfigBytes);
        if (content === null)
            continue;
        const m = content.match(/^current-context:\s*['"]?([^'"\s#]+)/m);
        if (m)
            return m[1];
    }
    return null;
}
function handleKubectl(rest, ctx, run, x) {
    const vf = ['-n', '--namespace', '--context', '--cluster', '--kubeconfig', '-s', '--server', '--user', '-f', '--filename', '-l', '--selector', '-o', '--output', '-c', '--container', '--replicas', '-p', '--patch', '--type', '-k', '--kustomize', '--as', '--token', '--image'];
    const p = positionals(rest, vf);
    const s1 = p[0]?.text;
    if (s1 === 'exec') {
        const dd = rest.findIndex((a) => a.text === '--');
        if (dd >= 0) {
            const inner = rest.slice(dd + 1);
            dispatch(inner, childCtx(ctx, { cwds: [null], remote: true, vars: new Map(), aliases: new Map() }), run, { ...x, env: new Map() });
        }
        return;
    }
    if (s1 === 'config' && p[1]?.text === 'use-context') {
        ctx.kubeContext = p[2] ? p[2].text : null;
        return;
    }
    if (s1 === null) {
        hit(run, 'S2', 'kubectl_dynamic_verb');
        return;
    }
    if (!['apply', 'delete', 'rollout', 'scale', 'replace', 'patch', 'set', 'create', 'edit', 'drain', 'autoscale'].includes(s1 || ''))
        return;
    const ns = valueFlag(rest, ['-n', '--namespace'], ['-n']);
    let context = valueFlag(rest, ['--context']);
    if (context === undefined)
        context = ctx.kubeContext;
    if (context === undefined)
        context = kubeContextFromConfig(run, ctx, x, valueFlag(rest, ['--kubeconfig']));
    if (prodValue(context) || (ns !== undefined && prodValue(ns))) {
        hit(run, 'S2', 'kubectl_production_context');
        run.flags.add('prod');
    }
}
function handleHelm(rest, ctx, run) {
    const vf = ['-n', '--namespace', '--kube-context', '--kubeconfig', '-f', '--values', '--set', '--set-string', '--version', '--repo', '-o', '--output', '--timeout'];
    const p = positionals(rest, vf);
    const s1 = p[0]?.text;
    if (!['install', 'upgrade', 'uninstall', 'delete', 'rollback', 'del', 'un'].includes(s1 || '') && s1 !== null)
        return;
    const ns = valueFlag(rest, ['-n', '--namespace'], ['-n']);
    let context = valueFlag(rest, ['--kube-context']);
    if (context === undefined)
        context = ctx.kubeContext;
    if (context === undefined)
        context = kubeContextFromConfig(run, ctx, emptyExec(), valueFlag(rest, ['--kubeconfig']));
    const valueFiles = [];
    for (let i = 0; i < rest.length; i += 1)
        if ((rest[i].text === '-f' || rest[i].text === '--values') && rest[i + 1])
            valueFiles.push(rest[i + 1].text);
    if (s1 === null || prodValue(context) || (ns !== undefined && prodValue(ns)) || valueFiles.some((f) => f === null || tables_1.PROD_ENV.test(path.posix.basename(f)))) {
        hit(run, 'S2', 'helm_production_context');
        run.flags.add('prod');
    }
}
function emptyExec() {
    return { cmd: { words: [], assignments: [], redirects: [], heredoc: null, heredocDynamic: false, pipedInput: false, pipesOutput: false, background: false, subshell: false }, info: { upstream: [], ansiC: false, subs: [] }, env: new Map() };
}
function handleDocker(rest, ctx, run) {
    // docker [global opts] exec|compose exec|container exec [opts] CONTAINER CMD...
    const globalVf = new Set(['-H', '--host', '--context', '-c', '--config', '-l', '--log-level', '--tlscacert', '--tlscert', '--tlskey']);
    let i = 0;
    while (i < rest.length && rest[i].text !== null && rest[i].text.startsWith('-'))
        i += globalVf.has(rest[i].text) ? 2 : 1;
    const s0 = rest[i]?.text;
    if (s0 === 'compose' || s0 === 'container') {
        i += 1;
        if (s0 === 'compose')
            while (i < rest.length && rest[i].text !== null && rest[i].text.startsWith('-'))
                i += ['-f', '--file', '-p', '--project-name', '--env-file', '--profile'].includes(rest[i].text) ? 2 : 1;
        if (rest[i]?.text !== 'exec' && rest[i]?.text !== 'run')
            return;
    }
    else if (s0 !== 'exec')
        return;
    i += 1;
    const execVf = new Set(['-u', '--user', '-w', '--workdir', '-e', '--env', '--env-file', '--detach-keys', '--index']);
    while (i < rest.length && rest[i].text !== null && rest[i].text.startsWith('-'))
        i += execVf.has(rest[i].text) ? 2 : 1;
    const inner = rest.slice(i + 1);
    if (inner.length)
        dispatch(inner, childCtx(ctx, { cwds: [null], remote: true, vars: new Map(), aliases: new Map() }), run, emptyExec());
    // docker push is out of scope for v1 (owner decision Q2).
}
function handleMarrowCli(rest, run) {
    const sub = positionals(rest, [])[0];
    if (!sub)
        return;
    if (sub.text === null || tables_1.MARROW_OWNER_SUBS.has(sub.text))
        hit(run, 'S0', 'marrow_owner_command');
}
function handleClaudeCli(rest, run) {
    const s = positionals(rest, []).map((a) => a.text);
    if (s[0] === 'plugin' && ['uninstall', 'remove', 'disable', 'rm'].includes(s[1] || '') && (s[2] === null || /marrow/i.test(s[2] || '')))
        hit(run, 'S0', 'claude_plugin_uninstall_marrow');
    if (s[0] === 'mcp' && ['remove', 'rm'].includes(s[1] || '') && (s[2] === null || /marrow/i.test(s[2] || '')))
        hit(run, 'S0', 'claude_mcp_remove_marrow');
}
// ---------------------------------------------------------------------------------------------
// S4 secret dumpers that are separate programs
function handleSecretDumper(prog, rest, run) {
    const s = positionals(rest, ['-a', '-s', '-l', '--vault', '--account', '--format', '-field', '--field', '-mount']).map((a) => a.text);
    const stop = (reason) => { hit(run, 'S4', reason); return true; };
    switch (prog) {
        case 'security':
            if (/^find-(?:generic|internet)-password$/.test(rest[0]?.text || '') && rest.some((a) => a.text === '-w' || a.text === '-g'))
                return stop('keychain_password');
            return true;
        case 'secret-tool': return s[0] === 'lookup' || s[0] === null ? stop('secret_tool_lookup') : true;
        case 'op': return (s[0] === 'read' || (s[0] === 'item' && s[1] === 'get') || s[0] === null) ? stop('op_read') : true;
        case 'vault': return ((s[0] === 'kv' && ['get', 'read'].includes(s[1] || '')) || s[0] === 'read' || s[0] === null) ? stop('vault_read') : true;
        case 'pass': {
            if (s[0] === 'show' || s[0] === null)
                return stop('pass_show');
            if (s[0] && !['ls', 'list', 'find', 'search', 'init', 'insert', 'add', 'edit', 'generate', 'rm', 'remove', 'delete', 'mv', 'rename', 'cp', 'copy', 'git', 'help', 'version', 'grep', 'otp'].includes(s[0]) && !rest.some((a) => a.text === '-c' || a.text === '--clip'))
                return stop('pass_show');
            return true;
        }
        default: return false;
    }
}
// ---------------------------------------------------------------------------------------------
// S5 delete programs
function handleRm(rest, ctx, run) {
    let recursive = false;
    const targets = [];
    let after = false;
    for (const a of rest) {
        if (a.text === null) {
            if (!after && a.pattern.startsWith('-')) {
                recursive = true;
                continue;
            }
            targets.push(a);
            continue;
        }
        if (!after && a.text === '--') {
            after = true;
            continue;
        }
        if (!after && a.text.startsWith('--')) {
            const n = a.text.slice(2);
            if (n.length >= 1 && 'recursive'.startsWith(n))
                recursive = true;
            continue;
        }
        if (!after && a.text.startsWith('-') && a.text.length > 1) {
            if (/[rR]/.test(a.text))
                recursive = true;
            continue;
        }
        targets.push(a);
    }
    if (!recursive)
        return;
    for (const t of targets)
        checkDeleteTarget(t, ctx, run, 'rm_recursive', 'tree');
}
function handleRmdir(rest, ctx, run) {
    if (!rest.some((a) => a.text === '-p' || a.text === '--parents' || (a.text !== null && /^-[a-z]*p/.test(a.text))))
        return;
    for (const t of nonOptions(rest)) {
        checkDeleteTarget(t, ctx, run, 'rmdir_parents', 'tree');
        if (t.text && path.posix.isAbsolute(expandTilde(t.text, run) || ''))
            hit(run, 'S5', 'rmdir_parents_absolute');
    }
}
function handleFind(rest, ctx, run, x) {
    const starts = [];
    let i = 0;
    while (i < rest.length && rest[i].text !== null && /^-[HLP]$|^-O\d$|^-D$/.test(rest[i].text))
        i += rest[i].text === '-D' ? 2 : 1;
    while (i < rest.length) {
        const t = rest[i].text;
        if (t !== null && (t.startsWith('-') || t === '(' || t === '!' || t === ')'))
            break;
        starts.push(rest[i]);
        i += 1;
    }
    if (starts.length === 0)
        starts.push(litArg('.'));
    const expr = rest.slice(i);
    let deletes = false;
    for (let k = 0; k < expr.length; k += 1) {
        const t = expr[k].text;
        if (t === '-delete')
            deletes = true;
        if (t === '-exec' || t === '-execdir' || t === '-ok' || t === '-okdir') {
            const end = expr.findIndex((a, idx) => idx > k && (a.text === ';' || a.text === '+' || a.text === '\\;'));
            const inner = expr.slice(k + 1, end < 0 ? expr.length : end).map((a) => (a.text !== null && a.text.includes('{}') ? dynArg() : a));
            const innerProg = inner[0] ? progName(inner[0], run) : null;
            if (innerProg === 'rm' || innerProg === 'shred' || innerProg === 'unlink' || innerProg === 'rmdir')
                deletes = true;
            // Inner commands run with matched paths as dynamic operands.
            if (innerProg !== 'rm')
                dispatch(inner, ctx, run, x);
            k = end < 0 ? expr.length : end;
        }
    }
    // find … -name .env -exec cat {} : the matched names are secret files read by the inner command.
    const names = [];
    let readerExec = false;
    for (let k = 0; k < expr.length; k += 1) {
        const t = expr[k].text;
        if ((t === '-name' || t === '-iname' || t === '-path' || t === '-ipath' || t === '-wholename') && expr[k + 1])
            names.push(expr[k + 1].text ?? '*');
        if ((t === '-exec' || t === '-execdir' || t === '-ok' || t === '-okdir') && expr[k + 1]) {
            const p = progName(expr[k + 1], run);
            if (p === null || !tables_1.S4_EXEMPT_PROGRAMS.has(p))
                readerExec = true;
        }
    }
    if (readerExec && names.length) {
        const samples = (0, tables_1.secretSamples)(run.home, cwdsList(ctx));
        for (const n of names) {
            const re = patternToRegex(n.replace(/^\*\*\//, ''), false);
            if (samples.some((smp) => (re.test(path.posix.basename(smp)) || re.test(smp)) && isSecretPath(smp, run))) {
                hit(run, 'S4', 'find_exec_secret_name');
                break;
            }
        }
    }
    if (deletes)
        for (const s of starts) {
            checkProtectedWrite(s, ctx, run, 'find_delete', false);
            checkDeleteTarget(s, ctx, run, 'find_delete', 'find');
        }
}
function handleRsync(rest, ctx, run) {
    if (!rest.some((a) => a.text !== null && /^--(?:del|delete(?:-[a-z]+)?|remove-source-files)$/.test(a.text)))
        return;
    const ops = nonOptions(rest, new Set(['-e', '--rsh', '--exclude', '--include', '--filter', '-f', '--files-from', '--port', '--password-file', '--log-file', '--backup-dir', '--suffix', '--chmod', '--chown']));
    const dest = ops[ops.length - 1];
    if (!dest)
        return;
    if (dest.text !== null && /^[^/]*:/.test(dest.text)) {
        hit(run, 'S5', 'rsync_delete_remote');
        return;
    }
    checkDeleteTarget(dest, ctx, run, 'rsync_delete', 'children');
    checkProtectedWrite(dest, ctx, run, 'rsync_delete', true);
}
function handleShred(rest, ctx, run) {
    if (!rest.some((a) => a.text === '-u' || a.text === '--remove' || (a.text !== null && /^-[a-z]*u/.test(a.text))))
        return;
    for (const t of nonOptions(rest, new Set(['-n', '--iterations', '-s', '--size'])))
        checkDeleteTarget(t, ctx, run, 'shred_remove', 'tree');
}
function handleDd(rest, run) {
    for (const a of rest) {
        if (a.text === null) {
            if (a.pattern.startsWith('of='))
                hit(run, 'S5', 'dd_dynamic_device');
            continue;
        }
        if (a.text.startsWith('of=/dev/') && !SAFE_DEVICES.test(a.text.slice(3)))
            hit(run, 'S5', 'dd_device_write');
    }
}
// ---------------------------------------------------------------------------------------------
// Grep tool glob, Edit/Write tool on protected files
function checkGrepGlob(glob, ctx, run) {
    const g = glob.replace(/^\*\*\//, '');
    const re = patternToRegex(g, false);
    const samples = (0, tables_1.secretSamples)(run.home, cwdsList(ctx));
    if (samples.some((s) => re.test(path.posix.basename(s)) && isSecretPath(s, run)))
        hit(run, 'S4', 'tool_grep_glob_secret');
}
const JSON_HOOK_CONFIG = /(?:^|\/)(?:\.claude\/settings(?:\.local)?\.json|\.codex\/hooks\.json|\.cursor\/hooks\.json|\.cursor\/mcp\.json|\.gemini\/settings\.json|\.mcp\.json)$/;
function checkToolWrite(p, tool, input, ctx, run) {
    const abs = absCandidates(p, ctx, run);
    if (!abs) {
        hit(run, 'S0', 'tool_write_unresolved');
        return;
    }
    let isProt = false;
    for (const a of abs)
        for (const r of realCandidates(a, run, true))
            if (run.isProtected(run.fold ? r.toLowerCase() : r))
                isProt = true;
    if (!isProt)
        return;
    const target = abs[0];
    if (!JSON_HOOK_CONFIG.test(target) || tool === 'apply_patch' || tool === 'notebookedit') {
        hit(run, 'S0', 'tool_write_protected_path');
        return;
    }
    const before = safeRead(run.env, target, tables_1.LIMITS.maxConfigBytes);
    let after = null;
    if (tool === 'write' || tool === 'write_file' || tool === 'create_file' || (tool.startsWith('str_replace') && input.command === 'create')) {
        after = typeof input.content === 'string' ? input.content : typeof input.file_text === 'string' ? input.file_text : null;
    }
    else {
        if (before === null) {
            hit(run, 'S0', 'tool_edit_hook_config_unreadable');
            return;
        }
        const edits = Array.isArray(input.edits) ? input.edits : [input];
        after = before;
        for (const e of edits) {
            const oldS = typeof e.old_string === 'string' ? e.old_string : typeof e.old_str === 'string' ? e.old_str : null;
            const newS = typeof e.new_string === 'string' ? e.new_string : typeof e.new_str === 'string' ? e.new_str : null;
            if (oldS === null || newS === null || oldS === '') {
                after = null;
                break;
            }
            if (!after.includes(oldS)) {
                after = null;
                break;
            }
            after = e.replace_all === true ? after.split(oldS).join(newS) : after.replace(oldS, () => newS);
        }
    }
    if (after === null) {
        hit(run, 'S0', 'tool_edit_hook_config_unknown_result');
        return;
    }
    const was = marrowExtract(before === null ? '{}' : before);
    const now = marrowExtract(after);
    if (was === null || now === null || was !== now)
        hit(run, 'S0', 'tool_edit_hook_config_changes_marrow');
}
// The parts of a hook/MCP config that keep Marrow running: hook entries that mention Marrow, any
// other hook switch (disableAllHooks …), Marrow MCP servers and env that the hook runtime reads.
function marrowExtract(text) {
    let json;
    try {
        json = JSON.parse(text);
    }
    catch {
        return null;
    }
    if (!json || typeof json !== 'object' || Array.isArray(json))
        return null;
    const obj = json;
    const out = {};
    const hooks = obj.hooks;
    if (hooks && typeof hooks === 'object') {
        const h = {};
        for (const [event, entries] of Object.entries(hooks)) {
            const list = Array.isArray(entries) ? entries : [entries];
            const kept = list.filter((e) => /marrow/i.test(JSON.stringify(e)));
            if (kept.length)
                h[event] = kept;
        }
        out.hooks = h;
    }
    else if (hooks !== undefined)
        out.hooks = hooks;
    for (const [k, v] of Object.entries(obj))
        if (k !== 'hooks' && /hook/i.test(k))
            out[k] = v;
    const servers = obj.mcpServers;
    if (servers && typeof servers === 'object') {
        const m = {};
        for (const [k, v] of Object.entries(servers))
            if (/marrow/i.test(k) || /marrow/i.test(JSON.stringify(v)))
                m[k] = v;
        out.mcpServers = m;
    }
    const env = obj.env;
    if (env && typeof env === 'object') {
        const e = {};
        for (const [k, v] of Object.entries(env))
            if (/^MARROW_|^NODE_OPTIONS$|^NODE_PATH$|^PATH$|^HOME$/.test(k))
                e[k] = v;
        out.env = e;
    }
    return JSON.stringify(Object.keys(out).sort().map((k) => [k, out[k]]));
}
//# sourceMappingURL=mapper.js.map