"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PUBLISH_LIFECYCLE = exports.MAX_MAKE_DEPTH = exports.MAX_MANIFEST_BYTES = exports.MAX_SCRIPT_BYTES = void 0;
exports.resolvePackageScript = resolvePackageScript;
exports.packageCommands = packageCommands;
exports.resolveMakeTargets = resolveMakeTargets;
exports.readScriptFile = readScriptFile;
const seatbelt_path_1 = require("./seatbelt-path");
// Indirect command resolution for S2/S3 (spec §1.2, abuse rows A11/A12):
// package.json scripts, Makefile recipes and script files are read at hook
// time so a harmless-looking name cannot hide a deploy or publish. Anything
// that cannot be read exactly comes back 'unknown'.
exports.MAX_SCRIPT_BYTES = 64 * 1024;
exports.MAX_MANIFEST_BYTES = 1024 * 1024;
exports.MAX_MAKE_DEPTH = 3;
function readResolved(fs, path, maxBytes) {
    const real = (0, seatbelt_path_1.realPath)(fs, path, { followFinal: true });
    if (real.status !== 'resolved')
        return { status: 'unknown', reason: 'unreadable' };
    if (!real.exists)
        return { status: 'absent' };
    try {
        const entry = fs.lstat(real.path);
        if (!entry)
            return { status: 'absent' };
        if (entry.type !== 'file')
            return { status: 'unknown', reason: 'not_file' };
        if (entry.size > maxBytes)
            return { status: 'unknown', reason: 'too_large' };
        const text = fs.readFile(real.path, maxBytes);
        return text === null ? { status: 'unknown', reason: 'too_large' } : { status: 'ok', text, path: real.path };
    }
    catch {
        return { status: 'unknown', reason: 'unreadable' };
    }
}
function parentOf(dir) {
    if (dir === '/')
        return null;
    return dir.slice(0, dir.lastIndexOf('/')) || '/';
}
/**
 * The commands `npm|pnpm|yarn|bun run <name>` executes: pre<name>, <name>,
 * post<name>, from the nearest package.json at or above dir (npm's prefix).
 * A missing script is 'absent' (the runner fails); a malformed manifest is unknown.
 */
function resolvePackageScript(fs, dir, name) {
    return packageCommands(fs, dir, [`pre${name}`, name, `post${name}`]);
}
/** Lifecycle scripts `npm publish` runs (S3 "lifecycle prepublish*"). */
exports.PUBLISH_LIFECYCLE = ['prepublish', 'prepare', 'prepublishOnly', 'prepack', 'postpack', 'publish', 'postpublish'];
function packageCommands(fs, dir, names) {
    let current = dir;
    while (current) {
        const read = readResolved(fs, current === '/' ? '/package.json' : `${current}/package.json`, exports.MAX_MANIFEST_BYTES);
        if (read.status === 'unknown')
            return { status: 'unknown', reason: read.reason };
        if (read.status === 'ok') {
            let manifest;
            try {
                manifest = JSON.parse(read.text);
            }
            catch {
                return { status: 'unknown', reason: 'malformed' };
            }
            if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest))
                return { status: 'unknown', reason: 'malformed' };
            const scripts = manifest.scripts;
            if (scripts !== undefined && (typeof scripts !== 'object' || scripts === null || Array.isArray(scripts)))
                return { status: 'unknown', reason: 'malformed' };
            const table = (scripts || {});
            const commands = [];
            for (const name of names) {
                if (!Object.prototype.hasOwnProperty.call(table, name))
                    continue;
                const command = table[name];
                if (typeof command !== 'string')
                    return { status: 'unknown', reason: 'malformed' };
                commands.push({ name, command });
            }
            return { status: 'ok', packageDir: current, commands };
        }
        current = parentOf(current);
    }
    return { status: 'absent' };
}
const MAKEFILE_NAMES = ['GNUmakefile', 'makefile', 'Makefile'];
/**
 * A simple Makefile recipe parse: explicit rules, recipe lines, prerequisites
 * (depth ≤3) and `$(VAR)`/`${VAR}` from simple assignments or the command
 * line. `include`, conditionals, pattern rules or an unknown variable make
 * the answer dynamic, which the mapper treats like an unknown script.
 */
function resolveMakeTargets(fs, dir, targets, options = {}) {
    let read = { status: 'absent' };
    if (options.makefile)
        read = readResolved(fs, options.makefile.startsWith('/') ? options.makefile : `${dir}/${options.makefile}`, exports.MAX_MANIFEST_BYTES);
    else {
        for (const name of MAKEFILE_NAMES) {
            read = readResolved(fs, `${dir}/${name}`, exports.MAX_MANIFEST_BYTES);
            if (read.status !== 'absent')
                break;
        }
    }
    if (read.status !== 'ok')
        return read.status === 'absent' ? read : { status: 'unknown', reason: read.reason };
    const variables = {};
    const rules = new Map();
    let firstTarget = null;
    let dynamic = false;
    let current = [];
    const lines = read.text.replace(/\\\r?\n/g, ' ').split(/\r?\n/);
    for (const line of lines) {
        if (line.startsWith('\t')) {
            for (const rule of current)
                rule.recipe.push(line.slice(1));
            continue;
        }
        const trimmed = line.replace(/#.*$/, '').trim();
        if (!trimmed)
            continue;
        if (/^(-?include|sinclude|ifeq|ifneq|ifdef|ifndef|else|endif|define|endef|export|vpath)\b/.test(trimmed)) {
            dynamic = true;
            current = [];
            continue;
        }
        const assign = /^(?:override\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*(\?=|:::=|::=|:=|\+=|!=|=)\s*(.*)$/.exec(trimmed);
        if (assign) {
            const [, name, op, value] = assign;
            if (op === '!=')
                dynamic = true;
            else if (op === '+=')
                variables[name] = `${variables[name] ?? ''} ${value}`.trim();
            else if (op !== '?=' || variables[name] === undefined)
                variables[name] = value;
            current = [];
            continue;
        }
        const rule = /^([^:=]+?)\s*::?\s*([^=]*)$/.exec(trimmed);
        if (!rule) {
            dynamic = true;
            current = [];
            continue;
        }
        const names = rule[1].split(/\s+/).filter(Boolean);
        let prereqs = rule[2];
        let inlineRecipe = null;
        const semi = prereqs.indexOf(';');
        if (semi >= 0) {
            inlineRecipe = prereqs.slice(semi + 1).trim();
            prereqs = prereqs.slice(0, semi);
        }
        current = [];
        for (const name of names) {
            if (name.includes('%'))
                dynamic = true;
            if (name.startsWith('.'))
                continue;
            if (firstTarget === null && !name.includes('%'))
                firstTarget = name;
            const entry = rules.get(name) || { prerequisites: [], recipe: [] };
            entry.prerequisites.push(...prereqs.split(/\s+/).filter((p) => p && p !== '|'));
            if (inlineRecipe)
                entry.recipe.push(inlineRecipe);
            rules.set(name, entry);
            current.push(entry);
        }
    }
    const values = { ...variables, ...(options.overrides || {}) };
    const expand = (text, depth = 0) => text.replace(/\$(?:\(([^()]*)\)|\{([^{}]*)\}|([A-Za-z@<^*?%$]))/g, (match, a, b, c) => {
        const name = (a ?? b ?? c);
        if (name === '$')
            return '$';
        if (/^[@<^*?%]$/.test(name) || /\s/.test(name) || depth > 8 || values[name] === undefined) {
            if (!/^[@<^*?%]$/.test(name))
                dynamic = true;
            return match;
        }
        return expand(values[name], depth + 1);
    });
    const commands = [];
    const visit = (target, depth, seen) => {
        if (seen.has(target))
            return;
        seen.add(target);
        const rule = rules.get(target);
        if (!rule)
            return;
        if (depth < exports.MAX_MAKE_DEPTH)
            for (const prerequisite of rule.prerequisites)
                visit(expand(prerequisite), depth + 1, seen);
        else if (rule.prerequisites.length > 0)
            dynamic = true;
        for (const line of rule.recipe)
            commands.push(expand(line).replace(/^[\s@+-]+/, ''));
    };
    const wanted = targets.length > 0 ? targets : firstTarget ? [firstTarget] : [];
    for (const target of wanted)
        visit(target, 0, new Set());
    return { status: 'ok', makefile: read.path, commands, dynamic: dynamic || wanted.some((t) => !rules.has(t)) };
}
/** A script file run as `./x.sh` or `bash x.sh` (≤64 KB), realpath-ed; the interpreter comes from the shebang. */
function readScriptFile(fs, path) {
    const read = readResolved(fs, path, exports.MAX_SCRIPT_BYTES);
    if (read.status !== 'ok')
        return read;
    const shebang = /^#!\s*(\S+)(?:\s+(\S+))?/.exec(read.text);
    let program = shebang ? shebang[1].split('/').pop() || '' : 'sh';
    if (program === 'env' && shebang?.[2])
        program = shebang[2];
    const interpreter = /^(sh|bash|zsh|dash|ksh|ash)$/.test(program) ? 'shell' : 'other';
    return { status: 'ok', path: read.path, interpreter, text: read.text };
}
//# sourceMappingURL=seatbelt-scripts.js.map