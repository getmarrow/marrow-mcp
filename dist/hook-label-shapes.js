"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.commandPositionLabels = commandPositionLabels;
const node_fs_1 = require("node:fs");
const node_path_1 = require("node:path");
const hook_tool_policy_1 = require("./hook-tool-policy");
const normalized_action_1 = require("./normalized-action");
const SWITCHES = { commit: 'MARROW_HOOK_LABEL_COMMIT', dryrun: 'MARROW_HOOK_LABEL_DRYRUN', path: 'MARROW_HOOK_LABEL_PATH' };
const MAX_TEXT = 4000, CONFIG_BYTES = 262_144, MAX_LEVELS = 64;
const BASH_KEYS = new Set(['command', 'description', 'timeout', 'run_in_background']);
const EDIT_TOOLS = new Set(['write', 'edit', 'multiedit']);
const SOURCE_EXTENSIONS = new Set(['py', 'js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'md', 'mdx', 'txt', 'rst', 'go', 'rs', 'java', 'kt', 'rb', 'c', 'h', 'cc',
    'cpp', 'hpp', 'cs', 'swift', 'php', 'css', 'scss', 'html', 'vue', 'svelte']);
/** ON only when unset, empty or exactly `on`; any other value turns the rule (or, for MARROW_HOOK_LABELS, all three) off. */
function labelRuleOn(rule) {
    const on = (name) => { const value = process.env[name]; return value === undefined || value === '' || value === 'on'; };
    return on('MARROW_HOOK_LABELS') && on(SWITCHES[rule]);
}
/** The labels of a call that is WHOLLY one closed shape, else null (keep 3.9.114). A thrown error is null. */
function commandPositionLabels(event, cwd) {
    try {
        return shapeLabels(event, cwd);
    }
    catch {
        return null;
    }
}
function shapeLabels(event, cwd) {
    if (!event || typeof event !== 'object' || Object.getOwnPropertySymbols(event).length)
        return null; // a PowerShell twin carries its dialect
    const record = event;
    const input = record.tool_input;
    if (record.input_truncated !== undefined || !input || typeof input !== 'object' || Array.isArray(input))
        return null;
    const fields = input;
    if (record.tool_name === 'Bash') {
        const command = fields.command;
        if (typeof command !== 'string' || !command.length || command.length > MAX_TEXT || !Object.keys(fields).every((key) => BASH_KEYS.has(key)))
            return null;
        for (let i = 0; i < command.length; i += 1) {
            const code = command.charCodeAt(i);
            if ((code < 0x20 && code !== 0x0a) || code > 0x7e)
                return null;
        }
        // The whole text must also pass the client redactor uncut: a message holding a secret-shaped value keeps 3.9.114.
        const commit = labelRuleOn('commit') && commitShape(command, cwd);
        const dryRun = !commit && labelRuleOn('dryrun') && !command.includes('\n') && dryRunShape(command, cwd);
        return (commit || dryRun) && (0, normalized_action_1.normalizeShellCommand)(command).truncated === false ? { type: 'process', surfaces: commit ? ['github'] : [] } : null;
    }
    if (typeof record.tool_name === 'string' && EDIT_TOOLS.has(record.tool_name.toLowerCase()) && labelRuleOn('path')) {
        const paths = (0, hook_tool_policy_1.toolTargetPaths)(record);
        return paths.length && paths.every((path) => sourcePath(path, cwd)) ? { type: 'process', surfaces: [] } : null;
    }
    return null;
}
/** 1..1024 characters of [A-Za-z0-9._/-] (a char loop: no pattern runs on agent text). */
function isWord(word, digitsOnly = false) {
    if (typeof word !== 'string' || !word.length || word.length > 1024)
        return false;
    for (const char of word) {
        const digit = char >= '0' && char <= '9';
        if (digitsOnly ? !digit : !(digit || (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || '._/-'.includes(char)))
            return false;
    }
    return true;
}
/** A relative path whose components are all plain names: no empty, `.`, `..` or dot-led component (so no dot folder or file). */
function plainComponents(path) {
    return path.split('/').every((part) => part.length > 0 && !part.startsWith('.'));
}
/** `[git add <flags|paths> && ]git commit <flags> -m <M>`, exactly; M a single-quoted, plain double-quoted or quoted here-doc literal. */
function commitShape(command, cwd) {
    let rest = command;
    if (rest.startsWith('git add ')) {
        const end = rest.indexOf(' && ');
        if (end < 0)
            return false;
        const words = rest.slice('git add '.length, end).split(' ');
        for (const word of words) {
            if (['-A', '--all', '-u', '--update'].includes(word))
                continue;
            if (word !== '.' && !(isWord(word) && !word.startsWith('/') && !word.startsWith('-') && plainComponents(word)))
                return false;
            if ((0, hook_tool_policy_1.isSecretPath)(word, cwd) || (0, hook_tool_policy_1.isProtectedWriteTarget)(word, cwd))
                return false;
        }
        rest = rest.slice(end + 4);
    }
    if (!rest.startsWith('git commit '))
        return false;
    rest = rest.slice('git commit '.length);
    const seen = new Set();
    let messages = 0;
    while (rest.length) {
        const space = rest.indexOf(' ');
        const word = space < 0 ? rest : rest.slice(0, space);
        if (word === '-m') {
            const value = rest.slice(3);
            const length = messageLength(value);
            if (length < 0 || (messages += 1) > 1)
                return false;
            rest = value.slice(length);
            if (rest.length && !rest.startsWith(' '))
                return false;
            rest = rest.slice(1);
            if (!rest.length && value.length > length)
                return false; // a trailing space
            continue;
        }
        if (!['-q', '--quiet', '-s', '--signoff', '-a', '--all'].includes(word) || seen.has(word))
            return false;
        seen.add(word);
        rest = space < 0 ? '' : rest.slice(space + 1);
        if (space >= 0 && !rest.length)
            return false;
    }
    return messages === 1;
}
const HEREDOC_OPEN = ['"$(cat <<\'EOF\'\n', '"$(cat <<"EOF"\n'];
const HEREDOC_CLOSE = '\nEOF\n)"';
/** The length of the message word at the start of `text`, or -1 when it is not one of the three literal forms. */
function messageLength(text) {
    const open = HEREDOC_OPEN.find((prefix) => text.startsWith(prefix));
    if (open) {
        const end = text.indexOf(HEREDOC_CLOSE, open.length - 1);
        if (end < 0 || end + HEREDOC_CLOSE.length !== text.length)
            return -1; // nothing after the closing `)"`
        const body = text.slice(open.length, end);
        // A shell that misreads a `)` of the body as the end of `$(` would read the rest in double quotes: none of `"`, `$`, backtick, backslash.
        if (['"', '$', '`', '\\'].some((char) => body.includes(char)))
            return -1;
        return body.split('\n').some((line) => line === 'EOF') ? -1 : text.length;
    }
    const quote = text[0];
    if (quote !== "'" && quote !== '"')
        return -1;
    const end = text.indexOf(quote, 1);
    if (end < 0)
        return -1;
    for (let i = 1; i < end; i += 1) {
        const char = text[i];
        if (char === '\n' || (quote === '"' && (char === '$' || char === '`' || char === '\\' || char === '!')))
            return -1;
    }
    return end + 1;
}
/** `[cd <abs> && ](npx )?wrangler deploy --dry-run [--outdir O] [2>&1] [| tail|head -N]`, the G1 dry-run proof, and a clean config chain. */
function dryRunShape(command, cwd) {
    const words = command.split(' ');
    let at = 0;
    let folder = cwd, changed = false;
    if (words[0] === 'cd') {
        const path = words[1] ?? '';
        if (words[2] !== '&&' || !isWord(path) || !path.startsWith('/') || path.split('/').includes('..'))
            return false;
        folder = path;
        changed = true;
        at = 3;
    }
    if (words[at] === 'npx')
        at += 1;
    if (words[at] !== 'wrangler' || words[at + 1] !== 'deploy')
        return false;
    at += 2;
    let dryRuns = 0, outdirs = 0;
    for (; at < words.length; at += 1) {
        const word = words[at];
        if (word === '--dry-run') {
            dryRuns += 1;
            continue;
        }
        if (word === '--outdir' || word.startsWith('--outdir=')) {
            const value = word === '--outdir' ? words[(at += 1)] : word.slice('--outdir='.length);
            if ((outdirs += 1) > 1 || !outdirPath(value, folder))
                return false;
            continue;
        }
        break;
    }
    if (words[at] === '2>&1')
        at += 1;
    const count = words[at + 2] ?? '';
    if (words[at] === '|' && ['tail', 'head'].includes(words[at + 1]) && count.startsWith('-') && count.length <= 7 && isWord(count.slice(1), true))
        at += 3;
    if (at !== words.length || dryRuns !== 1)
        return false;
    // G1: no other spelling of the flag anywhere (the last flag wins), so the one bare --dry-run is the only one.
    if (words.some((word) => word !== '--dry-run' && (word.toLowerCase().startsWith('--dry') || word.toLowerCase().startsWith('--no-dry'))))
        return false;
    return typeof folder === 'string' && folder.startsWith('/') && cleanConfigChain(folder, changed);
}
function outdirPath(value, folder) {
    if (value === undefined || !isWord(value) || value.startsWith('-'))
        return false;
    const relative = value.startsWith('/tmp/') ? value.slice('/tmp/'.length) : value;
    if (relative.startsWith('/') || !plainComponents(relative))
        return false;
    return !(0, hook_tool_policy_1.isProtectedWriteTarget)(value, folder);
}
/**
 * Wrangler reads its config from the working folder up. Every wrangler.toml, wrangler.json and wrangler.jsonc that exists
 * must be a regular file (not a link) of at most 256 KiB, UTF-8, with no `build` in any case (a configured build runs on a
 * dry run); no .wrangler/deploy/config.json may exist. A folder that does not exist contributes nothing when it is the
 * `cd` target (the chain stops there); any other error fails closed.
 */
function cleanConfigChain(folder, changed) {
    let real;
    try {
        real = (0, node_fs_1.realpathSync)(folder);
    }
    catch (error) {
        return changed && error.code === 'ENOENT';
    }
    for (let level = 0, dir = real; level < MAX_LEVELS; level += 1) {
        for (const name of ['wrangler.toml', 'wrangler.json', 'wrangler.jsonc', (0, node_path_1.join)('.wrangler', 'deploy', 'config.json')]) {
            if (!cleanConfig((0, node_path_1.join)(dir, name), name.startsWith('.')))
                return false;
        }
        const parent = (0, node_path_1.dirname)(dir);
        if (parent === dir)
            return true;
        dir = parent;
    }
    return false;
}
function cleanConfig(path, mustBeAbsent) {
    try {
        (0, node_fs_1.lstatSync)(path);
    }
    catch (error) {
        return error.code === 'ENOENT';
    }
    if (mustBeAbsent || !(0, node_fs_1.lstatSync)(path).isFile())
        return false;
    // No link is followed and no FIFO swapped in after the lstat can block the open.
    const fd = (0, node_fs_1.openSync)(path, node_fs_1.constants.O_RDONLY | node_fs_1.constants.O_NOFOLLOW | node_fs_1.constants.O_NONBLOCK);
    try {
        const stat = (0, node_fs_1.fstatSync)(fd);
        if (!stat.isFile() || stat.size > CONFIG_BYTES)
            return false;
        const bytes = Buffer.alloc(CONFIG_BYTES + 1);
        const length = (0, node_fs_1.readSync)(fd, bytes, 0, bytes.length, 0);
        if (length > CONFIG_BYTES)
            return false;
        const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, length));
        return !text.toLowerCase().includes('build');
    }
    finally {
        (0, node_fs_1.closeSync)(fd);
    }
}
/** A source file the edit tools may name without its words labelling the call. */
function sourcePath(path, cwd) {
    if (path.length > 1024 || !isWord(path) || path.split('/').some((part) => part === '..' || part.startsWith('.')))
        return false;
    const name = path.slice(path.lastIndexOf('/') + 1);
    const dot = name.lastIndexOf('.');
    return dot > 0 && SOURCE_EXTENSIONS.has(name.slice(dot + 1)) && !(0, hook_tool_policy_1.isProtectedWriteTarget)(path, cwd);
}
//# sourceMappingURL=hook-label-shapes.js.map