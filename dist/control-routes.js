"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CONTROL_ROUTE_ASK_TEXT = exports.CONTROL_ROUTE_DENY_TEXT = void 0;
exports.wrapperOptionTakesValue = wrapperOptionTakesValue;
exports.controlRoute = controlRoute;
const hook_tool_policy_1 = require("./hook-tool-policy");
/**
 * MCP-10: the visible ways to switch Marrow's local control off or remove it through the installer. A command that runs the installer
 * (`npx @getmarrow/install ...`, `marrow-install ...`, `node .../@getmarrow/install/bin/marrow-install.js ...`) with a `control` word other
 * than `enable`/`status`, with `disable` or `uninstall`, or with any argument the shell expands, is a control-off route. The agent's own
 * `--yes` approves nothing: such a command is labelled `security on marrow-control` and held for the account owner.
 */
exports.CONTROL_ROUTE_DENY_TEXT = 'Turning Marrow control off needs the account owner. Ask them to run it in their own terminal.';
const INSTALLER_PACKAGE = /(?:^|=)@getmarrow\/install(?:@[^\s/]*)?$/i;
const INSTALLER_BIN = /(?:^|\/)marrow-install(?:\.[cm]?js)?$/i;
const INSTALLER_PATH = /@getmarrow\/install\//i;
const WRAPPER = /^(?:sudo|env|nohup|time|exec|command|builtin|nice|ionice|stdbuf|timeout|xargs|setsid)$/;
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const SHELL_PROGRAM = /^(?:sh|bash|zsh|dash|ksh)$/;
// Programs that can run an installer package or file: a grep, a cat or a commit message that merely names it is not a route.
const RUNNER = /^(?:npx|pnpx|bunx|npm|pnpm|yarn|bun|node|nodejs|deno|corepack)$/;
const SAFE_CONTROL_SUBCOMMAND = new Set(['enable', 'status']);
exports.CONTROL_ROUTE_ASK_TEXT = 'Marrow: this would switch Marrow control off or change its hooks. Approve it only if you, the account owner, want that.';
const CONTROL_ROUTE_BUDGET_MS = 250;
const GUARDED_TEXT = /@getmarrow\/(?:install|mcp)|marrow-(?:install|mcp)|MARROW_AUTO_HOOK/i;
const MCP_MARKER = /(?:^|=)@getmarrow\/mcp(?:@[^\s/]*)?$|(?:^|\/)marrow-mcp$|@getmarrow\/mcp\//i;
// T1: wrapper options that take an argument consume it (`env -u NAME`, `sudo -u USER`, `timeout -s SIGNAL`); the normalizer reads the same table.
const WRAPPER_VALUE_OPTIONS = {
    env: ['-u', '--unset', '-C', '--chdir', '-S', '--split-string'], doas: ['-u', '-C'], exec: ['-a'], nice: ['-n', '--adjustment'], timeout: ['-s', '-k', '--signal', '--kill-after'],
    sudo: ['-u', '-g', '-h', '-p', '-C', '-D', '-r', '-t', '-U', '-R', '-T', '--user', '--group', '--host', '--prompt', '--close-from', '--chdir', '--role', '--type', '--other-user', '--chroot', '--command-timeout'],
    ionice: ['-c', '-n', '-p', '-P', '-u', '--class', '--classdata', '--pid', '--pgid', '--uid'], stdbuf: ['-i', '-o', '-e', '--input', '--output', '--error'],
    xargs: ['-I', '-n', '-P', '-L', '-d', '-s', '-a', '-E', '--max-args', '--max-procs', '--max-lines', '--delimiter', '--max-chars', '--arg-file', '--eof'],
};
// Wrappers whose first plain word is a value (`timeout 240`, `chrt 5`, `taskset 3`); proven readers, whose words are text, never run.
const POSITIONAL_VALUE = /^(?:timeout|chrt|taskset)$/;
const READER = /^(?:echo|printf|grep|egrep|fgrep|rg|cat|head|tail|less)$/;
const RUN_CAPABLE = /^(?:npx|pnpx|bunx|npm|pnpm|yarn|bun|node|nodejs|deno|corepack|sh|bash|zsh|dash|ksh|eval|exec|xargs|watch|flock|script|su|runuser|ssh|parallel|unbuffer|setsid|nohup|chrt|taskset|doas|sudo|env|timeout|nice|ionice|stdbuf|time|command|builtin)$/;
const PACKAGE_MANAGER = /^(?:npm|pnpm|yarn|bun)$/;
const NOT_RUN_VERB = /^(?:install|i|add|ci|view|info|show|v|ls|list|outdated|why|pack|uninstall|remove|rm|un|update|upgrade|audit|docs|home|repo|search)$/;
const INSTALLER_SAFE = /^(?:doctor|status|help|version)$/;
const INSTALLER_ROUTE_FLAG = /^--?(?:disable|uninstall|setup|update|repair|off|reset|remove|install\w*|hooks?\w*)(?:=|$)/i;
const MCP_SAFE = /^(?:drain-spool|spool-status|seatbelt-status|ping|help|h|version|(?:(?:claude|cline|codex|cursor|gemini|grok|windsurf)-)?(?:pre-action-|context-|session-|permission-request-)?hook)$/;
const installerMarker = (word) => INSTALLER_PACKAGE.test(word) || INSTALLER_BIN.test(word) || INSTALLER_PATH.test(word);
/** Whether a wrapper option takes the next word as its argument (T1). */
function wrapperOptionTakesValue(wrapper, option) {
    return WRAPPER_VALUE_OPTIONS[wrapper]?.includes(option) ?? false;
}
function baseName(word) {
    const cut = word.lastIndexOf('/');
    return cut < 0 ? word : word.slice(cut + 1);
}
function installerArguments(words) {
    const marker = words.findIndex((word) => INSTALLER_PACKAGE.test(word) || INSTALLER_BIN.test(word) || INSTALLER_PATH.test(word));
    return marker < 0 ? null : words.slice(marker + 1);
}
function routeArguments(args, segment) {
    if (segment.expansions.length > 0 || args.some((arg) => /[$`*?[~]/.test(arg)))
        return true;
    if (args.some((arg) => /^-{0,2}(?:disable|uninstall)$/i.test(arg)))
        return true;
    const control = args.findIndex((arg) => arg.toLowerCase() === 'control');
    if (control < 0)
        return false;
    const subcommands = args.slice(control + 1).filter((arg) => !arg.startsWith('-')).map((arg) => arg.toLowerCase());
    return !(subcommands.length > 0 && subcommands.every((arg) => SAFE_CONTROL_SUBCOMMAND.has(arg)));
}
function segmentIsRoute(segment, depth) {
    let at = 0;
    while (at < segment.words.length && ASSIGNMENT.test(segment.words[at]))
        at += 1;
    while (at < segment.words.length && WRAPPER.test(baseName(segment.words[at]))) {
        at += 1;
        while (at < segment.words.length && (segment.words[at].startsWith('-') || ASSIGNMENT.test(segment.words[at]) || /^\d+$/.test(segment.words[at])))
            at += 1;
    }
    const words = segment.words.slice(at);
    if (!words.length)
        return false;
    if (SHELL_PROGRAM.test(baseName(words[0]))) {
        const flag = words.findIndex((word, index) => index > 0 && /^-[A-Za-z]*c[A-Za-z]*$/.test(word));
        if (flag > 0 && words[flag + 1] !== undefined)
            return controlRoute(words[flag + 1], depth + 1);
    }
    const program = words[0];
    const runs = RUNNER.test(baseName(program)) || INSTALLER_BIN.test(program) || INSTALLER_PATH.test(program) || /[$`]/.test(program);
    const args = runs ? installerArguments(words) : null;
    return args !== null && routeArguments(args, segment);
}
/** The words after a marker, past the bin names and `--` that follow it (`npx --package=@getmarrow/mcp marrow-mcp setup`). */
function afterMarker(words, marker, family) {
    let at = marker + 1;
    while (at < words.length && (words[at] === '--' || family(words[at])))
        at += 1;
    return words.slice(at);
}
function installerHeld(args, segment, depth, deadline, bare) {
    if (segment.expansions.length > 0 || args.some((arg) => /[$`*?[~]/.test(arg) || INSTALLER_ROUTE_FLAG.test(arg)))
        return true;
    const plain = args.filter((arg) => !arg.startsWith('-')).map((arg) => arg.toLowerCase());
    if (!plain.length)
        return bare && !args.some((arg) => /^--?(?:version|help|v|h)$/.test(arg));
    if (plain[0] === 'run')
        return segmentHeld({ ...segment, words: afterMarker(args, args.findIndex((arg) => arg.toLowerCase() === 'run'), () => false) }, depth + 1, deadline);
    if (plain[0] === 'control')
        return !(plain.length > 1 && plain.slice(1).every((arg) => SAFE_CONTROL_SUBCOMMAND.has(arg)));
    return !plain.every((arg) => INSTALLER_SAFE.test(arg));
}
function mcpHeld(args, segment) {
    if (segment.expansions.length > 0 || args.some((arg) => /[$`*?[~]/.test(arg)))
        return true;
    return args.some((arg) => !MCP_SAFE.test(arg.replace(/^--?/, '').replace(/=[^]*$/, '').toLowerCase()));
}
// T1: wrapper options consume their arguments; running the installer or marrow-mcp with a subcommand not proven safe is a route unless the
// program is a proven reader, and so is `MARROW_AUTO_HOOK` set for a program or exported.
function segmentHeld(segment, depth, deadline) {
    if (Date.now() > deadline)
        throw new Error('control route budget spent');
    const all = segment.words;
    let at = 0;
    while (at < all.length && ASSIGNMENT.test(all[at]))
        at += 1;
    let certain = true;
    let splitString = false;
    let xargs = false;
    while (at < all.length && (WRAPPER.test(baseName(all[at])) || /^(?:doas|chrt|taskset)$/.test(baseName(all[at])))) {
        const wrapper = baseName(all[at]);
        xargs ||= wrapper === 'xargs';
        at += 1;
        for (; at < all.length && (all[at].startsWith('-') || ASSIGNMENT.test(all[at])); at += 1) {
            if (all[at] === '--') {
                at += 1;
                break;
            }
            splitString ||= wrapper === 'env' && /^(?:-S|--split-string)/.test(all[at]);
            if (wrapperOptionTakesValue(wrapper, all[at]))
                at += 1;
            else if (all[at].startsWith('-'))
                certain = false;
        }
        if (POSITIONAL_VALUE.test(wrapper) && at < all.length)
            at += 1;
    }
    if (all.slice(0, at).some((word) => /^MARROW_AUTO_HOOK=/.test(word)))
        return true;
    if (splitString && GUARDED_TEXT.test(all.join(' ')))
        return true;
    const words = all.slice(at);
    if (!words.length)
        return false;
    const program = baseName(words[0]);
    if (/^(?:export|declare|typeset|readonly|local)$/.test(program) && words.some((word) => /^MARROW_AUTO_HOOK(?:=|$)/.test(word)))
        return true;
    if (certain && (READER.test(program) || (program === 'git' && /^(?:commit|log|show|grep)$/.test(words[1] ?? ''))
        || (program === 'gh' && /^(?:pr|issue)$/.test(words[1] ?? '') && /^(?:create|comment|edit)$/.test(words[2] ?? ''))))
        return false;
    const runs = (marker) => marker === 0 || all.slice(0, at + marker).some((word) => RUN_CAPABLE.test(baseName(word)) || /[$`]/.test(word));
    const notRun = PACKAGE_MANAGER.test(program) && NOT_RUN_VERB.test(words.slice(1).find((word) => !word.startsWith('-')) ?? '');
    const installer = words.findIndex(installerMarker);
    const mcp = words.findIndex((word) => MCP_MARKER.test(word));
    if (xargs && (installer >= 0 || mcp >= 0))
        return true;
    if (!notRun && installer >= 0 && (runs(installer) || depth > 0)
        && installerHeld(afterMarker(words, installer, installerMarker), segment, depth, deadline, runs(installer)))
        return true;
    if (!notRun && mcp >= 0 && (runs(mcp) || depth > 0) && mcpHeld(afterMarker(words, mcp, (word) => MCP_MARKER.test(word)), segment))
        return true;
    // A runner fed a variable where the text names the installer (`I=@getmarrow/install; npx $I control disable`) cannot be read as one command.
    if (installer < 0 && mcp < 0 && (RUN_CAPABLE.test(program) || /[$`]/.test(words[0])) && (segment.expansions.length > 0 || words.some((word) => /[$`]/.test(word))))
        return true;
    // Shell text carried as one word (`bash -c "..."`, `eval "..."`, `su -c "..."`) is judged as a command of its own.
    return words.some((word) => GUARDED_TEXT.test(word) && /[\s;&|()<>$`]/.test(word) && controlRoute(word, depth + 1, deadline));
}
/** Whether the shell text can switch Marrow control off or remove it (installer, marrow-mcp, MARROW_AUTO_HOOK), or cannot be read as one fixed
 * command: text naming them that the parser cannot read, that nests deeper than 3 or that spends the time budget is held (T1). */
function controlRoute(command, depth = 0, deadline = Date.now() + CONTROL_ROUTE_BUDGET_MS) {
    try {
        if (typeof command !== 'string' || !GUARDED_TEXT.test(command))
            return false;
        if (depth > 3 || Date.now() > deadline)
            return true;
        const segments = (0, hook_tool_policy_1.parseShellSegments)(command);
        if (!segments)
            return true;
        return segments.some((segment) => segmentIsRoute(segment, depth) || segmentHeld(segment, depth, deadline));
    }
    catch {
        return true;
    }
}
//# sourceMappingURL=control-routes.js.map