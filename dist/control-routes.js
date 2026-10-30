"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CONTROL_ROUTE_DENY_TEXT = void 0;
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
const INSTALLER_TEXT = /@getmarrow\/install|marrow-install/i;
const WRAPPER = /^(?:sudo|env|nohup|time|exec|command|builtin|nice|ionice|stdbuf|timeout|xargs|setsid)$/;
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;
const SHELL_PROGRAM = /^(?:sh|bash|zsh|dash|ksh)$/;
// Programs that can run an installer package or file: a grep, a cat or a commit message that merely names it is not a route.
const RUNNER = /^(?:npx|pnpx|bunx|npm|pnpm|yarn|bun|node|nodejs|deno|corepack)$/;
const SAFE_CONTROL_SUBCOMMAND = new Set(['enable', 'status']);
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
/** Whether the shell text runs the installer in a way that can switch Marrow control off, remove it, or cannot be read as one fixed command. */
function controlRoute(command, depth = 0) {
    try {
        if (typeof command !== 'string' || !INSTALLER_TEXT.test(command))
            return false;
        if (depth > 3)
            return true;
        const segments = (0, hook_tool_policy_1.parseShellSegments)(command);
        // A command the parser cannot read that names the installer next to a control word is held, never guessed at.
        if (!segments)
            return /control|disable|uninstall|[$`]/i.test(command);
        return segments.some((segment) => segmentIsRoute(segment, depth));
    }
    catch {
        return true;
    }
}
//# sourceMappingURL=control-routes.js.map