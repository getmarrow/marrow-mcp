"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SETUP_UNCONFIRMED_TEXT = exports.CLAIMED_NO_KEY_TEXT = exports.HOOK_BUDGET_MS = exports.SEATBELT_ROLLOUT = void 0;
exports.seatbeltStopText = seatbeltStopText;
exports.accountFloorStops = accountFloorStops;
exports.hostMapperFs = hostMapperFs;
exports.hostSeatbeltGit = hostSeatbeltGit;
exports.keylessSeatbelt = keylessSeatbelt;
exports.seatbeltStatus = seatbeltStatus;
exports.accountFloor = accountFloor;
exports.outageRisk = outageRisk;
const fallback_copy_1 = require("./fallback-copy");
/**
 * Compiled-in rollout table. Not env, not a file: changing a value is a one-line, reviewed code
 * change. `keyless: 'off'` makes every keyless machine `claimed_no_key` (3.9.103 holds plus the
 * floor). `account_floor: 'on'` enforces the S0-S5 floor before the server flow.
 */
exports.SEATBELT_ROLLOUT = Object.freeze({
    keyless: 'on',
    account_floor: 'watch',
});
/** One wall-clock budget for the whole seatbelt path (mode resolution and mapper). Over it: stop. */
exports.HOOK_BUDGET_MS = 300;
exports.CLAIMED_NO_KEY_TEXT = 'Marrow is linked to an account but has no working key; owner: run `npx -y @getmarrow/install@latest doctor`.';
/**
 * `claimed_no_key` with no account evidence and no rejected key: a fallback because the machine's
 * setup could not be confirmed (an evidence dir others can write, an unreadable probe, a home
 * mismatch, strict mode). Same holds as CLAIMED_NO_KEY_TEXT, but it never claims an account exists.
 * This constant is the generic wording; a hold names its reason (setupUnconfirmedText, fallback-copy.ts).
 */
exports.SETUP_UNCONFIRMED_TEXT = (0, fallback_copy_1.setupUnconfirmedText)(fallback_copy_1.FALLBACK_OTHER);
const LABELS = {
    S0: 'a change to Marrow seatbelt settings or an owner-only command',
    S1: 'force-push or delete of a protected branch',
    S2: 'production deploy',
    S3: 'package publish',
    S4: 'reading, copying or writing secrets (like .env files or private keys)',
    S5: 'recursive delete outside the workspace',
    Sx: 'obfuscated execution',
    hook: 'a safety check that could not finish',
};
const CODE = /^[A-Za-z0-9_.:-]{1,64}$/;
function codes(list) {
    return Array.isArray(list) ? list.filter((item) => typeof item === 'string' && CODE.test(item)).slice(0, 16) : [];
}
/** What the agent and the person read after the label, in every stop. */
const STOP_ADVICE = 'If you (the person at this machine) meant it, run it yourself in your own terminal. Agent: do not retry it another way and do not edit Marrow settings; tell the user it was stopped.';
/** Keyless (no account): the way to approval prompts. The plugin path is the one the plugin's own docs give. */
const KEYLESS_KEY_ADVICE = 'For approval prompts instead of stops, add a Marrow key: getmarrow.ai/docs#start-here (Claude Code plugin: put MARROW_API_KEY in ~/.marrow/env, chmod 600, then /reload-plugins).';
/** The label of a stop. A script Marrow could not read is named as such: it is not known to be what its name says. */
function stopLabel(category, reason) {
    const label = LABELS[category] || LABELS.hook;
    return reason === 'script_unreadable' ? `a script Marrow could not read (treated as ${label})` : label;
}
/** `modeReason`: the fixed code that explains a fallback (pickFallbackReason); only read when the machine is not account-linked. */
function seatbeltStopText(category, rule, reason, mode, accountLinked = true, modeReason) {
    const head = `MARROW SEATBELT stopped this action: ${stopLabel(category, reason)}. ${STOP_ADVICE}`;
    const code = `Code: ${CODE.test(rule) ? rule : 'unknown'}/${CODE.test(reason) ? reason : 'unknown'}`;
    if (mode === 'account')
        return `${head} ${code}.`;
    if (mode === 'seatbelt')
        return `${head} ${KEYLESS_KEY_ADVICE} ${code}.`;
    return accountLinked
        ? `${head} ${exports.CLAIMED_NO_KEY_TEXT} ${code}.`
        : `${head} ${(0, fallback_copy_1.fallbackSentence)(modeReason)} ${code}; mode: ${(0, fallback_copy_1.fallbackCode)(modeReason)}.`;
}
/** §4.2: an S0-S5 floor stop is lifted only by an enforced server allow (a verified permit); an advisory allow never lifts it. */
function accountFloorStops(rollout, floor, server) {
    if (rollout !== 'on' || !floor || floor.decision !== 'stop')
        return false;
    return server !== 'enforced_allow';
}
/** The event as the receipt writer may use it: to derive enums and keyed hashes only, never stored. */
function recordContext(event, home) {
    return { tool_name: event.tool_name, tool_input: event.tool_input, cwd: event.cwd, session: event.session, truncated: event.truncated, home };
}
function record(entry, event, home) {
    try {
        require('./record').recordSeatbeltDecision(entry, recordContext(event, home));
    }
    catch { /* the record hook never changes a decision */ }
}
function gone(error) {
    const code = error?.code;
    return code === 'ENOENT' || code === 'ENOTDIR';
}
function unreadable(error) {
    const code = error?.code;
    return code === 'EACCES' || code === 'EPERM';
}
/** The mapper's file view over the host. Missing: null. A failure the mapper must not guess about throws (it stops on fs_error). */
function hostMapperFs(fs3) {
    const fs = require('node:fs');
    const realpath = (p) => {
        try {
            return fs.realpathSync(p);
        }
        catch (error) {
            if (gone(error))
                return null;
            throw error;
        }
    };
    return {
        realpath,
        readFile(p, maxBytes) {
            const real = realpath(p);
            if (real === null)
                return null;
            try {
                return fs3.readFile(real, maxBytes);
            }
            catch (error) {
                if (gone(error) || unreadable(error))
                    return null;
                throw error;
            }
        },
        readdir(p) {
            try {
                return fs.readdirSync(p);
            }
            catch (error) {
                if (gone(error) || unreadable(error))
                    return null;
                throw error;
            }
        },
    };
}
const BRANCH_NAME = /^[A-Za-z0-9._/+@-]+$/;
/**
 * The git view the mapper gets (r4 contract). `currentBranch` is read at every call, never cached;
 * anything unclear is null. `getAll` throws when the config cannot be read in full.
 */
function hostSeatbeltGit(fs3, home, env) {
    const G = require('../seatbelt-git');
    const P = require('../seatbelt-path');
    const gitEnv = () => Object.keys(env).some((name) => name.startsWith('GIT_'));
    const configEnv = { ...env };
    // git reads $HOME; when it is the trusted home under another spelling (a symlink) it is the same files.
    if (typeof env.HOME === 'string' && env.HOME !== home) {
        const real = P.realPath(fs3, env.HOME, { followFinal: true });
        if (real.status === 'resolved' && real.exists && real.path === home)
            configEnv.HOME = home;
    }
    // The work tree that holds the `.git` entry nearest to cwd; null when none; 'unknown' when unclear.
    const worktree = (cwd) => {
        const real = P.realPath(fs3, cwd, { followFinal: true });
        if (real.status !== 'resolved' || !real.exists)
            return 'unknown';
        let dir = real.path;
        for (;;) {
            const entry = fs3.lstat(dir === '/' ? '/.git' : `${dir}/.git`);
            if (entry && (entry.type === 'dir' || entry.type === 'file'))
                return dir;
            if (entry)
                return 'unknown';
            if (dir === '/')
                return null;
            dir = dir.slice(0, dir.lastIndexOf('/')) || '/';
        }
    };
    const dirsOf = (cwd) => {
        const dirs = G.discoverGitDirs(fs3, cwd, configEnv);
        if (dirs === 'unknown')
            throw new Error('git_dirs_unknown');
        return dirs;
    };
    const refExists = (commonDir, branch) => {
        const loose = fs3.lstat(`${commonDir}/refs/heads/${branch}`);
        if (loose && loose.type === 'file')
            return true;
        if (loose)
            return false;
        const packedEntry = fs3.lstat(`${commonDir}/packed-refs`);
        if (!packedEntry)
            return false;
        if (packedEntry.type !== 'file')
            return false;
        const packed = fs3.readFile(`${commonDir}/packed-refs`, G.MAX_GIT_CONFIG_BYTES);
        return packed !== null && packed.split('\n').some((line) => line.endsWith(` refs/heads/${branch}`));
    };
    return {
        toplevel(cwd) {
            if (gitEnv())
                throw new Error('git_env');
            const top = worktree(cwd);
            if (top === 'unknown')
                throw new Error('git_toplevel_unknown');
            return top;
        },
        getAll(cwd, key) {
            const dirs = dirsOf(cwd);
            const config = G.loadGitConfig(fs3, { home, dirs, env: configEnv });
            if (config.incomplete)
                throw new Error('git_config_unreadable');
            return G.gitConfigValues(config, key);
        },
        currentBranch(cwd) {
            if (gitEnv())
                return null;
            try {
                const top = worktree(cwd);
                if (top === null || top === 'unknown')
                    return null;
                const dirs = G.discoverGitDirs(fs3, cwd, configEnv);
                if (dirs === null || dirs === 'unknown')
                    return null;
                for (const marker of ['rebase-merge', 'rebase-apply', 'BISECT_LOG'])
                    if (fs3.lstat(`${dirs.gitDir}/${marker}`))
                        return null;
                const head = G.readGitHead(fs3, dirs);
                if (head.kind !== 'branch')
                    return null;
                const name = head.branch;
                if (!BRANCH_NAME.test(name) || name.startsWith('-') || name.startsWith('/') || name.endsWith('/')
                    || name.includes('..') || name.includes('//') || name.endsWith('.lock'))
                    return null;
                return refExists(dirs.commonDir, name) ? name : null;
            }
            catch {
                return null;
            }
        },
        remoteHead(cwd, remote) {
            const dirs = dirsOf(cwd);
            if (!dirs)
                return null;
            const head = G.readRemoteDefaultBranch(fs3, dirs, remote);
            if (head === 'unknown')
                throw new Error('remote_head_unknown');
            return head;
        },
    };
}
const TEMP_ROOTS = /^\/(?:tmp|var\/tmp|private\/tmp|var\/folders|private\/var\/folders)(?:\/|$)/;
/** $TMPDIR only when it resolves under a system temp root: the environment can only narrow the workspace. */
function trustedTmpdir() {
    try {
        const real = require('node:fs').realpathSync(require('node:os').tmpdir());
        return TEMP_ROOTS.test(real) && real !== '/' ? real : undefined;
    }
    catch {
        return undefined;
    }
}
function mapperEnv(home, cwd, budgetMs) {
    const fs3 = require('../seatbelt-fs').nodeSeatbeltFs();
    return {
        cwd: typeof cwd === 'string' && cwd.startsWith('/') ? cwd : null,
        home,
        tmpdir: trustedTmpdir(),
        platform: process.platform,
        fs: hostMapperFs(fs3),
        git: hostSeatbeltGit(fs3, home, process.env),
        budgetMs: Math.max(0, budgetMs),
    };
}
function evaluate(event, home, budgetMs) {
    const { evaluateSeatbelt } = require('./mapper');
    return evaluateSeatbelt({ tool_name: String(event.tool_name || ''), tool_input: event.tool_input }, mapperEnv(home, event.cwd, budgetMs));
}
function passwdHome() {
    try {
        const home = require('node:os').userInfo().homedir;
        return typeof home === 'string' && home.startsWith('/') ? home : null;
    }
    catch {
        return null;
    }
}
/** The keyless branch of the hook: mode (U4), then the mapper (U2) with the U3 resolvers. Never throws. */
function keylessSeatbelt(harness, event) {
    const started = Date.now();
    let mode = 'claimed_no_key';
    let accountLinked = false;
    // A resolution that fails or has no reason keeps the generic code.
    let modeReason = fallback_copy_1.FALLBACK_OTHER;
    let trustedHome;
    const stop = (reason) => {
        record({ v: 1, mode, enforcement: 'enforce', harness, decision: 'stop', category: 'hook', rule: 'U5.fail_closed', reasons: [reason], flags: [], parse: 'unparsed', latency_ms: Date.now() - started }, event, trustedHome);
        return { mode, accountLinked, recognized: true, modeReason, stopText: seatbeltStopText('hook', 'U5.fail_closed', reason, mode, accountLinked, modeReason) };
    };
    try {
        const { resolveSeatbeltModeOnHost } = require('../seatbelt-mode');
        const resolution = resolveSeatbeltModeOnHost();
        mode = resolution.mode === 'seatbelt' && exports.SEATBELT_ROLLOUT.keyless === 'on' ? 'seatbelt' : 'claimed_no_key';
        accountLinked = resolution.reasons.includes('account_evidence') || resolution.reasons.includes('key_rejected');
        modeReason = (0, fallback_copy_1.pickFallbackReason)(resolution.reasons);
        if (event.truncated)
            return stop('input_truncated');
        const home = resolution.homes[0] || passwdHome() || '/nonexistent-home';
        trustedHome = home;
        const decision = evaluate(event, home, exports.HOOK_BUDGET_MS - (Date.now() - started));
        if (Date.now() - started > exports.HOOK_BUDGET_MS)
            return stop('hook_budget');
        const reasons = codes(decision.reasons);
        record({
            v: 1, mode, enforcement: 'enforce', harness, decision: decision.decision === 'pass' ? 'pass' : 'stop',
            category: CODE.test(decision.category) ? decision.category : 'unknown', rule: CODE.test(decision.rule) ? decision.rule : 'unknown',
            reasons, flags: codes(decision.flags), parse: CODE.test(decision.parse) ? decision.parse : 'unknown', latency_ms: Date.now() - started,
        }, event, home);
        if (decision.decision === 'pass')
            return { mode, accountLinked, recognized: decision.recognized === true, modeReason, stopText: null };
        return { mode, accountLinked, recognized: true, modeReason, stopText: seatbeltStopText(decision.category, decision.rule, reasons[0] || 'unspecified', mode, accountLinked, modeReason) };
    }
    catch {
        return stop('hook_error');
    }
}
/** The reason codes mode resolution can emit (src/seatbelt-mode.ts), the only ones the status line may print. */
const STATUS_REASONS = ['strict', 'key_rejected', 'home_unknown', 'home_unusable', 'env_home_unusable', 'home_mismatch', 'account_evidence', 'evidence_unknown'];
/**
 * What `marrow-mcp seatbelt-status` prints (the installer's doctor reads it): the mode this machine's
 * hook would be in right now, from the same resolution the keyless hook runs (same key lookup, same
 * rollout table), and the resolver's reason codes that are on a closed list. Reads only; writes no file
 * or state, opens no connection, and names no key, path, user or environment value. Throws when the
 * resolution does (the caller prints the unknown line).
 */
function seatbeltStatus() {
    const { resolveSeatbeltModeOnHost } = require('../seatbelt-mode');
    const resolution = resolveSeatbeltModeOnHost({ argv: [] });
    const mode = resolution.mode === 'seatbelt' && exports.SEATBELT_ROLLOUT.keyless !== 'on' ? 'claimed_no_key' : resolution.mode;
    const reasons = STATUS_REASONS.filter((code) => resolution.reasons.includes(code));
    return { mode, reasons };
}
/**
 * The account floor. `watch`: computed after the answer, for the record only; it never throws and
 * never writes output. `on` (not active): run before the server flow; a returned text is a stop.
 */
function accountFloor(harness, event, deadlineAt) {
    const started = Date.now();
    try {
        const budget = Math.min(exports.HOOK_BUDGET_MS, (Number.isFinite(deadlineAt) ? deadlineAt : Number.POSITIVE_INFINITY) - started - 200);
        const enforcement = exports.SEATBELT_ROLLOUT.account_floor === 'on' ? 'enforce' : 'watch';
        if (!(budget >= 20)) {
            record({ v: 1, mode: 'account', enforcement, harness, decision: 'skipped', category: 'none', rule: 'none', reasons: ['floor_no_budget'], flags: [], parse: 'ok', latency_ms: 0 }, event);
            return enforcement === 'enforce' ? seatbeltStopText('hook', 'U5.fail_closed', 'hook_budget', 'account') : null;
        }
        const decision = event.truncated ? null : evaluate(event, passwdHome() || '/nonexistent-home', budget);
        const stopped = decision === null || decision.decision === 'stop' || Date.now() - started > budget;
        record({
            v: 1, mode: 'account', enforcement, harness, decision: stopped ? 'stop' : 'pass',
            category: decision && CODE.test(decision.category) ? decision.category : 'hook', rule: decision && CODE.test(decision.rule) ? decision.rule : 'U5.fail_closed',
            reasons: decision ? codes(decision.reasons) : ['input_truncated'], flags: decision ? codes(decision.flags) : [],
            parse: decision && CODE.test(decision.parse) ? decision.parse : 'unparsed', latency_ms: Date.now() - started,
        }, event);
        if (!accountFloorStops(exports.SEATBELT_ROLLOUT.account_floor, { decision: stopped ? 'stop' : 'pass' }, 'none'))
            return null;
        return decision && decision.decision === 'stop'
            ? seatbeltStopText(decision.category, decision.rule, codes(decision.reasons)[0] || 'unspecified', 'account')
            : seatbeltStopText('hook', 'U5.fail_closed', decision ? 'hook_budget' : 'input_truncated', 'account');
    }
    catch {
        return exports.SEATBELT_ROLLOUT.account_floor === 'on' ? seatbeltStopText('hook', 'U5.fail_closed', 'hook_error', 'account') : null;
    }
}
// Hits that only mean the mapper could not finish (load, an internal error): not a reading of the action.
const UNFINISHED_HIT = /^(?:budget_[a-z_]+|mapper_error|fs_error)$/;
/**
 * I3: how the mapper reads an action for the outage hold (Marrow unreachable). `high`: an S0-S5/S-x hit
 * or a program on the outage list (git push, publish, deploy, remote delete), a dynamic subcommand of a
 * listed program included. `not_high`: the mapper read all of it and found neither. `unknown`: it could
 * not (budget, error, unparsed or dynamic text, truncated input, a tool it does not recognise); the hook
 * then keeps the client classifier's answer. `shell`: the event ran a shell command. Never throws;
 * writes no receipt or output.
 */
function outageRisk(event, deadlineAt) {
    const started = Date.now();
    try {
        const budget = Math.min(exports.HOOK_BUDGET_MS, (Number.isFinite(deadlineAt) ? deadlineAt : Number.POSITIVE_INFINITY) - started - 200);
        if (!(budget >= 20) || event.truncated)
            return { shell: false, risk: 'unknown' };
        const decision = evaluate(event, passwdHome() || '/nonexistent-home', budget);
        const shell = decision.shell === true;
        if (Date.now() - started > budget)
            return { shell, risk: 'unknown' };
        // T-3: a command that only prints its help or version is never held in an outage.
        if (decision.outageHelpOnly === true && decision.parse === 'ok' && decision.recognized === true)
            return { shell, risk: 'not_high' };
        // A real hit or a listed program is high even where the rest of the text could not be read; a listed
        // program whose subcommand word is dynamic (`unknown`) may be the listed one, so it is high too.
        if (decision.hits.some((h) => !UNFINISHED_HIT.test(h.reason)))
            return { shell, risk: 'high' };
        if (decision.risk.length)
            return { shell, risk: 'high' };
        if (decision.decision === 'stop' || decision.parse !== 'ok' || decision.recognized !== true)
            return { shell, risk: 'unknown' };
        return { shell, risk: 'not_high' };
    }
    catch {
        return { shell: false, risk: 'unknown' };
    }
}
//# sourceMappingURL=hook.js.map