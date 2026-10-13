// U5: the seatbelt in the pre-action hook (SEATBELT-SPEC.md §1.1, §1.3, §2.1, §4.2).
//
// hook-pre-action.ts loads this module lazily, inside a try: a module that fails to load, an
// exception or the time budget is a stop (§2.1.4). Everything here reads only trusted inputs: the
// home from U4 (passwd or the hook's --home), the event cwd, and the hook process's own files.
import type { SeatbeltDecision, SeatbeltEnv, SeatbeltFs as MapperFs, SeatbeltGit } from './mapper';
import type { SeatbeltFs } from '../seatbelt-fs';
import type { SeatbeltRecord, SeatbeltRecordContext } from './record';

/**
 * Compiled-in rollout table. Not env, not a file: changing a value is a one-line, reviewed code
 * change. `keyless: 'off'` makes every keyless machine `claimed_no_key` (3.9.103 holds plus the
 * floor). `account_floor: 'on'` enforces the S0-S5 floor before the server flow.
 */
export const SEATBELT_ROLLOUT: { readonly keyless: 'on' | 'off'; readonly account_floor: 'watch' | 'on' } = Object.freeze({
  keyless: 'on',
  account_floor: 'watch',
});

/** One wall-clock budget for the whole seatbelt path (mode resolution and mapper). Over it: stop. */
export const HOOK_BUDGET_MS = 300;

export const CLAIMED_NO_KEY_TEXT = 'Marrow is linked to an account but has no working key; owner: run `marrow doctor`.';

const LABELS: Record<string, string> = {
  S0: 'a change to Marrow seatbelt settings or an owner-only command',
  S1: 'force-push or delete of a protected branch',
  S2: 'production deploy',
  S3: 'package publish',
  S4: 'credential or secret access',
  S5: 'recursive delete outside the workspace',
  Sx: 'obfuscated execution',
  hook: 'a safety check that could not finish',
};

const CODE = /^[A-Za-z0-9_.:-]{1,64}$/;

function codes(list: unknown): string[] {
  return Array.isArray(list) ? list.filter((item): item is string => typeof item === 'string' && CODE.test(item)).slice(0, 16) : [];
}

export function seatbeltStopText(category: string, rule: string, reason: string, mode: 'seatbelt' | 'claimed_no_key' | 'account'): string {
  const label = LABELS[category] || LABELS.hook;
  const head = `MARROW SEATBELT stopped this action: ${label} (${CODE.test(rule) ? rule : 'unknown'}, ${CODE.test(reason) ? reason : 'unknown'}). This needs the machine owner. Do not retry it another way or edit Marrow settings.`;
  if (mode === 'account') return `${head} Tell the owner: run it yourself in your own terminal.`;
  return mode === 'seatbelt'
    ? `${head} Tell the owner: run it yourself in your own terminal, or run "marrow claim" to get one-tap approvals.`
    : `${head} ${CLAIMED_NO_KEY_TEXT}`;
}

/** §4.2: an S0-S5 floor stop is lifted only by an enforced server allow (a verified permit); an advisory allow never lifts it. */
export function accountFloorStops(
  rollout: 'watch' | 'on',
  floor: Pick<SeatbeltDecision, 'decision'> | null,
  server: 'enforced_allow' | 'advisory_allow' | 'deny' | 'none',
): boolean {
  if (rollout !== 'on' || !floor || floor.decision !== 'stop') return false;
  return server !== 'enforced_allow';
}

/** The event as the receipt writer may use it: to derive enums and keyed hashes only, never stored. */
function recordContext(event: SeatbeltHookEvent, home?: string): SeatbeltRecordContext {
  return { tool_name: event.tool_name, tool_input: event.tool_input, cwd: event.cwd, session: event.session, truncated: event.truncated, home };
}

function record(entry: SeatbeltRecord, event: SeatbeltHookEvent, home?: string): void {
  try {
    (require('./record') as typeof import('./record')).recordSeatbeltDecision(entry, recordContext(event, home));
  } catch { /* the record hook never changes a decision */ }
}

function gone(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException | null)?.code;
  return code === 'ENOENT' || code === 'ENOTDIR';
}

function unreadable(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException | null)?.code;
  return code === 'EACCES' || code === 'EPERM';
}

/** The mapper's file view over the host. Missing: null. A failure the mapper must not guess about throws (it stops on fs_error). */
export function hostMapperFs(fs3: SeatbeltFs): MapperFs {
  const fs = require('node:fs') as typeof import('node:fs');
  const realpath = (p: string): string | null => {
    try {
      return fs.realpathSync(p);
    } catch (error) {
      if (gone(error)) return null;
      throw error;
    }
  };
  return {
    realpath,
    readFile(p, maxBytes) {
      const real = realpath(p);
      if (real === null) return null;
      try {
        return fs3.readFile(real, maxBytes);
      } catch (error) {
        if (gone(error) || unreadable(error)) return null;
        throw error;
      }
    },
    readdir(p) {
      try {
        return fs.readdirSync(p);
      } catch (error) {
        if (gone(error) || unreadable(error)) return null;
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
export function hostSeatbeltGit(fs3: SeatbeltFs, home: string, env: NodeJS.ProcessEnv): SeatbeltGit {
  const G = require('../seatbelt-git') as typeof import('../seatbelt-git');
  const P = require('../seatbelt-path') as typeof import('../seatbelt-path');
  const gitEnv = () => Object.keys(env).some((name) => name.startsWith('GIT_'));
  const configEnv: Record<string, string | undefined> = { ...env };
  // git reads $HOME; when it is the trusted home under another spelling (a symlink) it is the same files.
  if (typeof env.HOME === 'string' && env.HOME !== home) {
    const real = P.realPath(fs3, env.HOME, { followFinal: true });
    if (real.status === 'resolved' && real.exists && real.path === home) configEnv.HOME = home;
  }
  // The work tree that holds the `.git` entry nearest to cwd; null when none; 'unknown' when unclear.
  const worktree = (cwd: string): string | null | 'unknown' => {
    const real = P.realPath(fs3, cwd, { followFinal: true });
    if (real.status !== 'resolved' || !real.exists) return 'unknown';
    let dir = real.path;
    for (;;) {
      const entry = fs3.lstat(dir === '/' ? '/.git' : `${dir}/.git`);
      if (entry && (entry.type === 'dir' || entry.type === 'file')) return dir;
      if (entry) return 'unknown';
      if (dir === '/') return null;
      dir = dir.slice(0, dir.lastIndexOf('/')) || '/';
    }
  };
  const dirsOf = (cwd: string) => {
    const dirs = G.discoverGitDirs(fs3, cwd, configEnv);
    if (dirs === 'unknown') throw new Error('git_dirs_unknown');
    return dirs;
  };
  const refExists = (commonDir: string, branch: string): boolean => {
    const loose = fs3.lstat(`${commonDir}/refs/heads/${branch}`);
    if (loose && loose.type === 'file') return true;
    if (loose) return false;
    const packedEntry = fs3.lstat(`${commonDir}/packed-refs`);
    if (!packedEntry) return false;
    if (packedEntry.type !== 'file') return false;
    const packed = fs3.readFile(`${commonDir}/packed-refs`, G.MAX_GIT_CONFIG_BYTES);
    return packed !== null && packed.split('\n').some((line) => line.endsWith(` refs/heads/${branch}`));
  };
  return {
    toplevel(cwd) {
      if (gitEnv()) throw new Error('git_env');
      const top = worktree(cwd);
      if (top === 'unknown') throw new Error('git_toplevel_unknown');
      return top;
    },
    getAll(cwd, key) {
      const dirs = dirsOf(cwd);
      const config = G.loadGitConfig(fs3, { home, dirs, env: configEnv });
      if (config.incomplete) throw new Error('git_config_unreadable');
      return G.gitConfigValues(config, key);
    },
    currentBranch(cwd) {
      if (gitEnv()) return null;
      try {
        const top = worktree(cwd);
        if (top === null || top === 'unknown') return null;
        const dirs = G.discoverGitDirs(fs3, cwd, configEnv);
        if (dirs === null || dirs === 'unknown') return null;
        for (const marker of ['rebase-merge', 'rebase-apply', 'BISECT_LOG']) if (fs3.lstat(`${dirs.gitDir}/${marker}`)) return null;
        const head = G.readGitHead(fs3, dirs);
        if (head.kind !== 'branch') return null;
        const name = head.branch;
        if (!BRANCH_NAME.test(name) || name.startsWith('-') || name.startsWith('/') || name.endsWith('/')
          || name.includes('..') || name.includes('//') || name.endsWith('.lock')) return null;
        return refExists(dirs.commonDir, name) ? name : null;
      } catch {
        return null;
      }
    },
    remoteHead(cwd, remote) {
      const dirs = dirsOf(cwd);
      if (!dirs) return null;
      const head = G.readRemoteDefaultBranch(fs3, dirs, remote);
      if (head === 'unknown') throw new Error('remote_head_unknown');
      return head;
    },
  };
}

const TEMP_ROOTS = /^\/(?:tmp|var\/tmp|private\/tmp|var\/folders|private\/var\/folders)(?:\/|$)/;

/** $TMPDIR only when it resolves under a system temp root: the environment can only narrow the workspace. */
function trustedTmpdir(): string | undefined {
  try {
    const real = (require('node:fs') as typeof import('node:fs')).realpathSync((require('node:os') as typeof import('node:os')).tmpdir());
    return TEMP_ROOTS.test(real) && real !== '/' ? real : undefined;
  } catch {
    return undefined;
  }
}

export interface SeatbeltHookEvent {
  tool_name: unknown;
  tool_input: unknown;
  /** The event's cwd as the harness sent it; anything but an absolute path means the workspace is unknown. */
  cwd: unknown;
  /** The harness adapter cut the input: the action is not known in full. */
  truncated: boolean;
  /** The harness session id; used only for the receipt's keyed session_key. */
  session?: unknown;
}

function mapperEnv(home: string, cwd: unknown, budgetMs: number): SeatbeltEnv {
  const fs3 = (require('../seatbelt-fs') as typeof import('../seatbelt-fs')).nodeSeatbeltFs();
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

function evaluate(event: SeatbeltHookEvent, home: string, budgetMs: number): SeatbeltDecision {
  const { evaluateSeatbelt } = require('./mapper') as typeof import('./mapper');
  return evaluateSeatbelt({ tool_name: String(event.tool_name || ''), tool_input: event.tool_input }, mapperEnv(home, event.cwd, budgetMs));
}

function passwdHome(): string | null {
  try {
    const home = (require('node:os') as typeof import('node:os')).userInfo().homedir;
    return typeof home === 'string' && home.startsWith('/') ? home : null;
  } catch {
    return null;
  }
}

export interface KeylessOutcome {
  mode: 'seatbelt' | 'claimed_no_key';
  /** The agent text of a stop; null when the seatbelt passes the action. */
  stopText: string | null;
}

/** The keyless branch of the hook: mode (U4), then the mapper (U2) with the U3 resolvers. Never throws. */
export function keylessSeatbelt(harness: string, event: SeatbeltHookEvent): KeylessOutcome {
  const started = Date.now();
  let mode: KeylessOutcome['mode'] = 'claimed_no_key';
  let trustedHome: string | undefined;
  const stop = (reason: string): KeylessOutcome => {
    record({ v: 1, mode, enforcement: 'enforce', harness, decision: 'stop', category: 'hook', rule: 'U5.fail_closed', reasons: [reason], flags: [], parse: 'unparsed', latency_ms: Date.now() - started }, event, trustedHome);
    return { mode, stopText: seatbeltStopText('hook', 'U5.fail_closed', reason, mode) };
  };
  try {
    const { resolveSeatbeltModeOnHost } = require('../seatbelt-mode') as typeof import('../seatbelt-mode');
    const resolution = resolveSeatbeltModeOnHost();
    mode = resolution.mode === 'seatbelt' && SEATBELT_ROLLOUT.keyless === 'on' ? 'seatbelt' : 'claimed_no_key';
    if (event.truncated) return stop('input_truncated');
    const home = resolution.homes[0] || passwdHome() || '/nonexistent-home';
    trustedHome = home;
    const decision = evaluate(event, home, HOOK_BUDGET_MS - (Date.now() - started));
    if (Date.now() - started > HOOK_BUDGET_MS) return stop('hook_budget');
    const reasons = codes(decision.reasons);
    record({
      v: 1, mode, enforcement: 'enforce', harness, decision: decision.decision === 'pass' ? 'pass' : 'stop',
      category: CODE.test(decision.category) ? decision.category : 'unknown', rule: CODE.test(decision.rule) ? decision.rule : 'unknown',
      reasons, flags: codes(decision.flags), parse: CODE.test(decision.parse) ? decision.parse : 'unknown', latency_ms: Date.now() - started,
    }, event, home);
    if (decision.decision === 'pass') return { mode, stopText: null };
    return { mode, stopText: seatbeltStopText(decision.category, decision.rule, reasons[0] || 'unspecified', mode) };
  } catch {
    return stop('hook_error');
  }
}

/**
 * The account floor. `watch`: computed after the answer, for the record only; it never throws and
 * never writes output. `on` (not active): run before the server flow; a returned text is a stop.
 */
export function accountFloor(harness: string, event: SeatbeltHookEvent, deadlineAt: number): string | null {
  const started = Date.now();
  try {
    const budget = Math.min(HOOK_BUDGET_MS, (Number.isFinite(deadlineAt) ? deadlineAt : Number.POSITIVE_INFINITY) - started - 200);
    const enforcement = SEATBELT_ROLLOUT.account_floor === 'on' ? 'enforce' : 'watch';
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
    if (!accountFloorStops(SEATBELT_ROLLOUT.account_floor, { decision: stopped ? 'stop' : 'pass' }, 'none')) return null;
    return decision && decision.decision === 'stop'
      ? seatbeltStopText(decision.category, decision.rule, codes(decision.reasons)[0] || 'unspecified', 'account')
      : seatbeltStopText('hook', 'U5.fail_closed', decision ? 'hook_budget' : 'input_truncated', 'account');
  } catch {
    return SEATBELT_ROLLOUT.account_floor === 'on' ? seatbeltStopText('hook', 'U5.fail_closed', 'hook_error', 'account') : null;
  }
}
