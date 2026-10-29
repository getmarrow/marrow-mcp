import { type BigIntStats } from 'node:fs';
export type WinPolicy = 'no_write_by_others' | 'no_access_by_others';
export interface WinObject {
    rel: string;
    kind: 'dir' | 'file';
    policy: WinPolicy;
}
export type WinReason = 'platform' | 'path' | 'chain' | 'canonical' | 'sysroot' | 'powershell' | 'spawn' | 'output' | 'timeout' | 'descriptor' | 'owner' | 'acl' | 'mkdir' | 'internal';
export type WinProof = {
    ok: true;
    home: string;
    canonical: Record<string, string>;
    identity: string;
    provedAtMs: number;
    fileKeys: Record<string, string>;
} | {
    ok: false;
    reason: WinReason;
};
/** `provedAtMs`: when the ACL answer was obtained. `stateKey`: (dev:ino) of the state file the proof covered, else null. */
export type WinEnsureOk = {
    ok: true;
    marrow: string;
    directory: string;
    target: string;
    stateProven: boolean;
    identity: string;
    provedAtMs: number;
    stateKey: string | null;
};
export type WinEnsure = WinEnsureOk | {
    ok: false;
    reason: WinReason;
};
export interface WinSpawnResult {
    status: number | null;
    signal: string | null;
    error?: unknown;
    stdout: unknown;
    stderr?: unknown;
}
export interface WinSpawnOptions {
    stdio: ['ignore', 'pipe', 'pipe'];
    encoding: 'utf8';
    windowsHide: true;
    shell: false;
    timeout: number;
    maxBuffer: number;
    cwd: string;
    env: Record<string, string>;
}
export interface WinProofCacheEntry {
    at: number;
    signature: string;
}
/** A state file born this long before the proof began still counts as created after it (file-system clock granularity). */
export declare const WIN_BIRTH_TOLERANCE_MS = 250;
export interface WinDeps {
    platform: NodeJS.Platform;
    env: Readonly<Record<string, string | undefined>>;
    lstatBig(path: string): BigIntStats;
    realpathNative(path: string): string;
    spawnSync(file: string, args: string[], options: WinSpawnOptions): WinSpawnResult;
    randomHex(bytes: number): string;
    now(): number;
    mkdir(path: string): void;
    /** In-process only (R7). Never written to disk. */
    cache?: Map<string, WinProofCacheEntry>;
}
export declare const WIN_PROOF_TIMEOUT_MS = 5000;
export declare const WIN_PROOF_MAX_BUFFER = 65536;
export declare const WIN_PROOF_CACHE_MS = 2000;
/** Production dependencies: Node's own fs, child_process and crypto. There is no env switch. */
export declare function realWindowsDeps(): WinDeps;
/** True only for `X:\a\b` with no alias, device, stream, UNC, relative or forward-slash form. */
export declare function validWindowsPath(value: unknown): value is string;
interface ParsedAce {
    type: number;
    flags: number;
    mask: number;
    sid: string;
}
/** Self-relative SECURITY_DESCRIPTOR to its owner SID and allow/deny ACEs; null for anything outside the grammar. */
export declare function parseSecurityDescriptor(buffer: Buffer): {
    owner: string;
    aces: ParsedAce[];
} | null;
/**
 * Judges one object's descriptor (base64) against `policy`. null: private enough. Otherwise a reason.
 * The owner must be trusted; a deny ACE can only remove access and is skipped; every allow ACE for
 * someone else is judged by its raw mask.
 */
export declare function evaluateDescriptor(encoded: unknown, trusted: ReadonlySet<string>, policy: WinPolicy): WinReason | null;
export declare const WIN_ACL_SCRIPT: string;
export declare const WIN_ACL_ENCODED: string;
/** The proof. Never throws; every failure is `{ ok: false, reason }`. */
export declare function proveWindowsPrivate(request: {
    home: string;
    objects: readonly WinObject[];
}, deps: WinDeps): WinProof;
/**
 * `~/.marrow` and `~/.marrow/session-loop-guard` are created when absent (they inherit the profile
 * DACL), checked for reparse points and canonicalised after each creation, and then proven private
 * together with `state.json` when it exists. `home` is the caller's `os.homedir()`; HOME is never read.
 * This spawns PowerShell: call it BEFORE taking the state lock, never while holding it.
 */
export declare function ensureWindowsPrivateState(home: unknown, deps: WinDeps): WinEnsure;
/**
 * Called while the state lock is held: the cheap structural half only (path grammar, no reparse
 * point, canonical path, hard-link count) plus the folder identity of the earlier proof. It never
 * spawns anything. A state file that appeared or was replaced after the proof is accepted if it is a
 * plain single-link file in an unchanged, already proven folder: only a trusted principal can create
 * entries there. A changed folder identity is a refusal, with no retry.
 */
export declare function verifyWindowsPrivateState(home: unknown, proof: WinEnsureOk, deps: WinDeps): boolean;
export {};
//# sourceMappingURL=win-private-state.d.ts.map