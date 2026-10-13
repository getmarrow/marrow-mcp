import { type SeatbeltFs } from './seatbelt-fs';
export type SeatbeltMode = 'seatbelt' | 'account' | 'claimed_no_key';
export declare const ACCOUNT_EVIDENCE: readonly ["env_file", "env_local_file", "device_binding", "claimed_marker", "host_approvals_state", "mcp_spool", "runner_holds_salt", "hook_claimed_marker", "marrow_dir", "evidence_dirs"];
export type AccountEvidence = typeof ACCOUNT_EVIDENCE[number];
export type EvidenceState = 'present' | 'absent' | 'unknown';
export type KeyState = 'none' | 'present' | 'rejected';
export interface SeatbeltModeInput {
    fs: SeatbeltFs;
    /** The home directory from passwd (getpwuid), never $HOME. */
    passwdHome: string | null;
    /** This hook process's argv: `--home <abs>` / `--home=<abs>` and the installer's `--claimed` marker. */
    argv: string[];
    /** Trusted key state: from the owner files or the hook's own environment; 'rejected' after a 401. */
    key: KeyState;
    uid?: number | null;
    /** MARROW_SEATBELT_STRICT=1: never seatbelt. */
    strict?: boolean;
    /**
     * Homes named only by the environment ($HOME, USERPROFILE): today's writers
     * (src/env.ts, host-approval-state, lifecycle-spool, grok hooks) put keys
     * and state there. Probed for evidence only; one that is not a trusted home
     * gives `home_mismatch`. Never used for keys or later reads.
     */
    envHomes?: string[];
    /** Extra hook config files from env relocation (CODEX_HOME, CLAUDE_CONFIG_DIR ...). Additive; a relative path is unknown. */
    extraHookConfigs?: string[];
    /** Extra hook script directories (CLINE_DIR ...). Additive; a relative path is unknown. */
    extraHookDirs?: string[];
    /**
     * The owner's private group id (privateGroupId), read only when a group-writable evidence dir is
     * met. Absent or null: group write is refused (the U4 rule).
     */
    privateGid?: (() => number | null) | number | null;
}
export interface SeatbeltModeResolution {
    mode: SeatbeltMode;
    homes: string[];
    evidence: Record<AccountEvidence, EvidenceState>;
    /** Fixed reason codes, no paths or values. */
    reasons: string[];
}
/** Harness hook configs (user level) that carry the installer's `--claimed` marker after a claim. */
export declare const HOOK_CONFIG_FILES: string[];
/**
 * Hook script directories (Cline runs the executable scripts in its hooks
 * directory). Every regular file in them is scanned for the marker. U8 must
 * publish the exact paths it writes; any path it adds must be added here.
 */
export declare const HOOK_CONFIG_DIRS: string[];
/** Every `--home` value in the hook's argv (repeated flags are all kept: a mismatch is contradictory). */
export declare function homeFlags(argv: string[]): string[];
/**
 * The owner's private group (Debian OpenSSH "user-group-modes"), read from the local files only:
 * uid has exactly one local passwd entry, no other passwd entry has its primary gid, and that gid
 * has exactly one local group entry whose member list names nobody but the owner. Anything else,
 * including an unreadable file, a network name service (users there cannot be listed) or root,
 * gives null: group write then stays refused, as before.
 */
export declare function privateGroupId(fs: SeatbeltFs, uid: number | null): number | null;
export declare function resolveSeatbeltMode(input: SeatbeltModeInput): SeatbeltModeResolution;
export declare const MODE_ENV_NAMES: string[];
/**
 * Host wiring for the hook (U5 calls this). The key comes only from the hook's
 * environment or the owner files in a trusted home (never repo .env files);
 * keyRejected is set after the server answers 401.
 */
export declare function resolveSeatbeltModeOnHost(options?: {
    argv?: string[];
    env?: NodeJS.ProcessEnv;
    fs?: SeatbeltFs;
    passwdHome?: string | null;
    uid?: number | null;
    keyRejected?: boolean;
    /** Tests: the private group answer; default reads the local account files (Linux only). */
    privateGid?: (() => number | null) | number | null;
}): SeatbeltModeResolution;
//# sourceMappingURL=seatbelt-mode.d.ts.map