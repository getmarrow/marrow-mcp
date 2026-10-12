import { type SeatbeltFs } from './seatbelt-fs';
export type SeatbeltMode = 'seatbelt' | 'account' | 'claimed_no_key';
export declare const ACCOUNT_EVIDENCE: readonly ["env_file", "env_local_file", "device_binding", "claimed_marker", "host_approvals_state", "mcp_spool", "runner_holds_salt", "hook_claimed_marker", "marrow_dir"];
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
/** Every `--home` value in the hook's argv (repeated flags are all kept: a mismatch is contradictory). */
export declare function homeFlags(argv: string[]): string[];
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
}): SeatbeltModeResolution;
//# sourceMappingURL=seatbelt-mode.d.ts.map