import * as nodeFs from 'node:fs';
export interface SeatbeltRecord {
    v: 1;
    mode: 'seatbelt' | 'claimed_no_key' | 'account';
    /** `enforce`: the decision was the hook's answer. `watch`: computed for the record only (account floor). */
    enforcement: 'enforce' | 'watch';
    harness: string;
    decision: 'pass' | 'stop' | 'skipped';
    category: string;
    rule: string;
    reasons: string[];
    flags: string[];
    parse: string;
    latency_ms: number;
}
/**
 * What the hook knew about the event. It is used only to derive enums and keyed hashes and is never
 * stored. `home` is the trusted home (passwd, or the hook's baked --home), never the agent's $HOME.
 */
export interface SeatbeltRecordContext {
    tool_name?: unknown;
    tool_input?: unknown;
    cwd?: unknown;
    session?: unknown;
    truncated?: boolean;
    home?: string | null;
}
type Fs = typeof nodeFs;
/** Test seams (host, owner, clock, file system, caps). The hook passes none of them. */
export interface ReceiptOptions {
    home?: string | null;
    uid?: number | null;
    now?: number;
    fs?: Fs;
    maxTotalBytes?: number;
    retentionDays?: number;
    lockWaitMs?: number;
}
export declare const MAX_RECEIPT_BYTES: number;
export declare const MAX_TOTAL_BYTES: number;
export declare const RETENTION_DAYS = 90;
export type DropReason = 'unsafe_store' | 'lock_timeout' | 'write_failed' | 'cap_full' | 'oversize' | 'platform' | 'error';
/** Flags the mapper emits (test/seatbelt-u6-receipts reads the source to prove it) plus the two the receipt adds for the account floor. */
export declare const FLAG_CODES: ReadonlySet<string>;
export interface SeatbeltReceipt {
    v: 1;
    id: string;
    seq: number;
    prev: string;
    ts: number;
    ts_label: 'client_time';
    mode: string;
    enforcement: string;
    harness: string;
    event: 'pre_tool';
    tool_kind: string;
    tool: string;
    decision: string;
    category: string;
    rule: string;
    reasons: string[];
    programs: string[];
    subcommand: string;
    flags: string[];
    target_class: string;
    parse: string;
    action_key: string;
    workspace_key: string;
    session_key: string;
    engine: {
        pkg: string;
        contract: string;
        source_commit: string;
        rules: string;
        tables: string;
    };
    latency_ms: number;
}
/** The problems with a receipt object (an empty list means valid). Used by the writer and by every consumer of the fields. */
export declare function validateReceipt(value: unknown): string[];
/** Write one receipt. Never throws; says what happened. The hook calls recordSeatbeltDecision; tests call this with options. */
export declare function writeSeatbeltReceipt(record: SeatbeltRecord, context?: SeatbeltRecordContext, options?: ReceiptOptions): 'written' | 'dropped';
/**
 * This machine's private salt: the receipts store's (~/.marrow/seatbelt/salt under the passwd home, 32 random
 * bytes, 0600, owned by this uid, read with O_NOFOLLOW, created once), with every check openStore makes. It keys
 * hashes that leave the machine only as a MAC (normalized-action exact_hmac); the salt itself is never sent,
 * printed or logged. null when the store is missing, unsafe, not ours or unreadable: the caller then fails closed.
 * Cached per process. The options are test seams (home, uid, fs) and bypass the cache.
 */
export declare function deviceSalt(options?: Pick<ReceiptOptions, 'home' | 'uid' | 'fs'>): Buffer | null;
/** The record hook U5 calls once per decision. It never throws, writes no output and never changes a decision. */
export declare function recordSeatbeltDecision(record: SeatbeltRecord, context?: SeatbeltRecordContext): void;
export {};
//# sourceMappingURL=record.d.ts.map