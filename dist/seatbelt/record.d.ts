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
/** Default: no-op. It must never throw into the hook, never write output and never change a decision. */
export declare function recordSeatbeltDecision(record: SeatbeltRecord): void;
//# sourceMappingURL=record.d.ts.map