// Record hook for seatbelt decisions (U5 calls it once per decision; U6 implements receipts).
// The record holds only spec §1.5 field classes: enums, rule ids, fixed reason and flag codes and a
// bounded integer. Never command text, paths, branch names, arguments or values.

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
export function recordSeatbeltDecision(record: SeatbeltRecord): void {
  void record;
}
