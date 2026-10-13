"use strict";
// Record hook for seatbelt decisions (U5 calls it once per decision; U6 implements receipts).
// The record holds only spec §1.5 field classes: enums, rule ids, fixed reason and flag codes and a
// bounded integer. Never command text, paths, branch names, arguments or values.
Object.defineProperty(exports, "__esModule", { value: true });
exports.recordSeatbeltDecision = recordSeatbeltDecision;
/** Default: no-op. It must never throw into the hook, never write output and never change a decision. */
function recordSeatbeltDecision(record) {
    void record;
}
//# sourceMappingURL=record.js.map