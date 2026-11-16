/** N5: MARROW_UPDATE_NOTICE=off (also 0, false, no): no line on any surface and no state read or write. */
export declare function updateNoticeOff(): boolean;
/** The status tool's line: shown on every call while N1 holds (no state). */
export declare function updateNoticeLine(...answers: unknown[]): string | null;
/** The hooks' line: at most once per UTC day per (installed, latest) pair; an unsafe or unwritable state shows none. Never throws. */
export declare function hookUpdateNotice(answer: unknown): string | null;
/** N3, pre-action: only into the separate additionalContext of a Claude Code or Codex answer that neither denies nor asks. */
export declare function withPreActionNotice(output: Record<string, unknown>, harness: string, result: {
    runtime?: unknown;
    outage?: boolean;
    timedOut?: boolean;
}): Record<string, unknown>;
//# sourceMappingURL=update-notice.d.ts.map