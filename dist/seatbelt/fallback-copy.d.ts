/** The reason codes of the resolver that can explain a fallback, in the order the text picks one. */
declare const REASON_ORDER: readonly ["strict", "key_rejected", "home_unknown", "home_unusable", "env_home_unusable", "home_mismatch", "evidence_unknown"];
export type FallbackReason = typeof REASON_ORDER[number];
export declare const FALLBACK_OTHER = "setup_unconfirmed";
/** The one code that explains the fallback: the first of the resolver's reasons in the fixed order, else the generic code. */
export declare function pickFallbackReason(reasons: unknown): FallbackReason | typeof FALLBACK_OTHER;
/** The sentence both fallback texts share. Fixed words only: no path, value or user name. */
export declare function fallbackSentence(code?: string | null): string;
/** The code printed after "Code:" / "mode:" for a pick. */
export declare function fallbackCode(code?: string | null): string;
/** The hold text for a protected action when the fallback is on and the seatbelt did not answer. */
export declare function setupUnconfirmedText(code?: string | null): string;
/** Every hold text setupUnconfirmedText can return: one per row of the table, generated from it and from no input. */
export declare function setupUnconfirmedTexts(): string[];
export {};
//# sourceMappingURL=fallback-copy.d.ts.map