/**
 * The shared redactor for text that leaves the process. Every pattern starts
 * at a boundary and bounds or delimits its repeats, so a scan is linear in
 * the text: an adversarial input (a long run of a secret word, unterminated
 * quotes, repeated `?`) cannot make it quadratic. Only the secret is
 * replaced (by a fixed marker); the text after it is kept, so two texts that
 * differ after a secret stay different.
 *
 * A replaced value that may also hide command text or a field separator (a
 * quoted value with blanks, quotes or shell operators; an unquoted one with
 * `& ; | < > ( ) # , ?`, a backtick or a `$` expansion; a URL password with
 * `@`) becomes `[REDACTED_AMBIGUOUS]`, the backend's marker for a value that
 * never binds an approval (backend src/utils/redaction.ts hide()): two actions
 * that differ only inside such a span must never share one.
 */
export declare const AMBIGUOUS_REDACTION_MARKER = "[REDACTED_AMBIGUOUS]";
export declare function redactSensitiveText(value: string): string;
export declare function redactSensitiveValue(value: unknown, depth?: number): unknown;
/**
 * Redacts every string in a value that is sent as data (workflow fields,
 * context, inputs): the structure, array lengths and every other value are
 * kept, so nothing is dropped or reshaped; a text field under a credential
 * name is replaced whole. Past depth 32 a value is withheld.
 */
export declare function redactSensitiveStrings<T>(value: T, depth?: number): T;
//# sourceMappingURL=redact.d.ts.map