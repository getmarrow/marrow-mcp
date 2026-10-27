/**
 * The class (live or test) of a Stripe-style key (`sk_`, `rk_`, `pk_`) inside a span that a redactor is about to
 * replace, so the marker that stands for the span keeps the class: an approval, a hold or a correlation made for an
 * action with a test key can never cover the same action with a live key.
 *
 * Fail closed: the answer is `test` only when every key-shaped token of the span is the exact lowercase ASCII
 * `sk_test_` / `rk_test_` / `pk_test_` shape. A live prefix in any spelling the text can be folded to (case, a
 * `-` for the `_`, NFKC/NFKD-foldable forms, zero-width / format / combining characters, percent or Basic-auth base64
 * encoding), an unknown or malformed prefix, or a test prefix that is not exactly canonical, is `live`. A span with
 * no such token has no class (`null`): its marker stays what it was. The class is read, never copied: callers pick a
 * marker from a closed set of constants.
 */
export type KeyClass = 'live' | 'test';
/** The class of the Stripe-style key(s) in `span`, or null when it holds none. Linear in the span. */
export declare function keyClassOf(span: string): KeyClass | null;
//# sourceMappingURL=key-class.d.ts.map