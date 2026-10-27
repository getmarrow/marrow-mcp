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

/** Format, combining and control characters (zero-width space and joiners, BOM, soft hyphen, bidi marks, accents, NUL). */
const HIDDEN = /[\p{Cf}\p{Mn}\p{Me}\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/gu;
const LIVE_TOKEN = /(?<![a-z0-9])(?:sk|rk|pk)[_-]live/;
/** `sk_` and more that is neither `test` nor `live`: an unknown or malformed class (`sk_prod_…`, `sk_…`). */
const UNKNOWN_TOKEN = /(?<![a-z0-9])(?:sk|rk|pk)_(?!test)[a-z0-9_-]{12,}/;
const TEST_TOKEN = /(?<![a-z0-9])(?:sk|rk|pk)[_-]test/g;
const CANONICAL_TEST = /(?<![A-Za-z0-9])(?:sk|rk|pk)_test_[A-Za-z0-9_-]{12,}/g;
const PLAIN_ASCII = /^[\t\n\r\x20-\x7e]*$/;
const BASE64_SPAN = /^\s*(?:Basic\s+)?([A-Za-z0-9+/]{16,4096}={0,2})\s*$/i;
const PERCENT = /%([0-9A-Fa-f]{2})/g;

/** The span with the readings a backend or a client may give it added after it (percent escapes, Basic-auth base64). */
function withReadings(span: string): string {
  let probe = span;
  if (span.includes('%')) probe += `\n${span.replace(PERCENT, (_m, hex: string) => String.fromCharCode(parseInt(hex, 16)))}`;
  const basic = BASE64_SPAN.exec(span);
  if (basic) probe += `\n${Buffer.from(basic[1], 'base64').toString('latin1')}`;
  return probe;
}

/** The class of the Stripe-style key(s) in `span`, or null when it holds none. Linear in the span. */
export function keyClassOf(span: string): KeyClass | null {
  const probe = withReadings(span);
  // NFKD, not NFKC: an accent composed onto a letter (`i` + U+0301) must come apart so the mark can be dropped.
  const folded = probe.normalize('NFKD').toLowerCase().replace(HIDDEN, '');
  if (LIVE_TOKEN.test(folded) || UNKNOWN_TOKEN.test(folded)) return 'live';
  const tests = folded.match(TEST_TOKEN);
  if (!tests) return null;
  const canonical = probe.match(CANONICAL_TEST);
  return PLAIN_ASCII.test(probe) && canonical !== null && canonical.length === tests.length ? 'test' : 'live';
}
