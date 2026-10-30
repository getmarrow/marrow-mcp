"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.keyClassOf = keyClassOf;
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
function withReadings(span) {
    let probe = span;
    if (span.includes('%'))
        probe += `\n${span.replace(PERCENT, (_m, hex) => String.fromCharCode(parseInt(hex, 16)))}`;
    const basic = BASE64_SPAN.exec(span);
    if (basic)
        probe += `\n${Buffer.from(basic[1], 'base64').toString('latin1')}`;
    return probe;
}
/** The class of the Stripe-style key(s) in `span`, or null when it holds none. Linear in the span. */
function keyClassOf(span) {
    const probe = withReadings(span);
    // NFKD, not NFKC: an accent composed onto a letter (`i` + U+0301) must come apart so the mark can be dropped.
    const folded = probe.normalize('NFKD').toLowerCase().replace(HIDDEN, '');
    if (LIVE_TOKEN.test(folded) || UNKNOWN_TOKEN.test(folded))
        return 'live';
    const tests = folded.match(TEST_TOKEN);
    if (!tests)
        return null;
    const canonical = probe.match(CANONICAL_TEST);
    return PLAIN_ASCII.test(probe) && canonical !== null && canonical.length === tests.length ? 'test' : 'live';
}
//# sourceMappingURL=key-class.js.map