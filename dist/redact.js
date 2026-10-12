"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.AMBIGUOUS_REDACTION_MARKER = void 0;
exports.redactSensitiveText = redactSensitiveText;
exports.redactSensitiveValue = redactSensitiveValue;
exports.AMBIGUOUS_REDACTION_MARKER = '[REDACTED_AMBIGUOUS]';
const COMMAND_STRUCTURE = /[\s'"`;&|<>()#,?]|\$\(/;
const UNQUOTED_STRUCTURE = /[&;|<>()`#,?]|\$[({A-Za-z_]/;
/** The marker for one hidden value: ambiguous when the value may also hide command text. */
function hide(value, plain = '[REDACTED]', quoted = false) {
    return (quoted ? COMMAND_STRUCTURE : UNQUOTED_STRUCTURE).test(value) ? exports.AMBIGUOUS_REDACTION_MARKER : plain;
}
/** A quoted (`"…"` / `'…'`) or bare value: the marker for its content; an unterminated quote is ambiguous. */
function hideMaybeQuoted(value, plain = '[REDACTED]') {
    if (value.startsWith('\\"')) {
        if (value.length < 4 || !value.endsWith('\\"'))
            return exports.AMBIGUOUS_REDACTION_MARKER;
        return hide(value.slice(2, -2), plain, true);
    }
    const quote = value[0];
    if (quote === '"' || quote === "'") {
        if (value.length < 2 || value[value.length - 1] !== quote)
            return exports.AMBIGUOUS_REDACTION_MARKER;
        return hide(value.slice(1, -1), plain, true);
    }
    return hide(value, plain);
}
/** A credential-like name (as in `NAME=value`, `NAME: value`, `"name": "value"`). */
const SECRET_NAME = /SECRET|TOKEN|API[_-]?KEY|CREDENTIAL|PASSWORD|PRIVATE[_-]?KEY/i;
/** The same names, plus `passwd` and `authorization`, as a quoted key (`"api_key": …`). */
const SECRET_KEY_NAME = /SECRET|TOKEN|API[_-]?KEY|CREDENTIAL|PASSWORD|PASSWD|PRIVATE[_-]?KEY|AUTHORIZATION/i;
/** A query parameter name that carries a secret. */
const SECRET_QUERY_NAME = /code|token|secret|signature|sig|credential|password|session|auth|api[_-]?key|apikey|client[_-]?secret|(?:^|[-_])key|key(?:[-_]|$)/i;
/** `"name": "value"` / `'name': 'value'` / `"name": value` (JSON, Python, YAML flow), also with the quotes escaped inside a shell string (`\"name\":\"value\"`). */
const QUOTED_NAME_VALUE = /(\\?["'])([A-Za-z0-9_.-]{1,128})\1([ \t]{0,8}:[ \t]{0,8})(\\"(?:[^"\\\n]|\\[^"\n]){0,8192}(?:\\")?|"(?:[^"\\\n]|\\.){0,8192}"?|'(?:[^'\\\n]|\\.){0,8192}'?|[^\s"',;}\]\\]{1,8192})/g;
/** `scheme://user:password@host`: the password is replaced, scheme, user and host stay. */
const URL_USERINFO = /(?<![A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]{0,31}:\/\/)([^\s/@:'"`]{0,256}):([^\s/'"`]{1,1024})@/g;
/** `Authorization: <scheme> <value>` / `Proxy-Authorization: <value>`: the value is replaced, the scheme word stays. */
const AUTH_HEADER = /\b((?:Proxy-)?Authorization)([ \t]{0,8}[:=][ \t]{0,8})(?:(Basic|Bearer|Digest|Token|Negotiate|NTLM|ApiKey|Bot|HOBA|Mutual|AWS4-HMAC-SHA256)[ \t]{1,8})?([^\s"'`,;]{1,8192})/gi;
/** Digest parameters derived from the password. */
const DIGEST_PARAM = /\b(response|cnonce|nonce)=("[^"\n]{0,1024}(?:"|$)|[^\s,;"]{1,1024})/gi;
/** A value an earlier rule already replaced by a marker: it stays as it is (an ambiguous marker is never made plain). */
const OWN_MARKER_AHEAD = /^['"]?\[(?:REDACTED(?:_[A-Z_]{1,20})?|redacted)\]/;
function nameValueRedactor(text) {
    // `NAME=value` / `NAME: value`: the name is a whole word, so the match cannot start inside a run.
    const pattern = /\b([A-Za-z0-9_]{1,4096})(\s{0,64}[:=]\s{0,64})/g;
    const quoted = /(["'])([^"'\n]{0,4096})\1/y;
    const value = /['"]?[^'"\s,;]{6,}/y;
    let out = '';
    let copied = 0;
    for (let match = pattern.exec(text); match; match = pattern.exec(text)) {
        const end = match.index + match[0].length;
        if (!SECRET_NAME.test(match[1]) || OWN_MARKER_AHEAD.test(text.slice(end, end + 24))) {
            pattern.lastIndex = end;
            continue;
        }
        quoted.lastIndex = end;
        const whole = quoted.exec(text);
        if (whole && whole[2].length >= 6) {
            // A quoted value is hidden up to its closing quote, blanks included.
            out += text.slice(copied, match.index) + `${match[1]}=${hide(whole[2], '[REDACTED]', true)}`;
            copied = quoted.lastIndex;
            pattern.lastIndex = copied;
            continue;
        }
        value.lastIndex = end;
        const found = value.exec(text);
        if (!found) {
            pattern.lastIndex = end;
            continue;
        }
        out += text.slice(copied, match.index) + `${match[1]}=${hide(found[0].replace(/^['"]/, ''))}`;
        copied = value.lastIndex;
        pattern.lastIndex = copied;
    }
    return out + text.slice(copied);
}
function queryRedactor(text) {
    // `?name=value` / `&name=value`: the name stops at the next `?`, so every start scans its own run only.
    const pattern = /([?&])([^=&#?\s]{0,4096})=/g;
    const value = /[^&#\s]*/y;
    let out = '';
    let copied = 0;
    for (let match = pattern.exec(text); match; match = pattern.exec(text)) {
        const end = match.index + match[0].length;
        if (!SECRET_QUERY_NAME.test(match[2])) {
            pattern.lastIndex = end;
            continue;
        }
        value.lastIndex = end;
        const found = value.exec(text);
        out += text.slice(copied, end) + hide(found ? found[0] : '', '[redacted]');
        copied = value.lastIndex;
        pattern.lastIndex = copied > end ? copied : end;
    }
    return out + text.slice(copied);
}
function digestRedactor(text) {
    if (!/\bDigest[ \t]/i.test(text))
        return text;
    return text.replace(/\bDigest[ \t]{1,8}[^\n]{0,4096}/gi, (span) => span.replace(DIGEST_PARAM, (_m, name, v) => `${name}=${hideMaybeQuoted(v)}`));
}
function redactSensitiveText(value) {
    let out = value
        .replace(QUOTED_NAME_VALUE, (match, quote, name, sep, v) => (SECRET_KEY_NAME.test(name) ? `${quote}${name}${quote}${sep}${quote.length > 1 ? '\\"' : '"'}${hideMaybeQuoted(v)}${quote.length > 1 ? '\\"' : '"'}` : match))
        .replace(URL_USERINFO, (_m, scheme, user, password) => (`${scheme}${user}:${password.includes('@') ? exports.AMBIGUOUS_REDACTION_MARKER : hide(password)}@`));
    out = digestRedactor(out)
        .replace(AUTH_HEADER, (_match, header, sep, scheme, v) => (`${header}${sep}${scheme ? `${scheme} ` : ''}${hide(v)}`))
        .replace(/(\B--(?:password|pass|secret|api-key|apikey|token|auth|access-token|client-secret|private-key|key)=)([^\s"'`]+|"[^"]*(?:"|$)|'[^']*(?:'|$))/gi, (_m, flag, v) => `${flag}${hideMaybeQuoted(v)}`)
        .replace(/(\B--(?:password|pass|secret|api-key|apikey|token|auth|access-token|client-secret|private-key|key)\s+)([^\s"'`]+|"[^"]*(?:"|$)|'[^']*(?:'|$))/gi, (_m, flag, v) => `${flag}${hideMaybeQuoted(v)}`)
        .replace(/\b(Bearer|Token|ApiKey|API_KEY|MARROW_API_KEY|MARROW_KEY)\s+[\w.\-+/=]{12,}\b/gi, '$1 [REDACTED]')
        // `Basic <base64>` outside a header: base64 of `user:password` (a digit, `+`, `/`, `=` or an inner capital), not a plain word.
        .replace(/\bBasic([ \t]{1,8})([A-Za-z0-9+/]{8,8192}={0,2})(?![A-Za-z0-9+/=])/g, (match, space, token) => (/[0-9+/=]|.[A-Z]/.test(token) ? `Basic${space}[REDACTED]` : match));
    out = nameValueRedactor(out)
        .replace(/\b(mrw_[A-Za-z0-9_\-]{8,})\b/g, '[REDACTED_MARROW_KEY]')
        .replace(/\bmrw_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_[A-Fa-f0-9]{16,}\b/gi, '[REDACTED_MARROW_KEY]')
        .replace(/\b(?:sk|pk|ghp|github_pat|npm|cfut)_[A-Za-z0-9_\-]{12,}\b/g, '[REDACTED_TOKEN]');
    return queryRedactor(out)
        .replace(/([?&](?:token|key|secret|password|auth|signature|sig|session)=)([^&#\s]*)/gi, (match, name, v) => (/^\[(?:redacted|REDACTED_AMBIGUOUS)\]$/.test(v) ? match : `${name}${hide(v, '[redacted]')}`));
}
function redactSensitiveValue(value, depth = 0) {
    if (depth > 4)
        return '[redacted-depth]';
    if (typeof value === 'string')
        return redactSensitiveText(value);
    if (typeof value === 'number' || typeof value === 'boolean' || value == null)
        return value;
    if (Array.isArray(value))
        return value.slice(0, 20).map((item) => redactSensitiveValue(item, depth + 1));
    if (typeof value === 'object') {
        const out = {};
        for (const [key, item] of Object.entries(value).slice(0, 40)) {
            out[key] = /(?:secret|token|api[_-]?key|password|credential|authorization|private[_-]?key)/i.test(key)
                ? '[redacted]'
                : redactSensitiveValue(item, depth + 1);
        }
        return out;
    }
    return String(value);
}
//# sourceMappingURL=redact.js.map