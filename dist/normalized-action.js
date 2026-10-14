"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MAX_SCAN_CHARS = void 0;
exports.looksLikeKey = looksLikeKey;
exports.classifySecretName = classifySecretName;
exports.normalizeShellCommand = normalizeShellCommand;
exports.deployCommandText = deployCommandText;
exports.normalizedHookAction = normalizedHookAction;
const node_crypto_1 = require("node:crypto");
const node_os_1 = require("node:os");
const hook_tool_policy_1 = require("./hook-tool-policy");
const SECRET = '[secret]';
const HASH_VERSION = 'marrow-normalized-action-v3';
const EDIT_TOOLS = /^(?:edit|write|multiedit|apply_patch|notebookedit|replace|write_file|edit_file|delete_file|search_replace|delete|create_file)$/i;
const MAX_DEPTH = 3;
/** A word, data text or input string longer than this is not scanned: it is withheld and the action marked truncated. */
exports.MAX_SCAN_CHARS = 16_384;
/** A command longer than this, or more text scanned in total, gives up on exactness (truncated placeholder). */
const MAX_COMMAND_CHARS = 262_144;
const MAX_TOTAL_SCAN_CHARS = 524_288;
/** Words and operators in one command; more gives up on exactness (truncated placeholder). */
const MAX_TOKENS = 4_096;
/** Credential-literal matches scanned in one text before it is withheld as truncated. */
const MAX_ASSIGNMENTS = 2_048;
/** Wall-clock time normalization may take when the caller gives no deadline. */
const DEFAULT_NORMALIZE_MS = 1_000;
/** Thrown when normalization runs out of its budget: the caller sends a truncated placeholder instead. */
class NormalizationLimit extends Error {
}
function newExactness(deadline = Date.now() + DEFAULT_NORMALIZE_MS, exact = false) {
    return { truncated: false, budget: { scanned: 0, deadline }, exact, sigs: [] };
}
/**
 * A value withheld only because it MAY be a secret (it may also be an id, a commit or a name that decides the
 * action): replaced and the action marked truncated; the exact pass keeps it as it is.
 */
function withheld(state, original, replacement = SECRET) {
    state.truncated = true; // exact: kept
    return state.exact ? original : replacement;
}
/** Counts text about to be scanned against the shared budget; past it, normalization stops. */
function spend(state, chars) {
    state.budget.scanned += chars;
    if (state.budget.scanned > MAX_TOTAL_SCAN_CHARS || Date.now() > state.budget.deadline)
        throw new NormalizationLimit();
}
function sha256(text) {
    return (0, node_crypto_1.createHash)('sha256').update(text).digest('hex');
}
// ---------------------------------------------------------------------------
// Key-shaped values
// ---------------------------------------------------------------------------
const KNOWN_KEY_PREFIX = /^(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{12,}$|^(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}$|^github_pat_[A-Za-z0-9_]{20,}$|^(?:sk|pk|rk)[-_](?:live|test|proj|ant)?[-_]?[A-Za-z0-9_-]{12,}$|^xox[abprs]-[A-Za-z0-9-]{10,}$|^AIza[0-9A-Za-z_-]{30,}$|^glpat-[A-Za-z0-9_-]{16,}$|^npm_[A-Za-z0-9]{20,}$|^mrw_[A-Za-z0-9_-]{8,}$|^cfut_[A-Za-z0-9_-]{12,}$|^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/;
const PEM = /-----BEGIN [A-Z ]*(?:PRIVATE KEY|CERTIFICATE)-----/;
/** Known formats that only name a key or are public (AWS key, user, group and role ids; publishable keys): the exact pass keeps them. */
const PUBLIC_KNOWN_KEY = /^(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{12,}$|^pk[-_]/;
/** A value shaped like a key, token or password hash (mixed-case random text, long hex, known prefixes). */
function looksLikeKey(value) {
    const text = value.trim();
    if (!text)
        return false;
    if (KNOWN_KEY_PREFIX.test(text))
        return true;
    if (PEM.test(text))
        return true;
    // A content digest (sha256:...) names content; it is not a secret.
    if (/^(?:sha(?:1|256|384|512)):[0-9a-f]+$/i.test(text))
        return false;
    if (/^[0-9a-f]{32,}$/i.test(text))
        return true;
    if (text.length >= 20 && /^[A-Za-z0-9+/=_-]+$/.test(text) && /[a-z]/.test(text) && /[A-Z]/.test(text) && /[0-9]/.test(text))
        return true;
    return false;
}
const KEY_SPLIT = /([\s=:,;@/?&'"`()[\]{}<>|!*$])/;
/**
 * Replaces key-shaped values in a text. A known key format is a credential;
 * any other random-looking value may be an id or a commit, so it marks the
 * action truncated.
 */
function redactKeyShapes(text, state) {
    const whole = text.trim();
    if (whole && !/\s/.test(whole) && looksLikeKey(whole)) {
        if (!KNOWN_KEY_PREFIX.test(whole) && !PEM.test(whole))
            return withheld(state, text);
        return state.exact && PUBLIC_KNOWN_KEY.test(whole) ? text : SECRET;
    }
    if (PEM.test(text)) {
        // The exact pass replaces only a private key block; a certificate or a public key block is kept.
        return text.replace(/-----BEGIN ([A-Z ]*)-----[\s\S]*?(?:-----END [A-Z ]*-----|$)/g, (block, label) => (state.exact && !/PRIVATE/.test(label) ? block : SECRET));
    }
    return text.split(KEY_SPLIT).map((part) => {
        if (!looksLikeKey(part))
            return part;
        if (!KNOWN_KEY_PREFIX.test(part))
            return withheld(state, part);
        return state.exact && PUBLIC_KNOWN_KEY.test(part) ? part : SECRET;
    }).join('');
}
// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------
function nameParts(name) {
    return name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}
const CREDENTIAL_STEM = /password|passwd|passphrase|passcode|secret|token|apikey|accesskey|privatekey|signingkey|masterkey|encryptionkey|accountkey|credential|creds|bearer|cookie|authorization|requirepass|masterauth|storepass|keypass|newpass|oldpass|pwd/;
const CREDENTIAL_WORDS = new Set(['pass', 'pw', 'otp', 'totp', 'pat', 'jwt']);
/** A name part that contains `pass` names a password (DBPASS, ADMINPASS), except these ordinary words. */
const PASS_WORDS_NOT_SECRET = /bypass|compass|passage|passive|passeng|passport|passthr|surpass|overpass|underpass|trespass|passover|passable|passing|passed|passes/;
const holdsPass = (part) => part.includes('pass') && !PASS_WORDS_NOT_SECRET.test(part);
const CREDENTIAL_PAIRS = ['api_key', 'access_key', 'private_key', 'secret_key', 'signing_key', 'master_key', 'encryption_key', 'account_key', 'auth_key'];
const AMBIGUOUS_WORDS = new Set(['auth', 'oauth', 'key', 'keys', 'session', 'sessionid', 'sid', 'signature', 'sig', 'pin', 'cred', 'hmac', 'sk']);
const REFERENCE_LAST = new Set([
    'file', 'files', 'path', 'paths', 'dir', 'name', 'names', 'id', 'ids', 'arn', 'ref', 'uri', 'url', 'type', 'mode',
    'ttl', 'length', 'size', 'scope', 'scopes', 'expiry', 'expires', 'version', 'alias', 'env', 'region', 'policy',
    'count', 'limit', 'fd', 'stdin', 'prompt', 'rotation', 'format', 'algorithm', 'alg', 'method', 'provider', 'store',
    'helper', 'command', 'cmd', 'prefix', 'field', 'var', 'location', 'endpoint', 'host', 'port', 'user', 'username', 'email',
]);
/**
 * What a value under this name is: a credential (replaced; the action stays
 * exact), ambiguous (replaced; the action is marked truncated), a reference
 * to a secret such as its file, name or id (kept), or plain (kept).
 */
function classifySecretName(name) {
    const parts = nameParts(name);
    if (!parts.length)
        return 'plain';
    const joined = parts.join('_');
    const credential = parts.some((part) => CREDENTIAL_STEM.test(part) || CREDENTIAL_WORDS.has(part) || holdsPass(part))
        || CREDENTIAL_PAIRS.some((pair) => joined === pair || joined.startsWith(`${pair}_`) || joined.endsWith(`_${pair}`) || joined.includes(`_${pair}_`));
    const ambiguous = !credential && parts.some((part) => AMBIGUOUS_WORDS.has(part));
    if (!credential && !ambiguous)
        return 'plain';
    const last = parts[parts.length - 1];
    if (REFERENCE_LAST.has(last))
        return 'reference';
    return credential ? 'credential' : 'ambiguous';
}
function holdsSecret(name) {
    const kind = classifySecretName(name);
    return kind === 'credential' || kind === 'ambiguous';
}
/** A name part that ends in a credential word (DB_PASSWORD, PGPASSWORD, GITHUB_TOKEN, ADMINPASS), not one that only starts with it. */
const CERTAIN_END = /(?:password|passwd|passphrase|passcode|secret|token|apikey|accesskey|privatekey|signingkey|masterkey|encryptionkey|accountkey|credential|creds|bearer|cookie|authorization|requirepass|masterauth|storepass|keypass|newpass|oldpass|pwd)$/;
/**
 * classifySecretName, except that the exact pass (exact_hmac, never sent) reads a credential name as certain only
 * when a part ends in a credential word, is one (otp, pat, jwt), or the name holds a pair (api_key): a value under
 * `passwordless`, `SECRETNAME`, `TOKENID`, `max_tokens` or `credentials` may name or count something that decides
 * the action, so the exact pass keeps it (as an ambiguous value). Pass 1 is unchanged.
 */
function nameClass(name, state) {
    const kind = classifySecretName(name);
    if (!state.exact || kind !== 'credential')
        return kind;
    const parts = nameParts(name);
    const joined = parts.join('_');
    const pair = CREDENTIAL_PAIRS.some((item) => joined === item || joined.startsWith(`${item}_`) || joined.endsWith(`_${item}`) || joined.includes(`_${item}_`));
    const certain = pair || parts.some((part) => CREDENTIAL_WORDS.has(part) || CERTAIN_END.test(part) || (holdsPass(part) && part.endsWith('pass')));
    return certain ? 'credential' : 'ambiguous';
}
// ---------------------------------------------------------------------------
// Secrets inside a text
// ---------------------------------------------------------------------------
// Every pattern starts at a boundary (lookbehind) and bounds its repeats, so
// a scan is linear in the text: no start inside a run, no unbounded backtracking.
const URL_CREDENTIALS = /(?<![a-z0-9+.-])([a-z][a-z0-9+.-]{0,31}:\/\/)([^\s/@:'"]{0,256}):([^\s/@'"]{1,1024})@/gi;
/** An auth scheme (any case for Bearer and Basic) followed by a token-shaped value; the value is read by hand. */
const AUTH_SCHEME = /\b([Bb][Ee][Aa][Rr][Ee][Rr]|[Bb][Aa][Ss][Ii][Cc]|BEARER|BASIC|Token|Bot)([ \t]{1,8})(?=[A-Za-z0-9._~+/=-]{8})/g;
const URL_CODE = /([?&])((?:auth(?:orization)?_)?code)=/gi;
/** A name and its separator (`name=`, `name: `, `"name": `); the value is read by hand after it. */
const NAME_SEPARATOR = /(["']?)(?<![A-Za-z0-9_.-])([A-Za-z_][A-Za-z0-9_.-]{0,127})\1([ \t]{0,8}[:=][ \t]{0,8})/g;
/** After a separator: an identifier-like field name and its own separator (`env=`, `env:`, `"env":`). */
const FIELD_AHEAD = /[ \t]{0,8}(["']?)[A-Za-z_][A-Za-z0-9_.-]{0,127}\1[ \t]{0,8}[=:]/y;
function fieldAhead(text, at) {
    FIELD_AHEAD.lastIndex = at;
    return FIELD_AHEAD.test(text);
}
/**
 * Where an unquoted credential value ends (one rule for every path): at
 * whitespace or a quote; at `&`, `;` or `|` only when an identifier-like
 * `name=`/`name:` field or a shell operator boundary (whitespace) follows; at
 * `#` or `,` only when a `name=`/`name:` field follows. Anything else
 * (`ab#cd`, `ab,cd`, `ab&cd`, `ab)cd`) is part of the value, so no part of a
 * password stays in the normalized text. `wordOnly`: the value is one shell
 * word, so whitespace and quotes inside it are part of it.
 */
function credentialValueEnd(text, start, wordOnly = false) {
    let i = start;
    while (i < text.length) {
        const c = text[i];
        if (!wordOnly && (c === '"' || c === '\'' || /\s/.test(c)))
            return i;
        if (c === '&' || c === ';' || c === '|') {
            let j = i + 1;
            while (j < text.length && (text[j] === '&' || text[j] === ';' || text[j] === '|'))
                j += 1;
            if ((!wordOnly && j < text.length && /\s/.test(text[j])) || fieldAhead(text, j))
                return i;
            i = j;
            continue;
        }
        if ((c === '#' || c === ',') && fieldAhead(text, i + 1))
            return i;
        i += 1;
    }
    return i;
}
/**
 * A credential value that itself holds `name=value` (beyond base64 `=`
 * padding) may have carried more than the credential: withholding it could
 * merge different actions, so the action is marked truncated.
 */
function holdsMoreThanCredential(value) {
    return /=(?!=*$)/.test(value);
}
/**
 * A credential value followed by another field (`S,env=prod`, `S&env=prod`)
 * is cut at that separator: the rest stays in the hashed form, so actions
 * that differ after it stay different, and the action is marked truncated
 * (never bound), since the separator may have been part of the credential.
 * Without a following `name=` field the whole value is the credential.
 */
function cutCredential(value, state) {
    const at = credentialValueEnd(value, 0, true);
    if (at >= value.length) {
        if (holdsMoreThanCredential(value))
            return withheld(state, value);
        return SECRET;
    }
    state.truncated = true; // exact: certain (the credential before the field; the rest is scanned in the same pass)
    return SECRET + redactText(value.slice(at), state);
}
/** One-value auth header (`Authorization: Bearer X`, `X-Api-Key: K`): the whole value is the credential. */
const SINGLE_VALUE_HEADER = /^[^:\s]{1,128}:[ \t]*(?:(?:Bearer|Basic|Token|Bot)[ \t]+)?[^\s;,&]+[ \t]*$/i;
/**
 * Replaces the secrets inside one word or text: URL passwords, auth header
 * values, OAuth codes, credential-named literals (credentials; ambiguous
 * names mark the action truncated) and key-shaped values.
 */
function redactText(text, state) {
    // Not scanned (the exact pass keeps it as it is).
    if (text.length > exports.MAX_SCAN_CHARS)
        return withheld(state, text);
    spend(state, text.length);
    // A short word without a separator cannot hold any of these (keys need 12 or more characters).
    if (text.length < 12 && !/[:=?&@\s]/.test(text))
        return text;
    // M2-R1: a `#` or `?` in the password ends the URL authority for URL parsers (`https://deploy:443#@host`
    // goes to host `deploy`), while libpq, mysql and redis clients take the whole span as the password. It is
    // hidden either way, but it is not a certain credential: the action is marked truncated and the exact pass
    // keeps the span, so it never shares a key with `https://deploy:<pw>@host`.
    let out = text.replace(URL_CREDENTIALS, (_match, scheme, user, password) => (`${scheme}${user}:${/[#?]/.test(password) ? withheld(state, password) : SECRET}@`));
    // The exact pass keeps a `Token`/`Bot` value that is not key-shaped (`git commit -m "Token rotation"`).
    out = replaceValuesAfter(out, AUTH_SCHEME, state.exact ? (scheme, value) => /^(?:Token|Bot)$/.test(scheme) && !looksLikeKey(value) : null);
    // The exact pass keeps a URL `code` value: it may be an OAuth code, but it may as well be a country or product code.
    out = replaceValuesAfter(out, URL_CODE, state.exact ? () => true : null);
    return redactKeyShapes(redactAssignments(out, state), state);
}
/**
 * Replaces the value after each match of `pattern` (an auth scheme, an OAuth code), ended by the shared rule.
 * `keep` (exact pass only): a value it returns true for stays as it is.
 */
function replaceValuesAfter(text, pattern, keep) {
    pattern.lastIndex = 0;
    let out = '';
    let copied = 0;
    for (let match = pattern.exec(text); match; match = pattern.exec(text)) {
        const start = match.index + match[0].length;
        const end = credentialValueEnd(text, start);
        if (end <= start) {
            pattern.lastIndex = start + 1;
            continue;
        }
        if (keep && keep(match[1], text.slice(start, end))) {
            pattern.lastIndex = end;
            continue;
        }
        out += text.slice(copied, start) + SECRET;
        copied = end;
        pattern.lastIndex = end;
    }
    return out + text.slice(copied);
}
/**
 * Credential-named literals (`name=value`, `name: value`, `"name": "value"`),
 * also nested in a plain value (a URL query): one pass, no recursion. After a
 * plain name the scan continues inside its value; after a credential name the
 * value is replaced and skipped. Too many names in one text: it is withheld.
 */
function redactAssignments(text, state) {
    const pattern = NAME_SEPARATOR;
    pattern.lastIndex = 0;
    let out = '';
    let copied = 0;
    let matches = 0;
    for (let match = pattern.exec(text); match; match = pattern.exec(text)) {
        matches += 1;
        // Too many names to scan: withheld (the exact pass keeps the text as it is).
        if (matches > MAX_ASSIGNMENTS)
            return withheld(state, text);
        const kind = nameClass(match[2], state);
        if (kind !== 'credential' && kind !== 'ambiguous')
            continue;
        let start = match.index + match[0].length;
        let end = start;
        const quote = text[start] === '"' || text[start] === '\'' ? text[start] : '';
        if (quote) {
            start += 1;
            const close = text.indexOf(quote, start);
            end = close;
        }
        if (!quote || end < 0)
            end = credentialValueEnd(text, start);
        if (end <= start)
            continue;
        const value = text.slice(start, end);
        if (!value.startsWith('[secret') && !value.startsWith('[data:')) {
            const replacement = kind === 'ambiguous' || holdsMoreThanCredential(value) ? withheld(state, value) : SECRET;
            out += text.slice(copied, start) + replacement;
            copied = end;
        }
        pattern.lastIndex = end;
    }
    return out + text.slice(copied);
}
/**
 * Data a command reads: its SHA-256 in the hashed form; `[secret]` and
 * truncated when it feeds a secrets command or file (all of it is the
 * secret); the SHA-256 of its redacted form and truncated when it looks secret.
 */
function dataMarker(text, feedsSecrets, state, words = null) {
    if (state.exact) {
        // The exact pass: only the certain credentials inside the data are replaced and the rest is hashed, also for
        // data a secrets command or file reads (a vault policy, an authorized_keys line, a kubeconfig differ outside
        // any secret), so data that differs outside a certain credential never shares exact material.
        const probe = { truncated: false, budget: state.budget, exact: true, sigs: [] };
        return `[data:${sha256(`${HASH_VERSION}\nexact-data\n${redactText(text, probe)}`)}]`;
    }
    if (feedsSecrets) {
        state.truncated = true; // exact: kept (hashed above, certain credentials replaced)
        return SECRET;
    }
    // Secret-shaped data (`'{"api_key":"S","env":"production"}'`): the secrets are
    // replaced and the rest is hashed, so data that differs outside a secret gives
    // a different key, data that differs only in a secret the same one. Withheld:
    // the action is truncated and never binds an approval.
    const probe = { truncated: false, budget: state.budget, exact: false, sigs: [] };
    const redacted = redactText(text, probe);
    if (redacted !== text) {
        state.truncated = true; // exact: kept (hashed above, certain credentials replaced)
        return `[secret-data:${sha256(`${HASH_VERSION}\nsecret-data\n${redacted}`)}]`;
    }
    // Printed words (`words`): hashed as their list, so word boundaries count.
    return words === null ? `[data:${sha256(`${HASH_VERSION}\ndata\n${text}`)}]` : `[data:${sha256(`${HASH_VERSION}\nwords\n${JSON.stringify(words)}`)}]`;
}
/**
 * Text echoed or printed into a pipe or a file: probed for secrets as the shell joins it (one space), as
 * before; hashed as the list of printed words, so word boundaries and flags count (`echo -n X` is not
 * `echo "-n X"`, `printf '%s\n' a b` is not `printf '%s\n' 'a b'`). The exact pass replaces the certain
 * credentials word by word and keeps the boundaries too.
 */
function printedData(words, feedsSecrets, state) {
    if (state.exact) {
        const probe = { truncated: false, budget: state.budget, exact: true, sigs: [] };
        return `[data:${sha256(`${HASH_VERSION}\nexact-words\n${JSON.stringify(words.map((word) => redactText(word, probe)))}`)}]`;
    }
    return dataMarker(words.join(' '), feedsSecrets, state, words);
}
const OPERATORS = ['<<<', '&&', '||', '|&', '>>', '<<', ';;', '|', '&', ';', '<', '>', '(', ')', '\n'];
/**
 * Splits a command into words and operators, honoring quotes and escapes (an approximation of the shell).
 * `crIsWord` (the exact pass): a CR is a word character, as it is to the shell.
 */
function tokenize(command, crIsWord = false) {
    const tokens = [];
    let current = '';
    let started = false;
    const push = () => {
        if (started)
            tokens.push({ value: current, op: false });
        current = '';
        started = false;
    };
    for (let i = 0; i < command.length; i += 1) {
        const ch = command[i];
        if (ch === '\\' && i + 1 < command.length) {
            current += command[i + 1];
            started = true;
            i += 1;
            continue;
        }
        if (ch === '\'' || ch === '"') {
            const end = command.indexOf(ch, i + 1);
            const body = end < 0 ? command.slice(i + 1) : command.slice(i + 1, end);
            current += ch === '"' ? body.replace(/\\(["\\$`])/g, '$1') : body;
            started = true;
            i = end < 0 ? command.length : end;
            continue;
        }
        if (ch === ' ' || ch === '\t' || (ch === '\r' && !crIsWord)) {
            push();
            continue;
        }
        const op = OPERATORS.find((candidate) => command.startsWith(candidate, i));
        if (op) {
            push();
            tokens.push({ value: op === '\n' ? ';' : op, op: true });
            i += op.length - 1;
            continue;
        }
        current += ch;
        started = true;
    }
    push();
    return tokens;
}
/** A placeholder word for a heredoc body or here-string, resolved per command. */
function slotWord(slot) {
    return `\u0000${slot}\u0000`;
}
const SLOT = /^\u0000(\d+)\u0000$/;
/**
 * Heredoc bodies are input to the command, never part of it: each is moved
 * to `data` and its place marked, before tokenizing.
 */
function extractHeredocs(command, data) {
    const lines = command.split('\n');
    const out = [];
    const pending = [];
    for (let n = 0; n < lines.length; n += 1) {
        if (pending.length) {
            const doc = pending.shift();
            const body = [];
            let closed = false;
            for (; n < lines.length; n += 1) {
                if (lines[n].replace(/^[ \t]+|[ \t]+$/g, '') === doc.tag) {
                    closed = true;
                    break;
                }
                body.push(doc.dash ? lines[n].replace(/^\t+/, '') : lines[n]);
            }
            data[doc.slot] = body.join('\n');
            if (!closed)
                break;
            continue;
        }
        out.push(lines[n].replace(/(?<!<)<<(-?)[ \t]*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\2/g, (_match, dash, _quote, tag) => {
            data.push('');
            const slot = data.length - 1;
            pending.push({ tag, dash: dash === '-', slot });
            return `<<${tag} ${slotWord(slot)} `;
        }));
    }
    return out.join('\n');
}
const WRAPPERS = new Set(['sudo', 'doas', 'env', 'time', 'nohup', 'exec', 'command', 'nice', 'ionice', 'stdbuf', 'timeout', 'xargs', 'npx', 'bunx', 'pnpx']);
const SHELLS = /^(?:ba|z|da|k|fi|tc|c)?sh$/;
const MYSQL_FAMILY = new Set(['mysql', 'mariadb', 'mysqldump', 'mysqladmin', 'mysqlimport', 'mysqlshow', 'mysqlcheck', 'mysqlsh']);
const MONGO_FAMILY = new Set(['mongo', 'mongosh', 'mongodump', 'mongorestore', 'mongoexport', 'mongoimport', 'mongostat', 'mongotop', 'mongofiles']);
/** `-p` is always the password. */
const ALWAYS_P = new Set(['sshpass', 'twine', 'useradd', 'usermod', ...MONGO_FAMILY]);
/** `-p` is the password in a `login` subcommand. */
const LOGIN_P = new Set(['docker', 'podman', 'nerdctl', 'buildah', 'helm', 'oras', 'crane', 'skopeo', 'regctl', 'az', 'oc', 'cf']);
/** `-P` is the password. */
const UPPER_P = new Set(['sqlcmd', 'bcp', 'osql', 'isql']);
const REDIS_FAMILY = new Set(['redis-cli', 'keydb-cli', 'valkey-cli']);
const CURL_FAMILY = new Set(['curl', 'wget', 'http', 'https', 'xh']);
const OPENSSL_PASS_FLAGS = new Set(['-pass', '-passin', '-passout', '-k', '-kfile', '-password']);
const AUTH_HEADER = /authorization|token|key|secret|cookie|bearer|basic/i;
/** Flags of secrets commands whose value is a target, never the secret (`gh secret set N --repo org/app`). */
const SECRET_COMMAND_VALUE_FLAGS = new Set([
    'repo', 'repos', 'env', 'environment', 'org', 'app', 'application', 'namespace', 'context', 'cluster', 'project',
    'config', 'mount', 'visibility', 'type', 'scope', 'region', 'profile', 'account', 'team', 'target', 'stage',
    'service', 'site', 'path', 'name', 'vault',
]);
const SECRET_COMMAND_SHORT_VALUE_FLAGS = {
    gh: new Set(['-R', '-e', '-o', '-a', '-v']),
    kubectl: new Set(['-n']),
    oc: new Set(['-n']),
    doppler: new Set(['-p', '-c']),
};
function secretCommandValueFlag(program, flag) {
    if (flag.startsWith('--'))
        return SECRET_COMMAND_VALUE_FLAGS.has(flag.slice(2).toLowerCase());
    return SECRET_COMMAND_SHORT_VALUE_FLAGS[program]?.has(flag) ?? false;
}
const SSH_VALUE_FLAGS = new Set(['-b', '-c', '-D', '-E', '-e', '-F', '-I', '-i', '-J', '-L', '-l', '-m', '-O', '-o', '-p', '-Q', '-R', '-S', '-W', '-w']);
/** Programs that take secrets on their input. */
const SECRET_PROGRAMS = new Set([
    'vault', 'op', 'pass', 'gopass', 'sops', 'age', 'kubeseal', 'ssh-add', 'sshpass', 'chpasswd', 'passwd', 'htpasswd',
    'keytool', 'security', 'gpg', 'gpg2', 'systemd-creds', 'bw', 'lpass', 'doppler', 'infisical', 'dotenvx', 'secret-tool',
]);
const SECRET_FILE = /(?:^|\/)\.env(?:[.\w-]*)$|\.(?:pem|key|p12|pfx|jks|keystore|kdbx|gpg|asc|ppk)$|(?:^|\/)id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$|(?:^|\/)\.(?:npmrc|netrc|pgpass|git-credentials|pypirc|dockercfg|htpasswd|my\.cnf)$|(?:^|\/)\.docker\/config\.json$|(?:^|\/)\.kube\/config$|kubeconfig|authorized_keys|credential|secret|token|passw|(?:^|[/._-])pass(?:$|[/._-])|(?:^|\/)shadow$/i;
const REDIRECTS = new Set(['>', '>>', '<', '<<', '<<<']);
function basename(word) {
    return word.replace(/^.*\//, '');
}
const ASSIGNMENT = /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/s;
function parseSegment(words) {
    let index = 0;
    while (index < words.length && ASSIGNMENT.test(words[index]))
        index += 1;
    while (index < words.length && WRAPPERS.has(basename(words[index]))) {
        index += 1;
        while (index < words.length && (words[index].startsWith('-') || ASSIGNMENT.test(words[index]) || /^\d+[smhd]?$/.test(words[index])))
            index += 1;
    }
    const program = index < words.length ? basename(words[index]).toLowerCase() : null;
    const plain = [];
    const targets = [];
    for (let i = index + 1; i < words.length; i += 1) {
        const word = words[i];
        if (REDIRECTS.has(word)) {
            if ((word === '>' || word === '>>') && i + 1 < words.length)
                targets.push(words[i + 1]);
            // Skip the file, the heredoc tag (and its body slot) or the here-string slot.
            i += 1;
            if (word === '<<' && i + 1 < words.length && SLOT.test(words[i + 1]))
                i += 1;
            continue;
        }
        if (SLOT.test(word))
            continue;
        plain.push(i);
    }
    return { index, program, plain, targets };
}
function isSecretFile(path) {
    return SECRET_FILE.test(path);
}
function programStem(program) {
    return program.replace(/\.(?:sh|bash|py|js|mjs|ts|rb|pl|ps1|exe)$/i, '');
}
/** env stores: values set there may be secrets (`netlify env:set`, `heroku config:set`, `railway variables set`). */
function storeContext(positionals) {
    return positionals.some((word, i) => /^(?:env|config|variables?|vars?|secrets?):(?:set|add|push|import|create|update|put)$/.test(word)
        || (/^(?:env|variables?|vars?)$/.test(word) && /^(?:set|add|push|import|put|create|update)$/.test(positionals[i + 1] ?? '')));
}
/** Whether a command takes secrets on its input (data fed to it is withheld). */
function takesSecrets(words, parsed) {
    const { program } = parsed;
    if (!program)
        return false;
    if (SECRET_PROGRAMS.has(programStem(program)) || classifySecretName(programStem(program)) === 'credential')
        return true;
    const args = parsed.plain.map((i) => words[i]);
    const positionals = args.filter((word) => !word.startsWith('-')).slice(0, 4).map((word) => word.toLowerCase());
    if (positionals.some((word) => /secret|credential|passw|token|login|keychain|keyring|keyvault/.test(word) || /^o?auth$/.test(word) || /:auth$/.test(word)))
        return true;
    if (program === 'aws' && positionals[0] === 'configure')
        return true;
    if (storeContext(positionals))
        return true;
    if (args.some((word) => /^--?with-token(?:=|$)/.test(word) || (/^--?[a-z-]+-(?:stdin|fd)(?:=|$)/i.test(word) && holdsSecret(word.replace(/^-+/, '').replace(/-(?:stdin|fd)(?:=.*)?$/i, '')))))
        return true;
    if (program === 'tee' && positionals.some(isSecretFile))
        return true;
    return parsed.targets.some(isSecretFile);
}
function assignedValue(name, value, state) {
    const kind = nameClass(name, state);
    if (kind === 'credential' || kind === 'ambiguous') {
        if (kind === 'ambiguous' || holdsMoreThanCredential(value))
            return `${name}=${withheld(state, state.exact ? dataMarker(value, false, state) : value)}`;
        return `${name}=${SECRET}`;
    }
    return value ? `${name}=${dataMarker(value, false, state)}` : `${name}=`;
}
/** Normalizes one simple command (a segment between operators); returns its words and program name. */
function redactSegment(words, ctx) {
    const { state } = ctx;
    const out = [...words];
    const handled = new Set();
    const removed = new Set();
    const parsed = parseSegment(out);
    const { index, program, targets } = parsed;
    // Environment assignments before the program (and a wrapper's own, as in `env X=1 cmd`).
    for (let i = 0; i < index; i += 1) {
        const match = ASSIGNMENT.exec(out[i]);
        if (match) {
            out[i] = assignedValue(match[1], match[2], state);
            handled.add(i);
        }
    }
    // Input data: heredoc bodies and here-strings go to this command and on through a pipe.
    const downstreamTakes = ctx.pipedOut && ctx.downstreamTakes;
    const secretTarget = targets.some(isSecretFile);
    const feedsHere = takesSecrets(out, parsed) || downstreamTakes || secretTarget;
    for (let i = 0; i < out.length; i += 1) {
        const slot = SLOT.exec(out[i]);
        if (!slot)
            continue;
        out[i] = dataMarker(ctx.data[Number(slot[1])] ?? '', feedsHere, state);
        handled.add(i);
    }
    const finish = () => {
        const result = [];
        out.forEach((word, i) => {
            if (removed.has(i))
                return;
            result.push(handled.has(i) ? word : redactText(word, state));
        });
        return { words: result, program };
    };
    if (!program)
        return finish();
    // Text echoed or printed into a pipe or a file is data.
    if ((program === 'echo' || program === 'printf') && (ctx.pipedOut || targets.length)) {
        const printed = parsed.plain;
        if (printed.length) {
            out[printed[0]] = printedData(printed.map((i) => out[i]), downstreamTakes || secretTarget, state);
            handled.add(printed[0]);
            for (const i of printed.slice(1))
                removed.add(i);
        }
        return finish();
    }
    // export / declare NAME=value: like a leading assignment.
    if (['export', 'declare', 'typeset', 'local', 'readonly', 'set'].includes(program)) {
        for (const i of parsed.plain) {
            const match = ASSIGNMENT.exec(out[i]);
            if (match) {
                out[i] = assignedValue(match[1], match[2], state);
                handled.add(i);
            }
        }
        return finish();
    }
    // Commands inside the command: `bash -c CMD`, `ssh HOST CMD …`, `eval …`, `su -c CMD`.
    const embed = (at, text, also = []) => {
        if (ctx.depth >= MAX_DEPTH) {
            out[at] = withheld(state, text);
        }
        else {
            out[at] = normalizeInner(text, state, ctx.depth + 1).text;
        }
        handled.add(at);
        for (const i of also)
            removed.add(i);
    };
    const plainWords = parsed.plain;
    if (program === 'eval' && plainWords.length) {
        embed(plainWords[0], plainWords.map((i) => out[i]).join(' '), plainWords.slice(1));
    }
    else if (program === 'ssh' || program === 'autossh') {
        let k = 0;
        while (k < plainWords.length && out[plainWords[k]].startsWith('-')) {
            k += SSH_VALUE_FLAGS.has(out[plainWords[k]]) ? 2 : 1;
        }
        const remote = plainWords.slice(k + 1);
        if (remote.length)
            embed(remote[0], remote.map((i) => out[i]).join(' '), remote.slice(1));
    }
    else if (program === 'su') {
        for (let k = 0; k < plainWords.length; k += 1) {
            const word = out[plainWords[k]];
            if ((word === '-c' || word === '--command') && k + 1 < plainWords.length) {
                embed(plainWords[k + 1], out[plainWords[k + 1]]);
                break;
            }
            if (word.startsWith('--command=')) {
                const text = word.slice('--command='.length);
                embed(plainWords[k], text);
                out[plainWords[k]] = `--command=${out[plainWords[k]]}`;
                break;
            }
        }
    }
    const shellAt = [index, ...plainWords];
    for (let k = 0; k + 2 < shellAt.length; k += 1) {
        if (handled.has(shellAt[k + 2]) || removed.has(shellAt[k + 2]))
            continue;
        if (SHELLS.test(basename(out[shellAt[k]]).toLowerCase()) && /^-[a-zA-Z]*c$/.test(out[shellAt[k + 1]])) {
            embed(shellAt[k + 2], out[shellAt[k + 2]]);
        }
    }
    const args = plainWords.filter((i) => !handled.has(i) && !removed.has(i));
    const positionals = args.filter((i) => !out[i].startsWith('-'));
    const positionOf = new Map(positionals.map((i, position) => [i, position]));
    const lastArg = args[args.length - 1];
    const htpasswdBatch = program === 'htpasswd' && args.some((value) => /^-[a-zA-Z]*b/.test(out[value]));
    const subcommands = positionals.slice(0, 3).map((i) => out[i].toLowerCase());
    const lowered = positionals.map((i) => out[i].toLowerCase());
    // A secrets command is named by a bare subcommand word (`gh secret set`, `vault kv put secret/app`),
    // never by a field inside a form body, query or JSON (`client_secret=K&path=/a`).
    const secretContext = subcommands.some((word) => /secret/.test(word) && /^[a-z0-9][a-z0-9_.:\/-]*$/.test(word));
    const loginContext = subcommands.includes('login');
    const envStore = storeContext(lowered.slice(0, 4));
    const stem = programStem(program);
    const redactAt = (i, ambiguous = false) => {
        out[i] = ambiguous || holdsMoreThanCredential(out[i]) ? withheld(state, out[i]) : SECRET;
        handled.add(i);
    };
    // An auth header: a one-value header is the credential; any other (`Cookie: a=1; env=prod`)
    // keeps its other fields, with the credentials inside replaced.
    const redactHeaderValue = (header) => {
        if (SINGLE_VALUE_HEADER.test(header)) {
            const colon = header.indexOf(':');
            const value = header.slice(colon + 1);
            if (holdsMoreThanCredential(value))
                return withheld(state, header);
            if (!state.exact)
                return SECRET;
            // The exact pass: the value of a credential header (or a Bearer/Basic value) is certain; any other
            // one-value header (`X-Idempotency-Key: k`) and the header name are kept.
            const name = header.slice(0, colon);
            if (nameClass(name, state) !== 'credential' && !/^[ \t]*(?:Bearer|Basic)[ \t]/i.test(value))
                return header;
            // Basic USER:PASSWORD names who acts, as `curl -u` does: only the password is certain.
            const basic = /^[ \t]*Basic[ \t]+([A-Za-z0-9+/]+={0,2})[ \t]*$/i.exec(value);
            const decoded = basic ? Buffer.from(basic[1], 'base64').toString('latin1') : '';
            return /^[\x20-\x7e]*:/.test(decoded) ? `${name}:Basic ${JSON.stringify(decoded.slice(0, decoded.indexOf(':')))}:${SECRET}` : `${name}:${SECRET}`;
        }
        const redacted = redactText(header, state);
        return redacted === header ? withheld(state, header) : redacted;
    };
    // curl -b/--cookie NAME=VALUE[; …] is a Cookie header (without `=` it names a cookie file).
    const redactCookieValue = (value) => {
        if (!value.includes('='))
            return value;
        const redacted = redactHeaderValue(`Cookie: ${value}`);
        return redacted.startsWith('Cookie: ') ? redacted.slice('Cookie: '.length) : redacted;
    };
    // A credential `NAME=value` argument: a form body (`api_key=K&sql=DROP`) keeps its other fields.
    const credentialArgument = (name, value) => {
        if (/[&#]/.test(value))
            return redactText(`${name}=${value}`, state);
        return `${name}=${cutCredential(value, state)}`;
    };
    // The exact pass: `curl -u USER:PASSWORD` names who acts; only the password is certain.
    const exactUser = (value) => (value.includes(':') ? `${value.slice(0, value.indexOf(':'))}:${SECRET}` : value);
    // The exact pass: openssl `pass:X` and a bare value are the password; `env:`, `file:`, `fd:` name where it is.
    const exactOpensslPass = (value) => (/^(?:env|file|fd):/.test(value) ? value : /^pass:/.test(value) ? `pass:${SECRET}` : SECRET);
    // A program named for a secret (set-password.sh): its arguments cannot be told apart (the exact pass keeps them).
    if (!SECRET_PROGRAMS.has(stem) && classifySecretName(stem) === 'credential') {
        for (const i of positionals)
            redactAt(i, true);
    }
    let afterSecretWord = -1;
    for (let k = 0; k < args.length; k += 1) {
        const i = args[k];
        if (handled.has(i))
            continue;
        const arg = out[i];
        const valueAt = () => {
            const j = args[k + 1];
            return j !== undefined && !handled.has(j) && !out[j].startsWith('-') ? j : null;
        };
        // `exactForm` (exact pass only): the certain part of a value that also names something (a user, a file).
        const next = (ambiguous = false, exactForm = null) => {
            const j = valueAt();
            if (j !== null) {
                if (ambiguous)
                    out[j] = state.exact ? withheld(state, out[j]) : withheld(state, out[j], cutCredential(out[j], state));
                else
                    out[j] = state.exact && exactForm ? exactForm(out[j]) : cutCredential(out[j], state);
                handled.add(j);
                k += 1;
            }
        };
        const attachedOrNext = (prefix) => {
            if (arg.length > prefix.length) {
                out[i] = `${prefix}${SECRET}`;
                handled.add(i);
            }
            else {
                next();
            }
        };
        const byName = (name) => {
            const kind = nameClass(name, state);
            if (kind === 'credential')
                next();
            else if (kind === 'ambiguous')
                next(true);
        };
        // --flag=value (or -flag=value)
        const long = /^(--?[A-Za-z0-9][A-Za-z0-9_.-]*)=(.*)$/s.exec(arg);
        if (long) {
            const name = long[1].replace(/^-+/, '');
            if (name === 'from-literal' || name === 'from-env-literal') {
                const replaced = `${long[1]}=${long[2].replace(/^([^=]*)=.*$/s, `$1=${SECRET}`)}`;
                out[i] = holdsMoreThanCredential(long[2].replace(/^[^=]*=/, '')) ? withheld(state, arg, replaced) : replaced;
                handled.add(i);
            }
            else if (CURL_FAMILY.has(program) && /^(?:u|user|proxy-user)$/.test(name)) {
                out[i] = `${long[1]}=${state.exact ? exactUser(long[2]) : SECRET}`;
                handled.add(i);
            }
            else if (CURL_FAMILY.has(program) && name === 'header' && AUTH_HEADER.test(long[2])) {
                out[i] = `${long[1]}=${redactHeaderValue(long[2])}`;
                handled.add(i);
            }
            else if (CURL_FAMILY.has(program) && name === 'cookie') {
                out[i] = `${long[1]}=${redactCookieValue(long[2])}`;
                handled.add(i);
            }
            else if (holdsSecret(name)) {
                const kind = nameClass(name, state);
                if (kind === 'ambiguous')
                    out[i] = withheld(state, arg, `${long[1]}=${cutCredential(long[2], state)}`);
                else if (kind === 'credential')
                    out[i] = `${long[1]}=${cutCredential(long[2], state)}`;
                handled.add(i);
            }
            continue;
        }
        // --flag value
        if (/^--[A-Za-z0-9]/.test(arg)) {
            const name = arg.slice(2);
            if (CURL_FAMILY.has(program) && /^(?:user|proxy-user)$/.test(name))
                next(false, exactUser);
            else if (CURL_FAMILY.has(program) && name === 'header') {
                const j = valueAt();
                if (j !== null && AUTH_HEADER.test(out[j])) {
                    out[j] = redactHeaderValue(out[j]);
                    handled.add(j);
                    k += 1;
                }
            }
            else if (CURL_FAMILY.has(program) && name === 'cookie') {
                const j = valueAt();
                if (j !== null) {
                    out[j] = redactCookieValue(out[j]);
                    handled.add(j);
                    k += 1;
                }
            }
            else if (program === 'gh' && secretContext && name === 'body')
                next();
            else
                byName(name);
            continue;
        }
        // Short flags by program; single-dash long names (-password, -token) by name.
        if (/^-[A-Za-z]/.test(arg)) {
            if (MYSQL_FAMILY.has(program) && /^-p.+/.test(arg)) {
                out[i] = `-p${SECRET}`;
                handled.add(i);
            }
            else if (ALWAYS_P.has(program) && /^-p/.test(arg))
                attachedOrNext('-p');
            else if (LOGIN_P.has(program) && loginContext && /^-p/.test(arg))
                attachedOrNext('-p');
            else if (UPPER_P.has(program) && /^-P/.test(arg))
                attachedOrNext('-P');
            else if (REDIS_FAMILY.has(program) && /^-a/.test(arg))
                attachedOrNext('-a');
            else if (CURL_FAMILY.has(program) && (arg === '-u' || arg === '-U'))
                next(false, exactUser);
            else if (CURL_FAMILY.has(program) && arg === '-H') {
                const j = valueAt();
                if (j !== null && AUTH_HEADER.test(out[j])) {
                    out[j] = redactHeaderValue(out[j]);
                    handled.add(j);
                    k += 1;
                }
            }
            else if (CURL_FAMILY.has(program) && arg === '-b') {
                const j = valueAt();
                if (j !== null) {
                    out[j] = redactCookieValue(out[j]);
                    handled.add(j);
                    k += 1;
                }
            }
            else if (program === 'openssl' && OPENSSL_PASS_FLAGS.has(arg))
                next(false, arg === '-kfile' ? (value) => value : exactOpensslPass);
            else if (program === 'gh' && secretContext && arg === '-b')
                next();
            else if (/^-[A-Za-z][A-Za-z0-9_-]{2,}$/.test(arg))
                byName(arg.slice(1));
            continue;
        }
        // NAME=value arguments: a credential name, any value in a secrets command, env-store values.
        const assignment = ASSIGNMENT.exec(arg);
        if (assignment) {
            const [, name, value] = assignment;
            if (secretContext) {
                // In a secrets command every value is a secret: withheld whole, and truncated if it held more fields.
                out[i] = /[&#]/.test(value) || holdsMoreThanCredential(value) ? withheld(state, arg, `${name}=${SECRET}`) : `${name}=${SECRET}`;
                handled.add(i);
            }
            else if (holdsSecret(name)) {
                const kind = nameClass(name, state);
                if (kind === 'ambiguous')
                    out[i] = withheld(state, arg, credentialArgument(name, value));
                else if (kind === 'credential')
                    out[i] = credentialArgument(name, value);
                else
                    out[i] = redactText(arg, state);
                handled.add(i);
            }
            else if (envStore) {
                out[i] = assignedValue(name, value, state);
                handled.add(i);
            }
            continue;
        }
        if (program === 'openssl' && /^(?:pass|env|file|fd):/.test(arg)) {
            out[i] = state.exact ? exactOpensslPass(arg) : arg.replace(/:.*/s, `:${SECRET}`);
            handled.add(i);
            continue;
        }
        const position = positionOf.get(i) ?? -1;
        const previous = position > 0 ? out[positionals[position - 1]].toLowerCase() : '';
        const beforePrevious = position > 1 ? out[positionals[position - 2]].toLowerCase() : '';
        // aws configure set <name> <value>; npm|yarn|pnpm config set <name> <value>
        if ((program === 'aws' && subcommands[0] === 'configure' && previous === 'set')
            || (['npm', 'yarn', 'pnpm'].includes(program) && beforePrevious === 'config' && previous === 'set')) {
            byName(arg);
            continue;
        }
        // env stores: `netlify env:set NAME VALUE`, `railway variables set NAME VALUE`
        if (envStore && position > 0 && /^(?:env|config|variables?|vars?):(?:set|add|push|import|create|update|put)$|^(?:set|add|put|push|import|create|update)$/.test(previous)) {
            const j = valueAt();
            if (j !== null) {
                const kind = nameClass(arg, state);
                if (kind === 'credential')
                    redactAt(j);
                else if (kind === 'ambiguous')
                    redactAt(j, true);
                else {
                    out[j] = dataMarker(out[j], false, state);
                    handled.add(j);
                }
                k += 1;
            }
            continue;
        }
        // Known positional passwords.
        if ((/^(?:password|passwd)$/i.test(arg) && program !== 'gh')
            || (REDIS_FAMILY.has(program) && /^(?:auth|requirepass|masterauth)$/i.test(arg))
            || (program === 'vault' && subcommands[0] === 'login' && arg.toLowerCase() === 'login')) {
            next();
            continue;
        }
        if (program === 'rabbitmqctl' && ['add_user', 'change_password'].includes(subcommands[0] ?? '') && i === positionals[positionals.length - 1] && positionals.length >= 3) {
            redactAt(i);
            continue;
        }
        // In a secrets command (gh secret set NAME, doppler secrets set NAME VALUE ...),
        // the name stays; later positionals are values.
        if (secretContext) {
            const before = k > 0 ? out[args[k - 1]] : '';
            // The value of a known non-secret flag (`--repo org/app`, `-n staging`) is part of the action, kept as is.
            if (afterSecretWord >= 0 && secretCommandValueFlag(program, before))
                continue;
            if (afterSecretWord >= 0) {
                afterSecretWord += 1;
                // After an unknown flag the word may be that flag's value, not the secret: withheld, and the action never binds.
                if (afterSecretWord > 2)
                    redactAt(i, /^-/.test(before) && !before.includes('='));
            }
            else if (/secret/i.test(arg)) {
                afterSecretWord = 0;
            }
        }
        // htpasswd -b FILE USER PASSWORD: the last positional.
        if (htpasswdBatch && i === lastArg)
            redactAt(i);
    }
    return finish();
}
function quoteWord(word) {
    return /[\s'"\\|&;<>()$`*?]/.test(word) ? `'${word.replace(/'/g, `'\\''`)}'` : word;
}
const SIG_SPECIAL = '$`*?[{~';
const HEREDOC_OPEN = /(?<!<)<<(-?)[ \t]*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\2/g;
/**
 * What quoting does to the characters the shell expands (`$`, backquote, `*`, `?`, `[`, `{`, `~`), in order: `A`
 * when the shell acts on it, `L` when it is literal (single quotes, a backslash, double quotes for all but `$` and
 * backquote, a quoted heredoc). The words the normalizer reads are unquoted, so `rm -rf '*'` and `rm -rf *`,
 * `'$HOME'` and `$HOME`, `<<'EOF'` and `<<EOF` read alike; this signature keeps them apart. `'*'`, `"*"` and `\*`
 * mean the same and sign the same.
 */
function quoteSignature(command) {
    const parts = [];
    const lines = command.split('\n');
    const pending = [];
    let quote = '';
    for (let n = 0; n < lines.length; n += 1) {
        if (pending.length && !quote) {
            const doc = pending.shift();
            for (; n < lines.length; n += 1) {
                const line = lines[n];
                if (line.replace(/^[ \t]+|[ \t]+$/g, '') === doc.tag)
                    break;
                for (let i = 0; i < line.length; i += 1) {
                    const c = line[i];
                    if (!doc.quoted && c === '\\' && i + 1 < line.length && '$`\\'.includes(line[i + 1])) {
                        if (SIG_SPECIAL.includes(line[i + 1]))
                            parts.push(`L${line[i + 1]}`);
                        i += 1;
                    }
                    else if (SIG_SPECIAL.includes(c))
                        parts.push(`${!doc.quoted && (c === '$' || c === '`') ? 'A' : 'L'}${c}`);
                }
            }
            parts.push('|');
            continue;
        }
        const line = lines[n];
        if (!quote)
            for (const match of line.matchAll(HEREDOC_OPEN))
                pending.push({ tag: match[3], quoted: match[2] !== '' });
        for (let i = 0; i < line.length; i += 1) {
            const c = line[i];
            if (quote === "'") {
                if (c === "'")
                    quote = '';
                else if (SIG_SPECIAL.includes(c))
                    parts.push(`L${c}`);
                continue;
            }
            if (c === '\\' && i + 1 < line.length) {
                const next = line[i + 1];
                if (SIG_SPECIAL.includes(next))
                    parts.push(`L${next}`);
                i += 1;
                continue;
            }
            if (quote === '"') {
                if (c === '"')
                    quote = '';
                else if (SIG_SPECIAL.includes(c))
                    parts.push(`${c === '$' || c === '`' ? 'A' : 'L'}${c}`);
                continue;
            }
            if (c === "'" || c === '"') {
                quote = c;
                continue;
            }
            if (SIG_SPECIAL.includes(c))
                parts.push(`A${c}`);
        }
        if (quote)
            parts.push('/');
    }
    return parts.join('');
}
function normalizeInner(command, state, depth) {
    if (command.length > MAX_COMMAND_CHARS)
        throw new NormalizationLimit();
    spend(state, 0);
    // Quoting of the characters the shell expands (kept apart from the unquoted words, see quoteSignature).
    const signature = quoteSignature(command);
    if (signature)
        state.sigs.push(`${depth}:${signature}`);
    // A lone CR (not before LF) is a word character to the shell; read as a line end here, so the action is
    // truncated and the exact pass keeps it (`main<CR>` is not `main`, `build<CR>dist` is not `build ; dist`).
    if (/\r(?!\n)/.test(command))
        state.truncated = true; // exact: kept (crIsWord)
    const data = [];
    const lines = state.exact ? command.replace(/\r\n/g, '\n') : command.replace(/\r\n?/g, '\n');
    const tokens = tokenize(extractHeredocs(lines, data), state.exact);
    if (tokens.length > MAX_TOKENS)
        throw new NormalizationLimit();
    const segments = [];
    let current = [];
    for (let i = 0; i < tokens.length; i += 1) {
        const token = tokens[i];
        if (!token.op) {
            current.push(token.value);
            continue;
        }
        if (token.value === '<<<') {
            // A here-string is the command's input.
            current.push('<<<');
            if (i + 1 < tokens.length && !tokens[i + 1].op) {
                data.push(tokens[i + 1].value);
                current.push(slotWord(data.length - 1));
                i += 1;
            }
            continue;
        }
        if (['>', '>>', '<', '<<'].includes(token.value)) {
            // A redirection (and a heredoc tag) belongs to the current command.
            current.push(token.value);
            continue;
        }
        segments.push({ words: current, op: token.value });
        current = [];
    }
    segments.push({ words: current, op: null });
    const words = [];
    const programs = [];
    // Whether anything later in each segment's pipeline takes secrets: one pass from the end.
    const piped = (k) => segments[k].op === '|' || segments[k].op === '|&';
    const sinkAfter = new Array(segments.length).fill(false);
    for (let k = segments.length - 2; k >= 0; k -= 1) {
        if (!piped(k))
            continue;
        const next = segments[k + 1].words;
        sinkAfter[k] = (next.length > 0 && takesSecrets(next, parseSegment(next))) || sinkAfter[k + 1];
    }
    segments.forEach((segment, k) => {
        if (segment.words.length) {
            const result = redactSegment(segment.words, {
                pipedOut: piped(k),
                downstreamTakes: sinkAfter[k],
                data,
                state,
                depth,
            });
            words.push(...result.words.map(quoteWord));
            if (result.program && /^[a-z0-9][a-z0-9._+-]{0,63}$/.test(result.program) && !looksLikeKey(result.program) && !programs.includes(result.program)) {
                programs.push(result.program);
            }
        }
        const op = segment.op;
        if (op && (op !== ';' || (words.length && words[words.length - 1] !== ';')))
            words.push(op);
    });
    while (words.length && words[words.length - 1] === ';')
        words.pop();
    return { text: words.join(' '), programs: programs.slice(0, 16) };
}
/**
 * The normalized form of a shell command (see the module comment): hashed,
 * never sent. `truncated` is true when something that may change what the
 * command does had to be withheld. Exported for tests.
 */
function normalizeShellCommand(command, deadline, exact = false) {
    const state = newExactness(deadline, exact);
    try {
        const result = normalizeInner(command, state, 0);
        // The exact pass: the form exact_hmac keys (the words, the shell references and the quoting).
        if (exact)
            return { ...result, text: exactShellForm(result.text, command, state), truncated: state.truncated };
        return { ...result, truncated: state.truncated };
    }
    catch (error) {
        if (error instanceof NormalizationLimit)
            return { text: '', programs: [], truncated: true };
        throw error;
    }
}
function sortedValue(value, depth = 0) {
    if (depth > 6 || !value || typeof value !== 'object')
        return value;
    if (Array.isArray(value))
        return value.map((item) => sortedValue(item, depth + 1));
    return Object.fromEntries(Object.keys(value).sort()
        .map((key) => [key, sortedValue(value[key], depth + 1)]));
}
/** A tool input with credentials and key-shaped values replaced; hashed, never sent. */
function redactedInput(value, state, depth = 0) {
    // Past the depth or entry bounds the exact pass stops; exact_hmac then keys the raw canonical input.
    if (depth > 6) {
        if (state.exact)
            throw new NormalizationLimit();
        state.truncated = true; // exact: raw (canonical input)
        return SECRET;
    }
    if (typeof value === 'string')
        return redactText(value, state);
    if (Array.isArray(value)) {
        if (value.length > 64 && state.exact)
            throw new NormalizationLimit();
        if (value.length > 64)
            state.truncated = true; // exact: raw (canonical input)
        return value.slice(0, 64).map((item) => redactedInput(item, state, depth + 1));
    }
    if (value && typeof value === 'object') {
        const entries = Object.entries(value);
        if (entries.length > 64 && state.exact)
            throw new NormalizationLimit();
        if (entries.length > 64)
            state.truncated = true; // exact: raw (canonical input)
        const out = {};
        for (const [key, item] of entries.slice(0, 64)) {
            const kind = nameClass(key, state);
            if (kind === 'credential' || kind === 'ambiguous') {
                // The exact pass keeps an ambiguous value, and looks inside an object or array under a credential
                // name (`credentials: {user, role, password}`): only a value itself is certain.
                if (kind === 'ambiguous')
                    state.truncated = true; // exact: kept (below)
                out[key] = state.exact && (kind === 'ambiguous' || (item !== null && typeof item === 'object')) ? redactedInput(item, state, depth + 1) : SECRET;
            }
            else {
                out[key] = redactedInput(item, state, depth + 1);
            }
        }
        return out;
    }
    return value;
}
/**
 * The host's own shell text when trimming changed what bash runs, else null. The command is read trimmed, but a
 * lone CR, a vertical tab, a form feed or a non-ASCII space at either end is part of a word in bash (`main<CR>` is
 * another ref than `main`). ASCII spaces, tabs, newlines and CRLF line ends at the ends change nothing.
 */
function untrimmedShellText(event, trimmed) {
    const input = event.tool_input && typeof event.tool_input === 'object' && !Array.isArray(event.tool_input)
        ? event.tool_input : null;
    const host = typeof event.tool_input === 'string' ? event.tool_input
        : typeof input?.command === 'string' ? input.command : typeof input?.cmd === 'string' ? input.cmd : null;
    if (host === null || host === trimmed)
        return null;
    const at = host.indexOf(trimmed);
    if (at < 0)
        return null;
    const edges = `${host.slice(0, at)}${host.slice(at + trimmed.length)}`.replace(/\r\n/g, '\n');
    return /[^ \t\n]/.test(edges) ? host : null;
}
/**
 * The command a shell tool runs. Codex may send an argument vector
 * (["bash", "-lc", "<command>"]): its command is the same text a string form
 * would carry, so both give the same normalized action.
 */
function shellCommand(event) {
    const input = event.tool_input && typeof event.tool_input === 'object' && !Array.isArray(event.tool_input)
        ? event.tool_input : null;
    const argv = Array.isArray(input?.command) ? input.command : Array.isArray(input?.cmd) ? input.cmd : null;
    if (argv && argv.every((item) => typeof item === 'string')) {
        const words = argv;
        if (words.length === 3 && /^(?:.*\/)?(?:ba|z|da|k)?sh$/.test(words[0]) && /^-[a-z]*c$/.test(words[1]))
            return words[2];
        // An argument vector runs without a shell: every word is literal, so any character the shell reads is quoted.
        return words.map((word) => (/[\s'"\\$`*?[\]{}~|&;<>()!#]/.test(word) ? `'${word.replace(/'/g, `'\\''`)}'` : word)).join(' ');
    }
    return (0, hook_tool_policy_1.hookToolCommand)(event);
}
/**
 * An edit path as sent: the person's home directory as `~`, and another
 * user's home as `/home/[user]` (marked truncated, since it no longer names
 * one path), so no user name leaves the machine.
 */
function withoutUserName(path, state) {
    const home = (0, node_os_1.homedir)();
    if (home && home !== '/' && (path === home || path.startsWith(`${home}/`)))
        return `~${path.slice(home.length)}`;
    const other = /^(\/(?:home|Users))\/[^/]+(?=\/|$)/.exec(path);
    if (!other)
        return path;
    state.truncated = true; // exact: n/a (paths are not exact material; the whole input is)
    return `${other[1]}/[user]${path.slice(other[0].length)}`;
}
// ---------------------------------------------------------------------------
// Deploy command text (the only command text ever sent)
// ---------------------------------------------------------------------------
/** A launcher that may stand directly before the tool: one word, or two. */
const DEPLOY_LAUNCHERS = [['npx'], ['bunx']];
/** An environment value the service may read: lower-case letters, digits and dashes. */
const DEPLOY_ENV_VALUE = /^[a-z0-9-]{1,32}$/;
/**
 * The deploy tools whose non-production target can never fall back to
 * production, word for word (mirrors the service's allow-list exactly): the
 * tool and its subcommand, the one environment flag it must carry, and the
 * flags it may also carry once. Only SST: wrangler (`--env staging` deploys
 * production when that environment is missing), vercel, netlify (a draft
 * still runs the build and functions with production settings), serverless
 * and railway are not here.
 */
const DEPLOY_GRAMMARS = [
    { tools: ['sst'], subcommands: [['deploy']], envFlag: '--stage', optionalFlags: ['--verbose'] },
];
/**
 * The command text, only when the whole command is one of the deploy
 * grammars word for word: a single clause of plain ASCII words separated by
 * spaces or tabs (no operator, newline, quote, escape, variable, substitution,
 * subshell or wrapper such as bash -c, eval or xargs), an optional single
 * launcher, the tool and subcommand, exactly one environment flag with a
 * value matching DEPLOY_ENV_VALUE (or none, where the grammar has none), and
 * no other word. Anything else sends no text, only the hash, so no free-text
 * word ever leaves the machine.
 */
function deployCommandText(command) {
    if (typeof command !== 'string' || command.length > 512)
        return null;
    const trimmed = command.replace(/^[ \t]+|[ \t]+$/g, '');
    if (!trimmed || !/^[A-Za-z0-9 \t._=/:@-]+$/.test(trimmed))
        return null;
    let words = trimmed.split(/[ \t]+/);
    for (const launcher of DEPLOY_LAUNCHERS) {
        if (launcher.every((word, index) => words[index] === word)) {
            words = words.slice(launcher.length);
            break;
        }
    }
    const tool = words[0];
    const grammar = DEPLOY_GRAMMARS.find((entry) => entry.tools.includes(tool));
    if (!grammar)
        return null;
    const rest = words.slice(1);
    // The longest subcommand that matches.
    const subcommand = [...grammar.subcommands].sort((a, b) => b.length - a.length)
        .find((sub) => sub.every((word, index) => rest[index] === word));
    if (!subcommand)
        return null;
    const flags = rest.slice(subcommand.length);
    let value = null;
    let envFlags = 0;
    const seenOptional = new Set();
    for (let k = 0; k < flags.length; k += 1) {
        const flag = flags[k];
        if (grammar.optionalFlags.includes(flag)) {
            if (seenOptional.has(flag))
                return null;
            seenOptional.add(flag);
        }
        else if (grammar.envFlag !== null && flag === grammar.envFlag && k + 1 < flags.length) {
            envFlags += 1;
            value = flags[k + 1];
            k += 1;
        }
        else if (grammar.envFlag !== null && flag.startsWith(`${grammar.envFlag}=`)) {
            envFlags += 1;
            value = flag.slice(grammar.envFlag.length + 1);
        }
        else {
            return null;
        }
    }
    if (grammar.envFlag === null ? envFlags !== 0 : envFlags !== 1 || value === null || !DEPLOY_ENV_VALUE.test(value))
        return null;
    return normalizedWords(words, trimmed);
}
/** The words as the normalized form writes them (single spaces), launcher included. */
function normalizedWords(_toolWords, trimmed) {
    return trimmed.split(/[ \t]+/).join(' ');
}
function inputHash(input, state) {
    if (input === undefined || input === null)
        return {};
    const text = JSON.stringify(sortedValue(redactedInput(input, state)));
    if (text.includes(SECRET))
        state.truncated = true; // exact: n/a (pass 1 only; exactMaterial is the exact form)
    return { input_sha256: sha256(`${HASH_VERSION}\ninput\n${text}`) };
}
function withExactness(action, state) {
    return state.truncated ? { ...action, truncated: true } : action;
}
// ---------------------------------------------------------------------------
// Exact material for a truncated action (exact_hmac; M2)
// ---------------------------------------------------------------------------
const EXACT_DOMAIN = 'marrow-exact-action-v1';
/** Raw canonical input past this is never keyed: a nonce instead (it matches nothing). */
const MAX_RAW_EXACT_CHARS = 1_048_576;
const EXACT_SALT_NOTE = 'Marrow: the private device key for exact action matching is unavailable or unsafe on this machine, so a held action that hides a value is asked again instead of resumed on retry. Owner: run the Marrow installer doctor command in a terminal.';
/** Canonical JSON (keys sorted at every depth), or null past 1 MB, past 64 levels, or when it cannot be serialized. */
function canonicalJson(value) {
    const parts = [];
    let size = 0;
    const push = (text) => {
        size += text.length;
        if (size > MAX_RAW_EXACT_CHARS)
            throw new NormalizationLimit();
        parts.push(text);
    };
    const walk = (item, depth) => {
        if (depth > 64)
            throw new NormalizationLimit();
        if (Array.isArray(item)) {
            if (item.length > MAX_RAW_EXACT_CHARS / 2)
                throw new NormalizationLimit();
            push('[');
            item.forEach((entry, index) => { if (index)
                push(','); walk(entry, depth + 1); });
            push(']');
        }
        else if (item !== null && typeof item === 'object') {
            const keys = Object.keys(item);
            if (keys.length > MAX_RAW_EXACT_CHARS / 4)
                throw new NormalizationLimit();
            push('{');
            keys.sort().forEach((key, index) => {
                if (index)
                    push(',');
                push(`${JSON.stringify(key)}:`);
                walk(item[key], depth + 1);
            });
            push('}');
        }
        else {
            push(JSON.stringify(item) ?? 'null');
        }
    };
    try {
        walk(value, 0);
        return parts.join('');
    }
    catch {
        return null;
    }
}
/**
 * Every shell reference in a command, in order: `$NAME`, `${...}`, `$(...)` (balanced) and backquoted text,
 * quotes ignored (so a quoted literal `$` counts as well: stricter). A reference is never a credential value
 * itself: `API_KEY=$READONLY_KEY` and `API_KEY=$ADMIN_KEY`, or `mysql -p"$(cat ro.pw)"` and `"$(cat admin.pw)"`,
 * name different credentials. The exact pass replaces a credential position whole, so the references are
 * added to the exact material; two commands that differ only in a literal credential still match.
 */
function shellReferences(command) {
    const refs = [];
    for (let i = 0; i < command.length; i += 1) {
        const ch = command[i];
        if (ch === '`') {
            const end = command.indexOf('`', i + 1);
            const stop = end < 0 ? command.length : end + 1;
            refs.push(command.slice(i, stop));
            i = stop - 1;
        }
        else if (ch === '$' && (command[i + 1] === '(' || command[i + 1] === '{')) {
            const open = command[i + 1];
            const close = open === '(' ? ')' : '}';
            let depth = 0;
            let j = i + 1;
            for (; j < command.length; j += 1) {
                if (command[j] === open)
                    depth += 1;
                else if (command[j] === close) {
                    depth -= 1;
                    if (depth === 0)
                        break;
                }
            }
            refs.push(command.slice(i, Math.min(j + 1, command.length)));
            i = Math.min(j, command.length);
        }
        else if (ch === '$') {
            const name = /^\$(?:[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])/.exec(command.slice(i, i + 256));
            if (name) {
                refs.push(name[0]);
                i += name[0].length - 1;
            }
        }
    }
    return refs;
}
/** The exact form of a command: its words (only certain credentials replaced), its shell references and its quoting. */
function exactShellForm(text, command, state) {
    return `${text}\n${JSON.stringify(shellReferences(command))}\n${JSON.stringify(state.sigs)}`;
}
/** The raw input as material (a placeholder, or an exact pass that hit a limit): the command, or the canonical input. */
function rawExactMaterial(event, kind) {
    if (kind === 'shell') {
        try {
            const trimmed = shellCommand(event);
            const command = untrimmedShellText(event, trimmed) ?? trimmed;
            return typeof command === 'string' && command.length <= MAX_RAW_EXACT_CHARS ? `raw-shell\n${command}` : null;
        }
        catch {
            return null;
        }
    }
    const json = canonicalJson(event.tool_input ?? null);
    return json === null ? null : `raw-input\n${json}`;
}
/**
 * The exact material of an action: the same normalization with `exact` set (only a certain credential replaced,
 * every other value kept), or the raw input when that pass hits a limit. null: no material (a nonce instead).
 */
function exactMaterial(event, kind, deadline) {
    const state = newExactness(deadline, true);
    // Over 1 MB of material: a nonce (asked again), as for raw material.
    const bounded = (material) => (material.length <= MAX_RAW_EXACT_CHARS + 16 ? material : null);
    try {
        if (kind === 'shell') {
            const trimmed = shellCommand(event);
            const host = untrimmedShellText(event, trimmed);
            if (host !== null)
                return bounded(`raw-shell\n${host}`);
            const { text } = normalizeInner(trimmed, state, 0);
            return bounded(`exact-shell\n${exactShellForm(text, trimmed, state)}`);
        }
        const input = event.tool_input;
        const text = input === undefined || input === null ? 'null' : JSON.stringify(sortedValue(redactedInput(input, state)));
        return bounded(`exact-input\n${text}`);
    }
    catch (error) {
        return error instanceof NormalizationLimit ? rawExactMaterial(event, kind) : null;
    }
}
let saltNoted = false;
/** The device salt (seatbelt store, same checks), or null with one stderr line per process (no path, no value). */
function exactSalt() {
    let salt = null;
    try {
        salt = require('./seatbelt/record').deviceSalt();
    }
    catch {
        salt = null;
    }
    if (!salt && !saltNoted) {
        saltNoted = true;
        try {
            process.stderr.write(`${EXACT_SALT_NOTE}\n`);
        }
        catch { /* best effort */ }
    }
    return salt;
}
/**
 * exact_hmac: HMAC-SHA256(device salt, domain, kind, the host's full tool name, material), 128 bits. Without a
 * salt or material it is a fresh random nonce, which matches nothing: never unsalted, never the merged form.
 */
function exactHmac(salt, kind, toolName, material) {
    if (!salt || salt.length < 16 || material === null)
        return (0, node_crypto_1.randomBytes)(16).toString('hex');
    return (0, node_crypto_1.createHmac)('sha256', salt).update(`${EXACT_DOMAIN}\n${kind}\n${JSON.stringify(toolName)}\n`).update(material).digest('hex').slice(0, 32);
}
/**
 * The normalized action of a hook event. `deadlineAt` bounds the time it may
 * take (default one second from now): past it, or past the size limits, the
 * action is a truncated placeholder (kind and tool name only), which the
 * service never binds, so the hook still answers within its host's budget.
 * An event whose input a host adapter cut or dropped (`input_truncated`) is
 * marked truncated as well.
 *
 * A truncated action also carries `tool_input.exact_hmac`: a keyed hash (the
 * device salt never leaves the machine) of the action with only certain
 * credentials replaced, so two actions that differ anywhere else never share a
 * correlation, hold or key, and a retry that differs only in a certain
 * credential (an OTP) still does. A placeholder keys the raw input (up to
 * 1 MB). Input a host adapter cut or dropped, input over 1 MB and a missing or
 * unsafe salt give a random nonce: the action matches nothing (it is asked
 * again). `salt` is a test seam (undefined: the device salt).
 */
function normalizedHookAction(event, options = {}) {
    const deadline = options.deadlineAt ?? Date.now() + DEFAULT_NORMALIZE_MS;
    const state = newExactness(deadline);
    const toolName = (0, hook_tool_policy_1.normalizeHookToolName)(event.tool_name) || 'tool';
    // The host's own tool name, exactly as sent (stable across retries); the policy name decides the kind.
    // Not trimmed, so `X ` and `X` get different actions; a name past 128 characters is never bound.
    const rawToolName = typeof event.tool_name === 'string' && event.tool_name ? event.tool_name : toolName;
    const hostToolName = rawToolName.slice(0, 128);
    if (rawToolName.length > 128)
        state.truncated = true; // exact: kept (the full name is in exact_hmac)
    const kind = (0, hook_tool_policy_1.isMcpHookTool)(event.tool_name) || /^MCP:/i.test(hostToolName) ? 'mcp'
        : (0, hook_tool_policy_1.isShellGovernedTool)(event) ? 'shell'
            : EDIT_TOOLS.test(toolName) ? 'edit'
                : 'other';
    const inputCut = event.input_truncated === true;
    if (inputCut)
        state.truncated = true; // exact: nonce (the cut or dropped input is all that is left)
    let action;
    let placeholder = false;
    try {
        action = normalizedOfKind(event, kind, hostToolName, state);
    }
    catch (error) {
        if (!(error instanceof NormalizationLimit))
            throw error;
        action = { tool_kind: kind, tool_name: hostToolName, tool_input: {}, truncated: true };
        placeholder = true;
    }
    if (action.truncated !== true)
        return action;
    const material = inputCut ? null : placeholder ? rawExactMaterial(event, kind) : exactMaterial(event, kind, deadline);
    const salt = options.salt !== undefined ? options.salt : material === null ? null : exactSalt();
    return { ...action, tool_input: { ...action.tool_input, exact_hmac: exactHmac(salt, kind, rawToolName, material) } };
}
function normalizedOfKind(event, kind, hostToolName, state) {
    if (kind === 'mcp') {
        return withExactness({ tool_kind: 'mcp', tool_name: hostToolName, tool_input: inputHash(event.tool_input, state) }, state);
    }
    if (kind === 'shell') {
        const raw = shellCommand(event);
        if (untrimmedShellText(event, raw) !== null)
            state.truncated = true; // exact: raw (the host's untrimmed text)
        const { text, programs } = normalizeInner(raw, state, 0);
        // A secret was replaced: the action is never bound or reused (it asks each time).
        if (text.includes(SECRET))
            state.truncated = true; // exact: n/a (pass 1 only; the exact pass decides each value)
        // The command text itself only for a deploy the service can judge word for word (see deployCommandText).
        // Judged on the host's exact text (a trimmed non-ASCII space must not slip through).
        const input = event.tool_input && typeof event.tool_input === 'object' && !Array.isArray(event.tool_input) ? event.tool_input : null;
        const exact = typeof input?.command === 'string' ? input.command : typeof input?.cmd === 'string' ? input.cmd : raw;
        const deployText = state.truncated ? null : deployCommandText(exact);
        return withExactness({
            tool_kind: 'shell',
            tool_name: hostToolName,
            programs,
            tool_input: {
                // An exact action also hashes its quoting (never for a truncated one: a secret's characters stay out of it).
                command_sha256: sha256(`${HASH_VERSION}\nshell\n${state.truncated || !state.sigs.length ? text : `${text}\n${JSON.stringify(state.sigs)}`}`),
                ...(deployText !== null && deployText === text ? { command: deployText } : {}),
            },
        }, state);
    }
    if (kind === 'edit') {
        const targets = (0, hook_tool_policy_1.toolTargetPaths)(event);
        if (targets.length > 64)
            state.truncated = true; // exact: n/a (paths are not exact material; the whole input is)
        const paths = targets.slice(0, 64).map((path) => {
            const redacted = redactText(withoutUserName(path, state), state);
            if (redacted.length > 512 || redacted.includes(SECRET))
                state.truncated = true; // exact: n/a (as above)
            return redacted.slice(0, 512);
        });
        return withExactness({ tool_kind: 'edit', tool_name: hostToolName, paths, tool_input: inputHash(event.tool_input, state) }, state);
    }
    return withExactness({ tool_kind: 'other', tool_name: hostToolName, tool_input: inputHash(event.tool_input, state) }, state);
}
//# sourceMappingURL=normalized-action.js.map