"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MAX_SCAN_CHARS = void 0;
exports.looksLikeKey = looksLikeKey;
exports.classifySecretName = classifySecretName;
exports.normalizeShellCommand = normalizeShellCommand;
exports.normalizedHookAction = normalizedHookAction;
const node_crypto_1 = require("node:crypto");
const hook_tool_policy_1 = require("./hook-tool-policy");
const SECRET = '[secret]';
const HASH_VERSION = 'marrow-normalized-action-v2';
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
function newExactness(deadline = Date.now() + DEFAULT_NORMALIZE_MS) {
    return { truncated: false, budget: { scanned: 0, deadline } };
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
            state.truncated = true;
        return SECRET;
    }
    if (PEM.test(text)) {
        return text.replace(/-----BEGIN [A-Z ]*-----[\s\S]*?(?:-----END [A-Z ]*-----|$)/g, SECRET);
    }
    return text.split(KEY_SPLIT).map((part) => {
        if (!looksLikeKey(part))
            return part;
        if (!KNOWN_KEY_PREFIX.test(part))
            state.truncated = true;
        return SECRET;
    }).join('');
}
// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------
function nameParts(name) {
    return name.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
}
const CREDENTIAL_STEM = /password|passwd|passphrase|passcode|secret|token|apikey|accesskey|privatekey|credential|bearer|cookie|authorization|requirepass|masterauth|storepass|keypass|newpass|oldpass/;
const CREDENTIAL_WORDS = new Set(['pass', 'pwd', 'pw', 'otp', 'totp', 'creds', 'pat', 'jwt']);
const CREDENTIAL_PAIRS = ['api_key', 'access_key', 'private_key', 'secret_key', 'signing_key', 'master_key', 'encryption_key', 'account_key', 'auth_key'];
const AMBIGUOUS_WORDS = new Set(['auth', 'oauth', 'key', 'keys', 'session', 'signature', 'sig', 'pin', 'cred', 'hmac', 'sk']);
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
    const credential = parts.some((part) => CREDENTIAL_STEM.test(part) || CREDENTIAL_WORDS.has(part))
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
// ---------------------------------------------------------------------------
// Secrets inside a text
// ---------------------------------------------------------------------------
// Every pattern starts at a boundary (lookbehind) and bounds its repeats, so
// a scan is linear in the text: no start inside a run, no unbounded backtracking.
const URL_CREDENTIALS = /(?<![a-z0-9+.-])([a-z][a-z0-9+.-]{0,31}:\/\/)([^\s/@:'"]{0,256}):([^\s/@'"]{1,1024})@/gi;
const AUTH_SCHEME = /\b(Bearer|Basic|Token|Bot)([ \t]{1,8})([A-Za-z0-9._~+/=-]{8,})/g;
const URL_CODE = /([?&])((?:auth(?:orization)?_)?code)=([^&#\s'"]+)/gi;
/** A name and its separator (`name=`, `name: `, `"name": `); the value is read by hand after it. */
const NAME_SEPARATOR = /(["']?)(?<![A-Za-z0-9_.-])([A-Za-z_][A-Za-z0-9_.-]{0,127})\1([ \t]{0,8}[:=][ \t]{0,8})/g;
/** An unquoted value ends at a quote, whitespace, a list or block end, or the next query/form field (`&`, `#`). */
const VALUE_END = /["'\s,;)}\]&#]/;
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
const FOLLOWING_FIELD = /[,;&#][ \t]{0,8}[A-Za-z_][A-Za-z0-9_.-]{0,127}=/;
function cutCredential(value, state) {
    const at = value.search(FOLLOWING_FIELD);
    if (at < 0) {
        if (holdsMoreThanCredential(value))
            state.truncated = true;
        return SECRET;
    }
    state.truncated = true;
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
    if (text.length > exports.MAX_SCAN_CHARS) {
        state.truncated = true;
        return SECRET;
    }
    spend(state, text.length);
    // A short word without a separator cannot hold any of these (keys need 12 or more characters).
    if (text.length < 12 && !/[:=?&@\s]/.test(text))
        return text;
    let out = text.replace(URL_CREDENTIALS, (_match, scheme, user) => `${scheme}${user}:${SECRET}@`);
    out = out.replace(AUTH_SCHEME, (_match, scheme, space) => `${scheme}${space}${SECRET}`);
    out = out.replace(URL_CODE, (_match, separator, name) => `${separator}${name}=${SECRET}`);
    return redactKeyShapes(redactAssignments(out, state), state);
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
        if (matches > MAX_ASSIGNMENTS) {
            state.truncated = true;
            return SECRET;
        }
        const kind = classifySecretName(match[2]);
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
        if (!quote || end < 0) {
            end = start;
            while (end < text.length && !VALUE_END.test(text[end]))
                end += 1;
        }
        if (end <= start)
            continue;
        const value = text.slice(start, end);
        if (!value.startsWith('[secret') && !value.startsWith('[data:')) {
            if (kind === 'ambiguous' || holdsMoreThanCredential(value))
                state.truncated = true;
            out += text.slice(copied, start) + SECRET;
            copied = end;
        }
        pattern.lastIndex = end;
    }
    return out + text.slice(copied);
}
/** Whether a text carries anything secret-shaped (it is then withheld, never hashed). */
function secretShaped(text, state) {
    const probe = { truncated: false, budget: state.budget };
    return redactText(text, probe) !== text;
}
/**
 * Data a command reads: its SHA-256 in the hashed form, or `[secret]` and
 * truncated when it feeds a secrets command or file or looks secret.
 */
function dataMarker(text, feedsSecrets, state) {
    if (feedsSecrets || secretShaped(text, state)) {
        state.truncated = true;
        return SECRET;
    }
    return `[data:${sha256(`${HASH_VERSION}\ndata\n${text}`)}]`;
}
const OPERATORS = ['<<<', '&&', '||', '|&', '>>', '<<', ';;', '|', '&', ';', '<', '>', '(', ')', '\n'];
/** Splits a command into words and operators, honoring quotes and escapes (an approximation of the shell). */
function tokenize(command) {
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
        if (ch === ' ' || ch === '\t' || ch === '\r') {
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
    const kind = classifySecretName(name);
    if (kind === 'credential' || kind === 'ambiguous') {
        if (kind === 'ambiguous' || holdsMoreThanCredential(value))
            state.truncated = true;
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
            out[printed[0]] = dataMarker(printed.map((i) => out[i]).join(' '), downstreamTakes || secretTarget, state);
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
            out[at] = SECRET;
            state.truncated = true;
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
        if (ambiguous || holdsMoreThanCredential(out[i]))
            state.truncated = true;
        out[i] = SECRET;
        handled.add(i);
    };
    // An auth header: a one-value header is the credential; any other (`Cookie: a=1; env=prod`)
    // keeps its other fields, with the credentials inside replaced.
    const redactHeaderValue = (header) => {
        if (SINGLE_VALUE_HEADER.test(header)) {
            if (holdsMoreThanCredential(header.replace(/^[^:]*:/, '')))
                state.truncated = true;
            return SECRET;
        }
        const redacted = redactText(header, state);
        if (redacted === header)
            state.truncated = true;
        return redacted === header ? SECRET : redacted;
    };
    // A credential `NAME=value` argument: a form body (`api_key=K&sql=DROP`) keeps its other fields.
    const credentialArgument = (name, value) => {
        if (/[&#]/.test(value))
            return redactText(`${name}=${value}`, state);
        return `${name}=${cutCredential(value, state)}`;
    };
    // A program named for a secret (set-password.sh): its arguments cannot be told apart.
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
        const next = (ambiguous = false) => {
            const j = valueAt();
            if (j !== null) {
                if (ambiguous)
                    state.truncated = true;
                out[j] = cutCredential(out[j], state);
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
            const kind = classifySecretName(name);
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
                if (holdsMoreThanCredential(long[2].replace(/^[^=]*=/, '')))
                    state.truncated = true;
                out[i] = `${long[1]}=${long[2].replace(/^([^=]*)=.*$/s, `$1=${SECRET}`)}`;
                handled.add(i);
            }
            else if (CURL_FAMILY.has(program) && /^(?:u|user|proxy-user)$/.test(name)) {
                out[i] = `${long[1]}=${SECRET}`;
                handled.add(i);
            }
            else if (CURL_FAMILY.has(program) && name === 'header' && AUTH_HEADER.test(long[2])) {
                out[i] = `${long[1]}=${redactHeaderValue(long[2])}`;
                handled.add(i);
            }
            else if (holdsSecret(name)) {
                if (classifySecretName(name) === 'ambiguous')
                    state.truncated = true;
                out[i] = `${long[1]}=${cutCredential(long[2], state)}`;
                handled.add(i);
            }
            continue;
        }
        // --flag value
        if (/^--[A-Za-z0-9]/.test(arg)) {
            const name = arg.slice(2);
            if (CURL_FAMILY.has(program) && /^(?:user|proxy-user)$/.test(name))
                next();
            else if (CURL_FAMILY.has(program) && name === 'header') {
                const j = valueAt();
                if (j !== null && AUTH_HEADER.test(out[j])) {
                    out[j] = redactHeaderValue(out[j]);
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
                next();
            else if (CURL_FAMILY.has(program) && arg === '-H') {
                const j = valueAt();
                if (j !== null && AUTH_HEADER.test(out[j])) {
                    out[j] = redactHeaderValue(out[j]);
                    handled.add(j);
                    k += 1;
                }
            }
            else if (program === 'openssl' && OPENSSL_PASS_FLAGS.has(arg))
                next();
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
                if (/[&#]/.test(value) || holdsMoreThanCredential(value))
                    state.truncated = true;
                out[i] = `${name}=${SECRET}`;
                handled.add(i);
            }
            else if (holdsSecret(name)) {
                if (classifySecretName(name) === 'ambiguous')
                    state.truncated = true;
                out[i] = credentialArgument(name, value);
                handled.add(i);
            }
            else if (envStore) {
                out[i] = assignedValue(name, value, state);
                handled.add(i);
            }
            continue;
        }
        if (program === 'openssl' && /^(?:pass|env|file|fd):/.test(arg)) {
            out[i] = arg.replace(/:.*/s, `:${SECRET}`);
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
                const kind = classifySecretName(arg);
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
function normalizeInner(command, state, depth) {
    if (command.length > MAX_COMMAND_CHARS)
        throw new NormalizationLimit();
    spend(state, 0);
    const data = [];
    const tokens = tokenize(extractHeredocs(command.replace(/\r\n?/g, '\n'), data));
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
function normalizeShellCommand(command, deadline) {
    const state = newExactness(deadline);
    try {
        const result = normalizeInner(command, state, 0);
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
    if (depth > 6) {
        state.truncated = true;
        return SECRET;
    }
    if (typeof value === 'string')
        return redactText(value, state);
    if (Array.isArray(value)) {
        if (value.length > 64)
            state.truncated = true;
        return value.slice(0, 64).map((item) => redactedInput(item, state, depth + 1));
    }
    if (value && typeof value === 'object') {
        const entries = Object.entries(value);
        if (entries.length > 64)
            state.truncated = true;
        const out = {};
        for (const [key, item] of entries.slice(0, 64)) {
            const kind = classifySecretName(key);
            if (kind === 'credential' || kind === 'ambiguous') {
                if (kind === 'ambiguous')
                    state.truncated = true;
                out[key] = SECRET;
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
        return words.map((word) => (/[\s'"]/.test(word) ? `'${word.replace(/'/g, `'\\''`)}'` : word)).join(' ');
    }
    return (0, hook_tool_policy_1.hookToolCommand)(event);
}
function inputHash(input, state) {
    if (input === undefined || input === null)
        return {};
    const text = JSON.stringify(sortedValue(redactedInput(input, state)));
    if (text.includes(SECRET))
        state.truncated = true;
    return { input_sha256: sha256(`${HASH_VERSION}\ninput\n${text}`) };
}
function withExactness(action, state) {
    return state.truncated ? { ...action, truncated: true } : action;
}
/**
 * The normalized action of a hook event. `deadlineAt` bounds the time it may
 * take (default one second from now): past it, or past the size limits, the
 * action is a truncated placeholder (kind and tool name only), which the
 * service never binds, so the hook still answers within its host's budget.
 * An event whose input a host adapter cut or dropped (`input_truncated`) is
 * marked truncated as well.
 */
function normalizedHookAction(event, options = {}) {
    const state = newExactness(options.deadlineAt);
    const toolName = (0, hook_tool_policy_1.normalizeHookToolName)(event.tool_name) || 'tool';
    // The host's own tool name (stable across retries); the policy name decides the kind.
    const hostToolName = (typeof event.tool_name === 'string' && event.tool_name.trim() ? event.tool_name.trim() : toolName).slice(0, 128);
    const kind = (0, hook_tool_policy_1.isMcpHookTool)(event.tool_name) || /^MCP:/i.test(hostToolName) ? 'mcp'
        : (0, hook_tool_policy_1.isShellGovernedTool)(event) ? 'shell'
            : EDIT_TOOLS.test(toolName) ? 'edit'
                : 'other';
    if (event.input_truncated === true)
        state.truncated = true;
    try {
        return normalizedOfKind(event, kind, hostToolName, state);
    }
    catch (error) {
        if (error instanceof NormalizationLimit)
            return { tool_kind: kind, tool_name: hostToolName, tool_input: {}, truncated: true };
        throw error;
    }
}
function normalizedOfKind(event, kind, hostToolName, state) {
    if (kind === 'mcp') {
        return withExactness({ tool_kind: 'mcp', tool_name: hostToolName, tool_input: inputHash(event.tool_input, state) }, state);
    }
    if (kind === 'shell') {
        const { text, programs } = normalizeInner(shellCommand(event), state, 0);
        // A secret was replaced: the action is never bound or reused (it asks each time).
        if (text.includes(SECRET))
            state.truncated = true;
        return withExactness({
            tool_kind: 'shell',
            tool_name: hostToolName,
            programs,
            tool_input: { command_sha256: sha256(`${HASH_VERSION}\nshell\n${text}`) },
        }, state);
    }
    if (kind === 'edit') {
        const targets = (0, hook_tool_policy_1.toolTargetPaths)(event);
        if (targets.length > 64)
            state.truncated = true;
        const paths = targets.slice(0, 64).map((path) => {
            const redacted = redactText(path, state);
            if (redacted.length > 512 || redacted.includes(SECRET))
                state.truncated = true;
            return redacted.slice(0, 512);
        });
        return withExactness({ tool_kind: 'edit', tool_name: hostToolName, paths, tool_input: inputHash(event.tool_input, state) }, state);
    }
    return withExactness({ tool_kind: 'other', tool_name: hostToolName, tool_input: inputHash(event.tool_input, state) }, state);
}
//# sourceMappingURL=normalized-action.js.map