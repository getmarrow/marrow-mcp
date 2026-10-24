"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ENV_NAME_CORPUS = void 0;
exports.lastSegment = lastSegment;
exports.secretEnvBase = secretEnvBase;
exports.volumeHost = volumeHost;
exports.mountSources = mountSources;
exports.regexMatchesAny = regexMatchesAny;
// Secret env file names in the forms the mapper reads besides a plain operand: the host side of a container bind mount, the names a find primary matches
// and the names the stage in front of xargs lists. Pure string work (the mapper turns its words into these strings); no I/O, nothing from the command is
// ever run, and the one pattern language it reads (find -regex) is matched by a bounded matcher, never by a RegExp built from the command.
const tables_1 = require("./tables");
/** The basename of a path as written (the last segment, a trailing slash ignored). */
function lastSegment(text) {
    const t = text.replace(/\/+$/, '');
    return t.slice(t.lastIndexOf('/') + 1);
}
/**
 * A basename the shared secret table reads as an env file: `.env`, `.env.<word>` (a template such as `.env.example` is not) and `.dev.vars`, whatever the case
 * (the same case-blind reading the keyed policy has); `<name>.env` is `present`. The table stays the one source (src/secret-paths.ts): this only repeats
 * its name rules for a word that is not yet a path.
 */
function secretEnvBase(base) {
    const b = base.toLowerCase();
    if (/^\.env(?:\.|$)/.test(b))
        return tables_1.ENV_TEMPLATE_SUFFIX.test(b) ? null : 'secret';
    if (b === '.dev.vars')
        return 'secret';
    if (b.length > 4 && b.endsWith('.env'))
        return 'present';
    return null;
}
/** Names a glob that cannot be listed is judged against, besides the mapper's own samples: common secret env names a project holds. */
exports.ENV_NAME_CORPUS = [
    '.env.staging', '.env.development', '.env.dev', '.env.prod', '.env.test', '.env.ci', '.env.dist', '.env.defaults', '.env.default', '.env.backup', '.env.bak',
    '.env.old', '.env.secret', '.env.secrets', '.env.private', '.env.production.local', '.env.development.local', '.env.test.local', '.env.local.bak',
    '.env.myapp', '.env.docker', '.env.compose', 'config.env', 'prod.env', 'dev.env', 'staging.env', 'local.env', 'secrets.env', 'docker.env',
];
/** The host side of a `-v`/`--volume` value `host:container[:options]`: the text before the first colon; null with no colon (an anonymous volume) or an empty host. */
function volumeHost(value) {
    const at = value.indexOf(':');
    return at > 0 ? value.slice(0, at) : null;
}
/** The `source=` / `src=` values of a `--mount` value (comma-separated `key=value` fields): every one, a repeated key included, whatever the mount type. */
function mountSources(value) {
    const out = [];
    for (const field of value.split(',')) {
        const m = field.trim().replace(/^["']|["']$/g, '').match(/^(?:source|src)\s*=\s*([\s\S]*)$/i);
        if (m)
            out.push(m[1].trim().replace(/^["']|["']$/g, ''));
    }
    return out;
}
class Unreadable extends Error {
}
class OutOfSteps extends Error {
}
const MAX_PATTERN = 400;
const MAX_STEPS = 200_000;
const MAX_INTERVAL = 32;
const CLASSES = {
    alpha: [['a', 'z'], ['A', 'Z']], digit: [['0', '9']], alnum: [['a', 'z'], ['A', 'Z'], ['0', '9']], upper: [['A', 'Z']], lower: [['a', 'z']],
    punct: [['!', '/'], [':', '@'], ['[', '`'], ['{', '~']], space: [[' ', ' '], ['\t', '\r']], blank: [[' ', ' '], ['\t', '\t']], xdigit: [['0', '9'], ['a', 'f'], ['A', 'F']],
    word: [['a', 'z'], ['A', 'Z'], ['0', '9'], ['_', '_']], cntrl: [['\u0000', '\u001f']], graph: [['!', '~']], print: [[' ', '~']],
};
const ESCAPE_SETS = {
    w: { neg: false, cls: 'word' }, W: { neg: true, cls: 'word' }, s: { neg: false, cls: 'space' }, S: { neg: true, cls: 'space' }, d: { neg: false, cls: 'digit' }, D: { neg: true, cls: 'digit' },
};
function parseRegex(p, emacs) {
    if (p.length > MAX_PATTERN)
        throw new Unreadable();
    let i = 0;
    let depth = 0;
    const atAlt = () => (emacs ? p.startsWith('\\|', i) : p[i] === '|');
    const atClose = () => depth > 0 && (emacs ? p.startsWith('\\)', i) : p[i] === ')');
    const parseAlt = () => {
        const branches = [parseCat()];
        while (i < p.length && atAlt()) {
            i += emacs ? 2 : 1;
            branches.push(parseCat());
        }
        return branches.length === 1 ? branches[0] : { t: 'alt', n: branches };
    };
    const parseBracket = () => {
        i += 1;
        let neg = false;
        if (p[i] === '^') {
            neg = true;
            i += 1;
        }
        const items = [];
        let first = true;
        for (;;) {
            if (i >= p.length)
                throw new Unreadable();
            const c = p[i];
            if (c === ']' && !first) {
                i += 1;
                break;
            }
            first = false;
            if (c === '[' && p[i + 1] === ':') {
                const end = p.indexOf(':]', i + 2);
                const cls = end < 0 ? undefined : CLASSES[p.slice(i + 2, end)];
                if (!cls)
                    throw new Unreadable();
                items.push(...cls);
                i = end + 2;
                continue;
            }
            if (c === '[' && (p[i + 1] === '.' || p[i + 1] === '='))
                throw new Unreadable();
            if (c === '\\' && i + 1 < p.length && ESCAPE_SETS[p[i + 1]] && !ESCAPE_SETS[p[i + 1]].neg) {
                items.push(...CLASSES[ESCAPE_SETS[p[i + 1]].cls]);
                i += 2;
                continue;
            }
            if (p[i + 1] === '-' && i + 2 < p.length && p[i + 2] !== ']') {
                items.push([c, p[i + 2]]);
                i += 3;
                continue;
            }
            items.push([c, c]);
            i += 1;
        }
        return { t: 'set', neg, items };
    };
    const interval = () => {
        const m = (emacs ? p.slice(i).match(/^\\\{(\d+)(,(\d*))?\\\}/) : p.slice(i).match(/^\{(\d+)(,(\d*))?\}/));
        if (!m)
            return null;
        const min = Number(m[1]);
        const max = m[2] === undefined ? min : m[3] === '' ? Number.POSITIVE_INFINITY : Number(m[3]);
        if (min > MAX_INTERVAL || (Number.isFinite(max) && max > MAX_INTERVAL) || max < min)
            throw new Unreadable();
        i += m[0].length;
        return { min, max };
    };
    const parseAtom = () => {
        const c = p[i];
        if (c === '.') {
            i += 1;
            return { t: 'any' };
        }
        if (c === '[')
            return parseBracket();
        if (c === '^' || c === '$') {
            i += 1;
            return { t: 'empty' };
        }
        if (!emacs && c === '(') {
            i += 1;
            depth += 1;
            const n = parseAlt();
            if (p[i] !== ')')
                throw new Unreadable();
            i += 1;
            depth -= 1;
            return n;
        }
        if (c === '\\') {
            if (i + 1 >= p.length)
                throw new Unreadable();
            const d = p[i + 1];
            if (emacs && d === '(') {
                i += 2;
                depth += 1;
                const n = parseAlt();
                if (!p.startsWith('\\)', i))
                    throw new Unreadable();
                i += 2;
                depth -= 1;
                return n;
            }
            if (/[1-9]/.test(d))
                throw new Unreadable();
            if (ESCAPE_SETS[d]) {
                i += 2;
                return { t: 'set', neg: ESCAPE_SETS[d].neg, items: CLASSES[ESCAPE_SETS[d].cls] };
            }
            if (d === 'b' || d === 'B' || d === '<' || d === '>' || d === '`' || d === "'") {
                i += 2;
                return { t: 'empty' };
            }
            i += 2;
            return { t: 'lit', c: d };
        }
        i += 1;
        return { t: 'lit', c };
    };
    const parseCat = () => {
        const items = [];
        while (i < p.length && !atAlt() && !atClose()) {
            let atom;
            // an operator with nothing in front of it is an ordinary character
            if ((p[i] === '*' || p[i] === '+' || p[i] === '?') && items.length === 0) {
                atom = { t: 'lit', c: p[i] };
                i += 1;
            }
            else
                atom = parseAtom();
            for (;;) {
                const c = p[i];
                if (c === '*') {
                    i += 1;
                    atom = { t: 'rep', n: atom, min: 0, max: Number.POSITIVE_INFINITY };
                    continue;
                }
                if (c === '+') {
                    i += 1;
                    atom = { t: 'rep', n: atom, min: 1, max: Number.POSITIVE_INFINITY };
                    continue;
                }
                if (c === '?') {
                    i += 1;
                    atom = { t: 'rep', n: atom, min: 0, max: 1 };
                    continue;
                }
                if (emacs && (p.startsWith('\\+', i) || p.startsWith('\\?', i))) {
                    atom = { t: 'rep', n: atom, min: p[i + 1] === '+' ? 1 : 0, max: p[i + 1] === '+' ? Number.POSITIVE_INFINITY : 1 };
                    i += 2;
                    continue;
                }
                const iv = c === '{' || c === '\\' ? interval() : null;
                if (iv) {
                    atom = { t: 'rep', n: atom, min: iv.min, max: iv.max };
                    continue;
                }
                break;
            }
            items.push(atom);
        }
        return items.length === 1 ? items[0] : { t: 'cat', n: items };
    };
    const node = parseAlt();
    if (i < p.length)
        throw new Unreadable();
    return node;
}
function matchNode(node, s, i, k, st) {
    st.steps += 1;
    if (st.steps > MAX_STEPS)
        throw new OutOfSteps();
    switch (node.t) {
        case 'empty': return k(i);
        case 'any': return i < s.length && k(i + 1);
        case 'lit': return i < s.length && (st.ci ? s[i].toLowerCase() === node.c.toLowerCase() : s[i] === node.c) && k(i + 1);
        case 'set': {
            if (i >= s.length)
                return false;
            const ch = s[i];
            const chs = st.ci ? [ch.toLowerCase(), ch.toUpperCase()] : [ch];
            const inSet = chs.some((c) => node.items.some(([lo, hi]) => c >= lo && c <= hi));
            return inSet !== node.neg && k(i + 1);
        }
        case 'cat': {
            const step = (idx, at) => (idx === node.n.length ? k(at) : matchNode(node.n[idx], s, at, (j) => step(idx + 1, j), st));
            return step(0, i);
        }
        case 'alt': return node.n.some((alt) => matchNode(alt, s, i, k, st));
        case 'rep': {
            const again = (count, at) => {
                if (count < node.max && matchNode(node.n, s, at, (j) => (j === at && count >= node.min ? false : again(count + 1, j)), st))
                    return true;
                return count >= node.min && k(at);
            };
            return again(0, i);
        }
    }
}
/**
 * Whether a find `-regex` pattern matches any of the candidate paths (the whole path, as find matches it), read as emacs and as extended syntax.
 * `unsure`: neither reading could be completed (unreadable syntax, too large, out of steps) and none matched.
 */
function regexMatchesAny(pattern, candidates) {
    let unsure = false;
    for (const emacs of [true, false]) {
        let node;
        try {
            node = parseRegex(pattern, emacs);
        }
        catch {
            unsure = true;
            continue;
        }
        const st = { steps: 0, ci: true };
        try {
            for (const c of candidates)
                if (c.length <= 300 && matchNode(node, c, 0, (j) => j === c.length, st))
                    return 'yes';
        }
        catch {
            unsure = true;
        }
    }
    return unsure ? 'unsure' : 'no';
}
//# sourceMappingURL=env-names.js.map