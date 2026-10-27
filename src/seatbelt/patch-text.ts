// WK-5: the files a patch writes. `patch`, `git apply` and `git am` write the files their patch text names, so the
// mapper reads a literal patch file and treats every name in it as a write target (like the destination of tee, cp
// and mv). This module is text and option parsing only: no file system, no shell, no state.
//
// Names are over-collected on purpose. Every `---`, `+++`, `***` and `Index:` line counts, hunk content included (a
// deleted line `-- x` reads as a header), after any leading run of spaces, tabs and `X` (GNU patch skips that run
// too), and a name with a space is read both whole and up to its first space. An
// extra name only matters when it is protected; a real name is never dropped because it looks like content.
// Whatever the reader cannot be sure of is `doubt`, and the mapper turns doubt into an unknown write (S0, a stop).

export type PatchKind = 'patch' | 'apply' | 'am';

// A header line longer than a path can be is not read (it also bounds the work of the `diff --git` split below).
export const MAX_HEADER_CHARS = 4096;
// A patch that names more files than this is not read; the mapper checks every name against the protected paths.
export const MAX_NAMES = 256;

export interface PatchNames {
  /** Every candidate file name, as the headers spell it (before -p and -d). */
  names: string[];
  /** Why the text is not certain (the first reason), or null. Any doubt is an unknown write. */
  doubt: string | null;
}

const ENCODINGS_OK = new Set(['7bit', '8bit', 'binary']);

/**
 * The file names in patch text. `mail` also reads mailbox input (`git am`): a body whose transfer encoding is not
 * plain (quoted-printable, base64) or whose lines are flowed (`format=flowed`) hides the names from this reader,
 * so it is doubt. So is a Content-Type or Content-Transfer-Encoding header that git could read differently from
 * the text here (an RFC 2047 encoded word in it).
 */
export function readPatchNames(text: string, mail: boolean): PatchNames {
  const names = new Set<string>();
  let doubt: string | null = null;
  const note = (why: string): void => { if (doubt === null) doubt = why; };
  // `soft` names (the words of a plain `diff` command line) are skipped when odd instead of raising doubt.
  const add = (raw: string, soft: boolean): void => {
    if (raw === '') { if (!soft) note('empty_name'); return; }
    if (raw === '/dev/null') return;
    if (raw.startsWith('"') || /[\\\u0000-\u001f\u007f]/.test(raw)) { if (!soft) note('odd_name'); return; }
    if (raw.split('/').includes('..')) { if (!soft) note('dotdot'); return; }
    if (names.size >= MAX_NAMES) { note('too_many_names'); return; }
    names.add(raw);
  };
  // `--- name<TAB>timestamp`: the name ends at the first TAB; with no TAB it may end at the first space.
  const header = (rest: string): void => {
    if (rest.length > MAX_HEADER_CHARS) { note('long_header'); return; }
    const body = rest.replace(/^[ \t]+/, '');
    const tab = body.indexOf('\t');
    const whole = (tab === -1 ? body : body.slice(0, tab)).replace(/ +$/, '');
    add(whole, false);
    const space = whole.indexOf(' ');
    if (space > 0) add(whole.slice(0, space), false);
  };
  // `diff --git a/x b/y`: the two names are split at every space (a name may hold spaces).
  const gitHeader = (rest: string): void => {
    if (rest.length > MAX_HEADER_CHARS) { note('long_header'); return; }
    if (rest.includes('"')) { note('odd_name'); return; }
    if (!rest.includes(' ')) { note('odd_git_header'); return; }
    for (let i = rest.indexOf(' '); i !== -1 && doubt === null; i = rest.indexOf(' ', i + 1)) {
      add(rest.slice(0, i), false);
      add(rest.slice(i + 1), false);
    }
  };
  // The mail header (Content-Type or Content-Transfer-Encoding) the current line belongs to, in mail mode.
  let mailHeader: 'type' | 'encoding' | null = null;
  for (const raw of text.split('\n')) {
    if (doubt !== null) break;
    const whole = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
    if (mail) {
      // `git am` un-flows a `format=flowed; delsp=yes` body, the patch part included: a line that ends in a space is
      // joined to the next one and the space is dropped, so a header name split over two mail lines is one name to
      // git. This reader does not follow that, so any flowed mail is doubt, whether the word sits in the Content-Type
      // header, a folded one, a MIME part header (any case) or the body. git format-patch never writes a flowed mail.
      if (/format\s*=\s*"?flowed/i.test(whole)) { note('flowed_mail_body'); continue; }
      // git also decodes RFC 2047 encoded words (`=?utf-8?q?format=3Dflowed?=`) in a header value before it reads
      // the Content-Type, and it looks for `base64` and `quoted-printable` anywhere in a Content-Transfer-Encoding
      // value. A header is its line at column 0 plus the folded lines under it (they start with a space or a tab).
      if (whole[0] !== ' ' && whole[0] !== '\t') mailHeader = /^content-type:/i.test(whole) ? 'type' : /^content-transfer-encoding:/i.test(whole) ? 'encoding' : null;
      if (mailHeader !== null && whole.includes('=?')) { note('encoded_mail_header'); continue; }
      if (mailHeader === 'encoding' && /base64|quoted-printable/i.test(whole)) { note('encoded_mail_body'); continue; }
    }
    // GNU patch skips any run of spaces, tabs and `X` before it tests a line for a header, so every test reads the
    // line after that run (a header may sit anywhere after the first diff, indented or not).
    let at = 0;
    while (at < whole.length && (whole[at] === ' ' || whole[at] === '\t' || whole[at] === 'X')) at += 1;
    const line = whole.slice(at);
    if (/^(?:---|\+\+\+|\*\*\*)[ \t]/.test(line)) header(line.slice(4));
    else if (line.startsWith('Index:')) header(line.slice(6));
    else if (line.startsWith('diff ')) {
      const rest = line.slice(5);
      if (rest.startsWith('--git ')) gitHeader(rest.slice(6));
      else if (rest.startsWith('--cc ') || rest.startsWith('--combined ')) note('combined_diff');
      else if (rest.length > MAX_HEADER_CHARS) note('long_header');
      else for (const word of rest.split(' ')) if (word !== '' && !word.startsWith('-')) add(word, true);
    } else if (line.startsWith('==== ')) note('perforce_header');
    // A patch that makes or changes a symlink (mode 120000) can write through it in a later entry.
    else if (/^(?:new file mode|new mode|old mode|deleted file mode) 120000/.test(line)) note('symlink_patch');
    else {
      // git spells a move `rename from|to` or, in its older form, `rename old|new` (and `copy` alike).
      const move = /^(?:rename|copy) (?:from|to|old|new) (.*)$/.exec(line);
      if (move) { if (move[1].length > MAX_HEADER_CHARS) note('long_header'); else add(move[1], false); continue; }
      // Any other line that opens like a move is a spelling this reader does not know.
      if (/^(?:rename|copy)[ \t]/.test(line)) { note('odd_move_header'); continue; }
      if (mail) {
        const encoding = /^content-transfer-encoding:[ \t]*([^\s;]*)/i.exec(whole);
        if (encoding && !ENCODINGS_OK.has(encoding[1].toLowerCase())) note('encoded_mail_body');
      }
    }
  }
  if (doubt === null && names.size === 0) note('no_headers');
  return { names: [...names], doubt };
}

/**
 * `name` with its first `count` leading components removed: the smallest prefix holding `count` slashes, adjacent
 * slashes counting as one (GNU patch -p, git apply -p). Null when the name has fewer slashes than that.
 */
export function stripComponents(name: string, count: number): string | null {
  let at = 0;
  for (let left = count; left > 0; left -= 1) {
    const slash = name.indexOf('/', at);
    if (slash === -1) return null;
    at = slash;
    while (name[at] === '/') at += 1;
  }
  return name.slice(at);
}

/**
 * Every path a name may stand for. The name as written is always one of them. `git apply` and `git am` strip one
 * component by default; `patch` with no -p keeps the base name only. A name with fewer components than the strip
 * count adds nothing.
 */
export function targetNames(names: readonly string[], kind: PatchKind, strip: number | null): string[] {
  const count = kind === 'patch' ? strip : (strip === null ? 1 : strip);
  const out = new Set<string>();
  for (const name of names) {
    out.add(name);
    if (count === null) {
      const base = name.replace(/\/+$/, '').split('/').pop() || '';
      if (base !== '') out.add(base);
    } else {
      const stripped = stripComponents(name, count);
      if (stripped !== null && stripped !== '') out.add(stripped);
    }
  }
  return [...out];
}

export interface PatchCall {
  /** False for a word the parser does not list (an unknown option, a bad value): the call is an unknown write. */
  ok: boolean;
  why: string;
  /** The -p / --strip value, or null when not given. */
  strip: number | null;
  /** -d / --directory values. */
  dirs: string[];
  /** Patch files named by -i / --input. */
  inputs: string[];
  /** Other files the call writes: -o, -r, --reject-file, --global-reject-file, --build-fake-ancestor. */
  extraWrites: string[];
  /** Words that are not options. */
  operands: string[];
  /** Writes nothing: patch --dry-run, git apply --check/--stat/--numstat/--summary. Only when the parse is certain. */
  readOnly: boolean;
  /** The one word is a help or version request. */
  info: boolean;
}

interface Spec {
  noValue: ReadonlySet<string>;
  value: ReadonlySet<string>;
  shortNoValue: string;
  shortValue: string;
  info: ReadonlySet<string>;
}
const set = (text: string): ReadonlySet<string> => new Set(text.split(/\s+/).filter(Boolean));

// GNU patch 2.7 (also read by BSD patch): the options it takes and the ones that change which file is written.
// Left out on purpose, so the call is an unknown write: -B -Y -z -V and their long forms (a backup name can be any
// path), -e/--ed and -n/--normal (no file headers), --follow-symlinks and --merge.
const PATCH_SPEC: Spec = {
  noValue: set('backup backup-if-mismatch no-backup-if-mismatch binary dry-run force forward ignore-whitespace quiet silent '
    + 'remove-empty-files reverse set-time set-utc verbose batch posix unified context help version'),
  value: set('directory input output strip fuzz reject-file global-reject-file ifdef debug read-only get reject-format'),
  shortNoValue: 'bEfRstTuZlcNv',
  shortValue: 'dDFgiopxr',
  info: set('--help --version -v'),
};
const APPLY_SPEC: Spec = {
  noValue: set('stat numstat summary check index cached intent-to-add apply reverse reject unsafe-paths allow-overlap allow-empty '
    + 'verbose quiet recount inaccurate-eof binary no-add ignore-space-change ignore-whitespace unidiff-zero 3way'),
  value: set('directory include exclude whitespace build-fake-ancestor'),
  shortNoValue: 'vqRzN3',
  shortValue: 'pC',
  info: set('-h --help'),
};
const AM_SPEC: Spec = {
  noValue: set('signoff keep keep-non-patch keep-cr scissors message-id quiet utf8 3way rerere-autoupdate ignore-space-change '
    + 'ignore-whitespace committer-date-is-author-date ignore-date reject allow-empty no-verify verify'),
  value: set('directory include exclude whitespace'),
  shortNoValue: 'skcmqu3n',
  shortValue: 'pC',
  info: set('-h --help'),
};
const SPECS: Record<PatchKind, Spec> = { patch: PATCH_SPEC, apply: APPLY_SPEC, am: AM_SPEC };

/** Reads the words after `patch`, `git apply` or `git am`. Every word must be literal text (the caller checks). */
export function parsePatchCall(kind: PatchKind, words: readonly string[]): PatchCall {
  const spec = SPECS[kind];
  const call: PatchCall = { ok: true, why: '', strip: null, dirs: [], inputs: [], extraWrites: [], operands: [], readOnly: false, info: false };
  const fail = (why: string): PatchCall => { call.ok = false; call.why = why; return call; };
  if (words.length === 1 && spec.info.has(words[0])) { call.info = true; return call; }
  const seen = new Set<string>();
  let negated = false;
  let repeated = false;
  let dryRuns = 0;
  let strips = 0;
  const give = (name: string, value: string): string | null => {
    switch (name) {
      case 'p': case 'strip':
        if (!/^\d{1,6}$/.test(value)) return 'bad_strip';
        call.strip = Number(value); strips += 1; return null;
      case 'd': case 'directory': call.dirs.push(value); return null;
      case 'i': case 'input': call.inputs.push(value); return null;
      case 'o': case 'output': case 'r': case 'reject-file': case 'global-reject-file': case 'build-fake-ancestor': call.extraWrites.push(value); return null;
      case 'C': return /^\d{1,6}$/.test(value) ? null : 'bad_context';
      default: return null;
    }
  };
  let ended = false;
  for (let i = 0; i < words.length; i += 1) {
    const word = words[i];
    if (ended || word === '-' || !word.startsWith('-')) { call.operands.push(word); continue; }
    if (word === '--') { ended = true; continue; }
    if (word.startsWith('--')) {
      const eq = word.indexOf('=');
      let name = eq === -1 ? word.slice(2) : word.slice(2, eq);
      const attached = eq === -1 ? null : word.slice(eq + 1);
      if (spec.value.has(name)) {
        const value = attached !== null ? attached : words[i + 1];
        if (value === undefined) return fail('missing_value');
        if (attached === null) i += 1;
        const bad = give(name, value);
        if (bad) return fail(bad);
        seen.add(name);
        continue;
      }
      // `--no-<name>` of a listed flag undoes it: the later word wins in git, so no read-only reading is trusted.
      if (!spec.noValue.has(name) && name.startsWith('no-') && spec.noValue.has(name.slice(3)) && attached === null && kind !== 'patch') { negated = true; name = name.slice(3); }
      if (!spec.noValue.has(name)) return fail('unknown_option');
      // `--unified=3`, `--context=3`: a count only.
      if (attached !== null && !((name === 'unified' || name === 'context') && /^\d{1,6}$/.test(attached))) return fail('unknown_option');
      if (name === 'dry-run') dryRuns += 1;
      if (seen.has(name)) repeated = true;
      seen.add(name);
      continue;
    }
    // A short word: one or more letters (patch and git: `-p1`, `-pN`, `-C3`, clusters like `-Nf`).
    for (let k = 1; k < word.length; k += 1) {
      const c = word[k];
      if (spec.shortNoValue.includes(c)) { seen.add(`-${c}`); continue; }
      if (!spec.shortValue.includes(c)) return fail('unknown_option');
      let value = word.slice(k + 1);
      if (value === '') {
        value = words[i + 1];
        if (value === undefined) return fail('missing_value');
        i += 1;
      }
      const bad = give(c, value);
      if (bad) return fail(bad);
      seen.add(`-${c}`);
      break;
    }
    // git reads one letter per word for its flags and `-p`/`-C` with a number: a cluster of several flags is a form
    // the parser does not claim, so it is not read.
    if (kind !== 'patch' && word.length > 2 && !/^-[pC]\d+$/.test(word)) return fail('unknown_option');
  }
  // Repeats that can change the target set (the last one wins in git; patch changes directory in order).
  if (strips > 1 || call.dirs.length > 1 || call.inputs.length > 1) return fail('repeated_option');
  if (kind === 'patch') {
    call.readOnly = dryRuns === 1 && call.extraWrites.length === 0;
  } else if (kind === 'apply') {
    const reading = ['check', 'stat', 'numstat', 'summary'].some((n) => seen.has(n));
    const writing = ['apply', 'reject', 'index', 'cached', 'intent-to-add', '3way', 'build-fake-ancestor', '-3', '-N'].some((n) => seen.has(n));
    call.readOnly = reading && !writing && !negated && !repeated;
  }
  return call;
}
