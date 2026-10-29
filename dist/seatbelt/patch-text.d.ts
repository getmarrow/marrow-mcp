export type PatchKind = 'patch' | 'apply' | 'am';
export declare const MAX_HEADER_CHARS = 4096;
export declare const MAX_NAMES = 256;
export interface PatchNames {
    /** Every candidate file name, as the headers spell it (before -p and -d). */
    names: string[];
    /** Why the text is not certain (the first reason), or null. Any doubt is an unknown write. */
    doubt: string | null;
}
/**
 * The file names in patch text. `mail` also reads mailbox input (`git am`): a body whose transfer encoding is not
 * plain (quoted-printable, base64) or whose lines are flowed (`format=flowed`) hides the names from this reader,
 * so it is doubt. So is a Content-Type or Content-Transfer-Encoding header that git could read differently from
 * the text here (an RFC 2047 encoded word in it).
 */
export declare function readPatchNames(text: string, mail: boolean): PatchNames;
/**
 * `name` with its first `count` leading components removed: the smallest prefix holding `count` slashes, adjacent
 * slashes counting as one (GNU patch -p, git apply -p). Null when the name has fewer slashes than that.
 */
export declare function stripComponents(name: string, count: number): string | null;
/**
 * Every path a name may stand for. The name as written is always one of them. `git apply` and `git am` strip one
 * component by default; `patch` with no -p keeps the base name only. A name with fewer components than the strip
 * count adds nothing.
 */
export declare function targetNames(names: readonly string[], kind: PatchKind, strip: number | null): string[];
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
/** Reads the words after `patch`, `git apply` or `git am`. Every word must be literal text (the caller checks). */
export declare function parsePatchCall(kind: PatchKind, words: readonly string[]): PatchCall;
//# sourceMappingURL=patch-text.d.ts.map