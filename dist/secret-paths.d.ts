/**
 * The secret file paths both Marrow hooks read (one table): the keyless seatbelt stops a read
 * of one (S4), and the keyed policy treats it as a secret access. Home-anchored entries are matched
 * home-agnostic (`**`/ prefix), which is stricter: another user's or root's credential file is just
 * as secret. Globs: `**` any depth, `*` within one name.
 */
export declare const SECRET_PATTERNS: readonly string[];
/**
 * A `<name>.env` file is read as `.env` is (same operations, same S-code) when it is there to
 * read, or when git names it as a pathspec or object (history holds it). A word that names no file,
 * such as `process.env` in `grep -rn "process.env" src`, is not a secret path; `.env` and `.env.*`
 * above stay unconditional. `<name>.env.example` never matches.
 */
export declare const PRESENT_SECRET_PATTERNS: readonly string[];
//# sourceMappingURL=secret-paths.d.ts.map