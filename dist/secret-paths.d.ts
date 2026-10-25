/**
 * The secret file paths both Marrow hooks read (one table): the keyless seatbelt stops a read
 * of one (S4), and the keyed policy treats it as a secret access. Home-anchored entries are matched
 * home-agnostic (`**`/ prefix), which is stricter: another user's or root's credential file is just
 * as secret. Globs: `**` any depth, `*` within one name.
 */
export declare const SECRET_PATTERNS: readonly string[];
/**
 * The host-approvals state file, its temp copies and any backup beside it, by absolute path. Matched case-insensitively (a case-folding
 * file system reads `.MARROW/Host-Approvals/State.json` as the file). The keyed hook uses it next to SECRET_PATTERNS.
 */
export declare const APPROVAL_STATE_PATH: RegExp;
/**
 * Anything below the folder, at any depth. The keyed hook resolves `cd <folder>; cat ~+/state.json` to `<folder>/~+/state.json` (it never
 * expands `~+`), which the salt's `**` pattern reads as the salt: the state file is read the same way.
 */
export declare const APPROVAL_STATE_TREE: RegExp;
/** The extra S4 reason the seatbelt mapper adds to a hit on that file; the keyed hook keeps it, as it keeps the env-dump reasons. */
export declare const APPROVAL_STATE_REASON = "host_approvals_state";
/**
 * A `<name>.env` file is read as `.env` is (same operations, same S-code) when it is there to
 * read, or when git names it as a pathspec or object (history holds it). A word that names no file,
 * such as `process.env` in `grep -rn "process.env" src`, is not a secret path; `.env` and `.env.*`
 * above stay unconditional. `<name>.env.example` never matches.
 */
export declare const PRESENT_SECRET_PATTERNS: readonly string[];
/**
 * The only `.env` templates, by name: `.env.example`, `.env.sample` and `.env.template`. The keyed policy builds its template test from this list; the keyless
 * table (ENV_TEMPLATE_SUFFIX in the keyless tables.ts) names the same three, and test/keyed-env-dist-defaults.test.js fails when the two differ. Every other
 * `.env.<word>` (`.env.dist`, `.env.defaults` and `.env.default` too) is a secret file in both modes. Never widen this list.
 */
export declare const ENV_TEMPLATE_WORDS: readonly string[];
/** `/proc/<pid>/environ` and `/proc/<pid>/task/<tid>/environ`, `self` and `thread-self` included: the process's whole environment. */
export declare const PROC_ENVIRON: RegExp;
/**
 * `/proc`, `/proc/<pid|self|thread-self>` and `/proc/<…>/task[/<tid>]` (a number, `self`, or a glob in the id's place): a folder a search tool
 * walks, reaching the `environ` of every process under it. `/proc/cpuinfo` and `/proc/sys` hold none.
 */
export declare const PROC_PROCESS_TREE: RegExp;
//# sourceMappingURL=secret-paths.d.ts.map