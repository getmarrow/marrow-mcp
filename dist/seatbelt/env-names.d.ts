/** `secret`: read as a secret env file by its name alone; `present`: `<name>.env`, which the shared table reads only where the file is there. */
export type EnvNameKind = 'secret' | 'present' | null;
/** The basename of a path as written (the last segment, a trailing slash ignored). */
export declare function lastSegment(text: string): string;
/**
 * A basename the shared secret table reads as an env file: `.env`, `.env.<word>` (a template such as `.env.example` is not) and `.dev.vars`, whatever the case
 * (the same case-blind reading the keyed policy has); `<name>.env` is `present`. The table stays the one source (src/secret-paths.ts): this only repeats
 * its name rules for a word that is not yet a path.
 */
export declare function secretEnvBase(base: string): EnvNameKind;
/** Names a glob that cannot be listed is judged against, besides the mapper's own samples: common secret env names a project holds. */
export declare const ENV_NAME_CORPUS: readonly string[];
/** The host side of a `-v`/`--volume` value `host:container[:options]`: the text before the first colon; null with no colon (an anonymous volume) or an empty host. */
export declare function volumeHost(value: string): string | null;
/** The `source=` / `src=` values of a `--mount` value (comma-separated `key=value` fields): every one, a repeated key included, whatever the mount type. */
export declare function mountSources(value: string): string[];
/**
 * Whether a find `-regex` pattern matches any of the candidate paths (the whole path, as find matches it), read as emacs and as extended syntax.
 * `unsure`: neither reading could be completed (unreadable syntax, too large, out of steps) and none matched.
 */
export declare function regexMatchesAny(pattern: string, candidates: readonly string[]): 'yes' | 'no' | 'unsure';
//# sourceMappingURL=env-names.d.ts.map