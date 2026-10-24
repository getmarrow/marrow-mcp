/**
 * The secret file paths both Marrow hooks read (one table): the keyless seatbelt stops a read
 * of one (S4), and the keyed policy treats it as a secret access. Home-anchored entries are matched
 * home-agnostic (`**`/ prefix), which is stricter: another user's or root's credential file is just
 * as secret. Globs: `**` any depth, `*` within one name.
 */
export const SECRET_PATTERNS: readonly string[] = [
  '**/.ssh/id_*', '**/.ssh/*_key', '**/.aws/credentials', '**/.aws/sso/cache/**',
  '**/.config/gcloud/**/*credentials*', '**/.config/gcloud/**/access_tokens.db', '**/.azure/**',
  '**/.kube/config', '**/.docker/config.json', '**/.npmrc', '**/.pypirc', '**/.netrc', '**/.git-credentials',
  '**/.config/gh/hosts.yml', '**/.config/op/**', '**/.gnupg/private-keys*', '**/.gnupg/private-keys*/**',
  '**/.marrow/env*', '**/.claude.json', '**/.claude/settings.local.json', '/proc/*/environ', '/proc/*/task/*/environ',
  '**/.env', '**/.env.*', '**/.dev.vars',
  // Marrow's own fleet env file and credential store.
  '**/.marrow/fleet.env', '**/.marrow/credentials/**',
  // The receipts' device salt (U6) and any other salt in Marrow's state: with it an agent could compute receipt and
  // exact-action keys. Writes there are S0.
  '**/.marrow/**/salt',
  // The host-approvals state file (holds, the secret that keys them, and the no-device-key fallback key derived from it) and every
  // name beside it: its temp copy (`.state-<pid>-<hex>.tmp`) and any backup hold the same secret. The folder itself is not listed: names
  // and stat stay open, only reads of what is in it stop. Writes there are S0.
  '**/.marrow/host-approvals/*',
];

/**
 * The host-approvals state file, its temp copies and any backup beside it, by absolute path. Matched case-insensitively (a case-folding
 * file system reads `.MARROW/Host-Approvals/State.json` as the file). The keyed hook uses it next to SECRET_PATTERNS.
 */
export const APPROVAL_STATE_PATH = /(?:^|\/)\.marrow\/host-approvals\/[^/]+$/i;
/**
 * Anything below the folder, at any depth. The keyed hook resolves `cd <folder>; cat ~+/state.json` to `<folder>/~+/state.json` (it never
 * expands `~+`), which the salt's `**` pattern reads as the salt: the state file is read the same way.
 */
export const APPROVAL_STATE_TREE = /(?:^|\/)\.marrow\/host-approvals\/.+$/i;
/** The extra S4 reason the seatbelt mapper adds to a hit on that file; the keyed hook keeps it, as it keeps the env-dump reasons. */
export const APPROVAL_STATE_REASON = 'host_approvals_state';

/**
 * A `<name>.env` file is read as `.env` is (same operations, same S-code) when it is there to
 * read, or when git names it as a pathspec or object (history holds it). A word that names no file,
 * such as `process.env` in `grep -rn "process.env" src`, is not a secret path; `.env` and `.env.*`
 * above stay unconditional. `<name>.env.example` never matches.
 */
export const PRESENT_SECRET_PATTERNS: readonly string[] = ['**/*.env'];

/**
 * The only `.env` templates, by name: `.env.example`, `.env.sample` and `.env.template`. The keyed policy builds its template test from this list; the keyless
 * table (ENV_TEMPLATE_SUFFIX in src/seatbelt/tables.ts) names the same three, and test/keyed-env-dist-defaults.test.js fails when the two differ. Every other
 * `.env.<word>` (`.env.dist`, `.env.defaults` and `.env.default` too) is a secret file in both modes. Never widen this list.
 */
export const ENV_TEMPLATE_WORDS: readonly string[] = ['example', 'sample', 'template'];

/** `/proc/<pid>/environ` and `/proc/<pid>/task/<tid>/environ`, `self` and `thread-self` included: the process's whole environment. */
export const PROC_ENVIRON = /^\/proc\/[^/]+\/(?:task\/[^/]+\/)?environ$/;

/**
 * `/proc`, `/proc/<pid|self|thread-self>` and `/proc/<…>/task[/<tid>]` (a number, `self`, or a glob in the id's place): a folder a search tool
 * walks, reaching the `environ` of every process under it. `/proc/cpuinfo` and `/proc/sys` hold none.
 */
export const PROC_PROCESS_TREE = /^\/proc(?:\/(?:\d+|self|thread-self|[^/]*[*?[][^/]*)(?:\/task(?:\/(?:\d+|self|thread-self|[^/]*[*?[][^/]*))?)?)?\/?$/;
