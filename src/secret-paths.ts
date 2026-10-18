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
  '**/.marrow/env*', '**/.claude.json', '**/.claude/settings.local.json', '/proc/*/environ',
  '**/.env', '**/.env.*', '**/.dev.vars',
  // Marrow's own fleet env file and credential store.
  '**/.marrow/fleet.env', '**/.marrow/credentials/**',
  // The receipts' device salt (U6) and any other salt in Marrow's state: with it an agent could compute receipt and
  // exact-action keys. Writes there are S0.
  '**/.marrow/**/salt',
];

/**
 * A `<name>.env` file is read as `.env` is (same operations, same S-code) when it is there to
 * read, or when git names it as a pathspec or object (history holds it). A word that names no file,
 * such as `process.env` in `grep -rn "process.env" src`, is not a secret path; `.env` and `.env.*`
 * above stay unconditional. `<name>.env.example` never matches.
 */
export const PRESENT_SECRET_PATTERNS: readonly string[] = ['**/*.env'];
