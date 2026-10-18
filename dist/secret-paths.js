"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PRESENT_SECRET_PATTERNS = exports.SECRET_PATTERNS = void 0;
/**
 * The secret file paths both Marrow hooks read (one table, PKG-M1): the keyless seatbelt stops a read
 * of one (S4), and the keyed policy treats it as a secret access. Home-anchored entries are matched
 * home-agnostic (`**`/ prefix), which is stricter: another user's or root's credential file is just
 * as secret. Globs: `**` any depth, `*` within one name.
 */
exports.SECRET_PATTERNS = [
    '**/.ssh/id_*', '**/.ssh/*_key', '**/.aws/credentials', '**/.aws/sso/cache/**',
    '**/.config/gcloud/**/*credentials*', '**/.config/gcloud/**/access_tokens.db', '**/.azure/**',
    '**/.kube/config', '**/.docker/config.json', '**/.npmrc', '**/.pypirc', '**/.netrc', '**/.git-credentials',
    '**/.config/gh/hosts.yml', '**/.config/op/**', '**/.gnupg/private-keys*', '**/.gnupg/private-keys*/**',
    '**/.marrow/env*', '**/.claude.json', '**/.claude/settings.local.json', '/proc/*/environ',
    '**/.env', '**/.env.*', '**/.dev.vars',
    // PKG-M1: Marrow's own fleet env file and credential store.
    '**/.marrow/fleet.env', '**/.marrow/credentials/**',
    // The receipts' device salt (U6) and any other salt in Marrow's state: with it an agent could compute receipt and
    // exact-action keys. Writes there are S0.
    '**/.marrow/**/salt',
];
/**
 * PKG-M1: a `<name>.env` file is read as `.env` is (same operations, same S-code) when it is there to
 * read, or when git names it as a pathspec or object (history holds it). A word that names no file,
 * such as `process.env` in `grep -rn "process.env" src`, is not a secret path; `.env` and `.env.*`
 * above stay unconditional. `<name>.env.example` never matches.
 */
exports.PRESENT_SECRET_PATTERNS = ['**/*.env'];
//# sourceMappingURL=secret-paths.js.map