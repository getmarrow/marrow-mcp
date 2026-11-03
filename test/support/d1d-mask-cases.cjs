'use strict';
// Test-only. Commands that put regex metacharacters, repeated shipping words and very long texts next to a shipping word of a data slot: the label the hook gives each is
// compared with the golden file (d1d-mask-golden.json, made from the port tip d0f7d8a69bac), so a change of how the masked text is built shows.
const rep = (s, n) => s.repeat(n);
const COMMANDS = [
  "git grep -c 'deploy' main",
  "git grep -n 'dep(loy' HEAD",
  "git grep -n 'deploy|release' HEAD",
  "git grep -E 'deploy|release|x' HEAD",
  "git grep -n 'deploy*' HEAD",
  "git grep -n 'deploy\\\\' HEAD",
  "git grep -n '[deploy]' HEAD",
  "git grep -n '^deploy$' HEAD",
  "git grep -n 'a.deploy.b' HEAD",
  "git grep -n 'deploy' -- 'release*'",
  "git grep -e deploy -e release HEAD",
  "git grep -c deploy HEAD && git grep -c release HEAD",
  "git grep -c Deploy HEAD",
  "git grep -c DEPLOY HEAD",
  "git grep -c d1 HEAD",
  "git grep -c prod HEAD",
  "git grep -c production HEAD",
  "git grep -c 'prod production' HEAD",
  "git grep -c unpublish HEAD; git grep -c publish HEAD",
  "git grep -c deploy HEAD; echo deploy",
  "cat <<'EOF'\ndeploy (notes) | release * \\ end\nEOF",
  "ls deploy; ls production",
  "cd deploy && ls release",
  "sed -n '1,5p' deploy.md",
  `git grep -e deploy ${rep('x ', 1000)}HEAD`,
  `git grep -c ${rep('deploy|', 1000)}x HEAD`,
  `git grep -c ${rep('deploy ', 10000)}HEAD`,
  `git grep -c ${rep('(', 3000)}deploy${rep(')', 3000)} HEAD`,
  `git grep -c ${rep('*', 3000)}deploy HEAD`,
  `git grep -c ${rep('\\', 3000)}deploy HEAD`,
  `git grep -c ${rep('|', 3000)}deploy HEAD`,
];
module.exports = { COMMANDS };
