// Copied verbatim from the independent audit of 613473cf (Barvis, 2026-10-12): out/evidence/ of the audit.
// Each row is the auditor's own reproducing case; test/seatbelt-audit-regression.test.js runs them.
'use strict';
const S = (id, cmd, opts) => ({ id, cmd, expect: 'stop', opts });
module.exports = [
  S('timeout-long', 'timeout --signal=KILL 5 npm publish'), S('timeout-k', 'timeout -k 1 5 npm publish'), S('nice-num', 'nice -10 npm publish'),
  S('sudo-dd', 'sudo -- npm publish'), S('sudo-flags', 'sudo -H -n -u u npm publish'), S('env-C', 'env -C /home/u/proj npm publish'),
  S('env-u', 'env -u X npm publish'), S('env-dd', 'env -- npm publish'), S('command-dd', 'command -- npm publish'), S('exec-c', 'exec -c npm publish'),
  S('npm-exec-package', 'npm exec --package=vercel -- vercel --prod'), S('npm-exec-c', "npm exec -c 'vercel --prod'"),
  S('npx-c', "npx -c 'vercel --prod'"), S('npm-ws-run', 'npm --workspace web run deploy'), S('yarn-run', 'yarn run deploy'),
  S('xargs-sh', "echo 'npm publish' | xargs -I{} sh -c '{}'"), S('xargs-0', 'printf "publish" | xargs -0 npm'),
  S('find-exec-sh', "find . -maxdepth 0 -exec sh -c 'npm publish' \;"), S('ionice', 'ionice -c3 npm publish'),
  S('setsid', 'setsid npm publish'), S('stdbuf', 'stdbuf -i0 -oL npm publish'), S('flock', 'flock /tmp/l npm publish'),
  S('flock-c', "flock /tmp/l -c 'npm publish'"), S('chroot?', 'chroot / npm publish'), S('unshare', 'unshare -r npm publish'),
  S('nsenter', 'nsenter -t 1 npm publish'), S('strace', 'strace -f npm publish'), S('ltrace?', 'ltrace npm publish'),
  S('dotenv-run', 'dotenv -- npm publish'), S('cross-env', 'cross-env NODE_ENV=production npm publish'), S('npx-cross-env', 'npx cross-env A=1 npm publish'),
  S('concurrently', "npx concurrently 'npm publish'"), S('npm-run-all', 'npx npm-run-all deploy'), S('entr', "ls | entr npm publish"),
  S('tmux', "tmux new -d 'npm publish'"), S('screen', "screen -dm npm publish"), S('at?', "echo 'npm publish' | at now"),
  S('make-e', 'make -e deploy'), S('make-var', "make deploy CMD='x'"), S('just-deploy', 'just deploy'), S('task-deploy', 'task deploy'),
  S('turbo-deploy', 'npx turbo run deploy'), S('nx', 'npx nx run app:deploy'),
  S('git-push-via-git-c-dir-alias', "git -C . -c alias.x='push -f' x origin main"),
  S('pipe-into-git-push-stdin?', 'yes | git push --force origin main'),
  S('newline-in-quoted-bashc', "bash -c 'npm test\nnpm publish'"),
  S('semicolon-in-dq-bashc', 'bash -c "npm test; git push -f origin main"'),
];
