'use strict';
module.exports = [
  { id: 'B1a', cmd: 'cmd=(npm test); cmd[1]=publish; "${cmd[@]}"' },
  { id: 'B1b', cmd: 'cmd=(git push); "${cmd[@]}" -f origin main' },
  { id: 'B1c', cmd: 'w=(wrangler pages deploy); "${w[@]}" dist --branch main' },
  { id: 'B1d', cmd: 'c=(ls /home/u); c[0]=rm; c[2]=-rf; "${c[@]}"' },
  { id: 'B2a', cmd: 'wrangler pages deploy dist --cwd ../other-repo' },
  { id: 'B2b', cmd: 'npx wrangler pages deploy dist --cwd=/home/u/other-repo' },
  { id: 'B3a', cmd: 'wrangler pages deploy dist & git checkout main' },
  { id: 'B3b', cmd: 'wrangler pages deploy dist | git checkout main' },
  { id: 'B3c', cmd: 'git push -f origin "$(git branch --show-current)" & git checkout main' },
  { id: 'B4a', cmd: 'git -c remote.origin.push=refs/heads/feat/x:refs/heads/main push -f origin "$(git branch --show-current)"' },
  { id: 'B4b', cmd: 'git config remote.origin.push +refs/heads/feat/x:refs/heads/main && git push origin "$(git branch --show-current)"' },
];
