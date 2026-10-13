'use strict';
const S = 'stop', P = 'pass';
module.exports = [
  ['A:elem-assign', 'cmd=(npm test); cmd[1]=publish; "${cmd[@]}"', S],
  ['A:elem-assign-0', 'cmd=(echo publish); cmd[0]=npm; "${cmd[@]}"', S],
  ['A:elem-assign-rm', 'c=(ls /home/u); c[0]=rm; c[2]=-rf; "${c[@]}"', S],
  ['A:elem-assign-git', 'a=(git status); a[1]=push; a[2]=-f; a[3]=origin; a[4]=main; "${a[@]}"', S],
  ['A:index-literal', 'cmd=([0]=npm [1]=publish); "${cmd[@]}"', S],
  ['A:prefix-then-args', 'cmd=(git push); "${cmd[@]}" -f origin main', S],
  ['A:prefix-npm', 'cmd=(npm); "${cmd[@]}" publish', S],
  ['A:prefix-rm', 'cmd=(rm -rf); "${cmd[@]}" /home/u', S],
  ['A:prefix-vercel', 'd=(vercel); "${d[@]}" --prod', S],
  ['A:prefix-wrangler', 'w=(wrangler pages deploy); "${w[@]}" dist --branch main', S],
  ['A:prefix-cat', 'r=(cat); "${r[@]}" ~/.aws/credentials', S],
  ['A:unquoted-prefix', 'cmd=(git push); ${cmd[@]} -f origin main', S],
  ['A:single-elem', 'g=(git); "${g[@]}" push -f origin main', S],
  ['A:star', 'cmd=(git push); ${cmd[*]} -f origin main', S],
  ['A:first-elem', 'cmd=(git push); "${cmd[0]}" push -f origin main', S],
  ['A:pass-test', 'cmd=(npm test); "${cmd[@]}"', P],
  ['A:pass-prefix-test', 'cmd=(npm); "${cmd[@]}" test', P],
].map(([id, cmd, expect]) => ({ id, cmd, expect }));
