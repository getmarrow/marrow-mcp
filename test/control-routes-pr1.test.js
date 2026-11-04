const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const test = require('node:test');

// PR-1 (reading half, 39a): wrapped control-off forms reach the owner check. controlRoute = legacy route OR the extra reading, so nothing master holds is lowered.
// All texts are static strings, never run. CONTROL_ROUTES_DIST lets the same file run against a BASE build (the red column).
const DIST = process.env.CONTROL_ROUTES_DIST || join(__dirname, '..', 'dist');
const routes = require(join(DIST, 'control-routes.js'));
const policy = require(join(DIST, 'hook-tool-policy.js'));
const { controlRoute } = routes;
// The 222 abuse rows of the spec (id, text, master column of the spec, PR-1 column, real BASE answer); 9 texts are cut at the spec's width (d01 d02 d03 d10 d12 d18 x31 h09 h10).
const ROWS = /* ROWS-BEGIN */ [
  {"id":"c01-H","text":"marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c02-H","text":"marrow-install control disable --yes","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c03-H","text":"npx @getmarrow/install control disable --yes","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c04-H","text":"npx -y @getmarrow/install@latest control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c05-H","text":"npx @getmarrow/install@0.1.77 control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c06-H","text":"npx --yes @getmarrow/install@^0.1 control off","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c07-H","text":"pnpm dlx @getmarrow/install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c08-H","text":"npm exec @getmarrow/install -- control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c09-H","text":"yarn dlx @getmarrow/install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c10-H","text":"bunx @getmarrow/install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c11-H","text":"pnpx @getmarrow/install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c12-H","text":"node /usr/lib/node_modules/@getmarrow/install/bin/marrow-install.js control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c13-H","text":"node ./node_modules/.bin/marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c14-H","text":"/usr/local/bin/marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c15-H","text":"./marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c16-H","text":"FOO=1 marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c17-H","text":"env FOO=1 marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c18-H","text":"marrow-install -- control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c19-H","text":"npx @getmarrow/install uninstall","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c20-H","text":"npx @getmarrow/install uninstall --yes --all","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c21-H","text":"marrow-install --uninstall","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c22-H","text":"npx @getmarrow/install control enable disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c23-C","text":"marrow-install control status --off","master":"clear","pr1":"clear","pr1raw":"clear","cls":"C","base":"clear"},
  {"id":"c24-H","text":"marrow-install control disable --yes --json","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c25-H","text":"marrow-install control --json disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c26-H","text":"marrow-install Control Disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c27-H","text":"npx @getmarrow/install control $ACTION","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c28-H","text":"marrow-install control \"disable\"","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c29-H","text":"marrow-install control dis''able","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c30-H","text":"\"marrow-install\" control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c31-R","text":"marrow\\-install control disable","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"c32-R","text":"marrow-ins''tall control disable","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"c33-R","text":"m=marrow; ${m}-install control disable","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"c34-R","text":"$'\\x6d\\x61rrow-install' control disable","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"c35-R","text":"ma\"\"rrow-install control disable","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"c36-R","text":"\uff4d\uff41\uff52\uff52\uff4f\uff57\uff0d\uff49\uff4e\uff53\uff54\uff41\uff4c\uff4c control disable","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"c37-R","text":"marr\u043ew-install control disable","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"c38-R","text":"marrow-in\u200bstall control disable","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"c39-H","text":"npx @getmarrow/install control disable; echo done","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c40-H","text":"cd /tmp && marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c41-H","text":"true || marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c42-H","text":"echo go | marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c43-H","text":"marrow-install control disable &","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"c44-H","text":"echo a\nmarrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"w01-H","text":"bash -c 'marrow-install control disable'","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"w02-H","text":"sh -c \"npx @getmarrow/install control disable\"","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"w03-R","text":"eval \"marrow-install control disable\"","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w04-R","text":"echo \"control disable\" | xargs marrow-install","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w05-R","text":"find /tmp -maxdepth 0 -exec marrow-install control disable \\;","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w06-H","text":"timeout 5 marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"w07-R","text":"env -S 'marrow-install control disable'","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w08-R","text":"sudo -u root marrow-install control disable","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w09-H","text":"nohup marrow-install control disable &","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"w10-R","text":"for i in 1; do marrow-install control disable; done","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w11-R","text":"if true; then npx @getmarrow/install control disable; fi","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w12-H","text":"f() { marrow-install control disable; }; f","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"w13-R","text":"alias m=marrow-install; m control disable","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w14-R","text":"x=marrow-install; $x control disable","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w15-H","text":"c=disable; marrow-install control $c","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"w16-R","text":"node -e \"require('child_process').execSync('marrow-install control disable')\"","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w17-R","text":"python3 -c \"import os; os.system('marrow-install control disable')\"","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w18-H","text":"npx --package=@getmarrow/install marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"w19-R","text":"deno run npm:@getmarrow/install control disable","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w20-H","text":"bash -c \"bash -c 'marrow-install control disable'\"","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"w22-R","text":"echo \"marrow-install control disable\" | sh","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w23-R","text":"echo \"marrow-install control disable\" | bash -s","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w24-H","text":"bash <<'EOF'\nmarrow-install control disable\nEOF","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"w25-H","text":"bash <<< \"marrow-install control disable\"","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"w26-H","text":"(marrow-install control disable)","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"w27-H","text":"{ marrow-install control disable; }","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"w28-H","text":"$(echo marrow-install) control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"w29-H","text":"bash <(echo marrow-install control disable)","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"w30-R","text":"printf 'marrow-install control disable' > /srv/x.sh && sh /srv/x.sh","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w33-H","text":"sudo marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"w34-H","text":"sudo -E marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"w35-H","text":"command -p marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"w36-H","text":"nice -n 5 marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"w37-R","text":"timeout -s KILL 30 marrow-install control disable","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w38-H","text":"stdbuf -oL marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"w40-H","text":"exec marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"w41-H","text":"setsid -f marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"w42-R","text":"watch marrow-install control disable","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w43-R","text":"ssh host 'marrow-install control disable'","master":"clear","pr1":"clear","pr1raw":"clear","cls":"R","base":"clear"},
  {"id":"w44-R","text":"docker exec box marrow-install control disable","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w45-R","text":"while true; do marrow-install control disable; break; done","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w46-R","text":"until false; do npx @getmarrow/install uninstall --yes; done","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w47-R","text":"case x in x) marrow-install control disable;; esac","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"HOLD"},
  {"id":"w48-R","text":"! marrow-install control disable","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w49-R","text":"time marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"HOLD"},
  {"id":"w50-R","text":"doas marrow-install control disable","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w51-R","text":"perl -e 'system(\"marrow-install control disable\")'","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w52-R","text":"ruby -e 'system(\"marrow-install\", \"control\", \"disable\")'","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w53-R","text":"git -c alias.x='!marrow-install control disable' x","master":"clear","pr1":"clear","pr1raw":"clear","cls":"R","base":"clear"},
  {"id":"w54-R","text":"make -C /tmp run CMD=\"marrow-install control disable\"","master":"clear","pr1":"clear","pr1raw":"clear","cls":"R","base":"clear"},
  {"id":"w55-R","text":"parallel marrow-install ::: control disable","master":"clear","pr1":"clear","pr1raw":"clear","cls":"R","base":"clear"},
  {"id":"w56-R","text":"script -qc \"marrow-install control disable\" /dev/null","master":"clear","pr1":"clear","pr1raw":"clear","cls":"R","base":"clear"},
  {"id":"w57-R","text":"bash -lc 'marrow-install control disable'","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"HOLD"},
  {"id":"w58-R","text":"bash -c $'marrow-install control disable'","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"HOLD"},
  {"id":"w59-R","text":"cmd=\"marrow-install control disable\"; $cmd","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w60-R","text":"cmd=\"marrow-install control disable\"; eval \"$cmd\"","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w61-R","text":"cmd=\"marrow-install control disable\"; bash -c \"$cmd\"","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w62-R","text":"function m { marrow-install \"$@\"; }; m control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"HOLD"},
  {"id":"w63-R","text":"sh -c 'exec marrow-install control disable'","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"HOLD"},
  {"id":"w64-R","text":"echo marrow-install control disable | xargs -0 sh -c","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"w65-R","text":"printf '%s\\n' marrow-install | xargs -I{} {} control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"HOLD"},
  {"id":"v01-H","text":"c=disable; marrow-install control $c","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"v02-H","text":"marrow-install control ${SUB}","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"v03-H","text":"marrow-install control 'echo disable'","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"v04-H","text":"marrow-install control $(echo disable)","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"v05-R","text":"sub=disable; npx @getmarrow/install control \"${sub}\"","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"HOLD"},
  {"id":"r01-R","text":"npm uninstall -g @getmarrow/mcp","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"r02-R","text":"npm rm -g @getmarrow/mcp","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"r03-R","text":"npm remove --global @getmarrow/mcp","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"r04-R","text":"npm un -g @getmarrow/mcp","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"r05-R","text":"npm r -g @getmarrow/mcp","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"r06-R","text":"pnpm remove -g @getmarrow/mcp","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"r07-R","text":"yarn global remove @getmarrow/mcp","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"r08-R","text":"bun remove -g @getmarrow/mcp","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"r09-R","text":"claude mcp remove marrow","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"r10-R","text":"claude plugin uninstall marrow","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"r11-R","text":"marrow control disable","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"r12-R","text":"marrow uninstall","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"r13-R","text":"npm uninstall @getmarrow/install","master":"clear","pr1":"clear","pr1raw":"clear","cls":"R","base":"clear"},
  {"id":"r14-R","text":"claude plugin marketplace remove marrow","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"r15-R","text":"claude mcp remove marrow --scope user","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"r16-R","text":"sudo npm uninstall -g @getmarrow/mcp","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"r17-R","text":"bash -c 'npm uninstall -g @getmarrow/mcp'","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"r18-R","text":"for p in @getmarrow/mcp; do npm uninstall -g $p; done","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"k01-C","text":"marrow-install control status","master":"clear","pr1":"clear","pr1raw":"clear","cls":"C","base":"clear"},
  {"id":"k02-C","text":"marrow-install control enable","master":"clear","pr1":"clear","pr1raw":"clear","cls":"C","base":"clear"},
  {"id":"k03-C","text":"npx @getmarrow/install control status --json","master":"clear","pr1":"clear","pr1raw":"clear","cls":"C","base":"clear"},
  {"id":"k04-C","text":"npx @getmarrow/install doctor","master":"clear","pr1":"clear","pr1raw":"clear","cls":"C","base":"clear"},
  {"id":"k05-C","text":"npx @getmarrow/install@latest --yes","master":"clear","pr1":"clear","pr1raw":"clear","cls":"C","base":"clear"},
  {"id":"k06-C","text":"npm install -g @getmarrow/mcp","master":"clear","pr1":"clear","pr1raw":"clear","cls":"C","base":"clear"},
  {"id":"k07-C","text":"npm ls -g @getmarrow/mcp","master":"clear","pr1":"clear","pr1raw":"clear","cls":"C","base":"clear"},
  {"id":"k08-C","text":"claude mcp list","master":"clear","pr1":"clear","pr1raw":"clear","cls":"C","base":"clear"},
  {"id":"k09-C","text":"marrow claim","master":"clear","pr1":"clear","pr1raw":"clear","cls":"C","base":"clear"},
  {"id":"k10-C","text":"claude mcp add marrow -- npx @getmarrow/mcp","master":"clear","pr1":"clear","pr1raw":"clear","cls":"C","base":"clear"},
  {"id":"k11-C","text":"npm uninstall -g left-pad","master":"clear","pr1":"clear","pr1raw":"clear","cls":"C","base":"clear"},
  {"id":"k12-C","text":"npx @getmarrow/install update","master":"clear","pr1":"clear","pr1raw":"clear","cls":"C","base":"clear"},
  {"id":"k13-C","text":"marrow-install status","master":"clear","pr1":"clear","pr1raw":"clear","cls":"C","base":"clear"},
  {"id":"k14-C","text":"npx @getmarrow/install control","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"C","base":"HOLD"},
  {"id":"k15-C","text":"node /usr/lib/node_modules/@getmarrow/install/bin/marrow-install.js control enable","master":"clear","pr1":"clear","pr1raw":"clear","cls":"C","base":"clear"},
  {"id":"k16-C","text":"claude mcp remove other-server","master":"clear","pr1":"clear","pr1raw":"clear","cls":"C","base":"clear"},
  {"id":"d01-D","text":"for r in marrow-install marrow-sdk; do echo \"$r $(git -C /srv/mirrors/$r.git grep -c TODO | wc","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"D","base":"HOLD"},
  {"id":"d02-D","text":"while read r; do git -C /srv/mirrors/$r.git grep -c TODO; done <<< \"marrow-install marrow-sdk\"","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"D","base":"HOLD"},
  {"id":"d03-D","text":"cat >> /srv/logs/dogfood.md <<'EOF'\nTALLY: friction 9. Control off is owner-only (the owner ru","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"D","base":"clear"},
  {"id":"d04-D","text":"pnpm -C $HOME/marrow-install install","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"D","base":"HOLD"},
  {"id":"d05-D","text":"for r in marrow-install marrow-sdk; do { git -C /srv/mirrors/$r.git grep -c TODO; } ; done","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"D","base":"HOLD"},
  {"id":"d06-D","text":"git commit -m \"$(cat <<'EOF'\ndocs: marrow-install control disable is owner-only\nEOF\n)\"","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"D","base":"HOLD"},
  {"id":"d07-D","text":"git -C \"$(git rev-parse --show-toplevel)/marrow-install\" grep -c disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"D","base":"HOLD"},
  {"id":"d08-D","text":"cat <<'EOF' | grep -c marrow-install\nmarrow-install control disable\nEOF","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"D","base":"HOLD"},
  {"id":"d09-D","text":"r=marrow-install; git -C /srv/mirrors/$r.git grep -c TODO","master":"clear","pr1":"clear","pr1raw":"clear","cls":"D","base":"clear"},
  {"id":"d10-D","text":"for d in /srv/mirrors/marrow-install.git /srv/mirrors/marrow-sdk.git; do git -C $d grep -c \"cont","master":"clear","pr1":"clear","pr1raw":"clear","cls":"D","base":"HOLD"},
  {"id":"d11-D","text":"grep -rn \"marrow-install control disable\" \"$HOME/notes\"","master":"clear","pr1":"clear","pr1raw":"clear","cls":"D","base":"clear"},
  {"id":"d12-D","text":"echo \"Control off is owner-only; run marrow-install control disable yourself\" >> \"$HOME/notes/lo","master":"clear","pr1":"clear","pr1raw":"clear","cls":"D","base":"HOLD"},
  {"id":"d13-D","text":"printf '%s\\n' \"marrow-install: $(date)\" >> /srv/logs/x.log","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"D","base":"HOLD"},
  {"id":"d14-D","text":"ls -la /srv/mirrors/marrow-install.git/$(date +%Y)","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"D","base":"HOLD"},
  {"id":"d15-D","text":"(cd /srv/mirrors/marrow-install.git && git grep -c TODO)","master":"clear","pr1":"clear","pr1raw":"clear","cls":"D","base":"clear"},
  {"id":"d16-D","text":"git log --oneline -5 -- marrow-install/ $(git ls-files | head -1)","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"D","base":"HOLD"},
  {"id":"d17-D","text":"rg -c \"marrow-install control disable\" /srv/repos --glob '!node_modules'","master":"clear","pr1":"clear","pr1raw":"clear","cls":"D","base":"clear"},
  {"id":"d18-D","text":"for r in marrow-install marrow-sdk; do echo \"== $r\"; git -C /srv/mirrors/$r.git log --oneline -3","master":"clear","pr1":"clear","pr1raw":"clear","cls":"D","base":"clear"},
  {"id":"d19-D","text":"cat > /srv/note.md <<EOF\nrepo marrow-install control $USER\nEOF","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"D","base":"HOLD"},
  {"id":"d20-D","text":"find /srv/mirrors -maxdepth 1 -name 'marrow-install*' -type d","master":"clear","pr1":"clear","pr1raw":"clear","cls":"D","base":"clear"},
  {"id":"x01-H","text":"cat > /srv/run.sh <<'EOF'\nmarrow-install control disable\nEOF\nsh /srv/run.sh","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"x02-H","text":"echo \"marrow-install control disable\" | sh","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"clear"},
  {"id":"x03-H","text":"cat <<'EOF' | bash\nmarrow-install control disable\nEOF","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"x04-H","text":"for r in marrow-install; do $r control disable; done","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"clear"},
  {"id":"x05-H","text":"for r in marrow-install; do ${r} control disable; done","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"clear"},
  {"id":"x06-H","text":"for c in \"marrow-install control disable\"; do $c; done","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"clear"},
  {"id":"x07-H","text":"cat <<EOF\n$(marrow-install control disable)\nEOF","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"x08-H","text":"GIT_PAGER='marrow-install control disable' git log","master":"clear","pr1":"clear","pr1raw":"clear","cls":"H","base":"clear"},
  {"id":"x09-H","text":"git -c core.pager='marrow-install control disable' log","master":"clear","pr1":"clear","pr1raw":"clear","cls":"H","base":"clear"},
  {"id":"x10-H","text":"rg --pre 'marrow-install control disable' foo .","master":"clear","pr1":"clear","pr1raw":"clear","cls":"H","base":"clear"},
  {"id":"x11-H","text":"git grep -O'marrow-install control disable' foo","master":"clear","pr1":"clear","pr1raw":"clear","cls":"H","base":"clear"},
  {"id":"x12-H","text":"echo hi; alias g=marrow-install; g control disable","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"clear"},
  {"id":"x13-H","text":"python3 <<'EOF'\nimport os\nos.system(\"marrow-install control disable\")\nEOF","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"x14-H","text":"node <<'EOF'\nrequire('child_process').execSync('marrow-install control disable')\nEOF","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"x15-H","text":"find /srv -name 'marrow-install*' -exec marrow-install control disable \\;","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"clear"},
  {"id":"x16-H","text":"ls /srv/marrow-install | xargs marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"x17-H","text":"echo marrow-install > /srv/p; $(cat /srv/p) control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"x18-H","text":"git commit -m \"marrow-install\" && marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"x19-H","text":"cat /srv/marrow-install/notes | sh","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"clear"},
  {"id":"x20-H","text":"cat <<'EOF' > /srv/s.sh\nmarrow-install control disable\nEOF\nbash /srv/s.sh","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"x21-H","text":"echo marrow-install control disable | tee /dev/stderr | sh","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"clear"},
  {"id":"x22-H","text":"cat 'echo /srv/marrow-install' ; marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"x23-H","text":"for r in marrow-install; do git -C /srv/$r.git log; done; marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"x24-H","text":"grep -c marrow-install /srv/x.log; npx @getmarrow/install uninstall","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"x25-H","text":"export P=marrow-install; $P control disable","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"clear"},
  {"id":"x26-H","text":"read -r p <<< \"marrow-install\"; $p control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"x27-H","text":"git -C /srv/marrow-install grep -c x && bash -c 'marrow-install control disable'","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"x28-H","text":"sed -n 'e marrow-install control disable' /etc/hostname","master":"clear","pr1":"clear","pr1raw":"clear","cls":"H","base":"clear"},
  {"id":"x29-H","text":"awk 'BEGIN{system(\"marrow-install control disable\")}'","master":"clear","pr1":"clear","pr1raw":"clear","cls":"H","base":"clear"},
  {"id":"x30-H","text":"cat <<'EOF'\n$(marrow-install control disable)\nEOF\nbash -c \"$(cat <<'EOF'\nmarrow-install","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"x31-H","text":"echo \"#!/bin/sh\" > /srv/m; echo \"marrow-install control disable\" >> /srv/m; chmod +x /srv/m; /tm","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"clear"},
  {"id":"x32-H","text":"grep -c marrow-install /srv/x.log || marrow-install control disable","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"x33-H","text":"git log --format=%H -1 marrow-install; source /srv/a.sh","master":"clear","pr1":"clear","pr1raw":"clear","cls":"H","base":"clear"},
  {"id":"x34-H","text":"echo marrow-install; . ./a.sh","master":"clear","pr1":"clear","pr1raw":"clear","cls":"H","base":"clear"},
  {"id":"x35-H","text":"cat marrow-install | exec sh","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"clear"},
  {"id":"x36-H","text":"tee /srv/q.sh <<< \"marrow-install control disable\" >/dev/null; sh /srv/q.sh","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"g01-R","text":"marrow-inst{a..a}ll control disable --yes","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"g02-R","text":"/usr/local/bin/marrow-inst* control disable --yes","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"g03-R","text":"npx @getmarrow/inst{a..a}ll control disable --yes","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"g04-H","text":"{marrow-install,} control disable --yes","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"g05-R","text":"~/.npm/_npx/*/node_modules/.bin/marrow-* control disable --yes","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"g06-R","text":"marrow-i?stall control disable --yes","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"g07-R","text":"sudo marrow-inst{a..a}ll control disable --yes","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"g08-C","text":"echo marrow-inst{a..a}ll control disable","master":"clear","pr1":"clear","pr1raw":"clear","cls":"C","base":"clear"},
  {"id":"g09-C","text":"ls marrow-inst*","master":"clear","pr1":"clear","pr1raw":"clear","cls":"C","base":"clear"},
  {"id":"g10-C","text":"grep -r 'marrow-inst*' .","master":"clear","pr1":"clear","pr1raw":"clear","cls":"C","base":"clear"},
  {"id":"g11-R","text":"/usr/local/bin/marrow-inst[a]ll control disable --yes","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"g12-R","text":"npx @getmar{r,r}ow/install control disable --yes","master":"clear","pr1":"HOLD","pr1raw":"HOLD","cls":"R","base":"clear"},
  {"id":"h01-H","text":"cat > .git/config <<'EOF'\n[core]\n\tfsmonitor = marrow-install control disable --yes\nEOF\ng","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"h02-D","text":"cat >> ~/.bashrc <<'EOF'\nmarrow-install control disable --yes\nEOF","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"D","base":"HOLD"},
  {"id":"h03-H","text":"sort -S 1b --compress-program=marrow-install big.txt \"$(echo f)\"","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"h04-H","text":"sort -o ~/.claude/settings.json f \"$(echo g)\" # marrow-install control","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"h05-H","text":"find ~/.claude -name \"*marrow*\" -delete \"$(echo x)\" # marrow-install control","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"h06-H","text":"git -C /srv/marrow-install.git log --output=/home/u/.claude/settings.json \"$(echo x)\"","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"},
  {"id":"h07-D","text":"tee ~/.claude/settings.json <<'EOF'\n{}\nEOF\n# marrow-install control","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"D","base":"HOLD"},
  {"id":"h08-F","text":"find / -name x -fprint ~/.claude/settings.json # marrow-install control \"$(echo)\"","master":"clear","pr1":"clear","pr1raw":"clear","cls":"F","base":"clear"},
  {"id":"h09-F","text":"printf '*.x diff=d\\n' > .gitattributes && git config diff.d.command 'marrow-install control disa","master":"clear","pr1":"clear","pr1raw":"clear","cls":"F","base":"HOLD"},
  {"id":"h10-H","text":"echo '[core]\nfsmonitor = marrow-install control disable' > .git/config; echo \"$(date)\"; git st","master":"HOLD","pr1":"HOLD","pr1raw":"HOLD","cls":"H","base":"HOLD"}
] /* ROWS-END */;
const hold = (text, note) => assert.equal(controlRoute(text), true, `HOLD expected: ${note || text}`);
const clear = (text, note) => assert.equal(controlRoute(text), false, `clear expected: ${note || text}`);
const X = 'marrow-install control disable';
const withLimits = (patch, fn) => {
  const saved = { ...routes.CONTROL_READ_LIMITS };
  Object.assign(routes.CONTROL_READ_LIMITS, patch);
  try { return fn(); } finally { Object.assign(routes.CONTROL_READ_LIMITS, saved); }
};

// ---- B01 / LD-A0a: the legacy block is master's, byte for byte (only the function name and the export keyword differ)
test('B01 legacy block hash equals master a1bf437a / A0 eb09174 lines 41-72', () => {
  const src = fs.readFileSync(join(__dirname, '..', 'src', 'control-routes.ts'), 'utf8');
  const start = src.indexOf('function segmentIsRoute(');
  const end = src.indexOf('\n}\n', src.indexOf('function legacyRoute(')) + 3;
  assert.ok(start > 0 && end > start, 'legacy block found');
  const block = src.slice(start, end).replace('function legacyRoute(', 'export function controlRoute(');
  assert.equal(createHash('sha256').update(block).digest('hex'), 'cea8d4602602e0040d7669ca33cdde4436ba2501c3dc3948912a9d78c93f654b');
  assert.match(src, /export function controlRoute\([^)]*\): boolean \{\s*return legacyRoute\(/, 'controlRoute = legacyRoute || newRoute');
});

// ---- B03 / LD-A0c: the 222 abuse rows (columns: master answer, PR-1 answer). 39b rows are listed, never asserted looser than master.
const IN_39A = new Set('c31 c32 c33 c34 c35 c36 c37 c38 w03 w04 w05 w07 w08 w10 w11 w13 w14 w19 w37 w45 w46 w48 w50 w59 w60 w61 w64 x04 x05 x06 x12 x15 x25 g01 g02 g03 g05 g06 g07 g11 g12'.split(' '));
test('B03 222 abuse rows', () => {
  assert.equal(ROWS.length, 222);
  const bad = [];
  for (const row of ROWS) {
    const got = controlRoute(row.text);
    const stem = row.id.split('-')[0];
    if (row.base === 'HOLD' && !got) bad.push(`${row.id} lowered`);
    else if (row.base === 'clear' && row.pr1 === 'clear' && got) bad.push(`${row.id} newly held`);
    else if (row.base === 'clear' && row.pr1 === 'HOLD' && IN_39A.has(stem) && !got) bad.push(`${row.id} not raised`);
  }
  assert.deepEqual(bad, []);
});
test('B03 the 41 reading rows are red on master (clear) and green here', () => {
  assert.equal(ROWS.filter((r) => IN_39A.has(r.id.split('-')[0])).length, 41);
  for (const row of ROWS.filter((r) => IN_39A.has(r.id.split('-')[0]))) { assert.equal(row.base, 'clear', row.id); hold(row.text, row.id); }
});

// ---- B04: one positive and one near-miss per form F01-F16 and F33
const PAIRS = [
  ['F01', 'marrow\\-install control disable', 'marrow\\-install control status'],
  ['F02', "$'\\x6d\\x61rrow-install' control disable", "$'\\x6d\\x61rrow-install' control status"],
  ['F03', 'ｍａｒｒｏｗ－ｉｎｓｔａｌｌ control disable', 'ｍａｒｒｏｗ－ｉｎｓｔａｌｌ control status'],
  ['F04', 'deno run npm:@getmarrow/install control disable', 'deno run npm:left-pad control disable'],
  ['F05', `for i in 1; do ${X}; done`, 'for i in 1; do marrow-install control status; done'],
  ['F06', `sudo -u root ${X}`, 'sudo -u root marrow-install doctor'],
  ['F07', `eval "${X}"`, 'eval "marrow-install control status"'],
  ['F08', `env -S '${X}'`, "env -S 'marrow-install control status'"],
  ['F09', `find /tmp -maxdepth 0 -exec ${X} \\;`, 'find /tmp -maxdepth 0 -exec marrow-install control status \\;'],
  ['F10', 'echo "control disable" | xargs marrow-install', 'echo marrow-install | xargs grep -c x'],
  ['F11', `alias m=marrow-install; m control disable`, 'alias m=marrow-install; m control status'],
  ['F12', 'x=marrow-install; $x control disable', 'x=marrow-install; $x control status'],
  ['F13', 'for r in marrow-install; do $r control disable; done', 'for r in marrow-install; do $r control status; done'],
  ['F14', 'm=$(echo marrow); ${m}-install control disable', 'm=$(echo marrow); ${m}-install control status'],
  ['F15', `bash -c "bash -c '${X}'"`, `bash -c "bash -c 'marrow-install control status'"`],
  ['F16', `(${X})`, '(marrow-install doctor)'],
  ['F33', 'marrow-inst{a..a}ll control disable', 'echo marrow-inst{a..a}ll control disable'],
];
for (const [form, positive, near] of PAIRS) {
  test(`B04 ${form} positive holds, near-miss clear`, () => { hold(positive, `${form} positive`); clear(near, `${form} near-miss`); });
}

// ---- B05: spelling views, one row per spelling and per look-alike entry
const SPELLINGS = [
  ['single quotes', "'marrow-install' control disable"], ['double quotes', '"marrow-install" control disable'],
  ['quote pair inside the name', "marrow-ins''tall control disable"], ['double quote pair inside', 'ma""rrow-install control disable'],
  ['quoted subcommand', 'marrow-install control "dis\'\'able"'], ['backslash', 'marrow\\-install control disable'],
  ['backslash in subcommand', 'marrow-install control dis\\able'], ['line continuation', 'marrow-ins\\\ntall control disable'],
  ['ANSI-C hex', "$'\\x6d\\x61rrow-install' control disable"], ['ANSI-C unicode', "$'\\u006darrow-install' control disable"],
  ['ANSI-C long unicode', "$'\\U0000006darrow-install' control disable"], ['ANSI-C octal', "$'\\155arrow-install' control disable"],
  ['ANSI-C whole name', "$'marrow-install' control disable"], ['ANSI-C subcommand', "marrow-install control $'dis\\x61ble'"],
  ['ANSI-C control char kept as data', "$'marrow-install' control disable $'\\cA'"], ['ANSI-C escaped quote', "$'marrow-install' control $'disable\\''"],
  ['quotes around the package', 'npx "@getmarrow/install" control disable'], ['mixed quotes', "npx '@get'\"marrow\"/install control disable"],
];
for (const [id, text] of SPELLINGS) test(`B05 unquote view: ${id}`, () => hold(text));
const ZERO_WIDTH = ['​', '‌', '‍', '⁠', '﻿', '­'];
for (const ch of ZERO_WIDTH) test(`B05 invisible removal U+${ch.codePointAt(0).toString(16)}`, () => hold(`marrow-in${ch}stall control disable`));
test('B05 NFKC fold: full-width subcommand and name', () => { hold('marrow-install control ｄｉｓａｂｌｅ'); hold('ｍａｒｒｏｗ-install control disable'); });
// [look-alike, real letter, context]: each entry is the only thing that hides the word in its context
const CONTEXT = { name: (l, f) => `npx @getmarrow/install control disable`.replace(l, f), disable: (l, f) => `marrow-install ${'disable'.replace(l, f)}`, uninstall: (l, f) => `marrow-install ${'uninstall'.replace(l, f)}`, control: (l, f) => `marrow-install ${'control'.replace(l, f)}` };
const LOOKALIKES = [
  ['а', 'a', 'name'], ['е', 'e', 'name'], ['о', 'o', 'name'], ['і', 'i', 'name'], ['ѕ', 's', 'name'], ['ԝ', 'w', 'name'], ['м', 'm', 'name'], ['т', 't', 'name'],
  ['г', 'r', 'name'], ['ӏ', 'l', 'name'], ['ɡ', 'g', 'name'], ['ᴍ', 'm', 'name'], ['ʀ', 'r', 'name'], ['ɴ', 'n', 'name'], ['ᴛ', 't', 'name'],
  ['ʟ', 'l', 'name'], ['ı', 'i', 'name'], ['ο', 'o', 'name'], ['α', 'a', 'name'], ['ᴡ', 'w', 'name'], ['ꜱ', 's', 'name'],
  ['ԁ', 'd', 'disable'], ['ʙ', 'b', 'disable'], ['ᴇ', 'e', 'disable'], ['а', 'a', 'disable'], ['і', 'i', 'disable'], ['ѕ', 's', 'disable'], ['ᴜ', 'u', 'uninstall'],
  ['с', 'c', 'control'], ['о', 'o', 'control'], ['т', 't', 'control'], ['ʀ', 'r', 'control'], ['ɴ', 'n', 'control'], ['ӏ', 'l', 'control'],
];
for (const [fake, real, ctx] of LOOKALIKES) {
  test(`B05 look-alike U+${fake.codePointAt(0).toString(16)} for ${real} (${ctx})`, () => {
    const text = CONTEXT[ctx](real, fake);
    assert.notEqual(text, CONTEXT[ctx](real, real));
    hold(text);
    clear(`echo ${fake} marrow-install status`, `${real} look-alike as data`);
  });
}
test('B05 view cost is counted: over 262,144 chars only the raw view is read', () => {
  hold(`${X}${' '.repeat(262200)}`);
  hold(`${' '.repeat(262200)}\n${X}`);
  hold(`marrow-install doctor${' '.repeat(262200)}`);
  clear(`ls -la${' '.repeat(262200)}`);
  assert.ok(routes.CONTROL_READ_STATS.steps <= 262400, 'counted');
});

// ---- B06: wrappers x value options x glued forms
const MORE = { timeout: '30 ' };
const WRAPPERS = [
  ['sudo', [['-u', 'root'], ['-g', 'wheel'], ['-h', 'host'], ['-p', 'pw:'], ['-C', '3'], ['-D', '/tmp'], ['-R', '/tmp'], ['-T', '5'], ['-U', 'root'], ['--user', 'root'], ['--group', 'wheel']], ['-uroot', '--user=root', '-gwheel', '-E']],
  ['doas', [['-u', 'root'], ['-C', '/etc/doas.conf']], ['-uroot']],
  ['env', [['-u', 'FOO'], ['-C', '/tmp'], ['--unset', 'FOO'], ['--chdir', '/tmp']], ['-uFOO', '--unset=FOO', '--chdir=/tmp', '-i', 'A=1']],
  ['nohup', [], []], ['builtin', [], []], ['exec', [['-a', 'name']], ['-aname', '-c']], ['command', [], ['-p']],
  ['time', [['-f', '%e'], ['-o', '/dev/null'], ['--format', '%e']], ['-f%e', '--output=/dev/null', '-p']],
  ['nice', [['-n', '5'], ['--adjustment', '5']], ['-n5', '--adjustment=5']],
  ['ionice', [['-c', '2'], ['-n', '4'], ['-p', '1']], ['-c2', '-n4']],
  ['stdbuf', [['-o', 'L'], ['-i', '0'], ['-e', 'L']], ['-oL', '-i0', '-eL']],
  ['timeout', [['-s', 'KILL'], ['-k', '5'], ['--signal', 'KILL'], ['--kill-after', '5']], ['-sKILL', '--signal=KILL', '-k5', '--foreground']],
  ['xargs', [['-n', '1'], ['-I', '%'], ['-P', '2'], ['-d', '\\n'], ['-E', 'eof'], ['-a', '/dev/null']], ['-n1', '-P2', '-0', '-r']],
  ['setsid', [], ['-f', '-w', '-c']], ['unbuffer', [], ['-p']],
];
for (const [wrapper, spaced, glued] of WRAPPERS) {
  const more = MORE[wrapper] || '';
  test(`B06 wrapper ${wrapper}`, () => {
    hold(`${wrapper} ${more}${X}`);
    for (const [flag, value] of spaced) { hold(`${wrapper} ${flag} ${value} ${more}${X}`, `${wrapper} ${flag} ${value}`); clear(`${wrapper} ${flag} ${value} ${more}echo ${X}`, `${wrapper} ${flag} data`); }
    for (const flag of glued) hold(`${wrapper} ${flag} ${more}${X}`, `${wrapper} ${flag}`);
    if (wrapper !== 'xargs') clear(`${wrapper} ${more}marrow-install doctor`);
    clear(`${wrapper} ${more}echo ${X}`);
  });
}
test('B06 stacked wrappers and repeated flags (last one wins)', () => {
  hold(`sudo -u root env -u A nice -n 5 timeout -s KILL 30 ionice -c 2 ${X}`);
  hold(`sudo -u a -u b ${X}`); hold(`timeout -s TERM -s KILL 30 ${X}`);
  hold(`time -f %e sudo -u root nohup ${X}`); hold(`doas -u root npx @getmarrow/install@latest control disable`);
  hold(`env -iS '${X}'`); hold(`env -i -S '${X}'`); hold(`env --split-string='${X}'`); hold(`env -S${JSON.stringify(X)}`); clear("env -S 'marrow-install control status'");
  hold(`${'nohup '.repeat(1200)}${X}`); clear(`${'nohup '.repeat(1200)}echo ${X}`);
});

// ---- B07: keywords and constructs, before the installer, before a wrapper
const FORMS = [
  (c) => `if true; then ${c}; fi`, (c) => `if false; then true; else ${c}; fi`, (c) => `if false; then true; elif ${c}; then true; fi`, (c) => `if ${c}; then true; fi`,
  (c) => `while true; do ${c}; break; done`, (c) => `while ${c}; do true; done`, (c) => `until false; do ${c}; done`, (c) => `until ${c}; do true; done`,
  (c) => `for i in 1; do ${c}; done`, (c) => `select s in a; do ${c}; done`, (c) => `! ${c}`, (c) => `{ ${c}; }`, (c) => `(${c})`, (c) => `case a in a) ${c};; esac`,
  (c) => `case a in a|b) ${c};; esac`, (c) => `true; ${c}`, (c) => `true && ${c}`, (c) => `false || ${c}`, (c) => `true | ${c}`, (c) => `while true; do while true; do ${c}; done; done`,
  (c) => `do ${c}`, (c) => `then ${c}`, (c) => `else ${c}`, (c) => `if ! ${c}; then true; fi`, (c) => `f() { ${c}; }; f`, (c) => `function f { ${c}; }`,
];
const PARSE_NULL = [11, 12, 13, 14, 24, 25];
FORMS.forEach((form, index) => {
  test(`B07 construct ${index}`, () => {
    hold(form(X)); hold(form(`sudo -u root ${X}`)); hold(form(`timeout -s KILL 30 ${X}`)); hold(form(`npx @getmarrow/install control disable`));
    clear(form('marrow-install doctor')); clear(form('sudo -u root marrow-install doctor'));
    if (!PARSE_NULL.includes(index)) clear(form(`echo ${X}`)); // master's parse-null fallback already holds a brace group, subshell, case arm or function body that names control words
  });
});
test('B07 done fi esac in on their own are not commands', () => { clear('for i in 1; do true; done; if true; then true; fi; case a in a) true;; esac'); hold(`done; fi; esac; ${X}`); });

// ---- B08: alias / variable / for-list bindings
const BOUND = [
  'alias m=marrow-install; m control disable', "alias m='marrow-install control'; m disable", 'alias a=b; alias b=marrow-install; a control disable',
  'alias a=b; alias b=c; alias c=d; alias d=marrow-install; a control disable',
  'x=marrow-install; $x control disable', 'x=marrow-install; ${x} control disable', 'export P=marrow-install; $P control disable', 'declare P=marrow-install; $P control disable',
  'declare -x P=marrow-install; $P control disable', 'local P=marrow-install; $P control disable', 'readonly P=marrow-install; $P control disable',
  'read -r p <<< "marrow-install"; $p control disable', 'for r in marrow-install; do $r control disable; done', 'for r in a marrow-install b; do ${r} control disable; done',
  'for c in "marrow-install control disable"; do $c; done', 'cmd="marrow-install control disable"; $cmd', 'cmd="marrow-install control disable"; eval "$cmd"',
  'cmd="marrow-install control disable"; bash -c "$cmd"', 'm=marrow; ${m}-install control disable', 'p=@getmarrow/install; npx $p control disable',
  'x=left-pad; x=marrow-install; $x control disable', 'x=marrow-install; x=left-pad; $x control disable', 'a=mar; b=row-install; $a$b control disable',
  'sub=disable; marrow-install control $sub', 'm=$(echo marrow); ${m}-install control disable', '$r control disable', 'r=$(pick); $r uninstall',
];
BOUND.forEach((text, index) => test(`B08 binding ${index}`, () => hold(text)));
test('B08 near-misses stay clear', () => {
  for (const text of ['x=marrow-install; $x control status', 'alias m=marrow-install; m control status', 'for r in a b; do $r control disable; done'.replace('control disable', 'status'),
    'x=left-pad; $x control status', 'cmd=ls; $cmd control disable', '$cmd', '$cmd status', '$cmd control status', 'for r in a b; do echo $r; done', 'x=marrow-install; echo $x control disable',
    '$cmd; echo control disable; marrow-install doctor']) clear(text);
});
test('B08 F14 stays inside the segment (M21)', () => { hold('$cmd; $r control disable'); clear('$cmd; echo control disable; marrow-install doctor'); });
test('B08 definitions and rounds are counted: over the limit holds when the installer is named', () => {
  const many = Array.from({ length: 70 }, (_, i) => `v${i}=a${i}`).join('; ');
  hold(`${many}; marrow-install doctor`); clear(`${many}; ls`);
  hold('alias a=b; alias b=c; alias c=d; alias d=e; alias e=marrow-install; a doctor');
  const segments = Array.from({ length: 260 }, () => 'true').join('; ');
  hold(`${segments}; marrow-install doctor`); clear(`${segments}; ls`);
});

// ---- B15: fail closed (parser null, throws, depth, budget, size)
test('B04 lexer guards: comments, redirect targets, ANSI-C escapes, nested braces, self-appending bindings, long brace words', () => {
  clear('echo ok # a; npx -y @getmarrow/install control disable'); clear('echo ok #; marrow-install uninstall');
  clear('> marrow-install control disable'); clear('2> marrow-install control disable');
  hold("npx -y $'@getmarrow/inst\\x61ll' control disable"); hold("npx -y @getmarrow/inst$'\\141'll control disable");
  hold('npx -y @getm{arro,xxxx}w/ins{tal,xxx}l control disable');
  clear('export PATH=$PATH:/opt/marrow-install/bin; echo $PATH'); clear('PATH=$PATH:/opt/marrow-install npx other-tool run $PATH');
  clear(`npx -y ${'{a,b}'.repeat(7)}${'z'.repeat(140)}marrow control disable`); hold(`npx -y ${'{a,b}'.repeat(7)}marrow control disable`);
});
test('B15 depth over 3 holds when the text names the installer', () => {
  const nest = (n, inner) => (n === 0 ? inner : `bash -c ${JSON.stringify(nest(n - 1, inner))}`);
  hold(nest(3, 'marrow-install control disable')); hold(nest(5, 'marrow-install doctor')); clear(nest(5, 'ls'));
  assert.equal(controlRoute('marrow-install doctor', 4), true); assert.equal(controlRoute('ls', 4), false);
});
test('B15 text over 8192 bytes holds when a view names the installer, clear when it names neither', () => {
  const pad = ' '.repeat(8200);
  hold(`marrow-install doctor${pad}`); hold(`ma""rrow-in\\stall doctor${pad}`); hold(`${pad}\n@getmarrow/install`); hold(`marrow-inst{a..a}ll control disable;${pad}`);
  clear(`ls -la${pad}`); clear(`echo "marrow"${pad}`);
});
test('B15 budget overrun holds when the text names the installer (forced budget of 1)', () => withLimits({ steps: 1 }, () => {
  hold('marrow-install doctor'); hold('ls; marrow-install status'); clear('ls -la /tmp'); clear('echo hello world');
}));
test('B15 a thrown reader error holds when the text names the installer', () => {
  const saved = String.prototype.normalize;
  String.prototype.normalize = function () { throw new Error('forced'); };
  try { hold('marrow-install doctor'); hold(`${X}`); clear('ls -la'); } finally { String.prototype.normalize = saved; }
  const parse = policy.parseShellSegments;
  policy.parseShellSegments = () => { throw new Error('forced'); };
  try { hold('marrow-install control disable'); clear('ls -la'); } finally { policy.parseShellSegments = parse; }
});
test('B15 parser null keeps the legacy fallback and the extra reading still runs', () => {
  const parse = policy.parseShellSegments;
  policy.parseShellSegments = () => null;
  try { hold('marrow-install control disable'); hold('sudo -u root marrow-install control disable'); hold('x=marrow-install; $x control disable'); clear('marrow-install doctor'); clear('ls -la'); } finally { policy.parseShellSegments = parse; }
});
test('B15 the answer is the same when asked twice, and the empty and odd inputs are clear', () => {
  for (const text of [X, 'ls', '', ' ', ';;', '((', '$(', '`', "'", '"', '$\'', '\\', '{', '}', '#']) assert.equal(controlRoute(text), controlRoute(text), text);
  for (const text of ['', ' ', ';;', '((', '$(', '`', "'", '"', '\\', '{', '}', '#', '$']) clear(text);
  assert.equal(controlRoute(undefined), false); assert.equal(controlRoute(null), false); assert.equal(controlRoute(42), false);
});

// ---- B25: shell-expanded spellings
const GLOBS = [
  'marrow-inst{a..a}ll control disable --yes', '/usr/local/bin/marrow-inst* control disable --yes', 'npx @getmarrow/inst{a..a}ll control disable --yes', '{marrow-install,} control disable --yes',
  '~/.npm/_npx/*/node_modules/.bin/marrow-* control disable --yes', 'marrow-i?stall control disable --yes', 'sudo marrow-inst{a..a}ll control disable --yes',
  '/usr/local/bin/marrow-inst[a]ll control disable --yes', 'npx @getmar{r,r}ow/install control disable --yes', 'env A=1 marrow-inst{a,}ll control disable', 'timeout 5 marrow-i?stall control disable',
  'pnpm dlx @getmarrow/inst[a]ll control disable', 'bunx @getmarrow/instal? control disable', 'npx --package=@getmarrow/inst{a..a}ll marrow-install control disable',
  'marrow-install{,.js} control disable', 'marrow-{install,sdk} uninstall', 'marrow-install.[cm]js control disable', 'node /x/@getmarrow/inst*/bin/marrow-install.js control disable',
  'marrow* control disable', 'marrow-{a..z}{a..z}{a..z} control disable', '{,}marrow-i?stall control disable', 'marrow-ins{t,t}{a,a}ll control disable', 'marrow-inst{a..a}ll uninstall',
];
GLOBS.forEach((text, index) => test(`B25 glob/brace spelling ${index}`, () => hold(text)));
test('B25 data positions and short targets stay clear', () => {
  for (const text of ['echo marrow-inst{a..a}ll control disable', 'ls marrow-inst*', "grep -r 'marrow-inst*' .", 'echo marrow-i?stall', 'cat marrow-inst[a]ll', 'git log -- marrow-inst*',
    'm* control disable', 'mar* control disable', 'marr* control disable', 'marro* control disable', '{m,n}a?? control disable', 'x{a..z}{a..z}{a..z}ll control disable',
    'marrow-inst{a..a}ll control status', 'ls /usr/local/bin/marrow-inst*', 'npx left-pad{a..a} control disable', 'rm -rf marrow-inst*']) clear(text);
  hold('marrow* control disable');
});

// ---- B17 consumers (classification label, deny text, ordering with other classification)
const { classifyTool } = require(join(DIST, 'hook-pre-action.js'));
const { heldLabel } = require('./support/mcp-109-n2-categories.cjs');
const SECURITY_LABEL = 'classified Bash action: security on marrow-control';
const bash = (command, cwd) => classifyTool({ tool_name: 'Bash', tool_input: { command }, cwd: cwd || tmpdir() });
test('B17 consumers: label, risk, chain with another surface, constant deny text', () => {
  for (const text of ['sudo -u root marrow-install control disable', "$'\\x6d\\x61rrow-install' control disable", 'marrow-inst{a..a}ll control disable']) {
    const result = bash(text);
    assert.equal(heldLabel(result.action), SECURITY_LABEL, text); assert.equal(result.protected, true); assert.equal(result.risk, 'high');
  }
  const chain = bash('git push origin HEAD && sudo -u root marrow-install control disable');
  assert.match(chain.action, /marrow-control/); assert.equal(chain.protected, true);
  assert.equal(bash('sudo -u root marrow-install doctor').action === SECURITY_LABEL, false);
  assert.equal(routes.CONTROL_ROUTE_DENY_TEXT, 'Turning Marrow control off needs the account owner. Ask them to run it in their own terminal.');
  assert.equal(controlRoute(X), controlRoute(X));
});
test('B19 the answer does not depend on the environment or the working folder', () => {
  const prod = fs.mkdtempSync(join(tmpdir(), 'prod-marrow-live-'));
  try {
    for (const text of [X, 'sudo -u root marrow-install control disable', 'marrow-inst{a..a}ll control disable', 'marrow-install control status', 'ls -la']) {
      assert.equal(bash(text, prod).action, bash(text, tmpdir()).action, text);
      assert.equal(bash(text, '/').action, bash(text, prod).action, text);
    }
  } finally { fs.rmSync(prod, { recursive: true, force: true }); }
  assert.equal(controlRoute.length <= 2, true, 'controlRoute takes no environment input');
});

// ---- B18: growth, asserted in counted steps only (the 50 ms median row is measured by the builder at load1 < 16: no wall clock in the suite).
function shapes(size) {
  const wrap = 'sudo -u root '; const opt = '-n 5 '; const nest = '$(';
  return {
    wrappers: `${wrap.repeat(Math.ceil(size / wrap.length))}echo hi`, options: `timeout ${opt.repeat(Math.ceil(size / opt.length))}30 echo hi`,
    nested: `${nest.repeat(Math.ceil(size / 2))}`, oneWord: `${'a'.repeat(size)} control`, named: `marrow-install doctor ${'x '.repeat(Math.ceil(size / 2))}`,
  };
}
test('B18 growth is near-linear: counted steps, no wall clock', () => {
  const sizes = [8000, 16384, 32768, 1048576];
  for (const shape of Object.keys(shapes(10))) {
    const counted = sizes.map((size) => { const text = shapes(size)[shape]; controlRoute(text); return { size: text.length, steps: routes.CONTROL_READ_STATS.steps }; });
    for (let i = 1; i < counted.length; i += 1) {
      const sizeRatio = counted[i].size / counted[i - 1].size; const stepRatio = counted[i].steps / Math.max(1, counted[i - 1].steps);
      assert.ok(stepRatio <= sizeRatio * 1.2 && stepRatio >= sizeRatio / 1.2, `${shape} ${counted[i - 1].size}->${counted[i].size}: steps ratio ${stepRatio.toFixed(2)} vs size ratio ${sizeRatio.toFixed(2)}`);
    }
    counted.forEach((entry) => assert.ok(entry.steps <= entry.size * 8 + 2000, `${shape} ${entry.size}: ${entry.steps} steps`));
  }
});

// ---- credential stores: the reader works on text only and never touches a file
test('credential stores are never opened, stat-ed or followed (text reader only)', () => {
  const src = fs.readFileSync(join(__dirname, '..', 'src', 'control-routes.ts'), 'utf8');
  assert.equal(/from 'node:|from 'fs'|from 'os'|from 'child_process'|require\(/.test(src), false, 'no fs, os, child_process or require in the route reader');
  const home = fs.mkdtempSync(join(tmpdir(), 'pr1-home-'));
  const STORES = ['.claude.json', '.claude/settings.local.json', '.npmrc', '.git-credentials', '.marrow/fleet.env', '.marrow/env', '.marrow/credentials/key.json', '.config/gh/hosts.yml', 'auth.json', '.hermes/config.yaml'];
  const seen = [];
  const names = ['readFileSync', 'openSync', 'statSync', 'lstatSync', 'readdirSync', 'readlinkSync', 'realpathSync', 'existsSync', 'accessSync', 'createReadStream'];
  const saved = names.map((name) => [name, fs[name]]);
  try {
    for (const rel of STORES) { const file = join(home, rel); fs.mkdirSync(join(file, '..'), { recursive: true }); fs.writeFileSync(file, 'dummy'); }
    fs.linkSync(join(home, '.npmrc'), join(home, 'hard-link')); fs.symlinkSync(join(home, '.git-credentials'), join(home, 'sym-link'));
    for (const [name, fn] of saved) fs[name] = function (...args) { if (String(args[0]).includes('pr1-home-')) seen.push(name); return fn.apply(this, args); };
    for (const rel of [...STORES, 'hard-link', 'sym-link']) {
      controlRoute(`cat ${join(home, rel)}; sudo -u root marrow-install control disable ${join(home, rel)}`); controlRoute(`$'\\x6d'arrow-install uninstall --file ${join(home, rel)}`); controlRoute(`ls ${join(home, rel)}`);
    }
  } finally { for (const [name, fn] of saved) fs[name] = fn; fs.rmSync(home, { recursive: true, force: true }); }
  assert.deepEqual(seen, []);
});

// ---- PA1 / PA2 (patch-df3-39a): the PR #39 shape groups and the data-mention rows, on the real hook path (classifyTool: label, risk, protected).
// The shapes are test/support/df3-39a-pr39-shapes.cjs (vendored from PR #39 head 4bab54eea74c). The A0 columns are the answers of A0 eb0917427bc5 measured on its committed
// dist (H = held as a control-off route, c = clear); DF3_39A_A0_DIST=<A0 dist folder> re-measures them (the red column).
const PR39 = require('./support/df3-39a-pr39-shapes.cjs');
const A0_COLUMN = { GAP1: "cccccccc", COMPOUND: "cccHHHcccHccccHccHHHHHHHHHHHHHcHHHcHcHHHHHHccccHcHH", DECODE: "cHcccHcccccHcHccc", DATA_MENTIONS: "HHHHcccccccccccccccccccHcccccccccccccccccccccccccccc" };
// The keep-clear rows k01-k16 and r13 of the spec abuse table (text, A0 answer).
const KEEP_ROWS = [
  { id: "r13-R", text: "npm uninstall @getmarrow/install", a0: "c" },
  { id: "k01-C", text: "marrow-install control status", a0: "c" },
  { id: "k02-C", text: "marrow-install control enable", a0: "c" },
  { id: "k03-C", text: "npx @getmarrow/install control status --json", a0: "c" },
  { id: "k04-C", text: "npx @getmarrow/install doctor", a0: "c" },
  { id: "k05-C", text: "npx @getmarrow/install@latest --yes", a0: "c" },
  { id: "k06-C", text: "npm install -g @getmarrow/mcp", a0: "c" },
  { id: "k07-C", text: "npm ls -g @getmarrow/mcp", a0: "c" },
  { id: "k08-C", text: "claude mcp list", a0: "c" },
  { id: "k09-C", text: "marrow claim", a0: "c" },
  { id: "k10-C", text: "claude mcp add marrow -- npx @getmarrow/mcp", a0: "c" },
  { id: "k11-C", text: "npm uninstall -g left-pad", a0: "c" },
  { id: "k12-C", text: "npx @getmarrow/install update", a0: "c" },
  { id: "k13-C", text: "marrow-install status", a0: "c" },
  { id: "k14-C", text: "npx @getmarrow/install control", a0: "H" },
  { id: "k15-C", text: "node /usr/lib/node_modules/@getmarrow/install/bin/marrow-install.js control enable", a0: "c" },
  { id: "k16-C", text: "claude mcp remove other-server", a0: "c" },
];
const heldOnHookPath = (text) => { const result = bash(text); return heldLabel(result.action) === SECURITY_LABEL && result.protected === true && result.risk === 'high'; };
const rowId = (group, index) => `${group}-${String(index + 1).padStart(2, '0')}`;
const countOf = (column) => [...column].filter((ch) => ch === 'H').length;

for (const group of ['GAP1', 'COMPOUND', 'DECODE']) {
  PR39[group].forEach(([name, text], index) => test(`B13 ${rowId(group, index)} ${name}: held as security on marrow-control`, () => {
    assert.equal(heldOnHookPath(text), true, 'hook path label, protected, high');
    assert.equal(controlRoute(text), true, 'controlRoute');
  }));
}
test('B13 group sizes and the A0 red column (GAP1 0 of 8, COMPOUND 31 of 51, DECODE 4 of 17 held on A0)', () => {
  assert.deepEqual(['GAP1', 'COMPOUND', 'DECODE'].map((group) => PR39[group].length), [8, 51, 17]);
  assert.deepEqual(['GAP1', 'COMPOUND', 'DECODE'].map((group) => A0_COLUMN[group].length), [8, 51, 17]);
  assert.deepEqual(['GAP1', 'COMPOUND', 'DECODE'].map((group) => countOf(A0_COLUMN[group])), [0, 31, 4]);
});

PR39.DATA_MENTIONS.forEach(([name, text], index) => test(`B12 ${rowId('DATA_MENTIONS', index)} ${name}: same answer as A0 (${A0_COLUMN.DATA_MENTIONS[index] === 'H' ? 'held' : 'clear'})`, () => {
  const held = A0_COLUMN.DATA_MENTIONS[index] === 'H';
  assert.equal(heldOnHookPath(text), held, 'hook path');
  assert.equal(controlRoute(text), held, 'controlRoute');
}));
KEEP_ROWS.forEach((row) => test(`B12 ${row.id}: same answer as A0 (${row.a0 === 'H' ? 'held' : 'clear'})`, () => {
  const held = row.a0 === 'H';
  assert.equal(heldOnHookPath(row.text), held, 'hook path');
  assert.equal(controlRoute(row.text), held, 'controlRoute');
}));
test('B12 sizes: 52 data mentions (5 held, 47 clear on A0) and 17 keep rows (only k14-C held)', () => {
  assert.equal(PR39.DATA_MENTIONS.length, 52);
  assert.equal(A0_COLUMN.DATA_MENTIONS.length, 52);
  assert.equal(countOf(A0_COLUMN.DATA_MENTIONS), 5);
  assert.deepEqual(KEEP_ROWS.filter((row) => row.a0 === 'H').map((row) => row.id), ['k14-C']);
  assert.equal(KEEP_ROWS.length, 17);
});
test('B12 the vendored F1 fixture is the PR #39 file', () => {
  const bytes = fs.readFileSync(join(__dirname, 'support', 'df3-39a-pr39-F1.json'));
  assert.equal(createHash('sha256').update(bytes).digest('hex'), '7f94ea8aac55a3f5404d24e6756779f1c263287f3cf0cf25d17325783e6d4c23');
});
if (process.env.DF3_39A_A0_DIST) {
  test('B12/B13 the A0 columns are what A0 answers (DF3_39A_A0_DIST)', () => {
    const a0Route = require(join(process.env.DF3_39A_A0_DIST, 'control-routes.js')).controlRoute;
    for (const group of ['GAP1', 'COMPOUND', 'DECODE', 'DATA_MENTIONS']) {
      PR39[group].forEach(([, text], index) => assert.equal(a0Route(text), A0_COLUMN[group][index] === 'H', rowId(group, index)));
    }
    for (const row of KEEP_ROWS) assert.equal(a0Route(row.text), row.a0 === 'H', row.id);
  });
}

// ---- PA4 (patch-df3-39a): the six plants round 1 called equivalent (m14 m18 m26 m30 m33 m36). Over the 31,507 replay commands and the 350 abuse and shape rows each plant answers
// like the tip, because master's route already holds every text that spells the installer out. Each one changes the answer on a text whose installer name only shows after the
// quotes are removed (master's route never sees it), so each has its own row here.
const nestEval = (inner, levels) => { let text = inner; for (let at = 0; at < levels; at += 1) text = `eval '${text.replace(/'/g, "'\\''")}'`; return text; };
test('PA4 m14: read NAME <<< VALUE binds the value (a quote-split installer line run through the name)', () => {
  hold('read c <<< "marrow-inst""all control disable"; $c');
});
test('PA4 m18: the depth limit is 3 (4 nested evals of a quote-split installer line hold, 3 are read)', () => {
  hold(nestEval("marrow-inst''all status", 4));
  clear(nestEval("marrow-inst''all status", 3));
});
test('PA4 m26: a here-string word stays a word (an expansion fed to a quote-split installer)', () => {
  hold('marrow-inst""all <<< $x');
  hold("marrow-inst''all status <<< $x");
});
test('PA4 m30: a braced parameter is one word (its default text is data, never a command)', () => {
  clear("echo ${P:-x;marrow-inst''all control disable}");
  clear('echo "${P:-x;marrow-inst""all control disable}"');
});
test('PA4 m33: a command substitution starts its own command', () => {
  hold("echo $(marrow-inst''all control disable)");
  hold("x=$(marrow-inst''all control disable)");
});
test('PA4 m36: a command substitution inside double quotes is read as a command', () => {
  hold('echo "$(marrow-inst\'\'all control disable)"');
  hold('echo "`marrow-inst\'\'all control disable`"');
});
