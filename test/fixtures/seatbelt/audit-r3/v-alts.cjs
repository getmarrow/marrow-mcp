'use strict';
// Rows of the delta audit of 452da607 (Barvis, 2026-10-12), N2 class "C:*": conditional assignments.
// The audit's v-alts.cjs was not in the evidence folder; these rows are written from its v-alts.out
// ids and the commands the audit's RESULT.md and v-alts.base.out list (same ids, same expectation).
const S = 'stop', P = 'pass';
const noise = 'if y; then n1=a; else n1=b; fi; if y; then n2=a; fi; [ -n "$CI" ] && n3=1; ';
module.exports = [
  { id: 'C:if-else-word', cmd: 'if y; then w=publish; else w=test; fi; npm $w', expect: S },
  { id: 'C:if-else-sub', cmd: 'if y; then c=npm; else c=echo; fi; $c publish', expect: S },
  { id: 'C:if-else-force', cmd: 'if y; then w=-f; else w=-n; fi; git push $w origin main', expect: S },
  { id: 'C:andor-sub', cmd: 'test -f x && w=publish || w=test; npm $w', expect: S },
  { id: 'C:case-sub', cmd: 'case $x in a) w=publish;; b) w=test;; esac; npm $w', expect: S },
  { id: 'C:pre1', cmd: 'if y; then w=test; else w=publish; fi; npm $w', expect: S },
  { id: 'C:pre5', cmd: `${noise}if y; then w=publish; else w=test; fi; npm $w`, expect: S },
  { id: 'C:pre6', cmd: `${noise}${noise}if y; then c=npm; else c=echo; fi; $c publish`, expect: S },
  { id: 'C:pre7', cmd: `${noise}if y; then w=-f; else w=-n; fi; git push $w origin main`, expect: S },
  { id: 'C:pre10', cmd: `${noise}${noise}${noise}if y; then w=publish; else w=test; fi; npm $w`, expect: S },
  { id: 'C:pre10-word', cmd: `${noise}${noise}if y; then c=npm; fi; $c publish`, expect: S },
  { id: 'C:pre10-unused-args', cmd: `${noise}if y; then w=publish; else w=test; fi; npm publish $w`, expect: S },
  { id: 'C:pre10-rm', cmd: `${noise}${noise}if y; then d=/home/u; else d=dist; fi; rm -rf $d`, expect: S },
  { id: 'C:loop-6', cmd: 'w=test; while y; do npm $w; w=publish; done', expect: S },
  // the same shapes as the audit's base-oracle list in v-alts.base.out
  { id: 'C:then-only', cmd: 'if y; then w=publish; fi; npm $w', expect: S },
  { id: 'C:set-then-cond', cmd: 'w=test; if y; then w=publish; fi; npm $w', expect: S },
  { id: 'C:or-chain', cmd: 'true || w=publish; npm $w', expect: S },
  { id: 'C:andand-flag', cmd: '[ -n "$CI" ] && x=--prod; vercel $x', expect: S },
  // neighbours that must keep passing: both branches benign, an unconditional override
  { id: 'C:pass-both-benign', cmd: 'if y; then w=test; else w=build; fi; npm $w', expect: P },
  { id: 'C:pass-override', cmd: 'w=publish; w=test; npm $w', expect: P },
];
