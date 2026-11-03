# LOWER_SHAPES-d1d-final

The kept data slots of P-D after the cut (reports/CUT.md), in lint-rules-d1.md R1 format, one exact slot per row. The operand_spec is the literal set of words a mask may replace in that slot; the word sits inside the operand (a pattern, a heredoc body line, a path), so a row is not a whole-operand match. Slots T05 and T06 carry the three extra words commit, permit and closure (main 01:4xZ, DF1); no other slot does. Program keys joined with a hyphen (`git-grep`, `grep-file`, `cat-heredoc`) name a subcommand or a carrier that R1 cannot express (draft DESIGN section 8, Q4); the closed condition of each slot is in ACCEPTANCE-d1d-final.md rows F1 to F7. A row applies only when the whole text passes every gate of that ACCEPTANCE (all programs listed, parse ok, no A0 hit, no hold). This is the whole drop allowlist: a slot not in this file lowers nothing. Cut slots (not in this file): T01 T02 T03 T03H T04 T07 P01-P04 P06 P10-P18 R01 V01 K01.

| id | program | flags | operand_class | operand_spec |
|---|---|---|---|---|
| T05a | grep | none | literal | {publish,unpublish,deprecate,deploy,release,wrangler,production,prod,migration,schema,database,d1,commit,permit,closure} |
| T05b | grep | -e | literal | {publish,unpublish,deprecate,deploy,release,wrangler,production,prod,migration,schema,database,d1,commit,permit,closure} |
| T05c | egrep | none | literal | {publish,unpublish,deprecate,deploy,release,wrangler,production,prod,migration,schema,database,d1,commit,permit,closure} |
| T05d | egrep | -e | literal | {publish,unpublish,deprecate,deploy,release,wrangler,production,prod,migration,schema,database,d1,commit,permit,closure} |
| T05e | fgrep | none | literal | {publish,unpublish,deprecate,deploy,release,wrangler,production,prod,migration,schema,database,d1,commit,permit,closure} |
| T05f | fgrep | -e | literal | {publish,unpublish,deprecate,deploy,release,wrangler,production,prod,migration,schema,database,d1,commit,permit,closure} |
| T05g | rg | none | literal | {publish,unpublish,deprecate,deploy,release,wrangler,production,prod,migration,schema,database,d1,commit,permit,closure} |
| T05h | rg | -e | literal | {publish,unpublish,deprecate,deploy,release,wrangler,production,prod,migration,schema,database,d1,commit,permit,closure} |
| T05i | git-grep | none | literal | {publish,unpublish,deprecate,deploy,release,wrangler,production,prod,migration,schema,database,d1,commit,permit,closure} |
| T05j | git-grep | -e | literal | {publish,unpublish,deprecate,deploy,release,wrangler,production,prod,migration,schema,database,d1,commit,permit,closure} |
| T06 | cat-heredoc | none | literal | {publish,unpublish,deprecate,deploy,release,wrangler,production,prod,migration,schema,database,d1,commit,permit,closure} |
| P07a | grep-file | none | literal | {publish,unpublish,deprecate,deploy,release,wrangler,production,prod,migration,schema,database,d1} |
| P07b | egrep-file | none | literal | {publish,unpublish,deprecate,deploy,release,wrangler,production,prod,migration,schema,database,d1} |
| P07c | fgrep-file | none | literal | {publish,unpublish,deprecate,deploy,release,wrangler,production,prod,migration,schema,database,d1} |
| P07d | rg-file | none | literal | {publish,unpublish,deprecate,deploy,release,wrangler,production,prod,migration,schema,database,d1} |
| P07e | git-grep-file | none | literal | {publish,unpublish,deprecate,deploy,release,wrangler,production,prod,migration,schema,database,d1} |
| P08 | sed | -n | literal | {publish,unpublish,deprecate,deploy,release,wrangler,production,prod,migration,schema,database,d1} |
| P09 | cd | none | literal | {publish,unpublish,deprecate,deploy,release,wrangler,production,prod,migration,schema,database,d1} |
| P05 | ls | none | literal | {publish,unpublish,deprecate,deploy,release,wrangler,production,prod,migration,schema,database,d1} |
