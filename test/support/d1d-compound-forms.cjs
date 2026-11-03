'use strict';
// Test-only. D1d round 3: one command per LOWER_SHAPES slot and every compound or wrapper form that can put it somewhere other than "alone". Used by test/d1d-compound.test.js
// and by the cell drivers (the same table, so the cells and the test cannot drift). A form wraps X = head line (+ heredoc body lines): pre and post go on the head line,
// which is valid before a heredoc body; the `nl` forms put X on its own lines. A form that cannot hold X returns null.
const W = 'deploy';
const SLOTS = {
  T05a: `grep -n '${W}' f`, T05b: `grep -e ${W} f`, T05c: `egrep -n '${W}' f`, T05d: `egrep -e ${W} f`, T05e: `fgrep -n '${W}' f`, T05f: `fgrep -e ${W} f`,
  T05g: `rg -n '${W}' src`, T05h: `rg -e ${W} src`, T05i: `git grep -n '${W}' HEAD`, T05j: `git grep -e ${W} -- src`,
  T06: `cat <<'EOF'\n${W} notes\nEOF`,
  P07a: `grep -rn x ${W}`, P07b: `egrep x ${W}.md`, P07c: `fgrep x ${W}.md`, P07d: `rg x ${W}`, P07e: `git grep -n x HEAD -- ${W}/x.ts`,
  P08: `sed -n '1,5p' ${W}.md`, P09: `cd ${W}`, P05: `ls ${W}`,
};
// The slots whose plain form is lowered (the others are read-only on master: no question is asked for them, so there is nothing to lower).
const PLAIN_LOWERED = ['T05c', 'T05d', 'T05e', 'T05f', 'T05i', 'T05j', 'T06', 'P07b', 'P07c', 'P07e', 'P08'];
const F = (pre, post) => (h, b) => pre + h + post + (b ? '\n' + b : '');
const NL = (pre, post) => (h, b) => pre + '\n' + h + (b ? '\n' + b : '') + '\n' + post;
const Y = 'npm publish';
const FORMS = {
  brace: F('{ ', '; }'), brace_nl: NL('{', '}'), subshell: F('( ', ' )'), subshell_nl: NL('(', ')'),
  cmdsub: F('$( ', ' )'), cmdsub_echo: F('echo $( ', ' )'), cmdsub_assign: F('v=$( ', ' )'), cmdsub_quoted: F('echo "$( ', ' )"'),
  backtick: F('`', '`'), backtick_echo: F('echo `', '`'), backtick_assign: F('v=`', '`'),
  if_then: F('if true; then ', '; fi'), if_then_nl: NL('if true; then', 'fi'), if_cond: F('if ', '; then true; fi'), if_cond_nl: (h, b) => 'if ' + h + (b ? '\n' + b : '') + '\nthen true; fi',
  if_else: F('if false; then true; else ', '; fi'), elif_cond: F('if false; then true; elif ', '; then true; fi'), elif_branch: F('if false; then true; elif true; then ', '; fi'),
  while_cond: F('while ', '; do true; done'), while_cond_do_nl: (h, b) => 'while ' + h + (b ? '\n' + b : '') + '\ndo sleep 5; done', while_body: F('while true; do ', '; done'), while_body_nl: NL('while true; do', 'done'),
  until_cond: F('until ', '; do true; done'), until_body: F('until false; do ', '; done'), until_body_nl: NL('until false; do', 'done'),
  for: F('for i in 1 2; do ', '; done'), for_nl: NL('for i in 1 2; do', 'done'), for_noin: F('for i; do ', '; done'), select: F('select i in a b; do ', '; done'),
  case: F('case x in x) ', ' ;; esac'), case_nl: NL('case x in x)', ';; esac'),
  func_paren: F('f() { ', '; }; f'), func_kw: F('function f { ', '; }; f'), func_kw_paren: F('function f() { ', '; }; f'), func_paren_nl: NL('f() {', '}; f'),
  bang: F('! ', ''), bang_brace: F('! { ', '; }'), time_: F('time ', ''), time_p: F('time -p ', ''),
  and_first: F('', ' && true'), and_second: F('true && ', ''), and_first_Y: F('', ` && ${Y}`), and_second_Y: F(`${Y} && `, ''),
  or_first: F('', ' || true'), or_second: F('false || ', ''), or_first_Y: F('', ` || ${Y}`), or_second_Y: F(`${Y} || `, ''),
  semi_first: F('', '; true'), semi_second: F('true; ', ''), semi_first_Y: F('', `; ${Y}`), semi_second_Y: F(`${Y}; `, ''),
  nl_first: (h, b) => h + (b ? '\n' + b : '') + '\ntrue', nl_second: (h, b) => 'true\n' + h + (b ? '\n' + b : ''),
  pipe_first: F('', ' | cat'), pipe_second: F('echo a | ', ''), pipe_first_wc: F('', ' | wc -l'), pipe_first_sh: F('', ' | sh'), pipe_second_Y: F(`${Y} | `, ''),
  pipe_grp_first: F('{ ', '; } | cat'), pipe_sub_first: F('( ', ' ) | cat'), pipe_grp_second: F('cat | { ', '; }'), pipe_while_read: F('echo a | while read l; do ', '; done'),
  bg_after: F('', ' &'), bg_before: F('true & ', ''), bg_brace: F('{ ', '; } &'), dbl_bracket: F('[[ -n x ]] && { ', '; }'), arith: F('(( 1 )) && { ', '; }'), coproc: F('coproc { ', '; }'),
  nested_if_while: F('if true; then while true; do ', '; done; fi'), nested_brace_until: F('{ until false; do ', '; done; }'), nested_sub_while: F('( while true; do ', '; done )'),
  cmdsub_in_arg: F('echo start $(echo ', ') end'),
  w_env: F('env ', ''), w_nohup: F('nohup ', ''), w_command: F('command ', ''), w_exec: F('exec ', ''), w_timeout: F('timeout 5 ', ''), w_nice: F('nice ', ''), w_sudo: F('sudo ', ''), w_xargs: F('echo a | xargs ', ''),
  w_bash_c: (h, b) => (b ? null : `bash -c "${h.replace(/(["\\$`])/g, '\\$1')}"`), w_sh_c: (h, b) => (b ? null : `sh -c '${h.replace(/'/g, "'\\''")}'`),
  zsh_repeat: F('repeat 3 do ', '; done'), zsh_foreach: NL('foreach i (a b)', 'end'), zsh_for_short: F('for i in a b; { ', '; }'), zsh_while_paren: F('while (( 1 )) { ', '; }'),
  cont_while: (h, b) => (b ? null : `wh\\\nile true; do\n${h}\ndone`),
};
// The same single command with only blanks, a comment line, a trailing newline, a trailing semicolon or a trailing /dev/null redirect around it: none of these is a compound or wrapper form.
const ALONE = {
  alone: (x) => x, trailing_nl: (x) => x + '\n', trailing_semi: (x) => (x.includes('\n') ? null : x + ';'), lead_blank: (x) => '  ' + x, lead_nl: (x) => '\n' + x,
  lead_comment: (x) => '# find it\n' + x, null_redirect: (x) => (x.includes('\n') ? null : x + ' 2>/dev/null'),
};
function build(slot, form) {
  const [head, ...rest] = SLOTS[slot].split('\n');
  return FORMS[form](head, rest.join('\n'));
}
module.exports = { SLOTS, FORMS, ALONE, PLAIN_LOWERED, build };
