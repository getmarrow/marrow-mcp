// Assignment guards (audit N2). The vendored parser flattens `if/else`, `case`, `&&`/`||`, loops,
// groups and pipelines into one list of simple commands, so the mapper cannot tell an assignment that
// always runs from one that runs on some branches. This module reads the raw text once, in a single
// linear pass, and reports for every variable assignment in text order whether it is unconditional.
//
// It only has to be sound in one direction: an assignment is reported unconditional only when it is at
// the top level, not after `&&`/`||`, not in a pipeline, not backgrounded, and not inside any
// compound, group or subshell. Anything it is unsure of (unbalanced quotes or brackets, a keyword
// that does not close) comes out conditional, or the whole scan returns null and the caller treats
// every assignment as conditional.

export interface AssignEvent {
  name: string;
  // Runs on every path through the text (top level, first element of its list, not a pipeline stage).
  uncond: boolean;
  // Conditional, but assigned on every branch of an if/elif/else chain that has an else: the variable
  // cannot be left unset by the chain.
  exhaustive: boolean;
  // Inside a loop body: a later assignment in the body is visible to earlier uses on the next round.
  inLoop: boolean;
  // `export NAME=…`, `declare NAME=…`, `local`, `readonly`, `typeset` (as opposed to a leading `NAME=…`).
  declare: boolean;
  // `NAME=(a b c)`: the elements (null when one of them is not a plain literal).
  array?: string[] | null;
}

const ASSIGN = /^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=/;
const DECLARE_WORDS = new Set(['export', 'declare', 'typeset', 'local', 'readonly']);
const MAX_EVENTS = 4096;

interface Frame {
  kind: 'if' | 'loop' | 'case' | 'paren' | 'brace';
  // if-chains: the names assigned in each branch so far, whether an else was seen, and every event
  // that happened directly inside (including those that bubbled up from nested ifs).
  branches: Array<Set<string>>;
  hasElse: boolean;
  events: number[];
}

export function scanAssignments(src: string): AssignEvent[] | null {
  const events: AssignEvent[] = [];
  const stack: Frame[] = [];
  const n = src.length;
  let i = 0;
  let andor = false;
  let inPipe = false;
  let broken = false;
  let cmdStart = true;
  let declareArgs = false;
  let afterRedir = false;
  // The last token was `&&`, `||`, `|` or `|&`: a newline does not end the list.
  let continued = false;
  let pending: number[] = []; // events of the simple command being read
  const heredocs: Array<{ delim: string; strip: boolean }> = [];

  const finish = (nonPersistent: boolean) => {
    if (nonPersistent) for (const k of pending) events[k].uncond = false;
    pending = [];
    declareArgs = false;
    afterRedir = false;
  };
  const record = (name: string, declare: boolean) => {
    if (events.length >= MAX_EVENTS) { broken = true; return; }
    const loop = stack.some((f) => f.kind === 'loop');
    const uncond = stack.length === 0 && !andor && !inPipe && !broken;
    const k = events.length;
    events.push({ name, uncond, exhaustive: false, inLoop: loop, declare });
    pending.push(k);
    // Branch bookkeeping for exhaustiveness: only a direct, plain assignment inside an if-branch.
    const top = stack[stack.length - 1];
    if (top && top.kind === 'if' && !andor && !inPipe) {
      top.branches[top.branches.length - 1].add(name);
      top.events.push(k);
    }
  };
  const popTo = (kind: Frame['kind']) => {
    // Close the innermost frame of this kind; frames above it are unbalanced (a stray keyword).
    for (let s = stack.length - 1; s >= 0; s -= 1) {
      if (stack[s].kind !== kind) continue;
      while (stack.length - 1 > s) { stack.pop(); broken = true; }
      return stack.pop() as Frame;
    }
    broken = true;
    return null;
  };
  // Skip a balanced region opened just before `from` (inclusive of nested quotes). Returns the index
  // after the closer, or -1 when it does not close.
  const skipBalanced = (from: number, open: string, close: string): number => {
    let depth = 1;
    let p = from;
    while (p < n) {
      const c = src[p];
      if (c === '\\') { p += 2; continue; }
      if (c === "'") { const e = src.indexOf("'", p + 1); if (e < 0) return -1; p = e + 1; continue; }
      if (c === '"') {
        p += 1;
        while (p < n && src[p] !== '"') p += src[p] === '\\' ? 2 : 1;
        if (p >= n) return -1;
        p += 1;
        continue;
      }
      if (c === '`') { const e = src.indexOf('`', p + 1); if (e < 0) return -1; p = e + 1; continue; }
      if (c === open) depth += 1;
      else if (c === close) { depth -= 1; if (depth === 0) return p + 1; }
      p += 1;
    }
    return -1;
  };

  while (i < n) {
    const ch = src[i];
    if (ch === ' ' || ch === '\t' || ch === '\r') { i += 1; continue; }
    if (ch === '\\' && src[i + 1] === '\n') { i += 2; continue; }
    if (ch === '\n') {
      finish(false);
      // A newline right after `&&`, `||`, `|` or `|&` continues the list: the state is kept.
      if (!continued) { andor = false; inPipe = false; }
      cmdStart = true;
      i += 1;
      // Heredoc bodies start on the next line and end at a line holding only the delimiter.
      while (heredocs.length) {
        const h = heredocs.shift() as { delim: string; strip: boolean };
        let found = false;
        while (i <= n) {
          let end = src.indexOf('\n', i);
          if (end < 0) end = n;
          let line = src.slice(i, end);
          if (h.strip) line = line.replace(/^\t+/, '');
          i = end + 1;
          if (line === h.delim) { found = true; break; }
          if (end >= n) break;
        }
        if (!found) return null;
      }
      continue;
    }
    if (ch === '#') { const e = src.indexOf('\n', i); i = e < 0 ? n : e; continue; }
    // Operators.
    if (ch === ';') {
      const m = /^(?:;;&|;;|;&|;)/.exec(src.slice(i, i + 3)) as RegExpExecArray;
      continued = false;
      finish(false);
      andor = false;
      inPipe = false;
      cmdStart = true;
      i += m[0].length;
      continue;
    }
    if (ch === '&') {
      if (src[i + 1] === '&') { finish(false); andor = true; inPipe = false; cmdStart = true; continued = true; i += 2; continue; }
      if (src[i + 1] === '>') {
        // `&>` / `&>>` redirect.
        i += src[i + 2] === '>' ? 3 : 2;
        afterRedir = true;
        continue;
      }
      // Background: the assignment runs in a subshell.
      continued = false;
      finish(true);
      andor = false;
      inPipe = false;
      cmdStart = true;
      i += 1;
      continue;
    }
    if (ch === '|') {
      if (src[i + 1] === '|') { finish(false); andor = true; inPipe = false; cmdStart = true; continued = true; i += 2; continue; }
      // A pipeline stage runs in a subshell: its assignments do not persist, and neither do the next stage's.
      finish(true);
      inPipe = true;
      cmdStart = true;
      continued = true;
      i += src[i + 1] === '&' ? 2 : 1;
      continue;
    }
    if (ch === '(') {
      stack.push({ kind: 'paren', branches: [], hasElse: false, events: [] });
      finish(false);
      cmdStart = true;
      i += 1;
      continue;
    }
    if (ch === ')') {
      finish(false);
      const top = stack[stack.length - 1];
      if (top && top.kind === 'paren') stack.pop();
      else if (top && top.kind === 'case') { /* end of a case pattern */ }
      else broken = true;
      cmdStart = true;
      i += 1;
      continue;
    }
    if (ch === '<' || ch === '>') {
      // Process substitution is a word part; everything else is a redirect operator.
      if (src[i + 1] === '(') {
        const e = skipBalanced(i + 2, '(', ')');
        if (e < 0) return null;
        i = e;
        if (!afterRedir) cmdStart = false;
        afterRedir = false;
        continue;
      }
      const m = /^(?:<<<|<<-|<<|<>|<&|>>|>\||>&|<|>)/.exec(src.slice(i, i + 3)) as RegExpExecArray;
      const op = m[0];
      i += op.length;
      if (op === '<<' || op === '<<-') {
        while (src[i] === ' ' || src[i] === '\t') i += 1;
        let delim = '';
        let q = false;
        while (i < n && !/[\s;&|<>()]/.test(src[i])) {
          if (src[i] === "'" || src[i] === '"') {
            const e = src.indexOf(src[i], i + 1);
            if (e < 0) return null;
            delim += src.slice(i + 1, e);
            q = true;
            i = e + 1;
            continue;
          }
          if (src[i] === '\\') { delim += src[i + 1] || ''; q = true; i += 2; continue; }
          delim += src[i];
          i += 1;
        }
        void q;
        if (src[i - 1] === undefined) return null;
        heredocs.push({ delim, strip: op === '<<-' });
      } else afterRedir = true;
      continue;
    }

    // A word.
    continued = false;
    let raw = '';
    let quoted = false;
    const start = i;
    for (;;) {
      if (i >= n) break;
      const c = src[i];
      if (c === ' ' || c === '\t' || c === '\r' || c === '\n' || c === ';' || c === '&' || c === '|' || c === '(' || c === ')' || c === '<' || c === '>') break;
      if (c === '\\') {
        if (src[i + 1] === '\n') { i += 2; continue; }
        quoted = true;
        raw += src.slice(i, i + 2);
        i += 2;
        continue;
      }
      if (c === "'") {
        const e = src.indexOf("'", i + 1);
        if (e < 0) return null;
        raw += src.slice(i, e + 1);
        quoted = true;
        i = e + 1;
        continue;
      }
      if (c === '"') {
        let p = i + 1;
        while (p < n && src[p] !== '"') {
          if (src[p] === '\\') { p += 2; continue; }
          if (src[p] === '$' && src[p + 1] === '(') {
            const e = skipBalanced(p + 2, '(', ')');
            if (e < 0) return null;
            p = e;
            continue;
          }
          if (src[p] === '`') { const e = src.indexOf('`', p + 1); if (e < 0) return null; p = e + 1; continue; }
          p += 1;
        }
        if (p >= n) return null;
        raw += src.slice(i, p + 1);
        quoted = true;
        i = p + 1;
        continue;
      }
      if (c === '$' && src[i + 1] === "'") {
        let p = i + 2;
        while (p < n && src[p] !== "'") p += src[p] === '\\' ? 2 : 1;
        if (p >= n) return null;
        raw += src.slice(i, p + 1);
        quoted = true;
        i = p + 1;
        continue;
      }
      if (c === '$' && src[i + 1] === '(') {
        const e = skipBalanced(i + 2, '(', ')');
        if (e < 0) return null;
        raw += src.slice(i, e);
        i = e;
        continue;
      }
      if (c === '$' && src[i + 1] === '{') {
        const e = skipBalanced(i + 2, '{', '}');
        if (e < 0) return null;
        raw += src.slice(i, e);
        i = e;
        continue;
      }
      if (c === '`') {
        const e = src.indexOf('`', i + 1);
        if (e < 0) return null;
        raw += src.slice(i, e + 1);
        i = e + 1;
        continue;
      }
      raw += c;
      i += 1;
    }
    if (i === start) { i += 1; continue; }

    // `NAME=(a b c)`: an array literal; `$NAME` is its first element (audit N2).
    let arrayElements: string[] | null | undefined;
    if (src[i] === '(' && /^[A-Za-z_][A-Za-z0-9_]*\+?=$/.test(raw) && cmdStart && !afterRedir) {
      const e = skipBalanced(i + 1, '(', ')');
      if (e < 0) return null;
      const inner = src.slice(i + 1, e - 1);
      const els = (inner.match(/'[^']*'|"(?:\\.|[^"\\])*"|[^\s]+/g) || []).map((el) => (/[$`]/.test(el) ? null : el.replace(/^(['"])([\s\S]*)\1$/, '$2')));
      arrayElements = els.some((el) => el === null) ? null : (els as string[]);
      i = e;
    }

    if (afterRedir) { afterRedir = false; continue; }
    // `2>file`, `3<&0`: a file descriptor number in front of a redirect is not a word.
    if (/^[0-9]+$/.test(raw) && (src[i] === '<' || src[i] === '>')) continue;
    if (!cmdStart) {
      if (declareArgs && ASSIGN.test(raw)) {
        const eq = raw.indexOf('=');
        record(raw.slice(0, eq).replace(/\+$/, '').replace(/\[.*$/, ''), true);
      }
      continue;
    }
    // Command position.
    if (ASSIGN.test(raw)) {
      const eq = raw.indexOf('=');
      record(raw.slice(0, eq).replace(/\+$/, '').replace(/\[.*$/, ''), false);
      if (arrayElements !== undefined) events[events.length - 1].array = arrayElements;
      continue;
    }
    if (!quoted) {
      switch (raw) {
        case 'if': stack.push({ kind: 'if', branches: [new Set<string>()], hasElse: false, events: [] }); continue;
        case 'then': continue;
        case 'elif': {
          const top = stack[stack.length - 1];
          if (top && top.kind === 'if') top.branches.push(new Set<string>()); else broken = true;
          continue;
        }
        case 'else': {
          const top = stack[stack.length - 1];
          if (top && top.kind === 'if') { top.hasElse = true; top.branches.push(new Set<string>()); } else broken = true;
          continue;
        }
        case 'fi': {
          const f = popTo('if');
          cmdStart = false;
          if (f) {
            if (f.hasElse) {
              // A name assigned in every branch is never left unset by this chain.
              const all = f.branches.length ? [...f.branches[0]].filter((nm) => f.branches.every((b) => b.has(nm))) : [];
              for (const k of f.events) if (all.includes(events[k].name)) events[k].exhaustive = true;
              const parent = stack[stack.length - 1];
              if (parent && parent.kind === 'if') {
                for (const nm of all) parent.branches[parent.branches.length - 1].add(nm);
                parent.events.push(...f.events);
              }
            }
          }
          continue;
        }
        case 'while': case 'until': stack.push({ kind: 'loop', branches: [], hasElse: false, events: [] }); continue;
        case 'for': case 'select':
          stack.push({ kind: 'loop', branches: [], hasElse: false, events: [] });
          cmdStart = false; // the header words are not commands; `do` after `;` or a newline is
          continue;
        case 'do': continue;
        case 'done': popTo('loop'); cmdStart = false; continue;
        case 'case':
          stack.push({ kind: 'case', branches: [], hasElse: false, events: [] });
          cmdStart = false;
          continue;
        case 'esac': popTo('case'); cmdStart = false; continue;
        case '{': stack.push({ kind: 'brace', branches: [], hasElse: false, events: [] }); continue;
        case '}': popTo('brace'); cmdStart = false; continue;
        case '!': case 'time': continue;
        case 'function': cmdStart = false; continue;
        default: break;
      }
    }
    // An ordinary command word.
    cmdStart = false;
    if (!quoted && DECLARE_WORDS.has(raw)) declareArgs = true;
  }
  finish(false);
  return events;
}
