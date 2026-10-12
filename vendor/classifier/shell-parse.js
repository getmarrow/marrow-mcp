'use strict';

// A conservative POSIX-shell parser for classification. It turns a command string into simple
// commands (argv words, assignments, redirects, heredoc bodies) and records every construct it
// cannot resolve statically (variables, command/process substitution, eval-like forms). The
// classifier treats anything dynamic as not routine, so a parse gap can only add a server check,
// never skip one (ADV-06 H1-H3).

const MAX_SOURCE_BYTES = 64 * 1024;
const MAX_COMMANDS = 256;

const SEPARATOR_KEYWORDS = new Set(['if', 'then', 'else', 'elif', 'fi', 'do', 'done', 'while', 'until', '!', '{', '}', 'time']);

class ParseError extends Error {}

function decodeAnsiC(body) {
  let out = '';
  for (let i = 0; i < body.length; i += 1) {
    const ch = body[i];
    if (ch !== '\\' || i === body.length - 1) { out += ch; continue; }
    const next = body[i + 1];
    i += 1;
    const simple = { n: '\n', t: '\t', r: '\r', a: '\x07', b: '\b', e: '\x1b', E: '\x1b', f: '\f', v: '\v', '\\': '\\', "'": "'", '"': '"', '?': '?' };
    if (Object.prototype.hasOwnProperty.call(simple, next)) { out += simple[next]; continue; }
    if (next === 'x') {
      const match = body.slice(i + 1).match(/^[0-9a-fA-F]{1,2}/);
      if (match) { out += String.fromCharCode(parseInt(match[0], 16)); i += match[0].length; continue; }
    }
    if (next === 'u' || next === 'U') {
      const match = body.slice(i + 1).match(next === 'u' ? /^[0-9a-fA-F]{1,4}/ : /^[0-9a-fA-F]{1,8}/);
      if (match) { out += String.fromCodePoint(parseInt(match[0], 16)); i += match[0].length; continue; }
    }
    if (/[0-7]/.test(next)) {
      const match = body.slice(i).match(/^[0-7]{1,3}/);
      out += String.fromCharCode(parseInt(match[0], 8));
      i += match[0].length - 1;
      continue;
    }
    if (next === 'c') { i += 1; continue; }
    out += `\\${next}`;
  }
  return out;
}

// Returns the index just past the matching close paren for a "(" at `start - 1`, honouring
// quotes and nested parentheses. Throws on an unterminated group.
function scanBalanced(src, start, open = '(', close = ')') {
  let depth = 1;
  let i = start;
  while (i < src.length) {
    const ch = src[i];
    if (ch === '\\') { i += 2; continue; }
    if (ch === '<' && src[i + 1] === '<' && src[i + 2] !== '<') {
      // Heredoc inside a substitution: skip its body so quotes in the text (for example an
      // apostrophe in a commit message) do not unbalance the scan.
      const match = src.slice(i).match(/^<<-?\s*(['"]?)([A-Za-z0-9_.-]+)\1/);
      if (match) {
        const bodyStart = src.indexOf('\n', i + match[0].length);
        if (bodyStart < 0) throw new ParseError('unterminated heredoc');
        const stripTabs = src[i + 2] === '-';
        let j = bodyStart + 1;
        let found = false;
        while (j <= src.length) {
          let end = src.indexOf('\n', j);
          if (end < 0) end = src.length;
          const line = stripTabs ? src.slice(j, end).replace(/^\t+/, '') : src.slice(j, end);
          j = end + 1;
          if (line === match[2]) { found = true; break; }
          if (end >= src.length) break;
        }
        if (!found) throw new ParseError('unterminated heredoc');
        i = j - 1;
        continue;
      }
    }
    if (ch === "'") {
      const end = src.indexOf("'", i + 1);
      if (end < 0) throw new ParseError('unterminated quote');
      i = end + 1;
      continue;
    }
    if (ch === '"') {
      i += 1;
      while (i < src.length && src[i] !== '"') i += src[i] === '\\' ? 2 : 1;
      if (i >= src.length) throw new ParseError('unterminated quote');
      i += 1;
      continue;
    }
    if (ch === '`') {
      const end = src.indexOf('`', i + 1);
      if (end < 0) throw new ParseError('unterminated backtick');
      i = end + 1;
      continue;
    }
    if (ch === open) depth += 1;
    else if (ch === close) {
      depth -= 1;
      if (depth === 0) return i + 1;
    }
    i += 1;
  }
  throw new ParseError('unterminated group');
}

function newWord() {
  return { text: '', dynamic: false, quoted: false, substitution: false, started: false, variables: [], slots: [] };
}

function tokenize(src, state) {
  const tokens = [];
  let word = newWord();
  const pendingHeredocs = [];
  let i = 0;

  const pushWord = () => {
    if (word.started) tokens.push({ type: 'word', word });
    word = newWord();
  };
  const pushOp = (op) => { pushWord(); tokens.push({ type: 'op', op }); };
  const markSubstitution = (inner) => {
    word.dynamic = true;
    word.substitution = true;
    word.started = true;
    word.slots.push({ type: 'sub' });
    state.substitutions.push(inner);
    state.reasons.add('command_substitution');
  };

  const readHeredocBodies = () => {
    while (pendingHeredocs.length > 0) {
      const heredoc = pendingHeredocs.shift();
      const lines = [];
      let found = false;
      while (i < src.length) {
        let end = src.indexOf('\n', i);
        if (end < 0) end = src.length;
        let line = src.slice(i, end);
        i = end + 1;
        if (heredoc.stripTabs) line = line.replace(/^\t+/, '');
        if (line === heredoc.delimiter) { found = true; break; }
        lines.push(line);
      }
      heredoc.token.body = lines.join('\n');
      heredoc.token.bodyDynamic = !heredoc.quoted && /[$`]/.test(heredoc.token.body);
      if (!found) state.reasons.add('unterminated_heredoc');
    }
  };

  while (i < src.length) {
    const ch = src[i];

    if (ch === '\n') {
      pushOp(';');
      i += 1;
      readHeredocBodies();
      continue;
    }
    if (ch === ' ' || ch === '\t' || ch === '\r') { pushWord(); i += 1; continue; }
    if (ch === '#' && !word.started) {
      const end = src.indexOf('\n', i);
      i = end < 0 ? src.length : end;
      continue;
    }
    if (ch === '\\') {
      if (src[i + 1] === '\n') { i += 2; continue; }
      if (i + 1 < src.length) { word.text += src[i + 1]; word.started = true; word.quoted = true; }
      i += 2;
      continue;
    }
    if (ch === "'") {
      const end = src.indexOf("'", i + 1);
      if (end < 0) throw new ParseError('unterminated single quote');
      word.text += src.slice(i + 1, end);
      word.started = true;
      word.quoted = true;
      i = end + 1;
      continue;
    }
    if (ch === '$' && src[i + 1] === "'") {
      let j = i + 2;
      while (j < src.length && src[j] !== "'") j += src[j] === '\\' ? 2 : 1;
      if (j >= src.length) throw new ParseError('unterminated ANSI-C quote');
      word.text += decodeAnsiC(src.slice(i + 2, j));
      word.started = true;
      word.quoted = true;
      state.reasons.add('ansi_c_quote');
      i = j + 1;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      word.started = true;
      word.quoted = true;
      while (j < src.length && src[j] !== '"') {
        const c = src[j];
        if (c === '\\' && j + 1 < src.length) {
          const n = src[j + 1];
          if (n === '$' || n === '`' || n === '"' || n === '\\') { word.text += n; j += 2; continue; }
          if (n === '\n') { j += 2; continue; }
          word.text += c;
          j += 1;
          continue;
        }
        if (c === '$' && src[j + 1] === '(') {
          if (src[j + 2] === '(') {
            const end = scanBalanced(src, j + 3);
            word.text += '\u0000';
            word.slots.push({ type: 'arith' });
            word.dynamic = true;
            j = end + 1;
            continue;
          }
          const end = scanBalanced(src, j + 2);
          markSubstitution(src.slice(j + 2, end - 1));
          word.text += '\u0000';
          j = end;
          continue;
        }
        if (c === '`') {
          const end = src.indexOf('`', j + 1);
          if (end < 0) throw new ParseError('unterminated backtick');
          markSubstitution(src.slice(j + 1, end));
          word.text += '\u0000';
          j = end + 1;
          continue;
        }
        if (c === '$' && /[A-Za-z_{0-9@*#?$!-]/.test(src[j + 1] || '')) {
          const match = src.slice(j + 1).match(/^(\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])/);
          const name = match ? match[0].replace(/^\{|\}$/g, '') : '?';
          word.dynamic = true;
          word.variables.push(name);
          word.slots.push({ type: 'var', name });
          word.text += '\u0000';
          j += 1 + (match ? match[0].length : 0);
          continue;
        }
        word.text += c;
        j += 1;
      }
      if (j >= src.length) throw new ParseError('unterminated double quote');
      i = j + 1;
      continue;
    }
    if (ch === '`') {
      const end = src.indexOf('`', i + 1);
      if (end < 0) throw new ParseError('unterminated backtick');
      markSubstitution(src.slice(i + 1, end));
      word.text += '\u0000';
      i = end + 1;
      continue;
    }
    if (ch === '$') {
      const next = src[i + 1] || '';
      if (next === '(' && src[i + 2] === '(') {
        const end = scanBalanced(src, i + 3);
        word.text += '\u0000';
        word.slots.push({ type: 'arith' });
        word.dynamic = true;
        word.started = true;
        i = end + 1;
        continue;
      }
      if (next === '(') {
        const end = scanBalanced(src, i + 2);
        markSubstitution(src.slice(i + 2, end - 1));
        word.text += '\u0000';
        i = end;
        continue;
      }
      const match = src.slice(i + 1).match(/^(\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])/);
      if (match) {
        const name = match[0].replace(/^\{|\}$/g, '');
        word.dynamic = true;
        word.started = true;
        word.variables.push(name);
        word.slots.push({ type: 'var', name });
        word.text += '\u0000';
        i += 1 + match[0].length;
        continue;
      }
      word.text += '$';
      word.started = true;
      i += 1;
      continue;
    }
    if ((ch === '<' || ch === '>') && src[i + 1] === '(' && !word.started) {
      const end = scanBalanced(src, i + 2);
      markSubstitution(src.slice(i + 2, end - 1));
      state.reasons.add('process_substitution');
      word.text += '\u0000';
      i = end;
      continue;
    }
    if (ch === '<' || ch === '>' || (ch === '&' && src[i + 1] === '>')) {
      let fd = null;
      if (word.started && !word.quoted && /^[0-9]+$/.test(word.text)) { fd = word.text; word = newWord(); }
      pushWord();
      const rest = src.slice(i);
      const op = (rest.match(/^(&>>|&>|<<<|<<-|<<|<>|>>|>\||>&|<&|<|>)/) || [ch])[0];
      i += op.length;
      tokens.push({ type: 'redir', op, fd });
      if (op === '<<' || op === '<<-') {
        // Read the delimiter word now so the body can be collected after the next newline.
        while (src[i] === ' ' || src[i] === '\t') i += 1;
        let delimiter = '';
        let quoted = false;
        while (i < src.length && !/[\s;&|<>()]/.test(src[i])) {
          if (src[i] === "'" || src[i] === '"') {
            const q = src[i];
            const end = src.indexOf(q, i + 1);
            if (end < 0) throw new ParseError('unterminated heredoc delimiter');
            delimiter += src.slice(i + 1, end);
            quoted = true;
            i = end + 1;
            continue;
          }
          if (src[i] === '\\') { delimiter += src[i + 1] || ''; quoted = true; i += 2; continue; }
          delimiter += src[i];
          i += 1;
        }
        const heredocToken = { type: 'heredoc', delimiter, body: '', bodyDynamic: false };
        tokens.push(heredocToken);
        pendingHeredocs.push({ delimiter, quoted, stripTabs: op === '<<-', token: heredocToken });
      }
      continue;
    }
    if (ch === '|' || ch === '&' || ch === ';' || ch === '(' || ch === ')') {
      const rest = src.slice(i);
      const op = (rest.match(/^(\|\||\|&|&&|;;&|;;|;&|\||&|;|\(|\))/) || [ch])[0];
      if (op === ';;' || op === ';&' || op === ';;&') state.reasons.add('case_statement');
      pushOp(op);
      i += op.length;
      continue;
    }
    if ((ch === '*' || ch === '?' || ch === '[') && !word.quoted) word.glob = true;
    word.text += ch;
    word.started = true;
    i += 1;
  }
  pushWord();
  if (pendingHeredocs.length) readHeredocBodies();
  return tokens;
}

function newCommand() {
  return { words: [], assignments: [], redirects: [], heredoc: null, heredocDynamic: false, pipedInput: false, pipesOutput: false, background: false, subshell: false };
}

function parseShell(source, options = {}) {
  const depth = options.depth || 0;
  const state = { substitutions: [], reasons: new Set() };
  const result = { ok: true, commands: [], substitutions: state.substitutions, reasons: [], dynamic: false, error: null };
  const text = String(source == null ? '' : source);
  if (Buffer.byteLength(text) > MAX_SOURCE_BYTES) {
    return { ...result, ok: false, dynamic: true, error: 'too_large', reasons: ['too_large'] };
  }
  let tokens;
  try {
    tokens = tokenize(text, state);
  } catch (error) {
    return { ...result, ok: false, dynamic: true, error: error instanceof ParseError ? error.message : 'parse_error', reasons: ['unparseable'] };
  }

  let current = newCommand();
  let forState = null;
  let subshellDepth = 0;
  let expectRedirTarget = null;
  const finish = (op) => {
    if (current.words.length || current.assignments.length || current.redirects.length || current.heredoc !== null) {
      if (op === '|' || op === '|&') current.pipesOutput = true;
      if (op === '&') current.background = true;
      current.subshell = subshellDepth > 0;
      result.commands.push(current);
    }
    const next = newCommand();
    if (op === '|' || op === '|&') next.pipedInput = true;
    current = next;
  };

  for (let t = 0; t < tokens.length; t += 1) {
    const token = tokens[t];
    if (expectRedirTarget) {
      if (token.type === 'word') {
        expectRedirTarget.target = token.word;
        expectRedirTarget = null;
        continue;
      }
      if (token.type === 'heredoc') { expectRedirTarget = null; }
      else { state.reasons.add('dangling_redirect'); expectRedirTarget = null; }
    }
    if (token.type === 'heredoc') {
      current.heredoc = token.body;
      current.heredocDynamic = token.bodyDynamic;
      continue;
    }
    if (token.type === 'redir') {
      const redirect = { op: token.op, fd: token.fd, target: null };
      current.redirects.push(redirect);
      if (token.op !== '<<' && token.op !== '<<-') expectRedirTarget = redirect;
      continue;
    }
    if (token.type === 'op') {
      if (token.op === '(') {
        // `name ( )` defines a function; otherwise a subshell group.
        if (current.words.length === 1 && tokens[t + 1] && tokens[t + 1].type === 'op' && tokens[t + 1].op === ')') {
          current.words = [];
          t += 1;
          continue;
        }
        finish(';');
        subshellDepth += 1;
        continue;
      }
      if (token.op === ')') { finish(';'); subshellDepth = Math.max(0, subshellDepth - 1); continue; }
      finish(token.op);
      continue;
    }
    const word = token.word;
    if (forState) {
      // `for NAME [in ITEMS...]; do`: record the loop variable and its literal items so the
      // classifier can check every value the body will see.
      if (!word.quoted && word.text === 'do') {
        result.commands.push({ ...newCommand(), forLoop: { name: forState.name, items: forState.sawIn ? forState.items : null } });
        forState = null;
      } else if (forState.name === null) forState.name = word.text;
      else if (!forState.sawIn && !word.quoted && word.text === 'in') forState.sawIn = true;
      else if (forState.sawIn) forState.items.push(word);
      continue;
    }
    if (current.words.length === 0) {
      if (!word.quoted && SEPARATOR_KEYWORDS.has(word.text)) continue;
      if (!word.quoted && (word.text === 'for' || word.text === 'select')) { forState = { name: null, items: [], sawIn: false }; continue; }
      if (!word.quoted && (word.text === 'case' || word.text === 'coproc')) { state.reasons.add(`${word.text}_statement`); }
      if (!word.quoted && word.text === 'function') { t += 1; continue; }
      if (/^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=/.test(word.text)) {
        current.assignments.push(word);
        continue;
      }
    }
    current.words.push(word);
  }
  if (expectRedirTarget) state.reasons.add('dangling_redirect');
  finish(';');

  if (result.commands.length > MAX_COMMANDS) {
    return { ...result, ok: false, dynamic: true, error: 'too_many_commands', reasons: ['too_many_commands'] };
  }
  result.reasons = [...state.reasons];
  result.dynamic = result.reasons.length > 0 || result.commands.some((command) => command.words.some((w) => w.dynamic)
    || command.redirects.some((r) => r.target && r.target.dynamic));
  result.depth = depth;
  return result;
}

module.exports = { parseShell, decodeAnsiC, MAX_SOURCE_BYTES };
