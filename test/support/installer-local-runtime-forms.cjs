// The installer's hook command forms, copied verbatim from @getmarrow/install
// d0125a2c80c8762c96d669dd89cc854ecc0a2ca8 src/mcp-runtime.js (lines 300-412), as a
// fixture of what the installer writes. Not used by the package itself.
'use strict';

const VERSION_RE = /^\d+\.\d+\.\d+$/;

// ---------------------------------------------------------------------------
// Hook commands: the canonical npx form <-> the local runtime form.
// ---------------------------------------------------------------------------

const ARGS = '--package=@getmarrow/mcp@(\\d+\\.\\d+\\.\\d+) marrow-mcp ([a-z][a-z-]{0,63})';
const RUN = (version) => `$HOME/.marrow/runtime/mcp/${version}/run`;
const NODE = (version) => `$HOME/.marrow/runtime/mcp/${version}/node`;

// 1. A plain entrypoint command.
function localPlain(version, sub) {
  const args = `--package=@getmarrow/mcp@${version} marrow-mcp ${sub}`;
  return `/bin/sh -c 'M="${RUN(version)}"; if [ -x "$M" ]; then exec "$M" ${args}; fi; exec npx -y ${args}'`;
}
const LOCAL_PLAIN_RE = new RegExp(`^/bin/sh -c 'M="\\$HOME/\\.marrow/runtime/mcp/(\\d+\\.\\d+\\.\\d+)/run"; if \\[ -x "\\$M" \\]; then exec "\\$M" ${ARGS}; fi; exec npx -y --package=@getmarrow/mcp@\\2 marrow-mcp \\3'$`);
const CANONICAL_PLAIN_RE = new RegExp(`^npx -y ${ARGS}$`);

// 2. An entrypoint inside an `sh -c '...'` wrapper (Windsurf, Gemini).
function localInner(version, sub) {
  const args = `--package=@getmarrow/mcp@${version} marrow-mcp ${sub}`;
  return `{ M="${RUN(version)}"; if [ -x "$M" ]; then "$M" ${args}; else npx -y ${args}; fi; }`;
}
const LOCAL_INNER_RE = new RegExp(`\\{ M="\\$HOME/\\.marrow/runtime/mcp/(\\d+\\.\\d+\\.\\d+)/run"; if \\[ -x "\\$M" \\]; then "\\$M" ${ARGS}; else npx -y --package=@getmarrow/mcp@\\2 marrow-mcp \\3; fi; \\}`, 'g');
const CANONICAL_INNER_RE = new RegExp(`npx -y ${ARGS}`, 'g');

// 3. A node guard (`node -e '...'`) that spawns the entrypoint through npx.
const SPAWN_NPX = 'spawn(process.platform==="win32"?"npx.cmd":"npx",';
function localSpawn(version, argsJson) {
  return `spawn(...((f,m,a)=>f.existsSync(m)?[m,a.slice(1)]:[process.platform==="win32"?"npx.cmd":"npx",a])(require("node:fs"),(process.env.HOME||"")+${JSON.stringify(`/.marrow/runtime/mcp/${version}/run`)},${argsJson}),`;
}
const LOCAL_SPAWN_RE = /spawn\(\.\.\.\(\(f,m,a\)=>f\.existsSync\(m\)\?\[m,a\.slice\(1\)\]:\[process\.platform==="win32"\?"npx\.cmd":"npx",a\]\)\(require\("node:fs"\),\(process\.env\.HOME\|\|""\)\+"\/\.marrow\/runtime\/mcp\/\d+\.\d+\.\d+\/run",(\["-y","--package=@getmarrow\/mcp@\d+\.\d+\.\d+","marrow-mcp","[a-z-]+"\])\),/g;
const CANONICAL_SPAWN_RE = /spawn\(process\.platform==="win32"\?"npx\.cmd":"npx",(\["-y","--package=@getmarrow\/mcp@(\d+\.\d+\.\d+)","marrow-mcp","[a-z-]+"\]),/g;
const localGuardPrefix = (version) => `N="${NODE(version)}"; [ -x "$N" ] || N=node; exec "$N" -e '`;
const LOCAL_GUARD_PREFIX_RE = /^N="\$HOME\/\.marrow\/runtime\/mcp\/\d+\.\d+\.\d+\/node"; \[ -x "\$N" \] \|\| N=node; exec "\$N" -e '/;

// The canonical (npx) form of a hook command; any other command is returned unchanged.
function delocalizeHookCommand(command) {
  if (typeof command !== 'string') return command;
  const plain = command.match(LOCAL_PLAIN_RE);
  if (plain && plain[1] === plain[2]) return `npx -y --package=@getmarrow/mcp@${plain[2]} marrow-mcp ${plain[3]}`;
  if (LOCAL_GUARD_PREFIX_RE.test(command)) {
    return command.replace(LOCAL_GUARD_PREFIX_RE, 'node -e \'').replace(LOCAL_SPAWN_RE, `${SPAWN_NPX}$1,`);
  }
  if (command.startsWith('/bin/sh -c \'') && LOCAL_INNER_RE.test(command)) {
    LOCAL_INNER_RE.lastIndex = 0;
    const inner = command.replace(LOCAL_INNER_RE, (match, runVersion, version, sub) => (
      runVersion === version ? `npx -y --package=@getmarrow/mcp@${version} marrow-mcp ${sub}` : match
    ));
    return inner === command ? command : `sh -c '${inner.slice('/bin/sh -c \''.length)}`;
  }
  return command;
}

// The local runtime form of a canonical hook command for `version`, or the command unchanged
// when it is not a Marrow entrypoint for that version. The result always maps back exactly.
function localizeHookCommand(command, version) {
  if (typeof command !== 'string' || !VERSION_RE.test(String(version || ''))) return command;
  let local = command;
  const plain = command.match(CANONICAL_PLAIN_RE);
  if (plain) {
    if (plain[1] !== version) return command;
    local = localPlain(version, plain[2]);
  } else if (command.startsWith('node -e \'') && command.includes(SPAWN_NPX)) {
    let matched = false;
    const body = command.slice('node -e \''.length).replace(CANONICAL_SPAWN_RE, (match, argsJson, specVersion) => {
      if (specVersion !== version) return match;
      matched = true;
      return localSpawn(version, argsJson);
    });
    if (!matched) return command;
    local = `${localGuardPrefix(version)}${body}`;
  } else if (command.startsWith('sh -c \'')) {
    let matched = false;
    const body = command.slice('sh -c \''.length).replace(CANONICAL_INNER_RE, (match, specVersion, sub) => {
      if (specVersion !== version) return match;
      matched = true;
      return localInner(version, sub);
    });
    if (!matched) return command;
    local = `/bin/sh -c '${body}`;
  } else {
    return command;
  }
  return delocalizeHookCommand(local) === command ? local : command;
}

// Every `command` string in a parsed hook settings object.
function mapHookCommands(value, map) {
  if (Array.isArray(value)) return value.map((entry) => mapHookCommands(entry, map));
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).map(([key, entry]) => [
    key,
    key === 'command' && typeof entry === 'string' ? map(entry) : mapHookCommands(entry, map),
  ]));
}

// Hook settings text with Marrow's entrypoints for `version` switched to the local runtime.
function localizeHookSettingsText(text, version) {
  if (typeof text !== 'string' || !text.trim()) return text;
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return text;
  }
  let changed = false;
  const mapped = mapHookCommands(parsed, (command) => {
    const local = localizeHookCommand(command, version);
    if (local !== command) changed = true;
    return local;
  });
  return changed ? `${JSON.stringify(mapped, null, 2)}\n` : text;
}

module.exports = { delocalizeHookCommand, localizeHookCommand, localizeHookSettingsText };
