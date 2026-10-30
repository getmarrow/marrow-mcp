"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.WINDOWS_REASONS = void 0;
exports.matcherCells = matcherCells;
exports.windowsProtectedHits = windowsProtectedHits;
exports.mergeWindowsHits = mergeWindowsHits;
exports.withWindowsProtected = withWindowsProtected;
const tables_1 = require("./tables");
const baseline = require('../../vendor/classifier/policy-baseline.js');
/** The reason codes this module adds. The decision's rule is `<category>.<reason>` when one of them leads it. */
exports.WINDOWS_REASONS = Object.freeze({
    protectedPath: 'windows_protected_path',
    persistence: 'windows_persistence',
    shim: 'windows_shim_write',
    secretPath: 'windows_secret_path',
    envDump: 'windows_env_dump',
    secretStore: 'windows_secret_store',
    oddPath: 'windows_odd_path',
});
// ---------------------------------------------------------------------------------------------
// patterns
// A home the hook does not know: `~/X` is matched in any folder (`**/X`), except where that would catch
// ordinary project folders (`bin`, `.cursor`, `.gemini`, `Library`); those are matched in any profile.
const HOME = 'c:/users/__user__';
const GENERIC_HOME_DIRS = new Set(['bin', '.cursor', '.gemini', 'library']);
// Windows places with no POSIX twin. `op`: like a POSIX protected path, any program that is not a reader stops
// on it. `wo`: like the POSIX program folders and system trees (OPERAND_RULE_OMITS), only a write stops.
const WINDOWS_PROTECTED = [
    // PowerShell profiles and modules (the POSIX .bashrc / .profile).
    ['**/documents/windowspowershell/**', 'op'], ['**/documents/powershell/**', 'op'], ['**/profile.ps1', 'op'], ['**/*_profile.ps1', 'op'],
    // Marrow's code copies and the hook configs.
    ['**/npm-cache/_npx/*/node_modules/@getmarrow/**', 'op'], ['**/.claude/plugins/**', 'op'], ['**/.claude/settings*.json', 'op'],
    // The git and Git Bash configuration Git for Windows reads (the POSIX /etc/gitconfig, /etc/profile).
    ['**/.config/git/config', 'op'], ['**/git/etc/gitconfig', 'op'], ['**/git/mingw64/etc/gitconfig', 'op'], ['?:/programdata/git/config', 'op'],
    ['**/git/etc/profile', 'op'], ['**/git/etc/profile.d/**', 'op'], ['**/git/etc/bash.bashrc', 'op'], ['**/git/etc/bash_profile', 'op'],
    // Claude Code managed settings on Windows (the POSIX /etc/claude-code) and the hosts file.
    ['?:/programdata/claudecode/**', 'op'], ['?:/program_files/claudecode/**', 'op'], ['?:/windows/system32/drivers/etc/hosts', 'op'],
    // Start-up and PATH folders (the POSIX LaunchAgents and ~/.local/bin).
    ['**/start_menu/programs/startup/**', 'wo'], ['**/appdata/roaming/npm/**', 'wo'], ['**/appdata/local/microsoft/windowsapps/**', 'wo'],
    // System trees (the POSIX /usr, /etc).
    ['?:/windows/**', 'wo'], ['?:/program_files/**', 'wo'], ['?:/program_files_x86/**', 'wo'], ['?:/programdata/**', 'wo'],
];
// Windows secret stores with no POSIX twin, plus two agent credential files (stricter than POSIX, Windows only).
const WINDOWS_SECRETS = [
    '**/appdata/roaming/microsoft/credentials/**', '**/appdata/local/microsoft/credentials/**', '**/appdata/roaming/microsoft/protect/**',
    '**/appdata/roaming/microsoft/crypto/**', '**/appdata/roaming/github_cli/hosts.yml', '**/appdata/roaming/gcloud/**/*credentials*',
    '**/appdata/roaming/gcloud/**/access_tokens.db', '**/appdata/roaming/npm/etc/npmrc', '?:/programdata/ssh/ssh_host_*',
    '**/system32/config/sam', '**/system32/config/security', '**/.claude/.credentials.json', '**/.codex/auth.json',
];
const KEY_EXT = /\.(?:pem|key|p12|pfx|ppk)$/;
const KEY_EXT_SAMPLES = ['server.pem', 'tls.key', 'cert.p12', 'cert.pfx', 'key.ppk'];
// Folders whose removal or move takes a protected file with it (the POSIX protected anchors).
const HOME_ANCHORS = ['.marrow', '.claude', '.cursor', '.codex', '.gemini', '.grok', '.codeium', '.windsurf', '.hermes', '.openclaw', '.ssh', '.aws',
    '.kube', '.docker', '.azure', '.gnupg', '.config/git', '.config/gh', '.config/gcloud', '.npm/_npx', '.local/bin', 'bin',
    'appdata/local/npm-cache/_npx', 'appdata/roaming/npm', 'appdata/roaming/microsoft/windows/start_menu/programs/startup',
    'appdata/roaming/microsoft/credentials', 'appdata/roaming/microsoft/protect', 'appdata/local/microsoft/windowsapps',
    'documents/windowspowershell', 'documents/powershell'];
const SYSTEM_ANCHORS = ['?:/windows', '?:/program_files', '?:/program_files_x86', '?:/programdata'];
// Concrete names for the glob parts of the patterns: a wildcard operand or an 8.3 short name is compared with these.
const GLOB_COMP_SAMPLES = {
    'id_*': ['id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa'],
    '*_key': ['deploy_key'],
    '*credentials*': ['credentials', 'application_default_credentials.json', 'credentials.db'],
    'private-keys*': ['private-keys-v1.d'],
    'env*': ['env', 'env.local'],
    '.env.*': ['.env.local', '.env.production', '.env.development', '.env.test'],
    '*.env': ['app.env', 'prod.env'],
    '*.json': ['installed_plugins.json', 'known_marketplaces.json'],
    '*marrow*': ['marrow', 'getmarrow'],
    'settings*.json': ['settings.json', 'settings.local.json'],
    '*_profile.ps1': ['microsoft.powershell_profile.ps1', 'microsoft.vscode_profile.ps1'],
    'ssh_host_*': ['ssh_host_rsa_key', 'ssh_host_ed25519_key'],
};
// Program names a host may run a hook with. cmd.exe looks in the CURRENT folder before PATH (PATHEXT order), so
// one of these written anywhere can replace the hook (audit RC-1d, consumer C19).
const SHIM = /^(?:(?:node|nodejs|npx|npm|pnpm|yarn|git|bash|sh|cmd|powershell|pwsh|whoami|python3?|py|marrow[\w.-]*)\.(?:com|exe|bat|cmd|ps1)|(?:node|npx)\.(?:vbs|vbe|js|jse|wsf|wsh|msc|cpl))$/;
const SHIM_SAMPLES = ['node.cmd', 'node.exe', 'node.bat', 'node.com', 'node.ps1', 'npx.cmd', 'npm.cmd', 'git.exe', 'pwsh.exe', 'powershell.exe',
    'cmd.exe', 'bash.exe', 'marrow-mcp.cmd'];
// Patterns are ours (never agent text): a RegExp per glob part is safe here.
function patternCompRe(g) {
    return new RegExp(`^${g.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]')}$`);
}
function compilePattern(raw) {
    const lower = raw.toLowerCase();
    let text = lower;
    if (lower.startsWith('~/')) {
        const rest = lower.slice(2);
        text = GENERIC_HOME_DIRS.has(rest.split('/')[0]) ? `?:/users/*/${rest}` : `**/${rest}`;
    }
    text = multiword(text);
    const comps = text.split('/').map((c, i) => {
        if (c === '**')
            return { k: 'gs' };
        if (i === 0 && c === '')
            return { k: 'lit', v: '' };
        if (c === '?:')
            return { k: 'glob', v: c, re: /^[a-z]:$/ };
        return /[*?]/.test(c) ? { k: 'glob', v: c, re: patternCompRe(c) } : { k: 'lit', v: c };
    });
    // The last literal part: a path without it (and without a wildcard part) cannot match.
    let key = null;
    for (let i = comps.length - 1; i >= 0; i -= 1) {
        const c = comps[i];
        if (c.k === 'lit' && c.v !== '') {
            key = c.v;
            break;
        }
    }
    return { comps, key };
}
let PATTERNS = null;
let PATTERN_SOURCE = null;
function patterns(parts) {
    if (PATTERNS && PATTERN_SOURCE === parts.protectedExtra)
        return PATTERNS;
    const op = [];
    const wo = [];
    for (const p of [...baseline.BASELINE_POLICY.protected_paths, ...parts.protectedExtra])
        (parts.operandOmits.has(p) ? wo : op).push(compilePattern(p));
    for (const [p, kind] of WINDOWS_PROTECTED)
        (kind === 'op' ? op : wo).push(compilePattern(p));
    const secret = [...tables_1.SECRET_PATTERNS, ...tables_1.PRESENT_SECRET_PATTERNS, ...WINDOWS_SECRETS].map(compilePattern);
    PATTERNS = { op, wo, secret };
    PATTERN_SOURCE = parts.protectedExtra;
    return PATTERNS;
}
// ---------------------------------------------------------------------------------------------
// wildcards in agent text: a linear walk, never a RegExp
/**
 * The cells the two matchers below fill (wildMatch: glob x text; matches: pattern parts x path parts), added up since the last reset.
 * A test reads it to pin the cost of a decision by a count and not by a clock (M-4); no decision reads it.
 */
const matcherWork = { cells: 0 };
function matcherCells(reset = false) {
    const n = matcherWork.cells;
    if (reset)
        matcherWork.cells = 0;
    return n;
}
/** `*` is any run of characters, `?` one character. O(glob x text). */
function wildMatch(glob, text) {
    matcherWork.cells += glob.length * text.length;
    let prev = new Uint8Array(text.length + 1);
    let cur = new Uint8Array(text.length + 1);
    prev[0] = 1;
    for (let i = 1; i <= glob.length; i += 1) {
        const g = glob[i - 1];
        const star = g === '*';
        cur[0] = star ? prev[0] : 0;
        for (let j = 1; j <= text.length; j += 1) {
            if (star)
                cur[j] = prev[j] || cur[j - 1] ? 1 : 0;
            else
                cur[j] = prev[j - 1] && (g === '?' || g === text[j - 1]) ? 1 : 0;
        }
        [prev, cur] = [cur, prev];
    }
    return prev[text.length] === 1;
}
const DYN = '\u0001';
const SHORT_NAME = /^([^~./*?\u0001]{1,6})~\d{1,6}(?:\.([^.*?\u0001]{1,3}))?$/;
function fuzzyOf(c) {
    if (/[*?[\u0001]/.test(c)) {
        // A character class is one character; a dynamic part is any run.
        const glob = c.replace(/\[[^\]]*\]?/g, '?').split(DYN).join('*').replace(/\*+/g, '*');
        return (name) => wildMatch(glob, name);
    }
    const m = SHORT_NAME.exec(c);
    if (!m)
        return null;
    const heads = [m[1]];
    if (/^.{1,2}[0-9a-f]{4}$/.test(m[1]))
        heads.push(m[1].slice(0, m[1].length - 4));
    const ext = m[2];
    return (name) => {
        // A short name keeps an underscore of the long name (`ID_RSA~1`); spaces are dropped. Both readings are tried.
        const kept = name.replace(/^\.+/, '').replace(/ /g, '');
        return [kept, kept.replace(/_/g, '')].some((n) => {
            if (!heads.some((h) => n.startsWith(h)))
                return false;
            if (!ext)
                return true;
            const dot = n.lastIndexOf('.');
            return dot > 0 && n.slice(dot + 1).startsWith(ext);
        });
    };
}
// Multi-word folder names the patterns name as one word.
function multiword(s) {
    return s.replace(/start\s+menu/g, 'start_menu').replace(/program\s+files\s*\(x86\)/g, 'program_files_x86').replace(/program\s+files/g, 'program_files')
        .replace(/github\s+cli/g, 'github_cli');
}
// Environment variables and PowerShell names that stand for a known folder.
const FOLDER_VARS = [
    [/\$\{env:(?:userprofile|home)\}|\$env:(?:userprofile|home)\b|%userprofile%|%home%|%homedrive%%homepath%|\$env:homedrive\$env:homepath|\$\{(?:home|userprofile)\}|\$(?:home|userprofile)\b/g, HOME],
    [/\$\{env:appdata\}|\$env:appdata\b|%appdata%/g, `${HOME}/appdata/roaming`],
    [/\$\{env:localappdata\}|\$env:localappdata\b|%localappdata%/g, `${HOME}/appdata/local`],
    [/\$\{env:(?:temp|tmp)\}|\$env:(?:temp|tmp)\b|%(?:temp|tmp)%/g, `${HOME}/appdata/local/temp`],
    [/\$\{env:(?:programdata|allusersprofile)\}|\$env:(?:programdata|allusersprofile)\b|%(?:programdata|allusersprofile)%/g, 'c:/programdata'],
    [/\$\{env:programfiles\(x86\)\}|%programfiles\(x86\)%/g, 'c:/program_files_x86'],
    [/\$\{env:(?:programfiles|programw6432)\}|\$env:(?:programfiles|programw6432)\b|%(?:programfiles|programw6432)%/g, 'c:/program_files'],
    [/\$\{env:(?:systemroot|windir)\}|\$env:(?:systemroot|windir)\b|%(?:systemroot|windir)%/g, 'c:/windows'],
    [/\$\{env:onedrive\}|\$env:onedrive\b|%onedrive%/g, `${HOME}/onedrive`],
    [/\$profile(?:\.(?:currentusercurrenthost|currentuserallhosts|allusersallhosts|alluserscurrenthost))?\b/g, `${HOME}/documents/windowspowershell/microsoft.powershell_profile.ps1`],
    [/\$pshome\b/g, 'c:/windows/system32/windowspowershell/v1.0'],
    [/shell:(?:common\s*)?startup|\[(?:system\.)?environment\]::getfolderpath\(\s*['"]?(?:common)?startup['"]?\s*\)|\[(?:system\.)?environment\+specialfolder\]::(?:common)?startup/g, `${HOME}/appdata/roaming/microsoft/windows/start_menu/programs/startup`],
    [/\[(?:system\.)?environment\]::getfolderpath\(\s*['"]?userprofile['"]?\s*\)/g, HOME],
    [/\[(?:system\.)?environment\]::getfolderpath\(\s*['"]?(?:mydocuments|personal)['"]?\s*\)/g, `${HOME}/documents`],
    [/\[(?:system\.)?environment\]::getfolderpath\(\s*['"]?applicationdata['"]?\s*\)/g, `${HOME}/appdata/roaming`],
    [/\[(?:system\.)?environment\]::getfolderpath\(\s*['"]?localapplicationdata['"]?\s*\)/g, `${HOME}/appdata/local`],
    [/\$pwd\b|%cd%/g, '.'],
];
function expandFolders(s) {
    let out = s;
    for (const [re, to] of FOLDER_VARS)
        out = out.replace(re, to);
    // `~` at the start of a word is the home folder (PowerShell, Git Bash).
    return out.replace(/(^|[\s"'=(,;|&<>{}])~(?=\/|$|[\s"';|&)<>,])/g, `$1${HOME}`);
}
/** Device, UNC, provider, URL and MSYS forms of one path, rewritten to `x:/...` where they name a drive. */
function pathPrefixes(p) {
    let s = p;
    s = s.replace(/^file:\/\/(?:localhost)?\/?(?=[a-z]:)/, '').replace(/^file:\/\/\//, '/');
    s = s.replace(/^(?:microsoft\.powershell\.core\/)?filesystem::/, '');
    s = s.replace(/^\/\/[?.]\/unc\//, '//').replace(/^\/\/[?.]\/(?=[a-z]:)/, '').replace(/^\/\?\?\/(?=[a-z]:)/, '');
    s = s.replace(/^\/\/[^/]+\/([a-z])\$(?=\/|$)/, '$1:');
    s = s.replace(/^\/(?:mnt\/|cygdrive\/)?([a-z])(?=\/|$)/, '$1:');
    // `C:Users\x` (relative to the drive's current folder): read from the drive root (the strict reading).
    s = s.replace(/^([a-z]):(?=[^/])/, '$1:/');
    return s;
}
/**
 * The parts of a path as Windows opens it, lower case. Trailing dots and spaces of a part are dropped and an
 * alternate data stream (`name:stream`, `name::$DATA`) is cut off, as Win32 does; `.` and `..` are resolved.
 * A UNC path starts with the part `//`; a path from the drive root starts with ''. A profile folder name is
 * `__user__`. A part that is only a variable is DYN (any number of parts). Null: longer than any path.
 */
function comps(raw) {
    if (raw.length > tables_1.LIMITS.maxPathChars)
        return null;
    const s = pathPrefixes(raw);
    const unc = s.startsWith('//');
    const parts = (unc ? s.slice(2) : s).split('/');
    const out = [];
    if (unc)
        out.push('//');
    const drive = /^[a-z]:$/.test(parts[0]);
    parts.forEach((part, i) => {
        let c = part;
        if (!(i === 0 && drive)) {
            const colon = c.indexOf(':');
            if (colon >= 0)
                c = c.slice(0, colon);
            if (c !== '.' && c !== '..')
                c = c.replace(/[. ]+$/, '');
            c = c.replace(/^ +/, '');
        }
        if (i === 0 && c === '' && !unc && parts.length > 1) {
            out.push('');
            return;
        }
        if (c === '' || c === '.')
            return;
        if (c === '..') {
            const prev = out[out.length - 1];
            if (prev !== undefined && prev !== '..' && prev !== '' && prev !== '//' && !/^[a-z]:$/.test(prev) && prev !== DYN)
                out.pop();
            else if (prev === undefined || prev === '..')
                out.push('..');
            return;
        }
        out.push(c);
    });
    if ((/^[a-z]:$/.test(out[0] || '') || out[0] === '') && out[1] === 'users' && out.length >= 3)
        out[2] = '__user__';
    return out;
}
function view(c) {
    const gs = c.map((x) => x === DYN);
    const fz = c.map((x) => (x === DYN ? () => true : fuzzyOf(x)));
    return { comps: c, fz, gs, hasFuzzy: fz.some(Boolean), set: new Set(c) };
}
function compMatch(p, c, fuzzy) {
    if (p.k === 'gs')
        return false;
    if (fuzzy) {
        if (p.k === 'lit')
            return p.v !== '' && (fuzzy(p.v) || (p.v.includes('_') && fuzzy(p.v.replace(/_/g, ''))));
        if (p.v === '?:' || p.v === '*')
            return true;
        return (GLOB_COMP_SAMPLES[p.v] || [p.v.replace(/[*?]/g, 'x')]).some((v) => fuzzy(v));
    }
    if (c === '__user__' && p.k === 'glob')
        return true;
    return p.k === 'lit' ? p.v === c : p.re.test(c);
}
/** The pattern matches the path. Both sides may hold "any number of parts" (`**`, a dynamic part). */
function matches(pat, v) {
    if (pat.key !== null && !v.hasFuzzy && !v.set.has(pat.key))
        return false;
    const n = v.comps.length;
    const m = pat.comps.length;
    const memo = new Uint8Array((m + 1) * (n + 1));
    matcherWork.cells += (m + 1) * (n + 1);
    const go = (i, j) => {
        const k = i * (n + 1) + j;
        if (memo[k])
            return memo[k] === 1;
        let r;
        if (i === m && j === n)
            r = true;
        else if (j < n && v.gs[j])
            r = go(i, j + 1) || (i < m && go(i + 1, j));
        else if (i === m)
            r = false;
        else {
            const pc = pat.comps[i];
            if (pc.k === 'gs')
                r = go(i + 1, j) || (j < n && go(i, j + 1));
            else
                r = j < n && compMatch(pc, v.comps[j], v.fz[j]) && go(i + 1, j + 1);
        }
        memo[k] = r ? 1 : 2;
        return r;
    };
    return go(0, 0);
}
function anyMatch(list, v) {
    return list.some((p) => matches(p, v));
}
function isSecret(v, parts) {
    if (!v.comps.length)
        return false;
    const base = v.comps[v.comps.length - 1];
    const baseFz = v.fz[v.fz.length - 1];
    if (!baseFz && /^\.env(?:\.|$)/.test(base) && tables_1.ENV_TEMPLATE_SUFFIX.test(base))
        return false;
    const keyFile = baseFz ? KEY_EXT_SAMPLES.some((s) => baseFz(s)) : KEY_EXT.test(base);
    if (keyFile && !v.comps.some((c) => tables_1.KEY_FIXTURE_SEGMENTS.has(c)))
        return true;
    if (!anyMatch(patterns(parts).secret, v))
        return false;
    // ssh public keys are never secret.
    if (!baseFz && v.comps.includes('.ssh') && /\.pub$/.test(base))
        return false;
    return true;
}
function protectedKind(v, parts) {
    if (!v.comps.length)
        return null;
    const pats = patterns(parts);
    if (anyMatch(pats.op, v))
        return 'op';
    if (anyMatch(pats.wo, v))
        return 'wo';
    return null;
}
/** The last part is a program name a hook may be run with. A wildcard counts only for the classic extensions. */
function isShim(v) {
    if (!v.comps.length)
        return false;
    const base = v.comps[v.comps.length - 1];
    const fz = v.fz[v.fz.length - 1];
    return fz ? SHIM_SAMPLES.some((s) => fz(s)) : SHIM.test(base);
}
let ANCHORS = null;
function anchors() {
    if (ANCHORS)
        return ANCHORS;
    const home = HOME_ANCHORS.map((a) => compilePattern(`?:/users/*/${a}`).comps);
    const system = SYSTEM_ANCHORS.map((a) => compilePattern(a).comps);
    const tails = HOME_ANCHORS.filter((a) => !GENERIC_HOME_DIRS.has(a.split('/')[0])).map((a) => a.split('/'));
    ANCHORS = { home, system, tails };
    return ANCHORS;
}
/**
 * The path is an anchor or a folder above one (its removal or move takes a protected file with it).
 * `minDepth`: the fewest parts an absolute path needs (4 = only folders inside a profile).
 */
function ancestorOfAnchor(v, minDepth) {
    const a = anchors();
    const rooted = v.comps[0] === '';
    const c = rooted ? ['c:', ...v.comps.slice(1)] : v.comps;
    const fz = rooted ? [null, ...v.fz.slice(1)] : v.fz;
    const prefixOf = (anchor) => c.length <= anchor.length && c.every((x, i) => compMatch(anchor[i], x, fz[i]));
    if (/^[a-z]:$/.test(c[0] || '')) {
        if (c.length < minDepth)
            return false;
        return a.home.some(prefixOf) || a.system.some(prefixOf);
    }
    if (c[0] === '//')
        return false;
    if (c[0] === '..' || c[0] === DYN)
        return minDepth <= 1;
    // A relative path under an unknown folder: the start of a profile anchor (`.claude`, `appdata\roaming`).
    return a.tails.some((t) => c.length <= t.length && c.every((x, i) => (fz[i] ? fz[i](t[i]) : x === t[i])));
}
/**
 * The folder is an anchor itself or the profile folder: a protected folder (`.ssh`, `.claude`, `appdata\roaming\npm` ...), a system
 * tree, or `C:\Users\<name>`. `del <folder>\*` is then a hit; a folder only ABOVE an anchor (`Documents`, `AppData`) is not, since
 * `*` names the files in the folder and not the folders under it. The folder has no wildcard (bareStarFolder).
 */
function isAnchorFolder(v) {
    const a = anchors();
    const rooted = v.comps[0] === '';
    const c = rooted ? ['c:', ...v.comps.slice(1)] : v.comps;
    if (/^[a-z]:$/.test(c[0] || '')) {
        if (c.length === 3 && c[1] === 'users')
            return true;
        return [...a.home, ...a.system].some((anchor) => c.length === anchor.length && c.every((x, i) => compMatch(anchor[i], x, null)));
    }
    if (c[0] === '//' || c[0] === '..' || c[0] === DYN)
        return false;
    return a.tails.some((t) => c.length === t.length && c.every((x, i) => x === t[i]));
}
// ---------------------------------------------------------------------------------------------
// shell text
const READERS = new Set(['type', 'gc', 'get-content', 'cat', 'more', 'less', 'head', 'tail', 'findstr', 'find', 'select-string', 'sls', 'fc', 'comp',
    'compare-object', 'diff', 'get-filehash', 'format-hex', 'fhx', 'get-item', 'gi', 'get-itemproperty', 'gp', 'get-acl', 'test-path', 'resolve-path',
    'rvpa', 'split-path', 'join-path', 'convert-path', 'dir', 'ls', 'gci', 'get-childitem', 'tree', 'where', 'get-command', 'gcm', 'which', 'echo',
    'write-output', 'write', 'write-host', 'cd', 'chdir', 'set-location', 'sl', 'pushd', 'push-location', 'popd', 'pop-location', 'wc', 'grep', 'rg',
    'measure-object']);
// Programs that take a secret path without printing or copying its content (POSIX S4_EXEMPT_PROGRAMS).
const S4_EXEMPT = new Set(['dir', 'ls', 'gci', 'get-childitem', 'tree', 'test-path', 'resolve-path', 'rvpa', 'split-path', 'join-path', 'convert-path',
    'get-acl', 'icacls', 'attrib', 'takeown', 'cd', 'chdir', 'set-location', 'sl', 'pushd', 'push-location', 'popd', 'echo', 'write-output', 'write',
    'write-host', 'where', 'get-command', 'gcm', 'which', 'del', 'erase', 'rd', 'rmdir', 'rm', 'ri', 'remove-item', 'mkdir', 'md', 'ssh', 'ssh-add',
    'sftp', 'kubectl', 'helm']);
const GIT_READ_SUBS = new Set(['status', 'diff', 'log', 'show', 'blame', 'annotate', 'ls-files', 'ls-tree', 'grep', 'add', 'rev-parse', 'cat-file',
    'check-ignore', 'check-attr', 'shortlog', 'whatchanged', 'describe', 'name-rev', 'rev-list', 'diff-tree', 'diff-files', 'diff-index',
    'count-objects', 'help', 'version', 'var', 'commit']);
const GIT_S4_EXEMPT_SUBS = new Set(['rm', 'check-ignore', 'check-attr', 'ls-files', 'status', 'log', 'restore']);
// Programs that remove, move, rename, link or re-permission what they name: a folder above an anchor stops.
const DESTRUCTIVE = new Set(['del', 'erase', 'rd', 'rmdir', 'rm', 'ri', 'remove-item', 'move', 'mv', 'mi', 'move-item', 'ren', 'rename', 'rni',
    'rename-item', 'robocopy', 'mklink', 'new-item', 'ni', 'set-acl', 'icacls', 'takeown', 'attrib', 'fsutil', 'junction', 'ln']);
// Modelled writers: with DESTRUCTIVE, the only programs that stop on a `wo` place (POSIX: the system trees and program folders).
const WRITERS = new Set([...DESTRUCTIVE, 'set-content', 'sc', 'add-content', 'ac', 'out-file', 'tee', 'tee-object', 'md', 'mkdir', 'copy', 'cp',
    'cpi', 'copy-item', 'xcopy', 'clear-content', 'clc', 'expand', 'expand-archive', 'compress-archive', 'tar', '7z', '7za', 'unzip',
    'invoke-webrequest', 'iwr', 'invoke-restmethod', 'irm', 'wget', 'curl', 'start-bitstransfer', 'bitsadmin', 'certutil', 'install', 'replace',
    'export-csv', 'export-clixml', 'set-itemproperty', 'sp', 'new-itemproperty', 'dd', 'sed', 'scp', 'rsync', 'touch', 'set-item', 'si']);
const DOTNET_WRITE = /\[(?:system\.)?io\.(?:file|directory)\]::(?:write|append|copy|move|create|replace|open(?!read)|delete|setattributes|encrypt)|\.(?:copyto|moveto|writealltext|writeallbytes|writealllines|appendalltext|createtext|appendtext|openwrite|downloadfile|savetofile|delete)\s*\(|system\.net\.webclient|::extracttodirectory|scripting\.filesystemobject|io\.streamwriter/;
const INTERPRETERS = new Set(['node', 'nodejs', 'python', 'python3', 'py', 'ruby', 'perl', 'php', 'deno', 'bun', 'tsx', 'ts-node']);
const START_LIKE = new Set(['start', 'start-process', 'saps']);
// Text whose meaning the lexical reading cannot follow (built strings, evaluated text): the mapper's own
// S0/S4 tripwire is applied to it, as the mapper does for text it cannot parse.
const DYNAMIC_TEXT = /(?:^|[^a-z0-9_-])(?:iex|invoke-expression|invoke-command|icm)(?![a-z0-9_-])|\[scriptblock\]::create|\[char\]|-join(?![a-z])|-f(?=\s)|\[string\]::(?:concat|join|format)|\.replace\s*\(|-replace(?![a-z])|\.invoke\s*\(|frombase64string|-split(?![a-z])/;
function progBase(w) {
    if (!w)
        return '';
    const b = w.slice(w.lastIndexOf('/') + 1);
    return b.replace(/\.(?:exe|cmd|bat|com|ps1)$/, '');
}
/**
 * The text cut into commands and words with every quote removed: separators split even inside a quoted
 * string (the strict reading; a quoted command passed to `cmd /c` or `powershell -c` is read as commands).
 */
function segments(t) {
    const out = [];
    const fresh = (opener) => ({ words: [], redirect: new Set(), input: new Set(), here: new Set(), opener, hasEq: false, assign: false });
    let cur = fresh('');
    let word = '';
    let pending = false;
    let pendingIn = false;
    let pendingHere = false;
    const endWord = () => {
        if (!word)
            return;
        if (pending) {
            cur.redirect.add(cur.words.length);
            pending = false;
        }
        if (pendingIn) {
            cur.input.add(cur.words.length);
            pendingIn = false;
        }
        if (pendingHere) {
            cur.here.add(cur.words.length);
            pendingHere = false;
        }
        cur.words.push(word);
        word = '';
    };
    const endSeg = (opener) => {
        endWord();
        if (cur.words.length)
            out.push(cur);
        cur = fresh(opener);
        pending = false;
        pendingIn = false;
        pendingHere = false;
    };
    for (let i = 0; i < t.length; i += 1) {
        const ch = t[i];
        if (ch === '"' || ch === "'")
            continue;
        if (ch === '$' && t[i + 1] === '(') {
            endSeg('$(');
            i += 1;
            continue;
        }
        if (ch === '(') {
            endSeg('(');
            continue;
        }
        if (ch === '{') {
            endSeg('{');
            continue;
        }
        if (';|&\n\r)}'.includes(ch)) {
            endSeg(';');
            continue;
        }
        if (ch === '>') {
            // `2>`, `*>`: the descriptor is not a word.
            if (/^(?:\d|\*)$/.test(word))
                word = '';
            endWord();
            while (t[i + 1] === '>')
                i += 1;
            pending = true;
            continue;
        }
        if (ch === '<') {
            // `< name` reads the file; `<<` and `<<<` (here-documents and here-strings) and `<(` take text or a command, not a file.
            endWord();
            let n = 1;
            while (t[i + 1] === '<') {
                i += 1;
                n += 1;
            }
            pendingIn = n === 1 && t[i + 1] !== '(';
            pendingHere = n > 1;
            continue;
        }
        if (ch === '=') {
            // `$x = …`, `$x += …`: a PowerShell assignment.
            if (/^[-+*/?]$/.test(word))
                word = '';
            endWord();
            if (cur.words.length === 1 && cur.words[0].startsWith('$') && !cur.hasEq)
                cur.assign = true;
            cur.hasEq = true;
            continue;
        }
        if (ch === ',' || /\s/.test(ch)) {
            endWord();
            continue;
        }
        word += ch;
    }
    endSeg(';');
    return out;
}
/**
 * The program of a command and the index of its word; `cmd /c`, `powershell -c`, call operators and `$x =` are looked through.
 * `launchers`: the indexes of the words that only start the command (`cmd.exe` of `cmd.exe /c ...`, `powershell.exe`, `pwsh.exe`,
 * and the program word after `env`). Each is the program position of its own level and is read like the program word is; the
 * words of the command they start are never launchers, so those are read in full.
 */
function programOf(seg) {
    const w = seg.words;
    if (seg.opener === '(')
        return { prog: '', at: -1, sub: null, launchers: [] };
    let i = 0;
    if (seg.assign) {
        // `$x = <command>` runs the command; `$x = <value>` stores a value (no program: every word is an operand).
        if (w.length < 2 || !/^[a-z][a-z0-9-]*$/.test(w[1]))
            return { prog: '', at: -1, sub: null, launchers: [] };
        i = 1;
    }
    // A redirect target is never the program (`> x.json echo`, or `echo '{}' > x.json`, whose `{}` cut the text).
    while (i < w.length && (seg.redirect.has(i) || w[i] === '.' || w[i] === '&' || w[i] === 'call' || w[i] === '@'))
        i += 1;
    let prog = progBase(w[i]);
    const launchers = [];
    for (let depth = 0; depth < 4 && i < w.length; depth += 1) {
        let j = -1;
        if (prog === 'cmd')
            j = w.findIndex((x, k) => k > i && /^\/[ckr]$/.test(x));
        else if (prog === 'powershell' || prog === 'pwsh')
            j = w.findIndex((x, k) => k > i && /^[-/](?:c|co|com|comm|comma|comman|command|commandwithargs|cwa)$/.test(x));
        if (j < 0 || j + 1 >= w.length)
            break;
        launchers.push(i);
        i = j + 1;
        // A redirect target is never the program here either (`cmd.exe /c > node.cmd echo x` writes node.cmd).
        while (i < w.length && (seg.redirect.has(i) || w[i] === '.' || w[i] === '&' || w[i] === 'call'))
            i += 1;
        prog = progBase(w[i]);
    }
    // `env` runs the next word as a program (after `-i`, `-0`, `-v`). Its program word is a launcher; what `env` itself does with
    // the rest is not changed. With an `=` in the text the assignments cannot be told from the program, so nothing is looked through.
    if (prog === 'env' && !seg.hasEq) {
        let k = i + 1;
        while (k < w.length && /^-(?:i|0|v)$/.test(w[k]))
            k += 1;
        if (k < w.length && !w[k].startsWith('-') && !seg.redirect.has(k))
            launchers.push(k);
    }
    let sub = null;
    if (prog === 'git') {
        for (let k = i + 1; k < w.length; k += 1) {
            if (/^-[cC]$/.test(w[k]) || /^--(?:git-dir|work-tree|namespace|exec-path)$/.test(w[k])) {
                k += 1;
                continue;
            }
            if (w[k].startsWith('-'))
                continue;
            sub = w[k];
            break;
        }
    }
    return { prog, at: i, sub, launchers };
}
function isOption(w) {
    return /^-[a-z?][\w?-]*$/.test(w) || /^--[a-z][\w-]*$/.test(w) || /^\/[a-z?]{1,12}$/.test(w);
}
// Verbs that persist something or poison the environment (S0) and that read secrets (S4), matched on the
// normalised text. Each test is linear: two facts that must both hold are tested on their own.
const WS = '(?:^|[^a-z0-9_.$-])';
const PERSIST = [
    new RegExp(`${WS}setx(?:\\.exe)?(?![a-z0-9_.-])`),
    /::\s*setenvironmentvariable\b|\.setenvironmentvariable\s*\(/,
    new RegExp(`${WS}reg(?:\\.exe)?\\s+(?:add|import|load|restore|copy|delete|unload)(?![a-z0-9_-])`),
    new RegExp(`${WS}(?:regedit|regedt32|regini)(?:\\.exe)?(?![a-z0-9_-])`),
    /(?:register|set)-scheduled(?:task|job)\b|schedule\.service|new-jobtrigger/,
    /__eventfilter|commandlineeventconsumer|activescripteventconsumer|__filtertoconsumerbinding|stdregprov/,
    new RegExp(`${WS}sc(?:\\.exe)?\\s+(?:create|config|failure)\\s`),
    /(?:new|set)-service\b/,
];
const SCHTASKS = new RegExp(`${WS}schtasks(?:\\.exe)?(?![a-z0-9_-])`);
const SCHTASKS_WRITE = /\/(?:create|change)\b/;
const AT_JOB = new RegExp(`${WS}at(?:\\.exe)?\\s+(?:\\/\\/\\S+\\s+)?\\d{1,2}:\\d{2}`);
const WMIC = new RegExp(`${WS}wmic(?:\\.exe)?(?![a-z0-9_-])`);
const WMIC_ENV = /\benvironment\b/;
const REG_PATH = /(?:^|[^a-z0-9_])(?:hk(?:cu|lm|cr|u|cc)|hkey_(?:current_user|local_machine|classes_root|users|current_config))(?=[:/\s"';]|$)|registry::/;
const REG_WRITE = /(?:new|set|remove|rename|copy|move|clear)-item(?:property)?\b|(?:^|[\s;|&({])(?:ni|si|sp|rp|ri|rni|rnp|cpi|cpp|mi|mp|cli|clp|del|erase|rm|rd|rmdir|move|copy|mv|cp)(?=$|[\s;|&)}])|(?:\.|::)\s*(?:setvalue|createsubkey|deletevalue|deletesubkey(?:tree)?|setaccesscontrol)\s*\(/;
const STORE = new RegExp(`${WS}(?:cmdkey|vaultcmd)(?:\\.exe)?(?![a-z0-9_-])|passwordvault|get-storedcredential|${WS}cred(?:read|enumerate)\\b|protecteddata\\]?::\\s*unprotect|mimikatz|sekurlsa|lsadump|credential-manager(?:-core)?\\s+(?:get|erase|store)|${WS}git(?:\\.exe)?\\s+credential(?:-manager(?:-core)?)?\\s+(?:fill|get)`);
const STORE_PAIRS = [[/convertfrom-securestring/, /-asplaintext/], [/comsvcs/, /minidump/], [/lsass/, /dump|procdump|minidump/],
    [/get-credential|pscredential/, /getnetworkcredential\(\)\s*\.\s*password/]];
const PROVIDER_ENV = /(?:^|[^a-z0-9_${:])(env|variable):\/?([a-z0-9_*?().-]*)/g;
const ENV_READ = /\$\{?env:([a-z0-9_]+)\}?(\s*=(?!=))?/g;
const GETENV = /getenvironmentvariable\s*\(\s*(['"]?)([^'"),\s]*)/g;
const CMD_VAR = /%([a-z_][a-z0-9_]*)%|!([a-z_][a-z0-9_]*)!/g;
function verbHits(s, hit) {
    if (PERSIST.some((re) => re.test(s)) || (SCHTASKS.test(s) && SCHTASKS_WRITE.test(s)) || (WMIC.test(s) && WMIC_ENV.test(s))
        || (REG_PATH.test(s) && REG_WRITE.test(s)) || AT_JOB.test(s))
        hit('S0', exports.WINDOWS_REASONS.persistence);
    if (STORE.test(s) || STORE_PAIRS.some(([a, b]) => a.test(s) && b.test(s)))
        hit('S4', exports.WINDOWS_REASONS.secretStore);
    for (const m of s.matchAll(PROVIDER_ENV)) {
        const name = m[2];
        if (name === '' || /[*?]/.test(name) || tables_1.SECRET_VAR.test(name)) {
            hit('S4', exports.WINDOWS_REASONS.envDump);
            break;
        }
    }
    for (const m of s.matchAll(ENV_READ))
        if (!m[2] && tables_1.SECRET_VAR.test(m[1])) {
            hit('S4', exports.WINDOWS_REASONS.envDump);
            break;
        }
    if (/getenvironmentvariables\b/.test(s))
        hit('S4', exports.WINDOWS_REASONS.envDump);
    for (const m of s.matchAll(GETENV))
        if (!m[1] || tables_1.SECRET_VAR.test(m[2])) {
            hit('S4', exports.WINDOWS_REASONS.envDump);
            break;
        }
    for (const m of s.matchAll(CMD_VAR))
        if (tables_1.SECRET_VAR.test(m[1] || m[2])) {
            hit('S4', exports.WINDOWS_REASONS.envDump);
            break;
        }
}
/**
 * Git commit and tag messages (`-m "..."`) are data. A message is taken out of the text only when it is a plain
 * literal in every shell that may read it: a double-quoted string at the top level (an even count of `"` and `'`
 * before it), in a git command, with no `$`, backtick, `%`, `!`, `^` or `\` inside, and no `^`, backtick or `\"`
 * anywhere in the text.
 */
// One forward pass (linear): the quote counts and the command start are carried from match to match, and the
// git test is made once per command start. A git head that would end after the message counts as not git.
const GIT_HEAD = /\s*(?:\S*[\\/])?git(?:\.exe)?\s/iy;
function stripGitMessages(raw) {
    if (/[\^`]|\\"/.test(raw))
        return raw;
    let pos = 0;
    let dq = 0;
    let sq = 0;
    let segStart = -1;
    const heads = new Map();
    return raw.replace(/(\s(?:-m|--message)(?:\s+|=))"([^"$`%!^\\\r\n]*)"(?=\s|$)/gi, (all, head, _msg, offset) => {
        for (; pos < offset; pos += 1) {
            const ch = raw[pos];
            if (ch === '"')
                dq += 1;
            else if (ch === "'")
                sq += 1;
            else if (ch === ';' || ch === '&' || ch === '|' || ch === '\n' || ch === '(' || ch === '{')
                segStart = pos;
        }
        if (dq % 2 !== 0 || sq % 2 !== 0)
            return all;
        let end = heads.get(segStart);
        if (end === undefined) {
            GIT_HEAD.lastIndex = segStart + 1;
            end = GIT_HEAD.test(raw) ? GIT_HEAD.lastIndex : -1;
            heads.set(segStart, end);
        }
        if (end < 0 || end > offset)
            return all;
        return `${head}""`;
    });
}
function normText(raw) {
    let s = raw;
    s = s.replace(/[\u2010-\u2015\u2212]/g, '-').replace(/[\u2018-\u201b\u2032]/g, "'").replace(/[\u201c-\u201f\u2033]/g, '"');
    s = s.replace(/[\u00a0\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/g, ' ').replace(/[\u200b-\u200d\u2060\ufeff]/g, '');
    s = s.toLowerCase().replace(/[`^]/g, '').replace(/\\/g, '/');
    // String joints (`'C:\Users\x\.aws\' + 'credentials'`).
    s = s.replace(/(["'])\s*\+\s*(["'])/g, '');
    s = multiword(expandFolders(s));
    // The profile folder name may hold spaces: one word for matching.
    s = s.replace(/([a-z]:\/+users\/+)([^/;|&<>"'\n\r(){},=]+)(?=\/)/g, '$1__user__');
    return s;
}
/** A word with its variables as dynamic parts (`$x`, `${x}`, `$env:x`, `%x%`, `!x!`); known folders were expanded before. */
function dynWord(w) {
    return w.replace(/\$\{[^}]*\}|\$(?:[a-z_][a-z0-9_]*:)?[a-z_][a-z0-9_]*|\$_|%[a-z_][a-z0-9_()]*%|![a-z_][a-z0-9_]*!/g, DYN);
}
/** `-EncodedCommand` values (any accepted spelling) that decode to UTF-16LE text, from the text as written. */
function encodedTexts(raw) {
    const out = [];
    const re = /(?:^|[\s"'])[-/\u2013\u2014](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)(?:\s+|:)["']?([A-Za-z0-9+/=]{8,})/gi;
    for (const m of raw.matchAll(re)) {
        if (out.length >= 16)
            break;
        const buf = Buffer.from(m[1], 'base64');
        if (buf.length < 2 || buf.length % 2 !== 0)
            continue;
        const text = buf.toString('utf16le');
        if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(text))
            continue;
        out.push(text);
    }
    return out;
}
// ---------------------------------------------------------------------------------------------
// unusual path spellings (owner route "hold all odd paths", 22 Oct 2026)
//
// On win32 a path written in an unusual way is HELD for the owner (Sx.windows_odd_path), whatever it points at. Nothing here
// resolves a path or asks where a form leads: the spelling alone is the reason. The forms: 8.3 short names (a `NAME~N` part),
// the `\\?\` and `\\.\` prefixes and the NT `\??\` prefix, UNC paths, three or more leading separators, a mix of `/` and `\` at the
// start of a path, an alternate data stream (`name:stream`, `::$DATA`), and a path that starts like one and cannot be taken apart
// (longer than any path, a control character, a look-alike of a separator). Plain paths, URLs, host:port, `git@host:repo`, git
// revisions (`HEAD~1`, `HEAD:src/a.ts`) and `a:/b` pairs (container volumes, PATH lists) are not held. The check only adds a hit,
// so it can never turn a stop into a pass, and it runs from the same win32-only entry as the rest.
//
// A stream on a bare name (no separator) is read from the words around it, since a bare word alone says little (`app.main:app`,
// `localhost:3000`, `echo a:b` are not paths): the typed spellings (`a.txt::$DATA`, `a.txt:s:$DATA`, `:Zone.Identifier`) in any
// word; any colon in a word that a file program or a redirect names as a path (`type fxfile:s`, `echo x > fxfile:s`,
// `Set-Content fxfile:s x`), except a PowerShell drive or variable scope (`Env:PATH`, `$env:TEMP`) or a DOS device (`nul:`); and, in any other word, a colon after
// a file-like name with a stream name behind it (`node a.txt:s`), except host:port and file:line:col.
const SEP = '[\\\\/]';
const ODD_DEVICE = new RegExp(`^${SEP}{2}[?.]${SEP}|^${SEP}\\?\\?${SEP}`);
const ODD_UNC = new RegExp(`^${SEP}{2}[^\\\\/\\s?.][^\\\\/]*${SEP}[^\\\\/]`);
const ODD_LEADING = new RegExp(`^${SEP}{3,}[^\\\\/]`);
const URL_SCHEME = /^[a-z][a-z0-9+.-]+:\/\//i;
const SCP_LIKE = /^[^\\/:\s@]+@[^\\/:\s]+:/;
const HOST_PORT = /^[a-z0-9.-]+:\d{1,5}(?:[\\/]|$)/i;
const STREAM_TYPE = /:\$(?:data|index_allocation|bitmap|attribute_list|ea|reparse_point)\b|:zone\.identifier\b/i;
const SHORT_PART = /^[^\s~\\/:*?"<>|]{1,8}~\d{1,7}(?:\.[^\s~\\/:*?"<>|.]{0,3})?$/;
const SEP_LOOKALIKE = /[\uff0f\uff3c\u2215\u2216\u29f5\u29f8\u2044]/;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f]/;
const PS_DRIVE = /^(?:\$(?:env|global|script|local|private|using):[^:]*$|(?:env|variable|function|alias|cert|wsman|hklm|hkcu|temp|certificate):|(?:registry|variable|alias|function|environment|certificate|wsman)::|(?:nul|con|prn|aux|com\d|lpt\d):$)/i;
const STREAM_TYPED = /:[^:\s]*:\$(?:data|index_allocation|bitmap|attribute_list|ea|reparse_point)\b|:zone\.identifier\b/i;
const LINE_COL = /^[^\s:\\/]+:\d{1,5}(?::\d{1,5})?$/;
const FILE_LIKE = /\.(?:txt|log|json|jsonc|ini|cfg|conf|config|env|yml|yaml|toml|xml|md|csv|tsv|dat|bak|tmp|db|sqlite|kdbx|pem|key|crt|cer|pfx|p12|pub|ps1|psm1|bat|cmd|vbs|exe|dll|lnk|zip|7z|tar|gz|pdf|docx?|xlsx?|html?|css)$|^\.[\w-]+$/i;
// Programs whose every operand is a path, and cmdlets whose first operand is the path.
const PATH_OPERANDS = new Set(['dir', 'ls', 'gci', 'get-childitem', 'cd', 'chdir', 'set-location', 'sl', 'pushd', 'push-location', 'type', 'cat', 'gc',
    'get-content', 'more', 'copy', 'cp', 'copy-item', 'cpi', 'move', 'mv', 'move-item', 'mi', 'del', 'erase', 'rd', 'rmdir', 'rm', 'ri', 'remove-item',
    'ren', 'rename', 'rni', 'rename-item', 'get-item', 'gi', 'test-path', 'notepad', 'mkdir', 'md', 'tree', 'xcopy', 'attrib', 'tee', 'tee-object', 'sort', 'fc',
    'comp', 'get-filehash', 'get-acl', 'set-acl', 'import-csv', 'export-csv', 'resolve-path', 'invoke-item', 'ii', 'get-itemproperty', 'gp']);
const PATH_FIRST_OPERAND = new Set(['set-content', 'sc', 'add-content', 'ac', 'out-file', 'new-item', 'ni', 'clear-content', 'clc']);
// For those cmdlets the path is the first positional word or the value of a path-naming parameter, wherever it stands. PowerShell takes
// any unique prefix of a parameter name, so every prefix counts; a prefix that fits a path name is read as one (fail closed). The value
// of a data parameter (`-Value x`, `-Encoding utf8`) is no path and must not use up the first-operand slot.
const PATH_PARAMS = ['path', 'literalpath', 'pspath', 'filepath', 'name', 'destination', 'lp'];
const DATA_PARAMS = ['value', 'encoding', 'itemtype', 'type', 'delimiter', 'inputobject', 'width', 'filter', 'include', 'exclude', 'credential', 'readcount', 'totalcount', 'tail', 'head'];
function paramOf(w) {
    const m = /^-([a-z]+)(:?)/.exec(w);
    if (!m)
        return null;
    const n = m[1];
    const path = PATH_PARAMS.some((p) => p.startsWith(n));
    return { path, data: !path && DATA_PARAMS.some((p) => p.startsWith(n)), attached: m[2] === ':' };
}
// ls with sort flags (`ls -St`, `ls -Str`) is no PowerShell -Stream: ls is Get-ChildItem there, which has no such parameter.
const LS_SORT = /^-Str?$/;
// Programs that open a file or folder by the name given, for a bare `NAME~N` word (no separator): a short name there.
const FILE_PROGRAMS = new Set(['dir', 'ls', 'gci', 'get-childitem', 'cd', 'chdir', 'set-location', 'sl', 'pushd', 'push-location', 'type', 'cat', 'gc',
    'get-content', 'more', 'copy', 'cp', 'copy-item', 'cpi', 'move', 'mv', 'move-item', 'mi', 'del', 'erase', 'rd', 'rmdir', 'rm', 'ri', 'remove-item',
    'xcopy', 'robocopy', 'mkdir', 'md', 'ren', 'rename', 'rni', 'rename-item', 'tree', 'attrib', 'icacls', 'takeown', 'get-item', 'gi', 'test-path',
    'start', 'invoke-item', 'ii', 'explorer', 'notepad']);
function baseName(w) {
    return w.slice(Math.max(w.lastIndexOf('/'), w.lastIndexOf('\\')) + 1).toLowerCase().replace(/\.(?:exe|cmd|bat|com|ps1)$/, '');
}
/**
 * One word (or, for a file tool, one whole path) read for an unusual spelling. `path`: the value is a path by definition (a file
 * tool's argument); otherwise it must look like one. `git`: a git command is earlier in the line, so `name~N` and `rev:path`
 * are revisions. `fileProgram`: a program that opens files by name is earlier in the line, so a bare `NAME~N` is a short name.
 * `operand`: a file program or a redirect names this word as a path, so a colon in a bare word is a stream.
 */
// A `file:` URL whose path is a drive (`file:///C:/x`, `file:/C:/x`, `file:C:/x`, `file:///C%3A/x`, `file:///C|/x`; the shell text is cut at
// the `|`, which leaves `file:///C`) or a UNC share
// (`file://srv/share/x`, `file:////srv/share/x`). `file://localhost/C:/x` is a drive path; a `file:` URL with a plain rooted path is not held.
const FILE_URL = /^file:([\\/]*)([\s\S]*)$/i;
const DRIVE_START = /^[a-z](?::|\||%3a|%7c|$)/i;
function fileUrlOdd(t) {
    const m = FILE_URL.exec(t);
    if (!m)
        return false;
    const seps = m[1].length;
    const rest = m[2];
    if (seps >= 4)
        return true;
    if (seps === 2) {
        const host = /^[^\\/]*/.exec(rest)[0];
        if (host !== '' && host.toLowerCase() !== 'localhost')
            return true;
        return DRIVE_START.test(rest.slice(host.length).replace(/^[\\/]+/, ''));
    }
    return DRIVE_START.test(rest);
}
// PowerShell's `-Stream` (and its shortest unambiguous forms `-St`, `-Str`, `-Stre`, `-Strea`), with a value after a space or a colon:
// it reaches an alternate data stream without any odd spelling in the path. `-S` alone is far too common (`git status -s`) to hold.
const STREAM_PARAM = /^-st(?:r(?:e(?:a(?:m)?)?)?)?(?::|$)/i;
function bareStream(t, git, operand) {
    const colon = t.indexOf(':');
    if (colon < 0)
        return false;
    if (STREAM_TYPED.test(t))
        return true;
    if (git || PS_DRIVE.test(t))
        return false;
    if (operand)
        return colon > 0;
    return t.length > colon + 1 && t[colon + 1] !== ':' && FILE_LIKE.test(t.slice(0, colon)) && !HOST_PORT.test(t) && !LINE_COL.test(t);
}
function oddPathWord(raw, path, git, fileProgram, operand = false) {
    const t = raw.replace(/^[-/][a-z][\w-]*:/i, '');
    if (t === '')
        return false;
    if (oddPathCore(t, path, git, fileProgram, operand))
        return true;
    for (const rest of behindPrefix(t))
        if (oddPathCore(rest, path, git, fileProgram, operand))
            return true;
    return false;
}
// What a word may carry in front of a path without being a different kind of word: a PowerShell provider (`FileSystem::`,
// `Microsoft.PowerShell.Core\FileSystem::`), a response file mark (`@list`), one attached option letter (`-o\\srv\x`, `/o\\srv\x`), and
// the string prefix of interpreter code (`r'..'`, `b'..'`, `f'..'`; the quote itself is already gone from the word). The word
// after the prefix is read like a word of its own, once per prefix.
const PROVIDER_PREFIX = /^(?:[\w.-]+\\)?[a-z][\w.-]*::/i;
const STRING_PREFIX = /^(?:rb|br|fr|rf|[rbfu])(?=[\\/]{2})/i;
function behindPrefix(t) {
    const out = [];
    const provider = PROVIDER_PREFIX.exec(t);
    if (provider)
        out.push(t.slice(provider[0].length));
    if (t[0] === '@')
        out.push(t.slice(1));
    if (/^[-/][a-z]./i.test(t))
        out.push(t.slice(2));
    const prefix = STRING_PREFIX.exec(t);
    if (prefix)
        out.push(t.slice(prefix[0].length));
    return out.filter((rest) => rest !== '');
}
function oddPathCore(t, path, git, fileProgram, operand) {
    if (fileUrlOdd(t))
        return true;
    if (URL_SCHEME.test(t) || SCP_LIKE.test(t))
        return path;
    const drive = /^[a-z]:/i.test(t);
    const rooted = drive || /^[\\/]|^\.{1,2}[\\/]/.test(t);
    const hasSep = /[\\/]/.test(t);
    if (!path && !rooted && !hasSep)
        return (fileProgram && !git && SHORT_PART.test(t)) || bareStream(t, git, operand);
    // A path that starts like one and cannot be taken apart.
    if ((path || rooted) && (t.length > tables_1.LIMITS.maxPathChars || CONTROL.test(t) || SEP_LOOKALIKE.test(t)))
        return true;
    if (ODD_DEVICE.test(t) || ODD_UNC.test(t) || ODD_LEADING.test(t))
        return true;
    // The first two separators of a path that starts at a drive, a root or a dot differ in kind: `C:/fx\a`, `C:\/x`, `./a\b`.
    if (rooted) {
        const first = t.search(/[\\/]/);
        const second = first < 0 ? -1 : t.slice(first + 1).search(/[\\/]/);
        if (second >= 0 && t[first] !== t[first + 1 + second])
            return true;
    }
    // An alternate data stream: a stream type anywhere; a colon after the drive letter's own in a path that starts like one; or a
    // colon in the last part of any other path when a dot comes before it (`a.txt:s`). A colon followed by a separator makes a pair
    // of paths (`a:/b`, `HKLM:\x`), `host:80` is a port, and a git revision is `rev:path`.
    const body = drive ? t.slice(2) : t;
    if (body.includes(':') && STREAM_TYPE.test(body))
        return true;
    if (body.includes(':') && !/:[\\/]/.test(body) && !HOST_PORT.test(body) && !(git && !drive)) {
        const last = body.split(/[\\/]/).pop() || '';
        const colon = last.indexOf(':');
        if (path || rooted ? true : colon > 0 && last.slice(0, colon).includes('.'))
            return true;
    }
    // 8.3 short names: any part between separators. A git revision (`origin/main~1`) is no path.
    if (t.includes('~') && !(git && !t.includes('\\') && !drive)) {
        for (const part of t.split(/[\\/]/))
            if (part.includes('~') && SHORT_PART.test(part))
                return true;
    }
    return false;
}
/** Shell text (or interpreter code) with its words read for an unusual spelling; the separators of the text are kept as written. */
function oddPathText(raw, st) {
    const s = raw.replace(/[\u2010-\u2015\u2212]/g, '-').replace(/[\u2018-\u201b\u2032]/g, "'").replace(/[\u201c-\u201f\u2033]/g, '"')
        .replace(/[\u00a0\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/g, ' ').replace(/[\u200b-\u200d\u2060\ufeff]/g, '').replace(/[`^]/g, '')
        .replace(/(["'])\s*\+\s*(["'])/g, '')
        // `${x}` and `${env:x}` are the variables `$x` and `$env:x` here: the braces would cut the word, and `${x}:s` is held like `$x:s`.
        // Only a plain name: `${x:-a.txt}` (a default) stays as it was.
        .replace(/\$\{((?:env:)?\w{1,128})\}/gi, '$$$1');
    for (const seg of segments(s)) {
        if (!tick(st))
            return false;
        let git = false;
        let fileProgram = false;
        let operands = false;
        let first = false;
        let pathCmd = false;
        let pathNext = false;
        let dataNext = false;
        const ls = baseName(seg.words[0] || '') === 'ls';
        for (let k = 0; k < seg.words.length; k += 1) {
            const word = seg.words[k];
            const redirect = seg.redirect.has(k) || seg.input.has(k);
            // The word after `<<` or `<<<` is text (a here-string) or a delimiter, not a file, unless a redirect names it (`cat <<< > x`).
            const here = seg.here.has(k) && !redirect;
            if (STREAM_PARAM.test(word) && !(ls && k > 0 && LS_SORT.test(word)))
                return true;
            let operand = redirect || operands;
            if (pathCmd && !redirect && !here) {
                const param = paramOf(word.toLowerCase());
                if (param && (param.path || param.data)) {
                    if (param.attached)
                        operand = operand || param.path;
                    else if (param.path)
                        pathNext = true;
                    else
                        dataNext = true;
                }
                else if (!isOption(word.toLowerCase())) {
                    if (dataNext)
                        dataNext = false;
                    else if (first || pathNext) {
                        operand = true;
                        first = false;
                        pathNext = false;
                    }
                }
            }
            if (oddPathWord(word, false, git, fileProgram, operand && !here))
                return true;
            const name = baseName(word);
            if (name === 'git')
                git = true;
            else if (FILE_PROGRAMS.has(name))
                fileProgram = true;
            if (PATH_OPERANDS.has(name))
                operands = true;
            else if (PATH_FIRST_OPERAND.has(name)) {
                first = true;
                pathCmd = true;
            }
        }
    }
    return false;
}
function addHit(st, category, reason) {
    if (!st.hits.some((h) => h.category === category && h.reason === reason))
        st.hits.push({ category, reason });
}
function tick(st) {
    if (st.over)
        return false;
    st.work += 1;
    if (Date.now() >= st.deadline) {
        st.over = true;
        addHit(st, 'Sx', 'budget_time');
        return false;
    }
    if (st.work > tables_1.LIMITS.maxToolNodes) {
        st.over = true;
        addHit(st, 'Sx', 'budget_work');
        return false;
    }
    return true;
}
const INTERESTING = /[/~*?.\u0001]|^[a-z]:/;
// The mapper's S0/S4 tripwire, on text the lexical reading cannot follow.
const TRIPWIRE_REASON = {
    tripwire_secret_path: exports.WINDOWS_REASONS.secretPath, tripwire_env_file: exports.WINDOWS_REASONS.secretPath, tripwire_secret_dumper: exports.WINDOWS_REASONS.envDump,
    tripwire_self_protection: exports.WINDOWS_REASONS.protectedPath, tripwire_plugin_protection: exports.WINDOWS_REASONS.protectedPath,
};
/** The name a bare `*` stands for when its folder is known: one part that no protected or shim pattern lists. */
const BARE_STAR_NAME = '\u0002';
/**
 * The folder whose files a path names when its last part is exactly `*` or `*.*` (cmd's "every file", the same set) and every part
 * before it is a plain name (no wildcard, no variable, no 8.3 short name); null for any other path. The folder may be empty (`*`
 * alone: the working folder, not known).
 */
function bareStarFolder(c) {
    const last = c[c.length - 1];
    if (last !== '*' && last !== '*.*')
        return null;
    const folder = view(c.slice(0, -1));
    return folder.hasFuzzy ? null : folder;
}
/** One shell text, or interpreter code (`code`: no program or reader is trusted). `depth` bounds decoded text. */
function scanText(raw, st, depth, code) {
    if (depth > 4 || st.over || typeof raw !== 'string' || raw.trim() === '')
        return;
    const head = raw.length > tables_1.LIMITS.maxCommandBytes ? raw.slice(0, tables_1.LIMITS.maxCommandBytes) : raw;
    const s = normText(code ? head : stripGitMessages(head));
    verbHits(s, (c, r) => addHit(st, c, r));
    if (oddPathText(code ? head : stripGitMessages(head), st))
        addHit(st, 'Sx', exports.WINDOWS_REASONS.oddPath);
    if (code || DYNAMIC_TEXT.test(s)) {
        const flat = s.replace(/["']/g, '');
        for (const t of tables_1.TRIPWIRE) {
            if ((t.category === 'S0' || t.category === 'S4') && t.re.test(flat)) {
                addHit(st, t.category, TRIPWIRE_REASON[t.reason] || (t.category === 'S0' ? exports.WINDOWS_REASONS.protectedPath : exports.WINDOWS_REASONS.secretPath));
            }
        }
    }
    const dotnetWrite = DOTNET_WRITE.test(s);
    for (const seg of segments(s)) {
        if (st.over)
            return;
        const { prog, at, sub, launchers } = code ? { prog: '', at: -1, sub: null, launchers: [] } : programOf(seg);
        // cmd `set` with no value lists variables (`set`, `set AWS`); PowerShell `Get-Variable` lists them.
        if (prog === 'set' && !seg.hasEq && (seg.words.length === at + 1 || (seg.words.length === at + 2 && /^[a-z_][a-z0-9_]*$/.test(seg.words[at + 1]))))
            addHit(st, 'S4', exports.WINDOWS_REASONS.envDump);
        if ((prog === 'get-variable' || prog === 'gv') && (seg.words.length === at + 1 || seg.words.slice(at + 1).some((x) => /[*?]/.test(x))))
            addHit(st, 'S4', exports.WINDOWS_REASONS.envDump);
        const reader = prog === 'git' ? sub !== null && GIT_READ_SUBS.has(sub) : READERS.has(prog);
        const s4Exempt = prog === 'git' ? sub !== null && GIT_S4_EXEMPT_SUBS.has(sub) : S4_EXEMPT.has(prog);
        const writer = WRITERS.has(prog) || (dotnetWrite && !reader);
        let firstOperand = -1;
        for (let k = 0; k < seg.words.length; k += 1) {
            if (!tick(st))
                return;
            const w = seg.words[k];
            if (isOption(w))
                continue;
            const isProg = k === at;
            if (!isProg && k > at && firstOperand < 0)
                firstOperand = k;
            const p = dynWord(w.replace(/^-[a-z][\w-]*:(?=.)/, ''));
            if (!INTERESTING.test(p) || !/[a-z0-9._~]/.test(p.split(DYN).join('')))
                continue;
            const c = comps(p);
            if (!c || !c.length)
                continue;
            const v = view(c);
            const redirect = seg.redirect.has(k);
            if (isSecret(v, st.parts) && !(s4Exempt && !redirect))
                addHit(st, 'S4', exports.WINDOWS_REASONS.secretPath);
            if (isProg)
                continue;
            // A last part of exactly `*` (or `*.*`) under a folder that is known (no wildcard, variable or 8.3 name in it) names the files IN that
            // folder, as POSIX expands it. It is read as one plain name that no protected pattern lists: a protected folder still holds
            // it, and the folder itself is checked as an anchor (a protected folder, the profile, a system tree, or a folder above one).
            // Any other wildcard keeps the reading that it may stand for any name.
            const folder = bareStarFolder(c);
            const kind = protectedKind(folder ? view([...folder.comps, BARE_STAR_NAME]) : v, st.parts);
            const script = INTERPRETERS.has(prog) && k === firstOperand;
            const started = START_LIKE.has(prog) && k === firstOperand;
            const readOnly = reader && !redirect;
            if (kind === 'op' && !readOnly && !script && !started)
                addHit(st, 'S0', exports.WINDOWS_REASONS.protectedPath);
            // A word that only starts the command (`cmd.exe` of `cmd.exe /c copy a b`) is no write target, no folder the command
            // removes and no file it creates: the write-only, ancestor and shim checks skip it. The secret check above and the
            // protected-place check just above still ran on it, and every word after it is read in full.
            if (launchers.includes(k))
                continue;
            if (kind === 'wo' && (redirect || writer))
                addHit(st, 'S0', exports.WINDOWS_REASONS.protectedPath);
            // The folder of a bare `*` is checked, not the wildcard word: it must be an anchor itself (the folder of a relative `*` alone,
            // `del *`, is not known).
            const above = folder ? isAnchorFolder(folder) : ancestorOfAnchor(v, 3);
            const aboveWrite = folder ? above : ancestorOfAnchor(v, 4);
            if (!readOnly && (DESTRUCTIVE.has(prog) || (dotnetWrite && prog === '')) && above)
                addHit(st, 'S0', exports.WINDOWS_REASONS.protectedPath);
            else if (!readOnly && (redirect || writer) && prog !== 'md' && prog !== 'mkdir' && aboveWrite)
                addHit(st, 'S0', exports.WINDOWS_REASONS.protectedPath);
            const literalShim = !v.fz[v.fz.length - 1];
            if (!folder && isShim(v) && !readOnly && !script && !started && (literalShim || redirect || writer))
                addHit(st, 'S0', exports.WINDOWS_REASONS.shim);
        }
    }
    for (const text of encodedTexts(head))
        scanText(text, st, depth + 1, false);
}
function toolPath(raw, st, mode, text = false) {
    if (!tick(st) || typeof raw !== 'string' || !raw)
        return;
    // An unusual spelling is held first and whole; the readings below only add to it. A value that is not a path field (a string
    // of an MCP call) is read word by word.
    if (text ? oddPathText(raw, st) : oddPathWord(raw, true, false, false))
        addHit(st, 'Sx', exports.WINDOWS_REASONS.oddPath);
    const c = comps(multiword(expandFolders(raw.toLowerCase().replace(/\\/g, '/'))));
    if (!c || !c.length)
        return;
    const v = view(c);
    // A write of a secret that is also a protected file (an 8.3 name may stand for either) gets both hits.
    if (isSecret(v, st.parts))
        addHit(st, 'S4', exports.WINDOWS_REASONS.secretPath);
    if (mode === 'read')
        return;
    // Phase A: no JSON-compare relaxation for hook configs on Windows; any write to a protected path stops.
    if (protectedKind(v, st.parts) !== null) {
        addHit(st, 'S0', exports.WINDOWS_REASONS.protectedPath);
        return;
    }
    if (mode === 'delete' && ancestorOfAnchor(v, 1)) {
        addHit(st, 'S0', exports.WINDOWS_REASONS.protectedPath);
        return;
    }
    if (isShim(v))
        addHit(st, 'S0', exports.WINDOWS_REASONS.shim);
}
const MCP_WRITE_VERBS = /write|edit|create|move|delete|remove|rename|put|update|append|save|mkdir|copy|patch|upload/;
// As mapper.ts mcpPathChecks: every string value of an MCP call (or the path fields of a tool the mapper
// does not recognise); a secret is S4, and a protected path is S0 when the tool's name says it writes.
function mcpPaths(label, input, st, allStrings) {
    const writes = MCP_WRITE_VERBS.test(label);
    const deletes = /delete|remove|move|rename/.test(label);
    const walked = st.parts.walkPathInputs(input, st.deadline, allStrings);
    const mode = deletes ? 'delete' : writes ? 'write' : 'read';
    for (const p of walked.paths)
        toolPath(p, st, mode);
    for (const p of walked.strings.filter((t) => t.length <= tables_1.LIMITS.maxPathChars && !/[\r\n]/.test(t)))
        toolPath(p, st, mode, !walked.paths.includes(p));
}
function tryJson(text) {
    try {
        return JSON.parse(text);
    }
    catch {
        return null;
    }
}
const URL_FIELD = /path|file|dir|src|dest|uri|target|source|^from$|^to$|include/i;
/**
 * The mapper takes `file://` off a path field before it is read here, which hides the drive or share behind it (`file:///C:/x` reads
 * as `/C:/x`, `file://srv/share/x` as `srv/share/x`). The field as written is read once more for a `file:` URL with a drive or a share.
 */
function fileUrlFields(input, st) {
    const check = (v) => {
        if (typeof v === 'string') {
            if (fileUrlOdd(v.trim()))
                addHit(st, 'Sx', exports.WINDOWS_REASONS.oddPath);
        }
        else if (Array.isArray(v))
            v.slice(0, 64).forEach(check);
    };
    for (const [key, value] of Object.entries(input))
        if (URL_FIELD.test(key))
            check(value);
    if (Array.isArray(input.edits))
        for (const e of input.edits.slice(0, 64))
            if (e && typeof e === 'object')
                check(e.file_path);
}
/** The extra hits for one event on win32 (the same tool reading as mapper.ts evaluateEvent). */
function windowsProtectedHits(event, env, parts, startedAt = Date.now()) {
    const st = {
        hits: [], work: 0, parts, over: false,
        deadline: startedAt + (typeof env.budgetMs === 'number' && env.budgetMs >= 0 ? env.budgetMs : tables_1.LIMITS.timeBudgetMs),
    };
    const tool = String((event && event.tool_name) || '');
    const name = tool.toLowerCase().replace(/^(?:functions\.\s*)+/, '');
    let rawInput = event && event.tool_input;
    let rawText = null;
    if (typeof rawInput === 'string') {
        // Over the size cap the mapper stops (budget_tool_input); the head is still read here.
        const body = rawInput.slice(0, tables_1.LIMITS.maxToolJsonChars).replace(/^\uFEFF/, '');
        const parsed = /^\s*[{[]/.test(body) ? tryJson(body) : null;
        if (parsed && typeof parsed === 'object')
            rawInput = parsed;
        else {
            rawText = body;
            const kv = /^\s*(?:command|cmd|script|shell_command|commandline)\s*[=:]\s*([\s\S]+)$/i.exec(body);
            if (kv)
                rawText = `${body}\n${kv[1]}`;
            rawInput = {};
        }
    }
    if (Array.isArray(rawInput))
        rawInput = { commands: rawInput.filter((v) => typeof v === 'string'), items: rawInput.filter((v) => v && typeof v === 'object') };
    const input = (rawInput && typeof rawInput === 'object' ? rawInput : {});
    const nativeShell = parts.tools.nativeShell.get(tool);
    if (nativeShell !== undefined)
        rawText = rawText === null ? nativeShell : `${rawText}\n${nativeShell}`;
    const mcp = tables_1.SHELL_TOOL_NAMES.has(name) ? null : parts.mcpCall(name, input);
    // A call whose arguments cannot be read: the mapper does not recognise it, and the hook gives master's answer.
    if (mcp && mcp.malformed)
        return st.hits;
    const evName = mcp ? mcp.name : name;
    const evInput = mcp ? mcp.args : input;
    const shellInput = !mcp && tool === 'Workflow' && typeof evInput.script === 'string'
        ? Object.fromEntries(Object.entries(evInput).filter(([key]) => key !== 'script')) : evInput;
    const invocation = parts.shellInvocations(evName, shellInput, st.deadline, rawText);
    if (invocation) {
        for (const text of invocation.shell) {
            if (st.over)
                break;
            scanText(text, st, 0, false);
        }
        for (const code of invocation.code) {
            if (st.over)
                break;
            scanText(code, st, 0, true);
        }
        if (mcp)
            mcpPaths(mcp.label, evInput, st, true);
        return st.hits;
    }
    const t = parts.tools;
    fileUrlFields(evInput, st);
    if (mcp)
        mcpPaths(mcp.label, evInput, st, true);
    else if (t.read.has(name) || t.grep.has(name)) {
        for (const p of parts.pathInputs(input))
            toolPath(p, st, 'read');
    }
    else if (t.write.has(name)) {
        const targets = name === 'apply_patch' ? parts.patchPaths(String(input.patch || input.input || input.content || '')) : parts.pathInputs(input);
        const viewOnly = (name === 'str_replace_editor' || name === 'str_replace_based_edit_tool') && String(input.command || '') === 'view';
        for (const p of targets)
            toolPath(p, st, viewOnly ? 'read' : 'write');
    }
    else if (t.delete.has(name)) {
        for (const p of parts.pathInputs(input))
            toolPath(p, st, 'delete');
    }
    else if (!t.list.has(name) && !t.inert.has(name) && !t.nonShell.has(name)) {
        mcpPaths(name, input, st, false);
    }
    return st.hits;
}
const ORDER = ['S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'Sx'];
/** The mapper's decision with the extra hits added. Hits are only added; a stop is never removed. */
function mergeWindowsHits(decision, extra) {
    const fresh = extra.filter((h) => !decision.hits.some((d) => d.category === h.category && d.reason === h.reason));
    if (!fresh.length)
        return decision;
    const hits = [...decision.hits, ...fresh].sort((a, b) => ORDER.indexOf(a.category) - ORDER.indexOf(b.category));
    const category = hits[0].category;
    const rule = decision.decision === 'stop' && decision.category === category ? decision.rule : `${category}.${hits[0].reason}`;
    return { ...decision, decision: 'stop', category, rule, reasons: hits.map((h) => h.reason), hits, outageHelpOnly: false };
}
/** The one entry point (mapper.ts evaluateSeatbelt): win32 only; any other platform gets the decision unchanged. */
function withWindowsProtected(decision, event, env, parts, startedAt) {
    if (env.platform !== 'win32')
        return decision;
    return mergeWindowsHits(decision, windowsProtectedHits(event, env, parts, startedAt));
}
//# sourceMappingURL=win-protected.js.map