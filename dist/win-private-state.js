"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.WIN_ACL_ENCODED = exports.WIN_ACL_SCRIPT = exports.WIN_PROOF_CACHE_MS = exports.WIN_PROOF_MAX_BUFFER = exports.WIN_PROOF_TIMEOUT_MS = exports.WIN_BIRTH_TOLERANCE_MS = void 0;
exports.realWindowsDeps = realWindowsDeps;
exports.validWindowsPath = validWindowsPath;
exports.parseSecurityDescriptor = parseSecurityDescriptor;
exports.evaluateDescriptor = evaluateDescriptor;
exports.proveWindowsPrivate = proveWindowsPrivate;
exports.ensureWindowsPrivateState = ensureWindowsPrivateState;
exports.verifyWindowsPrivateState = verifyWindowsPrivateState;
// Windows private-state proof for the local loop guard (3.9.106 spec, parts A1 and A2).
//
// POSIX proves "private" with uid and mode bits. Node reports 0o666 for everything on Windows, so
// the proof here uses the real Windows facts instead: a strict path grammar, no reparse point
// anywhere in the chain, the canonical long path, and the owner plus DACL read as raw SIDs and
// masks from the binary security descriptor that Windows PowerShell `Get-Acl` returns, parsed here
// with a closed grammar. The ACL query runs before the state lock is taken, never while it is held.
//
// Fail closed: every error, timeout, parse doubt or unknown value is a refusal with a fixed reason
// code. A reason never carries a path or a value. Nothing here reads HOME, the PATH, or any Marrow
// key, and no secret is passed to the child process. All OS access goes through `WinDeps`.
const node_crypto_1 = require("node:crypto");
const node_fs_1 = require("node:fs");
/** A state file born this long before the proof began still counts as created after it (file-system clock granularity). */
exports.WIN_BIRTH_TOLERANCE_MS = 250;
// Sized from real cold-start data (a first PowerShell start on a slow runner); on expiry the proof still denies.
exports.WIN_PROOF_TIMEOUT_MS = 5000;
exports.WIN_PROOF_MAX_BUFFER = 65536;
exports.WIN_PROOF_CACHE_MS = 2000;
const MAX_DESCRIPTOR_BYTES = 12 * 1024;
const MAX_DESCRIPTOR_LINE = 16 * 1024;
const processCache = new Map();
class WinRefusal extends Error {
    reason;
    constructor(reason) {
        super(reason);
        this.reason = reason;
    }
}
function refuse(reason) { throw new WinRefusal(reason); }
/** Production dependencies: Node's own fs, child_process and crypto. There is no env switch. */
function realWindowsDeps() {
    return {
        platform: process.platform,
        env: process.env,
        lstatBig: (path) => (0, node_fs_1.lstatSync)(path, { bigint: true }),
        realpathNative: (path) => node_fs_1.realpathSync.native(path),
        spawnSync: (file, args, options) => require('node:child_process').spawnSync(file, args, options),
        randomHex: (bytes) => (0, node_crypto_1.randomBytes)(bytes).toString('hex'),
        now: () => Date.now(),
        mkdir: (path) => { (0, node_fs_1.mkdirSync)(path); },
        cache: processCache,
    };
}
// ---- path grammar ------------------------------------------------------------------------
const DEVICE_NAME = /^(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(?:COM|LPT)[0-9\u00b9\u00b2\u00b3])$/i;
/** True only for `X:\a\b` with no alias, device, stream, UNC, relative or forward-slash form. */
function validWindowsPath(value) {
    if (typeof value !== 'string' || value.length < 4 || value.length > 240)
        return false;
    if (!/^[A-Za-z]:\\/.test(value) || value.includes('/') || value.endsWith('\\'))
        return false;
    for (let index = 0; index < value.length; index += 1)
        if (value.charCodeAt(index) < 0x20)
            return false;
    if (/[<>"|?*]/.test(value))
        return false;
    const rest = value.slice(3);
    if (rest.includes(':'))
        return false;
    for (const part of rest.split('\\')) {
        if (part === '' || part === '.' || part === '..' || part.endsWith('.') || part.endsWith(' '))
            return false;
        if (DEVICE_NAME.test(part.split('.')[0].replace(/ +$/, '')))
            return false;
    }
    return true;
}
function componentCount(path) { return path.slice(3).split('\\').length; }
function sameOrUnder(child, parent) {
    const c = child.toLowerCase();
    const p = parent.toLowerCase();
    return c === p || c.startsWith(`${p}\\`);
}
/**
 * Every prefix must be a plain folder (file at the end) and must resolve to itself. lstat alone is not
 * enough on Windows: Node reports only some reparse points as links (a junction whose target is a
 * volume GUID, or a volume mount point, looks like an ordinary folder). So each prefix also has to
 * canonicalise to exactly one more component under the previous prefix's canonical path, with the
 * same name (a different name is allowed only for an 8.3 short name, which contains `~`), on one volume.
 */
function chain(path, final, deps) {
    if (!validWindowsPath(path))
        refuse('path');
    const parts = path.slice(3).split('\\');
    let current = path.slice(0, 2);
    let parentReal = current.toLowerCase();
    const out = [];
    for (let index = 0; index < parts.length; index += 1) {
        current = `${current}\\${parts[index]}`;
        let stat;
        try {
            stat = deps.lstatBig(current);
        }
        catch {
            return refuse('chain');
        }
        if (stat.isSymbolicLink())
            refuse('chain');
        if (out.length > 0 && stat.dev !== out[0].stat.dev)
            refuse('chain');
        let real;
        try {
            real = deps.realpathNative(current);
        }
        catch {
            return refuse('canonical');
        }
        if (!validWindowsPath(real) || real.startsWith('\\\\'))
            return refuse('canonical');
        const lowerReal = real.toLowerCase();
        const name = real.slice(real.lastIndexOf('\\') + 1).toLowerCase();
        if (!lowerReal.startsWith(`${parentReal}\\`) || componentCount(real) !== index + 1
            || (name !== parts[index].toLowerCase() && !/~\d+(?:\.[^.]*)?$/.test(parts[index]) && !(index === 1 && parts[index].toLowerCase() === 'system32' && name === 'syswow64')))
            return refuse('canonical');
        parentReal = lowerReal;
        if (final === 'file' && index === parts.length - 1 ? !stat.isFile() : !stat.isDirectory())
            refuse('chain');
        out.push({ path: current, stat });
    }
    return out;
}
function canonicalOf(lexical, deps) {
    let real;
    try {
        real = deps.realpathNative(lexical);
    }
    catch {
        return refuse('canonical');
    }
    if (!validWindowsPath(real) || real.startsWith('\\\\') || componentCount(real) !== componentCount(lexical))
        return refuse('canonical');
    return real;
}
// ---- the security descriptor: closed binary grammar ----------------------------------------------
//
// PowerShell returns `GetSecurityDescriptorBinaryForm()` as base64. Binary keeps SIDs and masks raw:
// no SDDL alias table, no locale, no domain-relative alias (`LA`, `DU`, ...). Anything the grammar
// does not know is a refusal.
const CONTROL_ALLOWED = 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0100 | 0x0200 | 0x0400 | 0x0800 | 0x1000 | 0x2000 | 0x4000 | 0x8000;
const CONTROL_DACL_PRESENT = 0x0004;
const CONTROL_SELF_RELATIVE = 0x8000;
const ACE_ALLOWED = 0;
const ACE_DENIED = 1;
const ACE_FLAGS_ALLOWED = 0x1F; // object, container, no-propagate, inherit-only, inherited
const ACE_INHERIT_ONLY = 0x08;
// write/add-file, append/add-subdir, write-EA, delete-child, write-attributes, DELETE, WRITE_DAC,
// WRITE_OWNER, ACCESS_SYSTEM_SECURITY, MAXIMUM_ALLOWED, GENERIC_ALL, GENERIC_WRITE
const WRITE_CLASS = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x1000000 | 0x2000000 | 0x10000000 | 0x40000000;
const CREATOR_OWNER = 'S-1-3-0';
const CREATOR_GROUP = 'S-1-3-1';
function sidAt(buffer, offset) {
    if (offset < 0 || offset + 8 > buffer.length || buffer[offset] !== 1)
        return null;
    const count = buffer[offset + 1];
    if (count < 1 || count > 15)
        return null;
    const length = 8 + 4 * count;
    if (offset + length > buffer.length)
        return null;
    const authority = buffer.readUIntBE(offset + 2, 6);
    const parts = [authority > 0xFFFFFFFF ? `0x${authority.toString(16)}` : String(authority)];
    for (let index = 0; index < count; index += 1)
        parts.push(String(buffer.readUInt32LE(offset + 8 + 4 * index)));
    return { sid: `S-1-${parts.join('-')}`, length };
}
/** Self-relative SECURITY_DESCRIPTOR to its owner SID and allow/deny ACEs; null for anything outside the grammar. */
function parseSecurityDescriptor(buffer) {
    if (buffer.length < 20 || buffer.length > MAX_DESCRIPTOR_BYTES || buffer[0] !== 1 || buffer[1] !== 0)
        return null;
    const control = buffer.readUInt16LE(2);
    if ((control & CONTROL_SELF_RELATIVE) === 0 || (control & CONTROL_DACL_PRESENT) === 0 || (control & ~CONTROL_ALLOWED) !== 0)
        return null;
    const ownerOffset = buffer.readUInt32LE(4);
    const groupOffset = buffer.readUInt32LE(8);
    const saclOffset = buffer.readUInt32LE(12);
    const daclOffset = buffer.readUInt32LE(16);
    // The SACL is never read (it grants nothing), but a flag and an offset that disagree are refused.
    const saclPresent = (control & 0x0010) !== 0;
    if ((!saclPresent && saclOffset !== 0) || (saclPresent && saclOffset !== 0 && (saclOffset < 20 || saclOffset >= buffer.length)))
        return null;
    // An owner is required, and a present but null DACL (offset 0) is refused: that grants everyone everything.
    if (ownerOffset < 20 || daclOffset < 20)
        return null;
    const owner = sidAt(buffer, ownerOffset);
    if (!owner)
        return null;
    const regions = [[ownerOffset, ownerOffset + owner.length]];
    // The primary group grants nothing: syntax only, never evaluated.
    if (groupOffset !== 0) {
        const group = groupOffset < 20 ? null : sidAt(buffer, groupOffset);
        if (!group)
            return null;
        regions.push([groupOffset, groupOffset + group.length]);
    }
    if (daclOffset + 8 > buffer.length)
        return null;
    const revision = buffer[daclOffset];
    const aclSize = buffer.readUInt16LE(daclOffset + 2);
    const count = buffer.readUInt16LE(daclOffset + 4);
    if ((revision !== 2 && revision !== 4) || aclSize < 8 || daclOffset + aclSize > buffer.length || count > 1024)
        return null;
    const aclEnd = daclOffset + aclSize;
    const aces = [];
    let at = daclOffset + 8;
    for (let index = 0; index < count; index += 1) {
        if (at + 16 > aclEnd)
            return null;
        const type = buffer[at];
        const flags = buffer[at + 1];
        const size = buffer.readUInt16LE(at + 2);
        if ((type !== ACE_ALLOWED && type !== ACE_DENIED) || (flags & ~ACE_FLAGS_ALLOWED) !== 0 || size < 16 || at + size > aclEnd)
            return null;
        const sid = sidAt(buffer, at + 8);
        if (!sid || 8 + sid.length !== size)
            return null;
        aces.push({ type, flags, mask: buffer.readUInt32LE(at + 4), sid: sid.sid });
        at += size;
    }
    if (at !== aclEnd)
        return null;
    regions.push([daclOffset, aclEnd]);
    // The parts of one descriptor never overlap, and without a SACL (Get-Acl does not read one) the
    // descriptor ends where its last part ends.
    regions.sort((a, b) => a[0] - b[0]);
    for (let index = 1; index < regions.length; index += 1)
        if (regions[index][0] < regions[index - 1][1])
            return null;
    if (!saclPresent && regions[regions.length - 1][1] !== buffer.length)
        return null;
    return { owner: owner.sid, aces };
}
/**
 * Judges one object's descriptor (base64) against `policy`. null: private enough. Otherwise a reason.
 * The owner must be trusted; a deny ACE can only remove access and is skipped; every allow ACE for
 * someone else is judged by its raw mask.
 */
function evaluateDescriptor(encoded, trusted, policy) {
    if (typeof encoded !== 'string' || encoded.length === 0 || encoded.length > MAX_DESCRIPTOR_LINE || encoded.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(encoded))
        return 'descriptor';
    const parsed = parseSecurityDescriptor(Buffer.from(encoded, 'base64'));
    if (!parsed)
        return 'descriptor';
    if (!trusted.has(parsed.owner))
        return 'owner';
    for (const ace of parsed.aces) {
        if (ace.type === ACE_DENIED || trusted.has(ace.sid))
            continue;
        if (ace.sid === CREATOR_OWNER && (ace.flags & ACE_INHERIT_ONLY) !== 0)
            continue;
        if (ace.sid === CREATOR_GROUP)
            return 'acl';
        if (policy === 'no_write_by_others' ? (ace.mask & WRITE_CLASS) !== 0 : ace.mask !== 0)
            return 'acl';
    }
    return null;
}
// ---- the Get-Acl spawn ------------------------------------------------------------------------------
// A source constant: no path or value is ever interpolated into it. It is passed as -EncodedCommand
// (base64 of UTF-16LE), so there is no quoting, no standard-input session and no profile. Every ACL
// line is written by the same expression that calls Get-Acl, so a failed Get-Acl can never leave an
// earlier object's value to be printed for a later one. One catch turns any error into exit 3.
// Paths come from MARROW_WINACL_P<i> environment items. The user's SID comes from the process token.
const SCRIPT = [
    "$ErrorActionPreference='Stop'",
    "$ProgressPreference='SilentlyContinue'",
    'try{',
    "$nonce=[Environment]::GetEnvironmentVariable('MARROW_WINACL_NONCE')",
    "[Console]::Out.WriteLine('BEGIN '+$nonce)",
    "[Console]::Out.WriteLine('SID '+[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)",
    "$n=[int][Environment]::GetEnvironmentVariable('MARROW_WINACL_N')",
    "for($i=1;$i -le $n;$i++){[Console]::Out.WriteLine('ACL '+$i+' '+[Convert]::ToBase64String((Microsoft.PowerShell.Security\\Get-Acl -LiteralPath ([Environment]::GetEnvironmentVariable('MARROW_WINACL_P'+$i))).GetSecurityDescriptorBinaryForm()))}",
    "[Console]::Out.WriteLine('END '+$nonce)",
    'exit 0',
    '}catch{exit 3}',
    '',
].join('\n');
exports.WIN_ACL_SCRIPT = SCRIPT;
exports.WIN_ACL_ENCODED = Buffer.from(SCRIPT, 'utf16le').toString('base64');
const POWERSHELL_ARGS = ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', exports.WIN_ACL_ENCODED];
function parseOutput(stdout, nonce, count) {
    if (typeof stdout !== 'string' || stdout.length > exports.WIN_PROOF_MAX_BUFFER)
        return refuse('output');
    const lines = stdout.split(/\r?\n/);
    if (lines.length > 0 && lines[lines.length - 1] === '')
        lines.pop();
    if (lines.length !== count + 3)
        return refuse('output');
    if (lines[0] !== `BEGIN ${nonce}` || lines[lines.length - 1] !== `END ${nonce}`)
        return refuse('output');
    const sidLine = /^SID (S-1-\d{1,3}(?:-\d{1,10}){1,14})$/.exec(lines[1]);
    if (!sidLine)
        return refuse('output');
    const descriptors = [];
    for (let index = 1; index <= count; index += 1) {
        const prefix = `ACL ${index} `;
        const line = lines[index + 1];
        if (!line.startsWith(prefix))
            return refuse('output');
        const descriptor = line.slice(prefix.length);
        if (descriptor.length === 0 || descriptor.length > MAX_DESCRIPTOR_LINE)
            return refuse('output');
        descriptors.push(descriptor);
    }
    return { sid: sidLine[1], descriptors };
}
function systemRoot(env, canonicalHome) {
    const root = env.SystemRoot;
    if (typeof root !== 'string' || !/^[A-Za-z]:\\[A-Za-z0-9_.-]{1,64}$/.test(root) || !validWindowsPath(root))
        return refuse('sysroot');
    const windir = env.windir;
    if (windir !== undefined && windir.toLowerCase() !== root.toLowerCase())
        return refuse('sysroot');
    if (sameOrUnder(root, canonicalHome))
        return refuse('sysroot');
    return root;
}
/** Folder identity: (dev, ino, birthtime) of every directory in the chains. ctime is not used: NTFS bumps it on every entry created inside. */
function identityOf(stats) {
    return [...stats.entries()].filter(([, stat]) => stat.isDirectory()).sort(([a], [b]) => (a < b ? -1 : 1))
        .map(([path, stat]) => `${path}|${stat.dev}|${stat.ino}|${stat.birthtimeNs}`).join('\n');
}
// ---- the whole proof ----------------------------------------------------------------------------------
function prove(request, deps) {
    if (deps.platform !== 'win32')
        refuse('platform');
    if (request.objects.length === 0 || request.objects.length > 8)
        refuse('internal');
    const startedAt = deps.now();
    const homeChain = chain(request.home, 'dir', deps);
    const home = canonicalOf(request.home, deps);
    const canonical = {};
    const stats = new Map();
    const fileKeys = {};
    for (const entry of homeChain)
        stats.set(entry.path.toLowerCase(), entry.stat);
    const paths = [];
    for (const object of request.objects) {
        const lexical = `${home}\\${object.rel}`;
        const links = chain(lexical, object.kind, deps);
        const real = canonicalOf(lexical, deps);
        if (!sameOrUnder(real, home) || canonical[object.rel] !== undefined)
            refuse('canonical');
        // A state file must not be a hard link.
        if (object.kind === 'file') {
            const last = links[links.length - 1].stat;
            if (last.nlink !== 1n)
                refuse('chain');
            fileKeys[object.rel] = `${last.dev}:${last.ino}`;
        }
        for (const entry of links)
            stats.set(entry.path.toLowerCase(), entry.stat);
        canonical[object.rel] = real;
        paths.push(real);
    }
    const root = systemRoot(deps.env, home);
    const exe = `${root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
    chain(exe, 'file', deps);
    const realExe = canonicalOf(exe, deps);
    if (sameOrUnder(realExe, home))
        refuse('powershell');
    const key = JSON.stringify([root, request.objects.map((object, index) => [object.rel, object.kind, object.policy, paths[index]])]);
    const identity = identityOf(stats);
    // A state file that was replaced is a different object: it is part of what a cached answer covers.
    const signature = `${identity}\n${Object.entries(fileKeys).map(([rel, id]) => `${rel}=${id}`).join('\n')}`;
    const cache = deps.cache;
    const cached = cache?.get(key);
    if (cached && cached.signature === signature && deps.now() - cached.at <= exports.WIN_PROOF_CACHE_MS && deps.now() - cached.at >= 0) {
        return { home, canonical, identity, provedAtMs: cached.at, fileKeys };
    }
    cache?.delete(key);
    let temp = `${root}\\Temp`;
    try {
        const candidate = `${home}\\AppData\\Local\\Temp`;
        chain(candidate, 'dir', deps);
        temp = canonicalOf(candidate, deps);
    }
    catch { /* fall back to the Windows temp folder */ }
    const nonce = deps.randomHex(16);
    if (!/^[0-9a-f]{32}$/.test(nonce))
        refuse('internal');
    const env = {
        SystemRoot: root,
        windir: root,
        PSModulePath: `${root}\\System32\\WindowsPowerShell\\v1.0\\Modules`,
        TEMP: temp,
        TMP: temp,
        MARROW_WINACL_NONCE: nonce,
        MARROW_WINACL_N: String(paths.length),
    };
    paths.forEach((path, index) => { env[`MARROW_WINACL_P${index + 1}`] = path; });
    let result;
    try {
        result = deps.spawnSync(realExe, POWERSHELL_ARGS, {
            stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8', windowsHide: true, shell: false,
            timeout: exports.WIN_PROOF_TIMEOUT_MS, maxBuffer: exports.WIN_PROOF_MAX_BUFFER, cwd: `${root}\\System32`, env,
        });
    }
    catch {
        return refuse('spawn');
    }
    if (result && result.error && result.error.code === 'ETIMEDOUT')
        return refuse('timeout');
    if (!result || result.error || result.signal || result.status !== 0)
        return refuse('spawn');
    const parsed = parseOutput(result.stdout, nonce, paths.length);
    const trusted = new Set([parsed.sid, 'S-1-5-18', 'S-1-5-32-544']);
    request.objects.forEach((object, index) => {
        const verdict = evaluateDescriptor(parsed.descriptors[index], trusted, object.policy);
        if (verdict !== null)
            refuse(verdict);
    });
    cache?.set(key, { at: startedAt, signature });
    return { home, canonical, identity, provedAtMs: startedAt, fileKeys };
}
/** The proof. Never throws; every failure is `{ ok: false, reason }`. */
function proveWindowsPrivate(request, deps) {
    try {
        const proven = prove(request, deps);
        return { ok: true, home: proven.home, canonical: proven.canonical, identity: proven.identity, provedAtMs: proven.provedAtMs, fileKeys: proven.fileKeys };
    }
    catch (error) {
        return { ok: false, reason: error instanceof WinRefusal ? error.reason : 'internal' };
    }
}
// ---- create the two directories, then prove them -------------------------------------------------------
const STATE_DIRECTORY = 'session-loop-guard';
const STATE_FILE = 'state.json';
function presentNoFollow(path, deps) {
    try {
        deps.lstatBig(path);
        return true;
    }
    catch (error) {
        if (error?.code === 'ENOENT')
            return false;
        return refuse('chain');
    }
}
function makeDirectory(path, deps) {
    if (!presentNoFollow(path, deps)) {
        try {
            deps.mkdir(path);
        }
        catch (error) {
            if (error?.code !== 'EEXIST')
                refuse('mkdir');
        }
    }
    chain(path, 'dir', deps);
    // The parent is already canonical, so the child must resolve to exactly the path we built.
    const real = canonicalOf(path, deps);
    if (real.toLowerCase() !== path.toLowerCase())
        refuse('canonical');
    return real;
}
/**
 * `~/.marrow` and `~/.marrow/session-loop-guard` are created when absent (they inherit the profile
 * DACL), checked for reparse points and canonicalised after each creation, and then proven private
 * together with `state.json` when it exists. `home` is the caller's `os.homedir()`; HOME is never read.
 * This spawns PowerShell: call it BEFORE taking the state lock, never while holding it.
 */
function ensureWindowsPrivateState(home, deps) {
    try {
        if (deps.platform !== 'win32')
            refuse('platform');
        if (!validWindowsPath(home))
            refuse('path');
        const startedAt = deps.now();
        chain(home, 'dir', deps);
        const canonicalHome = canonicalOf(home, deps);
        const marrow = makeDirectory(`${canonicalHome}\\.marrow`, deps);
        const directory = makeDirectory(`${marrow}\\${STATE_DIRECTORY}`, deps);
        const target = `${directory}\\${STATE_FILE}`;
        const stateProven = presentNoFollow(target, deps);
        const objects = [
            { rel: '.marrow', kind: 'dir', policy: 'no_write_by_others' },
            { rel: `.marrow\\${STATE_DIRECTORY}`, kind: 'dir', policy: 'no_access_by_others' },
        ];
        if (stateProven)
            objects.push({ rel: `.marrow\\${STATE_DIRECTORY}\\${STATE_FILE}`, kind: 'file', policy: 'no_access_by_others' });
        const proof = proveWindowsPrivate({ home: canonicalHome, objects }, deps);
        if (!proof.ok)
            return proof;
        const stateKey = stateProven ? proof.fileKeys[`.marrow\\${STATE_DIRECTORY}\\${STATE_FILE}`] ?? null : null;
        // Born after this moment means created inside the proven folder, which gave it the proven DACL.
        const provedAtMs = Math.min(startedAt, proof.provedAtMs);
        return { ok: true, marrow: proof.canonical['.marrow'], directory: proof.canonical[`.marrow\\${STATE_DIRECTORY}`], target, stateProven, identity: proof.identity, provedAtMs, stateKey };
    }
    catch (error) {
        return { ok: false, reason: error instanceof WinRefusal ? error.reason : 'internal' };
    }
}
/**
 * Called while the state lock is held: the cheap structural half only (path grammar, no reparse
 * point, canonical path, hard-link count) plus the folder identity of the earlier proof. It never
 * spawns anything. A state file that appeared or was replaced after the proof is accepted if it is a
 * plain single-link file in an unchanged, already proven folder: only a trusted principal can create
 * entries there. A changed folder identity is a refusal, with no retry.
 */
function verifyWindowsPrivateState(home, proof, deps) {
    try {
        if (deps.platform !== 'win32' || !validWindowsPath(home))
            return false;
        const stats = new Map();
        const note = (entries) => { for (const entry of entries)
            stats.set(entry.path.toLowerCase(), entry.stat); };
        chain(home, 'dir', deps);
        const canonicalHome = canonicalOf(home, deps);
        note(chain(canonicalHome, 'dir', deps));
        for (const [expected, kind] of [[proof.marrow, 'dir'], [proof.directory, 'dir']]) {
            note(chain(expected, kind, deps));
            if (canonicalOf(expected, deps).toLowerCase() !== expected.toLowerCase() || !sameOrUnder(expected, canonicalHome))
                return false;
        }
        if (presentNoFollow(proof.target, deps)) {
            const entries = chain(proof.target, 'file', deps);
            const file = entries[entries.length - 1].stat;
            if (file.nlink !== 1n || canonicalOf(proof.target, deps).toLowerCase() !== proof.target.toLowerCase())
                return false;
            // The file the proof covered is fine. Any other state file (new, or renamed over by a writer) is accepted
            // only if it was BORN after the proof began: a file created inside the proven folder inherited its
            // DACL, while one moved in from elsewhere keeps its old DACL and an older birth time.
            const covered = proof.stateKey !== null && proof.stateKey === `${file.dev}:${file.ino}`;
            if (!covered && file.birthtimeNs < BigInt(Math.max(0, proof.provedAtMs - exports.WIN_BIRTH_TOLERANCE_MS)) * 1000000n)
                return false;
        }
        return identityOf(stats) === proof.identity;
    }
    catch {
        return false;
    }
}
//# sourceMappingURL=win-private-state.js.map