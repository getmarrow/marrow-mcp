import { userInfo } from 'node:os';
import { resolveMarrowEnv } from './env';
import { nodeSeatbeltFs, type SeatbeltFs } from './seatbelt-fs';
import { realPath } from './seatbelt-path';

// Seatbelt mode resolution (spec §1.1, §2.1 rule 5, abuse rows A15/A18).
//
// `seatbelt` is the only mode that is looser than 3.9.102's keyless blanket
// deny, so it is chosen only when every probe of every trusted home answers a
// clean "absent". Any account evidence, any probe that cannot be answered, a
// contradictory home, or a rejected key gives `claimed_no_key` (or `account`
// with a usable key). The ratchet is one-way: evidence only ever moves the
// answer away from `seatbelt`. The environment never selects the mode or the
// trusted home (passwd or the hook's --home value). It is read only to
// tighten: the key (which can only select `account`), MARROW_SEATBELT_STRICT,
// and the places 3.9.102 and the harnesses write evidence when relocated by
// env ($HOME, USERPROFILE, CODEX_HOME, CLAUDE_CONFIG_DIR, CLINE_DIR, the
// Gemini system settings path). Evidence there counts; an env home that is not
// the trusted home is a contradiction (`home_mismatch`); a key found there is
// never used.

export type SeatbeltMode = 'seatbelt' | 'account' | 'claimed_no_key';

export const ACCOUNT_EVIDENCE = [
  'env_file',
  'env_local_file',
  'device_binding',
  'claimed_marker',
  'host_approvals_state',
  'mcp_spool',
  'runner_holds_salt',
  'hook_claimed_marker',
  'marrow_dir',
  /** The home and every directory holding evidence: owned by this user and not group/world-writable. Never 'present'. */
  'evidence_dirs',
] as const;
export type AccountEvidence = typeof ACCOUNT_EVIDENCE[number];
export type EvidenceState = 'present' | 'absent' | 'unknown';

export type KeyState = 'none' | 'present' | 'rejected';

export interface SeatbeltModeInput {
  fs: SeatbeltFs;
  /** The home directory from passwd (getpwuid), never $HOME. */
  passwdHome: string | null;
  /** This hook process's argv: `--home <abs>` / `--home=<abs>` and the installer's `--claimed` marker. */
  argv: string[];
  /** Trusted key state: from the owner files or the hook's own environment; 'rejected' after a 401. */
  key: KeyState;
  uid?: number | null;
  /** MARROW_SEATBELT_STRICT=1: never seatbelt. */
  strict?: boolean;
  /**
   * Homes named only by the environment ($HOME, USERPROFILE): today's writers
   * (src/env.ts, host-approval-state, lifecycle-spool, grok hooks) put keys
   * and state there. Probed for evidence only; one that is not a trusted home
   * gives `home_mismatch`. Never used for keys or later reads.
   */
  envHomes?: string[];
  /** Extra hook config files from env relocation (CODEX_HOME, CLAUDE_CONFIG_DIR ...). Additive; a relative path is unknown. */
  extraHookConfigs?: string[];
  /** Extra hook script directories (CLINE_DIR ...). Additive; a relative path is unknown. */
  extraHookDirs?: string[];
}

export interface SeatbeltModeResolution {
  mode: SeatbeltMode;
  homes: string[];
  evidence: Record<AccountEvidence, EvidenceState>;
  /** Fixed reason codes, no paths or values. */
  reasons: string[];
}

/** Harness hook configs (user level) that carry the installer's `--claimed` marker after a claim. */
export const HOOK_CONFIG_FILES = [
  '.claude/settings.json',
  '.codex/hooks.json',
  '.cursor/hooks.json',
  '.gemini/settings.json',
  '.codeium/windsurf/hooks.json',
  '.grok/hooks/marrow.json',
  '.claude/settings.local.json',
  '.codex/config.toml',
];

/**
 * Hook script directories (Cline runs the executable scripts in its hooks
 * directory). Every regular file in them is scanned for the marker. U8 must
 * publish the exact paths it writes; any path it adds must be added here.
 */
export const HOOK_CONFIG_DIRS = ['Documents/Cline/Hooks', '.cline/hooks'];
const MAX_HOOK_DIR_ENTRIES = 64;

/** Directories under a home whose owner and mode are checked (others could delete evidence in them). */
const EVIDENCE_DIRS = ['.marrow/device', '.marrow/host-approvals', '.marrow/spool', '.marrow/runner-holds', '.claude', '.codex', '.cursor', '.gemini', '.codeium', '.codeium/windsurf', '.grok', '.grok/hooks', 'Documents', 'Documents/Cline', ...HOOK_CONFIG_DIRS, '.cline'];

const MAX_HOOK_CONFIG_BYTES = 1024 * 1024;
const CLAIMED_TOKEN = /(?:^|[\s"'\\])--claimed(?:$|[\s"'=\\])/;

/** Every `--home` value in the hook's argv (repeated flags are all kept: a mismatch is contradictory). */
export function homeFlags(argv: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--home') {
      out.push(argv[i + 1] ?? '');
      i += 1;
    } else if (arg.startsWith('--home=')) out.push(arg.slice('--home='.length));
  }
  return out;
}

function argvClaimed(argv: string[]): boolean {
  return argv.some((arg) => arg === '--claimed' || arg.startsWith('--claimed='));
}

function exists(fs: SeatbeltFs, path: string): EvidenceState {
  try {
    return fs.lstat(path) ? 'present' : 'absent';
  } catch {
    return 'unknown';
  }
}

function worst(a: EvidenceState, b: EvidenceState): EvidenceState {
  if (a === 'present' || b === 'present') return 'present';
  if (a === 'unknown' || b === 'unknown') return 'unknown';
  return 'absent';
}

function probeSpool(fs: SeatbeltFs, dir: string): EvidenceState {
  try {
    const entry = fs.lstat(dir);
    if (!entry) return 'absent';
    if (entry.type !== 'dir') return 'unknown';
    return fs.readdir(dir).some((name) => /^mcp-.*\.json$/i.test(name)) ? 'present' : 'absent';
  } catch {
    return 'unknown';
  }
}

function probeHookConfig(fs: SeatbeltFs, path: string, skipNonFiles = false): EvidenceState {
  try {
    const entry = fs.lstat(path);
    if (!entry) return 'absent';
    if (skipNonFiles && entry.type === 'dir') return 'absent';
    let target = path;
    if (entry.type === 'symlink') {
      const real = realPath(fs, path, { followFinal: true });
      if (real.status !== 'resolved' || !real.exists) return 'unknown';
      target = real.path;
    }
    const text = fs.readFile(target, MAX_HOOK_CONFIG_BYTES);
    if (text === null) return 'unknown';
    return CLAIMED_TOKEN.test(text) ? 'present' : 'absent';
  } catch {
    return 'unknown';
  }
}

function probeHookDir(fs: SeatbeltFs, dir: string): EvidenceState {
  try {
    const real = realPath(fs, dir, { followFinal: true });
    if (real.status !== 'resolved') return 'unknown';
    if (!real.exists) return 'absent';
    const entry = fs.lstat(real.path);
    if (!entry) return 'absent';
    if (entry.type !== 'dir') return 'unknown';
    const names = fs.readdir(real.path);
    if (names.length > MAX_HOOK_DIR_ENTRIES) return 'unknown';
    let state: EvidenceState = 'absent';
    for (const name of names) state = worst(state, probeHookConfig(fs, `${real.path}/${name}`, true));
    return state;
  } catch {
    return 'unknown';
  }
}

/** A directory that holds evidence: absent is fine; otherwise its real target must be a dir owned by uid, not group/world-writable. */
function probeTrustedDir(fs: SeatbeltFs, dir: string, uid: number | null): EvidenceState {
  try {
    const real = realPath(fs, dir, { followFinal: true });
    if (real.status !== 'resolved') return 'unknown';
    if (!real.exists) return 'absent';
    const entry = fs.lstat(real.path);
    if (!entry) return 'absent';
    if (entry.type !== 'dir') return 'unknown';
    if (uid !== null && entry.uid !== uid) return 'unknown';
    if ((entry.mode & 0o022) !== 0) return 'unknown';
    return 'absent';
  } catch {
    return 'unknown';
  }
}

// ~/.marrow itself: absent and a plain directory owned by this user are both
// fine (keyless installs keep control.json there). A symlink, a file, another
// owner, group/world write or an unreadable entry cannot be reasoned about, so it is unknown.
function probeMarrowDir(fs: SeatbeltFs, dir: string, uid: number | null): EvidenceState {
  try {
    const entry = fs.lstat(dir);
    if (!entry) return 'absent';
    if (entry.type !== 'dir') return 'unknown';
    if (uid !== null && entry.uid !== uid) return 'unknown';
    // Others could delete evidence from a group/world-writable directory.
    if ((entry.mode & 0o022) !== 0) return 'unknown';
    return 'absent';
  } catch {
    return 'unknown';
  }
}

function probeHome(fs: SeatbeltFs, home: string, uid: number | null): Record<AccountEvidence, EvidenceState> {
  const marrow = `${home}/.marrow`;
  let hooks: EvidenceState = 'absent';
  for (const file of HOOK_CONFIG_FILES) hooks = worst(hooks, probeHookConfig(fs, `${home}/${file}`));
  for (const dir of HOOK_CONFIG_DIRS) hooks = worst(hooks, probeHookDir(fs, `${home}/${dir}`));
  let dirs = probeTrustedDir(fs, home, uid);
  for (const dir of EVIDENCE_DIRS) dirs = worst(dirs, probeTrustedDir(fs, `${home}/${dir}`, uid));
  return {
    env_file: exists(fs, `${marrow}/env`),
    env_local_file: exists(fs, `${marrow}/env.local`),
    device_binding: exists(fs, `${marrow}/device/binding.json`),
    claimed_marker: exists(fs, `${marrow}/claimed`),
    // Spec: "has a protected_categories cache". Any state file counts: it is only
    // ever written after talking to a server, and counting more is stricter.
    host_approvals_state: exists(fs, `${marrow}/host-approvals/state.json`),
    mcp_spool: probeSpool(fs, `${marrow}/spool`),
    runner_holds_salt: exists(fs, `${marrow}/runner-holds/.salt`),
    hook_claimed_marker: hooks,
    marrow_dir: probeMarrowDir(fs, marrow, uid),
    evidence_dirs: dirs === 'present' ? 'unknown' : dirs,
  };
}

/** A usable home: absolute, no `.`/`..` parts, and an existing directory other than `/` after realpath. */
function trustedHome(fs: SeatbeltFs, value: string | null | undefined): string | null {
  if (typeof value !== 'string' || !value.startsWith('/') || value.split('/').some((part) => part === '..' || part === '.')) return null;
  const real = realPath(fs, value, { followFinal: true });
  // A service user's `/` home is shared with everything on the machine.
  if (real.status !== 'resolved' || !real.exists || real.path === '/') return null;
  try {
    return fs.lstat(real.path)?.type === 'dir' ? real.path : null;
  } catch {
    return null;
  }
}

export function resolveSeatbeltMode(input: SeatbeltModeInput): SeatbeltModeResolution {
  const reasons: string[] = [];
  const uid = input.uid === undefined ? null : input.uid;
  const evidence = Object.fromEntries(ACCOUNT_EVIDENCE.map((id) => [id, 'absent'])) as Record<AccountEvidence, EvidenceState>;
  if (argvClaimed(input.argv)) evidence.hook_claimed_marker = 'present';

  const flags = homeFlags(input.argv);
  const candidates = [...flags, ...(input.passwdHome === null ? [] : [input.passwdHome])];
  const homes: string[] = [];
  let homeProblem = false;
  if (input.passwdHome === null && flags.length === 0) {
    homeProblem = true;
    reasons.push('home_unknown');
  }
  for (const candidate of candidates) {
    const home = trustedHome(input.fs, candidate);
    if (home === null) {
      homeProblem = true;
      reasons.push('home_unusable');
      continue;
    }
    if (!homes.includes(home)) homes.push(home);
  }
  if (homes.length > 1) {
    homeProblem = true;
    reasons.push('home_mismatch');
  }
  // Env homes ($HOME ...) only tighten: probed for evidence, and one that is
  // not a trusted home is a contradiction. They never join `homes`.
  const probeHomes = [...homes];
  for (const value of input.envHomes || []) {
    const home = trustedHome(input.fs, value);
    if (home === null) {
      homeProblem = true;
      if (!reasons.includes('env_home_unusable')) reasons.push('env_home_unusable');
      continue;
    }
    if (!homes.includes(home)) {
      homeProblem = true;
      if (!reasons.includes('home_mismatch')) reasons.push('home_mismatch');
    }
    if (!probeHomes.includes(home)) probeHomes.push(home);
  }
  // Every home named anywhere is probed: evidence in any of them counts.
  for (const home of probeHomes) {
    const probed = probeHome(input.fs, home, uid);
    for (const id of ACCOUNT_EVIDENCE) evidence[id] = worst(evidence[id], probed[id]);
  }
  for (const file of input.extraHookConfigs || []) {
    evidence.hook_claimed_marker = worst(evidence.hook_claimed_marker, file.startsWith('/') ? probeHookConfig(input.fs, file) : 'unknown');
  }
  for (const dir of input.extraHookDirs || []) {
    evidence.hook_claimed_marker = worst(evidence.hook_claimed_marker, dir.startsWith('/') ? probeHookDir(input.fs, dir) : 'unknown');
  }

  const present = ACCOUNT_EVIDENCE.filter((id) => evidence[id] === 'present');
  const unknown = ACCOUNT_EVIDENCE.filter((id) => evidence[id] === 'unknown');
  if (present.length > 0) reasons.push('account_evidence');
  if (unknown.length > 0) reasons.push('evidence_unknown');

  let mode: SeatbeltMode;
  if (input.key === 'present') mode = 'account';
  else if (input.key === 'rejected') {
    mode = 'claimed_no_key';
    reasons.push('key_rejected');
  } else if (homeProblem || present.length > 0 || unknown.length > 0) mode = 'claimed_no_key';
  else if (input.strict) {
    mode = 'claimed_no_key';
    reasons.push('strict');
  } else mode = 'seatbelt';
  return { mode, homes, evidence, reasons };
}

/** The only environment names mode resolution reads: the key lookup's names, the strict switch and the tighten-only evidence relocations. */
const KEY_ENV_NAMES = ['MARROW_API_KEY', 'MARROW_KEY', 'MARROW_BASE_URL', 'MARROW_SESSION_ID'];
/** Env homes 3.9.102 writes under (src/env.ts: HOME, then USERPROFILE). */
const ENV_HOME_NAMES = ['HOME', 'USERPROFILE'];
/** Env-relocated harness config: name -> files (or, for dirs, '' meaning the dir itself is scanned). */
const ENV_HOOK_FILES: Record<string, string[]> = {
  CODEX_HOME: ['hooks.json', 'config.toml'],
  CLAUDE_CONFIG_DIR: ['settings.json', 'settings.local.json'],
  GEMINI_CLI_SYSTEM_SETTINGS_PATH: [''],
};
const ENV_HOOK_DIRS: Record<string, string> = { CLINE_DIR: 'hooks' };
export const MODE_ENV_NAMES = [...KEY_ENV_NAMES, 'MARROW_SEATBELT_STRICT', ...ENV_HOME_NAMES, ...Object.keys(ENV_HOOK_FILES), ...Object.keys(ENV_HOOK_DIRS)];

function passwdHomeDirectory(): string | null {
  try {
    const home = userInfo().homedir;
    return typeof home === 'string' && home ? home : null;
  } catch {
    return null;
  }
}

/**
 * Host wiring for the hook (U5 calls this). The key comes only from the hook's
 * environment or the owner files in a trusted home (never repo .env files);
 * keyRejected is set after the server answers 401.
 */
export function resolveSeatbeltModeOnHost(options: {
  argv?: string[];
  env?: NodeJS.ProcessEnv;
  fs?: SeatbeltFs;
  passwdHome?: string | null;
  uid?: number | null;
  keyRejected?: boolean;
} = {}): SeatbeltModeResolution {
  const env = options.env || process.env;
  const fs = options.fs || nodeSeatbeltFs();
  const argv = options.argv || process.argv.slice(2);
  const passwdHome = options.passwdHome === undefined ? passwdHomeDirectory() : options.passwdHome;
  const uid = options.uid === undefined ? (typeof process.getuid === 'function' ? process.getuid() : null) : options.uid;
  // Only MODE_ENV_NAMES are read. None of them can select seatbelt or the
  // trusted home: the env homes and relocated configs only add evidence.
  const keyEnv: NodeJS.ProcessEnv = {};
  for (const name of KEY_ENV_NAMES) {
    const value = env[name];
    if (typeof value === 'string') keyEnv[name] = value;
  }
  const strict = env.MARROW_SEATBELT_STRICT === '1';
  const homes = [...homeFlags(argv), ...(passwdHome ? [passwdHome] : [])];
  let key: KeyState = 'none';
  if (keyEnv.MARROW_API_KEY || keyEnv.MARROW_KEY) key = 'present';
  for (const home of homes) {
    if (key === 'present') break;
    const real = trustedHome(fs, home);
    if (!real) continue;
    if (resolveMarrowEnv({ env: keyEnv, home: real, trustedOnly: true }).apiKey) key = 'present';
  }
  if (key === 'present' && options.keyRejected) key = 'rejected';
  const envHomes: string[] = [];
  for (const name of ENV_HOME_NAMES) {
    const value = env[name];
    // 3.9.102 uses `env.HOME || ...`: an empty value falls through to the next.
    if (typeof value === 'string' && value !== '') envHomes.push(value);
  }
  const extraHookConfigs: string[] = [];
  for (const [name, files] of Object.entries(ENV_HOOK_FILES)) {
    const value = env[name];
    if (typeof value !== 'string' || value.trim() === '') continue;
    for (const file of files) extraHookConfigs.push(file ? `${value.replace(/\/+$/, '')}/${file}` : value);
  }
  const extraHookDirs: string[] = [];
  for (const [name, sub] of Object.entries(ENV_HOOK_DIRS)) {
    const value = env[name];
    if (typeof value === 'string' && value.trim() !== '') extraHookDirs.push(`${value.replace(/\/+$/, '')}/${sub}`);
  }
  return resolveSeatbeltMode({ fs, passwdHome, argv, key, uid, strict, envHomes, extraHookConfigs, extraHookDirs });
}
