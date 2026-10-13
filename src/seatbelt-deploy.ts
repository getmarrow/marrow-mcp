import type { SeatbeltFs } from './seatbelt-fs';
import { realPath } from './seatbelt-path';

// Deploy config readers for S2's environment resolver (spec §1.2). Each
// returns the environment-like names the config selects or defines; the
// mapper (U2) matches them against the production set. A config that exists
// but cannot be read or parsed is 'unknown', which the mapper treats as
// production for tools that default to production.

export const MAX_DEPLOY_CONFIG_BYTES = 256 * 1024;

export type DeployRead<T> = { status: 'absent' } | { status: 'unknown' } | ({ status: 'ok'; source: string } & T);

function readText(fs: SeatbeltFs, path: string): { status: 'absent' } | { status: 'unknown' } | { status: 'ok'; text: string; path: string } {
  const real = realPath(fs, path, { followFinal: true });
  if (real.status !== 'resolved') return { status: 'unknown' };
  if (!real.exists) return { status: 'absent' };
  try {
    const entry = fs.lstat(real.path);
    if (!entry) return { status: 'absent' };
    if (entry.type !== 'file' || entry.size > MAX_DEPLOY_CONFIG_BYTES) return { status: 'unknown' };
    const text = fs.readFile(real.path, MAX_DEPLOY_CONFIG_BYTES);
    return text === null ? { status: 'unknown' } : { status: 'ok', text, path: real.path };
  } catch {
    return { status: 'unknown' };
  }
}

/** JSON with comments and trailing commas (wrangler.jsonc, .firebaserc). Null when it does not parse. */
export function parseJsonc(text: string): unknown {
  let out = '';
  let inString = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (inString) {
      out += ch;
      if (ch === '\\') out += text[++i] ?? '';
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') {
      inString = true;
      out += ch;
    } else if (ch === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i += 1;
      out += '\n';
    } else if (ch === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      if (end < 0) return null;
      i = end + 1;
    } else out += ch;
  }
  try {
    return JSON.parse(out.replace(/,(\s*[}\]])/g, '$1'));
  } catch {
    return null;
  }
}

interface TomlDoc {
  /** section name ('' for top level) -> key -> raw string value */
  sections: Map<string, Map<string, string>>;
}

/** Minimal TOML: [section] / [[array]] headers and key = "string" | bare value. Null on a malformed header. */
export function parseSimpleToml(text: string): TomlDoc | null {
  const sections = new Map<string, Map<string, string>>([['', new Map()]]);
  let section = '';
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/^\s+/, '');
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('[')) {
      const header = /^\[\[?([^\]]+)\]\]?\s*(?:#.*)?$/.exec(line);
      if (!header) return null;
      section = header[1].trim().split('.').map((part) => part.trim().replace(/^"(.*)"$/, '$1')).join('.');
      if (!sections.has(section)) sections.set(section, new Map());
      continue;
    }
    const pair = /^("?[A-Za-z0-9_.-]+"?)\s*=\s*(.*)$/.exec(line);
    if (!pair) continue;
    let value = pair[2].trim();
    const quoted = /^"((?:[^"\\]|\\.)*)"|^'([^']*)'/.exec(value);
    if (quoted) value = quoted[1] ?? quoted[2];
    else value = value.replace(/\s+#.*$/, '');
    (sections.get(section) as Map<string, string>).set(pair[1].replace(/^"(.*)"$/, '$1'), value);
  }
  return { sections };
}

function dir(path: string, name: string): string {
  return `${path.replace(/\/+$/, '')}/${name}`;
}

/** The hook env merged with the deploy command's prefix assignments (they reach the tool's environment). */
export type DeployEnv = Record<string, string | undefined>;

/**
 * Env each tool reads that selects or relocates its deploy target. These are
 * not modelled: any of them present (even empty) makes the reader 'unknown',
 * which the mapper treats as production.
 */
export const DEPLOY_RELOCATING_ENV = {
  wrangler: ['CLOUDFLARE_ENV', 'WRANGLER_ENV', 'CLOUDFLARE_ACCOUNT_ID', 'CF_ACCOUNT_ID', 'WRANGLER_CONFIG'],
  vercel: ['VERCEL_PROJECT_ID', 'VERCEL_ORG_ID', 'VERCEL_ENV', 'VERCEL_SCOPE'],
  fly: ['FLY_APP', 'FLY_APP_NAME', 'FLY_CONFIG'],
  firebase: ['FIREBASE_PROJECT', 'GCLOUD_PROJECT', 'FIREBASE_CONFIG'],
  kube: ['KUBECONTEXT', 'KUBECTL_CONTEXT'],
  sam: ['SAM_CONFIG_ENV', 'AWS_PROFILE', 'AWS_DEFAULT_PROFILE', 'AWS_CONFIG_FILE'],
  sst: ['SST_STAGE', 'SST_CONFIG'],
  terraform: ['TF_DATA_DIR', 'TF_WORKSPACE', 'TF_CLI_ARGS', 'TF_CLI_ARGS_apply', 'TF_CLI_ARGS_destroy', 'TF_CLI_CONFIG_FILE'],
  gcloud: ['CLOUDSDK_CONFIG', 'CLOUDSDK_ACTIVE_CONFIG_NAME', 'CLOUDSDK_CORE_PROJECT', 'GOOGLE_CLOUD_PROJECT'],
} as const;

function relocated(env: DeployEnv | undefined, tool: keyof typeof DEPLOY_RELOCATING_ENV): boolean {
  return Boolean(env) && DEPLOY_RELOCATING_ENV[tool].some((name) => (env as DeployEnv)[name] !== undefined);
}

export interface WranglerTarget {
  /** null for the top level (production). */
  environment: string | null;
  /** The worker name this environment deploys (an env without `name` inherits `<top>-<env>`; null when there is no top-level name). */
  name: string | null;
  /** Every route/routes pattern and custom domain named in this environment. */
  routes: string[];
}

/**
 * wrangler.toml / wrangler.json / wrangler.jsonc: the named environments
 * ([env.<name>]) and, per environment, the worker name and routes it deploys
 * to (the top level is production). An environment whose name or a route
 * equals the top level's deploys to the production worker; the mapper must
 * compare `targets`, not only environment names.
 */
export function readWranglerConfig(fs: SeatbeltFs, projectDir: string, configPath?: string, env?: DeployEnv): DeployRead<{ environments: string[]; targets: WranglerTarget[] }> {
  if (relocated(env, 'wrangler')) return { status: 'unknown' };
  const candidates = configPath ? [configPath.startsWith('/') ? configPath : dir(projectDir, configPath)] : ['wrangler.json', 'wrangler.jsonc', 'wrangler.toml'].map((n) => dir(projectDir, n));
  for (const file of candidates) {
    const read = readText(fs, file);
    if (read.status === 'absent') continue;
    if (read.status === 'unknown') return read;
    if (file.endsWith('.toml')) {
      const doc = parseSimpleToml(read.text);
      if (!doc) return { status: 'unknown' };
      const environments = [...new Set([...doc.sections.keys()].filter((s) => s.startsWith('env.')).map((s) => s.split('.')[1]))];
      // Routes in arrays/inline tables are not parsed by the minimal TOML reader: any `route`/`routes`/`custom_domain`
      // value that is not a plain string makes the routes unknown.
      const tomlRoutes = (section: string): string[] | null => {
        const values = doc.sections.get(section);
        const out: string[] = [];
        for (const [key, value] of values || []) {
          if (key !== 'route' && key !== 'routes' && key !== 'pattern') continue;
          if (/^[[{]/.test(value)) return null;
          out.push(value);
        }
        for (const [name, values2] of doc.sections) {
          if (name === section || !name.startsWith(section ? `${section}.` : '')) continue;
          const rest = section ? name.slice(section.length + 1) : name;
          if (!/^(routes?|custom_domains?)$/.test(rest)) continue;
          for (const [key, value] of values2) if (key === 'pattern' || key === 'route') out.push(value);
        }
        return out;
      };
      const top = doc.sections.get('')?.get('name') ?? null;
      const targets: WranglerTarget[] = [];
      const topRoutes = tomlRoutes('');
      if (topRoutes === null) return { status: 'unknown' };
      targets.push({ environment: null, name: top, routes: topRoutes });
      for (const environment of environments) {
        const routes = tomlRoutes(`env.${environment}`);
        if (routes === null) return { status: 'unknown' };
        const own = doc.sections.get(`env.${environment}`)?.get('name');
        targets.push({ environment, name: own ?? (top ? `${top}-${environment}` : null), routes });
      }
      return { status: 'ok', source: read.path, environments, targets };
    }
    const json = parseJsonc(read.text);
    if (!json || typeof json !== 'object' || Array.isArray(json)) return { status: 'unknown' };
    const root = json as Record<string, unknown>;
    const jsonRoutes = (node: Record<string, unknown>): string[] | null => {
      const out: string[] = [];
      for (const key of ['route', 'routes']) {
        const value = node[key];
        if (value === undefined) continue;
        for (const item of Array.isArray(value) ? value : [value]) {
          if (typeof item === 'string') out.push(item);
          else if (item && typeof item === 'object' && typeof (item as Record<string, unknown>).pattern === 'string') out.push((item as Record<string, string>).pattern);
          else return null;
        }
      }
      return out;
    };
    const envs = root.env;
    if (envs !== undefined && (!envs || typeof envs !== 'object' || Array.isArray(envs))) return { status: 'unknown' };
    const top = typeof root.name === 'string' ? root.name : null;
    const topRoutes = jsonRoutes(root);
    if (topRoutes === null) return { status: 'unknown' };
    const targets: WranglerTarget[] = [{ environment: null, name: top, routes: topRoutes }];
    const environments = envs ? Object.keys(envs) : [];
    for (const environment of environments) {
      const node = (envs as Record<string, unknown>)[environment];
      if (!node || typeof node !== 'object' || Array.isArray(node)) return { status: 'unknown' };
      const routes = jsonRoutes(node as Record<string, unknown>);
      if (routes === null) return { status: 'unknown' };
      const own = (node as Record<string, unknown>).name;
      targets.push({ environment, name: typeof own === 'string' ? own : top ? `${top}-${environment}` : null, routes });
    }
    return { status: 'ok', source: read.path, environments, targets };
  }
  return { status: 'absent' };
}

/** .vercel/project.json links the dir to a project; `vercel --prod` needs no other config. */
export function readVercelLink(fs: SeatbeltFs, projectDir: string, env?: DeployEnv): DeployRead<{ linked: true }> {
  if (relocated(env, 'vercel')) return { status: 'unknown' };
  const read = readText(fs, dir(projectDir, '.vercel/project.json'));
  if (read.status !== 'ok') return read;
  const json = parseJsonc(read.text);
  return json && typeof json === 'object' ? { status: 'ok', source: read.path, linked: true } : { status: 'unknown' };
}

/** fly.toml: the app name(s). `fly deploy` always deploys that app's production machines. */
export function readFlyConfig(fs: SeatbeltFs, projectDir: string, configPath?: string, env?: DeployEnv): DeployRead<{ apps: string[] }> {
  if (relocated(env, 'fly')) return { status: 'unknown' };
  const read = readText(fs, configPath ? (configPath.startsWith('/') ? configPath : dir(projectDir, configPath)) : dir(projectDir, 'fly.toml'));
  if (read.status !== 'ok') return read;
  const doc = parseSimpleToml(read.text);
  if (!doc) return { status: 'unknown' };
  const app = doc.sections.get('')?.get('app');
  return { status: 'ok', source: read.path, apps: app ? [app] : [] };
}

/** .firebaserc: the default project and every alias -> project id. */
export function readFirebaseProjects(fs: SeatbeltFs, projectDir: string, env?: DeployEnv): DeployRead<{ defaultProjects: string[]; aliases: Record<string, string> }> {
  if (relocated(env, 'firebase')) return { status: 'unknown' };
  const read = readText(fs, dir(projectDir, '.firebaserc'));
  if (read.status !== 'ok') return read;
  const json = parseJsonc(read.text) as { projects?: unknown } | null;
  if (!json || typeof json !== 'object') return { status: 'unknown' };
  const projects = json.projects && typeof json.projects === 'object' ? json.projects as Record<string, unknown> : {};
  const aliases: Record<string, string> = {};
  for (const [alias, id] of Object.entries(projects)) if (typeof id === 'string') aliases[alias] = id;
  return { status: 'ok', source: read.path, defaultProjects: aliases.default ? [aliases.default] : [], aliases };
}

/**
 * kubectl current context(s) and their namespaces. KUBECONFIG (from the hook
 * env or the same command) is added to ~/.kube/config, never substituted for
 * it, so the env can only add candidates. A relative KUBECONFIG entry (it
 * depends on the command's cwd), a JSON kubeconfig, or a found config with
 * no current-context is 'unknown'.
 */
export function readKubeContexts(fs: SeatbeltFs, home: string | null, kubeconfigEnv?: string, env?: DeployEnv): DeployRead<{ contexts: Array<{ name: string; namespace: string | null }> }> {
  if (relocated(env, 'kube')) return { status: 'unknown' };
  const entries = String(kubeconfigEnv || '').split(':').filter(Boolean);
  if (entries.some((p) => !p.startsWith('/'))) return { status: 'unknown' };
  const files = [...(home ? [dir(home, '.kube/config')] : []), ...entries];
  const contexts: Array<{ name: string; namespace: string | null }> = [];
  let found = false;
  for (const file of [...new Set(files)]) {
    const read = readText(fs, file);
    if (read.status === 'absent') continue;
    if (read.status === 'unknown') return read;
    found = true;
    // kubeconfig may be JSON (YAML's superset); this reader parses block YAML only.
    if (/^\s*[{[]/.test(read.text)) return { status: 'unknown' };
    const current = /^current-context:\s*["']?([^"'\s#]*)["']?\s*(?:#.*)?$/m.exec(read.text);
    if (!current) {
      // kubectl merges files; a context set only in a flow/quoted form this reader misses is unknown.
      if (/current-context/.test(read.text)) return { status: 'unknown' };
      continue;
    }
    const name = current[1];
    if (!name) return { status: 'unknown' };
    // Find this context's namespace in the contexts: list (block YAML only).
    let namespace: string | null = null;
    const blocks = read.text.split(/\n(?=[ \t]*-[ \t\n])/);
    for (const block of blocks) {
      const blockName = /(?:^|\n)[ \t]*-?[ \t]*name:[ \t]*["']?([^"'\s#]+)/.exec(block);
      if (blockName && blockName[1] === name && /\bcontext:/.test(block)) {
        const ns = /\bnamespace:[ \t]*["']?([^"'\s#]+)/.exec(block);
        if (ns) namespace = ns[1];
      }
    }
    contexts.push({ name, namespace });
  }
  if (!found) return { status: 'absent' };
  if (contexts.length === 0) return { status: 'unknown' };
  return { status: 'ok', source: files.join(':'), contexts };
}

/** samconfig.toml: config environments and stack names. */
export function readSamConfig(fs: SeatbeltFs, projectDir: string, env?: DeployEnv): DeployRead<{ configEnvs: string[]; stacks: string[] }> {
  if (relocated(env, 'sam')) return { status: 'unknown' };
  const read = readText(fs, dir(projectDir, 'samconfig.toml'));
  if (read.status !== 'ok') return read;
  const doc = parseSimpleToml(read.text);
  if (!doc) return { status: 'unknown' };
  const configEnvs = new Set<string>();
  const stacks = new Set<string>();
  for (const [section, values] of doc.sections) {
    if (!section) continue;
    configEnvs.add(section.split('.')[0]);
    const stack = values.get('stack_name');
    if (stack) stacks.add(stack);
  }
  return { status: 'ok', source: read.path, configEnvs: [...configEnvs], stacks: [...stacks] };
}

/** SST's selected stage (.sst/stage). */
export function readSstStage(fs: SeatbeltFs, projectDir: string, env?: DeployEnv): DeployRead<{ stage: string }> {
  if (relocated(env, 'sst')) return { status: 'unknown' };
  const read = readText(fs, dir(projectDir, '.sst/stage'));
  if (read.status !== 'ok') return read;
  const stage = read.text.trim();
  return /^[A-Za-z0-9_-]{1,64}$/.test(stage) ? { status: 'ok', source: read.path, stage } : { status: 'unknown' };
}

/** Terraform's selected workspace (.terraform/environment); absent means `default`. TF_DATA_DIR / TF_WORKSPACE in env are 'unknown'. */
export function readTerraformWorkspace(fs: SeatbeltFs, projectDir: string, env?: DeployEnv): DeployRead<{ workspace: string }> {
  if (relocated(env, 'terraform')) return { status: 'unknown' };
  const read = readText(fs, dir(projectDir, '.terraform/environment'));
  if (read.status !== 'ok') return read;
  const workspace = read.text.trim();
  return /^[A-Za-z0-9_.-]{1,90}$/.test(workspace) ? { status: 'ok', source: read.path, workspace } : { status: 'unknown' };
}

/** gcloud's active configuration's [core] project. */
export function readGcloudProject(fs: SeatbeltFs, home: string | null, env?: DeployEnv): DeployRead<{ project: string }> {
  if (relocated(env, 'gcloud')) return { status: 'unknown' };
  if (!home) return { status: 'unknown' };
  const active = readText(fs, dir(home, '.config/gcloud/active_config'));
  if (active.status === 'unknown') return active;
  const name = active.status === 'ok' ? active.text.trim() : 'default';
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(name)) return { status: 'unknown' };
  const read = readText(fs, dir(home, `.config/gcloud/configurations/config_${name}`));
  if (read.status !== 'ok') return read;
  const doc = parseSimpleToml(read.text);
  const project = doc?.sections.get('core')?.get('project');
  return project ? { status: 'ok', source: read.path, project } : { status: 'unknown' };
}
