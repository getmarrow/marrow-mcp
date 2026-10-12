"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MAX_DEPLOY_CONFIG_BYTES = void 0;
exports.parseJsonc = parseJsonc;
exports.parseSimpleToml = parseSimpleToml;
exports.readWranglerConfig = readWranglerConfig;
exports.readVercelLink = readVercelLink;
exports.readFlyConfig = readFlyConfig;
exports.readFirebaseProjects = readFirebaseProjects;
exports.readKubeContexts = readKubeContexts;
exports.readSamConfig = readSamConfig;
exports.readSstStage = readSstStage;
exports.readTerraformWorkspace = readTerraformWorkspace;
exports.readGcloudProject = readGcloudProject;
const seatbelt_path_1 = require("./seatbelt-path");
// Deploy config readers for S2's environment resolver (spec §1.2). Each
// returns the environment-like names the config selects or defines; the
// mapper (U2) matches them against the production set. A config that exists
// but cannot be read or parsed is 'unknown', which the mapper treats as
// production for tools that default to production.
exports.MAX_DEPLOY_CONFIG_BYTES = 256 * 1024;
function readText(fs, path) {
    const real = (0, seatbelt_path_1.realPath)(fs, path, { followFinal: true });
    if (real.status !== 'resolved')
        return { status: 'unknown' };
    if (!real.exists)
        return { status: 'absent' };
    try {
        const entry = fs.lstat(real.path);
        if (!entry)
            return { status: 'absent' };
        if (entry.type !== 'file' || entry.size > exports.MAX_DEPLOY_CONFIG_BYTES)
            return { status: 'unknown' };
        const text = fs.readFile(real.path, exports.MAX_DEPLOY_CONFIG_BYTES);
        return text === null ? { status: 'unknown' } : { status: 'ok', text, path: real.path };
    }
    catch {
        return { status: 'unknown' };
    }
}
/** JSON with comments and trailing commas (wrangler.jsonc, .firebaserc). Null when it does not parse. */
function parseJsonc(text) {
    let out = '';
    let inString = false;
    for (let i = 0; i < text.length; i += 1) {
        const ch = text[i];
        if (inString) {
            out += ch;
            if (ch === '\\')
                out += text[++i] ?? '';
            else if (ch === '"')
                inString = false;
            continue;
        }
        if (ch === '"') {
            inString = true;
            out += ch;
        }
        else if (ch === '/' && text[i + 1] === '/') {
            while (i < text.length && text[i] !== '\n')
                i += 1;
            out += '\n';
        }
        else if (ch === '/' && text[i + 1] === '*') {
            const end = text.indexOf('*/', i + 2);
            if (end < 0)
                return null;
            i = end + 1;
        }
        else
            out += ch;
    }
    try {
        return JSON.parse(out.replace(/,(\s*[}\]])/g, '$1'));
    }
    catch {
        return null;
    }
}
/** Minimal TOML: [section] / [[array]] headers and key = "string" | bare value. Null on a malformed header. */
function parseSimpleToml(text) {
    const sections = new Map([['', new Map()]]);
    let section = '';
    for (const raw of text.split(/\r?\n/)) {
        const line = raw.replace(/^\s+/, '');
        if (!line || line.startsWith('#'))
            continue;
        if (line.startsWith('[')) {
            const header = /^\[\[?([^\]]+)\]\]?\s*(?:#.*)?$/.exec(line);
            if (!header)
                return null;
            section = header[1].trim().split('.').map((part) => part.trim().replace(/^"(.*)"$/, '$1')).join('.');
            if (!sections.has(section))
                sections.set(section, new Map());
            continue;
        }
        const pair = /^("?[A-Za-z0-9_.-]+"?)\s*=\s*(.*)$/.exec(line);
        if (!pair)
            continue;
        let value = pair[2].trim();
        const quoted = /^"((?:[^"\\]|\\.)*)"|^'([^']*)'/.exec(value);
        if (quoted)
            value = quoted[1] ?? quoted[2];
        else
            value = value.replace(/\s+#.*$/, '');
        sections.get(section).set(pair[1].replace(/^"(.*)"$/, '$1'), value);
    }
    return { sections };
}
function dir(path, name) {
    return `${path.replace(/\/+$/, '')}/${name}`;
}
/** wrangler.toml / wrangler.json / wrangler.jsonc: the named environments ([env.<name>]); top level is production. */
function readWranglerConfig(fs, projectDir, configPath) {
    const candidates = configPath ? [configPath.startsWith('/') ? configPath : dir(projectDir, configPath)] : ['wrangler.json', 'wrangler.jsonc', 'wrangler.toml'].map((n) => dir(projectDir, n));
    for (const file of candidates) {
        const read = readText(fs, file);
        if (read.status === 'absent')
            continue;
        if (read.status === 'unknown')
            return read;
        if (file.endsWith('.toml')) {
            const doc = parseSimpleToml(read.text);
            if (!doc)
                return { status: 'unknown' };
            const environments = [...new Set([...doc.sections.keys()].filter((s) => s.startsWith('env.')).map((s) => s.split('.')[1]))];
            return { status: 'ok', source: read.path, environments };
        }
        const json = parseJsonc(read.text);
        if (!json || typeof json !== 'object')
            return { status: 'unknown' };
        const env = json.env;
        return { status: 'ok', source: read.path, environments: env && typeof env === 'object' ? Object.keys(env) : [] };
    }
    return { status: 'absent' };
}
/** .vercel/project.json links the dir to a project; `vercel --prod` needs no other config. */
function readVercelLink(fs, projectDir) {
    const read = readText(fs, dir(projectDir, '.vercel/project.json'));
    if (read.status !== 'ok')
        return read;
    const json = parseJsonc(read.text);
    return json && typeof json === 'object' ? { status: 'ok', source: read.path, linked: true } : { status: 'unknown' };
}
/** fly.toml: the app name(s). `fly deploy` always deploys that app's production machines. */
function readFlyConfig(fs, projectDir, configPath) {
    const read = readText(fs, configPath ? (configPath.startsWith('/') ? configPath : dir(projectDir, configPath)) : dir(projectDir, 'fly.toml'));
    if (read.status !== 'ok')
        return read;
    const doc = parseSimpleToml(read.text);
    if (!doc)
        return { status: 'unknown' };
    const app = doc.sections.get('')?.get('app');
    return { status: 'ok', source: read.path, apps: app ? [app] : [] };
}
/** .firebaserc: the default project and every alias -> project id. */
function readFirebaseProjects(fs, projectDir) {
    const read = readText(fs, dir(projectDir, '.firebaserc'));
    if (read.status !== 'ok')
        return read;
    const json = parseJsonc(read.text);
    if (!json || typeof json !== 'object')
        return { status: 'unknown' };
    const projects = json.projects && typeof json.projects === 'object' ? json.projects : {};
    const aliases = {};
    for (const [alias, id] of Object.entries(projects))
        if (typeof id === 'string')
            aliases[alias] = id;
    return { status: 'ok', source: read.path, defaultProjects: aliases.default ? [aliases.default] : [], aliases };
}
/**
 * kubectl current context(s) and their namespaces. KUBECONFIG (from the hook
 * env or the same command) is added to ~/.kube/config, never substituted for
 * it, so the env can only add candidates.
 */
function readKubeContexts(fs, home, kubeconfigEnv) {
    const files = [...(home ? [dir(home, '.kube/config')] : []), ...String(kubeconfigEnv || '').split(':').filter((p) => p.startsWith('/'))];
    const contexts = [];
    let found = false;
    for (const file of [...new Set(files)]) {
        const read = readText(fs, file);
        if (read.status === 'absent')
            continue;
        if (read.status === 'unknown')
            return read;
        found = true;
        const current = /^current-context:\s*["']?([^"'\s#]*)["']?\s*(?:#.*)?$/m.exec(read.text);
        if (!current)
            continue;
        const name = current[1];
        if (!name)
            continue;
        // Find this context's namespace in the contexts: list (block YAML only).
        let namespace = null;
        const blocks = read.text.split(/\n(?=[ \t]*-[ \t\n])/);
        for (const block of blocks) {
            const blockName = /(?:^|\n)[ \t]*-?[ \t]*name:[ \t]*["']?([^"'\s#]+)/.exec(block);
            if (blockName && blockName[1] === name && /\bcontext:/.test(block)) {
                const ns = /\bnamespace:[ \t]*["']?([^"'\s#]+)/.exec(block);
                if (ns)
                    namespace = ns[1];
            }
        }
        contexts.push({ name, namespace });
    }
    if (!found)
        return { status: 'absent' };
    return { status: 'ok', source: files.join(':'), contexts };
}
/** samconfig.toml: config environments and stack names. */
function readSamConfig(fs, projectDir) {
    const read = readText(fs, dir(projectDir, 'samconfig.toml'));
    if (read.status !== 'ok')
        return read;
    const doc = parseSimpleToml(read.text);
    if (!doc)
        return { status: 'unknown' };
    const configEnvs = new Set();
    const stacks = new Set();
    for (const [section, values] of doc.sections) {
        if (!section)
            continue;
        configEnvs.add(section.split('.')[0]);
        const stack = values.get('stack_name');
        if (stack)
            stacks.add(stack);
    }
    return { status: 'ok', source: read.path, configEnvs: [...configEnvs], stacks: [...stacks] };
}
/** SST's selected stage (.sst/stage). */
function readSstStage(fs, projectDir) {
    const read = readText(fs, dir(projectDir, '.sst/stage'));
    if (read.status !== 'ok')
        return read;
    const stage = read.text.trim();
    return /^[A-Za-z0-9_-]{1,64}$/.test(stage) ? { status: 'ok', source: read.path, stage } : { status: 'unknown' };
}
/** Terraform's selected workspace (.terraform/environment); absent means `default`. */
function readTerraformWorkspace(fs, projectDir) {
    const read = readText(fs, dir(projectDir, '.terraform/environment'));
    if (read.status !== 'ok')
        return read;
    const workspace = read.text.trim();
    return /^[A-Za-z0-9_.-]{1,90}$/.test(workspace) ? { status: 'ok', source: read.path, workspace } : { status: 'unknown' };
}
/** gcloud's active configuration's [core] project. */
function readGcloudProject(fs, home) {
    if (!home)
        return { status: 'unknown' };
    const active = readText(fs, dir(home, '.config/gcloud/active_config'));
    if (active.status === 'unknown')
        return active;
    const name = active.status === 'ok' ? active.text.trim() : 'default';
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(name))
        return { status: 'unknown' };
    const read = readText(fs, dir(home, `.config/gcloud/configurations/config_${name}`));
    if (read.status !== 'ok')
        return read;
    const doc = parseSimpleToml(read.text);
    const project = doc?.sections.get('core')?.get('project');
    return project ? { status: 'ok', source: read.path, project } : { status: 'unknown' };
}
//# sourceMappingURL=seatbelt-deploy.js.map