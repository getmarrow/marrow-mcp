import type { SeatbeltFs } from './seatbelt-fs';
export declare const MAX_DEPLOY_CONFIG_BYTES: number;
export type DeployRead<T> = {
    status: 'absent';
} | {
    status: 'unknown';
} | ({
    status: 'ok';
    source: string;
} & T);
/** JSON with comments and trailing commas (wrangler.jsonc, .firebaserc). Null when it does not parse. */
export declare function parseJsonc(text: string): unknown;
interface TomlDoc {
    /** section name ('' for top level) -> key -> raw string value */
    sections: Map<string, Map<string, string>>;
}
/** Minimal TOML: [section] / [[array]] headers and key = "string" | bare value. Null on a malformed header. */
export declare function parseSimpleToml(text: string): TomlDoc | null;
/** The hook env merged with the deploy command's prefix assignments (they reach the tool's environment). */
export type DeployEnv = Record<string, string | undefined>;
/**
 * Env each tool reads that selects or relocates its deploy target. These are
 * not modelled: any of them present (even empty) makes the reader 'unknown',
 * which the mapper treats as production.
 */
export declare const DEPLOY_RELOCATING_ENV: {
    readonly wrangler: readonly ["CLOUDFLARE_ENV", "WRANGLER_ENV", "CLOUDFLARE_ACCOUNT_ID", "CF_ACCOUNT_ID", "WRANGLER_CONFIG"];
    readonly vercel: readonly ["VERCEL_PROJECT_ID", "VERCEL_ORG_ID", "VERCEL_ENV", "VERCEL_SCOPE"];
    readonly fly: readonly ["FLY_APP", "FLY_APP_NAME", "FLY_CONFIG"];
    readonly firebase: readonly ["FIREBASE_PROJECT", "GCLOUD_PROJECT", "FIREBASE_CONFIG"];
    readonly kube: readonly ["KUBECONTEXT", "KUBECTL_CONTEXT"];
    readonly sam: readonly ["SAM_CONFIG_ENV", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_CONFIG_FILE"];
    readonly sst: readonly ["SST_STAGE", "SST_CONFIG"];
    readonly terraform: readonly ["TF_DATA_DIR", "TF_WORKSPACE", "TF_CLI_ARGS", "TF_CLI_ARGS_apply", "TF_CLI_ARGS_destroy", "TF_CLI_CONFIG_FILE"];
    readonly gcloud: readonly ["CLOUDSDK_CONFIG", "CLOUDSDK_ACTIVE_CONFIG_NAME", "CLOUDSDK_CORE_PROJECT", "GOOGLE_CLOUD_PROJECT"];
};
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
export declare function readWranglerConfig(fs: SeatbeltFs, projectDir: string, configPath?: string, env?: DeployEnv): DeployRead<{
    environments: string[];
    targets: WranglerTarget[];
}>;
/** .vercel/project.json links the dir to a project; `vercel --prod` needs no other config. */
export declare function readVercelLink(fs: SeatbeltFs, projectDir: string, env?: DeployEnv): DeployRead<{
    linked: true;
}>;
/** fly.toml: the app name(s). `fly deploy` always deploys that app's production machines. */
export declare function readFlyConfig(fs: SeatbeltFs, projectDir: string, configPath?: string, env?: DeployEnv): DeployRead<{
    apps: string[];
}>;
/** .firebaserc: the default project and every alias -> project id. */
export declare function readFirebaseProjects(fs: SeatbeltFs, projectDir: string, env?: DeployEnv): DeployRead<{
    defaultProjects: string[];
    aliases: Record<string, string>;
}>;
/**
 * kubectl current context(s) and their namespaces. KUBECONFIG (from the hook
 * env or the same command) is added to ~/.kube/config, never substituted for
 * it, so the env can only add candidates. A relative KUBECONFIG entry (it
 * depends on the command's cwd), a JSON kubeconfig, or a found config with
 * no current-context is 'unknown'.
 */
export declare function readKubeContexts(fs: SeatbeltFs, home: string | null, kubeconfigEnv?: string, env?: DeployEnv): DeployRead<{
    contexts: Array<{
        name: string;
        namespace: string | null;
    }>;
}>;
/** samconfig.toml: config environments and stack names. */
export declare function readSamConfig(fs: SeatbeltFs, projectDir: string, env?: DeployEnv): DeployRead<{
    configEnvs: string[];
    stacks: string[];
}>;
/** SST's selected stage (.sst/stage). */
export declare function readSstStage(fs: SeatbeltFs, projectDir: string, env?: DeployEnv): DeployRead<{
    stage: string;
}>;
/** Terraform's selected workspace (.terraform/environment); absent means `default`. TF_DATA_DIR / TF_WORKSPACE in env are 'unknown'. */
export declare function readTerraformWorkspace(fs: SeatbeltFs, projectDir: string, env?: DeployEnv): DeployRead<{
    workspace: string;
}>;
/** gcloud's active configuration's [core] project. */
export declare function readGcloudProject(fs: SeatbeltFs, home: string | null, env?: DeployEnv): DeployRead<{
    project: string;
}>;
export {};
//# sourceMappingURL=seatbelt-deploy.d.ts.map