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
/** wrangler.toml / wrangler.json / wrangler.jsonc: the named environments ([env.<name>]); top level is production. */
export declare function readWranglerConfig(fs: SeatbeltFs, projectDir: string, configPath?: string): DeployRead<{
    environments: string[];
}>;
/** .vercel/project.json links the dir to a project; `vercel --prod` needs no other config. */
export declare function readVercelLink(fs: SeatbeltFs, projectDir: string): DeployRead<{
    linked: true;
}>;
/** fly.toml: the app name(s). `fly deploy` always deploys that app's production machines. */
export declare function readFlyConfig(fs: SeatbeltFs, projectDir: string, configPath?: string): DeployRead<{
    apps: string[];
}>;
/** .firebaserc: the default project and every alias -> project id. */
export declare function readFirebaseProjects(fs: SeatbeltFs, projectDir: string): DeployRead<{
    defaultProjects: string[];
    aliases: Record<string, string>;
}>;
/**
 * kubectl current context(s) and their namespaces. KUBECONFIG (from the hook
 * env or the same command) is added to ~/.kube/config, never substituted for
 * it, so the env can only add candidates.
 */
export declare function readKubeContexts(fs: SeatbeltFs, home: string | null, kubeconfigEnv?: string): DeployRead<{
    contexts: Array<{
        name: string;
        namespace: string | null;
    }>;
}>;
/** samconfig.toml: config environments and stack names. */
export declare function readSamConfig(fs: SeatbeltFs, projectDir: string): DeployRead<{
    configEnvs: string[];
    stacks: string[];
}>;
/** SST's selected stage (.sst/stage). */
export declare function readSstStage(fs: SeatbeltFs, projectDir: string): DeployRead<{
    stage: string;
}>;
/** Terraform's selected workspace (.terraform/environment); absent means `default`. */
export declare function readTerraformWorkspace(fs: SeatbeltFs, projectDir: string): DeployRead<{
    workspace: string;
}>;
/** gcloud's active configuration's [core] project. */
export declare function readGcloudProject(fs: SeatbeltFs, home: string | null): DeployRead<{
    project: string;
}>;
export {};
//# sourceMappingURL=seatbelt-deploy.d.ts.map