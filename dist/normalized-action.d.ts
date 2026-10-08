/**
 * The exact action a hook-classified tool call performs, in the service's
 * normalized_action shape (marrow.gate.v1 `action`), so Marrow binds a gate,
 * a hold and an approval to that exact command or tool call, not to the
 * coarse classification ("deploy on production") the hook also sends.
 *
 * What leaves the machine: the tool kind, the host's tool name, the program
 * names of a shell command, the file paths of an edit, a SHA-256 of the
 * command or tool input, and `truncated: true` when that hash could not cover
 * everything that decides what the action does. The command text and the
 * tool input themselves are never sent.
 *
 * Before hashing, a normalized form is built (whitespace and quoting
 * normalized) in which:
 * - A credential is replaced by `[secret]`, and the action stays exact (only
 *   the credential differs between two such commands). Credentials are:
 *   values of environment assignments, flags, `NAME=value` arguments and
 *   inline `name: value` / `"name": "value"` literals whose name is a
 *   credential name (password, passwd, passphrase, pwd, secret, token, OTP,
 *   API key, access key, private key, client secret, bearer, cookie,
 *   credential); the password in any `scheme://user:password@` URL;
 *   `Bearer`/`Basic`/`Token` header values; an OAuth `code` in a URL; known
 *   key formats (AWS, GitHub, Stripe, Slack, Google, GitLab, npm, JWT, PEM,
 *   Marrow); the password flags of known programs (`mysql -p<pw>`, `sshpass
 *   -p`, `docker|podman|helm|az|oc|cf login -p`, `mongo* -p`, `twine -p`,
 *   `useradd -p`, `sqlcmd|bcp|osql|isql -P`, `redis-cli -a`, `curl -u/-U`,
 *   auth headers, `openssl -pass*` and `pass:`, `keytool -storepass`,
 *   `java -D…password=`, `gh secret set -b`, `kubectl --from-literal`);
 *   `aws configure set <secret name> <value>`,
 *   `npm|yarn|pnpm config set <secret name> <value>`; the values a secrets
 *   command sets (`gh|doppler|fly|wrangler … secret(s) set NAME VALUE`, `vault
 *   … password=…`, `vault login TOKEN`, `htpasswd -b`, `rabbitmqctl add_user`,
 *   `mysqladmin password`, `redis AUTH` and `requirepass`).
 * - Data a command reads (text echoed or printed into a pipe or a file,
 *   heredoc bodies, here-strings) and the values of other environment
 *   assignments and env-store settings (`env:set`, `config:set`, `variables
 *   set`) are replaced by a SHA-256 of the data when the data carries
 *   nothing secret-shaped and does not feed a secrets command or a secrets
 *   file: different data gives a different hash, the same data the same hash.
 * - Anything else that may be a secret is replaced by `[secret]` and the
 *   action is marked `truncated: true`, so Marrow never binds an approval to
 *   it and always asks: data that feeds a secrets command (`… secret put`,
 *   `docker login --password-stdin`, `aws configure`, `vault`, `passwd` …)
 *   or file (`.env*`, keys, `.npmrc`, `.pgpass` …) or looks secret; values
 *   under ambiguous names (`key`, `auth`, `session`, `signature`, `pin`);
 *   random-looking values (long hex, mixed-case strings of 20 or more
 *   characters), which may also be an id or a commit; the arguments of a
 *   program named for a secret (`set-password.sh`); and inputs cut for size.
 *
 * Commands run through `bash -c`, `ssh HOST …`, `eval` and `su -c` are
 * normalized the same way. Everything else stays in the normalized form, which
 * is only hashed; a password typed as a plain argument of an unknown program
 * (`./deploy.sh hunter2`) cannot be recognized and is covered only by the
 * hash. The same command gives the same hash on every machine and on every
 * retry. A program name or path that looks like a key is dropped or
 * replaced.
 */
export type NormalizedHookAction = {
    tool_kind: 'shell' | 'edit' | 'mcp' | 'other';
    tool_name: string;
    programs?: string[];
    paths?: string[];
    tool_input: {
        command_sha256: string;
    } | {
        input_sha256: string;
    } | Record<string, never>;
    /** The hash could not cover everything that decides the action: Marrow never binds an approval to it. */
    truncated?: true;
};
type ToolEvent = {
    tool_name?: unknown;
    tool_input?: unknown;
};
/** A value shaped like a key, token or password hash (mixed-case random text, long hex, known prefixes). */
export declare function looksLikeKey(value: string): boolean;
type NameClass = 'credential' | 'ambiguous' | 'reference' | 'plain';
/**
 * What a value under this name is: a credential (replaced; the action stays
 * exact), ambiguous (replaced; the action is marked truncated), a reference
 * to a secret such as its file, name or id (kept), or plain (kept).
 */
export declare function classifySecretName(name: string): NameClass;
/**
 * The normalized form of a shell command (see the module comment): hashed,
 * never sent. `truncated` is true when something that may change what the
 * command does had to be withheld. Exported for tests.
 */
export declare function normalizeShellCommand(command: string): {
    text: string;
    programs: string[];
    truncated: boolean;
};
export declare function normalizedHookAction(event: ToolEvent): NormalizedHookAction;
export {};
//# sourceMappingURL=normalized-action.d.ts.map