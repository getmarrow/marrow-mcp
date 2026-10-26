# Security policy

## Reporting a vulnerability

Please report security problems privately. Do not open a public issue or pull request for them.

1. Use GitHub's private vulnerability reporting: open the [Security tab](https://github.com/getmarrow/marrow-mcp/security) of this repository and choose "Report a vulnerability".
2. Or email the contact published in [security.txt](https://getmarrow.ai/.well-known/security.txt): `Contact: mailto:security@getmarrow.ai`.

Please include what you found, the version or commit, and the steps to reproduce it. Do not include real credentials, API keys or other people's data; use test accounts and dummy values.

## Scope

In scope:

- the `@getmarrow/mcp` npm package built from this repository: the MCP server, the approval hooks and the command-risk checks they run;
- how it reads, sends, stores and redacts Marrow API keys and other credentials;
- the GitHub Actions workflows and the release process of this repository (npm publishing and MCP Registry metadata), including anything that could let someone publish, or change what users install;
- documentation that states a security property the code does not have.

Also welcome through the same contact: findings about the hosted Marrow AI service and website at getmarrow.ai.

Out of scope:

- denial-of-service or volume testing, spam, social engineering and physical attacks;
- problems that need an already compromised machine, account or key;
- software we do not publish (MCP clients, agent hosts, npm, GitHub): please report those to their owners;
- scanner output without a demonstrated impact.

## Testing rules

Test only against your own installs, keys and accounts. Do not access other people's data, and stop at the minimum needed to show the problem. Please check the latest release first, and keep the details private until a fix has been released.
