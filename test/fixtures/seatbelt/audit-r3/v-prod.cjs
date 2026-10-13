'use strict';
// The audit's v-prod rows (production never looser, 19 rows). v-prod.cjs itself was not in the
// evidence folder; the ids are the audit's (v-prod.out) and the commands follow its RESULT.md §7 row 9.
const S = 'stop', P = 'pass';
module.exports = [
  { id: 'TF:dev-and-prod-varfile', cmd: 'terraform apply -var-file=dev.tfvars -var-file=prod.tfvars', expect: S },
  { id: 'TF:prod-varfile-dev-var', cmd: 'terraform apply -var-file=prod.tfvars -var env=dev', expect: S },
  { id: 'TF:chdir-staging-prod-vars', cmd: 'terraform -chdir=infra/staging apply -var-file=prod.tfvars', expect: S },
  { id: 'TF:ws-env-prod-dev-var', cmd: 'TF_WORKSPACE=prod terraform apply -var-file=dev.tfvars', expect: S },
  { id: 'TF:ws-select-twice', cmd: 'terraform workspace select dev && terraform workspace select prod && terraform apply', expect: S },
  { id: 'TF:bash-c', cmd: 'bash -c "terraform apply"', expect: S },
  { id: 'TF:chdir-var', cmd: 'terraform -chdir=$D apply', expect: S },
  { id: 'TF:misleading-msg', cmd: 'terraform apply -var "note=dev test" -var-file=prod.tfvars', expect: S },
  { id: 'TF:cd-prod-path-dev-word', cmd: 'cd infra/prod && terraform apply -var-file=dev.tfvars', expect: S },
  { id: 'TF:tofu', cmd: 'tofu apply', expect: S },
  { id: 'TF:unknown-flag', cmd: 'terraform apply --weird-flag', expect: S },
  { id: 'WP:branch-twice', cmd: 'wrangler pages deploy dist --branch feat --branch main', expect: S },
  { id: 'WP:branch-var', cmd: 'wrangler pages deploy dist --branch=$B', expect: S },
  { id: 'WP:branch-production', cmd: 'wrangler pages deploy dist --branch production', expect: S },
  { id: 'WP:chain', cmd: 'wrangler pages deploy dist --branch feat && npx wrangler pages deploy dist', expect: S, opts: { current: 'main' } },
  { id: 'WP:pass-branch', cmd: 'wrangler pages deploy dist --branch feat/x', expect: P },
  { id: 'RW:env-twice', cmd: 'railway up --environment dev --environment production', expect: S },
  { id: 'RW:env-var', cmd: 'railway up -e $E', expect: S },
  { id: 'TAG:force-chain', cmd: 'git fetch && git push --force origin refs/tags/v1.0.0', expect: S },
];
