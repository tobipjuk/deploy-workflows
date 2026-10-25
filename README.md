# deploy-workflows

Shared, reusable GitHub Actions workflows and a Terraform module for production deploys of
Tobi's Terraform projects, with **approval in Telegram via Orion**.

This repository is the **integrity anchor**: AWS gives plan and deploy credentials only to jobs
running *these* workflow files from *this* repository's `main` (OIDC `job_workflow_ref`). The
dev box (omarchy) and its agents must never be able to write here.

```
project repo (box can push)                deploy-workflows (box can't write)          AWS
───────────────────────────                ────────────────────────────────           ───
push to main ─► plan.yml ──── uses ──────► tf-plan.yml@main ── OIDC sub ─────────────► <p>-github-plan (read-only)
                                            plan, gates, plan-summary.json,
                                            plan-bundle (1 day, only with a deploy role)
                                                         │
Orion (server) polls plan runs ◄─────────────────────────┘
  └─ Telegram: summary + [Approve] ─► Tobi taps (user id checked)
  └─ GitHub App dispatches deploy.yml (inputs: plan_run_id, bundle_sha256, changes_digest, allow_destroy)
                 deploy.yml ── uses ──────► tf-apply.yml@main ── OIDC sub ─────────────► <p>-github-deploy
                                            verify run + bundle + digest,                 (only: actor <app>[bot],
                                            gates, apply saved plan,                       workflow_dispatch, attempt 1,
                                            invalidate, smoke check                        tf-apply.yml@main, main)
```

| Path | What |
|---|---|
| `.github/workflows/tf-plan.yml` | Reusable plan (called from a project's `plan.yml`) |
| `.github/workflows/tf-apply.yml` | Reusable apply of an approved plan (called from `deploy.yml`) |
| `.github/actions/tools` | Puts `scripts/` and `policy/` on the runner (always from this repo) |
| `scripts/plan_report.py` | Plan summary, `plan-summary.json`, changes digest, destroy/code-execution/provider gates |
| `scripts/bundle.py` | Creates and verifies the plan bundle |
| `.github/workflows/tf-attest.yml` | Nested in tf-plan.yml: attests the plan artifacts (no project code) |
| `scripts/attest.py` | Plan attestation: manifest + audience, RS256/JWKS verification of the tf-attest OIDC token |
| `scripts/tf_sandbox.sh` | Runs Terraform as an unprivileged user with a scrubbed environment and egress firewall |
| `scripts/egress_proxy.py` | The sandbox's only way out: CONNECT proxy for AWS + Terraform registry hosts |
| `scripts/check_tf_config.py` | Static pre-plan gate on provider/backend/terraform blocks and module sources |
| `scripts/check_plan_run.py` | Is this plan run deployable (main, newest, < 2 h, made by tf-plan.yml)? |
| `scripts/check_lockfile.py` | Provider allowlist, checked before `terraform init` |
| `policy/allowed-providers.txt` | Providers a deploy may use |
| `policy/egress/<owner>/<repo>.json` | Per-repo trusted egress hosts, region, account, state bucket |
| `modules/github-oidc-roles` | Terraform: plan + deploy roles, trust, boundaries, guardrails, data guard |
| `docs/oidc-trust.md` | The OIDC sub template, exact subjects, the `gh api` call |
| `docs/orion-interface.md` | The contract Orion's approver implements |

## Using it in a project

1. **CI stack** (applied by a human with SSO admin, own state key), e.g. `terraform/ci/`:

   ```hcl
   module "roles" {
     source = "git::https://github.com/tobipjuk/deploy-workflows.git//modules/github-oidc-roles?ref=<commit>"
     account_id  = "<12 digits>"
     region      = "eu-west-2"
     name_prefix = "<p>"
     project_tag = "<Project tag>"
     github_repo = "tobipjuk/<repo>"
     approver_app_slug  = "<app slug>"      # needed when create_deploy_role = true
     create_deploy_role = true              # false in the Organization management account
     state_bucket = "<bucket>"
     state_keys   = ["prod/terraform.tfstate"]
     plan_secret_parameter_arns = ["arn:aws:ssm:<region>:<acct>:parameter/<p>/prod/*"]
     private_bucket_names       = ["<backups bucket>"]
     dns_zones                  = [{ zone_id = "<id>", apex = "<domain>" }]
     protected_txt_names        = ["_dmarc.<domain>"]
     protected_record_name_patterns = ["*._domainkey.<domain>"]
     boundary_statements        = [...]  # ceiling: the project's own resources
     deploy_statements          = [...]  # writes per resource type
     lambda_boundary_statements = [...]  # what the project's functions do at runtime
   }
   ```

   starhuntercrew's `terraform/ci/` is the reference implementation (`policies.tf` shows how
   to derive the statements from the resource types in the stack).

2. **OIDC sub template** for the repo: `docs/oidc-trust.md` (one `gh api` call).
3. **Repo variables**: `AWS_ACCOUNT_ID`, `AWS_PLAN_ROLE_ARN`, `AWS_DEPLOY_ROLE_ARN` (only where a
   deploy role exists), `TF_STATE_BUCKET`, `APPROVER_APP_SLUG`, plus smoke-check ones.
4. **Callers**: `.github/workflows/plan.yml` and `deploy.yml` (copy starhuntercrew's; inputs
   documented at the top of `tf-plan.yml` / `tf-apply.yml`). Keep them thin.
5. **Orion**: register the repo (`docs/orion-interface.md` section 10).
6. **Egress/state policy**: Tobi adds `policy/egress/<owner>/<repo>.json` here (see below).

### Egress and state policy (per project, trusted, required)

Terraform runs in a sandbox whose only way out is a proxy that relays to an **exact** host list.
That list, the region, the account and the state bucket come from a **trusted policy file in
this repository**, `policy/egress/<owner>/<repo>.json`, selected by the run's
`github.repository`, never by a workflow input: the project repo's `plan.yml` is writable by the
box and runs without approval, so nothing in it may widen egress or redirect state.

```json
{
 "schema": 1,
 "repository": "tobipjuk/<repo>",
 "account_id": "<12 digits>",
 "region": "eu-west-2",
 "state_bucket": "<state bucket>",
 "state_region": "eu-west-2",
 "services": ["lambda", "dynamodb", "logs", "ssm", "sns", "events", "monitoring", "apigateway", "email"],
 "global_hosts": ["iam.amazonaws.com", "cloudfront.amazonaws.com", "route53.amazonaws.com"],
 "buckets": ["<own bucket>", "<own bucket>"],
 "s3_path_style": false
}
```

- `services`: one regional endpoint name per AWS service the Terraform code calls (`apigateway`
  for API Gateway v1/v2, `email` for SES v1, `monitoring` for CloudWatch alarms, `events`,
  `logs`, `lambda`, `dynamodb`, `ssm`, `sns`, `sqs`, `kms` ...). `sts.<region>` is always added.
- `global_hosts`: global endpoints (`iam`, `cloudfront`, `route53`, `budgets` `.amazonaws.com`)
  and anything in a second region, e.g. an `aws.us_east_1` alias: `acm.us-east-1.amazonaws.com`
  and `sts.us-east-1.amazonaws.com`.
- `buckets`: every bucket the code manages or reads (dot-free names); the state bucket is added.
- Derived from `account_id`, own account only: `<account>.ddb.<region>.amazonaws.com` when
  `dynamodb` is listed (SDK account-based endpoints) and `<account>.s3-control.<region>.amazonaws.com`
  when there are buckets (bucket tags via S3 Control in AWS provider 6.x).
- `s3_path_style`: keep false. The path-style host serves every bucket, attacker-owned ones too.

The pipeline refuses a repo without a file, a file for another repository, unknown fields,
`s3*`/`execute-api`/`elb*` services, dotted buckets and wildcards (`scripts/egress_hosts.py`).
Caller inputs `aws_region`, `aws_account_id` and the optional `state_bucket` must **agree** with
the file; the backend always uses the file's bucket and region (`-backend-config`).

**Onboarding a repo = a pull request to deploy-workflows, made and merged by Tobi**, adding its
policy file. A missing endpoint fails the job at the "Sandbox egress" step ("egress policy
missing hosts", with the refused count; hostnames are never logged). A watchdog
stops Terraform as soon as the proxy refuses a connection (the AWS provider otherwise retries a
refused endpoint for half an hour: its `max_retries` of 25 ignores `AWS_MAX_ATTEMPTS`, which the
sandbox still sets to 2 with `AWS_RETRY_MODE=standard`), and the plan and apply jobs time out
after 20 minutes.

To list the missing hosts, run the plan locally (never in CI) with a read-only profile:

```bash
tests/sandbox/local-plan.sh ~/GitHub/<repo> <tf_dir> tobipjuk/<repo> <aws-profile>
```

It runs the real `terraform plan -lock=false` in the same sandbox and proxy in a throwaway
container, with the policy's host list, and prints the ALLOWED/REFUSED hostnames from a private
file (`SANDBOX_DEBUG_HOSTS_FILE`, refused when `GITHUB_ACTIONS=true`). Add what's legitimate to
the policy; never a path-style S3, `execute-api` or `elb` host.

Requirements on the project's Terraform:

- `.terraform.lock.hcl` committed, providers only from `policy/allowed-providers.txt`.
- No provisioners, no `external` data source (both refused).
- Gitignored files that apply reads (e.g. `archive_file` zips) listed in `bundle_globs`.
- Lambda execution roles at path `/<p>-lambda/` with `permissions_boundary = <p>-lambda-boundary`
  (see "Existing Lambda roles"), otherwise CI can't change them (fails closed).
- Secrets not in the planned stack (see "Secrets").

## What the gates check

tf-plan (with the plan role):

- override files, `*.auto.tfvars`, CLI config files in the repo → refused;
- lock file providers outside the allowlist → refused **before** `init`, so the provider never runs;
- provider/backend/terraform settings outside the CI allowlist (endpoints, proxies, CA bundles,
  shared config files, assume_role, skip_* ...) and non-local modules → refused before `init`;
- Terraform runs sandboxed: own uid, `env -i`, egress only through the allowlisting proxy;
- plan JSON: provisioners, `external` data sources, providers outside the allowlist → blocked;
- deletes, replacements, unknown or missing actions, `action_invocations`, `deferred_changes`,
  incomplete plans → refused unless `plan.yml` was dispatched with `allow_destroy`;
- bundle, summary and the plan attestation (OIDC token over their hashes) uploaded only when
  the project has a deploy role.

tf-apply (with the deploy role; AWS has already checked actor/event/attempt/workflow):

- actor `<slug>[bot]`, triggering actor = actor, first attempt, ref main, input formats;
- approval data read from the dispatch **event** (`github.event.inputs`), not from the caller's `with:`;
- the plan run: `plan.yml`, this repo (not a fork), main, push/dispatch, success, exactly the
  two jobs of tf-plan.yml (plan + nested attest, all attempts, both successful), referencing
  `tf-plan.yml` and `tf-attest.yml` and nothing outside deploy-workflows `@refs/heads/main`, made
  from main's current head, newest successful plan run, started < 2 h ago;
- the plan attestation: OIDC token minted by the nested `tf-attest.yml@main` job (no project
  code) in that run, whose `aud` commits to the sha256 of the downloaded bundle and
  `plan-summary.json` (Guardian F1);
- the bundle: sha256 = approved value, only expected members, no links or traversal, complete
  `SHA256SUMS`, `SOURCE` = this commit, never overwrites a tracked file or writes through a symlink;
- the plan file again: changes digest = the one Tobi approved, destroy gate (with the dispatched
  `allow_destroy`), code execution and provider gates;
- `terraform apply tfplan` (never re-plans; Terraform rejects a stale plan);
- invalidations from `terraform output` names, smoke check without credentials;
- an optional project post-deploy script runs in a **separate job with no AWS credentials**.

## Threat model

**Attack surface:** the project repos (code, Terraform, caller workflows, repo variables), the
GitHub Actions runtime, Orion's approver (App key + Telegram bot), Tobi's Telegram account, the
AWS roles. **Likely attacker:** a compromised or misled agent on the dev box (it holds a GitHub
token with write access to the project repos), or someone who steals that token. **Blast
radius we design for:** a project's own resources in its own account; never the Organization,
identities, billing, audit, mail routing, or other projects.

Guardian's review of the first template (starhuntercrew `20d162e`) and how each finding is handled:

| # | Finding | Now |
|---|---|---|
| 1, 2 | GitHub Free can't enforce required reviewers on private repos, so the `production` environment wasn't a real gate; the box could approve/dispatch itself | **Solved by the approval architecture.** The deploy role trusts only runs dispatched by Orion's App (`actor <slug>[bot]`), as `workflow_dispatch`, first attempt, inside `tf-apply.yml@main`. The App key lives only on Orion's server; Orion dispatches only after a tap from Tobi's Telegram user id. The box can dispatch `deploy.yml` with Tobi's token, but then `actor` is `tobipjuk` and AWS refuses |
| 3 | Plan role could read secrets | Plan role: explicit deny on `ssm:GetParameter*` for the project's secret paths and on `kms:Decrypt`; data guard on both roles denies DynamoDB items, private bucket objects, `logs:FilterLogEvents/GetLogEvents/StartQuery/...`, `ses:ListContacts/GetContact/*SuppressedDestination*`, Secrets Manager values. Project side: see "Secrets" |
| 4 | Deploy role could mint roles | Roles CI creates or changes must live under `/<p>-lambda/` and carry `<p>-lambda-boundary` (Lambda data plane only; IAM/STS/control plane denied; credentials useless outside the project's own functions via `lambda:SourceFunctionArn`). Detection: see "Monitoring" |
| 5 | Private buckets could be opened | Deny `PutBucketPolicy`, `DeleteBucketPolicy`, `PutBucketAcl`, `PutObjectAcl`, `PutBucketPublicAccessBlock`, `PutBucketOwnershipControls` on private buckets; `PutAccountPublicAccessBlock` everywhere |
| 6 | DNS takeover of mail | Deny `ChangeResourceRecordSets` when the batch has MX/NS/SOA/CAA (`route53:ChangeResourceRecordSetsRecordTypes`), TXT on the apex and listed names (`...NormalizedRecordNames`), and any change on listed patterns (DKIM `*._domainkey.<domain>`); `DeleteHostedZone`, `route53domains:*` denied |
| 7 | `iam:PermissionsBoundary` doesn't cover `UpdateAssumeRolePolicy`; existing Lambda roles had no boundary | `iam:UpdateAssumeRolePolicy` is denied to CI outright (trust changes are human-only). Existing roles must be moved once by a human to the Lambda path + boundary; until then CI can't touch them |
| 8 | Wildcard `PassRole`, account-wide CloudFront policy wildcards, ACM deletes | `PassRole` only on `role/<p>-lambda/*` to `lambda.amazonaws.com`; CloudFront update/delete only on the listed ids (create stays on the type: new ids are unknown); ACM delete/tag only with the project's tag, in the boundary too |
| 9 | Bundle uploaded without a deploy role | Bundle (and its sha) produced only when `deploy_enabled` |
| 10 | Unknown plan constructs | `action_invocations`, `deferred_changes`, incomplete plans and missing/null actions count as destructive |
| F1 | A box-added job in the same `plan.yml` run (`needs: plan`, `actions: write`) can download `plan-bundle`, keep the genuine tfplan, swap a Lambda zip, re-tar with the right `SOURCE`, and re-upload `plan-bundle` + `plan-summary` with a matching `bundle_sha256` and any diff text; the changes digest (addresses + actions only) doesn't notice, Orion and tf-apply pass, AWS gets the malicious zip | **Plan attestation**: a nested job from a separate file, `tf-attest.yml` (called only by tf-plan.yml, runs no project code), mints a GitHub OIDC token with `aud = deploy-workflows-plan:v2:<sha256(manifest)>`, the manifest holding the sha256 of the bundle and of the whole `plan-summary.json` (diff included). Only that job carries `job_workflow_ref = tf-attest.yml@refs/heads/main`; a box-added job's token carries the project's own workflow ref, and the plan job's carries `tf-plan.yml` (it runs project Terraform, so it must not be able to attest even if Terraform escaped). tf-apply verifies signature (GitHub JWKS), `iss`, `job_workflow_ref`, `repository`, `run_id`, `run_attempt`, `sha`, `ref`, `iat` inside the run, then recomputes both hashes from the downloaded artifacts (`scripts/attest.py`). A box-written `plan.yml` calling `tf-attest.yml` directly is refused because the run must consist of exactly tf-plan's two jobs, both successful, referencing both files. Defenc| F1b | (Guardian on f63cf2e, HIGH) The attestation token was minted in the job that runs project Terraform; with `id-token: write` every step there holds the OIDC request credentials, so Terraform reading `/proc/self/environ` (HCL `file()`) could mint tokens for any audience | (a) separate attest job (nested `tf-attest.yml`, no project code); (b) the token must carry `job_workflow_ref = tf-attest.yml@refs/heads/main`. Environments can't serve as the distinguishing claim: GitHub Free can't use environments in private repos; (c) Terraform runs as user `tfsandbox` (no sudo, no docker) with `env -i` (HOME, PATH, LANG, TF_*, AWS_REGION only), a copy of the checkout without `.git`, and a copy of the AWS profile; the runner's home is closed (0700) (`scripts/tf_sandbox.sh`, tested in a container by `tests/sandbox/run.sh`). Same in tf-apply. JWKS fetch refuses redirects; `kid` must be a non-empty string |
| M2 | (Guardian, ICE review) The plan role runs on every push without approval and can read secrets (state, Lambda env). The allowlisted aws provider/S3 backend accept `endpoints {}`, proxies, `custom_ca_bundle`, `shared_config_files` (`credential_process`), `assume_role`, `skip_*` ...: an aliased provider whose endpoint URL carries a secret leaks it during plan | (1) **static pre-plan gate** `scripts/check_tf_config.py` (tf-plan and tf-apply, before init): allowlists, not denylists, for provider blocks (aws: alias, region, profile, allowed/forbidden_account_ids, max_retries, retry_mode, default_tags.tags, ignore_tags; archive/random: alias), `terraform {}` (required_version, required_providers, backend), backends (s3 basics, local path), profile = the pipeline's profile or `var.x`, module sources local only; root and every local module, HCL and JSON syntax, unparseable = refused. Terraform can't set env vars and runs under `env -i`. (2) **egress allowlist**: the sandbox uid may only reach a local CONNECT proxy (iptables/ip6tables owner match, no DNS, no IMDS); the proxy relays :443 to `*.amazonaws.com`, `registry.terraform.io`, `releases.hashicorp.com` only, refuses non-global addresses, logs counts not names. (3) **needs-attention list** in the summary and `plan-summary.json`: API integration targets, CloudFront origins, Lambda permissions and function URL auth, trust/IAM policies, DNS records, SNS subscriptions, Lambda env changes, S3 bucket-config resources, shown first in Telegram; digest binding unchanged |
| M2b | (Guardian on ca85a7d) HIGH: `data "terraform_remote_state"` takes a backend `config` map (endpoint overrides) and passed the gate. MEDIUM: `*.amazonaws.com` includes attacker-ownable hosts (virtual-hosted buckets, `*.execute-api.*`, `*.elb.*`). LOW: setup trusted any listener on the proxy port; attention values could carry secrets in URLs, record values, policy docs | Built-in data/resource types other than `terraform_data` (so `terraform_remote_state`) refused, HCL and JSON. Exact per-project host list (first from workflow inputs, superseded by M2c: trusted policy files), path-style S3 opt-in, fail closed when unset; the proxy is always started by setup, must bind, and proves itself with a pid ready-file. Attention and redacted diff: URLs lose userinfo/query/fragment, DNS record values, policy documents and env vars never shown, sensitivity masks win; tests assert a secret never appears |
| M2c | (Guardian on bdc9c83) The egress list and state bucket came from caller inputs in the box-writable `plan.yml`, which runs on every push: the box could add its own bucket or turn path-style on | Trusted `policy/egress/<owner>/<repo>.json` here, keyed by `github.repository`; missing file = refused; region, account and state bucket from the file (backend override uses them), caller inputs may only agree; the `egress_*` inputs are gone, so callers don't change |
e in depth: the plan run must have exactly those two jobs (all attempts) and every referenced workflow must be deploy-workflows `@refs/heads/main`. Orion performs the same verification before showing a plan (second layer: what Tobi sees is attested too). Artifact attestations (Enterprise for private repos) and job outputs (not readable via the REST jobs API) weren't usable |

Further hardening in this version: plan attestation (F1), changes digest binding (what Tobi saw = what is applied),
provider allowlist before `init`, provisioner/external-program refusal, plan run provenance
(`referenced_workflows`), re-runs refused in the trust, post-deploy code without credentials.

**Residual risks (accepted, with mitigations):**

- **Orion's server and the App private key.** Whoever has the key can dispatch deploys of
  plans that tf-plan produced (they can't change what tf-plan does or skip the gates). Keep the
  key only on the server, out of agent containers; rotate it if the server is suspected.
  Orion's approver must be deterministic code: summary text (addresses, commit subject, diff
  values) is attacker-influenced and must never reach the LLM's prompt.
- **Tobi's Telegram account.** A hijacked account can approve. Telegram 2FA (cloud password),
  check active sessions; approvals are only possible for plans of commits already on main.
- **The box keeps write access to project repos (incl. Workflows permission).** It can change
  `plan.yml`/`deploy.yml` callers, the project's Terraform and code, and repo variables. It
  can't change the reusable workflows, the scripts, the allowlist or the AWS trust. What it can
  do: push a malicious commit whose plan Tobi then approves. Tobi sees the change list, the
  redacted diff, the commit and a link to it, so **approve means trusting that commit**:
  look at the commit link for anything unexpected (Lambda code ships in a bundle and shows
  only as a `source_code_hash` change). Plans run box-written Terraform with the read-only
  plan role (allowlisted providers only), so the plan role's read scope is what a box
  compromise can read: keep it narrow.
- **Write access to this repo.** Anyone who can push to deploy-workflows' `main` controls
  every deploy. The box's GitHub token must not reach this repo (fine-grained token without
  it), `main` here gets a ruleset (no force-push, no deletion), and changes are reviewed.
- **An approved plan can create a Lambda role with an attacker-chosen trust policy.** CI may
  create roles under `/<p>-lambda/` (that is how Lambda roles are managed), and IAM has no
  condition key for a new role's trust policy. The Lambda boundary caps what such a role can
  do (data plane only, and nothing outside the project's own functions via
  `lambda:SourceFunctionArn`), but `logs:*` writes and `kms:Decrypt`/`GenerateDataKey*` are exempt
  from that source-function deny (still bounded by the boundary's allows). So, again,
  **approving a commit means trusting it**. Turn on IAM Access Analyzer (see "Monitoring"): it
  flags a role trusting anything outside the account.
- **Trust changes on existing Lambda roles are human applies.** `iam:UpdateAssumeRolePolicy` is
  denied to CI outright (the boundary condition can't guard it), so a plan that changes a Lambda
  role's `assume_role_policy` fails at apply: apply it by hand with SSO.
- **Never widen the plan role's reads to secrets.** Don't add `ssm:Get*` (or other secret reads)
  to `read_actions` while `plan_deny_kms_decrypt = false`: with Decrypt allowed, that would let
  every box-written plan read SecureStrings.
- **Requests to the project's own AWS endpoints remain a channel.** The egress list is exact
  (the project's regional/global API hosts and its own buckets), but an API call to an allowed
  endpoint can still name another account's resource (e.g. `lambda:GetFunction` on a foreign
  ARN) with a secret in a name or parameter; IAM denies it, yet it may be logged on the owner's
  side. An RCP/SCP on `aws:ResourceAccount` would shrink this; secrets out of state and env
  (README "Secrets") remove what there is to leak.
- **Logs, the job summary and artifacts are readable by anyone with repo read access, the box
  included.** Terraform's own output (errors, `terraform show` text in the summary) prints
  non-sensitive values, and the plan bundle holds the full plan with state values. Today the box
  can read the same data with Tobi's SSO session, so this adds no new reader; if the box loses
  AWS access, withhold Terraform output from logs and encrypt the bundle (KMS key: plan role
  encrypt-only, deploy role decrypt).
- **GitHub itself** (Actions, OIDC issuer, artifact storage) is trusted.
- **ReadOnlyAccess on both roles**, capped by the boundary: control-plane reads of the
  project's services in the account (other projects' resource *metadata* in a shared account
  is visible). Moving each project to its own account (#131) shrinks this.
- **SES v1 identity/config-set writes** have Resource `*` (region-limited): the service has
  little resource-level support.

## Secrets

The AWS provider decrypts every `aws_ssm_parameter` on refresh (even with `value_wo`), and
`random_password.result` is stored in state. So a stack that **manages** secret parameters
needs `kms:Decrypt` in every plan and keeps the secrets in its state, which the plan role
reads. The fix is project-side:

1. Move secret parameters into a small `terraform/secrets/` stack applied only by a human with
   SSO. Generate values with `ephemeral "random_password"` and write them with
   `value_wo` + `value_wo_version`, so neither that stack's plan nor its state holds them:

   ```hcl
   ephemeral "random_password" "pepper" {
     length  = 48
     special = false
   }

   resource "aws_ssm_parameter" "pepper" {
     name             = "/<p>/prod/progress_pepper"
     type             = "SecureString"
     value_wo         = ephemeral.random_password.pepper.result
     value_wo_version = 1 # bump to rotate
   }
   ```

2. The planned stack references the parameters by name/ARN only (Lambda reads them at runtime).
3. Migrating existing parameters: `removed { from = ... lifecycle { destroy = false } }` in the
   old stack, `import` in the new one. **Don't let the import write a new value** where rotating
   breaks data (an HMAC pepper invalidates stored codes): import those without `value_wo` and
   `lifecycle { ignore_changes = [value, insecure_value] }`, or leave them unmanaged.

Until then set `plan_secret_parameter_arns` anyway: the plan fails closed at refresh instead of
reading secrets.

## Existing Lambda roles

Roles created before this module (path `/`, no boundary) can't be changed by CI. Move them once,
by a human apply of the project stack:

```hcl
resource "aws_iam_role" "lambda" {
  name                 = "<p>-waitlist-lambda-role"
  path                 = "/<p>-lambda/"            # forces replacement (new ARN)
  permissions_boundary = "<lambda_boundary_arn output>"
  assume_role_policy   = data.aws_iam_policy_document.assume.json
}
```

Check first that `lambda_boundary_statements` covers every action in the roles' policies
(otherwise the function loses that access), then apply and invoke each function once. If a
function breaks because of `lambda:SourceFunctionArn`, set
`lambda_boundary_require_source_function = false` and tell Tobi.

## Monitoring (recommended, per account)

- **IAM Access Analyzer** (account analyzer, free): flags roles trusting principals outside the
  account, e.g. a Lambda role whose trust was widened. `aws accessanalyzer create-analyzer
  --analyzer-name account --type ACCOUNT` in the main region.
- **EventBridge alert** on IAM writes by the CI roles (IAM events arrive in **us-east-1**):

  ```json
  {"source": ["aws.iam"], "detail-type": ["AWS API Call via CloudTrail"],
   "detail": {"eventName": ["CreateRole", "DeleteRole", "PutRolePolicy", "AttachRolePolicy",
                            "DetachRolePolicy", "PutRolePermissionsBoundary", "UpdateAssumeRolePolicy"],
              "userIdentity": {"sessionContext": {"sessionIssuer": {
                "userName": ["<p>-github-deploy", "<p>-github-plan"]}}}}}
  ```

  → SNS topic → email to Tobi. A second rule without the `userIdentity` filter on
  `UpdateAssumeRolePolicy` for `/<p>-lambda/` roles catches widened trust by anyone. Needs a
  CloudTrail trail (management events) in the account.

## CloudFormation and CDK projects (later)

trmnl (plain CloudFormation, `server/deploy.sh`) and echo-show (CDK v2) don't fit tf-plan /
tf-apply. The same shape works with a later `cfn-plan.yml` / `cfn-apply.yml` pair:

- plan = `aws cloudformation create-change-set` (CDK: `cdk synth` + `cdk diff --method=template`,
  then a change set from the synthesised template and assets) with the plan role, summary from
  `describe-change-set` (`Replacement`, `Action`, resource types), change set ARN + template
  sha256 in place of the bundle;
- apply = `execute-change-set` of exactly that change set with the deploy role, refusing
  `Replacement: True`/`Remove` without `allow_destroy`, same trust and Orion contract.

Not built yet; the module's trust and guardrails apply unchanged (boundary statements differ).

## Development

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests
tests/sandbox/run.sh          # needs docker: Terraform sandbox separation + egress firewall
TF_BIN=$(which terraform) tests/sandbox/real-terraform.sh   # optional: real init/plan via the proxy
actionlint .github/workflows/*.yml
terraform fmt -check -recursive modules
(cd modules/github-oidc-roles && terraform init -backend=false && terraform validate && terraform test)
```

CI (`.github/workflows/ci.yml`) runs the same. Changes to `main` here change every project's
deploys at the next run: review them like production changes.
