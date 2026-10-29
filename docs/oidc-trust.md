# AWS trust for the plan and deploy roles

Who may plan and who may deploy is decided by **AWS**, from the GitHub OIDC token's `sub`.
The workflows check the same things again, but only so a refusal is readable; a run that
dodges those checks still can't get credentials.

## The repo-level sub template

Each project repo customises its OIDC `sub` with the REST API
(`PUT /repos/{owner}/{repo}/actions/oidc/customization/sub`). GitHub then builds the `sub`
from the listed claims, **in the listed order**, as `key:value` pairs joined by `:`. Two
details from the GitHub docs (*OpenID Connect reference → Customizing the subject claims*):

- `repo` is written as `repo:<owner>/<name>` (immutable-subject repos:
  `repo:<owner>@<ownerId>/<name>@<repoId>`; set the module's `github_repo` to match).
- `context` is written **without** a `context:` key. It is the default-format context:
  `ref:refs/heads/main` for a branch run, `environment:<name>` when the job has an environment,
  `pull_request` for PRs.
- Any `:` **inside** a value becomes `%3A`, so a value can't fake a `:key:` boundary.

Claims allowed in `include_claim_keys` are the token's claims, among them `repo`, `context`,
`actor`, `actor_id`, `event_name`, `job_workflow_ref`, `job_workflow_sha`, `ref`, `ref_type`,
`environment`, `repository_owner`, `run_attempt`, `runner_environment`, `workflow`,
`workflow_ref`. For a job inside a reusable workflow, `job_workflow_ref` is the **reusable**
workflow's path and ref (`tobipjuk/deploy-workflows/.github/workflows/tf-apply.yml@refs/heads/main`),
not the caller's: that is what makes deploy-workflows the integrity anchor.

Template (the module's `oidc_sub_customization` output):

```json
{"use_default": false,
 "include_claim_keys": ["repo", "context", "event_name", "actor", "run_attempt", "job_workflow_ref"]}
```

Resulting subjects for `tobipjuk/starhuntercrew` (approver App slug `orion-approver` as an example):

| Run | sub |
|---|---|
| plan on push | `repo:tobipjuk/starhuntercrew:ref:refs/heads/main:event_name:push:actor:tobipjuk:run_attempt:1:job_workflow_ref:tobipjuk/deploy-workflows/.github/workflows/tf-plan.yml@refs/heads/main` |
| approved deploy | `repo:tobipjuk/starhuntercrew:ref:refs/heads/main:event_name:workflow_dispatch:actor:orion-approver[bot]:run_attempt:1:job_workflow_ref:tobipjuk/deploy-workflows/.github/workflows/tf-apply.yml@refs/heads/main` |

Both workflows print the `sub` of their token ("Show the OIDC subject" step; the token itself is
never printed), so a mismatch is easy to see.

### Applying it

The trust policies must exist **before** the template is switched on (otherwise the next run's
token matches nothing, which fails closed but is noisy). Order per repo:

1. Apply the project's CI stack (roles with the new trust).
2. Set the template (needs repo admin, i.e. Tobi's token, **before** the box's token loses admin):

   ```bash
   gh api -X PUT repos/tobipjuk/<repo>/actions/oidc/customization/sub \
     -H "Accept: application/vnd.github+json" \
     --input - <<'EOF'
   {"use_default": false,
    "include_claim_keys": ["repo", "context", "event_name", "actor", "run_attempt", "job_workflow_ref"]}
   EOF
   gh api repos/tobipjuk/<repo>/actions/oidc/customization/sub   # check
   ```

3. Push or dispatch `plan.yml` and read the printed `OIDC sub` line.

`run_attempt` in the sub is **required**; there is no fallback. Without it, a re-run of an
approved deploy run (re-runs keep `actor` = the App, and anyone with write access to the repo,
including the box, can re-run) would get deploy credentials again. If the API ever rejects the
template (422), stop: don't drop the claim, don't loosen the trust, keep deploys manual and
redesign. (The module has no switch for it on purpose.)

Rollback: `{"use_default": true}` restores `repo:<o>/<r>:ref:refs/heads/main` subjects (the
roles then accept nothing until their trust is changed back too).

## Trust policies (module `github-oidc-roles`)

Plan role: `StringEquals aud = sts.amazonaws.com`, and `StringLike sub` in

```
repo:<repo>:ref:refs/heads/main:event_name:push:actor:*:run_attempt:*:job_workflow_ref:tobipjuk/deploy-workflows/.github/workflows/tf-plan.yml@refs/heads/main
repo:<repo>:ref:refs/heads/main:event_name:workflow_dispatch:actor:*:run_attempt:*:job_workflow_ref:tobipjuk/deploy-workflows/.github/workflows/tf-plan.yml@refs/heads/main
```

The `*` stand only for the actor and the attempt. Because `job_workflow_ref` is the last claim
and colons inside values are encoded, the suffix pins the reusable workflow exactly. No PR
subjects: plans read state.

Deploy role: `StringEquals` on both `aud` and the one exact `sub`:

```
repo:<repo>:ref:refs/heads/main:event_name:workflow_dispatch:actor:<app-slug>[bot]:run_attempt:1:job_workflow_ref:tobipjuk/deploy-workflows/.github/workflows/tf-apply.yml@refs/heads/main
```

So a deploy credential needs all of: this repo, branch main, a `workflow_dispatch`, dispatched by
the approver App (whose private key is only on Orion's server), first attempt, and the job
running inside `tf-apply.yml` from deploy-workflows' main. Tobi's own token (and so the box)
can dispatch `deploy.yml`, but then `actor` is `tobipjuk` and AWS refuses.

## Site projects (`site-plan.yml` / `site-apply.yml`)

Same sub template, same rules; only the reusable workflow names differ (`docs/site-pipeline.md`):

```
plan role:   repo:<repo>:ref:refs/heads/main:event_name:push:actor:*:run_attempt:*:job_workflow_ref:tobipjuk/deploy-workflows/.github/workflows/site-plan.yml@refs/heads/main
             repo:<repo>:ref:refs/heads/main:event_name:workflow_dispatch:actor:*:run_attempt:*:job_workflow_ref:tobipjuk/deploy-workflows/.github/workflows/site-plan.yml@refs/heads/main
deploy role: repo:<repo>:ref:refs/heads/main:event_name:workflow_dispatch:actor:<app-slug>[bot]:run_attempt:1:job_workflow_ref:tobipjuk/deploy-workflows/.github/workflows/site-apply.yml@refs/heads/main
```

A site project's roles must never trust `tf-plan.yml`/`tf-apply.yml`, and a Terraform project's
never `site-plan.yml`/`site-apply.yml`. The module's `pipeline = "site"` (not built yet) will set
these; the identity policies are drafted by `scripts/site_iam.py`.
