# Site policies (one file per project repo using site-plan.yml / site-apply.yml)

`<owner>/<repo>.json` is the trusted configuration of that repository's site pipeline: account,
region, bucket, the keys and prefixes the site may use (SITE), the manifest location, the Lambda
and its member allowlist, the gate (CloudFront Function) and its test cases, the distribution,
the smoke checks. site-plan.yml and site-apply.yml pick the file by `github.repository` (run
context, not an input); no file = the run is refused. It lives here because the project repo is
writable by the box and its `plan.yml` runs without approval.

Schema and rules: `docs/site-pipeline.md` and `scripts/site_policy.py` (`check-policy`). Example:
`tests/fixtures/site/policy/tobipjuk/lego-mindstorms.json`. Changing a file changes what the next
plan may do, and any plan made before the change can no longer be applied (the bundle records
the policy file's sha256).

Onboarding a repo = a reviewed PR to deploy-workflows by Tobi adding its file.
