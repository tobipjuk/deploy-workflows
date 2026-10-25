# Egress policies (one file per project repo)

`<owner>/<repo>.json` is the trusted egress and state configuration for that repository's
pipeline. tf-plan.yml and tf-apply.yml pick the file by `github.repository` (run context, not an
input); no file = the run is refused. It lives here, in deploy-workflows, because the project
repo (and its `plan.yml`) is writable by the box and runs without approval.

Fields: `schema` (1), `repository`, `account_id`, `region`, `state_bucket`, `state_region`,
`services` (regional API endpoint names), `global_hosts` (exact global or second-region API
hosts), `buckets` (the project's own dot-free bucket names), `s3_path_style` (keep false).
See scripts/egress_hosts.py for what each becomes and what is refused.

Onboarding a repo = a reviewed PR to deploy-workflows by Tobi adding its file.
