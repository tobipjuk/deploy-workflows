# ---------------------------------------------------------------------------------------
# github-oidc-roles: the AWS side of the deploy-workflows pipeline for one project.
#
#   <p>-github-plan     read-only; trusts tf-plan.yml@main runs on main (push/dispatch)
#   <p>-github-deploy   scoped writes; trusts ONLY tf-apply.yml@main runs on main that were
#                       dispatched (workflow_dispatch) by Orion's approver App, first attempt
#   <p>-ci-boundary     permissions boundary (ceiling) of both CI roles
#   <p>-ci-guardrails   explicit denies on both CI roles (org/identity/billing/audit, trust
#                       policy edits, self-modification, private bucket exposure, mail DNS)
#   <p>-ci-data-guard   explicit denies on both CI roles: no data reads (items, objects, logs,
#                       contacts), plan role also no secrets
#   <p>-lambda-boundary ceiling for every role CI creates or changes: Lambda data plane only,
#                       no IAM/STS; such roles must live under path /<p>-lambda/
#   GitHub OIDC provider (optional; one per account)
#
# Applied by a human with SSO admin from the project's CI stack. Nothing in here is
# changeable by the CI roles themselves (no IAM allow outside /<p>-lambda/, plus a deny).
# ---------------------------------------------------------------------------------------

data "aws_partition" "current" {}

locals {
  partition = data.aws_partition.current.partition
  acct      = var.account_id
  p         = var.name_prefix

  oidc_host = "token.actions.githubusercontent.com"
  oidc_arn  = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.github[0].arn

  plan_role_name   = "${local.p}-github-plan"
  deploy_role_name = "${local.p}-github-deploy"
  ci_boundary_name = "${local.p}-ci-boundary"
  lambda_boundary  = "${local.p}-lambda-boundary"
  guardrails_name  = "${local.p}-ci-guardrails"
  data_guard_name  = "${local.p}-ci-data-guard"

  policy_arn_prefix   = "arn:${local.partition}:iam::${local.acct}:policy/"
  ci_boundary_arn     = "${local.policy_arn_prefix}${local.ci_boundary_name}"
  lambda_boundary_arn = "${local.policy_arn_prefix}${local.lambda_boundary}"

  lambda_role_path    = "/${local.p}-lambda/"
  lambda_role_pattern = "arn:${local.partition}:iam::${local.acct}:role${local.lambda_role_path}*"

  ci_role_arns = [
    "arn:${local.partition}:iam::${local.acct}:role/${local.plan_role_name}",
    "arn:${local.partition}:iam::${local.acct}:role/${local.deploy_role_name}",
  ]
  ci_policy_arns = [for n in [local.ci_boundary_name, local.lambda_boundary, local.guardrails_name, local.data_guard_name] : "${local.policy_arn_prefix}${n}"]

  # --- OIDC subjects ---------------------------------------------------------------------
  # Repo-level template (docs/oidc-trust.md): include_claim_keys in this order. GitHub renders
  # each claim as key:value joined by ':' (context renders as ref:refs/heads/<branch>), and
  # encodes ':' inside values as %3A. run_attempt is REQUIRED: the deploy role trusts attempt 1
  # only, so a re-run of an approved deploy (which keeps actor = the App) gets no credentials.
  sub_claim_keys = ["repo", "context", "event_name", "actor", "run_attempt", "job_workflow_ref"]

  wf_prefix        = "${var.deploy_workflows_repo}/.github/workflows"
  plan_wf_ref      = "${local.wf_prefix}/tf-plan.yml@${var.deploy_workflows_ref}"
  apply_wf_ref     = "${local.wf_prefix}/tf-apply.yml@${var.deploy_workflows_ref}"
  sub_head         = "repo:${var.github_repo}:ref:refs/heads/${var.github_branch}"
  plan_subjects    = [for ev in ["push", "workflow_dispatch"] : "${local.sub_head}:event_name:${ev}:actor:*:run_attempt:*:job_workflow_ref:${local.plan_wf_ref}"]
  deploy_subject   = var.approver_app_slug == null ? null : "${local.sub_head}:event_name:workflow_dispatch:actor:${var.approver_app_slug}[bot]:run_attempt:1:job_workflow_ref:${local.apply_wf_ref}"
  read_only_policy = "arn:${local.partition}:iam::aws:policy/ReadOnlyAccess"
}

# --- GitHub OIDC provider ------------------------------------------------------------------

data "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 0 : 1
  url   = "https://${local.oidc_host}"
}

resource "aws_iam_openid_connect_provider" "github" {
  count          = var.create_oidc_provider ? 1 : 0
  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
  # GitHub's root CA thumbprints (AWS no longer relies on these for GitHub, but the API wants them).
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd",
  ]
}

# --- Managed policies ----------------------------------------------------------------------

resource "aws_iam_policy" "ci_boundary" {
  name        = local.ci_boundary_name
  description = "Ceiling for ${local.p} CI roles: reads, own resources, own state, Lambda roles under ${local.lambda_role_path} only."
  policy      = local.ci_boundary_policy

  lifecycle {
    precondition {
      condition     = length(local.ci_boundary_policy) <= 6144
      error_message = "The CI boundary exceeds the 6,144-character managed policy limit: trim boundary_statements."
    }
  }
}

resource "aws_iam_policy" "lambda_boundary" {
  name        = local.lambda_boundary
  description = "Ceiling for ${local.p} Lambda execution roles (path ${local.lambda_role_path}): data plane only, no IAM/STS."
  policy      = local.lambda_boundary_policy

  lifecycle {
    precondition {
      condition     = length(local.lambda_boundary_policy) <= 6144
      error_message = "The Lambda boundary exceeds the 6,144-character managed policy limit."
    }
  }
}

resource "aws_iam_policy" "guardrails" {
  name        = local.guardrails_name
  description = "Explicit denies for ${local.p} CI roles: org/identity/billing/audit, trust edits, self-modification, bucket exposure, mail DNS."
  policy      = local.guardrails_policy

  lifecycle {
    precondition {
      condition     = length(local.guardrails_policy) <= 6144
      error_message = "The guardrails policy exceeds the 6,144-character managed policy limit."
    }
  }
}

resource "aws_iam_policy" "data_guard" {
  name        = local.data_guard_name
  description = "Explicit denies for ${local.p} CI roles: no table items, private objects, log events or contact lists."
  policy      = local.data_guard_policy
}

# --- Plan role -----------------------------------------------------------------------------

resource "aws_iam_role" "plan" {
  name                 = local.plan_role_name
  description          = "GitHub Actions terraform plan for ${var.github_repo}@${var.github_branch} via ${local.plan_wf_ref} (read-only)."
  max_session_duration = var.session_duration_seconds
  permissions_boundary = aws_iam_policy.ci_boundary.arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "GithubPlanOnMainViaTfPlan"
      Effect    = "Allow"
      Principal = { Federated = local.oidc_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "${local.oidc_host}:aud" = "sts.amazonaws.com" }
        StringLike   = { "${local.oidc_host}:sub" = local.plan_subjects }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "plan" {
  for_each = {
    read_only  = local.read_only_policy
    guardrails = aws_iam_policy.guardrails.arn
    data_guard = aws_iam_policy.data_guard.arn
  }
  role       = aws_iam_role.plan.name
  policy_arn = each.value
}

resource "aws_iam_role_policy" "plan_no_secrets" {
  count  = length(local.plan_secret_statements) > 0 ? 1 : 0
  name   = "plan-no-secrets"
  role   = aws_iam_role.plan.id
  policy = jsonencode({ Version = "2012-10-17", Statement = local.plan_secret_statements })
}

# --- Deploy role ---------------------------------------------------------------------------

resource "aws_iam_role" "deploy" {
  count                = var.create_deploy_role ? 1 : 0
  name                 = local.deploy_role_name
  description          = "GitHub Actions terraform apply for ${var.github_repo}: tf-apply.yml@main, dispatched by ${coalesce(var.approver_app_slug, "?")}[bot] only."
  max_session_duration = var.session_duration_seconds
  permissions_boundary = aws_iam_policy.ci_boundary.arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "GithubDeployApprovedByOrion"
      Effect    = "Allow"
      Principal = { Federated = local.oidc_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "${local.oidc_host}:aud" = "sts.amazonaws.com"
          "${local.oidc_host}:sub" = local.deploy_subject
        }
      }
    }]
  })

  lifecycle {
    precondition {
      condition     = var.approver_app_slug != null
      error_message = "create_deploy_role = true needs approver_app_slug (Orion's approver GitHub App)."
    }
  }
}

resource "aws_iam_role_policy_attachment" "deploy" {
  for_each = var.create_deploy_role ? {
    read_only  = local.read_only_policy
    guardrails = aws_iam_policy.guardrails.arn
    data_guard = aws_iam_policy.data_guard.arn
  } : {}
  role       = aws_iam_role.deploy[0].name
  policy_arn = each.value
}

resource "aws_iam_role_policy" "deploy_writes" {
  count  = var.create_deploy_role ? 1 : 0
  name   = "deploy-writes"
  role   = aws_iam_role.deploy[0].id
  policy = local.deploy_policy

  lifecycle {
    precondition {
      condition     = length(local.deploy_policy) <= 10240
      error_message = "deploy-writes exceeds the 10,240-character inline policy budget."
    }
  }
}
