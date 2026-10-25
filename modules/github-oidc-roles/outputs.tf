output "plan_role_arn" {
  description = "Repository variable AWS_PLAN_ROLE_ARN."
  value       = aws_iam_role.plan.arn
}

output "deploy_role_arn" {
  description = "Repository variable AWS_DEPLOY_ROLE_ARN (null while create_deploy_role = false)."
  value       = one(aws_iam_role.deploy[*].arn)
}

output "ci_boundary_arn" {
  description = "Permissions boundary of both CI roles."
  value       = aws_iam_policy.ci_boundary.arn
}

output "lambda_boundary_arn" {
  description = "Boundary every role CI creates or changes must carry. Put it on the project's Lambda roles (permissions_boundary)."
  value       = aws_iam_policy.lambda_boundary.arn
}

output "lambda_role_path" {
  description = "IAM path the project's Lambda roles must use (path = ...) so CI may manage them."
  value       = local.lambda_role_path
}

output "github_oidc_provider_arn" {
  description = "GitHub OIDC provider the roles trust."
  value       = local.oidc_arn
}

output "plan_subjects" {
  description = "OIDC sub patterns the plan role accepts (StringLike)."
  value       = local.plan_subjects
}

output "deploy_subject" {
  description = "The only OIDC sub the deploy role accepts (StringEquals)."
  value       = local.deploy_subject
}

output "oidc_sub_customization" {
  description = "Body for PUT /repos/{owner}/{repo}/actions/oidc/customization/sub (docs/oidc-trust.md)."
  value       = jsonencode({ use_default = false, include_claim_keys = local.sub_claim_keys })
}

output "policy_sizes" {
  description = "Characters used per policy (managed limit 6,144; inline budget 10,240 per role)."
  value = {
    ci_boundary     = length(local.ci_boundary_policy)
    lambda_boundary = length(local.lambda_boundary_policy)
    guardrails      = length(local.guardrails_policy)
    data_guard      = length(local.data_guard_policy)
    deploy_writes   = length(local.deploy_policy)
  }
}
