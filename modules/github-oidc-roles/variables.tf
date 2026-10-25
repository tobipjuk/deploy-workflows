# Inputs of the github-oidc-roles module. The caller (a project's small CI stack, applied by a
# human with SSO admin) owns the provider and the backend; this module only builds IAM.

variable "account_id" {
  description = "AWS account the roles live in (used in ARNs)."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be 12 digits."
  }
}

variable "region" {
  description = "Primary region of the project's stack (used for the Lambda boundary's source-function ARN pattern)."
  type        = string
}

variable "name_prefix" {
  description = "Prefix of every resource the project owns (e.g. shc). Role, boundary and Lambda role path names derive from it."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,20}$", var.name_prefix))
    error_message = "name_prefix: lowercase letters, digits and dashes, 2-21 chars."
  }
}

variable "project_tag" {
  description = "Value of the Project tag the project's resources carry (tag-conditioned deletes)."
  type        = string
}

# --- GitHub / trust ---------------------------------------------------------------

variable "github_repo" {
  description = "The repository as it appears in the OIDC sub (owner/name; with immutable subjects owner@ownerId/name@repoId)."
  type        = string
}

variable "github_branch" {
  description = "Branch whose runs may plan and deploy."
  type        = string
  default     = "main"
}

variable "deploy_workflows_repo" {
  description = "Repository holding the reusable workflows (the integrity anchor)."
  type        = string
  default     = "tobipjuk/deploy-workflows"
}

variable "deploy_workflows_ref" {
  description = "Ref of deploy-workflows the roles trust."
  type        = string
  default     = "refs/heads/main"
}

variable "approver_app_slug" {
  description = "Slug of Orion's approver GitHub App. The deploy role trusts only runs whose actor is <slug>[bot]. Required when create_deploy_role = true."
  type        = string
  default     = null
  validation {
    condition     = var.approver_app_slug == null || can(regex("^[a-z0-9][a-z0-9-]{0,62}$", var.approver_app_slug))
    error_message = "approver_app_slug must be a GitHub App slug (lowercase, digits, dashes)."
  }
}

variable "create_oidc_provider" {
  description = "true = create GitHub's OIDC provider; false = reuse the account's existing one (aws iam list-open-id-connect-providers)."
  type        = bool
  default     = false
}

variable "create_deploy_role" {
  description = "Create the deploy role. Keep false in an Organization management account (plan-only there)."
  type        = bool
  default     = false
}

variable "session_duration_seconds" {
  description = "Maximum session length of both CI roles."
  type        = number
  default     = 3600
}

# --- State ----------------------------------------------------------------------

variable "state_bucket" {
  description = "S3 bucket holding the project's Terraform state (may be shared with other projects)."
  type        = string
}

variable "state_keys" {
  description = "State keys the pipeline plans/applies (e.g. [\"prod/terraform.tfstate\"]). Plan reads them, deploy also writes them and their .tflock."
  type        = list(string)
}

# --- Data protection --------------------------------------------------------------

variable "plan_secret_parameter_arns" {
  description = "SSM parameter ARNs (wildcards ok) the PLAN role must never read. Note: the AWS provider decrypts on every refresh of aws_ssm_parameter, so the plan fails if the planned stack manages these parameters: move them to a human-applied secrets stack first (README, 'Secrets')."
  type        = list(string)
  default     = []
}

variable "plan_deny_kms_decrypt" {
  description = "Deny kms:Decrypt to the plan role everywhere (no SecureString or KMS-encrypted data reads). Set false only if the state bucket uses SSE-KMS."
  type        = bool
  default     = true
}

variable "plan_allow_lambda_env_decrypt" {
  description = <<-EOT
    Let Lambda decrypt function environment variables on the CI roles' behalf, for the project's
    own functions only (kms:ViaService = lambda.<region>.amazonaws.com AND encryption context
    aws:lambda:FunctionArn like arn:aws:lambda:<region>:<acct>:function:<prefix>-*). Without it
    the plan role's kms:Decrypt deny makes Lambda hide all env vars on refresh (perpetual diff),
    and the deploy role can't have Lambda encrypt changed env vars. Every other Decrypt stays
    denied to the plan role. Set true for projects whose Lambda functions have env vars.
  EOT
  type        = bool
  default     = false
}

variable "private_bucket_names" {
  description = "Buckets holding private data (backups, exports). CI may not read their objects or change their policy, ACL, public access block or ownership controls."
  type        = list(string)
  default     = []
}

variable "dns_zones" {
  description = "Hosted zones the project writes records into: zone id + apex name (lowercase, no trailing dot). MX/NS/SOA/CAA changes and TXT changes on the apex and protected_txt_names are denied."
  type = list(object({
    zone_id = string
    apex    = string
  }))
  default = []
  validation {
    condition     = alltrue([for z in var.dns_zones : can(regex("^[A-Za-z0-9.-]+\\.?$", trimspace(z.apex))) && can(regex("^Z[A-Z0-9]+$", z.zone_id))])
    error_message = "dns_zones: apex must be a DNS name (a trailing dot is fine, it is stripped) and zone_id a Route 53 zone id."
  }
}

variable "protected_txt_names" {
  description = "Extra record names (normalised: lowercase, no trailing dot) whose TXT records CI may not change, e.g. _dmarc.example.com."
  type        = list(string)
  default     = []
}

variable "protected_record_name_patterns" {
  description = "Record name patterns (StringLike, normalised) CI may not change at all, whatever the type, e.g. *._domainkey.example.com (a DKIM CNAME pointed elsewhere = mail spoofing)."
  type        = list(string)
  default     = []
}

# --- Project-specific permissions -------------------------------------------------

variable "read_actions" {
  description = "Control-plane read actions allowed by the CI boundary on all resources (Terraform refresh)."
  type        = list(string)
  default = [
    "acm:Describe*", "acm:Get*", "acm:List*", "apigateway:GET",
    "cloudfront:Describe*", "cloudfront:Get*", "cloudfront:List*",
    "cloudwatch:Describe*", "cloudwatch:List*", "dynamodb:Describe*", "dynamodb:List*",
    "events:Describe*", "events:List*", "iam:Get*", "iam:List*", "kms:DescribeKey",
    "lambda:List*", "logs:Describe*", "logs:List*", "route53:Get*", "route53:List*",
    "s3:ListAllMyBuckets", "ses:Describe*", "ses:Get*", "ses:List*", "sns:List*",
    "ssm:DescribeParameters", "sts:GetCallerIdentity", "tag:GetResources",
  ]
}

variable "boundary_statements" {
  description = "Project statements (IAM statement objects) added to the CI boundary: the ceiling for both CI roles, scoped to the project's own resources."
  type        = any
  default     = []
}

variable "deploy_statements" {
  description = "Project statements for the deploy role's write policy (inline, deploy-writes)."
  type        = any
  default     = []
}

variable "lambda_boundary_statements" {
  description = "Project statements added to the Lambda boundary: what the project's Lambda functions may do at runtime (data plane only)."
  type        = any
  default     = []
}

variable "lambda_boundary_require_source_function" {
  description = "Deny Lambda-role credentials used outside a <prefix>-* function (lambda:SourceFunctionArn), so a role with a widened trust policy is useless elsewhere. Logs and KMS writes/decrypts are exempt (bounded by the allows)."
  type        = bool
  default     = true
}
