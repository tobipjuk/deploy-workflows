# Policy documents. Effective rights of a CI role = (identity policies AND ci-boundary) minus
# every Deny in guardrails / data-guard / plan-no-secrets. Effective rights of a role CI creates
# = its own policies AND lambda-boundary.

locals {
  state_bucket_arn = "arn:${local.partition}:s3:::${var.state_bucket}"
  # key and key.tflock (S3 native locking)
  state_object_arns = [for k in var.state_keys : "arn:${local.partition}:s3:::${var.state_bucket}/${k}*"]

  private_bucket_arns = [for b in var.private_bucket_names : "arn:${local.partition}:s3:::${b}"]
  private_object_arns = [for b in var.private_bucket_names : "arn:${local.partition}:s3:::${b}/*"]

  zone_arns = [for z in var.dns_zones : "arn:${local.partition}:route53:::hostedzone/${z.zone_id}"]
  # Route 53 condition keys carry normalised names: lowercase, no trailing dot. Normalise the
  # inputs the same way, or an FQDN like "example.com." would make the denies match nothing.
  protected_txt = distinct(concat(
    [for z in var.dns_zones : trimsuffix(lower(trimspace(z.apex)), ".")],
    [for n in var.protected_txt_names : trimsuffix(lower(trimspace(n)), ".")],
  ))
  protected_patterns = distinct([for n in var.protected_record_name_patterns : trimsuffix(lower(trimspace(n)), ".")])
  source_fn_pattern  = "arn:${local.partition}:lambda:${var.region}:${local.acct}:function:${local.p}-*"
  lambda_via         = "lambda.${var.region}.amazonaws.com"
  # Lambda env var encryption, on the caller's behalf, for the project's own functions only.
  lambda_env_kms_condition = {
    StringEquals = { "kms:ViaService" = local.lambda_via }
    StringLike   = { "kms:EncryptionContext:aws:lambda:FunctionArn" = local.source_fn_pattern }
  }
  lambda_env_kms_statements = var.plan_allow_lambda_env_decrypt ? [{
    Sid       = "LambdaEnvKmsOwnFunctions"
    Effect    = "Allow"
    Action    = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey", "kms:GenerateDataKeyWithoutPlaintext"]
    Resource  = "*"
    Condition = local.lambda_env_kms_condition
  }] : []

  # ---- CI boundary: the ceiling ----------------------------------------------------------
  ci_boundary_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid      = "ReadControlPlanes"
        Effect   = "Allow"
        Action   = var.read_actions
        Resource = "*"
      },
      {
        Sid       = "ListStateKeys"
        Effect    = "Allow"
        Action    = ["s3:ListBucket"]
        Resource  = local.state_bucket_arn
        Condition = { StringLike = { "s3:prefix" = [for k in var.state_keys : "${k}*"] } }
      },
      {
        Sid      = "OwnStateKeys"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = local.state_object_arns
      },
      {
        # Roles CI creates or changes: only under the Lambda path, only with the Lambda boundary.
        Sid       = "LambdaRolesWithLambdaBoundary"
        Effect    = "Allow"
        Action    = ["iam:CreateRole", "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:PutRolePermissionsBoundary"]
        Resource  = local.lambda_role_pattern
        Condition = { StringEquals = { "iam:PermissionsBoundary" = local.lambda_boundary_arn } }
      },
      {
        Sid      = "LambdaRolesHousekeeping"
        Effect   = "Allow"
        Action   = ["iam:DeleteRole", "iam:TagRole", "iam:UntagRole", "iam:UpdateRole", "iam:UpdateRoleDescription"]
        Resource = local.lambda_role_pattern
      },
      {
        Sid       = "PassLambdaRolesToLambda"
        Effect    = "Allow"
        Action    = ["iam:PassRole"]
        Resource  = local.lambda_role_pattern
        Condition = { StringEquals = { "iam:PassedToService" = "lambda.amazonaws.com" } }
      },
    ], local.lambda_env_kms_statements, var.boundary_statements)
  })

  # ---- Guardrails: explicit denies on both CI roles ------------------------------------------
  guardrails_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid    = "DenyOrgIdentityBillingAudit"
        Effect = "Deny"
        Action = [
          "organizations:*", "account:*", "sso:*", "sso-directory:*", "sso-oauth:*",
          "identitystore:*", "identitystore-auth:*",
          "iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
          "iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:AddUserToGroup",
          "iam:CreateServiceSpecificCredential", "iam:*OpenIDConnectProvider*", "iam:*SAMLProvider*",
          "iam:DeleteRolePermissionsBoundary", "iam:*AccountPasswordPolicy",
          # iam:PermissionsBoundary is not in UpdateAssumeRolePolicy's request context, so a
          # boundary condition can't guard it: trust policy changes are human-only.
          "iam:UpdateAssumeRolePolicy",
          "iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
          "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
          "cloudtrail:PutEventSelectors", "access-analyzer:Delete*", "access-analyzer:Update*",
          "aws-portal:*", "billing:*", "payments:*", "tax:*", "invoicing:*", "purchase-orders:*",
          "budgets:*", "ce:*", "cur:*",
          "sts:AssumeRole", "sts:GetFederationToken",
          "s3:PutAccountPublicAccessBlock", "route53domains:*", "route53:DeleteHostedZone",
        ]
        Resource = "*"
      },
      {
        Sid       = "DenyCiSelfModification"
        Effect    = "Deny"
        NotAction = ["iam:Get*", "iam:List*"]
        Resource  = concat(local.ci_role_arns, local.ci_policy_arns)
      },
      ], length(local.private_bucket_arns) == 0 ? [] : [
      {
        # Private data buckets stay private: no policy/ACL/public-access/ownership changes.
        Sid    = "DenyPrivateBucketExposure"
        Effect = "Deny"
        Action = [
          "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketAcl", "s3:PutObjectAcl",
          "s3:PutBucketPublicAccessBlock", "s3:PutBucketOwnershipControls",
        ]
        Resource = concat(local.private_bucket_arns, local.private_object_arns)
      },
      ], length(local.zone_arns) == 0 ? [] : [
      {
        # Mail routing, delegation and CA authorisation are human-only.
        Sid       = "DenyMailAndDelegationRecords"
        Effect    = "Deny"
        Action    = ["route53:ChangeResourceRecordSets"]
        Resource  = local.zone_arns
        Condition = { "ForAnyValue:StringEquals" = { "route53:ChangeResourceRecordSetsRecordTypes" = ["MX", "NS", "SOA", "CAA"] } }
      },
      {
        # SPF/verification TXT on the apex (and DMARC etc.). A batch that touches a protected
        # name and any TXT record is refused as a whole: fails closed.
        Sid      = "DenyProtectedTxtRecords"
        Effect   = "Deny"
        Action   = ["route53:ChangeResourceRecordSets"]
        Resource = local.zone_arns
        Condition = {
          "ForAnyValue:StringEquals" = {
            "route53:ChangeResourceRecordSetsRecordTypes"           = ["TXT"]
            "route53:ChangeResourceRecordSetsNormalizedRecordNames" = local.protected_txt
          }
        }
      },
      ], length(local.zone_arns) == 0 || length(local.protected_patterns) == 0 ? [] : [
      {
        Sid       = "DenyProtectedRecordNames"
        Effect    = "Deny"
        Action    = ["route53:ChangeResourceRecordSets"]
        Resource  = local.zone_arns
        Condition = { "ForAnyValue:StringLike" = { "route53:ChangeResourceRecordSetsNormalizedRecordNames" = local.protected_patterns } }
      },
    ])
  })

  # ---- Data guard: no reading of data, both CI roles ----------------------------------------
  data_guard_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid    = "DenyDataReads"
        Effect = "Deny"
        Action = [
          "dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan",
          "dynamodb:PartiQLSelect", "dynamodb:GetRecords", "dynamodb:GetShardIterator",
          "dynamodb:ExportTableToPointInTime", "dynamodb:RestoreTable*", "dynamodb:ImportTable",
          "dynamodb:CreateBackup",
          "logs:FilterLogEvents", "logs:GetLogEvents", "logs:StartQuery", "logs:GetQueryResults",
          "logs:StartLiveTail", "logs:GetLogRecord", "logs:CreateExportTask",
          "ses:ListContacts", "ses:GetContact", "ses:*SuppressedDestination*",
          "secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue",
        ]
        Resource = "*"
      },
      ], length(local.private_object_arns) == 0 ? [] : [
      {
        Sid      = "DenyPrivateObjects"
        Effect   = "Deny"
        Action   = ["s3:GetObject*", "s3:RestoreObject", "s3:ReplicateObject"]
        Resource = local.private_object_arns
      },
    ])
  })

  # ---- Plan role only: no secrets ---------------------------------------------------------------
  plan_secret_statements = concat(
    length(var.plan_secret_parameter_arns) == 0 ? [] : [{
      Sid      = "DenySecretParameters"
      Effect   = "Deny"
      Action   = ["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParameterHistory", "ssm:GetParametersByPath"]
      Resource = var.plan_secret_parameter_arns
    }],
    var.plan_deny_kms_decrypt && !var.plan_allow_lambda_env_decrypt ? [{
      Sid      = "DenyDecrypt"
      Effect   = "Deny"
      Action   = ["kms:Decrypt"]
      Resource = "*"
    }] : [],
    # Opt-in: deny every Decrypt that is not Lambda decrypting one of the project's own functions'
    # env vars. With the context key absent both conditions match, so all else stays denied.
    var.plan_deny_kms_decrypt && var.plan_allow_lambda_env_decrypt ? [
      {
        Sid       = "DenyDecryptExceptViaLambda"
        Effect    = "Deny"
        Action    = ["kms:Decrypt"]
        Resource  = "*"
        Condition = { StringNotEquals = { "kms:ViaService" = local.lambda_via } }
      },
      {
        Sid       = "DenyDecryptExceptOwnFunctionEnv"
        Effect    = "Deny"
        Action    = ["kms:Decrypt"]
        Resource  = "*"
        Condition = { StringNotLike = { "kms:EncryptionContext:aws:lambda:FunctionArn" = local.source_fn_pattern } }
      },
    ] : [],
    # The plan role's identity needs the allow as well (ReadOnlyAccess has no kms:Decrypt).
    var.plan_allow_lambda_env_decrypt ? [{
      Sid       = "AllowLambdaEnvDecryptOwnFunctions"
      Effect    = "Allow"
      Action    = ["kms:Decrypt"]
      Resource  = "*"
      Condition = local.lambda_env_kms_condition
    }] : [],
  )

  # ---- Deploy role writes (project statements) -------------------------------------------------
  deploy_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid      = "StateWriteAndLock"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:DeleteObject"]
        Resource = local.state_object_arns
      },
      {
        Sid       = "LambdaRolesWithLambdaBoundary"
        Effect    = "Allow"
        Action    = ["iam:CreateRole", "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:PutRolePermissionsBoundary"]
        Resource  = local.lambda_role_pattern
        Condition = { StringEquals = { "iam:PermissionsBoundary" = local.lambda_boundary_arn } }
      },
      {
        Sid      = "LambdaRolesHousekeeping"
        Effect   = "Allow"
        Action   = ["iam:DeleteRole", "iam:TagRole", "iam:UntagRole", "iam:UpdateRole", "iam:UpdateRoleDescription"]
        Resource = local.lambda_role_pattern
      },
      {
        Sid       = "PassLambdaRolesToLambda"
        Effect    = "Allow"
        Action    = ["iam:PassRole"]
        Resource  = local.lambda_role_pattern
        Condition = { StringEquals = { "iam:PassedToService" = "lambda.amazonaws.com" } }
      },
    ], local.lambda_env_kms_statements, var.deploy_statements)
  })

  # ---- Lambda boundary: what any role CI creates can ever do ---------------------------------
  lambda_boundary_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid      = "OwnLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:${local.partition}:logs:${var.region}:${local.acct}:log-group:/aws/lambda/${local.p}-*"
      },
      {
        Sid    = "DenyControlPlane"
        Effect = "Deny"
        Action = [
          "iam:*", "sts:AssumeRole*", "sts:GetFederationToken", "sts:GetSessionToken",
          "organizations:*", "account:*", "sso:*", "identitystore:*",
          "lambda:Create*", "lambda:Update*", "lambda:Delete*", "lambda:Add*", "lambda:Remove*", "lambda:Put*",
          "cloudtrail:*", "kms:Create*", "kms:Put*", "kms:Schedule*", "kms:Disable*",
        ]
        Resource = "*"
      },
      ], var.lambda_boundary_require_source_function ? [
      {
        # Credentials of these roles only work from inside the project's own functions.
        # Logs and KMS are exempt (service-side calls; still bounded by the allows).
        Sid       = "DenyOutsideOwnFunctions"
        Effect    = "Deny"
        NotAction = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "kms:Decrypt", "kms:GenerateDataKey*"]
        Resource  = "*"
        Condition = { ArnNotLike = { "lambda:SourceFunctionArn" = local.source_fn_pattern } }
      },
    ] : [], var.lambda_boundary_statements)
  })
}
