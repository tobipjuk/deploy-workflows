# Offline tests (mock provider, plan only): terraform init -backend=false && terraform test

mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
}

variables {
  account_id           = "123456789012"
  region               = "eu-west-2"
  name_prefix          = "tst"
  project_tag          = "test-project"
  github_repo          = "tobipjuk/example"
  approver_app_slug    = "orion-approver"
  create_oidc_provider = true
  create_deploy_role   = true
  state_bucket         = "tst-state"
  state_keys           = ["prod/terraform.tfstate"]
  private_bucket_names = ["tst-backups"]
  # FQDN trailing dots and upper case on purpose: the denies must still match normalised names.
  dns_zones                      = [{ zone_id = "Z0123456789ABC", apex = "Example.COM." }]
  protected_txt_names            = ["_DMARC.example.com."]
  protected_record_name_patterns = ["*._domainkey.Example.com."]
}

run "dns_names_are_normalised" {
  command = plan

  assert {
    condition = (
      [for s in jsondecode(aws_iam_policy.guardrails.policy).Statement : s.Condition["ForAnyValue:StringEquals"]["route53:ChangeResourceRecordSetsNormalizedRecordNames"] if s.Sid == "DenyProtectedTxtRecords"][0]
      == ["example.com", "_dmarc.example.com"]
    )
    error_message = "Protected TXT names must be lowercase without a trailing dot."
  }

  assert {
    condition = (
      [for s in jsondecode(aws_iam_policy.guardrails.policy).Statement : s.Condition["ForAnyValue:StringLike"]["route53:ChangeResourceRecordSetsNormalizedRecordNames"] if s.Sid == "DenyProtectedRecordNames"][0]
      == ["*._domainkey.example.com"]
    )
    error_message = "Protected name patterns must be lowercase without a trailing dot."
  }
}

run "subjects_pin_workflow_and_attempt" {
  command = plan

  assert {
    condition     = output.deploy_subject == "repo:tobipjuk/example:ref:refs/heads/main:event_name:workflow_dispatch:actor:orion-approver[bot]:run_attempt:1:job_workflow_ref:tobipjuk/deploy-workflows/.github/workflows/tf-apply.yml@refs/heads/main"
    error_message = "Deploy subject must pin actor, workflow_dispatch, attempt 1 and tf-apply.yml@main."
  }

  assert {
    condition     = jsondecode(output.oidc_sub_customization).include_claim_keys == ["repo", "context", "event_name", "actor", "run_attempt", "job_workflow_ref"]
    error_message = "The sub template must include run_attempt."
  }

  assert {
    condition     = alltrue([for s in output.plan_subjects : endswith(s, ":run_attempt:*:job_workflow_ref:tobipjuk/deploy-workflows/.github/workflows/tf-plan.yml@refs/heads/main")])
    error_message = "Plan subjects must end with tf-plan.yml@main."
  }
}

run "deploy_role_needs_app_slug" {
  command = plan

  variables {
    approver_app_slug = null
  }

  expect_failures = [aws_iam_role.deploy]
}
