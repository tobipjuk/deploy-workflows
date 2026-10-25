"""Tests for scripts/plan_report.py. Stdlib only: python3 -m unittest discover -s tests"""
import importlib.util
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("plan_report", ROOT / "scripts" / "plan_report.py")
pr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pr)

SECRET = "s3cr3t-value-never-print"


def pr_rules():
    return pr.ATTENTION_RULES
ALLOW = str(ROOT / "policy" / "allowed-providers.txt")
AWS = "registry.terraform.io/hashicorp/aws"


def rc(address, *actions, before=None, after=None, bs=None, as_=None, unknown=None, provider=AWS):
    return {"address": address, "provider_name": provider, "change": {
        "actions": list(actions),
        "before": before if before is not None else {"value": SECRET},
        "after": after if after is not None else {"value": SECRET},
        "before_sensitive": bs if bs is not None else {},
        "after_sensitive": as_ if as_ is not None else {},
        "after_unknown": unknown if unknown is not None else {},
    }}


def plan(*changes, **extra):
    return {"format_version": "1.2", "resource_changes": list(changes), **extra}


class PlanReportTest(unittest.TestCase):
    def run_main(self, p, *extra):
        with tempfile.TemporaryDirectory() as d:
            pj = os.path.join(d, "plan.json")
            with open(pj, "w") as f:
                json.dump(p, f)
            summ, outs, js = (os.path.join(d, n) for n in ("summary.md", "out.txt", "ps.json"))
            out, err = StringIO(), StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = pr.main([pj, "--summary", summ, "--outputs", outs, "--json", js,
                                "--allowed-providers", ALLOW, *extra])
            with open(summ) as f:
                summary = f.read()
            with open(outs) as f:
                outputs = dict(line.split("=", 1) for line in f.read().splitlines())
            with open(js) as f:
                doc = json.load(f)
            return code, summary, outputs, out.getvalue() + err.getvalue(), doc

    def test_ar_v71_shape(self):
        p = plan(
            rc('module.app.aws_s3_object.site["assets/js/ar.js"]', "create"),
            rc('module.app.aws_s3_object.site["assets/js/sky.js"]', "create"),
            *[rc(f'module.app.aws_s3_object.site["f{i}"]', "update",
                 before={"etag": f"old{i}", "content": SECRET}, after={"etag": f"new{i}", "content": SECRET + "2"})
              for i in range(4)],
            rc('module.static_site.aws_s3_object.site["privacy/index.html"]', "update"),
            rc("module.dns.aws_route53_zone.primary", "no-op"),
            rc("data.aws_caller_identity.current", "read"),
        )
        code, summary, o, log, doc = self.run_main(p)
        self.assertEqual(code, 0)
        self.assertEqual((o["add"], o["change"], o["destroy"], o["replace"]), ("2", "5", "0", "0"))
        self.assertEqual((o["has_changes"], o["destructive"], o["blocked"]), ("true", "false", "false"))
        self.assertIn("2 to add, 5 to change, 0 to destroy, 0 to replace", summary)
        self.assertEqual(len(doc["changes"]), 7)
        self.assertEqual(doc["changes_digest"], o["digest"])
        attrs = {a["path"]: a for d in doc["diff"] for a in d["attrs"]}
        self.assertEqual(attrs["etag"]["after"], '"new3"')
        self.assertEqual(attrs["content"]["after"], "(hidden)")
        blob = summary + log + json.dumps(doc)
        self.assertNotIn(SECRET, blob)

    def test_sensitive_masks_hide_values(self):
        p = plan(rc("aws_lambda_function.f", "update",
                    before={"memory_size": 128, "tags": {"a": "x"}, "opaque": "old-" + SECRET},
                    after={"memory_size": 256, "tags": {"a": "y"}, "opaque": "new-" + SECRET},
                    bs={"opaque": True}, as_={"opaque": True}))
        code, _, _, log, doc = self.run_main(p)
        self.assertEqual(code, 0)
        attrs = {a["path"]: a for a in doc["diff"][0]["attrs"]}
        self.assertEqual(attrs["memory_size"]["after"], "256")
        self.assertEqual(attrs["tags.a"]["after"], '"y"')
        self.assertEqual(attrs["opaque"]["after"], "(hidden)")
        self.assertNotIn(SECRET, json.dumps(doc) + log)

    def test_whole_object_sensitive_and_unknown(self):
        p = plan(rc("aws_ssm_parameter.p", "update", before={"value": SECRET, "version": 1},
                    after={"value": SECRET + "x", "version": None}, bs=True, as_=True),
                 rc("aws_lambda_function.g", "update", before={"version": "3"}, after={"version": None},
                    unknown={"version": True}))
        _, _, _, log, doc = self.run_main(p)
        by = {d["address"]: d["attrs"] for d in doc["diff"]}
        self.assertTrue(all(a["after"] == "(hidden)" for a in by["aws_ssm_parameter.p"]))
        self.assertEqual(by["aws_lambda_function.g"][0]["after"], "(known after apply)")
        self.assertNotIn(SECRET, json.dumps(doc) + log)

    def test_name_filter_hides_unmasked_secrets(self):
        p = plan(rc("aws_lambda_function.f", "update",
                    before={"environment": [{"variables": {"API_KEY": SECRET}}], "admin_token": "a" + SECRET},
                    after={"environment": [{"variables": {"API_KEY": SECRET + "2"}}], "admin_token": "b" + SECRET}))
        _, _, _, log, doc = self.run_main(p)
        self.assertTrue(all(a["after"] == "(hidden)" for a in doc["diff"][0]["attrs"]))
        self.assertNotIn(SECRET, json.dumps(doc) + log)

    def test_long_values_and_many_attrs_truncated(self):
        before = {f"a{i}": "x" * 200 for i in range(20)}
        after = {f"a{i}": "y" * 200 for i in range(20)}
        _, _, _, _, doc = self.run_main(plan(rc("x.y", "update", before=before, after=after)))
        attrs = doc["diff"][0]["attrs"]
        self.assertEqual(len(attrs), pr.MAX_DIFF_ATTRS + 1)
        self.assertTrue(doc["diff_truncated"])
        self.assertLessEqual(len(attrs[0]["after"]), pr.MAX_VALUE_CHARS)

    def test_no_changes(self):
        code, summary, o, _, doc = self.run_main(plan(rc("a.b", "no-op")))
        self.assertEqual(code, 0)
        self.assertEqual(o["has_changes"], "false")
        self.assertFalse(doc["has_changes"])
        self.assertIn("No changes", summary)

    def test_destroy_replace_unknown_fail_closed(self):
        for actions in (["delete"], ["delete", "create"], ["create", "delete"], ["mystery"], []):
            code, _, o, log, _ = self.run_main(plan(rc("module.ops.aws_s3_bucket.backups", *actions)))
            self.assertEqual(code, 3, actions)
            self.assertEqual(o["destructive"], "true")
            self.assertIn("allow_destroy", log)

    def test_null_or_missing_actions_destructive(self):
        for change in ({"actions": None}, {}, None):
            p = plan({"address": "a.b", "change": change})
            code, _, o, _, _ = self.run_main(p)
            self.assertEqual(code, 3, change)
            self.assertEqual(o["destructive"], "true")

    def test_action_invocations_and_deferred_destructive(self):
        for extra in ({"action_invocations": [{"address": "action.aws_lambda_invoke.x"}]},
                      {"deferred_changes": [{"reason": "provider_config_unknown"}]},
                      {"complete": False}):
            code, _, o, _, doc = self.run_main(plan(rc("a.b", "update", before={"x": 1}, after={"x": 2}), **extra))
            self.assertEqual(code, 3, extra)
            self.assertEqual(o["destructive"], "true")
            self.assertTrue(doc["flags"])

    def test_action_invocations_alone_count_as_changes(self):
        code, _, o, _, _ = self.run_main(plan(action_invocations=[{"address": "action.x.y"}]))
        self.assertEqual(o["has_changes"], "true")
        self.assertEqual(code, 3)

    def test_destroy_allowed(self):
        code, _, o, _, _ = self.run_main(plan(rc("x.y", "delete")), "--allow-destroy", "true")
        self.assertEqual(code, 0)
        self.assertEqual(o["destroy"], "1")

    def test_digest_binding(self):
        p = plan(rc("a.b", "update"), rc("c.d", "create"))
        _, _, o, _, _ = self.run_main(p)
        code, *_ = self.run_main(p, "--expect-digest", o["digest"])
        self.assertEqual(code, 0)
        code, _, _, log, _ = self.run_main(p, "--expect-digest", "0" * 64)
        self.assertEqual(code, 5)
        self.assertIn("digest", log)
        # order of resource_changes does not matter, actions do
        p2 = plan(rc("c.d", "create"), rc("a.b", "update"))
        self.assertEqual(self.run_main(p2)[2]["digest"], o["digest"])
        p3 = plan(rc("a.b", "update"), rc("c.d", "delete", "create"))
        self.assertNotEqual(self.run_main(p3)[2]["digest"], o["digest"])

    def test_digest_is_canonical_json(self):
        changes = [{"address": "a.b", "actions": ["update"]}]
        import hashlib
        self.assertEqual(pr.digest(changes), hashlib.sha256(
            b'[{"actions":["update"],"address":"a.b"}]').hexdigest())

    def test_provisioner_blocked(self):
        p = plan(rc("terraform_data.x", "create", provider="terraform.io/builtin/terraform"),
                 configuration={"root_module": {"module_calls": {"m": {"module": {"resources": [
                     {"address": "terraform_data.x", "mode": "managed", "type": "terraform_data",
                      "provisioners": [{"type": "local-exec"}]}]}}}}})
        code, summary, o, log, doc = self.run_main(p, "--allow-destroy", "true")
        self.assertEqual(code, 4)
        self.assertEqual(o["blocked"], "true")
        self.assertTrue(any("module.m.terraform_data.x" in b and "local-exec" in b for b in doc["blocked"]))

    def test_external_data_source_blocked(self):
        p = plan(rc("a.b", "update"), configuration={"root_module": {"resources": [
            {"address": "data.external.x", "mode": "data", "type": "external"}]}})
        code, _, _, _, doc = self.run_main(p)
        self.assertEqual(code, 4)
        self.assertTrue(any("external" in b for b in doc["blocked"]))

    def test_provider_outside_allowlist_blocked(self):
        p = plan(rc("evil_thing.x", "create", provider="registry.terraform.io/evil/evil"),
                 configuration={"provider_config": {"aws": {"full_name": AWS}}})
        code, _, _, _, doc = self.run_main(p)
        self.assertEqual(code, 4)
        self.assertEqual(doc["blocked"], ["provider not in the allowlist: registry.terraform.io/evil/evil"])

    def test_meta_in_json(self):
        _, _, _, _, doc = self.run_main(plan(rc("a.b", "update")), "--meta", "run_id=123",
                                        "--meta", "deployable=true", "--meta", "bundle_sha256=null",
                                        "--meta", "commit_subject=App: x = y")
        self.assertEqual(doc["run_id"], 123)
        self.assertIs(doc["deployable"], True)
        self.assertIsNone(doc["bundle_sha256"])
        self.assertEqual(doc["commit_subject"], "App: x = y")
        self.assertEqual(doc["schema"], 1)

    # --- needs attention (Guardian M2) ---------------------------------------------------------
    def tc(self, rtype, name, *actions, **kw):
        r = rc(f"{rtype}.{name}", *actions, **kw)
        r["type"] = rtype
        return r

    def test_attention_flags_risky_changes(self):
        p = plan(
            self.tc("aws_apigatewayv2_integration", "api", "update",
                    before={"integration_uri": "arn:aws:lambda:eu-west-2:1:function:shc-api"},
                    after={"integration_uri": "https://evil.example/collect"}),
            self.tc("aws_cloudfront_distribution", "site", "update",
                    before={"origin": [{"domain_name": "shc-site.s3.amazonaws.com", "origin_id": "s3"}]},
                    after={"origin": [{"domain_name": "attacker.example.net", "origin_id": "s3"}]}),
            self.tc("aws_lambda_permission", "public", "create", before={},
                    after={"principal": "*", "action": "lambda:InvokeFunction"}),
            self.tc("aws_s3_bucket_policy", "backups", "create", before={}, after={"policy": "{}"}),
            self.tc("aws_iam_role", "lambda", "update", before={"assume_role_policy": "a", "name": "r"},
                    after={"assume_role_policy": "b", "name": "r"}),
            self.tc("aws_lambda_function", "api", "update",
                    before={"environment": [{"variables": {"TOKEN": SECRET}}], "memory_size": 128},
                    after={"environment": [{"variables": {"TOKEN": SECRET + "x"}}], "memory_size": 128}),
            self.tc("aws_s3_object", "site", "update", before={"etag": "a"}, after={"etag": "b"}),
        )
        code, summary, o, log, doc = self.run_main(p)
        self.assertEqual(code, 0)
        by = {(a["address"], a["path"]): a for a in doc["attention"]}
        self.assertEqual(by[("aws_apigatewayv2_integration.api", "integration_uri")]["after"],
                         "https://evil.example/collect")
        self.assertEqual(by[("aws_cloudfront_distribution.site", "origin[0].domain_name")]["after"],
                         "attacker.example.net")
        self.assertEqual(by[("aws_lambda_permission.public", "principal")]["after"], "*")
        self.assertIn(("aws_s3_bucket_policy.backups", None), by)
        self.assertEqual(by[("aws_iam_role.lambda", "assume_role_policy")]["after"], "(changed, value not shown)")
        env = by[("aws_lambda_function.api", "environment[0].variables.TOKEN")]
        self.assertEqual(env["after"], "(changed, value not shown)")
        self.assertFalse(any(a["address"] == "aws_s3_object.site" for a in doc["attention"]))
        self.assertEqual(o["attention"], str(len(doc["attention"])))
        self.assertIn("Needs attention", summary)
        self.assertIn("attacker.example.net", summary)
        self.assertNotIn(SECRET, json.dumps(doc) + summary + log)

    def test_attention_respects_sensitivity_and_does_not_change_digest(self):
        base = [self.tc("aws_s3_object", "o", "update", before={"etag": "a"}, after={"etag": "b"})]
        risky = self.tc("aws_apigatewayv2_integration", "api", "update",
                        before={"integration_uri": "x"}, after={"integration_uri": "y"},
                        bs={"integration_uri": True}, as_={"integration_uri": True})
        _, _, o1, _, d1 = self.run_main(plan(*base, self.tc("aws_apigatewayv2_integration", "api", "update",
                                                             before={"integration_uri": "x"}, after={"integration_uri": "z"})))
        _, _, o2, _, d2 = self.run_main(plan(*base, risky))
        self.assertEqual(o1["digest"], o2["digest"])  # digest binds addresses + actions only
        self.assertEqual(d2["attention"][0]["after"], "(hidden)")

    def test_attention_never_shows_secret_capable_values(self):
        p = plan(
            self.tc("aws_apigatewayv2_integration", "api", "update",
                    before={"integration_uri": "https://ok.example/hook"},
                    after={"integration_uri": f"https://evil.example/c?token={SECRET}#{SECRET}"}),
            self.tc("aws_sns_topic_subscription", "s", "create", before={},
                    after={"endpoint": f"https://u:{SECRET}@evil.example/p", "protocol": "https"}),
            self.tc("aws_route53_record", "txt", "create", before={},
                    after={"name": "x.example.com", "type": "TXT", "records": [SECRET]}),
            self.tc("aws_lambda_function", "f", "update",
                    before={"environment": [{"variables": {"PLAIN": "a"}}]},
                    after={"environment": [{"variables": {"PLAIN": SECRET}}]}),
            self.tc("aws_iam_role_policy", "p", "update", before={"policy": "{}"},
                    after={"policy": '{"Sid":"' + SECRET + '"}'}),
            self.tc("aws_iam_role", "r", "update", before={"assume_role_policy": "{}"},
                    after={"assume_role_policy": '{"x":"' + SECRET + '"}'}),
            self.tc("aws_cloudfront_distribution", "d", "update",
                    before={"origin": [{"domain_name": "a.example"}]},
                    after={"origin": [{"domain_name": "b.example"}]},
                    as_={"origin": [{"domain_name": True}]}),
        )
        code, summary, o, log, doc = self.run_main(p)
        self.assertEqual(code, 0)
        blob = json.dumps(doc) + summary + log
        self.assertNotIn(SECRET, blob)
        by = {(a["address"], a["path"]): a for a in doc["attention"]}
        self.assertEqual(by[("aws_apigatewayv2_integration.api", "integration_uri")]["after"],
                         "https://evil.example/c?…#…")
        self.assertEqual(by[("aws_sns_topic_subscription.s", "endpoint")]["after"], "https://…@evil.example/p")
        self.assertEqual(by[("aws_route53_record.txt", "records[0]")]["after"], "(changed, value not shown)")
        self.assertEqual(by[("aws_cloudfront_distribution.d", "origin[0].domain_name")]["after"], "(hidden)")

    def test_rule_review(self):
        # Every show=True rule names things only; secret-capable paths are show=False.
        secret_capable = ("policy", "assume_role_policy", "environment[0].variables.X", "records[0]")
        for _, path_re, label, show in pr_rules():
            if show:
                for path in secret_capable:
                    self.assertIsNone(path_re.match(path), (label, path))

    def test_attention_unchanged_paths_not_flagged(self):
        p = plan(self.tc("aws_cloudfront_distribution", "d", "update",
                         before={"origin": [{"domain_name": "same"}], "comment": "a"},
                         after={"origin": [{"domain_name": "same"}], "comment": "b"}))
        _, _, _, _, doc = self.run_main(p)
        self.assertEqual(doc["attention"], [])

    def test_bad_input(self):
        with tempfile.TemporaryDirectory() as d:
            pj = os.path.join(d, "plan.json")
            for body in ("not json", "[]", json.dumps({"format_version": "1.2", "errored": True})):
                with open(pj, "w") as f:
                    f.write(body)
                with redirect_stderr(StringIO()), redirect_stdout(StringIO()):
                    self.assertEqual(pr.main([pj]), 2, body)


if __name__ == "__main__":
    unittest.main()
