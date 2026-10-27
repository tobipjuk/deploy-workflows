"""Static checks on the site workflows and the IAM drafts (scripts/site_iam.py)."""
import json
import re
import unittest
from pathlib import Path

import site_fakes as F  # noqa: E402
import site_iam  # noqa: E402
import site_policy as sp  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / ".github" / "workflows"


def policy():
    return sp.validate_policy(json.loads((F.POLICY_DIR / "tobipjuk" / "lego-mindstorms.json").read_text()))


class IamDraftTest(unittest.TestCase):
    def test_deploy_role_exactly_14_actions_and_notaction(self):
        doc = site_iam.deploy_policy(policy())
        allows = {a for s in doc["Statement"] if s["Effect"] == "Allow" for a in s["Action"]}
        self.assertEqual(len(site_iam.DEPLOY_ACTIONS), 14)
        self.assertEqual(allows, set(site_iam.DEPLOY_ACTIONS))
        deny = [s for s in doc["Statement"] if s.get("NotAction")]
        self.assertEqual(len(deny), 1)
        self.assertEqual(deny[0]["Effect"], "Deny")
        self.assertEqual(deny[0]["Resource"], "*")
        self.assertEqual(set(deny[0]["NotAction"]), set(site_iam.DEPLOY_ACTIONS))
        for s in doc["Statement"]:
            if s["Effect"] == "Allow":
                self.assertNotEqual(s["Resource"], "*", s["Sid"])

    def test_m2b_variant_adds_exactly_describe_key_value_store(self):
        arn = "arn:aws:cloudfront::880207437749:key-value-store/kvs-1"
        doc = site_iam.deploy_policy(policy(), kvs_arn=arn)
        deny = [s for s in doc["Statement"] if s.get("NotAction")][0]
        self.assertEqual(set(deny["NotAction"]) - set(site_iam.DEPLOY_ACTIONS), {"cloudfront:DescribeKeyValueStore"})
        dangerous = [s for s in doc["Statement"] if s["Sid"] == "DenyDangerous"][0]["Action"]
        self.assertNotIn("cloudfront:DescribeKeyValueStore", dangerous)
        self.assertIn("cloudfront-keyvaluestore:*", dangerous)

    def test_every_write_is_conditional(self):
        doc = site_iam.deploy_policy(policy())
        st = [s for s in doc["Statement"] if s["Sid"] == "DenyUnconditionalPut"][0]
        self.assertEqual(st["Condition"], {"Null": {"s3:if-match": "true", "s3:if-none-match": "true"}})

    def test_plan_role_reads_text_keys_only(self):
        doc = site_iam.plan_policy(policy())
        allows = {a for s in doc["Statement"] if s["Effect"] == "Allow" for a in s["Action"]}
        self.assertEqual(allows, set(site_iam.PLAN_ACTIONS))
        text = [s for s in doc["Statement"] if s["Sid"] == "SiteTextKeysOnly"][0]["Resource"]
        for r in text:
            self.assertTrue(re.search(r"\.(" + "|".join(sorted(sp.TEXT_EXTS)) + r")$", r), r)
        self.assertNotIn("arn:aws:s3:::ev3-workshop-880207437749/pages/*", text)
        self.assertIn("arn:aws:s3:::ev3-workshop-880207437749/pages/*.json", text)

    def test_sizes_fit_iam_limits(self):
        for doc in (site_iam.deploy_policy(policy()), site_iam.plan_policy(policy())):
            self.assertLess(len(json.dumps(doc, separators=(",", ":"))), 6144)

    def test_committed_drafts_are_current(self):
        d = ROOT / "docs" / "site-pipeline"
        self.assertEqual(json.loads((d / "lego-mindstorms-deploy-role.json").read_text()),
                         site_iam.deploy_policy(policy()))
        self.assertEqual(json.loads((d / "lego-mindstorms-plan-role.json").read_text()),
                         site_iam.plan_policy(policy()))


class WorkflowTest(unittest.TestCase):
    def test_site_plan_shape(self):
        s = (WF / "site-plan.yml").read_text()
        self.assertIn("    name: site plan\n", s)
        self.assertIn("uses: tobipjuk/deploy-workflows/.github/workflows/tf-attest.yml@main", s)
        self.assertIn("lfs: false", s)
        self.assertIn("persist-credentials: false", s)
        self.assertIn("working-directory: ${{ runner.temp }}", s)
        for line in re.findall(r"^(?!\s*#).*\$TOOLS/scripts/[a-z_]+\.py.*", s, re.M):
            self.assertIn("python3 -I", line)
        code = "\n".join(ln for ln in s.splitlines() if not ln.lstrip().startswith("#"))
        self.assertIsNone(re.search(r"git lfs|^\s*(uv|make|npm|npx|pip3?|bash|sh)\s", code, re.M))

    def test_site_apply_shape(self):
        s = (WF / "site-apply.yml").read_text()
        self.assertIn("check_plan_run.py\" --kind site", s)
        self.assertNotIn("actions/checkout", s)
        self.assertIn("--verify-only", s)
        self.assertLess(s.index("--verify-only"), s.index("Assume the deploy role"))
        self.assertIn("github.event.inputs.bundle_sha256", s)

    def test_tf_apply_refuses_other_kinds(self):
        s = (WF / "tf-apply.yml").read_text()
        self.assertIn("check_plan_run.py\" --kind terraform", s)
        self.assertIn("is not applied by tf-apply", s)

    def test_tf_attest_names_both_callers(self):
        s = (WF / "tf-attest.yml").read_text()
        self.assertIn("Called ONLY from tf-plan.yml and site-plan.yml", s)


if __name__ == "__main__":
    unittest.main()
