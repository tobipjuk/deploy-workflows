"""Tests for scripts/deploy_result.py (deploy-result.json status, orion-interface §8)."""
import importlib.util
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("deploy_result", ROOT / "scripts" / "deploy_result.py")
dr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dr)

ENV = {"APPLY_OUTCOME": "success", "ADD": "2", "CHANGE": "5", "DESTROY": "0", "REPLACE": "0",
       "TARGET": "starhuntercrew", "GITHUB_REPOSITORY": "tobipjuk/starhuntercrew", "GITHUB_SHA": "a" * 40,
       "GITHUB_RUN_ID": "99", "PLAN_RUN_ID": "42", "BUNDLE_SHA256": "b" * 64, "CHANGES_DIGEST": "c" * 64}


class DeployResultTest(unittest.TestCase):
    def run_with(self, env, checks):
        with tempfile.TemporaryDirectory() as d:
            cd = os.path.join(d, "checks")
            os.makedirs(cd)
            for k, v in checks.items():
                Path(cd, k).write_text(v + "\n")
            out, gh = os.path.join(d, "r.json"), os.path.join(d, "gh")
            old = dict(os.environ)
            os.environ.update(env)
            try:
                with redirect_stdout(StringIO()):
                    dr.main(["--checks-dir", cd, "--out", out, "--github-output", gh])
            finally:
                os.environ.clear()
                os.environ.update(old)
            return json.loads(Path(out).read_text()), Path(gh).read_text()

    def test_deployed(self):
        doc, gh = self.run_with(ENV, {"egress": "ok", "invalidation": "ok", "smoke": "ok"})
        self.assertEqual((doc["status"], doc["applied"]), ("deployed", True))
        self.assertEqual(doc["counts"], {"add": 2, "change": 5, "destroy": 0, "replace": 0})
        self.assertIn("result=deployed", gh)
        self.assertEqual(doc["schema"], 2)

    def test_skipped_checks_are_fine(self):
        doc, _ = self.run_with(ENV, {"egress": "ok"})
        self.assertEqual(doc["status"], "deployed")
        self.assertEqual(doc["checks"]["smoke"], "skipped")

    def test_applied_with_warnings(self):
        for checks, text in (({"egress": "warning", "invalidation": "ok", "smoke": "ok"}, "applied, egress warning"),
                             ({"egress": "ok", "invalidation": "pending", "smoke": "ok"}, "applied, invalidation pending"),
                             ({"egress": "ok", "invalidation": "ok", "smoke": "failed"}, "applied, smoke failed")):
            doc, _ = self.run_with(ENV, checks)
            self.assertEqual(doc["status"], "deployed_with_warnings", checks)
            self.assertTrue(doc["applied"])
            self.assertEqual(doc["summary"], text)

    def test_not_applied_is_failed(self):
        for outcome in ("failure", "skipped", "cancelled", ""):
            doc, gh = self.run_with(dict(ENV, APPLY_OUTCOME=outcome), {"egress": "warning"})
            self.assertEqual((doc["status"], doc["applied"]), ("failed", False), outcome)
            self.assertIn("result=failed", gh)

    def test_garbage_check_value_counts_as_failed(self):
        doc, _ = self.run_with(ENV, {"smoke": "rm -rf"})
        self.assertEqual(doc["checks"]["smoke"], "failed")
        self.assertEqual(doc["status"], "deployed_with_warnings")



class PartialTest(unittest.TestCase):
    def test_partial_site_apply_is_failed_with_a_note(self):
        status, text = dr.summarise(False, {}, partial=True)
        self.assertEqual(status, "failed")
        self.assertIn("partially applied", text)
        self.assertEqual(dr.build({"APPLY_OUTCOME": "failure", "PARTIAL": "true"}, {})["status"], "failed")


if __name__ == "__main__":
    unittest.main()
