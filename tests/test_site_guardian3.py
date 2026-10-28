"""Guardian review of origin/main..fff80e5: M1 (Lambda env var names unreadable under the plan
role's kms:Decrypt deny)."""
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

import site_fakes as F  # noqa: E402
import site_aws  # noqa: E402
import site_diff as sd  # noqa: E402
import site_plan  # noqa: E402
from test_site_apply import run_apply  # noqa: E402
from test_site_plan import adopt, labels, outputs, run_plan, summary  # noqa: E402

BUCKET = "ev3-workshop-880207437749"
FN = "ev3-workshop-progress-api"


class EnvNamesUnreadableTest(unittest.TestCase):
    """M1: the plan role can't decrypt the Lambda environment, so Lambda returns
    Environment.Error instead of Variables. The names are then not compared (not a mismatch)
    and the card says they weren't verified."""

    def setUp(self):
        self.env = F.Env(self)
        adopt(self.env)
        self.env.commit({"site/index.html": b"<!doctype html>\n<p>v2</p>\n"})

    def test_unreadable_names_are_not_a_mismatch_and_are_shown(self):
        rc, log = run_plan(self.env, event="push")
        self.assertEqual(rc, 0, log)
        doc = summary(self.env)
        self.assertTrue(doc["deployable"], doc["site"]["not_deployable"])
        self.assertNotIn("Settings mismatch", labels(doc))
        self.assertEqual(doc["site"]["settings_mismatch"], [])
        self.assertEqual(doc["site"]["settings_unverified"], ["env_names"])
        att = [a for a in doc["attention"] if a["label"] == "Lambda env var names unreadable"]
        self.assertEqual(len(att), 1)
        self.assertEqual(att[0]["address"], f"lambda:{FN}")
        self.assertIn("env var names unreadable (KMS denied: AccessDeniedException)", att[0]["after"])

    def test_other_settings_still_compared_when_names_unreadable(self):
        sj = F.site_json()
        sj["lambda_settings"]["memory_size"] = 512
        self.env.commit({"deploy/site.json": json.dumps(sj).encode()})
        rc, log = run_plan(self.env, event="push")
        doc = summary(self.env)
        self.assertFalse(doc["deployable"])
        self.assertEqual([b["field"] for b in doc["site"]["settings_mismatch"]], ["memory_size"])

    def test_readable_names_are_compared(self):
        self.env.aws.lambda_env_readable = True
        sj = F.site_json()
        sj["lambda_settings"]["env_names"] = ["TABLE"]
        self.env.commit({"deploy/site.json": json.dumps(sj).encode()})
        rc, log = run_plan(self.env, event="push")
        doc = summary(self.env)
        self.assertFalse(doc["deployable"])
        self.assertEqual([b["field"] for b in doc["site"]["settings_mismatch"]], ["env_names"])
        self.assertEqual(doc["site"]["settings_unverified"], [])
        self.assertNotIn("Lambda env var names unreadable", labels(doc))

    def test_readable_matching_names_no_entry(self):
        self.env.aws.lambda_env_readable = True
        rc, log = run_plan(self.env, event="push")
        doc = summary(self.env)
        self.assertTrue(doc["deployable"], doc["site"]["not_deployable"])
        self.assertEqual(doc["site"]["settings_unverified"], [])

    def test_check_settings_unit(self):
        live = {"runtime": "python3.13", "handler": "progress.handler", "memory_size": 256, "timeout": 10,
                "architectures": ["arm64"], "env_names": [], "env_error": "AccessDeniedException",
                "layers": None, "vpc_id": None, "kms_key_arn": None, "package_type": "Zip",
                "state": "Active", "last_update_status": "Successful"}
        self.assertEqual(sd.check_settings(F.LAMBDA_SETTINGS, live), [])
        self.assertEqual(sd.env_names_error(live), "AccessDeniedException")
        live["env_error"] = None
        self.assertEqual([b["field"] for b in sd.check_settings(F.LAMBDA_SETTINGS, live)], ["env_names"])
        self.assertIsNone(sd.env_names_error(live))

    def test_cli_projects_the_environment_error(self):
        with tempfile.TemporaryDirectory() as d:
            argv = os.path.join(d, "argv")
            b = os.path.join(d, "aws")
            Path(b).write_text(
                "#!/bin/sh\n"
                f"printf '%s\\n' \"$@\" > '{argv}'\n"
                "echo '{\"runtime\": \"python3.13\", \"env_names\": [], \"env_error\": \"AccessDeniedException\"}'\n")
            os.chmod(b, stat.S_IRWXU)
            cfg = site_aws.CliAws("eu-west-2", aws_bin=b).lambda_get_configuration(FN)
            self.assertEqual(cfg["env_error"], "AccessDeniedException")
            q = Path(argv).read_text().split("\n")
            query = q[q.index("--query") + 1]
            self.assertIn("env_error:Environment.Error.ErrorCode", query)
            self.assertIn("env_names:keys(Environment.Variables || `{}`)", query)
            self.assertNotIn("Environment.Variables.", query)  # names only, never values


if __name__ == "__main__":
    unittest.main()
