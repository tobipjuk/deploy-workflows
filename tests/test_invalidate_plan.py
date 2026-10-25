"""Tests for scripts/invalidate_plan.py with the callers' real `invalidate` lines."""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("invalidate_plan", ROOT / "scripts" / "invalidate_plan.py")
ip = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ip)

ICE = "cloudfront_distribution_id if aws_s3_object.site\n"  # incaseofemergency deploy.yml, exact
SHC = ("app_cloudfront_distribution_id\n"
       "cloudfront_distribution_id\n"
       "games_cloudfront_distribution_id if module.games.\n")  # starhuntercrew deploy.yml, exact


class InvalidatePlanTest(unittest.TestCase):
    def test_ice_line(self):
        # deploy run 40204951622: rejected as "Bad invalidate line" by the old bash regex
        changed = ['aws_s3_object.site["service-worker.js"]', "aws_lambda_function.api"]
        self.assertEqual(ip.plan(ICE, changed), ["cloudfront_distribution_id"])
        self.assertEqual(ip.plan(ICE, ["aws_lambda_function.api"]), [])

    def test_shc_lines(self):
        self.assertEqual(ip.plan(SHC, ['module.app.aws_s3_object.site["sw.js"]']),
                         ["app_cloudfront_distribution_id", "cloudfront_distribution_id"])
        self.assertEqual(ip.plan(SHC, ['module.games.aws_s3_object.site["sw.js"]']),
                         ["app_cloudfront_distribution_id", "cloudfront_distribution_id",
                          "games_cloudfront_distribution_id"])

    def test_bracketed_prefix_and_bad_lines(self):
        self.assertEqual(ip.plan('d if aws_s3_object.site["a"]', ['aws_s3_object.site["a"]']), ["d"])
        for bad in ("d if", "d iff x", "d if a b", "$(evil)", "d if x;rm"):
            with self.assertRaises(ValueError, msg=bad):
                ip.plan(bad, [])

    def test_old_bash_regex_was_broken(self):
        import subprocess
        old = r'^([A-Za-z0-9_]+)([[:space:]]+if[[:space:]]+([A-Za-z0-9_.\"\[\]-]+))?$'
        r = subprocess.run(["bash", "-c", f'[[ "games_cloudfront_distribution_id if module.games." =~ {old} ]]'])
        self.assertNotEqual(r.returncode, 0)  # documents the bug this helper replaces


if __name__ == "__main__":
    unittest.main()
