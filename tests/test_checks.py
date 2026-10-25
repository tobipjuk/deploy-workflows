"""Tests for scripts/check_plan_run.py (evaluate) and scripts/check_lockfile.py."""
import datetime as dt
import importlib.util
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cpr = load("check_plan_run")
clf = load("check_lockfile")

REPO = "tobipjuk/starhuntercrew"
SHA = "c" * 40
NOW = dt.datetime(2026, 10, 25, 12, 0, tzinfo=dt.timezone.utc)
REUSABLE = "tobipjuk/deploy-workflows/.github/workflows/tf-plan.yml"


def run(**over):
    r = {
        "id": 42, "path": ".github/workflows/plan.yml", "repository": {"full_name": REPO},
        "head_repository": {"full_name": REPO}, "head_branch": "main", "event": "push",
        "status": "completed", "conclusion": "success", "head_sha": SHA,
        "referenced_workflows": [{"path": REUSABLE + "@main", "ref": "refs/heads/main", "sha": "d" * 40}],
        "run_started_at": "2026-10-25T11:00:00Z",
    }
    r.update(over)
    return r


def ev(r, latest=42, now=NOW):
    return cpr.evaluate(r, latest, now, REPO, SHA, ".github/workflows/plan.yml", REUSABLE, 7200)


class PlanRunTest(unittest.TestCase):
    def test_ok(self):
        self.assertEqual(ev(run()), [])
        self.assertEqual(ev(run(event="workflow_dispatch", path=".github/workflows/plan.yml@refs/heads/main")), [])

    def test_each_rule(self):
        cases = {
            "path": run(path=".github/workflows/evil.yml"),
            "another repository": run(repository={"full_name": "x/y"}),
            "fork": run(head_repository={"full_name": "attacker/starhuntercrew"}),
            "branch": run(head_branch="feature"),
            "event": run(event="pull_request"),
            "completed/success": run(conclusion="failure"),
            "superseded": run(head_sha="e" * 40),
            "tf-plan.yml": run(referenced_workflows=[{"path": REUSABLE + "@feature", "ref": "refs/heads/feature"}]),
            "expire": run(run_started_at="2026-10-25T09:59:00Z"),
            "start time": run(run_started_at=None, created_at=None),
        }
        for want, r in cases.items():
            problems = ev(r)
            self.assertTrue(any(want in p for p in problems), (want, problems))

    def test_no_reusable_reference(self):
        self.assertTrue(ev(run(referenced_workflows=[])))
        self.assertTrue(ev(run(referenced_workflows=None)))

    def test_job_count(self):
        self.assertEqual(cpr.evaluate(run(), 42, NOW, REPO, SHA, ".github/workflows/plan.yml", REUSABLE, 7200,
                                      jobs=[{"name": "plan / terraform plan"}]), [])
        for jobs in ([], [{}, {}], [{}, {}, {}]):
            problems = cpr.evaluate(run(), 42, NOW, REPO, SHA, ".github/workflows/plan.yml", REUSABLE, 7200, jobs=jobs)
            self.assertTrue(any("exactly 1" in p for p in problems), jobs)

    def test_every_referenced_workflow_from_anchor_main(self):
        good = {"path": REUSABLE + "@main", "ref": "refs/heads/main", "sha": "d" * 40}
        for extra in ({"path": "evil/repo/.github/workflows/x.yml@main", "ref": "refs/heads/main"},
                      {"path": "tobipjuk/deploy-workflows/.github/workflows/tf-plan.yml@dev", "ref": "refs/heads/dev"},
                      {"path": "tobipjuk/deploy-workflows-evil/.github/workflows/tf-plan.yml@main", "ref": "refs/heads/main"}):
            problems = ev(run(referenced_workflows=[good, extra]))
            self.assertTrue(any("outside" in p for p in problems), extra)

    def test_newer_run_supersedes(self):
        self.assertTrue(any("newer" in p for p in ev(run(), latest=43)))
        self.assertTrue(any("newer" in p for p in ev(run(), latest=None)))

    def test_bad_args(self):
        with redirect_stderr(StringIO()):
            self.assertEqual(cpr.main(["--repo", REPO, "--run-id", "12; rm", "--expected-sha", SHA]), 1)
            self.assertEqual(cpr.main(["--repo", REPO, "--run-id", "12", "--expected-sha", "short"]), 1)


class LockfileTest(unittest.TestCase):
    def check(self, text):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, ".terraform.lock.hcl")
            with open(p, "w") as f:
                f.write(text)
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()) as err:
                code = clf.main([p, str(ROOT / "policy" / "allowed-providers.txt")])
            return code, err.getvalue()

    def test_allowed(self):
        code, _ = self.check('provider "registry.terraform.io/hashicorp/aws" {\n}\n'
                             'provider "registry.terraform.io/hashicorp/archive" {\n}\n')
        self.assertEqual(code, 0)

    def test_refused(self):
        code, err = self.check('provider "registry.terraform.io/hashicorp/aws" {\n}\n'
                               'provider "registry.terraform.io/hashicorp/external" {\n}\n')
        self.assertEqual(code, 1)
        self.assertIn("hashicorp/external", err)

    def test_empty_or_missing(self):
        self.assertEqual(self.check("# nothing\n")[0], 1)
        with redirect_stderr(StringIO()):
            self.assertEqual(clf.main(["/nonexistent/.terraform.lock.hcl", "/nonexistent"]), 1)


if __name__ == "__main__":
    unittest.main()
