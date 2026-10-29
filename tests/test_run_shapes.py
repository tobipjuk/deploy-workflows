"""Regression tests on run shapes observed on real GitHub (2026-10-25, private repo, Free plan).

tests/fixtures/run-shapes/*.json hold redacted GET /actions/runs/{id} and
/actions/runs/{id}/jobs?filter=all responses for honest and hostile plan.yml variants. The
stub variants ran in a throwaway repo whose tf-plan.yml/tf-attest.yml mirror deploy-workflows'
job structure, so `reusable` points there. Every variant except the honest one must be refused.
"""
import datetime as dt
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("check_plan_run", ROOT / "scripts" / "check_plan_run.py")
cpr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cpr)

FIXTURES = sorted((ROOT / "tests" / "fixtures" / "run-shapes").glob("*.json"))


def load(name):
    return json.loads((ROOT / "tests" / "fixtures" / "run-shapes" / f"{name}.json").read_text())


def evaluate(doc):
    run, jobs = doc["run"], doc["jobs"]
    listed = jobs["jobs"]
    job_list = listed if jobs["total_count"] == len(listed) else [None] * jobs["total_count"]
    now = cpr.parse_time(run["run_started_at"]) + dt.timedelta(minutes=10)
    return cpr.evaluate(run, run["id"], now, run["repository"]["full_name"], run["head_sha"],
                        ".github/workflows/plan.yml", doc["reusable"], 7200, jobs=job_list)


class RunShapeTest(unittest.TestCase):
    def test_fixtures_present(self):
        self.assertGreaterEqual(len(FIXTURES), 11)

    def test_every_variant(self):
        for f in FIXTURES:
            doc = json.loads(f.read_text())
            problems = evaluate(doc)
            if doc["expect"] == "accept":
                self.assertEqual(problems, [], doc["variant"])
            else:
                self.assertTrue(problems, f"{doc['variant']} was accepted: {doc['description']}")

    def test_real_nested_job_names(self):
        names = sorted(j["name"] for j in load("a-stub")["jobs"]["jobs"])
        self.assertEqual(names, ["plan / attest / attest plan artifacts", "plan / terraform plan"])
        # a skipped nested call shows as the caller-level record only
        names = sorted(j["name"] for j in load("a-real")["jobs"]["jobs"])
        self.assertEqual(names, ["plan / attest", "plan / terraform plan"])

    def test_nested_token_carries_inner_job_workflow_ref(self):
        claims = load("a-stub")["token_claims"]
        refs = sorted(c["job_workflow_ref"] for c in claims)
        self.assertEqual(refs, ["tobipjuk/dw-shape-test/.github/workflows/tf-attest.yml@refs/heads/main",
                                "tobipjuk/dw-shape-test/.github/workflows/tf-plan.yml@refs/heads/main"])
        self.assertTrue(all(c["workflow_ref"].endswith("/plan.yml@refs/heads/main") for c in claims))

    def test_referenced_workflows_is_a_set(self):
        # tf-plan called twice is listed once: the reference list can't count calls
        paths = [r["path"] for r in load("e-stub")["run"]["referenced_workflows"]]
        self.assertEqual(len(paths), len(set(paths)))
        self.assertEqual(load("e-stub")["jobs"]["total_count"], 4)

    def test_forged_names_only_caught_by_references(self):
        problems = evaluate(load("c2-stub"))
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("tf-plan.yml", problems[0])

    def test_empty_matrix_only_caught_by_run_conclusion(self):
        # Load-bearing: these runs have exactly 2 successful jobs with the right names AND
        # reference both workflows; GitHub marks the run failed. Never relax the run-level
        # conclusion check.
        for v in ("c3-stub", "c5-stub"):
            problems = evaluate(load(v))
            self.assertEqual(problems, ["run is completed/failure, not completed/success"], v)

    def test_rerun_counts_all_attempts(self):
        doc = load("f-rerun")
        self.assertEqual(doc["run"]["run_attempt"], 2)
        self.assertEqual(doc["jobs"]["total_count"], 4)
        self.assertTrue(any("4 jobs" in p for p in evaluate(doc)))



def site_variant(jobs=("plan / site plan", "plan / attest / attest plan artifacts"),
                 refs=("site-plan.yml", "tf-attest.yml")):
    """A site plan run, derived from the observed a-stub shape: the caller's job calls
    site-plan.yml, whose second job nests tf-attest.yml (synthetic: not observed on GitHub)."""
    doc = load("a-stub")
    run = dict(doc["run"])
    run["referenced_workflows"] = [{"path": f"tobipjuk/deploy-workflows/.github/workflows/{r}@main",
                                    "ref": "refs/heads/main", "sha": "d" * 40} for r in refs]
    job_list = [{"name": n, "status": "completed", "conclusion": "success", "run_attempt": 1} for n in jobs]
    return run, job_list


def evaluate_kind(run, job_list, kind):
    now = cpr.parse_time(run["run_started_at"]) + dt.timedelta(minutes=10)
    return cpr.evaluate(run, run["id"], now, run["repository"]["full_name"], run["head_sha"],
                        ".github/workflows/plan.yml", cpr.KINDS[kind]["reusable"], 7200, jobs=job_list, kind=kind)


class SiteRunShapeTest(unittest.TestCase):
    def test_honest_site_run(self):
        self.assertEqual(evaluate_kind(*site_variant(), "site"), [])

    def test_site_run_is_not_a_terraform_run(self):
        self.assertTrue(evaluate_kind(*site_variant(), "terraform"))

    def test_terraform_run_is_not_a_site_run(self):
        run, jobs = site_variant(jobs=("plan / terraform plan", "plan / attest / attest plan artifacts"),
                                 refs=("tf-plan.yml", "tf-attest.yml"))
        self.assertEqual(evaluate_kind(run, jobs, "terraform"), [])
        self.assertTrue(evaluate_kind(run, jobs, "site"))

    def test_exact_set_of_referenced_workflows(self):
        """L3: a run that also references tf-plan.yml (or any third deploy-workflows file) is refused,
        even with exactly two successful jobs."""
        for refs in (("site-plan.yml", "tf-attest.yml", "tf-plan.yml"),
                     ("site-plan.yml", "tf-attest.yml", "site-apply.yml"),
                     ("site-plan.yml",), ("tf-attest.yml",)):
            with self.subTest(refs=refs):
                self.assertTrue(evaluate_kind(*site_variant(refs=refs), "site"))
        run, jobs = site_variant(jobs=("plan / terraform plan", "plan / attest / attest plan artifacts"),
                                 refs=("tf-plan.yml", "tf-attest.yml", "site-plan.yml"))
        self.assertTrue(evaluate_kind(run, jobs, "terraform"))

    def test_site_job_shapes(self):
        for jobs in (("plan / site plan",), ("plan / site plan", "plan / attest / attest plan artifacts", "x"),
                     ("plan / terraform plan", "plan / attest / attest plan artifacts"),
                     ("plan / site plan", "plan / attest")):
            with self.subTest(jobs=jobs):
                self.assertTrue(evaluate_kind(*site_variant(jobs=jobs), "site"))


if __name__ == "__main__":
    unittest.main()
