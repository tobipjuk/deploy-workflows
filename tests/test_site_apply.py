"""Tests for scripts/site_apply.py: fake AWS, fake LFS server, real plans from site_plan.py.

Covers the apply order, drift between plan and apply (round 3 L3), conditional writes,
silent gate tests (round 4 M1, round 5 L4), LFS verification before the first write (round 4
M5(3)), half-done applies and the manifest, and tampered bundles/summaries."""
import contextlib
import io
import json
import os
import shutil
import tarfile
import unittest

import site_fakes as F  # noqa: E402
import site_apply  # noqa: E402
import site_plan  # noqa: E402


def plan(env, **kw):
    err = io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(err):
        rc = site_plan.main(env.plan_args(**kw), aws=env.aws, lfs=env.lfs.client())
    assert rc == 0, err.getvalue()
    with open(env.root / "gh-output", encoding="utf-8") as f:
        o = dict(line.strip().split("=", 1) for line in f if "=" in line)
    os.unlink(env.root / "gh-output")
    return o


class Http:
    def __init__(self, env, ok=True):
        self.env, self.ok, self.urls = env, ok, []

    def __call__(self, url):
        self.urls.append(url)
        path = url.split(".net", 1)[1]
        if not self.ok:
            return 500, b""
        if path == "/":
            return 302, b""
        if path == "/api/progress":
            return 401, b""
        return 200, self.env.aws.buckets[self.env.policy["bucket"]][path[1:]]["data"]


def run_apply(env, outputs=None, digest=None, bundle_sha=None, allow_destroy=False, http=None, extra=()):
    o = outputs or plan_outputs(env)
    lines = []
    err = io.StringIO()
    checks = env.root / "checks"
    shutil.rmtree(checks, ignore_errors=True)
    ghout = env.root / "apply-output"
    if ghout.exists():
        os.unlink(ghout)
    args = ["--bundle", str(env.out / "plan-bundle.tar"), "--summary", str(env.out / "plan-summary.json"),
            "--bundle-sha256", bundle_sha or o["bundle_sha256"], "--changes-digest", digest or o["digest"],
            "--sha", env.sha, "--repository", F.REPOSITORY, "--policy-dir", str(F.POLICY_DIR),
            "--checks-dir", str(checks), "--github-output", str(ghout), "--plan-run-id", "777",
            "--allow-destroy", "true" if allow_destroy else "false", *extra]
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(err):
        rc = site_apply.main(args, aws=env.aws, lfs=env.lfs.client(), sleep=lambda s: None,
                             http_get=http or Http(env), out=lines.append)
    env.last_apply_output = ghout.read_text() if ghout.exists() else ""
    env.last_checks = {p.name: p.read_text().strip() for p in checks.iterdir()} if checks.exists() else {}
    return rc, "\n".join(lines) + err.getvalue()




def plan_outputs(env):
    return env.plan_out


def planned(env, **kw):
    env.plan_out = plan(env, **kw)
    return env.plan_out


def manifest(env):
    b = env.aws.buckets["ev3-workshop-deploy-880207437749"]["deployed-manifest.json"]
    return json.loads(b["data"])


class ApplyHappyTest(unittest.TestCase):
    def test_adoption_writes_only_the_manifest(self):
        env = F.Env(self)
        planned(env)
        rc, log = run_apply(env)
        self.assertEqual(rc, 0, log)
        writes = env.aws.writes()
        self.assertEqual(writes, [("s3:PutObject", "ev3-workshop-deploy-880207437749", "deployed-manifest.json")])
        m = manifest(env)
        self.assertEqual(len(m["objects"]), 12)
        live = env.aws.buckets[env.policy["bucket"]]
        for k, v in m["objects"].items():
            self.assertEqual(v["etag"], live[k]["etag"])
        self.assertIn("applied=true", env.last_apply_output)
        self.assertEqual(env.last_checks, {"smoke": "ok"})  # nothing to invalidate

    def test_full_change_order_and_result(self):
        env = F.Env(self)
        planned(env)
        self.assertEqual(run_apply(env)[0], 0)
        new_page = F.WEBP + b"new"
        env.commit({"site/api/viewer_gate.js": F.GATE_JS + b"// v2\n",
                    "site/api/session.py": F.SESSION_PY + b"# v2\n",
                    "site/index.html": b"<!doctype html>\n<p>v2</p>\n",
                    "building-instructions/pages/public/abc123/p009.webp": F.pointer(new_page),
                    "site/img/other.png": F.PNG + b"other"},
                   delete=["site/img/logo.png"], lfs=[new_page])
        sj = F.site_json()
        env.commit({"deploy/site.json": json.dumps(sj).encode()})
        planned(env, event="push")
        env.aws.calls.clear()
        rc, log = run_apply(env)
        self.assertEqual(rc, 0, log)
        ops = [c[0] for c in env.aws.calls if c[0] not in ("s3:ListObjectsV2", "s3:GetObject",
                                                             "lambda:GetFunction", "cloudfront:DescribeFunction",
                                                             "lambda:GetFunctionConfiguration",
                                                             "cloudfront:GetInvalidation")]
        self.assertEqual(ops, ["cloudfront:UpdateFunction", "cloudfront:TestFunction", "cloudfront:TestFunction",
                               "cloudfront:TestFunction", "lambda:UpdateFunctionCode", "s3:PutObject",
                               "s3:PutObject", "s3:PutObject", "cloudfront:PublishFunction", "s3:DeleteObject", "s3:PutObject",
                               "cloudfront:CreateInvalidation"])
        live = env.aws.buckets[env.policy["bucket"]]
        self.assertNotIn("img/logo.png", live)
        self.assertEqual(live["pages/abc123/p009.webp"]["data"], new_page)
        self.assertEqual(live["pages/abc123/p009.webp"]["ct"], "image/webp")
        self.assertEqual(live["index.html"]["cc"], "public, max-age=300")
        self.assertEqual(env.aws.functions["ev3-workshop-site-pin"]["LIVE"]["code"], F.GATE_JS + b"// v2\n")
        inv = list(env.aws.invalidations.values())[0]
        self.assertEqual(sorted(inv), ["/", "/img/logo.png", "/img/other.png", "/index.html",
                                       "/pages/abc123/p009.webp"])
        m = manifest(env)
        self.assertEqual(m["objects"]["index.html"]["etag"], live["index.html"]["etag"])
        self.assertEqual(env.last_checks, {"invalidation": "ok", "smoke": "ok"})
        for line in ("gate test: no cookie, page: 302 to the PIN page: pass", "gate: published to LIVE",
                     "lambda: code updated"):
            self.assertIn(line, log)
        # and the next plan sees nothing to do
        os.unlink(env.out / "plan-summary.json")
        os.unlink(env.out / "plan-bundle.tar")
        out = plan(env, event="push")
        self.assertEqual(out["has_changes"], "false")

    def test_smoke_failure_is_a_warning(self):
        env = F.Env(self)
        planned(env)
        rc, log = run_apply(env, http=Http(env, ok=False))
        self.assertEqual(rc, 0, log)
        self.assertEqual(env.last_checks["smoke"], "failed")


class DriftTest(unittest.TestCase):
    """round 3 L3: the apply re-reads live and refuses on any difference from the plan."""

    def setUp(self):
        self.env = F.Env(self)
        planned(self.env)
        self.assertEqual(run_apply(self.env)[0], 0)
        self.env.commit({"site/index.html": b"<!doctype html>\n<p>v2</p>\n"})
        planned(self.env, event="push")
        self.env.aws.calls.clear()

    def assert_refused(self, needle):
        rc, log = run_apply(self.env)
        self.assertEqual(rc, 1, log)
        self.assertIn(needle, log)
        self.assertEqual(self.env.aws.writes(), [])

    def test_s3_changed(self):
        self.env.aws.put_live(self.env.policy["bucket"], "book.html", b"<p>mac</p>")
        self.assert_refused("live S3 changed")

    def test_s3_object_added(self):
        self.env.aws.put_live(self.env.policy["bucket"], "img/new.png", F.PNG)
        self.assert_refused("live S3 changed")

    def test_manifest_changed(self):
        m = self.env.aws.buckets["ev3-workshop-deploy-880207437749"]["deployed-manifest.json"]
        m["etag"] = "0" * 32
        self.assert_refused("manifest.json changed")

    def test_lambda_changed(self):
        self.env.aws.lambdas["ev3-workshop-progress-api"]["revision"] = "rev-mac"
        self.assert_refused("Lambda changed")

    def test_gate_changed(self):
        self.env.aws.functions["ev3-workshop-site-pin"]["DEVELOPMENT"]["etag"] = "Dmac"
        self.assert_refused("gate changed")


class TamperBase(unittest.TestCase):
    def setUp(self):
        self.env = F.Env(self)
        planned(self.env)
        self.assertEqual(run_apply(self.env)[0], 0)
        self.env.commit({"site/index.html": b"<!doctype html>\n<p>v2</p>\n"})
        planned(self.env, event="push")
        self.env.aws.calls.clear()

    def assert_refused(self, needle, **kw):
        rc, log = run_apply(self.env, **kw)
        self.assertEqual(rc, 1, log)
        self.assertIn(needle, log)
        self.assertEqual(self.env.aws.writes(), [])

    def rewrite_summary(self, fn):
        p = self.env.out / "plan-summary.json"
        d = json.loads(p.read_text())
        fn(d)
        p.write_text(json.dumps(d))


class TamperTest(TamperBase):
    def test_wrong_bundle_sha(self):
        self.assert_refused("not the approved one", bundle_sha="0" * 64)

    def test_wrong_digest(self):
        self.assert_refused("changes_digest", digest="0" * 64)

    def test_summary_lies_about_plan(self):
        self.rewrite_summary(lambda d: d["site"].__setitem__("plan_sha256", "0" * 64))
        self.assert_refused("does not describe this bundle")

    def test_summary_not_deployable(self):
        self.rewrite_summary(lambda d: d.__setitem__("deployable", False))
        self.assert_refused("deployable")

    def test_summary_kind_terraform(self):
        self.rewrite_summary(lambda d: d.__setitem__("kind", "terraform"))
        self.assert_refused("kind")

    def test_rebuilt_bundle_with_other_plan(self):
        """A re-tarred bundle with a matching sha passed in (e.g. by a lying dispatcher) still has
        to match the summary's plan_sha256 and the recomputed digest."""
        import site_bundle
        p = self.env.out / "plan-bundle.tar"
        with tarfile.open(p) as t:
            plan_doc = json.loads(t.extractfile("plan.json").read())
            src = t.extractfile("SOURCE").read().decode().strip()
            blobs = {m.name[6:]: t.extractfile(m).read() for m in t.getmembers() if m.name.startswith("blobs/")}
        plan_doc["puts"][0]["cache_control"] = "public, max-age=31536000, immutable"
        new = site_bundle.create(str(p), src, plan_doc, blobs)
        self.rewrite_summary(lambda d: d.__setitem__("bundle_sha256", new))
        self.assert_refused("plan.json", bundle_sha=new)

    def test_policy_changed_since_plan(self):
        import site_policy
        orig = site_policy.load_policy

        def other(d, r):
            pol, sha = orig(d, r)
            return pol, "f" * 64
        site_policy.load_policy = other
        try:
            self.assert_refused("policy changed")
        finally:
            site_policy.load_policy = orig


class GateTest(unittest.TestCase):
    def setUp(self):
        self.env = F.Env(self)
        planned(self.env)
        self.assertEqual(run_apply(self.env)[0], 0)

    def change_gate(self, code):
        self.env.commit({"site/api/viewer_gate.js": code, "site/index.html": b"<!doctype html>\n<p>v2</p>\n"})
        planned(self.env, event="push")
        self.env.aws.calls.clear()

    def test_failing_gate_test_stops_before_live(self):
        self.change_gate(b"// BROKEN: lets everyone in\nfunction handler(e) { return e.request; }\n")
        rc, log = run_apply(self.env)
        self.assertEqual(rc, 1, log)
        self.assertIn("gate test: no cookie, page: 302 to the PIN page: FAIL", log)
        self.assertIn("gate test: the PIN page passes: pass", log)
        writes = [w[0] for w in self.env.aws.writes()]
        self.assertEqual(writes, ["cloudfront:UpdateFunction"])  # DEVELOPMENT only
        fn = self.env.aws.functions["ev3-workshop-site-pin"]
        self.assertEqual(fn["LIVE"]["code"], F.GATE_JS)
        self.assertEqual(self.env.aws.buckets[self.env.policy["bucket"]]["index.html"]["data"][:15], b"<!doctype html>")
        self.assertNotIn(b"v2", self.env.aws.buckets[self.env.policy["bucket"]]["index.html"]["data"])

    def test_gate_output_never_printed(self):
        """round 4 M1 / round 5 L4: a malicious gate puts the key into its redirect and headers."""
        self.env.aws.gate_secret_in_output = True
        self.change_gate(b"// LEAK the key\nfunction handler(e) { return e.request; }\n")
        rc, log = run_apply(self.env)
        self.assertEqual(rc, 1)
        everything = log + self.env.last_apply_output + json.dumps(self.env.last_checks)
        self.assertNotIn(F.SECRET, everything)
        self.assertNotIn("/x?k=", everything)
        self.assertNotIn("302", everything.replace("302 to the PIN page", ""))

    def test_secret_in_passing_output_never_printed(self):
        self.env.aws.gate_secret_in_output = True  # the pass-through case carries the edge key
        self.change_gate(F.GATE_JS + b"// v3\n")
        rc, log = run_apply(self.env)
        self.assertEqual(rc, 0, log)
        self.assertNotIn(F.SECRET, log + self.env.last_apply_output)

    def test_gate_case_evaluation(self):
        ok = site_apply.gate_case_passes
        self.assertTrue(ok({"output": json.dumps({"request": {"uri": "/pin.html"}})}, {"pass": True, "uri": "/pin.html"}))
        self.assertFalse(ok({"output": json.dumps({"request": {"uri": "/x"}})}, {"pass": True, "uri": "/pin.html"}))
        self.assertFalse(ok({"output": "not json"}, {"pass": True}))
        self.assertFalse(ok({"output": json.dumps({"request": {}}), "error": True}, {"pass": True}))
        r = {"output": json.dumps({"response": {"statusCode": 302, "headers": {"location": {"value": "/pin.html?n=/"}}}})}
        self.assertTrue(ok(r, {"status": 302, "location_prefix": "/pin.html"}))
        self.assertFalse(ok(r, {"status": 401}))
        self.assertFalse(ok({"output": json.dumps({"response": {"statusCode": 302}})},
                            {"status": 302, "location_prefix": "/pin.html"}))


class LfsAtApplyTest(unittest.TestCase):
    def test_lfs_verified_before_first_write(self):
        """round 4 M5(3) / round 5 L1: adoption's range read is unverified; the apply fetches the
        full object, verifies the oid and repeats the magic check before writing anything."""
        env = F.Env(self)
        evil = b"<html><script>steal()</script></html>"
        env.commit({"building-instructions/pages/public/zzz/p001.webp": F.pointer(evil)}, lfs=[evil])
        env.lfs.range_override = {F.sha(evil): F.WEBP[:16]}
        planned(env)  # adoption: magic on an unverified (spoofed) range read passes
        env.aws.calls.clear()
        rc, log = run_apply(env)
        self.assertEqual(rc, 1, log)
        self.assertIn("magic bytes", log)
        self.assertEqual(env.aws.writes(), [])

    def test_lfs_swapped_after_plan(self):
        env = F.Env(self)
        planned(env)
        self.assertEqual(run_apply(env)[0], 0)
        new = F.WEBP + b"x"
        env.commit({"building-instructions/pages/public/abc123/p007.webp": F.pointer(new)}, lfs=[new])
        planned(env, event="push")
        env.lfs.objects[F.sha(new)] = F.WEBP + b"y"
        env.aws.calls.clear()
        rc, log = run_apply(env)
        self.assertEqual(rc, 1, log)
        self.assertIn("does not match its oid", log)
        self.assertEqual(env.aws.writes(), [])


class PartialTest(unittest.TestCase):
    def setUp(self):
        self.env = F.Env(self)
        planned(self.env)
        self.assertEqual(run_apply(self.env)[0], 0)
        self.env.commit({"site/index.html": b"<!doctype html>\n<p>v2</p>\n",
                         "site/book.html": b"<!doctype html>\n<p>book v2</p>\n"})
        planned(self.env, event="push")

    def test_failed_put_records_what_was_written(self):
        import site_aws
        self.env.aws.faults["s3:PutObject"] = [None, site_aws.AwsError("s3:PutObject", "PreconditionFailed")]
        rc, log = run_apply(self.env)
        self.assertEqual(rc, 2, log)
        self.assertIn("partial=true", self.env.last_apply_output)
        m = manifest(self.env)
        live = self.env.aws.buckets[self.env.policy["bucket"]]
        # book.html (first, sorted) was written and is recorded with its new ETag; index.html was
        # not, and keeps its old entry (its live ETag didn't change).
        self.assertEqual(m["objects"]["book.html"]["etag"], live["book.html"]["etag"])
        self.assertEqual(m["objects"]["book.html"]["sha256"], F.sha(b"<!doctype html>\n<p>book v2</p>\n"))
        self.assertEqual(m["objects"]["index.html"]["etag"], live["index.html"]["etag"])
        self.assertNotEqual(m["objects"]["index.html"]["sha256"], F.sha(b"<!doctype html>\n<p>v2</p>\n"))
        self.assertIn("PreconditionFailed", log)

    def test_manifest_write_failure(self):
        import site_aws
        self.env.aws.faults["s3:PutObject"] = [None, None, site_aws.AwsError("s3:PutObject", "PreconditionFailed")]
        rc, log = run_apply(self.env)
        self.assertEqual(rc, 2, log)
        self.assertIn("LIVE DRIFT", log)


class InvalidationTest(unittest.TestCase):
    def test_over_100_paths_is_star(self):
        env = F.Env(self)
        planned(env)
        self.assertEqual(run_apply(env)[0], 0)
        files = {f"site/img/i{i:03}.png": F.PNG + bytes([i]) for i in range(101)}
        env.commit(files)
        planned(env, event="push")
        rc, log = run_apply(env)
        self.assertEqual(rc, 0, log)
        self.assertEqual(list(env.aws.invalidations.values())[-1], ["/*"])

    def test_paths_are_encoded(self):
        env = F.Env(self)
        planned(env)
        self.assertEqual(run_apply(env)[0], 0)
        env.commit({"building-instructions/community/clock/model.ldr": b"0 clock v2\n"})
        planned(env, event="push")
        self.assertEqual(run_apply(env)[0], 0)
        self.assertEqual(list(env.aws.invalidations.values())[-1], ["/community/clock/model.ldr"])


class DestroyTest(unittest.TestCase):
    def test_destructive_needs_allow_destroy_at_apply(self):
        env = F.Env(self)
        for i in range(25):
            env.aws.put_live(env.policy["bucket"], f"pages/old/p{i}.webp", F.WEBP)
        planned(env, allow_destroy=True)
        env.aws.calls.clear()
        rc, log = run_apply(env)
        self.assertEqual(rc, 1, log)
        self.assertIn("destructive", log)
        self.assertEqual(env.aws.writes(), [])
        rc, log = run_apply(env, allow_destroy=True)
        self.assertEqual(rc, 0, log)
        self.assertFalse(any(k.startswith("pages/old/") for k in env.aws.buckets[env.policy["bucket"]]))



class DesiredTamperTest(TamperBase):
    """Defence in depth: even a plan.json that is consistently re-bundled and re-summarised
    (which the attestation prevents) can't put keys outside SITE into the manifest."""

    def rebundle(self, mutate):
        import hashlib
        import site_bundle
        import site_policy as sp
        p = self.env.out / "plan-bundle.tar"
        with tarfile.open(p) as t:
            plan_doc = json.loads(t.extractfile("plan.json").read())
            src = t.extractfile("SOURCE").read().decode().strip()
            blobs = {m.name[6:]: t.extractfile(m).read() for m in t.getmembers() if m.name.startswith("blobs/")}
        mutate(plan_doc)
        new = site_bundle.create(str(p), src, plan_doc, blobs)
        psha = hashlib.sha256(site_bundle.canonical_json(plan_doc)).hexdigest()

        def fix(d):
            d["bundle_sha256"] = new
            d["site"]["plan_sha256"] = psha
        self.rewrite_summary(fix)
        pol, polsha = sp.load_policy(str(F.POLICY_DIR), F.REPOSITORY)
        return lambda: site_apply.verify_inputs(str(p), str(self.env.out / "plan-summary.json"), new,
                                                self.env.plan_out["digest"], self.env.sha, F.REPOSITORY,
                                                pol, polsha, False)

    def test_desired_outside_site(self):
        run = self.rebundle(lambda d: d["desired"].__setitem__("admin/x.html", dict(d["desired"]["index.html"])))
        with self.assertRaises(site_apply.ApplyRefused):
            run()

    def test_desired_wrong_content_type(self):
        run = self.rebundle(lambda d: d["desired"]["index.html"].__setitem__("content_type", "text/plain"))
        with self.assertRaises(site_apply.ApplyRefused):
            run()

    def test_put_differs_from_desired(self):
        run = self.rebundle(lambda d: d["desired"]["index.html"].__setitem__("sha256", "0" * 64))
        with self.assertRaises(site_apply.ApplyRefused):
            run()

    def test_consistent_rebundle_passes(self):
        """Control: the same path with no mutation verifies, so the refusals above are real."""
        run = self.rebundle(lambda d: None)
        run()

if __name__ == "__main__":
    unittest.main()
