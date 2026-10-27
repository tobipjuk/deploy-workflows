"""Tests for scripts/site_plan.py + site_diff.py: fixture git repo, fake AWS, fake LFS server.

Adversarial cases follow the Guardian findings in lego-mindstorms docs/deploy-pipeline-design.md
section 3 (round numbers in the test names' docstrings)."""
import contextlib
import io
import json
import os
import unittest

import site_fakes as F  # noqa: E402  (puts scripts/ on sys.path)
import site_diff as sd  # noqa: E402
import site_plan  # noqa: E402


def run_plan(env, **kw):
    err, out = io.StringIO(), io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
        rc = site_plan.main(env.plan_args(**kw), aws=env.aws, lfs=env.lfs.client())
    return rc, out.getvalue() + err.getvalue()


def summary(env):
    with open(env.out / "plan-summary.json", encoding="utf-8") as f:
        return json.load(f)


def labels(doc):
    return [a["label"] for a in doc["attention"]]


def outputs(env):
    p = env.root / "gh-output"
    if not p.exists():
        return {}
    with open(p, encoding="utf-8") as f:
        return dict(line.strip().split("=", 1) for line in f if "=" in line)


def adopt(env):
    """Plan (adoption) + apply, so a manifest exists afterwards."""
    import test_site_apply as A
    rc, log = run_plan(env)
    assert rc == 0, log
    env.plan_out = outputs(env)
    rc, log = A.run_apply(env)
    assert rc == 0, log
    for p in ("plan-summary.json", "plan-bundle.tar"):
        os.unlink(env.out / p)
    os.unlink(env.root / "gh-output")


class AdoptionTest(unittest.TestCase):
    def test_adoption_all_live_equal(self):
        env = F.Env(self)
        rc, log = run_plan(env)
        self.assertEqual(rc, 0, log)
        doc = summary(env)
        self.assertEqual(doc["kind"], "site")
        self.assertTrue(doc["site"]["adoption"])
        self.assertEqual(doc["changes"], [{"actions": ["create"], "address": "manifest:deployed-manifest.json"}])
        self.assertEqual(labels(doc), ["BASELINE ADOPTION"])
        self.assertIn("12 live objects adopted", doc["attention"][0]["after"])
        self.assertTrue(doc["deployable"])
        self.assertTrue((env.out / "plan-bundle.tar").exists())
        self.assertEqual(doc["bundle_sha256"], outputs(env)["bundle_sha256"])
        # Orion's canonical digest
        canon = json.dumps(doc["changes"], sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        import hashlib
        self.assertEqual(doc["changes_digest"], hashlib.sha256(canon.encode()).hexdigest())

    def test_push_without_manifest_fails_the_run(self):
        """round 4 M5 / round 5 L3: a push plan stops early with no baseline and fails."""
        env = F.Env(self)
        rc, log = run_plan(env, event="push")
        self.assertEqual(rc, 3)
        self.assertIn("No baseline yet", log)
        self.assertFalse((env.out / "plan-summary.json").exists())
        self.assertEqual(outputs(env).get("no_baseline"), "true")
        # it never fetched LFS objects (no 1.4 GB re-fetch per push)
        self.assertEqual([r for r in env.lfs.requests if r[0] == "get"], [])

    def test_adoption_multipart_binary_by_etag(self):
        """round 4 M3: binary keys adopt by MD5 / multipart ETag, from verified LFS bytes."""
        env = F.Env(self, multipart_pdf=True)
        rc, log = run_plan(env)
        self.assertEqual(rc, 0, log)
        self.assertEqual(summary(env)["counts"]["add"], 0)
        self.assertIn(("get", F.sha(F.PDF), None), env.lfs.requests)

    def test_adoption_text_by_live_bytes_not_md5(self):
        """round 4 M3: a text key whose live bytes differ is a change, whatever its ETag says."""
        env = F.Env(self)
        obj = env.aws.buckets[env.policy["bucket"]]["index.html"]
        obj["data"] = b"<!doctype html>\n<script>evil()</script>\n"  # ETag left stale on purpose
        rc, log = run_plan(env)
        self.assertEqual(rc, 0, log)
        doc = summary(env)
        self.assertIn({"actions": ["update"], "address": "s3:index.html"}, doc["changes"])
        text = doc["site"]["diffs"][0]["text"]
        self.assertIn("-<script>evil()</script>", text)

    def test_adoption_unverified_range_read_for_new_lfs_objects(self):
        """round 4 M5(2): new LFS objects are existence-checked and range-read, not fetched."""
        env = F.Env(self)
        new = F.WEBP + b"new page"
        env.commit({"building-instructions/pages/public/def456/p001.webp": F.pointer(new)}, lfs=[new])
        rc, log = run_plan(env)
        self.assertEqual(rc, 0, log)
        gets = [r for r in env.lfs.requests if r[0] == "get" and r[1] == F.sha(new)]
        self.assertEqual(gets, [("get", F.sha(new), "bytes=0-15")])
        self.assertIn("magic-checked unverified", summary(env)["attention"][-1]["after"])


class SteadyStateTest(unittest.TestCase):
    def setUp(self):
        self.env = F.Env(self)
        adopt(self.env)

    def test_idempotent_after_apply(self):
        rc, log = run_plan(self.env, event="push")
        self.assertEqual(rc, 0, log)
        self.assertFalse((self.env.out / "plan-summary.json").exists())
        self.assertEqual(outputs(self.env)["has_changes"], "false")

    def test_code_change_full_diff_against_live(self):
        env = self.env
        env.commit({"site/sw.js": b"const CACHE = 'v2';\nself.addEventListener('fetch', () => {});\n",
                    "site/pin.html": b"<!doctype html>\n<form>PIN 2</form>\n"})
        rc, log = run_plan(env, event="push")
        self.assertEqual(rc, 0, log)
        doc = summary(env)
        self.assertEqual(labels(doc)[:2], ["PIN page", "Service worker"])
        files = [d["file"] for d in doc["site"]["diffs"]]
        self.assertEqual(files, ["pin.html", "sw.js"])
        self.assertIn("-const CACHE = 'v1';\n+const CACHE = 'v2';", doc["site"]["diffs"][1]["text"])
        self.assertTrue(doc["deployable"])

    def test_live_drift_diffed_against_live_bytes(self):
        """round 3 H3: a Mac fallback deploy shows as LIVE DRIFT and the diff's old side is live."""
        env = self.env
        env.aws.put_live(env.policy["bucket"], "index.html", b"<!doctype html>\n<p>mac</p>\n", "text/html")
        env.commit({"site/index.html": b"<!doctype html>\n<p>box</p>\n"})
        rc, log = run_plan(env, event="push")
        self.assertEqual(rc, 0, log)
        doc = summary(env)
        self.assertIn("LIVE DRIFT", labels(doc))
        self.assertIn("-<p>mac</p>\n+<p>box</p>", doc["site"]["diffs"][0]["text"])

    def test_extra_live_object_in_site_is_deleted_outside_site_not_deployable(self):
        """round 4 L4 / round 5 L2."""
        env = self.env
        env.aws.put_live(env.policy["bucket"], "img/stray.png", F.PNG)
        rc, _ = run_plan(env, event="push")
        doc = summary(env)
        self.assertIn({"actions": ["delete"], "address": "s3:img/stray.png"}, doc["changes"])
        self.assertTrue(doc["deployable"])
        env.aws.put_live(env.policy["bucket"], "old-login.html", b"x")
        os.unlink(env.out / "plan-bundle.tar")
        rc, _ = run_plan(env, event="push")
        doc = summary(env)
        self.assertFalse(doc["deployable"])
        self.assertTrue(any("outside SITE" in r for r in doc["site"]["not_deployable"]))
        self.assertNotIn({"actions": ["delete"], "address": "s3:old-login.html"}, doc["changes"])
        self.assertFalse((env.out / "plan-bundle.tar").exists())

    def test_delete_of_root_or_code_key_needs_attention(self):
        env = self.env
        sj = F.site_json()
        sj["mappings"] = [m for m in sj["mappings"] if m.get("key") != "book.html"]
        env.commit({"deploy/site.json": json.dumps(sj).encode()})
        rc, log = run_plan(env, event="push")
        self.assertEqual(rc, 0, log)
        doc = summary(env)
        self.assertIn("Delete of a root or code key", labels(doc))
        self.assertFalse(doc["destructive"])

    def test_many_deletes_are_destructive(self):
        env = self.env
        for i in range(21):
            env.aws.put_live(env.policy["bucket"], f"img/old{i}.png", F.PNG)
        rc, log = run_plan(env, event="push")
        self.assertEqual(rc, 4, log)
        self.assertIn("allow_destroy", log)
        self.assertFalse((env.out / "plan-summary.json").exists())
        self.assertFalse((env.out / "plan-bundle.tar").exists())
        rc, log = run_plan(env, allow_destroy=True)
        self.assertEqual(rc, 0, log)
        self.assertTrue(summary(env)["destructive"])
        self.assertTrue((env.out / "plan-bundle.tar").exists())

    def test_settings_mismatch_not_deployable(self):
        env = self.env
        env.aws.lambdas["ev3-workshop-progress-api"]["config"]["memory_size"] = 512
        env.commit({"site/index.html": b"<!doctype html>\n<p>x</p>\n"})
        run_plan(env, event="push")
        doc = summary(env)
        self.assertFalse(doc["deployable"])
        self.assertIn("Settings mismatch", labels(doc))
        self.assertFalse((env.out / "plan-bundle.tar").exists())

    def test_lambda_and_gate_changes_come_first(self):
        env = self.env
        env.commit({"site/api/session.py": F.SESSION_PY + b"\n\ndef extra():\n    return 1\n",
                    "site/api/viewer_gate.js": F.GATE_JS + b"// v2\n",
                    "site/index.html": b"<!doctype html>\n<p>x</p>\n"})
        rc, log = run_plan(env, event="push")
        self.assertEqual(rc, 0, log)
        doc = summary(env)
        self.assertEqual(labels(doc)[:2], ["Gate code", "Lambda code"])
        addrs = [d["address"] for d in doc["site"]["diffs"]]
        self.assertEqual(addrs, ["cloudfront-function:ev3-workshop-site-pin", "lambda:ev3-workshop-progress-api",
                                 "s3:index.html"])
        self.assertIn("+def extra():", doc["site"]["diffs"][1]["text"])

    def test_gate_development_leftover_shown(self):
        env = self.env
        env.aws.functions["ev3-workshop-site-pin"]["DEVELOPMENT"]["code"] = b"// leftover\n"
        env.commit({"site/index.html": b"<!doctype html>\n<p>x</p>\n"})
        run_plan(env, event="push")
        doc = summary(env)
        self.assertIn("Gate DEVELOPMENT differs from LIVE", labels(doc))
        self.assertTrue(any(d["file"].startswith("DEVELOPMENT") for d in doc["site"]["diffs"]))

    def test_invisible_and_bidi_escaped(self):
        """round 3 H4."""
        env = self.env
        env.commit({"site/index.html": "<!doctype html>\n<p>ok‮;evil()​</p>\n".encode()})
        run_plan(env, event="push")
        doc = summary(env)
        text = doc["site"]["diffs"][0]["text"]
        self.assertIn("<U+202E>", text)
        self.assertIn("<U+200B>", text)
        self.assertNotIn("‮", json.dumps(doc, ensure_ascii=False))
        self.assertIn("Invisible or bidi characters", labels(doc))

    def test_code_diff_too_large_is_not_deployable(self):
        """round 3 H1: a truncated code diff makes the plan undeployable."""
        env = self.env
        big = b"<!doctype html>\n" + b"".join(b"<p>line %d</p>\n" % i for i in range(120000))
        env.commit({"site/book.html": big})
        rc, log = run_plan(env, event="push")
        self.assertEqual(rc, 0, log)
        doc = summary(env)
        self.assertFalse(doc["deployable"])
        self.assertFalse(doc["diff_complete"])
        self.assertFalse((env.out / "plan-bundle.tar").exists())

    def test_lfs_object_with_wrong_bytes_refused(self):
        """round 3 L2: downloads are checked against the oid."""
        env = self.env
        new = F.WEBP + b"page 3"
        env.commit({"building-instructions/pages/public/abc123/p003.webp": F.pointer(new)}, lfs=[new])
        env.lfs.objects[F.sha(new)] = F.WEBP + b"page 4"  # same size, other bytes
        rc, log = run_plan(env, event="push")
        self.assertEqual(rc, 1)
        self.assertIn("does not match its oid", log)

    def test_lfs_object_missing_refused(self):
        env = self.env
        new = F.WEBP + b"never pushed"
        env.commit({"building-instructions/pages/public/abc123/p004.webp": F.pointer(new)})
        rc, log = run_plan(env, event="push")
        self.assertEqual(rc, 1)
        self.assertIn("not in GitHub's LFS store", log)

    def test_lfs_object_that_is_html_refused_by_magic(self):
        """steady state: magic bytes on VERIFIED bytes."""
        env = self.env
        evil = b"<html><script>steal()</script></html>"
        env.commit({"building-instructions/pages/public/abc123/p005.webp": F.pointer(evil)}, lfs=[evil])
        rc, log = run_plan(env, event="push")
        self.assertEqual(rc, 1)
        self.assertIn("magic bytes", log)


class RefusalTest(unittest.TestCase):
    def setUp(self):
        self.env = F.Env(self)

    def refused(self, needle, **kw):
        rc, log = run_plan(self.env, **kw)
        self.assertEqual(rc, 1, log)
        self.assertIn(needle, log)
        self.assertFalse((self.env.out / "plan-summary.json").exists())
        self.assertFalse((self.env.out / "plan-bundle.tar").exists())
        return log

    def test_pointer_smuggled_into_code_key(self):
        """round 4 H2: code committed as an LFS pointer would get no diff."""
        js = b"alert(1)\n"
        self.env.commit({"site/sw.js": F.pointer(js)}, lfs=[js])
        self.refused("is an LFS pointer")

    def test_pointer_variant_into_text_key(self):
        self.env.commit({"building-instructions/community/clock/model.ldr":
                         b"version https://git-lfs.github.com/spec/v1\r\noid sha256:" + b"a" * 64 + b"\r\nsize 9\r\n"})
        self.refused("is an LFS pointer")

    def test_malformed_pointer_on_binary_key(self):
        self.env.commit({"site/img/logo.png": b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"A" * 64
                         + b"\nsize 1\n"})
        self.refused("malformed LFS pointer")

    def test_pointer_with_extension_lines(self):
        self.env.commit({"site/img/logo.png": b"version https://git-lfs.github.com/spec/v1\next-0-foo sha256:"
                         + b"a" * 64 + b"\noid sha256:" + b"a" * 64 + b"\nsize 1\n"})
        self.refused("LFS pointer")

    def test_html_disguised_as_png(self):
        """round 4 L1."""
        self.env.commit({"site/img/x.png": b"<html><script>alert(1)</script>"})
        self.refused("magic bytes")

    def test_key_and_source_extension_must_agree(self):
        sj = F.site_json()
        sj["mappings"].append({"source": "site/book.html", "key": "img/book.png", "cache": "long"})
        self.env.commit({"deploy/site.json": json.dumps(sj).encode()})
        self.refused("same known extension")

    def test_browser_types_only_from_site(self):
        self.env.commit({"building-instructions/community/clock/x.html": b"<script>alert(1)</script>\n"})
        self.refused("may only come from")

    def test_symlink_source(self):
        self.env.commit({}, symlinks={"site/img/env.png": "/proc/self/environ"})
        self.refused("not a regular file")

    def test_symlinked_site_json(self):
        self.env.commit({}, symlinks={"deploy/site.json": "/etc/passwd"})
        self.refused("not a regular file")

    def test_unknown_extension(self):
        self.env.commit({"site/img/run.exe": b"MZ"})
        self.refused("type table")

    def test_uppercase_text_extension(self):
        self.env.commit({"site/img/X.SVG": b"<svg/>"})
        self.refused("lowercase")

    def test_not_utf8_or_nul(self):
        self.env.commit({"site/book.html": b"<p>\xff</p>"})
        self.refused("not UTF-8")
        self.env.commit({"site/book.html": b"<p>\x00</p>"})
        self.refused("control character")

    def test_new_lambda_member_refused(self):
        """round 4 L2: a new or renamed member refuses the plan until the policy PR adds it."""
        self.env.commit({"site/api/helper.py": b"x = 1\n"})
        self.refused("not in the policy's allowlist")

    def test_shadowing_member_refused_even_if_not_listed(self):
        self.env.commit({"site/api/json.py": b"def loads(s):\n    return steal(s)\n"})
        self.refused("not in the policy's allowlist")

    def test_lambda_member_not_text(self):
        self.env.commit({"site/api/session.py": b"\x00\x01binary"})
        self.refused("control character")

    def test_key_outside_site(self):
        sj = F.site_json()
        sj["mappings"].append({"source": "site/book.html", "key": "admin.html", "cache": "short"})
        self.env.commit({"deploy/site.json": json.dumps(sj).encode()})
        self.refused("outside the policy's SITE")

    def test_overlapping_mappings(self):
        sj = F.site_json()
        sj["mappings"].append({"source": "site/book.html", "key": "index.html", "cache": "short"})
        self.env.commit({"deploy/site.json": json.dumps(sj).encode()})
        self.refused("two mappings")

    def test_traversal_prefix(self):
        sj = F.site_json()
        sj["mappings"].append({"source_dir": "site/img", "prefix": "img/../x/", "cache": "long"})
        self.env.commit({"deploy/site.json": json.dumps(sj).encode()})
        self.refused("dot")

    def test_unknown_site_json_field(self):
        sj = F.site_json()
        sj["bucket"] = "attacker-bucket"
        self.env.commit({"deploy/site.json": json.dumps(sj).encode()})
        self.refused("unknown fields")

    def test_target_input_must_match_policy(self):
        self.refused("differs from the policy", extra=("--target", "other"))

    def test_policy_for_unknown_repo(self):
        rc, log = run_plan(self.env, extra=("--repository", "tobipjuk/other"))
        self.assertEqual(rc, 1)
        self.assertIn("no site policy", log)

    def test_live_lambda_code_must_match_codesha(self):
        self.env.aws.download = lambda url, dest, max_bytes=0: open(dest, "wb").write(b"PK\x05\x06" + b"\0" * 18)
        self.refused("does not match its CodeSha256")


class NoDeployRoleTest(unittest.TestCase):
    def test_summary_without_bundle(self):
        env = F.Env(self)
        rc, log = run_plan(env, deploy=False)
        self.assertEqual(rc, 0, log)
        doc = summary(env)
        self.assertFalse(doc["deployable"])
        self.assertFalse((env.out / "plan-bundle.tar").exists())
        self.assertNotIn("bundle_sha256", outputs(env))


class LiveZipTest(unittest.TestCase):
    def test_non_text_live_member_needs_attention(self):
        env = F.Env(self)
        z = F.make_zip({"progress.py": F.PROGRESS_PY, "session.py": F.SESSION_PY, "native.so": b"\x7fELF\x00\x01"})
        env.aws.set_lambda("ev3-workshop-progress-api", z,
                           {**F.LAMBDA_SETTINGS, "env": {"TABLE": "t", "SECRET_NAME": "s"}})
        rc, log = run_plan(env)
        self.assertEqual(rc, 0, log)
        doc = summary(env)
        self.assertIn("Non-text member in the live Lambda zip", labels(doc))
        # the zip we build drops it: a Lambda change, with the removal shown
        self.assertIn({"actions": ["update"], "address": "lambda:ev3-workshop-progress-api"}, doc["changes"])


class DiffUnitTest(unittest.TestCase):
    def test_zip_is_deterministic(self):
        a = sd.build_zip({"b.py": b"1\n", "a.py": b"2\n"})
        b = sd.build_zip({"a.py": b"2\n", "b.py": b"1\n"})
        self.assertEqual(a, b)
        self.assertEqual(sorted(sd.read_zip(a)), ["a.py", "b.py"])

    def test_multipart_etag(self):
        data = b"x" * (8 * 1024 * 1024 + 5)
        whole, parts = sd.md5_info_bytes(data)
        import hashlib
        et = hashlib.md5(b"".join(parts)).hexdigest() + "-2"
        self.assertTrue(sd.etag_equal(et, whole, parts))
        self.assertFalse(sd.etag_equal(et[:-1] + "3", whole, parts))
        self.assertTrue(sd.etag_equal('"' + whole + '"', whole, parts))

    def test_escape(self):
        self.assertEqual(sd.escape_line("a⁦b c\td"), ("a<U+2066>b<U+00A0>c\td", 2))
        self.assertEqual(sd.escape_line("tag\U000e0041"), ("tag<U+E0041>", 1))

    def test_new_file_and_cr(self):
        t, a, r, inv = sd.text_diff(None, "x\r\ny\n", "a", "b")
        self.assertIn("+++ b", t)
        self.assertIn("+x<U+000D>", t)
        self.assertEqual((r, inv), (0, 1))



class LargeTextTest(unittest.TestCase):
    def test_huge_data_file_listed_without_diff_huge_code_not_deployable(self):
        env = F.Env(self)
        adopt(env)
        env.commit({"building-instructions/community/clock/model.ldr": b"0 x\n" * 300000})
        rc, log = run_plan(env, event="push")
        self.assertEqual(rc, 0, log)
        doc = summary(env)
        self.assertTrue(doc["deployable"])
        self.assertTrue(doc["site"]["data_diffs_truncated"])
        os.unlink(env.out / "plan-summary.json")
        os.unlink(env.out / "plan-bundle.tar")
        env.commit({"site/sw.js": b"//" + b"x" * 1_100_000 + b"\n"})
        rc, log = run_plan(env, event="push")
        self.assertEqual(rc, 0, log)
        doc = summary(env)
        self.assertFalse(doc["deployable"])
        self.assertFalse(doc["diff_complete"])


if __name__ == "__main__":
    unittest.main()
