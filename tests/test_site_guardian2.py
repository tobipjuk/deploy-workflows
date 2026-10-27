"""Guardian review of f944888: M1 (Cache-Control / Content-Type), L1 (escaped paths),
L3 (no raw failures in the apply), L4 (bidi items never truncated), L7 (homoglyph hint)."""
import contextlib
import io
import json
import os
import unittest

import site_fakes as F  # noqa: E402
import site_apply  # noqa: E402
import site_aws  # noqa: E402
import site_diff as sd  # noqa: E402
import site_policy as sp  # noqa: E402
from test_site_apply import manifest, planned, run_apply  # noqa: E402
from test_site_plan import adopt, labels, outputs, run_plan, summary  # noqa: E402

BUCKET = "ev3-workshop-880207437749"


def clear(env):
    for p in ("plan-summary.json", "plan-bundle.tar"):
        if (env.out / p).exists():
            os.unlink(env.out / p)
    if (env.root / "gh-output").exists():
        os.unlink(env.root / "gh-output")


class CacheMetadataTest(unittest.TestCase):
    def setUp(self):
        self.env = F.Env(self)
        adopt(self.env)

    def test_manifest_records_live_metadata_and_last_modified(self):
        m = manifest(self.env)
        live = self.env.aws.buckets[BUCKET]
        for k, o in m["objects"].items():
            self.assertEqual(sp.CACHE_CLASSES[o["cache"]], live[k]["cc"], k)
            self.assertEqual(o["content_type"], live[k]["ct"], k)
            self.assertEqual(o["last_modified"], live[k]["lm"], k)

    def test_in_place_metadata_change_is_drift_and_an_update(self):
        """A Mac copy-object in place keeps the ETag: LastModified catches it, and the bytes
        alone no longer make the object 'same'."""
        env = self.env
        env.aws.set_meta(BUCKET, "index.html", cc="public, max-age=31536000, immutable")
        rc, log = run_plan(env, event="push")
        self.assertEqual(rc, 0, log)
        doc = summary(env)
        self.assertIn({"actions": ["update"], "address": "s3:index.html"}, doc["changes"])
        self.assertIn("LIVE DRIFT", labels(doc))
        att = [a for a in doc["attention"] if a["label"] == "Cache-Control or Content-Type"]
        self.assertEqual(len(att), 1)
        self.assertIn("immutable", att[0]["before"])
        self.assertEqual(att[0]["after"], "text/html; charset=utf-8 | public, max-age=300")
        self.assertEqual([d for d in doc["site"]["diffs"] if d["file"] == "index.html"], [])
        env.plan_out = outputs(env)
        rc, log = run_apply(env)
        self.assertEqual(rc, 0, log)
        self.assertEqual(env.aws.buckets[BUCKET]["index.html"]["cc"], "public, max-age=300")
        clear(env)
        rc, log = run_plan(env, event="push")
        self.assertFalse((env.out / "plan-summary.json").exists(), log)

    def test_binary_metadata_drift_reuploads(self):
        env = self.env
        env.aws.set_meta(BUCKET, "img/logo.png", ct="text/html")
        run_plan(env, event="push")
        doc = summary(env)
        self.assertIn({"actions": ["update"], "address": "s3:img/logo.png"}, doc["changes"])

    def test_box_chosen_immutable_on_root_key_refused(self):
        sj = F.site_json()
        for m in sj["mappings"]:
            if m.get("key") in ("index.html", "sw.js"):
                m["cache"] = "immutable"
        self.env.commit({"deploy/site.json": json.dumps(sj).encode()})
        rc, log = run_plan(self.env, event="push")
        self.assertEqual(rc, 1, log)
        self.assertIn("not allowed for 'index.html'", log)

    def test_prefix_cache_pinned(self):
        sj = F.site_json()
        for m in sj["mappings"]:
            if m.get("prefix") == "community/":
                m["cache"] = "long"  # public caching of private designers' files
        self.env.commit({"deploy/site.json": json.dumps(sj).encode()})
        rc, log = run_plan(self.env, event="push")
        self.assertEqual(rc, 1, log)
        self.assertIn("not allowed", log)

    def test_allowed_class_change_on_root_key_needs_attention_and_applies(self):
        env = self.env
        sj = F.site_json()
        for m in sj["mappings"]:
            if m.get("key") == "book.html":
                m["cache"] = "no-cache"
        env.commit({"deploy/site.json": json.dumps(sj).encode()})
        rc, log = run_plan(env, event="push")
        self.assertEqual(rc, 0, log)
        doc = summary(env)
        self.assertIn({"actions": ["update"], "address": "s3:book.html"}, doc["changes"])
        self.assertIn("Cache-Control or Content-Type", labels(doc))
        env.plan_out = outputs(env)
        self.assertEqual(run_apply(env)[0], 0)
        self.assertEqual(env.aws.buckets[BUCKET]["book.html"]["cc"], "no-cache")
        self.assertEqual(manifest(env)["objects"]["book.html"]["cache"], "no-cache")

    def test_new_code_key_with_long_cache_needs_attention(self):
        self.env.commit({"site/img/icon.svg": b"<svg xmlns='http://www.w3.org/2000/svg'/>\n"})
        run_plan(self.env, event="push")
        att = [a for a in summary(self.env)["attention"] if a["label"] == "Cache-Control or Content-Type"]
        self.assertEqual([a["address"] for a in att], ["s3:img/icon.svg"])

    def test_metadata_changed_between_plan_and_apply(self):
        env = self.env
        env.commit({"site/index.html": b"<!doctype html>\n<p>v2</p>\n"})
        env.plan_out = None
        rc, log = run_plan(env, event="push")
        env.plan_out = outputs(env)
        env.aws.set_meta(BUCKET, "book.html", cc="no-cache")
        env.aws.calls.clear()
        rc, log = run_apply(env)
        self.assertEqual(rc, 1, log)
        self.assertIn("live S3 changed", log)
        self.assertEqual(env.aws.writes(), [])


class AdoptionMetadataTest(unittest.TestCase):
    def test_adoption_checks_metadata_of_text_and_binary(self):
        env = F.Env(self)
        env.aws.buckets[BUCKET]["sw.js"]["cc"] = "public, max-age=300"  # Mac served sw.js cacheable
        env.aws.buckets[BUCKET]["instructions/core.pdf"]["ct"] = "binary/octet-stream"
        rc, log = run_plan(env)
        self.assertEqual(rc, 0, log)
        doc = summary(env)
        self.assertIn({"actions": ["update"], "address": "s3:sw.js"}, doc["changes"])
        self.assertIn({"actions": ["update"], "address": "s3:instructions/core.pdf"}, doc["changes"])
        self.assertIn("Cache-Control or Content-Type", labels(doc))
        heads = [c for c in env.aws.calls if c[0] == "s3:HeadObject"]
        self.assertTrue(heads)


class EscapingTest(unittest.TestCase):
    def test_tree_path_with_newline_cannot_inject_workflow_commands(self):
        """L1: a path with a newline would start a new log line (::add-mask:: etc.)."""
        env = F.Env(self)
        env.commit({"site/api/x\n::stop-commands::tok\n.py": b"x = 1\n"})
        rc, log = run_plan(env)
        self.assertEqual(rc, 1, log)
        self.assertNotIn("\n::stop-commands::", log)
        self.assertNotIn("\n::stop-commands::", (env.root / "step-summary.md").read_text())
        self.assertIn("\\n::stop-commands::", log)

    def test_one_line(self):
        self.assertEqual(sd.one_line("a\nb\r\x1b"), "a\\x0ab\\x0d\\x1b")


class ApplyRobustnessTest(unittest.TestCase):
    """L3: unexpected errors are reported as refused/partial, never as a traceback, and the
    post-apply checks can't fail an applied deploy."""

    def setUp(self):
        self.env = F.Env(self)
        adopt(self.env)
        self.env.commit({"site/index.html": b"<!doctype html>\n<p>v2</p>\n",
                         "site/book.html": b"<!doctype html>\n<p>book v2</p>\n"})
        rc, log = run_plan(self.env, event="push")
        self.env.plan_out = outputs(self.env)

    def test_unexpected_error_before_writes(self):
        self.env.aws.faults["s3:ListObjectsV2"] = [RuntimeError("boom LEAKED_EDGE_KEY_MARKER")]
        rc, log = run_apply(self.env)
        self.assertEqual(rc, 1, log)
        self.assertIn("internal error RuntimeError", log)
        self.assertNotIn("Traceback", log)
        self.assertNotIn(F.SECRET, log)
        self.assertIn("applied=false", self.env.last_apply_output)

    def test_unexpected_error_after_a_write_is_partial_with_manifest(self):
        self.env.aws.faults["s3:PutObject"] = [None, RuntimeError("boom")]
        rc, log = run_apply(self.env)
        self.assertEqual(rc, 2, log)
        self.assertIn("partial=true", self.env.last_apply_output)
        self.assertEqual(manifest(self.env)["objects"]["book.html"]["etag"],
                         self.env.aws.buckets[BUCKET]["book.html"]["etag"])

    def test_invalidation_errors_are_a_check_not_a_failure(self):
        def bad(*a):
            raise KeyError("i")
        self.env.aws.cf_create_invalidation = bad
        rc, log = run_apply(self.env)
        self.assertEqual(rc, 0, log)
        self.assertEqual(self.env.last_checks["invalidation"], "failed")
        self.assertIn("applied=true", self.env.last_apply_output)

    def test_smoke_exception_is_a_check(self):
        def http(url):
            raise ValueError("x")
        rc, log = run_apply(self.env, http=http)
        self.assertEqual(rc, 0, log)
        self.assertEqual(self.env.last_checks["smoke"], "failed")

    def test_gate_test_empty_response_fails_the_case_silently(self):
        env = F.Env(self)
        adopt(env)
        env.commit({"site/api/viewer_gate.js": F.GATE_JS + b"// v2\n"})
        run_plan(env, event="push")
        env.plan_out = outputs(env)

        def empty(*a):
            raise site_aws.AwsError("cloudfront:TestFunction", "unexpected response")
        env.aws.cf_test_function = empty
        rc, log = run_apply(env)
        self.assertEqual(rc, 1, log)
        self.assertIn("gate test: the PIN page passes: FAIL", log)


class AttentionCapTest(unittest.TestCase):
    def test_bidi_items_survive_the_cap(self):
        items = [sd._att(f"s3:k{i}", "LIVE DRIFT", "info") for i in range(100)]
        items += [sd._att(f"s3:b{i}", "Invisible or bidi characters", "update") for i in range(5)]
        kept, trunc = sd.cap_attention(sd.order_attention(items))
        self.assertTrue(trunc)
        self.assertEqual(len(kept), sd.MAX_ATTENTION)
        self.assertEqual(sum(a["label"] == "Invisible or bidi characters" for a in kept), 5)
        self.assertEqual(kept[0]["label"], "Invisible or bidi characters")


class HomoglyphTest(unittest.TestCase):
    def test_cyrillic_in_code_flagged(self):
        env = F.Env(self)
        adopt(env)
        env.commit({"site/index.html": "<!doctype html>\n<script>if (аdmin) go()</script>\n".encode()})
        run_plan(env, event="push")
        self.assertIn("Non-ASCII letters or combining marks in code", labels(summary(env)))


class CliEmptyResponseTest(unittest.TestCase):
    def test_none_response_is_an_aws_error(self):
        import stat
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            b = os.path.join(d, "aws")
            Path(b).write_text("#!/bin/sh\nexit 0\n")
            os.chmod(b, stat.S_IRWXU)
            aws = site_aws.CliAws("eu-west-2", aws_bin=b)
            for call in (lambda: aws.cf_test_function("g", "E", b"{}"),
                         lambda: aws.cf_create_invalidation("E1", ["/"], "r"),
                         lambda: aws.lambda_get_function("f"),
                         lambda: aws.head_object("b", "k")):
                with self.assertRaises(site_aws.AwsError):
                    call()


if __name__ == "__main__":
    unittest.main()
