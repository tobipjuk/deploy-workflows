"""Tests for scripts/site_policy.py, lfs_fetch.py pointers, and site_aws.py's silent CLI wrapper."""
import base64
import copy
import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

import site_fakes as F  # noqa: E402
import lfs_fetch  # noqa: E402
import site_aws  # noqa: E402
import site_policy as sp  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def policy():
    with open(F.POLICY_DIR / "tobipjuk" / "lego-mindstorms.json", encoding="utf-8") as f:
        return json.load(f)


class PolicyTest(unittest.TestCase):
    def test_fixture_and_every_real_policy_valid(self):
        sp.validate_policy(policy(), F.REPOSITORY)
        for p in sorted((ROOT / "policy" / "site").glob("*/*.json")):
            with self.subTest(p=p.name):
                doc = json.loads(p.read_text())
                sp.validate_policy(doc, f"{p.parent.name}/{p.stem}")

    def bad(self, fn, needle):
        doc = policy()
        fn(doc)
        with self.assertRaises(sp.PolicyError) as cm:
            sp.validate_policy(doc, F.REPOSITORY)
        self.assertIn(needle, str(cm.exception))

    def test_refusals(self):
        self.bad(lambda d: d.__setitem__("extra", 1), "unknown fields")
        self.bad(lambda d: d.__setitem__("repository", "tobipjuk/other"), "another repository")
        self.bad(lambda d: d.__setitem__("kind", "terraform"), "kind")
        self.bad(lambda d: d["lambda"]["members"].append("json.py"), "shadows")
        self.bad(lambda d: d["lambda"]["members"].append("boto3.py"), "shadows")
        self.bad(lambda d: d["lambda"]["members"].append("os.py"), "shadows")
        self.bad(lambda d: d["lambda"]["members"].append("sub/x.py"), "lambda member")
        self.bad(lambda d: d["prefixes"].append("img/sub/"), "overlap")
        self.bad(lambda d: d["prefixes"].append("../"), "prefix")
        self.bad(lambda d: d["root_keys"].append("img/x.png"), "contains '/'")
        self.bad(lambda d: d["manifest"].__setitem__("bucket", d["bucket"]), "outside the site bucket")
        self.bad(lambda d: d.__setitem__("bucket", "a.b.c"), "bucket")
        self.bad(lambda d: d["gate"]["tests"][0]["expect"].__setitem__("pass", False), "expect")
        self.bad(lambda d: d["gate"]["tests"].append(dict(d["gate"]["tests"][0])), "duplicate")
        self.bad(lambda d: d["smoke"].__setitem__("base_url", "http://x.example"), "base_url")
        self.bad(lambda d: d.__setitem__("max_objects", 50000), "max_objects")

    def test_load_policy_keyed_by_repository(self):
        pol, h = sp.load_policy(str(F.POLICY_DIR), F.REPOSITORY)
        self.assertEqual(h, hashlib.sha256((F.POLICY_DIR / "tobipjuk" / "lego-mindstorms.json").read_bytes()).hexdigest())
        for repo in ("tobipjuk/../x", "tobipjuk/nope", "x", "../../etc/passwd"):
            with self.assertRaises(sp.PolicyError):
                sp.load_policy(str(F.POLICY_DIR), repo)


class SiteJsonTest(unittest.TestCase):
    def setUp(self):
        self.pol = sp.validate_policy(policy())

    def test_ok(self):
        sp.validate_site_json(F.site_json(), self.pol)

    def bad(self, doc, needle):
        with self.assertRaises(sp.PolicyError) as cm:
            sp.validate_site_json(doc, self.pol)
        self.assertIn(needle, str(cm.exception))

    def test_refusals(self):
        d = F.site_json()
        d["mappings"][0]["cache"] = "forever"
        self.bad(d, "cache")
        d = F.site_json()
        d["mappings"][0]["content_type"] = "text/html"
        self.bad(d, "unknown fields")
        d = F.site_json()
        d["lambda_settings"]["handler"] = "evil.handler"
        self.bad(d, "allowlist")
        d = F.site_json()
        d["mappings"].append({"source_dir": "site", "prefix": "other/", "cache": "long"})
        self.bad(d, "outside the policy's SITE")
        d = F.site_json()
        d["mappings"] = d["mappings"] * 30
        self.bad(d, "mappings must have")

    def test_max_objects(self):
        pol = copy.deepcopy(self.pol)
        pol["max_objects"] = 3
        tree = {f"site/img/{i}.png": {} for i in range(5)}
        with self.assertRaises(sp.PolicyError):
            sp.expand_mappings({"mappings": [{"source_dir": "site/img", "prefix": "img/", "cache": "long"}]}, pol, tree)


class ClassifyTest(unittest.TestCase):
    def test_tables(self):
        self.assertEqual(sp.classify("a/b.html", "site/b.html"), ("code", "text/html; charset=utf-8"))
        self.assertEqual(sp.classify("x.ldr", "y.ldr"), ("data", "text/plain; charset=utf-8"))
        self.assertEqual(sp.classify("x.JPG", "y.JPG"), ("binary", "image/jpeg"))
        for k, s in (("x.html", "x.png"), ("x", "x"), ("x.exe", "x.exe"), ("X.JS", "X.JS"), ("x.md", "x.md")):
            with self.assertRaises(sp.PolicyError):
                sp.classify(k, s)

    def test_keys(self):
        for good in ("index.html", "community/clock/MOC-8716_Artem 16_clock.lxf", "a/(b) c.pdf"):
            sp.check_key(good)
        for bad in ("", "/x", "a//b", "a/../b", "a/./b", "a/ b", "x?y", "x#y", "x%2e", "x*", "‮x",
                    "café.png", "a\\b", "a\nb"):
            with self.assertRaises(sp.PolicyError, msg=bad):
                sp.check_key(bad)

    def test_magic(self):
        self.assertTrue(sp.magic_ok("webp", F.WEBP))
        self.assertFalse(sp.magic_ok("webp", b"RIFF\0\0\0\0WAVE"))
        self.assertTrue(sp.magic_ok("PNG", F.PNG))
        self.assertTrue(sp.magic_ok("mp4", b"\0\0\0\x20ftypisom"))
        self.assertFalse(sp.magic_ok("pdf", b"<html>"))


class PointerTest(unittest.TestCase):
    def test_strict(self):
        data = b"hello"
        self.assertEqual(lfs_fetch.parse_pointer(F.pointer(data)), (F.sha(data), 5))
        self.assertIsNone(lfs_fetch.parse_pointer(b"\x89PNG"))
        # Not pointer-like at all: plain bytes (a text key would upload and diff them in full;
        # a binary key would fail its magic check).
        self.assertIsNone(lfs_fetch.parse_pointer(F.pointer(data).upper()))
        for bad in (F.pointer(data).replace(b"\n", b"\r\n"), F.pointer(data) + b"\n",
                    F.pointer(data).replace(b"size 5", b"size 05"),
                    b"oid sha256:" + b"a" * 64 + b"\nversion https://git-lfs.github.com/spec/v1\nsize 1\n"):
            with self.assertRaises(lfs_fetch.LfsError):
                lfs_fetch.parse_pointer(bad)


class LfsClientTest(unittest.TestCase):
    def test_fetch_verify_head_missing(self):
        with F.FakeLfsServer() as srv:
            data = b"PK\x03\x04" + b"q" * 100
            srv.add(data)
            c = srv.client()
            oid = F.sha(data)
            missing = "0" * 64
            self.assertEqual(c.missing([(oid, len(data)), (missing, 3)]), [missing])
            with tempfile.TemporaryDirectory() as d:
                p = os.path.join(d, "o")
                c.fetch(oid, len(data), p)
                self.assertEqual(Path(p).read_bytes(), data)
                srv.objects[oid] = data[:-1] + b"x"
                with self.assertRaises(lfs_fetch.LfsError):
                    c.fetch(oid, len(data), p + "2")
                self.assertFalse(os.path.exists(p + "2"))
                self.assertFalse(os.path.exists(p + "2.part"))
            self.assertEqual(c.head(oid, len(data), 4), b"PK\x03\x04")
            # batch requests carry the token; downloads don't get it (only the action's header)
            batch = [r for r in srv.requests if r[0] == "batch"]
            self.assertTrue(all(r[2].startswith("Basic ") for r in batch))

    def test_https_only(self):
        with self.assertRaises(lfs_fetch.LfsError):
            lfs_fetch.LfsClient(F.REPOSITORY, "t", server="http://github.com")
        c = lfs_fetch.LfsClient(F.REPOSITORY, "t")
        with self.assertRaises(lfs_fetch.LfsError):
            c._check_url("http://evil.example/x")


FAKE_AWS = r"""#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_AWS_LOG"], "a") as f:
    f.write(json.dumps(args) + "\n")
secret = "LEAKED_EDGE_KEY_MARKER"
op = args[1]
if op == "test-function":
    if os.environ.get("FAKE_AWS_FAIL"):
        sys.stderr.write("An error occurred (FunctionExecutionError) when calling the TestFunction operation: "
                         "key is " + secret + "\n")
        sys.exit(254)
    print(json.dumps({"o": json.dumps({"response": {"statusCode": 302, "headers": {"location": {"value": "/p?" + secret}}}}),
                      "f": None}))
    sys.stderr.write("warning: logs " + secret + "\n")
elif op == "put-object":
    body = [a for a in args if a.startswith("--checksum-sha256=")][0].split("=", 1)[1]
    print(json.dumps({"e": '"abc"', "c": body}))
elif op == "get-object":
    sys.stderr.write("An error occurred (NoSuchKey) when calling the GetObject operation: The specified key does not exist.\n")
    sys.exit(254)
elif op == "get-function-configuration":
    print(json.dumps({"runtime": "python3.13", "env_names": ["TABLE"]}))
else:
    print("{}")
"""


class CliAwsTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)
        self.bin = os.path.join(self.d.name, "aws")
        Path(self.bin).write_text(FAKE_AWS)
        os.chmod(self.bin, stat.S_IRWXU)
        self.log = os.path.join(self.d.name, "log")
        os.environ["FAKE_AWS_LOG"] = self.log
        self.addCleanup(os.environ.pop, "FAKE_AWS_LOG", None)
        self.aws = site_aws.CliAws("eu-west-2", aws_bin=self.bin)

    def calls(self):
        return [json.loads(x) for x in Path(self.log).read_text().splitlines()]

    def test_test_function_output_stays_in_memory(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            r = self.aws.cf_test_function("gate", "E1", b"{}")
        self.assertNotIn(F.SECRET, buf.getvalue())
        self.assertEqual(set(r), {"output", "error"})
        self.assertIn("--query", self.calls()[-1])
        self.assertIn("--stage=DEVELOPMENT", self.calls()[-1])

    def test_errors_carry_only_the_code(self):
        os.environ["FAKE_AWS_FAIL"] = "1"
        self.addCleanup(os.environ.pop, "FAKE_AWS_FAIL", None)
        with self.assertRaises(site_aws.AwsError) as cm:
            self.aws.cf_test_function("gate", "E1", b"{}")
        self.assertEqual(str(cm.exception), "cloudfront:TestFunction: FunctionExecutionError")
        self.assertNotIn(F.SECRET, repr(cm.exception.__dict__))

    def test_not_found(self):
        with self.assertRaises(site_aws.NotFound):
            self.aws.get_object("b", "k", os.path.join(self.d.name, "o"))

    def test_put_object_is_conditional_single_part_with_checksum(self):
        p = os.path.join(self.d.name, "body")
        Path(p).write_bytes(b"x")
        h = base64.b64encode(hashlib.sha256(b"x").digest()).decode()
        self.assertEqual(self.aws.put_object("b", "-k.html", p, "text/html", "no-cache", h, if_match="e1"), "abc")
        self.aws.put_object("b", "k", p, "text/html", "no-cache", h, if_none_match=True)
        a, b = self.calls()
        self.assertIn("--key=-k.html", a)
        self.assertIn("--if-match=e1", a)
        self.assertIn("--if-none-match=*", b)
        self.assertIn("--checksum-algorithm=SHA256", a)
        self.assertIn(f"--checksum-sha256={h}", a)
        with self.assertRaises(site_aws.AwsError):
            self.aws.put_object("b", "k", p, "t", "c", h)
        with self.assertRaises(site_aws.AwsError):
            self.aws.put_object("b", "k", p, "t", "c", h, if_match="e", if_none_match=True)

    def test_lambda_configuration_never_asks_for_env_values(self):
        self.aws.lambda_get_configuration("fn")
        q = self.calls()[-1][self.calls()[-1].index("--query") + 1]
        self.assertIn("keys(Environment.Variables", q)
        self.assertNotIn("Environment.Variables}", q)

    def test_code_location_must_be_aws(self):
        with self.assertRaises(site_aws.AwsError):
            self.aws.download("https://evil.example/x.zip", os.path.join(self.d.name, "z"))
        with self.assertRaises(site_aws.AwsError):
            self.aws.download("http://x.s3.amazonaws.com/x.zip", os.path.join(self.d.name, "z"))


if __name__ == "__main__":
    unittest.main()
