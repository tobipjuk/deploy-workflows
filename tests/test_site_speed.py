"""Adoption speed (run 40854404792: ~9,000 live binary keys, one `aws` process per HEAD and
one LFS fetch at a time, ran out of the job's 45 minutes): the HTTP HEAD path (SigV4 signed
here), run_parallel, and that the parallel adoption decides exactly what the old one did."""
import contextlib
import datetime as dt
import http.server
import io
import os
import threading
import time
import unittest

import site_fakes as F  # noqa: E402  (puts scripts/ on sys.path)
import site_aws  # noqa: E402
import site_policy as sp  # noqa: E402
import site_plan  # noqa: E402
import test_site_plan as T  # noqa: E402

CREDS = ("AKIDEXAMPLE", "SECRET_KEY_MARKER", "SESSION_TOKEN_MARKER")


class SigV4Test(unittest.TestCase):
    def test_aws_documented_vector(self):
        """AWS S3 SigV4 docs, "GET Object" example (header-based auth)."""
        h = site_aws.sigv4_headers("GET", "examplebucket.s3.amazonaws.com", "/test.txt", "", "us-east-1", "s3",
                                   ("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", None),
                                   "20130524T000000Z", {"Range": "bytes=0-9"})
        self.assertEqual(h["authorization"],
                         "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, "
                         "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, "
                         "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
        self.assertNotIn("host", h)  # http.client sends Host itself

    def test_session_token_is_signed(self):
        h = site_aws.sigv4_headers("HEAD", "b.s3.eu-west-2.amazonaws.com", "/k", "", "eu-west-2", "s3", CREDS,
                                   "20261029T000000Z")
        self.assertEqual(h["x-amz-security-token"], CREDS[2])
        self.assertIn("SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token,", h["authorization"])

    def test_uri_encode(self):
        e = site_aws._uri_encode
        self.assertEqual(e("pages/a b/p~1.webp", True), "pages/a%20b/p~1.webp")
        self.assertEqual(e("community/é+x", True), "community/%C3%A9%2Bx")
        self.assertEqual(e("a/b", False), "a%2Fb")


class FakeS3:
    """HEAD on 127.0.0.1: checks the signed Host and the auth header, serves metadata."""

    def __init__(self):
        self.objects = {}   # path -> (etag, ct, cc)
        self.fail = []      # statuses to answer first, in order
        self.requests = []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_HEAD(self):
                outer.requests.append((self.path, self.headers.get("Host"), self.headers.get("Authorization"),
                                       self.headers.get("x-amz-security-token")))
                if outer.fail:
                    self.send_response(outer.fail.pop(0))
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                o = outer.objects.get(self.path)
                if o is None:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("ETag", f'"{o[0]}"')
                self.send_header("Content-Type", o[1])
                if o[2] is not None:
                    self.send_header("Cache-Control", o[2])
                self.send_header("Content-Length", "123")
                self.end_headers()

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def client(self):
        return site_aws.S3HeadHttp("my-bucket", "eu-west-2", CREDS, endpoint=("127.0.0.1", self.port),
                                   clock=lambda: dt.datetime(2026, 10, 29, tzinfo=dt.timezone.utc))


class S3HeadHttpTest(unittest.TestCase):
    def setUp(self):
        self.s3 = FakeS3()
        self.addCleanup(self.s3.close)
        self.c = self.s3.client()
        self.addCleanup(self.c.close)
        saved = site_aws.HEAD_BACKOFF
        site_aws.HEAD_BACKOFF = 0
        self.addCleanup(setattr, site_aws, "HEAD_BACKOFF", saved)

    def test_200_returns_the_cli_fields(self):
        self.s3.objects["/pages/a%20b/p1.webp"] = ("e1", "image/webp", "public, max-age=31536000, immutable")
        self.s3.objects["/img/x.png"] = ("e2", "image/png", None)
        self.assertEqual(self.c.head("pages/a b/p1.webp"), {"etag": "e1", "content_type": "image/webp",
                                                            "cache_control": "public, max-age=31536000, immutable"})
        self.assertEqual(self.c.head("img/x.png"), {"etag": "e2", "content_type": "image/png", "cache_control": None})
        path, host, auth, tok = self.s3.requests[0]
        self.assertEqual(host, "my-bucket.s3.eu-west-2.amazonaws.com")
        self.assertTrue(auth.startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261029/eu-west-2/s3/aws4_request"))
        self.assertEqual(tok, CREDS[2])

    def test_errors_carry_only_the_status(self):
        with self.assertRaises(site_aws.NotFound) as cm:
            self.c.head("nope")
        self.assertEqual(str(cm.exception), "s3:HeadObject: 404")
        self.s3.fail = [403]
        with self.assertRaises(site_aws.AwsError) as cm:
            self.c.head("nope")
        self.assertEqual(str(cm.exception), "s3:HeadObject: 403")
        for marker in CREDS:
            self.assertNotIn(marker, repr(cm.exception.__dict__))

    def test_retries_throttling_and_5xx(self):
        self.s3.objects["/k"] = ("e", "text/plain", "no-cache")
        self.s3.fail = [503, 500]
        self.assertEqual(self.c.head("k")["etag"], "e")
        self.s3.fail = [503] * site_aws.HEAD_ATTEMPTS
        with self.assertRaises(site_aws.AwsError) as cm:
            self.c.head("k")
        self.assertEqual(str(cm.exception), "s3:HeadObject: 503")

    def test_real_endpoints_only_or_loopback(self):
        with self.assertRaises(site_aws.AwsError):
            site_aws.S3HeadHttp("bad.bucket.name", "eu-west-2", CREDS)
        with self.assertRaises(site_aws.AwsError):
            site_aws.S3HeadHttp("b-1", "eu-west-2/../x", CREDS)
        c = site_aws.S3HeadHttp("b-1", "eu-west-2", CREDS, endpoint=("example.com", 80))
        with self.assertRaises(site_aws.AwsError):
            c.head("k")
        self.assertEqual(site_aws.S3HeadHttp("b-1", "eu-west-2", CREDS).host, "b-1.s3.eu-west-2.amazonaws.com")


class HttpPathChoiceTest(unittest.TestCase):
    def setUp(self):
        saved = {k: os.environ.get(k) for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")}

        def restore():
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        self.addCleanup(restore)
        os.environ.update(AWS_ACCESS_KEY_ID=CREDS[0], AWS_SECRET_ACCESS_KEY=CREDS[1], AWS_SESSION_TOKEN=CREDS[2])

    def test_runner_shape_uses_http(self):
        c = site_aws.CliAws("eu-west-2")._http_head_client("ev3-workshop-880207437749")
        self.assertIsInstance(c, site_aws.S3HeadHttp)
        self.assertEqual(c.creds, CREDS)

    def test_cli_whenever_it_is_not_the_runner_shape(self):
        self.assertIsNone(site_aws.CliAws("eu-west-2", profile="lego")._http_head_client("b-1"))
        self.assertIsNone(site_aws.CliAws("eu-west-2", aws_bin="/x/aws")._http_head_client("b-1"))
        self.assertIsNone(site_aws.CliAws("eu-west-2", s3_http=False)._http_head_client("b-1"))
        self.assertIsNone(site_aws.CliAws("eu-west-2")._http_head_client("dotted.bucket"))
        os.environ.pop("AWS_SECRET_ACCESS_KEY")
        self.assertIsNone(site_aws.CliAws("eu-west-2")._http_head_client("b-1"))

    def test_head_objects_through_the_http_path(self):
        s3 = FakeS3()
        self.addCleanup(s3.close)
        for i in range(40):
            s3.objects[f"/p/{i}.webp"] = (f"e{i}", "image/webp", "c")
        aws = site_aws.CliAws("eu-west-2", s3_http=lambda bucket: s3.client())
        lines = []
        got = aws.head_objects("my-bucket", [f"p/{i}.webp" for i in range(40)], progress=lines.append)
        self.assertEqual({k: v["etag"] for k, v in got.items()}, {f"p/{i}.webp": f"e{i}" for i in range(40)})
        self.assertTrue(lines[-1].startswith("site plan: HEAD (https) 40/40 ("), lines[-1])
        self.assertFalse(any("webp" in x for x in lines))  # counts only, never key names


class RunParallelTest(unittest.TestCase):
    def test_results_and_first_error(self):
        self.assertEqual(site_aws.run_parallel(lambda x: x * 2, range(50), 8, "x", progress=None),
                         {i: i * 2 for i in range(50)})
        self.assertEqual(site_aws.run_parallel(lambda x: x, [], 8, "x", progress=None), {})
        ran = []

        def f(x):
            ran.append(x)
            time.sleep(0.001)
            if x == 3:
                raise site_aws.AwsError("s3:HeadObject", "403")
            return x
        with self.assertRaises(site_aws.AwsError):
            site_aws.run_parallel(f, range(10000), 2, "x", progress=None)
        self.assertLess(len(ran), 10000)  # the rest was cancelled, not run


class ParallelAdoptionTest(unittest.TestCase):
    def test_bulk_head_once_for_exactly_the_compared_keys(self):
        env = F.Env(self)
        calls = []
        orig = env.aws.head_objects

        def spy(bucket, keys, progress=None):
            calls.append(list(keys))
            return orig(bucket, keys, progress)
        env.aws.head_objects = spy
        rc, log = T.run_plan(env)
        self.assertEqual(rc, 0, log)
        self.assertEqual(len(calls), 1)
        binary = sorted(k for k in env.aws.buckets[env.policy["bucket"]] if sp.classify(k, k)[0] == "binary")
        self.assertEqual(sorted(calls[0]), binary)
        self.assertIn("site plan: adoption,", log)

    def test_duplicate_lfs_objects_fetched_once_both_compared(self):
        env = F.Env(self)
        env.commit({"building-instructions/pages/public/abc123/p003.webp": F.pointer(F.WEBP)})
        env.aws.put_live(env.policy["bucket"], "pages/abc123/p003.webp", F.WEBP, "image/webp",
                         sp.CACHE_CLASSES["immutable"])
        rc, log = T.run_plan(env)
        self.assertEqual(rc, 0, log)
        self.assertEqual(T.summary(env)["counts"]["add"], 0)
        gets = [r for r in env.lfs.requests if r[0] == "get" and r[1] == F.sha(F.WEBP)]
        self.assertEqual(len(gets), 1)

    def test_one_stale_live_object_is_still_a_content_put(self):
        """Same size, different bytes: the ETag check still catches it (no weaker check)."""
        env = F.Env(self)
        b = env.aws.buckets[env.policy["bucket"]]["pages/abc123/p001.webp"]
        b["data"] = bytes(len(F.WEBP))
        b["etag"] = F.md5(b["data"])
        rc, log = T.run_plan(env)
        self.assertEqual(rc, 0, log)
        doc = T.summary(env)
        self.assertIn({"actions": ["update"], "address": "s3:pages/abc123/p001.webp"}, doc["changes"])

    def test_expired_lfs_href_is_asked_for_again(self):
        env = F.Env(self)
        lfs = env.lfs.client()
        orig_batch = lfs.batch

        def short_lived(objects):
            return {o: (dict(a, expires_in=0) if a else a) for o, a in orig_batch(objects).items()}
        lfs.batch = short_lived
        seen = []
        orig_fetch = lfs.fetch

        def fetch(oid, size, dest, action=None):
            seen.append(action)
            return orig_fetch(oid, size, dest, action=action)
        lfs.fetch = fetch
        err, out = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            rc = site_plan.main(env.plan_args(), aws=env.aws, lfs=lfs)
        self.assertEqual(rc, 0, out.getvalue() + err.getvalue())
        self.assertTrue(seen)
        self.assertTrue(all(a is None for a in seen))  # every fetch re-asked the batch API


if __name__ == "__main__":
    unittest.main()
