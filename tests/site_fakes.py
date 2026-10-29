"""Fakes for the site pipeline tests: AWS in memory, a GitHub LFS server on loopback, a fixture
git repository. Nothing here talks to AWS or GitHub."""
import base64
import hashlib
import http.server
import io
import json
import os
import subprocess
import tempfile
import threading
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
import sys  # noqa: E402

sys.path.insert(0, str(SCRIPTS))
import site_aws  # noqa: E402

POLICY_DIR = ROOT / "tests" / "fixtures" / "site" / "policy"
REPOSITORY = "tobipjuk/lego-mindstorms"
SECRET = "LEAKED_EDGE_KEY_MARKER"

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 40
WOFF2 = b"wOF2" + b"\x01" * 40
PDF = b"%PDF-1.7\n" + b"x" * 500
WEBP = b"RIFF\x24\x00\x00\x00WEBPVP8 " + b"\x02" * 60

GATE_JS = b"""// gate
function handler(event) {
  var req = event.request, uri = req.uri;
  if (uri === '/pin.html' || uri.indexOf('/fonts/') === 0) return req;
  return { statusCode: 302, headers: { location: { value: '/pin.html?next=' + encodeURIComponent(uri) } } };
}
"""
PROGRESS_PY = b"import json\n\nimport session\n\n\ndef handler(event, _context):\n    return {'statusCode': 401}\n"
SESSION_PY = b"import hmac\n\n\ndef valid(token):\n    return False\n"
LAMBDA_SETTINGS = {"runtime": "python3.13", "handler": "progress.handler", "memory_size": 256, "timeout": 10,
                   "architectures": ["arm64"], "env_names": ["TABLE", "SECRET_NAME"], "layers": [],
                   "vpc": False, "kms_key_arn": None, "package_type": "Zip"}


def md5(b):
    return hashlib.md5(b).hexdigest()


def sha(b):
    return hashlib.sha256(b).hexdigest()


def b64sha(b):
    return base64.b64encode(hashlib.sha256(b).digest()).decode()


def pointer(data):
    return f"version https://git-lfs.github.com/spec/v1\noid sha256:{sha(data)}\nsize {len(data)}\n".encode()


def make_zip(members, ts=(2025, 5, 5, 5, 5, 6)):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in members.items():
            z.writestr(zipfile.ZipInfo(n, date_time=ts), d)
    return buf.getvalue()


# --- AWS -------------------------------------------------------------------------------------------

class FakeAws:
    """Implements the site_aws.CliAws interface in memory, with S3/Lambda/CloudFront semantics
    the pipeline relies on (conditional writes, revision ids, function stages and ETags)."""

    def __init__(self):
        self.buckets = {}
        self.lambdas = {}
        self.functions = {}
        self.invalidations = {}
        self.calls = []
        self.faults = {}   # op name -> exception to raise (once per entry in a list) or callable
        # The plan role denies kms:Decrypt, so Lambda can't decrypt the environment for it and
        # GetFunctionConfiguration returns Environment = {"Error": {"ErrorCode":
        # "AccessDeniedException"}} without Variables (seen live, Guardian on fff80e5 M1).
        # True models a role that may decrypt (the names come back).
        self.lambda_env_readable = False
        self.n = 0

    def _tick(self):
        self.n += 1
        return self.n

    def _call(self, op, *detail):
        self.calls.append((op,) + detail)
        f = self.faults.get(op)
        if isinstance(f, list) and f:
            exc = f.pop(0)
            if exc is not None:
                raise exc
        elif callable(f):
            f(*detail)

    # S3
    def put_live(self, bucket, key, data, ct="application/octet-stream", cc="", multipart=False):
        b = self.buckets.setdefault(bucket, {})
        etag = md5(data)
        if multipart:
            parts = [hashlib.md5(data[i:i + 8 * 1024 * 1024]).digest() for i in range(0, len(data), 8 * 1024 * 1024)]
            etag = hashlib.md5(b"".join(parts)).hexdigest() + f"-{len(parts)}"
        b[key] = {"data": data, "etag": etag, "ct": ct, "cc": cc, "lm": f"2026-10-27T10:{self._tick():05d}Z"}

    def set_meta(self, bucket, key, ct=None, cc=None):
        """A metadata-only change (copy-object in place): same ETag, new LastModified."""
        o = self.buckets[bucket][key]
        if ct is not None:
            o["ct"] = ct
        if cc is not None:
            o["cc"] = cc
        o["lm"] = f"2026-10-27T11:{self._tick():05d}Z"

    def list_objects(self, bucket):
        self._call("s3:ListObjectsV2", bucket)
        return {k: {"etag": v["etag"], "size": len(v["data"]), "last_modified": v["lm"]}
                for k, v in self.buckets.get(bucket, {}).items()}

    def get_object(self, bucket, key, dest):
        return self.get_object_meta(bucket, key, dest)["etag"]

    def get_object_meta(self, bucket, key, dest):
        self._call("s3:GetObject", bucket, key)
        o = self.buckets.get(bucket, {}).get(key)
        if o is None:
            raise site_aws.NotFound("s3:GetObject", "NoSuchKey")
        with open(dest, "wb") as f:
            f.write(o["data"])
        return {"etag": o["etag"], "content_type": o["ct"], "cache_control": o["cc"]}

    def head_object(self, bucket, key):
        self._call("s3:HeadObject", bucket, key)
        o = self.buckets.get(bucket, {}).get(key)
        if o is None:
            raise site_aws.NotFound("s3:HeadObject", "404")
        return {"etag": o["etag"], "content_type": o["ct"], "cache_control": o["cc"]}

    def head_objects(self, bucket, keys, progress=None):
        return {k: self.head_object(bucket, k) for k in keys}

    def put_object(self, bucket, key, path, content_type, cache_control, sha256_b64, if_match=None, if_none_match=False):
        self._call("s3:PutObject", bucket, key)
        if bool(if_match) == bool(if_none_match):
            raise site_aws.AwsError("s3:PutObject", "unconditional write")
        with open(path, "rb") as f:
            data = f.read()
        if b64sha(data) != sha256_b64:
            raise site_aws.AwsError("s3:PutObject", "BadDigest")
        b = self.buckets.setdefault(bucket, {})
        cur = b.get(key)
        if if_none_match and cur is not None:
            raise site_aws.AwsError("s3:PutObject", "PreconditionFailed")
        if if_match and (cur is None or cur["etag"] != if_match):
            raise site_aws.AwsError("s3:PutObject", "PreconditionFailed")
        b[key] = {"data": data, "etag": md5(data), "ct": content_type, "cc": cache_control,
                  "lm": f"2026-10-27T12:{self._tick():05d}Z"}
        return b[key]["etag"]

    def delete_object(self, bucket, key, if_match):
        self._call("s3:DeleteObject", bucket, key)
        cur = self.buckets.get(bucket, {}).get(key)
        if cur is None or cur["etag"] != if_match:
            raise site_aws.AwsError("s3:DeleteObject", "PreconditionFailed")
        del self.buckets[bucket][key]

    # Lambda
    def set_lambda(self, name, zip_bytes, config=None):
        cfg = dict(config or {})
        self.lambdas[name] = {"zip": zip_bytes, "revision": f"rev-{self._tick()}", "config": cfg}

    def lambda_get_function(self, name):
        self._call("lambda:GetFunction", name)
        f = self.lambdas[name]
        return {"location": f"https://awslambda-eu-west-2-tasks.s3.eu-west-2.amazonaws.com/{name}",
                "repository_type": "S3", "code_sha256": b64sha(f["zip"]), "revision_id": f["revision"]}

    def download(self, url, dest, max_bytes=0):
        self._call("lambda:code download", url)
        name = url.rsplit("/", 1)[-1]
        with open(dest, "wb") as fh:
            fh.write(self.lambdas[name]["zip"])

    def lambda_get_configuration(self, name):
        self._call("lambda:GetFunctionConfiguration", name)
        f = self.lambdas[name]
        c = f["config"]
        return {"runtime": c.get("runtime"), "handler": c.get("handler"), "memory_size": c.get("memory_size"),
                "timeout": c.get("timeout"), "architectures": c.get("architectures"),
                "env_names": sorted((c.get("env") or {}).keys()) if self.lambda_env_readable or not c.get("env")
                else [],
                "env_error": None if self.lambda_env_readable or not c.get("env") else "AccessDeniedException",
                "layers": c.get("layers") or None,
                "vpc_id": c.get("vpc_id"), "kms_key_arn": c.get("kms_key_arn"), "package_type": "Zip",
                "revision_id": f["revision"], "code_sha256": b64sha(f["zip"]), "state": "Active",
                "last_update_status": "Successful"}

    def lambda_update_code(self, name, zip_path, revision_id):
        self._call("lambda:UpdateFunctionCode", name)
        f = self.lambdas[name]
        if revision_id != f["revision"]:
            raise site_aws.AwsError("lambda:UpdateFunctionCode", "PreconditionFailedException")
        with open(zip_path, "rb") as fh:
            f["zip"] = fh.read()
        f["revision"] = f"rev-{self._tick()}"
        return {"code_sha256": b64sha(f["zip"]), "revision_id": f["revision"]}

    # CloudFront Functions
    def set_function(self, name, code, config=None, dev_code=None):
        cfg = config or {"Comment": "PIN", "Runtime": "cloudfront-js-2.0",
                         "KeyValueStoreAssociations": ["arn:aws:cloudfront::880207437749:key-value-store/kvs-1"]}
        self.functions[name] = {
            "LIVE": {"code": code, "etag": f"L{self._tick()}", "config": dict(cfg)},
            "DEVELOPMENT": {"code": dev_code if dev_code is not None else code, "etag": f"D{self._tick()}",
                            "config": dict(cfg)},
        }

    def cf_describe_function(self, name, stage):
        self._call("cloudfront:DescribeFunction", name, stage)
        s = self.functions[name][stage]
        return {"etag": s["etag"], "status": "DEPLOYED", "config": dict(s["config"])}

    def cf_get_function(self, name, stage):
        self._call("cloudfront:GetFunction", name, stage)
        s = self.functions[name][stage]
        return s["code"], s["etag"]

    def cf_update_function(self, name, if_match, config, code):
        self._call("cloudfront:UpdateFunction", name)
        d = self.functions[name]["DEVELOPMENT"]
        if if_match != d["etag"]:
            raise site_aws.AwsError("cloudfront:UpdateFunction", "PreconditionFailed")
        if config != d["config"]:
            raise AssertionError("FunctionConfig changed")
        d["code"] = code
        d["etag"] = f"D{self._tick()}"
        return d["etag"]

    gate_secret_in_output = False

    def cf_test_function(self, name, if_match, event):
        self._call("cloudfront:TestFunction", name)
        d = self.functions[name]["DEVELOPMENT"]
        if if_match != d["etag"]:
            raise site_aws.AwsError("cloudfront:TestFunction", "PreconditionFailed")
        ev = json.loads(event)
        req = ev["request"]
        code = d["code"]
        uri = req["uri"]
        if b"BROKEN" in code:
            out = {"request": req}  # lets everything through
        elif b"LEAK" in code:
            out = {"response": {"statusCode": 302, "headers": {"location": {"value": f"/x?k={SECRET}"},
                                                                "x-key": {"value": SECRET}}}}
        elif uri == "/pin.html" or uri.startswith("/fonts/"):
            out = {"request": req}
        else:
            out = {"response": {"statusCode": 302, "statusDescription": "Found",
                                "headers": {"location": {"value": "/pin.html?next=" + uri}}}}
        if self.gate_secret_in_output and "request" in out:
            out["request"]["headers"]["x-ev3-edge"] = {"value": SECRET}
        return {"output": json.dumps(out), "error": False}

    def cf_publish_function(self, name, if_match):
        self._call("cloudfront:PublishFunction", name)
        fn = self.functions[name]
        if if_match != fn["DEVELOPMENT"]["etag"]:
            raise site_aws.AwsError("cloudfront:PublishFunction", "PreconditionFailed")
        fn["LIVE"] = {"code": fn["DEVELOPMENT"]["code"], "etag": f"L{self._tick()}",
                      "config": dict(fn["DEVELOPMENT"]["config"])}
        return "UNASSOCIATED"

    def cf_create_invalidation(self, distribution_id, paths, caller_reference):
        self._call("cloudfront:CreateInvalidation", distribution_id, tuple(paths))
        i = f"I{self._tick()}"
        self.invalidations[i] = list(paths)
        return i

    def cf_get_invalidation(self, distribution_id, inv_id):
        self._call("cloudfront:GetInvalidation", distribution_id, inv_id)
        return "Completed"

    def writes(self):
        w = {"s3:PutObject", "s3:DeleteObject", "lambda:UpdateFunctionCode", "cloudfront:UpdateFunction",
             "cloudfront:PublishFunction"}
        return [c for c in self.calls if c[0] in w]


# --- LFS server ---------------------------------------------------------------------------------

class FakeLfsServer:
    """GitHub's LFS batch API + downloads, on 127.0.0.1. `objects` = {oid: bytes served};
    serve bytes that don't match their oid to test verification."""

    def __init__(self):
        self.objects = {}
        self.requests = []
        self.no_ranges = False
        self.range_override = {}
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append(("batch", [o["oid"] for o in body["objects"]], self.headers.get("Authorization")))
                objs = []
                for o in body["objects"]:
                    if o["oid"] in outer.objects:
                        objs.append({"oid": o["oid"], "size": o["size"], "actions": {"download": {
                            "href": f"http://127.0.0.1:{outer.port}/obj/{o['oid']}",
                            "header": {"X-Token": "dl"}}}})
                    else:
                        objs.append({"oid": o["oid"], "size": o["size"], "error": {"code": 404, "message": "nope"}})
                data = json.dumps({"transfer": "basic", "objects": objs}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/vnd.git-lfs+json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                oid = self.path.rsplit("/", 1)[-1]
                rng = self.headers.get("Range")
                outer.requests.append(("get", oid, rng))
                data = outer.objects.get(oid)
                if data is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                if rng and oid in outer.range_override:
                    data = outer.range_override[oid]
                    self.send_response(206)
                elif rng and not outer.no_ranges:
                    end = int(rng.split("-")[1])
                    data = data[:end + 1]
                    self.send_response(206)
                else:
                    self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()

    def add(self, data):
        self.objects[sha(data)] = data

    def client(self):
        import lfs_fetch
        return lfs_fetch.LfsClient(REPOSITORY, "tok", server=f"http://127.0.0.1:{self.port}",
                                   allow_loopback_http=True, timeout=10)


# --- fixture repository ------------------------------------------------------------------------------

def site_json(**over):
    doc = {
        "schema": 1,
        "mappings": [
            {"source": "site/index.html", "key": "index.html", "cache": "short"},
            {"source": "site/pin.html", "key": "pin.html", "cache": "short"},
            {"source": "site/book.html", "key": "book.html", "cache": "short"},
            {"source": "site/sw.js", "key": "sw.js", "cache": "no-cache"},
            {"source": "site/community.json", "key": "community.json", "cache": "short"},
            {"source_dir": "site/img", "prefix": "img/", "cache": "long"},
            {"source_dir": "site/fonts", "prefix": "fonts/", "cache": "long"},
            {"source_dir": "building-instructions/pages/public", "prefix": "pages/", "cache": "immutable"},
            {"source_dir": "building-instructions/official", "prefix": "instructions/", "cache": "long",
             "include": ["*.pdf"]},
            {"source_dir": "building-instructions/community", "prefix": "community/", "cache": "private-day",
             "exclude": ["README.md"]},
        ],
        "lambda_settings": dict(LAMBDA_SETTINGS),
    }
    doc.update(over)
    return doc


def base_files():
    """{path: bytes} of a small Workshop. LFS-tracked files are written as pointers; their real
    bytes are returned in the second dict (oid -> bytes) for the fake LFS server."""
    lfs = {}

    def via_lfs(data):
        lfs[sha(data)] = data
        return pointer(data)
    files = {
        "deploy/site.json": json.dumps(site_json(), indent=1).encode(),
        "site/index.html": b"<!doctype html>\n<title>Workshop</title>\n<script src=\"app.js\"></script>\n",
        "site/pin.html": b"<!doctype html>\n<form>PIN</form>\n",
        "site/book.html": b"<!doctype html>\n<p>book</p>\n",
        "site/sw.js": b"const CACHE = 'v1';\nself.addEventListener('fetch', () => {});\n",
        "site/community.json": b"{\"models\": []}\n",
        "site/img/logo.png": PNG,
        "site/fonts/a.woff2": WOFF2,
        "site/api/progress.py": PROGRESS_PY,
        "site/api/session.py": SESSION_PY,
        "site/api/test_api.py": b"import unittest\n",
        "site/api/viewer_gate.js": GATE_JS,
        "building-instructions/pages/public/abc123/p001.webp": via_lfs(WEBP),
        "building-instructions/pages/public/abc123/p002.webp": via_lfs(WEBP + b"2"),
        "building-instructions/official/core.pdf": via_lfs(PDF),
        "building-instructions/community/clock/model.ldr": b"0 clock\n1 16 0 0 0 1 0 0 0 1 0 0 0 1 3001.dat\n",
        "building-instructions/community/clock/MOC clock.lxf": via_lfs(b"PK\x03\x04" + b"z" * 50),
        "building-instructions/community/README.md": b"# readme\n",
    }
    return files, lfs


class FixtureRepo:
    def __init__(self, root):
        self.dir = root
        os.makedirs(root, exist_ok=True)
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                        GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e", GIT_COMMITTER_NAME="t",
                        GIT_COMMITTER_EMAIL="t@e")
        self.git("init", "-q", "-b", "main")

    def git(self, *args):
        r = subprocess.run(["git", "-C", self.dir, *args], capture_output=True, env=self.env, check=True)
        return r.stdout.decode().strip()

    def commit(self, files, delete=(), symlinks=None, msg="c"):
        for p, data in files.items():
            fp = Path(self.dir, p)
            fp.parent.mkdir(parents=True, exist_ok=True)
            if fp.is_symlink():
                fp.unlink()
            fp.write_bytes(data)
        for p, target in (symlinks or {}).items():
            fp = Path(self.dir, p)
            fp.parent.mkdir(parents=True, exist_ok=True)
            if fp.exists() or fp.is_symlink():
                fp.unlink()
            os.symlink(target, fp)
        for p in delete:
            Path(self.dir, p).unlink()
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", msg)
        return self.git("rev-parse", "HEAD")


def load_policy():
    import site_policy
    return site_policy.load_policy(str(POLICY_DIR), REPOSITORY)


def deploy_like_mac(aws, files, lfs, policy, multipart_pdf=False):
    """Put the site live the way deploy_aws.sh does today (no manifest)."""
    import site_policy
    sitej = json.loads(files["deploy/site.json"])
    tree = {p: {"mode": "100644", "type": "blob", "oid": "x"} for p in files}
    mapping = site_policy.expand_mappings(sitej, policy, tree)
    for key, (src, cache) in mapping.items():
        data = files[src]
        if data.startswith(b"version https://git-lfs"):
            data = lfs[data.split(b"oid sha256:")[1][:64].decode()]
        _, ct = site_policy.classify(key, src)
        aws.put_live(policy["bucket"], key, data, ct, site_policy.CACHE_CLASSES[cache],
                     multipart=multipart_pdf and key.endswith(".pdf"))
    aws.set_lambda(policy["lambda"]["function_name"],
                   make_zip({"progress.py": files["site/api/progress.py"], "session.py": files["site/api/session.py"]}),
                   {**LAMBDA_SETTINGS, "env": {"TABLE": "t", "SECRET_NAME": "s"}})
    aws.set_function(policy["gate"]["function_name"], files["site/api/viewer_gate.js"])


class Env:
    """A fixture repo + fake AWS + fake LFS, ready for site_plan / site_apply."""

    def __init__(self, testcase, live=True, multipart_pdf=False):
        self.tmp = tempfile.TemporaryDirectory(prefix="site-test-")
        testcase.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = FixtureRepo(str(self.root / "repo"))
        self.files, self.lfs_objects = base_files()
        self.sha = self.repo.commit(self.files)
        self.policy, self.policy_sha = load_policy()
        self.aws = FakeAws()
        self.lfs = FakeLfsServer().__enter__()
        testcase.addCleanup(self.lfs.__exit__)
        for d in self.lfs_objects.values():
            self.lfs.add(d)
        if live:
            deploy_like_mac(self.aws, self.files, self.lfs_objects, self.policy, multipart_pdf=multipart_pdf)
        self.out = self.root / "out"

    def commit(self, files=None, delete=(), symlinks=None, lfs=None):
        for d in (lfs or []):
            self.lfs.add(d)
            self.lfs_objects[sha(d)] = d
        self.files.update(files or {})
        for p in delete:
            self.files.pop(p, None)
        self.sha = self.repo.commit(files or {}, delete=delete, symlinks=symlinks)
        return self.sha

    def plan_args(self, event="workflow_dispatch", deploy=True, allow_destroy=False, extra=()):
        return ["--repo-dir", str(self.repo.dir), "--sha", self.sha, "--repository", REPOSITORY,
                "--policy-dir", str(POLICY_DIR), "--event", event, "--out-dir", str(self.out),
                "--deploy-enabled", "true" if deploy else "false",
                "--allow-destroy", "true" if allow_destroy else "false",
                "--github-output", str(self.root / "gh-output"), "--summary", str(self.root / "step-summary.md"),
                "--meta", "run_id=777", "--meta", "run_attempt=1", "--meta", "event=" + event, *extra]
