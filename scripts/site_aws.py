#!/usr/bin/env python3
"""AWS access for the site pipeline, through the `aws` CLI on the runner. Stdlib only.
One exception, for speed: bulk HeadObject (head_objects) signs its own HTTPS requests (SigV4)
with the same environment credentials, to the same S3 host, when it runs on the runner.

site_plan.py and site_apply.py take an object with these methods (tests inject a fake), so
the diff and apply logic never touch AWS directly. This implementation is deliberately
SILENT: it captures every byte the CLI prints, keeps only the fields the caller asked for
(CLI `--query` projections, so e.g. Lambda environment values never leave the CLI process),
and turns failures into AwsError("<operation>: <AWS error code>"), never the AWS message.
That matters for the gate: TestFunction output, function logs and error messages could carry
a key the gate's code chose to put there (round 4 M1, round 5 L4).
"""
import datetime as dt
import hashlib
import hmac
import http.client
import json
import os
import re
import ssl
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import urllib.error
import urllib.parse
import urllib.request

MAX_LAMBDA_ZIP = 70 * 1024 * 1024
_CODE_RE = re.compile(r"An error occurred \(([A-Za-z0-9.]{1,64})\)")
# Bulk HEAD (adoption plans HEAD every live binary key, ~9,000 for lego-mindstorms): one `aws`
# process per key costs ~0.75 s of CPU-bound start-up, so 8 threads on a 4-vCPU runner managed
# ~4 keys/s and the plan ran out of its 45 minutes (run 40854404792). The HTTP path signs the
# same HeadObject request itself (SigV4, stdlib) with the credentials configure-aws-credentials
# put in the environment, to the host the CLI uses, over one kept-alive TLS connection per thread.
HEAD_WORKERS_HTTP = 16
HEAD_WORKERS_CLI = 8
HEAD_ATTEMPTS = 4
HEAD_BACKOFF = 0.2     # seconds, doubled per retry, at most 3 s
_BUCKET_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]")
_REGION_RE = re.compile(r"[a-z]{2}(-[a-z]+)+-[0-9]")
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def _uri_encode(s, slash_ok):
    """SigV4 URI encoding: every byte except A-Z a-z 0-9 - . _ ~ (and '/' in a path) as %XX."""
    safe = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~" + (b"/" if slash_ok else b"")
    return "".join(chr(b) if b in safe else "%%%02X" % b for b in s.encode("utf-8"))


def sigv4_headers(method, host, path, query, region, service, creds, amz_date, headers=None,
                  payload_sha256=EMPTY_SHA256):
    """Headers for a SigV4-signed request (AWS Signature Version 4, header form). path and
    query are already URI-encoded; creds = (access key id, secret, session token or None)."""
    access, secret, token = creds
    h = {"host": host, "x-amz-content-sha256": payload_sha256, "x-amz-date": amz_date}
    if token:
        h["x-amz-security-token"] = token
    for k, v in (headers or {}).items():
        h[k.lower()] = v
    names = sorted(h)
    canonical = "\n".join([method, path, query, "".join(f"{k}:{' '.join(str(h[k]).split())}\n" for k in names),
                           ";".join(names), payload_sha256])
    day = amz_date[:8]
    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    k = ("AWS4" + secret).encode()
    for part in (day, region, service, "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    out = {k: v for k, v in h.items() if k != "host"}
    out["authorization"] = f"AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={';'.join(names)}, Signature={sig}"
    return out


def env_credentials():
    """(key id, secret, session token) from the environment, or None. Never logged."""
    a, s = os.environ.get("AWS_ACCESS_KEY_ID"), os.environ.get("AWS_SECRET_ACCESS_KEY")
    if not a or not s:
        return None
    return a, s, os.environ.get("AWS_SESSION_TOKEN") or None


class S3HeadHttp:
    """HeadObject over HTTPS for one bucket, signed here. Thread-safe: one connection per thread.

    Errors are AwsError("s3:HeadObject", "<HTTP status>"), like the CLI's "(403)" / "(404)";
    no response text is ever kept (HEAD has no body anyway). 5xx, 429 and connection errors
    are retried (the CLI's standard retry mode does the same)."""

    def __init__(self, bucket, region, creds, endpoint=None, timeout=60, clock=None):
        if not _BUCKET_RE.fullmatch(bucket or "") or not _REGION_RE.fullmatch(region or ""):
            raise AwsError("s3:HeadObject", "bucket or region unfit for the HTTP path")
        self.bucket = bucket
        self.region = region
        self.creds = creds
        self.timeout = timeout
        self.clock = clock or (lambda: dt.datetime.now(dt.timezone.utc))
        # endpoint override is for tests only: (host, port) of a loopback plain-HTTP server.
        self.host = f"{bucket}.s3.{region}.amazonaws.com"
        self.endpoint = endpoint
        self._local = threading.local()
        self._all = []
        self._lock = threading.Lock()

    def close(self):
        with self._lock:
            conns, self._all = self._all, []
        for c in conns:
            c.close()

    def _conn(self, fresh=False):
        c = getattr(self._local, "conn", None)
        if c is not None and not fresh:
            return c
        if c is not None:
            c.close()
        if self.endpoint:
            host, port = self.endpoint
            if host not in ("127.0.0.1", "localhost"):
                raise AwsError("s3:HeadObject", "test endpoint must be loopback")
            c = http.client.HTTPConnection(host, port, timeout=self.timeout)
        else:
            c = http.client.HTTPSConnection(self.host, 443, timeout=self.timeout,
                                            context=ssl.create_default_context())
        self._local.conn = c
        with self._lock:
            self._all.append(c)
        return c

    def head(self, key):
        path = "/" + _uri_encode(key, slash_ok=True)
        status = None
        for attempt in range(HEAD_ATTEMPTS):
            if attempt:
                time.sleep(min(HEAD_BACKOFF * 2 ** attempt, 3))
            amz_date = self.clock().strftime("%Y%m%dT%H%M%SZ")
            hdrs = sigv4_headers("HEAD", self.host, path, "", self.region, "s3", self.creds, amz_date)
            if self.endpoint:
                hdrs["host"] = self.host  # signed as the real host; the test server checks it
            try:
                c = self._conn(fresh=attempt > 0)
                c.request("HEAD", path, headers=hdrs)
                r = c.getresponse()
                r.read()
                status = r.status
            except (OSError, http.client.HTTPException):
                status = None
                continue
            if status == 200:
                if not r.getheader("ETag"):
                    raise AwsError("s3:HeadObject", "unexpected response")
                return {"etag": strip_etag(r.getheader("ETag")), "content_type": r.getheader("Content-Type"),
                        "cache_control": r.getheader("Cache-Control")}
            if status == 404:
                raise NotFound("s3:HeadObject", "404")
            if status not in (429, 500, 502, 503, 504):
                raise AwsError("s3:HeadObject", str(status))
        raise AwsError("s3:HeadObject", str(status) if status else "connection failed")


def run_parallel(fn, items, workers, label, progress=print, every=1000, min_interval=30.0):
    """fn over items in a thread pool; returns {item: result}. The first exception cancels what
    hasn't started and is re-raised. Progress lines (counts only, never names) go to progress."""
    items = list(items)
    out = {}
    if not items:
        return out
    t0 = last = time.monotonic()
    ex = ThreadPoolExecutor(max_workers=max(1, min(workers, len(items))))
    try:
        futs = {ex.submit(fn, it): it for it in items}
        from concurrent.futures import as_completed
        for n, f in enumerate(as_completed(futs), 1):
            out[futs[f]] = f.result()
            now = time.monotonic()
            if progress and (n % every == 0 or now - last >= min_interval or n == len(items)):
                el = now - t0
                eta = el / n * (len(items) - n)
                progress(f"site plan: {label} {n}/{len(items)} ({el:.0f} s, about {eta:.0f} s left)")
                last = now
    except BaseException:
        ex.shutdown(wait=True, cancel_futures=True)
        raise
    ex.shutdown(wait=True)
    return out


class AwsError(RuntimeError):
    def __init__(self, op, code):
        super().__init__(f"{op}: {code}")
        self.op = op
        self.code = code


class NotFound(AwsError):
    pass


def strip_etag(e):
    return str(e or "").strip('"')


def _need(doc, op, *keys):
    """A response must be an object with these keys; anything else is an error, never a crash."""
    if not isinstance(doc, dict) or any(k not in doc for k in keys):
        raise AwsError(op, "unexpected response")
    return doc


class CliAws:
    def __init__(self, region, profile=None, aws_bin="aws", timeout=600, s3_http=None):
        self.region = region
        self.profile = profile
        self.aws_bin = aws_bin
        self.timeout = timeout
        # Bulk HEAD over HTTP: None = automatic (the runner: default `aws`, no profile, the
        # role's credentials in the environment), False = always the CLI, or a factory
        # (bucket) -> object with head(key), for tests.
        self.s3_http = s3_http

    # -- plumbing ----------------------------------------------------------------------------
    def _run(self, op, args, region=None, query=None, raw=False):
        cmd = [self.aws_bin, *args, "--region", region or self.region, "--output", "json"]
        if self.profile:
            cmd += ["--profile", self.profile]
        if query:
            cmd += ["--query", query]
        env = dict(os.environ, AWS_PAGER="", AWS_CLI_AUTO_PROMPT="off")
        try:
            r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, timeout=self.timeout,
                               env=env, check=False)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise AwsError(op, e.__class__.__name__) from None
        if r.returncode != 0:
            m = _CODE_RE.search(r.stderr.decode("utf-8", "replace"))
            code = m.group(1) if m else f"exit {r.returncode}"
            if code in ("NoSuchKey", "404", "NotFound", "ResourceNotFoundException", "NoSuchFunctionExists"):
                raise NotFound(op, code)
            raise AwsError(op, code)
        if raw:
            return r.stdout
        out = r.stdout.decode("utf-8", "replace").strip()
        if not out:
            return None
        try:
            return json.loads(out)
        except ValueError:
            raise AwsError(op, "unparseable response") from None

    # -- S3 ----------------------------------------------------------------------------------
    def list_objects(self, bucket):
        doc = self._run("s3:ListObjectsV2", ["s3api", "list-objects-v2", f"--bucket={bucket}"],
                        query="Contents[].{k:Key,e:ETag,s:Size,m:LastModified}") or []
        if not isinstance(doc, list):
            raise AwsError("s3:ListObjectsV2", "unexpected response")
        out = {}
        for o in doc:
            _need(o, "s3:ListObjectsV2", "k", "e", "s")
            out[o["k"]] = {"etag": strip_etag(o["e"]), "size": int(o["s"]), "last_modified": str(o.get("m") or "")}
        return out

    def get_object(self, bucket, key, dest):
        """Download to dest; returns the ETag. Raises NotFound if the key doesn't exist."""
        return self.get_object_meta(bucket, key, dest)["etag"]

    def get_object_meta(self, bucket, key, dest):
        """Download to dest; returns {etag, content_type, cache_control}."""
        doc = _need(self._run("s3:GetObject", ["s3api", "get-object", f"--bucket={bucket}", f"--key={key}", dest],
                              query="{e:ETag,t:ContentType,c:CacheControl}"), "s3:GetObject", "e")
        return {"etag": strip_etag(doc["e"]), "content_type": doc.get("t"), "cache_control": doc.get("c")}

    def head_object(self, bucket, key):
        """{etag, content_type, cache_control} without the body (needs s3:GetObject)."""
        doc = _need(self._run("s3:HeadObject", ["s3api", "head-object", f"--bucket={bucket}", f"--key={key}"],
                              query="{e:ETag,t:ContentType,c:CacheControl}"), "s3:HeadObject", "e")
        return {"etag": strip_etag(doc["e"]), "content_type": doc.get("t"), "cache_control": doc.get("c")}

    def _http_head_client(self, bucket):
        if self.s3_http is False:
            return None
        if callable(self.s3_http):
            return self.s3_http(bucket)
        creds = env_credentials()
        if self.profile or self.aws_bin != "aws" or creds is None:
            return None
        if not _BUCKET_RE.fullmatch(bucket) or not _REGION_RE.fullmatch(self.region):
            return None
        return S3HeadHttp(bucket, self.region, creds)

    def head_objects(self, bucket, keys, progress=print):
        """{key: head_object(bucket, key)} for many keys, in parallel; same fields and errors
        as head_object. Uses the HTTP path when it can (see S3HeadHttp), else the CLI."""
        client = self._http_head_client(bucket)
        if client is not None:
            try:
                return run_parallel(client.head, keys, HEAD_WORKERS_HTTP, "HEAD (https)", progress)
            finally:
                if hasattr(client, "close"):
                    client.close()
        return run_parallel(lambda k: self.head_object(bucket, k), keys, HEAD_WORKERS_CLI, "HEAD (aws cli)", progress)

    def put_object(self, bucket, key, path, content_type, cache_control, sha256_b64,
                   if_match=None, if_none_match=False):
        if bool(if_match) == bool(if_none_match):
            raise AwsError("s3:PutObject", "exactly one of If-Match / If-None-Match is required")
        args = ["s3api", "put-object", f"--bucket={bucket}", f"--key={key}", f"--body={path}",
                f"--content-type={content_type}", f"--cache-control={cache_control}",
                "--checksum-algorithm=SHA256", f"--checksum-sha256={sha256_b64}"]
        args.append(f"--if-match={if_match}" if if_match else "--if-none-match=*")
        doc = self._run("s3:PutObject", args, query="{e:ETag,c:ChecksumSHA256}")
        if not isinstance(doc, dict) or not doc.get("e") or doc.get("c") != sha256_b64:
            raise AwsError("s3:PutObject", "checksum not confirmed")
        return strip_etag(doc["e"])

    def delete_object(self, bucket, key, if_match):
        self._run("s3:DeleteObject", ["s3api", "delete-object", f"--bucket={bucket}", f"--key={key}",
                                      f"--if-match={if_match}"], query="DeleteMarker")

    # -- Lambda ------------------------------------------------------------------------------
    def lambda_get_function(self, name):
        doc = self._run("lambda:GetFunction", ["lambda", "get-function", f"--function-name={name}"],
                        query="{l:Code.Location,t:Code.RepositoryType,c:Configuration.CodeSha256,"
                              "r:Configuration.RevisionId}")
        _need(doc, "lambda:GetFunction", "l", "c", "r")
        return {"location": doc["l"], "repository_type": doc["t"], "code_sha256": doc["c"],
                "revision_id": doc["r"]}

    def lambda_get_configuration(self, name):
        # Only names of environment variables, never values. Under the plan role's kms:Decrypt
        # deny, Lambda returns Environment = {"Error": {"ErrorCode": "AccessDeniedException", ...}}
        # and no Variables: env_error carries that code so the caller can tell "unreadable" from
        # "no variables" (Guardian on fff80e5, M1).
        doc = self._run("lambda:GetFunctionConfiguration",
                        ["lambda", "get-function-configuration", f"--function-name={name}"],
                        query="{runtime:Runtime,handler:Handler,memory_size:MemorySize,timeout:Timeout,"
                              "architectures:Architectures,env_names:keys(Environment.Variables || `{}`),"
                              "env_error:Environment.Error.ErrorCode,"
                              "layers:Layers[].Arn,vpc_id:VpcConfig.VpcId,kms_key_arn:KMSKeyArn,"
                              "package_type:PackageType,revision_id:RevisionId,code_sha256:CodeSha256,"
                              "state:State,last_update_status:LastUpdateStatus}")
        return _need(doc, "lambda:GetFunctionConfiguration")

    def lambda_update_code(self, name, zip_path, revision_id):
        doc = self._run("lambda:UpdateFunctionCode",
                        ["lambda", "update-function-code", f"--function-name={name}",
                         f"--zip-file=fileb://{zip_path}", f"--revision-id={revision_id}"],
                        query="{c:CodeSha256,r:RevisionId}")
        _need(doc, "lambda:UpdateFunctionCode", "c", "r")
        return {"code_sha256": doc["c"], "revision_id": doc["r"]}

    def download(self, url, dest, max_bytes=MAX_LAMBDA_ZIP):
        """Fetch the presigned Lambda code URL (no credentials sent)."""
        u = urllib.parse.urlsplit(url)
        if u.scheme != "https" or not (u.hostname or "").endswith(".amazonaws.com"):
            raise AwsError("lambda:code download", "unexpected code location")
        n = 0
        try:
            with urllib.request.urlopen(url, timeout=120) as r, open(dest, "wb") as f:
                while True:
                    chunk = r.read(1 << 20)
                    if not chunk:
                        break
                    n += len(chunk)
                    if n > max_bytes:
                        raise AwsError("lambda:code download", "too large")
                    f.write(chunk)
        except (urllib.error.URLError, OSError) as e:
            raise AwsError("lambda:code download", e.__class__.__name__) from None
        return dest

    # -- CloudFront Functions ------------------------------------------------------------------
    def cf_describe_function(self, name, stage):
        doc = self._run("cloudfront:DescribeFunction",
                        ["cloudfront", "describe-function", f"--name={name}", f"--stage={stage}"],
                        region="us-east-1",
                        query="{e:ETag,s:FunctionSummary.Status,c:FunctionSummary.FunctionConfig}")
        _need(doc, "cloudfront:DescribeFunction", "e")
        cfg = doc.get("c") or {}
        kvs = (cfg.get("KeyValueStoreAssociations") or {}).get("Items") or []
        return {"etag": doc["e"], "status": doc.get("s"),
                "config": {"Comment": cfg.get("Comment", ""), "Runtime": cfg.get("Runtime"),
                           "KeyValueStoreAssociations": sorted(i.get("KeyValueStoreARN") for i in kvs)}}

    def cf_get_function(self, name, stage):
        with tempfile.TemporaryDirectory(prefix="cf-") as d:
            out = os.path.join(d, "code")
            doc = self._run("cloudfront:GetFunction",
                            ["cloudfront", "get-function", f"--name={name}", f"--stage={stage}", out],
                            region="us-east-1", query="{e:ETag}")
            _need(doc, "cloudfront:GetFunction", "e")
            with open(out, "rb") as f:
                return f.read(), doc["e"]

    @staticmethod
    def _cfg_json(config):
        kvs = config.get("KeyValueStoreAssociations") or []
        cfg = {"Comment": config.get("Comment", ""), "Runtime": config["Runtime"]}
        if kvs:
            cfg["KeyValueStoreAssociations"] = {"Quantity": len(kvs),
                                                "Items": [{"KeyValueStoreARN": a} for a in kvs]}
        return json.dumps(cfg)

    def cf_update_function(self, name, if_match, config, code):
        with tempfile.TemporaryDirectory(prefix="cf-") as d:
            cp, gp = os.path.join(d, "code.js"), os.path.join(d, "config.json")
            with open(cp, "wb") as f:
                f.write(code)
            with open(gp, "w", encoding="utf-8") as f:
                f.write(self._cfg_json(config))
            doc = self._run("cloudfront:UpdateFunction",
                            ["cloudfront", "update-function", f"--name={name}", f"--if-match={if_match}",
                             f"--function-config=file://{gp}", f"--function-code=fileb://{cp}"],
                            region="us-east-1", query="{e:ETag}")
        return _need(doc, "cloudfront:UpdateFunction", "e")["e"]

    def cf_test_function(self, name, if_match, event):
        """Returns {'output': str|None, 'error': bool}. Logs, utilisation and error text are
        dropped here and never returned."""
        with tempfile.TemporaryDirectory(prefix="cf-") as d:
            ep = os.path.join(d, "event.json")
            with open(ep, "wb") as f:
                f.write(event)
            doc = self._run("cloudfront:TestFunction",
                            ["cloudfront", "test-function", f"--name={name}", f"--if-match={if_match}",
                             "--stage=DEVELOPMENT", f"--event-object=fileb://{ep}"],
                            region="us-east-1",
                            query="{o:TestResult.FunctionOutput,f:TestResult.FunctionErrorMessage}")
        _need(doc, "cloudfront:TestFunction")
        return {"output": doc.get("o"), "error": bool(doc.get("f"))}

    def cf_publish_function(self, name, if_match):
        doc = self._run("cloudfront:PublishFunction",
                        ["cloudfront", "publish-function", f"--name={name}", f"--if-match={if_match}"],
                        region="us-east-1", query="{s:FunctionSummary.Status}")
        return _need(doc, "cloudfront:PublishFunction").get("s")

    def cf_create_invalidation(self, distribution_id, paths, caller_reference):
        with tempfile.TemporaryDirectory(prefix="cf-") as d:
            bp = os.path.join(d, "batch.json")
            with open(bp, "w", encoding="utf-8") as f:
                json.dump({"Paths": {"Quantity": len(paths), "Items": paths},
                           "CallerReference": caller_reference}, f)
            doc = self._run("cloudfront:CreateInvalidation",
                            ["cloudfront", "create-invalidation", f"--distribution-id={distribution_id}",
                             f"--invalidation-batch=file://{bp}"], region="us-east-1",
                            query="{i:Invalidation.Id}")
        return _need(doc, "cloudfront:CreateInvalidation", "i")["i"]

    def cf_get_invalidation(self, distribution_id, inv_id):
        doc = self._run("cloudfront:GetInvalidation",
                        ["cloudfront", "get-invalidation", f"--distribution-id={distribution_id}", f"--id={inv_id}"],
                        region="us-east-1", query="{s:Invalidation.Status}")
        return _need(doc, "cloudfront:GetInvalidation", "s")["s"]
