#!/usr/bin/env python3
"""AWS access for the site pipeline, through the `aws` CLI on the runner. Stdlib only.

site_plan.py and site_apply.py take an object with these methods (tests inject a fake), so
the diff and apply logic never touch AWS directly. This implementation is deliberately
SILENT: it captures every byte the CLI prints, keeps only the fields the caller asked for
(CLI `--query` projections, so e.g. Lambda environment values never leave the CLI process),
and turns failures into AwsError("<operation>: <AWS error code>"), never the AWS message.
That matters for the gate: TestFunction output, function logs and error messages could carry
a key the gate's code chose to put there (round 4 M1, round 5 L4).
"""
import json
import os
import re
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request

MAX_LAMBDA_ZIP = 70 * 1024 * 1024
_CODE_RE = re.compile(r"An error occurred \(([A-Za-z0-9.]{1,64})\)")


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
    def __init__(self, region, profile=None, aws_bin="aws", timeout=600):
        self.region = region
        self.profile = profile
        self.aws_bin = aws_bin
        self.timeout = timeout

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
        # Only names of environment variables, never values.
        doc = self._run("lambda:GetFunctionConfiguration",
                        ["lambda", "get-function-configuration", f"--function-name={name}"],
                        query="{runtime:Runtime,handler:Handler,memory_size:MemorySize,timeout:Timeout,"
                              "architectures:Architectures,env_names:keys(Environment.Variables || `{}`),"
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
