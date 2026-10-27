#!/usr/bin/env python3
"""Trusted rules for the site pipeline (site-plan.yml / site-apply.yml). Stdlib only.

Two inputs are validated here:

  policy/site/<owner>/<repo>.json   TRUSTED, in deploy-workflows (a PR by Tobi). Chosen by the
                                    run's github.repository, never by an input. Account, region,
                                    bucket, the keys and prefixes the site may use (SITE), the
                                    manifest location, the Lambda and its member allowlist, the
                                    gate (CloudFront Function) and its test cases, the
                                    distribution, the smoke checks.
  deploy/site.json                  UNTRUSTED, in the project repo (the box can write it). A
                                    bounded mapping from repo paths to keys inside SITE, a cache
                                    class per mapping, and the Lambda settings the project
                                    expects live (a mismatch makes the plan not deployable; the
                                    pipeline never changes settings).

Everything the pipeline decides about a file (text or binary, code or data, content type,
magic bytes, whether a browser runs it) comes from the fixed tables below, never from either
file. See docs/site-pipeline.md.

  site_policy.py check-policy FILE [--repository OWNER/REPO]
  site_policy.py check-site-json FILE --policy FILE
"""
import argparse
import fnmatch
import hashlib
import json
import re
import sys

POLICY_SCHEMA = 1
SITE_SCHEMA = 1
MAX_OBJECTS_CEILING = 20000
MAX_MAPPINGS = 200
MAX_KEY_LEN = 512
MAX_LAMBDA_MEMBER_BYTES = 256 * 1024
MAX_GATE_BYTES = 10 * 1024  # CloudFront Functions code limit

# --- file classes -------------------------------------------------------------------------
# "code": served as something a browser interprets; every change is shown in full on the card,
#         a truncated code diff makes the plan not deployable.
# "data": text served as text/plain; full diffs, may be truncated.
# "binary": compared by sha256 / ETag, checked by magic bytes.
# Text classes must come from plain git (an LFS pointer there refuses the plan, round 4 H2) and
# must have a lowercase extension (the plan role's GetObject ARN patterns are case-sensitive).
CODE_TYPES = {
    "html": "text/html; charset=utf-8",
    "htm": "text/html; charset=utf-8",
    "js": "text/javascript; charset=utf-8",
    "mjs": "text/javascript; charset=utf-8",
    "css": "text/css; charset=utf-8",
    "svg": "image/svg+xml",
    "xml": "application/xml",
    "json": "application/json",
    "webmanifest": "application/manifest+json",
}
DATA_TYPES = {ext: "text/plain; charset=utf-8" for ext in ("txt", "ldr", "mpd", "py")}
TEXT_EXTS = frozenset(CODE_TYPES) | frozenset(DATA_TYPES)
# Types a browser runs or renders as active content: only from policy browser_code_sources.
BROWSER_RUN_EXTS = frozenset({"html", "htm", "js", "mjs", "css", "svg", "xml"})

_ZIP = (b"PK\x03\x04", b"PK\x05\x06")
_MOV_ATOMS = (b"ftyp", b"moov", b"wide", b"free", b"mdat", b"skip", b"pnot")
# ext -> (content type, [(offset, magic bytes), ...]); any one entry matching is enough.
BINARY_TYPES = {
    "webp": ("image/webp", None),  # special-cased: RIFF....WEBP
    "png": ("image/png", [(0, b"\x89PNG\r\n\x1a\n")]),
    "jpg": ("image/jpeg", [(0, b"\xff\xd8\xff")]),
    "jpeg": ("image/jpeg", [(0, b"\xff\xd8\xff")]),
    "gif": ("image/gif", [(0, b"GIF87a"), (0, b"GIF89a")]),
    "ico": ("image/x-icon", [(0, b"\x00\x00\x01\x00")]),
    "pdf": ("application/pdf", [(0, b"%PDF-")]),
    "woff2": ("font/woff2", [(0, b"wOF2")]),
    "woff": ("font/woff", [(0, b"wOFF")]),
    "ttf": ("font/ttf", [(0, b"\x00\x01\x00\x00"), (0, b"true")]),
    "otf": ("font/otf", [(0, b"OTTO")]),
    "mp4": ("video/mp4", [(4, b"ftyp")]),
    "mov": ("video/quicktime", [(4, a) for a in _MOV_ATOMS]),
    "mp3": ("audio/mpeg", [(0, b"ID3"), (0, b"\xff\xfb"), (0, b"\xff\xf3"), (0, b"\xff\xf2"),
                           (0, b"\xff\xfa")]),
    "zip": ("application/zip", [(0, m) for m in _ZIP]),
    "rar": ("application/vnd.rar", [(0, b"Rar!\x1a\x07")]),
    # Designers' files: downloads, never rendered.
    "lxf": ("application/octet-stream", [(0, m) for m in _ZIP]),
    "ev3": ("application/octet-stream", [(0, m) for m in _ZIP]),
    "lmsp": ("application/octet-stream", [(0, m) for m in _ZIP]),
    "sb3": ("application/octet-stream", [(0, m) for m in _ZIP]),
    "io": ("application/octet-stream", [(0, m) for m in _ZIP]),
    "lxfml": ("application/octet-stream", [(0, b"<?xml"), (0, b"\xef\xbb\xbf<?xml"), (0, b"<LXFML")]),
}
MAGIC_BYTES_NEEDED = 16

# S3 Cache-Control classes (round 3 M2: "cache settings" = this header only, from a fixed set).
CACHE_CLASSES = {
    "no-cache": "no-cache",
    "short": "public, max-age=300",
    "long": "public, max-age=2592000",
    "immutable": "public, max-age=31536000, immutable",
    "private-short": "private, max-age=300",
    "private-day": "private, max-age=86400",
    "private-immutable": "private, max-age=31536000, immutable",
}

# Names a Lambda member may not take: the runtime puts the function's directory first on
# sys.path, so json.py or boto3/ would replace the real module for every import (round 4 L2).
RUNTIME_MODULES = frozenset({
    "boto3", "botocore", "s3transfer", "urllib3", "dateutil", "jmespath", "six",
    "awslambdaric", "bootstrap", "runtime", "lambda_runtime_client", "lambda_runtime_marshaller",
    "lambda_runtime_exception", "lambda_runtime_log_utils", "sitecustomize", "usercustomize",
    "typing_extensions", "simplejson", "requests", "certifi", "idna", "charset_normalizer",
    "pip", "setuptools", "pkg_resources", "_distutils_hack", "__init__", "__main__",
})


class PolicyError(ValueError):
    pass


def ext_of(name):
    base = name.rsplit("/", 1)[-1]
    if "." not in base.strip("."):
        return ""
    return base.rsplit(".", 1)[-1]


def classify(key, source):
    """Return (class, content_type) for a destination key and its source path.

    Both extensions must agree (case-insensitively) so a file can't change type on its way
    (round 4 L1: x.html uploaded as x.png). Unknown extensions are refused.
    """
    ek, es = ext_of(key), ext_of(source)
    if not ek or ek.lower() != es.lower():
        raise PolicyError(f"key {key!r} and source {source!r} must have the same known extension")
    low = ek.lower()
    if low in TEXT_EXTS:
        if ek != low or es != low:
            raise PolicyError(f"text file extension must be lowercase: {source!r}")
        if low in CODE_TYPES:
            return "code", CODE_TYPES[low]
        return "data", DATA_TYPES[low]
    if low in BINARY_TYPES:
        return "binary", BINARY_TYPES[low][0]
    raise PolicyError(f"extension .{ek} is not in the site pipeline's type table: {source!r}")


def magic_ok(ext, head):
    ext = ext.lower()
    if ext == "webp":
        return len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    entries = BINARY_TYPES.get(ext, ("", []))[1] or []
    return any(head[off:off + len(m)] == m for off, m in entries)


def module_name_shadows(name):
    """True if a Lambda member's top-level module name shadows the stdlib or the runtime."""
    top = name.split("/", 1)[0]
    if top.endswith(".py"):
        top = top[:-3]
    stdlib = getattr(sys, "stdlib_module_names", frozenset())
    return top in stdlib or top in RUNTIME_MODULES or top.lower() in RUNTIME_MODULES \
        or top.startswith("_")


# --- key and path rules ---------------------------------------------------------------------
# ASCII only (no homoglyphs or bidi in keys), no characters with meaning in URLs or
# invalidation paths (% ? # * \ "), no empty / . / .. segments.
_SEG = r"[A-Za-z0-9 ._~@+(),'&!=-]+"
KEY_RE = re.compile(rf"{_SEG}(/{_SEG})*")
PREFIX_RE = re.compile(rf"({_SEG}/)+")
REPO_PATH_RE = KEY_RE


def check_key(key, what="key"):
    if not isinstance(key, str) or not key or len(key) > MAX_KEY_LEN or not KEY_RE.fullmatch(key):
        raise PolicyError(f"{what} {key!r} has characters or a shape the site pipeline refuses")
    for seg in key.split("/"):
        if seg in (".", "..") or seg != seg.strip() or seg.strip(".") == "":
            raise PolicyError(f"{what} {key!r} has an empty, dot or space-padded segment")
    return key


def check_repo_path(path, what="path"):
    check_key(path, what)
    if path.split("/", 1)[0] in (".git", ".github"):
        raise PolicyError(f"{what} {path!r} is inside .git or .github")
    return path


def _expect(cond, msg):
    if not cond:
        raise PolicyError(msg)


def _exact_fields(obj, required, optional=(), where="policy"):
    _expect(isinstance(obj, dict), f"{where} must be an object")
    keys = set(obj)
    missing = set(required) - keys
    extra = keys - set(required) - set(optional)
    _expect(not missing, f"{where}: missing {sorted(missing)}")
    _expect(not extra, f"{where}: unknown fields {sorted(extra)}")


def _str(v, pattern, what):
    _expect(isinstance(v, str) and re.fullmatch(pattern, v) is not None, f"{what} is invalid: {v!r}")
    return v


def _int(v, lo, hi, what):
    _expect(isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi, f"{what} must be an int in [{lo}, {hi}]")
    return v


BUCKET_RE = r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]"
FUNCTION_RE = r"[A-Za-z0-9_-]{1,64}"
GATE_TEST_NAME_RE = r"[A-Za-z0-9 ,.:()/_-]{1,80}"
HEADER_NAME_RE = r"[a-z0-9-]{1,64}"
HEADER_VALUE_RE = r"[\x20-\x7e]{0,512}"


def validate_policy(doc, repository=None):
    """Validate a trusted site policy; returns the normalised dict (raises PolicyError)."""
    _exact_fields(doc, ["schema", "kind", "repository", "target", "account_id", "region", "bucket",
                        "root_keys", "prefixes", "browser_code_sources", "manifest", "lambda", "gate",
                        "distribution_id", "smoke"], ["max_objects", "max_deletes"])
    _expect(doc["schema"] == POLICY_SCHEMA, "policy schema must be 1")
    _expect(doc["kind"] == "site", "policy kind must be 'site'")
    _str(doc["repository"], r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", "repository")
    if repository is not None:
        _expect(doc["repository"] == repository, "policy file is for another repository")
    _str(doc["target"], r"[a-z0-9][a-z0-9-]{0,62}", "target")
    _str(doc["account_id"], r"[0-9]{12}", "account_id")
    _str(doc["region"], r"[a-z]{2}(-[a-z]+)+-[0-9]", "region")
    _str(doc["bucket"], BUCKET_RE, "bucket")
    _str(doc["distribution_id"], r"E[A-Z0-9]{5,20}", "distribution_id")
    max_objects = doc.get("max_objects", MAX_OBJECTS_CEILING)
    _int(max_objects, 1, MAX_OBJECTS_CEILING, "max_objects")
    _int(doc.get("max_deletes", 20), 0, 1000, "max_deletes")

    roots, prefixes = doc["root_keys"], doc["prefixes"]
    _expect(isinstance(roots, list) and isinstance(prefixes, list) and (roots or prefixes),
            "root_keys/prefixes must be lists, not both empty")
    for k in roots:
        check_key(k, "root key")
        _expect("/" not in k, f"root key {k!r} contains '/'")
    for p in prefixes:
        _expect(isinstance(p, str) and PREFIX_RE.fullmatch(p) is not None, f"prefix {p!r} is invalid")
        check_key(p[:-1], "prefix")
    _expect(len(set(roots)) == len(roots) and len(set(prefixes)) == len(prefixes), "duplicate keys/prefixes")
    for a in prefixes:
        for b in prefixes:
            _expect(a == b or not a.startswith(b), f"prefixes overlap: {a!r} / {b!r}")
        for r in roots:
            _expect(not r.startswith(a), f"root key {r!r} lies under prefix {a!r}")

    srcs = doc["browser_code_sources"]
    _expect(isinstance(srcs, list) and srcs, "browser_code_sources must be a non-empty list")
    for s in srcs:
        _expect(isinstance(s, str) and s.endswith("/"), f"browser_code_sources entry {s!r} must end in /")
        check_repo_path(s[:-1], "browser_code_sources entry")

    m = doc["manifest"]
    _exact_fields(m, ["bucket", "key"], where="manifest")
    _str(m["bucket"], BUCKET_RE, "manifest.bucket")
    check_key(m["key"], "manifest.key")
    _expect(m["bucket"] != doc["bucket"], "the manifest must live outside the site bucket")

    lam = doc["lambda"]
    _exact_fields(lam, ["function_name", "source_dir", "members"], ["ignore"], where="lambda")
    _str(lam["function_name"], FUNCTION_RE, "lambda.function_name")
    check_repo_path(lam["source_dir"], "lambda.source_dir")
    members = lam["members"]
    _expect(isinstance(members, list) and members and len(members) <= 50, "lambda.members must be 1..50 names")
    for name in members:
        _str(name, r"[a-z_][a-z0-9_]{0,63}\.py", "lambda member")
        _expect(not module_name_shadows(name), f"lambda member {name!r} shadows a standard library or runtime module")
    _expect(len(set(members)) == len(members), "duplicate lambda members")
    ignore = lam.get("ignore", [])
    _expect(isinstance(ignore, list) and all(isinstance(g, str) and re.fullmatch(r"[A-Za-z0-9_.*?-]{1,64}", g)
                                             for g in ignore), "lambda.ignore must be simple globs")
    for name in members:
        _expect(not any(fnmatch.fnmatchcase(name, g) for g in ignore), f"lambda member {name!r} matches an ignore glob")

    gate = doc["gate"]
    _exact_fields(gate, ["function_name", "source", "tests"], where="gate")
    _str(gate["function_name"], FUNCTION_RE, "gate.function_name")
    check_repo_path(gate["source"], "gate.source")
    _expect(gate["source"].endswith(".js"), "gate.source must be a .js file")
    tests = gate["tests"]
    _expect(isinstance(tests, list) and 1 <= len(tests) <= 20, "gate.tests must have 1..20 cases")
    names = set()
    for t in tests:
        _exact_fields(t, ["name", "uri", "expect"], ["method", "headers", "cookies"], where="gate test")
        _str(t["name"], GATE_TEST_NAME_RE, "gate test name")
        _expect(t["name"] not in names, f"duplicate gate test name {t['name']!r}")
        names.add(t["name"])
        _str(t["uri"], r"/[\x21-\x7e]{0,255}", "gate test uri")
        _str(t.get("method", "GET"), r"GET|HEAD|POST|PUT|DELETE|OPTIONS", "gate test method")
        for field in ("headers", "cookies"):
            v = t.get(field, {})
            _expect(isinstance(v, dict) and len(v) <= 20, f"gate test {field} must be an object")
            for hk, hv in v.items():
                _str(hk, HEADER_NAME_RE if field == "headers" else r"[A-Za-z0-9_-]{1,64}", f"gate test {field} name")
                _str(hv, HEADER_VALUE_RE, f"gate test {field} value")
        e = t["expect"]
        _expect(isinstance(e, dict), "gate test expect must be an object")
        if "pass" in e:
            _exact_fields(e, ["pass"], ["uri"], where="gate test expect")
            _expect(e["pass"] is True, "expect.pass must be true")
            if "uri" in e:
                _str(e["uri"], r"/[\x21-\x7e]{0,255}", "expect.uri")
        else:
            _exact_fields(e, ["status"], ["location_prefix"], where="gate test expect")
            _int(e["status"], 200, 599, "expect.status")
            if "location_prefix" in e:
                _str(e["location_prefix"], r"/[\x21-\x7e]{0,255}", "expect.location_prefix")

    smoke = doc["smoke"]
    _exact_fields(smoke, ["base_url", "checks"], where="smoke")
    _str(smoke["base_url"], r"https://[a-z0-9.-]+\.[a-z]{2,}", "smoke.base_url")
    checks = smoke["checks"]
    _expect(isinstance(checks, list) and len(checks) <= 10, "smoke.checks must be a list of up to 10")
    for c in checks:
        _exact_fields(c, ["path", "status"], ["body_sha256_of_key"], where="smoke check")
        _str(c["path"], r"/[A-Za-z0-9._~/-]{0,200}", "smoke check path")
        _int(c["status"], 200, 599, "smoke check status")
        if "body_sha256_of_key" in c:
            check_key(c["body_sha256_of_key"], "smoke check key")
    return doc


def in_site(policy, key):
    """True if key is inside SITE (a root key or under an allowed prefix)."""
    return key in policy["root_keys"] or any(key.startswith(p) for p in policy["prefixes"])


def policy_path(policy_dir, repository):
    _str(repository, r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", "repository")
    owner, name = repository.split("/")
    _expect(owner not in (".", "..") and name not in (".", ".."), "repository is invalid")
    return f"{policy_dir.rstrip('/')}/{owner}/{name}.json"


def load_policy(policy_dir, repository):
    """Load the trusted policy for repository. Returns (policy, sha256 of the file bytes)."""
    path = policy_path(policy_dir, repository)
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        raise PolicyError(f"no site policy for {repository} (policy/site/{repository}.json): "
                          "onboarding is a reviewed PR to deploy-workflows") from None
    try:
        doc = json.loads(raw)
    except ValueError:
        raise PolicyError("site policy is not JSON") from None
    return validate_policy(doc, repository), hashlib.sha256(raw).hexdigest()


# --- deploy/site.json (untrusted) ------------------------------------------------------------

SETTINGS_FIELDS = ("runtime", "handler", "memory_size", "timeout", "architectures", "env_names",
                   "layers", "vpc", "kms_key_arn", "package_type")


def validate_site_json(doc, policy):
    """Validate the project's deploy/site.json against the trusted policy."""
    _exact_fields(doc, ["schema", "mappings", "lambda_settings"], where="deploy/site.json")
    _expect(doc["schema"] == SITE_SCHEMA, "deploy/site.json schema must be 1")
    maps = doc["mappings"]
    _expect(isinstance(maps, list) and 1 <= len(maps) <= MAX_MAPPINGS, f"mappings must have 1..{MAX_MAPPINGS} entries")
    for i, mp in enumerate(maps):
        where = f"deploy/site.json mappings[{i}]"
        _expect(isinstance(mp, dict), f"{where} must be an object")
        if "source" in mp:
            _exact_fields(mp, ["source", "key", "cache"], where=where)
            check_repo_path(mp["source"], f"{where}.source")
            check_key(mp["key"], f"{where}.key")
            _expect(in_site(policy, mp["key"]), f"{where}: key {mp['key']!r} is outside the policy's SITE")
        else:
            _exact_fields(mp, ["source_dir", "prefix", "cache"], ["include", "exclude"], where=where)
            check_repo_path(mp["source_dir"], f"{where}.source_dir")
            pre = mp["prefix"]
            _expect(isinstance(pre, str) and PREFIX_RE.fullmatch(pre) is not None, f"{where}.prefix {pre!r} is invalid")
            check_key(pre[:-1], f"{where}.prefix")
            _expect(any(pre.startswith(p) for p in policy["prefixes"]),
                    f"{where}: prefix {pre!r} is outside the policy's SITE prefixes")
            for g in ("include", "exclude"):
                v = mp.get(g, [])
                _expect(isinstance(v, list) and len(v) <= 50 and all(
                    isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9 ._*?/\[\]-]{1,128}", x) for x in v),
                    f"{where}.{g} must be a list of simple globs")
        _expect(mp["cache"] in CACHE_CLASSES, f"{where}.cache must be one of {sorted(CACHE_CLASSES)}")
    s = doc["lambda_settings"]
    _exact_fields(s, list(SETTINGS_FIELDS), where="deploy/site.json lambda_settings")
    _str(s["runtime"], r"[a-z0-9.]{1,32}", "runtime")
    _str(s["handler"], r"[A-Za-z0-9_]{1,64}\.[A-Za-z0-9_]{1,64}", "handler")
    _int(s["memory_size"], 128, 10240, "memory_size")
    _int(s["timeout"], 1, 900, "timeout")
    _expect(isinstance(s["architectures"], list) and all(a in ("x86_64", "arm64") for a in s["architectures"])
            and len(s["architectures"]) == 1, "architectures must be [x86_64] or [arm64]")
    _expect(isinstance(s["env_names"], list) and all(isinstance(n, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", n)
                                                     for n in s["env_names"]), "env_names must be variable names")
    _expect(isinstance(s["layers"], list) and all(isinstance(x, str) and len(x) < 256 for x in s["layers"]), "layers")
    _expect(isinstance(s["vpc"], bool), "vpc must be a boolean")
    _expect(s["kms_key_arn"] is None or (isinstance(s["kms_key_arn"], str) and len(s["kms_key_arn"]) < 256), "kms_key_arn")
    _expect(s["package_type"] == "Zip", "package_type must be Zip")
    handler_module = s["handler"].split(".")[0] + ".py"
    _expect(handler_module in policy["lambda"]["members"],
            f"handler module {handler_module} is not in the policy's Lambda member allowlist")
    return doc


def expand_mappings(site, policy, tree):
    """Resolve mappings against the commit's file list.

    tree: {repo path: entry} for every blob in the commit. Returns {key: (source, cache class)}.
    Refuses a key produced twice, a mapping that matches nothing, keys outside SITE, sources
    that aren't regular files, and more objects than the policy allows.
    """
    out = {}

    def add(key, src, cache, where):
        check_key(key, f"{where} key")
        _expect(in_site(policy, key), f"{where}: key {key!r} is outside the policy's SITE")
        _expect(key not in out, f"{where}: key {key!r} is produced by two mappings (overlap)")
        out[key] = (src, cache)

    for i, mp in enumerate(site["mappings"]):
        where = f"mappings[{i}]"
        if "source" in mp:
            _expect(mp["source"] in tree, f"{where}: source {mp['source']!r} is not a file in the commit")
            add(mp["key"], mp["source"], mp["cache"], where)
            continue
        d = mp["source_dir"].rstrip("/") + "/"
        inc = mp.get("include") or ["*"]
        exc = mp.get("exclude") or []
        n = 0
        for path in sorted(tree):
            if not path.startswith(d):
                continue
            rel = path[len(d):]
            if not any(fnmatch.fnmatchcase(rel, g) for g in inc) or any(fnmatch.fnmatchcase(rel, g) for g in exc):
                continue
            add(mp["prefix"] + rel, path, mp["cache"], where)
            n += 1
        _expect(n > 0, f"{where}: source_dir {d!r} matches no files")
    limit = policy.get("max_objects", MAX_OBJECTS_CEILING)
    _expect(len(out) <= limit, f"deploy/site.json maps {len(out)} objects; the limit is {limit}")
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("check-policy")
    p.add_argument("file")
    p.add_argument("--repository")
    s = sub.add_parser("check-site-json")
    s.add_argument("file")
    s.add_argument("--policy", required=True)
    args = ap.parse_args(argv)
    try:
        if args.cmd == "check-policy":
            with open(args.file, encoding="utf-8") as f:
                validate_policy(json.load(f), args.repository)
        else:
            with open(args.policy, encoding="utf-8") as f:
                pol = validate_policy(json.load(f))
            with open(args.file, encoding="utf-8") as f:
                validate_site_json(json.load(f), pol)
    except (OSError, ValueError) as e:
        print(f"::error::{e}"[:400], file=sys.stderr)
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
