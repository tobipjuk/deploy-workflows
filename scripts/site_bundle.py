#!/usr/bin/env python3
"""The site plan bundle (plan-bundle.tar), written by site_plan.py, read by site_apply.py.

Layout (uncompressed tar, fixed mtimes, mode 0644):
  SOURCE            the commit the plan was made from
  plan.json         operations, pre-state, desired manifest (see site_plan.py)
  lambda.zip        only if the Lambda changes: the zip built by trusted code
  gate.js           only if the gate changes
  blobs/<sha256>    plain-git bytes of every object to upload (LFS objects travel as oids)
  SHA256SUMS        sha256 of every other member

Content-addressed: no name in the bundle comes from the project repo. verify() refuses any
other member, links, duplicates, a wrong sum, a blob whose name isn't its sha256, and a
SOURCE other than the commit being deployed. Stdlib only.
"""
import hashlib
import io
import json
import re
import tarfile

MAX_MEMBER = 256 * 1024 * 1024
MAX_TOTAL = 480 * 1024 * 1024  # GitHub artifact quota is 500 MB


class BundleError(ValueError):
    pass


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _add(tar, name, data):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o644
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    tar.addfile(info, io.BytesIO(data))


def canonical_json(obj):
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def create(out_path, source, plan, blobs, lambda_zip=None, gate_js=None):
    """blobs: {sha256 hex: bytes}. Returns the tar's sha256."""
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise BundleError("source must be a 40-hex commit")
    members = {"SOURCE": (source + "\n").encode(), "plan.json": canonical_json(plan)}
    if lambda_zip is not None:
        members["lambda.zip"] = lambda_zip
    if gate_js is not None:
        members["gate.js"] = gate_js
    for h, data in blobs.items():
        if _sha(data) != h:
            raise BundleError("blob does not match its name")
        members["blobs/" + h] = data
    total = sum(len(v) for v in members.values())
    if total > MAX_TOTAL:
        raise BundleError(f"plan bundle would be {total} bytes, over the artifact limit")
    sums = "".join(f"{_sha(members[n])}  {n}\n" for n in sorted(members)).encode()
    with tarfile.open(out_path, "w", format=tarfile.PAX_FORMAT) as tar:
        for n in sorted(members):
            _add(tar, n, members[n])
        _add(tar, "SHA256SUMS", sums)
    h = hashlib.sha256()
    with open(out_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def verify(tar_path, expected_sha256, source):
    """Return {'plan': dict, 'plan_bytes': bytes, 'lambda_zip': bytes|None, 'gate_js': bytes|None,
    'blobs': {sha: bytes}}; raises BundleError."""
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or ""):
        raise BundleError("expected sha256 must be 64 lowercase hex")
    h = hashlib.sha256()
    with open(tar_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    if h.hexdigest() != expected_sha256:
        raise BundleError("bundle sha256 is not the approved one")
    data, total = {}, 0
    with tarfile.open(tar_path, "r:") as tar:
        for m in tar.getmembers():
            name = m.name
            if not m.isreg():
                raise BundleError(f"bundle member is not a regular file: {name!r}")
            if not (name in ("SOURCE", "plan.json", "lambda.zip", "gate.js", "SHA256SUMS")
                    or re.fullmatch(r"blobs/[0-9a-f]{64}", name)):
                raise BundleError(f"unexpected bundle member {name!r}")
            if name in data:
                raise BundleError(f"duplicate bundle member {name!r}")
            if m.size > MAX_MEMBER:
                raise BundleError(f"bundle member too large: {name!r}")
            total += m.size
            if total > MAX_TOTAL:
                raise BundleError("bundle too large")
            data[name] = tar.extractfile(m).read()
    for req in ("SOURCE", "plan.json", "SHA256SUMS"):
        if req not in data:
            raise BundleError(f"bundle has no {req}")
    listed = {}
    for line in data["SHA256SUMS"].decode("ascii", "replace").splitlines():
        mt = re.fullmatch(r"([0-9a-f]{64})  (\S+)", line)
        if not mt or mt.group(2) in listed:
            raise BundleError("malformed SHA256SUMS")
        listed[mt.group(2)] = mt.group(1)
    if set(listed) != set(data) - {"SHA256SUMS"}:
        raise BundleError("SHA256SUMS does not list exactly the bundle members")
    for n, s in listed.items():
        if _sha(data[n]) != s:
            raise BundleError(f"sha256 mismatch for {n}")
    blobs = {}
    for n, b in data.items():
        if n.startswith("blobs/"):
            if _sha(b) != n[6:]:
                raise BundleError("blob does not match its name")
            blobs[n[6:]] = b
    if data["SOURCE"].decode("ascii", "replace").strip() != source:
        raise BundleError("the plan was made from another commit")
    try:
        plan = json.loads(data["plan.json"])
    except ValueError:
        raise BundleError("plan.json is not JSON") from None
    if canonical_json(plan) != data["plan.json"]:
        raise BundleError("plan.json is not canonical")
    return {"plan": plan, "plan_bytes": data["plan.json"], "lambda_zip": data.get("lambda.zip"),
            "gate_js": data.get("gate.js"), "blobs": blobs}
