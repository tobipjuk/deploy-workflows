#!/usr/bin/env python3
"""Git LFS for the site pipeline: strict pointer parsing and our own download client.

The site pipeline never runs `git lfs` (that would read the project's .lfsconfig and
.gitattributes): the checkout is `lfs: false`, pointers are read from git objects as data, and
objects come from GitHub's LFS batch API through this module. Every full download is checked
against the pointer's oid (sha256) and size before anyone uses it (round 3 L2). Stdlib only.

Pointer format (git-lfs spec v1), accepted only exactly like this:

  version https://git-lfs.github.com/spec/v1\\n
  oid sha256:<64 lowercase hex>\\n
  size <decimal>\\n
"""
import base64
import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

POINTER_RE = re.compile(rb"version https://git-lfs\.github\.com/spec/v1\noid sha256:([0-9a-f]{64})\nsize (0|[1-9][0-9]{0,11})\n")
MAX_POINTER_BYTES = 200
MAX_OBJECT_BYTES = 200 * 1024 * 1024
BATCH_SIZE = 100
LFS_MEDIA = "application/vnd.git-lfs+json"


class LfsError(ValueError):
    pass


def looks_like_pointer(data):
    """Loose detection: anything that might be meant as an LFS pointer (used to refuse)."""
    head = data[:MAX_POINTER_BYTES * 2]
    return head.startswith(b"version ") and (b"git-lfs" in head or b"hawser" in head) \
        or b"oid sha256:" in head[:400]


def parse_pointer(data):
    """Return (oid, size) for a strict v1 pointer, None if data is not pointer-like at all.

    Raises LfsError for something that looks like a pointer but isn't exactly one: ambiguous
    blobs are refused, never guessed at.
    """
    if not looks_like_pointer(data):
        return None
    if len(data) > MAX_POINTER_BYTES:
        raise LfsError("LFS pointer-like blob is too large")
    m = POINTER_RE.fullmatch(data)
    if not m:
        raise LfsError("malformed LFS pointer (only the strict v1 form with oid and size is accepted)")
    size = int(m.group(2))
    if size > MAX_OBJECT_BYTES:
        raise LfsError("LFS object is larger than the site pipeline allows")
    return m.group(1).decode("ascii"), size


def sha256_file(path):
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise LfsError(f"LFS batch API redirected ({code}); refusing")


class LfsClient:
    """GitHub LFS batch API client (download only)."""

    def __init__(self, repository, token, server="https://github.com", allow_loopback_http=False, timeout=120):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository or ""):
            raise LfsError("bad repository")
        self.repository = repository
        self.token = token or ""
        self.server = server.rstrip("/")
        self.allow_loopback_http = allow_loopback_http
        self.timeout = timeout
        self._check_url(self.server)

    def _check_url(self, url):
        u = urllib.parse.urlsplit(url)
        if u.scheme == "https" and u.hostname:
            return
        if self.allow_loopback_http and u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost"):
            return
        raise LfsError("LFS URLs must be https")

    def _batch_once(self, objects):
        body = json.dumps({"operation": "download", "transfers": ["basic"], "hash_algo": "sha256",
                           "objects": [{"oid": o, "size": s} for o, s in objects]}).encode()
        req = urllib.request.Request(f"{self.server}/{self.repository}.git/info/lfs/objects/batch",
                                     data=body, method="POST")
        req.add_header("Accept", LFS_MEDIA)
        req.add_header("Content-Type", LFS_MEDIA)
        if self.token:
            cred = base64.b64encode(f"x-access-token:{self.token}".encode()).decode()
            req.add_unredirected_header("Authorization", "Basic " + cred)
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(req, timeout=self.timeout) as r:
                doc = json.loads(r.read(16 * 1024 * 1024))
        except urllib.error.HTTPError as e:
            raise LfsError(f"LFS batch API answered HTTP {e.code}") from None
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise LfsError(f"LFS batch API failed: {e.__class__.__name__}") from None
        out = {}
        for o in doc.get("objects") or []:
            oid = o.get("oid")
            act = ((o.get("actions") or {}).get("download")) if isinstance(o, dict) else None
            if isinstance(act, dict) and isinstance(act.get("href"), str):
                out[oid] = act
            else:
                out[oid] = None
        return out

    def batch(self, objects):
        """objects: iterable of (oid, size). Returns {oid: download action or None (missing)}."""
        objs = sorted(set(objects))
        out = {}
        for i in range(0, len(objs), BATCH_SIZE):
            part = objs[i:i + BATCH_SIZE]
            got = self._batch_once(part)
            for oid, _ in part:
                out[oid] = got.get(oid)
        return out

    def missing(self, objects):
        """The oids of objects GitHub's LFS store doesn't have."""
        return sorted(oid for oid, act in self.batch(objects).items() if act is None)

    def _open(self, action, rng=None):
        href = action["href"]
        self._check_url(href)
        req = urllib.request.Request(href)
        for k, v in (action.get("header") or {}).items():
            if isinstance(k, str) and isinstance(v, str):
                req.add_unredirected_header(k, v)
        if rng:
            req.add_header("Range", rng)
        return urllib.request.urlopen(req, timeout=self.timeout)

    def fetch(self, oid, size, dest, action=None):
        """Download one object to dest and verify sha256 + size against the pointer."""
        if action is None:
            action = self.batch([(oid, size)]).get(oid)
        if action is None:
            raise LfsError(f"LFS object {oid[:12]} is not in the LFS store")
        h = hashlib.sha256()
        n = 0
        tmp = dest + ".part"
        try:
            with self._open(action) as r, open(tmp, "wb") as f:
                while True:
                    chunk = r.read(1 << 20)
                    if not chunk:
                        break
                    n += len(chunk)
                    if n > size:
                        raise LfsError(f"LFS object {oid[:12]} is larger than its pointer says")
                    h.update(chunk)
                    f.write(chunk)
        except urllib.error.HTTPError as e:
            raise LfsError(f"LFS download of {oid[:12]} answered HTTP {e.code}") from None
        except (urllib.error.URLError, OSError) as e:
            raise LfsError(f"LFS download of {oid[:12]} failed: {e.__class__.__name__}") from None
        finally:
            if os.path.exists(tmp) and (n != size or h.hexdigest() != oid):
                os.unlink(tmp)
        if n != size or h.hexdigest() != oid:
            raise LfsError(f"LFS object {oid[:12]} does not match its oid/size")
        os.replace(tmp, dest)
        return dest

    def head(self, oid, size, nbytes, action=None):
        """First bytes of an object via a range read. UNVERIFIED (adoption only, round 5 L1)."""
        if action is None:
            action = self.batch([(oid, size)]).get(oid)
        if action is None:
            raise LfsError(f"LFS object {oid[:12]} is not in the LFS store")
        try:
            with self._open(action, rng=f"bytes=0-{max(nbytes - 1, 0)}") as r:
                return r.read(nbytes)
        except (urllib.error.URLError, OSError) as e:
            raise LfsError(f"LFS range read of {oid[:12]} failed: {e.__class__.__name__}") from None
