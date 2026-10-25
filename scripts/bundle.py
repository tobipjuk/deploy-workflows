#!/usr/bin/env python3
"""Create and verify the plan bundle: the saved plan plus the gitignored build files that
`terraform apply` reads from disk (e.g. archive_file zips), bound to one commit.

  bundle.py create --root DIR --tfplan FILE --source SHA --out TAR [--glob PATTERN ...]
  bundle.py verify --root DIR --tar TAR --sha256 HEX --source SHA --tfplan-dest FILE [--glob PATTERN ...]

Layout of the (uncompressed) tar:
  tfplan            the saved plan
  SOURCE            the commit the plan was made from
  files/<relpath>   build files, relative to the repository root
  SHA256SUMS        sha256 of every other member (sorted, `sha256  name` lines)

verify refuses: a tar whose sha256 differs, any member that isn't a regular file or a directory,
absolute or `..` names, names outside the layout, files not matching --glob, paths through
.git/.terraform, files tracked by git, symlinks on the destination path, a SHA256SUMS that
doesn't list exactly the members, a wrong per-file sum, and a SOURCE other than --source.
create prints the tar's sha256. Stdlib only (plus `git ls-files` for the tracked-file check).
"""
import argparse
import fnmatch
import hashlib
import io
import os
import re
import subprocess
import sys
import tarfile

MAX_MEMBER_BYTES = 512 * 1024 * 1024
FORBIDDEN_PARTS = {".git", ".terraform", ""}


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_rel(rel, globs):
    """True if rel is a clean relative path that matches one of the globs."""
    if not rel or rel.startswith("/") or "\\" in rel:
        return False
    parts = rel.split("/")
    if any(p in FORBIDDEN_PARTS or p in (".", "..") for p in parts):
        return False
    if not re.fullmatch(r"[A-Za-z0-9._/@+-]+", rel):
        return False
    return any(fnmatch.fnmatchcase(rel, g) for g in globs)


def collect(root, globs):
    found = []
    root = os.path.realpath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", ".terraform")]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if safe_rel(rel, globs) and os.path.isfile(full) and not os.path.islink(full):
                found.append(rel)
    return sorted(found)


def _add_bytes(tar, name, data):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o644
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    tar.addfile(info, io.BytesIO(data))


def create(root, tfplan, source, out, globs):
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("source must be a 40-hex commit sha")
    members = {}
    with open(tfplan, "rb") as f:
        members["tfplan"] = f.read()
    members["SOURCE"] = (source + "\n").encode()
    for rel in collect(root, globs):
        with open(os.path.join(root, rel), "rb") as f:
            members["files/" + rel] = f.read()
    sums = "".join(f"{sha256_bytes(members[n])}  {n}\n" for n in sorted(members))
    with tarfile.open(out, "w", format=tarfile.PAX_FORMAT) as tar:
        for n in sorted(members):
            _add_bytes(tar, n, members[n])
        _add_bytes(tar, "SHA256SUMS", sums.encode())
    return sha256_file(out), len(members) - 2


def _tracked(root, rel):
    r = subprocess.run(["git", "-C", root, "ls-files", "--error-unmatch", "--", rel],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    return r.returncode == 0


def verify(root, tar_path, expected_sha, source, tfplan_dest, globs, check_git=True):
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha or ""):
        raise ValueError("expected sha256 must be 64 lowercase hex")
    actual = sha256_file(tar_path)
    if actual != expected_sha:
        raise ValueError(f"bundle sha256 mismatch (expected {expected_sha}, got {actual})")
    data = {}
    with tarfile.open(tar_path, "r:") as tar:
        for m in tar.getmembers():
            name = m.name[2:] if m.name.startswith("./") else m.name
            name = name.rstrip("/") if m.isdir() else name
            if m.isdir():
                if name in ("", ".", "files") or (name.startswith("files/") and safe_dir(name[6:])):
                    continue
                raise ValueError(f"unexpected directory in bundle: {name!r}")
            if not m.isreg():
                raise ValueError(f"bundle member is not a regular file: {name!r}")
            if m.size > MAX_MEMBER_BYTES:
                raise ValueError(f"bundle member too large: {name!r}")
            if name in ("tfplan", "SOURCE", "SHA256SUMS"):
                pass
            elif name.startswith("files/") and safe_rel(name[6:], globs):
                pass
            else:
                raise ValueError(f"unexpected member in bundle: {name!r}")
            if name in data:
                raise ValueError(f"duplicate member in bundle: {name!r}")
            data[name] = tar.extractfile(m).read()
    for required in ("tfplan", "SOURCE", "SHA256SUMS"):
        if required not in data:
            raise ValueError(f"bundle has no {required}")
    listed = {}
    for line in data["SHA256SUMS"].decode("ascii").splitlines():
        mt = re.fullmatch(r"([0-9a-f]{64})  (\S+)", line)
        if not mt or mt.group(2) in listed:
            raise ValueError("malformed SHA256SUMS")
        listed[mt.group(2)] = mt.group(1)
    present = {n for n in data if n != "SHA256SUMS"}
    if set(listed) != present:
        raise ValueError("SHA256SUMS does not list exactly the bundle members")
    for n, s in listed.items():
        if sha256_bytes(data[n]) != s:
            raise ValueError(f"sha256 mismatch for {n}")
    if data["SOURCE"].decode("ascii").strip() != source:
        raise ValueError("the plan was made from another commit")

    root_real = os.path.realpath(root)
    for n in sorted(present):
        if not n.startswith("files/"):
            continue
        rel = n[6:]
        dest = os.path.join(root_real, rel)
        parent = os.path.dirname(dest)
        existing = parent
        while not os.path.lexists(existing):
            existing = os.path.dirname(existing)
        if os.path.realpath(existing) != existing or not (existing + os.sep).startswith(root_real + os.sep):
            raise ValueError(f"destination path goes through a symlink: {rel}")
        os.makedirs(parent, exist_ok=True)
        if os.path.lexists(dest) and (os.path.islink(dest) or not os.path.isfile(dest)):
            raise ValueError(f"destination exists and is not a regular file: {rel}")
        if check_git and _tracked(root_real, rel):
            raise ValueError(f"bundle would overwrite a tracked file: {rel}")
        with open(dest, "wb") as f:
            f.write(data[n])
    with open(tfplan_dest, "wb") as f:
        f.write(data["tfplan"])
    return actual, len(present) - 2


def safe_dir(rel):
    parts = rel.split("/")
    return bool(rel) and not any(p in FORBIDDEN_PARTS or p in (".", "..") for p in parts) \
        and re.fullmatch(r"[A-Za-z0-9._/@+-]+", rel) is not None


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create")
    c.add_argument("--root", required=True)
    c.add_argument("--tfplan", required=True)
    c.add_argument("--source", required=True)
    c.add_argument("--out", required=True)
    c.add_argument("--glob", action="append", default=[])
    v = sub.add_parser("verify")
    v.add_argument("--root", required=True)
    v.add_argument("--tar", required=True)
    v.add_argument("--sha256", required=True)
    v.add_argument("--source", required=True)
    v.add_argument("--tfplan-dest", required=True)
    v.add_argument("--glob", action="append", default=[])
    v.add_argument("--no-git-check", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    try:
        if args.cmd == "create":
            sha, n = create(args.root, args.tfplan, args.source, args.out, args.glob)
            print(f"sha256={sha}")
            print(f"files={n}")
        else:
            sha, n = verify(args.root, args.tar, args.sha256, args.source, args.tfplan_dest,
                            args.glob, check_git=not args.no_git_check)
            print(f"verified sha256={sha} files={n}")
    except (OSError, ValueError, tarfile.TarError, UnicodeDecodeError) as e:
        print(f"::error::plan bundle: {e}"[:400], file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
