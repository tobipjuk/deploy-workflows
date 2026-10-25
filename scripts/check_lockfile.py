#!/usr/bin/env python3
"""Refuse a Terraform root whose lock file names a provider outside the allowlist.

  check_lockfile.py LOCKFILE ALLOWLIST

Runs BEFORE `terraform init`, so a provider that isn't allowed is never downloaded or
executed with the role's credentials. `init -lockfile=readonly` then guarantees the
configuration can't use a provider the lock file doesn't list. Exit 0 ok, 1 refused/bad input.
"""
import re
import sys


def providers(text):
    return re.findall(r'^provider\s+"([^"]+)"\s*\{', text, flags=re.MULTILINE)


def main(argv):
    if len(argv) != 2:
        print("usage: check_lockfile.py LOCKFILE ALLOWLIST", file=sys.stderr)
        return 1
    try:
        with open(argv[0], encoding="utf-8") as f:
            used = providers(f.read())
        with open(argv[1], encoding="utf-8") as f:
            allowed = {ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")}
    except OSError as e:
        print(f"::error::cannot read {e.filename}: lock file required (commit .terraform.lock.hcl)",
              file=sys.stderr)
        return 1
    if not used:
        print("::error::the lock file lists no providers", file=sys.stderr)
        return 1
    bad = sorted(set(used) - allowed)
    for p in bad:
        print(f"::error::provider not in the deploy-workflows allowlist: {p}", file=sys.stderr)
    if not bad:
        print("providers ok: " + ", ".join(sorted(set(used))))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
