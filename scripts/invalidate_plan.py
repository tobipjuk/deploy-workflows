#!/usr/bin/env python3
"""Which CloudFront invalidations a deploy needs (tf-apply.yml `invalidate` input).

  invalidate_plan.py --lines TEXT --addresses CHANGED_ADDRESSES_FILE

Each non-empty line is `OUTPUT` or `OUTPUT if ADDRESS_PREFIX`: OUTPUT is a terraform output
holding a distribution id; with `if`, it applies only when the plan changed an address that
starts with ADDRESS_PREFIX (e.g. `module.games.` or `aws_s3_object.site`). Prints the OUTPUT
names to invalidate, one per line; exit 1 on a malformed line.

(Replaces a bash `[[ =~ ]]` whose bracket expression `[...\\[\\]-]` ended early, so every
`if` line was rejected: ICE deploy run 40204951622.)
"""
import argparse
import re
import sys

LINE = re.compile(r"^([A-Za-z0-9_]+)(?:\s+if\s+([A-Za-z0-9_.\[\]\"-]+))?$")


def plan(lines, addresses):
    out = []
    for raw in lines.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = LINE.match(line)
        if not m:
            raise ValueError(f"bad invalidate line: {line[:120]!r}")
        name, prefix = m.group(1), m.group(2)
        if prefix and not any(a.startswith(prefix) for a in addresses):
            continue
        if name not in out:
            out.append(name)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--lines", required=True)
    ap.add_argument("--addresses", required=True)
    args = ap.parse_args(argv)
    try:
        with open(args.addresses, encoding="utf-8") as f:
            addresses = [ln.rstrip("\n") for ln in f if ln.strip()]
        names = plan(args.lines, addresses)
    except (OSError, ValueError) as e:
        print(f"::error::{e}", file=sys.stderr)
        return 1
    for n in names:
        print(n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
