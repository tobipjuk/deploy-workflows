#!/usr/bin/env python3
"""Write deploy-result.json for Orion (docs/orion-interface.md section 8). Stdlib only.

  deploy_result.py --checks-dir DIR --out FILE [--github-output FILE]

Environment (from tf-apply.yml): APPLY_OUTCOME (steps.apply.outcome), ADD/CHANGE/DESTROY/REPLACE,
TARGET, PLAN_RUN_ID, BUNDLE_SHA256, CHANGES_DIGEST, GITHUB_REPOSITORY/SHA/RUN_ID.
DIR holds one file per post-apply check (egress, invalidation, smoke) with ok | failed |
pending | warning; a missing file means the check didn't run (skipped).

status:
  deployed                applied, every check ok or skipped
  deployed_with_warnings  applied, at least one check failed/pending/warning
  failed                  not applied (a gate, the bundle, the apply itself ...)
"""
import argparse
import json
import os
import sys

CHECKS = ("egress", "invalidation", "smoke")
VALUES = {"ok", "failed", "pending", "warning"}


def read_checks(d):
    out = {}
    for c in CHECKS:
        try:
            with open(os.path.join(d, c), encoding="ascii") as f:
                v = f.read().strip()
        except OSError:
            v = "skipped"
        out[c] = v if v in VALUES or v == "skipped" else "failed"
    return out


def summarise(applied, checks):
    if not applied:
        return "failed", "not applied"
    bad = {k: v for k, v in checks.items() if v not in ("ok", "skipped")}
    if not bad:
        return "deployed", "applied, checks ok"
    words = []
    if "egress" in bad:
        words.append("egress warning")
    for k in ("invalidation", "smoke"):
        if k in bad:
            words.append(f"{k} {bad[k]}")
    return "deployed_with_warnings", "applied, " + ", ".join(words)


def build(env, checks):
    applied = env.get("APPLY_OUTCOME") == "success"
    status, text = summarise(applied, checks)

    def count(k):
        v = env.get(k)
        return int(v) if v and v.isdigit() else None
    return {
        "schema": 2,
        "target": env.get("TARGET"), "repo": env.get("GITHUB_REPOSITORY"), "sha": env.get("GITHUB_SHA"),
        "deploy_run_id": int(env.get("GITHUB_RUN_ID") or 0), "plan_run_id": env.get("PLAN_RUN_ID"),
        "bundle_sha256": env.get("BUNDLE_SHA256"), "changes_digest": env.get("CHANGES_DIGEST"),
        "applied": applied,
        "counts": {k.lower(): count(k) for k in ("ADD", "CHANGE", "DESTROY", "REPLACE")},
        "checks": checks,
        "status": status,
        "summary": text,
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--checks-dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--github-output")
    args = ap.parse_args(argv)
    doc = build(os.environ, read_checks(args.checks_dir))
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
    if args.github_output:
        with open(args.github_output, "a", encoding="ascii") as f:
            f.write(f"result={doc['status']}\n")
    print(f"deploy result: {doc['status']} ({doc['summary']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
