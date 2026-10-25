#!/usr/bin/env python3
"""Build the Terraform sandbox's exact egress host list for one project (Guardian M2, MEDIUM).

`*.amazonaws.com` includes hosts anyone can own: virtual-hosted S3 buckets, API Gateway
(`*.execute-api.*`), load balancers (`*.elb.*`), and more. So the proxy only relays to an EXACT
list, derived here from workflow inputs, and refuses everything else.

  egress_hosts.py --policy-dir DIR/policy/egress --repository OWNER/REPO --expect-region R
                  --expect-account ID [--expect-state-bucket B] --out FILE [--github-output FILE]

The values come from the TRUSTED policy file policy/egress/<owner>/<repo>.json in
deploy-workflows, selected by github.repository (run context). Caller inputs (from the
box-writable plan.yml/deploy.yml) are only checked for agreement; they never add hosts. No file
= refused. Outputs the trusted state bucket/region for the backend override.

Produces (one per line):
  - sts.<region>.amazonaws.com (always: credentials/account checks)
  - <service>.<region>.amazonaws.com for each --services name (regional API endpoints), and for
    dynamodb also <account_id>.ddb.<region>.amazonaws.com (SDK account-based endpoint)
  - each --global-hosts entry (global or us-east-1 API endpoints, e.g. iam.amazonaws.com,
    cloudfront.amazonaws.com, route53.amazonaws.com, acm.us-east-1.amazonaws.com)
  - <account_id>.s3-control.<region>.amazonaws.com when the project has buckets (S3 Control:
    bucket tags in AWS provider 6.x; account-scoped, own account only)
  - <bucket>.s3.<region>.amazonaws.com and <bucket>.s3.amazonaws.com for the state bucket (in
    --state-region) and each --buckets name (virtual-hosted style)
  - with --s3-path-style only: s3.<region>.amazonaws.com. Off by default: a CONNECT proxy sees
    only the host, and the path-style host serves EVERY bucket, attacker-owned ones included.

Refused (exit 1): no services (fail closed), service names s3*, execute-api, elb*,
elasticloadbalancing is fine (the API); global hosts that aren't `<name>.amazonaws.com` or
`<name>.<region>.amazonaws.com`, or that are s3*/execute-api/elb hosts; bucket names with dots
or outside S3's naming rules; anything else malformed.
"""
import argparse
import json
import os
import re
import sys

REGION = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-[0-9]$")
SERVICE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
BUCKET = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
GLOBAL_HOST = re.compile(r"^([a-z0-9]+(?:-[a-z0-9]+)*)(\.[a-z]{2}(?:-gov)?-[a-z]+-[0-9])?\.amazonaws\.com$")
FORBIDDEN_SERVICE = re.compile(r"^(s3.*|execute-api|elb.*)$")


class HostError(ValueError):
    pass


def words(s):
    return [w for w in re.split(r"[\s,]+", s or "") if w]


def build(region, state_bucket, services, global_hosts=(), buckets=(), state_region=None, s3_path_style=False,
          account_id=None):
    if not REGION.match(region or ""):
        raise HostError(f"bad region {region!r}")
    state_region = state_region or region
    if not REGION.match(state_region):
        raise HostError(f"bad state region {state_region!r}")
    if not services:
        raise HostError("the policy lists no egress services: refusing")
    hosts = {f"sts.{region}.amazonaws.com"}
    for svc in services:
        if not SERVICE.match(svc) or FORBIDDEN_SERVICE.match(svc):
            raise HostError(f"service {svc!r} is not allowed (S3 goes through buckets; no execute-api/elb)")
        hosts.add(f"{svc}.{region}.amazonaws.com")
        if svc == "dynamodb" and account_id:
            # AWS SDK v2 account-based endpoints (seen on the first ICE plan): pinned to the
            # project's own account id, so not attacker-ownable.
            if not re.fullmatch(r"[0-9]{12}", str(account_id)):
                raise HostError("bad account id")
            hosts.add(f"{account_id}.ddb.{region}.amazonaws.com")
    for h in global_hosts:
        h = h.lower().rstrip(".")
        m = GLOBAL_HOST.match(h)
        if not m or FORBIDDEN_SERVICE.match(m.group(1)):
            raise HostError(f"global host {h!r} is not an allowed API endpoint")
        hosts.add(h)
    if buckets and account_id:
        # S3 Control (bucket tags in AWS provider 6.x), account-scoped host: own account only.
        if not re.fullmatch(r"[0-9]{12}", str(account_id)):
            raise HostError("bad account id")
        hosts.add(f"{account_id}.s3-control.{region}.amazonaws.com")
    for b, r in [(state_bucket, state_region)] + [(b, region) for b in buckets]:
        if not BUCKET.match(b or "") or ".." in b or "." in b:
            raise HostError(f"bucket {b!r} is not a valid dot-free S3 bucket name")
        hosts.add(f"{b}.s3.{r}.amazonaws.com")
        hosts.add(f"{b}.s3.amazonaws.com")
    if s3_path_style:
        hosts.add(f"s3.{region}.amazonaws.com")
    return sorted(hosts)


POLICY_KEYS = {"schema", "repository", "account_id", "region", "state_bucket", "state_region", "services",
               "global_hosts", "buckets", "s3_path_style"}
REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def load_policy(policy_dir, repository):
    """The trusted policy for `repository` (from the run context). Raises HostError if absent/bad."""
    if not REPO.match(repository or "") or ".." in repository:
        raise HostError(f"bad repository {repository!r}")
    path = os.path.join(policy_dir, repository + ".json")
    try:
        with open(path, encoding="utf-8") as f:
            pol = json.load(f)
    except FileNotFoundError:
        raise HostError(f"no egress policy for {repository} in deploy-workflows (policy/egress/{repository}.json): "
                        "onboarding is a PR to deploy-workflows")
    except (OSError, ValueError) as e:
        raise HostError(f"unreadable egress policy for {repository}: {e.__class__.__name__}")
    if not isinstance(pol, dict) or set(pol) != POLICY_KEYS or pol.get("schema") != 1:
        raise HostError("egress policy has unexpected fields or schema")
    if pol["repository"] != repository:
        raise HostError("egress policy is for another repository")
    if not re.fullmatch(r"[0-9]{12}", str(pol["account_id"])):
        raise HostError("egress policy account_id")
    for k in ("services", "global_hosts", "buckets"):
        if not isinstance(pol[k], list) or not all(isinstance(x, str) for x in pol[k]):
            raise HostError(f"egress policy {k} must be a list of strings")
    if not isinstance(pol["s3_path_style"], bool):
        raise HostError("egress policy s3_path_style must be a boolean")
    return pol


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy-dir", required=True)
    ap.add_argument("--repository", required=True, help="github.repository (run context)")
    ap.add_argument("--expect-region", default="", help="caller input: must equal the policy's region")
    ap.add_argument("--expect-state-bucket", default="", help="caller input: empty or equal to the policy's")
    ap.add_argument("--expect-account", default="", help="caller input: must equal the policy's account")
    ap.add_argument("--out", required=True)
    ap.add_argument("--github-output", help="append state_bucket, state_region, region, account_id")
    args = ap.parse_args(argv)
    try:
        pol = load_policy(args.policy_dir, args.repository)
        # Caller inputs (box-writable) may only agree with the trusted policy, never extend it.
        if args.expect_region != pol["region"]:
            raise HostError(f"aws_region input {args.expect_region!r} differs from the trusted policy")
        if args.expect_state_bucket and args.expect_state_bucket != pol["state_bucket"]:
            raise HostError("state_bucket input differs from the trusted policy")
        if args.expect_account != str(pol["account_id"]):
            raise HostError("aws_account_id input differs from the trusted policy")
        hosts = build(pol["region"], pol["state_bucket"], pol["services"], pol["global_hosts"],
                      pol["buckets"], pol["state_region"], pol["s3_path_style"], str(pol["account_id"]))
    except HostError as e:
        print(f"::error::egress policy: {e}", file=sys.stderr)
        return 1
    with open(args.out, "w", encoding="ascii") as f:
        f.write("\n".join(hosts) + "\n")
    if args.github_output:
        with open(args.github_output, "a", encoding="ascii") as f:
            f.write(f"state_bucket={pol['state_bucket']}\nstate_region={pol['state_region']}\n"
                    f"region={pol['region']}\naccount_id={pol['account_id']}\n")
    print(f"egress policy {args.repository}: {len(hosts)} AWS hosts (+ Terraform registry for init)")
    for h in hosts:
        print(f"  {h}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
