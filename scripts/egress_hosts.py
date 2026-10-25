#!/usr/bin/env python3
"""Build the Terraform sandbox's exact egress host list for one project (Guardian M2, MEDIUM).

`*.amazonaws.com` includes hosts anyone can own: virtual-hosted S3 buckets, API Gateway
(`*.execute-api.*`), load balancers (`*.elb.*`), and more. So the proxy only relays to an EXACT
list, derived here from workflow inputs, and refuses everything else.

  egress_hosts.py --region R --state-bucket B [--state-region R2] --services "lambda dynamodb ..."
                  [--global-hosts "iam.amazonaws.com cloudfront.amazonaws.com ..."]
                  [--buckets "b1 b2"] [--s3-path-style] --out FILE

Produces (one per line):
  - sts.<region>.amazonaws.com (always: credentials/account checks)
  - <service>.<region>.amazonaws.com for each --services name (regional API endpoints)
  - each --global-hosts entry (global or us-east-1 API endpoints, e.g. iam.amazonaws.com,
    cloudfront.amazonaws.com, route53.amazonaws.com, acm.us-east-1.amazonaws.com)
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


def build(region, state_bucket, services, global_hosts=(), buckets=(), state_region=None, s3_path_style=False):
    if not REGION.match(region or ""):
        raise HostError(f"bad region {region!r}")
    state_region = state_region or region
    if not REGION.match(state_region):
        raise HostError(f"bad state region {state_region!r}")
    if not services:
        raise HostError("no egress services listed (egress_services is required): refusing")
    hosts = {f"sts.{region}.amazonaws.com"}
    for svc in services:
        if not SERVICE.match(svc) or FORBIDDEN_SERVICE.match(svc):
            raise HostError(f"service {svc!r} is not allowed (S3 goes through buckets; no execute-api/elb)")
        hosts.add(f"{svc}.{region}.amazonaws.com")
    for h in global_hosts:
        h = h.lower().rstrip(".")
        m = GLOBAL_HOST.match(h)
        if not m or FORBIDDEN_SERVICE.match(m.group(1)):
            raise HostError(f"global host {h!r} is not an allowed API endpoint")
        hosts.add(h)
    for b, r in [(state_bucket, state_region)] + [(b, region) for b in buckets]:
        if not BUCKET.match(b or "") or ".." in b or "." in b:
            raise HostError(f"bucket {b!r} is not a valid dot-free S3 bucket name")
        hosts.add(f"{b}.s3.{r}.amazonaws.com")
        hosts.add(f"{b}.s3.amazonaws.com")
    if s3_path_style:
        hosts.add(f"s3.{region}.amazonaws.com")
    return sorted(hosts)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--region", required=True)
    ap.add_argument("--state-bucket", required=True)
    ap.add_argument("--state-region", default="")
    ap.add_argument("--services", default="")
    ap.add_argument("--global-hosts", default="")
    ap.add_argument("--buckets", default="")
    ap.add_argument("--s3-path-style", action="store_true")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    try:
        hosts = build(args.region, args.state_bucket, words(args.services), words(args.global_hosts),
                      words(args.buckets), args.state_region or None, args.s3_path_style)
    except HostError as e:
        print(f"::error::egress hosts: {e}", file=sys.stderr)
        return 1
    with open(args.out, "w", encoding="ascii") as f:
        f.write("\n".join(hosts) + "\n")
    print(f"egress allowlist: {len(hosts)} AWS hosts (+ Terraform registry for init)")
    for h in hosts:
        print(f"  {h}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
