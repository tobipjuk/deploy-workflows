#!/usr/bin/env python3
"""Render the IAM identity policies of a site's plan and deploy roles from its trusted site
policy (design section 2, "What the roles can do"). DRAFTS for review: nothing here applies
anything; the github-oidc-roles module (`pipeline = "site"`, not built yet) or a human applies
them. Stdlib only.

  site_iam.py POLICY_JSON --role deploy|plan [--kvs-arn ARN] [--compact]

Deploy role: the 14 actions below on their exact resources (15 with
cloudfront:DescribeKeyValueStore if the build-time check M2b shows UpdateFunction/TestFunction
need it, via --kvs-arn), one Deny with NotAction = exactly those actions on "*" (an attached
managed policy or a widened boundary can't add rights), a Deny on unconditional PutObject, and
explicit denies on the dangerous families as a second layer.

Plan role: reads only (no ReadOnlyAccess): the function, the gate, the bucket listing, GetObject
on TEXT keys only (the site's text extensions under SITE) and the manifest, with its own
NotAction deny and explicit denies on the key store, secret values and kms:Decrypt.

Both roles also get s3:ListBucket on the manifest bucket, limited to the manifest key: without
it S3 answers a missing manifest with 403 instead of 404, and the adoption plan/apply couldn't
tell "no baseline yet" from "access denied" (found while building; not in design rev. 3).
"""
import argparse
import json
import sys

import os
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import site_policy as sp  # noqa: E402

DEPLOY_ACTIONS = [
    "s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:ListBucket",
    "lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:UpdateFunctionCode",
    "cloudfront:DescribeFunction", "cloudfront:GetFunction", "cloudfront:UpdateFunction",
    "cloudfront:TestFunction", "cloudfront:PublishFunction",
    "cloudfront:CreateInvalidation", "cloudfront:GetInvalidation",
]
PLAN_ACTIONS = ["s3:GetObject", "s3:ListBucket", "lambda:GetFunction", "lambda:GetFunctionConfiguration",
                "cloudfront:GetFunction", "cloudfront:DescribeFunction"]


def _arns(pol):
    acct, region = pol["account_id"], pol["region"]
    b = f"arn:aws:s3:::{pol['bucket']}"
    site = [f"{b}/{k}" for k in pol["root_keys"]] + [f"{b}/{p}*" for p in pol["prefixes"]]
    text = [f"{b}/{k}" for k in pol["root_keys"] if sp.ext_of(k) in sp.TEXT_EXTS]
    text += [f"{b}/{p}*.{e}" for p in pol["prefixes"] for e in sorted(sp.TEXT_EXTS)]
    m = pol["manifest"]
    return {
        "bucket": b, "site": site, "text": text,
        "manifest_bucket": f"arn:aws:s3:::{m['bucket']}",
        "manifest": f"arn:aws:s3:::{m['bucket']}/{m['key']}", "manifest_key": m["key"],
        "function": f"arn:aws:lambda:{region}:{acct}:function:{pol['lambda']['function_name']}",
        "gate": f"arn:aws:cloudfront::{acct}:function/{pol['gate']['function_name']}",
        "distribution": f"arn:aws:cloudfront::{acct}:distribution/{pol['distribution_id']}",
    }


def manifest_list(a):
    return {"Sid": "ManifestListOwnKey", "Effect": "Allow", "Action": ["s3:ListBucket"],
            "Resource": a["manifest_bucket"],
            "Condition": {"StringEquals": {"s3:prefix": [a["manifest_key"]]}}}


def deploy_policy(pol, kvs_arn=None):
    a = _arns(pol)
    actions = list(DEPLOY_ACTIONS)
    st = [
        {"Sid": "SiteObjects", "Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
         "Resource": a["site"]},
        {"Sid": "SiteListing", "Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": a["bucket"]},
        {"Sid": "Manifest", "Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": a["manifest"]},
        manifest_list(a),
        {"Sid": "LambdaCodeOnly", "Effect": "Allow",
         "Action": ["lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:UpdateFunctionCode"],
         "Resource": a["function"]},
        {"Sid": "GateCode", "Effect": "Allow",
         "Action": ["cloudfront:DescribeFunction", "cloudfront:GetFunction", "cloudfront:UpdateFunction",
                    "cloudfront:TestFunction", "cloudfront:PublishFunction"], "Resource": a["gate"]},
        {"Sid": "Invalidate", "Effect": "Allow", "Action": ["cloudfront:CreateInvalidation", "cloudfront:GetInvalidation"],
         "Resource": a["distribution"]},
    ]
    if kvs_arn:
        actions.append("cloudfront:DescribeKeyValueStore")
        st.append({"Sid": "KeyStoreMetadata", "Effect": "Allow", "Action": ["cloudfront:DescribeKeyValueStore"],
                   "Resource": kvs_arn})
    kvs_deny = ["cloudfront:CreateKeyValueStore", "cloudfront:UpdateKeyValueStore", "cloudfront:DeleteKeyValueStore"]
    if not kvs_arn:
        kvs_deny.append("cloudfront:DescribeKeyValueStore")
    st += [
        {"Sid": "DenyEverythingElse", "Effect": "Deny", "NotAction": actions, "Resource": "*"},
        {"Sid": "DenyUnconditionalPut", "Effect": "Deny", "Action": ["s3:PutObject"], "Resource": "*",
         "Condition": {"Null": {"s3:if-match": "true", "s3:if-none-match": "true"}}},
        {"Sid": "DenyDangerous", "Effect": "Deny", "Resource": "*", "Action": [
            "iam:*", "sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML",
            "lambda:UpdateFunctionConfiguration", "lambda:AddPermission", "lambda:RemovePermission",
            "lambda:*FunctionUrl*", "lambda:CreateFunction", "lambda:DeleteFunction", "lambda:PublishLayerVersion",
            "cloudfront:UpdateDistribution", "cloudfront:CreateFunction", "cloudfront:DeleteFunction",
            *kvs_deny, "cloudfront-keyvaluestore:*",
            "apigateway:*", "dynamodb:*", "secretsmanager:*", "kms:*", "ssm:*",
            "s3:PutBucket*", "s3:DeleteBucket*", "s3:PutObjectAcl", "s3:DeleteObjectVersion"]},
    ]
    return {"Version": "2012-10-17", "Statement": st}


def plan_policy(pol):
    a = _arns(pol)
    st = [
        {"Sid": "LambdaRead", "Effect": "Allow", "Action": ["lambda:GetFunction", "lambda:GetFunctionConfiguration"],
         "Resource": a["function"]},
        {"Sid": "GateRead", "Effect": "Allow", "Action": ["cloudfront:GetFunction", "cloudfront:DescribeFunction"],
         "Resource": a["gate"]},
        {"Sid": "SiteListing", "Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": a["bucket"]},
        {"Sid": "SiteTextKeysOnly", "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": a["text"]},
        {"Sid": "ManifestRead", "Effect": "Allow", "Action": ["s3:GetObject"], "Resource": a["manifest"]},
        manifest_list(a),
        {"Sid": "DenyEverythingElse", "Effect": "Deny", "NotAction": list(PLAN_ACTIONS), "Resource": "*"},
        {"Sid": "DenySecrets", "Effect": "Deny", "Resource": "*",
         "Action": ["cloudfront-keyvaluestore:*", "secretsmanager:GetSecretValue", "kms:Decrypt"]},
    ]
    return {"Version": "2012-10-17", "Statement": st}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("policy")
    ap.add_argument("--role", choices=["deploy", "plan"], required=True)
    ap.add_argument("--kvs-arn")
    ap.add_argument("--compact", action="store_true")
    args = ap.parse_args(argv)
    with open(args.policy, encoding="utf-8") as f:
        pol = sp.validate_policy(json.load(f))
    doc = deploy_policy(pol, args.kvs_arn) if args.role == "deploy" else plan_policy(pol)
    if args.compact:
        print(json.dumps(doc, separators=(",", ":")))
    else:
        print(json.dumps(doc, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
