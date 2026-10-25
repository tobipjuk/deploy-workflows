#!/usr/bin/env python3
"""Summarise and gate a Terraform plan (the JSON from `terraform show -json tfplan`).

Used by tf-plan.yml (report) and tf-apply.yml (gate). Stdlib only.

  plan_report.py PLAN_JSON [--summary FILE] [--outputs FILE] [--json FILE]
                 [--addresses FILE] [--allow-destroy true|false] [--expect-digest HEX]
                 [--allowed-providers FILE] [--meta KEY=VALUE ...]

--summary            append a Markdown section (counts, flags, addresses, redacted diff) to FILE
--outputs            append key=value lines (has_changes, destructive, blocked, add, change,
                     destroy, replace, digest) to FILE, e.g. $GITHUB_OUTPUT
--json               write plan-summary.json (the Telegram-safe summary, see docs/orion-interface.md)
--addresses          write every changed address, one per line, to FILE
--allow-destroy      false (default): exit 3 when the plan deletes, replaces or does anything
                     not understood (fail closed)
--expect-digest      exit 5 unless changes_digest equals HEX (binds what was approved to what
                     is applied)
--allowed-providers  provider allowlist (one registry address per line); a provider outside it
                     blocks the plan (exit 4)
--meta               extra top-level fields for plan-summary.json (repo, sha, run_id...)

What it reads: addresses, action lists, provider names, the configuration's provisioners and
data sources, and attribute values ONLY for the redacted diff: a value is shown only if neither
Terraform's sensitivity masks nor the name filter mark it, and is truncated.

Exit codes: 0 ok, 2 bad input, 3 destructive without --allow-destroy true,
4 blocked (code execution or provider outside the allowlist), 5 digest mismatch.
"""
import argparse
import hashlib
import json
import re
import sys

SCHEMA = 1
BENIGN = (["no-op"], ["read"])
MAX_DIFF_RESOURCES = 40
MAX_DIFF_ATTRS = 8
MAX_VALUE_CHARS = 60
MAX_SUMMARY_LINES = 200

# Attribute path segments whose values are never shown, whatever the masks say.
HIDDEN_NAME = re.compile(
    r"(secret|password|passwd|token|pepper|salt|private|credential|api_?key|access_?key|auth"
    r"|cookie|session|signature|certificate_(body|chain)|^content(_base64)?$|^variables$"
    r"|user_data|_wo$|^value$|(^|_)policy$|^records$|^body$|^definition$)",
    re.IGNORECASE,
)

# Terraform's built-in provider (terraform_data, terraform_remote_state): not downloaded, no
# lock file entry; terraform_data's only code path is a provisioner, which is blocked anyway.
BUILTIN_PROVIDERS = {"terraform.io/builtin/terraform"}

# Things that execute code with the deploy role's credentials beyond the provider itself.
CODE_EXEC_DATA_TYPES = {"external"}


def classify(actions):
    """Map Terraform's action list to one bucket, or None for no-op/read.

    Missing, null, empty or unknown action lists land in "other", which counts as destructive.
    """
    if not isinstance(actions, list) or not actions:
        return "other"
    acts = [str(a) for a in actions]
    if acts in BENIGN:
        return None
    if "delete" in acts and "create" in acts:
        return "replace"
    if acts == ["create"]:
        return "add"
    if acts == ["update"]:
        return "change"
    if acts == ["delete"]:
        return "destroy"
    if acts == ["forget"]:
        return "forget"
    return "other"


def digest(changes):
    """sha256 over the canonical JSON of [{address, actions}] sorted by address.

    Orion recomputes this from plan-summary.json's `changes` and tf-apply recomputes it from
    the plan file; equal digests mean the applied plan is the approved one.
    """
    canon = json.dumps(changes, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canon.encode("ascii")).hexdigest()


# --- redacted attribute diff -----------------------------------------------------------

def _mask_at(mask, key):
    if mask is True:
        return True
    if isinstance(mask, dict):
        return mask.get(key, False)
    if isinstance(mask, list) and isinstance(key, int) and key < len(mask):
        return mask[key]
    return False


URL = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*://)([^/?#@]*@)?([^/?#]*)([^?#]*)(\?[^#]*)?(#.*)?$")


def sanitize_url(v):
    """Drop userinfo, query and fragment from URL-looking strings: they are where secrets ride
    (https://user:pass@host/?token=...). Host and path stay visible."""
    if not isinstance(v, str):
        return v
    m = URL.match(v.strip())
    if not m:
        return v
    scheme, userinfo, host, path, query, frag = m.groups()
    return (scheme + ("…@" if userinfo else "") + host + path + ("?…" if query else "")
            + ("#…" if frag else ""))


def _render(v):
    if isinstance(v, str):
        s = json.dumps(sanitize_url(v), ensure_ascii=False)
    elif v is None or isinstance(v, (bool, int, float)):
        s = json.dumps(v)
    else:
        s = "(" + type(v).__name__ + ")"
    if len(s) > MAX_VALUE_CHARS:
        s = s[: MAX_VALUE_CHARS - 1] + "…"
    return s


def _diff(before, after, unknown, bmask, amask, path, out):
    keys = None
    if isinstance(before, dict) or isinstance(after, dict):
        b = before if isinstance(before, dict) else {}
        a = after if isinstance(after, dict) else {}
        keys = sorted(set(b) | set(a))
        get_b, get_a = b.get, a.get
    elif isinstance(before, list) or isinstance(after, list):
        b = before if isinstance(before, list) else []
        a = after if isinstance(after, list) else []
        keys = list(range(max(len(b), len(a))))
        get_b = lambda k: b[k] if k < len(b) else None  # noqa: E731
        get_a = lambda k: a[k] if k < len(a) else None  # noqa: E731
    if keys is not None and not (bmask is True or amask is True):
        for k in keys:
            _diff(get_b(k), get_a(k), _mask_at(unknown, k), _mask_at(bmask, k), _mask_at(amask, k),
                  path + [k], out)
        return
    if before == after and unknown is not True:
        return
    shown = ".".join(str(p) if isinstance(p, str) else f"[{p}]" for p in path).replace(".[", "[")
    hidden = (bmask is not False and bmask not in ({}, [])) or (amask is not False and amask not in ({}, [])) \
        or any(isinstance(p, str) and HIDDEN_NAME.search(p) for p in path)
    if hidden:
        out.append({"path": shown, "before": "(hidden)", "after": "(hidden)"})
    elif unknown is True:
        out.append({"path": shown, "before": _render(before), "after": "(known after apply)"})
    else:
        out.append({"path": shown, "before": _render(before), "after": _render(after)})


def attr_diff(change):
    out = []
    try:
        _diff(change.get("before"), change.get("after"), change.get("after_unknown") or False,
              change.get("before_sensitive") or False, change.get("after_sensitive") or False, [], out)
    except RecursionError:
        return [{"path": "(too deep)", "before": "", "after": ""}]
    return out


# --- needs-attention changes (Guardian M2) -----------------------------------------------------
# Changes that redirect traffic, grant access or open data, shown first in the job summary and in
# Telegram so they can't hide in a long list of S3 objects. They don't change the gates; the
# summary (and so this list) is bound by the attestation, the addresses by the changes digest.

MAX_ATTENTION = 30
MAX_ATTENTION_VALUE = 100
BUCKET_CONFIG = re.compile(r"^aws_s3_bucket_(policy|acl|public_access_block|ownership_controls|cors_configuration"
                           r"|website_configuration|replication_configuration|notification|logging"
                           r"|server_side_encryption_configuration|versioning|lifecycle_configuration)$")
# (resource type, attribute path, label, show the value?)
# show=True only for paths that name things (hosts, principals, ARNs, auth types); URLs among them
# lose userinfo/query/fragment (sanitize_url). Policy documents, env vars and record values are
# never shown, and Terraform's sensitivity masks always win ("(hidden)").
ATTENTION_RULES = [
    (re.compile(r"^aws_apigatewayv2_integration$"), re.compile(r"^integration_uri$"), "API integration target", True),
    (re.compile(r"^aws_api_gateway_integration$"), re.compile(r"^uri$"), "API integration target", True),
    (re.compile(r"^aws_cloudfront_distribution$"), re.compile(r"^origin\[\d+\]\.domain_name$"), "CloudFront origin", True),
    (re.compile(r"^aws_lambda_permission$"),
     re.compile(r"^(principal|source_arn|source_account|principal_org_id|function_url_auth_type)$"),
     "Lambda invoke permission", True),
    (re.compile(r"^aws_lambda_function_url$"), re.compile(r"^authorization_type$"), "Lambda function URL auth", True),
    (re.compile(r"^aws_iam_role$"), re.compile(r"^assume_role_policy$"), "role trust policy", False),
    (re.compile(r"^aws_iam_(role_policy|policy)$"), re.compile(r"^policy$"), "IAM policy document", False),
    (re.compile(r"^aws_iam_role_policy_attachment$"), re.compile(r"^policy_arn$"), "managed policy attached", True),
    (re.compile(r"^aws_route53_record$"), re.compile(r"^(name|type|alias\[0\]\.name)$"), "DNS record", True),
    # TXT and other record values can carry anything: flagged, value not shown.
    (re.compile(r"^aws_route53_record$"), re.compile(r"^records\[\d+\]$"), "DNS record value", False),
    (re.compile(r"^aws_sns_topic_subscription$"), re.compile(r"^(endpoint|protocol)$"), "SNS subscription", True),
    (re.compile(r"^aws_lambda_function$"), re.compile(r"^environment\[0\]\.variables\..+$"),
     "Lambda environment variable", False),
]


def _flat(v, sens, unk, prefix, out):
    if sens is True:
        out[prefix] = "(hidden)"
        return
    if unk is True:
        out[prefix] = "(known after apply)"
        return
    if isinstance(v, dict):
        for k in v:
            _flat(v[k], _mask_at(sens, k), _mask_at(unk, k), f"{prefix}.{k}" if prefix else str(k), out)
    elif isinstance(v, list):
        for i, x in enumerate(v):
            _flat(x, _mask_at(sens, i), _mask_at(unk, i), f"{prefix}[{i}]", out)
    else:
        out[prefix] = v


def flatten(change, side):
    out = {}
    try:
        if side == "after":
            _flat(change.get("after"), change.get("after_sensitive") or False, change.get("after_unknown") or False, "", out)
        else:
            _flat(change.get("before"), change.get("before_sensitive") or False, False, "", out)
    except RecursionError:
        return {}
    return out


def _att_value(path, v, show):
    if v is None:
        return None
    if v in ("(hidden)", "(known after apply)"):
        return v
    # Curated paths (domains, principals, URIs) are shown unless Terraform marks them sensitive;
    # policy documents and env vars are never shown here.
    if not show:
        return "(changed, value not shown)"
    s = sanitize_url(v) if isinstance(v, str) else json.dumps(v)
    return s if len(s) <= MAX_ATTENTION_VALUE else s[: MAX_ATTENTION_VALUE - 1] + "…"


def attention(rc, kind):
    rtype = str(rc.get("type") or "")
    addr = str(rc.get("address", "?"))
    change = rc.get("change") if isinstance(rc.get("change"), dict) else {}
    hits = []
    if BUCKET_CONFIG.match(rtype):
        hits.append({"address": addr, "label": "S3 bucket configuration", "action": kind, "path": None,
                     "before": None, "after": None})
        return hits
    rules = [(pr, label, show) for tr, pr, label, show in ATTENTION_RULES if tr.match(rtype)]
    if not rules:
        return hits
    before = flatten(change, "before") if kind != "add" else {}
    after = flatten(change, "after") if kind != "destroy" else {}
    # Change detection on the raw values (masked ones would compare "(hidden)" == "(hidden)").
    raw_b = flatten({"before": change.get("before")}, "before") if kind != "add" else {}
    raw_a = flatten({"after": change.get("after")}, "after") if kind != "destroy" else {}
    for path in sorted(set(before) | set(after)):
        for pr, label, show in rules:
            if pr.match(path) and (kind in ("add", "destroy") or raw_b.get(path) != raw_a.get(path)
                                   or after.get(path) == "(known after apply)"):
                hits.append({"address": addr, "label": label, "action": kind, "path": path,
                             "before": _att_value(path, before.get(path), show),
                             "after": _att_value(path, after.get(path), show)})
                break
    return hits


# --- configuration scan: provisioners, external data sources, providers -----------------

def _walk_modules(module, prefix=""):
    yield prefix, module or {}
    for name, call in ((module or {}).get("module_calls") or {}).items():
        yield from _walk_modules((call or {}).get("module"), f"{prefix}module.{name}.")


def scan_config(plan, allowed_providers):
    flags = []
    cfg = plan.get("configuration") or {}
    for prefix, mod in _walk_modules(cfg.get("root_module")):
        for r in mod.get("resources") or []:
            addr = prefix + str(r.get("address", "?"))
            if r.get("provisioners"):
                kinds = sorted({str(p.get("type", "?")) for p in r["provisioners"]})
                flags.append(f"provisioner ({', '.join(kinds)}) on {addr}")
            if r.get("mode") == "data" and r.get("type") in CODE_EXEC_DATA_TYPES:
                flags.append(f"data source {r.get('type')} runs a program: {addr}")
    if allowed_providers is not None:
        used = set()
        for pc in (cfg.get("provider_config") or {}).values():
            if pc.get("full_name"):
                used.add(pc["full_name"])
        for rc in plan.get("resource_changes") or []:
            if rc.get("provider_name"):
                used.add(rc["provider_name"])
        for p in sorted(used - allowed_providers - BUILTIN_PROVIDERS):
            flags.append(f"provider not in the allowlist: {p}")
    return flags


def load_allowlist(path):
    if not path:
        return None
    with open(path, encoding="utf-8") as f:
        return {ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")}


# --- analysis ------------------------------------------------------------------------------

def analyse(plan, allowed_providers=None):
    if not isinstance(plan, dict) or "format_version" not in plan:
        raise ValueError("not a terraform show -json plan")
    if plan.get("errored"):
        raise ValueError("the plan errored")
    groups = {k: [] for k in ("add", "change", "destroy", "replace", "forget", "other")}
    changes, diffs, attn = [], [], []
    for rc in plan.get("resource_changes") or []:
        change = rc.get("change") if isinstance(rc.get("change"), dict) else {}
        actions = change.get("actions")
        kind = classify(actions)
        if not kind:
            continue
        addr = str(rc.get("address", "?"))
        groups[kind].append(addr)
        changes.append({"address": addr,
                        "actions": [str(a) for a in actions] if isinstance(actions, list) else []})
        attn.extend(attention(rc, kind))
        if kind in ("change", "replace"):
            d = attr_diff(change)
            if d:
                diffs.append({"address": addr, "attrs": d})
    for v in groups.values():
        v.sort()
    changes.sort(key=lambda c: (c["address"], c["actions"]))
    diffs.sort(key=lambda d: d["address"])
    attn.sort(key=lambda a: (a["address"], a["path"] or ""))

    flags = []
    action_invocations = plan.get("action_invocations") or []
    deferred = plan.get("deferred_changes") or []
    if action_invocations:
        flags.append(f"{len(action_invocations)} action invocation(s): treated as destructive")
    if deferred:
        flags.append(f"{len(deferred)} deferred change(s): plan incomplete, treated as destructive")
    if plan.get("complete") is False:
        flags.append("plan marked incomplete: treated as destructive")
    blocked = scan_config(plan, allowed_providers)

    destructive = bool(groups["destroy"] or groups["replace"] or groups["other"]
                       or action_invocations or deferred or plan.get("complete") is False)
    return {
        "groups": groups,
        "changes": changes,
        "digest": digest(changes),
        "diffs": diffs,
        "attention": attn,
        "has_changes": bool(changes or action_invocations or deferred),
        "destructive": destructive,
        "flags": flags,
        "blocked": blocked,
        "counts": {
            **{k: len(v) for k, v in groups.items()},
            "action_invocations": len(action_invocations),
            "deferred": len(deferred),
        },
    }


def truncated_diffs(diffs):
    out, truncated = [], False
    for d in diffs:
        if len(out) >= MAX_DIFF_RESOURCES:
            truncated = True
            break
        attrs = d["attrs"]
        if len(attrs) > MAX_DIFF_ATTRS:
            truncated = True
            attrs = attrs[:MAX_DIFF_ATTRS] + [{"path": f"… {len(d['attrs']) - MAX_DIFF_ATTRS} more",
                                                "before": "", "after": ""}]
        out.append({"address": d["address"], "attrs": attrs})
    return out, truncated


def summary_json(result, meta):
    diff, truncated = truncated_diffs(result["diffs"])
    doc = {
        "schema": SCHEMA,
        **meta,
        "counts": result["counts"],
        "has_changes": result["has_changes"],
        "destructive": result["destructive"],
        "flags": result["flags"],
        "blocked": result["blocked"],
        "changes": result["changes"],
        "changes_digest": result["digest"],
        "diff": diff,
        "diff_truncated": truncated,
        "attention": result["attention"][:MAX_ATTENTION],
        "attention_truncated": len(result["attention"]) > MAX_ATTENTION,
    }
    return doc


def markdown(result):
    g, c = result["groups"], result["counts"]
    out = [
        "### Terraform plan",
        "",
        f"**{c['add']} to add, {c['change']} to change, {c['destroy']} to destroy, "
        f"{c['replace']} to replace**"
        + (f", {c['forget']} to forget" if c["forget"] else "")
        + (f", {c['other']} other" if c["other"] else ""),
        "",
        f"Changes digest: `{result['digest']}`",
        "",
    ]
    for f in result["blocked"]:
        out.append(f"> **Blocked:** {f}")
    for f in result["flags"]:
        out.append(f"> **Flag:** {f}")
    if result["blocked"] or result["flags"]:
        out.append("")
    if not result["has_changes"]:
        out += ["No changes. Nothing to deploy.", ""]
        return "\n".join(out) + "\n"
    if result["attention"]:
        out += [f"**Needs attention ({len(result['attention'])}):**", ""]
        for a in result["attention"][:MAX_ATTENTION]:
            detail = f" `{a['path']}`: {a['before']} → {a['after']}" if a["path"] else ""
            out.append(f"- {a['label']} ({a['action']}) `{a['address']}`{detail}")
        out.append("")
    labels = [("replace", "Replace (destroy + create)"), ("destroy", "Destroy"), ("other", "Other"),
              ("add", "Add"), ("change", "Change"), ("forget", "Forget")]
    shown, total = 0, sum(len(v) for v in g.values())
    for key, label in labels:
        if not g[key]:
            continue
        out.append(f"<details{' open' if key in ('replace', 'destroy', 'other') else ''}>"
                   f"<summary>{label}: {len(g[key])}</summary>")
        out.append("")
        for a in g[key]:
            if shown >= MAX_SUMMARY_LINES:
                out.append(f"- … ({total - shown} more)")
                break
            out.append(f"- `{a}`")
            shown += 1
        out += ["", "</details>", ""]
    diff, truncated = truncated_diffs(result["diffs"])
    if diff:
        out += ["<details><summary>Attribute diff (redacted" + (", truncated" if truncated else "")
                + ")</summary>", ""]
        for d in diff:
            out.append(f"- `{d['address']}`")
            for a in d["attrs"]:
                out.append(f"  - `{a['path']}`: {a['before']} → {a['after']}")
        out += ["", "</details>", ""]
    return "\n".join(out) + "\n"


def parse_meta(items):
    meta = {}
    for item in items or []:
        k, sep, v = item.partition("=")
        if not sep or not re.fullmatch(r"[a-z_][a-z0-9_]*", k):
            raise ValueError(f"bad --meta {k!r}")
        if v in ("true", "false"):
            meta[k] = v == "true"
        elif v == "null":
            meta[k] = None
        elif re.fullmatch(r"[0-9]{1,18}", v):
            meta[k] = int(v)
        else:
            meta[k] = v
    return meta


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("plan_json")
    ap.add_argument("--summary")
    ap.add_argument("--outputs")
    ap.add_argument("--json", dest="json_out")
    ap.add_argument("--addresses")
    ap.add_argument("--allow-destroy", choices=["true", "false"], default="false")
    ap.add_argument("--expect-digest")
    ap.add_argument("--allowed-providers")
    ap.add_argument("--meta", action="append")
    args = ap.parse_args(argv)
    try:
        meta = parse_meta(args.meta)
        allow = load_allowlist(args.allowed_providers)
        with open(args.plan_json, encoding="utf-8") as f:
            result = analyse(json.load(f), allow)
    except (OSError, ValueError) as e:
        print(f"::error::cannot read plan JSON: {e.__class__.__name__}: {e}"[:300], file=sys.stderr)
        return 2

    c = result["counts"]
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as f:
            f.write(markdown(result))
    if args.outputs:
        with open(args.outputs, "a", encoding="utf-8") as f:
            f.write(f"has_changes={str(result['has_changes']).lower()}\n")
            f.write(f"destructive={str(result['destructive']).lower()}\n")
            f.write(f"blocked={str(bool(result['blocked'])).lower()}\n")
            f.write(f"digest={result['digest']}\n")
            f.write(f"attention={len(result['attention'])}\n")
            for k in ("add", "change", "destroy", "replace"):
                f.write(f"{k}={c[k]}\n")
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(summary_json(result, meta), f, indent=1, sort_keys=True, ensure_ascii=False)
            f.write("\n")
    if args.addresses:
        with open(args.addresses, "w", encoding="utf-8") as f:
            for ch in result["changes"]:
                f.write(ch["address"] + "\n")
    print(f"plan: {c['add']} add, {c['change']} change, {c['destroy']} destroy, {c['replace']} replace, "
          f"destructive={str(result['destructive']).lower()}, blocked={len(result['blocked'])}, "
          f"digest={result['digest']}")

    if args.expect_digest is not None and args.expect_digest != result["digest"]:
        print("::error::The plan's changes digest does not match the approved one. Not applying.",
              file=sys.stderr)
        return 5
    if result["blocked"]:
        for b in result["blocked"]:
            print(f"::error::Blocked: {b}", file=sys.stderr)
        return 4
    if result["destructive"] and args.allow_destroy != "true":
        print("::error::The plan deletes, replaces or does something not understood. Refusing. "
              "Plan again by hand (workflow_dispatch) with allow_destroy = true if intended.",
              file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
