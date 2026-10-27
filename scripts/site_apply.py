#!/usr/bin/env python3
"""Site apply: carry out an approved, attested site plan with the deploy role.

  site_apply.py --bundle TAR --summary JSON --bundle-sha256 HEX --changes-digest HEX
                --sha SHA --repository OWNER/REPO --policy-dir DIR --checks-dir DIR
                [--allow-destroy true|false] [--github-output FILE] [--step-summary FILE]
                [--verify-only]

Runs in site-apply.yml after check_plan_run.py --kind site and attest.py verify. Order
(design section 4):

  0. verify the bundle and the summary against the approved values and the trusted policy,
     and recompute the change list (digest) from plan.json
  1. pre-state: the whole S3 listing, the manifest ETag, the Lambda's RevisionId and
     CodeSha256, the gate's LIVE/DEVELOPMENT ETags and config must equal the plan's; any
     drift stops here, nothing written
  2. fetch every LFS object the apply uploads, verify oid + size on the full bytes, repeat the
     magic-byte check: before the first write
  3. gate: UpdateFunction (config unchanged) on DEVELOPMENT, then TestFunction per policy case;
     SILENT: case name and pass/fail only, never the status, Location, headers, logs or errors
  4. Lambda: UpdateFunctionCode with the plan's RevisionId, wait, check CodeSha256
  5. S3: single-part PutObject, SHA-256 checksum, If-Match (or If-None-Match: *) on the pre-state
  6. gate: PublishFunction
  7. deletes (the approved list, If-Match)
  8. manifest: If-Match on its pre-state ETag (If-None-Match: * the first time); after a
     failure from step 4 on, it still records what was written
  9. invalidate and smoke check (post-apply checks, never fail an applied deploy)

Exit codes: 0 applied; 1 refused before any write; 2 failed after a write (partial).
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

import lfs_fetch  # noqa: E402
import site_aws  # noqa: E402
import site_bundle  # noqa: E402
import site_diff as sd  # noqa: E402
import site_plan  # noqa: E402
import site_policy as sp  # noqa: E402

GATE_VIEWER_IP = "198.51.100.7"
INVALIDATION_LIMIT = 100


class ApplyRefused(Exception):
    """Refused before anything was written."""


class ApplyFailed(Exception):
    """Failed after something was written."""


def b64(hexstr):
    return base64.b64encode(bytes.fromhex(hexstr)).decode("ascii")


# --- 0. verification -------------------------------------------------------------------------

def verify_inputs(bundle_path, summary_path, bundle_sha256, digest, sha, repository, policy, policy_sha256,
                  allow_destroy):
    try:
        b = site_bundle.verify(bundle_path, bundle_sha256, sha)
    except site_bundle.BundleError as e:
        raise ApplyRefused(f"plan bundle: {e}") from None
    with open(summary_path, "rb") as f:
        try:
            summary = json.loads(f.read())
        except ValueError:
            raise ApplyRefused("plan-summary.json is not JSON") from None
    plan = b["plan"]
    want = {"kind": "site", "repo": repository, "sha": sha, "bundle_sha256": bundle_sha256,
            "changes_digest": digest, "deployable": True, "diff_complete": True, "target": policy["target"]}
    for k, v in want.items():
        if summary.get(k) != v:
            raise ApplyRefused(f"plan summary field {k} is not the approved/expected value")
    if (summary.get("site") or {}).get("plan_sha256") != hashlib.sha256(b["plan_bytes"]).hexdigest():
        raise ApplyRefused("plan summary does not describe this bundle's plan.json")
    if plan.get("kind") != "site" or plan.get("repository") != repository or plan.get("target") != policy["target"]:
        raise ApplyRefused("plan.json is for another kind, repository or target")
    if plan.get("policy_sha256") != policy_sha256:
        raise ApplyRefused("the site policy changed since the plan: plan again")
    if plan.get("bucket") != policy["bucket"] or plan.get("manifest") != policy["manifest"]:
        raise ApplyRefused("plan.json names another bucket or manifest than the policy")
    changes = sd.changes_from_plan(plan)
    if sd.changes_digest(changes) != digest or summary.get("changes") != changes:
        raise ApplyRefused("the plan's changes are not the approved ones (digest mismatch)")
    if plan.get("destructive") and not allow_destroy:
        raise ApplyRefused("destructive plan (deletes over the policy's limit) without allow_destroy")
    if len(plan["deletes"]) > policy.get("max_deletes", 20) and not plan.get("destructive"):
        raise ApplyRefused("plan.json understates its deletes")
    # Defence in depth: everything the apply writes must fit the trusted policy and tables.
    for p in plan["puts"]:
        sp.check_key(p["key"])
        if not sp.in_site(policy, p["key"]):
            raise ApplyRefused(f"put outside SITE: {p['key']}")
        cls, ct = sp.classify(p["key"], p["key"])
        if ct != p["content_type"] or cls != p["class"] or p["cache_control"] not in sp.CACHE_CLASSES.values():
            raise ApplyRefused(f"put {p['key']}: content type or cache class outside the tables")
        if p["action"] not in ("create", "update") or (p["action"] == "create") != (p["if_match"] is None):
            raise ApplyRefused(f"put {p['key']}: bad precondition")
        src = p["source"]
        if src["type"] == "blob":
            if p["sha256"] not in b["blobs"] or len(b["blobs"][p["sha256"]]) != p["size"]:
                raise ApplyRefused(f"put {p['key']}: bytes missing from the bundle")
            data = b["blobs"][p["sha256"]]
            if cls in ("code", "data"):
                sd.check_text(data, p["key"])
                if lfs_fetch.looks_like_pointer(data):
                    raise ApplyRefused(f"put {p['key']}: text key carries an LFS pointer")
            elif not sp.magic_ok(sp.ext_of(p["key"]), data[:sp.MAGIC_BYTES_NEEDED]):
                raise ApplyRefused(f"put {p['key']}: magic bytes")
        elif src["type"] == "lfs":
            if cls != "binary" or src["oid"] != p["sha256"] or src["size"] != p["size"]:
                raise ApplyRefused(f"put {p['key']}: LFS source on a text key or oid mismatch")
        else:
            raise ApplyRefused(f"put {p['key']}: unknown source")
    for d in plan["deletes"]:
        sp.check_key(d["key"])
        if not sp.in_site(policy, d["key"]) or not d.get("if_match"):
            raise ApplyRefused(f"delete outside SITE or unconditional: {d['key']}")
        if d["key"] in plan["desired"]:
            raise ApplyRefused(f"{d['key']} is both deleted and desired")
    # The manifest is built from `desired`: it must describe SITE keys with table values only.
    for k, d in plan["desired"].items():
        sp.check_key(k)
        if not sp.in_site(policy, k) or d.get("cache") not in sp.CACHE_CLASSES \
                or sp.classify(k, k)[1] != d.get("content_type") or not re.fullmatch(r"[0-9a-f]{64}", d.get("sha256", "")):
            raise ApplyRefused(f"desired entry {k} is outside the policy or the tables")
    for p in plan["puts"]:
        want = plan["desired"].get(p["key"])
        if want is None or want["sha256"] != p["sha256"] or want["size"] != p["size"]:
            raise ApplyRefused(f"put {p['key']} does not match the desired manifest")
    lam = plan.get("lambda")
    if lam:
        z = b["lambda_zip"]
        if z is None or sd.sha256_hex(z) != lam["zip_sha256"] or lam["function_name"] != policy["lambda"]["function_name"]:
            raise ApplyRefused("Lambda zip missing or not the planned one")
        members = sd.read_zip(z)
        if set(members) != set(policy["lambda"]["members"]) or set(members) != set(lam["members"]):
            raise ApplyRefused("Lambda zip members are not the policy's allowlist")
        for n, data in members.items():
            if sp.module_name_shadows(n) or sd.sha256_hex(data) != lam["members"][n]:
                raise ApplyRefused(f"Lambda member {n} is not the planned one")
            sd.check_text(data, n)
    elif b["lambda_zip"] is not None:
        raise ApplyRefused("bundle carries a Lambda zip the plan doesn't use")
    gate = plan.get("gate")
    if gate:
        g = b["gate_js"]
        if g is None or sd.sha256_hex(g) != gate["sha256"] or gate["function_name"] != policy["gate"]["function_name"]:
            raise ApplyRefused("gate code missing or not the planned one")
        sd.check_text(g, "gate.js")
    elif b["gate_js"] is not None:
        raise ApplyRefused("bundle carries gate code the plan doesn't use")
    return plan, summary, b


# --- the apply ------------------------------------------------------------------------------------

def gate_event(case):
    req = {"method": case.get("method", "GET"), "uri": case["uri"], "querystring": {},
           "headers": {k: {"value": v} for k, v in (case.get("headers") or {}).items()},
           "cookies": {k: {"value": v} for k, v in (case.get("cookies") or {}).items()}}
    ev = {"version": "1.0", "context": {"eventType": "viewer-request"}, "viewer": {"ip": GATE_VIEWER_IP},
          "request": req}
    return json.dumps(ev, sort_keys=True).encode()


def gate_case_passes(result, expect):
    """Evaluate one TestFunction result in memory. Never returns or logs any part of it."""
    try:
        if result.get("error"):
            return False
        out = json.loads(result.get("output") or "")
        if not isinstance(out, dict):
            return False
        if expect.get("pass"):
            req = out.get("request")
            ok = isinstance(req, dict) and out.get("response") is None
            if ok and "uri" in expect:
                ok = req.get("uri") == expect["uri"]
            return bool(ok)
        resp = out.get("response")
        if not isinstance(resp, dict) or resp.get("statusCode") != expect["status"]:
            return False
        if "location_prefix" in expect:
            loc = ((resp.get("headers") or {}).get("location") or {}).get("value")
            return isinstance(loc, str) and loc.startswith(expect["location_prefix"])
        return True
    except Exception:  # noqa: BLE001 - any oddity is a failed case, silently
        return False


class Applier:
    def __init__(self, policy, plan, bundle, aws, lfs, workdir, log, sleep=time.sleep, http_get=None,
                 now=time.time):
        self.policy = policy
        self.plan = plan
        self.bundle = bundle
        self.aws = aws
        self.lfs = lfs
        self.workdir = workdir
        self.log = log
        self.sleep = sleep
        self.http_get = http_get
        self.now = now
        self.old_manifest = None
        self.done_puts = {}
        self.done_deletes = set()
        self.lambda_done = None
        self.gate_published = False
        self.wrote = False
        self.lfs_paths = {}

    # 1
    def check_prestate(self):
        pre = self.plan["prestate"]
        pol = self.policy
        listing = self.aws.list_objects(pol["bucket"])
        if {k: v["etag"] for k, v in listing.items()} != pre["listing"]:
            changed = sorted(set(listing) ^ set(pre["listing"]) |
                             {k for k in listing if k in pre["listing"] and listing[k]["etag"] != pre["listing"][k]})
            raise ApplyRefused(f"live S3 changed since the plan ({len(changed)} keys, e.g. {changed[:3]}): plan again")
        mp = os.path.join(self.workdir, "manifest.json")
        try:
            etag = self.aws.get_object(pol["manifest"]["bucket"], pol["manifest"]["key"], mp)
            with open(mp, "rb") as f:
                self.old_manifest = site_plan.parse_manifest(f.read(), pol)
        except site_aws.NotFound:
            etag = None
        except sd.Refused as e:
            raise ApplyRefused(str(e)) from None
        if etag != pre["manifest_etag"]:
            raise ApplyRefused("deployed-manifest.json changed since the plan: plan again")
        gf = self.aws.lambda_get_function(pol["lambda"]["function_name"])
        if gf["revision_id"] != pre["lambda"]["revision_id"] or gf["code_sha256"] != pre["lambda"]["code_sha256"]:
            raise ApplyRefused("the Lambda changed since the plan: plan again")
        gname = pol["gate"]["function_name"]
        live = self.aws.cf_describe_function(gname, "LIVE")
        dev = self.aws.cf_describe_function(gname, "DEVELOPMENT")
        g = pre["gate"]
        if live["etag"] != g["live_etag"] or dev["etag"] != g["dev_etag"] or dev["config"] != g["config"]:
            raise ApplyRefused("the gate changed since the plan: plan again")
        self.log("pre-state: unchanged since the plan")

    # 2
    def fetch_lfs(self):
        objs = {(p["source"]["oid"], p["source"]["size"]) for p in self.plan["puts"] if p["source"]["type"] == "lfs"}
        if not objs:
            return
        d = os.path.join(self.workdir, "lfs")
        os.makedirs(d, exist_ok=True)
        try:
            actions = self.lfs.batch(objs)
            for oid, size in sorted(objs):
                if actions.get(oid) is None:
                    raise ApplyRefused(f"LFS object {oid[:12]} is not in the LFS store")
                path = os.path.join(d, oid)
                self.lfs.fetch(oid, size, path, action=actions[oid])
                got, n = lfs_fetch.sha256_file(path)
                if got != oid or n != size:
                    raise ApplyRefused(f"LFS object {oid[:12]} does not match its oid")
                self.lfs_paths[oid] = path
        except lfs_fetch.LfsError as e:
            raise ApplyRefused(str(e)) from None
        for p in self.plan["puts"]:
            if p["source"]["type"] == "lfs":
                with open(self.lfs_paths[p["source"]["oid"]], "rb") as f:
                    head = f.read(sp.MAGIC_BYTES_NEEDED)
                if not sp.magic_ok(sp.ext_of(p["key"]), head):
                    raise ApplyRefused(f"{p['key']}: LFS object is not a .{sp.ext_of(p['key'])} file (magic bytes)")
        self.log(f"LFS: {len(objs)} object(s) fetched and verified")

    # 3
    def gate_update_and_test(self):
        if not self.plan.get("gate"):
            return None
        gname = self.policy["gate"]["function_name"]
        pre = self.plan["prestate"]["gate"]
        etag = self.aws.cf_update_function(gname, pre["dev_etag"], pre["config"], self.bundle["gate_js"])
        self.log("gate: DEVELOPMENT updated (LIVE untouched)")
        failed = []
        for case in self.policy["gate"]["tests"]:
            try:
                res = self.aws.cf_test_function(gname, etag, gate_event(case))
                ok = gate_case_passes(res, case["expect"])
            except site_aws.AwsError:
                ok = False
            self.log(f"gate test: {case['name']}: {'pass' if ok else 'FAIL'}")
            if not ok:
                failed.append(case["name"])
        if failed:
            raise ApplyRefused(f"gate test(s) failed: {', '.join(failed)}. LIVE is untouched")
        return etag

    # 4
    def lambda_update(self):
        lam = self.plan.get("lambda")
        if not lam:
            return
        name = lam["function_name"]
        zp = os.path.join(self.workdir, "lambda.zip")
        with open(zp, "wb") as f:
            f.write(self.bundle["lambda_zip"])
        self.wrote = True
        res = self.aws.lambda_update_code(name, zp, self.plan["prestate"]["lambda"]["revision_id"])
        deadline = self.now() + 300
        while True:
            cfg = self.aws.lambda_get_configuration(name)
            st = cfg.get("last_update_status")
            if st == "Successful":
                break
            if st == "Failed" or self.now() > deadline:
                raise ApplyFailed("the Lambda update did not finish successfully")
            self.sleep(3)
        if res["code_sha256"] != lam["code_sha256"] or cfg.get("code_sha256") != lam["code_sha256"]:
            raise ApplyFailed("the Lambda's CodeSha256 is not the planned zip's")
        self.lambda_done = lam["code_sha256"]
        self.log("lambda: code updated")

    # 5
    def s3_puts(self):
        bucket = self.policy["bucket"]
        n = 0
        for p in self.plan["puts"]:
            if p["source"]["type"] == "blob":
                path = os.path.join(self.workdir, "blob")
                with open(path, "wb") as f:
                    f.write(self.bundle["blobs"][p["sha256"]])
            else:
                path = self.lfs_paths[p["source"]["oid"]]
            self.wrote = True
            etag = self.aws.put_object(bucket, p["key"], path, p["content_type"], p["cache_control"],
                                       b64(p["sha256"]), if_match=p["if_match"],
                                       if_none_match=p["if_match"] is None)
            self.done_puts[p["key"]] = etag
            n += 1
        if n:
            self.log(f"s3: {n} object(s) uploaded")

    # 6
    def gate_publish(self, etag):
        if not self.plan.get("gate"):
            return
        self.wrote = True
        self.aws.cf_publish_function(self.policy["gate"]["function_name"], etag)
        self.gate_published = True
        self.log("gate: published to LIVE")

    # 7
    def s3_deletes(self):
        for d in self.plan["deletes"]:
            self.wrote = True
            self.aws.delete_object(self.policy["bucket"], d["key"], d["if_match"])
            self.done_deletes.add(d["key"])
        if self.plan["deletes"]:
            self.log(f"s3: {len(self.plan['deletes'])} object(s) deleted")

    # 8
    def manifest_doc(self, sha, plan_run_id):
        pre = self.plan["prestate"]
        old = (self.old_manifest or {}).get("objects", {})
        planned_puts = {p["key"] for p in self.plan["puts"]}
        objs = {}
        for key, d in self.plan["desired"].items():
            if key in self.done_puts:
                objs[key] = {**d, "etag": self.done_puts[key]}
            elif key in planned_puts:
                o = old.get(key)
                if o is not None and o.get("etag") == pre["listing"].get(key):
                    objs[key] = o
            elif key in pre["listing"]:
                objs[key] = {**d, "etag": pre["listing"][key]}
        for dl in self.plan["deletes"]:
            if dl["key"] not in self.done_deletes:
                o = old.get(dl["key"])
                if o is not None and o.get("etag") == pre["listing"].get(dl["key"]):
                    objs[dl["key"]] = o
        if self.lambda_done:
            lam = {"code_sha256": self.lambda_done, "members": self.plan["lambda"]["members"]}
        else:
            lam = {"code_sha256": pre["lambda"]["code_sha256"], "members": self.plan["lambda_members_live"]}
        gate = {"live_sha256": self.plan["gate"]["sha256"] if self.gate_published else pre["gate"]["live_sha256"]}
        return {"schema": site_plan.MANIFEST_SCHEMA, "repository": self.policy["repository"],
                "bucket": self.policy["bucket"], "commit": sha, "plan_run_id": str(plan_run_id or ""),
                "written_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "objects": dict(sorted(objs.items())), "lambda": lam, "gate": gate}

    def write_manifest(self, sha, plan_run_id):
        doc = self.manifest_doc(sha, plan_run_id)
        data = (json.dumps(doc, indent=1, sort_keys=True) + "\n").encode()
        path = os.path.join(self.workdir, "manifest-new.json")
        with open(path, "wb") as f:
            f.write(data)
        m = self.policy["manifest"]
        pre = self.plan["prestate"]["manifest_etag"]
        self.aws.put_object(m["bucket"], m["key"], path, "application/json", "no-store",
                            b64(sd.sha256_hex(data)), if_match=pre, if_none_match=pre is None)
        self.log(f"manifest: written ({len(doc['objects'])} objects)")

    # 9
    def invalidate(self, checks_dir, deadline_s=900):
        keys = sorted(set(self.done_puts) | self.done_deletes)
        if not keys:
            return
        paths = ["/" + urllib.parse.quote(k, safe="/-_.~()'!") for k in keys]
        if "index.html" in keys:
            paths.append("/")
        if len(paths) > INVALIDATION_LIMIT:
            paths = ["/*"]
        result = "failed"
        try:
            dist = self.policy["distribution_id"]
            inv = self.aws.cf_create_invalidation(dist, paths, f"site-{self.plan['policy_sha256'][:8]}-{int(self.now())}")
            end = self.now() + deadline_s
            result = "pending"
            while self.now() < end:
                if self.aws.cf_get_invalidation(dist, inv) == "Completed":
                    result = "ok"
                    break
                self.sleep(20)
        except site_aws.AwsError as e:
            self.log(f"invalidation: {e}")
        self.log(f"invalidation ({len(paths)} path(s)): {result}")
        _check(checks_dir, "invalidation", result)

    def smoke(self, checks_dir):
        sm = self.policy["smoke"]
        if not sm["checks"] or self.http_get is None:
            return
        ok_all = True
        for c in sm["checks"]:
            ok = False
            for attempt in range(6):
                try:
                    status, body = self.http_get(sm["base_url"] + c["path"])
                except Exception:  # noqa: BLE001
                    status, body = None, b""
                ok = status == c["status"]
                if ok and "body_sha256_of_key" in c:
                    want = (self.plan["desired"].get(c["body_sha256_of_key"]) or {}).get("sha256")
                    ok = want is not None and hashlib.sha256(body or b"").hexdigest() == want
                if ok:
                    break
                self.sleep(10)
            self.log(f"smoke {c['path']}: {'ok' if ok else 'FAILED'}")
            ok_all = ok_all and ok
        _check(checks_dir, "smoke", "ok" if ok_all else "failed")

    def run(self, sha, plan_run_id, checks_dir):
        self.check_prestate()
        self.fetch_lfs()
        dev_etag = self.gate_update_and_test()
        try:
            self.lambda_update()
            self.s3_puts()
            self.gate_publish(dev_etag)
            self.s3_deletes()
        except (site_aws.AwsError, ApplyFailed) as e:
            if self.wrote:
                self._salvage_manifest(sha, plan_run_id)
                raise ApplyFailed(str(e)) from None
            raise ApplyRefused(str(e)) from None
        except Exception as e:  # noqa: BLE001 - never leave written keys out of the manifest
            if self.wrote:
                self._salvage_manifest(sha, plan_run_id)
                raise ApplyFailed(f"internal error {e.__class__.__name__}") from None
            raise ApplyRefused(f"internal error {e.__class__.__name__}") from None
        try:
            self.write_manifest(sha, plan_run_id)
        except site_aws.AwsError as e:
            raise ApplyFailed(f"everything was written but the manifest write failed ({e}); the next plan "
                              "shows these keys as LIVE DRIFT") from None

    def _salvage_manifest(self, sha, plan_run_id):
        try:
            self.write_manifest(sha, plan_run_id)
        except site_aws.AwsError as e:
            self.log(f"manifest: NOT written after the failure ({e}); the next plan shows LIVE DRIFT")


def _check(checks_dir, name, value):
    if checks_dir:
        os.makedirs(checks_dir, exist_ok=True)
        with open(os.path.join(checks_dir, name), "w", encoding="ascii") as f:
            f.write(value + "\n")


def http_get_no_redirect(url):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(url, headers={"Cache-Control": "no-cache", "User-Agent": "deploy-workflows-smoke"})
    try:
        with opener.open(req, timeout=20) as r:
            return r.status, r.read(5 * 1024 * 1024)
    except urllib.error.HTTPError as e:
        return e.code, b""


def main(argv=None, aws=None, lfs=None, sleep=time.sleep, http_get=http_get_no_redirect, out=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--summary", required=True)
    ap.add_argument("--bundle-sha256", required=True)
    ap.add_argument("--changes-digest", required=True)
    ap.add_argument("--sha", required=True)
    ap.add_argument("--repository", required=True)
    ap.add_argument("--policy-dir", required=True)
    ap.add_argument("--checks-dir")
    ap.add_argument("--plan-run-id", default="")
    ap.add_argument("--allow-destroy", choices=["true", "false"], default="false")
    ap.add_argument("--expect-region")
    ap.add_argument("--expect-account")
    ap.add_argument("--github-output")
    ap.add_argument("--verify-only", action="store_true")
    args = ap.parse_args(argv)
    log = out or (lambda s: print(s, flush=True))

    def output(k, v):
        if args.github_output:
            with open(args.github_output, "a", encoding="utf-8") as f:
                f.write(f"{k}={v}\n")

    if not re.fullmatch(r"[0-9a-f]{64}", args.changes_digest) or not re.fullmatch(r"[0-9a-f]{40}", args.sha):
        log("::error::bad --changes-digest or --sha")
        return 1
    work = tempfile.mkdtemp(prefix="site-apply-")
    applier = None
    try:
        policy, psha = sp.load_policy(args.policy_dir, args.repository)
        if args.expect_region and args.expect_region != policy["region"]:
            raise ApplyRefused("aws_region input differs from the policy")
        if args.expect_account and args.expect_account != policy["account_id"]:
            raise ApplyRefused("aws_account_id input differs from the policy")
        plan, summary, bundle = verify_inputs(args.bundle, args.summary, args.bundle_sha256, args.changes_digest,
                                              args.sha, args.repository, policy, psha, args.allow_destroy == "true")
        counts = summary["counts"]
        for k in ("add", "change", "destroy"):
            output(k, counts.get(k, 0))
        output("replace", 0)
        log(f"verified: plan for {args.sha[:12]}, {counts['add']} add, {counts['change']} change, "
            f"{counts['destroy']} delete")
        if args.verify_only:
            return 0
        if aws is None:
            aws = site_aws.CliAws(policy["region"])
        if lfs is None:
            lfs = lfs_fetch.LfsClient(args.repository, os.environ.get("GITHUB_TOKEN", ""))
        applier = Applier(policy, plan, bundle, aws, lfs, work, log, sleep=sleep, http_get=http_get)
        applier.run(args.sha, args.plan_run_id, args.checks_dir)
    except (ApplyRefused, sp.PolicyError, sd.Refused) as e:
        log(f"::error::Not applied, nothing written: {e}"[:600])
        output("applied", "false")
        return 1
    except ApplyFailed as e:
        log(f"::error::Deploy FAILED after writes: {e}"[:600])
        output("applied", "false")
        output("partial", "true")
        return 2
    except (site_aws.AwsError, lfs_fetch.LfsError, site_bundle.BundleError, OSError, ValueError, KeyError,
            TypeError) as e:
        wrote = bool(applier and applier.wrote)
        if not isinstance(e, (site_aws.AwsError, lfs_fetch.LfsError, site_bundle.BundleError)):
            e = f"internal error {e.__class__.__name__}"
        log(f"::error::Deploy {'FAILED after writes' if wrote else 'not applied, nothing written'}: {e}"[:600])
        output("applied", "false")
        if wrote:
            output("partial", "true")
        return 2 if wrote else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)
    output("applied", "true")
    applier.invalidate(args.checks_dir)
    applier.smoke(args.checks_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
