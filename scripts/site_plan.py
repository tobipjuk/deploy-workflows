#!/usr/bin/env python3
"""Site plan: read the commit as data, read LIVE with the plan role, diff, write the card.

  site_plan.py --repo-dir DIR --sha SHA --repository OWNER/REPO --policy-dir DIR
               --event push|workflow_dispatch --out-dir DIR [--deploy-enabled true|false]
               [--allow-destroy true|false] [--target NAME] [--meta KEY=VALUE ...]
               [--summary FILE] [--github-output FILE]

Runs in site-plan.yml as `python3 -I` from the deploy-workflows tools directory with the
working directory outside the checkout. No project code runs: the commit is read with
`git ls-tree` / `git cat-file` (raw objects: no filters, hooks, attributes or .lfsconfig),
LFS objects come from GitHub's LFS API through lfs_fetch.py, the Lambda zip is built here from
the policy's member allowlist.

Writes into --out-dir: plan-summary.json (when there are changes) and plan-bundle.tar (when
there are changes and the plan is deployable). Exit codes: 0 ok, 1 refused (error printed),
3 no baseline yet on a push (run plan.yml by hand), 4 destructive without allow_destroy.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

import lfs_fetch  # noqa: E402
import site_aws  # noqa: E402
import site_bundle  # noqa: E402
import site_diff as sd  # noqa: E402
import site_policy as sp  # noqa: E402

SITE_JSON = "deploy/site.json"
MANIFEST_SCHEMA = 1


class NoBaseline(Exception):
    pass


# --- reading the commit -------------------------------------------------------------------------

class GitReader:
    """Raw git objects of one commit. No working-tree reads, so a symlink in the commit can't
    point the plan at a runner file, and no filter or hook of the repo ever runs."""

    def __init__(self, repo_dir, sha):
        self.repo_dir = repo_dir
        self.sha = sha
        self.env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_NO_REPLACE_OBJECTS": "1",
                    "GIT_TERMINAL_PROMPT": "0", "HOME": tempfile.gettempdir(), "LC_ALL": "C"}
        self._proc = None

    def tree(self):
        r = subprocess.run(["git", "-C", self.repo_dir, "ls-tree", "-r", "-z", "--full-tree", self.sha],
                           capture_output=True, env=self.env, check=False)
        if r.returncode != 0:
            raise sd.Refused("cannot list the commit's files")
        out = {}
        for rec in r.stdout.split(b"\0"):
            if not rec:
                continue
            meta, _, path = rec.partition(b"\t")
            mode, typ, oid = meta.decode().split(" ")
            try:
                p = path.decode("utf-8")
            except UnicodeDecodeError:
                p = path.decode("utf-8", "replace")
            out[p] = {"mode": mode, "type": typ, "oid": oid}
        return out

    def read(self, oid, max_bytes=sd.MAX_LIVE_ZIP_UNCOMPRESSED * 3):
        if self._proc is None:
            self._proc = subprocess.Popen(["git", "-C", self.repo_dir, "cat-file", "--batch"],
                                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=self.env)
        self._proc.stdin.write(oid.encode() + b"\n")
        self._proc.stdin.flush()
        header = self._proc.stdout.readline().decode().split()
        if len(header) != 3 or header[1] != "blob":
            raise sd.Refused("a mapped path is not a git blob")
        size = int(header[2])
        if size > max_bytes:
            raise sd.Refused("a source file is too large")
        data = self._proc.stdout.read(size)
        self._proc.stdout.read(1)
        return data

    def close(self):
        if self._proc:
            self._proc.stdin.close()
            self._proc.stdout.close()
            self._proc.wait()
            self._proc = None


def _regular(tree, path, what):
    e = tree.get(path)
    if e is None:
        raise sd.Refused(f"{what} {path} is not in the commit")
    if e["type"] != "blob" or e["mode"] not in ("100644", "100755"):
        raise sd.Refused(f"{what} {path} is not a regular file (symlink or submodule)")
    return e


# --- manifest -------------------------------------------------------------------------------------

def parse_manifest(raw, policy):
    try:
        m = json.loads(raw)
    except ValueError:
        raise sd.Refused("deployed-manifest.json is not JSON: repair it on the Mac") from None
    ok = (isinstance(m, dict) and m.get("schema") == MANIFEST_SCHEMA and m.get("repository") == policy["repository"]
          and m.get("bucket") == policy["bucket"] and isinstance(m.get("objects"), dict))
    if not ok:
        raise sd.Refused("deployed-manifest.json has an unexpected shape: repair it on the Mac")
    for k, v in m["objects"].items():
        sp.check_key(k, "manifest key")
        if not (sp.in_site(policy, k) and isinstance(v, dict) and isinstance(v.get("sha256"), str)
                and isinstance(v.get("etag"), str) and isinstance(v.get("size"), int)):
            raise sd.Refused("deployed-manifest.json has an invalid entry: repair it on the Mac")
    return m


# --- the planner ------------------------------------------------------------------------------------

class Planner:
    def __init__(self, policy, policy_sha256, aws, lfs, git, workdir, event, deploy_enabled, allow_destroy):
        self.policy = policy
        self.policy_sha256 = policy_sha256
        self.aws = aws
        self.lfs = lfs
        self.git = git
        self.workdir = workdir
        self.event = event
        self.deploy_enabled = deploy_enabled
        self.allow_destroy = allow_destroy

    # 1-3: the commit's desired state
    def desired_state(self, tree):
        e = _regular(tree, SITE_JSON, "deploy/site.json")
        try:
            site = json.loads(self.git.read(e["oid"], 1024 * 1024))
        except ValueError:
            raise sd.Refused("deploy/site.json is not JSON") from None
        sp.validate_site_json(site, self.policy)
        mapping = sp.expand_mappings(site, self.policy, tree)
        desired, texts, bytes_by_sha, lfs_objs = {}, {}, {}, {}
        browser_srcs = self.policy["browser_code_sources"]
        for key, (src, cache) in sorted(mapping.items()):
            ent = _regular(tree, src, "source")
            cls, ctype = sp.classify(key, src)
            ext = sp.ext_of(key).lower()
            if ext in sp.BROWSER_RUN_EXTS and not any(src.startswith(p) for p in browser_srcs):
                raise sd.Refused(f"{src}: a type the browser runs may only come from {browser_srcs}")
            data = self.git.read(ent["oid"])
            d = {"class": cls, "content_type": ctype, "cache": cache, "cache_control": sp.CACHE_CLASSES[cache],
                 "source_path": src}
            if cls in ("code", "data"):
                if lfs_fetch.looks_like_pointer(data):
                    raise sd.Refused(f"{src} is an LFS pointer, but {key} is served as text: text and code "
                                     "must be plain git (round 4 H2)")
                texts[key] = sd.check_text(data, src)
                d.update(sha256=sd.sha256_hex(data), size=len(data), source={"type": "blob"})
                bytes_by_sha[d["sha256"]] = data
            else:
                try:
                    ptr = lfs_fetch.parse_pointer(data)
                except lfs_fetch.LfsError as err:
                    raise sd.Refused(f"{src}: {err}") from None
                if ptr:
                    oid, size = ptr
                    d.update(sha256=oid, size=size, source={"type": "lfs", "oid": oid, "size": size})
                    lfs_objs[key] = (oid, size)
                else:
                    if not sp.magic_ok(ext, data[:sp.MAGIC_BYTES_NEEDED]):
                        raise sd.Refused(f"{src}: content is not a .{ext} file (magic bytes)")
                    d.update(sha256=sd.sha256_hex(data), size=len(data), source={"type": "blob"})
                    bytes_by_sha[d["sha256"]] = data
            desired[key] = d
        return site, desired, texts, bytes_by_sha, lfs_objs

    # Lambda members from the allowlist (round 3 H2, round 4 L2)
    def lambda_members(self, tree):
        lam = self.policy["lambda"]
        d = lam["source_dir"].rstrip("/") + "/"
        allowed, ignore = set(lam["members"]), lam.get("ignore", [])
        import fnmatch
        for path in sorted(tree):
            if not path.startswith(d) or not path.endswith(".py"):
                continue
            rel = path[len(d):]
            if rel in allowed:
                continue
            if "/" not in rel and any(fnmatch.fnmatchcase(rel, g) for g in ignore):
                continue
            raise sd.Refused(f"{path!r}: new or renamed Lambda member, not in the policy's allowlist "
                             "(add it with a reviewed deploy-workflows PR)")
        members = {}
        for name in sorted(allowed):
            e = _regular(tree, d + name, "Lambda member")
            data = self.git.read(e["oid"], sp.MAX_LAMBDA_MEMBER_BYTES)
            if len(data) > sp.MAX_LAMBDA_MEMBER_BYTES:
                raise sd.Refused(f"{d + name} is larger than 256 KB")
            sd.check_text(data, d + name)
            members[name] = data
        return members

    def gate_code(self, tree):
        g = self.policy["gate"]["source"]
        e = _regular(tree, g, "gate source")
        data = self.git.read(e["oid"], sp.MAX_GATE_BYTES)
        if len(data) > sp.MAX_GATE_BYTES:
            raise sd.Refused(f"{g} is larger than the CloudFront Functions limit")
        sd.check_text(data, g)
        return data

    # 4: live state
    def live_state(self, desired):
        pol = self.policy
        listing = self.aws.list_objects(pol["bucket"])
        mpath = os.path.join(self.workdir, "manifest.json")
        try:
            metag = self.aws.get_object(pol["manifest"]["bucket"], pol["manifest"]["key"], mpath)
            with open(mpath, "rb") as f:
                manifest = parse_manifest(f.read(), pol)
        except site_aws.NotFound:
            metag, manifest = None, None
        live_text, live_meta = {}, {}
        for key, d in desired.items():
            if d["class"] in ("code", "data") and key in listing:
                p = os.path.join(self.workdir, "live-text")
                live_meta[key] = self.aws.get_object_meta(pol["bucket"], key, p)
                with open(p, "rb") as f:
                    live_text[key] = f.read()
        fn = pol["lambda"]["function_name"]
        gf = self.aws.lambda_get_function(fn)
        if gf.get("repository_type") not in (None, "S3"):
            raise sd.Refused("the Lambda is not a zip function")
        zpath = os.path.join(self.workdir, "live.zip")
        self.aws.download(gf["location"], zpath)
        with open(zpath, "rb") as f:
            zdata = f.read()
        if sd.b64_of_hex(sd.sha256_hex(zdata)) != gf["code_sha256"]:
            raise sd.Refused("the downloaded Lambda code does not match its CodeSha256")
        config = self.aws.lambda_get_configuration(fn)
        gname = pol["gate"]["function_name"]
        live_desc = self.aws.cf_describe_function(gname, "LIVE")
        dev_desc = self.aws.cf_describe_function(gname, "DEVELOPMENT")
        live_code, _ = self.aws.cf_get_function(gname, "LIVE")
        dev_code, _ = self.aws.cf_get_function(gname, "DEVELOPMENT")
        return {
            "listing": listing, "manifest": manifest, "manifest_etag": metag, "live_text": live_text,
            "live_meta": live_meta,
            "lambda": {"revision_id": gf["revision_id"], "code_sha256": gf["code_sha256"],
                       "members": sd.read_zip(zdata), "config": config},
            "gate": {"live_etag": live_desc["etag"], "dev_etag": dev_desc["etag"], "config": dev_desc["config"],
                     "live_config": live_desc["config"], "live_code": live_code, "dev_code": dev_code},
        }

    def run(self):
        tree = self.git.tree()
        site, desired, texts, bytes_by_sha, lfs_objs = self.desired_state(tree)
        new_members = self.lambda_members(tree)
        gate_new = self.gate_code(tree)
        live = self.live_state(desired)
        adoption = live["manifest"] is None
        if adoption and self.event != "workflow_dispatch":
            raise NoBaseline()
        pol = self.policy
        manifest_objs = None if adoption else live["manifest"]["objects"]

        # LFS objects: existence first (one batch), verified fetch where the plan needs bytes.
        verified_heads = {}
        lfs_dir = os.path.join(self.workdir, "lfs")
        os.makedirs(lfs_dir, exist_ok=True)
        actions = self.lfs.batch(set(lfs_objs.values())) if lfs_objs else {}
        missing = sorted({oid for oid, a in actions.items() if a is None})
        if missing:
            keys = sorted(k for k, (o, _) in lfs_objs.items() if o in missing)
            raise sd.Refused(f"{len(missing)} LFS object(s) are not in GitHub's LFS store, e.g. {keys[:3]}")

        def fetch_verified(key):
            oid, size = lfs_objs[key]
            p = os.path.join(lfs_dir, oid)
            if not os.path.exists(p):
                try:
                    self.lfs.fetch(oid, size, p, action=actions.get(oid))
                except lfs_fetch.LfsError as err:
                    raise sd.Refused(f"{desired[key]['source_path']}: {err}") from None
            with open(p, "rb") as f:
                verified_heads[key] = f.read(sp.MAGIC_BYTES_NEEDED)
            return p

        def binary_match(key):  # adoption only: by live ETag (MD5 / multipart), binary keys only
            d, lv = desired[key], live["listing"][key]
            if d["source"]["type"] == "blob":
                whole, parts = sd.md5_info_bytes(bytes_by_sha[d["sha256"]])
            else:
                p = fetch_verified(key)
                whole, parts = sd.md5_info_file(p)
                os.unlink(p)
            return sd.etag_equal(lv["etag"], whole, parts)

        if adoption:
            # Binary keys can only be adopted if their metadata is the desired one too: HEAD every
            # live binary key of the right size (in parallel; adoption runs about once).
            heads = [k for k, d in desired.items() if d["class"] == "binary" and k in live["listing"]
                     and live["listing"][k]["size"] == d["size"]]
            if heads:
                from concurrent.futures import ThreadPoolExecutor
                with ThreadPoolExecutor(max_workers=8) as ex:
                    for k, meta in zip(heads, ex.map(lambda k: self.aws.head_object(pol["bucket"], k), heads)):
                        live["live_meta"][k] = meta
        s3 = sd.compute_s3(pol, desired, live["listing"], manifest_objs, live["live_text"], binary_match, adoption,
                           live["live_meta"])
        unverified = []
        for put in s3["puts"]:
            key = put["key"]
            if key not in lfs_objs:
                continue
            ext = sp.ext_of(key)
            if key not in verified_heads:
                if adoption:
                    oid, size = lfs_objs[key]
                    try:
                        head = self.lfs.head(oid, size, sp.MAGIC_BYTES_NEEDED, action=actions.get(oid))
                    except lfs_fetch.LfsError:
                        fetch_verified(key)
                        head = verified_heads[key]
                    else:
                        unverified.append(key)
                else:
                    p = fetch_verified(key)
                    os.unlink(p)
                    head = verified_heads[key]
            else:
                head = verified_heads[key]
            if not sp.magic_ok(ext, head):
                raise sd.Refused(f"{desired[key]['source_path']}: LFS object is not a .{ext} file (magic bytes)")
        shutil.rmtree(lfs_dir, ignore_errors=True)

        attention, diffs, reasons = [], [], []
        drift = list(s3["drift"])

        # Cache-Control / Content-Type of code and root keys (Guardian on f944888, M1)
        for put in s3["puts"]:
            key = put["key"]
            d = desired[key]
            if not ("/" not in key or d["class"] == "code"):
                continue
            old_cc, old_ct = put["live_cache_control"], put["live_content_type"]
            changed = put["action"] == "update" and (old_cc != d["cache_control"] or old_ct != d["content_type"])
            if changed or (put["action"] == "create" and d["cache"] in sd.LONG_CACHE):
                before = f"{old_ct or '?'} | {old_cc or '?'}" if put["action"] == "update" else None
                attention.append(sd._att(f"s3:{key}", "Cache-Control or Content-Type", put["action"], key,
                                         before, f"{d['content_type']} | {d['cache_control']}"))

        # S3 text diffs: old = live bytes
        for put in s3["puts"]:
            key = put["key"]
            d = desired[key]
            if d["class"] not in ("code", "data") or put["reason"] == "metadata":
                continue
            old = None
            if key in live["live_text"]:
                old = sd.text_or_none(live["live_text"][key])
                if old is None:
                    old = f"(live object is not UTF-8 text: {len(live['live_text'][key])} bytes)"
            if max(len(old or ""), len(texts[key])) > sd.MAX_TEXT_DIFF_INPUT:
                # Too large to diff on a card: a code file can't be shown in full (not deployable),
                # a data file is listed without its diff.
                diffs.append({"address": f"s3:{key}", "file": key, "kind": d["class"], "added": 0, "removed": 0,
                              "invisible": 0, "too_large": True,
                              "text": f"--- live/{key}\n+++ commit/{key}\n(too large to diff: {d['size']} bytes, "
                                      f"sha256 {d['sha256']})\n"})
                continue
            text, a, r, inv = sd.text_diff(old, texts[key], f"live/{key}", f"commit/{key}")
            if adoption and d["class"] == "code":
                inv = max(inv, sd.count_invisible(texts[key]))
            diffs.append({"address": f"s3:{key}", "file": key, "kind": d["class"], "text": text,
                          "added": a, "removed": r, "invisible": inv})
            if key == "pin.html":
                attention.append(sd._att("s3:pin.html", "PIN page", put["action"], None, None, f"+{a} -{r} lines"))
            elif key == "sw.js":
                attention.append(sd._att("s3:sw.js", "Service worker", put["action"], None, None, f"+{a} -{r} lines"))
        if adoption:
            for key in s3["adopted"]:
                if desired[key]["class"] == "code":
                    n = sd.count_invisible(texts[key])
                    if n:
                        attention.append(sd._att(f"s3:{key}", "Invisible or bidi characters", "adopt", key, None,
                                                 f"{n} in the adopted file"))

        # Lambda
        man_lambda = None if adoption else live["manifest"].get("lambda")
        lc = sd.lambda_changes(pol, new_members, live["lambda"]["members"], man_lambda)
        diffs += lc["diffs"]
        attention += lc["attention"]
        drift += lc["drift"]
        zip_bytes = sd.build_zip(new_members) if lc["changed"] else None
        if lc["changed"]:
            a = sum(x["added"] for x in lc["diffs"])
            r = sum(x["removed"] for x in lc["diffs"])
            attention.append(sd._att(f"lambda:{pol['lambda']['function_name']}", "Lambda code", "update",
                                     None, None, f"{len(lc['diffs'])} file(s), +{a} -{r} lines"))

        # Gate
        gname = pol["gate"]["function_name"]
        gaddr = f"cloudfront-function:{gname}"
        g = live["gate"]
        gate_changed = gate_new != g["live_code"]
        if g["dev_code"] != g["live_code"]:
            dev_s = sd.text_or_none(g["dev_code"]) or "(not text)"
            live_s = sd.text_or_none(g["live_code"]) or "(not text)"
            t, a, r, inv = sd.text_diff(live_s, dev_s, "LIVE/gate.js", "DEVELOPMENT/gate.js")
            diffs.append({"address": gaddr, "file": "DEVELOPMENT stage (not live)", "kind": "code", "text": t,
                          "added": a, "removed": r, "invisible": inv})
            attention.append(sd._att(gaddr, "Gate DEVELOPMENT differs from LIVE", "info", None, None,
                                     "leftover DEVELOPMENT code (a stopped apply or a change by hand)"))
        if g["config"] != g["live_config"]:
            reasons.append("the gate's DEVELOPMENT config differs from LIVE: fix it on the Mac")
        if gate_changed:
            live_s = sd.text_or_none(g["live_code"])
            if live_s is None:
                live_s = f"(live gate code is not text: {len(g['live_code'])} bytes)"
            t, a, r, inv = sd.text_diff(live_s, gate_new.decode("utf-8"), "LIVE/gate.js",
                                        f"commit/{pol['gate']['source']}")
            diffs.append({"address": gaddr, "file": pol["gate"]["source"], "kind": "code", "text": t,
                          "added": a, "removed": r, "invisible": inv})
            attention.append(sd._att(gaddr, "Gate code", "update", None, None, f"+{a} -{r} lines"))
        if not adoption:
            mg = live["manifest"].get("gate") or {}
            if mg.get("live_sha256") and mg["live_sha256"] != sd.sha256_hex(g["live_code"]):
                drift.append({"key": gaddr, "what": "live gate code differs from the last pipeline deploy"})

        # Settings: never changed by the pipeline; a mismatch means "change it on the Mac first".
        bad = sd.check_settings(site["lambda_settings"], live["lambda"]["config"])
        for b in bad:
            attention.append(sd._att(f"lambda:{pol['lambda']['function_name']}", "Settings mismatch", "info",
                                     b["field"], json.dumps(b["live"])[:100], json.dumps(b["expected"])[:100]))
        if bad:
            reasons.append("live Lambda settings differ from deploy/site.json: change them on the Mac first")
        env_err = sd.env_names_error(live["lambda"]["config"])
        unverified = ["env_names"] if env_err else []
        if env_err:
            attention.append(sd._att(f"lambda:{pol['lambda']['function_name']}", "Lambda env var names unreadable",
                                     "info", "env_names", None,
                                     f"env var names unreadable (KMS denied: {env_err}): not compared with "
                                     "deploy/site.json"))

        # Deletes, drift, outside-SITE objects
        for dl in s3["deletes"]:
            k = dl["key"]
            if "/" not in k or sd.is_code_key(k):
                attention.append(sd._att(f"s3:{k}", "Delete of a root or code key", "delete", k))
        if s3["outside"]:
            reasons.append(f"{len(s3['outside'])} live object(s) outside SITE: clean up on the Mac")
        if drift:
            if len(drift) <= 20:
                for x in drift:
                    attention.append(sd._att(x["key"] if ":" in x["key"] else f"s3:{x['key']}", "LIVE DRIFT",
                                             "info", None, None, x["what"]))
            else:
                attention.append(sd._att("s3:*", "LIVE DRIFT", "info", None, None,
                                         f"{len(drift)} objects (full list in the attachment)"))
        for dfx in diffs:
            if dfx["kind"] == "code":
                n = sd.count_nonascii_letters_added(dfx["text"])
                if n:
                    attention.append(sd._att(dfx["address"], "Non-ASCII letters or combining marks in code", "update",
                                             dfx["file"], None, f"{n} in added lines (possible homoglyphs)"))
            if dfx["invisible"] and dfx["kind"] in ("code", "data"):
                attention.append(sd._att(dfx["address"], "Invisible or bidi characters", "update", dfx["file"],
                                         None, f"{dfx['invisible']} in added lines (shown as <U+XXXX>)"))
        if adoption:
            attention.append(sd._att(f"manifest:{pol['manifest']['key']}", "BASELINE ADOPTION", "create", None, None,
                                     f"first pipeline deploy: {len(s3['adopted'])} live objects adopted, "
                                     f"{len(s3['puts'])} uploads, {len(s3['deletes'])} deletes"
                                     + (f", {len(unverified)} LFS objects magic-checked unverified "
                                        "(the apply verifies them in full)" if unverified else "")))

        manifest_action = None
        if s3["puts"] or s3["deletes"] or lc["changed"] or gate_changed or s3["adopted"] or drift or adoption:
            manifest_action = "create" if adoption else "update"
        destructive = len(s3["deletes"]) > pol.get("max_deletes", 20)

        kept, code_complete, data_truncated = sd.fit_diffs(diffs)
        if not code_complete:
            reasons.append("a code diff is too large to show in full on the card: not deployable")
        attention, att_trunc = sd.cap_attention(sd.order_attention(attention))

        prestate = {
            "listing": {k: v["etag"] for k, v in sorted(live["listing"].items())},
            "last_modified": {k: v.get("last_modified", "") for k, v in sorted(live["listing"].items())},
            "manifest_etag": live["manifest_etag"],
            "lambda": {"revision_id": live["lambda"]["revision_id"], "code_sha256": live["lambda"]["code_sha256"]},
            "gate": {"live_etag": g["live_etag"], "dev_etag": g["dev_etag"], "config": g["config"],
                     "live_sha256": sd.sha256_hex(g["live_code"]), "dev_sha256": sd.sha256_hex(g["dev_code"])},
        }
        put_set = {p["key"]: p for p in s3["puts"]}
        plan = {
            "schema": 1, "kind": "site", "repository": pol["repository"], "target": pol["target"],
            "policy_sha256": self.policy_sha256, "adoption": adoption,
            "bucket": pol["bucket"], "manifest": pol["manifest"],
            "prestate": prestate,
            "puts": [{"key": k, "action": p["action"], "if_match": p["if_match"], "sha256": desired[k]["sha256"],
                      "size": desired[k]["size"], "content_type": desired[k]["content_type"],
                      "cache_control": desired[k]["cache_control"], "class": desired[k]["class"],
                      "reason": p["reason"], "source": desired[k]["source"]} for k, p in sorted(put_set.items())],
            "deletes": s3["deletes"],
            "adopted": s3["adopted"],
            "desired": {k: {"sha256": d["sha256"], "size": d["size"], "content_type": d["content_type"],
                            "cache": d["cache"]} for k, d in sorted(desired.items())},
            "lambda": None if not lc["changed"] else {
                "function_name": pol["lambda"]["function_name"], "zip_sha256": sd.sha256_hex(zip_bytes),
                "code_sha256": sd.b64_of_hex(sd.sha256_hex(zip_bytes)),
                "members": {n: sd.sha256_hex(b) for n, b in new_members.items()}},
            "lambda_members_live": {n: sd.sha256_hex(b) for n, b in live["lambda"]["members"].items()},
            "gate": None if not gate_changed else {"function_name": gname, "sha256": sd.sha256_hex(gate_new)},
            "manifest_action": manifest_action,
            "destructive": destructive,
        }
        changes = sd.changes_from_plan(plan)
        counts = sd.counts_from_changes(changes)
        prefixes = {}
        for c in changes:
            if c["address"].startswith("s3:"):
                slot = prefixes.setdefault(sd.prefix_of(pol, c["address"][3:]), {"create": 0, "update": 0, "delete": 0})
                slot[c["actions"][0]] += 1
        blobs = {p["sha256"]: bytes_by_sha[p["sha256"]] for p in plan["puts"] if p["source"]["type"] == "blob"}
        return {
            "plan": plan, "blobs": blobs, "zip": zip_bytes, "gate": gate_new if gate_changed else None,
            "changes": changes, "counts": counts, "destructive": destructive, "attention": attention,
            "attention_truncated": att_trunc, "diffs": kept, "code_complete": code_complete,
            "data_truncated": data_truncated, "reasons": reasons, "drift": drift, "prefixes": prefixes,
            "adoption": adoption, "settings": {"mismatch": bad, "unverified": unverified},
            "has_changes": bool(changes),
        }


def summary_doc(res, meta, deploy_enabled):
    reasons = list(res["reasons"])
    if not deploy_enabled:
        reasons.append("no deploy role for this project (AWS_DEPLOY_ROLE_ARN unset)")
    doc = {
        "schema": 1, "kind": "site", **meta,
        "counts": res["counts"], "has_changes": res["has_changes"], "destructive": res["destructive"],
        "deployable": not reasons, "flags": [f"{res['counts']['destroy']} deletes: more than the policy's "
                                             "limit, treated as destructive"] if res["destructive"] else [],
        "blocked": [], "changes": res["changes"], "changes_digest": sd.changes_digest(res["changes"]),
        "diff": [], "diff_truncated": (not res["code_complete"]) or res["data_truncated"],
        "diff_complete": res["code_complete"],
        "attention": res["attention"], "attention_truncated": res["attention_truncated"],
        "bundle_sha256": None,
        "site": {
            "adoption": res["adoption"], "not_deployable": reasons, "prefixes": res["prefixes"],
            "drift": res["drift"], "diffs": res["diffs"], "data_diffs_truncated": res["data_truncated"],
            "settings_mismatch": res["settings"]["mismatch"],
            "settings_unverified": res["settings"]["unverified"],
            "plan_sha256": hashlib.sha256(site_bundle.canonical_json(res["plan"])).hexdigest(),
        },
    }
    raw = json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False).encode("utf-8")
    if len(raw) > sd.MAX_SUMMARY_BYTES:
        # Keep code diffs; drop data diffs, then the drift list, before giving up.
        doc["site"]["diffs"] = [d for d in doc["site"]["diffs"] if d["kind"] == "code"]
        doc["site"]["data_diffs_truncated"] = True
        doc["diff_truncated"] = True
        raw = json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False).encode("utf-8")
        if len(raw) > sd.MAX_SUMMARY_BYTES:
            doc["site"]["drift"] = doc["site"]["drift"][:200]
            raw = json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False).encode("utf-8")
        if len(raw) > sd.MAX_SUMMARY_BYTES:
            doc["site"]["not_deployable"].append("the plan summary is too large for the card: split the change")
            doc["deployable"] = False
            doc["site"]["diffs"] = []
            doc["diff_complete"] = False
    doc["deployable"] = not doc["site"]["not_deployable"]
    return doc


def markdown(doc):
    c = doc["counts"]
    s = doc["site"]
    out = ["### Site plan" + (" (BASELINE ADOPTION)" if s["adoption"] else ""), "",
           f"**{c['add']} to add, {c['change']} to change, {c['destroy']} to delete**", "",
           f"Changes digest: `{doc['changes_digest']}`", ""]
    for r in s["not_deployable"]:
        out.append(f"> **Not deployable:** {r}")
    if s["not_deployable"]:
        out.append("")
    if doc["attention"]:
        out += [f"**Needs attention ({len(doc['attention'])}):**", ""]
        for a in doc["attention"]:
            detail = " ".join(str(x) for x in (a["path"], a["before"], a["after"]) if x)
            out.append(f"- {a['label']} ({a['action']}) `{a['address']}` {detail}")
        out.append("")
    if s["prefixes"]:
        out += ["| prefix | create | update | delete |", "|---|---|---|---|"]
        for p, v in sorted(s["prefixes"].items()):
            out.append(f"| `{p}` | {v['create']} | {v['update']} | {v['delete']} |")
        out.append("")
    if s["diffs"]:
        out += ["<details><summary>Diffs (code first)</summary>", "", "```diff"]
        body = "".join(d["text"] for d in s["diffs"])
        out += [body[:60000].replace("```", "`​``"), "```", "</details>", ""]
    return "\n".join(out) + "\n"


def parse_meta(items):
    import plan_report
    return plan_report.parse_meta(items)


def main(argv=None, aws=None, lfs=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-dir", required=True)
    ap.add_argument("--sha", required=True)
    ap.add_argument("--repository", required=True)
    ap.add_argument("--policy-dir", required=True)
    ap.add_argument("--event", required=True, choices=["push", "workflow_dispatch"])
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--target")
    ap.add_argument("--expect-region")
    ap.add_argument("--expect-account")
    ap.add_argument("--deploy-enabled", choices=["true", "false"], default="false")
    ap.add_argument("--allow-destroy", choices=["true", "false"], default="false")
    ap.add_argument("--meta", action="append", default=[])
    ap.add_argument("--summary")
    ap.add_argument("--github-output")
    args = ap.parse_args(argv)

    def out(k, v):
        if args.github_output:
            with open(args.github_output, "a", encoding="utf-8") as f:
                f.write(f"{k}={v}\n")

    git = None
    work = tempfile.mkdtemp(prefix="site-plan-")
    try:
        policy, psha = sp.load_policy(args.policy_dir, args.repository)
        if args.target is not None and args.target != policy["target"]:
            raise sp.PolicyError(f"target input {args.target!r} differs from the policy's {policy['target']!r}")
        if args.expect_region and args.expect_region != policy["region"]:
            raise sp.PolicyError("aws_region input differs from the policy")
        if args.expect_account and args.expect_account != policy["account_id"]:
            raise sp.PolicyError("aws_account_id input differs from the policy")
        if not __import__("re").fullmatch(r"[0-9a-f]{40}", args.sha):
            raise sp.PolicyError("bad --sha")
        if aws is None:
            aws = site_aws.CliAws(policy["region"])
        if lfs is None:
            lfs = lfs_fetch.LfsClient(args.repository, os.environ.get("GITHUB_TOKEN", ""))
        git = GitReader(args.repo_dir, args.sha)
        planner = Planner(policy, psha, aws, lfs, git, work, args.event, args.deploy_enabled == "true",
                          args.allow_destroy == "true")
        res = planner.run()
    except NoBaseline:
        print("::error::No baseline yet (no deployed-manifest.json): a push plan stops here. "
              "Run plan.yml by hand (workflow_dispatch) to make the adoption plan.", file=sys.stderr)
        out("no_baseline", "true")
        return 3
    except (sp.PolicyError, sd.Refused, lfs_fetch.LfsError, site_aws.AwsError, site_bundle.BundleError) as e:
        msg = sd.one_line(str(e))[:600]
        print(f"::error::Site plan refused: {msg}", file=sys.stderr)
        if args.summary:
            with open(args.summary, "a", encoding="utf-8") as f:
                f.write(f"### Site plan refused\n\n{msg}\n")
        return 1
    finally:
        if git:
            git.close()
        shutil.rmtree(work, ignore_errors=True)

    meta = parse_meta(args.meta)
    meta.setdefault("repo", args.repository)
    meta.setdefault("sha", args.sha)
    meta["target"] = policy["target"]
    meta["allow_destroy_requested"] = args.allow_destroy == "true"
    doc = summary_doc(res, meta, args.deploy_enabled == "true")
    os.makedirs(args.out_dir, exist_ok=True)
    out("has_changes", str(res["has_changes"]).lower())
    out("destructive", str(res["destructive"]).lower())
    out("deployable", str(doc["deployable"]).lower())
    out("digest", doc["changes_digest"])
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as f:
            f.write(markdown(doc) if res["has_changes"] else "### Site plan\n\nNo changes. Nothing to deploy.\n")
    print(f"site plan: {doc['counts']['add']} add, {doc['counts']['change']} change, "
          f"{doc['counts']['destroy']} delete, deployable={str(doc['deployable']).lower()}, "
          f"adoption={str(res['adoption']).lower()}, digest={doc['changes_digest']}")
    if not res["has_changes"]:
        return 0
    if res["destructive"] and args.allow_destroy != "true":
        print("::error::The plan deletes more objects than the policy's limit. Run plan.yml by hand with "
              "allow_destroy = true if intended.", file=sys.stderr)
        return 4
    if doc["deployable"]:
        bsha = site_bundle.create(os.path.join(args.out_dir, "plan-bundle.tar"), args.sha, res["plan"],
                                  res["blobs"], res["zip"], res["gate"])
        doc["bundle_sha256"] = bsha
        doc["bundle_artifact"] = "plan-bundle"
        out("bundle_sha256", bsha)
    with open(os.path.join(args.out_dir, "plan-summary.json"), "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, sort_keys=True, ensure_ascii=False)
        f.write("\n")
    if doc["deployable"]:
        with open(os.path.join(args.out_dir, "plan-summary.json"), "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()
        out("summary_sha256", h)
    return 0


if __name__ == "__main__":
    sys.exit(main())
