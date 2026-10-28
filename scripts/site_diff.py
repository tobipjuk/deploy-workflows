#!/usr/bin/env python3
"""Trusted diff for the site pipeline: what the commit wants vs what is LIVE in AWS. Stdlib only.

Pure functions, no I/O: site_plan.py reads the commit and AWS and calls these; tests call them
directly with fixtures. Design: lego-mindstorms docs/deploy-pipeline-design.md (rev. 3).

The card can't lie because every "old" side comes from AWS (S3 bytes for text keys, the
Lambda's live zip, the gate's LIVE stage), never from a record the box can write; the
manifest (written only by the deploy role) is cross-checked against live ETags, and any
mismatch is LIVE DRIFT. Every changed line of code goes into plan-summary.json (attested), and
a code diff that doesn't fit makes the plan not deployable.
"""
import difflib
import hashlib
import base64
import io
import unicodedata
import zipfile

import site_policy as sp

ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)
MULTIPART_CHUNK = 8 * 1024 * 1024  # aws s3 cp/sync default part size (round 4 M3: binary keys only)
MAX_LIVE_ZIP_UNCOMPRESSED = 100 * 1024 * 1024
MAX_SUMMARY_BYTES = 1_800_000      # Orion refuses a plan-summary.json > 2 MB
MAX_CODE_DIFF_BYTES = 1_200_000
MAX_ATTENTION = 60
MAX_TEXT_DIFF_INPUT = 1_000_000  # characters per side; larger text files aren't diffed
DIFF_CONTEXT = 3

# Characters that render as nothing or reorder text. Escaped in every diff line and counted.
_EXTRA_INVISIBLE = {0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800, 0x180E, 0x034F, 0x17B4, 0x17B5}


class Refused(ValueError):
    """The plan is refused (the job fails, nothing is offered)."""


# --- text --------------------------------------------------------------------------------------

def check_text(data, what):
    """Decode a text file: UTF-8, no NUL, no control characters except tab, LF and CR."""
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused(f"{what} is not UTF-8 text") from None
    for ch in s:
        o = ord(ch)
        if (o < 0x20 and ch not in "\t\n\r") or o == 0x7F:
            raise Refused(f"{what} contains control character U+{o:04X}")
    return s


def is_invisible(ch):
    if ch in ("\t", "\n", " "):
        return False
    o = ord(ch)
    if o in _EXTRA_INVISIBLE or 0xE0000 <= o <= 0xE007F:
        return True
    cat = unicodedata.category(ch)
    return cat in ("Cc", "Cf", "Co", "Cn", "Cs", "Zl", "Zp") or (cat == "Zs" and ch != " ")


def escape_line(s):
    """Replace invisible and bidi characters by <U+XXXX>. Returns (escaped, count)."""
    out, n = [], 0
    for ch in s:
        if is_invisible(ch):
            out.append(f"<U+{ord(ch):04X}>")
            n += 1
        else:
            out.append(ch)
    return "".join(out), n


def text_diff(old, new, old_label, new_label):
    """Unified diff of two strings with invisible characters escaped.

    Returns (text, added, removed, invisible_in_added). old None = new file.
    Lines are split on LF only, so a CR or a missing final newline shows as a change.
    """
    a = [] if old is None else old.split("\n")
    b = new.split("\n")
    added = removed = invis = 0
    lines = []
    # unified_diff emits exactly two header lines (--- / +++) and then hunks: every later line
    # is classified by its first character only, so content that starts with "++" or "--"
    # (e.g. "++i;") still counts as an added or removed line (Guardian on fff80e5, L1).
    for i, ln in enumerate(difflib.unified_diff(a, b, fromfile="/dev/null" if old is None else old_label,
                                                tofile=new_label, n=DIFF_CONTEXT, lineterm="")):
        if i >= 2 and ln.startswith("+"):
            added += 1
            esc, c = escape_line(ln)
            invis += c
        elif i >= 2 and ln.startswith("-"):
            removed += 1
            esc, _ = escape_line(ln)
        else:
            esc, _ = escape_line(ln)
        lines.append(esc)
    return "\n".join(lines) + ("\n" if lines else ""), added, removed, invis


def safe_key(key):
    """A live key as shown on the card: invisible/bidi characters (also U+2028) as <U+XXXX>,
    then any control character escaped (Guardian on e90b777, 4)."""
    return one_line(escape_line(key)[0])


def one_line(s):
    """Escape control characters so a message can't start a new line (and with it a GitHub
    workflow command such as ::add-mask:: or ::stop-commands::) in the log or the summary."""
    return "".join(ch if ch >= " " and ch != "\x7f" else f"\\x{ord(ch):02x}" for ch in s)


def count_nonascii_letters_added(diff_text):
    """Letters outside ASCII and combining marks in a diff's added lines (homoglyph hint)."""
    n = 0
    lines = diff_text.split("\n")
    # Skip only the two header lines text_diff starts with; an added line whose content starts
    # with "++" is still an added line (Guardian on fff80e5, L1).
    if len(lines) >= 2 and lines[0].startswith("--- ") and lines[1].startswith("+++ "):
        lines = lines[2:]
    for ln in lines:
        if ln.startswith("+"):
            for ch in ln:
                if ord(ch) > 127 and unicodedata.category(ch)[0] in ("L", "M"):
                    n += 1
    return n


# Never dropped by the cap: what can't be read anywhere else on the card (Guardian L4; the two
# summary entries added on fff80e5, Guardian on e90b777, 3).
NEVER_DROPPED = ("Invisible or bidi characters", "Data files without a diff", "Lambda env var names unreadable")


def cap_attention(items):
    """At most MAX_ATTENTION entries; NEVER_DROPPED entries are never dropped (Guardian L4)."""
    if len(items) <= MAX_ATTENTION:
        return items, False
    keep_always = [a for a in items if a["label"] in NEVER_DROPPED]
    rest = [a for a in items if a["label"] not in NEVER_DROPPED]
    room = max(MAX_ATTENTION - 1 - len(keep_always), 0)
    dropped = len(rest) - room
    kept = order_attention(keep_always + rest[:room])
    return kept + [_att("*", "More", "info", None, None, f"{dropped} more (full list in the attachment)")], True


def count_invisible(s):
    return sum(1 for ch in s if is_invisible(ch))


# --- hashes and ETags --------------------------------------------------------------------------

def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def b64_of_hex(h):
    return base64.b64encode(bytes.fromhex(h)).decode("ascii")


def md5_info_bytes(data):
    """(whole md5 hex, [part digests]) for in-memory content."""
    parts = [hashlib.md5(data[i:i + MULTIPART_CHUNK]).digest() for i in range(0, len(data), MULTIPART_CHUNK)] or [hashlib.md5(b"").digest()]
    return hashlib.md5(data).hexdigest(), parts


def md5_info_file(path):
    whole = hashlib.md5()
    parts = []
    with open(path, "rb") as f:
        while True:
            chunk = f.read(MULTIPART_CHUNK)
            if not chunk:
                break
            whole.update(chunk)
            parts.append(hashlib.md5(chunk).digest())
    return whole.hexdigest(), parts or [hashlib.md5(b"").digest()]


def etag_equal(etag, md5_whole, md5_parts):
    """Does a live S3 ETag match this content? Single-part ETag = MD5; multipart = MD5 of the
    8 MiB part MD5s + "-N" (what aws s3 cp/sync writes). Used for binary keys only (M3)."""
    etag = (etag or "").strip('"')
    if "-" in etag:
        h, _, n = etag.partition("-")
        if not n.isdigit() or int(n) != len(md5_parts):
            return False
        return hashlib.md5(b"".join(md5_parts)).hexdigest() == h
    return etag == md5_whole


# --- Lambda zip --------------------------------------------------------------------------------

def build_zip(members):
    """Deterministic zip: sorted names, fixed timestamps, mode 0644, deflate level 9."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name in sorted(members):
            zi = zipfile.ZipInfo(name, date_time=ZIP_EPOCH)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = (0o100644 << 16)
            zi.create_system = 3
            z.writestr(zi, members[name], compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return buf.getvalue()


def read_zip(data):
    """Members of a live zip: {name: bytes}. Directories skipped; bounded."""
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise Refused("the live Lambda code is not a zip") from None
    out, total = {}, 0
    for zi in z.infolist():
        if zi.is_dir():
            continue
        total += zi.file_size
        if total > MAX_LIVE_ZIP_UNCOMPRESSED:
            raise Refused("the live Lambda zip is too large to diff")
        if zi.filename in out:
            raise Refused("the live Lambda zip has duplicate members")
        out[zi.filename] = z.read(zi)
    return out


def text_or_none(data):
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return None if "\x00" in s else s


# --- the plan ------------------------------------------------------------------------------------

def prefix_of(policy, key):
    for p in policy["prefixes"]:
        if key.startswith(p):
            return p
    return "(root)"


def key_ok(key):
    """True if key passes site_policy.check_key (the apply refuses any other key)."""
    try:
        sp.check_key(key)
    except sp.PolicyError:
        return False
    return True


def is_code_key(key):
    return sp.ext_of(key).lower() in sp.CODE_TYPES


def compute_s3(policy, desired, live, manifest, live_text, binary_match, adoption, live_meta=None):
    """Decide S3 operations.

    desired:      {key: {class, content_type, cache_control, cache, sha256, size, source}}
    live:         {key: {etag, size, last_modified}} from ListObjectsV2 (the whole bucket)
    manifest:     None (adoption) or {key: {sha256, size, etag, content_type, cache, last_modified?}}
    live_text:    {key: bytes} live bytes of text keys that exist live
    binary_match: callable(key) -> True/False for adoption of binary keys by ETag (M3)
    live_meta:    {key: {content_type, cache_control}} read from AWS: every live text key (GET)
                  and, in adoption, every binary key that matched by ETag (HEAD)
    An object is unchanged only if its bytes AND its Content-Type and Cache-Control are the
    desired ones (Guardian on f944888, M1); a metadata-only difference is an update with
    reason "metadata". Returns dict with puts, deletes, adopted, drift, outside, unsafe_keys
    (live keys in SITE that fail site_policy.check_key: never planned for delete)."""
    live_meta = live_meta or {}
    puts, deletes, adopted, drift, outside, unsafe = [], [], [], [], [], []
    for key in sorted(desired):
        d = desired[key]
        lv = live.get(key)
        m = (manifest or {}).get(key)
        trusted = False  # the manifest entry describes the live object
        if manifest is not None:
            if m is not None and lv is None:
                drift.append({"key": key, "what": "in the manifest but missing live"})
            elif m is not None and m["etag"] != lv["etag"]:
                drift.append({"key": key, "what": "live ETag differs from the manifest (changed outside the pipeline)"})
            elif m is not None and m.get("last_modified") and m["last_modified"] != lv.get("last_modified"):
                drift.append({"key": key, "what": "live object rewritten outside the pipeline (LastModified; "
                                                  "metadata may differ)"})
            elif m is None and lv is not None:
                drift.append({"key": key, "what": "live object not in the manifest"})
            else:
                trusted = m is not None
        if lv is None:
            puts.append({"key": key, "action": "create", "if_match": None, "reason": "new",
                         "live_content_type": None, "live_cache_control": None})
            continue
        meta = live_meta.get(key)
        if d["class"] in ("code", "data"):
            same_bytes = key in live_text and sha256_hex(live_text[key]) == d["sha256"]
        elif trusted:
            same_bytes = m["sha256"] == d["sha256"] and m["size"] == d["size"]
            meta = {"content_type": m.get("content_type"),
                    "cache_control": sp.CACHE_CLASSES.get(m.get("cache"), m.get("cache"))}
        elif manifest is None:
            same_bytes = lv["size"] == d["size"] and binary_match(key)
        else:
            same_bytes = False  # drifted binary: re-upload the commit's bytes
        same_meta = meta is not None and meta.get("content_type") == d["content_type"] \
            and meta.get("cache_control") == d["cache_control"]
        if same_bytes and same_meta:
            if m is None or not trusted or m["sha256"] != d["sha256"]:
                adopted.append(key)
        else:
            puts.append({"key": key, "action": "update", "if_match": lv["etag"],
                         "reason": "metadata" if same_bytes else "content",
                         "live_content_type": (meta or {}).get("content_type"),
                         "live_cache_control": (meta or {}).get("cache_control")})
    for key in sorted(live):
        if key in desired:
            continue
        if not sp.in_site(policy, key):
            outside.append(key)
            drift.append({"key": safe_key(key), "what": "live object outside SITE (the deploy role can't delete it)"})
            continue
        if not key_ok(key):
            # The apply's check_key would refuse this delete after the approval: like an
            # outside-SITE object, it is cleaned up on the Mac (Guardian on fff80e5, L2).
            unsafe.append(key)
            drift.append({"key": safe_key(key), "what": "live object in SITE with a key the pipeline refuses "
                                                        "(it can't delete it)"})
            continue
        if manifest is not None and key not in manifest:
            drift.append({"key": key, "what": "extra live object (not in the manifest): planned for delete"})
        deletes.append({"key": key, "if_match": live[key]["etag"]})
    if manifest is not None:
        for key in sorted(manifest):
            if key not in desired and key not in live:
                drift.append({"key": key, "what": "in the manifest but missing live (dropped from the manifest)"})
    return {"puts": puts, "deletes": deletes, "adopted": adopted, "drift": drift, "outside": outside,
            "unsafe_keys": unsafe}


def check_settings(expected, live):
    """Compare live Lambda settings with deploy/site.json. Returns a list of mismatching fields.

    When the env var names are unreadable (env_names_error), env_names is left out of the
    comparison: Lambda then returns no names at all, so comparing would always mismatch (or,
    with env_names: [], always match without checking anything). The caller says so on the card."""
    bad = []
    pairs = {
        "runtime": (expected["runtime"], live.get("runtime")),
        "handler": (expected["handler"], live.get("handler")),
        "memory_size": (expected["memory_size"], live.get("memory_size")),
        "timeout": (expected["timeout"], live.get("timeout")),
        "architectures": (expected["architectures"], live.get("architectures") or ["x86_64"]),
        "env_names": (sorted(expected["env_names"]), sorted(live.get("env_names") or [])),
        "layers": (expected["layers"], live.get("layers") or []),
        "vpc": (expected["vpc"], bool(live.get("vpc_id"))),
        "kms_key_arn": (expected["kms_key_arn"] or None, live.get("kms_key_arn") or None),
        "package_type": (expected["package_type"], live.get("package_type") or "Zip"),
    }
    if env_names_error(live):
        del pairs["env_names"]
    for k, (want, got) in pairs.items():
        if want != got:
            bad.append({"field": k, "expected": want, "live": got})
    if live.get("state") not in (None, "Active") or live.get("last_update_status") not in (None, "Successful"):
        bad.append({"field": "state", "expected": "Active/Successful",
                    "live": f"{live.get('state')}/{live.get('last_update_status')}"})
    return bad


def env_names_error(live):
    """The error code Lambda returned instead of the environment (the plan role's kms:Decrypt
    deny makes it AccessDeniedException), or None when the variable names were readable."""
    code = live.get("env_error")
    if not code:
        return None
    return one_line(str(code))[:64]


def lambda_changes(policy, new_members, live_members, manifest_lambda):
    """Compare the zip we build with the live zip, member by member.

    Returns {changed, diffs: [...], attention: [...], drift: [...]}."""
    name = policy["lambda"]["function_name"]
    address = f"lambda:{name}"
    diffs, attention, drift = [], [], []
    changed = set(new_members) != set(live_members) or any(
        new_members[n] != live_members.get(n) for n in new_members)
    for n in sorted(set(new_members) - set(live_members)):
        attention.append(_att(address, "New or renamed Lambda member", "update", n, None, "(not in the live zip)"))
    for n in sorted(live_members):
        if text_or_none(live_members[n]) is None:
            attention.append(_att(address, "Non-text member in the live Lambda zip", "update", n,
                                  f"{len(live_members[n])} bytes, sha256 {sha256_hex(live_members[n])[:16]}", None))
    if changed:
        for n in sorted(set(new_members) | set(live_members)):
            new = new_members.get(n)
            old = live_members.get(n)
            if new == old:
                continue
            new_s = None if new is None else new.decode("utf-8")
            old_s = None if old is None else text_or_none(old)
            if new_s is None:
                text = f"--- live/{n}\n+++ (removed from the zip)\n"
                if old_s is not None:
                    text += "".join(f"-{escape_line(x)[0]}\n" for x in old_s.split("\n"))
                diffs.append({"address": address, "file": n, "kind": "code", "text": text,
                              "added": 0, "removed": 0 if old_s is None else len(old_s.split("\n")), "invisible": 0})
                continue
            if old is not None and old_s is None:
                old_s = f"(live member is not text: {len(old)} bytes, sha256 {sha256_hex(old)[:16]})"
            text, a, r, inv = text_diff(old_s, new_s, f"live/{n}", f"commit/{n}")
            diffs.append({"address": address, "file": n, "kind": "code", "text": text,
                          "added": a, "removed": r, "invisible": inv})
    if manifest_lambda:
        live_hashes = {n: sha256_hex(b) for n, b in live_members.items()}
        if manifest_lambda.get("members") != live_hashes:
            drift.append({"key": address, "what": "live Lambda code differs from the last pipeline deploy"})
    return {"changed": changed, "diffs": diffs, "attention": attention, "drift": drift}


def _att(address, label, action, path=None, before=None, after=None):
    return {"address": address, "label": label, "action": action, "path": path, "before": before, "after": after}


LONG_CACHE = ("long", "immutable", "private-immutable")

ATTENTION_ORDER = [
    "Invisible or bidi characters",
    "Gate code", "Gate DEVELOPMENT differs from LIVE", "Lambda code", "PIN page", "Service worker",
    "Cache-Control or Content-Type",
    "New or renamed Lambda member", "Non-text member in the live Lambda zip",
    "Data files without a diff",
    "Delete of a root or code key", "LIVE DRIFT", "Settings mismatch",
    "Lambda env var names unreadable",
    "Non-ASCII letters or combining marks in code", "BASELINE ADOPTION",
]


def order_attention(items):
    rank = {label: i for i, label in enumerate(ATTENTION_ORDER)}
    return sorted(items, key=lambda a: rank.get(a["label"], len(rank)))


def diff_rank(d):
    """Gate, Lambda, pin.html, sw.js, other code, then data (design section 2)."""
    addr = d["address"]
    if addr.startswith("cloudfront-function:"):
        return (0, addr, d.get("file") or "")
    if addr.startswith("lambda:"):
        return (1, addr, d.get("file") or "")
    if addr == "s3:pin.html":
        return (2, addr, "")
    if addr == "s3:sw.js":
        return (3, addr, "")
    return (4 if d["kind"] == "code" else 5, addr, "")


def fit_diffs(diffs):
    """Order diffs and fit them into the summary budget.

    Returns (kept, code_complete, data_truncated). A code diff never gets cut in the middle:
    it is either complete or missing, and a missing one makes the plan not deployable."""
    kept, used, code_complete, data_truncated = [], 0, True, False
    for d in sorted(diffs, key=diff_rank):
        n = len(d["text"].encode("utf-8")) + 200
        if d.get("too_large"):
            if d["kind"] == "code":
                code_complete = False
            else:
                data_truncated = True
        if d["kind"] == "code":
            if used + n > MAX_CODE_DIFF_BYTES:
                code_complete = False
                continue
        elif used + n > MAX_CODE_DIFF_BYTES:
            data_truncated = True
            continue
        kept.append(d)
        used += n
    return kept, code_complete, data_truncated


def data_diffs_hidden(diffs, kept):
    """Number of data files whose diff is not on the card: too large to diff, or dropped by
    fit_diffs for the summary budget."""
    shown = {id(d) for d in kept if not d.get("too_large")}
    return sum(1 for d in diffs if d["kind"] == "data" and id(d) not in shown)


def data_diffs_attention(n):
    """NEEDS ATTENTION entry for data files changed without a diff on the card (Guardian on
    fff80e5, L4): their invisible or bidi characters can't be flagged. Still deployable."""
    return _att("s3:*", "Data files without a diff", "update", None, None,
                f"{n} data file{'s' if n != 1 else ''} changed without a diff on the card (full content in the commit)")


def changes_from_plan(plan):
    """The card's change list, derived only from plan.json, so tf-apply-style digest binding
    works: the apply recomputes it from the bundle and compares with the approved digest."""
    ch = [{"address": f"s3:{p['key']}", "actions": [p["action"]]} for p in plan["puts"]]
    ch += [{"address": f"s3:{d['key']}", "actions": ["delete"]} for d in plan["deletes"]]
    if plan.get("lambda"):
        ch.append({"address": f"lambda:{plan['lambda']['function_name']}", "actions": ["update"]})
    if plan.get("gate"):
        ch.append({"address": f"cloudfront-function:{plan['gate']['function_name']}", "actions": ["update"]})
    if plan.get("manifest_action"):
        ch.append({"address": f"manifest:{plan['manifest']['key']}", "actions": [plan["manifest_action"]]})
    ch.sort(key=lambda c: (c["address"], c["actions"]))
    return ch


def counts_from_changes(changes):
    c = {"add": 0, "change": 0, "destroy": 0, "replace": 0, "forget": 0, "other": 0,
         "action_invocations": 0, "deferred": 0}
    for x in changes:
        a = x["actions"][0]
        c["add" if a == "create" and x["address"].startswith("s3:") else
          "destroy" if a == "delete" else "change"] += 1
    return c


def changes_digest(changes):
    import json
    canon = json.dumps(changes, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canon.encode("ascii")).hexdigest()
