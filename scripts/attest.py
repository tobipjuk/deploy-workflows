#!/usr/bin/env python3
"""Plan attestation: bind the plan bundle and plan-summary.json to the trusted tf-plan job.

Why: any job in the project's plan.yml run (which the box can write) can replace the run's
artifacts. A GitHub OIDC token whose `aud` commits to the artifact hashes, minted inside
the nested tf-attest.yml job (which runs no project code), can't be forged by such a job, nor
by the plan job's sandboxed Terraform: their tokens carry another job_workflow_ref (the
caller's plan.yml, or tf-plan.yml). See docs/orion-interface.md, section 4a.

  attest.py manifest --repo R --run-id N --run-attempt N --sha SHA --bundle TAR --summary JSON
                     --out manifest.json
      writes the canonical manifest and prints the audience (aud=...)

  attest.py verify --token token.jwt --manifest manifest.json --jwks JWKS.json|--jwks-url URL
                   --bundle TAR --summary JSON --repo R --run-id N --run-attempt N --sha SHA
                   --not-before ISO --not-after ISO [--expect-bundle-sha256 HEX]
                   [--expect-digest HEX]

Manifest (canonical JSON: sorted keys, no whitespace, ASCII):
  {"bundle_sha256": hex, "repo": "o/r", "run_attempt": int, "run_id": int, "schema": 2,
   "sha": hex40, "summary_sha256": hex, "type": "deploy-workflows-plan"}
Audience: "deploy-workflows-plan:v2:" + sha256(canonical manifest bytes), lowercase hex.

Signature check is RS256 (RSASSA-PKCS1-v1_5 + SHA-256) against GitHub's JWKS, implemented
with the stdlib by comparing the full expected encoding (no padding parsing). Stdlib only.
"""
import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import re
import sys
import urllib.request

ISSUER = "https://token.actions.githubusercontent.com"
JWKS_URL = ISSUER + "/.well-known/jwks"
AUD_PREFIX = "deploy-workflows-plan:v2:"
# The token must come from the nested tf-attest.yml job (no project code), never from the plan
# job (tf-plan.yml, which runs sandboxed project Terraform).
ATTEST_WORKFLOW_REF = "tobipjuk/deploy-workflows/.github/workflows/tf-attest.yml@refs/heads/main"
MIN_RSA_BITS = 2048
CLOCK_SKEW = 120  # seconds of slack around the plan run window
# DER prefix of DigestInfo for SHA-256 (RFC 8017, section 9.2 note 1)
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


class AttestationError(ValueError):
    pass


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def build_manifest(repo, run_id, run_attempt, sha, bundle_sha256, summary_sha256):
    m = {
        "bundle_sha256": bundle_sha256, "repo": repo, "run_attempt": int(run_attempt),
        "run_id": int(run_id), "schema": 2, "sha": sha, "summary_sha256": summary_sha256,
        "type": "deploy-workflows-plan",
    }
    check_manifest_shape(m)
    return m


def check_manifest_shape(m):
    if not isinstance(m, dict) or set(m) != {"bundle_sha256", "repo", "run_attempt", "run_id", "schema",
                                             "sha", "summary_sha256", "type"}:
        raise AttestationError("manifest has unexpected fields")
    if m["schema"] != 2 or m["type"] != "deploy-workflows-plan":
        raise AttestationError("manifest schema/type")
    for k in ("bundle_sha256", "summary_sha256"):
        if not isinstance(m[k], str) or not re.fullmatch(r"[0-9a-f]{64}", m[k]):
            raise AttestationError(f"manifest {k} is not 64 hex")
    if not isinstance(m["sha"], str) or not re.fullmatch(r"[0-9a-f]{40}", m["sha"]):
        raise AttestationError("manifest sha is not 40 hex")
    if not isinstance(m["repo"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", m["repo"]):
        raise AttestationError("manifest repo")
    for k in ("run_id", "run_attempt"):
        if not isinstance(m[k], int) or isinstance(m[k], bool) or m[k] < 1:
            raise AttestationError(f"manifest {k}")


def audience(manifest):
    return AUD_PREFIX + hashlib.sha256(canonical(manifest)).hexdigest()


# --- JWT / RS256 -----------------------------------------------------------------------

def b64url_decode(s):
    if not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", s):
        raise AttestationError("bad base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def rs256_verify(n, e, message, signature):
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    em = pow(s, e, n).to_bytes(k, "big")
    t = SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    if k < len(t) + 11:
        return False
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return hmac.compare_digest(em, expected)


def verify_jwt(token, jwks):
    """Return the claims of an RS256 JWT signed by a key in jwks; raise otherwise."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise AttestationError("token is not a JWT")
    try:
        header = json.loads(b64url_decode(parts[0]))
        claims = json.loads(b64url_decode(parts[1]))
    except (ValueError, UnicodeDecodeError) as e:
        raise AttestationError(f"token header/payload unreadable: {e.__class__.__name__}")
    if not isinstance(header, dict) or header.get("alg") != "RS256":
        raise AttestationError("token alg is not RS256")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise AttestationError("token kid is missing or not a string")
    keys = [k for k in (jwks or {}).get("keys", []) if isinstance(k, dict) and k.get("kid") == kid]
    if len(keys) != 1:
        raise AttestationError("signing key not found in JWKS")
    key = keys[0]
    if key.get("kty") != "RSA" or key.get("alg", "RS256") != "RS256" or key.get("use", "sig") != "sig":
        raise AttestationError("JWKS key is not an RS256 signing key")
    n = int.from_bytes(b64url_decode(key["n"]), "big")
    e = int.from_bytes(b64url_decode(key["e"]), "big")
    if n.bit_length() < MIN_RSA_BITS or e < 3 or e % 2 == 0:
        raise AttestationError("JWKS key too weak")
    if not rs256_verify(n, e, (parts[0] + "." + parts[1]).encode("ascii"), b64url_decode(parts[2])):
        raise AttestationError("token signature invalid")
    if not isinstance(claims, dict):
        raise AttestationError("token claims are not an object")
    return claims


def parse_time(s):
    return dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))


def verify(token, manifest_bytes, jwks, bundle_path, summary_path, repo, run_id, run_attempt, sha,
           not_before, not_after, expect_bundle_sha256=None, expect_digest=None):
    """Raise AttestationError unless everything binds. Returns the claims."""
    claims = verify_jwt(token, jwks)
    try:
        manifest = json.loads(manifest_bytes)
    except ValueError:
        raise AttestationError("manifest is not JSON")
    check_manifest_shape(manifest)
    if canonical(manifest) != manifest_bytes.strip():
        raise AttestationError("manifest is not in canonical form")

    aud = claims.get("aud")
    want_aud = audience(manifest)
    if aud != want_aud and aud != [want_aud]:
        raise AttestationError("token audience does not match the manifest")
    checks = {
        "iss": ISSUER,
        "job_workflow_ref": ATTEST_WORKFLOW_REF,
        "repository": repo,
        "run_id": str(run_id),
        "run_attempt": str(run_attempt),
        "sha": sha,
        "ref": "refs/heads/main",
    }
    for k, v in checks.items():
        if str(claims.get(k)) != v:
            raise AttestationError(f"token claim {k} is {claims.get(k)!r}, expected {v!r}")
    if claims.get("event_name") not in ("push", "workflow_dispatch"):
        raise AttestationError("token event_name")
    iat = claims.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        raise AttestationError("token has no iat")
    lo = parse_time(not_before).timestamp() - CLOCK_SKEW
    hi = parse_time(not_after).timestamp() + CLOCK_SKEW
    if not lo <= iat <= hi:
        raise AttestationError("token was not issued during the plan run")
    # exp is deliberately ignored: the token is a signature over the manifest, not a credential.

    if (manifest["repo"], manifest["run_id"], manifest["run_attempt"], manifest["sha"]) != \
            (repo, int(run_id), int(run_attempt), sha):
        raise AttestationError("manifest is for another run or commit")
    bundle_sha = sha256_file(bundle_path)
    summary_sha = sha256_file(summary_path)
    if bundle_sha != manifest["bundle_sha256"]:
        raise AttestationError("plan bundle differs from the attested one")
    if summary_sha != manifest["summary_sha256"]:
        raise AttestationError("plan summary differs from the attested one")
    if expect_bundle_sha256 is not None and bundle_sha != expect_bundle_sha256:
        raise AttestationError("plan bundle is not the approved one")
    with open(summary_path, encoding="utf-8") as f:
        summary = json.load(f)
    if summary.get("bundle_sha256") != bundle_sha or summary.get("sha") != sha \
            or str(summary.get("run_id")) != str(run_id) or summary.get("repo") != repo:
        raise AttestationError("plan summary does not describe this bundle/run")
    if expect_digest is not None and summary.get("changes_digest") != expect_digest:
        raise AttestationError("approved digest is not the attested summary's digest")
    return claims


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AttestationError(f"JWKS fetch was redirected ({code}); refusing")


def fetch_jwks(url):
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(url, timeout=30) as r:
        if r.status != 200:
            raise AttestationError(f"JWKS fetch returned {r.status}")
        return json.loads(r.read(1 << 20))


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("manifest")
    for a in ("--repo", "--run-id", "--run-attempt", "--sha", "--bundle", "--summary", "--out"):
        m.add_argument(a, required=True)
    v = sub.add_parser("verify")
    for a in ("--token", "--manifest", "--bundle", "--summary", "--repo", "--run-id", "--run-attempt",
              "--sha", "--not-before", "--not-after"):
        v.add_argument(a, required=True)
    g = v.add_mutually_exclusive_group(required=True)
    g.add_argument("--jwks")
    g.add_argument("--jwks-url")
    v.add_argument("--expect-bundle-sha256")
    v.add_argument("--expect-digest")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "manifest":
            man = build_manifest(args.repo, args.run_id, args.run_attempt, args.sha,
                                 sha256_file(args.bundle), sha256_file(args.summary))
            with open(args.out, "wb") as f:
                f.write(canonical(man))
            print(f"aud={audience(man)}")
            return 0
        if args.jwks_url:
            if args.jwks_url != JWKS_URL:
                raise AttestationError("only GitHub's JWKS URL is accepted")
            jwks = fetch_jwks(args.jwks_url)
        else:
            with open(args.jwks, encoding="utf-8") as f:
                jwks = json.load(f)
        with open(args.token, encoding="ascii") as f:
            token = f.read()
        with open(args.manifest, "rb") as f:
            manifest_bytes = f.read()
        verify(token, manifest_bytes, jwks, args.bundle, args.summary, args.repo, args.run_id,
               args.run_attempt, args.sha, args.not_before, args.not_after,
               args.expect_bundle_sha256, args.expect_digest)
        print("plan attestation ok: bundle and summary attested by tf-attest.yml@main in this run")
        return 0
    except (OSError, ValueError, KeyError, UnicodeDecodeError) as e:
        print(f"::error::plan attestation: {e}"[:400], file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
