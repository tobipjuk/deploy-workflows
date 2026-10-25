#!/usr/bin/env python3
"""Regenerate tests/fixtures/attestation-vector.json (a fresh throwaway RSA key each time; the
private key is never written). The vector is what Orion's verifier is tested against too.

  python3 tests/make_attestation_vector.py
"""
import base64
import calendar
import hashlib
import importlib.util
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import jwt_testkit as kit  # noqa: E402

spec = importlib.util.spec_from_file_location("attest", ROOT / "scripts" / "attest.py")
at = importlib.util.module_from_spec(spec)
spec.loader.exec_module(at)

REPO = "tobipjuk/starhuntercrew"
RUN_ID = 18234567890
SHA = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d"
STARTED, UPDATED = "2026-10-25T10:40:00Z", "2026-10-25T10:44:30Z"
IAT = calendar.timegm(time.strptime("2026-10-25T10:43:10Z", "%Y-%m-%dT%H:%M:%SZ"))


def build():
    bundle = b"example plan bundle bytes\n"
    changes = [{"actions": ["update"], "address": 'module.app.aws_s3_object.site["sw.js"]'}]
    digest = hashlib.sha256(json.dumps(changes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    summary_doc = {"schema": 1, "repo": REPO, "target": "starhuntercrew", "sha": SHA, "run_id": RUN_ID,
                   "run_attempt": 1, "changes": changes, "changes_digest": digest,
                   "bundle_sha256": hashlib.sha256(bundle).hexdigest(), "bundle_artifact": "plan-bundle"}
    summary = (json.dumps(summary_doc, indent=1, sort_keys=True) + "\n").encode()
    manifest = at.build_manifest(REPO, RUN_ID, 1, SHA, hashlib.sha256(bundle).hexdigest(),
                                 hashlib.sha256(summary).hexdigest())
    aud = at.audience(manifest)
    key = kit.generate_key()
    kid = "test-key-1"
    claims = {
        "iss": at.ISSUER, "aud": aud, "sub": f"repo:{REPO}:ref:refs/heads/main:event_name:push:actor:tobipjuk:run_attempt:1:job_workflow_ref:{at.PLAN_WORKFLOW_REF}",
        "repository": REPO, "repository_owner": "tobipjuk", "ref": "refs/heads/main", "sha": SHA,
        "event_name": "push", "actor": "tobipjuk", "run_id": str(RUN_ID), "run_number": "7", "run_attempt": "1",
        "workflow_ref": f"{REPO}/.github/workflows/plan.yml@refs/heads/main",
        "job_workflow_ref": at.PLAN_WORKFLOW_REF, "runner_environment": "github-hosted",
        "iat": IAT, "nbf": IAT - 5, "exp": IAT + 300,
    }
    return {
        "description": "Plan attestation test vector (throwaway key; see docs/orion-interface.md 4a).",
        "jwks": kit.jwks(key, kid),
        # Stored as its three parts (join with ".") so secret scanners don't flag a test JWT.
        "token_parts": kit.make_token(key, kid, claims).split("."),
        "manifest": at.canonical(manifest).decode("ascii"),
        "aud": aud,
        "bundle_b64": base64.b64encode(bundle).decode(),
        "summary": summary.decode(),
        "params": {"repo": REPO, "run_id": RUN_ID, "run_attempt": 1, "sha": SHA,
                   "not_before": STARTED, "not_after": UPDATED,
                   "bundle_sha256": hashlib.sha256(bundle).hexdigest(),
                   "summary_sha256": hashlib.sha256(summary).hexdigest(),
                   "changes_digest": digest},
    }


if __name__ == "__main__":
    out = ROOT / "tests" / "fixtures" / "attestation-vector.json"
    out.write_text(json.dumps(build(), indent=1) + "\n")
    print(f"wrote {os.path.relpath(out)}")
