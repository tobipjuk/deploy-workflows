"""Tests for scripts/attest.py (plan attestation, Guardian F1). Stdlib only."""
import base64
import copy
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import jwt_testkit as kit  # noqa: E402

spec = importlib.util.spec_from_file_location("attest", ROOT / "scripts" / "attest.py")
at = importlib.util.module_from_spec(spec)
spec.loader.exec_module(at)

VECTOR = json.loads((ROOT / "tests" / "fixtures" / "attestation-vector.json").read_text())
VECTOR["token"] = ".".join(VECTOR["token_parts"])


class AttestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = kit.generate_key()
        cls.jwks = kit.jwks(cls.key, "k1")
        token_parts = VECTOR["token"].split(".")
        cls.claims = json.loads(base64.urlsafe_b64decode(token_parts[1] + "=" * (-len(token_parts[1]) % 4)))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.bundle = os.path.join(d, "plan-bundle.tar")
        self.summary = os.path.join(d, "plan-summary.json")
        with open(self.bundle, "wb") as f:
            f.write(base64.b64decode(VECTOR["bundle_b64"]))
        with open(self.summary, "w", encoding="utf-8") as f:
            f.write(VECTOR["summary"])
        self.p = VECTOR["params"]

    def tearDown(self):
        self.tmp.cleanup()

    def verify(self, token=None, manifest=None, jwks=None, **over):
        p = {**self.p, **over}
        return at.verify(token or VECTOR["token"], (manifest or VECTOR["manifest"]).encode(),
                         jwks or VECTOR["jwks"], self.bundle, self.summary, p["repo"], p["run_id"],
                         p["run_attempt"], p["sha"], p["not_before"], p["not_after"],
                         p.get("expect_bundle", self.p["bundle_sha256"]), p.get("expect_digest", self.p["changes_digest"]))

    def resign(self, **claim_over):
        claims = {**self.claims, **claim_over}
        return kit.make_token(self.key, "k1", claims)

    # --- the vector ------------------------------------------------------------------
    def test_vector_verifies(self):
        claims = self.verify()
        self.assertEqual(claims["aud"], VECTOR["aud"])

    def test_vector_aud_is_manifest_hash(self):
        self.assertEqual(VECTOR["aud"], at.AUD_PREFIX + hashlib.sha256(VECTOR["manifest"].encode()).hexdigest())
        self.assertEqual(json.loads(VECTOR["manifest"])["bundle_sha256"], self.p["bundle_sha256"])
        self.assertEqual(json.loads(VECTOR["manifest"])["summary_sha256"], self.p["summary_sha256"])

    def test_manifest_cli_matches_vector(self):
        out = os.path.join(self.tmp.name, "m.json")
        with redirect_stdout(StringIO()) as o:
            code = at.main(["manifest", "--repo", self.p["repo"], "--run-id", str(self.p["run_id"]),
                            "--run-attempt", "1", "--sha", self.p["sha"], "--bundle", self.bundle,
                            "--summary", self.summary, "--out", out])
        self.assertEqual(code, 0)
        self.assertEqual(Path(out).read_text(), VECTOR["manifest"])
        self.assertIn(f"aud={VECTOR['aud']}", o.getvalue())

    # --- F1: swapped artifacts ---------------------------------------------------------
    def test_tampered_bundle(self):
        with open(self.bundle, "ab") as f:
            f.write(b"evil zip")
        with self.assertRaisesRegex(at.AttestationError, "bundle differs"):
            self.verify()

    def test_tampered_summary_diff_text(self):
        doc = json.loads(VECTOR["summary"])
        doc["diff"] = [{"address": "x", "attrs": [{"path": "etag", "before": "a", "after": "harmless"}]}]
        with open(self.summary, "w") as f:
            f.write(json.dumps(doc, indent=1, sort_keys=True) + "\n")
        with self.assertRaisesRegex(at.AttestationError, "summary differs"):
            self.verify()

    def test_forged_manifest_and_aud_need_a_new_token(self):
        # Attacker swaps the bundle and writes a matching manifest: the old token's aud no longer fits.
        with open(self.bundle, "wb") as f:
            f.write(b"evil")
        m = json.loads(VECTOR["manifest"])
        m["bundle_sha256"] = hashlib.sha256(b"evil").hexdigest()
        with self.assertRaisesRegex(at.AttestationError, "audience"):
            self.verify(manifest=at.canonical(m).decode(), expect_bundle=m["bundle_sha256"])

    def test_token_from_another_job_rejected(self):
        # A box-added job in plan.yml can mint a token with any aud, but its job_workflow_ref is
        # the caller's workflow, not deploy-workflows' tf-plan.yml.
        for ref in ("tobipjuk/starhuntercrew/.github/workflows/plan.yml@refs/heads/main",
                    "tobipjuk/deploy-workflows/.github/workflows/tf-plan.yml@refs/heads/feature",
                    "tobipjuk/deploy-workflows/.github/workflows/tf-apply.yml@refs/heads/main"):
            token = self.resign(job_workflow_ref=ref)
            with self.assertRaisesRegex(at.AttestationError, "job_workflow_ref"):
                self.verify(token=token, jwks=self.jwks)

    def test_claims_bound_to_run_and_commit(self):
        cases = {"repository": "tobipjuk/other", "run_id": "1", "run_attempt": "2", "sha": "f" * 40,
                 "iss": "https://evil.example", "ref": "refs/heads/feature"}
        for k, v in cases.items():
            with self.assertRaisesRegex(at.AttestationError, k, msg=k):
                self.verify(token=self.resign(**{k: v}), jwks=self.jwks)
        with self.assertRaisesRegex(at.AttestationError, "event_name"):
            self.verify(token=self.resign(event_name="pull_request"), jwks=self.jwks)

    def test_iat_outside_run_window(self):
        for iat in (self.claims["iat"] - 3600, self.claims["iat"] + 3600, "123"):
            with self.assertRaisesRegex(at.AttestationError, "iat|issued"):
                self.verify(token=self.resign(iat=iat), jwks=self.jwks)

    def test_expired_token_still_ok(self):
        self.verify(token=self.resign(exp=1), jwks=self.jwks)

    def test_wrong_run_params(self):
        with self.assertRaisesRegex(at.AttestationError, "run_id"):
            self.verify(run_id=99)
        with self.assertRaisesRegex(at.AttestationError, "sha"):
            self.verify(sha="e" * 40)

    def test_approved_values_must_match(self):
        with self.assertRaisesRegex(at.AttestationError, "approved one"):
            self.verify(expect_bundle="0" * 64)
        with self.assertRaisesRegex(at.AttestationError, "approved digest"):
            self.verify(expect_digest="0" * 64)

    # --- signature / JWKS ----------------------------------------------------------------
    def test_bad_signature(self):
        h, p, s = VECTOR["token"].split(".")
        sig = bytearray(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
        sig[-1] ^= 1
        bad = f"{h}.{p}.{kit.b64u(bytes(sig))}"
        with self.assertRaisesRegex(at.AttestationError, "signature"):
            self.verify(token=bad)

    def test_payload_swap_breaks_signature(self):
        h, _, s = VECTOR["token"].split(".")
        p2 = kit.b64u(json.dumps({**self.claims, "run_id": "1"}).encode())
        with self.assertRaisesRegex(at.AttestationError, "signature"):
            self.verify(token=f"{h}.{p2}.{s}")

    def test_other_key_or_kid(self):
        with self.assertRaisesRegex(at.AttestationError, "signature"):
            self.verify(token=VECTOR["token"], jwks={"keys": [{**self.jwks["keys"][0], "kid": "test-key-1"}]})
        with self.assertRaisesRegex(at.AttestationError, "key not found"):
            self.verify(token=self.resign(), jwks=VECTOR["jwks"])

    def test_alg_none_and_hs256_refused(self):
        for alg in ("none", "HS256"):
            h = kit.b64u(json.dumps({"alg": alg, "kid": "k1"}).encode())
            p = kit.b64u(json.dumps(self.claims).encode())
            with self.assertRaisesRegex(at.AttestationError, "RS256"):
                self.verify(token=f"{h}.{p}.", jwks=self.jwks)

    def test_weak_key_refused(self):
        small = kit.generate_key(bits=1024)
        token = kit.make_token(small, "s", self.claims)
        with self.assertRaisesRegex(at.AttestationError, "weak"):
            self.verify(token=token, jwks=kit.jwks(small, "s"))

    def test_non_canonical_manifest(self):
        pretty = json.dumps(json.loads(VECTOR["manifest"]), indent=1, sort_keys=True)
        with self.assertRaisesRegex(at.AttestationError, "canonical"):
            self.verify(manifest=pretty)
        m = json.loads(VECTOR["manifest"])
        m["extra"] = 1
        with self.assertRaisesRegex(at.AttestationError, "unexpected fields"):
            self.verify(manifest=at.canonical(m).decode())

    def test_cli_verify(self):
        d = self.tmp.name
        paths = {}
        for name, body in (("token.jwt", VECTOR["token"]), ("manifest.json", VECTOR["manifest"]),
                           ("jwks.json", json.dumps(VECTOR["jwks"]))):
            paths[name] = os.path.join(d, name)
            Path(paths[name]).write_text(body)
        base = ["verify", "--token", paths["token.jwt"], "--manifest", paths["manifest.json"],
                "--jwks", paths["jwks.json"], "--bundle", self.bundle, "--summary", self.summary,
                "--repo", self.p["repo"], "--run-id", str(self.p["run_id"]), "--run-attempt", "1",
                "--sha", self.p["sha"], "--not-before", self.p["not_before"], "--not-after", self.p["not_after"],
                "--expect-bundle-sha256", self.p["bundle_sha256"], "--expect-digest", self.p["changes_digest"]]
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            self.assertEqual(at.main(base), 0)
            self.assertEqual(at.main(base[:-1] + ["0" * 64]), 1)
            bad_url = [a if a != "--jwks" else "--jwks-url" for a in base]
            bad_url[bad_url.index("--jwks-url") + 1] = "https://evil.example/jwks"
            self.assertEqual(at.main(bad_url), 1)


if __name__ == "__main__":
    unittest.main()
