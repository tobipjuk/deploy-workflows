"""Tests for scripts/bundle.py (create/verify of the plan bundle). Needs git on PATH."""
import hashlib
import importlib.util
import io
import os
import subprocess
import tarfile
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bundle", ROOT / "scripts" / "bundle.py")
bd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bd)

SHA = "a" * 40
GLOB = "terraform/modules/*/build/*.zip"


def git(repo, *args):
    subprocess.run(["git", "-C", repo, *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class BundleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.src = os.path.join(self.d, "src")
        self.dst = os.path.join(self.d, "dst")
        for repo in (self.src, self.dst):
            os.makedirs(os.path.join(repo, "terraform/modules/api"))
            with open(os.path.join(repo, "terraform/modules/api/main.tf"), "w") as f:
                f.write("# tracked\n")
            git(repo, "init", "-q")
            git(repo, "add", ".")
            git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init")
        os.makedirs(os.path.join(self.src, "terraform/modules/api/build"))
        with open(os.path.join(self.src, "terraform/modules/api/build/shc-api.zip"), "wb") as f:
            f.write(b"PK zip bytes")
        os.makedirs(os.path.join(self.src, "terraform/modules/api/other"))
        with open(os.path.join(self.src, "terraform/modules/api/other/x.zip"), "wb") as f:
            f.write(b"not in glob")
        self.tfplan = os.path.join(self.d, "tfplan")
        with open(self.tfplan, "wb") as f:
            f.write(b"saved plan")
        self.tar = os.path.join(self.d, "plan-bundle.tar")
        self.sha, self.n = bd.create(self.src, self.tfplan, SHA, self.tar, [GLOB])

    def tearDown(self):
        self.tmp.cleanup()

    def verify(self, tar=None, sha=None, source=SHA, globs=(GLOB,)):
        tar = tar or self.tar
        sha = sha or bd.sha256_file(tar)
        return bd.verify(self.dst, tar, sha, source, os.path.join(self.dst, "tfplan"), list(globs))

    def craft(self, members, sums=None):
        """Write a tar with the given (name, bytes|TarInfo-type) members; SHA256SUMS auto unless given."""
        path = os.path.join(self.d, "crafted.tar")
        with tarfile.open(path, "w") as t:
            data = {}
            for name, payload, kind in members:
                info = tarfile.TarInfo(name)
                if kind == "sym":
                    info.type = tarfile.SYMTYPE
                    info.linkname = payload
                    t.addfile(info)
                    continue
                info.size = len(payload)
                t.addfile(info, io.BytesIO(payload))
                data[name] = payload
            if sums is None:
                sums = "".join(f"{hashlib.sha256(v).hexdigest()}  {k}\n" for k, v in sorted(data.items()))
            info = tarfile.TarInfo("SHA256SUMS")
            info.size = len(sums.encode())
            t.addfile(info, io.BytesIO(sums.encode()))
        return path

    def base(self):
        return [("tfplan", b"saved plan", "f"), ("SOURCE", (SHA + "\n").encode(), "f")]

    def test_roundtrip(self):
        self.assertEqual(self.n, 1)
        sha, n = self.verify()
        self.assertEqual((sha, n), (self.sha, 1))
        with open(os.path.join(self.dst, "terraform/modules/api/build/shc-api.zip"), "rb") as f:
            self.assertEqual(f.read(), b"PK zip bytes")
        with open(os.path.join(self.dst, "tfplan"), "rb") as f:
            self.assertEqual(f.read(), b"saved plan")
        self.assertFalse(os.path.exists(os.path.join(self.dst, "terraform/modules/api/other/x.zip")))

    def test_deterministic(self):
        tar2 = os.path.join(self.d, "again.tar")
        self.assertEqual(bd.create(self.src, self.tfplan, SHA, tar2, [GLOB])[0], self.sha)

    def test_wrong_sha(self):
        with self.assertRaisesRegex(ValueError, "mismatch"):
            self.verify(sha="0" * 64)
        with self.assertRaisesRegex(ValueError, "64"):
            bd.verify(self.dst, self.tar, "", SHA, os.path.join(self.dst, "tfplan"), [GLOB])

    def test_wrong_commit(self):
        with self.assertRaisesRegex(ValueError, "another commit"):
            self.verify(source="b" * 40)

    def test_traversal_and_odd_names(self):
        for name in ("files/../../etc/x.zip", "/abs", "files/terraform/modules/api/build/../x.zip",
                     "files/.git/hooks/pre-commit", "files/terraform/modules/.terraform/build/p.zip", "extra"):
            tar = self.craft(self.base() + [(name, b"x", "f")])
            with self.assertRaises(ValueError, msg=name):
                self.verify(tar=tar)

    def test_symlink_member(self):
        tar = self.craft(self.base() + [("files/terraform/modules/api/build/l.zip", "/etc/passwd", "sym")])
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.verify(tar=tar)

    def test_unlisted_and_bad_sum(self):
        good = self.base() + [("files/terraform/modules/api/build/a.zip", b"x", "f")]
        tar = self.craft(good, sums=f"{hashlib.sha256(b'saved plan').hexdigest()}  tfplan\n")
        with self.assertRaisesRegex(ValueError, "exactly"):
            self.verify(tar=tar)
        sums = "".join(f"{'0' * 64}  {n}\n" for n, _, _ in sorted(good))
        tar = self.craft(good, sums=sums)
        with self.assertRaisesRegex(ValueError, "sha256 mismatch for"):
            self.verify(tar=tar)

    def test_glob_mismatch(self):
        with self.assertRaisesRegex(ValueError, "unexpected member"):
            self.verify(globs=("lambda/*.zip",))

    def test_tracked_file_not_overwritten(self):
        tar = self.craft(self.base() + [("files/terraform/modules/api/main.tf", b"evil", "f")])
        with self.assertRaisesRegex(ValueError, "tracked"):
            bd.verify(self.dst, tar, bd.sha256_file(tar), SHA, os.path.join(self.dst, "tfplan"),
                      ["terraform/modules/*/*.tf"])

    def test_symlinked_destination_dir(self):
        outside = os.path.join(self.d, "outside")
        os.makedirs(outside)
        os.symlink(outside, os.path.join(self.dst, "terraform/modules/api/build"))
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.verify()
        self.assertEqual(os.listdir(outside), [])

    def test_cli(self):
        with redirect_stdout(StringIO()) as out, redirect_stderr(StringIO()):
            code = bd.main(["verify", "--root", self.dst, "--tar", self.tar, "--sha256", self.sha,
                            "--source", SHA, "--tfplan-dest", os.path.join(self.dst, "tfplan"), "--glob", GLOB])
        self.assertEqual(code, 0)
        self.assertIn("verified", out.getvalue())
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            code = bd.main(["verify", "--root", self.dst, "--tar", self.tar, "--sha256", "f" * 64,
                            "--source", SHA, "--tfplan-dest", os.path.join(self.dst, "tfplan"), "--glob", GLOB])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
