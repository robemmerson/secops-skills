"""Offline tests for scan-images.py. Run: python3 -m unittest discover plugins/dependency-updates/tests"""
import contextlib, importlib.util, io, os, tempfile, unittest
from pathlib import Path

SCRIPTS = os.path.join(os.path.dirname(__file__), "..", "skills", "dependency-updates", "scripts")
spec = importlib.util.spec_from_file_location("scan_images", os.path.join(SCRIPTS, "scan-images.py"))
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


class ClassifyTest(unittest.TestCase):
    def test_buckets(self):
        cases = {
            "nginx": "untagged",
            "localhost:5000/app": "untagged",
            "nginx:latest": "floating",
            "nginx:stable-alpine": "floating",
            "postgres:16": "partial",
            "golang:1.25": "partial",
            "node:22-alpine": "partial",
            "ghcr.io/example/app:1.2.3": "version",
            "registry.example.com:5000/app:v2.0.1": "version",
            "ghcr.io/example/app:1.2.3@sha256:" + "0" * 64: "digest",
            "${IMAGE}": "variable",
            "postgres:${PG_VERSION:-16}": "variable",
        }
        for ref, want in cases.items():
            self.assertEqual(scan.classify(ref), want, ref)


class ScanTest(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())

    def write(self, name, text):
        p = self.d / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def test_dockerfile_skips_scratch_and_stage_names(self):
        f = self.write("Dockerfile", "FROM --platform=$BUILDPLATFORM golang:1.25 AS build\n"
                                     "FROM build AS test\nFROM scratch\n# FROM old:1\nFROM alpine:3.22.1\n")
        self.assertEqual([(r, c) for r, _, c in scan.scan_file(f, False)],
                         [("golang:1.25", False), ("old:1", True), ("alpine:3.22.1", False)])

    def test_compose_names_and_all_yaml(self):
        self.write("compose.yaml", "services:\n  a:\n    image: \"nginx:1.29.0\"\n")
        self.write("k8s/deploy.yaml", "spec:\n  containers:\n    - image: redis:7\n")
        self.write("node_modules/x/compose.yaml", "services:\n  a:\n    image: skipped\n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            scan.main([str(self.d)])
        self.assertIn("nginx:1.29.0", out.getvalue())
        self.assertNotIn("redis", out.getvalue())
        self.assertNotIn("skipped", out.getvalue())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            scan.main(["--all-yaml", str(self.d)])
        self.assertIn("redis:7", out.getvalue())


if __name__ == "__main__":
    unittest.main()
