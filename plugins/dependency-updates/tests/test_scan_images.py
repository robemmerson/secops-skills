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
        p.write_text(text, encoding="utf-8")
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



D64 = "sha256:" + "0" * 64


class ClassifyEdgeTest(unittest.TestCase):
    def test_more_buckets(self):
        cases = {
            "nginx:1.29.0": "version",                         # tag only
            f"nginx:1.29.0@{D64}": "digest",                   # tag@digest
            f"nginx@{D64}": "digest",                          # digest only
            "nginx:latest": "floating",
            "nginx:latest-alpine": "floating",
            "ubuntu": "untagged",
            "docker.io/library/ubuntu": "untagged",
            "localhost:5000/team/app": "untagged",             # the port is not a tag
            "registry.example.com:5000/team/app:1.4.2": "version",
            "registry.example.com:5000/team/app:main": "floating",
            "mcr.microsoft.com/dotnet/sdk:9.0": "partial",
            "python:3.13-slim": "partial",
            "python:3.13.1-slim-bookworm": "version",
            "${REGISTRY}/app:1.0.0": "variable",
            "$BASE_IMAGE": "variable",
            "node:${NODE_VERSION}": "variable",
            "alpine:edge": "floating",
            "busybox:musl": "floating",                        # no digit: a variant name, not a release
        }
        for ref, want in cases.items():
            with self.subTest(ref=ref):
                self.assertEqual(scan.classify(ref), want)


class FilesTest(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.d)

    def write(self, name, text):
        p = self.d / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return p

    def refs(self, f, all_yaml=False):
        return [r for r, _, c in scan.scan_file(f, all_yaml) if not c]

    def run_main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(scan.main(list(argv)), 0)
        return out.getvalue()

    def test_dockerfile_args_and_stages(self):
        f = self.write("Dockerfile", "ARG GO=1.25\nARG BASE=gcr.io/distroless/static\n"
                                     "FROM golang:${GO} as build\n"
                                     "FROM build AS test\n"
                                     "FROM ${BASE}:nonroot\n"
                                     "FROM --platform=linux/amd64 BUILD\n"         # stage names are case-insensitive
                                     "COPY --from=build /out /out\n")
        self.assertEqual(self.refs(f), ["golang:${GO}", "${BASE}:nonroot"])
        self.assertEqual([scan.classify(r) for r in self.refs(f)], ["variable", "variable"])

    def test_dockerfile_name_variants(self):
        for name in ("Dockerfile.prod", "api.Dockerfile", "Containerfile", "build/app.dockerfile"):
            with self.subTest(name=name):
                self.assertEqual(self.refs(self.write(name, "FROM alpine:3.22.1\n")), ["alpine:3.22.1"])
        self.assertEqual(self.refs(self.write("notes.txt", "FROM alpine:3\n")), [])

    def test_compose_image_and_build_only_services(self):
        self.write("docker-compose.override.yml", "services:\n  db:\n    image: postgres:16\n"
                                                  "  # cache:\n  #   image: redis:7\n")
        self.write("compose.yaml", "services:\n  web:\n    build: ./web\n"
                                   "  api:\n    build:\n      context: .\n    image: registry.example.com/api:1.0.0\n")
        self.write("web/Dockerfile", "FROM node:22-alpine\n")
        out = self.run_main(str(self.d))
        self.assertIn("postgres:16", out)
        self.assertIn("registry.example.com/api:1.0.0", out)  # build + image: the tag it is pushed as
        self.assertIn("node:22-alpine", out)                  # a build-only service's base, via its Dockerfile
        self.assertIn("3 active image references in 3 files, 1 commented out.", out)

    def test_kubernetes_manifests_need_all_yaml(self):
        self.write("k8s/deploy.yaml", """apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      initContainers:
        - name: init
          image: busybox:1.37
      containers:
        - name: app
          image: "ghcr.io/example/app:1.2.3"
---
apiVersion: batch/v1
kind: CronJob
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - image: ghcr.io/example/report@""" + D64 + "\n")
        self.write("rendered/chart.yml", "# Source: app/templates/deploy.yaml\nkind: Deployment\nspec:\n"
                                         "  template:\n    spec:\n      containers:\n"
                                         "      - image: \"docker.io/library/nginx:latest\"\n")
        self.assertNotIn("busybox", self.run_main(str(self.d)))
        out = self.run_main("--all-yaml", str(self.d))
        for ref in ("busybox:1.37", "ghcr.io/example/app:1.2.3", "ghcr.io/example/report@" + D64,
                    "docker.io/library/nginx:latest"):
            self.assertIn(ref, out)
        self.assertIn("DIGEST  (1/4)", out)
        self.assertIn("FLOATING  (1/4)", out)

    def test_exclude_matches_relative_and_absolute_paths(self):
        self.write("tests/fixtures/compose.yaml", "services:\n  a:\n    image: fixture:1.0.0\n")
        self.write("compose.yaml", "services:\n  a:\n    image: real:1.0.0\n")
        for pattern in ("tests/*", "*/fixtures/*", str(self.d / "tests") + "/*"):
            with self.subTest(pattern=pattern):
                out = self.run_main("--exclude", pattern, str(self.d))
                self.assertNotIn("fixture:1.0.0", out)
                self.assertIn("real:1.0.0", out)

    def test_skipped_directories_and_summary(self):
        self.write(".venv/lib/compose.yaml", "services:\n  a:\n    image: venv:1\n")
        self.write("vendor/x/Dockerfile", "FROM vendored:1\n")
        out = self.run_main(str(self.d))
        self.assertNotIn("venv:1", out)
        self.assertNotIn("vendored", out)
        self.assertIn("0 active image references in 0 files", out)

    def test_moving_reference_count(self):
        self.write("compose.yaml", "services:\n  a:\n    image: nginx\n  b:\n    image: redis:7\n"
                                   "  c:\n    image: app:1.2.3\n")
        out = self.run_main(str(self.d))
        self.assertIn("2 are on a moving reference", out)
        self.assertLess(out.index("UNTAGGED"), out.index("PARTIAL"))
        self.assertLess(out.index("PARTIAL"), out.index("VERSION"))

if __name__ == "__main__":
    unittest.main()
