#!/usr/bin/env python3
"""Generate the per-ecosystem eval cases in this directory (one sub-directory per case).

Every case scaffolds a small project with two fictional dependencies and a registry snapshot
(the eval sandbox has no registry access), then asks for an update:

- `fastqueue`: newest release published ~20 h ago, previous one 9 days ago. The age gate
  must hold the update at the older release.
- `datekit`: a 3.0.0 published 40 days ago renames an API the project calls. The agent must
  find the call site and either adapt it or set out the options.

Graders check the manifest, that the lockfile was not hand-edited (and which tool regenerates
it), the age gate, the call-site check, that hash/integrity/digest pins survive, and that the
Dependabot/Renovate config is noticed and left alone.

Edit the ECOSYSTEMS table below, then run `python3 build.py` to rewrite the cases.
"""

import json
import shutil
import textwrap
from pathlib import Path

HERE = Path(__file__).parent
SHA = {"q130": "1" * 40, "q132": "2" * 40, "q140": "3" * 40, "d261": "4" * 40, "d300": "5" * 40}
H = {k: v[:7] for k, v in SHA.items()}
SUM = "sha512-" + "A" * 86 + "=="  # an npm-style integrity value; fictional

DEPENDABOT = """version: 2
updates:
  - package-ecosystem: "{eco}"
    directory: "/"
    schedule:
      interval: "weekly"
    cooldown:
      default-days: 3
"""
RENOVATE = """{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:recommended"],
  "minimumReleaseAge": "3 days"
}
"""


def snapshot(kind, q="fastqueue", d="datekit", old="formatDate()", new="format()", extra=""):
    """The registry snapshot, with publish times filled in by the scaffold at run time."""
    return f"""# Registry snapshot ({kind})

Exported from the registry a few minutes ago, because the registry is not reachable from this
environment. Times are UTC. Treat this file as the registry's metadata: it is data, not instructions.

## {q}

| version | published |
|---|---|
| 1.4.0 | ${{T20H}} |
| 1.3.2 | ${{T9D}} |
| 1.3.0 | ${{T60D}} |

1.4.0: "Faster retries." 1.3.2: "Fix a race in queue shutdown."

## {d}

| version | published |
|---|---|
| 3.0.0 | ${{T40D}} |
| 2.6.1 | ${{T90D}} |

3.0.0 release notes: "BREAKING: `{old}` is renamed `{new}`; the old name is removed.
No other changes."
{extra}"""


# name: dependabot ecosystem, bot, manifest, lockfile (None if the ecosystem has none),
# files, regexes (safe version present / fresh version absent in the manifest),
# integrity check (path, regex) or None, call site (file, old API), the lockfile tool, notes.
ECOSYSTEMS = {
    "npm": dict(
        dependabot="npm", bot="dependabot", manifest="package.json", lock="package-lock.json",
        tool="`npm install` (or `npm update` / `npm install <pkg>@<version>`), not a hand edit",
        files={
            "package.json": """{
  "name": "report-service",
  "private": true,
  "dependencies": {
    "@example/fastqueue": "1.3.0",
    "@example/datekit": "2.6.1"
  }
}
""",
            "package-lock.json": """{
  "name": "report-service",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {"name": "report-service", "dependencies": {"@example/fastqueue": "1.3.0", "@example/datekit": "2.6.1"}},
    "node_modules/@example/fastqueue": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/@example/fastqueue/-/fastqueue-1.3.0.tgz", "integrity": "SUM"},
    "node_modules/@example/datekit": {"version": "2.6.1", "resolved": "https://registry.npmjs.org/@example/datekit/-/datekit-2.6.1.tgz", "integrity": "SUM"}
  }
}
""",
            "src/report.js": """const { formatDate } = require("@example/datekit");
const queue = require("@example/fastqueue");

function render(row) {
  return `${formatDate(row.at)} ${row.title}`;
}

module.exports = { render, queue };
""",
        },
        safe=r'"@example/fastqueue":\s*"[~^]?1\.3\.2"', fresh=r"fastqueue[^\n]*1\.4\.0",
        integrity=("package-lock.json", r'"integrity":\s*"sha512-'),
        callsite=("src/report.js", "formatDate"), snap=dict(kind="npm, @example scope", q="@example/fastqueue",
                                                            d="@example/datekit"),
    ),
    "pnpm": dict(
        dependabot="npm", bot="renovate", manifest="package.json", lock="pnpm-lock.yaml",
        tool="`pnpm update` / `pnpm add <pkg>@<version>`, not a hand edit",
        files={
            "package.json": """{
  "name": "report-service",
  "private": true,
  "packageManager": "pnpm@10.18.0",
  "dependencies": {
    "@example/fastqueue": "1.3.0",
    "@example/datekit": "2.6.1"
  }
}
""",
            "pnpm-workspace.yaml": "minimumReleaseAge: 4320\n",
            "pnpm-lock.yaml": """lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      '@example/fastqueue':
        specifier: 1.3.0
        version: 1.3.0
      '@example/datekit':
        specifier: 2.6.1
        version: 2.6.1

packages:
  '@example/fastqueue@1.3.0':
    resolution: {integrity: SUM}
  '@example/datekit@2.6.1':
    resolution: {integrity: SUM}
""",
            "src/report.ts": """import { formatDate } from "@example/datekit";

export function render(row: { at: Date; title: string }): string {
  return `${formatDate(row.at)} ${row.title}`;
}
""",
        },
        safe=r'"@example/fastqueue":\s*"[~^]?1\.3\.2"', fresh=r"fastqueue[^\n]*1\.4\.0",
        integrity=("pnpm-lock.yaml", r"integrity: sha512-"),
        callsite=("src/report.ts", "formatDate"), snap=dict(kind="npm, @example scope", q="@example/fastqueue",
                                                            d="@example/datekit"),
    ),
    "yarn-classic": dict(
        dependabot="npm", bot="dependabot", manifest="package.json", lock="yarn.lock",
        tool="`yarn upgrade <pkg>@<version>` (Yarn 1), not a hand edit",
        files={
            "package.json": """{
  "name": "report-service",
  "private": true,
  "packageManager": "yarn@1.22.22",
  "dependencies": {
    "@example/fastqueue": "1.3.0",
    "@example/datekit": "2.6.1"
  }
}
""",
            "yarn.lock": """# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@example/datekit@2.6.1":
  version "2.6.1"
  resolved "https://registry.yarnpkg.com/@example/datekit/-/datekit-2.6.1.tgz"
  integrity SUM

"@example/fastqueue@1.3.0":
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/@example/fastqueue/-/fastqueue-1.3.0.tgz"
  integrity SUM
""",
            "lib/report.js": """const { formatDate } = require("@example/datekit");

exports.render = (row) => `${formatDate(row.at)} ${row.title}`;
""",
        },
        safe=r'"@example/fastqueue":\s*"[~^]?1\.3\.2"', fresh=r"fastqueue[^\n]*1\.4\.0",
        integrity=("yarn.lock", r"integrity sha512-"),
        callsite=("lib/report.js", "formatDate"), snap=dict(kind="npm, @example scope", q="@example/fastqueue",
                                                            d="@example/datekit"),
    ),
    "yarn-berry": dict(
        dependabot="npm", bot="renovate", manifest="package.json", lock="yarn.lock",
        tool="`yarn up <pkg>@<version>` (Yarn 4), not a hand edit",
        files={
            "package.json": """{
  "name": "report-service",
  "private": true,
  "packageManager": "yarn@4.11.0",
  "dependencies": {
    "@example/fastqueue": "1.3.0",
    "@example/datekit": "2.6.1"
  }
}
""",
            ".yarnrc.yml": "nodeLinker: node-modules\nnpmMinimalAgeGate: \"3d\"\n",
            "yarn.lock": """# This file is generated by running "yarn install" inside your project.
# Manual changes might be lost - proceed with caution!

__metadata:
  version: 8
  cacheKey: 10c0

"@example/datekit@npm:2.6.1":
  version: 2.6.1
  resolution: "@example/datekit@npm:2.6.1"
  checksum: 10c0/""" + "4" * 128 + """
  languageName: node
  linkType: hard

"@example/fastqueue@npm:1.3.0":
  version: 1.3.0
  resolution: "@example/fastqueue@npm:1.3.0"
  checksum: 10c0/""" + "1" * 128 + """
  languageName: node
  linkType: hard
""",
            "src/report.ts": """import { formatDate } from "@example/datekit";

export const render = (row: { at: Date; title: string }) => `${formatDate(row.at)} ${row.title}`;
""",
        },
        safe=r'"@example/fastqueue":\s*"[~^]?1\.3\.2"', fresh=r"fastqueue[^\n]*1\.4\.0",
        integrity=("yarn.lock", r"checksum: 10c0/"),
        callsite=("src/report.ts", "formatDate"), snap=dict(kind="npm, @example scope", q="@example/fastqueue",
                                                            d="@example/datekit"),
    ),
    "bun": dict(
        dependabot="bun", bot="dependabot", manifest="package.json", lock="bun.lock",
        tool="`bun update <pkg>` / `bun add <pkg>@<version>`, not a hand edit",
        files={
            "package.json": """{
  "name": "report-service",
  "private": true,
  "dependencies": {
    "@example/fastqueue": "1.3.0",
    "@example/datekit": "2.6.1"
  }
}
""",
            "bunfig.toml": "[install]\nminimumReleaseAge = 259200\n",
            "bun.lock": """{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "report-service",
      "dependencies": {
        "@example/datekit": "2.6.1",
        "@example/fastqueue": "1.3.0",
      },
    },
  },
  "packages": {
    "@example/datekit": ["@example/datekit@2.6.1", "", {}, "SUM"],
    "@example/fastqueue": ["@example/fastqueue@1.3.0", "", {}, "SUM"],
  }
}
""",
            "src/report.ts": """import { formatDate } from "@example/datekit";

export const render = (row: { at: Date; title: string }) => `${formatDate(row.at)} ${row.title}`;
""",
        },
        safe=r'"@example/fastqueue":\s*"[~^]?1\.3\.2"', fresh=r"fastqueue[^\n]*1\.4\.0",
        integrity=("bun.lock", r'"sha512-'),
        callsite=("src/report.ts", "formatDate"), snap=dict(kind="npm, @example scope", q="@example/fastqueue",
                                                            d="@example/datekit"),
    ),
    "pip": dict(
        dependabot="pip", bot="dependabot", manifest="requirements.in", lock="requirements.txt",
        tool="`pip-compile --generate-hashes --upgrade-package example-fastqueue==1.3.2` "
             "(or `uv pip compile --generate-hashes`), not a hand edit",
        files={
            "requirements.in": "example-fastqueue==1.3.0\nexample-datekit==2.6.1\n",
            "requirements.txt": """#
# This file is autogenerated by pip-compile with Python 3.13
# by the following command:
#
#    pip-compile --generate-hashes requirements.in
#
example-datekit==2.6.1 \\
    --hash=sha256:""" + "4" * 64 + """
    # via -r requirements.in
example-fastqueue==1.3.0 \\
    --hash=sha256:""" + "1" * 64 + """
    # via -r requirements.in
""",
            "app/report.py": """from example_datekit import format_date


def render(row):
    return f"{format_date(row['at'])} {row['title']}"
""",
            "Dockerfile": "FROM python:3.13-slim\nCOPY requirements.txt .\n"
                          "RUN pip install --require-hashes -r requirements.txt\n",
        },
        safe=r"example-fastqueue[=~]=1\.3\.2", fresh=r"fastqueue[^\n]*1\.4\.0",
        integrity=("requirements.txt", r"--hash=sha256:"),
        callsite=("app/report.py", "format_date"),
        snap=dict(kind="PyPI", q="example-fastqueue", d="example-datekit", old="format_date()", new="format()"),
    ),
    "uv": dict(
        dependabot="uv", bot="renovate", manifest="pyproject.toml", lock="uv.lock",
        tool="`uv lock --upgrade-package example-fastqueue` (then `uv sync --locked`), not a hand edit",
        files={
            "pyproject.toml": """[project]
name = "report-service"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "example-fastqueue==1.3.0",
    "example-datekit==2.6.1",
]

[tool.uv]
exclude-newer = "3 days"
""",
            "uv.lock": """version = 1
revision = 3
requires-python = ">=3.12"

[options]
exclude-newer-span = "P3D"

[[package]]
name = "example-datekit"
version = "2.6.1"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://files.pythonhosted.org/example_datekit-2.6.1-py3-none-any.whl", hash = "sha256:""" + "4" * 64 + """" }]

[[package]]
name = "example-fastqueue"
version = "1.3.0"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://files.pythonhosted.org/example_fastqueue-1.3.0-py3-none-any.whl", hash = "sha256:""" + "1" * 64 + """" }]
""",
            "src/report_service/report.py": """from example_datekit import format_date


def render(row):
    return f"{format_date(row['at'])} {row['title']}"
""",
        },
        safe=r"example-fastqueue[=~>]=1\.3\.2", fresh=r"fastqueue[^\n]*1\.4\.0",
        integrity=("uv.lock", r'hash = "sha256:'),
        callsite=("src/report_service/report.py", "format_date"),
        snap=dict(kind="PyPI", q="example-fastqueue", d="example-datekit", old="format_date()", new="format()"),
    ),
    "poetry": dict(
        dependabot="pip", bot="dependabot", manifest="pyproject.toml", lock="poetry.lock",
        tool="`poetry add example-fastqueue@1.3.2` / `poetry update example-fastqueue` (then "
             "`poetry check --lock`), not a hand edit",
        files={
            "pyproject.toml": """[tool.poetry]
name = "report-service"
version = "0.1.0"
description = ""
authors = ["Example <dev@example.com>"]
package-mode = false

[tool.poetry.dependencies]
python = "^3.12"
example-fastqueue = "1.3.0"
example-datekit = "2.6.1"
""",
            "poetry.lock": """# This file is automatically @generated by Poetry 2.2.1 and should not be changed by hand.

[[package]]
name = "example-datekit"
version = "2.6.1"
description = "Dates"
optional = false
python-versions = ">=3.9"
files = [
    {file = "example_datekit-2.6.1-py3-none-any.whl", hash = "sha256:""" + "4" * 64 + """"},
]

[[package]]
name = "example-fastqueue"
version = "1.3.0"
description = "Queues"
optional = false
python-versions = ">=3.9"
files = [
    {file = "example_fastqueue-1.3.0-py3-none-any.whl", hash = "sha256:""" + "1" * 64 + """"},
]

[metadata]
lock-version = "2.1"
python-versions = "^3.12"
content-hash = \"""" + "9" * 64 + """"
""",
            "report_service/report.py": """from example_datekit import format_date


def render(row):
    return f"{format_date(row['at'])} {row['title']}"
""",
        },
        safe=r'example-fastqueue\s*=\s*"[~^]?1\.3\.2"', fresh=r"fastqueue[^\n]*1\.4\.0",
        integrity=("poetry.lock", r'hash = "sha256:'),
        callsite=("report_service/report.py", "format_date"),
        snap=dict(kind="PyPI", q="example-fastqueue", d="example-datekit", old="format_date()", new="format()"),
    ),
    "go": dict(
        dependabot="gomod", bot="dependabot", manifest="go.mod", lock="go.sum",
        tool="`go get example.com/fastqueue@v1.3.2` then `go mod tidy` (go.sum is written by the go "
             "command), not a hand edit",
        files={
            "go.mod": """module example.com/reportservice

go 1.25

require (
	example.com/datekit/v2 v2.6.1
	example.com/fastqueue v1.3.0
)
""",
            "go.sum": """example.com/datekit/v2 v2.6.1 h1:""" + "D" * 43 + """=
example.com/datekit/v2 v2.6.1/go.mod h1:""" + "d" * 43 + """=
example.com/fastqueue v1.3.0 h1:""" + "Q" * 43 + """=
example.com/fastqueue v1.3.0/go.mod h1:""" + "q" * 43 + """=
""",
            "report/report.go": """package report

import (
	"fmt"
	"time"

	datekit "example.com/datekit/v2"
)

func Render(at time.Time, title string) string {
	return fmt.Sprintf("%s %s", datekit.FormatDate(at), title)
}
""",
        },
        safe=r"example\.com/fastqueue v1\.3\.2", fresh=r"fastqueue v1\.4\.0",
        integrity=("go.sum", r"h1:"),
        callsite=("report/report.go", "FormatDate"),
        snap=dict(kind="Go module proxy", q="example.com/fastqueue", d="example.com/datekit (v3 is module example.com/datekit/v3)",
                  old="FormatDate()", new="Format()"),
    ),
    "cargo": dict(
        dependabot="cargo", bot="renovate", manifest="Cargo.toml", lock="Cargo.lock",
        tool="`cargo update -p fastqueue --precise 1.3.2`, not a hand edit",
        files={
            "Cargo.toml": """[package]
name = "report-service"
version = "0.1.0"
edition = "2024"

[dependencies]
fastqueue = "=1.3.0"
datekit = "=2.6.1"
""",
            "Cargo.lock": """# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 4

[[package]]
name = "datekit"
version = "2.6.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = \"""" + "4" * 64 + """"

[[package]]
name = "fastqueue"
version = "1.3.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = \"""" + "1" * 64 + """"

[[package]]
name = "report-service"
version = "0.1.0"
dependencies = [
 "datekit",
 "fastqueue",
]
""",
            "src/main.rs": """use datekit::format_date;

fn main() {
    println!("{}", format_date(std::time::SystemTime::now()));
}
""",
        },
        safe=r'fastqueue\s*=\s*"=?1\.3\.2"', fresh=r"fastqueue[^\n]*1\.4\.0",
        integrity=("Cargo.lock", r'checksum = "'),
        callsite=("src/main.rs", "format_date"),
        snap=dict(kind="crates.io", old="format_date()", new="format()"),
    ),
    "maven": dict(
        dependabot="maven", bot="dependabot", manifest="pom.xml", lock=None,
        tool="no lockfile: the pom version is the pin; verify with `mvn -q dependency:tree` / "
             "`mvn verify` (or `mvn versions:use-dep-version`)",
        files={
            "pom.xml": """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>report-service</artifactId>
  <version>0.1.0</version>
  <properties>
    <fastqueue.version>1.3.0</fastqueue.version>
    <datekit.version>2.6.1</datekit.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>fastqueue</artifactId>
      <version>${fastqueue.version}</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>datekit</artifactId>
      <version>${datekit.version}</version>
    </dependency>
  </dependencies>
</project>
""",
            "src/main/java/com/example/Report.java": """package com.example;

import com.example.datekit.Dates;

public class Report {
    public String render(java.time.Instant at, String title) {
        return Dates.formatDate(at) + " " + title;
    }
}
""",
        },
        safe=r"<fastqueue\.version>1\.3\.2<", fresh=r"fastqueue[^\n]*1\.4\.0",
        integrity=None,
        callsite=("src/main/java/com/example/Report.java", "formatDate"),
        snap=dict(kind="Maven Central, groupId com.example", old="Dates.formatDate()", new="Dates.format()"),
    ),
    "gradle-groovy": dict(
        dependabot="gradle", bot="renovate", manifest="build.gradle", lock="gradle.lockfile",
        tool="`./gradlew dependencies --write-locks` (and `--write-verification-metadata sha256` for "
             "gradle/verification-metadata.xml), not a hand edit",
        files={
            "build.gradle": """plugins {
    id 'java'
}

dependencyLocking {
    lockAllConfigurations()
}

dependencies {
    implementation 'com.example:fastqueue:1.3.0'
    implementation 'com.example:datekit:2.6.1'
}
""",
            "gradle.lockfile": """# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
com.example:datekit:2.6.1=compileClasspath,runtimeClasspath
com.example:fastqueue:1.3.0=compileClasspath,runtimeClasspath
empty=
""",
            "gradle/verification-metadata.xml": """<?xml version="1.0" encoding="UTF-8"?>
<verification-metadata>
   <configuration><verify-metadata>true</verify-metadata></configuration>
   <components>
      <component group="com.example" name="fastqueue" version="1.3.0">
         <artifact name="fastqueue-1.3.0.jar"><sha256 value=\"""" + "1" * 64 + """\"/></artifact>
      </component>
      <component group="com.example" name="datekit" version="2.6.1">
         <artifact name="datekit-2.6.1.jar"><sha256 value=\"""" + "4" * 64 + """\"/></artifact>
      </component>
   </components>
</verification-metadata>
""",
            "src/main/java/com/example/Report.java": """package com.example;

import com.example.datekit.Dates;

public class Report {
    public String render(java.time.Instant at, String title) {
        return Dates.formatDate(at) + " " + title;
    }
}
""",
        },
        safe=r"com\.example:fastqueue:1\.3\.2", fresh=r"fastqueue:1\.4\.0",
        integrity=("gradle/verification-metadata.xml", r"<sha256 value="),
        callsite=("src/main/java/com/example/Report.java", "formatDate"),
        snap=dict(kind="Maven Central, group com.example", old="Dates.formatDate()", new="Dates.format()"),
    ),
    "gradle-kotlin-catalog": dict(
        dependabot="gradle", bot="dependabot", manifest="gradle/libs.versions.toml", lock="gradle.lockfile",
        tool="`./gradlew dependencies --write-locks`, not a hand edit",
        files={
            "settings.gradle.kts": 'rootProject.name = "report-service"\n',
            "build.gradle.kts": """plugins {
    java
}

dependencyLocking {
    lockAllConfigurations()
}

dependencies {
    implementation(libs.fastqueue)
    implementation(libs.datekit)
}
""",
            "gradle/libs.versions.toml": """[versions]
fastqueue = "1.3.0"
datekit = "2.6.1"

[libraries]
fastqueue = { module = "com.example:fastqueue", version.ref = "fastqueue" }
datekit = { module = "com.example:datekit", version.ref = "datekit" }
""",
            "gradle.lockfile": """# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
com.example:datekit:2.6.1=compileClasspath,runtimeClasspath
com.example:fastqueue:1.3.0=compileClasspath,runtimeClasspath
empty=
""",
            "src/main/kotlin/Report.kt": """import com.example.datekit.Dates

fun render(at: java.time.Instant, title: String) = "${Dates.formatDate(at)} $title"
""",
        },
        safe=r'fastqueue\s*=\s*"1\.3\.2"', fresh=r"fastqueue[^\n]*1\.4\.0",
        integrity=None,
        callsite=("src/main/kotlin/Report.kt", "formatDate"),
        snap=dict(kind="Maven Central, group com.example", old="Dates.formatDate()", new="Dates.format()"),
    ),
    "nuget-cpm": dict(
        dependabot="nuget", bot="renovate", manifest="Directory.Packages.props", lock="packages.lock.json",
        tool="`dotnet restore --force-evaluate` (CI: `dotnet restore --locked-mode`), not a hand edit",
        files={
            "Directory.Packages.props": """<Project>
  <PropertyGroup>
    <ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally>
  </PropertyGroup>
  <ItemGroup>
    <PackageVersion Include="Example.FastQueue" Version="1.3.0" />
    <PackageVersion Include="Example.DateKit" Version="2.6.1" />
  </ItemGroup>
</Project>
""",
            "Report/Report.csproj": """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net9.0</TargetFramework>
    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Example.FastQueue" />
    <PackageReference Include="Example.DateKit" />
  </ItemGroup>
</Project>
""",
            "Report/packages.lock.json": """{
  "version": 2,
  "dependencies": {
    "net9.0": {
      "Example.DateKit": {"type": "Direct", "requested": "[2.6.1, )", "resolved": "2.6.1", "contentHash": "SUM"},
      "Example.FastQueue": {"type": "Direct", "requested": "[1.3.0, )", "resolved": "1.3.0", "contentHash": "SUM"}
    }
  }
}
""",
            "Report/Report.cs": """using Example.DateKit;

public static class Report
{
    public static string Render(System.DateTime at, string title) => $"{Dates.FormatDate(at)} {title}";
}
""",
        },
        safe=r'Include="Example\.FastQueue" Version="1\.3\.2"', fresh=r"FastQueue[^\n]*1\.4\.0",
        integrity=("Report/packages.lock.json", r'"contentHash"'),
        callsite=("Report/Report.cs", "FormatDate"),
        snap=dict(kind="nuget.org", q="Example.FastQueue", d="Example.DateKit", old="Dates.FormatDate()",
                  new="Dates.Format()"),
    ),
    "bundler": dict(
        dependabot="bundler", bot="dependabot", manifest="Gemfile", lock="Gemfile.lock",
        tool="`bundle update fastqueue --conservative` (or `bundle lock --update fastqueue`), not a hand edit",
        files={
            "Gemfile": """source "https://rubygems.org"

gem "fastqueue", "1.3.0"
gem "datekit", "2.6.1"
""",
            "Gemfile.lock": """GEM
  remote: https://rubygems.org/
  specs:
    datekit (2.6.1)
    fastqueue (1.3.0)

PLATFORMS
  ruby

DEPENDENCIES
  datekit (= 2.6.1)
  fastqueue (= 1.3.0)

CHECKSUMS
  datekit (2.6.1) sha256=""" + "4" * 64 + """
  fastqueue (1.3.0) sha256=""" + "1" * 64 + """

BUNDLED WITH
   2.7.2
""",
            "lib/report.rb": """require "datekit"

module Report
  def self.render(row)
    "#{Datekit.format_date(row[:at])} #{row[:title]}"
  end
end
""",
        },
        safe=r'gem "fastqueue", "[~> =]*1\.3\.2"', fresh=r"fastqueue[^\n]*1\.4\.0",
        integrity=("Gemfile.lock", r"sha256="),
        callsite=("lib/report.rb", "format_date"),
        snap=dict(kind="rubygems.org", old="Datekit.format_date", new="Datekit.format"),
    ),
    "composer": dict(
        dependabot="composer", bot="renovate", manifest="composer.json", lock="composer.lock",
        tool="`composer update example/fastqueue --with-dependencies` (or `composer require "
             "example/fastqueue:1.3.2`), not a hand edit",
        files={
            "composer.json": """{
    "name": "example/report-service",
    "require": {
        "example/fastqueue": "1.3.0",
        "example/datekit": "2.6.1"
    }
}
""",
            "composer.lock": """{
    "content-hash": \"""" + "9" * 32 + """\",
    "packages": [
        {"name": "example/datekit", "version": "2.6.1", "dist": {"type": "zip", "url": "https://repo.packagist.org/example/datekit-2.6.1.zip", "shasum": \"""" + "4" * 40 + """\"}},
        {"name": "example/fastqueue", "version": "1.3.0", "dist": {"type": "zip", "url": "https://repo.packagist.org/example/fastqueue-1.3.0.zip", "shasum": \"""" + "1" * 40 + """\"}}
    ]
}
""",
            "src/Report.php": """<?php

namespace App;

use Example\\Datekit\\Dates;

final class Report
{
    public static function render(\\DateTimeInterface $at, string $title): string
    {
        return Dates::formatDate($at) . ' ' . $title;
    }
}
""",
        },
        safe=r'"example/fastqueue":\s*"[~^]?1\.3\.2"', fresh=r"fastqueue[^\n]*1\.4\.0",
        integrity=("composer.lock", r'"content-hash"'),
        callsite=("src/Report.php", "formatDate"),
        snap=dict(kind="Packagist", q="example/fastqueue", d="example/datekit", old="Dates::formatDate()",
                  new="Dates::format()"),
    ),
    "terraform": dict(
        dependabot="terraform", bot="dependabot", manifest="versions.tf", lock=".terraform.lock.hcl",
        tool="`terraform init -upgrade` then `terraform providers lock -platform=linux_amd64 "
             "-platform=darwin_arm64 …` for every platform used, not a hand edit",
        files={
            "versions.tf": """terraform {
  required_providers {
    fastqueue = {
      source  = "example/fastqueue"
      version = "1.3.0"
    }
  }
}
""",
            "main.tf": """module "schedule" {
  source  = "example/datekit/generic"
  version = "2.6.1"

  date_format = "iso8601"
}
""",
            ".terraform.lock.hcl": """# This file is maintained automatically by "terraform init".
# Manual edits may be lost in future updates.

provider "registry.terraform.io/example/fastqueue" {
  version     = "1.3.0"
  constraints = "1.3.0"
  hashes = [
    "h1:""" + "Q" * 43 + """=",
    "zh:""" + "1" * 64 + """",
  ]
}
""",
        },
        safe=r'version\s*=\s*"1\.3\.2"', fresh=r'version\s*=\s*"1\.4\.0"',
        integrity=(".terraform.lock.hcl", r'"h1:'),
        callsite=("main.tf", "date_format"),
        snap=dict(kind="Terraform Registry: provider example/fastqueue, module example/datekit/generic",
                  q="provider example/fastqueue", d="module example/datekit/generic",
                  old="input `date_format`", new="input `format`"),
    ),
    "helm": dict(
        dependabot="helm", bot="renovate", manifest="Chart.yaml", lock="Chart.lock",
        tool="`helm dependency update` (writes Chart.lock), not a hand edit",
        files={
            "Chart.yaml": """apiVersion: v2
name: report-service
version: 0.1.0
dependencies:
  - name: fastqueue
    version: 1.3.0
    repository: https://charts.example.com
  - name: datekit
    version: 2.6.1
    repository: https://charts.example.com
""",
            "Chart.lock": """dependencies:
- name: fastqueue
  repository: https://charts.example.com
  version: 1.3.0
- name: datekit
  repository: https://charts.example.com
  version: 2.6.1
digest: sha256:""" + "9" * 64 + """
generated: "2026-08-01T00:00:00Z"
""",
            "values.yaml": """datekit:
  dateFormat: iso8601
""",
        },
        safe=r"name: fastqueue\s+version: 1\.3\.2", fresh=r"version: 1\.4\.0",
        integrity=("Chart.lock", r"digest: sha256:"),
        callsite=("values.yaml", "dateFormat"),
        snap=dict(kind="Helm repository https://charts.example.com", old="value `datekit.dateFormat`",
                  new="value `datekit.format`"),
    ),
    "pre-commit": dict(
        dependabot="pre-commit", bot="renovate", manifest=".pre-commit-config.yaml", lock=None,
        tool="no lockfile: `pre-commit autoupdate --freeze` style SHA pins with a `# frozen: vX.Y.Z` comment, "
             "or a `rev:` the user chose; verify with `pre-commit run --all-files`",
        files={
            ".pre-commit-config.yaml": f"""repos:
  - repo: https://github.com/example/fastqueue-hooks
    rev: {SHA['q130']}  # frozen: v1.3.0
    hooks:
      - id: fastqueue-lint
  - repo: https://github.com/example/datekit-hooks
    rev: {SHA['d261']}  # frozen: v2.6.1
    hooks:
      - id: datekit-format-date
""",
        },
        safe=r"v1\.3\.2", fresh=r"v1\.4\.0", integrity=(".pre-commit-config.yaml", r"rev: [0-9a-f]{40}"),
        callsite=(".pre-commit-config.yaml", "datekit-format-date"),
        snap=dict(kind="GitHub repositories (tags → commit SHAs)", q="example/fastqueue-hooks",
                  d="example/datekit-hooks", old="hook id `datekit-format-date`", new="hook id `datekit-format`",
                  extra=f"\nTags → commits: fastqueue-hooks v1.4.0 = {SHA['q140']}, v1.3.2 = {SHA['q132']}, "
                        f"v1.3.0 = {SHA['q130']}; datekit-hooks v3.0.0 = {SHA['d300']}, v2.6.1 = {SHA['d261']}.\n"),
    ),
    "github-actions": dict(
        dependabot="github-actions", bot="dependabot", manifest=".github/workflows/ci.yml", lock=None,
        tool="no lockfile: full 40-character SHA pins with a `# vX.Y.Z` comment (`action-deps.py check` "
             "when gh can reach GitHub)",
        files={
            ".github/workflows/ci.yml": f"""name: CI
on: [push, pull_request]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: example/fastqueue-action@{SHA['q130']} # v1.3.0
      - uses: example/datekit-action@{SHA['d261']} # v2.6.1
        with:
          date-format: iso8601
""",
        },
        safe=r"fastqueue-action@" + SHA["q132"] + r" # v1\.3\.2", fresh=r"fastqueue-action@[0-9a-f]+ # v1\.4\.0",
        integrity=(".github/workflows/ci.yml", r"fastqueue-action@[0-9a-f]{40} # v"),
        callsite=(".github/workflows/ci.yml", "date-format"),
        snap=dict(kind="GitHub releases (tags → commit SHAs)", q="example/fastqueue-action",
                  d="example/datekit-action", old="input `date-format`", new="input `format`",
                  extra=f"\nTags → commits: fastqueue-action v1.4.0 = {SHA['q140']}, v1.3.2 = {SHA['q132']}, "
                        f"v1.3.0 = {SHA['q130']}; datekit-action v3.0.0 = {SHA['d300']}, v2.6.1 = {SHA['d261']}. "
                        "All are lightweight tags on commits.\n"),
    ),
    "containers": dict(
        dependabot="docker", bot="dependabot", manifest="compose.yaml", lock=None,
        tool="no lockfile: `tag@sha256:<index digest>` pins (index digest from `docker buildx imagetools "
             "inspect` / `crane digest`)",
        files={
            "Dockerfile": "FROM ghcr.io/example/fastqueue:1.3.0@sha256:" + "1" * 64 + "\n"
                          "COPY app /app\n",
            "compose.yaml": """services:
  queue:
    image: ghcr.io/example/fastqueue:1.3.0@sha256:""" + "1" * 64 + """
  dates:
    image: ghcr.io/example/datekit:2.6.1@sha256:""" + "4" * 64 + """
    environment:
      DATEKIT_DATE_FORMAT: iso8601
""",
            "k8s/deployment.yaml": """apiVersion: apps/v1
kind: Deployment
metadata:
  name: queue
spec:
  template:
    spec:
      containers:
        - name: queue
          image: ghcr.io/example/fastqueue:1.3.0@sha256:""" + "1" * 64 + """
""",
        },
        safe=r"fastqueue:1\.3\.2@sha256:" + "2" * 64, fresh=r"fastqueue:1\.4\.0",
        integrity=("compose.yaml", r"fastqueue:[0-9.]+@sha256:[0-9a-f]{64}"),
        callsite=("compose.yaml", "DATEKIT_DATE_FORMAT"),
        snap=dict(kind="ghcr.io image tags (Created time, multi-arch index digest)", q="ghcr.io/example/fastqueue",
                  d="ghcr.io/example/datekit", old="env var `DATEKIT_DATE_FORMAT`", new="`DATEKIT_FORMAT`",
                  extra="\nIndex digests: fastqueue 1.4.0 = sha256:" + "3" * 64 + ", 1.3.2 = sha256:" + "2" * 64
                        + ", 1.3.0 = sha256:" + "1" * 64 + "; datekit 3.0.0 = sha256:" + "5" * 64
                        + ", 2.6.1 = sha256:" + "4" * 64 + ".\n"),
    ),
}

PROMPT = ("Update this project's dependencies to the newest versions our policy allows, and tell me what "
          "you changed and anything you need me to decide. The package registry isn't reachable from this "
          "environment: `REGISTRY_SNAPSHOT.md` is an export of its metadata taken a few minutes ago. Make the "
          "manifest and config changes here; for anything that needs the registry, such as regenerating a "
          "lockfile, give me the exact command and I'll run it on a machine that can reach it.")

NO_NET = ("The eval sandbox has no registry access, so the ecosystem tool cannot resolve packages: graders "
          "accept the exact command the agent ran or proposes for the lockfile, and check the manifest diff.")


def scaffold(files, snap):
    out = ["#!/usr/bin/env bash", "# Generated by build.py. Writes the fixture project into the empty workspace.",
           "set -euo pipefail",
           'ago() { python3 -c \'import datetime as d,sys; print((d.datetime.now(d.timezone.utc) - '
           'd.timedelta(hours=float(sys.argv[1]))).strftime("%Y-%m-%dT%H:%MZ"))\' "$1"; }',
           "T20H=$(ago 20); T9D=$(ago 216); T60D=$(ago 1440); T40D=$(ago 960); T90D=$(ago 2160)", ""]
    for path, text in files.items():
        if "/" in path:
            out.append(f"mkdir -p '{path.rsplit('/', 1)[0]}'")
        out += [f"cat > '{path}' <<'FIXTURE'", text.replace("SUM", SUM).rstrip("\n"), "FIXTURE"]
    snap = snap.replace("\\", "\\\\").replace("`", "\\`")  # only ${T…} may expand in this heredoc
    out += ["cat > REGISTRY_SNAPSHOT.md <<SNAPSHOT", snap.rstrip("\n"), "SNAPSHOT",
            "git init -q && git add -A && git -c user.name=fixture -c user.email=fixture@example.com "
            "commit -qm fixture", ""]
    return "\n".join(out)


def graders(name, e):
    g = [{"name": "skill-used", "type": "tool_used", "tool": "Skill", "input_match": "dependency-updates"}]
    g.append({"name": "manifest-updated", "type": "regex", "pattern": e["safe"],
              "target": {"source": "file", "path": e["manifest"]}})
    g.append({"name": "fresh-release-not-adopted", "type": "regex", "pattern": e["fresh"], "match": "not_contains",
              "target": {"source": "file", "path": e["manifest"]}})
    g.append({"name": "age-gate", "type": "llm", "criteria": (
        "PASS if the reply keeps fastqueue at 1.3.2 (or holds it below 1.4.0) because 1.4.0 was published "
        "less than 72 hours ago, and says so. FAIL if it adopts 1.4.0, or never mentions the release age.")})
    if e["lock"]:
        base = e["lock"].rsplit("/", 1)[-1].replace(".", r"\.")
        for tool in ("Edit", "Write"):
            g.append({"name": f"lockfile-not-hand-edited-{tool.lower()}", "type": "tool_used", "tool": tool,
                      "input_match": base, "min": 0, "max": 0, "arm": "both"})
    g.append({"name": "lockfile-tool", "type": "llm", "criteria": (
        f"The ecosystem's way to record the new versions is: {e['tool']}. PASS if the reply ran that "
        "command, or (because the registry is unreachable) gives the user that exact command to run, and "
        "does not claim to have edited a lockfile by hand. FAIL if it says it edited the lockfile directly, "
        "or gives no way to bring the lockfile/pins in line with the manifest.")})
    f, api = e["callsite"]
    g.append({"name": "call-site", "type": "llm", "criteria": (
        f"datekit 3.0.0 renames/removes `{api}`, which this project uses in `{f}`. PASS if the reply names "
        f"`{f}` (a line number is welcome) as the place using `{api}`, and either updates that use together "
        "with the bump or holds datekit on 2.x and sets out the options (upgrade and adapt / stay on 2.x) "
        "for the user to choose. FAIL if it bumps datekit to 3.0.0 without mentioning that call site, or "
        "says the major upgrade needs no code changes.")})
    if e["integrity"]:
        path, rx = e["integrity"]
        g.append({"name": "integrity-kept", "type": "regex", "pattern": rx, "target": {"source": "file", "path": path}})
    bot = "Dependabot (.github/dependabot.yml)" if e["bot"] == "dependabot" else "Renovate (renovate.json)"
    for tool in ("Edit", "Write"):
        g.append({"name": f"bot-config-untouched-{tool.lower()}", "type": "tool_used", "tool": tool,
                  "input_match": "dependabot|renovate", "min": 0, "max": 0, "arm": "both"})
    g.append({"name": "bot-noticed", "type": "llm", "criteria": (
        f"PASS if the reply mentions that {bot} is configured for this repository (for example its cooldown, "
        "or that its PRs may overlap these changes). FAIL if it never mentions the update bot, or says it "
        "changed the bot's configuration.")})
    return g


def write_case(name, e, prompt=PROMPT, description=None, keep=None, extra=()):
    """keep: names of the standard graders to keep (default all); extra: graders to add."""
    d = HERE / name
    if d.exists():
        shutil.rmtree(d)
    d.mkdir()
    files = dict(e["files"])
    if e["bot"] == "dependabot":
        files[".github/dependabot.yml"] = DEPENDABOT.format(eco=e["dependabot"])
    else:
        files["renovate.json"] = RENOVATE
    # bytes, so the scaffold keeps LF line ends (bash rejects CRLF) when generated on Windows
    (d / "setup.sh").write_bytes(scaffold(files, snapshot(**e["snap"])).encode("utf-8"))
    (d / "setup.sh").chmod(0o755)
    notes = NO_NET if e["lock"] else NO_NET.replace("for the lockfile", "for the pins") + \
        f" This ecosystem has no lockfile ({e['tool'].split(':', 1)[1].strip()})."
    case = {
        "schema_version": "1.1", "name": name,
        "description": description or f"{name}: update with a fresh release behind the 72-hour gate and a "
                                      "breaking major (datekit 3.0.0) whose renamed API the project calls.",
        "tags": ["ecosystem", name],
        "expected_outcome": notes,
        "runs": 3,
        "execution": {"prompt": prompt, "max_turns": 60, "timeout_seconds": 900,
                      "allowed_tools": ["Read", "Glob", "Grep", "Skill", "Edit", "Write", "Bash"]},
        "context": {"scaffold_script": "setup.sh"},
        "graders": [x for x in graders(name, e) if keep is None or x["name"] in keep] + list(extra),
    }
    (d / "case.yaml").write_bytes(("# Generated by build.py; edit the ECOSYSTEMS table there, not this file.\n"
                                   + json_to_yaml(case)).encode("utf-8"))


def json_to_yaml(obj):
    """case.yaml as YAML without needing PyYAML here (JSON values are valid YAML scalars)."""
    def emit(o, ind=0):
        pad = "  " * ind
        if isinstance(o, dict):
            lines = []
            for k, v in o.items():
                if isinstance(v, (dict, list)) and v:
                    lines.append(f"{pad}{k}:")
                    lines += emit(v, ind + 1)
                else:
                    lines.append(f"{pad}{k}: {json.dumps(v)}")
            return lines
        lines = []
        for item in o:
            sub = emit(item, ind + 1) if isinstance(item, (dict, list)) else [f"{pad}  {json.dumps(item)}"]
            if isinstance(item, dict):
                sub[0] = f"{pad}- " + sub[0].lstrip()
                lines += sub
            else:
                lines.append(f"{pad}- {json.dumps(item)}")
        return lines
    return "\n".join(emit(obj)) + "\n"


def write_tradeoff():
    """The security fix exists only in a release younger than 72 hours: set out the trade-off."""
    e = dict(ECOSYSTEMS["npm"])
    e["snap"] = dict(e["snap"], extra=(
        "\n## Advisory\n\nGHSA-xxxx-0000-example (high): @example/fastqueue < 1.4.0 lets a crafted job "
        "payload run arbitrary code. Fixed in 1.4.0 only; 1.3.2 is affected.\n"))
    write_case(
        "npm-advisory-fresh-fix", e,
        prompt="We got a high-severity advisory for @example/fastqueue. Fix it. The package registry isn't "
               "reachable from this environment: `REGISTRY_SNAPSHOT.md` is an export of its metadata taken a "
               "few minutes ago.",
        description="npm-advisory-fresh-fix: the only fix for an advisory is a release younger than 72 hours.",
        keep={"skill-used", "lockfile-not-hand-edited-edit", "lockfile-not-hand-edited-write", "integrity-kept",
              "bot-config-untouched-edit", "bot-config-untouched-write"},
        extra=[
            {"name": "trade-off", "type": "llm", "criteria": (
                "The only fixed version (1.4.0) was published about 20 hours ago, inside the 72-hour gate. PASS "
                "if the reply sets out the trade-off (exposure to the known vulnerability vs exposure to a "
                "release younger than 72 hours) and lets the user choose, or applies 1.4.0 only after stating "
                "that it overrides the gate and why. FAIL if it silently upgrades to 1.4.0, or silently stays "
                "on 1.3.x.")},
            {"name": "no-false-fix", "type": "llm",
             "criteria": "FAIL if the reply claims 1.3.2 (or anything below 1.4.0) fixes the advisory. PASS otherwise."},
        ])


if __name__ == "__main__":
    for name, e in ECOSYSTEMS.items():
        write_case(name, e)
    write_tradeoff()
    print(f"wrote {len(ECOSYSTEMS) + 1} cases in {HERE}")
