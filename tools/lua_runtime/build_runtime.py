#!/usr/bin/env python3
"""Build the ignored browser bundle from the locked Fengari sources."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys


RUNTIME_DIR = Path(__file__).resolve().parent
ROOT = RUNTIME_DIR.parents[1]
OUTPUT = ROOT / "src" / "lua-vm.js"
NODE_MODULES = RUNTIME_DIR / "node_modules"
PACKAGE_JSON = RUNTIME_DIR / "package.json"


def inputs():
    for path in RUNTIME_DIR.rglob("*"):
        if not path.is_file():
            continue
        if "node_modules" in path.parts or "__pycache__" in path.parts:
            continue
        if path.suffix in (".js", ".lua", ".json"):
            yield path


def is_current():
    if not OUTPUT.is_file():
        return False
    output_time = OUTPUT.stat().st_mtime_ns
    return all(path.stat().st_mtime_ns <= output_time for path in inputs())


def run_npm(npm, *args):
    subprocess.run([npm, *args], cwd=ROOT, check=True)


def dependencies_are_installed():
    try:
        manifest = json.loads(PACKAGE_JSON.read_text())
        locked = json.loads((RUNTIME_DIR / "package-lock.json").read_text())["packages"]
        installed_packages = json.loads(
            (NODE_MODULES / ".package-lock.json").read_text()
        )["packages"]
        for path, package in installed_packages.items():
            if not path:
                continue
            expected = locked.get(path)
            if expected is None:
                return False
            for field in ("version", "resolved", "integrity"):
                if package.get(field) != expected.get(field):
                    return False
        for path, package in locked.items():
            if path and not package.get("optional") and path not in installed_packages:
                return False
        for group in ("dependencies", "devDependencies"):
            for name, version in manifest.get(group, {}).items():
                package_json = NODE_MODULES.joinpath(*name.split("/"), "package.json")
                installed_manifest = json.loads(package_json.read_text())
                if installed_manifest.get("version") != version:
                    return False
        return True
    except (OSError, ValueError):
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="rebuild even when the bundle is current")
    args = parser.parse_args(argv)

    if not args.force and is_current():
        print("Lua runtime bundle is up to date.")
        return 0

    npm = shutil.which("npm")
    node = shutil.which("node")
    if not npm or not node:
        print("Building the Lua runtime requires Node.js 18+ and npm.", file=sys.stderr)
        return 1
    node_version = subprocess.check_output([node, "--version"], text=True).strip()
    try:
        node_major = int(node_version.lstrip("v").split(".", 1)[0])
    except ValueError:
        node_major = 0
    if node_major < 18:
        print("Building the Lua runtime requires Node.js 18+ and npm.", file=sys.stderr)
        return 1

    if not dependencies_are_installed():
        print("Installing locked Lua runtime build dependencies...")
        run_npm(npm, "ci", "--prefix", str(RUNTIME_DIR))

    run_npm(npm, "run", "build", "--prefix", str(RUNTIME_DIR))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
