#!/usr/bin/env bash
# Build dist/homecore-os-<version>.zip (the installation kit). Run from the repo.
set -Eeuo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
version=$(cat VERSION)
name="homecore-os-$version"
mkdir -p dist
python3 - "$name" <<'PY'
import os, sys, zipfile
name = sys.argv[1]
include = ["README.md", "LICENSE", "VERSION", "cli", "docs", "scripts", "stack", "system"]
out = f"dist/{name}.zip"
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for item in include:
        paths = [item] if os.path.isfile(item) else [
            os.path.join(r, f) for r, _, fs in os.walk(item) for f in fs if "__pycache__" not in r]
        for p in sorted(paths):
            info = zipfile.ZipInfo.from_file(p, f"{name}/{p}")
            info.compress_type = zipfile.ZIP_DEFLATED
            with open(p, "rb") as fh:
                z.writestr(info, fh.read())   # keeps the executable bits
print(out)
PY
(cd dist && sha256sum "$name.zip" >"$name.zip.sha256")
echo "dist/$name.zip.sha256"
