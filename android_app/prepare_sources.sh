#!/usr/bin/env bash
#
# Copies shared source files from the project root into android_app/
# so that `flet build apk` can package them.
#
# Run from the repository root:
#   bash android_app/prepare_sources.sh
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Copying shared sources into android_app/ ..."

cp "$ROOT_DIR/data_cap.py" "$SCRIPT_DIR/data_cap.py"

mkdir -p "$SCRIPT_DIR/utility"
touch "$SCRIPT_DIR/utility/__init__.py"
cp "$ROOT_DIR/utility/base32.py" "$SCRIPT_DIR/utility/base32.py"
cp "$ROOT_DIR/utility/dns.py"    "$SCRIPT_DIR/utility/dns.py"

echo "Done. You can now run:  cd android_app && flet build apk"
