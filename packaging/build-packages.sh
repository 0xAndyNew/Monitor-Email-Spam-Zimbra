#!/usr/bin/env bash
# ==============================================================================
# PACKAGE BUILDER SCRIPT (.RPM AND .DEB)
# Run this script to rebuild .rpm and .deb packages from source.
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if command -v python3 >/dev/null 2>&1; then
    python3 "$SCRIPT_DIR/build_rpm_deb.py"
elif command -v python >/dev/null 2>&1; then
    python "$SCRIPT_DIR/build_rpm_deb.py"
else
    echo "Error: Python 3 is required to build packages."
    exit 1
fi
