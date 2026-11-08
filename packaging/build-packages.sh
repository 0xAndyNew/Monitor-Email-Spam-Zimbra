#!/usr/bin/env bash
# ==============================================================================
# SCRIPT ĐÓNG GÓI LẠI FILE .RPM VÀ .DEB (build-packages.sh)
# Chạy lệnh này nếu anh muốn tự đóng gói lại file .rpm và .deb sau khi sửa code
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if command -v python3 >/dev/null 2>&1; then
    python3 "$SCRIPT_DIR/build_rpm_deb.py"
elif command -v python >/dev/null 2>&1; then
    python "$SCRIPT_DIR/build_rpm_deb.py"
else
    echo "Lỗi: Cần cài đặt Python 3 để chạy trình đóng gói."
    exit 1
fi
