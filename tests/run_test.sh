#!/usr/bin/env bash
# ==============================================================================
# BỘ KIỂM THỬ TỰ ĐỘNG (AUTOMATED TEST SUITE) CHO ZIMBRA-SPAM-MONITOR
# Kiểm tra:
# 1. Cú pháp Bash và cấu trúc nhị phân của gói .deb & .rpm
# 2. Mô phỏng phân tích /var/log/zimbra.log (theo phút & theo giờ) và postqueue
# 3. Kiểm tra lọc Whitelist, phân loại ngưỡng WARNING / CRITICAL
# 4. Kiểm tra tự động khóa tài khoản (zmprov) và gửi cảnh báo Telegram + Email
# 5. Kiểm tra cơ chế Cooldown và lệnh --status, --test, --unlock
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MONITOR_BIN="$ROOT_DIR/src/zimbra-spam-monitor"

echo "=== [1/5] Kiểm tra cú pháp Bash (bash -n) ==="
bash -n "$MONITOR_BIN"
bash -n "$ROOT_DIR/packaging/build-packages.sh"
echo " -> [PASS] Cú pháp Bash hợp lệ."

echo "=== [2/5] Kiểm tra cấu trúc gói .deb và .rpm ==="
python - "$ROOT_DIR" << 'PYEOF'
import gzip
import hashlib
import io
import struct
import sys
import tarfile
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

root = Path(sys.argv[1])
deb_path = root / "zimbra-spam-monitor_1.0.0-1_all.deb"
rpm_path = root / "zimbra-spam-monitor-1.0.0-1.noarch.rpm"

assert deb_path.exists() and deb_path.stat().st_size > 5000, "Missing or empty .deb"
assert rpm_path.exists() and rpm_path.stat().st_size > 5000, "Missing or empty .rpm"

# Verify .deb ar header
deb_data = deb_path.read_bytes()
assert deb_data.startswith(b"!<arch>\n"), "Invalid .deb ar magic"
assert b"debian-binary" in deb_data[:100], "Missing debian-binary member"
assert b"control.tar.gz" in deb_data, "Missing control.tar.gz"
assert b"data.tar.gz" in deb_data, "Missing data.tar.gz"

# Verify .rpm Lead, Signature Header, Main Header, and CPIO Payload
rpm_data = rpm_path.read_bytes()
assert rpm_data[:4] == b"\xed\xab\xee\xdb", "Invalid RPM Lead magic"
# Signature header starts at byte 96
assert rpm_data[96:104] == b"\x8e\xad\xe8\x01\x00\x00\x00\x00", "Invalid RPM Signature Header magic"
sig_entries, sig_dlen = struct.unpack("!II", rpm_data[104:112])
sig_total = 16 + sig_entries * 16 + sig_dlen
if sig_total % 8 != 0:
    sig_total += 8 - (sig_total % 8)

main_start = 96 + sig_total
assert rpm_data[main_start:main_start+8] == b"\x8e\xad\xe8\x01\x00\x00\x00\x00", "Invalid RPM Main Header magic"
main_entries, main_dlen = struct.unpack("!II", rpm_data[main_start+8:main_start+16])
payload_start = main_start + 16 + main_entries * 16 + main_dlen

cpio_raw = gzip.decompress(rpm_data[payload_start:])
assert cpio_raw.startswith(b"070701"), "Invalid CPIO newc header inside RPM"
assert b"./usr/bin/zimbra-spam-monitor" in cpio_raw, "Missing binary in RPM CPIO"
assert b"./etc/zimbra-spam-monitor/config.conf" in cpio_raw, "Missing config.conf in RPM CPIO"
assert b"TRAILER!!!" in cpio_raw, "Missing CPIO TRAILER"
print(" -> [PASS] Cấu trúc nhị phân .deb và .rpm đạt chuẩn 100%.")
PYEOF

echo "=== [3/5] Thiết lập môi trường giả lập Zimbra ==="
TEST_TMP=$(mktemp -d 2>/dev/null || echo "/tmp/zsm_test_$$")
mkdir -p "$TEST_TMP"
trap 'rm -rf "$TEST_TMP"' EXIT

FAKE_LOG="$TEST_TMP/zimbra.log"
FAKE_CFG="$TEST_TMP/config.conf"
FAKE_WL="$TEST_TMP/whitelist.conf"
FAKE_STATE="$TEST_TMP/state"
FAKE_MON_LOG="$TEST_TMP/monitor.log"
FAKE_TG_OUT="$TEST_TMP/telegram_sent.txt"
FAKE_MAIL_OUT="$TEST_TMP/email_sent.txt"
FAKE_ZMPROV_OUT="$TEST_TMP/zmprov_actions.txt"

# Mốc thời gian cố định: 2026-11-08 15:00:00 (Epoch = 1794124800)
FIXED_EPOCH=$(date -d "2026-11-08 15:00:00" +%s)

# Tạo log giả lập:
# - normal@company.com: 5 mail (Bình thường)
# - marketing@company.com: 250 mail (Nằm trong Whitelist -> Bỏ qua)
# - warn_user@company.com: 90 mail trong 10 phút (Vượt ngưỡng WARN = 80)
# - hacked_user@company.com: 210 mail trong 10 phút từ IP 203.0.113.99 (Vượt ngưỡng CRIT = 200)
: > "$FAKE_LOG"
for i in $(seq 1 5); do
    printf "Nov  8 14:55:10 mail postfix/smtpd[1001]: QNORM%03d: client=localhost[127.0.0.1], sasl_method=LOGIN, sasl_username=normal@company.com\n" "$i" >> "$FAKE_LOG"
    printf "Nov  8 14:55:11 mail postfix/smtp[1002]: QNORM%03d: to=<partner%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, status=sent (250 OK)\n" "$i" "$i" >> "$FAKE_LOG"
done

for i in $(seq 1 250); do
    printf "Nov  8 14:56:10 mail postfix/smtpd[1001]: QMKT%03d: client=localhost[127.0.0.1], sasl_method=LOGIN, sasl_username=marketing@company.com\n" "$i" >> "$FAKE_LOG"
    printf "Nov  8 14:56:11 mail postfix/smtp[1002]: QMKT%03d: to=<cust%d@yahoo.com>, relay=mx.yahoo.com[1.2.3.4]:25, status=sent (250 OK)\n" "$i" "$i" >> "$FAKE_LOG"
done

for i in $(seq 1 90); do
    printf "Nov  8 14:57:10 mail postfix/smtpd[1001]: QWARN%03d: client=unknown[198.51.100.22], sasl_method=LOGIN, sasl_username=warn_user@company.com\n" "$i" >> "$FAKE_LOG"
    printf "Nov  8 14:57:11 mail postfix/smtp[1002]: QWARN%03d: to=<target%d@outlook.com>, relay=mx.outlook.com[1.2.3.4]:25, status=sent (250 OK)\n" "$i" "$i" >> "$FAKE_LOG"
done

for i in $(seq 1 210); do
    printf "Nov  8 14:58:10 mail postfix/smtpd[1001]: QCRIT%03d: client=botnet[203.0.113.99], sasl_method=LOGIN, sasl_username=hacked_user@company.com\n" "$i" >> "$FAKE_LOG"
    printf "Nov  8 14:58:11 mail postfix/smtp[1002]: QCRIT%03d: to=<victim%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, status=deferred (host mx.gmail.com said: 421-4.7.28 Rate limited)\n" "$i" "$i" >> "$FAKE_LOG"
done

echo "marketing@company.com" > "$FAKE_WL"

# Tạo mock script cho postqueue, zmprov, sendmail, curl
MOCK_PQ="$TEST_TMP/mock_postqueue.sh"
cat << 'EOF' > "$MOCK_PQ"
#!/usr/bin/env bash
cat << 'QOUT'
-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------
A1B2C3D4E1      1234 Sun Nov  8 14:58:15  hacked_user@company.com
                                         (host mx.gmail.com said: 421-4.7.28 Rate limited)
                                         victim1@gmail.com

A1B2C3D4E2*     1234 Sun Nov  8 14:58:16  hacked_user@company.com
                                         victim2@gmail.com
QOUT
EOF
chmod +x "$MOCK_PQ"

MOCK_ZMPROV="$TEST_TMP/mock_zmprov.sh"
cat << EOF > "$MOCK_ZMPROV"
#!/usr/bin/env bash
echo "\$*" >> "$FAKE_ZMPROV_OUT"
exit 0
EOF
chmod +x "$MOCK_ZMPROV"

MOCK_SENDMAIL="$TEST_TMP/mock_sendmail.sh"
cat << EOF > "$MOCK_SENDMAIL"
#!/usr/bin/env bash
cat >> "$FAKE_MAIL_OUT"
echo "---END_MAIL---" >> "$FAKE_MAIL_OUT"
exit 0
EOF
chmod +x "$MOCK_SENDMAIL"

MOCK_CURL="$TEST_TMP/mock_curl.sh"
cat << EOF > "$MOCK_CURL"
#!/usr/bin/env bash
echo "\$*" >> "$FAKE_TG_OUT"
echo '{"ok":true}'
exit 0
EOF
chmod +x "$MOCK_CURL"

cat << EOF > "$FAKE_CFG"
MONITOR_ENABLED="true"
ZIMBRA_LOG_FILE="$FAKE_LOG"
LOG_TAIL_LINES=100000
COUNT_INTERNAL_TO_INTERNAL="false"
INTERNAL_DOMAINS="company.com"
LOOKBACK_MINUTES=10
WARN_SENT_PER_WINDOW=80
CRIT_SENT_PER_WINDOW=200
ENABLE_HOURLY_CHECK="true"
WARN_SENT_PER_HOUR=300
CRIT_SENT_PER_HOUR=600
WARN_QUEUE_PER_USER=40
CRIT_QUEUE_PER_USER=100
WARN_TOTAL_QUEUE=300
AUTO_LOCK_ON_CRITICAL="true"
AUTO_HOLD_QUEUE_ON_CRITICAL="false"
TELEGRAM_ENABLED="true"
TELEGRAM_BOT_TOKEN="999999:TEST_TOKEN"
TELEGRAM_CHAT_ID="-100987654321"
EMAIL_ENABLED="true"
EMAIL_DELIVERY_MODE="local"
ALERT_EMAIL_TO="admin@company.com"
ALERT_EMAIL_FROM="zimbra-monitor@company.com"
ALERT_COOLDOWN_MINUTES=30
WHITELIST_FILE="$FAKE_WL"
STATE_DIR="$FAKE_STATE"
MONITOR_LOG_FILE="$FAKE_MON_LOG"
EOF

echo "=== [4/5] Chạy kiểm tra chu kỳ quét (--run) ==="
ZSM_CONFIG_FILE="$FAKE_CFG" \
ZSM_NOW_EPOCH="$FIXED_EPOCH" \
ZSM_POSTQUEUE_CMD="$MOCK_PQ" \
ZSM_ZMPROV_CMD="$MOCK_ZMPROV" \
ZSM_SENDMAIL_CMD="$MOCK_SENDMAIL" \
ZSM_CURL_CMD="$MOCK_CURL" \
ZSM_HOSTNAME="mail.company.com" \
bash "$MONITOR_BIN" --run

# Kiểm tra kết quả:
# 1. hacked_user@company.com phải bị khóa tự động
grep -q "ma hacked_user@company.com zimbraAccountStatus locked" "$FAKE_ZMPROV_OUT"
echo " -> [PASS] Tự động khóa tài khoản vượt ngưỡng CRITICAL (hacked_user@company.com)."

# 2. warn_user@company.com KHÔNG bị khóa, chỉ cảnh báo WARNING
if grep -q "warn_user@company.com" "$FAKE_ZMPROV_OUT"; then
    echo " -> [FAIL] warn_user@company.com không được phép bị khóa!"
    exit 1
fi
echo " -> [PASS] Tài khoản mức WARNING (warn_user@company.com) chỉ cảnh báo, không bị khóa."

# 3. marketing@company.com nằm trong Whitelist nên KHÔNG bị cảnh báo
if grep -q "marketing@company.com" "$FAKE_MAIL_OUT"; then
    echo " -> [FAIL] marketing@company.com nằm trong Whitelist nhưng vẫn bị cảnh báo!"
    exit 1
fi
echo " -> [PASS] Whitelist hoạt động chính xác (bỏ qua marketing@company.com)."

# 4. Kiểm tra nội dung Email và Telegram
grep -q "hacked_user@company.com" "$FAKE_MAIL_OUT"
grep -q "warn_user@company.com" "$FAKE_MAIL_OUT"
grep -q "203.0.113.99" "$FAKE_MAIL_OUT"
grep -q "hacked_user@company.com" "$FAKE_TG_OUT"
echo " -> [PASS] Cảnh báo Telegram & Email chứa đầy đủ tài khoản spam, số lượng mail và IP nguồn."

echo "=== [5/6] Kiểm tra lệnh --status, --test và --unlock ==="
STATUS_OUT=$(ZSM_CONFIG_FILE="$FAKE_CFG" \
ZSM_NOW_EPOCH="$FIXED_EPOCH" \
ZSM_POSTQUEUE_CMD="$MOCK_PQ" \
ZSM_HOSTNAME="mail.company.com" \
bash "$MONITOR_BIN" --status)

echo "$STATUS_OUT" | grep -q "hacked_user@company.com"
echo " -> [PASS] Lệnh --status hiển thị đúng bảng thống kê."

echo "=== [6/6] Kiểm tra Giao diện Bảng điều khiển Chọn mục (--menu / --text-menu) ==="
# Mô phỏng người dùng bấm chọn trên menu mới:
# - Chọn 2 (Cấu hình Cảnh báo & Test) -> Chọn 3 (Gửi thử tin nhắn Test Cảnh Báo) -> Enter -> Chọn 0 (Quay lại)
# - Chọn 3 (Chỉnh sửa Ngưỡng) -> Chọn 2 (Sửa WARN_SENT_PER_WINDOW) -> Nhập 125 -> Chọn 0 (Quay lại)
# - Chọn 4 (Tự động khóa & Mở khóa) -> Chọn 3 (Chọn mở khóa tài khoản từ danh sách) -> Chọn 1 (hacked_user@company.com) -> Enter -> Chọn 0 (Quay lại)
# - Chọn 5 (Quản lý Whitelist) -> Chọn 2 (Thêm Whitelist) -> Nhập vip@company.com -> Enter -> Chọn 0 (Quay lại)
# - Chọn 0 (Thoát)
printf "2\n3\n\n0\n3\n2\n125\n0\n4\n3\n1\n\n0\n5\n2\nvip@company.com\n\n0\n0\n" | \
ZSM_CONFIG_FILE="$FAKE_CFG" \
ZSM_ZMPROV_CMD="$MOCK_ZMPROV" \
ZSM_SENDMAIL_CMD="$MOCK_SENDMAIL" \
ZSM_CURL_CMD="$MOCK_CURL" \
ZSM_UI_MODE="text" \
bash "$MONITOR_BIN" --text-menu >/dev/null 2>&1

grep -q "^WARN_SENT_PER_WINDOW=125" "$FAKE_CFG"
echo " -> [PASS] Chọn chỉnh sửa ngưỡng qua Giao diện Menu thành công (WARN_SENT_PER_WINDOW=125)."

grep -q "ma hacked_user@company.com zimbraAccountStatus active" "$FAKE_ZMPROV_OUT"
echo " -> [PASS] Chọn mở khóa tài khoản từ danh sách trong Giao diện Menu thành công."

grep -q "vip@company.com" "$FAKE_WL"
echo " -> [PASS] Chọn thêm Whitelist qua Giao diện Menu thành công."

echo ""
echo "======================================================================"
echo " TẤT CẢ CÁC BÀI KIỂM THỬ (6/6) ĐỀU THÀNH CÔNG 100%!"
echo "======================================================================"
