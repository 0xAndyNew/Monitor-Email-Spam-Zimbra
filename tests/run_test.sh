#!/usr/bin/env bash
# ==============================================================================
# AUTOMATED TEST SUITE FOR ZIMBRA-SPAM-MONITOR
# Verifies:
# 1. Bash syntax & 100% ASCII encoding check (zero font/locale issues)
# 2. Binary structure of .deb & .rpm packages
# 3. Simulated /var/log/zimbra.log (short-window & hourly) and postqueue analysis
# 4. Whitelist filtering, WARNING / CRITICAL thresholds, auto-lock, Telegram & Email
# 5. Interactive Control Panel Menu (--text-menu) navigation & edits
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MONITOR_BIN="$ROOT_DIR/src/zimbra-spam-monitor"

echo "=== [1/6] Checking Bash syntax (bash -n) ==="
bash -n "$MONITOR_BIN"
bash -n "$ROOT_DIR/packaging/build-packages.sh"
echo " -> [PASS] Bash syntax is valid."

echo "=== [2/6] Verifying 100% ASCII-safe encoding & .deb / .rpm binary structure ==="
PY_CMD="python"
if python3 --version >/dev/null 2>&1; then
    PY_CMD="python3"
fi

"$PY_CMD" - "$ROOT_DIR" << 'PYEOF'
import gzip
import struct
import sys
from pathlib import Path

root = Path(sys.argv[1])

# Verify 100% pure ASCII across all packaged runtime/config files
ascii_files = [
    root / "src" / "zimbra-spam-monitor",
    root / "config" / "config.conf",
    root / "config" / "whitelist.conf",
    root / "packaging" / "cron.d" / "zimbra-spam-monitor",
    root / "packaging" / "logrotate.d" / "zimbra-spam-monitor",
    root / "packaging" / "zimbra-spam-monitor.spec",
]
for f in ascii_files:
    raw = f.read_bytes()
    non_ascii = [b for b in raw if b > 127]
    assert not non_ascii, f"Non-ASCII bytes found in {f}"

deb_path = root / "zimbra-spam-monitor_1.1.1-1_all.deb"
rpm_path = root / "zimbra-spam-monitor-1.1.1-1.noarch.rpm"

assert deb_path.exists() and deb_path.stat().st_size > 5000, "Missing or empty .deb"
assert rpm_path.exists() and rpm_path.stat().st_size > 5000, "Missing or empty .rpm"

deb_data = deb_path.read_bytes()
assert deb_data.startswith(b"!<arch>\n"), "Invalid .deb ar magic"
assert b"debian-binary" in deb_data[:100], "Missing debian-binary member"
assert b"control.tar.gz" in deb_data, "Missing control.tar.gz"
assert b"data.tar.gz" in deb_data, "Missing data.tar.gz"

rpm_data = rpm_path.read_bytes()
assert rpm_data[:4] == b"\xed\xab\xee\xdb", "Invalid RPM Lead magic"
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
print(" -> [PASS] 100% ASCII encoding & valid .deb / .rpm binary structures verified.")
PYEOF

echo "=== [3/6] Setting up simulated Zimbra environment ==="
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

FIXED_EPOCH=$(date -d "2026-11-08 15:00:00" +%s)

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

echo "=== [4/6] Running scan cycle (--run) ==="
ZSM_CONFIG_FILE="$FAKE_CFG" \
ZSM_NOW_EPOCH="$FIXED_EPOCH" \
ZSM_POSTQUEUE_CMD="$MOCK_PQ" \
ZSM_ZMPROV_CMD="$MOCK_ZMPROV" \
ZSM_SENDMAIL_CMD="$MOCK_SENDMAIL" \
ZSM_CURL_CMD="$MOCK_CURL" \
ZSM_HOSTNAME="mail.company.com" \
bash "$MONITOR_BIN" --run

grep -q "ma hacked_user@company.com zimbraAccountStatus locked" "$FAKE_ZMPROV_OUT"
echo " -> [PASS] Auto-locked CRITICAL spammer (hacked_user@company.com)."

if grep -q "warn_user@company.com" "$FAKE_ZMPROV_OUT"; then
    echo " -> [FAIL] warn_user@company.com should not be locked!"
    exit 1
fi
echo " -> [PASS] WARNING account (warn_user@company.com) alerted only, not locked."

if grep -q "marketing@company.com" "$FAKE_MAIL_OUT"; then
    echo " -> [FAIL] Whitelisted marketing@company.com triggered an alert!"
    exit 1
fi
echo " -> [PASS] Whitelist bypassed marketing@company.com properly."

grep -q "hacked_user@company.com" "$FAKE_MAIL_OUT"
grep -q "warn_user@company.com" "$FAKE_MAIL_OUT"
grep -q "203.0.113.99" "$FAKE_MAIL_OUT"
grep -q "SYSTEM TOTAL TRAFFIC" "$FAKE_MAIL_OUT"
grep -q "Sent: 345 | Deferred: 210 | Bounced: 0" "$FAKE_MAIL_OUT"
grep -q "REMAINING MAIL QUEUE" "$FAKE_MAIL_OUT"
grep -q "Spam Time" "$FAKE_MAIL_OUT"
if grep -q "Automated Action" "$FAKE_MAIL_OUT" || grep -q "Target Domains" "$FAKE_MAIL_OUT"; then
    echo " -> [FAIL] Removed fields still present in alert!"
    exit 1
fi
grep -q "hacked_user@company.com" "$FAKE_TG_OUT"
echo " -> [PASS] Clean Telegram & Email layout verified (Account, Spam Time, Source IPs, Queue, System Total)."

echo "=== [5/6] Verifying --status command ==="
STATUS_OUT=$(ZSM_CONFIG_FILE="$FAKE_CFG" \
ZSM_NOW_EPOCH="$FIXED_EPOCH" \
ZSM_POSTQUEUE_CMD="$MOCK_PQ" \
ZSM_HOSTNAME="mail.company.com" \
bash "$MONITOR_BIN" --status)

echo "$STATUS_OUT" | grep -q "hacked_user@company.com"
echo " -> [PASS] --status output verified."

echo "=== [6/6] Verifying Interactive Control Panel Menu (--text-menu) ==="
printf "2\n3\n\n0\n3\n2\n125\n0\n4\n3\n1\n\n0\n5\n2\nvip@company.com\n\n0\n0\n" | \
ZSM_CONFIG_FILE="$FAKE_CFG" \
ZSM_ZMPROV_CMD="$MOCK_ZMPROV" \
ZSM_SENDMAIL_CMD="$MOCK_SENDMAIL" \
ZSM_CURL_CMD="$MOCK_CURL" \
ZSM_UI_MODE="text" \
bash "$MONITOR_BIN" --text-menu >/dev/null 2>&1

grep -q "^WARN_SENT_PER_WINDOW=125" "$FAKE_CFG"
echo " -> [PASS] Threshold updated via Control Panel Menu (WARN_SENT_PER_WINDOW=125)."

grep -q "ma hacked_user@company.com zimbraAccountStatus active" "$FAKE_ZMPROV_OUT"
echo " -> [PASS] Account unlocked via Control Panel Menu."

grep -q "vip@company.com" "$FAKE_WL"
echo " -> [PASS] Whitelist entry added via Control Panel Menu."

echo ""
echo "======================================================================"
echo " ALL AUTOMATED TESTS (6/6) PASSED 100%!"
echo "======================================================================"
