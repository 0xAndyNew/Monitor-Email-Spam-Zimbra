#!/usr/bin/env bash
# ==============================================================================
# AUTOMATED TEST SUITE FOR ZIMBRA-SPAM-MONITOR v1.2.0
# Verifies:
# 1. Bash syntax & 100% ASCII encoding across all packaged files & README
# 2. Binary structure of .deb & .rpm packages (v1.2.0-1)
# 3. Zimbra Amavis double-Queue-ID correlation (zero 2x double counting, keeps IP)
# 4. Multi-signal detection (Msgs, Rcpts, Uniq Rcpts, Failed Rate, Botnet IPs,
#    External Spoofing, Amavis SPAM/RBL) + False-Positive protections:
#    - Single CC/BCC announcement not auto-locked
#    - Internal same-domain alias not flagged as spoofing
#    - Old Postfix deferred queue retries (delay=1800) ignored in 5m window
#    - Whitelist bypass
# 5. Duplicate zmprov lock prevention & Cooldown suppression
# 6. Admin --unlock cutoff recovery (normal mail after unlock stays NORMAL)
# 7. --status live 5-minute dashboard output
# 8. Interactive Control Panel (--text-menu) grouped submenus
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MONITOR_BIN="$ROOT_DIR/src/zimbra-spam-monitor"

echo "=== [1/8] Checking Bash syntax (bash -n) ==="
bash -n "$MONITOR_BIN"
bash -n "$ROOT_DIR/packaging/build-packages.sh"
echo " -> [PASS] Bash syntax is valid."

echo "=== [2/8] Verifying 100% ASCII-safe encoding & .deb / .rpm binary structure ==="
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

ascii_files = [
    root / "src" / "zimbra-spam-monitor",
    root / "config" / "config.conf",
    root / "config" / "whitelist.conf",
    root / "packaging" / "cron.d" / "zimbra-spam-monitor",
    root / "packaging" / "logrotate.d" / "zimbra-spam-monitor",
    root / "packaging" / "zimbra-spam-monitor.spec",
    root / "README.md",
]
for f in ascii_files:
    raw = f.read_bytes()
    non_ascii = [b for b in raw if b > 127]
    assert not non_ascii, f"Non-ASCII bytes found in {f}"

deb_path = root / "zimbra-spam-monitor_1.2.0-1_all.deb"
rpm_path = root / "zimbra-spam-monitor-1.2.0-1.noarch.rpm"

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
print(" -> [PASS] 100% ASCII encoding & valid v1.2.0 .deb / .rpm binary structures verified.")
PYEOF

echo "=== [3/8] Setting up simulated Zimbra + Postfix + Amavis environment ==="
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

# Case A: Normal user (5 emails via Amavis two-hop QID1 -> QID2: must count as 5, NOT 10!)
for i in $(seq 1 5); do
    printf "Nov  8 14:56:10 mail postfix/submission/smtpd[1001]: QNPRE%03d: client=office[192.0.2.10], sasl_method=LOGIN, sasl_username=normal@company.com\n" "$i" >> "$FAKE_LOG"
    printf "Nov  8 14:56:10 mail postfix/qmgr[1002]: QNPRE%03d: from=<normal@company.com>, size=1200, nrcpt=1 (queue active)\n" "$i" >> "$FAKE_LOG"
    printf "Nov  8 14:56:11 mail postfix/smtp[1003]: QNPRE%03d: to=<partner%d@gmail.com>, relay=127.0.0.1[127.0.0.1]:10024, delay=0.2, status=sent (250 2.0.0 from MTA(smtp:[127.0.0.1]:10025): 250 2.0.0 Ok: queued as QNPOST%03d)\n" "$i" "$i" "$i" >> "$FAKE_LOG"
    printf "Nov  8 14:56:11 mail postfix/qmgr[1002]: QNPOST%03d: from=<normal@company.com>, size=1600, nrcpt=1 (queue active)\n" "$i" >> "$FAKE_LOG"
    printf "Nov  8 14:56:12 mail postfix/smtp[1004]: QNPOST%03d: to=<partner%d@gmail.com>, relay=mx.gmail.com[142.250.1.1]:25, delay=0.5, status=sent (250 OK)\n" "$i" "$i" >> "$FAKE_LOG"
done

# Case B: Whitelisted marketing account (220 emails -> bypassed)
for i in $(seq 1 220); do
    printf "Nov  8 14:56:20 mail postfix/smtpd[1001]: QMKT%03d: client=localhost[127.0.0.1], sasl_method=LOGIN, sasl_username=marketing@company.com\n" "$i" >> "$FAKE_LOG"
    printf "Nov  8 14:56:21 mail postfix/smtp[1002]: QMKT%03d: to=<cust%d@yahoo.com>, relay=mx.yahoo.com[1.2.3.4]:25, delay=0.4, status=sent (250 OK)\n" "$i" "$i" >> "$FAKE_LOG"
done

# Case C: Old deferred queue retries from 30 mins ago (delay=1800 -> MUST NOT count as new 5m spam!)
for i in $(seq 1 120); do
    printf "Nov  8 14:57:00 mail postfix/qmgr[1002]: QOLD%03d: from=<old_retry@company.com>, size=1400, nrcpt=1 (queue active)\n" "$i" >> "$FAKE_LOG"
    printf "Nov  8 14:57:01 mail postfix/smtp[1004]: QOLD%03d: to=<old%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=1800, status=deferred (421 try again later)\n" "$i" "$i" >> "$FAKE_LOG"
done

# Case D: Legitimate same-domain alias (sale_alias@company.com sending as sales@company.com -> NOT spoof!)
for i in $(seq 1 12); do
    printf "Nov  8 14:57:15 mail postfix/submission/smtpd[1001]: QALS%03d: client=office[192.0.2.25], sasl_method=LOGIN, sasl_username=sale_alias@company.com\n" "$i" >> "$FAKE_LOG"
    printf "Nov  8 14:57:15 mail postfix/qmgr[1002]: QALS%03d: from=<sales@company.com>, size=1500, nrcpt=1 (queue active)\n" "$i" >> "$FAKE_LOG"
    printf "Nov  8 14:57:16 mail postfix/smtp[1004]: QALS%03d: to=<client%d@partner.com>, relay=mx.partner.com[1.2.3.4]:25, delay=0.3, status=sent (250 OK)\n" "$i" "$i" >> "$FAKE_LOG"
done

# Case E: CEO sends 1 single BCC holiday announcement to 170 external partners (Msgs=1, Rcpts=170 -> WARNING only, MUST NOT auto-lock!)
printf "Nov  8 14:57:30 mail postfix/submission/smtpd[1001]: QCEO001: client=office[192.0.2.50], sasl_method=LOGIN, sasl_username=ceo@company.com\n" >> "$FAKE_LOG"
printf "Nov  8 14:57:30 mail postfix/qmgr[1002]: QCEO001: from=<ceo@company.com>, size=4500, nrcpt=170 (queue active)\n" >> "$FAKE_LOG"
for i in $(seq 1 170); do
    dom_idx=$(( (i % 8) + 1 ))
    printf "Nov  8 14:57:31 mail postfix/smtp[1004]: QCEO001: to=<vip%d@partner%d.com>, relay=mx.partner.com[1.2.3.4]:25, delay=0.6, status=sent (250 OK)\n" "$i" "$dom_idx" >> "$FAKE_LOG"
done

# Case F: WARNING account via Failed Rate (25 msgs, 10 bounced = 40.0% >= 30%, < 40 rcpts so WARNING, not CRITICAL)
for i in $(seq 1 25); do
    printf "Nov  8 14:58:00 mail postfix/submission/smtpd[1001]: QWARN%03d: client=home[198.51.100.22], sasl_method=LOGIN, sasl_username=warn_user@company.com\n" "$i" >> "$FAKE_LOG"
    if (( i <= 10 )); then
        printf "Nov  8 14:58:01 mail postfix/smtp[1004]: QWARN%03d: to=<bad%d@outlook.com>, relay=mx.outlook.com[1.2.3.4]:25, delay=0.5, status=bounced (550 5.1.1 User unknown)\n" "$i" "$i" >> "$FAKE_LOG"
    else
        printf "Nov  8 14:58:01 mail postfix/smtp[1004]: QWARN%03d: to=<ok%d@outlook.com>, relay=mx.outlook.com[1.2.3.4]:25, delay=0.5, status=sent (250 OK)\n" "$i" "$i" >> "$FAKE_LOG"
    fi
done

# Case G: Low-volume Phishing/Spoofing account (only 12 emails, but Amavis SPAM + external Spoof From -> CRITICAL + Auto-lock!)
for i in $(seq 1 12); do
    printf "Nov  8 14:58:20 mail postfix/submission/smtpd[1001]: QPHPRE%03d: client=vps[91.214.124.88], sasl_method=LOGIN, sasl_username=phish_user@company.com\n" "$i" >> "$FAKE_LOG"
    printf "Nov  8 14:58:20 mail postfix/qmgr[1002]: QPHPRE%03d: from=<security@fake-bank.org>, size=2100, nrcpt=1 (queue active)\n" "$i" >> "$FAKE_LOG"
    printf "Nov  8 14:58:21 mail amavis[2001]: (2001-%02d) Passed SPAMMY {RelayedTaggedOutbound}, ORIGINATING [91.214.124.88]:51000 <security@fake-bank.org> -> <victim%d@gmail.com>, Queue-ID: QPHPRE%03d, Hits: 9.85\n" "$i" "$i" "$i" >> "$FAKE_LOG"
    printf "Nov  8 14:58:21 mail postfix/smtp[1003]: QPHPRE%03d: to=<victim%d@gmail.com>, relay=127.0.0.1[127.0.0.1]:10024, delay=0.3, status=sent (250 2.0.0 Ok: queued as QPHPOST%03d)\n" "$i" "$i" "$i" >> "$FAKE_LOG"
    printf "Nov  8 14:58:22 mail postfix/smtp[1004]: QPHPOST%03d: to=<victim%d@gmail.com>, relay=mx.gmail.com[142.250.1.1]:25, delay=0.6, status=sent (250 OK)\n" "$i" "$i" >> "$FAKE_LOG"
done

# Case H: High-volume Botnet Burst Spammer (180 msgs across 10 external domains, 5 botnet IPs, 120 deferred w/ 4.7.28 -> CRITICAL + Auto-lock!)
BOT_IPS=("203.0.113.11" "203.0.113.22" "198.51.100.33" "192.0.2.44" "185.220.101.55")
for i in $(seq 1 180); do
    ip_idx=$(( i % 5 ))
    bip="${BOT_IPS[$ip_idx]}"
    d_idx=$(( (i % 10) + 1 ))
    printf "Nov  8 14:58:40 mail postfix/submission/smtpd[1001]: QCRIT%03d: client=botnet[%s], sasl_method=LOGIN, sasl_username=hacked_user@company.com\n" "$i" "$bip" >> "$FAKE_LOG"
    printf "Nov  8 14:58:40 mail postfix/qmgr[1002]: QCRIT%03d: from=<hacked_user@company.com>, size=1800, nrcpt=1 (queue active)\n" "$i" >> "$FAKE_LOG"
    if (( i <= 120 )); then
        printf "Nov  8 14:58:41 mail postfix/smtp[1004]: QCRIT%03d: to=<target%d@extdom%d.org>, relay=mx.ext.org[1.2.3.4]:25, delay=0.5, status=deferred (host mx.ext.org said: 421-4.7.28 Unusual rate of unsolicited mail)\n" "$i" "$i" "$d_idx" >> "$FAKE_LOG"
    else
        printf "Nov  8 14:58:41 mail postfix/smtp[1004]: QCRIT%03d: to=<target%d@extdom%d.org>, relay=mx.ext.org[1.2.3.4]:25, delay=0.5, status=sent (250 OK)\n" "$i" "$i" "$d_idx" >> "$FAKE_LOG"
    fi
done

echo "marketing@company.com" > "$FAKE_WL"

MOCK_PQ="$TEST_TMP/mock_postqueue.sh"
cat << 'EOF' > "$MOCK_PQ"
#!/usr/bin/env bash
cat << 'QOUT'
-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------
A1B2C3D4E1      1234 Sun Nov  8 14:58:45  hacked_user@company.com
                                         (host mx.ext.org said: 421-4.7.28 Rate limited)
                                         target1@extdom1.org

A1B2C3D4E2*     1234 Sun Nov  8 14:58:46  hacked_user@company.com
                                         target2@extdom2.org
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

cp "$ROOT_DIR/config/config.conf" "$FAKE_CFG"
sed -i "s|^ZIMBRA_LOG_FILE=.*|ZIMBRA_LOG_FILE=\"$FAKE_LOG\"|" "$FAKE_CFG"
sed -i "s|^INTERNAL_DOMAINS=.*|INTERNAL_DOMAINS=\"company.com\"|" "$FAKE_CFG"
sed -i "s|^TELEGRAM_BOT_TOKEN=.*|TELEGRAM_BOT_TOKEN=\"999999:TEST_TOKEN\"|" "$FAKE_CFG"
sed -i "s|^TELEGRAM_CHAT_ID=.*|TELEGRAM_CHAT_ID=\"-100987654321\"|" "$FAKE_CFG"
sed -i "s|^EMAIL_DELIVERY_MODE=.*|EMAIL_DELIVERY_MODE=\"local\"|" "$FAKE_CFG"
sed -i "s|^ALERT_EMAIL_TO=.*|ALERT_EMAIL_TO=\"admin@company.com\"|" "$FAKE_CFG"
sed -i "s|^ALERT_EMAIL_FROM=.*|ALERT_EMAIL_FROM=\"zimbra-monitor@company.com\"|" "$FAKE_CFG"
sed -i "s|^WHITELIST_FILE=.*|WHITELIST_FILE=\"$FAKE_WL\"|" "$FAKE_CFG"
sed -i "s|^STATE_DIR=.*|STATE_DIR=\"$FAKE_STATE\"|" "$FAKE_CFG"
sed -i "s|^MONITOR_LOG_FILE=.*|MONITOR_LOG_FILE=\"$FAKE_MON_LOG\"|" "$FAKE_CFG"

echo "=== [4/8] Running multi-signal scan cycle (--run) ==="
ZSM_CONFIG_FILE="$FAKE_CFG" \
ZSM_NOW_EPOCH="$FIXED_EPOCH" \
ZSM_POSTQUEUE_CMD="$MOCK_PQ" \
ZSM_ZMPROV_CMD="$MOCK_ZMPROV" \
ZSM_SENDMAIL_CMD="$MOCK_SENDMAIL" \
ZSM_CURL_CMD="$MOCK_CURL" \
ZSM_HOSTNAME="mail.company.com" \
bash "$MONITOR_BIN" --run

# Verify CRITICAL spammers locked
grep -q "ma hacked_user@company.com zimbraAccountStatus locked" "$FAKE_ZMPROV_OUT"
grep -q "ma phish_user@company.com zimbraAccountStatus locked" "$FAKE_ZMPROV_OUT"
echo " -> [PASS] Auto-locked both burst spammer (hacked_user) and low-volume phishing/spoof user (phish_user)."

# Verify CEO single BCC announcement and warn_user were NOT auto-locked
if grep -q "ceo@company.com" "$FAKE_ZMPROV_OUT" || grep -q "warn_user@company.com" "$FAKE_ZMPROV_OUT"; then
    echo " -> [FAIL] ceo@company.com or warn_user@company.com should NOT be auto-locked!"
    exit 1
fi
grep -q "ceo@company.com" "$FAKE_MAIL_OUT"
grep -q "warn_user@company.com" "$FAKE_MAIL_OUT"
echo " -> [PASS] Single CC/BCC announcement (ceo@company.com) & Failed-Rate WARNING alerted only, NOT locked."

# Verify false-positive protections (old queue retries, internal alias, normal Amavis 2-hop, whitelist)
for clean_acc in "marketing@company.com" "old_retry@company.com" "sale_alias@company.com" "normal@company.com"; do
    if grep -q "$clean_acc" "$FAKE_MAIL_OUT"; then
        echo " -> [FAIL] Clean/whitelisted/old-retry account $clean_acc falsely triggered an alert!"
        exit 1
    fi
done
echo " -> [PASS] Zero false positives on Amavis 2-hop, Postfix old retries (delay=1800), internal aliases, and whitelist."

# Verify exact metrics & formatting in generated alerts
grep -q "ACCOUNT SPAM METRICS (LAST 5 MINS)" "$FAKE_MAIL_OUT"
grep -q "Messages Sent : 180 msgs" "$FAKE_MAIL_OUT"
grep -q "Recipients    : 180 total (Unique: 180 | Domains: 10)" "$FAKE_MAIL_OUT"
grep -q "Failed Rate   : 66.7% (120/180 failed)" "$FAKE_MAIL_OUT"
grep -q "5 IPs" "$FAKE_MAIL_OUT"
grep -q "Amavis SPAM: 12 | Spoof From: 12" "$FAKE_MAIL_OUT"
grep -q "91.214.124.88 (1 IP)" "$FAKE_MAIL_OUT"
echo " -> [PASS] Alert view verified (Messages Sent, Recipients, Unique/Domains, Failed Rate, Source IPs, Amavis/Spoof/RBL)."

echo "=== [5/8] Verifying Cooldown & Duplicate zmprov Prevention ==="
LOCK_CALLS_BEFORE=$(wc -l < "$FAKE_ZMPROV_OUT")
MAIL_CALLS_BEFORE=$(grep -c -- "---END_MAIL---" "$FAKE_MAIL_OUT")

# Advance 4 minutes (within 30m cooldown): should skip duplicate alerts &zmprov calls
NEXT_EPOCH=$(( FIXED_EPOCH + 240 ))
ZSM_CONFIG_FILE="$FAKE_CFG" \
ZSM_NOW_EPOCH="$NEXT_EPOCH" \
ZSM_POSTQUEUE_CMD="$MOCK_PQ" \
ZSM_ZMPROV_CMD="$MOCK_ZMPROV" \
ZSM_SENDMAIL_CMD="$MOCK_SENDMAIL" \
ZSM_CURL_CMD="$MOCK_CURL" \
ZSM_HOSTNAME="mail.company.com" \
bash "$MONITOR_BIN" --run

LOCK_CALLS_AFTER=$(wc -l < "$FAKE_ZMPROV_OUT")
MAIL_CALLS_AFTER=$(grep -c -- "---END_MAIL---" "$FAKE_MAIL_OUT")
if [[ "$LOCK_CALLS_BEFORE" != "$LOCK_CALLS_AFTER" || "$MAIL_CALLS_BEFORE" != "$MAIL_CALLS_AFTER" ]]; then
    echo " -> [FAIL] Cooldown failed to suppress duplicate alert or zmprov!"
    exit 1
fi
echo " -> [PASS] 30-min cooldown suppressed duplicate alerts and prevented redundant zmprov JVM calls."

echo "=== [6/8] Verifying Admin --unlock Cutoff & Recovery to NORMAL ==="
UNLOCK_EPOCH=$(( FIXED_EPOCH + 300 ))
ZSM_CONFIG_FILE="$FAKE_CFG" \
ZSM_NOW_EPOCH="$UNLOCK_EPOCH" \
ZSM_ZMPROV_CMD="$MOCK_ZMPROV" \
bash "$MONITOR_BIN" --unlock hacked_user@company.com >/dev/null

# After unlock, hacked_user sends 4 normal work emails (below threshold)
for i in $(seq 1 4); do
    printf "Nov  8 15:06:10 mail postfix/submission/smtpd[1001]: QPOST%03d: client=office[192.0.2.10], sasl_method=LOGIN, sasl_username=hacked_user@company.com\n" "$i" >> "$FAKE_LOG"
    printf "Nov  8 15:06:11 mail postfix/smtp[1004]: QPOST%03d: to=<client%d@gmail.com>, relay=mx.gmail.com[142.250.1.1]:25, delay=0.3, status=sent (250 OK)\n" "$i" "$i" >> "$FAKE_LOG"
done

POST_UNLOCK_SCAN_EPOCH=$(date -d "2026-11-08 15:07:00" +%s)
EMPTY_PQ="$TEST_TMP/empty_pq.sh"
printf "#!/usr/bin/env bash\necho 'Mail queue is empty'\n" > "$EMPTY_PQ"
chmod +x "$EMPTY_PQ"

MAIL_BEFORE_RECOVERY=$(grep -c -- "---END_MAIL---" "$FAKE_MAIL_OUT")
ZSM_CONFIG_FILE="$FAKE_CFG" \
ZSM_NOW_EPOCH="$POST_UNLOCK_SCAN_EPOCH" \
ZSM_POSTQUEUE_CMD="$EMPTY_PQ" \
ZSM_ZMPROV_CMD="$MOCK_ZMPROV" \
ZSM_SENDMAIL_CMD="$MOCK_SENDMAIL" \
ZSM_CURL_CMD="$MOCK_CURL" \
ZSM_HOSTNAME="mail.company.com" \
bash "$MONITOR_BIN" --run

MAIL_AFTER_RECOVERY=$(grep -c -- "---END_MAIL---" "$FAKE_MAIL_OUT")
if [[ "$MAIL_BEFORE_RECOVERY" != "$MAIL_AFTER_RECOVERY" ]]; then
    echo " -> [FAIL] Unlocked account sending 4 normal emails triggered a false alert!"
    exit 1
fi
echo " -> [PASS] Unlocked account sending < threshold emails treated as NORMAL immediately."

echo "=== [7/8] Verifying --status Live 5m Dashboard ==="
STATUS_OUT=$(ZSM_CONFIG_FILE="$FAKE_CFG" \
ZSM_NOW_EPOCH="$FIXED_EPOCH" \
ZSM_POSTQUEUE_CMD="$MOCK_PQ" \
ZSM_HOSTNAME="mail.company.com" \
bash "$MONITOR_BIN" --status)

echo "$STATUS_OUT" | grep -q "LIVE SYSTEM STATUS (LAST 5 MINS)"
echo "$STATUS_OUT" | grep -q "hacked_user@company.com"
echo "$STATUS_OUT" | grep -q "normal@company.com         | 5     | 5 (5)"
echo " -> [PASS] --status output verified (Amavis 2-hop counted as 5, not 10)."

echo "=== [8/8] Verifying Interactive Control Panel Menu (--text-menu) ==="
# Navigate:
# [2] Notifications -> [3] Send Test Alert -> Enter -> [0] Back
# [3] Thresholds -> [2] Volume -> [1] Messages Sent (WARN=75, CRIT=180) -> [0] Back -> [0] Back
# [4] Lock Control -> [3] Unlock phish_user (item 1) -> Enter -> [0] Back
# [5] Whitelist -> [2] Add vip@company.com -> Enter -> [0] Back
# [0] Exit
printf "2\n3\n\n0\n3\n2\n1\n75\n180\n0\n0\n4\n3\n1\n\n0\n5\n2\nvip@company.com\n\n0\n0\n" | \
ZSM_CONFIG_FILE="$FAKE_CFG" \
ZSM_ZMPROV_CMD="$MOCK_ZMPROV" \
ZSM_SENDMAIL_CMD="$MOCK_SENDMAIL" \
ZSM_CURL_CMD="$MOCK_CURL" \
ZSM_UI_MODE="text" \
bash "$MONITOR_BIN" --text-menu >/dev/null 2>&1

grep -q "^WARN_MESSAGES_SENT=75" "$FAKE_CFG"
grep -q "^CRIT_MESSAGES_SENT=180" "$FAKE_CFG"
echo " -> [PASS] Grouped Thresholds updated via Control Panel Menu (WARN_MESSAGES_SENT=75, CRIT_MESSAGES_SENT=180)."

grep -q "ma phish_user@company.com zimbraAccountStatus active" "$FAKE_ZMPROV_OUT"
echo " -> [PASS] Account unlocked via Control Panel Menu."

grep -q "vip@company.com" "$FAKE_WL"
echo " -> [PASS] Whitelist entry added via Control Panel Menu."

echo ""
echo "======================================================================"
echo " ALL AUTOMATED TESTS (8/8) PASSED 100%!"
echo "======================================================================"
