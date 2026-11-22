#!/usr/bin/env bash
# ==============================================================================
# AUTOMATED TEST SUITE FOR ZIMBRA-SPAM-MONITOR v1.3.2 (16 STAGES)
# Verifies:
#  1. Bash syntax & static Zero-Server/OS-Mutation safety audit
#  2. 100% 7-bit ASCII encoding & valid v1.3.2-1 .deb / .rpm binary structures
#  3. Simulated single-server Zimbra environment (zimbra/mailbox/audit logs + mocks)
#  4. Multi-signal scan cycle (--run), Amavis 2-hop, cache flush, exact 5m sys_tot
#  5. Cooldown, Long Queue IDs, decoupled lock retry on zmprov fail, Held exclusion
#  6. Locked-account desync recovery (benign external unlock vs RE-LOCK on spam)
#  7. Security regressions (Command Injection block, curl stdin secrets, config escape)
#  8. Counting accuracy (per-msg Spoof/Amavis, deduped deferred retries, expired)
#  9. Multi-window Low-and-Slow (1h rolling buckets + idempotent re-runs)
# 10. Single-server mailbox.log real Webmail /24 IPs, 4G safety, audit.log brute-force
# 11. Auto-forward safeguard, spoofed QID queue hold, internal malware, local pickup
# 12. Custom limits, Composite Risk Score, LDAP multi-domain cache, logrotate .1
# 13. Self-RBL (127.255.x guard & state-change), --audit, Webhook, JSONL, Outbox retry
# 14. Admin --unlock (clears rolling history) & --status live dashboard + IP cache
# 15. Interactive Control Panel (--text-menu) & exact whitelist removal
# 16. v1.3.2 Hardening: Inbound DoS, 1-msg deferred, Lock cap, System shield, NAT & Cron
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MONITOR_BIN="$ROOT_DIR/src/zimbra-spam-monitor"

export ZSM_TG_RATE_SLEEP=0

PY_CMD="python"
if python3 --version >/dev/null 2>&1; then
    PY_CMD="python3"
fi

echo "=== [1/16] Checking Bash syntax & Zero-Server/OS-Mutation safety audit ==="
bash -n "$MONITOR_BIN"
bash -n "$ROOT_DIR/packaging/build-packages.sh"

"$PY_CMD" - "$MONITOR_BIN" << 'PYEOF'
import re, sys
from pathlib import Path

code = Path(sys.argv[1]).read_text(encoding="ascii")
# Strip full-line comments when checking executable code & printed strings
non_comment = "\n".join(line for line in code.splitlines() if not line.lstrip().startswith("#"))

forbidden_patterns = [
    (r"postconf\s+-e\b", "postconf -e (Postfix mutation)"),
    (r"zmlocalconfig\s+-e\b", "zmlocalconfig -e (Zimbra mutation)"),
    (r"zmprov\s+(mcf|ms|mc|md|cd|dd)\b", "zmprov global/server/domain mutation"),
    (r"\bzmcontrol\b", "zmcontrol service control"),
    (r"postfix\s+(reload|restart|stop|start)\b", "postfix service control"),
    (r"\b(apt-get|apt\s+install|apt\s+upgrade|yum\s+install|yum\s+update|dnf\s+install|dnf\s+update)\b", "OS package manager mutation"),
    (r"\b(iptables|nft\s+add|firewall-cmd|fail2ban-client)\b", "OS firewall/fail2ban mutation"),
    (r"\bsysctl\s+-w\b", "OS kernel sysctl mutation"),
    (r"\bsystemctl\s+(restart|reload|stop|start|enable|disable)\b", "systemd service mutation"),
]

for pat, label in forbidden_patterns:
    m = re.search(pat, non_comment)
    assert m is None, f"FORBIDDEN mutation pattern found ({label}): {m.group(0)}"

print(" -> [PASS] Bash syntax valid & 0 forbidden server/OS mutation commands detected.")
PYEOF

echo "=== [2/16] Verifying 100% ASCII encoding & v1.3.2 .deb / .rpm structures ==="
"$PY_CMD" - "$ROOT_DIR" << 'PYEOF'
import gzip, struct, sys
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
    root / "CLAUDE.md",
    root / "LICENSE",
    root / ".gitignore",
    root / "tests" / "run_test.sh",
]
for f in ascii_files:
    raw = f.read_bytes()
    non_ascii = [b for b in raw if b > 127]
    assert not non_ascii, f"Non-ASCII bytes found in {f}"

deb_path = root / "zimbra-spam-monitor_1.3.2-1_all.deb"
rpm_path = root / "zimbra-spam-monitor-1.3.2-1.noarch.rpm"

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
print(" -> [PASS] 100% ASCII encoding & valid v1.3.2-1 .deb / .rpm binary structures verified.")
PYEOF

echo "=== [3/16] Setting up simulated single-server Zimbra environment ==="
TEST_TMP=$(mktemp -d 2>/dev/null || echo "/tmp/zsm_test_$$")
mkdir -p "$TEST_TMP"
trap 'rm -rf "$TEST_TMP"' EXIT

FAKE_LOG="$TEST_TMP/zimbra.log"
FAKE_MBOX_LOG="$TEST_TMP/mailbox.log"
FAKE_AUDIT_LOG="$TEST_TMP/audit.log"
FAKE_CFG="$TEST_TMP/config.conf"
FAKE_WL="$TEST_TMP/whitelist.conf"
FAKE_STATE="$TEST_TMP/state"
FAKE_MON_LOG="$TEST_TMP/monitor.log"
FAKE_JSON_LOG="$TEST_TMP/events.jsonl"
FAKE_TG_ARGS="$TEST_TMP/curl_args.txt"
FAKE_TG_BODY="$TEST_TMP/telegram_body.txt"
FAKE_WH_BODY="$TEST_TMP/webhook_body.txt"
FAKE_MAIL_OUT="$TEST_TMP/email_sent.txt"
FAKE_ZMPROV_OUT="$TEST_TMP/zmprov_actions.txt"
FAKE_POSTSUPER_OUT="$TEST_TMP/postsuper_actions.txt"

FIXED_EPOCH=$(date -d "2026-11-08 15:00:00" +%s)

: > "$FAKE_LOG"
: > "$FAKE_MBOX_LOG"
: > "$FAKE_AUDIT_LOG"

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

# Case E: CEO sends 1 single BCC announcement to 170 partners (Msgs=1, Rcpts=170 -> WARNING only, NOT auto-locked!)
printf "Nov  8 14:57:30 mail postfix/submission/smtpd[1001]: QCEO001: client=office[192.0.2.50], sasl_method=LOGIN, sasl_username=ceo@company.com\n" >> "$FAKE_LOG"
printf "Nov  8 14:57:30 mail postfix/qmgr[1002]: QCEO001: from=<ceo@company.com>, size=4500, nrcpt=170 (queue active)\n" >> "$FAKE_LOG"
for i in $(seq 1 170); do
    dom_idx=$(( (i % 8) + 1 ))
    printf "Nov  8 14:57:31 mail postfix/smtp[1004]: QCEO001: to=<vip%d@partner%d.com>, relay=mx.partner.com[1.2.3.4]:25, delay=0.6, status=sent (250 OK)\n" "$i" "$dom_idx" >> "$FAKE_LOG"
done

# Case F: WARNING account via Failed Rate (25 msgs, 10 bounced = 40.0% >= 30%, < 40 rcpts -> WARNING only)
for i in $(seq 1 25); do
    printf "Nov  8 14:58:00 mail postfix/submission/smtpd[1001]: QWARN%03d: client=home[198.51.100.22], sasl_method=LOGIN, sasl_username=warn_user@company.com\n" "$i" >> "$FAKE_LOG"
    if (( i <= 10 )); then
        printf "Nov  8 14:58:01 mail postfix/smtp[1004]: QWARN%03d: to=<bad%d@outlook.com>, relay=mx.outlook.com[1.2.3.4]:25, delay=0.5, status=bounced (550 5.1.1 User unknown)\n" "$i" "$i" >> "$FAKE_LOG"
    else
        printf "Nov  8 14:58:01 mail postfix/smtp[1004]: QWARN%03d: to=<ok%d@outlook.com>, relay=mx.outlook.com[1.2.3.4]:25, delay=0.5, status=sent (250 OK)\n" "$i" "$i" >> "$FAKE_LOG"
    fi
done

# Case G: Low-volume Phishing/Spoofing account (12 distinct msgs, Amavis SPAM + external Spoof -> CRITICAL + Auto-lock!)
for i in $(seq 1 12); do
    printf "Nov  8 14:58:20 mail postfix/submission/smtpd[1001]: QPHPRE%03d: client=vps[91.214.124.88], sasl_method=LOGIN, sasl_username=phish_user@company.com\n" "$i" >> "$FAKE_LOG"
    printf "Nov  8 14:58:20 mail postfix/qmgr[1002]: QPHPRE%03d: from=<security@fake-bank.org>, size=2100, nrcpt=1 (queue active)\n" "$i" >> "$FAKE_LOG"
    printf "Nov  8 14:58:21 mail amavis[2001]: (2001-%02d) Passed SPAMMY {RelayedTaggedOutbound}, ORIGINATING [91.214.124.88]:51000 <security@fake-bank.org> -> <victim%d@gmail.com>, Queue-ID: QPHPRE%03d, Hits: 9.85\n" "$i" "$i" "$i" >> "$FAKE_LOG"
    printf "Nov  8 14:58:21 mail postfix/smtp[1003]: QPHPRE%03d: to=<victim%d@gmail.com>, relay=127.0.0.1[127.0.0.1]:10024, delay=0.3, status=sent (250 2.0.0 Ok: queued as QPHPOST%03d)\n" "$i" "$i" "$i" >> "$FAKE_LOG"
    printf "Nov  8 14:58:22 mail postfix/smtp[1004]: QPHPOST%03d: to=<victim%d@gmail.com>, relay=mx.gmail.com[142.250.1.1]:25, delay=0.6, status=sent (250 OK)\n" "$i" "$i" >> "$FAKE_LOG"
done

# Case H: High-volume Botnet Burst Spammer (180 msgs across 10 external domains, 5 distinct /24 botnet IPs, 120 deferred 4.7.28)
BOT_IPS=("203.0.113.11" "203.0.114.22" "198.51.100.33" "192.0.2.44" "185.220.101.55")
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

# Case I: Local Webmail spammer connecting via LAN IP [10.2.1.23] without SASL (65 msgs -> WARNING)
for i in $(seq 1 65); do
    printf "Nov  8 14:59:10 mail postfix/smtpd[1005]: QWEB%03d: client=mail.company.com[10.2.1.23]\n" "$i" >> "$FAKE_LOG"
    printf "Nov  8 14:59:10 mail postfix/qmgr[1002]: QWEB%03d: from=<webmail_warn@company.com>, size=1300, nrcpt=1 (queue active)\n" "$i" >> "$FAKE_LOG"
    printf "Nov  8 14:59:11 mail postfix/smtp[1004]: QWEB%03d: to=<ext%d@gmail.com>, relay=mx.gmail.com[142.250.1.1]:25, delay=0.4, status=sent (250 OK)\n" "$i" "$i" >> "$FAKE_LOG"
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

MOCK_PS="$TEST_TMP/mock_postsuper.sh"
cat << EOF > "$MOCK_PS"
#!/usr/bin/env bash
while IFS= read -r q; do
    echo "\$* \$q" >> "$FAKE_POSTSUPER_OUT"
done
exit 0
EOF
chmod +x "$MOCK_PS"

MOCK_ZMPROV="$TEST_TMP/mock_zmprov.sh"
cat << EOF > "$MOCK_ZMPROV"
#!/usr/bin/env bash
if [[ -f "$TEST_TMP/fail_zmprov" ]]; then
    echo "FAIL \$*" >> "$FAKE_ZMPROV_OUT"
    exit 1
fi
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

# Mock curl: captures CLI args (verifying token/pass NOT exposed!), stdin config, and body files
MOCK_CURL="$TEST_TMP/mock_curl.sh"
cat << EOF > "$MOCK_CURL"
#!/usr/bin/env bash
echo "\$*" >> "$FAKE_TG_ARGS"
stdin_cfg=\$(cat)
if [[ -f "$TEST_TMP/fail_curl" ]]; then
    echo '{"ok":false,"description":"Simulated outage"}'
    exit 7
fi
for arg in "\$@"; do
    if [[ "\$arg" == text@* ]]; then
        cat "\${arg#text@}" >> "$FAKE_TG_BODY"
        echo "" >> "$FAKE_TG_BODY"
        echo "---END_TG---" >> "$FAKE_TG_BODY"
    elif [[ "\$arg" == @* ]]; then
        cat "\${arg#@}" >> "$FAKE_WH_BODY"
        echo "" >> "$FAKE_WH_BODY"
    fi
done
echo '{"ok":true}'
exit 0
EOF
chmod +x "$MOCK_CURL"

MOCK_HOSTNAME="$TEST_TMP/mock_hostname.sh"
cat << 'EOF' > "$MOCK_HOSTNAME"
#!/usr/bin/env bash
if [[ "$1" == "-I" ]]; then
    echo "10.2.1.23"
else
    echo "mail.company.com"
fi
EOF
chmod +x "$MOCK_HOSTNAME"

MOCK_DIG="$TEST_TMP/mock_dig.sh"
cat << 'EOF' > "$MOCK_DIG"
#!/usr/bin/env bash
args="$*"
if [[ "$args" == *" TXT _dmarc."* ]]; then
    echo '"v=DMARC1; p=quarantine"'
    exit 0
fi
if [[ "$args" == *" TXT "* ]]; then
    echo '"v=spf1 mx ip4:103.56.158.99 -all"'
    exit 0
fi
if [[ "$args" == *"zen.spamhaus.org"* ]]; then
    if [[ -f "${ZSM_TEST_RBL_LISTED:-/nonexistent}" ]]; then
        echo "127.0.0.2"
    elif [[ -f "${ZSM_TEST_RBL_ERR:-/nonexistent}" ]]; then
        echo "127.255.255.254"
    fi
    exit 0
fi
if [[ "$args" == *"bl.spamcop.net"* || "$args" == *"bl.mailspike.net"* || "$args" == *"uceprotect"* || "$args" == *"psbl.surriel.com"* ]]; then
    exit 0
fi
if [[ "$args" == *"@1.1.1.1"* || "$args" == *"@8.8.8.8"* ]]; then
    echo "edge.company.com."
    echo "103.56.158.99"
else
    echo "10.2.1.23"
fi
EOF
chmod +x "$MOCK_DIG"

MOCK_POSTCONF="$TEST_TMP/mock_postconf.sh"
cat << 'EOF' > "$MOCK_POSTCONF"
#!/usr/bin/env bash
case "$2" in
    smtpd_sender_login_maps) echo "proxy:ldap:/opt/zimbra/conf/ldap-slm.cf" ;;
    smtpd_reject_unlisted_sender) echo "yes" ;;
    smtpd_client_message_rate_limit) echo "100" ;;
esac
EOF
chmod +x "$MOCK_POSTCONF"

MOCK_LDAP="$TEST_TMP/mock_ldapsearch.sh"
cat << 'EOF' > "$MOCK_LDAP"
#!/usr/bin/env bash
echo "dn: dc=company,dc=com"
echo "zimbraDomainName: company.com"
echo "dn: dc=brand2,dc=vn"
echo "zimbraDomainName: brand2.vn"
EOF
chmod +x "$MOCK_LDAP"

cp "$ROOT_DIR/config/config.conf" "$FAKE_CFG"
sed -i "s|^ZIMBRA_LOG_FILE=.*|ZIMBRA_LOG_FILE=\"$FAKE_LOG\"|" "$FAKE_CFG"
sed -i "s|^ZIMBRA_MAILBOX_LOG_FILE=.*|ZIMBRA_MAILBOX_LOG_FILE=\"$FAKE_MBOX_LOG\"|" "$FAKE_CFG"
sed -i "s|^ZIMBRA_AUDIT_LOG_FILE=.*|ZIMBRA_AUDIT_LOG_FILE=\"$FAKE_AUDIT_LOG\"|" "$FAKE_CFG"
sed -i "s|^INTERNAL_DOMAINS=.*|INTERNAL_DOMAINS=\"company.com\"|" "$FAKE_CFG"
sed -i "s|^TELEGRAM_BOT_TOKEN=.*|TELEGRAM_BOT_TOKEN=\"999999:SUPER_SECRET_TOKEN\"|" "$FAKE_CFG"
sed -i "s|^TELEGRAM_CHAT_ID=.*|TELEGRAM_CHAT_ID=\"-100987654321\"|" "$FAKE_CFG"
sed -i "s|^EMAIL_DELIVERY_MODE=.*|EMAIL_DELIVERY_MODE=\"local\"|" "$FAKE_CFG"
sed -i "s|^ALERT_EMAIL_TO=.*|ALERT_EMAIL_TO=\"admin@company.com\"|" "$FAKE_CFG"
sed -i "s|^ALERT_EMAIL_FROM=.*|ALERT_EMAIL_FROM=\"zimbra-monitor@company.com\"|" "$FAKE_CFG"
sed -i "s|^WHITELIST_FILE=.*|WHITELIST_FILE=\"$FAKE_WL\"|" "$FAKE_CFG"
sed -i "s|^STATE_DIR=.*|STATE_DIR=\"$FAKE_STATE\"|" "$FAKE_CFG"
sed -i "s|^MONITOR_LOG_FILE=.*|MONITOR_LOG_FILE=\"$FAKE_MON_LOG\"|" "$FAKE_CFG"
sed -i "s|^JSON_LOG_FILE=.*|JSON_LOG_FILE=\"$FAKE_JSON_LOG\"|" "$FAKE_CFG"
sed -i "s|^RBL_CHECK_ENABLED=.*|RBL_CHECK_ENABLED=\"false\"|" "$FAKE_CFG"

run_scan() {
    local ep="$1"
    local pq="${2:-$MOCK_PQ}"
    local cfg="${3:-$FAKE_CFG}"
    ZSM_CONFIG_FILE="$cfg" \
    ZSM_NOW_EPOCH="$ep" \
    ZSM_POSTQUEUE_CMD="$pq" \
    ZSM_POSTSUPER_CMD="$MOCK_PS" \
    ZSM_POSTCONF_CMD="$MOCK_POSTCONF" \
    ZSM_ZMPROV_CMD="$MOCK_ZMPROV" \
    ZSM_LDAPSEARCH_CMD="$MOCK_LDAP" \
    ZSM_SENDMAIL_CMD="$MOCK_SENDMAIL" \
    ZSM_CURL_CMD="$MOCK_CURL" \
    ZSM_DIG_CMD="$MOCK_DIG" \
    ZSM_HOST_CMD="/nonexistent/host" \
    ZSM_NSLOOKUP_CMD="/nonexistent/nslookup" \
    ZSM_HOSTNAME_CMD="$MOCK_HOSTNAME" \
    ZSM_HOSTNAME="mail.company.com" \
    bash "$MONITOR_BIN" --run
}

echo "=== [4/16] Running multi-signal scan cycle (--run) ==="
run_scan "$FIXED_EPOCH"

# Verify CRITICAL spammers locked + per-account cache flushed!
grep -q "ma hacked_user@company.com zimbraAccountStatus locked" "$FAKE_ZMPROV_OUT"
grep -q "fc account hacked_user@company.com" "$FAKE_ZMPROV_OUT"
grep -q "ma phish_user@company.com zimbraAccountStatus locked" "$FAKE_ZMPROV_OUT"
grep -q "fc account phish_user@company.com" "$FAKE_ZMPROV_OUT"

# Verify CEO single BCC announcement and warn_user NOT auto-locked
if grep -q "ceo@company.com" "$FAKE_ZMPROV_OUT" || grep -q "warn_user@company.com" "$FAKE_ZMPROV_OUT"; then
    echo " -> [FAIL] ceo@company.com or warn_user@company.com should NOT be auto-locked!"
    exit 1
fi
grep -q "ceo@company.com" "$FAKE_MAIL_OUT"
grep -q "warn_user@company.com" "$FAKE_MAIL_OUT"

# Verify zero false positives on clean/whitelisted/old-retry/alias accounts
for clean_acc in "marketing@company.com" "old_retry@company.com" "sale_alias@company.com" "normal@company.com"; do
    if grep -q "$clean_acc" "$FAKE_MAIL_OUT"; then
        echo " -> [FAIL] Clean/whitelisted/old-retry account $clean_acc falsely triggered an alert!"
        exit 1
    fi
done

# Verify exact metrics, Origin, Risk Score, Account State, DNS IP, and 5m System Outbound
grep -q "Server        : mail.company.com (103.56.158.99)" "$FAKE_MAIL_OUT"
grep -q "Origin        : SASL (external client)" "$FAKE_MAIL_OUT"
grep -q "Account State : LOCKED (Auto-locked now via zmprov + cache flushed)" "$FAKE_MAIL_OUT"
grep -q "Account State : NOT LOCKED (Active - Alert Only)" "$FAKE_MAIL_OUT"
grep -q "Risk Score    :" "$FAKE_MAIL_OUT"
grep -q "webmail_warn@company.com" "$FAKE_MAIL_OUT"
grep -q "Messages Sent : 180 msgs" "$FAKE_MAIL_OUT"
grep -q "Recipients    : 180 total (Unique: 180 | Domains: 10" "$FAKE_MAIL_OUT"
grep -q "Failed Rate   : 66.7% (120/180 failed)" "$FAKE_MAIL_OUT"
grep -q "5 IPs" "$FAKE_MAIL_OUT"
grep -q "Amavis SPAM: 12 | Spoof From: 12" "$FAKE_MAIL_OUT"
grep -q "91.214.124.88 (1 IP)" "$FAKE_MAIL_OUT"
grep -q "SYSTEM OUTBOUND (LAST 5 MINS)" "$FAKE_MAIL_OUT"
grep -q "LOCKED (Auto-locked now via zmprov + cache flushed)" "$FAKE_TG_BODY"
echo " -> [PASS] Multi-signal detection, cache flush, Origin/Risk Score, DNS IP & zero false positives verified."

echo "=== [5/16] Verifying Cooldown, Long Queue IDs, Decoupled Lock Retry & Held Exclusion ==="
LOCK_CALLS_BEFORE=$(wc -l < "$FAKE_ZMPROV_OUT")
MAIL_CALLS_BEFORE=$(grep -c -- "---END_MAIL---" "$FAKE_MAIL_OUT")

# Advance 4m (within 30m cooldown): must suppress duplicate alerts & zmprov calls
NEXT_EPOCH=$(( FIXED_EPOCH + 240 ))
run_scan "$NEXT_EPOCH"

LOCK_CALLS_AFTER=$(wc -l < "$FAKE_ZMPROV_OUT")
MAIL_CALLS_AFTER=$(grep -c -- "---END_MAIL---" "$FAKE_MAIL_OUT")
if [[ "$LOCK_CALLS_BEFORE" != "$LOCK_CALLS_AFTER" || "$MAIL_CALLS_BEFORE" != "$MAIL_CALLS_AFTER" ]]; then
    echo " -> [FAIL] Cooldown failed to suppress duplicate alert or zmprov!"
    exit 1
fi

# Advance 31m with 105 Postfix Long Queue IDs (live) for already-locked phish_user
LONG_PQ="$TEST_TMP/mock_long_pq.sh"
{
    echo "#!/usr/bin/env bash"
    echo "cat << 'LQOUT'"
    echo "-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------"
    for i in $(seq 1 105); do
        printf "4XxY9z3kM%04d   1500 Sun Nov  8 14:59:00  phish_user@company.com\n" "$i"
        printf "                                         victim%d@gmail.com\n" "$i"
    done
    echo "-- 157 Kbytes in 105 Requests."
    echo "LQOUT"
} > "$LONG_PQ"
chmod +x "$LONG_PQ"

REPEAT_EPOCH=$(( FIXED_EPOCH + 1860 ))
run_scan "$REPEAT_EPOCH" "$LONG_PQ"

LOCK_CALLS_REPEAT=$(wc -l < "$FAKE_ZMPROV_OUT")
MAIL_CALLS_REPEAT=$(grep -c -- "---END_MAIL---" "$FAKE_MAIL_OUT")
if [[ "$LOCK_CALLS_REPEAT" != "$LOCK_CALLS_BEFORE" ]] || (( MAIL_CALLS_REPEAT <= MAIL_CALLS_AFTER )); then
    echo " -> [FAIL] 30m repeat alert with leftover Long Queue IDs did not fire!"
    exit 1
fi
grep -q "Account State : ALREADY LOCKED (" "$FAKE_MAIL_OUT"
grep -q "Account Queue : 105 emails (Hold: 0)" "$FAKE_MAIL_OUT"

# Now mark all 105 messages as HELD ('!'): must NOT re-trigger CRITICAL alert!
HELD_PQ="$TEST_TMP/mock_held_pq.sh"
{
    echo "#!/usr/bin/env bash"
    echo "cat << 'HQOUT'"
    echo "-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------"
    for i in $(seq 1 105); do
        printf "4XxY9z3kM%04d!  1500 Sun Nov  8 14:59:00  phish_user@company.com\n" "$i"
        printf "                                         victim%d@gmail.com\n" "$i"
    done
    echo "HQOUT"
} > "$HELD_PQ"
chmod +x "$HELD_PQ"

STOP_EPOCH=$(( FIXED_EPOCH + 3720 ))
MAIL_BEFORE_HELD=$(grep -c -- "---END_MAIL---" "$FAKE_MAIL_OUT")
run_scan "$STOP_EPOCH" "$HELD_PQ"
MAIL_AFTER_HELD=$(grep -c -- "---END_MAIL---" "$FAKE_MAIL_OUT")
if [[ "$MAIL_BEFORE_HELD" != "$MAIL_AFTER_HELD" ]]; then
    echo " -> [FAIL] Already-HELD ('!') queue messages falsely triggered CRITICAL alert!"
    exit 1
fi

# Decoupled Lock Retry: if zmprov FAILS on cycle 1, cycle 2 (inside 30m cooldown!) MUST retry and lock!
EMPTY_PQ="$TEST_TMP/empty_pq.sh"
printf "#!/usr/bin/env bash\necho 'Mail queue is empty'\n" > "$EMPTY_PQ"
chmod +x "$EMPTY_PQ"

RETRY_T1=$(( FIXED_EPOCH + 7200 ))
T1_STR=$(date -d "@$(( RETRY_T1 - 60 ))" '+%b %e %H:%M:%S')
for i in $(seq 1 155); do
    printf "%s mail postfix/submission/smtpd[1001]: QRTY%03d: client=vps[198.51.100.99], sasl_method=LOGIN, sasl_username=retry_lock@company.com\n" "$T1_STR" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/smtp[1004]: QRTY%03d: to=<u%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=0.2, status=sent (250 OK)\n" "$T1_STR" "$i" "$i" >> "$FAKE_LOG"
done

touch "$TEST_TMP/fail_zmprov"
run_scan "$RETRY_T1" "$EMPTY_PQ"
grep -q "LOCK FAILED" "$FAKE_MAIL_OUT"
rm -f "$TEST_TMP/fail_zmprov"

# Only 2 minutes later (still inside 30m alert cooldown!): lock MUST retry and succeed!
run_scan "$(( RETRY_T1 + 120 ))" "$EMPTY_PQ"
grep -q "^ma retry_lock@company.com zimbraAccountStatus locked$" "$FAKE_ZMPROV_OUT"
echo " -> [PASS] Cooldown, Long Queue IDs, Held exclusion & decoupled lock retry verified."

echo "=== [6/16] Verifying Locked-Account Desync Recovery (Benign Unlock vs RE-LOCK) ==="
# Case 6a: phish_user was locked at FIXED_EPOCH. Suppose admin unlocked externally via Web UI
# and phish_user sends 3 NORMAL emails 3 hours later -> MUST NOT re-lock, MUST clear stale lock DB!
DESYNC_T1=$(( FIXED_EPOCH + 10800 ))
DT1_STR=$(date -d "@$(( DESYNC_T1 - 60 ))" '+%b %e %H:%M:%S')
for i in $(seq 1 3); do
    printf "%s mail postfix/submission/smtpd[1001]: QBN%03d: client=office[192.0.2.10], sasl_method=LOGIN, sasl_username=phish_user@company.com\n" "$DT1_STR" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/smtp[1004]: QBN%03d: to=<ok%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=0.2, status=sent (250 OK)\n" "$DT1_STR" "$i" "$i" >> "$FAKE_LOG"
done
PHISH_LOCKS_BEFORE=$(grep -c "ma phish_user@company.com zimbraAccountStatus locked" "$FAKE_ZMPROV_OUT")
run_scan "$DESYNC_T1" "$EMPTY_PQ"
PHISH_LOCKS_AFTER=$(grep -c "ma phish_user@company.com zimbraAccountStatus locked" "$FAKE_ZMPROV_OUT")
if [[ "$PHISH_LOCKS_BEFORE" != "$PHISH_LOCKS_AFTER" ]]; then
    echo " -> [FAIL] Externally unlocked account sending 3 normal emails was falsely re-locked!"
    exit 1
fi
if grep -qi "^phish_user@company.com|" "$FAKE_STATE/locked_accounts.db" 2>/dev/null; then
    echo " -> [FAIL] Stale locked_accounts.db entry was not cleaned after benign external unlock!"
    exit 1
fi

# Case 6b: hacked_user is still in locked_accounts.db, yet sends CRITICAL spam again after grace window -> RE-LOCKED!
DESYNC_T2=$(( FIXED_EPOCH + 11100 ))
DT2_STR=$(date -d "@$(( DESYNC_T2 - 60 ))" '+%b %e %H:%M:%S')
for i in $(seq 1 155); do
    printf "%s mail postfix/submission/smtpd[1001]: QRLK%03d: client=bot[198.51.100.77], sasl_method=LOGIN, sasl_username=hacked_user@company.com\n" "$DT2_STR" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/smtp[1004]: QRLK%03d: to=<v%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=0.2, status=sent (250 OK)\n" "$DT2_STR" "$i" "$i" >> "$FAKE_LOG"
done
run_scan "$DESYNC_T2" "$EMPTY_PQ"
grep -q "RE-LOCKED (Still sending after prior lock" "$FAKE_MAIL_OUT"
echo " -> [PASS] Desync self-healing verified (no false re-lock on benign mail; RE-LOCKED on active CRITICAL spam)."

echo "=== [7/16] Verifying Security Fixes (Command Injection, Hidden Token, Safe Config Writer) ==="
# 7a: Telegram bot token MUST NEVER appear in curl CLI arguments (ps aux protection)
if grep -q "SUPER_SECRET_TOKEN" "$FAKE_TG_ARGS"; then
    echo " -> [FAIL] TELEGRAM_BOT_TOKEN leaked onto curl CLI arguments!"
    exit 1
fi

# 7b: Command injection payload in log email address (single quote) MUST NOT invoke zmprov
INJ_T=$(( FIXED_EPOCH + 14400 ))
INJ_STR=$(date -d "@$(( INJ_T - 30 ))" '+%b %e %H:%M:%S')
for i in $(seq 1 155); do
    printf "%s mail postfix/submission/smtpd[1001]: QINJ%03d: client=vps[198.51.100.88], sasl_method=LOGIN, sasl_username=bad';touch_/tmp/pwn;@company.com\n" "$INJ_STR" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/smtp[1004]: QINJ%03d: to=<x%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=0.2, status=sent (250 OK)\n" "$INJ_STR" "$i" "$i" >> "$FAKE_LOG"
done
run_scan "$INJ_T" "$EMPTY_PQ"
if grep -q "touch_/tmp/pwn" "$FAKE_ZMPROV_OUT"; then
    echo " -> [FAIL] Invalid/malicious email with single quote was passed to zmprov!"
    exit 1
fi
grep -q "NOT LOCKED (Invalid or non-mailbox identity" "$FAKE_MAIL_OUT"

# 7c: Complex SMTP password with | & $ " \ round-trips cleanly via update_cfg_var
SPECIAL_CFG="$TEST_TMP/special_pw.conf"
cp "$FAKE_CFG" "$SPECIAL_CFG"
COMPLEX_PW='a|b&c$HOME"e\f'
ZSM_CONFIG_FILE="$SPECIAL_CFG" bash -c '
    source <(sed "/^# ENTRYPOINT/,\$d" "'"$MONITOR_BIN"'")
    load_config
    update_cfg_var "SMTP_PASS" "$1"
    SMTP_PASS=""
    load_config
    [[ "$SMTP_PASS" == "$1" ]] || { echo "MISMATCH: got [$SMTP_PASS]"; exit 1; }
' _ "$COMPLEX_PW"
echo " -> [PASS] Security fixes verified (Command Injection blocked, token hidden from curl args, special chars safe)."

echo "=== [8/16] Verifying Per-Message Amavis/Spoof Counting, Deduped Retries & status=expired ==="
ACC_T=$(( FIXED_EPOCH + 18000 ))
ACC_STR=$(date -d "@$(( ACC_T - 40 ))" '+%b %e %H:%M:%S')
# 8a: 1 single email CC to 12 external recipients flagged by Amavis + external spoof = 1 Amavis / 1 Spoof (NOT 12!)
printf "%s mail postfix/submission/smtpd[1001]: QCC001: client=office[192.0.2.90], sasl_method=LOGIN, sasl_username=cc_single@company.com\n" "$ACC_STR" >> "$FAKE_LOG"
printf "%s mail postfix/qmgr[1002]: QCC001: from=<promo@external-agency.net>, size=2000, nrcpt=12 (queue active)\n" "$ACC_STR" >> "$FAKE_LOG"
printf "%s mail amavis[2001]: (2001-99) Passed SPAMMY {RelayedTaggedOutbound}, ORIGINATING [192.0.2.90]:51000 <promo@external-agency.net> -> <r1@gmail.com>, Queue-ID: QCC001, Hits: 8.5\n" "$ACC_STR" >> "$FAKE_LOG"
for i in $(seq 1 12); do
    printf "%s mail postfix/smtp[1004]: QCC001: to=<r%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=0.3, status=sent (250 OK)\n" "$ACC_STR" "$i" >> "$FAKE_LOG"
done

# 8b: Same (root_qid, rcpt) retried 3 times (deferred -> deferred -> sent) across 25 msgs -> 0% failed (NOT 66%!)
for i in $(seq 1 25); do
    printf "%s mail postfix/submission/smtpd[1001]: QDED%03d: client=office[192.0.2.91], sasl_method=LOGIN, sasl_username=dedup_ok@company.com\n" "$ACC_STR" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/smtp[1004]: QDED%03d: to=<p%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=1.0, status=deferred (421 temp)\n" "$ACC_STR" "$i" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/smtp[1004]: QDED%03d: to=<p%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=15.0, status=deferred (421 temp)\n" "$ACC_STR" "$i" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/smtp[1004]: QDED%03d: to=<p%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=30.0, status=sent (250 OK)\n" "$ACC_STR" "$i" "$i" >> "$FAKE_LOG"
done

# 8c: status=expired counted as failed (25 msgs, 12 expired = 48.0% >= 30% -> WARNING)
for i in $(seq 1 25); do
    printf "%s mail postfix/submission/smtpd[1001]: QEXP%03d: client=office[192.0.2.92], sasl_method=LOGIN, sasl_username=exp_warn@company.com\n" "$ACC_STR" "$i" >> "$FAKE_LOG"
    if (( i <= 12 )); then
        printf "%s mail postfix/error[1004]: QEXP%03d: to=<e%d@dead.org>, delay=1.0, status=expired (delivery expired)\n" "$ACC_STR" "$i" "$i" >> "$FAKE_LOG"
    else
        printf "%s mail postfix/smtp[1004]: QEXP%03d: to=<e%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=0.4, status=sent (250 OK)\n" "$ACC_STR" "$i" "$i" >> "$FAKE_LOG"
    fi
done

run_scan "$ACC_T" "$EMPTY_PQ"
if grep -q "cc_single@company.com" "$FAKE_ZMPROV_OUT" || grep -q "cc_single@company.com" "$FAKE_MAIL_OUT"; then
    echo " -> [FAIL] Single CC email (12 rcpts) falsely inflated Amavis/Spoof count to 12!"
    exit 1
fi
if grep -q "dedup_ok@company.com" "$FAKE_MAIL_OUT"; then
    echo " -> [FAIL] Deduped deferred->sent retries falsely triggered Failed Rate alert!"
    exit 1
fi
grep -q "exp_warn@company.com" "$FAKE_MAIL_OUT"
echo " -> [PASS] Per-msg Spoof/Amavis, deduped deferred->sent retries, and status=expired verified."

echo "=== [9/16] Verifying Multi-Window Low-and-Slow (1h Rolling Buckets & Idempotency) ==="
LS_BASE=$(( FIXED_EPOCH + 36000 ))
# Simulate 12 consecutive 5-minute buckets x 55 msgs each (= 660 msgs in 1h; each 5m is < 60 WARN!)
for b in $(seq 0 11); do
    B_EP=$(( LS_BASE + b * 300 ))
    B_STR=$(date -d "@$(( B_EP - 30 ))" '+%b %e %H:%M:%S')
    for i in $(seq 1 55); do
        printf "%s mail postfix/submission/smtpd[1001]: QLS%02d%03d: client=vps[198.51.200.5], sasl_method=LOGIN, sasl_username=slow_spam@company.com\n" "$B_STR" "$b" "$i" >> "$FAKE_LOG"
        printf "%s mail postfix/smtp[1004]: QLS%02d%03d: to=<t%d_%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=0.2, status=sent (250 OK)\n" "$B_STR" "$b" "$i" "$b" "$i" >> "$FAKE_LOG"
    done
    run_scan "$B_EP" "$EMPTY_PQ"
done
# Re-run twice in the same final bucket (simulating 1-min cron) -> MUST stay 660, NOT double-count!
FINAL_LS=$(( LS_BASE + 11 * 300 ))
run_scan "$(( FINAL_LS + 30 ))" "$EMPTY_PQ"
run_scan "$(( FINAL_LS + 60 ))" "$EMPTY_PQ"

grep -q "ma slow_spam@company.com zimbraAccountStatus locked" "$FAKE_ZMPROV_OUT"
grep -q "1h Msgs (660>=600)" "$FAKE_MAIL_OUT"
# Verify rolling_history sum for slow_spam is exactly 660 (never inflated by re-runs)
SLOW_SUM=$(awk -F'|' '$2 == "slow_spam@company.com" {s += $3} END {print s+0}' "$FAKE_STATE/rolling_history.db")
if [[ "$SLOW_SUM" != "660" ]]; then
    echo " -> [FAIL] Expected idempotent 1h rolling sum=660, got $SLOW_SUM!"
    exit 1
fi
echo " -> [PASS] Low-and-slow 1h detection (660 msgs) & idempotent bucket merge verified."

echo "=== [10/16] Verifying Single-Server mailbox.log Real Webmail /24 IPs, 4G Safety & audit.log Brute-Force ==="
MBOX_T=$(( FIXED_EPOCH + 50000 ))
MBOX_SYS=$(date -d "@$(( MBOX_T - 40 ))" '+%b %e %H:%M:%S')
MBOX_ISO=$(date -d "@$(( MBOX_T - 40 ))" '+%Y-%m-%d %H:%M:%S')

# 10a: Webmail botnet using 5 DISTINCT /24 subnets (25 msgs via local 127.0.0.1 in zimbra.log, real oip= in mailbox.log) -> CRITICAL + Lock!
WEB_BOT_IPS=("45.10.1.5" "45.11.2.6" "45.12.3.7" "45.13.4.8" "45.14.5.9")
for i in $(seq 1 25); do
    wip="${WEB_BOT_IPS[$(( i % 5 ))]}"
    printf "%s mail postfix/smtpd[1005]: QWBOT%03d: client=localhost[127.0.0.1]\n" "$MBOX_SYS" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/qmgr[1002]: QWBOT%03d: from=<web_botnet@company.com>, size=1100, nrcpt=1 (queue active)\n" "$MBOX_SYS" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/smtp[1004]: QWBOT%03d: to=<v%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=0.3, status=sent (250 OK)\n" "$MBOX_SYS" "$i" "$i" >> "$FAKE_LOG"
    printf "%s,123 INFO  [qtp1-1] [name=web_botnet@company.com;mid=10;ip=127.0.0.1;oip=%s;ua=ZimbraWebClient;] smtp - Sending message to MTA at 127.0.0.1\n" "$MBOX_ISO" "$wip" >> "$FAKE_MBOX_LOG"
done

# 10b: Mobile 4G user rotating 5 IPs inside the SAME /24 subnet (171.244.10.11..15, 25 msgs) -> 1 /24 net -> NO alert!
for i in $(seq 1 25); do
    mip="171.244.10.$(( 11 + (i % 5) ))"
    printf "%s mail postfix/submission/smtpd[1001]: Q4G%03d: client=telco[%s], sasl_method=LOGIN, sasl_username=mobile_4g@company.com\n" "$MBOX_SYS" "$i" "$mip" >> "$FAKE_LOG"
    printf "%s mail postfix/smtp[1004]: Q4G%03d: to=<c%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=0.3, status=sent (250 OK)\n" "$MBOX_SYS" "$i" "$i" >> "$FAKE_LOG"
done

# 10c: Brute-force in audit.log (55 failed logins from 185.99.1.10) + Auth-After-Fail (6 fails + 1 success for victim_bf@company.com)
for i in $(seq 1 55); do
    printf "%s,100 WARN  [qtp1-2] [name=target%d@company.com;ip=127.0.0.1;oip=185.99.1.10;] security - cmd=Auth; account=target%d@company.com; protocol=soap; error=authentication failed for [target%d@company.com], invalid password;\n" "$MBOX_ISO" "$i" "$i" "$i" >> "$FAKE_AUDIT_LOG"
done
for i in $(seq 1 6); do
    printf "%s,200 WARN  [qtp1-3] [name=victim_bf@company.com;ip=127.0.0.1;oip=185.99.2.20;] security - cmd=Auth; account=victim_bf@company.com; protocol=soap; error=authentication failed for [victim_bf@company.com], invalid password;\n" "$MBOX_ISO" >> "$FAKE_AUDIT_LOG"
done
printf "%s,900 INFO  [qtp1-3] [name=victim_bf@company.com;ip=127.0.0.1;oip=185.99.2.20;] security - cmd=Auth; account=victim_bf@company.com; protocol=soap;\n" "$MBOX_ISO" >> "$FAKE_AUDIT_LOG"

run_scan "$MBOX_T" "$EMPTY_PQ"

grep -q "ma web_botnet@company.com zimbraAccountStatus locked" "$FAKE_ZMPROV_OUT"
grep -q "45.10.1.5" "$FAKE_MAIL_OUT"
if grep -q "mobile_4g@company.com" "$FAKE_MAIL_OUT" || grep -q "mobile_4g@company.com" "$FAKE_ZMPROV_OUT"; then
    echo " -> [FAIL] Mobile 4G user within same /24 subnet triggered false botnet alert!"
    exit 1
fi
grep -q "ZIMBRA AUTH BRUTE-FORCE WARNING" "$FAKE_MAIL_OUT"
grep -q "185.99.1.10" "$FAKE_STATE/attacker_ips.log"
grep -q "Login After 6 Fails (185.99.2.20)" "$FAKE_MAIL_OUT"
if grep -q "victim_bf@company.com" "$FAKE_ZMPROV_OUT"; then
    echo " -> [FAIL] Brute-force victim account was falsely auto-locked!"
    exit 1
fi
echo " -> [PASS] mailbox.log real Webmail /24 IPs, 4G subnet safety, brute-force summary & auth-after-fail verified."

echo "=== [11/16] Verifying Auto-Forward Safeguard, Spoofed Queue Hold, Internal Malware & Local Pickup ==="
S11_T=$(( FIXED_EPOCH + 56000 ))
S11_STR=$(date -d "@$(( S11_T - 30 ))" '+%b %e %H:%M:%S')

# 11a: Auto-forward (local/webmail origin, 12 Gmail 5.7.1 rejects, no SASL, no spoof, no volume) -> WARNING ONLY, NOT locked!
for i in $(seq 1 12); do
    printf "%s mail postfix/smtpd[1005]: QFWD%03d: client=localhost[127.0.0.1]\n" "$S11_STR" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/qmgr[1002]: QFWD%03d: from=<autofwd_user@company.com>, size=1200, nrcpt=1 (queue active)\n" "$S11_STR" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/smtp[1004]: QFWD%03d: to=<personal@gmail.com>, relay=mx.gmail.com[142.250.1.1]:25, delay=0.5, status=bounced (550-5.7.1 Unsolicited message)\n" "$S11_STR" "$i" >> "$FAKE_LOG"
done

# 11b: Spoofed SASL sender with AUTO_HOLD_QUEUE_ON_CRITICAL=true -> must hold QID even though queue envelope From is fake@random.org!
for i in $(seq 1 12); do
    printf "%s mail postfix/submission/smtpd[1001]: QSPF%03d: client=vps[91.1.2.3], sasl_method=LOGIN, sasl_username=spoof_hold@company.com\n" "$S11_STR" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/qmgr[1002]: QSPF%03d: from=<fake@random-external.org>, size=1500, nrcpt=1 (queue active)\n" "$S11_STR" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/smtp[1004]: QSPF%03d: to=<v%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=0.3, status=deferred (421 temp)\n" "$S11_STR" "$i" "$i" >> "$FAKE_LOG"
done

# 11c: Internal-to-internal Amavis Blocked BANNED malware via smtp/lmtp (must be caught even when COUNT_INTERNAL_TO_INTERNAL=false!)
for i in $(seq 1 4); do
    printf "%s mail postfix/submission/smtpd[1001]: QINT%03d: client=office[192.0.2.70], sasl_method=LOGIN, sasl_username=int_malware@company.com\n" "$S11_STR" "$i" >> "$FAKE_LOG"
    printf "%s mail amavis[2001]: (2001-%02d) Blocked BANNED (.exe) {DiscardedInternal}, ORIGINATING [192.0.2.70]:50000 <int_malware@company.com> -> <staff%d@company.com>, Queue-ID: QINT%03d\n" "$S11_STR" "$i" "$i" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/smtp[1003]: QINT%03d: to=<staff%d@company.com>, relay=127.0.0.1[127.0.0.1]:10024, delay=0.2, status=sent (250 2.7.0 Ok, discarded)\n" "$S11_STR" "$i" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/lmtp[1005]: QINT%03d: to=<staff%d@company.com>, relay=mail.company.com[127.0.0.1]:7025, delay=0.1, status=sent (250 2.1.5 Delivery OK)\n" "$S11_STR" "$i" "$i" >> "$FAKE_LOG"
done

# 11d: Local pickup webshell (uid=33, 22 msgs with external From) + benign root@localhost (30 msgs -> ignored!)
for i in $(seq 1 22); do
    printf "%s mail postfix/pickup[1009]: QPKP%03d: uid=33 from=<promo@evil-shell.biz>\n" "$S11_STR" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/qmgr[1002]: QPKP%03d: from=<promo@evil-shell.biz>, size=900, nrcpt=1 (queue active)\n" "$S11_STR" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/smtp[1004]: QPKP%03d: to=<x%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=0.2, status=sent (250 OK)\n" "$S11_STR" "$i" "$i" >> "$FAKE_LOG"
done
for i in $(seq 1 30); do
    printf "%s mail postfix/pickup[1009]: QROT%03d: uid=0 from=<root@localhost>\n" "$S11_STR" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/qmgr[1002]: QROT%03d: from=<root@localhost>, size=500, nrcpt=1 (queue active)\n" "$S11_STR" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/smtp[1004]: QROT%03d: to=<ops%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=0.2, status=sent (250 OK)\n" "$S11_STR" "$i" "$i" >> "$FAKE_LOG"
done

SPOOF_PQ="$TEST_TMP/mock_spoof_pq.sh"
cat << 'EOF' > "$SPOOF_PQ"
#!/usr/bin/env bash
cat << 'SQOUT'
-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------
QSPF001         1500 Sun Nov  8 14:58:00  fake@random-external.org
                                         v1@gmail.com
QSPF002         1500 Sun Nov  8 14:58:01  fake@random-external.org
                                         v2@gmail.com
SQOUT
EOF
chmod +x "$SPOOF_PQ"

HOLD_CFG="$TEST_TMP/hold.conf"
cp "$FAKE_CFG" "$HOLD_CFG"
sed -i 's|^AUTO_HOLD_QUEUE_ON_CRITICAL=.*|AUTO_HOLD_QUEUE_ON_CRITICAL="true"|' "$HOLD_CFG"

run_scan "$S11_T" "$SPOOF_PQ" "$HOLD_CFG"

if grep -q "autofwd_user@company.com" "$FAKE_ZMPROV_OUT"; then
    echo " -> [FAIL] Auto-forward webmail/local user was falsely auto-locked!"
    exit 1
fi
grep -q "autofwd_user@company.com" "$FAKE_MAIL_OUT"
grep -q "Local/Forward Safeguard" "$FAKE_MAIL_OUT"
grep -q -- "-h - QSPF001" "$FAKE_POSTSUPER_OUT"
grep -q -- "-h - QSPF002" "$FAKE_POSTSUPER_OUT"
grep -q "int_malware@company.com" "$FAKE_MAIL_OUT"
grep -q "local-pickup-uid:33" "$FAKE_MAIL_OUT"
if grep -q "local-pickup-uid:33" "$FAKE_ZMPROV_OUT" || grep -q "local-pickup-uid:0" "$FAKE_MAIL_OUT"; then
    echo " -> [FAIL] Local pickup either called zmprov or falsely alerted root@localhost!"
    exit 1
fi
echo " -> [PASS] Auto-forward safeguard, spoofed QID hold, internal Amavis malware & local pickup verified."

echo "=== [12/16] Verifying Custom Limits, Composite Risk Score, LDAP Multi-Domain & Logrotate .1 ==="
S12_T=$(( FIXED_EPOCH + 62000 ))
S12_STR=$(date -d "@$(( S12_T - 30 ))" '+%b %e %H:%M:%S')

# 12a: Custom limit "bulk_ok@company.com 250 500" -> sends 180 msgs (< 250) -> MUST NOT alert!
echo "bulk_ok@company.com 250 500" >> "$FAKE_WL"
for i in $(seq 1 180); do
    printf "%s mail postfix/submission/smtpd[1001]: QBLK%03d: client=app[192.0.2.80], sasl_method=LOGIN, sasl_username=bulk_ok@company.com\n" "$S12_STR" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/smtp[1004]: QBLK%03d: to=<c%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=0.2, status=sent (250 OK)\n" "$S12_STR" "$i" "$i" >> "$FAKE_LOG"
done

# 12b: Evasive spammer staying JUST UNDER every single WARN threshold simultaneously:
# Msgs=50 (<60), Rcpts=50 (<100), Failed=24% (12/50 <30%), IPs=2 /24 (<3), Spoof=2 (<3), Amavis=2 (<3)
# Score: Msgs(12) + Fail(16) + IPs(13) + Spoof(16) + Amavis(16) + Queue(13 for 35 queued) = 86 >= 85 -> CRITICAL!
for i in $(seq 1 50); do
    eip="198.51.$(( 10 + (i % 2) )).5"
    printf "%s mail postfix/submission/smtpd[1001]: QEVS%03d: client=vps[%s], sasl_method=LOGIN, sasl_username=evasive@company.com\n" "$S12_STR" "$i" "$eip" >> "$FAKE_LOG"
    if (( i <= 2 )); then
        printf "%s mail postfix/qmgr[1002]: QEVS%03d: from=<fake@spoof-ext.org>, size=1200, nrcpt=1 (queue active)\n" "$S12_STR" "$i" >> "$FAKE_LOG"
        printf "%s mail amavis[2001]: (2001-%02d) Passed SPAMMY {RelayedTaggedOutbound}, ORIGINATING [%s]:5000 <fake@spoof-ext.org> -> <v%d@gmail.com>, Queue-ID: QEVS%03d, Hits: 8.0\n" "$S12_STR" "$i" "$eip" "$i" "$i" >> "$FAKE_LOG"
    else
        printf "%s mail postfix/qmgr[1002]: QEVS%03d: from=<evasive@company.com>, size=1200, nrcpt=1 (queue active)\n" "$S12_STR" "$i" >> "$FAKE_LOG"
    fi
    if (( i <= 12 )); then
        printf "%s mail postfix/smtp[1004]: QEVS%03d: to=<v%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=0.3, status=deferred (421 temp)\n" "$S12_STR" "$i" "$i" >> "$FAKE_LOG"
    else
        printf "%s mail postfix/smtp[1004]: QEVS%03d: to=<v%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=0.3, status=sent (250 OK)\n" "$S12_STR" "$i" "$i" >> "$FAKE_LOG"
    fi
done

EVS_PQ="$TEST_TMP/mock_evs_pq.sh"
{
    echo "#!/usr/bin/env bash"
    echo "cat << 'EQOUT'"
    echo "-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------"
    for i in $(seq 1 35); do
        printf "QEVSQ%04d       1200 Sun Nov  8 14:59:00  evasive@company.com\n" "$i"
        printf "                                         v%d@gmail.com\n" "$i"
    done
    echo "EQOUT"
} > "$EVS_PQ"
chmod +x "$EVS_PQ"

run_scan "$S12_T" "$EVS_PQ"
if grep -q "bulk_ok@company.com" "$FAKE_MAIL_OUT"; then
    echo " -> [FAIL] Account under Custom Limit (180 < 250) falsely triggered alert!"
    exit 1
fi
grep -q "ma evasive@company.com zimbraAccountStatus locked" "$FAKE_ZMPROV_OUT"
grep -q "Risk Score (" "$FAKE_MAIL_OUT"

# 12c: LDAP Multi-Domain Discovery + Logrotate (.1) Continuity
ROT_LOG="$TEST_TMP/rot_zimbra.log"
ROT_LOG1="${ROT_LOG}.1"
ROT_CFG="$TEST_TMP/rot.conf"
ROT_STATE="$TEST_TMP/rot_state"
cp "$FAKE_CFG" "$ROT_CFG"
sed -i "s|^ZIMBRA_LOG_FILE=.*|ZIMBRA_LOG_FILE=\"$ROT_LOG\"|" "$ROT_CFG"
sed -i "s|^INTERNAL_DOMAINS=.*|INTERNAL_DOMAINS=\"auto\"|" "$ROT_CFG"
sed -i "s|^STATE_DIR=.*|STATE_DIR=\"$ROT_STATE\"|" "$ROT_CFG"

ROT_T=$(( FIXED_EPOCH + 70000 ))
ROT_OLD=$(date -d "@$(( ROT_T - 120 ))" '+%b %e %H:%M:%S')
ROT_NEW=$(date -d "@$(( ROT_T - 20 ))" '+%b %e %H:%M:%S')
: > "$ROT_LOG1"
: > "$ROT_LOG"
# 35 msgs in rotated .1 + 35 msgs in current log = 70 msgs >= 60 WARN for secondary domain brand2.vn (webmail)!
for i in $(seq 1 35); do
    printf "%s mail postfix/smtpd[1005]: QRT1%03d: client=localhost[127.0.0.1]\n" "$ROT_OLD" "$i" >> "$ROT_LOG1"
    printf "%s mail postfix/qmgr[1002]: QRT1%03d: from=<sales@brand2.vn>, size=1000, nrcpt=1 (queue active)\n" "$ROT_OLD" "$i" >> "$ROT_LOG1"
    printf "%s mail postfix/smtp[1004]: QRT1%03d: to=<c%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=0.2, status=sent (250 OK)\n" "$ROT_OLD" "$i" "$i" >> "$ROT_LOG1"
done
for i in $(seq 36 70); do
    printf "%s mail postfix/smtpd[1005]: QRT2%03d: client=localhost[127.0.0.1]\n" "$ROT_NEW" "$i" >> "$ROT_LOG"
    printf "%s mail postfix/qmgr[1002]: QRT2%03d: from=<sales@brand2.vn>, size=1000, nrcpt=1 (queue active)\n" "$ROT_NEW" "$i" >> "$ROT_LOG"
    printf "%s mail postfix/smtp[1004]: QRT2%03d: to=<c%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=0.2, status=sent (250 OK)\n" "$ROT_NEW" "$i" "$i" >> "$ROT_LOG"
done

run_scan "$ROT_T" "$EMPTY_PQ" "$ROT_CFG"
grep -q "brand2.vn" "$ROT_STATE/domains.cache"
grep -q "sales@brand2.vn" "$FAKE_MAIL_OUT"
grep -q "Messages Sent : 70 msgs" "$FAKE_MAIL_OUT"
echo " -> [PASS] Custom Limits, Composite Risk Score, LDAP multi-domain cache & logrotate .1 continuity verified."

echo "=== [13/16] Verifying Self-RBL, Read-Only --audit, Webhook, JSONL & Outbox Retry ==="
# 13a: Self-RBL QUERY_ERROR (127.255.255.254) MUST NOT report as LISTED!
touch "$TEST_TMP/rbl_err"
RBL_ERR_OUT=$(ZSM_CONFIG_FILE="$FAKE_CFG" ZSM_DIG_CMD="$MOCK_DIG" ZSM_HOST_CMD="/nonexistent/host" \
    ZSM_NSLOOKUP_CMD="/nonexistent/nslookup" ZSM_HOSTNAME_CMD="$MOCK_HOSTNAME" ZSM_HOSTNAME="mail.company.com" \
    ZSM_TEST_RBL_ERR="$TEST_TMP/rbl_err" bash "$MONITOR_BIN" --check-rbl)
echo "$RBL_ERR_OUT" | grep -q "\[QUERY_ERROR\]"
if echo "$RBL_ERR_OUT" | grep -q "\[LISTED!\]"; then
    echo " -> [FAIL] Spamhaus 127.255.255.254 query error was falsely reported as LISTED!"
    exit 1
fi
rm -f "$TEST_TMP/rbl_err"

# 13b: Self-RBL LISTED (127.0.0.2) -> alerts on state change ONLY!
RBL_CFG="$TEST_TMP/rbl.conf"
RBL_STATE="$TEST_TMP/rbl_state"
cp "$FAKE_CFG" "$RBL_CFG"
sed -i "s|^STATE_DIR=.*|STATE_DIR=\"$RBL_STATE\"|" "$RBL_CFG"
sed -i 's|^RBL_CHECK_ENABLED=.*|RBL_CHECK_ENABLED="true"|' "$RBL_CFG"
sed -i 's|^RBL_CHECK_INTERVAL_MINUTES=.*|RBL_CHECK_INTERVAL_MINUTES=1|' "$RBL_CFG"
sed -i 's|^WEBHOOK_ENABLED=.*|WEBHOOK_ENABLED="true"|' "$RBL_CFG"
sed -i 's|^WEBHOOK_URL=.*|WEBHOOK_URL="https://hooks.example.test/secret_wh"|' "$RBL_CFG"
sed -i 's|^WEBHOOK_FORMAT=.*|WEBHOOK_FORMAT="generic"|' "$RBL_CFG"

touch "$TEST_TMP/rbl_listed"
MAIL_PRE_RBL=$(grep -c -- "---END_MAIL---" "$FAKE_MAIL_OUT")
ZSM_TEST_RBL_LISTED="$TEST_TMP/rbl_listed" run_scan "$(( FIXED_EPOCH + 80000 ))" "$EMPTY_PQ" "$RBL_CFG"
MAIL_POST_RBL=$(grep -c -- "---END_MAIL---" "$FAKE_MAIL_OUT")
(( MAIL_POST_RBL > MAIL_PRE_RBL ))
grep -q "SERVER IP BLACKLISTED (RBL)" "$FAKE_MAIL_OUT"
grep -q '"event":"self_rbl"' "$FAKE_WH_BODY"

# Re-run 2 mins later while STILL listed: NO duplicate alert because state did not change!
ZSM_TEST_RBL_LISTED="$TEST_TMP/rbl_listed" run_scan "$(( FIXED_EPOCH + 80120 ))" "$EMPTY_PQ" "$RBL_CFG"
MAIL_STILL_RBL=$(grep -c -- "---END_MAIL---" "$FAKE_MAIL_OUT")
if [[ "$MAIL_POST_RBL" != "$MAIL_STILL_RBL" ]]; then
    echo " -> [FAIL] Self-RBL re-alerted even though listing state did not change!"
    exit 1
fi
rm -f "$TEST_TMP/rbl_listed"

# 13c: Read-only --audit
AUDIT_OUT=$(ZSM_CONFIG_FILE="$FAKE_CFG" ZSM_DIG_CMD="$MOCK_DIG" ZSM_HOST_CMD="/nonexistent/host" \
    ZSM_NSLOOKUP_CMD="/nonexistent/nslookup" ZSM_POSTCONF_CMD="$MOCK_POSTCONF" \
    ZSM_HOSTNAME_CMD="$MOCK_HOSTNAME" ZSM_HOSTNAME="mail.company.com" bash "$MONITOR_BIN" --audit)
echo "$AUDIT_OUT" | grep -q "SPF DNS record found"
echo "$AUDIT_OUT" | grep -q "DMARC DNS record found"
echo "$AUDIT_OUT" | grep -q "OVERALL ANTI-SPAM POSTURE SCORE: 100 / 100"

# 13d: Validate every line in JSONL log is valid JSON
"$PY_CMD" - "$FAKE_JSON_LOG" << 'PYEOF'
import json, sys
from pathlib import Path
lines = [l for l in Path(sys.argv[1]).read_text(encoding="ascii").splitlines() if l.strip()]
assert len(lines) >= 3, "Expected >= 3 JSONL events"
for l in lines:
    obj = json.loads(l)
    assert "event" in obj and "version" in obj
print(f" -> [PASS] Validated {len(lines)} well-formed JSONL events.")
PYEOF

# 13e: Outbox retry when curl fails on cycle 1 and recovers on cycle 2
OB_CFG="$TEST_TMP/outbox.conf"
OB_STATE="$TEST_TMP/ob_state"
OB_LOG="$TEST_TMP/ob.log"
cp "$FAKE_CFG" "$OB_CFG"
sed -i "s|^STATE_DIR=.*|STATE_DIR=\"$OB_STATE\"|" "$OB_CFG"
sed -i "s|^ZIMBRA_LOG_FILE=.*|ZIMBRA_LOG_FILE=\"$OB_LOG\"|" "$OB_CFG"
sed -i 's|^EMAIL_ENABLED=.*|EMAIL_ENABLED="false"|' "$OB_CFG"

OB_T=$(( FIXED_EPOCH + 85000 ))
OB_STR=$(date -d "@$(( OB_T - 20 ))" '+%b %e %H:%M:%S')
for i in $(seq 1 70); do
    printf "%s mail postfix/submission/smtpd[1001]: QOB%03d: client=vps[198.51.100.5], sasl_method=LOGIN, sasl_username=outbox_user@company.com\n" "$OB_STR" "$i" >> "$OB_LOG"
    printf "%s mail postfix/smtp[1004]: QOB%03d: to=<u%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=0.2, status=sent (250 OK)\n" "$OB_STR" "$i" "$i" >> "$OB_LOG"
done

touch "$TEST_TMP/fail_curl"
run_scan "$OB_T" "$EMPTY_PQ" "$OB_CFG"
[[ $(find "$OB_STATE/outbox" -name '*.msg' | wc -l | tr -d ' ') -eq 1 ]]
rm -f "$TEST_TMP/fail_curl"
run_scan "$(( OB_T + 120 ))" "$EMPTY_PQ" "$OB_CFG"
[[ $(find "$OB_STATE/outbox" -name '*.msg' | wc -l | tr -d ' ') -eq 0 ]]
grep -q "outbox_user@company.com" "$FAKE_TG_BODY"
echo " -> [PASS] Self-RBL, read-only --audit, Webhook, JSONL & Outbox retry verified."

echo "=== [14/16] Verifying Admin --unlock (Clears Rolling History), --status & 24h IP Cache ==="
UNLOCK_EPOCH=$(( FIXED_EPOCH + 90000 ))
ZSM_CONFIG_FILE="$FAKE_CFG" \
ZSM_NOW_EPOCH="$UNLOCK_EPOCH" \
ZSM_ZMPROV_CMD="$MOCK_ZMPROV" \
bash "$MONITOR_BIN" --unlock slow_spam@company.com >/dev/null

# Verify slow_spam rolling history was cleared
if grep -q "slow_spam@company.com" "$FAKE_STATE/rolling_history.db" 2>/dev/null; then
    echo " -> [FAIL] --unlock did not clear slow_spam@company.com from rolling_history.db!"
    exit 1
fi

ZSM_CONFIG_FILE="$FAKE_CFG" \
ZSM_NOW_EPOCH="$UNLOCK_EPOCH" \
ZSM_ZMPROV_CMD="$MOCK_ZMPROV" \
bash "$MONITOR_BIN" --unlock hacked_user@company.com >/dev/null

# After unlock, hacked_user sends 4 normal emails -> stays NORMAL
POST_STR=$(date -d "@$(( UNLOCK_EPOCH + 60 ))" '+%b %e %H:%M:%S')
for i in $(seq 1 4); do
    printf "%s mail postfix/submission/smtpd[1001]: QPOST%03d: client=office[192.0.2.10], sasl_method=LOGIN, sasl_username=hacked_user@company.com\n" "$POST_STR" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/smtp[1004]: QPOST%03d: to=<client%d@gmail.com>, relay=mx.gmail.com[142.250.1.1]:25, delay=0.3, status=sent (250 OK)\n" "$POST_STR" "$i" "$i" >> "$FAKE_LOG"
done
POST_UNLOCK_SCAN_EPOCH=$(( UNLOCK_EPOCH + 120 ))
MAIL_BEFORE_REC=$(grep -c -- "---END_MAIL---" "$FAKE_MAIL_OUT")
run_scan "$POST_UNLOCK_SCAN_EPOCH" "$EMPTY_PQ"
MAIL_AFTER_REC=$(grep -c -- "---END_MAIL---" "$FAKE_MAIL_OUT")
if [[ "$MAIL_BEFORE_REC" != "$MAIL_AFTER_REC" ]]; then
    echo " -> [FAIL] Unlocked account sending 4 normal emails triggered a false alert!"
    exit 1
fi

STATUS_OUT=$(ZSM_CONFIG_FILE="$FAKE_CFG" ZSM_NOW_EPOCH="$FIXED_EPOCH" ZSM_POSTQUEUE_CMD="$MOCK_PQ" \
    ZSM_DIG_CMD="$MOCK_DIG" ZSM_HOST_CMD="/nonexistent/host" ZSM_NSLOOKUP_CMD="/nonexistent/nslookup" \
    ZSM_HOSTNAME_CMD="$MOCK_HOSTNAME" ZSM_HOSTNAME="mail.company.com" bash "$MONITOR_BIN" --status)
echo "$STATUS_OUT" | grep -q "LIVE SYSTEM STATUS (LAST 5 MINS)"
echo "$STATUS_OUT" | grep -q "Zimbra Server   : mail.company.com (103.56.158.99)"
echo "$STATUS_OUT" | grep -q "Locked Accounts :"
echo "$STATUS_OUT" | grep -q "normal@company.com         | 5     | 5 (5)"
[[ -f "$FAKE_STATE/server_ip.cache" ]] && grep -q "103.56.158.99" "$FAKE_STATE/server_ip.cache"

CFG_MANUAL_IP="$TEST_TMP/config_manual_ip.conf"
cp "$FAKE_CFG" "$CFG_MANUAL_IP"
sed -i 's|^SERVER_IP=.*|SERVER_IP="203.0.113.77"|' "$CFG_MANUAL_IP"
STATUS_MANUAL=$(ZSM_CONFIG_FILE="$CFG_MANUAL_IP" ZSM_NOW_EPOCH="$FIXED_EPOCH" ZSM_POSTQUEUE_CMD="$MOCK_PQ" \
    ZSM_DIG_CMD="$MOCK_DIG" ZSM_HOSTNAME_CMD="$MOCK_HOSTNAME" ZSM_HOSTNAME="mail.company.com" bash "$MONITOR_BIN" --status)
echo "$STATUS_MANUAL" | grep -q "Zimbra Server   : mail.company.com (203.0.113.77)"
echo " -> [PASS] --unlock recovery, --status dashboard, 24h server_ip.cache & manual SERVER_IP verified."

echo "=== [15/16] Verifying Control Panel (--text-menu) & Exact Whitelist Removal ==="
# Prepare exact-match whitelist test: admin@company.com AND sub-admin@company.com
printf "admin@company.com\nsub-admin@company.com\n" > "$FAKE_WL"

# Navigate:
# [2] Alerts & Test -> [3] Send Test Alert -> Enter -> [0] Back
# [3] Spam Limits -> [4] Email Limit (120, 240)
#                 -> [7] Hourly Limit (150, 300)
#                 -> [8] Toggle Risk Score -> [0] Back
# [5] Whitelist -> [3] Remove -> [1] admin@company.com -> Enter
#               -> [4] Add Custom Limit -> vip@company.com, 400, 800 -> Enter -> [0] Back
# [0] Exit
printf "2\n3\n\n0\n3\n4\n120\n240\n7\n150\n300\n8\n0\n5\n3\n1\n\n4\nvip@company.com\n400\n800\n\n0\n0\n" | \
ZSM_CONFIG_FILE="$FAKE_CFG" \
ZSM_ZMPROV_CMD="$MOCK_ZMPROV" \
ZSM_SENDMAIL_CMD="$MOCK_SENDMAIL" \
ZSM_CURL_CMD="$MOCK_CURL" \
ZSM_DIG_CMD="$MOCK_DIG" \
ZSM_HOST_CMD="/nonexistent/host" \
ZSM_NSLOOKUP_CMD="/nonexistent/nslookup" \
ZSM_HOSTNAME_CMD="$MOCK_HOSTNAME" \
ZSM_HOSTNAME="mail.company.com" \
ZSM_UI_MODE="text" \
bash "$MONITOR_BIN" --text-menu >/dev/null 2>&1

grep -q "^WARN_RECIPIENTS=120" "$FAKE_CFG"
grep -q "^CRIT_RECIPIENTS=240" "$FAKE_CFG"
grep -q "^WARN_MESSAGES_SENT=72" "$FAKE_CFG"
grep -q "^CRIT_MESSAGES_SENT=180" "$FAKE_CFG"
grep -q "^WARN_HOURLY_MESSAGES=150" "$FAKE_CFG"
grep -q "^CRIT_HOURLY_MESSAGES=300" "$FAKE_CFG"
grep -q '^RISK_SCORE_ENABLED="false"' "$FAKE_CFG"
if grep -qi "^admin@company.com$" "$FAKE_WL"; then
    echo " -> [FAIL] admin@company.com was not removed from whitelist!"
    exit 1
fi
grep -q "^sub-admin@company.com$" "$FAKE_WL"
grep -q "^vip@company.com 400 800$" "$FAKE_WL"

# Verify upsert_whitelist_entry deduplication
ZSM_CONFIG_FILE="$FAKE_CFG" bash "$MONITOR_BIN" --whitelist-add "vip@company.com 500 1000" >/dev/null
UP_CNT=$(grep -c -i "^vip@company.com" "$FAKE_WL" || true)
if [[ "$UP_CNT" -ne 1 ]]; then
    echo " -> [FAIL] upsert_whitelist_entry created duplicate entry for vip@company.com (count: $UP_CNT)!"
    exit 1
fi
grep -q "^vip@company.com 500 1000$" "$FAKE_WL"
echo " -> [PASS] Control Panel Menu, custom limit add & exact whitelist removal verified."

echo "=== [16/16] Verifying v1.3.2 Hardening: Inbound DoS, 1-Msg Deferred, Lock Cap, System Shield, NAT & Cron ==="
S16_T=$(( FIXED_EPOCH + 110000 ))
S16_STR=$(date -d "@$(( S16_T - 30 ))" '+%b %e %H:%M:%S')
S16_ISO=$(date -d "@$(( S16_T - 30 ))" '+%Y-%m-%d %H:%M:%S')
: > "$FAKE_MAIL_OUT"
: > "$FAKE_ZMPROV_OUT"

# 16a: Remote DoS attempt - 160 forged inbound spam emails from external Internet IP -> Amavis 10025 -> LMTP 7025
# MUST NOT be attributed to ceo_safe@company.com and MUST NOT lock!
for i in $(seq 1 160); do
    printf "%s mail postfix/smtpd[2001]: QDOSIN%03d: client=evil.bot[45.33.1.2]\n" "$S16_STR" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/qmgr[2002]: QDOSIN%03d: from=<ceo_safe@company.com>, size=1400, nrcpt=1 (queue active)\n" "$S16_STR" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/amavisd/smtpd[2003]: QDOSOUT%03d: client=localhost[127.0.0.1]\n" "$S16_STR" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/qmgr[2002]: QDOSOUT%03d: from=<ceo_safe@company.com>, size=2000, nrcpt=1 (queue active)\n" "$S16_STR" "$i" >> "$FAKE_LOG"
    printf "%s mail amavis[2004]: (2004-%03d) Passed SPAMMY {RelayedTaggedInbound}, [45.33.1.2]:12345 <ceo_safe@company.com> -> <staff@company.com>, Queue-ID: QDOSIN%03d, Hits: 9.2\n" "$S16_STR" "$i" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/smtp[2005]: QDOSIN%03d: to=<staff@company.com>, relay=127.0.0.1[127.0.0.1]:10024, delay=0.2, status=sent (250 2.0.0 from MTA(smtp:[127.0.0.1]:10025): 250 2.0.0 Ok: queued as QDOSOUT%03d)\n" "$S16_STR" "$i" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/lmtp[2006]: QDOSOUT%03d: to=<staff@company.com>, relay=mail.company.com[10.2.1.23]:7025, delay=0.1, status=sent (250 2.1.5 Delivery OK)\n" "$S16_STR" "$i" >> "$FAKE_LOG"
done

# 16b: Single legitimate BCC email (msgs=1) to 45 recipients with 30 deferred (66.7% fail) -> WARNING only, NOT locked!
printf "%s mail postfix/submission/smtpd[2001]: Q1DEF001: client=office[192.0.2.88], sasl_method=LOGIN, sasl_username=bcc_defer@company.com\n" "$S16_STR" >> "$FAKE_LOG"
printf "%s mail postfix/qmgr[2002]: Q1DEF001: from=<bcc_defer@company.com>, size=3000, nrcpt=45 (queue active)\n" "$S16_STR" >> "$FAKE_LOG"
for i in $(seq 1 45); do
    if (( i <= 30 )); then
        printf "%s mail postfix/smtp[2005]: Q1DEF001: to=<p%d@partner.org>, relay=mx.partner.org[1.2.3.4]:25, delay=0.5, status=deferred (421 temporary DNS/network hiccup)\n" "$S16_STR" "$i" >> "$FAKE_LOG"
    else
        printf "%s mail postfix/smtp[2005]: Q1DEF001: to=<p%d@partner.org>, relay=mx.partner.org[1.2.3.4]:25, delay=0.5, status=sent (250 OK)\n" "$S16_STR" "$i" >> "$FAKE_LOG"
    fi
done

# 16c: Protected Zimbra system account (spam.xyz999@company.com) sends 160 msgs -> alert only, NOT locked!
for i in $(seq 1 160); do
    printf "%s mail postfix/submission/smtpd[2001]: QSYS%03d: client=localhost[127.0.0.1], sasl_method=LOGIN, sasl_username=spam.xyz999@company.com\n" "$S16_STR" "$i" >> "$FAKE_LOG"
    printf "%s mail postfix/smtp[2005]: QSYS%03d: to=<ext%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=0.2, status=sent (250 OK)\n" "$S16_STR" "$i" "$i" >> "$FAKE_LOG"
done

# 16d: Circuit Breaker MAX_LOCKS_PER_CYCLE=2 with 4 CRITICAL spammers -> locks ONLY 2, caps remaining 2!
for u in 1 2 3 4; do
    for i in $(seq 1 160); do
        printf "%s mail postfix/submission/smtpd[2001]: QCAP%dX%03d: client=bot[203.0.113.%d], sasl_method=LOGIN, sasl_username=cap%d@company.com\n" "$S16_STR" "$u" "$i" "$u" "$u" >> "$FAKE_LOG"
        printf "%s mail postfix/smtp[2005]: QCAP%dX%03d: to=<t%d@gmail.com>, relay=mx.gmail.com[1.2.3.4]:25, delay=0.2, status=sent (250 OK)\n" "$S16_STR" "$u" "$i" "$i" >> "$FAKE_LOG"
    done
done

# 16e: Office NAT AUTH_AFTER_FAIL safeguard - colleague_a fails 6x on office IP, colleague_b succeeds -> NO alert for colleague_b!
for i in $(seq 1 6); do
    printf "%s,100 WARN  [qtp1-9] [name=colleague_a@company.com;ip=127.0.0.1;oip=198.51.100.77;] security - cmd=Auth; account=colleague_a@company.com; protocol=soap; error=authentication failed for [colleague_a@company.com], invalid password;\n" "$S16_ISO" >> "$FAKE_AUDIT_LOG"
done
printf "%s,500 INFO  [qtp1-9] [name=colleague_b@company.com;ip=127.0.0.1;oip=198.51.100.77;] security - cmd=Auth; account=colleague_b@company.com; protocol=soap;\n" "$S16_ISO" >> "$FAKE_AUDIT_LOG"

CAP_CFG="$TEST_TMP/cap.conf"
cp "$FAKE_CFG" "$CAP_CFG"
sed -i 's|^MAX_LOCKS_PER_CYCLE=.*|MAX_LOCKS_PER_CYCLE=2|' "$CAP_CFG"
sed -i 's|^CRIT_MESSAGES_SENT=.*|CRIT_MESSAGES_SENT=150|' "$CAP_CFG"
sed -i 's|^WARN_MESSAGES_SENT=.*|WARN_MESSAGES_SENT=60|' "$CAP_CFG"

run_scan "$S16_T" "$EMPTY_PQ" "$CAP_CFG"

# Verify 16a: ceo_safe completely immune to inbound spoofed spam
if grep -q "ceo_safe@company.com" "$FAKE_MAIL_OUT" || grep -q "ceo_safe@company.com" "$FAKE_ZMPROV_OUT"; then
    echo " -> [FAIL] Inbound spoofed spam via Amavis/LMTP falsely impacted ceo_safe@company.com!"
    exit 1
fi

# Verify 16b: single-message deferred BCC stays WARNING, never locked
grep -q "bcc_defer@company.com" "$FAKE_MAIL_OUT"
if grep -q "bcc_defer@company.com" "$FAKE_ZMPROV_OUT"; then
    echo " -> [FAIL] Single deferred BCC email falsely auto-locked bcc_defer@company.com!"
    exit 1
fi

# Verify 16c: protected Zimbra system account alerted but NOT locked
grep -q "spam.xyz999@company.com" "$FAKE_MAIL_OUT"
grep -q "Protected system account - alert only" "$FAKE_MAIL_OUT"
if grep -q "spam.xyz999@company.com" "$FAKE_ZMPROV_OUT"; then
    echo " -> [FAIL] Protected Zimbra system account spam.xyz999@company.com was falsely locked!"
    exit 1
fi

# Verify 16d: MAX_LOCKS_PER_CYCLE=2 capped locks at exactly 2 out of 4 CRITICAL accounts
CAP_LOCK_CNT=$(grep -c "ma cap[1-4]@company.com zimbraAccountStatus locked" "$FAKE_ZMPROV_OUT" || true)
if [[ "$CAP_LOCK_CNT" -ne 2 ]]; then
    echo " -> [FAIL] MAX_LOCKS_PER_CYCLE=2 locked ${CAP_LOCK_CNT} accounts instead of 2!"
    exit 1
fi
grep -q "Safety cap: MAX_LOCKS_PER_CYCLE=2 reached" "$FAKE_MAIL_OUT"

# Verify 16e: colleague_b on shared office NAT IP did NOT receive false AUTH_AFTER_FAIL alert
if grep -q "colleague_b@company.com" "$FAKE_MAIL_OUT"; then
    echo " -> [FAIL] Office NAT colleague_b@company.com triggered false AUTH_AFTER_FAIL alert!"
    exit 1
fi

# Verify 16f: Fresh default cron file reports "Every 5 mins", NOT "Paused"
CRON_MENU_OUT=$(printf "0\n" | ZSM_CONFIG_FILE="$FAKE_CFG" ZSM_CRON_FILE="$ROOT_DIR/packaging/cron.d/zimbra-spam-monitor" \
    ZSM_DIG_CMD="$MOCK_DIG" ZSM_HOSTNAME_CMD="$MOCK_HOSTNAME" ZSM_HOSTNAME="mail.company.com" \
    ZSM_UI_MODE="text" bash "$MONITOR_BIN" --text-menu 2>&1 || true)
echo "$CRON_MENU_OUT" | grep -q "Check: Every 5 mins"
if echo "$CRON_MENU_OUT" | grep -q "Check: Paused"; then
    echo " -> [FAIL] Default cron.d file falsely displayed 'Check: Paused'!"
    exit 1
fi
echo " -> [PASS] Inbound DoS immunity, 1-msg deferred guard, lock cap, system shield, NAT guard & cron status verified."

echo ""
echo "======================================================================"
echo " ALL AUTOMATED TESTS (16/16) PASSED 100%!"
echo "======================================================================"
