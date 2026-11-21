# Zimbra Outbound Spam Monitor (`zimbra-spam-monitor` v1.3.1)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/0xAndyNew/Monitor-Email-Spam-Zimbra?color=blue)](https://github.com/0xAndyNew/Monitor-Email-Spam-Zimbra/releases)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20ZCS%208%2C%209%2C%2010-orange.svg)](#)
[![Tests](https://img.shields.io/badge/tests-15%2F15%20passing-brightgreen.svg)](tests/run_test.sh)

Ultra-lightweight multi-signal & multi-window outbound email spam detection, alerting (**Telegram** + **Email** + **Webhook** + **JSONL**), and automatic single-account locking tool for **Zimbra Collaboration Suite (ZCS)** on Linux.

> **Vietnamese Guide:** [Doc Huong Dan Su Dung & Van Hanh Tieng Viet (HDSD.md)](HDSD.md)

Built specifically for production single-server and multi-domain Zimbra servers with **ultra-low CPU/RAM footprint** (early timestamp pruning, per-second `mktime()` cache, C-speed `grep` pre-filters, native `ldapsearch` domain cache, zero background daemons, zero periodic JVM calls, self `renice`/`ionice`) and a **100% ASCII-safe English Interactive Control Panel**.

---

## Safety Guarantee (Zero Mail Server / OS Mutation)

- **Strictly READ-ONLY against Mail Server & OS configuration**: never runs `postconf -e`, `zmlocalconfig -e`, `zmprov mcf/ms/mc/md`, `zmcontrol`, `postfix reload`, `apt`/`yum`/`dnf`, `iptables`/`firewalld`, `fail2ban-client`, `sysctl`, or `systemctl`.
- Only writes to its own files (`/etc/zimbra-spam-monitor/*`, `/etc/cron.d/zimbra-spam-monitor`, `/var/lib/zimbra-spam-monitor/*`, `/var/log/zimbra-spam-monitor*`).
- Remediation is strictly scoped to **a single confirmed CRITICAL compromised account** (`zmprov ma <account> zimbraAccountStatus locked`, per-account `zmprov fc account <account>` auth cache flush, and optional targeted `postsuper -h` disabled by default).
- Every release is checked by an automated static safety audit in `tests/run_test.sh`.

---

## 1. Quick Installation from GitHub Releases (`.rpm` & `.deb`)

Releases page: https://github.com/0xAndyNew/Monitor-Email-Spam-Zimbra/releases/tag/v1.3.1

### A. RHEL / CentOS / Rocky Linux / AlmaLinux (`.rpm`)
Run as `root` on your Zimbra server:
```bash
wget -O zimbra-spam-monitor-1.3.1-1.noarch.rpm https://github.com/0xAndyNew/Monitor-Email-Spam-Zimbra/releases/download/v1.3.1/zimbra-spam-monitor-1.3.1-1.noarch.rpm
rpm -Uvh zimbra-spam-monitor-1.3.1-1.noarch.rpm
```
*(Or: `yum localinstall -y zimbra-spam-monitor-1.3.1-1.noarch.rpm`)*

### B. Ubuntu / Debian (`.deb`)
Run as `root` on your Zimbra server:
```bash
wget -O zimbra-spam-monitor_1.3.1-1_all.deb https://github.com/0xAndyNew/Monitor-Email-Spam-Zimbra/releases/download/v1.3.1/zimbra-spam-monitor_1.3.1-1_all.deb
dpkg -i zimbra-spam-monitor_1.3.1-1_all.deb
```

---

## 2. Multi-Signal & Multi-Window Spam Detection Engine

`zimbra-spam-monitor` combines **short-window burst detection (5m)**, **idempotent rolling multi-window detection (1h / 24h)** for low-and-slow spammers, **single-server `mailbox.log` + `audit.log` correlation**, and a **Composite Risk Score (0-100)**:

| # | Metric / Signal | Window & Calculation | Default `WARNING` | Default `CRITICAL` |
| :-: | :--- | :--- | :--- | :--- |
| **1** | **Messages Sent** | 5m distinct root `Queue-ID` submitted | `>= 60` msgs | `>= 150` msgs |
| **2** | **Total Recipients** | 5m deduplicated `(Queue-ID, to=<...>)` deliveries | `>= 100` rcpts | `>= 200` rcpts *(with `Msgs >= 10`)* |
| **3** | **Unique Recipients** | 5m distinct recipients *(with `Ext Domains >= 5`)* | `>= 80` rcpts | `>= 160` rcpts *(with `Msgs >= 10`)* |
| **4** | **Failed Rate (%)** | `(Deferred + Bounced + Expired) / Recipients * 100%` | `>= 30%` *(min `20` rcpts)* | `>= 50%` *(min `40` rcpts)* |
| **5** | **Distinct Source /24s** | Distinct `/24` IPv4 (`/64` IPv6) nets *(incl. real Webmail `oip=` from `mailbox.log`)* | `>= 3` nets *(min `10` msgs)* | `>= 5` nets *(min `20` msgs)* |
| **6** | **Sender Spoofing** | Authenticated `sasl_username != external From` *(counted once per message)* | `>= 3` msgs | `>= 10` msgs |
| **7** | **Amavis SPAM / RBL** | Amavis `SPAM/SPAMMY/INFECTED/BANNED` (`Hits >= 6.0`) or MX `5.7.1/4.7.28`/RBL *(auto-forward safe)* | `>= 3` signals | `>= 10` signals *(SASL or w/ volume/spoof)* |
| **8** | **Account Live Queue** | Active + Deferred queue per sender *(Held `!` mail excluded)* | `>= 40` emails | `>= 100` emails |
| **9** | **Low-and-Slow (1h/24h)** | Idempotent 5m submission buckets merged via `max()` | `300/1h` or `1500/24h` | `600/1h` msgs *(24h is WARN-only)* |
| **10** | **Brute-Force / Auth** | `audit.log` + Postfix SASL failures (`>= 50`/IP summary; login after `>= 5` fails) | Consolidated / Account WARN | Never locks brute-force victims |
| **11** | **Composite Risk Score** | Weighted `0-100` score across simultaneous weak signals | `>= 60` *(>= 2 signals)* | `>= 85` *(>= 3 signals, >= 1 quality)* |

### Production Accuracy & Reliability Safeguards:
- **Zero False-Lock Protections**:
  - Single legitimate CC/BCC announcements (`Msgs < 10`) never trigger `CRITICAL` auto-lock; Spoof & Amavis counts are per unique message (`root_qid`), not multiplied by CC recipients.
  - Auto-forwarding users receiving spam that remote MX (e.g. Gmail) rejects with `5.7.1` from `webmail/local` origin stay `WARNING` only unless accompanied by SASL, spoofing, or volume signals.
  - Tracks Postfix SMTP (`postfix/smtp[`), delivery error (`postfix/error[`), and single-server internal mailbox delivery post-Amavis (`postfix/lmtp[` on port 7025) while strictly ignoring incoming external deliveries.
  - Mobile 4G/5G users rotating IPs inside the same carrier `/24` subnet count as 1 subnet.
  - Retried `deferred` deliveries for the same `(root_qid, rcpt)` are deduplicated to their final status.
  - Held (`!`) queue messages are excluded from Account Queue thresholds so locked accounts stop re-alerting once held.
  - Per-account Custom Limits in `whitelist.conf` (`marketing@company.com 500 1000`) allow higher volume while still catching spoofing or malware, with automatic duplicate removal (`upsert_whitelist_entry`).
- **Immediate & Resilient Containment**:
  - **Per-Account Cache Flush**: Immediately runs `zmprov fc account <user>` after locking to terminate active Webmail/SOAP/ActiveSync tokens without impacting other users.
  - **Decoupled Remediation**: Lock attempts run before alert cooldown -- if `zmprov` fails transiently, the next cycle retries immediately instead of waiting 30 minutes.
  - **Desync Self-Healing**: If an admin manually unlocks an account via Zimbra Web UI and normal traffic resumes, the stale lock record is cleared cleanly; if `CRITICAL` spam resumes, it automatically `RE-LOCK`s.
  - **Spoof-Aware Queue Hold**: When enabled, holds queued messages by both envelope sender and correlated SASL Queue-IDs.
- **Zero Lost Alerts**:
  - **Outbox Retry Queue** (`/var/lib/zimbra-spam-monitor/outbox/`): Automatically retries failed Telegram/Email/Webhook sends on subsequent cycles (up to 6 retries / 60m).
  - **Telegram Flood Protection**: Respects `429 retry_after`, enforces 4000-char cap, batches overflow beyond `MAX_ALERTS_PER_CYCLE=8` into 1 summary.
  - **Self-RBL Monitor (`--check-rbl`)**: Checks server IP against active DNSBLs (`zen.spamhaus.org`, `bl.spamcop.net`, `bl.mailspike.net`, `dnsbl-1.uceprotect.net`, `psbl.surriel.com`), treats Spamhaus `127.255.255.x` as query error (never false blacklist), alerts only on state transitions.
  - **Monitor Health Check**: Alerts if `/var/log/zimbra.log` is missing or stale (> 30m).
- **Security Hardening**:
  - Strict email validation + `stdin` `zmprov` invocation (eliminates shell/command injection).
  - Telegram Bot Token, Webhook URL, and SMTP credentials passed via `curl --config -` stdin (hidden from `ps aux`).
  - Safe `awk` config writer properly escaping `|`, `&`, `$`, `"`, `\`, `` ` ``.

---

## 3. Streamlined Interactive Control Panel

Run as `root`:
```bash
zimbra-spam-monitor
```
- Uses `whiptail` / `dialog` arrow-key TUI automatically when available.
- Use `zimbra-spam-monitor --text-menu` for plain numbered menu mode (`1..6`).

```text
==============================================================================
 ZIMBRA SPAM MONITOR v1.3.1
------------------------------------------------------------------------------
 Service: ON | Check: Every 5 mins | Auto-Lock: ON | TG: ON | Mail: ON
------------------------------------------------------------------------------
  [1 ] Live Status & Queue
  [2 ] Alerts & Test          (Telegram / Email / Webhook / Test)
  [3 ] Spam Limits & Schedule (Limit: 100/200 | 5m | 1h: 300/600)
  [4 ] Unlock & Auto-Lock     (Auto-Lock: ON | Queue Control)
  [5 ] Whitelist & Limits     (Trusted & Custom Per-User Limits)
  [6 ] Logs, RBL & Audit      (Service: ON | Read-Only Audit)
  [0 ] Exit
==============================================================================
```

### Key Menu Capabilities:
- **[1] Live Status & Queue**: Real-time table of recent outbound senders, Postfix queue breakdown, and active list of locked accounts (`Locked Accounts: <count> (<list>)`).
- **[2] Alerts & Test**: Manage Telegram Bot Token, Chat ID, Email alert settings, Webhook integration, and send test alerts.
- **[3] Spam Limits & Schedule**:
  - `[1..3]` Check interval, lookback window, and alert cooldown.
  - `[4]` 5-minute message and recipient thresholds.
  - `[5]` Failed delivery rate percentage.
  - `[6]` Postfix queue limit per user.
  - `[7]` Hourly Limit (1h Low-and-Slow message limits).
  - `[8]` Composite Risk Score Engine toggle (`ON`/`OFF`).
- **[4] Unlock & Auto-Lock**: Toggle auto-lock (`AUTO_LOCK_ON_CRITICAL`), manage auto-hold, and unlock accounts with automatic history clearance.
- **[5] Whitelist & Limits**: Add/remove full bypass (`marketing@domain.com` or `@domain.com`) or Per-Account Custom Limits (`marketing@domain.com 500 1000`) with automatic deduplication.
- **[6] Logs, RBL & Audit**: Toggle service status, view live logs, inspect events JSONL, run Self-RBL check, or launch the read-only Zimbra posture audit.

---

## 4. Direct CLI Commands

```bash
zimbra-spam-monitor                             # Open Interactive Control Panel
zimbra-spam-monitor --status                    # Live 5-min status table & Postfix queue
zimbra-spam-monitor --test                      # Send test notification (Telegram/Email/Webhook)
zimbra-spam-monitor --unlock user@dom.com       # Unlock account, clear cooldown & 1h/24h history
zimbra-spam-monitor --whitelist-add a@b.c       # Full bypass whitelist entry
zimbra-spam-monitor --whitelist-add a@b.c 500 1000  # Per-account custom WARN/CRIT limits
zimbra-spam-monitor --check-rbl                 # Read-only DNSBL blacklist check for server IP
zimbra-spam-monitor --audit                     # 100% read-only Zimbra anti-spam posture audit
```

### Sample Live Status Output (`--status`):
```text
==============================================================================
 ZIMBRA SPAM MONITOR v1.3.1 - LIVE SYSTEM STATUS (LAST 5 MINS)
==============================================================================
 Zimbra Server   : mail.company.com (103.56.158.99)
 Monitor Status  : ON | Range: 5m | Cooldown: 30m | Auto-Lock: true
 Alert Channels  : TG=true | Mail=true (admin@company.com) | Webhook=false | Outbox=0
 Locked Accounts : 0 (None)
 System Outbound : 12 emails (Sent: 12 | Deferred: 0 | Bounced: 0)
 Postfix Queue   : 0 emails (Active: 0 | Deferred: 0 | Hold: 0)
------------------------------------------------------------------------------
 Sender Account             | Sent  | Rcpts (Deliv) | Fail (%) | Queue | Risk
------------------------------------------------------------------------------
 user1@company.com          | 5     | 5 (5)         | 0%       | 0     | 0
 user2@company.com          | 7     | 7 (7)         | 0%       | 0     | 0
==============================================================================
```

---

## 5. Uninstall

- **RHEL / CentOS / Rocky / AlmaLinux:**
  ```bash
  rpm -e zimbra-spam-monitor
  ```
- **Ubuntu / Debian:**
  ```bash
  apt purge -y zimbra-spam-monitor
  ```

---

## 6. Building Packages & Running Tests from Source
```bash
python3 packaging/build_rpm_deb.py
bash tests/run_test.sh
```

---

## 7. License & Author

- Licensed under the [MIT License](LICENSE).
- Author: **0xAndyNew** -- [0xAndyNew/Monitor-Email-Spam-Zimbra](https://github.com/0xAndyNew/Monitor-Email-Spam-Zimbra)
