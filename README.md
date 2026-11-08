# Zimbra Outbound Spam Monitor (`zimbra-spam-monitor` v1.2.0)

Multi-signal outbound email spam detection, alerting (**Telegram** + **Email**), and automatic compromised account locking tool for **Zimbra Collaboration Suite (ZCS)**.

Designed specifically for production Zimbra servers with **near-zero CPU/RAM overhead** (~0.1-0.3s per 5-minute scan, zero background daemons, zero periodic JVM calls) and a **100% ASCII-safe English Interactive Control Panel** (`whiptail`/`dialog` arrow-key TUI & numbered text fallback).

---

## 1. Quick Installation from GitHub Releases (`.rpm` & `.deb`)

Releases page: https://github.com/0xAndyNew/Monitor-Email-Spam-Zimbra/releases/tag/v1.2.0

### A. RHEL / CentOS / Rocky Linux / AlmaLinux (`.rpm`)
Run as `root` on your Zimbra server:
```bash
wget -O zimbra-spam-monitor-1.2.0-1.noarch.rpm https://github.com/0xAndyNew/Monitor-Email-Spam-Zimbra/releases/download/v1.2.0/zimbra-spam-monitor-1.2.0-1.noarch.rpm
rpm -Uvh zimbra-spam-monitor-1.2.0-1.noarch.rpm
```
*(Or: `yum localinstall -y zimbra-spam-monitor-1.2.0-1.noarch.rpm`)*

### B. Ubuntu / Debian (`.deb`)
Run as `root` on your Zimbra server:
```bash
wget -O zimbra-spam-monitor_1.2.0-1_all.deb https://github.com/0xAndyNew/Monitor-Email-Spam-Zimbra/releases/download/v1.2.0/zimbra-spam-monitor_1.2.0-1_all.deb
dpkg -i zimbra-spam-monitor_1.2.0-1_all.deb
```

---

## 2. Multi-Signal Outbound Spam Detection Engine (Per 5-Minute Window)

Instead of accumulating whole-day or 60-minute totals that cause false alerts after remediation, `zimbra-spam-monitor` evaluates each **independent 5-minute sliding window** (`LOOKBACK_MINUTES=5`) across **8 anti-spam indicators**:

| # | Metric (Last 5 Mins) | Calculation | Default `WARNING` | Default `CRITICAL` |
| :-: | :--- | :--- | :--- | :--- |
| **1** | **Messages Sent** | Distinct root `Queue-ID` messages submitted | `>= 60` msgs | `>= 150` msgs |
| **2** | **Total Recipients** | Total outbound `to=<...>` recipient deliveries | `>= 100` rcpts | `>= 200` rcpts *(with `Msgs >= 10`)* |
| **3** | **Unique Recipients** | Distinct recipient addresses *(with `Ext Domains >= 5`)* | `>= 80` rcpts | `>= 160` rcpts *(with `Msgs >= 10`)* |
| **4** | **Failed Rate (%)** | `(Deferred + Bounced) / Recipients * 100%` | `>= 30%` *(min `20` rcpts)* | `>= 50%` *(min `40` rcpts)* |
| **5** | **Distinct Source IPs** | Distinct client IPs authenticating on 1 user | `>= 3` IPs *(min `10` msgs)* | `>= 5` IPs *(min `20` msgs)* |
| **6** | **Sender Spoofing** | Authenticated `sasl_username != external From` | `>= 3` msgs | `>= 10` msgs |
| **7** | **Amavis SPAM / RBL** | Zimbra Amavis `SPAM/SPAMMY/INFECTED` (`Hits >= 6.0`) or remote MX `5.7.1/4.7.28/RBL` rejects | `>= 3` msgs | `>= 10` msgs |
| **8** | **Account Mail Queue** | Current messages queued in Postfix for 1 sender | `>= 40` emails | `>= 100` emails |

### Built-in Zimbra Production Safeguards:
- **Amavis Double-Queue-ID Correlation**: Links pre-filter `Queue-ID 1` (`127.0.0.1:10024/10026/10032`) to post-filter `Queue-ID 2` so outbound emails are **never double-counted (2x)** and retain the attacker's real **Source IP** and `sasl_username`.
- **Postfix Queue Retry Protection**: Calculates true submission time (`log_time - delay`) so old `deferred` messages retried by Postfix 20-30 minutes later are **never mistaken for newly sent spam**.
- **False-Positive Protection**:
  - Single legitimate CC/BCC company announcements (`Messages Sent < 10`) will never trigger `CRITICAL` auto-lock on recipient count alone.
  - Legitimate same-domain Zimbra personas/aliases (`sale01@company.com` sending as `sales@company.com`) are not flagged as external spoofing.
- **Clean Post-Unlock Recovery**: Unlocking an account (`zimbra-spam-monitor --unlock` or Menu `[4]`) records an unlock cutoff timestamp so all prior spam logs are ignored; once outbound traffic stays below threshold in the next 5-minute window, the account is treated as `NORMAL`.

---

## 3. Interactive Control Panel Usage

Run as `root`:
```bash
zimbra-spam-monitor
```
- Uses `whiptail` / `dialog` arrow-key TUI boxes (`UP`/`DOWN` + `ENTER`) automatically when available.
- Use `zimbra-spam-monitor --text-menu` if you prefer a numbered text menu (`1..8`).

### Main Control Panel:
```text
==============================================================================
 ZIMBRA SPAM MONITOR CONTROL PANEL v1.2.0
------------------------------------------------------------------------------
 Status: [ENABLED] | Cron: [Every 5 mins] | Auto-Lock: [ON]
------------------------------------------------------------------------------
  [1 ] View System Status & Top Senders (Live 5m Metrics & Queue)
  [2 ] Configure Alerts & Test (TG:ON | Mail:admin@company.com)
  [3 ] Edit Spam Rules & Thresholds (Window: 5m | Cooldown: 30m)
  [4 ] Auto-Lock Settings & Unlock Accounts (Auto-Lock: ON)
  [5 ] Manage Sender Whitelist (View / Add / Remove)
  [6 ] Change Cron Check Schedule (Every 5 mins)
  [7 ] Enable / Disable Monitoring Service (Current: ENABLED)
  [8 ] View Recent Monitor Logs (/var/log/zimbra-spam-monitor.log)
  [0 ] Exit
==============================================================================
```

### Grouped Threshold Configuration (`Menu [3]`):
```text
==============================================================================
 EDIT SPAM DETECTION RULES & THRESHOLDS
------------------------------------------------------------------------------
 Window: [5 mins] | Cooldown: [30 mins] | Scope: [External & SASL]
------------------------------------------------------------------------------
  [1 ] Scan Window & Cooldown     (Window: 5m | Repeat Cooldown: 30m)
  [2 ] Volume Thresholds          (Msgs: 60/150 | Rcpts: 100/200 | Uniq: 80/160)
  [3 ] Failed Rate Thresholds     (Min Rcpts: 20 | Warn: 30% | Crit: 50%)
  [4 ] Botnet & Spoofing Rules    (Source IPs: 3/5 | Spoof From: 3/10)
  [5 ] Content & Queue Rules      (Amavis/RBL: 3/10 | Queue: 40/100 | SysQ: 300)
  [6 ] Traffic Counting Scope     (External & SASL - Toggle)
  [0 ] Back to Main Menu
==============================================================================
```

---

## 4. Sample Notification & Alert Frequency / Duration

### Sample Notification Format (Telegram & Email):
```text
============================================================
         ZIMBRA SPAM ALERT - CRITICAL
============================================================
Server        : mail.company.com (203.0.113.10)
Alert Time    : 2026-11-08 21:40:05
Spam Time     : 2026-11-08 (21:35:12 -> 21:40:04)
Spam Account  : ketoan@company.com
Source IPs    : 113.161.72.45, 45.122.200.19, 185.220.101.8 (3 IPs)
Reason        : Msgs (185>=150), Unique Rcpts (210>=160), Failed Rate (54.9%>=50%)

------------------------------------------------------------
[1] ACCOUNT SPAM METRICS (LAST 5 MINS)
------------------------------------------------------------
Messages Sent : 185 msgs
Recipients    : 215 total (Unique: 210 | Domains: 38)
Failed Rate   : 54.9% (118/215 failed)
                Sent: 97 | Deferred: 86 | Bounced: 32
Spam Signals  : Amavis SPAM: 14 | Spoof From: 0 | RBL: 9

------------------------------------------------------------
[2] REMAINING MAIL QUEUE
------------------------------------------------------------
Account Queue : 86 emails
System Queue  : 104 emails
                Active: 10 | Deferred: 94 | Hold: 0

------------------------------------------------------------
[3] SYSTEM TOTAL TRAFFIC
------------------------------------------------------------
Total Traffic : 1420 emails
                Sent: 1285 | Deferred: 98 | Bounced: 37
============================================================
```

### Alert Frequency, Cooldown & Duration:
1. **Background Scan Frequency (Default: Every `5` minutes)**: Cron runs `zimbra-spam-monitor --run` every `5` minutes (changeable in Menu `[6]`).
2. **Immediate Initial Alert**: Sent immediately on the first 5-minute scan where an account violates a `WARNING` or `CRITICAL` rule.
3. **Repeat Cooldown (Default: `30` minutes)**: Controlled by `ALERT_COOLDOWN_MINUTES=30`. Duplicate alerts at the same severity are suppressed for 30 minutes. Escalation from `WARNING` to `CRITICAL` bypasses cooldown and alerts immediately.
4. **Automatic Stop**: Once the 5-minute metrics and Postfix queue drop below `WARNING` thresholds (or after the admin resets the password and runs `Unlock`), alerts stop immediately.

---

## 5. Direct CLI Commands

```bash
zimbra-spam-monitor                        # Open Interactive Control Panel
zimbra-spam-monitor --status               # Print live 5-min status table & queue
zimbra-spam-monitor --test                 # Send test alert to Telegram & Email
zimbra-spam-monitor --unlock user@dom.com  # Unlock Zimbra account & clear history
zimbra-spam-monitor --whitelist-add a@b.c  # Add sender/domain to whitelist
```

---

## 6. Uninstall

- **RHEL / CentOS / Rocky / AlmaLinux:**
  ```bash
  rpm -e zimbra-spam-monitor
  ```
- **Ubuntu / Debian:**
  ```bash
  apt purge -y zimbra-spam-monitor
  ```

---

## 7. Building Packages from Source
```bash
python3 packaging/build_rpm_deb.py
bash tests/run_test.sh
```
