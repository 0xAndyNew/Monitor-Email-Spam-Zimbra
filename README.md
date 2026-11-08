# Zimbra Outbound Spam Monitor (`zimbra-spam-monitor` v1.1.1)

Automated outbound email spam detection, alerting (**Telegram** + **Email**), and account auto-locking tool for **Zimbra Collaboration Suite (ZCS)**.

Includes a **100% ASCII-safe English Interactive Control Panel** (supports `whiptail`/`dialog` arrow-key TUI boxes as well as numbered text menus) to prevent any font or locale encoding issues across SSH terminals.

---

## 1. Quick Installation from GitHub Releases (`.rpm` & `.deb`)

Releases page: https://github.com/0xAndyNew/Monitor-Email-Spam-Zimbra/releases/tag/v1.1.1

### A. RHEL / CentOS / Rocky Linux / AlmaLinux (`.rpm`)
Run as `root` on your Zimbra server:
```bash
wget -O zimbra-spam-monitor-1.1.1-1.noarch.rpm https://github.com/0xAndyNew/Monitor-Email-Spam-Zimbra/releases/download/v1.1.1/zimbra-spam-monitor-1.1.1-1.noarch.rpm
rpm -Uvh zimbra-spam-monitor-1.1.1-1.noarch.rpm
```
*(Or: `yum localinstall -y zimbra-spam-monitor-1.1.1-1.noarch.rpm`)*

### B. Ubuntu / Debian (`.deb`)
Run as `root` on your Zimbra server:
```bash
wget -O zimbra-spam-monitor_1.1.1-1_all.deb https://github.com/0xAndyNew/Monitor-Email-Spam-Zimbra/releases/download/v1.1.1/zimbra-spam-monitor_1.1.1-1_all.deb
dpkg -i zimbra-spam-monitor_1.1.1-1_all.deb
```

---

## 2. Interactive Control Panel Usage

After installing the package, run:
```bash
zimbra-spam-monitor
```
- Uses `whiptail` / `dialog` arrow-key menus (`UP`/`DOWN` + `ENTER`) automatically when available.
- Use `zimbra-spam-monitor --text-menu` if you prefer a numbered text menu (`1..8`).

### Main Control Panel Layout:
```text
==============================================================================
 ZIMBRA SPAM MONITOR CONTROL PANEL v1.1.0
------------------------------------------------------------------------------
 Status: [ENABLED] | Cron: [Every 5 mins] | Auto-Lock: [ON]
------------------------------------------------------------------------------
  [1 ] View System Status & Top Senders
  [2 ] Configure Alerts & Test (TG:ON | Mail:admin@domain.com)
  [3 ] Edit Spam Thresholds (10m: 80/200 | 60m: 300/600)
  [4 ] Auto-Lock Settings & Unlock Accounts (Auto-Lock: ON)
  [5 ] Manage Sender Whitelist (View / Add / Remove)
  [6 ] Change Cron Check Schedule (Every 5 mins)
  [7 ] Enable / Disable Monitoring Service (Current: ENABLED)
  [8 ] View Recent Monitor Logs (/var/log/zimbra-spam-monitor.log)
  [0 ] Exit
==============================================================================
```

### Key Menu Features:
1. **`[1]` View System Status & Top Senders**: Displays current Postfix queue counts (`Active`, `Deferred`, `Hold`) and top outbound senders over the short window and last 60 minutes.
2. **`[2]` Configure Alerts & Test (Combined Menu)**:
   - **`[1]` Configure Telegram Alerts**: Toggle On/Off, set `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`.
   - **`[2]` Configure Email & SMTP Alerts**: Toggle On/Off, select delivery mode (`auto` / `local` / `smtp`), auto-detect Zimbra Admin email (`auto`) or set custom recipients, and configure optional fallback external SMTP.
   - **`[3]` Send Test Alert Now**: Immediately sends a test alert to both Telegram and Email.
3. **`[3]` Edit Spam Thresholds**: Select individual thresholds to edit:
   - Short Scan Window (`LOOKBACK_MINUTES`, default `10` mins): Warning `80` / Critical `200`.
   - Hourly Check (`60` mins): Warning `300` / Critical `600`.
   - Postfix Queue per User: Warning `40` / Critical `100`.
   - Total Server Queue Warning: `300`.
   - Alert Cooldown Interval: `30` mins.
4. **`[4]` Auto-Lock Settings & Unlock Accounts**:
   - Toggle automatic account locking (`zmprov ma <user> zimbraAccountStatus locked`) when reaching `CRITICAL`.
   - Toggle automatic Postfix queue hold (`postsuper -h`) on `CRITICAL`.
   - Select & unlock recently auto-locked accounts directly from a list.
5. **`[5]` Manage Sender Whitelist**: View, add, or select & remove whitelisted emails (`marketing@domain.com`) or domains (`@domain.com`).
6. **`[6]` Change Cron Check Schedule**: One-select cron interval (`Every 1, 2, 5, 10, 15, 30 minutes`, or `Pause`).

---

## 3. Direct CLI Commands

```bash
zimbra-spam-monitor                        # Open Interactive Control Panel
zimbra-spam-monitor --status               # Print status table & top senders
zimbra-spam-monitor --test                 # Send test alert to Telegram & Email
zimbra-spam-monitor --unlock user@dom.com  # Unlock a Zimbra account & clear cooldown
zimbra-spam-monitor --whitelist-add a@b.c  # Add sender/domain to whitelist
```

---

## 4. Uninstall

- **RHEL / CentOS / Rocky / AlmaLinux:**
  ```bash
  rpm -e zimbra-spam-monitor
  ```
- **Ubuntu / Debian:**
  ```bash
  apt purge -y zimbra-spam-monitor
  ```

---

## 5. Building Packages from Source
```bash
python3 packaging/build_rpm_deb.py
bash tests/run_test.sh
```
