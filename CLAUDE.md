# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`zimbra-spam-monitor` (v1.3.0) is an ultra-lightweight, multi-signal & multi-window outbound email spam detection, alerting (Telegram + Email + Webhook + JSONL), and single-account auto-locking tool for Zimbra Collaboration Suite (ZCS) on Linux. It operates without persistent background daemons via cron checks, minimizes CPU/RAM with early timestamp pruning and per-second `mktime()` caching, and avoids periodic Zimbra JVM (`zmprov`) calls.

## Strict Safety Invariant (Zero Mail Server / OS Mutation)

- NEVER add any command that mutates Mail Server or OS configuration (`postconf -e`, `zmlocalconfig -e`, `zmprov mcf/ms/mc/md/cd/dd`, `zmcontrol`, `postfix reload/restart`, `apt/yum/dnf`, `iptables/nft/firewall-cmd`, `fail2ban-client`, `sysctl -w`, `systemctl`).
- The automated test suite (`tests/run_test.sh` stage 1) statically scans `src/zimbra-spam-monitor` and fails if any forbidden mutation pattern appears.
- Only read-only queries (`ldapsearch`, `postqueue -p`, `postconf -h`, DNS lookups, log reads) and targeted single-account remediation (`zmprov ma <validated_email> zimbraAccountStatus locked/active`, `zmprov fc account <validated_email>`, optional `postsuper -h/-H`) are permitted.

## Common Development Commands

### Running Tests

```bash
# Run the full 15-stage automated test suite
bash tests/run_test.sh
```

The 15 stages cover:
1. Bash syntax (`bash -n`) & static Zero-Server/OS-Mutation safety audit
2. 100% 7-bit ASCII encoding & `.deb`/`.rpm` `v1.3.0-1` binary structure inspection
3. Simulated single-server Zimbra environment (`zimbra.log`, `mailbox.log`, `audit.log` + mocks)
4. Multi-signal scan (`--run`), Amavis 2-hop correlation, `zmprov fc account`, exact 5m `sys_tot`
5. Cooldown, Long Queue IDs, decoupled lock retry on `zmprov` failure, Held (`!`) queue exclusion
6. Locked-account desync recovery (benign external unlock cleanup vs `RE-LOCKED` on active spam)
7. Security regressions (Command Injection block, `curl` stdin secret hiding, safe `update_cfg_var`)
8. Counting accuracy (per-message Spoof/Amavis, deduped deferred retries, `status=expired`)
9. Multi-window Low-and-Slow (`1h` rolling buckets + idempotency across repeated runs)
10. Single-server `mailbox.log` real Webmail `/24` IPs, mobile 4G `/24` safety, `audit.log` brute-force & auth-after-fail
11. Auto-forward safeguard, spoofed QID queue hold, internal Amavis malware, local `postfix/pickup` webshell
12. Per-account Custom Limits, Composite Risk Score, `ldapsearch` multi-domain cache, logrotate `.1`
13. Self-RBL (`127.255.255.x` query-error guard & state-change alerting), read-only `--audit`, Webhook, JSONL, Outbox retry
14. Admin `--unlock` (clears rolling history), `--status` dashboard & 24h `server_ip.cache`
15. Interactive Control Panel (`--text-menu`) & exact whitelist removal

### Syntax & Packaging

```bash
bash -n src/zimbra-spam-monitor
bash -n packaging/build-packages.sh
python3 packaging/build_rpm_deb.py
```

Generated packages in repository root:
- `zimbra-spam-monitor_1.3.0-1_all.deb`
- `zimbra-spam-monitor-1.3.0-1.noarch.rpm`

### Local CLI & Mock Environment Variables

Available mock/override environment variables:
- `ZSM_CONFIG_FILE`: Override path to `config.conf`
- `ZSM_CRON_FILE`: Override path to cron file
- `ZSM_NOW_EPOCH`: Override epoch timestamp for deterministic window testing
- `ZSM_POSTQUEUE_CMD`, `ZSM_POSTSUPER_CMD`, `ZSM_POSTCONF_CMD`: Override Postfix binaries
- `ZSM_ZMPROV_CMD`, `ZSM_LDAPSEARCH_CMD`: Override Zimbra/LDAP binaries
- `ZSM_SENDMAIL_CMD`, `ZSM_CURL_CMD`: Override mail/HTTP binaries
- `ZSM_DIG_CMD`, `ZSM_HOST_CMD`, `ZSM_NSLOOKUP_CMD`, `ZSM_HOSTNAME_CMD`: Override DNS/host tools
- `ZSM_HOSTNAME`, `ZSM_SERVER_IP`: Override hostname / server IP
- `ZSM_MAILBOX_LOG_FILE`, `ZSM_AUDIT_LOG_FILE`, `ZSM_LOCALCONFIG_FILE`: Override Zimbra file paths
- `ZSM_TG_RATE_SLEEP`: Override inter-message Telegram sleep seconds (default `1`, `0` in tests)
- `ZSM_UI_MODE`: Force UI mode (`auto`, `tui`, `text`)

## Architecture and Structure

### File Organization

- `src/zimbra-spam-monitor`: Monolithic Bash executable containing CLI, TUI, ultra-low-RAM log analysis engine, remediation, outbox/alerting, Self-RBL, and read-only `--audit`.
- `config/config.conf`: Default configuration template (all v1.3.0 knobs have safe defaults in script for seamless v1.2.x upgrades).
- `config/whitelist.conf`: Supports both full bypass (`email` / `@domain`) and Per-Account Custom Limits (`email WARN CRIT`).
- `packaging/build_rpm_deb.py`: Pure-Python builder creating `.deb` (ar + tar.gz) and `.rpm` (RPM v4 + CPIO).
- `packaging/zimbra-spam-monitor.spec`: RPM spec file for `rpmbuild`.
- `packaging/cron.d/zimbra-spam-monitor`: Default 5-minute cron schedule.
- `packaging/logrotate.d/zimbra-spam-monitor`: Rotates both `/var/log/zimbra-spam-monitor.log` and `/var/log/zimbra-spam-monitor-events.jsonl`.
- `tests/run_test.sh`: 15-stage self-contained integration & security test suite.

### Critical Production Invariants

- **Early Timestamp Pruning & `mktime()` Cache**: Lines older than `prune_cutoff = scan_cutoff - 120` are skipped immediately before field splitting, regex, or hash allocation; per-second timestamp keys (`prev_ts_key`) avoid 99.5% of `mktime()` calls.
- **Amavis Double Queue-ID Correlation & Retry Deduplication**: Links pre-filter (`127.0.0.1`/`localhost`/`[::1]:100xx`) to post-filter `queued as <qid2>`, deduplicates `(acct, root_qid, rcpt)` status transitions in O(1), counts Spoof/Amavis once per unique `root_qid`, and uses `log_time - delay` to ignore old queue retries.
- **Single-Server Auxiliary Log Correlation**: Pre-filters `mailbox.log` (`smtp - Sending message`) and `audit.log` (`cmd=Auth|authentication failed`) with C-speed `grep` to extract real Webmail `oip=` IPs (counted by `/24` subnet) and detect brute-force / auth-after-fail.
- **State Directory** (`/var/lib/zimbra-spam-monitor`):
  - `cooldown.db`: Alert cooldown state (bypassed on WARN->CRITICAL escalation or RE-LOCK).
  - `locked_accounts.db`: `account|timestamp|lock_epoch` (backward-compatible with 2-field v1.2.x files) with desync self-healing.
  - `unlock_cutoff.db`: Per-account unlock cutoff epoch.
  - `rolling_history.db`: Idempotent 5-minute submission buckets (`max`-merged, 24h TTL) for 1h/24h low-and-slow detection.
  - `server_ip.cache` & `domains.cache`: 24h caches for DNS Server IP and `ldapsearch` hosted domains (zero periodic JVM).
  - `outbox/`: Retry queue (up to 6 retries / 60m) for failed Telegram/Email/Webhook alerts.
  - `rbl_state.db` & `rbl_last_check.ts`: Self-RBL state-change tracker.
  - `attacker_ips.log`: Passive attacker IP log for external SIEM/firewall consumption.
- **100% 7-Bit ASCII Encoding Rule**: All repository files must strictly contain 7-bit ASCII bytes (0-127).
