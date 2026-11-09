# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`zimbra-spam-monitor` is a multi-signal outbound email spam detection, alerting (Telegram + Email), and automatic account locking tool for Zimbra Collaboration Suite (ZCS) on Linux. It operates without persistent background daemons, executing via 5-minute cron checks with near-zero CPU/RAM overhead and avoiding unnecessary Zimbra JVM (`zmprov`) invocations.

## Common Development Commands

### Running Tests

```bash
# Run the full automated test suite (8 test stages)
bash tests/run_test.sh
```

The test suite exercises:
1. Bash syntax validation (`bash -n`)
2. 100% ASCII-safe character validation and `.deb`/`.rpm` binary structure inspection
3. Simulated Zimbra + Postfix + Amavis log environment setup
4. Multi-signal log scan cycle (`--run`)
5. Alert cooldown & duplicate `zmprov` lock prevention
6. Admin `--unlock` cutoff timestamp recovery
7. `--status` live 5-minute dashboard output
8. Interactive Control Panel text menu navigation (`--text-menu`)

### Syntax & Linting

```bash
# Validate Bash scripts syntax
bash -n src/zimbra-spam-monitor
bash -n packaging/build-packages.sh
```

### Building Packages

```bash
# Build both .deb and .rpm packages using the standalone Python builder
python3 packaging/build_rpm_deb.py

# Alternatively, via shell wrapper
bash packaging/build-packages.sh
```

Generated packages are placed in the repository root:
- `zimbra-spam-monitor_<version>-<release>_all.deb`
- `zimbra-spam-monitor-<version>-<release>.noarch.rpm`

### Running the CLI Locally / Testing Mocks

The script supports environment variable overrides to test without a live Zimbra installation:

```bash
# Test status output with mock inputs
ZSM_CONFIG_FILE="config/config.conf" \
ZSM_UI_MODE="text" \
bash src/zimbra-spam-monitor --status

# Test the text-based interactive menu
ZSM_CONFIG_FILE="config/config.conf" \
ZSM_UI_MODE="text" \
bash src/zimbra-spam-monitor --text-menu

# Test background scan with mock utilities
ZSM_CONFIG_FILE="/path/to/custom.conf" \
ZSM_NOW_EPOCH=$(date +%s) \
ZSM_POSTQUEUE_CMD="/path/to/mock_postqueue.sh" \
ZSM_ZMPROV_CMD="/path/to/mock_zmprov.sh" \
ZSM_SENDMAIL_CMD="/path/to/mock_sendmail.sh" \
ZSM_CURL_CMD="curl" \
bash src/zimbra-spam-monitor --run
```

Available mock/override environment variables:
- `ZSM_CONFIG_FILE`: Override path to `config.conf` (default: `/etc/zimbra-spam-monitor/config.conf`)
- `ZSM_CRON_FILE`: Override path to cron file (default: `/etc/cron.d/zimbra-spam-monitor`)
- `ZSM_NOW_EPOCH`: Override current system epoch timestamp for deterministic log window testing
- `ZSM_POSTQUEUE_CMD`: Override `postqueue` executable path
- `ZSM_ZMPROV_CMD`: Override `zmprov` executable path
- `ZSM_SENDMAIL_CMD`: Override `sendmail` executable path
- `ZSM_CURL_CMD`: Override `curl` executable path
- `ZSM_HOSTNAME`: Override detected hostname
- `ZSM_UI_MODE`: Force UI mode (`auto`, `tui` for whiptail/dialog, `text` for plain numbers)

## Architecture and Structure

### File Organization

- `src/zimbra-spam-monitor`: Main executable script (monolithic Bash script containing CLI, TUI, log analysis, remediation, and alerting logic).
- `config/config.conf`: Default configuration template with all detection thresholds, delivery settings, and file paths.
- `config/whitelist.conf`: Whitelist file containing trusted email addresses and `@domain.com` patterns.
- `packaging/build_rpm_deb.py`: Pure-Python cross-platform package builder that constructs `.deb` (ar + tar.gz) and `.rpm` (RPM v4 binary format with CPIO payload) without external distro packaging tools.
- `packaging/zimbra-spam-monitor.spec`: RPM spec file definition for standard rpmbuild environments.
- `packaging/cron.d/zimbra-spam-monitor`: Cron schedule running `--run` every 5 minutes by default.
- `packaging/logrotate.d/zimbra-spam-monitor`: Log rotation configuration for `/var/log/zimbra-spam-monitor.log`.
- `tests/run_test.sh`: Self-contained integration test suite with synthetic log generators and mock Zimbra binaries.

### Multi-Signal Outbound Spam Detection Engine

Detection evaluates an independent lookback window (default `LOOKBACK_MINUTES=5`) over `/var/log/zimbra.log` (`analyze_zimbra_log`) across 8 indicators:
1. **Messages Sent**: Distinct root queue IDs submitted (`WARN_MESSAGES_SENT=60`, `CRIT_MESSAGES_SENT=150`).
2. **Total Recipients**: Outbound `to=<...>` deliveries (`WARN_RECIPIENTS=100`, `CRIT_RECIPIENTS=200`, requires `CRIT_MIN_MESSAGES_FOR_BULK=10` to avoid locking single CC/BCC announcements).
3. **Unique Recipients**: Distinct recipients across external domains (`WARN_UNIQUE_RECIPIENTS=80`, `CRIT_UNIQUE_RECIPIENTS=160`, min 5 external domains).
4. **Failed Rate (%)**: `(Deferred + Bounced) / Recipients * 100%` (`WARN_FAILED_RATE_PCT=30%` at >= 20 rcpts, `CRIT_FAILED_RATE_PCT=50%` at >= 40 rcpts).
5. **Distinct Source IPs**: Authenticated client IPs per account (`WARN_SOURCE_IPS=3` at >= 10 msgs, `CRIT_SOURCE_IPS=5` at >= 20 msgs).
6. **Sender Spoofing**: Mismatch between `sasl_username` and external `From:` address (`WARN_SPOOF_COUNT=3`, `CRIT_SPOOF_COUNT=10`). Legitimate same-domain Zimbra personas/aliases are ignored.
7. **Amavis SPAM / RBL Rejections**: Amavis spam score >= `AMAVIS_SPAM_SCORE_THRESHOLD` (default 6.0), `INFECTED`, or remote MX `5.7.1`/`4.7.28`/RBL rejections (`WARN_SPAM_SIGNALS=3`, `CRIT_SPAM_SIGNALS=10`).
8. **Postfix Queue Inspection**: Current queued messages per sender via `postqueue -p` (`WARN_QUEUE_PER_USER=40`, `CRIT_QUEUE_PER_USER=100`, `WARN_TOTAL_QUEUE=300`).

### Critical Production Invariants

- **Amavis Double Queue-ID Correlation**: Correlates pre-filter queue ID (`127.0.0.1:10024/10026/10032`) with post-filter queue ID (`queued as <qid2>`) so outbound messages are never double-counted while retaining the originating source IP and `sasl_username`.
- **Postfix Retry Timestamp Calculation**: Calculates `log_timestamp - delay` to identify true submission time, preventing old deferred mail retries (e.g. `delay=1800`) from being counted as fresh 5-minute outbound spam.
- **State Management & Cooldown** (`/var/lib/zimbra-spam-monitor`):
  - `cooldown.db`: Suppresses duplicate alerts for the same account within `ALERT_COOLDOWN_MINUTES=30`. Escalation from `WARNING` to `CRITICAL` bypasses cooldown.
  - `locked_accounts.db`: Records locked accounts to prevent duplicate `zmprov` JVM executions on subsequent cycles.
  - `unlock_cutoff.db`: Records unlock cutoff timestamp when an account is unlocked (`--unlock`); log lines prior to this timestamp are excluded.
- **100% ASCII Encoding Rule**: All code, configuration, documentation, and packaging files in this repository must contain strictly 7-bit ASCII characters (byte values 0-127). Non-ASCII characters will break the automated test suite.
