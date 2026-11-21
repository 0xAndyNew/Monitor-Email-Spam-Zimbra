Name:           zimbra-spam-monitor
Version:        1.3.1
Release:        1
Summary:        Zimbra Outbound Email Spam Monitor & Alert System (Telegram + Email + Webhook)
License:        MIT
Group:          System Environment/Daemons
BuildArch:      noarch
Requires:       bash, gawk, curl, crontabs

%description
Ultra-lightweight multi-signal and multi-window outbound spam detection and alerting
system for Zimbra Collaboration Suite (strictly read-only against server & OS config).
- Evaluates 5m burst + 1h/24h low-and-slow limits, /24 source subnets, and Risk Score.
- Correlates Amavis Queue-ID hops, mailbox.log real Webmail IPs, and audit.log brute-force.
- Sends reliable Telegram, Email & Webhook alerts with Outbox retry and JSONL event log.
- Includes Self-RBL reputation check (--check-rbl) and read-only posture audit (--audit).
- Automatically locks CRITICAL accounts (with per-account cache flush) without JVM bloat.

%install
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/etc/zimbra-spam-monitor
mkdir -p %{buildroot}/etc/cron.d
mkdir -p %{buildroot}/etc/logrotate.d
mkdir -p %{buildroot}/var/lib/zimbra-spam-monitor

install -m 0755 %{_sourcedir}/zimbra-spam-monitor %{buildroot}/usr/bin/zimbra-spam-monitor
install -m 0640 %{_sourcedir}/config.conf %{buildroot}/etc/zimbra-spam-monitor/config.conf
install -m 0644 %{_sourcedir}/whitelist.conf %{buildroot}/etc/zimbra-spam-monitor/whitelist.conf
install -m 0644 %{_sourcedir}/zimbra-spam-monitor.cron %{buildroot}/etc/cron.d/zimbra-spam-monitor
install -m 0644 %{_sourcedir}/zimbra-spam-monitor.logrotate %{buildroot}/etc/logrotate.d/zimbra-spam-monitor

%post
mkdir -p /var/lib/zimbra-spam-monitor
touch /var/log/zimbra-spam-monitor.log
chmod 0640 /var/log/zimbra-spam-monitor.log
echo "======================================================================"
echo " [OK] Installed successfully: zimbra-spam-monitor v1.3.1"
echo " -> Run the command below to open the Interactive Control Panel:"
echo "      zimbra-spam-monitor"
echo "======================================================================"

%postun
if [ "$1" = "0" ]; then
    rm -rf /var/lib/zimbra-spam-monitor
fi

%files
%attr(0755, root, root) /usr/bin/zimbra-spam-monitor
%dir %attr(0755, root, root) /etc/zimbra-spam-monitor
%config(noreplace) %attr(0640, root, root) /etc/zimbra-spam-monitor/config.conf
%config(noreplace) %attr(0644, root, root) /etc/zimbra-spam-monitor/whitelist.conf
%config(noreplace) %attr(0644, root, root) /etc/cron.d/zimbra-spam-monitor
%config(noreplace) %attr(0644, root, root) /etc/logrotate.d/zimbra-spam-monitor
%dir %attr(0755, root, root) /var/lib/zimbra-spam-monitor
