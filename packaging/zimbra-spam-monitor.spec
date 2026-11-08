Name:           zimbra-spam-monitor
Version:        1.1.1
Release:        1
Summary:        Zimbra Outbound Email Spam Monitor & Alert System (Telegram + Email)
License:        MIT
Group:          System Environment/Daemons
BuildArch:      noarch
Requires:       bash, gawk, curl, crontabs

%description
Automated outbound spam detection and alerting system for Zimbra Collaboration Suite.
- Scans /var/log/zimbra.log for short-window (minutes) and hourly outbound email rates.
- Inspects Postfix mail queue (postqueue / mailq) per sender and server-wide.
- Sends instant alerts via Telegram Bot API and Email (Local Postfix / External SMTP).
- Automatically locks compromised accounts (zimbraAccountStatus locked) on Critical threshold.
- Includes an interactive TUI / Menu control panel (run: zimbra-spam-monitor).

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
echo " [OK] Installed successfully: zimbra-spam-monitor v1.1.0"
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
