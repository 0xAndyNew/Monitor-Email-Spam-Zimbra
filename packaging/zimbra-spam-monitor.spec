Name:           zimbra-spam-monitor
Version:        1.0.0
Release:        1
Summary:        Zimbra Outbound Email Spam Monitor & Alert System (Telegram + Email)
License:        MIT
Group:          System Environment/Daemons
BuildArch:      noarch
Requires:       bash, gawk, curl, crontabs

%description
He thong giam sat va canh bao Email Spam Outbound cho Zimbra Collaboration Suite.
- Quet /var/log/zimbra.log dem so luong email gui ra ngoai theo Phut va theo Gio.
- Kiem tra hang doi Postfix (postqueue / mailq) theo tung tai khoan.
- Gui canh bao tuc thoi qua Telegram Bot API va Email (Postfix noi bo / SMTP ngoai).
- Tu dong khoa tai khoan (zimbraAccountStatus locked) khi vuot nguong Critical.

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
echo " [OK] Da cai dat thanh cong goi: zimbra-spam-monitor-1.0.0"
echo " 1. Chinh sua cau hinh truc tiep tai:"
echo "      nano /etc/zimbra-spam-monitor/config.conf"
echo "    Hoac chay menu cau hinh nhanh:"
echo "      zimbra-spam-monitor --configure"
echo " 2. Kiem tra gui thong bao Telegram & Email:"
echo "      zimbra-spam-monitor --test"
echo " 3. Xem trang thai luu luong gui mail & hang doi hien tai:"
echo "      zimbra-spam-monitor --status"
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
