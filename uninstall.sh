#!/bin/bash
set -e

echo "[*] Disabling and removing XDP protection..."
systemctl disable --now xdp-ddos.service 2>/dev/null || true
rm -f /etc/systemd/system/xdp-ddos.service
systemctl daemon-reload


echo "[*] Removing sysctl tuning..."
rm -f /etc/sysctl.d/99-ddos.conf
sysctl --system >/dev/null

echo "[*] Removing Fail2ban configurations..."
rm -f /etc/fail2ban/filter.d/nginx-limit-req.conf
rm -f /etc/fail2ban/jail.local
systemctl restart fail2ban 2>/dev/null || true

echo "[*] Cleaning up compiled files and cronjobs..."
crontab -l 2>/dev/null | grep -v "ddos-update-geo" | crontab - 2>/dev/null || true
rm -f /usr/local/lib/xdp_filter.o
rm -f /usr/local/bin/ddos-update-geo
rm -f /usr/local/bin/ddos-stats
rm -f /etc/ddos-protect.conf
rm -f /usr/local/bin/ddos-uninstall
rm -f /usr/local/bin/ddos-reconfigure

if [ -f "/etc/nginx/conf.d/ddos-slowloris.conf" ]; then
    rm -f /etc/nginx/conf.d/ddos-slowloris.conf
    systemctl restart nginx 2>/dev/null || true
fi

echo "[+] Uninstallation complete. System is back to normal."
