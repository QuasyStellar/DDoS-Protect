#!/bin/bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "/etc/ddos-protect.conf" ]; then
    source "/etc/ddos-protect.conf"
fi

DEFAULT_IFACE=${IFACE:-$(ip route get 8.8.8.8 | grep -oP 'dev \K\S+')}
DEFAULT_RATE=${RATE_LIMIT_PPS:-100000}
DEFAULT_GLOBAL_UDP=${GLOBAL_UDP_PPS:-100000}
DEFAULT_GEO=${BLOCKED_COUNTRIES:-"br za mx bd in ar co cn ve ec pk uz tn vn id th ir ng eg tw kr"}
DEFAULT_WEB=${WEB_PORTS:-"http,https"}
DEFAULT_SSH=${SSH_PORT:-"22"}

echo "=========================================="
echo "    DDoS Protection Configuration         "
echo "=========================================="

if [ "$NON_INTERACTIVE" != "1" ]; then
    read -t 15 -p "Network Interface [$DEFAULT_IFACE]: " input_iface </dev/tty || true
    IFACE=${input_iface:-$DEFAULT_IFACE}

    read -t 15 -p "Rate Limit (PPS per IP) [$DEFAULT_RATE]: " input_rate </dev/tty || true
    RATE_LIMIT_PPS=${input_rate:-$DEFAULT_RATE}

    read -t 15 -p "Global UDP Limit (PPS) [$DEFAULT_GLOBAL_UDP]: " input_udp </dev/tty || true
    GLOBAL_UDP_PPS=${input_udp:-$DEFAULT_GLOBAL_UDP}

    read -t 15 -p "Blocked Countries (space separated) [$DEFAULT_GEO]: " input_geo </dev/tty || true
    BLOCKED_COUNTRIES=${input_geo:-$DEFAULT_GEO}

    read -t 15 -p "Fail2ban Web Ports [$DEFAULT_WEB]: " input_web </dev/tty || true
    WEB_PORTS=${input_web:-$DEFAULT_WEB}

    read -t 15 -p "Fail2ban SSH Port [$DEFAULT_SSH]: " input_ssh </dev/tty || true
    SSH_PORT=${input_ssh:-$DEFAULT_SSH}
else
    echo "[*] Applying configuration from /etc/ddos-protect.conf..."
    IFACE=$DEFAULT_IFACE
    RATE_LIMIT_PPS=$DEFAULT_RATE
    GLOBAL_UDP_PPS=$DEFAULT_GLOBAL_UDP
    BLOCKED_COUNTRIES=$DEFAULT_GEO
    WEB_PORTS=$DEFAULT_WEB
    SSH_PORT=$DEFAULT_SSH
fi

echo "[*] Saving configuration to /etc/ddos-protect.conf..."
echo "# DDoS Protect Global Configuration" > /etc/ddos-protect.conf
echo "IFACE=\"$IFACE\"" >> /etc/ddos-protect.conf
echo "RATE_LIMIT_PPS=$RATE_LIMIT_PPS" >> /etc/ddos-protect.conf
echo "GLOBAL_UDP_PPS=$GLOBAL_UDP_PPS" >> /etc/ddos-protect.conf
echo "BLOCKED_COUNTRIES=\"$BLOCKED_COUNTRIES\"" >> /etc/ddos-protect.conf
echo "WEB_PORTS=\"$WEB_PORTS\"" >> /etc/ddos-protect.conf
echo "SSH_PORT=\"$SSH_PORT\"" >> /etc/ddos-protect.conf

echo "[*] Installing dependencies..."
apt-get update >/dev/null
apt-get install -y clang llvm libbpf-dev gcc-multilib fail2ban linux-headers-$(uname -r) >/dev/null

if [ ! -f /usr/local/sbin/bpftool ]; then
    echo "[*] Custom kernel detected. Downloading static bpftool..."
    curl -sL https://github.com/libbpf/bpftool/releases/download/v7.7.0/bpftool-v7.7.0-amd64.tar.gz | tar -xz -C /usr/local/sbin/ bpftool
    chmod +x /usr/local/sbin/bpftool
fi

echo "[*] Applying Sysctl dynamically..."
TOTAL_MEM_MB=$(free -m | awk '/^Mem:/{print $2}')

if [ "$TOTAL_MEM_MB" -le 2048 ]; then
    CONNTRACK_MAX=262144
    RMEM=16777216
elif [ "$TOTAL_MEM_MB" -le 8192 ]; then
    CONNTRACK_MAX=1048576
    RMEM=33554432
else
    CONNTRACK_MAX=4194304
    RMEM=67108864
fi

cat <<EOF > /etc/sysctl.d/99-ddos.conf
net.netfilter.nf_conntrack_max = $CONNTRACK_MAX
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_rfc1337 = 1
net.netfilter.nf_conntrack_udp_timeout = 15
net.netfilter.nf_conntrack_udp_timeout_stream = 120
net.core.rmem_max = $RMEM
net.core.wmem_max = $RMEM
EOF

sysctl -p /etc/sysctl.d/99-ddos.conf >/dev/null

echo "[*] Detecting external interface..."
if [ -z "$IFACE" ]; then
    IFACE=$(ip route get 8.8.8.8 | grep -oP 'dev \K\S+')
fi
if [ -z "$IFACE" ]; then
    echo "[-] FATAL: Could not detect external network interface."
    exit 1
fi
echo "    Found interface: $IFACE"

echo "[*] Compiling XDP program (Per-IP: ${RATE_LIMIT_PPS} PPS, Global UDP: ${GLOBAL_UDP_PPS} PPS)..."
mkdir -p /usr/local/lib

CLANG_FLAGS="-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -DRATE_LIMIT_PPS=${RATE_LIMIT_PPS} -DGLOBAL_UDP_PPS=${GLOBAL_UDP_PPS}"

clang $CLANG_FLAGS -c $DIR/src/xdp_filter.c -o /usr/local/lib/xdp_filter.o

echo "[*] Setting up Systemd for XDP..."
sed "s/{{IFACE}}/$IFACE/g" $DIR/conf/xdp-ddos.service > /etc/systemd/system/xdp-ddos.service
systemctl daemon-reload
systemctl enable --now xdp-ddos.service

echo "[*] Installing CLI tools..."
cp $DIR/src/geoloader.sh /usr/local/bin/ddos-update-geo
cp $DIR/stats.sh /usr/local/bin/ddos-stats
cp $DIR/uninstall.sh /usr/local/bin/ddos-uninstall

echo '#!/bin/bash' > /usr/local/bin/ddos-reconfigure
echo 'echo "[*] Re-downloading and reconfiguring DDoS Protect..."' >> /usr/local/bin/ddos-reconfigure
echo 'curl -sL https://raw.githubusercontent.com/QuasyStellar/ddos-protect/main/bootstrap.sh | NON_INTERACTIVE=1 bash' >> /usr/local/bin/ddos-reconfigure

chmod +x /usr/local/bin/ddos-update-geo /usr/local/bin/ddos-stats /usr/local/bin/ddos-uninstall /usr/local/bin/ddos-reconfigure

echo "[*] Running GeoLoader to populate BPF map..."
ddos-update-geo

echo "[*] Setting up Auto-Update (Cron)..."
if ! crontab -l 2>/dev/null | grep -q "ddos-update-geo"; then
    (crontab -l 2>/dev/null; echo "0 4 * * 0 /usr/local/bin/ddos-update-geo >/dev/null 2>&1") | crontab -
    echo "    Weekly auto-update scheduled (Sunday 04:00)."
fi

echo "[*] Configuring Fail2ban..."
cp $DIR/conf/nginx-limit-req.conf /etc/fail2ban/filter.d/
sed -e "s/{{WEB_PORTS}}/${WEB_PORTS:-http,https}/g" \
    -e "s/{{SSH_PORT}}/${SSH_PORT:-22}/g" \
    $DIR/conf/jail.local > /etc/fail2ban/jail.local
systemctl restart fail2ban

if [ -d "/etc/nginx/conf.d" ]; then
    echo "[*] Installing Nginx Anti-Slowloris protection..."
    cp $DIR/conf/nginx-slowloris.conf /etc/nginx/conf.d/ddos-slowloris.conf
    systemctl restart nginx 2>/dev/null || true
else
    echo "⚠️ Nginx not found on host (/etc/nginx/conf.d is missing)."
    echo "   If you use Dockerized Nginx, please manually copy conf/nginx-*.conf to your container."
fi

echo "[+] Installation complete! DDoS protection is active."
