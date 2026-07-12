#!/bin/bash
set -e

RAW_BASE="https://raw.githubusercontent.com/QuasyStellar/ddos-protect/main"
INSTALL_DIR="/tmp/ddos-protect"

echo "=========================================="
echo "    Advanced DDoS Protection Bootstrap    "
echo "=========================================="

echo "[*] Downloading core files..."
mkdir -p $INSTALL_DIR/src
mkdir -p $INSTALL_DIR/conf

curl -sfL "$RAW_BASE/src/xdp_filter.c" -o $INSTALL_DIR/src/xdp_filter.c
curl -sfL "$RAW_BASE/src/geoloader.sh" -o $INSTALL_DIR/src/geoloader.sh
curl -sfL "$RAW_BASE/stats.sh" -o $INSTALL_DIR/stats.sh
curl -sfL "$RAW_BASE/uninstall.sh" -o $INSTALL_DIR/uninstall.sh
curl -sfL "$RAW_BASE/install.sh" -o $INSTALL_DIR/install.sh

curl -sfL "$RAW_BASE/conf/jail.local" -o $INSTALL_DIR/conf/jail.local
curl -sfL "$RAW_BASE/conf/nginx-limit-req.conf" -o $INSTALL_DIR/conf/nginx-limit-req.conf
curl -sfL "$RAW_BASE/conf/nginx-slowloris.conf" -o $INSTALL_DIR/conf/nginx-slowloris.conf
curl -sfL "$RAW_BASE/conf/xdp-ddos.service" -o $INSTALL_DIR/conf/xdp-ddos.service

chmod +x $INSTALL_DIR/install.sh $INSTALL_DIR/stats.sh $INSTALL_DIR/uninstall.sh $INSTALL_DIR/src/geoloader.sh

echo "[*] Starting installation..."
cd $INSTALL_DIR
bash install.sh

echo "[*] Cleaning up..."
cd /
rm -rf "$INSTALL_DIR"
echo "[+] Bootstrap finished successfully."
