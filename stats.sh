#!/bin/bash
export PATH=$PATH:/usr/local/sbin:/usr/sbin:/sbin

MAP_ID=$(bpftool map show | grep "stats_map" | awk -F':' '{print $1}' | head -n1 | tr -d ' ')

if [ -z "$MAP_ID" ]; then
    echo "[-] Stats map not found. Is XDP currently attached to the interface?"
    exit 1
fi

get_stat() {
    local key=$1
    local hex_key=$(printf "%02x 00 00 00" $key)
    local val_hex=$(bpftool map lookup id $MAP_ID key hex $hex_key 2>/dev/null | grep -E "^cpu~")
    local total=0
    
    if [ -n "$val_hex" ]; then
        while read -r line; do
            local bytes=$(echo "$line" | cut -d':' -f2)
            local hex=$(echo $bytes | awk '{print $8$7$6$5$4$3$2$1}')
            local val=$((16#$hex))
            total=$((total + val))
        done <<< "$val_hex"
    fi
    echo "$total"
}

# Clear screen for live monitoring
clear
echo "============================================="
echo "      🛡️ XDP DDoS Protection Real-Time Stats  "
echo "============================================="
echo ""
echo " 🌍 Geo-Blocked Packets:       $(get_stat 0)"
echo " 🚦 Per-IP Rate-Limited:       $(get_stat 1)"
echo " ☠️ Invalid TCP (SYN Flood):   $(get_stat 2)"
echo " ☠️ Invalid UDP Packets:       $(get_stat 3)"
echo " 🌐 Global UDP Flood Drops:    $(get_stat 4)"
echo ""
echo "============================================="
echo "💡 Usage hint: Use 'watch -n 1 bash stats.sh' to view in real-time."
echo "💡 To reset counters: systemctl restart xdp-ddos.service"
