#!/bin/bash
set -e
set -o pipefail

if [ -f "/etc/ddos-protect.conf" ]; then
    source /etc/ddos-protect.conf
else
    BLOCKED_COUNTRIES="br za mx bd in ar co cn ve ec pk uz tn vn id th ir ng eg tw kr"
fi

COUNTRIES=($BLOCKED_COUNTRIES)
URL_TEMPLATE="https://www.ipdeny.com/ipblocks/data/countries/%s.zone"
BATCH_FILE="/tmp/bpftool_batch.txt"

# Find geo_map ID
MAP_ID=$(/usr/local/sbin/bpftool map show | grep geo_map | awk -F':' '{print $1}' | head -n1 | tr -d ' ')
if [ -z "$MAP_ID" ]; then
    echo "geo_map not found! Is the XDP program loaded?"
    exit 1
fi

echo -n "" > "$BATCH_FILE"

for country in "${COUNTRIES[@]}"; do
    echo "Downloading ${country^^} zones..."
    url=$(printf "$URL_TEMPLATE" "$country")
    
    curl -s "$url" | awk -F'/' -v map_id="$MAP_ID" '
    function hex(dec) {
        return sprintf("%02x", dec)
    }
    NF==2 {
        ip=$1; prefix=$2
        
        # Convert prefix to 4-byte little endian hex
        p_hex = hex(prefix) " 00 00 00"
        
        # Convert IP to 4-byte network byte order hex
        split(ip, octets, ".")
        if (length(octets) == 4) {
            ip_hex = hex(octets[1]) " " hex(octets[2]) " " hex(octets[3]) " " hex(octets[4])
            
            print "map update id " map_id " key hex " p_hex " " ip_hex " value hex 01"
        }
    }' >> "$BATCH_FILE"
done

echo "Applying $BATCH_FILE via bpftool..."
/usr/local/sbin/bpftool batch file "$BATCH_FILE"
echo "Done!"
