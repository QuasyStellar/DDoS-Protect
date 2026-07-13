# DDOS-Protect

DDOS-Protect is a high-performance, industrial-grade Layer 3/4/7 DDoS mitigation system written in **C (eBPF/XDP)** and **Go**. It is designed to provide massive volumetric packet filtering directly within the Linux kernel, requiring nearly zero CPU overhead, making it ideal for resource-constrained environments like 1-vCPU VPS instances hosting VPNs (Xray, Hysteria) or web servers.

By intercepting and filtering packets directly inside the Network Interface Card (NIC) driver's memory space, DDOS-Protect drops malicious traffic before it ever reaches the Linux kernel's standard networking stack or iptables.

---

## Key Advantages

*   **Pure In-Kernel XDP Filtering:** Blocks UDP floods, TCP SYN floods, and IP fragmentation attacks at the driver level, capable of absorbing 10+ Mpps without affecting system load.
*   **Layer 7 TLS SNI Inspection:** Features deep packet inspection within the kernel. It decodes TLS ClientHello packets and instantly drops connections if the requested Server Name Indication (SNI) does not match the configured whitelist, protecting hidden endpoints from scanners.
*   **XDP-Aware NAT (Universal Auto-Discovery):** Overcomes standard XDP NAT-blindness. The Go control plane automatically parses standard `iptables` and `nftables` rulesets, syncing NAT mappings directly into an eBPF map. This allows XDP to perform true Stateful TCP tracking for containers behind routing engines like Docker or NextPATH.
*   **Strict TCP Tracking (Orphan ACK Drops):** Validates every incoming TCP ACK against the host's real socket tables. If an ACK packet belongs to a non-existent connection, it is dropped instantly as an "Orphan ACK", mitigating sophisticated state-exhaustion attacks.
*   **Adaptive Rate Limiting (EWMA Algorithm):** Instead of static limits that penalize legitimate users, the Go daemon utilizes an Exponentially Weighted Moving Average (EWMA) algorithm. It continuously monitors CPU drops and dynamically scales TCP and UDP packet-per-second limits based on attack severity.
*   **GeoIP Bloom Filters:** Blocks entire hostile country subnets in O(1) time. Uses a highly optimized LPM (Longest Prefix Match) Trie combined with an IP-spoofing Bloom Filter, avoiding the memory bloat of standard iptables.

---

## Deployment & Setup

DDOS-Protect is distributed as a lightweight, statically compiled Docker container running in the host network namespace.

### Pre-requisites
- Docker & Docker Compose
- Linux Kernel 5.4 or higher (5.15+ recommended for full BPF map support)

### Quick Start
1. Create a working directory and pull the repository:
   ```bash
   mkdir -p ddos-protect && cd ddos-protect
   curl -O https://raw.githubusercontent.com/QuasyStellar/DDOS-Protect/main/docker-compose.yml
   curl -o .env https://raw.githubusercontent.com/QuasyStellar/DDOS-Protect/main/.env.example
   ```
2. Open the `.env` file in your preferred text editor and adjust the variables to fit your network (e.g., `IFACE`, `ALLOWED_SNI`).
3. Start the stack (Docker will automatically pull the compiled image from Docker Hub):
   ```bash
   docker compose up -d
   ```

---

## Configuration Reference

All parameters are configured via environment variables in the `.env` file.

### Core Settings
| Variable | Default | Description |
|----------|---------|-------------|
| `IFACE` | `eth0` | The public-facing network interface to attach the XDP program to. |
| `RATE_LIMIT_PPS` | `100000` | Base limit for TCP/General packets per second per IP. |
| `GLOBAL_UDP_PPS` | `100000` | Base global limit for incoming UDP packets per second. |
| `STRICT_TCP_TRACKING`| `0` | Set to `1` to enable dropping of ACK packets for unknown connections. |
| `METRICS_ADDR` | `127.0.0.1:9090` | The address to bind the Prometheus metrics endpoint to. |

### L7 & GeoIP Filtering
| Variable | Default | Description |
|----------|---------|-------------|
| `ALLOWED_SNI` | - | Comma-separated list of allowed domains (e.g., `vpn.example.com`). If empty, SNI filtering is disabled. |
| `ALLOWED_PORTS` | `80,443,8443` | Comma-separated list of open ports. XDP uses an O(1) Array Map for these to achieve ultra-fast Early Port Switching. |
| `BLOCKED_COUNTRIES` | `br za mx bd in ar...` | Space-separated ISO codes of countries to block via GeoIP. These countries are known for high botnet activity. |

### Advanced Architecture
| Variable | Default | Description |
|----------|---------|-------------|
| `STRICT_TCP_TRACKING`| `0` | Set to `1` to drop TCP ACK packets for unknown connections. This is crucial for stopping **ACK Floods**, a common DDoS vector that bypasses standard SYN limiters. |
| `NAT_MAPPINGS` | - | Comma-separated static NAT mappings (`PublicPort:InternalIP:InternalPort`). Setting this **disables** background auto-discovery polling, saving CPU cycles. If empty, Auto-Discovery runs every 10s. |

---

## Diagnostics & Troubleshooting

### View XDP Program Status:
You can verify that the XDP program is successfully attached to your network interface using standard `iproute2` commands:
```bash
ip -details link show dev eth0
```
Look for the `xdp` flag in the output.

### View Daemon Logs:
The Go daemon continuously prints metrics, EWMA dynamic limit adjustments, and NAT synchronization status.
```bash
docker logs -f ddos-protect
```

### Prometheus Metrics:
The Go daemon exposes a Prometheus metrics endpoint. By default, it binds to `127.0.0.1:9090` (for security), but you can change this using the `METRICS_ADDR` variable in `.env` (e.g., `METRICS_ADDR=0.0.0.0:9090` if scraping externally).

You can scrape it to monitor real-time drops and attack statistics in Grafana:
```bash
curl http://localhost:9090/metrics
```
Metrics exported include `ddos_rate_limit_drops_total`, `ddos_udp_global_drops_total`, `ddos_geo_drops_total`, and `ddos_invalid_drops_total`.

### View eBPF Map Statistics:
To inspect the internal state of the kernel eBPF maps (run this on your host machine, requires `bpftool` installed):
```bash
bpftool map dump name rate_limit_map
bpftool map dump name geo_map
```

---

## L7 Application Security Recommendations

While `DDOS-Protect` intercepts volumetric Layer 3/4 floods in the kernel, sophisticated HTTP/7 brute-force attacks and Slowloris sweeps should be mitigated at the application level.

We provide a set of battle-tested configuration templates in the `conf/` directory. Here is exactly how to apply them to your system:

### 1. Nginx Configuration (Rate Limits & Slowloris)
If you are running Nginx directly on the host (or via Docker with mounted configs):
```bash
# 1. Download the Slowloris security template to nginx
sudo curl -sSL https://raw.githubusercontent.com/QuasyStellar/DDOS-Protect/main/conf/nginx-slowloris.conf -o /etc/nginx/conf.d/nginx-slowloris.conf

# 2. Open your main Nginx configuration (e.g., /etc/nginx/nginx.conf)
# and add this in the `http { ... }` block to define the rate limit zone:
#   limit_req_zone $binary_remote_addr zone=flood:10m rate=10r/s;
#   limit_conn_zone $binary_remote_addr zone=addr:10m;

# 3. Open your website config (e.g., /etc/nginx/sites-available/default)
# and add these limits inside your `server { ... }` block:
#   limit_req zone=flood burst=20 nodelay;
#   limit_conn addr 10;

# 4. Reload Nginx
sudo systemctl reload nginx
```

### 2. Fail2ban Configuration (L7 Bans)
To automatically parse Nginx error logs and issue permanent `nftables` bans for HTTP brute-force scanners:
```bash
# 1. Install Fail2ban if you haven't already
sudo apt-get install fail2ban -y

# 2. Download the custom Nginx fail2ban filter
sudo curl -sSL https://raw.githubusercontent.com/QuasyStellar/DDOS-Protect/main/conf/fail2ban-nginx-limit-req.conf -o /etc/fail2ban/filter.d/nginx-limit-req.conf

# 3. Download our aggressive jail configuration
sudo curl -sSL https://raw.githubusercontent.com/QuasyStellar/DDOS-Protect/main/conf/jail.local -o /etc/fail2ban/jail.local

# 4. Restart Fail2ban to apply the new rules
sudo systemctl restart fail2ban
```
*(If you run Fail2ban in Docker, simply mount `conf/jail.local` as a volume to `/etc/fail2ban/jail.local` inside your `docker-compose.yml`)*
---

## Development & Building

If you prefer to compile the eBPF bytecode and the Go daemon locally without Docker:

1. Install prerequisites:
   ```bash
   apt-get install clang llvm libbpf-dev linux-headers-$(uname -r) golang
   ```
2. Generate the eBPF bindings:
   ```bash
   cd daemon
   go generate
   ```
3. Compile the Go daemon:
   ```bash
   go build -ldflags="-s -w" -o ddos-daemon .
   ```
