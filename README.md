# Enterprise DDoS Protection Stack (eBPF/XDP)

**DDoS-Protect** is an enterprise-grade, ultra-lightweight packet filtering system built on modern Linux eBPF/XDP technology. Designed to scale seamlessly across any hardware environment—from 1-vCPU VPS nodes to high-capacity dedicated bare-metal servers. It provides uncompromising protection for high-traffic Web servers (Nginx) and performance-critical VPN deployments (Xray, Hysteria).

The stack intercepts and drops malicious traffic directly at the network interface card (NIC) driver level, yielding near-zero CPU overhead.

## Key Features

- **Anti-IP Spoofing (Bloom Filter)**: Implements an `O(1)` BPF Bloom Filter to pre-screen 1,000,000 randomly spoofed IP addresses, preventing kernel spinlock contention and protecting the primary LRU Hash rate-limit maps during intense volumetric floods.
- **Enterprise Scalability**: Automatically calculates and applies optimal kernel sysctl parameters (conntrack limits, TCP memory buffers, SYN cookies) based on total system RAM, dynamically adapting from 512MB micro-nodes to 128GB+ enterprise servers.
- **Extreme Performance**: Operates at the network interface driver level (Native XDP). Drops malicious packets before they reach the Linux network stack, ensuring line-rate processing even during multi-gigabit volumetric attacks.
- **O(1) Geo-Blocking**: Utilizes hardware-level BPF LPM Tries to instantly block traffic from massive country subnets (over 56,000 subnets) with zero performance degradation. Auto-updates dynamically.
- **Port-Specific Rate Limiting**: 
  - Dynamic UDP limits (up to 100,000 packets/sec) to prevent throughput degradation for modern QUIC-based VPNs like Hysteria on ports 443/8443.
  - Strict 1,000 PPS caps on other ports to prevent DNS/NTP amplification sweeps.
  - Intelligent bypass for fragmented IP packets to prevent corruption of large encrypted tunnel packets.
- **NextPATH Integration**: Tuned Sysctl parameters (extended UDP session timeouts) for stable local DNS and DNAT routing.
- **Automation**: Fully automated installation, out-of-the-box Fail2ban configuration for Nginx/SSH, and weekly automated IP list updates via Cron.
- **Native Linux Integration**: Zero-trace installation directly into system directories.
- **Fail2ban Integration**: Detects and permabans L7 brute-force attacks via `nftables`.
- **Anti-Slowloris**: Automatically hardens Nginx against slow-connection attacks.

## Architecture Overview

1. `src/xdp_filter.c`: The core eBPF bytecode that attaches to the network interface.
2. `src/geoloader.sh`: A parser that downloads subnet zones from ipdeny.com and inserts them directly into the BPF Map. Auto-updates every Sunday at 04:00.
3. `conf/jail.local`: Strict Fail2ban rules to protect SSH and Nginx against L7 brute-force attacks.

## Installation

To install, simply run this one-liner. It will download the necessary scripts, compile the C code, install everything into native Linux directories (`/usr/local/bin`), and delete all temporary files:
```bash
curl -sL https://raw.githubusercontent.com/QuasyStellar/ddos-protect/main/bootstrap.sh | bash
```

## Configuration

After installation, you can edit the global configuration file to change rate limits, protected ports, and blocked countries:
```bash
nano /etc/ddos-protect.conf
```
*Note: If you change the configuration, run `ddos-reconfigure` to recompile the kernel module and apply the new limits.*

## Usage & Management

Once installed, the DDoS protection runs automatically in the background. You can manage it from any directory using these global commands:

- **`ddos-stats`**: View real-time statistics of dropped/blocked packets (live dashboard).
- **`ddos-update-geo`**: Manually update the IP blocklists from ipdeny.com.
- **`ddos-reconfigure`**: Recompile and apply changes made in `/etc/ddos-protect.conf`.
- **`ddos-uninstall`**: Completely remove the protection, scripts, and all traces from the system.

## Docker Support
XDP protection works out-of-the-box for Docker (packets are dropped at the driver level). For L7 Fail2ban protection, ensure you mount Nginx logs to the host (`-v /var/log/nginx:/var/log/nginx`) and manually copy the `conf/nginx-*.conf` files into your container.


## Uninstallation

To safely remove the XDP filters, sysctl parameters, and cron jobs, restoring the server to its original state:
```bash
bash /opt/ddos-protect/uninstall.sh
```
