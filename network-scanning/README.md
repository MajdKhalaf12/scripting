# Network Scanning

Python scripts for network discovery and service fingerprinting: ICMP ping sweeps, TCP SYN port scans (Scapy), optional Nmap-based service/OS detection, and HTTP banner grabbing.

**Use only on networks and hosts you own or have explicit permission to test.**

## Requirements

- Python 3
- [Nmap](https://nmap.org/) installed on your system (for `fingerprint.py` and `wrapper.py`)
- Python packages: `scapy`, `python-nmap`

```bash
python -m venv .venv
source .venv/bin/activate
pip install scapy python-nmap
```

On macOS/Linux, Scapy may need elevated privileges for raw packets (ICMP/TCP SYN). Run with `sudo` when scans fail without it.

## Scripts

| Script | Purpose |
|--------|---------|
| `ping_sweeper.py` | ICMP ping sweep of a subnet, then TCP SYN scan of ports 1–1024 on each live host |
| `fingerprint.py` | Scan a single host with Nmap; write service/OS fields to CSV |
| `service_fingerprint.py` | Grab HTTP banners from open ports via TCP socket |
| `wrapper.py` | Full pipeline: ping sweep → port scan → Nmap fingerprint → append to `scan_results.csv` |

## Usage

Run commands from this directory (`network-scanning/`).

### Ping sweep and port scan

```bash
python ping_sweeper.py <network> <netmask>
```

Example: `python ping_sweeper.py 192.168.1.0 24`

### Nmap fingerprint (single host)

```bash
python fingerprint.py <host> [-p PORTS] [-o OUTPUT.csv]
```

Defaults: ports `1-1024`, output `scan_results.csv`.

Example: `python fingerprint.py 192.168.1.10 -p 22,80,443`

### HTTP banner grab

```bash
python service_fingerprint.py <ip> -p <port1,port2,...>
```

Example: `python service_fingerprint.py 192.168.1.10 -p 80,443`

### Full network workflow

```bash
python wrapper.py <network> <netmask>
```

Discovers live hosts, scans ports 1–1023 on each, runs Nmap on every open port, and appends rows to `scan_results.csv`.

## Output

`fingerprint.py` and `wrapper.py` append scan rows to CSV with columns: `ip`, `os`, `port`, `name`, `product`, `version`.
