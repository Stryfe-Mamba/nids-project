
# 🛡️ PyNIDS — Python Network Intrusion Detection System

![Python](https://img.shields.io/badge/Python-3.13-blue)
![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-red)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

A real-time Network Intrusion Detection System (NIDS) built from scratch
on Kali Linux using Python and Scapy. Passively monitors live network
traffic and detects common attack patterns with configurable thresholds,
colored alerts, and persistent logging.

---

## 📸 Demo

```
==================================================
        NETWORK INTRUSION DETECTION SYSTEM
              Built on Kali Linux
==================================================

2026-06-22 05:57:42 [INFO]     NIDS starting up...
2026-06-22 05:57:42 [INFO]     Monitoring network traffic on eth0...
2026-06-22 05:57:42 [WARNING]  [ALERT #1] PORT_SCAN detected  | Source: 192.168.56.1
2026-06-22 05:57:43 [CRITICAL] [ALERT #2] SYN_FLOOD detected  | Source: 192.168.56.1
2026-06-22 05:58:35 [CRITICAL] [ALERT #3] ICMP_FLOOD detected | Source: 192.168.56.1

==================================================
         NIDS SESSION SUMMARY
==================================================
  Total Packets Captured : 1287
  Total Alerts Generated : 3
  Detector Statistics:
    PORT_SCAN  : 1 IPs tracked
    SYN_FLOOD  : 1 IPs tracked
    ICMP_FLOOD : 1 IPs tracked
==================================================
```

---

## ✨ Features

- 🔴 **Live Packet Capture** — Monitors network interface in promiscuous mode using Scapy
- 🔍 **Port Scan Detection** — Detects rapid multi-port probing via sliding time window
- 💥 **SYN Flood Detection** — Identifies TCP SYN floods by analyzing packet flags
- 📡 **ICMP Flood Detection** — Catches ping floods from any source IP in real time
- 🎨 **Colored Alert System** — WARNING (yellow) and CRITICAL (red) severity levels
- 📁 **Rotating Log Files** — Automatic log rotation, never fills your disk
- 🧩 **Modular Architecture** — Each detector is independent and easily extensible
- ⚙️ **Configurable Thresholds** — All settings in config.yaml, no code changes needed
- 🛑 **Graceful Shutdown** — Clean Ctrl+C handling with full session statistics

---

## 🏗️ Project Structure

```
nids_project/
│
├── main.py                  ← Entry point, signal handling, session summary
├── config.yaml              ← All thresholds and settings
├── requirements.txt         ← Python dependencies
│
├── src/
│   ├── capture.py           ← Live packet capture engine (Scapy + threading)
│   ├── analyzer.py          ← Central packet processing pipeline
│   ├── alerts.py            ← Alert formatting and severity routing
│   ├── logger.py            ← Colored console + rotating file logging
│   │
│   └── detectors/
│       ├── port_scan.py     ← Port scan detection logic
│       ├── syn_flood.py     ← SYN flood detection logic
│       └── icmp_flood.py    ← ICMP flood detection logic
│
└── logs/
    └── nids.log             ← Persistent alert and event log
```

---

## ⚙️ Requirements

- Kali Linux (or any Debian-based Linux)
- Python 3.10+
- Root privileges (required for raw socket access)

---

## 🚀 Installation

### Step 1 — Clone the Repository:

```bash
git clone git@github.com:YourUsername/PyNIDS.git
cd PyNIDS
```

### Step 2 — Install Dependencies:

```bash
sudo apt install -y python3-scapy python3-flask \
     python3-yaml python3-colorama python3-flask-socketio
```

### Step 3 — Create Virtual Environment:

```bash
python3 -m venv venv --system-site-packages
source venv/bin/activate
```

### Step 4 — Run the NIDS:

```bash
sudo python3 main.py
```

---

## ⚙️ Configuration

All thresholds and settings live in `config.yaml`:

```yaml
network:
  interface: "eth0"      # Network interface to monitor
  promiscuous: true      # Capture all packets on segment

thresholds:
  port_scan:
    max_ports: 15        # Unique ports before alert fires
    time_window: 10      # Detection window in seconds

  syn_flood:
    max_syns: 100        # SYN packets per second before alert
    time_window: 1       # Detection window in seconds

  icmp_flood:
    max_packets: 50      # ICMP packets per second before alert
    time_window: 1       # Detection window in seconds

logging:
  log_file: "logs/nids.log"
  log_level: "INFO"
  max_file_size_mb: 10
  backup_count: 5
```

---

## 🧪 Testing

### Start the NIDS:
```bash
sudo python3 main.py
```

### Test 1 — Port Scan Detection:
```bash
sudo nmap -sS 127.0.0.1
```

### Test 2 — SYN Flood Detection:
```bash
sudo hping3 -S -p 80 --flood 127.0.0.1
```

### Test 3 — ICMP Flood Detection:
```bash
sudo ping -f 127.0.0.1
```

---

## 🔭 How Detection Works

### Port Scan Detection
Tracks unique destination ports per source IP using a sliding time
window backed by a deque data structure. Normal users connect to one
or two ports. Scanners probe dozens in seconds.

```
Normal user:    connects to port 80          → no alert
Port scanner:   probes 21,22,80,443,3306...  → WARNING alert
```

### SYN Flood Detection
Monitors TCP packets with only the SYN flag set (0x02). Legitimate
TCP connections complete the three-way handshake (SYN→SYN-ACK→ACK).
Flood attacks send thousands of SYN packets with no follow-up,
exhausting server connection tables.

```
Normal connection:  SYN → SYN-ACK → ACK    → no alert
SYN flood:          SYN SYN SYN SYN SYN... → CRITICAL alert
```

### ICMP Flood Detection
Counts ICMP echo request packets (type 8) per source IP within a
configurable time window. Normal ping sends one packet per second.
Floods send hundreds to thousands per second.

```
Normal ping:   1 packet/second   → no alert
ICMP flood:    500+ packets/sec  → CRITICAL alert
```

---

## 🗺️ Roadmap

- [ ] Real-time web dashboard (Flask + SocketIO)
- [ ] Automatic IP blocking via iptables
- [ ] DNS flood detection
- [ ] HTTP flood detection
- [ ] IP whitelist and blacklist support
- [ ] Email and SMS alert notifications
- [ ] Docker container support
- [ ] Unit tests for all detectors

---

## 🧠 Concepts Covered

Building this project teaches:

- TCP/IP networking and packet structure
- Raw sockets and promiscuous mode
- Scapy packet capture and dissection
- Sliding time window algorithms
- Python threading and signal handling
- Rotating file logging
- YAML configuration management
- Modular software architecture
- Real-world attack patterns and detection

---

## ⚠️ Legal Disclaimer

This tool is intended for **educational purposes** and **authorized
security testing only**. Only use on networks and systems you own or
have explicit written permission to test. Unauthorized network
monitoring may violate local laws and regulations. The author assumes
no liability for misuse.

---

## 🧰 Built With

| Tool | Purpose |
|---|---|
| [Scapy](https://scapy.net/) | Packet capture and analysis |
| [Flask](https://flask.palletsprojects.com/) | Web framework (dashboard) |
| [PyYAML](https://pyyaml.org/) | Configuration file parsing |
| [Colorama](https://pypi.org/project/colorama/) | Colored terminal output |
| Python 3.13 | Core language |
| Kali Linux 6.12 | Development and testing platform |

---

## 👨‍💻 Author

Built as a hands-on cybersecurity engineering project covering
real-world network security concepts from packet capture to
threat detection and alert generation.
