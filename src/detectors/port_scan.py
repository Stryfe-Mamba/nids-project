"""
port_scan.py - Port scan detection module
Detects when a single IP probes too many ports
in a short time window.
"""

import time
import yaml
from collections import defaultdict, deque
from src.logger import get_logger


class PortScanDetector:
    """
    Detects port scanning behavior.

    Strategy: Track unique destination ports per source IP
    within a sliding time window. Alert when count exceeds
    configured threshold.
    """

    def __init__(self, config_path="config.yaml"):
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)

        ps_config           = config["thresholds"]["port_scan"]
        self.max_ports      = ps_config["max_ports"]
        self.time_window    = ps_config["time_window"]
        self.logger         = get_logger()

        # For each source IP, track timestamps of port probes
        # defaultdict means missing keys auto-create empty deque
        # Structure: { "192.168.1.100": deque([(timestamp, port), ...]) }
        self.tracker = defaultdict(deque)

        # Track which IPs we have already alerted on
        # to avoid alert spam
        self.alerted = set()

    def analyze(self, packet):
        """
        Analyze a single packet for port scan behavior.
        Returns (True, details) if scan detected, else (False, "")
        """
        from scapy.all import IP, TCP

        # Only analyze TCP packets with IP layer
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return False, ""

        src_ip  = packet[IP].src
        dst_port = packet[TCP].dport
        now     = time.time()

        # Add this probe to tracker
        self.tracker[src_ip].append((now, dst_port))

        # Remove entries outside the time window
        while (self.tracker[src_ip] and
               now - self.tracker[src_ip][0][0] > self.time_window):
            self.tracker[src_ip].popleft()

        # Count unique ports in current window
        ports_in_window = set(
            port for _, port in self.tracker[src_ip]
        )
        unique_port_count = len(ports_in_window)

        # Check threshold
        if unique_port_count >= self.max_ports:
            if src_ip not in self.alerted:
                self.alerted.add(src_ip)
                details = (
                    f"Probed {unique_port_count} unique ports "
                    f"in {self.time_window}s window. "
                    f"Ports: {sorted(ports_in_window)}"
                )
                return True, details

        # Reset alert if IP drops below threshold
        # (allows re-alerting after a quiet period)
        elif src_ip in self.alerted:
            if unique_port_count < self.max_ports // 2:
                self.alerted.discard(src_ip)

        return False, ""

    def get_stats(self):
        """Return current tracking statistics."""
        return {
            ip: len(set(p for _, p in probes))
            for ip, probes in self.tracker.items()
            if probes
        }
