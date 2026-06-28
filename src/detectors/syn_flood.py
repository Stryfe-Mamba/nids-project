"""
syn_flood.py - SYN flood detection module
Detects TCP SYN flood attacks by counting SYN packets
per source IP within a time window.
"""

import time
import yaml
from collections import defaultdict, deque
from src.logger import get_logger


class SynFloodDetector:
    """
    Detects SYN flood attacks.

    Strategy: Count TCP packets with ONLY the SYN flag set
    per source IP per second. A SYN flood sends thousands
    of SYN packets without completing the TCP handshake.
    """

    def __init__(self, config_path="config.yaml"):
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)

        sf_config           = config["thresholds"]["syn_flood"]
        self.max_syns       = sf_config["max_syns"]
        self.time_window    = sf_config["time_window"]
        self.logger         = get_logger()

        # Track SYN packet timestamps per source IP
        self.tracker = defaultdict(deque)
        self.alerted = set()

    def analyze(self, packet):
        """
        Analyze a packet for SYN flood behavior.
        Returns (True, details) if flood detected, else (False, "")
        """
        from scapy.all import IP, TCP

        # Only process IP/TCP packets
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return False, ""

        # Check for SYN flag only (flags == 0x02)
        # SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04
        tcp_flags = packet[TCP].flags
        if tcp_flags != 0x02:   # Must be ONLY SYN, no ACK
            return False, ""

        src_ip  = packet[IP].src
        now     = time.time()

        # Record this SYN packet
        self.tracker[src_ip].append(now)

        # Remove timestamps outside our window
        while (self.tracker[src_ip] and
               now - self.tracker[src_ip][0] > self.time_window):
            self.tracker[src_ip].popleft()

        syn_count = len(self.tracker[src_ip])

        # Check threshold
        if syn_count >= self.max_syns:
            if src_ip not in self.alerted:
                self.alerted.add(src_ip)
                details = (
                    f"{syn_count} SYN packets in "
                    f"{self.time_window}s "
                    f"(threshold: {self.max_syns})"
                )
                return True, details

        elif src_ip in self.alerted:
            if syn_count < self.max_syns // 2:
                self.alerted.discard(src_ip)

        return False, ""

    def get_stats(self):
        """Return SYN counts per IP in current window."""
        now = time.time()
        return {
            ip: len([t for t in times
                     if now - t <= self.time_window])
            for ip, times in self.tracker.items()
        }
