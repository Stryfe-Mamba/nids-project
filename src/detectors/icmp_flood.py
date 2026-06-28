"""
icmp_flood.py - ICMP flood detection module
Detects ping floods and ICMP-based DoS attacks.
"""

import time
import yaml
from collections import defaultdict, deque
from src.logger import get_logger


class IcmpFloodDetector:
    """
    Detects ICMP flood attacks (ping floods).

    Strategy: Count ICMP echo-request packets per source IP
    within a time window. Normal ping sends 1 packet/second.
    A flood sends hundreds per second.
    """

    def __init__(self, config_path="config.yaml"):
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)

        icmp_config         = config["thresholds"]["icmp_flood"]
        self.max_packets    = icmp_config["max_packets"]
        self.time_window    = icmp_config["time_window"]
        self.logger         = get_logger()

        self.tracker = defaultdict(deque)
        self.alerted = set()

    def analyze(self, packet):
        """
        Analyze a packet for ICMP flood behavior.
        Returns (True, details) if flood detected, else (False, "")
        """
        from scapy.all import IP, ICMP

        # Only process ICMP packets
        if not (packet.haslayer(IP) and packet.haslayer(ICMP)):
            return False, ""

        # Only count echo requests (type=8), not replies
        if packet[ICMP].type != 8:
            return False, ""

        src_ip  = packet[IP].src
        now     = time.time()

        self.tracker[src_ip].append(now)

        # Prune old entries
        while (self.tracker[src_ip] and
               now - self.tracker[src_ip][0] > self.time_window):
            self.tracker[src_ip].popleft()

        icmp_count = len(self.tracker[src_ip])

        if icmp_count >= self.max_packets:
            if src_ip not in self.alerted:
                self.alerted.add(src_ip)
                details = (
                    f"{icmp_count} ICMP echo-requests in "
                    f"{self.time_window}s "
                    f"(threshold: {self.max_packets})"
                )
                return True, details

        elif src_ip in self.alerted:
            if icmp_count < self.max_packets // 2:
                self.alerted.discard(src_ip)

        return False, ""

    def get_stats(self):
        """Return ICMP counts per IP in current window."""
        now = time.time()
        return {
            ip: len([t for t in times
                     if now - t <= self.time_window])
            for ip, times in self.tracker.items()
        }
