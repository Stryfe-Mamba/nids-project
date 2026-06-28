"""
analyzer.py - Packet analysis engine for the NIDS
Coordinates all detection modules and triggers alerts.
"""

import yaml
from src.logger import get_logger
from src.alerts import AlertManager
from src.detectors.port_scan import PortScanDetector
from src.detectors.syn_flood import SynFloodDetector
from src.detectors.icmp_flood import IcmpFloodDetector


class PacketAnalyzer:
    """
    Central analysis engine.
    Receives packets from capture engine and runs
    them through all registered detectors.
    """

    def __init__(self, config_path="config.yaml"):
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        self.logger         = get_logger()
        self.alert_manager  = AlertManager(config_path)
        self.packet_count   = 0

        # Initialize all detectors
        self.detectors = {
            "PORT_SCAN":  PortScanDetector(config_path),
            "SYN_FLOOD":  SynFloodDetector(config_path),
            "ICMP_FLOOD": IcmpFloodDetector(config_path),
        }

        self.logger.info(
            f"Analyzer initialized with "
            f"{len(self.detectors)} detectors"
        )

    def process_packet(self, packet):
        """
        Main packet processing pipeline.
        Called by PacketCapture for every captured packet.
        """
        self.packet_count += 1

        # Run packet through every detector
        for attack_type, detector in self.detectors.items():
            try:
                detected, details = detector.analyze(packet)
                if detected:
                    self.alert_manager.send_alert(
                        attack_type,
                        self._get_src_ip(packet),
                        details
                    )
            except Exception as e:
                self.logger.error(
                    f"Error in {attack_type} detector: {e}"
                )

    def _get_src_ip(self, packet):
        """Extract source IP from packet safely."""
        from scapy.all import IP
        if packet.haslayer(IP):
            return packet[IP].src
        return "unknown"

    def get_stats(self):
        """Return statistics from all detectors."""
        stats = {
            "total_packets": self.packet_count,
            "total_alerts":  self.alert_manager.get_alert_count(),
            "detectors":     {}
        }
        for name, detector in self.detectors.items():
            stats["detectors"][name] = detector.get_stats()
        return stats
