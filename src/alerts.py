"""
alerts.py - Alert generation and formatting for the NIDS
Handles threat notifications with severity levels
"""

import yaml
from datetime import datetime
from src.logger import get_logger

# Severity levels for different attack types
SEVERITY = {
    "PORT_SCAN":   "WARNING",
    "SYN_FLOOD":   "CRITICAL",
    "ICMP_FLOOD":  "CRITICAL",
}


class AlertManager:
    """
    Manages alert generation and routing.
    All detection modules use this to raise alerts.
    """

    def __init__(self, config_path="config.yaml"):
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        self.logger         = get_logger()
        self.alert_config   = self.config["alerts"]
        self.alert_count    = 0

    def send_alert(self, attack_type, src_ip, details=""):
        """
        Send an alert for a detected attack.

        Args:
            attack_type: String like 'PORT_SCAN', 'SYN_FLOOD'
            src_ip:      The attacker's IP address
            details:     Extra context about the attack
        """

        self.alert_count += 1
        severity    = SEVERITY.get(attack_type, "WARNING")
        timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Format the alert message
        message = (
            f"[ALERT #{self.alert_count}] "
            f"{attack_type} detected | "
            f"Source: {src_ip} | "
            f"Time: {timestamp}"
        )

        if details:
            message += f" | Details: {details}"

        # Route to appropriate log level
        if severity == "CRITICAL":
            self.logger.critical(message)
        elif severity == "WARNING":
            self.logger.warning(message)
        else:
            self.logger.info(message)

    def get_alert_count(self):
        """Return total number of alerts generated."""
        return self.alert_count
