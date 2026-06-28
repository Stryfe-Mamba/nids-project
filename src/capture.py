"""
capture.py - Packet capture engine for the NIDS
Responsible for capturing packets from the network interface
and passing them to the analyzer for processing.
"""

import yaml
import threading
from scapy.all import sniff, conf
from src.logger import get_logger


class PacketCapture:
    """
    Captures packets from a network interface.
    Passes each packet to a callback function for analysis.
    """

    def __init__(self, config_path="config.yaml"):
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        self.logger         = get_logger()
        self.interface      = self.config["network"]["interface"]
        self.promiscuous    = self.config["network"]["promiscuous"]
        self.running        = False
        self.packet_count   = 0
        self.callback       = None

    def set_callback(self, callback):
        """
        Register the function to call for each captured packet.
        This will be our analyzer's process_packet method.
        """
        self.callback = callback

    def _process_packet(self, packet):
        """
        Internal handler called by Scapy for each packet.
        Increments counter and forwards to registered callback.
        """
        self.packet_count += 1

        if self.packet_count % 100 == 0:
            self.logger.debug(
                f"Packets captured so far: {self.packet_count}"
            )

        if self.callback:
            self.callback(packet)

    def start(self):
        """
        Start capturing packets on the configured interface.
        Runs in a background thread so it doesn't block main program.
        """
        if not self.callback:
            self.logger.error(
                "No callback registered. "
                "Call set_callback() before start()."
            )
            return

        self.running = True
        self.logger.info(
            f"Starting packet capture on interface: {self.interface}"
        )
        self.logger.info(
            f"Promiscuous mode: {self.promiscuous}"
        )

        # Run sniff in a background thread
        self.thread = threading.Thread(
            target=self._capture_loop,
            daemon=True
        )
        self.thread.start()
        self.logger.info("Packet capture started successfully")

    def _capture_loop(self):
        """
        The actual Scapy sniff call.
        Runs in background thread started by start().
        """
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,        # Don't store packets in memory
                promisc=self.promiscuous,
                stop_filter=lambda p: not self.running
            )
        except Exception as e:
            self.logger.error(f"Capture error: {e}")
            self.running = False

    def stop(self):
        """Stop packet capture gracefully."""
        self.running = False
        self.logger.info(
            f"Capture stopped. "
            f"Total packets captured: {self.packet_count}"
        )

    def get_packet_count(self):
        """Return total packets captured so far."""
        return self.packet_count
