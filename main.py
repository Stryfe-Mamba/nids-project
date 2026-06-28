"""
main.py - Entry point for the NIDS
Wires all modules together and manages startup/shutdown.
"""

import sys
import time
import signal
import yaml
from src.logger import setup_logger
from src.capture import PacketCapture
from src.analyzer import PacketAnalyzer


# Global references for signal handler
capture  = None
analyzer = None
logger   = None


def signal_handler(signum, frame):
    """
    Handle Ctrl+C gracefully.
    Stops capture and prints final statistics.
    """
    print()
    logger.info("Shutdown signal received. Stopping NIDS...")

    if capture:
        capture.stop()

    if analyzer:
        stats = analyzer.get_stats()
        print()
        print("=" * 50)
        print("         NIDS SESSION SUMMARY")
        print("=" * 50)
        print(f"  Total Packets Captured : {stats['total_packets']}")
        print(f"  Total Alerts Generated : {stats['total_alerts']}")
        print()
        print("  Detector Statistics:")
        for name, data in stats["detectors"].items():
            print(f"    {name}: {len(data)} IPs tracked")
        print("=" * 50)

    logger.info("NIDS stopped cleanly. Goodbye.")
    sys.exit(0)


def print_banner():
    """Print startup banner."""
    print()
    print("=" * 50)
    print("        NETWORK INTRUSION DETECTION SYSTEM")
    print("              Built on Kali Linux")
    print("=" * 50)
    print()


def load_config(config_path="config.yaml"):
    """Load and return configuration."""
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def main():
    global capture, analyzer, logger

    # Print banner
    print_banner()

    # Setup logger first - everything else depends on it
    logger = setup_logger()
    logger.info("NIDS starting up...")

    # Load config
    config = load_config()
    interface = config["network"]["interface"]

    # Initialize components
    logger.info("Initializing analyzer...")
    analyzer = PacketAnalyzer()

    logger.info("Initializing packet capture...")
    capture = PacketCapture()

    # Wire capture to analyzer
    capture.set_callback(analyzer.process_packet)

    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    # Start capture
    logger.info(f"Starting NIDS on interface: {interface}")
    logger.info("Press Ctrl+C to stop")
    print()
    capture.start()

    # Keep main thread alive while capture runs in background
    logger.info("NIDS is running. Monitoring network traffic...")
    while True:
        time.sleep(10)
        stats = analyzer.get_stats()
        logger.info(
            f"Status: {stats['total_packets']} packets "
            f"analyzed, {stats['total_alerts']} alerts generated"
        )


if __name__ == "__main__":
    main()
