"""
logger.py - Centralized logging for the NIDS
Handles both file logging and console output
"""

import logging
import logging.handlers
import os
import yaml
from colorama import Fore, Style, init

# Initialize colorama for cross-platform color support
init(autoreset=True)

# Map log level strings from config to Python logging constants
LOG_LEVELS = {
    "DEBUG":    logging.DEBUG,
    "INFO":     logging.INFO,
    "WARNING":  logging.WARNING,
    "ERROR":    logging.ERROR,
    "CRITICAL": logging.CRITICAL
}

# Color mapping for console output
LEVEL_COLORS = {
    "DEBUG":    Fore.CYAN,
    "INFO":     Fore.GREEN,
    "WARNING":  Fore.YELLOW,
    "ERROR":    Fore.RED,
    "CRITICAL": Fore.RED + Style.BRIGHT
}


def setup_logger(config_path="config.yaml"):
    """
    Initialize and return the NIDS logger.
    Reads settings from config.yaml automatically.
    """

    # Load configuration
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    log_config  = config["logging"]
    log_file    = log_config["log_file"]
    log_level   = LOG_LEVELS.get(log_config["log_level"], logging.INFO)
    max_bytes   = log_config["max_file_size_mb"] * 1024 * 1024
    backup      = log_config["backup_count"]

    # Ensure logs directory exists
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    # Create logger instance
    logger = logging.getLogger("NIDS")
    logger.setLevel(log_level)

    # Avoid duplicate handlers if setup_logger is called twice
    if logger.handlers:
        return logger

    # --- File Handler (rotating) ---
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup
    )
    file_handler.setLevel(log_level)

    # File format: timestamp [LEVEL] message
    file_formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(file_formatter)

    # --- Console Handler (colored) ---
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)

    # Custom colored formatter for console
    class ColoredFormatter(logging.Formatter):
        def format(self, record):
            color = LEVEL_COLORS.get(record.levelname, "")
            record.msg = f"{color}{record.msg}{Style.RESET_ALL}"
            return super().format(record)

    console_formatter = ColoredFormatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_handler.setFormatter(console_formatter)

    # Attach both handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


def get_logger():
    """
    Return existing NIDS logger instance.
    Call this from any module that needs logging.
    """
    return logging.getLogger("NIDS")
