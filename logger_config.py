import logging
import os
import sys

LOGGER_NAME = os.getenv("LOGGER_NAME", "file_manager_logger")
LOG_PATH = os.getenv("LOG_PATH", "/app/logs/file_manager.log")

logger = logging.getLogger(LOGGER_NAME)
logger.setLevel(logging.INFO)

formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

file_handler = logging.FileHandler(LOG_PATH)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)
