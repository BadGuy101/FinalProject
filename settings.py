# config/settings.py

import logging
import platform
from pathlib import Path


ALLOWED_EXTENSIONS = [".exe", ".dll", ".docx", ".pdf", ".xls", ".xlsx", ".bat", ".js"]

# ====================== NETWORK CONFIG ======================
NETWORK_INTERFACE = "Wi-Fi" if platform.system() == "Windows" else "eth0"
MAX_LOG_BYTES = 1_000_000  # 1MB log rotation
LOG_BACKUP_COUNT = 3  # Keep 3 rotated logs


TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe" if platform.system() == "Windows" else "/usr/bin/tshark"


# ====================== SECURITY LISTS ======================
SUSPICIOUS_DOMAINS = [
    "ads", "track", "pop", "click", "banner", 
    "doubleclick.net", "adnxs.com", "revcontent.com"
]

SUSPICIOUS_EXTENSIONS = {
    '.exe', '.scr', '.bat', '.cmd', '.com', 
    '.pif', '.vbs', '.js', '.jar', '.dmg'
}

# ====================== PATH CONFIG ======================
BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DATASET_PATH = BASE_DIR / "datasets" / "malware_data.csv"
WATCH_PATH = str(BASE_DIR / "watched")
QUARANTINE_DIR = BASE_DIR / "quarantine"
TEMP_DIR = BASE_DIR / "temp"

# ====================== APP CONFIG ======================
APP_NAME = "AdvoShield"
VERSION = "1.0.0"
LOG_LEVEL = logging.INFO
LOG_DIR = BASE_DIR / "logs"


# ====================== SCANNING CONFIG ======================
MAX_SCAN_THREADS = 4
THREAT_FEED_TIMEOUT = 30  # seconds
UPDATE_INTERVAL_MINUTES = 60

# ====================== ML CONFIG ======================
MIN_TRAINING_SAMPLES = 10
DEFAULT_ML_MODELS = [
    "random_forest",
    "xgboost",
    "svm"
]

# ====================== GUI CONFIG ======================
DEFAULT_WINDOW_SIZE = (1200, 800)
APP_THEME = "dark"  # 'dark' or 'light'

# ====================== WINDOWS SPECIFIC ======================
if platform.system() == "Windows":
    DRIVER_CONFIG = {
        'symlink': r"\\.\AdvShld_68737644",
        'max_scan_size': 1024 * 1024,  # 1MB
        'auto_protect': True
    }
    
    REGISTRY_KEYS_TO_WATCH = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Internet Explorer\Main"
    ]
else:
    DRIVER_CONFIG = None
    REGISTRY_KEYS_TO_WATCH = []

# ====================== ML RETRAINER PATHS ======================

FEEDBACK_LOG_PATH = str(BASE_DIR / "data" / "feedback_log.csv")
MODEL_OUTPUT_PATH = str(BASE_DIR / "models" / "retrained_model.pkl")
