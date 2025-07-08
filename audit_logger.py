# utils/audit_logger.py

from datetime import datetime
from pathlib import Path
from config.settings import LOG_DIR

class AuditLogger:
    def __init__(self, log_file: Path = LOG_DIR / "audit.log"):
        self.log_file = log_file
        LOG_DIR.mkdir(parents=True, exist_ok=True)

    def log_event(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] [{level}] {message}\n"
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(entry)
