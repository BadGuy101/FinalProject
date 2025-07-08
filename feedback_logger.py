# utils/feedback_logger.py

import csv
import os
from datetime import datetime
from config.settings import FEEDBACK_LOG_PATH

class FeedbackLogger:
    def __init__(self, path=FEEDBACK_LOG_PATH):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            with open(path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "file_path", "file_size", "detections", "threat_level", "is_malicious", "label"])

    def log_feedback(self, scan_result: dict, label: str):
        """Log scan results with true label (benign/malicious)"""
        with open(self.path, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().isoformat(),
                scan_result.get('file_path'),
                scan_result.get('file_size'),
                len(scan_result.get('detections', [])),
                scan_result.get('threat_level'),
                int(scan_result.get('is_malicious', False)),
                label
            ])
