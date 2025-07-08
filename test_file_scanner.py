# tests/test_file_scanner.py

import unittest
import os
from pathlib import Path
from engines.file_scanner import AdvancedFileScanner

class TestAdvancedFileScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = AdvancedFileScanner()

        # Setup test directory and files
        self.test_dir = Path("tests/tmp")
        self.test_dir.mkdir(parents=True, exist_ok=True)

        self.benign_file = self.test_dir / "benign.txt"
        self.suspicious_file = self.test_dir / "suspicious.exe"

        # Create benign file
        self.benign_file.write_text("This is a safe file.")

        # Create suspicious file
        self.suspicious_file.write_text("fake binary content")

    def test_is_suspicious_returns_false_for_benign_file(self):
        result = self.scanner.is_suspicious(str(self.benign_file))
        self.assertFalse(result, "Benign file incorrectly flagged as suspicious.")

    def test_is_suspicious_returns_true_for_suspicious_file(self):
        result = self.scanner.is_suspicious(str(self.suspicious_file))
        self.assertTrue(result, "Suspicious file not flagged correctly.")

    def test_extract_features_returns_dict(self):
        features = self.scanner.extract_features(str(self.suspicious_file))
        self.assertIsInstance(features, dict, "Features should be returned as a dictionary.")
        self.assertIn("size", features, "Missing expected 'size' feature.")

    def test_scan_file_executes_and_returns_result(self):
        result = self.scanner.scan_file(str(self.suspicious_file))
        self.assertIsInstance(result, dict, "Scan result should be a dictionary.")
        self.assertIn("is_malicious", result, "Missing expected 'is_malicious' key.")

    def tearDown(self):
        # Cleanup test files
        for f in self.test_dir.glob("*"):
            f.unlink()
        self.test_dir.rmdir()

