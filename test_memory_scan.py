import unittest
import struct
from unittest.mock import patch, MagicMock
from core.security_manager import SecurityManager
from core.exceptions import ScanError

class TestMemoryScan(unittest.TestCase):
    def setUp(self):
        self.sm = SecurityManager()
        self.sm.driver = MagicMock()
        self.sm.process_monitor = MagicMock()
        
        # Mock memory regions
        self.sm.process_monitor.get_memory_regions.return_value = [
            (0x400000, 0x1000),
            (0x500000, 0x2000)
        ]

    def test_scan_normal_process(self):
        """Test scanning unprotected process"""
        # Mock driver returning 2 memory matches
        mock_result = struct.pack('<QQ', 0x400123, 0x500456)
        self.sm.driver.scan_memory.return_value = mock_result
        
        results = self.sm.scan_process(1234)
        self.assertEqual(len(results), 2)
        self.assertEqual(results, [0x400123, 0x500456])

    def test_scan_protected_process(self):
        """Test scan blocked for protected process"""
        self.sm.protected_processes.add(1234)
        results = self.sm.scan_process(1234)
        self.assertEqual(len(results), 0)  # Should return empty list

    def test_scan_invalid_process(self):
        """Test scan with invalid PID"""
        self.sm.process_monitor.get_memory_regions.return_value = []
        results = self.sm.scan_process(99999)
        self.assertEqual(len(results), 0)

    def test_scan_driver_failure(self):
        """Test driver failure during scan"""
        self.sm.driver.scan_memory.side_effect = DriverError("Test error")
        with self.assertRaises(ScanError):
            self.sm.scan_process(1234)

    def test_scan_large_pattern(self):
        """Test pattern size validation"""
        large_pattern = bytes([0x90] * 5000)  # 5KB pattern
        with self.assertRaises(ValueError):
            self.sm.scan_process(1234, pattern=large_pattern)

    def test_result_parsing(self):
        """Test raw result parsing"""
        test_data = struct.pack('<QQQ', 0x1111, 0x2222, 0x3333)
        results = self.sm._parse_scan_results(test_data)
        self.assertEqual(results, [0x1111, 0x2222, 0x3333])

if __name__ == '__main__':
    unittest.main()